#!/usr/bin/env python3
# tools/verify_enote.py — independent, DEPENDENCY-FREE Python oracle for the NC-8
# encrypted-note delivery (shielded-pool Option A, owner-decided 2026-07-17). It
# reproduces the frozen wire format that src/crypto/enote/enote.c implements and
# gates the C ciphertext byte-for-byte against tools/vectors/enote.json.
#
#   python3 tools/verify_enote.py             # verify against the committed enote.json
#   python3 tools/verify_enote.py --selftest  # KATs + per-vector recompute, print PASS
#
# This oracle is PURE PYTHON on the standard library only (hashlib, hmac, struct,
# json) — matching every other tools/verify_*.py in the tree (verify_view_key.py,
# verify_pedersen.py, …). It imports NO third-party package: the three primitives
# (P-256 scalar mult + SEC1 compress, HKDF-SHA256, ChaCha20-Poly1305) are all
# implemented from scratch below, so a shared bug in the determ C stack cannot
# hide behind a wrapper around it. It does NOT shell out to `determ`.
#
# The from-scratch routines are copied from the sibling oracles so they are not
# reinvented: the P-256 EC ladder + SEC1 compress from tools/verify_pedersen.py,
# the RFC 5869 HKDF-SHA256 from tools/verify_view_key.py. ChaCha20-Poly1305 is
# implemented here per RFC 8439 §2.3/§2.5/§2.8 and gated against the RFC 8439
# §2.8.2 known-answer vector before anything else runs.
#
# ─── EXACT CONSTRUCTION (ephemeral-static ECIES over NIST P-256) ─────────────
# The construction below mirrors enote.c / enote.h line-for-line:
#
#   seal(recipient_pub[33 compressed], pt, eph_sk[32]):
#     E   = eph_sk · G                                   ephemeral pubkey
#     E33 = compressed SEC1(E)                           33 bytes (0x02/0x03 prefix)
#     Z   = eph_sk · R  (ECDH) ; z = Z.x                 32-byte big-endian shared x
#     okm = HKDF-SHA256(salt=b"determ-enote-v1", ikm=z,
#                       info = E33 || recipient_pub33, L=44)
#     key = okm[0:32] ; nonce = okm[32:44]               12-byte KDF-derived nonce
#     ct||tag = ChaCha20-Poly1305(key, nonce, aad=E33).encrypt(pt)   # tag 16B, appended
#     wire = E33 || ct || tag                            len = len(pt) + 49
#
# Byte-for-byte pins that MUST match the C (see enote.c):
#   * E33 / recipient_pub33 are compressed SEC1 (33B, 0x02/0x03 prefix).
#   * ECDH shared secret = the 32-byte big-endian X coordinate of Z = eph_sk·R,
#     which is enote.c's z65[1..33] (the X limb of the uncompressed point).
#   * HKDF-SHA256, length=44, salt=b"determ-enote-v1" (15 bytes, no trailing NUL —
#     `sizeof(ENOTE_DST) - 1` in enote.c), info = E33 || recipient_pub33 (66 bytes).
#   * key=okm[0:32], nonce=okm[32:44]; ChaCha20-Poly1305 with aad=E33 → ct||tag.
#   * wire = E33 || ct || tag.
import hashlib
import hmac
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(HERE, "tools", "vectors", "enote.json")

SALT = b"determ-enote-v1"            # HKDF salt / domain-separation tag (15 bytes)
OKM_LEN = 44                         # K(32) || N(12)
EPH_LEN = 33                         # compressed P-256 ephemeral pubkey
TAG_LEN = 16                         # Poly1305 tag
OVERHEAD = EPH_LEN + TAG_LEN         # 49

# ─── P-256 EC ladder + SEC1 compress (copied from tools/verify_pedersen.py) ──
# Public FIPS 186 / SEC 2 domain parameters for NIST P-256 (secp256r1).
P  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A  = (P - 3) % P
B  = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N  = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G  = (GX, GY)


def pt_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None                              # P + (-P) = O
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def pt_mul(k, pt):
    k %= N
    r, q = None, pt
    while k:
        if k & 1:
            r = pt_add(r, q)
        q = pt_add(q, q)
        k >>= 1
    return r


def compress(pt):
    if pt is None:
        raise ValueError("cannot compress the identity")
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def _scalar(sk_bytes):
    """32-byte big-endian scalar in [1, n-1]."""
    if len(sk_bytes) != 32:
        raise ValueError("secret key must be exactly 32 bytes")
    k = int.from_bytes(sk_bytes, "big")
    if not (0 < k < N):
        raise ValueError("secret key out of range [1, n-1]")
    return k


def base_mul(sk_bytes):
    """E = sk·G — the compressed SEC1 point and the raw (x, y)."""
    return pt_mul(_scalar(sk_bytes), G)


def point_mul(sk_bytes, pt):
    """Z = sk·pt (ECDH scalar mult onto an arbitrary point)."""
    return pt_mul(_scalar(sk_bytes), pt)


# ─── RFC 5869 HKDF-SHA256, from scratch (copied from verify_view_key.py) ─────
def hkdf_extract(salt, ikm):
    if not salt:
        salt = b"\x00" * 32          # RFC 5869 §2.2: default salt = HashLen zeros
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    if length > 255 * 32:
        raise ValueError("HKDF-SHA256 output limit is 255*32 bytes")
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def hkdf(salt, ikm, info, length):
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


# ─── ChaCha20-Poly1305 AEAD, from scratch (RFC 8439 §2.3/§2.5/§2.8) ──────────
_MASK32 = 0xffffffff
_CHACHA_CONST = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)


def _rotl32(v, c):
    return ((v << c) | (v >> (32 - c))) & _MASK32


def _quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & _MASK32; s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK32; s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & _MASK32; s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _MASK32; s[b] = _rotl32(s[b] ^ s[c], 7)


def _chacha20_block(key, counter, nonce):
    """RFC 8439 §2.3: 64-byte keystream block. key=32B, nonce=12B, counter=u32."""
    state = list(_CHACHA_CONST)
    state += list(struct.unpack("<8I", key))
    state.append(counter & _MASK32)
    state += list(struct.unpack("<3I", nonce))
    work = list(state)
    for _ in range(10):                          # 20 rounds = 10 column+diagonal
        _quarter_round(work, 0, 4, 8, 12)
        _quarter_round(work, 1, 5, 9, 13)
        _quarter_round(work, 2, 6, 10, 14)
        _quarter_round(work, 3, 7, 11, 15)
        _quarter_round(work, 0, 5, 10, 15)
        _quarter_round(work, 1, 6, 11, 12)
        _quarter_round(work, 2, 7, 8, 13)
        _quarter_round(work, 3, 4, 9, 14)
    out = [(work[i] + state[i]) & _MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


def _chacha20_xor(key, counter, nonce, data):
    """RFC 8439 §2.4: encrypt/decrypt `data` (counter starts at `counter`)."""
    out = bytearray()
    for j in range(0, len(data), 64):
        ks = _chacha20_block(key, counter + (j // 64), nonce)
        chunk = data[j:j + 64]
        out += bytes(b ^ ks[i] for i, b in enumerate(chunk))
    return bytes(out)


def _poly1305_mac(msg, key):
    """RFC 8439 §2.5: one-time Poly1305 MAC. key=32B (r||s)."""
    r = int.from_bytes(key[0:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block + b"\x01", "little")   # append the high 1 bit
        acc = ((acc + n) * r) % p
    acc = (acc + s) % (1 << 128)
    return acc.to_bytes(16, "little")


def _pad16(x):
    rem = len(x) % 16
    return b"" if rem == 0 else b"\x00" * (16 - rem)


def _poly1305_key_gen(key, nonce):
    """RFC 8439 §2.6: one-time Poly1305 key = ChaCha20 block(counter=0)[0:32]."""
    return _chacha20_block(key, 0, nonce)[:32]


def chacha20_poly1305_encrypt(key, nonce, aad, plaintext):
    """RFC 8439 §2.8 AEAD encrypt. Returns ct || tag (tag appended, 16B)."""
    otk = _poly1305_key_gen(key, nonce)
    ct = _chacha20_xor(key, 1, nonce, plaintext)
    mac_data = (aad + _pad16(aad) + ct + _pad16(ct)
                + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct)))
    tag = _poly1305_mac(mac_data, otk)
    return ct + tag


def chacha20_poly1305_decrypt(key, nonce, aad, ct_tag):
    """RFC 8439 §2.8 AEAD decrypt. Returns plaintext or raises on a bad tag."""
    if len(ct_tag) < TAG_LEN:
        raise ValueError("ciphertext shorter than the tag")
    ct, tag = ct_tag[:-TAG_LEN], ct_tag[-TAG_LEN:]
    otk = _poly1305_key_gen(key, nonce)
    mac_data = (aad + _pad16(aad) + ct + _pad16(ct)
                + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct)))
    if not hmac.compare_digest(_poly1305_mac(mac_data, otk), tag):
        raise ValueError("Poly1305 tag mismatch (note is not ours)")
    return _chacha20_xor(key, 1, nonce, ct)


# ─── enote seal / open (composition mirroring enote.c) ───────────────────────
def _kdf(shared_x, e33, recip33):
    """okm = HKDF-SHA256(salt=SALT, ikm=shared_x, info=E33||R33, L=44)."""
    return hkdf(SALT, shared_x, e33 + recip33, OKM_LEN)


def recipient_pub(recipient_sk):
    """recipient_pub33 = compressed(recipient_sk · G)."""
    return compress(base_mul(recipient_sk))


def seal(recipient_sk, pt, eph_sk):
    """Return (wire, recipient_pub33). wire = E33 || ct || tag."""
    recip33 = recipient_pub(recipient_sk)
    E = base_mul(eph_sk)
    e33 = compress(E)
    R = base_mul(recipient_sk)
    Z = point_mul(eph_sk, R)                     # Z = eph_sk · R (ECDH)
    if Z is None:
        raise ValueError("degenerate ECDH shared point")
    shared_x = Z[0].to_bytes(32, "big")          # z = Z.x, 32-byte big-endian
    okm = _kdf(shared_x, e33, recip33)
    key, nonce = okm[:32], okm[32:44]
    ct_tag = chacha20_poly1305_encrypt(key, nonce, e33, pt)   # ct || tag
    return e33 + ct_tag, recip33


def open_(recipient_sk, wire):
    """Trial-decrypt a wire. Raises on a non-verifying tag ("not ours")."""
    if len(wire) < OVERHEAD:
        raise ValueError("wire shorter than overhead")
    e33 = wire[:EPH_LEN]
    ct_tag = wire[EPH_LEN:]
    E = _decompress(e33)
    Z = point_mul(recipient_sk, E)               # Z = recipient_sk · E (same Z.x)
    if Z is None:
        raise ValueError("degenerate ECDH shared point")
    shared_x = Z[0].to_bytes(32, "big")
    recip33 = recipient_pub(recipient_sk)
    okm = _kdf(shared_x, e33, recip33)
    key, nonce = okm[:32], okm[32:44]
    return chacha20_poly1305_decrypt(key, nonce, e33, ct_tag)


def _decompress(buf):
    """SEC1 compressed -> (x, y). Used by open_ for the ephemeral point."""
    if len(buf) != 33 or buf[0] not in (2, 3):
        raise ValueError("not a 33-byte compressed point")
    x = int.from_bytes(buf[1:], "big")
    if x >= P:
        raise ValueError("x-coordinate out of range")
    g = (pow(x, 3, P) + A * x + B) % P
    y = pow(g, (P + 1) // 4, P)                  # P == 3 mod 4
    if y * y % P != g:
        raise ValueError("point not on curve")
    if (y & 1) != (buf[0] & 1):
        y = P - y
    return (x, y)


# ─── primitive KATs (gate the from-scratch code before any vector) ───────────
def _kat_hkdf():
    # RFC 5869 A.1 (basic test case with SHA-256).
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = hkdf(salt, ikm, info, 42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a"
                         "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865"), "RFC 5869 A.1 HKDF"


def _kat_chacha20_poly1305():
    # RFC 8439 §2.8.2 AEAD known-answer vector.
    key = bytes(range(0x80, 0xa0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
          b"only one tip for the future, sunscreen would be it.")
    want_ct = ("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
               "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
               "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
               "3ff4def08e4b7a9de576d26586cec64b6116")
    want_tag = "1ae10b594f09e26a7e902ecbd0600691"
    got = chacha20_poly1305_encrypt(key, nonce, aad, pt)
    assert got[:-TAG_LEN].hex() == want_ct, "RFC 8439 §2.8.2 ciphertext"
    assert got[-TAG_LEN:].hex() == want_tag, "RFC 8439 §2.8.2 tag"
    # round-trip: decrypt recovers the plaintext, tamper is rejected.
    assert chacha20_poly1305_decrypt(key, nonce, aad, got) == pt, "AEAD round-trip"
    bad = bytearray(got); bad[-1] ^= 1
    try:
        chacha20_poly1305_decrypt(key, nonce, aad, bytes(bad))
    except ValueError:
        pass
    else:
        raise AssertionError("AEAD accepted a tampered tag")


def _kat_p256():
    # G has order n: n·G = O, and 1·G = G (compressed matches the SEC 2 base pt).
    assert compress(pt_mul(1, G)).hex() == (
        "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"), \
        "P-256 base point compression"
    assert pt_mul(N, G) is None, "P-256 n·G == O"


# ─── corpus verification against the FROZEN enote.json ───────────────────────
def _recompute(v):
    """Recompute (wire_hex, recip_hex) from a vector's secret inputs."""
    rsk = bytes.fromhex(v["recipient_sk_hex"])
    esk = bytes.fromhex(v["eph_sk_hex"])
    pt = bytes.fromhex(v["pt_hex"])
    wire, recip33 = seal(rsk, pt, esk)
    return wire.hex(), recip33.hex()


def verify_corpus(verbose=False):
    """Recompute every committed vector; return (n, failures[])."""
    with open(CORPUS) as f:
        doc = json.load(f)
    vecs = doc["vectors"]
    failures = []
    for v in vecs:
        name = v["name"]
        wire_hex, recip_hex = _recompute(v)
        ok = True
        if recip_hex != v["recipient_pub_hex"]:
            failures.append(
                "%s: recipient_pub mismatch\n    got  %s...\n    want %s..."
                % (name, recip_hex[:16], v["recipient_pub_hex"][:16]))
            ok = False
        if wire_hex != v["ct_hex"]:
            failures.append(
                "%s: wire (ct) mismatch\n    got  %s...\n    want %s..."
                % (name, wire_hex[:16], v["ct_hex"][:16]))
            ok = False
        else:
            # A verifying tag is the ownership signal — round-trip the wire too.
            dec = open_(bytes.fromhex(v["recipient_sk_hex"]),
                        bytes.fromhex(v["ct_hex"]))
            if dec != bytes.fromhex(v["pt_hex"]):
                failures.append("%s: decrypt did not recover the plaintext" % name)
                ok = False
        if verbose:
            print("  %s %s (len(pt)=%d)"
                  % ("ok  " if ok else "FAIL", name, len(v["pt_hex"]) // 2))
    return len(vecs), failures


def main():
    _kat_hkdf()
    _kat_chacha20_poly1305()
    _kat_p256()
    selftest = "--selftest" in sys.argv
    n, failures = verify_corpus(verbose=selftest)
    if failures:
        for msg in failures:
            print("  DIFF %s" % msg)
        print("[verify_enote] %d FAILURE(S) against %s" % (len(failures), CORPUS))
        return 1
    if selftest:
        print("PASS: verify_enote %d vectors" % n)
    else:
        print("[verify] enote.json: %d vector(s) recomputed byte-equal through the "
              "independent pure-python oracle (P-256 + HKDF-SHA256 + "
              "ChaCha20-Poly1305)" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
