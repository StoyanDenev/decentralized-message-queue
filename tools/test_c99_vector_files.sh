#!/usr/bin/env bash
# test_c99_vector_files.sh — CRYPTO-C99-SPEC §3.13 test-vector validation, the
# OFFLINE half: every vector file in tools/vectors/<primitive>.json is (1)
# schema-validated and (2) recomputed end-to-end with an INDEPENDENT
# implementation (python hashlib / hmac / pbkdf2_hmac for the hash/MAC/KDF
# families; cryptography.hazmat ChaCha20Poly1305 / AESGCM / Ed25519 / X25519 /
# ec.SECP256R1 for the AEAD + curve families). Any byte that drifts from the recomputation
# turns this RED, so a corrupted / hand-edited / fabricated vector can never
# sit silently in the corpus that the binary-side test-*-c99 subcommands and
# future CI gates consume.
#
# Provenance of the corpus (see each file's "source" field): the NIST SHA
# examples (FIPS 180-2 Appendix B/C numbering — FIPS 180-4 dropped the worked
# examples and points to the NIST CSRC examples page; the empty-message case
# is NIST CAVP ShortMsg Len=0), RFC 4231, RFC 7914 §11, RFC 5869 A.1-A.3, RFC 7693, RFC 8439
# §2.8.2, the McGrew-Viega GCM AES-256 KATs, RFC 8032 §7.1 TEST 1-3,
# RFC 7748 §5.2 + §6.1, the generated §3.8c P-256 corpus (p256.json — every
# value recomputed here from cryptography.hazmat ec.SECP256R1; curve p/a/b and
# the group order are recovered from the library itself, never hardcoded), and
# RFC 9380 Appendix J.1.1 + K.1 (p256_h2c.json — suite
# P256_XMD:SHA-256_SSWU_RO_ hash_to_curve + expand_message_xmd SHA-256;
# re-derived here end-to-end by a from-scratch §5.3.1/§5.2/§6.6.2/§3 pipeline
# on hashlib.sha256 with curve p/a/b from the same p256_params() recovery),
# and RFC 9497 Appendix A.3 (p256_oprf.json — suite P256-SHA256, OPRF mode
# 0x00 + VOPRF mode 0x01, batch size 1 only; re-derived here end-to-end by a
# from-scratch §3.1/§3.2.1/§3.3.1/§3.3.2/§2.2 pipeline — contextString,
# DeriveKeyPair from Seed+KeyInfo, Blind/BlindEvaluate/Finalize, and the full
# DLEQ ComputeComposites(Fast)/GenerateProof(with the appendix
# ProofRandomScalar)/VerifyProof — on the same h2c machinery, with the group
# order n taken from RFC 9497 §4.3 and cross-checked against the library via
# (n-1)*G == -G; the A.3.2.3 batch-size-2 vector is deliberately absent, as
# the C99 protocol layer under test is single-element).
# Where the same vector is hardcoded in a src/main.cpp
# test-*-c99 dispatch block (SHA-2 empty/"abc", HMAC RFC 4231 cases 1-2, HKDF
# A.1/A.3, PBKDF2 c=4096, four BLAKE2b cases, Ed25519 TEST 1, the full X25519
# §6.1 example), the JSON bytes are the SAME bytes, so the file corpus and the
# binary pins cannot disagree without one of the two tests going RED.
#
# Needs NO determ binary, never SKIPs, runs offline (python + the
# "cryptography" package only). Run from repo root:
#   bash tools/test_c99_vector_files.sh
set -u
cd "$(dirname "$0")/.."

echo "=== C99 vector-file corpus (tools/vectors/*.json): schema + full recomputation ==="

OUT=$(python - <<'PYEOF' 2>&1
import glob, hashlib, hmac, json, os, sys

def ok(m):  print("  ok: " + m)
def bad(m): print("  bad: " + m)

EXPECTED = {
    "sha256.json", "sha512.json", "hmac_sha256.json", "pbkdf2_sha256.json",
    "hkdf_sha256.json", "blake2b.json", "chacha20_poly1305.json",
    "aes256_gcm.json", "ed25519.json", "x25519.json", "p256.json",
    "p256_h2c.json", "p256_oprf.json",
    "sha2_cavp_sha256.json", "sha2_cavp_sha512.json", "aes_gcm_cavp.json",
    "frost_ed25519_rfc9591.json", "aes_gcm_decrypt.json",
    "chacha20_poly1305_decrypt.json", "argon2id.json",
    "xchacha20_poly1305_decrypt.json", "ed25519_verify_strict.json",
    "base64_strict.json", "sha3_shake.json", "mldsa_ntt.json", "mldsa_sample.json",
    "mldsa_pack.json", "mldsa_keygen.json", "mldsa_sign.json", "mldsa_verify.json",
    "pedersen.json", "bp_ipa.json", "bp_rangeproof.json", "bp_agg_rangeproof.json",
    "ff_pedersen.json", "ff_scalar.json",
}

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
except Exception as e:
    bad("python 'cryptography' package unavailable (%s) — cannot recompute AEAD/curve vectors" % e)
    sys.exit(0)

def unhex(v, label):
    """strict: must be a canonical lowercase even-length hex string"""
    if not isinstance(v, str):
        raise ValueError("%s is not a string" % label)
    b = bytes.fromhex(v)          # raises on odd length / non-hex
    if b.hex() != v:
        raise ValueError("%s is not canonical lowercase hex" % label)
    return b

def need(vec, fields, label):
    missing = [f for f in fields if f not in vec]
    if missing:
        raise ValueError("%s missing field(s): %s" % (label, ", ".join(missing)))

def hkdf_sha256_ref(salt, ikm, info, L):
    """from-scratch RFC 5869 extract+expand on stdlib hmac (independent of hazmat)"""
    prk = hmac.new(salt if salt else b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < L:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:L]

# ---- per-primitive recomputation; each returns None (match) or an error str ----
def chk_sha(vec, label, algo, dlen):
    need(vec, ["msg_hex", "digest_hex"], label)
    msg = unhex(vec["msg_hex"], label + " msg_hex") * int(vec.get("repeat", 1))
    got = hashlib.new(algo, msg).hexdigest()
    want = unhex(vec["digest_hex"], label + " digest_hex").hex()
    if len(want) != 2 * dlen: return "digest_hex is not %d bytes" % dlen
    if got != want: return "recomputed %s != digest_hex %s" % (got, want)

def chk_hmac_sha256(vec, label):
    need(vec, ["key_hex", "msg_hex", "mac_len", "mac_hex"], label)
    key = unhex(vec["key_hex"], label + " key_hex")
    msg = unhex(vec["msg_hex"], label + " msg_hex")
    maclen = int(vec["mac_len"])
    if not (1 <= maclen <= 32): return "mac_len %d out of range" % maclen
    want = unhex(vec["mac_hex"], label + " mac_hex")
    if len(want) != maclen: return "mac_hex length != mac_len"
    got = hmac.new(key, msg, hashlib.sha256).digest()[:maclen]
    if got != want: return "recomputed %s != mac_hex %s" % (got.hex(), want.hex())

def chk_pbkdf2(vec, label):
    need(vec, ["password_hex", "salt_hex", "iterations", "dklen", "dk_hex"], label)
    got = hashlib.pbkdf2_hmac("sha256",
                              unhex(vec["password_hex"], label + " password_hex"),
                              unhex(vec["salt_hex"], label + " salt_hex"),
                              int(vec["iterations"]), int(vec["dklen"])).hex()
    want = unhex(vec["dk_hex"], label + " dk_hex").hex()
    if got != want: return "recomputed %s != dk_hex %s" % (got, want)

def chk_hkdf(vec, label):
    need(vec, ["ikm_hex", "salt_hex", "info_hex", "length", "okm_hex"], label)
    ikm  = unhex(vec["ikm_hex"], label + " ikm_hex")
    salt = unhex(vec["salt_hex"], label + " salt_hex")
    info = unhex(vec["info_hex"], label + " info_hex")
    L = int(vec["length"])
    want = unhex(vec["okm_hex"], label + " okm_hex")
    if len(want) != L: return "okm_hex length != length"
    got = hkdf_sha256_ref(salt, ikm, info, L)
    got2 = HKDF(algorithm=hashes.SHA256(), length=L,
                salt=salt if salt else None, info=info).derive(ikm)
    if got != got2: return "stdlib-hmac HKDF and hazmat HKDF disagree (runner bug)"
    if got != want: return "recomputed %s != okm_hex %s" % (got.hex(), want.hex())

def chk_blake2b(vec, label):
    need(vec, ["msg_hex", "key_hex", "outlen", "digest_hex"], label)
    outlen = int(vec["outlen"])
    if not (1 <= outlen <= 64): return "outlen %d out of range" % outlen
    got = hashlib.blake2b(unhex(vec["msg_hex"], label + " msg_hex"),
                          digest_size=outlen,
                          key=unhex(vec["key_hex"], label + " key_hex")).hexdigest()
    want = unhex(vec["digest_hex"], label + " digest_hex").hex()
    if len(want) != 2 * outlen: return "digest_hex length != outlen"
    if got != want: return "recomputed %s != digest_hex %s" % (got, want)

def chk_aead(vec, label, cls, nonce_field):
    need(vec, ["key_hex", nonce_field, "aad_hex", "plaintext_hex",
               "ciphertext_hex", "tag_hex"], label)
    key   = unhex(vec["key_hex"], label + " key_hex")
    nonce = unhex(vec[nonce_field], label + " " + nonce_field)
    aad   = unhex(vec["aad_hex"], label + " aad_hex")
    pt    = unhex(vec["plaintext_hex"], label + " plaintext_hex")
    ct    = unhex(vec["ciphertext_hex"], label + " ciphertext_hex")
    tag   = unhex(vec["tag_hex"], label + " tag_hex")
    if len(tag) != 16: return "tag_hex is not 16 bytes"
    got = cls(key).encrypt(nonce, pt, aad if aad else None)
    if got != ct + tag:
        return "recomputed ct||tag %s != vector %s" % (got.hex(), (ct + tag).hex())
    back = cls(key).decrypt(nonce, ct + tag, aad if aad else None)
    if back != pt: return "decrypt(ct||tag) != plaintext"

def chk_aes256_gcm_decrypt(vec, label):
    # Decrypt-direction corpus: result PASS must decrypt to plaintext_hex;
    # result FAIL (tampered tag/ct/aad, wrong key) must be REJECTED by the
    # oracle too — proving the vector genuinely fails, not just that the C99
    # side rejects it. Arbitrary IV lengths exercise the GHASH-J0 path.
    need(vec, ["result", "key_hex", "iv_hex", "aad_hex",
               "ciphertext_hex", "tag_hex"], label)
    key = unhex(vec["key_hex"], label + " key_hex")
    iv  = unhex(vec["iv_hex"], label + " iv_hex")
    aad = unhex(vec["aad_hex"], label + " aad_hex")
    ct  = unhex(vec["ciphertext_hex"], label + " ciphertext_hex")
    tag = unhex(vec["tag_hex"], label + " tag_hex")
    if len(tag) != 16: return "tag_hex is not 16 bytes"
    try:
        got = AESGCM(key).decrypt(iv, ct + tag, aad if aad else None)
        decrypted = True
    except Exception:
        decrypted = False
    if vec["result"] == "PASS":
        if not decrypted: return "PASS vector failed to decrypt under the oracle"
        pt = unhex(vec["plaintext_hex"], label + " plaintext_hex")
        if got != pt: return "oracle plaintext != vector plaintext_hex"
    elif vec["result"] == "FAIL":
        if decrypted: return "FAIL vector DECRYPTED under the oracle (not genuinely tampered)"
    else:
        return "unknown result %r" % vec["result"]

def chk_chacha20_poly1305_decrypt(vec, label):
    # Decrypt-direction corpus, same contract as aes256_gcm_decrypt: PASS
    # must decrypt to plaintext_hex under the oracle; FAIL must be rejected
    # (proving the vector is genuinely tampered, not merely C99-rejected).
    need(vec, ["result", "key_hex", "nonce_hex", "aad_hex",
               "ciphertext_hex", "tag_hex"], label)
    key   = unhex(vec["key_hex"], label + " key_hex")
    nonce = unhex(vec["nonce_hex"], label + " nonce_hex")
    aad   = unhex(vec["aad_hex"], label + " aad_hex")
    ct    = unhex(vec["ciphertext_hex"], label + " ciphertext_hex")
    tag   = unhex(vec["tag_hex"], label + " tag_hex")
    if len(tag) != 16: return "tag_hex is not 16 bytes"
    try:
        got = ChaCha20Poly1305(key).decrypt(nonce, ct + tag, aad if aad else None)
        decrypted = True
    except Exception:
        decrypted = False
    if vec["result"] == "PASS":
        if not decrypted: return "PASS vector failed to decrypt under the oracle"
        pt = unhex(vec["plaintext_hex"], label + " plaintext_hex")
        if got != pt: return "oracle plaintext != vector plaintext_hex"
    elif vec["result"] == "FAIL":
        if decrypted: return "FAIL vector DECRYPTED under the oracle (not genuinely tampered)"
    else:
        return "unknown result %r" % vec["result"]

def chk_xchacha20_poly1305_decrypt(vec, label):
    # XChaCha20-Poly1305 decrypt-direction corpus. hazmat has no XChaCha;
    # the oracle is pynacl (libsodium bindings). Missing pynacl is a
    # FAILURE, not a skip (fail-closed, same posture as cryptography /
    # argon2-cffi). Install: pip install pynacl.
    need(vec, ["result", "key_hex", "nonce_hex", "aad_hex",
               "ciphertext_hex", "tag_hex"], label)
    try:
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
    except Exception as e:
        return "pynacl not importable (%s) — pip install pynacl" % e
    key   = unhex(vec["key_hex"], label + " key_hex")
    nonce = unhex(vec["nonce_hex"], label + " nonce_hex")
    aad   = unhex(vec["aad_hex"], label + " aad_hex")
    ct    = unhex(vec["ciphertext_hex"], label + " ciphertext_hex")
    tag   = unhex(vec["tag_hex"], label + " tag_hex")
    if len(nonce) != 24: return "nonce_hex is not 24 bytes"
    if len(tag) != 16: return "tag_hex is not 16 bytes"
    try:
        got = crypto_aead_xchacha20poly1305_ietf_decrypt(
            ct + tag, aad if aad else None, nonce, key)
        decrypted = True
    except Exception:
        decrypted = False
    if vec["result"] == "PASS":
        if not decrypted: return "PASS vector failed to decrypt under the oracle"
        pt = unhex(vec["plaintext_hex"], label + " plaintext_hex")
        if got != pt: return "oracle plaintext != vector plaintext_hex"
    elif vec["result"] == "FAIL":
        if decrypted: return "FAIL vector DECRYPTED under the oracle (not genuinely tampered)"
    else:
        return "unknown result %r" % vec["result"]

def chk_ed25519_verify_strict(vec, label):
    # The strict-verifier consensus-rule pin. Oracle = pynacl/libsodium,
    # which is ALSO strict (rejects S >= L + non-canonical pubkeys) — so
    # PASS must verify and FAIL must be rejected under the oracle too,
    # proving each FAIL vector is genuinely non-canonical/tampered rather
    # than merely C99-rejected. Missing pynacl is a FAILURE (fail-closed).
    need(vec, ["result", "public_key_hex", "msg_hex", "signature_hex"], label)
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except Exception as e:
        return "pynacl not importable (%s) — pip install pynacl" % e
    pk  = unhex(vec["public_key_hex"], label + " public_key_hex")
    msg = unhex(vec["msg_hex"], label + " msg_hex")
    sig = unhex(vec["signature_hex"], label + " signature_hex")
    try:
        VerifyKey(pk).verify(msg, sig)
        verified = True
    except Exception:
        verified = False
    if vec["result"] == "PASS":
        if not verified: return "PASS vector rejected by the strict oracle"
    elif vec["result"] == "FAIL":
        if verified: return "FAIL vector ACCEPTED by the strict oracle (not genuinely non-canonical)"
    else:
        return "unknown result %r" % vec["result"]

def chk_base64_strict(vec, label):
    # Independent strict RFC 4648 s4 decode oracle (no external dep — a
    # from-scratch decoder, distinct from the C module the binary side
    # tests and stricter than python's binascii, which tolerates non-
    # canonical trailing bits). PASS must decode to decoded_hex; FAIL must
    # be rejected. Pins the exact determ_base64_decode contract: standard
    # alphabet only, len % 4 == 0, correct '=' padding, no mid-string '=',
    # zero non-canonical trailing bits, no embedded whitespace/newline.
    need(vec, ["result", "b64"], label)
    ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    REV = {c: i for i, c in enumerate(ALPHABET)}
    def strict_decode(s):
        if len(s) % 4 != 0:
            raise ValueError("length not a multiple of 4")
        out = bytearray()
        for i in range(0, len(s), 4):
            quad = s[i:i+4]
            pad = 0
            if quad[3] == '=':
                pad += 1
                if quad[2] == '=':
                    pad += 1
            # '=' only allowed in the final quantum, tail positions
            for j, ch in enumerate(quad):
                is_last_quad = (i + 4 == len(s))
                if ch == '=':
                    if not is_last_quad:
                        raise ValueError("'=' before final quantum")
                    if j < 2:
                        raise ValueError("'=' in position 0/1")
                    if j == 2 and pad != 2:
                        raise ValueError("'=' padding shape invalid")
                elif ch not in REV:
                    raise ValueError("non-alphabet char %r" % ch)
            v = 0
            for ch in quad:
                v = (v << 6) | (0 if ch == '=' else REV[ch])
            if pad == 0:
                out += bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])
            elif pad == 1:
                if v & 0xFF:
                    raise ValueError("non-canonical trailing bits (pad=1)")
                out += bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF])
            else:  # pad == 2
                if v & 0xFFFF:
                    raise ValueError("non-canonical trailing bits (pad=2)")
                out += bytes([(v >> 16) & 0xFF])
        return bytes(out)
    b64 = vec["b64"]
    try:
        decoded = strict_decode(b64)
        rejected = False
    except ValueError:
        decoded = None
        rejected = True
    if vec["result"] == "PASS":
        if rejected:
            return "PASS vector rejected by the strict oracle"
        exp = unhex(vec["decoded_hex"], label + " decoded_hex")
        if decoded != exp:
            return "oracle decode %r != decoded_hex" % decoded.hex()
    elif vec["result"] == "FAIL":
        if not rejected:
            return "FAIL vector ACCEPTED by the strict oracle (not malformed)"
    else:
        return "unknown result %r" % vec["result"]

def chk_argon2id(vec, label):
    # Recompute the Argon2id tag with argon2-cffi (the P-H-C reference
    # bindings — the corpus oracle, itself proven byte-equal to the four
    # libsodium KATs pinned in `determ test-argon2id-c99`). Missing
    # argon2-cffi is a FAILURE, not a skip (same fail-closed posture as the
    # `cryptography` dependency): a silently-skipped primitive would read
    # as coverage. Install: pip install argon2-cffi.
    need(vec, ["password_hex", "salt_hex", "t_cost", "m_cost_kib",
               "parallelism", "outlen", "tag_hex"], label)
    try:
        from argon2.low_level import hash_secret_raw, Type
    except Exception as e:
        return "argon2-cffi not importable (%s) — pip install argon2-cffi" % e
    pwd  = unhex(vec["password_hex"], label + " password_hex")
    salt = unhex(vec["salt_hex"], label + " salt_hex")
    tag  = unhex(vec["tag_hex"], label + " tag_hex")
    got = hash_secret_raw(secret=pwd, salt=salt,
                          time_cost=int(vec["t_cost"]),
                          memory_cost=int(vec["m_cost_kib"]),
                          parallelism=int(vec["parallelism"]),
                          hash_len=int(vec["outlen"]),
                          type=Type.ID)
    if got != tag:
        return "recomputed tag %s != vector %s" % (got.hex(), tag.hex())

def chk_ed25519(vec, label):
    need(vec, ["seed_hex", "public_key_hex", "msg_hex", "signature_hex"], label)
    sk  = Ed25519PrivateKey.from_private_bytes(unhex(vec["seed_hex"], label + " seed_hex"))
    msg = unhex(vec["msg_hex"], label + " msg_hex")
    pk  = sk.public_key()
    got_pk = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    want_pk = unhex(vec["public_key_hex"], label + " public_key_hex").hex()
    if got_pk != want_pk: return "derived pubkey %s != public_key_hex %s" % (got_pk, want_pk)
    got_sig = sk.sign(msg)
    want_sig = unhex(vec["signature_hex"], label + " signature_hex")
    if got_sig != want_sig:
        return "recomputed signature %s != signature_hex %s" % (got_sig.hex(), want_sig.hex())
    pk.verify(want_sig, msg)   # raises on invalid

def chk_x25519(vec, label):
    t = vec.get("type")
    if t == "scalarmult":
        need(vec, ["scalar_hex", "u_hex", "output_hex"], label)
        got = X25519PrivateKey.from_private_bytes(
                  unhex(vec["scalar_hex"], label + " scalar_hex")).exchange(
                  X25519PublicKey.from_public_bytes(unhex(vec["u_hex"], label + " u_hex"))).hex()
        want = unhex(vec["output_hex"], label + " output_hex").hex()
        if got != want: return "recomputed %s != output_hex %s" % (got, want)
    elif t == "dh":
        need(vec, ["private_a_hex", "private_b_hex", "public_a_hex",
                   "public_b_hex", "shared_hex"], label)
        ska = X25519PrivateKey.from_private_bytes(unhex(vec["private_a_hex"], label + " private_a_hex"))
        skb = X25519PrivateKey.from_private_bytes(unhex(vec["private_b_hex"], label + " private_b_hex"))
        raw = lambda k: k.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if raw(ska).hex() != unhex(vec["public_a_hex"], label + " public_a_hex").hex():
            return "derived public_a %s != public_a_hex" % raw(ska).hex()
        if raw(skb).hex() != unhex(vec["public_b_hex"], label + " public_b_hex").hex():
            return "derived public_b %s != public_b_hex" % raw(skb).hex()
        sab = ska.exchange(X25519PublicKey.from_public_bytes(raw(skb))).hex()
        sba = skb.exchange(X25519PublicKey.from_public_bytes(raw(ska))).hex()
        want = unhex(vec["shared_hex"], label + " shared_hex").hex()
        if sab != want or sba != want:
            return "recomputed shared %s/%s != shared_hex %s" % (sab, sba, want)
    else:
        return "unknown x25519 vector type %r" % t

_P256_PARAMS = []
def p256_params():
    """Recover (p, a, b) of SECP256R1 mechanically from library-generated points
    (gcd of point-relation eliminants), so the invalid_point curve-equation check
    uses NO hardcoded curve constants. Cached after first call."""
    if _P256_PARAMS:
        return _P256_PARAMS[0]
    import itertools, math
    pts = []
    for s in range(1, 7):
        nums = ec.derive_private_key(s, ec.SECP256R1()).public_key().public_numbers()
        pts.append((nums.x, nums.y))
    f = [y * y - x * x * x for (x, y) in pts]
    g = 0
    for (i, j, k) in itertools.combinations(range(6), 3):
        g = math.gcd(g, abs((f[i] - f[j]) * (pts[j][0] - pts[k][0])
                            - (f[j] - f[k]) * (pts[i][0] - pts[j][0])))
    q = 2
    while q < 100000 and g.bit_length() > 256:
        while g % q == 0 and g.bit_length() > 256:
            g //= q
        q += 1
    p = g
    if p.bit_length() != 256:
        raise ValueError("p256 prime recovery failed (%d-bit candidate)" % p.bit_length())
    a = ((f[0] - f[1]) * pow(pts[0][0] - pts[1][0], -1, p)) % p
    b = (f[0] - a * pts[0][0]) % p
    if a != p - 3 or any((y * y - x * x * x - a * x - b) % p for (x, y) in pts):
        raise ValueError("p256 curve-parameter recovery inconsistent")
    _P256_PARAMS.append((p, a, b))
    return _P256_PARAMS[0]

def chk_p256(vec, label):
    t = vec.get("type")
    if t == "keygen":
        need(vec, ["scalar_hex", "public_uncompressed_hex"], label)
        scalar = unhex(vec["scalar_hex"], label + " scalar_hex")
        if len(scalar) != 32: return "scalar_hex is not 32 bytes"
        want = unhex(vec["public_uncompressed_hex"], label + " public_uncompressed_hex")
        if len(want) != 65 or want[0] != 0x04:
            return "public_uncompressed_hex is not 65 bytes 0x04||X||Y"
        got = ec.derive_private_key(int.from_bytes(scalar, "big"),
                                    ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        if got != want:
            return "derived pubkey %s != public_uncompressed_hex %s" % (got.hex(), want.hex())
    elif t == "ecdh":
        need(vec, ["private_a_hex", "private_b_hex", "public_a_uncompressed_hex",
                   "public_b_uncompressed_hex", "shared_x_hex"], label)
        ska = ec.derive_private_key(
            int.from_bytes(unhex(vec["private_a_hex"], label + " private_a_hex"), "big"),
            ec.SECP256R1())
        skb = ec.derive_private_key(
            int.from_bytes(unhex(vec["private_b_hex"], label + " private_b_hex"), "big"),
            ec.SECP256R1())
        unc = lambda k: k.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        if unc(ska).hex() != unhex(vec["public_a_uncompressed_hex"],
                                   label + " public_a_uncompressed_hex").hex():
            return "derived public_a %s != public_a_uncompressed_hex" % unc(ska).hex()
        if unc(skb).hex() != unhex(vec["public_b_uncompressed_hex"],
                                   label + " public_b_uncompressed_hex").hex():
            return "derived public_b %s != public_b_uncompressed_hex" % unc(skb).hex()
        want = unhex(vec["shared_x_hex"], label + " shared_x_hex")
        if len(want) != 32: return "shared_x_hex is not 32 bytes"
        sab = ska.exchange(ec.ECDH(), skb.public_key())
        sba = skb.exchange(ec.ECDH(), ska.public_key())
        if sab != want or sba != want:
            return "recomputed shared %s/%s != shared_x_hex %s" % (sab.hex(), sba.hex(), want.hex())
    elif t == "invalid_point":
        need(vec, ["point_uncompressed_hex"], label)
        pt = unhex(vec["point_uncompressed_hex"], label + " point_uncompressed_hex")
        if len(pt) != 65 or pt[0] != 0x04:
            return "point_uncompressed_hex is not 65 bytes 0x04||X||Y"
        # checked via the curve equation directly (from_encoded_point may or may
        # not validate depending on the cryptography/OpenSSL version)
        p, a, b = p256_params()
        x = int.from_bytes(pt[1:33], "big")
        y = int.from_bytes(pt[33:65], "big")
        if (y * y - x * x * x - a * x - b) % p == 0:
            return "point satisfies the curve equation — it is NOT an invalid point"
    else:
        return "unknown p256 vector type %r" % t

# ---- RFC 9380 P-256 hash-to-curve (suite P256_XMD:SHA-256_SSWU_RO_) ----
# From-scratch re-derivation on hashlib.sha256 + integer arithmetic only:
# expand_message_xmd per §5.3.1, hash_to_field per §5.2 (m=1, L=48),
# simplified SSWU per §6.6.2 (Z=-10 per §8.2), sgn0 per §4.1 (m=1, x mod 2),
# hash_to_curve per §3 (h_eff=1 so clear_cofactor is the identity). Curve
# p/a/b come from p256_params() — recovered from the cryptography library,
# never hardcoded.
def h2c_expand_xmd(msg, dst, len_in_bytes):
    ell = -(-len_in_bytes // 32)
    if ell > 255 or len_in_bytes > 65535 or len(dst) > 255:
        raise ValueError("expand_message_xmd bounds exceeded")
    dst_prime = dst + bytes([len(dst)])
    b0 = hashlib.sha256(b"\x00" * 64 + msg + len_in_bytes.to_bytes(2, "big")
                        + b"\x00" + dst_prime).digest()
    bi = hashlib.sha256(b0 + b"\x01" + dst_prime).digest()
    out = bi
    for i in range(2, ell + 1):
        bi = hashlib.sha256(bytes(x ^ y for x, y in zip(b0, bi))
                            + bytes([i]) + dst_prime).digest()
        out += bi
    return out[:len_in_bytes]

def h2c_map_sswu(u, p, a, b):
    z = (-10) % p                              # RFC 9380 §8.2: Z = -10
    inv0 = lambda x: pow(x, p - 2, p)          # inv0(0) == 0
    tv1 = inv0((z * z * pow(u, 4, p) + z * u * u) % p)
    x1 = (-b * inv0(a)) % p * (1 + tv1) % p
    if tv1 == 0:
        x1 = b * inv0(z * a % p) % p
    gx1 = (pow(x1, 3, p) + a * x1 + b) % p
    x2 = (z * u * u % p) * x1 % p
    gx2 = (pow(x2, 3, p) + a * x2 + b) % p
    if pow(gx1, (p - 1) // 2, p) in (0, 1):
        x, g = x1, gx1
    else:
        x, g = x2, gx2
    y = pow(g, (p + 1) // 4, p)                # p == 3 mod 4
    if (y * y - g) % p:
        raise ValueError("sswu: g(x) unexpectedly non-square")
    if (u % 2) != (y % 2):                     # sgn0 m=1
        y = p - y
    return (x, y)

def h2c_point_add(p1, p2, p, a):
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % p == 0:
        raise ValueError("Q0 + Q1 is the point at infinity")
    if p1 == p2:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, p - 2, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, p - 2, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)

def chk_p256_h2c(vec, label):
    t = vec.get("type")
    if t == "expand_message_xmd":
        need(vec, ["msg_hex", "dst_hex", "len_in_bytes", "uniform_bytes_hex"], label)
        msg = unhex(vec["msg_hex"], label + " msg_hex")
        dst = unhex(vec["dst_hex"], label + " dst_hex")
        L = int(vec["len_in_bytes"])
        want = unhex(vec["uniform_bytes_hex"], label + " uniform_bytes_hex")
        if len(want) != L: return "uniform_bytes_hex length != len_in_bytes"
        got = h2c_expand_xmd(msg, dst, L)
        if got != want:
            return "recomputed %s != uniform_bytes_hex %s" % (got.hex(), want.hex())
    elif t == "hash_to_curve":
        need(vec, ["msg_hex", "dst_hex", "u0_hex", "u1_hex", "px_hex", "py_hex"], label)
        msg = unhex(vec["msg_hex"], label + " msg_hex")
        dst = unhex(vec["dst_hex"], label + " dst_hex")
        p, a, b = p256_params()
        ub = h2c_expand_xmd(msg, dst, 96)      # count=2 * m=1 * L=48 (§8.2)
        u0 = int.from_bytes(ub[:48], "big") % p
        u1 = int.from_bytes(ub[48:], "big") % p
        for got_u, fld in ((u0, "u0_hex"), (u1, "u1_hex")):
            want_u = unhex(vec[fld], label + " " + fld)
            if len(want_u) != 32: return "%s is not 32 bytes" % fld
            if got_u != int.from_bytes(want_u, "big"):
                return "recomputed %s %064x != vector %s" % (fld, got_u, want_u.hex())
        px, py = h2c_point_add(h2c_map_sswu(u0, p, a, b),
                               h2c_map_sswu(u1, p, a, b), p, a)
        want_x = unhex(vec["px_hex"], label + " px_hex")
        want_y = unhex(vec["py_hex"], label + " py_hex")
        if len(want_x) != 32 or len(want_y) != 32:
            return "px_hex/py_hex is not 32 bytes"
        if (py * py - px * px * px - a * px - b) % p:
            return "recomputed P is not on the curve (runner bug)"
        if px != int.from_bytes(want_x, "big") or py != int.from_bytes(want_y, "big"):
            return "recomputed P (%064x, %064x) != vector (%s, %s)" % (
                px, py, want_x.hex(), want_y.hex())
    else:
        return "unknown p256_h2c vector type %r" % t

# ---- RFC 9497 OPRF/VOPRF, suite P256-SHA256 (mode 0x00 / 0x01) ----
# From-scratch re-derivation of the full protocol on the h2c machinery above:
# contextString per §3.1, DeriveKeyPair per §3.2.1 (skSm re-derived from
# Seed+KeyInfo, never trusted from the file), Blind/BlindEvaluate/Finalize per
# §3.3.1, VOPRF per §3.3.2, and the DLEQ proof system per §2.2
# (ComputeComposites(Fast), GenerateProof with the vector's fixed
# ProofRandomScalar, VerifyProof). Curve p/a/b come from p256_params(); the
# group order n is the RFC 9497 §4.3 Order() value, accepted only after a
# library cross-check that (n-1)*G == -G (and n is 256 bits), so a corrupted
# constant cannot validate.
_P256_ORDER = []
def p256_order():
    if _P256_ORDER:
        return _P256_ORDER[0]
    p, a, b = p256_params()
    n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    g1 = ec.derive_private_key(1, ec.SECP256R1()).public_key().public_numbers()
    gn = ec.derive_private_key(n - 1, ec.SECP256R1()).public_key().public_numbers()
    if n.bit_length() != 256 or (gn.x, gn.y) != (g1.x, p - g1.y):
        raise ValueError("p256 order cross-check failed: (n-1)*G != -G")
    _P256_ORDER.append((n, (g1.x, g1.y)))
    return _P256_ORDER[0]

def oprf_pt_add(p1, p2, p, a):
    """identity-aware wrapper (None = point at infinity) over h2c_point_add"""
    if p1 is None: return p2
    if p2 is None: return p1
    try:
        return h2c_point_add(p1, p2, p, a)
    except ValueError:
        return None                       # P + (-P) = infinity

def oprf_pt_mul(k, pt, p, a, n):
    k %= n
    r, q = None, pt
    while k:
        if k & 1: r = oprf_pt_add(r, q, p, a)
        q = oprf_pt_add(q, q, p, a)
        k >>= 1
    return r

def oprf_ser(pt):
    if pt is None: raise ValueError("cannot serialize the identity element")
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")

def oprf_deser(buf, p, a, b, label):
    if len(buf) != 33 or buf[0] not in (2, 3):
        raise ValueError("%s is not a 33-byte compressed point" % label)
    x = int.from_bytes(buf[1:], "big")
    if x >= p: raise ValueError("%s x-coordinate out of range" % label)
    g = (pow(x, 3, p) + a * x + b) % p
    y = pow(g, (p + 1) // 4, p)
    if y * y % p != g: raise ValueError("%s is not on the curve" % label)
    if (y & 1) != (buf[0] & 1): y = p - y
    return (x, y)

def oprf_i2osp2(v): return v.to_bytes(2, "big")

def oprf_hash_to_scalar(msg, ctx, n, dst_prefix=b"HashToScalar-"):
    return int.from_bytes(h2c_expand_xmd(msg, dst_prefix + ctx, 48), "big") % n

def oprf_hash_to_group(msg, ctx, p, a, b):
    ub = h2c_expand_xmd(msg, b"HashToGroup-" + ctx, 96)
    u0, u1 = (int.from_bytes(ub[:48], "big") % p,
              int.from_bytes(ub[48:], "big") % p)
    return oprf_pt_add(h2c_map_sswu(u0, p, a, b), h2c_map_sswu(u1, p, a, b), p, a)

def oprf_derive_key_pair(seed, info, ctx, n):
    di = seed + oprf_i2osp2(len(info)) + info
    for counter in range(256):
        sk = oprf_hash_to_scalar(di + bytes([counter]), ctx, n, b"DeriveKeyPair")
        if sk != 0: return sk
    raise ValueError("DeriveKeyPairError")

def oprf_composites(k, B_pt, C, D, ctx, p, a, n):
    """k=None -> ComputeComposites (§2.2.2); k=Scalar -> ComputeCompositesFast (§2.2.1)"""
    Bm = oprf_ser(B_pt)
    seed_dst = b"Seed-" + ctx
    seed = hashlib.sha256(oprf_i2osp2(len(Bm)) + Bm +
                          oprf_i2osp2(len(seed_dst)) + seed_dst).digest()
    M = Z = None
    for i, (c_pt, d_pt) in enumerate(zip(C, D)):
        Ci, Di = oprf_ser(c_pt), oprf_ser(d_pt)
        t = (oprf_i2osp2(len(seed)) + seed + oprf_i2osp2(i) +
             oprf_i2osp2(len(Ci)) + Ci + oprf_i2osp2(len(Di)) + Di + b"Composite")
        di = oprf_hash_to_scalar(t, ctx, n)
        M = oprf_pt_add(oprf_pt_mul(di, c_pt, p, a, n), M, p, a)
        if k is None:
            Z = oprf_pt_add(oprf_pt_mul(di, d_pt, p, a, n), Z, p, a)
    if k is not None:
        Z = oprf_pt_mul(k, M, p, a, n)
    return M, Z

def oprf_challenge(B_pt, M, Z, t2, t3, ctx, n):
    buf = b""
    for e in (B_pt, M, Z, t2, t3):
        s = oprf_ser(e)
        buf += oprf_i2osp2(len(s)) + s
    return oprf_hash_to_scalar(buf + b"Challenge", ctx, n)

def chk_p256_oprf(vec, label):
    t = vec.get("type")
    if t not in ("oprf", "voprf"):
        return "unknown p256_oprf vector type %r" % t
    need(vec, ["mode", "seed_hex", "key_info_hex", "sks_hex", "input_hex",
               "blind_hex", "blinded_element_hex", "evaluation_element_hex",
               "output_hex"], label)
    mode = int(vec["mode"])
    if (t, mode) not in (("oprf", 0), ("voprf", 1)):
        return "type %r / mode %d mismatch (oprf=0x00, voprf=0x01)" % (t, mode)
    p, a, b = p256_params()
    n, G1 = p256_order()
    ctx = b"OPRFV1-" + bytes([mode]) + b"-P256-SHA256"
    # DeriveKeyPair (§3.2.1): re-derive skSm from Seed+KeyInfo
    sks = oprf_derive_key_pair(unhex(vec["seed_hex"], label + " seed_hex"),
                               unhex(vec["key_info_hex"], label + " key_info_hex"),
                               ctx, n)
    want_sks = unhex(vec["sks_hex"], label + " sks_hex")
    if len(want_sks) != 32 or sks != int.from_bytes(want_sks, "big"):
        return "DeriveKeyPair(seed, key_info) %064x != sks_hex %s" % (sks, want_sks.hex())
    inp   = unhex(vec["input_hex"], label + " input_hex")
    blind = int.from_bytes(unhex(vec["blind_hex"], label + " blind_hex"), "big")
    if not (0 < blind < n): return "blind_hex out of scalar range"
    want_be = unhex(vec["blinded_element_hex"], label + " blinded_element_hex")
    want_ee = unhex(vec["evaluation_element_hex"], label + " evaluation_element_hex")
    want_out = unhex(vec["output_hex"], label + " output_hex")
    if len(want_out) != 32: return "output_hex is not 32 bytes (Nh)"
    # Blind (§3.3.1) with the vector's fixed blind scalar
    input_pt = oprf_hash_to_group(inp, ctx, p, a, b)
    if input_pt is None: return "HashToGroup(input) is the identity (InvalidInputError)"
    got_be = oprf_ser(oprf_pt_mul(blind, input_pt, p, a, n))
    if got_be != want_be:
        return "recomputed BlindedElement %s != blinded_element_hex %s" % (got_be.hex(), want_be.hex())
    # BlindEvaluate
    be_pt = oprf_deser(want_be, p, a, b, label + " blinded_element_hex")
    got_ee = oprf_ser(oprf_pt_mul(sks, be_pt, p, a, n))
    if got_ee != want_ee:
        return "recomputed EvaluationElement %s != evaluation_element_hex %s" % (got_ee.hex(), want_ee.hex())
    # Finalize (§3.3.1): unblind + length-prefixed transcript hash
    ee_pt = oprf_deser(want_ee, p, a, b, label + " evaluation_element_hex")
    unb = oprf_ser(oprf_pt_mul(pow(blind, -1, n), ee_pt, p, a, n))
    got_out = hashlib.sha256(oprf_i2osp2(len(inp)) + inp +
                             oprf_i2osp2(len(unb)) + unb + b"Finalize").digest()
    if got_out != want_out:
        return "recomputed Output %s != output_hex %s" % (got_out.hex(), want_out.hex())
    if t == "voprf":
        need(vec, ["pks_hex", "proof_hex", "proof_random_scalar_hex"], label)
        want_pks = unhex(vec["pks_hex"], label + " pks_hex")
        got_pks = oprf_ser(oprf_pt_mul(sks, G1, p, a, n))
        if got_pks != want_pks:
            return "recomputed pkS %s != pks_hex %s" % (got_pks.hex(), want_pks.hex())
        want_proof = unhex(vec["proof_hex"], label + " proof_hex")
        if len(want_proof) != 64: return "proof_hex is not 64 bytes (c||s)"
        r = int.from_bytes(unhex(vec["proof_random_scalar_hex"],
                                 label + " proof_random_scalar_hex"), "big")
        if not (0 < r < n): return "proof_random_scalar_hex out of scalar range"
        pks_pt = oprf_deser(want_pks, p, a, b, label + " pks_hex")
        # GenerateProof (§2.2.1) with fixed r, over one-item lists (§3.3.2)
        M, Z = oprf_composites(sks, pks_pt, [be_pt], [ee_pt], ctx, p, a, n)
        c = oprf_challenge(pks_pt, M, Z, oprf_pt_mul(r, G1, p, a, n),
                           oprf_pt_mul(r, M, p, a, n), ctx, n)
        s = (r - c * sks) % n
        got_proof = c.to_bytes(32, "big") + s.to_bytes(32, "big")
        if got_proof != want_proof:
            return "recomputed Proof %s != proof_hex %s" % (got_proof.hex(), want_proof.hex())
        # VerifyProof (§2.2.2) on the vector's proof bytes must pass
        vc = int.from_bytes(want_proof[:32], "big")
        vs = int.from_bytes(want_proof[32:], "big")
        Mv, Zv = oprf_composites(None, pks_pt, [be_pt], [ee_pt], ctx, p, a, n)
        t2 = oprf_pt_add(oprf_pt_mul(vs, G1, p, a, n),
                         oprf_pt_mul(vc, pks_pt, p, a, n), p, a)
        t3 = oprf_pt_add(oprf_pt_mul(vs, Mv, p, a, n),
                         oprf_pt_mul(vc, Zv, p, a, n), p, a)
        if oprf_challenge(pks_pt, Mv, Zv, t2, t3, ctx, n) != vc:
            return "VerifyProof(proof_hex) failed — challenge mismatch"

_MLDSA = {}
def _mldsa_ctx():
    # From-scratch FIPS 204 / Dilithium NTT reference, distinct from the C99
    # under test: zetas DERIVED here from zeta=1753 (never read from the C), plus
    # a schoolbook negacyclic-convolution second oracle for the product vectors.
    if _MLDSA: return _MLDSA
    Q=8380417; N=256; MONT=(1<<32)%Q; QINV=pow(Q,-1,1<<32); ROOT=1753
    F=(MONT*MONT%Q)*pow(N,-1,Q)%Q
    def brv8(i): return int('{:08b}'.format(i)[::-1],2)
    def smod(x):
        x%=Q; return x-Q if x>Q//2 else x
    Z=[smod(MONT*pow(ROOT,brv8(i),Q)%Q) for i in range(N)]
    def mr(a):
        t=((a&0xFFFFFFFF)*QINV)&0xFFFFFFFF
        if t>=(1<<31): t-=(1<<32)
        return (a-t*Q)>>32
    def ntt(p):
        p=p[:]; k=0; L=128
        while L>=1:
            s=0
            while s<N:
                k+=1; z=Z[k]
                for j in range(s,s+L):
                    t=mr(z*p[j+L]); p[j+L]=p[j]-t; p[j]=p[j]+t
                s+=2*L
            L>>=1
        return p
    def inv(p):
        p=p[:]; k=256; L=1
        while L<N:
            s=0
            while s<N:
                k-=1; z=-Z[k]
                for j in range(s,s+L):
                    t=p[j]; p[j]=t+p[j+L]; p[j+L]=mr(z*(t-p[j+L]))
                s+=2*L
            L<<=1
        return [mr(F*x) for x in p]
    def sb(a,b):
        r=[0]*N
        for i in range(N):
            for j in range(N):
                k=i+j; v=a[i]*b[j]%Q
                if k>=N: r[k-N]=(r[k-N]-v)%Q
                else: r[k]=(r[k]+v)%Q
        return [smod(x) for x in r]
    def prod(a,b):
        na,nb=ntt(a[:]),ntt(b[:]); pw=[mr(na[i]*nb[i]) for i in range(N)]
        return [smod(x) for x in inv(pw[:])]
    def dft(a):
        # INDEPENDENT forward-NTT oracle (direct evaluation, no butterfly/zetas reuse):
        # ntt(a)[j] == sum_i a[i]*root^(i*(2*brv8(j)+1)) mod q, standard domain.
        out=[0]*N
        for j in range(N):
            e=(2*brv8(j)+1)%512; acc=0
            for i in range(N): acc=(acc+a[i]*pow(ROOT,(i*e)%512,Q))%Q
            out[j]=acc%Q
        return out
    _MLDSA.update(dict(Q=Q,N=N,smod=smod,ntt=ntt,sb=sb,prod=prod,dft=dft,
                       ok=(QINV==58728449 and Z[1]==25847 and F==41978)))
    return _MLDSA

def chk_mldsa_pack(vec, label):
    # FIPS 204 coefficient bit-packing. Two INDEPENDENT checks (not a round-trip
    # tautology): recompute the LSB-first packed bytes AND re-extract each field
    # by a direct bit-slice (absolute-offset, a distinct code path). t1 is also
    # cross-checked vs the canonical reference pack_t1 formula.
    Q = 8380417; N = 256; D = 13
    G1_17 = 1 << 17; G1_19 = 1 << 19; G2_88 = (Q-1)//88; G2_32 = (Q-1)//32
    def pack_bits(vals, bits):
        total = (len(vals)*bits+7)//8; out = bytearray(total); acc = 0; nb = 0; oi = 0
        for v in vals:
            acc |= (v & ((1<<bits)-1)) << nb; nb += bits
            while nb >= 8: out[oi] = acc & 0xFF; oi += 1; acc >>= 8; nb -= 8
        if nb: out[oi] = acc & 0xFF
        return bytes(out)
    def unpack_bits(buf, n, bits):
        vals=[]; acc=0; nb=0; bi=0
        for _ in range(n):
            while nb < bits: acc |= buf[bi] << nb; bi += 1; nb += 8
            vals.append(acc & ((1<<bits)-1)); acc >>= bits; nb -= bits
        return vals
    def slice_field(buf, i, bits):
        v = 0
        for b in range(bits):
            k = i*bits + b; v |= ((buf[k>>3] >> (k&7)) & 1) << b
        return v
    def ref_pack_t1(a):
        r = bytearray(320)
        for i in range(N//4):
            r[5*i+0] = a[4*i+0] & 0xFF
            r[5*i+1] = ((a[4*i+0]>>8) | (a[4*i+1]<<2)) & 0xFF
            r[5*i+2] = ((a[4*i+1]>>6) | (a[4*i+2]<<4)) & 0xFF
            r[5*i+3] = ((a[4*i+2]>>4) | (a[4*i+3]<<6)) & 0xFF
            r[5*i+4] = (a[4*i+3]>>2) & 0xFF
        return bytes(r)
    need(vec, ["kind", "coeffs", "bits", "bytes_hex"], label)
    kind = vec["kind"]; bits = int(vec["bits"])
    coeffs = [int(x) for x in vec["coeffs"]]
    if len(coeffs) != N: return "coeffs is not 256 ints"
    buf = unhex(vec["bytes_hex"], label + " bytes_hex")
    if kind == "t1":    fields = coeffs
    elif kind == "t0":  fields = [(1 << (D-1)) - c for c in coeffs]
    elif kind == "eta": fields = [int(vec["eta"]) - c for c in coeffs]
    elif kind == "w1":  fields = coeffs
    elif kind == "z":   fields = [int(vec["gamma1"]) - c for c in coeffs]
    else: return "unknown mldsa_pack kind %r" % kind
    if pack_bits(fields, bits) != buf: return "repacked bytes != bytes_hex"
    if any(slice_field(buf, i, bits) != fields[i] for i in range(N)): return "bit-slice oracle != fields"
    if unpack_bits(buf, N, bits) != fields: return "unpack != fields"
    if kind == "t1" and ref_pack_t1(coeffs) != buf: return "!= reference pack_t1"

def chk_mldsa_sample(vec, label):
    # FIPS 204 / Dilithium rejection samplers over python hashlib SHAKE — an
    # implementation of SHAKE DISTINCT from the C determ_shake under test (and
    # proven byte-equal to it in R62). Recompute each vector and match the stored
    # output byte-for-byte, plus the structural invariants.
    import hashlib
    Q = 8380417; N = 256
    def sample_uniform(seed):
        buf = hashlib.shake_128(seed).digest(4096); i = 0; a = []
        while len(a) < N:
            if i + 3 > len(buf): buf = hashlib.shake_128(seed).digest(len(buf) + 4096)
            t = buf[i] | (buf[i+1] << 8) | ((buf[i+2] & 0x7F) << 16); i += 3
            if t < Q: a.append(t)
        return a
    def sample_eta(seed, eta):
        buf = hashlib.shake_256(seed).digest(4096); i = 0; a = []
        while len(a) < N:
            if i >= len(buf): buf = hashlib.shake_256(seed).digest(len(buf) + 4096)
            b = buf[i]; i += 1
            for z in (b & 0x0F, b >> 4):
                if len(a) >= N: break
                if eta == 2:
                    if z < 15: a.append(2 - (z % 5))
                else:
                    if z < 9: a.append(4 - z)
        return a
    def sample_in_ball(seed, tau):
        buf = hashlib.shake_256(seed).digest(8 + 4096)
        signs = int.from_bytes(buf[:8], "little"); pos = 8; c = [0]*N
        for i in range(N - tau, N):
            while True:
                if pos >= len(buf): buf = hashlib.shake_256(seed).digest(len(buf) + 4096)
                j = buf[pos]; pos += 1
                if j <= i: break
            c[i] = c[j]; c[j] = 1 - 2*(signs & 1); signs >>= 1
        return c
    # INDEPENDENT value-mapping representations (spec TABLE / stdlib, NOT the
    # shared arithmetic rule) — catch a mapping wrong in both C and python.
    ETA2=[2,1,0,-1,-2,2,1,0,-1,-2,2,1,0,-1,-2]; ETA4=[4,3,2,1,0,-1,-2,-3,-4]; SGN={0:1,1:-1}
    def sample_uniform_indep(seed):
        buf=hashlib.shake_128(seed).digest(4096); i=0; a=[]
        while len(a)<N:
            if i+3>len(buf): buf=hashlib.shake_128(seed).digest(len(buf)+4096)
            t=int.from_bytes(bytes([buf[i],buf[i+1],buf[i+2]&0x7F]),"little"); i+=3
            if t<Q: a.append(t)
        return a
    def sample_eta_indep(seed,eta):
        tbl=ETA2 if eta==2 else ETA4; buf=hashlib.shake_256(seed).digest(4096); i=0; a=[]
        while len(a)<N:
            if i>=len(buf): buf=hashlib.shake_256(seed).digest(len(buf)+4096)
            b=buf[i]; i+=1
            for z in (b&0x0F,b>>4):
                if len(a)>=N: break
                if z<len(tbl): a.append(tbl[z])
        return a
    def sample_in_ball_indep(seed,tau):
        buf=hashlib.shake_256(seed).digest(8+4096); signs=int.from_bytes(buf[:8],"little"); pos=8; c=[0]*N
        for i in range(N-tau,N):
            while True:
                if pos>=len(buf): buf=hashlib.shake_256(seed).digest(len(buf)+4096)
                j=buf[pos]; pos+=1
                if j<=i: break
            c[i]=c[j]; c[j]=SGN[signs&1]; signs>>=1
        return c
    G1_17=1<<17; G1_19=1<<19
    def sample_gamma1(seed,g1):
        bits=18 if g1==G1_17 else 20; buf=hashlib.shake_256(seed).digest(N*bits//8)
        vals=[]; acc=0; nb=0; bi=0
        for _ in range(N):
            while nb<bits: acc|=buf[bi]<<nb; bi+=1; nb+=8
            vals.append(acc&((1<<bits)-1)); acc>>=bits; nb-=bits
        return [g1-f for f in vals]
    def sample_gamma1_indep(seed,g1):
        # INDEPENDENT field read: bit-slice by absolute offset (not word-at-a-time).
        bits=18 if g1==G1_17 else 20; buf=hashlib.shake_256(seed).digest(N*bits//8); out=[]
        for i in range(N):
            v=0
            for b in range(bits):
                k=i*bits+b; v|=((buf[k>>3]>>(k&7))&1)<<b
            out.append(g1-v)
        return out
    need(vec, ["kind", "seed_hex", "out"], label)
    seed = unhex(vec["seed_hex"], label + " seed_hex")
    out = vec["out"]
    if not isinstance(out, list) or len(out) != N:
        return "out is not a 256-int array"
    out = [int(x) for x in out]
    kind = vec["kind"]
    if kind == "uniform":
        if any(not (0 <= c < Q) for c in out): return "uniform out-of-range"
        if sample_uniform(seed) != out: return "recomputed sample_uniform != out"
        if sample_uniform_indep(seed) != out: return "independent (int.from_bytes) read disagrees"
    elif kind == "eta":
        eta = int(vec["eta"])
        if eta not in (2, 4): return "eta must be 2 or 4"
        if any(not (-eta <= c <= eta) for c in out): return "eta out-of-range"
        if sample_eta(seed, eta) != out: return "recomputed sample_eta != out"
        if sample_eta_indep(seed, eta) != out: return "independent spec-TABLE mapping disagrees"
    elif kind == "in_ball":
        tau = int(vec["tau"])
        if not (0 <= tau <= N): return "tau out of [0,256]"
        nz = [x for x in out if x]
        if len(nz) != tau or any(x not in (-1, 1) for x in nz) or sum(x*x for x in out) != tau:
            return "not exactly tau +/-1 (||c||^2 != tau)"
        if sample_in_ball(seed, tau) != out: return "recomputed sample_in_ball != out"
        if sample_in_ball_indep(seed, tau) != out: return "independent sign-TABLE mapping disagrees"
    elif kind == "gamma1":
        g1 = int(vec["gamma1"])
        if g1 not in (G1_17, G1_19): return "gamma1 must be 2^17 or 2^19"
        if any(not (-g1 < c <= g1) for c in out): return "gamma1 out of (-g1, g1]"
        if sample_gamma1(seed, g1) != out: return "recomputed sample_gamma1 != out"
        if sample_gamma1_indep(seed, g1) != out: return "independent bit-slice field read disagrees"
    else:
        return "unknown mldsa_sample kind %r" % kind

def chk_mldsa_ntt(vec, label):
    m=_mldsa_ctx()
    if not m["ok"]: return "internal NTT reference constants drifted (runner bug)"
    N=m["N"]
    def ints(a, fld):
        if not isinstance(a, list) or len(a)!=N: return None
        return [int(x) for x in a]
    t=vec.get("type")
    if t=="ntt":
        need(vec, ["in","ntt_out"], label)
        pin=ints(vec["in"],"in"); want=ints(vec["ntt_out"],"ntt_out")
        if pin is None or want is None: return "in/ntt_out is not a 256-int array"
        got=m["ntt"](pin[:])
        if got!=want: return "recomputed ntt != ntt_out"
        # independent direct-DFT oracle (no butterfly reuse) must agree mod q
        dref=m["dft"](pin); Q=m["Q"]
        if any((want[j]-dref[j])%Q for j in range(m["N"])):
            return "ntt_out disagrees with the independent direct-DFT oracle"
    elif t=="product":
        need(vec, ["a","b","prod"], label)
        a=ints(vec["a"],"a"); b=ints(vec["b"],"b"); want=ints(vec["prod"],"prod")
        if a is None or b is None or want is None: return "a/b/prod is not a 256-int array"
        fast=m["prod"](a,b); slow=m["sb"](a,b)
        if fast!=slow: return "fast ring-product != schoolbook oracle (runner bug)"
        if [m["smod"](x) for x in want]!=slow: return "stored prod != schoolbook oracle"
    else:
        return "unknown mldsa_ntt vector type %r" % t

def chk_sha3_shake(vec, label):
    # FIPS 202 SHA-3 / SHAKE, recomputed with python hashlib (sha3_256,
    # sha3_512, shake_128, shake_256) — an independent Keccak, distinct from
    # the C99 sha3.c the binary side runs. Per-vector "alg" discriminator;
    # SHAKE carries "outlen" (XOF), the fixed-length hashes must not.
    need(vec, ["alg", "msg_hex", "digest_hex"], label)
    alg = vec["alg"]
    msg = unhex(vec["msg_hex"], label + " msg_hex")
    want = unhex(vec["digest_hex"], label + " digest_hex").hex()
    if alg == "SHA3-256":
        if "outlen" in vec: return "fixed-length alg carries outlen"
        if len(want) != 64: return "SHA3-256 digest_hex is not 32 bytes"
        got = hashlib.sha3_256(msg).hexdigest()
    elif alg == "SHA3-512":
        if "outlen" in vec: return "fixed-length alg carries outlen"
        if len(want) != 128: return "SHA3-512 digest_hex is not 64 bytes"
        got = hashlib.sha3_512(msg).hexdigest()
    elif alg == "SHAKE128":
        need(vec, ["outlen"], label)
        outlen = int(vec["outlen"])
        if len(want) != 2 * outlen: return "SHAKE128 digest_hex length != 2*outlen"
        got = hashlib.shake_128(msg).hexdigest(outlen)
    elif alg == "SHAKE256":
        need(vec, ["outlen"], label)
        outlen = int(vec["outlen"])
        if len(want) != 2 * outlen: return "SHAKE256 digest_hex length != 2*outlen"
        got = hashlib.shake_256(msg).hexdigest(outlen)
    else:
        return "unknown sha3/shake alg %r" % alg
    if got != want: return "recomputed %s != digest_hex %s" % (got, want)

def chk_frost_ed25519_rfc9591(vec, label):
    # RFC 9591 E.1 FROST(Ed25519, SHA-512): the scalar-arithmetic subset a
    # python oracle can recompute WITHOUT edwards point math — (a) the Shamir
    # shares f(i) = sk + c1*i mod L, (b) the aggregate z = sum(z_i) mod L,
    # (c) the aggregate signature verifying as plain Ed25519 under the group
    # public key (pyca is the second independent oracle). The full point-side
    # re-derivation (public shares, binding factors per §4.4, R) was done at
    # import time (R48) and is recorded in the file's source string; the
    # BINARY half additionally re-derives shares/group_pk through
    # determ_frost_keygen_trusted. L is the standard Ed25519 group order —
    # self-checking here: a wrong L fails the share equations against the
    # RFC-published values.
    if vec.get("type") != "frost_sign":
        return "unknown frost_ed25519_rfc9591 vector type %r" % vec.get("type")
    need(vec, ["group_secret_key_hex", "group_public_key_hex", "message_hex",
               "share_polynomial_coefficients_hex", "participant_shares",
               "round_two_outputs", "sig_hex", "min_participants",
               "max_participants"], label)
    L = 2**252 + 27742317777372353535851937790883648493
    sk = int.from_bytes(unhex(vec["group_secret_key_hex"], label + " sk"), "little")
    coeffs = [int.from_bytes(unhex(c, label + " coeff"), "little")
              for c in vec["share_polynomial_coefficients_hex"]]
    if len(coeffs) != int(vec["min_participants"]) - 1:
        return "coefficient count != t-1"
    for ps in vec["participant_shares"]:
        i = int(ps["identifier"])
        want = unhex(ps["participant_share_hex"], label + " share")
        f = sk
        for k, c in enumerate(coeffs, start=1):
            f = (f + c * pow(i, k, L)) % L
        if f.to_bytes(32, "little") != want:
            return "Shamir share f(%d) mismatch: %064x != %s" % (i, f, want.hex())
    sig = unhex(vec["sig_hex"], label + " sig_hex")
    if len(sig) != 64: return "sig_hex is not 64 bytes"
    zsum = 0
    for rt in vec["round_two_outputs"]:
        zsum = (zsum + int.from_bytes(unhex(rt["sig_share_hex"], label + " z"),
                                      "little")) % L
    if zsum.to_bytes(32, "little") != sig[32:]:
        return "sum(sig_shares) mod L != sig[32:] (aggregate z mismatch)"
    try:
        Ed25519PublicKey.from_public_bytes(
            unhex(vec["group_public_key_hex"], label + " pk")
        ).verify(sig, unhex(vec["message_hex"], label + " msg"))
    except Exception as e:
        return "aggregate signature does not verify as plain Ed25519 under the group pk (%s)" % e

def chk_mldsa_keygen(vec, label):
    # ML-DSA (FIPS 204) KeyGen KAT — the AUTHORITATIVE NIST ACVP oracle (seed ->
    # pk/sk). Recompute ML-DSA.KeyGen_internal(seed) through the INDEPENDENT python
    # keygen (tools/verify_mldsa_keygen.py; hashlib SHAKE + a from-scratch python
    # NTT, distinct from the C determ NTT under test) and match the stored ACVP
    # pk/sk byte-for-byte. Both C and python are pinned against the frozen NIST
    # bytes, so a bug shared by both is still caught by the external reference.
    # The wrapper cd's to the repo root before piping this heredoc to `python -`,
    # so cwd is the repo root and "tools" holds verify_mldsa_keygen (there is no
    # reliable __file__ under `python -`).
    if "tools" not in sys.path: sys.path.insert(0, "tools")
    try:
        import verify_mldsa_keygen as vk
    except Exception as e:
        return "cannot import verify_mldsa_keygen (%s)" % e
    need(vec, ["paramSet", "seed_hex", "pk_hex", "sk_hex"], label)
    ps = vec["paramSet"]
    if ps not in vk.PARAMS: return "unknown paramSet %r" % ps
    k, l, eta = vk.PARAMS[ps]
    seed = unhex(vec["seed_hex"], label + " seed_hex")
    if len(seed) != 32: return "seed must be 32 bytes"
    pk, sk = vk.keygen(seed, k, l, eta)
    if pk.hex().upper() != vec["pk_hex"].upper(): return "recomputed pk != ACVP reference"
    if sk.hex().upper() != vec["sk_hex"].upper(): return "recomputed sk != ACVP reference"
    if pk[:32] != sk[:32]: return "pk/sk rho prefix mismatch"

def _import_vs():
    if "tools" not in sys.path: sys.path.insert(0, "tools")
    import verify_mldsa_sign as vs
    return vs
def chk_mldsa_sign(vec, label):
    # ML-DSA (FIPS 204) Sign_internal KAT — the NIST ACVP sigGen (deterministic)
    # oracle. Recompute the signature through the INDEPENDENT python signer
    # (tools/verify_mldsa_sign.py; hashlib SHAKE + from-scratch NTT, distinct from
    # the C) and match the stored ACVP signature byte-for-byte.
    try: vs = _import_vs()
    except Exception as e: return "cannot import verify_mldsa_sign (%s)" % e
    need(vec, ["paramSet", "mprime_hex", "sk_hex", "sig_hex"], label)
    ps = vec["paramSet"]
    if ps not in vs.PARAMS: return "unknown paramSet %r" % ps
    got = vs.sign_internal(unhex(vec["sk_hex"], label+" sk"),
                           unhex(vec["mprime_hex"], label+" mprime"), vs.PARAMS[ps])
    if got.hex() != vec["sig_hex"].lower(): return "recomputed signature != ACVP reference"
def chk_mldsa_verify(vec, label):
    # ML-DSA (FIPS 204) Verify_internal KAT — the NIST ACVP sigVer oracle.
    # Recompute accept/reject through the independent python verifier and match the
    # stored testPassed flag (exercises the norm bounds + the hint-decode rejects).
    try: vs = _import_vs()
    except Exception as e: return "cannot import verify_mldsa_sign (%s)" % e
    need(vec, ["paramSet", "mprime_hex", "pk_hex", "sig_hex", "expected"], label)
    ps = vec["paramSet"]
    if ps not in vs.PARAMS: return "unknown paramSet %r" % ps
    try:
        got = vs.verify_internal(unhex(vec["pk_hex"], label+" pk"),
                                 unhex(vec["mprime_hex"], label+" mprime"),
                                 unhex(vec["sig_hex"], label+" sig"), vs.PARAMS[ps])
    except Exception:
        got = False
    if bool(got) != bool(vec["expected"]):
        return "verify %s, expected %s (%s)" % (got, vec["expected"], vec.get("reason",""))

def chk_pedersen(vec, label):
    # §3.19 Pedersen commitment over P-256 — independent recomputation via the
    # from-scratch EC + RFC 9380 hash_to_curve in tools/verify_pedersen.py: H and
    # every C = v*G + r*H are recomputed here, never trusted from the file. Same
    # dual-oracle posture as the mldsa checkers (C determ vs this python).
    if "tools" not in sys.path: sys.path.insert(0, "tools")
    try:
        import verify_pedersen as vp
    except Exception as e:
        return "cannot import verify_pedersen (%s)" % e
    return vp.check_pedersen(vec, label)

def chk_bp_ipa(vec, label):
    # §3.19 inc.4 Bulletproofs inner-product argument — recompute the whole proof
    # (P + L/R points + final a,b) from the stored witness through the independent
    # from-scratch Python IPA in tools/verify_bp_ipa.py, and match the frozen bytes.
    # Same dual-oracle posture: the C determ IPA is checked against this Python.
    if "tools" not in sys.path: sys.path.insert(0, "tools")
    try:
        import verify_bp_ipa as vi
    except Exception as e:
        return "cannot import verify_bp_ipa (%s)" % e
    return vi.check_ipa(vec, label)

def chk_bp_rangeproof(vec, label):
    # §3.19 inc.5 Bulletproofs range proof — rebuild the prover randomness from
    # (n, seed), recompute V + the whole proof (A/S/T1/T2/taux/mu/that + the inner
    # IPA) through the independent from-scratch Python in tools/verify_bp_rangeproof.py,
    # and match the frozen bytes. Same dual-oracle posture as bp_ipa.
    if "tools" not in sys.path: sys.path.insert(0, "tools")
    try:
        import verify_bp_rangeproof as vr
    except Exception as e:
        return "cannot import verify_bp_rangeproof (%s)" % e
    return vr.check_rangeproof(vec, label)

def chk_bp_agg_rangeproof(vec, label):
    # §3.19 inc.6 aggregated range proof — rebuild randomness from (m,n,seed), recompute
    # the m value commitments + the whole proof through the independent from-scratch Python
    # in tools/verify_bp_agg_rangeproof.py, and match the frozen bytes. Same dual-oracle posture.
    if "tools" not in sys.path: sys.path.insert(0, "tools")
    try:
        import verify_bp_agg_rangeproof as va
    except Exception as e:
        return "cannot import verify_bp_agg_rangeproof (%s)" % e
    return va.check_agg_rangeproof(vec, label)

def chk_ff_pedersen(vec, label):
    # §3.20 finite-field Pedersen over RFC 3526 MODP-3072 — recompute g^v*h^r mod p
    # (or the homomorphic product) through the independent from-scratch Python in
    # tools/verify_ff_pedersen.py (native bignums), and match the frozen 384-byte bytes.
    if "tools" not in sys.path: sys.path.insert(0, "tools")
    try:
        import verify_ff_pedersen as vf
    except Exception as e:
        return "cannot import verify_ff_pedersen (%s)" % e
    return vf.check_ff_pedersen(vec, label)

def chk_ff_scalar(vec, label):
    # §3.20 inc.3 scalar field mod q — recompute add/mul/inv/reduce/hash_to_scalar
    # through the independent from-scratch Python (tools/verify_ff_scalar.py, native
    # bignums) and match the frozen 384-byte big-endian bytes.
    if "tools" not in sys.path: sys.path.insert(0, "tools")
    try:
        import verify_ff_scalar as vs
    except Exception as e:
        return "cannot import verify_ff_scalar (%s)" % e
    return vs.check_ff_scalar(vec, label)

CHECKERS = {
    "sha256":             lambda v, l: chk_sha(v, l, "sha256", 32),
    "sha512":             lambda v, l: chk_sha(v, l, "sha512", 64),
    "hmac_sha256":        chk_hmac_sha256,
    "pbkdf2_hmac_sha256": chk_pbkdf2,
    "hkdf_sha256":        chk_hkdf,
    "blake2b":            chk_blake2b,
    "chacha20_poly1305":  lambda v, l: chk_aead(v, l, ChaCha20Poly1305, "nonce_hex"),
    "aes256_gcm":         lambda v, l: chk_aead(v, l, AESGCM, "iv_hex"),
    "ed25519":            chk_ed25519,
    "x25519":             chk_x25519,
    "p256":               chk_p256,
    "p256_h2c":           chk_p256_h2c,
    "p256_oprf":          chk_p256_oprf,
    "frost_ed25519_rfc9591": chk_frost_ed25519_rfc9591,
    "aes256_gcm_decrypt": chk_aes256_gcm_decrypt,
    "chacha20_poly1305_decrypt": chk_chacha20_poly1305_decrypt,
    "argon2id": chk_argon2id,
    "xchacha20_poly1305_decrypt": chk_xchacha20_poly1305_decrypt,
    "ed25519_verify_strict": chk_ed25519_verify_strict,
    "base64_strict": chk_base64_strict,
    "sha3_shake": chk_sha3_shake,
    "mldsa_ntt": chk_mldsa_ntt,
    "mldsa_sample": chk_mldsa_sample,
    "mldsa_pack": chk_mldsa_pack,
    "mldsa_keygen": chk_mldsa_keygen,
    "mldsa_sign": chk_mldsa_sign,
    "mldsa_verify": chk_mldsa_verify,
    "pedersen": chk_pedersen,
    "bp_ipa": chk_bp_ipa,
    "bp_rangeproof": chk_bp_rangeproof,
    "bp_agg_rangeproof": chk_bp_agg_rangeproof,
    "ff_pedersen": chk_ff_pedersen,
    "ff_scalar": chk_ff_scalar,
}

files = sorted(glob.glob(os.path.join("tools", "vectors", "*.json")))
names = {os.path.basename(f) for f in files}
for missing in sorted(EXPECTED - names):
    bad("expected vector file tools/vectors/%s is MISSING" % missing)
for extra in sorted(names - EXPECTED):
    ok("note: extra vector file %s (validated below; add it to EXPECTED when intentional)" % extra)

for path in files:
    base = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except Exception as e:
        bad("%s: not valid JSON (%s)" % (base, e))
        continue
    schema_bad = False
    for k, t in (("primitive", str), ("source", str), ("vectors", list)):
        if not isinstance(obj.get(k), t) or not obj.get(k):
            bad("%s: schema — missing/empty %r (must be non-empty %s)" % (base, k, t.__name__))
            schema_bad = True
    if schema_bad:
        continue
    prim = obj["primitive"]
    checker = CHECKERS.get(prim)
    if checker is None:
        bad("%s: unknown primitive %r — no recomputation path (fail-closed)" % (base, prim))
        continue
    ok("%s: schema valid (primitive=%s, %d vectors, source: %s)"
       % (base, prim, len(obj["vectors"]), obj["source"].split(";")[0]))
    for i, vec in enumerate(obj["vectors"]):
        label = "%s[%d]" % (base, i)
        name = vec.get("name", "(unnamed)") if isinstance(vec, dict) else "(not an object)"
        if not isinstance(vec, dict):
            bad("%s: vector is not a JSON object" % label)
            continue
        try:
            err = checker(vec, label)
        except Exception as e:
            err = "exception during recomputation: %s" % e
        if err:
            bad("%s %s: %s" % (label, name, err))
        else:
            ok("%s %s: recomputation matches byte-for-byte" % (label, name))
PYEOF
)
rc=$?
echo "$OUT"
if [ $rc -ne 0 ]; then
  echo "  bad: python verifier exited non-zero (rc=$rc) before completing"
fi

MISMATCHES=$(printf '%s\n' "$OUT" | grep -c '^  bad:')
[ $rc -ne 0 ] && MISMATCHES=$((MISMATCHES + 1))
OKS=$(printf '%s\n' "$OUT" | grep -c '^  ok:')

echo ""
if [ "$MISMATCHES" -eq 0 ] && [ "$OKS" -gt 0 ]; then
  echo "  PASS: test_c99_vector_files"
  exit 0
else
  [ "$OKS" -eq 0 ] && echo "  bad: zero ok-lines — verifier produced no positive evidence (treated as failure)"
  [ "$MISMATCHES" -eq 0 ] && MISMATCHES=1
  echo "  FAIL: test_c99_vector_files ($MISMATCHES mismatches)"
  exit 1
fi
