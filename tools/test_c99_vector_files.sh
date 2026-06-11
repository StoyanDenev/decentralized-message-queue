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
# on hashlib.sha256 with curve p/a/b from the same p256_params() recovery).
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
    "p256_h2c.json",
}

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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
