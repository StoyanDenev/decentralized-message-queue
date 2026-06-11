#!/usr/bin/env bash
# test_c99_vector_files.sh — CRYPTO-C99-SPEC §3.13 test-vector validation, the
# OFFLINE half: every vector file in tools/vectors/<primitive>.json is (1)
# schema-validated and (2) recomputed end-to-end with an INDEPENDENT
# implementation (python hashlib / hmac / pbkdf2_hmac for the hash/MAC/KDF
# families; cryptography.hazmat ChaCha20Poly1305 / AESGCM / Ed25519 / X25519
# for the AEAD + curve families). Any byte that drifts from the recomputation
# turns this RED, so a corrupted / hand-edited / fabricated vector can never
# sit silently in the corpus that the binary-side test-*-c99 subcommands and
# future CI gates consume.
#
# Provenance of the corpus (see each file's "source" field): the NIST SHA
# examples (FIPS 180-2 Appendix B/C numbering — FIPS 180-4 dropped the worked
# examples and points to the NIST CSRC examples page; the empty-message case
# is NIST CAVP ShortMsg Len=0), RFC 4231, RFC 7914 §11, RFC 5869 A.1-A.3, RFC 7693, RFC 8439
# §2.8.2, the McGrew-Viega GCM AES-256 KATs, RFC 8032 §7.1 TEST 1-3, and
# RFC 7748 §5.2 + §6.1. Where the same vector is hardcoded in a src/main.cpp
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
    "aes256_gcm.json", "ed25519.json", "x25519.json",
}

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
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
