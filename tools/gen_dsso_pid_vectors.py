#!/usr/bin/env python3
"""tools/gen_dsso_pid_vectors.py — the fixture generator for `determ-dsso selftest-pid`.

WHAT IT PRODUCES. `dapps/dsso/dsso_pid_vectors.h`: every SD-JWT VC presentation,
disclosure, Key Binding JWT, Token Status List token, zlib blob and P-256 key the
gate needs, emitted as C literals. The header says DO NOT EDIT because this file
is the editor.

WHY IT IS COMMITTED. The vectors are frozen data. Frozen data that cannot be
regenerated from the repository is data nobody can audit or extend: a reviewer
who wants to know whether an accept case really is an accept case, or who needs a
new rejection vector, would otherwise have to reconstruct the generator. The
2026-09-17 PID increment landed the vectors without this file and recorded the
gap; this is the repair.

WHAT IT ANCHORS TO, in order of independence.
  1. **RFC 6979 §A.2.5** (P-256, SHA-256) — the published deterministic-ECDSA
     known-answer vectors. `selftest_6979()` below checks this file's own signer
     against them BEFORE any fixture is emitted, so the generator is anchored to a
     published vector rather than to itself. The SAME published vectors are
     re-checked inside the C gate against `dsso_es256_verify`, so the C verifier
     does not depend on this generator at all.
  2. **OpenSSL**, through the `cryptography` package (`openssl_verify()`): every
     signature this file produces is verified by an independent third-party
     implementation before it is written out.
  3. **The C verifier under test**, at gate time.
  So a shipped accept case is THREE implementations agreeing — a pure-Python
  P-256 (different language, different representation, affine arithmetic),
  OpenSSL, and the C code — not a C signer agreeing with a C verifier, which is
  the failure mode a self-generated corpus has.

Everything else the fixtures contain (SHA-256 digests, HMAC, zlib, base64url,
JSON) comes from the Python standard library.

DETERMINISM. Every secret scalar, salt and nonce below is a fixed constant and
ECDSA k is RFC 6979 deterministic, so two runs produce byte-identical output. A
run that changes the committed header is a change to the fixtures and must be
reviewed as one; `git diff --stat dapps/dsso/dsso_pid_vectors.h` after a run is
the check.

REGENERATE (from the repository root):

    python3 tools/gen_dsso_pid_vectors.py        # rewrites the header in place
    git diff --stat dapps/dsso/dsso_pid_vectors.h   # expect: no change
    cmake --build build-linux --target determ-dsso && \
      ./build-linux/determ-dsso selftest-pid     # expect: 156 assertions, PASS

Requires python3 >= 3.8 and the `cryptography` package for the OpenSSL
cross-check. The cross-check is NOT optional: without it the vectors rest on one
implementation, so a missing `cryptography` is a hard failure, not a skipped step.

This generator is NOT part of any gate and nothing in the build depends on it —
`tools/run_all.sh` never invokes it and `determ-dsso` has no file IO. It is run by
hand when a fixture must change. See `docs/proofs/DssoPidVerification.md`.
"""

import hashlib
import hmac
import json
import os
import zlib
import base64
import sys

# Repo-relative, resolved from THIS FILE's location, so the generator writes the
# committed header whatever directory it is invoked from (and never a stale
# absolute path from the worktree it was first written in).
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "dapps", "dsso", "dsso_pid_vectors.h")

# ── P-256, from scratch ─────────────────────────────────────────────────────
P  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
N  = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
A  = (-3) % P
B  = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


def inv(x, m):
    return pow(x, m - 2, m)


def pt_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def pt_mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = pt_add(r, pt)
        pt = pt_add(pt, pt)
        k >>= 1
    return r


def on_curve(pt):
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def pub(d):
    q = pt_mul(d, (GX, GY))
    assert on_curve(q)
    return q


# RFC 6979 §3.2 deterministic nonce, HMAC-SHA256.
def rfc6979_k(d, h1):
    hlen = 32
    v = b"\x01" * hlen
    k = b"\x00" * hlen
    x = d.to_bytes(32, "big")
    e = int.from_bytes(h1, "big")
    if e >= N:
        e -= N
    m = e.to_bytes(32, "big")
    k = hmac.new(k, v + b"\x00" + x + m, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + m, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def ecdsa_sign(d, msg):
    h = hashlib.sha256(msg).digest()
    e = int.from_bytes(h, "big")
    if e >= N:
        e -= N
    while True:
        k = rfc6979_k(d, h)
        pt = pt_mul(k, (GX, GY))
        r = pt[0] % N
        if r == 0:
            continue
        s = inv(k, N) * (e + r * d) % N
        if s == 0:
            continue
        return r, s


def ecdsa_verify(q, msg, r, s):
    if not (1 <= r < N and 1 <= s < N):
        return False
    h = hashlib.sha256(msg).digest()
    e = int.from_bytes(h, "big")
    if e >= N:
        e -= N
    w = inv(s, N)
    u1, u2 = e * w % N, r * w % N
    pt = pt_add(pt_mul(u1, (GX, GY)), pt_mul(u2, q))
    if pt is None:
        return False
    return pt[0] % N == r


def sig64(d, msg, high_s=False):
    r, s = ecdsa_sign(d, msg)
    if high_s:
        s = N - s
    assert ecdsa_verify(pub(d), msg, r, s)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# ── self-anchoring: RFC 6979 A.2.5 (P-256 / SHA-256) ────────────────────────
def check_rfc6979():
    d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    q = pub(d)
    assert q[0] == 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6, "pubkey x"
    assert q[1] == 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299, "pubkey y"
    r, s = ecdsa_sign(d, b"sample")
    assert r == 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716, hex(r)
    assert s == 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8, hex(s)
    r, s = ecdsa_sign(d, b"test")
    assert r == 0xF1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367, hex(r)
    assert s == 0x019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083, hex(s)
    print("RFC 6979 A.2.5 (P-256/SHA-256): PASS — this generator's signer is "
          "anchored to a published vector", file=sys.stderr)


# ── cross-check with OpenSSL via `cryptography` ─────────────────────────────
def openssl_verify(q, msg, raw):
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature
    key = ec.EllipticCurvePublicNumbers(q[0], q[1], ec.SECP256R1()).public_key()
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:], "big")
    der = utils.encode_dss_signature(r, s)
    try:
        key.verify(der, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ── JOSE helpers ────────────────────────────────────────────────────────────
def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def jjson(o):
    return json.dumps(o, separators=(",", ":"), sort_keys=False).encode()


def jwt(header, payload, d, sig_over=None, high_s=False, raw_sig=None):
    si = (b64u(jjson(header)) + "." + b64u(jjson(payload))).encode()
    if raw_sig is not None:
        s = raw_sig
    elif d is None:
        s = b""
    else:
        s = sig64(d, sig_over if sig_over is not None else si, high_s=high_s)
    return si.decode() + "." + b64u(s)


def disclosure(salt, name, value):
    return b64u(jjson([salt, name, value]))


def dig(d):
    return b64u(hashlib.sha256(d.encode()).digest())


# ── keys (fixed, from a label — reproducible, no randomness) ────────────────
def key_from(label):
    d = int.from_bytes(hashlib.sha256(("determ-dsso-pid/" + label).encode()).digest(), "big") % (N - 1) + 1
    return d, pub(d)


ISS = "https://pid.example-ms.eu"
ISS2 = "https://pid.example-ms2.eu"
ISS_UNK = "https://rogue.example"
KID = "ms-pid-2026-a"
KID_STATUS = "ms-status-2026-a"
KID_UNK = "ms-pid-2026-z"
RP_ID = "https://dsso.determ.example/rp"
NONCE = "Q1hZWkFCQ0RFRkdISUpLTE1OT1BRUlM"[:32]
NONCE2 = "OTg3NjU0MzIxMDk4NzY1NDMyMTA5ODc2"[:32]
BIND_NONCE = "YmluZGNoYWxsZW5nZS0wMDAxLWFiY2Rl"[:32]

D_ISS, Q_ISS = key_from("issuer-a")
D_ISS2, Q_ISS2 = key_from("issuer-b-substantial")
D_STATUS, Q_STATUS = key_from("status-signer")
D_UNK, Q_UNK = key_from("rogue")
D_HOLDER, Q_HOLDER = key_from("holder")
D_OTHER, Q_OTHER = key_from("other-holder")

NOW = 1789000000          # the gate's fixed "now"
IAT = NOW - 86400 * 30
EXP = NOW + 86400 * 300

URI_MAIN = "https://pid.example-ms.eu/statuslists/1"
URI_EXPIRED = "https://pid.example-ms.eu/statuslists/expired"
URI_WRONGSUB = "https://pid.example-ms.eu/statuslists/wrongsub"
URI_UNTRUSTED = "https://pid.example-ms.eu/statuslists/untrusted"
URI_MISSING = "https://pid.example-ms.eu/statuslists/gone"
URI_BOMB = "https://pid.example-ms.eu/statuslists/bomb"
URI_CROSSISS = "https://pid.example-ms.eu/statuslists/crossiss"
# The SECOND PID Provider publishes its OWN status list, signed by its own key:
# since a status token must come from the credential's own issuer, a credential
# from ISS2 cannot be covered by ISS's list.
URI_MS2 = "https://pid.example-ms2.eu/statuslists/1"

SALT1 = "2GLC42sKQveCfGfryNRN9w"
SALT2 = "eluV5Og3gSNII8EYnsxA_A"
SALT3 = "6Ij7tM-a5iVPGboS5tmvVA"
SALT4 = "eI8ZWm9QnKPpNPeNenHdhQ"
SALT5 = "Qg_O64zqAxe412a108iroA"
SALT6 = "AJx-095VPrpTtN4QMOqROA"

DISC = {
    "family_name": disclosure(SALT1, "family_name", "Petrova"),
    "given_name": disclosure(SALT2, "given_name", "Maria"),
    "birth_date": disclosure(SALT3, "birth_date", "1992-04-17"),
    "pan": disclosure(SALT4, "personal_administrative_number", "9204170000"),
}
DECOY = [dig(disclosure(SALT5, "birth_place", "Sofia")),
         dig(disclosure(SALT6, "resident_address", "ul. Alabin 1"))]

SD_ALL = [dig(v) for v in DISC.values()] + DECOY


def jwk(q):
    return {"kty": "EC", "crv": "P-256",
            "x": b64u(q[0].to_bytes(32, "big")),
            "y": b64u(q[1].to_bytes(32, "big"))}


def base_payload(**over):
    p = {
        "iss": ISS,
        "vct": "urn:eudi:pid:1",
        "iat": IAT,
        "nbf": IAT,
        "exp": EXP,
        "acr": "http://eidas.europa.eu/LoA/high",
        "issuing_country": "BG",
        "cnf": {"jwk": jwk(Q_HOLDER)},
        "status": {"status_list": {"idx": 7, "uri": URI_MAIN}},
        "_sd_alg": "sha-256",
        "_sd": list(SD_ALL),
    }
    p.update(over)
    for k in [k for k, v in p.items() if v is None]:
        del p[k]
    return p


def build(*, header=None, payload=None, issuer_d=D_ISS, issuer_raw_sig=None,
          issuer_sig_over=None, discs=None, kb=True, kb_d=D_HOLDER,
          kb_header=None, kb_payload=None, kb_sd_hash=None, high_s=False):
    hdr = {"alg": "ES256", "typ": "dc+sd-jwt", "kid": KID}
    if header:
        hdr = dict(hdr); hdr.update(header)
        for k in [k for k, v in hdr.items() if v is None]:
            del hdr[k]
    pl = payload if payload is not None else base_payload()
    issued = jwt(hdr, pl, issuer_d, sig_over=issuer_sig_over,
                 high_s=high_s, raw_sig=issuer_raw_sig)
    ds = discs if discs is not None else list(DISC.values())
    prefix = issued + "~" + "".join(d + "~" for d in ds)
    if not kb:
        return prefix
    kh = {"alg": "ES256", "typ": "kb+jwt"}
    if kb_header:
        kh = dict(kh); kh.update(kb_header)
        for k in [k for k, v in kh.items() if v is None]:
            del kh[k]
    kp = {"aud": RP_ID, "nonce": NONCE, "iat": NOW - 5,
          "sd_hash": kb_sd_hash if kb_sd_hash is not None
                     else b64u(hashlib.sha256(prefix.encode()).digest())}
    if kb_payload:
        kp = dict(kp); kp.update(kb_payload)
        for k in [k for k, v in kp.items() if v is None]:
            del kp[k]
    return prefix + jwt(kh, kp, kb_d)


# ── status tokens ───────────────────────────────────────────────────────────
def status_bits(entries, nbytes=32, bits=1):
    """entries: {index: value}. LSB-first packing (draft-ietf-oauth-status-list)."""
    buf = bytearray(nbytes)
    per = 8 // bits
    for i, v in entries.items():
        assert i // per < nbytes
        buf[i * bits // 8] |= (v & ((1 << bits) - 1)) << (i * bits % 8)
    return bytes(buf)


def status_token(sub, entries, *, exp=NOW + 3600, d=D_STATUS, kid=KID_STATUS,
                 iss=ISS, bits=2, lst_override=None):
    raw = status_bits(entries, bits=bits)
    lst = lst_override if lst_override is not None else b64u(zlib.compress(raw, 9))
    hdr = {"alg": "ES256", "typ": "statuslist+jwt", "kid": kid}
    pl = {"iss": iss, "sub": sub, "iat": NOW - 60, "exp": exp,
          "status_list": {"bits": bits, "lst": lst}}
    return jwt(hdr, pl, d)


ENTRIES = {7: 0, 9: 1, 11: 2}

STATUS_FIXTURES = [
    (URI_MAIN, status_token(URI_MAIN, ENTRIES), 0),
    (URI_EXPIRED, status_token(URI_EXPIRED, ENTRIES, exp=NOW - 10), 0),
    (URI_WRONGSUB, status_token(URI_MAIN, ENTRIES), 0),
    (URI_UNTRUSTED, status_token(URI_UNTRUSTED, ENTRIES, d=D_UNK, kid=KID_UNK), 0),
    (URI_MISSING, "", 1),                        # fetch fails outright
    (URI_BOMB, status_token(URI_BOMB, ENTRIES,
                            lst_override=b64u(zlib.compress(b"\x00" * 200000, 9))), 0),
    # A status token for THIS credential's list, validly signed by a DIFFERENT
    # PID Provider that is also on the trust anchor list. Everything about it is
    # well-formed: `sub` matches, the signature verifies against a trusted
    # anchor, it is in date. Only the ISSUER is wrong.
    (URI_CROSSISS, status_token(URI_CROSSISS, ENTRIES, d=D_ISS2,
                                kid=KID + "-b", iss=ISS2), 0),
    (URI_MS2, status_token(URI_MS2, ENTRIES, d=D_ISS2, kid=KID + "-b", iss=ISS2), 0),
]

# ── the vector table ────────────────────────────────────────────────────────
V = []


def add(name, text, note):
    V.append((name, text, note))


ok = build()
add("OK", ok, "the accept case: every rule satisfied")

# rule 1 — structure. These are byte-level and do not need a signer, but they
# are generated here so the gate holds one table.
add("NO_TILDE", ok.split("~")[0], "no `~` at all: not a presentation")
add("FOUR_DOTS", ok.replace("~", "..~", 1), "a JWT with four segments")
add("B64_PAD", ok.replace(ok.split(".")[0], ok.split(".")[0] + "=", 1),
    "base64url padding in the header segment")

# rule 2 — issuer trust
add("ISS_UNKNOWN",
    build(payload=base_payload(iss=ISS_UNK), issuer_d=D_UNK),
    "issuer not in the PID Provider trust anchor list (OIA_12)")
add("KID_UNKNOWN",
    build(header={"kid": KID_UNK}),
    "known issuer, key id not in the trust list")
add("HDR_JWK",
    build(header={"jwk": jwk(Q_UNK)}),
    "header carries its own key: the token choosing its verifier")
add("HDR_X5C",
    build(header={"x5c": ["MIIB"]}),
    "header carries a certificate chain")
add("HDR_CRIT",
    build(header={"crit": ["b64"]}),
    "header demands an extension DSSO does not implement")

# rule 3 — signature
add("ALG_NONE",
    build(header={"alg": "none"}, issuer_d=None),
    "alg: none with an empty signature")
add("ALG_HS256",
    build(header={"alg": "HS256"}),
    "algorithm substitution: HS256 over the issuer's EC key")
add("SIG_WRONG_KEY",
    build(issuer_d=D_UNK),
    "signature by a key that is not the anchor's")
add("SIG_OTHER_BYTES",
    build(issuer_raw_sig=sig64(D_ISS, b"a different signing input")),
    "a real signature by the real key, over different bytes")
add("SIG_TRUNC",
    ok.replace(ok.split("~")[0].split(".")[2], ok.split("~")[0].split(".")[2][:-4], 1),
    "truncated signature")
add("SIG_HIGH_S", build(high_s=True),
    "the malleated (r, n-s) twin: ECDSA accepts it, and the gate asserts it "
    "buys no second acceptance")

# rule 4 — selective disclosure
add("DISC_NO_DIGEST",
    build(discs=list(DISC.values()) + [disclosure(SALT5, "nationality", "BG")]),
    "a disclosure matching no _sd digest")
add("DISC_DUP",
    build(discs=list(DISC.values()) + [DISC["family_name"]]),
    "the same disclosure presented twice")
add("DISC_RESERVED",
    build(payload=base_payload(_sd=SD_ALL + [dig(disclosure(SALT5, "iss", "https://rogue.example"))]),
          discs=list(DISC.values()) + [disclosure(SALT5, "iss", "https://rogue.example")]),
    "a digest-backed disclosure that overwrites a registered claim")
add("DISC_SHADOW",
    build(payload=base_payload(_sd=SD_ALL + [dig(disclosure(SALT5, "issuing_country", "DE"))]),
          discs=list(DISC.values()) + [disclosure(SALT5, "issuing_country", "DE")]),
    "a digest-backed disclosure shadowing a cleartext payload claim")
add("DISC_SHORT_SALT",
    build(payload=base_payload(_sd=SD_ALL + [dig(disclosure("abc", "nationality", "BG"))]),
          discs=list(DISC.values()) + [disclosure("abc", "nationality", "BG")]),
    "a disclosure salt below 128 bits")
add("SD_ALG_OTHER",
    build(payload=base_payload(_sd_alg="sha-512")),
    "_sd_alg naming an algorithm this verifier does not implement")

# rule 5 — holder binding
add("KB_MISSING", build(kb=False), "no Key Binding JWT at all (OIA_02)")
add("KB_OTHER_KEY", build(kb_d=D_OTHER), "KB-JWT signed by a key the credential does not bind")
add("KB_REPLAY",
    build(discs=list(DISC.values())[:3],
          kb_sd_hash=b64u(hashlib.sha256(
              (build().rsplit("~", 1)[0] + "~").encode()).digest())),
    "a KB-JWT lifted from another presentation (sd_hash covers other bytes)")
add("NO_CNF", build(payload=base_payload(cnf=None)),
    "credential asserts no holder key")
add("KB_TYP", build(kb_header={"typ": "JWT"}), "KB-JWT not typed kb+jwt")

# rule 6 — audience and request binding
add("AUD_OTHER", build(kb_payload={"aud": "https://other.example/rp"}),
    "presentation addressed to a different relying party")
add("NONCE_OTHER", build(kb_payload={"nonce": NONCE2}),
    "presentation answering a different request")

# rule 7 — freshness
add("EXPIRED", build(payload=base_payload(exp=NOW - 1000)), "credential past exp by more than the skew")
add("EXP_IN_SKEW", build(payload=base_payload(exp=NOW - 60)),
    "credential past exp by LESS than the configured skew: accepted, and the gate "
    "says so out loud rather than letting the tolerance be invisible")
add("FUTURE_IAT", build(payload=base_payload(iat=NOW + 4000, nbf=NOW + 4000, exp=EXP)),
    "credential issued in the future")
add("NBF_FUTURE", build(payload=base_payload(nbf=NOW + 4000)), "credential not yet valid")
add("CRED_ANCIENT",
    build(payload=base_payload(iat=NOW - 86400 * 4000, nbf=NOW - 86400 * 4000, exp=EXP)),
    "implausibly old credential (beyond max_cred_age)")
add("KB_STALE", build(kb_payload={"iat": NOW - 100000}),
    "presentation minted long before it was offered")

# rule 8 — status
add("REVOKED", build(payload=base_payload(status={"status_list": {"idx": 9, "uri": URI_MAIN}})),
    "credential revoked in the status list")
add("SUSPENDED", build(payload=base_payload(status={"status_list": {"idx": 11, "uri": URI_MAIN}})),
    "credential suspended in the status list")
add("STATUS_STALE",
    build(payload=base_payload(status={"status_list": {"idx": 7, "uri": URI_EXPIRED}})),
    "status token past its own exp: fails CLOSED")
add("STATUS_WRONGSUB",
    build(payload=base_payload(status={"status_list": {"idx": 7, "uri": URI_WRONGSUB}})),
    "status token is for a different list: fails CLOSED")
add("STATUS_UNTRUSTED",
    build(payload=base_payload(status={"status_list": {"idx": 7, "uri": URI_UNTRUSTED}})),
    "status token signed outside the trust anchor list")
add("STATUS_UNAVAIL",
    build(payload=base_payload(status={"status_list": {"idx": 7, "uri": URI_MISSING}})),
    "status token cannot be fetched: fails CLOSED")
add("STATUS_OOR",
    build(payload=base_payload(status={"status_list": {"idx": 5000, "uri": URI_MAIN}})),
    "index past the end of the bitstring: fails CLOSED")
add("STATUS_BOMB",
    build(payload=base_payload(status={"status_list": {"idx": 7, "uri": URI_BOMB}})),
    "status bitstring inflating past the cap: fails CLOSED")
add("STATUS_CROSSISS",
    build(payload=base_payload(status={"status_list": {"idx": 7, "uri": URI_CROSSISS}})),
    "status token signed by ANOTHER trusted PID Provider, not the credential's own")
add("NO_STATUS", build(payload=base_payload(status=None)),
    "credential carries no status information at all")

# rule 9 — assurance
add("LOA_SUBSTANTIAL", build(payload=base_payload(acr="http://eidas.europa.eu/LoA/substantial")),
    "credential asserts substantial where high is required")
add("LOA_ABSENT", build(payload=base_payload(acr=None)), "credential asserts no level")
add("LOA_UNKNOWN", build(payload=base_payload(acr="urn:example:super")),
    "credential asserts an unrecognised level")
add("LOA_CAPPED",
    build(header={"kid": KID + "-b"},
          payload=base_payload(iss=ISS2,
                               status={"status_list": {"idx": 7, "uri": URI_MS2}}),
          issuer_d=D_ISS2),
    "issuer is capped at substantial by its anchor but asserts high")

# a second, distinct subject (for the two-accounts binding rule)
D2_HOLDER, Q2_HOLDER = key_from("holder-2")
DISC_B = {
    "family_name": disclosure(SALT1, "family_name", "Ivanov"),
    "given_name": disclosure(SALT2, "given_name", "Georgi"),
    "birth_date": disclosure(SALT3, "birth_date", "1988-11-02"),
    "pan": disclosure(SALT4, "personal_administrative_number", "8811020000"),
}
SD_B = [dig(v) for v in DISC_B.values()] + DECOY


def build_b(nonce=NONCE, **kw):
    pl = base_payload(cnf={"jwk": jwk(Q2_HOLDER)}, _sd=SD_B)
    return build(payload=pl, discs=list(DISC_B.values()), kb_d=D2_HOLDER,
                 kb_payload={"nonce": nonce}, **kw)


add("SUBJECT_B", build_b(), "a second, distinct PID subject")
add("OK_BINDNONCE", build(kb_payload={"nonce": BIND_NONCE}),
    "subject A answering the account-binding challenge")
add("OK_BINDNONCE2", build(kb_payload={"nonce": NONCE2}),
    "subject A answering a second binding challenge")
add("SUBJECT_B_BINDNONCE", build_b(nonce=BIND_NONCE),
    "subject B answering the account-binding challenge")
add("SUBJECT_B_BINDNONCE2", build_b(nonce=NONCE2),
    "subject B answering a second binding challenge")
add("NO_PAN",
    build(payload=base_payload(_sd=[dig(v) for k, v in DISC.items() if k != "pan"] + DECOY),
          discs=[v for k, v in DISC.items() if k != "pan"]),
    "no personal_administrative_number disclosed: nothing to bind to")


# ── emit ────────────────────────────────────────────────────────────────────
def c_str(s, indent="    "):
    out = []
    for i in range(0, len(s), 72):
        out.append('%s"%s"' % (indent, s[i:i + 72]))
    return "\n".join(out) if out else '%s""' % indent


def c_bytes(b):
    rows = []
    for i in range(0, len(b), 12):
        rows.append("    " + ", ".join("0x%02x" % x for x in b[i:i + 12]))
    return ",\n".join(rows)


def sec1(q):
    return b"\x04" + q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")


def main():
    check_rfc6979()
    # Cross-check every emitted issuer/KB signature against OpenSSL.
    for label, (d, q) in [("issuer", (D_ISS, Q_ISS)), ("issuer2", (D_ISS2, Q_ISS2)),
                          ("status", (D_STATUS, Q_STATUS)), ("holder", (D_HOLDER, Q_HOLDER))]:
        m = b"cross-check-" + label.encode()
        raw = sig64(d, m)
        assert openssl_verify(q, m, raw), label
    print("OpenSSL cross-check of this generator's signer: PASS", file=sys.stderr)

    lines = []
    w = lines.append
    w("/* dsso_pid_vectors.h — GENERATED TEST DATA for `determ-dsso selftest-pid`.")
    w(" *")
    w(" * DO NOT EDIT — REGENERATE. This file is written by")
    w(" *     python3 tools/gen_dsso_pid_vectors.py")
    w(" * run from the repository root; that generator's header states what each")
    w(" * fixture is for and how to check a regeneration (the run is deterministic,")
    w(" * so `git diff` after it must be empty unless the fixtures were meant to")
    w(" * change). Editing this file by hand desynchronizes it from the generator")
    w(" * and from the anchors below.")
    w(" *")
    w(" * ANCHORS. The generator's P-256 ECDSA is an INDEPENDENT pure-Python")
    w(" * implementation: it is anchored to the RFC 6979 A.2.5 known-answer")
    w(" * vectors and every signature emitted here is additionally re-verified")
    w(" * against OpenSSL before it is written out. So the accept case in the gate")
    w(" * is three implementations agreeing (the generator, OpenSSL, and the C")
    w(" * verifier under test), not a C signer agreeing with a C verifier. The gate")
    w(" * ALSO checks dsso_es256_verify against those same published RFC 6979")
    w(" * vectors directly, so the C verifier does not depend on the generator.")
    w(" *")
    w(" * The data is inline here rather than under tools/vectors/ on purpose: the")
    w(" * determ-dsso binary has no file IO and no fixture-path resolution, and")
    w(" * reading a JSON corpus in order to test a JSON reader would make the gate")
    w(" * depend on the thing it is testing. */")
    w("#ifndef DETERM_DSSO_PID_VECTORS_H")
    w("#define DETERM_DSSO_PID_VECTORS_H")
    w("")
    w('#define PIDV_ISS        "%s"' % ISS)
    w('#define PIDV_ISS2       "%s"' % ISS2)
    w('#define PIDV_KID        "%s"' % KID)
    w('#define PIDV_KID2       "%s"' % (KID + "-b"))
    w('#define PIDV_KID_STATUS "%s"' % KID_STATUS)
    w('#define PIDV_RP_ID      "%s"' % RP_ID)
    w('#define PIDV_NONCE      "%s"' % NONCE)
    w('#define PIDV_NONCE2     "%s"' % NONCE2)
    w('#define PIDV_BIND_NONCE "%s"' % BIND_NONCE)
    w("#define PIDV_NOW        ((int64_t)%d)" % NOW)
    w("")
    for nm, q in [("ISSUER", Q_ISS), ("ISSUER2", Q_ISS2), ("STATUS", Q_STATUS),
                  ("ROGUE", Q_UNK), ("HOLDER", Q_HOLDER)]:
        w("static const uint8_t PIDV_PK_%s[65] = {" % nm)
        w(c_bytes(sec1(q)))
        w("};")
    w("")
    w("typedef struct { const char *name; const char *text; const char *note; } pidv_vec;")
    w("")
    for nm, text, note in V:
        w("/* %s */" % note)
        w("static const char PIDV_%s[] =" % nm)
        w(c_str(text) + ";")
    w("")
    w("typedef struct { const char *uri; const char *token; int fail; } pidv_status;")
    w("static const pidv_status PIDV_STATUS_FIXTURES[] = {")
    for uri, tok, fail in STATUS_FIXTURES:
        w('    { "%s",' % uri)
        w(c_str(tok, indent="      ") + ",")
        w("      %d }," % fail)
    w("};")
    w("#define PIDV_N_STATUS (sizeof PIDV_STATUS_FIXTURES / sizeof PIDV_STATUS_FIXTURES[0])")
    w("")
    # a standalone zlib blob for the inflate fuzz arm
    blob = zlib.compress(status_bits(ENTRIES, bits=2), 9)
    plain = status_bits(ENTRIES, bits=2)
    w("/* A zlib blob and its plaintext, for the bounded-inflate fuzz arm. */")
    w("static const uint8_t PIDV_ZLIB[%d] = {" % len(blob))
    w(c_bytes(blob))
    w("};")
    w("static const uint8_t PIDV_ZLIB_PLAIN[%d] = {" % len(plain))
    w(c_bytes(plain))
    w("};")
    w("")
    w("#endif /* DETERM_DSSO_PID_VECTORS_H */")
    with open(OUT, "w") as f:
        f.write("\n".join(lines) + "\n")
    print("wrote %s (%d vectors, %d status fixtures)" % (OUT, len(V), len(STATUS_FIXTURES)),
          file=sys.stderr)


if __name__ == "__main__":
    main()
