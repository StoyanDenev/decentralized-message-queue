#!/usr/bin/env python3
# verify_opaque3dh.py — python-prove-first reference for the DSSO G4 OPAQUE-3DH
# AKE core (RFC 9807 §6.4 "3DH"), the construction the owner selected for
# co-generating the shared session key `sso_key` (v2.25-DSSO-DAPP-SPEC §4-5).
#
# SCOPE (G4 inc.1): the AKE key-schedule + 3DH + transcript-MAC mutual auth ONLY.
# The credential_request / credential_response are opaque byte blobs here — they
# are filled in by the ALREADY-SHIPPED threshold-OPRF + the OPAQUE envelope in
# inc.2. So this reference proves the AKE core in isolation: both parties derive
# the SAME session_key from the three DH values + the transcript, and the two
# MACs bind the whole transcript (any tamper breaks them).
#
# v2 (C2 fix, 2026-09-17) — THE TRANSCRIPT BINDS BOTH STATIC PUBLIC KEYS.
# v1 bound neither, so an attacker holding only the victim's PUBLIC `pk_c` could
# pick its own `(sk_s', esk_s')`, run the server half, and be accepted by the
# honest client (v2.25-DSSO-DAPP-SPEC §0.0(2), claim C2 — reproduced before the
# fix). v2 carries RFC 9807 §4.1.1 `CleartextCredentials{server_public_key,
# server_identity, client_identity}` (plus the client's public key) inside the
# preamble, and the same bytes are the AAD of the credential envelope at the
# login layer, so the envelope tag and the transcript MAC commit to ONE block.
# The v1 encoding and its KAT are RETIRED (no deployment existed; keeping the
# impersonable construction compiled in would be a downgrade target). The tags
# moved v1 -> v2 so the two encodings can never be confused.
#
# NO new hardness assumption / NO new primitive: P-256 scalar-mult (the 3 DH), a
# TLS-1.3/RFC-9807 HKDF-Expand-Label schedule over HKDF-SHA256, and HMAC-SHA256.
# All present in determ::c99 (p256.c / hkdf.c / hmac). The C port reproduces the
# KAT emitted here byte-for-byte (the dual-oracle discipline). THIS FILE IS THE
# INDEPENDENT ORACLE: every byte below is re-derived here (its own P-256 ladder,
# its own HKDF/Expand-Label, its own encoders); no constant is copied from the C.
#
# Domain separation: Determ is realizing the OPAQUE-3DH CONSTRUCTION for its own
# DSSO DApp, not claiming wire-interop with other OPAQUE stacks, so the label
# prefix is the house "DTM-DSSO-OPAQUE3DH-v2-" tag (RFC 9807 uses "OPAQUE-").
import hashlib
import hmac as _hmac
import sys

# ─── P-256 EC ladder + SEC1 compress (copied from tools/verify_notekey.py) ────
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = (P - 3) % P
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G = (GX, GY)


def pt_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
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
        raise ValueError("cannot serialize the identity element")
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


# ─── HKDF-SHA256 (RFC 5869) + TLS-1.3/RFC-9807-style Expand-Label ─────────────
NH = 32  # SHA-256 output length
LABEL_PREFIX = b"DTM-DSSO-OPAQUE3DH-v2-"
PREAMBLE_TAG = b"DTM-DSSO-OPAQUEv2-"
CLEARCRED_TAG = b"DTM-DSSO-CLEARCRED-v2-"


def i2osp(x, n):
    return int(x).to_bytes(n, "big")


def hkdf_extract(salt, ikm):
    if not salt:
        salt = b"\x00" * NH
    return _hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = _hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def expand_label(secret, label, context, length):
    hkdf_label = (i2osp(length, 2)
                  + i2osp(len(LABEL_PREFIX) + len(label), 1) + LABEL_PREFIX + label
                  + i2osp(len(context), 1) + context)
    return hkdf_expand(secret, hkdf_label, length)


def derive_secret(secret, label, transcript):
    return expand_label(secret, label, hashlib.sha256(transcript).digest(), NH)


def mac(key, msg):
    return _hmac.new(key, msg, hashlib.sha256).digest()


# ─── The OPAQUE-3DH AKE (RFC 9807 §6.4) ──────────────────────────────────────
# A party's long-term identity is a P-256 keypair; each session adds an ephemeral
# keypair. The 3DH combines (client-eph × server-eph), (client-eph × server-stat),
# (client-stat × server-eph). credential_request / credential_response are opaque
# transcript blobs (the OPRF/envelope layer, inc.2).
#
# CleartextCredentials — RFC 9807 §4.1.1, verbatim in content, with the house tag
# and the client's public key added. These EXACT BYTES are also the AAD under
# which the login layer seals the credential envelope, so the envelope tag and
# the AKE transcript MAC commit to one and the same block.
def cleartext_credentials(pk_s, pk_c, server_identity, client_identity):
    return (CLEARCRED_TAG
            + compress(pk_s)
            + compress(pk_c)
            + i2osp(len(server_identity), 2) + server_identity
            + i2osp(len(client_identity), 2) + client_identity)


# Transcript preamble. v1 put the two identity strings around `ke1`; v2 folds
# them into the CleartextCredentials block so the identities and the static keys
# they belong to travel as ONE authenticated unit.
def preamble(context, clear_creds, ke1, inner_ke2):
    return (PREAMBLE_TAG
            + i2osp(len(context), 2) + context
            + clear_creds
            + ke1
            + inner_ke2)


def key_schedule(ikm, pre):
    prk = hkdf_extract(b"", ikm)
    handshake_secret = derive_secret(prk, b"HandshakeSecret", pre)
    session_key = derive_secret(prk, b"SessionKey", pre)
    km2 = expand_label(handshake_secret, b"ServerMAC", b"", NH)
    km3 = expand_label(handshake_secret, b"ClientMAC", b"", NH)
    return session_key, km2, km3


def _ke1(cred_request, client_nonce, epk_c):
    return cred_request + client_nonce + compress(epk_c)


def _inner_ke2(cred_response, server_nonce, epk_s):
    return cred_response + server_nonce + compress(epk_s)


# The shared transcript inputs, mirroring `determ_opaque3dh_transcript`. The two
# static public keys are TRANSCRIPT FIELDS, not call arguments: a party has
# exactly one slot in which a static key can enter, and that slot is MAC-covered.
class Transcript(object):
    def __init__(self, context, client_identity, server_identity,
                 client_public_key, server_public_key,
                 cred_request, cred_response, client_nonce, server_nonce):
        self.context = context
        self.client_identity = client_identity
        self.server_identity = server_identity
        self.client_public_key = client_public_key   # the point pk_c
        self.server_public_key = server_public_key   # the point pk_s
        self.cred_request = cred_request
        self.cred_response = cred_response
        self.client_nonce = client_nonce
        self.server_nonce = server_nonce

    def clear_creds(self):
        return cleartext_credentials(self.server_public_key, self.client_public_key,
                                     self.server_identity, self.client_identity)

    def replace(self, **kw):
        t = Transcript(self.context, self.client_identity, self.server_identity,
                       self.client_public_key, self.server_public_key,
                       self.cred_request, self.cred_response,
                       self.client_nonce, self.server_nonce)
        for k, v in kw.items():
            setattr(t, k, v)
        return t


def server_finalize(t, sk_s, esk_s, epk_c):
    """Server side: 3DH, key schedule, produce server_mac, expect client_mac.
    `pk_c` comes from t.client_public_key (dh3) — NOT from a call argument."""
    ke1 = _ke1(t.cred_request, t.client_nonce, epk_c)
    epk_s = pt_mul(esk_s, G)
    inner = _inner_ke2(t.cred_response, t.server_nonce, epk_s)
    # 3DH (server view): dh1 = esk_s·epk_c, dh2 = sk_s·epk_c, dh3 = esk_s·pk_c
    dh1 = compress(pt_mul(esk_s, epk_c))
    dh2 = compress(pt_mul(sk_s, epk_c))
    dh3 = compress(pt_mul(esk_s, t.client_public_key))
    ikm = dh1 + dh2 + dh3
    pre = preamble(t.context, t.clear_creds(), ke1, inner)
    session_key, km2, km3 = key_schedule(ikm, pre)
    server_mac = mac(km2, hashlib.sha256(pre).digest())
    expected_client_mac = mac(km3, hashlib.sha256(pre + server_mac).digest())
    return {"epk_s": epk_s, "server_mac": server_mac,
            "session_key": session_key, "expected_client_mac": expected_client_mac}


def client_finalize(t, sk_c, esk_c, epk_s, server_mac):
    """Client side: 3DH, key schedule, verify server_mac, produce client_mac.
    `pk_s` comes from t.server_public_key (dh2) — the key the client ANCHORED,
    never one the peer handed it."""
    epk_c = pt_mul(esk_c, G)
    ke1 = _ke1(t.cred_request, t.client_nonce, epk_c)
    inner = _inner_ke2(t.cred_response, t.server_nonce, epk_s)
    # 3DH (client view): dh1 = esk_c·epk_s, dh2 = esk_c·pk_s, dh3 = sk_c·epk_s
    dh1 = compress(pt_mul(esk_c, epk_s))
    dh2 = compress(pt_mul(esk_c, t.server_public_key))
    dh3 = compress(pt_mul(sk_c, epk_s))
    ikm = dh1 + dh2 + dh3
    pre = preamble(t.context, t.clear_creds(), ke1, inner)
    session_key, km2, km3 = key_schedule(ikm, pre)
    ok = _hmac.compare_digest(server_mac, mac(km2, hashlib.sha256(pre).digest()))
    client_mac = mac(km3, hashlib.sha256(pre + server_mac).digest())
    return {"server_mac_ok": ok, "client_mac": client_mac, "session_key": session_key}


# ─── self-test: both sides agree; MACs bind the transcript AND both keys ─────
def _fixed(byte):
    return bytes([byte]) * 32


def selftest():
    ctx = b"determ-dsso-test"
    cid, sid = b"alice@rp", b"determ-idp"
    sk_c, sk_s = _fixed(0x11), _fixed(0x22)
    esk_c, esk_s = _fixed(0x33), _fixed(0x44)
    ic, ic2 = int.from_bytes(sk_c, "big"), int.from_bytes(esk_c, "big")
    is_, is2 = int.from_bytes(sk_s, "big"), int.from_bytes(esk_s, "big")
    pk_c, pk_s = pt_mul(ic, G), pt_mul(is_, G)
    epk_c = pt_mul(ic2, G)
    cnon, snon = _fixed(0x55), _fixed(0x66)
    creq, cresp = b"CRED-REQ-blob", b"CRED-RESP-blob"

    t = Transcript(ctx, cid, sid, pk_c, pk_s, creq, cresp, cnon, snon)
    s = server_finalize(t, is_, is2, epk_c)
    c = client_finalize(t, ic, ic2, s["epk_s"], s["server_mac"])

    fails = 0

    def chk(cond, msg):
        nonlocal fails
        print(("  PASS: " if cond else "  FAIL: ") + msg)
        if not cond:
            fails += 1

    chk(c["server_mac_ok"], "client verifies the server MAC (server authenticated)")
    chk(c["session_key"] == s["session_key"],
        "both parties derive the SAME session_key from the 3 DH + transcript")
    chk(c["client_mac"] == s["expected_client_mac"],
        "server's expected client MAC == client's client MAC (client authenticated)")
    chk(len(c["session_key"]) == 32 and c["session_key"] != b"\x00" * 32,
        "session_key is 32 non-zero bytes")

    # tamper: a different server nonce breaks agreement (transcript-bound)
    s2 = server_finalize(t.replace(server_nonce=_fixed(0x99)), is_, is2, epk_c)
    chk(s2["session_key"] != s["session_key"],
        "a changed server_nonce yields a DIFFERENT session_key (transcript-bound)")
    c_bad = client_finalize(t, ic, ic2, s["epk_s"], s2["server_mac"])
    chk(not c_bad["server_mac_ok"],
        "client REJECTS a server MAC computed over a different transcript")

    # ── C2-a: the reproduced IdP impersonation is now REJECTED ──────────────
    # The attacker knows ONLY the PUBLIC pk_c. It picks its own (sk_s', esk_s')
    # and runs the server half. The honest client runs with the pk_s it ANCHORED
    # (the trust boundary — see the spec §0.0(2) custody note), not the one the
    # peer offered. Pre-fix this returned server_mac_ok == 1 and an agreeing key.
    sk_s_atk, esk_s_atk = _fixed(0xa7), _fixed(0xb9)
    ia, ia2 = int.from_bytes(sk_s_atk, "big"), int.from_bytes(esk_s_atk, "big")
    pk_s_atk = pt_mul(ia, G)
    a = server_finalize(t.replace(server_public_key=pk_s_atk), ia, ia2, epk_c)
    v = client_finalize(t, ic, ic2, a["epk_s"], a["server_mac"])   # t = ANCHORED pk_s
    chk(not v["server_mac_ok"],
        "C2-a: an impersonator holding only pk_c is REJECTED by the honest client")
    chk(v["session_key"] != a["session_key"],
        "C2-a: the impersonator does NOT share a session_key with the client")

    # ── C2-b: the PURE server_public_key binding ────────────────────────────
    # A server that DOES hold the real sk_s but CLAIMS a different static key.
    # All three DH values are identical on both sides (dh2 = sk_s·epk_c on the
    # server, esk_c·pk_s on the client), so ONLY the preamble differs: this leg
    # tests the binding itself, and it is the assertion that fails again if pk_s
    # is ever dropped from the transcript (or the envelope AAD nulled).
    s_lie = server_finalize(t.replace(server_public_key=pk_s_atk), is_, is2, epk_c)
    c_lie = client_finalize(t, ic, ic2, s_lie["epk_s"], s_lie["server_mac"])
    chk(not c_lie["server_mac_ok"],
        "C2-b: a server that lies about its static key is REJECTED even though "
        "every DH value agrees (server_public_key is transcript-bound)")

    # ── C2-c: the PURE client_public_key binding ────────────────────────────
    # The client's own DH never reads t.client_public_key (dh1 = esk_c·epk_s,
    # dh2 = esk_c·pk_s, dh3 = sk_c·epk_s), so a client whose transcript claims a
    # different pk_c has identical DH values and differs ONLY in the preamble.
    pk_other = pt_mul(int.from_bytes(_fixed(0x5c), "big"), G)
    c_pkc = client_finalize(t.replace(client_public_key=pk_other), ic, ic2,
                            s["epk_s"], s["server_mac"])
    chk(not c_pkc["server_mac_ok"],
        "C2-c: a substituted client_public_key is REJECTED (transcript-bound) "
        "although the client's own DH values are unchanged")

    # ── C2-d/e: the identities ──────────────────────────────────────────────
    c_sid = client_finalize(t.replace(server_identity=b"evil-idp"), ic, ic2,
                            s["epk_s"], s["server_mac"])
    chk(not c_sid["server_mac_ok"], "C2-d: a substituted server_identity is REJECTED")
    c_cid = client_finalize(t.replace(client_identity=b"mallory@rp"), ic, ic2,
                            s["epk_s"], s["server_mac"])
    chk(not c_cid["server_mac_ok"], "C2-e: a substituted client_identity is REJECTED")

    print("KAT clear_creds = " + t.clear_creds().hex())
    print("KAT session_key =", c["session_key"].hex())
    print("KAT server_mac  =", s["server_mac"].hex())
    print("KAT client_mac  =", c["client_mac"].hex())
    print()
    print("  " + ("PASS" if fails == 0 else "FAIL") + ": verify_opaque3dh selftest")
    return fails


if __name__ == "__main__":
    sys.exit(1 if selftest() else 0)
