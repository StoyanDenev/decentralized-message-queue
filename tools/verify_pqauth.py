#!/usr/bin/env python3
# tools/verify_pqauth.py — independent oracle for the DPQ1 post-quantum
# transaction-authentication envelope (determ::pqauth, CRYPTO-C99-SPEC §3.21).
#
# The envelope binds a transaction's canonical message (the chain's
# Transaction::signing_bytes) to an ML-DSA (FIPS 204) signature, optionally in
# HYBRID with Ed25519 (an attacker must break BOTH). This module reproduces the
# envelope BYTES from the seeds + message using an INDEPENDENT python ed25519
# (pynacl) + the from-scratch python ML-DSA signer (verify_mldsa_keygen /
# verify_mldsa_sign — hashlib SHAKE + a python NTT, distinct from the C determ
# code), and checks them byte-for-byte against tools/vectors/pqauth.json. The
# shipped C++ determ::pqauth is checked against the SAME frozen bytes by
# `determ test-pqauth` — two independent implementations, one frozen corpus.
#
#   python tools/verify_pqauth.py            # verify the committed corpus
#   python tools/verify_pqauth.py --emit     # (re)generate the corpus
import hashlib, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_mldsa_keygen import keygen as mldsa_keygen
from verify_mldsa_sign import sign_internal as mldsa_sign, PARAMS as MLDSA_PARAMS
import nacl.signing

HERE   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(HERE, "tools", "vectors", "pqauth.json")

# ─── DPQ1 envelope format (v1) ───────────────────────────────────────────────
#   MAGIC(4)="DPQ1" | scheme(1) | pq_pk_len(2 BE) | pq_pk | pq_sig_len(2 BE) |
#   pq_sig | [ ed_pk(32) | ed_sig(64) ]   (the ed_* fields iff scheme & 0x10)
# pq_sig covers M' = 0x00|len(CTX)|CTX|message (the ML-DSA "external" interface,
# domain-separated by CTX). ed_sig covers the RAW message, so a hybrid tx's
# Ed25519 half is verifiable by the chain's existing Ed25519 path unchanged.
MAGIC = b"DPQ1"
CTX   = b"determ-pqtx-v1"
SCHEME_NAME = {0x01: "ML-DSA-44", 0x02: "ML-DSA-65", 0x03: "ML-DSA-87",
               0x11: "ML-DSA-44", 0x12: "ML-DSA-65", 0x13: "ML-DSA-87"}
def is_hybrid(s): return (s & 0x10) != 0
def be16(x):      return bytes([(x >> 8) & 0xff, x & 0xff])

def build_envelope(scheme, message, mldsa_seed, ed_seed=None):
    name = SCHEME_NAME[scheme]
    p    = MLDSA_PARAMS[name]
    pk, sk = mldsa_keygen(mldsa_seed, p["k"], p["l"], p["eta"])
    # CTX' = CTX || scheme: binding the scheme byte into the ML-DSA context makes
    # the signature refuse a cross-scheme re-label (hybrid-strip / downgrade defence).
    Mp     = bytes([0x00, len(CTX) + 1]) + CTX + bytes([scheme]) + message
    pq_sig = mldsa_sign(sk, Mp, p)                 # deterministic (rnd = 32 zero bytes)
    env  = bytearray()
    env += MAGIC
    env += bytes([scheme])
    env += be16(len(pk));     env += pk
    env += be16(len(pq_sig)); env += pq_sig
    if is_hybrid(scheme):
        assert ed_seed is not None, "hybrid scheme needs an ed_seed"
        sk_ed  = nacl.signing.SigningKey(ed_seed)
        ed_pk  = bytes(sk_ed.verify_key)
        # Ed25519 signs scheme || message (same scheme binding as the ML-DSA half).
        ed_sig = sk_ed.sign(bytes([scheme]) + message).signature   # RFC 8032 detached 64B
        env += ed_pk
        env += ed_sig
    return bytes(env)

# Fixed, reproducible vector inputs (mldsa_seed = 0x00..0x1f, ed_seed = 0x40..0x5f,
# message = 0x00..0x3f) covering every scheme + the hybrid path.
MLDSA_SEED = bytes(range(0, 32))
ED_SEED    = bytes(range(0x40, 0x60))
MESSAGE    = bytes(range(0, 64))
VECS = [
    ("pqonly-mldsa44", 0x01, False),
    ("pqonly-mldsa65", 0x02, False),
    ("pqonly-mldsa87", 0x03, False),
    ("hybrid-mldsa65", 0x12, True),
]

def make_corpus():
    out = []
    for name, scheme, hybrid in VECS:
        env = build_envelope(scheme, MESSAGE, MLDSA_SEED, ED_SEED if hybrid else None)
        out.append({
            "name": name,
            "scheme": scheme,
            "mldsa_seed": MLDSA_SEED.hex(),
            "ed_seed": ED_SEED.hex() if hybrid else None,
            "message": MESSAGE.hex(),
            "envelope_len": len(env),
            "envelope_sha256": hashlib.sha256(env).hexdigest(),
            "envelope_hex": env.hex(),
        })
    return out

def emit():
    corpus = make_corpus()
    with open(CORPUS, "w") as f:
        json.dump(corpus, f, indent=1)
        f.write("\n")
    print(f"[emit] wrote {len(corpus)} vector(s) -> {CORPUS}")
    for v in corpus:
        print(f"  {v['name']:16s} scheme=0x{v['scheme']:02x} len={v['envelope_len']:5d} "
              f"sha256={v['envelope_sha256'][:16]}...")

def verify():
    with open(CORPUS) as f:
        corpus = json.load(f)
    ok = 0
    for v in corpus:
        scheme  = v["scheme"]
        msg     = bytes.fromhex(v["message"])
        mseed   = bytes.fromhex(v["mldsa_seed"])
        eseed   = bytes.fromhex(v["ed_seed"]) if v["ed_seed"] else None
        env     = build_envelope(scheme, msg, mseed, eseed)
        if env.hex() != v["envelope_hex"]:
            print(f"  FAIL {v['name']}: envelope byte mismatch (len {len(env)} vs {v['envelope_len']})")
            return 1
        if hashlib.sha256(env).hexdigest() != v["envelope_sha256"]:
            print(f"  FAIL {v['name']}: sha256 mismatch")
            return 1
        ok += 1
    print(f"[verify] pqauth.json: {ok} vector(s) byte-equal through the independent "
          f"python ed25519 + ML-DSA oracle")
    return 0

if __name__ == "__main__":
    if "--emit" in sys.argv:
        emit()
    else:
        sys.exit(verify())
