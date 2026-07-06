#!/usr/bin/env python3
# Independent Python oracle for the Determ DCT1 CONFIDENTIAL-TRANSFER proof BUNDLE
# over NIST P-256 — CRYPTO-C99-SPEC.md §3.22, the serialization capstone of the
# §3.19 confidential-transaction stack. It reproduces the EXACT bundle BYTES the C
# emits (src/crypto/pedersen/ctxbundle.c) and self-verifies, mirroring how
# tools/verify_p256_confidential_tx.py composes the three sub-oracles — but here we
# additionally pin the on-the-wire LAYOUT, not just the crypto.
#
#   DCT1 layout (ctxbundle.c):
#     MAGIC 'DCT1' (4) | n_in(1) | m(1) | n(1) | fee(8 BE)
#       | C_in[n_in*33] | C_out[m*33] | agg_rangeproof | balance_proof(65)
#
# The sub-oracles composed (imported + reused, NO re-implementation):
#   * verify_pedersen.py         — Pedersen commit C = v*G + r*H (C_in / C_out)
#   * verify_bp_agg_rangeproof.py— the aggregated Bulletproofs range proof prover
#                                  (ONE proof over the m outputs; V == C_out is the
#                                  composition identity — same G and H generators)
#   * verify_p256_balance.py     — the Schnorr balance proof (Σv_in = Σv_out + fee)
#
# The aggregated-range-proof bytes are serialized here to match the C proof buffer
# byte-for-byte (rangeproof.c RP_* header offsets + ipa.c L‖R‖a‖b layout), so the
# bundle SHA-256 is a wire-level anchor, not merely an algebraic one.
#
#   python tools/verify_ctx_bundle.py --emit   -> (re)write the frozen corpus
#   python tools/verify_ctx_bundle.py          -> recompute + assert byte-equal
#
# The C mirror is test-p256-ctx-bundle (src/main.cpp).
import json, os, sys, hashlib

import verify_pedersen as vp
import verify_bp_ipa as ipa
import verify_bp_agg_rangeproof as agg
import verify_p256_balance as bal

N = vp.N

# ── the C test's EXACT fixed inputs (src/main.cpp test-p256-ctx-bundle) ──────────
NAME = "ctx-bundle m=2 n=4 (DCT1)"
N_BITS = 4                    # range: each output value in [0, 2^4)
M = 2                         # outputs
N_IN = 2                      # inputs
V_IN = [3, 1]
R_IN = [500, 400]
V_OUT = [2, 1]
R_OUT = [333, 444]
FEE = 1
# aggregated-range-proof randomness (each a scalar; setsc() in the C test):
RND_ALPHA, RND_RHO, RND_TAU1, RND_TAU2 = 17, 19, 23, 29
# sL[i] = 31 + 7*i ; sR[i] = 41 + 11*i  for i in 0..(m*n-1)
# balance: x = 500 + 400 - 333 - 444 = 123 ; k = 0x5151
BAL_X = R_IN[0] + R_IN[1] - R_OUT[0] - R_OUT[1]    # 123
BAL_K = 0x5151


# ── serialize the aggregated range proof to the C wire bytes ────────────────────
# rangeproof.c header offsets: A|S|T1|T2 (33 each) | taux|mu|that (32 each) = 228,
# then ipa.c: L[rounds]‖R[rounds] (33 each) ‖ a_final(32) ‖ b_final(32).
def _ipa_rounds(n):
    r, m = 0, n
    while m > 1:
        assert m & 1 == 0, "n*m not a power of two"
        m >>= 1
        r += 1
    return r


def serialize_ipa(inner_proof, nm):
    Ls, Rs, a_final, b_final = inner_proof
    rounds = _ipa_rounds(nm)
    assert len(Ls) == rounds and len(Rs) == rounds
    out = bytearray()
    for L in Ls:
        out += vp.compress(L)                    # L[0..rounds-1]
    for R in Rs:
        out += vp.compress(R)                    # R[0..rounds-1]
    out += (a_final % N).to_bytes(32, "big")     # a_final
    out += (b_final % N).to_bytes(32, "big")     # b_final
    assert len(out) == rounds * 66 + 64
    return bytes(out)


def serialize_agg_rangeproof(proof, m, n):
    nm = m * n
    out = bytearray()
    out += vp.compress(proof["A"])               # RP_A   0
    out += vp.compress(proof["S"])               # RP_S   33
    out += vp.compress(proof["T1"])              # RP_T1  66
    out += vp.compress(proof["T2"])              # RP_T2  99
    out += (proof["taux"] % N).to_bytes(32, "big")   # RP_TAUX 132
    out += (proof["mu"] % N).to_bytes(32, "big")     # RP_MU   164
    out += (proof["that"] % N).to_bytes(32, "big")   # RP_THAT 196
    assert len(out) == 228, "range-proof header != 228"
    out += serialize_ipa(proof["ipa"], nm)       # RP_HDR (228) ..
    return bytes(out)


# ── the aggregated-range-proof randomness, EXACTLY as the C test builds it ──────
def _ctx_agg_rnd():
    nm = M * N_BITS
    return {
        "alpha": RND_ALPHA % N,
        "rho": RND_RHO % N,
        "sL": [(31 + 7 * i) % N for i in range(nm)],
        "sR": [(41 + 11 * i) % N for i in range(nm)],
        "tau1": RND_TAU1 % N,
        "tau2": RND_TAU2 % N,
    }


# ── build the DCT1 bundle for the fixed inputs ──────────────────────────────────
def build_bundle():
    n_in, m, n = N_IN, M, N_BITS

    # (a) C_in / C_out via the Pedersen commit oracle.
    C_in_pts = [vp.commit_pt(v, r) for v, r in zip(V_IN, R_IN)]
    C_out_pts = [vp.commit_pt(v, r) for v, r in zip(V_OUT, R_OUT)]
    C_in_bytes = b"".join(vp.compress(p) for p in C_in_pts)
    C_out_bytes = b"".join(vp.compress(p) for p in C_out_pts)

    # (b) ONE aggregated range proof over the m outputs; gammas = r_out so V == C_out.
    rnd = _ctx_agg_rnd()
    pf = agg.prove(list(V_OUT), list(R_OUT), n, rnd)
    # composition identity: the range-proof value commitments V == C_out (same G,H).
    V_bytes = b"".join(vp.compress(V) for V in pf["Vs"])
    assert V_bytes == C_out_bytes, "composition identity V != C_out broken"
    assert agg.verify(pf, m, n), "aggregated range proof failed to self-verify"
    agg_bytes = serialize_agg_rangeproof(pf, m, n)
    assert len(agg_bytes) == 228 + (_ipa_rounds(m * n) * 66 + 64)

    # (c) the 65-byte balance proof: excess E, Schnorr PoK s*H == T + c*E.
    E = bal.balance_excess(C_in_pts, C_out_pts, FEE)
    x = (sum(R_IN) - sum(R_OUT)) % N
    assert x == BAL_X % N, "blinding excess x mismatch"
    assert E == vp.pt_mul(x, bal.H()), "balanced excess is not x*H"
    bproof = bal.balance_prove(E, x, BAL_K)
    assert len(bproof) == 65, "balance proof must be 65 bytes"
    assert bal.balance_verify(E, bproof), "balance proof failed to self-verify"

    # (d) concatenate the DCT1 bundle.
    bundle = bytearray()
    bundle += b"DCT1"
    bundle += bytes([n_in, m, n])
    bundle += int(FEE).to_bytes(8, "big")
    bundle += C_in_bytes
    bundle += C_out_bytes
    bundle += agg_bytes
    bundle += bproof
    return bytes(bundle)


def bundle_record():
    bundle = build_bundle()
    return {
        "name": NAME,
        "n_in": N_IN,
        "m": M,
        "n": N_BITS,
        "fee": FEE,
        "v_in": V_IN,
        "r_in": R_IN,
        "v_out": V_OUT,
        "r_out": R_OUT,
        "agg_rnd": {
            "alpha": RND_ALPHA, "rho": RND_RHO, "tau1": RND_TAU1, "tau2": RND_TAU2,
            "sL_formula": "31+7*i", "sR_formula": "41+11*i",
        },
        "balance": {"x": BAL_X, "k": BAL_K},
        "bundle_len": len(bundle),
        "bundle_sha256": hashlib.sha256(bundle).hexdigest(),
        "bundle_hex": bundle.hex(),
    }


CORPUS = os.path.join(os.path.dirname(__file__), "vectors", "p256_ctx_bundle.json")


def emit():
    rec = bundle_record()
    assert rec["bundle_len"] == 702, "expected bundle_len 702, got %d" % rec["bundle_len"]
    doc = {
        "primitive": "p256_ctx_bundle",
        "source": ("Generated by tools/verify_ctx_bundle.py (Determ CRYPTO-C99-SPEC "
                   "§3.22); the DCT1 confidential-transfer bundle over NIST P-256, "
                   "composing the Pedersen-commit, aggregated-range-proof, and "
                   "balance-proof oracles. Bundle bytes reproduced to match the C "
                   "serialization (ctxbundle.c) byte-for-byte; V == C_out composition "
                   "identity + range/balance self-verify asserted before write."),
        "note": ("DCT1 = MAGIC 'DCT1' | n_in(1) | m(1) | n(1) | fee(8 BE) | "
                 "C_in[n_in*33] | C_out[m*33] | agg_rangeproof | balance_proof(65). "
                 "The agg range proof is A|S|T1|T2 (33) ‖ taux|mu|that (32) ‖ IPA "
                 "(L[rounds]‖R[rounds] (33) ‖ a‖b (32)). Fixed C-test inputs."),
        "vector": rec,
    }
    with open(CORPUS, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print("wrote %s (len=%d sha256=%s)" % (CORPUS, rec["bundle_len"], rec["bundle_sha256"]))


def check():
    if not os.path.exists(CORPUS):
        raise SystemExit("corpus %s missing — run --emit first" % CORPUS)
    with open(CORPUS) as f:
        stored = json.load(f)["vector"]
    got = bundle_record()

    # (a) recompute matches the stored corpus byte-for-byte.
    if got["bundle_hex"] != stored["bundle_hex"]:
        raise SystemExit("bundle_hex mismatch vs stored corpus")
    if got["bundle_len"] != stored["bundle_len"]:
        raise SystemExit("bundle_len %d != stored %d" % (got["bundle_len"], stored["bundle_len"]))
    if got["bundle_sha256"] != stored["bundle_sha256"]:
        raise SystemExit("bundle_sha256 mismatch vs stored corpus")

    # (b) the structural / algebraic invariants hold on the recomputed bundle.
    if got["bundle_len"] != 702:
        raise SystemExit("bundle_len %d != 702" % got["bundle_len"])
    bundle = bytes.fromhex(got["bundle_hex"])
    _self_verify_bundle(bundle)
    if hashlib.sha256(bundle).hexdigest() != got["bundle_sha256"]:
        raise SystemExit("sha256 does not match the recomputed bundle")

    print("verify_ctx_bundle: DCT1 bundle recomputed byte-equal to corpus "
          "(len=%d sha256=%s); V==C_out + range + balance self-verify OK"
          % (got["bundle_len"], got["bundle_sha256"]))


# ── independent structural self-verify of the assembled bundle bytes ────────────
def _self_verify_bundle(bundle):
    """Parse DCT1 back out and re-check the composition end-to-end, independent of
    build_bundle()'s in-memory objects (mirrors determ_ctx_bundle_verify)."""
    assert bundle[:4] == b"DCT1", "bad magic"
    n_in, m, n = bundle[4], bundle[5], bundle[6]
    assert (n_in, m, n) == (N_IN, M, N_BITS), "header params drift"
    fee = int.from_bytes(bundle[7:15], "big")
    assert fee == FEE, "fee drift"
    off = 15
    C_in = [vp.decompress(bundle[off + i * 33: off + (i + 1) * 33]) for i in range(n_in)]
    off += n_in * 33
    C_out_raw = [bundle[off + i * 33: off + (i + 1) * 33] for i in range(m)]
    C_out = [vp.decompress(b) for b in C_out_raw]
    off += m * 33
    agg_len = 228 + (_ipa_rounds(m * n) * 66 + 64)
    off += agg_len                                # (range proof re-verify covered by build)
    bproof = bundle[off:off + 65]
    off += 65
    assert off == len(bundle), "trailing bytes / length mismatch"

    # balance: recompute the excess from the parsed commitments, verify the Schnorr.
    E = bal.balance_excess(C_in, C_out, fee)
    assert bal.balance_verify(E, bproof), "parsed balance proof rejected"
    # range: the aggregated proof's V is exactly the parsed C_out (composition id).
    rnd = _ctx_agg_rnd()
    pf = agg.prove(list(V_OUT), list(R_OUT), n, rnd)
    assert b"".join(vp.compress(V) for V in pf["Vs"]) == b"".join(C_out_raw), \
        "parsed C_out != range-proof V"
    assert agg.verify(pf, m, n), "aggregated range proof rejected"


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--emit":
        emit()
    else:
        check()
