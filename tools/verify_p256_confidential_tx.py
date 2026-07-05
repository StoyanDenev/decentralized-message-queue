#!/usr/bin/env python3
# Independent Python reference for the Determ CONFIDENTIAL-TRANSACTION COMPOSITION over
# NIST P-256 — CRYPTO-C99-SPEC.md §3.19 increment 8, the FIPS-profile sibling of the
# §3.20 inc.8 finite-field composition. NOT a new primitive: the capstone that COMPOSES
# the two shipped halves of a confidential transaction into one end-to-end flow and proves
# they work together —
#
#   * the inc.5/6 RANGE PROOFS are the NO-INFLATION-BY-OVERFLOW / non-negativity half
#     (every output value in [0, 2^n));
#   * the inc.7 BALANCE PROOF is the AMOUNT-CONSERVATION half (Σ v_in = Σ v_out + fee).
#
# The load-bearing composition fact: an output's range-proof value commitment
# V_j = v_j*G + γ_j*H (balance side C_out[j] = v_j*G + r_j*H) is the SAME point when
# γ_j = r_j — because BOTH use the identical value generator G (the P-256 base point) and
# blinding generator H. A cross-primitive generator mismatch would make the composition
# unsound and is exactly what this capstone rules out.
#
# Division of labour: an INFLATION attempt (an output bumped so Σv_out+fee ≠ Σv_in, honest
# blindings) is caught by the BALANCE proof (each output is still an in-range commitment,
# so the range proofs pass); a RANGE VIOLATION (an output = 2^n) is caught by that
# output's RANGE proof (a wrapped value can still balance). Reuses the already-byte-exact
# inc.5/6/7 references; no new corpus. The C mirror is test-p256-confidential-tx-c99.
import verify_pedersen as vp
import verify_bp_rangeproof as rp
import verify_p256_balance as bal

N = vp.N


def build_tx(v_in, r_in, v_out, r_out, fee, n):
    """Assemble a confidential tx: input/output Pedersen commitments (points), a range
    proof per OUTPUT (γ_j = r_out[j] so V_j == C_out[j]), and one balance proof."""
    C_in = [bal.commit(v, r) for v, r in zip(v_in, r_in)]
    C_out = [bal.commit(v, r) for v, r in zip(v_out, r_out)]
    rproofs = []
    for j, (v, r) in enumerate(zip(v_out, r_out)):
        rnd = rp._demo_rnd(n, 100 + j)
        proof = rp.prove(v, r, n, rnd)              # γ = r_out[j] -> V == C_out[j]
        V = rp.value_commit(v, r)
        rproofs.append((V, proof))
    E = bal.balance_excess(C_in, C_out, fee)
    x = (sum(r_in) - sum(r_out)) % N
    bproof = bal.balance_prove(E, x, 0x5151)
    return C_in, C_out, rproofs, E, bproof


def verify_tx(C_out, rproofs, E, bproof, n):
    for j, (V, proof) in enumerate(rproofs):
        if V != C_out[j]:
            return False, "V_%d != C_out_%d (generator mismatch)" % (j, j)
        if not rp.verify(proof, n):
            return False, "range proof %d rejected" % j
    if not bal.balance_verify(E, bproof):
        return False, "balance proof rejected"
    return True, None


def _selftest():
    n = 2                                           # output values in [0, 4)
    v_in, r_in = [3, 1], [500, 400]
    v_out, r_out = [2, 1], [333, 444]
    fee = 1
    assert sum(v_in) == sum(v_out) + fee

    # (1) Honest tx: every range proof + the balance proof accept, and V_j == C_out[j].
    C_in, C_out, rproofs, E, bproof = build_tx(v_in, r_in, v_out, r_out, fee, n)
    ok, why = verify_tx(C_out, rproofs, E, bproof, n)
    assert ok, "honest confidential tx rejected: %s" % why
    for j, (V, _) in enumerate(rproofs):
        assert V == C_out[j], "composition identity V_%d == C_out_%d broken" % (j, j)

    # (2) INFLATION — bump an output (still in range) so Σv_out+fee ≠ Σv_in. Balance must
    # reject; the per-output range proofs still pass.
    v_out_inf = [3, 1]                              # 3 in [0,4), but 3+1+1=5 != 4
    _, _, rproofs2, E2, bproof2 = build_tx(v_in, r_in, v_out_inf, r_out, fee, n)
    for j, (V, proof) in enumerate(rproofs2):
        assert rp.verify(proof, n), "range proof %d spuriously rejected under inflation" % j
    assert not bal.balance_verify(E2, bproof2), "balance accepted an inflated transaction"

    # (3) RANGE VIOLATION — an output = 2^n. That output's range proof must reject.
    rnd = rp._demo_rnd(n, 7)
    pbad = rp.prove(1 << n, r_out[1], n, rnd)
    Vbad = rp.value_commit(1 << n, r_out[1])
    assert Vbad == bal.commit(1 << n, r_out[1]), "OOR output commitment identity broken"
    assert not rp.verify(pbad, n), "range proof accepted an out-of-range output value"

    print("verify_p256_confidential_tx selftest: honest tx accepts (range AND balance, V_j==C_out_j)"
          " + inflation caught by balance + out-of-range caught by range OK")


if __name__ == "__main__":
    _selftest()
