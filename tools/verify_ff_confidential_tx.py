#!/usr/bin/env python3
# Independent Python reference for the Determ CONFIDENTIAL-TRANSACTION COMPOSITION over
# Z_p* — CRYPTO-C99-SPEC.md §3.20 increment 8. This is NOT a new primitive: it is the
# capstone that COMPOSES the two shipped halves of a confidential transaction into one
# end-to-end flow and proves they work together —
#
#   * the inc.5/6 RANGE PROOFS are the NO-INFLATION-BY-OVERFLOW / non-negativity half:
#     every output value lies in [0, 2^n), so no output is negative and none wraps the
#     field to forge coins;
#   * the inc.7 BALANCE PROOF is the AMOUNT-CONSERVATION half: Σ v_in = Σ v_out + fee,
#     so the transaction neither mints nor burns value.
#
# The load-bearing composition fact this file proves is that the SAME Pedersen commitment
# object serves BOTH primitives: an output's tx commitment C_out[j] = g^{v_j}·h^{r_j}
# (balance side) is byte-identical to that output's range-proof value commitment
# V_j = g^{v_j}·h^{γ_j} when γ_j = r_j — because BOTH use the identical value generator
# g = 4 and blinding generator h = DETERM_FF_H. A cross-primitive generator mismatch
# (a different g or h between the range proof and the balance proof) would make the
# composition unsound and is exactly what this capstone rules out.
#
# It also demonstrates the DIVISION OF LABOUR between the two halves:
#   * an INFLATION attempt (an output value bumped so Σv_out+fee ≠ Σv_in, honest
#     blindings) is caught by the BALANCE proof — each individual output is still a valid
#     in-range commitment, so the range proofs still pass; only balance fails;
#   * a RANGE VIOLATION (an output value = 2^n, out of range) is caught by that output's
#     RANGE proof — balance could still be made to hold via a compensating wrapped value,
#     so range is the half that must catch it.
#
# Reuses the already-byte-exact inc.5/6/7 references (verify_ff_rangeproof /
# verify_ff_balance); no new corpus (the composed bytes are pinned by ff_rangeproof.json /
# ff_aggrangeproof.json / ff_balance.json). The C mirror is test-ff-confidential-tx-c99,
# which composes the identical public §3.20 APIs. NOT constant-time (owner-gated).
import verify_ff_pedersen as vp
import verify_ff_rangeproof as rp
import verify_ff_balance as bal

P, Q = vp.P, vp.Q


def _blinders(seed, n):
    """Deterministic range-proof blinders (γ, α, ρ, τ1, τ2, sL, sR) for a KAT-reproducible
    proof — a real prover MUST draw these from a CSPRNG for hiding to hold."""
    return rp._params(seed, 0, n)


def build_tx(v_in, r_in, v_out, r_out, fee, n):
    """Assemble a confidential transaction: input/output Pedersen commitments, a range
    proof per OUTPUT, and one balance proof. Returns everything the verifier needs."""
    C_in = [bal.commit(v, r) for v, r in zip(v_in, r_in)]
    C_out = [bal.commit(v, r) for v, r in zip(v_out, r_out)]
    # One range proof per output. The blinding factor γ_j fed to the range proof IS the
    # output's commitment blinding r_out[j], so V_j == C_out[j] exactly.
    rproofs = []
    for j, (v, r) in enumerate(zip(v_out, r_out)):
        gamma, alpha, rho, tau1, tau2, sL, sR = _blinders(b"cotx-out-%d" % j, n)
        gamma = r                                 # bind γ_j = r_out[j] -> V_j = C_out[j]
        V, proof = rp.prove(v, gamma, alpha, rho, tau1, tau2, sL, sR, n)
        rproofs.append((V, proof))
    # Balance proof over all commitments.
    E = bal.balance_excess(C_in, C_out, fee)
    x = (sum(r_in) - sum(r_out)) % Q
    bproof = bal.balance_prove(E, x, 0x5151)
    return C_in, C_out, rproofs, E, bproof


def verify_tx(C_out, rproofs, E, bproof, n):
    """A confidential tx is valid iff (1) every output's range proof verifies against that
    output's commitment, AND (2) the balance proof verifies. Also checks the composition
    identity V_j == C_out[j] (the two primitives share the same commitment)."""
    for j, (V, proof) in enumerate(rproofs):
        if V != C_out[j]:
            return False, "V_%d != C_out_%d (generator mismatch between range and balance)" % (j, j)
        if not rp.verify(V, proof, n):
            return False, "range proof %d rejected" % j
    if not bal.balance_verify(E, bproof):
        return False, "balance proof rejected"
    return True, None


def _selftest():
    n = 4                                          # output values in [0, 16)
    # Balanced: Σv_in = 15 = Σv_out (12) + fee (3); all outputs in range.
    v_in, r_in = [9, 6], [111, 222]
    v_out, r_out = [8, 4], [333, 444]
    fee = 3
    assert sum(v_in) == sum(v_out) + fee

    # (1) Honest tx: every range proof + the balance proof accept, and V_j == C_out[j].
    C_in, C_out, rproofs, E, bproof = build_tx(v_in, r_in, v_out, r_out, fee, n)
    ok, why = verify_tx(C_out, rproofs, E, bproof, n)
    assert ok, "honest confidential tx rejected: %s" % why
    for j, (V, _) in enumerate(rproofs):
        assert V == C_out[j], "composition identity V_%d == C_out_%d broken" % (j, j)

    # (2) INFLATION — bump an output value (still in range) so Σv_out+fee > Σv_in, honest
    # blindings. The balance proof must reject; the per-output range proofs still pass.
    v_out_inf = [10, 4]                            # 10 in range, but 10+4+3=17 != 15
    C_in2, C_out2, rproofs2, E2, bproof2 = build_tx(v_in, r_in, v_out_inf, r_out, fee, n)
    for j, (V, proof) in enumerate(rproofs2):      # each output is still in-range -> range OK
        assert rp.verify(V, proof, n), "range proof %d spuriously rejected under inflation" % j
    assert not bal.balance_verify(E2, bproof2), "balance accepted an inflated transaction"

    # (3) RANGE VIOLATION — an output value = 2^n (out of range). That output's range proof
    # must reject (this is the half balance cannot catch: a wrapped value can still balance).
    v_out_oor = [8, 1 << n]                        # second output out of range
    r_out_oor = [333, 444]
    _, C_out3, rproofs3, _, _ = build_tx(v_in, r_in, v_out_oor, r_out_oor, fee, n)
    Vbad, pbad = rproofs3[1]
    assert Vbad == C_out3[1], "OOR output commitment identity broken"
    assert not rp.verify(Vbad, pbad, n), "range proof accepted an out-of-range output value"

    print("verify_ff_confidential_tx selftest: honest tx accepts (range AND balance, V_j==C_out_j)"
          " + inflation caught by balance + out-of-range caught by range OK")


if __name__ == "__main__":
    _selftest()
