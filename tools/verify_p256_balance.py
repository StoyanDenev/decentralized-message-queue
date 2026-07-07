#!/usr/bin/env python3
# Independent Python reference for the Determ CONFIDENTIAL-TX BALANCE PROOF over NIST
# P-256 — CRYPTO-C99-SPEC.md §3.19 increment 7: the amount-conservation half of a confidential
# transaction (the §3.19 inc.5/6 range proofs are the no-inflation half), proving
# Σ v_in = Σ v_out + fee WITHOUT revealing any amount, given Pedersen commitments
# C = v*G + r*H (G the P-256 base point = the value generator, H the §3.19
# nothing-up-my-sleeve blinding generator).
#
# The transaction balances iff the "excess"
#     E = Σ C_in − Σ C_out − fee*G       (in the P-256 group)
# has NO G-component, i.e. E = x*H for the blinding excess x = (Σ r_in − Σ r_out) mod n.
# The prover proves knowledge of that x with a Schnorr proof of discrete log base H
# (E = x*H). Since log_G(H) is unknown, E = x*H is only possible when the G-coefficient
# (Σv_in − Σv_out − fee) is 0 — hence balanced.
#
# The point subtractions are SCALAR negations in the exponent (−C = (n−1)*C, −fee*G =
# (n−fee)*G) so the excess is one multi-exponentiation (determ_pedersen_msm) — no point
# negation primitive is needed. This is the from-scratch oracle the C port
# (src/crypto/pedersen/balance.c) is checked against byte-for-byte (p256_balance.json).
import hashlib, json, os
import verify_pedersen as vp

N = vp.N
G = vp.G
BAL_DST = b"DETERM-P256-BALANCE-v1-challenge"


def _s32(x):
    return x.to_bytes(32, "big")


def H():
    return vp.derive_h()


def commit(v, r):
    return vp.commit_pt(v, r)              # v*G + r*H (P-256), identity-aware


def balance_excess(C_in, C_out, fee):
    """E = Σ C_in − Σ C_out − fee*G. −C = (n−1)*C, −fee*G = (n−fee)*G — matches the C
    determ_pedersen_msm over [C_in(1), C_out(n−1), G(n−fee)]."""
    acc = None
    for C in C_in:
        acc = vp.pt_add(acc, vp.pt_mul(1, C))
    negone = (N - 1) % N
    for C in C_out:
        acc = vp.pt_add(acc, vp.pt_mul(negone, C))
    negfee = (-fee) % N
    acc = vp.pt_add(acc, vp.pt_mul(negfee, G))
    return acc


def _hts(msg):
    """determ_p256_hash_to_scalar: RFC 9380 hash_to_field mod n, m=1, L=48, count=1."""
    return int.from_bytes(vp.expand_xmd(msg, BAL_DST, 48), "big") % N


def balance_prove(E, x, k):
    """Schnorr PoK of x with E = x*H. T = k*H ; c = H_s(E‖T) ; s = k + c·x mod n.
    proof = compress(T) ‖ s  (33 + 32 = 65 bytes). x, k in [0,n)."""
    T = vp.pt_mul(k, H())
    c = _hts(vp.compress(E) + vp.compress(T))
    s = (k + c * x) % N
    return vp.compress(T) + _s32(s)


def balance_verify(E, proof):
    """True iff s*H == T + c*E."""
    T = vp.decompress(proof[:33])
    s = int.from_bytes(proof[33:65], "big")
    c = _hts(vp.compress(E) + vp.compress(T))
    lhs = vp.pt_mul(s, H())
    rhs = vp.pt_add(T, vp.pt_mul(c, E))
    return lhs == rhs


# ── §3.13 file-half checker ───────────────────────────────────────────────────
def check_p256_balance(vec, label):
    C_in = [vp.decompress(bytes.fromhex(h)) for h in vec["c_in_hex"]]
    C_out = [vp.decompress(bytes.fromhex(h)) for h in vec["c_out_hex"]]
    fee = vec["fee"]
    x = int(vec["x_hex"], 16)
    k = int(vec["k_hex"], 16)
    E = balance_excess(C_in, C_out, fee)
    if vp.compress(E).hex() != vec["e_hex"]:
        return "recomputed excess E != e_hex"
    proof = balance_prove(E, x, k)
    if proof.hex() != vec["proof_hex"]:
        return "recomputed proof != proof_hex"
    if not balance_verify(E, proof):
        return "own balance proof failed to verify"
    return None


def _selftest():
    # balanced: Σv_in = 30 = Σv_out (27) + fee (3)
    v_in, r_in = [10, 20], [111, 222]
    v_out, r_out = [5, 22], [33, 44]
    fee = 3
    C_in = [commit(v, r) for v, r in zip(v_in, r_in)]
    C_out = [commit(v, r) for v, r in zip(v_out, r_out)]
    E = balance_excess(C_in, C_out, fee)
    x = (sum(r_in) - sum(r_out)) % N
    assert E == vp.pt_mul(x, H()), "balanced excess is not x*H"
    proof = balance_prove(E, x, 0x9999)
    assert balance_verify(E, proof), "valid balance proof rejected"
    # unbalanced: bump one output value -> E gains a G-component -> proof can't verify
    C_out_bad = [commit(6, r_out[0]), commit(v_out[1], r_out[1])]
    E_bad = balance_excess(C_in, C_out_bad, fee)
    assert E_bad != vp.pt_mul(x, H()), "unbalanced excess unexpectedly has no G-component"
    assert not balance_verify(E_bad, balance_prove(E_bad, x, 0x9999)), \
        "balance verify accepted an unbalanced transaction"
    # tamper s -> reject
    bad = bytearray(proof); bad[-1] ^= 1
    assert not balance_verify(E, bytes(bad)), "balance verify accepted a tampered proof"
    # fee = 0 edge (the (n-fee)*G term is n*G = identity)
    Ci = [commit(7, 55)]; Co = [commit(7, 66)]
    E2 = balance_excess(Ci, Co, 0)
    x2 = (55 - 66) % N
    assert balance_verify(E2, balance_prove(E2, x2, 0x1234)), "fee=0 balance failed"
    print("verify_p256_balance selftest: balanced accept + unbalanced/tamper reject + fee=0 OK")


def emit():
    vectors = []
    for name, v_in, r_in, v_out, r_out, fee in [
        ("balance 2in-2out fee3", [10, 20], [111, 222], [5, 22], [33, 44], 3),
        ("balance 1in-2out fee0", [100], [777], [40, 60], [123, 600], 0),
    ]:
        C_in = [commit(v, r) for v, r in zip(v_in, r_in)]
        C_out = [commit(v, r) for v, r in zip(v_out, r_out)]
        E = balance_excess(C_in, C_out, fee)
        x = (sum(r_in) - sum(r_out)) % N
        k = int.from_bytes(hashlib.sha256(name.encode()).digest(), "big") % N or 1
        proof = balance_prove(E, x, k)
        assert balance_verify(E, proof)
        vectors.append({"name": name, "type": "balance",
                        "c_in_hex": [vp.compress(C).hex() for C in C_in],
                        "c_out_hex": [vp.compress(C).hex() for C in C_out],
                        "fee": fee, "x_hex": _s32(x).hex(), "k_hex": _s32(k).hex(),
                        "e_hex": vp.compress(E).hex(), "proof_hex": proof.hex()})
    doc = {"primitive": "p256_balance",
           "source": ("Generated by tools/verify_p256_balance.py (Determ CRYPTO-C99-SPEC §3.19 inc.7); "
                      "confidential-tx balance proof over NIST P-256 — a Schnorr PoK that the "
                      "commitment excess E = Σ C_in − Σ C_out − fee*G opens to zero (E = x*H). "
                      "From-scratch Python reference (own scalar-mult ladder)."),
           "note": ("Balance proof: proves Σv_in = Σv_out + fee without revealing amounts. "
                    "E computed by one multi-exponentiation (−C=(n−1)*C, −fee*G=(n−fee)*G); "
                    "proof = compress(T)‖s (Schnorr, challenge DST DETERM-P256-BALANCE-v1-challenge). "
                    "Commitments 33-byte SEC1 compressed; scalars 32-byte big-endian; fee a uint64."),
           "vectors": vectors}
    out = os.path.join(os.path.dirname(__file__), "vectors", "p256_balance.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=2); f.write("\n")
    print("wrote %s (%d vectors)" % (out, len(vectors)))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "emit":
        emit()
    else:
        _selftest()
