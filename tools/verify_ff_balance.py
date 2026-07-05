#!/usr/bin/env python3
# Independent Python reference for the Determ CONFIDENTIAL-TX BALANCE PROOF over Z_p* —
# CRYPTO-C99-SPEC.md §3.20 increment 7. The amount-conservation half of a confidential
# transaction (the range proofs, inc.5/6, are the no-inflation half): proves
# Σ v_in = Σ v_out + fee WITHOUT revealing any amount, given Pedersen commitments
# C = g^v · h^r mod p (g = 4, h the inc.1 nothing-up-my-sleeve generator).
#
# The transaction balances iff the "excess"
#     E = Π C_in · Π C_out^{-1} · g^{-fee}   (in G_q ⊂ Z_p*)
# has NO g-component, i.e. E = h^{r_excess} for the blinding excess
# r_excess = (Σ r_in − Σ r_out) mod q. The prover proves knowledge of that r_excess with
# a Schnorr proof of discrete log base h (E = h^x). Since log_g(h) is unknown, E = h^x is
# only possible when the g-exponent (Σv_in − Σv_out − fee) is 0 — hence balanced.
#
# The group-element inverses are SCALAR negations in the exponent (C^{-1} = C^{q-1} in
# G_q, g^{-fee} = g^{q-fee}) so the whole thing is one multi-exponentiation — no group
# inverse primitive is needed. This is the from-scratch oracle the C port
# (src/crypto/ff/ffbalance.c) is checked against byte-for-byte (ff_balance.json).
import hashlib, json, os
import verify_ff_pedersen as vp
import verify_ff_scalar as vs

P, Q, ELEM = vp.P, vp.Q, vp.ELEM
G_VAL = 4
H = vp.H
BAL_CDST = b"DETERM-FF-BALANCE-v1-challenge"


def _b(x):
    return x.to_bytes(ELEM, "big")


def commit(v, r):
    return vp.commit_int(v, r)            # g^v · h^r mod p (vp.G = 4, vp.H = H)


def balance_excess(C_in, C_out, fee):
    """E = Π C_in · Π C_out^{-1} · g^{-fee} mod p. C^{-1} = C^{q-1} (order-q), g^{-fee} =
    g^{(q-fee) mod q}. Matches the C determ_ff_msm over [C_in(1), C_out(q-1), g(q-fee)]."""
    acc = 1
    for C in C_in:
        acc = (acc * C) % P
    negone = (Q - 1) % Q                  # scalar -1 mod q
    for C in C_out:
        acc = (acc * pow(C, negone, P)) % P
    negfee = (-fee) % Q                   # scalar -fee mod q
    acc = (acc * pow(G_VAL, negfee, P)) % P
    return acc


def _challenge(E, T):
    return vs.hash_to_scalar(_b(E) + _b(T), BAL_CDST)


def balance_prove(E, x, k):
    """Schnorr PoK of x with E = h^x. T = h^k ; c = H(E‖T) ; s = k + c·x mod q.
    proof = T ‖ s (2×384 big-endian). x, k in [0,q)."""
    T = pow(H, k, P)
    c = _challenge(E, T)
    s = (k + c * x) % Q
    return _b(T) + _b(s)


def balance_verify(E, proof):
    """0/True iff h^s == T · E^c."""
    T = int.from_bytes(proof[:ELEM], "big")
    s = int.from_bytes(proof[ELEM:2 * ELEM], "big")
    c = _challenge(E, T)
    lhs = pow(H, s, P)
    rhs = (T * pow(E, c, P)) % P
    return lhs == rhs


# ── §3.13 file-half checker ───────────────────────────────────────────────────
def check_ff_balance(vec, label):
    C_in = [int(h, 16) for h in vec["c_in_hex"]]
    C_out = [int(h, 16) for h in vec["c_out_hex"]]
    fee = vec["fee"]
    x = int(vec["x_hex"], 16)
    k = int(vec["k_hex"], 16)
    E = balance_excess(C_in, C_out, fee)
    if _b(E).hex() != vec["e_hex"]:
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
    x = (sum(r_in) - sum(r_out)) % Q
    assert E == pow(H, x, P), "balanced excess is not h^{r_excess}"
    proof = balance_prove(E, x, 0x9999)
    assert balance_verify(E, proof), "valid balance proof rejected"
    # unbalanced: bump one output value -> E gains a g-component -> proof can't verify
    C_out_bad = [commit(6, r_out[0]), commit(v_out[1], r_out[1])]
    E_bad = balance_excess(C_in, C_out_bad, fee)
    assert E_bad != pow(H, x, P), "unbalanced excess unexpectedly has no g-component"
    assert not balance_verify(E_bad, balance_prove(E_bad, x, 0x9999)), \
        "balance verify accepted an unbalanced transaction"
    # tamper s -> reject
    bad = bytearray(proof); bad[-1] ^= 1
    assert not balance_verify(E, bytes(bad)), "balance verify accepted a tampered proof"
    # fee = 0 edge (the g^{-fee} term is the identity)
    v_in2, r_in2, v_out2, r_out2 = [7], [55], [7], [66]
    Ci = [commit(v_in2[0], r_in2[0])]; Co = [commit(v_out2[0], r_out2[0])]
    E2 = balance_excess(Ci, Co, 0)
    x2 = (r_in2[0] - r_out2[0]) % Q
    assert balance_verify(E2, balance_prove(E2, x2, 0x1234)), "fee=0 balance failed"
    print("verify_ff_balance selftest: balanced accept + unbalanced/tamper reject + fee=0 OK")


def emit():
    vectors = []
    for name, v_in, r_in, v_out, r_out, fee in [
        ("balance 2in-2out fee3", [10, 20], [111, 222], [5, 22], [33, 44], 3),
        ("balance 1in-2out fee0", [100], [777], [40, 60], [123, 654], 0),
    ]:
        C_in = [commit(v, r) for v, r in zip(v_in, r_in)]
        C_out = [commit(v, r) for v, r in zip(v_out, r_out)]
        E = balance_excess(C_in, C_out, fee)
        x = (sum(r_in) - sum(r_out)) % Q
        k = int.from_bytes(hashlib.sha256(name.encode()).digest() * 12, "big") % Q or 1
        proof = balance_prove(E, x, k)
        assert balance_verify(E, proof)
        vectors.append({"name": name, "type": "balance",
                        "c_in_hex": [_b(C).hex() for C in C_in],
                        "c_out_hex": [_b(C).hex() for C in C_out],
                        "fee": fee, "x_hex": vp._s(x), "k_hex": vp._s(k),
                        "e_hex": _b(E).hex(), "proof_hex": proof.hex()})
    doc = {"primitive": "ff_balance",
           "source": ("Generated by tools/verify_ff_balance.py (Determ CRYPTO-C99-SPEC §3.20 inc.7); "
                      "confidential-tx balance proof over the RFC 3526 MODP-3072 subgroup — a Schnorr "
                      "PoK that the commitment excess E = Π C_in · Π C_out^{-1} · g^{-fee} opens to zero "
                      "(E = h^x). From-scratch Python bignum reference."),
           "note": ("Balance proof: proves Σv_in = Σv_out + fee without revealing amounts. "
                    "E computed by one multi-exponentiation (C^{-1}=C^{q-1}, g^{-fee}=g^{q-fee}); "
                    "proof = T‖s (Schnorr, challenge DST DETERM-FF-BALANCE-v1-challenge). "
                    "Commitments/scalars 384-byte big-endian; fee a uint64."),
           "vectors": vectors}
    out = os.path.join(os.path.dirname(__file__), "vectors", "ff_balance.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=2); f.write("\n")
    print("wrote %s (%d vectors)" % (out, len(vectors)))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "emit":
        emit()
    else:
        _selftest()
