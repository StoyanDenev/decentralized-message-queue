#!/usr/bin/env python3
# Independent Python reference for the Determ Bulletproofs single-value RANGE
# PROOF over NIST P-256 — CRYPTO-C99-SPEC.md §3.19 increment 5. This is the
# from-scratch oracle the C port is checked against (byte-for-byte proof bytes),
# and the design reference the C is ported FROM (python-prove-first discipline).
#
# A Bulletproofs range proof (Bünz et al. 2018, §4.1/§4.2, non-interactive via
# Fiat-Shamir) proves that a Pedersen-committed value v lies in [0, 2^n) WITHOUT
# revealing v, in 2*log2(n)+O(1) group elements. The value commitment is the
# §3.19 inc.1 Pedersen commitment V = v*g + gamma*h; the log-size compression of
# the final <l,r> = t_hat check is the §3.19 inc.4 inner-product argument.
#
# Generator layout (all nothing-up-my-sleeve, mutually independent):
#   g      = the P-256 base point           (the VALUE generator)
#   h      = derive_h()  (Pedersen scalar H, distinct DST)   (the BLINDING gen)
#   g_i    = derive_gen(i, 0)  (the "G" family)   (the bit-vector a_L generators)
#   h_i    = derive_gen(i, 1)  (the "H" family)   (the bit-vector a_R generators)
#   u      = derive_gen(0xFFFFFFFF, 0)            (the IPA inner-product gen)
# The IPA runs over g_i and the y-scaled h'_i = y^-i * h_i (the Bulletproofs
# generator re-basing that folds the y^n weighting into the h side).
import verify_pedersen as vp
import verify_bp_ipa as ipa

N = vp.N
G = vp.G                                    # the value generator g (base point)

RANGE_LABEL = b"DETERM-BP-RANGE-v1"
RANGE_CHAL_DST = b"DETERM-BP-RANGE-v1-challenge"


def h_scalar():
    """The blinding generator h — the Pedersen scalar H (unknown log_g(h))."""
    return vp.derive_h()


def g_vec(n):
    return [vp.derive_gen(i, 0) for i in range(n)]


def h_vec(n):
    return [vp.derive_gen(i, 1) for i in range(n)]


def u_gen():
    return vp.derive_gen(ipa.U_INDEX, 0)


def powers(x, n):
    """[1, x, x^2, ..., x^(n-1)] mod N."""
    out = [1 % N]
    for _ in range(1, n):
        out.append((out[-1] * x) % N)
    return out


def value_commit(v, gamma):
    """V = v*g + gamma*h (the §3.19 inc.1 Pedersen commitment shape)."""
    return ipa.msm([v % N, gamma % N], [G, h_scalar()])


class RTranscript:
    """Deterministic Fiat-Shamir transcript for the range proof, seeded with the
    statement (V, n); challenges hash the whole running buffer and are re-absorbed.
    Distinct label/DST from the IPA's, so the two transcripts never collide."""

    def __init__(self, V, n):
        self.t = bytearray(RANGE_LABEL)
        self.t += vp.compress(V)
        self.t += n.to_bytes(4, "big")

    def absorb(self, pt):
        self.t += vp.compress(pt)

    def challenge(self):
        x = ipa.hash_to_scalar(bytes(self.t), RANGE_CHAL_DST)
        if x == 0:
            raise ValueError("zero challenge")
        self.t += x.to_bytes(32, "big")
        return x


def bit_decompose(v, n):
    """a_L = the n low bits of v (little-endian)."""
    return [(v >> i) & 1 for i in range(n)]


def delta(y, z, n):
    """delta(y,z) = (z - z^2)*<1^n, y^n> - z^3*<1^n, 2^n>  (the verifier's public
    scalar correction; Bünz et al. eq. for t_0)."""
    sum_y = sum(powers(y, n)) % N
    sum_2 = (pow(2, n, N) - 1) % N              # <1^n, 2^n> = 2^n - 1
    return ((z - z * z) * sum_y - pow(z, 3, N) * sum_2) % N


def prove(v, gamma, n, rnd):
    """Returns a proof dict. `rnd` supplies the prover randomness deterministically
    (alpha, rho, sL[n], sR[n], tau1, tau2) so the proof bytes are reproducible."""
    g, h = G, h_scalar()
    gv, hv, u = g_vec(n), h_vec(n), u_gen()
    aL = bit_decompose(v, n)
    aR = [(aL[i] - 1) % N for i in range(n)]
    alpha, rho = rnd["alpha"], rnd["rho"]
    sL, sR = rnd["sL"], rnd["sR"]
    tau1, tau2 = rnd["tau1"], rnd["tau2"]

    V = value_commit(v, gamma)
    A = ipa.msm([alpha] + aL + aR, [h] + gv + hv)          # alpha*h + <aL,gv> + <aR,hv>
    S = ipa.msm([rho] + sL + sR, [h] + gv + hv)            # rho*h   + <sL,gv> + <sR,hv>

    tr = RTranscript(V, n)
    tr.absorb(A)
    tr.absorb(S)
    y = tr.challenge()
    z = tr.challenge()

    yn = powers(y, n)
    twon = powers(2, n)
    z2 = (z * z) % N

    # l(X) = (aL - z*1) + sL*X ;  r(X) = yn o (aR + z*1 + sR*X) + z^2*2^n
    l0 = [(aL[i] - z) % N for i in range(n)]
    l1 = list(sL)
    r0 = [(yn[i] * ((aR[i] + z) % N) + z2 * twon[i]) % N for i in range(n)]
    r1 = [(yn[i] * sR[i]) % N for i in range(n)]

    t1 = (ipa.inner(l1, r0) + ipa.inner(l0, r1)) % N       # <l(X),r(X)> linear coeff
    t2 = ipa.inner(l1, r1) % N                             # ... quadratic coeff
    T1 = ipa.msm([t1, tau1], [g, h])                       # t1*g + tau1*h
    T2 = ipa.msm([t2, tau2], [g, h])                       # t2*g + tau2*h

    tr.absorb(T1)
    tr.absorb(T2)
    x = tr.challenge()

    l = [(l0[i] + l1[i] * x) % N for i in range(n)]
    r = [(r0[i] + r1[i] * x) % N for i in range(n)]
    that = ipa.inner(l, r)                                 # t_hat = <l, r>
    taux = (tau2 * (x * x) + tau1 * x + z2 * gamma) % N
    mu = (alpha + rho * x) % N

    # IPA sub-proof of <l, r> = t_hat over (gv, h'v = y^-i * hv, u).
    yinvn = powers(pow(y, N - 2, N), n)
    hprime = [vp.pt_mul(yinvn[i], hv[i]) for i in range(n)]
    P_ipa = ipa.commit_P(l, r, gv, hprime, u)              # <l,gv> + <r,h'v> + that*u
    inner_proof = ipa.prove(l, r, gv, hprime, u, P_ipa, n)

    return {"V": V, "A": A, "S": S, "T1": T1, "T2": T2,
            "taux": taux, "mu": mu, "that": that, "ipa": inner_proof, "n": n}


def verify(proof, n):
    g, h = G, h_scalar()
    gv, hv, u = g_vec(n), h_vec(n), u_gen()
    V, A, S = proof["V"], proof["A"], proof["S"]
    T1, T2 = proof["T1"], proof["T2"]
    taux, mu, that = proof["taux"], proof["mu"], proof["that"]

    tr = RTranscript(V, n)
    tr.absorb(A)
    tr.absorb(S)
    y = tr.challenge()
    z = tr.challenge()
    tr.absorb(T1)
    tr.absorb(T2)
    x = tr.challenge()

    yn = powers(y, n)
    twon = powers(2, n)
    z2 = (z * z) % N

    # Check 1 (the t_hat / polynomial identity):
    #   that*g + taux*h  ==  z^2*V + delta(y,z)*g + x*T1 + x^2*T2
    lhs = ipa.msm([that, taux], [g, h])
    rhs = ipa.msm([z2, delta(y, z, n), x, (x * x) % N], [V, g, T1, T2])
    if lhs != rhs:
        return False

    # Check 2 (the IPA relation): reconstruct P = <l,gv> + <r,h'v> from the public
    # transcript, then verify the inner-product argument binds <l,r> = that.
    yinvn = powers(pow(y, N - 2, N), n)
    hprime = [vp.pt_mul(yinvn[i], hv[i]) for i in range(n)]
    # P = A + x*S - z*<1,gv> + <z*yn + z^2*2^n, h'v> - mu*h
    scalars = ([1, x] + [(-z) % N] * n
               + [(z * yn[i] + z2 * twon[i]) % N for i in range(n)] + [(-mu) % N])
    points = [A, S] + gv + hprime + [h]
    P = ipa.msm(scalars, points)
    P_ipa = vp.pt_add(P, vp.pt_mul(that, u))
    return ipa.verify(P_ipa, gv, hprime, u, proof["ipa"], n)


# ---- deterministic prover randomness (fixed, reproducible KAT inputs) ----
def _demo_rnd(n, seed):
    return {
        "alpha": (7 * seed + 3) % N,
        "rho": (11 * seed + 5) % N,
        "sL": [(13 * seed + 17 * i + 1) % N for i in range(n)],
        "sR": [(19 * seed + 23 * i + 2) % N for i in range(n)],
        "tau1": (29 * seed + 31) % N,
        "tau2": (37 * seed + 41) % N,
    }


def proof_to_hex(proof):
    d = {
        "V_hex": vp.compress(proof["V"]).hex(),
        "A_hex": vp.compress(proof["A"]).hex(),
        "S_hex": vp.compress(proof["S"]).hex(),
        "T1_hex": vp.compress(proof["T1"]).hex(),
        "T2_hex": vp.compress(proof["T2"]).hex(),
        "taux_hex": "%064x" % proof["taux"],
        "mu_hex": "%064x" % proof["mu"],
        "that_hex": "%064x" % proof["that"],
    }
    d.update({("ipa_" + k): v for k, v in ipa.proof_to_hex(proof["ipa"]).items()})
    return d


def check_rangeproof(vec, label):
    """§3.13 file-half checker (imported by test_c99_vector_files.sh)."""
    n = int(vec["n"])
    v = int(vec["v_hex"], 16)
    gamma = int(vec["gamma_hex"], 16)
    rnd = _demo_rnd(n, int(vec["seed"]))
    got = proof_to_hex(prove(v, gamma, n, rnd))
    for k in ("V_hex", "A_hex", "S_hex", "T1_hex", "T2_hex",
              "taux_hex", "mu_hex", "that_hex",
              "ipa_L_hex", "ipa_R_hex", "ipa_a_hex", "ipa_b_hex"):
        if got[k] != vec[k]:
            return "recomputed %s != vector" % k
    # also confirm a live round-trip, so the corpus is not just static bytes
    if not verify(prove(v, gamma, n, rnd), n):
        return "round-trip verify failed (runner bug)"
    return None


def _t0_oracle(v, gamma, n, rnd):
    """Decisive algebraic oracle: t_0 = <l0, r0> must equal z^2*v + delta(y,z)
    for an in-range v — the identity Check 1 relies on. Recompute it the long way
    (from the l0/r0 vectors) and compare to the closed form, independent of prove()."""
    g, h = G, h_scalar()
    gv, hv = g_vec(n), h_vec(n)
    aL = bit_decompose(v, n)
    aR = [(aL[i] - 1) % N for i in range(n)]
    V = value_commit(v, gamma)
    A = ipa.msm([rnd["alpha"]] + aL + aR, [h] + gv + hv)
    S = ipa.msm([rnd["rho"]] + rnd["sL"] + rnd["sR"], [h] + gv + hv)
    tr = RTranscript(V, n)
    tr.absorb(A); tr.absorb(S)
    y = tr.challenge(); z = tr.challenge()
    yn = powers(y, n); twon = powers(2, n); z2 = (z * z) % N
    l0 = [(aL[i] - z) % N for i in range(n)]
    r0 = [(yn[i] * ((aR[i] + z) % N) + z2 * twon[i]) % N for i in range(n)]
    t0 = ipa.inner(l0, r0)
    expect = (z2 * (v % N) + delta(y, z, n)) % N
    assert t0 == expect, "t0 oracle broke: n=%d v=%d" % (n, v)


def _selftest():
    for n in (1, 2, 4, 8, 16):
        for seed, v in ((1, 0), (2, 1), (3, (1 << n) - 1), (4, min(5, (1 << n) - 1))):
            gamma = (101 * seed + 7) % N
            rnd = _demo_rnd(n, seed)
            _t0_oracle(v, gamma, n, rnd)                 # the algebraic reason Check 1 holds
            pf = prove(v, gamma, n, rnd)
            assert verify(pf, n), "round-trip failed n=%d v=%d" % (n, v)
            # soundness: tamper each scalar / point field -> reject
            import copy
            for fld in ("taux", "mu", "that"):
                bad = copy.copy(pf); bad[fld] = (pf[fld] + 1) % N
                assert not verify(bad, n), "accepted tampered %s n=%d" % (fld, n)
            for fld in ("A", "S", "T1", "T2", "V"):
                bad = copy.copy(pf); bad[fld] = vp.pt_add(pf[fld], G)
                assert not verify(bad, n), "accepted tampered %s n=%d" % (fld, n)
        # out-of-range: v = 2^n cannot yield a verifying proof
        oor = prove(1 << n, (13) % N, n, _demo_rnd(n, 9))
        assert not verify(oor, n), "accepted an out-of-range v=2^%d" % n
    print("verify_bp_rangeproof selftest: t0-oracle + round-trip + tamper + "
          "out-of-range OK for n in {1,2,4,8,16}")


def emit():
    import json, os
    vectors = []
    for n, seed, v in ((4, 1, 9), (8, 2, 200), (16, 3, 43210)):
        gamma = (101 * seed + 7) % N
        rnd = _demo_rnd(n, seed)
        pf = prove(v, gamma, n, rnd)
        assert verify(pf, n)
        d = {"name": "rangeproof n=%d v=%d" % (n, v), "type": "rangeproof",
             "n": n, "seed": seed, "v_hex": "%064x" % v, "gamma_hex": "%064x" % gamma}
        d.update(proof_to_hex(pf))
        vectors.append(d)
    doc = {
        "primitive": "bp_rangeproof",
        "source": ("Generated by tools/verify_bp_rangeproof.py (Determ CRYPTO-C99-SPEC "
                   "§3.19 inc.5); the Bulletproofs single-value range proof over NIST "
                   "P-256, deterministic Fiat-Shamir transcript, proof bytes recomputed "
                   "from scratch (own P-256 EC + RFC 9380 h2c + the inc.4 IPA)."),
        "note": ("Range proof v in [0,2^n): V=v*g+gamma*h; A,S bit-vector commits; "
                 "T1,T2 poly commits; taux,mu,that scalars; then the inc.4 IPA over "
                 "(g_i, h'_i=y^-i*h_i, u). Prover randomness from _demo_rnd(n,seed)."),
        "vectors": vectors,
    }
    out = os.path.join(os.path.dirname(__file__), "vectors", "bp_rangeproof.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print("wrote %s (%d vectors)" % (out, len(vectors)))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "emit":
        emit()
    else:
        _selftest()
