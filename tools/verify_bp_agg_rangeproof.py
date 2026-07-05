#!/usr/bin/env python3
# Independent Python reference for the Determ AGGREGATED Bulletproofs range proof
# over NIST P-256 — CRYPTO-C99-SPEC.md §3.19 increment 6. Proves that m Pedersen-
# committed values v_0..v_{m-1} each lie in [0, 2^n) in ONE proof of size
# 2*log2(m*n)+O(1) group elements (vs. m separate proofs). This is the from-scratch
# oracle the C port is checked against byte-for-byte, and the design reference the C
# is ported FROM (python-prove-first discipline).
#
# Construction (Bunz et al. 2018 §4.3, the aggregation of m single range proofs):
# the m bit-vectors are concatenated into length-mn a_L; value j's 2^n slot is
# scaled by z^(2+j) (0-indexed j, so j=0 -> z^2 recovers the single-value case).
# The final <l,r> = t_hat check is compressed by the inc.4 IPA over the mn-wide
# generators. Reuses the single-value helpers from verify_bp_rangeproof.py.
import verify_pedersen as vp
import verify_bp_ipa as ipa
import verify_bp_rangeproof as rp

N = vp.N
G = vp.G

AGG_LABEL = b"DETERM-BP-AGGRANGE-v1"
AGG_CHAL_DST = b"DETERM-BP-AGGRANGE-v1-challenge"


def value_commit(v, gamma):
    return rp.value_commit(v, gamma)          # V = v*g + gamma*h


class ATranscript:
    """Deterministic Fiat-Shamir transcript for the aggregated proof, seeded with
    (m, n, V_0..V_{m-1}). Distinct label/DST from the single-value + IPA transcripts."""

    def __init__(self, Vs, n):
        m = len(Vs)
        self.t = bytearray(AGG_LABEL)
        self.t += m.to_bytes(4, "big")
        self.t += n.to_bytes(4, "big")
        for V in Vs:
            self.t += vp.compress(V)

    def absorb(self, pt):
        self.t += vp.compress(pt)

    def challenge(self):
        x = ipa.hash_to_scalar(bytes(self.t), AGG_CHAL_DST)
        if x == 0:
            raise ValueError("zero challenge")
        self.t += x.to_bytes(32, "big")
        return x


def _zslot(z, twon, m, n):
    """The concatenated z^(2+j) * 2^n vector (length m*n): slot j scaled by z^(2+j)."""
    out = [0] * (m * n)
    zp = (z * z) % N                          # z^(2+0) = z^2
    for j in range(m):
        for k in range(n):
            out[j * n + k] = (zp * twon[k]) % N
        zp = (zp * z) % N                     # z^(2+j) -> z^(2+j+1)
    return out


def delta(y, z, m, n):
    """delta(y,z) = (z - z^2)*<1^{mn}, y^{mn}> - (sum_j z^(3+j)) * <1^n, 2^n>."""
    nm = m * n
    sum_y = sum(rp.powers(y, nm)) % N
    sum_2 = (pow(2, n, N) - 1) % N             # <1^n, 2^n>
    zsum = 0
    zp = pow(z, 3, N)                          # z^(3+0)
    for j in range(m):
        zsum = (zsum + zp) % N
        zp = (zp * z) % N
    return ((z - z * z) * sum_y - zsum * sum_2) % N


def prove(vs, gammas, n, rnd):
    """vs, gammas: length-m lists. rnd supplies alpha, rho, sL[mn], sR[mn], tau1, tau2."""
    m = len(vs)
    nm = m * n
    g, h = G, rp.h_scalar()
    gv, hv, u = rp.g_vec(nm), rp.h_vec(nm), rp.u_gen()
    Vs = [value_commit(vs[j], gammas[j]) for j in range(m)]

    aL = []
    for j in range(m):
        aL += rp.bit_decompose(vs[j], n)      # concat of m n-bit decompositions
    aR = [(aL[i] - 1) % N for i in range(nm)]

    alpha, rho = rnd["alpha"], rnd["rho"]
    sL, sR = rnd["sL"], rnd["sR"]
    tau1, tau2 = rnd["tau1"], rnd["tau2"]

    A = ipa.msm([alpha] + aL + aR, [h] + gv + hv)
    S = ipa.msm([rho] + sL + sR, [h] + gv + hv)

    tr = ATranscript(Vs, n)
    tr.absorb(A); tr.absorb(S)
    y = tr.challenge(); z = tr.challenge()

    yn = rp.powers(y, nm)
    twon = rp.powers(2, n)
    z2 = (z * z) % N
    zslot = _zslot(z, twon, m, n)

    l0 = [(aL[i] - z) % N for i in range(nm)]
    l1 = list(sL)
    r0 = [(yn[i] * ((aR[i] + z) % N) + zslot[i]) % N for i in range(nm)]
    r1 = [(yn[i] * sR[i]) % N for i in range(nm)]

    t1 = (ipa.inner(l1, r0) + ipa.inner(l0, r1)) % N
    t2 = ipa.inner(l1, r1) % N
    T1 = ipa.msm([t1, tau1], [g, h])
    T2 = ipa.msm([t2, tau2], [g, h])

    tr.absorb(T1); tr.absorb(T2)
    x = tr.challenge()

    l = [(l0[i] + l1[i] * x) % N for i in range(nm)]
    r = [(r0[i] + r1[i] * x) % N for i in range(nm)]
    that = ipa.inner(l, r)

    # taux = tau2*x^2 + tau1*x + sum_j z^(2+j)*gamma_j
    taux = (tau2 * (x * x) + tau1 * x) % N
    zp = z2
    for j in range(m):
        taux = (taux + zp * gammas[j]) % N
        zp = (zp * z) % N
    mu = (alpha + rho * x) % N

    yinvn = rp.powers(pow(y, N - 2, N), nm)
    hprime = [vp.pt_mul(yinvn[i], hv[i]) for i in range(nm)]
    P_ipa = ipa.commit_P(l, r, gv, hprime, u)
    inner_proof = ipa.prove(l, r, gv, hprime, u, P_ipa, nm)

    return {"Vs": Vs, "A": A, "S": S, "T1": T1, "T2": T2,
            "taux": taux, "mu": mu, "that": that, "ipa": inner_proof, "m": m, "n": n}


def verify(proof, m, n):
    nm = m * n
    g, h = G, rp.h_scalar()
    gv, hv, u = rp.g_vec(nm), rp.h_vec(nm), rp.u_gen()
    Vs, A, S = proof["Vs"], proof["A"], proof["S"]
    T1, T2 = proof["T1"], proof["T2"]
    taux, mu, that = proof["taux"], proof["mu"], proof["that"]
    if len(Vs) != m:
        return False

    tr = ATranscript(Vs, n)
    tr.absorb(A); tr.absorb(S)
    y = tr.challenge(); z = tr.challenge()
    tr.absorb(T1); tr.absorb(T2)
    x = tr.challenge()

    yn = rp.powers(y, nm)
    twon = rp.powers(2, n)
    z2 = (z * z) % N
    zslot = _zslot(z, twon, m, n)

    # Check 1: that*g + taux*h == sum_j z^(2+j)*V_j + delta*g + x*T1 + x^2*T2
    scal = [that, taux]
    pts = [g, h]
    lhs = ipa.msm(scal, pts)
    rscal = []
    rpts = []
    zp = z2
    for j in range(m):
        rscal.append(zp); rpts.append(Vs[j]); zp = (zp * z) % N
    rscal += [delta(y, z, m, n), x, (x * x) % N]
    rpts += [g, T1, T2]
    rhs = ipa.msm(rscal, rpts)
    if lhs != rhs:
        return False

    # Check 2: reconstruct P = A + x*S - z*<1,gv> + <z*y^{mn} + zslot, h'> - mu*h
    yinvn = rp.powers(pow(y, N - 2, N), nm)
    hprime = [vp.pt_mul(yinvn[i], hv[i]) for i in range(nm)]
    scalars = ([1, x] + [(-z) % N] * nm
               + [(z * yn[i] + zslot[i]) % N for i in range(nm)] + [(-mu) % N])
    points = [A, S] + gv + hprime + [h]
    P = ipa.msm(scalars, points)
    P_ipa = vp.pt_add(P, vp.pt_mul(that, u))
    return ipa.verify(P_ipa, gv, hprime, u, proof["ipa"], nm)


# ---- deterministic prover randomness (fixed, reproducible) ----
def _demo_rnd(nm, seed):
    return {
        "alpha": (7 * seed + 3) % N,
        "rho": (11 * seed + 5) % N,
        "sL": [(13 * seed + 17 * i + 1) % N for i in range(nm)],
        "sR": [(19 * seed + 23 * i + 2) % N for i in range(nm)],
        "tau1": (29 * seed + 31) % N,
        "tau2": (37 * seed + 41) % N,
    }


def _demo_vals(m, n, seed):
    vs = [((41 * seed + 7 * j + 3) % (1 << n)) for j in range(m)]
    gammas = [((101 * seed + 13 * j + 7) % N) for j in range(m)]
    return vs, gammas


def proof_to_hex(proof):
    d = {
        "V_hex": [vp.compress(V).hex() for V in proof["Vs"]],
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


def check_agg_rangeproof(vec, label):
    """§3.13 file-half checker (imported by test_c99_vector_files.sh)."""
    m = int(vec["m"]); n = int(vec["n"])
    vs = [int(x, 16) for x in vec["v_hex"]]
    gammas = [int(x, 16) for x in vec["gamma_hex"]]
    rnd = _demo_rnd(m * n, int(vec["seed"]))
    got = proof_to_hex(prove(vs, gammas, n, rnd))
    if got["V_hex"] != vec["V_hex"]:
        return "recomputed V commitments != vector"
    for k in ("A_hex", "S_hex", "T1_hex", "T2_hex", "taux_hex", "mu_hex", "that_hex",
              "ipa_L_hex", "ipa_R_hex", "ipa_a_hex", "ipa_b_hex"):
        if got[k] != vec[k]:
            return "recomputed %s != vector" % k
    if not verify(prove(vs, gammas, n, rnd), m, n):
        return "round-trip verify failed (runner bug)"
    return None


def _t0_oracle(vs, gammas, n, rnd):
    """t_0 = <l0,r0> must equal sum_j z^(2+j)*v_j + delta(y,z) — the identity Check 1
    relies on. Recomputed the long way, independent of prove()."""
    m = len(vs); nm = m * n
    g, h = G, rp.h_scalar()
    gv, hv = rp.g_vec(nm), rp.h_vec(nm)
    aL = []
    for j in range(m):
        aL += rp.bit_decompose(vs[j], n)
    aR = [(aL[i] - 1) % N for i in range(nm)]
    Vs = [value_commit(vs[j], gammas[j]) for j in range(m)]
    A = ipa.msm([rnd["alpha"]] + aL + aR, [h] + gv + hv)
    S = ipa.msm([rnd["rho"]] + rnd["sL"] + rnd["sR"], [h] + gv + hv)
    tr = ATranscript(Vs, n)
    tr.absorb(A); tr.absorb(S)
    y = tr.challenge(); z = tr.challenge()
    yn = rp.powers(y, nm); twon = rp.powers(2, n); z2 = (z * z) % N
    zslot = _zslot(z, twon, m, n)
    l0 = [(aL[i] - z) % N for i in range(nm)]
    r0 = [(yn[i] * ((aR[i] + z) % N) + zslot[i]) % N for i in range(nm)]
    t0 = ipa.inner(l0, r0)
    expect = delta(y, z, m, n)
    zp = z2
    for j in range(m):
        expect = (expect + zp * (vs[j] % N)) % N
        zp = (zp * z) % N
    assert t0 == expect, "t0 oracle broke: m=%d n=%d" % (m, n)


def _selftest():
    for m, n in ((1, 4), (2, 2), (2, 4), (4, 2), (2, 8), (4, 4)):
        for seed in (1, 2, 3):
            vs, gammas = _demo_vals(m, n, seed)
            rnd = _demo_rnd(m * n, seed)
            _t0_oracle(vs, gammas, n, rnd)
            pf = prove(vs, gammas, n, rnd)
            assert verify(pf, m, n), "round-trip failed m=%d n=%d" % (m, n)
            import copy
            for fld in ("taux", "mu", "that"):
                bad = copy.copy(pf); bad[fld] = (pf[fld] + 1) % N
                assert not verify(bad, m, n), "accepted tampered %s m=%d n=%d" % (fld, m, n)
            for fld in ("A", "S", "T1", "T2"):
                bad = copy.copy(pf); bad[fld] = vp.pt_add(pf[fld], G)
                assert not verify(bad, m, n), "accepted tampered %s m=%d n=%d" % (fld, m, n)
            # tamper one value commitment -> reject
            bad = copy.copy(pf); bad["Vs"] = list(pf["Vs"]); bad["Vs"][0] = vp.pt_add(pf["Vs"][0], G)
            assert not verify(bad, m, n), "accepted tampered V m=%d n=%d" % (m, n)
        # out-of-range: make value 0 be 2^n (one bad value in the batch) -> reject
        vs, gammas = _demo_vals(m, n, 9)
        vs = list(vs); vs[0] = 1 << n
        pf = prove(vs, gammas, n, _demo_rnd(m * n, 9))
        assert not verify(pf, m, n), "accepted out-of-range value in batch m=%d n=%d" % (m, n)
    print("verify_bp_agg_rangeproof selftest: t0-oracle + round-trip + tamper + "
          "out-of-range-in-batch OK for (m,n) in {(1,4),(2,2),(2,4),(4,2),(2,8),(4,4)}")


def emit():
    import json, os
    vectors = []
    for m, n, seed in ((2, 4, 1), (4, 4, 2), (2, 8, 3)):
        vs, gammas = _demo_vals(m, n, seed)
        rnd = _demo_rnd(m * n, seed)
        pf = prove(vs, gammas, n, rnd)
        assert verify(pf, m, n)
        d = {"name": "agg-rangeproof m=%d n=%d" % (m, n), "type": "agg_rangeproof",
             "m": m, "n": n, "seed": seed,
             "v_hex": ["%064x" % v for v in vs], "gamma_hex": ["%064x" % g for g in gammas]}
        d.update(proof_to_hex(pf))
        vectors.append(d)
    doc = {
        "primitive": "bp_agg_rangeproof",
        "source": ("Generated by tools/verify_bp_agg_rangeproof.py (Determ CRYPTO-C99-SPEC "
                   "§3.19 inc.6); the AGGREGATED Bulletproofs range proof over NIST P-256, "
                   "m values in one proof, deterministic Fiat-Shamir, from-scratch EC."),
        "note": ("Aggregated range proof: m values v_j in [0,2^n) in one proof. a_L = concat "
                 "of m n-bit decomps; value j's 2^n slot scaled z^(2+j); IPA over m*n. "
                 "Vals/gammas from _demo_vals(m,n,seed), randomness from _demo_rnd(m*n,seed)."),
        "vectors": vectors,
    }
    out = os.path.join(os.path.dirname(__file__), "vectors", "bp_agg_rangeproof.json")
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
