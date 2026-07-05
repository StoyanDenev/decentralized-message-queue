#!/usr/bin/env python3
# Independent Python reference for the Determ FINITE-FIELD single-value Bulletproofs
# RANGE PROOF over Z_p* — CRYPTO-C99-SPEC.md §3.20 increment 5 (the MODERN-profile
# mirror of the §3.19 P-256 range proof, src/crypto/pedersen/rangeproof.c). Proves a
# Pedersen-committed value v lies in [0, 2^n) WITHOUT revealing v, in 2·log2(n)+O(1)
# group elements. Value commitment V = g^v · h^gamma mod p (g = 4, the §3.20 inc.1
# value generator; h = the nothing-up-my-sleeve blinding generator). Bit-vector
# commitments A, S over the inc.2 generator families; the <l,r>=t_hat check compressed
# by the inc.4 IPA over (G_i, h'_i = y^-i·H_i, u). Transcript DETERM-FF-BP-RANGE-v1.
#
# From-scratch oracle the C port (src/crypto/ff/ffrangeproof.c) is checked against
# byte-for-byte (tools/vectors/ff_rangeproof.json, §3.13 dual-oracle). Reuses the inc.1
# generators, inc.3 scalar field, inc.4 IPA; Python native bignums are the reference.
import hashlib, json, os
import verify_ff_pedersen as vp
import verify_ff_scalar as vs
import verify_ff_ipa as vi

P, Q, ELEM = vp.P, vp.Q, vp.ELEM
G_VAL = 4                                  # the §3.20 inc.1 value generator (a QR of order q)
H = vp.H
U_INDEX = 0xFFFFFFFF
RANGE_MAX_BITS = 64

RTR_LABEL = b"DETERM-FF-BP-RANGE-v1"
RTR_CDST = b"DETERM-FF-BP-RANGE-v1-challenge"


def _b(x):
    return x.to_bytes(ELEM, "big")


def sadd(a, b): return (a + b) % Q
def ssub(a, b): return (a - b) % Q
def smul(a, b): return (a * b) % Q
def sinv(a): return pow(a, Q - 2, Q)


def gen(i, which): return vp.derive_gen(i, which)
def gen_u(): return vp.derive_gen(U_INDEX, 0)


def inner(a, b): return sum(smul(a[i], b[i]) for i in range(len(a))) % Q


def msm(scalars, points):
    acc = 1
    for s, pt in zip(scalars, points):
        acc = (acc * pow(pt, s, P)) % P
    return acc


def powers(x, m):
    out = [1] * m
    for i in range(1, m):
        out[i] = smul(out[i - 1], x)
    return out


def rounds(n):
    if n < 1 or n > RANGE_MAX_BITS:
        raise ValueError("n out of range")
    r, m = 0, n
    while m > 1:
        if m & 1:
            raise ValueError("n not a power of two")
        m >>= 1
        r += 1
    return r


def proof_len(n):
    return 7 * ELEM + (2 * rounds(n) + 2) * ELEM


class _RTr:
    def __init__(self, Vval, n):
        self.buf = bytearray(RTR_LABEL)
        self.buf += _b(Vval)
        self.buf += int(n).to_bytes(4, "big")

    def absorb(self, ptval):
        self.buf += _b(ptval)

    def challenge(self):
        c = vs.hash_to_scalar(bytes(self.buf), RTR_CDST)
        if c == 0:
            raise ValueError("zero challenge")
        self.buf += _b(c)
        return c


def commit_value(v, gamma):
    return (pow(G_VAL, v, P) * pow(H, gamma, P)) % P


def prove(v, gamma, alpha, rho, tau1, tau2, sL, sR, n):
    rounds(n)
    G = [gen(i, 0) for i in range(n)]
    Hh = [gen(i, 1) for i in range(n)]
    u = gen_u()
    V = commit_value(v, gamma)
    aL = [(v >> i) & 1 for i in range(n)]
    aR = [ssub(aL[i], 1) for i in range(n)]
    A = (pow(H, alpha, P) * msm(aL, G) % P) * msm(aR, Hh) % P
    S = (pow(H, rho, P) * msm(sL, G) % P) * msm(sR, Hh) % P
    tr = _RTr(V, n)
    tr.absorb(A); tr.absorb(S)
    y = tr.challenge(); z = tr.challenge()
    yn = powers(y, n)
    twon = [(1 << i) % Q for i in range(n)]
    z2 = smul(z, z)
    l0 = [ssub(aL[i], z) for i in range(n)]
    r0 = [sadd(smul(yn[i], sadd(aR[i], z)), smul(z2, twon[i])) for i in range(n)]
    r1 = [smul(yn[i], sR[i]) for i in range(n)]
    t1 = sadd(inner(sL, r0), inner(l0, r1))
    t2 = inner(sL, r1)
    T1 = (pow(G_VAL, t1, P) * pow(H, tau1, P)) % P
    T2 = (pow(G_VAL, t2, P) * pow(H, tau2, P)) % P
    tr.absorb(T1); tr.absorb(T2)
    x = tr.challenge()
    l = [sadd(l0[i], smul(sL[i], x)) for i in range(n)]
    r = [sadd(r0[i], smul(r1[i], x)) for i in range(n)]
    that = inner(l, r)
    x2 = smul(x, x)
    taux = sadd(sadd(smul(tau2, x2), smul(tau1, x)), smul(z2, gamma))
    mu = sadd(alpha, smul(rho, x))
    yinv = sinv(y)
    yinvn = powers(yinv, n)
    hprime = [pow(Hh[i], yinvn[i], P) for i in range(n)]
    P_ipa = (msm(l, G) * msm(r, hprime) % P) * pow(u, that, P) % P
    ipa = vi.prove_gens(l, r, G, hprime, u, P_ipa)
    proof = b"".join(_b(e) for e in (A, S, T1, T2, taux, mu, that)) + ipa
    return V, proof


def verify(V, proof, n):
    rounds(n)
    if len(proof) != proof_len(n):
        return False
    G = [gen(i, 0) for i in range(n)]
    Hh = [gen(i, 1) for i in range(n)]
    u = gen_u()
    off = [0]

    def rd():
        e = int.from_bytes(proof[off[0]:off[0] + ELEM], "big"); off[0] += ELEM; return e
    A, S, T1, T2, taux, mu, that = (rd() for _ in range(7))
    ipa = proof[off[0]:]
    tr = _RTr(V, n)
    tr.absorb(A); tr.absorb(S)
    y = tr.challenge(); z = tr.challenge()
    tr.absorb(T1); tr.absorb(T2)
    x = tr.challenge()
    yn = powers(y, n)
    twon = [(1 << i) % Q for i in range(n)]
    z2 = smul(z, z); x2 = smul(x, x)
    # Check 1: g^that·h^taux == V^{z^2}·g^delta·T1^x·T2^{x^2}
    sum_y = sum(yn) % Q
    sum_2 = sum(twon) % Q
    delta = ssub(smul(ssub(z, z2), sum_y), smul(smul(z2, z), sum_2))
    lhs = (pow(G_VAL, that, P) * pow(H, taux, P)) % P
    rhs = msm([z2, delta, x, x2], [V, G_VAL, T1, T2])
    if lhs != rhs:
        return False
    # Check 2: P = A·S^x·(ΠG^{-z})·(Πh'^{z·y^i+z^2·2^i})·h^{-mu}, then IPA
    yinv = sinv(y)
    yinvn = powers(yinv, n)
    hprime = [pow(Hh[i], yinvn[i], P) for i in range(n)]
    negz = ssub(0, z); negmu = ssub(0, mu)
    scal = [1, x] + [negz] * n + [sadd(smul(z, yn[i]), smul(z2, twon[i])) for i in range(n)] + [negmu]
    pts = [A, S] + G + hprime + [H]
    Pp = msm(scal, pts)
    P_ipa = (Pp * pow(u, that, P)) % P
    return vi.verify_gens(P_ipa, ipa, G, hprime, u)


# ── §3.20 increment 6: the AGGREGATED range proof (m values, one proof) ───────
AGG_LABEL = b"DETERM-FF-BP-AGGRANGE-v1"
AGG_CDST = b"DETERM-FF-BP-AGGRANGE-v1-challenge"
MN_MAX = 256


def agg_rounds(m, n):
    if m < 1 or n < 1 or n > RANGE_MAX_BITS:
        raise ValueError("bad (m,n)")
    nm = m * n
    if nm < 1 or nm > MN_MAX:
        raise ValueError("m*n out of range")
    r, t = 0, nm
    while t > 1:
        if t & 1:
            raise ValueError("m*n not a power of two")
        t >>= 1
        r += 1
    return r


def agg_proof_len(m, n):
    return 7 * ELEM + (2 * agg_rounds(m, n) + 2) * ELEM


class _ATr:
    def __init__(self, Vs, m, n):
        self.buf = bytearray(AGG_LABEL)
        self.buf += int(m).to_bytes(4, "big") + int(n).to_bytes(4, "big")
        for V in Vs:
            self.buf += _b(V)

    def absorb(self, ptval):
        self.buf += _b(ptval)

    def challenge(self):
        c = vs.hash_to_scalar(bytes(self.buf), AGG_CDST)
        if c == 0:
            raise ValueError("zero challenge")
        self.buf += _b(c)
        return c


def agg_prove(v, gamma, alpha, rho, tau1, tau2, sL, sR, m, n):
    agg_rounds(m, n)
    nm = m * n
    G = [gen(i, 0) for i in range(nm)]
    Hh = [gen(i, 1) for i in range(nm)]
    u = gen_u()
    Vs = [commit_value(v[j], gamma[j]) for j in range(m)]
    aL, aR = [], []
    for j in range(m):
        for k in range(n):
            bit = (v[j] >> k) & 1
            aL.append(bit); aR.append(ssub(bit, 1))
    A = (pow(H, alpha, P) * msm(aL, G) % P) * msm(aR, Hh) % P
    S = (pow(H, rho, P) * msm(sL, G) % P) * msm(sR, Hh) % P
    tr = _ATr(Vs, m, n)
    tr.absorb(A); tr.absorb(S)
    y = tr.challenge(); z = tr.challenge()
    yn = powers(y, nm)
    twon = [(1 << k) % Q for k in range(n)]
    z2 = smul(z, z)
    zslot = [0] * nm
    zpow = z2
    for j in range(m):                                  # value j's 2^n slot scaled z^(2+j)
        for k in range(n):
            zslot[j * n + k] = smul(zpow, twon[k])
        zpow = smul(zpow, z)
    l0 = [ssub(aL[i], z) for i in range(nm)]
    r0 = [sadd(smul(yn[i], sadd(aR[i], z)), zslot[i]) for i in range(nm)]
    r1 = [smul(yn[i], sR[i]) for i in range(nm)]
    t1 = sadd(inner(sL, r0), inner(l0, r1))
    t2 = inner(sL, r1)
    T1 = (pow(G_VAL, t1, P) * pow(H, tau1, P)) % P
    T2 = (pow(G_VAL, t2, P) * pow(H, tau2, P)) % P
    tr.absorb(T1); tr.absorb(T2)
    x = tr.challenge()
    l = [sadd(l0[i], smul(sL[i], x)) for i in range(nm)]
    r = [sadd(r0[i], smul(r1[i], x)) for i in range(nm)]
    that = inner(l, r)
    x2 = smul(x, x)
    taux = sadd(smul(tau2, x2), smul(tau1, x))
    zpow = z2
    for j in range(m):                                  # + Σ_j z^(2+j)·gamma_j
        taux = sadd(taux, smul(zpow, gamma[j]))
        zpow = smul(zpow, z)
    mu = sadd(alpha, smul(rho, x))
    yinv = sinv(y)
    yinvn = powers(yinv, nm)
    hprime = [pow(Hh[i], yinvn[i], P) for i in range(nm)]
    P_ipa = (msm(l, G) * msm(r, hprime) % P) * pow(u, that, P) % P
    ipa = vi.prove_gens(l, r, G, hprime, u, P_ipa)
    proof = b"".join(_b(e) for e in (A, S, T1, T2, taux, mu, that)) + ipa
    return Vs, proof


def agg_verify(Vs, proof, m, n):
    agg_rounds(m, n)
    nm = m * n
    if len(proof) != agg_proof_len(m, n):
        return False
    G = [gen(i, 0) for i in range(nm)]
    Hh = [gen(i, 1) for i in range(nm)]
    u = gen_u()
    off = [0]

    def rd():
        e = int.from_bytes(proof[off[0]:off[0] + ELEM], "big"); off[0] += ELEM; return e
    A, S, T1, T2, taux, mu, that = (rd() for _ in range(7))
    ipa = proof[off[0]:]
    tr = _ATr(Vs, m, n)
    tr.absorb(A); tr.absorb(S)
    y = tr.challenge(); z = tr.challenge()
    tr.absorb(T1); tr.absorb(T2)
    x = tr.challenge()
    yn = powers(y, nm)
    twon = [(1 << k) % Q for k in range(n)]
    z2 = smul(z, z); x2 = smul(x, x)
    zslot = [0] * nm
    vscal = [0] * m
    zsum = 0
    zpow = z2
    for j in range(m):
        vscal[j] = zpow                                 # z^(2+j) for the V-side
        zsum = sadd(zsum, smul(zpow, z))                # Σ_j z^(3+j) for delta
        for k in range(n):
            zslot[j * n + k] = smul(zpow, twon[k])
        zpow = smul(zpow, z)
    sum_y = sum(yn) % Q
    sum_2 = sum(twon) % Q
    delta = ssub(smul(ssub(z, z2), sum_y), smul(zsum, sum_2))
    lhs = (pow(G_VAL, that, P) * pow(H, taux, P)) % P
    rhs = msm(vscal + [delta, x, x2], Vs + [G_VAL, T1, T2])
    if lhs != rhs:
        return False
    yinv = sinv(y)
    yinvn = powers(yinv, nm)
    hprime = [pow(Hh[i], yinvn[i], P) for i in range(nm)]
    negz = ssub(0, z); negmu = ssub(0, mu)
    scal = [1, x] + [negz] * nm + [sadd(smul(z, yn[i]), zslot[i]) for i in range(nm)] + [negmu]
    pts = [A, S] + G + hprime + [H]
    Pp = msm(scal, pts)
    P_ipa = (Pp * pow(u, that, P)) % P
    return vi.verify_gens(P_ipa, ipa, G, hprime, u)


def check_ff_aggrangeproof(vec, label):
    m, n = vec["m"], vec["n"]
    v = [int(x, 16) for x in vec["v_hex"]]
    gamma = [int(x, 16) for x in vec["gamma_hex"]]
    alpha, rho, tau1, tau2 = (int(vec[k], 16) for k in ("alpha_hex", "rho_hex", "tau1_hex", "tau2_hex"))
    sL = [int(s, 16) for s in vec["sL_hex"]]
    sR = [int(s, 16) for s in vec["sR_hex"]]
    Vs, proof = agg_prove(v, gamma, alpha, rho, tau1, tau2, sL, sR, m, n)
    if "".join(_b(V).hex() for V in Vs) != vec["v_commit_hex"]:
        return "recomputed V_j != v_commit_hex"
    if proof.hex() != vec["proof_hex"]:
        return "recomputed proof != proof_hex"
    if not agg_verify(Vs, proof, m, n):
        return "own aggregated proof failed to verify"
    return None


def _rand(seed, m):
    """Deterministic pseudo-random scalars in [1,q) (no RNG — reproducible corpus)."""
    return [int.from_bytes(hashlib.sha256(seed + bytes([i])).digest() * 12, "big") % Q or 1
            for i in range(m)]


# ── §3.13 file-half checker (imported by test_c99_vector_files.sh) ────────────
def check_ff_rangeproof(vec, label):
    n = vec["n"]
    v = int(vec["v_hex"], 16)
    gamma = int(vec["gamma_hex"], 16)
    alpha, rho, tau1, tau2 = (int(vec[k], 16) for k in ("alpha_hex", "rho_hex", "tau1_hex", "tau2_hex"))
    sL = [int(s, 16) for s in vec["sL_hex"]]
    sR = [int(s, 16) for s in vec["sR_hex"]]
    V, proof = prove(v, gamma, alpha, rho, tau1, tau2, sL, sR, n)
    if _b(V).hex() != vec["v_commit_hex"]:
        return "recomputed V != v_commit_hex"
    if proof.hex() != vec["proof_hex"]:
        return "recomputed proof != proof_hex"
    if not verify(V, proof, n):
        return "own proof failed to verify"
    return None


def _params(seed, v, n):
    gamma = _rand(seed + b"g", 1)[0]
    alpha, rho, tau1, tau2 = _rand(seed + b"a", 4)
    sL = _rand(seed + b"L", n)
    sR = _rand(seed + b"R", n)
    return gamma, alpha, rho, tau1, tau2, sL, sR


def _selftest():
    for n, v in ((2, 3), (4, 11), (8, 200)):
        gamma, alpha, rho, tau1, tau2, sL, sR = _params(b"st%d" % n, v, n)
        V, proof = prove(v, gamma, alpha, rho, tau1, tau2, sL, sR, n)
        assert len(proof) == proof_len(n), "proof length wrong n=%d" % n
        assert verify(V, proof, n), "valid range proof rejected n=%d" % n
        # out of range: v = 2^n exactly must fail to verify against its own commitment
        vbad = 1 << n
        Vb = commit_value(vbad, gamma)
        _, pbad = prove(vbad, gamma, alpha, rho, tau1, tau2, sL, sR, n)
        assert not verify(Vb, pbad, n), "verify accepted out-of-range v=2^n (n=%d)" % n
        # tamper: flip last byte of t_hat region -> reject
        bad = bytearray(proof); bad[6 * ELEM + ELEM - 1] ^= 1
        assert not verify(V, bytes(bad), n), "verify accepted tampered proof n=%d" % n
        # wrong commitment -> reject
        assert not verify((V * 2) % P, proof, n), "verify accepted wrong V n=%d" % n
    # ── aggregated ──
    for m, n in ((2, 2), (2, 4), (4, 2)):
        vv = [((3 << k) % (1 << n)) for k in range(m)]     # arbitrary in-range values
        gamma, alpha, rho, tau1, tau2, sL, sR = _agg_params(b"agg%d_%d" % (m, n), m, n)
        Vs, proof = agg_prove(vv, gamma, alpha, rho, tau1, tau2, sL, sR, m, n)
        assert len(proof) == agg_proof_len(m, n), "agg proof len wrong (m=%d,n=%d)" % (m, n)
        assert agg_verify(Vs, proof, m, n), "valid aggregated proof rejected (m=%d,n=%d)" % (m, n)
        # one value out of range in the batch -> reject
        vbad = list(vv); vbad[m - 1] = 1 << n
        Vb, pbad = agg_prove(vbad, gamma, alpha, rho, tau1, tau2, sL, sR, m, n)
        assert not agg_verify(Vb, pbad, m, n), "aggregated verify accepted an out-of-range value (m=%d,n=%d)" % (m, n)
        # tamper -> reject
        bad = bytearray(proof); bad[6 * ELEM + ELEM - 1] ^= 1
        assert not agg_verify(Vs, bytes(bad), m, n), "aggregated verify accepted tampered proof (m=%d,n=%d)" % (m, n)
        # m=1 reduces to the single-value proof (same V, same verify path)
    assert agg_proof_len(1, 4) == proof_len(4), "m=1 aggregated != single-value length"
    print("verify_ff_rangeproof selftest: single (n=2,4,8) + aggregated (m·n=4,8) prove/verify"
          " + out-of-range + tamper + wrong-V OK")


def _agg_params(seed, m, n):
    gamma = _rand(seed + b"g", m)
    alpha, rho, tau1, tau2 = _rand(seed + b"a", 4)
    sL = _rand(seed + b"L", m * n)
    sR = _rand(seed + b"R", m * n)
    return gamma, alpha, rho, tau1, tau2, sL, sR


def emit():
    vectors = []
    for n, v in ((2, 3), (4, 11)):
        gamma, alpha, rho, tau1, tau2, sL, sR = _params(b"corpus%d" % n, v, n)
        V, proof = prove(v, gamma, alpha, rho, tau1, tau2, sL, sR, n)
        vectors.append({
            "name": "rangeproof n=%d v=%d" % (n, v), "type": "rangeproof", "n": n,
            "v_hex": vp._s(v), "gamma_hex": vp._s(gamma),
            "alpha_hex": vp._s(alpha), "rho_hex": vp._s(rho),
            "tau1_hex": vp._s(tau1), "tau2_hex": vp._s(tau2),
            "sL_hex": [vp._s(s) for s in sL], "sR_hex": [vp._s(s) for s in sR],
            "v_commit_hex": _b(V).hex(), "proof_hex": proof.hex()})
    doc = {"primitive": "ff_rangeproof",
           "source": ("Generated by tools/verify_ff_rangeproof.py (Determ CRYPTO-C99-SPEC §3.20 inc.5); "
                      "single-value Bulletproofs range proof over the RFC 3526 MODP-3072 subgroup, "
                      "from-scratch Python bignum reference."),
           "note": ("Range proof v in [0,2^n): V=g^v·h^gamma; A/S bit-vector commits; t-poly T1/T2; "
                    "IPA over (G_i,h'_i=y^-i·H_i,u). Transcript DETERM-FF-BP-RANGE-v1. Prover randomness "
                    "supplied for reproducibility. Elements/scalars 384-byte big-endian. n small (3072-bit "
                    "modexp ~1700x slower than P-256); n up to 64 supported."),
           "vectors": vectors}
    out = os.path.join(os.path.dirname(__file__), "vectors", "ff_rangeproof.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=2); f.write("\n")
    print("wrote %s (%d vectors)" % (out, len(vectors)))


def emit_agg():
    vectors = []
    for m, n in ((2, 2), (2, 4)):                       # m·n = 4, 8 (small — heavy modexp)
        vv = [((3 << k) % (1 << n)) for k in range(m)]
        gamma, alpha, rho, tau1, tau2, sL, sR = _agg_params(b"corpusagg%d_%d" % (m, n), m, n)
        Vs, proof = agg_prove(vv, gamma, alpha, rho, tau1, tau2, sL, sR, m, n)
        vectors.append({
            "name": "aggrangeproof m=%d n=%d" % (m, n), "type": "aggrangeproof", "m": m, "n": n,
            "v_hex": [vp._s(x) for x in vv], "gamma_hex": [vp._s(x) for x in gamma],
            "alpha_hex": vp._s(alpha), "rho_hex": vp._s(rho),
            "tau1_hex": vp._s(tau1), "tau2_hex": vp._s(tau2),
            "sL_hex": [vp._s(s) for s in sL], "sR_hex": [vp._s(s) for s in sR],
            "v_commit_hex": "".join(_b(V).hex() for V in Vs), "proof_hex": proof.hex()})
    doc = {"primitive": "ff_aggrangeproof",
           "source": ("Generated by tools/verify_ff_rangeproof.py emit-agg (Determ CRYPTO-C99-SPEC "
                      "§3.20 inc.6); AGGREGATED Bulletproofs range proof (m values, one proof) over "
                      "the RFC 3526 MODP-3072 subgroup, from-scratch Python bignum reference."),
           "note": ("Aggregated range proof: every v_j in [0,2^n) in ONE proof of size "
                    "2·log2(m·n)+O(1). Value j's 2^n slot scaled z^(2+j); delta gains Σ_j z^(3+j); "
                    "m=1 recovers the single-value proof. Transcript DETERM-FF-BP-AGGRANGE-v1. "
                    "v_commit_hex is the m concatenated 384-byte V_j. Elements/scalars 384-byte "
                    "big-endian. m·n small (3072-bit modexp ~1700x slower than P-256); m·n up to 256."),
           "vectors": vectors}
    out = os.path.join(os.path.dirname(__file__), "vectors", "ff_aggrangeproof.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=2); f.write("\n")
    print("wrote %s (%d vectors)" % (out, len(vectors)))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "emit":
        emit()
    elif len(sys.argv) > 1 and sys.argv[1] == "emit-agg":
        emit_agg()
    else:
        _selftest()
