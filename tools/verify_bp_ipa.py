#!/usr/bin/env python3
# Independent Python reference for the Determ Bulletproofs inner-product argument
# (IPA) over NIST P-256 — CRYPTO-C99-SPEC.md §3.19 increment 4. This is the
# from-scratch oracle the C port is checked against (byte-for-byte proof bytes),
# and the design reference the C is ported FROM (python-prove-first discipline).
#
# The IPA (Bulletproofs §3, non-interactive via Fiat-Shamir) proves knowledge of
# vectors a, b with
#       P = <a, g> + <b, h> + <a,b>*u
# for public generator vectors g, h, a point u, and a commitment P — with a proof
# of size 2*log2(n) points + 2 scalars instead of the trivial 2n.
#
# Reuses the P-256 EC + RFC 9380 hash-to-curve from verify_pedersen.py.
import verify_pedersen as vp

N = vp.N
G = vp.G

LABEL = b"DETERM-BP-IPA-v1"
CHAL_DST = b"DETERM-BP-IPA-v1-challenge"
# u (the inner-product generator) — a nothing-up-my-sleeve point independent of
# the g_i/h_i families: the RO image of a distinct index in the G family.
U_INDEX = 0xFFFFFFFF


def hash_to_scalar(msg, dst):
    # RFC 9380 hash_to_field with the group order n as modulus (m=1, L=48).
    return int.from_bytes(vp.expand_xmd(msg, dst, 48), "big") % N


def pt_mul(k, pt):
    return vp.pt_mul(k % N, pt)


def pt_add(a, b):
    return vp.pt_add(a, b)


def inner(a, b):
    return sum((ai * bi) % N for ai, bi in zip(a, b)) % N


def msm(scalars, points):
    acc = None
    for s, pt in zip(scalars, points):
        s %= N
        if s == 0:
            continue
        acc = pt_add(acc, pt_mul(s, pt))
    return acc


def setup(n):
    """Public parameters: g[n], h[n], u. Deterministic nothing-up-my-sleeve."""
    g = [vp.derive_gen(i, 0) for i in range(n)]
    h = [vp.derive_gen(i, 1) for i in range(n)]
    u = vp.derive_gen(U_INDEX, 0)
    return g, h, u


class Transcript:
    """Deterministic Fiat-Shamir transcript: an append-only byte buffer seeded
    with the statement (P, u, n); each challenge hashes the whole buffer and is
    re-absorbed so subsequent challenges depend on it."""

    def __init__(self, P, u, n):
        self.t = bytearray(LABEL)
        self.t += vp.compress(P)
        self.t += vp.compress(u)
        self.t += n.to_bytes(4, "big")

    def absorb(self, pt):
        self.t += vp.compress(pt)

    def challenge(self):
        x = hash_to_scalar(bytes(self.t), CHAL_DST)
        if x == 0:                       # negligible; a zero challenge is unusable
            raise ValueError("zero challenge")
        self.t += x.to_bytes(32, "big")
        return x


def commit_P(a, b, g, h, u):
    """P = <a, g> + <b, h> + <a,b>*u (the statement the prover knows an opening of)."""
    return msm(list(a) + list(b) + [inner(a, b)], list(g) + list(h) + [u])


def prove(a, b, g, h, u, P, n):
    """Returns (L_list, R_list, a_final, b_final). n must be a power of two."""
    tr = Transcript(P, u, n)
    a, b, g, h = list(a), list(b), list(g), list(h)
    Ls, Rs = [], []
    while n > 1:
        m = n // 2
        aL, aR = a[:m], a[m:]
        bL, bR = b[:m], b[m:]
        gL, gR = g[:m], g[m:]
        hL, hR = h[:m], h[m:]
        cL = inner(aL, bR)
        cR = inner(aR, bL)
        L = msm(aL + bR + [cL], gR + hL + [u])       # <aL,gR> + <bR,hL> + cL*u
        R = msm(aR + bL + [cR], gL + hR + [u])       # <aR,gL> + <bL,hR> + cR*u
        tr.absorb(L)
        tr.absorb(R)
        x = tr.challenge()
        xinv = pow(x, N - 2, N)
        a = [(aL[i] * x + aR[i] * xinv) % N for i in range(m)]
        b = [(bL[i] * xinv + bR[i] * x) % N for i in range(m)]
        g = [pt_add(pt_mul(xinv, gL[i]), pt_mul(x, gR[i])) for i in range(m)]
        h = [pt_add(pt_mul(x, hL[i]), pt_mul(xinv, hR[i])) for i in range(m)]
        Ls.append(L)
        Rs.append(R)
        n = m
    return Ls, Rs, a[0], b[0]


def verify(P, g, h, u, proof, n):
    Ls, Rs, a, b = proof
    tr = Transcript(P, u, n)
    g, h, Pp = list(g), list(h), P
    j = 0
    while n > 1:
        m = n // 2
        tr.absorb(Ls[j])
        tr.absorb(Rs[j])
        x = tr.challenge()
        xinv = pow(x, N - 2, N)
        x2 = (x * x) % N
        x2inv = (xinv * xinv) % N
        gL, gR = g[:m], g[m:]
        hL, hR = h[:m], h[m:]
        g = [pt_add(pt_mul(xinv, gL[i]), pt_mul(x, gR[i])) for i in range(m)]
        h = [pt_add(pt_mul(x, hL[i]), pt_mul(xinv, hR[i])) for i in range(m)]
        Pp = pt_add(pt_add(pt_mul(x2, Ls[j]), Pp), pt_mul(x2inv, Rs[j]))
        j += 1
        n = m
    rhs = pt_add(pt_add(pt_mul(a, g[0]), pt_mul(b, h[0])), pt_mul((a * b) % N, u))
    return Pp == rhs


def proof_to_hex(proof):
    Ls, Rs, a, b = proof
    return {
        "L_hex": [vp.compress(p).hex() for p in Ls],
        "R_hex": [vp.compress(p).hex() for p in Rs],
        "a_hex": "%064x" % a,
        "b_hex": "%064x" % b,
    }


# ---- deterministic test vector inputs (fixed, reproducible) ----
def _demo_ab(n):
    a = [((7 * i + 3) % N) for i in range(n)]
    b = [((5 * i + 11) % N) for i in range(n)]
    return a, b


def check_ipa(vec, label):
    """§3.13 file-half checker (imported by test_c99_vector_files.sh)."""
    n = int(vec["n"])
    a = [int(x, 16) for x in vec["av_hex"]]
    b = [int(x, 16) for x in vec["bv_hex"]]
    g, h, u = setup(n)
    P = commit_P(a, b, g, h, u)
    got = proof_to_hex(prove(a, b, g, h, u, P, n))
    if got["a_hex"] != vec["a_hex"] or got["b_hex"] != vec["b_hex"]:
        return "recomputed final (a,b) != vector"
    if got["L_hex"] != vec["L_hex"] or got["R_hex"] != vec["R_hex"]:
        return "recomputed L/R proof points != vector"
    # also confirm P and verify, so the corpus is a live round-trip not just bytes
    if vp.compress(P).hex() != vec["P_hex"]:
        return "recomputed commitment P != P_hex"
    if not verify(P, g, h, u, prove(a, b, g, h, u, P, n), n):
        return "round-trip verify failed (runner bug)"
    return None


def _check_invariant(a, b, g, h, u, P, n):
    """Decisive algebraic oracle: at EVERY fold the invariant
    P_running = <a,g> + <b,h> + <a,b>*u must hold, where P_running is the
    original P updated by x^2*L + x^-2*R each round. Independent of verify()."""
    tr = Transcript(P, u, n)
    a, b, g, h, Pr = list(a), list(b), list(g), list(h), P
    while n > 1:
        assert vp.compress(commit_P(a, b, g, h, u)) == vp.compress(Pr), \
            "invariant broke at n=%d" % n
        m = n // 2
        aL, aR, bL, bR = a[:m], a[m:], b[:m], b[m:]
        gL, gR, hL, hR = g[:m], g[m:], h[:m], h[m:]
        L = msm(aL + bR + [inner(aL, bR)], gR + hL + [u])
        R = msm(aR + bL + [inner(aR, bL)], gL + hR + [u])
        tr.absorb(L); tr.absorb(R)
        x = tr.challenge(); xinv = pow(x, N - 2, N)
        a = [(aL[i] * x + aR[i] * xinv) % N for i in range(m)]
        b = [(bL[i] * xinv + bR[i] * x) % N for i in range(m)]
        g = [pt_add(pt_mul(xinv, gL[i]), pt_mul(x, gR[i])) for i in range(m)]
        h = [pt_add(pt_mul(x, hL[i]), pt_mul(xinv, hR[i])) for i in range(m)]
        Pr = pt_add(pt_add(pt_mul((x * x) % N, L), Pr), pt_mul((xinv * xinv) % N, R))
        n = m
    assert vp.compress(commit_P(a, b, g, h, u)) == vp.compress(Pr), "final invariant broke"


def _selftest():
    for n in (1, 2, 4, 8, 16):
        a, b = _demo_ab(n)
        g, h, u = setup(n)
        P = commit_P(a, b, g, h, u)
        _check_invariant(a, b, g, h, u, P, n)
        pf = prove(a, b, g, h, u, P, n)
        assert verify(P, g, h, u, pf, n), "round-trip failed n=%d" % n
        # soundness: a wrong commitment must not verify
        Pbad = pt_add(P, u)
        assert not verify(Pbad, g, h, u, pf, n), "accepted a wrong P n=%d" % n
        # tamper: flip the final a
        Ls, Rs, fa, fb = pf
        assert not verify(P, g, h, u, (Ls, Rs, (fa + 1) % N, fb), n), "accepted tampered a n=%d" % n
        # tamper a proof point (n>1 has L/R)
        if n > 1:
            assert not verify(P, g, h, u, (([pt_add(Ls[0], u)] + Ls[1:]), Rs, fa, fb), n), \
                "accepted tampered L n=%d" % n
    print("verify_bp_ipa selftest: round-trip + soundness + tamper OK for n in {1,2,4,8,16}")


def emit():
    import json, os
    vectors = []
    for n in (4, 8):
        a, b = _demo_ab(n)
        g, h, u = setup(n)
        P = commit_P(a, b, g, h, u)
        pf = prove(a, b, g, h, u, P, n)
        assert verify(P, g, h, u, pf, n)
        d = {"name": "ipa n=%d round-trip" % n, "type": "ipa", "n": n,
             "av_hex": ["%064x" % v for v in a], "bv_hex": ["%064x" % v for v in b],
             "P_hex": vp.compress(P).hex()}
        d.update(proof_to_hex(pf))
        vectors.append(d)
    doc = {
        "primitive": "bp_ipa",
        "source": ("Generated by tools/verify_bp_ipa.py (Determ CRYPTO-C99-SPEC "
                   "§3.19 inc.4); the Bulletproofs inner-product argument over "
                   "NIST P-256, deterministic Fiat-Shamir transcript, proof bytes "
                   "recomputed from scratch (own P-256 EC + RFC 9380 h2c)."),
        "note": ("IPA over P-256: P = <a,g> + <b,h> + <a,b>*u; proof = L[log n] ‖ "
                 "R[log n] ‖ a_final ‖ b_final. Generators g_i/h_i = gen(i,0/1), "
                 "u = gen(0xFFFFFFFF, 0). Vectors a_i=7i+3, b_i=5i+11."),
        "vectors": vectors,
    }
    out = os.path.join(os.path.dirname(__file__), "vectors", "bp_ipa.json")
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
