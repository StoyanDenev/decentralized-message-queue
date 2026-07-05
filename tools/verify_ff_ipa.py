#!/usr/bin/env python3
# Independent Python reference for the Determ FINITE-FIELD Bulletproofs INNER-PRODUCT
# ARGUMENT (IPA) over Z_p* — CRYPTO-C99-SPEC.md §3.20 increment 4 (the MODERN-profile
# mirror of the §3.19 P-256 IPA, src/crypto/pedersen/ipa.c). Proves knowledge of vectors
# a, b with the commitment
#
#     P = Π g_i^{a_i} · Π h_i^{b_i} · u^{<a,b>}   (mod p, in the order-q subgroup G_q)
#
# in 2·log2(n) group elements + 2 scalars, via a deterministic Fiat-Shamir transcript.
# Group = RFC 3526 MODP-3072 subgroup (elements mod p); scalar/exponent field mod q.
#
# This is the from-scratch oracle the C port (src/crypto/ff/ffipa.c) is checked against
# byte-for-byte (tools/vectors/ff_ipa.json, §3.13 dual-oracle). Reuses the inc.1
# generators (derive_gen) and inc.3 scalar field (verify_ff_scalar); Python native
# bignums are the reference arithmetic.
#
#   * emit()          -> (re)generate tools/vectors/ff_ipa.json.
#   * check_ff_ipa    -> §3.13 file-half checker (imported by test_c99_vector_files.sh).
import hashlib, json, os
import verify_ff_pedersen as vp
import verify_ff_scalar as vs

P, Q, ELEM = vp.P, vp.Q, vp.ELEM
U_INDEX = 0xFFFFFFFF                       # nothing-up-my-sleeve inner-product generator u
IPA_MAX_N = 256

TR_LABEL = b"DETERM-FF-BP-IPA-v1"
TR_CDST = b"DETERM-FF-BP-IPA-v1-challenge"


def _to_bytes(x):
    return x.to_bytes(ELEM, "big")


def gen(i, which):
    return vp.derive_gen(i, which)


def gen_u():
    return vp.derive_gen(U_INDEX, 0)


def sinv(a):
    return pow(a, Q - 2, Q)


def inner(a, b):
    return sum((a[i] * b[i]) % Q for i in range(len(a))) % Q


def msm(scalars, points):
    """Π points_i^{scalars_i} mod p."""
    acc = 1
    for s, pt in zip(scalars, points):
        acc = (acc * pow(pt, s, P)) % P
    return acc


def rounds_for(n):
    if n < 1 or n > IPA_MAX_N:
        raise ValueError("n out of range")
    r, m = 0, n
    while m > 1:
        if m & 1:
            raise ValueError("n not a power of two")
        m >>= 1
        r += 1
    return r


class _Tr:
    """Deterministic transcript, byte-identical to the C ipa transcript buffer."""
    def __init__(self, Pval, uval, n):
        self.buf = bytearray()
        self.buf += TR_LABEL
        self.buf += _to_bytes(Pval)
        self.buf += _to_bytes(uval)
        self.buf += int(n).to_bytes(4, "big")

    def absorb(self, ptval):
        self.buf += _to_bytes(ptval)

    def challenge(self):
        x = vs.hash_to_scalar(bytes(self.buf), TR_CDST)   # 13 SHA-256 blocks -> mod q
        if x == 0:
            raise ValueError("zero challenge")
        self.buf += _to_bytes(x)
        return x


def commit(a, b):
    """P = Π g_i^{a_i} · Π h_i^{b_i} · u^{<a,b>} mod p."""
    n = len(a)
    rounds_for(n)
    g = [gen(i, 0) for i in range(n)]
    h = [gen(i, 1) for i in range(n)]
    u = gen_u()
    acc = msm(a, g)
    acc = (acc * msm(b, h)) % P
    acc = (acc * pow(u, inner(a, b), P)) % P
    return acc


def prove_gens(a, b, g, h, u, Pval):
    n = len(a)
    rounds_for(n)
    a, b, g, h = a[:], b[:], g[:], h[:]
    tr = _Tr(Pval, u, n)
    Ls, Rs = [], []
    cur = n
    while cur > 1:
        m = cur // 2
        aL, aR = a[:m], a[m:cur]
        bL, bR = b[:m], b[m:cur]
        gL, gR = g[:m], g[m:cur]
        hL, hR = h[:m], h[m:cur]
        cL = inner(aL, bR)
        cR = inner(aR, bL)
        L = (msm(aL, gR) * msm(bR, hL) % P) * pow(u, cL, P) % P
        R = (msm(aR, gL) * msm(bL, hR) % P) * pow(u, cR, P) % P
        tr.absorb(L); tr.absorb(R)
        x = tr.challenge(); xi = sinv(x)
        a = [((aL[i] * x) % Q + (aR[i] * xi) % Q) % Q for i in range(m)]   # a' = aL·x + aR·x^-1
        b = [((bL[i] * xi) % Q + (bR[i] * x) % Q) % Q for i in range(m)]   # b' = bL·x^-1 + bR·x
        g = [(pow(gL[i], xi, P) * pow(gR[i], x, P)) % P for i in range(m)] # g' = gL^x^-1 · gR^x
        h = [(pow(hL[i], x, P) * pow(hR[i], xi, P)) % P for i in range(m)] # h' = hL^x · hR^x^-1
        Ls.append(L); Rs.append(R)
        cur = m
    return (b"".join(_to_bytes(L) for L in Ls) + b"".join(_to_bytes(R) for R in Rs)
            + _to_bytes(a[0]) + _to_bytes(b[0]))


def verify_gens(Pval, proof, g, h, u):
    n = len(g)
    rounds = rounds_for(n)
    if len(proof) != (2 * rounds + 2) * ELEM:
        return False
    g, h = g[:], h[:]
    off = 0
    Ls = [int.from_bytes(proof[off + i * ELEM: off + (i + 1) * ELEM], "big") for i in range(rounds)]; off += rounds * ELEM
    Rs = [int.from_bytes(proof[off + i * ELEM: off + (i + 1) * ELEM], "big") for i in range(rounds)]; off += rounds * ELEM
    af = int.from_bytes(proof[off:off + ELEM], "big"); off += ELEM
    bf = int.from_bytes(proof[off:off + ELEM], "big")
    tr = _Tr(Pval, u, n)
    Pp = Pval
    cur = n
    for rd in range(rounds):
        L, R = Ls[rd], Rs[rd]
        tr.absorb(L); tr.absorb(R)
        x = tr.challenge(); xi = sinv(x)
        x2 = (x * x) % Q
        x2i = (xi * xi) % Q
        m = cur // 2
        gL, gR = g[:m], g[m:cur]
        hL, hR = h[:m], h[m:cur]
        g = [(pow(gL[i], xi, P) * pow(gR[i], x, P)) % P for i in range(m)]
        h = [(pow(hL[i], x, P) * pow(hR[i], xi, P)) % P for i in range(m)]
        Pp = (pow(L, x2, P) * Pp % P) * pow(R, x2i, P) % P        # P' = L^{x^2}·P·R^{x^-2}
        cur = m
    rhs = (pow(g[0], af, P) * pow(h[0], bf, P) % P) * pow(u, (af * bf) % Q, P) % P
    return Pp == rhs


def prove(a, b, Pval):
    n = len(a)
    g = [gen(i, 0) for i in range(n)]
    h = [gen(i, 1) for i in range(n)]
    return prove_gens(a, b, g, h, gen_u(), Pval)


def verify(Pval, proof, n):
    g = [gen(i, 0) for i in range(n)]
    h = [gen(i, 1) for i in range(n)]
    return verify_gens(Pval, proof, g, h, gen_u())


def _vec(seed, n):
    """Deterministic pseudo-random a,b in [0,q) from a seed (no RNG — reproducible corpus)."""
    a, b = [], []
    for i in range(n):
        a.append(int.from_bytes(hashlib.sha256(b"a" + seed + bytes([i])).digest() * 12, "big") % Q)
        b.append(int.from_bytes(hashlib.sha256(b"b" + seed + bytes([i])).digest() * 12, "big") % Q)
    return a, b


# ── §3.13 file-half checker (imported by test_c99_vector_files.sh) ────────────
def check_ff_ipa(vec, label):
    t = vec.get("type")
    n = vec["n"]
    a = [int(x, 16) for x in vec["a_hex"]]
    b = [int(x, 16) for x in vec["b_hex"]]
    if t == "ipa_commit":
        if _to_bytes(commit(a, b)).hex() != vec["p_hex"]:
            return "recomputed commit != p_hex"
    elif t == "ipa_prove":
        Pval = int(vec["p_hex"], 16)
        proof = prove(a, b, Pval)
        if proof.hex() != vec["proof_hex"]:
            return "recomputed proof != proof_hex"
        if not verify(Pval, proof, n):
            return "own proof failed to verify"
    else:
        return "unknown ff_ipa vector type %r" % t
    return None


def _selftest():
    for n in (1, 2, 4, 8):
        a, b = _vec(b"st%d" % n, n)
        Pval = commit(a, b)
        proof = prove(a, b, Pval)
        assert len(proof) == (2 * rounds_for(n) + 2) * ELEM, "proof length wrong n=%d" % n
        assert verify(Pval, proof, n), "valid proof rejected n=%d" % n
        # soundness: a wrong commitment must reject
        assert not verify((Pval * 2) % P, proof, n), "verify accepted wrong P n=%d" % n
        # tamper: flip the last byte of the final scalar -> reject
        bad = bytearray(proof); bad[-1] ^= 1
        assert not verify(Pval, bytes(bad), n), "verify accepted tampered proof n=%d" % n
    print("verify_ff_ipa selftest: commit/prove/verify round-trip + soundness (n=1,2,4,8) OK")


def emit():
    vectors = []
    # n in {2,4} only: the C-side recompute (test-c99-vectors) does full 3072-bit
    # modexp, ~1700x slower than P-256; n=4 already exercises multi-round folding. The
    # Python file-half (native bignums) is fast regardless. n up to 256 stays supported.
    for n in (2, 4):
        a, b = _vec(b"corpus%d" % n, n)
        Pval = commit(a, b)
        vectors.append({"name": "ipa_commit n=%d" % n, "type": "ipa_commit", "n": n,
                        "a_hex": [vp._s(x) for x in a], "b_hex": [vp._s(x) for x in b],
                        "p_hex": _to_bytes(Pval).hex()})
        vectors.append({"name": "ipa_prove n=%d" % n, "type": "ipa_prove", "n": n,
                        "a_hex": [vp._s(x) for x in a], "b_hex": [vp._s(x) for x in b],
                        "p_hex": _to_bytes(Pval).hex(), "proof_hex": prove(a, b, Pval).hex()})
    doc = {"primitive": "ff_ipa",
           "source": ("Generated by tools/verify_ff_ipa.py (Determ CRYPTO-C99-SPEC §3.20 inc.4); "
                      "Bulletproofs inner-product argument over the RFC 3526 MODP-3072 subgroup, "
                      "from-scratch Python bignum reference."),
           "note": ("IPA over Z_p*: P = Π g_i^{a_i}·Π h_i^{b_i}·u^{<a,b>} mod p, proof = "
                    "2·log2(n) elements + 2 scalars, deterministic Fiat-Shamir (transcript "
                    "label DETERM-FF-BP-IPA-v1). Elements/scalars 384-byte big-endian."),
           "vectors": vectors}
    out = os.path.join(os.path.dirname(__file__), "vectors", "ff_ipa.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=2); f.write("\n")
    print("wrote %s (%d vectors)" % (out, len(vectors)))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "emit":
        emit()
    else:
        _selftest()
