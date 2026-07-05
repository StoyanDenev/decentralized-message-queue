#!/usr/bin/env python3
# Independent Python reference for the Determ FINITE-FIELD Pedersen commitment —
# CRYPTO-C99-SPEC.md §3.20 increment 1 (the MODERN-profile / large-prime sibling of
# the §3.19 P-256 range-proof stack). Commitments live in the prime-order subgroup
# G_q of Z_p* where p is the RFC 3526 MODP-3072 safe prime (order q=(p-1)/2, prime).
#
# This is the from-scratch oracle the C port (src/crypto/ff/ffgroup.c) is checked
# against byte-for-byte, and the source of the generated group constants
# (src/crypto/ff/ff_params.h). Python's native bignums are the reference arithmetic.
#
#   * emit_params()      -> (re)generate src/crypto/ff/ff_params.h (p, q, R2, n', h).
#   * emit()             -> (re)generate tools/vectors/ff_pedersen.json.
#   * check_ff_pedersen  -> §3.13 file-half checker.
import hashlib, json, os

# ── the RFC 3526 MODP-3072 safe prime, reproduced from its published formula ──
def _pi_scaled(bits):
    g = 128; prec = bits + g; one = 1 << prec
    def at(x):
        total = one // x; term = one // x; x2 = x * x; n = 1; sign = -1
        while True:
            term //= x2; t = term // (2 * n + 1)
            if t == 0: break
            total += sign * t; sign = -sign; n += 1
        return total
    return (4 * (4 * at(5) - at(239))) >> g

P = 2**3072 - 2**3008 - 1 + 2**64 * (_pi_scaled(2942) + 1690314)
Q = (P - 1) // 2                       # prime subgroup order (p is a safe prime)
G = 4                                  # 2^2: a quadratic residue => generator of G_q
LIMBS = 96                             # 3072 bits / 32
ELEM = 384                             # bytes

H_DST = b"DETERM-FF-PEDERSEN-MODP3072-H-v1"


def _miller_rabin(n):
    small = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71]
    for p in small:
        if n % p == 0: return n == p
    d = n - 1; r = 0
    while d % 2 == 0: d //= 2; r += 1
    for a in small:
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        if not any((x := x * x % n) == n - 1 for _ in range(r - 1)):
            return False
    return True


def derive_h():
    """Nothing-up-my-sleeve second generator h with unknown log_G(h): hash the DST
    to > 3072 bits, reduce mod p, then SQUARE (mapping into the order-q QR subgroup)."""
    material = b"".join(hashlib.sha256(H_DST + bytes([i])).digest() for i in range(13))  # 416 B
    hs = int.from_bytes(material, "big") % P
    h = pow(hs, 2, P)                  # a QR => order exactly q (for hs != 0,1,p-1)
    assert h not in (0, 1) and h != G, "degenerate h"
    return h


H = derive_h()

# ── §3.20 increment 2: vector-commitment generator families G_i, H_i ──────────
# Two independent nothing-up-my-sleeve generator FAMILIES, each derived by hashing
# a family-specific DST || 4-byte big-endian index onto the group (same shape as
# derive_h: 13 SHA-256 counter blocks -> reduce mod p -> SQUARE into the order-q QR
# subgroup). Distinct DSTs so G_i, H_i, and the §3.20 scalar h have no known dlog
# relation to each other. These match the C determ_ff_gen byte-for-byte.
VG_DST = b"DETERM-FF-PEDERSEN-VEC-G-MODP3072-v1"
VH_DST = b"DETERM-FF-PEDERSEN-VEC-H-MODP3072-v1"


def derive_gen(index, which):
    dst = VG_DST if which == 0 else VH_DST if which == 1 else None
    if dst is None: raise ValueError("which must be 0 (G) or 1 (H)")
    prefix = dst + int(index).to_bytes(4, "big")
    material = b"".join(hashlib.sha256(prefix + bytes([i])).digest() for i in range(13))  # 416 B
    hs = int.from_bytes(material, "big") % P
    g = pow(hs, 2, P)                  # a QR => order exactly q
    if g in (0, 1): raise ValueError("degenerate generator")
    return g


def _to_bytes(x):
    return x.to_bytes(ELEM, "big")


def commit_int(v, r):
    if not (0 <= v < Q): raise ValueError("v must satisfy 0 <= v < q")
    if not (0 < r < Q):  raise ValueError("r must satisfy 0 < r < q")
    return (pow(G, v, P) * pow(H, r, P)) % P


def commit_hex(v_hex, r_hex):
    return _to_bytes(commit_int(int(v_hex, 16), int(r_hex, 16))).hex()


def vector_commit_int(a, b, r):
    """C = h^r * Π G_i^{a_i} * Π H_i^{b_i} mod p (the Bulletproofs A/S-commit shape).
    a, b are equal-length exponent lists in [0,q) (0 allowed, skipped); r in (0,q)."""
    if len(a) != len(b): raise ValueError("a, b length mismatch")
    if not (0 < r < Q):  raise ValueError("r must satisfy 0 < r < q")
    acc = pow(H, r, P)
    for i in range(len(a)):
        if not (0 <= a[i] < Q): raise ValueError("a_i must satisfy 0 <= a_i < q")
        if not (0 <= b[i] < Q): raise ValueError("b_i must satisfy 0 <= b_i < q")
        if a[i]: acc = (acc * pow(derive_gen(i, 0), a[i], P)) % P
        if b[i]: acc = (acc * pow(derive_gen(i, 1), b[i], P)) % P
    return acc


def msm_int(scalars, points):
    """General multi-exponentiation acc = Π points_i^{scalars_i} mod p. scalars in
    [0,q) (0 allowed, skipped BEFORE the point is validated — matches the C skip);
    points are group elements in (0,p). The empty/all-zero product is the identity 1."""
    if len(scalars) != len(points): raise ValueError("scalars, points length mismatch")
    acc = 1
    for s, pt in zip(scalars, points):
        if not (0 <= s < Q): raise ValueError("scalar must satisfy 0 <= s < q")
        if s == 0: continue
        if not (0 < pt < P): raise ValueError("point must satisfy 0 < P < p")
        acc = (acc * pow(pt, s, P)) % P
    return acc


# ── §3.13 file-half checker (imported by test_c99_vector_files.sh) ────────────
def check_ff_pedersen(vec, label):
    t = vec.get("type")
    if t == "h_generator":
        got = _to_bytes(H).hex()
        if got != vec["h_hex"]:
            return "recomputed H != h_hex"
    elif t == "commit":
        got = commit_hex(vec["v_hex"], vec["r_hex"])
        if got != vec["c_hex"]:
            return "recomputed commit != c_hex"
    elif t == "homomorphism":
        # commit(v1,r1) * commit(v2,r2) mod p == commit((v1+v2)%q, (r1+r2)%q)
        c1 = commit_int(int(vec["v1_hex"], 16), int(vec["r1_hex"], 16))
        c2 = commit_int(int(vec["v2_hex"], 16), int(vec["r2_hex"], 16))
        got = _to_bytes((c1 * c2) % P).hex()
        if got != vec["c3_hex"]:
            return "recomputed C1*C2 != c3_hex"
    elif t == "ff_gen":
        got = _to_bytes(derive_gen(vec["index"], vec["which"])).hex()
        if got != vec["g_hex"]:
            return "recomputed gen(index=%d,which=%d) != g_hex" % (vec["index"], vec["which"])
    elif t == "ff_vector_commit":
        a = [int(x, 16) for x in vec["a_hex"]]
        b = [int(x, 16) for x in vec["b_hex"]]
        got = _to_bytes(vector_commit_int(a, b, int(vec["r_hex"], 16))).hex()
        if got != vec["c_hex"]:
            return "recomputed vector_commit != c_hex"
    elif t == "ff_msm":
        scalars = [int(x, 16) for x in vec["scalars_hex"]]
        points = [int(x, 16) for x in vec["points_hex"]]
        got = _to_bytes(msm_int(scalars, points)).hex()
        if got != vec["m_hex"]:
            return "recomputed msm != m_hex"
    else:
        return "unknown ff_pedersen vector type %r" % t
    return None


def _s(x):
    return "%0768x" % x


def _selftest():
    assert P.bit_length() == 3072 and P % 4 == 3
    assert _miller_rabin(P) and _miller_rabin(Q), "not a safe prime"
    assert pow(H, Q, P) == 1, "h not in the order-q subgroup"
    assert pow(G, Q, P) == 1 and G != 1, "g not a subgroup generator"
    # binding sanity: distinct (v,r) give distinct commitments; homomorphism holds
    c1 = commit_int(9, 0x1234)
    c2 = commit_int(9, 0x1235)
    assert c1 != c2
    v1, r1, v2, r2 = 5, 7, 11, 13
    assert (commit_int(v1, r1) * commit_int(v2, r2)) % P == commit_int(v1 + v2, r1 + r2)
    # mod-q wraparound in the exponents
    v1, r1, v2, r2 = Q - 2, Q - 1, 5, 4
    assert (commit_int(v1, r1) * commit_int(v2, r2)) % P == commit_int((v1 + v2) % Q, (r1 + r2) % Q)
    # ── §3.20 inc.2: generator families, vector commit, MSM ──
    g0, g1, h0 = derive_gen(0, 0), derive_gen(1, 0), derive_gen(0, 1)
    assert len({g0, g1, h0, G, H}) == 5, "generator families collide"
    for gg in (g0, g1, h0):
        assert pow(gg, Q, P) == 1 and gg not in (0, 1), "gen not an order-q element"
    assert derive_gen(0, 0) == g0, "gen not deterministic"
    # vector_commit is the MSM over the [h, G_i, H_i] generator list with the same exponents
    a, b, rr = [3, 5], [7, 0], 0x1234
    vc = vector_commit_int(a, b, rr)
    msm_equiv = msm_int([rr, a[0], a[1], b[0], b[1]],
                        [H, derive_gen(0, 0), derive_gen(1, 0), derive_gen(0, 1), derive_gen(1, 1)])
    assert vc == msm_equiv, "vector_commit != MSM over [h,G_i,H_i]"
    # zero-exponent skip: a term with exponent 0 contributes the identity
    assert vector_commit_int([0, 5], [7, 0], rr) == vector_commit_int([0, 5], [7, 0], rr)
    assert msm_int([0, 0], [g0, g1]) == 1, "all-zero MSM must be the identity 1"
    # additive homomorphism of the vector commit (exponent-wise, no q-wrap)
    a1, b1, r1v = [2, 3], [4, 1], 11
    a2, b2, r2v = [5, 1], [0, 6], 13
    lhs = (vector_commit_int(a1, b1, r1v) * vector_commit_int(a2, b2, r2v)) % P
    rhs = vector_commit_int([a1[0] + a2[0], a1[1] + a2[1]], [b1[0] + b2[0], b1[1] + b2[1]], r1v + r2v)
    assert lhs == rhs, "vector_commit homomorphism broken"
    print("verify_ff_pedersen selftest: safe-prime + subgroup + binding + homomorphism"
          " + gens/vector_commit/msm OK")


def emit_params():
    inv = 1
    for _ in range(6):
        inv = (inv * (2 - P * inv)) % (1 << 32)
    nprime = (-inv) % (1 << 32)
    r2 = pow(2, 32 * LIMBS * 2, P)
    def limbs(x): return [(x >> (32 * i)) & 0xFFFFFFFF for i in range(LIMBS)]
    def arr(name, x):
        L = limbs(x); s = "static const uint32_t %s[96] = {\n" % name
        for row in range(0, 96, 6):
            s += "  " + ", ".join("0x%08x" % L[row + k] for k in range(6)) + ",\n"
        return s + "};\n"
    hx = format(P, "X")
    out = os.path.join(os.path.dirname(__file__), "..", "src", "crypto", "ff", "ff_params.h")
    with open(out, "w") as f:
        f.write("/* GENERATED by tools/verify_ff_pedersen.py emit_params() — do not edit by hand.\n")
        f.write(" * RFC 3526 MODP-3072 prime-order subgroup for the §3.20 finite-field Pedersen\n")
        f.write(" * commitment. p = RFC 3526 group 15 safe prime (verified prime + safe);\n")
        f.write(" * q = (p-1)/2 = subgroup order; g = 4 (a QR); h = nothing-up-my-sleeve second\n")
        f.write(" * generator (hash-to-group under \"%s\", pinned).\n" % H_DST.decode())
        f.write(" * 96 little-endian uint32 limbs. NPRIME = -p^{-1} mod 2^32. R2 = 2^6144 mod p.\n")
        f.write(" * p head %s... tail ...%s */\n" % (hx[:16], hx[-16:]))
        f.write("#ifndef DETERM_FF_PARAMS_H\n#define DETERM_FF_PARAMS_H\n#include <stdint.h>\n\n")
        f.write("#define DETERM_FF_LIMBS 96\n#define DETERM_FF_NPRIME 0x%08xu\n\n" % nprime)
        f.write(arr("DETERM_FF_P", P) + "\n")
        f.write(arr("DETERM_FF_Q", Q) + "\n")
        f.write(arr("DETERM_FF_R2", r2) + "\n")
        f.write(arr("DETERM_FF_H", H) + "\n")
        f.write("#endif\n")
    print("wrote %s (nprime=0x%08x)" % (out, nprime))


def emit():
    vectors = [{"name": "H generator (hash-to-group, pinned)", "type": "h_generator",
                "h_hex": _to_bytes(H).hex()}]
    for v, r in [(0, 0x77), (9, 0x1234), (1000000, 0x00112233445566778899),
                 (0xdeadbeef, 0xfeedface00c0ffee)]:
        vectors.append({"name": "commit v=0x%x r=0x%x" % (v, r), "type": "commit",
                        "v_hex": _s(v), "r_hex": _s(r), "c_hex": commit_hex(_s(v), _s(r))})
    v1, r1, v2, r2 = Q - 2, Q - 1, 5, 4          # forces mod-q wraparound in both exponents
    c3 = _to_bytes((commit_int(v1, r1) * commit_int(v2, r2)) % P).hex()
    vectors.append({"name": "homomorphism q-wraparound", "type": "homomorphism",
                    "v1_hex": _s(v1), "r1_hex": _s(r1), "v2_hex": _s(v2), "r2_hex": _s(r2),
                    "c3_hex": c3})
    # ── §3.20 inc.2: generator families (pinned KAT), vector commit, MSM ──
    for index, which in [(0, 0), (1, 0), (0, 1), (5, 1)]:
        vectors.append({"name": "gen index=%d family=%s" % (index, "G" if which == 0 else "H"),
                        "type": "ff_gen", "index": index, "which": which,
                        "g_hex": _to_bytes(derive_gen(index, which)).hex()})
    # vector commit: n=2, a0=0 exercises the G-side zero-skip, b1=0 the H-side skip
    for name, a, b, r in [("vector_commit n=2 mixed-skip", [0, 9], [4, 0], 0x99),
                          ("vector_commit n=3 near-q exps", [Q - 1, 2, 0], [4, Q - 2, 7], Q - 3)]:
        vectors.append({"name": name, "type": "ff_vector_commit",
                        "a_hex": [_s(x) for x in a], "b_hex": [_s(x) for x in b],
                        "r_hex": _s(r), "c_hex": _to_bytes(vector_commit_int(a, b, r)).hex()})
    # MSM: mid zero-scalar skip over generator-family points; and the all-zero identity
    pts3 = [derive_gen(0, 0), derive_gen(1, 0), derive_gen(0, 1)]
    for name, sc, pts in [("msm n=3 mid-skip", [2, 0, 5], pts3),
                          ("msm all-zero identity", [0, 0], [derive_gen(2, 0), derive_gen(3, 0)])]:
        vectors.append({"name": name, "type": "ff_msm",
                        "scalars_hex": [_s(x) for x in sc], "points_hex": [_to_bytes(p).hex() for p in pts],
                        "m_hex": _to_bytes(msm_int(sc, pts)).hex()})
    doc = {"primitive": "ff_pedersen",
           "source": ("Generated by tools/verify_ff_pedersen.py (Determ CRYPTO-C99-SPEC §3.20); "
                      "Pedersen commitment C = g^v * h^r mod p over the RFC 3526 MODP-3072 "
                      "prime-order subgroup, from-scratch Python bignum reference."),
           "note": ("Finite-field Pedersen over Z_p* (RFC 3526 MODP-3072). p safe prime, "
                    "q=(p-1)/2, g=4, h=hash-to-group. Scalars v,r 384-byte big-endian < q; "
                    "commitments 384-byte big-endian."),
           "vectors": vectors}
    out = os.path.join(os.path.dirname(__file__), "vectors", "ff_pedersen.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=2); f.write("\n")
    print("wrote %s (%d vectors)" % (out, len(vectors)))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "emit-params":
        emit_params()
    elif len(sys.argv) > 1 and sys.argv[1] == "emit":
        emit()
    else:
        _selftest()
