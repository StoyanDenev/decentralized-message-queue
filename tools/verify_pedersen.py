#!/usr/bin/env python3
# Independent Python reference for the Determ Pedersen commitment over P-256
# (CRYPTO-C99-SPEC.md §3.19). This is the SECOND implementation of the §3.13
# dual-oracle gate: it re-derives the second generator H via RFC 9380
# hash_to_curve (P256_XMD:SHA-256_SSWU_RO_) and recomputes each commitment
# C = v*G + r*H from scratch (own scalar-mult ladder), independent of the C.
#
#   * emit()          — regenerate tools/vectors/pedersen.json (self-checks that
#                       the derived H matches the C-pinned KAT before writing).
#   * check_pedersen  — imported by tools/test_c99_vector_files.sh (§3.13 file
#                       half): recompute each vector, compare to the frozen hex.
#
# P-256 domain parameters are the public FIPS 186 / SEC 2 constants; they are
# cross-checked structurally (G on-curve, n*G == O is implied by the RFC-vector-
# gated h2c matching the C's pinned H).
import hashlib, json, os, sys

P  = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A  = (P - 3) % P
B  = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N  = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G  = (GX, GY)

# H = hash_to_curve(MSG, DST) — the fixed nothing-up-my-sleeve inputs; MUST match
# PEDERSEN_H_MSG / PEDERSEN_H_DST in src/crypto/pedersen/pedersen.c byte-for-byte.
H_MSG = b"Determ Pedersen generator H over NIST P-256 v1"
H_DST = b"DETERM-PEDERSEN-P256_XMD:SHA-256_SSWU_RO_"

# The C-pinned compressed H (test-pedersen-c99 / src/main.cpp). emit() refuses to
# write unless the from-scratch derivation reproduces this exactly.
H_PINNED = "0235527ee68afadb08b77415a8b00cc314abb1fd526451508271ee6c441ae0ad55"


def expand_xmd(msg, dst, length):
    ell = -(-length // 32)
    if ell > 255 or length > 65535 or len(dst) > 255:
        raise ValueError("expand_message_xmd bounds exceeded")
    dst_p = dst + bytes([len(dst)])
    b0 = hashlib.sha256(b"\x00" * 64 + msg + length.to_bytes(2, "big")
                        + b"\x00" + dst_p).digest()
    bi = hashlib.sha256(b0 + b"\x01" + dst_p).digest()
    out = bi
    for i in range(2, ell + 1):
        bi = hashlib.sha256(bytes(x ^ y for x, y in zip(b0, bi))
                            + bytes([i]) + dst_p).digest()
        out += bi
    return out[:length]


def map_sswu(u):
    z = (-10) % P                               # RFC 9380 §8.2: Z = -10
    inv0 = lambda x: pow(x, P - 2, P)           # inv0(0) == 0
    tv1 = inv0((z * z * pow(u, 4, P) + z * u * u) % P)
    x1 = (-B * inv0(A)) % P * (1 + tv1) % P
    if tv1 == 0:
        x1 = B * inv0(z * A % P) % P
    gx1 = (pow(x1, 3, P) + A * x1 + B) % P
    x2 = (z * u * u % P) * x1 % P
    gx2 = (pow(x2, 3, P) + A * x2 + B) % P
    if pow(gx1, (P - 1) // 2, P) in (0, 1):
        x, g = x1, gx1
    else:
        x, g = x2, gx2
    y = pow(g, (P + 1) // 4, P)                  # P == 3 mod 4
    if (y * y - g) % P:
        raise ValueError("sswu: g(x) unexpectedly non-square")
    if (u % 2) != (y % 2):                       # sgn0 m=1
        y = P - y
    return (x, y)


def pt_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None                              # P + (-P) = O
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def pt_mul(k, pt):
    k %= N
    r, q = None, pt
    while k:
        if k & 1:
            r = pt_add(r, q)
        q = pt_add(q, q)
        k >>= 1
    return r


def compress(pt):
    if pt is None:
        raise ValueError("cannot compress the identity")
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def derive_h():
    ub = expand_xmd(H_MSG, H_DST, 96)            # count=2 * m=1 * L=48
    u0 = int.from_bytes(ub[:48], "big") % P
    u1 = int.from_bytes(ub[48:], "big") % P
    return pt_add(map_sswu(u0), map_sswu(u1))


def commit_pt(v, r):
    if not (0 < r < N):
        raise ValueError("r must satisfy 0 < r < n")
    if v >= N:
        raise ValueError("v must be < n")
    H = derive_h()
    return pt_add(pt_mul(v, G), pt_mul(r, H))     # v==0 -> pt_mul(0,G)=None, add is identity-aware


def commit_hex(v_hex, r_hex):
    return compress(commit_pt(int(v_hex, 16), int(r_hex, 16))).hex()


# ---- §3.13 file-half checker (imported by test_c99_vector_files.sh) ----
def check_pedersen(vec, label):
    t = vec.get("type")
    if t == "h_generator":
        want = vec["h_hex"]
        got = compress(derive_h()).hex()
        if got != want:
            return "recomputed H %s != h_hex %s" % (got, want)
    elif t == "commit":
        got = commit_hex(vec["v_hex"], vec["r_hex"])
        if got != vec["c_hex"]:
            return "recomputed commit %s != c_hex %s" % (got, vec["c_hex"])
    elif t == "homomorphism":
        # commit(v1,r1) (+) commit(v2,r2) == c3, where c3 is the frozen add
        # result. Exercises the mod-n reduction of v1+v2 / r1+r2 (the group law
        # reduces inherently), which the no-carry binary gate does not reach.
        c1 = commit_pt(int(vec["v1_hex"], 16), int(vec["r1_hex"], 16))
        c2 = commit_pt(int(vec["v2_hex"], 16), int(vec["r2_hex"], 16))
        got = compress(pt_add(c1, c2)).hex()
        if got != vec["c3_hex"]:
            return "recomputed C1+C2 %s != c3_hex %s" % (got, vec["c3_hex"])
    else:
        return "unknown pedersen vector type %r" % t
    return None


def _s32(x):
    return "%064x" % x


def emit():
    h = compress(derive_h()).hex()
    if h != H_PINNED:
        raise SystemExit("H mismatch: derived %s != C-pinned %s" % (h, H_PINNED))
    # (v, r) inputs: zero-value, small, and multi-byte (r always 0 < r < n).
    commits = [
        (0,        0x77),
        (9,        0x1234),
        (1000000,  0x0011223344556677),
        (0xdeadbeef, 0xfeedface00c0ffee),
    ]
    vectors = [{"name": "H generator (nothing-up-my-sleeve)",
                "type": "h_generator", "h_hex": h}]
    for v, r in commits:
        vh, rh = _s32(v), _s32(r)
        vectors.append({
            "name": "commit v=0x%x r=0x%x" % (v, r),
            "type": "commit", "v_hex": vh, "r_hex": rh,
            "c_hex": commit_hex(vh, rh),
        })
    # Additive homomorphism with mod-n WRAPAROUND on both v and r (v1+v2 and
    # r1+r2 both exceed n): commit(v1,r1) (+) commit(v2,r2) == commit((v1+v2) mod
    # n, (r1+r2) mod n). Pins the reduction path the no-carry binary gate misses.
    v1, r1, v2, r2 = N - 2, N - 1, 5, 5
    c3 = compress(commit_pt((v1 + v2) % N, (r1 + r2) % N)).hex()
    vectors.append({
        "name": "homomorphism v/r mod-n wraparound",
        "type": "homomorphism",
        "v1_hex": _s32(v1), "r1_hex": _s32(r1),
        "v2_hex": _s32(v2), "r2_hex": _s32(r2),
        "c3_hex": c3,
    })
    doc = {
        "primitive": "pedersen",
        "source": ("Generated by tools/verify_pedersen.py (Determ CRYPTO-C99-SPEC "
                   "§3.19); H via RFC 9380 P256_XMD:SHA-256_SSWU_RO_ hash_to_curve, "
                   "commitments C = v*G + r*H via an independent from-scratch P-256 "
                   "EC ladder; self-checked against the C-pinned H KAT before write."),
        "note": ("Pedersen commitment over NIST P-256 (Determ CRYPTO-C99-SPEC "
                 "§3.19). H = hash_to_curve(MSG, DST) via P256_XMD:SHA-256_"
                 "SSWU_RO_ (RFC 9380); commitments C = v*G + r*H, SEC1 "
                 "compressed. Scalars 32-byte big-endian < n."),
        "vectors": vectors,
    }
    out = os.path.join(os.path.dirname(__file__), "vectors", "pedersen.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print("wrote %s (%d vectors, H=%s)" % (out, len(vectors), h))


if __name__ == "__main__":
    emit()
