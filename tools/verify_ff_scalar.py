#!/usr/bin/env python3
# Independent Python reference for the Determ FINITE-FIELD SCALAR FIELD mod q —
# CRYPTO-C99-SPEC.md §3.20 increment 3 (the scalar/exponent field the §3.20
# Bulletproofs IPA / range proof operate in). q = (p-1)/2 is the prime order of the
# subgroup G_q of Z_p*, p = RFC 3526 MODP-3072 safe prime.
#
# This is the from-scratch oracle the C port (src/crypto/ff/ffgroup.c, the inc.3
# determ_ff_scalar_* + determ_ff_hash_to_scalar) is checked against byte-for-byte
# (tools/vectors/ff_scalar.json, §3.13 dual-oracle). Python's native bignums are the
# reference arithmetic; q is imported from the inc.1 reference so there is a single
# source of the modulus.
#
#   * emit()             -> (re)generate tools/vectors/ff_scalar.json.
#   * check_ff_scalar    -> §3.13 file-half checker (imported by test_c99_vector_files.sh).
import hashlib, json, os
import verify_ff_pedersen as vp

Q = vp.Q                                   # prime subgroup order = scalar field modulus
ELEM = vp.ELEM                             # 384 bytes

# Fixed DST for the hash-to-scalar KAT (the IPA passes its own transcript DST at runtime;
# this pins the construction). Distinct from the group hash-to-group DSTs.
HTS_DST = b"DETERM-FF-HASH-TO-SCALAR-MODP3072-Q-v1"


def _to_bytes(x):
    return x.to_bytes(ELEM, "big")


def _s(x):
    return "%0768x" % x


def sc_reduce(x):
    return x % Q


def sc_add(a, b):
    if not (0 <= a < Q and 0 <= b < Q): raise ValueError("operands must be < q")
    return (a + b) % Q


def sc_mul(a, b):
    if not (0 <= a < Q and 0 <= b < Q): raise ValueError("operands must be < q")
    return (a * b) % Q


def sc_sub(a, b):
    if not (0 <= a < Q and 0 <= b < Q): raise ValueError("operands must be < q")
    return (a - b) % Q


def sc_inv(a):
    if not (0 < a < Q): raise ValueError("a must satisfy 0 < a < q")
    return pow(a, Q - 2, Q)                # Fermat: a^{q-2} = a^{-1} mod q (q prime)


def hash_to_scalar(msg, dst):
    """13 SHA-256 blocks of (dst || msg || counter) -> 416 bytes -> reduce mod q.
    Byte-identical to the C determ_ff_hash_to_scalar (streaming SHA-256, same order)."""
    material = b"".join(hashlib.sha256(dst + msg + bytes([i])).digest() for i in range(13))
    return int.from_bytes(material, "big") % Q


# ── §3.13 file-half checker (imported by test_c99_vector_files.sh) ────────────
def check_ff_scalar(vec, label):
    t = vec.get("type")
    if t == "sc_reduce":
        got = _to_bytes(sc_reduce(int(vec["in_hex"], 16))).hex()
        if got != vec["out_hex"]:
            return "recomputed reduce != out_hex"
    elif t == "sc_add":
        got = _to_bytes(sc_add(int(vec["a_hex"], 16), int(vec["b_hex"], 16))).hex()
        if got != vec["out_hex"]:
            return "recomputed a+b != out_hex"
    elif t == "sc_mul":
        got = _to_bytes(sc_mul(int(vec["a_hex"], 16), int(vec["b_hex"], 16))).hex()
        if got != vec["out_hex"]:
            return "recomputed a*b != out_hex"
    elif t == "sc_sub":
        got = _to_bytes(sc_sub(int(vec["a_hex"], 16), int(vec["b_hex"], 16))).hex()
        if got != vec["out_hex"]:
            return "recomputed a-b != out_hex"
    elif t == "sc_inv":
        got = _to_bytes(sc_inv(int(vec["a_hex"], 16))).hex()
        if got != vec["out_hex"]:
            return "recomputed a^-1 != out_hex"
    elif t == "hash_to_scalar":
        got = _to_bytes(hash_to_scalar(bytes.fromhex(vec["msg_hex"]),
                                       vec["dst"].encode())).hex()
        if got != vec["out_hex"]:
            return "recomputed hash_to_scalar != out_hex"
    else:
        return "unknown ff_scalar vector type %r" % t
    return None


def _selftest():
    assert vp._miller_rabin(Q), "q not prime"
    # ring axioms
    a, b, c = 0x1111, 0x2222, Q - 3
    assert sc_add(a, b) == (a + b)
    assert sc_add(c, 5) == (c + 5) % Q and sc_add(c, 5) < Q, "add must wrap mod q"
    assert sc_mul(a, b) == a * b
    assert sc_mul(Q - 1, Q - 1) == pow(Q - 1, 2, Q)
    assert sc_sub(b, a) == b - a                                    # b>a: no wrap
    assert sc_sub(a, b) == (a - b) % Q and 0 < sc_sub(a, b) < Q     # a<b: underflow wraps
    assert sc_add(sc_sub(a, b), b) == a and sc_sub(a, a) == 0
    for x in (1, 2, 7, 0x123456789, Q - 1, Q // 2):
        assert sc_mul(x, sc_inv(x)) == 1, "inverse broken for %d" % x
    # hash_to_scalar deterministic, reduced, nonzero
    h = hash_to_scalar(b"determ-ipa-challenge-0001", HTS_DST)
    assert 0 < h < Q and h == hash_to_scalar(b"determ-ipa-challenge-0001", HTS_DST)
    assert hash_to_scalar(b"x", HTS_DST) != hash_to_scalar(b"y", HTS_DST)
    print("verify_ff_scalar selftest: q prime + add/mul/inv ring axioms + hash_to_scalar OK")


def emit():
    vectors = []
    # sc_reduce: values that need reduction (q+7, 2q-1, ~4q via a wide input < 2^3072)
    for name, x in [("reduce q+7", Q + 7), ("reduce 2q-1", 2 * Q - 1),
                    ("reduce near-2^3072", (1 << 3072) - 1)]:
        vectors.append({"name": name, "type": "sc_reduce",
                        "in_hex": _s(x % (1 << 3072)), "out_hex": _to_bytes(sc_reduce(x % (1 << 3072))).hex()})
    # sc_add: plain + a wrap (a+b >= q)
    for name, a, b in [("add small", 0x1234, 0x5678), ("add wrap", Q - 3, 10)]:
        vectors.append({"name": name, "type": "sc_add", "a_hex": _s(a), "b_hex": _s(b),
                        "out_hex": _to_bytes(sc_add(a, b)).hex()})
    # sc_mul: small + near-q operands
    for name, a, b in [("mul small", 0x9, 0x1234), ("mul near-q", Q - 2, Q - 5)]:
        vectors.append({"name": name, "type": "sc_mul", "a_hex": _s(a), "b_hex": _s(b),
                        "out_hex": _to_bytes(sc_mul(a, b)).hex()})
    # sc_sub: plain + an underflow (a < b -> wraps mod q) + a-0
    for name, a, b in [("sub small", 0x5678, 0x1234), ("sub underflow", 3, 10), ("sub a-0", 0x99, 0)]:
        vectors.append({"name": name, "type": "sc_sub", "a_hex": _s(a), "b_hex": _s(b),
                        "out_hex": _to_bytes(sc_sub(a, b)).hex()})
    # sc_inv: a few (the C recomputes a^{q-2}; file-half also implicitly checks a*inv==1)
    for name, a in [("inv 7", 7), ("inv deadbeef", 0xdeadbeef), ("inv q-1", Q - 1)]:
        vectors.append({"name": name, "type": "sc_inv", "a_hex": _s(a),
                        "out_hex": _to_bytes(sc_inv(a)).hex()})
    # hash_to_scalar KAT
    msg = b"determ-ipa-challenge-0001"
    vectors.append({"name": "hash_to_scalar KAT", "type": "hash_to_scalar",
                    "msg_hex": msg.hex(), "dst": HTS_DST.decode(),
                    "out_hex": _to_bytes(hash_to_scalar(msg, HTS_DST)).hex()})
    doc = {"primitive": "ff_scalar",
           "source": ("Generated by tools/verify_ff_scalar.py (Determ CRYPTO-C99-SPEC §3.20 inc.3); "
                      "scalar field mod q = (p-1)/2 over the RFC 3526 MODP-3072 subgroup, "
                      "from-scratch Python bignum reference."),
           "note": ("Scalar/exponent field for the §3.20 Bulletproofs IPA/range proof. "
                    "q prime, scalars 384-byte big-endian < q. add/mul/inv mod q; "
                    "hash_to_scalar = 13 SHA-256 counter blocks of (dst||msg||i) mod q."),
           "vectors": vectors}
    out = os.path.join(os.path.dirname(__file__), "vectors", "ff_scalar.json")
    with open(out, "w") as f:
        json.dump(doc, f, indent=2); f.write("\n")
    print("wrote %s (%d vectors)" % (out, len(vectors)))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "emit":
        emit()
    else:
        _selftest()
