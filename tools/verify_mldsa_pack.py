#!/usr/bin/env python3
"""verify_mldsa_pack.py — module-local reproducibility gate + generator for
tools/vectors/mldsa_pack.json (the Determ C99 ML-DSA / Dilithium coefficient
bit-packing, CRYPTO-C99-SPEC §3.18 increment 4).

Two INDEPENDENT checks, so this is not a round-trip tautology (the R64/R65
lesson): (1) the stored bytes are recomputed by a from-scratch LSB-first bit
packer and matched; (2) every field is re-extracted by a **direct bit-slice**
that reads bits by absolute offset — a code path distinct from the unpacker — so
a symmetric permutation bug in pack/unpack cannot survive. The generic packer is
also cross-checked against the canonical Dilithium `pack_t1` formula.

Usage:
  python tools/verify_mldsa_pack.py            # verify the stored corpus
  python tools/verify_mldsa_pack.py --emit     # (re)generate then verify
Prints "mldsa pack vectors: N/N OK"; stdlib only.
"""
import json, os, sys, random

Q = 8380417
N = 256
D = 13
G1_17 = 1 << 17
G1_19 = 1 << 19
G2_88 = (Q - 1) // 88
G2_32 = (Q - 1) // 32

def pack_bits(vals, bits):
    total = (len(vals) * bits + 7) // 8
    out = bytearray(total); acc = 0; nbits = 0; oi = 0
    for v in vals:
        acc |= (v & ((1 << bits) - 1)) << nbits; nbits += bits
        while nbits >= 8:
            out[oi] = acc & 0xFF; oi += 1; acc >>= 8; nbits -= 8
    if nbits:
        out[oi] = acc & 0xFF
    return bytes(out)

def unpack_bits(buf, n, bits):
    vals = []; acc = 0; nbits = 0; bi = 0
    for _ in range(n):
        while nbits < bits:
            acc |= buf[bi] << nbits; bi += 1; nbits += 8
        vals.append(acc & ((1 << bits) - 1)); acc >>= bits; nbits -= bits
    return vals

def slice_field(buf, i, bits):
    """INDEPENDENT: read field i bit-by-bit by absolute offset (distinct code path)."""
    v = 0
    for b in range(bits):
        k = i * bits + b
        v |= ((buf[k >> 3] >> (k & 7)) & 1) << b
    return v

def ref_pack_t1(a):
    """Canonical Dilithium pack_t1 (10-bit), byte-for-byte, as a cross-oracle."""
    r = bytearray(320)
    for i in range(N // 4):
        r[5*i+0] = a[4*i+0] & 0xFF
        r[5*i+1] = ((a[4*i+0] >> 8) | (a[4*i+1] << 2)) & 0xFF
        r[5*i+2] = ((a[4*i+1] >> 6) | (a[4*i+2] << 4)) & 0xFF
        r[5*i+3] = ((a[4*i+2] >> 4) | (a[4*i+3] << 6)) & 0xFF
        r[5*i+4] = (a[4*i+3] >> 2) & 0xFF
    return bytes(r)

# per-encoding: (bits, coefficient -> unsigned field, unsigned field -> coefficient)
def enc_t1(c):  return c
def enc_t0(c):  return (1 << (D-1)) - c
def enc_z17(c): return G1_17 - c
def enc_z19(c): return G1_19 - c
def enc_eta(eta): return lambda c: eta - c

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(HERE, "tools", "vectors", "mldsa_pack.json")

def poly(seed, lo, hi):
    random.seed(seed)
    return [random.randrange(lo, hi) for _ in range(N)]

def gen():
    vecs = []
    def add(kind, name, coeffs, fields, bits, **extra):
        v = {"kind": kind, "name": name, "coeffs": coeffs, "bits": bits,
             "bytes_hex": pack_bits(fields, bits).hex()}
        v.update(extra); vecs.append(v)
    # t1: 10-bit unsigned
    for s in (11, 12):
        c = poly(s, 0, 1 << 10); add("t1", "t1 seed %d" % s, c, [enc_t1(x) for x in c], 10)
    # t0: 13-bit, coeff in (-2^12, 2^12]
    for s in (21, 22):
        c = poly(s, -(1 << 12) + 1, (1 << 12) + 1); add("t0", "t0 seed %d" % s, c, [enc_t0(x) for x in c], 13)
    # eta: 2 (3-bit) and 4 (4-bit)
    for eta, bits in ((2, 3), (4, 4)):
        c = poly(30 + eta, -eta, eta + 1)
        add("eta", "eta%d" % eta, c, [enc_eta(eta)(x) for x in c], bits, eta=eta)
    # w1: unsigned, g2-dependent width
    for g2, m, bits in ((G2_88, 44, 6), (G2_32, 16, 4)):
        c = poly(40 + bits, 0, m); add("w1", "w1 g2=%d" % g2, c, c, bits, gamma2=g2)
    # z: g1-dependent width
    for g1, bits, ef in ((G1_17, 18, enc_z17), (G1_19, 20, enc_z19)):
        c = poly(50 + bits, -g1 + 1, g1 + 1); add("z", "z g1=%d" % g1, c, [ef(x) for x in c], bits, gamma1=g1)
    doc = {"primitive": "mldsa_pack",
           "source": "FIPS 204 / Dilithium coefficient bit-packing (LSB-first) generated "
                     "by tools/verify_mldsa_pack.py; bytes_hex recomputed + independently "
                     "bit-sliced; t1 cross-checked vs the reference pack_t1 formula",
           "vectors": vecs}
    with open(CORPUS, "w") as f:
        json.dump(doc, f, indent=1)
    print("emitted %d vectors -> %s" % (len(vecs), CORPUS))

def fields_of(v):
    kind = v["kind"]; c = v["coeffs"]
    if kind == "t1":  return [enc_t1(x) for x in c]
    if kind == "t0":  return [enc_t0(x) for x in c]
    if kind == "eta": return [enc_eta(v["eta"])(x) for x in c]
    if kind == "w1":  return c
    if kind == "z":   return [(v["gamma1"]) - x for x in c]
    return None

def verify():
    with open(CORPUS) as f:
        doc = json.load(f)
    n = ok = 0
    for v in doc["vectors"]:
        n += 1
        bits = v["bits"]; coeffs = v["coeffs"]
        buf = bytes.fromhex(v["bytes_hex"])
        fields = fields_of(v)
        if fields is None:
            print("  bad: %s: unknown kind %r" % (v.get("name"), v["kind"])); continue
        # (1) recompute the packed bytes
        if pack_bits(fields, bits) != buf:
            print("  bad: %s: repacked bytes != bytes_hex" % v["name"]); continue
        # (2) INDEPENDENT bit-slice + unpack round-trip both recover the fields
        if any(slice_field(buf, i, bits) != fields[i] for i in range(N)):
            print("  bad: %s: bit-slice oracle != fields" % v["name"]); continue
        if unpack_bits(buf, N, bits) != fields:
            print("  bad: %s: unpack != fields" % v["name"]); continue
        # (3) t1 cross-check vs the canonical reference formula
        if v["kind"] == "t1" and ref_pack_t1(coeffs) != buf:
            print("  bad: %s: != reference pack_t1" % v["name"]); continue
        ok += 1
    print("mldsa pack vectors: %d/%d OK" % (ok, n))
    return ok == n and n > 0

if __name__ == "__main__":
    if "--emit" in sys.argv or not os.path.exists(CORPUS):
        gen()
    sys.exit(0 if verify() else 1)
