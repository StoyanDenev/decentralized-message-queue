#!/usr/bin/env python3
# tools/verify_mldsa_keygen.py — ML-DSA (FIPS 204) KeyGen corpus verifier.
#
# The corpus tools/vectors/mldsa_keygen.json holds the AUTHORITATIVE NIST ACVP
# KeyGen vectors (seed -> pk/sk) — the first EXTERNAL oracle on the PQ track. This
# script recomputes ML-DSA.KeyGen_internal(seed) through an INDEPENDENT python
# implementation (hashlib SHAKE + the FIPS 204 sample/pack rules + a from-scratch
# python NTT) and checks it reproduces the stored ACVP pk/sk byte-for-byte. The C
# `determ test-c99-vectors` runs the SAME corpus through the shipped C keygen; both
# are pinned against the frozen NIST bytes, so a bug shared by C and python is still
# caught by the external reference.
#
#   python tools/verify_mldsa_keygen.py            # verify the committed corpus
#   python tools/verify_mldsa_keygen.py --emit S   # (re)generate from an ACVP
#                                                   # internalProjection.json at S
import hashlib, json, os, sys

Q = 8380417; N = 256; D = 13; ZETA = 1753
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(HERE, "tools", "vectors", "mldsa_keygen.json")
PARAMS = {"ML-DSA-44": (4, 4, 2), "ML-DSA-65": (6, 5, 4), "ML-DSA-87": (8, 7, 2)}

def brv8(i):
    r = 0
    for b in range(8): r |= ((i >> b) & 1) << (7 - b)
    return r
ZS = [pow(ZETA, brv8(k), Q) for k in range(256)]

def ntt(a):
    a = a[:]; k = 0; length = 128
    while length >= 1:
        start = 0
        while start < 256:
            k += 1; z = ZS[k]
            for j in range(start, start + length):
                t = (z * a[j + length]) % Q
                a[j + length] = (a[j] - t) % Q
                a[j] = (a[j] + t) % Q
            start += 2 * length
        length //= 2
    return a

def invntt(a):
    a = a[:]; k = 256; length = 1
    while length < 256:
        start = 0
        while start < 256:
            k -= 1; z = (-ZS[k]) % Q
            for j in range(start, start + length):
                t = a[j]
                a[j] = (t + a[j + length]) % Q
                a[j + length] = (z * ((t - a[j + length]) % Q)) % Q
            start += 2 * length
        length *= 2
    f = pow(256, Q - 2, Q)
    return [(x * f) % Q for x in a]

def sample_uniform(seed):
    buf = hashlib.shake_128(seed).digest(4096); i = 0; a = []
    while len(a) < N:
        if i + 3 > len(buf): buf = hashlib.shake_128(seed).digest(len(buf) + 4096)
        t = buf[i] | (buf[i+1] << 8) | ((buf[i+2] & 0x7F) << 16); i += 3
        if t < Q: a.append(t)
    return a
def sample_eta(seed, eta):
    buf = hashlib.shake_256(seed).digest(4096); i = 0; a = []
    while len(a) < N:
        if i >= len(buf): buf = hashlib.shake_256(seed).digest(len(buf) + 4096)
        b = buf[i]; i += 1
        for z in (b & 0x0F, b >> 4):
            if len(a) >= N: break
            if eta == 2:
                if z < 15: a.append(2 - (z % 5))
            else:
                if z < 9: a.append(4 - z)
    return a

def le16(x): return bytes([x & 0xff, (x >> 8) & 0xff])
def power2round(r):
    r %= Q; r0 = r % (1 << D)
    if r0 > (1 << (D - 1)): r0 -= (1 << D)
    return (r - r0) >> D, r0

def simple_bitpack(w, bits):
    out = bytearray(); acc = 0; nb = 0
    for cf in w:
        acc |= (cf & ((1 << bits) - 1)) << nb; nb += bits
        while nb >= 8: out.append(acc & 0xff); acc >>= 8; nb -= 8
    if nb: out.append(acc & 0xff)
    return bytes(out)
def bitpack(w, a, b):
    return simple_bitpack([b - cf for cf in w], (a + b).bit_length())

def keygen(xi, k, l, eta):
    h = hashlib.shake_256(xi + bytes([k]) + bytes([l])).digest(128)
    rho, rhop, K = h[:32], h[32:96], h[96:128]
    A = [[sample_uniform(rho + bytes([j]) + bytes([i])) for j in range(l)] for i in range(k)]
    s1 = [sample_eta(rhop + le16(i), eta) for i in range(l)]
    s2 = [sample_eta(rhop + le16(l + i), eta) for i in range(k)]
    s1h = [ntt(s1[j]) for j in range(l)]
    t1 = []; t0 = []
    for i in range(k):
        acc = [0] * N
        for j in range(l):
            acc = [(acc[c] + A[i][j][c] * s1h[j][c]) % Q for c in range(N)]
        ti = invntt(acc)
        ti = [(ti[c] + s2[i][c]) % Q for c in range(N)]
        r1 = [0]*N; r0 = [0]*N
        for c in range(N): r1[c], r0[c] = power2round(ti[c])
        t1.append(r1); t0.append(r0)
    pk = rho + b"".join(simple_bitpack(t1[i], 10) for i in range(k))
    tr = hashlib.shake_256(pk).digest(64)
    sk = rho + K + tr
    sk += b"".join(bitpack(s1[i], eta, eta) for i in range(l))
    sk += b"".join(bitpack(s2[i], eta, eta) for i in range(k))
    sk += b"".join(bitpack(t0[i], (1 << (D-1)) - 1, 1 << (D-1)) for i in range(k))
    return pk, sk

def emit(acvp_path):
    d = json.load(open(acvp_path)); vecs = []
    for g in d["testGroups"]:
        ps = g["parameterSet"]; t = g["tests"][0]
        vecs.append({"paramSet": ps, "tcId": t["tcId"], "seed_hex": t["seed"].lower(),
                     "pk_hex": t["pk"].lower(), "sk_hex": t["sk"].lower()})
    doc = {"primitive": "mldsa_keygen",
           "source": "NIST ACVP-Server gen-val ML-DSA-keyGen-FIPS204 internalProjection.json "
                     "(first AFT test of each parameter set); the authoritative FIPS 204 "
                     "KeyGen KAT (seed xi -> pk/sk). Recomputed by tools/verify_mldsa_keygen.py.",
           "vectors": vecs}
    with open(CORPUS, "w") as f: json.dump(doc, f, indent=1)
    print("emitted %d vectors -> %s" % (len(vecs), CORPUS))

def verify():
    doc = json.load(open(CORPUS)); n = ok = 0
    for v in doc["vectors"]:
        n += 1; ps = v["paramSet"]; k, l, eta = PARAMS[ps]
        xi = bytes.fromhex(v["seed_hex"])
        pk, sk = keygen(xi, k, l, eta)
        if pk.hex().upper() != v["pk_hex"].upper():
            print("  bad: %s: pk != ACVP" % ps); continue
        if sk.hex().upper() != v["sk_hex"].upper():
            print("  bad: %s: sk != ACVP" % ps); continue
        # structural cross-check: pk and sk share rho (first 32 bytes)
        if pk[:32] != sk[:32]:
            print("  bad: %s: pk/sk rho prefix mismatch" % ps); continue
        ok += 1
    print("mldsa keygen vectors: %d/%d OK" % (ok, n))
    return ok == n and n > 0

if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--emit":
        emit(sys.argv[2])
    sys.exit(0 if verify() else 1)
