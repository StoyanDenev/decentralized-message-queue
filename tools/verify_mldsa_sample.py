#!/usr/bin/env python3
"""verify_mldsa_sample.py — module-local reproducibility gate + generator for
tools/vectors/mldsa_sample.json (the Determ C99 ML-DSA / Dilithium rejection
samplers, CRYPTO-C99-SPEC §3.18 increment 3).

What this cross-checks (honest scope, per the R65 self-audit): the SHAKE STREAM
is checked against an INDEPENDENT SHAKE — python `hashlib.shake_128/256`, distinct
from the C `determ_shake` (proven byte-equal + vs OpenSSL in R62). The rejection /
value-mapping RULE layered on top is the FIPS 204 algorithm (Alg 29/30/31); the C
and python encode the SAME rule, so the byte-exact C-vs-python KAT alone would NOT
catch a rule that is wrong in BOTH (e.g. an eta sign-flip that stays in range).
To close that gap this gate ALSO recomputes each family's value mapping with an
INDEPENDENT REPRESENTATION (a spec lookup TABLE for the eta / in-ball-sign
mapping — data, not the arithmetic formula — and stdlib `int.from_bytes` for the
uniform 23-bit read) and asserts it agrees, plus the structural invariants
(coefficient bounds, exactly-τ signed-ones). The AUTHORITATIVE end-to-end pin of
the value mapping arrives with the FIPS 204 keygen/sign ACVP KATs (a later
increment, once the samplers have a consumer).

Usage:
  python tools/verify_mldsa_sample.py            # verify the stored corpus
  python tools/verify_mldsa_sample.py --emit     # (re)generate then verify
Prints "mldsa sample vectors: N/N OK"; stdlib `hashlib` only.
"""
import json, os, sys, hashlib

Q = 8380417
N = 256

def sample_uniform(seed):
    xof = hashlib.shake_128(seed); buf = xof.digest(4096); i = 0; a = []
    while len(a) < N:
        if i + 3 > len(buf):
            buf = hashlib.shake_128(seed).digest(len(buf) + 4096)
        t = buf[i] | (buf[i+1] << 8) | ((buf[i+2] & 0x7F) << 16); i += 3
        if t < Q: a.append(t)
    return a

def sample_eta(seed, eta):
    buf = hashlib.shake_256(seed).digest(4096); i = 0; a = []
    while len(a) < N:
        if i >= len(buf):
            buf = hashlib.shake_256(seed).digest(len(buf) + 4096)
        b = buf[i]; i += 1
        for z in (b & 0x0F, b >> 4):
            if len(a) >= N: break
            if eta == 2:
                if z < 15: a.append(2 - (z % 5))
            else:
                if z < 9: a.append(4 - z)
    return a

def sample_in_ball(seed, tau):
    buf = hashlib.shake_256(seed).digest(8 + 4096)
    signs = int.from_bytes(buf[:8], "little"); pos = 8
    c = [0] * N
    for i in range(N - tau, N):
        while True:
            if pos >= len(buf):
                buf = hashlib.shake_256(seed).digest(len(buf) + 4096)
            j = buf[pos]; pos += 1
            if j <= i: break
        c[i] = c[j]; c[j] = 1 - 2 * (signs & 1); signs >>= 1
    return c

# --- INDEPENDENT value-mapping representations (data/stdlib, NOT the formulas
# the C + the samplers above share) — catch a rule wrong in both, e.g. a sign
# flip. FIPS 204 CoeffFromHalfByte tables, hand-entered from the standard: ---
_ETA2_TABLE = [2, 1, 0, -1, -2, 2, 1, 0, -1, -2, 2, 1, 0, -1, -2]   # z=0..14
_ETA4_TABLE = [4, 3, 2, 1, 0, -1, -2, -3, -4]                       # z=0..8
_SIGN_TABLE = {0: 1, 1: -1}                                         # bit -> +/-1

def sample_uniform_indep(seed):
    """Same accept rule, but the 23-bit read via stdlib int.from_bytes (LE)."""
    buf = hashlib.shake_128(seed).digest(4096); i = 0; a = []
    while len(a) < N:
        if i + 3 > len(buf):
            buf = hashlib.shake_128(seed).digest(len(buf) + 4096)
        t = int.from_bytes(bytes([buf[i], buf[i+1], buf[i+2] & 0x7F]), "little"); i += 3
        if t < Q: a.append(t)
    return a

def sample_eta_indep(seed, eta):
    tbl = _ETA2_TABLE if eta == 2 else _ETA4_TABLE
    buf = hashlib.shake_256(seed).digest(4096); i = 0; a = []
    while len(a) < N:
        if i >= len(buf): buf = hashlib.shake_256(seed).digest(len(buf) + 4096)
        b = buf[i]; i += 1
        for z in (b & 0x0F, b >> 4):
            if len(a) >= N: break
            if z < len(tbl): a.append(tbl[z])
    return a

def sample_in_ball_indep(seed, tau):
    buf = hashlib.shake_256(seed).digest(8 + 4096)
    signs = int.from_bytes(buf[:8], "little"); pos = 8; c = [0] * N
    for i in range(N - tau, N):
        while True:
            if pos >= len(buf): buf = hashlib.shake_256(seed).digest(len(buf) + 4096)
            j = buf[pos]; pos += 1
            if j <= i: break
        c[i] = c[j]; c[j] = _SIGN_TABLE[signs & 1]; signs >>= 1
    return c

G1_17 = 1 << 17
G1_19 = 1 << 19

def _unpack_bits(buf, n, bits):
    vals = []; acc = 0; nb = 0; bi = 0
    for _ in range(n):
        while nb < bits: acc |= buf[bi] << nb; bi += 1; nb += 8
        vals.append(acc & ((1 << bits) - 1)); acc >>= bits; nb -= bits
    return vals

def sample_gamma1(seed, g1):
    bits = 18 if g1 == G1_17 else 20
    buf = hashlib.shake_256(seed).digest(N * bits // 8)
    return [g1 - f for f in _unpack_bits(buf, N, bits)]

def sample_gamma1_indep(seed, g1):
    # INDEPENDENT field read: bit-slice each field by absolute offset (distinct
    # from the word-at-a-time unpacker), then g1 - field.
    bits = 18 if g1 == G1_17 else 20
    buf = hashlib.shake_256(seed).digest(N * bits // 8)
    out = []
    for i in range(N):
        v = 0
        for b in range(bits):
            k = i * bits + b; v |= ((buf[k >> 3] >> (k & 7)) & 1) << b
        out.append(g1 - v)
    return out

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(HERE, "tools", "vectors", "mldsa_sample.json")

def gen():
    vecs = []
    U = [("uniform: zero seed", b"\x00" * 34),
         ("uniform: seq seed", bytes(range(34))),
         ("uniform: text seed", b"determ-mldsa-uniform" + b"\x00" * 14)]
    for name, seed in U:
        vecs.append({"kind": "uniform", "name": name, "seed_hex": seed.hex(),
                     "out": sample_uniform(seed)})
    for eta in (2, 4):
        for name, seed in [("eta%d: zero seed" % eta, b"\x00" * 66),
                           ("eta%d: seq seed" % eta, bytes(range(66)))]:
            vecs.append({"kind": "eta", "eta": eta, "name": name,
                         "seed_hex": seed.hex(), "out": sample_eta(seed, eta)})
    for tau in (39, 49, 60):
        for name, seed in [("inball tau=%d: zero seed" % tau, b"\x00" * 32),
                           ("inball tau=%d: seq seed" % tau, bytes(range(48)))]:
            vecs.append({"kind": "in_ball", "tau": tau, "name": name,
                         "seed_hex": seed.hex(), "out": sample_in_ball(seed, tau)})
    for g1 in (G1_17, G1_19):
        for name, seed in [("gamma1 g1=%d: zero seed" % g1, b"\x00" * 66),
                           ("gamma1 g1=%d: seq seed" % g1, bytes(range(66)))]:
            vecs.append({"kind": "gamma1", "gamma1": g1, "name": name,
                         "seed_hex": seed.hex(), "out": sample_gamma1(seed, g1)})
    doc = {"primitive": "mldsa_sample",
           "source": "FIPS 204 / Dilithium rejection samplers (RejNTTPoly Alg 30, "
                     "RejBoundedPoly Alg 31, SampleInBall Alg 29) over python "
                     "hashlib SHAKE (independent of the C determ_shake); generated "
                     "by tools/verify_mldsa_sample.py",
           "vectors": vecs}
    with open(CORPUS, "w") as f:
        json.dump(doc, f, indent=1)
    print("emitted %d vectors -> %s" % (len(vecs), CORPUS))

def verify():
    with open(CORPUS) as f:
        doc = json.load(f)
    n = ok = 0
    for v in doc["vectors"]:
        n += 1
        seed = bytes.fromhex(v["seed_hex"]); out = v["out"]
        if v["kind"] == "uniform":
            got = sample_uniform(seed)
            if len(out) != N or any(not (0 <= c < Q) for c in out):
                print("  bad: %s: out-of-range" % v["name"]); continue
            if got != out:
                print("  bad: %s: recompute != stored" % v["name"]); continue
            if sample_uniform_indep(seed) != out:
                print("  bad: %s: independent (int.from_bytes) read disagrees" % v["name"]); continue
        elif v["kind"] == "eta":
            eta = v["eta"]; got = sample_eta(seed, eta)
            if len(out) != N or any(not (-eta <= c <= eta) for c in out):
                print("  bad: %s: out-of-range" % v["name"]); continue
            if got != out:
                print("  bad: %s: recompute != stored" % v["name"]); continue
            if sample_eta_indep(seed, eta) != out:
                print("  bad: %s: independent spec-TABLE mapping disagrees (sign/value bug)" % v["name"]); continue
        elif v["kind"] == "in_ball":
            tau = v["tau"]; got = sample_in_ball(seed, tau)
            nz = [x for x in out if x]
            if len(nz) != tau or any(x not in (-1, 1) for x in nz) or sum(x*x for x in out) != tau:
                print("  bad: %s: not exactly tau +/-1" % v["name"]); continue
            if got != out:
                print("  bad: %s: recompute != stored" % v["name"]); continue
            if sample_in_ball_indep(seed, tau) != out:
                print("  bad: %s: independent sign-TABLE mapping disagrees" % v["name"]); continue
        elif v["kind"] == "gamma1":
            g1 = v["gamma1"]; got = sample_gamma1(seed, g1)
            if len(out) != N or any(not (-g1 < c <= g1) for c in out):
                print("  bad: %s: out-of-range (must be in (-g1, g1])" % v["name"]); continue
            if got != out:
                print("  bad: %s: recompute != stored" % v["name"]); continue
            if sample_gamma1_indep(seed, g1) != out:
                print("  bad: %s: independent bit-slice field read disagrees" % v["name"]); continue
        else:
            print("  bad: %s: unknown kind %r" % (v.get("name"), v["kind"])); continue
        ok += 1
    print("mldsa sample vectors: %d/%d OK" % (ok, n))
    return ok == n and n > 0

if __name__ == "__main__":
    if "--emit" in sys.argv or not os.path.exists(CORPUS):
        gen()
    sys.exit(0 if verify() else 1)
