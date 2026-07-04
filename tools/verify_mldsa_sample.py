#!/usr/bin/env python3
"""verify_mldsa_sample.py — module-local reproducibility gate + generator for
tools/vectors/mldsa_sample.json (the Determ C99 ML-DSA / Dilithium rejection
samplers, CRYPTO-C99-SPEC §3.18 increment 3).

Independent oracle: python's `hashlib.shake_128/256` — a SHAKE implementation
DISTINCT from the C `determ_shake` under test (and proven byte-equal to it +
OpenSSL in R62, `determ test-sha3-c99`). The sampler rejection rules layered on
top are the canonical FIPS 204 algorithms (Alg 29/30/31), each simple enough to
verify by inspection, so a stored vector is a genuine cross-implementation KAT:
the C side (determ_shake + rule) must reproduce the python side (hashlib + rule)
byte-for-byte, AND the structural invariants (coefficient bounds, exactly-tau
signed-ones) hold.

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
        elif v["kind"] == "eta":
            eta = v["eta"]; got = sample_eta(seed, eta)
            if len(out) != N or any(not (-eta <= c <= eta) for c in out):
                print("  bad: %s: out-of-range" % v["name"]); continue
            if got != out:
                print("  bad: %s: recompute != stored" % v["name"]); continue
        elif v["kind"] == "in_ball":
            tau = v["tau"]; got = sample_in_ball(seed, tau)
            nz = [x for x in out if x]
            if len(nz) != tau or any(x not in (-1, 1) for x in nz) or sum(x*x for x in out) != tau:
                print("  bad: %s: not exactly tau +/-1" % v["name"]); continue
            if got != out:
                print("  bad: %s: recompute != stored" % v["name"]); continue
        else:
            print("  bad: %s: unknown kind %r" % (v.get("name"), v["kind"])); continue
        ok += 1
    print("mldsa sample vectors: %d/%d OK" % (ok, n))
    return ok == n and n > 0

if __name__ == "__main__":
    if "--emit" in sys.argv or not os.path.exists(CORPUS):
        gen()
    sys.exit(0 if verify() else 1)
