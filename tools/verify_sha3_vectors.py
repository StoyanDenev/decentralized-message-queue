#!/usr/bin/env python3
"""verify_sha3_vectors.py — self-check + reproducibility gate for the FIPS 202
SHA-3 / SHAKE KAT corpus at tools/vectors/sha3_shake.json.

Every stored digest is REGENERATED from scratch with python's hashlib
(sha3_256 / sha3_512 / shake_128 / shake_256 — the independent oracle that
cross-generated the corpus) and asserted byte-equal to the stored
digest_hex. Any drifted / hand-edited / fabricated byte turns this RED, so a
corrupted vector can never sit silently in the corpus that the C99
`determ test-sha3-c99` subcommand consumes.

The corpus is thus self-checking (it recomputes its own answers) and
reproducible (re-running this reproduces every hex from the message alone).

Needs no determ binary, no third-party package — stdlib hashlib only.
Run from anywhere:  python tools/verify_sha3_vectors.py
Prints "sha3 vectors: N/N OK" and exits 0 on full success; otherwise prints
each mismatch and exits 1.
"""
import hashlib
import json
import os
import sys

# FIPS 202 sponge rate (bytes) per algorithm — documented here so the corpus's
# rate-boundary intent (inputs of length rate-1 / rate / rate+1) is auditable.
RATE = {"SHA3-256": 136, "SHA3-512": 72, "SHAKE128": 168, "SHAKE256": 136}

CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "vectors", "sha3_shake.json")


def oracle(alg, msg, outlen):
    """Independent recomputation via hashlib. Fixed-length hashes ignore
    outlen; XOFs require it."""
    if alg == "SHA3-256":
        return hashlib.sha3_256(msg).hexdigest()
    if alg == "SHA3-512":
        return hashlib.sha3_512(msg).hexdigest()
    if alg == "SHAKE128":
        return hashlib.shake_128(msg).hexdigest(outlen)
    if alg == "SHAKE256":
        return hashlib.shake_256(msg).hexdigest(outlen)
    raise ValueError("unknown alg %r" % (alg,))


def main():
    with open(CORPUS, "r", encoding="utf-8") as f:
        doc = json.load(f)

    vectors = doc.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        print("bad: corpus has no vectors")
        return 1

    mismatches = []
    total = len(vectors)

    for i, v in enumerate(vectors):
        tag = v.get("name", "#%d" % i)
        try:
            alg = v["alg"]
            if alg not in RATE:
                mismatches.append("[%s] unknown alg %r" % (tag, alg))
                continue

            # strict hex decode — odd-length / non-hex raises here
            msg = bytes.fromhex(v["msg_hex"])

            is_xof = alg in ("SHAKE128", "SHAKE256")
            outlen = v.get("outlen")
            if is_xof:
                if not isinstance(outlen, int) or outlen < 0:
                    mismatches.append("[%s] SHAKE vector missing valid outlen"
                                      % tag)
                    continue
            else:
                if "outlen" in v:
                    mismatches.append("[%s] fixed-length alg %s must not carry "
                                      "outlen" % (tag, alg))
                    continue

            stored = v["digest_hex"]
            if not isinstance(stored, str):
                mismatches.append("[%s] digest_hex is not a string" % tag)
                continue
            # canonical lowercase hex; length must match the claimed output
            bytes.fromhex(stored)
            if is_xof and len(stored) != 2 * outlen:
                mismatches.append("[%s] digest_hex length %d != 2*outlen %d"
                                  % (tag, len(stored), 2 * outlen))
                continue

            got = oracle(alg, msg, outlen)
            if got != stored:
                mismatches.append("[%s] %s(msg=%dB%s):\n    stored %s\n    got    %s"
                                  % (tag, alg, len(msg),
                                     (", outlen=%d" % outlen) if is_xof else "",
                                     stored, got))
        except KeyError as e:
            mismatches.append("[%s] missing field %s" % (tag, e))
        except ValueError as e:
            mismatches.append("[%s] %s" % (tag, e))

    if mismatches:
        print("sha3 vectors: %d/%d OK — %d MISMATCH:"
              % (total - len(mismatches), total, len(mismatches)))
        for m in mismatches:
            print("  bad: " + m)
        return 1

    print("sha3 vectors: %d/%d OK" % (total, total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
