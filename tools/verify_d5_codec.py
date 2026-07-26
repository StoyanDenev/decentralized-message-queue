#!/usr/bin/env python3
"""D.5 canonical-binary payload codecs — independent from-scratch oracle.

The dual-oracle for `determ test-d5-codec`: an implementation of the SPEC
section 3/section 7 wire layouts that shares NO code with the C
(src/dapp/d5codec.c). --gen freezes tools/vectors/d5_codec.json (the encoded
bytes for known structs); the C decodes them to the same fields AND re-encodes
to the same bytes, byte-for-byte. Big-endian, length-prefixed, no JSON on the
wire (DECISION-LOG D2). Dependency-free (stdlib only).
"""
import json
import sys

FMT = 1
MSG_ROSTER, MSG_CASE_OPEN, MSG_RESULT = 1, 2, 3
ROSTER_ADD, ROSTER_REMOVE = 0, 1


def u8(v):  return bytes([v & 0xff])
def u16(v): return v.to_bytes(2, "big")
def u32(v): return v.to_bytes(4, "big")
def u64(v): return v.to_bytes(8, "big")
def lp(b):  return u16(len(b)) + b     # u16 length-prefixed bytes


def enc_roster(op, ids):
    out = u8(FMT) + u8(MSG_ROSTER) + u8(op) + u16(len(ids))
    for i in ids:
        out += lp(i)
    return out


def enc_case_open(case_id, roster_cutoff, draw_height, n, m, algo):
    return (u8(FMT) + u8(MSG_CASE_OPEN) + lp(case_id)
            + u64(roster_cutoff) + u64(draw_height) + u32(n) + u32(m) + u8(algo))


def enc_result(case_id, draw_height, roster_cutoff, seed, algo, n, m, sel):
    assert len(seed) == 32
    assert len(sel) == n + m
    out = (u8(FMT) + u8(MSG_RESULT) + lp(case_id) + u64(draw_height)
           + u64(roster_cutoff) + seed + u8(algo) + u32(n) + u32(m))
    for s in sel:
        out += lp(s)
    return out


def _mid(i):
    import hashlib
    return hashlib.sha256(("D5-MEMBER-%d" % i).encode()).digest()


def build_corpus():
    seed = bytes(range(32))
    vecs = []
    vecs.append({
        "name": "roster-add-3", "type": "roster", "op": ROSTER_ADD,
        "ids_hex": [_mid(i).hex() for i in range(3)],
        "encoded_hex": enc_roster(ROSTER_ADD, [_mid(i) for i in range(3)]).hex(),
    })
    vecs.append({
        "name": "roster-remove-strid", "type": "roster", "op": ROSTER_REMOVE,
        "ids_hex": [b"judge-07".hex()],
        "encoded_hex": enc_roster(ROSTER_REMOVE, [b"judge-07"]).hex(),
    })
    vecs.append({
        "name": "case-open-basic", "type": "case_open",
        "case_id": "CASE-2026-000123", "roster_cutoff_height": "99000",
        "draw_height": "100000", "n_primary": 3, "m_alternate": 2, "draw_algo_version": 1,
        "encoded_hex": enc_case_open(b"CASE-2026-000123", 99000, 100000, 3, 2, 1).hex(),
    })
    sel = [_mid(i) for i in (7, 2, 41, 13, 5)]
    vecs.append({
        "name": "result-3primary-2alt", "type": "result",
        "case_id": "CASE-2026-000123", "draw_height": "100000",
        "roster_cutoff_height": "99000", "seed_hex": seed.hex(), "draw_algo_version": 1,
        "n_primary": 3, "m_alternate": 2,
        "sel_ids_hex": [s.hex() for s in sel],
        "encoded_hex": enc_result(b"CASE-2026-000123", 100000, 99000, seed, 1, 3, 2, sel).hex(),
    })
    return {"format": "d5-canonical-binary-v1", "vectors": vecs}


def selftest():
    # round-trip parity: encode -> (bytes) is deterministic + stable.
    a = enc_case_open(b"C", 1, 2, 3, 4, 1)
    b = enc_case_open(b"C", 1, 2, 3, 4, 1)
    assert a == b
    # field ordering is load-bearing: cutoff before draw_height (SPEC §3).
    assert enc_case_open(b"C", 1, 2, 0, 0, 1) != enc_case_open(b"C", 2, 1, 0, 0, 1)
    print("verify_d5_codec selftest: PASS")


def main(argv):
    if "--selftest" in argv:
        selftest()
        return 0
    out = "tools/vectors/d5_codec.json"
    for i, a in enumerate(argv):
        if a == "--out" and i + 1 < len(argv):
            out = argv[i + 1]
    corpus = build_corpus()
    with open(out, "w", newline="\n") as f:
        json.dump(corpus, f, indent=2)
        f.write("\n")
    print("wrote %s (%d vectors)" % (out, len(corpus["vectors"])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
