#!/usr/bin/env python3
"""D.5 lowest-hash sortition — independent from-scratch oracle (SPEC section 4).

The dual-oracle for `determ test-d5-draw`: an implementation of the ratified
D1 draw that shares NO code with the C (src/dapp/d5draw.c). --gen freezes
tools/vectors/d5_draw.json; the C recomputes every vector byte-for-byte and must
match. Dependency-free (hashlib only), so the citizen verifier is auditable by
anyone. See docs/proofs/D5-RANDOM-SELECTION-SPEC.md.

  ctx    = SHA256( domain || case_id || H_be64 || cutoff_be64 || algo )
  key(i) = SHA256( seed || ctx || id_i )
  select = the (N + M) members with the SMALLEST key, ascending; tie-break on
           the id bytes (lexicographic, shorter id first on a shared prefix).
"""
import hashlib
import json
import sys

ALGO_LOWEST_HASH = 1


def _sha(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def d5_ctx(domain, case_id, draw_height, roster_cutoff_height, algo):
    return _sha(domain, case_id,
                draw_height.to_bytes(8, "big"),
                roster_cutoff_height.to_bytes(8, "big"),
                bytes([algo]))


def d5_draw(seed, domain, case_id, draw_height, roster_cutoff_height, algo,
            ids, n_primary, m_alternate):
    """Return the selected member ids in selection order (primaries then alts)."""
    ctx = d5_ctx(domain, case_id, draw_height, roster_cutoff_height, algo)
    # (key, id) — Python bytes comparison is lexicographic-then-shorter-first,
    # which matches the C d5_less (memcmp, shorter id first on a shared prefix).
    keyed = sorted((( _sha(seed, ctx, mid), mid) for mid in ids),
                   key=lambda t: (t[0], t[1]))
    want = n_primary + m_alternate
    return [mid for (_k, mid) in keyed[:want]]


def _pseudonym(i):
    # Model the ratified D2 non-PII id form: SHA256(national_id || salt).
    return hashlib.sha256(("D5-MEMBER-%d" % i).encode()).digest()


def _vector(name, seed, domain, case_id, H, cutoff, ids, n, m):
    sel = d5_draw(seed, domain.encode(), case_id.encode(), H, cutoff,
                  ALGO_LOWEST_HASH, ids, n, m)
    return {
        "name": name,
        "seed_hex": seed.hex(),
        "domain": domain,
        "case_id": case_id,
        "draw_height": str(H),
        "roster_cutoff_height": str(cutoff),
        "draw_algo_version": ALGO_LOWEST_HASH,
        "n_primary": n,
        "m_alternate": m,
        "ids_hex": [x.hex() for x in ids],
        "expected_selected_ids_hex": [x.hex() for x in sel],
    }


def build_corpus():
    seed = bytes(range(32))                      # 00 01 .. 1f
    seed2 = bytes((0xff - i) for i in range(32))
    vecs = []
    vecs.append(_vector("basic-3of200-2alt", seed, "d5.court.example",
                        "CASE-2026-000123", 100000, 99000,
                        [_pseudonym(i) for i in range(200)], 3, 2))
    vecs.append(_vector("single-1of5", seed, "d5.court.example",
                        "CASE-2026-000124", 100050, 99000,
                        [_pseudonym(i) for i in range(5)], 1, 0))
    vecs.append(_vector("all-8-selected", seed2, "d5.jury.example",
                        "JURY-2026-7", 200000, 199000,
                        [_pseudonym(i) for i in range(8)], 5, 3))
    vecs.append(_vector("large-1000-7primary", seed, "d5.court.example",
                        "CASE-2026-BIG", 500000, 499000,
                        [_pseudonym(i) for i in range(1000)], 7, 0))
    # Variable-length, non-32-byte ids to exercise the tie-break / length path.
    strids = [("judge-%02d" % i).encode() for i in range(12)]
    vecs.append(_vector("strids-4of12", seed, "d5.court.strids",
                        "CASE-STR-1", 12345, 12000, strids, 4, 0))
    return {"algo": "lowest-hash-sortition-v1", "vectors": vecs}


def selftest():
    seed = bytes(range(32))
    ids = [_pseudonym(i) for i in range(50)]
    a = d5_draw(seed, b"dom", b"CASE-1", 1000, 900, ALGO_LOWEST_HASH, ids, 5, 2)
    # order-independence: reversing the roster yields the identical selected SET.
    b = d5_draw(seed, b"dom", b"CASE-1", 1000, 900, ALGO_LOWEST_HASH,
                list(reversed(ids)), 5, 2)
    assert set(a) == set(b), "order-independence broken"
    assert a == list(reversed(list(reversed(a)))), "sanity"
    # ctx-binding: a different case_id yields a different selection (w.h.p.).
    c = d5_draw(seed, b"dom", b"CASE-2", 1000, 900, ALGO_LOWEST_HASH, ids, 5, 2)
    assert a != c, "ctx (case_id) not bound into the draw"
    # height-binding.
    d = d5_draw(seed, b"dom", b"CASE-1", 1001, 900, ALGO_LOWEST_HASH, ids, 5, 2)
    assert a != d, "draw_height not bound into the draw"
    print("verify_d5_draw selftest: PASS")


def main(argv):
    if "--selftest" in argv:
        selftest()
        return 0
    out = "tools/vectors/d5_draw.json"
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
