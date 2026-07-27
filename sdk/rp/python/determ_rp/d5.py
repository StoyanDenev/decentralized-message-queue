# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Determ Contributors
"""D.5 government random-selection — relying-party / citizen draw-CONSISTENCY SDK.

The Apache-2.0 client-side surface of D.5 (SPEC docs/proofs/D5-RANDOM-SELECTION-SPEC.md):
given ONE already-canonicalized triple — a single `ROSTER_ADD` envelope, its
`case-open`, and the published `result` — plus the committee-authenticated beacon
seed, INDEPENDENTLY re-derive the lowest-hash draw and refute a published result
that disagrees. It is the reusable extraction of the draw check the reference build
ships in `tools/verify_d5rp.py`; `import determ_rp.d5` and check a draw with no
daemon and no C toolchain. Dependency-free (stdlib `hashlib` only).

SCOPE / TRUST BOUNDARY (read before relying on a verdict — provable security, B3,
nothing aspirational). `verify_result` proves ONE thing: the published selection
equals `d5_draw(authenticated_seed, this ADD-roster, this case-open)`, with the
canonical-binary codec's fail-closed bounds. It does NOT, and structurally CANNOT
(it sees no chain, no block heights, and no committee signatures), establish the
rest of the SPEC's soundness chain. The CALLER is responsible for:
  * committee-authenticating the blocks the streams came from (light-client
    committee-sig proofs) and the seed (the S-042 successor binding);
  * the SPEC §9 height ordering `h_r <= h_o < H < h_s`;
  * folding the FULL roster ADD/REMOVE stream and freezing it to
    `roster_cutoff_height` (this SDK rejects a non-ADD op rather than silently
    treat a lone REMOVE as the eligible set);
  * first-open-wins across multiple `case-open`s;
  * stream COMPLETENESS (that no on-chain roster/case-open/result was hidden).
A citizen facing an UNTRUSTED daemon must therefore use `determ-light
verify-selection`, which performs ALL of the above; this SDK alone is a draw-
consistency check over a caller-canonicalized, caller-authenticated triple, NOT a
standalone trustless verifier. The BUSL-1.1 *producer* side lives in
`dapps/d5-random-selection/` and is NOT part of this Apache SDK.

Wire layouts (SPEC §3/§7):
    DAPP_CALL envelope   [u8 topic_len][topic][u32 LE ct_len][ct]   (ct_len is LITTLE-endian)
    roster    [u8 fmt=1][u8 type=1][u8 op][u16 count]{ [u16 id_len][id] }*count
    case-open [u8 1][u8 2][u16 cid_len][cid][u64 cutoff][u64 H][u32 N][u32 M][u8 algo]
    result    [u8 1][u8 3][u16 cid_len][cid][u64 H][u64 cutoff][seed:32][u8 algo]
              [u32 N][u32 M]{ [u16 id_len][id] }*(N+M)
(d5codec fields are big-endian; only the DAPP_CALL envelope's ct_len is LE.)
"""
import hashlib

ALGO_LOWEST_HASH = 1
_MSG_ROSTER, _MSG_CASE_OPEN, _MSG_RESULT = 1, 2, 3
ROSTER_ADD, ROSTER_REMOVE = 0, 1
# Fail-closed codec bounds — MUST match src/dapp/d5codec.c / include/determ/dapp/d5draw.h
# (D5_MAX_ROSTER / D5_MAX_FIELD). A decoder that omits them accepts oversized or
# empty-id rosters the canonical C codec rejects, diverging from determ-light.
D5_MAX_ROSTER = 16384   # max members per draw / selection
D5_MAX_FIELD  = 4096    # max length-prefixed field (domain / case_id / member-id)


class D5Error(Exception):
    """Any malformed stream / wire divergence — fail-closed, never a false SELECTED."""


def _sha(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


# ── the ratified D1 lowest-hash sortition (SPEC §4) ──────────────────────────
def d5_ctx(domain, case_id, draw_height, roster_cutoff_height, algo):
    return _sha(domain, case_id,
                draw_height.to_bytes(8, "big"),
                roster_cutoff_height.to_bytes(8, "big"),
                bytes([algo]))


def d5_draw(seed, domain, case_id, draw_height, roster_cutoff_height, algo,
            ids, n_primary, m_alternate):
    """The N+M members with the SMALLEST SHA256(seed || ctx || id), ascending key;
    tie-break on the id bytes. Order-independent, per-member stateless."""
    ctx = d5_ctx(domain, case_id, draw_height, roster_cutoff_height, algo)
    keyed = sorted(((_sha(seed, ctx, mid), mid) for mid in ids), key=lambda t: (t[0], t[1]))
    return [mid for (_k, mid) in keyed[:n_primary + m_alternate]]


# ── bounds-checked big-endian read cursor over the d5codec payload ───────────
class _Cur:
    def __init__(self, b):
        self.b = b
        self.o = 0

    def take(self, n):
        if self.o + n > len(self.b):
            raise D5Error("truncated payload")
        v = self.b[self.o:self.o + n]
        self.o += n
        return v

    def u8(self):  return self.take(1)[0]
    def u16(self): return int.from_bytes(self.take(2), "big")
    def u32(self): return int.from_bytes(self.take(4), "big")
    def u64(self): return int.from_bytes(self.take(8), "big")

    def lp(self):
        # Length-prefixed field with the canonical C codec's fail-closed bound:
        # every field (case_id / member-id / selected-id) is in [1, D5_MAX_FIELD].
        n = self.u16()
        if n == 0 or n > D5_MAX_FIELD:
            raise D5Error("length-prefixed field out of bounds [1, %d]: %d"
                          % (D5_MAX_FIELD, n))
        return self.take(n)

    def end(self):
        if self.o != len(self.b):
            raise D5Error("trailing bytes after payload")


def strip_dapp_call(envelope):
    """Parse the DAPP_CALL envelope → (topic:str, ciphertext:bytes). The ct_len is
    u32 LITTLE-endian (distinct from the big-endian d5codec internals)."""
    if len(envelope) < 1:
        raise D5Error("empty envelope")
    tl = envelope[0]
    if tl == 0 or 1 + tl + 4 > len(envelope):
        raise D5Error("bad topic_len")
    topic = envelope[1:1 + tl].decode("ascii")
    off = 1 + tl
    ct_len = int.from_bytes(envelope[off:off + 4], "little")
    off += 4
    if off + ct_len != len(envelope):
        raise D5Error("ct_len does not consume the remaining bytes")
    return topic, envelope[off:off + ct_len]


def decode_roster(ct):
    c = _Cur(ct)
    if c.u8() != 1:            raise D5Error("roster: bad fmt")
    if c.u8() != _MSG_ROSTER:  raise D5Error("roster: bad msg_type")
    op = c.u8()
    if op not in (ROSTER_ADD, ROSTER_REMOVE):
        raise D5Error("roster: bad op %d" % op)
    count = c.u16()
    if count == 0 or count > D5_MAX_ROSTER:
        raise D5Error("roster count out of bounds [1, %d]: %d" % (D5_MAX_ROSTER, count))
    ids = [c.lp() for _ in range(count)]
    c.end()
    return op, ids


def decode_case_open(ct):
    c = _Cur(ct)
    if c.u8() != 1:               raise D5Error("case-open: bad fmt")
    if c.u8() != _MSG_CASE_OPEN:  raise D5Error("case-open: bad msg_type")
    cid = c.lp()
    cutoff = c.u64(); H = c.u64(); n = c.u32(); m = c.u32(); algo = c.u8()
    c.end()
    return dict(case_id=cid, roster_cutoff_height=cutoff, draw_height=H,
                n_primary=n, m_alternate=m, draw_algo_version=algo)


def decode_result(ct):
    c = _Cur(ct)
    if c.u8() != 1:            raise D5Error("result: bad fmt")
    if c.u8() != _MSG_RESULT:  raise D5Error("result: bad msg_type")
    cid = c.lp()
    H = c.u64(); cutoff = c.u64(); seed = c.take(32); algo = c.u8()
    n = c.u32(); m = c.u32()
    # Overflow-safe count bound, mirroring d5codec.c d5_result_decode.
    if n > D5_MAX_ROSTER or m > D5_MAX_ROSTER - n:
        raise D5Error("result n/m out of bounds")
    total = n + m
    if total == 0 or total > D5_MAX_ROSTER:
        raise D5Error("result selection count out of bounds [1, %d]: %d"
                      % (D5_MAX_ROSTER, total))
    sel = [c.lp() for _ in range(total)]
    c.end()
    return dict(case_id=cid, draw_height=H, roster_cutoff_height=cutoff, seed=seed,
                draw_algo_version=algo, n_primary=n, m_alternate=m, selected=sel)


def verify_result(domain, roster_env, case_open_env, result_env, seed):
    """Verify a published D.5 selection from its three DAPP_CALL envelopes.

    `domain` is bytes-or-str (the D.5 DApp domain, part of the draw ctx).
    `seed` is REQUIRED: the 32-byte committee-authenticated beacon seed
    (`cumulative_rand[draw_height]`) the caller confirmed OUT OF BAND via the
    S-042 successor binding (e.g. `determ-light verify-rand`). The result
    payload ALSO carries a `seed` field, but it is an UNTRUSTED claim by the RP
    and is deliberately IGNORED here — a rigged authority controls that field,
    so a self-consistency check against it is not a verification. There is no
    seedless "verify" path by design: making the authenticated seed mandatory
    prevents mistaking self-consistency for a real refutation (provable
    security, doctrine B3 — nothing aspirational). Use `decode_result(...)['seed']`
    if you explicitly want the RP's *claimed* seed (e.g. to audit a producer's
    internal consistency), and pass it in knowingly.

    Returns a dict {ok, selected, roster_op, roster_size, case_id, draw_height}.
    Raises D5Error on any wire divergence or if the published result does NOT
    equal the independent canonical draw. Never a false-positive.
    """
    if isinstance(domain, str):
        domain = domain.encode()
    if seed is None or len(seed) != 32:
        raise D5Error("seed must be the 32-byte authenticated beacon seed "
                      "(no seedless verify — the result's own seed field is an "
                      "untrusted RP claim)")

    tr, roster_ct = strip_dapp_call(roster_env)
    tc, case_ct   = strip_dapp_call(case_open_env)
    ts, res_ct    = strip_dapp_call(result_env)
    if (tr, tc, ts) != ("roster", "case-open", "result"):
        raise D5Error("unexpected envelope topics: %r" % ((tr, tc, ts),))

    op, roster_ids = decode_roster(roster_ct)
    if op != ROSTER_ADD:
        raise D5Error("verify_result handles a single ROSTER_ADD envelope; a lone "
                      "REMOVE (or a multi-op roster) requires folding the full "
                      "stream to the cutoff — use determ-light verify-selection")
    # Dedup like the std::set the full C verifier materializes (a duplicated id
    # must not occupy two selection ranks). A published result built over a
    # duplicated roster then fails the count/rank compare below (fail-closed).
    seen = set(); uniq = []
    for mid in roster_ids:
        b = bytes(mid)
        if b not in seen:
            seen.add(b); uniq.append(mid)
    roster_ids = uniq
    co = decode_case_open(case_ct)
    rs = decode_result(res_ct)

    if co["case_id"] != rs["case_id"]:
        raise D5Error("case-open / result case_id mismatch")
    for k in ("draw_height", "roster_cutoff_height", "n_primary", "m_alternate",
              "draw_algo_version"):
        if co[k] != rs[k]:
            raise D5Error("case-open / result %s mismatch (%r vs %r)" % (k, co[k], rs[k]))
    if rs["draw_algo_version"] != ALGO_LOWEST_HASH:
        raise D5Error("unexpected draw_algo_version %d" % rs["draw_algo_version"])
    if len(rs["selected"]) != co["n_primary"] + co["m_alternate"]:
        raise D5Error("published selection count != N+M")

    canonical = d5_draw(seed, domain, co["case_id"], co["draw_height"],
                        co["roster_cutoff_height"], co["draw_algo_version"],
                        roster_ids, co["n_primary"], co["m_alternate"])
    if canonical != rs["selected"]:
        raise D5Error("published result != independent canonical draw")

    return dict(ok=True, selected=list(canonical), roster_op=op,
                roster_size=len(roster_ids),
                case_id=co["case_id"], draw_height=co["draw_height"])


def is_selected(member_id, verified):
    """Given a `verify_result` return, is `member_id` (bytes) in the selection?"""
    return member_id in verified["selected"]
