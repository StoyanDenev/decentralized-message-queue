#!/usr/bin/env python3
"""D.5 reference-RP producer — independent from-scratch oracle (SPEC §7/§12 inc.6a).

The dual-oracle for the BUSL-1.1 `d5rp` producer (dapps/d5-random-selection):
given `d5rp emit`'s three DAPP_CALL streams, this INDEPENDENTLY parses the chain
envelope, decodes the d5codec payloads, and RE-DERIVES the lowest-hash draw over
the published roster + seed — asserting it equals the published `result`. It
shares NO code with the C producer (d5rp.c) or its C selftest: the draw is the
already-frozen `verify_d5_draw.d5_draw` oracle, and the envelope / codec decoders
below are written from the SPEC wire layout, not the C. So a producer bug present
in BOTH the C producer AND its C selftest — e.g. a wrong `result`, or the exact
envelope-endianness divergence a citizen `collect_d5_streams` would reject — is
caught here by a separate implementation.

DAPP_CALL envelope (include/determ/chain/block.hpp:150-157) — note the ct_len is
u32 LITTLE-endian, DISTINCT from the big-endian d5codec internals:
    [u8 topic_len][topic ascii][u32 LE ct_len][ct]
d5codec payloads (SPEC §3, big-endian, length-prefixed):
    roster    [u8 fmt=1][u8 type=1][u8 op][u16 count]{ [u16 id_len][id] }*count
    case-open [u8 1][u8 2][u16 cid_len][cid][u64 cutoff][u64 H][u32 N][u32 M][u8 algo]
    result    [u8 1][u8 3][u16 cid_len][cid][u64 H][u64 cutoff][seed:32][u8 algo]
              [u32 N][u32 M]{ [u16 id_len][id] }*(N+M)

Dependency-free (stdlib only). Usage:
    d5rp emit | python3 tools/verify_d5rp.py --check -      # independent verify
    python3 tools/verify_d5rp.py --gen                      # freeze the vector
    python3 tools/verify_d5rp.py --selftest
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_d5_draw import d5_draw, ALGO_LOWEST_HASH   # the frozen draw oracle

MSG_ROSTER, MSG_CASE_OPEN, MSG_RESULT = 1, 2, 3


class WireError(Exception):
    pass


class Cur:
    """A bounds-checked big-endian read cursor over `buf`."""
    def __init__(self, buf):
        self.b = buf
        self.o = 0

    def take(self, n):
        if self.o + n > len(self.b):
            raise WireError("truncated payload")
        v = self.b[self.o:self.o + n]
        self.o += n
        return v

    def u8(self):  return self.take(1)[0]
    def u16(self): return int.from_bytes(self.take(2), "big")
    def u32(self): return int.from_bytes(self.take(4), "big")
    def u64(self): return int.from_bytes(self.take(8), "big")
    def lp(self):  return self.take(self.u16())   # u16-length-prefixed bytes

    def done(self):
        if self.o != len(self.b):
            raise WireError("trailing bytes after payload")


def strip_envelope(env):
    """Parse [u8 topic_len][topic][u32 LE ct_len][ct] -> (topic, ct)."""
    if len(env) < 1:
        raise WireError("empty envelope")
    tl = env[0]
    if tl == 0 or 1 + tl + 4 > len(env):
        raise WireError("bad topic_len")
    topic = env[1:1 + tl].decode("ascii")
    off = 1 + tl
    ct_len = int.from_bytes(env[off:off + 4], "little")   # u32 LE — the key detail
    off += 4
    if off + ct_len != len(env):
        raise WireError("ct_len does not consume the remaining bytes")
    return topic, env[off:off + ct_len]


def decode_roster(ct):
    c = Cur(ct)
    if c.u8() != 1:               raise WireError("roster: bad fmt")
    if c.u8() != MSG_ROSTER:      raise WireError("roster: bad msg_type")
    op = c.u8()
    count = c.u16()
    ids = [c.lp() for _ in range(count)]
    c.done()
    return op, ids


def decode_case_open(ct):
    c = Cur(ct)
    if c.u8() != 1:               raise WireError("case-open: bad fmt")
    if c.u8() != MSG_CASE_OPEN:   raise WireError("case-open: bad msg_type")
    cid = c.lp()
    cutoff = c.u64(); H = c.u64(); n = c.u32(); m = c.u32(); algo = c.u8()
    c.done()
    return dict(case_id=cid, roster_cutoff_height=cutoff, draw_height=H,
                n_primary=n, m_alternate=m, draw_algo_version=algo)


def decode_result(ct):
    c = Cur(ct)
    if c.u8() != 1:               raise WireError("result: bad fmt")
    if c.u8() != MSG_RESULT:      raise WireError("result: bad msg_type")
    cid = c.lp()
    H = c.u64(); cutoff = c.u64(); seed = c.take(32); algo = c.u8()
    n = c.u32(); m = c.u32()
    sel = [c.lp() for _ in range(n + m)]
    c.done()
    return dict(case_id=cid, draw_height=H, roster_cutoff_height=cutoff, seed=seed,
                draw_algo_version=algo, n_primary=n, m_alternate=m, selected=sel)


def parse_emit(text):
    """Read `d5rp emit` output: a `# ... domain=X case_id=Y ...` header + three
    `<topic> <hex>` lines. Returns (domain, {topic: envelope_bytes})."""
    domain = None
    streams = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            mo = re.search(r"domain=(\S+)", line)
            if mo:
                domain = mo.group(1)
            continue
        parts = line.split()
        if len(parts) == 2:
            streams[parts[0]] = bytes.fromhex(parts[1])
    if domain is None:
        raise WireError("emit output missing `domain=` header")
    for t in ("roster", "case-open", "result"):
        if t not in streams:
            raise WireError("emit output missing the %r stream" % t)
    return domain, streams


def verify_emit(text):
    """INDEPENDENTLY verify a `d5rp emit` output. Raises on any divergence."""
    domain, streams = parse_emit(text)

    tr, roster_ct = strip_envelope(streams["roster"])
    tc, case_ct   = strip_envelope(streams["case-open"])
    ts, res_ct    = strip_envelope(streams["result"])
    if (tr, tc, ts) != ("roster", "case-open", "result"):
        raise WireError("unexpected envelope topics: %r" % ((tr, tc, ts),))

    op, roster_ids = decode_roster(roster_ct)
    co = decode_case_open(case_ct)
    rs = decode_result(res_ct)

    # Cross-field consistency between case-open and result.
    if co["case_id"] != rs["case_id"]:
        raise WireError("case-open / result case_id mismatch")
    for k in ("draw_height", "roster_cutoff_height", "n_primary", "m_alternate",
              "draw_algo_version"):
        if co[k] != rs[k]:
            raise WireError("case-open / result %s mismatch (%r vs %r)"
                            % (k, co[k], rs[k]))
    if rs["draw_algo_version"] != ALGO_LOWEST_HASH:
        raise WireError("unexpected draw_algo_version %d" % rs["draw_algo_version"])
    if len(rs["selected"]) != co["n_primary"] + co["m_alternate"]:
        raise WireError("published selection count != N+M")

    # THE independent check: re-derive the lowest-hash draw over the published
    # roster + seed under the published params, and require it to EQUAL the
    # published result (ordered). Separate implementation from the C producer.
    canonical = d5_draw(rs["seed"], domain.encode(), co["case_id"],
                        co["draw_height"], co["roster_cutoff_height"],
                        co["draw_algo_version"], roster_ids,
                        co["n_primary"], co["m_alternate"])
    if canonical != rs["selected"]:
        raise WireError("published result != independent canonical draw "
                        "(%d vs %d selected; first mismatch)"
                        % (len(rs["selected"]), len(canonical)))
    return dict(domain=domain, roster_op=op, roster_size=len(roster_ids),
                case_id=co["case_id"].decode("latin-1"),
                selected=len(canonical))


# ── frozen-vector (regression pin) ──────────────────────────────────────────
def gen_vector(emit_text):
    domain, streams = parse_emit(emit_text)
    return {
        "format": "d5rp-dapp-call-streams-v1",
        "domain": domain,
        "roster_hex": streams["roster"].hex(),
        "case-open_hex": streams["case-open"].hex(),
        "result_hex": streams["result"].hex(),
    }


def _read(path):
    if path == "-":
        return sys.stdin.read()
    with open(path, "r") as f:
        return f.read()


def selftest():
    # Build a minimal emit-shaped input from the codec encoders (independent of
    # the C), verify it round-trips through the oracle, and confirm a corrupted
    # result is REJECTED.
    from verify_d5_codec import enc_roster, enc_case_open, enc_result, ROSTER_ADD

    def env(topic, ct):
        tb = topic.encode()
        return bytes([len(tb)]) + tb + len(ct).to_bytes(4, "little") + ct

    seed = bytes(range(32))
    domain = "d5.court"
    case_id = b"CASE-1"
    ids = [("D5-MEMBER-%d" % i).encode() for i in range(12)]
    sel = d5_draw(seed, domain.encode(), case_id, 100, 80, ALGO_LOWEST_HASH, ids, 3, 2)

    roster = env("roster", enc_roster(ROSTER_ADD, ids))
    caseo  = env("case-open", enc_case_open(case_id, 80, 100, 3, 2, ALGO_LOWEST_HASH))
    result = env("result", enc_result(case_id, 100, 80, seed, ALGO_LOWEST_HASH, 3, 2, sel))
    text = ("# domain=%s case_id=CASE-1\nroster %s\ncase-open %s\nresult %s\n"
            % (domain, roster.hex(), caseo.hex(), result.hex()))

    info = verify_emit(text)
    assert info["selected"] == 5 and info["roster_size"] == 12, info

    # NEG: swap two published selected ids -> independent re-derivation mismatch.
    bad_sel = sel[:]
    bad_sel[0], bad_sel[1] = bad_sel[1], bad_sel[0]
    bad_result = env("result", enc_result(case_id, 100, 80, seed, ALGO_LOWEST_HASH,
                                          3, 2, bad_sel))
    bad_text = ("# domain=%s case_id=CASE-1\nroster %s\ncase-open %s\nresult %s\n"
                % (domain, roster.hex(), caseo.hex(), bad_result.hex()))
    try:
        verify_emit(bad_text)
    except WireError:
        pass
    else:
        raise AssertionError("oracle accepted a corrupted result")

    # NEG: big-endian ct_len (wrong) -> envelope parse fails.
    tb = b"roster"
    ct = enc_roster(ROSTER_ADD, ids)
    be = bytes([len(tb)]) + tb + len(ct).to_bytes(4, "big") + ct
    try:
        strip_envelope(be)
        # a big-endian length only parses clean if it happens to equal the LE one
        # (len < 256), so also assert it would misframe a >255 ct:
        if len(ct) >= 256:
            raise AssertionError("oracle accepted a big-endian ct_len")
    except WireError:
        pass
    print("verify_d5rp selftest: PASS")


def main(argv):
    if "--selftest" in argv:
        selftest()
        return 0
    if "--check" in argv:
        i = argv.index("--check")
        path = argv[i + 1] if i + 1 < len(argv) else "-"
        try:
            info = verify_emit(_read(path))
        except WireError as e:
            print("verify_d5rp: FAIL — %s" % e)
            return 1
        print("verify_d5rp: PASS — domain=%s roster=%d selected=%d"
              % (info["domain"], info["roster_size"], info["selected"]))
        return 0
    if "--gen" in argv:
        i = argv.index("--gen")
        emit_path = argv[i + 1] if i + 1 < len(argv) else "-"
        out = "tools/vectors/d5rp.json"
        for j, a in enumerate(argv):
            if a == "--out" and j + 1 < len(argv):
                out = argv[j + 1]
        vec = gen_vector(_read(emit_path))
        with open(out, "w", newline="\n") as f:
            json.dump(vec, f, indent=2)
            f.write("\n")
        print("wrote %s" % out)
        return 0
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
