#!/usr/bin/env python3
"""D.5 reference-RP producer gate — thin CLI over the Apache SDK `determ_rp.d5`.

The dual-oracle for the BUSL-1.1 `d5rp` producer (dapps/d5-random-selection):
given `d5rp emit`'s three DAPP_CALL streams, INDEPENDENTLY parse the chain
envelope, decode the d5codec payloads, and re-derive the lowest-hash draw — then
assert the RP's published `result` equals the independent canonical draw. The
verification logic now LIVES in the Apache-2.0 SDK (sdk/rp/python/determ_rp/d5.py,
SPEC §12 item 8): this tool is a thin caller that adds the `d5rp emit` output
format glue + the frozen-vector regression pin. It shares no code with the C
producer (d5rp.c) or its C selftest, so a producer bug present in BOTH the C
producer AND its C selftest — e.g. the envelope-endianness divergence a citizen
`collect_d5_streams` would reject — is caught here by a separate implementation.

Usage:
    d5rp emit | python3 tools/verify_d5rp.py --check -      # independent verify
    python3 tools/verify_d5rp.py --gen -                    # freeze the vector
    python3 tools/verify_d5rp.py --selftest
"""
import json
import os
import re
import sys

# The verification core lives in the Apache-2.0 RP SDK; this tool dogfoods it.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "sdk", "rp", "python"))
from determ_rp.d5 import (   # noqa: E402
    d5_draw, D5Error, strip_dapp_call, decode_roster, decode_case_open,
    decode_result, verify_result, ALGO_LOWEST_HASH,
)


def parse_emit(text):
    """Read `d5rp emit` output: a `# ... domain=X ...` header + three
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
        raise D5Error("emit output missing `domain=` header")
    for t in ("roster", "case-open", "result"):
        if t not in streams:
            raise D5Error("emit output missing the %r stream" % t)
    return domain, streams


def verify_emit(text):
    """INDEPENDENTLY verify a `d5rp emit` output via the SDK. Raises on divergence.

    This is a PRODUCER self-consistency audit (does the RP's published result
    match a draw over the RP's own declared seed + roster?), so it knowingly uses
    the seed the RP committed in the result payload — passed EXPLICITLY, since the
    SDK has no seedless verify. A real citizen instead passes the S-042-
    authenticated beacon seed, not this claimed one."""
    domain, streams = parse_emit(text)
    _, res_ct = strip_dapp_call(streams["result"])
    claimed_seed = decode_result(res_ct)["seed"]
    info = verify_result(domain, streams["roster"], streams["case-open"],
                         streams["result"], claimed_seed)
    return dict(domain=domain, roster_size=info["roster_size"],
                selected=len(info["selected"]),
                case_id=info["case_id"].decode("latin-1"))


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
    # the C), verify it round-trips through the SDK, and confirm a corrupted
    # result + a big-endian ct_len are REJECTED.
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

    info = verify_result(domain, roster, caseo, result, seed)
    assert info["ok"] and len(info["selected"]) == 5 and info["roster_size"] == 12, info

    # NEG: the SDK has no seedless verify — a missing/short seed is refused.
    try:
        verify_result(domain, roster, caseo, result, None)
    except D5Error:
        pass
    else:
        raise AssertionError("SDK accepted a seedless verify")

    # NEG: swap two published selected ids -> independent re-derivation mismatch.
    bad = sel[:]; bad[0], bad[1] = bad[1], bad[0]
    bad_result = env("result", enc_result(case_id, 100, 80, seed, ALGO_LOWEST_HASH, 3, 2, bad))
    try:
        verify_result(domain, roster, caseo, bad_result, seed)
    except D5Error:
        pass
    else:
        raise AssertionError("SDK accepted a corrupted result")

    # NEG: big-endian ct_len (wrong) -> envelope parse fails when ct >= 256.
    ct = enc_roster(ROSTER_ADD, ids)
    be = bytes([len(b"roster")]) + b"roster" + len(ct).to_bytes(4, "big") + ct
    try:
        strip_dapp_call(be)
        if len(ct) >= 256:
            raise AssertionError("SDK accepted a big-endian ct_len")
    except D5Error:
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
        except D5Error as e:
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
