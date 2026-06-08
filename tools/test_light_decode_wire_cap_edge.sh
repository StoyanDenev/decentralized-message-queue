#!/usr/bin/env bash
# determ-light decode-wire — S-022 PER-TYPE BODY-SIZE CAP boundary (OFFLINE).
#
# Pure offline test (no cluster, no daemon, no genesis, no network). Crafts
# raw binary wire envelopes BY HAND per the published A3 / S8 spec and drives
# the REAL `determ-light decode-wire` decoder against the S-022 per-message-
# type max_message_bytes cap — the fail-closed gate at light/main.cpp:5743
#   if (buf.size() > cap) throw WireMalformed(... "exceeds its S-022 cap" ...)
# where cap = wire_max_message_bytes(msg_type) (light/main.cpp:5510).
#
# WHY THIS EDGE IS UNCOVERED (non-duplication evidence):
#   * tools/test_light_decode_wire.sh exercises every OTHER decode-wire path
#     (bad magic/version/reserved, out-of-range type, HELLO, lp-json len
#     mismatch, invalid JSON, tx reserved/trailing, expect-type, short frame)
#     but NEVER crafts a frame that exceeds a per-type cap — its largest
#     artifact is a ~30-byte JSON. The cap branch is dead-untested there.
#   * tools/test_wallet_decode_wire_frame.sh is a DIFFERENT binary
#     (determ-wallet decode-wire-frame) and only REPORTS per_type_cap as a
#     field on tiny frames; it never sizes a frame over a cap to force
#     rejection.
#   * tools/test_wire_negotiation.sh checks the cap-TABLE arithmetic via
#     `determ test-wire-negotiation` (a daemon unit test) — it asserts the
#     tiers are ordered and reachable, but never drives the light binary
#     against an oversize frame on disk.
# So no test anywhere makes the light decoder REJECT an oversize frame.
#
# The S-022 cap is the load-bearing anti-flood property: the 16 MB framing
# ceiling is intentionally loose (snapshot/chain need it), and the tight
# per-type cap (1 MB consensus chatter / 4 MB block-class) is what actually
# bounds a flooder. A decoder that enforced only the 16 MB ceiling — or that
# applied the WRONG tier's cap — would silently accept a 3.9 MB STATUS_RESPONSE
# that the daemon's peer.cpp:90 would drop. This test pins the boundary:
#
# Assertions:
#   1. STATUS_RESPONSE (1 MB tier) at EXACTLY 1 MB total  → VALID,     exit 0.
#      (cap is inclusive: `buf.size() > cap` is strict-greater.)
#   2. STATUS_RESPONSE at 1 MB + 1                         → MALFORMED, exit 3,
#      detail mentions the S-022 cap.
#   3. TYPE-AWARENESS: a STATUS_RESPONSE sized to 1 MB + 4096 (well under the
#      4 MB BLOCK cap, well under the 16 MB framing ceiling) is STILL rejected
#      → MALFORMED, exit 3. This proves the gate uses the PER-TYPE cap, not
#      the global ceiling or a fatter tier's cap.
#   4. CONTROL: a BLOCK (4 MB tier) at that SAME 1 MB + 4096 size is VALID,
#      exit 0 — same byte count, different type, opposite verdict. This is the
#      type-awareness cross-check: only the discriminator byte differs.
#   5. --json verdict on the over-cap frame is exactly "MALFORMED".
#
# Run from repo root: bash tools/test_light_decode_wire_cap_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

PY=python
command -v python >/dev/null 2>&1 || PY=python3

TMP="build/test_light_decode_wire_cap_edge.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# craft_lp_json_sized <out> <msg_type> <total_bytes>
# Writes a binary envelope [0xB1][0x01][msg_type][0x00][u32 LE json_len][json]
# whose TOTAL on-disk size is exactly <total_bytes>, with a VALID JSON payload
# (so the only thing that can trip the decoder is the size gate, not a JSON
# parse error). json_len = total - 8 (4 header + 4 length prefix). The JSON is
# {"p":"AAAA...A"} padded to the exact byte count.
craft_lp_json_sized() {
  "$PY" - "$@" <<'EOF'
import struct, sys
out, mtype, total = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
json_len = total - 8
# overhead of '{"p":""}' is 8 chars; pad the value to reach json_len.
pad = json_len - 8
assert pad >= 0, "total too small for a valid JSON payload"
js = b'{"p":"' + (b'A' * pad) + b'"}'
assert len(js) == json_len, (len(js), json_len)
body = bytes([0xB1, 0x01, mtype, 0x00]) + struct.pack("<I", json_len) + js
assert len(body) == total, (len(body), total)
open(out, "wb").write(body)
EOF
}

run_decode() {  # run_decode <file> [extra args...]; sets RC + OUT globals
  set +e
  OUT=$("$DETERM_LIGHT" decode-wire --in "$1" "${@:2}" 2>&1)
  RC=$?
  set -e
}

CAP_1M=1048576          # 1 MB  — STATUS_RESPONSE / consensus-chatter tier
OVER_1M=1048577         # 1 MB + 1
MID=$((CAP_1M + 4096))  # 1 MB + 4096 — over the 1 MB cap, under the 4 MB cap
MSG_STATUS=8            # STATUS_RESPONSE → 1 MB cap
MSG_BLOCK=1             # BLOCK          → 4 MB cap

echo "=== 1. STATUS_RESPONSE at EXACTLY 1 MB total → VALID exit 0 (cap inclusive) ==="
craft_lp_json_sized "$TMP/at_cap.bin" "$MSG_STATUS" "$CAP_1M"
run_decode "$TMP/at_cap.bin"
if [ "$RC" = "0" ] && echo "$OUT" | head -1 | grep -q "VALID"; then
  assert "true" "STATUS_RESPONSE @ 1 MB (== cap) → VALID exit 0"
else
  echo "$OUT"; assert "false" "STATUS_RESPONSE @ 1 MB (== cap) → VALID exit 0 (rc=$RC)"
fi

echo
echo "=== 2. STATUS_RESPONSE at 1 MB + 1 → MALFORMED exit 3 (S-022 cap) ==="
craft_lp_json_sized "$TMP/over_cap.bin" "$MSG_STATUS" "$OVER_1M"
run_decode "$TMP/over_cap.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -q "MALFORMED" \
   && echo "$OUT" | grep -qi "cap"; then
  assert "true" "STATUS_RESPONSE @ 1 MB+1 → MALFORMED exit 3 with cap detail"
else
  echo "$OUT"; assert "false" "STATUS_RESPONSE @ 1 MB+1 → MALFORMED exit 3 (rc=$RC)"
fi

echo
echo "=== 3. TYPE-AWARE: STATUS_RESPONSE @ 1 MB+4096 (< 4 MB, < 16 MB) still MALFORMED ==="
# Proves the gate uses the PER-TYPE cap, not the 16 MB framing ceiling and not
# a fatter tier — this size would be VALID for a BLOCK but must be rejected
# for a STATUS_RESPONSE.
craft_lp_json_sized "$TMP/status_mid.bin" "$MSG_STATUS" "$MID"
run_decode "$TMP/status_mid.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -q "MALFORMED"; then
  assert "true" "STATUS_RESPONSE @ 1 MB+4096 → MALFORMED exit 3 (per-type cap)"
else
  echo "$OUT"; assert "false" "STATUS_RESPONSE @ 1 MB+4096 → MALFORMED exit 3 (rc=$RC)"
fi

echo
echo "=== 4. CONTROL: BLOCK @ the SAME 1 MB+4096 size → VALID exit 0 (4 MB tier) ==="
# Identical byte count, only the discriminator byte (offset 2) differs:
# 8 (STATUS_RESPONSE, 1 MB cap) → rejected; 1 (BLOCK, 4 MB cap) → accepted.
craft_lp_json_sized "$TMP/block_mid.bin" "$MSG_BLOCK" "$MID"
run_decode "$TMP/block_mid.bin"
if [ "$RC" = "0" ] && echo "$OUT" | head -1 | grep -q "VALID"; then
  assert "true" "BLOCK @ 1 MB+4096 → VALID exit 0 (same size, fatter tier)"
else
  echo "$OUT"; assert "false" "BLOCK @ 1 MB+4096 → VALID exit 0 (rc=$RC)"
fi

echo
echo "=== 5. --json verdict on the over-cap frame is exactly MALFORMED ==="
run_decode "$TMP/over_cap.bin" --json
VERDICT=$(echo "$OUT" | tail -1 | "$PY" -c "
import json,sys
try:
  d=json.loads(sys.stdin.read()); print(d.get('verdict','?'))
except Exception: print('ERR')
")
if [ "$VERDICT" = "MALFORMED" ]; then
  assert "true" "--json verdict=MALFORMED on over-cap frame"
else
  echo "$OUT"; assert "false" "--json verdict=MALFORMED (got $VERDICT)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_decode_wire_cap_edge"; exit 0
else
  echo "  FAIL: test_light_decode_wire_cap_edge"; exit 1
fi
