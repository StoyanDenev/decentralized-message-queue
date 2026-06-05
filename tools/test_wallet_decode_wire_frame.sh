#!/usr/bin/env bash
# determ-wallet decode-wire-frame CLI test.
#
# Exercises the OFFLINE wire-frame decoder + bounds-validator. Given a
# captured inter-peer message body (the bytes inside the transport
# [u32 length BE] frame), the command reproduces the receive-side framing
# logic in src/net/peer.cpp::Peer::read_body byte-for-byte — NO daemon,
# socket, or chain state. It detects the envelope by first byte, names the
# MsgType, and applies the S-022 two-stage gate (16 MiB framing ceiling +
# per-type max_message_bytes cap).
#
# Wire constants under test (pinned to include/determ/net/messages.hpp +
# src/net/binary_codec.cpp):
#   * First byte '{' (0x7B) = legacy JSON envelope; msg_type from "type".
#   * First byte 0xB1       = binary envelope v1; 4-byte header
#                             [magic 0xB1][version 0x01][msg_type u8][reserved 0x00].
#   * Cap tiers: 16 MiB SNAPSHOT_RESPONSE(16)/CHAIN_RESPONSE(6);
#                4 MiB BLOCK(1)/BEACON_HEADER(12)/SHARD_TIP(13)/
#                CROSS_SHARD_RECEIPT_BUNDLE(14)/HEADERS_RESPONSE(18);
#                1 MiB everything else.
#
# This test builds the wire bytes independently in Python and asserts the
# wallet's classification (envelope, msg_type_name, per_type_cap, accepted)
# matches — correctness, not just shape. No cluster, no daemon, no network.
#
# Differentiation vs sibling commands:
#   * inspect-tx   — decodes a TRANSACTION's INNER fields from a tx JSON.
#   * receipt-key  — derives a composite state-root leaf-KEY hex.
#   * decode-wire-frame — classifies + bounds an on-wire MESSAGE envelope.
#
# Assertions (~24):
#   1.  Global help mentions decode-wire-frame.
#   2.  decode-wire-frame --help exits 0.
#   3.  Unknown CLI arg: exit 1.
#   4.  No input source: exit 1.
#   5.  Both --in and --in-file: exit 1.
#   6.  Invalid hex: exit 1.
#   7.  Empty hex: exit 1.
#   8.  Binary HELLO: envelope=binary, name=HELLO, cap=1MiB, accepted, exit 0.
#   9.  Binary TRANSACTION: name=TRANSACTION, cap=1MiB, accepted.
#  10.  Binary BLOCK: name=BLOCK, per_type_cap=4MiB, accepted.
#  11.  Binary SNAPSHOT_RESPONSE: name=SNAPSHOT_RESPONSE, cap=16MiB, accepted.
#  12.  Binary CHAIN_RESPONSE: cap=16MiB.
#  13.  Binary HEADERS_RESPONSE: cap=4MiB.
#  14.  JSON envelope: envelope=json, name=STATUS_RESPONSE, accepted, exit 0.
#  15.  JSON --in-file via stdin: parses identically.
#  16.  Unknown first byte: envelope=unknown, accepted=false, exit 2.
#  17.  Binary unknown MsgType (99): accepted=false, exit 2.
#  18.  Binary bad reserved byte: reserved_ok=false, accepted=false, exit 2.
#  19.  Binary truncated header (<4 bytes): accepted=false, exit 2.
#  20.  Binary unsupported version: accepted=false, exit 2.
#  21.  JSON missing "type" field: accepted=false, exit 2.
#  22.  --json shape has all expected keys.
#  23.  Text-mode msg_type_name == JSON-mode.
#  24.  Determinism — two runs give identical JSON.
#
# Run from repo root: bash tools/test_wallet_decode_wire_frame.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in:                $1"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

CAP_1M=$((1 * 1024 * 1024))
CAP_4M=$((4 * 1024 * 1024))
CAP_16M=$((16 * 1024 * 1024))

# ── Independently-built wire bodies (Python; mirrors binary_codec.cpp) ───
# Binary envelope header: [0xB1][0x01][msg_type][0x00] + payload.
bin_env() {  # bin_env <msg_type> <payload_hex>
  $PY -c "
import sys
mt = int('$1')
pl = '$2'
print('b101' + format(mt, '02x') + '00' + pl)
"
}

HELLO_BIN=$(bin_env 0 "")
TX_BIN=$(bin_env 2 "00000000")            # msg_type 2 = TRANSACTION
BLOCK_BIN=$(bin_env 1 "00000000")         # msg_type 1 = BLOCK (4 MiB)
SNAP_BIN=$(bin_env 16 "00000000")         # msg_type 16 = SNAPSHOT_RESPONSE
CHAIN_BIN=$(bin_env 6 "00000000")         # msg_type 6 = CHAIN_RESPONSE
HDRS_BIN=$(bin_env 18 "00000000")         # msg_type 18 = HEADERS_RESPONSE
UNKNOWN_TYPE_BIN=$(bin_env 99 "")         # discriminator out of table
BAD_RESERVED="b1010205"                   # reserved byte = 0x05 (must be 0)
TRUNC_BIN="b101"                          # only 2 header bytes
BAD_VER="b102020000"                      # version byte = 0x02 (only 0x01)

# JSON envelope: {"type":8,...} → STATUS_RESPONSE.
JSON_BODY=$($PY -c "print('{\"type\":8,\"payload\":{}}'.encode().hex())")
JSON_NOTYPE=$($PY -c "print('{\"payload\":{}}'.encode().hex())")
UNKNOWN_FIRST=$($PY -c "print('ff0102'.lower())")   # 0xFF first byte

field() {  # field <json> <key>
  echo "$1" | $PY -c "import json,sys; print(json.loads(sys.stdin.read()).get('$2',''))"
}

echo "=== 1. Global help mentions decode-wire-frame ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "decode-wire-frame" "help mentions decode-wire-frame"

echo
echo "=== 2. decode-wire-frame --help exits 0 ==="
set +e
"$WALLET" decode-wire-frame --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "decode-wire-frame --help exits 0"

echo
echo "=== 3. Unknown CLI arg: exit 1 ==="
set +e
"$WALLET" decode-wire-frame --bogus >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "unknown arg returns 1"

echo
echo "=== 4. No input source: exit 1 ==="
set +e
"$WALLET" decode-wire-frame >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "no input source returns 1"

echo
echo "=== 5. Both --in and --in-file: exit 1 ==="
set +e
"$WALLET" decode-wire-frame --in "$HELLO_BIN" --in-file - >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "both --in and --in-file returns 1"

echo
echo "=== 6. Invalid hex: exit 1 ==="
set +e
"$WALLET" decode-wire-frame --in "zzzz" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "invalid hex returns 1"

echo
echo "=== 7. Empty hex: exit 1 ==="
set +e
"$WALLET" decode-wire-frame --in "" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "empty hex returns 1"

echo
echo "=== 8. Binary HELLO: envelope=binary, name=HELLO, cap=1MiB, accepted ==="
set +e
J=$("$WALLET" decode-wire-frame --in "$HELLO_BIN" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "binary HELLO exits 0"
assert_eq "$(field "$J" envelope)"      "binary"   "binary HELLO: envelope=binary"
assert_eq "$(field "$J" msg_type_name)" "HELLO"    "binary HELLO: name=HELLO"
assert_eq "$(field "$J" per_type_cap)"  "$CAP_1M"  "binary HELLO: cap=1MiB"
assert_eq "$(field "$J" accepted)"      "True"     "binary HELLO: accepted"

echo
echo "=== 9. Binary TRANSACTION: name=TRANSACTION, cap=1MiB, accepted ==="
J=$("$WALLET" decode-wire-frame --in "$TX_BIN" --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" msg_type_name)" "TRANSACTION" "binary TX: name=TRANSACTION"
assert_eq "$(field "$J" per_type_cap)"  "$CAP_1M"     "binary TX: cap=1MiB"
assert_eq "$(field "$J" accepted)"      "True"        "binary TX: accepted"

echo
echo "=== 10. Binary BLOCK: name=BLOCK, per_type_cap=4MiB ==="
J=$("$WALLET" decode-wire-frame --in "$BLOCK_BIN" --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" msg_type_name)" "BLOCK"    "binary BLOCK: name=BLOCK"
assert_eq "$(field "$J" per_type_cap)"  "$CAP_4M"  "binary BLOCK: cap=4MiB"

echo
echo "=== 11. Binary SNAPSHOT_RESPONSE: cap=16MiB ==="
J=$("$WALLET" decode-wire-frame --in "$SNAP_BIN" --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" msg_type_name)" "SNAPSHOT_RESPONSE" "binary SNAP: name=SNAPSHOT_RESPONSE"
assert_eq "$(field "$J" per_type_cap)"  "$CAP_16M"          "binary SNAP: cap=16MiB"

echo
echo "=== 12. Binary CHAIN_RESPONSE: cap=16MiB ==="
J=$("$WALLET" decode-wire-frame --in "$CHAIN_BIN" --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" msg_type_name)" "CHAIN_RESPONSE" "binary CHAIN: name=CHAIN_RESPONSE"
assert_eq "$(field "$J" per_type_cap)"  "$CAP_16M"        "binary CHAIN: cap=16MiB"

echo
echo "=== 13. Binary HEADERS_RESPONSE: cap=4MiB ==="
J=$("$WALLET" decode-wire-frame --in "$HDRS_BIN" --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J" msg_type_name)" "HEADERS_RESPONSE" "binary HDRS: name=HEADERS_RESPONSE"
assert_eq "$(field "$J" per_type_cap)"  "$CAP_4M"          "binary HDRS: cap=4MiB"

echo
echo "=== 14. JSON envelope: name=STATUS_RESPONSE, accepted ==="
set +e
J=$("$WALLET" decode-wire-frame --in "$JSON_BODY" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "JSON envelope exits 0"
assert_eq "$(field "$J" envelope)"      "json"            "JSON: envelope=json"
assert_eq "$(field "$J" msg_type_name)" "STATUS_RESPONSE" "JSON: name=STATUS_RESPONSE"
assert_eq "$(field "$J" accepted)"      "True"            "JSON: accepted"

echo
echo "=== 15. JSON via --in-file stdin parses identically ==="
J2=$(printf '%s\n' "$JSON_BODY" | "$WALLET" decode-wire-frame --in-file - --json 2>&1 | tr -d '\r')
assert_eq "$(field "$J2" msg_type_name)" "STATUS_RESPONSE" "stdin JSON: name=STATUS_RESPONSE"

echo
echo "=== 16. Unknown first byte: accepted=false, exit 2 ==="
set +e
J=$("$WALLET" decode-wire-frame --in "$UNKNOWN_FIRST" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "unknown first byte exits 2"
assert_eq "$(field "$J" envelope)" "unknown" "unknown first byte: envelope=unknown"
assert_eq "$(field "$J" accepted)" "False"   "unknown first byte: not accepted"

echo
echo "=== 17. Binary unknown MsgType (99): accepted=false, exit 2 ==="
set +e
J=$("$WALLET" decode-wire-frame --in "$UNKNOWN_TYPE_BIN" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "binary unknown MsgType exits 2"
assert_eq "$(field "$J" msg_type_name)" "UNKNOWN" "unknown MsgType: name=UNKNOWN"
assert_eq "$(field "$J" accepted)"      "False"   "unknown MsgType: not accepted"

echo
echo "=== 18. Binary bad reserved byte: reserved_ok=false, exit 2 ==="
set +e
J=$("$WALLET" decode-wire-frame --in "$BAD_RESERVED" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "bad reserved byte exits 2"
assert_eq "$(field "$J" reserved_ok)" "False" "bad reserved: reserved_ok=false"
assert_eq "$(field "$J" accepted)"    "False" "bad reserved: not accepted"

echo
echo "=== 19. Binary truncated header (<4 bytes): exit 2 ==="
set +e
J=$("$WALLET" decode-wire-frame --in "$TRUNC_BIN" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "truncated header exits 2"
assert_eq "$(field "$J" accepted)" "False" "truncated header: not accepted"

echo
echo "=== 20. Binary unsupported version: exit 2 ==="
set +e
J=$("$WALLET" decode-wire-frame --in "$BAD_VER" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "unsupported version exits 2"
assert_eq "$(field "$J" accepted)" "False" "unsupported version: not accepted"

echo
echo "=== 21. JSON missing \"type\": exit 2 ==="
set +e
J=$("$WALLET" decode-wire-frame --in "$JSON_NOTYPE" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "2" "JSON missing type exits 2"
assert_eq "$(field "$J" accepted)" "False" "JSON missing type: not accepted"

echo
echo "=== 22. --json shape has all expected keys ==="
J=$("$WALLET" decode-wire-frame --in "$HELLO_BIN" --json 2>&1 | tr -d '\r')
PARSED_OK=$(echo "$J" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
keys = ('envelope','msg_type','msg_type_name','body_bytes','per_type_cap',
        'frame_ceiling','within_per_type_cap','within_frame_ceiling','accepted')
print('yes' if all(k in d for k in keys) else 'no')
" 2>/dev/null || echo "no")
assert_eq "$PARSED_OK" "yes" "--json has all expected keys"
assert_eq "$(field "$J" frame_ceiling)" "$CAP_16M" "--json frame_ceiling=16MiB"

echo
echo "=== 23. Text-mode msg_type_name == JSON-mode ==="
TEXT_NAME=$("$WALLET" decode-wire-frame --in "$BLOCK_BIN" 2>&1 \
  | tr -d '\r' | grep '^msg_type_name:' | awk '{print $2}')
assert_eq "$TEXT_NAME" "BLOCK" "text-mode msg_type_name == JSON-mode"

echo
echo "=== 24. Determinism (two runs identical) ==="
R1=$("$WALLET" decode-wire-frame --in "$SNAP_BIN" --json 2>&1 | tr -d '\r')
R2=$("$WALLET" decode-wire-frame --in "$SNAP_BIN" --json 2>&1 | tr -d '\r')
assert_eq "$R1" "$R2" "two invocations give identical JSON"

echo
echo "================================"
echo "Total: PASS=$pass_count FAIL=$fail_count"
echo "================================"

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
exit 0
