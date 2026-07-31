#!/usr/bin/env bash
# determ-light decode-wire — OFFLINE binary wire-envelope decode + validate.
#
# Pure offline test (no cluster, no daemon, no genesis). Crafts raw binary
# wire artifacts BY HAND (independent of the daemon's codec) per the
# published A3 / S8 envelope spec in src/net/binary_codec.cpp, then exercises
# `determ-light decode-wire` against well-formed and deliberately-malformed
# frames. Because the test producer and the decoder are written from the
# SAME spec but in DIFFERENT languages/code, a passing run is a genuine
# cross-implementation conformance check on the binary envelope format.
#
# Envelope layout under test (offsets, the BODY after the transport u32 len):
#   0  magic   = 0xB1
#   1  version = 0x01
#   2  msg_type (u8)
#   3  reserved = 0x00
#   4+ payload — for non-TRANSACTION: [u32 LE json_len][json_bytes];
#                for TRANSACTION (msg_type 2): 4x256-bit frame + trailer.
#
# Verdict / exit contract:
#   VALID     → exit 0
#   MALFORMED → exit 3 (structural spec violation, fail-closed)
#   I/O/usage → exit 1
#
# Assertions:
#   1. Well-formed STATUS_RESPONSE (lp-json) frame → VALID, exit 0.
#   2. --json report carries verdict=VALID + correct msg_type_name.
#   3. Bad magic byte (0x7B — the DELETED legacy-JSON first byte; D2
#      binary-only wire) → MALFORMED, exit 3.
#   4. Wrong version (0x02) → MALFORMED, exit 3.
#   5. Non-zero reserved byte → MALFORMED, exit 3.
#   6. msg_type out of range (99) → MALFORMED, exit 3.
#   7. HELLO (msg_type 0): the D2 fixed binary HELLO frame → VALID with
#      decoded domain/port/role/shard_id/wire_version (this leg INVERTED
#      when D2 gave HELLO a binary frame — pre-D2 binary HELLO was
#      MALFORMED); truncated fields and trailing bytes → MALFORMED.
#   8. lp-json declared length != body length → MALFORMED, exit 3.
#   9. lp-json payload that is not valid JSON → MALFORMED, exit 3.
#  10. Well-formed TRANSACTION frame → VALID with decoded amount/fee/nonce.
#  11. TRANSACTION with non-zero amount-block reserved slot → MALFORMED.
#  12. TRANSACTION with stray bytes after sig/hash → MALFORMED via the
#      §3.21 pq_auth section rules (truncated header / empty section /
#      length mismatch); a WELL-FORMED [u32 len][bytes] pq_auth section →
#      VALID with pq_auth_len reported (D2-inc1 mirror).
#  13. --expect-type mismatch → MALFORMED, exit 3.
#  14. Missing --in → exit 1 (usage, not MALFORMED).
#  15. Frame shorter than the 4-byte header → MALFORMED, exit 3.
#
# Run from repo root: bash tools/test_light_decode_wire.sh
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

TMP="build/test_light_decode_wire.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

# craft_lp_json <out> <magic> <version> <msgtype> <reserved> <json> [<declared_len_override>]
# Writes a binary envelope with a length-prefixed JSON payload. When the
# override is empty the declared length matches the JSON exactly.
craft_lp_json() {
  "$PY" - "$@" <<'EOF'
import struct, sys
out, magic, ver, mtype, reserved, js = sys.argv[1:7]
override = sys.argv[7] if len(sys.argv) > 7 else ""
body = bytearray()
body += bytes([int(magic, 0), int(ver, 0), int(mtype, 0), int(reserved, 0)])
jb = js.encode("utf-8")
declared = int(override) if override != "" else len(jb)
body += struct.pack("<I", declared)
body += jb
open(out, "wb").write(bytes(body))
EOF
}

# craft_tx <out> <amount> <fee> <nonce> <reserved_slot> <txtype> <from> <to> <trailing_pad>
# Writes a TRANSACTION (msg_type 2) frame: 4x256-bit core + trailer. Uses a
# zero 32-byte payload slot (payload_len = 0). sig = 64 zero bytes, hash =
# 32 zero bytes. trailing_pad appends N stray bytes after hash (for the
# trailing-garbage rejection test).
craft_tx() {
  "$PY" - "$@" <<'EOF'
import struct, sys
(out, amount, fee, nonce, reserved_slot, txtype,
 frm, to, trailing_pad) = sys.argv[1:10]
body = bytearray()
body += bytes([0xB1, 0x01, 0x02, 0x00])       # envelope header
body += bytes(32)                             # sender slot (zeros)
body += struct.pack("<Q", int(amount))        # amount
body += struct.pack("<Q", int(fee))           # fee
body += struct.pack("<Q", int(nonce))         # nonce
body += struct.pack("<Q", int(reserved_slot)) # reserved (must be 0)
body += bytes(32)                             # recipient slot (zeros)
body += bytes(32)                             # payload slot (zeros)
body += bytes([int(txtype)])                  # type
body += struct.pack("<H", 0)                  # payload_len = 0
fb = frm.encode("utf-8"); tb = to.encode("utf-8")
body += bytes([len(fb)]) + fb                 # from
body += bytes([len(tb)]) + tb                 # to
body += bytes(64)                             # sig
body += bytes(32)                             # hash
body += bytes(int(trailing_pad))              # stray trailing bytes
open(out, "wb").write(bytes(body))
EOF
}

# craft_status_response <out> <height> <genesis_hex_or_empty> [<pad>]
# Writes the D2-inc6a fixed STATUS_RESPONSE frame:
#   [0xB1][0x01][8][0x00][height u64 LE][genesis_len u8][genesis]
# pad appends N stray trailing bytes (for the exact-consumption legs).
craft_status_response() {
  "$PY" - "$@" <<'EOF'
import struct, sys
out, height, genesis = sys.argv[1:4]
pad = int(sys.argv[4]) if len(sys.argv) > 4 else 0
body = bytearray([0xB1, 0x01, 0x08, 0x00])
body += struct.pack("<Q", int(height))
gb = genesis.encode("utf-8")
body += bytes([len(gb)]) + gb
body += bytes(pad)
open(out, "wb").write(bytes(body))
EOF
}

run_decode() {  # run_decode <file> [extra args...]; sets RC + OUT globals
  set +e
  OUT=$("$DETERM_LIGHT" decode-wire --in "$1" "${@:2}" 2>&1)
  RC=$?
  set -e
}

echo "=== 1. Well-formed STATUS_RESPONSE (D2-inc6a fixed frame) → VALID exit 0 ==="
craft_status_response "$TMP/status.bin" 42 "$(printf 'a%.0s' $(seq 1 64))"
run_decode "$TMP/status.bin"
if [ "$RC" = "0" ] && echo "$OUT" | head -1 | grep -q "VALID"; then
  assert "true" "STATUS_RESPONSE frame → VALID exit 0"
else
  echo "$OUT"; assert "false" "STATUS_RESPONSE frame → VALID exit 0 (rc=$RC)"
fi

echo
echo "=== 2. --json report has verdict=VALID + msg_type_name ==="
run_decode "$TMP/status.bin" --json
NAME=$(echo "$OUT" | tail -1 | "$PY" -c "
import json,sys
try:
  d=json.loads(sys.stdin.read())
  print(d.get('verdict','?')+'/'+d.get('msg_type_name','?'))
except Exception: print('ERR')
")
if [ "$NAME" = "VALID/STATUS_RESPONSE" ]; then
  assert "true" "--json verdict=VALID, msg_type_name=STATUS_RESPONSE"
else
  echo "$OUT"; assert "false" "--json verdict/name (got $NAME)"
fi

echo
echo "=== 2b. STATUS_RESPONSE frame: decoded fields + fail-closed arms ==="
FIELDS=$(echo "$OUT" | tail -1 | "$PY" -c "
import json,sys
try:
  d=json.loads(sys.stdin.read())
  print('%s/%s/%s' % (d.get('payload_kind'), d.get('height'), len(d.get('genesis',''))))
except Exception: print('ERR')
")
if [ "$FIELDS" = "req_frame/42/64" ]; then
  assert "true" "STATUS_RESPONSE: payload_kind=req_frame, height=42, genesis 64 chars"
else
  assert "false" "STATUS_RESPONSE decoded fields (got $FIELDS)"
fi
# EMPTY genesis (an empty chain) is LEGAL and must stay distinguishable from
# a 64-zero hash — the light mirror of the daemon's length-prefixed field.
craft_status_response "$TMP/status_empty.bin" 0 ""
run_decode "$TMP/status_empty.bin"
[ "$RC" = "0" ] && assert "true" "STATUS_RESPONSE with EMPTY genesis → VALID (empty chain)" \
                 || { echo "$OUT"; assert "false" "STATUS_RESPONSE empty genesis → VALID (rc=$RC)"; }
# A genesis length outside {0, 64} is rejected.
craft_status_response "$TMP/status_badlen.bin" 1 "abc"
run_decode "$TMP/status_badlen.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "genesis length"; then
  assert "true" "STATUS_RESPONSE genesis length not in {0,64} → MALFORMED exit 3"
else
  echo "$OUT"; assert "false" "STATUS_RESPONSE bad genesis length → exit 3 (rc=$RC)"
fi
# Trailing bytes after the frame → MALFORMED (exact consumption).
craft_status_response "$TMP/status_pad.bin" 1 "" 3
run_decode "$TMP/status_pad.bin"
[ "$RC" = "3" ] && assert "true" "STATUS_RESPONSE trailing bytes → MALFORMED exit 3" \
                 || { echo "$OUT"; assert "false" "STATUS_RESPONSE trailing bytes → exit 3 (rc=$RC)"; }

echo
echo "=== 3. Bad magic (0x7B legacy-JSON sentinel) → MALFORMED exit 3 ==="
craft_lp_json "$TMP/badmagic.bin" 0x7B 0x01 8 0x00 '{"x":1}'
run_decode "$TMP/badmagic.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -q "MALFORMED"; then
  assert "true" "bad magic → MALFORMED exit 3"
else
  echo "$OUT"; assert "false" "bad magic → MALFORMED exit 3 (rc=$RC)"
fi

echo
echo "=== 4. Wrong version (0x02) → MALFORMED exit 3 ==="
craft_lp_json "$TMP/badver.bin" 0xB1 0x02 8 0x00 '{"x":1}'
run_decode "$TMP/badver.bin"
[ "$RC" = "3" ] && assert "true" "wrong version → exit 3" \
                 || { echo "$OUT"; assert "false" "wrong version → exit 3 (rc=$RC)"; }

echo
echo "=== 5. Non-zero reserved byte → MALFORMED exit 3 ==="
craft_lp_json "$TMP/badres.bin" 0xB1 0x01 8 0x07 '{"x":1}'
run_decode "$TMP/badres.bin"
[ "$RC" = "3" ] && assert "true" "non-zero reserved → exit 3" \
                 || { echo "$OUT"; assert "false" "non-zero reserved → exit 3 (rc=$RC)"; }

echo
echo "=== 6. msg_type out of range (99) → MALFORMED exit 3 ==="
craft_lp_json "$TMP/badtype.bin" 0xB1 0x01 99 0x00 '{"x":1}'
run_decode "$TMP/badtype.bin"
[ "$RC" = "3" ] && assert "true" "msg_type 99 → exit 3" \
                 || { echo "$OUT"; assert "false" "msg_type 99 → exit 3 (rc=$RC)"; }

echo
echo "=== 7. HELLO (msg_type 0): D2 fixed binary frame → VALID exit 0 ==="
# craft_hello <out> <domain> <port> <role> <shard_id> <wire_version> <pad>
# Writes the D2 binary HELLO frame: [u8 dlen][domain][u16 LE port][u8 role]
# [u32 LE shard_id][u8 wire_version]. pad appends N stray trailing bytes.
craft_hello() {
  "$PY" - "$@" <<'EOF'
import struct, sys
out, domain, port, role, shard, wv, pad = sys.argv[1:8]
body = bytearray()
body += bytes([0xB1, 0x01, 0x00, 0x00])       # envelope header, HELLO
db = domain.encode("utf-8")
body += bytes([len(db)]) + db
body += struct.pack("<H", int(port))
body += bytes([int(role)])
body += struct.pack("<I", int(shard))
body += bytes([int(wv)])
body += bytes(int(pad))
open(out, "wb").write(bytes(body))
EOF
}
craft_hello "$TMP/hello.bin" "node-a.example" 17777 2 3 1 0
run_decode "$TMP/hello.bin" --json
HELLO_FIELDS=$(echo "$OUT" | tail -1 | "$PY" -c "
import json,sys
try:
  d=json.loads(sys.stdin.read())
  print('%s/%s/%s/%s/%s/%s' % (d.get('verdict'), d.get('domain'),
        d.get('port'), d.get('role'), d.get('shard_id'),
        d.get('wire_version')))
except Exception: print('ERR')
")
if [ "$HELLO_FIELDS" = "VALID/node-a.example/17777/2/3/1" ]; then
  assert "true" "binary HELLO frame → VALID with decoded fields (D2 flip: pre-D2 this was MALFORMED)"
else
  echo "$OUT"; assert "false" "binary HELLO frame decode (got $HELLO_FIELDS)"
fi
# 7b. Truncated HELLO (missing wire_version byte) → MALFORMED.
craft_hello "$TMP/hello_tr.bin" "x" 1 0 0 1 0
"$PY" -c "
d=open('$TMP/hello_tr.bin','rb').read()
open('$TMP/hello_tr.bin','wb').write(d[:-1])
"
run_decode "$TMP/hello_tr.bin"
[ "$RC" = "3" ] && assert "true" "truncated HELLO frame → MALFORMED exit 3" \
                 || { echo "$OUT"; assert "false" "truncated HELLO → exit 3 (rc=$RC)"; }
# 7c. Trailing byte after wire_version → MALFORMED (fail-closed; additive
#     fields must arrive behind a bumped wire_version, never as padding).
craft_hello "$TMP/hello_pad.bin" "x" 1 0 0 1 1
run_decode "$TMP/hello_pad.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "trailing"; then
  assert "true" "HELLO trailing byte → MALFORMED exit 3"
else
  echo "$OUT"; assert "false" "HELLO trailing byte → exit 3 (rc=$RC)"
fi

echo
echo "=== 8. lp-json declared length != body → MALFORMED exit 3 ==="
# Carried by CONTRIB (4) — a type that still uses the length-prefixed JSON
# payload after D2-inc6a moved the request/status types to fixed frames.
# JSON is 7 bytes; declare 99.
craft_lp_json "$TMP/lenmis.bin" 0xB1 0x01 4 0x00 '{"x":1}' 99
run_decode "$TMP/lenmis.bin"
[ "$RC" = "3" ] && assert "true" "json_len mismatch → exit 3" \
                 || { echo "$OUT"; assert "false" "json_len mismatch → exit 3 (rc=$RC)"; }

echo
echo "=== 9. lp-json payload not valid JSON → MALFORMED exit 3 ==="
craft_lp_json "$TMP/notjson.bin" 0xB1 0x01 4 0x00 'not-json-at-all'
run_decode "$TMP/notjson.bin"
[ "$RC" = "3" ] && assert "true" "invalid JSON payload → exit 3" \
                 || { echo "$OUT"; assert "false" "invalid JSON payload → exit 3 (rc=$RC)"; }

echo
echo "=== 10. Well-formed TRANSACTION → VALID with decoded scalars ==="
craft_tx "$TMP/tx.bin" 500 3 7 0 0 alice bob 0
run_decode "$TMP/tx.bin" --json
SCALARS=$(echo "$OUT" | tail -1 | "$PY" -c "
import json,sys
try:
  d=json.loads(sys.stdin.read())
  print('%s/%s/%s/%s/%s' % (d.get('verdict'), d.get('amount'),
        d.get('fee'), d.get('nonce'), d.get('msg_type_name')))
except Exception: print('ERR')
")
if [ "$SCALARS" = "VALID/500/3/7/TRANSACTION" ]; then
  assert "true" "TRANSACTION decoded amount=500 fee=3 nonce=7"
else
  echo "$OUT"; assert "false" "TRANSACTION decode (got $SCALARS)"
fi

echo
echo "=== 11. TRANSACTION reserved amount-block slot non-zero → MALFORMED ==="
craft_tx "$TMP/txres.bin" 500 3 7 1 0 alice bob 0
run_decode "$TMP/txres.bin"
[ "$RC" = "3" ] && assert "true" "tx reserved slot → exit 3" \
                 || { echo "$OUT"; assert "false" "tx reserved slot → exit 3 (rc=$RC)"; }

echo
echo "=== 12. TRANSACTION stray bytes after sig/hash → pq_auth rules ==="
# D2-inc1: bytes after the hash must form a well-formed [u32 LE len][bytes]
# pq_auth section consuming the frame exactly. Stray pads now hit the
# section's fail-closed arms instead of a generic trailing-byte reject.
# 12a. 3 pad bytes: too short for the section header.
craft_tx "$TMP/txpad3.bin" 500 3 7 0 0 alice bob 3
run_decode "$TMP/txpad3.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "pq_auth"; then
  assert "true" "3 stray bytes → MALFORMED (truncated pq_auth section header)"
else
  echo "$OUT"; assert "false" "3 stray bytes → pq_auth reject (rc=$RC)"
fi
# 12b. 4 zero bytes: a zero-length section is non-canonical.
craft_tx "$TMP/txpad4.bin" 500 3 7 0 0 alice bob 4
run_decode "$TMP/txpad4.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "empty pq_auth"; then
  assert "true" "zero-length pq_auth section → MALFORMED (non-canonical)"
else
  echo "$OUT"; assert "false" "zero-length pq_auth → reject (rc=$RC)"
fi
# 12c. A WELL-FORMED pq_auth section → VALID with pq_auth_len reported.
craft_tx "$TMP/txpq.bin" 500 3 7 0 11 pqbearer bob 0
"$PY" -c "
import struct
d = bytearray(open('$TMP/txpq.bin','rb').read())
sec = bytes(range(1, 41))                     # 40-byte pq_auth stand-in
d += struct.pack('<I', len(sec)) + sec
open('$TMP/txpq.bin','wb').write(bytes(d))
"
run_decode "$TMP/txpq.bin" --json
PQ=$(echo "$OUT" | tail -1 | "$PY" -c "
import json,sys
try:
  d=json.loads(sys.stdin.read())
  print('%s/%s' % (d.get('verdict'), d.get('pq_auth_len')))
except Exception: print('ERR')
")
if [ "$PQ" = "VALID/40" ]; then
  assert "true" "well-formed pq_auth section → VALID, pq_auth_len=40 (D2-inc1 mirror)"
else
  echo "$OUT"; assert "false" "pq_auth section decode (got $PQ)"
fi
# 12d. Declared pq_auth length short of the remainder → MALFORMED.
craft_tx "$TMP/txpqbad.bin" 500 3 7 0 11 pqbearer bob 0
"$PY" -c "
import struct
d = bytearray(open('$TMP/txpqbad.bin','rb').read())
d += struct.pack('<I', 9) + bytes(5)          # declare 9, supply 5
open('$TMP/txpqbad.bin','wb').write(bytes(d))
"
run_decode "$TMP/txpqbad.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "pq_auth length mismatch"; then
  assert "true" "pq_auth length mismatch → MALFORMED exit 3"
else
  echo "$OUT"; assert "false" "pq_auth length mismatch → exit 3 (rc=$RC)"
fi

echo
echo "=== 13. --expect-type mismatch → MALFORMED exit 3 ==="
run_decode "$TMP/status.bin" --expect-type BLOCK
[ "$RC" = "3" ] && assert "true" "expect-type mismatch → exit 3" \
                 || { echo "$OUT"; assert "false" "expect-type mismatch → exit 3 (rc=$RC)"; }
# ...and a matching --expect-type still passes.
run_decode "$TMP/status.bin" --expect-type status_response
[ "$RC" = "0" ] && assert "true" "expect-type match (case-insensitive) → exit 0" \
                 || { echo "$OUT"; assert "false" "expect-type match → exit 0 (rc=$RC)"; }

echo
echo "=== 14. Missing --in → usage error exit 1 (not MALFORMED) ==="
set +e
"$DETERM_LIGHT" decode-wire --json >/dev/null 2>&1
RC=$?
set -e
[ "$RC" = "1" ] && assert "true" "missing --in → exit 1" \
                 || assert "false" "missing --in → exit 1 (got $RC)"

echo
echo "=== 15. Frame shorter than 4-byte header → MALFORMED exit 3 ==="
"$PY" -c "open('$TMP/short.bin','wb').write(bytes([0xB1,0x01]))"
run_decode "$TMP/short.bin"
[ "$RC" = "3" ] && assert "true" "2-byte frame → MALFORMED exit 3" \
                 || { echo "$OUT"; assert "false" "2-byte frame → exit 3 (rc=$RC)"; }

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_decode_wire"; exit 0
else
  echo "  FAIL: test_light_decode_wire"; exit 1
fi
