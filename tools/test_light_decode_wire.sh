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
#   4+ payload — per msg_type: the D2 fixed frames (HELLO, TRANSACTION, the
#                request/status set, the consensus-chatter set, and since
#                D2-inc7a/inc7b the five Block-carrying types + CONTRIB), or
#                [u32 LE json_len][json_bytes] for the two types still on the
#                lp-JSON path (SNAPSHOT_RESPONSE / HEADERS_RESPONSE).
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
#  16. D2-inc7a Block-carrying frames: the canonical binary Block container
#      (chain::Block::encode_frame) assembled HERE from the published section
#      order — 3 fixed fields, 23 u16 counts, the fixed tail — so an EMPTY
#      frame is exactly 297 bytes. That number is derived independently and
#      then checked against the mirror's report, which is a genuine
#      cross-implementation pin on the daemon's BF-0 constant. BLOCK and
#      BEACON_HEADER (incl. a folded block with records + a witness) → VALID;
#      trailing bytes and truncation → MALFORMED.
#  17. SHARD_TIP POISON-WITNESS: the mirror implements the same
#      allow_witnesses MAP the daemon does. A tip carrying a witness or folded
#      records → MALFORMED (only BEACON producers fold; a legitimate tip is a
#      LEAF, and a poisoned one would make the folded beacon block unparseable
#      fleet-wide). The SAME block inside CROSS_SHARD_RECEIPT_BUNDLE → VALID,
#      which is what proves it is a per-type map and not a blanket reject.
#      Without this leg the two implementations would disagree on frame
#      validity — the S-043 asymmetry class the reserved-byte audit found.
#  18. CHAIN_RESPONSE frame: has_more ∈ {0,1} (a bool has exactly two
#      canonical encodings), the block list, the EMPTY 'nothing more' reply,
#      a 65535 count-lie rejected before any allocation, trailing bytes.
#  19. D2-inc7b CONTRIB frame: the always-present layout decoded field by
#      field, plus trailing-byte / truncation / count-lie rejects.
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
# Carried by HEADERS_RESPONSE (18) — after D2-inc7a/inc7b only it and
# SNAPSHOT_RESPONSE still use the length-prefixed JSON payload (CONTRIB and
# the five Block-carrying types moved to true binary frames).
# JSON is 7 bytes; declare 99.
craft_lp_json "$TMP/lenmis.bin" 0xB1 0x01 18 0x00 '{"x":1}' 99
run_decode "$TMP/lenmis.bin"
[ "$RC" = "3" ] && assert "true" "json_len mismatch → exit 3" \
                 || { echo "$OUT"; assert "false" "json_len mismatch → exit 3 (rc=$RC)"; }

echo
echo "=== 9. lp-json payload not valid JSON → MALFORMED exit 3 ==="
craft_lp_json "$TMP/notjson.bin" 0xB1 0x01 18 0x00 'not-json-at-all'
run_decode "$TMP/notjson.bin"
[ "$RC" = "3" ] && assert "true" "invalid JSON payload → exit 3" \
                 || { echo "$OUT"; assert "false" "invalid JSON payload → exit 3 (rc=$RC)"; }
# ...and a WELL-FORMED lp-json payload on that same type still decodes, so
# the two rejects above cannot pass because the branch rejects everything.
craft_lp_json "$TMP/lpok.bin" 0xB1 0x01 18 0x00 '{"headers":[],"from":0,"count":0,"height":0}'
run_decode "$TMP/lpok.bin"
[ "$RC" = "0" ] && assert "true" "lp-json control: a well-formed HEADERS_RESPONSE payload → VALID" \
                 || { echo "$OUT"; assert "false" "lp-json control → exit 0 (rc=$RC)"; }

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
echo "=== 16. D2-inc7a Block-carrying payload frames (BLOCK / BEACON_HEADER) ==="
# craft_block_msg <out> <msgtype> <prefix_u32_or_empty> <witness:0|1>
#                 <records:0|1> <pad> [<index>]
# Writes an envelope carrying the canonical binary Block container
# (chain::Block::encode_frame). The frame is assembled HERE from the published
# section order — 3 fixed fields, 23 u16 counts, and the fixed tail — so an
# empty frame is exactly 297 bytes (independently derived; the daemon pins the
# same number as BF-0). `prefix` writes a u32 LE ahead of the frame (SHARD_TIP's
# shard_id / the bundle's src_shard).
craft_block_msg() {
  "$PY" - "$@" <<'EOF'
import struct, sys
out, mtype, prefix, witness, records, pad = sys.argv[1:7]
index = int(sys.argv[7]) if len(sys.argv) > 7 else 5

def block_frame(index, witness=False, records=False):
    b = bytearray()
    b += struct.pack("<Q", index)          # index
    b += bytes(32)                         # prev_hash
    b += struct.pack("<q", 1234)           # timestamp (i64 in a u64 slot)
    for _ in range(15):                    # transactions .. creator_dh_secrets
        b += struct.pack("<H", 0)
    b += bytes(32) * 3                     # tx_root/delay_seed/delay_output
    b += bytes([0])                        # consensus_mode
    b += bytes([0])                        # bft_proposer (empty lp string)
    b += struct.pack("<H", 0)              # creator_block_sigs
    b += bytes(32)                         # cumulative_rand
    for _ in range(5):                     # abort/equiv/receipts/initial_state
        b += struct.pack("<H", 0)
    b += bytes(32) * 2                     # state_root/partner_subset_hash
    b += bytes([0])                        # signature_form
    b += struct.pack("<I", 0)              # eligible_count
    b += struct.pack("<I", 0)              # source_shard_id
    if records:
        rec = struct.pack("<I", 1) + struct.pack("<Q", index - 1) \
            + struct.pack("<I", 3) + bytes(32) + bytes([2]) + b"eu"
        b += struct.pack("<H", 1) + bytes([len(rec)]) + rec
    else:
        b += struct.pack("<H", 0)          # shard_tip_records
    if witness:
        w = block_frame(index - 1)
        b += struct.pack("<H", 1) + struct.pack("<I", len(w)) + w
    else:
        b += struct.pack("<H", 0)          # shard_tip_witnesses
    return bytes(b)

body = bytearray([0xB1, 0x01, int(mtype), 0x00])
if prefix != "":
    body += struct.pack("<I", int(prefix))
body += block_frame(index, witness == "1", records == "1")
body += bytes(int(pad))
open(out, "wb").write(bytes(body))
EOF
}
craft_block_msg "$TMP/block.bin" 1 "" 0 0 0 7
run_decode "$TMP/block.bin" --json
BLK=$(echo "$OUT" | tail -1 | "$PY" -c "
import json,sys
try:
  d=json.loads(sys.stdin.read())
  print('%s/%s/%s/%s' % (d.get('verdict'), d.get('payload_kind'),
        d.get('block_index'), d.get('block_frame_len')))
except Exception: print('ERR')
")
if [ "$BLK" = "VALID/block_frame/7/297" ]; then
  assert "true" "BLOCK: the 297-byte empty Block frame → VALID (independently derived minimum matches the daemon's BF-0 pin)"
else
  echo "$OUT"; assert "false" "BLOCK frame decode (got $BLK)"
fi
craft_block_msg "$TMP/beacon.bin" 12 "" 1 1 0 7
run_decode "$TMP/beacon.bin" --json
BEA=$(echo "$OUT" | tail -1 | "$PY" -c "
import json,sys
try:
  d=json.loads(sys.stdin.read())
  print('%s/%s/%s' % (d.get('verdict'), d.get('block_shard_tip_records'),
        d.get('block_shard_tip_witnesses')))
except Exception: print('ERR')
")
if [ "$BEA" = "VALID/1/1" ]; then
  assert "true" "BEACON_HEADER: a FOLDED beacon block (records + one witness) → VALID"
else
  echo "$OUT"; assert "false" "BEACON_HEADER folded block (got $BEA)"
fi
craft_block_msg "$TMP/block_pad.bin" 1 "" 0 0 3 7
run_decode "$TMP/block_pad.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "trailing"; then
  assert "true" "BLOCK trailing bytes → MALFORMED exit 3 (exact consumption)"
else
  echo "$OUT"; assert "false" "BLOCK trailing bytes → exit 3 (rc=$RC)"
fi
craft_block_msg "$TMP/block_tr.bin" 1 "" 0 0 0 7
"$PY" -c "
d=open('$TMP/block_tr.bin','rb').read()
open('$TMP/block_tr.bin','wb').write(d[:-1])
"
run_decode "$TMP/block_tr.bin"
[ "$RC" = "3" ] && assert "true" "truncated BLOCK frame → MALFORMED exit 3" \
                 || { echo "$OUT"; assert "false" "truncated BLOCK → exit 3 (rc=$RC)"; }

echo
echo "=== 17. SHARD_TIP poison-witness: the allow_witnesses MAP ==="
# A legitimate shard tip is a LEAF — only BEACON producers fold records and
# attach witnesses. The mirror must fail-close the same shape the daemon does,
# or the two implementations disagree on frame validity (the S-043 class).
craft_block_msg "$TMP/tip_ok.bin" 13 7 0 0 0 9
run_decode "$TMP/tip_ok.bin" --json
TIP=$(echo "$OUT" | tail -1 | "$PY" -c "
import json,sys
try:
  d=json.loads(sys.stdin.read())
  print('%s/%s/%s' % (d.get('verdict'), d.get('payload_kind'), d.get('shard_id')))
except Exception: print('ERR')
")
if [ "$TIP" = "VALID/shard_tip_frame/7" ]; then
  assert "true" "SHARD_TIP: a LEAF tip → VALID with shard_id decoded"
else
  echo "$OUT"; assert "false" "SHARD_TIP leaf decode (got $TIP)"
fi
craft_block_msg "$TMP/tip_w.bin" 13 7 1 0 0 9
run_decode "$TMP/tip_w.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "leaf block"; then
  assert "true" "SHARD_TIP carrying a WITNESS → MALFORMED exit 3 (POISON-WITNESS)"
else
  echo "$OUT"; assert "false" "SHARD_TIP witness reject (rc=$RC)"
fi
craft_block_msg "$TMP/tip_r.bin" 13 7 0 1 0 9
run_decode "$TMP/tip_r.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "empty shard_tip_records"; then
  assert "true" "SHARD_TIP carrying folded RECORDS → MALFORMED exit 3"
else
  echo "$OUT"; assert "false" "SHARD_TIP records reject (rc=$RC)"
fi
# The SAME witness-carrying block is legal as a CROSS_SHARD_RECEIPT_BUNDLE —
# proving the mirror implements a per-type MAP, not a blanket reject.
craft_block_msg "$TMP/bundle.bin" 14 3 1 1 0 9
run_decode "$TMP/bundle.bin" --json
BUN=$(echo "$OUT" | tail -1 | "$PY" -c "
import json,sys
try:
  d=json.loads(sys.stdin.read())
  print('%s/%s/%s' % (d.get('verdict'), d.get('payload_kind'), d.get('src_shard')))
except Exception: print('ERR')
")
if [ "$BUN" = "VALID/bundle_frame/3" ]; then
  assert "true" "CROSS_SHARD_RECEIPT_BUNDLE: the SAME records+witness block → VALID (allow_witnesses is a per-type map)"
else
  echo "$OUT"; assert "false" "bundle frame decode (got $BUN)"
fi

echo
echo "=== 18. CHAIN_RESPONSE frame: has_more, block list, count-lie ==="
# craft_chain_response <out> <has_more> <nblocks> <count_override_or_empty> <pad>
craft_chain_response() {
  "$PY" - "$@" <<'EOF'
import struct, sys
out, has_more, nblocks, override, pad = sys.argv[1:6]

def block_frame(index):
    b = bytearray()
    b += struct.pack("<Q", index) + bytes(32) + struct.pack("<q", 1)
    for _ in range(15): b += struct.pack("<H", 0)
    b += bytes(32) * 3 + bytes([0]) + bytes([0]) + struct.pack("<H", 0) + bytes(32)
    for _ in range(5): b += struct.pack("<H", 0)
    b += bytes(32) * 2 + bytes([0]) + struct.pack("<I", 0) + struct.pack("<I", 0)
    b += struct.pack("<H", 0) + struct.pack("<H", 0)
    return bytes(b)

body = bytearray([0xB1, 0x01, 0x06, 0x00])
body += bytes([int(has_more)])
n = int(nblocks)
body += struct.pack("<H", int(override) if override != "" else n)
for i in range(n):
    f = block_frame(i)
    body += struct.pack("<I", len(f)) + f
body += bytes(int(pad))
open(out, "wb").write(bytes(body))
EOF
}
craft_chain_response "$TMP/cr.bin" 1 2 "" 0
run_decode "$TMP/cr.bin" --json
CR=$(echo "$OUT" | tail -1 | "$PY" -c "
import json,sys
try:
  d=json.loads(sys.stdin.read())
  print('%s/%s/%s/%s' % (d.get('verdict'), d.get('payload_kind'),
        d.get('has_more'), d.get('blocks')))
except Exception: print('ERR')
")
if [ "$CR" = "VALID/chain_response_frame/True/2" ]; then
  assert "true" "CHAIN_RESPONSE: two blocks + has_more=1 → VALID"
else
  echo "$OUT"; assert "false" "CHAIN_RESPONSE decode (got $CR)"
fi
craft_chain_response "$TMP/cr_empty.bin" 0 0 "" 0
run_decode "$TMP/cr_empty.bin"
[ "$RC" = "0" ] && assert "true" "CHAIN_RESPONSE: the EMPTY 'nothing more' reply → VALID" \
                 || { echo "$OUT"; assert "false" "empty CHAIN_RESPONSE → exit 0 (rc=$RC)"; }
craft_chain_response "$TMP/cr_hm.bin" 2 0 "" 0
run_decode "$TMP/cr_hm.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "has_more must be 0 or 1"; then
  assert "true" "CHAIN_RESPONSE has_more=2 → MALFORMED exit 3 (a bool has two encodings)"
else
  echo "$OUT"; assert "false" "CHAIN_RESPONSE has_more=2 reject (rc=$RC)"
fi
craft_chain_response "$TMP/cr_lie.bin" 0 1 65535 0
run_decode "$TMP/cr_lie.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "declares 65535 elements"; then
  assert "true" "CHAIN_RESPONSE count-lie (65535 declared) → MALFORMED before any allocation"
else
  echo "$OUT"; assert "false" "CHAIN_RESPONSE count-lie reject (rc=$RC)"
fi
craft_chain_response "$TMP/cr_pad.bin" 0 1 "" 4
run_decode "$TMP/cr_pad.bin"
[ "$RC" = "3" ] && assert "true" "CHAIN_RESPONSE trailing bytes → MALFORMED exit 3" \
                 || { echo "$OUT"; assert "false" "CHAIN_RESPONSE trailing → exit 3 (rc=$RC)"; }

echo
echo "=== 19. D2-inc7b CONTRIB frame ==="
# craft_contrib <out> <block_index> <signer> <ntx> <proposer_time>
#               <tx_count_override_or_empty> <pad>
craft_contrib() {
  "$PY" - "$@" <<'EOF'
import struct, sys
out, bi, signer, ntx, ptime, override, pad = sys.argv[1:8]
body = bytearray([0xB1, 0x01, 0x04, 0x00])
body += struct.pack("<Q", int(bi))
sb = signer.encode("utf-8")
body += bytes([len(sb)]) + sb
body += bytes(32)                              # prev_hash
body += struct.pack("<Q", 3)                   # aborts_gen
n = int(ntx)
body += struct.pack("<H", int(override) if override != "" else n)
body += bytes(32) * n                          # tx_hashes
body += bytes(32)                              # dh_input
body += bytes(32) * 3                          # the three view roots
body += struct.pack("<H", 0) * 3               # the three view lists
body += struct.pack("<Q", int(ptime))          # proposer_time
body += bytes(32)                              # view_shardtip_root
body += struct.pack("<H", 0)                   # view_shardtip_list
body += bytes(64)                              # ed_sig
body += bytes(int(pad))
open(out, "wb").write(bytes(body))
EOF
}
craft_contrib "$TMP/contrib.bin" 42 "node-a.tld" 2 1700000000 "" 0
run_decode "$TMP/contrib.bin" --json
CON=$(echo "$OUT" | tail -1 | "$PY" -c "
import json,sys
try:
  d=json.loads(sys.stdin.read())
  print('%s/%s/%s/%s/%s/%s' % (d.get('verdict'), d.get('payload_kind'),
        d.get('block_index'), d.get('signer'), d.get('tx_hashes'),
        d.get('proposer_time')))
except Exception: print('ERR')
")
if [ "$CON" = "VALID/contrib_frame/42/node-a.tld/2/1700000000" ]; then
  assert "true" "CONTRIB: the always-present frame → VALID with every scalar decoded"
else
  echo "$OUT"; assert "false" "CONTRIB decode (got $CON)"
fi
craft_contrib "$TMP/contrib_pad.bin" 42 "n1" 0 0 "" 1
run_decode "$TMP/contrib_pad.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "trailing"; then
  assert "true" "CONTRIB trailing byte → MALFORMED exit 3 (exact consumption)"
else
  echo "$OUT"; assert "false" "CONTRIB trailing byte → exit 3 (rc=$RC)"
fi
craft_contrib "$TMP/contrib_lie.bin" 42 "n1" 1 0 65535 0
run_decode "$TMP/contrib_lie.bin"
if [ "$RC" = "3" ] && echo "$OUT" | grep -qi "declares 65535 elements"; then
  assert "true" "CONTRIB tx_hashes count-lie → MALFORMED before any allocation"
else
  echo "$OUT"; assert "false" "CONTRIB count-lie reject (rc=$RC)"
fi
craft_contrib "$TMP/contrib_tr.bin" 42 "n1" 0 0 "" 0
"$PY" -c "
d=open('$TMP/contrib_tr.bin','rb').read()
open('$TMP/contrib_tr.bin','wb').write(d[:-1])
"
run_decode "$TMP/contrib_tr.bin"
[ "$RC" = "3" ] && assert "true" "truncated CONTRIB frame → MALFORMED exit 3" \
                 || { echo "$OUT"; assert "false" "truncated CONTRIB → exit 3 (rc=$RC)"; }

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_decode_wire"; exit 0
else
  echo "  FAIL: test_light_decode_wire"; exit 1
fi
