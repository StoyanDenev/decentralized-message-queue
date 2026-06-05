#!/usr/bin/env bash
# determ-wallet receipt-key CLI test.
#
# Exercises the OFFLINE composite state-root leaf-key deriver. Given the
# logical coordinates of a composite-namespace leaf (i: / m: / p:), the
# command emits the exact hex body the daemon's `state_proof` RPC expects
# for that namespace — the precise string determ-light computes internally
# before fetching a composite-key proof (see src/node/node.cpp
# rpc_state_proof and docs/proofs/ReceiptInclusionProofSoundness.md).
#
# The byte layout MUST match src/chain/chain.cpp build_state_leaves
# byte-for-byte:
#   i:  body = u64_be(src_shard) || tx_hash[32]      (40B), value=SHA256(0x01)
#   m:  body = u32_be(shard_id)                      ( 4B)
#   p:  body = u64_be(eff_height) || u32_be(idx)     (12B)
#
# This test recomputes the EXPECTED hex independently in Python and asserts
# the wallet output matches it exactly — correctness, not just shape. No
# cluster, no daemon, no network: pure offline derivation.
#
# Differentiation vs sibling commands:
#   * derive-tx-hash  — recompute a TRANSACTION hash from an envelope.
#   * state-proof-verify — VERIFY a returned Merkle proof against a root.
#   * receipt-key     — DERIVE the composite leaf-KEY hex to request a proof.
#
# Assertions (~22):
#   1.  Global help mentions receipt-key.
#   2.  receipt-key --help exits 0.
#   3.  Unknown CLI arg: exit 1.
#   4.  Bad --namespace value: exit 1.
#   5.  i: missing --tx-hash: exit 1.
#   6.  i: missing --src-shard: exit 1.
#   7.  i: --tx-hash wrong length (not 32 bytes): exit 1.
#   8.  i: --tx-hash invalid hex: exit 1.
#   9.  i: --src-shard non-decimal: exit 1.
#  10.  i: happy path (default namespace): exit 0.
#  11.  i: key_body_hex matches independent Python computation.
#  12.  i: full_key_bytes_hex == hex("i:") + key_body_hex.
#  13.  i: value_hash == SHA256(0x01).
#  14.  i: --json parseable + has all four keys.
#  15.  i: --json key_body_hex matches non-JSON output.
#  16.  i: determinism — two invocations give identical key_body_hex.
#  17.  m: happy path: key_body_hex == u32_be(shard_id).
#  18.  m: --json has NO value_hash key (i:-only field).
#  19.  m: missing --shard-id: exit 1.
#  20.  p: happy path: key_body_hex == u64_be(eff)+u32_be(idx).
#  21.  p: full_key_bytes_hex == hex("p:") + key_body_hex.
#  22.  p: missing --idx: exit 1.
#
# Run from repo root: bash tools/test_wallet_receipt_key.sh
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

# Fixed test vectors.
SRC_SHARD=7
TX_HASH="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
SHARD_ID=3
EFF_HEIGHT=12345
IDX=2

# ── Independent reference computations (Python) ─────────────────────────
# i: body = u64_be(src_shard) || tx_hash[32]
EXP_I_BODY=$($PY -c "
import struct
print(struct.pack('>Q', $SRC_SHARD).hex() + '$TX_HASH')
")
# value_hash = SHA256(0x01)
EXP_I_VALUE=$($PY -c "
import hashlib
print(hashlib.sha256(bytes([1])).hexdigest())
")
EXP_I_FULL=$($PY -c "print(('i:').encode().hex() + '$EXP_I_BODY')")

# m: body = u32_be(shard_id)
EXP_M_BODY=$($PY -c "
import struct
print(struct.pack('>I', $SHARD_ID).hex())
")
EXP_M_FULL=$($PY -c "print(('m:').encode().hex() + '$EXP_M_BODY')")

# p: body = u64_be(eff_height) || u32_be(idx)
EXP_P_BODY=$($PY -c "
import struct
print(struct.pack('>Q', $EFF_HEIGHT).hex() + struct.pack('>I', $IDX).hex())
")
EXP_P_FULL=$($PY -c "print(('p:').encode().hex() + '$EXP_P_BODY')")

field() {  # field <json> <key>
  echo "$1" | $PY -c "import json,sys; print(json.loads(sys.stdin.read()).get('$2',''))"
}

echo "=== 1. Global help mentions receipt-key ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "receipt-key" "help mentions receipt-key"

echo
echo "=== 2. receipt-key --help exits 0 ==="
set +e
"$WALLET" receipt-key --help >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "receipt-key --help exits 0"

echo
echo "=== 3. Unknown CLI arg: exit 1 ==="
set +e
"$WALLET" receipt-key --bogus >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "unknown arg returns 1"

echo
echo "=== 4. Bad --namespace: exit 1 ==="
set +e
"$WALLET" receipt-key --namespace z >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "bad --namespace returns 1"

echo
echo "=== 5. i: missing --tx-hash: exit 1 ==="
set +e
"$WALLET" receipt-key --namespace i --src-shard "$SRC_SHARD" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "i: missing --tx-hash returns 1"

echo
echo "=== 6. i: missing --src-shard: exit 1 ==="
set +e
"$WALLET" receipt-key --namespace i --tx-hash "$TX_HASH" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "i: missing --src-shard returns 1"

echo
echo "=== 7. i: --tx-hash wrong length: exit 1 ==="
set +e
"$WALLET" receipt-key --src-shard "$SRC_SHARD" --tx-hash "00112233" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "i: short tx-hash returns 1"

echo
echo "=== 8. i: --tx-hash invalid hex: exit 1 ==="
BADHEX=$($PY -c "print('zz' * 32)")
set +e
"$WALLET" receipt-key --src-shard "$SRC_SHARD" --tx-hash "$BADHEX" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "i: non-hex tx-hash returns 1"

echo
echo "=== 9. i: --src-shard non-decimal: exit 1 ==="
set +e
"$WALLET" receipt-key --src-shard "0x7" --tx-hash "$TX_HASH" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "i: non-decimal src-shard returns 1"

echo
echo "=== 10-13. i: happy path + correctness ==="
set +e
I_JSON=$("$WALLET" receipt-key --src-shard "$SRC_SHARD" --tx-hash "$TX_HASH" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "i: happy path (default namespace) returns 0"
I_BODY=$(field "$I_JSON" key_body_hex)
I_FULL=$(field "$I_JSON" full_key_bytes_hex)
I_VALUE=$(field "$I_JSON" value_hash)
assert_eq "$I_BODY"  "$EXP_I_BODY"  "i: key_body_hex matches u64_be(src)+tx_hash"
assert_eq "$I_FULL"  "$EXP_I_FULL"  "i: full_key_bytes_hex == hex(i:)+body"
assert_eq "$I_VALUE" "$EXP_I_VALUE" "i: value_hash == SHA256(0x01)"

echo
echo "=== 14-15. i: --json shape + cross-check vs text mode ==="
PARSED_OK=$(echo "$I_JSON" | $PY -c "
import json,sys
d = json.loads(sys.stdin.read())
ok = all(k in d for k in ('namespace','key_body_hex','full_key_bytes_hex','value_hash'))
print('yes' if ok else 'no')
" 2>/dev/null || echo "no")
assert_eq "$PARSED_OK" "yes" "i: --json has all four keys"
TEXT_BODY=$("$WALLET" receipt-key --src-shard "$SRC_SHARD" --tx-hash "$TX_HASH" 2>&1 \
  | tr -d '\r' | grep '^key_body_hex:' | awk '{print $2}')
assert_eq "$TEXT_BODY" "$I_BODY" "i: text-mode key_body_hex == JSON-mode"

echo
echo "=== 16. i: determinism (two runs identical) ==="
RUN1=$("$WALLET" receipt-key --src-shard "$SRC_SHARD" --tx-hash "$TX_HASH" --json 2>&1 | tr -d '\r')
RUN2=$("$WALLET" receipt-key --src-shard "$SRC_SHARD" --tx-hash "$TX_HASH" --json 2>&1 | tr -d '\r')
B1=$(field "$RUN1" key_body_hex)
B2=$(field "$RUN2" key_body_hex)
assert_eq "$B1" "$B2" "i: two invocations give identical key_body_hex"

echo
echo "=== 17-19. m: namespace ==="
set +e
M_JSON=$("$WALLET" receipt-key --namespace m --shard-id "$SHARD_ID" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "m: happy path returns 0"
M_BODY=$(field "$M_JSON" key_body_hex)
M_FULL=$(field "$M_JSON" full_key_bytes_hex)
assert_eq "$M_BODY" "$EXP_M_BODY" "m: key_body_hex == u32_be(shard_id)"
assert_eq "$M_FULL" "$EXP_M_FULL" "m: full_key_bytes_hex == hex(m:)+body"
HAS_VALUE=$(echo "$M_JSON" | $PY -c "import json,sys; print('yes' if 'value_hash' in json.loads(sys.stdin.read()) else 'no')")
assert_eq "$HAS_VALUE" "no" "m: --json has no value_hash (i:-only)"
set +e
"$WALLET" receipt-key --namespace m >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "m: missing --shard-id returns 1"

echo
echo "=== 20-22. p: namespace ==="
set +e
P_JSON=$("$WALLET" receipt-key --namespace p --eff-height "$EFF_HEIGHT" --idx "$IDX" --json 2>&1 | tr -d '\r')
RC=$?
set -e
assert_eq "$RC" "0" "p: happy path returns 0"
P_BODY=$(field "$P_JSON" key_body_hex)
P_FULL=$(field "$P_JSON" full_key_bytes_hex)
assert_eq "$P_BODY" "$EXP_P_BODY" "p: key_body_hex == u64_be(eff)+u32_be(idx)"
assert_eq "$P_FULL" "$EXP_P_FULL" "p: full_key_bytes_hex == hex(p:)+body"
set +e
"$WALLET" receipt-key --namespace p --eff-height "$EFF_HEIGHT" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "p: missing --idx returns 1"

echo
echo "================================"
echo "Total: PASS=$pass_count FAIL=$fail_count"
echo "================================"

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
exit 0
