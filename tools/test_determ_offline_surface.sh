#!/usr/bin/env bash
# determ DAEMON OFFLINE subcommand surface — daemon-free regression.
#
# Pure offline test (no cluster, no daemon, no RPC). Exercises the
# `determ` (chain-daemon) subcommands that need NO running node — the
# local-only operations an operator can run air-gapped against
# file fixtures or bare arguments:
#
#   init                local keygen + config emission (no genesis pin)
#   verify-genesis      standalone genesis.json validator — loads,
#                       recomputes compute_genesis_hash, emits a 64-hex
#                       hash; fail-closed on a wrong --expected-hash pin
#   genesis-tool build  loads the same genesis.json, writes a .hash
#                       sidecar, and prints the genesis_hash — which MUST
#                       equal verify-genesis's (same identity contract)
#   genesis-tool        reads the init-minted node key and prints the
#     peer-info          JSON entry an operator hands to the genesis
#                       assembler (no RPC; key on disk only)
#   tx-hash             Transaction::from_json + compute_hash over an
#                       operator-supplied tx.json (offline hashing);
#                       fail-closed on a structurally malformed tx
#   where-is            deterministic shard routing for an address;
#                       fail-closed when the required --shard-count is
#                       absent
#
# None of these open a socket — they operate purely on argv + local
# files, so the whole script runs with no chain.json, no peers, and no
# RPC port. At least three groups assert a fail-closed path (bad input →
# non-zero exit, never a false success):
#   * verify-genesis  wrong --expected-hash → exit 1 + FAIL diagnostic
#   * tx-hash         malformed tx (missing required field) → exit 1
#   * where-is        missing --shard-count → exit 1
#
# SKIP-with-PASS (exit 0) when the determ binary is absent, so this
# script is a no-op pass in minimal build environments, never a hard
# failure.
#
# Run from repo root: bash tools/test_determ_offline_surface.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found; build with"
    echo "        cmake --build build --config Release --target determ"
    exit 0
fi

TMP="build/test_determ_offline_surface.$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# A valid genesis.json fixture (mirrors tools/test_verify_genesis.sh):
# strong-mode 3-of-3, empty initial sets, default genesis_message.
cat > "$TMP/genesis.json" <<EOF
{
  "chain_id": "test-determ-offline-surface",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 100,
  "min_stake": 1000,
  "initial_creators": [],
  "initial_balances": []
}
EOF

echo "=== 1. init → offline keygen + config emission, exit 0 ==="
set +e
OUT=$("$DETERM" init --data-dir "$TMP/dd" --profile web 2>&1); RC=$?
set -e
if [ "$RC" = "0" ] \
   && [ -s "$TMP/dd/node_key.json" ] \
   && [ -s "$TMP/dd/config.json" ] \
   && echo "$OUT" | grep -q "Config written to"; then
    assert "true" "init wrote node_key.json + config.json (no daemon)"
else
    echo "$OUT"
    assert "false" "init wrote node_key.json + config.json (RC=$RC)"
fi

echo
echo "=== 2. init → unknown --profile fails closed, exit 1 ==="
set +e
"$DETERM" init --data-dir "$TMP/dd_bad" --profile bogus-profile >/dev/null 2>&1; RC=$?
set -e
if [ "$RC" != "0" ]; then
    assert "true" "init unknown --profile → non-zero exit"
else
    assert "false" "init unknown --profile → non-zero exit (got $RC)"
fi

echo
echo "=== 3. verify-genesis OK on a valid genesis.json ==="
set +e
OUT=$("$DETERM" verify-genesis --in "$TMP/genesis.json" 2>&1); RC=$?
set -e
HASH=$(echo "$OUT" | grep "genesis_hash" | head -1 | awk '{print $NF}')
if [ "$RC" = "0" ] \
   && echo "$OUT" | grep -q "genesis OK" \
   && [ "${#HASH}" -eq 64 ]; then
    assert "true" "verify-genesis OK + 64-hex genesis_hash"
else
    echo "$OUT"
    assert "false" "verify-genesis OK + 64-hex genesis_hash (RC=$RC, hash='$HASH')"
fi

echo
echo "=== 4. verify-genesis --json is parseable + carries operational params ==="
set +e
JSON_OUT=$("$DETERM" verify-genesis --in "$TMP/genesis.json" --json 2>&1); RC=$?
set -e
SHAPE=$(echo "$JSON_OUT" | $PY -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    ok = (d.get('status') == 'ok'
          and len(d.get('genesis_hash','')) == 64
          and 'm_creators' in d
          and 'bft_enabled' in d)
    print('true' if ok else 'false')
except Exception:
    print('false')
")
if [ "$RC" = "0" ] && [ "$SHAPE" = "true" ]; then
    assert "true" "verify-genesis --json valid + has genesis_hash/m_creators/bft_enabled"
else
    echo "$JSON_OUT"
    assert "false" "verify-genesis --json shape (RC=$RC)"
fi

echo
echo "=== 5. verify-genesis fails closed on a wrong --expected-hash pin ==="
set +e
OUT=$("$DETERM" verify-genesis --in "$TMP/genesis.json" \
        --expected-hash 0000000000000000000000000000000000000000000000000000000000000000 2>&1)
RC=$?
set -e
if [ "$RC" != "0" ] && echo "$OUT" | grep -q "FAIL"; then
    assert "true" "wrong --expected-hash → non-zero exit + FAIL diagnostic"
else
    echo "$OUT"
    assert "false" "wrong --expected-hash → non-zero exit + FAIL diagnostic (RC=$RC)"
fi

echo
echo "=== 6. genesis-tool build agrees with verify-genesis (same identity hash) ==="
set +e
BUILD_OUT=$("$DETERM" genesis-tool build "$TMP/genesis.json" --json 2>&1); RC=$?
set -e
BUILD_HASH=$(echo "$BUILD_OUT" | $PY -c "
import sys, json
try:
    print(json.loads(sys.stdin.read()).get('genesis_hash',''))
except Exception:
    print('')
")
# The .hash sidecar is always written by genesis-tool build.
if [ "$RC" = "0" ] \
   && [ "${#BUILD_HASH}" -eq 64 ] \
   && [ "$BUILD_HASH" = "$HASH" ] \
   && [ -s "$TMP/genesis.json.hash" ]; then
    assert "true" "genesis-tool build hash == verify-genesis hash + wrote .hash sidecar"
else
    echo "$BUILD_OUT"
    assert "false" "genesis-tool build hash matches verify-genesis (RC=$RC, build='$BUILD_HASH', vg='$HASH')"
fi

echo
echo "=== 7. genesis-tool peer-info reads the init key (no RPC) ==="
set +e
PI_OUT=$("$DETERM" genesis-tool peer-info my.node --data-dir "$TMP/dd" --stake 5000 2>&1); RC=$?
set -e
PI_SHAPE=$(echo "$PI_OUT" | $PY -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    ok = (d.get('domain') == 'my.node'
          and len(d.get('ed_pub','')) == 64
          and d.get('initial_stake') == 5000)
    print('true' if ok else 'false')
except Exception:
    print('false')
")
if [ "$RC" = "0" ] && [ "$PI_SHAPE" = "true" ]; then
    assert "true" "peer-info emits {domain, ed_pub(64 hex), initial_stake}"
else
    echo "$PI_OUT"
    assert "false" "peer-info shape (RC=$RC)"
fi

echo
echo "=== 8. Build a valid tx.json fixture (all Transaction::from_json fields) ==="
$PY -c "
import json
json.dump({
    'type': 0, 'from': 'alice.determ', 'to': 'bob.determ',
    'amount': 100, 'fee': 1, 'nonce': 0, 'payload': '',
    'sig': '00' * 64, 'hash': '00' * 32,
}, open('$TMP/tx.json', 'w'))
# Malformed: drop the required 'sig' field — must fail closed.
json.dump({
    'type': 0, 'from': 'alice.determ', 'to': 'bob.determ',
    'amount': 100, 'nonce': 0, 'payload': '', 'hash': '00' * 32,
}, open('$TMP/tx_bad.json', 'w'))
"
if [ -s "$TMP/tx.json" ] && [ -s "$TMP/tx_bad.json" ]; then
    assert "true" "tx fixtures written"
else
    assert "false" "tx fixtures written"
fi

echo
echo "=== 9. tx-hash computes a 64-hex hash on a valid tx (plain + --json agree) ==="
set +e
TXH=$("$DETERM" tx-hash --in "$TMP/tx.json" 2>&1); RC1=$?
TXJ=$("$DETERM" tx-hash --in "$TMP/tx.json" --json 2>&1); RC2=$?
set -e
TXJ_HASH=$(echo "$TXJ" | $PY -c "
import sys, json
try:
    print(json.loads(sys.stdin.read()).get('hash',''))
except Exception:
    print('')
")
if [ "$RC1" = "0" ] && [ "$RC2" = "0" ] \
   && [ "${#TXH}" -eq 64 ] \
   && [ "$TXH" = "$TXJ_HASH" ]; then
    assert "true" "tx-hash 64-hex + plain output matches --json hash"
else
    echo "plain=$TXH json=$TXJ"
    assert "false" "tx-hash 64-hex + plain==json (RC1=$RC1, RC2=$RC2)"
fi

echo
echo "=== 10. tx-hash fails closed on a malformed tx (missing required field) ==="
set +e
OUT=$("$DETERM" tx-hash --in "$TMP/tx_bad.json" 2>&1); RC=$?
set -e
if [ "$RC" != "0" ] && echo "$OUT" | grep -q "Error"; then
    assert "true" "malformed tx → non-zero exit + Error diagnostic"
else
    echo "$OUT"
    assert "false" "malformed tx → non-zero exit + Error diagnostic (RC=$RC)"
fi

echo
echo "=== 11. where-is routes deterministically (plain + --json agree) ==="
set +e
WI_PLAIN=$("$DETERM" where-is alice.determ --shard-count 4 2>&1); RC1=$?
WI_JSON=$("$DETERM" where-is alice.determ --shard-count 4 --json 2>&1); RC2=$?
set -e
# Plain form: "<addr> -> shard <N> (of <count>)". Pull the shard index.
WI_PLAIN_SHARD=$(echo "$WI_PLAIN" | grep -oE "shard [0-9]+" | head -1 | awk '{print $2}')
WI_JSON_SHARD=$(echo "$WI_JSON" | $PY -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    print(d.get('shard')) if (d.get('shard_count') == 4
                              and 0 <= int(d.get('shard', -1)) < 4) else print('')
except Exception:
    print('')
")
if [ "$RC1" = "0" ] && [ "$RC2" = "0" ] \
   && [ -n "$WI_PLAIN_SHARD" ] \
   && [ "$WI_PLAIN_SHARD" = "$WI_JSON_SHARD" ]; then
    assert "true" "where-is plain shard == --json shard (in [0,4))"
else
    echo "plain=$WI_PLAIN json=$WI_JSON"
    assert "false" "where-is routing agreement (RC1=$RC1, RC2=$RC2)"
fi

echo
echo "=== 12. where-is fails closed when --shard-count is absent ==="
set +e
OUT=$("$DETERM" where-is alice.determ 2>&1); RC=$?
set -e
if [ "$RC" != "0" ] && echo "$OUT" | grep -qi "shard-count"; then
    assert "true" "missing --shard-count → non-zero exit + diagnostic"
else
    echo "$OUT"
    assert "false" "missing --shard-count → non-zero exit + diagnostic (RC=$RC)"
fi

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_determ_offline_surface"; exit 0
else
  echo "  FAIL: test_determ_offline_surface"; exit 1
fi