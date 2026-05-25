#!/usr/bin/env bash
# determ-light watch-head — periodic trust-minimized head monitor.
#
# Boots a 3-node cluster, runs `watch-head --count 2 --interval 1` and
# `watch-head --count 1 --interval 1` against one node, and validates
# (a) the structured-line shape per tick, (b) sigs_valid=yes against a
# healthy cluster, (c) startup fail-closed on a wrong-genesis file.
#
# Assertions:
#   1. --count 2 run prints exactly 2 TICK lines, both parse cleanly +
#      report sigs_valid=yes.
#   2. Wrong-genesis startup → non-zero exit + diagnostic mentions
#      "GENESIS HASH MISMATCH".
#   3. Head field is well-formed across ticks (height non-zero, valid
#      hex prefixes in head_hash + state_root).
#   4. --count 1 emits exactly one TICK line.
#
# Run from repo root: bash tools/test_light_watch_head.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found; build with"
    echo "        cmake --build build --config Release --target determ-light"
    exit 0
fi

T=test_light_watch_head
TABS=$PROJECT_ROOT/$T

declare -a NODE_PIDS

cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  done
}
trap cleanup EXIT INT

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Init 3-node cluster (chain_id=test-light-wh-REAL) ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

cat > $T/gen.json <<EOF
{
  "chain_id": "test-light-wh-REAL",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 100}]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

# Wrong-genesis variant: different chain_id ⇒ different genesis hash.
cat > $T/gen_wrong.json <<EOF
{
  "chain_id": "test-light-wh-WRONG",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 100}]
}
EOF

configure_node() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain'] = 'node$n'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/n$n/chain.json'
c['key_path']   = '$TABS/n$n/node_key.json'
c['data_dir']   = '$TABS/n$n'
c['tx_commit_ms'] = 500
c['block_sig_ms'] = 500
c['abort_claim_ms'] = 250
with open('$T/n$n/config.json','w') as f: json.dump(c, f, indent=2)
"
}
configure_node 1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

echo
echo "=== 2. Wait for chain past height 3 ==="
for _ in $(seq 1 80); do
  H=$($DETERM status --rpc-port 8771 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 3 ] 2>/dev/null; then break; fi
  sleep 0.5
done
echo "  chain height: $H"

echo
echo "=== 3. watch-head --count 2 --interval 1 (healthy cluster) ==="
set +e
OUT=$($DETERM_LIGHT watch-head --rpc-port 8771 --genesis $T/gen.json \
        --count 2 --interval 1 2>&1)
RC=$?
set -e
echo "$OUT"

if [ "$RC" = "0" ]; then
    assert "true" "watch-head --count 2 exit 0"
else
    assert "false" "watch-head --count 2 exit 0 (got $RC)"
fi

# Count TICK lines.
TICK_COUNT=$(echo "$OUT" | grep -cE "^TICK [0-9]+:")
if [ "$TICK_COUNT" = "2" ]; then
    assert "true" "exactly 2 TICK lines emitted"
else
    assert "false" "expected 2 TICK lines, got $TICK_COUNT"
fi

echo
echo "=== 4. Both ticks report sigs_valid=yes ==="
YES_COUNT=$(echo "$OUT" | grep -cE "^TICK [0-9]+:.*sigs_valid=yes")
if [ "$YES_COUNT" = "2" ]; then
    assert "true" "both ticks sigs_valid=yes"
else
    assert "false" "expected 2 sigs_valid=yes lines, got $YES_COUNT"
fi

echo
echo "=== 5. Tick lines well-formed (height + hex prefixes) ==="
# Verify each TICK line has height=<digits>, head_hash=<16hex>, and
# committee_size=<digits>. state_root may be empty pre-S-033 but
# this cluster is post-S-038 so it should be populated.
WELL_FORMED=$(echo "$OUT" | grep -E "^TICK [0-9]+: height=[0-9]+ head_hash=[0-9a-f]{16} state_root=[0-9a-f]{16} committee_size=[0-9]+ sigs_valid=(yes|no)" | wc -l)
if [ "$WELL_FORMED" = "2" ]; then
    assert "true" "both TICK lines parse via expected regex"
else
    assert "false" "expected 2 well-formed TICK lines, got $WELL_FORMED"
fi

echo
echo "=== 6. watch-head --count 1 prints exactly one TICK line ==="
set +e
OUT1=$($DETERM_LIGHT watch-head --rpc-port 8771 --genesis $T/gen.json \
         --count 1 --interval 1 2>&1)
RC1=$?
set -e
echo "$OUT1"
TICK_COUNT1=$(echo "$OUT1" | grep -cE "^TICK [0-9]+:")
if [ "$RC1" = "0" ] && [ "$TICK_COUNT1" = "1" ]; then
    assert "true" "--count 1 emits exactly one TICK line"
else
    assert "false" "--count 1: RC=$RC1 ticks=$TICK_COUNT1 (expected RC=0 ticks=1)"
fi

echo
echo "=== 7. watch-head with wrong genesis → fail-closed ==="
set +e
OUT_WRONG=$($DETERM_LIGHT watch-head --rpc-port 8771 --genesis $T/gen_wrong.json \
              --count 1 --interval 1 2>&1)
RC_WRONG=$?
set -e
echo "$OUT_WRONG"
if [ "$RC_WRONG" != "0" ]; then
    assert "true" "watch-head with wrong genesis exits non-zero ($RC_WRONG)"
else
    assert "false" "watch-head with wrong genesis should exit non-zero (got 0)"
fi

# Diagnostic must mention GENESIS HASH MISMATCH.
GM=$(echo "$OUT_WRONG" | grep -q "GENESIS HASH MISMATCH" && echo true || echo false)
assert "$GM" "wrong-genesis diagnostic contains 'GENESIS HASH MISMATCH'"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: test_light_watch_head"; exit 0
else
  echo "  FAIL: test_light_watch_head"; exit 1
fi
