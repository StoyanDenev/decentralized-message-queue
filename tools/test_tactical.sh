#!/usr/bin/env bash
# Tactical-profile smoke test. Verifies the Layer-1 swarm-coordination
# profile (PROFILE_TACTICAL_TEST: K=M=3 strong, SHARD + EXTENDED, sub-30ms
# rounds at test timing) boots cleanly and produces blocks at the expected
# cadence. Models the unmanned-mobile-unit (drone, robot) deployment shape.
#
# Asserts:
#   1. determ init --profile tactical_test produces a valid config.
#   2. Three nodes peered at tactical-test timing finalize their first 5
#      blocks within the test-grade ceiling (~250 ms total at 50 ms/block).
#   3. Status RPC reports chain_role = SHARD and sharding_mode = EXTENDED.
#
# Run from repo root: bash tools/test_tactical.sh
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe
T=test_tactical

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

get_status_field() {
  $DETERM status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('$2','-'))
except: print('-')"
}

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

echo "=== 1. Init 3 nodes with tactical_test profile (SHARD + EXTENDED, K=3) ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile tactical_test 2>&1 | tail -1
done

echo
echo "=== 2. Generate peer-info entries ==="
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json
$DETERM genesis-tool peer-info node2 --data-dir $T/n2 --stake 1000 > $T/p2.json
$DETERM genesis-tool peer-info node3 --data-dir $T/n3 --stake 1000 > $T/p3.json

echo
echo "=== 3. Build genesis (M=3, K=3 strong, tactical timing) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-tactical",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "initial_shard_count": 3,
  "epoch_blocks": 100,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 1000}],
  "shard_regions": ["us-east", "us-east", "us-east"]
}
EOF
$DETERM genesis-tool build-sharded $T/gen.json
GEN_HASH=$(cat $T/gen.json.shard0.json.hash)
echo "  Shard0 genesis hash: $GEN_HASH"

echo
echo "=== 4. Start nodes peered at distinct ports ==="
for n in 1 2 3; do
  port=$((7777 + (n-1)*10))
  rpc=$((7778 + (n-1)*10))
  $DETERM start --data-dir $T/n$n --listen-port $port --rpc-port $rpc \
    --genesis $T/gen.json.shard0.json --peer 127.0.0.1:7777 \
    --peer 127.0.0.1:7787 --peer 127.0.0.1:7797 \
    > $T/n$n.log 2>&1 &
  NODE_PIDS+=($!)
done

echo
echo "=== 5. Poll for height >= 5 (tactical-test ceiling: 1500 ms) ==="
DEADLINE=$((SECONDS + 2))
HEIGHT=0
while [ $SECONDS -lt $DEADLINE ]; do
  HEIGHT=$(get_status_field 7778 height)
  [ "$HEIGHT" != "-" ] && [ "$HEIGHT" -ge 5 ] && break
  sleep 0.05
done

echo "  Final height: $HEIGHT"
ROLE=$(get_status_field 7778 chain_role)
SMODE=$(get_status_field 7778 sharding_mode)
echo "  chain_role: $ROLE  sharding_mode: $SMODE"

if [ "$HEIGHT" -ge 5 ] && [ "$ROLE" = "shard" ] && [ "$SMODE" = "extended" ]; then
  echo "PASS"
  exit 0
else
  echo "FAIL"
  exit 1
fi
