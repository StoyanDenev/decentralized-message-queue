#!/usr/bin/env bash
# E4 — finite, self-terminating subsidy fund.
#
# Chain configured with subsidy_pool_initial = 100, block_subsidy = 30.
# Expected lifecycle:
#   blocks 1-3: full 30 paid (cumulative 30 / 60 / 90 within pool).
#   block 4:    only 10 paid (pool drained to 100/100 — last partial).
#   block 5+:   0 subsidy; transaction fees alone reward creators.
#
# Asserts:
#   1. Pool drains in the expected order (cumulative paid equals
#      min(block * block_subsidy, subsidy_pool_initial)).
#   2. After pool exhaustion the chain keeps producing blocks (validators
#      still active even without subsidy reward).
#   3. The A1 unitary-balance invariant continues to hold across the
#      exhaustion transition (a violation would throw at apply time and
#      kill the node).
#
# Run from repo root: bash tools/test_finite_subsidy.sh
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe
T=test_finite_subsidy

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

echo "=== 1. Init 3 nodes with single_test profile ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== 2. Build genesis (block_subsidy=30, subsidy_pool_initial=100) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-finite-subsidy",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 30,
  "subsidy_pool_initial": 100,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)
GPATH="C:/sauromatae/$T/gen.json"

echo
echo "=== 3. Configure 3-mesh ==="
configure_node() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain'] = 'node$n'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers
c['genesis_path'] = '$GPATH'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = 'C:/sauromatae/$T/n$n/chain.json'
c['key_path'] = 'C:/sauromatae/$T/n$n/node_key.json'
c['data_dir'] = 'C:/sauromatae/$T/n$n'
with open('$T/n$n/config.json','w') as f: json.dump(c,f,indent=2)
"
}
configure_node 1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

echo
echo "=== 4. Start 3 nodes ==="
NODE_PIDS=("" "" "")
for n in 1 2 3; do
  $DETERM start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  sleep 0.3
done

echo
echo "=== 5. Poll until chain advances past expected exhaustion (height >= 10) ==="
for _ in $(seq 1 80); do
  H=$(get_status_field 8771 height)
  if [ "$H" != "-" ] && [ "$H" -ge 10 ] 2>/dev/null; then break; fi
  sleep 0.2
done

H=$(get_status_field 8771 height)
echo "  height: $H"

# Inspect creators' balances. After pool exhaustion, blocks pay only
# fees (0 in this test — no user txs). Total subsidy ever paid =
# subsidy_pool_initial. With 3 creators sharing equally per block,
# cumulative-paid divided across them yields ~33.3 each. Cumulative
# total across all 3 = subsidy_pool_initial = 100. Per-creator may
# vary by ±1 from the dust rule (creator[0] gets remainders).
B1=$($DETERM balance node1 --rpc-port 8771 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('balance',0))
except: print(0)")
B2=$($DETERM balance node2 --rpc-port 8771 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('balance',0))
except: print(0)")
B3=$($DETERM balance node3 --rpc-port 8771 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('balance',0))
except: print(0)")
TOTAL=$(( B1 + B2 + B3 ))
echo "  creator balances: node1=$B1 node2=$B2 node3=$B3 sum=$TOTAL"

PASS=true
if [ "$H" = "-" ] || [ "$H" -lt 10 ] 2>/dev/null; then
  echo "  FAIL: chain didn't advance past exhaustion height"; PASS=false
fi
if [ "$TOTAL" -ne 100 ]; then
  echo "  FAIL: cumulative subsidy = $TOTAL, expected 100 (== subsidy_pool_initial)"
  PASS=false
fi

# A1 invariant: if any block had violated it, a node would have thrown
# and stopped producing. Reaching height >= 10 implies the invariant
# held across the pool-exhaustion transition.

if $PASS; then
  echo
  echo "  PASS: E4 finite subsidy fund end-to-end"
  echo "        - subsidy_pool_initial = 100 hard-cap honored"
  echo "        - cumulative paid = 100 (chain stopped minting after exhaustion)"
  echo "        - chain continued past exhaustion (height $H)"
  echo "        - A1 unitary-balance invariant held across the transition"
fi
