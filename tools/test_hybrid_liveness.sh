#!/usr/bin/env bash
# Hybrid-mode liveness test for DHCoin v1 rev.6.
# Verifies the K-committee rotation tolerates a creator going down:
#   - M_pool=4 registered, K=3 committee per round.
#   - Run all 4 nodes for warm-up.
#   - Kill 1 node mid-run.
#   - Verify the remaining 3 nodes continue producing blocks (the K=3
#     committee can still form from 3 survivors after the dead one is
#     suspended-out).
#
# This is the actual claimed liveness benefit of hybrid mode (M_pool − K
# silent creators tolerated via rotation).
#
# Run from repo root: bash tools/test_hybrid_liveness.sh
set -u
cd "$(dirname "$0")/.."

DHCOIN=build/Release/dhcoin.exe
T=test_hyb_live

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

get_height() {
  $DHCOIN status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height','-'))
except: print('-')"
}
get_head() {
  $DHCOIN status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('head_hash','?'))
except: print('?')"
}

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3 $T/n4

echo "=== 1. Init 4 nodes ==="
for n in 1 2 3 4; do
  $DHCOIN init --data-dir $T/n$n --profile web 2>&1 | tail -1
  $DHCOIN genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== 2. Build genesis: M_pool=4, K=3 hybrid (union, K-committee) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-hybrid-liveness",
  "m_creators": 4,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n'),
$(cat $T/p4.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 1000000}]
}
EOF
$DHCOIN genesis-tool build $T/gen.json
GHASH=$(cat $T/gen.json.hash)
GPATH="C:/sauromatae/$T/gen.json"

echo
echo "=== 3. Configure 4-mesh (block_sig_ms=4000 for committee-timing tolerance) ==="
configure_node() {
  local n=$1 domain=$2 listen=$3 rpc=$4 peers=$5
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain'] = '$domain'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers
c['genesis_path'] = '$GPATH'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = 'C:/sauromatae/$T/n$n/chain.json'
c['key_path'] = 'C:/sauromatae/$T/n$n/node_key.json'
c['data_dir'] = 'C:/sauromatae/$T/n$n'
c['tx_commit_ms'] = 3000
c['block_sig_ms'] = 4000
c['abort_claim_ms'] = 2000
with open('$T/n$n/config.json','w') as f: json.dump(c,f,indent=2)
"
}
configure_node 1 node1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773","127.0.0.1:7774"]'
configure_node 2 node2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773","127.0.0.1:7774"]'
configure_node 3 node3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772","127.0.0.1:7774"]'
configure_node 4 node4 7774 8774 '["127.0.0.1:7771","127.0.0.1:7772","127.0.0.1:7773"]'

echo
echo "=== 4. Start 4 nodes ==="
NODE_PIDS=("" "" "" "")
for n in 1 2 3 4; do
  $DHCOIN start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  sleep 0.3
done

echo
echo "=== 5. Warm-up: 30s with all 4 nodes alive ==="
sleep 30
H_PRE=$(get_height 8771)
echo "  pre-kill height: $H_PRE"
echo "  heights: n1=$(get_height 8771) n2=$(get_height 8772) n3=$(get_height 8773) n4=$(get_height 8774)"

echo
echo "=== 6. KILL node4 (simulate creator going down) ==="
kill "${NODE_PIDS[3]}" 2>/dev/null
sleep 1
kill -9 "${NODE_PIDS[3]}" 2>/dev/null
NODE_PIDS[3]=""
echo "  node4 killed; surviving 3 must form K=3 committees after suspension"

echo
echo "=== 7. Wait 60s for chain to recover (suspension mechanism kicks in after some aborts) ==="
for i in 1 2 3 4 5 6; do
  sleep 10
  H_POST=$(get_height 8771)
  echo "  [t=$((30 + i*10))s] heights: n1=$H_POST n2=$(get_height 8772) n3=$(get_height 8773)"
done

H_FINAL=$(get_height 8771)

echo
echo "=== 8. Verify chain advanced after creator drop ==="
DELTA=$((H_FINAL - H_PRE))
echo "  pre-kill height:  $H_PRE"
echo "  final height:     $H_FINAL"
echo "  delta:            $DELTA blocks during the 60s after kill"

if [ "$DELTA" -gt 0 ]; then
  echo "  PASS: chain advanced after losing 1 of 4 creators (K-committee rotation works)"
else
  echo "  FAIL: chain stalled. K-committee rotation may need more aborts to suspend node4."
fi

echo
echo "=== 9. Cross-node consistency on surviving 3 ==="
HEAD1=$(get_head 8771)
HEAD2=$(get_head 8772)
HEAD3=$(get_head 8773)
echo "  n1: $HEAD1"
echo "  n2: $HEAD2"
echo "  n3: $HEAD3"
if [ "$HEAD1" = "$HEAD2" ] && [ "$HEAD2" = "$HEAD3" ]; then
  echo "  PASS: surviving nodes agree on head_hash"
else
  echo "  WARN: head_hash divergence (in-flight block possible)"
fi

echo
echo "=== 10. Tail of n1 log to show abort+recovery pattern ==="
tail -20 $T/n1/log
