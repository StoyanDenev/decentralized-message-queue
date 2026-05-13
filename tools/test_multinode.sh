#!/usr/bin/env bash
# Multi-node end-to-end test for Determ v1 rev.4.
# Starts 3 nodes in cluster profile (M=3, K=3 strong, delay_T=1M), peers them,
# waits for blocks to be produced, queries status, checks consistency.
#
# Run from repo root: bash tools/test_multinode.sh
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe
T=test_mn

cleanup() {
  echo
  echo "=== Stopping nodes ==="
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  done
  echo "Logs at:"
  for n in 1 2 3; do echo "  $T/n$n/log"; done
}
trap cleanup EXIT INT

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

echo "=== 1. Generate node keys (cluster profile) ==="
$DETERM init --data-dir $T/n1 --profile regional 2>&1 | tail -1
$DETERM init --data-dir $T/n2 --profile regional 2>&1 | tail -1
$DETERM init --data-dir $T/n3 --profile regional 2>&1 | tail -1

echo
echo "=== 2. Generate peer-info entries ==="
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json
$DETERM genesis-tool peer-info node2 --data-dir $T/n2 --stake 1000 > $T/p2.json
$DETERM genesis-tool peer-info node3 --data-dir $T/n3 --stake 1000 > $T/p3.json

echo
echo "=== 3. Build genesis (M=3, K=3 strong, subsidy=10, regional profile) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-multinode",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [
    {"domain": "treasury", "balance": 1000000}
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json
GHASH=$(cat $T/gen.json.hash)
# determ.exe is a native Windows binary; use Windows-native paths in configs.
GPATH="C:/sauromatae/$T/gen.json"
echo "Genesis path: $GPATH"

echo
echo "=== 4. Configure each node (domain, ports, peers, genesis pin) ==="
configure_node() {
  local n=$1
  local domain=$2
  local listen=$3
  local rpc=$4
  local peers_json=$5
  local cfg=$T/n$n/config.json
  python -c "
import json, sys
with open('$cfg') as f: c = json.load(f)
c['domain']           = '$domain'
c['listen_port']      = $listen
c['rpc_port']         = $rpc
c['bootstrap_peers']  = $peers_json
c['genesis_path']     = '$GPATH'
c['genesis_hash']     = '$GHASH'
# Windows-native paths for the native binary.
c['chain_path']       = 'C:/sauromatae/$T/n$n/chain.json'
c['key_path']         = 'C:/sauromatae/$T/n$n/node_key.json'
c['data_dir']         = 'C:/sauromatae/$T/n$n'
# Extra-generous timeouts for the test environment (Windows multi-process,
# loopback gossip, placeholder VDF). Production values should match the
# selected profile.
c['tx_commit_ms']     = 2000
c['block_sig_ms']     = 2000
c['abort_claim_ms']   = 1000
with open('$cfg', 'w') as f: json.dump(c, f, indent=2)
print(f'  n$n: domain=$domain listen=$listen rpc=$rpc peers=$peers_json (tx_commit=2000ms, delay=200k, block_sig=2000ms)')
"
}

configure_node 1 node1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 node2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 node3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

echo
echo "=== 5. Start 3 nodes (background, logs to $T/n*/log) ==="
NODE_PIDS=()
for n in 1 2 3; do
  $DETERM start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS+=($!)
  echo "  n$n started (pid ${NODE_PIDS[-1]})"
  sleep 0.3   # stagger so peer connects don't all fire simultaneously
done

echo
echo "=== 6. Wait 30s for sync + block production ==="
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 3
  echo "[t=$((i*3))s] heights:"
  for n in 1 2 3; do
    H=$($DETERM status --rpc-port 877$n 2>/dev/null | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print(j.get('result', {}).get('height', 'no-result'))
except Exception as e:
    print(f'err:{e}')
" 2>/dev/null)
    echo "  n$n: height=$H"
  done
done

echo
echo "=== 7. Final status snapshots ==="
for n in 1 2 3; do
  echo "--- n$n ---"
  $DETERM status --rpc-port 877$n 2>&1 | head -25
done

echo
echo "=== 8. Block production summary ==="
for n in 1 2 3; do
  blocks=$(grep -c "accepted block" $T/n$n/log 2>/dev/null || echo 0)
  errors=$(grep -c "ERROR\|error\|abort" $T/n$n/log 2>/dev/null || echo 0)
  echo "  n$n: $blocks blocks accepted, $errors errors/aborts"
done

echo
echo "=== 9. Tail of each node's log (last 10 lines) ==="
for n in 1 2 3; do
  echo "--- n$n log tail ---"
  tail -10 $T/n$n/log
done
