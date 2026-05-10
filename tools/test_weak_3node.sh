#!/usr/bin/env bash
# Minimal weak-mode test: M=3 pool, K=2 committee.
# Each round picks 2-of-3 creators deterministically from cumulative_rand.
# tx_root = intersection of K=2 lists.
#
# Run from repo root: bash tools/test_weak_3node.sh
set -u
cd "$(dirname "$0")/.."

DHCOIN=build/Release/dhcoin.exe
T=test_weak3

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
  $DHCOIN status --rpc-port "$1" 2>/dev/null \
    | python -c "import sys,json
try: print(json.load(sys.stdin).get('height','-'))
except: print('-')"
}
get_head() {
  $DHCOIN status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('head_hash','?'))
except: print('?')"
}

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

echo "=== Init 3 nodes (web profile) ==="
for n in 1 2 3; do
  $DHCOIN init --data-dir $T/n$n --profile web 2>&1 | tail -1
  $DHCOIN genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== Build genesis (M_pool=3, K_committee=2 weak BFT) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-weak-3node",
  "m_creators": 3,
  "k_block_sigs": 2,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 1000000}]
}
EOF
$DHCOIN genesis-tool build $T/gen.json
GHASH=$(cat $T/gen.json.hash)
GPATH="C:/sauromatae/$T/gen.json"

echo
echo "=== Configure 3-mesh ==="
configure_node() {
  local n=$1 domain=$2 listen=$3 rpc=$4 peers_json=$5
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain'] = '$domain'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers_json
c['genesis_path'] = '$GPATH'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = 'C:/sauromatae/$T/n$n/chain.json'
c['key_path'] = 'C:/sauromatae/$T/n$n/node_key.json'
c['data_dir'] = 'C:/sauromatae/$T/n$n'
c['tx_commit_ms'] = 2000
c['block_sig_ms'] = 2000
c['abort_claim_ms'] = 1000
with open('$T/n$n/config.json','w') as f: json.dump(c,f,indent=2)
print(f'  n$n: $domain listen=$listen rpc=$rpc')
"
}
configure_node 1 node1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 node2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 node3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

echo
echo "=== Start 3 nodes ==="
NODE_PIDS=("" "" "")
for n in 1 2 3; do
  $DHCOIN start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  echo "  n$n: pid ${NODE_PIDS[$((n-1))]}"
  sleep 0.3
done

echo
echo "=== Wait 30s ==="
sleep 30

echo
echo "=== Status ==="
for n in 1 2 3; do
  H=$(get_height 877$n)
  HEAD=$(get_head 877$n)
  echo "  n$n: height=$H head=${HEAD:0:16}..."
done

echo
echo "=== Consistency ==="
HEAD1=$(get_head 8771)
ALL_AGREE=true
for n in 2 3; do
  Hn=$(get_head 877$n)
  if [ "$Hn" != "$HEAD1" ]; then ALL_AGREE=false; fi
done
if $ALL_AGREE; then
  echo "  PASS: all 3 nodes agree on head_hash"
else
  echo "  WARN: divergence"
fi

echo
echo "=== Block-counts ==="
for n in 1 2 3; do
  blocks=$(grep -c "accepted block" $T/n$n/log)
  echo "  node$n: $blocks blocks accepted"
done

echo
echo "=== K-committee verification ==="
python -c "
import json
with open('$T/n1/chain.json') as f: chain = json.load(f)
print(f'  chain length: {len(chain)} blocks')
sizes = [len(b['creators']) for b in chain[1:]]
print(f'  block creator-counts (post-genesis): {sizes}')
if sizes and all(s == 2 for s in sizes):
    print(f'  PASS: every block has exactly K=2 creators (not M_pool=3)')
elif sizes:
    print(f'  FAIL: expected K=2; got {set(sizes)}')

committees = [tuple(sorted(b['creators'])) for b in chain[1:]]
unique = set(committees)
print(f'  unique committees over {len(committees)} blocks: {len(unique)}')
print(f'  committees: {sorted(unique)}')
if len(unique) > 1:
    print(f'  PASS: K-committee rotates across blocks')
"
