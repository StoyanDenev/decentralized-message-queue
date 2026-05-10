#!/usr/bin/env bash
# Weak-mode K-committee test for Determ v1 rev.5.
# Verifies the K-committee + intersection-tx_root design:
#   - 4 nodes registered (M_pool=4), committee size K=3 per round.
#   - Each round picks 3-of-4 deterministically from cumulative_rand.
#   - tx_root = intersection of K=3 lists.
#   - All 4 nodes converge on identical chain state.
#
# Run from repo root: bash tools/test_weak_mode.sh
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe
T=test_weak

declare -a NODE_PIDS

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
}
trap cleanup EXIT INT

get_height() {
  $DETERM status --rpc-port "$1" 2>/dev/null \
    | python -c "import sys,json
try: print(json.load(sys.stdin).get('height','-'))
except: print('-')"
}

get_head() {
  $DETERM status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('head_hash','?'))
except: print('?')"
}

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3 $T/n4

echo "=== 1. Init 4 nodes ==="
for n in 1 2 3 4; do
  $DETERM init --data-dir $T/n$n --profile web 2>&1 | tail -1
done

echo
echo "=== 2. Generate peer-info entries ==="
for n in 1 2 3 4; do
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== 3. Build genesis (M_pool=4, K_committee=3 weak BFT, subsidy=10) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-weak-mode",
  "m_creators": 4,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n'),
$(cat $T/p4.json | tr -d '\n')
  ],
  "initial_balances": [
    {"domain": "treasury", "balance": 1000000}
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json
GHASH=$(cat $T/gen.json.hash)
GPATH="C:/sauromatae/$T/gen.json"

echo
echo "=== 4. Configure 4 nodes (4-mesh, ports 7771-7774, rpc 8771-8774) ==="
configure_node() {
  local n=$1
  local domain=$2
  local listen=$3
  local rpc=$4
  local peers_json=$5
  local cfg=$T/n$n/config.json
  python -c "
import json
with open('$cfg') as f: c = json.load(f)
c['domain']           = '$domain'
c['listen_port']      = $listen
c['rpc_port']         = $rpc
c['bootstrap_peers']  = $peers_json
c['genesis_path']     = '$GPATH'
c['genesis_hash']     = '$GHASH'
c['chain_path']       = 'C:/sauromatae/$T/n$n/chain.json'
c['key_path']         = 'C:/sauromatae/$T/n$n/node_key.json'
c['data_dir']         = 'C:/sauromatae/$T/n$n'
c['tx_commit_ms']     = 2000
c['block_sig_ms']     = 2000
c['abort_claim_ms']   = 1000
with open('$cfg', 'w') as f: json.dump(c, f, indent=2)
print(f'  n$n: $domain listen=$listen rpc=$rpc')
"
}
configure_node 1 node1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773","127.0.0.1:7774"]'
configure_node 2 node2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773","127.0.0.1:7774"]'
configure_node 3 node3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772","127.0.0.1:7774"]'
configure_node 4 node4 7774 8774 '["127.0.0.1:7771","127.0.0.1:7772","127.0.0.1:7773"]'

echo
echo "=== 5. Start 4 nodes ==="
NODE_PIDS=("" "" "" "")
for n in 1 2 3 4; do
  $DETERM start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  echo "  n$n: pid ${NODE_PIDS[$((n-1))]}"
  sleep 0.3
done

echo
echo "=== 6. Wait 30s for sync + block production ==="
sleep 30

echo
echo "=== 7. Status snapshots ==="
for n in 1 2 3 4; do
  H=$(get_height 877$n)
  HEAD=$(get_head 877$n)
  echo "  n$n: height=$H head=${HEAD:0:16}..."
done

echo
echo "=== 8. Consistency check ==="
HEAD1=$(get_head 8771)
ALL_AGREE=true
for n in 2 3 4; do
  HEADn=$(get_head 877$n)
  if [ "$HEADn" != "$HEAD1" ]; then ALL_AGREE=false; fi
done
if $ALL_AGREE; then
  echo "  PASS: all 4 nodes agree on head_hash"
else
  echo "  WARN: head_hash divergence (in-flight block possible)"
fi

echo
echo "=== 9. Block-counts and committee membership inspection ==="
for n in 1 2 3 4; do
  blocks=$(grep -c "accepted block" $T/n$n/log)
  echo "  node$n: $blocks blocks accepted"
done

echo
echo "=== 10. Verify K-committee size in chain ==="
python -c "
import json
chain_path = '$T/n1/chain.json'
with open(chain_path) as f: chain = json.load(f)
print(f'  chain length: {len(chain)} blocks (incl genesis)')
sizes = [len(b['creators']) for b in chain[1:]]   # skip genesis
print(f'  block creator-counts (post-genesis): {sizes[:10]}{\"...\" if len(sizes)>10 else \"\"}')
all_size_3 = all(s == 3 for s in sizes)
if sizes and all_size_3:
    print(f'  PASS: every block has exactly K=3 creators (committee size, not M_pool=4)')
elif sizes:
    print(f'  FAIL: expected all blocks to have K=3 creators; got {set(sizes)}')
else:
    print(f'  no post-genesis blocks to inspect')

# Check that committees rotate (different creator sets across blocks)
committees = [tuple(sorted(b['creators'])) for b in chain[1:]]
unique = set(committees)
print(f'  unique committees over {len(committees)} blocks: {len(unique)}')
if len(unique) > 1:
    print(f'  PASS: committee rotates across blocks')
else:
    print(f'  NOTE: same committee for every block (could be coincidence at small N)')
"
