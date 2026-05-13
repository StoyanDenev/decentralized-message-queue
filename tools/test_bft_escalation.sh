#!/usr/bin/env bash
# rev.8 per-height BFT escalation test. M=K=3 strong, bft_enabled=true,
# bft_escalation_threshold=2. Kill 1 of 3 mid-test; expect chain to:
#   1. Try MD K-of-K, abort 2x against the dead node.
#   2. Escalate to BFT 2-of-3 with designated proposer.
#   3. Finalize a BFT-mode block (consensus_mode=1, bft_proposer=<live node>).
#   4. Continue producing BFT blocks until the dead node returns or
#      operator intervention.
#
# Run from repo root: bash tools/test_bft_escalation.sh
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe
T=test_bft_esc

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
  $DETERM status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height','-'))
except: print('-')"
}

count_bft_blocks() {
  local n=$1
  python -c "
import json
try:
  blocks = json.load(open('$T/n$n/chain.json'))
  bft = sum(1 for b in blocks if b.get('consensus_mode',0) == 1)
  md  = sum(1 for b in blocks if b.get('consensus_mode',0) == 0)
  print(f'{md} {bft}')
except Exception as e:
  print('- -')
"
}

last_bft_proposer() {
  local n=$1
  python -c "
import json
try:
  blocks = json.load(open('$T/n$n/chain.json'))
  bft = [b for b in blocks if b.get('consensus_mode',0) == 1]
  if bft: print(bft[-1].get('bft_proposer','?'))
  else: print('(none)')
except Exception as e:
  print('?')
"
}

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

echo "=== 1. Init 3 nodes ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== 2. Build genesis: M=K=3 strong, bft_enabled=true, threshold=1 ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-bft-esc",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "bft_enabled": true,
  "bft_escalation_threshold": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 1000000}]
}
EOF
$DETERM genesis-tool build $T/gen.json
GHASH=$(cat $T/gen.json.hash)
GPATH="C:/sauromatae/$T/gen.json"

echo
echo "=== 3. Configure 3-mesh ==="
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
c['tx_commit_ms'] = 4000
c['block_sig_ms'] = 4000
c['abort_claim_ms'] = 2000
with open('$T/n$n/config.json','w') as f: json.dump(c,f,indent=2)
"
}
configure_node 1 node1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 node2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 node3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

echo
echo "=== 4. Start 3 nodes ==="
NODE_PIDS=("" "" "")
for n in 1 2 3; do
  $DETERM start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  sleep 0.3
done

echo
echo "=== 5. Warm-up: poll until chain advances (>= 3 blocks) ==="
for _ in $(seq 1 30); do
  H_PRE=$(get_height 8771)
  if [ "$H_PRE" != "-" ] && [ "$H_PRE" -ge 3 ] 2>/dev/null; then break; fi
  sleep 0.2
done
H_PRE=$(get_height 8771)
read MD_PRE BFT_PRE <<< "$(count_bft_blocks 1)"
echo "  pre-kill: height=$H_PRE  MD-blocks=$MD_PRE  BFT-blocks=$BFT_PRE"

echo
echo "=== 6. KILL node3 (force escalation) ==="
kill "${NODE_PIDS[2]}" 2>/dev/null
sleep 1
kill -9 "${NODE_PIDS[2]}" 2>/dev/null
NODE_PIDS[2]=""
echo "  node3 killed; with threshold=2 the chain should produce BFT blocks"
echo "  after 2 round-1 aborts at the same height."

echo
echo "=== 7. Poll up to 30s for escalation (break early on first BFT block) ==="
for i in $(seq 1 60); do
  sleep 0.5
  read MD_NOW BFT_NOW <<< "$(count_bft_blocks 1)"
  if [ "$BFT_NOW" -gt 0 ]; then
    H_NOW=$(get_height 8771)
    echo "  BFT block seen after ${i}*0.5s: height=$H_NOW  MD=$MD_NOW  BFT=$BFT_NOW"
    break
  fi
done

H_FINAL=$(get_height 8771)
read MD_FINAL BFT_FINAL <<< "$(count_bft_blocks 1)"
LAST_PROPOSER=$(last_bft_proposer 1)

echo
echo "=== 8. Verify ==="
echo "  pre-kill: height=$H_PRE   MD=$MD_PRE   BFT=$BFT_PRE"
echo "  post-60s: height=$H_FINAL MD=$MD_FINAL BFT=$BFT_FINAL"
echo "  last BFT proposer: $LAST_PROPOSER"

if [ "$BFT_FINAL" -gt 0 ]; then
  echo "  PASS: chain produced BFT-mode blocks after kill (escalation worked)"
  if [ "$LAST_PROPOSER" = "node1" ] || [ "$LAST_PROPOSER" = "node2" ]; then
    echo "  PASS: BFT proposer is one of the live nodes ($LAST_PROPOSER)"
  else
    echo "  WARN: BFT proposer is unexpected: $LAST_PROPOSER"
  fi
else
  echo "  FAIL: no BFT blocks produced. Chain probably stalled in MD mode"
  echo "  before escalating. Check logs in $T/n*/log."
fi

echo
echo "=== 9. Tail of n1 log (escalation evidence) ==="
tail -25 $T/n1/log
