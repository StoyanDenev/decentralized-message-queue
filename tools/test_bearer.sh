#!/usr/bin/env bash
# Bearer-wallet end-to-end test for Determ v1 rev.6.
# Validates the two-tier identity model:
#   1. Create anonymous account A with privkey held only by user.
#   2. Genesis funds A with 100 DTM.
#   3. Create anonymous account B (recipient).
#   4. `determ send_anon` signs TRANSFER from A to B with raw privkey,
#      submits via daemon's `submit_tx` RPC.
#   5. Verify B's balance updates on all 3 nodes (full anonymity flow).
#
# Strong mode for fastest block production.
# Run from repo root: bash tools/test_bearer.sh
set -u
cd "$(dirname "$0")/.."

source tools/common.sh
T=test_bearer

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

get_balance() {
  $DETERM balance "$2" --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('balance','-'))
except: print('-')"
}
get_height() {
  $DETERM status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('height','-'))
except: print('-')"
}

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

echo "=== 1. Init 3 nodes (single_test profile: SINGLE+NONE) ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== 2. Create anonymous account A (sender) ==="
$DETERM account create --out $T/A.json
A_ADDR=$(python -c "import json; print(json.load(open('$T/A.json'))['address'])")
A_PRIV=$(python -c "import json; print(json.load(open('$T/A.json'))['privkey'])")
echo "  A address: $A_ADDR"

echo
echo "=== 3. Create anonymous account B (recipient) ==="
$DETERM account create --out $T/B.json
B_ADDR=$(python -c "import json; print(json.load(open('$T/B.json'))['address'])")
echo "  B address: $B_ADDR"

echo
echo "=== 4. Build genesis: M=K=3 strong, A funded with 100 DTM ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-bearer",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [
    {"domain": "$A_ADDR", "balance": 100}
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json
GHASH=$(cat $T/gen.json.hash)
GPATH="$PROJECT_ROOT/$T/gen.json"

echo
echo "=== 5. Configure 3-mesh ==="
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
c['chain_path'] = '$PROJECT_ROOT/$T/n$n/chain.json'
c['key_path'] = '$PROJECT_ROOT/$T/n$n/node_key.json'
c['data_dir'] = '$PROJECT_ROOT/$T/n$n'
c['tx_commit_ms'] = 2000
c['block_sig_ms'] = 2000
c['abort_claim_ms'] = 1000
with open('$T/n$n/config.json','w') as f: json.dump(c,f,indent=2)
"
}
configure_node 1 node1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 node2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 node3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

echo
echo "=== 6. Start 3 nodes ==="
NODE_PIDS=("" "" "")
for n in 1 2 3; do
  $DETERM start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  sleep 0.3
done

echo
echo "=== 7. Poll until chain advances (height >= 3) ==="
for _ in $(seq 1 30); do
  H=$(get_height 8771)
  if [ "$H" != "-" ] && [ "$H" -ge 3 ] 2>/dev/null; then break; fi
  sleep 0.2
done

echo "  heights: n1=$(get_height 8771) n2=$(get_height 8772) n3=$(get_height 8773)"
echo "  A balance @ n1: $(get_balance 8771 $A_ADDR)  (expected: 100, from genesis)"
echo "  B balance @ n1: $(get_balance 8771 $B_ADDR)  (expected: 0, never funded)"

echo
echo "=== 8. Use send_anon: bearer wallet A signs TRANSFER 25 DTM to B ==="
RESP=$($DETERM send_anon "$B_ADDR" 25 "$A_PRIV" --rpc-port 8771 2>&1)
echo "  RPC response: $RESP"

echo
echo "=== 9. Poll up to 30s for inclusion + cross-node balance convergence ==="
EXPECTED_A=75
EXPECTED_B=25
ALL_PASS=false
for attempt in $(seq 1 30); do
  sleep 1
  ok=true
  for n in 1 2 3; do
    bal_a=$(get_balance 877$n $A_ADDR)
    bal_b=$(get_balance 877$n $B_ADDR)
    if [ "$bal_a" != "$EXPECTED_A" ] || [ "$bal_b" != "$EXPECTED_B" ]; then
      ok=false; break
    fi
  done
  if $ok; then ALL_PASS=true; echo "  converged after ${attempt}s"; break; fi
done

echo
echo "=== 10. Final balances on all 3 nodes ==="
for n in 1 2 3; do
  bal_a=$(get_balance 877$n $A_ADDR)
  bal_b=$(get_balance 877$n $B_ADDR)
  echo "  n$n: A=$bal_a (expect $EXPECTED_A), B=$bal_b (expect $EXPECTED_B)"
done

echo
echo "=== Test summary ==="
if $ALL_PASS; then
  echo "  PASS: bearer-wallet TRANSFER round-trip across 3 nodes via send_anon + submit_tx"
  echo "  - anon account A (key-derived address) signed offline"
  echo "  - submit_tx RPC accepted external signed tx"
  echo "  - tx gossiped, included in block, applied"
  echo "  - both A (debited) and B (credited) balances consistent across cluster"
else
  echo "  FAIL: balance mismatch — see logs"
fi
