#!/usr/bin/env bash
# Adversarial integration test for Determ v1 rev.4.
# Verifies:
#   1. Strong mode (M=3, K=3) produces blocks under happy path (extends the
#      multi-node test by also exercising tx submission).
#   2. Tx submission round-trip: TRANSFER from node1 → anon recipient,
#      balance updates visible on all 3 nodes (validates account_state apply
#      and the Ed25519 sig path through the daemon's RPC + producer + apply).
#
# What we don't yet test (documented design limitations / out of v1 scope):
#   - Weak mode (K<M) end-to-end. Honest v1 finalize requires M sigs to
#     avoid silent forks (different peers collecting different K-subsets);
#     true K-of-M needs fork-choice logic. Genesis still accepts K<M as a
#     forward-compatible parameter; node treats it as M for now.
#   - "Kill creator mid-round" with M=3, only 3 registered creators: Phase 1
#     unanimity guarantees no progress. Needs ≥4 registered creators so
#     selection has slack to skip the dead one.
#
# Run from repo root: bash tools/test_adversarial.sh
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe
T=test_adv

# Track node PIDs for cleanup. NOTE: we may stop node3 mid-test, so we
# clear its slot to avoid double-kill complaints.
declare -a NODE_PIDS

cleanup() {
  echo
  echo "=== Stopping any remaining nodes ==="
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  done
  echo "Logs at: $T/n*/log"
}
trap cleanup EXIT INT

# `determ status` and `determ balance` already unwrap the JSON-RPC `result`
# envelope, so the CLI's stdout is the result object directly.
get_height() {
  local port=$1
  $DETERM status --rpc-port "$port" 2>/dev/null \
    | python -c "import sys,json
try: print(json.load(sys.stdin).get('height','-'))
except: print('-')"
}

get_balance() {
  local port=$1
  local domain=$2
  $DETERM balance "$domain" --rpc-port "$port" 2>/dev/null \
    | python -c "import sys,json
try: print(json.load(sys.stdin).get('balance','-'))
except: print('-')"
}

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

echo "=== 1. Init 3 nodes (web profile, will override to weak K=2) ==="
$DETERM init --data-dir $T/n1 --profile web 2>&1 | tail -1
$DETERM init --data-dir $T/n2 --profile web 2>&1 | tail -1
$DETERM init --data-dir $T/n3 --profile web 2>&1 | tail -1

echo
echo "=== 2. Generate peer-info entries ==="
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json
$DETERM genesis-tool peer-info node2 --data-dir $T/n2 --stake 1000 > $T/p2.json
$DETERM genesis-tool peer-info node3 --data-dir $T/n3 --stake 1000 > $T/p3.json

echo
echo "=== 3. Create anonymous recipient account ==="
$DETERM account create > $T/recipient.json
RECIPIENT=$(python -c "import json; print(json.load(open('$T/recipient.json'))['address'])")
echo "  recipient address: $RECIPIENT"

echo
echo "=== 4. Build genesis (M=3, K=3 strong BFT, subsidy=10) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-adversarial",
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
GPATH="C:/sauromatae/$T/gen.json"

echo
echo "=== 5. Configure nodes (extra-generous timers for stable Windows test) ==="
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
print(f'  n$n: domain=$domain listen=$listen rpc=$rpc')
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
  echo "  n$n: pid ${NODE_PIDS[$((n-1))]}"
  sleep 0.3
done

echo
echo "=== 7. Wait 30s for sync + block production (gives node1 enough subsidy to fund a TRANSFER) ==="
sleep 30

H1=$(get_height 8771)
H2=$(get_height 8772)
H3=$(get_height 8773)
echo "  heights:  n1=$H1  n2=$H2  n3=$H3"

if [ "$H1" = "-" ] || [ "$H1" = "1" ]; then
  echo "  FAIL: n1 not producing blocks"; exit 1
fi
echo "  PASS: blocks producing under strong BFT (M=3, K=3)"

echo
echo "=== 8. Check creator balances (should have block subsidy accumulated) ==="
for n in 1 2 3; do
  bal=$(get_balance 877$n "node$n")
  echo "  node$n balance (via rpc 877$n): $bal"
done

echo
echo "=== 9. Submit TRANSFER from node1 → recipient (1 DTM, well within node1's balance) ==="
RESP=$($DETERM send "$RECIPIENT" 1 --rpc-port 8771 2>&1)
echo "  RPC response: $RESP"

echo
echo "=== 10. Wait 12s for inclusion (a few rounds at ~4 s/block) ==="
sleep 12

echo
echo "=== 11. Verify recipient balance == 1 on all 3 nodes ==="
ALL_AGREE=true
for n in 1 2 3; do
  bal=$(get_balance 877$n "$RECIPIENT")
  echo "  recipient via rpc 877$n: $bal"
  if [ "$bal" != "1" ]; then ALL_AGREE=false; fi
done
if $ALL_AGREE; then
  echo "  PASS: tx round-trip confirmed across all nodes"
else
  echo "  FAIL: balance disagreement (expected 1)"
fi

echo
echo "=== 12. Final consistency check across all 3 nodes ==="
get_head() {
  $DETERM status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('head_hash','?'))
except: print('?')"
}
HEAD1=$(get_head 8771)
HEAD2=$(get_head 8772)
HEAD3=$(get_head 8773)
echo "  n1 head_hash: $HEAD1"
echo "  n2 head_hash: $HEAD2"
echo "  n3 head_hash: $HEAD3"
if [ "$HEAD1" = "$HEAD2" ] && [ "$HEAD2" = "$HEAD3" ]; then
  echo "  PASS: all nodes agree on head_hash"
else
  echo "  NOTE: hash divergence possible during in-flight block; check heights too"
fi

echo
echo "=== 13. Final block counts in logs ==="
for n in 1 2 3; do
  blocks=$(grep -c "accepted block" $T/n$n/log 2>/dev/null || echo 0)
  echo "  node$n: $blocks blocks accepted"
done

echo
echo "=== Test summary ==="
echo "  Strong BFT mode (K=M=3): blocks producing ✓"
echo "  Tx round-trip via RPC submit + gossip + apply: $($ALL_AGREE && echo "✓" || echo "✗")"
echo "  Cross-node consistency: $([ "$HEAD1" = "$HEAD2" ] && [ "$HEAD2" = "$HEAD3" ] && echo "✓" || echo "✗")"
