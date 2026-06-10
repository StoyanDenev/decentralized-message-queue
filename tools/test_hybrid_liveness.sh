#!/usr/bin/env bash
# Hybrid-mode liveness test for Determ v1 rev.6.
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

source tools/common.sh
T=test_hyb_live

pass_count=0; fail_count=0

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
get_head() {
  $DETERM status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('head_hash','?'))
except: print('?')"
}

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3 $T/n4

echo "=== 1. Init 4 nodes ==="
# regional_test: the only K<M profile that boots a 1-shard genesis
# (SHARD/CURRENT/MODERN). The genesis below overrides M/K to 4/3; the profile
# only pins sharding_mode/chain_role/crypto/timing. Do NOT use 'web' — it is
# EXTENDED sharding mode and the A6 boot guard rejects a 1-shard genesis.
for n in 1 2 3 4; do
  $DETERM init --data-dir $T/n$n --profile regional_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
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
$DETERM genesis-tool build $T/gen.json
GHASH=$(cat $T/gen.json.hash)
GPATH="$PROJECT_ROOT/$T/gen.json"

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
c['chain_path'] = '$PROJECT_ROOT/$T/n$n/chain.json'
c['key_path'] = '$PROJECT_ROOT/$T/n$n/node_key.json'
c['data_dir'] = '$PROJECT_ROOT/$T/n$n'
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
  $DETERM start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  sleep 0.3
done

echo
echo "=== 5. Warm-up: 30s with all 4 nodes alive ==="
sleep 30
H_PRE=$(get_height 8771)
echo "  pre-kill height: $H_PRE"
echo "  heights: n1=$(get_height 8771) n2=$(get_height 8772) n3=$(get_height 8773) n4=$(get_height 8774)"
# Fail-closed guard: H_PRE must be numeric (not the '-' dead-RPC sentinel)
# and > 0 (warm-up actually produced blocks) before any arithmetic on it.
case "$H_PRE" in
  ''|*[!0-9]*)
    echo "  bad: warm-up height is non-numeric ('$H_PRE') — RPC dead or nodes failed to boot"
    echo
    echo "  Diagnostics: tail of n1 log:"
    tail -20 $T/n1/log 2>/dev/null | sed 's/^/    | /'
    echo "  FAIL: test_hybrid_liveness (warm-up RPC dead / nodes failed to boot)"
    exit 1
    ;;
  0)
    echo "  bad: warm-up produced no blocks (height 0)"
    echo
    echo "  Diagnostics: tail of n1 log:"
    tail -20 $T/n1/log 2>/dev/null | sed 's/^/    | /'
    echo "  FAIL: test_hybrid_liveness (warm-up produced no blocks)"
    exit 1
    ;;
  *)
    echo "  ok: warm-up height $H_PRE > 0"
    pass_count=$((pass_count + 1))
    ;;
esac

echo
echo "=== 6. KILL node4 (simulate creator going down) ==="
kill "${NODE_PIDS[3]}" 2>/dev/null
sleep 1
kill -9 "${NODE_PIDS[3]}" 2>/dev/null
NODE_PIDS[3]=""
echo "  node4 killed; surviving 3 must form K=3 committees after suspension"

echo
echo "=== 7. Poll up to 150s for chain to recover (break early once height advances; suspension kicks in after some aborts) ==="
for i in $(seq 1 30); do
  sleep 5
  H_NOW=$(get_height 8771)
  case "$H_NOW" in
    ''|*[!0-9]*)
      echo "  [t=+$((i*5))s] n1 RPC not answering"
      continue
      ;;
  esac
  echo "  [t=+$((i*5))s] heights: n1=$H_NOW n2=$(get_height 8772) n3=$(get_height 8773)"
  if [ "$H_NOW" -gt "$H_PRE" ]; then
    echo "  chain advanced after ~$((i*5))s post-kill"
    break
  fi
done

H_FINAL=$(get_height 8771)

echo
echo "=== 8. Verify chain advanced after creator drop ==="
# Fail-closed guard: never feed the '-' dead-RPC sentinel into arithmetic.
case "$H_FINAL" in
  ''|*[!0-9]*)
    echo "  bad: final height is non-numeric ('$H_FINAL') — n1 RPC dead after kill"
    fail_count=$((fail_count + 1))
    DELTA=0
    ;;
  *)
    DELTA=$((H_FINAL - H_PRE))
    ;;
esac
echo "  pre-kill height:  $H_PRE"
echo "  final height:     $H_FINAL"
echo "  delta:            $DELTA blocks after kill"

if [ "$DELTA" -gt 0 ]; then
  echo "  ok: chain advanced after losing 1 of 4 creators (K-committee rotation works)"
  pass_count=$((pass_count + 1))
else
  echo "  bad: chain stalled within the 150s window. K-committee rotation /"
  echo "       abort-driven suspension failed to exclude the dead creator."
  fail_count=$((fail_count + 1))
fi

echo
echo "=== 9. Cross-node consistency on surviving 3 ==="
HEAD1=$(get_head 8771)
HEAD2=$(get_head 8772)
HEAD3=$(get_head 8773)
echo "  n1: $HEAD1"
echo "  n2: $HEAD2"
echo "  n3: $HEAD3"
# Fail-closed: '?' is the dead-RPC sentinel from get_head — three identical
# sentinels must never count as agreement.
BAD_HEAD=0
for H in "$HEAD1" "$HEAD2" "$HEAD3"; do
  case "$H" in ''|'?') BAD_HEAD=1 ;; esac
done
if [ "$BAD_HEAD" -ne 0 ]; then
  echo "  bad: one or more surviving nodes returned no head_hash (dead RPC)"
  fail_count=$((fail_count + 1))
elif [ "$HEAD1" = "$HEAD2" ] && [ "$HEAD2" = "$HEAD3" ]; then
  echo "  ok: surviving nodes agree on head_hash"
  pass_count=$((pass_count + 1))
else
  echo "  WARN: head_hash divergence (in-flight block possible)"
fi

echo
echo "=== 10. Tail of n1 log to show abort+recovery pattern ==="
tail -20 $T/n1/log 2>/dev/null | sed 's/^/    | /'

echo
echo "=== 11. Summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" -eq 0 ]; then
  echo "  PASS: test_hybrid_liveness"
  exit 0
else
  echo "  FAIL: test_hybrid_liveness ($fail_count checks failed)"
  exit 1
fi
