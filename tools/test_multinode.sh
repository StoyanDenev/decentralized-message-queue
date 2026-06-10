#!/usr/bin/env bash
# Multi-node end-to-end test for Determ v1 rev.4.
# Starts 3 nodes in cluster profile (M=3, K=3 strong, delay_T=1M), peers them,
# waits for blocks to be produced, queries status, checks consistency.
#
# Run from repo root: bash tools/test_multinode.sh
set -u
cd "$(dirname "$0")/.."

source tools/common.sh
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
# Abnormal-exit guard: if the script dies before the final summary, still
# stop the nodes and emit a last-line FAIL marker for run_all.sh.
# cleanup() itself must never call exit (it must not clobber exit codes).
on_abort() {
  trap - EXIT INT
  cleanup
  echo "  FAIL: test_multinode (aborted before summary)"
  exit 1
}
trap on_abort EXIT INT

# Fail counter: every machine-checked failure site must bump this.
# Step 6b carries the assertions: per-node numeric RPC height >= 2 and
# 64-hex head_hash agreement across all 3 nodes (resampled for in-flight
# skew). Historically this script was a pure smoke test with zero
# machine-checked assertions and an unconditional PASS.
FAILS=0

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
GPATH="$PROJECT_ROOT/$T/gen.json"
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
c['chain_path']       = '$PROJECT_ROOT/$T/n$n/chain.json'
c['key_path']         = '$PROJECT_ROOT/$T/n$n/node_key.json'
c['data_dir']         = '$PROJECT_ROOT/$T/n$n'
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

echo
echo "=== 6. Wait 30s for sync + block production ==="
# (The old extractor here read j['result']['height'] — a nested envelope the
# status RPC never returns; it printed 'no-result' on healthy nodes. The
# flat .get('height') shape matches every green sibling.)
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 3
  echo "[t=$((i*3))s] heights:"
  for n in 1 2 3; do
    echo "  n$n: height=$(get_height 877$n)"
  done
done

echo
echo "=== 6b. Assertions: per-node liveness + head agreement ==="
# De-vacuation: this test previously had ZERO machine-checked assertions
# (unconditional PASS). Liveness is asserted from RPC height (log greps are
# stdio-buffer-unreliable); agreement uses the weak_mode resample pattern
# (blocks land ~1/s, so sequential fetches can straddle a boundary).
for n in 1 2 3; do
  H=$(get_height 877$n)
  if [[ ! "$H" =~ ^[0-9]+$ ]] || [ "$H" -lt 2 ]; then
    echo "  bad: n$n height '$H' is not numeric >= 2 (dead RPC or no blocks)"
    FAILS=$((FAILS+1))
  else
    echo "  ok: n$n height $H >= 2"
  fi
done
# No-fork check by AGREEMENT ON A CONFIRMED PAST BLOCK, not the live tip:
# this chain mints ~10+ blocks/s, so sequential head_hash fetches are
# perpetually 1-2 blocks apart (tip skew, not divergence). Pick a height
# well below every node's tip and require all three return the SAME
# block_hash there — a true no-fork assertion robust to tip skew.
block_hash_at() {
  # The `block` RPC returns the block BODY (no block_hash field — clients
  # recompute it). The `headers` RPC carries the server-computed block_hash,
  # so use it to compare a confirmed block across nodes.
  $DETERM headers --from "$2" --count 1 --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try:
    hs=json.load(sys.stdin).get('headers',[])
    print(hs[0].get('block_hash','?') if hs else '?')
except: print('?')"
}
MINH=$(get_height 8771)
for n in 2 3; do
  Hn=$(get_height 877$n)
  [[ "$Hn" =~ ^[0-9]+$ ]] && [ "$Hn" -lt "$MINH" ] && MINH=$Hn
done
if [[ "$MINH" =~ ^[0-9]+$ ]] && [ "$MINH" -ge 4 ]; then
  CHECK_H=$((MINH - 2))   # a height every node has confirmed
  BH1=$(block_hash_at 8771 "$CHECK_H")
  if [[ ! "$BH1" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "  bad: n1 block_hash at height $CHECK_H not 64 hex (got '$BH1')"
    FAILS=$((FAILS+1))
  else
    SAME=true
    for n in 2 3; do
      BHn=$(block_hash_at 877$n "$CHECK_H")
      if [ "$BHn" != "$BH1" ]; then
        echo "  bad: n$n block_hash@$CHECK_H=$BHn != n1=$BH1 (FORK)"
        SAME=false
      fi
    done
    $SAME && echo "  ok: all 3 nodes agree on block_hash @ height $CHECK_H (no fork)"
    $SAME || FAILS=$((FAILS+1))
  fi
else
  echo "  bad: min height '$MINH' < 4 — cannot pick a confirmed common block"
  FAILS=$((FAILS+1))
fi

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
# Raw node-log lines are prefixed so they can never collide with
# run_all.sh's ^\s*PASS: / ^\s*FAIL: marker grep over the last 10 lines.
for n in 1 2 3; do
  echo "--- n$n log tail ---"
  tail -10 $T/n$n/log 2>/dev/null | sed 's/^/    | /'
done

echo
echo "=== Test summary ==="
trap - EXIT INT
cleanup
if [ "$FAILS" -eq 0 ]; then
  echo "  PASS: test_multinode"
  exit 0
else
  echo "  FAIL: test_multinode ($FAILS checks failed)"
  exit 1
fi
