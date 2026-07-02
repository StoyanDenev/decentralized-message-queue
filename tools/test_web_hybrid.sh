#!/usr/bin/env bash
# Profile-coverage smoke test for web_test (SHARD + EXTENDED, M=4 K=3 hybrid).
# Mirrors prod `web` posture (retuned M=3/K=2 -> M=4/K=3 by the S-044/S-045 fix);
# verifies a SHARD-role chain in EXTENDED mode with K<M (hybrid committee)
# SUSTAINS production.
#
# What this exercises that other tests don't:
#   - K<M hybrid committee finalization (every other regression test uses
#     K=M strong). With M=4 K=3, each round selects a 3-of-4 committee.
#   - SHARD+EXTENDED posture (initial_shard_count >= 3 invariant satisfied).
#   - web_test profile end-to-end (previously unreferenced by CI).
#
# Note: like every green cluster sibling (test_multinode.sh et al.), the
# config overrides the profile's phase timers to test-environment values
# (2000/2000/1000 ms). The raw web_test 5/5/3 ms timers are below Windows
# timer granularity and deadlock a live 3-process cluster via spurious
# abort quorums; production deployments keep the profile values.
#
# Run from repo root: bash tools/test_web_hybrid.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

T=test_web_hybrid

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
mkdir -p $T/n1 $T/n2 $T/n3 $T/n4

echo "=== 1. Init 4 SHARD-role nodes with web_test profile (M=4 K=3, S-044/S-045 fix) ==="
for n in 1 2 3 4; do
  $DETERM init --data-dir $T/n$n --profile web_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== 2. Build SHARD genesis (M=4 K=3 hybrid, EXTENDED needs initial_shard_count=3) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-web-hybrid",
  "m_creators": 4,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 0,
  "initial_shard_count": 3,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n'),
$(cat $T/p4.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)
GPATH="$PROJECT_ROOT/$T/gen.json"

echo
echo "=== 3. Configure 4-mesh ==="
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
c['chain_path'] = '$PROJECT_ROOT/$T/n$n/chain.json'
c['key_path'] = '$PROJECT_ROOT/$T/n$n/node_key.json'
c['data_dir'] = '$PROJECT_ROOT/$T/n$n'
# Test-environment timer overrides (same values as test_multinode.sh /
# test_sharded_smoke.sh). The raw web_test 5/5/3 ms phase timers sit below
# Windows ~15.6 ms timer granularity, producing spurious phase timeouts that
# generate abort claims and slow convergence. At the fixed M=4/K=3 posture the
# max(2,K-1)=2 claim floor means a lone straggle no longer excludes anyone, so
# the chain still converges — but the relaxed timers keep the run stable and
# fast on CI. Production deployments keep the profile's phase-timer values.
c['tx_commit_ms'] = 2000
c['block_sig_ms'] = 2000
c['abort_claim_ms'] = 1000
with open('$T/n$n/config.json','w') as f: json.dump(c,f,indent=2)
"
}
configure_node 1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773","127.0.0.1:7774"]'
configure_node 2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773","127.0.0.1:7774"]'
configure_node 3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772","127.0.0.1:7774"]'
configure_node 4 7774 8774 '["127.0.0.1:7771","127.0.0.1:7772","127.0.0.1:7773"]'

echo
echo "=== 4. Start 4 nodes ==="
NODE_PIDS=("" "" "" "")
for n in 1 2 3 4; do
  $DETERM start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  sleep 0.3
done

echo
echo "=== 5. Poll for SUSTAINED production (height >= 5) ==="
# S-044/S-045 FIXED: the web profile is now M=4/K=3 (was M=3/K=2). K>=3
# disarms the S-044 single-claim abort cascade (the F-a max(2,K-1) quorum
# floor is a no-op at K=3 but the quorum is now 2 corroborating claims, so a
# lone straggle excludes nobody), and MD margin M-K=1 means a single dead
# member still forms a full K-of-K MD 3-of-3 committee among the survivors —
# no escalation dependence. The old KNOWN-BUG note (K=2 cascade wedge) is
# resolved; the sustained-production bar (height >= 5) is RESTORED.
for _ in $(seq 1 300); do
  H=$(get_status_field 8771 height)
  if [ "$H" != "-" ] && [ "$H" -ge 5 ] 2>/dev/null; then break; fi
  sleep 0.2
done

H1=$(get_status_field 8771 height)
ROLE=$(get_status_field 8771 chain_role)

# Inspect the highest EXISTING block's committee size — must be 3 (hybrid
# K=3 of M=4). Height H means blocks 0..H-1 exist; block H-1 is the newest.
if [[ "$H1" =~ ^[0-9]+$ ]] && [ "$H1" -ge 2 ]; then
  TOP=$((H1 - 1))
else
  TOP=1
fi
COMMITTEE_SIZE=$($DETERM show-block "$TOP" --rpc-port 8771 2>/dev/null | python -c "
import sys, json
try:
  b = json.load(sys.stdin)
  print(len(b.get('creators', [])))
except Exception:
  print('-')
")

echo "  height: $H1"
echo "  n1 role: $ROLE (expected shard)"
echo "  block #$TOP committee size: $COMMITTEE_SIZE (expected 3 — K=3 of M=4)"

PASS=true
FAILED=0
if ! [[ "$H1" =~ ^[0-9]+$ ]] || [ "$H1" -lt 5 ]; then
  echo "  bad: sustained production bar not met (height=$H1, want >= 5) — S-044/S-045 regression?"; PASS=false; FAILED=$((FAILED+1))
fi
if [ "$ROLE" != "shard" ]; then
  echo "  bad: role mismatch — expected shard, got $ROLE"; PASS=false; FAILED=$((FAILED+1))
fi
if [ "$COMMITTEE_SIZE" != "3" ]; then
  echo "  bad: committee size $COMMITTEE_SIZE != 3 (hybrid K<M not exercised)"; PASS=false; FAILED=$((FAILED+1))
fi

if $PASS; then
  echo
  echo "  - 4 shard nodes booted web_test (EXTENDED, M=4/K=3) and sustained production (height >= 5)"
  echo "  - hybrid K=3 committee selected (not full M=4) — selection + finalization sound"
  echo "  - initial_shard_count=3 satisfied EXTENDED's S>=3 gate"
  echo "  - S-044/S-045 FIXED: K>=3 + MD margin 1 — no abort-cascade wedge"
  echo "  PASS: test_web_hybrid"
  exit 0
else
  echo "  --- n1 log tail ---"
  tail -15 $T/n1/log 2>/dev/null | sed 's/^/    | /'
  echo "  FAIL: test_web_hybrid ($FAILED checks failed)"
  exit 1
fi
