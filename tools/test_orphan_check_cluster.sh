#!/usr/bin/env bash
# test_orphan_check_cluster.sh — local 3-node-cluster smoke test for
# tools/operator_chain_orphan_check.sh. NOT a regression test (no
# test_*.sh prefix on the operator-script naming convention — this is a
# scratch driver used by the author to validate the operator tool
# against a live cluster, and is left in tree so others can re-run the
# smoke check after future changes).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

T=test_orphan_check
declare -a NODE_PIDS
cleanup() {
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null; done
  sleep 1
  for pid in "${NODE_PIDS[@]:-}"; do [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null; done
}
trap cleanup EXIT INT

get_height() {
  $DETERM status --rpc-port "$1" 2>/dev/null \
    | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)"
}

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

echo "=== 1. Init 3 nodes ==="
for n in 1 2 3; do
  # M=3 K=3 strong (was K=2 — the S-044/S-045 fix; K>=3 avoids the abort
  # cascade), single-shard (avoids the `web` preset's initial_shard_count>=3
  # requirement, unneeded for a chain-continuity smoke test).
  $DETERM init --data-dir $T/n$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== 2. Build genesis (M=3, K=3; single-shard via single_test profile) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-orphan-check",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)
GPATH="$PROJECT_ROOT/$T/gen.json"

configure_node() {
  local n=$1 listen=$2 rpc=$3 peers_json=$4
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain'] = 'node$n'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers_json
c['genesis_path'] = '$GPATH'
c['genesis_hash'] = '$GHASH'
c['chain_path']   = '$PROJECT_ROOT/$T/n$n/chain.json'
c['key_path']     = '$PROJECT_ROOT/$T/n$n/node_key.json'
c['data_dir']     = '$PROJECT_ROOT/$T/n$n'
c['tx_commit_ms'] = 600
c['block_sig_ms'] = 600
c['abort_claim_ms']= 300
with open('$T/n$n/config.json','w') as f: json.dump(c,f,indent=2)
"
}
configure_node 1 7841 8841 '["127.0.0.1:7842","127.0.0.1:7843"]'
configure_node 2 7842 8842 '["127.0.0.1:7841","127.0.0.1:7843"]'
configure_node 3 7843 8843 '["127.0.0.1:7841","127.0.0.1:7842"]'

echo
echo "=== 3. Start 3 nodes ==="
for n in 1 2 3; do
  $DETERM start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  sleep 0.3
done

echo
echo "=== 4. Wait for chain to reach height >= 5 (~60s budget) ==="
for _ in $(seq 1 120); do
  H=$(get_height 8841)
  if [ "$H" -ge 5 ]; then break; fi
  sleep 0.5
done
echo "  n1 height: $H"
if [ "$H" -lt 3 ]; then
  tail -20 $T/n1/log 2>/dev/null | sed 's/^/    | /'
  trap - EXIT INT; cleanup || true
  echo "  FAIL: test_orphan_check_cluster (chain didn't mine >= 3 blocks; height=$H)"
  exit 1
fi

echo
echo "=== 5. Run operator_chain_orphan_check.sh against n1 (RPC mode) ==="
bash tools/operator_chain_orphan_check.sh --rpc-port 8841
RC=$?
echo "  rc=$RC"

echo
echo "=== 6. JSON mode + --anomalies-only ==="
bash tools/operator_chain_orphan_check.sh --rpc-port 8841 --json
echo
bash tools/operator_chain_orphan_check.sh --rpc-port 8841 --anomalies-only

echo
echo "=== 7. Done ==="
# Marker needs the colon run_all.sh greps for (^\s*PASS:) — a bare "  PASS"
# never matched, so this test counted as a no-marker failure even at rc=0.
trap - EXIT INT
cleanup || true
if [ "$RC" = "0" ]; then
  echo "  PASS: test_orphan_check_cluster"
  exit 0
else
  echo "  FAIL: test_orphan_check_cluster (orphan-check rc=$RC)"
  exit 1
fi
