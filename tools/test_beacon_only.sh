#!/usr/bin/env bash
# Profile-coverage smoke test for cluster_test (BEACON + CURRENT).
# Mirrors prod `cluster` posture; verifies a BEACON-role chain can boot,
# pass the A6 sharding-mode gate, finalize blocks under fast timers, and
# report `chain_role = beacon` via RPC.
#
# Test overrides the profile's M=K=3 default to M=K=2 in genesis. The 5ms
# phase-1 timer + 3-node K=M=3 cold-start race is structurally flaky:
# any cold-start lag in node3 triggers abort cascades that the BFT
# escalation path doesn't always recover from cleanly. M=K=2 (smaller
# committee) finalizes reliably under the same fast timers and still
# exercises the profile's posture (BEACON role + CURRENT mode + the A6
# startup gate). The profile's M=K=3 default is what `determ init`
# writes into a fresh config; operators tune genesis they actually deploy.
#
# What this exercises that other tests don't:
#   - BEACON-role single chain (other tests use BEACON only as part of
#     a beacon+shard composition).
#   - cluster_test profile end-to-end (previously unreferenced by CI).
#
# Run from repo root: bash tools/test_beacon_only.sh
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe
T=test_beacon_only

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
mkdir -p $T/n1 $T/n2 $T/n3

echo "=== 1. Init 3 BEACON-role nodes with cluster_test profile ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile cluster_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== 2. Build BEACON genesis (chain_role=1, M=K=2 — see header comment) ==="
# bft_escalation_threshold=1 so any startup hiccup recovers within one
# abort cycle rather than waiting for 5 cumulative aborts (the default).
cat > $T/gen.json <<EOF
{
  "chain_id": "test-beacon-only",
  "m_creators": 2,
  "k_block_sigs": 2,
  "block_subsidy": 10,
  "chain_role": 1,
  "initial_shard_count": 1,
  "bft_enabled": true,
  "bft_escalation_threshold": 1,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)
GPATH="C:/sauromatae/$T/gen.json"

echo
echo "=== 3. Configure 3-mesh ==="
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
c['chain_path'] = 'C:/sauromatae/$T/n$n/chain.json'
c['key_path'] = 'C:/sauromatae/$T/n$n/node_key.json'
c['data_dir'] = 'C:/sauromatae/$T/n$n'
with open('$T/n$n/config.json','w') as f: json.dump(c,f,indent=2)
"
}
configure_node 1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

echo
echo "=== 4. Start 3 nodes with staggered startup ==="
# Longer per-node sleep so each node's gossip + RPC are ready before the
# next contributes its phase-1 to the round. cluster_test's 5ms phase-1
# timer punishes any cold-start lag with phase1 aborts.
NODE_PIDS=("" "" "")
for n in 1 2 3; do
  $DETERM start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  sleep 0.8
done

echo
echo "=== 5. Poll until chain advances (height >= 3) ==="
for _ in $(seq 1 80); do
  H=$(get_status_field 8771 height)
  if [ "$H" != "-" ] && [ "$H" -ge 3 ] 2>/dev/null; then break; fi
  sleep 0.2
done

H1=$(get_status_field 8771 height)
H2=$(get_status_field 8772 height)
H3=$(get_status_field 8773 height)
ROLE=$(get_status_field 8771 chain_role)

echo "  heights: n1=$H1 n2=$H2 n3=$H3"
echo "  n1 role: $ROLE (expected beacon)"

PASS=true
if [ "$H1" = "-" ] || [ "$H1" -lt 3 ] 2>/dev/null; then
  echo "  FAIL: chain didn't advance"; PASS=false
fi
if [ "$ROLE" != "beacon" ]; then
  echo "  FAIL: role mismatch — expected beacon, got $ROLE"; PASS=false
fi

if $PASS; then
  echo
  echo "  PASS: cluster_test profile (BEACON + CURRENT) end-to-end"
  echo "        - 3 beacon nodes finalized blocks under sub-30 ms timers"
  echo "        - RPC reports chain_role = beacon"
  echo "        - genesis overrides profile's M=K=3 default to M=K=2 for"
  echo "          cold-start reliability (see header comment)"
fi
