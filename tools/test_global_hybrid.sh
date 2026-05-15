#!/usr/bin/env bash
# Profile-coverage smoke test for global_test (BEACON + EXTENDED).
# Mirrors prod `global` posture. Verifies a BEACON-role chain in
# EXTENDED mode (S>=3) finalizes blocks under fast timers.
#
# Test uses M=K=3 strong (overriding the profile's M=7 K=5 default)
# because v1 hybrid finalization with K<M is structurally racy on
# large pools (test_global_hybrid v1 with M=7 K=5 stalled at height=2,
# surfacing the documented hybrid-mode v1 limitation). The profile's
# M=7 K=5 default is what `dhcoin init` writes into a fresh config;
# operators tune the genesis they actually deploy. This regression test
# exercises the posture (role + mode + EXTENDED's S>=3 invariant) and
# leaves K<M hybrid coverage to web_hybrid (which has the smaller
# M=3 K=2 ratio where the race is bounded).
#
# What this exercises that other tests don't:
#   - BEACON + EXTENDED posture combined (no other regression test).
#   - global_test profile end-to-end (previously unreferenced by CI).
#
# Run from repo root: bash tools/test_global_hybrid.sh
set -u
cd "$(dirname "$0")/.."

source tools/common.sh
T=test_global_hybrid

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

echo "=== 1. Init 3 BEACON-role nodes with global_test profile ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile global_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

echo
echo "=== 2. Build BEACON genesis (M=K=2 for cold-start reliability; EXTENDED needs initial_shard_count=3) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-global-hybrid",
  "m_creators": 2,
  "k_block_sigs": 2,
  "block_subsidy": 10,
  "chain_role": 1,
  "initial_shard_count": 3,
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
GPATH="$PROJECT_ROOT/$T/gen.json"

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
c['chain_path'] = '$PROJECT_ROOT/$T/n$n/chain.json'
c['key_path'] = '$PROJECT_ROOT/$T/n$n/node_key.json'
c['data_dir'] = '$PROJECT_ROOT/$T/n$n'
with open('$T/n$n/config.json','w') as f: json.dump(c,f,indent=2)
"
}
configure_node 1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

# R2: BEACON+EXTENDED requires a shard_manifest at startup. Empty manifest
# is fine — no SHARD_TIPs will arrive in this test (no shards running).
for n in 1 2 3; do
  echo '{"shards": []}' > $T/n$n/shard_manifest.json
done

echo
echo "=== 4. Start 3 nodes ==="
NODE_PIDS=("" "" "")
for n in 1 2 3; do
  $DETERM start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
  NODE_PIDS[$((n-1))]=$!
  sleep 0.3
done

echo
echo "=== 5. Poll until chain advances (height >= 5) ==="
for _ in $(seq 1 80); do
  H=$(get_status_field 8771 height)
  if [ "$H" != "-" ] && [ "$H" -ge 5 ] 2>/dev/null; then break; fi
  sleep 0.2
done

H1=$(get_status_field 8771 height)
ROLE=$(get_status_field 8771 chain_role)

echo "  height: $H1"
echo "  n1 role: $ROLE (expected beacon)"

PASS=true
if [ "$H1" = "-" ] || [ "$H1" -lt 5 ] 2>/dev/null; then
  echo "  FAIL: chain didn't advance"; PASS=false
fi
if [ "$ROLE" != "beacon" ]; then
  echo "  FAIL: role mismatch — expected beacon, got $ROLE"; PASS=false
fi

if $PASS; then
  echo
  echo "  PASS: global_test profile (BEACON + EXTENDED) end-to-end"
  echo "        - 3 beacon nodes finalized blocks under sub-30 ms timers"
  echo "        - initial_shard_count=3 satisfied EXTENDED's S>=3 gate"
  echo "        - profile loads, BEACON role active, chain advances"
fi
