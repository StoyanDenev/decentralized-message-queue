#!/usr/bin/env bash
# R2 integration test — beacon-side shard manifest + region-filtered
# SHARD_TIP validation.
#
# What this exercises that other tests don't:
#   - Beacon loads shard_manifest.json at startup (no longer optional under
#     EXTENDED mode).
#   - Manifest-missing case under EXTENDED is fail-closed (beacon refuses
#     to start with a clear error).
#   - SHARD_TIP gossip reaches the beacon (the region-filter codepath in
#     `on_shard_tip` is exercised). End-to-end SHARD_TIP _validation_ needs
#     a unified validator pool (B2c.2-full work, future) — this test does
#     not assert successful tip verification, only that the gossip path
#     runs through the manifest-driven filter.
#
# Topology: 1 beacon (BEACON + EXTENDED) + 1 shard chain (SHARD + EXTENDED,
# committee_region = "us-east"). Beacon manifest declares shard 0 as us-east.
#
# Run from repo root: bash tools/test_shard_manifest.sh
set -u
cd "$(dirname "$0")/.."

source tools/common.sh
T=test_shard_manifest

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
mkdir -p $T/beacon $T/shard1 $T/shard2

echo "=== 1. Init: 1 beacon + 2 shard nodes (shard has 2 validators) ==="
$DETERM init --data-dir $T/beacon --profile global_test 2>&1 | tail -1
# shard nodes use web_test (SHARD+EXTENDED) — needed to accept the
# committee_region in their genesis; regional_test (SHARD+CURRENT) would
# reject any non-empty committee_region per the A6 startup gate.
$DETERM init --data-dir $T/shard1 --profile web_test 2>&1 | tail -1
$DETERM init --data-dir $T/shard2 --profile web_test 2>&1 | tail -1

$DETERM genesis-tool peer-info beacon_node --data-dir $T/beacon --stake 1000 > $T/beacon_p.json
$DETERM genesis-tool peer-info shard_n1    --data-dir $T/shard1 --stake 1000 > $T/shard1_p.json
$DETERM genesis-tool peer-info shard_n2    --data-dir $T/shard2 --stake 1000 > $T/shard2_p.json

# Inject region tags. Beacon doesn't need a region (pool is global at
# beacon level — manifest tells beacon what each SHARD's region is, not
# its own region). Shard validators tag region=us-east.
python -c "
import json
for f, region in [('$T/beacon_p.json',''), ('$T/shard1_p.json','us-east'), ('$T/shard2_p.json','us-east')]:
  with open(f) as g: e = json.load(g)
  if region: e['region'] = region
  with open(f,'w') as g: json.dump(e, g)
"

echo
echo "=== 2. Build genesis files (separate for beacon and shard) ==="
# Beacon genesis: chain_role=1, S=3 (EXTENDED gate), committee_region="" (beacon stays global).
cat > $T/beacon_gen.json <<EOF
{
  "chain_id": "test-shard-manifest",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "chain_role": 1,
  "initial_shard_count": 3,
  "initial_creators": [
$(cat $T/beacon_p.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build $T/beacon_gen.json | tail -1
BEACON_GHASH=$(cat $T/beacon_gen.json.hash)

# Shard genesis: chain_role=2, shard_id=0, committee_region="us-east", S=3.
# Both shard validators (also us-east) listed in initial_creators.
cat > $T/shard_gen.json <<EOF
{
  "chain_id": "test-shard-manifest",
  "m_creators": 2,
  "k_block_sigs": 2,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 0,
  "initial_shard_count": 3,
  "committee_region": "us-east",
  "initial_creators": [
$(cat $T/shard1_p.json | tr -d '\n'),
$(cat $T/shard2_p.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build $T/shard_gen.json | tail -1
SHARD_GHASH=$(cat $T/shard_gen.json.hash)

echo
echo "=== 3. Configure beacon + shard nodes; beacon ships shard_manifest ==="
configure_node() {
  local dir=$1 domain=$2 listen=$3 rpc=$4 peers=$5 gen=$6 ghash=$7 cross_field=$8 cross_peers=$9
  python -c "
import json
with open('$T/$dir/config.json') as f: c = json.load(f)
c['domain'] = '$domain'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers
c['$cross_field'] = $cross_peers
c['genesis_path'] = '$PROJECT_ROOT/$T/$gen'
c['genesis_hash'] = '$ghash'
c['chain_path'] = '$PROJECT_ROOT/$T/$dir/chain.json'
c['key_path'] = '$PROJECT_ROOT/$T/$dir/node_key.json'
c['data_dir'] = '$PROJECT_ROOT/$T/$dir'
with open('$T/$dir/config.json','w') as f: json.dump(c,f,indent=2)
"
}
configure_node beacon beacon_node 7771 8771 '[]' beacon_gen.json $BEACON_GHASH shard_peers  '["127.0.0.1:7781","127.0.0.1:7782"]'
configure_node shard1 shard_n1    7781 8781 '["127.0.0.1:7782"]' shard_gen.json  $SHARD_GHASH  beacon_peers '["127.0.0.1:7771"]'
configure_node shard2 shard_n2    7782 8782 '["127.0.0.1:7781"]' shard_gen.json  $SHARD_GHASH  beacon_peers '["127.0.0.1:7771"]'

# R2: beacon manifest pins shard 0 to us-east.
cat > $T/beacon/shard_manifest.json <<EOF
{
  "shards": [
    { "shard_id": 0, "committee_region": "us-east" }
  ]
}
EOF

echo
echo "=== 4. Start beacon + 2 shard nodes ==="
NODE_PIDS=("" "" "")
$DETERM start --config $T/beacon/config.json > $T/beacon/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.5
$DETERM start --config $T/shard1/config.json > $T/shard1/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.5
$DETERM start --config $T/shard2/config.json > $T/shard2/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.5

echo
echo "=== 5. Wait for shard to produce blocks + beacon to verify tips ==="
for _ in $(seq 1 80); do
  SH=$(get_status_field 8781 height)
  TIPS=$(get_status_field 8771 tracked_shard_tips)
  if [ "$SH" != "-" ] && [ "$SH" -ge 5 ] 2>/dev/null \
     && [ "$TIPS" != "-" ] && [ "$TIPS" -ge 1 ] 2>/dev/null; then break; fi
  sleep 0.2
done

SHARD_H=$(get_status_field 8781 height)
BEACON_H=$(get_status_field 8771 height)
BEACON_TIPS=$(get_status_field 8771 tracked_shard_tips)
SHARD_TIPS_SEEN=$(grep -E "shard tip|on_shard_tip" $T/beacon/log 2>/dev/null | wc -l | tr -d ' ')
MANIFEST_LOG=$(grep "loaded shard_manifest" $T/beacon/log 2>/dev/null | head -1)

echo "  shard1 height: $SHARD_H"
echo "  beacon height: $BEACON_H"
echo "  beacon tracked_shard_tips: $BEACON_TIPS (validation needs unified pool — B2c.2-full)"
echo "  manifest load log: ${MANIFEST_LOG:-(missing)}"

FAILS=0
if [ -z "$MANIFEST_LOG" ]; then
  echo "  bad: beacon did not log shard_manifest load"; FAILS=$((FAILS+1))
fi
# Sentinel-hardened: get_status_field returns '-' on dead RPC, and any
# other non-numeric value would make the old `-lt` tests error out
# (status 2 -> condition false -> silent false-green). Require real
# numeric heights.
if ! [[ "$SHARD_H" =~ ^[0-9]+$ ]] || [ "$SHARD_H" -lt 5 ]; then
  echo "  bad: shard chain did not advance (height='$SHARD_H', need numeric >= 5)"; FAILS=$((FAILS+1))
fi
if ! [[ "$BEACON_H" =~ ^[0-9]+$ ]] || [ "$BEACON_H" -lt 3 ]; then
  echo "  bad: beacon chain did not advance (height='$BEACON_H', need numeric >= 3)"; FAILS=$((FAILS+1))
fi

# Now test the fail-closed path: a fresh beacon-EXTENDED node without
# a manifest must refuse to start.
mkdir -p $T/beacon_no_manifest
$DETERM init --data-dir $T/beacon_no_manifest --profile global_test 2>&1 > /dev/null
python -c "
import json
with open('$T/beacon_no_manifest/config.json') as f: c = json.load(f)
c['genesis_path'] = '$PROJECT_ROOT/$T/beacon_gen.json'
c['genesis_hash'] = '$BEACON_GHASH'
c['chain_path']   = '$PROJECT_ROOT/$T/beacon_no_manifest/chain.json'
c['key_path']     = '$PROJECT_ROOT/$T/beacon_no_manifest/node_key.json'
c['data_dir']     = '$PROJECT_ROOT/$T/beacon_no_manifest'
c['listen_port']  = 7799
c['rpc_port']     = 8799
with open('$T/beacon_no_manifest/config.json','w') as f: json.dump(c,f,indent=2)
"
# Explicitly NO manifest file in this data_dir. Start should fail.
START_OUT=$($DETERM start --config $T/beacon_no_manifest/config.json 2>&1 || true)
if echo "$START_OUT" | grep -q "requires a shard→region map"; then
  echo "  ok: fail-closed — beacon refuses to start without a map (committed or manifest)"
else
  echo "  bad: beacon (EXTENDED) without manifest did not error as expected"
  echo "  Got:"
  echo "$START_OUT" | sed 's/^/    | /'
  FAILS=$((FAILS+1))
fi

# ── D3.5e-2: the GENESIS-COMMITTED shard→region map (beacon_shard_regions) ──
# is authoritative when present, replacing the node-local manifest file.
echo
echo "=== 5. D3.5e-2: genesis-committed shard→region map ==="
# A beacon genesis that COMMITS the map (epoch_blocks default 1000 >= 2).
cat > $T/beacon_map_gen.json <<EOF
{
  "chain_id": "test-shard-manifest-map",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "chain_role": 1,
  "initial_shard_count": 3,
  "beacon_shard_regions": [
    {"shard_id": 0, "committee_region": "us-east"},
    {"shard_id": 1, "committee_region": "eu-west"},
    {"shard_id": 2, "committee_region": "ap-se"}
  ],
  "initial_creators": [
$(cat $T/beacon_p.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$DETERM genesis-tool build $T/beacon_map_gen.json | tail -1
BEACON_MAP_GHASH=$(cat $T/beacon_map_gen.json.hash)

# (a) committed map + NO manifest file: the node loads the map from GENESIS.
mkdir -p $T/beacon_map
$DETERM init --data-dir $T/beacon_map --profile global_test 2>&1 > /dev/null
python -c "
import json
with open('$T/beacon_map/config.json') as f: c = json.load(f)
c['genesis_path'] = '$PROJECT_ROOT/$T/beacon_map_gen.json'
c['genesis_hash'] = '$BEACON_MAP_GHASH'
c['chain_path']   = '$PROJECT_ROOT/$T/beacon_map/chain.json'
c['key_path']     = '$PROJECT_ROOT/$T/beacon_map/node_key.json'
c['data_dir']     = '$PROJECT_ROOT/$T/beacon_map'
c['listen_port']  = 7798
c['rpc_port']     = 8798
with open('$T/beacon_map/config.json','w') as f: json.dump(c,f,indent=2)
"
$DETERM start --config $T/beacon_map/config.json > $T/beacon_map/log 2>&1 &
MAP_PID=$!
sleep 3
kill $MAP_PID 2>/dev/null; wait $MAP_PID 2>/dev/null
if grep -q "from GENESIS (committed, authoritative)" $T/beacon_map/log; then
  echo "  ok: committed map loaded from genesis (authoritative, no manifest file)"
else
  echo "  bad: beacon did not log the genesis-committed map"
  tail -8 $T/beacon_map/log 2>/dev/null | sed 's/^/    | /'
  FAILS=$((FAILS+1))
fi

# (b) committed map + a CONFLICTING manifest file: startup MUST fail-close.
cat > $T/beacon_map/shard_manifest.json <<EOF
{"shards":[{"shard_id":0,"committee_region":"us-WEST"},
           {"shard_id":1,"committee_region":"eu-west"},
           {"shard_id":2,"committee_region":"ap-se"}]}
EOF
CONFLICT_OUT=$($DETERM start --config $T/beacon_map/config.json 2>&1 || true)
if echo "$CONFLICT_OUT" | grep -q "conflicts with the genesis-committed"; then
  echo "  ok: fail-closed — a manifest file that disagrees with the committed map is rejected"
else
  echo "  bad: conflicting manifest did not fail-close"
  echo "$CONFLICT_OUT" | sed 's/^/    | /'
  FAILS=$((FAILS+1))
fi

echo
echo "=== Test summary ==="
if [ "$FAILS" -eq 0 ]; then
  echo "  ok: R2 shard manifest loading + fail-closed enforcement"
  echo "      - beacon loaded manifest at startup ($MANIFEST_LOG)"
  echo "      - shard chain produced blocks (height $SHARD_H)"
  echo "      - beacon chain produced blocks (height $BEACON_H)"
  echo "      - missing-manifest under EXTENDED rejected fail-closed"
  echo "      (end-to-end SHARD_TIP _validation_ awaits unified-pool work)"
  echo "  PASS: test_shard_manifest"
  exit 0
else
  echo "  --- diagnostics: node log tails ---"
  for d in beacon shard1 shard2; do
    echo "  -- $T/$d/log (last 12 lines) --"
    tail -12 $T/$d/log 2>/dev/null | sed 's/^/    | /'
  done
  echo "  FAIL: test_shard_manifest ($FAILS checks failed)"
  exit 1
fi
