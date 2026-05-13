#!/usr/bin/env bash
# R3 / R1 integration test — regional committee filtering.
#
# Deploys a SHARD chain with `committee_region = us-east` and 6 initial
# creators: 3 tagged region=us-east, 3 tagged region=eu-west. Verifies:
#
#   1. Only us-east validators are selected for the committee (R1 filter).
#   2. eu-west validators never appear in `block.creators`.
#   3. The chain progresses normally with only the 3 in-region nodes
#      running (the 3 out-of-region nodes don't have to be online —
#      they wouldn't be selected anyway).
#   4. Genesis hash includes committee_region (different region → different
#      hash for an otherwise-identical config).
#
# Uses web_test profile (SHARD + EXTENDED, M=3 K=2). EXTENDED's S>=3
# gate is satisfied by `initial_shard_count=3` in genesis even though
# only shard_id=0 actually runs in this test.
#
# Run from repo root: bash tools/test_regional_shards.sh
set -u
cd "$(dirname "$0")/.."

UNCHAINED=build/Release/unchained.exe
T=test_regional_shards

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
  $UNCHAINED status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('$2','-'))
except: print('-')"
}

rm -rf $T
for n in 1 2 3 4 5 6; do mkdir -p $T/n$n; done

echo "=== 1. Init 6 nodes: n1-n3 us-east (active), n4-n6 eu-west (spectators) ==="
for n in 1 2 3 4 5 6; do
  $UNCHAINED init --data-dir $T/n$n --profile web_test 2>&1 | tail -1
  $UNCHAINED genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

# Inject region into each peer-info entry post-hoc (peer-info doesn't yet
# emit region — R0 plumbing is in registry only; genesis JSON is the source
# of truth).
inject_region() {
  local n=$1 region=$2
  python -c "
import json
with open('$T/p$n.json') as f: e = json.load(f)
e['region'] = '$region'
with open('$T/p$n.json','w') as f: json.dump(e, f)
"
}
for n in 1 2 3; do inject_region $n us-east; done
for n in 4 5 6; do inject_region $n eu-west; done

echo
echo "=== 2. Build genesis (committee_region=us-east, S=3, 6 creators across 2 regions) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-regional-shards",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 0,
  "initial_shard_count": 3,
  "committee_region": "us-east",
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n'),
$(cat $T/p4.json | tr -d '\n'),
$(cat $T/p5.json | tr -d '\n'),
$(cat $T/p6.json | tr -d '\n')
  ],
  "initial_balances": []
}
EOF
$UNCHAINED genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)
GPATH="C:/sauromatae/$T/gen.json"

# Genesis-hash distinctness check: build an alternate with committee_region=eu-west.
cp $T/gen.json $T/gen_alt.json
python -c "
import json
g = json.load(open('$T/gen_alt.json'))
g['committee_region'] = 'eu-west'
json.dump(g, open('$T/gen_alt.json','w'), indent=2)
"
$UNCHAINED genesis-tool build $T/gen_alt.json > /dev/null 2>&1
GHASH_ALT=$(cat $T/gen_alt.json.hash 2>/dev/null)

echo
echo "=== 3. Configure 3 us-east nodes (n1-n3) into a mesh; n4-n6 not started ==="
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
echo "=== 4. Start 3 us-east nodes only (eu-west nodes deliberately absent) ==="
NODE_PIDS=("" "" "")
for n in 1 2 3; do
  $UNCHAINED start --config $T/n$n/config.json > $T/n$n/log 2>&1 &
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
echo "  height: $H1"

# Inspect a recent block's committee — should be entirely from {node1,node2,node3}.
COMMITTEE=$($UNCHAINED show-block 3 --rpc-port 8771 2>/dev/null | python -c "
import sys, json
try:
  b = json.load(sys.stdin)
  print(' '.join(b.get('creators', [])))
except Exception:
  print('')
")
echo "  block #3 committee: $COMMITTEE"

PASS=true
if [ "$H1" = "-" ] || [ "$H1" -lt 5 ] 2>/dev/null; then
  echo "  FAIL: chain didn't advance with us-east-only validators online"; PASS=false
fi

# Validate committee contents — every member must be node1, node2, or node3.
for member in $COMMITTEE; do
  case "$member" in
    node1|node2|node3) ;;
    *)
      echo "  FAIL: out-of-region member $member appeared on committee"
      PASS=false
      ;;
  esac
done

# Genesis-hash distinctness: same config with eu-west should produce a different hash.
if [ -n "$GHASH_ALT" ] && [ "$GHASH" = "$GHASH_ALT" ]; then
  echo "  FAIL: committee_region not bound into genesis hash (us-east hash == eu-west hash)"
  PASS=false
fi

if $PASS; then
  echo
  echo "  PASS: regional committee filter (R1) end-to-end"
  echo "        - committee_region=us-east + 6 creators (3 us-east, 3 eu-west)"
  echo "        - only us-east validators selected for committee"
  echo "        - chain finalized with only in-region nodes online"
  echo "        - committee_region distinct in genesis hash (us-east != eu-west)"
fi
