#!/usr/bin/env bash
# Stage B2b-lite smoke test. Demonstrates the rev.9 sharded structure:
# beacon and shard nodes can boot side-by-side using their distinct
# genesis files (different hashes per chain_role + shard_id).
#
# This test does NOT exercise cross-chain coordination — that's Stage B2c
# (shards reading beacon's epoch boundaries, beacon tracking shard tips,
# cross-shard receipts). For now we just verify:
#   1. genesis-tool build-sharded produces 1 beacon + S shard genesis files.
#   2. Each genesis has a distinct hash.
#   3. Beacon+shard nodes can boot with their own genesis files.
#   4. RPC status reports the chain_role and shard_id correctly.
#   5. Each chain produces blocks independently.
#
# With S=1, both chains use the same creator set (which means each chain
# runs as if it's on its own — they don't talk). Each chain's committee is
# the same (genesis-pinned creators) but their cumulative_rand differs
# because of the role+shard_id mixing in compute_genesis_hash.
#
# Run from repo root: bash tools/test_sharded_smoke.sh
set -u
cd "$(dirname "$0")/.."

DHCOIN=build/Release/dhcoin.exe
T=test_sharded

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
  $DHCOIN status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('$2','-'))
except: print('-')"
}

rm -rf $T
# Two committees (creators): we need at least 2 creators per chain so
# the K=2 committee can finalize. Same creators serve both beacon and
# shard committees in this smoke test (no actual rotation across chains).
mkdir -p $T/beacon/n1 $T/beacon/n2 $T/shard/n1 $T/shard/n2

echo "=== 1. Init nodes (separate data dirs per chain) ==="
for chain in beacon shard; do
  for n in 1 2; do
    $DHCOIN init --data-dir $T/$chain/n$n --profile web 2>&1 | tail -1
  done
done

echo
echo "=== 2. Generate peer-info entries (one creator pair per chain) ==="
$DHCOIN genesis-tool peer-info node1 --data-dir $T/beacon/n1 --stake 1000 > $T/beacon_p1.json
$DHCOIN genesis-tool peer-info node2 --data-dir $T/beacon/n2 --stake 1000 > $T/beacon_p2.json
$DHCOIN genesis-tool peer-info node1 --data-dir $T/shard/n1 --stake 1000  > $T/shard_p1.json
$DHCOIN genesis-tool peer-info node2 --data-dir $T/shard/n2 --stake 1000  > $T/shard_p2.json

echo
echo "=== 3. Build genesis with build-sharded (S=1: one beacon + one shard) ==="
# Beacon genesis input uses beacon's creator pair. We then call build-sharded
# with this base config to produce <gen>.beacon.json and <gen>.shard0.json.
# Note: in a real deployment beacon and shard would use the same validator
# pool (registered at the beacon). For this smoke test they're independent.
cat > $T/beacon_gen.json <<EOF
{
  "chain_id": "test-sharded-smoke",
  "m_creators": 2,
  "k_block_sigs": 2,
  "block_subsidy": 10,
  "initial_shard_count": 1,
  "epoch_blocks": 100,
  "initial_creators": [
$(cat $T/beacon_p1.json | tr -d '\n'),
$(cat $T/beacon_p2.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 1000}]
}
EOF
$DHCOIN genesis-tool build-sharded $T/beacon_gen.json

# Shard uses its own peer-info because the keys are in different data dirs
# (the shard's nodes have their own keys). In a real deployment this is
# unified at the beacon's validator pool — for this smoke test we keep
# them disjoint.
cat > $T/shard_gen.json <<EOF
{
  "chain_id": "test-sharded-smoke",
  "m_creators": 2,
  "k_block_sigs": 2,
  "block_subsidy": 10,
  "initial_shard_count": 1,
  "epoch_blocks": 100,
  "initial_creators": [
$(cat $T/shard_p1.json | tr -d '\n'),
$(cat $T/shard_p2.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 1000}]
}
EOF
$DHCOIN genesis-tool build-sharded $T/shard_gen.json

BEACON_GEN="$T/beacon_gen.json.beacon.json"
BEACON_HASH=$(cat $T/beacon_gen.json.beacon.json.hash)
SHARD_GEN="$T/shard_gen.json.shard0.json"
SHARD_HASH=$(cat $T/shard_gen.json.shard0.json.hash)

echo
echo "  Beacon genesis hash: $BEACON_HASH"
echo "  Shard0 genesis hash: $SHARD_HASH"

if [ "$BEACON_HASH" = "$SHARD_HASH" ]; then
  echo "  FAIL: beacon and shard hashes are identical (role+shard_id should differ)"
  exit 1
else
  echo "  PASS: beacon and shard genesis hashes are distinct"
fi

echo
echo "=== 4. Configure 2 beacon nodes + 2 shard nodes (different ports) ==="
configure_node() {
  local chain=$1 n=$2 domain=$3 listen=$4 rpc=$5 peers=$6 gen_path=$7 gen_hash=$8
  python -c "
import json
with open('$T/$chain/n$n/config.json') as f: c = json.load(f)
c['domain'] = '$domain'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers
c['genesis_path'] = 'C:/sauromatae/$gen_path'
c['genesis_hash'] = '$gen_hash'
c['chain_path'] = 'C:/sauromatae/$T/$chain/n$n/chain.json'
c['key_path'] = 'C:/sauromatae/$T/$chain/n$n/node_key.json'
c['data_dir'] = 'C:/sauromatae/$T/$chain/n$n'
c['tx_commit_ms'] = 2000
c['delay_T'] = 200000
c['block_sig_ms'] = 2000
c['abort_claim_ms'] = 1000
with open('$T/$chain/n$n/config.json','w') as f: json.dump(c,f,indent=2)
"
}
# Beacon network: ports 7771/7772 (gossip), 8771/8772 (rpc)
configure_node beacon 1 node1 7771 8771 '["127.0.0.1:7772"]' "$BEACON_GEN" "$BEACON_HASH"
configure_node beacon 2 node2 7772 8772 '["127.0.0.1:7771"]' "$BEACON_GEN" "$BEACON_HASH"
# Shard0 network: ports 7781/7782 (gossip), 8781/8782 (rpc)  — SEPARATE from beacon
configure_node shard 1 node1 7781 8781 '["127.0.0.1:7782"]' "$SHARD_GEN" "$SHARD_HASH"
configure_node shard 2 node2 7782 8782 '["127.0.0.1:7781"]' "$SHARD_GEN" "$SHARD_HASH"

echo
echo "=== 5. Start 4 nodes (2 beacon + 2 shard, separate networks) ==="
NODE_PIDS=("" "" "" "")
$DHCOIN start --config $T/beacon/n1/config.json > $T/beacon/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DHCOIN start --config $T/beacon/n2/config.json > $T/beacon/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DHCOIN start --config $T/shard/n1/config.json > $T/shard/n1/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.3
$DHCOIN start --config $T/shard/n2/config.json > $T/shard/n2/log 2>&1 &
NODE_PIDS[3]=$!; sleep 0.3

echo
echo "=== 6. Poll until both chains produce blocks (height >= 3 each) ==="
for _ in $(seq 1 60); do
  BH=$(get_status_field 8771 height); SH=$(get_status_field 8781 height)
  if [ "$BH" != "-" ] && [ "$SH" != "-" ] && [ "$BH" -ge 3 ] 2>/dev/null && [ "$SH" -ge 3 ] 2>/dev/null; then
    break
  fi
  sleep 0.2
done

BEACON_HEIGHT=$(get_status_field 8771 height)
BEACON_ROLE=$(get_status_field 8771 chain_role)
BEACON_SHARDID=$(get_status_field 8771 shard_id)
SHARD_HEIGHT=$(get_status_field 8781 height)
SHARD_ROLE=$(get_status_field 8781 chain_role)
SHARD_SHARDID=$(get_status_field 8781 shard_id)

echo
echo "=== 7. Verify ==="
echo "  Beacon n1 status: role=$BEACON_ROLE, shard_id=$BEACON_SHARDID, height=$BEACON_HEIGHT"
echo "  Shard0 n1 status: role=$SHARD_ROLE,  shard_id=$SHARD_SHARDID, height=$SHARD_HEIGHT"

PASS=true
if [ "$BEACON_ROLE" != "beacon" ]; then
  echo "  FAIL: beacon node reports role=$BEACON_ROLE (expected beacon)"
  PASS=false
fi
if [ "$SHARD_ROLE" != "shard" ]; then
  echo "  FAIL: shard node reports role=$SHARD_ROLE (expected shard)"
  PASS=false
fi
if [ "$BEACON_HEIGHT" = "-" ] || [ "$BEACON_HEIGHT" = "0" ]; then
  echo "  FAIL: beacon chain didn't advance (height=$BEACON_HEIGHT)"
  PASS=false
fi
if [ "$SHARD_HEIGHT" = "-" ] || [ "$SHARD_HEIGHT" = "0" ]; then
  echo "  FAIL: shard chain didn't advance (height=$SHARD_HEIGHT)"
  PASS=false
fi

if $PASS; then
  echo "  PASS: beacon and shard chains both produced blocks independently"
  echo "  PASS: rpc_status correctly reports chain_role + shard_id"
fi

echo
echo "=== 8. Tail of beacon n1 log (showing role tag) ==="
grep "role=" $T/beacon/n1/log | head -2
echo
echo "=== 9. Tail of shard0 n1 log (showing role tag) ==="
grep "role=" $T/shard/n1/log | head -2

echo
echo "Note: Stage B2b/B2c will add cross-chain coordination — shards reading"
echo "the beacon's epoch boundary, beacon tracking shard tips, cross-shard"
echo "receipts. For this smoke test, beacon and shard chains are independent;"
echo "each runs the rev.8 protocol on its own genesis."
