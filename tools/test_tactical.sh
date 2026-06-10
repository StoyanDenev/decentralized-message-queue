#!/usr/bin/env bash
# Tactical-profile smoke test. Verifies the Layer-1 swarm-coordination
# profile (PROFILE_TACTICAL_TEST: K=M=3 strong, SHARD + EXTENDED) boots
# cleanly and produces blocks. Models the unmanned-mobile-unit (drone,
# robot) deployment shape. Config timers are overridden to 500/500/250 ms
# for cold-start tolerance on the test host (Windows multi-process);
# wall-clock cadence is deliberately NOT asserted — that is the known
# desync fragility in this suite.
#
# Asserts:
#   1. determ init --profile tactical_test produces a valid config.
#   2. Three nodes peered on one EXTENDED shard (shard0 of a 3-shard
#      build-sharded genesis, committee_region=us-east) finalize their
#      first 5 blocks within the poll window (~60 s ceiling).
#   3. Status RPC reports top-level chain_role = shard and nested
#      protections.sharding_mode = extended.
#
# Run from repo root: bash tools/test_tactical.sh
set -u
cd "$(dirname "$0")/.."

source tools/common.sh
T=test_tactical
TNAME=test_tactical.sh

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

# sharding_mode lives ONLY nested at protections.sharding_mode in the
# status RPC (src/node/node.cpp); there is no top-level key.
get_sharding_mode() {
  $DETERM status --rpc-port "$1" 2>/dev/null | python -c "import sys,json
try: print(json.load(sys.stdin).get('protections',{}).get('sharding_mode','-'))
except: print('-')"
}

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3

echo "=== 1. Init 3 nodes with tactical_test profile (SHARD + EXTENDED, K=3) ==="
# tactical/tactical_test mandate CryptoProfile::FIPS; a binary built with
# -DDETERM_CRYPTO=modern refuses them at init ("Crypto profile mismatch").
# That is a build capability gate, not a chain defect — SKIP (suite
# convention: PASS marker with SKIP note) so the suite stays meaningful on
# modern-crypto dev builds while FIPS builds exercise the full test.
INIT_OUT=$($DETERM init --data-dir $T/n1 --profile tactical_test 2>&1)
if echo "$INIT_OUT" | grep -q "Crypto profile mismatch"; then
  echo "  SKIP: $INIT_OUT"
  echo "  PASS: $TNAME (SKIP — tactical profile mandates FIPS; binary built DETERM_CRYPTO=modern)"
  exit 0
fi
echo "$INIT_OUT" | tail -1
for n in 2 3; do
  $DETERM init --data-dir $T/n$n --profile tactical_test 2>&1 | tail -1
done

echo
echo "=== 2. Generate peer-info entries (region-tagged for the us-east committee) ==="
# --region is required: build-sharded stamps committee_region="us-east"
# into shard0's genesis, and eligible_in_region() is strict equality —
# untagged creators yield an empty committee pool and 0 blocks forever.
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 --region us-east > $T/p1.json
$DETERM genesis-tool peer-info node2 --data-dir $T/n2 --stake 1000 --region us-east > $T/p2.json
$DETERM genesis-tool peer-info node3 --data-dir $T/n3 --stake 1000 --region us-east > $T/p3.json

echo
echo "=== 3. Build sharded genesis (M=3, K=3 strong, S=3, all shards us-east) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-tactical",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "initial_shard_count": 3,
  "epoch_blocks": 100,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "treasury", "balance": 1000}],
  "shard_regions": ["us-east", "us-east", "us-east"]
}
EOF
$DETERM genesis-tool build-sharded $T/gen.json
GEN_HASH=$(cat $T/gen.json.shard0.json.hash)
# determ.exe is a native Windows binary; configs need absolute native paths.
GEN_PATH="$PROJECT_ROOT/$T/gen.json.shard0.json"
echo "  Shard0 genesis hash: $GEN_HASH"

echo
echo "=== 4. Configure 3 nodes (ports, peers, genesis pin, cold-start timers) ==="
# `determ start` accepts ONLY --config/--data-dir; per-node settings must
# be patched into config.json (the old --listen-port/--rpc-port/--genesis/
# --peer flags were silently ignored).
configure_node() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  python -c "
import json
with open('$T/n$n/config.json') as f: c = json.load(f)
c['domain'] = 'node$n'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers
c['genesis_path'] = '$GEN_PATH'
c['genesis_hash'] = '$GEN_HASH'
c['chain_path'] = '$PROJECT_ROOT/$T/n$n/chain.json'
c['key_path'] = '$PROJECT_ROOT/$T/n$n/node_key.json'
c['data_dir'] = '$PROJECT_ROOT/$T/n$n'
c['tx_commit_ms'] = 500
c['block_sig_ms'] = 500
c['abort_claim_ms'] = 250
with open('$T/n$n/config.json','w') as f: json.dump(c, f, indent=2)
print('  n$n: listen=$listen rpc=$rpc (timers 500/500/250 ms)')
"
}
configure_node 1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

echo
echo "=== 5. Start 3 nodes (staggered) ==="
for n in 1 2 3; do
  $DETERM start --config $T/n$n/config.json > $T/n$n.log 2>&1 &
  NODE_PIDS+=($!)
  sleep 0.3
done

echo
echo "=== 6. Poll for height >= 5 (ceiling ~60 s) ==="
HEIGHT=-
for _ in $(seq 1 120); do
  HEIGHT=$(get_status_field 8771 height)
  if [[ "$HEIGHT" =~ ^[0-9]+$ ]] && [ "$HEIGHT" -ge 5 ]; then break; fi
  sleep 0.5
done

echo "  Final height: $HEIGHT"
ROLE=$(get_status_field 8771 chain_role)
SMODE=$(get_sharding_mode 8771)
echo "  chain_role: $ROLE  protections.sharding_mode: $SMODE"

FAILED=0
if [[ "$HEIGHT" =~ ^[0-9]+$ ]] && [ "$HEIGHT" -ge 5 ]; then
  echo "  ok: height $HEIGHT >= 5"
else
  echo "  bad: height '$HEIGHT' not a number >= 5 (dead RPC sentinel is '-')"
  FAILED=$((FAILED + 1))
fi
if [ "$ROLE" = "shard" ]; then
  echo "  ok: chain_role = shard"
else
  echo "  bad: chain_role '$ROLE' != shard"
  FAILED=$((FAILED + 1))
fi
if [ "$SMODE" = "extended" ]; then
  echo "  ok: protections.sharding_mode = extended"
else
  echo "  bad: protections.sharding_mode '$SMODE' != extended"
  FAILED=$((FAILED + 1))
fi

if [ "$FAILED" -eq 0 ]; then
  echo "  PASS: $TNAME"
  exit 0
else
  for n in 1 2 3; do
    echo "  --- $T/n$n.log (tail) ---"
    tail -15 $T/n$n.log 2>/dev/null
  done
  echo "  FAIL: $TNAME ($FAILED checks failed)"
  exit 1
fi
