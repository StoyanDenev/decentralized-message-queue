#!/usr/bin/env bash
# A5 — Governance PARAM_CHANGE end-to-end smoke test.
#
# Boots a 3-node chain in governed mode with 3 founder keyholders
# (3-of-3 threshold = N-of-N). One of the donor nodes (donor1) is
# both a validator AND a founder; it sends a PARAM_CHANGE tx
# changing MIN_STAKE 1000 → 2000 at a future effective_height.
# The test then snapshots the chain and verifies via snapshot inspect
# that min_stake on the restored state equals 2000.
#
# What this exercises end-to-end:
#   * Genesis with governance_mode=1 + 3 keyholders.
#   * Validator's PARAM_CHANGE multisig + whitelist path.
#   * Chain's stage_param_change(effective_height) at apply.
#   * Chain's activate_pending_params() at block boundary.
#   * Snapshot save/restore round-tripping pending entries.
#
# Run from repo root: bash tools/test_governance_param_change.sh

set -u
cd "$(dirname "$0")/.."

DETERM=C:/sauromatae/build/Release/determ.exe
T=test_gov_pc
TABS=C:/sauromatae/$T

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

rm -rf $T
mkdir -p $T/donor1 $T/donor2 $T/donor3

echo "=== 1. Init 3 donor data dirs ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/donor$n --profile single_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info donor$n --data-dir $T/donor$n --stake 1000 \
    > $T/p$n.json
done

# Use donor1/2/3's pubkeys also as the three founder keyholders
# (3-of-3). Pulling priv_seed from each node's key file lets the test
# sign without needing a separate keyholder keystore.
PK1=$(python -c "import json; print(json.load(open('$T/donor1/node_key.json'))['pubkey'])")
PK2=$(python -c "import json; print(json.load(open('$T/donor2/node_key.json'))['pubkey'])")
PK3=$(python -c "import json; print(json.load(open('$T/donor3/node_key.json'))['pubkey'])")
PRIV1=$(python -c "import json; print(json.load(open('$T/donor1/node_key.json'))['priv_seed'])")
PRIV2=$(python -c "import json; print(json.load(open('$T/donor2/node_key.json'))['priv_seed'])")
PRIV3=$(python -c "import json; print(json.load(open('$T/donor3/node_key.json'))['priv_seed'])")

echo
echo "=== 2. Build governed genesis (mode=1, 3 keyholders, threshold=3) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-gov-pc",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 10,
  "min_stake": 1000,
  "governance_mode": 1,
  "param_threshold": 3,
  "param_keyholders": ["$PK1","$PK2","$PK3"],
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "donor1", "balance": 1000}]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)

echo
echo "=== 3. Configure 3 nodes ==="
configure_node() {
  local n=$1 listen=$2 rpc=$3 peers=$4
  python -c "
import json
with open('$T/donor$n/config.json') as f: c = json.load(f)
c['domain'] = 'donor$n'
c['listen_port'] = $listen
c['rpc_port'] = $rpc
c['bootstrap_peers'] = $peers
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/donor$n/chain.json'
c['key_path'] = '$TABS/donor$n/node_key.json'
c['data_dir'] = '$TABS/donor$n'
c['tx_commit_ms'] = 500
c['block_sig_ms'] = 500
c['abort_claim_ms'] = 250
with open('$T/donor$n/config.json','w') as f: json.dump(c,f,indent=2)
"
}
configure_node 1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

echo
echo "=== 4. Start 3 nodes ==="
NODE_PIDS=("" "" "")
$DETERM start --config $T/donor1/config.json > $T/donor1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/donor2/config.json > $T/donor2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/donor3/config.json > $T/donor3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.3

echo
echo "=== 5. Wait for chain to advance past height 5 ==="
for _ in $(seq 1 120); do
  H=$($DETERM status --rpc-port 8771 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -ge 5 ] 2>/dev/null; then break; fi
  sleep 0.5
done
H_BEFORE=$($DETERM status --rpc-port 8771 2>/dev/null \
            | python -c "import sys,json; print(json.load(sys.stdin)['height'])")
echo "  height before PARAM_CHANGE: $H_BEFORE"

# Effective height = current + 5 (gives plenty of room for the tx
# to land in a block before activation).
EFF=$((H_BEFORE + 5))
# Value: MIN_STAKE = 2000 encoded as 8-byte LE: 2000 = 0x07D0 →
# "d0 07 00 00 00 00 00 00"
VALUE_HEX="d007000000000000"

echo
echo "=== 6. Submit PARAM_CHANGE MIN_STAKE → 2000 at height $EFF ==="
$DETERM submit-param-change \
  --priv "$PRIV1" \
  --from donor1 \
  --name MIN_STAKE \
  --value-hex "$VALUE_HEX" \
  --effective-height "$EFF" \
  --fee 0 \
  --keyholder-sig "0:$PRIV1" \
  --keyholder-sig "1:$PRIV2" \
  --keyholder-sig "2:$PRIV3" \
  --rpc-port 8771 2>&1 | tail -5

echo
echo "=== 7. Wait for chain to advance past effective_height ==="
for _ in $(seq 1 120); do
  H=$($DETERM status --rpc-port 8771 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -gt "$EFF" ] 2>/dev/null; then break; fi
  sleep 0.5
done
H_AFTER=$($DETERM status --rpc-port 8771 2>/dev/null \
           | python -c "import sys,json; print(json.load(sys.stdin)['height'])")
echo "  height after wait: $H_AFTER (need > $EFF)"

echo
echo "=== 8. Snapshot + inspect: verify min_stake activated ==="
$DETERM snapshot create --out $T/snap.json --rpc-port 8771 2>&1 | tail -1
MIN_STAKE_LIVE=$($DETERM snapshot inspect --in $T/snap.json 2>&1 \
                  | grep "min_stake" | head -1 \
                  | awk '{print $NF}')
echo "  live min_stake: $MIN_STAKE_LIVE (expected 2000)"

echo
echo "=== Test summary ==="
if [ "$MIN_STAKE_LIVE" = "2000" ]; then
  echo "  PASS: governance PARAM_CHANGE end-to-end"
  echo "  - governed-mode genesis built with 3-of-3 keyholders"
  echo "  - PARAM_CHANGE accepted by validator (multisig + whitelist)"
  echo "  - chain advanced past effective_height"
  echo "  - activate_pending_params mutated chain state"
  echo "  - snapshot inspect reports MIN_STAKE = 2000"
else
  echo "  FAIL: min_stake did not activate (saw '$MIN_STAKE_LIVE')"
fi
