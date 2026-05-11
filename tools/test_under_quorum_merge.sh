#!/usr/bin/env bash
# R4 — MERGE_EVENT end-to-end smoke test.
#
# What this verifies:
#   1. submit-merge-event CLI produces a canonical MergeEvent payload
#      wrapped in a Transaction, signed by a registered domain.
#   2. The validator accepts the tx (EXTENDED + shape + charset).
#   3. apply_transactions inserts (shard_id → {partner_id, region})
#      into Chain::merge_state_ when partner == (shard+1) mod S.
#   4. The state persists into snapshot JSON's "merge_state" array.
#   5. A second MERGE_EVENT (event=end) erases the entry.
#
# What this does NOT verify (Phase 6 work):
#   * Auto-detection by beacon (eligible_in_region < 2K observation
#     window emitting MERGE_BEGIN automatically).
#   * S-036 witness-window historical validation at apply time.
#   * Cross-shard receipt routing across BEGIN/END boundaries.
#
# Topology: 1 SHARD chain (shard_id=0, region=us-east, S=3 satisfies
# the EXTENDED >=3 gate). 3 validators all online. We submit
# MERGE_EVENT events with shard_id=0, partner_id=1 (modular-next),
# refugee_region=us-east — i.e., this very chain becomes a refugee.
# That's enough to exercise the apply-side state machine.
#
# Run from repo root: bash tools/test_under_quorum_merge.sh
set -u
cd "$(dirname "$0")/.."

DETERM=build/Release/determ.exe
T=test_uq_merge
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
mkdir -p $T/n1 $T/n2 $T/n3

echo "=== 1. Init 3 nodes (web_test = SHARD+EXTENDED, M=3 K=2) ==="
for n in 1 2 3; do
  $DETERM init --data-dir $T/n$n --profile web_test 2>&1 | tail -1
  $DETERM genesis-tool peer-info node$n --data-dir $T/n$n --stake 1000 > $T/p$n.json
done

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

echo
echo "=== 2. Build genesis (SHARD shard_id=0, S=3, region=us-east) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-uq-merge",
  "m_creators": 3,
  "k_block_sigs": 2,
  "block_subsidy": 10,
  "chain_role": 2,
  "shard_id": 0,
  "initial_shard_count": 3,
  "committee_region": "us-east",
  "merge_threshold_blocks": 5,
  "revert_threshold_blocks": 10,
  "merge_grace_blocks": 2,
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n'),
$(cat $T/p2.json | tr -d '\n'),
$(cat $T/p3.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "node1", "balance": 1000}]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)
GPATH="$TABS/gen.json"

echo
echo "=== 3. Configure 3 nodes (longer timers for cold-start tolerance) ==="
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
c['chain_path'] = '$TABS/n$n/chain.json'
c['key_path'] = '$TABS/n$n/node_key.json'
c['data_dir'] = '$TABS/n$n'
c['tx_commit_ms'] = 500
c['block_sig_ms'] = 500
c['abort_claim_ms'] = 250
with open('$T/n$n/config.json','w') as f: json.dump(c,f,indent=2)
"
}
configure_node 1 7771 8771 '["127.0.0.1:7772","127.0.0.1:7773"]'
configure_node 2 7772 8772 '["127.0.0.1:7771","127.0.0.1:7773"]'
configure_node 3 7773 8773 '["127.0.0.1:7771","127.0.0.1:7772"]'

echo
echo "=== 4. Start 3 nodes ==="
NODE_PIDS=("" "" "")
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
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
echo "  height before MERGE_BEGIN: $H_BEFORE"

PRIV1=$(python -c "import json; print(json.load(open('$T/n1/node_key.json'))['priv_seed'])")
EFF=$((H_BEFORE + 5))

echo
echo "=== 6. Submit MERGE_BEGIN(shard=0, partner=1, region=us-east) at h=$EFF ==="
$DETERM submit-merge-event \
  --priv "$PRIV1" \
  --from node1 \
  --event begin \
  --shard-id 0 --partner-id 1 \
  --effective-height "$EFF" \
  --evidence-window-start "$((H_BEFORE - 5))" \
  --refugee-region us-east \
  --fee 0 \
  --rpc-port 8771 2>&1 | tail -4

echo
echo "=== 7. Wait for tx inclusion + a few more blocks ==="
for _ in $(seq 1 60); do
  H=$($DETERM status --rpc-port 8771 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -gt $((H_BEFORE + 3)) ] 2>/dev/null; then break; fi
  sleep 0.5
done

echo
echo "=== 8. Snapshot + verify merge_state populated ==="
$DETERM snapshot create --out $T/snap_begin.json --rpc-port 8771 2>&1 | tail -1
MERGE_COUNT=$(python -c "
import json
try:
    s = json.load(open('$T/snap_begin.json'))
    print(len(s.get('merge_state', [])))
except Exception as e:
    print(0)")
MERGE_FIRST=$(python -c "
import json
try:
    s = json.load(open('$T/snap_begin.json'))
    m = s.get('merge_state', [])
    if m:
        print('shard={} partner={} region={}'.format(
            m[0].get('shard_id','?'),
            m[0].get('partner_id','?'),
            m[0].get('refugee_region','?')))
    else:
        print('(empty)')
except Exception as e:
    print('error: '+str(e))")
echo "  merge_state entries: $MERGE_COUNT"
echo "  first entry: $MERGE_FIRST"

echo
echo "=== 9. Submit MERGE_END(shard=0, partner=1) and verify state clears ==="
$DETERM submit-merge-event \
  --priv "$PRIV1" \
  --from node1 \
  --event end \
  --shard-id 0 --partner-id 1 \
  --effective-height "$((EFF + 5))" \
  --evidence-window-start 0 \
  --fee 0 \
  --rpc-port 8771 2>&1 | tail -4

for _ in $(seq 1 60); do
  H=$($DETERM status --rpc-port 8771 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -gt $((H_BEFORE + 10)) ] 2>/dev/null; then break; fi
  sleep 0.5
done

$DETERM snapshot create --out $T/snap_end.json --rpc-port 8771 2>&1 | tail -1
MERGE_COUNT_END=$(python -c "
import json
try:
    s = json.load(open('$T/snap_end.json'))
    print(len(s.get('merge_state', [])))
except: print(-1)")
echo "  merge_state entries after END: $MERGE_COUNT_END"

echo
echo "=== Test summary ==="
PASS_BEGIN=false
PASS_END=false
if [ "$MERGE_COUNT" = "1" ] && \
   echo "$MERGE_FIRST" | grep -q "shard=0" && \
   echo "$MERGE_FIRST" | grep -q "partner=1" && \
   echo "$MERGE_FIRST" | grep -q "region=us-east"; then
  PASS_BEGIN=true
fi
if [ "$MERGE_COUNT_END" = "0" ]; then PASS_END=true; fi

if $PASS_BEGIN && $PASS_END; then
  echo "  PASS: MERGE_EVENT apply state machine"
  echo "  - submit-merge-event CLI accepted"
  echo "  - validator EXTENDED-mode gate passed"
  echo "  - MERGE_BEGIN inserted {shard=0, partner=1, region=us-east}"
  echo "  - snapshot persisted merge_state"
  echo "  - MERGE_END erased the entry"
else
  echo "  FAIL: BEGIN_ok=$PASS_BEGIN END_ok=$PASS_END"
  echo "        begin merge_state: $MERGE_FIRST"
  echo "        end merge_state count: $MERGE_COUNT_END"
fi
