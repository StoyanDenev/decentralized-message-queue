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
# the EXTENDED >=3 gate). 4 validators all online (M=4, K=3). K=3 (not
# the web profile's K=2) because K=2 committees wedge under ordinary
# timing skew: the abort-claim quorum at K=2 is K-1=1, so any single
# phase straggle abort-excludes a member with one claim; the resulting
# aborts_gen desync drops contribs and cascades more single-claim aborts
# until the pool falls below K and the chain halts permanently (aborts
# clear only on block accept; BFT escalation is unreachable at K=2
# because k_bft = ceil(2K/3) = 2 = K). Observed live on three sibling
# tests — tracked in SECURITY.md (S-044). The merge-event machinery
# under test here is K-independent (an apply-path feature gated only on
# sharding_mode=extended), so K=3-of-4 preserves the intent exactly.
# We submit MERGE_EVENT events with shard_id=0, partner_id=1
# (modular-next), refugee_region=us-east — i.e., this very chain becomes
# a refugee. That's enough to exercise the apply-side state machine.
#
# Run from repo root: bash tools/test_under_quorum_merge.sh
set -u
cd "$(dirname "$0")/.."

source tools/common.sh
T=test_uq_merge
TABS=$PROJECT_ROOT/$T

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

# Hard-fail helper: print node-log diagnostics ABOVE, then the single
# final FAIL marker line, then exit 1 (cleanup() in the EXIT trap does
# not call exit, so the failing status is preserved). Log lines are
# prefixed with "| " so they can never match run_all.sh's ^\s*PASS: grep.
fail_hard() {
  local reason="$1"
  echo
  echo "  --- diagnostics: node log tails ---"
  for n in 1 2 3 4; do
    echo "  -- $T/n$n/log (last 12 lines) --"
    tail -12 "$T/n$n/log" 2>/dev/null | sed 's/^/  | /'
  done
  echo "  FAIL: test_under_quorum_merge ($reason)"
  exit 1
}

rm -rf $T
mkdir -p $T/n1 $T/n2 $T/n3 $T/n4

echo "=== 1. Init 4 nodes (web_test = SHARD+EXTENDED, M=4 K=3) ==="
for n in 1 2 3 4; do
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
for n in 1 2 3 4; do inject_region $n us-east; done

echo
echo "=== 2. Build genesis (SHARD shard_id=0, S=3, region=us-east) ==="
cat > $T/gen.json <<EOF
{
  "chain_id": "test-uq-merge",
  "m_creators": 4,
  "k_block_sigs": 3,
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
$(cat $T/p3.json | tr -d '\n'),
$(cat $T/p4.json | tr -d '\n')
  ],
  "initial_balances": [{"domain": "node1", "balance": 1000}]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1
GHASH=$(cat $T/gen.json.hash)
GPATH="$TABS/gen.json"

echo
echo "=== 3. Configure 4 nodes (generous timers per green test_multinode.sh) ==="
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
# Extra-generous timeouts for the test environment (Windows multi-process,
# loopback gossip, placeholder VDF) — same values as the green
# test_multinode.sh. The old 500/500/250 values made a phase-2 straggle
# (and the resulting K=2 mutual cross-abort halt) near-certain here.
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
$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!; sleep 0.3
$DETERM start --config $T/n2/config.json > $T/n2/log 2>&1 &
NODE_PIDS[1]=$!; sleep 0.3
$DETERM start --config $T/n3/config.json > $T/n3/log 2>&1 &
NODE_PIDS[2]=$!; sleep 0.3
$DETERM start --config $T/n4/config.json > $T/n4/log 2>&1 &
NODE_PIDS[3]=$!; sleep 0.3

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
            | python -c "import sys,json
try: print(json.load(sys.stdin)['height'])
except: pass")
echo "  height before MERGE_BEGIN: ${H_BEFORE:-(none)}"
# Hard precondition: the BEGIN tx is only valid in a block with
# index >= evidence_window_start(0) + merge_threshold_blocks(5), so a
# chain that never reached height 5 can NEVER include it. An empty
# H_BEFORE (dead RPC) would also silently turn EFF into 20 via bash
# arithmetic on an empty var — fail hard instead of degrading.
if [ -z "$H_BEFORE" ] || ! [ "$H_BEFORE" -ge 5 ] 2>/dev/null; then
  fail_hard "chain did not reach height 5 (height=${H_BEFORE:-none})"
fi

PRIV1=$(python -c "import json; print(json.load(open('$T/n1/node_key.json'))['priv_seed'])")
# Bounds checks (R4 Phase 6) require:
#   effective_height >= block.index + merge_grace_blocks (genesis grace=2)
#   evidence_window_start + merge_threshold_blocks (5) <= block.index
# Use evidence_window_start=0 (always valid) and effective_height with
# plenty of slack so the tx lands in a block where index is in the
# valid window.
EFF=$((H_BEFORE + 20))

echo
echo "=== 6. Submit MERGE_BEGIN(shard=0, partner=1, region=us-east) at h=$EFF ==="
SUBMIT_OUT=$($DETERM submit-merge-event \
  --priv "$PRIV1" \
  --from node1 \
  --event begin \
  --shard-id 0 --partner-id 1 \
  --effective-height "$EFF" \
  --evidence-window-start 0 \
  --refugee-region us-east \
  --fee 0 \
  --rpc-port 8771 2>&1)
SUBMIT_RC=$?
echo "$SUBMIT_OUT" | tail -4 | sed 's/^/  | /'
if [ "$SUBMIT_RC" -ne 0 ] || ! echo "$SUBMIT_OUT" | grep -q '"queued"'; then
  fail_hard "MERGE_BEGIN submit rejected (rc=$SUBMIT_RC)"
fi

echo
echo "=== 7. Wait for tx inclusion + a few more blocks ==="
INCLUDED_BEGIN=false
for _ in $(seq 1 60); do
  H=$($DETERM status --rpc-port 8771 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -gt $((H_BEFORE + 3)) ] 2>/dev/null; then INCLUDED_BEGIN=true; break; fi
  sleep 0.5
done
if ! $INCLUDED_BEGIN; then
  fail_hard "chain stalled after MERGE_BEGIN submit (height=$H, want > $((H_BEFORE + 3)))"
fi

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
H_AFTER_BEGIN=$($DETERM status --rpc-port 8771 2>/dev/null \
                | python -c "import sys,json
try: print(json.load(sys.stdin)['height'])
except: pass")
# Same empty-var arithmetic hazard as H_BEFORE: fail hard on dead RPC.
if [ -z "$H_AFTER_BEGIN" ]; then
  fail_hard "status RPC dead before MERGE_END submit"
fi
END_EFF=$((H_AFTER_BEGIN + 20))
SUBMIT_END_OUT=$($DETERM submit-merge-event \
  --priv "$PRIV1" \
  --from node1 \
  --event end \
  --shard-id 0 --partner-id 1 \
  --effective-height "$END_EFF" \
  --evidence-window-start 0 \
  --fee 0 \
  --rpc-port 8771 2>&1)
SUBMIT_END_RC=$?
echo "$SUBMIT_END_OUT" | tail -4 | sed 's/^/  | /'
if [ "$SUBMIT_END_RC" -ne 0 ] || ! echo "$SUBMIT_END_OUT" | grep -q '"queued"'; then
  fail_hard "MERGE_END submit rejected (rc=$SUBMIT_END_RC)"
fi

INCLUDED_END=false
for _ in $(seq 1 60); do
  H=$($DETERM status --rpc-port 8771 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -gt "$((H_AFTER_BEGIN + 3))" ] 2>/dev/null; then INCLUDED_END=true; break; fi
  sleep 0.5
done
if ! $INCLUDED_END; then
  fail_hard "chain stalled after MERGE_END submit (height=$H, want > $((H_AFTER_BEGIN + 3)))"
fi

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
# De-vacuated: END only counts if BEGIN actually applied — an empty
# merge_state on a chain where MERGE_BEGIN never landed must NOT read
# as a successful erase. Assert the 1 -> 0 transition.
if $PASS_BEGIN && [ "$MERGE_COUNT_END" = "0" ]; then PASS_END=true; fi

if $PASS_BEGIN && $PASS_END; then
  echo "  ok: submit-merge-event CLI accepted"
  echo "  ok: validator EXTENDED-mode gate passed"
  echo "  ok: MERGE_BEGIN inserted {shard=0, partner=1, region=us-east}"
  echo "  ok: snapshot persisted merge_state"
  echo "  ok: MERGE_END erased the entry (1 -> 0)"
  echo "  PASS: test_under_quorum_merge"
  exit 0
else
  echo "  begin merge_state count: $MERGE_COUNT (want 1), entry: $MERGE_FIRST"
  echo "  end merge_state count: $MERGE_COUNT_END (want 0, conditioned on BEGIN)"
  echo "  FAIL: test_under_quorum_merge (BEGIN_ok=$PASS_BEGIN END_ok=$PASS_END)"
  exit 1
fi
