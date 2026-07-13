#!/usr/bin/env bash
# D3.6 / S-036 — MERGE_EVENT is fail-closed on SHARD chains.
#
# HISTORY: this was the R4 MERGE_EVENT smoke test that submitted a MERGE_BEGIN to
# a SHARD and asserted the shard ACCEPTED + applied it (populating merge_state_).
# D3.6 (S-036) reversed that: MERGE_EVENT is a BEACON-coordinated event
# (block.hpp: "valid only under BEACON chain role"), and a shard cannot verify the
# historical distress witness (the `t:` records are beacon-only state). Accepting a
# shard-submitted MERGE_BEGIN would admit a FABRICATED-distress committee dilution
# unchecked — the reachable S-036 exploit. So the validator now fail-closes
# MERGE_EVENT on every non-BEACON chain (validator.cpp MERGE_EVENT branch,
# chain_role != BEACON -> reject).
#
# What this verifies NOW:
#   1. A shard-submitted MERGE_BEGIN NEVER populates merge_state_ (the fabricated
#      merge is rejected at block validation — the reachable exploit is closed).
#   2. The chain keeps advancing past the submit (the rejected tx does not stall
#      block production — same handling as any other chain-invalid tx type, e.g.
#      REGION_CHANGE / PARAM_CHANGE-uncontrolled).
#
# The BEACON-path historical witness (accept genuine distress / reject fabricated)
# is the deterministic in-process falsifier (D3.7); the beacon merge flow itself is
# owner-gated Layer-2 work.
#
# Topology: 1 SHARD chain (shard_id=0, region=us-east, S=3 satisfies
# the EXTENDED >=3 gate). 4 validators all online (M=4, K=3) — which is
# now also the shipped `web` default (the S-044/S-045 retune from M=3/K=2).
# K=3 because K=2 committees WEDGED under ordinary timing skew (the
# abort-claim quorum at K=2 was K-1=1, so a single straggle excluded a
# member with one claim, cascading until the pool fell below K). That is
# S-044, now ✅ Mitigated (fix F-a makes the quorum max(2,K-1),
# unsatisfiable at K=2; SECURITY.md §S-044). The merge-event machinery
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
# The mempool may QUEUE the tx (rejection then happens at block validation) or
# reject it up-front — either is fine. The security assertion below is that the
# shard NEVER APPLIES it (merge_state stays empty) and that it does not stall.
echo "  (submit result noted; the block-validation fail-close is the real gate)"

echo
echo "=== 7. Wait several blocks — the rejected MERGE_EVENT must NOT stall ==="
# Same handling as any chain-invalid tx (REGION_CHANGE / PARAM_CHANGE-uncontrolled
# / CT-disabled): the fail-closed MERGE_EVENT never enters a valid block, and block
# production keeps advancing. A stall here would be a real liveness regression.
CHAIN_ADVANCED=false
for _ in $(seq 1 90); do
  H=$($DETERM status --rpc-port 8771 2>/dev/null \
       | python -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)")
  if [ "$H" -gt $((H_BEFORE + 4)) ] 2>/dev/null; then CHAIN_ADVANCED=true; break; fi
  sleep 0.5
done
if ! $CHAIN_ADVANCED; then
  fail_hard "chain STALLED after the shard MERGE_BEGIN submit (height=$H, want > $((H_BEFORE + 4))) — a fail-closed MERGE_EVENT must not halt block production"
fi

echo
echo "=== 8. Snapshot + verify merge_state stayed EMPTY (fabricated merge NOT applied) ==="
$DETERM snapshot create --out $T/snap.json --rpc-port 8771 2>&1 | tail -1
MERGE_COUNT=$(python -c "
import json
try:
    s = json.load(open('$T/snap.json'))
    print(len(s.get('merge_state', [])))
except Exception:
    print(-1)")
echo "  merge_state entries: $MERGE_COUNT (want 0 — shard fail-closed the merge)"
# Best-effort diagnostic: the D3.6 reject reason should appear in a node log.
if grep -rhq "MERGE_EVENT valid only on a BEACON" $T/n*/log 2>/dev/null; then
  echo "  ok: node log shows the D3.6 BEACON-only reject reason"
fi

echo
echo "=== Test summary ==="
if [ "$MERGE_COUNT" = "0" ] && $CHAIN_ADVANCED; then
  echo "  ok: chain advanced past the submit (a fail-closed tx does not stall)"
  echo "  ok: merge_state stayed EMPTY — the shard fail-closed the fabricated"
  echo "       MERGE_BEGIN (D3.6 / S-036: the reachable committee-dilution exploit"
  echo "       is closed; MERGE_EVENT is beacon-coordinated only)"
  echo "  PASS: test_under_quorum_merge"
  exit 0
else
  echo "  merge_state count: $MERGE_COUNT (want 0), chain_advanced=$CHAIN_ADVANCED"
  echo "  FAIL: test_under_quorum_merge (shard did NOT fail-close the merge, or the chain stalled)"
  exit 1
fi
