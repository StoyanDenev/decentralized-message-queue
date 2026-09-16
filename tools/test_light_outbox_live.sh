#!/usr/bin/env bash
# determ-light outbox — LIVE gate (single-node chain; NOT part of FAST=1).
#
# The offline gate (tools/test_light_outbox.sh) proves the local guarantees and
# drives the real submit/reconcile cores over a fixture chain. This gate runs the
# same CLI against a REAL daemon so the contract is confirmed end to end:
#   1. three queued TRANSFERs → submit → reconcile until FINALIZED/APPLIED;
#      the sender's verified balance and nonce move by exactly the queued totals;
#      `verify-tx-inclusion` agrees with the recorded heights.
#   2. lost reply (DETERM_LIGHT_OUTBOX_INJECT=drop_response) → UNKNOWN → the
#      identical bytes are re-sent → exactly ONE application on the ledger.
#   3. daemon outage: submit while the daemon is down keeps the slot QUEUED with
#      a transport note; after the daemon restarts from its chain files the same
#      bytes are submitted and finalized (client + node restart survival).
#   4. a fee bump at the same nonce: both alternates watched; exactly one
#      application; the winner is attributed with the original msg_id.
#   5. an explicit stale nonce (a second outbox for the same key, an A1
#      violation) → STALE at submit → CONSUMED/UNLOCATED at reconcile — never
#      re-sent, never silently lost; prune --include-unlocated raises the floor
#      (dropping a quarantined file below it) and an explicit --nonce below it
#      is refused.
#   6. two submit workers racing on one outbox: one is locked out (exit 5) or
#      they serialize; the ledger still applies each slot once.
#   7. a daemon on another chain is refused (exit 6) before anything is sent.
# SKIPs (exit 0) when the binaries are absent or the local chain cannot mint.
#
# Run from repo root: bash tools/test_light_outbox_live.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

for b in "${DETERM:-}" "${DETERM_WALLET:-}" "${DETERM_LIGHT:-}"; do
  if [ -z "$b" ] || [ ! -x "$b" ]; then echo "  SKIP: determ / determ-wallet / determ-light binary not found"; exit 0; fi
done

T=test_light_outbox_live
TABS=$PROJECT_ROOT/$T
NODE_PID=""
cleanup() { [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null; sleep 0.5; [ -n "$NODE_PID" ] && kill -9 "$NODE_PID" 2>/dev/null; true; }
trap cleanup EXIT INT
rm -rf "$T"; mkdir -p "$T/n1" "$T/g2"
pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}
PY=python
command -v python >/dev/null 2>&1 || PY=python3
L="$DETERM_LIGHT"
RPC=8791

echo "=== setup: keys, genesis (sender funded), single node ==="
"$DETERM_WALLET" account-create-batch --count 2 --json > "$T/keys.json" 2>/dev/null
ADDR_A=$($PY -c "import json; print(json.load(open('$T/keys.json'))['accounts'][0]['address'])")
ADDR_B=$($PY -c "import json; print(json.load(open('$T/keys.json'))['accounts'][1]['address'])")
KPRIV_A=$($PY -c "import json; print(json.load(open('$T/keys.json'))['accounts'][0]['privkey_hex'])")
"$DETERM_WALLET" account-import --priv "$KPRIV_A" --out "$T/key_a.bin" >/dev/null 2>&1
$DETERM init --data-dir "$T/n1" --profile single_test >/dev/null 2>&1
$DETERM genesis-tool peer-info node1 --data-dir "$T/n1" --stake 1000 > "$T/p1.json"
cat > "$T/gen.json" <<EOF
{"chain_id":"test-light-outbox","m_creators":1,"k_block_sigs":1,"block_subsidy":1,
 "initial_creators":[$(tr -d '\n' < "$T/p1.json")],
 "initial_balances":[{"domain":"$ADDR_A","balance":10000}]}
EOF
$DETERM genesis-tool build "$T/gen.json" >/dev/null 2>&1 || { echo "  SKIP: genesis-tool build failed"; exit 0; }
GHASH=$(cat "$T/gen.json.hash")
cp "$T/gen.json" "$T/g2/gen.json"
$PY - "$T/n1/config.json" "$TABS" "$GHASH" "$RPC" <<'EOF'
import json, sys
p, tabs, ghash, rpc = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
c = json.load(open(p))
c.update({'domain': 'node1', 'listen_port': rpc - 1000, 'rpc_port': rpc, 'bootstrap_peers': [],
          'genesis_path': tabs + '/gen.json', 'genesis_hash': ghash, 'chain_path': tabs + '/n1/chain.json',
          'key_path': tabs + '/n1/node_key.json', 'data_dir': tabs + '/n1',
          'tx_commit_ms': 500, 'block_sig_ms': 500, 'abort_claim_ms': 250})
json.dump(c, open(p, 'w'), indent=2)
EOF
start_node() { $DETERM start --config "$T/n1/config.json" >> "$T/n1/log" 2>&1 & NODE_PID=$!; }
height() { $DETERM status --rpc-port $RPC 2>/dev/null | $PY -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)"; }
wait_height() { local want=$1; for _ in $(seq 1 120); do H=$(height); [ "${H:-0}" -ge "$want" ] 2>/dev/null && return 0; sleep 0.5; done; return 1; }
start_node; sleep 0.5
if ! wait_height 3; then echo "  SKIP: local single-node chain did not mint (height=$(height))"; exit 0; fi
echo "  chain height: $(height)"

G="$T/gen.json"; K="$T/key_a.bin"; OB="$T/outbox"
state() { "$L" outbox status --outbox "$1" --json 2>/dev/null | $PY -c "
import json,sys; d=json.load(sys.stdin)
for s in d['slots']:
    if s['nonce']==$2: print(s['state']+'/'+s['apply']); break
else: print('none')"; }
field() { "$L" outbox status --outbox "$1" --json 2>/dev/null | $PY -c "
import json,sys; d=json.load(sys.stdin)
for s in d['slots']:
    if s['nonce']==$2: print(s['$3']); break"; }
reconcile_until() { # dir nonce want tries
  local dir=$1 n=$2 want=$3 tries=${4:-40}
  for _ in $(seq 1 "$tries"); do
    "$L" outbox reconcile --outbox "$dir" --genesis "$G" --rpc-port $RPC --wait 30 >/dev/null 2>&1
    [ "$(state "$dir" "$n")" = "$want" ] && return 0
    sleep 1
  done
  return 1
}
trustless() { "$L" balance-trustless --rpc-port $RPC --genesis "$G" --domain "$ADDR_A" --json --wait 30 2>/dev/null | tail -1 | $PY -c "import json,sys; d=json.load(sys.stdin); print(d['$1'])"; }

echo
echo "=== 1. three queued TRANSFERs → SUBMITTED → FINALIZED/APPLIED; exact balance/nonce deltas ==="
PRE_BAL=$(trustless balance); PRE_NONCE=$(trustless next_nonce)
for i in 1 2 3; do
  OUT=$("$L" outbox enqueue --outbox "$OB" --genesis "$G" --keyfile "$K" --to "$ADDR_B" --amount $((100 * i)) --fee 1 --rpc-port $RPC 2>&1)
  echo "$OUT" | grep -q "queued locally" || assert false "enqueue $i: $OUT"
done
"$L" outbox status --outbox "$OB" | grep -c "QUEUED" | grep -q 3 && assert true "three slots QUEUED with consecutive nonces from the daemon hint" || assert false "three QUEUED slots"
"$L" outbox submit --outbox "$OB" --genesis "$G" --rpc-port $RPC > "$T/submit1.txt" 2>&1
N_SUB=$("$L" outbox status --outbox "$OB" | grep -c SUBMITTED)
assert "$([ "$N_SUB" = "3" ] && echo true || echo false)" "submit → all three SUBMITTED (an RPC 'queued' is not finality)"
OK=true; for n in 0 1 2; do reconcile_until "$OB" $((PRE_NONCE + n)) "FINALIZED/APPLIED" || OK=false; done
assert "$OK" "reconcile → every slot FINALIZED/APPLIED (inclusion + successor + nonce proof)"
POST_BAL=$(trustless balance); POST_NONCE=$(trustless next_nonce)
assert "$([ $((PRE_BAL - POST_BAL)) = "603" ] && [ $((POST_NONCE - PRE_NONCE)) = "3" ] && echo true || echo false)" "ledger deltas exact: balance -603 (100+200+300 + 3 fees), nonce +3 (got -$((PRE_BAL - POST_BAL)), +$((POST_NONCE - PRE_NONCE)))"
H0=$(field "$OB" "$PRE_NONCE" included_height); TX0=$(field "$OB" "$PRE_NONCE" tx_hash)
"$L" verify-tx-inclusion --rpc-port $RPC --genesis "$G" --tx-hash "$TX0" --height "$H0" 2>&1 | grep -q "INCLUDED" && assert true "verify-tx-inclusion confirms the recorded height for slot 0" || assert false "verify-tx-inclusion at recorded height"

echo
echo "=== 2. lost reply → UNKNOWN → identical bytes re-sent → exactly one application ==="
PRE_BAL=$(trustless balance); PRE_NONCE=$(trustless next_nonce)
"$L" outbox enqueue --outbox "$OB" --genesis "$G" --keyfile "$K" --to "$ADDR_B" --amount 50 --fee 1 --rpc-port $RPC >/dev/null 2>&1
DETERM_LIGHT_OUTBOX_INJECT=drop_response "$L" outbox submit --outbox "$OB" --genesis "$G" --rpc-port $RPC >/dev/null 2>&1
S=$(state "$OB" "$PRE_NONCE")
assert "$([ "$S" = "UNKNOWN/UNKNOWN" ] && echo true || echo false)" "reply dropped → slot UNKNOWN (got $S)"
HASH_BEFORE=$(field "$OB" "$PRE_NONCE" tx_hash)
"$L" outbox submit --outbox "$OB" --genesis "$G" --rpc-port $RPC --now > "$T/submit2.txt" 2>&1
HASH_AFTER=$(field "$OB" "$PRE_NONCE" tx_hash)
assert "$([ "$HASH_BEFORE" = "$HASH_AFTER" ] && echo true || echo false)" "the re-send carries the same tx hash (same nonce, same bytes)"
reconcile_until "$OB" "$PRE_NONCE" "FINALIZED/APPLIED" && assert true "the message finalizes exactly once" || assert false "finalize after lost reply (state $(state "$OB" "$PRE_NONCE"))"
POST_BAL=$(trustless balance)
assert "$([ $((PRE_BAL - POST_BAL)) = "51" ] && echo true || echo false)" "balance moved by exactly one amount+fee (51; got $((PRE_BAL - POST_BAL)))"

echo
echo "=== 3. daemon outage: queued through the outage, submitted after the restart ==="
PRE_NONCE=$(trustless next_nonce)
"$L" outbox enqueue --outbox "$OB" --genesis "$G" --keyfile "$K" --to "$ADDR_B" --amount 7 --fee 1 --rpc-port $RPC >/dev/null 2>&1
kill "$NODE_PID" 2>/dev/null; wait "$NODE_PID" 2>/dev/null; NODE_PID=""
sleep 0.5
"$L" outbox submit --outbox "$OB" --genesis "$G" --rpc-port $RPC > "$T/submit3.txt" 2>&1; RC=$?
S=$(state "$OB" "$PRE_NONCE"); LO=$(field "$OB" "$PRE_NONCE" last_outcome)
assert "$([ "$RC" = "0" ] && [ "$S" = "QUEUED/UNKNOWN" ] && [ "$LO" = "transport" ] && echo true || echo false)" "daemon down: slot stays QUEUED with a transport note (rc=$RC state=$S last=$LO)"
start_node; sleep 0.5
wait_height 1 || assert false "daemon restarted from its chain files"
"$L" outbox submit --outbox "$OB" --genesis "$G" --rpc-port $RPC --now >/dev/null 2>&1
reconcile_until "$OB" "$PRE_NONCE" "FINALIZED/APPLIED" && assert true "after the restart the same bytes are submitted and finalized" || assert false "finalize after outage (state $(state "$OB" "$PRE_NONCE"))"

echo
echo "=== 4. fee bump: both alternates watched, exactly one application, original msg_id ==="
PRE_BAL=$(trustless balance); PRE_NONCE=$(trustless next_nonce)
"$L" outbox enqueue --outbox "$OB" --genesis "$G" --keyfile "$K" --to "$ADDR_B" --amount 20 --fee 0 --rpc-port $RPC >/dev/null 2>&1
MSG=$(field "$OB" "$PRE_NONCE" msg_id)
"$L" outbox submit --outbox "$OB" --genesis "$G" --rpc-port $RPC >/dev/null 2>&1
"$L" outbox replace --outbox "$OB" --genesis "$G" --keyfile "$K" --nonce "$PRE_NONCE" --fee 2 >/dev/null 2>&1
"$L" outbox submit --outbox "$OB" --genesis "$G" --rpc-port $RPC --now >/dev/null 2>&1
reconcile_until "$OB" "$PRE_NONCE" "FINALIZED/APPLIED" && assert true "the slot finalizes once with two alternates watched" || assert false "fee-bump finalize (state $(state "$OB" "$PRE_NONCE"))"
POST_BAL=$(trustless balance)
DELTA=$((PRE_BAL - POST_BAL))
assert "$([ "$DELTA" = "20" ] || [ "$DELTA" = "22" ] && echo true || echo false)" "exactly one alternate applied: balance delta is 20 or 22 (got $DELTA)"
assert "$([ "$(field "$OB" "$PRE_NONCE" msg_id)" = "$MSG" ] && echo true || echo false)" "the applied message keeps the original msg_id"

echo
echo "=== 5. explicit stale nonce (second outbox, same key = A1 violation) → STALE → CONSUMED/UNLOCATED ==="
OB2="$T/outbox2"
"$L" outbox enqueue --outbox "$OB2" --genesis "$G" --keyfile "$K" --to "$ADDR_B" --amount 5 --fee 0 --nonce 0 >/dev/null 2>&1
"$L" outbox submit --outbox "$OB2" --genesis "$G" --rpc-port $RPC > "$T/submit5.txt" 2>&1
assert "$([ "$(field "$OB2" 0 last_outcome)" = "stale-nonce" ] && echo true || echo false)" "submit reports stale-nonce"
"$L" outbox reconcile --outbox "$OB2" --genesis "$G" --rpc-port $RPC --wait 30 >/dev/null 2>&1
S=$(state "$OB2" 0)
assert "$([ "$S" = "CONSUMED/UNLOCATED" ] && echo true || echo false)" "reconcile → CONSUMED/UNLOCATED (nonce proven spent, no inclusion located) (got $S)"
"$L" outbox prune --outbox "$OB2" --older-than 0 >/dev/null 2>&1
[ "$(state "$OB2" 0)" = "CONSUMED/UNLOCATED" ] && assert true "prune keeps an UNLOCATED slot unless --include-unlocated" || assert false "prune kept UNLOCATED"
cp "$OB2/00000000000000000000.msg" "$OB2/00000000000000000000.msg.corrupt-1"   # a quarantined file at a nonce about to be proven consumed
"$L" outbox prune --outbox "$OB2" --older-than 0 --include-unlocated > "$T/prune5.txt" 2>&1
assert "$([ -z "$(ls "$OB2"/*.corrupt-* 2>/dev/null)" ] && grep -q "1 quarantined file(s) below the floor" "$T/prune5.txt" && echo true || echo false)" "prune drops a quarantined file once the floor proves its nonce consumed"
OUT=$("$L" outbox enqueue --outbox "$OB2" --genesis "$G" --keyfile "$K" --to "$ADDR_B" --amount 5 --fee 0 --nonce 0 2>&1); RC=$?
assert "$([ "$RC" = "1" ] && echo "$OUT" | grep -q "nonce floor" && [ "$(state "$OB2" 0)" = "none" ] && echo true || echo false)" "after the prune the floor refuses an explicit --nonce below it (rc=$RC)"

echo
echo "=== 6. two submit workers racing on one outbox ==="
PRE_NONCE=$(trustless next_nonce); PRE_BAL=$(trustless balance)
"$L" outbox enqueue --outbox "$OB" --genesis "$G" --keyfile "$K" --to "$ADDR_B" --amount 3 --fee 0 --rpc-port $RPC >/dev/null 2>&1
"$L" outbox submit --outbox "$OB" --genesis "$G" --rpc-port $RPC --now > "$T/w1.txt" 2>&1 & W1=$!
"$L" outbox submit --outbox "$OB" --genesis "$G" --rpc-port $RPC --now > "$T/w2.txt" 2>&1 & W2=$!
wait $W1; R1=$?; wait $W2; R2=$?
assert "$([ "$R1" = "0" -o "$R1" = "5" ] && [ "$R2" = "0" -o "$R2" = "5" ] && echo true || echo false)" "each worker either ran or was locked out (rc $R1 / $R2)"
reconcile_until "$OB" "$PRE_NONCE" "FINALIZED/APPLIED" && assert true "the raced slot finalizes" || assert false "raced slot finalize"
POST_BAL=$(trustless balance)
assert "$([ $((PRE_BAL - POST_BAL)) = "3" ] && echo true || echo false)" "the ledger applied the raced slot exactly once (delta 3; got $((PRE_BAL - POST_BAL)))"

echo
echo "=== 7. a daemon on another chain is refused before anything is sent ==="
cat > "$T/g2/gen2.json" <<EOF
{"chain_id":"other-chain","m_creators":1,"k_block_sigs":1,"initial_creators":[$(tr -d '\n' < "$T/p1.json")],"initial_balances":[]}
EOF
$DETERM genesis-tool build "$T/g2/gen2.json" >/dev/null 2>&1
OB3="$T/outbox3"
"$L" outbox enqueue --outbox "$OB3" --genesis "$T/g2/gen2.json" --keyfile "$K" --to "$ADDR_B" --amount 1 --fee 0 --nonce 0 >/dev/null 2>&1
"$L" outbox submit --outbox "$OB3" --genesis "$T/g2/gen2.json" --rpc-port $RPC > "$T/submit7.txt" 2>&1; RC=$?
assert "$([ "$RC" = "6" ] && [ "$(field "$OB3" 0 attempts)" = "0" ] && echo true || echo false)" "genesis mismatch → exit 6, nothing sent (rc=$RC)"

echo
echo "=== summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then echo "  PASS: test_light_outbox_live"; exit 0; fi
echo "  FAIL: test_light_outbox_live"; exit 1
