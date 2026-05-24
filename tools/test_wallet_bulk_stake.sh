#!/usr/bin/env bash
# determ-wallet bulk-stake CLI test.
#
# Exercises batch STAKE submission from a single keyfile across many
# validator-domain rows via the daemon's RPC, with per-row nonce
# sequencing. STAKE differs from TRANSFER in wire format: tx.to is
# empty, tx.amount is 0, and the stake amount is carried as an 8-byte
# LE payload (matches chain::apply STAKE branch). The chain credits
# stake to tx.from (the staker), so the keyfile owner accumulates the
# sum of all submitted amounts. Verifies:
#
#   1. Help text mentions bulk-stake.
#   2. Missing --priv-keyfile / --stake-list returns exit 1.
#   3. Missing --rpc-port (without --dry-run) returns exit 1.
#   4. File-not-found on --stake-list returns exit 1.
#   5. Bring up a single-node daemon, fund a staker with a large
#      balance, prepare a 3-row stake-list.
#   6. JSON batch submission: all 3 succeed, nonce-sequencing correct,
#      ending_nonce - starting_nonce == batch_size, staker's
#      stake_locked increases by sum(amounts).
#   7. CSV batch (no header) yields same per-row results.
#   8. --dry-run skips submission, each row carries signed_tx, sender
#      stake unchanged.
#   9. --continue-on-error with one bad row keeps the run going; good
#      rows still submit; exit 2; aborted=false.
#  10. Default abort-on-first-error halts at first failing row;
#      subsequent rows not attempted; aborted=true; exit 2.
#  11. JSON envelope shape: top-level keys complete.
#  12. --starting-nonce override pins the sequencing start.
#  13. Malformed CSV (missing amount column) returns exit 1.
#  14. Stake-list with zero-amount row returns exit 1 (parse-time
#      validation; STAKE-with-zero burns nonce + fee on-chain).
#  15. signed_tx envelope shape: type=3, to="", amount=0, payload is
#      16-hex (8 bytes encoded), 128-hex sig, 64-hex hash.
#
# Run from repo root: bash tools/test_wallet_bulk_stake.sh

set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"
T=test_wallet_bulk_stake
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

rm -rf $T
mkdir -p $T/n1

pass_count=0; fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing: $2"; fail_count=$((fail_count + 1)); fi
}

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# ── 1. Help text mentions bulk-stake ─────────────────────────────────────────
echo "=== 1. Help text mentions bulk-stake ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "bulk-stake" "help mentions bulk-stake"

# ── 2. Missing --priv-keyfile / --stake-list: exit 1 ─────────────────────────
echo
echo "=== 2. Missing required args: exit 1 ==="
set +e
ERR=$("$WALLET" bulk-stake --rpc-port 18847 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "missing --priv-keyfile/--stake-list returns exit 1"
assert_contains "$ERR" "priv-keyfile" "diagnostic mentions --priv-keyfile"

# ── 3. Missing --rpc-port without --dry-run: exit 1 ──────────────────────────
echo
echo "=== 3. Missing --rpc-port (no --dry-run): exit 1 ==="
echo '{"stakes":[]}' > $T/empty.json
# For these "missing arg" smoke checks the keyfile just needs to be
# parseable; we'll replace it with the registered-validator keyfile
# below once the daemon is up.
"$WALLET" account-create-batch --count 1 --out $T/staker.json >/dev/null 2>&1
$PY -c "
import json
with open('$T/staker.json') as f: d=json.load(f)
acc = d['accounts'][0]
out = {'address': acc['address'], 'privkey_hex': acc['privkey_hex']}
with open('$T/staker_single.json','w') as f: json.dump(out, f)
"
set +e
ERR=$("$WALLET" bulk-stake --priv-keyfile $T/staker_single.json \
       --stake-list $T/empty.json 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "missing --rpc-port returns exit 1"
assert_contains "$ERR" "rpc-port" "diagnostic mentions --rpc-port"

# ── 4. File-not-found on --stake-list: exit 1 ────────────────────────────────
echo
echo "=== 4. File-not-found on --stake-list: exit 1 ==="
set +e
ERR=$("$WALLET" bulk-stake --priv-keyfile $T/staker_single.json \
       --stake-list $T/does-not-exist.json --dry-run 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "missing --stake-list returns exit 1"
assert_contains "$ERR" "cannot open" "diagnostic mentions cannot open"

# ── 5. Bring up single-node daemon + fund the validator domain ───────────────
# STAKE txs from anon-addresses are rejected by the chain
# (Node::verify_tx_signature_locked permits only TRANSFER from anon);
# the keyfile MUST belong to a registered validator domain. We use the
# node's own ed25519 key as the wallet keyfile, with address="node1"
# (the registered domain). Fund "node1" with a fat balance so STAKEs
# clear at apply time.
echo
echo "=== 5. Init single-node daemon + fund the validator domain ==="
$DETERM init --data-dir $T/n1 --profile single_test 2>&1 | tail -1 >/dev/null
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json

# Repurpose the node's key as the wallet keyfile (address="node1").
NODE_PRIV=$($PY -c "import json; print(json.load(open('$T/n1/node_key.json'))['priv_seed'])")
$PY -c "
import json
out = {'address': 'node1', 'privkey_hex': '$NODE_PRIV'}
with open('$T/staker_single.json','w') as f: json.dump(out, f)
"
ADDR_S=node1
echo "  Staker  ADDR_S = $ADDR_S (registered validator domain)"

GEN_FUND_S=1000000
cat > $T/gen.json <<EOF
{
  "chain_id": "test-bulk-stake",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "initial_balances": [
    {"domain": "node1", "balance": $GEN_FUND_S}
  ],
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n')
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1 >/dev/null
GHASH=$(cat $T/gen.json.hash)

RPC_PORT=18847
$PY -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain'] = 'node1'
c['listen_port'] = 17847
c['rpc_port'] = $RPC_PORT
c['genesis_path'] = '$TABS/gen.json'
c['genesis_hash'] = '$GHASH'
c['chain_path'] = '$TABS/n1/chain.json'
c['key_path']   = '$TABS/n1/node_key.json'
c['data_dir']   = '$TABS/n1'
c['tx_commit_ms']  = 200
c['block_sig_ms']  = 200
c['abort_claim_ms']= 100
with open('$T/n1/config.json','w') as f: json.dump(c, f, indent=2)
"

$DETERM start --config $T/n1/config.json > $T/n1/log 2>&1 &
NODE_PIDS[0]=$!
sleep 2

# Wait for chain to advance past genesis.
for _ in $(seq 1 40); do
  H=$($DETERM status --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)" 2>/dev/null)
  [ "$H" -ge "2" ] && break
  sleep 0.5
done
echo "  chain advanced past genesis (height=$H)"

# ── 6. JSON batch (3 rows): all submit, nonce sequencing, stake credited ─────
echo
echo "=== 6. JSON batch (3 rows): all submit, stake credited ==="
EX_1=100
EX_2=200
EX_3=300
SUM_BATCH=$((EX_1 + EX_2 + EX_3))
cat > $T/stakes.json <<EOF
{"stakes":[
  {"domain": "validator1.v", "amount": $EX_1},
  {"domain": "validator2.v", "amount": $EX_2},
  {"domain": "validator3.v", "amount": $EX_3}
]}
EOF

# Capture pre-stake locked amount (zero for a never-staked address).
PRE_LOCKED=$($DETERM nonce $ADDR_S --rpc-port $RPC_PORT 2>/dev/null | \
            $PY -c "import sys,json
try:
    d=json.load(sys.stdin); print(d.get('next_nonce',0))
except: print(0)")
PRE_STAKE=$($PY -c "
import json, sys, urllib.request as u
" 2>/dev/null || echo "0")
# Just use the wallet's stake_info via RPC. Simpler: call $DETERM stakes
# and grep, but $DETERM stake_info is the per-domain query.
STAKE_PRE=$($DETERM stake_info $ADDR_S --rpc-port $RPC_PORT 2>/dev/null | \
            $PY -c "import sys,json
try:
    d=json.load(sys.stdin); print(d.get('locked',0))
except: print(0)")
echo "  pre-stake locked = $STAKE_PRE"

set +e
OUT=$("$WALLET" bulk-stake --priv-keyfile $T/staker_single.json \
       --stake-list $T/stakes.json --rpc-port $RPC_PORT 2>&1 | tr -d '\r')
RC=$?
set -e
echo "$OUT" | head -c 800; echo
assert_eq "$RC" "0" "JSON batch returns exit 0 (all rows ok)"

BSIZE=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['batch_size'])")
SUB=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['submitted'])")
FAIL=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['failed'])")
SN=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['starting_nonce'])")
EN=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['ending_nonce'])")
assert_eq "$BSIZE" "3" "batch_size = 3"
assert_eq "$SUB"   "3" "submitted = 3"
assert_eq "$FAIL"  "0" "failed = 0"
assert_eq "$((EN - SN))" "3" "ending_nonce - starting_nonce == batch_size (3)"

# Per-row nonce sequencing: row i has nonce = starting_nonce + i.
R0_NCE=$(echo "$OUT" | $PY -c "import sys,json; d=json.load(sys.stdin); print(d['results'][0]['nonce'])")
R1_NCE=$(echo "$OUT" | $PY -c "import sys,json; d=json.load(sys.stdin); print(d['results'][1]['nonce'])")
R2_NCE=$(echo "$OUT" | $PY -c "import sys,json; d=json.load(sys.stdin); print(d['results'][2]['nonce'])")
assert_eq "$((R0_NCE - SN))" "0" "row 0 nonce = starting_nonce + 0"
assert_eq "$((R1_NCE - SN))" "1" "row 1 nonce = starting_nonce + 1"
assert_eq "$((R2_NCE - SN))" "2" "row 2 nonce = starting_nonce + 2"

# Each row reports status=ok with a 64-hex tx_hash + carries the
# correct domain label (mapped to row order).
ALL_OK=$(echo "$OUT" | $PY -c "
import sys,json
d=json.load(sys.stdin)
ok = all(row['status']=='ok' and len(row['tx_hash'])==64 for row in d['results'])
print('ok' if ok else 'fail')
")
assert_eq "$ALL_OK" "ok" "every row has status=ok and 64-hex tx_hash"

DOM0=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['results'][0]['domain'])")
DOM1=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['results'][1]['domain'])")
assert_eq "$DOM0" "validator1.v" "row 0 carries domain validator1.v"
assert_eq "$DOM1" "validator2.v" "row 1 carries domain validator2.v"

# Wait for txs to land + verify staker's stake_locked grew by sum.
sleep 3
STAKE_POST=$($DETERM stake_info $ADDR_S --rpc-port $RPC_PORT 2>/dev/null | \
             $PY -c "import sys,json
try:
    d=json.load(sys.stdin); print(d.get('locked',0))
except: print(0)")
echo "  post-stake locked = $STAKE_POST"
assert_eq "$STAKE_POST" "$((STAKE_PRE + SUM_BATCH))" "staker stake_locked grew by $SUM_BATCH (was $STAKE_PRE, now $STAKE_POST)"

# ── 7. CSV batch (no header) yields same per-row results ─────────────────────
echo
echo "=== 7. CSV batch (no header): all submit ==="
EX_1b=11
EX_2b=22
EX_3b=33
cat > $T/stakes.csv <<EOF
validator1.v,$EX_1b
validator2.v,$EX_2b
validator3.v,$EX_3b
EOF
set +e
OUT2=$("$WALLET" bulk-stake --priv-keyfile $T/staker_single.json \
        --stake-list $T/stakes.csv --rpc-port $RPC_PORT 2>&1 | tr -d '\r')
RC2=$?
set -e
assert_eq "$RC2" "0" "CSV batch returns exit 0"
SUB2=$(echo "$OUT2" | $PY -c "import sys,json; print(json.load(sys.stdin)['submitted'])")
assert_eq "$SUB2" "3" "CSV batch: submitted = 3"

# Confirm starting_nonce advanced past prior batch.
SN2=$(echo "$OUT2" | $PY -c "import sys,json; print(json.load(sys.stdin)['starting_nonce'])")
if [ "$SN2" -ge "3" ]; then
  assert_eq "ok" "ok" "second batch starting_nonce >= 3 (was $SN2; previous batch advanced nonce)"
else
  assert_eq "ok" "fail" "second batch starting_nonce >= 3 (got $SN2)"
fi
sleep 3
STAKE_AFTER_CSV=$($DETERM stake_info $ADDR_S --rpc-port $RPC_PORT 2>/dev/null | \
                   $PY -c "import sys,json
try:
    d=json.load(sys.stdin); print(d.get('locked',0))
except: print(0)")
EXPECTED_AFTER_CSV=$((STAKE_PRE + SUM_BATCH + EX_1b + EX_2b + EX_3b))
assert_eq "$STAKE_AFTER_CSV" "$EXPECTED_AFTER_CSV" "post-CSV stake_locked = $EXPECTED_AFTER_CSV"

# ── 8. --dry-run: no submission, signed_tx present, stake unchanged ──────────
echo
echo "=== 8. --dry-run: no submission, signed_tx present ==="
PRE_DRY_STAKE=$STAKE_AFTER_CSV
set +e
OUT3=$("$WALLET" bulk-stake --priv-keyfile $T/staker_single.json \
        --stake-list $T/stakes.json --rpc-port $RPC_PORT --dry-run 2>&1 | tr -d '\r')
RC3=$?
set -e
assert_eq "$RC3" "0" "--dry-run returns exit 0"
DRY=$(echo "$OUT3" | $PY -c "import sys,json; print(json.load(sys.stdin)['dry_run'])")
assert_eq "$DRY" "True" "dry_run = true in envelope"

# Every row has a signed_tx with the STAKE wire shape:
#   type=3, to="", amount=0, payload=16-hex (8 bytes LE), sig=128-hex,
#   hash=64-hex.
ALL_SIGNED=$(echo "$OUT3" | $PY -c "
import sys,json
d=json.load(sys.stdin)
ok = all(
    ('signed_tx' in row)
    and isinstance(row['signed_tx'], dict)
    and row['signed_tx'].get('type') == 3
    and row['signed_tx'].get('to') == ''
    and row['signed_tx'].get('amount') == 0
    and len(row['signed_tx'].get('payload','')) == 16
    and len(row['signed_tx'].get('sig','')) == 128
    and len(row['signed_tx'].get('hash','')) == 64
    for row in d['results']
)
print('ok' if ok else 'fail')
")
assert_eq "$ALL_SIGNED" "ok" "every dry-run row has signed_tx with STAKE shape (type=3, to='', amount=0, 16-hex payload, 128-hex sig, 64-hex hash)"

sleep 2
POST_DRY_STAKE=$($DETERM stake_info $ADDR_S --rpc-port $RPC_PORT 2>/dev/null | \
                 $PY -c "import sys,json
try:
    d=json.load(sys.stdin); print(d.get('locked',0))
except: print(0)")
assert_eq "$POST_DRY_STAKE" "$PRE_DRY_STAKE" "staker stake_locked unchanged after --dry-run"

# ── 9. --continue-on-error: one bad row, others continue, exit 2 ─────────────
echo
echo "=== 9. --continue-on-error with one bad row ==="
# Force a submit-time failure by reusing a nonce that's already been
# consumed. Override --starting-nonce to 0 (well below current); the
# middle row will still get rejected with stale-nonce... actually all
# 3 rows would fail. A cleaner failure: pin row 1 to an existing nonce
# (replay) and rows 0/2 to fresh ones.
#
# Easier: use --starting-nonce that's stale by 1; then row 0 = stale,
# row 1 = current, row 2 = future. Stale row 0 fails immediately with
# "stale nonce N (expected >= N+1)" but rows 1+2 will succeed.
#
# Simpler still: make the middle row insufficient-balance by setting a
# huge amount that consumes more than the staker has. STAKE
# pre-checks balance at submit_tx — but it does not (chain.cpp::case
# STAKE just charges + continues if balance is enough at APPLY time).
# Actually node.cpp::rpc_stake DOES pre-check; but rpc_submit_tx
# doesn't. So an amount > balance would land in mempool then fail at
# apply. We need a SYNCHRONOUS submit_tx error.
#
# Synchronous reject options:
#   - Stale nonce (rejected with "stale nonce")
#   - Bad signature (we sign correctly — can't trigger)
#   - Mempool full (hard to trigger here)
#
# Use stale-nonce on the middle row by submitting two batches with
# overlapping nonces. First we do a small 3-row run with --starting-
# nonce N. Then a 3-row run with --starting-nonce N+0 (row 0 stale,
# rows 1-2 fresh)... but ALL three are stale-or-replay since 1=replay,
# 2=replay. The middle-fail pattern requires careful nonce arithmetic.
#
# Cleanest approach: have the wallet submit a "valid run of 3 rows"
# at a starting_nonce N, but where row 1 is an EXACT replay of an
# already-submitted tx. Replay rejection per (from, nonce) when
# fee == incumbent: "incumbent tx at (from, nonce) has equal-or-
# higher fee".
#
# Step 1: submit 1 row at nonce N (consumes nonce N).
# Step 2: submit a 3-row batch at starting_nonce N-something so row 1
#         hits an existing nonce.
#
# Pragmatic: just submit rows 0 and 2 with fresh nonces, row 1 with a
# replay nonce. --continue-on-error: rows 0 + 2 succeed, row 1 fails.
sleep 3
CUR_NONCE=$($DETERM nonce $ADDR_S --rpc-port $RPC_PORT 2>/dev/null | \
            $PY -c "import sys,json
try:
    d=json.load(sys.stdin); print(d.get('next_nonce',0))
except: print(0)")
echo "  current next_nonce = $CUR_NONCE"

# Submit 1 isolated STAKE at nonce CUR_NONCE+1 (rows 0,1,2 of the
# batch will use CUR_NONCE, CUR_NONCE+1, CUR_NONCE+2 — so row 1 is
# the conflict). Use single-row dry-run? No — we need it on-chain.
# Use bulk-stake with starting_nonce = CUR_NONCE+1 and a 1-row list.
cat > $T/stakes_block.json <<EOF
{"stakes":[{"domain":"blocker.v","amount":7}]}
EOF
"$WALLET" bulk-stake --priv-keyfile $T/staker_single.json \
       --stake-list $T/stakes_block.json --rpc-port $RPC_PORT \
       --starting-nonce $((CUR_NONCE + 1)) >/dev/null 2>&1 || true

# Now submit a 3-row batch starting at CUR_NONCE; row 1 collides with
# the blocker we just put in mempool at nonce CUR_NONCE+1.
cat > $T/stakes_mixed.json <<EOF
{"stakes":[
  {"domain": "v1.v", "amount": 5},
  {"domain": "v2.v", "amount": 7},
  {"domain": "v3.v", "amount": 9}
]}
EOF
set +e
"$WALLET" bulk-stake --priv-keyfile $T/staker_single.json \
        --stake-list $T/stakes_mixed.json --rpc-port $RPC_PORT \
        --starting-nonce $CUR_NONCE --continue-on-error > $T/out5.raw 2>&1
RC5=$?
OUT5=$(tr -d '\r' < $T/out5.raw)
set -e

assert_eq "$RC5" "2" "--continue-on-error with failure returns exit 2"
FAIL5=$(echo "$OUT5" | $PY -c "import sys,json; print(json.load(sys.stdin)['failed'])")
SUB5=$(echo "$OUT5" | $PY -c "import sys,json; print(json.load(sys.stdin)['submitted'])")
ABT5=$(echo "$OUT5" | $PY -c "import sys,json; print(json.load(sys.stdin)['aborted'])")
# Row 1 hits replay; rows 0 + 2 succeed.
assert_eq "$FAIL5" "1" "--continue-on-error: failed = 1 (the colliding nonce row)"
assert_eq "$SUB5"  "2" "--continue-on-error: submitted = 2 (the two non-colliding rows)"
assert_eq "$ABT5"  "False" "--continue-on-error: aborted = false"

# Failed row carries a reason.
HAS_REASON=$(echo "$OUT5" | $PY -c "
import sys,json
d=json.load(sys.stdin)
err_rows = [r for r in d['results'] if r['status']=='error']
print('ok' if len(err_rows)>=1 and err_rows[0].get('reason') else 'fail')
")
assert_eq "$HAS_REASON" "ok" "--continue-on-error: failed row carries non-empty 'reason'"

# ── 10. Default abort-on-first-error: halt at first failing row ──────────────
echo
echo "=== 10. Default abort-on-first-error: halt at first failing row ==="
sleep 3
# Build a fresh mixed batch where row 0 is fresh, row 1 collides.
# Re-fetch CUR_NONCE, then plant blocker at CUR_NONCE+1, then submit
# 3 rows starting at CUR_NONCE.
CUR_NONCE2=$($DETERM nonce $ADDR_S --rpc-port $RPC_PORT 2>/dev/null | \
             $PY -c "import sys,json
try:
    d=json.load(sys.stdin); print(d.get('next_nonce',0))
except: print(0)")
"$WALLET" bulk-stake --priv-keyfile $T/staker_single.json \
       --stake-list $T/stakes_block.json --rpc-port $RPC_PORT \
       --starting-nonce $((CUR_NONCE2 + 1)) >/dev/null 2>&1 || true

set +e
"$WALLET" bulk-stake --priv-keyfile $T/staker_single.json \
        --stake-list $T/stakes_mixed.json --rpc-port $RPC_PORT \
        --starting-nonce $CUR_NONCE2 > $T/out6.raw 2>&1
RC6=$?
OUT6=$(tr -d '\r' < $T/out6.raw)
set -e

assert_eq "$RC6" "2" "default-abort returns exit 2"
ABT6=$(echo "$OUT6" | $PY -c "import sys,json; print(json.load(sys.stdin)['aborted'])")
FAIL6=$(echo "$OUT6" | $PY -c "import sys,json; print(json.load(sys.stdin)['failed'])")
RCNT6=$(echo "$OUT6" | $PY -c "import sys,json; print(len(json.load(sys.stdin)['results']))")
assert_eq "$ABT6"  "True" "default-abort: aborted = true"
assert_eq "$FAIL6" "1"    "default-abort: failed = 1"
assert_eq "$RCNT6" "2"    "default-abort: results length = 2 (row 0 ok + row 1 failed); row 2 not attempted"

# ── 11. JSON envelope top-level shape ────────────────────────────────────────
echo
echo "=== 11. JSON envelope top-level keys ==="
ENV_OK=$(echo "$OUT" | $PY -c "
import sys, json
d = json.load(sys.stdin)
keys = sorted(d.keys())
need = sorted(['keyfile','batch_size','submitted','failed','starting_nonce',
               'ending_nonce','dry_run','aborted','results'])
print('ok' if keys == need else f'missing: have {keys}, need {need}')
")
assert_eq "$ENV_OK" "ok" "top-level keys are {keyfile, batch_size, submitted, failed, starting_nonce, ending_nonce, dry_run, aborted, results}"

# ── 12. --starting-nonce override pins the start ─────────────────────────────
echo
echo "=== 12. --starting-nonce override pins the start ==="
set +e
OUT7=$("$WALLET" bulk-stake --priv-keyfile $T/staker_single.json \
        --stake-list $T/stakes.json --rpc-port $RPC_PORT \
        --dry-run --starting-nonce 999 2>&1 | tr -d '\r')
RC7=$?
set -e
assert_eq "$RC7" "0" "--starting-nonce override returns exit 0 (dry-run)"
SN7=$(echo "$OUT7" | $PY -c "import sys,json; print(json.load(sys.stdin)['starting_nonce'])")
EN7=$(echo "$OUT7" | $PY -c "import sys,json; print(json.load(sys.stdin)['ending_nonce'])")
R0N7=$(echo "$OUT7" | $PY -c "import sys,json; print(json.load(sys.stdin)['results'][0]['nonce'])")
R2N7=$(echo "$OUT7" | $PY -c "import sys,json; print(json.load(sys.stdin)['results'][2]['nonce'])")
assert_eq "$SN7"  "999"  "starting_nonce = 999 with override"
assert_eq "$EN7"  "1002" "ending_nonce = 999 + 3 = 1002"
assert_eq "$R0N7" "999"  "row 0 nonce = 999 (override)"
assert_eq "$R2N7" "1001" "row 2 nonce = 1001 (override + 2)"

# ── 13. Malformed CSV (missing amount column) returns exit 1 ─────────────────
echo
echo "=== 13. Malformed CSV (missing amount): exit 1 ==="
cat > $T/bad.csv <<EOF
validator-only-no-amount
EOF
set +e
ERR=$("$WALLET" bulk-stake --priv-keyfile $T/staker_single.json \
       --stake-list $T/bad.csv --dry-run 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "malformed CSV returns exit 1"
assert_contains "$ERR" "expected" "diagnostic mentions expected format"

# ── 14. Zero-amount row returns exit 1 (parse-time validation) ───────────────
echo
echo "=== 14. Zero-amount row in stake-list: exit 1 ==="
cat > $T/zero.json <<EOF
{"stakes":[
  {"domain": "good.v", "amount": 5},
  {"domain": "zero.v", "amount": 0}
]}
EOF
set +e
ERR=$("$WALLET" bulk-stake --priv-keyfile $T/staker_single.json \
       --stake-list $T/zero.json --dry-run 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "zero-amount row returns exit 1"
assert_contains "$ERR" "positive" "diagnostic mentions amount must be positive"

# Same in CSV form.
cat > $T/zero.csv <<EOF
good.v,5
zero.v,0
EOF
set +e
ERR=$("$WALLET" bulk-stake --priv-keyfile $T/staker_single.json \
       --stake-list $T/zero.csv --dry-run 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "zero-amount CSV row returns exit 1"

# ── 15. Pre-check signed_tx wire shape independently from test 8 ─────────────
echo
echo "=== 15. signed_tx wire shape: STAKE encoding details ==="
# Test 8 batched the assertion; here we drill into each field with
# its own assertion so a regression in any single field is obvious.
ONE_ROW=$(echo "$OUT3" | $PY -c "
import sys,json
d=json.load(sys.stdin)
import json as j
print(j.dumps(d['results'][0]['signed_tx']))
")
TX_TYPE=$(echo "$ONE_ROW" | $PY -c "import sys,json; print(json.load(sys.stdin)['type'])")
TX_TO=$(echo "$ONE_ROW"   | $PY -c "import sys,json; print(repr(json.load(sys.stdin)['to']))")
TX_AMT=$(echo "$ONE_ROW"  | $PY -c "import sys,json; print(json.load(sys.stdin)['amount'])")
TX_FROM=$(echo "$ONE_ROW" | $PY -c "import sys,json; print(json.load(sys.stdin)['from'])")
TX_PAYL=$(echo "$ONE_ROW" | $PY -c "import sys,json; print(json.load(sys.stdin)['payload'])")
TX_SIGL=$(echo "$ONE_ROW" | $PY -c "import sys,json; print(len(json.load(sys.stdin)['sig']))")
TX_HSHL=$(echo "$ONE_ROW" | $PY -c "import sys,json; print(len(json.load(sys.stdin)['hash']))")
assert_eq "$TX_TYPE" "3"        "signed_tx.type = 3 (STAKE)"
assert_eq "$TX_TO"   "''"       "signed_tx.to = '' (empty per STAKE convention)"
assert_eq "$TX_AMT"  "0"        "signed_tx.amount = 0 (STAKE convention; payload carries amount)"
assert_eq "$TX_FROM" "$ADDR_S"  "signed_tx.from = staker address"
# payload is the 8-byte LE encoding of EX_1 (100 = 0x64). Verify byte 0.
PAYL_BYTE0=$(echo "$TX_PAYL" | cut -c1-2)
assert_eq "$PAYL_BYTE0" "64"    "signed_tx.payload byte 0 = 0x64 (low byte of 100)"
PAYL_LEN=${#TX_PAYL}
assert_eq "$PAYL_LEN" "16"      "signed_tx.payload length = 16 hex chars (8 bytes)"
assert_eq "$TX_SIGL" "128"      "signed_tx.sig length = 128 hex chars (64 bytes Ed25519)"
assert_eq "$TX_HSHL" "64"       "signed_tx.hash length = 64 hex chars (32 bytes SHA-256)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet bulk-stake"
  exit 0
else
  echo "  FAIL"
  exit 1
fi
