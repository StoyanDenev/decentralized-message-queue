#!/usr/bin/env bash
# determ-wallet bulk-send CLI test.
#
# Exercises batch TRANSFER submission from a single keyfile to many
# recipients via the daemon's RPC. Verifies:
#
#   1. Help text mentions bulk-send.
#   2. Missing --priv-keyfile / --batch-file returns exit 1 with a clear
#      diagnostic.
#   3. Missing --rpc-port (without --dry-run) returns exit 1.
#   4. Bring up a single-node daemon, fund a sender ADDR_A with a large
#      genesis balance, create 3 recipient anon-addresses.
#   5. JSON batch (3 rows) submission: all 3 succeed; per-row nonce
#      sequencing is starting_nonce + row_index; ending_nonce delta ==
#      batch_size; recipient balances post-submission match expected.
#   6. CSV batch (3 rows, no header) yields the same per-row results.
#   7. CSV with a `to,amount,fee` header line is parsed correctly.
#   8. --dry-run skips submission, each row carries `signed_tx`, sender
#      balance is unchanged.
#   9. --continue-on-error with one bad row (insufficient balance via a
#      ludicrously-large amount) keeps the run going; the good rows still
#      submit; exit 2 (at least one row failed); aborted=false.
#  10. Default abort-on-first-error halts at the first failing row; later
#      rows are NOT submitted; aborted=true; exit 2.
#  11. JSON envelope shape: top-level keys are
#      {keyfile, batch_size, submitted, failed, starting_nonce,
#       ending_nonce, dry_run, aborted, results}.
#  12. --starting-nonce override pins the sequencing start.
#
# Run from repo root: bash tools/test_wallet_bulk_send.sh

set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"
T=test_wallet_bulk_send
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

# ── 1. Help text mentions bulk-send ──────────────────────────────────────────
echo "=== 1. Help text mentions bulk-send ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "bulk-send" "help mentions bulk-send"

# ── 2. Missing --priv-keyfile / --batch-file: exit 1 ─────────────────────────
echo
echo "=== 2. Missing required args: exit 1 ==="
set +e
ERR=$("$WALLET" bulk-send --rpc-port 18841 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "missing --priv-keyfile/--batch-file returns exit 1"
assert_contains "$ERR" "priv-keyfile" "diagnostic mentions --priv-keyfile"

# ── 3. Missing --rpc-port without --dry-run: exit 1 ──────────────────────────
echo
echo "=== 3. Missing --rpc-port (no --dry-run): exit 1 ==="
echo '[]' > $T/empty.json
"$WALLET" account-create-batch --count 1 --out $T/sender.json >/dev/null 2>&1
$PY -c "
import json
with open('$T/sender.json') as f: d=json.load(f)
acc = d['accounts'][0]
out = {'address': acc['address'], 'privkey_hex': acc['privkey_hex']}
with open('$T/sender_single.json','w') as f: json.dump(out, f)
"
set +e
ERR=$("$WALLET" bulk-send --priv-keyfile $T/sender_single.json \
       --batch-file $T/empty.json 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "missing --rpc-port returns exit 1"
assert_contains "$ERR" "rpc-port" "diagnostic mentions --rpc-port"

# ── 4. Bring up single-node daemon + create 3 recipients ─────────────────────
echo
echo "=== 4. Init single-node daemon + create sender + 3 recipients ==="
$DETERM init --data-dir $T/n1 --profile single_test 2>&1 | tail -1 >/dev/null
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json

"$WALLET" account-create-batch --count 3 --out $T/recipients.json >/dev/null 2>&1
ADDR_X=$($PY -c "import json; print(json.load(open('$T/recipients.json'))['accounts'][0]['address'])")
ADDR_Y=$($PY -c "import json; print(json.load(open('$T/recipients.json'))['accounts'][1]['address'])")
ADDR_Z=$($PY -c "import json; print(json.load(open('$T/recipients.json'))['accounts'][2]['address'])")
ADDR_A=$($PY -c "import json; print(json.load(open('$T/sender_single.json'))['address'])")
echo "  Sender   ADDR_A = $ADDR_A"
echo "  Recipient ADDR_X = $ADDR_X"
echo "  Recipient ADDR_Y = $ADDR_Y"
echo "  Recipient ADDR_Z = $ADDR_Z"

GEN_FUND_A=1000000
cat > $T/gen.json <<EOF
{
  "chain_id": "test-bulk-send",
  "m_creators": 1,
  "k_block_sigs": 1,
  "block_subsidy": 10,
  "initial_balances": [
    {"domain": "$ADDR_A", "balance": $GEN_FUND_A}
  ],
  "initial_creators": [
$(cat $T/p1.json | tr -d '\n')
  ]
}
EOF
$DETERM genesis-tool build $T/gen.json | tail -1 >/dev/null
GHASH=$(cat $T/gen.json.hash)

RPC_PORT=18841
$PY -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain'] = 'node1'
c['listen_port'] = 17841
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

# ── 5. JSON batch (3 rows): all submit, nonce sequencing correct ─────────────
echo
echo "=== 5. JSON batch (3 rows): all submit, nonce sequencing correct ==="
EX_X=100
EX_Y=200
EX_Z=300
cat > $T/batch.json <<EOF
[
  {"to": "$ADDR_X", "amount": $EX_X},
  {"to": "$ADDR_Y", "amount": $EX_Y},
  {"to": "$ADDR_Z", "amount": $EX_Z}
]
EOF

OUT=$("$WALLET" bulk-send --priv-keyfile $T/sender_single.json \
       --batch-file $T/batch.json --rpc-port $RPC_PORT 2>&1 | tr -d '\r')
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

# Each row reports status=ok and has a 64-hex tx_hash.
ALL_OK=$(echo "$OUT" | $PY -c "
import sys,json
d=json.load(sys.stdin)
ok = all(row['status']=='ok' and len(row['tx_hash'])==64 for row in d['results'])
print('ok' if ok else 'fail')
")
assert_eq "$ALL_OK" "ok" "every row has status=ok and 64-hex tx_hash"

# Wait for the txs to land + verify recipient balances via anon-batch-balance.
sleep 3
BAL_OUT=$("$WALLET" anon-batch-balance --rpc-port $RPC_PORT \
           --addresses "$ADDR_X,$ADDR_Y,$ADDR_Z" 2>&1 | tr -d '\r')
BAL_X=$(echo "$BAL_OUT" | $PY -c "import sys,json; d=json.load(sys.stdin); print([a['balance'] for a in d['addresses'] if a['address']=='$ADDR_X'][0])")
BAL_Y=$(echo "$BAL_OUT" | $PY -c "import sys,json; d=json.load(sys.stdin); print([a['balance'] for a in d['addresses'] if a['address']=='$ADDR_Y'][0])")
BAL_Z=$(echo "$BAL_OUT" | $PY -c "import sys,json; d=json.load(sys.stdin); print([a['balance'] for a in d['addresses'] if a['address']=='$ADDR_Z'][0])")
assert_eq "$BAL_X" "$EX_X" "ADDR_X balance == $EX_X after bulk-send"
assert_eq "$BAL_Y" "$EX_Y" "ADDR_Y balance == $EX_Y after bulk-send"
assert_eq "$BAL_Z" "$EX_Z" "ADDR_Z balance == $EX_Z after bulk-send"

# ── 6. CSV batch (no header) yields same per-row results ─────────────────────
echo
echo "=== 6. CSV batch (no header): all submit ==="
EX_X2=11
EX_Y2=22
EX_Z2=33
cat > $T/batch.csv <<EOF
$ADDR_X,$EX_X2
$ADDR_Y,$EX_Y2
$ADDR_Z,$EX_Z2
EOF

OUT2=$("$WALLET" bulk-send --priv-keyfile $T/sender_single.json \
        --batch-file $T/batch.csv --rpc-port $RPC_PORT 2>&1 | tr -d '\r')
RC2=$?
assert_eq "$RC2" "0" "CSV batch returns exit 0"
SUB2=$(echo "$OUT2" | $PY -c "import sys,json; print(json.load(sys.stdin)['submitted'])")
assert_eq "$SUB2" "3" "CSV batch: submitted = 3"

# Confirm starting_nonce advanced (sender has already done one batch).
SN2=$(echo "$OUT2" | $PY -c "import sys,json; print(json.load(sys.stdin)['starting_nonce'])")
if [ "$SN2" -ge "3" ]; then
  assert_eq "ok" "ok" "second batch starting_nonce >= 3 (was $SN2; previous batch advanced ADDR_A nonce)"
else
  assert_eq "ok" "fail" "second batch starting_nonce >= 3 (got $SN2)"
fi
sleep 3
BAL_OUT2=$("$WALLET" anon-batch-balance --rpc-port $RPC_PORT \
            --addresses "$ADDR_X,$ADDR_Y,$ADDR_Z" 2>&1 | tr -d '\r')
BAL_X2=$(echo "$BAL_OUT2" | $PY -c "import sys,json; d=json.load(sys.stdin); print([a['balance'] for a in d['addresses'] if a['address']=='$ADDR_X'][0])")
assert_eq "$BAL_X2" "$((EX_X + EX_X2))" "ADDR_X balance == $((EX_X + EX_X2)) after two batches"

# ── 7. CSV with `to,amount,fee` header is parsed (header skipped) ────────────
echo
echo "=== 7. CSV with header line: skipped ==="
cat > $T/batch_hdr.csv <<EOF
to,amount,fee
$ADDR_X,1,0
EOF
OUT3=$("$WALLET" bulk-send --priv-keyfile $T/sender_single.json \
        --batch-file $T/batch_hdr.csv --rpc-port $RPC_PORT 2>&1 | tr -d '\r')
RC3=$?
assert_eq "$RC3" "0" "CSV-with-header returns exit 0"
BSIZE3=$(echo "$OUT3" | $PY -c "import sys,json; print(json.load(sys.stdin)['batch_size'])")
assert_eq "$BSIZE3" "1" "CSV header line skipped: batch_size = 1"

# ── 8. --dry-run: no submission, each row carries signed_tx ─────────────────
echo
echo "=== 8. --dry-run: no submission, each row has signed_tx ==="
sleep 1
PRE_BAL_A=$("$WALLET" anon-batch-balance --rpc-port $RPC_PORT \
             --addresses "$ADDR_A" 2>&1 | tr -d '\r' | \
            $PY -c "import sys,json; print(json.load(sys.stdin)['addresses'][0]['balance'])")
OUT4=$("$WALLET" bulk-send --priv-keyfile $T/sender_single.json \
        --batch-file $T/batch.json --rpc-port $RPC_PORT --dry-run 2>&1 | tr -d '\r')
RC4=$?
assert_eq "$RC4" "0" "--dry-run returns exit 0"
DRY=$(echo "$OUT4" | $PY -c "import sys,json; print(json.load(sys.stdin)['dry_run'])")
assert_eq "$DRY" "True" "dry_run = true in envelope"
ALL_SIGNED=$(echo "$OUT4" | $PY -c "
import sys,json
d=json.load(sys.stdin)
ok = all(('signed_tx' in row) and isinstance(row['signed_tx'], dict) and
         row['signed_tx'].get('type')==0 and len(row['signed_tx'].get('sig',''))==128 and
         len(row['signed_tx'].get('hash',''))==64 for row in d['results'])
print('ok' if ok else 'fail')
")
assert_eq "$ALL_SIGNED" "ok" "every dry-run row has a valid signed_tx (type=0, 128-hex sig, 64-hex hash)"

sleep 2
POST_BAL_A=$("$WALLET" anon-batch-balance --rpc-port $RPC_PORT \
              --addresses "$ADDR_A" 2>&1 | tr -d '\r' | \
             $PY -c "import sys,json; print(json.load(sys.stdin)['addresses'][0]['balance'])")
assert_eq "$POST_BAL_A" "$PRE_BAL_A" "sender balance unchanged after --dry-run"

# ── 9. --continue-on-error: one bad row, others continue, exit 2 ─────────────
echo
echo "=== 9. --continue-on-error with one bad row ==="
# Force a real submit-time failure: an uppercase-hex anon recipient. S-028
# requires anon addresses in canonical lowercase form; submit_tx rejects
# the non-canonical shape loud-and-clear ("submitted tx.to is non-canonical
# (uppercase hex)..."). Mempool admission doesn't check the spend budget
# at submit time, so an "amount > balance" row is admitted at submit and
# only fails at apply — uppercase is the cleanest synchronous reject.
ADDR_Y_UPPER=$(echo "$ADDR_Y" | $PY -c "import sys; s=sys.stdin.read().strip(); print('0x' + s[2:].upper())")
cat > $T/batch_mixed.json <<EOF
[
  {"to": "$ADDR_X", "amount": 5},
  {"to": "$ADDR_Y_UPPER", "amount": 7},
  {"to": "$ADDR_Z", "amount": 9}
]
EOF
set +e
# Capture exit code BEFORE the pipeline (bash $? is the last pipe stage).
"$WALLET" bulk-send --priv-keyfile $T/sender_single.json \
        --batch-file $T/batch_mixed.json --rpc-port $RPC_PORT \
        --continue-on-error > $T/out5.raw 2>&1
RC5=$?
OUT5=$(tr -d '\r' < $T/out5.raw)
set -e
assert_eq "$RC5" "2" "--continue-on-error with failure returns exit 2"

FAIL5=$(echo "$OUT5" | $PY -c "import sys,json; print(json.load(sys.stdin)['failed'])")
SUB5=$(echo "$OUT5" | $PY -c "import sys,json; print(json.load(sys.stdin)['submitted'])")
ABT5=$(echo "$OUT5" | $PY -c "import sys,json; print(json.load(sys.stdin)['aborted'])")
assert_eq "$FAIL5" "1" "--continue-on-error: failed = 1"
assert_eq "$SUB5"  "2" "--continue-on-error: submitted = 2 (the two good rows)"
assert_eq "$ABT5"  "False" "--continue-on-error: aborted = false"

# The middle row carries status=error + a reason; bracket rows OK.
S0_5=$(echo "$OUT5" | $PY -c "import sys,json; print(json.load(sys.stdin)['results'][0]['status'])")
S1_5=$(echo "$OUT5" | $PY -c "import sys,json; print(json.load(sys.stdin)['results'][1]['status'])")
S2_5=$(echo "$OUT5" | $PY -c "import sys,json; print(json.load(sys.stdin)['results'][2]['status'])")
assert_eq "$S0_5" "ok"    "--continue-on-error: row 0 status=ok"
assert_eq "$S1_5" "error" "--continue-on-error: row 1 status=error"
assert_eq "$S2_5" "ok"    "--continue-on-error: row 2 status=ok"
HAS_REASON=$(echo "$OUT5" | $PY -c "
import sys,json
d=json.load(sys.stdin)
print('ok' if 'reason' in d['results'][1] and d['results'][1]['reason'] else 'fail')
")
assert_eq "$HAS_REASON" "ok" "--continue-on-error: failed row carries non-empty 'reason'"

# ── 10. Default abort-on-first-error: halt at first failing row ─────────────
echo
echo "=== 10. Default abort-on-first-error: halt at first failing row ==="
# Sleep so test 9's submitted txs land on-chain and the sender's next_nonce
# advances; otherwise this run would hit "incumbent tx at (from, nonce)"
# on row 0 (same nonce as test 9 row 0 — fee was equal so the chain rejects
# the replay).
sleep 3
set +e
"$WALLET" bulk-send --priv-keyfile $T/sender_single.json \
        --batch-file $T/batch_mixed.json --rpc-port $RPC_PORT > $T/out6.raw 2>&1
RC6=$?
OUT6=$(tr -d '\r' < $T/out6.raw)
set -e
assert_eq "$RC6" "2" "default-abort returns exit 2"
ABT6=$(echo "$OUT6" | $PY -c "import sys,json; print(json.load(sys.stdin)['aborted'])")
FAIL6=$(echo "$OUT6" | $PY -c "import sys,json; print(json.load(sys.stdin)['failed'])")
# Results array length should reflect early halt: includes the failing row
# but NOT the subsequent row(s). Row 0 succeeds, row 1 fails ⇒ halt ⇒
# results has 2 entries.
RCNT6=$(echo "$OUT6" | $PY -c "import sys,json; print(len(json.load(sys.stdin)['results']))")
assert_eq "$ABT6"  "True" "default-abort: aborted = true"
assert_eq "$FAIL6" "1"    "default-abort: failed = 1"
assert_eq "$RCNT6" "2"    "default-abort: results array length = 2 (row 0 ok + row 1 failed); row 2 not attempted"

# ── 11. JSON envelope shape ──────────────────────────────────────────────────
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

# ── 12. --starting-nonce override ────────────────────────────────────────────
echo
echo "=== 12. --starting-nonce override pins the start ==="
OUT7=$("$WALLET" bulk-send --priv-keyfile $T/sender_single.json \
        --batch-file $T/batch.json --rpc-port $RPC_PORT \
        --dry-run --starting-nonce 999 2>&1 | tr -d '\r')
RC7=$?
assert_eq "$RC7" "0" "--starting-nonce override returns exit 0 (dry-run)"
SN7=$(echo "$OUT7" | $PY -c "import sys,json; print(json.load(sys.stdin)['starting_nonce'])")
EN7=$(echo "$OUT7" | $PY -c "import sys,json; print(json.load(sys.stdin)['ending_nonce'])")
R0N7=$(echo "$OUT7" | $PY -c "import sys,json; print(json.load(sys.stdin)['results'][0]['nonce'])")
R2N7=$(echo "$OUT7" | $PY -c "import sys,json; print(json.load(sys.stdin)['results'][2]['nonce'])")
assert_eq "$SN7"  "999"  "starting_nonce = 999 with override"
assert_eq "$EN7"  "1002" "ending_nonce = 999 + 3 = 1002"
assert_eq "$R0N7" "999"  "row 0 nonce = 999 (override)"
assert_eq "$R2N7" "1001" "row 2 nonce = 1001 (override + 2)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet bulk-send"
  exit 0
else
  echo "  FAIL"
  exit 1
fi
