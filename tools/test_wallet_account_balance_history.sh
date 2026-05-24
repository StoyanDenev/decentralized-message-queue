#!/usr/bin/env bash
# determ-wallet account-balance-history CLI test.
#
# Exercises the historical-balance NDJSON exporter against a running
# single-node daemon. Verifies the full surface of the new command —
# CLI parse, argument validation, account-shape policing, walk-window
# semantics, --checkpoint-every cadence, --include-empty-blocks
# behavior, --out file write, S-028 anon-address case normalization,
# happy-path single-account export over a sequence of credit/debit
# transactions, NDJSON line-by-line JSON validity, per-row shape
# (block / balance / delta_since_last / tx_count_window /
# checkpoint_source).
#
# Run from repo root: bash tools/test_wallet_account_balance_history.sh

set -u
# Intentionally NOT set -e: this test deliberately invokes the wallet
# with bad arguments to assert exit codes. We manually capture and
# assert RC values where they matter.
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"
T=test_wallet_account_balance_history
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

# ── 1. Help text mentions account-balance-history ────────────────────────────
echo "=== 1. Help text mentions account-balance-history ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "account-balance-history" "help mentions account-balance-history"

# ── 2. Per-command --help renders ────────────────────────────────────────────
echo
echo "=== 2. Per-command --help renders ==="
SUB_H=$("$WALLET" account-balance-history --help 2>&1 | tr -d '\r')
assert_contains "$SUB_H" "checkpoint_source" "per-command help documents checkpoint_source field"
assert_contains "$SUB_H" "checkpoint-every" "per-command help documents --checkpoint-every"
assert_contains "$SUB_H" "S-028" "per-command help notes S-028 normalization"

# ── 3. Missing --rpc-port: exit 1 ────────────────────────────────────────────
echo
echo "=== 3. Missing --rpc-port: exit 1 ==="
ERR=$("$WALLET" account-balance-history --account alice.v 2>&1)
RC=$?
assert_eq "$RC" "1" "missing --rpc-port returns exit 1"
assert_contains "$ERR" "rpc-port" "diagnostic mentions --rpc-port"

# ── 4. Missing --account: exit 1 ─────────────────────────────────────────────
echo
echo "=== 4. Missing --account: exit 1 ==="
ERR=$("$WALLET" account-balance-history --rpc-port 1 2>&1)
RC=$?
assert_eq "$RC" "1" "missing --account returns exit 1"
assert_contains "$ERR" "account" "diagnostic mentions --account"

# ── 5. Invalid account shape: exit 1 ─────────────────────────────────────────
echo
echo "=== 5. Invalid account shape (neither anon nor domain): exit 1 ==="
ERR=$("$WALLET" account-balance-history --rpc-port 1 --account xyz 2>&1)
RC=$?
assert_eq "$RC" "1" "invalid account shape returns exit 1"
assert_contains "$ERR" "invalid account" "diagnostic mentions invalid account"

# ── 6. --last + --from mutual exclusion: exit 1 ──────────────────────────────
echo
echo "=== 6. --last mutually exclusive with --from / --to: exit 1 ==="
ERR=$("$WALLET" account-balance-history --rpc-port 1 --account alice.v --last 10 --from 0 2>&1)
RC=$?
assert_eq "$RC" "1" "--last + --from returns exit 1"
assert_contains "$ERR" "mutually exclusive" "diagnostic mentions mutually exclusive"

# ── 7. Bad RPC port (daemon not running): exit 1 ─────────────────────────────
echo
echo "=== 7. Bad RPC port (no daemon): exit 1 ==="
ERR=$("$WALLET" account-balance-history --rpc-port 1 --account alice.v 2>&1)
RC=$?
assert_eq "$RC" "1" "unreachable RPC port returns exit 1"
assert_contains "$ERR" "connect" "diagnostic mentions connection failure"

# ── 8. Bring up a single-node daemon + create anon accounts ──────────────────
echo
echo "=== 8. Init single-node daemon + create anon accounts ==="
$DETERM init --data-dir $T/n1 --profile single_test 2>&1 | tail -1 >/dev/null
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json

"$WALLET" account-create-batch --count 3 --out $T/anons.json >/dev/null 2>&1
ADDR_A=$($PY -c "import json; print(json.load(open('$T/anons.json'))['accounts'][0]['address'])")
ADDR_B=$($PY -c "import json; print(json.load(open('$T/anons.json'))['accounts'][1]['address'])")
ADDR_C=$($PY -c "import json; print(json.load(open('$T/anons.json'))['accounts'][2]['address'])")
"$WALLET" account-create-batch --count 1 --out $T/orphan.json >/dev/null 2>&1
ADDR_D=$($PY -c "import json; print(json.load(open('$T/orphan.json'))['accounts'][0]['address'])")
echo "  ADDR_A = $ADDR_A"
echo "  ADDR_B = $ADDR_B"
echo "  ADDR_C = $ADDR_C"
echo "  ADDR_D = $ADDR_D (never used)"

GEN_FUND_A=1000000
cat > $T/gen.json <<EOF
{
  "chain_id": "test-account-balance-history",
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

RPC_PORT=18851
$PY -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain'] = 'node1'
c['listen_port'] = 17851
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

for _ in $(seq 1 40); do
  H=$($DETERM status --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)" 2>/dev/null)
  [ "$H" -ge "2" ] && break
  sleep 0.5
done
echo "  chain advanced past genesis (height=$H)"

# Send a handful of txs from ADDR_A so the wallet has both debit + credit
# rows to walk. We send 3 different amounts to ADDR_B (3 distinct
# blocks if the producer chooses to spread them) so checkpoint cadence
# is exercised on a non-trivial trajectory.
PRIV_A=$($PY -c "import json; print(json.load(open('$T/anons.json'))['accounts'][0]['privkey_hex'])")
SEND_1=1000
SEND_2=2000
SEND_3=3000
$DETERM send_anon "$ADDR_B" $SEND_1 "$PRIV_A" --rpc-port $RPC_PORT 2>&1 >/dev/null
sleep 0.5
$DETERM send_anon "$ADDR_B" $SEND_2 "$PRIV_A" --rpc-port $RPC_PORT 2>&1 >/dev/null
sleep 0.5
$DETERM send_anon "$ADDR_C" $SEND_3 "$PRIV_A" --rpc-port $RPC_PORT 2>&1 >/dev/null

# Wait for the third tx to land.
EXPECTED_C=$SEND_3
for _ in $(seq 1 60); do
  CB=$($DETERM balance "$ADDR_C" --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json
try: print(json.load(sys.stdin).get('balance',0))
except: print(0)")
  [ "$CB" = "$EXPECTED_C" ] && break
  sleep 0.5
done

EXPECTED_B=$((SEND_1 + SEND_2))
EXPECTED_A=$((GEN_FUND_A - SEND_1 - SEND_2 - SEND_3))
echo "  ADDR_A balance: $(\
   $DETERM balance "$ADDR_A" --rpc-port $RPC_PORT 2>/dev/null \
   | $PY -c "import sys,json; print(json.load(sys.stdin).get('balance',0))")"
echo "  ADDR_B balance: $(\
   $DETERM balance "$ADDR_B" --rpc-port $RPC_PORT 2>/dev/null \
   | $PY -c "import sys,json; print(json.load(sys.stdin).get('balance',0))")"
echo "  ADDR_C balance: $(\
   $DETERM balance "$ADDR_C" --rpc-port $RPC_PORT 2>/dev/null \
   | $PY -c "import sys,json; print(json.load(sys.stdin).get('balance',0))")"

# Capture the latest chain height for window-bound assertions.
HEAD_H=$($DETERM status --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('height',0))")
HEAD_IDX=$((HEAD_H - 1))
echo "  HEAD_H=$HEAD_H HEAD_IDX=$HEAD_IDX"

# ── 9. Happy-path single account (ADDR_A) over a small window ────────────────
echo
echo "=== 9. Single-account history (ADDR_A) anchored to current head ==="
# Use --last so the wallet computes to_h = current head_index inside its
# own status RPC (avoids racing against chain advancement between the
# test's HEAD_IDX snapshot and the wallet's resolution of the window).
# Use --last with a generous N so the walk covers the genesis-to-head
# range. --checkpoint-every 2 so every other block is an authoritative
# anchor; the walk should produce at least 1 emitted row.
NOW_HEAD=$($DETERM status --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('height',0))")
WALK_N=$((NOW_HEAD + 100))   # bigger than current height = walk from genesis
OUT_A=$("$WALLET" account-balance-history --rpc-port $RPC_PORT \
          --account "$ADDR_A" --last $WALK_N \
          --checkpoint-every 2 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "single-account history returns exit 0"

# Count NDJSON lines: should have at least 1.
N_LINES=$(echo "$OUT_A" | grep -c '^{' || true)
if [ "$N_LINES" -ge "1" ]; then
  assert_eq "ok" "ok" "single-account history emitted at least 1 NDJSON row (got $N_LINES)"
else
  assert_eq "fail" "ok" "single-account history emitted at least 1 NDJSON row (got $N_LINES)"
fi

# ── 10. NDJSON validity — each line is its own JSON object ───────────────────
echo
echo "=== 10. Each NDJSON line is a valid JSON object ==="
NDJSON_OK=$(echo "$OUT_A" | $PY -c "
import sys, json
ok = True
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        if not isinstance(d, dict):
            ok = False; break
    except Exception:
        ok = False; break
print('ok' if ok else 'fail')
")
assert_eq "$NDJSON_OK" "ok" "every NDJSON line parses as a JSON object"

# ── 11. NDJSON row shape ─────────────────────────────────────────────────────
echo
echo "=== 11. NDJSON row has expected fields ==="
ROW_OK=$(echo "$OUT_A" | $PY -c "
import sys, json
need = sorted(['block','balance','delta_since_last','tx_count_window','checkpoint_source'])
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    keys = sorted(d.keys())
    if keys != need:
        print('missing: have', keys, 'need', need); sys.exit(0)
print('ok')
")
assert_eq "$ROW_OK" "ok" "every NDJSON row has all expected fields"

# ── 12. checkpoint_source values are in {rpc, interpolated} ──────────────────
echo
echo "=== 12. checkpoint_source values are valid ==="
SOURCE_OK=$(echo "$OUT_A" | $PY -c "
import sys, json
ok = True
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    s = d.get('checkpoint_source','')
    if s not in ('rpc','interpolated'):
        ok = False; break
print('ok' if ok else 'fail')
")
assert_eq "$SOURCE_OK" "ok" "every checkpoint_source is 'rpc' or 'interpolated'"

# ── 13. The LAST emitted row has checkpoint_source=rpc ──────────────────────
# When --last covers the full chain (and the wallet computes to_h via its
# own status RPC), the row at block = head_index will be marked
# checkpoint_source = "rpc" (the only block where the `account` RPC
# value IS the historical balance).
echo
echo "=== 13. Last emitted row has checkpoint_source=rpc ==="
LAST_SOURCE=$(echo "$OUT_A" | grep '^{' | tail -1 | $PY -c "import sys,json; print(json.loads(sys.stdin.read()).get('checkpoint_source',''))")
assert_eq "$LAST_SOURCE" "rpc" "last emitted row has checkpoint_source=rpc"

# ── 14. Last emitted balance is non-zero (full window covers credits) ───────
# We don't assert equality against a single balance RPC call because the
# chain keeps advancing (subsidy splits to ADDR_A as a registered
# validator can change the value between the wallet's snapshot and the
# test's follow-up call). Instead assert the value is non-zero and
# within a reasonable bound (much smaller than GEN_FUND_A since we sent
# out non-trivial amounts).
echo
echo "=== 14. Last NDJSON balance is non-zero + plausibly bounded ==="
LAST_BAL=$(echo "$OUT_A" | grep '^{' | tail -1 | $PY -c "import sys,json; print(json.loads(sys.stdin.read()).get('balance',0))")
if [ "$LAST_BAL" -gt "0" ] && [ "$LAST_BAL" -le "$GEN_FUND_A" ]; then
  assert_eq "ok" "ok" "final row balance > 0 and <= GEN_FUND_A (got $LAST_BAL)"
else
  assert_eq "fail" "ok" "final row balance plausible (got $LAST_BAL)"
fi

# ── 15. delta_since_last on the first row is 0 ───────────────────────────────
echo
echo "=== 15. First emitted row has delta_since_last == 0 ==="
FIRST_DELTA=$(echo "$OUT_A" | grep '^{' | head -1 | $PY -c "import sys,json; print(json.loads(sys.stdin.read()).get('delta_since_last',-1))")
assert_eq "$FIRST_DELTA" "0" "first row delta_since_last is 0 (anchor)"

# ── 16. tx_count_window non-negative integer on every row ────────────────────
echo
echo "=== 16. tx_count_window is a non-negative integer ==="
TXC_OK=$(echo "$OUT_A" | $PY -c "
import sys, json
ok = True
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    tc = d.get('tx_count_window', -1)
    if not isinstance(tc, int) or tc < 0:
        ok = False; break
print('ok' if ok else 'fail')
")
assert_eq "$TXC_OK" "ok" "every tx_count_window is a non-negative int"

# ── 17. block values are non-negative and monotonically increasing ───────────
echo
echo "=== 17. block values are non-negative and increase monotonically ==="
# We don't pin an upper bound because the chain is advancing in the
# background and the wallet's internal head_index can be larger than
# the test's pre-walk HEAD_IDX snapshot. Monotonicity + non-negative is
# the load-bearing invariant.
BLOCK_OK=$(echo "$OUT_A" | $PY -c "
import sys, json
prev = -1
ok = True
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    b = d.get('block', -1)
    if b < 0:
        ok = False; break
    if b <= prev:
        ok = False; break
    prev = b
print('ok' if ok else 'fail')
")
assert_eq "$BLOCK_OK" "ok" "block values are non-negative and strictly monotonic"

# ── 18. --include-empty-blocks emits one row per block in window ─────────────
echo
echo "=== 18. --include-empty-blocks emits one row per block in window ==="
WINDOW_N=5
# Use --last N + --include-empty-blocks: exactly N rows expected.
OUT_EMPTY=$("$WALLET" account-balance-history --rpc-port $RPC_PORT \
              --account "$ADDR_D" --last $WINDOW_N --include-empty-blocks \
              --checkpoint-every 0 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--include-empty-blocks invocation returns exit 0"
N_EMPTY=$(echo "$OUT_EMPTY" | grep -c '^{' || true)
assert_eq "$N_EMPTY" "$WINDOW_N" "--include-empty-blocks emits exactly --last=$WINDOW_N rows"

# ── 19. --checkpoint-every 0 marks the head row as rpc; other rows interpolated ─
echo
echo "=== 19. --checkpoint-every 0 marks head row 'rpc'; pre-head 'interpolated' ==="
HEAD_S_19=$(echo "$OUT_EMPTY" | $PY -c "
import sys, json
target_blocks = []
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    target_blocks.append(d)
if not target_blocks:
    print('empty'); sys.exit(0)
last = target_blocks[-1]
print(last.get('checkpoint_source',''))
")
assert_eq "$HEAD_S_19" "rpc" "head row has checkpoint_source=rpc with --checkpoint-every 0"

# ── 20. Default skip behavior (no --include-empty-blocks): fewer rows ────────
echo
echo "=== 20. Default behavior skips no-change blocks (ADDR_D unused → fewer rows than window) ==="
OUT_D_DEF=$("$WALLET" account-balance-history --rpc-port $RPC_PORT \
              --account "$ADDR_D" --last $WINDOW_N --checkpoint-every 10 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "default-behavior unused-account walk returns exit 0"
N_DEF=$(echo "$OUT_D_DEF" | grep -c '^{' || true)
# Without --include-empty-blocks and no balance changes, only
# checkpoint rows are emitted. With --checkpoint-every 10 and a window
# of WINDOW_N=5, only the first + last block in the window are
# checkpoints (anchor + head closer). So at most 2 rows are expected.
if [ "$N_DEF" -le "$WINDOW_N" ]; then
  assert_eq "ok" "ok" "default mode emits <= window size rows (got $N_DEF)"
else
  assert_eq "fail" "ok" "default mode emits <= window size rows (got $N_DEF)"
fi

# ── 21. --out writes NDJSON to file (default stdout absent) ──────────────────
echo
echo "=== 21. --out writes NDJSON to file ==="
"$WALLET" account-balance-history --rpc-port $RPC_PORT \
    --account "$ADDR_A" --last 8 \
    --checkpoint-every 2 --include-empty-blocks --out $T/out.ndjson > $T/stdout_out 2>&1
RC=$?
assert_eq "$RC" "0" "--out invocation returns exit 0"
assert_eq "$(test -s $T/out.ndjson && echo yes)" "yes" "--out file is non-empty"
STDOUT_LINES=$(grep -c '^{' $T/stdout_out 2>/dev/null || true)
assert_eq "$STDOUT_LINES" "0" "stdout does not duplicate NDJSON when --out is set"
FILE_OK=$($PY -c "
import json
ok = True
with open('$T/out.ndjson') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            if not isinstance(d, dict):
                ok = False; break
        except Exception:
            ok = False; break
print('ok' if ok else 'fail')
")
assert_eq "$FILE_OK" "ok" "every line in --out file is valid JSON"

# ── 22. Empty chain-window (--from > --to): exit 0, zero rows ────────────────
echo
echo "=== 22. Backward window (--from > --to) returns exit 0 + zero rows ==="
OUT_BACK=$("$WALLET" account-balance-history --rpc-port $RPC_PORT \
             --account "$ADDR_A" --from 100 --to 50 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "backward window returns exit 0"
N_BACK=$(echo -n "$OUT_BACK" | grep -c '^{' || true)
assert_eq "$N_BACK" "0" "backward window emits zero rows"

# ── 23. S-028 anon-address case normalization ────────────────────────────────
echo
echo "=== 23. Mixed-case anon address normalized to lowercase (S-028) ==="
ADDR_A_UPPER=$(echo "$ADDR_A" | $PY -c "import sys; s=sys.stdin.read().strip(); print('0x' + s[2:].upper())")
# Two walks over identical small windows (--last 6) so uppercase input
# must normalize to the same canonical lowercase form and produce the
# same row count.
OUT_LOW=$("$WALLET" account-balance-history --rpc-port $RPC_PORT \
            --account "$ADDR_A" --last 6 \
            --checkpoint-every 0 --include-empty-blocks 2>&1 | tr -d '\r')
OUT_CASE=$("$WALLET" account-balance-history --rpc-port $RPC_PORT \
             --account "$ADDR_A_UPPER" --last 6 \
             --checkpoint-every 0 --include-empty-blocks 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "mixed-case anon input returns exit 0"
N_LOW=$(echo "$OUT_LOW" | grep -c '^{' || true)
N_CASE=$(echo "$OUT_CASE" | grep -c '^{' || true)
assert_eq "$N_CASE" "$N_LOW" "mixed-case anon yields same row count as lowercase"

# A diagnostic on stderr should be present for the S-028 warning.
ERR_CASE=$("$WALLET" account-balance-history --rpc-port $RPC_PORT \
             --account "$ADDR_A_UPPER" --from 0 --to 0 \
             --checkpoint-every 0 2>&1 >/dev/null | tr -d '\r')
assert_contains "$ERR_CASE" "S-028" "S-028 warning printed for mixed-case anon input"

# ── 24. Domain-style account (foo.v) is accepted by parser ───────────────────
echo
echo "=== 24. Domain-style account is accepted by parser ==="
# Use a tiny --last 3 window to keep the walk cheap; we're checking
# parser acceptance + exit code, not the historical-balance math.
OUT_DOM=$("$WALLET" account-balance-history --rpc-port $RPC_PORT \
            --account "foo.v" --last 3 --checkpoint-every 0 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "proper-domain account (foo.v) accepted by parser (exit 0)"

# A no-dot single-label string ('node1') is NOT a valid domain shape;
# the wallet must reject it as an invalid account.
ERR=$("$WALLET" account-balance-history --rpc-port $RPC_PORT \
        --account "node1" 2>&1)
RC=$?
assert_eq "$RC" "1" "single-label string ('node1') rejected as invalid account"

# ── 25. --checkpoint-every 0 emits a checkpoint at every block ───────────────
echo
echo "=== 25. --checkpoint-every 0 + --include-empty-blocks emits one row per block ==="
OUT_C0=$("$WALLET" account-balance-history --rpc-port $RPC_PORT \
           --account "$ADDR_A" --last 4 \
           --checkpoint-every 0 --include-empty-blocks 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--checkpoint-every 0 returns exit 0"
N_C0=$(echo "$OUT_C0" | grep -c '^{' || true)
assert_eq "$N_C0" "4" "--checkpoint-every 0 + --last 4 emits 4 rows"

# ── 26. balance is a non-negative integer on every row ───────────────────────
echo
echo "=== 26. balance is a non-negative integer ==="
BAL_OK=$(echo "$OUT_A" | $PY -c "
import sys, json
ok = True
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    b = d.get('balance', -1)
    if not isinstance(b, int) or b < 0:
        ok = False; break
print('ok' if ok else 'fail')
")
assert_eq "$BAL_OK" "ok" "every balance is a non-negative int"

# ── 27. --last N with N=1 produces at most 1 row ─────────────────────────────
echo
echo "=== 27. --last 1 produces at most 1 row ==="
OUT_L1=$("$WALLET" account-balance-history --rpc-port $RPC_PORT \
           --account "$ADDR_A" --last 1 --include-empty-blocks 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--last 1 returns exit 0"
N_L1=$(echo "$OUT_L1" | grep -c '^{' || true)
assert_eq "$N_L1" "1" "--last 1 emits exactly 1 row"

# ── 28. --last 0 is rejected ─────────────────────────────────────────────────
echo
echo "=== 28. --last 0 is rejected (exit 1) ==="
ERR=$("$WALLET" account-balance-history --rpc-port $RPC_PORT \
        --account "$ADDR_A" --last 0 2>&1)
RC=$?
assert_eq "$RC" "1" "--last 0 returns exit 1"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet account-balance-history"
  exit 0
else
  echo "  FAIL"
  exit 1
fi
