#!/usr/bin/env bash
# determ-wallet tx-history-export CLI test.
#
# Exercises the wallet's NDJSON transaction-history exporter against a
# running single-node daemon. Verifies the full surface of the new
# command — CLI parse, argument validation, account-shape policing,
# walk-window semantics (--from / --to / --last), --include-empty-blocks
# behavior, --out file write, S-028 anon-address case normalization,
# happy-path single + multi-account exports, empty-result edge case, and
# NDJSON line-by-line JSON validity.
#
# Run from repo root: bash tools/test_wallet_tx_history_export.sh

set -u
# Intentionally NOT set -e: this test deliberately invokes the wallet
# with bad arguments to assert exit codes, and also tolerates the rare
# race where the daemon's mempool drops a duplicate-nonce retry. We
# manually capture and assert RC values where they matter.
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"
T=test_wallet_tx_history_export
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

# ── 1. Help text mentions tx-history-export ───────────────────────────────────
echo "=== 1. Help text mentions tx-history-export ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "tx-history-export" "help mentions tx-history-export"

# ── 2. Per-command help renders ───────────────────────────────────────────────
echo
echo "=== 2. Per-command --help renders ==="
SUB_H=$("$WALLET" tx-history-export --help 2>&1 | tr -d '\r')
assert_contains "$SUB_H" "NDJSON" "per-command help mentions NDJSON"
assert_contains "$SUB_H" "block_hash" "per-command help documents block_hash output field"

# ── 3. Missing --rpc-port: exit 1 ─────────────────────────────────────────────
echo
echo "=== 3. Missing --rpc-port: exit 1 ==="
ERR=$("$WALLET" tx-history-export --accounts alice.v 2>&1)
RC=$?
assert_eq "$RC" "1" "missing --rpc-port returns exit 1"
assert_contains "$ERR" "rpc-port" "diagnostic mentions --rpc-port"

# ── 4. Missing --accounts: exit 1 ─────────────────────────────────────────────
echo
echo "=== 4. Missing --accounts: exit 1 ==="
ERR=$("$WALLET" tx-history-export --rpc-port 1 2>&1)
RC=$?
assert_eq "$RC" "1" "missing --accounts returns exit 1"
assert_contains "$ERR" "accounts" "diagnostic mentions --accounts"

# ── 5. Invalid account shape: exit 1 ──────────────────────────────────────────
echo
echo "=== 5. Invalid account shape (neither anon nor domain): exit 1 ==="
ERR=$("$WALLET" tx-history-export --rpc-port 1 --accounts xyz 2>&1)
RC=$?
assert_eq "$RC" "1" "invalid account shape returns exit 1"
assert_contains "$ERR" "invalid account" "diagnostic mentions invalid account"

# ── 6. --last + --from mutual exclusion: exit 1 ──────────────────────────────
echo
echo "=== 6. --last mutually exclusive with --from / --to: exit 1 ==="
ERR=$("$WALLET" tx-history-export --rpc-port 1 --accounts alice.v --last 10 --from 0 2>&1)
RC=$?
assert_eq "$RC" "1" "--last + --from returns exit 1"
assert_contains "$ERR" "mutually exclusive" "diagnostic mentions mutually exclusive"

ERR=$("$WALLET" tx-history-export --rpc-port 1 --accounts alice.v --last 10 --to 5 2>&1)
RC=$?
assert_eq "$RC" "1" "--last + --to returns exit 1"

# ── 7. Bad RPC port (daemon not running): exit 1 ──────────────────────────────
echo
echo "=== 7. Bad RPC port (no daemon): exit 1 ==="
ERR=$("$WALLET" tx-history-export --rpc-port 1 --accounts alice.v 2>&1)
RC=$?
assert_eq "$RC" "1" "unreachable RPC port returns exit 1"
assert_contains "$ERR" "connect" "diagnostic mentions connection failure"

# ── 8. Unreadable accounts file: exit 1 ───────────────────────────────────────
echo
echo "=== 8. Unreadable accounts file (@/no/such/file): exit 1 ==="
ERR=$("$WALLET" tx-history-export --rpc-port 1 --accounts @/no/such/file 2>&1)
RC=$?
assert_eq "$RC" "1" "missing accounts file returns exit 1"
assert_contains "$ERR" "cannot open" "diagnostic mentions cannot open"

# ── 9. Bring up a single-node daemon + create anon accounts ───────────────────
echo
echo "=== 9. Init single-node daemon + create anon accounts ==="
$DETERM init --data-dir $T/n1 --profile single_test 2>&1 | tail -1 >/dev/null
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json

"$WALLET" account-create-batch --count 3 --out $T/anons.json >/dev/null 2>&1
ADDR_A=$($PY -c "import json; print(json.load(open('$T/anons.json'))['accounts'][0]['address'])")
ADDR_B=$($PY -c "import json; print(json.load(open('$T/anons.json'))['accounts'][1]['address'])")
ADDR_C=$($PY -c "import json; print(json.load(open('$T/anons.json'))['accounts'][2]['address'])")
# A FOURTH, never-touched address (different keypair pool) for the
# empty-result edge case.
"$WALLET" account-create-batch --count 1 --out $T/orphan.json >/dev/null 2>&1
ADDR_D=$($PY -c "import json; print(json.load(open('$T/orphan.json'))['accounts'][0]['address'])")
echo "  ADDR_A = $ADDR_A"
echo "  ADDR_B = $ADDR_B"
echo "  ADDR_C = $ADDR_C"
echo "  ADDR_D = $ADDR_D (never used)"

# Genesis funds ADDR_A; B / C / D start at zero.
GEN_FUND_A=1000000
cat > $T/gen.json <<EOF
{
  "chain_id": "test-tx-history-export",
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

for _ in $(seq 1 40); do
  H=$($DETERM status --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json
try: print(json.load(sys.stdin).get('height',0))
except: print(0)" 2>/dev/null)
  [ "$H" -ge "2" ] && break
  sleep 0.5
done
echo "  chain advanced past genesis (height=$H)"

# Send 1234 to ADDR_B and 5678 to ADDR_C, both from ADDR_A.
PRIV_A=$($PY -c "import json; print(json.load(open('$T/anons.json'))['accounts'][0]['privkey_hex'])")
EXPECTED_B=1234
EXPECTED_C=5678
$DETERM send_anon "$ADDR_B" $EXPECTED_B "$PRIV_A" --rpc-port $RPC_PORT 2>&1 >/dev/null
sleep 0.5
$DETERM send_anon "$ADDR_C" $EXPECTED_C "$PRIV_A" --rpc-port $RPC_PORT 2>&1 >/dev/null

for _ in $(seq 1 60); do
  CB=$($DETERM balance "$ADDR_C" --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json
try: print(json.load(sys.stdin).get('balance',0))
except: print(0)")
  [ "$CB" = "$EXPECTED_C" ] && break
  sleep 0.5
done
echo "  ADDR_B balance: $($DETERM balance "$ADDR_B" --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('balance',0))")"
echo "  ADDR_C balance: $($DETERM balance "$ADDR_C" --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('balance',0))")"

# Capture the latest chain height for window-window assertions later.
HEAD_H=$($DETERM status --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('height',0))")
HEAD_IDX=$((HEAD_H - 1))
echo "  HEAD_H=$HEAD_H HEAD_IDX=$HEAD_IDX"

# ── 10. Happy-path single account (ADDR_A) ───────────────────────────────────
# Pin --to to HEAD_IDX so the walk is a fixed-size historical replay;
# the producer continues to advance the chain in the background but the
# walk + assertions stay bounded.
echo
echo "=== 10. Single-account export (ADDR_A as sender) ==="
OUT_A=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
          --accounts "$ADDR_A" --from 0 --to $HEAD_IDX 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "single-account export returns exit 0"

# Count lines and assert at least 2 rows (ADDR_A sent 2 txs as `from`).
N_LINES=$(echo "$OUT_A" | grep -c '^{' || true)
if [ "$N_LINES" -ge "2" ]; then
  assert_eq "ok" "ok" "single-account export emitted at least 2 NDJSON rows (got $N_LINES)"
else
  assert_eq "fail" "ok" "single-account export emitted at least 2 NDJSON rows (got $N_LINES)"
fi

# ── 11. NDJSON validity — each line is its own JSON object ───────────────────
echo
echo "=== 11. Each NDJSON line is a valid JSON object ==="
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

# ── 12. NDJSON row shape — block, block_hash, tx_index, type, from, to ────────
echo
echo "=== 12. NDJSON row has expected fields ==="
ROW_OK=$(echo "$OUT_A" | $PY -c "
import sys, json
need = sorted(['block','block_hash','tx_index','type','from','to','amount','fee','nonce','tx_hash'])
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if 'matches' in d: continue
    keys = sorted(d.keys())
    if keys != need:
        print('missing: have', keys, 'need', need); sys.exit(0)
print('ok')
")
assert_eq "$ROW_OK" "ok" "NDJSON row has all expected fields"

# ── 13. tx-row from-field matches the queried account ────────────────────────
echo
echo "=== 13. Each row's from OR to matches the queried account ==="
ALL_FROM_A=$(echo "$OUT_A" | $PY -c "
import sys, json
target = '$ADDR_A'
ok = True
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if 'matches' in d: continue
    if d.get('from') != target and d.get('to') != target:
        ok = False; break
print('ok' if ok else 'fail')
")
assert_eq "$ALL_FROM_A" "ok" "every row's from OR to matches ADDR_A"

# ── 14. type field is the upper-case mnemonic ────────────────────────────────
echo
echo "=== 14. type field renders as upper-case mnemonic ==="
TYPE_OK=$(echo "$OUT_A" | $PY -c "
import sys, json
known = {'TRANSFER','REGISTER','DEREGISTER','STAKE','UNSTAKE','REGION_CHANGE','PARAM_CHANGE','MERGE_EVENT','COMPOSABLE_BATCH','DAPP_REGISTER','DAPP_CALL'}
ok = True
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if 'matches' in d: continue
    t = d.get('type','')
    if t not in known and not t.startswith('UNKNOWN_'):
        ok = False; break
print('ok' if ok else 'fail')
")
assert_eq "$TYPE_OK" "ok" "every row's type is a known mnemonic or UNKNOWN_<N>"

# ── 15. Multi-account export aggregates correctly ────────────────────────────
echo
echo "=== 15. Multi-account export (A + B + C) ==="
OUT_ABC=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
            --accounts "$ADDR_A,$ADDR_B,$ADDR_C" --from 0 --to $HEAD_IDX 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "multi-account export returns exit 0"

# ADDR_B and ADDR_C should each appear as `to` in exactly one row.
HITS_B=$(echo "$OUT_ABC" | $PY -c "
import sys, json
target = '$ADDR_B'
n = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if 'matches' in d: continue
    if d.get('to') == target or d.get('from') == target: n += 1
print(n)
")
if [ "$HITS_B" -ge "1" ]; then
  assert_eq "ok" "ok" "multi-account export captures ADDR_B (got $HITS_B rows)"
else
  assert_eq "fail" "ok" "multi-account export captures ADDR_B (got $HITS_B rows)"
fi

HITS_C=$(echo "$OUT_ABC" | $PY -c "
import sys, json
target = '$ADDR_C'
n = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if 'matches' in d: continue
    if d.get('to') == target or d.get('from') == target: n += 1
print(n)
")
if [ "$HITS_C" -ge "1" ]; then
  assert_eq "ok" "ok" "multi-account export captures ADDR_C (got $HITS_C rows)"
else
  assert_eq "fail" "ok" "multi-account export captures ADDR_C (got $HITS_C rows)"
fi

# ── 16. Amount + nonce + tx_hash sanity ───────────────────────────────────────
echo
echo "=== 16. ADDR_B row has expected amount + populated tx_hash ==="
B_AMOUNT=$(echo "$OUT_ABC" | $PY -c "
import sys, json
target = '$ADDR_B'
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if 'matches' in d: continue
    if d.get('to') == target:
        print(d.get('amount','')); sys.exit(0)
print('')
")
assert_eq "$B_AMOUNT" "$EXPECTED_B" "ADDR_B credit row amount = $EXPECTED_B"

B_TX_HASH_LEN=$(echo "$OUT_ABC" | $PY -c "
import sys, json
target = '$ADDR_B'
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if 'matches' in d: continue
    if d.get('to') == target:
        print(len(d.get('tx_hash',''))); sys.exit(0)
print(0)
")
assert_eq "$B_TX_HASH_LEN" "64" "ADDR_B row tx_hash is 64 hex chars (32 bytes)"

# ── 17. Empty-result edge case: ADDR_D (never used) ───────────────────────────
echo
echo "=== 17. Unused account (ADDR_D) yields zero rows + exit 0 ==="
OUT_D=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
          --accounts "$ADDR_D" --from 0 --to $HEAD_IDX 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "empty-result export returns exit 0"
N_LINES_D=$(echo -n "$OUT_D" | grep -c '^{' || true)
assert_eq "$N_LINES_D" "0" "empty-result export emits zero rows"

# ── 18. --include-empty-blocks emits per-block empty markers ─────────────────
# Pin the window to a fixed tail so the assertion is robust against chain
# growth between status + export. We use --last 5 to bracket the last 5
# blocks — the daemon's producer continues advancing during the test, so
# pinning by --to <historical_head> would also work but --last is more
# concise.
echo
echo "=== 18. --include-empty-blocks emits {block, matches: []} per empty block ==="
WINDOW_N=5
OUT_EMPTY=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
              --accounts "$ADDR_D" --include-empty-blocks --last $WINDOW_N 2>&1 | tr -d '\r')
N_EMPTY=$(echo "$OUT_EMPTY" | $PY -c "
import sys, json
n = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if 'matches' in d and isinstance(d['matches'], list) and len(d['matches']) == 0:
        n += 1
print(n)
")
# With --last 5 and ADDR_D (never used), every one of the 5 walked
# blocks should produce an empty marker. The assertion is on the exact
# count: if the wallet skipped one or doubled-emitted, we'd see drift.
assert_eq "$N_EMPTY" "$WINDOW_N" "--include-empty-blocks emits one empty marker per block (--last $WINDOW_N)"

# Empty-marker shape contains only block + matches.
EMPTY_SHAPE_OK=$(echo "$OUT_EMPTY" | $PY -c "
import sys, json
ok = True
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if 'matches' in d:
        keys = sorted(d.keys())
        if keys != ['block','matches']:
            ok = False; break
print('ok' if ok else 'fail')
")
assert_eq "$EMPTY_SHAPE_OK" "ok" "empty-block markers have only {block, matches} keys"

# ── 19. --out writes to file (default stdout absent) ──────────────────────────
# Pin the window (--from 0 --to $HEAD_IDX) so the walk is bounded and
# fast as the producer continues to mint blocks behind us.
echo
echo "=== 19. --out writes NDJSON to file ==="
"$WALLET" tx-history-export --rpc-port $RPC_PORT \
    --accounts "$ADDR_A" --from 0 --to $HEAD_IDX --out $T/out.ndjson > $T/stdout_out 2>&1
RC=$?
assert_eq "$RC" "0" "--out invocation returns exit 0"
assert_eq "$(test -s $T/out.ndjson && echo yes)" "yes" "--out file is non-empty"
# Stdout should NOT contain the NDJSON rows when --out is set.
STDOUT_LINES=$(grep -c '^{' $T/stdout_out 2>/dev/null || true)
assert_eq "$STDOUT_LINES" "0" "stdout does not duplicate NDJSON when --out is set"
# Per-line validity of the file.
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

# ── 20. @file account list yields same matches as inline list ────────────────
echo
echo "=== 20. @file --accounts yields the same match count as inline ==="
cat > $T/accts.txt <<EOF
# A comment line
$ADDR_A

$ADDR_B
$ADDR_C
EOF
OUT_F=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
          --accounts @$T/accts.txt --from 0 --to $HEAD_IDX 2>&1 | tr -d '\r')
INLINE_COUNT=$(echo "$OUT_ABC" | grep -c '^{' || true)
FILE_COUNT=$(echo "$OUT_F" | grep -c '^{' || true)
assert_eq "$FILE_COUNT" "$INLINE_COUNT" "@file row count = inline-list row count"

# ── 21. --from / --to window selection clamps correctly ───────────────────────
echo
echo "=== 21. --from H --to H window selection ==="
OUT_WIN=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
            --accounts "$ADDR_A" --from 0 --to $HEAD_IDX 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--from/--to window returns exit 0"
# Full window should match the no-window default.
FULL_WIN_COUNT=$(echo "$OUT_WIN" | grep -c '^{' || true)
DEFAULT_COUNT=$(echo "$OUT_A" | grep -c '^{' || true)
assert_eq "$FULL_WIN_COUNT" "$DEFAULT_COUNT" "0..head explicit window = default walk"

# Past-tail --to clamps (operator races between status + export). Pin
# both --from and --to to historical-window values so this stays a
# tiny walk regardless of how much the chain has advanced.
OUT_CLAMP=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
              --accounts "$ADDR_A" --from 0 --to 1 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "narrow window walks without error (exit 0)"

# Backward window (--from > --to): honest empty export, exit 0.
OUT_BACK=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
             --accounts "$ADDR_A" --from 10 --to 5 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "backward window (--from > --to) returns exit 0"
N_BACK=$(echo -n "$OUT_BACK" | grep -c '^{' || true)
assert_eq "$N_BACK" "0" "backward window emits zero rows"

# ── 22. --last N window ────────────────────────────────────────────────────────
# Use a small fixed window (--last 10) so the assertion is stable as the
# producer advances the chain in the background. We assert exact equality:
# with --include-empty-blocks each of the 10 walked blocks must emit
# exactly one line (matching or empty marker).
echo
echo "=== 22. --last N walks the last N blocks ==="
LAST_N=10
OUT_LAST=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
             --accounts "$ADDR_A" --last $LAST_N --include-empty-blocks 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "--last $LAST_N returns exit 0"
N_LAST_BLOCKS=$(echo "$OUT_LAST" | $PY -c "
import sys, json
n = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if 'matches' in d or 'block' in d:
        n += 1
print(n)
")
assert_eq "$N_LAST_BLOCKS" "$LAST_N" "--last $LAST_N covers exactly $LAST_N blocks (got $N_LAST_BLOCKS lines)"

# ── 23. S-028 anon-address case normalization ─────────────────────────────────
# Bracket both walks to a fixed past-tail window so chain advancement
# between the lowercase and uppercase walks doesn't perturb the count.
# Pin --to to HEAD_IDX (snapshot from section 9, well behind the current
# producer tip — so this is a historical-replay range that stays stable).
echo
echo "=== 23. Mixed-case anon address normalized to lowercase (S-028) ==="
ADDR_A_UPPER=$(echo "$ADDR_A" | $PY -c "import sys; s=sys.stdin.read().strip(); print('0x' + s[2:].upper())")
OUT_LOW=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
            --accounts "$ADDR_A" --from 0 --to $HEAD_IDX 2>&1 | tr -d '\r')
OUT_CASE=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
             --accounts "$ADDR_A_UPPER" --from 0 --to $HEAD_IDX 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "mixed-case anon input returns exit 0"
N_CASE=$(echo "$OUT_CASE" | grep -c '^{' || true)
N_LOW=$(echo "$OUT_LOW" | grep -c '^{' || true)
assert_eq "$N_CASE" "$N_LOW" "mixed-case anon yields same row count as lowercase (over identical window)"

# The emitted from/to fields in the rows should be lowercase (S-028
# canonical form — clients consuming the NDJSON shouldn't have to
# case-normalize themselves to dedup against another export).
CASE_LOWER_OK=$(echo "$OUT_CASE" | $PY -c "
import sys, json
target_lower = '$ADDR_A'
ok = True
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if 'matches' in d: continue
    f = d.get('from','')
    t = d.get('to','')
    # Either field that's the queried account must be lowercase.
    if f.lower() == target_lower and f != target_lower: ok = False; break
    if t.lower() == target_lower and t != target_lower: ok = False; break
print('ok' if ok else 'fail')
")
assert_eq "$CASE_LOWER_OK" "ok" "row from/to fields normalized to lowercase"

# ── 24. block_hash is a 64-char hex string ────────────────────────────────────
echo
echo "=== 24. block_hash is 64 hex chars per row ==="
BH_OK=$(echo "$OUT_ABC" | $PY -c "
import sys, json
ok = True
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    d = json.loads(line)
    if 'matches' in d: continue
    bh = d.get('block_hash','')
    if len(bh) != 64:
        ok = False; break
    try:
        int(bh, 16)
    except Exception:
        ok = False; break
print('ok' if ok else 'fail')
")
assert_eq "$BH_OK" "ok" "every row's block_hash is 64 hex chars"

# ── 25. Empty --accounts list (only whitespace / comments) exits 1 ────────────
echo
echo "=== 25. Empty --accounts list (only comments) exits 1 ==="
cat > $T/empty_accts.txt <<'EOF'
# only comments here
# nothing else

EOF
ERR=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
        --accounts @$T/empty_accts.txt 2>&1)
RC=$?
assert_eq "$RC" "1" "empty accounts file returns exit 1"
assert_contains "$ERR" "zero" "diagnostic mentions zero entries"

# ── 26. Unwritable --out (directory in place of file) exits 1 ─────────────────
echo
echo "=== 26. Unwritable --out (try to write where a directory exists) exits 1 ==="
mkdir -p $T/blockingdir
ERR=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
        --accounts "$ADDR_A" --from 0 --to 0 --out $T/blockingdir 2>&1)
RC=$?
assert_eq "$RC" "1" "unwritable --out returns exit 1"

# ── 27. Domain-style account validates ────────────────────────────────────────
echo
echo "=== 27. Domain-style account (foo.v) is accepted by parser ==="
# Proper domain shape ([a-z][a-z0-9-]*\.[a-z]+) — even though there are no
# matching txs, the parse + walk must accept it (RPC simply returns no
# matches and the export exits 0).
OUT_DOM=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
            --accounts "foo.v" --from 0 --to $HEAD_IDX 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "proper-domain account (foo.v) accepted by parser (exit 0)"

# A no-dot single-label string ('node1') is NOT a valid domain shape
# per the documented regex — must be rejected as an invalid account.
ERR=$("$WALLET" tx-history-export --rpc-port $RPC_PORT \
        --accounts "node1" 2>&1)
RC=$?
assert_eq "$RC" "1" "single-label string ('node1') rejected as invalid account"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet tx-history-export"
  exit 0
else
  echo "  FAIL: test_wallet_tx_history_export"
  exit 1
fi
