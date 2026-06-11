#!/usr/bin/env bash
# determ-wallet anon-batch-balance CLI test.
#
# Exercises the wallet's batch-balance RPC client against a running
# single-node daemon. Verifies:
#
#   1. Help line mentions anon-batch-balance.
#   2. Missing --rpc-port returns exit 1 with a clear diagnostic.
#   3. Bad RPC port (daemon not running there) returns exit 1.
#   4. Bring up a single-node daemon (M=K=1), credit 3 anon addresses
#      with known balances via repeated `send_anon` from a bootstrap
#      account.
#   5. Wallet's anon-batch-balance returns the expected per-address
#      balances + total balance over a comma-separated address list.
#   6. JSON envelope has rpc_port, chain_height, addresses[], summary{}.
#   7. Address-file input (@path) yields the same result as comma-
#      separated input.
#   8. --include-nonce surfaces a `nonce` field per address.
#   9. --include-stake surfaces a `stake` field per address.
#  10. Case-insensitive address input (mixed-case anon hex) normalizes
#      correctly (S-028 parity).
#  11. A never-funded address shows balance=0, exists=false.
#  12. The summary.exists_count and summary.total_balance match the
#      per-address totals.
#
# Run from repo root: bash tools/test_wallet_anon_batch_balance.sh

set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"
T=test_wallet_anon_batch_balance
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

# ── 1. Help text mentions anon-batch-balance ──────────────────────────────────
echo "=== 1. Help text mentions anon-batch-balance ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
assert_contains "$H" "anon-batch-balance" "help mentions anon-batch-balance"

# ── 2. Missing --rpc-port: exit 1 ─────────────────────────────────────────────
echo
echo "=== 2. Missing --rpc-port: exit 1 ==="
set +e
ERR=$("$WALLET" anon-batch-balance --addresses 0xdeadbeef 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "missing --rpc-port returns exit 1"
assert_contains "$ERR" "rpc-port" "diagnostic mentions --rpc-port"

# ── 3. Bad RPC port (no daemon): exit 1 ───────────────────────────────────────
echo
echo "=== 3. Bad RPC port (daemon not running): exit 1 ==="
set +e
ERR=$("$WALLET" anon-batch-balance --rpc-port 1 --addresses 0xdeadbeef 2>&1)
RC=$?
set -e
assert_eq "$RC" "1" "unreachable RPC port returns exit 1"
assert_contains "$ERR" "connect" "diagnostic mentions connection failure"

# ── 4. Bring up a single-node daemon and create three anon accounts ───────────
echo
echo "=== 4. Init single-node daemon + create 3 anon accounts ==="
$DETERM init --data-dir $T/n1 --profile single_test 2>&1 | tail -1 >/dev/null
$DETERM genesis-tool peer-info node1 --data-dir $T/n1 --stake 1000 > $T/p1.json

# Create 3 anon accounts via wallet account-create-batch.
"$WALLET" account-create-batch --count 3 --out $T/anons.json >/dev/null 2>&1
ADDR_A=$($PY -c "import json; print(json.load(open('$T/anons.json'))['accounts'][0]['address'])")
ADDR_B=$($PY -c "import json; print(json.load(open('$T/anons.json'))['accounts'][1]['address'])")
ADDR_C=$($PY -c "import json; print(json.load(open('$T/anons.json'))['accounts'][2]['address'])")
# A FOURTH, never-funded address (different keypair pool) to exercise
# the exists=false branch.
"$WALLET" account-create-batch --count 1 --out $T/orphan.json >/dev/null 2>&1
ADDR_D=$($PY -c "import json; print(json.load(open('$T/orphan.json'))['accounts'][0]['address'])")
echo "  ADDR_A = $ADDR_A"
echo "  ADDR_B = $ADDR_B"
echo "  ADDR_C = $ADDR_C"
echo "  ADDR_D = $ADDR_D (unfunded)"

# Genesis funds ADDR_A with a big bag; ADDR_B / ADDR_C start at zero
# and get funded via send_anon from ADDR_A so we exercise nonce
# advancement too. ADDR_D never receives anything.
GEN_FUND_A=1000000
cat > $T/gen.json <<EOF
{
  "chain_id": "test-anon-batch-balance",
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

RPC_PORT=18831
$PY -c "
import json
with open('$T/n1/config.json') as f: c = json.load(f)
c['domain'] = 'node1'
c['listen_port'] = 17831
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

# Send 1234 to ADDR_B and 5678 to ADDR_C, both from ADDR_A.
PRIV_A=$($PY -c "import json; print(json.load(open('$T/anons.json'))['accounts'][0]['privkey_hex'])")
EXPECTED_B=1234
EXPECTED_C=5678
$DETERM send_anon "$ADDR_B" $EXPECTED_B "$PRIV_A" --rpc-port $RPC_PORT 2>&1 >/dev/null
sleep 0.5
$DETERM send_anon "$ADDR_C" $EXPECTED_C "$PRIV_A" --rpc-port $RPC_PORT 2>&1 >/dev/null

# Wait for ADDR_C's balance to land (the second tx).
for _ in $(seq 1 60); do
  CB=$($DETERM balance "$ADDR_C" --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json
try: print(json.load(sys.stdin).get('balance',0))
except: print(0)")
  [ "$CB" = "$EXPECTED_C" ] && break
  sleep 0.5
done
echo "  ADDR_B balance: $($DETERM balance "$ADDR_B" --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('balance',0))")"
echo "  ADDR_C balance: $($DETERM balance "$ADDR_C" --rpc-port $RPC_PORT 2>/dev/null | $PY -c "import sys,json; print(json.load(sys.stdin).get('balance',0))")"

EXPECTED_A=$(($GEN_FUND_A - $EXPECTED_B - $EXPECTED_C))   # fee=0 default

# ── 5. Comma-separated address list → per-address balances ───────────────────
echo
echo "=== 5. Comma-separated --addresses returns expected balances ==="
OUT=$("$WALLET" anon-batch-balance --rpc-port $RPC_PORT \
        --addresses "$ADDR_A,$ADDR_B,$ADDR_C" 2>&1 | tr -d '\r')
echo "$OUT" | head -c 400 ; echo
RC=$?
assert_eq "$RC" "0" "comma-sep list returns exit 0"

BAL_A=$(echo "$OUT" | $PY -c "import sys,json; d=json.load(sys.stdin); print([a['balance'] for a in d['addresses'] if a['address']=='$ADDR_A'][0])")
BAL_B=$(echo "$OUT" | $PY -c "import sys,json; d=json.load(sys.stdin); print([a['balance'] for a in d['addresses'] if a['address']=='$ADDR_B'][0])")
BAL_C=$(echo "$OUT" | $PY -c "import sys,json; d=json.load(sys.stdin); print([a['balance'] for a in d['addresses'] if a['address']=='$ADDR_C'][0])")
assert_eq "$BAL_A" "$EXPECTED_A" "balance for ADDR_A matches expected"
assert_eq "$BAL_B" "$EXPECTED_B" "balance for ADDR_B matches expected"
assert_eq "$BAL_C" "$EXPECTED_C" "balance for ADDR_C matches expected"

# Summary totals.
TOT_BAL=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['summary']['total_balance'])")
EXP_TOT=$(($EXPECTED_A + $EXPECTED_B + $EXPECTED_C))
assert_eq "$TOT_BAL" "$EXP_TOT" "summary.total_balance = sum of per-address balances"

EXISTS_CNT=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['summary']['exists_count'])")
assert_eq "$EXISTS_CNT" "3" "summary.exists_count = 3 (all funded)"

TOT_ADDRS=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['summary']['total_addresses'])")
assert_eq "$TOT_ADDRS" "3" "summary.total_addresses = 3"

# ── 6. JSON envelope shape ────────────────────────────────────────────────────
echo
echo "=== 6. JSON envelope has expected top-level keys ==="
ENV_OK=$(echo "$OUT" | $PY -c "
import sys, json
d = json.load(sys.stdin)
keys = sorted(d.keys())
need = sorted(['rpc_port', 'chain_height', 'addresses', 'summary'])
print('ok' if keys == need else f'missing: have {keys}, need {need}')
")
assert_eq "$ENV_OK" "ok" "top-level keys are {rpc_port, chain_height, addresses, summary}"

RPC_FIELD=$(echo "$OUT" | $PY -c "import sys,json; print(json.load(sys.stdin)['rpc_port'])")
assert_eq "$RPC_FIELD" "$RPC_PORT" "rpc_port field reflects --rpc-port argument"

# ── 7. @file input ────────────────────────────────────────────────────────────
echo
echo "=== 7. Address file (@<path>) input yields same per-address balances ==="
cat > $T/addrs.txt <<EOF
# A comment line
$ADDR_A
$ADDR_B

$ADDR_C
EOF
OUT_F=$("$WALLET" anon-batch-balance --rpc-port $RPC_PORT \
          --addresses @$T/addrs.txt 2>&1 | tr -d '\r')
BAL_A_F=$(echo "$OUT_F" | $PY -c "import sys,json; d=json.load(sys.stdin); print([a['balance'] for a in d['addresses'] if a['address']=='$ADDR_A'][0])")
BAL_B_F=$(echo "$OUT_F" | $PY -c "import sys,json; d=json.load(sys.stdin); print([a['balance'] for a in d['addresses'] if a['address']=='$ADDR_B'][0])")
BAL_C_F=$(echo "$OUT_F" | $PY -c "import sys,json; d=json.load(sys.stdin); print([a['balance'] for a in d['addresses'] if a['address']=='$ADDR_C'][0])")
assert_eq "$BAL_A_F" "$EXPECTED_A" "@file balance for ADDR_A"
assert_eq "$BAL_B_F" "$EXPECTED_B" "@file balance for ADDR_B"
assert_eq "$BAL_C_F" "$EXPECTED_C" "@file balance for ADDR_C"

ADDR_CNT_F=$(echo "$OUT_F" | $PY -c "import sys,json; print(len(json.load(sys.stdin)['addresses']))")
assert_eq "$ADDR_CNT_F" "3" "@file with 3 entries + 1 comment + 1 blank produces 3 rows"

# ── 8. --include-nonce surfaces nonce ─────────────────────────────────────────
echo
echo "=== 8. --include-nonce surfaces a 'nonce' field per address ==="
OUT_N=$("$WALLET" anon-batch-balance --rpc-port $RPC_PORT \
          --addresses "$ADDR_A,$ADDR_B,$ADDR_C" --include-nonce 2>&1 | tr -d '\r')
NCE_A_OK=$(echo "$OUT_N" | $PY -c "
import sys,json
d = json.load(sys.stdin)
ok = all(('nonce' in row and isinstance(row['nonce'], int)) for row in d['addresses'])
print('ok' if ok else 'missing-nonce')
")
assert_eq "$NCE_A_OK" "ok" "every address row has an int 'nonce' field with --include-nonce"

# ADDR_A sent 2 txs (one to ADDR_B, one to ADDR_C). Its next_nonce
# should be at least 2.
NCE_A=$(echo "$OUT_N" | $PY -c "import sys,json; d=json.load(sys.stdin); print([a['nonce'] for a in d['addresses'] if a['address']=='$ADDR_A'][0])")
if [ "$NCE_A" -ge "2" ]; then
  assert_eq "ok" "ok" "ADDR_A next_nonce >= 2 (advanced by 2 send_anon txs; got $NCE_A)"
else
  assert_eq "ok" "fail" "ADDR_A next_nonce >= 2 (got $NCE_A)"
fi

# ── 9. --include-stake surfaces stake ─────────────────────────────────────────
echo
echo "=== 9. --include-stake surfaces a 'stake' field per address ==="
OUT_S=$("$WALLET" anon-batch-balance --rpc-port $RPC_PORT \
          --addresses "$ADDR_A,$ADDR_B,$ADDR_C" --include-stake 2>&1 | tr -d '\r')
STK_ALL_OK=$(echo "$OUT_S" | $PY -c "
import sys,json
d = json.load(sys.stdin)
ok = all(('stake' in row and isinstance(row['stake'], int)) for row in d['addresses'])
print('ok' if ok else 'missing-stake')
")
assert_eq "$STK_ALL_OK" "ok" "every address row has an int 'stake' field with --include-stake"
# Anon addresses never stake; expect 0 for all three.
STK_TOT=$(echo "$OUT_S" | $PY -c "import sys,json; print(json.load(sys.stdin)['summary']['total_stake'])")
assert_eq "$STK_TOT" "0" "summary.total_stake = 0 (anon addresses can't stake)"

# ── 10. Case-insensitive address input ────────────────────────────────────────
echo
echo "=== 10. Mixed-case address input normalizes to canonical lowercase ==="
ADDR_A_UPPER=$(echo "$ADDR_A" | $PY -c "import sys; s=sys.stdin.read().strip(); print('0x' + s[2:].upper())")
OUT_CASE=$("$WALLET" anon-batch-balance --rpc-port $RPC_PORT \
             --addresses "$ADDR_A_UPPER" 2>&1 | tr -d '\r')
NORM_ADDR=$(echo "$OUT_CASE" | $PY -c "import sys,json; print(json.load(sys.stdin)['addresses'][0]['address'])")
assert_eq "$NORM_ADDR" "$ADDR_A" "uppercase input '0xABC...' normalized to lowercase '0xabc...'"
NORM_BAL=$(echo "$OUT_CASE" | $PY -c "import sys,json; print(json.load(sys.stdin)['addresses'][0]['balance'])")
assert_eq "$NORM_BAL" "$EXPECTED_A" "normalized-case balance lookup returns the funded amount"

# ── 11. Never-funded address: exists=false, balance=0 ────────────────────────
echo
echo "=== 11. Unfunded address (ADDR_D) shows exists=false, balance=0 ==="
OUT_D=$("$WALLET" anon-batch-balance --rpc-port $RPC_PORT \
          --addresses "$ADDR_D" 2>&1 | tr -d '\r')
BAL_D=$(echo "$OUT_D" | $PY -c "import sys,json; print(json.load(sys.stdin)['addresses'][0]['balance'])")
EX_D=$(echo "$OUT_D" | $PY -c "import sys,json; print(json.load(sys.stdin)['addresses'][0]['exists'])")
EXISTS_CNT_D=$(echo "$OUT_D" | $PY -c "import sys,json; print(json.load(sys.stdin)['summary']['exists_count'])")
assert_eq "$BAL_D" "0" "ADDR_D balance is 0 (never funded)"
assert_eq "$EX_D" "False" "ADDR_D exists=false"
assert_eq "$EXISTS_CNT_D" "0" "summary.exists_count = 0 when only ADDR_D queried"

# ── 12. Mixed (funded + unfunded) batch: summary aggregates correctly ────────
echo
echo "=== 12. Mixed batch (funded + unfunded) aggregates correctly ==="
OUT_M=$("$WALLET" anon-batch-balance --rpc-port $RPC_PORT \
          --addresses "$ADDR_A,$ADDR_D,$ADDR_B" 2>&1 | tr -d '\r')
EX_CNT_M=$(echo "$OUT_M" | $PY -c "import sys,json; print(json.load(sys.stdin)['summary']['exists_count'])")
TOT_M=$(echo "$OUT_M" | $PY -c "import sys,json; print(json.load(sys.stdin)['summary']['total_balance'])")
TADDRS_M=$(echo "$OUT_M" | $PY -c "import sys,json; print(json.load(sys.stdin)['summary']['total_addresses'])")
assert_eq "$EX_CNT_M" "2" "exists_count = 2 (A + B funded; D not)"
assert_eq "$TOT_M" "$(($EXPECTED_A + $EXPECTED_B))" "total_balance = ADDR_A + ADDR_B (ADDR_D = 0)"
assert_eq "$TADDRS_M" "3" "total_addresses = 3 even with one unfunded"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: determ-wallet anon-batch-balance"
  exit 0
else
  echo "  FAIL: test_wallet_anon_batch_balance"
  exit 1
fi
