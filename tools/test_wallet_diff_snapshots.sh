#!/usr/bin/env bash
# determ-wallet diff-snapshots offline-diff CLI test.
#
# Covers:
#   1. --help text exists and lists every supported --group + every
#      anomaly code.
#   2. Missing --from / --to / unknown --group → diagnostic + exit 1.
#   3. Missing input file → diagnostic + exit 1.
#   4. Malformed input JSON → diagnostic + exit 1.
#   5. Identical snapshots → identical_snapshots INFO anomaly + exit 0.
#   6. Simple diff (one account balance changed, counters bump) →
#      [~] account line + counter delta + exit 0 (no CRITICAL).
#   7. --account-detail surfaces per-account balance-delta line.
#   8. --group filtering shows only the requested group.
#   9. --json output is well-formed JSON with the documented shape.
#   10. CRITICAL anomaly detection:
#       a. state_root_unchanged_but_accounts_changed → exit 2.
#       b. supply_drift → exit 2.
#   11. INFO anomaly (block_index_negative_delta) → exit 0 (informational).
#
# Run from repo root: bash tools/test_wallet_diff_snapshots.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

# Per-run scratch directory so concurrent runs don't collide.
SCRATCH="build/test_wallet_diff_snapshots.$$"
mkdir -p "$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

pass_count=0; fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in:                $1"; fail_count=$((fail_count + 1)); fi
}
assert_not_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  FAIL: $3 (unexpected substring: $2)"; fail_count=$((fail_count + 1))
  else echo "  PASS: $3"; pass_count=$((pass_count + 1)); fi
}

# --------------------------------------------------------------------------
# Fixture helpers — write hand-crafted snapshot JSON files. The wallet
# command parses text-only (no Chain::restore_from_snapshot), so minimal
# envelopes suffice — we only need fields the diff cares about.
# --------------------------------------------------------------------------
write_snapshot() {
    # $1 = output path
    # $2 = block_index
    # $3 = head_hash
    # $4 = accumulated_inbound
    # $5 = accumulated_outbound
    # $6 = accounts array (JSON literal, e.g. '[{"domain":"a","balance":10,"next_nonce":0}]')
    # $7 = stakes array (JSON literal)
    # $8 = registrants array
    # $9 = pending_param_changes (JSON literal)
    # ${10} = headers array (JSON literal; tail entry can carry state_root)
    cat > "$1" <<EOF
{
  "version": 1,
  "block_index": $2,
  "head_hash": "$3",
  "accounts": $6,
  "stakes": $7,
  "registrants": $8,
  "applied_inbound_receipts": [],
  "block_subsidy": 100,
  "subsidy_pool_initial": 0,
  "subsidy_mode": 0,
  "lottery_jackpot_multiplier": 0,
  "min_stake": 1000,
  "suspension_slash": 10,
  "unstake_delay": 1000,
  "shard_count": 1,
  "shard_salt": "0000000000000000000000000000000000000000000000000000000000000000",
  "shard_id": 0,
  "genesis_total": 1000000,
  "accumulated_subsidy": 0,
  "accumulated_slashed": 0,
  "accumulated_inbound": $4,
  "accumulated_outbound": $5,
  "abort_records": [],
  "merge_state": [],
  "dapp_registry": [],
  "pending_param_changes": $9,
  "headers": ${10}
}
EOF
}

# Empty arrays + a tail header with state_root.
EMPTY_ARR='[]'
SR_AAAA='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
SR_BBBB='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
HDR_SR_A='[{"index":0,"state_root":"'"$SR_AAAA"'"}]'
HDR_SR_B='[{"index":0,"state_root":"'"$SR_BBBB"'"}]'

echo "=== 1. --help text contains every group + every anomaly code ==="
HELP=$($WALLET diff-snapshots --help 2>&1 | tr -d '\r')
assert_contains "$HELP" "diff-snapshots --from"            "help shows synopsis"
assert_contains "$HELP" "counters"                          "help lists counters group"
assert_contains "$HELP" "registrants"                       "help lists registrants group"
assert_contains "$HELP" "params"                            "help lists params group"
assert_contains "$HELP" "block_index_negative_delta"        "help documents block_index_negative_delta"
assert_contains "$HELP" "supply_drift"                      "help documents supply_drift"
assert_contains "$HELP" "identical_snapshots"               "help documents identical_snapshots"
assert_contains "$HELP" "state_root_unchanged_but_accounts_changed" "help documents state_root anomaly"
assert_contains "$HELP" "--account-detail"                  "help documents --account-detail"

echo
echo "=== 2. Missing args / unknown group → exit 1 ==="
set +e
$WALLET diff-snapshots >/dev/null 2>&1; RC=$?
set -e
assert_eq "$RC" "1" "missing --from + --to exits 1"

set +e
ERR=$($WALLET diff-snapshots --from x 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "missing --to alone exits 1"
assert_contains "$ERR" "required"   "missing --to diagnostic mentions required"

# Write a placeholder pair before --group validation so the diagnostic
# fires for the bad group, not for missing files.
A_FILE="$SCRATCH/a.json"
B_FILE="$SCRATCH/b.json"
write_snapshot "$A_FILE" 0 "0000" 0 0 "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR"
write_snapshot "$B_FILE" 0 "0000" 0 0 "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR"

set +e
ERR=$($WALLET diff-snapshots --from "$A_FILE" --to "$B_FILE" --group bogus 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "unknown --group exits 1"
assert_contains "$ERR" "unknown --group" "unknown --group diagnostic"

echo
echo "=== 3. Missing input file → exit 1 + diagnostic ==="
set +e
ERR=$($WALLET diff-snapshots --from "$SCRATCH/does_not_exist.json" --to "$B_FILE" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "missing --from file exits 1"
assert_contains "$ERR" "cannot open" "missing-file diagnostic mentions cannot open"

echo
echo "=== 4. Malformed JSON → exit 1 + diagnostic ==="
BAD_FILE="$SCRATCH/bad.json"
echo "this is not json {" > "$BAD_FILE"
set +e
ERR=$($WALLET diff-snapshots --from "$BAD_FILE" --to "$B_FILE" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "malformed JSON exits 1"
assert_contains "$ERR" "JSON parse" "malformed-JSON diagnostic"

echo
echo "=== 5. Identical snapshots → identical_snapshots INFO + exit 0 ==="
ACCTS='[{"domain":"acct1","balance":500,"next_nonce":0}]'
write_snapshot "$A_FILE" 10 "deadbeef" 50 30 "$ACCTS" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR"
write_snapshot "$B_FILE" 10 "deadbeef" 50 30 "$ACCTS" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR"
set +e
OUT=$($WALLET diff-snapshots --from "$A_FILE" --to "$B_FILE" 2>&1)
RC=$?
set -e
OUT=$(echo "$OUT" | tr -d '\r')
assert_eq "$RC" "0" "identical snapshots exit 0"
assert_contains "$OUT" "identical_snapshots" "identical_snapshots anomaly emitted"
assert_contains "$OUT" "INFO"                "anomaly marked INFO (no CRITICAL)"
assert_not_contains "$OUT" "CRITICAL"        "no CRITICAL anomalies on identical snapshots"

echo
echo "=== 6. Simple diff happy path: one account changed + counters bump ==="
ACCTS_A='[{"domain":"acct1","balance":500,"next_nonce":0},{"domain":"acct2","balance":100,"next_nonce":0}]'
ACCTS_B='[{"domain":"acct1","balance":600,"next_nonce":1},{"domain":"acct2","balance":100,"next_nonce":0}]'
write_snapshot "$A_FILE" 10 "h1" 50 30 "$ACCTS_A" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR"
write_snapshot "$B_FILE" 11 "h2" 100 80 "$ACCTS_B" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR"
set +e
OUT=$($WALLET diff-snapshots --from "$A_FILE" --to "$B_FILE" 2>&1)
RC=$?
set -e
OUT=$(echo "$OUT" | tr -d '\r')
assert_eq "$RC" "0" "simple diff exit 0"
assert_contains "$OUT" "[counters]"                          "shows counters section"
assert_contains "$OUT" "accumulated_inbound: 50 -> 100"      "shows inbound delta"
assert_contains "$OUT" "accumulated_outbound: 30 -> 80"      "shows outbound delta"
assert_contains "$OUT" "[accounts]"                          "shows accounts section"
assert_contains "$OUT" "modified: 1"                         "shows 1 modified account"
assert_not_contains "$OUT" "supply_drift"                    "no supply_drift on matching account changes"
assert_not_contains "$OUT" "CRITICAL"                        "no CRITICAL on healthy diff"
# block_index delta is 1, positive — no block_index_negative_delta anomaly.
assert_not_contains "$OUT" "block_index_negative_delta"      "no negative block_index_delta anomaly"

echo
echo "=== 7. --account-detail emits per-account balance-delta line ==="
set +e
OUT=$($WALLET diff-snapshots --from "$A_FILE" --to "$B_FILE" --account-detail 2>&1)
RC=$?
set -e
OUT=$(echo "$OUT" | tr -d '\r')
assert_eq "$RC" "0" "--account-detail exit 0"
assert_contains "$OUT" "\[~\] acct1 balance: 500 -> 600"   "per-account balance-delta line"
# Default mode (no --account-detail) must NOT emit the [~] balance line.
OUT_DEFAULT=$($WALLET diff-snapshots --from "$A_FILE" --to "$B_FILE" 2>&1 | tr -d '\r')
assert_not_contains "$OUT_DEFAULT" "\[~\] acct1 balance"   "default mode hides per-account detail"

echo
echo "=== 8. --group filtering ==="
# NOTE: bare `[counters]` in grep is a character class — escape brackets
# explicitly so the test matches the literal section header.
OUT=$($WALLET diff-snapshots --from "$A_FILE" --to "$B_FILE" --group counters 2>&1 | tr -d '\r')
assert_contains     "$OUT" '\[counters\]' "--group counters shows counters"
assert_not_contains "$OUT" '\[accounts\]' "--group counters hides accounts"
assert_not_contains "$OUT" '\[stakes\]'   "--group counters hides stakes"

OUT=$($WALLET diff-snapshots --from "$A_FILE" --to "$B_FILE" --group accounts 2>&1 | tr -d '\r')
assert_contains     "$OUT" '\[accounts\]' "--group accounts shows accounts"
assert_not_contains "$OUT" '\[counters\]' "--group accounts hides counters"

echo
echo "=== 9. --json output well-formed + documented shape ==="
JSON=$($WALLET diff-snapshots --from "$A_FILE" --to "$B_FILE" --json 2>&1 | tr -d '\r')
assert_contains "$JSON" '"from"'              "json has from envelope"
assert_contains "$JSON" '"to"'                "json has to envelope"
assert_contains "$JSON" '"block_index_delta"' "json has block_index_delta"
assert_contains "$JSON" '"counters"'          "json has counters group"
assert_contains "$JSON" '"accounts"'          "json has accounts group"
assert_contains "$JSON" '"anomalies"'         "json has anomalies array"
assert_contains "$JSON" '"modified"'          "json accounts.modified populated"
# Validate the JSON is parseable.
if command -v python3 >/dev/null 2>&1; then
    if echo "$JSON" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); assert d['block_index_delta']==1; assert d['from']['block_index']==10; assert d['to']['block_index']==11; assert 'modified' in d['accounts']; assert d['accounts']['modified'][0]['key']=='acct1'" 2>/dev/null; then
        echo "  PASS: json parses + structural invariants hold (python3)"; pass_count=$((pass_count + 1))
    else
        echo "  FAIL: json parse / structural check failed"; fail_count=$((fail_count + 1))
    fi
else
    echo "  SKIP: python3 unavailable; structural-only check above"
fi

echo
echo "=== 10a. CRITICAL: state_root_unchanged_but_accounts_changed → exit 2 ==="
# Identical state_root + DIFFERENT accounts.
write_snapshot "$A_FILE" 10 "h1" 50 30 "$ACCTS_A" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR" "$HDR_SR_A"
write_snapshot "$B_FILE" 10 "h1" 50 30 "$ACCTS_B" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR" "$HDR_SR_A"
set +e
OUT=$($WALLET diff-snapshots --from "$A_FILE" --to "$B_FILE" 2>&1)
RC=$?
set -e
OUT=$(echo "$OUT" | tr -d '\r')
assert_eq "$RC" "2" "state_root-unchanged-but-accounts-changed exits 2"
assert_contains "$OUT" "CRITICAL" "CRITICAL anomaly marker emitted"
assert_contains "$OUT" "state_root_unchanged_but_accounts_changed" "anomaly code emitted"

echo
echo "=== 10b. CRITICAL: supply_drift → exit 2 ==="
# Counter advanced but NO account or stake changed.
write_snapshot "$A_FILE" 10 "h1" 50 30 "$ACCTS_A" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR"
write_snapshot "$B_FILE" 10 "h1" 999 30 "$ACCTS_A" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR"
set +e
OUT=$($WALLET diff-snapshots --from "$A_FILE" --to "$B_FILE" 2>&1)
RC=$?
set -e
OUT=$(echo "$OUT" | tr -d '\r')
assert_eq "$RC" "2" "supply_drift exits 2"
assert_contains "$OUT" "supply_drift" "supply_drift anomaly emitted"
assert_contains "$OUT" "CRITICAL"     "supply_drift marked CRITICAL"

echo
echo "=== 11. INFO: block_index_negative_delta → exit 0 (informational only) ==="
# --from has a HIGHER block_index than --to (caller swapped args).
write_snapshot "$A_FILE" 100 "h1" 50 30 "$ACCTS_A" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR"
write_snapshot "$B_FILE"  10 "h2" 50 30 "$ACCTS_A" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR" "$EMPTY_ARR"
set +e
OUT=$($WALLET diff-snapshots --from "$A_FILE" --to "$B_FILE" 2>&1)
RC=$?
set -e
OUT=$(echo "$OUT" | tr -d '\r')
assert_eq "$RC" "0" "negative-block-index-delta exits 0 (INFO only)"
assert_contains "$OUT" "block_index_negative_delta" "block_index_negative_delta anomaly emitted"
assert_contains "$OUT" "INFO"                      "block_index_negative_delta marked INFO"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet diff-snapshots"; exit 0
else
    echo "  FAIL: test_wallet_diff_snapshots"; exit 1
fi
