#!/usr/bin/env bash
# determ-wallet supply-audit offline A1 unitary-supply-identity test.
#
# The A1 invariant (asserted by the chain after every block apply in
# src/chain/chain.cpp::apply_transactions) is:
#
#     live_total = Σ accounts[].balance + Σ stakes[].locked
#     expected   = genesis_total + accumulated_subsidy + accumulated_inbound
#                - accumulated_slashed - accumulated_outbound
#     BALANCED  <=>  live_total == expected
#
# determ-wallet does NOT link the chain library (TCB separation), so the
# subcommand recomputes the identity by parsing the snapshot JSON directly.
# This wrapper exercises that parser end-to-end.
#
# Covers:
#   1. --help text exists + documents the identity, both flags, exit codes.
#   2. Missing --snapshot / unknown arg → diagnostic + exit 1.
#   3. Missing input file → exit 1 (NOT exit 2 — that's reserved for a
#      genuine identity violation).
#   4. Malformed JSON → exit 1.
#   5. Balanced snapshot (human) → "balanced" + exit 0.
#   6. Balanced snapshot (--json) → balanced:true, live==expected, exit 0.
#   7. --in <file> alias behaves identically to --snapshot.
#   8. Violated snapshot (live inflated) → VIOLATED + exit 2 + correct delta.
#   9. Underflow-trap snapshot (slashed+outbound exceed additive side):
#      the raw modular expected_total wraps, but the underflow-safe additive
#      comparison must still report VIOLATED + exit 2.
#   10. Stakes contribute to live_total (stake-only balanced snapshot).
#
# Run from repo root: bash tools/test_wallet_supply_audit.sh
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
SCRATCH="build/test_wallet_supply_audit.$$"
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
# Fixture helper — write a minimal snapshot JSON. The wallet command parses
# text-only (no Chain::restore_from_snapshot), so only the fields the audit
# touches are required: accounts[].balance, stakes[].locked, and the five
# c:-namespace counters.
# --------------------------------------------------------------------------
write_snapshot() {
    # $1 = output path
    # $2 = block_index
    # $3 = accounts array (JSON literal)
    # $4 = stakes array (JSON literal)
    # $5 = genesis_total
    # $6 = accumulated_subsidy
    # $7 = accumulated_inbound
    # $8 = accumulated_slashed
    # $9 = accumulated_outbound
    cat > "$1" <<EOF
{
  "version": 1,
  "block_index": $2,
  "accounts": $3,
  "stakes": $4,
  "registrants": [],
  "genesis_total": $5,
  "accumulated_subsidy": $6,
  "accumulated_inbound": $7,
  "accumulated_slashed": $8,
  "accumulated_outbound": $9
}
EOF
}

EMPTY='[]'

echo "=== 1. --help documents identity + flags + exit codes ==="
HELP=$($WALLET supply-audit --help 2>&1 | tr -d '\r')
assert_contains "$HELP" "supply-audit --snapshot"       "help shows synopsis"
assert_contains "$HELP" "accumulated_subsidy"           "help references A1 counters"
assert_contains "$HELP" "accumulated_slashed"           "help references slashed counter"
assert_contains "$HELP" "live_total"                    "help references live_total"
assert_contains "$HELP" "underflow"                     "help explains underflow-safe comparison"
assert_contains "$HELP" "--in"                          "help documents --in alias"
assert_contains "$HELP" "balanced"                      "help documents balanced exit_reason"

echo
echo "=== 2. Missing --snapshot / unknown arg → exit 1 ==="
set +e
$WALLET supply-audit >/dev/null 2>&1; RC=$?
set -e
assert_eq "$RC" "1" "missing --snapshot exits 1"

set +e
ERR=$($WALLET supply-audit --bogus 2>&1); RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "unknown arg exits 1"
assert_contains "$ERR" "unknown argument" "unknown-arg diagnostic"

echo
echo "=== 3. Missing input file → exit 1 (NOT exit 2) ==="
set +e
ERR=$($WALLET supply-audit --snapshot "$SCRATCH/nope.json" 2>&1); RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "missing file exits 1"
assert_contains "$ERR" "cannot open" "missing-file diagnostic"

echo
echo "=== 4. Malformed JSON → exit 1 ==="
BAD="$SCRATCH/bad.json"
echo "not json {" > "$BAD"
set +e
ERR=$($WALLET supply-audit --snapshot "$BAD" 2>&1); RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "malformed JSON exits 1"
assert_contains "$ERR" "JSON parse" "malformed-JSON diagnostic"

echo
echo "=== 5. Balanced snapshot (human) → balanced + exit 0 ==="
# genesis 1000 + subsidy 200 + inbound 50 - slashed 30 - outbound 20 = 1200
# live = 700 (acct) + 500 (stake) = 1200  → balanced
BAL="$SCRATCH/bal.json"
ACCTS='[{"domain":"a","balance":700,"next_nonce":0}]'
STKS='[{"domain":"a","locked":500,"unlock_height":0}]'
write_snapshot "$BAL" 42 "$ACCTS" "$STKS" 1000 200 50 30 20
set +e
OUT=$($WALLET supply-audit --snapshot "$BAL" 2>&1); RC=$?
set -e
OUT=$(echo "$OUT" | tr -d '\r')
assert_eq "$RC" "0" "balanced snapshot exits 0"
assert_contains "$OUT" "live_total"          "human output shows live_total"
assert_contains "$OUT" "expected_total"      "human output shows expected_total"
assert_contains "$OUT" "balanced"            "human output reports balanced"
assert_not_contains "$OUT" "VIOLATED"        "balanced snapshot not flagged VIOLATED"

echo
echo "=== 6. Balanced snapshot (--json) → balanced:true, live==expected ==="
JSON=$($WALLET supply-audit --snapshot "$BAL" --json 2>&1 | tr -d '\r')
assert_contains "$JSON" '"balanced":true'        "json balanced:true"
assert_contains "$JSON" '"live_total":1200'      "json live_total=1200"
assert_contains "$JSON" '"expected_total":1200'  "json expected_total=1200"
assert_contains "$JSON" '"exit_reason":"balanced"' "json exit_reason balanced"
if command -v python3 >/dev/null 2>&1; then
    if echo "$JSON" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); assert d['balanced'] is True; assert d['live_total']==1200; assert d['expected_total']==1200; assert d['sum_account_balance']==700; assert d['sum_stake_locked']==500; assert d['delta']=='0'" 2>/dev/null; then
        echo "  PASS: json parses + structural invariants hold (python3)"; pass_count=$((pass_count + 1))
    else
        echo "  FAIL: json parse / structural check failed"; fail_count=$((fail_count + 1))
    fi
else
    echo "  SKIP: python3 unavailable; substring checks above"
fi

echo
echo "=== 7. --in alias behaves identically to --snapshot ==="
OUT_IN=$($WALLET supply-audit --in "$BAL" 2>&1 | tr -d '\r')
set +e
$WALLET supply-audit --in "$BAL" >/dev/null 2>&1; RC=$?
set -e
assert_eq "$RC" "0" "--in alias exits 0 on balanced"
assert_contains "$OUT_IN" "balanced" "--in alias reports balanced"

echo
echo "=== 8. Violated snapshot (live inflated) → VIOLATED + exit 2 ==="
# Same counters, but acct balance bumped to 800 → live 1300 != expected 1200.
VIO="$SCRATCH/vio.json"
ACCTS_BAD='[{"domain":"a","balance":800,"next_nonce":0}]'
write_snapshot "$VIO" 42 "$ACCTS_BAD" "$STKS" 1000 200 50 30 20
set +e
OUT=$($WALLET supply-audit --snapshot "$VIO" 2>&1); RC=$?
set -e
OUT=$(echo "$OUT" | tr -d '\r')
assert_eq "$RC" "2" "violated snapshot exits 2"
assert_contains "$OUT" "VIOLATED" "human output reports VIOLATED"
# delta = rhs - lhs = (1000+200+50) - (1300+30+20) = 1250 - 1350 = -100
assert_contains "$OUT" "-100" "violation delta is -100"
JSON=$($WALLET supply-audit --snapshot "$VIO" --json 2>&1 | tr -d '\r')
assert_contains "$JSON" '"balanced":false'         "json balanced:false on violation"
assert_contains "$JSON" '"exit_reason":"violated"' "json exit_reason violated"

echo
echo "=== 9. Underflow-trap: slashed+outbound exceed additive side → VIOLATED ==="
# genesis 10, all-else 0 except slashed 100, live 0.
# Raw modular expected_total = 10 - 100 = wraps to a huge uint64; the
# underflow-safe additive form (lhs=100 vs rhs=10) must catch this.
UNDER="$SCRATCH/under.json"
write_snapshot "$UNDER" 7 "$EMPTY" "$EMPTY" 10 0 0 100 0
set +e
OUT=$($WALLET supply-audit --snapshot "$UNDER" 2>&1); RC=$?
set -e
OUT=$(echo "$OUT" | tr -d '\r')
assert_eq "$RC" "2" "underflow-trap snapshot exits 2 (not silently balanced)"
assert_contains "$OUT" "VIOLATED" "underflow trap reports VIOLATED"
JSON=$($WALLET supply-audit --snapshot "$UNDER" --json 2>&1 | tr -d '\r')
assert_contains "$JSON" '"balanced":false' "underflow trap json balanced:false"

echo
echo "=== 10. Stakes contribute to live_total (stake-only balanced) ==="
# genesis 0, subsidy 5000, no other counters; live = 0 acct + 5000 stake.
STAKE_ONLY="$SCRATCH/stakeonly.json"
STKS_5000='[{"domain":"v","locked":5000,"unlock_height":100}]'
write_snapshot "$STAKE_ONLY" 3 "$EMPTY" "$STKS_5000" 0 5000 0 0 0
set +e
$WALLET supply-audit --snapshot "$STAKE_ONLY" >/dev/null 2>&1; RC=$?
set -e
assert_eq "$RC" "0" "stake-only balanced snapshot exits 0"
JSON=$($WALLET supply-audit --snapshot "$STAKE_ONLY" --json 2>&1 | tr -d '\r')
assert_contains "$JSON" '"sum_stake_locked":5000' "json sum_stake_locked=5000"
assert_contains "$JSON" '"live_total":5000'       "json live_total=5000 (stake only)"
assert_contains "$JSON" '"balanced":true'         "stake-only snapshot balanced"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet supply-audit"; exit 0
else
    echo "  FAIL"; exit 1
fi
