#!/usr/bin/env bash
# determ verify-genesis — standalone genesis.json validator end-to-end.
#
# Exercises the operator-facing surface added alongside the S-039
# diagnostic-UX finding. verify-genesis lets operators:
#   * sanity-check a genesis.json before deploying ("does this hash
#     to what I expect?")
#   * compare chain identities across teams ("does our genesis match
#     theirs?")
#   * confirm config integrity ("did anyone touch this since I pinned
#     the hash in my config?")
#
# Assertions covered:
#   1. Successful load + hash emission on a valid genesis.json
#   2. --json emits parseable single-line JSON
#   3. JSON output includes operational params (m_creators etc.)
#      that are NOT in the identity hash (the S-039 UX surface)
#   4. --expected-hash matches the computed hash → exit 0
#   5. --expected-hash mismatches → exit 1 with FAIL diagnostic
#   6. Missing --in arg → usage message + exit 1
#   7. Bad path → cannot_open error
#   8. Oversized genesis_message → rejected at parse time
#   9. LOTTERY with multiplier < 2 → rejected (E3 validation)
#
# Run from repo root: bash tools/test_verify_genesis.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

T=test_verify_genesis
TABS=$PROJECT_ROOT/$T
rm -rf $T
mkdir -p $T

pass=0; fail=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass=$((pass+1))
  else echo "  FAIL: $2"; fail=$((fail+1)); fi
}

# Valid genesis.json
cat > $T/genesis.json <<EOF
{
  "chain_id": "test-verify-genesis",
  "m_creators": 3,
  "k_block_sigs": 3,
  "block_subsidy": 100,
  "min_stake": 1000,
  "initial_creators": [],
  "initial_balances": []
}
EOF

echo "=== 1. Successful load + hash emission ==="
OUT=$($DETERM verify-genesis --in $T/genesis.json 2>&1)
echo "$OUT" | head -5
if echo "$OUT" | grep -q "genesis OK"; then assert true "genesis OK on valid file"
else assert false "expected 'genesis OK' in output"; fi

# Extract the computed hash for downstream use.
HASH=$(echo "$OUT" | grep "genesis_hash" | head -1 | awk '{print $NF}')
if [ -n "$HASH" ] && [ ${#HASH} -eq 64 ]; then
  assert true "genesis_hash is 64 hex chars (got $HASH)"
else
  assert false "expected 64-hex-char genesis_hash, got '$HASH'"
fi

echo
echo "=== 2. --json emits parseable single-line JSON ==="
JSON_OUT=$($DETERM verify-genesis --in $T/genesis.json --json 2>&1)
echo "$JSON_OUT" | head -1
if echo "$JSON_OUT" | python -c "import sys, json; json.loads(sys.stdin.read())" 2>/dev/null; then
  assert true "--json output is valid JSON"
else
  assert false "--json output failed to parse"
fi

echo
echo "=== 3. JSON output includes operational params (S-039 UX surface) ==="
HAS_M_CREATORS=$(echo "$JSON_OUT" | python -c "import sys, json; print('m_creators' in json.loads(sys.stdin.read()))")
HAS_BFT=$(echo "$JSON_OUT" | python -c "import sys, json; print('bft_enabled' in json.loads(sys.stdin.read()))")
if [ "$HAS_M_CREATORS" = "True" ] && [ "$HAS_BFT" = "True" ]; then
  assert true "--json output includes operational params (m_creators, bft_enabled) per S-039 UX surface"
else
  assert false "--json output missing operational params"
fi

echo
echo "=== 4. --expected-hash MATCHES ==="
$DETERM verify-genesis --in $T/genesis.json --expected-hash "$HASH" > $T/match.out 2>&1
RC=$?
if [ $RC -eq 0 ] && grep -q "matches" $T/match.out; then
  assert true "matching --expected-hash exits 0 + reports match"
else
  assert false "matching --expected-hash unexpected (rc=$RC)"
fi

echo
echo "=== 5. --expected-hash MISMATCHES ==="
$DETERM verify-genesis --in $T/genesis.json --expected-hash 0000000000000000000000000000000000000000000000000000000000000000 > $T/mismatch.out 2>&1
RC=$?
if [ $RC -ne 0 ] && grep -q "FAIL" $T/mismatch.out; then
  assert true "mismatched --expected-hash exits non-zero + FAIL diagnostic"
else
  assert false "mismatched --expected-hash unexpected (rc=$RC)"
fi

echo
echo "=== 6. Missing --in arg ==="
$DETERM verify-genesis > $T/no_in.out 2>&1
RC=$?
if [ $RC -ne 0 ] && grep -q "Usage:" $T/no_in.out; then
  assert true "missing --in shows usage + exits non-zero"
else
  assert false "missing --in should show usage"
fi

echo
echo "=== 7. Bad path ==="
$DETERM verify-genesis --in /nonexistent.json > $T/bad_path.out 2>&1
RC=$?
if [ $RC -ne 0 ]; then
  assert true "bad path exits non-zero"
else
  assert false "bad path should fail"
fi

echo
echo "=== 8. Oversized genesis_message ==="
# 257-byte message — exceeds the 256-byte cap.
MSG=$(python -c "print('x' * 257)")
cat > $T/oversize.json <<EOF
{
  "chain_id": "test-oversize",
  "genesis_message": "$MSG",
  "initial_creators": []
}
EOF
$DETERM verify-genesis --in $T/oversize.json > $T/oversize.out 2>&1
RC=$?
if [ $RC -ne 0 ]; then
  assert true "oversized genesis_message rejected"
else
  assert false "oversized genesis_message should be rejected"
fi

echo
echo "=== 9. LOTTERY multiplier < 2 ==="
cat > $T/bad_lottery.json <<EOF
{
  "chain_id": "test-bad-lottery",
  "subsidy_mode": 1,
  "lottery_jackpot_multiplier": 1,
  "block_subsidy": 100,
  "initial_creators": []
}
EOF
$DETERM verify-genesis --in $T/bad_lottery.json > $T/bad_lottery.out 2>&1
RC=$?
if [ $RC -ne 0 ]; then
  assert true "LOTTERY with multiplier < 2 rejected (E3 validation)"
else
  assert false "LOTTERY with multiplier < 2 should be rejected"
fi

echo
echo "── Summary ──"
echo "PASS: $pass; FAIL: $fail"
if [ $fail -eq 0 ]; then
  echo "  PASS: verify-genesis CLI"
  exit 0
else
  echo "  FAIL: verify-genesis CLI had failures"
  exit 1
fi
