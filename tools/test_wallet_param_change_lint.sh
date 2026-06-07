#!/usr/bin/env bash
# determ-wallet param-change-lint — OFFLINE build-time governance PARAM_CHANGE lint.
#
# Predicts, BEFORE submission, whether a PARAM_CHANGE will activate EFFECTIVE-ly,
# silently no-op (INERT_BAD_WIDTH — a whitelisted numeric chain-scalar MIN_STAKE
# / SUSPENSION_SLASH / UNSTAKE_DELAY whose value is not exactly 8 bytes, which
# src/chain/chain.cpp::activate_pending_params' parse_u64 rejects), be HOOK_ONLY,
# or be UNKNOWN_NAME (off the src/node/validator.cpp kWhitelist — the validator
# rejects the tx). The wallet-side build-time dual of operator_param_activation_
# preflight.sh. Reimplements the whitelist + 8-byte width rule (wallet TCB
# separation — no chain-library link). Exit 0 EFFECTIVE/HOOK_ONLY, 2
# INERT_BAD_WIDTH/UNKNOWN_NAME, 1 args/parse.
#
# FULLY OFFLINE (no cluster). Run from repo root: bash tools/test_wallet_param_change_lint.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi
W="$DETERM_WALLET"
PY=python

T=test_wallet_param_change_lint
rm -rf "$T"; mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}
EIGHT=$($PY -c "print('00'*8)")   # 8-byte zero value

echo "=== 1. arg handling ==="
"$W" param-change-lint --help >/dev/null 2>&1;                          assert "$([ $? -eq 0 ] && echo true || echo false)" "--help exit 0"
"$W" param-change-lint >/dev/null 2>&1;                                 assert "$([ $? -eq 1 ] && echo true || echo false)" "no args exit 1"
"$W" param-change-lint --name MIN_STAKE >/dev/null 2>&1;                assert "$([ $? -eq 1 ] && echo true || echo false)" "missing --value-hex exit 1"
"$W" param-change-lint --name MIN_STAKE --value-hex "$EIGHT" --tx-json x >/dev/null 2>&1
assert "$([ $? -eq 1 ] && echo true || echo false)" "--tx-json + --name mutually exclusive exit 1"
"$W" param-change-lint --name MIN_STAKE --value-hex 0g0g >/dev/null 2>&1; assert "$([ $? -eq 1 ] && echo true || echo false)" "non-hex value exit 1"
"$W" param-change-lint --name MIN_STAKE --value-hex 012 >/dev/null 2>&1;  assert "$([ $? -eq 1 ] && echo true || echo false)" "odd-length hex exit 1"

verdict_of() { "$W" param-change-lint --name "$1" --value-hex "$2" --json 2>/dev/null | $PY -c "import json,sys;print(json.load(sys.stdin)['verdict'])" 2>/dev/null; }

echo; echo "=== 2. EFFECTIVE: the 3 numeric chain-scalars with an 8-byte value -> exit 0 ==="
for n in MIN_STAKE SUSPENSION_SLASH UNSTAKE_DELAY; do
  "$W" param-change-lint --name "$n" --value-hex "$EIGHT" >/dev/null 2>&1; rc=$?
  v=$(verdict_of "$n" "$EIGHT")
  assert "$([ "$v" = "EFFECTIVE" ] && [ $rc -eq 0 ] && echo true || echo false)" "$n + 8 bytes -> EFFECTIVE exit 0"
done

echo; echo "=== 3. INERT_BAD_WIDTH: numeric scalar, wrong widths (4 / 0 / 16 bytes) -> exit 2 ==="
for w in 01020304 "" $($PY -c "print('00'*16)"); do
  bytes=$(( ${#w} / 2 ))
  "$W" param-change-lint --name MIN_STAKE --value-hex "$w" >/dev/null 2>&1; rc=$?
  v=$(verdict_of MIN_STAKE "$w")
  assert "$([ "$v" = "INERT_BAD_WIDTH" ] && [ $rc -eq 2 ] && echo true || echo false)" "MIN_STAKE + $bytes bytes -> INERT_BAD_WIDTH exit 2"
done

echo; echo "=== 4. HOOK_ONLY: the 6 hook-forwarded whitelisted names -> exit 0 ==="
for n in tx_commit_ms block_sig_ms abort_claim_ms bft_escalation_threshold param_keyholders param_threshold; do
  "$W" param-change-lint --name "$n" --value-hex "$EIGHT" >/dev/null 2>&1; rc=$?
  v=$(verdict_of "$n" "$EIGHT")
  assert "$([ "$v" = "HOOK_ONLY" ] && [ $rc -eq 0 ] && echo true || echo false)" "$n -> HOOK_ONLY exit 0"
done

echo; echo "=== 5. UNKNOWN_NAME: off-whitelist -> exit 2 ==="
for n in bogus_param block_subsidy MIN_stake; do   # block_subsidy is a const-leaf but NOT whitelisted; MIN_stake wrong case
  "$W" param-change-lint --name "$n" --value-hex "$EIGHT" >/dev/null 2>&1; rc=$?
  v=$(verdict_of "$n" "$EIGHT")
  assert "$([ "$v" = "UNKNOWN_NAME" ] && [ $rc -eq 2 ] && echo true || echo false)" "$n -> UNKNOWN_NAME exit 2"
done

echo; echo "=== 6. --tx-json round-trip: decode the actual built PARAM_CHANGE payload ==="
"$W" param-change-build --name MIN_STAKE --value 1000 --effective-height 100 --nonce 0 --from node1 --out "$T/eff.json" >/dev/null 2>&1
"$W" param-change-lint --tx-json "$T/eff.json" >/dev/null 2>&1
assert "$([ $? -eq 0 ] && echo true || echo false)" "built MIN_STAKE --value 1000 -> EFFECTIVE exit 0 (payload-decoded)"
"$W" param-change-build --name MIN_STAKE --value-hex 0102 --effective-height 100 --nonce 0 --from node1 --out "$T/inert.json" >/dev/null 2>&1
"$W" param-change-lint --tx-json "$T/inert.json" >/dev/null 2>&1
assert "$([ $? -eq 2 ] && echo true || echo false)" "built MIN_STAKE --value-hex 0102 (2 bytes) -> INERT exit 2 (the trap)"
"$W" param-change-build --name tx_commit_ms --value 50 --effective-height 100 --nonce 0 --from node1 --out "$T/hook.json" >/dev/null 2>&1
NAME=$("$W" param-change-lint --tx-json "$T/hook.json" --json 2>/dev/null | $PY -c "import json,sys;print(json.load(sys.stdin)['name'])")
assert "$([ "$NAME" = "tx_commit_ms" ] && echo true || echo false)" "payload-decode recovers the name (tx_commit_ms)"

echo; echo "=== 7. --json shape ==="
JOK=$("$W" param-change-lint --name MIN_STAKE --value-hex "$EIGHT" --json 2>/dev/null | $PY -c "
import json,sys
d=json.load(sys.stdin)
print('true' if d['verdict']=='EFFECTIVE' and d['effective'] is True and d['value_bytes']==8 else 'false')")
assert "$JOK" "--json carries verdict + effective + value_bytes"

echo; echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then echo "  PASS: test_wallet_param_change_lint"; exit 0
else echo "  FAIL: test_wallet_param_change_lint"; exit 1; fi
