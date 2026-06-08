#!/usr/bin/env bash
# determ-wallet account-export HEX-VALIDITY rejection edge test.
#
# Targets the two `from_hex`-throw rejection branches in cmd_account_export
# that NO existing test exercises:
#
#   wallet/main.cpp:2376  try { (void)from_hex(address.substr(2)); }
#                catch -> "account-export: 'address' hex body is not valid hex"
#   wallet/main.cpp:2389  try { priv_bytes = from_hex(privkey_hex); }
#                catch -> "account-export: 'privkey_hex' is not valid hex"
#
# Why this is a DISTINCT layer from what test_wallet_account_export.sh covers:
#   - That suite's case 23 feeds "aabbccdd" (no 0x prefix, wrong length) ->
#     caught by the LENGTH/PREFIX guard (size != 66) BEFORE from_hex runs.
#   - Its case 24 feeds "aabbcc" (short privkey) -> caught by the LENGTH guard
#     (size != 64) BEFORE from_hex runs.
#   Neither ever reaches the hex-content validation. This test feeds inputs
#   that PASS the length+prefix guards (address is exactly 66 chars and starts
#   with "0x"; privkey is exactly 64 chars) but contain a non-hex character,
#   so the ONLY guard that can reject them is the from_hex catch. This is the
#   fail-closed contract that matters: an address/privkey with the right shape
#   but garbage content must NOT be silently exported (a corrupt seed would
#   flow downstream into backup-create --secret / account-import and produce a
#   wrong wallet).
#
# A subtlety this test pins down: from_hex (wallet/main.cpp:93) parses each
# 2-char pair via `istringstream >> std::hex`. A non-hex char at an ODD
# position within a pair (e.g. the trailing char of "...az") is silently
# IGNORED because the leading hex digit parses successfully and the stream
# does not fail. To actually trip the rejection, the non-hex char must sit at
# an EVEN position (start of a pair, e.g. "za..."). Case D documents the
# lenient-parse path as a control so the position-sensitivity of the guard is
# explicit and the edge is provably distinct from a pure length failure.
#
# Assertions:
#   A. address: 66 chars, "0x" prefix, non-hex 'z' at even position -> rc=1,
#      diagnostic mentions "'address' hex body is not valid hex".
#   B. privkey_hex: 64 chars, non-hex 'g' at even position -> rc=1,
#      diagnostic mentions "'privkey_hex' is not valid hex".
#   C. privkey_hex: 64 chars, full non-hex pair "zz" at start -> rc=1
#      (confirms whole-pair garbage rejects too).
#   D. CONTROL (lenient-parse quirk): privkey_hex 64 chars, valid hex except a
#      trailing non-hex 'z' at the final ODD position -> rc=0 (from_hex's
#      partial-pair parse silently accepts the leading digit). Documents that
#      the guard is position-sensitive, not a blanket character scan.
#   E. HAPPY-PATH CONTROL: fully valid 0x+64-hex address and 64-hex privkey
#      export with rc=0, proving the rejections in A-C are content-specific,
#      not a blanket refusal of every input.
#
# Run from repo root: bash tools/test_wallet_account_export_hex_validity_edge.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       missing substring: $2"; echo "       in:                $1"; fail_count=$((fail_count + 1)); fi
}

# Reusable fully-valid building blocks (length+prefix correct, hex content
# correct). We mutate ONE field at a time so each assertion isolates exactly
# one guard.
VALID_PRIV="$(printf 'a%.0s' $(seq 1 64))"          # 64 hex chars
VALID_ADDR="0x$(printf 'b%.0s' $(seq 1 64))"        # 0x + 64 hex chars (len 66)

# Sanity: confirm the building blocks are the exact lengths the guards expect
# (so a future change to the helpers can't silently neuter the test).
assert_eq "${#VALID_PRIV}" "64" "fixture VALID_PRIV is exactly 64 chars"
assert_eq "${#VALID_ADDR}" "66" "fixture VALID_ADDR is exactly 66 chars (0x + 64)"

write_acc() {  # $1=addr $2=priv $3=outfile
  printf '{"address":"%s","privkey_hex":"%s"}' "$1" "$2" > "$3"
}

echo
echo "=== A. address 0x+66-len but non-hex 'z' at EVEN position -> reject ==="
# 0x + 'z' + 63 'a' = length 66, prefix 0x; first hex pair "za" fails std::hex.
BAD_ADDR="0xz$(printf 'a%.0s' $(seq 1 63))"
assert_eq "${#BAD_ADDR}" "66" "  (precondition) bad address is length 66 so it passes the length guard"
write_acc "$BAD_ADDR" "$VALID_PRIV" "$TMP/a.json"
set +e
ERR=$("$WALLET" account-export --in "$TMP/a.json" 2>&1); RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on non-hex address body (right length, right prefix)"
assert_contains "$ERR" "'address' hex body is not valid hex" \
  "diagnostic identifies the address hex-body guard (not the length guard)"

echo
echo "=== B. privkey_hex 64-len but non-hex 'g' at EVEN position -> reject ==="
# 'g' + 63 'a' = length 64; first pair "ga" fails std::hex.
BAD_PRIV="g$(printf 'a%.0s' $(seq 1 63))"
assert_eq "${#BAD_PRIV}" "64" "  (precondition) bad privkey is length 64 so it passes the length guard"
write_acc "$VALID_ADDR" "$BAD_PRIV" "$TMP/b.json"
set +e
ERR=$("$WALLET" account-export --in "$TMP/b.json" 2>&1); RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on non-hex privkey_hex (right length)"
assert_contains "$ERR" "'privkey_hex' is not valid hex" \
  "diagnostic identifies the privkey hex-content guard (not the length guard)"

echo
echo "=== C. privkey_hex 64-len with full garbage pair 'zz' at start -> reject ==="
BAD_PRIV2="zz$(printf 'a%.0s' $(seq 1 62))"
assert_eq "${#BAD_PRIV2}" "64" "  (precondition) length 64"
write_acc "$VALID_ADDR" "$BAD_PRIV2" "$TMP/c.json"
set +e
ERR=$("$WALLET" account-export --in "$TMP/c.json" 2>&1); RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on whole-pair non-hex privkey"
assert_contains "$ERR" "'privkey_hex' is not valid hex" \
  "diagnostic identifies the privkey hex-content guard"

echo
echo "=== D. CONTROL: lenient-parse quirk — trailing 'z' at ODD position accepted ==="
# 63 valid 'a' + trailing 'z' = length 64. The final pair is "az": std::hex
# reads the leading 'a' (=0x0a) and stops; the stream does NOT fail, so
# from_hex silently accepts it. This proves the guard keys on PAIR-aligned
# parse failure, not a character-by-character hex scan — i.e. the rejections
# in A-C are NOT a trivial "string contains a non-hex char" check.
LENIENT_PRIV="$(printf 'a%.0s' $(seq 1 63))z"
assert_eq "${#LENIENT_PRIV}" "64" "  (precondition) length 64"
write_acc "$VALID_ADDR" "$LENIENT_PRIV" "$TMP/d.json"
set +e
OUT=$("$WALLET" account-export --in "$TMP/d.json" 2>&1); RC=$?
set -e
assert_eq "$RC" "0" "trailing-odd-position non-hex is accepted (from_hex partial-pair parse) — documents real behavior"

echo
echo "=== E. HAPPY-PATH CONTROL: fully valid address+privkey export rc=0 ==="
write_acc "$VALID_ADDR" "$VALID_PRIV" "$TMP/e.json"
set +e
OUT=$("$WALLET" account-export --in "$TMP/e.json" 2>&1 | tr -d '\r\n'); RC=$?
set -e
assert_eq "$RC" "0" "exit 0 on fully valid input (rejection is content-specific, not blanket)"
assert_eq "$OUT" "$VALID_PRIV" "raw-hex stdout echoes the valid 64-hex privkey"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet account-export hex-validity edge"; exit 0
else
    echo "  FAIL"; exit 1
fi
