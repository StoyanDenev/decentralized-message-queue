#!/usr/bin/env bash
# A2 Phase 5 — OPAQUE adapter interface (stub implementation).
#
# Verifies:
#   1. register + authenticate with the right password produces matching
#      export_keys.
#   2. authenticate with the wrong password produces a different
#      export_key (under the stub) — Phase 6's real OPAQUE will reject
#      outright, but the stub is deterministic-but-divergent.
#   3. guardian_id binding: register(pw, gid=1) and authenticate(pw,
#      record_from_gid1, gid=2) is rejected.
#   4. Truncated/malformed record is rejected.
#   5. is_stub() returns true and suite_name is "stub-argon2id-v1".
#   6. Two registrations with the same password produce different
#      records (fresh salt per register) AND different export_keys.
#
# Phase 6 will rewrite this test once libopaque replaces the stub —
# notably, assertion 2 (wrong password produces different key) becomes
# (wrong password fails entirely with no key emitted), which is the
# real OPAQUE security property.
#
# Run from repo root: bash tools/test_wallet_opaque_adapter.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

WALLET="$DETERM_WALLET"
PW="myp4ssphr4se"
GID=3

pass_count=0; fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}
assert_neq() {
  if [ "$1" != "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3 (unexpected equality)"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Register + authenticate round-trip ==="
REG_OUT=$($WALLET opaque-handshake --mode register --password "$PW" --guardian-id $GID | tr -d '\r')
SUITE=$(echo "$REG_OUT" | grep "suite:"      | awk '{print $2}')
IS_STUB=$(echo "$REG_OUT" | grep "is_stub:"  | awk '{print $2}')
RECORD=$(echo "$REG_OUT" | grep "record:"    | awk '{print $2}')
REG_KEY=$(echo "$REG_OUT" | grep "export_key:" | awk '{print $2}')
assert_eq "$SUITE" "stub-argon2id-v1" "suite name"
assert_eq "$IS_STUB" "true" "is_stub reports stub"

AUTH_OUT=$($WALLET opaque-handshake --mode authenticate --password "$PW" \
            --guardian-id $GID --record $RECORD | tr -d '\r')
AUTH_KEY=$(echo "$AUTH_OUT" | grep "export_key:" | awk '{print $2}')
assert_eq "$AUTH_KEY" "$REG_KEY" "register/authenticate produce matching key"

echo
echo "=== 2. Wrong password produces different export key (stub) ==="
WRONG_OUT=$($WALLET opaque-handshake --mode authenticate --password "wrongpw" \
              --guardian-id $GID --record $RECORD | tr -d '\r')
WRONG_KEY=$(echo "$WRONG_OUT" | grep "export_key:" | awk '{print $2}')
assert_neq "$WRONG_KEY" "$REG_KEY" "wrong password yields different key"

echo
echo "=== 3. Guardian-id binding (gid mismatch rejected) ==="
GID_MISMATCH_OUT=$($WALLET opaque-handshake --mode authenticate --password "$PW" \
                      --guardian-id 5 --record $RECORD 2>&1 | tr -d '\r')
if echo "$GID_MISMATCH_OUT" | grep -q "authenticate failed"; then
  echo "  PASS: guardian_id mismatch rejected"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: guardian_id mismatch not rejected — got: $GID_MISMATCH_OUT"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 4. Malformed record rejected ==="
MAL_OUT=$($WALLET opaque-handshake --mode authenticate --password "$PW" \
              --guardian-id $GID --record deadbeef 2>&1 | tr -d '\r')
if echo "$MAL_OUT" | grep -q "authenticate failed"; then
  echo "  PASS: short record rejected"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: short record not rejected — got: $MAL_OUT"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 5. Two registrations: fresh salt + different keys ==="
REG2_OUT=$($WALLET opaque-handshake --mode register --password "$PW" --guardian-id $GID | tr -d '\r')
RECORD2=$(echo "$REG2_OUT" | grep "record:"     | awk '{print $2}')
REG2_KEY=$(echo "$REG2_OUT" | grep "export_key:" | awk '{print $2}')
assert_neq "$RECORD2"  "$RECORD"  "two registers produce different records"
assert_neq "$REG2_KEY" "$REG_KEY" "two registers produce different export keys"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: OPAQUE adapter (stub) end-to-end"; exit 0
else
  echo "  FAIL"; exit 1
fi
