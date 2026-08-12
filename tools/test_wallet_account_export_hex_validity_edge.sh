#!/usr/bin/env bash
# determ-wallet account-export DAK1 STRUCTURAL rejection edge test.
#
# HISTORY: this script used to pin the JSON-era from_hex content-validation
# branches of cmd_account_export. D2 deleted the JSON keyfile reader — the
# input is now the canonical binary DAK1 container (exactly 68 bytes:
# magic 'DAK1' || pubkey 32B || priv_seed 32B) whose decoder enforces
# exact length, magic, and pubkey==derive(seed). The hex-content branches
# no longer exist, so this edge suite pins the BINARY structural contract
# at the CLI boundary instead — the edges the main account-export suite
# does NOT cover:
#
#   A. EVERY strict prefix (0..67 bytes) of a valid DAK1 rejects (rc=1)
#      — the CLI-level truncation sweep, short direction of exact-length.
#   B. Trailing-byte forms (69 and 70 bytes) reject — long direction.
#   C. LAST-byte tampers: flipping pubkey[31] (byte 35) or seed[31]
#      (byte 67) each reject via derive-equality (the main suite only
#      flips the FIRST pubkey byte; the last-byte cases prove the check
#      covers the whole field, not a prefix compare).
#   D. Empty file rejects.
#   E. HAPPY-PATH CONTROL: the untampered container exports rc=0 and the
#      raw-hex view equals the seed — proving A-D are content-specific.
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

PY=python
command -v python >/dev/null 2>&1 || PY=python3

pass_count=0
fail_count=0
assert_eq() {
  if [ "$1" = "$2" ]; then echo "  PASS: $3"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $3"; echo "       expected: $2"; echo "       got:      $1"; fail_count=$((fail_count + 1)); fi
}

# Fixture: one valid DAK1 keyfile minted through the production writer.
SEED="$(printf 'a%.0s' $(seq 1 64))"    # 64 hex chars, deterministic
"$WALLET" account-import --priv "$SEED" --out "$TMP/acc.bin" >/dev/null
SZ=$(wc -c < "$TMP/acc.bin" | tr -d ' ')
assert_eq "$SZ" "68" "fixture DAK1 keyfile is exactly 68 bytes"

export_rc() {  # $1 = keyfile; echoes account-export's exit code
  set +e
  "$WALLET" account-export --in "$1" >/dev/null 2>&1
  local rc=$?
  set -e
  echo "$rc"
}

echo
echo "=== A. Truncation sweep: every strict prefix 0..67 rejects ==="
sweep_fail=0
for n in $(seq 0 67); do
  head -c "$n" "$TMP/acc.bin" > "$TMP/trunc.bin"
  RC=$(export_rc "$TMP/trunc.bin")
  if [ "$RC" != "1" ]; then
    echo "  FAIL: ${n}-byte prefix accepted (rc=$RC)"
    sweep_fail=$((sweep_fail + 1))
  fi
done
if [ "$sweep_fail" = "0" ]; then
  echo "  PASS: all 68 strict prefixes reject with rc=1"; pass_count=$((pass_count + 1))
else
  echo "  FAIL: $sweep_fail prefixes were accepted"; fail_count=$((fail_count + 1))
fi

echo
echo "=== B. Trailing bytes reject (69 and 70 bytes) ==="
cp "$TMP/acc.bin" "$TMP/long1.bin"; printf '\x00' >> "$TMP/long1.bin"
cp "$TMP/long1.bin" "$TMP/long2.bin"; printf '\xff' >> "$TMP/long2.bin"
assert_eq "$(export_rc "$TMP/long1.bin")" "1" "69-byte container rejects (exact-length, long direction)"
assert_eq "$(export_rc "$TMP/long2.bin")" "1" "70-byte container rejects"

echo
echo "=== C. LAST-byte tampers reject via derive-equality ==="
$PY -c "
d = bytearray(open('$TMP/acc.bin','rb').read())
d[35] ^= 0x01                       # pubkey[31]
open('$TMP/pub_last.bin','wb').write(bytes(d))"
$PY -c "
d = bytearray(open('$TMP/acc.bin','rb').read())
d[67] ^= 0x01                       # priv_seed[31]
open('$TMP/seed_last.bin','wb').write(bytes(d))"
assert_eq "$(export_rc "$TMP/pub_last.bin")" "1" "pubkey LAST-byte flip rejects (full-field derive check)"
assert_eq "$(export_rc "$TMP/seed_last.bin")" "1" "seed LAST-byte flip rejects (full-field derive check)"

echo
echo "=== D. Empty file rejects ==="
: > "$TMP/empty.bin"
assert_eq "$(export_rc "$TMP/empty.bin")" "1" "empty keyfile rejects"

echo
echo "=== E. HAPPY-PATH CONTROL: untampered container exports rc=0 ==="
set +e
OUT=$("$WALLET" account-export --in "$TMP/acc.bin" 2>&1 | tr -d '\r\n'); RC=$?
set -e
assert_eq "$RC" "0" "exit 0 on the untampered DAK1 (rejections are content-specific)"
assert_eq "$OUT" "$SEED" "raw-hex stdout view echoes the 64-hex seed"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet account-export DAK1 structural edge"; exit 0
else
    echo "  FAIL: test_wallet_account_export_hex_validity_edge"; exit 1
fi
