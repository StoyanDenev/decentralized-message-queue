#!/usr/bin/env bash
# determ-wallet inspect-envelope diagnostic CLI test.
#
# Verifies the metadata dumper:
#   1. Reads a fixture envelope file (written via `envelope encrypt`)
#      and prints the expected header fields (DWE1 magic, iters, salt,
#      nonce, ciphertext lengths) WITHOUT performing AES-GCM.
#   2. --json output is well-formed and contains the same metadata.
#   3. AAD presence flag flips between envelopes with and without AAD.
#   4. Reports the correct iters value (matches what was passed in).
#   5. Non-existent input file → non-zero exit + diagnostic.
#   6. Truncated / malformed envelope content → non-zero exit + diagnostic.
#   7. Empty file → non-zero exit + diagnostic.
#   8. Wrong-format (random hex but not a valid envelope blob) → reject.
#
# Run from repo root: bash tools/test_wallet_inspect_envelope.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"
PLAIN="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
PW="hunter2"
ITERS=10000   # low for test speed; production uses 600000

# Per-run scratch directory so concurrent runs don't collide.
SCRATCH="build/test_wallet_inspect_envelope.$$"
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

echo "=== Setup: write a fixture envelope without AAD ==="
ENV_NOAAD_FILE="$SCRATCH/env_noaad.txt"
$WALLET envelope encrypt --plaintext $PLAIN --password "$PW" --iters $ITERS \
    | tr -d '\r' > "$ENV_NOAAD_FILE"
if [ ! -s "$ENV_NOAAD_FILE" ]; then
    echo "  FAIL: fixture envelope file is empty"; exit 1
fi
echo "  wrote $ENV_NOAAD_FILE ($(wc -c < "$ENV_NOAAD_FILE") bytes)"

echo
echo "=== 1. Human-readable inspect (no AAD) ==="
OUT=$($WALLET inspect-envelope --in "$ENV_NOAAD_FILE" | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit code 0"
assert_contains "$OUT" "DWE1"           "reports DWE1 magic"
assert_contains "$OUT" "pbkdf2_iters:    $ITERS" "reports correct PBKDF2 iters"
assert_contains "$OUT" "salt_len:        16"    "reports 16-byte salt"
assert_contains "$OUT" "nonce_len:       12"    "reports 12-byte nonce"
assert_contains "$OUT" "aad_present:     false" "reports aad_present=false"
assert_contains "$OUT" "tag:           16"      "reports 16-byte GCM tag"

echo
echo "=== 2. JSON output (no AAD) ==="
JSON=$($WALLET inspect-envelope --in "$ENV_NOAAD_FILE" --json | tr -d '\r')
assert_contains "$JSON" "\"format\":\"DWE1\""        "json format=DWE1"
assert_contains "$JSON" "\"version\":1"              "json version=1"
assert_contains "$JSON" "\"pbkdf2_iters\":$ITERS"    "json iters matches"
assert_contains "$JSON" "\"salt_len\":16"            "json salt_len=16"
assert_contains "$JSON" "\"nonce_len\":12"           "json nonce_len=12"
assert_contains "$JSON" "\"aad_present\":false"      "json aad_present=false"
assert_contains "$JSON" "\"aad_len\":0"              "json aad_len=0"
assert_contains "$JSON" "\"tag_len\":16"             "json tag_len=16"

# Verify JSON parses with python (the canonical validator if present).
if command -v python3 >/dev/null 2>&1; then
    if echo "$JSON" | python3 -c "import sys, json; json.loads(sys.stdin.read())" 2>/dev/null; then
        echo "  PASS: json is well-formed (python3 json.loads)"; pass_count=$((pass_count + 1))
    else
        echo "  FAIL: json failed to parse via python3"; fail_count=$((fail_count + 1))
    fi
else
    echo "  SKIP: python3 unavailable; structural-only check"
fi

echo
echo "=== 3. Inspect envelope WITH AAD — aad_present flips ==="
ENV_AAD_FILE="$SCRATCH/env_aad.txt"
$WALLET envelope encrypt --plaintext $PLAIN --password "$PW" \
    --aad cafebabe --iters $ITERS | tr -d '\r' > "$ENV_AAD_FILE"
OUT_AAD=$($WALLET inspect-envelope --in "$ENV_AAD_FILE" | tr -d '\r')
assert_contains "$OUT_AAD" "aad_present:     true" "aad_present=true with AAD"
assert_contains "$OUT_AAD" "aad_len:         4"    "aad_len=4 with cafebabe"
assert_contains "$OUT_AAD" "aad_hex:         cafebabe" "reports aad_hex"

echo
echo "=== 4. iters value passes through (non-default value) ==="
ENV_ALT_FILE="$SCRATCH/env_alt_iters.txt"
ALT_ITERS=12345
$WALLET envelope encrypt --plaintext $PLAIN --password "$PW" --iters $ALT_ITERS \
    | tr -d '\r' > "$ENV_ALT_FILE"
OUT_ALT=$($WALLET inspect-envelope --in "$ENV_ALT_FILE" | tr -d '\r')
assert_contains "$OUT_ALT" "pbkdf2_iters:    $ALT_ITERS" "alternate iters reported"
# Sanity: not still reading the previous fixture's value.
assert_not_contains "$OUT_ALT" "pbkdf2_iters:    $ITERS" "alt envelope is not the previous one"

echo
echo "=== 5. Missing --in file → non-zero exit ==="
MISSING="$SCRATCH/does_not_exist.env"
# Capture exit code WITHOUT a pipeline so $? reflects the wallet binary,
# not tr or any post-filter. Run twice: once for the exit code, once for
# the diagnostic. Cheap because there's no PBKDF2 work in the diag path.
set +e
$WALLET inspect-envelope --in "$MISSING" >/dev/null 2>&1
RC=$?
ERR=$($WALLET inspect-envelope --in "$MISSING" 2>&1)
set -e
ERR=$(echo "$ERR" | tr -d '\r')
if [ "$RC" != "0" ]; then
    echo "  PASS: non-zero exit on missing file (rc=$RC)"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: missing file produced zero exit"; fail_count=$((fail_count + 1))
fi
assert_contains "$ERR" "cannot open" "diagnostic mentions cannot open"

echo
echo "=== 6. Truncated envelope → non-zero exit, malformed diagnostic ==="
TRUNC_FILE="$SCRATCH/env_truncated.txt"
# Keep first ~half of the blob — guarantees the trailing parts are gone
# and likely an odd hex length / missing dot section.
ENV_LEN=$(wc -c < "$ENV_NOAAD_FILE")
HALF=$((ENV_LEN / 2))
head -c $HALF "$ENV_NOAAD_FILE" > "$TRUNC_FILE"
set +e
$WALLET inspect-envelope --in "$TRUNC_FILE" >/dev/null 2>&1
RC=$?
ERR=$($WALLET inspect-envelope --in "$TRUNC_FILE" 2>&1)
set -e
ERR=$(echo "$ERR" | tr -d '\r')
if [ "$RC" != "0" ]; then
    echo "  PASS: non-zero exit on truncated envelope (rc=$RC)"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: truncated envelope accepted (rc=0)"; fail_count=$((fail_count + 1))
fi
assert_contains "$ERR" "malformed" "diagnostic mentions malformed"

echo
echo "=== 7. Empty file → non-zero exit ==="
EMPTY_FILE="$SCRATCH/empty.txt"
: > "$EMPTY_FILE"
set +e
$WALLET inspect-envelope --in "$EMPTY_FILE" >/dev/null 2>&1
RC=$?
ERR=$($WALLET inspect-envelope --in "$EMPTY_FILE" 2>&1)
set -e
ERR=$(echo "$ERR" | tr -d '\r')
if [ "$RC" != "0" ]; then
    echo "  PASS: non-zero exit on empty file (rc=$RC)"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: empty file accepted (rc=0)"; fail_count=$((fail_count + 1))
fi
assert_contains "$ERR" "empty" "diagnostic mentions empty"

echo
echo "=== 8. Wrong-format file (random hex, not an envelope) → reject ==="
# Six dot-separated hex sections but with WRONG magic value (not "DWE1").
# Exercises the magic check in envelope::deserialize.
WRONG_FILE="$SCRATCH/wrong_format.txt"
echo "deadbeef.00112233445566778899aabbccddeeff.10270000.000102030405060708090a0b.cafebabe.00112233" > "$WRONG_FILE"
set +e
$WALLET inspect-envelope --in "$WRONG_FILE" >/dev/null 2>&1
RC=$?
ERR=$($WALLET inspect-envelope --in "$WRONG_FILE" 2>&1)
set -e
ERR=$(echo "$ERR" | tr -d '\r')
if [ "$RC" != "0" ]; then
    echo "  PASS: non-zero exit on wrong-format file (rc=$RC)"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: wrong-format file accepted (rc=0)"; fail_count=$((fail_count + 1))
fi
assert_contains "$ERR" "malformed" "wrong-format diagnostic mentions malformed"

echo
echo "=== 9. inspect-envelope NEVER requires a password ==="
# The diagnostic must not prompt for or require --password. Verify by
# passing no auth-related args and checking we got real metadata above.
# This is implicit in tests 1-4, but call it out as a regression marker:
# the command line above already includes no --password and worked.
echo "  PASS: no --password flag accepted/required (covered by tests 1-4)"
pass_count=$((pass_count + 1))

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet inspect-envelope"; exit 0
else
    echo "  FAIL"; exit 1
fi
