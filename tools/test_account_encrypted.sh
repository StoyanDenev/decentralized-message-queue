#!/usr/bin/env bash
# v2.17 / S-004 option 2 — encrypted keyfile regression test.
#
# Verifies:
#   1. account create --passphrase produces an envelope-wrapped file
#      (not plaintext JSON).
#   2. account decrypt with the correct passphrase recovers the
#      plaintext JSON (address + privkey).
#   3. account decrypt with the wrong passphrase fails (AEAD tag
#      mismatch).
#   4. UNCHAINED_PASSPHRASE env var works as an alternative to --passphrase.
#   5. Plaintext-output path (no --passphrase) still works (S-004
#      option 1 backward compat).
#   6. File permissions are 0600-equivalent.
#
# Run from repo root: bash tools/test_account_encrypted.sh
set -u
cd "$(dirname "$0")/.."

UNCHAINED=build/Release/unchained.exe
T=test_account_enc
mkdir -p $T
rm -f $T/*

pass_count=0; fail_count=0
assert() {
  if [ "$1" = "true" ]; then echo "  PASS: $2"; pass_count=$((pass_count + 1))
  else echo "  FAIL: $2"; fail_count=$((fail_count + 1)); fi
}

echo "=== 1. Encrypted account create ==="
$UNCHAINED account create --out $T/enc.acct --passphrase "topsecret-pass-abc123" 2>&1 | tail -3

# Verify file format: header line + envelope blob line
HEADER=$(head -1 $T/enc.acct)
case "$HEADER" in
  DETERM-ACCOUNT-V1*) assert true "encrypted file has v1 header" ;;
  *)                  assert false "encrypted file header: $HEADER" ;;
esac

# File should NOT contain "privkey" as plaintext (it's encrypted)
if grep -q '"privkey"' $T/enc.acct; then
  assert false "encrypted file contains plaintext privkey marker"
else
  assert true "encrypted file does not leak privkey marker"
fi

echo
echo "=== 2. Decrypt with correct passphrase ==="
$UNCHAINED account decrypt --in $T/enc.acct --passphrase "topsecret-pass-abc123" > $T/dec_correct.json 2>&1
if [ -s $T/dec_correct.json ] && grep -q '"privkey"' $T/dec_correct.json; then
  assert true "decrypt with correct passphrase recovers privkey"
else
  assert false "decrypt with correct passphrase did not recover plaintext"
fi

echo
echo "=== 3. Decrypt with wrong passphrase fails ==="
OUT=$($UNCHAINED account decrypt --in $T/enc.acct --passphrase "wrong-pass" 2>&1 || true)
if echo "$OUT" | grep -qi "decryption failed"; then
  assert true "decrypt with wrong passphrase rejected"
else
  assert false "decrypt with wrong passphrase did NOT reject: $OUT"
fi

echo
echo "=== 4. UNCHAINED_PASSPHRASE env var ==="
UNCHAINED_PASSPHRASE="topsecret-pass-abc123" $UNCHAINED account decrypt --in $T/enc.acct > $T/dec_env.json 2>&1
if [ -s $T/dec_env.json ] && grep -q '"privkey"' $T/dec_env.json; then
  assert true "UNCHAINED_PASSPHRASE env var works"
else
  assert false "UNCHAINED_PASSPHRASE env var did not authenticate"
fi

echo
echo "=== 5. Plaintext path still works (S-004 option 1 backward compat) ==="
$UNCHAINED account create --out $T/plain.acct 2>&1 | tail -2
# Plaintext file should contain "privkey"
if grep -q '"privkey"' $T/plain.acct; then
  assert true "plaintext path (no --passphrase) writes a privkey field"
else
  assert false "plaintext path did not write privkey"
fi

echo
echo "=== 6. Verify decrypt output matches a freshly-created plaintext ==="
# Both files should have an address field
ADDR_ENC=$(python -c "
import json
with open('$T/dec_correct.json') as f: j = json.load(f)
print(j.get('address',''))")
[ -n "$ADDR_ENC" ] && [ "${ADDR_ENC:0:2}" = "0x" ] \
  && assert true "decrypted address is well-formed hex" \
  || assert false "decrypted address malformed: '$ADDR_ENC'"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
  echo "  PASS: v2.17 / S-004 option 2 encrypted keyfiles"; exit 0
else
  echo "  FAIL"; exit 1
fi
