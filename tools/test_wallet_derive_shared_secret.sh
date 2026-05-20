#!/usr/bin/env bash
# determ-wallet derive-shared-secret CLI test.
#
# `derive-shared-secret` is an off-chain X25519 Diffie-Hellman key-agreement
# CLI. Two anon-address holders (each with an Ed25519 wallet keypair) each
# independently compute the same 32-byte shared secret from
#   * their own Ed25519 priv_seed (kept private), and
#   * the peer's Ed25519 pubkey (public, IS the peer's anon-address minus
#     "0x").
# The output is a KDF input for end-to-end encrypted off-chain messaging
# (HKDF + AEAD on top of the raw DH secret).
#
# Mechanism (libsodium):
#   1. crypto_sign_ed25519_seed_keypair(priv_seed) -> Ed25519 64-byte SK
#   2. crypto_sign_ed25519_sk_to_curve25519(SK)    -> X25519 SK (clamped)
#   3. crypto_sign_ed25519_pk_to_curve25519(PK)    -> X25519 PK (Montgomery)
#   4. crypto_scalarmult(my_x_sk, peer_x_pk)       -> 32-byte shared point
#
# Coverage (~16 assertions):
#   1. Help text mentions derive-shared-secret.
#   2. Setup: generate two distinct wallet accounts (k1, k2) via
#      account-create-batch and extract pubkeys.
#   3. Happy-path: k1 + pub2 emits one-line JSON with shared_secret_hex.
#   4. Output is parseable JSON.
#   5. shared_secret_hex is exactly 64 lowercase hex chars.
#   6. shared_secret_hex is non-zero (not the all-zero point — small-
#      subgroup attack indicator).
#   7. DH symmetry: derive(k1, pub2) == derive(k2, pub1).
#   8. Determinism: derive(k1, pub2) called twice yields the same bytes.
#   9. Distinctness: derive(k1, pub1) (DH-with-self) != derive(k1, pub2)
#      (DH-with-peer) — sanity check that the peer pubkey actually
#      participates in the computation.
#  10. Missing --priv-keyfile -> rc=1.
#  11. Missing --pubkey -> rc=1.
#  12. --priv-keyfile pointing at a non-existent path -> rc=1.
#  13. --priv-keyfile JSON missing 'privkey_hex' field -> rc=1.
#  14. --pubkey of length != 64 hex chars -> rc=1.
#  15. --pubkey non-hex (z's mixed in) -> rc=1.
#  16. Unknown argument -> rc=1.
#
# Run from repo root: bash tools/test_wallet_derive_shared_secret.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

# Scratch under build/ to dodge MSYS path translation quirks (Python under
# Windows subprocess.run can't see /tmp paths the way the bash layer does).
SCRATCH="build/test_wallet_derive_shared_secret.$$"
mkdir -p "$SCRATCH"
TMP="$SCRATCH"
trap 'rm -rf "$SCRATCH"' EXIT

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

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# ── 1. Help text mentions derive-shared-secret ───────────────────────────────
echo "=== 1. Help text mentions derive-shared-secret ==="
H=$("$WALLET" help 2>&1 | tr -d '\r')
if echo "$H" | grep -q "derive-shared-secret"; then
    echo "  PASS: help mentions derive-shared-secret"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: help missing derive-shared-secret"; fail_count=$((fail_count + 1))
fi

# ── 2. Setup: generate two distinct wallet accounts ───────────────────────────
echo
echo "=== 2. Setup: generate two distinct keyfiles via account-create-batch ==="
"$WALLET" account-create-batch --count 1 --out "$TMP/b1.json" >/dev/null 2>&1
RC1=$?
"$WALLET" account-create-batch --count 1 --out "$TMP/b2.json" >/dev/null 2>&1
RC2=$?
assert_eq "$RC1" "0" "account-create-batch (k1) succeeded"
assert_eq "$RC2" "0" "account-create-batch (k2) succeeded"

# Repackage each batch's single account as the single-account JSON shape
# {"address":"0x..","privkey_hex":".."} — same shape account-export
# consumes, which is what derive-shared-secret expects for --priv-keyfile.
$PY -c "
import json, sys
d = json.load(open(sys.argv[1]))
a = d['accounts'][0]
json.dump({'address': a['address'], 'privkey_hex': a['privkey_hex']},
          open(sys.argv[2], 'w'))
" "$TMP/b1.json" "$TMP/k1.json"
$PY -c "
import json, sys
d = json.load(open(sys.argv[1]))
a = d['accounts'][0]
json.dump({'address': a['address'], 'privkey_hex': a['privkey_hex']},
          open(sys.argv[2], 'w'))
" "$TMP/b2.json" "$TMP/k2.json"

ADDR1=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['address'])" "$TMP/k1.json")
ADDR2=$($PY -c "import json,sys; print(json.load(open(sys.argv[1]))['address'])" "$TMP/k2.json")
PUB1=${ADDR1#0x}
PUB2=${ADDR2#0x}
echo "  setup: ADDR1=$ADDR1"
echo "  setup: ADDR2=$ADDR2"
if [ "$PUB1" != "$PUB2" ]; then
    echo "  PASS: the two generated accounts have distinct pubkeys"
    pass_count=$((pass_count + 1))
else
    echo "  FAIL: generated accounts have identical pubkeys (CSPRNG collision?!)"
    fail_count=$((fail_count + 1))
fi

# ── 3. Happy-path: derive(k1, pub2) emits one-line JSON ───────────────────────
echo
echo "=== 3. Happy-path: derive(k1, pub2) emits one-line JSON ==="
OUT12=$("$WALLET" derive-shared-secret --priv-keyfile "$TMP/k1.json" --pubkey "$PUB2" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on happy-path derive"
# Must contain the shared_secret_hex field name.
assert_contains "$OUT12" "shared_secret_hex" "output contains shared_secret_hex field"

# ── 4. Output is parseable JSON ───────────────────────────────────────────────
echo
echo "=== 4. Output is parseable JSON ==="
PARSED=$(echo "$OUT12" | $PY -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print('YES' if 'shared_secret_hex' in d else 'NO_FIELD')
except Exception as e:
    print('PARSE_FAIL:', e)
")
assert_eq "$PARSED" "YES" "stdout parses as JSON with shared_secret_hex"

# Extract the hex for downstream checks.
S12=$(echo "$OUT12" | $PY -c "import json,sys; print(json.load(sys.stdin)['shared_secret_hex'])")

# ── 5. shared_secret_hex is exactly 64 lowercase hex chars ────────────────────
echo
echo "=== 5. shared_secret_hex is 64 lowercase hex chars ==="
S12_LEN=${#S12}
assert_eq "$S12_LEN" "64" "shared_secret_hex length == 64 (32 bytes)"
# Lowercase-hex shape regex.
SHAPE=$(echo "$S12" | $PY -c "
import re, sys
v = sys.stdin.read().strip()
print('YES' if re.match(r'^[0-9a-f]{64}\$', v) else 'NO')
")
assert_eq "$SHAPE" "YES" "shared_secret_hex matches /^[0-9a-f]{64}\$/"

# ── 6. shared_secret_hex is non-zero ──────────────────────────────────────────
echo
echo "=== 6. shared_secret_hex is non-zero ==="
ZERO="0000000000000000000000000000000000000000000000000000000000000000"
if [ "$S12" = "$ZERO" ]; then
    echo "  FAIL: shared_secret_hex is all-zero (small-subgroup attack indicator)"
    fail_count=$((fail_count + 1))
else
    echo "  PASS: shared_secret_hex is non-zero"
    pass_count=$((pass_count + 1))
fi

# ── 7. DH symmetry: derive(k1, pub2) == derive(k2, pub1) ──────────────────────
echo
echo "=== 7. DH symmetry: derive(k1, pub2) == derive(k2, pub1) ==="
OUT21=$("$WALLET" derive-shared-secret --priv-keyfile "$TMP/k2.json" --pubkey "$PUB1" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on inverse derive"
S21=$(echo "$OUT21" | $PY -c "import json,sys; print(json.load(sys.stdin)['shared_secret_hex'])")
assert_eq "$S12" "$S21" "derive(k1, pub2) == derive(k2, pub1) (DH symmetry)"

# ── 8. Determinism: repeated calls yield the same bytes ───────────────────────
echo
echo "=== 8. Determinism: derive(k1, pub2) called twice -> same bytes ==="
OUT12_AGAIN=$("$WALLET" derive-shared-secret --priv-keyfile "$TMP/k1.json" --pubkey "$PUB2" 2>&1 | tr -d '\r')
S12_AGAIN=$(echo "$OUT12_AGAIN" | $PY -c "import json,sys; print(json.load(sys.stdin)['shared_secret_hex'])")
assert_eq "$S12_AGAIN" "$S12" "two derive(k1, pub2) calls produce byte-identical output"

# ── 9. Distinctness: derive(k1, pub1) != derive(k1, pub2) ─────────────────────
# This is the sanity check that the peer pubkey actually enters the
# computation. derive(k1, pub1) is the DH of k1's own seed with its own
# pubkey — a valid but distinct operation; it MUST NOT equal the cross-DH
# value (would indicate the peer pubkey is being ignored).
echo
echo "=== 9. Distinctness: derive(k1, pub1) != derive(k1, pub2) ==="
OUT11=$("$WALLET" derive-shared-secret --priv-keyfile "$TMP/k1.json" --pubkey "$PUB1" 2>&1 | tr -d '\r')
RC=$?
assert_eq "$RC" "0" "exit 0 on derive(k1, pub1) (DH-with-self)"
S11=$(echo "$OUT11" | $PY -c "import json,sys; print(json.load(sys.stdin)['shared_secret_hex'])")
if [ "$S11" != "$S12" ]; then
    echo "  PASS: derive(k1, pub1) != derive(k1, pub2) — peer pubkey participates"
    pass_count=$((pass_count + 1))
else
    echo "  FAIL: derive(k1, pub1) == derive(k1, pub2) — peer pubkey is being ignored?!"
    fail_count=$((fail_count + 1))
fi

# ── 10. Missing --priv-keyfile fails ──────────────────────────────────────────
echo
echo "=== 10. Missing --priv-keyfile fails ==="
set +e
ERR=$("$WALLET" derive-shared-secret --pubkey "$PUB2" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing --priv-keyfile"
assert_contains "$ERR" "priv-keyfile" "diagnostic mentions --priv-keyfile"

# ── 11. Missing --pubkey fails ────────────────────────────────────────────────
echo
echo "=== 11. Missing --pubkey fails ==="
set +e
ERR=$("$WALLET" derive-shared-secret --priv-keyfile "$TMP/k1.json" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on missing --pubkey"
assert_contains "$ERR" "pubkey" "diagnostic mentions --pubkey"

# ── 12. --priv-keyfile non-existent path fails ────────────────────────────────
echo
echo "=== 12. --priv-keyfile pointing at non-existent path fails ==="
set +e
ERR=$("$WALLET" derive-shared-secret --priv-keyfile "$TMP/does_not_exist.json" --pubkey "$PUB2" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on non-existent --priv-keyfile"
assert_contains "$ERR" "open" "diagnostic mentions cannot open"

# ── 13. --priv-keyfile JSON missing 'privkey_hex' field fails ─────────────────
echo
echo "=== 13. --priv-keyfile JSON missing 'privkey_hex' field fails ==="
$PY -c "
import json, sys
json.dump({'address': '$ADDR1'}, open(sys.argv[1], 'w'))
" "$TMP/no_priv.json"
set +e
ERR=$("$WALLET" derive-shared-secret --priv-keyfile "$TMP/no_priv.json" --pubkey "$PUB2" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 when 'privkey_hex' missing"
assert_contains "$ERR" "privkey_hex" "diagnostic mentions privkey_hex"

# ── 14. --pubkey wrong length fails ───────────────────────────────────────────
echo
echo "=== 14. --pubkey wrong length (63 chars) fails ==="
SHORT=$(echo "$PUB2" | cut -c1-63)
set +e
ERR=$("$WALLET" derive-shared-secret --priv-keyfile "$TMP/k1.json" --pubkey "$SHORT" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on 63-char --pubkey"
assert_contains "$ERR" "64 hex" "diagnostic mentions 64 hex"

# ── 15. --pubkey non-hex fails ────────────────────────────────────────────────
echo
echo "=== 15. --pubkey non-hex (z's mixed in) fails ==="
BAD="zz97395ae1f0413984f48ef3feaf38616fa991196ee8d245ce11b71c01b2c1df"
set +e
ERR=$("$WALLET" derive-shared-secret --priv-keyfile "$TMP/k1.json" --pubkey "$BAD" 2>&1)
RC=$?
set -e
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "1" "exit 1 on non-hex --pubkey"
assert_contains "$ERR" "hex" "diagnostic mentions hex"

# ── 16. Unknown argument fails ────────────────────────────────────────────────
echo
echo "=== 16. Unknown argument fails ==="
set +e
"$WALLET" derive-shared-secret --priv-keyfile "$TMP/k1.json" --pubkey "$PUB2" --bogus >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "exit 1 on unknown argument"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet derive-shared-secret"
    exit 0
else
    echo "  FAIL"
    exit 1
fi
