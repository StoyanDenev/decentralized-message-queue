#!/usr/bin/env bash
# determ-wallet OFFLINE subcommand surface — daemon-free regression.
#
# Pure offline test (no cluster, no daemon, no RPC). Exercises the
# determ-wallet subcommands an operator can run air-gapped against
# locally-built fixtures — the secret-handling + signed-envelope surface
# that never needs a running node:
#
#   help / version            structured usage / banner, exit 0
#   account-create-batch      fresh Ed25519 keypair batch → anon-address
#                             (the keypair source every other group reuses)
#   account-derive-batch      DETERMINISTIC sibling: same --seed always
#                             produces the same accounts; different seeds
#                             produce disjoint sets; usage error fails closed
#   keyfile-create            passphrase-encrypted DETERM-NODE-V1 keyfile
#   keyfile-info              passive metadata dump (no passphrase); a
#                             tampered header magic fails closed (exit 2)
#   inspect-envelope          DWE1 envelope metadata; a malformed blob
#                             fails closed (exit 2), missing --in usage (1)
#   tx-sign-verify            chain-canonical Ed25519 sig verify; a tampered
#                             amount fails closed (exit 2), missing flags (1)
#   validate-tx               offline structural + sig + tx_hash battery on
#                             a sign-anon-tx envelope (overall_valid); a
#                             tampered body fails closed (exit 2)
#   derive-tx-hash            recompute tx_hash = SHA-256(signing_bytes);
#                             --check on a tampered hash fails closed (exit 2)
#
# All fixtures are built inline the way tools/test_wallet_keyfile_info.sh
# and tools/test_wallet_tx_sign_verify.sh do — keypairs are minted via the
# wallet's own account-create-batch (the keyfile/validate loaders reject an
# address that doesn't match its Ed25519 pubkey per S-028, so the pairs must
# be genuine), and the tx envelopes are produced by sign-anon-tx. No cluster
# bring-up; no network.
#
# SKIP-with-PASS (exit 0) when determ-wallet is absent, so this script is a
# no-op pass in minimal build environments, never a hard failure. Sibling of
# tools/test_determ_light_offline_surface.sh.
#
# Run from repo root: bash tools/test_determ_wallet_offline_surface.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

# Per-run scratch dir under build/ — same Windows-friendly pattern other
# wallet tests use (avoids MSYS /tmp path opaqueness for the native exe).
TMP="build/test_determ_wallet_offline_surface.$$"
mkdir -p "$TMP"
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

PY=python
command -v python >/dev/null 2>&1 || PY=python3

echo "=== 1. help → structured usage, exit 0 ==="
set +e
OUT=$("$WALLET" help 2>&1 | tr -d '\r'); RC=$?
set -e
assert_eq "$RC" "0" "help exits 0"
assert_contains "$OUT" "Usage: determ-wallet" "help prints usage banner"

echo
echo "=== 2. version → exit 0, prints determ-wallet banner ==="
set +e
OUT=$("$WALLET" version 2>&1 | tr -d '\r'); RC=$?
set -e
assert_eq "$RC" "0" "version exits 0"
assert_contains "$OUT" "determ-wallet" "version prints determ-wallet banner"

echo
echo "=== 3. account-create-batch → fresh keypair batch ==="
set +e
"$WALLET" account-create-batch --count 2 --out "$TMP/keys.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "account-create-batch exits 0"
SHAPE=$($PY -c "
import json
try:
    d = json.load(open('$TMP/keys.json'))
    accts = d['accounts']
    ok = (len(accts) == 2
          and all(a['address'].startswith('0x') and len(a['address']) == 66 for a in accts)
          and all(len(a['privkey_hex']) == 64 for a in accts)
          and accts[0]['address'] != accts[1]['address'])
    print('true' if ok else 'false')
except Exception:
    print('false')
")
assert_eq "$SHAPE" "true" "account-create-batch shape (2 distinct 0x+64hex addrs, 64-hex privkeys)"

ADDR_A=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][0]['address'])")
ADDR_B=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][1]['address'])")
PRIV_A=$($PY -c "import json; print(json.load(open('$TMP/keys.json'))['accounts'][0]['privkey_hex'])")
PUB_A="${ADDR_A#0x}"
# Single-account JSON for the signer commands (sign-anon-tx / validate-tx).
$PY -c "import json; d=json.load(open('$TMP/keys.json')); json.dump(d['accounts'][0], open('$TMP/key_a.json','w'))"

echo
echo "=== 4. account-create-batch --count 0 → usage error, exit 1 ==="
set +e
"$WALLET" account-create-batch --count 0 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "account-create-batch --count 0 fails closed (exit 1)"

echo
echo "=== 5. account-derive-batch → deterministic from a master seed ==="
SEED=$($PY -c "print('11' * 32)")
set +e
"$WALLET" account-derive-batch --seed "$SEED" --count 3 --out "$TMP/derive1.json" >/dev/null 2>&1
RC=$?
"$WALLET" account-derive-batch --seed "$SEED" --count 3 --out "$TMP/derive2.json" --force >/dev/null 2>&1
RC2=$?
set -e
assert_eq "$RC"  "0" "account-derive-batch run 1 exits 0"
assert_eq "$RC2" "0" "account-derive-batch run 2 exits 0"
DSHAPE=$($PY -c "
import json
try:
    d = json.load(open('$TMP/derive1.json'))
    accts = d['accounts']
    ok = ('master_seed_hash_hex' in d
          and len(d['master_seed_hash_hex']) == 64
          and d['count'] == 3
          and len(accts) == 3
          and [a['index'] for a in accts] == [0, 1, 2]
          and all(a['address'].startswith('0x') for a in accts))
    print('true' if ok else 'false')
except Exception:
    print('false')
")
assert_eq "$DSHAPE" "true" "account-derive-batch shape (master_seed_hash_hex + indexed accounts)"
DETERMINISTIC=$($PY -c "
import json
a = json.load(open('$TMP/derive1.json'))['accounts']
b = json.load(open('$TMP/derive2.json'))['accounts']
print('true' if a == b else 'false')
")
assert_eq "$DETERMINISTIC" "true" "same --seed reproduces identical accounts"

echo
echo "=== 6. account-derive-batch: different seed → disjoint set ==="
SEED2=$($PY -c "print('22' * 32)")
set +e
"$WALLET" account-derive-batch --seed "$SEED2" --count 3 --out "$TMP/derive3.json" >/dev/null 2>&1
set -e
DISJOINT=$($PY -c "
import json
a = {x['address'] for x in json.load(open('$TMP/derive1.json'))['accounts']}
c = {x['address'] for x in json.load(open('$TMP/derive3.json'))['accounts']}
print('true' if a.isdisjoint(c) else 'false')
")
assert_eq "$DISJOINT" "true" "different seed produces a disjoint account set"

echo
echo "=== 7. account-derive-batch: missing --seed → usage error, exit 1 ==="
set +e
"$WALLET" account-derive-batch --count 3 >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "account-derive-batch missing --seed fails closed (exit 1)"

echo
echo "=== 8. keyfile-create → passphrase-encrypted DETERM-NODE-V1 keyfile ==="
PASS_FILE="$TMP/passphrase.txt"
printf '%s\n' "correct horse battery staple" > "$PASS_FILE"
KEYFILE="$TMP/node_key.enc"
set +e
"$WALLET" keyfile-create --priv "$PRIV_A" --passphrase-from "file:$PASS_FILE" \
    --out "$KEYFILE" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "keyfile-create exits 0"
if [ -s "$KEYFILE" ]; then
    echo "  PASS: keyfile-create wrote a non-empty keyfile"; pass_count=$((pass_count + 1))
else
    echo "  FAIL: keyfile-create produced an empty keyfile"; fail_count=$((fail_count + 1))
fi

echo
echo "=== 9. keyfile-info → passive metadata (no passphrase) ==="
set +e
OUT=$("$WALLET" keyfile-info --in "$KEYFILE" 2>&1 | tr -d '\r'); RC=$?
set -e
assert_eq "$RC" "0" "keyfile-info exits 0"
assert_contains "$OUT" "DETERM-NODE-V1" "keyfile-info reports header_version"
assert_contains "$OUT" "pubkey_hex:        $PUB_A" "keyfile-info reports the baked-in pubkey"

echo
echo "=== 10. keyfile-info: tampered header magic → fail closed, exit 2 ==="
TAMPER_KEYFILE="$TMP/node_key_tampered.enc"
sed 's/^DETERM-NODE-V1/DETERM-NODE-V9/' "$KEYFILE" > "$TAMPER_KEYFILE"
set +e
"$WALLET" keyfile-info --in "$TAMPER_KEYFILE" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "keyfile-info tampered header magic fails closed (exit 2)"

echo
echo "=== 11. keyfile-info: missing --in → usage error, exit 1 ==="
set +e
"$WALLET" keyfile-info >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "keyfile-info missing --in fails closed (exit 1)"

echo
echo "=== 12. inspect-envelope → DWE1 metadata ==="
ENV_FILE="$TMP/env.txt"
"$WALLET" envelope encrypt --plaintext deadbeef --password "pw" --iters 1000 \
    2>/dev/null | tr -d '\r' > "$ENV_FILE"
if [ ! -s "$ENV_FILE" ]; then
    echo "  FAIL: inspect-envelope fixture is empty"; fail_count=$((fail_count + 1))
else
    echo "  PASS: inspect-envelope fixture written"; pass_count=$((pass_count + 1))
fi
set +e
OUT=$("$WALLET" inspect-envelope --in "$ENV_FILE" 2>&1 | tr -d '\r'); RC=$?
set -e
assert_eq "$RC" "0" "inspect-envelope exits 0"
assert_contains "$OUT" "DWE1" "inspect-envelope reports the DWE1 format"

echo
echo "=== 13. inspect-envelope: malformed blob → fail closed, exit 2 ==="
echo "not-a-real-envelope-blob" > "$TMP/env_bad.txt"
set +e
"$WALLET" inspect-envelope --in "$TMP/env_bad.txt" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "inspect-envelope malformed blob fails closed (exit 2)"

echo
echo "=== 14. inspect-envelope: missing --in → usage error, exit 1 ==="
set +e
"$WALLET" inspect-envelope >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "inspect-envelope missing --in fails closed (exit 1)"

echo
echo "=== 15. tx-sign-verify → chain-canonical Ed25519 verify ==="
# Build a synthetic signed tx with an independent Ed25519 signer (Python's
# cryptography lib) over the chain's signing_bytes — same scheme as
# tools/test_wallet_tx_sign_verify.sh.
$PY - "$TMP/tx1.json" "$ADDR_A" "$ADDR_B" "$PRIV_A" <<'PY_EOF'
import hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
out_path, sender, recipient, priv_hex = sys.argv[1:]
amount, fee, nonce = 1000, 5, 1
payload = bytes.fromhex("deadbeef")
sb  = bytes([0])                                   # TxType TRANSFER
sb += sender.encode("utf-8")    + b"\x00"
sb += recipient.encode("utf-8") + b"\x00"
sb += struct.pack(">Q", amount)
sb += struct.pack(">Q", fee)
sb += struct.pack(">Q", nonce)
sb += payload
priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
sig  = priv.sign(sb)
doc = {"type": 0, "from": sender, "to": recipient, "amount": amount,
       "fee": fee, "nonce": nonce, "payload": payload.hex(),
       "sig": sig.hex(), "hash": hashlib.sha256(sb).hexdigest()}
json.dump(doc, open(out_path, "w"))
PY_EOF
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx1.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "tx-sign-verify valid sig exits 0"

echo
echo "=== 16. tx-sign-verify: tampered amount → fail closed, exit 2 ==="
$PY -c "
import json
d = json.load(open('$TMP/tx1.json'))
d['amount'] = d['amount'] + 1   # sig no longer binds the body
json.dump(d, open('$TMP/tx1_tampered.json', 'w'))
"
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx1_tampered.json" --pubkey "$PUB_A" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "tx-sign-verify tampered amount fails closed (exit 2)"

echo
echo "=== 17. tx-sign-verify: missing --pubkey → usage error, exit 1 ==="
set +e
"$WALLET" tx-sign-verify --tx "$TMP/tx1.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "tx-sign-verify missing --pubkey fails closed (exit 1)"

echo
echo "=== 18. validate-tx → offline structural + sig + tx_hash battery ==="
# sign-anon-tx produces an envelope whose `from` is the anon-address, so
# validate-tx can derive the verify pubkey without an operator anchor.
"$WALLET" sign-anon-tx --keyfile "$TMP/key_a.json" --to "$ADDR_B" \
    --amount 1000 --fee 5 --nonce 1 --out "$TMP/signed.json" >/dev/null 2>&1
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed.json" --json > "$TMP/validate_out.json" 2>&1
RC=$?
set -e
assert_eq "$RC" "0" "validate-tx happy path exits 0"
OVERALL=$($PY -c "import json; print(json.load(open('$TMP/validate_out.json'))['overall_valid'])")
assert_eq "$OVERALL" "True" "validate-tx overall_valid is True on a clean envelope"

echo
echo "=== 19. validate-tx: tampered body → fail closed, exit 2 ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
d['amount'] = d['amount'] + 1   # body diverges from sig + stored hash
json.dump(d, open('$TMP/signed_tampered.json', 'w'))
"
set +e
"$WALLET" validate-tx --tx-json "$TMP/signed_tampered.json" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "validate-tx tampered body fails closed (exit 2)"

echo
echo "=== 20. validate-tx: missing --tx-json → usage error, exit 1 ==="
set +e
"$WALLET" validate-tx >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "validate-tx missing --tx-json fails closed (exit 1)"

echo
echo "=== 21. derive-tx-hash → recompute matches the envelope's stored hash ==="
STORED_HASH=$($PY -c "import json; print(json.load(open('$TMP/signed.json'))['hash'])")
set +e
RECOMPUTED=$("$WALLET" derive-tx-hash --tx-json "$TMP/signed.json" 2>&1 | tr -d '\r\n')
RC=$?
set -e
assert_eq "$RC" "0" "derive-tx-hash exits 0"
assert_eq "${#RECOMPUTED}" "64" "derive-tx-hash output is 64 hex chars"
assert_eq "$RECOMPUTED" "$STORED_HASH" "derive-tx-hash matches the envelope's stored hash"

echo
echo "=== 22. derive-tx-hash --check on a tampered hash → fail closed, exit 2 ==="
$PY -c "
import json
d = json.load(open('$TMP/signed.json'))
h = d['hash']
d['hash'] = ('0' if h[0] != '0' else 'a') + h[1:]   # corrupt the stored hash
json.dump(d, open('$TMP/signed_badhash.json', 'w'))
"
set +e
"$WALLET" derive-tx-hash --tx-json "$TMP/signed_badhash.json" --check >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "2" "derive-tx-hash --check mismatch fails closed (exit 2)"

echo
echo "=== 23. derive-tx-hash: missing --tx-json → usage error, exit 1 ==="
set +e
"$WALLET" derive-tx-hash >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "derive-tx-hash missing --tx-json fails closed (exit 1)"

echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet offline surface"
    exit 0
else
    echo
    echo "  FAIL: determ-wallet offline surface"
    exit 1
fi