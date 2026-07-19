#!/usr/bin/env bash
# NC-8 §5a CLIENT→CONSENSUS loop, CROSS-BINARY: `determ-light register-note-key`
# builds a canonical, submittable REGISTER_NOTE_KEY (TxType 17, account-Ed25519-
# signed, fee-only), and `determ verify-audit-tx` applies the validator's
# anon-account accept-check (anon-sig + shape gate) to that exact JSON — the
# same rule the block validator runs (src/node/validator.cpp anon whitelist +
# the REGISTER_NOTE_KEY shape gate). A tx this pair accepts is one a validator
# accepts, so this is the provable client→consensus loop for the note_pk
# publication. Pure offline; no daemon. Sibling of test_light_audit_tx.sh.
#
# This is the determ-light BUILDER that the inc.5a review flagged as missing;
# it lets the verify-notekey path be driven to a live INCLUDED end-to-end
# (build here → submit-tx → verify-notekey).
#
# Assertions:
#   1. register-note-key --note-pk writes a submittable REGISTER_NOTE_KEY (exit 0).
#   2. verify-audit-tx VERIFIES it (exit 0) — the consensus check accepts.
#   3. register-note-key --clear (revoke, empty payload) also verifies.
#   4. tampering the fee -> verify-audit-tx INVALID (exit 3) (sig binds the fee).
#   5. --note-pk and --clear together -> refused by register-note-key (exit 1).
#   6. a 32-byte note-pk (wrong length) -> build error (exit 1).
#   7. a non-note-key tx (TRANSFER) -> verify-audit-tx INVALID (exit 3).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
    echo "  SKIP: determ-light binary not found"; exit 0; fi
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found (needed to mint a keyfile)"; exit 0; fi
if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found (needed for verify-audit-tx)"; exit 0; fi

TMP="build/test_light_register_note_key.$$"; mkdir -p "$TMP"; trap 'rm -rf "$TMP"' EXIT
PY=python; command -v python >/dev/null 2>&1 || PY=python3
rc=0
pass(){ echo "  PASS: $1"; }
fail(){ echo "  FAIL: $1"; rc=1; }

# Mint an anon keypair + write a canonical light keyfile ({address,privkey_hex}).
"$DETERM_WALLET" account-create-batch --count 1 --out "$TMP/keys.json" >/dev/null 2>&1
$PY -c "import json,sys; json.dump(json.load(open(sys.argv[1]))['accounts'][0], open(sys.argv[2],'w'))" \
    "$TMP/keys.json" "$TMP/key.json"

# A well-formed 33-byte SEC1-compressed note_pk (0x02 || 32 bytes). The accept-
# check does NOT validate on-curve (consensus-inert), so any 33 bytes suffice.
NOTE_PK="02$(printf 'a1%.0s' $(seq 1 32))"   # 2 + 64 = 66 hex = 33 bytes
NOTE_PK_32="$(printf 'a1%.0s' $(seq 1 32))"  # 64 hex = 32 bytes (wrong length)

# 1: build a REGISTER_NOTE_KEY (set form).
if "$DETERM_LIGHT" register-note-key --keyfile "$TMP/key.json" --note-pk "$NOTE_PK" \
     --fee 1 --nonce 0 --out "$TMP/set.json" >/dev/null 2>&1; then
  pass "register-note-key --note-pk wrote a submittable REGISTER_NOTE_KEY"
else fail "register-note-key --note-pk"; fi

# 2: the accept-check (in the full binary) accepts it.
if "$DETERM" verify-audit-tx --file "$TMP/set.json" >/dev/null 2>&1; then
  pass "verify-audit-tx VERIFIED REGISTER_NOTE_KEY (consensus check accepts)"
else fail "verify-audit-tx rejected a valid REGISTER_NOTE_KEY"; fi

# 3: the clear (revoke) form — empty payload — also verifies.
"$DETERM_LIGHT" register-note-key --keyfile "$TMP/key.json" --clear \
     --fee 1 --nonce 0 --out "$TMP/clr.json" >/dev/null 2>&1
if "$DETERM" verify-audit-tx --file "$TMP/clr.json" >/dev/null 2>&1; then
  pass "register-note-key --clear verifies (empty-payload revoke)"
else fail "register-note-key --clear did not verify"; fi

# 4: tamper the fee -> INVALID (the Ed25519 sig binds fee via signing_bytes).
# write_json_file emits compact JSON (no space after the colon).
sed 's/"fee":1/"fee":2/' "$TMP/set.json" > "$TMP/bad.json"
"$DETERM" verify-audit-tx --file "$TMP/bad.json" >/dev/null 2>&1
if [ $? -eq 3 ]; then pass "tampered fee -> INVALID (exit 3)"; else fail "tamper not rejected"; fi

# 5: --note-pk and --clear together are a usage error.
if "$DETERM_LIGHT" register-note-key --keyfile "$TMP/key.json" --note-pk "$NOTE_PK" \
     --clear --fee 1 --nonce 0 >/dev/null 2>&1; then
  fail "register-note-key accepted both --note-pk and --clear"
else pass "register-note-key refuses --note-pk + --clear together (exit 1)"; fi

# 6: a 32-byte note-pk (wrong length) is a build error.
if "$DETERM_LIGHT" register-note-key --keyfile "$TMP/key.json" --note-pk "$NOTE_PK_32" \
     --fee 1 --nonce 0 >/dev/null 2>&1; then
  fail "register-note-key accepted a 32-byte note-pk"
else pass "register-note-key rejects a 32-byte note-pk (must be 33; exit 1)"; fi

# 7: a non-note-key tx (plain TRANSFER) -> verify-audit-tx INVALID (type gate).
ADDR=$($PY -c "import json; print(json.load(open('$TMP/key.json'))['address'])")
"$DETERM_LIGHT" sign-tx --keyfile "$TMP/key.json" --type TRANSFER --to "$ADDR" \
     --amount 1 --fee 0 --nonce 0 --out "$TMP/xfer.json" >/dev/null 2>&1
"$DETERM" verify-audit-tx --file "$TMP/xfer.json" >/dev/null 2>&1
if [ $? -eq 3 ]; then pass "TRANSFER -> verify-audit-tx INVALID (type gate)"; else fail "TRANSFER not rejected by type gate"; fi

echo ""
if [ $rc -eq 0 ]; then echo "  PASS: note-key client->consensus loop"; else echo "  FAIL: register-note-key e2e"; fi
exit $rc
