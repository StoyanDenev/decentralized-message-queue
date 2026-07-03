#!/usr/bin/env bash
# determ-wallet envelope FORMAT-FREEZE regression (backward compatibility).
#
# Every other envelope test (tools/test_envelope.sh, tools/
# test_wallet_envelope.sh, tools/test_wallet_envelope_roundtrip_fuzz.sh)
# round-trips with the CURRENT binary: encrypt and decrypt both use the
# code at HEAD, so a coordinated format change — a different KDF, a new
# AEAD, a reordered wire layout — passes all of them while silently
# orphaning every envelope already written to disk (encrypted keyfiles,
# Shamir backup shares, cold-sign archives).
#
# This test is the missing guard: it embeds an envelope blob PRODUCED BY
# A PAST BUILD verbatim and requires every future backend to still
# decrypt it to the exact pinned payload. The pinned blob is the on-disk
# FORMAT CONTRACT for the DWE1 wire layout (wallet/envelope.hpp):
#
#   [magic "DWE1"] [salt_len u8 + salt] [pbkdf2_iters u32 LE]
#   [nonce 12B] [aad_len u16 LE + aad] [ct_len u32 LE + ct||tag]
#   key = PBKDF2-HMAC-SHA-256(password, salt, iters, 32)
#   cipher = AES-256-GCM, 16-byte tag appended to ciphertext
#   hex serialization: magic.salt.iters.nonce.aad.ct (dot-separated)
#
# If this test goes RED, the change under test broke decryption of
# every envelope in the field. That is a consensus-grade compatibility
# break for wallet artifacts: do NOT "fix" the test by re-pinning the
# blob unless a deliberate, versioned format migration (new magic, with
# a legacy-decrypt path) is being shipped and documented.
#
# Pinned fixture provenance — generated 2026-07-03 with the then-current
# build/Release/determ-wallet.exe (wallet already on the determ::c99
# crypto backend, post-1c migration), exact commands:
#
#   PLAIN=44455445524d20656e76656c6f706520666f726d617420667265657a65207631
#         (= ASCII "DETERM envelope format freeze v1", 32 bytes)
#   PW="determ-format-freeze-2026"
#   determ-wallet envelope encrypt --plaintext $PLAIN --password "$PW" \
#       --iters 10000                    # -> PINNED_ENV (no AAD)
#   determ-wallet envelope encrypt --plaintext $PLAIN --password "$PW" \
#       --aad cafebabe --iters 10000     # -> PINNED_ENV_AAD
#
# (10000 iters keeps the test fast; the iteration count is stored inside
# the envelope, so decrypt exercises the exact same KDF/AEAD code path
# as the production 600k-iter default.)
#
# Coverage:
#   1. Pinned no-AAD envelope decrypts to the pinned payload, byte-for-byte.
#   2. Pinned AAD envelope decrypts with the pinned AAD, byte-for-byte.
#   3. Wrong passphrase against the pinned envelope fails (exit 2, AEAD
#      tag failure) — freezes the fail-closed contract, and proves leg 1
#      is not a decrypt-anything stub.
#   4. Wrong AAD against the pinned AAD envelope fails — freezes the
#      AAD-binding semantics for old envelopes.
#   5. Fresh round-trip (encrypt at HEAD -> decrypt at HEAD) sanity leg,
#      so a RED run distinguishes "format broke old blobs" (1-4 fail,
#      5 passes) from "envelope code is broken outright" (5 fails too).
#
# Run from repo root: bash tools/test_wallet_envelope_compat.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
    echo "  SKIP: determ-wallet binary not found; build with"
    echo "        cmake --build build --config Release --target determ-wallet"
    exit 0
fi

WALLET="$DETERM_WALLET"

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

# ── Pinned fixtures (DO NOT REGENERATE — see header) ─────────────────────────
PINNED_PW="determ-format-freeze-2026"
PINNED_PLAIN="44455445524d20656e76656c6f706520666f726d617420667265657a65207631"
PINNED_AAD="cafebabe"

PINNED_ENV=$(cat <<'PINNED_ENV_EOF'
44574531.416f500429b4b97ea53c39aeb9c3a8d8.10270000.2b6838502f2888e85a77da52..efa9a1b058ba0266c773fe977813733095f9b9ee5cdf355f35a183f28901947123ff04d30a7abc45042f4b8663b808aa
PINNED_ENV_EOF
)

PINNED_ENV_AAD=$(cat <<'PINNED_ENV_AAD_EOF'
44574531.aead3f328fe5dd5e5655b78acda08a0e.10270000.08d62bd4bdc21c8f3d65a429.cafebabe.5c958719c254eb25633521f705c146e6b965711dc1d8aa480e802cd52dc7050003fb227b84781ad9d665c845dca9bd11
PINNED_ENV_AAD_EOF
)

# ── 1. Pinned no-AAD envelope decrypts byte-for-byte ─────────────────────────
echo "=== 1. Pinned envelope (no AAD) decrypts to pinned payload ==="
DEC=$("$WALLET" envelope decrypt --envelope "$PINNED_ENV" --password "$PINNED_PW" 2>&1)
RC=$?
DEC=$(echo "$DEC" | tr -d '\r')
assert_eq "$RC" "0" "pinned envelope decrypt exit 0"
assert_eq "$DEC" "$PINNED_PLAIN" "pinned envelope payload byte-for-byte"

# ── 2. Pinned AAD envelope decrypts byte-for-byte ────────────────────────────
echo
echo "=== 2. Pinned envelope (AAD-bound) decrypts to pinned payload ==="
DEC_AAD=$("$WALLET" envelope decrypt --envelope "$PINNED_ENV_AAD" --password "$PINNED_PW" --aad "$PINNED_AAD" 2>&1)
RC=$?
DEC_AAD=$(echo "$DEC_AAD" | tr -d '\r')
assert_eq "$RC" "0" "pinned AAD envelope decrypt exit 0"
assert_eq "$DEC_AAD" "$PINNED_PLAIN" "pinned AAD envelope payload byte-for-byte"

# ── 3. Wrong passphrase against the pinned envelope fails ────────────────────
echo
echo "=== 3. Wrong passphrase against pinned envelope rejected ==="
ERR=$("$WALLET" envelope decrypt --envelope "$PINNED_ENV" --password "wrong-passphrase" 2>&1)
RC=$?
ERR=$(echo "$ERR" | tr -d '\r')
assert_eq "$RC" "2" "wrong passphrase exit 2"
assert_contains "$ERR" "AEAD tag failure" "wrong passphrase yields AEAD tag failure"

# ── 4. Wrong AAD against the pinned AAD envelope fails ───────────────────────
echo
echo "=== 4. Wrong AAD against pinned AAD envelope rejected ==="
ERR_AAD=$("$WALLET" envelope decrypt --envelope "$PINNED_ENV_AAD" --password "$PINNED_PW" --aad "deadbeef" 2>&1)
RC=$?
ERR_AAD=$(echo "$ERR_AAD" | tr -d '\r')
assert_eq "$RC" "2" "wrong AAD exit 2"
assert_contains "$ERR_AAD" "AEAD tag failure" "wrong AAD yields AEAD tag failure"

# ── 5. Fresh round-trip sanity leg (isolates format break vs code break) ─────
echo
echo "=== 5. Fresh encrypt->decrypt round-trip at HEAD ==="
FRESH_ENV=$("$WALLET" envelope encrypt --plaintext "$PINNED_PLAIN" --password "$PINNED_PW" --iters 10000 2>&1)
RC=$?
FRESH_ENV=$(echo "$FRESH_ENV" | tr -d '\r')
assert_eq "$RC" "0" "fresh encrypt exit 0"
FRESH_DEC=$("$WALLET" envelope decrypt --envelope "$FRESH_ENV" --password "$PINNED_PW" 2>&1)
RC=$?
FRESH_DEC=$(echo "$FRESH_DEC" | tr -d '\r')
assert_eq "$RC" "0" "fresh decrypt exit 0"
assert_eq "$FRESH_DEC" "$PINNED_PLAIN" "fresh round-trip payload matches"

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo "=== Test summary ==="
echo "  $pass_count pass / $fail_count fail"
if [ "$fail_count" = "0" ]; then
    echo "  PASS: determ-wallet envelope format-freeze compat"
    exit 0
else
    echo "  FAIL: test_wallet_envelope_compat"
    echo "  NOTE: if legs 1-4 failed while leg 5 passed, the change under"
    echo "        test broke decryption of PREVIOUSLY-WRITTEN envelopes"
    echo "        (keyfiles, backup shares). Do not re-pin the fixture;"
    echo "        ship a versioned migration with a legacy-decrypt path."
    exit 1
fi
