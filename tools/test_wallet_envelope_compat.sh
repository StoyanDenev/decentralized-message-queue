#!/usr/bin/env bash
# determ-wallet envelope FORMAT-FREEZE regression (D2 binary container).
#
# Two frozen contracts, both required:
#
#   A. REJECT-LEGACY: the pre-D2 dot-separated hex TEXT serialization
#      ("magic.salt.params.nonce.aad.ct") is DELETED, pre-genesis, with no
#      migration path. Readers must REJECT the legacy form at parse (exit 1,
#      "deserialize failed") — never misparse it, never reach the cipher.
#      The two legacy blobs below are the 2026-07-03 pinned fixtures kept
#      verbatim as HOSTILE inputs.
#
#   B. FORMAT-FREEZE (new form): the canonical binary DWE container
#      (wallet/envelope.hpp byte layout, serialized on the CLI as plain
#      lowercase hex, no dots) is the on-disk contract from here on. The
#      pinned blobs below were produced 2026-08-12 by build-linux/
#      determ-wallet at the D2 migration commit, exact commands:
#
#        PLAIN=44455445524d20656e76656c6f706520666f726d617420667265657a65207631
#              (= ASCII "DETERM envelope format freeze v1", 32 bytes)
#        PW="determ-format-freeze-2026"
#        determ-wallet envelope encrypt --plaintext $PLAIN --password "$PW" \
#            --iters 10000                    # -> PINNED_BIN_DWE1 (no AAD)
#        determ-wallet envelope encrypt --plaintext $PLAIN --password "$PW" \
#            --aad cafebabe --iters 10000     # -> PINNED_BIN_DWE1_AAD
#        determ-wallet envelope encrypt --plaintext $PLAIN --password "$PW" \
#                                             # -> PINNED_BIN_DWE2 (Argon2id)
#
#      Every future build must still decrypt them byte-for-byte. If a leg
#      of B goes RED, the change under test broke decryption of every
#      envelope in the field — do NOT re-pin unless a deliberate, versioned
#      format migration (new magic + legacy-decrypt path) is being shipped.
#
# Coverage:
#   1. Legacy dot-hex blob (no AAD)  -> exit 1, parse reject (never exit 2).
#   2. Legacy dot-hex blob (AAD)     -> exit 1, parse reject.
#   3. Pinned binary DWE1 decrypts to the pinned payload, byte-for-byte.
#   4. Pinned binary DWE1+AAD decrypts with the pinned AAD, byte-for-byte.
#   5. Pinned binary DWE2 (Argon2id) decrypts, byte-for-byte.
#   6. Wrong passphrase on a pinned binary blob -> exit 2 (AEAD, fail-closed).
#   7. Fresh round-trip at HEAD; output is dot-free plain hex.
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

# S-114 (2026-09-18): the raw `--password` now prints WARNING[seed-on-command-line]
# to stderr, which lands in every capture below. The first cut of that increment
# answered it with `2>/dev/null` — and MEASURABLY WEAKENED this file: the four
# format-freeze captures are exact equalities, so merged stderr was an implicit
# "and stderr is empty" assertion, and against a shim that is the real binary
# plus ONE unrelated stderr line this wrapper went from 8 FAIL / rc=1 to 0 FAIL /
# rc=0 — completely green on a defect it used to catch. The fix is to take the
# password OFF the command line through the `--password-from` twin the same
# increment adds, and KEEP `2>&1` everywhere. Measured after: 16 pass / 0 fail
# against the real binary, 7 FAIL / rc=1 against the shim.
SCRATCH="build/test_wallet_envelope_compat.$$"
mkdir -p "$SCRATCH"
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

PINNED_PW="determ-format-freeze-2026"
# The same password, off argv. 0600 because it is a password in a file.
PWF="$SCRATCH/pw.txt"
printf '%s\n' "$PINNED_PW" > "$PWF"; chmod 600 "$PWF"
PINNED_PLAIN="44455445524d20656e76656c6f706520666f726d617420667265657a65207631"
PINNED_AAD="cafebabe"

# ── LEGACY fixtures (pre-D2 dot-hex text; now HOSTILE inputs) ────────────────
LEGACY_ENV="44574531.416f500429b4b97ea53c39aeb9c3a8d8.10270000.2b6838502f2888e85a77da52..efa9a1b058ba0266c773fe977813733095f9b9ee5cdf355f35a183f28901947123ff04d30a7abc45042f4b8663b808aa"
LEGACY_ENV_AAD="44574531.aead3f328fe5dd5e5655b78acda08a0e.10270000.08d62bd4bdc21c8f3d65a429.cafebabe.5c958719c254eb25633521f705c146e6b965711dc1d8aa480e802cd52dc7050003fb227b84781ad9d665c845dca9bd11"

# ── PINNED binary-form fixtures (DO NOT REGENERATE — see header) ─────────────
PINNED_BIN_DWE1="4457453110f33543665c8fad4a40d565096a0620f210270000ed1c1903d869fde234dc64470000300000004cdd8ea79bd736e0d6e9ddb7246d24f2e4f102460ab784bdf12e0c2dc96ea75179d9638818beabd6aa281d98da118b36"
PINNED_BIN_DWE1_AAD="44574531109edf34567936415aabac72a1f2fcb9311027000041552d049c1359b2e67300ea0400cafebabe30000000da97aa1ede593786d0fc5da0600ceb75475dd89130c8a78ea7b9f0b8dd0e3d6fa4107b5010022c5923fe74c50953f3e5"
PINNED_BIN_DWE2="44574532103ddb1acfff50ef3cf5a9ed5cbca6f3ec0300000000000100010000005bee1016bd697b25ee8bb2ce0000300000009aaeb6a3bbd52f24eebb011cc35c19d0a4ccdabff52691fb4c7566dfaaa8d83701da97e46ac960d71f78d3ed73d3a850"

# ── 1. Legacy dot-hex blob (no AAD) is rejected at PARSE ─────────────────────
echo "=== 1. Legacy dot-hex envelope REJECTED at parse (exit 1, not 2) ==="
set +e
"$WALLET" envelope decrypt --envelope "$LEGACY_ENV" --password "$PINNED_PW" >/dev/null 2>&1
RC=$?
ERR=$("$WALLET" envelope decrypt --envelope "$LEGACY_ENV" --password "$PINNED_PW" 2>&1 | tr -d '\r')
set -e
assert_eq "$RC" "1" "legacy no-AAD blob exits 1 (parse reject, never reaches AEAD)"
assert_contains "$ERR" "deserialize failed" "legacy no-AAD diagnostic: deserialize failed"

# ── 2. Legacy dot-hex blob (AAD) is rejected at PARSE ────────────────────────
echo
echo "=== 2. Legacy dot-hex AAD envelope REJECTED at parse (exit 1) ==="
set +e
"$WALLET" envelope decrypt --envelope "$LEGACY_ENV_AAD" --password "$PINNED_PW" --aad "$PINNED_AAD" >/dev/null 2>&1
RC=$?
set -e
assert_eq "$RC" "1" "legacy AAD blob exits 1 (parse reject)"

# ── 3. Pinned binary DWE1 decrypts byte-for-byte ─────────────────────────────
echo
echo "=== 3. Pinned binary DWE1 envelope decrypts to pinned payload ==="
set +e
DEC=$("$WALLET" envelope decrypt --envelope "$PINNED_BIN_DWE1" --password-from "file:$PWF" 2>&1)
RC=$?
set -e
DEC=$(echo "$DEC" | tr -d '\r')
assert_eq "$RC" "0" "pinned binary DWE1 decrypt exit 0"
assert_eq "$DEC" "$PINNED_PLAIN" "pinned binary DWE1 payload byte-for-byte"

# ── 4. Pinned binary DWE1+AAD decrypts byte-for-byte ─────────────────────────
echo
echo "=== 4. Pinned binary DWE1 AAD envelope decrypts to pinned payload ==="
set +e
DEC_AAD=$("$WALLET" envelope decrypt --envelope "$PINNED_BIN_DWE1_AAD" --password-from "file:$PWF" --aad "$PINNED_AAD" 2>&1)
RC=$?
set -e
DEC_AAD=$(echo "$DEC_AAD" | tr -d '\r')
assert_eq "$RC" "0" "pinned binary DWE1 AAD decrypt exit 0"
assert_eq "$DEC_AAD" "$PINNED_PLAIN" "pinned binary DWE1 AAD payload byte-for-byte"

# ── 5. Pinned binary DWE2 (Argon2id) decrypts byte-for-byte ──────────────────
echo
echo "=== 5. Pinned binary DWE2 (Argon2id) envelope decrypts ==="
set +e
DEC2=$("$WALLET" envelope decrypt --envelope "$PINNED_BIN_DWE2" --password-from "file:$PWF" 2>&1)
RC=$?
set -e
DEC2=$(echo "$DEC2" | tr -d '\r')
assert_eq "$RC" "0" "pinned binary DWE2 decrypt exit 0"
assert_eq "$DEC2" "$PINNED_PLAIN" "pinned binary DWE2 payload byte-for-byte"

# ── 6. Wrong passphrase on a pinned binary blob fails closed ─────────────────
echo
echo "=== 6. Wrong passphrase against pinned binary envelope rejected ==="
set +e
"$WALLET" envelope decrypt --envelope "$PINNED_BIN_DWE1" --password "wrong-passphrase" >/dev/null 2>&1
RC=$?
ERR=$("$WALLET" envelope decrypt --envelope "$PINNED_BIN_DWE1" --password "wrong-passphrase" 2>&1 | tr -d '\r')
set -e
assert_eq "$RC" "2" "wrong passphrase exit 2"
assert_contains "$ERR" "AEAD tag failure" "wrong passphrase yields AEAD tag failure"

# ── 7. Fresh round-trip at HEAD; output is dot-free plain hex ────────────────
echo
echo "=== 7. Fresh encrypt->decrypt round-trip at HEAD (dot-free hex) ==="
set +e
FRESH_ENV=$("$WALLET" envelope encrypt --plaintext "$PINNED_PLAIN" --password-from "file:$PWF" --iters 10000 2>&1)
RC=$?
set -e
FRESH_ENV=$(echo "$FRESH_ENV" | tr -d '\r')
assert_eq "$RC" "0" "fresh encrypt exit 0"
if echo "$FRESH_ENV" | grep -q '\.'; then
  echo "  FAIL: fresh envelope contains a dot (legacy text form resurfaced)"
  fail_count=$((fail_count + 1))
else
  echo "  PASS: fresh envelope is dot-free plain hex"
  pass_count=$((pass_count + 1))
fi
case "$FRESH_ENV" in
  *[!0-9a-f]*) echo "  FAIL: fresh envelope is not lowercase hex"; fail_count=$((fail_count + 1)) ;;
  *)           echo "  PASS: fresh envelope is lowercase hex only"; pass_count=$((pass_count + 1)) ;;
esac
set +e
FRESH_DEC=$("$WALLET" envelope decrypt --envelope "$FRESH_ENV" --password-from "file:$PWF" 2>&1)
RC=$?
set -e
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
    echo "  NOTE: if the pinned-binary legs failed while leg 7 passed, the"
    echo "        change under test broke decryption of PREVIOUSLY-WRITTEN"
    echo "        binary envelopes (keyfiles, backup shares). Do not re-pin;"
    echo "        ship a versioned migration with a legacy-decrypt path."
    exit 1
fi
