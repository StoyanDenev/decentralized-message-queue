#!/usr/bin/env bash
# NC-8 wiring inc.2: the CONFIDENTIAL_TRANSFER encrypted-note (enote) delivery
# region (EncryptedNoteDeliveryDesign §5). An OPTIONAL, per-output ciphertext
# region trails the DCT1 bundle; the profile pinned at genesis selects how it is
# committed — MODERN emits an `en:` state leaf (light-client-provable), FIPS
# keeps it payload-only (state-root-invariant). The region is CONSENSUS-INERT:
# only a malformed FRAME rejects; a valid-but-garbage ciphertext is accepted and
# never decrypted in consensus.
#
# Gates (via `determ test-ctx-enote`): the shared ctx_split_enotes mirror that
# BOTH the validator accept-rule and chain apply consume (structural bounds:
# count/index/length/exact-consumption); MODERN records an en: leaf that diverges
# state_root from a plain transfer; FIPS is state-root-invariant to the region; a
# malformed region is a no-op; en: round-trips through the state snapshot and is
# dropped when its note is spent (en: ⊆ cn:).
#
# Run from repo root: bash tools/test_ctx_enote.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== NC-8 ctx-enote region (MODERN en: leaf / FIPS payload-only; consensus-inert) ==="
OUT=$($DETERM test-ctx-enote 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: ctx-enote all assertions"; then
  echo ""
  echo "  PASS: ctx-enote unit test"
  exit 0
else
  echo ""
  echo "  FAIL: ctx-enote had assertion failures"
  exit 1
fi
