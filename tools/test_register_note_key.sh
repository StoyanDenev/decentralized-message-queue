#!/usr/bin/env bash
# NC-8 wiring inc.5a — the REGISTER_NOTE_KEY consensus tx + nk: state leaf
# (EncryptedNoteDeliveryDesign §5.6, CRYPTO-C99-SPEC §3.25 publication). The
# on-chain PUBLICATION of a recipient's 33-byte P-256 note_pk so a third-party
# sender can find whom to seal a CONFIDENTIAL_TRANSFER enote to (Option (a): a
# dedicated tx + leaf, cloning the shipped ROTATE_AUDIT_KEY / ak: template).
#
# Gates (via `determ test-register-note-key`): set/rotate/clear lifecycle on the
# nk: leaf (a real inc.4-derived note_pk), fee-only accounting (A1 intact),
# apply-level fail-closed skips (wrong length / non-zero amount / non-empty to),
# state-proof observability, JSON-snapshot round-trip (cleared + live), and THE
# DECISIVE PROPERTY — an anonymous bearer account (the primary CONFIDENTIAL_
# TRANSFER payee) CAN publish a note key at the validator while it still cannot
# REGISTER. Byte-neutral when unused: a note-key-free chain's state root is
# byte-identical (pinned by the FAST golden corpus + the leaf-absent assertion).
#
# Run from repo root: bash tools/test_register_note_key.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== NC-8 note-key publication (inc.5a) — REGISTER_NOTE_KEY + nk: leaf ==="
OUT=$($DETERM test-register-note-key 2>&1)
echo "$OUT"

if echo "$OUT" | tail -3 | grep -q "PASS: test-register-note-key"; then
  echo ""
  echo "  PASS: register-note-key unit test"
  exit 0
else
  echo ""
  echo "  FAIL: register-note-key had assertion failures"
  exit 1
fi
