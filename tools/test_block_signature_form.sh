#!/usr/bin/env bash
# A6 / §7.5.1 (pre-launch register A5+A6, owner 2026-07-09) — the
# Block.signature_form discriminator: the frozen slot that says how
# creator_block_sigs[] is interpreted (0 = the shipped Ed25519 K-of-K;
# reserved 1 = BLS-aggregate slot, 2 = ML-DSA K-of-K, 0xFF forward-compat).
#
# The binary test pins: zero-skip wire round-trip (form 0 is ELIDED from
# JSON — every existing chain/golden byte-identical), the S-018 out-of-u8
# range guards (an oversized value must fail closed, never truncate into a
# DIFFERENT form), hash + committee-digest distinctness (a post-sign relabel
# of the sig array changes the digest, so the K-of-K signatures no longer
# verify), and the validator's fail-closed dispatch (every non-zero form
# rejected BEFORE any signature check; form 0 passes the gate). The
# producer/light digest-parity for the new conditional append is pinned by
# the FB62 static guard (tools/test_block_digest_xbinary_parity.sh).
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

echo "=== A6 Block.signature_form discriminator ==="
OUT=$($DETERM test-block-signature-form 2>&1)
RC=$?
echo "$OUT"

if [ $RC -ne 0 ] || echo "$OUT" | grep -q "FAIL:"; then
  echo ""
  echo "  FAIL: test_block_signature_form (assertion failure, rc=$RC)"
  exit 1
fi
if echo "$OUT" | tail -3 | grep -q "PASS: test-block-signature-form"; then
  echo ""
  echo "  PASS: test_block_signature_form"
  exit 0
else
  echo ""
  echo "  FAIL: test_block_signature_form (missing summary marker)"
  exit 1
fi
