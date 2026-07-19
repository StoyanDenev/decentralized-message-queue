#!/usr/bin/env bash
# minix JSON phase 2, increment 4: determ::djson ADVERSARIAL parse-rejection +
# number-boundary DIFFERENTIAL.
#
# The swap-safety property (docs/proofs/MinixTacticalProfile.md §5): before
# determ::djson can replace nlohmann on the byte-critical wire/digest/HMAC path,
# the two impls must AGREE on accept-vs-reject for EVERY input a hostile peer can
# send — a divergence forks (one accepts a claims_json the other rejects) or
# desyncs the RPC HMAC. inc.1 proved dump-parity + ~24 rejection cases; this
# sweeps the adversarial boundary comprehensively: literal-case lookalikes,
# NaN/Infinity barewords, the full number-malformation grammar, structural
# truncations, \u surrogate edges, the u64/i64 magnitude boundaries
# (accept-agreement where the value crosses into a double — its dtoa is the known
# out-of-scope NC-1 gap), and whitespace/duplicate-key canonicalization parity.
# nlohmann is the FROZEN oracle linked in the same binary, so each verdict is
# MEASURED, not predicted. ADDITIVE: no production consumer is swapped.
#
# Run from repo root: bash tools/test_determ_json_adversarial.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== minix JSON phase 2 inc.4 — determ::djson adversarial accept/reject-agreement vs nlohmann ==="
OUT=$("$DETERM" test-determ-json-adversarial 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-determ-json-adversarial"; then
  echo "  PASS: determ-json adversarial rejection-agreement"
  exit 0
else
  echo "  FAIL: determ-json adversarial rejection-agreement (exit $rc)"
  exit 1
fi
