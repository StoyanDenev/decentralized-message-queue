#!/usr/bin/env bash
# Abort-event digest CANONICALIZATION hardening. hash_abort_event() hashes the
# canonical claims form (only the six consensus-bound fields, sorted; unknown
# members stripped) instead of the verbatim peer JSON, via ONE shared helper
# (include/determ/chain/abort_canonical.hpp) called by BOTH the daemon
# (producer.cpp) and the light-client mirror (light/verify.cpp). This stops an
# attacker-injected extra member in an otherwise-valid abort claim — which the
# per-claim signature does not cover and per-claim validation ignores — from
# riding the K-of-K block digest, and it unblocks the minix determ::djson swap
# for this site (no attacker-controlled double reaches dump()).
#
# `determ test-abort-claims-canonical` asserts (14): BYTE-NEUTRALITY for honest
# claims (canonical == verbatim → every honest abort block's digest UNCHANGED,
# no fork/migration), three non-semantic channels STRIPPED (unknown members, the
# numeric-VALUE encoding of int fields — a float-encoded block_index truncates
# past validation but is canonicalized away — and hex case), each LOAD-BEARING
# (the variation DOES change the verbatim bytes), and the non-array / malformed
# / empty fallbacks. The
# whole-suite witness that the digest is byte-neutral is that every existing
# abort test (test-abort-event-apply, the FA abort traces) + the consensus
# goldens stay green with this change in.
#
# Run from repo root: bash tools/test_abort_claims_canonical.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== abort-event digest canonicalization (strip injected members; byte-neutral for honest) ==="
OUT=$("$DETERM" test-abort-claims-canonical 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-abort-claims-canonical"; then
  echo "  PASS: abort-claims-canonical"
  exit 0
else
  echo "  FAIL: abort-claims-canonical (exit $rc)"
  exit 1
fi
