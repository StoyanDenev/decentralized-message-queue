#!/usr/bin/env bash
# minix JSON phase 2, increment 1: determ::djson DUAL-ORACLE byte-parity gate.
#
# The load-bearing minix property (docs/proofs/MinixTacticalProfile.md §5): a
# from-scratch in-tree JSON module must dump() BYTE-IDENTICALLY to the vendored
# nlohmann on the subset the daemon puts on a consensus/HMAC path — the
# abort-event digest (hash_abort_event SHA-256s claims_json.dump(), mirrored in
# the light client) and the RPC HMAC (method|params.dump()). nlohmann is the
# FROZEN reference, linked in the same `determ` binary, so parity is measured
# empirically (parse→dump both, byte-compare), not predicted. This increment is
# ADDITIVE (introduces determ::djson + proves the property); no production
# consumer is swapped onto it yet.
#
# `determ test-determ-json` also gates: round-trip idempotence, key-sort
# canonicalization, the two exact byte-critical shapes, the builder path,
# strict-UTF-8 fail-closed on dump (both impls throw), parse-rejection AGREEMENT
# on malformed peer input (both impls reject), and the depth-cap hardening
# divergence. It returns non-zero on any assertion failure — the wrapper gates
# on that exit code (a summary-string grep goes stale silently).
#
# Run from repo root: bash tools/test_determ_json.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM:-}" ] || [ ! -x "$DETERM" ]; then
    echo "  SKIP: determ binary not found"; exit 0; fi

echo "=== minix JSON phase 2 inc.1 — determ::djson dual-oracle byte-parity vs nlohmann ==="
OUT=$("$DETERM" test-determ-json 2>&1); rc=$?
echo "$OUT"
echo ""
if [ $rc -eq 0 ] && echo "$OUT" | tail -1 | grep -q "PASS: test-determ-json"; then
  echo "  PASS: determ-json dual-oracle byte-parity"
  exit 0
else
  echo "  FAIL: determ-json had assertion failures (exit $rc)"
  exit 1
fi
