#!/usr/bin/env bash
# test_audit_coverage.sh — completeness guard for the local audit's coverage
# record (C99-MINIX-PORT §14.1; summary in ADR-006 §7).
#
# Every tracked file must carry an explicit disposition in
# tools/audit_coverage.tsv (REVIEWED, PARTIAL, PENDING, DATA or EXCLUDED). A
# REVIEWED/PARTIAL row pins the git blob that was reviewed; a file changed since
# then is reported STALE and counted as pending, never as reviewed. The guard
# fails when a tracked file has no disposition or a row is malformed; it does
# not claim that PENDING files were read. Terminal marker: `  PASS:`/`  FAIL:`.
set -u
cd "$(dirname "$0")/.."
PY=""
for candidate in python3 python; do
  if "$candidate" -c '' >/dev/null 2>&1; then PY=$candidate; break; fi
done
[ -n "$PY" ] || { echo "  FAIL: test_audit_coverage (no working python3/python)"; exit 1; }
exec "$PY" tools/audit_coverage.py --check
