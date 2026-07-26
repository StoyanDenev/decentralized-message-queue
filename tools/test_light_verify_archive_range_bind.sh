#!/usr/bin/env bash
# LightVerify EXP-1 — verify-archive must bind the DISPLAYED range labels
# (from / count) to the archive's actual CONTENT.
#
# THE GAP: an export-headers archive is a proof-carrying artifact verified
# OFFLINE by a third party. Its summary prints `range: [from, from+count)` from
# the envelope's self-declared `from`/`count` fields. The crypto binding
# (prev_hash chain + per-header committee sigs) authenticates the HEADERS that
# are present, but nothing tied the displayed `from`/`count` labels to them. So a
# MITM/archive-forger could serve a genuinely committee-signed slice — say the
# real headers for indices [500..510] — yet stamp `from=0, count=1000`, and
# verify-archive would print "range: [0, 1000)" for content that actually covers
# [500, 511) — deceiving the auditor about WHICH range was verified. Same
# "displayed label not bound to committee-anchored content" class as
# LSB-ANCHOR-INDEX.
#
# THE FIX: a structural gate (placed BEFORE the genesis/crypto gates) requiring
# declared `from` == headers[0].index and declared `count` == #records. The first
# header's index is committee-authenticated by the sig chain, so the label is
# transitively bound. Client-side only; no node/consensus change. export-headers
# always writes from==first_index and count==size, so no honest archive regresses.
#
# Fully OFFLINE + FAST (hand-built JSON fixtures; the structural gate needs no
# real crypto and fires before the genesis-load step, so a nonexistent --genesis
# suffices).
#   NEG-from   from(0)  != headers[0].index(5)  -> reject (exit 1) with the
#              "declared from" diagnostic, BEFORE the genesis gate.
#   NEG-count  count(99) != #records(1)          -> reject (exit 1) with the
#              "declared count" diagnostic.
#   CTRL       from(5)==index(5), count(1)==#records(1) -> passes the range gate,
#              falls through to a LATER gate (genesis load on a nonexistent
#              --genesis) — proves the gate is live, not a tautology, and that a
#              MATCHING label is NOT refused.
# Falsify-on-mutant (neutralize both range checks): NEG-from + NEG-count fall
# through to the genesis-load gate (no "declared" diagnostic), flipping both NEG
# asserts while CTRL is unchanged.
#
# NB: never `echo "$OUT"` raw — grep the captured var. (Durable run_all lesson:
# a verifier's own reject lines can false-trip the tail-10 FAIL: marker scan.)
#
# Run from repo root: bash tools/test_light_verify_archive_range_bind.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi

T=$(mktemp -d 2>/dev/null || echo "${TMPDIR:-/tmp}/determ-light-archrange.$$")
mkdir -p "$T"
trap 'rm -rf "$T"' EXIT INT

pass=0; fail=0
assert() { if [ "$1" = "true" ]; then echo "  PASS: $2"; pass=$((pass+1));
           else echo "  FAIL: $2"; fail=$((fail+1)); fi; }

GH64=$(printf 'a%.0s' $(seq 1 64))
NOGEN="$T/nonexistent_gen.json"   # deliberately absent -> genesis-load is a LATER gate

# NEG-from: real single-header slice at index 5, but the label claims from=0.
cat > "$T/from_mismatch.json" <<JSON
{"genesis_hash":"$GH64","from":0,"count":1,"headers":[{"index":5,"header_json":{"index":5}}]}
JSON
# NEG-count: from matches (5), but count(99) overstates the 1 record present.
cat > "$T/count_mismatch.json" <<JSON
{"genesis_hash":"$GH64","from":5,"count":99,"headers":[{"index":5,"header_json":{"index":5}}]}
JSON
# CTRL: from(5)==index(5), count(1)==#records(1) — both labels bound.
cat > "$T/range_match.json" <<JSON
{"genesis_hash":"$GH64","from":5,"count":1,"headers":[{"index":5,"header_json":{"index":5}}]}
JSON

echo "=== NEG-from: declared from(0) != headers[0].index(5) -> reject ==="
set +e
OUT=$("$DETERM_LIGHT" verify-archive --in "$T/from_mismatch.json" --genesis "$NOGEN" 2>&1); RC=$?
set -e
HIT=$(echo "$OUT" | grep -qiE "declared from=0 != headers\[0\].index=5" && [ $RC -ne 0 ] && echo true || echo false)
assert "$HIT" "NEG-from: mislabelled 'from' rejected at the range gate (exact diagnostic, nonzero exit)"

echo "=== NEG-count: declared count(99) != #records(1) -> reject ==="
set +e
OUT2=$("$DETERM_LIGHT" verify-archive --in "$T/count_mismatch.json" --genesis "$NOGEN" 2>&1); RC2=$?
set -e
HIT2=$(echo "$OUT2" | grep -qiE "declared count=99 != actual header count=1" && [ $RC2 -ne 0 ] && echo true || echo false)
assert "$HIT2" "NEG-count: overstated 'count' rejected at the range gate (exact diagnostic, nonzero exit)"

echo "=== CTRL: matching from/count passes the range gate, falls through to a LATER gate ==="
set +e
OUT3=$("$DETERM_LIGHT" verify-archive --in "$T/range_match.json" --genesis "$NOGEN" 2>&1); RC3=$?
set -e
# Must NOT trip either range diagnostic (proves a MATCHING label is not refused).
NOTRIP=$(echo "$OUT3" | grep -qiE "declared (from|count)=" && echo false || echo true)
assert "$NOTRIP" "CTRL: a MATCHING from/count is NOT refused by the range gate (non-vacuity)"

echo
echo "  $pass pass / $fail fail"
if [ "$fail" = "0" ]; then
  echo "  PASS: test_light_verify_archive_range_bind"; exit 0
else
  echo "  FAIL: test_light_verify_archive_range_bind"; exit 1
fi
