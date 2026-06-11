#!/usr/bin/env bash
# test_cluster_output_discipline.sh — STATIC suite-wide output/exit-discipline
# RATCHET over every cluster-boot test (any tools/test_*.sh that launches a
# node via `$DETERM start`).
#
# WHY THIS EXISTS
# ---------------
# tools/run_all.sh detects each test's outcome by grepping the LAST 10 OUTPUT
# LINES for a "^\s*FAIL:" marker FIRST, then "^\s*PASS:" (run_all.sh, outcome-
# detection block). Under that contract a test can still lie two ways:
#   * FALSE-GREEN — a failing run that never prints a "FAIL:" colon-marker in
#     its tail (echo-only failures, bare "FAIL" without the colon, failures
#     that never reach any marker) while a per-check "PASS: ..." line lands in
#     the window. Observed live: test_adversarial false-greened through two
#     remediation sweeps while every node was boot-dead.
#   * FALSE-RED — a healthy run with no "PASS:" colon-marker at all (bare
#     "PASS" without ':', a ✓/✗ summary) counts as a "(no marker)" failure.
# Three remediation passes (commits 249b773, f26f1fb, 7fccf84) plus the
# suite-wide bare-marker colon fix brought all ~86 cluster tests to the house
# discipline, and run_all.sh's detection was flipped to FAIL-first so that a
# printed FAIL marker always wins over stray per-check PASS lines. This guard
# is the RATCHET that keeps the per-test half of that contract true: it turns
# any regression — or any NEW test shipped without the discipline — RED at the
# source level, with no cluster boot needed.
#
# THE PINNED DISCIPLINE (per cluster-boot test)
#   D1 PASS-marker presence: >= 1 `echo "...PASS: ...` colon-marker line
#      (success must be visible — rejects the no-marker / bare-"PASS" classes
#      that false-RED a healthy run).
#   D2 FAIL-marker presence: >= 1 `echo "...FAIL: ...` colon-marker line
#      (failure must be visible — under FAIL-first detection this is exactly
#      what prevents a failing run from being false-greened by its own
#      per-check PASS lines).
#   D3 failure propagation: `exit 1` appears somewhere (standalone /
#      `bash test.sh && ...` consumers are exit-code-based).
#   D4 no bare markers: no `echo "  PASS"` / `echo "  FAIL"` immediately
#      followed by the closing quote (the no-colon bug that made
#      test_orphan_check_cluster count as a failure at rc=0).
#
# This guard checks SHAPE, not truth: it cannot prove an assertion is sound,
# only that the reporting plumbing cannot lie about it. (Sentinel hardening
# and assertion soundness are per-test review work — see the remediation
# commits and SECURITY.md S-044/S-045 for what that review surfaced.)
#
# COMPANION CONTRACT (pinned here too): run_all.sh must keep checking FAIL:
# BEFORE PASS: — D5 asserts the detection-order line shape in run_all.sh so
# the two halves of the contract cannot drift apart silently.
#
# LIVENESS (SELFTEST=1): synthetic drifted snippets are fed through the SAME
# check functions and each violation class must be flagged RED.
#
# Pure read-only source check (grep/sed over tools/*.sh). Needs NO determ
# binary, never SKIPs, does NOT source tools/common.sh, runs offline.
# run_all.sh auto-discovers it and reads the single terminal PASS:/FAIL: marker.
set -u
cd "$(dirname "$0")/.."

SELF="tools/test_cluster_output_discipline.sh"
VIOLATIONS=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOLATIONS=$((VIOLATIONS + 1)); }

# ── check_file <file> ───────────────────────────────────────────────────────
# Runs D1..D4 on one file (accumulates the global counter via bad()).
# Marker matching is deliberately anchor-light (`echo "` anywhere on the
# line) so assert-helper bodies and `cmd && echo "..."` forms count too.
check_file() {
  local f="$1" base
  base=$(basename "$f")

  # D1: at least one colon PASS-marker emission.
  if ! grep -qE 'echo "\s*PASS: ' "$f"; then
    bad "$base — D1: no colon PASS-marker (echo \"  PASS: ...\") — a healthy run counts as a no-marker failure"
  fi

  # D2: at least one colon FAIL-marker emission (under FAIL-first detection
  # this is what makes a failing run un-false-greenable).
  if ! grep -qE 'echo "\s*FAIL: ' "$f"; then
    bad "$base — D2: no colon FAIL-marker (echo \"  FAIL: ...\") — a failing run cannot raise the fail-closed signal run_all.sh keys on"
  fi

  # D3: failure propagation to the exit code.
  if ! grep -q "exit 1" "$f"; then
    bad "$base — D3: no 'exit 1' anywhere — internal failures never reach the exit code"
  fi

  # D4: bare marker without the colon (never matches run_all's grep).
  if grep -qE 'echo "\s*(PASS|FAIL)"' "$f"; then
    bad "$base — D4: bare PASS/FAIL marker without ':' — invisible to run_all.sh's ^\\s*PASS:/^\\s*FAIL: grep"
  fi
}

# ── D5: run_all.sh detection order (FAIL before PASS) ───────────────────────
check_runner_order() {
  local fail_ln pass_ln
  # Fixed-string match on the detection greps' literal pattern text.
  fail_ln=$(grep -nF '"^\s*FAIL:"' tools/run_all.sh | head -1 | cut -d: -f1)
  pass_ln=$(grep -nF '"^\s*PASS:"' tools/run_all.sh | head -1 | cut -d: -f1)
  if [ -z "$fail_ln" ] || [ -z "$pass_ln" ]; then
    bad "run_all.sh — D5: could not locate the FAIL:/PASS: detection greps (shape changed; re-pin this guard)"
  elif [ "$fail_ln" -ge "$pass_ln" ]; then
    bad "run_all.sh — D5: PASS: is checked before FAIL: — a per-check PASS line in a failing run's tail window false-greens the suite"
  else
    ok "run_all.sh checks FAIL: (line $fail_ln) before PASS: (line $pass_ln) — fail-closed detection order"
  fi
}

# ── SELFTEST mode ───────────────────────────────────────────────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: discipline checks flag each violation class ==="
  ST_FAIL=0
  TMPD=$(mktemp -d)
  trap 'rm -rf "$TMPD"' EXIT

  mkcase() { printf '%s\n' "$2" > "$TMPD/$1"; }

  # (0) clean snippet — all checks green (assert-helper per-check PASS lines
  #     are FINE under FAIL-first detection; the terminal markers carry it).
  mkcase clean.sh '#!/usr/bin/env bash
$DETERM start --config c.json &
assert() { if $1; then echo "  PASS: $2"; else echo "  bad: $2"; FAILS=$((FAILS+1)); fi; }
if [ "$FAILS" -eq 0 ]; then
  echo "  PASS: test_clean"
  exit 0
else
  echo "  FAIL: test_clean ($FAILS checks failed)"
  exit 1
fi'
  # (1) D1+D4: bare PASS without colon (the orphan_check bug).
  mkcase bare.sh '#!/usr/bin/env bash
$DETERM start --config c.json &
[ "$RC" = "0" ] && echo "  PASS" || echo "  FAIL: test_bare (rc=$RC)"
exit $RC'
  # (2) D2: failure path never emits a FAIL: colon-marker.
  mkcase nofail.sh '#!/usr/bin/env bash
$DETERM start --config c.json &
if $PASS; then
  echo "  PASS: test_nofail"
  exit 0
else
  echo "something went wrong"
  exit 1
fi'
  # (3) D3: no exit 1 anywhere (the exit-code gap).
  mkcase noexit.sh '#!/usr/bin/env bash
$DETERM start --config c.json &
echo "  FAIL: test_noexit (would need exit)"
if $PASS; then
  echo "  PASS: test_noexit"
  exit 0
fi'

  st_expect() {  # st_expect <case-file> <want(clean|red)> <label>
    local before=$VIOLATIONS got
    check_file "$TMPD/$1" >/dev/null 2>&1
    got=$((VIOLATIONS - before))
    VIOLATIONS=$before   # selftest violations must not leak into the verdict
    if [ "$2" = "clean" ]; then
      [ "$got" -eq 0 ] && echo "  ok:  $3 -> clean (as required)" \
                       || { echo "  bad: $3 flagged $got violation(s) on a CLEAN snippet" >&2; ST_FAIL=$((ST_FAIL+1)); }
    else
      [ "$got" -gt 0 ] && echo "  ok:  $3 -> RED ($got violation(s), as required)" \
                       || { echo "  bad: $3 NOT flagged — the guard is not live for this class" >&2; ST_FAIL=$((ST_FAIL+1)); }
    fi
  }

  st_expect clean.sh  clean "clean assert-helper snippet"
  st_expect bare.sh   red   "bare-PASS-no-colon (D1+D4)"
  st_expect nofail.sh red   "failure path without FAIL: marker (D2)"
  st_expect noexit.sh red   "missing exit-1 propagation (D3)"

  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_cluster_output_discipline SELFTEST (all violation classes flagged; clean snippet green)"
    exit 0
  else
    echo "  FAIL: test_cluster_output_discipline SELFTEST ($ST_FAIL liveness failure(s))"
    exit 1
  fi
fi

# ── live run over the cluster-boot population ───────────────────────────────
echo "=== cluster output/exit-discipline ratchet (static; run_all.sh FAIL-first marker contract) ==="
check_runner_order
CHECKED=0
for f in tools/test_*.sh; do
  [ "$f" = "$SELF" ] && continue
  grep -q '\$DETERM start' "$f" || continue
  CHECKED=$((CHECKED+1))
  check_file "$f"
done
ok "checked $CHECKED cluster-boot tests against D1 (PASS: marker), D2 (FAIL: marker), D3 (exit-1 propagation), D4 (colon markers)"

echo ""
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "  PASS: test_cluster_output_discipline ($CHECKED cluster tests + run_all.sh detection order all meet the contract)"
  exit 0
else
  echo "  FAIL: test_cluster_output_discipline ($VIOLATIONS violation(s) — a test or the runner can lie about an outcome)"
  exit 1
fi
