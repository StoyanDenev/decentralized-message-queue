#!/usr/bin/env bash
# test_light_wait_surface.sh — PURELY STATIC completeness guard for the S-042
# "every head-anchored binding consumer forwards --wait" invariant in determ-light.
#
# WHAT THIS IS
# ------------
# S-042's trustless readers anchor a daemon-served state proof to a COMMITTEE-SIGNED
# head. When the operator passes `--wait <seconds>`, that anchoring must keep retrying
# until a freshly-signed head appears, otherwise a light client racing a just-produced
# block reads a head that is not yet committee-attested and either fails spuriously or
# (worse) is forced onto a stale anchor. The usability fix threaded a `wait_seconds`
# (a.k.a. `max_wait_seconds`) parameter through EVERY head-anchored binding consumer:
# `committee_bound_state_root`, `verify_state_root_at`, `read_account_trustless`, and
# `read_stake_trustless`. The exact class of bug just fixed was a handful of call sites
# (verify-and-submit / verify-unstake-eligibility / committee-at-height) that bound the
# head WITHOUT forwarding the operator's `--wait`, so the wait was silently a no-op.
#
# THE RISK THIS LOCKS
# -------------------
# A future command handler can be added that calls one of these binding helpers but
# forgets to forward `wait_seconds` — re-opening exactly the S-042 head-read usability
# gap, silently, with no build/run failure. This guard turns RED the instant any
# binding call site drops the wait argument, BEFORE any build or cluster run.
#
# WHY STRUCTURAL COUNTS, NOT PROXIMITY
# ------------------------------------
# A prior guard used a line-proximity heuristic ("a wait token within N lines of the
# call") and produced 15 false positives. This guard uses ZERO proximity heuristics.
# Instead it walks each multi-line call from its open token to its terminating `);`
# and asserts that terminating line ends in a wait variable. That is an exact,
# false-positive-free structural property: a call either closes with `wait_seconds)` /
# `max_wait_seconds)` or it does not.
#
# THREE INVARIANTS (all static, source-only over light/main.cpp):
#   A. Every `committee_bound_state_root(` CALL closes its argument list with a wait
#      variable. We count call-opens (strict `committee_bound_state_root\(` — no space
#      before the paren, which excludes the prose comments that write
#      "committee_bound_state_root (fetches …)") and, for each, verify the first
#      terminating `);` line ends in `(wait_seconds|max_wait_seconds))`. opens==good,
#      bad==0. There are 9 such calls today.
#   B. Every command-handler CALL to verify_state_root_at / read_account_trustless /
#      read_stake_trustless closes its argument list with a wait variable. The lone
#      in-file DEFINITION (`StakeView read_stake_trustless(`) is excluded structurally:
#      a definition's signature closes with `) {`, never `);`, and we additionally
#      skip the return-typed open line. This is the robust form of "no call site ends
#      in a bare wait-slot literal": a call that dropped the wait arg would close in a
#      bare `0)` / required-arg-only `)` and be flagged as a BAD closer. 6 calls today.
#   C. The determ-light help/usage block advertises `[--wait <seconds>]` on at least
#      MIN_WAIT_HELP head-anchored command lines. This is a LOWER BOUND, so adding more
#      wait-aware commands never falsely fails; it only fires if the help block is
#      gutted. 16 such lines today; the floor is 14.
#
# QUARANTINE (B only): an escape hatch for a single known call site that must land
# without a wait arg (e.g. a non-head-anchored overload that legitimately takes no
# wait). Add the call's 1-based line number in light/main.cpp to B_QUARANTINE. Empty
# by default — prefer fixing over quarantining.
#
# SELFTEST (SELFTEST=1): re-runs A/B/C against a scratch COPY of light/main.cpp with a
# synthetic violation injected per invariant, and asserts the guard flags each. Proves
# the checks are live, not tautological. No real source is modified. Run:
#       SELFTEST=1 bash tools/test_light_wait_surface.sh
#
# Optional live cross-check (only when DETERM_LIGHT is set): also assert the
# `$DETERM_LIGHT help` output advertises `[--wait <seconds>]`. SKIPs cleanly when unset
# — the guard's verdict NEVER depends on a binary being present.
#
# Pure read-only source check (grep/awk over light/main.cpp). Needs NO determ binary,
# never requires a build/cluster. SKIP-clean (exit 0) when light/main.cpp is absent so
# a source-light checkout does not turn the suite RED. Deterministic + offline.
# run_all.sh auto-discovers it (tools/test_*.sh) and reads the single terminal
# PASS:/FAIL: marker.
#
# Exit 0 = every head-anchored binding consumer forwards --wait (or target absent);
# exit 1 = a binding call site dropped the wait argument (S-042 usability regression).
set -u
cd "$(dirname "$0")/.."

TARGET="light/main.cpp"
MIN_WAIT_HELP=14   # lower bound for invariant C (16 today); never an exact count.

# B-only quarantine: 1-based line numbers in light/main.cpp of helper CALL sites that
# are intentionally allowed to omit a wait argument. Whitespace/newline separated.
# EMPTY by default. is_b_quarantined matches an exact line number.
B_QUARANTINE=""
is_b_quarantined() { printf '%s\n' $B_QUARANTINE | grep -qxF "$1"; }

VIOLATIONS=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOLATIONS=$((VIOLATIONS + 1)); }

# ── check_invariants <file> ─────────────────────────────────────────────────────
# Runs A/B/C against <file> (the real light/main.cpp in production, a mutated scratch
# copy under SELFTEST). Prints ok/bad and increments VIOLATIONS. Pure awk/grep; the
# awk scanner is CR-tolerant (\r? in every end-of-line anchor) so a CRLF checkout
# passes on Windows git-bash and Linux/Mac alike.
check_invariants() {
  local file="$1"

  # ── A: committee_bound_state_root( calls all close with a wait variable. ───────
  # Walk each call from the strict open token (no space before "(", which excludes the
  # prose-comment form "committee_bound_state_root (…)") to its first terminating ");"
  # and require that line to end in a wait var. Emits "A opens=N good=N bad=N".
  local a_out a_opens a_good a_bad
  a_out=$(awk '
    /committee_bound_state_root\(/ && !/committee_bound_state_root\(\)/ { opens++; inside=1 }
    inside && /\)[ \t]*;[ \t]*(\/\/.*)?\r?$/ {
      if ($0 ~ /(wait_seconds|max_wait_seconds)[ \t]*\)[ \t]*;[ \t]*(\/\/.*)?\r?$/) good++
      else { bad++; print "    A bad-closer @" NR ": " $0 > "/dev/stderr" }
      inside=0
    }
    END { printf "%d %d %d", opens, good, bad }
  ' "$file")
  a_opens=${a_out%% *}; a_bad=${a_out##* }; a_good=$(echo "$a_out" | awk '{print $2}')
  if [ "$a_opens" -ge 1 ] && [ "$a_bad" = "0" ] && [ "$a_opens" = "$a_good" ]; then
    ok "A all $a_opens committee_bound_state_root() call(s) forward a wait var (close in wait_seconds)/max_wait_seconds))"
  else
    bad "A committee_bound_state_root: opens=$a_opens good=$a_good bad=$a_bad — a binding call dropped --wait (S-042 head-read REGRESSION)"
  fi

  # ── B: helper calls all close with a wait variable (definition excluded). ──────
  # Same walk for verify_state_root_at / read_account_trustless / read_stake_trustless.
  # The in-file definition "StakeView read_stake_trustless(" is skipped: its signature
  # closes with ") {" (never ");") AND we drop return-typed open lines explicitly. A
  # BAD closer = a call that ended in a bare wait-slot literal (e.g. "…, height)") with
  # no wait var. Quarantined line numbers are excluded. Emits "B opens=N good=N bad=N".
  local b_out b_opens b_good b_bad
  b_out=$(awk -v quar="$B_QUARANTINE" '
    BEGIN { n=split(quar, q, /[ \t\n]+/); for (i=1;i<=n;i++) if (q[i]!="") QQ[q[i]]=1 }
    /(verify_state_root_at|read_account_trustless|read_stake_trustless)\(/ && !/(verify_state_root_at|read_account_trustless|read_stake_trustless)\(\)/ {
      # Skip the function DEFINITION: a return-typed signature open line.
      if ($0 ~ /^[ \t]*(StakeView|AccountView|StateRootResult)[ \t]+(verify_state_root_at|read_account_trustless|read_stake_trustless)\(/) { def++; next }
      open_nr=NR; inside=1
    }
    inside && /\)[ \t]*;[ \t]*\r?$/ {
      if (open_nr in QQ) { quarn++; inside=0; next }
      if ($0 ~ /(wait_seconds|max_wait_seconds)[ \t]*\)[ \t]*;[ \t]*\r?$/) good++
      else { bad++; print "    B bad-closer (call opened @" open_nr ") @" NR ": " $0 > "/dev/stderr" }
      inside=0
    }
    END { printf "%d %d %d %d %d", opens_real(), good, bad, def, quarn }
    function opens_real() { return good + bad }
  ' "$file")
  b_opens=$(echo "$b_out" | awk '{print $1}')
  b_good=$(echo "$b_out" | awk '{print $2}')
  b_bad=$(echo "$b_out"  | awk '{print $3}')
  if [ "$b_opens" -ge 1 ] && [ "$b_bad" = "0" ] && [ "$b_opens" = "$b_good" ]; then
    ok "B all $b_opens verify_state_root_at/read_account_trustless/read_stake_trustless call(s) forward a wait var"
  else
    bad "B helper calls: opens=$b_opens good=$b_good bad=$b_bad — a head-anchored read dropped --wait (S-042 REGRESSION)"
  fi

  # ── C: help/usage block advertises [--wait <seconds>] on >= MIN_WAIT_HELP lines. ─
  # Lower bound, not exact — adding more wait-aware commands never trips this; it only
  # fires if the help surface is gutted, which would mask the parameter from operators.
  local c_count
  c_count=$(grep -cF '[--wait <seconds>]' "$file" 2>/dev/null || echo 0)
  if [ "$c_count" -ge "$MIN_WAIT_HELP" ]; then
    ok "C help block advertises [--wait <seconds>] on $c_count line(s) (>= floor $MIN_WAIT_HELP)"
  else
    bad "C only $c_count help line(s) carry [--wait <seconds>] (< floor $MIN_WAIT_HELP) — wait surface shrank below the head-anchored command set"
  fi
}

# ── SELFTEST mode (SELFTEST=1) ────────────────────────────────────────────────────
# Prove A/B/C are LIVE: copy the real light/main.cpp into a scratch file, inject one
# regression per invariant, and assert check_invariants flags each. Uses the SAME
# check_invariants the production path uses. No real source is modified.
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: S-042 wait-surface guard liveness (inject regressions -> expect RED) ==="
  if [ ! -f "$TARGET" ]; then
    echo "  SKIP: $TARGET absent — cannot run SELFTEST"; exit 0
  fi
  ST_FAIL=0
  tmproot=$(mktemp -d 2>/dev/null || echo "/tmp/s042wait.$$")
  mkdir -p "$tmproot"
  trap 'rm -rf "$tmproot"' EXIT

  st_expect_red() {
    # $1 label  $2 scratch file (already mutated). Runs the checks; expects >=1 violation.
    local label="$1" sfile="$2" before="$VIOLATIONS" delta
    check_invariants "$sfile" >/dev/null 2>&1
    delta=$((VIOLATIONS - before))
    VIOLATIONS="$before"   # reset — selftest must not pollute the real count
    if [ "$delta" -ge 1 ]; then echo "  ok:  $label -> flagged ($delta violation(s))"
    else
      echo "  bad: $label -> NOT flagged (guard is not live for this regression)" >&2
      ST_FAIL=$((ST_FAIL + 1))
    fi
  }

  # Sanity: a faithful copy of the real source must PASS (zero violations).
  clean="$tmproot/clean.cpp"
  cp "$TARGET" "$clean"
  before="$VIOLATIONS"; check_invariants "$clean" >/dev/null 2>&1
  if [ "$VIOLATIONS" = "$before" ]; then echo "  ok:  clean-copy sanity -> 0 violations"
  else echo "  bad: clean-copy sanity unexpectedly flagged" >&2; ST_FAIL=$((ST_FAIL + 1)); fi
  VIOLATIONS="$before"

  # RA: drop the wait var from one committee_bound_state_root call closer.
  #     Rewrite the FIRST "<ws>wait_seconds);" closer to a bare "<ws>0);".
  ra="$tmproot/ra.cpp"
  awk 'done!=1 && /^[ \t]*wait_seconds\)[ \t]*;[ \t]*\r?$/ { sub(/wait_seconds/, "0"); done=1 } { print }' "$clean" > "$ra"
  st_expect_red "RA committee_bound_state_root closer dropped wait var" "$ra"

  # RB: drop the wait var from a helper call closer (read_stake_trustless w/ state_path).
  #     "/*state_path=*/\"\", wait_seconds);" -> "/*state_path=*/\"\", 0);"
  rb="$tmproot/rb.cpp"
  sed 's@/\*state_path=\*/"", wait_seconds);@/*state_path=*/"", 0);@' "$clean" > "$rb"
  st_expect_red "RB helper call closer dropped wait var" "$rb"

  # RC: gut the help surface — strip every [--wait <seconds>] occurrence.
  rc="$tmproot/rc.cpp"
  sed 's/\[--wait <seconds>\]//g' "$clean" > "$rc"
  st_expect_red "RC help block stripped of [--wait <seconds>]" "$rc"

  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_light_wait_surface SELFTEST (flags all 3 regression classes)"
    exit 0
  else
    echo "  FAIL: test_light_wait_surface SELFTEST ($ST_FAIL self-test failure(s))"
    exit 1
  fi
fi

# ── Production path ───────────────────────────────────────────────────────────────
echo "=== S-042 determ-light --wait completeness guard (static; $TARGET) ==="

if [ ! -f "$TARGET" ]; then
  echo "  SKIP: $TARGET not present — nothing to guard (source-light checkout)."
  echo "  PASS: test_light_wait_surface (SKIP — target absent)"
  exit 0
fi

check_invariants "$TARGET"

# Optional live cross-check — only when DETERM_LIGHT is set. SKIPs cleanly otherwise;
# the guard's verdict above does NOT depend on it.
if [ -n "${DETERM_LIGHT:-}" ] && [ -x "${DETERM_LIGHT}" ]; then
  if "$DETERM_LIGHT" help 2>/dev/null | grep -qF '[--wait <seconds>]'; then
    ok "live $DETERM_LIGHT help advertises [--wait <seconds>]"
  else
    bad "live $DETERM_LIGHT help does NOT advertise [--wait <seconds>] — built binary lost the wait surface"
  fi
else
  echo "  skip: DETERM_LIGHT unset/non-exec — static checks only (offline)."
fi

echo ""
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "  PASS: test_light_wait_surface (every head-anchored binding consumer forwards --wait; help surface intact)"
  exit 0
else
  echo "  FAIL: test_light_wait_surface ($VIOLATIONS S-042 wait-surface regression(s) — a head-anchored read may ignore --wait)"
  exit 1
fi