#!/usr/bin/env bash
# test_light_state_root_binding_guard.sh — STATIC regression guard for S-042.
#
# WHAT THIS IS
# ------------
# S-042 (HIGH, fixed in commit 2194c53): the determ-light trustless readers used
# to report a `state_root` taken straight from a daemon-supplied header FIELD. The
# committee signs `compute_block_digest`, which EXCLUDES `state_root` (and a stripped
# `rpc_headers` reply omits the heavy fields `signing_bytes` needs, so the light
# client cannot recompute `block_hash` from a header). A malicious daemon could
# therefore swap the `state_root` field AFTER the committee signed and have it
# reported as "committee-verified" -> forged balance.
#
# The fix routes EVERY trustless state read through
# `light/trustless_read.cpp::committee_bound_state_root`, which fetches the FULL block
# (the `block` RPC), recomputes `block_hash = compute_hash()` (which binds state_root),
# and requires it to equal the COMMITTEE-SIGNED `prev_hash` of the successor block.
#
# A one-time adversarial sweep confirmed zero residual field-trust at fix time. THIS
# guard makes that protection DURABLE: it turns RED the instant a future edit
# reintroduces the vulnerable pattern or strips the binding — BEFORE any build/run.
# It is the static complement to the live cluster forgery-catch leg (CI/WSL2).
#
# THREE INVARIANTS (all static, source-only):
#   I1. The vulnerable anchor pattern `proof_root != vc.head_state_root` (and any
#       `!= vc.head_state_root` trust comparison) MUST NOT exist anywhere in light/.
#       This was THE field-trust anchor; the fix removed all 10 occurrences. A
#       regression that reintroduces a header-field anchor would bring it back.
#   I2. `committee_bound_state_root` MUST be called from every reader file that
#       anchors a state-proof: trustless_read.cpp, main.cpp, account_history.cpp,
#       verify_state_root.cpp. (Zero calls in any of them = a reader stopped binding.)
#   I3. The helper itself (trustless_read.cpp) MUST retain its three load-bearing
#       pieces: the FULL-block fetch (`rpc.call("block"`), the successor-prev_hash
#       binding check (`succ_prev != recomputed_hex`), and a fail-closed SECURITY
#       throw. Stripping any of these would silently un-bind state_root.
#
# LIVENESS (SELFTEST=1): re-runs the three checks against scratch COPIES of the real
# files with a regression injected into each, and asserts the guard flags every one.
# Proves the checks are live, not tautological. Run:
#       SELFTEST=1 bash tools/test_light_state_root_binding_guard.sh
#
# Pure read-only source check (grep over light/*.cpp/.hpp). Needs NO determ binary,
# never SKIPs, does NOT source tools/common.sh. Deterministic + offline. run_all.sh
# auto-discovers it (tools/test_*.sh) and reads the single terminal PASS:/FAIL: marker.
#
# Exit 0 = the S-042 binding is intact; exit 1 = a regression reopened the gap.
set -u
cd "$(dirname "$0")/.."

READER_FILES="trustless_read.cpp main.cpp account_history.cpp verify_state_root.cpp"

VIOLATIONS=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOLATIONS=$((VIOLATIONS + 1)); }

# ── check_invariants <dir> ──────────────────────────────────────────────────────
# Runs I1/I2/I3 against the light-client sources rooted at <dir>. Prints ok/bad and
# increments VIOLATIONS. Used against the real light/ (production) and against
# scratch copies (SELFTEST). All greps are over .cpp/.hpp only.
check_invariants() {
  local dir="$1"

  # I1: the vulnerable field-trust anchor pattern must be absent.
  # `!= vc.head_state_root` was the exact comparison every pre-fix reader used to
  # "trust" the daemon's head state_root field. Count across all light sources.
  local i1
  i1=$(grep -rhoE '!=[[:space:]]*vc\.head_state_root' "$dir" 2>/dev/null | wc -l | tr -d ' ')
  if [ "$i1" = "0" ]; then
    ok "I1 no '!= vc.head_state_root' field-trust anchor (S-042 pattern eradicated)"
  else
    bad "I1 found $i1 '!= vc.head_state_root' field-trust anchor(s) — S-042 REGRESSION"
    grep -rnE '!=[[:space:]]*vc\.head_state_root' "$dir" 2>/dev/null | sed 's/^/       /' >&2
  fi

  # I2: every reader file still calls committee_bound_state_root.
  local f n
  for f in $READER_FILES; do
    if [ ! -f "$dir/$f" ]; then
      bad "I2 reader file $f MISSING under $dir"
      continue
    fi
    n=$(grep -c "committee_bound_state_root" "$dir/$f" 2>/dev/null)
    if [ "$n" -ge 1 ]; then
      ok "I2 $f routes through committee_bound_state_root ($n ref(s))"
    else
      bad "I2 $f has ZERO committee_bound_state_root calls — a reader stopped binding state_root"
    fi
  done

  # I3: the helper retains its three load-bearing pieces (in trustless_read.cpp).
  local helper="$dir/trustless_read.cpp"
  if [ ! -f "$helper" ]; then
    bad "I3 trustless_read.cpp MISSING under $dir"
  else
    if grep -qE 'rpc\.call\("block"' "$helper"; then
      ok "I3a helper fetches the FULL block (rpc.call(\"block\"))"
    else
      bad "I3a helper no longer fetches the FULL block — state_root recompute is impossible from a stripped header"
    fi
    if grep -qE 'succ_prev[[:space:]]*!=[[:space:]]*recomputed_hex' "$helper"; then
      ok "I3b helper retains the successor-prev_hash binding check"
    else
      bad "I3b helper lost the 'succ_prev != recomputed_hex' binding check — state_root no longer bound to committee sigs"
    fi
    if grep -qE 'SECURITY' "$helper"; then
      ok "I3c helper retains a fail-closed SECURITY throw"
    else
      bad "I3c helper lost its SECURITY fail-closed throw"
    fi
  fi
}

# ── SELFTEST mode (SELFTEST=1) ──────────────────────────────────────────────────
# Prove the checks are LIVE: copy the real light/ sources into a scratch dir, inject
# one regression per invariant, and assert check_invariants flags each. Uses the SAME
# check_invariants the production path uses. No real source is modified.
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: S-042 binding-guard liveness (inject regressions -> expect RED) ==="
  ST_FAIL=0
  tmproot=$(mktemp -d 2>/dev/null || echo "/tmp/s042guard.$$")
  mkdir -p "$tmproot"
  trap 'rm -rf "$tmproot"' EXIT

  st_expect_red() {
    # $1 label  $2 scratch dir (already mutated). Runs the checks; expects >=1 violation.
    local label="$1" sdir="$2" before="$VIOLATIONS" delta
    check_invariants "$sdir" >/dev/null 2>&1
    delta=$((VIOLATIONS - before))
    VIOLATIONS="$before"   # reset — selftest must not pollute the real count
    if [ "$delta" -ge 1 ]; then echo "  ok:  $label -> flagged ($delta violation(s))"
    else
      echo "  bad: $label -> NOT flagged (guard is not live for this regression)" >&2
      ST_FAIL=$((ST_FAIL + 1))
    fi
  }

  # Sanity: a faithful copy of the real sources must PASS (zero violations).
  clean="$tmproot/clean"; mkdir -p "$clean"
  cp light/trustless_read.cpp light/main.cpp light/account_history.cpp \
     light/verify_state_root.cpp "$clean"/ 2>/dev/null
  before="$VIOLATIONS"; check_invariants "$clean" >/dev/null 2>&1
  if [ "$VIOLATIONS" = "$before" ]; then echo "  ok:  clean-copy sanity -> 0 violations"
  else echo "  bad: clean-copy sanity unexpectedly flagged" >&2; ST_FAIL=$((ST_FAIL + 1)); fi
  VIOLATIONS="$before"

  # R1: reintroduce the field-trust anchor in main.cpp.
  r1="$tmproot/r1"; mkdir -p "$r1"; cp "$clean"/* "$r1"/
  printf '\n    } else if (proof_root != vc.head_state_root) { throw 1; }\n' >> "$r1/main.cpp"
  st_expect_red "R1 reintroduced '!= vc.head_state_root' anchor" "$r1"

  # R2: strip committee_bound_state_root from a reader (account_history.cpp).
  r2="$tmproot/r2"; mkdir -p "$r2"; cp "$clean"/* "$r2"/
  sed 's/committee_bound_state_root/h.value_state_root_FIELD/g' "$clean/account_history.cpp" > "$r2/account_history.cpp"
  st_expect_red "R2 reader stopped calling committee_bound_state_root" "$r2"

  # R3: remove the helper's successor-prev_hash binding check.
  r3="$tmproot/r3"; mkdir -p "$r3"; cp "$clean"/* "$r3"/
  sed 's/succ_prev != recomputed_hex/false \/* binding removed *\//' "$clean/trustless_read.cpp" > "$r3/trustless_read.cpp"
  st_expect_red "R3 helper lost the successor binding check" "$r3"

  # R4: remove the helper's FULL-block fetch.
  r4="$tmproot/r4"; mkdir -p "$r4"; cp "$clean"/* "$r4"/
  sed 's/rpc\.call("block"/rpc.call("headers_stripped"/' "$clean/trustless_read.cpp" > "$r4/trustless_read.cpp"
  st_expect_red "R4 helper lost the FULL-block fetch" "$r4"

  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_light_state_root_binding_guard SELFTEST (flags all 4 regression classes)"
    exit 0
  else
    echo "  FAIL: test_light_state_root_binding_guard SELFTEST ($ST_FAIL self-test failure(s))"
    exit 1
  fi
fi

echo "=== S-042 light-client state_root binding regression guard (static; light/ sources) ==="
check_invariants light

echo ""
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "  PASS: test_light_state_root_binding_guard (S-042 binding intact: no field-trust anchor; all readers route through committee_bound_state_root; helper binding pieces present)"
  exit 0
else
  echo "  FAIL: test_light_state_root_binding_guard ($VIOLATIONS S-042 regression(s) — a trustless reader may again trust an unsigned state_root field)"
  exit 1
fi
