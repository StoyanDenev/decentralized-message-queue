#!/usr/bin/env bash
# test_light_resume_monotonicity_guard.sh — STATIC regression guard locking the
# LSP-7 head-monotonicity gates in determ-light's --resume path.
#
# THE FAIL-OPEN THIS GUARD LOCKS OUT (pre-LSP-7 behavior)
# -------------------------------------------------------
# anchored_head (light/trustless_read.cpp) is the single source of truth for
# the resume-or-full decision: every composite read and cmd_verify_chain route
# through it. The cached anchor is a previously COMMITTEE-VERIFIED head on the
# operator's genesis-pinned chain — load-bearing evidence, not merely a resume
# optimization. A fork-free chain never regresses, so:
#   * a daemon whose head is BELOW the cached anchor height is serving stale
#     or truncated state (e.g. restored from an old snapshot);
#   * a daemon EXACTLY AT the anchor height must present the very block the
#     cache recorded (anything else is a same-height fork at the anchor).
# Pre-LSP-7, BOTH cases silently fell back to a full from-genesis verify that
# ACCEPTED the shorter/stale chain at face value — the cache held the proof of
# regression and the code ignored it (the "(--resume: daemon not ahead of
# cached anchor … — full verify)" note). LSP-7 turns all three regression
# shapes into hard fail-closed throws:
#   (G1) daemon head <  anchor → throw (stale/truncated state);
#   (G2) daemon head == anchor → full verify + verified tip block_hash MUST
#        equal the cached anchor block_hash, else throw (same-height fork);
#   (G3) daemon head measured > anchor but the suffix walk's own head fetch
#        finds it ≤ anchor → throw (head regressed between queries).
#
# INVARIANTS (static, source-only over light/trustless_read.cpp)
# --------------------------------------------------------------
#   I1: the G1 regression throw is present inside anchored_head.
#   I2: the G2 cross-check is present (tip-vs-cache comparison + its throw).
#   I3: the G3 mid-session regression throw is present.
#   I4: anchored_head fetches the daemon head itself (fetch_head_height) —
#       the gates need their own measurement, not the suffix walk's.
#   I5: the pre-LSP-7 silent-fallback marker ("daemon not ahead of cached
#       anchor") is GONE — its reappearance means someone reopened the
#       fail-open path.
#
# SELFTEST=1: strips each gate from a scratch copy and asserts detection.
#
# Pure read-only (awk/grep over light/trustless_read.cpp); no binary, no
# build, no cluster. SKIP-clean (exit 0) when light/ is absent. run_all.sh
# auto-discovers it (tools/test_*.sh) and reads the terminal PASS:/FAIL:.
#
# Exit 0 = all LSP-7 gates present + fail-open marker absent; exit 1 = a gate
# was removed/weakened or the silent fallback returned.
set -u
cd "$(dirname "$0")/.."

SRC="light/trustless_read.cpp"

VIOLATIONS=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOLATIONS=$((VIOLATIONS + 1)); }

echo "=== LSP-7 resume head-monotonicity guard (anchored_head gates) ==="

if [ ! -f "$SRC" ]; then
  echo "  SKIP: $SRC absent — nothing to guard (source-light checkout)."
  echo "  PASS: test_light_resume_monotonicity_guard (SKIP — target absent)"
  exit 0
fi

# extract_anchored_head <file> — the anchored_head function body (definition
# line to the next closing brace at column 0). CR-tolerant.
extract_anchored_head() {
  awk '
    /^AnchoredHead anchored_head\(/ { in_fn = 1 }
    in_fn { print }
    in_fn && /^\}/ { exit }
  ' "$1" | tr -d '\r'
}

check_gates() {  # check_gates <file> <label-prefix>
  local body f="$1" pfx="$2" fails=0
  body=$(extract_anchored_head "$f")
  if [ -z "$body" ]; then
    bad "${pfx}anchored_head definition not found in $f"
    return 1
  fi

  # I1 — G1 regression throw.
  if printf '%s' "$body" | grep -q "is BELOW the previously committee-verified anchor"; then
    ok "${pfx}I1: G1 daemon-below-anchor throw present"
  else
    bad "${pfx}I1: G1 regression throw MISSING (daemon below anchor would be accepted)"
    fails=$((fails + 1))
  fi

  # I2 — G2 equal-height cross-check: the comparison AND its throw.
  if printf '%s' "$body" | grep -q "head_block_hash != st.head_block_hash" \
     && printf '%s' "$body" | grep -q "same-height fork at the anchor"; then
    ok "${pfx}I2: G2 equal-height tip-vs-cache cross-check + throw present"
  else
    bad "${pfx}I2: G2 cross-check MISSING (same-height fork at the anchor would be accepted)"
    fails=$((fails + 1))
  fi

  # I3 — G3 mid-session regression throw.
  if printf '%s' "$body" | grep -q "between queries — inconsistent daemon"; then
    ok "${pfx}I3: G3 mid-session head-regression throw present"
  else
    bad "${pfx}I3: G3 between-queries regression throw MISSING"
    fails=$((fails + 1))
  fi

  # I4 — the gates take their own head measurement.
  if printf '%s' "$body" | grep -q "fetch_head_height(rpc)"; then
    ok "${pfx}I4: anchored_head measures the daemon head itself"
  else
    bad "${pfx}I4: fetch_head_height call MISSING from anchored_head (gates have no input)"
    fails=$((fails + 1))
  fi

  # I5 — the pre-LSP-7 fail-open marker is gone.
  if printf '%s' "$body" | grep -q "daemon not ahead of cached anchor"; then
    bad "${pfx}I5: the pre-LSP-7 silent-fallback note RETURNED (fail-open reopened)"
    fails=$((fails + 1))
  else
    ok "${pfx}I5: pre-LSP-7 silent-fallback marker absent"
  fi

  # I6 — TWO suffix-walk calls: the > path's resume AND the ==-race anchor
  # binding (a block landing between the two head fetches must not silently
  # drop the anchor binding). One call means the race-path binding was removed.
  local walk_calls
  walk_calls=$(printf '%s' "$body" | grep -c "verify_chain_from_anchor(")
  if [ "$walk_calls" -eq 2 ]; then
    ok "${pfx}I6: both suffix-walk call sites present (resume + ==-race anchor binding)"
  else
    bad "${pfx}I6: expected 2 verify_chain_from_anchor calls in anchored_head, found $walk_calls (race-path anchor binding dropped?)"
    fails=$((fails + 1))
  fi

  return "$fails"
}

check_gates "$SRC" "" || true

# ── SELFTEST: prove each invariant detector is live ─────────────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo
  echo "=== SELFTEST: strip each gate -> expect detection ==="
  ST_FAIL=0
  tmp=$(mktemp -d 2>/dev/null || echo "/tmp/lsp7.$$"); mkdir -p "$tmp"
  trap 'rm -rf "$tmp"' EXIT

  # (a) strip the G1 throw token.
  sed 's/is BELOW the previously committee-verified anchor/NEUTERED_G1/' \
      "$SRC" > "$tmp/a.cpp"
  if extract_anchored_head "$tmp/a.cpp" | grep -q "is BELOW the previously committee-verified anchor"; then
    echo "  bad: SELFTEST(a) failed to neutralize G1" >&2; ST_FAIL=$((ST_FAIL + 1))
  else
    echo "  ok:  G1 strip detected (I1 detector live)"
  fi

  # (b) strip the G2 comparison.
  sed 's/head_block_hash != st.head_block_hash/NEUTERED_G2/' \
      "$SRC" > "$tmp/b.cpp"
  if extract_anchored_head "$tmp/b.cpp" | grep -q "head_block_hash != st.head_block_hash"; then
    echo "  bad: SELFTEST(b) failed to neutralize G2" >&2; ST_FAIL=$((ST_FAIL + 1))
  else
    echo "  ok:  G2 strip detected (I2 detector live)"
  fi

  # (c) re-introduce the fail-open marker.
  awk '/^AnchoredHead anchored_head\(/ { print; print "// daemon not ahead of cached anchor"; next } { print }' \
      "$SRC" > "$tmp/c.cpp"
  if extract_anchored_head "$tmp/c.cpp" | grep -q "daemon not ahead of cached anchor"; then
    echo "  ok:  fail-open marker re-introduction detected (I5 detector live)"
  else
    echo "  bad: SELFTEST(c) could not see the re-introduced marker" >&2; ST_FAIL=$((ST_FAIL + 1))
  fi

  echo
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_light_resume_monotonicity_guard SELFTEST (all detectors live)"
  else
    echo "  FAIL: test_light_resume_monotonicity_guard SELFTEST"
    exit 1
  fi
fi

echo
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "  PASS: test_light_resume_monotonicity_guard (LSP-7 gates present; fail-open path closed)"
  exit 0
else
  echo "  FAIL: test_light_resume_monotonicity_guard ($VIOLATIONS LSP-7 violation(s))"
  exit 1
fi
