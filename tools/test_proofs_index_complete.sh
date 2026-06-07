#!/usr/bin/env bash
# test_proofs_index_complete.sh — proofs-index completeness guard.
#
# The proofs index docs/proofs/README.md is the single human-readable entry
# point into the per-property analytic proofs. A new PROOF doc dropped into
# docs/proofs/ can sit there un-indexed forever: nothing links it, so a
# reviewer walking the index never sees it. This guard closes that gap.
#
# Invariant: every docs/proofs/*.md (EXCLUDING README.md itself) is LINKED from
# the index — its basename appears as a Markdown link TARGET `](...<basename>)`
# somewhere in docs/proofs/README.md — UNLESS it is on the EXCLUDE list below. A
# bare backtick mention (`Foo.md`) in another row's prose is NOT a link target
# and does NOT count as indexed: the point is that the doc has its own reachable
# entry, not merely that its name is uttered. Detection is therefore the
# link-target form `]( ... basename )`, not a plain substring match.
#
# EXCLUDE list (the load-bearing distinction): a handful of PROCESS / SPEC /
# PLAN / GUIDANCE docs physically live under docs/proofs/ but are NOT formal
# theorem proofs and therefore are NOT entries in the formal-proofs index
# (docs/proofs/README.md is specifically the *proofs* index). These are pinned
# in EXCLUDE so the guard does not demand they be linked — e.g. DECISION-LOG,
# MAINNET_READINESS, *-PLAN, *-SPEC, *_GUIDANCE, Improvements,
# FROST_DEVIATION_NOTICE, UnitTestCoverageMap. Every other docs/proofs/*.md is
# a genuine proof and MUST be indexed; a NEW un-indexed proof (not on EXCLUDE)
# turns the guard RED. This is the inverse-allowlist pattern: the exception set
# is small, named, and rationale-documented, and the default is "must index".
#
# History: an earlier revision QUARANTINEd 32 docs (the 17 genuine but
# then-un-indexed S0xx / F2*Composition proofs + these 15 non-proof docs). The
# 17 proofs were subsequently back-filled into README.md (one house-style index
# row each), so the quarantine collapses to this 15-doc EXCLUDE list of genuine
# non-proof docs. Re-derive the current un-indexed set with:
#   for f in docs/proofs/*.md; do b=$(basename "$f"); [ "$b" = README.md ] && continue;
#     grep -qE "\]\([^)]*${b//./\\.}\)" docs/proofs/README.md || echo "$b"; done | sort
# That set must equal EXCLUDE (modulo any new proof you are mid-adding).
#
# Pure text/parse check over docs/ — needs NO determ binary, never SKIPs, so it
# does NOT source tools/common.sh (which would hard-exit without a binary).
# run_all.sh judges outcome from the single terminal `  PASS:` / `  FAIL:`
# marker; per-file results use neutral `  ok:` / `  exclude:` / `  bad:`
# prefixes so they cannot be mistaken for the test verdict.
#
# Exit 0 = every proof doc indexed (modulo EXCLUDE); exit 1 = NEW un-indexed.
set -u
cd "$(dirname "$0")/.."

PROOFS_DIR="docs/proofs"
README="$PROOFS_DIR/README.md"

# EXCLUDE — non-proof PROCESS / SPEC / PLAN / GUIDANCE docs that live under
# docs/proofs/ but are intentionally NOT entries in the formal-proofs index.
# Add a basename here ONLY for a genuinely-non-proof doc; for a real proof,
# LINK it into README.md instead (that is the whole point of this guard).
EXCLUDE="
CRYPTO-C99-SPEC.md
DAPP_SDK_GUIDANCE.md
DECISION-LOG.md
ECONOMICS_CONFIG_GUIDANCE.md
F2-V210-IMPLEMENTATION-PLAN.md
FROST_DEVIATION_NOTICE.md
IMPLEMENTATION-SEQUENCING.md
Improvements.md
MAINNET_READINESS.md
PFS_DEPLOYMENT_GUIDANCE.md
PRE-IMPLEMENTATION-REVIEW.md
UnitTestCoverageMap.md
V1.1-PLAN.md
V210-PhaseD-RandomnessWiring.md
v2.26-ROTATION-SPEC.md
"
is_excluded() { printf '%s\n' "$EXCLUDE" | grep -qxF "$1"; }

# Escape a basename for safe use inside the grep ERE link-target pattern
# (only '.' is special in a basename — turn each into '\.').
ere_escape() { printf '%s' "$1" | sed 's/\./\\./g'; }

# Is basename $1 present as a Markdown link target in README?  Matches the
# `]( ... <basename> )` form — covers `[txt](Foo.md)` and `[txt](sub/Foo.md)`.
is_indexed() {
  local esc; esc=$(ere_escape "$1")
  grep -qE "\]\([^)]*${esc}\)" "$README"
}

OK=0; EXCL=0; NEW_BAD=0

echo "=== proofs-index completeness guard (every docs/proofs/*.md proof linked in README.md) ==="

if [ ! -f "$README" ]; then
  echo "  bad:        $README not found — cannot verify index completeness" >&2
  echo ""
  echo "  FAIL: test_proofs_index_complete (index file missing)"
  exit 1
fi

for f in "$PROOFS_DIR"/*.md; do
  [ -f "$f" ] || continue
  b=$(basename "$f")
  [ "$b" = "README.md" ] && continue
  if is_indexed "$b"; then
    OK=$((OK + 1))
    echo "  ok:         $b"
  else
    if is_excluded "$b"; then
      echo "  exclude:    $b (non-proof process/spec/guidance doc — not an index entry)"
      EXCL=$((EXCL + 1))
    else
      echo "  bad:        $b (NEW un-indexed proof — add a link target in README.md)" >&2
      NEW_BAD=$((NEW_BAD + 1))
    fi
  fi
done

# Stale-EXCLUDE hygiene: an EXCLUDE entry whose file no longer exists, or which
# is now actually indexed, is dead weight — report (does NOT fail the guard).
while IFS= read -r e; do
  [ -z "$e" ] && continue
  if [ ! -f "$PROOFS_DIR/$e" ]; then
    echo "  note:       EXCLUDE entry '$e' has no file under $PROOFS_DIR — prune it"
  elif is_indexed "$e"; then
    echo "  note:       EXCLUDE entry '$e' is now indexed — prune it from EXCLUDE"
  fi
done <<< "$EXCLUDE"

echo ""
echo "  scanned: $((OK + EXCL + NEW_BAD)) proof-dir doc(s) — $OK indexed, $EXCL excluded (non-proof), $NEW_BAD new-unindexed"
echo ""
if [ "$NEW_BAD" -eq 0 ]; then
  echo "  PASS: test_proofs_index_complete (all proofs indexed; $EXCL non-proof docs excluded; no new drift)"
  exit 0
else
  echo "  FAIL: test_proofs_index_complete ($NEW_BAD new un-indexed proof doc(s) not linked in README.md)"
  exit 1
fi
