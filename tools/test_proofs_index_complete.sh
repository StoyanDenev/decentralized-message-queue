#!/usr/bin/env bash
# test_proofs_index_complete.sh — proofs-index completeness guard.
#
# The proofs index docs/proofs/README.md is the single human-readable entry
# point into the per-property analytic proofs. A new proof doc dropped into
# docs/proofs/ can sit there un-indexed forever: nothing links it, so a
# reviewer walking the index never sees it. This guard closes that gap.
#
# Invariant: every docs/proofs/*.md (EXCLUDING README.md itself) is LINKED from
# the index — its basename appears as a Markdown link TARGET `](...<basename>)`
# somewhere in docs/proofs/README.md. A bare backtick mention (`Foo.md`) in
# another row's prose is NOT a link target and does NOT count as indexed: the
# point is that the doc has its own reachable entry, not merely that its name is
# uttered. Detection is therefore the link-target form `]( ... basename )`, not
# a plain substring match.
#
# Quarantine: the QUARANTINE list below pins the genuine PRE-EXISTING set of
# un-indexed docs (mirrors the tools/test_tools_bash_n_surface.sh pattern). A
# quarantined un-indexed doc is reported `quarantine:` and does NOT fail the
# guard; a NEW (non-quarantined) un-indexed doc turns it RED. This keeps the
# guard GREEN on the current tree while still catching future drift — when a
# quarantined doc IS finally linked it is reported `fixed:` so the entry can be
# pruned. The list mixes two kinds of pre-existing offenders:
#   (a) genuine un-indexed PROOFS (the S0xx security-property proofs +
#       F2*Composition that belong in the index but were never linked), and
#   (b) deliberately-unlinked PROCESS / SPEC / GUIDANCE docs that live under
#       docs/proofs/ but are not index entries (DECISION-LOG, MAINNET_READINESS,
#       *-PLAN, *-SPEC, *_GUIDANCE, Improvements, etc.).
# Both are quarantined so the guard is conservative (zero false-positives) now;
# linking any of them later is a clean win the guard will flag as `fixed:`.
#
# Pure text/parse check over docs/ — needs NO determ binary, never SKIPs, so it
# does NOT source tools/common.sh (which would hard-exit without a binary).
# run_all.sh judges outcome from the single terminal `  PASS:` / `  FAIL:`
# marker; per-file results use neutral `  ok:` / `  quarantine:` / `  fixed:` /
# `  bad:` prefixes so they cannot be mistaken for the test verdict.
#
# Exit 0 = every proof doc indexed (modulo quarantine); exit 1 = NEW un-indexed.
set -u
cd "$(dirname "$0")/.."

PROOFS_DIR="docs/proofs"
README="$PROOFS_DIR/README.md"

# Quarantine — the genuine PRE-EXISTING un-indexed docs under docs/proofs/.
# Re-derive with:
#   for f in docs/proofs/*.md; do b=$(basename "$f"); [ "$b" = README.md ] && continue;
#     grep -qE "\]\([^)]*${b//./\\.}\)" docs/proofs/README.md || echo "$b"; done | sort
# Add a basename here only to keep the guard GREEN over a doc that is genuinely
# meant to stay unlinked; prefer LINKING new proofs into README.md instead.
QUARANTINE="
CRYPTO-C99-SPEC.md
DAPP_SDK_GUIDANCE.md
DECISION-LOG.md
ECONOMICS_CONFIG_GUIDANCE.md
F2-V210-IMPLEMENTATION-PLAN.md
F2ApplyComposition.md
F2RPCAuthEnvComposition.md
FROST_DEVIATION_NOTICE.md
IMPLEMENTATION-SEQUENCING.md
Improvements.md
MAINNET_READINESS.md
PFS_DEPLOYMENT_GUIDANCE.md
PRE-IMPLEMENTATION-REVIEW.md
S005PassphraseKeyfile.md
S008BoundedMempool.md
S009DelayHashRemoval.md
S013PerSignerCap.md
S014RateLimiterDDOSResistance.md
S015AsyncSavePersistence.md
S016InboundReceiptTimeOrdered.md
S019DAppEndpointSpoof.md
S020CommitteeSelection.md
S022WireFormatCapsCompleteness.md
S023NodeKeyfileEncryption.md
S024EpochBlocks.md
S025BFTEscalationSoundness.md
S026TcpKeepalive.md
S027InfoLeakage.md
UnitTestCoverageMap.md
V1.1-PLAN.md
V210-PhaseD-RandomnessWiring.md
v2.26-ROTATION-SPEC.md
"
is_quarantined() { printf '%s\n' "$QUARANTINE" | grep -qxF "$1"; }

# Escape a basename for safe use inside the ripgrep/grep ERE link-target pattern
# (only '.' is special in a basename — turn each into '\.').
ere_escape() { printf '%s' "$1" | sed 's/\./\\./g'; }

# Is basename $1 present as a Markdown link target in README?  Matches the
# `]( ... <basename> )` form — covers `[txt](Foo.md)` and `[txt](sub/Foo.md)`.
is_indexed() {
  local esc; esc=$(ere_escape "$1")
  grep -qE "\]\([^)]*${esc}\)" "$README"
}

OK=0; QUAR=0; NEW_BAD=0; FIXED=0

echo "=== proofs-index completeness guard (every docs/proofs/*.md linked in README.md) ==="

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
    if is_quarantined "$b"; then
      echo "  fixed:      $b (was quarantined — now linked in README; prune from QUARANTINE)"
      FIXED=$((FIXED + 1))
    else
      echo "  ok:         $b"
    fi
  else
    if is_quarantined "$b"; then
      echo "  quarantine: $b (KNOWN un-indexed — tracked; link it into README to clear)"
      QUAR=$((QUAR + 1))
    else
      echo "  bad:        $b (NEW un-indexed proof — add a link target in README.md)" >&2
      NEW_BAD=$((NEW_BAD + 1))
    fi
  fi
done

echo ""
echo "  scanned: $((OK + QUAR + NEW_BAD)) proof doc(s) — $OK indexed, $QUAR quarantined, $NEW_BAD new-unindexed, $FIXED newly-linked"
echo ""
if [ "$NEW_BAD" -eq 0 ]; then
  echo "  PASS: test_proofs_index_complete ($QUAR pre-existing un-indexed quarantined; no new drift)"
  exit 0
else
  echo "  FAIL: test_proofs_index_complete ($NEW_BAD new un-indexed proof doc(s) not linked in README.md)"
  exit 1
fi
