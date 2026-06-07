#!/usr/bin/env bash
# test_frost_chain_guard.sh — FROST-not-a-chain-primitive coherence RATCHET.
#
# Enforces docs/proofs/FROST_DEVIATION_NOTICE.md (2026-06-07, authority Stoyan
# Denev): FROST was a Claude-introduced design deviation and has been REMOVED
# from the v1.1 chain consensus path. The FROST C99 code under src/crypto/frost/
# is retained ONLY as a library; it is NOT a chain-consensus primitive, NOT in
# the v1.1 formal-verification surface, NOT in any substrate bundle.
#
# This guard is a ratchet: it FAILS if any of the T1-authoritative docs below
# re-asserts FROST AS a chain-consensus primitive (a "FROST-as-chain" claim).
# It scans ONLY the seven T1 docs — not the proofs/ or design docs, which
# legitimately discuss FROST's history, the C99 library, and the removal.
#
# How it judges a line (case-insensitive throughout):
#   1. Match the line against the INCOHERENT (FROST-as-chain) patterns below.
#   2. A matched line is EXCULPATED (NOT a violation) if it ALSO contains any
#      "explaining-the-removal" marker (removed from / library-only / not a
#      chain / FROST_DEVIATION_NOTICE / de-scoped / not in the chain). Those
#      lines are documenting the removal, which is exactly what we WANT.
#   3. Any matched-and-not-exculpated line is a VIOLATION.
#
# Conservative by construction: the incoherent-pattern set is the specific list
# of known re-introduction phrasings (not a blanket "any FROST mention"), so a
# doc that merely references FROST's library status or RFC pedigree does not
# trip the guard. New drift that re-asserts FROST-as-chain in a T1 doc turns it
# RED.
#
# Pure read-only TEXT check over docs/ (grep only) — needs NO determ binary, so
# it never SKIPs and does NOT source tools/common.sh (which would hard-exit
# without a built binary). run_all.sh auto-discovers it (tools/test_*.sh) and
# judges outcome from the SINGLE terminal `  PASS:` / `  FAIL:` marker; per-file
# results use a neutral `  ok:` / `  bad:` prefix so they cannot be mistaken for
# the test verdict.
#
# Exit 0 = coherent (FROST not re-asserted as a chain primitive); exit 1 = drift.
set -u
cd "$(dirname "$0")/.."

# ── The seven T1-authoritative docs (and ONLY these). ──────────────────────────
FILES="
docs/README.md
docs/PROTOCOL.md
docs/SECURITY.md
docs/WHITEPAPER-v1.x.md
docs/MOTIVATION.md
docs/CLI-REFERENCE.md
docs/QUICKSTART.md
"

# ── Incoherent FROST-as-chain patterns (case-insensitive, ERE). ────────────────
# A line matching ANY of these is asserting FROST as a chain-consensus primitive.
# Joined with alternation into one ERE.
INCOHERENT='FROST .*(DKG infra|infrastructure) .*retained|FROST.*shared foundation|retained for .*(Beaconless|threshold signing|cross-shard random)|v2\.10 FROST threshold-sig|FROST-Ed25519 optional, for co-sign'

# ── Exculpatory markers: a matched line carrying any of these is EXPLAINING the
#    removal, so it is OK (not a violation). Case-insensitive ERE. ──────────────
EXCULPATORY='removed from|library-only|not a chain|FROST_DEVIATION_NOTICE|de-scoped|DE-SCOPED|not in the chain'

VIOLATIONS=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOLATIONS=$((VIOLATIONS + 1)); }

echo "=== FROST-as-chain coherence guard (T1 docs; enforces FROST_DEVIATION_NOTICE.md) ==="

for f in $FILES; do
  if [ ! -f "$f" ]; then
    bad "$f — MISSING (expected T1 doc not found)"
    continue
  fi

  # Lines that match an incoherent pattern AND are NOT exculpated.
  # grep -inE prints "lineno:content"; the second grep -ivE drops exculpated lines.
  HITS=$(grep -inE -- "$INCOHERENT" "$f" 2>/dev/null | grep -ivE -- "$EXCULPATORY")

  if [ -z "$HITS" ]; then
    ok "$f — no FROST-as-chain assertion"
  else
    bad "$f — FROST re-asserted as a chain primitive (NOT explaining removal):"
    # Echo each offending line (with its line number) under the bad: marker.
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      echo "       $line" >&2
    done <<EOF
$HITS
EOF
  fi
done

echo ""
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "  PASS: test_frost_chain_guard (FROST not re-asserted as a chain primitive in any T1 doc)"
  exit 0
else
  echo "  FAIL: test_frost_chain_guard ($VIOLATIONS T1 doc(s) re-assert FROST-as-chain — see FROST_DEVIATION_NOTICE.md)"
  exit 1
fi