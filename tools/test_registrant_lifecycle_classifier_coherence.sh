#!/usr/bin/env bash
# test_registrant_lifecycle_classifier_coherence.sh — STATIC source guard for the
# light-client registrant deactivation classifier (register RP-5 /
# RegistrantProofSoundness).
#
# When the light client classifies a registrant against the committee-anchored
# head, deactivation is (light/main.cpp):
#     bool deactivated = (inactive_from != 0
#                         && inactive_from <= anchored_height);
# A registrant is deactivated iff it has a non-sentinel inactive_from (0 means
# "never deactivated") AND that height is at-or-below the committee-anchored head.
# The register's surviving mutant is `bool deactivated = false;` — a registrant
# deactivated as of the anchored height is then reported still-ACTIVE — or a
# dropped conjunct. Both survive every existing gate: the verdict is
# light-client-internal and no test drives a deactivated-registrant proof.
#
# This guard pins, at the PRODUCTION source (keyed on CONTENT, not a line number):
#   (1) NON-VACUITY: exactly ONE `bool deactivated =` assignment — a rename or
#       delete flips the count RED. The anchor is paren-independent so it stays
#       GREEN under the `-> false` mutation (which the CONTENT check then flags).
#   (2) CONTENT: the whitespace-normalised RHS (accumulated across the two
#       physical lines) == `(inactive_from!=0&&inactive_from<=anchored_height)`.
#   Plus per-conjunct diagnostics for a precise failure message.
#
# Pure read-only awk over one .cpp file. No build, no node, never SKIPs.
# `SELFTEST=1 bash tools/test_registrant_lifecycle_classifier_coherence.sh` drives
# a coherent statement and both mutants (`false`, dropped-conjunct) through the
# SAME extractor. Exit 0 = the classifier is exact; exit 1 = drift.
set -u
cd "$(dirname "$0")/.."

LIGHT_FILE=light/main.cpp
EXPECTED_DEACT_ASSIGNS=1
GOLDEN='(inactive_from!=0&&inactive_from<=anchored_height)'

# extract_deact <file> — prints "n|rhs":
#   n   = count of `bool deactivated =` assignments
#   rhs = whitespace-normalised RHS of the last one, accumulated to the `;`
extract_deact() {
  awk '
    /bool deactivated[ \t]*=/ && !cap { cap = 1; buf = "" }
    cap {
      line = $0; sub(/\/\/.*/, "", line)
      buf = buf " " line
      if (line ~ /;/) {
        n++
        expr = buf
        sub(/^.*bool deactivated[ \t]*=[ \t]*/, "", expr)  # keep RHS only
        sub(/;.*$/, "", expr)                              # drop ; onward
        gsub(/[ \t]+/, "", expr)                           # whitespace-normalize
        rhs = expr
        cap = 0
      }
    }
    END { printf "%d|%s\n", n, rhs }
  ' "$1"
}

# ── SELFTEST: the extractor + the drift rule are live ────────────────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: registrant deactivation-classifier source extractor ==="
  ST_FAIL=0
  GOOD=$(extract_deact /dev/stdin <<'EOF'
                        bool deactivated = (inactive_from != 0
                                            && inactive_from <= anchored_height);
EOF
)
  BAD_FALSE=$(extract_deact /dev/stdin <<'EOF'
                        bool deactivated = false;
EOF
)
  BAD_DROP=$(extract_deact /dev/stdin <<'EOF'
                        bool deactivated = (inactive_from != 0);
EOF
)
  if [ "$GOOD" = "1|$GOLDEN" ]; then
    echo "  ok:  a coherent classifier extracts as n=1 rhs=$GOLDEN [$GOOD]"
  else
    echo "  bad: coherent statement mis-extracted [$GOOD] (extractor wrong)" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi
  if [ "$BAD_FALSE" = "1|false" ]; then
    echo "  ok:  a '= false' mutant keeps the anchor (n=1) but flips the RHS [$BAD_FALSE]"
  else
    echo "  bad: '= false' mutant unexpected extraction [$BAD_FALSE]" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi
  case "$BAD_DROP" in
    1\|*'<=anchored_height'*) echo "  bad: dropped-conjunct mutant still has the anchored-height conjunct [$BAD_DROP]" >&2; ST_FAIL=$((ST_FAIL + 1)) ;;
    1\|*)                     echo "  ok:  a dropped-conjunct mutant is flagged (n=1, conjunct gone) [$BAD_DROP]" ;;
    *)                        echo "  bad: dropped-conjunct mutant unexpected extraction [$BAD_DROP]" >&2; ST_FAIL=$((ST_FAIL + 1)) ;;
  esac
  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_registrant_lifecycle_classifier_coherence SELFTEST (extractor flags a relaxed classifier)"
    exit 0
  else
    echo "  FAIL: test_registrant_lifecycle_classifier_coherence SELFTEST ($ST_FAIL self-test failure(s))"
    exit 1
  fi
fi

# ── MAIN: pin the live production classifier ──────────────────────────────────────
VIOL=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOL=$((VIOL + 1)); }

PROPS=$(extract_deact "$LIGHT_FILE")
N=${PROPS%%|*}
RHS=${PROPS#*|}

if [ "$N" -eq "$EXPECTED_DEACT_ASSIGNS" ]; then
  ok "exactly $EXPECTED_DEACT_ASSIGNS deactivation classifier (non-vacuity anchor holds)"
else
  bad "found $N 'bool deactivated =' assignments, expected $EXPECTED_DEACT_ASSIGNS (rename / delete / duplicate)"
fi

if [ "$RHS" = "$GOLDEN" ]; then
  ok "deactivated classifier RHS == golden [$RHS]"
else
  bad "deactivated RHS drifted: got [$RHS] want [$GOLDEN]"
fi

case "$RHS" in
  *'inactive_from!=0'*) ok "binds the inactive_from!=0 sentinel-live conjunct" ;;
  *)                    bad "sentinel conjunct (inactive_from!=0) dropped — the 0 = never-deactivated sentinel is mis-handled" ;;
esac

case "$RHS" in
  *'inactive_from<=anchored_height'*) ok "binds the inactive_from<=anchored_height conjunct" ;;
  *)                                  bad "anchored-height conjunct dropped — deactivation not evaluated against the committee-anchored head" ;;
esac

if [ "$RHS" != 'false' ]; then
  ok "classifier is not hardcoded false"
else
  bad "deactivated hardcoded false — a deactivated registrant would report still-ACTIVE"
fi

echo ""
if [ "$VIOL" -eq 0 ]; then
  echo "  PASS: test_registrant_lifecycle_classifier_coherence (the deactivation classifier is exact: inactive_from != 0 && inactive_from <= anchored_height)"
  exit 0
else
  echo "  FAIL: test_registrant_lifecycle_classifier_coherence ($VIOL violation(s) — the registrant deactivation classifier has drifted)"
  exit 1
fi
