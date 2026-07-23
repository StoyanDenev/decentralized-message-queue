#!/usr/bin/env bash
# test_dapp_registry_active_boundary_coherence.sh — STATIC source guard for the
# light-client dapp-registry active/inactive boundary (register DR-6 /
# DAppRegistryReadSoundness).
#
# When the light client reports a DApp's active/inactive verdict against the
# committee-anchored head, the boundary is a STRICT inequality (light/main.cpp):
#     active = (anchored_height < inactive_from);
# The strictness is the security-relevant bit: a DApp deactivated at height H
# carries inactive_from == H, and a call anchored at exactly H must see it
# INACTIVE (DAPP_CALL is rejected once inactive_from <= height). The register's
# surviving mutant relaxes the boundary — `active = true;` (report every DApp
# active) or `<` -> `<=` (a DApp deactivated at exactly anchored_height is
# reported ACTIVE for one extra block). Both survive every existing gate: the
# verdict is light-client-internal, and no test drives a boundary-height DApp.
#
# This guard pins, at the PRODUCTION source, three things over the sole boundary
# site (keyed on CONTENT, not a line number):
#   (A) NON-VACUITY: exactly ONE `active = (anchored_height ...` site — a rename,
#       delete, or `-> true` rewrite drops the count to 0 -> RED.
#   (B) FULL-EXPRESSION: the whitespace-normalised RHS == `(anchored_height<inactive_from)`.
#   (C) STRICT-OPERATOR: the operator between the operands is exactly `<`, not `<=`.
#
# Pure read-only awk over one .cpp file. No build, no node, never SKIPs.
# `SELFTEST=1 bash tools/test_dapp_registry_active_boundary_coherence.sh` drives a
# coherent line and both mutants (`<=`, `true`) through the SAME extractor.
# Exit 0 = the boundary is the strict live comparison; exit 1 = drift.
set -u
cd "$(dirname "$0")/.."

LIGHT_FILE=light/main.cpp
EXPECTED_BOUNDARY_SITES=1

# extract_boundary <file> — prints "sites|expr|op" for the dapp active-boundary.
#   sites = count of `active = (anchored_height ...` lines (comment-stripped)
#   expr  = whitespace-normalised RHS of the last such assignment
#   op    = the operator token captured between anchored_height and inactive_from
extract_boundary() {
  awk '
    {
      line = $0; sub(/\/\/.*/, "", line)
      if (line ~ /active[ \t]*=[ \t]*\(anchored_height/) {
        sites++
        rhs = line
        sub(/^.*active[ \t]*=[ \t]*/, "", rhs)   # drop up to & incl "active ="
        sub(/;.*$/, "", rhs)                     # drop trailing ; and rest
        gsub(/[ \t]+/, "", rhs)                  # normalize whitespace
        expr = rhs
        op = rhs
        sub(/^.*anchored_height/, "", op)        # drop through the LHS operand
        sub(/inactive_from.*$/, "", op)          # drop from the RHS operand on
        sub(/^\(/, "", op); sub(/\)$/, "", op)   # defensive: strip stray parens
      }
    }
    END { printf "%d|%s|%s\n", sites, expr, op }
  ' "$1"
}

# ── SELFTEST: the extractor + the drift rule are live ────────────────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: dapp-registry active-boundary source extractor ==="
  ST_FAIL=0
  GOOD=$(extract_boundary /dev/stdin <<'EOF'
                        active = (anchored_height < inactive_from);
EOF
)
  BAD_LE=$(extract_boundary /dev/stdin <<'EOF'
                        active = (anchored_height <= inactive_from);
EOF
)
  BAD_TRUE=$(extract_boundary /dev/stdin <<'EOF'
                        active = true;
EOF
)
  if [ "$GOOD" = "1|(anchored_height<inactive_from)|<" ]; then
    echo "  ok:  a coherent strict boundary extracts as sites=1 expr=(anchored_height<inactive_from) op=< [$GOOD]"
  else
    echo "  bad: coherent line mis-extracted [$GOOD] (extractor wrong)" >&2
    ST_FAIL=$((ST_FAIL + 1))
  fi
  case "$BAD_LE" in
    1\|*\|\<) echo "  bad: <=-mutant NOT flagged (op still <) [$BAD_LE]" >&2; ST_FAIL=$((ST_FAIL + 1)) ;;
    1\|*)     echo "  ok:  a <=-relaxed boundary is flagged (sites still 1, op != <) [$BAD_LE]" ;;
    *)        echo "  bad: <=-mutant unexpected extraction [$BAD_LE]" >&2; ST_FAIL=$((ST_FAIL + 1)) ;;
  esac
  case "$BAD_TRUE" in
    0\|*) echo "  ok:  a constant-true rewrite is flagged (anchor dropped, sites 0) [$BAD_TRUE]" ;;
    *)    echo "  bad: constant-true mutant NOT flagged [$BAD_TRUE]" >&2; ST_FAIL=$((ST_FAIL + 1)) ;;
  esac
  echo ""
  if [ "$ST_FAIL" -eq 0 ]; then
    echo "  PASS: test_dapp_registry_active_boundary_coherence SELFTEST (extractor flags a relaxed boundary)"
    exit 0
  else
    echo "  FAIL: test_dapp_registry_active_boundary_coherence SELFTEST ($ST_FAIL self-test failure(s))"
    exit 1
  fi
fi

# ── MAIN: pin the live production boundary ────────────────────────────────────────
VIOL=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOL=$((VIOL + 1)); }

PROPS=$(extract_boundary "$LIGHT_FILE")
SITES=${PROPS%%|*}; REST=${PROPS#*|}
EXPR=${REST%%|*}
OP=${REST##*|}

if [ "$SITES" -eq "$EXPECTED_BOUNDARY_SITES" ]; then
  ok "exactly $EXPECTED_BOUNDARY_SITES dapp-registry active-boundary site (non-vacuity anchor holds)"
else
  bad "$SITES active-boundary sites, expected $EXPECTED_BOUNDARY_SITES (anchor drift / rewritten to a constant)"
fi

if [ "$EXPR" = "(anchored_height<inactive_from)" ]; then
  ok "active-boundary RHS == (anchored_height<inactive_from) [$EXPR]"
else
  bad "active-boundary RHS drifted to [$EXPR] — not the strict live comparison"
fi

if [ "$OP" = "<" ]; then
  ok "boundary operator is STRICT < (a DApp deactivated at exactly anchored_height reports INACTIVE)"
else
  bad "boundary operator is [$OP], not strict < — a DApp deactivated at exactly anchored_height would be reported ACTIVE"
fi

echo ""
if [ "$VIOL" -eq 0 ]; then
  echo "  PASS: test_dapp_registry_active_boundary_coherence (the dapp active/inactive boundary is the strict live comparison anchored_height < inactive_from)"
  exit 0
else
  echo "  FAIL: test_dapp_registry_active_boundary_coherence ($VIOL violation(s) — the dapp-registry active boundary has drifted)"
  exit 1
fi
