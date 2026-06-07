#!/usr/bin/env bash
# test_tools_bash_n_surface.sh — syntactic-health meta-guard over tools/*.sh.
#
# run_all.sh only executes tools/test_*.sh, so a broken tools/operator_*.sh
# (or any non-test script) can sit in the tree unparseable and never be
# caught. This guard closes that gap: it runs `bash -n` over EVERY tools/*.sh
# and fails if any NON-quarantined script has a syntax error.
#
# Line-ending robustness: the check strips CR (\r) into a temp copy before
# `bash -n`, so a CRLF-but-syntactically-valid script passes on Windows
# git-bash and on Linux/Mac alike — only genuine syntax errors fail.
#
# Quarantine: an optional escape hatch (QUARANTINE below) for a path that must
# land broken before its fix — a quarantined script that fails is reported as
# `quarantine:` and does NOT fail the guard, while a NEW (non-quarantined)
# failure turns the test RED. QUARANTINE is currently EMPTY: the 11 scripts
# this guard discovered broken at R43 have all been repaired, so the guard now
# enforces zero syntax errors across every tools/*.sh. Prefer fixing over
# quarantining.
#
# Pure text/parse check — needs NO determ binary, never SKIPs. run_all judges
# outcome from the single terminal `  PASS:` / `  FAIL:` marker.
#
# Exit 0 = no new breakage; exit 1 = a non-quarantined script fails bash -n.
set -u
cd "$(dirname "$0")/.."

# Quarantine list — EMPTY. The 11 scripts discovered broken at R43 (committed
# CRLF + a `cmd <<'PY' || { echo…; exit 1; }` heredoc whose handler body was
# swallowed into the heredoc, leaving the `{` group unterminated) were all
# REPAIRED — the guard now enforces zero syntax errors across every tools/*.sh.
# Re-add a path here only as a temporary measure if a genuinely-broken script
# must land before its fix; prefer fixing.
QUARANTINE=""
is_quarantined() { printf '%s\n' "$QUARANTINE" | grep -qxF "$1"; }

OK=0; NEW_BAD=0; QUAR=0; FIXED=0
TMP="build/.bash_n_check.$$.sh"
mkdir -p build 2>/dev/null || true
trap 'rm -f "$TMP"' EXIT

echo "=== tools/*.sh syntactic-health guard (bash -n, CR-tolerant) ==="

for f in tools/*.sh; do
  [ -f "$f" ] || continue
  tr -d '\r' < "$f" > "$TMP" 2>/dev/null
  if bash -n "$TMP" 2>/dev/null; then
    OK=$((OK + 1))
    if is_quarantined "$f"; then
      echo "  fixed:      $f (was quarantined — now parses; prune from QUARANTINE)"
      FIXED=$((FIXED + 1))
    fi
  else
    if is_quarantined "$f"; then
      echo "  quarantine: $f (KNOWN-BROKEN — tracked for repair)"
      QUAR=$((QUAR + 1))
    else
      echo "  bad:        $f (NEW syntax error — bash -n failed)" >&2
      NEW_BAD=$((NEW_BAD + 1))
    fi
  fi
done

echo ""
echo "  scanned: $((OK + QUAR + NEW_BAD)) scripts — $OK ok, $QUAR quarantined, $NEW_BAD new-bad, $FIXED newly-fixed"
echo ""
if [ "$NEW_BAD" -eq 0 ]; then
  echo "  PASS: test_tools_bash_n_surface ($QUAR known-broken quarantined; no new breakage)"
  exit 0
else
  echo "  FAIL: test_tools_bash_n_surface ($NEW_BAD non-quarantined script(s) fail bash -n)"
  exit 1
fi
