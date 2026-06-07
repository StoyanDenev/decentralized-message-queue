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
# Quarantine: a set of pre-existing broken scripts (committed with CRLF +
# unterminated/indented `PY` heredocs, discovered R43 by this very guard) is
# listed below. A quarantined script that still fails is reported as
# `quarantine:` (KNOWN-BROKEN, tracked) and does NOT fail the guard — so the
# suite stays green while the debt is explicit and visible. The guard's
# forward value is real: any NEW (non-quarantined) script that fails to parse
# turns this test RED. A quarantined script that NOW parses is reported as
# `fixed:` so the list can be pruned.
#
# Tracking: the quarantined scripts are slated for repair (CRLF->LF + heredoc
# terminator fix, no logic change) as a dedicated task. When all are fixed,
# empty QUARANTINE below and this guard enforces zero syntax errors tree-wide.
#
# Pure text/parse check — needs NO determ binary, never SKIPs. run_all judges
# outcome from the single terminal `  PASS:` / `  FAIL:` marker.
#
# Exit 0 = no new breakage; exit 1 = a non-quarantined script fails bash -n.
set -u
cd "$(dirname "$0")/.."

# Known-broken (R43 discovery) — repair tracked separately. Keep sorted.
QUARANTINE="
tools/operator_account_balance_history.sh
tools/operator_account_growth.sh
tools/operator_block_creator_fairness.sh
tools/operator_chain_freshness.sh
tools/operator_chain_verify.sh
tools/operator_committee_rotation.sh
tools/operator_consensus_latency.sh
tools/operator_dapp_registration_audit.sh
tools/operator_param_history.sh
tools/operator_stake_yield.sh
tools/operator_validator_history.sh
"
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
