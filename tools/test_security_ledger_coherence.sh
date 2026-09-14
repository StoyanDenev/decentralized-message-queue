#!/usr/bin/env bash
# test_security_ledger_coherence.sh — docs/SECURITY.md ledger coherence guard.
#
# Problem it solves (audit 2026-09-14): the §1 executive-summary counts and the
# §2 triage-table row statuses were hand-maintained independently, so the
# summary printed "Open: 0" for a month while the DECISION-LOG recorded nine
# open Criticals and a reopened S-052. The ledger is an authoritative no-TIER
# convergence point (CLAUDE.md); its summary must be DERIVED from its rows.
#
# Asserts, over docs/SECURITY.md only (pure grep/awk text check, no binary,
# never SKIPs):
#   (1) the §2 triage table exists (header `| ID | Sev | Title | ...`);
#   (2) the set of S-items named in the summary row "Open (untouched)" equals
#       the set of triage rows whose status cell contains "OPEN" (⚠ OPEN), and
#       that row's Total cell equals their count;
#   (3) the same for the summary row "Reopened" and status "REOPENED";
#   (4) no S-item named in the summary row "Mitigated in-session" has a triage
#       status containing "OPEN" or "REOPENED" (a reopened item may not also
#       be counted as mitigated).
#
# run_all.sh auto-discovers tools/test_*.sh and judges outcome from the single
# terminal `  PASS:` / `  FAIL:` marker; per-check lines use `  ok:` / `  drift:`.
# Exit 0 = coherent; exit 1 = ledger drift.
set -u
cd "$(dirname "$0")/.."

LEDGER="docs/SECURITY.md"
DRIFT=0
ok()    { echo "  ok:    $1"; }
drift() { echo "  drift: $1" >&2; DRIFT=$((DRIFT + 1)); }
verdict() {
  echo ""
  if [ "$DRIFT" -eq 0 ]; then echo "  PASS: $1"; exit 0
  else echo "  FAIL: $1 ($DRIFT drift)"; exit 1; fi
}

echo "=== security-ledger coherence guard (summary counts derived from triage rows) ==="

[ -f "$LEDGER" ] || { drift "$LEDGER not found"; verdict "test_security_ledger_coherence"; }

# (1) Triage table: rows from the `| ID | Sev | Title |` header to the next
# blank line. Emit "<id> <status-cell>" per row.
TRIAGE=$(awk '
  /^\| ID \| Sev \| Title \|/ { in_t = 1; next }
  in_t && /^[[:space:]]*$/     { in_t = 0 }
  in_t && /^\| S-[0-9]+ \|/ {
    n = split($0, c, "|"); id = c[2]; st = c[3];
    gsub(/^[ \t]+|[ \t]+$/, "", id); gsub(/^[ \t]+|[ \t]+$/, "", st);
    print id " " st
  }' "$LEDGER")
if [ -z "$TRIAGE" ]; then
  drift "no §2 triage table rows found (header '| ID | Sev | Title |')"
  verdict "test_security_ledger_coherence"
fi
ok "triage table: $(printf '%s\n' "$TRIAGE" | wc -l | tr -d ' ') S-rows"

# Sets of ids by status, sorted, one per line.
ids_with_status() {  # $1 = regex over the status cell
  printf '%s\n' "$TRIAGE" | awk -v re="$1" '{ st = $0; sub(/^[^ ]+ /, "", st); if (st ~ re) print $1 }' | sort -u
}
OPEN_ROWS=$(ids_with_status 'OPEN' | grep -v -x -F -f <(ids_with_status 'REOPENED') || true)
REOPENED_ROWS=$(ids_with_status 'REOPENED')

# Summary rows: ids listed in the row + the bold Total (last `**N**` cell).
summary_ids()   { grep -m1 "^| $1 |" "$LEDGER" | grep -o 'S-[0-9][0-9][0-9]' | sort -u; }
summary_total() { grep -m1 "^| $1 |" "$LEDGER" | grep -o '\*\*[0-9]*\*\*' | tail -1 | tr -d '*'; }

check_set() {  # $1 = summary row label, $2 = expected ids (sorted), $3 = status word
  local label="$1" expected="$2" word="$3" listed total n
  listed=$(summary_ids "$label")
  if [ -z "$(grep -m1 "^| $label |" "$LEDGER")" ]; then drift "summary row '$label' missing"; return; fi
  if [ "$listed" = "$expected" ]; then ok "summary '$label' names exactly the $word triage rows"
  else drift "summary '$label' lists [$(echo $listed)] but triage rows with status $word are [$(echo $expected)]"; fi
  total=$(summary_total "$label"); n=$(printf '%s' "$expected" | grep -c . || true)
  if [ "${total:-x}" = "$n" ]; then ok "summary '$label' total $total == $n $word rows"
  else drift "summary '$label' total is '${total:-?}' but $n triage rows carry status $word"; fi
}
check_set "Open (untouched)" "$OPEN_ROWS" "OPEN"
check_set "Reopened" "$REOPENED_ROWS" "REOPENED"

# (4) nothing counted as mitigated is open or reopened.
BAD=$(summary_ids "Mitigated in-session" | grep -x -F -f <(printf '%s\n%s\n' "$OPEN_ROWS" "$REOPENED_ROWS" | grep .) || true)
if [ -z "$BAD" ]; then ok "no mitigated-in-session item carries an OPEN/REOPENED triage status"
else drift "listed as mitigated but OPEN/REOPENED in the triage table: $(echo $BAD)"; fi

verdict "test_security_ledger_coherence"
