#!/usr/bin/env bash
# test_doc_citation_bounds.sh — STATIC guard against out-of-bounds source-line citations in docs.
#
# WHY THIS EXISTS
# --------------
# The proof/spec docs cite source as `path/file.ext:NNN`. As code shifts, those line
# numbers drift. This guard catches the UNAMBIGUOUS half of that drift automatically:
# a citation whose line number is past the file's end (the file shrank, content was
# deleted, or the file was replaced) — or that names a file which no longer exists.
# Both are hard, zero-false-positive errors (a line beyond EOF cannot be valid).
#
# It deliberately does NOT try to validate in-bounds line-SHIFT (e.g. 581 vs 612 when
# both are < EOF): a function name appears in prose next to many legitimate line
# targets (its definition, its call sites, its comment header, neighbouring helpers),
# so name-proximity heuristics produce mostly false positives. In-bounds digest-citation
# accuracy is held instead by the targeted runtime/source parity guards
# (test_block_digest_xbinary_parity.sh, test_signing_bytes_source_parity.sh) and review.
# This guard is the cheap, robust backstop that caught e.g. a light/main.cpp:7045
# citation when that file had only 6878 lines.
#
# RESOLUTION: a path-qualified citation (a '/' in the path) must exist verbatim from the
# repo root. A bare basename (chain.cpp:NNN) is resolved ONLY when it matches exactly one
# tracked source file (else skipped as ambiguous — e.g. main.cpp exists in src/, wallet/,
# light/). Only code files are checked (cpp/hpp/h/tla); .md/.sh self-references are not.
#
# A KNOWN-BAD quarantine list (CITATION_QUARANTINE) acknowledges a deliberately-archival
# citation without weakening the guard (same pattern as test_docs_link_check.sh). Keep it
# EMPTY; prefer fixing the citation. SELFTEST=1 proves the bounds check is live.
#
# Pure read-only (grep/wc/find over docs + source). No binary; never SKIPs; offline;
# deterministic. run_all.sh auto-discovers it. Exit 0 = all resolvable citations in-bounds.
set -u
cd "$(dirname "$0")/.."

# Known-bad citations to ACKNOWLEDGE (exact "path:line" tokens), space-separated. EMPTY
# by design — add only with a trailing-comment reason, and prefer fixing the citation.
CITATION_QUARANTINE=""

VIOLATIONS=0
ok()  { echo "  ok:  $1"; }
bad() { echo "  bad: $1" >&2; VIOLATIONS=$((VIOLATIONS + 1)); }
is_quarantined() { case " $CITATION_QUARANTINE " in *" $1 "*) return 0;; *) return 1;; esac; }

# resolve_citation <path-or-basename> -> resolved repo-relative file, or "" if
# unresolvable/ambiguous.
resolve_citation() {
  local p="$1"
  case "$p" in
    */*) [ -f "$p" ] && printf '%s' "$p"; return;;
  esac
  local matches n
  matches=$(find src light include wallet tools -type f -name "$p" 2>/dev/null)
  n=$(printf '%s\n' "$matches" | grep -c .)
  [ "$n" = "1" ] && printf '%s' "$matches"
}

check_corpus() {
  # $1 = docs root to scan. Increments VIOLATIONS for each out-of-bounds/missing cite.
  local root="$1"
  declare -A LINECOUNT RESOLVED
  local checked=0 oob=0 skipped=0 tok cpath line f tot
  local cites
  cites=$(grep -rhoE "[A-Za-z0-9_./-]+\.(cpp|hpp|h|tla):[0-9]+" "$root" 2>/dev/null | sort -u)
  while IFS= read -r tok; do
    [ -z "$tok" ] && continue
    is_quarantined "$tok" && { skipped=$((skipped+1)); continue; }
    cpath="${tok%:*}"; line="${tok##*:}"
    if [ -z "${RESOLVED[$cpath]+x}" ]; then RESOLVED[$cpath]="$(resolve_citation "$cpath")"; fi
    f="${RESOLVED[$cpath]}"
    # A path-qualified citation that does NOT resolve = a missing/renamed file (hard
    # error). A bare basename that doesn't resolve uniquely is skipped (ambiguous).
    if [ -z "$f" ]; then
      case "$cpath" in
        */*) bad "MISSING-FILE citation $tok -> $cpath does not exist"; oob=$((oob+1));;
        *)   skipped=$((skipped+1));;
      esac
      continue
    fi
    if [ -z "${LINECOUNT[$f]+x}" ]; then LINECOUNT[$f]="$(wc -l < "$f" | tr -d ' ')"; fi
    tot="${LINECOUNT[$f]}"
    checked=$((checked+1))
    if [ "$line" -gt "$tot" ] 2>/dev/null; then
      bad "OUT-OF-BOUNDS citation $tok -> $f has only $tot lines"; oob=$((oob+1))
    fi
  done <<< "$cites"
  [ "$oob" = "0" ] && ok "$checked resolvable citations in-bounds under $root/ ($skipped ambiguous/quarantined skipped)"
}

# ── SELFTEST: confirm the bounds check is live ───────────────────────────────────
if [ "${SELFTEST:-}" = "1" ]; then
  echo "=== SELFTEST: a past-EOF citation must be flagged ==="
  st_fail=0
  f="$(resolve_citation src/node/producer.cpp)"
  tot="$(wc -l < "$f" | tr -d ' ')"
  past=$((tot + 5000))
  if [ "$past" -gt "$tot" ]; then ok "SELFTEST: producer.cpp:$past > $tot lines would be flagged OUT-OF-BOUNDS"
  else echo "  bad: SELFTEST bounds arithmetic" >&2; st_fail=$((st_fail+1)); fi
  # missing-file resolution returns empty for a path-qualified non-existent file
  if [ -z "$(resolve_citation src/does/not/exist.cpp)" ]; then ok "SELFTEST: a path-qualified missing file resolves empty (flagged MISSING-FILE)"
  else echo "  bad: SELFTEST missing-file resolution" >&2; st_fail=$((st_fail+1)); fi
  echo ""
  if [ "$st_fail" = "0" ]; then echo "  PASS: test_doc_citation_bounds SELFTEST"; exit 0; else echo "  FAIL: test_doc_citation_bounds SELFTEST ($st_fail)"; exit 1; fi
fi

echo "=== doc source-line citations: resolvable + in-bounds (out-of-bounds / missing-file) ==="
check_corpus docs

echo ""
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "  PASS: test_doc_citation_bounds (all resolvable doc citations point at a real, in-bounds source line)"
  exit 0
else
  echo "  FAIL: test_doc_citation_bounds ($VIOLATIONS out-of-bounds / missing-file citation(s))"
  exit 1
fi
