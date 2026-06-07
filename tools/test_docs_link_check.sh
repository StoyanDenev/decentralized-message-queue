#!/usr/bin/env bash
# test_docs_link_check.sh — 1.0 CONSERVATIVE broken-intra-repo-link detector.
#
# Walks every Markdown file under docs/ and, for each, extracts
#   (a) Markdown links     [text](target)
#   (b) backticked paths   `target`
# and flags a target as BROKEN only when it is UNAMBIGUOUSLY an intra-repo file
# path that resolves to NO existing file on disk. Zero false-positives is the
# priority — a guard that cries wolf gets disabled and protects nothing.
#
# ---------------------------------------------------------------------------
# WHY MARKDOWN-LINK SYNTAX IS AUTHORITATIVE, BACKTICKS ARE NOT
# ---------------------------------------------------------------------------
# Empirically (this tree, authoring time): EVERY true Markdown `[text](target)`
# link resolves — there are zero broken `](...)` targets across all docs. The
# only "misses" come from BACKTICKED spans, and inspecting them shows they are
# overwhelmingly NOT links but code-identifier prose the docs use deliberately:
#   * bare basenames / partial paths   `main.cpp`, `chain/params.hpp`
#       (the real file is include/determ/chain/params.hpp — the doc shortens it)
#   * glob / wildcard patterns         `tools/test_*.sh`, `operator_*.sh`, `.md`
#   * runtime / generated artifacts    `chain.json`, `genesis.json`,
#       `~/.determ-light/state.json`, `%APPDATA%\determ\config.json`
#   * template placeholders            `tools/test_<feature>.sh`,
#       `tools/vectors/<primitive>.json`
# A backticked basename is therefore AMBIGUOUS — it is not "unambiguously an
# intra-repo file path." So:
#   - A Markdown `](target)` link is treated as an UNAMBIGUOUS intra-repo link:
#     if it has a real source extension and resolves nowhere, it is BROKEN.
#   - A backticked `target` is checked POSITIVELY only: it counts toward the
#     resolved tally when it both contains a directory separator ("/") AND
#     resolves; otherwise it is silently skipped. Backticks can never, by
#     themselves, turn the guard RED. (Wildcards/placeholders containing
#     * ? < > { } and whitespace are skipped outright.)
# This honours "extract backticked file paths" while staying conservative.
#
# Resolution: before resolving, SKIP http(s)://, any scheme://, mailto:,
# protocol-relative //, and pure #anchor fragments; STRIP a trailing #anchor.
# Only targets ending in .md/.tla/.sh/.cpp/.hpp/.json are considered. A
# (possibly relative) target is resolved against, in order:
#   1. the LINKING FILE'S OWN directory   (relative links)
#   2. the repo root                      (../-style + root-relative)
#   3. docs/                              (proofs link docs/ siblings bare)
#   4. docs/proofs/                       (proofs cross-ref each other bare,
#                                          e.g. `SECURITY.md`, `Preliminaries.md`)
#   5. docs/proofs/tla/                   (TLA+ modules live one level deeper)
# Only if it resolves in NONE of those is a Markdown-link target flagged BROKEN.
#
# Pure text/parse check over docs/ — needs NO determ binary, so it never SKIPs
# and does NOT source common.sh (which would hard-exit without a binary).
# run_all.sh judges outcome from the SINGLE terminal `  PASS:` / `  FAIL:`
# marker; per-item results use a NEUTRAL `  ok:` / `  bad:` / `  quarantine:`
# prefix so they can never be mistaken for the test verdict.
#
# Quarantine: an optional escape hatch (QUARANTINE below) — a "file|target"
# pair listed there that is broken is reported as `quarantine:` and does NOT
# fail the guard, while any NEW broken Markdown link turns the test RED.
# QUARANTINE is currently EMPTY (the tree resolved clean at authoring time).
# Prefer FIXING a broken link over quarantining it.
#
# Exit 0 = no new broken intra-repo Markdown links; exit 1 = a new one found.
set -u
cd "$(dirname "$0")/.."

DOCS_DIR="docs"

# Quarantine list — EMPTY. Add a "relative/file.md|target" line ONLY as a
# temporary measure if a genuinely-broken Markdown link must land before its
# fix. Match is on the literal "<linking-file-relpath>|<raw-target>" string.
QUARANTINE=""
is_quarantined() { printf '%s\n' "$QUARANTINE" | grep -qxF "$1"; }

OK=0; NEW_BAD=0; QUAR=0
bad()        { echo "  bad:        $1" >&2; NEW_BAD=$((NEW_BAD + 1)); }
quarantine() { echo "  quarantine: $1"; QUAR=$((QUAR + 1)); }

echo "=== docs/ intra-repo broken-link guard (conservative; .md/.tla/.sh/.cpp/.hpp/.json) ==="

if [ ! -d "$DOCS_DIR" ]; then
  bad "docs/ directory not found"
  echo ""
  echo "  FAIL: test_docs_link_check (docs/ missing)"
  exit 1
fi

# Classify a raw target. On success sets RESOLVED_TARGET to the anchor-stripped
# path and returns 0 (a real source-file path worth resolving); returns 1 to
# skip (URL / anchor / mailto / non-source-extension / wildcard / placeholder).
RESOLVED_TARGET=""
should_check() {
  local t="$1"
  RESOLVED_TARGET=""
  # Pure anchor fragment — skip.
  case "$t" in \#*) return 1 ;; esac
  # Any URI scheme (http:, https:, mailto:, ftp:, file:, ...) or a stray colon
  # (Windows-ish paths, %APPDATA% expansions) — skip conservatively.
  case "$t" in
    *://*)    return 1 ;;
    mailto:*) return 1 ;;
    *:*)      return 1 ;;
  esac
  # Protocol-relative "//host/..." — skip.
  case "$t" in //*) return 1 ;; esac
  # Wildcards / glob / template placeholders — not a concrete path; skip.
  case "$t" in
    *"*"*|*"?"*|*"<"*|*">"*|*"{"*|*"}"*) return 1 ;;
  esac
  # Strip a trailing #anchor (keep the file part).
  local path="${t%%#*}"
  [ -z "$path" ] && return 1
  # Must end in a recognised real source-file extension.
  case "$path" in
    *.md|*.tla|*.sh|*.cpp|*.hpp|*.json) ;;
    *) return 1 ;;
  esac
  RESOLVED_TARGET="$path"
  return 0
}

# Resolve RESOLVED_TARGET against the linking file's dir, then repo-root, docs/,
# docs/proofs/, docs/proofs/tla/. Returns 0 if any candidate exists.
# $1 = directory of the linking file (repo-relative).
resolves() {
  local linkdir="$1"
  local p="$RESOLVED_TARGET"
  local base
  for base in "$linkdir" "." "docs" "docs/proofs" "docs/proofs/tla"; do
    [ -e "$base/$p" ] && return 0
  done
  # Absolute-from-repo-root targets like "/docs/X.md" (leading slash).
  case "$p" in
    /*) [ -e ".${p}" ]  && return 0
        [ -e "${p#/}" ] && return 0 ;;
  esac
  return 1
}

# Extract candidate targets from one file and check each.
# $1 = repo-relative path to the markdown file.
check_file() {
  local f="$1"
  local dir
  dir="$(dirname "$f")"

  # Materialise the CR-stripped body FIRST, then run each grep against it
  # separately. Piping the same stdin into two greps in a { ...; } group does
  # NOT work — the first grep drains the pipe and the second sees EOF, silently
  # dropping every backticked target.
  local body md_links bt_spans
  body="$(tr -d '\r' < "$f")"
  md_links="$(printf '%s\n' "$body" | grep -oE '\]\([^)]+\)' || true)"
  bt_spans="$(printf '%s\n' "$body" | grep -oE '`[^`]+`'    || true)"

  # --- (a) Markdown links: UNAMBIGUOUS — a broken one fails the guard. ---
  local raw t key
  while IFS= read -r raw; do
    [ -z "$raw" ] && continue
    t="${raw#](}"; t="${t%)}"
    t="${t#"${t%%[![:space:]]*}"}"; t="${t%"${t##*[![:space:]]}"}"
    [ -z "$t" ] && continue
    case "$t" in *" "*) continue ;; esac   # real link target has no interior space
    should_check "$t" || continue
    if resolves "$dir"; then
      OK=$((OK + 1))
    else
      key="$f|$t"
      if is_quarantined "$key"; then
        quarantine "$key (KNOWN-BROKEN — tracked for repair)"
      else
        bad "$f -> $t (markdown link resolves nowhere: linkdir/root/docs/proofs/tla)"
      fi
    fi
  done <<EOF
$md_links
EOF

  # --- (b) Backticked spans: AMBIGUOUS — checked POSITIVELY only. A backtick   ---
  #     span counts toward the resolved tally only when it carries a directory
  #     separator (so it is plausibly a path, not a bare code identifier) AND
  #     actually resolves. It can never turn the guard RED.
  while IFS= read -r raw; do
    [ -z "$raw" ] && continue
    t="${raw#\`}"; t="${t%\`}"
    t="${t#"${t%%[![:space:]]*}"}"; t="${t%"${t##*[![:space:]]}"}"
    [ -z "$t" ] && continue
    case "$t" in *" "*) continue ;; esac   # prose span with spaces — not a path
    case "$t" in */*) ;; *) continue ;; esac  # require a "/" separator to be unambiguous
    should_check "$t" || continue
    if resolves "$dir"; then
      OK=$((OK + 1))
    fi
    # else: a bare/partial backticked path that does not resolve is EXPECTED
    # (docs use shortened paths as code identifiers) — silently ignore.
  done <<EOF
$bt_spans
EOF
}

# Walk every markdown file under docs/.
FILES="$(find "$DOCS_DIR" -type f -name '*.md' 2>/dev/null | sort)"
NFILES=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  NFILES=$((NFILES + 1))
  check_file "$f"
done <<EOF
$FILES
EOF

echo "  ok:         scanned $NFILES markdown file(s) under $DOCS_DIR/"

echo ""
echo "  checked targets: $OK resolved-ok, $QUAR quarantined, $NEW_BAD new-broken"
echo ""
if [ "$NEW_BAD" -eq 0 ]; then
  echo "  PASS: test_docs_link_check ($QUAR known-broken quarantined; no new broken intra-repo links)"
  exit 0
else
  echo "  FAIL: test_docs_link_check ($NEW_BAD new broken intra-repo Markdown link(s))"
  exit 1
fi