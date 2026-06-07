#!/usr/bin/env bash
# test_doc_tier_check.sh — 1.0 documentation-tiering coherence guard.
#
# Verifies the doc-freeze tiering invariant (ROADMAP index + TIER banners on
# the non-T1 docs). The on-disk truth is the literal banner marker `TIER:`
# carried on the first line of each non-T1 doc. Asserts:
#   (1) docs/ROADMAP.md exists — the single future-tier entry point.
#   (2) every doc carrying a `TIER:` banner references docs/ROADMAP.md in it.
#   (3) no doc carries MORE than one TIER banner (double-banner bug), and no
#       TIER banner is an orphan (fails to mention ROADMAP).
#
# Pure read-only TEXT check over docs/ (grep/find only) — needs NO determ
# binary, so it never SKIPs. run_all.sh auto-discovers it (tools/test_*.sh)
# and judges outcome from the SINGLE terminal `  PASS:` / `  FAIL:` marker;
# per-file results use a neutral `  ok:` / `  drift:` prefix so they cannot be
# mistaken for the test verdict.
#
# Exit 0 = coherent; exit 1 = tiering drift.
set -u
cd "$(dirname "$0")/.."

DOCS_DIR="docs"
ROADMAP="docs/ROADMAP.md"
ROADMAP_MARKER="ROADMAP.md"   # banner must reference the roadmap index
TIER_MARKER="TIER:"           # the literal banner marker scanned for

DRIFT=0
ok()    { echo "  ok:    $1"; }
drift() { echo "  drift: $1" >&2; DRIFT=$((DRIFT + 1)); }
verdict() {
  echo ""
  if [ "$DRIFT" -eq 0 ]; then echo "  PASS: $1"; exit 0
  else echo "  FAIL: $1 ($DRIFT drift)"; exit 1; fi
}

echo "=== doc-tiering coherence guard (ROADMAP index + non-T1 TIER banners) ==="

if [ ! -d "$DOCS_DIR" ]; then
  drift "docs/ directory not found"
  verdict "test_doc_tier_check"
fi

# (1) ROADMAP index exists.
if [ -f "$ROADMAP" ]; then ok "ROADMAP index present ($ROADMAP)"
else drift "ROADMAP index missing — expected $ROADMAP"; fi

# Derive the non-T1 set: every doc carrying the literal TIER: banner.
BANNERED=$(grep -rl -- "$TIER_MARKER" "$DOCS_DIR" 2>/dev/null | sort)
if [ -z "$BANNERED" ]; then
  ok "no TIER banners under $DOCS_DIR/ — nothing to check (vacuous)"
  verdict "test_doc_tier_check"
fi
N=$(printf '%s\n' "$BANNERED" | grep -c .)
echo "  scanned $DOCS_DIR/: $N file(s) carry a $TIER_MARKER banner"

# (2)+(3) per-file banner checks.
while IFS= read -r f; do
  [ -z "$f" ] && continue
  COUNT=$(grep -c -- "$TIER_MARKER" "$f")
  if [ "$COUNT" -gt 1 ]; then
    drift "$f — $COUNT TIER banners (double-banner; expected exactly 1)"
    continue
  fi
  if grep -- "$TIER_MARKER" "$f" | grep -q -- "$ROADMAP_MARKER"; then
    ok "$f — single banner links $ROADMAP_MARKER"
  else
    drift "$f — TIER banner does not mention $ROADMAP_MARKER (orphan banner)"
  fi
done <<EOF
$BANNERED
EOF

verdict "test_doc_tier_check"
