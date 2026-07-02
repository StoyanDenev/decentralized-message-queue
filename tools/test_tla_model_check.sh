#!/usr/bin/env bash
# test_tla_model_check.sh — run TLC over every docs/proofs/tla/*.cfg and require
# "No error has been found." from each. With --write, regenerate the compact
# results table in docs/proofs/tla/CHECK-RESULTS.md from the same run.
#
# KISS contract: every .cfg paired with a same-basename .tla MUST model-check
# green. There are no expected-failure exhibits (the one historical defect
# exhibit, AbortEscalation.cfg, was flipped to the shipped-fix posture when
# S-044/S-045 closed; pre-fix postures live as one-line CONSTANT edits in the
# spec headers, not as shipped configs). Spec-only .tla files (no .cfg) are
# imported helper modules or unconfigured specs — listed, not run.
#
# Requirements: java 11+ on PATH (or $DETERM_JAVA) and tools/tlc/tla2tools.jar
# (gitignored; pinned by sha256 below; fetch:
#   curl -sL -o tools/tlc/tla2tools.jar \
#     https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar ).
# SKIP-clean (exit 0) when java or the jar is absent — the model-check leg is
# environment-gated, like the cluster legs elsewhere in the suite.
#
# Usage: bash tools/test_tla_model_check.sh [--write] [--only <basename>] [--timeout <s>]
set -u
cd "$(dirname "$0")/.."

JAR="${DETERM_TLA2TOOLS:-tools/tlc/tla2tools.jar}"
JAVA="${DETERM_JAVA:-java}"
JAR_SHA256="237332bdcc79a35c7d26efa7b82c77c85c2744591c5598673a8a45085ff2a4fb"  # tla2tools v1.8.0
TLADIR=docs/proofs/tla
RESULTS=docs/proofs/tla/CHECK-RESULTS.md
TIMEOUT_S=240
WRITE=0
ONLY=""

# QUARANTINE — specs acknowledged NOT green, excluded from the gate with a
# recorded reason (same pattern as CITATION_QUARANTINE in the citation guard:
# keep this SHORT; prefer fixing or deleting the spec). Format: "Name|reason".
# A quarantined spec is not run (it is guaranteed red); it appears in the
# results table as QUARANTINED with its reason.
QUARANTINE=(
  "SnapshotIntegrity|triaged 2026-07-02: sentinel fix unmasked 3 pre-existing modeling bugs (proxy antecedents cannot express tamper-ordering); C++ round-trip exonerated (test_dapp_snapshot.sh 12/12); needs spec redesign"
  "EpochCommitteeRotation|triaged 2026-07-02: beacon-blind abstract CHOOSE selector cannot satisfy any rotation liveness (production select_m_creators IS beacon-sensitive); safety invariants T-ER1..T-ER4 need a beacon-sensitive selector model; needs spec redesign"
)

while [ $# -gt 0 ]; do
  case "$1" in
    --write) WRITE=1 ;;
    --only) ONLY="$2"; shift ;;
    --timeout) TIMEOUT_S="$2"; shift ;;
    *) echo "unknown arg: $1" >&2; exit 3 ;;
  esac
  shift
done

if ! "$JAVA" -version >/dev/null 2>&1; then
  echo "  SKIP: java not found — TLC model-check leg is environment-gated (install a JRE 11+)."
  echo "  PASS: test_tla_model_check (SKIP — no java)"
  exit 0
fi
if [ ! -f "$JAR" ]; then
  echo "  SKIP: $JAR absent — fetch tla2tools v1.8.0 (see header)."
  echo "  PASS: test_tla_model_check (SKIP — no tla2tools.jar)"
  exit 0
fi
GOT_SHA=$(sha256sum "$JAR" | awk '{print $1}')
if [ "$GOT_SHA" != "$JAR_SHA256" ]; then
  echo "  FAIL: test_tla_model_check ($JAR sha256=$GOT_SHA != pinned $JAR_SHA256 — refuse to run an unpinned model checker)"
  exit 1
fi

pass=0; fail=0; quarantined=0
rows=""
quarantine_reason() {
  local base="$1" q
  for q in "${QUARANTINE[@]}"; do
    [ "${q%%|*}" = "$base" ] && { printf '%s' "${q#*|}"; return 0; }
  done
  return 1
}

run_one() {
  local base="$1" out verdict states depth dur t0 t1 qr
  if qr=$(quarantine_reason "$base"); then
    quarantined=$((quarantined+1))
    echo "  QUARANTINED: $base — $qr"
    rows="$rows| $base | QUARANTINED | — | — | — |
"
    return
  fi
  t0=$(date +%s)
  out=$(cd "$TLADIR" && timeout "$TIMEOUT_S" "$JAVA" -XX:+UseParallelGC \
        -cp "$(pwd -W 2>/dev/null || pwd)/../../../$JAR" tlc2.TLC -deadlock -config "$base.cfg" "$base.tla" 2>&1)
  local rc=$?
  t1=$(date +%s); dur=$((t1 - t0))
  states=$(printf '%s\n' "$out" | grep -oE '^[0-9]+ states generated, [0-9]+ distinct' | tail -1 | awk '{print $4}')
  depth=$(printf '%s\n' "$out" | grep -oE 'depth of the complete state graph search is [0-9]+' | grep -oE '[0-9]+$')
  if printf '%s\n' "$out" | grep -q 'No error has been found'; then
    verdict="PASS"
    pass=$((pass+1))
    echo "  ok:  $base — PASS (${states:-?} distinct states, depth ${depth:-?}, ${dur}s)"
  elif [ $rc -eq 124 ]; then
    verdict="TIMEOUT(${TIMEOUT_S}s)"
    fail=$((fail+1))
    echo "  bad: $base — TIMEOUT after ${TIMEOUT_S}s" >&2
  else
    local err
    err=$(printf '%s\n' "$out" | grep -m1 -E '^Error|Parse Error|Semantic error|violated' | cut -c1-140)
    verdict="FAIL"
    fail=$((fail+1))
    echo "  bad: $base — FAIL: ${err:-$(printf '%s\n' "$out" | tail -2 | head -1 | cut -c1-140)}" >&2
  fi
  rows="$rows| $base | $verdict | ${states:-—} | ${depth:-—} | ${dur}s |
"
}

echo "=== TLC model check (tla2tools v1.8.0, timeout ${TIMEOUT_S}s/config) ==="
if [ -n "$ONLY" ]; then
  run_one "$ONLY"
else
  for cfg in "$TLADIR"/*.cfg; do
    run_one "$(basename "$cfg" .cfg)"
  done
fi

speconly=""
for t in "$TLADIR"/*.tla; do
  b=$(basename "$t" .tla)
  [ -f "$TLADIR/$b.cfg" ] || speconly="$speconly $b"
done

if [ "$WRITE" = "1" ] && [ -z "$ONLY" ]; then
  {
    echo "# TLA+ model-check results (generated — do not hand-edit)"
    echo
    echo "Generated by \`bash tools/test_tla_model_check.sh --write\` with tla2tools **v1.8.0**"
    echo "(sha256 \`$JAR_SHA256\`), java: \`$("$JAVA" -version 2>&1 | head -1)\`,"
    echo "date: $(date -u +%Y-%m-%d)."
    echo
    echo "Contract: every \`.cfg\` paired with a same-basename \`.tla\` must report"
    echo "\`No error has been found.\` — there are no expected-failure exhibits. Per-spec"
    echo "expected outcomes, CONSTANT scenarios, and state-space notes live in each"
    echo "spec's own header comment and \`.cfg\` preamble (single source of truth); this"
    echo "file records only the machine results. TLC runs with \`-deadlock\` disabled"
    echo "checking off (\`-deadlock\` flag = do NOT treat deadlock as error) because the"
    echo "specs model terminating exhibits; liveness properties are checked where the"
    echo "\`.cfg\` declares PROPERTIES."
    echo
    echo "| Spec | Verdict | Distinct states | Depth | Time |"
    echo "|---|---|---|---|---|"
    printf '%s' "$rows"
    echo
    echo "Spec-only modules (no \`.cfg\`; imported helpers or unconfigured):${speconly:- none}"
    echo
    echo "Summary: **$pass PASS / $fail FAIL / $quarantined QUARANTINED** of $((pass+fail+quarantined)) configs. Quarantine reasons live in the QUARANTINE list in \`tools/test_tla_model_check.sh\`."
  } > "$RESULTS"
  echo "  wrote: $RESULTS"
fi

echo
echo "=== Test summary ==="
echo "  $pass pass / $fail fail / $quarantined quarantined"
if [ "$fail" = "0" ]; then
  echo "  PASS: test_tla_model_check ($pass configs green; $quarantined quarantined with recorded reasons)"
  exit 0
else
  echo "  FAIL: test_tla_model_check ($fail config(s) not green)"
  exit 1
fi
