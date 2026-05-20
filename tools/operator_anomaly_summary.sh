#!/usr/bin/env bash
# operator_anomaly_summary.sh — Meta-aggregator that runs a curated set
# of operator_*.sh audit scripts against a single running determ
# daemon and emits a unified "anomaly dashboard" summary across all of
# them. Read-only RPC; safe against any running daemon.
#
# Role vs. the individual operator_*.sh scripts: each operator_X.sh is
# a focused, single-concern check (supply A1, head freshness, stake
# positions, DApp registry, ...). This script is the "dashboard
# composer" — it invokes each member of a curated set, collects each
# script's exit code + JSON output, and rolls up a single
# operator-facing summary: total anomalies, per-source breakdown,
# errored sources. The intended use is one-shot ops-readiness checks
# and cron-driven paging on the rolled-up status.
#
# Curated set (5 scripts):
#   operator_chain_health.sh     — daemon up / A1 ok / >=1 peer
#   operator_supply_check.sh     — A1 unitary-supply invariant
#   operator_block_lag_check.sh  — head.timestamp freshness vs wall-clock
#   operator_stake_audit.sh      — validator-set stake-position audit
#   operator_dapp_audit.sh       — on-chain DApp-registry inventory
#
# Per-source invocation pattern:
#   bash tools/operator_X.sh --rpc-port $PORT [--anomalies-only] --json
#
# Not every member script honors --anomalies-only — chain_health,
# supply_check, block_lag_check are single-fact checks that already
# encode the anomaly via exit code (2 = anomaly fired). For those,
# --anomalies-only is omitted from the per-script invocation; the
# JSON they emit lacks a `.anomalies` array but the universal exit
# contract is preserved.
#
# Universal exit-code contract for every operator_*.sh:
#   0 — clean / no anomaly
#   1 — RPC / script error
#   2 — at least one anomaly detected (operator alert gate)
#
# Per-source anomaly count extraction (in order of preference):
#   (a) `.anomalies | length` from JSON output  — used by scripts with
#       explicit anomaly-array surface (block_lag_check has no array;
#       account_growth-class scripts do).
#   (b) `.summary.anomaly_count`                — used by stake_audit.
#   (c) Fallback: 1 if exit code == 2, else 0   — universal exit-code
#       interpretation; covers chain_health, supply_check,
#       block_lag_check, and dapp_audit (the last has no anomaly
#       surface at all — it only fires exit 1 on RPC error and
#       always exits 0 otherwise, so it always contributes zero).
#
# Usage:
#   tools/operator_anomaly_summary.sh [--rpc-port N] [--json]
#
# Exit codes (rolled up from per-source results):
#   0 — every source clean
#   1 — at least one source returned an error
#   2 — at least one source reported an anomaly (no errors); operator
#       alert gate
set -u

usage() {
  cat <<'EOF'
Usage: operator_anomaly_summary.sh [--rpc-port N] [--json]

Run a curated set of operator_*.sh audit scripts against a single
running determ daemon and report a unified anomaly summary.

Curated sources:
  operator_chain_health.sh     — daemon / A1 / peer count
  operator_supply_check.sh     — A1 unitary-supply invariant
  operator_block_lag_check.sh  — head.timestamp freshness
  operator_stake_audit.sh      — validator-set stake-position audit
  operator_dapp_audit.sh       — on-chain DApp-registry inventory

For each source we capture:
  - exit code  (0 clean, 1 error, 2 anomaly fired)
  - JSON output (parsed for richer anomaly count when available)

Roll-up logic:
  total_anomalies = sum across sources
  errored_count   = sources that exited 1

Options:
  --rpc-port N    RPC port to query (default: 7778)
  --json          Emit structured JSON instead of human dashboard
  -h, --help      Show this help

Exit codes:
  0   every source clean
  1   at least one source errored
  2   at least one source reported an anomaly (no errors)
EOF
}

PORT=7778
JSON=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --rpc-port) PORT="${2:-}"; shift 2 ;;
    --json) JSON=1; shift ;;
    *) echo "operator_anomaly_summary: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guard on --rpc-port (mirrors the sibling operator_*.sh
# convention so misspellings fail fast rather than silently routing
# to default 7778).
case "$PORT" in *[!0-9]*|"")
  echo "operator_anomaly_summary: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_anomaly_summary: requires 'jq' (not found on PATH)" >&2
  exit 1
fi

# ── Curated source table ──────────────────────────────────────────────────────
# Each row: <script-name>|<supports-anomalies-only flag (0/1)>
# The "supports anomalies-only" column gates whether we pass that flag
# in the per-script invocation. Scripts that don't honor it would
# either ignore the flag silently or fail "unknown argument"; we keep
# the invocation tight to avoid relying on either behavior.
SOURCES=(
  "operator_chain_health.sh|0"
  "operator_supply_check.sh|0"
  "operator_block_lag_check.sh|0"
  "operator_stake_audit.sh|1"
  "operator_dapp_audit.sh|0"
)

# ── Per-source invocation ─────────────────────────────────────────────────────
# We collect lines of <name>\t<rc>\t<count>\t<status>\t<detail> into a
# tmp file so the JSON-emitter pass can replay them in order.
TMP_ROWS=$(mktemp)
trap 'rm -f "$TMP_ROWS"' EXIT

TOTAL_ANOMALIES=0
ERRORED_COUNT=0
ANOMALY_SOURCES=0

# Parse anomaly count from a single source's JSON output.
# Inputs: $1 = JSON string (possibly empty), $2 = exit code from script.
# Echoes a non-negative integer. The preference order matches the
# header comment.
extract_count() {
  local out="$1" rc="$2" n
  if [ -n "$out" ]; then
    # (a) `.anomalies | length` if the array exists.
    n=$(printf '%s' "$out" | jq -r 'if (.anomalies | type) == "array" then (.anomalies | length) else empty end' 2>/dev/null || true)
    if [ -n "$n" ] && [ "$n" != "null" ]; then
      printf '%s' "$n"
      return
    fi
    # (b) `.summary.anomaly_count` if present and numeric.
    n=$(printf '%s' "$out" | jq -r 'if (.summary.anomaly_count | type) == "number" then .summary.anomaly_count else empty end' 2>/dev/null || true)
    if [ -n "$n" ] && [ "$n" != "null" ]; then
      printf '%s' "$n"
      return
    fi
  fi
  # (c) Fallback to exit-code interpretation.
  if [ "$rc" = "2" ]; then
    printf '1'
  else
    printf '0'
  fi
}

# Pull a representative detail-snippet for the human output (best-
# effort; never load-bearing for the JSON or exit code). Examples:
#   block_lag_check  → "head_stale"  (when .stale==true)
#   stake_audit      → "anomaly_count=3"
# Empty string is fine — the human renderer falls back to a generic
# label.
extract_detail() {
  local out="$1" name="$2" d=""
  if [ -z "$out" ]; then printf ''; return; fi
  case "$name" in
    operator_block_lag_check.sh)
      local stale isolated
      stale=$(printf '%s' "$out" | jq -r '.stale // empty' 2>/dev/null || true)
      isolated=$(printf '%s' "$out" | jq -r '.isolated // empty' 2>/dev/null || true)
      [ "$stale" = "true" ] && d="head_stale"
      if [ "$isolated" = "true" ]; then
        if [ -n "$d" ]; then d="${d},isolated"; else d="isolated"; fi
      fi
      ;;
    operator_supply_check.sh)
      # supply_check has no --json flag (it prints a 1-line message),
      # so $out will typically be empty; leave detail blank — the human
      # column shows "a1_violated" anyway via exit-code mapping below.
      :
      ;;
    operator_chain_health.sh)
      local daemon a1 peers
      daemon=$(printf '%s' "$out" | jq -r '.daemon_responding // empty' 2>/dev/null || true)
      a1=$(printf '%s' "$out" | jq -r '.a1_invariant_ok // empty' 2>/dev/null || true)
      peers=$(printf '%s' "$out" | jq -r '.peers_ok // empty' 2>/dev/null || true)
      local parts=""
      [ "$daemon" = "false" ] && parts="daemon_down"
      if [ "$a1" = "false" ]; then
        [ -n "$parts" ] && parts="${parts},a1_violated" || parts="a1_violated"
      fi
      if [ "$peers" = "false" ]; then
        [ -n "$parts" ] && parts="${parts},no_peers" || parts="no_peers"
      fi
      d="$parts"
      ;;
    operator_stake_audit.sh)
      local ac
      ac=$(printf '%s' "$out" | jq -r '.summary.anomaly_count // empty' 2>/dev/null || true)
      [ -n "$ac" ] && [ "$ac" != "0" ] && d="anomaly_count=${ac}"
      ;;
    operator_dapp_audit.sh)
      # dapp_audit has no anomaly surface (informational only).
      :
      ;;
  esac
  printf '%s' "$d"
}

for ROW in "${SOURCES[@]}"; do
  NAME="${ROW%%|*}"
  SUPPORTS_ANOM="${ROW##*|}"
  SCRIPT="tools/${NAME}"

  # Build the per-script argv. --rpc-port is universal; --json is
  # universal; --anomalies-only is conditional.
  ARGS=("--rpc-port" "$PORT")
  [ "$SUPPORTS_ANOM" = "1" ] && ARGS+=("--anomalies-only")
  # Two of the curated scripts (supply_check) have no --json surface
  # — they emit a 1-line text message and rely on the exit code as
  # the machine-readable contract. We still pass --json defensively:
  # scripts that don't understand it will error out, and that errored
  # state is honestly what the operator should see in the dashboard
  # (a missed JSON contract is a bug to fix in the member script).
  # However supply_check is intentionally text-only by design, so
  # special-case: skip --json there.
  if [ "$NAME" != "operator_supply_check.sh" ]; then
    ARGS+=("--json")
  fi

  # Run the source. Capture stdout (the JSON / text payload) and exit
  # code; route stderr to /dev/null so a noisy script doesn't pollute
  # the meta-summary surface (the rolled-up status is still correct
  # because we rely on exit code, not stderr text).
  if [ ! -f "$SCRIPT" ]; then
    OUT=""
    RC=1
  else
    # NB: `OUT=$(...) || true` would mask the script's exit code by
    # making $? always 0. Use a two-step form: capture, then read $?
    # directly. `set -e` is not in effect (only set -u) so the
    # non-zero exit doesn't unwind us.
    OUT=$(bash "$SCRIPT" "${ARGS[@]}" 2>/dev/null)
    RC=$?
  fi

  COUNT=$(extract_count "$OUT" "$RC")
  case "$RC" in
    0) STATUS="OK" ;;
    2) STATUS="ALERT" ;;
    *) STATUS="ERROR" ;;
  esac
  DETAIL=$(extract_detail "$OUT" "$NAME")

  # Numeric-guard COUNT — extract_count guarantees a non-negative int
  # but a malformed jq result could in principle leak through; clamp
  # to 0 to keep the arithmetic safe.
  case "$COUNT" in *[!0-9]*|"") COUNT=0 ;; esac

  printf '%s\t%s\t%s\t%s\t%s\n' "$NAME" "$RC" "$COUNT" "$STATUS" "$DETAIL" >>"$TMP_ROWS"

  TOTAL_ANOMALIES=$(( TOTAL_ANOMALIES + COUNT ))
  [ "$STATUS" = "ERROR" ] && ERRORED_COUNT=$(( ERRORED_COUNT + 1 ))
  [ "$STATUS" = "ALERT" ] && ANOMALY_SOURCES=$(( ANOMALY_SOURCES + 1 ))
done

# ── Rolled-up exit code ───────────────────────────────────────────────────────
# Errors win over anomalies (1 > 2 in operational urgency: a missing
# RPC link means we can't see anomalies at all). Then anomalies. Then
# all-clean.
RC_OUT=0
if [ "$ERRORED_COUNT" -gt 0 ]; then
  RC_OUT=1
elif [ "$ANOMALY_SOURCES" -gt 0 ]; then
  RC_OUT=2
fi

SOURCE_COUNT="${#SOURCES[@]}"

# ── Emit output ───────────────────────────────────────────────────────────────
if [ "$JSON" = "1" ]; then
  # Build a sources array via jq -n / --argjson roll. We use a
  # tmp-driven loop because Bash array-of-objects doesn't compose
  # cleanly with jq -n.
  SOURCES_JSON='['
  FIRST=1
  while IFS=$'\t' read -r NAME RC COUNT STATUS DETAIL; do
    [ "$FIRST" = "1" ] || SOURCES_JSON+=','
    FIRST=0
    # Render detail as either a JSON string or null when empty.
    if [ -z "$DETAIL" ]; then
      DETAIL_JSON='null'
    else
      DETAIL_JSON=$(printf '%s' "$DETAIL" | jq -Rs '.')
    fi
    SOURCES_JSON+=$(jq -nc \
      --arg name   "$NAME" \
      --argjson rc "$RC" \
      --argjson n  "$COUNT" \
      --arg status "$STATUS" \
      --argjson detail "$DETAIL_JSON" \
      '{name:$name, exit_code:$rc, anomalies:$n, status:$status, detail:$detail}')
  done <"$TMP_ROWS"
  SOURCES_JSON+=']'
  jq -nc \
    --argjson sources "$SOURCES_JSON" \
    --argjson total   "$TOTAL_ANOMALIES" \
    --argjson errored "$ERRORED_COUNT" \
    --argjson alert   "$ANOMALY_SOURCES" \
    --argjson count   "$SOURCE_COUNT" \
    --argjson port    "$PORT" \
    '{
      sources: $sources,
      total_anomalies: $total,
      errored_count: $errored,
      alert_count: $alert,
      source_count: $count,
      rpc_port: $port
    }'
  exit $RC_OUT
fi

# Human dashboard.
echo "=== Anomaly summary (port $PORT) ==="
echo "Sources audited: $SOURCE_COUNT"

# Pre-compute the widest source-name column for alignment.
NAME_WIDTH=0
while IFS=$'\t' read -r NAME _ _ _ _; do
  W=${#NAME}
  [ "$W" -gt "$NAME_WIDTH" ] && NAME_WIDTH=$W
done <"$TMP_ROWS"
NAME_WIDTH=$(( NAME_WIDTH + 1 ))  # add trailing colon

while IFS=$'\t' read -r NAME RC COUNT STATUS DETAIL; do
  LABEL="${NAME}:"
  case "$STATUS" in
    OK)    SUMMARY="OK (${COUNT} anomalies)" ;;
    ALERT)
      if [ "$COUNT" = "1" ]; then
        if [ -n "$DETAIL" ]; then
          SUMMARY="ALERT (1 anomaly: ${DETAIL})"
        else
          SUMMARY="ALERT (1 anomaly)"
        fi
      else
        if [ -n "$DETAIL" ]; then
          SUMMARY="ALERT (${COUNT} anomalies: ${DETAIL})"
        else
          SUMMARY="ALERT (${COUNT} anomalies)"
        fi
      fi
      ;;
    ERROR) SUMMARY="ERROR (script exit ${RC})" ;;
    *)     SUMMARY="$STATUS" ;;
  esac
  printf "  %-${NAME_WIDTH}s %s\n" "$LABEL" "$SUMMARY"
done <"$TMP_ROWS"

# Footer line. Singular/plural toggling to match the sibling scripts'
# tone (operator_chain_health, operator_block_lag_check etc.).
if [ "$TOTAL_ANOMALIES" = "1" ]; then
  echo "Total: 1 anomaly across $SOURCE_COUNT audits"
else
  echo "Total: $TOTAL_ANOMALIES anomalies across $SOURCE_COUNT audits"
fi

if [ "$ERRORED_COUNT" -gt 0 ]; then
  if [ "$ERRORED_COUNT" = "1" ]; then
    echo "[X] 1 source errored"
  else
    echo "[X] $ERRORED_COUNT sources errored"
  fi
elif [ "$ANOMALY_SOURCES" -gt 0 ]; then
  if [ "$TOTAL_ANOMALIES" = "1" ]; then
    echo "[X] 1 anomaly detected"
  else
    echo "[X] $TOTAL_ANOMALIES anomalies detected"
  fi
else
  echo "[OK] all sources clean"
fi

exit $RC_OUT
