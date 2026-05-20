#!/usr/bin/env bash
# operator_dapp_audit.sh — Comprehensive on-chain DApp-registry audit
# for a running determ daemon. Combines `determ dapp-list`,
# `determ dapp-info` (per domain), and `determ head` into a single
# tabular or JSON digest classified by lifecycle status.
#
# Read-only RPC; safe against any running daemon. Daemon must already
# be listening on --rpc-port.
#
# Status classification (with H = current chain height):
#   ACTIVE       — entry.inactive_from == UINT64_MAX (never deactivated)
#   DEACTIVATING — entry.inactive_from >  H but < UINT64_MAX (in grace)
#   INACTIVE     — entry.inactive_from <= H (past DAPP_GRACE_BLOCKS)
#
# Usage:
#   tools/operator_dapp_audit.sh [--rpc-port N] [--json]
#                                [--active-only | --inactive-only]
#                                [--prefix STR] [--topic STR]
#
# RPC dependencies:
#   dapp_list      — compact iteration {domain, endpoint_url, topics, active}
#   dapp_info      — per-domain full record {registered_at, inactive_from, ...}
#   status (head)  — current chain height for status comparison
#
# Exit codes:
#   0 — audit ran, results returned
#   1 — RPC error / daemon unreachable / malformed response
set -u

usage() {
  cat <<'EOF'
Usage: operator_dapp_audit.sh [--rpc-port N] [--json]
                              [--active-only | --inactive-only]
                              [--prefix STR] [--topic STR]

Audit the on-chain DApp registry of a running determ daemon. Walks
the registry (server-side --prefix / --topic filters supported),
fetches per-domain detail, and classifies each entry by lifecycle
status against the current chain height.

Options:
  --rpc-port N    RPC port to query (default: 7778)
  --json          Emit structured JSON instead of human-readable table
  --active-only   Filter output to ACTIVE entries (inactive_from sentinel
                  or > current height)
  --inactive-only Filter output to entries where inactive_from <= height
                  (already past DAPP_GRACE_BLOCKS)
  --prefix STR    Pass-through server-side domain-prefix filter
  --topic STR     Pass-through server-side topic filter
  -h, --help      Show this help

Exit codes:
  0   audit ran, results returned
  1   RPC error / daemon unreachable / malformed response
EOF
}

PORT=7778
JSON=0
ACTIVE_ONLY=0
INACTIVE_ONLY=0
PREFIX=""
TOPIC=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --rpc-port) PORT="${2:-}"; shift 2 ;;
    --json) JSON=1; shift ;;
    --active-only) ACTIVE_ONLY=1; shift ;;
    --inactive-only) INACTIVE_ONLY=1; shift ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --topic) TOPIC="${2:-}"; shift 2 ;;
    *) echo "operator_dapp_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ "$ACTIVE_ONLY" = "1" ] && [ "$INACTIVE_ONLY" = "1" ]; then
  echo "operator_dapp_audit: --active-only and --inactive-only are mutually exclusive" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_dapp_audit: requires 'jq' (not found on PATH)" >&2
  exit 1
fi

# Sentinel UINT64_MAX as it appears in nlohmann::json output.
UINT64_MAX_STR="18446744073709551615"

# (1) Current chain height.
HEAD_OUT=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_dapp_audit: RPC error querying head (is daemon running on port $PORT?)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_OUT" | jq -r '.height // empty')
if [ -z "$HEIGHT" ]; then
  echo "operator_dapp_audit: malformed head response (port $PORT)" >&2
  exit 1
fi

# (2) Bulk registry walk. dapp-list returns compact entries; full
# detail (registered_at, inactive_from) requires per-domain dapp-info.
DAPP_LIST_ARGS=("dapp-list" "--rpc-port" "$PORT")
[ -n "$PREFIX" ] && DAPP_LIST_ARGS+=("--prefix" "$PREFIX")
[ -n "$TOPIC" ]  && DAPP_LIST_ARGS+=("--topic"  "$TOPIC")

LIST_OUT=$("$DETERM" "${DAPP_LIST_ARGS[@]}" 2>/dev/null) || {
  echo "operator_dapp_audit: RPC error querying dapp-list (port $PORT)" >&2
  exit 1
}

# Validate response shape: must have .dapps array.
DAPPS_TYPE=$(printf '%s' "$LIST_OUT" | jq -r '.dapps | type' 2>/dev/null || true)
if [ "$DAPPS_TYPE" != "array" ]; then
  echo "operator_dapp_audit: malformed dapp-list response (no .dapps array)" >&2
  exit 1
fi

DOMAINS=$(printf '%s' "$LIST_OUT" | jq -r '.dapps[].domain')

# (3) Per-domain dapp-info pass, with filtering + status classification.
# Emit one JSON object per line (jsonl) for easy aggregation.
ROWS=""
while IFS= read -r DOMAIN; do
  [ -z "$DOMAIN" ] && continue
  INFO_OUT=$("$DETERM" dapp-info --domain "$DOMAIN" --rpc-port "$PORT" 2>/dev/null) || {
    echo "operator_dapp_audit: RPC error querying dapp-info for '$DOMAIN'" >&2
    exit 1
  }
  # If the daemon couldn't find it (race vs deregister), skip.
  ERR=$(printf '%s' "$INFO_OUT" | jq -r '.error // empty')
  [ -n "$ERR" ] && continue

  REG_AT=$(printf '%s' "$INFO_OUT"   | jq -r '.registered_at // 0')
  INACT=$(printf '%s' "$INFO_OUT"    | jq -r '.inactive_from // 0')
  ENDPOINT=$(printf '%s' "$INFO_OUT" | jq -r '.endpoint_url // ""')
  TOPICS_JSON=$(printf '%s' "$INFO_OUT" | jq -c '.topics // []')
  TOPIC_COUNT=$(printf '%s' "$INFO_OUT" | jq -r '.topics | length')

  # Status classification.
  if [ "$INACT" = "$UINT64_MAX_STR" ]; then
    STATUS="ACTIVE"
  elif [ "$INACT" -gt "$HEIGHT" ] 2>/dev/null; then
    STATUS="DEACTIVATING"
  else
    STATUS="INACTIVE"
  fi

  # Filter.
  if [ "$ACTIVE_ONLY" = "1" ] && [ "$STATUS" = "INACTIVE" ]; then
    continue
  fi
  if [ "$INACTIVE_ONLY" = "1" ] && [ "$STATUS" != "INACTIVE" ]; then
    continue
  fi

  # Age in blocks (current - registered_at).
  AGE=$((HEIGHT - REG_AT))
  [ "$AGE" -lt 0 ] && AGE=0

  # Append row as one JSON line.
  ROW=$(jq -nc \
    --arg domain        "$DOMAIN" \
    --argjson reg_at    "$REG_AT" \
    --argjson inact     "$INACT" \
    --arg     status    "$STATUS" \
    --argjson tcount    "$TOPIC_COUNT" \
    --argjson topics    "$TOPICS_JSON" \
    --arg     endpoint  "$ENDPOINT" \
    --arg     prefix    "$PREFIX" \
    --argjson age       "$AGE" \
    '{
      domain: $domain,
      registered_at: $reg_at,
      inactive_from: $inact,
      status: $status,
      topic_count: $tcount,
      topics: $topics,
      endpoint_url: $endpoint,
      prefix: $prefix,
      age_blocks: $age
    }')
  ROWS="${ROWS}${ROW}
"
done <<EOF
$DOMAINS
EOF

# (4) Sort by registered_at ascending (oldest first), then by domain.
SORTED=""
if [ -n "$ROWS" ]; then
  SORTED=$(printf '%s' "$ROWS" | grep -v '^$' | jq -sc 'sort_by(.registered_at, .domain) | .[]')
fi

# (5) Aggregate summary.
TOTAL=0; N_ACTIVE=0; N_DEACTIVATING=0; N_INACTIVE=0
OLDEST=""; NEWEST=""
if [ -n "$SORTED" ]; then
  TOTAL=$(printf '%s\n' "$SORTED" | grep -c .)
  N_ACTIVE=$(printf '%s\n'       "$SORTED" | jq -s '[.[] | select(.status=="ACTIVE")] | length')
  N_DEACTIVATING=$(printf '%s\n' "$SORTED" | jq -s '[.[] | select(.status=="DEACTIVATING")] | length')
  N_INACTIVE=$(printf '%s\n'     "$SORTED" | jq -s '[.[] | select(.status=="INACTIVE")] | length')
  OLDEST=$(printf '%s\n'         "$SORTED" | jq -s 'map(.registered_at) | min')
  NEWEST=$(printf '%s\n'         "$SORTED" | jq -s 'map(.registered_at) | max')
fi
[ -z "$OLDEST" ] && OLDEST=null
[ -z "$NEWEST" ] && NEWEST=null

# (6) Output.
if [ "$JSON" = "1" ]; then
  if [ -n "$SORTED" ]; then
    DAPPS_ARR=$(printf '%s\n' "$SORTED" | jq -s '.')
  else
    DAPPS_ARR='[]'
  fi
  jq -nc \
    --argjson dapps           "$DAPPS_ARR" \
    --argjson total           "$TOTAL" \
    --argjson active          "$N_ACTIVE" \
    --argjson deactivating    "$N_DEACTIVATING" \
    --argjson inactive        "$N_INACTIVE" \
    --argjson oldest_height   "$OLDEST" \
    --argjson newest_height   "$NEWEST" \
    --argjson current_height  "$HEIGHT" \
    '{
      dapps: $dapps,
      summary: {
        total: $total,
        active: $active,
        deactivating: $deactivating,
        inactive: $inactive,
        oldest_height: $oldest_height,
        newest_height: $newest_height,
        current_height: $current_height
      }
    }'
  exit 0
fi

# Human-readable table.
printf 'DApp registry audit (port %s, current height %s)\n' "$PORT" "$HEIGHT"
printf '%-32s %14s %-13s %14s %6s  %s\n' \
  "DOMAIN" "REGISTERED_AT" "STATUS" "INACTIVE_FROM" "TOPICS" "ENDPOINT"
printf '%s\n' "--------------------------------------------------------------------------------------------------------"
if [ -n "$SORTED" ]; then
  printf '%s\n' "$SORTED" | while IFS= read -r ROW; do
    [ -z "$ROW" ] && continue
    D=$(printf '%s' "$ROW"   | jq -r '.domain')
    R=$(printf '%s' "$ROW"   | jq -r '.registered_at')
    S=$(printf '%s' "$ROW"   | jq -r '.status')
    I=$(printf '%s' "$ROW"   | jq -r '.inactive_from')
    TC=$(printf '%s' "$ROW"  | jq -r '.topic_count')
    EP=$(printf '%s' "$ROW"  | jq -r '.endpoint_url')
    # Replace UINT64_MAX with "—" for readability.
    [ "$I" = "$UINT64_MAX_STR" ] && I_DISP="—" || I_DISP="$I"
    printf '%-32s %14s %-13s %14s %6s  %s\n' \
      "$D" "$R" "$S" "$I_DISP" "$TC" "$EP"
  done
fi
printf '%s\n' "--------------------------------------------------------------------------------------------------------"
printf 'Total: %s   Active: %s   Deactivating: %s   Inactive: %s\n' \
  "$TOTAL" "$N_ACTIVE" "$N_DEACTIVATING" "$N_INACTIVE"
if [ "$TOTAL" -gt 0 ] 2>/dev/null; then
  printf 'Oldest registration: height %s   Newest registration: height %s\n' \
    "$OLDEST" "$NEWEST"
fi
exit 0
