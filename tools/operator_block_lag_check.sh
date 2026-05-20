#!/usr/bin/env bash
# operator_block_lag_check.sh — Detect when a daemon's head is stale
# relative to wall-clock. Compares head.timestamp (Unix epoch seconds,
# per Block::to_json) to `date +%s` and alerts when the gap exceeds
# the configured threshold.
#
# A stale head means one of:
#   (a) consensus stall (most concerning) — daemon up, peered, but
#       no new blocks finalizing;
#   (b) catch-up from cold start (informational) — daemon is
#       still syncing historical chain;
#   (c) network partition — zero peers + stale lag implies this
#       daemon is isolated.
#
# Read-only RPC; safe against any running daemon. Daemon must already
# be listening on --rpc-port.
#
# Usage:
#   tools/operator_block_lag_check.sh [--rpc-port N] [--threshold S]
#                                     [--profile NAME] [--json]
#
# Exit codes:
#   0 — head fresh (lag <= threshold)
#   1 — RPC error / daemon unreachable / malformed response
#   2 — head STALE (lag > threshold; operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_block_lag_check.sh [--rpc-port N] [--threshold S]
                                   [--profile NAME] [--json]

Reports head freshness: lag = now - head.timestamp (in seconds). Stale
when lag exceeds the threshold. Also reports peer count so a stale
result can be classified (zero peers ⇒ likely isolated; many peers
⇒ likely consensus stall).

Options:
  --rpc-port N    RPC port to query (default: 7778)
  --threshold S   Lag threshold in seconds (default: 300 = 5 min)
  --profile NAME  Set a profile-appropriate default threshold:
                    cluster  → 60s   (50ms blocks; head should be fresh)
                    web      → 300s  (default)
                    regional → 600s
                    global   → 1800s
                    tactical → 60s
                  An explicit --threshold wins over --profile.
  --json          Emit a structured JSON summary instead of human output
  -h, --help      Show this help

Exit codes:
  0   head fresh
  1   RPC error
  2   head STALE
EOF
}

PORT=7778
THRESHOLD=""
PROFILE=""
JSON=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --rpc-port) PORT="$2"; shift 2 ;;
    --threshold) THRESHOLD="$2"; shift 2 ;;
    --profile) PROFILE="$2"; shift 2 ;;
    --json) JSON=1; shift ;;
    *) echo "operator_block_lag_check: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Resolve the effective threshold. Explicit --threshold wins; otherwise
# the --profile preset; otherwise the 300s default. Profile values
# mirror chain timing knobs in include/determ/chain/params.hpp:
#   cluster  (~50ms blocks)         — head should be very fresh
#   web      (default ~1-3s blocks)
#   regional (~300ms blocks)        — wider WAN tolerance
#   global   (~600ms blocks)        — widest WAN tolerance
#   tactical (~20ms blocks)         — head should be very fresh
if [ -z "$THRESHOLD" ]; then
  case "$PROFILE" in
    cluster)  THRESHOLD=60 ;;
    web)      THRESHOLD=300 ;;
    regional) THRESHOLD=600 ;;
    global)   THRESHOLD=1800 ;;
    tactical) THRESHOLD=60 ;;
    "")       THRESHOLD=300 ;;
    *)
      echo "operator_block_lag_check: unknown --profile '$PROFILE' (expected: cluster|web|regional|global|tactical)" >&2
      exit 1 ;;
  esac
fi

# Numeric guards.
case "$THRESHOLD" in *[!0-9]*|"")
  echo "operator_block_lag_check: --threshold must be a non-negative integer (got '$THRESHOLD')" >&2
  exit 1 ;;
esac
case "$PORT" in *[!0-9]*|"")
  echo "operator_block_lag_check: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# (1) Head height + hash. `determ head --json` emits {height, head_hash}.
HEAD_OUT=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_block_lag_check: RPC error (is daemon running on port $PORT?)" >&2
  exit 1
}

if command -v jq >/dev/null 2>&1; then
  HEIGHT=$(printf '%s' "$HEAD_OUT"    | jq -r '.height')
  HEAD_HASH=$(printf '%s' "$HEAD_OUT" | jq -r '.head_hash')
else
  HEIGHT=$(printf '%s'    "$HEAD_OUT" | grep -o '"height":[^,}]*'     | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  HEAD_HASH=$(printf '%s' "$HEAD_OUT" | grep -o '"head_hash":"[^"]*"' | head -1 | sed 's/.*: *//; s/"//g')
fi

if [ -z "${HEIGHT:-}" ] || [ "$HEIGHT" = "null" ]; then
  echo "operator_block_lag_check: malformed head JSON (port $PORT)" >&2
  exit 1
fi

# Empty chain (height==0 + empty hash) — no head to compare against.
if [ "$HEIGHT" = "0" ] && [ -z "${HEAD_HASH:-}" ]; then
  echo "operator_block_lag_check: chain empty (height=0); no head timestamp to compare" >&2
  exit 1
fi

# (2) Head index = height - 1 (chain RPC convention: rpc_block(index)
# returns nullptr when index >= height; head block lives at height-1).
HEAD_INDEX=$(( HEIGHT - 1 ))
HEAD_TS=$("$DETERM" block-info "$HEAD_INDEX" --field timestamp --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_block_lag_check: RPC error fetching head block timestamp (index=$HEAD_INDEX, port $PORT)" >&2
  exit 1
}

# block-info --field timestamp emits a bare integer; strip whitespace.
HEAD_TS=$(printf '%s' "$HEAD_TS" | tr -d '[:space:]')
case "$HEAD_TS" in *[!0-9]*|"")
  echo "operator_block_lag_check: head timestamp not a Unix epoch integer (got '$HEAD_TS')" >&2
  exit 1 ;;
esac

# (3) Peer count.
PEER_COUNT=$("$DETERM" peers --count --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_block_lag_check: RPC error querying peers (port $PORT)" >&2
  exit 1
}
PEER_COUNT=$(printf '%s' "$PEER_COUNT" | tr -d '[:space:]')
case "$PEER_COUNT" in *[!0-9]*|"") PEER_COUNT=0 ;; esac

# (4) Wall-clock now (Unix epoch seconds).
NOW=$(date -u +%s)

# (5) Compute lag. Clamp at 0 so a clock-skewed daemon (head.timestamp
# slightly ahead of local wall-clock) reports lag=0 rather than negative.
if [ "$HEAD_TS" -gt "$NOW" ]; then
  LAG=0
else
  LAG=$(( NOW - HEAD_TS ))
fi

STALE="false"
[ "$LAG" -gt "$THRESHOLD" ] && STALE="true"

ISOLATED="false"
[ "$PEER_COUNT" -eq 0 ] && [ "$STALE" = "true" ] && ISOLATED="true"

RC=0
[ "$STALE" = "true" ] && RC=2

if [ "$JSON" = "1" ]; then
  cat <<EOF
{"height": $HEIGHT, "head_hash": "${HEAD_HASH:-}", "head_timestamp_unix": $HEAD_TS, "now_unix": $NOW, "lag_seconds": $LAG, "threshold_seconds": $THRESHOLD, "stale": $STALE, "peer_count": $PEER_COUNT, "isolated": $ISOLATED, "rpc_port": $PORT}
EOF
  exit $RC
fi

# Human output. UTC timestamps via `date -u -d @<unix>`; on platforms
# without GNU date (-d not supported), fall back to printing the raw
# Unix epoch.
fmt_ts() {
  local ts="$1"
  local out
  out=$(date -u -d "@$ts" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null) || out=""
  if [ -z "$out" ]; then
    out=$(date -u -r "$ts" '+%Y-%m-%d %H:%M:%S UTC' 2>/dev/null) || out=""
  fi
  [ -z "$out" ] && out="unix=$ts"
  printf '%s' "$out"
}

HEAD_TS_FMT=$(fmt_ts "$HEAD_TS")
NOW_FMT=$(fmt_ts "$NOW")
SHORT_HASH="${HEAD_HASH:0:16}"
[ -n "$SHORT_HASH" ] && SHORT_HASH="${SHORT_HASH}..."

echo "=== Block lag check (port $PORT, threshold ${THRESHOLD}s) ==="
echo "Head height: $HEIGHT"
echo "Head hash:   ${SHORT_HASH:-(none)}"
echo "Head timestamp: $HEAD_TS_FMT"
echo "Now:            $NOW_FMT"
echo "Lag: $LAG seconds"
echo "Peer count: $PEER_COUNT"
if [ "$STALE" = "false" ]; then
  echo "[OK] head fresh (${LAG}s <= ${THRESHOLD}s threshold)"
else
  echo "[X]  head STALE (${LAG}s > ${THRESHOLD}s threshold)"
  if [ "$ISOLATED" = "true" ]; then
    echo "[X]  zero peers — likely isolated"
  fi
fi
exit $RC
