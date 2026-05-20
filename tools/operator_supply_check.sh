#!/usr/bin/env bash
# operator_supply_check.sh — Verify A1 unitary-supply invariant on a
# running determ daemon.
#
# Composes `determ supply --json --rpc-port $PORT` (already shipped)
# and inspects `a1_invariant_ok`. Read-only RPC; safe against any
# running daemon. Daemon must already be listening on --rpc-port.
#
# Usage:
#   tools/operator_supply_check.sh [--rpc-port N] [--verbose]
#
# Exit codes:
#   0 — A1 invariant holds (live_total_supply == expected_total)
#   1 — RPC error / daemon unreachable / malformed JSON
#   2 — A1 invariant VIOLATED (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_supply_check.sh [--rpc-port N] [--verbose]

Verifies the A1 unitary-supply invariant on a running determ daemon
(live_total_supply == genesis_total + subsidy + inbound - slashed - outbound).

Options:
  --rpc-port N    RPC port to query (default: 7778)
  --verbose       Print the full supply JSON in addition to the 1-line summary
  -h, --help      Show this help

Exit codes:
  0   A1 invariant holds
  1   RPC error / daemon unreachable / malformed response
  2   A1 invariant VIOLATED
EOF
}

PORT=7778
VERBOSE=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --rpc-port) PORT="$2"; shift 2 ;;
    --verbose) VERBOSE=1; shift ;;
    *) echo "operator_supply_check: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."
source tools/common.sh

OUT=$("$DETERM" supply --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_supply_check: RPC error (is daemon running on port $PORT?)" >&2
  exit 1
}

if command -v jq >/dev/null 2>&1; then
  OK=$(printf '%s' "$OUT"     | jq -r '.a1_invariant_ok')
  LIVE=$(printf '%s' "$OUT"   | jq -r '.live_total_supply')
  EXPECT=$(printf '%s' "$OUT" | jq -r '.expected_total')
else
  OK=$(printf '%s' "$OUT"     | grep -o '"a1_invariant_ok":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  LIVE=$(printf '%s' "$OUT"   | grep -o '"live_total_supply":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  EXPECT=$(printf '%s' "$OUT" | grep -o '"expected_total":[^,}]*'    | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
fi

if [ -z "$OK" ]; then
  echo "operator_supply_check: malformed supply JSON (port $PORT)" >&2
  [ "$VERBOSE" = "1" ] && echo "$OUT" >&2
  exit 1
fi

[ "$VERBOSE" = "1" ] && echo "$OUT"

if [ "$OK" = "true" ]; then
  echo "operator_supply_check: A1 OK (live=$LIVE expected=$EXPECT, port $PORT)"
  exit 0
else
  echo "operator_supply_check: A1 VIOLATED (live=$LIVE expected=$EXPECT, port $PORT)" >&2
  exit 2
fi
