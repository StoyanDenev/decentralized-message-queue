#!/usr/bin/env bash
# operator_chain_health.sh — Multi-RPC health snapshot for a running
# determ daemon. Combines `determ head`, `determ peers --count`, and
# `determ supply --json` into a single "health digest" output.
#
# Read-only RPC; safe against any running daemon. Daemon must already
# be listening on --rpc-port.
#
# Usage:
#   tools/operator_chain_health.sh [--rpc-port N] [--json]
#
# Exit codes:
#   0 — all checks green (daemon responding, A1 holding, >=1 peer)
#   1 — RPC error (daemon unreachable or malformed response)
#   2 — at least one check red (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_chain_health.sh [--rpc-port N] [--json]

Multi-RPC health snapshot. Reports three checks:
  (a) daemon responding  — `determ head` returns a height + hash
  (b) A1 invariant       — `determ supply --json` reports a1_invariant_ok=true
  (c) at least 1 peer    — `determ peers --count` returns >= 1

Options:
  --rpc-port N    RPC port to query (default: 7778)
  --json          Emit a structured JSON summary instead of human digest
  -h, --help      Show this help

Exit codes:
  0   all green
  1   RPC error
  2   at least one check red
EOF
}

PORT=7778
JSON=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --rpc-port) PORT="$2"; shift 2 ;;
    --json) JSON=1; shift ;;
    *) echo "operator_chain_health: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."
source tools/common.sh

# (a) Daemon responding via `head`.
HEAD_OUT=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_chain_health: RPC error (is daemon running on port $PORT?)" >&2
  exit 1
}

# (b) A1 invariant. supply exits 2 on violation — don't bail on that.
SUPPLY_OUT=$("$DETERM" supply --json --rpc-port "$PORT" 2>/dev/null) ; SUPPLY_RC=$?
if [ "$SUPPLY_RC" != "0" ] && [ "$SUPPLY_RC" != "2" ]; then
  echo "operator_chain_health: RPC error querying supply (port $PORT)" >&2
  exit 1
fi

# (c) Peer count.
PEER_COUNT=$("$DETERM" peers --count --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_chain_health: RPC error querying peers (port $PORT)" >&2
  exit 1
}

if command -v jq >/dev/null 2>&1; then
  HEIGHT=$(printf '%s' "$HEAD_OUT"     | jq -r '.height')
  HEAD_HASH=$(printf '%s' "$HEAD_OUT"  | jq -r '.head_hash')
  A1=$(printf '%s' "$SUPPLY_OUT"       | jq -r '.a1_invariant_ok')
else
  HEIGHT=$(printf '%s' "$HEAD_OUT"     | grep -o '"height":[^,}]*'         | head -1 | sed 's/.*: *//; s/[",]//g')
  HEAD_HASH=$(printf '%s' "$HEAD_OUT"  | grep -o '"head_hash":"[^"]*"'     | head -1 | sed 's/.*: *//; s/"//g')
  A1=$(printf '%s' "$SUPPLY_OUT"       | grep -o '"a1_invariant_ok":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
fi

DAEMON_OK="false"; [ -n "$HEIGHT" ] && DAEMON_OK="true"
A1_OK="false";     [ "$A1" = "true" ] && A1_OK="true"
PEERS_OK="false";  [ "${PEER_COUNT:-0}" -ge 1 ] 2>/dev/null && PEERS_OK="true"

RC=0
[ "$DAEMON_OK" = "true" ] && [ "$A1_OK" = "true" ] && [ "$PEERS_OK" = "true" ] || RC=2

if [ "$JSON" = "1" ]; then
  cat <<EOF
{"daemon_responding": $DAEMON_OK, "a1_invariant_ok": $A1_OK, "peers_ok": $PEERS_OK, "height": ${HEIGHT:-0}, "head_hash": "${HEAD_HASH:-}", "peer_count": ${PEER_COUNT:-0}, "rpc_port": $PORT}
EOF
  exit $RC
fi

mark() { [ "$1" = "true" ] && printf '[OK]' || printf '[X] '; }
echo "operator_chain_health (port $PORT):"
echo "  $(mark "$DAEMON_OK") daemon responding   height=${HEIGHT:-?}  head=${HEAD_HASH:0:24}..."
echo "  $(mark "$A1_OK") A1 invariant         ok=${A1:-?}"
echo "  $(mark "$PEERS_OK") peers connected      count=${PEER_COUNT:-0}"
exit $RC
