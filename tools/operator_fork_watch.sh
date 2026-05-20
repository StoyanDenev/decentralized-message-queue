#!/usr/bin/env bash
# operator_fork_watch.sh — Cross-node fork detection wrapper around
# `determ check-fork`. Resolves each node's head independently, picks
# the smaller as the comparison endpoint, then checks the last N
# blocks (default 10) for `--field` divergence (default state_root).
#
# Read-only RPC; safe against any running daemon.
#
# Usage:
#   tools/operator_fork_watch.sh --node-a host:port --node-b host:port \
#                                [--window N] [--field NAME]
#
# Exit codes:
#   0 — nodes in sync over the comparison window
#   1 — RPC error / unreachable node / malformed response / bad args
#   2 — fork detected at a specific height H (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_fork_watch.sh --node-a host:port --node-b host:port \
                              [--window N] [--field NAME]

Compares the last N blocks (default 10) on two running determ daemons
and reports the first height (if any) where they diverge on the
specified block field. Picks the smaller of the two heads as the
window's upper bound; lower bound is max(0, head - window + 1).

Required:
  --node-a host:port    First node, e.g. 127.0.0.1:7778
  --node-b host:port    Second node, e.g. 127.0.0.1:7779

Options:
  --window N            How many blocks back from head to compare (default: 10)
  --field NAME          Block field to compare: state_root, block_hash,
                        prev_hash, index, timestamp (default: state_root)
  -h, --help            Show this help

Exit codes:
  0   nodes in sync over the window
  1   RPC error / bad args
  2   fork detected at a specific height
EOF
}

NODE_A=""
NODE_B=""
WINDOW=10
FIELD="state_root"
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --node-a) NODE_A="$2"; shift 2 ;;
    --node-b) NODE_B="$2"; shift 2 ;;
    --window) WINDOW="$2"; shift 2 ;;
    --field) FIELD="$2"; shift 2 ;;
    *) echo "operator_fork_watch: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$NODE_A" ] || [ -z "$NODE_B" ]; then
  echo "operator_fork_watch: --node-a and --node-b are required" >&2
  usage >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Split host:port → just port. Both nodes assumed reachable at 127.0.0.1
# for `determ head` (head is an RPC to localhost). The host portion is
# preserved for check-fork's own host-aware dispatch.
port_of() {
  case "$1" in
    *:*) printf '%s' "${1##*:}" ;;
    *)   echo "operator_fork_watch: address '$1' must be host:port" >&2; return 1 ;;
  esac
}

PORT_A=$(port_of "$NODE_A") || exit 1
PORT_B=$(port_of "$NODE_B") || exit 1

HEAD_A=$("$DETERM" head --field height --rpc-port "$PORT_A" 2>/dev/null) || {
  echo "operator_fork_watch: cannot reach node-a ($NODE_A)" >&2; exit 1;
}
HEAD_B=$("$DETERM" head --field height --rpc-port "$PORT_B" 2>/dev/null) || {
  echo "operator_fork_watch: cannot reach node-b ($NODE_B)" >&2; exit 1;
}

# Numeric guard.
case "$HEAD_A$HEAD_B$WINDOW" in *[!0-9]*)
  echo "operator_fork_watch: non-numeric head/window (A=$HEAD_A B=$HEAD_B W=$WINDOW)" >&2; exit 1 ;;
esac

# Pick smaller head; compute window lower bound.
TO=$HEAD_A; [ "$HEAD_B" -lt "$HEAD_A" ] && TO=$HEAD_B
FROM=$(( TO >= WINDOW ? TO - WINDOW + 1 : 0 ))

"$DETERM" check-fork --node-a "$NODE_A" --node-b "$NODE_B" \
  --from "$FROM" --to "$TO" --field "$FIELD" >/dev/null 2>&1
RC=$?

case "$RC" in
  0)
    echo "operator_fork_watch: node A head=$HEAD_A, node B head=$HEAD_B, divergence=NONE (field=$FIELD, window=[$FROM..$TO])"
    exit 0 ;;
  2)
    # Re-run for diagnostic detail.
    DETAIL=$("$DETERM" check-fork --node-a "$NODE_A" --node-b "$NODE_B" \
      --from "$FROM" --to "$TO" --field "$FIELD" --json 2>/dev/null)
    if command -v jq >/dev/null 2>&1; then
      H=$(printf '%s' "$DETAIL" | jq -r '.first_divergence')
    else
      H=$(printf '%s' "$DETAIL" | grep -o '"first_divergence":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
    fi
    echo "operator_fork_watch: node A head=$HEAD_A, node B head=$HEAD_B, divergence=AT $H (field=$FIELD, window=[$FROM..$TO])" >&2
    exit 2 ;;
  *)
    echo "operator_fork_watch: check-fork failed (rc=$RC; field=$FIELD, window=[$FROM..$TO])" >&2
    exit 1 ;;
esac
