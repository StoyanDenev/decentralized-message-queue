#!/usr/bin/env bash
# operator_light_fleet_crosscheck.sh — READ-ONLY fleet monitoring wrapper
# around `determ-light cross-check`. Runs the trust-minimized multi-peer
# divergence detector across >=2 independently-verified daemons (the
# eclipse / committee-signed-fork defense — LightClientCompositionMap §6),
# collapses its output to a single monitoring-friendly status line, and
# PASSES THROUGH the determ-light exit code so a cron/monitor can gate on it.
#
# Read-only: each peer is genesis-anchored + chain-verified, never written.
# Safe against any running daemon.
#
# Usage:
#   tools/operator_light_fleet_crosscheck.sh --genesis <file> \
#       (--rpc-port <N> | --peer <host:port>) x2+ [--json]
#
# Exit codes (passed through verbatim from `determ-light cross-check`):
#   0 — AGREE        (all peers sharing a height agree on block_hash+state_root)
#   2 — DIVERGENCE   (committee-signed fork detected — operator alert gate)
#   3 — INCONCLUSIVE (no two peers share a height this round — retry)
#   1 — UNVERIFIABLE (a peer failed its own verification) OR usage error
#
# SKIP (exit 0): determ-light binary unavailable — nothing to monitor here.
set -u

usage() {
  cat <<'EOF'
Usage: operator_light_fleet_crosscheck.sh --genesis <file> \
           (--rpc-port <N> | --peer <host:port>) x2+ [--json]

Read-only fleet monitor over `determ-light cross-check`. Verifies >=2
independent daemons against the SAME pinned genesis, then requires every
pair of peers reporting the same height to agree on (block_hash, state_root).
Prints one status line:

    CROSSCHECK <verdict> peers=<n> genesis=<short>

and exits with the verdict's code so a cron job / monitor can gate on it.

Required:
  --genesis <file>      Pinned genesis JSON every peer is anchored against.
  At least TWO peers, via any mix of:
    --rpc-port <N>      A localhost daemon (127.0.0.1:N). Repeatable.
    --peer <host:port>  A remote daemon. Repeatable.

Options:
  --json                Emit the underlying cross-check JSON (verdict + per-peer
                        rows) instead of the one-line status, still exit-coded.
  -h, --help            Show this help.

Exit codes (passed through from `determ-light cross-check`):
  0   AGREE          all shared-height peer groups consistent
  2   DIVERGENCE     committee-signed fork detected (alert)
  3   INCONCLUSIVE   no two peers share a height yet (retry)
  1   UNVERIFIABLE   a peer failed verification, or bad args

If the determ-light binary is unavailable this tool SKIPs (exit 0): there is
nothing for it to monitor on a host without the light client.
EOF
}

GENESIS=""
JSON=0
PEER_ARGS=()   # forwarded verbatim to cross-check
PEER_COUNT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --genesis)
      [ $# -ge 2 ] || { echo "operator_light_fleet_crosscheck: --genesis needs a value" >&2; exit 1; }
      GENESIS="$2"; shift 2 ;;
    --rpc-port)
      [ $# -ge 2 ] || { echo "operator_light_fleet_crosscheck: --rpc-port needs a value" >&2; exit 1; }
      PEER_ARGS+=(--rpc-port "$2"); PEER_COUNT=$((PEER_COUNT+1)); shift 2 ;;
    --peer)
      [ $# -ge 2 ] || { echo "operator_light_fleet_crosscheck: --peer needs a value" >&2; exit 1; }
      PEER_ARGS+=(--peer "$2"); PEER_COUNT=$((PEER_COUNT+1)); shift 2 ;;
    --json) JSON=1; shift ;;
    *) echo "operator_light_fleet_crosscheck: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Local usage validation BEFORE invoking the binary (mirrors cross-check's
# own gate: --genesis required + >= 2 peers). Fail with exit 1 + message.
if [ -z "$GENESIS" ]; then
  echo "operator_light_fleet_crosscheck: --genesis <file> is required" >&2
  usage >&2
  exit 1
fi
if [ "$PEER_COUNT" -lt 2 ]; then
  echo "operator_light_fleet_crosscheck: at least two peers are required" \
       "(--rpc-port <N> and/or --peer <host:port>); got $PEER_COUNT" >&2
  usage >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# SKIP gracefully if the light client isn't available — nothing to monitor.
if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "operator_light_fleet_crosscheck: SKIP — determ-light binary not found" \
       "(build with: cmake --build build --config Release --target determ-light)"
  exit 0
fi

# Short genesis label for the status line: basename without directory.
GENESIS_SHORT="${GENESIS##*/}"

if [ "$JSON" = "1" ]; then
  # Pass the raw verified JSON through; exit code is still the verdict.
  "$DETERM_LIGHT" cross-check --genesis "$GENESIS" "${PEER_ARGS[@]}" --json
  exit $?
fi

# Capture human output to extract the verdict, then collapse to one line.
OUT=$("$DETERM_LIGHT" cross-check --genesis "$GENESIS" "${PEER_ARGS[@]}" 2>&1)
RC=$?

# Map the exit code to a verdict label. The exit code is authoritative
# (the binary's contract); the text scrape is only a fallback for the
# UNVERIFIABLE-vs-usage split.
case "$RC" in
  0) VERDICT="AGREE" ;;
  2) VERDICT="DIVERGENCE" ;;
  3) VERDICT="INCONCLUSIVE" ;;
  1) VERDICT="UNVERIFIABLE" ;;
  *) VERDICT="ERROR" ;;
esac

LINE="CROSSCHECK $VERDICT peers=$PEER_COUNT genesis=$GENESIS_SHORT"
if [ "$RC" = "0" ]; then
  echo "$LINE"
else
  # Non-AGREE: surface on stderr for monitor capture, and append the first
  # diagnostic line from the binary if present (DIVERGENCE height / error).
  DETAIL=$(printf '%s\n' "$OUT" | grep -iE 'DIVERGENCE|UNVERIFIABLE|VERDICT|required' | head -1)
  if [ -n "$DETAIL" ]; then
    echo "$LINE :: $DETAIL" >&2
  else
    echo "$LINE" >&2
  fi
fi
exit $RC
