#!/usr/bin/env bash
# operator_consensus_lag.sh — detect consensus-lag among a set of peer
# nodes by polling each one's `status` RPC and comparing height to the
# fleet-wide max.
#
# Use case: an operator running a small cluster (or watching a public
# committee from a sidecar) wants a single command that flags any node
# whose tip is behind the leader by more than a threshold. The same
# signal can come from `determ check-fork` on two nodes, but that's a
# pairwise comparison; this script is N-way and biased toward "how far
# behind is each peer?" rather than "do these two diverge on field X?".
#
# Lag definition: max_height - peer_height (non-negative; the fleet
# max is by definition not lagging). Stragglers are peers whose lag
# exceeds --threshold (default 3 blocks — large enough to absorb the
# normal one-block-stale skew between a proposer and its committee
# during the Phase-2 reveal window, small enough to alert before a
# stalled peer falls so far behind it needs snapshot recovery).
#
# Unreachable peers (RPC error) are treated as max-lag stragglers
# (lag = max_height, peer_height = null) — operationally indistinguishable
# from a stalled node from the cluster's perspective, and an alert
# either way.
#
# Read-only RPC; safe against any running daemon. Each port must be
# listening on 127.0.0.1.
#
# Usage:
#   tools/operator_consensus_lag.sh --rpc-ports 8771,8772,8773 \
#                                   [--threshold N] [--json]
#
# Exit codes:
#   0   no stragglers (all peers within threshold of the fleet max)
#   1   at least one straggler detected (operator alert gate;
#       includes any unreachable peer) OR bad arguments
#
# Note on exit policy: collapsed to 0/1 per the script's own contract.
# Sibling operator scripts (operator_chain_health, operator_supply_check)
# use 0/1/2 splits to separate "RPC layer broken" from "alert gate
# fired"; this script keeps the simpler 0/1 split because a single
# unreachable peer is itself an alert condition (treated as a max-lag
# straggler), so the two-state contract is sufficient for monitoring
# wrappers.
set -u

usage() {
  cat <<'EOF'
Usage: operator_consensus_lag.sh --rpc-ports P1,P2,... [--threshold N] [--json]

Polls `determ status --rpc-port <P>` on each comma-separated port,
extracts the .height field, computes per-peer lag against the fleet
max, and flags peers whose lag exceeds --threshold as STRAGGLERS.

Unreachable peers (RPC error from `determ status`) are treated as
max-lag stragglers — their height is reported as null in JSON and
"unreachable" in the human table.

Required:
  --rpc-ports LIST     Comma-separated RPC ports (e.g. 8771,8772,8773).
                       At least one port is required; duplicates are
                       de-duped in stable order.

Options:
  --threshold N        Lag threshold in blocks (default: 3). A peer is
                       a straggler iff lag > threshold.
  --json               Emit structured JSON envelope instead of human
                       table. Shape:
                         {"max_height": N,
                          "peers": [{"port": P, "height": H|null,
                                     "lag": L, "straggler": bool,
                                     "reachable": bool}, ...],
                          "stragglers": [P, ...],
                          "ok": bool}
  -h, --help           Show this help.

Exit codes:
  0   no stragglers detected
  1   at least one straggler detected (includes unreachable peers)
      or bad arguments
EOF
}

PORTS_RAW=""
THRESHOLD=3
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)     usage; exit 0 ;;
    --rpc-ports)   PORTS_RAW="${2:-}"; shift 2 ;;
    --threshold)   THRESHOLD="${2:-}"; shift 2 ;;
    --json)        JSON_OUT=1; shift ;;
    *) echo "operator_consensus_lag: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$PORTS_RAW" ]; then
  echo "operator_consensus_lag: --rpc-ports is required (comma-separated, e.g. 8771,8772,8773)" >&2
  usage >&2
  exit 1
fi

# Numeric guard on threshold. 0 is a valid threshold (strict equality
# with the max). Negative would be a config error; keep the unsigned
# class.
case "$THRESHOLD" in *[!0-9]*|"")
  echo "operator_consensus_lag: --threshold must be a non-negative integer (got '$THRESHOLD')" >&2
  exit 1 ;;
esac

# Parse + validate ports. Split on comma, strip whitespace, dedup in
# encounter order (preserve operator-supplied ordering so the human
# output is predictable).
PORTS=""
SEEN=""
IFS=',' read -ra _PORTS <<<"$PORTS_RAW"
for raw in "${_PORTS[@]}"; do
  # Trim surrounding whitespace.
  p="${raw#"${raw%%[![:space:]]*}"}"
  p="${p%"${p##*[![:space:]]}"}"
  if [ -z "$p" ]; then
    continue
  fi
  case "$p" in *[!0-9]*)
    echo "operator_consensus_lag: --rpc-ports entry '$p' is not numeric" >&2
    exit 1 ;;
  esac
  if [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
    echo "operator_consensus_lag: --rpc-ports entry '$p' must be 1..65535" >&2
    exit 1
  fi
  # Dedup.
  case " $SEEN " in
    *" $p "*) continue ;;
  esac
  SEEN="$SEEN $p"
  if [ -z "$PORTS" ]; then PORTS="$p"; else PORTS="$PORTS $p"; fi
done

if [ -z "$PORTS" ]; then
  echo "operator_consensus_lag: --rpc-ports resolved to an empty list" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Poll each port's status RPC. We use `--field height` so we don't have
# to JSON-parse — the binary already extracts the value. Empty / non-
# numeric output is treated as unreachable (RPC returned but the field
# was absent: still actionable, still a straggler).
#
# Two parallel arrays (port -> height-or-empty) accumulated as
# whitespace-separated tokens. Heights default to empty string for
# unreachable peers (distinct from "0" which is a legitimate genesis-
# only fresh chain).
HEIGHTS=""
for port in $PORTS; do
  h=$("$DETERM" status --field height --rpc-port "$port" 2>/dev/null || true)
  # Strip any trailing whitespace/newline; tolerate the empty-line that
  # cmd_status emits when the field is absent.
  h="${h%$'\n'}"
  h="${h%$'\r'}"
  h="${h#"${h%%[![:space:]]*}"}"
  h="${h%"${h##*[![:space:]]}"}"
  # Reject non-numeric (also catches the empty case from the unreachable
  # path above). The python summarizer below treats "" as unreachable.
  case "$h" in
    ""|*[!0-9]*) h="" ;;
  esac
  if [ -z "$HEIGHTS" ]; then HEIGHTS="$h"; else HEIGHTS="$HEIGHTS|$h"; fi
done

# Hand off to python for the max + lag + straggler classification and
# the JSON / human rendering. Pipe-delimited so empty heights survive
# the split (whitespace-split would collapse empties).
PORTS_PIPE=$(printf '%s' "$PORTS" | tr ' ' '|')
python - "$PORTS_PIPE" "$HEIGHTS" "$THRESHOLD" "$JSON_OUT" <<'PY'
import json, sys

ports_s, heights_s, threshold_s, json_out_s = sys.argv[1:5]
ports     = [p for p in ports_s.split('|') if p]
heights_r = heights_s.split('|') if heights_s != "" else []
# Pad heights to len(ports) — defensive in case of an unexpected split
# mismatch (shouldn't happen because we always wrote one entry per port).
while len(heights_r) < len(ports):
    heights_r.append("")
threshold = int(threshold_s)
json_out  = json_out_s == "1"

peers = []
reachable_heights = []
for port_s, h_s in zip(ports, heights_r):
    port = int(port_s)
    if h_s == "":
        peers.append({"port": port, "height": None, "reachable": False})
    else:
        h = int(h_s)
        peers.append({"port": port, "height": h, "reachable": True})
        reachable_heights.append(h)

# Max-height across reachable peers. If no peer is reachable, max is 0
# and all peers are at "lag = 0" by that yardstick — but every one is
# also unreachable, so every one is still a straggler via the
# unreachable path. The two policies cohere.
max_height = max(reachable_heights) if reachable_heights else 0

stragglers = []
for p in peers:
    if not p["reachable"]:
        # Unreachable peer: report lag = max_height (i.e. the worst
        # case — they could be at 0). Always a straggler.
        p["lag"] = max_height
        p["straggler"] = True
        stragglers.append(p["port"])
    else:
        lag = max_height - p["height"]
        p["lag"] = lag
        p["straggler"] = lag > threshold
        if p["straggler"]:
            stragglers.append(p["port"])

ok = len(stragglers) == 0

if json_out:
    envelope = {
        "max_height": max_height,
        "peers":      peers,
        "stragglers": stragglers,
        "ok":         ok,
        "threshold":  threshold,
    }
    print(json.dumps(envelope))
    sys.exit(0 if ok else 1)

# Human-readable table.
print(f"=== Consensus lag check (threshold={threshold} blocks) ===")
print(f"Fleet max height: {max_height}")
print()
print(f"  {'port':>6}  {'height':>11}  {'lag':>6}  status")
print(f"  {'-'*6}  {'-'*11}  {'-'*6}  {'-'*23}")
for p in peers:
    if not p["reachable"]:
        h_disp = "unreachable"
        # "?" is more honest than "0" when max_height is itself 0
        # (all-unreachable case) — we genuinely don't know the lag.
        lag_disp = "?"
        status = "STRAGGLER (unreachable)"
    else:
        h_disp = str(p["height"])
        lag_disp = str(p["lag"])
        status = "STRAGGLER" if p["straggler"] else "OK"
    print(f"  {p['port']:>6}  {h_disp:>11}  {lag_disp:>6}  {status}")

print()
n = len(peers)
n_strag = len(stragglers)
if ok:
    print(f"[OK] all {n} peer(s) within {threshold} blocks of the fleet max")
else:
    print(f"[ALERT] {n_strag} of {n} peer(s) lagging > {threshold} blocks: "
          f"{','.join(str(s) for s in stragglers)}")
sys.exit(0 if ok else 1)
PY
exit $?
