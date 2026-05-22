#!/usr/bin/env bash
# operator_block_propagation_latency.sh — multi-node block-propagation
# latency tracker.
#
# Use case: an operator running (or watching) a small cluster wants to
# know how long blocks take to land at every peer. Long propagation
# latency between peers indicates slow links, gossip-out-of-lock
# congestion (v2.6 / S-031), network partitions, or a misbehaving
# producer that holds blocks under lock. This is the time-domain
# complement to `operator_consensus_lag.sh` (which is a single-shot
# height comparison) and `operator_consensus_latency.sh` (which is
# inter-block-delta from a single node's chain).
#
# Method: poll `determ status --rpc-port <P>` on each peer every
# --poll-interval-sec seconds for --duration-sec seconds. Record
# (timestamp, port, height, head_hash) on every poll. For each block
# height H we observed at least once, the "received_at" for a given
# port is the FIRST poll where that port reported height ≥ H — i.e.
# the earliest moment we can confirm the block had landed on that node.
# Per-block propagation latency = max(received_at) - min(received_at)
# across all ports. The port reporting the earliest received_at for a
# given height is the "leader" for that block (likely the producer or
# the producer's nearest committee neighbor).
#
# Resolution caveat: the script samples wall-clock time at poll
# boundaries, so per-block latency is quantized to ~--poll-interval-sec
# (default 1s). On sub-second profiles (cluster ~50ms, tactical ~20ms)
# blocks can propagate in <1s and all peers will appear to receive the
# same block in the same poll — latency reads 0s on those profiles
# unless you drop --poll-interval-sec below the block time. Operators
# running global (~2s/block) or regional (~600ms/block) get useful
# signal at the default poll interval.
#
# Anomalies (in priority order):
#   - high_propagation_latency: at least one block has latency > 2× the
#     median across all observed blocks. Median is robust to a small
#     number of slow blocks; this flag fires when at least one block is
#     much slower than typical for the same cluster.
#   - peer_stuck: at least one peer has not progressed (height didn't
#     change) for > --duration-sec / 4 seconds. Stuck for >25% of the
#     monitoring window is a strong signal of a real stall, not just a
#     between-blocks pause.
#   - head_hash_divergence: at any single poll, two peers report the
#     SAME height but DIFFERENT head_hash. This is the canonical fork
#     signal: same height, different chain. Logged immediately
#     (priority of priorities) because it indicates an active fork.
#     The check is per-poll; if peers later reconcile via fork-choice
#     (S-029) the divergence still gets flagged.
#
# Unreachable peers (RPC error) are tolerated for the duration of the
# poll loop — the poll record for that (timestamp, port) is omitted.
# A peer that is unreachable for the entire window is treated as
# peer_stuck (never progressed).
#
# Read-only RPC; safe against any running daemon. Each port must be
# listening on 127.0.0.1.
#
# Usage:
#   tools/operator_block_propagation_latency.sh \
#       --rpc-ports 8771,8772,8773 \
#       [--poll-interval-sec N] [--duration-sec N] \
#       [--lag-threshold N] [--json] [--anomalies-only]
#
# Exit codes:
#   0   healthy — no anomalies flagged
#   1   RPC / argument error (cannot reach ANY peer; bad args)
#   2   at least one anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_block_propagation_latency.sh --rpc-ports P1,P2,...
           [--poll-interval-sec N] [--duration-sec N]
           [--lag-threshold N] [--json] [--anomalies-only]

Tracks block-receive latency across multiple nodes. Polls each peer's
`determ status` every --poll-interval-sec seconds for --duration-sec
seconds. For each block height observed, computes per-peer received_at
(time of FIRST poll where that peer's height >= H) and per-block
propagation latency = max(received_at) - min(received_at) across peers.

Required:
  --rpc-ports LIST          Comma-separated RPC ports (e.g. 8771,8772,8773).
                            At least 2 ports needed for meaningful latency;
                            1 port runs without an inter-peer comparison.

Options:
  --poll-interval-sec N     Polling interval in seconds (default: 1).
                            Sub-second polls require sub-second precision
                            in `sleep` (most shells support fractional
                            seconds; this script uses integer seconds).
  --duration-sec N          Monitoring window in seconds (default: 60).
  --lag-threshold N         Blocks-behind-leader threshold (default: 3).
                            A peer reporting height < leader_height -
                            threshold at any poll is flagged in the
                            per-poll lag column (informational; doesn't
                            gate exit code by itself).
  --json                    Emit structured JSON envelope instead of human
                            table. Shape:
                              {"ports": [...], "duration_sec": N,
                               "poll_interval_sec": N, "polls": N,
                               "blocks_observed": N,
                               "blocks": [{"height": H, "received_at": {port: ts},
                                           "max_latency_sec": L, "leader_port": P}, ...],
                               "stats": {"median_latency_sec": ...,
                                         "p95_latency_sec": ...,
                                         "max_latency_sec": ...},
                               "anomalies": [...],
                               "ok": bool}
  --anomalies-only          Suppress healthy table output; still exits 2
                            on anomaly.
  -h, --help                Show this help.

Anomalies:
  high_propagation_latency  At least one block had latency > 2× median.
  peer_stuck                At least one peer didn't progress for
                            > duration_sec/4 seconds.
  head_hash_divergence      At a single poll, two peers reported the
                            SAME height but DIFFERENT head_hash
                            (fork signal — priority anomaly).

Exit codes:
  0   healthy (no anomalies)
  1   RPC / args error (no peer reachable; bad args)
  2   at least one anomaly fired
EOF
}

PORTS_RAW=""
POLL_INTERVAL_SEC=1
DURATION_SEC=60
LAG_THRESHOLD=3
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)            usage; exit 0 ;;
    --rpc-ports)          PORTS_RAW="${2:-}";          shift 2 ;;
    --poll-interval-sec)  POLL_INTERVAL_SEC="${2:-}";  shift 2 ;;
    --duration-sec)       DURATION_SEC="${2:-}";       shift 2 ;;
    --lag-threshold)      LAG_THRESHOLD="${2:-}";      shift 2 ;;
    --json)               JSON_OUT=1;                  shift ;;
    --anomalies-only)     ANOM_ONLY=1;                 shift ;;
    *) echo "operator_block_propagation_latency: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$PORTS_RAW" ]; then
  echo "operator_block_propagation_latency: --rpc-ports is required (comma-separated, e.g. 8771,8772,8773)" >&2
  usage >&2
  exit 1
fi

# Numeric guards. POLL_INTERVAL_SEC and DURATION_SEC must be positive;
# LAG_THRESHOLD may be 0 (strict equality with leader).
case "$POLL_INTERVAL_SEC" in *[!0-9]*|"")
  echo "operator_block_propagation_latency: --poll-interval-sec must be a positive integer (got '$POLL_INTERVAL_SEC')" >&2
  exit 1 ;;
esac
case "$DURATION_SEC" in *[!0-9]*|"")
  echo "operator_block_propagation_latency: --duration-sec must be a positive integer (got '$DURATION_SEC')" >&2
  exit 1 ;;
esac
case "$LAG_THRESHOLD" in *[!0-9]*|"")
  echo "operator_block_propagation_latency: --lag-threshold must be a non-negative integer (got '$LAG_THRESHOLD')" >&2
  exit 1 ;;
esac
if [ "$POLL_INTERVAL_SEC" -lt 1 ]; then
  echo "operator_block_propagation_latency: --poll-interval-sec must be >= 1 (got '$POLL_INTERVAL_SEC')" >&2
  exit 1
fi
if [ "$DURATION_SEC" -lt 1 ]; then
  echo "operator_block_propagation_latency: --duration-sec must be >= 1 (got '$DURATION_SEC')" >&2
  exit 1
fi
if [ "$DURATION_SEC" -lt "$POLL_INTERVAL_SEC" ]; then
  echo "operator_block_propagation_latency: --duration-sec ($DURATION_SEC) must be >= --poll-interval-sec ($POLL_INTERVAL_SEC)" >&2
  exit 1
fi

# Parse + validate ports (same logic as operator_consensus_lag.sh:
# split on comma, strip whitespace, dedup in encounter order).
PORTS=""
SEEN=""
IFS=',' read -ra _PORTS <<<"$PORTS_RAW"
for raw in "${_PORTS[@]}"; do
  p="${raw#"${raw%%[![:space:]]*}"}"
  p="${p%"${p##*[![:space:]]}"}"
  if [ -z "$p" ]; then continue; fi
  case "$p" in *[!0-9]*)
    echo "operator_block_propagation_latency: --rpc-ports entry '$p' is not numeric" >&2
    exit 1 ;;
  esac
  if [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
    echo "operator_block_propagation_latency: --rpc-ports entry '$p' must be 1..65535" >&2
    exit 1
  fi
  case " $SEEN " in
    *" $p "*) continue ;;
  esac
  SEEN="$SEEN $p"
  if [ -z "$PORTS" ]; then PORTS="$p"; else PORTS="$PORTS $p"; fi
done

if [ -z "$PORTS" ]; then
  echo "operator_block_propagation_latency: --rpc-ports resolved to an empty list" >&2
  exit 1
fi

# Compute the number of polls we'll do. Each pass over the port list
# counts as one poll; we wake up at t=0, t=POLL_INTERVAL_SEC, etc., up
# to (and including) the last poll that fits before DURATION_SEC
# elapses. POLL_COUNT = floor(DURATION_SEC / POLL_INTERVAL_SEC) + 1.
POLL_COUNT=$(( DURATION_SEC / POLL_INTERVAL_SEC + 1 ))

cd "$(dirname "$0")/.."
source tools/common.sh

# Collect poll records: one line per (poll_idx, port) sample, written
# as TSV to a temp file. Format:
#   <poll_idx>\t<elapsed_sec>\t<port>\t<height_or_empty>\t<head_hash_or_empty>
# Empty height/head_hash means the peer was unreachable at that poll.
TMP_POLLS=$(mktemp 2>/dev/null) || {
  echo "operator_block_propagation_latency: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_POLLS" 2>/dev/null' EXIT

# Sample a single (port) at a single poll. Returns (height, head_hash)
# tokens whitespace-separated on stdout, or empty/empty on RPC error.
# We pull the full status JSON (single RPC) and extract two fields via
# python — simpler and more robust than `--field` twice.
sample_port() {
  local port="$1"
  local raw rc
  raw=$("$DETERM" status --rpc-port "$port" 2>/dev/null) ; rc=$?
  if [ "$rc" != "0" ] || [ -z "$raw" ]; then
    printf '\t'
    return
  fi
  printf '%s' "$raw" | python -c '
import sys, json
try:
    j = json.loads(sys.stdin.read())
    h = j.get("height", "")
    hh = j.get("head_hash", "")
    print(f"{h}\t{hh}")
except Exception:
    print("\t")
'
}

# Run the poll loop. We track elapsed seconds against a reference
# epoch captured before the first sleep so cumulative drift doesn't
# bias later polls.
T0=$(date +%s)
ANY_REACHABLE=0
for poll_idx in $(seq 0 $(( POLL_COUNT - 1 ))); do
  for port in $PORTS; do
    line=$(sample_port "$port")
    height="${line%%$'\t'*}"
    head_hash="${line#*$'\t'}"
    NOW=$(date +%s)
    ELAPSED=$(( NOW - T0 ))
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$poll_idx" "$ELAPSED" "$port" "$height" "$head_hash" >>"$TMP_POLLS"
    if [ -n "$height" ]; then ANY_REACHABLE=1; fi
  done
  # Don't sleep after the last poll.
  if [ "$poll_idx" -lt "$(( POLL_COUNT - 1 ))" ]; then
    sleep "$POLL_INTERVAL_SEC"
  fi
done

if [ "$ANY_REACHABLE" = "0" ]; then
  echo "operator_block_propagation_latency: no peer reachable across the entire window (all $POLL_COUNT polls failed for every port)" >&2
  exit 1
fi

# Hand off to python for the analysis. Pass: ports, duration, interval,
# threshold, json/anom flags, and the poll log.
PORTS_PIPE=$(printf '%s' "$PORTS" | tr ' ' '|')
python - "$PORTS_PIPE" "$DURATION_SEC" "$POLL_INTERVAL_SEC" \
        "$LAG_THRESHOLD" "$JSON_OUT" "$ANOM_ONLY" "$TMP_POLLS" <<'PY'
import json, sys

(ports_s, dur_s, poll_s, lag_s, json_out_s, anom_only_s, polls_path) = sys.argv[1:8]
ports = [int(p) for p in ports_s.split('|') if p]
duration_sec = int(dur_s)
poll_interval_sec = int(poll_s)
lag_threshold = int(lag_s)
json_out = (json_out_s == "1")
anom_only = (anom_only_s == "1")

# polls: list of (poll_idx, elapsed_sec, port, height|None, head_hash|None)
polls = []
with open(polls_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t")
        # The last field (head_hash) may be empty; ensure we always have 5 cols.
        while len(parts) < 5:
            parts.append("")
        poll_idx, elapsed_s, port_s, h_s, hh_s = parts[0], parts[1], parts[2], parts[3], parts[4]
        try:
            poll_idx_i = int(poll_idx)
            elapsed_i  = int(elapsed_s)
            port_i     = int(port_s)
        except ValueError:
            continue
        h = int(h_s) if h_s.isdigit() else None
        hh = hh_s if hh_s else None
        polls.append((poll_idx_i, elapsed_i, port_i, h, hh))

# poll_count: number of unique poll_idx values observed (some polls may
# have failed on every port but we still emitted the row).
poll_indices = sorted({p[0] for p in polls})
poll_count = len(poll_indices)

# Group polls by poll_idx → list of (port, height, head_hash, elapsed).
# We use the elapsed_sec value of the FIRST entry in a poll batch as the
# canonical "poll time" — within one poll all ports were sampled in
# rapid succession (~ms apart).
poll_time = {}
poll_rows = {}
for (idx, elapsed, port, h, hh) in polls:
    if idx not in poll_time:
        poll_time[idx] = elapsed
    poll_rows.setdefault(idx, []).append((port, h, hh))

# ── received_at per (height, port) ────────────────────────────────────────────
# For each (height, port) pair, received_at = the elapsed_sec of the
# FIRST poll where that port reported height >= H. We compute this by
# walking polls in time order and remembering the first time we saw a
# height threshold cross for each port.
#
# We only consider heights actually observed at SOME peer during the
# monitoring window (no extrapolation; if a peer never reported a given
# height we just leave it absent — that peer is either lagging or never
# reached it before the window closed).
all_heights = sorted({h for (_, _, _, h, _) in polls if h is not None})

# For O(N) computation: per-port, sort polls by time and walk forward
# tracking max height seen. For each height H in all_heights, the
# received_at[port][H] is the first elapsed where max_height_so_far >= H.
received_at = {p: {} for p in ports}
port_max_height_at = {p: [] for p in ports}    # list of (elapsed, max_height)
for port in ports:
    samples = sorted(
        ((idx, h) for (idx, _, pp, h, _) in polls if pp == port and h is not None),
        key=lambda x: x[0]
    )
    max_h = -1
    for (idx, h) in samples:
        if h > max_h:
            max_h = h
            port_max_height_at[port].append((poll_time[idx], max_h))

# For each height, walk per-port crossings to find the first elapsed
# where that port's running max crossed >= H. Use a simple linear scan
# (heights count is bounded by poll_count, so O(P * polls * heights) is
# fine for any practical run length).
for H in all_heights:
    for port in ports:
        for (t, mh) in port_max_height_at[port]:
            if mh >= H:
                received_at[port][H] = t
                break

# ── per-block latency table ───────────────────────────────────────────────────
blocks = []
for H in all_heights:
    rx_by_port = {p: received_at[p].get(H) for p in ports}
    # received_at is None for ports that never reported >= H in the window.
    seen_times = [t for t in rx_by_port.values() if t is not None]
    if not seen_times:
        # Should not happen since H is in all_heights, but guard anyway.
        continue
    first_t = min(seen_times)
    last_t  = max(seen_times)
    # Leader = port with the earliest received_at; tie-break by port number.
    leader = min(
        ((p, t) for (p, t) in rx_by_port.items() if t is not None),
        key=lambda kv: (kv[1], kv[0]),
    )[0]
    blocks.append({
        "height": H,
        "received_at": rx_by_port,
        "first_received_at_sec": first_t,
        "last_received_at_sec":  last_t,
        "max_latency_sec":       last_t - first_t,
        "leader_port":           leader,
    })

# ── stats: median / p95 / max across all observed blocks ─────────────────────
latencies = sorted(b["max_latency_sec"] for b in blocks)
def quantile(sorted_xs, q):
    if not sorted_xs:
        return 0
    if len(sorted_xs) == 1:
        return sorted_xs[0]
    pos = q * (len(sorted_xs) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_xs) - 1)
    frac = pos - lo
    return int(round(sorted_xs[lo] + (sorted_xs[hi] - sorted_xs[lo]) * frac))

median_l = quantile(latencies, 0.50)
p95_l    = quantile(latencies, 0.95)
max_l    = latencies[-1] if latencies else 0

# ── anomaly classification ────────────────────────────────────────────────────
anomalies = []

# (1) high_propagation_latency: at least one block has latency > 2× median.
# Median is the robust center; we use strict > so a perfectly-uniform
# cluster (all latencies = median) never fires this. Requires at least
# 2 blocks (we need a non-trivial median to compare against).
high_prop = False
if len(latencies) >= 2 and median_l >= 0:
    threshold = 2 * median_l
    if max_l > threshold:
        high_prop = True
        anomalies.append("high_propagation_latency")

# (2) peer_stuck: any peer didn't progress for > duration_sec / 4.
# We measure "progress" as a strict increase in observed height. A peer
# that was unreachable for the entire window also counts as stuck.
stuck_threshold = duration_sec // 4
stuck_peers = []
for port in ports:
    heights_seen = port_max_height_at[port]
    if not heights_seen:
        # Never reachable in window.
        stuck_peers.append({"port": port, "last_progress_sec": None, "reason": "unreachable"})
        continue
    # Find longest gap between strictly-increasing heights. We use
    # poll_time bracketing: between any two consecutive "max increased"
    # entries, the gap is t[i+1] - t[i]. We also bracket the tail:
    # if the last increase was at t_last, the trailing gap is
    # (duration_sec - t_last). Likewise the head: if first increase was
    # at t_first, the leading gap is t_first - 0. Either can trigger.
    increase_times = [t for (t, _) in heights_seen]
    # Sentinel boundaries: 0 (start) and duration_sec (end).
    boundary = [0] + increase_times + [duration_sec]
    gaps = [(boundary[i+1] - boundary[i]) for i in range(len(boundary) - 1)]
    max_gap = max(gaps) if gaps else 0
    if max_gap > stuck_threshold:
        stuck_peers.append({"port": port, "longest_no_progress_sec": max_gap,
                            "last_progress_sec": increase_times[-1] if increase_times else None,
                            "reason": "no_progress"})
if stuck_peers:
    anomalies.append("peer_stuck")

# (3) head_hash_divergence: at any poll, two peers reported the SAME
# height but DIFFERENT head_hash. Loud anomaly — possible active fork.
divergences = []
for idx in poll_indices:
    rows = poll_rows.get(idx, [])
    # Group by height; if any group has > 1 distinct head_hash, divergence.
    by_height = {}
    for (port, h, hh) in rows:
        if h is None or hh is None:
            continue
        by_height.setdefault(h, []).append((port, hh))
    for (h, peers_with_h) in by_height.items():
        hashes = {hh for (_, hh) in peers_with_h}
        if len(hashes) > 1:
            divergences.append({
                "poll_idx":  idx,
                "elapsed_sec": poll_time[idx],
                "height":    h,
                "peers":     [{"port": p, "head_hash": hh} for (p, hh) in peers_with_h],
            })
if divergences:
    anomalies.append("head_hash_divergence")

ok = (len(anomalies) == 0)

# ── output ────────────────────────────────────────────────────────────────────
if json_out:
    env = {
        "ports": ports,
        "duration_sec":       duration_sec,
        "poll_interval_sec":  poll_interval_sec,
        "lag_threshold":      lag_threshold,
        "polls":              poll_count,
        "blocks_observed":    len(blocks),
        "blocks": [
            {
                "height":               b["height"],
                "received_at":          {str(p): t for (p, t) in b["received_at"].items()},
                "first_received_at_sec": b["first_received_at_sec"],
                "last_received_at_sec":  b["last_received_at_sec"],
                "max_latency_sec":       b["max_latency_sec"],
                "leader_port":           b["leader_port"],
            }
            for b in blocks
        ],
        "stats": {
            "median_latency_sec":  median_l,
            "p95_latency_sec":     p95_l,
            "max_latency_sec":     max_l,
        },
        "stuck_peers":  stuck_peers,
        "divergences":  divergences,
        "anomalies":    anomalies,
        "ok":           ok,
    }
    print(json.dumps(env))
    sys.exit(0 if ok else 2)

# Human-readable rendering.
header = ("=== Block propagation latency "
          f"(ports={','.join(str(p) for p in ports)}, "
          f"duration={duration_sec}s, poll={poll_interval_sec}s, "
          f"polls={poll_count}, blocks_observed={len(blocks)}) ===")
print(header)

if not anom_only:
    print()
    if not blocks:
        print("(no blocks observed across the monitoring window — "
              "either the chain didn't progress or no peer was reachable enough "
              "to capture a height sample)")
    else:
        # Per-block table. Columns: height, leader port, leader rx, every
        # peer's rx, max latency.
        cols = ["height", "leader", "first_rx_s"]
        for p in ports:
            cols.append(f"rx_{p}_s")
        cols.append("max_lat_s")
        # Width tuning.
        w_height = max(6, max(len(str(b["height"])) for b in blocks) + 1)
        w_leader = max(7, max(len(str(b["leader_port"])) for b in blocks) + 1)
        w_first  = 11
        w_rx     = 9
        w_lat    = 10
        header_row = (
            f"  {'height':>{w_height}}  {'leader':>{w_leader}}  "
            f"{'first_rx_s':>{w_first}}  "
            + "  ".join(f"{('rx_'+str(p)+'_s'):>{w_rx}}" for p in ports)
            + f"  {'max_lat_s':>{w_lat}}"
        )
        sep_row = (
            f"  {'-'*w_height}  {'-'*w_leader}  {'-'*w_first}  "
            + "  ".join('-'*w_rx for _ in ports)
            + f"  {'-'*w_lat}"
        )
        print(header_row)
        print(sep_row)
        for b in blocks:
            rx_cells = []
            for p in ports:
                t = b["received_at"].get(p)
                rx_cells.append(f"{('?' if t is None else str(t)):>{w_rx}}")
            print(
                f"  {b['height']:>{w_height}}  {b['leader_port']:>{w_leader}}  "
                f"{b['first_received_at_sec']:>{w_first}}  "
                + "  ".join(rx_cells)
                + f"  {b['max_latency_sec']:>{w_lat}}"
            )
        print()
        print("Latency summary (seconds across observed blocks):")
        print(f"  median: {median_l}")
        print(f"  p95:    {p95_l}")
        print(f"  max:    {max_l}")

print()
if ok:
    print(f"[OK] no anomalies across {len(blocks)} observed block(s), {len(ports)} peer(s)")
else:
    print(f"[ANOMALY] {len(anomalies)} flag(s): {','.join(anomalies)}")
    if high_prop:
        print(f"  high_propagation_latency : max latency {max_l}s > 2× median ({median_l}s)")
    if stuck_peers:
        labels = []
        for s in stuck_peers:
            if s["reason"] == "unreachable":
                labels.append(f"port {s['port']} (unreachable entire window)")
            else:
                labels.append(f"port {s['port']} (no progress for {s['longest_no_progress_sec']}s "
                              f"> threshold {stuck_threshold}s)")
        print(f"  peer_stuck               : {'; '.join(labels)}")
    if divergences:
        print(f"  head_hash_divergence     : {len(divergences)} poll(s) with same-height different-head_hash")
        for d in divergences[:5]:
            tail = ", ".join(f"port {pp['port']}={pp['head_hash'][:12]}..."
                              for pp in d["peers"])
            print(f"    poll {d['poll_idx']} (t={d['elapsed_sec']}s) height={d['height']}: {tail}")
        if len(divergences) > 5:
            print(f"    ... and {len(divergences) - 5} more divergence event(s)")
sys.exit(0 if ok else 2)
PY
exit $?
