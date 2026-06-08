#!/usr/bin/env bash
# operator_peer_rtt_audit.sh — per-peer RPC round-trip-latency audit.
#
# Use case: an operator running (or watching) a small cluster wants ONE
# command that answers "which of my reachable nodes are SLOW to answer
# RPC right now, and which are stalled / unreachable?" — i.e. the
# latency dimension of peer health, which NO existing tool reports.
#
# Sibling positioning (network / peer / latency lane) — the existing
# tools in this lane either enumerate peers WITHOUT timing them, or
# time block/consensus events rather than the RPC round-trip:
#   * operator_peer_topology.sh           — peer GRAPH shape
#     (eclipse / clustering / connected-components) across --rpc-ports.
#     Counts edges; never times a call.
#   * operator_peer_connectivity_health.sh — SINGLE-NODE connectivity
#     digest (peer count vs eclipse floor, committee-formability,
#     HELLO-handshake completeness). No latency.
#   * operator_consensus_lag.sh           — N-way HEIGHT lag across a
#     fleet (single-shot height comparison). No latency.
#   * operator_consensus_latency.sh       — inter-BLOCK timestamp deltas
#     from one node's chain (finalization wall-clock). Not RPC RTT.
#   * operator_block_propagation_latency.sh — time a BLOCK takes to land
#     at every peer (height-poll over a window). Not RPC RTT.
#
# THIS tool is the missing per-endpoint RPC-round-trip view: it TIMES a
# lightweight `status` call to each --rpc-ports endpoint, reports a
# min/mean/max latency table, and flags endpoints whose mean RTT exceeds
# a threshold (stalled) or that don't answer at all (unreachable). The
# confirmed gap it fills: the `peers` RPC (rpc_peers, src/node/node.cpp
# ~2547) returns only peer ADDRESSES with no latency, and the two
# peer-* tools above measure count/topology but never per-peer RTT.
#
# Peer enumeration cross-reference: in addition to timing the operator-
# supplied --rpc-ports, the script queries ONE anchor daemon's `peers`
# RPC (--peers-port, default = first --rpc-ports entry) so the summary
# can report how many peers that anchor node believes it is connected to
# alongside how many RPC endpoints the operator asked us to probe. This
# surfaces the common "I have N gossip peers but only M of them expose a
# reachable RPC port" gap.
#
# ── Why the probe targets are RPC PORTS, not gossip peer addresses ───
# The determ CLI hard-codes 127.0.0.1 for every rpc_call (see
# src/main.cpp — there is no --rpc-host flag), and the `peers` RPC
# returns GOSSIP addresses (host:gossip_port [ (domain)]), not RPC
# endpoints. There is therefore no way to derive a peer's RPC port from
# its gossip address. So, exactly like operator_peer_topology.sh and
# operator_consensus_lag.sh, the operator supplies the RPC ports to
# probe (each interpreted as 127.0.0.1:<port>). The anchor's `peers`
# list is used only for the connected-peer-count cross-reference, never
# as a probe target.
#
# ── RPCs consumed (read-only) ────────────────────────────────────────
#   determ status --rpc-port P   →  rpc_status() at src/node/node.cpp:2461
#       We don't read any field — we only TIME the round trip. The call
#       is the lightest read-only RPC the daemon exposes that proves the
#       full request/parse/dispatch/serialize/respond path is alive.
#   determ peers --json --rpc-port P  →  rpc_peers() at src/node/node.cpp:2547
#       Queried ONCE on the anchor for the connected-peer count only.
#
# No tx is ever sent; no chain file is read or written. Pure read.
#
# ── Latency method ───────────────────────────────────────────────────
# For each endpoint we issue --samples (default 3) sequential `status`
# RPCs, timing each round trip in milliseconds via python's monotonic
# clock (wall-clock would be skewed by NTP steps; monotonic is immune).
# We report min / mean / max over the successful samples. An endpoint is:
#   unreachable  if ZERO of its samples returned exit 0 (daemon down,
#                wrong port, or every probe timed out).
#   stalled      if it IS reachable but its mean RTT (over the successful
#                samples) exceeds --threshold-ms.
# The first sample for each endpoint pays any cold-start / process-spawn
# cost (the CLI is a fresh process per call); reporting min alongside
# mean lets the operator see the warm-path floor too.
#
# ── Classification / anomalies ───────────────────────────────────────
#   unreachable (CRITICAL)  endpoint answered 0 of --samples probes.
#   stalled     (WARN)      reachable but mean RTT > --threshold-ms.
#
# ── Exit-code contract ───────────────────────────────────────────────
#   0   ok / info / clean SKIP (no endpoint reachable is NOT a clean
#       skip — see below); all reachable endpoints within threshold.
#   1   argument error.
#   2   at least one CRITICAL anomaly (unreachable endpoint) fired, OR
#       --anomalies-only AND at least one anomaly (CRITICAL or WARN)
#       present.
#
# Exit policy mirrors operator_peer_topology / operator_chain_health:
# CRITICAL anomalies (unreachable) gate the exit code to 2. WARN
# anomalies (stalled) surface in the output but do NOT gate the exit on
# their own UNLESS --anomalies-only is set (in which case any anomaly
# makes exit 2). An all-unreachable run is the all-CRITICAL case → 2.
#
# ── Usage ────────────────────────────────────────────────────────────
#   tools/operator_peer_rtt_audit.sh --rpc-ports 8771,8772,8773 \
#       [--peers-port P] [--samples N] [--threshold-ms N] \
#       [--json] [--anomalies-only]
set -u

usage() {
  cat <<'EOF'
Usage: operator_peer_rtt_audit.sh --rpc-ports P1,P2,...
           [--peers-port P] [--samples N] [--threshold-ms N]
           [--json] [--anomalies-only]

Per-peer RPC round-trip-latency audit. TIMES a lightweight `determ
status` call to each supplied RPC endpoint (--samples probes each),
reports a min/mean/max latency table, and flags endpoints that are slow
(mean RTT over a threshold) or unreachable. Also queries ONE anchor
daemon's `peers` RPC for a connected-peer-count cross-reference.

Probe targets are RPC PORTS (each interpreted as 127.0.0.1:<port>): the
determ CLI is localhost-only and the `peers` RPC returns gossip
addresses with no RPC port, so — like operator_peer_topology.sh and
operator_consensus_lag.sh — the operator supplies the RPC ports to time.

Required:
  --rpc-ports LIST       Comma-separated RPC ports (e.g. 8771,8772,8773).
                         At least one port is required; duplicates are
                         de-duped in stable order. Each is timed as
                         127.0.0.1:<port>.

Options:
  --peers-port P         RPC port of the anchor daemon whose `peers` RPC
                         is queried ONCE for the connected-peer count
                         cross-reference. Default: the first --rpc-ports
                         entry. Must be 1..65535. If unreachable the
                         cross-reference is reported as n/a (not fatal).
  --samples N            Number of `status` round trips to time per
                         endpoint (default: 3). Must be >= 1. min/mean/max
                         are computed over the SUCCESSFUL samples only.
  --threshold-ms N       Mean-RTT threshold in milliseconds (default:
                         1000). A reachable endpoint whose mean RTT
                         exceeds N fires `stalled` (WARN). Must be a
                         positive integer.
  --json                 Emit a structured JSON envelope instead of the
                         human table.
  --anomalies-only       Suppress healthy table rows; still emit the
                         anomaly section + summary. With this flag set,
                         ANY anomaly present (CRITICAL or WARN) makes the
                         exit code 2.
  -h, --help             Show this help and exit 0.

Anomalies:
  unreachable  CRITICAL — endpoint answered 0 of --samples probes.
  stalled      WARN     — reachable but mean RTT > --threshold-ms.

Exit codes:
  0   all reachable endpoints within threshold (no CRITICAL anomaly)
  1   argument error
  2   at least one unreachable endpoint (CRITICAL), OR --anomalies-only
      AND at least one anomaly present
EOF
}

PORTS_RAW=""
PEERS_PORT=""
SAMPLES=3
THRESHOLD_MS=1000
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-ports)       PORTS_RAW="${2:-}";    shift 2 ;;
    --peers-port)      PEERS_PORT="${2:-}";   shift 2 ;;
    --samples)         SAMPLES="${2:-}";      shift 2 ;;
    --threshold-ms)    THRESHOLD_MS="${2:-}"; shift 2 ;;
    --json)            JSON_OUT=1;            shift ;;
    --anomalies-only)  ANOM_ONLY=1;           shift ;;
    *) echo "operator_peer_rtt_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$PORTS_RAW" ]; then
  echo "operator_peer_rtt_audit: --rpc-ports is required (comma-separated, e.g. 8771,8772,8773)" >&2
  usage >&2
  exit 1
fi

# ── numeric guards (exit 1 on bad args) ──────────────────────────────
case "$SAMPLES" in *[!0-9]*|"")
  echo "operator_peer_rtt_audit: --samples must be a positive integer (got '$SAMPLES')" >&2
  exit 1 ;;
esac
if [ "$SAMPLES" -lt 1 ]; then
  echo "operator_peer_rtt_audit: --samples must be >= 1 (got '$SAMPLES')" >&2
  exit 1
fi
case "$THRESHOLD_MS" in *[!0-9]*|"")
  echo "operator_peer_rtt_audit: --threshold-ms must be a positive integer (got '$THRESHOLD_MS')" >&2
  exit 1 ;;
esac
if [ "$THRESHOLD_MS" -lt 1 ]; then
  echo "operator_peer_rtt_audit: --threshold-ms must be >= 1 (got '$THRESHOLD_MS')" >&2
  exit 1
fi
if [ -n "$PEERS_PORT" ]; then
  case "$PEERS_PORT" in *[!0-9]*)
    echo "operator_peer_rtt_audit: --peers-port must be a positive integer (got '$PEERS_PORT')" >&2
    exit 1 ;;
  esac
  if [ "$PEERS_PORT" -lt 1 ] || [ "$PEERS_PORT" -gt 65535 ]; then
    echo "operator_peer_rtt_audit: --peers-port must be 1..65535 (got '$PEERS_PORT')" >&2
    exit 1
  fi
fi

# Parse + validate ports (same logic as operator_consensus_lag.sh /
# operator_peer_topology.sh: split on comma, strip whitespace, dedup in
# encounter order so the output is deterministic).
PORTS=""
SEEN=""
IFS=',' read -ra _PORTS <<<"$PORTS_RAW"
for raw in "${_PORTS[@]}"; do
  p="${raw#"${raw%%[![:space:]]*}"}"
  p="${p%"${p##*[![:space:]]}"}"
  if [ -z "$p" ]; then continue; fi
  case "$p" in *[!0-9]*)
    echo "operator_peer_rtt_audit: --rpc-ports entry '$p' is not numeric" >&2
    exit 1 ;;
  esac
  if [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
    echo "operator_peer_rtt_audit: --rpc-ports entry '$p' must be 1..65535" >&2
    exit 1
  fi
  case " $SEEN " in
    *" $p "*) continue ;;
  esac
  SEEN="$SEEN $p"
  if [ -z "$PORTS" ]; then PORTS="$p"; else PORTS="$PORTS $p"; fi
done

if [ -z "$PORTS" ]; then
  echo "operator_peer_rtt_audit: --rpc-ports resolved to an empty list" >&2
  exit 1
fi

# Default the anchor peers-port to the first --rpc-ports entry.
if [ -z "$PEERS_PORT" ]; then
  PEERS_PORT="${PORTS%% *}"
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── anchor peers cross-reference (read-only; one shot; non-fatal) ────
# Query the anchor's `peers` RPC for the connected-peer count. An
# unreachable anchor or a malformed array → count reported as n/a.
PEER_COUNT="n/a"
PEERS_OUT=$("$DETERM" peers --json --rpc-port "$PEERS_PORT" 2>/dev/null || true)
if [ -n "$PEERS_OUT" ]; then
  pc=$(printf '%s' "$PEERS_OUT" | python -c '
import sys, json
try:
    arr = json.loads(sys.stdin.read())
    print(len(arr) if isinstance(arr, list) else "")
except Exception:
    print("")
' 2>/dev/null)
  case "$pc" in
    ""|*[!0-9]*) PEER_COUNT="n/a" ;;
    *)           PEER_COUNT="$pc" ;;
  esac
fi

# ── per-endpoint RTT sampling ────────────────────────────────────────
# For each port, issue --samples timed `status` RPCs. We time each call
# in python (monotonic ms) wrapping the determ invocation, and emit one
# TSV record per endpoint:
#   <port>\t<n_ok>\t<ms1>|<ms2>|...   (only SUCCESSFUL sample ms listed)
# n_ok == 0 means unreachable (empty ms field).
TMP_RTT=$(mktemp 2>/dev/null) || {
  echo "operator_peer_rtt_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_RTT" 2>/dev/null' EXIT

now_ms() { python -c 'import time; print(int(time.monotonic()*1000))'; }

for port in $PORTS; do
  n_ok=0
  ms_list=""
  i=0
  while [ "$i" -lt "$SAMPLES" ]; do
    i=$((i + 1))
    t0=$(now_ms)
    if "$DETERM" status --rpc-port "$port" >/dev/null 2>&1; then
      t1=$(now_ms)
      dt=$((t1 - t0))
      # Guard against a non-monotonic blip (shouldn't happen with a
      # monotonic clock, but clamp to 0 defensively).
      if [ "$dt" -lt 0 ]; then dt=0; fi
      n_ok=$((n_ok + 1))
      if [ -z "$ms_list" ]; then ms_list="$dt"; else ms_list="$ms_list|$dt"; fi
    fi
  done
  printf '%s\t%s\t%s\n' "$port" "$n_ok" "$ms_list" >>"$TMP_RTT"
done

# ── summarize + classify + render in python ──────────────────────────
PORTS_PIPE=$(printf '%s' "$PORTS" | tr ' ' '|')
python - "$PORTS_PIPE" "$SAMPLES" "$THRESHOLD_MS" "$JSON_OUT" "$ANOM_ONLY" \
         "$PEERS_PORT" "$PEER_COUNT" "$TMP_RTT" <<'PY'
import json, sys

(ports_s, samples_s, thr_s, json_out_s, anom_only_s,
 peers_port_s, peer_count_s, rtt_path) = sys.argv[1:9]

ports        = [int(p) for p in ports_s.split('|') if p]
samples      = int(samples_s)
threshold_ms = int(thr_s)
json_out     = (json_out_s == "1")
anom_only    = (anom_only_s == "1")
peers_port   = int(peers_port_s)
peer_count   = None if peer_count_s == "n/a" else int(peer_count_s)

# Read per-endpoint RTT records.
rec_by_port = {}
with open(rtt_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t")
        while len(parts) < 3:
            parts.append("")
        port_s, nok_s, ms_flat = parts[0], parts[1], parts[2]
        try:
            port_i = int(port_s)
            n_ok   = int(nok_s)
        except ValueError:
            continue
        ms_vals = [int(x) for x in ms_flat.split("|") if x] if ms_flat else []
        rec_by_port[port_i] = (n_ok, ms_vals)

endpoints = []
unreachable_ports = []
stalled_ports = []
for port in ports:
    n_ok, ms_vals = rec_by_port.get(port, (0, []))
    reachable = (n_ok > 0 and len(ms_vals) > 0)
    if reachable:
        mn   = min(ms_vals)
        mx   = max(ms_vals)
        mean = sum(ms_vals) / len(ms_vals)
    else:
        mn = mx = mean = None
    is_unreachable = not reachable
    is_stalled = (reachable and mean is not None and mean > threshold_ms)
    if is_unreachable:
        unreachable_ports.append(port)
    if is_stalled:
        stalled_ports.append(port)
    endpoints.append({
        "port":         port,
        "reachable":    reachable,
        "samples":      samples,
        "ok_samples":   n_ok,
        "min_ms":       mn,
        "mean_ms":      (round(mean, 2) if mean is not None else None),
        "max_ms":       mx,
        "unreachable":  is_unreachable,
        "stalled":      is_stalled,
    })

# ── anomaly aggregation (priority order) ─────────────────────────────
anomalies = []   # list of (name, severity, detail)
for port in unreachable_ports:
    anomalies.append(("unreachable", "CRITICAL",
                      f"port {port} answered 0/{samples} status probes"))
for ep in endpoints:
    if ep["stalled"]:
        anomalies.append(("stalled", "WARN",
                          f"port {ep['port']} mean RTT {ep['mean_ms']}ms "
                          f"> {threshold_ms}ms"))

has_critical = any(sev == "CRITICAL" for (_, sev, _) in anomalies)
ok = (len(anomalies) == 0)

# Exit-code derivation:
#   --anomalies-only : exit 2 if ANY anomaly present.
#   otherwise        : exit 2 only if a CRITICAL anomaly present.
if anom_only:
    exit_code = 2 if anomalies else 0
else:
    exit_code = 2 if has_critical else 0

# ── JSON envelope ────────────────────────────────────────────────────
if json_out:
    env = {
        "peers_port":         peers_port,
        "anchor_peer_count":  peer_count,   # null when anchor unreachable
        "samples":            samples,
        "threshold_ms":       threshold_ms,
        "probed_endpoints":   len(ports),
        "endpoints":          endpoints,
        "unreachable_ports":  unreachable_ports,
        "stalled_ports":      stalled_ports,
        "anomalies":          [{"name": n, "severity": s, "detail": d}
                               for (n, s, d) in anomalies],
        "ok":                 ok,
    }
    print(json.dumps(env))
    sys.exit(exit_code)

# ── human table ──────────────────────────────────────────────────────
pc_disp = str(peer_count) if peer_count is not None else "n/a"
print(f"=== Peer RPC round-trip audit "
      f"(samples={samples}, threshold={threshold_ms}ms) ===")
print(f"Anchor peers RPC (port {peers_port}): connected_peer_count={pc_disp}")
print(f"Probed RPC endpoints: {len(ports)}")
print()

def is_anomalous(ep):
    return ep["unreachable"] or ep["stalled"]

rows = [ep for ep in endpoints if (not anom_only) or is_anomalous(ep)]
if not rows:
    if anom_only:
        print(f"(no anomalous endpoints — all reachable, all mean RTT "
              f"<= {threshold_ms}ms)")
    else:
        print("(no endpoints — empty --rpc-ports list)")
else:
    w_port = max(6, max(len(str(ep["port"])) for ep in rows) + 1)
    print(f"  {'port':>{w_port}}  {'min_ms':>8}  {'mean_ms':>9}  "
          f"{'max_ms':>8}  {'ok/n':>7}  status")
    print(f"  {'-'*w_port}  {'-'*8}  {'-'*9}  {'-'*8}  {'-'*7}  ------")
    for ep in rows:
        if ep["unreachable"]:
            mn = me = mx = "-"
            status = "UNREACHABLE"
        else:
            mn = str(ep["min_ms"])
            me = str(ep["mean_ms"])
            mx = str(ep["max_ms"])
            status = "STALLED" if ep["stalled"] else "OK"
        okn = f"{ep['ok_samples']}/{ep['samples']}"
        print(f"  {ep['port']:>{w_port}}  {mn:>8}  {me:>9}  {mx:>8}  "
              f"{okn:>7}  {status}")

print()
if ok:
    print(f"[OK] all {len(ports)} endpoint(s) reachable; "
          f"all mean RTT <= {threshold_ms}ms")
else:
    crit = [n for (n, s, _) in anomalies if s == "CRITICAL"]
    warn = [n for (n, s, _) in anomalies if s == "WARN"]
    if crit:
        print(f"[CRITICAL] {len(crit)} flag(s): "
              f"unreachable ports {','.join(str(p) for p in unreachable_ports)}")
    if warn:
        print(f"[WARN] {len(warn)} flag(s): "
              f"stalled ports {','.join(str(p) for p in stalled_ports)} "
              f"(mean RTT > {threshold_ms}ms)")

sys.exit(exit_code)
PY
exit $?
