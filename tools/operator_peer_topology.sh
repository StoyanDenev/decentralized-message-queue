#!/usr/bin/env bash
# operator_peer_topology.sh — peer-graph audit + eclipse/clustering/
# disconnection detection.
#
# Use case: an operator running (or watching) a small cluster wants a
# single command that audits the SHAPE of the peer-connection graph
# (not the consensus state of each node — that's what
# operator_consensus_lag.sh + operator_block_propagation_latency.sh
# are for). This script answers three operator questions in one pass:
#
#   - "Are any of my nodes eclipse-vulnerable?" — i.e. running with
#     too few peers to survive a single-peer compromise. The default
#     --isolated-threshold (2) flags any node with fewer than 2 peers
#     as CRITICAL.
#
#   - "Are any of my nodes resource-over-committed on gossip?" — i.e.
#     holding so many peer connections that the gossip-out-of-lock
#     path (v2.6 / S-031) and per-peer-IP rate limiter (S-014) are
#     doing meaningful work just to maintain the connection set. The
#     default --clustered-threshold (50) is well above the typical
#     small-cluster fan-out and well below the default per-node
#     resource budget; tune as needed for your deployment.
#
#   - "Is my cluster a single connected graph?" — i.e. would a partition
#     leave nodes that can't reach each other via gossip? Two or more
#     connected components in the audited graph is a CRITICAL signal:
#     the cluster has already split.
#
# Method: poll `determ peers --rpc-port <P> --json` on each
# --rpc-ports entry. The RPC returns an array of strings — each string
# is a peer address in the form `host:port` or `host:port (domain)`
# (post-HELLO when the domain is known). The script parses out the
# `host:port` core and uses that as the canonical node ID in the graph.
#
# Graph model:
#   nodes = union(local_rpc_ports, all_addresses_appearing_in_any_peer_list)
#   edges = { (P, Q) : RPC at port P listed Q in its peers }
#
# Edges are DIRECTED (P → Q means "P claims a connection to Q"). The
# underlying gossip transport is symmetric (TCP is bidirectional) so
# the expected steady state is A → B iff B → A. An asymmetric edge
# (A → B but not B → A) indicates one side hasn't yet observed the
# connection — typically a half-open TCP socket that the kernel hasn't
# reaped (S-026 keepalive eventually resolves these, but until then
# they're noisy in the audit). We flag asymmetric edges as a WARN
# anomaly (asymmetric_peer_view).
#
# Local-port identity: the script identifies each --rpc-ports entry by
# its `127.0.0.1:<rpc_port>` pseudo-address. Peer entries from other
# nodes that point at this RPC port are matched back via 127.0.0.1:P
# regardless of how the operator wrote the bootstrap list (e.g.
# `localhost:7777` and `127.0.0.1:7777` are the same node). Note: the
# gossip port and the RPC port are generally DIFFERENT — peer entries
# list gossip addresses (host:gossip_port), not RPC addresses. The
# script therefore matches local nodes to peer-listed addresses by
# port-suffix only when --rpc-ports happens to equal the gossip port,
# which is the common single-process default. For the more general
# case, the local-node node-IDs in the graph are 127.0.0.1:<rpc_port>
# and remote peers appear under their gossip addresses; the connected-
# components check then sees each local node as its own island unless
# at least one peer entry matches. This is intentional — the script
# warns about isolation rather than silently merging.
#
# Connected-components: undirected graph, computed via union-find on
# the symmetrized edge set. A graph_disconnected anomaly fires iff the
# union of all --rpc-ports falls into 2+ components in the symmetrized
# graph (i.e. there's a subset of local nodes with no path between them).
#
# Anomalies (priority order):
#   - graph_disconnected (CRITICAL): the symmetrized peer graph contains
#     two or more connected components that each include at least one
#     local --rpc-ports entry. Split-brain risk.
#   - node_isolated (CRITICAL): at least one --rpc-ports entry reported
#     fewer than --isolated-threshold peers. Eclipse risk.
#   - node_clustered (WARN): at least one --rpc-ports entry reported
#     more than --clustered-threshold peers. Resource over-commit risk.
#   - asymmetric_peer_view (WARN): exists (A,B) with A in --rpc-ports
#     and A claims B as a peer but B is also in --rpc-ports and B does
#     NOT claim A. Half-open connection. (We only flag pairs where both
#     ends are local nodes; we can't ground-truth the inverse for remote
#     peers we don't poll.)
#
# Unreachable peers (RPC error) are treated as node_isolated (peer_count
# = 0) AND contribute zero edges to the graph — they appear as isolated
# vertices and almost always also trigger graph_disconnected.
#
# Read-only RPC; safe against any running daemon. Each port must be
# listening on 127.0.0.1.
#
# Usage:
#   tools/operator_peer_topology.sh --rpc-ports 8771,8772,8773 \
#       [--isolated-threshold N] [--clustered-threshold N] \
#       [--json] [--anomalies-only]
#
# Exit codes:
#   0   healthy — no anomalies flagged
#   1   RPC / argument error (no peer reachable; bad args)
#   2   at least one CRITICAL anomaly fired
#
# Exit policy: the 0/1/2 split mirrors operator_chain_health and
# operator_block_propagation_latency. WARN-only anomalies (node_clustered,
# asymmetric_peer_view) DO NOT bump the exit code on their own — they
# are surfaced in the output but don't gate monitoring wrappers. The
# CRITICAL anomalies (graph_disconnected, node_isolated) do.
set -u

usage() {
  cat <<'EOF'
Usage: operator_peer_topology.sh --rpc-ports P1,P2,...
           [--isolated-threshold N] [--clustered-threshold N]
           [--json] [--anomalies-only]

Audits peer-connection topology across an operator-supplied list of
local RPC ports. For each port, calls `determ peers --json` to fetch
the peer list, then builds a directed connection graph (P -> Q iff P
lists Q). Computes per-node peer counts, graph-wide metrics
(connected components, min/max/mean degree), and anomalies.

Required:
  --rpc-ports LIST           Comma-separated RPC ports (e.g. 8771,8772,8773).
                             At least one port is required; duplicates are
                             de-duped in stable order.

Options:
  --isolated-threshold N     Warn when a node has fewer than N peers
                             (default: 2). Eclipse risk: a node with one
                             or zero peers can be controlled by that
                             peer's owner. Fires node_isolated (CRITICAL).
  --clustered-threshold N    Warn when a node has more than N peers
                             (default: 50). Resource-over-commit risk:
                             a node with too many simultaneous peers may
                             exhaust the per-peer-IP rate limiter (S-014)
                             or the gossip-out-of-lock task pool (v2.6 /
                             S-031). Fires node_clustered (WARN).
  --json                     Emit structured JSON envelope instead of
                             human table. Shape:
                               {"nodes": [{"port": P, "peer_count": N,
                                           "peers": [...], "reachable": bool,
                                           "isolated": bool,
                                           "clustered": bool}, ...],
                                "graph_metrics": {
                                   "components": N,
                                   "max_degree": N, "min_degree": N,
                                   "mean_degree": F,
                                   "edges": N, "directed_edges": N},
                                "anomalies": [...],
                                "ok": bool}
  --anomalies-only           Suppress healthy table rows; still emits the
                             anomaly section and graph metrics. Healthy
                             rows in the per-node table are dropped.
  -h, --help                 Show this help.

Anomalies (priority order):
  graph_disconnected         CRITICAL — the symmetrized peer graph has
                             2+ connected components covering local nodes.
  node_isolated              CRITICAL — peer_count < --isolated-threshold.
  node_clustered             WARN     — peer_count > --clustered-threshold.
  asymmetric_peer_view       WARN     — A claims B but B doesn't claim A
                             (both A and B are local nodes; remote-peer
                             asymmetry can't be detected here).

Exit codes:
  0   healthy (no anomalies, all WARN suppressed by absence)
  1   RPC / args error (no peer reachable; bad args)
  2   at least one CRITICAL anomaly fired (graph_disconnected or
      node_isolated). WARN anomalies do not gate the exit code.
EOF
}

PORTS_RAW=""
ISOLATED_THRESHOLD=2
CLUSTERED_THRESHOLD=50
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)              usage; exit 0 ;;
    --rpc-ports)            PORTS_RAW="${2:-}";            shift 2 ;;
    --isolated-threshold)   ISOLATED_THRESHOLD="${2:-}";   shift 2 ;;
    --clustered-threshold)  CLUSTERED_THRESHOLD="${2:-}";  shift 2 ;;
    --json)                 JSON_OUT=1;                    shift ;;
    --anomalies-only)       ANOM_ONLY=1;                   shift ;;
    *) echo "operator_peer_topology: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$PORTS_RAW" ]; then
  echo "operator_peer_topology: --rpc-ports is required (comma-separated, e.g. 8771,8772,8773)" >&2
  usage >&2
  exit 1
fi

# Numeric guards. ISOLATED_THRESHOLD must be >= 1 (a threshold of 0
# would mean "never flag isolation" since peer_count is always >= 0
# and we use strict-less-than — but that's a config bug, not a feature;
# reject it). CLUSTERED_THRESHOLD must be >= 1 for symmetric reasons
# (strict-greater-than means 0 would flag every node with >= 1 peer,
# which is noisy; reject as a config bug).
case "$ISOLATED_THRESHOLD" in *[!0-9]*|"")
  echo "operator_peer_topology: --isolated-threshold must be a positive integer (got '$ISOLATED_THRESHOLD')" >&2
  exit 1 ;;
esac
case "$CLUSTERED_THRESHOLD" in *[!0-9]*|"")
  echo "operator_peer_topology: --clustered-threshold must be a positive integer (got '$CLUSTERED_THRESHOLD')" >&2
  exit 1 ;;
esac
if [ "$ISOLATED_THRESHOLD" -lt 1 ]; then
  echo "operator_peer_topology: --isolated-threshold must be >= 1 (got '$ISOLATED_THRESHOLD')" >&2
  exit 1
fi
if [ "$CLUSTERED_THRESHOLD" -lt 1 ]; then
  echo "operator_peer_topology: --clustered-threshold must be >= 1 (got '$CLUSTERED_THRESHOLD')" >&2
  exit 1
fi
if [ "$ISOLATED_THRESHOLD" -gt "$CLUSTERED_THRESHOLD" ]; then
  echo "operator_peer_topology: --isolated-threshold ($ISOLATED_THRESHOLD) must be <= --clustered-threshold ($CLUSTERED_THRESHOLD)" >&2
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
    echo "operator_peer_topology: --rpc-ports entry '$p' is not numeric" >&2
    exit 1 ;;
  esac
  if [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
    echo "operator_peer_topology: --rpc-ports entry '$p' must be 1..65535" >&2
    exit 1
  fi
  case " $SEEN " in
    *" $p "*) continue ;;
  esac
  SEEN="$SEEN $p"
  if [ -z "$PORTS" ]; then PORTS="$p"; else PORTS="$PORTS $p"; fi
done

if [ -z "$PORTS" ]; then
  echo "operator_peer_topology: --rpc-ports resolved to an empty list" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Collect per-port peer lists into a temp file, one TSV record per row:
#   <port>\t<reachable_0_or_1>\t<peer1>|<peer2>|...
# The peer field uses '|' as separator so whitespace inside a peer
# string (e.g. the optional " (domain)" suffix) survives intact. Empty
# peer field means either no peers or an unreachable RPC.
TMP_PEERS=$(mktemp 2>/dev/null) || {
  echo "operator_peer_topology: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_PEERS" 2>/dev/null' EXIT

ANY_REACHABLE=0
for port in $PORTS; do
  # Capture stdout (JSON array) and stderr separately. We treat any
  # non-zero rc OR empty stdout as "unreachable". On success the JSON
  # is a top-level array of strings; if it's anything else (e.g. an
  # error wrapper) the python parse below will reject it and we record
  # unreachable.
  raw=$("$DETERM" peers --json --rpc-port "$port" 2>/dev/null) || raw=""
  if [ -z "$raw" ]; then
    # Unreachable. Record with empty peer field.
    printf '%s\t0\t\n' "$port" >>"$TMP_PEERS"
    continue
  fi
  # Hand the JSON to python to flatten into a '|'-separated string of
  # peer addresses. We strip the optional " (domain)" suffix so peer
  # identity is just host:port — that's how peer entries cross-reference
  # each other across nodes (the domain is post-HELLO and asymmetric;
  # host:port is the stable wire key).
  peers_flat=$(printf '%s' "$raw" | python -c '
import sys, json
try:
    arr = json.loads(sys.stdin.read())
    if not isinstance(arr, list):
        sys.exit(0)
    out = []
    for entry in arr:
        if not isinstance(entry, str):
            continue
        # Strip " (domain)" suffix if present.
        sp = entry.find(" (")
        core = entry[:sp] if sp > 0 else entry
        core = core.strip()
        if core:
            out.append(core)
    print("|".join(out))
except Exception:
    pass
')
  printf '%s\t1\t%s\n' "$port" "$peers_flat" >>"$TMP_PEERS"
  ANY_REACHABLE=1
done

if [ "$ANY_REACHABLE" = "0" ]; then
  echo "operator_peer_topology: no RPC port was reachable (all ${#_PORTS[@]} ports failed)" >&2
  exit 1
fi

# Hand off to python for graph build + metrics + anomaly classification
# + rendering. Pass: ports (pipe-delimited), thresholds, flags, and the
# peer log path.
PORTS_PIPE=$(printf '%s' "$PORTS" | tr ' ' '|')
python - "$PORTS_PIPE" "$ISOLATED_THRESHOLD" "$CLUSTERED_THRESHOLD" \
        "$JSON_OUT" "$ANOM_ONLY" "$TMP_PEERS" <<'PY'
import json, sys

(ports_s, iso_s, clu_s, json_out_s, anom_only_s, peers_path) = sys.argv[1:7]
ports = [int(p) for p in ports_s.split('|') if p]
iso_threshold = int(iso_s)
clu_threshold = int(clu_s)
json_out  = (json_out_s == "1")
anom_only = (anom_only_s == "1")

# Each local port gets a canonical node-id of "127.0.0.1:<port>". When a
# remote peer entry happens to point at one of our --rpc-ports values
# (single-process gossip == rpc port — common test/dev config), we
# match it back via a port-suffix check.
def local_id(port):
    return f"127.0.0.1:{port}"

# Read per-port peer records.
#   records: list of (port, reachable, [peer_addr, ...])
records = []
with open(peers_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t")
        while len(parts) < 3:
            parts.append("")
        port_s, reach_s, peers_flat = parts[0], parts[1], parts[2]
        try:
            port_i = int(port_s)
        except ValueError:
            continue
        reachable = (reach_s == "1")
        peer_list = [p for p in peers_flat.split("|") if p] if peers_flat else []
        records.append((port_i, reachable, peer_list))

# Build maps keyed by port for O(1) lookup later.
rec_by_port = {p: (r, pl) for (p, r, pl) in records}

# Canonical node-id for each entry. For local ports the id is
# 127.0.0.1:<port>; for remote peers the id is whatever address string
# we received (already stripped of the " (domain)" suffix).
local_node_ids = {p: local_id(p) for p in ports}

# Build the directed edge set as (src_id, dst_id) tuples. src is always
# a local node (the only nodes we can poll); dst can be either a local
# or a remote node.
#
# To match a remote peer entry back to a local node, we compare its
# host:port suffix against our --rpc-ports list. Peer addresses look
# like "host:port" — we split on the last ':' and check the port. If
# the port matches one of our local --rpc-ports, we normalize the dst
# id to 127.0.0.1:<port> (the canonical local id). This way an A→B
# edge and a B→A edge both reference the same node-id, which is what
# the symmetric / asymmetric checks below require.
def normalize_to_local_if_match(addr):
    # Find rightmost ':' (handles IPv6-ish "[::1]:7777" by NOT supporting
    # bracketed forms — Determ uses bare host:port; bracketed v6 would
    # need a separate parse).
    colon = addr.rfind(":")
    if colon <= 0:
        return addr  # Malformed; pass through verbatim so we don't lose it.
    port_part = addr[colon + 1:]
    if port_part.isdigit():
        try:
            pport = int(port_part)
            if pport in local_node_ids:
                return local_node_ids[pport]
        except ValueError:
            pass
    return addr

# Build directed edges, accumulate node-id set, count out-degree per
# local node.
directed_edges = set()
node_ids = set()
out_degree = {p: 0 for p in ports}
peer_lists = {p: [] for p in ports}

for (port, reachable, peer_list) in records:
    src_id = local_node_ids[port]
    node_ids.add(src_id)
    for raw_peer in peer_list:
        dst_id = normalize_to_local_if_match(raw_peer)
        # Self-loop: a local node listing itself. Possible if a node's
        # bootstrap_peers includes its own gossip endpoint. Skip — these
        # bias the degree count but say nothing about real connectivity.
        if dst_id == src_id:
            continue
        node_ids.add(dst_id)
        directed_edges.add((src_id, dst_id))
        out_degree[port] += 1
        peer_lists[port].append(raw_peer)

# Symmetrized (undirected) edge set: for graph-component analysis the
# transport direction is irrelevant (TCP is bidirectional in the actual
# gossip layer; only the local view is one-sided). We build the
# undirected edge set by treating (a,b) and (b,a) as the same.
undirected = set()
for (a, b) in directed_edges:
    key = (a, b) if a < b else (b, a)
    undirected.add(key)

# In-degree across the whole graph (how many distinct sources list me?).
in_degree = {nid: 0 for nid in node_ids}
for (a, b) in directed_edges:
    in_degree[b] = in_degree.get(b, 0) + 1

# ── union-find on the symmetrized graph ──────────────────────────────
# We do a textbook union-find with path compression. Components are
# numbered by their root id; we then count distinct roots across the
# subset of node_ids that are local (covers the "is my cluster split?"
# question without being confused by leaf remote peers that legitimately
# don't connect to anyone else in the audit).
parent = {nid: nid for nid in node_ids}
def find(x):
    # Iterative path compression.
    root = x
    while parent[root] != root:
        root = parent[root]
    while parent[x] != root:
        parent[x], x = root, parent[x]
    return root
def union(a, b):
    ra, rb = find(a), find(b)
    if ra != rb:
        parent[ra] = rb
for (a, b) in undirected:
    union(a, b)

# Components over LOCAL nodes only. A local node with zero edges is
# its own component (which is fine; that's the eclipse case).
local_roots = set()
local_node_to_root = {}
for p in ports:
    nid = local_node_ids[p]
    r = find(nid)
    local_roots.add(r)
    local_node_to_root[p] = r
components = len(local_roots)

# Local-component grouping for the JSON / human output: for each local
# port report which component it falls into (stable index in encounter
# order so the human output is deterministic).
root_to_component_idx = {}
for p in ports:
    r = local_node_to_root[p]
    if r not in root_to_component_idx:
        root_to_component_idx[r] = len(root_to_component_idx)

# ── degree summary across LOCAL ports ────────────────────────────────
# We report degree as the OUT-degree (peer_count from this node's
# perspective). The graph-wide min/max/mean degree summary is computed
# across local ports only — remote peers we didn't poll wouldn't have
# a meaningful peer_count from our vantage point.
peer_counts = [out_degree[p] for p in ports]
if peer_counts:
    min_deg = min(peer_counts)
    max_deg = max(peer_counts)
    mean_deg = sum(peer_counts) / len(peer_counts)
else:
    min_deg = max_deg = 0
    mean_deg = 0.0

# ── per-node anomaly flags ───────────────────────────────────────────
nodes_out = []
isolated_ports = []
clustered_ports = []
unreachable_ports = []
for p in ports:
    reachable, raw_pl = rec_by_port.get(p, (False, []))
    pc = out_degree[p]
    is_iso = pc < iso_threshold
    is_clu = pc > clu_threshold
    if not reachable:
        # An unreachable RPC counts as isolated (peer_count = 0 from
        # our perspective) and we record it explicitly so the operator
        # can distinguish "polled, low fan-out" from "didn't answer".
        unreachable_ports.append(p)
        is_iso = True
    if is_iso:
        isolated_ports.append(p)
    if is_clu:
        clustered_ports.append(p)
    nodes_out.append({
        "port":        p,
        "node_id":     local_node_ids[p],
        "reachable":   reachable,
        "peer_count":  pc,
        "peers":       raw_pl,
        "in_degree":   in_degree.get(local_node_ids[p], 0),
        "component":   root_to_component_idx[local_node_to_root[p]],
        "isolated":    is_iso,
        "clustered":   is_clu,
    })

# ── asymmetric_peer_view check (LOCAL pairs only) ────────────────────
# Iterate distinct unordered pairs (a,b) of local node-ids; flag the
# pair if exactly one of (a→b), (b→a) exists in the directed edge set.
local_id_set = set(local_node_ids.values())
asymmetric_pairs = []
local_ids_sorted = sorted(local_id_set)
for i in range(len(local_ids_sorted)):
    for j in range(i + 1, len(local_ids_sorted)):
        a, b = local_ids_sorted[i], local_ids_sorted[j]
        ab = (a, b) in directed_edges
        ba = (b, a) in directed_edges
        if ab != ba:
            asymmetric_pairs.append({
                "from": a if ab else b,
                "to":   b if ab else a,
                "note": "directed edge in one direction only",
            })

# ── anomaly aggregation (priority order) ─────────────────────────────
anomalies = []
critical_fired = False
# (1) graph_disconnected — CRITICAL. Requires >=2 local ports and >=2
# components covering them.
if len(ports) >= 2 and components >= 2:
    anomalies.append("graph_disconnected")
    critical_fired = True
# (2) node_isolated — CRITICAL.
if isolated_ports:
    anomalies.append("node_isolated")
    critical_fired = True
# (3) node_clustered — WARN (does not gate exit code).
if clustered_ports:
    anomalies.append("node_clustered")
# (4) asymmetric_peer_view — WARN (does not gate exit code).
if asymmetric_pairs:
    anomalies.append("asymmetric_peer_view")

ok = (len(anomalies) == 0)

# ── output ───────────────────────────────────────────────────────────
if json_out:
    env = {
        "nodes": nodes_out,
        "graph_metrics": {
            "components":     components,
            "max_degree":     max_deg,
            "min_degree":     min_deg,
            "mean_degree":    mean_deg,
            "edges":          len(undirected),
            "directed_edges": len(directed_edges),
        },
        "isolated_threshold":  iso_threshold,
        "clustered_threshold": clu_threshold,
        "isolated_ports":      isolated_ports,
        "clustered_ports":     clustered_ports,
        "unreachable_ports":   unreachable_ports,
        "asymmetric_pairs":    asymmetric_pairs,
        "anomalies":           anomalies,
        "ok":                  ok,
    }
    print(json.dumps(env))
    sys.exit(0 if not critical_fired else 2)

# Human-readable rendering.
header = ("=== Peer topology audit "
          f"(ports={','.join(str(p) for p in ports)}, "
          f"isolated_threshold={iso_threshold}, "
          f"clustered_threshold={clu_threshold}) ===")
print(header)

# Per-node table.
# Suppress healthy rows under --anomalies-only.
def is_anomalous(n):
    return n["isolated"] or n["clustered"] or not n["reachable"]

rows = [n for n in nodes_out if (not anom_only) or is_anomalous(n)]
print()
if not rows:
    if anom_only:
        print("(no anomalous nodes — all peer counts within "
              f"[{iso_threshold}, {clu_threshold}], all RPC reachable)")
    else:
        print("(no nodes — empty --rpc-ports list)")
else:
    # Width tuning. peers column: cap rendered list to keep table sane.
    w_port = max(6, max(len(str(n["port"])) for n in rows) + 1)
    w_pc   = max(5, max(len(str(n["peer_count"])) for n in rows) + 1)
    w_in   = max(5, max(len(str(n["in_degree"])) for n in rows) + 1)
    w_comp = max(5, max(len(str(n["component"])) for n in rows) + 1)
    w_stat = 24
    print(f"  {'port':>{w_port}}  {'peers':>{w_pc}}  {'in':>{w_in}}  "
          f"{'comp':>{w_comp}}  {'status':<{w_stat}}  peer_list")
    print(f"  {'-'*w_port}  {'-'*w_pc}  {'-'*w_in}  {'-'*w_comp}  "
          f"{'-'*w_stat}  ---------")
    for n in rows:
        flags = []
        if not n["reachable"]:
            flags.append("unreachable")
        if n["isolated"]:
            flags.append("ISOLATED")
        if n["clustered"]:
            flags.append("CLUSTERED")
        status = ",".join(flags) if flags else "OK"
        # Cap rendered peer list to 4 entries to keep table readable.
        plist = n["peers"]
        if len(plist) > 4:
            peer_disp = ", ".join(plist[:4]) + f", ... (+{len(plist) - 4})"
        else:
            peer_disp = ", ".join(plist) if plist else "(none)"
        print(f"  {n['port']:>{w_port}}  {n['peer_count']:>{w_pc}}  "
              f"{n['in_degree']:>{w_in}}  {n['component']:>{w_comp}}  "
              f"{status:<{w_stat}}  {peer_disp}")

print()
print("Graph metrics:")
print(f"  components       : {components}")
print(f"  edges (undirected): {len(undirected)}")
print(f"  edges (directed) : {len(directed_edges)}")
print(f"  degree min/mean/max : {min_deg} / {mean_deg:.2f} / {max_deg}")

print()
if ok:
    print(f"[OK] no anomalies across {len(ports)} node(s); "
          f"{components} component(s); "
          f"degree min/max = {min_deg}/{max_deg}")
else:
    # Split CRITICAL vs WARN in the summary so monitoring wrappers can
    # tell at a glance whether the exit code will be 2 or 0.
    crit = []
    warn = []
    for a in anomalies:
        if a in ("graph_disconnected", "node_isolated"):
            crit.append(a)
        else:
            warn.append(a)
    if crit:
        print(f"[CRITICAL] {len(crit)} flag(s): {','.join(crit)}")
    if warn:
        print(f"[WARN] {len(warn)} flag(s): {','.join(warn)}")
    if "graph_disconnected" in anomalies:
        # List each component as its set of local ports.
        comp_buckets = {}
        for p in ports:
            ci = root_to_component_idx[local_node_to_root[p]]
            comp_buckets.setdefault(ci, []).append(p)
        bits = ", ".join(
            f"comp{ci}={{{','.join(str(p) for p in sorted(comp_buckets[ci]))}}}"
            for ci in sorted(comp_buckets)
        )
        print(f"  graph_disconnected   : {components} component(s) — {bits}")
    if "node_isolated" in anomalies:
        if unreachable_ports:
            print(f"  node_isolated        : ports {','.join(str(p) for p in isolated_ports)} "
                  f"(peer_count < {iso_threshold}); "
                  f"unreachable subset = {','.join(str(p) for p in unreachable_ports)}")
        else:
            print(f"  node_isolated        : ports {','.join(str(p) for p in isolated_ports)} "
                  f"(peer_count < {iso_threshold})")
    if "node_clustered" in anomalies:
        print(f"  node_clustered       : ports {','.join(str(p) for p in clustered_ports)} "
              f"(peer_count > {clu_threshold})")
    if "asymmetric_peer_view" in anomalies:
        labels = [f"{ap['from']} -> {ap['to']}" for ap in asymmetric_pairs[:5]]
        more = "" if len(asymmetric_pairs) <= 5 else f" (+{len(asymmetric_pairs) - 5} more)"
        print(f"  asymmetric_peer_view : {len(asymmetric_pairs)} pair(s) — "
              f"{'; '.join(labels)}{more}")

sys.exit(0 if not critical_fired else 2)
PY
exit $?
