#!/usr/bin/env bash
# operator_peer_connectivity_health.sh — SINGLE-NODE connectivity-health
# digest for one running determ daemon.
#
# Use case: an operator (or a per-node monitoring agent) wants ONE
# command that answers "is THIS node's connectivity healthy RIGHT NOW?"
# purely from the node's own RPC surface — no need to know the other
# nodes' RPC ports. It cross-references the node's connected peer set
# (`determ peers`) against the consensus targets the node already knows
# from its own status (`determ status`): m_creators (committee size it
# must help form), node_count (registry size it could reach), and
# sync_state. It also mines a signal no other tool consumes: the
# per-peer HELLO-handshake completeness encoded in the peer-address
# string's optional " (domain)" suffix.
#
# Sibling positioning (network / peer / gossip / connectivity lane) —
# every existing tool in this lane is MULTI-NODE (needs --rpc-ports of
# several daemons) and analyzes cross-node RELATIONSHIPS:
#   * operator_peer_topology.sh           — multi-node peer GRAPH:
#     eclipse/clustering/connected-components across an operator-supplied
#     list of RPC ports. Needs >=1 (usefully >=2) ports.
#   * operator_network_partition_detect.sh — N-peer head_hash PARTITION
#     split (>=3 ports): same-height/different-tip clustering.
#   * operator_block_propagation_latency.sh — time-domain block landing
#     across N nodes (polls many ports over a window).
#   * operator_consensus_lag.sh            — N-way HEIGHT lag across a
#     fleet of ports.
#   * operator_chain_health.sh             — single node, but only a
#     coarse `peers --count >= 1` boolean (no handshake / committee /
#     registry cross-check).
#
# THIS tool is the missing SINGLE-NODE connectivity-health view: it
# needs exactly one --rpc-port and answers the eclipse/isolation/
# handshake-churn/committee-formability question from that node's own
# vantage point, with no knowledge of any other node's RPC port. The
# handshake-completeness ratio (peers with vs without a resolved domain)
# is a churn / HELLO-stall signal that NO other tool in the repo reads.
#
# ── RPCs consumed (read-only) ────────────────────────────────────────
#   determ status --rpc-port P   →  rpc_status() at src/node/node.cpp:2461
#       Fields used (all proven present in that handler):
#         .peer_count    (node.cpp:2468  = gossip_.peer_count())
#         .node_count    (node.cpp:2466  = registry_.size())
#         .m_creators    (node.cpp:2469  = cfg_.m_creators)
#         .sync_state    (node.cpp:2471  "in_sync" | "syncing")
#         .height        (node.cpp:2464)
#         .domain        (node.cpp:2467)
#         .next_creators (node.cpp:2525  array of domains; may be absent
#                         when the eligible pool < m_creators — handled)
#   determ peers --json --rpc-port P  →  rpc_peers() at src/node/node.cpp:2547
#       Returns a JSON array of strings. Each string is built in
#       GossipNet::peer_addresses() at src/net/gossip.cpp:345 as:
#         "<host:port>"                  when domain not yet known, OR
#         "<host:port> (<domain>)"       once HELLO has resolved a domain.
#       The presence/absence of the " (domain)" suffix is exactly the
#       per-peer HELLO-handshake-complete flag we mine here.
#
# No tx is ever sent; no chain file is read or written. Pure read.
#
# ── Classification logic ─────────────────────────────────────────────
# Let pc = peer_count, mc = m_creators, nc = node_count.
#
#   isolated            (CRITICAL)  pc == 0. The node has no peers — it
#                                   is eclipsed / partitioned off. If it
#                                   also reports sync_state="in_sync"
#                                   that is a stale-tip illusion.
#   below_min_peers     (CRITICAL)  pc < --min-peers (default 2). Eclipse
#                                   risk: a node with a single peer is at
#                                   that peer-owner's mercy.
#   committee_unreachable (WARN)    mc > 0 AND (pc + 1) < mc — even
#                                   counting itself the node cannot see
#                                   enough distinct participants to form
#                                   the m_creators committee. (Self +1
#                                   because the node can be its own
#                                   creator.) Skipped when mc == 0.
#   handshake_incomplete (WARN)     fraction of peers WITHOUT a resolved
#                                   domain >= --handshake-warn-frac
#                                   (default 0.50) AND pc > 0. Many half-
#                                   open / mid-HELLO connections = churn
#                                   or a HELLO-stall (S-014 token bucket
#                                   exempts HELLO, so this should clear
#                                   quickly in a healthy node).
#   sync_isolation       (WARN)     sync_state == "in_sync" AND pc == 0.
#                                   The node believes it is in sync but
#                                   has nobody to learn from — its tip is
#                                   unverifiable. (Implied by `isolated`
#                                   but surfaced separately because it is
#                                   operationally distinct: a freshly
#                                   genesis-bootstrapped solo node is
#                                   "in_sync" with itself and may be
#                                   intentionally standalone.)
#
# CRITICAL anomalies gate the exit code (→ 2 under --anomalies-only or
# whenever present). WARN anomalies are surfaced but do not, on their
# own, change a non-anomalies-only exit from 0.
#
# ── Exit-code contract ───────────────────────────────────────────────
#   0   ok / info / clean SKIP (daemon unreachable)
#   1   argument error OR malformed/unparseable RPC response
#   2   --anomalies-only AND at least one anomaly present
#
# ── Usage ────────────────────────────────────────────────────────────
#   tools/operator_peer_connectivity_health.sh [--rpc-port N]
#       [--min-peers N] [--handshake-warn-frac F]
#       [--json] [--anomalies-only]
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

usage() {
  cat <<'EOF'
Usage: operator_peer_connectivity_health.sh [--rpc-port N]
           [--min-peers N] [--handshake-warn-frac F]
           [--json] [--anomalies-only]

Single-node connectivity-health digest. Queries ONE daemon's own
`determ status` + `determ peers` RPCs and reports whether that node is
well-connected enough to participate in consensus right now: peer
count vs an eclipse floor, committee-formability vs m_creators, and the
fraction of peers still mid HELLO-handshake.

Options:
  --rpc-port N            RPC port of the daemon to query (default: 7778).
  --min-peers N           Eclipse floor. peer_count < N fires
                          below_min_peers (CRITICAL). Default 2. Must be
                          a non-negative integer.
  --handshake-warn-frac F Fraction in [0,1]. When the share of connected
                          peers WITHOUT a resolved domain (HELLO not yet
                          complete) is >= F, fire handshake_incomplete
                          (WARN). Default 0.50.
  --json                  Emit a machine-readable JSON envelope instead of
                          the human digest.
  --anomalies-only        Print only anomaly rows + verdict (suppress the
                          neutral per-metric rows). With this flag set,
                          ANY anomaly present makes the exit code 2.
  -h, --help              Show this help and exit 0.

Anomalies:
  isolated              CRITICAL — peer_count == 0.
  below_min_peers       CRITICAL — peer_count < --min-peers.
  committee_unreachable WARN     — m_creators>0 and peer_count+1 < m_creators.
  handshake_incomplete  WARN     — >= --handshake-warn-frac of peers lack a
                                   resolved domain (HELLO incomplete).
  sync_isolation        WARN     — sync_state=in_sync but peer_count == 0.

Exit codes:
  0   ok / info / clean SKIP (daemon unreachable on --rpc-port)
  1   argument error or malformed RPC response
  2   --anomalies-only AND at least one anomaly present
EOF
}

PORT=7778
MIN_PEERS=2
HANDSHAKE_WARN_FRAC="0.50"
JSON=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)               usage; exit 0 ;;
    --rpc-port)              PORT="${2:-}";               shift 2 ;;
    --min-peers)             MIN_PEERS="${2:-}";          shift 2 ;;
    --handshake-warn-frac)   HANDSHAKE_WARN_FRAC="${2:-}"; shift 2 ;;
    --json)                  JSON=1;                      shift ;;
    --anomalies-only)        ANOM_ONLY=1;                 shift ;;
    *) echo "operator_peer_connectivity_health: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── argument validation (exit 1 on bad args) ─────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_peer_connectivity_health: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "operator_peer_connectivity_health: --rpc-port must be 1..65535 (got '$PORT')" >&2
  exit 1
fi
case "$MIN_PEERS" in *[!0-9]*|"")
  echo "operator_peer_connectivity_health: --min-peers must be a non-negative integer (got '$MIN_PEERS')" >&2
  exit 1 ;;
esac
# handshake-warn-frac must parse as a float in [0,1]. Allow forms like
# 0, 1, 0.5, .5, 1.0 — reject anything non-numeric or out of range.
case "$HANDSHAKE_WARN_FRAC" in
  *[!0-9.]*|""|*.*.*)
    echo "operator_peer_connectivity_health: --handshake-warn-frac must be a number in [0,1] (got '$HANDSHAKE_WARN_FRAC')" >&2
    exit 1 ;;
esac
# Range check via awk (portable float compare).
if ! awk -v f="$HANDSHAKE_WARN_FRAC" 'BEGIN{ if (f+0 < 0 || f+0 > 1) exit 1; exit 0 }'; then
  echo "operator_peer_connectivity_health: --handshake-warn-frac must be in [0,1] (got '$HANDSHAKE_WARN_FRAC')" >&2
  exit 1
fi

# ── clean SKIP when daemon unreachable (exit 0, both modes) ──────────
STATUS_OUT=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null) || {
  if [ "$JSON" = "1" ]; then
    printf '{"skipped":true,"reason":"daemon unreachable","rpc_port":%s}\n' "$PORT"
  else
    echo "operator_peer_connectivity_health: INFO daemon unreachable on rpc-port $PORT (SKIP)"
  fi
  exit 0
}

PEERS_OUT=$("$DETERM" peers --json --rpc-port "$PORT" 2>/dev/null) || {
  if [ "$JSON" = "1" ]; then
    printf '{"skipped":true,"reason":"peers RPC unreachable","rpc_port":%s}\n' "$PORT"
  else
    echo "operator_peer_connectivity_health: INFO peers RPC unreachable on rpc-port $PORT (SKIP)"
  fi
  exit 0
}

# ── parse + classify in python (no jq dependency; matches sibling tools
#    that parse JSON via python) ──────────────────────────────────────
RESULT=$(printf '%s\n----PEERS----\n%s' "$STATUS_OUT" "$PEERS_OUT" | python - \
            "$MIN_PEERS" "$HANDSHAKE_WARN_FRAC" "$JSON" "$ANOM_ONLY" "$PORT" <<'PY'
import sys, json, re

min_peers   = int(sys.argv[1])
hs_frac     = float(sys.argv[2])
json_out    = (sys.argv[3] == "1")
anom_only   = (sys.argv[4] == "1")
port        = int(sys.argv[5])

raw = sys.stdin.read()
sep = "\n----PEERS----\n"
idx = raw.find(sep)
if idx < 0:
    print("MALFORMED: missing internal separator", file=sys.stderr)
    sys.exit(3)
status_raw = raw[:idx]
peers_raw  = raw[idx + len(sep):]

try:
    status = json.loads(status_raw)
    if not isinstance(status, dict):
        raise ValueError("status is not an object")
except Exception as e:
    print(f"MALFORMED: status not parseable JSON object ({e})", file=sys.stderr)
    sys.exit(3)

try:
    peers = json.loads(peers_raw)
    if not isinstance(peers, list):
        raise ValueError("peers is not an array")
except Exception as e:
    print(f"MALFORMED: peers not parseable JSON array ({e})", file=sys.stderr)
    sys.exit(3)

# ── pull status fields (rpc_status, src/node/node.cpp:2461) ──────────
def num(field, default=0):
    v = status.get(field, default)
    try:
        return int(v)
    except Exception:
        return default

peer_count_status = num("peer_count")   # node.cpp:2468
node_count        = num("node_count")    # node.cpp:2466
m_creators        = num("m_creators")    # node.cpp:2469
height            = num("height")        # node.cpp:2464
sync_state        = str(status.get("sync_state", ""))   # node.cpp:2471
domain            = str(status.get("domain", ""))       # node.cpp:2467
next_creators     = status.get("next_creators", None)   # node.cpp:2525 (may be absent)
next_creators_n   = len(next_creators) if isinstance(next_creators, list) else None

# ── derive per-peer handshake completeness from the peers array ──────
# Each entry is "host:port" (HELLO incomplete) or "host:port (domain)"
# (HELLO complete). The "(domain)" suffix is appended in
# GossipNet::peer_addresses() at src/net/gossip.cpp:348-349.
DOMAIN_SUFFIX = re.compile(r"\s\([^)]+\)\s*$")
peer_count = len(peers)          # ground truth from the array itself
hello_complete = 0
hello_pending  = 0
pending_addrs  = []
for entry in peers:
    if not isinstance(entry, str):
        # Defensive: a non-string array element is treated as pending
        # (unidentified) rather than crashing the audit.
        hello_pending += 1
        continue
    if DOMAIN_SUFFIX.search(entry):
        hello_complete += 1
    else:
        hello_pending += 1
        pending_addrs.append(entry.strip())

pending_frac = (hello_pending / peer_count) if peer_count > 0 else 0.0

# peer_count from the array is authoritative for everything below; the
# status field is reported alongside so a divergence is visible (it can
# differ by a tick due to a connect/disconnect between the two RPC
# calls — informational, not an anomaly).

# ── anomaly classification ───────────────────────────────────────────
anomalies = []   # list of (name, severity, detail)

if peer_count == 0:
    anomalies.append(("isolated", "CRITICAL",
                      "0 connected peers (eclipsed / partitioned)"))

if peer_count < min_peers:
    anomalies.append(("below_min_peers", "CRITICAL",
                      f"peer_count {peer_count} < --min-peers {min_peers}"))

# committee_unreachable: counting self (+1) the node cannot reach
# enough participants to form the m_creators committee. Only meaningful
# when m_creators is configured (> 0).
if m_creators > 0 and (peer_count + 1) < m_creators:
    anomalies.append(("committee_unreachable", "WARN",
                      f"peer_count+self ({peer_count + 1}) < m_creators ({m_creators})"))

if peer_count > 0 and pending_frac >= hs_frac:
    anomalies.append(("handshake_incomplete", "WARN",
                      f"{hello_pending}/{peer_count} peers lack a resolved domain "
                      f"(frac {pending_frac:.2f} >= {hs_frac:.2f})"))

if sync_state == "in_sync" and peer_count == 0:
    anomalies.append(("sync_isolation", "WARN",
                      "sync_state=in_sync but 0 peers (tip is unverifiable)"))

has_critical = any(sev == "CRITICAL" for (_, sev, _) in anomalies)
ok = (len(anomalies) == 0)

# ── JSON envelope ────────────────────────────────────────────────────
if json_out:
    env = {
        "rpc_port":               port,
        "domain":                 domain,
        "height":                 height,
        "sync_state":             sync_state,
        "peer_count":             peer_count,
        "peer_count_status_field": peer_count_status,
        "node_count":             node_count,
        "m_creators":             m_creators,
        "next_creators_count":    next_creators_n,
        "hello_complete":         hello_complete,
        "hello_pending":          hello_pending,
        "hello_pending_frac":     round(pending_frac, 4),
        "pending_peers":          pending_addrs,
        "min_peers":              min_peers,
        "handshake_warn_frac":    hs_frac,
        "anomalies":              [{"name": n, "severity": s, "detail": d}
                                   for (n, s, d) in anomalies],
        "ok":                     ok,
    }
    print(json.dumps(env))
    sys.exit(0)

# ── human digest ─────────────────────────────────────────────────────
out = []
out.append(f"operator_peer_connectivity_health (port {port}):")
if not anom_only:
    dom_disp = domain if domain else "(unset)"
    out.append(f"  node                 domain={dom_disp}  height={height}  sync_state={sync_state or '?'}")
    out.append(f"  peers connected      count={peer_count}  (status.peer_count={peer_count_status})")
    out.append(f"  registry size        node_count={node_count}")
    out.append(f"  committee target     m_creators={m_creators}  "
               f"reachable(self+peers)={peer_count + 1}")
    nc_disp = str(next_creators_n) if next_creators_n is not None else "n/a"
    out.append(f"  next_creators        count={nc_disp}")
    out.append(f"  handshake state      complete={hello_complete}  pending={hello_pending}  "
               f"pending_frac={pending_frac:.2f}")
    if pending_addrs:
        shown = ", ".join(pending_addrs[:4])
        more = "" if len(pending_addrs) <= 4 else f", ... (+{len(pending_addrs) - 4})"
        out.append(f"  pending peers        {shown}{more}")

if anomalies:
    out.append("  anomalies:")
    for (n, s, d) in anomalies:
        out.append(f"    [{s}] {n}: {d}")
elif anom_only:
    out.append("  (no anomalies)")

if ok:
    out.append(f"[OK] connectivity healthy: {peer_count} peer(s), "
               f"{hello_complete} HELLO-complete; "
               f"m_creators={m_creators} reachable")
else:
    crit = [n for (n, s, _) in anomalies if s == "CRITICAL"]
    warn = [n for (n, s, _) in anomalies if s == "WARN"]
    bits = []
    if crit: bits.append(f"{len(crit)} CRITICAL ({','.join(crit)})")
    if warn: bits.append(f"{len(warn)} WARN ({','.join(warn)})")
    out.append(f"[ANOMALY] {'; '.join(bits)}")

print("\n".join(out))
sys.exit(0)
PY
)
PY_RC=$?

# python exit 3 == malformed RPC response → map to the script's exit 1
# (RPC-parse error) per the exit-code contract. Any other non-zero from
# python (shouldn't happen) is also treated as a parse error.
if [ "$PY_RC" = "3" ]; then
  echo "operator_peer_connectivity_health: malformed RPC response on port $PORT" >&2
  [ -n "$RESULT" ] && printf '%s\n' "$RESULT" >&2
  exit 1
fi
if [ "$PY_RC" != "0" ]; then
  echo "operator_peer_connectivity_health: internal error parsing RPC response (rc=$PY_RC)" >&2
  [ -n "$RESULT" ] && printf '%s\n' "$RESULT" >&2
  exit 1
fi

printf '%s\n' "$RESULT"

# ── exit-code contract: anomaly gating only under --anomalies-only ───
# Re-derive "anomaly present" from the rendered output so we don't have
# to thread a second channel out of python. Both --json and human modes
# carry an unambiguous marker:
#   human : a literal "[ANOMALY]" verdict line.
#   json  : "ok": false  (and a non-empty anomalies array).
if [ "$ANOM_ONLY" = "1" ]; then
  if [ "$JSON" = "1" ]; then
    case "$RESULT" in
      *'"ok": false'*|*'"ok":false'*) exit 2 ;;
    esac
  else
    case "$RESULT" in
      *'[ANOMALY]'*) exit 2 ;;
    esac
  fi
fi
exit 0
