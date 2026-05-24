#!/usr/bin/env bash
# operator_network_partition_detect.sh — N-peer network-partition detector.
# Probes head_hash + chain_height + chain_id across N RPC endpoints and
# flags partition conditions where two or more honest-looking peers
# (same chain_id, modal height within a tolerance window) disagree on
# the tip block_hash.
#
# Sibling positioning (R36A6 family):
#   * operator_consensus_lag.sh         — N-way HEIGHT-only lag check
#     across a fleet. Asks "who is BEHIND?". No head_hash comparison,
#     so a fork at matching height is invisible to it.
#   * operator_chain_diff.sh            — PAIRWISE block-level diff
#     between TWO daemons across a height window. Catches historical
#     divergence + cross-node apply-determinism break. Cost grows with
#     window size; only two endpoints at a time.
#   * operator_chain_summary_diff.sh    — TWO-DAEMON SCALAR-FIELD diff
#     of chain-summary at the tip. Catches identity / supply / head
#     drift between exactly two peers.
#   * operator_network_partition_detect.sh (THIS) — N-PEER PARTITION
#     detection. Asks the orthogonal question:
#       "Across N peers at (roughly) the SAME height, do they all
#        agree on head_hash, or do they cluster into two-or-more groups
#        with DIFFERENT head_hash at that same height?"
#     A 2+ group split is the wire-level signature of a network
#     partition (honest committees finalized different blocks on each
#     side of the split). Minimum 3 endpoints required to make the
#     question meaningful (a 2-peer disagreement is just `chain_diff`).
#
# Partition definition:
#   A network partition manifests as 2+ groups of in-sync peers
#   (same chain_id, height within tolerance of the modal height across
#   the chain_id group) that disagree on head_hash. The script
#   intentionally bickets-by-chain_id FIRST because peers configured
#   for different chains entirely are NOT partitioned — they're
#   misconfigured. After chain_id bucketing, peers within
#   --height-tolerance of the per-chain_id modal height are "in-sync
#   candidates"; everyone else is "lagging" (out of the partition
#   analysis but still surfaced in the output).
#
# Algorithm:
#   1. For each port, fetch head height + head_hash + chain_id via
#      `determ head` / `determ chain-id` RPC calls (read-only).
#   2. Group peers by chain_id. Different chain_id = different network
#      (operator misconfig); reported as `chain_id_mismatch` anomaly
#      but NOT a partition.
#   3. Within each chain_id group:
#      a. Compute the modal height (mode; ties broken toward higher).
#      b. Partition peers into:
#           in_sync_candidates  — height within ±tolerance of modal
#           lagging             — height delta > tolerance
#      c. Among in_sync_candidates, group by head_hash. 2+ groups with
#         different head_hash at (effectively) the same height = a
#         partition.
#   4. Anomalies:
#      * partition_detected     — 2+ head_hash groups in a chain_id
#                                  bucket. CRITICAL operator alert.
#                                  Exit 2.
#      * majority_minority_split — one head_hash group has the majority
#                                  of in-sync peers, but a minority
#                                  group of 2+ peers sits on a different
#                                  head_hash. Subcase of partition_detected
#                                  but operationally distinct: the
#                                  minority is the "isolated" side and
#                                  likely needs reconnection (vs. a
#                                  symmetric 50/50 split which is more
#                                  ambiguous about which side to keep).
#      * high_lag_peer          — any peer lagging > 100 blocks from
#                                  its chain_id's modal height. Long-
#                                  running disconnection (not a
#                                  partition per se but worth flagging).
#      * chain_id_mismatch      — 2+ distinct chain_id values across
#                                  the endpoint set. Operator misconfig;
#                                  the per-chain_id partition analysis
#                                  still runs independently in each
#                                  bucket.
#      * unreachable_peer       — any peer's RPC failed. Diagnostic
#                                  only; doesn't gate the exit code on
#                                  its own (a stalled peer is its own
#                                  alert via operator_consensus_lag).
#
# Read-only RPC; safe against any running daemons. All ports must be
# listening on 127.0.0.1.
#
# Usage:
#   tools/operator_network_partition_detect.sh \
#         --rpc-ports 8771,8772,8773[,...] \
#         [--height-tolerance N] [--json] [--anomalies-only]
#
# Exit codes:
#   0   no partition detected (all in-sync peers agree on head_hash;
#       lagging / unreachable peers may still be present but are not
#       partition signals)
#   2   partition_detected fired (head_hash split among in-sync peers
#       on the same chain_id — operator alert gate)
#   1   RPC error / args error / malformed response / fewer than 3
#       endpoints supplied
set -u

usage() {
  cat <<'EOF'
Usage: operator_network_partition_detect.sh --rpc-ports P1,P2,P3[,...]
                                            [--height-tolerance N]
                                            [--json] [--anomalies-only]

Detects network partitions across N peer RPC endpoints by comparing
(height, head_hash, chain_id) tuples. A partition = 2+ groups of
in-sync peers (same chain_id, height within tolerance) that disagree
on the tip head_hash.

Required:
  --rpc-ports LIST     Comma-separated RPC ports (e.g. 8771,8772,8773),
                       OR @<file> to read one port per line from <file>.
                       Minimum 3 ports — a 2-peer disagreement is
                       trivially `chain_diff`, not a partition.
                       Duplicates de-duped in encounter order.

Options:
  --height-tolerance N Tolerate height drift up to N blocks from the
                       per-chain_id modal height (default: 3). Peers
                       further apart are classified as `lagging` and
                       excluded from partition analysis (a lagging
                       peer's stale head_hash is expected, not a
                       partition signal). Must be a non-negative integer.
  --json               Emit single-line JSON envelope (shape below).
  --anomalies-only     Suppress healthy rows in human output (only
                       show non-OK peers + anomalies + summary).
  -h, --help           Show this help.

Exit codes:
  0   no partition (all in-sync peers agree on head_hash in each
      chain_id bucket)
  2   partition_detected (head_hash split among in-sync peers on the
      same chain_id; operator alert gate)
  1   RPC error / args / malformed response / fewer than 3 endpoints

JSON envelope (--json):
  {"ports": [P1, P2, ...],
   "height_tolerance": N,
   "chain_ids": ["<cid>", ...],
   "peers": [
     {"port": P, "reachable": bool, "height": H|null,
      "head_hash": "<hex>"|null, "chain_id": "<cid>"|null,
      "bucket": "in_sync|lagging|unreachable",
      "head_group": <gid>|null, "lag": <int>|null}, ...
   ],
   "groups": [
     {"chain_id": "<cid>", "modal_height": H,
      "in_sync_peers": [P, ...], "lagging_peers": [P, ...],
      "head_groups": [
        {"head_hash": "<hex>", "peers": [P, ...]}, ...
      ],
      "majority_head_hash": "<hex>"|null,
      "minority_peer_count": N,
      "partitioned": bool}, ...
   ],
   "anomalies": ["partition_detected", "majority_minority_split", ...],
   "summary": {"n_peers": N, "n_reachable": N, "n_chain_ids": N,
               "n_in_sync": N, "n_lagging": N, "n_unreachable": N,
               "n_partitioned_groups": N}}

Examples:
  # 3-node committee health check.
  tools/operator_network_partition_detect.sh --rpc-ports 8771,8772,8773

  # Wider committee with looser drift tolerance (busy network).
  tools/operator_network_partition_detect.sh \
      --rpc-ports 8771,8772,8773,8774,8775,8776,8777 \
      --height-tolerance 5

  # Monitoring loop: machine-readable, only flag non-healthy.
  while true; do
    tools/operator_network_partition_detect.sh --rpc-ports @ports.txt \
        --json --anomalies-only || alert "partition"
    sleep 10
  done
EOF
}

PORTS_RAW=""
HEIGHT_TOL=3
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)            usage; exit 0 ;;
    --rpc-ports)          PORTS_RAW="${2:-}"; shift 2 ;;
    --height-tolerance)   HEIGHT_TOL="${2:-}"; shift 2 ;;
    --json)               JSON_OUT=1; shift ;;
    --anomalies-only)     ANOM_ONLY=1; shift ;;
    *) echo "operator_network_partition_detect: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$PORTS_RAW" ]; then
  echo "operator_network_partition_detect: --rpc-ports is required" >&2
  usage >&2
  exit 1
fi

case "$HEIGHT_TOL" in *[!0-9]*|"")
  echo "operator_network_partition_detect: --height-tolerance must be a non-negative integer (got '$HEIGHT_TOL')" >&2
  exit 1 ;;
esac

# @<file> form: read one port per line from <file>. Lines starting with
# '#' and blank lines are ignored. Resolves to the same comma-separated
# parse path below.
if [ "${PORTS_RAW#@}" != "$PORTS_RAW" ]; then
  pfile="${PORTS_RAW#@}"
  if [ ! -r "$pfile" ]; then
    echo "operator_network_partition_detect: --rpc-ports @-file not readable: '$pfile'" >&2
    exit 1
  fi
  PORTS_RAW=""
  while IFS= read -r line; do
    # Strip CR (Windows line endings).
    line="${line%$'\r'}"
    # Strip leading/trailing whitespace.
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    case "$line" in
      ''|'#'*) continue ;;
    esac
    if [ -z "$PORTS_RAW" ]; then PORTS_RAW="$line"; else PORTS_RAW="$PORTS_RAW,$line"; fi
  done < "$pfile"
  if [ -z "$PORTS_RAW" ]; then
    echo "operator_network_partition_detect: --rpc-ports @-file '$pfile' contained no ports" >&2
    exit 1
  fi
fi

# Parse + validate ports. Split on comma, trim, dedup-in-order.
PORTS=""
SEEN=""
IFS=',' read -ra _PORTS <<<"$PORTS_RAW"
for raw in "${_PORTS[@]}"; do
  p="${raw#"${raw%%[![:space:]]*}"}"
  p="${p%"${p##*[![:space:]]}"}"
  if [ -z "$p" ]; then
    continue
  fi
  case "$p" in *[!0-9]*)
    echo "operator_network_partition_detect: --rpc-ports entry '$p' is not numeric" >&2
    exit 1 ;;
  esac
  if [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
    echo "operator_network_partition_detect: --rpc-ports entry '$p' must be 1..65535" >&2
    exit 1
  fi
  case " $SEEN " in
    *" $p "*) continue ;;
  esac
  SEEN="$SEEN $p"
  if [ -z "$PORTS" ]; then PORTS="$p"; else PORTS="$PORTS $p"; fi
done

if [ -z "$PORTS" ]; then
  echo "operator_network_partition_detect: --rpc-ports resolved to an empty list" >&2
  exit 1
fi

# Count ports. Partition detection across <3 peers is degenerate
# (2 peers disagreeing = `chain_diff`, not a partition).
N_PORTS=$(printf '%s\n' $PORTS | wc -l | tr -d '[:space:]')
if [ "$N_PORTS" -lt 3 ]; then
  echo "operator_network_partition_detect: at least 3 distinct ports are required for partition detection (got $N_PORTS); use operator_chain_summary_diff.sh for pairwise comparison" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Resolve python for the per-peer aggregation and JSON / human render.
PYEXE=""
if   command -v python3 >/dev/null 2>&1; then PYEXE=python3
elif command -v python  >/dev/null 2>&1; then PYEXE=python
else
  echo "operator_network_partition_detect: python (python3 or python) is required for aggregation" >&2
  exit 1
fi

# ── Per-port probe ──────────────────────────────────────────────────────────
# For each port:
#   height    = `determ head --field height --rpc-port P`    (numeric)
#   head_hash = `determ head --field hash   --rpc-port P`    (hex; "" at genesis)
#   chain_id  = `determ chain-id           --rpc-port P`     (hex/str)
#
# Any per-port RPC failure on any of the three calls marks the peer as
# unreachable (we accumulate the partial fields anyway — null for the
# missing ones — so the output table can show which call succeeded).
# Per the script's contract, unreachable peers DON'T gate the exit
# code on their own; partition detection is the gate.
#
# We accumulate per-port records as pipe-joined fields ("port|h|hash|cid")
# and concatenate with a record separator so python can parse cleanly.
fetch_field() {
  # fetch_field <port> <subcommand> <field-or-empty>
  # → bare value on stdout, rc 0 on success, rc 1 on RPC error.
  local port="$1" sub="$2" field="$3"
  local out
  if [ -n "$field" ]; then
    out=$("$DETERM" "$sub" --field "$field" --rpc-port "$port" 2>/dev/null)
  else
    out=$("$DETERM" "$sub" --rpc-port "$port" 2>/dev/null)
  fi
  local rc=$?
  if [ "$rc" -ne 0 ]; then return 1; fi
  printf '%s' "$out" | tr -d '[:space:]'
}

# Per-peer record format: "port|reachable|height|head_hash|chain_id"
#   reachable = "1" iff ALL THREE probes returned rc 0.
#   Missing values render as the literal string "" (empty); python
#   side treats "" as null.
RECORDS=""
for port in $PORTS; do
  reach=1
  h=$(fetch_field "$port" head height) || { h=""; reach=0; }
  case "$h" in *[!0-9]*) h=""; reach=0 ;; esac

  # head_hash: only meaningful when height > 0. At genesis (height==0)
  # there is no last finalized block beyond block 0; `determ head
  # --field hash` returns the genesis-block hash on most builds, but
  # we treat empty as "no head" for the partition logic. Tolerate
  # empty hash at height 0 without marking unreachable.
  hh=$(fetch_field "$port" head hash) || { hh=""; reach=0; }

  cid=$("$DETERM" chain-id --rpc-port "$port" 2>/dev/null)
  rc=$?
  if [ "$rc" -ne 0 ]; then
    cid=""; reach=0
  else
    cid=$(printf '%s' "$cid" | tr -d '[:space:]')
  fi

  rec="${port}|${reach}|${h}|${hh}|${cid}"
  if [ -z "$RECORDS" ]; then RECORDS="$rec"; else RECORDS="${RECORDS}@@${rec}"; fi
done

# ── Hand off to python for the partition analysis + render ──────────────────
"$PYEXE" - "$HEIGHT_TOL" "$JSON_OUT" "$ANOM_ONLY" "$RECORDS" <<'PY'
import json, sys
from collections import Counter, defaultdict

height_tol_s, json_out_s, anom_only_s, records_s = sys.argv[1:5]
height_tol = int(height_tol_s)
json_out   = json_out_s == "1"
anom_only  = anom_only_s == "1"

# Lag threshold for the high_lag_peer anomaly. Long-running
# disconnection signature — peer's tip is so far below the modal
# height that it's likely been disconnected for hundreds of blocks
# rather than briefly out-of-sync.
HIGH_LAG_THRESHOLD = 100

# Parse records.
peers = []
for rec in records_s.split("@@"):
    if not rec:
        continue
    parts = rec.split("|")
    # Defensive: split must yield exactly 5 fields.
    while len(parts) < 5:
        parts.append("")
    port_s, reach_s, h_s, hh_s, cid_s = parts[:5]
    try:
        port = int(port_s)
    except ValueError:
        sys.stderr.write(f"operator_network_partition_detect: malformed record port '{port_s}'\n")
        sys.exit(1)
    reachable = (reach_s == "1")
    height = int(h_s) if h_s else None
    head_hash = hh_s if hh_s else None
    chain_id  = cid_s if cid_s else None
    peers.append({
        "port":      port,
        "reachable": reachable,
        "height":    height,
        "head_hash": head_hash,
        "chain_id":  chain_id,
        # Filled in below:
        "bucket":    "unreachable" if not reachable else None,
        "head_group": None,
        "lag":       None,
    })

# ── Group by chain_id ───────────────────────────────────────────────────────
# Only reachable peers participate in the per-chain_id partition analysis.
# Peers with chain_id=None (RPC failed for chain-id specifically) are
# bucketed as unreachable above.
by_cid = defaultdict(list)
for p in peers:
    if p["reachable"] and p["chain_id"] is not None and p["height"] is not None:
        by_cid[p["chain_id"]].append(p)

chain_ids_sorted = sorted(by_cid.keys())

groups = []
anomalies = set()

for cid in chain_ids_sorted:
    cohort = by_cid[cid]
    if not cohort:
        continue

    # Modal height (mode); ties broken toward the HIGHER value so the
    # in-sync band leans toward the leading edge (a peer at the highest
    # tied height is by definition not lagging).
    heights = [p["height"] for p in cohort]
    counter = Counter(heights)
    max_count = max(counter.values())
    candidates = [h for h, c in counter.items() if c == max_count]
    modal_height = max(candidates)

    in_sync = []
    lagging = []
    for p in cohort:
        delta = p["height"] - modal_height       # signed; negative ⇒ behind
        # |delta| against tolerance for in-sync classification. A peer
        # AHEAD of the modal height by > tolerance is also "lagging"
        # in the sense of being out-of-band for the partition test
        # (its head_hash necessarily differs because it's at a
        # different height); we still surface it but exclude it from
        # the same-height head_hash comparison.
        p["lag"] = -delta if delta <= 0 else delta  # absolute lag-from-modal
        if abs(delta) <= height_tol:
            p["bucket"] = "in_sync"
            in_sync.append(p)
        else:
            p["bucket"] = "lagging"
            lagging.append(p)

        # high_lag_peer flags peers that are FAR BEHIND (positive lag;
        # leading peers are not "lagging" in the operational sense).
        if delta < 0 and abs(delta) > HIGH_LAG_THRESHOLD:
            anomalies.add("high_lag_peer")

    # ── head_hash partition analysis within in-sync band ───────────────────
    # Peers with head_hash=None (e.g., empty-chain genesis state) are
    # bucketed separately — they CAN'T disagree with anyone because
    # they have no tip to compare. Group them under the "<empty>"
    # synthetic head_hash so they don't get silently dropped.
    head_buckets = defaultdict(list)
    for p in in_sync:
        key = p["head_hash"] if p["head_hash"] is not None else "<empty>"
        head_buckets[key].append(p["port"])

    # Sort head groups by descending peer count (majority first), then
    # by head_hash for stable ordering across runs.
    head_groups_sorted = sorted(
        head_buckets.items(),
        key=lambda kv: (-len(kv[1]), kv[0]),
    )

    # Assign head_group index to each peer (for the human row table)
    # in the same order as head_groups_sorted.
    hh_to_gid = {hh: gid for gid, (hh, _) in enumerate(head_groups_sorted)}
    for p in in_sync:
        key = p["head_hash"] if p["head_hash"] is not None else "<empty>"
        p["head_group"] = hh_to_gid[key]

    n_head_groups = len(head_groups_sorted)
    partitioned = n_head_groups >= 2

    if partitioned:
        anomalies.add("partition_detected")
        # majority_minority_split: top group is strictly larger than
        # the runner-up AND the runner-up has 2+ peers (we ignore
        # singletons because a single dissenter could be a lone
        # misbehaving / mid-sync node, not necessarily a "side" of the
        # partition). The "minority_peer_count" emitted below is the
        # sum of all NON-majority group peer counts (not just the
        # runner-up) so operators see the full minority cohort.
        top_size = len(head_groups_sorted[0][1])
        runner_up_size = len(head_groups_sorted[1][1])
        if top_size > runner_up_size and runner_up_size >= 2:
            anomalies.add("majority_minority_split")

    # Compute majority head_hash for the emitted group record. If
    # there's an outright majority (>50%), surface it; otherwise null
    # (a 50/50 split is symmetric and there's no clear majority).
    n_in_sync = len(in_sync)
    majority_head_hash = None
    if n_in_sync > 0:
        top_hh, top_peers = head_groups_sorted[0]
        if len(top_peers) * 2 > n_in_sync:
            majority_head_hash = top_hh if top_hh != "<empty>" else None
    minority_peer_count = n_in_sync - (
        len(head_groups_sorted[0][1]) if head_groups_sorted else 0
    )

    groups.append({
        "chain_id":     cid,
        "modal_height": modal_height,
        "in_sync_peers": sorted(p["port"] for p in in_sync),
        "lagging_peers": sorted(p["port"] for p in lagging),
        "head_groups": [
            {"head_hash": hh, "peers": sorted(ports)}
            for hh, ports in head_groups_sorted
        ],
        "majority_head_hash":  majority_head_hash,
        "minority_peer_count": minority_peer_count,
        "partitioned":         partitioned,
    })

# chain_id_mismatch anomaly: >1 distinct chain_id across reachable
# peers. Note that chain_id None (RPC error path) doesn't count here —
# only daemons that returned an actual chain_id contribute.
if len(chain_ids_sorted) > 1:
    anomalies.add("chain_id_mismatch")

# unreachable_peer anomaly: any peer with reachable=False. Diagnostic
# only (doesn't gate exit on its own per the script contract).
if any(not p["reachable"] for p in peers):
    anomalies.add("unreachable_peer")

# Sort anomalies for stable JSON output. Order is alphabetical except
# we float partition_detected to the front (it's the headline event).
anomalies_sorted = sorted(anomalies)
if "partition_detected" in anomalies_sorted:
    anomalies_sorted.remove("partition_detected")
    anomalies_sorted = ["partition_detected"] + anomalies_sorted

# Summary counters.
n_reachable    = sum(1 for p in peers if p["reachable"])
n_in_sync      = sum(1 for p in peers if p["bucket"] == "in_sync")
n_lagging      = sum(1 for p in peers if p["bucket"] == "lagging")
n_unreachable  = sum(1 for p in peers if p["bucket"] == "unreachable")
n_partitioned  = sum(1 for g in groups if g["partitioned"])
summary = {
    "n_peers":              len(peers),
    "n_reachable":          n_reachable,
    "n_chain_ids":          len(chain_ids_sorted),
    "n_in_sync":            n_in_sync,
    "n_lagging":            n_lagging,
    "n_unreachable":        n_unreachable,
    "n_partitioned_groups": n_partitioned,
}

# Exit code policy:
#   0   no partition_detected
#   2   partition_detected fired (operator alert gate)
exit_rc = 2 if "partition_detected" in anomalies_sorted else 0

# ── Render ──────────────────────────────────────────────────────────────────
if json_out:
    out = {
        "ports":            [p["port"] for p in peers],
        "height_tolerance": height_tol,
        "chain_ids":        chain_ids_sorted,
        "peers":            peers,
        "groups":           groups,
        "anomalies":        anomalies_sorted,
        "summary":          summary,
    }
    print(json.dumps(out, separators=(",", ":")))
    sys.exit(exit_rc)

# Human render.
def fmt_hash(h):
    if h is None:
        return "<none>"
    if h == "<empty>":
        return "<empty>"
    if len(h) >= 40 and all(c in "0123456789abcdefABCDEF" for c in h):
        return h[:12] + "..." + h[-6:]
    return h

def fmt_cid(c):
    if c is None:
        return "<none>"
    if len(c) >= 24 and all(c2 in "0123456789abcdefABCDEF" for c2 in c):
        return c[:10] + "..." + c[-6:]
    return c

print(f"=== Network partition detection (height_tolerance=±{height_tol} blocks) ===")
print(f"Probed {len(peers)} endpoint(s); {n_reachable} reachable, "
      f"{n_unreachable} unreachable; {len(chain_ids_sorted)} chain_id(s).")
print("")

# Per-peer table.
visible_peers = peers
if anom_only:
    visible_peers = [p for p in peers
                     if p["bucket"] != "in_sync"
                     or (p["head_group"] is not None and p["head_group"] != 0)]

if visible_peers:
    # Compute column widths.
    name_w = max(len("port"),       max((len(str(p["port"]))         for p in visible_peers), default=4))
    h_w    = max(len("height"),     max((len(str(p["height"]) if p["height"] is not None else "n/a") for p in visible_peers), default=6))
    hh_w   = max(len("head_hash"),  max((len(fmt_hash(p["head_hash"])) for p in visible_peers), default=9))
    cid_w  = max(len("chain_id"),   max((len(fmt_cid(p["chain_id"]))   for p in visible_peers), default=8))
    bucket_w = max(len("bucket"),   max((len(p["bucket"] or "?") for p in visible_peers), default=6))

    print(f"  {'port':>{name_w}}  {'height':>{h_w}}  "
          f"{'head_hash':<{hh_w}}  {'chain_id':<{cid_w}}  "
          f"{'bucket':<{bucket_w}}  group  lag")
    print(f"  {'-'*name_w}  {'-'*h_w}  {'-'*hh_w}  {'-'*cid_w}  {'-'*bucket_w}  -----  ---")
    for p in visible_peers:
        h_disp = str(p["height"]) if p["height"] is not None else "n/a"
        hh_disp = fmt_hash(p["head_hash"])
        cid_disp = fmt_cid(p["chain_id"])
        gid_disp = str(p["head_group"]) if p["head_group"] is not None else "-"
        lag_disp = str(p["lag"]) if p["lag"] is not None else "-"
        print(f"  {p['port']:>{name_w}}  {h_disp:>{h_w}}  "
              f"{hh_disp:<{hh_w}}  {cid_disp:<{cid_w}}  "
              f"{(p['bucket'] or '?'):<{bucket_w}}  "
              f"{gid_disp:>5}  {lag_disp:>3}")
else:
    print("  (no rows to display under --anomalies-only)")

print("")
# Per-chain_id partition report.
for g in groups:
    cid_disp = fmt_cid(g["chain_id"])
    n_in_sync_cohort = len(g["in_sync_peers"])
    n_lag = len(g["lagging_peers"])
    n_hg = len(g["head_groups"])
    label = "PARTITIONED" if g["partitioned"] else "ok"
    print(f"chain_id={cid_disp}  modal_height={g['modal_height']}  "
          f"in_sync={n_in_sync_cohort}  lagging={n_lag}  "
          f"head_groups={n_hg}  [{label}]")
    if not anom_only or g["partitioned"]:
        for gid, hg in enumerate(g["head_groups"]):
            marker = "*" if (g["majority_head_hash"] is not None
                             and hg["head_hash"] == g["majority_head_hash"]) else " "
            peers_disp = ",".join(str(p) for p in hg["peers"])
            print(f"  {marker} group {gid}: head_hash={fmt_hash(hg['head_hash'])}  "
                  f"peers=[{peers_disp}]  n={len(hg['peers'])}")

if anomalies_sorted:
    print("")
    print(f"Anomalies ({len(anomalies_sorted)}):")
    for a in anomalies_sorted:
        print(f"  [!] {a}")

print("")
print(f"Summary: n_peers={summary['n_peers']}  "
      f"reachable={n_reachable}  chain_ids={summary['n_chain_ids']}  "
      f"in_sync={n_in_sync}  lagging={n_lagging}  "
      f"unreachable={n_unreachable}  "
      f"partitioned_groups={n_partitioned}")
print("")
if exit_rc == 0:
    if n_partitioned == 0 and not anomalies_sorted:
        print(f"[OK] no partition detected — all in-sync peers agree on head_hash.")
    else:
        bits = []
        if "chain_id_mismatch" in anomalies_sorted:
            bits.append(f"{summary['n_chain_ids']} distinct chain_id(s) present")
        if "unreachable_peer" in anomalies_sorted:
            bits.append(f"{n_unreachable} unreachable peer(s)")
        if "high_lag_peer" in anomalies_sorted:
            bits.append("high_lag peer(s) detected")
        detail = "; ".join(bits) if bits else "see anomalies above"
        print(f"[OK] no partition_detected, but: {detail}.")
else:
    bits = []
    bits.append(f"{n_partitioned} chain_id group(s) split across multiple head_hash")
    if "majority_minority_split" in anomalies_sorted:
        bits.append("majority/minority split (minority of 2+ peers on a different head_hash)")
    detail = "; ".join(bits)
    print(f"[X]  Partition detected — {detail}.")

sys.exit(exit_rc)
PY
PY_RC=$?
exit "$PY_RC"
