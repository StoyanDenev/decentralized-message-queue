#!/usr/bin/env bash
# operator_receipt_settlement_latency.sh — Cross-shard receipt SETTLEMENT-
# LATENCY profiler. Pairs each outbound CrossShardReceipt emitted by THIS
# (source) shard against the inbound application that consumed it on the
# DESTINATION shard, and reports the per-receipt round-trip latency
# distribution (the block delta between source-emit and destination-apply)
# plus the set of receipts that were emitted but have NOT yet settled.
#
# THE OPERATOR QUESTION
#   "When my shard debits an account and emits a cross-shard receipt, how
#    many blocks does it actually take for the destination shard to credit
#    the recipient? Is the round-trip honoring the CROSS_SHARD_RECEIPT_
#    LATENCY soak, or is settlement dragging / stalling? Which specific
#    emitted receipts have NOT been applied anywhere yet?"
#
# WHY THIS IS DISTINCT FROM THE SIBLING CROSS-SHARD TOOLS
#   operator_cross_shard_health.sh   pending-pool depth + a per-block
#                                    emit/apply COUNT trace + a coarse
#                                    live apply-lag heuristic. It never
#                                    PAIRS a specific emitted receipt with
#                                    its application, so it cannot measure
#                                    per-receipt round-trip latency.
#   operator_receipt_audit.sh        FA7 dedup-set forensics + A1 delta +
#                                    per-shard volume table on ONE shard.
#   operator_receipt_flow.sh         fleet-level A1 COUNTER balance
#                                    (Σ_out vs Σ_in + in-flight); no
#                                    per-receipt pairing, no latency.
#   operator_receipt_proof_audit.sh  i:-namespace Merkle proof audit of
#                                    applied_inbound markers.
#   operator_receipt_settlement_latency.sh  (THIS)  the only tool that
#                                    JOINS the source shard's emitted
#                                    cross_shard_receipts[] to the
#                                    destination shard's inbound_receipts[]
#                                    on the (src_shard, src_block_index,
#                                    tx_hash) key, computes per-receipt
#                                    settlement latency = apply_index −
#                                    src_block_index, and produces the
#                                    min / p50 / p95 / max latency
#                                    distribution + an unsettled-receipt
#                                    roster.
#
# THE JOIN KEY
#   The same CrossShardReceipt struct appears on BOTH legs (see
#   src/chain/block.cpp::CrossShardReceipt::to_json) — emitted into the
#   source block's `cross_shard_receipts[]` and, after admission soak +
#   inclusion on the destination shard, into the destination block's
#   `inbound_receipts[]`. The triple (src_shard, src_block_index, tx_hash)
#   is the apply-time dedup key (chain.cpp applied_inbound set), so it is
#   a globally-unique receipt identifier and the natural join key here.
#
# WHAT IT NEEDS
#   The source leg lives on the LOCAL daemon (--rpc-port). The destination
#   leg lives on whichever OTHER shard daemon credited the recipient, so
#   --peer-ports must enumerate the destination shards' RPC ports. With NO
#   --peer-ports the script still walks the local outbound legs, reports
#   the emitted-receipt inventory + the destinations they targeted, and
#   marks every receipt UNSETTLED-UNKNOWN (it cannot see the apply side of
#   a shard it can't query) — useful as a "what did I send out?" inventory
#   but the latency distribution requires the destination ports.
#
# SETTLEMENT BUDGET (S-016 Option 2)
#   src/node/node.cpp::CROSS_SHARD_RECEIPT_LATENCY = 3 blocks of admission
#   soak between a receipt's local first-observation on the destination
#   shard and its inclusion in a produced block, on top of gossip-
#   propagation time. A healthy receipt therefore settles a few blocks
#   after its src_block_index. The `--settle-budget-slack` knob (default
#   20) sets the over-budget threshold: a SETTLED receipt whose latency
#   exceeds CROSS_SHARD_RECEIPT_LATENCY (3) + slack is flagged slow, and
#   an UNSETTLED receipt whose age (dst tip − src_block_index) exceeds the
#   same budget is flagged overdue.
#
# Read-only RPCs only (status / head / block-info). NEVER a mutating RPC.
# No node spawning, no --watch, no unbounded loops: a single bounded pass
# over the local source window + the destination windows, each block-info
# call with a per-call subprocess timeout, then exit.
#
# Single-shard deployments (sharding_mode == "none"): every cross-shard
# metric is trivially empty by construction. The script short-circuits to
# a single INFO line and exits 0.
#
# Anomalies (any fires → exit 2 in --anomalies-only mode):
#   receipts_unsettled_overdue   ≥1 emitted receipt is still UNSETTLED and
#                                its age (dst tip − src_block_index) on the
#                                queried destination shard exceeds
#                                CROSS_SHARD_RECEIPT_LATENCY + slack. The
#                                destination has been producing blocks long
#                                enough that the receipt should have applied
#                                — a stalled / aborting destination producer
#                                or a lost gossip bundle.
#   settlement_latency_high      ≥1 SETTLED receipt's measured round-trip
#                                latency exceeds the budget. Settlement is
#                                completing but slowly (gossip backlog or a
#                                congested destination producer).
#   settled_before_emit          ≥1 SETTLED receipt has a NEGATIVE latency
#                                (apply_index < src_block_index). Should be
#                                impossible — the destination cannot apply a
#                                receipt before the source emitted it. A hit
#                                indicates clock/index corruption or a
#                                cross-fed window from the wrong chain
#                                (mismatched genesis); catastrophic.
#
# Usage:
#   tools/operator_receipt_settlement_latency.sh --rpc-port N
#                       [--peer-ports P1,P2,…]
#                       [--from H] [--to H] [--last N]
#                       [--settle-budget-slack N]
#                       [--block-timeout S]
#                       [--anomalies-only] [--json]
#
# --rpc-port is the LOCAL (source) shard daemon (REQUIRED). The source
# window [--from..--to] (or --last) selects which emitted receipts to
# profile. --peer-ports lists the destination shards' RPC ports; each is
# walked from genesis-to-tip for matching inbound_receipts[] (capped — see
# --peer-scan-cap). All ports assume 127.0.0.1 (the determ CLI's RPC host).
#
# --json shape:
#   {"mode":"single|fleet","my_shard_id":N,"sharding_mode":"...",
#    "source_window":{"from":H,"to":H,"blocks":N},
#    "peer_ports":[N,...],
#    "emitted_count":N,"settled_count":N,"unsettled_count":N,
#    "latency":{"min":N,"p50":N,"p95":N,"max":N,"mean":N}|null,
#    "by_destination":[{"shard":N,"emitted":N,"settled":N,
#                       "unsettled":N,"p50_latency":N|null}, ...],
#    "slow_settlements":[{"tx_hash":"...","src_block_index":H,
#                         "dst_shard":N,"apply_index":H,"latency":N}, ...],
#    "unsettled_overdue":[{"tx_hash":"...","src_block_index":H,
#                          "dst_shard":N,"age":N}, ...],
#    "anomalies":[...], "rpc_port":N}
#
# Exit codes:
#   0   profiled OK (no anomalies, or default informational mode, or
#       single-shard deployment)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_receipt_settlement_latency.sh --rpc-port N
                    [--peer-ports P1,P2,…]
                    [--from H] [--to H] [--last N]
                    [--settle-budget-slack N]
                    [--peer-scan-cap N]
                    [--block-timeout S]
                    [--anomalies-only] [--json]

Cross-shard receipt settlement-latency profiler. Joins the LOCAL (source)
shard's emitted cross_shard_receipts[] to the DESTINATION shards'
inbound_receipts[] on the (src_shard, src_block_index, tx_hash) key,
computes each receipt's round-trip latency (apply_index − src_block_index),
and reports the latency distribution + the roster of emitted-but-unsettled
receipts.

NOTE: the latency distribution requires --peer-ports so the apply side is
visible. With no peers the script reports the emitted-receipt inventory +
their targeted destinations and marks everything UNSETTLED-UNKNOWN.

NOTE: meaningful only on multi-shard deployments. On sharding_mode=none the
script exits 0 with an INFO line.

Options:
  --rpc-port N             LOCAL (source) shard daemon RPC port (REQUIRED)
  --peer-ports P1,P2,…     Comma-separated destination shard RPC ports.
                           Each is walked genesis-to-tip (capped by
                           --peer-scan-cap) for matching inbound_receipts[].
  --from H                 Source-window lower bound, inclusive (default:
                           max(0, tip − 256 + 1))
  --to H                   Source-window upper bound, inclusive (default:
                           local tip)
  --last N                 Shorthand for [tip−N+1, tip] (exclusive with
                           --from / --to)
  --settle-budget-slack N  Over-budget threshold added to CROSS_SHARD_
                           RECEIPT_LATENCY (3) for the slow / overdue
                           anomalies (default: 20)
  --peer-scan-cap N        Max blocks to walk per destination shard
                           (most-recent N, ending at that shard's tip)
                           (default: 2000; 0 = no cap)
  --block-timeout S        Per-block-info RPC timeout in seconds (default 10)
  --anomalies-only         Print only flagged anomalies; exit 2 if any fire
  --json                   Emit a structured JSON envelope
  -h, --help               Show this help

Anomalies:
  receipts_unsettled_overdue  emitted receipt UNSETTLED on its destination
                              shard past CROSS_SHARD_RECEIPT_LATENCY + slack
  settlement_latency_high     SETTLED receipt's round-trip latency exceeds
                              the budget (slow settlement)
  settled_before_emit         SETTLED receipt with NEGATIVE latency
                              (apply before emit) — catastrophic

Exit codes:
  0   profiled OK (or single-shard deployment / informational mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=""
PEER_PORTS=""
FROM=""
TO=""
LAST=""
SETTLE_SLACK=20
PEER_SCAN_CAP=2000
BLOCK_TIMEOUT=10
ANOM_ONLY=0
JSON_OUT=0

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)              usage; exit 0 ;;
    --rpc-port)             PORT="${2:-}";          shift 2 ;;
    --peer-ports)           PEER_PORTS="${2:-}";    shift 2 ;;
    --from)                 FROM="${2:-}";          shift 2 ;;
    --to)                   TO="${2:-}";            shift 2 ;;
    --last)                 LAST="${2:-}";          shift 2 ;;
    --settle-budget-slack)  SETTLE_SLACK="${2:-}";  shift 2 ;;
    --peer-scan-cap)        PEER_SCAN_CAP="${2:-}"; shift 2 ;;
    --block-timeout)        BLOCK_TIMEOUT="${2:-}"; shift 2 ;;
    --anomalies-only)       ANOM_ONLY=1;            shift ;;
    --json)                 JSON_OUT=1;             shift ;;
    *) echo "operator_receipt_settlement_latency: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (multi-instance hosts; refuse to guess).
if [ -z "$PORT" ]; then
  echo "operator_receipt_settlement_latency: --rpc-port is required" >&2
  usage >&2
  exit 1
fi

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_receipt_settlement_latency: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
if [ -n "$LAST" ] && { [ -n "$FROM" ] || [ -n "$TO" ]; }; then
  echo "operator_receipt_settlement_latency: --last cannot be combined with --from / --to" >&2
  exit 1
fi
for v in "$FROM" "$TO" "$LAST"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_receipt_settlement_latency: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST" ] && [ "$LAST" = "0" ]; then
  echo "operator_receipt_settlement_latency: --last must be >= 1" >&2
  exit 1
fi
case "$SETTLE_SLACK" in *[!0-9]*|"")
  echo "operator_receipt_settlement_latency: --settle-budget-slack must be a non-negative integer (got '$SETTLE_SLACK')" >&2
  exit 1 ;;
esac
case "$PEER_SCAN_CAP" in *[!0-9]*|"")
  echo "operator_receipt_settlement_latency: --peer-scan-cap must be a non-negative integer (got '$PEER_SCAN_CAP')" >&2
  exit 1 ;;
esac
case "$BLOCK_TIMEOUT" in *[!0-9]*|"")
  echo "operator_receipt_settlement_latency: --block-timeout must be a positive integer (got '$BLOCK_TIMEOUT')" >&2
  exit 1 ;;
esac
if [ "$BLOCK_TIMEOUT" -lt 1 ]; then
  echo "operator_receipt_settlement_latency: --block-timeout must be >= 1" >&2; exit 1
fi

# Parse + validate --peer-ports (comma-separated). The LOCAL port is
# excluded from the peer set if the operator accidentally includes it
# (a shard cannot be its own cross-shard destination).
PEER_LIST=""
if [ -n "$PEER_PORTS" ]; then
  OLD_IFS="$IFS"; IFS=','
  for p in $PEER_PORTS; do
    p="$(printf '%s' "$p" | tr -d '[:space:]')"
    [ -z "$p" ] && continue
    case "$p" in *[!0-9]*)
      IFS="$OLD_IFS"
      echo "operator_receipt_settlement_latency: --peer-ports entry must be a positive integer (got '$p')" >&2
      exit 1 ;;
    esac
    [ "$p" = "$PORT" ] && continue   # drop the local port
    case " $PEER_LIST " in *" $p "*) : ;; *) PEER_LIST="$PEER_LIST $p" ;; esac
  done
  IFS="$OLD_IFS"
fi
PEER_LIST="$(printf '%s' "$PEER_LIST" | sed 's/^ *//; s/ *$//')"

cd "$(dirname "$0")/.."
source tools/common.sh

# python required for per-block JSON join + percentile math (block JSON is
# too nested to grep usefully; jq can't recompute percentiles cleanly).
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_receipt_settlement_latency: python (or python3) is required for the receipt join" >&2
  exit 1
fi
PY=python; command -v python >/dev/null 2>&1 || PY=python3

# Promote DETERM to an absolute path so python's subprocess.run resolves
# the binary the same on Linux/Mac/Git Bash (matches the pattern in the
# sibling cross-shard scripts).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: probe the LOCAL daemon for shard identity + head ─────────────────
STATUS_JSON=$("$DETERM" status --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_receipt_settlement_latency: RPC error from \`determ status\` (is daemon on port $PORT?)" >&2
  exit 1
}
read MY_SHARD_ID HEIGHT SHARDING_MODE <<EOF
$(printf '%s' "$STATUS_JSON" | "$PY" -c "
import sys, json
try:
    j = json.load(sys.stdin)
    my_shard      = int(j.get('shard_id', 0))
    height        = int(j.get('height', 0))
    prot          = j.get('protections') or {}
    sharding_mode = str(prot.get('sharding_mode', 'unknown'))
    print(my_shard, height, sharding_mode)
except Exception as e:
    sys.stderr.write('parse_failure: ' + str(e) + chr(10))
    sys.exit(1)
")
EOF
if [ -z "${HEIGHT:-}" ]; then
  echo "operator_receipt_settlement_latency: malformed status JSON (port $PORT)" >&2
  exit 1
fi
case "$MY_SHARD_ID" in *[!0-9]*|"") MY_SHARD_ID=0 ;; esac
case "$HEIGHT" in *[!0-9]*|"") echo "operator_receipt_settlement_latency: malformed status height" >&2; exit 1 ;; esac

# Highest finalized index on the local shard = height − 1.
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))

# Resolve source-window bounds. Precedence: --last > (--from / --to) > defaults.
if [ -n "$LAST" ]; then
  if [ "$LAST" -gt $(( TOP + 1 )) ]; then FROM=0; else FROM=$(( TOP - LAST + 1 )); fi
  TO=$TOP
else
  if [ -z "$TO" ];   then TO=$TOP; fi
  if [ -z "$FROM" ]; then
    if [ "$TOP" -ge 255 ]; then FROM=$(( TOP - 255 )); else FROM=0; fi
  fi
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_receipt_settlement_latency: --to ($TO) < --from ($FROM); nothing to profile" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

PEER_COUNT=0
if [ -n "$PEER_LIST" ]; then
  PEER_COUNT=$(printf '%s\n' $PEER_LIST | grep -c . || true)
  case "$PEER_COUNT" in *[!0-9]*|"") PEER_COUNT=0 ;; esac
fi
MODE="single"; [ "$PEER_COUNT" -gt 0 ] && MODE="fleet"

# ── Short-circuit: empty chain ───────────────────────────────────────────────
if [ "$HEIGHT" -eq 0 ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"mode":"%s","my_shard_id":%s,"sharding_mode":"%s","source_window":{"from":%s,"to":%s,"blocks":0},"peer_ports":[],"emitted_count":0,"settled_count":0,"unsettled_count":0,"latency":null,"by_destination":[],"slow_settlements":[],"unsettled_overdue":[],"anomalies":[],"rpc_port":%s,"info":"empty_chain"}\n' \
      "$MODE" "$MY_SHARD_ID" "$SHARDING_MODE" "$FROM" "$TO" "$PORT"
  else
    echo "operator_receipt_settlement_latency: chain has no finalized blocks yet (height=0, port $PORT)"
  fi
  exit 0
fi

# ── Short-circuit: single-shard deployment ───────────────────────────────────
if [ "$SHARDING_MODE" = "none" ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"mode":"%s","my_shard_id":%s,"sharding_mode":"none","source_window":{"from":%s,"to":%s,"blocks":%s},"peer_ports":[],"emitted_count":0,"settled_count":0,"unsettled_count":0,"latency":null,"by_destination":[],"slow_settlements":[],"unsettled_overdue":[],"anomalies":[],"rpc_port":%s,"info":"single_shard_deployment"}\n' \
      "$MODE" "$MY_SHARD_ID" "$FROM" "$TO" "$WIN_BLOCKS" "$PORT"
  else
    echo "INFO: single-shard deployment — no cross-shard settlement by construction"
    echo "      sharding_mode=none, my_shard_id=$MY_SHARD_ID, port $PORT"
  fi
  exit 0
fi

# ── Step 2: Python-driven walk + join + distribution + render ────────────────
# Source leg: walk local [FROM..TO] for cross_shard_receipts[] emitted by
# THIS shard. Destination legs: for each peer port, walk genesis-to-tip
# (capped) for inbound_receipts[]. Join on (src_shard, src_block_index,
# tx_hash); settlement latency = apply_block_index − src_block_index.
TMP_OUT=$(mktemp) || {
  echo "operator_receipt_settlement_latency: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

"$PY" - \
  "$DETERM_ABS" "$PORT" \
  "$FROM" "$TO" "$MY_SHARD_ID" \
  "$SETTLE_SLACK" "$PEER_SCAN_CAP" "$BLOCK_TIMEOUT" \
  "$TMP_OUT" "$PEER_LIST" <<'PY'
import json, subprocess, sys
from collections import defaultdict

(determ, port,
 from_s, to_s, my_shard_id_s,
 slack_s, peer_cap_s, block_timeout_s,
 out_path, peer_list_s) = sys.argv[1:11]

from_h        = int(from_s)
to_h          = int(to_s)
my_shard_id   = int(my_shard_id_s)
slack         = int(slack_s)
peer_cap      = int(peer_cap_s)
block_timeout = int(block_timeout_s)
peer_ports    = [int(p) for p in peer_list_s.split() if p.strip()]

CROSS_SHARD_RECEIPT_LATENCY = 3   # src/node/node.cpp
budget = CROSS_SHARD_RECEIPT_LATENCY + slack

def die(msg, code=1):
    sys.stderr.write(f"operator_receipt_settlement_latency: {msg}\n")
    sys.exit(code)

def block_info(p, h):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", str(p)],
            capture_output=True, text=True, timeout=block_timeout,
        )
    except subprocess.TimeoutExpired:
        die(f"block-info {h} (port {p}) timed out after {block_timeout}s")
    except Exception as e:
        die(f"block-info {h} (port {p}) failed: {e}")
    if r.returncode != 0:
        die(f"block-info {h} (port {p}) rc={r.returncode}\n{r.stderr}")
    try:
        blk = json.loads(r.stdout)
    except Exception:
        die(f"block-info {h} (port {p}) returned non-JSON")
    return blk if isinstance(blk, dict) else None

def head_top(p):
    # Highest finalized index on shard at port p = height − 1.
    try:
        r = subprocess.run(
            [determ, "head", "--field", "height", "--rpc-port", str(p)],
            capture_output=True, text=True, timeout=block_timeout,
        )
    except Exception as e:
        die(f"head (port {p}) failed: {e}")
    if r.returncode != 0:
        die(f"head (port {p}) rc={r.returncode}\n{r.stderr}")
    s = (r.stdout or "").strip()
    if not s.isdigit():
        die(f"head (port {p}) returned non-numeric '{s}'")
    h = int(s)
    return (h - 1) if h > 0 else 0, h

# ── Source leg: emitted receipts on the local shard ───────────────────────────
# emitted[key] = receipt record. key = (src_shard, src_block_index, tx_hash).
emitted = {}
emitted_by_dst = defaultdict(lambda: {"emitted": 0, "settled": 0,
                                      "unsettled": 0, "latencies": []})
for h in range(from_h, to_h + 1):
    blk = block_info(port, h)
    if blk is None:
        continue
    for o in (blk.get("cross_shard_receipts") or []):
        if not isinstance(o, dict):
            continue
        src   = int(o.get("src_shard", my_shard_id))
        # Only profile receipts THIS shard actually emitted. (A correct
        # producer only ever writes cross_shard_receipts[] with
        # src_shard == my_shard_id, but guard defensively.)
        if src != my_shard_id:
            continue
        dst   = int(o.get("dst_shard", 0))
        sbidx = int(o.get("src_block_index", h))
        thash = str(o.get("tx_hash", ""))
        amt   = int(o.get("amount", 0))
        key = (src, sbidx, thash)
        # Dedup identical keys (shouldn't recur within finalized blocks).
        if key in emitted:
            continue
        emitted[key] = {
            "src_shard":       src,
            "dst_shard":       dst,
            "src_block_index": sbidx,
            "tx_hash":         thash,
            "amount":          amt,
            "settled":         False,
            "apply_index":     None,
            "apply_port":      None,
            "latency":         None,
        }
        emitted_by_dst[dst]["emitted"] += 1

emitted_count = len(emitted)

# ── Destination legs: walk each peer port for matching inbound_receipts[] ─────
# We record the FIRST apply index seen per key (a correct chain applies a
# given receipt exactly once — the dedup set enforces it — but if a stale
# duplicate ever appeared we keep the earliest, which is the real settle).
peer_tips = {}
for p in peer_ports:
    tip, height = head_top(p)
    peer_tips[p] = tip
    if height <= 0:
        continue
    lo = 0
    if peer_cap > 0 and (tip + 1) > peer_cap:
        lo = tip - peer_cap + 1
    for h in range(lo, tip + 1):
        blk = block_info(p, h)
        if blk is None:
            continue
        for ib in (blk.get("inbound_receipts") or []):
            if not isinstance(ib, dict):
                continue
            src   = int(ib.get("src_shard", 0))
            sbidx = int(ib.get("src_block_index", 0))
            thash = str(ib.get("tx_hash", ""))
            key = (src, sbidx, thash)
            rec = emitted.get(key)
            if rec is None:
                continue   # not one of OUR emitted receipts in the window
            if rec["settled"] and rec["apply_index"] is not None \
               and h >= rec["apply_index"]:
                continue   # keep earliest apply
            rec["settled"]     = True
            rec["apply_index"] = h
            rec["apply_port"]  = p
            rec["latency"]     = h - rec["src_block_index"]

# ── Classify + build distribution ─────────────────────────────────────────────
settled_count   = 0
unsettled_count = 0
latencies       = []
slow_settlements = []
unsettled_overdue = []
negative_latency = []

for rec in emitted.values():
    dst = rec["dst_shard"]
    if rec["settled"]:
        settled_count += 1
        lat = rec["latency"]
        latencies.append(lat)
        emitted_by_dst[dst]["settled"] += 1
        emitted_by_dst[dst]["latencies"].append(lat)
        if lat < 0:
            negative_latency.append({
                "tx_hash":         rec["tx_hash"],
                "src_block_index": rec["src_block_index"],
                "dst_shard":       dst,
                "apply_index":     rec["apply_index"],
                "latency":         lat,
            })
        elif lat > budget:
            slow_settlements.append({
                "tx_hash":         rec["tx_hash"],
                "src_block_index": rec["src_block_index"],
                "dst_shard":       dst,
                "apply_index":     rec["apply_index"],
                "latency":         lat,
            })
    else:
        unsettled_count += 1
        emitted_by_dst[dst]["unsettled"] += 1
        # Overdue only when we actually queried the destination shard
        # (so we can see its tip) AND enough blocks have elapsed there.
        # peer_tips maps a PORT to a tip, but receipts are keyed by
        # dst_SHARD, not port — we don't have a shard→port map over RPC.
        # The conservative, correct rule: a receipt is "overdue" only if
        # SOME queried destination shard's tip is far enough past the
        # src_block_index AND the receipt was never found there. We use
        # the max queried tip as the most-advanced destination clock.
        if peer_tips:
            max_tip = max(peer_tips.values())
            age = max_tip - rec["src_block_index"]
            if age > budget:
                unsettled_overdue.append({
                    "tx_hash":         rec["tx_hash"],
                    "src_block_index": rec["src_block_index"],
                    "dst_shard":       dst,
                    "age":             age,
                })

def pct(sorted_vals, q):
    if not sorted_vals:
        return None
    # Nearest-rank percentile (no interpolation) — integer block counts.
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    import math
    rank = max(1, math.ceil(q / 100.0 * len(sorted_vals)))
    return sorted_vals[min(rank, len(sorted_vals)) - 1]

latency_stats = None
if latencies:
    s = sorted(latencies)
    latency_stats = {
        "min":  s[0],
        "p50":  pct(s, 50),
        "p95":  pct(s, 95),
        "max":  s[-1],
        "mean": sum(s) // len(s),
    }

# Per-destination summary (sorted by emitted DESC, then shard ASC).
by_destination = []
for dst in sorted(emitted_by_dst.keys(),
                  key=lambda d: (-emitted_by_dst[d]["emitted"], d)):
    agg = emitted_by_dst[dst]
    p50 = None
    if agg["latencies"]:
        ss = sorted(agg["latencies"])
        p50 = pct(ss, 50)
    by_destination.append({
        "shard":       dst,
        "emitted":     agg["emitted"],
        "settled":     agg["settled"],
        "unsettled":   agg["unsettled"],
        "p50_latency": p50,
    })

# Cap rosters so the renderer + JSON stay bounded.
slow_settlements.sort(key=lambda r: -r["latency"])
unsettled_overdue.sort(key=lambda r: -r["age"])

result = {
    "emitted_count":     emitted_count,
    "settled_count":     settled_count,
    "unsettled_count":   unsettled_count,
    "latency":           latency_stats,
    "by_destination":    by_destination,
    "slow_settlements":  slow_settlements[:50],
    "unsettled_overdue": unsettled_overdue[:50],
    "negative_latency":  negative_latency[:50],
    "budget":            budget,
    "peer_tips":         {str(k): v for k, v in peer_tips.items()},
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_receipt_settlement_latency: source/destination walk failed" >&2
  exit 1
fi

WALK_JSON=$(cat "$TMP_OUT")

# Pull scalars back out for the anomaly gate + shell-side reporting.
read EMITTED SETTLED UNSETTLED SLOW_N OVERDUE_N NEG_N BUDGET <<EOF
$(printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
w = json.load(sys.stdin)
print(w['emitted_count'], w['settled_count'], w['unsettled_count'],
      len(w['slow_settlements']), len(w['unsettled_overdue']),
      len(w['negative_latency']), w['budget'])
")
EOF
for v in EMITTED SETTLED UNSETTLED SLOW_N OVERDUE_N NEG_N BUDGET; do
  eval "val=\$$v"
  case "$val" in *[!0-9]*|"") eval "$v=0" ;; esac
done

# ── Step 3: collect anomalies ─────────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
[ "$OVERDUE_N" -gt 0 ] && add_anom "receipts_unsettled_overdue"
[ "$SLOW_N"    -gt 0 ] && add_anom "settlement_latency_high"
[ "$NEG_N"     -gt 0 ] && add_anom "settled_before_emit"

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 4: render ────────────────────────────────────────────────────────────
PEER_PORTS_JSON="[]"
if [ -n "$PEER_LIST" ]; then
  PEER_PORTS_JSON=$(printf '%s\n' $PEER_LIST | "$PY" -c "
import sys, json
print(json.dumps([int(x) for x in sys.stdin.read().split()]))
")
fi

if [ "$JSON_OUT" = "1" ]; then
  "$PY" - "$WALK_JSON" "$MODE" "$MY_SHARD_ID" "$SHARDING_MODE" \
        "$FROM" "$TO" "$WIN_BLOCKS" "$PEER_PORTS_JSON" "$ANOMALIES" "$PORT" <<'PY'
import json, sys
walk = json.loads(sys.argv[1])
envelope = {
    "mode":            sys.argv[2],
    "my_shard_id":     int(sys.argv[3]),
    "sharding_mode":   sys.argv[4],
    "source_window":   {"from": int(sys.argv[5]),
                        "to":   int(sys.argv[6]),
                        "blocks": int(sys.argv[7])},
    "peer_ports":      json.loads(sys.argv[8]),
    "emitted_count":   walk["emitted_count"],
    "settled_count":   walk["settled_count"],
    "unsettled_count": walk["unsettled_count"],
    "latency":         walk["latency"],
    "by_destination":  walk["by_destination"],
    "slow_settlements":   walk["slow_settlements"],
    "unsettled_overdue":  walk["unsettled_overdue"],
    "settled_before_emit": walk["negative_latency"],
    "budget":          walk["budget"],
    "anomalies":       ([a for a in sys.argv[9].split(",") if a]
                        if sys.argv[9] else []),
    "rpc_port":        int(sys.argv[10]),
}
print(json.dumps(envelope))
PY
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_receipt_settlement_latency: no anomalies (port $PORT, shard $MY_SHARD_ID, source window [$FROM..$TO], $EMITTED emitted, $SETTLED settled)"
  else
    echo "=== Cross-shard receipt settlement latency (port $PORT, shard $MY_SHARD_ID) ==="
    echo "Sharding mode: $SHARDING_MODE; mode: $MODE; settle budget: CROSS_SHARD_RECEIPT_LATENCY(3) + slack = $BUDGET blocks"
    if [ "$MODE" = "single" ]; then
      echo "[INFO] No --peer-ports supplied — destination apply side not visible."
      echo "       Reporting emitted-receipt inventory only; latency requires the destination shards' ports."
    else
      echo "Destination shard ports queried: $PEER_LIST"
    fi
    echo "Source window: blocks [$FROM..$TO] ($WIN_BLOCKS blocks)"
    echo "Emitted receipts: $EMITTED    Settled: $SETTLED    Unsettled: $UNSETTLED"

    if [ "$ANOM_ONLY" != "1" ]; then
      # Latency distribution.
      printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
w = json.load(sys.stdin)
lat = w['latency']
if lat is None:
    print('Latency distribution: (no settled receipts in window)')
else:
    print(f\"Latency distribution (blocks, settled receipts): min={lat['min']} p50={lat['p50']} p95={lat['p95']} max={lat['max']} mean={lat['mean']}\")
"
      # Per-destination table.
      printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
w = json.load(sys.stdin)
bd = w['by_destination']
if bd:
    print('Per-destination shard (top 10):')
    for r in bd[:10]:
        p50 = r['p50_latency']
        p50s = f'{p50}' if p50 is not None else '-'
        print(f\"  dst shard {r['shard']}: emitted={r['emitted']} settled={r['settled']} unsettled={r['unsettled']} p50_latency={p50s}\")
else:
    print('Per-destination shard: (no emitted receipts in window)')
"
    fi

    # Anomaly diagnostics.
    if [ "$OVERDUE_N" -gt 0 ]; then
      echo "Unsettled-overdue check: TRIPPED — $OVERDUE_N emitted receipt(s) past budget on the most-advanced destination tip (top 5):"
      printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
for r in json.load(sys.stdin)['unsettled_overdue'][:5]:
    th = r['tx_hash']; th = th[:16] + '...' if len(th) > 16 else th
    print(f\"  overdue: dst_shard={r['dst_shard']} src_block={r['src_block_index']} age={r['age']} tx={th}\")
"
    elif [ "$UNSETTLED" -gt 0 ] && [ "$MODE" = "single" ]; then
      echo "Unsettled-overdue check: not checkable ($UNSETTLED unsettled, but no --peer-ports to see the destination apply side)"
    else
      echo "Unsettled-overdue check: OK (no overdue unsettled receipts)"
    fi

    if [ "$SLOW_N" -gt 0 ]; then
      echo "Slow-settlement check: $SLOW_N settled receipt(s) exceeded the $BUDGET-block budget (top 5):"
      printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
for r in json.load(sys.stdin)['slow_settlements'][:5]:
    th = r['tx_hash']; th = th[:16] + '...' if len(th) > 16 else th
    print(f\"  slow: dst_shard={r['dst_shard']} src_block={r['src_block_index']} apply_block={r['apply_index']} latency={r['latency']} tx={th}\")
"
    else
      echo "Slow-settlement check: OK (all settled receipts within budget)"
    fi

    if [ "$NEG_N" -gt 0 ]; then
      echo "Apply-before-emit check: CATASTROPHIC — $NEG_N settled receipt(s) applied at an index BEFORE the source emit (mismatched chains / index corruption):"
      printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
for r in json.load(sys.stdin)['negative_latency'][:5]:
    th = r['tx_hash']; th = th[:16] + '...' if len(th) > 16 else th
    print(f\"  apply<emit: dst_shard={r['dst_shard']} src_block={r['src_block_index']} apply_block={r['apply_index']} latency={r['latency']} tx={th}\")
"
    else
      echo "Apply-before-emit check: OK (no negative-latency settlements)"
    fi

    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] cross-shard settlement healthy"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
    fi
  fi
fi

# ── Step 5: exit-code policy ─────────────────────────────────────────────────
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
