#!/usr/bin/env bash
# operator_cross_shard_health.sh — Cross-shard receipt + outbound queue
# health audit. Walks a window of finalized blocks and surfaces:
#
#   - per-block outbound-emitted CrossShardReceipt counts
#     (Block::cross_shard_receipts; see src/chain/block.cpp::Block::to_json)
#   - per-block inbound-applied CrossShardReceipt counts
#     (Block::inbound_receipts; same source)
#   - per-source-shard outbound totals (count + cumulative amount)
#   - per-destination-shard inbound totals (count + cumulative amount)
#   - status.pending_inbound_receipts (current pool depth — receipts that
#     were gossiped to this shard but haven't yet been baked into a block;
#     see src/node/node.cpp::rpc_status)
#
# Scope contrast vs. neighbouring scripts:
#   operator_receipt_audit.sh   — FA7 dedup-set health (no duplicate
#                                 (src_shard, tx_hash) within the window)
#                                 + A1 accumulated_inbound delta sanity
#                                 + per-shard credit/debit volume table.
#   operator_cross_shard_health.sh THIS — pool-depth + apply-lag oriented:
#                                 surfaces the live pending pool depth,
#                                 a per-block emit/apply trace, and the
#                                 "inbound admitted but not yet applied
#                                 within CROSS_SHARD_RECEIPT_LATENCY +
#                                 slack" anomaly. Designed as the
#                                 "is the cross-shard pipeline flowing?"
#                                 operator-on-call probe.
#
# Read-only RPCs only; safe against any running daemon.
#
# IMPORTANT — single-shard deployments: this script is only meaningful on
# multi-shard chains. On single-shard chains (sharding_mode == "none"),
# all per-block metrics are trivially 0 by construction (no cross-shard
# routing is possible), so the script short-circuits to a single INFO
# line and exits 0. The pending pool depth, outbound emit count, inbound
# apply count, and apply-lag anomaly are all guaranteed-zero in that case.
#
# Apply-lag semantics (S-016 Option 2):
#   src/node/node.cpp::CROSS_SHARD_RECEIPT_LATENCY = 3 blocks of
#   admission soak between local first-observation and inclusion in a
#   produced block (gossip propagation headroom). A receipt that's
#   admitted to pending_inbound_receipts_ but hasn't applied for more
#   than (latency + slack) blocks indicates either a stalled local
#   producer or a producer that's repeatedly aborting before including
#   the bundle. Threshold here: latency + 10-block slack (configurable
#   via --apply-lag-slack).
#
# Anomalies (any fires → exit 2 in --anomalies-only mode):
#   inbound_pending_backlog       status.pending_inbound_receipts >
#                                 --pending-backlog-threshold (default
#                                 100; gossip-propagation backlog signal)
#   outbound_destination_mismatch outbound-by-source-shard total over
#                                 the window doesn't sum to the local
#                                 outbound-cumulative delta — only
#                                 verifiable when window covers genesis-
#                                 to-head; otherwise reported as info
#                                 (see "subset-window caveats" below)
#   receipt_apply_lag             pending receipts older than
#                                 CROSS_SHARD_RECEIPT_LATENCY + slack
#                                 (i.e., should have applied by now)
#   inbound_replay_attempt        duplicate (src_shard, src_block_index,
#                                 tx_hash) inside the window's
#                                 inbound_receipts. The applied_inbound
#                                 dedup set rejects these at apply time,
#                                 so a hit here means a finalized block
#                                 contains the replay — this should
#                                 ALWAYS be 0; non-zero is catastrophic
#                                 (FA7 dedup-set bypass).
#
# Subset-window caveats:
#   - inbound_pending_backlog is a live snapshot, NOT bound to the
#     window; it always reflects current pool state.
#   - outbound_destination_mismatch is only checked when the window
#     covers genesis-to-head (from=0, to=head). For strict-subset
#     windows the per-shard breakdown is still emitted but the
#     anomaly is suppressed.
#   - receipt_apply_lag is also a live-snapshot anomaly (the receipt
#     ages we measure are from the LOCAL first-seen → current head
#     comparison; not the historical window).
#
# Usage:
#   tools/operator_cross_shard_health.sh --rpc-port N
#                                        [--from H] [--to H] [--last N]
#                                        [--pending-backlog-threshold N]
#                                        [--apply-lag-slack N]
#                                        [--anomalies-only] [--json]
#
# Defaults:
#   --from / --to / --last        last 256 blocks ending at head
#   --pending-backlog-threshold   100
#   --apply-lag-slack             10  (so receipt-apply-lag fires when
#                                       a pending receipt's local age
#                                       exceeds 3 + 10 = 13 blocks)
#
# --json shape:
#   {"my_shard_id":N, "shard_count":N, "shard_count_source":"inferred|override",
#    "sharding_mode":"none|current|extended",
#    "window":{"from":H,"to":H,"blocks":N},
#    "pending_inbound_receipts": N,
#    "per_block": [{"index":H,"outbound":N,"inbound":N,"outbound_amount":N,"inbound_amount":N}, ...],
#    "by_source":      [{"shard":N,"count":N,"total":N}, ...],
#    "by_destination": [{"shard":N,"count":N,"total":N}, ...],
#    "totals":{"outbound_count":N,"outbound_total":N,
#              "inbound_count":N,"inbound_total":N},
#    "replay_pairs":[{"src_shard":N,"src_block_index":H,"tx_hash":"..."}, ...],
#    "anomalies":[...], "rpc_port":N}
#
# Exit codes:
#   0   healthy (no anomalies, or default informational mode)
#   1   RPC error / bad args / malformed response
#   2   --anomalies-only AND >=1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_cross_shard_health.sh --rpc-port N
                                      [--from H] [--to H] [--last N]
                                      [--pending-backlog-threshold N]
                                      [--apply-lag-slack N]
                                      [--anomalies-only] [--json]

Cross-shard receipt + outbound queue health audit. Walks a window of
finalized blocks; reports per-block outbound/inbound CrossShardReceipt
emit + apply counts, per-shard breakdowns, current pending-pool depth,
and apply-lag / replay anomalies.

NOTE: meaningful only on multi-shard deployments. On sharding_mode=none
every cross-shard metric is trivially 0 — the script exits 0 with an
INFO line.

Options:
  --rpc-port N                  RPC port to query (REQUIRED)
  --from H                      Lower window bound, inclusive (default:
                                max(0, head - 256 + 1))
  --to H                        Upper window bound, inclusive (default:
                                current head)
  --last N                      Shorthand for [head-N+1, head]
                                (mutually exclusive with --from / --to)
  --pending-backlog-threshold N inbound_pending_backlog fires if
                                status.pending_inbound_receipts > N
                                (default: 100)
  --apply-lag-slack N           receipt_apply_lag fires if a pending
                                receipt's local age (head - first_seen)
                                exceeds CROSS_SHARD_RECEIPT_LATENCY (3)
                                + N (default: 10)
  --anomalies-only              Print only flagged anomalies; exit 2 if
                                any fire
  --json                        Emit structured JSON envelope
  -h, --help                    Show this help

Anomaly flags:
  inbound_pending_backlog       pending pool > threshold (slow gossip)
  outbound_destination_mismatch only checked when window=genesis-to-head:
                                window's outbound sum != chain's
                                accumulated_outbound at head
  receipt_apply_lag             pending receipts older than
                                CROSS_SHARD_RECEIPT_LATENCY + slack
  inbound_replay_attempt        duplicate (src_shard, src_block_index,
                                tx_hash) in finalized blocks — should
                                ALWAYS be 0; non-zero is catastrophic

Exit codes:
  0   healthy (or single-shard deployment)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND >=1 anomaly fired
EOF
}

PORT=""
FROM=""
TO=""
LAST=""
PENDING_BACKLOG_THRESHOLD=100
APPLY_LAG_SLACK=10
ANOM_ONLY=0
JSON_OUT=0

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                       usage; exit 0 ;;
    --rpc-port)                      PORT="${2:-}";                       shift 2 ;;
    --from)                          FROM="${2:-}";                       shift 2 ;;
    --to)                            TO="${2:-}";                         shift 2 ;;
    --last)                          LAST="${2:-}";                       shift 2 ;;
    --pending-backlog-threshold)     PENDING_BACKLOG_THRESHOLD="${2:-}";  shift 2 ;;
    --apply-lag-slack)               APPLY_LAG_SLACK="${2:-}";            shift 2 ;;
    --anomalies-only)                ANOM_ONLY=1;                         shift ;;
    --json)                          JSON_OUT=1;                          shift ;;
    *) echo "operator_cross_shard_health: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (multi-instance hosts; refuse to guess).
if [ -z "$PORT" ]; then
  echo "operator_cross_shard_health: --rpc-port is required" >&2
  usage >&2
  exit 1
fi

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_cross_shard_health: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
if [ -n "$LAST" ] && { [ -n "$FROM" ] || [ -n "$TO" ]; }; then
  echo "operator_cross_shard_health: --last cannot be combined with --from / --to" >&2
  exit 1
fi
for v in "$FROM" "$TO" "$LAST"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_cross_shard_health: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST" ] && [ "$LAST" = "0" ]; then
  echo "operator_cross_shard_health: --last must be >= 1" >&2
  exit 1
fi
case "$PENDING_BACKLOG_THRESHOLD" in *[!0-9]*|"")
  echo "operator_cross_shard_health: --pending-backlog-threshold must be a non-negative integer (got '$PENDING_BACKLOG_THRESHOLD')" >&2
  exit 1 ;;
esac
case "$APPLY_LAG_SLACK" in *[!0-9]*|"")
  echo "operator_cross_shard_health: --apply-lag-slack must be a non-negative integer (got '$APPLY_LAG_SLACK')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# python required for per-block JSON aggregation (Block::to_json is too
# nested to grep usefully and we can't lean on jq because the inbound /
# outbound arrays contain hex strings + nested objects).
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_cross_shard_health: python is required for per-block aggregation" >&2
  exit 1
fi
PY=python; command -v python >/dev/null 2>&1 || PY=python3

# Promote DETERM to an absolute path so python's subprocess.run resolves
# the binary the same on Linux/Mac/Git Bash (matches the pattern used in
# operator_dapp_inventory.sh and operator_block_inclusion_audit.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: probe daemon for shard config + chain head ────────────────────────
STATUS_JSON=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_cross_shard_health: RPC error from \`determ status\` (is daemon on port $PORT?)" >&2
  exit 1
}

# Extract status fields via python (no jq dependency).
read MY_SHARD_ID HEIGHT PENDING_INBOUND SHARDING_MODE <<EOF
$(printf '%s' "$STATUS_JSON" | "$PY" -c "
import sys, json
try:
    j = json.load(sys.stdin)
    my_shard       = int(j.get('shard_id', 0))
    height         = int(j.get('height', 0))
    pending        = int(j.get('pending_inbound_receipts', 0))
    prot           = j.get('protections') or {}
    sharding_mode  = str(prot.get('sharding_mode', 'unknown'))
    print(my_shard, height, pending, sharding_mode)
except Exception as e:
    sys.stderr.write('parse_failure: ' + str(e) + chr(10))
    sys.exit(1)
")
EOF
if [ -z "${HEIGHT:-}" ]; then
  echo "operator_cross_shard_health: malformed status JSON (port $PORT)" >&2
  exit 1
fi

# Highest finalized index = height - 1 (height is the NEXT-to-produce slot).
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))

# Resolve window bounds. Precedence: --last > (--from / --to) > defaults.
if [ -n "$LAST" ]; then
  if [ "$LAST" -gt $(( TOP + 1 )) ]; then
    FROM=0
  else
    FROM=$(( TOP - LAST + 1 ))
  fi
  TO=$TOP
else
  if [ -z "$TO" ];   then TO=$TOP; fi
  if [ -z "$FROM" ]; then
    if [ "$TOP" -ge 255 ]; then FROM=$(( TOP - 255 )); else FROM=0; fi
  fi
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_cross_shard_health: --to ($TO) < --from ($FROM); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Short-circuit: empty chain ───────────────────────────────────────────────
if [ "$HEIGHT" -eq 0 ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"my_shard_id":%s,"shard_count":1,"shard_count_source":"inferred","sharding_mode":"%s","window":{"from":%s,"to":%s,"blocks":0},"pending_inbound_receipts":%s,"per_block":[],"by_source":[],"by_destination":[],"totals":{"outbound_count":0,"outbound_total":0,"inbound_count":0,"inbound_total":0},"replay_pairs":[],"anomalies":[],"rpc_port":%s,"info":"empty_chain"}\n' \
      "$MY_SHARD_ID" "$SHARDING_MODE" "$FROM" "$TO" "$PENDING_INBOUND" "$PORT"
  else
    echo "operator_cross_shard_health: chain has no finalized blocks yet (height=0, port $PORT)"
  fi
  exit 0
fi

# ── Short-circuit: single-shard deployment ────────────────────────────────────
# sharding_mode == "none" guarantees shard_count = 1 by genesis construction.
# No cross-shard traffic is possible; emit the documented INFO line.
if [ "$SHARDING_MODE" = "none" ]; then
  # Still surface the pending pool depth (should be 0) so an operator can
  # confirm at-a-glance that this script is appropriate-and-trivial here.
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"my_shard_id":%s,"shard_count":1,"shard_count_source":"inferred","sharding_mode":"none","window":{"from":%s,"to":%s,"blocks":%s},"pending_inbound_receipts":%s,"per_block":[],"by_source":[],"by_destination":[],"totals":{"outbound_count":0,"outbound_total":0,"inbound_count":0,"inbound_total":0},"replay_pairs":[],"anomalies":[],"rpc_port":%s,"info":"single_shard_deployment"}\n' \
      "$MY_SHARD_ID" "$FROM" "$TO" "$WIN_BLOCKS" "$PENDING_INBOUND" "$PORT"
  else
    echo "INFO: single-shard deployment — no cross-shard activity by construction"
    echo "      sharding_mode=none, my_shard_id=$MY_SHARD_ID, pending_inbound_receipts=$PENDING_INBOUND, port $PORT"
  fi
  exit 0
fi

# ── Step 2: pull chain-summary once for accumulated_outbound at head ─────────
# Only used for the outbound_destination_mismatch gate (genesis-to-head
# windows only).
CS_JSON=$("$DETERM" chain-summary --last 1 --rpc-port "$PORT" 2>/dev/null) || CS_JSON='{}'
ACCUM_OUTBOUND_HEAD=$(printf '%s' "$CS_JSON" | "$PY" -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print(int(j.get('accumulated_outbound', 0)))
except Exception:
    print(0)
")
case "$ACCUM_OUTBOUND_HEAD" in *[!0-9]*|"") ACCUM_OUTBOUND_HEAD=0 ;; esac

# ── Step 3: walk window via block-info --json + aggregate ────────────────────
TMP_OUT=$(mktemp) || {
  echo "operator_cross_shard_health: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

"$PY" - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$MY_SHARD_ID" "$TMP_OUT" <<'PY'
import json, subprocess, sys
from collections import defaultdict

determ, port, from_h, to_h, my_shard_id, out_path = sys.argv[1:7]
from_h = int(from_h); to_h = int(to_h); my_shard_id = int(my_shard_id)

# Per-shard outbound: source-shard -> (count, total_amount).
# Source-side: every outbound receipt this shard emits is keyed by
# src_shard=my_shard_id (CrossShardReceipt::src_shard); we keep the
# per-source-shard map symmetric with inbound for cross-fleet aggregation
# (an operator running a different shard's daemon will see different
# rows here).
out_count_by_src = defaultdict(int)
out_total_by_src = defaultdict(int)
# Per-shard inbound: destination-shard -> (count, total_amount).
# All inbound seen on this node has dst_shard == my_shard_id by
# construction (filtered in on_cross_shard_receipt_bundle).
in_count_by_dst = defaultdict(int)
in_total_by_dst = defaultdict(int)

# Replay detection: (src_shard, src_block_index, tx_hash) tuple appearing
# twice anywhere in this window's inbound_receipts. The apply path's
# applied_inbound dedup set rejects these at apply time, so a hit here
# means a finalized block contains the duplicate — catastrophic.
seen_inbound = set()
replay_pairs = []
# Per-block trace.
per_block = []
max_shard_observed = my_shard_id
totals = {"outbound_count": 0, "outbound_total": 0,
          "inbound_count":  0, "inbound_total":  0}

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_cross_shard_health: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_cross_shard_health: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_cross_shard_health: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    # Outbound emitted by THIS shard in this block. Per
    # producer.cpp B3.2 the producer iterates TRANSFER txs and emits a
    # CrossShardReceipt for each cross-shard destination.
    csrs = blk.get("cross_shard_receipts") or []
    ob_count = len(csrs); ob_total = 0
    for o in csrs:
        src = int(o.get("src_shard", 0))
        dst = int(o.get("dst_shard", 0))
        amt = int(o.get("amount", 0))
        ob_total += amt
        out_count_by_src[src] += 1
        out_total_by_src[src] += amt
        if src > max_shard_observed: max_shard_observed = src
        if dst > max_shard_observed: max_shard_observed = dst

    # Inbound applied on THIS shard in this block. Per
    # chain.cpp::apply_block::apply_inbound_receipts each one credits
    # `to` and bumps accumulated_inbound.
    ibrs = blk.get("inbound_receipts") or []
    ib_count = len(ibrs); ib_total = 0
    for ib in ibrs:
        src   = int(ib.get("src_shard", 0))
        dst   = int(ib.get("dst_shard", 0))
        sbidx = int(ib.get("src_block_index", 0))
        thash = str(ib.get("tx_hash", ""))
        amt   = int(ib.get("amount", 0))
        ib_total += amt
        in_count_by_dst[dst] += 1
        in_total_by_dst[dst] += amt
        if src > max_shard_observed: max_shard_observed = src
        if dst > max_shard_observed: max_shard_observed = dst
        key = (src, sbidx, thash)
        if key in seen_inbound:
            replay_pairs.append({
                "src_shard":       src,
                "src_block_index": sbidx,
                "tx_hash":         thash,
            })
        else:
            seen_inbound.add(key)

    totals["outbound_count"] += ob_count
    totals["outbound_total"] += ob_total
    totals["inbound_count"]  += ib_count
    totals["inbound_total"]  += ib_total

    # Only emit per-block rows that actually have activity — for a 256-
    # block window on a chain doing 1 cross-shard tx/min this keeps the
    # default trace concise. Operators wanting the raw matrix use --json.
    if ob_count > 0 or ib_count > 0:
        per_block.append({
            "index":           h,
            "outbound":        ob_count,
            "inbound":         ib_count,
            "outbound_amount": ob_total,
            "inbound_amount":  ib_total,
        })

def sort_breakdown(count_d, total_d):
    keys = sorted(count_d.keys(),
                  key=lambda k: (-total_d[k], -count_d[k], k))
    return [{"shard": k, "count": count_d[k], "total": total_d[k]} for k in keys]

result = {
    "totals":              totals,
    "per_block":           per_block,
    "by_source":           sort_breakdown(out_count_by_src, out_total_by_src),
    "by_destination":      sort_breakdown(in_count_by_dst,  in_total_by_dst),
    "replay_pairs":        replay_pairs,
    "max_shard_observed":  max_shard_observed,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_cross_shard_health: block-walk failed" >&2
  exit 1
fi

WALK_JSON=$(cat "$TMP_OUT")

# Pull aggregate scalars back out of the aggregator JSON.
OUTBOUND_COUNT=$(printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
print(int(json.load(sys.stdin)['totals']['outbound_count']))
")
OUTBOUND_TOTAL=$(printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
print(int(json.load(sys.stdin)['totals']['outbound_total']))
")
INBOUND_COUNT=$(printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
print(int(json.load(sys.stdin)['totals']['inbound_count']))
")
INBOUND_TOTAL=$(printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
print(int(json.load(sys.stdin)['totals']['inbound_total']))
")
REPLAY_COUNT=$(printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
print(len(json.load(sys.stdin)['replay_pairs']))
")
MAX_SHARD_OBS=$(printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
print(int(json.load(sys.stdin)['max_shard_observed']))
")

# Infer shard_count from observed shards (+ this shard).
SHARD_COUNT=$(( MAX_SHARD_OBS + 1 ))
if [ "$SHARD_COUNT" -lt 1 ]; then SHARD_COUNT=1; fi

# ── Step 4: apply-lag anomaly ────────────────────────────────────────────────
# The receipt_apply_lag anomaly is a LIVE-SNAPSHOT signal: it checks
# whether pending_inbound_receipts is non-zero AND the chain has produced
# more than CROSS_SHARD_RECEIPT_LATENCY + slack blocks since the script
# started observing. We can't see per-receipt first_seen_block over RPC
# (it's a private field in node.cpp); the best proxy is:
#   - If pending pool depth has been > 0 across two status polls
#     separated by (latency + slack + 1) blocks, the producer has been
#     stuck. We don't run a second poll here (would balloon script runtime);
#     instead, we conservatively fire the anomaly when the pool is
#     non-empty AND the window crosses enough blocks for the soak to
#     have elapsed (WIN_BLOCKS >= latency + slack + 1). This catches
#     the common case ("pool has been stuck for the whole audit window")
#     and produces a single useful operator alert.
APPLY_LAG_THRESHOLD=$(( 3 + APPLY_LAG_SLACK ))  # CROSS_SHARD_RECEIPT_LATENCY=3
APPLY_LAG_TRIPPED=0
if [ "$PENDING_INBOUND" -gt 0 ] && [ "$WIN_BLOCKS" -gt "$APPLY_LAG_THRESHOLD" ]; then
  APPLY_LAG_TRIPPED=1
fi

# ── Step 5: outbound_destination_mismatch gate ───────────────────────────────
# Only check on genesis-to-head windows; otherwise we'd need a
# "accumulated_outbound as-of-block-N" RPC which doesn't exist.
OUT_MISMATCH_TRIPPED=0
OUT_MISMATCH_DIFF=0
OUT_DELTA_CHECKED=0
if [ "$FROM" = "0" ] && [ "$TO" = "$TOP" ]; then
  OUT_DELTA_CHECKED=1
  OUT_MISMATCH_DIFF=$(( OUTBOUND_TOTAL - ACCUM_OUTBOUND_HEAD ))
  if [ "$OUT_MISMATCH_DIFF" -lt 0 ]; then OUT_MISMATCH_DIFF=$(( - OUT_MISMATCH_DIFF )); fi
  if [ "$OUT_MISMATCH_DIFF" != "0" ]; then OUT_MISMATCH_TRIPPED=1; fi
fi

# ── Step 6: collect anomalies ────────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
[ "$PENDING_INBOUND"      -gt "$PENDING_BACKLOG_THRESHOLD" ] && add_anom "inbound_pending_backlog"
[ "$OUT_MISMATCH_TRIPPED" -eq 1 ]                            && add_anom "outbound_destination_mismatch"
[ "$APPLY_LAG_TRIPPED"    -eq 1 ]                            && add_anom "receipt_apply_lag"
[ "$REPLAY_COUNT"         -gt 0 ]                            && add_anom "inbound_replay_attempt"

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 7: render ───────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  "$PY" - "$WALK_JSON" "$MY_SHARD_ID" "$SHARD_COUNT" "$SHARDING_MODE" \
        "$FROM" "$TO" "$WIN_BLOCKS" "$PENDING_INBOUND" "$PORT" \
        "$ANOMALIES" <<'PY'
import json, sys
walk = json.loads(sys.argv[1])
envelope = {
    "my_shard_id":              int(sys.argv[2]),
    "shard_count":              int(sys.argv[3]),
    "shard_count_source":       "inferred",
    "sharding_mode":            sys.argv[4],
    "window":                   {"from": int(sys.argv[5]),
                                 "to":   int(sys.argv[6]),
                                 "blocks": int(sys.argv[7])},
    "pending_inbound_receipts": int(sys.argv[8]),
    "per_block":                walk["per_block"],
    "by_source":                walk["by_source"],
    "by_destination":           walk["by_destination"],
    "totals":                   walk["totals"],
    "replay_pairs":             walk["replay_pairs"],
    "anomalies":                ([a for a in sys.argv[10].split(",") if a]
                                 if sys.argv[10] else []),
    "rpc_port":                 int(sys.argv[9]),
}
print(json.dumps(envelope))
PY
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_cross_shard_health: no anomalies (port $PORT, window [$FROM..$TO], shard $MY_SHARD_ID of $SHARD_COUNT)"
  else
    echo "=== Cross-shard health audit (port $PORT, window [$FROM..$TO], $WIN_BLOCKS blocks) ==="
    echo "My shard: $MY_SHARD_ID (of $SHARD_COUNT inferred, sharding_mode=$SHARDING_MODE)"
    echo "Pending inbound pool depth: $PENDING_INBOUND (threshold: $PENDING_BACKLOG_THRESHOLD)"
    echo "Window totals:"
    echo "  outbound emitted:  $OUTBOUND_COUNT receipts, $OUTBOUND_TOTAL units debited"
    echo "  inbound applied:   $INBOUND_COUNT receipts, $INBOUND_TOTAL units credited"

    if [ "$ANOM_ONLY" != "1" ]; then
      # Per-source-shard outbound table (skipped if no outbound in window).
      if [ "$OUTBOUND_COUNT" -gt 0 ]; then
        echo "Per source shard (outbound, top 10):"
        printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
for r in json.load(sys.stdin)['by_source'][:10]:
    print(f'  shard {r[\"shard\"]}: {r[\"count\"]} receipts, {r[\"total\"]} debited')
"
      else
        echo "Per source shard (outbound): (none in window)"
      fi
      # Per-destination-shard inbound table.
      if [ "$INBOUND_COUNT" -gt 0 ]; then
        echo "Per destination shard (inbound, top 10):"
        printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
for r in json.load(sys.stdin)['by_destination'][:10]:
    print(f'  shard {r[\"shard\"]}: {r[\"count\"]} receipts, {r[\"total\"]} credited')
"
      else
        echo "Per destination shard (inbound): (none in window)"
      fi
      # Per-block activity trace (only blocks with outbound or inbound activity).
      PER_BLOCK_LEN=$(printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
print(len(json.load(sys.stdin)['per_block']))
")
      if [ "$PER_BLOCK_LEN" -gt 0 ]; then
        # Cap human-readable output at 20 rows; --json has the full set.
        echo "Per-block activity (blocks with cross-shard traffic, capped at 20):"
        printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
rows = json.load(sys.stdin)['per_block'][:20]
for r in rows:
    print(f'  block {r[\"index\"]:>9}: '
          f'out={r[\"outbound\"]:>3} ({r[\"outbound_amount\"]:>10}), '
          f'in={r[\"inbound\"]:>3} ({r[\"inbound_amount\"]:>10})')
if len(rows) == 20:
    print('  (truncated; use --json for full trace)')
"
      else
        echo "Per-block activity: (no cross-shard traffic in window)"
      fi
    fi

    # Anomaly diagnostics.
    if [ "$OUT_DELTA_CHECKED" = "1" ]; then
      if [ "$OUT_MISMATCH_TRIPPED" = "1" ]; then
        echo "Outbound delta check: MISMATCH — window sum $OUTBOUND_TOTAL vs chain accumulated_outbound $ACCUM_OUTBOUND_HEAD (diff=$OUT_MISMATCH_DIFF)"
      else
        echo "Outbound delta check: OK (window sum $OUTBOUND_TOTAL == chain accumulated_outbound $ACCUM_OUTBOUND_HEAD)"
      fi
    else
      echo "Outbound delta check: skipped (window [$FROM..$TO] is a strict subset of chain [0..$TOP]; no per-block accumulated_outbound RPC)"
    fi

    if [ "$APPLY_LAG_TRIPPED" = "1" ]; then
      echo "Apply-lag check: TRIPPED — pending pool has $PENDING_INBOUND receipts and window spans $WIN_BLOCKS blocks (> latency+slack=$APPLY_LAG_THRESHOLD); local producer may be stuck"
    elif [ "$PENDING_INBOUND" -gt 0 ]; then
      echo "Apply-lag check: pending pool non-empty ($PENDING_INBOUND receipts) but window too short to gate ($WIN_BLOCKS <= latency+slack=$APPLY_LAG_THRESHOLD)"
    else
      echo "Apply-lag check: OK (pending pool empty)"
    fi

    if [ "$REPLAY_COUNT" -gt 0 ]; then
      echo "Replay check: CATASTROPHIC — $REPLAY_COUNT duplicate (src_shard, src_block_index, tx_hash) tuple(s) in finalized blocks"
      printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
for r in json.load(sys.stdin)['replay_pairs'][:5]:
    th = r['tx_hash']
    th_short = th[:16] + '...' if len(th) > 16 else th
    print(f'  replay: src_shard={r[\"src_shard\"]} src_block={r[\"src_block_index\"]} tx={th_short}')
"
    else
      echo "Replay check: OK (no duplicate (src_shard, src_block_index, tx_hash) tuples)"
    fi

    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] cross-shard pipeline healthy"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
    fi
  fi
fi

# ── Step 8: exit-code policy ─────────────────────────────────────────────────
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
