#!/usr/bin/env bash
# operator_event_summary.sh — Aggregator across all three classes of
# consensus-level events that a running determ daemon can attribute to
# a specific validator address:
#
#   1. AbortEvents          (round-1 aborts; SUSPENSION_SLASH penalty)
#   2. EquivocationEvents   (FA6 double-sign; full-stake forfeiture)
#   3. MERGE_EVENT txs      (R7 under-quorum merges; BEGIN/END pairs;
#                            "terminator" = the apply-time `from` address
#                            on the tx, i.e. the validator that submitted
#                            it — this is the closest analog to a
#                            per-validator attribution for merges)
#
# This complements the focused single-class digests
# (operator_equivocation_digest, operator_merge_state_audit) by
# cross-aggregating across all three categories in a single window:
#
#   * Totals (raw + percentage breakdown)
#   * Per-validator combined breakdown (sorted by combined event count)
#   * Top incidents — validators whose combined event count is elevated
#   * Per-100-block bucket trends — stability vs. spike detection
#
# Read-only RPC. Daemon must be listening on --rpc-port. Requires `jq`
# (for the abort_events / equivocation_events extraction across the
# bulk `block-range` response) and Python (for the per-block MERGE_EVENT
# payload decode + bucket-trend aggregation — mirrors the same Python-
# heredoc pattern used by operator_merge_state_audit.sh).
#
# Usage:
#   tools/operator_event_summary.sh [--rpc-port N] [--json] \
#                                   [--from H] [--to H] \
#                                   [--anomalies-only] \
#                                   [--incident-threshold N] \
#                                   [--equiv-threshold N] \
#                                   [--instability-mult N] \
#                                   [--abort-flood-validators N] \
#                                   [--abort-flood-threshold N] \
#                                   [--bucket-size N]
#
# Defaults:
#   --rpc-port              7778
#   --from / --to           last 1000 blocks ending at current head
#                            (clamped to 0; --from must be <= --to)
#   --bucket-size           100   (per-100-block trend buckets)
#   --incident-threshold    20    (combined-events count to land on
#                                  the "top incidents" list)
#   --equiv-threshold       5     (validator equivocations to fire
#                                  high_equivocations anomaly — "> 5"
#                                  per task spec)
#   --instability-mult      3     (bucket counts > N× the prior bucket
#                                  fire trend_spike anomaly — "> 3×")
#   --abort-flood-validators 2    (>= N validators each crossing the
#                                  abort-flood threshold fire the
#                                  abort_flood anomaly — "multiple
#                                  validators with > 20 aborts")
#   --abort-flood-threshold 20    (per-validator abort count required
#                                  to count toward abort_flood)
#
# Anomalies (exit 2 under --anomalies-only):
#   high_equivocations   any single validator with > --equiv-threshold
#                        equivocations in the window. Clear malicious
#                        signal (FA6 should have slashed them, but the
#                        count is interesting for forensic timelines).
#   trend_spike          any bucket count > --instability-mult × the
#                        prior bucket count, for any of the three
#                        event categories. The first non-empty bucket
#                        is exempt (no "prior" baseline). Spike
#                        detection applies independently to abort,
#                        equivocation, and merge categories.
#   abort_flood          >= --abort-flood-validators distinct
#                        validators each exceeded
#                        --abort-flood-threshold aborts in the window.
#                        Signals network-wide instability (vs. one
#                        bad actor).
#
# RPC dependencies (all read-only):
#   - head      --json          (chain height for default --to)
#   - block-range FROM TO --json
#                                (bulk fetch of headers; carries
#                                 abort_events + equivocation_events per
#                                 block; transactions stripped — see
#                                 Node::rpc_headers strip list)
#   - block-info H --json        (per-block JSON with `transactions`
#                                 preserved; required for MERGE_EVENT
#                                 tx discovery — type=7 with hex payload
#                                 we decode in Python)
#
# Output (default human):
#   Section 1: Header (port, window).
#   Section 2: Totals (sum + per-category count + percentage).
#   Section 3: Per-validator breakdown (sorted by combined count desc,
#              top N controlled by --incident-threshold for the
#              "Top incidents" sub-section).
#   Section 4: Per-bucket trend (count per 100-block bucket per
#              category; trend status: stable / spike).
#   Section 5: Anomaly summary ([OK] or [WARN] lines).
#
# JSON envelope (--json):
#   {
#     "rpc_port": P,
#     "range": {"from": F, "to": T, "blocks": N},
#     "totals": {
#       "all": N,
#       "aborts": A, "equivocations": E, "merges": M,
#       "pct_aborts": ..., "pct_equivocations": ..., "pct_merges": ...
#     },
#     "by_validator": [
#       {"validator": "alice.tld",
#        "aborts": A, "equivocations": E, "merges": M,
#        "combined": A+E+M},
#       ...
#     ],
#     "top_incidents": [<subset of by_validator with combined >= threshold>],
#     "buckets": [
#       {"from": B0, "to": B0+99,
#        "aborts": A, "equivocations": E, "merges": M, "combined": C},
#       ...
#     ],
#     "anomalies": ["high_equivocations","trend_spike","abort_flood"],
#     "anomaly_details": {
#       "high_equivocations": [{"validator":"...","count":N}],
#       "trend_spike":        [{"category":"aborts","bucket_from":B,
#                               "this":T,"prior":P,"mult":M}],
#       "abort_flood":        [{"validator":"...","aborts":N}]
#     }
#   }
#
# Exit codes:
#   0   success; no anomalies (or anomalies present without
#       --anomalies-only — still success, anomalies in output)
#   1   RPC error / bad args / malformed response
#   2   --anomalies-only AND >= 1 anomaly detected
set -u

usage() {
  cat <<'EOF'
Usage: operator_event_summary.sh [--rpc-port N] [--json]
                                 [--from H] [--to H]
                                 [--anomalies-only]
                                 [--incident-threshold N]
                                 [--equiv-threshold N]
                                 [--instability-mult N]
                                 [--abort-flood-validators N]
                                 [--abort-flood-threshold N]
                                 [--bucket-size N]

Cross-aggregates abort + equivocation + merge events across a window
of finalized blocks. Reports totals, per-validator breakdown, top
incidents, per-bucket trends, and anomalies.

Options:
  --rpc-port N                RPC port to query (default: 7778)
  --json                      Emit structured JSON envelope
  --from H                    Lower window bound (inclusive).
                               Default: head - 1000.
  --to H                      Upper window bound (inclusive).
                               Default: current head.
  --anomalies-only            Suppress normal output unless an anomaly
                               fired; exit 2 if anomalies present.
  --incident-threshold N      Combined-events count for "top incidents"
                               list (default: 20)
  --equiv-threshold N         Per-validator equivocations > N fires
                               high_equivocations (default: 5)
  --instability-mult N        Bucket count > N× prior bucket fires
                               trend_spike (default: 3)
  --abort-flood-validators N  >= N validators over abort-flood
                               threshold fires abort_flood (default: 2)
  --abort-flood-threshold N   Per-validator abort count needed to
                               count toward abort_flood (default: 20)
  --bucket-size N             Block bucket size for trend report
                               (default: 100)
  -h, --help                  Show this help

Anomalies:
  high_equivocations   validator with > --equiv-threshold equivocations
  trend_spike          bucket count > --instability-mult× prior bucket
  abort_flood          >= --abort-flood-validators each over
                       --abort-flood-threshold aborts

Exit codes:
  0   success; no anomalies (or anomalies surfaced in normal output)
  1   RPC / args / parse failure
  2   --anomalies-only AND >= 1 anomaly detected
EOF
}

PORT=7778
JSON_OUT=0
FROM=""
TO=""
ANOM_ONLY=0
INCIDENT_THRESHOLD=20
EQUIV_THRESHOLD=5
INSTABILITY_MULT=3
ABORT_FLOOD_VALIDATORS=2
ABORT_FLOOD_THRESHOLD=20
BUCKET_SIZE=100

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                  usage; exit 0 ;;
    --rpc-port)                 PORT="${2:-}";                   shift 2 ;;
    --json)                     JSON_OUT=1;                      shift ;;
    --from)                     FROM="${2:-}";                   shift 2 ;;
    --to)                       TO="${2:-}";                     shift 2 ;;
    --anomalies-only)           ANOM_ONLY=1;                     shift ;;
    --incident-threshold)       INCIDENT_THRESHOLD="${2:-}";     shift 2 ;;
    --equiv-threshold)          EQUIV_THRESHOLD="${2:-}";        shift 2 ;;
    --instability-mult)         INSTABILITY_MULT="${2:-}";       shift 2 ;;
    --abort-flood-validators)   ABORT_FLOOD_VALIDATORS="${2:-}"; shift 2 ;;
    --abort-flood-threshold)    ABORT_FLOOD_THRESHOLD="${2:-}";  shift 2 ;;
    --bucket-size)              BUCKET_SIZE="${2:-}";            shift 2 ;;
    *) echo "operator_event_summary: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guards — order mirrors the option list above.
for pair in "PORT=$PORT" \
            "INCIDENT_THRESHOLD=$INCIDENT_THRESHOLD" \
            "EQUIV_THRESHOLD=$EQUIV_THRESHOLD" \
            "INSTABILITY_MULT=$INSTABILITY_MULT" \
            "ABORT_FLOOD_VALIDATORS=$ABORT_FLOOD_VALIDATORS" \
            "ABORT_FLOOD_THRESHOLD=$ABORT_FLOOD_THRESHOLD" \
            "BUCKET_SIZE=$BUCKET_SIZE"; do
  name="${pair%%=*}"; val="${pair#*=}"
  case "$val" in
    *[!0-9]*|"")
      flag=$(printf '%s' "$name" | tr '[:upper:]_' '[:lower:]-')
      echo "operator_event_summary: --$flag must be a positive integer (got '$val')" >&2
      exit 1 ;;
  esac
done
for v in "$FROM" "$TO"; do
  [ -z "$v" ] && continue
  case "$v" in *[!0-9]*)
    echo "operator_event_summary: --from / --to must be unsigned integers" >&2
    exit 1 ;;
  esac
done
if [ "$PORT" -lt 1 ];                  then echo "operator_event_summary: --rpc-port must be >= 1" >&2; exit 1; fi
if [ "$INCIDENT_THRESHOLD" -lt 1 ];    then echo "operator_event_summary: --incident-threshold must be >= 1" >&2; exit 1; fi
if [ "$EQUIV_THRESHOLD" -lt 1 ];       then echo "operator_event_summary: --equiv-threshold must be >= 1" >&2; exit 1; fi
if [ "$INSTABILITY_MULT" -lt 1 ];      then echo "operator_event_summary: --instability-mult must be >= 1" >&2; exit 1; fi
if [ "$ABORT_FLOOD_VALIDATORS" -lt 1 ];then echo "operator_event_summary: --abort-flood-validators must be >= 1" >&2; exit 1; fi
if [ "$ABORT_FLOOD_THRESHOLD" -lt 1 ]; then echo "operator_event_summary: --abort-flood-threshold must be >= 1" >&2; exit 1; fi
if [ "$BUCKET_SIZE" -lt 1 ];           then echo "operator_event_summary: --bucket-size must be >= 1" >&2; exit 1; fi

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_event_summary: jq is required (block-range JSON is too nested for grep fallback)" >&2
  exit 1
fi
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_event_summary: python (or python3) is required for MERGE_EVENT payload decoding + bucket aggregation" >&2
  exit 1
fi
PY_BIN=python
command -v python >/dev/null 2>&1 || PY_BIN=python3

# ── Step 1: resolve current head (drives default window) ──────────────────────
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_event_summary: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_event_summary: malformed head JSON (port $PORT)" >&2
  exit 1 ;;
esac

# Default window. `head`'s `height` is the next-to-be-produced index;
# highest finalized block has index = height - 1. Empty chain
# (HEIGHT = 0) handled inline below.
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))
if [ -z "$TO" ]; then
  TO=$TOP
fi
if [ -z "$FROM" ]; then
  FROM=$(( TOP > 1000 ? TOP - 1000 + 1 : 0 ))
fi

if [ "$TO" -lt "$FROM" ]; then
  echo "operator_event_summary: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi
if [ "$TO" -gt "$TOP" ]; then
  # Clamp silently — operator may have typed --to before chain caught up.
  TO=$TOP
fi

# Empty-chain short-circuit (same JSON shape as a normal zero-event run).
if [ "$TOP" -eq 0 ] && [ "$HEIGHT" -eq 0 ]; then
  WINDOW=$(( TO - FROM + 1 ))
  if [ "$JSON_OUT" = "1" ]; then
    jq -n --argjson p "$PORT" --argjson from "$FROM" --argjson to "$TO" --argjson w "$WINDOW" '{
      rpc_port: $p,
      range: {from: $from, to: $to, blocks: $w},
      totals: {all: 0, aborts: 0, equivocations: 0, merges: 0,
               pct_aborts: 0, pct_equivocations: 0, pct_merges: 0},
      by_validator: [],
      top_incidents: [],
      buckets: [],
      anomalies: [],
      anomaly_details: {high_equivocations: [], trend_spike: [], abort_flood: []}
    }'
  elif [ "$ANOM_ONLY" != "1" ]; then
    echo "=== Event summary (port $PORT, window [$FROM..$TO]) ==="
    echo "Chain has no finalized blocks yet (height=0)."
    echo "[OK] No events, no anomalies"
  fi
  exit 0
fi

# ── Step 2: bulk-fetch the window via block-range --json ─────────────────────
# Headers RPC strips `transactions` (no MERGE_EVENT visibility) but
# retains `abort_events` + `equivocation_events` (see
# Node::rpc_headers strip list in src/node/node.cpp).
RANGE_JSON=$("$DETERM" block-range "$FROM" "$TO" --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_event_summary: RPC error fetching block-range [$FROM..$TO] on port $PORT" >&2
  exit 1
}

# Flatten abort + equivocation events. Each event carries:
#   {block_index, validator, kind: "abort" | "equivocation"}
# For aborts: validator = aborting_node (AbortEvent::to_json field).
# For equivocations: validator = equivocator (EquivocationEvent field).
ABORT_EVENTS_JSON=$(printf '%s' "$RANGE_JSON" | jq -c '
  [ .headers[]
    | . as $blk
    | (.abort_events // [])[]
    | { block_index: $blk.index,
        validator: .aborting_node,
        kind: "abort" }
  ]
') || {
  echo "operator_event_summary: malformed abort_events extraction" >&2
  exit 1
}
EQUIV_EVENTS_JSON=$(printf '%s' "$RANGE_JSON" | jq -c '
  [ .headers[]
    | . as $blk
    | (.equivocation_events // [])[]
    | { block_index: $blk.index,
        validator: .equivocator,
        kind: "equivocation" }
  ]
') || {
  echo "operator_event_summary: malformed equivocation_events extraction" >&2
  exit 1
}

# ── Step 3: per-block MERGE_EVENT walk (Python decodes payload) ──────────────
# headers RPC strips `transactions`, so MERGE_EVENT discovery needs
# block-info per height. The walk + bucket aggregation + anomaly
# detection + render all happen in Python below — single pass through
# the chain window.
"$PY_BIN" - \
  "$DETERM" "$PORT" \
  "$FROM" "$TO" "$HEIGHT" \
  "$BUCKET_SIZE" "$INCIDENT_THRESHOLD" \
  "$EQUIV_THRESHOLD" "$INSTABILITY_MULT" \
  "$ABORT_FLOOD_VALIDATORS" "$ABORT_FLOOD_THRESHOLD" \
  "$ANOM_ONLY" "$JSON_OUT" \
  "$ABORT_EVENTS_JSON" "$EQUIV_EVENTS_JSON" <<'PY'
import json, sys, subprocess

(determ, port,
 from_s, to_s, height_s,
 bucket_size_s, incident_threshold_s,
 equiv_threshold_s, instability_mult_s,
 abort_flood_validators_s, abort_flood_threshold_s,
 anom_only_s, json_out_s,
 abort_events_json, equiv_events_json) = sys.argv[1:16]

from_h                  = int(from_s)
to_h                    = int(to_s)
height                  = int(height_s)
bucket_size             = int(bucket_size_s)
incident_threshold      = int(incident_threshold_s)
equiv_threshold         = int(equiv_threshold_s)
instability_mult        = int(instability_mult_s)
abort_flood_validators  = int(abort_flood_validators_s)
abort_flood_threshold   = int(abort_flood_threshold_s)
anom_only               = anom_only_s == "1"
json_out                = json_out_s == "1"

window_blocks = to_h - from_h + 1

try:
    abort_events = json.loads(abort_events_json)
except Exception as e:
    sys.stderr.write(f"operator_event_summary: abort_events JSON parse failed: {e}\n")
    sys.exit(1)
try:
    equiv_events = json.loads(equiv_events_json)
except Exception as e:
    sys.stderr.write(f"operator_event_summary: equivocation_events JSON parse failed: {e}\n")
    sys.exit(1)

# ── MERGE_EVENT walk ─────────────────────────────────────────────────────────
# Wire format mirror of src/chain/block.cpp::MergeEvent::encode/decode
# (same definitions used by operator_merge_state_audit.sh):
#   [0]      event_type (0=BEGIN, 1=END)
#   [1..4]   shard_id            (u32 LE)
#   [5..8]   partner_id          (u32 LE)
#   [9..16]  effective_height    (u64 LE)
#   [17..24] evidence_window_start (u64 LE; 0 for END)
#   [25]     region_len (max 32)
#   [26..]   refugee region (UTF-8)
TX_TYPE_MERGE_EVENT = 7  # src/chain/block.hpp::TxType::MERGE_EVENT

def is_merge_event(tx_type):
    if isinstance(tx_type, int): return tx_type == TX_TYPE_MERGE_EVENT
    if isinstance(tx_type, str): return tx_type in ("7", "MERGE_EVENT")
    return False

def decode_merge_event(hex_str):
    try:
        p = bytes.fromhex(hex_str)
    except Exception:
        return None
    if len(p) < 26:    return None
    if p[0] > 1:       return None
    rlen = p[25]
    if rlen > 32:      return None
    if len(p) != 26 + rlen: return None
    return {
        "event_type": p[0],  # 0=BEGIN, 1=END (kept here for future filtering;
                              # the aggregator counts both as "merge events")
    }

merge_events = []  # [{block_index, validator, kind: "merge"}, ...]

if height > 0:
    for h in range(from_h, to_h + 1):
        try:
            r = subprocess.run(
                [determ, "block-info", str(h), "--json", "--rpc-port", port],
                capture_output=True, text=True, timeout=10,
            )
        except Exception as e:
            sys.stderr.write(f"operator_event_summary: block-info {h} failed: {e}\n")
            sys.exit(1)
        if r.returncode != 0:
            sys.stderr.write(
                f"operator_event_summary: block-info {h} rc={r.returncode}\n{r.stderr}"
            )
            sys.exit(1)
        try:
            blk = json.loads(r.stdout)
        except Exception:
            sys.stderr.write(f"operator_event_summary: block-info {h} returned non-JSON\n")
            sys.exit(1)
        if not isinstance(blk, dict): continue
        for tx in (blk.get("transactions") or []):
            if not isinstance(tx, dict): continue
            if not is_merge_event(tx.get("type")): continue
            ev = decode_merge_event(tx.get("payload", ""))
            if ev is None: continue
            # `from` on a MERGE_EVENT tx is the validator (terminator)
            # that submitted the BEGIN/END. Attribution at the tx-`from`
            # level is the closest analog to per-validator credit for
            # merges (the MergeEvent payload itself doesn't carry an
            # actor field; it carries shard ids + region).
            merge_events.append({
                "block_index": h,
                "validator":   tx.get("from", "") or "",
                "kind":        "merge",
            })

# ── Totals ───────────────────────────────────────────────────────────────────
n_aborts  = len(abort_events)
n_equivs  = len(equiv_events)
n_merges  = len(merge_events)
n_all     = n_aborts + n_equivs + n_merges

def pct(n, d):
    if d == 0: return 0.0
    return round(100.0 * n / d, 1)

totals = {
    "all":               n_all,
    "aborts":            n_aborts,
    "equivocations":     n_equivs,
    "merges":            n_merges,
    "pct_aborts":        pct(n_aborts, n_all),
    "pct_equivocations": pct(n_equivs, n_all),
    "pct_merges":        pct(n_merges, n_all),
}

# ── Per-validator breakdown ──────────────────────────────────────────────────
per_val = {}  # validator -> {aborts, equivocations, merges}

def bump(v, key):
    if not v: return  # skip empty validator strings (defensive)
    rec = per_val.setdefault(v, {"aborts": 0, "equivocations": 0, "merges": 0})
    rec[key] += 1

for e in abort_events: bump(e.get("validator", ""), "aborts")
for e in equiv_events: bump(e.get("validator", ""), "equivocations")
for e in merge_events: bump(e.get("validator", ""), "merges")

by_validator = []
for v, rec in per_val.items():
    combined = rec["aborts"] + rec["equivocations"] + rec["merges"]
    by_validator.append({
        "validator":     v,
        "aborts":        rec["aborts"],
        "equivocations": rec["equivocations"],
        "merges":        rec["merges"],
        "combined":      combined,
    })
# Sort: combined desc, then equivocations desc (worst-class first),
# then aborts desc, then validator asc (deterministic ties).
by_validator.sort(key=lambda r: (
    -r["combined"], -r["equivocations"], -r["aborts"], r["validator"]
))

top_incidents = [r for r in by_validator if r["combined"] >= incident_threshold]

# ── Per-bucket trend ─────────────────────────────────────────────────────────
# Bucket B_i covers [from_h + i*bucket_size, from_h + (i+1)*bucket_size - 1],
# clamped to to_h. A block at index `h` belongs to bucket
# (h - from_h) // bucket_size. We emit one entry per bucket that has any
# coverage in the window (last bucket may be partial).
n_buckets = (window_blocks + bucket_size - 1) // bucket_size
buckets = []
for i in range(n_buckets):
    b_from = from_h + i * bucket_size
    b_to   = min(b_from + bucket_size - 1, to_h)
    buckets.append({
        "from":          b_from,
        "to":            b_to,
        "aborts":        0,
        "equivocations": 0,
        "merges":        0,
        "combined":      0,
    })

def bucket_index_of(block_index):
    return (block_index - from_h) // bucket_size

for e in abort_events:
    i = bucket_index_of(int(e["block_index"]))
    if 0 <= i < n_buckets:
        buckets[i]["aborts"] += 1
        buckets[i]["combined"] += 1
for e in equiv_events:
    i = bucket_index_of(int(e["block_index"]))
    if 0 <= i < n_buckets:
        buckets[i]["equivocations"] += 1
        buckets[i]["combined"] += 1
for e in merge_events:
    i = bucket_index_of(int(e["block_index"]))
    if 0 <= i < n_buckets:
        buckets[i]["merges"] += 1
        buckets[i]["combined"] += 1

# ── Anomaly detection ────────────────────────────────────────────────────────
# (1) high_equivocations: per-validator equivocations > equiv_threshold.
anomaly_high_equiv = []
for r in by_validator:
    if r["equivocations"] > equiv_threshold:
        anomaly_high_equiv.append({
            "validator": r["validator"],
            "count":     r["equivocations"],
        })

# (2) trend_spike: any bucket count > instability_mult × prior bucket
# count, per category. Skip the first bucket (no prior baseline).
# A bucket with `prior == 0` and `this > 0` doesn't trip the strict
# multiplicative test — that's intentional (a zero baseline + first-
# occurrence is informative but not necessarily anomalous).
anomaly_trend_spike = []
for cat in ("aborts", "equivocations", "merges"):
    for i in range(1, n_buckets):
        prev_n = buckets[i - 1][cat]
        this_n = buckets[i][cat]
        if prev_n > 0 and this_n > instability_mult * prev_n:
            anomaly_trend_spike.append({
                "category":    cat,
                "bucket_from": buckets[i]["from"],
                "bucket_to":   buckets[i]["to"],
                "this":        this_n,
                "prior":       prev_n,
                "mult":        round(this_n / prev_n, 2),
            })

# (3) abort_flood: >= abort_flood_validators distinct validators each
# above abort_flood_threshold aborts.
abort_offenders = [
    {"validator": r["validator"], "aborts": r["aborts"]}
    for r in by_validator if r["aborts"] > abort_flood_threshold
]
anomaly_abort_flood = abort_offenders if len(abort_offenders) >= abort_flood_validators else []

anomalies = []
if anomaly_high_equiv:  anomalies.append("high_equivocations")
if anomaly_trend_spike: anomalies.append("trend_spike")
if anomaly_abort_flood: anomalies.append("abort_flood")

# ── Rendering ────────────────────────────────────────────────────────────────
def emit_json():
    env = {
        "rpc_port":     int(port),
        "range":        {"from": from_h, "to": to_h, "blocks": window_blocks},
        "totals":       totals,
        "by_validator": by_validator,
        "top_incidents": top_incidents,
        "buckets":      buckets,
        "anomalies":    anomalies,
        "anomaly_details": {
            "high_equivocations": anomaly_high_equiv,
            "trend_spike":        anomaly_trend_spike,
            "abort_flood":        anomaly_abort_flood,
        },
    }
    print(json.dumps(env))

def emit_human():
    print(f"=== Event summary (port {port}, window [{from_h}..{to_h}]) ===")
    print(f"Total events: {n_all}")
    if n_all > 0:
        print(f"  AbortEvents:   {n_aborts} ({totals['pct_aborts']}%)")
        print(f"  Equivocations: {n_equivs} ({totals['pct_equivocations']}%)")
        print(f"  MergeEvents:   {n_merges} ({totals['pct_merges']}%)")
    else:
        print("  AbortEvents:   0")
        print("  Equivocations: 0")
        print("  MergeEvents:   0")

    if by_validator:
        print("Per-validator:")
        # Truncate validator strings to 28 chars for readability; if
        # operators want full values they should use --json.
        for r in by_validator:
            v = r["validator"]
            if len(v) > 28:
                v = v[:25] + "..."
            print(f"  {v:<28} {r['aborts']:>4} aborts, "
                  f"{r['equivocations']:>3} equivocations, "
                  f"{r['merges']:>3} merges  (combined: {r['combined']})")
    else:
        print("Per-validator: (none)")

    if top_incidents:
        print(f"Top incidents (combined >= {incident_threshold}):")
        for r in top_incidents:
            v = r["validator"]
            if len(v) > 28: v = v[:25] + "..."
            print(f"  {v:<28} combined={r['combined']}  "
                  f"(a={r['aborts']} e={r['equivocations']} m={r['merges']})")

    if buckets:
        # Compact trend line: "stable" when no anomaly_trend_spike,
        # else list spiking buckets/categories inline.
        spike_cats = sorted({s["category"] for s in anomaly_trend_spike})
        trend_label = ("spike (" + ",".join(spike_cats) + ")") if spike_cats else "stable"
        print(f"Per-bucket ({bucket_size}-block buckets, n={len(buckets)}): {trend_label}")
        # Brief per-bucket table only when total events warrant it (else
        # the report is just a wall of zeros).
        if n_all > 0:
            for b in buckets:
                if b["combined"] == 0: continue
                print(f"  [{b['from']:>7}..{b['to']:>7}] "
                      f"a={b['aborts']:<4} e={b['equivocations']:<3} "
                      f"m={b['merges']:<3} (combined={b['combined']})")

    if not anomalies:
        print("[OK] No anomalies")
    else:
        for d in anomaly_high_equiv:
            print(f"[WARN] high_equivocations: validator {d['validator']} "
                  f"with {d['count']} equivocations (threshold > {equiv_threshold})")
        for d in anomaly_trend_spike:
            print(f"[WARN] trend_spike: {d['category']} bucket "
                  f"[{d['bucket_from']}..{d['bucket_to']}] = {d['this']} "
                  f"vs prior {d['prior']} (x{d['mult']}; threshold > "
                  f"{instability_mult}x)")
        if anomaly_abort_flood:
            offenders = ", ".join(
                f"{d['validator']}({d['aborts']})" for d in anomaly_abort_flood
            )
            print(f"[WARN] abort_flood: {len(anomaly_abort_flood)} validators "
                  f"each > {abort_flood_threshold} aborts: {offenders}")

# --anomalies-only: silent unless an anomaly fired.
if anom_only:
    if anomalies:
        if json_out: emit_json()
        else:        emit_human()
        sys.exit(2)
    sys.exit(0)

if json_out: emit_json()
else:        emit_human()
sys.exit(0)
PY
RC=$?
exit "$RC"
