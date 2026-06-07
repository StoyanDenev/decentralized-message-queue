#!/usr/bin/env bash
# operator_inbound_admission_age.sh — Single-daemon, self-contained
# INBOUND cross-shard receipt ADMISSION-AGE profiler.
#
# THE OPERATOR QUESTION
#   "For every cross-shard receipt my shard has ADMITTED (baked into a
#    finalized block's inbound_receipts[]), how many blocks elapsed
#    between the SOURCE shard emitting it (its src_block_index) and THIS
#    shard finalizing it (the landing block's index)? Is that end-to-end
#    transit age stable, or is it creeping up (gossip backlog / a
#    congested local producer holding the pending pool)? And — the
#    correctness signal — is the mandated CROSS_SHARD_RECEIPT_LATENCY=3
#    admission soak being HONORED, i.e. is any receipt admitted SOONER
#    than the source could possibly have reached this shard?"
#
# WHAT IT MEASURES (purely from the LOCAL daemon — NO peer ports)
#   Each entry in a finalized block B's `inbound_receipts[]` is a
#   CrossShardReceipt carrying `src_block_index` (the height at which the
#   SOURCE shard emitted it) — see src/chain/block.cpp::CrossShardReceipt
#   ::to_json (fields: src_shard, dst_shard, src_block_index, tx_hash,
#   from, to, amount, fee, nonce). B carries its own `index`. We define
#
#       admission_age(receipt) = B.index − receipt.src_block_index
#
#   This is the END-TO-END cross-shard transit age (source-emit → local-
#   admit), inclusive of gossip propagation AND the S-016 Option-2
#   admission soak. We compute its distribution (min/p50/p95/max/mean)
#   plus a per-source-shard breakdown, walking ONLY this shard's own
#   finalized blocks. No --peer-ports, no source-side join.
#
# WHY THIS IS DISTINCT FROM THE SIBLING CROSS-SHARD TOOLS
#   operator_receipt_settlement_latency.sh  Measures the SAME delta
#                                  (apply_index − src_block_index) but
#                                  from the SOURCE side and REQUIRES
#                                  --peer-ports to see the destination
#                                  apply leg (a cross-DAEMON join). THIS
#                                  tool reads it off the DESTINATION's own
#                                  inbound_receipts[] with zero peers.
#   operator_cross_shard_health.sh  Apply-lag via the LIVE
#                                  status.pending_inbound_receipts pool
#                                  snapshot + per-block emit/apply COUNTS.
#                                  It never reads src_block_index off the
#                                  admitted receipts, so it cannot age a
#                                  finalized admission.
#   operator_inbound_reconciliation_audit.sh  Per-block F2-reconciled
#                                  admission COUNT + the F2 activation
#                                  height; it counts admissions, it does
#                                  not age them.
#   operator_receipt_audit.sh / operator_receipt_flow.sh  FA7 dedup-set
#                                  forensics / A1 supply-counter balance.
#                                  Neither computes an admission-age
#                                  distribution.
#   operator_inbound_outbound_balance.sh  NET signed flow over time; no
#                                  per-receipt age.
#
#   In short: this is the ONLY tool that ages a finalized inbound
#   admission against its source-emit height using a SINGLE daemon's
#   own chain — the receiving shard's view of how long cross-shard
#   value spent in flight before it landed.
#
# THE SOAK FLOOR (honesty note — read before trusting the floor check)
#   src/node/node.cpp::CROSS_SHARD_RECEIPT_LATENCY = 3 is keyed on the
#   destination's LOCAL first-observation height (pending_inbound_first_
#   seen_[key] = chain_.height() at receive time; the eligibility gate is
#   `first_seen + 3 <= now`). That first-seen height is RUNTIME state — it
#   is never serialized into a block, so it is NOT observable from
#   finalized JSON. admission_age here is therefore an UPPER bound on the
#   true local soak (it also includes the gossip-transit time from the
#   source). Consequently:
#     - A HEALTHY chain has admission_age >= the floor for essentially
#       every receipt (gossip cannot be instantaneous AND the soak adds 3
#       more blocks on top). admission_age BELOW the floor is the
#       interesting signal: it means a receipt was admitted faster than
#       (source-emit + soak) — only possible if the source clock ran
#       ahead of this shard's, the windows came from mismatched chains, or
#       src_block_index was corrupted. We surface that as
#       `admission_below_soak_floor` (suspicious, not provably a bug,
#       because the two shards' heights are independent counters — see
#       --floor-strict to harden it).
#     - A NEGATIVE admission_age (src_block_index > landing index) is
#       reported separately as `admission_age_negative` and is
#       catastrophic by the same reasoning regardless of clocks: this
#       shard finalized the receipt at a lower index than its own recorded
#       source-emit index for a receipt it claims came from ANOTHER shard
#       — index corruption or a cross-fed wrong-chain window.
#
# SINGLE-SHARD DEPLOYMENTS (sharding_mode == "none")
#   No cross-shard routing is possible, so inbound_receipts[] is empty by
#   construction. The script short-circuits to one INFO line, exit 0.
#
# Read-only RPCs ONLY (status / head / block-info). NEVER a mutating RPC,
# no node spawning, no --watch, no unbounded loops: a single bounded pass
# over the local block window, each block-info call with a per-call
# subprocess timeout, then exit.
#
# RPC / FIELD PROVENANCE (verified against src/, NOT invented):
#   determ status     --json  → shard_id, height, protections.sharding_mode
#                               (src/node/node.cpp::rpc_status)
#   determ head --field height → chain height
#                               (src/main.cpp::cmd_head → status RPC)
#   determ block-info H --json → full Block::to_json incl.
#                               inbound_receipts[] (src/main.cpp::
#                               cmd_block_info → `block` RPC → rpc_block →
#                               Chain::at(H).to_json; src/chain/block.cpp
#                               ::Block::to_json line ~471 emits
#                               "inbound_receipts")
#   inbound_receipts[].src_shard / .dst_shard / .src_block_index / .tx_hash
#                               (src/chain/block.cpp::CrossShardReceipt::
#                               to_json lines 197-210)
#
# Anomalies (any fires → exit 2 in --anomalies-only mode):
#   admission_age_high          ≥1 admitted receipt's admission_age
#                               exceeds CROSS_SHARD_RECEIPT_LATENCY (3) +
#                               --age-slack (default 50). Value spent
#                               unusually long in flight (gossip backlog
#                               or a local producer that repeatedly
#                               aborted before baking the pending bundle).
#   admission_below_soak_floor  ≥1 receipt admitted with admission_age <
#                               CROSS_SHARD_RECEIPT_LATENCY (3). With
#                               independent per-shard clocks this is
#                               suspicious-not-proven by default; with
#                               --floor-strict it is treated as a hard
#                               anomaly (use only when you KNOW the fleet
#                               is height-synchronized).
#   admission_age_negative      ≥1 receipt with admission_age < 0
#                               (src_block_index > landing index).
#                               Catastrophic: index corruption or a
#                               cross-fed wrong-chain window.
#
# Usage:
#   tools/operator_inbound_admission_age.sh --rpc-port N
#                       [--from H] [--to H] [--last N]
#                       [--age-slack N] [--floor-strict]
#                       [--block-timeout S]
#                       [--anomalies-only] [--json]
#
# --json shape:
#   {"skipped":false,"my_shard_id":N,"sharding_mode":"...",
#    "window":{"from":H,"to":H,"blocks":N},
#    "admitted_count":N,
#    "age":{"min":N,"p50":N,"p95":N,"max":N,"mean":N}|null,
#    "by_source":[{"shard":N,"admitted":N,"p50_age":N|null,"max_age":N|null},...],
#    "high_age":[{"tx_hash":"...","src_shard":N,"src_block_index":H,
#                 "landing_index":H,"age":N},...],
#    "below_floor":[...],"negative":[...],
#    "soak_floor":3,"age_budget":N,"floor_strict":bool,
#    "anomalies":[...],"rpc_port":N}
#
# Exit codes:
#   0   profiled OK (no anomalies / informational mode / single-shard /
#       empty window / daemon unreachable SKIP)
#   1   bad args / malformed RPC response / empty-window error
#   2   --anomalies-only AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_inbound_admission_age.sh --rpc-port N
                    [--from H] [--to H] [--last N]
                    [--age-slack N] [--floor-strict]
                    [--block-timeout S]
                    [--anomalies-only] [--json]

Single-daemon INBOUND cross-shard receipt admission-age profiler. Walks a
window of THIS shard's own finalized blocks and, for each admitted
inbound_receipts[] entry, computes

    admission_age = landing_block.index − receipt.src_block_index

the end-to-end cross-shard transit age (source-emit → local-admit). Reports
the age distribution + a per-source-shard breakdown. NO peer ports needed.

NOTE: admission_age is an UPPER bound on the true local S-016 soak (it also
includes gossip-transit time and the source/destination height offset). The
CROSS_SHARD_RECEIPT_LATENCY=3 soak floor is keyed on local first-observation
height, which is runtime-only state and NOT in finalized JSON — see the
header block for the full honesty note on the floor check.

NOTE: meaningful only on multi-shard deployments. On sharding_mode=none the
script exits 0 with an INFO line (inbound_receipts[] empty by construction).

Options:
  --rpc-port N        Daemon RPC port (REQUIRED)
  --from H            Window lower bound, inclusive (default: max(0, tip−255))
  --to H              Window upper bound, inclusive (default: tip)
  --last N            Shorthand for [tip−N+1, tip] (exclusive with --from/--to)
  --age-slack N       Over-budget threshold added to CROSS_SHARD_RECEIPT_
                      LATENCY (3) for the high-age anomaly (default: 50)
  --floor-strict      Treat admission_age < 3 as a HARD anomaly (only safe
                      when the fleet is height-synchronized; default: soft)
  --block-timeout S   Per-block-info RPC timeout in seconds (default 10)
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  --json              Emit a structured JSON envelope
  -h, --help          Show this help

Anomalies:
  admission_age_high         admitted receipt aged past 3 + --age-slack blocks
  admission_below_soak_floor admitted receipt aged < 3 (soft by default;
                             hard under --floor-strict)
  admission_age_negative     admitted receipt with src_block_index > landing
                             index (catastrophic: index/chain corruption)

Exit codes:
  0   profiled OK (or single-shard / empty window / daemon unreachable SKIP)
  1   bad args / malformed RPC response / empty-window error
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=""
FROM=""
TO=""
LAST=""
AGE_SLACK=50
FLOOR_STRICT=0
BLOCK_TIMEOUT=10
ANOM_ONLY=0
JSON_OUT=0

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";          shift 2 ;;
    --from)            FROM="${2:-}";          shift 2 ;;
    --to)              TO="${2:-}";            shift 2 ;;
    --last)            LAST="${2:-}";          shift 2 ;;
    --age-slack)       AGE_SLACK="${2:-}";     shift 2 ;;
    --floor-strict)    FLOOR_STRICT=1;         shift ;;
    --block-timeout)   BLOCK_TIMEOUT="${2:-}"; shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;            shift ;;
    --json)            JSON_OUT=1;             shift ;;
    *) echo "operator_inbound_admission_age: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (multi-instance hosts; refuse to guess).
if [ -z "$PORT" ]; then
  echo "operator_inbound_admission_age: --rpc-port is required" >&2
  usage >&2
  exit 1
fi

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_inbound_admission_age: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
if [ -n "$LAST" ] && { [ -n "$FROM" ] || [ -n "$TO" ]; }; then
  echo "operator_inbound_admission_age: --last cannot be combined with --from / --to" >&2
  exit 1
fi
for v in "$FROM" "$TO" "$LAST"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_inbound_admission_age: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST" ] && [ "$LAST" = "0" ]; then
  echo "operator_inbound_admission_age: --last must be >= 1" >&2
  exit 1
fi
case "$AGE_SLACK" in *[!0-9]*|"")
  echo "operator_inbound_admission_age: --age-slack must be a non-negative integer (got '$AGE_SLACK')" >&2
  exit 1 ;;
esac
case "$BLOCK_TIMEOUT" in *[!0-9]*|"")
  echo "operator_inbound_admission_age: --block-timeout must be a positive integer (got '$BLOCK_TIMEOUT')" >&2
  exit 1 ;;
esac
if [ "$BLOCK_TIMEOUT" -lt 1 ]; then
  echo "operator_inbound_admission_age: --block-timeout must be >= 1" >&2; exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# python required for per-block JSON walk + percentile math (block JSON is
# too nested to grep usefully; this mirrors the sibling cross-shard tools).
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_inbound_admission_age: python (or python3) is required for the receipt walk" >&2
  exit 1
fi
PY=python; command -v python >/dev/null 2>&1 || PY=python3

# Promote DETERM to an absolute path so python's subprocess.run resolves
# the binary the same on Linux/Mac/Git Bash (matches the sibling pattern).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: probe the daemon for shard identity + head ───────────────────────
# Unreachable daemon → clean INFO + SKIP, exit 0 (both human and --json).
STATUS_JSON=$("$DETERM" status --json --rpc-port "$PORT" 2>/dev/null) || {
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"skipped":true,"reason":"daemon_unreachable","rpc_port":%s}\n' "$PORT"
  else
    echo "INFO: daemon not reachable on port $PORT — SKIP (no cross-shard chain to profile)"
  fi
  exit 0
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
  echo "operator_inbound_admission_age: malformed status JSON (port $PORT)" >&2
  exit 1
fi
case "$MY_SHARD_ID" in *[!0-9]*|"") MY_SHARD_ID=0 ;; esac
case "$HEIGHT" in *[!0-9]*|"") echo "operator_inbound_admission_age: malformed status height" >&2; exit 1 ;; esac

# Highest finalized index = height − 1.
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))

# Resolve window bounds. Precedence: --last > (--from / --to) > defaults.
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
  echo "operator_inbound_admission_age: --to ($TO) < --from ($FROM); nothing to profile" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Short-circuit: empty chain ───────────────────────────────────────────────
if [ "$HEIGHT" -eq 0 ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"skipped":false,"my_shard_id":%s,"sharding_mode":"%s","window":{"from":%s,"to":%s,"blocks":0},"admitted_count":0,"age":null,"by_source":[],"high_age":[],"below_floor":[],"negative":[],"soak_floor":3,"age_budget":%s,"floor_strict":%s,"anomalies":[],"rpc_port":%s,"info":"empty_chain"}\n' \
      "$MY_SHARD_ID" "$SHARDING_MODE" "$FROM" "$TO" "$(( 3 + AGE_SLACK ))" \
      "$( [ "$FLOOR_STRICT" = "1" ] && echo true || echo false )" "$PORT"
  else
    echo "operator_inbound_admission_age: chain has no finalized blocks yet (height=0, port $PORT)"
  fi
  exit 0
fi

# ── Short-circuit: single-shard deployment ───────────────────────────────────
if [ "$SHARDING_MODE" = "none" ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"skipped":false,"my_shard_id":%s,"sharding_mode":"none","window":{"from":%s,"to":%s,"blocks":%s},"admitted_count":0,"age":null,"by_source":[],"high_age":[],"below_floor":[],"negative":[],"soak_floor":3,"age_budget":%s,"floor_strict":%s,"anomalies":[],"rpc_port":%s,"info":"single_shard_deployment"}\n' \
      "$MY_SHARD_ID" "$FROM" "$TO" "$WIN_BLOCKS" "$(( 3 + AGE_SLACK ))" \
      "$( [ "$FLOOR_STRICT" = "1" ] && echo true || echo false )" "$PORT"
  else
    echo "INFO: single-shard deployment — no inbound cross-shard receipts by construction"
    echo "      sharding_mode=none, my_shard_id=$MY_SHARD_ID, port $PORT"
  fi
  exit 0
fi

# ── Step 2: Python-driven local walk + distribution + render ─────────────────
TMP_OUT=$(mktemp) || {
  echo "operator_inbound_admission_age: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

"$PY" - \
  "$DETERM_ABS" "$PORT" \
  "$FROM" "$TO" "$MY_SHARD_ID" \
  "$AGE_SLACK" "$BLOCK_TIMEOUT" "$FLOOR_STRICT" \
  "$TMP_OUT" <<'PY'
import json, subprocess, sys
from collections import defaultdict

(determ, port,
 from_s, to_s, my_shard_id_s,
 slack_s, block_timeout_s, floor_strict_s,
 out_path) = sys.argv[1:10]

from_h        = int(from_s)
to_h          = int(to_s)
my_shard_id   = int(my_shard_id_s)
slack         = int(slack_s)
block_timeout = int(block_timeout_s)
floor_strict  = (floor_strict_s == "1")

CROSS_SHARD_RECEIPT_LATENCY = 3   # src/node/node.cpp
age_budget = CROSS_SHARD_RECEIPT_LATENCY + slack

def die(msg, code=1):
    sys.stderr.write(f"operator_inbound_admission_age: {msg}\n")
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

# ── Walk local [from..to] for inbound_receipts[]; age each admission. ─────────
ages           = []
by_source      = defaultdict(lambda: {"admitted": 0, "ages": []})
high_age       = []
below_floor    = []
negative       = []
admitted_count = 0

for h in range(from_h, to_h + 1):
    blk = block_info(port, h)
    if blk is None:
        continue
    # The landing block's own index. Prefer the JSON field; fall back to h
    # (block-info H returns the block AT index h, so they coincide).
    landing = int(blk.get("index", h))
    for ib in (blk.get("inbound_receipts") or []):
        if not isinstance(ib, dict):
            continue
        src   = int(ib.get("src_shard", 0))
        sbidx = int(ib.get("src_block_index", landing))
        thash = str(ib.get("tx_hash", ""))
        age   = landing - sbidx
        admitted_count += 1
        ages.append(age)
        by_source[src]["admitted"] += 1
        by_source[src]["ages"].append(age)
        rec = {
            "tx_hash":         thash,
            "src_shard":       src,
            "src_block_index": sbidx,
            "landing_index":   landing,
            "age":             age,
        }
        if age < 0:
            negative.append(rec)
        elif age < CROSS_SHARD_RECEIPT_LATENCY:
            below_floor.append(rec)
        elif age > age_budget:
            high_age.append(rec)

def pct(sorted_vals, q):
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    import math
    rank = max(1, math.ceil(q / 100.0 * len(sorted_vals)))
    return sorted_vals[min(rank, len(sorted_vals)) - 1]

age_stats = None
if ages:
    s = sorted(ages)
    age_stats = {
        "min":  s[0],
        "p50":  pct(s, 50),
        "p95":  pct(s, 95),
        "max":  s[-1],
        "mean": sum(s) // len(s),
    }

# Per-source-shard summary (sorted by admitted DESC, then shard ASC).
by_source_out = []
for src in sorted(by_source.keys(),
                  key=lambda d: (-by_source[d]["admitted"], d)):
    agg = by_source[src]
    ss = sorted(agg["ages"])
    by_source_out.append({
        "shard":   src,
        "admitted": agg["admitted"],
        "p50_age": pct(ss, 50) if ss else None,
        "max_age": ss[-1] if ss else None,
    })

# Bound rosters for renderer + JSON.
high_age.sort(key=lambda r: -r["age"])
below_floor.sort(key=lambda r: r["age"])
negative.sort(key=lambda r: r["age"])

result = {
    "admitted_count": admitted_count,
    "age":            age_stats,
    "by_source":      by_source_out,
    "high_age":       high_age[:50],
    "below_floor":    below_floor[:50],
    "negative":       negative[:50],
    "soak_floor":     CROSS_SHARD_RECEIPT_LATENCY,
    "age_budget":     age_budget,
    "floor_strict":   floor_strict,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_inbound_admission_age: local block walk failed" >&2
  exit 1
fi

WALK_JSON=$(cat "$TMP_OUT")

# Pull scalars back out for the anomaly gate + shell-side reporting.
read ADMITTED HIGH_N BELOW_N NEG_N AGE_BUDGET <<EOF
$(printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
w = json.load(sys.stdin)
print(w['admitted_count'], len(w['high_age']), len(w['below_floor']),
      len(w['negative']), w['age_budget'])
")
EOF
for v in ADMITTED HIGH_N BELOW_N NEG_N AGE_BUDGET; do
  eval "val=\$$v"
  case "$val" in *[!0-9]*|"") eval "$v=0" ;; esac
done

# ── Step 3: collect anomalies ────────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
[ "$HIGH_N" -gt 0 ] && add_anom "admission_age_high"
[ "$NEG_N"  -gt 0 ] && add_anom "admission_age_negative"
# below-floor is an anomaly only under --floor-strict (soft otherwise).
if [ "$BELOW_N" -gt 0 ] && [ "$FLOOR_STRICT" = "1" ]; then
  add_anom "admission_below_soak_floor"
fi

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 4: render ───────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  "$PY" - "$WALK_JSON" "$MY_SHARD_ID" "$SHARDING_MODE" \
        "$FROM" "$TO" "$WIN_BLOCKS" "$ANOMALIES" "$PORT" <<'PY'
import json, sys
walk = json.loads(sys.argv[1])
envelope = {
    "skipped":        False,
    "my_shard_id":    int(sys.argv[2]),
    "sharding_mode":  sys.argv[3],
    "window":         {"from": int(sys.argv[4]),
                       "to":   int(sys.argv[5]),
                       "blocks": int(sys.argv[6])},
    "admitted_count": walk["admitted_count"],
    "age":            walk["age"],
    "by_source":      walk["by_source"],
    "high_age":       walk["high_age"],
    "below_floor":    walk["below_floor"],
    "negative":       walk["negative"],
    "soak_floor":     walk["soak_floor"],
    "age_budget":     walk["age_budget"],
    "floor_strict":   walk["floor_strict"],
    "anomalies":      ([a for a in sys.argv[7].split(",") if a]
                       if sys.argv[7] else []),
    "rpc_port":       int(sys.argv[8]),
}
print(json.dumps(envelope))
PY
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_inbound_admission_age: no anomalies (port $PORT, shard $MY_SHARD_ID, window [$FROM..$TO], $ADMITTED admitted)"
  else
    echo "=== Inbound cross-shard receipt admission age (port $PORT, shard $MY_SHARD_ID) ==="
    echo "Sharding mode: $SHARDING_MODE; soak floor: CROSS_SHARD_RECEIPT_LATENCY=3; high-age budget: 3 + slack = $AGE_BUDGET blocks"
    echo "Window: blocks [$FROM..$TO] ($WIN_BLOCKS blocks)    Admitted inbound receipts: $ADMITTED"

    if [ "$ANOM_ONLY" != "1" ]; then
      # Age distribution.
      printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
w = json.load(sys.stdin)
a = w['age']
if a is None:
    print('Admission-age distribution: (no admitted inbound receipts in window)')
else:
    print(f\"Admission-age distribution (blocks, source-emit -> local-admit): min={a['min']} p50={a['p50']} p95={a['p95']} max={a['max']} mean={a['mean']}\")
"
      # Per-source-shard table.
      printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
w = json.load(sys.stdin)
bs = w['by_source']
if bs:
    print('Per-source shard (top 10):')
    for r in bs[:10]:
        p50 = r['p50_age']; mx = r['max_age']
        p50s = f'{p50}' if p50 is not None else '-'
        mxs  = f'{mx}'  if mx  is not None else '-'
        print(f\"  src shard {r['shard']}: admitted={r['admitted']} p50_age={p50s} max_age={mxs}\")
else:
    print('Per-source shard: (no admitted inbound receipts in window)')
"
    fi

    # Anomaly diagnostics.
    if [ "$HIGH_N" -gt 0 ]; then
      echo "High-age check: $HIGH_N admitted receipt(s) exceeded the $AGE_BUDGET-block budget (top 5):"
      printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
for r in json.load(sys.stdin)['high_age'][:5]:
    th = r['tx_hash']; th = th[:16] + '...' if len(th) > 16 else th
    print(f\"  high-age: src_shard={r['src_shard']} src_block={r['src_block_index']} landing={r['landing_index']} age={r['age']} tx={th}\")
"
    else
      echo "High-age check: OK (all admitted receipts within budget)"
    fi

    if [ "$BELOW_N" -gt 0 ]; then
      if [ "$FLOOR_STRICT" = "1" ]; then
        echo "Soak-floor check: TRIPPED (--floor-strict) — $BELOW_N receipt(s) admitted with age < 3 (top 5):"
      else
        echo "Soak-floor check: SOFT-NOTICE — $BELOW_N receipt(s) admitted with age < 3 (independent per-shard clocks; not a proven bug; top 5):"
      fi
      printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
for r in json.load(sys.stdin)['below_floor'][:5]:
    th = r['tx_hash']; th = th[:16] + '...' if len(th) > 16 else th
    print(f\"  below-floor: src_shard={r['src_shard']} src_block={r['src_block_index']} landing={r['landing_index']} age={r['age']} tx={th}\")
"
    else
      echo "Soak-floor check: OK (no receipts admitted below the 3-block floor)"
    fi

    if [ "$NEG_N" -gt 0 ]; then
      echo "Negative-age check: CATASTROPHIC — $NEG_N receipt(s) with src_block_index > landing index (index/chain corruption):"
      printf '%s' "$WALK_JSON" | "$PY" -c "
import sys, json
for r in json.load(sys.stdin)['negative'][:5]:
    th = r['tx_hash']; th = th[:16] + '...' if len(th) > 16 else th
    print(f\"  neg-age: src_shard={r['src_shard']} src_block={r['src_block_index']} landing={r['landing_index']} age={r['age']} tx={th}\")
"
    else
      echo "Negative-age check: OK (no negative admission ages)"
    fi

    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] inbound admission age healthy"
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
