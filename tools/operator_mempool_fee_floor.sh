#!/usr/bin/env bash
# operator_mempool_fee_floor.sh — S-008 mempool fee-floor / eviction-
# survival admission-pressure report.
#
# Answers the question neither sibling mempool tool addresses: under
# mempool pressure, WHAT FEE does an incoming transaction need to clear
# admission, and how many recently-accepted transactions are
# eviction-vulnerable at the fee floor?
#
# ── Why this is distinct from the existing mempool tools ──────────────
#   - operator_mempool_diagnostic.sh / operator_mempool_inspector.sh are
#     forward-staged for a per-tx `mempool` RPC that the daemon does NOT
#     expose today (the only mempool-visible field is the scalar
#     `mempool_size` inside the `status` RPC; the per-tx pool is
#     node-internal — see src/rpc/rpc.cpp dispatch(), which has no
#     `mempool` method). They focus on depth / age / sender-concentration
#     / nonce-gaps.
#   - operator_fee_distribution_audit.sh analyzes fee ATTRIBUTION to
#     creators (the recipient side: who collects fees, concentration,
#     collection drop).
#   This tool analyzes the fee distribution from the S-008 ADMISSION
#   side: the empirical fee floor, fee headroom needed to survive
#   eviction, and the eviction-vulnerable fraction of accepted traffic.
#
# ── What S-008 admission actually does (the mechanism modeled here) ────
# When the mempool is at MEMPOOL_MAX_TXS (10000), the admission gate
# (src/node/node.cpp::mempool_admit_check + mempool_make_room_for)
# rejects any incoming tx whose `fee` is <= the current minimum fee in
# the pool, and otherwise evicts the lowest-fee incumbent to make room.
# That makes the per-tx fee a priority key under pressure: a tx at the
# fee floor is the first to be evicted and the last to be admitted.
#
# We cannot read the live pool, but we CAN read the fees of transactions
# the chain has ALREADY ACCEPTED (block-info per-tx `fee`). Those
# accepted fees are the best on-chain proxy for the fee distribution the
# producer drains from the mempool. From them we derive:
#   - fee floor (p0/min) + p10 / p25 / p50 / p90 / max percentiles
#   - eviction-vulnerable count: accepted txs sitting AT the window
#     minimum fee (these are the first to be displaced under a full pool)
#   - low-fee-band count: accepted txs at fee <= --eviction-fee
#     (default 1 = the TX_FEE baseline per src/chain/genesis.cpp; a tx at
#     the baseline can be displaced by any tx paying baseline+1)
#   - survival fee: floor + 1 — the minimum fee an incoming tx must pay
#     to GUARANTEE it can evict the cheapest incumbent (fee strictly
#     greater than the current minimum, per mempool_make_room_for).
#   - fee uniformity: share of accepted txs at a SINGLE fee value.
#     A pool that is ~100% one fee value has no eviction headroom —
#     every tx is simultaneously the floor and a tie, so admission under
#     pressure degrades to hash tie-break (mempool_make_room_for breaks
#     fee ties deterministically by hash) and NO incoming tx at that same
#     fee can ever be admitted once the pool is full.
#
# Read-only RPC composition; safe against a running daemon. One
# block-info round-trip per block in the window.
#
# ── RPC dependencies (all read-only, all confirmed to exist) ──────────
#   - status              height + mempool_size scalar
#                         (src/node/node.cpp::rpc_status)
#   - head --field height current chain tip (fallback height source)
#   - block-info <h> --json   per-block transactions[] with per-tx `fee`
#                         (src/chain/block.cpp::Transaction::to_json →
#                          j["fee"]); block `timestamp`
# NO per-tx `mempool` RPC is invented or required — this tool deliberately
# scopes itself to on-chain accepted-tx fees, the real admission-side
# signal the live RPC surface exposes.
#
# Usage:
#   tools/operator_mempool_fee_floor.sh [--rpc-port N] [--json]
#                                       [--from H] [--to H]
#                                       [--eviction-fee F]
#                                       [--anomalies-only]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit structured JSON envelope instead of human table
#   --from H            Start of window (default: max(0, tip-1000))
#   --to H              End of window (default: tip)
#   --eviction-fee F    Low-fee band ceiling: count accepted txs with
#                       fee <= F as eviction-vulnerable (default: 1, the
#                       TX_FEE baseline). Such txs cannot survive a full
#                       pool against any tx paying F+1.
#   --anomalies-only    Print only flagged anomalies; exit 2 if any fire
#   -h, --help          Show this help
#
# Anomaly flags (each adds an entry to anomalies[]):
#   - floor_saturation     > 50% of accepted txs sit at the window's
#                          minimum fee. Under a full mempool these are
#                          all first-to-evict AND cannot displace each
#                          other (tie at the floor) — admission would
#                          stall for same-fee traffic. Strong fee-market
#                          flatness / spam-vulnerability signal.
#   - low_fee_dominant     > 80% of accepted txs are in the low-fee band
#                          (fee <= --eviction-fee). The chain is running
#                          almost entirely on minimum-fee traffic; there
#                          is effectively no fee headroom to prioritize
#                          urgent txs under S-008 pressure.
#   - mempool_under_pressure  live status.mempool_size >= 80% of
#                          MEMPOOL_MAX_TXS (10000) AND floor_saturation
#                          also holds. This is the dangerous combination:
#                          the pool is nearly full AND flat, so the next
#                          fee-floor tx is at imminent eviction risk.
#
# Exit codes (mirrors operator_fee_distribution_audit / operator_tx_throughput):
#   0   audit ran successfully, no anomalies (or default informational mode)
#   1   RPC error (daemon up but malformed) / bad args / empty window
#   2   --anomalies-only set AND >= 1 anomaly fired (operator alert gate)
#
# A daemon that is simply UNREACHABLE (down for maintenance) yields a
# clean [SKIP] + exit 0 so a monitoring wrapper doesn't page — same
# convention as operator_escalation_episodes.sh.
set -u

usage() {
  cat <<'EOF'
Usage: operator_mempool_fee_floor.sh [--rpc-port N] [--json]
                                     [--from H] [--to H]
                                     [--eviction-fee F]
                                     [--anomalies-only]

S-008 mempool fee-floor / eviction-survival admission-pressure report.
Computes, from on-chain ACCEPTED transaction fees over a block window,
the empirical fee floor + percentiles, the survival fee an incoming tx
must pay to evict the cheapest incumbent under a full pool, and the
eviction-vulnerable fraction of recent traffic. Cross-checks against
the live status.mempool_size depth versus the S-008 cap (10000).

This is the admission-side counterpart to the depth/age/sender tools:
the daemon exposes NO per-tx mempool RPC, so this tool deliberately
derives the fee-priority signal from accepted-tx fees (block-info),
which is the real signal the producer drains from the mempool.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human table
  --from H            Start of window (default: max(0, tip-1000))
  --to H              End of window (default: tip)
  --eviction-fee F    Low-fee band ceiling (default: 1 = TX_FEE baseline);
                      accepted txs with fee <= F counted as vulnerable
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  -h, --help          Show this help

Anomaly flags:
  floor_saturation        > 50% of accepted txs at the window minimum fee
  low_fee_dominant        > 80% of accepted txs at fee <= --eviction-fee
  mempool_under_pressure  status.mempool_size >= 80% of cap (10000) AND
                          floor_saturation also holds

Exit codes:
  0   success (or informational mode) / clean SKIP if daemon unreachable
  1   RPC error (daemon up but malformed) / bad args / empty window
  2   --anomalies-only AND >= 1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
EVICTION_FEE=1
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";         shift 2 ;;
    --json)            JSON_OUT=1;            shift ;;
    --from)            FROM_H="${2:-}";       shift 2 ;;
    --to)              TO_H="${2:-}";         shift 2 ;;
    --eviction-fee)    EVICTION_FEE="${2:-}"; shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;           shift ;;
    *) echo "operator_mempool_fee_floor: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Numeric guards on user-supplied values ───────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_mempool_fee_floor: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_mempool_fee_floor: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
case "$EVICTION_FEE" in *[!0-9]*|"")
  echo "operator_mempool_fee_floor: --eviction-fee must be a non-negative integer (got '$EVICTION_FEE')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# S-008 compile-time cap; mirrors include/determ/node/node.hpp::MEMPOOL_MAX_TXS.
# Used to compute the live pressure ratio for the mempool_under_pressure flag.
MEMPOOL_MAX_TXS=10000
PRESSURE_WARN_PCT=80      # status.mempool_size >= 80% of cap = "under pressure"
FLOOR_SATURATION_PCT=50   # > 50% of accepted txs at the floor fee
LOW_FEE_DOMINANT_PCT=80   # > 80% of accepted txs in the low-fee band

# Resolve DETERM to an absolute path so Python's subprocess.run (which on
# Windows uses CreateProcessW and does not honor the inherited bash cwd
# the way exec*() does) can locate the binary. Same idiom as
# operator_block_size_audit.sh.
case "$DETERM" in
  /*|[A-Za-z]:/*|[A-Za-z]:\\*) DETERM_ABS="$DETERM" ;;
  *) DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
esac

# Pick a python interpreter (python3 preferred, python fallback).
if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python  >/dev/null 2>&1; then PY=python
else
  echo "operator_mempool_fee_floor: [SKIP] no python interpreter found (need python3/python)"
  exit 0
fi

# ── Step 1: resolve chain head + live mempool depth (clean SKIP if down) ─────
# Prefer `status` (carries BOTH height and mempool_size in one round-trip).
# An unreachable daemon yields a clean SKIP (exit 0) so a monitoring
# wrapper run against a node down for maintenance doesn't page —
# distinguishing "daemon down" (informational) from "daemon up but
# malformed" (error). Same convention as operator_escalation_episodes.sh.
STATUS_JSON=$("$DETERM" status --rpc-port "$PORT" 2>/dev/null)
if [ -z "$STATUS_JSON" ]; then
  echo "operator_mempool_fee_floor: [SKIP] daemon unreachable on rpc-port $PORT (no status response)"
  exit 0
fi

# Extract height + mempool_size from the status JSON.
STATUS_PARSE=$(printf '%s' "$STATUS_JSON" | "$PY" -c "
import sys, json
try:
    j = json.load(sys.stdin)
    h = j.get('height')
    m = j.get('mempool_size', 0)
    print(f\"{int(h) if h is not None else ''}\t{int(m) if m is not None else 0}\")
except Exception:
    print('\t0')
")
HEAD_H=$(printf '%s' "$STATUS_PARSE" | cut -f1)
MEMPOOL_SIZE=$(printf '%s' "$STATUS_PARSE" | cut -f2)

# Fall back to head --field height if status didn't carry a usable height.
if [ -z "$HEAD_H" ]; then
  HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null || echo "")
fi
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_mempool_fee_floor: malformed status/head response (height='$HEAD_H', port $PORT)" >&2
  exit 1 ;;
esac
case "$MEMPOOL_SIZE" in *[!0-9]*|"") MEMPOOL_SIZE=0 ;; esac

if [ "$HEAD_H" = "0" ]; then
  echo "operator_mempool_fee_floor: chain is empty (height=0); nothing to audit" >&2
  exit 1
fi

# ── Step 2: resolve window ───────────────────────────────────────────────────
# Default: last 1000 blocks ending at tip (matches sibling fee/throughput tools).
FROM=${FROM_H:-$(( HEAD_H > 1000 ? HEAD_H - 1000 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_mempool_fee_floor: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 3: walk window + aggregate accepted-tx fee distribution ─────────────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_mempool_fee_floor: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

"$PY" - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_OUT" \
       "$EVICTION_FEE" "$MEMPOOL_SIZE" "$MEMPOOL_MAX_TXS" \
       "$PRESSURE_WARN_PCT" "$FLOOR_SATURATION_PCT" "$LOW_FEE_DOMINANT_PCT" <<'PY'
import json, subprocess, sys
from collections import Counter

(determ, port, from_h_s, to_h_s, out_path, evict_fee_s, mempool_size_s,
 cap_s, pressure_pct_s, floor_sat_pct_s, low_fee_pct_s) = sys.argv[1:12]
from_h         = int(from_h_s)
to_h           = int(to_h_s)
evict_fee      = int(evict_fee_s)
mempool_size   = int(mempool_size_s)
cap            = int(cap_s)
pressure_pct   = int(pressure_pct_s)
floor_sat_pct  = int(floor_sat_pct_s)
low_fee_pct    = int(low_fee_pct_s)

fees           = []            # every accepted tx fee in the window
fee_counter    = Counter()     # fee value -> count (uniformity + floor share)
blocks_seen    = 0
blocks_with_tx = 0

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_mempool_fee_floor: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        # Tail-boundary / sparse-chain holes are non-fatal; skip the height.
        continue
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_mempool_fee_floor: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue
    blocks_seen += 1
    txs = blk.get("transactions") or []
    if not isinstance(txs, list):
        continue
    block_has_tx = False
    for tx in txs:
        if not isinstance(tx, dict):
            continue
        fee = tx.get("fee", 0)
        try:
            fee = int(fee)
        except Exception:
            continue
        if fee < 0:
            continue
        fees.append(fee)
        fee_counter[fee] += 1
        block_has_tx = True
    if block_has_tx:
        blocks_with_tx += 1

total_tx = len(fees)

def pct_index(sorted_vals, p):
    # Nearest-rank percentile (p in [0,100]); returns value at the rank.
    if not sorted_vals:
        return 0
    if p <= 0:
        return sorted_vals[0]
    if p >= 100:
        return sorted_vals[-1]
    # rank = ceil(p/100 * n); 1-based -> 0-based index.
    import math
    rank = max(1, math.ceil(p / 100.0 * len(sorted_vals)))
    return sorted_vals[min(rank, len(sorted_vals)) - 1]

if total_tx > 0:
    sfees = sorted(fees)
    floor_fee = sfees[0]
    max_fee   = sfees[-1]
    p10 = pct_index(sfees, 10)
    p25 = pct_index(sfees, 25)
    p50 = pct_index(sfees, 50)
    p90 = pct_index(sfees, 90)
    total_fee = sum(fees)
    avg_fee   = total_fee // total_tx
    # survival fee = floor + 1: the minimum an incoming tx must pay to be
    # STRICTLY greater than the current minimum, hence able to evict the
    # cheapest incumbent under a full pool (mempool_make_room_for requires
    # tx.fee > min incumbent fee).
    survival_fee = floor_fee + 1
    # eviction-vulnerable: accepted txs sitting AT the window floor fee.
    at_floor_count = fee_counter.get(floor_fee, 0)
    # low-fee band: accepted txs with fee <= --eviction-fee.
    low_band_count = sum(c for f, c in fee_counter.items() if f <= evict_fee)
    # fee uniformity: the single most common fee value + its share.
    top_fee_val, top_fee_count = fee_counter.most_common(1)[0]
    distinct_fees = len(fee_counter)
else:
    floor_fee = max_fee = p10 = p25 = p50 = p90 = 0
    total_fee = avg_fee = survival_fee = 0
    at_floor_count = low_band_count = 0
    top_fee_val = top_fee_count = distinct_fees = 0

# Shares in basis points (integer; avoids float round-trip through shell).
def bps(n, d):
    return (n * 10000) // d if d > 0 else 0

floor_share_bps   = bps(at_floor_count, total_tx)
low_band_bps      = bps(low_band_count, total_tx)
top_fee_share_bps = bps(top_fee_count, total_tx)
pressure_bps      = bps(mempool_size, cap)

# ── Anomaly classification ───────────────────────────────────────────────────
anomalies = []
floor_saturation = (total_tx > 0 and floor_share_bps > floor_sat_pct * 100)
if floor_saturation:
    anomalies.append("floor_saturation")
if total_tx > 0 and low_band_bps > low_fee_pct * 100:
    anomalies.append("low_fee_dominant")
# mempool_under_pressure = pool nearly full AND flat at the floor.
mempool_pressure = (cap > 0 and pressure_bps >= pressure_pct * 100)
if mempool_pressure and floor_saturation:
    anomalies.append("mempool_under_pressure")

# Fee-distribution histogram: top-8 fee values by count (descending),
# for the human table. Ties broken by fee value ascending for determinism.
top_fee_hist = sorted(
    fee_counter.items(), key=lambda kv: (-kv[1], kv[0])
)[:8]

result = {
    "window":            {"from": from_h, "to": to_h, "blocks": to_h - from_h + 1},
    "blocks_seen":       blocks_seen,
    "blocks_with_tx":    blocks_with_tx,
    "total_tx":          total_tx,
    "total_fee":         total_fee,
    "avg_fee":           avg_fee,
    "floor_fee":         floor_fee,
    "survival_fee":      survival_fee,
    "max_fee":           max_fee,
    "percentiles":       {"p10": p10, "p25": p25, "p50": p50, "p90": p90},
    "distinct_fee_values": distinct_fees,
    "at_floor_count":    at_floor_count,
    "floor_share_bps":   floor_share_bps,
    "eviction_fee_band": evict_fee,
    "low_band_count":    low_band_count,
    "low_band_share_bps": low_band_bps,
    "top_fee_value":     top_fee_val,
    "top_fee_count":     top_fee_count,
    "top_fee_share_bps": top_fee_share_bps,
    "top_fee_histogram": [{"fee": f, "count": c} for f, c in top_fee_hist],
    "live_mempool_size": mempool_size,
    "mempool_cap":       cap,
    "pressure_bps":      pressure_bps,
    "anomalies":         anomalies,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_mempool_fee_floor: block-walk aggregation failed" >&2
  exit 1
fi

# ── Step 4: render envelope (JSON or human) + exit-code policy ───────────────
"$PY" - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$HEAD_H" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]
port      = int(sys.argv[4])
head_h    = int(sys.argv[5])

with open(out_path, "r", encoding="utf-8") as f:
    r = json.load(f)

anomalies  = r["anomalies"]
anom_count = len(anomalies)

def pct(bps):
    whole = bps // 100
    frac  = (bps % 100) // 10
    return f"{whole}.{frac}%"

if json_out:
    envelope = dict(r)
    envelope["rpc_port"]    = port
    envelope["head_height"] = head_h
    print(json.dumps(envelope))
    # Exit code resolved by the shell wrapper below via a sentinel file;
    # here we just emit. The shell re-reads anomalies for the 0/2 gate.
    sys.exit(0)

# Human-readable layout.
if anom_only and anom_count == 0:
    win = r["window"]
    print(f"operator_mempool_fee_floor: no anomalies "
          f"(port {port}, window [{win['from']}..{win['to']}])")
    sys.exit(0)

win = r["window"]
print(f"=== Mempool fee-floor / eviction-survival (port {port}, "
      f"window [{win['from']}..{win['to']}]) ===")
print(f"Chain height:        {head_h}")
print(f"Accepted txs:        {r['total_tx']} "
      f"over {r['blocks_with_tx']}/{r['blocks_seen']} fee-bearing blocks")
if r["total_tx"] == 0:
    print("No accepted transactions in window; fee-floor analysis N/A.")
else:
    p = r["percentiles"]
    print(f"Fee floor (min):     {r['floor_fee']}")
    print(f"Survival fee (+1):   {r['survival_fee']}  "
          f"(min fee to evict cheapest incumbent under a full pool)")
    print(f"Fee percentiles:     p10={p['p10']} p25={p['p25']} "
          f"p50={p['p50']} p90={p['p90']} max={r['max_fee']}")
    print(f"Average fee:         {r['avg_fee']}")
    print(f"Distinct fee values: {r['distinct_fee_values']}")
    if not anom_only:
        print(f"At-floor txs:        {r['at_floor_count']} "
              f"({pct(r['floor_share_bps'])} of accepted) — first-to-evict band")
        print(f"Low-fee band (<= {r['eviction_fee_band']}): "
              f"{r['low_band_count']} ({pct(r['low_band_share_bps'])} of accepted)")
        print(f"Most common fee:     {r['top_fee_value']} "
              f"({pct(r['top_fee_share_bps'])} of accepted)")
        hist = r["top_fee_histogram"]
        if hist:
            print("Fee histogram (top values by count):")
            for e in hist:
                share = pct((e["count"] * 10000) // r["total_tx"]) \
                        if r["total_tx"] > 0 else "0.0%"
                print(f"  fee {e['fee']:>10}: {e['count']:>8} ({share})")
    # Live pool pressure cross-check.
    print(f"Live mempool depth:  {r['live_mempool_size']} / {r['mempool_cap']} "
          f"({pct(r['pressure_bps'])} of S-008 cap)")

print()
if anom_count == 0:
    print("[OK] Fee floor healthy — eviction headroom present, pool not flat under pressure")
else:
    print(f"[ANOMALY] {anom_count} flag(s): {','.join(anomalies)}")
    if "floor_saturation" in anomalies:
        print(f"  floor_saturation       : {pct(r['floor_share_bps'])} of accepted txs "
              f"sit at the floor fee ({r['floor_fee']}) — these are all "
              "first-to-evict AND tie at the floor, so same-fee traffic "
              "stalls admission once the pool fills")
    if "low_fee_dominant" in anomalies:
        print(f"  low_fee_dominant       : {pct(r['low_band_share_bps'])} of accepted txs "
              f"pay <= {r['eviction_fee_band']} (low-fee band) — no fee headroom "
              "to prioritize urgent txs under S-008 pressure")
    if "mempool_under_pressure" in anomalies:
        print(f"  mempool_under_pressure : live depth {r['live_mempool_size']} = "
              f"{pct(r['pressure_bps'])} of cap AND fee floor is saturated — "
              "imminent eviction risk for the next fee-floor tx")
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_mempool_fee_floor: rendering failed" >&2
  exit 1
fi

# ── Step 5: exit-code policy ─────────────────────────────────────────────────
# Mirrors operator_fee_distribution_audit / operator_tx_throughput: exit 2
# only when --anomalies-only is set AND >= 1 anomaly fired. Default
# informational mode always exits 0 on a clean RPC pipeline. Re-read the
# anomaly count from the temp payload (works for both JSON + human paths).
ANOM_COUNT=$("$PY" -c "
import json, sys
try:
    with open('$TMP_OUT', 'r', encoding='utf-8') as f:
        print(len(json.load(f).get('anomalies', [])))
except Exception:
    print(0)
")
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac

if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
