#!/usr/bin/env bash
# operator_block_fullness_audit.sh — Audit per-block CAPACITY UTILIZATION
# (block fullness) across a window of finalized blocks on a running determ
# daemon. Answers the operator question:
#   "How FULL are my blocks? What share carry zero txs (empty-block rate),
#    what's the fill distribution against a soft per-block capacity, and is
#    saturation TRENDING UP (chain approaching its tx-per-block ceiling) or
#    sitting idle?"
#
# Fullness is measured as block.transactions count vs a SOFT per-block
# capacity target (--capacity, default 1000 txs). See the "Capacity model"
# note below — there is NO hard per-block tx-count cap constant in the
# determ source, so the capacity here is an operator-supplied planning
# target, not a protocol limit.
#
# Read-only RPC composition; safe against a running daemon. The daemon
# must already be listening on --rpc-port. This tool never sends a tx and
# never writes chain/snapshot files.
#
# ── Data source (verified against src) ────────────────────────────────────────
# Per-block tx count comes from the `block` RPC, surfaced via the
# `determ block-info <i> --json` CLI (same access path the sibling
# capacity tools use):
#   - Block::to_json emits `index` (src/chain/block.cpp:369),
#     `timestamp` (src/chain/block.cpp:371), and the `transactions` array
#     (src/chain/block.cpp:374-375). n_tx = len(transactions).
#   - The `block` RPC returns the full Block JSON, or null when the index
#     is at/above chain height (Node::rpc_block, src/node/node.cpp:2617-2620).
#   - The `status` RPC returns `height` (Node::rpc_status,
#     src/node/node.cpp:2464); `determ head --field height` reads it
#     (src/main.cpp:2692-2727 -> cmd_head calls the status RPC).
#   - `determ block-info <i> --json` prints the block RPC JSON envelope
#     (src/main.cpp:2791-2860 -> cmd_block_info).
#
# ── Capacity model (IMPORTANT — soft target, not a protocol cap) ──────────────
# determ has no MAX_BLOCK_TX / max_txs_per_block constant: the producer
# assembles a block from the mempool with no hard tx-count ceiling (the
# only enforced ceiling is the S-022 wire-byte cap on the encoded BLOCK
# message at Peer::read_body, which operator_block_size_audit.sh covers).
# So "fullness %" here is len(transactions) / --capacity, where --capacity
# is an operator planning target (default 1000). It is a UTILIZATION proxy
# for "are blocks getting close to the size at which I'd want to act
# (raise fees / shard / scale)", NOT a claim about a hard chain limit.
# Operators on a deployment with a known practical fill target should pass
# --capacity to match it. The empty-block rate and the early-vs-late
# fullness TREND are capacity-independent and meaningful regardless.
#
# ── Why this tool exists (sibling positioning — the uncovered gap) ────────────
# The capacity/throughput lane already has three tools, each answering a
# DIFFERENT question; none computes per-block fill utilization:
#
#   operator_block_size_audit.sh
#       BYTE size distribution (JSON-envelope length as a proxy) vs the
#       S-022 wire-BYTE cap. It does tally an `empty_blocks` COUNT as a
#       byte-audit aside, but it has NO empty-block RATE verdict, NO
#       per-block tx-COUNT fill ratio against a capacity target, and NO
#       early-vs-late saturation TREND. Bytes != tx-count fill: a window
#       of fat DAPP_CALL blocks can be byte-heavy yet low-tx-count, and a
#       window of tiny STAKE txs can be tx-count-full yet byte-light.
#       THIS tool measures the tx-count fill axis that one omits.
#
#   operator_tx_throughput.sh
#       TPS = total_txs / window_seconds (a RATE over wall-clock time). A
#       chain can run high TPS with half-empty blocks (fast cadence) or
#       low TPS with brim-full blocks (slow cadence). Fullness is the
#       per-block fill independent of cadence — orthogonal to TPS.
#
#   operator_tx_mix_trend.sh
#       Transaction-TYPE composition shift (what KIND of tx), not how MANY
#       per block.
#
#   operator_block_cadence_regularity.sh / operator_consensus_latency.sh
#       Inter-block TIMING (jitter / latency) — the time axis, not fill.
#
# This tool fills the per-block tx-count UTILIZATION gap with four signals
# the others don't compute:
#   (1) Empty-block rate — fraction of blocks with zero txs. High empty
#       rate on a network that's supposed to be carrying load is a demand
#       or mempool-admission anomaly.
#   (2) Fullness distribution — mean / p50 / p90 / max fill % vs --capacity.
#   (3) Saturation pressure — count of blocks at/over a high-water mark
#       (--saturated-pct of capacity, default 90%).
#   (4) Fullness TREND — mean fill of the early window half vs the late
#       half, surfacing a chain DRIFTING toward saturation (capacity
#       planning early-warning) or going idle.
#
# ── Anomaly flags (each adds an entry to anomalies[]) ─────────────────────────
#   empty_block_rate_high   empty-block fraction > --max-empty-pct (default 50%)
#   saturation_pressure     >= 1 block at/over --saturated-pct of --capacity
#   fullness_rising         late-half mean fill exceeds early-half mean fill
#                           by more than --trend-delta-pct points (default 25)
#                           AND late-half mean fill >= --saturated-pct/2
#                           (drift toward saturation, not just noise near 0)
#
# ── Exit codes ────────────────────────────────────────────────────────────────
#   0   fullness measured, no anomalies (or default informational mode);
#       also clean SKIP when the daemon is unreachable or the chain has no
#       produced blocks
#   1   bad args / RPC-parse error / malformed response / empty window
#   2   --anomalies-only set AND >= 1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_block_fullness_audit.sh [--rpc-port N] [--json]
                                        [--from H] [--to H] [--last-n N]
                                        [--capacity T]
                                        [--saturated-pct P]
                                        [--max-empty-pct P]
                                        [--trend-delta-pct P]
                                        [--anomalies-only]

Audit per-block transaction-count CAPACITY UTILIZATION (block fullness)
across a window of finalized blocks. Walks the window via block-info,
counts txs per block, and reports empty-block rate, fill distribution vs
a SOFT per-block capacity target, saturation-pressure count, and an
early-vs-late fullness trend.

NOTE: --capacity is an operator planning target, NOT a protocol limit.
determ enforces no hard per-block tx-count cap (only the S-022 wire-byte
cap, which operator_block_size_audit.sh covers). Fullness % = txs /
capacity is a utilization proxy. Empty-block rate and the fullness trend
are capacity-independent.

Options:
  --rpc-port N         RPC port to query (default: 7778)
  --json               Emit structured JSON envelope instead of human text
  --from H             Start block index (default: max(0, tip - 1000))
  --to H               End block index inclusive (default: tip)
  --last-n N           Audit the last N produced blocks (overrides --from)
  --capacity T         Soft per-block tx-count capacity target (default: 1000)
  --saturated-pct P    High-water mark as % of capacity (default: 90)
  --max-empty-pct P    Empty-block-rate anomaly threshold % (default: 50)
  --trend-delta-pct P  Rising-fullness anomaly threshold, points (default: 25)
  --anomalies-only     Print only anomalies; exit 2 if any fire
  -h, --help           Show this help

Anomaly flags:
  empty_block_rate_high  empty-block fraction > --max-empty-pct
  saturation_pressure    >= 1 block at/over --saturated-pct of --capacity
  fullness_rising        late-half mean fill exceeds early-half by more than
                         --trend-delta-pct points (drift toward saturation)

Exit codes:
  0   success / informational / clean SKIP (daemon unreachable or no blocks)
  1   bad args / RPC error / malformed response / empty window
  2   --anomalies-only AND >= 1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
LAST_N=""
CAPACITY=1000
SATURATED_PCT=90
MAX_EMPTY_PCT=50
TREND_DELTA_PCT=25

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)           usage; exit 0 ;;
    --rpc-port)          PORT="${2-}";            shift 2 ;;
    --json)              JSON_OUT=1;              shift ;;
    --from)              FROM_H="${2-}";          shift 2 ;;
    --to)                TO_H="${2-}";            shift 2 ;;
    --last-n)            LAST_N="${2-}";          shift 2 ;;
    --capacity)          CAPACITY="${2-}";        shift 2 ;;
    --saturated-pct)     SATURATED_PCT="${2-}";   shift 2 ;;
    --max-empty-pct)     MAX_EMPTY_PCT="${2-}";   shift 2 ;;
    --trend-delta-pct)   TREND_DELTA_PCT="${2-}"; shift 2 ;;
    --anomalies-only)    ANOM_ONLY=1;             shift ;;
    *) echo "operator_block_fullness_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Numeric guards ────────────────────────────────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_block_fullness_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for pair in "from:$FROM_H" "to:$TO_H" "last-n:$LAST_N"; do
  name="${pair%%:*}"; val="${pair#*:}"
  if [ -n "$val" ]; then
    case "$val" in *[!0-9]*)
      echo "operator_block_fullness_audit: --$name must be an unsigned integer (got '$val')" >&2
      exit 1 ;;
    esac
  fi
done
case "$CAPACITY" in *[!0-9]*|"")
  echo "operator_block_fullness_audit: --capacity must be a positive integer (got '$CAPACITY')" >&2
  exit 1 ;;
esac
if [ "$CAPACITY" -lt 1 ]; then
  echo "operator_block_fullness_audit: --capacity must be >= 1 (got '$CAPACITY')" >&2
  exit 1
fi
for pair in "saturated-pct:$SATURATED_PCT" "max-empty-pct:$MAX_EMPTY_PCT" "trend-delta-pct:$TREND_DELTA_PCT"; do
  name="${pair%%:*}"; val="${pair#*:}"
  case "$val" in *[!0-9]*|"")
    echo "operator_block_fullness_audit: --$name must be an integer 0..100 (got '$val')" >&2
    exit 1 ;;
  esac
  if [ "$val" -gt 100 ]; then
    echo "operator_block_fullness_audit: --$name must be <= 100 (got '$val')" >&2
    exit 1
  fi
done
if [ -n "$LAST_N" ] && [ "$LAST_N" -lt 1 ]; then
  echo "operator_block_fullness_audit: --last-n must be >= 1 (got '$LAST_N')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python behaves
# identically on Linux/Mac/Git Bash (mirrors operator_tx_mix_trend.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve current tip ───────────────────────────────────────────────
# SKIP (exit 0 + INFO) when the daemon is unreachable, matching the
# clean-skip behavior of operator_tx_mix_trend.sh / operator_reward_budget.sh.
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  if [ "$JSON_OUT" -eq 1 ]; then
    echo '{"skipped":true,"reason":"daemon unreachable","rpc_port":'"$PORT"'}'
  else
    echo "operator_block_fullness_audit: INFO daemon unreachable on rpc-port $PORT; nothing to audit (SKIP)"
  fi
  exit 0
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_block_fullness_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Empty chain (genesis only): no produced blocks to audit. INFO + SKIP.
if [ "$HEAD_H" -le 1 ]; then
  if [ "$JSON_OUT" -eq 1 ]; then
    echo '{"skipped":true,"reason":"no produced blocks","height":'"$HEAD_H"'}'
  else
    echo "operator_block_fullness_audit: INFO chain has no produced blocks (height=$HEAD_H); nothing to audit (SKIP)"
  fi
  exit 0
fi

# ── Step 2: resolve window bounds ─────────────────────────────────────────────
# `head --field height` returns total block count (block 0 = genesis;
# highest valid index = height - 1). Mirrors operator_tx_mix_trend.sh.
TOP=$(( HEAD_H > 0 ? HEAD_H - 1 : 0 ))
if [ -n "$LAST_N" ]; then
  FROM=$(( TOP - LAST_N + 1 ))
  if [ "$FROM" -lt 0 ]; then FROM=0; fi
  TO=$TOP
else
  FROM=${FROM_H:-$(( TOP > 1000 ? TOP - 1000 : 0 ))}
  TO=${TO_H:-$TOP}
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_block_fullness_audit: --from ($FROM) > --to ($TO); empty window" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 3: walk window + compute fullness stats in one Python pass ───────────
# Python driver: for each block-info JSON, count len(transactions), then
# compute empty-block rate, fill distribution vs --capacity, saturation
# count, and the early-vs-late half-window fullness trend.
#
# Output (single TSV summary line to TMP_STATS):
#   blocks  empty  total_txs  max_txs  mean_milli  p50_milli  p90_milli
#     saturated  early_mean_milli  late_mean_milli
# where *_milli = (value * 1000) rounded, so floats round-trip through the
# shell as integers (TPS-tool convention). Fill percentages are derived in
# shell from txs/capacity.
TMP_STATS=$(mktemp 2>/dev/null) || {
  echo "operator_block_fullness_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_STATS" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_STATS" <<'PYEOF'
import sys, json, subprocess

determ, port, from_s, to_s, out_path = sys.argv[1:6]
from_h, to_h = int(from_s), int(to_s)

tx_counts = []
empty = 0
total_txs = 0
max_txs = 0

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_block_fullness_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_block_fullness_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_block_fullness_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        # Defensive: out-of-range yields null -> not a dict. Skip silently.
        continue
    txs = blk.get("transactions") or []
    if not isinstance(txs, list):
        txs = []
    n = len(txs)
    tx_counts.append(n)
    total_txs += n
    if n == 0:
        empty += 1
    if n > max_txs:
        max_txs = n

blocks = len(tx_counts)
if blocks == 0:
    sys.stderr.write("operator_block_fullness_audit: window produced no blocks\n")
    sys.exit(1)

def pct(sorted_vals, q):
    # Nearest-rank percentile (q in [0,100]).
    if not sorted_vals:
        return 0
    idx = int(round((q / 100.0) * (len(sorted_vals) - 1)))
    if idx < 0: idx = 0
    if idx >= len(sorted_vals): idx = len(sorted_vals) - 1
    return sorted_vals[idx]

srt = sorted(tx_counts)
mean = total_txs / blocks
p50 = pct(srt, 50)
p90 = pct(srt, 90)

# Early vs late half-window means (trend). Split by position in the walked
# order (chronological since indices ascend). Odd block goes to early half.
half = blocks // 2
early = tx_counts[:blocks - half]   # first ceil(n/2)
late = tx_counts[blocks - half:]    # last floor(n/2)
early_mean = (sum(early) / len(early)) if early else 0.0
late_mean = (sum(late) / len(late)) if late else 0.0

def milli(x):
    return int(round(x * 1000))

with open(out_path, "w") as f:
    # Saturation count is capacity-dependent (a shell-side knob), so it is
    # computed in a separate count-only walk after this pass — not emitted
    # here. This line carries only capacity-independent distribution stats.
    f.write("\t".join(str(v) for v in [
        blocks, empty, total_txs, max_txs,
        milli(mean), p50, p90,
        milli(early_mean), milli(late_mean),
    ]) + "\n")
PYEOF

PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  echo "operator_block_fullness_audit: block walk failed (rc=$PY_RC)" >&2
  exit 1
fi

STATS_LINE=$(head -n1 "$TMP_STATS" 2>/dev/null)
if [ -z "$STATS_LINE" ]; then
  echo "operator_block_fullness_audit: no stats produced for window [$FROM..$TO]" >&2
  exit 1
fi

BLOCKS=$(printf '%s' "$STATS_LINE" | cut -f1)
EMPTY=$(printf '%s' "$STATS_LINE" | cut -f2)
TOTAL_TXS=$(printf '%s' "$STATS_LINE" | cut -f3)
MAX_TXS=$(printf '%s' "$STATS_LINE" | cut -f4)
MEAN_MILLI=$(printf '%s' "$STATS_LINE" | cut -f5)
P50=$(printf '%s' "$STATS_LINE" | cut -f6)
P90=$(printf '%s' "$STATS_LINE" | cut -f7)
EARLY_MILLI=$(printf '%s' "$STATS_LINE" | cut -f8)
LATE_MILLI=$(printf '%s' "$STATS_LINE" | cut -f9)

# ── Step 4: derive percentages + saturation count from capacity ───────────────
# Saturation high-water mark in absolute txs.
SAT_THRESHOLD=$(( CAPACITY * SATURATED_PCT / 100 ))
if [ "$SAT_THRESHOLD" -lt 1 ]; then SAT_THRESHOLD=1; fi

# Count saturated blocks. We did not carry per-block counts out of Python to
# keep the wire surface a single line; instead re-walk the saturation test
# cheaply via the distribution we have: a block is "at/over saturation" iff
# its tx count >= SAT_THRESHOLD. The only count guaranteed from summary stats
# is whether max >= threshold (>=1 saturated) — to get the exact count we ask
# Python once more in a tight count-only mode.
SATURATED=$(python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$SAT_THRESHOLD" <<'PYEOF2'
import sys, json, subprocess
determ, port, from_s, to_s, thr_s = sys.argv[1:6]
from_h, to_h, thr = int(from_s), int(to_s), int(thr_s)
sat = 0
for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15)
    except Exception:
        print(0); sys.exit(1)
    if r.returncode != 0:
        print(0); sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        print(0); sys.exit(1)
    if not isinstance(blk, dict):
        continue
    txs = blk.get("transactions") or []
    if isinstance(txs, list) and len(txs) >= thr:
        sat += 1
print(sat)
PYEOF2
)
SAT_RC=$?
if [ "$SAT_RC" -ne 0 ] || [ -z "$SATURATED" ]; then
  echo "operator_block_fullness_audit: saturation count walk failed" >&2
  exit 1
fi
case "$SATURATED" in *[!0-9]*)
  echo "operator_block_fullness_audit: saturation count non-numeric ('$SATURATED')" >&2
  exit 1 ;;
esac

# Percentages (integer math, x10 for one decimal of precision where useful).
# empty_pct = empty / blocks * 100
EMPTY_PCT=$(( EMPTY * 100 / BLOCKS ))
# Fill percentages vs capacity. MEAN_MILLI is mean_txs * 1000.
# mean_fill_pct = mean_txs / capacity * 100 = MEAN_MILLI / 1000 / capacity * 100
MEAN_FILL_PCT=$(( MEAN_MILLI * 100 / 1000 / CAPACITY ))
P50_FILL_PCT=$(( P50 * 100 / CAPACITY ))
P90_FILL_PCT=$(( P90 * 100 / CAPACITY ))
MAX_FILL_PCT=$(( MAX_TXS * 100 / CAPACITY ))
EARLY_FILL_PCT=$(( EARLY_MILLI * 100 / 1000 / CAPACITY ))
LATE_FILL_PCT=$(( LATE_MILLI * 100 / 1000 / CAPACITY ))
# Trend delta in fill-percentage points (late - early), can be negative.
TREND_DELTA_PCT_PTS=$(( LATE_FILL_PCT - EARLY_FILL_PCT ))

# ── Step 5: evaluate anomalies ────────────────────────────────────────────────
ANOMALIES=""
add_anom() { if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES $1"; fi; }

if [ "$EMPTY_PCT" -gt "$MAX_EMPTY_PCT" ]; then
  add_anom "empty_block_rate_high"
fi
if [ "$SATURATED" -ge 1 ]; then
  add_anom "saturation_pressure"
fi
# Rising fullness: late-half mean exceeds early-half by > trend-delta points
# AND late-half mean is non-trivial (>= half the saturation mark) so we don't
# flag noise wobble near zero.
RISING_FLOOR=$(( SATURATED_PCT / 2 ))
if [ "$TREND_DELTA_PCT_PTS" -gt "$TREND_DELTA_PCT" ] && [ "$LATE_FILL_PCT" -ge "$RISING_FLOOR" ]; then
  add_anom "fullness_rising"
fi

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  for _a in $ANOMALIES; do ANOM_COUNT=$(( ANOM_COUNT + 1 )); done
fi
if [ "$ANOM_COUNT" -gt 0 ]; then VERDICT="ANOMALY"; else VERDICT="OK"; fi

# ── Step 6: emit ──────────────────────────────────────────────────────────────
if [ "$JSON_OUT" -eq 1 ]; then
  # Build anomalies JSON array.
  AJSON=""
  for _a in $ANOMALIES; do
    if [ -z "$AJSON" ]; then AJSON="\"$_a\""; else AJSON="$AJSON,\"$_a\""; fi
  done
  printf '{'
  printf '"rpc_port":%s,' "$PORT"
  printf '"window":{"from":%s,"to":%s,"blocks":%s},' "$FROM" "$TO" "$BLOCKS"
  printf '"capacity":%s,"saturated_pct":%s,' "$CAPACITY" "$SATURATED_PCT"
  printf '"empty_blocks":%s,"empty_block_pct":%s,' "$EMPTY" "$EMPTY_PCT"
  printf '"total_txs":%s,"max_txs":%s,' "$TOTAL_TXS" "$MAX_TXS"
  printf '"mean_txs_milli":%s,"p50_txs":%s,"p90_txs":%s,' "$MEAN_MILLI" "$P50" "$P90"
  printf '"mean_fill_pct":%s,"p50_fill_pct":%s,"p90_fill_pct":%s,"max_fill_pct":%s,' \
    "$MEAN_FILL_PCT" "$P50_FILL_PCT" "$P90_FILL_PCT" "$MAX_FILL_PCT"
  printf '"saturated_blocks":%s,' "$SATURATED"
  printf '"early_fill_pct":%s,"late_fill_pct":%s,"trend_delta_pct_pts":%s,' \
    "$EARLY_FILL_PCT" "$LATE_FILL_PCT" "$TREND_DELTA_PCT_PTS"
  printf '"anomalies":[%s],"verdict":"%s"' "$AJSON" "$VERDICT"
  printf '}\n'
else
  if [ "$ANOM_ONLY" -eq 0 ]; then
    echo "Block fullness audit — window [$FROM..$TO] ($BLOCKS blocks), rpc-port $PORT"
    echo "  Capacity target (soft): $CAPACITY txs/block   saturation high-water: ${SATURATED_PCT}%"
    echo "  Empty blocks:    $EMPTY / $BLOCKS (${EMPTY_PCT}%)"
    echo "  Total txs:       $TOTAL_TXS   max/block: $MAX_TXS (${MAX_FILL_PCT}% of capacity)"
    echo "  Fill p50/p90:    ${P50_FILL_PCT}% / ${P90_FILL_PCT}%   mean: ${MEAN_FILL_PCT}%"
    echo "  Saturated blocks (>= ${SATURATED_PCT}% cap): $SATURATED"
    echo "  Trend (early -> late mean fill): ${EARLY_FILL_PCT}% -> ${LATE_FILL_PCT}% (${TREND_DELTA_PCT_PTS} pts)"
  fi
  if [ "$ANOM_COUNT" -gt 0 ]; then
    for _a in $ANOMALIES; do
      case "$_a" in
        empty_block_rate_high)
          echo "  [ANOMALY] empty_block_rate_high: ${EMPTY_PCT}% empty > ${MAX_EMPTY_PCT}% threshold" ;;
        saturation_pressure)
          echo "  [ANOMALY] saturation_pressure: $SATURATED block(s) at/over ${SATURATED_PCT}% of capacity ($SAT_THRESHOLD txs)" ;;
        fullness_rising)
          echo "  [ANOMALY] fullness_rising: late-half fill ${LATE_FILL_PCT}% exceeds early-half ${EARLY_FILL_PCT}% by ${TREND_DELTA_PCT_PTS} pts (> ${TREND_DELTA_PCT}); drift toward saturation" ;;
      esac
    done
    echo "[ANOMALY] $ANOM_COUNT fullness anomaly(ies) in window [$FROM..$TO]"
  else
    if [ "$ANOM_ONLY" -eq 0 ]; then
      echo "[OK] no block-fullness anomalies in window [$FROM..$TO]"
    fi
  fi
fi

if [ "$ANOM_ONLY" -eq 1 ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
