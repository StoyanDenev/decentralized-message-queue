#!/usr/bin/env bash
# operator_block_size_audit.sh — Audit block-size distribution (tx count
# + estimated serialized bytes per block) over a window. Walks the chain
# via `determ block-info <h> --json` and reports mean/median/p95/max of
# both metrics, plus tx-type distribution, plus an explicit comparison
# against the S-022 per-MsgType wire cap so operators can see whether
# block sizes are anywhere near the 4 MB BLOCK ceiling.
#
# Read-only RPC composition; safe against a running daemon. The daemon
# must already be listening on --rpc-port.
#
# Block-size estimation:
#
# There is no "block.serialized_bytes" RPC; the wire format is computed
# at gossip-encode time only. We approximate it from the JSON envelope
# by summing the serialized-JSON length of each block (`len(json.dumps(blk))`).
# This is an upper bound on the binary wire format (JSON encoding adds
# field names, quoting, hex-vs-bytes 2× expansion on every digest /
# signature / payload field), but it's the right ballpark for operator
# capacity planning: if your JSON-envelope block is 800 KB, the binary
# wire form is comfortably under the 4 MB BLOCK cap.
#
# The per-tx contribution dominates JSON size on non-empty blocks:
# Transaction::to_json emits `from` (~70 char anon addr) + `to` + 64-char
# sig hex + 64-char hash hex + variable payload hex (2× payload bytes)
# + type/amount/fee/nonce integers. The estimate's accuracy improves with
# tx count (header overhead is amortized).
#
# S-022 reference (include/determ/net/messages.hpp::max_message_bytes):
#   BLOCK / BEACON_HEADER / SHARD_TIP / CROSS_SHARD_RECEIPT_BUNDLE /
#   HEADERS_RESPONSE          : 4 MB
#   SNAPSHOT_RESPONSE / CHAIN_RESPONSE : 16 MB
#   Default (HELLO, CONTRIB, BLOCK_SIG, TRANSACTION, ABORT_*, ...)   : 1 MB
# This script uses the BLOCK cap (4 MB = 4194304 bytes) as the reference
# because that's the channel that carries finalized block bodies.
#
# Usage:
#   tools/operator_block_size_audit.sh [--rpc-port N] [--json]
#                                      [--from H] [--to H]
#                                      [--anomalies-only]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit structured JSON envelope instead of human table
#   --from H            Start of audit window (inclusive; default: max(0, tip-1000))
#   --to H              End of audit window (inclusive; default: tip)
#   --anomalies-only    Print only flagged anomalies; exit 2 if any fire
#   -h, --help          Show this help
#
# RPC dependencies (all read-only):
#   - head              (current chain height)
#   - block             (per-block JSON; via `determ block-info <i> --json`)
#
# Anomaly flags (each adds an entry to anomalies[]):
#   - block_size_warn         any block > 50% of S-022 BLOCK cap (2 MB)
#   - block_size_critical     any block > 80% of S-022 BLOCK cap (3.2 MB)
#   - tx_count_spike          any block has tx count > 10× window median
#   - empty_block_run         > 100 consecutive empty blocks in window
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_block_size_audit.sh [--rpc-port N] [--json]
                                    [--from H] [--to H]
                                    [--anomalies-only]

Audit block-size distribution (tx count + estimated bytes per block)
over a window. Walks the window via block-info, sums each block's
JSON-envelope length as an upper-bound estimate of serialized bytes,
and aggregates mean/median/p95/max + tx-type distribution. Reports
capacity headroom against S-022 BLOCK cap (4 MB) and flags anomalies.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human table
  --from H            Start of audit window (default: max(0, tip-1000))
  --to H              End of audit window (default: tip)
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  -h, --help          Show this help

Anomaly flags:
  block_size_warn      any block > 50% of S-022 BLOCK cap (2 MB)
  block_size_critical  any block > 80% of S-022 BLOCK cap (3.2 MB)
  tx_count_spike       any block with tx count > 10× window median
  empty_block_run      > 100 consecutive empty blocks in window

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="$2";   shift 2 ;;
    --json)            JSON_OUT=1;  shift ;;
    --from)            FROM_H="$2"; shift 2 ;;
    --to)              TO_H="$2";   shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1; shift ;;
    *) echo "operator_block_size_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_block_size_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_block_size_audit: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

# S-022 BLOCK cap. Mirrors include/determ/net/messages.hpp::max_message_bytes(BLOCK)
# = 4 * 1024 * 1024 = 4194304 bytes. See also src/main.cpp test-binary-codec
# §10 which locks this in as a regression test.
SIZE_CAP_BYTES=4194304
SIZE_WARN_BYTES=$(( SIZE_CAP_BYTES / 2 ))         # 50% = 2 MB
SIZE_CRIT_BYTES=$(( SIZE_CAP_BYTES * 80 / 100 ))  # 80% = 3.2 MB
EMPTY_RUN_THRESH=100
TX_SPIKE_MULT=10

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_block_size_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_block_size_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at tip (per spec).
FROM=${FROM_H:-$(( HEAD_H > 1000 ? HEAD_H - 1000 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_block_size_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi

# Window block count, inclusive.
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: walk the window + collect tx counts + size estimates ──────────────
# Python driver: handles JSON parsing + percentile math + tx-type
# tallying + max-empty-run tracking. Single block-info round trip per
# block (no batched RPC available on this surface).
#
# Output written as TSV summary to TMP_STATS (one line):
#   total_blocks<TAB>empty_blocks<TAB>nonempty_blocks
#   <TAB>tx_mean<TAB>tx_median<TAB>tx_p95<TAB>tx_max<TAB>tx_max_block_idx
#   <TAB>bytes_mean<TAB>bytes_median<TAB>bytes_p95<TAB>bytes_max<TAB>bytes_max_block_idx
#   <TAB>max_empty_run<TAB>warn_count<TAB>critical_count<TAB>spike_count
# Plus TMP_TXDIST: per-tx-type TSV (type_name<TAB>count) sorted by count desc.
TMP_STATS=$(mktemp 2>/dev/null) || {
  echo "operator_block_size_audit: cannot create temp file" >&2; exit 1;
}
TMP_TXDIST=$(mktemp 2>/dev/null) || {
  echo "operator_block_size_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_STATS" "$TMP_TXDIST" 2>/dev/null' EXIT

python - "$DETERM" "$PORT" "$FROM" "$TO" \
       "$SIZE_WARN_BYTES" "$SIZE_CRIT_BYTES" "$TX_SPIKE_MULT" \
       "$TMP_STATS" "$TMP_TXDIST" <<'PY'
import json, subprocess, sys
from collections import defaultdict

(determ, port, from_h, to_h,
 size_warn, size_crit, tx_spike_mult,
 stats_path, txdist_path) = sys.argv[1:10]
from_h        = int(from_h)
to_h          = int(to_h)
size_warn     = int(size_warn)
size_crit     = int(size_crit)
tx_spike_mult = int(tx_spike_mult)

# TxType integer → name mapping. Mirrors include/determ/chain/block.hpp
# TxType enum so the human-readable output uses canonical names.
# Any unseen integer falls back to "TYPE_<n>" so the script doesn't
# silently drop counts on future TxType additions.
TX_TYPE_NAMES = {
    0:  "TRANSFER",
    1:  "REGISTER",
    2:  "DEREGISTER",
    3:  "STAKE",
    4:  "UNSTAKE",
    5:  "REGION_CHANGE",
    6:  "PARAM_CHANGE",
    7:  "MERGE_EVENT",
    8:  "COMPOSABLE_BATCH",
    9:  "DAPP_REGISTER",
    10: "DAPP_CALL",
}

tx_counts          = []      # tx count per block
tx_count_blocks    = []      # parallel block-index list (for max-finder)
byte_sizes         = []      # JSON-envelope length per block
byte_size_blocks   = []      # parallel block-index list
type_counts        = defaultdict(int)
empty_blocks       = 0
max_empty_run      = 0
cur_empty_run      = 0
warn_count         = 0
critical_count     = 0
# tx_count_spike depends on the median — computed after the walk.

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_block_size_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_block_size_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_block_size_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    txs = blk.get("transactions") or []
    if not isinstance(txs, list):
        txs = []
    n_tx = len(txs)
    tx_counts.append(n_tx)
    tx_count_blocks.append(h)

    # Tally tx-type distribution.
    for tx in txs:
        if isinstance(tx, dict):
            t = tx.get("type")
            if isinstance(t, int):
                type_counts[t] += 1

    # Estimated serialized size = length of the canonical JSON envelope.
    # This is an UPPER BOUND on the binary wire format because the JSON
    # encoding expands every hex-encoded digest / sig / payload by ~2×
    # and adds field names + quoting. For operator capacity-planning
    # against the S-022 BLOCK cap (4 MB), the upper bound is the
    # conservative direction (if JSON-est is well under cap, the binary
    # form is too).
    #
    # We re-serialize via json.dumps (no whitespace) rather than reusing
    # the RPC response bytes because the RPC may emit a pretty-printed
    # or extra-whitespace variant depending on the daemon's dump mode.
    size = len(json.dumps(blk, separators=(",", ":")))
    byte_sizes.append(size)
    byte_size_blocks.append(h)

    if size > size_crit:
        critical_count += 1
    elif size > size_warn:
        warn_count += 1

    # Empty-block-run tracking. An "empty" block here is one with zero
    # transactions; consensus-empty blocks (no creators) are subsumed
    # because such blocks also carry no transactions. The longest
    # consecutive run is what we flag (an empty block here and there is
    # normal; a sustained run signals stalled tx flow or a mempool issue).
    if n_tx == 0:
        empty_blocks += 1
        cur_empty_run += 1
        if cur_empty_run > max_empty_run:
            max_empty_run = cur_empty_run
    else:
        cur_empty_run = 0

# Percentile via sort + index (type-7 quantile, same as numpy/R/excel).
def quantile(sorted_xs, q):
    if not sorted_xs:
        return 0
    if len(sorted_xs) == 1:
        return sorted_xs[0]
    pos = q * (len(sorted_xs) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_xs) - 1)
    frac = pos - lo
    return int(round(sorted_xs[lo] + (sorted_xs[hi] - sorted_xs[lo]) * frac))

def stats_for(values, blocks):
    if not values:
        return (0, 0, 0, 0, 0)
    sorted_v = sorted(values)
    mean = int(round(sum(values) / len(values)))
    median = quantile(sorted_v, 0.50)
    p95 = quantile(sorted_v, 0.95)
    mx = sorted_v[-1]
    # Find block index for max (first occurrence).
    mx_idx = 0
    for i, v in enumerate(values):
        if v == mx:
            mx_idx = blocks[i]
            break
    return (mean, median, p95, mx, mx_idx)

tx_mean, tx_median, tx_p95, tx_max, tx_max_block = stats_for(tx_counts, tx_count_blocks)
b_mean,  b_median,  b_p95,  b_max,  b_max_block  = stats_for(byte_sizes, byte_size_blocks)

# tx_count_spike: any single block has tx count > tx_spike_mult × median.
# Skip the check on a degenerate window where the median is 0 (an
# all-empty window has no meaningful spike threshold; any non-empty
# block would otherwise trip the flag trivially).
spike_count = 0
if tx_median > 0:
    thresh = tx_median * tx_spike_mult
    for v in tx_counts:
        if v > thresh:
            spike_count += 1

total_blocks = len(tx_counts)
nonempty_blocks = total_blocks - empty_blocks

with open(stats_path, "w", encoding="utf-8") as f:
    f.write("\t".join(str(x) for x in [
        total_blocks, empty_blocks, nonempty_blocks,
        tx_mean, tx_median, tx_p95, tx_max, tx_max_block,
        b_mean, b_median, b_p95, b_max, b_max_block,
        max_empty_run, warn_count, critical_count, spike_count,
    ]) + "\n")

# Tx-type distribution: name<TAB>count, sorted by count desc (ties by name asc).
named = []
for type_int, count in type_counts.items():
    name = TX_TYPE_NAMES.get(type_int, f"TYPE_{type_int}")
    named.append((name, count))
named.sort(key=lambda kv: (-kv[1], kv[0]))
with open(txdist_path, "w", encoding="utf-8") as f:
    for name, count in named:
        f.write(f"{name}\t{count}\n")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_block_size_audit: block-walk failed" >&2
  exit 1
fi

# ── Step 3: read stats back into shell-aggregable form ────────────────────────
STATS_LINE=$(head -1 "$TMP_STATS" 2>/dev/null || echo "")
if [ -z "$STATS_LINE" ]; then
  echo "operator_block_size_audit: empty stats payload" >&2
  exit 1
fi
TOTAL_BLOCKS=$(printf '%s'    "$STATS_LINE" | cut -f1)
EMPTY_BLOCKS=$(printf '%s'    "$STATS_LINE" | cut -f2)
NONEMPTY_BLOCKS=$(printf '%s' "$STATS_LINE" | cut -f3)
TX_MEAN=$(printf '%s'         "$STATS_LINE" | cut -f4)
TX_MEDIAN=$(printf '%s'       "$STATS_LINE" | cut -f5)
TX_P95=$(printf '%s'          "$STATS_LINE" | cut -f6)
TX_MAX=$(printf '%s'          "$STATS_LINE" | cut -f7)
TX_MAX_BLOCK=$(printf '%s'    "$STATS_LINE" | cut -f8)
B_MEAN=$(printf '%s'          "$STATS_LINE" | cut -f9)
B_MEDIAN=$(printf '%s'        "$STATS_LINE" | cut -f10)
B_P95=$(printf '%s'           "$STATS_LINE" | cut -f11)
B_MAX=$(printf '%s'           "$STATS_LINE" | cut -f12)
B_MAX_BLOCK=$(printf '%s'     "$STATS_LINE" | cut -f13)
MAX_EMPTY_RUN=$(printf '%s'   "$STATS_LINE" | cut -f14)
WARN_COUNT=$(printf '%s'      "$STATS_LINE" | cut -f15)
CRIT_COUNT=$(printf '%s'      "$STATS_LINE" | cut -f16)
SPIKE_COUNT=$(printf '%s'     "$STATS_LINE" | cut -f17)

# Total tx count = sum over per-type distribution. (Could also recompute
# from tx_mean × total_blocks, but the txdist sum is the ground truth.)
TOTAL_TXS=0
if [ -s "$TMP_TXDIST" ]; then
  TOTAL_TXS=$(awk -F'\t' '{s += $2} END {print s+0}' "$TMP_TXDIST")
fi

# Largest-block-as-percent-of-cap (basis points to avoid bash floats).
MAX_PCT_OF_CAP_BPS=0
if [ "$SIZE_CAP_BYTES" -gt 0 ]; then
  MAX_PCT_OF_CAP_BPS=$(( B_MAX * 10000 / SIZE_CAP_BYTES ))
fi

# ── Step 4: assemble anomalies list ───────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
if [ "$CRIT_COUNT" -gt 0 ];                       then add_anom "block_size_critical"; fi
if [ "$WARN_COUNT" -gt 0 ];                       then add_anom "block_size_warn"; fi
if [ "$SPIKE_COUNT" -gt 0 ];                      then add_anom "tx_count_spike"; fi
if [ "$MAX_EMPTY_RUN" -gt "$EMPTY_RUN_THRESH" ];  then add_anom "empty_block_run"; fi
ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# Helpers ─────────────────────────────────────────────────────────────────────
# Render a basis-point integer as "NN.N%".
render_pct() {
  local bps="$1"
  local whole=$(( bps / 100 ))
  local frac=$(( (bps % 100) / 10 ))
  printf '%d.%d%%' "$whole" "$frac"
}
# Render a byte count as a human-readable size (KB / MB with 1 decimal).
# Uses 1024-base (KiB/MiB) but labels as KB/MB for operator readability,
# matching the convention used in operator_*.sh output throughout.
render_bytes() {
  local b="$1"
  case "$b" in *[!0-9]*|"") echo "0 B"; return ;; esac
  if [ "$b" -ge 1048576 ]; then
    local whole=$(( b / 1048576 ))
    local frac=$(( (b % 1048576) * 10 / 1048576 ))
    printf '%d.%d MB' "$whole" "$frac"
  elif [ "$b" -ge 1024 ]; then
    local whole=$(( b / 1024 ))
    local frac=$(( (b % 1024) * 10 / 1024 ))
    printf '%d.%d KB' "$whole" "$frac"
  else
    printf '%d B' "$b"
  fi
}

# ── Step 5: emit output ───────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  printf '{"window":{"from":%s,"to":%s,"blocks":%s},' "$FROM" "$TO" "$WIN_BLOCKS"
  printf '"total_blocks":%s,"empty_blocks":%s,"nonempty_blocks":%s,"total_txs":%s,' \
    "$TOTAL_BLOCKS" "$EMPTY_BLOCKS" "$NONEMPTY_BLOCKS" "$TOTAL_TXS"
  printf '"tx_count_stats":{"mean":%s,"median":%s,"p95":%s,"max":%s,"max_block":%s},' \
    "$TX_MEAN" "$TX_MEDIAN" "$TX_P95" "$TX_MAX" "$TX_MAX_BLOCK"
  printf '"bytes_stats":{"mean":%s,"median":%s,"p95":%s,"max":%s,"max_block":%s},' \
    "$B_MEAN" "$B_MEDIAN" "$B_P95" "$B_MAX" "$B_MAX_BLOCK"
  printf '"tx_type_distribution":{'
  FIRST=1
  if [ -s "$TMP_TXDIST" ]; then
    while IFS=$'\t' read -r NAME CNT; do
      [ "$FIRST" = "1" ] || printf ','
      FIRST=0
      printf '"%s":%s' "$NAME" "$CNT"
    done <"$TMP_TXDIST"
  fi
  printf '},'
  printf '"size_cap_bytes":%s,"size_warn_bytes":%s,"size_critical_bytes":%s,' \
    "$SIZE_CAP_BYTES" "$SIZE_WARN_BYTES" "$SIZE_CRIT_BYTES"
  printf '"max_pct_of_cap_bps":%s,"size_warn_count":%s,"size_critical_count":%s,' \
    "$MAX_PCT_OF_CAP_BPS" "$WARN_COUNT" "$CRIT_COUNT"
  printf '"tx_count_spike_count":%s,"max_empty_run":%s,' \
    "$SPIKE_COUNT" "$MAX_EMPTY_RUN"
  printf '"anomalies":['
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | awk -F, '{
      for(i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"",$i }
    }'
  fi
  printf '],"rpc_port":%s,"head_height":%s}\n' "$PORT" "$HEAD_H"
else
  # Human-readable layout.
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_block_size_audit: no anomalies (port $PORT, window [$FROM..$TO])"
  else
    echo "=== Block size audit (port $PORT, window [$FROM..$TO]) ==="
    echo "Blocks: $TOTAL_BLOCKS ($NONEMPTY_BLOCKS non-empty, $EMPTY_BLOCKS empty)"
    if [ "$ANOM_ONLY" != "1" ]; then
      printf "Tx counts: mean %s, median %s, p95 %s, max %s (block %s)\n" \
        "$TX_MEAN" "$TX_MEDIAN" "$TX_P95" "$TX_MAX" "$TX_MAX_BLOCK"
      printf "Block bytes (estimated): mean %s, median %s, p95 %s, max %s (block %s)\n" \
        "$(render_bytes $B_MEAN)" "$(render_bytes $B_MEDIAN)" \
        "$(render_bytes $B_P95)"  "$(render_bytes $B_MAX)" "$B_MAX_BLOCK"
      if [ -s "$TMP_TXDIST" ] && [ "$TOTAL_TXS" -gt 0 ]; then
        DIST_LINE=""
        while IFS=$'\t' read -r NAME CNT; do
          PCT_BPS=$(( CNT * 10000 / TOTAL_TXS ))
          if [ -z "$DIST_LINE" ]; then
            DIST_LINE=$(printf "%s %s (%s)" "$NAME" "$CNT" "$(render_pct $PCT_BPS)")
          else
            DIST_LINE=$(printf "%s, %s %s (%s)" "$DIST_LINE" "$NAME" "$CNT" "$(render_pct $PCT_BPS)")
          fi
        done <"$TMP_TXDIST"
        echo "Tx-type distribution: $DIST_LINE"
      else
        echo "Tx-type distribution: (no transactions in window)"
      fi
      # Capacity summary: largest block vs S-022 cap.
      CAP_STATUS="No pressure."
      if [ "$MAX_PCT_OF_CAP_BPS" -gt 8000 ]; then
        CAP_STATUS="CRITICAL — exceeds 80% of cap."
      elif [ "$MAX_PCT_OF_CAP_BPS" -gt 5000 ]; then
        CAP_STATUS="WARN — exceeds 50% of cap."
      fi
      printf "Block-size cap (S-022): %s. Largest: %s (%s of cap). %s\n" \
        "$(render_bytes $SIZE_CAP_BYTES)" \
        "$(render_bytes $B_MAX)" \
        "$(render_pct $MAX_PCT_OF_CAP_BPS)" \
        "$CAP_STATUS"
    fi
    echo
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] No size anomalies"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
      if [ "$CRIT_COUNT" -gt 0 ]; then
        echo "  block_size_critical : $CRIT_COUNT block(s) exceed 80% of S-022 cap (> $(render_bytes $SIZE_CRIT_BYTES))"
      fi
      if [ "$WARN_COUNT" -gt 0 ]; then
        echo "  block_size_warn     : $WARN_COUNT block(s) exceed 50% of S-022 cap (> $(render_bytes $SIZE_WARN_BYTES))"
      fi
      if [ "$SPIKE_COUNT" -gt 0 ]; then
        echo "  tx_count_spike      : $SPIKE_COUNT block(s) have tx count > ${TX_SPIKE_MULT}× window median (>$(( TX_MEDIAN * TX_SPIKE_MULT )))"
      fi
      if [ "$MAX_EMPTY_RUN" -gt "$EMPTY_RUN_THRESH" ]; then
        echo "  empty_block_run     : longest empty-block run = $MAX_EMPTY_RUN (> $EMPTY_RUN_THRESH consecutive)"
      fi
    fi
  fi
fi

# ── Step 6: exit-code policy ──────────────────────────────────────────────────
# Same convention as operator_subsidy_audit / operator_fork_watch: exit 2
# only when --anomalies-only is set AND at least one anomaly fired.
# Default informational mode always exits 0 if the RPC walk succeeded.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
