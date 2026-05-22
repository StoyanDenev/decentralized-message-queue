#!/usr/bin/env bash
# operator_block_size_audit.sh — Audit per-block size distribution +
# per-tx-type breakdown over a block window. Walks the chain via
# `determ block-info <h> --json` and reports avg / p50 / p90 / p99
# block byte sizes (JSON-envelope length as proxy), per-tx-type counts
# + percentage shares, and event-payload counts (AbortEvents,
# EquivocationEvents, CrossShardReceipts). Surfaces capacity-pressure
# anomalies (cap approach / cap hit) and deployment-health signals
# (tx-type imbalance, equivocation evidence in window).
#
# Read-only RPC composition; safe against a running daemon. The daemon
# must already be listening on --rpc-port.
#
# Block-size estimation:
#
# There is no "block.serialized_bytes" RPC; the wire format is computed
# at gossip-encode time only. We approximate it from the JSON envelope
# by summing the canonical-JSON length of each block (`len(json.dumps(blk,
# separators=(',', ':')))`). This is an UPPER BOUND on the binary wire
# format — JSON adds field names, quoting, and 2× hex expansion on every
# digest/sig/payload — but it is the right ballpark for operator capacity
# planning against the S-022 framing-layer cap. If the JSON estimate is
# well under cap, the binary wire form is too.
#
# Different tx types have distinct size characteristics:
#   - TRANSFER varies with from/to address length (anon ≈ 70 chars hex,
#     named ≈ 16 chars).
#   - STAKE / UNSTAKE / DEREGISTER are small (no payload, fixed-shape).
#   - REGISTER carries the new public key + optional name.
#   - PARAM_CHANGE carries the param-name + value + N×(idx, ed_sig).
#   - DAPP_REGISTER carries service-pubkey + endpoint URL.
#   - DAPP_CALL is the largest in practice (payload hex, 2× the binary
#     payload length).
#
# Wire-cap reference (per S-022 / include/determ/net/messages.hpp::
# max_message_bytes):
#   BLOCK / BEACON_HEADER / SHARD_TIP / CROSS_SHARD_RECEIPT_BUNDLE /
#   HEADERS_RESPONSE         : 4 MB
#   SNAPSHOT_RESPONSE / CHAIN_RESPONSE                    : 16 MB
#   Default (HELLO, CONTRIB, BLOCK_SIG, TRANSACTION, ...) : 1 MB
# `--max-block-size-bytes` defaults to 16 MB (the framing-layer ceiling
# applied at Peer::read_body before MsgType-specific tightening). The
# script flags any block exceeding 75% of that cap as a capacity signal
# (`block_size_cap_approach`) and any block within 1 KB of the cap as an
# operational concern (`block_size_cap_hit`).
#
# Usage:
#   tools/operator_block_size_audit.sh --rpc-port N [--from H] [--to H]
#                                      [--last N]
#                                      [--max-block-size-bytes N]
#                                      [--json] [--anomalies-only]
#                                      [-h|--help]
#
# Options:
#   --rpc-port N                RPC port to query (REQUIRED)
#   --from H                    Start of audit window (inclusive)
#   --to H                      End of audit window (inclusive; default: tip)
#   --last N                    Audit last N blocks (mutually exclusive with --from)
#   --max-block-size-bytes N    Reference cap in bytes (default: 16777216 = 16 MB)
#   --json                      Emit structured JSON envelope instead of human
#   --anomalies-only            Print only anomalies; exit 2 if any fire
#   -h, --help                  Show this help
#
# Window defaults:
#   If neither --from, --to, nor --last is supplied, the window is
#   max(0, tip-1000)..tip (last 1000 blocks).
#
# RPC dependencies (all read-only):
#   - head              (current chain height)
#   - block             (per-block JSON; via `determ block-info <i> --json`)
#
# Anomaly flags (each adds an entry to anomalies[]):
#   - block_size_cap_approach   any block > 75% of --max-block-size-bytes
#                               (mempool-overflow / capacity-pressure signal)
#   - block_size_cap_hit        any block within 1 KB of --max-block-size-bytes
#                               (operational concern; producer may be on the
#                               edge of building unrelayable blocks)
#   - tx_type_imbalance_high    any single tx-type > 80% of total volume
#                               (deployment-health signal; could indicate a
#                               stuck workload, a runaway DApp, etc.)
#   - equivocation_events_in_window
#                               any block carries ≥1 equivocation_events
#                               (informational — slashing in progress; not an
#                               error condition per se but worth surfacing)
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_block_size_audit.sh --rpc-port N [--from H] [--to H]
                                    [--last N]
                                    [--max-block-size-bytes N]
                                    [--json] [--anomalies-only]
                                    [-h|--help]

Audit per-block size distribution + per-tx-type breakdown over a window.
Walks the window via block-info, computes block byte size from the JSON
envelope (upper bound on the binary wire format), aggregates avg + p50 +
p90 + p99, tallies per-tx-type counts/shares, and reports event-payload
counts. Flags capacity-pressure anomalies (cap approach, cap hit) and
deployment-health signals (tx-type imbalance, equivocation evidence).

Options:
  --rpc-port N                RPC port to query (REQUIRED)
  --from H                    Start of audit window (inclusive)
  --to H                      End of audit window (inclusive; default: tip)
  --last N                    Audit last N blocks (mutually exclusive with --from)
  --max-block-size-bytes N    Reference cap in bytes (default: 16777216 = 16 MB)
  --json                      Emit structured JSON envelope instead of human
  --anomalies-only            Print only anomalies; exit 2 if any fire
  -h, --help                  Show this help

Window defaults:
  If neither --from, --to, nor --last is supplied, the window is
  max(0, tip-1000)..tip (last 1000 blocks).

Anomaly flags:
  block_size_cap_approach        any block > 75% of --max-block-size-bytes
  block_size_cap_hit             any block within 1 KB of --max-block-size-bytes
  tx_type_imbalance_high         any single tx-type > 80% of total tx volume
  equivocation_events_in_window  any block carries ≥1 equivocation_events

Exit codes:
  0   success (or informational mode)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=""
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
LAST_N=""
MAX_BLOCK_SIZE_BYTES=16777216   # 16 MB framing-layer ceiling per S-022
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                 usage; exit 0 ;;
    --rpc-port)                PORT="${2:-}";                shift 2 ;;
    --json)                    JSON_OUT=1;                   shift ;;
    --from)                    FROM_H="${2:-}";              shift 2 ;;
    --to)                      TO_H="${2:-}";                shift 2 ;;
    --last)                    LAST_N="${2:-}";              shift 2 ;;
    --max-block-size-bytes)    MAX_BLOCK_SIZE_BYTES="${2:-}";shift 2 ;;
    --anomalies-only)          ANOM_ONLY=1;                  shift ;;
    *) echo "operator_block_size_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required per the spec.
if [ -z "$PORT" ]; then
  echo "operator_block_size_audit: --rpc-port is required" >&2
  usage >&2
  exit 1
fi

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_block_size_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H" "$LAST_N"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_block_size_audit: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
case "$MAX_BLOCK_SIZE_BYTES" in *[!0-9]*|"")
  echo "operator_block_size_audit: --max-block-size-bytes must be a positive integer (got '$MAX_BLOCK_SIZE_BYTES')" >&2
  exit 1 ;;
esac
if [ "$MAX_BLOCK_SIZE_BYTES" -lt 2048 ]; then
  # A cap below 2 KB makes the "within 1 KB of cap" threshold absurd —
  # surface that early rather than emit nonsense anomalies.
  echo "operator_block_size_audit: --max-block-size-bytes must be ≥ 2048 (got '$MAX_BLOCK_SIZE_BYTES')" >&2
  exit 1
fi
if [ -n "$FROM_H" ] && [ -n "$LAST_N" ]; then
  echo "operator_block_size_audit: --from and --last are mutually exclusive" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Resolve DETERM to an absolute path. Python's subprocess.run on Windows
# uses CreateProcessW which does not honor the inherited bash cwd the
# same way exec*() does — a relative `build/Release/determ.exe` resolves
# fine from a bash command but FileNotFoundError'd from python on
# Windows. Pre-resolving here keeps the Python driver portable without
# touching common.sh or the sibling operator_*.sh scripts.
case "$DETERM" in
  /*|[A-Za-z]:/*|[A-Za-z]:\\*) DETERM_ABS="$DETERM" ;;
  *) DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
esac

# Derived thresholds.
SOFT_THRESHOLD_BYTES=$(( MAX_BLOCK_SIZE_BYTES * 75 / 100 ))   # 75% of cap
HIT_THRESHOLD_BYTES=$(( MAX_BLOCK_SIZE_BYTES - 1024 ))        # within 1 KB
TX_TYPE_IMBALANCE_PCT_BPS=8000                                # 80% in basis points

# ── Step 1: resolve current tip ───────────────────────────────────────────────
HEAD_H=$("$DETERM_ABS" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_block_size_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_block_size_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: resolve window ────────────────────────────────────────────────────
# Precedence:
#   1. --from / --to explicit → use as-is (clamp --to to HEAD_H).
#   2. --last N → window = max(0, TO - N + 1) .. TO (where TO = --to or HEAD_H).
#   3. Default → max(0, HEAD_H - 1000) .. HEAD_H.
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi

if [ -n "$FROM_H" ]; then
  FROM="$FROM_H"
elif [ -n "$LAST_N" ]; then
  if [ "$LAST_N" -eq 0 ]; then
    echo "operator_block_size_audit: --last must be ≥ 1" >&2
    exit 1
  fi
  N1=$(( LAST_N - 1 ))
  if [ "$TO" -gt "$N1" ]; then
    FROM=$(( TO - N1 ))
  else
    FROM=0
  fi
else
  if [ "$HEAD_H" -gt 1000 ]; then
    FROM=$(( HEAD_H - 1000 ))
  else
    FROM=0
  fi
fi

if [ "$FROM" -gt "$TO" ]; then
  echo "operator_block_size_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 3: walk the window + collect per-block metrics ──────────────────────
# Python driver: handles JSON parsing + percentile math + tx-type +
# event tallying. Single block-info round trip per block (no batched
# RPC available on this surface). Output written to two temp files:
#   TMP_STATS (one TSV line):
#     total_blocks <TAB> empty_blocks <TAB> total_txs
#     <TAB> bytes_avg <TAB> bytes_p50 <TAB> bytes_p90 <TAB> bytes_p99 <TAB> bytes_max <TAB> bytes_max_block
#     <TAB> total_abort_events <TAB> total_equivocation_events <TAB> total_cross_shard_receipts
#     <TAB> blocks_with_equivocation
#     <TAB> approach_count <TAB> hit_count <TAB> imbalance_present
#   TMP_TXDIST (one row per tx-type seen):
#     name<TAB>count
TMP_STATS=$(mktemp 2>/dev/null) || {
  echo "operator_block_size_audit: cannot create temp file" >&2; exit 1;
}
TMP_TXDIST=$(mktemp 2>/dev/null) || {
  echo "operator_block_size_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_STATS" "$TMP_TXDIST" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" \
       "$SOFT_THRESHOLD_BYTES" "$HIT_THRESHOLD_BYTES" \
       "$TX_TYPE_IMBALANCE_PCT_BPS" \
       "$TMP_STATS" "$TMP_TXDIST" <<'PY'
import json, subprocess, sys
from collections import defaultdict

(determ, port, from_h, to_h,
 soft_thresh, hit_thresh, imbalance_bps,
 stats_path, txdist_path) = sys.argv[1:10]
from_h        = int(from_h)
to_h          = int(to_h)
soft_thresh   = int(soft_thresh)
hit_thresh    = int(hit_thresh)
imbalance_bps = int(imbalance_bps)

# TxType integer → canonical name. Mirrors include/determ/chain/block.hpp
# enum class TxType. Unknown integers fall back to TYPE_<n> so the
# script does not silently drop counts on future TxType additions.
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

byte_sizes               = []     # JSON-envelope length per block
byte_size_blocks         = []     # parallel block-index list (for max-finder)
type_counts              = defaultdict(int)
total_txs                = 0
empty_blocks             = 0
total_abort_events       = 0
total_equivocation       = 0
total_cross_shard        = 0
blocks_with_equivocation = 0
approach_count           = 0     # blocks > soft threshold (75% of cap)
hit_count                = 0     # blocks ≥ hit threshold (within 1 KB of cap)

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
    total_txs += n_tx
    if n_tx == 0:
        empty_blocks += 1

    # Tally tx-type distribution.
    for tx in txs:
        if isinstance(tx, dict):
            t = tx.get("type")
            if isinstance(t, int):
                type_counts[t] += 1

    # Event payloads.
    aes = blk.get("abort_events") or []
    if isinstance(aes, list):
        total_abort_events += len(aes)
    eqs = blk.get("equivocation_events") or []
    if isinstance(eqs, list):
        if len(eqs) > 0:
            blocks_with_equivocation += 1
        total_equivocation += len(eqs)
    csrs = blk.get("cross_shard_receipts") or []
    if isinstance(csrs, list):
        total_cross_shard += len(csrs)

    # Estimated serialized size = canonical-JSON envelope length. This
    # is an UPPER BOUND on the binary wire format because JSON adds
    # field names + quoting + 2× hex on every digest/sig/payload. We
    # re-serialize via json.dumps (separators removed) rather than
    # reusing the RPC response bytes because the RPC may emit a pretty-
    # printed variant depending on the daemon's dump mode.
    size = len(json.dumps(blk, separators=(",", ":")))
    byte_sizes.append(size)
    byte_size_blocks.append(h)

    if size >= hit_thresh:
        hit_count += 1
    if size > soft_thresh:
        approach_count += 1

# Percentile via sort + interpolation (type-7 quantile, same as
# numpy/R/excel). Returns 0 on empty input.
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

if byte_sizes:
    sorted_b = sorted(byte_sizes)
    bytes_avg = int(round(sum(byte_sizes) / len(byte_sizes)))
    bytes_p50 = quantile(sorted_b, 0.50)
    bytes_p90 = quantile(sorted_b, 0.90)
    bytes_p99 = quantile(sorted_b, 0.99)
    bytes_max = sorted_b[-1]
    bytes_max_block = 0
    for i, v in enumerate(byte_sizes):
        if v == bytes_max:
            bytes_max_block = byte_size_blocks[i]
            break
else:
    bytes_avg = 0
    bytes_p50 = 0
    bytes_p90 = 0
    bytes_p99 = 0
    bytes_max = 0
    bytes_max_block = 0

# tx_type_imbalance: any single tx-type > 80% of total tx volume.
# Only meaningful when total_txs > 0; an empty window has no
# meaningful share denominator and the flag stays off.
imbalance_present = 0
if total_txs > 0:
    for cnt in type_counts.values():
        if cnt * 10000 > imbalance_bps * total_txs:
            imbalance_present = 1
            break

total_blocks = len(byte_sizes)

with open(stats_path, "w", encoding="utf-8") as f:
    f.write("\t".join(str(x) for x in [
        total_blocks, empty_blocks, total_txs,
        bytes_avg, bytes_p50, bytes_p90, bytes_p99, bytes_max, bytes_max_block,
        total_abort_events, total_equivocation, total_cross_shard,
        blocks_with_equivocation,
        approach_count, hit_count, imbalance_present,
    ]) + "\n")

# Per-tx-type distribution, sorted by count desc then name asc.
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

# ── Step 4: read stats back into shell-aggregable form ────────────────────────
STATS_LINE=$(head -1 "$TMP_STATS" 2>/dev/null || echo "")
if [ -z "$STATS_LINE" ]; then
  echo "operator_block_size_audit: empty stats payload" >&2
  exit 1
fi
TOTAL_BLOCKS=$(printf '%s'    "$STATS_LINE" | cut -f1)
EMPTY_BLOCKS=$(printf '%s'    "$STATS_LINE" | cut -f2)
TOTAL_TXS=$(printf '%s'       "$STATS_LINE" | cut -f3)
BYTES_AVG=$(printf '%s'       "$STATS_LINE" | cut -f4)
BYTES_P50=$(printf '%s'       "$STATS_LINE" | cut -f5)
BYTES_P90=$(printf '%s'       "$STATS_LINE" | cut -f6)
BYTES_P99=$(printf '%s'       "$STATS_LINE" | cut -f7)
BYTES_MAX=$(printf '%s'       "$STATS_LINE" | cut -f8)
BYTES_MAX_BLOCK=$(printf '%s' "$STATS_LINE" | cut -f9)
TOTAL_ABORTS=$(printf '%s'    "$STATS_LINE" | cut -f10)
TOTAL_EQUIVS=$(printf '%s'    "$STATS_LINE" | cut -f11)
TOTAL_CSRS=$(printf '%s'      "$STATS_LINE" | cut -f12)
BLOCKS_WITH_EQUIV=$(printf '%s' "$STATS_LINE" | cut -f13)
APPROACH_COUNT=$(printf '%s'  "$STATS_LINE" | cut -f14)
HIT_COUNT=$(printf '%s'       "$STATS_LINE" | cut -f15)
IMBALANCE_PRESENT=$(printf '%s' "$STATS_LINE" | cut -f16)

# Largest-block-as-percent-of-cap, in basis points (avoids bash floats).
MAX_PCT_OF_CAP_BPS=0
if [ "$MAX_BLOCK_SIZE_BYTES" -gt 0 ]; then
  MAX_PCT_OF_CAP_BPS=$(( BYTES_MAX * 10000 / MAX_BLOCK_SIZE_BYTES ))
fi

# ── Step 5: anomaly classification ────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
if [ "$APPROACH_COUNT" -gt 0 ];     then add_anom "block_size_cap_approach"; fi
if [ "$HIT_COUNT" -gt 0 ];          then add_anom "block_size_cap_hit"; fi
if [ "$IMBALANCE_PRESENT" = "1" ];  then add_anom "tx_type_imbalance_high"; fi
if [ "$BLOCKS_WITH_EQUIV" -gt 0 ];  then add_anom "equivocation_events_in_window"; fi
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
# Render a byte count as human-readable (KB/MB with 1 decimal place,
# 1024-base, labels KB/MB per the convention in other operator_*.sh).
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

# ── Step 6: emit output ───────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  printf '{"window":{"from":%s,"to":%s,"blocks":%s},' "$FROM" "$TO" "$WIN_BLOCKS"
  printf '"total_blocks":%s,"empty_blocks":%s,"total_txs":%s,' \
    "$TOTAL_BLOCKS" "$EMPTY_BLOCKS" "$TOTAL_TXS"
  printf '"block_bytes":{"avg":%s,"p50":%s,"p90":%s,"p99":%s,"max":%s,"max_block":%s},' \
    "$BYTES_AVG" "$BYTES_P50" "$BYTES_P90" "$BYTES_P99" "$BYTES_MAX" "$BYTES_MAX_BLOCK"
  printf '"tx_type_distribution":{'
  FIRST=1
  if [ -s "$TMP_TXDIST" ]; then
    while IFS=$'\t' read -r NAME CNT; do
      [ "$FIRST" = "1" ] || printf ','
      FIRST=0
      # Compute per-type share in basis points (denominator = TOTAL_TXS).
      if [ "$TOTAL_TXS" -gt 0 ]; then
        PCT_BPS=$(( CNT * 10000 / TOTAL_TXS ))
      else
        PCT_BPS=0
      fi
      printf '"%s":{"count":%s,"share_bps":%s}' "$NAME" "$CNT" "$PCT_BPS"
    done <"$TMP_TXDIST"
  fi
  printf '},'
  printf '"event_counts":{"abort_events":%s,"equivocation_events":%s,"cross_shard_receipts":%s,"blocks_with_equivocation":%s},' \
    "$TOTAL_ABORTS" "$TOTAL_EQUIVS" "$TOTAL_CSRS" "$BLOCKS_WITH_EQUIV"
  printf '"max_block_size_bytes":%s,"soft_threshold_bytes":%s,"hit_threshold_bytes":%s,' \
    "$MAX_BLOCK_SIZE_BYTES" "$SOFT_THRESHOLD_BYTES" "$HIT_THRESHOLD_BYTES"
  printf '"max_pct_of_cap_bps":%s,"cap_approach_count":%s,"cap_hit_count":%s,' \
    "$MAX_PCT_OF_CAP_BPS" "$APPROACH_COUNT" "$HIT_COUNT"
  printf '"tx_type_imbalance_present":%s,' "$IMBALANCE_PRESENT"
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
    echo "=== Block size audit (port $PORT, window [$FROM..$TO], $WIN_BLOCKS blocks) ==="
    echo "Blocks: $TOTAL_BLOCKS ($EMPTY_BLOCKS empty), txs: $TOTAL_TXS"
    if [ "$ANOM_ONLY" != "1" ]; then
      printf "Block bytes (JSON envelope, approx upper bound on wire): avg %s, p50 %s, p90 %s, p99 %s, max %s (block %s)\n" \
        "$(render_bytes $BYTES_AVG)" \
        "$(render_bytes $BYTES_P50)" \
        "$(render_bytes $BYTES_P90)" \
        "$(render_bytes $BYTES_P99)" \
        "$(render_bytes $BYTES_MAX)" \
        "$BYTES_MAX_BLOCK"
      # Tx-type distribution line.
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
      # Event payload counts.
      printf "Events: abort=%s equivocation=%s cross_shard_receipts=%s (blocks with equivocation: %s)\n" \
        "$TOTAL_ABORTS" "$TOTAL_EQUIVS" "$TOTAL_CSRS" "$BLOCKS_WITH_EQUIV"
      # Capacity summary line.
      CAP_STATUS="No pressure."
      if [ "$HIT_COUNT" -gt 0 ]; then
        CAP_STATUS="CRITICAL — at least one block within 1 KB of cap."
      elif [ "$APPROACH_COUNT" -gt 0 ]; then
        CAP_STATUS="WARN — at least one block > 75% of cap."
      fi
      printf "Block-size cap (--max-block-size-bytes): %s. Largest: %s (%s of cap). %s\n" \
        "$(render_bytes $MAX_BLOCK_SIZE_BYTES)" \
        "$(render_bytes $BYTES_MAX)" \
        "$(render_pct $MAX_PCT_OF_CAP_BPS)" \
        "$CAP_STATUS"
    fi
    echo
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] No anomalies"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
      if [ "$APPROACH_COUNT" -gt 0 ]; then
        echo "  block_size_cap_approach        : $APPROACH_COUNT block(s) > 75% of cap (> $(render_bytes $SOFT_THRESHOLD_BYTES))"
      fi
      if [ "$HIT_COUNT" -gt 0 ]; then
        echo "  block_size_cap_hit             : $HIT_COUNT block(s) within 1 KB of cap (≥ $(render_bytes $HIT_THRESHOLD_BYTES))"
      fi
      if [ "$IMBALANCE_PRESENT" = "1" ]; then
        echo "  tx_type_imbalance_high         : one tx-type accounts for > 80% of total tx volume"
      fi
      if [ "$BLOCKS_WITH_EQUIV" -gt 0 ]; then
        echo "  equivocation_events_in_window  : $BLOCKS_WITH_EQUIV block(s) carry equivocation evidence (slashing in progress)"
      fi
    fi
  fi
fi

# ── Step 7: exit-code policy ──────────────────────────────────────────────────
# Same convention as the other operator_*.sh scripts: exit 2 only when
# --anomalies-only is set AND at least one anomaly fired. Default
# informational mode always exits 0 if the RPC walk succeeded.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
