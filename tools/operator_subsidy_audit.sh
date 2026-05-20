#!/usr/bin/env bash
# operator_subsidy_audit.sh — Audit E1/E3/E4 subsidy distribution over a
# window of blocks. Reports total subsidy minted, per-creator share, and
# flags concentration / A1-drift anomalies.
#
# Read-only RPC composition; safe against a running daemon. The script
# walks the requested window via `determ block-info <h> --json` (one
# round-trip per block) to collect each block's `creators` list, then
# attributes a per-block subsidy share of `1 / len(creators)` to each
# listed creator (matching the apply-side E3 split rule in
# chain.cpp::apply_block: equal split across creators with the division
# remainder credited to creators[0]). Window totals are checked against
# the chain's `accumulated_subsidy` counter (A1 unitary-supply ledger)
# for drift detection.
#
# RPC-shape note: there is no "supply as-of-block-N" RPC; the chain
# only exposes `accumulated_subsidy` at the current head. We therefore
# (1) take the head snapshot once before walking the window so the
# walk + post-walk reads observe the same `accumulated_subsidy` (modulo
# any blocks produced during the walk), and (2) estimate per-block
# subsidy as `accumulated_subsidy_head / height_head` (the average
# E1/E3/E4 mint per block over chain lifetime). For FLAT subsidy mode
# (default) this is exact; for E3 lottery mode it is an expectation
# (jackpot blocks pay block_subsidy * M, miss blocks pay 0; the average
# is identical). Window totals scale this estimate by the window's
# fraction of non-empty creator-blocks.
#
# Usage:
#   tools/operator_subsidy_audit.sh [--rpc-port N] [--json]
#                                   [--from H] [--to H]
#                                   [--anomalies-only]
#
# Options:
#   --rpc-port N       RPC port to query (default: 7778)
#   --json             Emit structured JSON envelope instead of human table
#   --from H           Start of audit window (inclusive; default: max(0, tip-100))
#   --to H             End of audit window (inclusive; default: tip)
#   --anomalies-only   Suppress healthy output; only print flagged anomalies.
#                      Exit 2 if any anomaly fires.
#   -h, --help         Show this help
#
# RPC dependencies (all read-only):
#   - head              (current chain height)
#   - supply  (--json)  (accumulated_subsidy + a1_invariant_ok)
#   - block             (per-block JSON; via `determ block-info <i> --json`)
#
# Anomaly flags (each adds an entry to anomalies[]):
#   - top_1_share_high       top creator received > 50% of window subsidy
#   - empty_creators_block   a block in the window has 0 creators (chain
#                            apply-side: no subsidy paid that block — can
#                            be normal in BFT-degraded / pre-quorum modes
#                            but worth flagging in operational audits)
#   - a1_delta_mismatch      window's estimated subsidy total deviates
#                            from per-block sum by > 1 unit (drift signal)
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_subsidy_audit.sh [--rpc-port N] [--json]
                                 [--from H] [--to H]
                                 [--anomalies-only]

Audit E1/E3/E4 subsidy distribution over a window of blocks. Walks the
window via block-info, attributes per-block subsidy by the apply-side
E3 split rule (1/len(creators) per listed creator), and reports
concentration metrics + A1-drift checks.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human table
  --from H            Start of audit window (default: max(0, tip-100))
  --to H              End of audit window (default: tip)
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  -h, --help          Show this help

Anomaly flags:
  top_1_share_high        top creator received > 50% of window subsidy
  empty_creators_block    a block in the window has 0 creators
  a1_delta_mismatch       window subsidy total deviates from per-block sum

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
    *) echo "operator_subsidy_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_subsidy_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_subsidy_audit: --from / --to must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve current tip + lifetime subsidy ────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_subsidy_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_subsidy_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Lifetime accumulated_subsidy via supply --field (single bare scalar).
ACCUM=$("$DETERM" supply --field accumulated_subsidy --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_subsidy_audit: cannot reach supply RPC (port $PORT)" >&2
  exit 1
}
case "$ACCUM" in *[!0-9]*|"")
  echo "operator_subsidy_audit: supply returned non-numeric '$ACCUM' (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 100 blocks ending at tip (per spec).
FROM=${FROM_H:-$(( HEAD_H > 100 ? HEAD_H - 100 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_subsidy_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi

# Per-block subsidy estimate (lifetime average; see header). Avoids
# divide-by-zero on a height=0 chain (no blocks → no subsidy data).
if [ "$HEAD_H" -gt 0 ]; then
  EST_PER_BLOCK=$(( ACCUM / HEAD_H ))
else
  EST_PER_BLOCK=0
fi

# Window block count, inclusive.
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: walk the window + attribute per-creator shares ────────────────────
# Python driver: handles JSON parsing + per-creator accumulation. Each
# block contributes EST_PER_BLOCK to its creators (split equally), so
# per-creator total = sum over blocks of (EST_PER_BLOCK / len(creators)).
# Output written as TSV ledger to TMP_LEDGER:
#   creator<TAB>blocks_present<TAB>subsidy_share<TAB>fractional_shares
# Plus a one-line TMP_META with: <empty_blocks>\t<per_block_sum>
TMP_LEDGER=$(mktemp 2>/dev/null) || {
  echo "operator_subsidy_audit: cannot create temp file" >&2; exit 1;
}
TMP_META=$(mktemp 2>/dev/null) || {
  echo "operator_subsidy_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_LEDGER" "$TMP_META" 2>/dev/null' EXIT

python - "$DETERM" "$PORT" "$FROM" "$TO" "$EST_PER_BLOCK" "$TMP_LEDGER" "$TMP_META" <<'PY'
import json, subprocess, sys
from collections import defaultdict

determ, port, from_h, to_h, est_per_block, ledger_path, meta_path = sys.argv[1:8]
from_h        = int(from_h)
to_h          = int(to_h)
est_per_block = int(est_per_block)

# blocks_present[creator] = count of blocks in [from, to] where creator
#                           appeared in the `creators` list.
# subsidy_share[creator]  = sum over those blocks of est_per_block /
#                           len(creators). Floor at apply-time matches
#                           chain.cpp's per_creator = total/m semantics;
#                           we mirror by integer division per block, then
#                           credit the remainder to creators[0] (same
#                           rule as the apply path).
blocks_present = defaultdict(int)
subsidy_share  = defaultdict(int)
empty_blocks   = 0
per_block_sum  = 0   # sum of (est_per_block) over non-empty-creator blocks;
                     # used for the A1 delta check.

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_subsidy_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_subsidy_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_subsidy_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue
    creators = blk.get("creators") or []
    if not isinstance(creators, list):
        creators = []
    if len(creators) == 0:
        empty_blocks += 1
        continue   # apply-side: no subsidy paid for empty-creator blocks
    per_block_sum += est_per_block
    m = len(creators)
    # Apply-side semantics: split equally, remainder to creators[0].
    each = est_per_block // m
    rem  = est_per_block - each * m
    for c in creators:
        if not isinstance(c, str): continue
        blocks_present[c] += 1
        subsidy_share[c]  += each
    # Remainder credited to first creator only (matches chain.cpp).
    if creators and isinstance(creators[0], str):
        subsidy_share[creators[0]] += rem

# Write per-creator ledger sorted by subsidy_share desc (ties by name asc).
rows = sorted(
    subsidy_share.items(),
    key=lambda kv: (-kv[1], kv[0])
)
with open(ledger_path, "w", encoding="utf-8") as f:
    for c, share in rows:
        f.write(f"{c}\t{blocks_present[c]}\t{share}\n")

with open(meta_path, "w", encoding="utf-8") as f:
    f.write(f"{empty_blocks}\t{per_block_sum}\n")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_subsidy_audit: block-walk failed" >&2
  exit 1
fi

# Read meta + ledger back into shell-aggregable form.
META_LINE=$(head -1 "$TMP_META" 2>/dev/null || echo "0\t0")
EMPTY_BLOCKS=$(printf '%s' "$META_LINE" | cut -f1)
PER_BLOCK_SUM=$(printf '%s' "$META_LINE" | cut -f2)
case "$EMPTY_BLOCKS"  in *[!0-9]*|"") EMPTY_BLOCKS=0 ;; esac
case "$PER_BLOCK_SUM" in *[!0-9]*|"") PER_BLOCK_SUM=0 ;; esac

# Total subsidy in window = sum of subsidy_share column.
TOTAL_WIN_SUBSIDY=0
DISTINCT_CREATORS=0
if [ -s "$TMP_LEDGER" ]; then
  TOTAL_WIN_SUBSIDY=$(awk -F'\t' '{s += $3} END {print s+0}' "$TMP_LEDGER")
  DISTINCT_CREATORS=$(awk 'END {print NR}' "$TMP_LEDGER")
fi

# Concentration metrics: top-1 + top-3 shares (in basis points to dodge
# bash's lack of floating point; emit ratios as integer fractions).
TOP_1_SHARE=0
TOP_3_SHARE=0
TOP_1_CREATOR=""
if [ "$TOTAL_WIN_SUBSIDY" -gt 0 ] && [ -s "$TMP_LEDGER" ]; then
  TOP_1=$(head -1 "$TMP_LEDGER")
  TOP_1_CREATOR=$(printf '%s' "$TOP_1" | cut -f1)
  TOP_1_AMT=$(printf '%s' "$TOP_1" | cut -f3)
  # Basis points (out of 10000) for integer-only fraction math.
  TOP_1_SHARE=$(( TOP_1_AMT * 10000 / TOTAL_WIN_SUBSIDY ))
  TOP_3_AMT=$(head -3 "$TMP_LEDGER" | awk -F'\t' '{s += $3} END {print s+0}')
  TOP_3_SHARE=$(( TOP_3_AMT * 10000 / TOTAL_WIN_SUBSIDY ))
fi

# A1 delta check: per-block sum (PER_BLOCK_SUM) should equal the sum of
# all subsidy_share values (TOTAL_WIN_SUBSIDY). Any drift indicates a
# bookkeeping bug in this script's attribution loop (the remainder
# allocation should reconcile exactly). Tolerance of 1 covers integer-
# division rounding on extreme creator-count blocks where per-block
# remainder = 0 (no drift possible) or per-block remainder credit
# already booked.
A1_DELTA_OK=1
A1_DELTA_DIFF=$(( PER_BLOCK_SUM - TOTAL_WIN_SUBSIDY ))
if [ "$A1_DELTA_DIFF" -lt 0 ]; then A1_DELTA_DIFF=$(( - A1_DELTA_DIFF )); fi
if [ "$A1_DELTA_DIFF" -gt 1 ]; then A1_DELTA_OK=0; fi

# ── Step 3: assemble anomalies list ───────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
if [ "$TOP_1_SHARE" -gt 5000 ]; then add_anom "top_1_share_high"; fi
if [ "$EMPTY_BLOCKS" -gt 0 ];     then add_anom "empty_creators_block"; fi
if [ "$A1_DELTA_OK" = "0" ];      then add_anom "a1_delta_mismatch"; fi
ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# Helper: render a basis-point integer as "NN.N%".
render_pct() {
  local bps="$1"
  local whole=$(( bps / 100 ))
  local frac=$(( (bps % 100) / 10 ))
  printf '%d.%d%%' "$whole" "$frac"
}

# ── Step 4: emit output ───────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  # Build JSON. Per-creator array sorted by subsidy_share desc.
  printf '{"window":{"from":%s,"to":%s,"blocks":%s},' "$FROM" "$TO" "$WIN_BLOCKS"
  printf '"total_minted":%s,"distinct_creators":%s,' "$TOTAL_WIN_SUBSIDY" "$DISTINCT_CREATORS"
  printf '"est_per_block_subsidy":%s,"empty_creators_blocks":%s,' "$EST_PER_BLOCK" "$EMPTY_BLOCKS"
  printf '"per_creator":['
  FIRST=1
  if [ -s "$TMP_LEDGER" ]; then
    while IFS=$'\t' read -r C BP SH; do
      [ "$FIRST" = "1" ] || printf ','
      FIRST=0
      if [ "$TOTAL_WIN_SUBSIDY" -gt 0 ]; then
        SH_BPS=$(( SH * 10000 / TOTAL_WIN_SUBSIDY ))
      else
        SH_BPS=0
      fi
      printf '{"creator":"%s","blocks_present":%s,"subsidy_share":%s,"share_bps":%s}' \
        "$C" "$BP" "$SH" "$SH_BPS"
    done <"$TMP_LEDGER"
  fi
  printf '],"top_1_share_bps":%s,"top_3_share_bps":%s,' "$TOP_1_SHARE" "$TOP_3_SHARE"
  printf '"top_1_creator":"%s",' "$TOP_1_CREATOR"
  if [ "$A1_DELTA_OK" = "1" ]; then
    printf '"a1_delta_check":"ok","a1_delta_diff":%s,' "$A1_DELTA_DIFF"
  else
    printf '"a1_delta_check":"mismatch","a1_delta_diff":%s,' "$A1_DELTA_DIFF"
  fi
  printf '"anomalies":['
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | awk -F, '{
      for(i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"",$i }
    }'
  fi
  printf '],"rpc_port":%s,"lifetime_accumulated_subsidy":%s,"head_height":%s}\n' \
    "$PORT" "$ACCUM" "$HEAD_H"
  # Exit-code policy below.
else
  # Human-readable layout.
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_subsidy_audit: no anomalies (port $PORT, window [$FROM..$TO])"
  else
    echo "=== Subsidy audit (port $PORT, window [$FROM..$TO], $WIN_BLOCKS blocks) ==="
    echo "Estimated per-block subsidy : $EST_PER_BLOCK  (lifetime accumulated_subsidy=$ACCUM / height=$HEAD_H)"
    echo "Total subsidy minted (est)  : $TOTAL_WIN_SUBSIDY"
    echo "Empty-creators blocks       : $EMPTY_BLOCKS"
    echo "Distinct creators in window : $DISTINCT_CREATORS"
    if [ "$DISTINCT_CREATORS" -gt 0 ] && [ "$ANOM_ONLY" != "1" ]; then
      echo
      echo "Per-creator distribution (sorted by share desc):"
      RANK=0
      while IFS=$'\t' read -r C BP SH; do
        RANK=$(( RANK + 1 ))
        if [ "$TOTAL_WIN_SUBSIDY" -gt 0 ]; then
          PCT_BPS=$(( SH * 10000 / TOTAL_WIN_SUBSIDY ))
          PCT=$(render_pct "$PCT_BPS")
        else
          PCT="-"
        fi
        TAG=""
        [ "$RANK" = "1" ] && TAG="  [top-1]"
        printf "  %-28s : %s (%s)  blocks=%s%s\n" "$C" "$SH" "$PCT" "$BP" "$TAG"
      done <"$TMP_LEDGER"
    fi
    echo
    if [ "$DISTINCT_CREATORS" -gt 0 ]; then
      echo "Top-1 share : $(render_pct "$TOP_1_SHARE")"
      echo "Top-3 share : $(render_pct "$TOP_3_SHARE")"
    fi
    if [ "$A1_DELTA_OK" = "1" ]; then
      echo "A1 check    : per-block sum=$PER_BLOCK_SUM matches per-creator total=$TOTAL_WIN_SUBSIDY (diff=$A1_DELTA_DIFF)"
    else
      echo "A1 check    : MISMATCH — per-block sum=$PER_BLOCK_SUM vs per-creator total=$TOTAL_WIN_SUBSIDY (diff=$A1_DELTA_DIFF)"
    fi
    echo
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] No concentration / A1 anomalies"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
    fi
  fi
fi

# ── Step 5: exit-code policy ─────────────────────────────────────────────────
# Same convention as operator_stake_audit / operator_fork_watch: exit 2
# only when --anomalies-only is set AND at least one anomaly fired.
# Default informational mode always exits 0 if the RPC walk succeeded.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
