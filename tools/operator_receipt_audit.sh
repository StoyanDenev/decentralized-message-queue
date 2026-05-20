#!/usr/bin/env bash
# operator_receipt_audit.sh — Audit cross-shard receipt flow on a running
# determ daemon. Walks a window of finalized blocks, reads the per-block
# `inbound_receipts[]` (credits received from other shards) and
# `cross_shard_receipts[]` (outbound debits emitted to other shards) per
# the Block JSON shape (see src/chain/block.cpp::Block::to_json and
# src/chain/block.cpp::CrossShardReceipt::to_json), and reports volume +
# per-shard breakdowns + dedup-set growth + A1 sanity checks.
#
# Apply-side invariants probed (all FA7-class):
#   1. No (src_shard, tx_hash) pair appears twice in inbound_receipts
#      within the window — the chain's `applied_inbound_receipts_` set
#      enforces this at apply time; a duplicate would indicate a
#      catastrophic dedup-set failure (would manifest as double-credit
#      and an A1 supply violation).
#   2. No inbound receipt has src_shard == my_shard_id — receipts are
#      cross-shard by construction; a self-shard receipt would indicate
#      broken routing (would also be caught by the apply path which
#      requires `r.src_shard != chain.my_shard_id()` in
#      validator.cpp::check_inbound_receipts).
#   3. Sum of inbound_receipts[].amount in the window equals the chain's
#      accumulated_inbound delta over that range (A1 unitary-supply
#      counter). When the window covers genesis-to-head we can verify
#      this directly against chain_summary; otherwise we report the
#      window-sum as informational and skip the delta gate.
#
# RPC-shape gap (documented):
#   There is no read-only RPC that exposes `shard_count`. `status`
#   surfaces `shard_id` (this node's) and `protections.sharding_mode`
#   (none/current/extended) but NOT the total shard count. We infer it
#   from observed receipts: max(src_shard, dst_shard, my_shard_id) + 1
#   across the window. Operators can override with --shard-count N. When
#   sharding_mode == "none" (or shard_count resolves to 1) we exit 0
#   immediately with an INFO line — single-shard chains have no
#   cross-shard traffic by construction.
#
# Outbound semantics:
#   The producer (producer.cpp B3.2) builds `cross_shard_receipts[]` by
#   iterating TRANSFER txs whose `to` routes off-shard via
#   `chain.is_cross_shard(tx.to)`. Reading the block's
#   `cross_shard_receipts[]` field is therefore equivalent to walking
#   transactions and filtering by destination shard, plus we get
#   `dst_shard` pre-computed (which would otherwise require the
#   shard_address_salt — only present in genesis.json, not in any RPC).
#
# Usage:
#   tools/operator_receipt_audit.sh [--rpc-port N] [--json]
#                                   [--from H] [--to H]
#                                   [--shard-count N] [--anomalies-only]
#
# Defaults:
#   --rpc-port      7778
#   --from / --to   last 1000 blocks ending at current head (clamped to 0)
#   --shard-count   inferred from observed receipts (or 1 if single-shard
#                   detected via status.protections.sharding_mode == "none")
#
# Output (default human):
#   Per-source-shard + per-destination-shard breakdown with counts +
#   credit/debit volume + percent share. Top-10 entries shown for each.
#   Net flow (inbound minus outbound) and dedup-set growth + A1 delta
#   check on the bottom.
#
# --json shape:
#   {"my_shard_id":N,"shard_count":N,"window":{"from":H,"to":H,"blocks":N},
#    "inbound":{"count":N,"total":N,"by_source":[{"shard":N,"count":N,
#                                                  "total":N,"pct_bps":N},…]},
#    "outbound":{"count":N,"total":N,"by_destination":[{"shard":N,"count":N,
#                                                       "total":N,"pct_bps":N},…]},
#    "net":N,"dedup_unique":N,"a1_delta_ok":true|false|null,
#    "a1_window_sum":N,"a1_chain_delta":N|null,
#    "anomalies":[…],"rpc_port":N,"sharding_mode":"…"}
#
# Anomaly flags:
#   duplicate_inbound_receipt   ≥1 (src_shard, tx_hash) pair appeared
#                                twice in inbound_receipts within the
#                                window. Catastrophic — implies FA7
#                                dedup failure. Exit 2.
#   self_shard_inbound          ≥1 inbound receipt where src_shard ==
#                                my_shard_id. Implies routing bug.
#                                Exit 2.
#   a1_delta_mismatch           window covers genesis-to-head AND
#                                window's inbound sum differs from the
#                                chain's accumulated_inbound at head.
#                                Exit 2.
#
# Exit codes:
#   0   success / informational (single-shard chain also exits 0)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_receipt_audit.sh [--rpc-port N] [--json]
                                 [--from H] [--to H]
                                 [--shard-count N] [--anomalies-only]

Audits cross-shard receipt flow (inbound credits + outbound debits)
over a window of finalized blocks, plus apply-side invariants:
FA7 dedup-set health (no duplicate (src_shard, tx_hash)), self-shard
routing check, and A1 accumulated_inbound delta sanity.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope instead of human table
  --from H            Start of audit window (default: max(0, head-1000))
  --to H              End of audit window (default: current head)
  --shard-count N     Override shard_count (default: inferred from receipts;
                       falls back to 1 if sharding_mode=="none")
  --anomalies-only    Print only flagged anomalies; exit 2 if any fire
  -h, --help          Show this help

Anomaly flags:
  duplicate_inbound_receipt   ≥1 duplicate (src_shard, tx_hash) pair
                              (catastrophic FA7 dedup failure)
  self_shard_inbound          ≥1 inbound receipt with src_shard ==
                              my_shard_id (broken routing)
  a1_delta_mismatch           window covers genesis-to-head AND
                              window sum != chain accumulated_inbound

Exit codes:
  0   success / informational (or single-shard deployment)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
SHARD_COUNT_OVERRIDE=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";              shift 2 ;;
    --json)            JSON_OUT=1;                 shift ;;
    --from)            FROM_H="${2:-}";            shift 2 ;;
    --to)              TO_H="${2:-}";              shift 2 ;;
    --shard-count)     SHARD_COUNT_OVERRIDE="${2:-}"; shift 2 ;;
    --anomalies-only)  ANOM_ONLY=1;                shift ;;
    *) echo "operator_receipt_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_receipt_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H" "$SHARD_COUNT_OVERRIDE"; do
  [ -z "$v" ] && continue
  case "$v" in *[!0-9]*)
    echo "operator_receipt_audit: --from / --to / --shard-count must be unsigned integers (got '$v')" >&2
    exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_receipt_audit: jq is required (per-block JSON is too nested for grep)" >&2
  exit 1
fi
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_receipt_audit: python is required for per-block aggregation" >&2
  exit 1
fi
PY=python; command -v python >/dev/null 2>&1 || PY=python3

# ── Step 1: probe daemon for shard config ────────────────────────────────────
STATUS_JSON=$("$DETERM" status --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_receipt_audit: RPC error from \`determ status\` (is daemon on port $PORT?)" >&2
  exit 1
}
MY_SHARD_ID=$(printf '%s' "$STATUS_JSON" | jq -r '.shard_id // 0')
case "$MY_SHARD_ID" in *[!0-9]*|"") MY_SHARD_ID=0 ;; esac
SHARDING_MODE=$(printf '%s' "$STATUS_JSON" | jq -r '.protections.sharding_mode // "unknown"')

# Resolve head height.
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_receipt_audit: RPC error from \`determ head\` (port $PORT)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height // 0')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_receipt_audit: malformed head JSON (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at current head. The highest
# finalized index is height-1.
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))
FROM=${FROM_H:-$(( TOP > 1000 ? TOP - 1000 + 1 : 0 ))}
TO=${TO_H:-$TOP}
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_receipt_audit: --to ($TO) < --from ($FROM); nothing to audit" >&2
  exit 1
fi

# Short-circuit on empty chain.
if [ "$HEIGHT" -eq 0 ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"my_shard_id":%s,"shard_count":1,"window":{"from":%s,"to":%s,"blocks":0},"inbound":{"count":0,"total":0,"by_source":[]},"outbound":{"count":0,"total":0,"by_destination":[]},"net":0,"dedup_unique":0,"a1_delta_ok":null,"a1_window_sum":0,"a1_chain_delta":null,"anomalies":[],"rpc_port":%s,"sharding_mode":"%s","info":"empty_chain"}\n' \
      "$MY_SHARD_ID" "$FROM" "$TO" "$PORT" "$SHARDING_MODE"
  else
    echo "operator_receipt_audit: chain has no finalized blocks yet (height=0, port $PORT)"
  fi
  exit 0
fi

# Single-shard short-circuit. sharding_mode=="none" → shard_count=1 by
# construction (genesis enforces this). No cross-shard activity possible.
if [ "$SHARDING_MODE" = "none" ] && [ -z "$SHARD_COUNT_OVERRIDE" ]; then
  WIN_BLOCKS=$(( TO - FROM + 1 ))
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"my_shard_id":%s,"shard_count":1,"window":{"from":%s,"to":%s,"blocks":%s},"inbound":{"count":0,"total":0,"by_source":[]},"outbound":{"count":0,"total":0,"by_destination":[]},"net":0,"dedup_unique":0,"a1_delta_ok":null,"a1_window_sum":0,"a1_chain_delta":null,"anomalies":[],"rpc_port":%s,"sharding_mode":"none","info":"single_shard_deployment"}\n' \
      "$MY_SHARD_ID" "$FROM" "$TO" "$WIN_BLOCKS" "$PORT"
  else
    echo "INFO: single-shard deployment — no cross-shard activity by construction (sharding_mode=none, port $PORT)"
  fi
  exit 0
fi

# Pull chain_summary once for the A1 accumulated_inbound at head. We use
# this for the genesis-to-head A1 delta check (only valid when window
# covers all blocks).
CS_JSON=$("$DETERM" chain-summary --last 1 --json --rpc-port "$PORT" 2>/dev/null) || {
  CS_JSON='{}'
}
ACCUM_INBOUND_HEAD=$(printf '%s' "$CS_JSON" | jq -r '.accumulated_inbound // 0')
case "$ACCUM_INBOUND_HEAD" in *[!0-9]*|"") ACCUM_INBOUND_HEAD=0 ;; esac

WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: walk window via block-info --json + aggregate ─────────────────────
TMP_OUT=$(mktemp) || {
  echo "operator_receipt_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

"$PY" - "$DETERM" "$PORT" "$FROM" "$TO" "$MY_SHARD_ID" "$TMP_OUT" <<'PY'
import json, subprocess, sys
from collections import defaultdict

determ, port, from_h, to_h, my_shard_id, out_path = sys.argv[1:7]
from_h = int(from_h); to_h = int(to_h); my_shard_id = int(my_shard_id)

# Per-shard inbound stats.
in_count_by_src = defaultdict(int)
in_total_by_src = defaultdict(int)
# Per-shard outbound stats.
out_count_by_dst = defaultdict(int)
out_total_by_dst = defaultdict(int)

# Dedup tracker for (src_shard, tx_hash) pairs across inbound receipts in
# the window. Duplicates within the same window would be a catastrophic
# FA7 dedup failure (apply path would also have rejected one).
seen_pairs = set()
duplicate_pairs = []   # list of (src_shard, tx_hash)
self_shard_pairs = []  # list of (src_shard, tx_hash) where src == my_shard_id

inbound_count = 0
inbound_total = 0
outbound_count = 0
outbound_total = 0
max_shard_observed = my_shard_id  # for shard_count inference

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_receipt_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_receipt_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_receipt_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    # Inbound receipts: credits this shard received from other shards in
    # this block. Per chain.cpp::apply_block, each one bumps
    # accumulated_inbound by .amount.
    ibrs = blk.get("inbound_receipts") or []
    for ib in ibrs:
        src   = int(ib.get("src_shard", 0))
        thash = str(ib.get("tx_hash", ""))
        amt   = int(ib.get("amount", 0))
        inbound_count += 1
        inbound_total += amt
        in_count_by_src[src] += 1
        in_total_by_src[src] += amt
        if src > max_shard_observed: max_shard_observed = src
        pair = (src, thash)
        if pair in seen_pairs:
            duplicate_pairs.append(pair)
        else:
            seen_pairs.add(pair)
        if src == my_shard_id:
            self_shard_pairs.append(pair)

    # Outbound: cross_shard_receipts emitted by THIS shard in this block.
    # Per producer.cpp B3.2, the producer builds these by iterating
    # TRANSFER txs and filtering by chain.is_cross_shard(to). Using the
    # block's pre-computed list (vs walking transactions) avoids needing
    # the shard_address_salt (which is in genesis.json, not any RPC).
    csrs = blk.get("cross_shard_receipts") or []
    for o in csrs:
        dst = int(o.get("dst_shard", 0))
        amt = int(o.get("amount", 0))
        outbound_count += 1
        outbound_total += amt
        out_count_by_dst[dst] += 1
        out_total_by_dst[dst] += amt
        if dst > max_shard_observed: max_shard_observed = dst

# Stable sort: by total desc, ties by shard asc.
def sort_breakdown(count_d, total_d):
    keys = sorted(count_d.keys(),
                  key=lambda k: (-total_d[k], -count_d[k], k))
    return [{"shard": k, "count": count_d[k], "total": total_d[k]} for k in keys]

result = {
    "inbound_count":    inbound_count,
    "inbound_total":    inbound_total,
    "outbound_count":   outbound_count,
    "outbound_total":   outbound_total,
    "by_source":        sort_breakdown(in_count_by_src,  in_total_by_src),
    "by_destination":   sort_breakdown(out_count_by_dst, out_total_by_dst),
    "dedup_unique":     len(seen_pairs),
    "duplicate_pairs":  [{"src_shard": s, "tx_hash": t} for (s, t) in duplicate_pairs],
    "self_shard_pairs": [{"src_shard": s, "tx_hash": t} for (s, t) in self_shard_pairs],
    "max_shard_observed": max_shard_observed,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_receipt_audit: block-walk failed" >&2
  exit 1
fi

WALK_JSON=$(cat "$TMP_OUT")

INBOUND_COUNT=$(printf '%s' "$WALK_JSON"  | jq -r '.inbound_count')
INBOUND_TOTAL=$(printf '%s' "$WALK_JSON"  | jq -r '.inbound_total')
OUTBOUND_COUNT=$(printf '%s' "$WALK_JSON" | jq -r '.outbound_count')
OUTBOUND_TOTAL=$(printf '%s' "$WALK_JSON" | jq -r '.outbound_total')
DEDUP_UNIQUE=$(printf '%s' "$WALK_JSON"   | jq -r '.dedup_unique')
DUP_COUNT=$(printf '%s' "$WALK_JSON"      | jq -r '.duplicate_pairs | length')
SELF_COUNT=$(printf '%s' "$WALK_JSON"     | jq -r '.self_shard_pairs | length')
MAX_SHARD_OBS=$(printf '%s' "$WALK_JSON"  | jq -r '.max_shard_observed')

# ── Step 3: resolve shard_count ──────────────────────────────────────────────
# Priority: explicit override > inferred from observations > 1 (single-shard).
if [ -n "$SHARD_COUNT_OVERRIDE" ]; then
  SHARD_COUNT="$SHARD_COUNT_OVERRIDE"
  SHARD_COUNT_SRC="override"
else
  SHARD_COUNT=$(( MAX_SHARD_OBS + 1 ))
  if [ "$SHARD_COUNT" -lt 1 ]; then SHARD_COUNT=1; fi
  SHARD_COUNT_SRC="inferred"
fi

NET=$(( INBOUND_TOTAL - OUTBOUND_TOTAL ))

# ── Step 4: A1 delta check ───────────────────────────────────────────────────
# Only meaningful when the window covers ALL finalized blocks (from=0,
# to=head). Otherwise we'd need a "accumulated_inbound as-of-block-N" RPC
# which doesn't exist (see header). When the window is a strict subset,
# we report a1_delta_ok = null and skip the gate.
A1_DELTA_OK=""    # "" → null (not applicable); "1" ok, "0" mismatch
A1_DELTA_DIFF=0
if [ "$FROM" = "0" ] && [ "$TO" = "$TOP" ]; then
  A1_DELTA_DIFF=$(( INBOUND_TOTAL - ACCUM_INBOUND_HEAD ))
  if [ "$A1_DELTA_DIFF" -lt 0 ]; then A1_DELTA_DIFF=$(( - A1_DELTA_DIFF )); fi
  if [ "$A1_DELTA_DIFF" = "0" ]; then
    A1_DELTA_OK=1
  else
    A1_DELTA_OK=0
  fi
fi

# ── Step 5: assemble anomalies ───────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}
[ "$DUP_COUNT"  -gt 0 ] && add_anom "duplicate_inbound_receipt"
[ "$SELF_COUNT" -gt 0 ] && add_anom "self_shard_inbound"
[ "$A1_DELTA_OK" = "0" ] && add_anom "a1_delta_mismatch"

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 6: render ───────────────────────────────────────────────────────────
# Percentages in basis points to dodge bash's lack of floating point.
pct_bps() {
  local num="$1" denom="$2"
  if [ "$denom" -le 0 ]; then echo 0; return; fi
  echo $(( num * 10000 / denom ))
}
render_pct() {
  local bps="$1"
  local whole=$(( bps / 100 ))
  local frac=$(( (bps % 100) / 10 ))
  printf '%d.%d%%' "$whole" "$frac"
}

if [ "$JSON_OUT" = "1" ]; then
  # Top-10 source + destination shard breakdowns, sorted by total desc.
  IN_BREAKDOWN=$(printf '%s' "$WALK_JSON" | jq -c --argjson total "$INBOUND_TOTAL" '
    [ .by_source[:10][] | . + {pct_bps: (if $total > 0 then (.total * 10000 / $total | floor) else 0 end)} ]
  ')
  OUT_BREAKDOWN=$(printf '%s' "$WALK_JSON" | jq -c --argjson total "$OUTBOUND_TOTAL" '
    [ .by_destination[:10][] | . + {pct_bps: (if $total > 0 then (.total * 10000 / $total | floor) else 0 end)} ]
  ')
  if [ -z "$A1_DELTA_OK" ]; then
    A1_OK_JSON="null"
    A1_CHAIN_DELTA_JSON="null"
  else
    A1_OK_JSON=$([ "$A1_DELTA_OK" = "1" ] && echo true || echo false)
    A1_CHAIN_DELTA_JSON="$ACCUM_INBOUND_HEAD"
  fi
  ANOM_JSON=$(if [ -z "$ANOMALIES" ]; then printf '[]'; else
    printf '['; printf '%s' "$ANOMALIES" | awk -F, '{
      for (i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"", $i }
    }'; printf ']'
  fi)
  printf '{"my_shard_id":%s,"shard_count":%s,"shard_count_source":"%s","window":{"from":%s,"to":%s,"blocks":%s},"inbound":{"count":%s,"total":%s,"by_source":%s},"outbound":{"count":%s,"total":%s,"by_destination":%s},"net":%s,"dedup_unique":%s,"a1_delta_ok":%s,"a1_window_sum":%s,"a1_chain_delta":%s,"anomalies":%s,"rpc_port":%s,"sharding_mode":"%s"}\n' \
    "$MY_SHARD_ID" "$SHARD_COUNT" "$SHARD_COUNT_SRC" \
    "$FROM" "$TO" "$WIN_BLOCKS" \
    "$INBOUND_COUNT" "$INBOUND_TOTAL" "$IN_BREAKDOWN" \
    "$OUTBOUND_COUNT" "$OUTBOUND_TOTAL" "$OUT_BREAKDOWN" \
    "$NET" "$DEDUP_UNIQUE" \
    "$A1_OK_JSON" "$INBOUND_TOTAL" "$A1_CHAIN_DELTA_JSON" \
    "$ANOM_JSON" "$PORT" "$SHARDING_MODE"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_receipt_audit: no anomalies (port $PORT, window [$FROM..$TO], shard $MY_SHARD_ID of $SHARD_COUNT)"
  else
    echo "=== Cross-shard receipt audit (port $PORT, window [$FROM..$TO], $WIN_BLOCKS blocks) ==="
    echo "My shard: $MY_SHARD_ID (of $SHARD_COUNT) [shard_count: $SHARD_COUNT_SRC, sharding_mode: $SHARDING_MODE]"
    echo "Inbound:  $INBOUND_COUNT receipts, $INBOUND_TOTAL credited"
    echo "Outbound: $OUTBOUND_COUNT TRANSFERs, $OUTBOUND_TOTAL debited"
    if [ "$NET" -lt 0 ]; then
      echo "Net (inbound - outbound): $NET (net outflow)"
    elif [ "$NET" -gt 0 ]; then
      echo "Net (inbound - outbound): +$NET (net inflow)"
    else
      echo "Net (inbound - outbound): 0 (balanced)"
    fi

    if [ "$ANOM_ONLY" != "1" ]; then
      if [ "$INBOUND_COUNT" -gt 0 ]; then
        echo "By source shard (inbound, top 10):"
        printf '%s' "$WALK_JSON" | jq -r --argjson total "$INBOUND_TOTAL" '
          .by_source[:10][]
          | [.shard, .count, .total,
             (if $total > 0 then (.total * 10000 / $total | floor) else 0 end)
            ] | @tsv' | \
        while IFS=$'\t' read -r SH CT TOT BPS; do
          printf '  shard %s: %s receipts, %s credited (%s)\n' \
            "$SH" "$CT" "$TOT" "$(render_pct "$BPS")"
        done
      else
        echo "By source shard (inbound): (none in window)"
      fi
      if [ "$OUTBOUND_COUNT" -gt 0 ]; then
        echo "By destination shard (outbound, top 10):"
        printf '%s' "$WALK_JSON" | jq -r --argjson total "$OUTBOUND_TOTAL" '
          .by_destination[:10][]
          | [.shard, .count, .total,
             (if $total > 0 then (.total * 10000 / $total | floor) else 0 end)
            ] | @tsv' | \
        while IFS=$'\t' read -r SH CT TOT BPS; do
          printf '  shard %s: %s receipts, %s debited (%s)\n' \
            "$SH" "$CT" "$TOT" "$(render_pct "$BPS")"
        done
      else
        echo "By destination shard (outbound): (none in window)"
      fi
    fi

    # Dedup-set status.
    if [ "$DUP_COUNT" = "0" ]; then
      echo "Dedup-set: $DEDUP_UNIQUE unique (src_shard, tx_hash) pairs [OK no duplicates]"
    else
      echo "Dedup-set: $DEDUP_UNIQUE unique pairs but $DUP_COUNT duplicate(s) detected [CATASTROPHIC — FA7 violation]"
      printf '%s' "$WALK_JSON" | jq -r '
        .duplicate_pairs[:5][] | "  duplicate: src_shard=\(.src_shard) tx_hash=\(.tx_hash[0:16])..."'
    fi
    # Self-shard receipts.
    if [ "$SELF_COUNT" -gt 0 ]; then
      echo "Self-shard inbound: $SELF_COUNT receipt(s) with src_shard == $MY_SHARD_ID [routing bug]"
      printf '%s' "$WALK_JSON" | jq -r '
        .self_shard_pairs[:5][] | "  self-routed: tx_hash=\(.tx_hash[0:16])..."'
    fi
    # A1 delta check.
    if [ "$A1_DELTA_OK" = "1" ]; then
      echo "A1 delta check: accumulated_inbound +$INBOUND_TOTAL matches chain head ($ACCUM_INBOUND_HEAD) [OK]"
    elif [ "$A1_DELTA_OK" = "0" ]; then
      echo "A1 delta check: MISMATCH — window sum $INBOUND_TOTAL vs chain head $ACCUM_INBOUND_HEAD (diff=$A1_DELTA_DIFF)"
    else
      echo "A1 delta check: skipped (window [$FROM..$TO] is a strict subset of chain [0..$TOP]; no per-block A1 snapshot RPC)"
    fi

    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] No FA7 / routing / A1 anomalies"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
    fi
  fi
fi

# ── Step 7: exit-code policy ─────────────────────────────────────────────────
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
