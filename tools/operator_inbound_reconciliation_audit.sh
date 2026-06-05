#!/usr/bin/env bash
# operator_inbound_reconciliation_audit.sh — Read-only health audit of
# cross-shard INBOUND-receipt reconciliation (v2.7 F2 / S-016) on a
# running determ daemon. Walks a window of finalized blocks, reports the
# per-block `inbound_receipts[]` admission count, and — once the genesis-
# pinned F2 activation height is known — flags every block AT/AFTER that
# height which admitted inbound receipts as a "F2-reconciled-admission"
# health signal (those blocks went through the deterministic committee-
# wide INTERSECTION reconciliation before the producer baked the body;
# see producer.cpp build_body() ~line 891 and validator.cpp
# check_inbound_receipts() ~line 1168).
#
# What this script IS (and is NOT):
#   This is a HEALTH-SIGNAL probe, not a per-receipt verifier. The
#   per-receipt FA7 invariants (dedup-set integrity, self-shard routing,
#   A1 accumulated_inbound delta) are already covered by the sibling
#   operator_receipt_audit.sh; the fleet-level Σ_out == Σ_in balance by
#   operator_receipt_flow.sh. THIS script answers the F2-specific
#   operational question:
#
#       "Across recent history, which blocks admitted inbound receipts,
#        and are those admissions landing in the F2-active regime (i.e.
#        through the committed-view INTERSECTION reconciliation) as
#        expected, or are inbound receipts still being admitted under the
#        pre-F2 (time-ordered, non-reconciled) admission path?"
#
#   A node whose head is well past the F2 activation height but which is
#   still admitting inbound receipts in blocks BELOW that height (e.g. a
#   mis-pinned genesis, or a chain replayed against a wrong activation
#   height) is a configuration-drift signal worth surfacing.
#
# F2 activation height (genesis-pinned; NOT exposed by any RPC):
#   `v2_7_f2_active_from_height` lives in GenesisConfig
#   (include/determ/chain/genesis.hpp); node.cpp captures it from the genesis
#   config (~line 174) and installs it into the chain via
#   chain_.set_f2_active_from_height(...) (~line 529).
#   There is no read-only RPC that surfaces it (status/head/chain-summary
#   do not carry it), so — exactly like operator_receipt_audit.sh's
#   --shard-count — the operator supplies it with --f2-activation-height N
#   (read it from the deployment's genesis.json). When omitted, the
#   per-block inbound counts are still reported, but the F2-regime
#   classification + the below-activation-admission gate are reported as
#   "not checkable" (skipped, never failed).
#
# RPC surface (read-only; safe against any running daemon):
#   status      → shard_id, protections.sharding_mode  (the `status` RPC)
#   head        → height: the `head` CLI (src/main.cpp::cmd_head) reads
#                 result["height"] from that same `status` RPC — there is no
#                 separate head RPC method
#   block-info  → per-block index + inbound_receipts[]  (full Block JSON via
#                 src/main.cpp::cmd_block_info; Block::to_json, src/chain/block.cpp)
#
# Single-shard deployments (sharding_mode == "none"): inbound_receipts is
# empty in every block by construction (no cross-shard traffic). The
# script short-circuits to a single INFO line and exits 0.
#
# Usage:
#   tools/operator_inbound_reconciliation_audit.sh [--rpc-port N]
#                                  [--f2-activation-height N]
#                                  [--from H] [--to H]
#                                  [--anomalies-only] [--json]
#
# Defaults:
#   --rpc-port               7778
#   --f2-activation-height   unset (F2-regime gate reported "not checkable")
#   --from / --to            last 1000 finalized blocks ending at head-1
#
# --json shape:
#   {"my_shard_id":N,"sharding_mode":"...","head_height":N,
#    "f2_activation_height":N|null,"window":{"from":H,"to":H,"blocks":N},
#    "totals":{"blocks_with_inbound":N,"inbound_receipt_count":N,
#              "f2_active_admissions":N,"pre_f2_admissions":N,
#              "below_activation_admissions":N},
#    "blocks":[{"index":H,"inbound_count":N,"f2_active":true|false|null},...],
#    "anomalies":[...],"rpc_port":N}
#   (the per-block "blocks" array is omitted in --anomalies-only mode.)
#
# Anomaly flags:
#   below_activation_admission   --f2-activation-height was supplied AND
#                                ≥1 block BELOW that height admitted inbound
#                                receipts that should have gone through a
#                                non-F2 (pre-reconciliation) path — purely a
#                                configuration-drift / mis-pin signal, NOT a
#                                consensus violation (the chain validated
#                                those blocks under whatever rules were
#                                active at their height). Exit 2 under
#                                --anomalies-only.
#
# Exit codes:
#   0   success / informational (single-shard deployment also exits 0)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND ≥1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_inbound_reconciliation_audit.sh [--rpc-port N]
                               [--f2-activation-height N]
                               [--from H] [--to H]
                               [--anomalies-only] [--json]

Read-only health audit of cross-shard INBOUND-receipt reconciliation
(v2.7 F2 / S-016). Walks a window of finalized blocks, reports per-block
inbound_receipts admission counts, and — when the genesis-pinned F2
activation height is supplied — classifies each admitting block as
F2-active (reconciled via committed-view INTERSECTION) or pre-F2, and
flags any below-activation admissions as a config-drift signal.

The F2 activation height (v2_7_f2_active_from_height) is genesis-pinned
and NOT exposed by any RPC; read it from the deployment's genesis.json
and pass it with --f2-activation-height. When omitted, inbound counts
are still reported but the F2-regime classification is skipped.

Options:
  --rpc-port N              RPC port to query (default: 7778)
  --f2-activation-height N  Genesis-pinned v2_7_f2_active_from_height.
                            When set, blocks at/after H are F2-active.
  --from H                  Start of audit window (default: max(0, head-1000))
  --to H                    End of audit window (default: head-1)
  --anomalies-only          Print only flagged anomalies; exit 2 if any fire
  --json                    Emit structured JSON envelope instead of table
  -h, --help                Show this help

Anomaly flags:
  below_activation_admission   --f2-activation-height supplied AND ≥1 block
                               below H admitted inbound receipts (config /
                               genesis-pin drift signal; not a consensus
                               violation)

Exit codes:
  0   success / informational (or single-shard deployment)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
F2_HEIGHT=""
FROM_H=""
TO_H=""
ANOM_ONLY=0
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)               usage; exit 0 ;;
    --rpc-port)              PORT="${2:-}";       shift 2 ;;
    --f2-activation-height)  F2_HEIGHT="${2:-}";  shift 2 ;;
    --from)                  FROM_H="${2:-}";     shift 2 ;;
    --to)                    TO_H="${2:-}";       shift 2 ;;
    --anomalies-only)        ANOM_ONLY=1;         shift ;;
    --json)                  JSON_OUT=1;          shift ;;
    *) echo "operator_inbound_reconciliation_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_inbound_reconciliation_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$F2_HEIGHT" "$FROM_H" "$TO_H"; do
  [ -z "$v" ] && continue
  case "$v" in *[!0-9]*)
    echo "operator_inbound_reconciliation_audit: --f2-activation-height / --from / --to must be unsigned integers (got '$v')" >&2
    exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_inbound_reconciliation_audit: jq is required (per-block JSON is too nested for grep)" >&2
  exit 1
fi
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_inbound_reconciliation_audit: python is required for per-block aggregation" >&2
  exit 1
fi
PY=python; command -v python >/dev/null 2>&1 || PY=python3

# ── Step 1: probe daemon for shard config ────────────────────────────────────
STATUS_JSON=$("$DETERM" status --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_inbound_reconciliation_audit: RPC error from \`determ status\` (is daemon on port $PORT?)" >&2
  exit 1
}
MY_SHARD_ID=$(printf '%s' "$STATUS_JSON" | jq -r '.shard_id // 0')
case "$MY_SHARD_ID" in *[!0-9]*|"") MY_SHARD_ID=0 ;; esac
SHARDING_MODE=$(printf '%s' "$STATUS_JSON" | jq -r '.protections.sharding_mode // "unknown"')

# Resolve head height.
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_inbound_reconciliation_audit: RPC error from \`determ head\` (port $PORT)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height // 0')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_inbound_reconciliation_audit: malformed head JSON (port $PORT)" >&2
  exit 1 ;;
esac

# Single-shard short-circuit. sharding_mode=="none" → inbound_receipts is
# empty in every block by construction (no cross-shard traffic).
if [ "$SHARDING_MODE" = "none" ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"my_shard_id":%s,"sharding_mode":"none","head_height":%s,"f2_activation_height":%s,"window":null,"totals":{"blocks_with_inbound":0,"inbound_receipt_count":0,"f2_active_admissions":0,"pre_f2_admissions":0,"below_activation_admissions":0},"blocks":[],"anomalies":[],"rpc_port":%s,"info":"single_shard_deployment"}\n' \
      "$MY_SHARD_ID" "$HEIGHT" "${F2_HEIGHT:-null}" "$PORT"
  else
    echo "INFO: single-shard deployment — no inbound receipts by construction (sharding_mode=none, port $PORT)"
  fi
  exit 0
fi

# Empty chain short-circuit.
if [ "$HEIGHT" -eq 0 ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"my_shard_id":%s,"sharding_mode":"%s","head_height":0,"f2_activation_height":%s,"window":null,"totals":{"blocks_with_inbound":0,"inbound_receipt_count":0,"f2_active_admissions":0,"pre_f2_admissions":0,"below_activation_admissions":0},"blocks":[],"anomalies":[],"rpc_port":%s,"info":"empty_chain"}\n' \
      "$MY_SHARD_ID" "$SHARDING_MODE" "${F2_HEIGHT:-null}" "$PORT"
  else
    echo "operator_inbound_reconciliation_audit: chain has no finalized blocks yet (height=0, port $PORT)"
  fi
  exit 0
fi

# Default window: last 1000 blocks ending at the head. Highest finalized
# index is height-1.
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))
FROM=${FROM_H:-$(( TOP > 1000 ? TOP - 1000 + 1 : 0 ))}
TO=${TO_H:-$TOP}
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_inbound_reconciliation_audit: --to ($TO) < --from ($FROM); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 2: walk window via block-info --json + aggregate ─────────────────────
TMP_OUT=$(mktemp) || {
  echo "operator_inbound_reconciliation_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

# F2_HEIGHT_ARG: empty string passed through means "unknown" to the python
# driver (it treats "" as None and skips the F2-regime classification).
"$PY" - "$DETERM" "$PORT" "$FROM" "$TO" "${F2_HEIGHT:-}" "$TMP_OUT" <<'PY'
import json, subprocess, sys

determ, port, from_h, to_h, f2_h_s, out_path = sys.argv[1:7]
from_h = int(from_h); to_h = int(to_h)
f2_h = int(f2_h_s) if f2_h_s != "" else None

blocks = []                       # per-block records (only those with inbound>0)
blocks_with_inbound = 0
inbound_receipt_count = 0
f2_active_admissions = 0          # receipts admitted in blocks index >= f2_h
pre_f2_admissions = 0             # receipts admitted in blocks index < f2_h
below_activation_blocks = []      # block indices < f2_h that admitted inbound

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_inbound_reconciliation_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_inbound_reconciliation_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_inbound_reconciliation_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    # Prefer the block's own index field; fall back to the walk counter.
    try:
        idx = int(blk.get("index", h))
    except Exception:
        idx = h

    ibrs = blk.get("inbound_receipts") or []
    n = len(ibrs)
    if n == 0:
        continue

    blocks_with_inbound += 1
    inbound_receipt_count += n

    # F2-regime classification: a block at/after the genesis-pinned
    # activation height went through the committed-view INTERSECTION
    # reconciliation before the body was baked (producer.cpp build_body).
    # Below the activation height, inbound receipts were admitted under the
    # pre-F2 time-ordered path — which, once the head is well past
    # activation, is a config / genesis-pin drift signal.
    if f2_h is None:
        f2_active = None
    else:
        f2_active = (idx >= f2_h)
        if f2_active:
            f2_active_admissions += n
        else:
            pre_f2_admissions += n
            below_activation_blocks.append(idx)

    blocks.append({"index": idx, "inbound_count": n, "f2_active": f2_active})

result = {
    "blocks": blocks,
    "blocks_with_inbound": blocks_with_inbound,
    "inbound_receipt_count": inbound_receipt_count,
    "f2_active_admissions": f2_active_admissions,
    "pre_f2_admissions": pre_f2_admissions,
    "below_activation_blocks": below_activation_blocks,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f)
PY
if [ "$?" -ne 0 ]; then
  echo "operator_inbound_reconciliation_audit: block-walk failed" >&2
  exit 1
fi

WALK_JSON=$(cat "$TMP_OUT")

BLOCKS_WITH_INBOUND=$(printf '%s' "$WALK_JSON" | jq -r '.blocks_with_inbound')
INBOUND_COUNT=$(printf '%s'      "$WALK_JSON" | jq -r '.inbound_receipt_count')
F2_ACTIVE_ADM=$(printf '%s'      "$WALK_JSON" | jq -r '.f2_active_admissions')
PRE_F2_ADM=$(printf '%s'         "$WALK_JSON" | jq -r '.pre_f2_admissions')
BELOW_COUNT=$(printf '%s'        "$WALK_JSON" | jq -r '.below_activation_blocks | length')

# ── Step 3: assemble anomalies ───────────────────────────────────────────────
# below_activation_admission only fires when --f2-activation-height was
# supplied (otherwise the regime is unknown and BELOW_COUNT is 0).
ANOMALIES=""
if [ -n "$F2_HEIGHT" ] && [ "$BELOW_COUNT" -gt 0 ]; then
  ANOMALIES="below_activation_admission"
fi
ANOM_COUNT=0
[ -n "$ANOMALIES" ] && ANOM_COUNT=1

# ── Step 4: render ───────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  F2_H_JSON="${F2_HEIGHT:-null}"
  ANOM_JSON=$(if [ -z "$ANOMALIES" ]; then printf '[]'; else printf '["%s"]' "$ANOMALIES"; fi)
  if [ "$ANOM_ONLY" = "1" ]; then
    BLOCKS_ARR="[]"
  else
    BLOCKS_ARR=$(printf '%s' "$WALK_JSON" | jq -c '.blocks')
  fi
  printf '{"my_shard_id":%s,"sharding_mode":"%s","head_height":%s,"f2_activation_height":%s,"window":{"from":%s,"to":%s,"blocks":%s},"totals":{"blocks_with_inbound":%s,"inbound_receipt_count":%s,"f2_active_admissions":%s,"pre_f2_admissions":%s,"below_activation_block_count":%s},"blocks":%s,"anomalies":%s,"rpc_port":%s}\n' \
    "$MY_SHARD_ID" "$SHARDING_MODE" "$HEIGHT" "$F2_H_JSON" \
    "$FROM" "$TO" "$WIN_BLOCKS" \
    "$BLOCKS_WITH_INBOUND" "$INBOUND_COUNT" "$F2_ACTIVE_ADM" "$PRE_F2_ADM" "$BELOW_COUNT" \
    "$BLOCKS_ARR" "$ANOM_JSON" "$PORT"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_inbound_reconciliation_audit: no anomalies (port $PORT, window [$FROM..$TO], shard $MY_SHARD_ID)"
  else
    echo "=== Inbound-receipt reconciliation audit (port $PORT, window [$FROM..$TO], $WIN_BLOCKS blocks) ==="
    echo "My shard: $MY_SHARD_ID  [sharding_mode: $SHARDING_MODE]  head_height: $HEIGHT"
    if [ -n "$F2_HEIGHT" ]; then
      echo "F2 activation height: $F2_HEIGHT (blocks at/after this height are F2-reconciled)"
    else
      echo "F2 activation height: (not supplied — F2-regime classification skipped)"
      echo "  Pass --f2-activation-height N (read v2_7_f2_active_from_height from genesis.json)"
      echo "  to classify admissions as F2-active vs pre-F2 and enable the drift gate."
    fi
    echo "Blocks admitting inbound receipts: $BLOCKS_WITH_INBOUND of $WIN_BLOCKS"
    echo "Total inbound receipts admitted:   $INBOUND_COUNT"
    if [ -n "$F2_HEIGHT" ]; then
      echo "  F2-active admissions (idx >= $F2_HEIGHT): $F2_ACTIVE_ADM"
      echo "  pre-F2 admissions    (idx <  $F2_HEIGHT): $PRE_F2_ADM"
    fi

    if [ "$ANOM_ONLY" != "1" ] && [ "$BLOCKS_WITH_INBOUND" -gt 0 ]; then
      echo "Per-block admissions (blocks with inbound_receipts, up to 20 shown):"
      printf '%s' "$WALK_JSON" | jq -r '
        .blocks[:20][]
        | [.index, .inbound_count,
           (if .f2_active == true then "F2-active"
            elif .f2_active == false then "pre-F2"
            else "unknown" end)] | @tsv' | \
      while IFS=$'\t' read -r IDX CNT REGIME; do
        printf '  block %s: %s inbound receipt(s) [%s]\n' "$IDX" "$CNT" "$REGIME"
      done
    fi

    if [ -n "$F2_HEIGHT" ] && [ "$BELOW_COUNT" -gt 0 ]; then
      echo "[ANOMALY] below_activation_admission — $BELOW_COUNT block(s) below the F2"
      echo "          activation height ($F2_HEIGHT) admitted inbound receipts. This is a"
      echo "          config / genesis-pin drift signal (not a consensus violation): those"
      echo "          blocks used the pre-F2 (non-reconciled) admission path. Verify the"
      echo "          deployment's genesis v2_7_f2_active_from_height matches expectation."
      printf '%s' "$WALK_JSON" | jq -r '.below_activation_blocks[:10][] | "          below-activation block: \(.)"'
    elif [ -n "$F2_HEIGHT" ]; then
      echo "[OK] all inbound admissions in window are at/after the F2 activation height."
    else
      echo "[OK] inbound admissions reported (F2-regime gate skipped — no activation height supplied)."
    fi
  fi
fi

# ── Step 5: exit-code policy ─────────────────────────────────────────────────
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
