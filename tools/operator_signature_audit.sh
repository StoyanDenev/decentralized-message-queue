#!/usr/bin/env bash
# operator_signature_audit.sh — K-of-K committee-signature distribution
# audit over a window of finalized blocks, with BFT-mode detection.
#
# Operator concern:
#   In healthy K-of-K consensus every committee member should be signing
#   every block they're selected for. A validator that's consistently
#   missing sigs is offline, partitioned, or buggy. A window dominated
#   by sub-K (BFT-mode) blocks signals that the cluster is sitting in
#   escalation — K-of-K is the steady state; BFT-mode is the fallback.
#
# Data source:
#   For each block in the window, `determ block-info <h> --json` returns
#   the full Block JSON. We extract two parallel arrays:
#       creators[]           — K validator domains in committee order
#       creator_block_sigs[] — K signatures (Ed25519 over compute_block_digest)
#                              encoded as 128-character hex strings. The
#                              all-zero sentinel ("0"*128) means "this
#                              validator did not sign / sig was not
#                              gathered in time". block.cpp's to_hex
#                              emits lowercase; we compare case-insensitively.
#
# Per-validator across the window:
#       selections    = # blocks in which validator appeared in creators[]
#       valid_sigs    = # blocks where their parallel slot was non-sentinel
#       missing_sigs  = selections - valid_sigs
#       miss_rate     = missing_sigs / selections (undefined if 0)
#       max_streak    = longest run of consecutive SELECTED blocks
#                       (in chain order) where they missed; off-duty
#                       blocks (not in creators[]) don't extend or reset
#                       the streak — only blocks where they had a duty.
#
# Window-wide aggregates:
#       total_blocks        = # blocks walked
#       total_slots         = Σ len(creators[]) over the window
#       total_valid         = Σ non-sentinel sigs
#       total_missing       = total_slots - total_valid
#       sig_fill_ratio      = total_valid / total_slots
#       k_mode_blocks       = # blocks where #sigs == K (full K-of-K)
#       bft_mode_blocks     = # blocks where #sigs < K AND #sigs >= Q
#                             where Q = ceil(2 * ceil(2K/3) / 3) is the
#                             BFT quorum threshold computed per-block
#                             from the observed K (so the audit stays
#                             correct under any committee size). A block
#                             with #sigs < Q is in neither bucket
#                             (degraded / pending finalization — should
#                             be rare for FINALIZED blocks but possible
#                             on the boundary).
#
# Anomalies:
#   validator_consistent_missing  any validator's miss_rate > 0.30
#                                 (chronic-downtime signal — on-call review)
#   bft_mode_dominant             > 50% of blocks are in BFT-mode
#                                 (K-of-K should be the steady state)
#   sig_fill_ratio_low            total_valid / total_slots < 0.80
#                                 (broader cluster-health signal — chronic
#                                 committee-participation gap)
#   validator_missing_streak      any single validator has consecutive
#                                 missed-streak > 10 (sustained downtime)
#
# Args:
#   [--rpc-port N]        RPC port to query (default: 8081)
#   [--from H]            Lower window bound, inclusive
#   [--to H]              Upper window bound, inclusive
#   [--last N]            Shorthand for [head-N+1, head] (default: 1000)
#   [--validator <dom>]   Filter by_validator output (cosmetic only —
#                         summary + anomalies still computed across the
#                         full population)
#   [--json]              Emit structured JSON envelope
#   [--anomalies-only]    Print only when ≥1 anomaly fires
#   [-h|--help]           Show this help
#
# Exit codes:
#   0   audit ran; no anomalies (or --anomalies-only set with no anomalies)
#   1   bad args / RPC error / malformed response
#   2   ≥1 anomaly fired (operator alert gate — sustained sig drift)
set -u

usage() {
  cat <<'EOF'
Usage: operator_signature_audit.sh [--rpc-port N]
                                   [--from H] [--to H] [--last N]
                                   [--validator <domain>]
                                   [--json] [--anomalies-only]

Audit the K-of-K committee-signature distribution over a window of
finalized blocks and detect BFT-mode escalation. For each block in the
window, parses `creators[]` + `creator_block_sigs[]` and tallies:

Per-validator:
  selections    blocks where they were drawn into the committee
  valid_sigs    non-sentinel signatures in their parallel slot
  missing_sigs  selections - valid_sigs
  miss_rate     missing_sigs / selections
  max_streak    longest consecutive SELECTED-but-missed streak
                (off-duty blocks neither extend nor reset)

Window-wide:
  total_blocks       blocks walked
  total_slots        sum of len(creators[]) across blocks
  total_valid        sum of non-sentinel signatures
  sig_fill_ratio     total_valid / total_slots
  k_mode_blocks      blocks with #sigs == K (full K-of-K)
  bft_mode_blocks    blocks with Q <= #sigs < K (BFT escalation)
                     where Q = ceil(2 * ceil(2K/3) / 3) per-block

Options:
  --rpc-port N          RPC port (default: 8081)
  --from H              Lower window bound, inclusive
                        (default: max(0, head - 999))
  --to H                Upper window bound, inclusive
                        (default: head)
  --last N              Shorthand for [head-N+1, head]
                        (default: 1000; exclusive with --from/--to)
  --validator <domain>  Limit by_validator output to this domain;
                        summary + anomalies still computed across the
                        full population (filter is cosmetic)
  --json                Emit structured JSON envelope
  --anomalies-only      Suppress healthy-state rows; pair with --json
                        for monitoring ingestion. Exit 2 when ≥1 anomaly
                        fires; exit 0 with quiet "OK" line otherwise.
  -h, --help            Show this help

Anomalies:
  validator_consistent_missing  miss_rate > 0.30 for any validator
  bft_mode_dominant             > 50% of blocks in BFT-mode
  sig_fill_ratio_low            total_valid / total_slots < 0.80
  validator_missing_streak      max_streak > 10 for any validator

JSON shape:
  {"window": {"from": F, "to": T},
   "by_validator": [{"domain":..., "selections":..., "valid_sigs":...,
                     "missing_sigs":..., "miss_rate":..., "max_streak":...},
                    ...],
   "summary": {"total_blocks":..., "total_slots":..., "total_valid":...,
               "sig_fill_ratio":..., "k_mode_blocks":...,
               "bft_mode_blocks":...},
   "anomalies": [...],
   "rpc_port": N}

Exit codes:
  0   success, no anomalies (or --anomalies-only set with no anomalies)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   ≥1 anomaly fired (operator alert gate)
EOF
}

PORT=8081
FROM=""
TO=""
LAST=""
VALIDATOR=""
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";      shift 2 ;;
    --from)           FROM="${2:-}";      shift 2 ;;
    --to)             TO="${2:-}";        shift 2 ;;
    --last)           LAST="${2:-}";      shift 2 ;;
    --validator)      VALIDATOR="${2:-}"; shift 2 ;;
    --json)           JSON_OUT=1;         shift ;;
    --anomalies-only) ANOM_ONLY=1;        shift ;;
    *) echo "operator_signature_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_signature_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
if [ -n "$LAST" ] && { [ -n "$FROM" ] || [ -n "$TO" ]; }; then
  echo "operator_signature_audit: --last cannot be combined with --from/--to" >&2
  exit 1
fi
for v in "$FROM" "$TO" "$LAST"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_signature_audit: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST" ] && [ "$LAST" = "0" ]; then
  echo "operator_signature_audit: --last must be >= 1" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_signature_audit: jq is required (block JSON traversal)" >&2
  exit 1
fi

# ── Step 1: resolve chain head ────────────────────────────────────────────────
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_signature_audit: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height // ""')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_signature_audit: malformed head JSON (height='$HEIGHT')" >&2
  exit 1 ;;
esac

# Highest finalized index = height - 1 (height is the NEXT-to-produce).
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))

# Resolve window bounds. --last > (--from/--to) > default-last-1000.
if [ -n "$LAST" ]; then
  if [ "$LAST" -gt $(( TOP + 1 )) ]; then
    FROM=0
  else
    FROM=$(( TOP - LAST + 1 ))
  fi
  TO=$TOP
else
  if [ -z "$TO" ]; then TO=$TOP; fi
  if [ -z "$FROM" ]; then
    if [ "$TOP" -gt 999 ]; then
      FROM=$(( TOP - 999 ))
    else
      FROM=0
    fi
  fi
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_signature_audit: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi
WINDOW=$(( TO - FROM + 1 ))

# ── Step 2: per-block walk → flat NDJSON of (domain, sig_hex, K-per-block) ────
# We stream a per-slot record per block to a temp file, then jq-reduce
# into per-validator and window-wide aggregates. Streaming keeps memory
# bounded for very large windows.
#
# Record shape (one per slot per block):
#   {"h": H, "dom": "<domain>", "sig_hex": "<128hex>",
#    "block_k": K, "valid_sigs_in_block": V}
#
# We also emit one "block-summary" record per block (separated by a
# leading "_kind":"block") so jq can classify each block as K-mode /
# BFT-mode / sub-quorum without re-scanning the slot stream.
ZERO_SIG="$(printf '0%.0s' {1..128})"
TMP_NDJSON=$(mktemp 2>/dev/null) || {
  echo "operator_signature_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_NDJSON" 2>/dev/null' EXIT

H=$FROM
while [ "$H" -le "$TO" ]; do
  BLK_JSON=$("$DETERM" block-info "$H" --json --rpc-port "$PORT" 2>/dev/null) || {
    echo "operator_signature_audit: RPC error from \`determ block-info $H\` (port $PORT)" >&2
    exit 1
  }
  # Validate JSON shape; bail loudly on malformed blocks rather than
  # silently dropping them (they'd skew the sig_fill_ratio downward).
  if ! printf '%s' "$BLK_JSON" | jq -e 'type == "object"' >/dev/null 2>&1; then
    echo "operator_signature_audit: block-info $H returned non-object JSON" >&2
    exit 1
  fi

  # Per-block reduction emits:
  #   - one "_kind":"slot" record per creator/sig pair
  #   - one "_kind":"block" summary record (K + valid_count for classification)
  # The all-zero sentinel ("0"*128, case-insensitive) means "didn't sign".
  printf '%s' "$BLK_JSON" | jq -c --arg zero "$ZERO_SIG" --argjson h "$H" '
    (.creators            // []) as $cs
    | (.creator_block_sigs // []) as $sigs
    | ($cs | length) as $K
    | ([range(0; $K)
        | { idx: ., dom: ($cs[.] // ""), sig: ($sigs[.] // "") }
        | select(.dom != "")
       ]) as $slots
    | ([$slots[]
        | (.sig | ascii_downcase) as $lsig
        | select($lsig != $zero and ($lsig | length) > 0)
       ] | length) as $valid_in_block
    | (
        ($slots[] | {
          _kind: "slot",
          h: $h,
          dom: .dom,
          sig_zero: ((.sig | ascii_downcase) == $zero or (.sig | length) == 0)
        }),
        { _kind: "block",
          h: $h,
          K: $K,
          valid_in_block: $valid_in_block }
      )
  ' >> "$TMP_NDJSON" || {
    echo "operator_signature_audit: jq projection failed on block $H" >&2
    exit 1
  }
  H=$(( H + 1 ))
done

# ── Step 3: aggregate via jq (per-validator + window) ────────────────────────
# Strategy:
#   Pass 1 (window aggregates): consume only _kind=="block" records.
#                               Compute total_blocks, total_slots,
#                               total_valid, k_mode_blocks,
#                               bft_mode_blocks. For each block, derive
#                               Q = ceil(2 * ceil(2K/3) / 3) and classify.
#   Pass 2 (per-validator):    consume only _kind=="slot" records.
#                              Group by dom; tally selections + valid +
#                              max consecutive missed-streak (in chain
#                              order — the NDJSON is already sorted by H
#                              because we walked sequentially).
TMP_AGG=$(mktemp 2>/dev/null) || {
  echo "operator_signature_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_NDJSON" "$TMP_AGG" 2>/dev/null' EXIT

# Window-wide pass.
WINDOW_JSON=$(jq -s -c '
  # Helpers: ceil(a/b) for integers a,b>0.
  def ceildiv(a; b): ((a + b - 1) / b | floor);

  ([.[] | select(._kind == "block")]) as $blocks
  | ($blocks | length)                          as $total_blocks
  | ([$blocks[].K]              | add // 0)     as $total_slots
  | ([$blocks[].valid_in_block] | add // 0)     as $total_valid
  | ([$blocks[]
      | .K              as $K
      | .valid_in_block as $V
      # Q = ceil(2 * ceil(2K/3) / 3) per PROTOCOL.md §5.3 (k_bft = ceil(2K/3),
      # Q = ceil(2 * k_bft / 3)). For K==3 (genesis-default) this gives
      # k_bft=2, Q=2 — a degenerate point where K-mode and BFT-mode are
      # the same number of sigs; we still distinguish them on V vs K
      # equality, so K-mode wins the tie (V == K).
      | (ceildiv(2 * $K; 3))     as $kbft
      | (ceildiv(2 * $kbft; 3))  as $Q
      | if $K == 0 then "empty"
        elif $V == $K then "k_mode"
        elif $V >= $Q then "bft_mode"
        else "sub_quorum"
        end
     ]) as $modes
  | ([$modes[] | select(. == "k_mode")]   | length) as $k_mode_blocks
  | ([$modes[] | select(. == "bft_mode")] | length) as $bft_mode_blocks
  | {
      total_blocks:    $total_blocks,
      total_slots:     $total_slots,
      total_valid:     $total_valid,
      total_missing:   ($total_slots - $total_valid),
      sig_fill_ratio:  (if $total_slots > 0
                        then ($total_valid / $total_slots)
                        else 0.0 end),
      k_mode_blocks:   $k_mode_blocks,
      bft_mode_blocks: $bft_mode_blocks
    }
' "$TMP_NDJSON")
if [ -z "$WINDOW_JSON" ]; then
  echo "operator_signature_audit: window aggregation failed" >&2
  exit 1
fi

# Per-validator pass. Group all slot-records by domain; the input is
# already in chain order (H ascending, slot ascending within block) so
# we can walk each domain's stream and accumulate streak in one pass.
BY_VAL_JSON=$(jq -s -c '
  [.[] | select(._kind == "slot")]
  | group_by(.dom)
  | map(
      . as $rs
      | $rs[0].dom as $dom
      | ($rs | length) as $selections
      | ($rs | map(select(.sig_zero | not)) | length) as $valid_sigs
      | (($selections - $valid_sigs)) as $missing_sigs
      | (if $selections > 0 then ($missing_sigs / $selections) else 0.0 end) as $miss_rate
      # Walk in chain order to find longest consecutive missed-streak.
      # Slots are already sorted by H ascending because the NDJSON
      # streams were appended in chain order.
      | (reduce $rs[] as $r ({cur: 0, max: 0};
          if $r.sig_zero
          then {cur: (.cur + 1), max: (if .cur + 1 > .max then .cur + 1 else .max end)}
          else {cur: 0, max: .max}
          end)
        ) as $streak
      | {
          domain:       $dom,
          selections:   $selections,
          valid_sigs:   $valid_sigs,
          missing_sigs: $missing_sigs,
          miss_rate:    $miss_rate,
          max_streak:   $streak.max
        }
    )
  | sort_by(-.miss_rate, -.max_streak, .domain)
' "$TMP_NDJSON")
if [ -z "$BY_VAL_JSON" ]; then
  # Empty window or no committee activity — emit empty list rather than
  # erroring; downstream code handles the no-validator-observed case.
  BY_VAL_JSON='[]'
fi

# ── Step 4: anomaly classification (jq side, single envelope build) ──────────
# Build the final envelope. Anomalies are computed against the FULL
# by_validator list (the --validator filter is applied only at render
# time on a copy — see Step 5 — to keep summary + anomalies cluster-wide).
ENVELOPE=$(jq -n -c \
  --argjson win "$WINDOW_JSON" \
  --argjson by  "$BY_VAL_JSON" \
  --argjson from "$FROM" \
  --argjson to   "$TO" \
  --argjson port "$PORT" '
  ($by) as $rows
  | ($win) as $summary
  | (
      []
      # validator_consistent_missing: miss_rate > 0.30 (with at least
      # one selection — a validator with selections == 0 has miss_rate
      # 0 by construction and wouldnt fire, but the guard is explicit).
      + (if any($rows[]; .selections > 0 and .miss_rate > 0.30)
         then ["validator_consistent_missing"] else [] end)
      # bft_mode_dominant: > 50% of (k_mode + bft_mode) blocks are
      # BFT-mode. We exclude sub_quorum + empty blocks from the
      # denominator so the threshold reflects true escalation density
      # vs noise from degraded boundary blocks.
      + (if (($summary.k_mode_blocks + $summary.bft_mode_blocks) > 0
             and $summary.bft_mode_blocks
                 > ($summary.k_mode_blocks + $summary.bft_mode_blocks) * 0.5)
         then ["bft_mode_dominant"] else [] end)
      # sig_fill_ratio_low: < 0.80 across the window (only meaningful
      # when total_slots > 0 — empty windows trivially fail the ratio
      # comparison since 0/0 is set to 0.0 above, but we guard anyway).
      + (if $summary.total_slots > 0 and $summary.sig_fill_ratio < 0.80
         then ["sig_fill_ratio_low"] else [] end)
      # validator_missing_streak: max_streak > 10.
      + (if any($rows[]; .max_streak > 10)
         then ["validator_missing_streak"] else [] end)
    ) as $anomalies
  | {
      window:       {from: $from, to: $to},
      by_validator: $rows,
      summary:      $summary,
      anomalies:    $anomalies,
      rpc_port:     $port
    }
')

ANOM_COUNT=$(printf '%s' "$ENVELOPE" | jq -r '.anomalies | length')

# ── Step 5: render ───────────────────────────────────────────────────────────
emit_json() {
  if [ -n "$VALIDATOR" ]; then
    printf '%s' "$ENVELOPE" | jq --arg v "$VALIDATOR" '
      .by_validator |= map(select(.domain == $v))
      | . + {filter_validator: $v}
    '
  else
    printf '%s' "$ENVELOPE" | jq .
  fi
}

emit_human() {
  echo "=== Signature audit (port $PORT, window [$FROM..$TO], $WINDOW blocks) ==="
  TB=$(printf '%s' "$ENVELOPE" | jq -r '.summary.total_blocks')
  TS=$(printf '%s' "$ENVELOPE" | jq -r '.summary.total_slots')
  TV=$(printf '%s' "$ENVELOPE" | jq -r '.summary.total_valid')
  TM=$(printf '%s' "$ENVELOPE" | jq -r '.summary.total_missing')
  KMB=$(printf '%s' "$ENVELOPE" | jq -r '.summary.k_mode_blocks')
  BMB=$(printf '%s' "$ENVELOPE" | jq -r '.summary.bft_mode_blocks')
  SFR=$(printf '%s' "$ENVELOPE" | jq -r '.summary.sig_fill_ratio | (. * 10000 | round / 100)')
  echo "Blocks: $TB    Slots: $TS    Valid: $TV    Missing: $TM"
  echo "Sig-fill ratio: ${SFR}%    K-mode: $KMB    BFT-mode: $BMB"
  if [ -n "$VALIDATOR" ]; then
    echo "Filter: validator='$VALIDATOR' (summary + anomalies still cluster-wide)"
  fi
  echo

  # Per-validator table. Filter applied here (cosmetic).
  if [ -n "$VALIDATOR" ]; then
    ROWS=$(printf '%s' "$ENVELOPE" | jq -c --arg v "$VALIDATOR" '
      .by_validator | map(select(.domain == $v))
    ')
  else
    ROWS=$(printf '%s' "$ENVELOPE" | jq -c '.by_validator')
  fi
  N_ROWS=$(printf '%s' "$ROWS" | jq 'length')

  if [ "$N_ROWS" = "0" ]; then
    if [ -n "$VALIDATOR" ]; then
      echo "[INFO] No committee appearances by '$VALIDATOR' in window"
    else
      echo "[INFO] No committee activity observed in window"
    fi
  else
    echo "Per-validator signatures (ranked by miss_rate, worst first):"
    printf '  %-28s %8s %7s %7s %7s %7s\n' \
      "domain" "selected" "signed" "missed" "miss%" "streak"
    printf '  %-28s %8s %7s %7s %7s %7s\n' \
      "----------------------------" "--------" "-------" "-------" "-------" "-------"
    # @tsv emits the per-validator row as tab-separated values; the
    # while-read loop applies printf column widths uniformly so very
    # long domains get truncated to 28 chars and miss_rate renders with
    # a trailing "%". Same column widths as the header above.
    printf '%s' "$ROWS" | jq -r '.[]
      | [.domain, .selections, .valid_sigs, .missing_sigs,
         (.miss_rate * 1000 | round / 10), .max_streak]
      | @tsv
    ' | while IFS=$'\t' read -r dom sel sig miss mr streak; do
      dom_short="${dom:0:28}"
      printf '  %-28s %8s %7s %7s %6s%% %7s\n' \
        "$dom_short" "$sel" "$sig" "$miss" "$mr" "$streak"
    done
  fi

  echo
  if [ "$ANOM_COUNT" = "0" ]; then
    echo "[OK] No signature-distribution anomalies"
  else
    printf '%s' "$ENVELOPE" | jq -r '.anomalies[]' | while IFS= read -r A; do
      case "$A" in
        validator_consistent_missing)
          OFF=$(printf '%s' "$ENVELOPE" | jq -r '
            [.by_validator[]
              | select(.selections > 0 and .miss_rate > 0.30)
              | "\(.domain) (\(.miss_rate * 1000 | round / 10)%)"
            ] | .[0:3] | join(", ")
          ')
          MORE=$(printf '%s' "$ENVELOPE" | jq -r '
            ([.by_validator[]
              | select(.selections > 0 and .miss_rate > 0.30)] | length) - 3
          ')
          if [ "$MORE" -gt 0 ]; then OFF="$OFF, +$MORE more"; fi
          echo "[WARN] validator_consistent_missing — miss_rate > 30%: $OFF"
          ;;
        bft_mode_dominant)
          echo "[WARN] bft_mode_dominant — >50% of classified blocks in BFT-mode ($BMB/$((KMB + BMB)))"
          ;;
        sig_fill_ratio_low)
          echo "[WARN] sig_fill_ratio_low — overall sig-fill ${SFR}% (< 80%)"
          ;;
        validator_missing_streak)
          OFF=$(printf '%s' "$ENVELOPE" | jq -r '
            [.by_validator[]
              | select(.max_streak > 10)
              | "\(.domain) (streak=\(.max_streak))"
            ] | .[0:3] | join(", ")
          ')
          MORE=$(printf '%s' "$ENVELOPE" | jq -r '
            ([.by_validator[] | select(.max_streak > 10)] | length) - 3
          ')
          if [ "$MORE" -gt 0 ]; then OFF="$OFF, +$MORE more"; fi
          echo "[WARN] validator_missing_streak — streak > 10: $OFF"
          ;;
        *)
          echo "[WARN] $A"
          ;;
      esac
    done
  fi
}

# --anomalies-only: suppress non-anomaly output entirely; exit 2 when
# anomalies fired, 0 with a quiet summary line otherwise.
if [ "$ANOM_ONLY" = "1" ]; then
  if [ "$ANOM_COUNT" -gt 0 ]; then
    if [ "$JSON_OUT" = "1" ]; then emit_json; else emit_human; fi
    exit 2
  fi
  echo "operator_signature_audit: no anomalies (port $PORT, window [$FROM..$TO], $WINDOW blocks)"
  exit 0
fi

if [ "$JSON_OUT" = "1" ]; then emit_json; else emit_human; fi

# Default behavior: any anomaly is an alert-worthy exit (2).
if [ "$ANOM_COUNT" -gt 0 ]; then exit 2; fi
exit 0
