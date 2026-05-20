#!/usr/bin/env bash
# operator_equivocation_digest.sh — Aggregate FA6 equivocation slashing
# events across a window of finalized blocks on a running determ daemon.
#
# FA6 equivocation slashing: when a validator signs two conflicting
# BlockSigMsgs at the same height (same Ed25519 key, two different
# block digests), any node can submit the two-signature proof. Once
# baked into a finalized block as an `EquivocationEvent`, the offender
# forfeits their ENTIRE locked stake and their registry entry is
# deactivated (much harsher than the SUSPENSION_SLASH penalty applied
# for round-1 aborts). This script gives operators a forensic digest:
# "what equivocation events landed on this chain and who paid?"
#
# Read-only RPC; safe against any running daemon. Daemon must already
# be listening on --rpc-port. Requires `jq` for JSON traversal of the
# nested block payloads.
#
# Usage:
#   tools/operator_equivocation_digest.sh [--rpc-port N] [--json] \
#                                         [--from H] [--to H] \
#                                         [--by-offender]
#
# Defaults:
#   --rpc-port      7778
#   --from / --to   last 1000 blocks ending at current head (clamped to 0)
#   --by-offender   off (chronological listing); when set, groups by
#                   `equivocator` domain and prints per-offender totals.
#
# RPC dependencies:
#   * `head      --json`          — current chain height
#   * `block-range --json`        — paginated bulk fetch of block JSON
#                                   (uses headers RPC which retains
#                                   `equivocation_events` per block).
#
# Output:
#   Human (default):
#     chronological table — block_index, offender, slashed_amount,
#     evidence_summary; then footer with totals + range scanned.
#     With --by-offender: per-offender summary instead.
#   --json:
#     {events:[...], summary:{total_events, total_slashed,
#                             unique_offenders,
#                             by_offender:{...}, range:{from,to}}}
#
# Caveat on `slashed_amount`:
#   The on-chain `EquivocationEvent` does not carry the slashed amount
#   (the validator forfeits ENTIRE locked stake at apply time; the
#   per-event amount is folded into `accumulated_slashed` but not
#   stamped onto the event payload). This script surfaces whatever
#   `slashed_amount` field is present on the event payload (forward-
#   compat with a future EquivocationEvent schema bump); when absent
#   it reports 0. For an authoritative cumulative figure, cross-check
#   `accumulated_slashed` delta across the same range via the
#   `chain-summary` RPC.
#
# Exit codes:
#   0   success (zero equivocations is also success — empty result)
#   1   RPC error / daemon unreachable / malformed response / bad args
set -u

usage() {
  cat <<'EOF'
Usage: operator_equivocation_digest.sh [--rpc-port N] [--json]
                                       [--from H] [--to H] [--by-offender]

Aggregates EquivocationEvent payloads from finalized blocks across a
window and reports offender + slashed-amount totals.

Options:
  --rpc-port N    RPC port to query (default: 7778)
  --json          Emit a structured JSON envelope instead of human output
  --from H        Lower window bound (inclusive). Default: head - 1000.
  --to H          Upper window bound (inclusive). Default: current head.
  --by-offender   Group by offender domain (per-offender totals instead
                  of chronological listing).
  -h, --help      Show this help

Exit codes:
  0   success (zero events is also success)
  1   RPC error / bad args / malformed response
EOF
}

PORT=7778
JSON=0
FROM=""
TO=""
BY_OFFENDER=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --rpc-port) PORT="$2"; shift 2 ;;
    --json) JSON=1; shift ;;
    --from) FROM="$2"; shift 2 ;;
    --to) TO="$2"; shift 2 ;;
    --by-offender) BY_OFFENDER=1; shift ;;
    *) echo "operator_equivocation_digest: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Numeric guard on user-supplied window bounds (post --help so --help
# never trips it).
for v in "$FROM" "$TO"; do
  [ -z "$v" ] && continue
  case "$v" in *[!0-9]*)
    echo "operator_equivocation_digest: --from / --to must be unsigned integers" >&2
    exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_equivocation_digest: jq is required (block JSON is too nested for the grep fallback)" >&2
  exit 1
fi

# Resolve current head.
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_equivocation_digest: RPC error (is daemon running on port $PORT?)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_equivocation_digest: malformed head JSON (port $PORT)" >&2
  exit 1 ;;
esac

# Default window: last 1000 blocks ending at current head. `head`'s
# `height` is the next-to-be-produced index; the highest finalized
# block has index = height - 1. Operator-supplied --from / --to win.
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))
if [ -z "$TO" ]; then
  TO=$TOP
fi
if [ -z "$FROM" ]; then
  FROM=$(( TOP > 1000 ? TOP - 1000 + 1 : 0 ))
fi

# Bounds validation.
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_equivocation_digest: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi
if [ "$TO" -gt "$TOP" ]; then
  # Clamp to chain tail without error — operator likely typed `--to`
  # before the chain had caught up.
  TO=$TOP
fi
if [ "$TOP" -eq 0 ] && [ "$HEIGHT" -eq 0 ]; then
  # Empty chain — nothing to digest.
  if [ "$JSON" = "1" ]; then
    printf '{"events":[],"summary":{"total_events":0,"total_slashed":0,"unique_offenders":0,"by_offender":{},"range":{"from":%s,"to":%s}}}\n' \
      "$FROM" "$TO"
  else
    echo "operator_equivocation_digest: chain has no finalized blocks yet (height=0)"
    echo "  range scanned: [$FROM..$TO] (0 blocks)"
    echo "  total events: 0  total slashed: 0  unique offenders: 0"
  fi
  exit 0
fi

# Bulk-fetch the window via block-range --json (paginated via headers
# RPC server-side). Headers RPC keeps `equivocation_events` per block.
RANGE_JSON=$("$DETERM" block-range "$FROM" "$TO" --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_equivocation_digest: RPC error fetching block-range [$FROM..$TO] on port $PORT" >&2
  exit 1
}

# Extract events. Each event in JSON is enriched with the containing
# block's index + hash so downstream consumers don't need to re-walk.
# `block_index` on the event itself is the height at which the *double-
# sign occurred*; that's not the same as the containing block index
# (the block carrying the evidence may finalize many heights later).
# We surface both as `containing_block_index` vs event's own `height`.
EVENTS_JSON=$(printf '%s' "$RANGE_JSON" | jq -c '
  [ .headers[]
    | . as $blk
    | (.equivocation_events // [])[]
    | {
        containing_block_index: $blk.index,
        containing_block_hash:  $blk.block_hash,
        offender:               .equivocator,
        height:                 .block_index,
        shard_id:               (.shard_id // 0),
        beacon_anchor_height:   (.beacon_anchor_height // 0),
        digest_a:               .digest_a,
        digest_b:               .digest_b,
        slashed_amount:         (.slashed_amount // 0)
      }
  ]
') || {
  echo "operator_equivocation_digest: malformed block-range payload (port $PORT)" >&2
  exit 1
}

# Summary aggregations.
TOTAL_EVENTS=$(printf '%s' "$EVENTS_JSON" | jq 'length')
TOTAL_SLASHED=$(printf '%s' "$EVENTS_JSON" | jq '[.[].slashed_amount] | add // 0')
UNIQUE_OFFENDERS=$(printf '%s' "$EVENTS_JSON" | jq '[.[].offender] | unique | length')
BY_OFFENDER_JSON=$(printf '%s' "$EVENTS_JSON" | jq -c '
  group_by(.offender)
  | map({
      key:   .[0].offender,
      value: { events: length, slashed: ([.[].slashed_amount] | add // 0) }
    })
  | from_entries
')

if [ "$JSON" = "1" ]; then
  jq -n \
    --argjson events "$EVENTS_JSON" \
    --argjson by_offender "$BY_OFFENDER_JSON" \
    --argjson total_events "$TOTAL_EVENTS" \
    --argjson total_slashed "$TOTAL_SLASHED" \
    --argjson unique_offenders "$UNIQUE_OFFENDERS" \
    --argjson from "$FROM" \
    --argjson to "$TO" \
    '{
       events: $events,
       summary: {
         total_events:     $total_events,
         total_slashed:    $total_slashed,
         unique_offenders: $unique_offenders,
         by_offender:      $by_offender,
         range:            { from: $from, to: $to }
       }
     }'
  exit 0
fi

# Human output.
WINDOW=$(( TO - FROM + 1 ))
if [ "$TOTAL_EVENTS" = "0" ]; then
  echo "operator_equivocation_digest: no equivocation events in range [$FROM..$TO] ($WINDOW blocks scanned, port $PORT)"
  exit 0
fi

if [ "$BY_OFFENDER" = "1" ]; then
  echo "operator_equivocation_digest (by offender, range [$FROM..$TO], port $PORT):"
  printf '  %-25s %-10s %s\n' "offender" "events" "slashed"
  # Sort offenders by slashed-desc, ties by events-desc, ties by domain.
  printf '%s' "$BY_OFFENDER_JSON" | jq -r '
    to_entries
    | sort_by(-(.value.slashed), -(.value.events), .key)
    | .[]
    | "  \(.key | .[0:25] | .+ (" " * (25 - length))) \(.value.events | tostring | .+ (" " * (10 - length))) \(.value.slashed)"
  '
else
  echo "operator_equivocation_digest (chronological, range [$FROM..$TO], port $PORT):"
  printf '  %-8s %-25s %-12s %s\n' "block" "offender" "slashed" "evidence"
  printf '%s' "$EVENTS_JSON" | jq -r '
    sort_by(.containing_block_index, .offender)
    | .[]
    | "  " + (.containing_block_index | tostring | .+ (" " * (8 - length)))
          + (.offender | .[0:25] | .+ (" " * (25 - length))) + " "
          + (.slashed_amount | tostring | .+ (" " * (12 - length))) + " "
          + "two BlockSig at height " + (.height | tostring)
          + (if .shard_id != 0 then " (shard=" + (.shard_id|tostring) + ")" else "" end)
  '
fi

echo "  ---"
echo "  total events: $TOTAL_EVENTS  total slashed: $TOTAL_SLASHED  unique offenders: $UNIQUE_OFFENDERS  range: [$FROM..$TO] ($WINDOW blocks)"
if [ "$TOTAL_SLASHED" = "0" ] && [ "$TOTAL_EVENTS" != "0" ]; then
  echo "  note: slashed_amount not in EquivocationEvent payload; folded into accumulated_slashed (see chain-summary)."
fi
exit 0
