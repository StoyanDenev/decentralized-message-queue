#!/usr/bin/env bash
# operator_chain_export.sh — Export the full chain (or a height range)
# to a portable JSON / NDJSON / compact CSV format for offline analysis.
#
# Member of the `tools/operator_*.sh` family. Read-only RPC against a
# running determ daemon. Daemon must already be listening on --rpc-port.
#
# Output formats:
#   --format ndjson   (default) — one block per line, valid JSON each.
#                                 Streams directly; works on chains of
#                                 any length without buffering.
#   --format json                — single JSON array wrapping all blocks.
#                                 Convenient for jq / one-shot tools
#                                 BUT memory-intensive on long chains
#                                 (entire payload buffered before write).
#                                 Prefer ndjson for cold-archive.
#   --format compact             — per-block 1-line tuple:
#                                 index,timestamp,head_hash,prev_hash,
#                                 tx_count,creator_count (CSV-friendly).
#                                 Streams; tx_count requires full block
#                                 fetch (block-range strips transactions
#                                 server-side).
#
# Output destinations:
#   --out <file>     write to file; mkdirp parent if missing
#   (default)        stream to stdout
#
# Range (mutually exclusive):
#   --from H --to H  inclusive range (default: [0, current head])
#   --last N         the last N finalized blocks ending at the head
#
# Include:
#   --include transactions  (default) full block JSON via `block-info`
#   --include none          header-only via paginated `block-range`
#                           (256/page); skips tx data. NOT valid for
#                           --format compact (compact needs tx_count
#                           which is only present in full blocks).
#
# Progress:
#   (default)        every 5% to stderr: "Exporting block N/M (X.Y%)..."
#   --quiet          suppress progress (errors still go to stderr)
#
# Use cases:
#   - Cold-archive the chain for compliance / audit retention.
#   - Pipe through `jq` or custom analysis scripts (use ndjson).
#   - Pre-stage data for bulk import into another tool (SQL DB, etc.).
#   - Compare exports between two daemons with `diff` (compact or
#     sorted-ndjson works well here).
#
# RPC dependencies (all read-only):
#   * head --json            — current chain height
#   * block-info <i> --json  — per-block full JSON (--include transactions
#                              and --format compact paths)
#   * block-range <f> <t>    — paginated header bulk-fetch
#                              (--include none path; 256/page server cap)
#
# Exit codes:
#   0   success
#   1   RPC error / bad args / file-write error / malformed response
set -u

usage() {
  cat <<'EOF'
Usage: operator_chain_export.sh [--rpc-port N] [--format F] [--include I]
                                [--from H --to H | --last N]
                                [--out FILE] [--quiet]

Exports the chain (or a height range) to NDJSON / JSON / compact CSV.
Streams ndjson + compact incrementally; --format json buffers the
whole payload (avoid on very long chains).

Options:
  --rpc-port N         RPC port to query (default: 7778)
  --format F           Output format (default: ndjson):
                         ndjson   one block per line, valid JSON each
                         json     single JSON array wrapping all blocks
                                  (memory-intensive — buffered)
                         compact  CSV tuple per block:
                                  index,timestamp,head_hash,prev_hash,
                                  tx_count,creator_count
  --include I          What to include per block (default: transactions):
                         transactions  full block JSON via block-info
                         none          header-only via block-range
                                       (paginated 256/page; faster but
                                       no tx data). Not valid for
                                       --format compact.
  --from H             Start height inclusive (default: 0)
  --to H               End height inclusive (default: current head)
  --last N             Export only the last N finalized blocks
                       (overrides --from / --to)
  --out FILE           Write to FILE (mkdirp parent dir); default stdout
  --quiet              Suppress 5%-progress lines on stderr
  -h, --help           Show this help

Exit codes:
  0   success
  1   RPC error / bad args / file write error / malformed response
EOF
}

PORT=7778
FORMAT="ndjson"
INCLUDE="transactions"
FROM_H=""
TO_H=""
LAST_N=""
OUT_FILE=""
QUIET=0

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)    usage; exit 0 ;;
    --rpc-port)   PORT="$2";     shift 2 ;;
    --format)     FORMAT="$2";   shift 2 ;;
    --include)    INCLUDE="$2";  shift 2 ;;
    --from)       FROM_H="$2";   shift 2 ;;
    --to)         TO_H="$2";     shift 2 ;;
    --last)       LAST_N="$2";   shift 2 ;;
    --out)        OUT_FILE="$2"; shift 2 ;;
    --quiet)      QUIET=1;       shift ;;
    *) echo "operator_chain_export: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Validate enums.
case "$FORMAT" in
  ndjson|json|compact) ;;
  *) echo "operator_chain_export: --format must be one of {ndjson,json,compact} (got '$FORMAT')" >&2
     exit 1 ;;
esac
case "$INCLUDE" in
  transactions|none) ;;
  *) echo "operator_chain_export: --include must be one of {transactions,none} (got '$INCLUDE')" >&2
     exit 1 ;;
esac
if [ "$FORMAT" = "compact" ] && [ "$INCLUDE" = "none" ]; then
  echo "operator_chain_export: --format compact needs tx_count (full blocks); --include none not allowed in compact mode" >&2
  exit 1
fi

# Numeric guards.
for v in "$PORT" "$FROM_H" "$TO_H" "$LAST_N"; do
  [ -z "$v" ] && continue
  case "$v" in *[!0-9]*)
    echo "operator_chain_export: numeric option got non-integer '$v'" >&2
    exit 1 ;;
  esac
done

# --last is mutually exclusive with --from / --to; if user combined,
# --last wins and we warn.
if [ -n "$LAST_N" ] && { [ -n "$FROM_H" ] || [ -n "$TO_H" ]; }; then
  echo "operator_chain_export: --last overrides --from / --to" >&2
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# Resolve current head height. `determ head --field height` emits a bare
# integer on stdout; exit 1 on RPC failure.
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_chain_export: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
HEAD_H=$(printf '%s' "$HEAD_H" | tr -d '[:space:]')
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_chain_export: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Chain "height" is next-to-be-produced index; the head block lives at
# height-1. Range bounds are block indices (heights), inclusive on both
# ends. Empty chain (height=0) ⇒ TIP = -1 effectively (no blocks).
if [ "$HEAD_H" = "0" ]; then
  echo "operator_chain_export: chain has no finalized blocks (height=0); nothing to export" >&2
  exit 1
fi
TIP=$(( HEAD_H - 1 ))

# Resolve [FROM, TO]. Precedence: --last wins if set, otherwise
# --from / --to (defaulting to [0, TIP]). Clamp to chain tail and
# floor at 0.
if [ -n "$LAST_N" ]; then
  if [ "$LAST_N" = "0" ]; then
    echo "operator_chain_export: --last 0 means zero blocks; nothing to export" >&2
    exit 1
  fi
  if [ "$LAST_N" -gt $(( TIP + 1 )) ]; then
    FROM=0
  else
    FROM=$(( TIP - LAST_N + 1 ))
  fi
  TO=$TIP
else
  FROM=${FROM_H:-0}
  TO=${TO_H:-$TIP}
fi
if [ "$TO" -gt "$TIP" ]; then TO=$TIP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_chain_export: --from ($FROM) > --to ($TO); nothing to export" >&2
  exit 1
fi

TOTAL=$(( TO - FROM + 1 ))

# Prepare output destination. --out triggers mkdirp on the parent
# directory; we then funnel all `print_*` writes into the file via an
# exec redirect on fd 3, which lets us still write progress + errors
# to stderr (fd 2) and silence fd 1 from the user's terminal.
if [ -n "$OUT_FILE" ]; then
  OUT_DIR=$(dirname -- "$OUT_FILE")
  if [ -n "$OUT_DIR" ] && [ "$OUT_DIR" != "." ] && [ ! -d "$OUT_DIR" ]; then
    mkdir -p -- "$OUT_DIR" || {
      echo "operator_chain_export: cannot create output directory '$OUT_DIR'" >&2
      exit 1
    }
  fi
  # Truncate / open for write. exec 3> opens fd 3 and pins it for the
  # rest of the script; emit() writes to fd 3 in both stdout and file
  # modes so the rest of the code is mode-agnostic.
  : > "$OUT_FILE" || {
    echo "operator_chain_export: cannot write to '$OUT_FILE'" >&2
    exit 1
  }
  exec 3>> "$OUT_FILE"
else
  exec 3>&1
fi
emit() { printf '%s' "$1" >&3; }
emit_line() { printf '%s\n' "$1" >&3; }

progress() {
  [ "$QUIET" = "1" ] && return 0
  # $1 = blocks done so far, $2 = total. Emit only at 0%, 5%, 10%, ...,
  # 100% boundaries (and the final tick); avoids spamming on tight
  # chains. We dedupe via $LAST_PCT_BUCKET tracked by caller.
  local done="$1" total="$2"
  local pct_x100=$(( done * 10000 / total ))   # e.g. 8.13% -> 813
  local pct_int=$(( pct_x100 / 100 ))
  local pct_frac=$(( pct_x100 % 100 ))
  printf 'operator_chain_export: exporting block %d/%d (%d.%02d%%)\n' \
    "$done" "$total" "$pct_int" "$pct_frac" >&2
}

# ── Header / footer for --format json (single-array mode) ────────────────────
# For ndjson + compact, no wrapper — each line is independent. For json,
# we emit "[\n" up-front, comma-separate per element (handled inline by
# the emit loop's $FIRST flag), and "\n]\n" at the end.
if [ "$FORMAT" = "json" ]; then
  emit_line "["
fi
FIRST=1   # used to suppress the leading comma for the first json item

# ── Streaming export loop ────────────────────────────────────────────────────
# Strategy:
#   --include transactions OR --format compact
#     ⇒ per-height `block-info <i> --json` (full block payload).
#       One RPC per block; predictable, bounded; allows true streaming.
#   --include none
#     ⇒ paginated `block-range FROM TO --json` (256/page). Bulk + fast,
#       but transactions + cross_shard_receipts + inbound_receipts +
#       initial_state are stripped server-side (see Node::rpc_headers
#       in src/node/node.cpp). We still get index / prev_hash /
#       timestamp / state_root / block_hash / creators per block.

LAST_PROGRESS_BUCKET=-1   # last reported 5%-bucket (0..20); -1 = none yet

# Emit one block. $1 = raw JSON for the block (full or stripped).
# Dispatches to format-specific renderer.
emit_block() {
  local blk_json="$1"
  case "$FORMAT" in
    ndjson)
      emit_line "$blk_json"
      ;;
    json)
      if [ "$FIRST" = "1" ]; then
        FIRST=0
      else
        emit_line ","
      fi
      emit "$blk_json"
      ;;
    compact)
      # CSV tuple: index,timestamp,head_hash,prev_hash,tx_count,creator_count
      # jq is the clean path; the fallback uses python (already required
      # by other operator scripts via operator_param_history.sh) to keep
      # field-extraction robust under nested payloads. We prefer jq.
      local line
      if command -v jq >/dev/null 2>&1; then
        line=$(printf '%s' "$blk_json" | jq -r \
          '"\(.index),\(.timestamp),\(.head_hash // .block_hash // ""),\(.prev_hash // ""),\(.transactions | length),\(.creators | length)"' \
          2>/dev/null) || line=""
      else
        line=$(printf '%s' "$blk_json" | python -c '
import sys, json
b = json.load(sys.stdin)
idx     = b.get("index", 0)
ts      = b.get("timestamp", 0)
hh      = b.get("head_hash") or b.get("block_hash") or ""
ph      = b.get("prev_hash", "")
txc     = len(b.get("transactions") or [])
crc     = len(b.get("creators") or [])
print(f"{idx},{ts},{hh},{ph},{txc},{crc}")
' 2>/dev/null) || line=""
      fi
      if [ -z "$line" ]; then
        echo "operator_chain_export: compact extraction failed for block payload" >&2
        return 1
      fi
      emit_line "$line"
      ;;
  esac
}

if [ "$INCLUDE" = "none" ] && [ "$FORMAT" != "compact" ]; then
  # ── Paginated block-range path (header-only, fast) ─────────────────────
  # `block-range --json` returns {"headers":[...], "from":F, "to":T,
  # "received":N}. We pre-chunk 256 at a time on the client side too,
  # so progress reporting stays smooth and one bad chunk doesn't sink
  # the rest.
  PAGE=256
  done=0
  cur=$FROM
  while [ "$cur" -le "$TO" ]; do
    end=$(( cur + PAGE - 1 ))
    if [ "$end" -gt "$TO" ]; then end=$TO; fi
    RANGE_JSON=$("$DETERM" block-range "$cur" "$end" --json --rpc-port "$PORT" 2>/dev/null) || {
      echo "operator_chain_export: block-range RPC failed [$cur..$end] on port $PORT" >&2
      exit 1
    }
    # Iterate headers[] in order. jq path preferred; python fallback.
    if command -v jq >/dev/null 2>&1; then
      # -c emits one compact JSON object per line. Each line is a
      # valid JSON for a single header — feed it into emit_block.
      while IFS= read -r hjson; do
        [ -z "$hjson" ] && continue
        emit_block "$hjson" || exit 1
        done=$(( done + 1 ))
        # Progress reporting (5%-bucket gating).
        bucket=$(( done * 20 / TOTAL ))
        if [ "$bucket" -gt "$LAST_PROGRESS_BUCKET" ]; then
          LAST_PROGRESS_BUCKET=$bucket
          progress "$done" "$TOTAL"
        fi
      done < <(printf '%s' "$RANGE_JSON" | jq -c '.headers[]?')
    else
      # Python fallback: same per-header iteration without jq.
      LINES=$(printf '%s' "$RANGE_JSON" | python -c '
import sys, json
o = json.load(sys.stdin)
for h in (o.get("headers") or []):
    sys.stdout.write(json.dumps(h, separators=(",", ":")) + "\n")
' 2>/dev/null) || {
        echo "operator_chain_export: malformed block-range payload" >&2
        exit 1
      }
      while IFS= read -r hjson; do
        [ -z "$hjson" ] && continue
        emit_block "$hjson" || exit 1
        done=$(( done + 1 ))
        bucket=$(( done * 20 / TOTAL ))
        if [ "$bucket" -gt "$LAST_PROGRESS_BUCKET" ]; then
          LAST_PROGRESS_BUCKET=$bucket
          progress "$done" "$TOTAL"
        fi
      done <<EOF
$LINES
EOF
    fi
    cur=$(( end + 1 ))
  done
else
  # ── Per-block path (full blocks via block-info) ────────────────────────
  # Streaming friendly: each block payload is fetched + emitted + freed
  # before the next RPC. No accumulation regardless of chain length
  # (json-format buffering happens only in the final consumer's reader,
  # since we emit comma-separated JSON objects to fd 3 inline).
  i=$FROM
  done=0
  while [ "$i" -le "$TO" ]; do
    BLK_JSON=$("$DETERM" block-info "$i" --json --rpc-port "$PORT" 2>/dev/null) || {
      echo "operator_chain_export: block-info $i failed (port $PORT)" >&2
      exit 1
    }
    if [ -z "$BLK_JSON" ]; then
      echo "operator_chain_export: block-info $i returned empty payload" >&2
      exit 1
    fi
    emit_block "$BLK_JSON" || exit 1
    done=$(( done + 1 ))
    bucket=$(( done * 20 / TOTAL ))
    if [ "$bucket" -gt "$LAST_PROGRESS_BUCKET" ]; then
      LAST_PROGRESS_BUCKET=$bucket
      progress "$done" "$TOTAL"
    fi
    i=$(( i + 1 ))
  done
fi

# ── Close --format json array ────────────────────────────────────────────────
if [ "$FORMAT" = "json" ]; then
  emit_line ""
  emit_line "]"
fi

# Force a final 100% progress tick if we missed it (TOTAL not divisible
# by 20, etc.). Cheap — operator can correlate "exported all blocks"
# explicitly.
if [ "$QUIET" != "1" ] && [ "$LAST_PROGRESS_BUCKET" -lt 20 ]; then
  progress "$TOTAL" "$TOTAL"
fi

if [ "$QUIET" != "1" ] && [ -n "$OUT_FILE" ]; then
  echo "operator_chain_export: wrote $TOTAL blocks ($FORMAT, --include $INCLUDE) to $OUT_FILE" >&2
fi

exit 0
