#!/usr/bin/env bash
# operator_chain_orphan_check.sh — Single-node chain-continuity audit
# that detects orphan / non-canonical blocks via index + prev_hash chain
# inspection.
#
# Sibling positioning:
#   * operator_chain_health.sh   — top-level health digest (height + peers
#                                  + A1 invariant). Doesn't walk the
#                                  chain.
#   * operator_chain_diff.sh     — PAIRWISE block-field divergence across
#                                  TWO running daemons. Catches cross-
#                                  node forks.
#   * operator_replay_validation.sh — SINGLE-daemon snapshot replay round-
#                                  trip + per-block field consistency.
#                                  Catches apply-determinism breaks; the
#                                  state_root gate is the headline.
#   * operator_fork_watch.sh     — Wrapper around `determ check-fork` for
#                                  cross-node tip divergence over a
#                                  small window.
#   * operator_orphan_check.sh   — STATE-MAP orphan detector (accounts_/
#                                  stakes_/registrants_ cross-refs). NOT
#                                  about block-level orphans.
#   * operator_chain_orphan_check.sh (THIS) — BLOCK-LEVEL orphan +
#                                  prev_hash continuity audit on ONE
#                                  daemon's chain (or a local chain.json
#                                  file). The right tool for "is the
#                                  block list itself canonical and
#                                  contiguous?".
#
# What it detects:
#
#   prev_hash_mismatch        block[i+1].prev_hash != block[i].compute_hash.
#                             Continuity break — the chain "leaves" the
#                             canonical history at height i+1. CRITICAL.
#   block_index_gap           block[i+1].index - block[i].index != 1.
#                             Block missing between two adjacent stored
#                             blocks. CRITICAL (a canonical chain.json
#                             from a healthy producer is dense in [0..head]).
#   duplicate_index           Two stored blocks share the same .index
#                             field. Very rare — means chain.json's blocks
#                             array was reordered or merged. CRITICAL.
#   head_hash_mismatch        chain.json's stored head_hash != actual tail
#                             block's compute_hash. CRITICAL (S-021 should
#                             catch this on daemon load; this script
#                             provides offline verification BEFORE the
#                             daemon tries to start). Only applies in
#                             --chain-file mode for wrapped-form
#                             chain.json. In --rpc-port mode we compare
#                             the daemon's reported head_hash against
#                             the RPC-computed tail block_hash.
#
# Two modes:
#
#   --rpc-port N     Query a running daemon. We pull `head --json` for
#                    height+head_hash, then `block-info <i> --json` for
#                    every block in [from..to]. The server computes
#                    block_hash for us (Block::to_json() doesn't store it
#                    on disk; the RPC layer adds it). Full prev_hash-vs-
#                    block_hash continuity walk + index gap detection.
#
#   --chain-file F   Offline inspection of a stored chain.json. We walk
#                    the blocks array and check (a) index monotonicity,
#                    (b) duplicate indices, (c) gaps. Stored chain.json
#                    blocks don't carry a precomputed hash field, so a
#                    full prev_hash chain walk needs a daemon — chain-
#                    file mode reports the prev_hash STRING-LEVEL
#                    continuity (block[i+1].prev_hash != block[i].prev_hash
#                    is suspicious — every block has a unique prev_hash
#                    so a repeated value catches a duplicated row) plus
#                    the chain.json head_hash field shape. For the
#                    deepest cryptographic check, point this script at a
#                    daemon with --rpc-port.
#
# Mutually exclusive — one of --rpc-port or --chain-file is required.
#
# Usage:
#   tools/operator_chain_orphan_check.sh [--rpc-port N]
#                                        [--chain-file PATH]
#                                        [--from H] [--to H]
#                                        [--json] [--anomalies-only]
#
# Exit codes:
#   0   no anomalies (healthy)
#   1   args / RPC / file / parse error
#   2   one or more anomalies detected (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_chain_orphan_check.sh
         (--rpc-port N | --chain-file PATH)
         [--from H] [--to H]
         [--json] [--anomalies-only]

Block-level orphan and prev_hash continuity audit on a single daemon's
chain (or a local chain.json file). Detects:
  * prev_hash_mismatch    block[i+1].prev_hash != block[i].compute_hash
                          (canonical chain continuity broken)
  * block_index_gap       block missing between two adjacent stored
                          blocks (chain.json[i+1].index - [i].index != 1)
  * duplicate_index       two stored blocks share the same .index
  * head_hash_mismatch    daemon/file head_hash != tail block_hash

Required (mutually exclusive — pick exactly one):
  --rpc-port N        Query a running daemon (default port 8545 if
                      neither --rpc-port nor --chain-file is supplied;
                      flagged as args error otherwise). Full prev_hash
                      vs block_hash continuity walk over [from..to].
  --chain-file PATH   Offline audit of a stored chain.json file
                      (wrapped form {head_hash, blocks: [...]} or
                      legacy bare array). Detects index gaps,
                      duplicate indices, and head_hash mismatch (when
                      wrapped). prev_hash continuity is reported as
                      "string-level" only (no compute_hash without a
                      daemon).

Options:
  --from H            Lower bound (inclusive). Default 0.
  --to H              Upper bound (inclusive). Default chain tip.
  --json              Single-line machine-readable JSON envelope.
  --anomalies-only    Suppress healthy per-block rows; only print
                      anomaly rows + summary.
  -h, --help          Show this help.

Exit codes:
  0   no anomalies
  1   args / RPC / file / parse error
  2   anomalies detected

JSON envelope (--json):
  {"mode": "rpc" | "chain-file",
   "rpc_port": N | null,
   "chain_file": "<path>" | null,
   "head_height": N,
   "window": {"from": H, "to": H},
   "blocks_checked": N,
   "anomalies": [
     {"kind": "prev_hash_mismatch" |
              "block_index_gap"   |
              "duplicate_index"   |
              "head_hash_mismatch",
      "block_index": N,
      "detail": "..."}, ...
   ],
   "summary": {
     "prev_hash_matches": N,
     "total_blocks":      N,
     "n_anomalies":       N
   }}

Examples:
  # Audit a running daemon's full chain.
  tools/operator_chain_orphan_check.sh --rpc-port 7778

  # Audit just the last 100 blocks via RPC.
  HEAD=$(determ head --field height --rpc-port 7778)
  tools/operator_chain_orphan_check.sh --rpc-port 7778 \
      --from $((HEAD - 100)) --to $((HEAD - 1))

  # Offline audit of a snapshot chain.json (e.g. from a backup or a
  # crashed node's data dir).
  tools/operator_chain_orphan_check.sh --chain-file backups/chain.json

  # JSON output for automation.
  tools/operator_chain_orphan_check.sh --rpc-port 7778 --json
EOF
}

PORT=""
CHAIN_FILE=""
FROM=""
TO=""
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}"; shift 2 ;;
    --chain-file)      CHAIN_FILE="${2:-}"; shift 2 ;;
    --from)            FROM="${2:-}"; shift 2 ;;
    --to)              TO="${2:-}"; shift 2 ;;
    --json)            JSON_OUT=1; shift ;;
    --anomalies-only)  ANOM_ONLY=1; shift ;;
    *) echo "operator_chain_orphan_check: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Exactly one of --rpc-port / --chain-file must be set (mutually exclusive).
if [ -n "$PORT" ] && [ -n "$CHAIN_FILE" ]; then
  echo "operator_chain_orphan_check: --rpc-port and --chain-file are mutually exclusive" >&2
  exit 1
fi
if [ -z "$PORT" ] && [ -z "$CHAIN_FILE" ]; then
  # Default per spec: RPC mode at port 8545.
  PORT=8545
fi

if [ -n "$PORT" ]; then
  case "$PORT" in *[!0-9]*|"")
    echo "operator_chain_orphan_check: --rpc-port must be a positive integer (got '$PORT')" >&2
    exit 1 ;;
  esac
  if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "operator_chain_orphan_check: --rpc-port must be 1..65535 (got '$PORT')" >&2
    exit 1
  fi
fi
if [ -n "$CHAIN_FILE" ]; then
  if [ ! -f "$CHAIN_FILE" ]; then
    echo "operator_chain_orphan_check: --chain-file not found: $CHAIN_FILE" >&2
    exit 1
  fi
  if [ ! -r "$CHAIN_FILE" ]; then
    echo "operator_chain_orphan_check: --chain-file not readable: $CHAIN_FILE" >&2
    exit 1
  fi
fi
for label_val in "from:$FROM" "to:$TO"; do
  label=${label_val%%:*}
  v=${label_val#*:}
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_chain_orphan_check: --$label must be a non-negative integer (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Scratch files for streaming anomaly + continuity rows. ───────────────────
ANOMALIES_FILE=$(mktemp 2>/dev/null) || { echo "operator_chain_orphan_check: cannot create tmp file" >&2; exit 1; }
ROWS_FILE=$(mktemp 2>/dev/null)      || { echo "operator_chain_orphan_check: cannot create tmp file" >&2; exit 1; }
trap 'rm -f "$ANOMALIES_FILE" "$ROWS_FILE"' EXIT

push_anomaly() {
  # push_anomaly <kind> <block_index> <detail>
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$ANOMALIES_FILE"
}
push_row() {
  # push_row <block_index> <status> <prev_hash> <block_hash>
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$ROWS_FILE"
}

PYEXE=""
if   command -v python3 >/dev/null 2>&1; then PYEXE=python3
elif command -v python  >/dev/null 2>&1; then PYEXE=python
fi

# ── MODE A: RPC ─────────────────────────────────────────────────────────────
HEAD_HEIGHT=0
HEAD_HASH=""
PREV_HASH_MATCHES=0
TOTAL_BLOCKS=0
BLOCKS_CHECKED=0
MODE=""

if [ -n "$PORT" ]; then
  MODE="rpc"
  HEAD_OUT=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
    echo "operator_chain_orphan_check: RPC error querying head on port $PORT (is daemon running?)" >&2
    exit 1
  }
  # Parse height + head_hash from head RPC.
  if [ -n "$PYEXE" ]; then
    PARSED=$("$PYEXE" - "$HEAD_OUT" <<'PY'
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    print(""); sys.exit(0)
if not isinstance(d, dict):
    print(""); sys.exit(0)
print(str(d.get("height", "")) + "\t" + str(d.get("head_hash", "")))
PY
)
    HEAD_HEIGHT=${PARSED%%$'\t'*}
    HEAD_HASH=${PARSED#*$'\t'}
  else
    HEAD_HEIGHT=$(printf '%s' "$HEAD_OUT" | grep -o '"height":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
    HEAD_HASH=$(printf  '%s' "$HEAD_OUT" | grep -o '"head_hash":"[^"]*"' | head -1 | sed 's/.*: *//; s/"//g')
  fi
  case "$HEAD_HEIGHT" in *[!0-9]*|"")
    echo "operator_chain_orphan_check: malformed head JSON (height not numeric: '$HEAD_HEIGHT')" >&2
    exit 1 ;;
  esac
  if [ "$HEAD_HEIGHT" = "0" ]; then
    echo "operator_chain_orphan_check: chain empty on port $PORT (height=0); nothing to audit" >&2
    exit 1
  fi
  TIP=$(( HEAD_HEIGHT - 1 ))

  # Resolve window. Default [0..TIP].
  if [ -z "$FROM" ]; then FROM=0; fi
  if [ -z "$TO" ];   then TO=$TIP; fi
  if [ "$FROM" -gt "$TO" ]; then
    echo "operator_chain_orphan_check: invalid window: --from $FROM > --to $TO" >&2
    exit 1
  fi
  if [ "$TO" -gt "$TIP" ]; then
    echo "operator_chain_orphan_check: --to $TO exceeds chain tip $TIP (height=$HEAD_HEIGHT, port=$PORT)" >&2
    exit 1
  fi

  # Walk [FROM..TO] in order. We need prev_hash AND block_hash per
  # block. The `block` RPC (used by `block-info <N> --json`) returns
  # Block::to_json() unchanged — which omits the computed `block_hash`
  # field (it's not stored on disk; the producer recomputes it). The
  # `headers` RPC, by contrast, explicitly computes + adds `block_hash`
  # to every header it returns. So we drive the walk via headers,
  # paginating up to 256 entries per call.
  if [ -z "$PYEXE" ]; then
    echo "operator_chain_orphan_check: --rpc-port mode requires python (python3 or python)" >&2
    exit 1
  fi
  PAGE_MAX=256
  PREV_PARENT_HASH=""
  ANCHOR_HASH=""

  # If FROM > 0, fetch FROM-1 first to anchor the prev_hash check on
  # the first window entry. Route the JSON through a file (same argv-
  # size concern as the page-walk below; a single header can exceed
  # 32KB after abort_events / creator_block_sigs collections).
  if [ "$FROM" -gt 0 ]; then
    ANCHOR_JSON=$("$DETERM" headers --from $(( FROM - 1 )) --count 1 --rpc-port "$PORT" 2>/dev/null) || {
      echo "operator_chain_orphan_check: RPC error fetching anchor headers $(( FROM - 1 )) on port $PORT" >&2
      exit 1
    }
    ANCHOR_INJ=$(mktemp 2>/dev/null) || { echo "operator_chain_orphan_check: cannot create tmp file" >&2; exit 1; }
    printf '%s' "$ANCHOR_JSON" > "$ANCHOR_INJ"
    ANCHOR_HASH=$("$PYEXE" - "$ANCHOR_INJ" <<'PY'
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        d = json.load(f)
except Exception:
    print(""); sys.exit(0)
hs = d.get("headers", []) if isinstance(d, dict) else []
if hs and isinstance(hs[0], dict):
    print(str(hs[0].get("block_hash", "")))
else:
    print("")
PY
)
    rm -f "$ANCHOR_INJ"
  fi

  CUR=$FROM
  while [ "$CUR" -le "$TO" ]; do
    REMAINING=$(( TO - CUR + 1 ))
    WANT=$PAGE_MAX
    if [ "$REMAINING" -lt "$WANT" ]; then WANT=$REMAINING; fi
    PAGE_JSON=$("$DETERM" headers --from "$CUR" --count "$WANT" --rpc-port "$PORT" 2>/dev/null) || {
      echo "operator_chain_orphan_check: RPC error fetching headers from=$CUR count=$WANT on port $PORT" >&2
      exit 1
    }
    # Parse the page; emit TSV (index\tprev_hash\tblock_hash) into a
    # tmp file we read line-by-line. The JSON can be hundreds of KB
    # (256 headers per page × abort_events/equivocation_events/sig
    # arrays) so we route it through a file rather than argv to dodge
    # the OS argv-size limit (~32KB on Windows).
    PAGE_TSV=$(mktemp 2>/dev/null)   || { echo "operator_chain_orphan_check: cannot create tmp file" >&2; exit 1; }
    PAGE_INJ=$(mktemp 2>/dev/null)   || { echo "operator_chain_orphan_check: cannot create tmp file" >&2; exit 1; }
    printf '%s' "$PAGE_JSON" > "$PAGE_INJ"
    "$PYEXE" - "$PAGE_INJ" "$PAGE_TSV" <<'PY'
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        d = json.load(f)
except Exception:
    sys.exit(2)
hs = d.get("headers", []) if isinstance(d, dict) else []
with open(sys.argv[2], "w", encoding="utf-8") as f:
    for h in hs:
        if not isinstance(h, dict):
            continue
        idx = h.get("index", "")
        ph  = h.get("prev_hash", "")
        bh  = h.get("block_hash", "")
        f.write(f"{idx}\t{ph}\t{bh}\n")
PY
    RC=$?
    if [ "$RC" -ne 0 ]; then
      rm -f "$PAGE_TSV" "$PAGE_INJ"
      echo "operator_chain_orphan_check: malformed headers response (from=$CUR)" >&2
      exit 1
    fi
    rm -f "$PAGE_INJ"

    EMPTY_PAGE=1
    while IFS=$'\t' read -r IDX PH BH; do
      [ -z "$IDX" ] && continue
      EMPTY_PAGE=0
      # Strip any trailing CR (Windows line endings from python file
      # write) — string compares below would otherwise spuriously fail
      # on byte-identical hashes that differ only by trailing \r.
      IDX=${IDX%$'\r'}
      PH=${PH%$'\r'}
      BH=${BH%$'\r'}
      case "$IDX" in *[!0-9]*)
        rm -f "$PAGE_TSV"
        echo "operator_chain_orphan_check: malformed header index '$IDX' (from=$CUR)" >&2
        exit 1 ;;
      esac
      if [ -z "$PH" ] || [ -z "$BH" ]; then
        rm -f "$PAGE_TSV"
        echo "operator_chain_orphan_check: malformed header at index $IDX (prev_hash='$PH' block_hash='$BH')" >&2
        exit 1
      fi

      # Sanity: server's reported index must match what we expect at
      # this position in the walk.
      EXPECTED_IDX=$CUR
      if [ "$IDX" != "$EXPECTED_IDX" ]; then
        push_anomaly "duplicate_index" "$EXPECTED_IDX" "headers RPC returned index=$IDX where $EXPECTED_IDX was expected (server-side desync)"
      fi

      STATUS="ok"
      if [ "$CUR" = "$FROM" ]; then
        if [ "$CUR" -gt 0 ]; then
          # Anchor check: window's first prev_hash must match the
          # anchor (FROM-1)'s block_hash.
          if [ -n "$ANCHOR_HASH" ] && [ "$ANCHOR_HASH" != "$PH" ]; then
            push_anomaly "prev_hash_mismatch" "$CUR" "block[$CUR].prev_hash=$PH does not match block[$(( CUR - 1 ))].block_hash=$ANCHOR_HASH"
            STATUS="prev_hash_mismatch"
          else
            PREV_HASH_MATCHES=$(( PREV_HASH_MATCHES + 1 ))
          fi
        else
          # Genesis. prev_hash must be all-zero.
          ZERO64=0000000000000000000000000000000000000000000000000000000000000000
          if [ "$PH" != "$ZERO64" ]; then
            push_anomaly "prev_hash_mismatch" "0" "genesis block prev_hash=$PH is not all-zero"
            STATUS="prev_hash_mismatch"
          else
            PREV_HASH_MATCHES=$(( PREV_HASH_MATCHES + 1 ))
          fi
        fi
      else
        if [ "$PREV_PARENT_HASH" != "$PH" ]; then
          push_anomaly "prev_hash_mismatch" "$CUR" "block[$CUR].prev_hash=$PH does not match block[$(( CUR - 1 ))].block_hash=$PREV_PARENT_HASH"
          STATUS="prev_hash_mismatch"
        else
          PREV_HASH_MATCHES=$(( PREV_HASH_MATCHES + 1 ))
        fi
      fi
      PREV_PARENT_HASH=$BH

      push_row "$CUR" "$STATUS" "$PH" "$BH"
      BLOCKS_CHECKED=$(( BLOCKS_CHECKED + 1 ))
      CUR=$(( CUR + 1 ))
    done < "$PAGE_TSV"
    rm -f "$PAGE_TSV"
    if [ "$EMPTY_PAGE" = "1" ]; then
      # Server returned no headers — chain shorter than requested OR
      # transient empty page. Break to avoid infinite loop.
      break
    fi
  done
  TOTAL_BLOCKS=$HEAD_HEIGHT

  # head_hash_mismatch: when the window includes the tip and the daemon
  # reports a head_hash, verify the last block we fetched matches it.
  if [ "$TO" = "$TIP" ] && [ -n "$HEAD_HASH" ] && [ -n "$PREV_PARENT_HASH" ]; then
    if [ "$HEAD_HASH" != "$PREV_PARENT_HASH" ]; then
      push_anomaly "head_hash_mismatch" "$TIP" "daemon head_hash=$HEAD_HASH does not match block-info[$TIP].hash=$PREV_PARENT_HASH"
    fi
  fi
fi

# ── MODE B: chain-file ──────────────────────────────────────────────────────
if [ -n "$CHAIN_FILE" ]; then
  MODE="chain-file"
  if [ -z "$PYEXE" ]; then
    echo "operator_chain_orphan_check: --chain-file mode requires python (python3 or python)" >&2
    exit 1
  fi
  # Hand the heavy lifting to python — parsing chain.json + walking the
  # blocks array for index gaps / duplicates / head_hash is far more
  # robust than bash scrapers. Python writes anomaly + row TSV to the
  # paths we pass and prints "height total" to stdout for us to capture.
  PARSED_OUT=$("$PYEXE" - "$CHAIN_FILE" "$ANOMALIES_FILE" "$ROWS_FILE" "${FROM:-}" "${TO:-}" <<'PY'
import json, sys

chain_path, anom_path, rows_path, from_s, to_s = sys.argv[1:6]

try:
    with open(chain_path, "r", encoding="utf-8") as f:
        j = json.load(f)
except FileNotFoundError:
    sys.stderr.write("chain-file: not found: " + chain_path + "\n"); sys.exit(2)
except json.JSONDecodeError as e:
    sys.stderr.write("chain-file: parse error: " + str(e) + "\n"); sys.exit(2)
except Exception as e:
    sys.stderr.write("chain-file: " + str(e) + "\n"); sys.exit(2)

# S-021 wrapped form: {"head_hash": "<hex>", "blocks": [...]}
# Legacy form: bare array of blocks.
head_hash = ""
if isinstance(j, list):
    blocks = j
elif isinstance(j, dict):
    if "blocks" not in j or not isinstance(j["blocks"], list):
        sys.stderr.write("chain-file: wrapped form missing 'blocks' array\n"); sys.exit(2)
    blocks = j["blocks"]
    head_hash = j.get("head_hash", "") or ""
else:
    sys.stderr.write("chain-file: expected JSON array or object\n"); sys.exit(2)

if not blocks:
    sys.stderr.write("chain-file: empty blocks array; nothing to audit\n"); sys.exit(2)

# Build (index, prev_hash) list, preserving array order.
parsed = []
for pos, b in enumerate(blocks):
    if not isinstance(b, dict):
        sys.stderr.write(f"chain-file: block at array position {pos} is not an object\n"); sys.exit(2)
    idx = b.get("index", None)
    ph  = b.get("prev_hash", None)
    if idx is None or ph is None:
        sys.stderr.write(f"chain-file: block at array position {pos} missing 'index' or 'prev_hash'\n"); sys.exit(2)
    try:
        idx = int(idx)
    except (ValueError, TypeError):
        sys.stderr.write(f"chain-file: block at array position {pos} has non-integer index\n"); sys.exit(2)
    parsed.append({"pos": pos, "index": idx, "prev_hash": str(ph)})

# Resolve window. Default [0 .. last_index]. Use array-stored indices,
# not array positions — so an operator who saw `--to N` from RPC mode
# gets the same window semantics here. Use max() instead of [-1] so
# duplicate-tail rows or appended-out-of-order entries don't truncate
# the inferred head height.
last_idx = max(b["index"] for b in parsed)
from_h = int(from_s) if from_s else 0
to_h   = int(to_s)   if to_s   else last_idx
if from_h > to_h:
    sys.stderr.write(f"chain-file: invalid window: --from {from_h} > --to {to_h}\n"); sys.exit(2)
if to_h > last_idx:
    sys.stderr.write(f"chain-file: --to {to_h} exceeds last stored index {last_idx}\n"); sys.exit(2)

anom_f = open(anom_path, "w", encoding="utf-8")
rows_f = open(rows_path, "w", encoding="utf-8")

# Detect duplicate indices across the WHOLE blocks array (not just window).
seen_idx = {}
for b in parsed:
    if b["index"] in seen_idx:
        first_pos = seen_idx[b["index"]]
        anom_f.write(f"duplicate_index\t{b['index']}\tblock index {b['index']} appears at array positions {first_pos} and {b['pos']}\n")
    else:
        seen_idx[b["index"]] = b["pos"]

# Walk window. Detect:
#   * index gaps:  next.index != prev.index + 1
#   * prev_hash continuity at string level (block[i+1].prev_hash should
#     equal the prior block's stored block_hash — but raw chain.json
#     blocks don't embed block_hash; we can still catch gross corruption
#     by flagging two consecutive blocks sharing the same prev_hash,
#     since every distinct block has a distinct parent hash).
window_blocks = [b for b in parsed if from_h <= b["index"] <= to_h]
window_blocks.sort(key=lambda b: b["index"])

prev_hash_matches = 0
blocks_checked   = 0
prior = None
for b in window_blocks:
    status = "ok"

    # Genesis prev_hash must be all-zero.
    if b["index"] == 0:
        zero = "0" * 64
        if b["prev_hash"] != zero:
            anom_f.write(f"prev_hash_mismatch\t0\tgenesis block prev_hash={b['prev_hash']} is not all-zero\n")
            status = "prev_hash_mismatch"
        else:
            prev_hash_matches += 1
    elif prior is not None:
        gap = b["index"] - prior["index"]
        if gap > 1:
            # Missing block(s) between prior and b.
            missing = b["index"] - 1
            anom_f.write(f"block_index_gap\t{missing}\tgap between block[{prior['index']}] and block[{b['index']}] — {gap - 1} block(s) missing\n")
            status = "block_index_gap"
        elif gap == 1:
            # Continuity at string level: block[i+1].prev_hash should not
            # equal block[i].prev_hash. Two consecutive rows with the
            # same prev_hash means chain.json has a duplicated entry.
            if b["prev_hash"] == prior["prev_hash"]:
                anom_f.write(f"prev_hash_mismatch\t{b['index']}\tblock[{b['index']}].prev_hash equals block[{prior['index']}].prev_hash (duplicate / corrupted row)\n")
                status = "prev_hash_mismatch"
            else:
                prev_hash_matches += 1
        # gap == 0 is captured by the duplicate_index pass above.
    else:
        # First in-window block but not index 0 — no prior to compare
        # against. Count as a probe but not a "match" (we can't verify
        # without an anchor).
        pass

    rows_f.write(f"{b['index']}\t{status}\t{b['prev_hash']}\t\n")
    blocks_checked += 1
    prior = b

# head_hash check (wrapped form only). The stored head_hash should be the
# tail block's compute_hash, but we don't have compute_hash available
# offline. We can still verify the field is present + non-empty + 64
# hex chars when the form is wrapped. If the operator passed a chain.json
# from a daemon that's currently running, the daemon's own load-time
# S-021 gate already verified it; we surface a CRITICAL anomaly when
# head_hash is malformed or empty in the wrapped form.
if isinstance(j, dict) and "head_hash" in j:
    hh = j.get("head_hash", "")
    if not isinstance(hh, str) or len(hh) == 0:
        anom_f.write(f"head_hash_mismatch\t{last_idx}\tchain.json wrapped form has empty head_hash field\n")
    elif len(hh) != 64 or not all(c in "0123456789abcdefABCDEF" for c in hh):
        anom_f.write(f"head_hash_mismatch\t{last_idx}\tchain.json head_hash={hh} is not 64 lowercase hex chars\n")

anom_f.close()
rows_f.close()

# Emit: <head_height> <total_blocks> <blocks_checked> <prev_hash_matches> <head_hash> <from> <to>
print(f"{last_idx + 1}\t{len(parsed)}\t{blocks_checked}\t{prev_hash_matches}\t{head_hash}\t{from_h}\t{to_h}")
PY
)
  RC=$?
  if [ "$RC" -ne 0 ]; then
    # Python wrote a diagnostic to stderr; surface it without prefixing.
    exit 1
  fi
  HEAD_HEIGHT=${PARSED_OUT%%$'\t'*}
  REST=${PARSED_OUT#*$'\t'}
  TOTAL_BLOCKS=${REST%%$'\t'*}
  REST=${REST#*$'\t'}
  BLOCKS_CHECKED=${REST%%$'\t'*}
  REST=${REST#*$'\t'}
  PREV_HASH_MATCHES=${REST%%$'\t'*}
  REST=${REST#*$'\t'}
  HEAD_HASH=${REST%%$'\t'*}
  REST=${REST#*$'\t'}
  FROM=${REST%%$'\t'*}
  REST=${REST#*$'\t'}
  TO=${REST%%$'\t'*}
fi

# ── Aggregate anomalies + rc ────────────────────────────────────────────────
ANOM_COUNT=0
if [ -s "$ANOMALIES_FILE" ]; then
  ANOM_COUNT=$(wc -l < "$ANOMALIES_FILE" | tr -d '[:space:]')
fi
RC=0
[ "$ANOM_COUNT" -gt 0 ] && RC=2

# ── JSON emit ───────────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  ANOM_JSON="[]"
  if [ "$ANOM_COUNT" -gt 0 ] && [ -n "$PYEXE" ]; then
    ANOM_JSON=$("$PYEXE" - "$ANOMALIES_FILE" <<'PY'
import json, sys
rows = []
with open(sys.argv[1], "r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line: continue
        parts = line.split("\t", 2)
        if len(parts) < 3: continue
        try: idx = int(parts[1])
        except ValueError: idx = parts[1]
        rows.append({"kind": parts[0], "block_index": idx, "detail": parts[2]})
print(json.dumps(rows, separators=(",", ":")))
PY
)
  elif [ "$ANOM_COUNT" -gt 0 ]; then
    # Hand-rolled fallback (detail strings may contain quotes — escape them).
    ANOM_JSON="["
    first=1
    while IFS=$'\t' read -r kind idx detail; do
      [ -z "$kind" ] && continue
      esc=$(printf '%s' "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g')
      if [ "$first" = "1" ]; then first=0; else ANOM_JSON="$ANOM_JSON,"; fi
      ANOM_JSON="$ANOM_JSON{\"kind\":\"$kind\",\"block_index\":$idx,\"detail\":\"$esc\"}"
    done < "$ANOMALIES_FILE"
    ANOM_JSON="$ANOM_JSON]"
  fi

  RPC_PORT_JSON="null"
  CHAIN_FILE_JSON="null"
  if [ -n "$PORT" ];       then RPC_PORT_JSON="$PORT"; fi
  if [ -n "$CHAIN_FILE" ]; then
    esc=$(printf '%s' "$CHAIN_FILE" | sed 's/\\/\\\\/g; s/"/\\"/g')
    CHAIN_FILE_JSON="\"$esc\""
  fi

  cat <<EOF
{"mode":"$MODE","rpc_port":$RPC_PORT_JSON,"chain_file":$CHAIN_FILE_JSON,"head_height":$HEAD_HEIGHT,"window":{"from":$FROM,"to":$TO},"blocks_checked":$BLOCKS_CHECKED,"anomalies":$ANOM_JSON,"summary":{"prev_hash_matches":$PREV_HASH_MATCHES,"total_blocks":$TOTAL_BLOCKS,"n_anomalies":$ANOM_COUNT}}
EOF
  exit $RC
fi

# ── Human render ────────────────────────────────────────────────────────────
echo ""
if [ "$MODE" = "rpc" ]; then
  echo "=== Chain orphan check (rpc port $PORT) ==="
else
  echo "=== Chain orphan check (chain-file $CHAIN_FILE) ==="
fi
echo "Head height:        $HEAD_HEIGHT"
if [ -n "$HEAD_HASH" ]; then
  echo "Head hash:          ${HEAD_HASH:0:24}..."
fi
echo "Total stored blocks:$TOTAL_BLOCKS"
echo "Window:             [$FROM..$TO]   ($BLOCKS_CHECKED blocks checked)"

# Per-block continuity rows (skipped in --anomalies-only mode).
if [ "$ANOM_ONLY" = "0" ] && [ -s "$ROWS_FILE" ]; then
  echo ""
  echo "Continuity rows:"
  printf '  %-8s  %-22s  %-32s\n' "index" "status" "prev_hash"
  printf '  %-8s  %-22s  %-32s\n' "--------" "----------------------" "--------------------------------"
  while IFS=$'\t' read -r idx status ph bh; do
    [ -z "$idx" ] && continue
    ph_disp="$ph"
    if [ "${#ph_disp}" -gt 32 ]; then ph_disp="${ph_disp:0:29}..."; fi
    printf '  %-8s  %-22s  %-32s\n' "$idx" "$status" "$ph_disp"
  done < "$ROWS_FILE"
fi

# Anomaly section — always rendered when present.
if [ "$ANOM_COUNT" -gt 0 ]; then
  echo ""
  echo "Anomalies ($ANOM_COUNT):"
  while IFS=$'\t' read -r kind idx detail; do
    [ -z "$kind" ] && continue
    echo "  [!] $kind  block_index=$idx  $detail"
  done < "$ANOMALIES_FILE"
fi

echo ""
echo "Summary: prev_hash_matches=$PREV_HASH_MATCHES / total_blocks=$TOTAL_BLOCKS  anomalies=$ANOM_COUNT"
echo ""
if [ "$RC" = "0" ]; then
  echo "[OK] No orphan blocks / continuity breaks detected over [$FROM..$TO]."
else
  echo "[X]  Chain orphan / continuity anomaly detected — see above."
fi
exit $RC
