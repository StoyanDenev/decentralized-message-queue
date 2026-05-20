#!/usr/bin/env bash
# operator_storage_growth.sh — Track chain storage footprint over time
# against the running daemon's height. Reports the size of every
# operator-managed file in the data dir (chain.json, snapshot.json,
# config.json, node_key.json) plus a derived bytes-per-block average,
# and flags the chain when chain.json crosses an operator-supplied
# large-state threshold (default 10 GB).
#
# This is a point-in-time storage snapshot: an operator schedules it on
# cron (hourly/daily) and the JSON output is suitable for ingestion
# into time-series monitoring (Prometheus textfile exporter, etc.).
# Growth-over-time is implied by the cron cadence + the bytes_per_block
# metric — the script itself does not persist history.
#
# Read-only: only stats files in the data dir + queries `determ head`.
# Safe to run against a live daemon. No mutation of any file.
#
# Usage:
#   tools/operator_storage_growth.sh [--rpc-port N] [--data-dir DIR]
#                                    [--threshold-gb N] [--json]
#                                    [--anomalies-only]
#
# Options:
#   --rpc-port N        RPC port to query for chain height (default: 7778)
#   --data-dir DIR      Determ data directory (default: $HOME/.determ on
#                       POSIX, $APPDATA/determ on Windows fallback)
#   --threshold-gb N    chain.json size threshold in GB. If chain.json
#                       exceeds this, anomalies[] gains
#                       "chain_size_threshold_exceeded" and the script
#                       exits 2 (operator alert gate). Default: 10
#   --json              Emit single-line JSON instead of human digest
#   --anomalies-only    Suppress healthy output; only print flagged
#                       anomalies. Exits 0 if none, 2 if any fired.
#   -h, --help          Show this help
#
# Inspected files (under --data-dir):
#   chain.json     — block ledger (the chain itself; main growth driver)
#   snapshot.json  — optional bootstrap snapshot (may be absent)
#   config.json    — node config (typically <KB; near-constant)
#   node_key.json  — node identity keypair (constant ~120 B)
#
# Exit codes:
#   0   success, no anomalies
#   1   file / RPC / arg error (daemon unreachable, data_dir missing,
#       non-numeric arg, etc.)
#   2   chain.json exceeds --threshold-gb (or --anomalies-only AND ≥1
#       anomaly fired — same gate, same exit)
#
# JSON shape:
#   {"data_dir":"<path>","height":<u64>,
#    "files":{
#      "chain.json":   {"present":true,"bytes":<u64>},
#      "snapshot.json":{"present":<bool>,"bytes":<u64>},
#      "config.json":  {"present":<bool>,"bytes":<u64>},
#      "node_key.json":{"present":<bool>,"bytes":<u64>}
#    },
#    "total_bytes":<u64>,
#    "bytes_per_block":<u64>,
#    "threshold_gb":<u64>,
#    "anomalies":[...],
#    "rpc_port":<N>}
set -u

usage() {
  cat <<'EOF'
Usage: operator_storage_growth.sh [--rpc-port N] [--data-dir DIR]
                                  [--threshold-gb N] [--json]
                                  [--anomalies-only]

Reports chain storage footprint over time: per-file byte counts under
--data-dir, total data-dir size, and bytes-per-block average derived
from `determ head` (live chain height).

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --data-dir DIR      Determ data directory (default: $HOME/.determ)
  --threshold-gb N    Flag chain.json > N GB (default: 10)
  --json              Single-line JSON output
  --anomalies-only    Only print flagged anomalies; exit 2 if any fire
  -h, --help          Show this help

Anomaly flags:
  chain_size_threshold_exceeded   chain.json exceeds --threshold-gb
  missing_chain_json              data_dir present but chain.json absent
                                  (pre-init / wrong data-dir / corruption)

Exit codes:
  0   success, no anomalies
  1   file / RPC / arg error
  2   threshold exceeded OR --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=7778
DATA_DIR=""
THRESHOLD_GB=10
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="$2";         shift 2 ;;
    --data-dir)        DATA_DIR="$2";     shift 2 ;;
    --threshold-gb)    THRESHOLD_GB="$2"; shift 2 ;;
    --json)            JSON_OUT=1;        shift ;;
    --anomalies-only)  ANOM_ONLY=1;       shift ;;
    *) echo "operator_storage_growth: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"")
  echo "operator_storage_growth: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
case "$THRESHOLD_GB" in *[!0-9]*|"")
  echo "operator_storage_growth: --threshold-gb must be a positive integer (got '$THRESHOLD_GB')" >&2
  exit 1 ;;
esac

# Default data-dir matches src/main.cpp::default_data_dir() — $HOME/.determ
# on POSIX, $APPDATA/determ on Windows. If neither env var is set, use
# the ".determ" relative fallback the binary itself uses.
if [ -z "$DATA_DIR" ]; then
  if [ -n "${HOME:-}" ]; then
    DATA_DIR="$HOME/.determ"
  elif [ -n "${APPDATA:-}" ]; then
    DATA_DIR="$APPDATA/determ"
  else
    DATA_DIR=".determ"
  fi
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: stat the data dir ────────────────────────────────────────────────
if [ ! -d "$DATA_DIR" ]; then
  echo "operator_storage_growth: data-dir not found: $DATA_DIR" >&2
  exit 1
fi

# Portable file-size getter. `stat -c %s` is GNU; `stat -f %z` is BSD/macOS;
# `wc -c < file` works everywhere but reads the whole file. We try the two
# stat forms first, then fall back to wc -c.
file_size() {
  local f="$1"
  if [ ! -f "$f" ]; then printf '%s' "0"; return; fi
  local s=""
  s=$(stat -c %s "$f" 2>/dev/null) && { printf '%s' "$s"; return; }
  s=$(stat -f %z "$f" 2>/dev/null) && { printf '%s' "$s"; return; }
  # Last-resort fallback. wc -c streams the file but is universally
  # available; for a 2 GB chain.json this costs a sequential read.
  s=$(wc -c < "$f" 2>/dev/null) && { printf '%s' "$s" | awk '{print $1}'; return; }
  printf '%s' "0"
}

CHAIN_FILE="$DATA_DIR/chain.json"
SNAP_FILE="$DATA_DIR/snapshot.json"
CONFIG_FILE="$DATA_DIR/config.json"
KEY_FILE="$DATA_DIR/node_key.json"

CHAIN_PRESENT="false"; [ -f "$CHAIN_FILE" ]  && CHAIN_PRESENT="true"
SNAP_PRESENT="false";  [ -f "$SNAP_FILE" ]   && SNAP_PRESENT="true"
CONFIG_PRESENT="false";[ -f "$CONFIG_FILE" ] && CONFIG_PRESENT="true"
KEY_PRESENT="false";   [ -f "$KEY_FILE" ]    && KEY_PRESENT="true"

CHAIN_BYTES=$(file_size "$CHAIN_FILE")
SNAP_BYTES=$(file_size "$SNAP_FILE")
CONFIG_BYTES=$(file_size "$CONFIG_FILE")
KEY_BYTES=$(file_size "$KEY_FILE")

# Defensive: file_size always emits a numeric, but stat output formats
# vary across distros. Coerce any unexpected non-numeric to 0 so the
# arithmetic below never blows up.
for v in CHAIN_BYTES SNAP_BYTES CONFIG_BYTES KEY_BYTES; do
  eval "case \"\$$v\" in *[!0-9]*|\"\") $v=0 ;; esac"
done

TOTAL_BYTES=$(( CHAIN_BYTES + SNAP_BYTES + CONFIG_BYTES + KEY_BYTES ))

# ── Step 2: resolve current tip ──────────────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_storage_growth: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_storage_growth: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# bytes_per_block = chain.json size / height. Genesis-only chains have
# height=0 (only the genesis block, no apply'd blocks yet); treat that as
# undefined and emit 0 to avoid div-by-zero. For chains with height>=1
# we use integer division; the operator can do floating-point math on
# the JSON output if they need fractional precision.
BPB=0
if [ "$HEAD_H" -gt 0 ] && [ "$CHAIN_BYTES" -gt 0 ]; then
  BPB=$(( CHAIN_BYTES / HEAD_H ))
fi

# ── Step 3: assemble anomalies list ──────────────────────────────────────────
# Convert threshold-GB to bytes for comparison. Bash arithmetic handles
# up to 2^63-1 safely; 10 GB = 10737418240 fits easily.
THRESHOLD_BYTES=$(( THRESHOLD_GB * 1073741824 ))

ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}

if [ "$CHAIN_PRESENT" = "false" ]; then
  add_anom "missing_chain_json"
fi
if [ "$CHAIN_BYTES" -gt "$THRESHOLD_BYTES" ]; then
  add_anom "chain_size_threshold_exceeded"
fi

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Helpers ──────────────────────────────────────────────────────────────────
# Human-readable size formatter (B/KB/MB/GB to one decimal). Same
# convention as operator_snapshot_check.sh::human_size.
human_size() {
  local b="$1"
  if [ "$b" -lt 1024 ] 2>/dev/null; then
    printf '%s B' "$b"
  elif [ "$b" -lt 1048576 ] 2>/dev/null; then
    awk -v n="$b" 'BEGIN { printf "%.1f KB", n/1024 }'
  elif [ "$b" -lt 1073741824 ] 2>/dev/null; then
    awk -v n="$b" 'BEGIN { printf "%.1f MB", n/1048576 }'
  else
    awk -v n="$b" 'BEGIN { printf "%.1f GB", n/1073741824 }'
  fi
}

# ── Step 4: emit ─────────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  printf '{"data_dir":"%s","height":%s,' "$DATA_DIR" "$HEAD_H"
  printf '"files":{'
  printf '"chain.json":{"present":%s,"bytes":%s},'    "$CHAIN_PRESENT"  "$CHAIN_BYTES"
  printf '"snapshot.json":{"present":%s,"bytes":%s},' "$SNAP_PRESENT"   "$SNAP_BYTES"
  printf '"config.json":{"present":%s,"bytes":%s},'   "$CONFIG_PRESENT" "$CONFIG_BYTES"
  printf '"node_key.json":{"present":%s,"bytes":%s}'  "$KEY_PRESENT"    "$KEY_BYTES"
  printf '},'
  printf '"total_bytes":%s,"bytes_per_block":%s,"threshold_gb":%s,' \
         "$TOTAL_BYTES" "$BPB" "$THRESHOLD_GB"
  printf '"anomalies":['
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | awk -F, '{
      for(i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"",$i }
    }'
  fi
  printf '],"rpc_port":%s}\n' "$PORT"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_storage_growth: no anomalies (port $PORT, data_dir=$DATA_DIR)"
  else
    echo "=== Storage growth (port $PORT, data_dir=$DATA_DIR) ==="
    echo "Chain height: $HEAD_H"
    echo "Files:"
    # Per-file breakdown. chain.json carries the per-block annotation
    # (the only file whose size scales with height); the others are
    # near-constant.
    if [ "$CHAIN_PRESENT" = "true" ]; then
      if [ "$HEAD_H" -gt 0 ] && [ "$BPB" -gt 0 ]; then
        printf "  chain.json:     %s (avg %s/block)\n" \
               "$(human_size "$CHAIN_BYTES")" "$(human_size "$BPB")"
      else
        printf "  chain.json:     %s\n" "$(human_size "$CHAIN_BYTES")"
      fi
    else
      echo   "  chain.json:     [absent]"
    fi
    if [ "$SNAP_PRESENT" = "true" ]; then
      printf "  snapshot.json:  %s\n" "$(human_size "$SNAP_BYTES")"
    else
      echo   "  snapshot.json:  [absent]"
    fi
    if [ "$CONFIG_PRESENT" = "true" ]; then
      printf "  config.json:    %s\n" "$(human_size "$CONFIG_BYTES")"
    else
      echo   "  config.json:    [absent]"
    fi
    if [ "$KEY_PRESENT" = "true" ]; then
      printf "  node_key.json:  %s\n" "$(human_size "$KEY_BYTES")"
    else
      echo   "  node_key.json:  [absent]"
    fi
    printf  "  data_dir total: %s\n" "$(human_size "$TOTAL_BYTES")"

    if [ "$HEAD_H" -gt 0 ] && [ "$BPB" -gt 0 ]; then
      printf "Average bytes per block: %s\n" "$(human_size "$BPB")"
    else
      echo   "Average bytes per block: - (chain at genesis or chain.json absent)"
    fi

    if [ "$ANOM_COUNT" = "0" ]; then
      printf "[OK] within threshold (%s GB)\n" "$THRESHOLD_GB"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
      case ",$ANOMALIES," in
        *,chain_size_threshold_exceeded,*)
          printf "  chain_size_threshold_exceeded : chain.json = %s exceeds %s GB threshold\n" \
                 "$(human_size "$CHAIN_BYTES")" "$THRESHOLD_GB"
          ;;
      esac
      case ",$ANOMALIES," in
        *,missing_chain_json,*)
          printf "  missing_chain_json            : %s not present (pre-init / wrong --data-dir / corruption)\n" \
                 "$CHAIN_FILE"
          ;;
      esac
    fi
  fi
fi

# ── Step 5: exit-code policy ─────────────────────────────────────────────────
# Two paths to exit 2:
#   (a) threshold exceeded (default mode) — always alerts the operator,
#       matches the "large-state pressure" intent in the task spec.
#   (b) --anomalies-only set AND any anomaly fired — matches the
#       operator_account_growth.sh / operator_subsidy_audit.sh / etc.
#       family convention.
# In practice (b) subsumes (a) when --anomalies-only is set; we keep
# the threshold-exceeded path as a strict exit-2 even in default mode
# because that's the explicit task-spec contract.
if [ "$ANOM_COUNT" -gt 0 ]; then
  # If threshold was breached, exit 2 regardless of --anomalies-only.
  case ",$ANOMALIES," in
    *,chain_size_threshold_exceeded,*) exit 2 ;;
  esac
  # Otherwise (e.g., missing_chain_json), exit 2 only under --anomalies-only.
  if [ "$ANOM_ONLY" = "1" ]; then exit 2; fi
fi
exit 0
