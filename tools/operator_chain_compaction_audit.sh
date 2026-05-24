#!/usr/bin/env bash
# operator_chain_compaction_audit.sh — chain.json storage-health audit
# + snapshot-bootstrap recommendation.
#
# chain.json grows monotonically with block count. A long-running
# permissionless node accumulates a chain.json that can drift from
# 10 MB into the hundreds of megabytes range; once it crosses the
# operator's disk-budget tolerance, the standard remediation is:
#   1. `determ snapshot create --out path/to/snap.json`
#   2. truncate chain.json (or restart from snapshot-only mode).
# This script tells the operator WHEN that remediation is due, by
# combining file-system stat against tunable byte-size + block-count
# thresholds.
#
# Sibling positioning:
#   * operator_chain_health.sh        — daemon liveness + A1 invariant + peers.
#   * operator_snapshot_lineage.sh    — directory audit of snapshot archive.
#   * operator_chain_compaction_audit.sh (this) — STORAGE health for the
#                                       chain.json file itself: byte-size
#                                       growth, per-block average, projected
#                                       2x size, snapshot-recommend trigger.
#
# Read-only RPC + read-only stat(). Safe against any running daemon.
#
# Algorithm:
#   1. Resolve chain.json path (--chain-path, else default `chain.json`
#      in the project root).
#   2. stat() the file. Absent ⇒ chain_file_missing CRITICAL anomaly.
#   3. Query daemon for head height via `determ head --field height`.
#   4. Compute bytes_per_block = file_size / head_height (when head>0).
#      projected_size_at_2x_mb = 2 × file_size_mb.
#   5. Detect adjacent snapshot file (sibling `*.snapshot.json` /
#      `snapshot.json` / `snap*.json` in the same directory) — absence
#      drives the snapshot_recommended anomaly when block_count is
#      over the recommend threshold.
#   6. Classify anomalies + emit.
#
# Anomaly flags:
#   chain_file_critical    CRITICAL  size > --critical-threshold-mb
#                                    (default 1000 MB = 1 GB). Disk
#                                    budget likely exceeded. Compact NOW.
#   chain_file_warn        WARN      size > --warn-threshold-mb
#                                    (default 100 MB). Plan a compaction
#                                    window in the next operational cycle.
#   snapshot_recommended   INFO      head_height > --snapshot-recommend-
#                                    threshold-blocks (default 50000)
#                                    AND no snapshot file detected
#                                    adjacent to chain.json.
#   chain_file_missing     CRITICAL  --chain-path (or default) not found.
#                                    Either the daemon was started with a
#                                    different chain_path OR the operator
#                                    pointed the script at the wrong dir.
#
# Output:
#   default (human):
#     - File stats line (path, size MB, mtime).
#     - Head height + bytes_per_block + projected_size_at_2x.
#     - Snapshot-adjacency line.
#     - Anomalies block (one line per anomaly) + verdict.
#   --json:
#     {chain_path, chain_path_exists, file_size_bytes, file_size_mb,
#      file_mtime_epoch, head_height, bytes_per_block,
#      projected_size_at_2x_mb, snapshot_detected, snapshot_path,
#      warn_threshold_mb, critical_threshold_mb,
#      snapshot_recommend_threshold_blocks,
#      anomalies: [{type, severity, detail}, ...],
#      rpc_port}
#
# Exit codes:
#   0   healthy (or only INFO-level snapshot_recommended)
#   1   args error / RPC error / file-stat error (when path SUPPLIED
#       but unreadable for a reason other than "missing" — e.g.,
#       permission denied. A missing file becomes the CRITICAL anomaly
#       chain_file_missing and exits 2 instead of 1, since "missing
#       at expected path" is an operator-actionable signal, not an
#       invocation failure)
#   2   CRITICAL anomaly fired (chain_file_critical, chain_file_missing)
#
# Note: WARN anomalies (chain_file_warn) do NOT trigger exit-2 by
# themselves; only CRITICAL anomalies do, matching the spec's "exit 2
# CRITICAL fired" wording. snapshot_recommended is INFO and never
# triggers a non-zero exit.
set -u

usage() {
  cat <<'EOF'
Usage: operator_chain_compaction_audit.sh --rpc-port N
                                          [--chain-path <path>]
                                          [--warn-threshold-mb N]
                                          [--critical-threshold-mb N]
                                          [--snapshot-recommend-threshold-blocks N]
                                          [--json] [--anomalies-only]
                                          [-h|--help]

Audit chain.json storage health + recommend snapshot compaction.

Required:
  --rpc-port N                                RPC port to query daemon

Options:
  --chain-path <path>                         Path to chain.json. Default:
                                              project-root chain.json
                                              (the daemon's status RPC does
                                              not surface Config.chain_path,
                                              so an explicit path is the
                                              authoritative way to point at
                                              a non-default location).
  --warn-threshold-mb N                       WARN when size > N MB
                                              (default: 100)
  --critical-threshold-mb N                   CRITICAL when size > N MB
                                              (default: 1000 = 1 GB)
  --snapshot-recommend-threshold-blocks N     Recommend snapshot when
                                              head_height > N AND no
                                              snapshot file detected next
                                              to chain.json (default: 50000)
  --json                                      Emit single-line JSON envelope
  --anomalies-only                            Suppress non-anomaly rows in
                                              human output
  -h, --help                                  Show this help

Exit codes:
  0   healthy (or only INFO-level snapshot_recommended)
  1   args error / RPC error / file-stat error (path supplied but
      unreadable for a reason other than "missing")
  2   CRITICAL anomaly fired (chain_file_critical, chain_file_missing)
EOF
}

PORT=""
CHAIN_PATH=""
WARN_MB=100
CRIT_MB=1000
SNAP_THRESH=50000
JSON_OUT=0
ANOM_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                                  usage; exit 0 ;;
    --rpc-port)                                 PORT="${2:-}";          shift 2 ;;
    --chain-path)                               CHAIN_PATH="${2:-}";    shift 2 ;;
    --warn-threshold-mb)                        WARN_MB="${2:-}";       shift 2 ;;
    --critical-threshold-mb)                    CRIT_MB="${2:-}";       shift 2 ;;
    --snapshot-recommend-threshold-blocks)      SNAP_THRESH="${2:-}";   shift 2 ;;
    --json)                                     JSON_OUT=1;             shift ;;
    --anomalies-only)                           ANOM_ONLY=1;            shift ;;
    *) echo "operator_chain_compaction_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required.
if [ -z "$PORT" ]; then
  echo "operator_chain_compaction_audit: --rpc-port is required" >&2
  usage >&2
  exit 1
fi

# Numeric guards on every numeric option. Empty allowed only for CHAIN_PATH
# (string). All numerics must be non-negative integers.
for nv in "rpc-port:$PORT" \
          "warn-threshold-mb:$WARN_MB" \
          "critical-threshold-mb:$CRIT_MB" \
          "snapshot-recommend-threshold-blocks:$SNAP_THRESH"; do
  label=${nv%%:*}
  val=${nv#*:}
  case "$val" in
    *[!0-9]*|"")
      echo "operator_chain_compaction_audit: --$label must be a non-negative integer (got '$val')" >&2
      exit 1 ;;
  esac
done

# Sanity: critical > warn (so a flag never fires both with the warn
# stricter than the critical). Equal is OK (degenerate but unambiguous).
if [ "$CRIT_MB" -lt "$WARN_MB" ]; then
  echo "operator_chain_compaction_audit: --critical-threshold-mb ($CRIT_MB) must be >= --warn-threshold-mb ($WARN_MB)" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: resolve chain.json path ────────────────────────────────────────────
# Default is the project-root `chain.json` — the conventional location
# used by the daemon when no Config.chain_path override is supplied.
# We do NOT attempt to query the daemon for chain_path because the
# `status` RPC does not surface that field (verified against
# Node::rpc_status in src/node/node.cpp). Operators with a non-default
# chain_path must pass --chain-path.
if [ -z "$CHAIN_PATH" ]; then
  CHAIN_PATH="$PROJECT_ROOT/chain.json"
fi

# Resolve to absolute path. If the user passed a relative path, anchor
# it at PROJECT_ROOT for consistency with the rest of the operator
# scripts (which all assume CWD = project root after the common.sh
# source).
case "$CHAIN_PATH" in
  /*|[A-Za-z]:/*|[A-Za-z]:\\*) CHAIN_PATH_ABS="$CHAIN_PATH" ;;
  *) CHAIN_PATH_ABS="$PROJECT_ROOT/$CHAIN_PATH" ;;
esac

# ── Step 2: stat the file ──────────────────────────────────────────────────────
# Two distinct outcomes:
#   - file exists       ⇒ capture size + mtime; downstream classifies
#                         against thresholds.
#   - file missing      ⇒ chain_file_missing CRITICAL anomaly. Continue
#                         the script (daemon still queried) so the
#                         envelope is complete for operator diagnostics.
#   - permission denied ⇒ exit 1 (invocation failure, not a chain-health
#                         signal).
FILE_EXISTS=0
FILE_SIZE_BYTES=0
FILE_MTIME=0
if [ -e "$CHAIN_PATH_ABS" ]; then
  if [ ! -r "$CHAIN_PATH_ABS" ]; then
    echo "operator_chain_compaction_audit: chain-path exists but is unreadable: $CHAIN_PATH_ABS" >&2
    exit 1
  fi
  # GNU stat first, then BSD stat. Failure here means "file is present
  # but stat surfaced no value" — treat as an invocation failure (the
  # file is unreadable in some structural way) so the operator gets
  # told there's a real problem rather than the script silently zeroing.
  FILE_SIZE_BYTES=$(stat -c %s -- "$CHAIN_PATH_ABS" 2>/dev/null) \
    || FILE_SIZE_BYTES=$(stat -f %z -- "$CHAIN_PATH_ABS" 2>/dev/null) \
    || {
      echo "operator_chain_compaction_audit: stat failed on $CHAIN_PATH_ABS" >&2
      exit 1
    }
  FILE_MTIME=$(stat -c %Y -- "$CHAIN_PATH_ABS" 2>/dev/null) \
    || FILE_MTIME=$(stat -f %m -- "$CHAIN_PATH_ABS" 2>/dev/null) \
    || FILE_MTIME=0
  case "$FILE_SIZE_BYTES" in *[!0-9]*|"")
    echo "operator_chain_compaction_audit: stat returned non-numeric size '$FILE_SIZE_BYTES'" >&2
    exit 1 ;;
  esac
  FILE_EXISTS=1
fi

# ── Step 3: query daemon for head height ──────────────────────────────────────
# Mirrors operator_chain_health.sh / operator_snapshot_lineage.sh:
# `determ head --field height --rpc-port N` returns the integer height.
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_chain_compaction_audit: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
HEAD_H=$(printf '%s' "$HEAD_H" | tr -d '[:space:]')
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_chain_compaction_audit: daemon returned non-numeric head '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 4: derived metrics ────────────────────────────────────────────────────
# bytes_per_block = file_size / head_height when head > 0. Both
# numerator and denominator are positive integers; the integer-division
# floor is fine for an operator estimate.
BYTES_PER_BLOCK=0
if [ "$HEAD_H" -gt 0 ] && [ "$FILE_SIZE_BYTES" -gt 0 ]; then
  BYTES_PER_BLOCK=$(( FILE_SIZE_BYTES / HEAD_H ))
fi

# File size in MB (rounded to two decimals via fixed-point math).
# We expose two values: integer-MB (for threshold comparison, matches
# the user-supplied --*-threshold-mb units) and a string with one
# decimal place (human-readable summary).
FILE_SIZE_MB_INT=$(( FILE_SIZE_BYTES / 1048576 ))
PROJECTED_2X_MB_INT=$(( FILE_SIZE_MB_INT * 2 ))

# render_mb: format an integer-byte count as a human "N.N MB" string.
# Bash has no float arithmetic; we compute one decimal place via
# integer math against 1 MiB = 1048576 bytes.
render_mb() {
  local b="$1"
  case "$b" in *[!0-9]*|"") echo "0.0 MB"; return ;; esac
  local whole=$(( b / 1048576 ))
  local frac=$(( (b % 1048576) * 10 / 1048576 ))
  printf '%d.%d MB' "$whole" "$frac"
}

# render_mtime: epoch → UTC ISO8601 for the human output. Use python
# (already required by sibling scripts) so we don't depend on `date -u
# -d @<epoch>` semantics that differ across BSD/GNU.
render_mtime() {
  local e="$1"
  case "$e" in *[!0-9]*|"") echo "unknown"; return ;; esac
  if [ "$e" -le 0 ]; then echo "unknown"; return; fi
  python -c "
import sys
from datetime import datetime, timezone
e = int(sys.argv[1])
print(datetime.fromtimestamp(e, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
" "$e" 2>/dev/null || echo "unknown"
}

# ── Step 5: detect adjacent snapshot file ──────────────────────────────────────
# Scan the directory of chain.json for any file that looks like a
# snapshot produced by `determ snapshot create`. The convention in this
# repo is operator-chosen output paths, but the dominant patterns
# observed in tools/test_*.sh + docs are `*.snapshot.json`,
# `snapshot*.json`, `snap*.json`. We pick the most-recently-modified
# match to surface in the JSON for operator inspection.
CHAIN_DIR=$(dirname -- "$CHAIN_PATH_ABS")
SNAPSHOT_DETECTED=0
SNAPSHOT_PATH=""
if [ -d "$CHAIN_DIR" ]; then
  # Build candidates list. `2>/dev/null` swallows the "no match"
  # diagnostics from find on directories with no matches.
  SNAPSHOT_CANDIDATES=$(find "$CHAIN_DIR" -maxdepth 1 -type f \
    \( -name '*.snapshot.json' -o -name 'snapshot*.json' -o -name 'snap*.json' \) \
    2>/dev/null)
  if [ -n "$SNAPSHOT_CANDIDATES" ]; then
    # Pick the most-recently-modified candidate. We DON'T run
    # `determ snapshot inspect` here — that is operator_snapshot_lineage.sh's
    # job and would inflate runtime for a presence-only check. The
    # mere existence of a file with the snapshot naming convention is
    # the signal the spec asks for.
    SNAPSHOT_PATH=$(printf '%s\n' "$SNAPSHOT_CANDIDATES" \
      | while IFS= read -r f; do
          if [ -n "$f" ]; then
            mt=$(stat -c %Y -- "$f" 2>/dev/null) || mt=$(stat -f %m -- "$f" 2>/dev/null) || mt=0
            printf '%s\t%s\n' "$mt" "$f"
          fi
        done \
      | sort -rn \
      | head -n 1 \
      | cut -f2-)
    [ -n "$SNAPSHOT_PATH" ] && SNAPSHOT_DETECTED=1
  fi
fi

# ── Step 6: classify anomalies ─────────────────────────────────────────────────
ANOM_TYPES=""
ANOM_SEVS=""
ANOM_DETAILS=""

# Helper: append anomaly. Uses pipe-separated fields and newline-separated
# rows so the downstream renderer can re-parse cleanly without quoting
# headaches. Pipes don't appear in our hand-rolled detail strings.
add_anom() {
  ANOM_TYPES="${ANOM_TYPES}${ANOM_TYPES:+|}$1"
  ANOM_SEVS="${ANOM_SEVS}${ANOM_SEVS:+|}$2"
  ANOM_DETAILS="${ANOM_DETAILS}${ANOM_DETAILS:+~~}$3"
}

# (a) chain_file_missing — CRITICAL. Surface BEFORE size thresholds; if
# the file is missing the size comparison is meaningless.
if [ "$FILE_EXISTS" = "0" ]; then
  add_anom "chain_file_missing" "CRITICAL" \
    "chain.json not found at expected path: $CHAIN_PATH_ABS"
fi

# (b) chain_file_critical — CRITICAL.
if [ "$FILE_EXISTS" = "1" ] && [ "$FILE_SIZE_MB_INT" -gt "$CRIT_MB" ]; then
  add_anom "chain_file_critical" "CRITICAL" \
    "chain.json size (${FILE_SIZE_MB_INT} MB) > critical threshold (${CRIT_MB} MB); compact immediately"
fi

# (c) chain_file_warn — WARN. Fires when over warn but NOT also over
# critical (avoids double-firing on a file that triggers both, since
# critical subsumes warn semantically).
if [ "$FILE_EXISTS" = "1" ] \
   && [ "$FILE_SIZE_MB_INT" -gt "$WARN_MB" ] \
   && [ "$FILE_SIZE_MB_INT" -le "$CRIT_MB" ]; then
  add_anom "chain_file_warn" "WARN" \
    "chain.json size (${FILE_SIZE_MB_INT} MB) > warn threshold (${WARN_MB} MB); schedule compaction"
fi

# (d) snapshot_recommended — INFO. Only fires when block_count exceeds
# the threshold AND no snapshot file is adjacent. If a snapshot IS
# adjacent, the operator has already done the compaction work and the
# script stays silent on this axis.
if [ "$HEAD_H" -gt "$SNAP_THRESH" ] && [ "$SNAPSHOT_DETECTED" = "0" ]; then
  add_anom "snapshot_recommended" "INFO" \
    "head_height ($HEAD_H) > recommend threshold ($SNAP_THRESH) and no snapshot found next to chain.json; run \`determ snapshot create\` and consider truncating chain.json"
fi

# Count anomalies + critical anomalies for exit-code resolution.
if [ -z "$ANOM_TYPES" ]; then
  ANOM_COUNT=0
else
  ANOM_COUNT=$(printf '%s' "$ANOM_TYPES" | awk -F'|' '{print NF}')
fi
if [ -z "$ANOM_SEVS" ]; then
  CRIT_COUNT=0
else
  CRIT_COUNT=$(printf '%s' "$ANOM_SEVS" | awk -F'|' '{c=0; for(i=1;i<=NF;i++) if($i=="CRITICAL") c++; print c}')
fi

# Exit code resolution: CRITICAL ⇒ 2; otherwise 0. WARN + INFO do NOT
# escalate by themselves (matches the spec wording "exit 2 CRITICAL
# fired").
EXIT_CODE=0
if [ "$CRIT_COUNT" -gt 0 ]; then EXIT_CODE=2; fi

# ── Step 7: emit output ────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  # Single-line JSON envelope. We hand-assemble (no jq dependency) so
  # the script stays self-contained on a vanilla bash + python install.
  # Strings are quoted but contain no embedded quotes by construction;
  # the only field that could carry user-supplied bytes is CHAIN_PATH,
  # which we run through python's json.dumps to be safe.
  CHAIN_PATH_JSON=$(printf '%s' "$CHAIN_PATH_ABS" \
    | python -c 'import sys,json; sys.stdout.write(json.dumps(sys.stdin.read()))' 2>/dev/null)
  [ -z "$CHAIN_PATH_JSON" ] && CHAIN_PATH_JSON='""'
  if [ "$SNAPSHOT_DETECTED" = "1" ]; then
    SNAP_PATH_JSON=$(printf '%s' "$SNAPSHOT_PATH" \
      | python -c 'import sys,json; sys.stdout.write(json.dumps(sys.stdin.read()))' 2>/dev/null)
    [ -z "$SNAP_PATH_JSON" ] && SNAP_PATH_JSON='null'
  else
    SNAP_PATH_JSON='null'
  fi
  EXISTS_JSON=$([ "$FILE_EXISTS" = "1" ] && echo "true" || echo "false")
  SNAP_DETECTED_JSON=$([ "$SNAPSHOT_DETECTED" = "1" ] && echo "true" || echo "false")

  printf '{"chain_path":%s,"chain_path_exists":%s,' "$CHAIN_PATH_JSON" "$EXISTS_JSON"
  printf '"file_size_bytes":%s,"file_size_mb":%s,"file_mtime_epoch":%s,' \
    "$FILE_SIZE_BYTES" "$FILE_SIZE_MB_INT" "$FILE_MTIME"
  printf '"head_height":%s,"bytes_per_block":%s,"projected_size_at_2x_mb":%s,' \
    "$HEAD_H" "$BYTES_PER_BLOCK" "$PROJECTED_2X_MB_INT"
  printf '"snapshot_detected":%s,"snapshot_path":%s,' \
    "$SNAP_DETECTED_JSON" "$SNAP_PATH_JSON"
  printf '"warn_threshold_mb":%s,"critical_threshold_mb":%s,' \
    "$WARN_MB" "$CRIT_MB"
  printf '"snapshot_recommend_threshold_blocks":%s,' "$SNAP_THRESH"
  printf '"anomalies":['
  if [ "$ANOM_COUNT" -gt 0 ]; then
    # Walk the parallel arrays. Pipes split types/sevs, "~~" splits
    # details (no quoting issues in the hand-rolled detail strings).
    python - "$ANOM_TYPES" "$ANOM_SEVS" "$ANOM_DETAILS" <<'PY'
import json, sys
types   = sys.argv[1].split("|") if sys.argv[1] else []
sevs    = sys.argv[2].split("|") if sys.argv[2] else []
details = sys.argv[3].split("~~") if sys.argv[3] else []
out = []
for i in range(len(types)):
    out.append({
        "type":     types[i],
        "severity": sevs[i]    if i < len(sevs)    else "",
        "detail":   details[i] if i < len(details) else "",
    })
sys.stdout.write(",".join(json.dumps(o) for o in out))
PY
  fi
  printf '],"rpc_port":%s}\n' "$PORT"
  exit "$EXIT_CODE"
fi

# Human-readable rendering.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
  echo "operator_chain_compaction_audit: no anomalies (port $PORT, path $CHAIN_PATH_ABS)"
  exit "$EXIT_CODE"
fi

echo "=== Chain compaction audit (port $PORT) ==="
if [ "$ANOM_ONLY" != "1" ]; then
  echo "chain.json:        $CHAIN_PATH_ABS"
  if [ "$FILE_EXISTS" = "1" ]; then
    echo "file size:         $(render_mb $FILE_SIZE_BYTES) ($FILE_SIZE_BYTES bytes)"
    echo "file mtime:        $(render_mtime $FILE_MTIME)"
  else
    echo "file size:         (missing — file not found at expected path)"
  fi
  echo "head height:       $HEAD_H blocks"
  if [ "$BYTES_PER_BLOCK" -gt 0 ]; then
    echo "bytes per block:   $BYTES_PER_BLOCK bytes/block (avg over full chain)"
  else
    echo "bytes per block:   n/a (chain empty or file missing)"
  fi
  echo "projected at 2x:   $PROJECTED_2X_MB_INT MB (if chain doubles in length)"
  if [ "$SNAPSHOT_DETECTED" = "1" ]; then
    echo "snapshot adjacent: yes — $SNAPSHOT_PATH"
  else
    echo "snapshot adjacent: no (none matching *.snapshot.json / snapshot*.json / snap*.json in $CHAIN_DIR)"
  fi
  echo "thresholds:        warn=${WARN_MB} MB, critical=${CRIT_MB} MB, snapshot-recommend=${SNAP_THRESH} blocks"
  echo
fi

if [ "$ANOM_COUNT" = "0" ]; then
  echo "[OK] No anomalies"
else
  # Render each anomaly row. Re-split the pipe-separated arrays inside
  # awk so we don't need to remember which index the inline read was at.
  echo "[ANOMALY] $ANOM_COUNT flag(s) ($CRIT_COUNT CRITICAL):"
  python - "$ANOM_TYPES" "$ANOM_SEVS" "$ANOM_DETAILS" <<'PY'
import sys
types   = sys.argv[1].split("|") if sys.argv[1] else []
sevs    = sys.argv[2].split("|") if sys.argv[2] else []
details = sys.argv[3].split("~~") if sys.argv[3] else []
markers = {"CRITICAL": "[X]", "WARN": "[!]", "INFO": "[i]"}
for i in range(len(types)):
    sev = sevs[i] if i < len(sevs) else ""
    m   = markers.get(sev, "[?]")
    d   = details[i] if i < len(details) else ""
    print(f"  {m} {types[i]} ({sev}): {d}")
PY
fi

exit "$EXIT_CODE"
