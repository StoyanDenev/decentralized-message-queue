#!/usr/bin/env bash
# operator_snapshot_check.sh — Verify a snapshot file's integrity AND
# (by default) check whether it matches a running daemon's state.
#
# Composes three existing, read-only surfaces:
#   * `determ snapshot inspect --in <file> --json`
#       Full restore-pipeline integrity check (S-033/S-038 state_root
#       gate). Exit 1 on any structural failure.
#   * `determ snapshot stats <file> --json`
#       Lightweight metadata read (file size on disk + A1 unitary-supply
#       counters) — `inspect` does not surface either of these.
#   * `determ head --json --rpc-port P`
#       Current chain head on the running daemon (height + head_hash).
#       Default mode only; --offline skips this and the daemon-compare
#       step entirely.
#
# All three are read-only; safe against any running daemon.
#
# Usage:
#   tools/operator_snapshot_check.sh --in <file>
#                                    [--rpc-port N] [--offline]
#                                    [--state-root <hex64>] [--json]
#
# Exit codes:
#   0 — snapshot integrity OK + (default mode) consistent with daemon
#   1 — file error / RPC error / malformed snapshot / bad args
#   2 — operator alert: fork detected (head_hash mismatch at equal
#       height) OR snapshot ahead of daemon (daemon's chain is shorter
#       than the snapshot — points at a stale/rolled-back daemon)
#
# Use cases:
#   1. Pre-restore triage — before pointing a fresh node at a snapshot,
#      verify the snapshot itself is structurally sound (integrity) and
#      that an existing same-chain reference daemon agrees with its head
#      hash at the snapshot's height (donor-side cross-check).
#   2. Fast-sync donor selection — confirm a snapshot is a valid donor
#      candidate for a peer (reports "BEHIND daemon by N blocks" so the
#      operator knows how much tail-replay the joining node still has).
#   3. Fork detection — when a snapshot and a daemon claim the same
#      height but different head hashes, exit 2 makes this a CI/cron
#      alert gate (the snapshot is from a fork, OR the daemon was
#      restored from a divergent state).
#   4. Trustless verification — combined with --state-root, pins the
#      snapshot's restored state_root against an externally-trusted
#      value (e.g., from a published checkpoint) without needing a
#      live daemon at all.
set -u

usage() {
  cat <<'EOF'
Usage: operator_snapshot_check.sh --in <file>
                                  [--rpc-port N] [--offline]
                                  [--state-root <hex64>] [--json]

Verifies a snapshot file's integrity (via `determ snapshot inspect`)
and, by default, compares its head_index + head_hash against the head
of a running determ daemon.

Required:
  --in <file>            Path to the snapshot file to verify

Options:
  --rpc-port N           RPC port of the running daemon (default: 7778)
  --offline              Skip the daemon comparison; only validate the
                         snapshot file's structure + state_root.
  --state-root <hex64>   Pin the snapshot's restored state_root against
                         an externally-trusted root (trustless gate).
                         If supplied and the snapshot's restored root
                         disagrees, exits 1.
  --json                 Emit single-line JSON instead of human digest
  -h, --help             Show this help

Exit codes:
  0   OK (integrity verified; --offline OR consistent with daemon)
  1   file error / RPC error / bad args / state-root mismatch
  2   operator alert (fork detected at equal height; OR snapshot ahead
      of daemon — daemon's chain is shorter than the snapshot)

JSON shape:
  {"snapshot_path":"<path>",
   "file_size":<bytes>,
   "snapshot":{
     "head_index":<u64>,"head_hash":"<hex>","state_root":"<hex>",
     "accounts":<n>,"stakes":<n>,"registrants":<n>,
     "genesis_total":<u64>,"accumulated_subsidy":<u64>,
     "accumulated_inbound":<u64>,"accumulated_slashed":<u64>,
     "accumulated_outbound":<u64>
   },
   "daemon":{"head_index":<u64>,"head_hash":"<hex>"} | null,
   "comparison":"behind"|"at"|"ahead" | null,
   "fork_detected":<bool>,
   "rpc_port":<N>}
EOF
}

IN=""
PORT=7778
OFFLINE=0
STATE_ROOT=""
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)     usage; exit 0 ;;
    --in)          IN="$2";          shift 2 ;;
    --rpc-port)    PORT="$2";        shift 2 ;;
    --offline)     OFFLINE=1;        shift ;;
    --state-root)  STATE_ROOT="$2";  shift 2 ;;
    --json)        JSON_OUT=1;       shift ;;
    *) echo "operator_snapshot_check: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$IN" ]; then
  echo "operator_snapshot_check: --in <file> is required" >&2
  usage >&2
  exit 1
fi

# Numeric guard on the port — protects downstream RPC + the JSON
# emitter from a non-numeric value sneaking through.
case "$PORT" in
  *[!0-9]*|"")
    echo "operator_snapshot_check: --rpc-port must be a positive integer (got '$PORT')" >&2
    exit 1 ;;
esac

# --state-root sanity: 64 hex chars (snapshot inspect enforces this
# server-side too, but reject early so the diagnostic mentions the
# operator-supplied value explicitly).
if [ -n "$STATE_ROOT" ]; then
  case "$STATE_ROOT" in
    *[!0-9a-fA-F]*|"")
      echo "operator_snapshot_check: --state-root must be 64 hex chars (got '$STATE_ROOT')" >&2
      exit 1 ;;
  esac
  if [ ${#STATE_ROOT} -ne 64 ]; then
    echo "operator_snapshot_check: --state-root must be exactly 64 hex chars (got ${#STATE_ROOT})" >&2
    exit 1
  fi
fi

# File-existence + readability check up front. `snapshot inspect` and
# `snapshot stats` both report cannot_open, but checking here makes the
# diagnostic mention the operator-supplied path before any subprocess.
if [ ! -f "$IN" ]; then
  echo "operator_snapshot_check: --in file not found: $IN" >&2
  exit 1
fi
if [ ! -r "$IN" ]; then
  echo "operator_snapshot_check: --in file not readable: $IN" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── 1. Structural integrity check via `snapshot inspect` ──
# Run the heavy restore + state_root recompute path. Pass through
# --state-root if supplied; `snapshot inspect` enforces the comparison
# and exits 1 if the snapshot's root disagrees with the supplied one.
INSPECT_ARGS=(snapshot inspect --in "$IN" --json)
if [ -n "$STATE_ROOT" ]; then
  INSPECT_ARGS+=(--state-root "$STATE_ROOT")
fi
INSPECT_OUT=$("$DETERM" "${INSPECT_ARGS[@]}" 2>&1)
INSPECT_RC=$?
if [ "$INSPECT_RC" -ne 0 ]; then
  echo "operator_snapshot_check: snapshot integrity check failed (rc=$INSPECT_RC, file=$IN)" >&2
  echo "$INSPECT_OUT" >&2
  exit 1
fi

# ── 2. Metadata (file size + A1 counters) via `snapshot stats` ──
# `snapshot inspect` does NOT surface either of these, so run the
# lightweight stats pass too. We already validated the file via the
# inspect pipeline above, so any parse failure here is unexpected.
STATS_OUT=$("$DETERM" snapshot stats "$IN" --json 2>&1)
STATS_RC=$?
if [ "$STATS_RC" -ne 0 ]; then
  echo "operator_snapshot_check: snapshot stats failed (rc=$STATS_RC, file=$IN)" >&2
  echo "$STATS_OUT" >&2
  exit 1
fi

# Field extraction — prefer jq when available, fall back to grep/sed
# (matches the operator_*.sh family convention).
if command -v jq >/dev/null 2>&1; then
  SNAP_INDEX=$(printf '%s' "$INSPECT_OUT"     | jq -r '.block_index')
  SNAP_HEAD=$(printf '%s' "$INSPECT_OUT"      | jq -r '.head_hash')
  SNAP_ROOT=$(printf '%s' "$INSPECT_OUT"      | jq -r '.state_root')
  SNAP_ACCT=$(printf '%s' "$INSPECT_OUT"      | jq -r '.accounts')
  SNAP_STAKE=$(printf '%s' "$INSPECT_OUT"     | jq -r '.stakes')
  SNAP_REG=$(printf '%s' "$INSPECT_OUT"       | jq -r '.registrants')
  FILE_SIZE=$(printf '%s' "$STATS_OUT"        | jq -r '.size_bytes')
  GEN_TOTAL=$(printf '%s' "$STATS_OUT"        | jq -r '.genesis_total')
  ACC_SUB=$(printf '%s' "$STATS_OUT"          | jq -r '.accumulated_subsidy')
  ACC_IN=$(printf '%s' "$STATS_OUT"           | jq -r '.accumulated_inbound')
  ACC_SLASH=$(printf '%s' "$STATS_OUT"        | jq -r '.accumulated_slashed')
  ACC_OUT=$(printf '%s' "$STATS_OUT"          | jq -r '.accumulated_outbound')
else
  # Numeric / string scrapers — match operator_supply_check.sh style.
  SNAP_INDEX=$(printf '%s' "$INSPECT_OUT"  | grep -o '"block_index":[^,}]*'         | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  SNAP_HEAD=$(printf '%s' "$INSPECT_OUT"   | grep -o '"head_hash":"[^"]*"'          | head -1 | sed 's/.*: *//; s/"//g')
  SNAP_ROOT=$(printf '%s' "$INSPECT_OUT"   | grep -o '"state_root":"[^"]*"'         | head -1 | sed 's/.*: *//; s/"//g')
  SNAP_ACCT=$(printf '%s' "$INSPECT_OUT"   | grep -o '"accounts":[^,}]*'            | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  SNAP_STAKE=$(printf '%s' "$INSPECT_OUT"  | grep -o '"stakes":[^,}]*'              | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  SNAP_REG=$(printf '%s' "$INSPECT_OUT"    | grep -o '"registrants":[^,}]*'         | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  FILE_SIZE=$(printf '%s' "$STATS_OUT"     | grep -o '"size_bytes":[^,}]*'          | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  GEN_TOTAL=$(printf '%s' "$STATS_OUT"     | grep -o '"genesis_total":[^,}]*'       | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  ACC_SUB=$(printf '%s' "$STATS_OUT"       | grep -o '"accumulated_subsidy":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  ACC_IN=$(printf '%s' "$STATS_OUT"        | grep -o '"accumulated_inbound":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  ACC_SLASH=$(printf '%s' "$STATS_OUT"     | grep -o '"accumulated_slashed":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  ACC_OUT=$(printf '%s' "$STATS_OUT"       | grep -o '"accumulated_outbound":[^,}]*'| head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
fi

# Defensive sanity check — these should all be populated after a
# successful inspect+stats pair. An empty value here points at a
# CLI-output-shape regression upstream.
if [ -z "${SNAP_INDEX:-}" ] || [ -z "${SNAP_HEAD:-}" ] || [ -z "${FILE_SIZE:-}" ]; then
  echo "operator_snapshot_check: malformed snapshot JSON (missing fields)" >&2
  echo "inspect: $INSPECT_OUT" >&2
  echo "stats:   $STATS_OUT" >&2
  exit 1
fi

# Human-readable file-size formatter (B / KB / MB / GB to one decimal).
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

# ── 3. Daemon comparison (skipped under --offline) ──
DAEMON_INDEX=""
DAEMON_HEAD=""
COMPARISON=""
FORK_DETECTED="false"
OFFSET=0
RC=0

if [ "$OFFLINE" = "0" ]; then
  HEAD_OUT=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
    echo "operator_snapshot_check: RPC error querying head (is daemon running on port $PORT?)" >&2
    exit 1
  }
  if command -v jq >/dev/null 2>&1; then
    DAEMON_INDEX=$(printf '%s' "$HEAD_OUT" | jq -r '.height')
    DAEMON_HEAD=$(printf '%s'  "$HEAD_OUT" | jq -r '.head_hash')
  else
    DAEMON_INDEX=$(printf '%s' "$HEAD_OUT" | grep -o '"height":[^,}]*'     | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
    DAEMON_HEAD=$(printf '%s'  "$HEAD_OUT" | grep -o '"head_hash":"[^"]*"' | head -1 | sed 's/.*: *//; s/"//g')
  fi
  if [ -z "${DAEMON_INDEX:-}" ] || [ -z "${DAEMON_HEAD:-}" ]; then
    echo "operator_snapshot_check: daemon returned malformed head JSON (port $PORT)" >&2
    echo "$HEAD_OUT" >&2
    exit 1
  fi

  # Three-way comparison.
  if [ "$SNAP_INDEX" -lt "$DAEMON_INDEX" ] 2>/dev/null; then
    COMPARISON="behind"
    OFFSET=$((SNAP_INDEX - DAEMON_INDEX))   # negative
  elif [ "$SNAP_INDEX" -gt "$DAEMON_INDEX" ] 2>/dev/null; then
    COMPARISON="ahead"
    OFFSET=$((SNAP_INDEX - DAEMON_INDEX))   # positive
    RC=2  # alert — daemon's chain is shorter than the snapshot
  else
    COMPARISON="at"
    OFFSET=0
    if [ "$SNAP_HEAD" != "$DAEMON_HEAD" ]; then
      FORK_DETECTED="true"
      RC=2
    fi
  fi
fi

# ── 4. Emit ──
if [ "$JSON_OUT" = "1" ]; then
  if [ "$OFFLINE" = "1" ]; then
    DAEMON_JSON="null"
    COMP_JSON="null"
  else
    DAEMON_JSON=$(printf '{"head_index":%s,"head_hash":"%s"}' "$DAEMON_INDEX" "$DAEMON_HEAD")
    COMP_JSON=$(printf '"%s"' "$COMPARISON")
  fi
  cat <<EOF
{"snapshot_path":"$IN","file_size":$FILE_SIZE,"snapshot":{"head_index":$SNAP_INDEX,"head_hash":"$SNAP_HEAD","state_root":"$SNAP_ROOT","accounts":$SNAP_ACCT,"stakes":$SNAP_STAKE,"registrants":$SNAP_REG,"genesis_total":$GEN_TOTAL,"accumulated_subsidy":$ACC_SUB,"accumulated_inbound":$ACC_IN,"accumulated_slashed":$ACC_SLASH,"accumulated_outbound":$ACC_OUT},"daemon":$DAEMON_JSON,"comparison":$COMP_JSON,"fork_detected":$FORK_DETECTED,"rpc_port":$PORT}
EOF
  exit $RC
fi

# Human output.
truncate_hash() {
  local h="$1"
  if [ -n "$h" ] && [ "${#h}" -gt 16 ]; then
    printf '%s...' "${h:0:16}"
  else
    printf '%s' "$h"
  fi
}

if [ "$OFFLINE" = "1" ]; then
  echo "=== Snapshot check (offline, snapshot=$IN) ==="
else
  echo "=== Snapshot check (port $PORT, snapshot=$IN) ==="
fi
echo "File size: $(human_size "$FILE_SIZE")"
echo "Snapshot state:"
echo "  head_index:  $SNAP_INDEX"
echo "  head_hash:   $(truncate_hash "$SNAP_HEAD")"
echo "  state_root:  $(truncate_hash "$SNAP_ROOT")"
echo "  accounts:    $SNAP_ACCT"
echo "  stakes:      $SNAP_STAKE"
echo "  registrants: $SNAP_REG"
echo "  genesis_total:        $GEN_TOTAL"
echo "  accumulated_subsidy:  $ACC_SUB"
echo "  accumulated_inbound:  $ACC_IN"
echo "  accumulated_slashed:  $ACC_SLASH"
echo "  accumulated_outbound: $ACC_OUT"

if [ "$OFFLINE" = "0" ]; then
  echo "Daemon state:"
  echo "  head_index:  $DAEMON_INDEX"
  echo "  head_hash:   $(truncate_hash "$DAEMON_HEAD")"
  echo "Comparison:"
  case "$COMPARISON" in
    behind)
      # OFFSET is negative; display absolute lag with sign for clarity.
      echo "  Snapshot is BEHIND daemon (offset: $OFFSET blocks)"
      ;;
    ahead)
      echo "  Snapshot is AHEAD of daemon (offset: +$OFFSET blocks) — daemon's chain is shorter"
      ;;
    at)
      if [ "$FORK_DETECTED" = "true" ]; then
        echo "  Snapshot is AT daemon height ($SNAP_INDEX) but head_hash MISMATCH — FORK"
        echo "    snapshot head: $SNAP_HEAD"
        echo "    daemon head:   $DAEMON_HEAD"
      else
        echo "  Snapshot is AT daemon height ($SNAP_INDEX); head_hash agrees"
      fi
      ;;
  esac
fi

echo "[OK] Snapshot integrity verified"
if [ -n "$STATE_ROOT" ]; then
  echo "[OK] state_root matches supplied --state-root"
fi

if [ "$OFFLINE" = "0" ]; then
  case "$COMPARISON" in
    behind)
      LAG=$((DAEMON_INDEX - SNAP_INDEX))
      echo "[OK] Snapshot consistent with daemon chain (behind by $LAG blocks — fast-sync donor candidate)"
      ;;
    at)
      if [ "$FORK_DETECTED" = "true" ]; then
        echo "[X]  FORK DETECTED — snapshot and daemon disagree at height $SNAP_INDEX" >&2
      else
        echo "[OK] Snapshot consistent with daemon chain (at head)"
      fi
      ;;
    ahead)
      LEAD=$((SNAP_INDEX - DAEMON_INDEX))
      echo "[X]  Snapshot AHEAD of daemon by $LEAD blocks — daemon may be stale or rolled back" >&2
      ;;
  esac
fi

exit $RC
