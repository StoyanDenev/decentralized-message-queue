#!/usr/bin/env bash
# operator_light_freshness_probe.sh — Daemon liveness/freshness probe from
# the light-client perspective: take repeated head-height samples through
# the determ-light binary and require the head to ADVANCE between them.
#
# THE OPERATOR QUESTION
#   "Is the daemon my light clients talk to actually FOLLOWING a live
#    chain — or is it serving a stale (possibly perfectly attested)
#    head?"
#
# WHY A TIME-SERIES PROBE (the F-1 limitation)
#   A single light-client invocation can prove a served head is
#   committee-signed and chained to the pinned genesis, but it CANNOT
#   prove the head is CURRENT — a daemon replaying yesterday's chain
#   serves proofs that verify perfectly (the F-1 "stale-but-attested
#   head" limitation in proofs/LightClientThreatModel.md: freshness is
#   per-invocation undetectable). Operationally the gap closes by
#   sampling over time: a live chain produces blocks, so the head height
#   must advance between samples. This probe takes --probes samples
#   --interval seconds apart and PASSes only if
#       (last_height - first_height) >= --min-advance.
#
# PROBE METHOD (cheapest head-height read in light/main.cpp)
#   `determ-light fetch-headers --rpc-port N --from 0 --count 0`
#   issues the unauthenticated `headers` RPC (raw line-delimited JSON
#   over TCP — NEVER curl/HTTP) and dumps the reply to stdout. Per
#   src/node/node.cpp::rpc_headers the reply ALWAYS carries
#       {"headers":[...], "from":F, "count":C, "height":H}
#   where `height` is the daemon's chain height (block count; head
#   index = height-1) — so --count 0 returns the height with zero
#   header payload. The height is DAEMON-ASSERTED here; this probe
#   measures liveness/advancement, not header authenticity (pair with
#   `determ-light watch-head` / verify-chain for the trust-minimized
#   view of the same head).
#
# Read-only RPC; safe against any running daemon.
#
# Usage:
#   tools/operator_light_freshness_probe.sh --rpc-port N
#       [--interval seconds] [--probes count] [--min-advance blocks]
#
# determ-light binary resolution (first hit wins):
#   1. $DETERM_LIGHT (env)
#   2. build/Release/determ-light.exe   (Windows MSVC multi-config)
#   3. build/determ-light.exe           (Windows single-config)
#   4. build/determ-light               (Linux/Mac single-config)
#   5. build/Release/determ-light       (Linux/Mac multi-config)
#
# Exit codes:
#   0   head advancing (delta >= --min-advance)        — PASS
#   1   head NOT advancing (stalled chain / stale daemon) — FAIL
#   2   prerequisites missing (binary absent, daemon unreachable,
#       malformed reply, or usage error)
set -u

SCRIPT=operator_light_freshness_probe

usage() {
  cat <<'EOF'
Usage: operator_light_freshness_probe.sh --rpc-port N
           [--interval seconds] [--probes count] [--min-advance blocks]

Daemon liveness/freshness probe from the light-client perspective.
Takes --probes head-height samples --interval seconds apart via
`determ-light fetch-headers` (the unauthenticated `headers` RPC, whose
reply always carries the daemon's chain height) and PASSes only if the
head ADVANCED:  (last_height - first_height) >= --min-advance.

Rationale: a single light-client invocation can prove a head is
committee-signed, but NOT that it is current — a daemon replaying an
old chain serves perfectly-verifying proofs (the F-1 stale-but-attested
head limitation). Requiring advancement over time detects that
operationally.

Required:
  --rpc-port N         RPC port of the daemon to probe

Options:
  --interval seconds   Seconds between samples (default: 10, min 1)
  --probes count       Number of samples to take (default: 2, min 2)
  --min-advance blocks Minimum required height gain between the first
                       and last sample (default: 1)
  -h, --help           Show this help

Environment:
  DETERM_LIGHT         Path to the determ-light binary (else the
                       standard build locations are probed:
                       build/Release/determ-light.exe, build/determ-light,
                       and their siblings)

Exit codes:
  0   head advancing (delta >= --min-advance)
  1   head NOT advancing — stalled chain or stale daemon
  2   prerequisites missing (binary absent, daemon unreachable,
      malformed reply, or usage error)
EOF
}

# ── arg parse (--help first so it never trips validation) ─────────────────────
PORT=""
INTERVAL=10
PROBES=2
MIN_ADVANCE=1
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)     usage; exit 0 ;;
    --rpc-port)    PORT="${2:-}";        shift 2 ;;
    --interval)    INTERVAL="${2:-}";    shift 2 ;;
    --probes)      PROBES="${2:-}";      shift 2 ;;
    --min-advance) MIN_ADVANCE="${2:-}"; shift 2 ;;
    *) echo "$SCRIPT: unknown argument: $1" >&2
       usage >&2; exit 2 ;;
  esac
done

# ── argument validation ───────────────────────────────────────────────────────
if [ -z "$PORT" ]; then
  echo "$SCRIPT: --rpc-port is required" >&2
  usage >&2
  exit 2
fi
case "$PORT" in *[!0-9]*|"")
  echo "$SCRIPT: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 2 ;;
esac
case "$INTERVAL" in *[!0-9]*|"")
  echo "$SCRIPT: --interval must be an unsigned integer (got '$INTERVAL')" >&2
  exit 2 ;;
esac
if [ "$INTERVAL" -lt 1 ]; then
  echo "$SCRIPT: --interval must be >= 1 second (got $INTERVAL)" >&2
  exit 2
fi
case "$PROBES" in *[!0-9]*|"")
  echo "$SCRIPT: --probes must be an unsigned integer (got '$PROBES')" >&2
  exit 2 ;;
esac
if [ "$PROBES" -lt 2 ]; then
  echo "$SCRIPT: --probes must be >= 2 (advancement needs two samples; got $PROBES)" >&2
  exit 2
fi
case "$MIN_ADVANCE" in *[!0-9]*|"")
  echo "$SCRIPT: --min-advance must be an unsigned integer (got '$MIN_ADVANCE')" >&2
  exit 2 ;;
esac

cd "$(dirname "$0")/.."

# ── determ-light binary resolution ────────────────────────────────────────────
# $DETERM_LIGHT env > standard build locations (mirrors tools/common.sh /
# operator_constants_audit.sh). An explicit env choice that is not
# executable is an ERROR, not a fall-through.
LIGHT=""
if [ -n "${DETERM_LIGHT:-}" ]; then
  LIGHT="$DETERM_LIGHT"
  if [ ! -x "$LIGHT" ]; then
    echo "$SCRIPT: \$DETERM_LIGHT '$LIGHT' is not an executable file" >&2
    exit 2
  fi
else
  for cand in build/Release/determ-light.exe build/determ-light.exe \
              build/determ-light build/Release/determ-light; do
    if [ -x "$cand" ]; then
      LIGHT="$cand"
      break
    fi
  done
  if [ -z "$LIGHT" ]; then
    echo "$SCRIPT: determ-light binary not found. Build it with" >&2
    echo "    cmake --build build --config Release --target determ-light" >&2
    echo "  or point at one via \$DETERM_LIGHT." >&2
    exit 2
  fi
fi

# ── head-height sampler ───────────────────────────────────────────────────────
# Prints the sampled height on stdout; returns non-zero on RPC failure or
# a malformed reply (diagnostic on stderr). --count 0 keeps the reply to
# the envelope only ({"headers":[],"from":0,"count":0,"height":H}) — no
# header bodies, so the grep fallback cannot hit a nested field.
sample_height() {
  local out h
  out=$("$LIGHT" fetch-headers --rpc-port "$PORT" --from 0 --count 0 2>&1) || {
    printf '%s\n' "$out" | head -1 >&2
    return 1
  }
  if command -v jq >/dev/null 2>&1; then
    h=$(printf '%s' "$out" | jq -r '.height' 2>/dev/null)
  else
    h=$(printf '%s' "$out" | grep -o '"height":[0-9]*' | head -1 | sed 's/.*://')
  fi
  case "$h" in
    ""|*[!0-9]*)
      echo "$SCRIPT: malformed headers reply (no numeric height): $(printf '%s' "$out" | head -c 200)" >&2
      return 1 ;;
  esac
  printf '%s\n' "$h"
  return 0
}

# ── probe loop ────────────────────────────────────────────────────────────────
echo "=== Light-client freshness probe (port $PORT) ==="
echo "light:       $LIGHT"
echo "plan:        $PROBES sample(s), ${INTERVAL}s apart, require advance >= $MIN_ADVANCE block(s)"

FIRST=""
LAST=""
i=1
while [ "$i" -le "$PROBES" ]; do
  if ! H=$(sample_height); then
    if [ "$i" -eq 1 ]; then
      echo "$SCRIPT: daemon unreachable on first probe (is a daemon listening on RPC port $PORT?)" >&2
    else
      echo "$SCRIPT: daemon became unreachable on probe $i/$PROBES (was responding earlier)" >&2
    fi
    exit 2
  fi
  echo "  probe $i/$PROBES  $(date +%H:%M:%S)  height=$H"
  [ -z "$FIRST" ] && FIRST="$H"
  LAST="$H"
  if [ "$i" -lt "$PROBES" ]; then
    sleep "$INTERVAL"
  fi
  i=$((i + 1))
done

# ── verdict ───────────────────────────────────────────────────────────────────
DELTA=$((LAST - FIRST))
SPAN=$(((PROBES - 1) * INTERVAL))
if [ "$DELTA" -ge "$MIN_ADVANCE" ]; then
  echo "[PASS] head advanced by $DELTA block(s) over ${SPAN}s (required >= $MIN_ADVANCE) — daemon is following a live chain"
  exit 0
fi
if [ "$DELTA" -lt 0 ]; then
  echo "  note: head went BACKWARDS by $((-DELTA)) block(s) — daemon restart or chain replacement?"
fi
echo "[FAIL] daemon head is NOT advancing — stalled chain or stale daemon"
echo "       (height $FIRST -> $LAST over ${SPAN}s; required advance >= $MIN_ADVANCE)"
echo "       A stale daemon can still serve perfectly-attested proofs (F-1):"
echo "       widen --interval / --probes before alarm if block production is slow."
exit 1
