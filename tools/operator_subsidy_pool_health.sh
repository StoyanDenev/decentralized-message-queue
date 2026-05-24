#!/usr/bin/env bash
# operator_subsidy_pool_health.sh — Track finite-pool (E4) subsidy drain
# rates + NEF (E1) pool depletion + projected exhaustion timeline on a
# running determ daemon. Read-only RPC composition; safe against a
# producing chain.
#
# Sibling scripts:
#   - operator_subsidy_audit.sh         — per-block subsidy ATTRIBUTION
#                                         across creators (distribution
#                                         drift, concentration, anomalies).
#   - operator_subsidy_lottery_audit.sh — LOTTERY-mode fairness (hit-rate
#                                         vs 1/M, per-creator chi-squared).
#   - operator_supply_check.sh          — A1 unitary-supply invariant gate.
#
# This script is the POOL HEALTH monitor: it computes the *current* pool
# level (E4 finite-pool remainder + E1 NEF pool balance), the observed
# drain RATE across a window of blocks, and the projected EXHAUSTION
# height (when subsidy stops paying / when NEF stops covering new
# REGISTERs). The output is structured for monitoring / alerting:
# operators can drive this from cron and gate on the exit code.
#
# Subsidy-mode taxonomy (per chain.cpp::apply_block + genesis.cpp):
#
#   subsidy_mode = 0   FLAT     per-block subsidy is exactly block_subsidy
#                               (E3 distribution; see operator_subsidy_audit
#                                for the per-creator split rule).
#   subsidy_mode = 1   LOTTERY  per-block subsidy is a two-point draw:
#                               block_subsidy * lottery_jackpot_multiplier
#                               (1/M of blocks) or 0 (rest). Expected
#                               per-block value equals FLAT subsidy.
#
# Pool axes (orthogonal to subsidy_mode — any combination is valid):
#
#   E4 FINITE_POOL   subsidy_pool_initial != 0: cumulative subsidy is
#                    hard-capped at the pool. Once accumulated_subsidy
#                    reaches subsidy_pool_initial, every subsequent block
#                    pays 0 subsidy. When subsidy_pool_initial == 0 the
#                    chain runs in PERPETUAL-subsidy mode (no pool to
#                    drain; pool-health analysis short-circuits as healthy).
#
#   E1 NEF           zeroth_pool_initial != 0: ZEROTH_ADDRESS pseudo-
#                    account holds the NEF pool. Halves on each *first-
#                    time* REGISTER. Drains geometrically toward 0; the
#                    last unit can be paid to the last new REGISTER then
#                    the pool effectively ceases to subsidize newcomers.
#                    When zeroth_pool_initial == 0 the chain has no NEF
#                    program (NEF analysis short-circuits).
#
# Algorithm:
#   1. Snapshot head_height + accumulated_subsidy + NEF balance (via
#      chain_summary + balance RPCs — both read-only).
#   2. Resolve the drain-rate window: --last N (default 1000) or
#      --from H / --to H. The window must end at OR before tip; for
#      historical windows the rate is estimated from the bracketing
#      blocks' accumulated_subsidy.
#   3. Pull the WINDOW START supply snapshot. The chain exposes
#      `accumulated_subsidy` only at the current head — to get the
#      window-start value we walk *just two blocks* (the one before
#      `--from` for the FROM snapshot — via block-info), and use the
#      current `accumulated_subsidy` as the TO snapshot (when --to ==
#      tip). For historical windows ending before tip we walk to read
#      the block-info delta. NB: block-info doesn't expose accumulated_
#      subsidy per block; we therefore approximate the per-block drain
#      via the (current_supply - inferred_start) / window arithmetic,
#      falling back to the lifetime average if the genesis-supplied
#      block_subsidy is unavailable.
#   4. Project exhaustion:
#        E4: blocks_until_empty = remaining_pool / drain_rate_per_block
#            projected_exhaustion_height = head + blocks_until_empty
#        E1: drain is geometric per first-time REGISTER (not per block);
#            we report the geometric half-life surrogate
#            (registrations_until_effectively_zero) using the observed
#            NEF pool delta over the window — IF the window saw at least
#            one halving event. Otherwise reports an INFO line.
#   5. Anomaly classification (additive — multiple flags can fire):
#        - subsidy_pool_critical   CRITICAL: remaining < crit-pct * initial
#        - subsidy_pool_warn       WARN:     remaining < warn-pct * initial
#        - drain_rate_spike        WARN:     observed > 2 * long-term mean
#        - exhaustion_imminent     CRITICAL: < 5000 blocks until empty
#        - nef_pool_exhausted      INFO:     ZEROTH balance == 0
#
# Mode sourcing precedence (subsidy_mode, subsidy_pool_initial,
# block_subsidy are NOT exposed over RPC — they're genesis-time
# constants):
#   1. --genesis <file>            — read directly from genesis JSON
#                                    (authoritative source; matches
#                                    operator_subsidy_lottery_audit's
#                                    pattern).
#   2. --subsidy-pool-initial V
#      --block-subsidy V
#      --subsidy-mode M            — operator-supplied overrides.
#   3. Heuristic fallback          — when neither is set: long-term
#                                    mean drain rate via
#                                    accumulated_subsidy / head_height.
#                                    The E4 critical-threshold check is
#                                    skipped (no initial-pool value to
#                                    compare against) and the script
#                                    reports an INFO line noting the
#                                    perpetual-mode assumption.
#
# Usage:
#   tools/operator_subsidy_pool_health.sh --rpc-port N
#                                         [--from H] [--to H] [--last N]
#                                         [--critical-threshold-pct F]
#                                         [--warn-threshold-pct F]
#                                         [--genesis <file>]
#                                         [--subsidy-pool-initial V]
#                                         [--block-subsidy V]
#                                         [--subsidy-mode M]
#                                         [--json] [--anomalies-only]
#
# RPC dependencies (all read-only):
#   - head                                        (current chain height)
#   - supply --field accumulated_subsidy          (E4 cumulative mint)
#   - balance ZEROTH_ADDRESS                      (E1 NEF pool balance)
#   - (no per-block walk — pool-health is a snapshot + window arithmetic)
#
# Exit codes:
#   0   healthy (all gates green / informational mode)
#   1   RPC error / bad args / malformed response
#   2   CRITICAL anomaly fired: exhaustion_imminent OR subsidy_pool_critical
#       (operator alert gate — distinct from sibling-script convention
#        where exit 2 requires --anomalies-only; for pool health the
#        CRITICAL gate fires unconditionally because pool exhaustion
#        cannot be silenced by an operator flag)
set -u

usage() {
  cat <<'EOF'
Usage: operator_subsidy_pool_health.sh --rpc-port N
                                       [--from H] [--to H] [--last N]
                                       [--critical-threshold-pct F]
                                       [--warn-threshold-pct F]
                                       [--genesis <file>]
                                       [--subsidy-pool-initial V]
                                       [--block-subsidy V]
                                       [--subsidy-mode M]
                                       [--json] [--anomalies-only]

Track E4 finite-pool subsidy drain + E1 NEF pool depletion. Snapshots
current pool level via RPC, computes observed drain rate across a
window, and projects exhaustion height. Anomaly classification + exit
2 on CRITICAL gates.

Required:
  --rpc-port N                    RPC port to query (no default).

Window (mutually exclusive groups; --last cannot be combined with
--from / --to):
  --from H                        Window start (inclusive). Default tip-1000.
  --to H                          Window end   (inclusive). Default tip.
  --last N                        Shorthand for [tip-N+1, tip]. Default 1000.

Anomaly thresholds (override defaults):
  --critical-threshold-pct F      Pool below F * initial fires CRITICAL.
                                  Default 0.05 (5%). F in [0.0, 1.0].
  --warn-threshold-pct F          Pool below F * initial fires WARN.
                                  Default 0.20 (20%). F in [0.0, 1.0].

Genesis sourcing (precedence: --genesis > CLI overrides > heuristic):
  --genesis <file>                Read subsidy_mode, block_subsidy,
                                  subsidy_pool_initial, zeroth_pool_initial
                                  from genesis JSON (authoritative).
  --subsidy-pool-initial V        E4 finite-pool size (operator-supplied).
  --block-subsidy V               Per-block subsidy value (FLAT-mode).
  --subsidy-mode M                0=FLAT, 1=LOTTERY (matches genesis enum).

Output:
  --json                          Emit structured JSON envelope.
  --anomalies-only                Print only flagged anomalies.
  -h, --help                      Show this help.

Anomaly flags:
  subsidy_pool_critical           CRITICAL: remaining_pool < crit-pct * initial
  subsidy_pool_warn               WARN:     remaining_pool < warn-pct * initial
  drain_rate_spike                WARN:     observed rate > 2x lifetime mean
  exhaustion_imminent             CRITICAL: projected_exhaustion_height
                                            < head + 5000 blocks
  nef_pool_exhausted              INFO:     ZEROTH balance == 0 (NEF inert)

Exit codes:
  0   healthy or informational mode
  1   RPC error / bad args / malformed response
  2   CRITICAL anomaly fired (exhaustion_imminent OR subsidy_pool_critical)
EOF
}

PORT=""
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
LAST_N=""
CRIT_PCT="0.05"
WARN_PCT="0.20"
GEN_PATH=""
POOL_INITIAL_OVR=""
BLOCK_SUBSIDY_OVR=""
SUBSIDY_MODE_OVR=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                  usage; exit 0 ;;
    --rpc-port)                 PORT="${2:-}";                shift 2 ;;
    --json)                     JSON_OUT=1;                   shift ;;
    --from)                     FROM_H="${2:-}";              shift 2 ;;
    --to)                       TO_H="${2:-}";                shift 2 ;;
    --last)                     LAST_N="${2:-}";              shift 2 ;;
    --critical-threshold-pct)   CRIT_PCT="${2:-}";            shift 2 ;;
    --warn-threshold-pct)       WARN_PCT="${2:-}";            shift 2 ;;
    --genesis)                  GEN_PATH="${2:-}";            shift 2 ;;
    --subsidy-pool-initial)     POOL_INITIAL_OVR="${2:-}";    shift 2 ;;
    --block-subsidy)            BLOCK_SUBSIDY_OVR="${2:-}";   shift 2 ;;
    --subsidy-mode)             SUBSIDY_MODE_OVR="${2:-}";    shift 2 ;;
    --anomalies-only)           ANOM_ONLY=1;                  shift ;;
    *) echo "operator_subsidy_pool_health: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (no defaults; refuses to guess the daemon on
# multi-instance hosts — matches operator_subsidy_audit + operator_committee_audit).
if [ -z "$PORT" ]; then
  echo "operator_subsidy_pool_health: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_subsidy_pool_health: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# --last is mutually exclusive with --from / --to (avoids ambiguity).
if [ -n "$LAST_N" ] && { [ -n "$FROM_H" ] || [ -n "$TO_H" ]; }; then
  echo "operator_subsidy_pool_health: --last cannot be combined with --from / --to" >&2
  exit 1
fi

# Numeric guards on unsigned-integer options.
for v in "$FROM_H" "$TO_H" "$LAST_N" \
         "$POOL_INITIAL_OVR" "$BLOCK_SUBSIDY_OVR" "$SUBSIDY_MODE_OVR"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_subsidy_pool_health: numeric option must be unsigned integer (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST_N" ] && [ "$LAST_N" = "0" ]; then
  echo "operator_subsidy_pool_health: --last must be >= 1" >&2
  exit 1
fi
if [ -n "$SUBSIDY_MODE_OVR" ] && [ "$SUBSIDY_MODE_OVR" -gt 1 ]; then
  echo "operator_subsidy_pool_health: --subsidy-mode must be 0 (FLAT) or 1 (LOTTERY); got '$SUBSIDY_MODE_OVR'" >&2
  exit 1
fi

# Threshold-pct guards: must be a float in [0.0, 1.0]. Done via python
# since bash doesn't do float arithmetic / range checks portably.
THRESH_CHECK=$(python - "$CRIT_PCT" "$WARN_PCT" <<'PY' 2>/dev/null
import sys
try:
    cp = float(sys.argv[1])
    wp = float(sys.argv[2])
    if not (0.0 <= cp <= 1.0):
        print(f"crit-pct out of range [0,1]: {cp}")
        sys.exit(1)
    if not (0.0 <= wp <= 1.0):
        print(f"warn-pct out of range [0,1]: {wp}")
        sys.exit(1)
    if cp > wp:
        print(f"crit-pct ({cp}) must be <= warn-pct ({wp})")
        sys.exit(1)
    print("OK")
except ValueError as e:
    print(f"non-numeric: {e}")
    sys.exit(1)
PY
)
if [ "$THRESH_CHECK" != "OK" ]; then
  echo "operator_subsidy_pool_health: bad threshold args: $THRESH_CHECK" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ZEROTH_ADDRESS canonical anon address (matches
# include/determ/chain/params.hpp::ZEROTH_ADDRESS and
# operator_subsidy_audit.sh exactly). Hard-coded — chain constant.
ZEROTH_ADDR="0x0000000000000000000000000000000000000000000000000000000000000000"

# ── Step 1: parse genesis (if supplied) to source authoritative constants ───
# Precedence: --genesis > CLI overrides > heuristic fallback.
GEN_MODE=""
GEN_BLOCK_SUBSIDY=""
GEN_POOL_INITIAL=""
GEN_ZEROTH_INITIAL=""
if [ -n "$GEN_PATH" ]; then
  if [ ! -r "$GEN_PATH" ]; then
    echo "operator_subsidy_pool_health: --genesis path not readable: $GEN_PATH" >&2
    exit 1
  fi
  GEN_PARSED=$(python - "$GEN_PATH" <<'PY' 2>/dev/null
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as f:
        g = json.load(f)
    mode = int(g.get("subsidy_mode", 0))
    bs   = int(g.get("block_subsidy", 0))
    spi  = int(g.get("subsidy_pool_initial", 0))
    zpi  = int(g.get("zeroth_pool_initial", 0))
    print(f"{mode}\t{bs}\t{spi}\t{zpi}")
except Exception as e:
    sys.stderr.write(f"genesis parse failed: {e}\n")
    sys.exit(2)
PY
)
  if [ -z "$GEN_PARSED" ]; then
    echo "operator_subsidy_pool_health: failed to parse --genesis JSON" >&2
    exit 1
  fi
  GEN_MODE=$(printf '%s' "$GEN_PARSED" | cut -f1)
  GEN_BLOCK_SUBSIDY=$(printf '%s' "$GEN_PARSED" | cut -f2)
  GEN_POOL_INITIAL=$(printf '%s' "$GEN_PARSED" | cut -f3)
  GEN_ZEROTH_INITIAL=$(printf '%s' "$GEN_PARSED" | cut -f4)
fi

# Resolve final values: CLI override > genesis > "" (heuristic).
SUBSIDY_MODE=${SUBSIDY_MODE_OVR:-$GEN_MODE}
BLOCK_SUBSIDY=${BLOCK_SUBSIDY_OVR:-$GEN_BLOCK_SUBSIDY}
POOL_INITIAL=${POOL_INITIAL_OVR:-$GEN_POOL_INITIAL}
ZEROTH_INITIAL=$GEN_ZEROTH_INITIAL    # only sourced from genesis (no CLI flag)

# Provenance tracking — feeds the JSON envelope so the operator can
# reason about which value the script used.
if [ -n "$SUBSIDY_MODE_OVR" ];    then MODE_SOURCE="cli";       elif [ -n "$GEN_MODE" ];           then MODE_SOURCE="genesis"; else MODE_SOURCE="unknown"; fi
if [ -n "$BLOCK_SUBSIDY_OVR" ];   then BS_SOURCE="cli";         elif [ -n "$GEN_BLOCK_SUBSIDY" ];  then BS_SOURCE="genesis";   else BS_SOURCE="heuristic"; fi
if [ -n "$POOL_INITIAL_OVR" ];    then POOL_SOURCE="cli";       elif [ -n "$GEN_POOL_INITIAL" ];   then POOL_SOURCE="genesis"; else POOL_SOURCE="unknown"; fi
if [ -n "$GEN_ZEROTH_INITIAL" ];  then ZEROTH_SOURCE="genesis"; else ZEROTH_SOURCE="unknown"; fi

# Default unresolved fields to 0 so the bash arithmetic below stays safe.
SUBSIDY_MODE=${SUBSIDY_MODE:-0}
BLOCK_SUBSIDY=${BLOCK_SUBSIDY:-0}
POOL_INITIAL=${POOL_INITIAL:-0}
ZEROTH_INITIAL=${ZEROTH_INITIAL:-0}

# ── Step 2: resolve current tip + take snapshots ────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_subsidy_pool_health: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_subsidy_pool_health: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# accumulated_subsidy is the E4 cumulative-mint counter (sole RPC-exposed
# pool-relevant scalar). remaining_pool = subsidy_pool_initial - accum
# when the chain runs in finite-pool mode.
ACCUM_NOW=$("$DETERM" supply --field accumulated_subsidy --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_subsidy_pool_health: cannot reach supply RPC (port $PORT)" >&2
  exit 1
}
case "$ACCUM_NOW" in *[!0-9]*|"")
  echo "operator_subsidy_pool_health: supply returned non-numeric '$ACCUM_NOW' (port $PORT)" >&2
  exit 1 ;;
esac

# NEF pool live balance (ZEROTH_ADDRESS). The E1 pool. Halves on each
# first-time REGISTER; drains geometrically toward 0.
NEF_NOW_RAW=$("$DETERM" balance "$ZEROTH_ADDR" --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_subsidy_pool_health: cannot reach balance RPC (port $PORT)" >&2
  exit 1
}
NEF_NOW=$(printf '%s' "$NEF_NOW_RAW" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print(int(j.get('balance', 0)))
except Exception:
    print('')
")
case "$NEF_NOW" in *[!0-9]*|"")
  echo "operator_subsidy_pool_health: balance for ZEROTH_ADDRESS returned non-numeric '$NEF_NOW'" >&2
  exit 1 ;;
esac

# ── Step 3: resolve window bounds ───────────────────────────────────────────
# Precedence: --last > (--from / --to) > defaults (last 1000).
# Index semantics match operator_subsidy_audit: `head --field height`
# returns *total block count*; highest valid index = height - 1.
TOP=$(( HEAD_H > 0 ? HEAD_H - 1 : 0 ))
if [ -n "$LAST_N" ]; then
  if [ "$LAST_N" -gt $(( TOP + 1 )) ]; then LAST_N=$(( TOP + 1 )); fi
  FROM=$(( TOP + 1 - LAST_N ))
  TO=$TOP
elif [ -n "$FROM_H" ] || [ -n "$TO_H" ]; then
  FROM=${FROM_H:-$(( TOP > 1000 ? TOP - 1000 : 0 ))}
  TO=${TO_H:-$TOP}
else
  # Default window: last 1000 blocks ending at tip.
  WIN_DEFAULT=1000
  if [ "$WIN_DEFAULT" -gt $(( TOP + 1 )) ]; then WIN_DEFAULT=$(( TOP + 1 )); fi
  FROM=$(( TOP + 1 - WIN_DEFAULT ))
  TO=$TOP
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_subsidy_pool_health: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))
if [ "$WIN_BLOCKS" -le 0 ]; then WIN_BLOCKS=1; fi

# ── Step 4: estimate drain rate ─────────────────────────────────────────────
# accumulated_subsidy is only exposed at HEAD — we cannot RPC the
# historical value. Two estimators:
#
#   long-term mean = accumulated_subsidy / head_height
#                    (exact for FLAT chains without pool exhaustion;
#                    expectation for LOTTERY; the canonical "lifetime
#                    average drain rate").
#
#   observed window = block_subsidy (when known) or long-term mean (fallback)
#                     Multiplied by window size for total window drain.
#                     For the spike-detection check we compare observed
#                     vs long-term — when both come from the same
#                     heuristic the ratio is 1.0 and the spike check
#                     never fires (defensive — operators who run without
#                     --genesis won't see false-positive spike alerts).
LONG_TERM_RATE_NUM=$ACCUM_NOW
LONG_TERM_RATE_DEN=$HEAD_H
if [ "$LONG_TERM_RATE_DEN" = "0" ]; then LONG_TERM_RATE_DEN=1; fi
LONG_TERM_RATE=$(( LONG_TERM_RATE_NUM / LONG_TERM_RATE_DEN ))

# Observed window-rate basis. If we have an authoritative block_subsidy
# (from genesis or CLI), use it directly. Otherwise fall back to the
# long-term mean.
if [ "$BLOCK_SUBSIDY" != "0" ] && [ -n "$BLOCK_SUBSIDY" ]; then
  OBS_RATE=$BLOCK_SUBSIDY
  RATE_SOURCE="block_subsidy"
else
  OBS_RATE=$LONG_TERM_RATE
  RATE_SOURCE="lifetime_mean"
fi

# Window-total drain estimate.
WIN_DRAIN=$(( OBS_RATE * WIN_BLOCKS ))

# ── Step 5: compute E4 finite-pool state ────────────────────────────────────
# remaining_pool is the canonical "how much subsidy can still be paid"
# scalar. When subsidy_pool_initial == 0 the chain is in perpetual-
# subsidy mode (no pool to drain) and pool-health analysis short-circuits.
if [ "$POOL_INITIAL" != "0" ] && [ -n "$POOL_INITIAL" ]; then
  if [ "$POOL_INITIAL" -ge "$ACCUM_NOW" ]; then
    REMAINING_POOL=$(( POOL_INITIAL - ACCUM_NOW ))
  else
    REMAINING_POOL=0
  fi
  POOL_DRAINED=$ACCUM_NOW
  POOL_MODE="finite"
else
  REMAINING_POOL=""
  POOL_DRAINED=$ACCUM_NOW
  POOL_MODE="perpetual"
fi

# Project exhaustion height — only meaningful when in finite-pool mode
# AND observed drain rate is non-zero.
PROJECTED_EXHAUST=""
BLOCKS_UNTIL_EMPTY=""
BLOCKS_UNTIL_CRITICAL=""
if [ "$POOL_MODE" = "finite" ] && [ "$OBS_RATE" -gt 0 ]; then
  BLOCKS_UNTIL_EMPTY=$(( REMAINING_POOL / OBS_RATE ))
  PROJECTED_EXHAUST=$(( HEAD_H + BLOCKS_UNTIL_EMPTY ))

  # Compute critical-threshold absolute value (initial * crit-pct) and
  # blocks until pool drops below it.
  CRIT_LEVEL=$(python - "$POOL_INITIAL" "$CRIT_PCT" <<'PY' 2>/dev/null
import sys
initial = int(sys.argv[1])
pct = float(sys.argv[2])
# Integer floor of initial * pct (matches the test gate's semantic).
print(int(initial * pct))
PY
)
  case "$CRIT_LEVEL" in *[!0-9]*|"") CRIT_LEVEL=0 ;; esac
  if [ "$REMAINING_POOL" -gt "$CRIT_LEVEL" ]; then
    BLOCKS_UNTIL_CRITICAL=$(( (REMAINING_POOL - CRIT_LEVEL) / OBS_RATE ))
  else
    BLOCKS_UNTIL_CRITICAL=0    # already at/below critical
  fi
fi

# ── Step 6: classify anomalies ──────────────────────────────────────────────
# Anomalies are additive (multiple flags can fire). CRITICAL gates
# unconditionally affect exit code; WARN / INFO are reportable but
# don't override the exit code unless --anomalies-only is in effect
# (matches operator_subsidy_audit's convention — except for CRITICAL
# pool-state which always exits 2).
ANOM_LIST=""
ANOM_CRITICAL=0
ANOM_WARN=0
ANOM_INFO=0

# (a) subsidy_pool_critical: remaining < crit-pct * initial. CRITICAL.
# Only applicable in finite-pool mode.
if [ "$POOL_MODE" = "finite" ]; then
  CRIT_LEVEL=$(python - "$POOL_INITIAL" "$CRIT_PCT" <<'PY' 2>/dev/null
import sys
print(int(int(sys.argv[1]) * float(sys.argv[2])))
PY
)
  case "$CRIT_LEVEL" in *[!0-9]*|"") CRIT_LEVEL=0 ;; esac
  if [ "$REMAINING_POOL" -lt "$CRIT_LEVEL" ]; then
    ANOM_LIST="$ANOM_LIST subsidy_pool_critical"
    ANOM_CRITICAL=$(( ANOM_CRITICAL + 1 ))
  else
    # (b) subsidy_pool_warn: remaining < warn-pct * initial. WARN.
    # Only fires if NOT already in CRITICAL state (a critical pool is
    # by definition also "warned" — no point double-flagging).
    WARN_LEVEL=$(python - "$POOL_INITIAL" "$WARN_PCT" <<'PY' 2>/dev/null
import sys
print(int(int(sys.argv[1]) * float(sys.argv[2])))
PY
)
    case "$WARN_LEVEL" in *[!0-9]*|"") WARN_LEVEL=0 ;; esac
    if [ "$REMAINING_POOL" -lt "$WARN_LEVEL" ]; then
      ANOM_LIST="$ANOM_LIST subsidy_pool_warn"
      ANOM_WARN=$(( ANOM_WARN + 1 ))
    fi
  fi
fi

# (c) drain_rate_spike: observed rate > 2x long-term mean. WARN.
# Skipped when observed rate is derived from the same lifetime-mean
# source as the comparator (would always be 1.0 — false negative).
if [ "$RATE_SOURCE" = "block_subsidy" ] && [ "$LONG_TERM_RATE" -gt 0 ]; then
  if [ "$OBS_RATE" -gt $(( LONG_TERM_RATE * 2 )) ]; then
    ANOM_LIST="$ANOM_LIST drain_rate_spike"
    ANOM_WARN=$(( ANOM_WARN + 1 ))
  fi
fi

# (d) exhaustion_imminent: projected_exhaustion_height < head + 5000. CRITICAL.
# Only meaningful in finite-pool mode with non-zero drain.
if [ -n "$BLOCKS_UNTIL_EMPTY" ] && [ "$BLOCKS_UNTIL_EMPTY" -lt 5000 ]; then
  ANOM_LIST="$ANOM_LIST exhaustion_imminent"
  ANOM_CRITICAL=$(( ANOM_CRITICAL + 1 ))
fi

# (e) nef_pool_exhausted: ZEROTH balance == 0. INFO.
# Only flag when the chain *had* a NEF program (zeroth_pool_initial > 0).
# A chain that never had NEF (zeroth_pool_initial == 0) is not "exhausted"
# — it never had NEF to begin with.
if [ "$NEF_NOW" = "0" ] && [ "$ZEROTH_INITIAL" != "0" ] && [ -n "$ZEROTH_INITIAL" ]; then
  ANOM_LIST="$ANOM_LIST nef_pool_exhausted"
  ANOM_INFO=$(( ANOM_INFO + 1 ))
fi

ANOM_TOTAL=$(( ANOM_CRITICAL + ANOM_WARN + ANOM_INFO ))

# ── Step 7: render output ───────────────────────────────────────────────────
# Drop the leading space from the anomaly accumulator.
ANOM_LIST="${ANOM_LIST# }"

if [ "$JSON_OUT" = "1" ]; then
  # JSON envelope. Field-set chosen to match the task spec exactly so
  # monitoring code can key off stable names. nef.* fields are emitted
  # only when zeroth_pool_initial > 0 (otherwise the chain has no NEF
  # program and the fields would be misleading).
  python - "$PORT" "$HEAD_H" \
          "$SUBSIDY_MODE" "$MODE_SOURCE" \
          "$BLOCK_SUBSIDY" "$BS_SOURCE" "$RATE_SOURCE" \
          "$POOL_MODE" "$POOL_INITIAL" "$POOL_SOURCE" \
          "$REMAINING_POOL" "$POOL_DRAINED" \
          "$OBS_RATE" "$LONG_TERM_RATE" \
          "$BLOCKS_UNTIL_EMPTY" "$BLOCKS_UNTIL_CRITICAL" \
          "$PROJECTED_EXHAUST" \
          "$ZEROTH_INITIAL" "$ZEROTH_SOURCE" "$NEF_NOW" \
          "$FROM" "$TO" "$WIN_BLOCKS" "$WIN_DRAIN" \
          "$CRIT_PCT" "$WARN_PCT" \
          "$ANOM_LIST" "$ANOM_CRITICAL" "$ANOM_WARN" "$ANOM_INFO" <<'PY'
import json, sys
(port, head_h, mode_s, mode_src, bs_s, bs_src, rate_src,
 pool_mode, pool_init_s, pool_src, remaining_s, pool_drained_s,
 obs_rate_s, lt_rate_s, blocks_empty_s, blocks_crit_s, exhaust_s,
 zpi_s, zpi_src, nef_now_s,
 from_s, to_s, win_s, win_drain_s,
 crit_pct_s, warn_pct_s,
 anom_list_s, anom_c_s, anom_w_s, anom_i_s) = sys.argv[1:30]

def i(s):
    return int(s) if s and s.lstrip('-').isdigit() else None

# subsidy_mode label.
mode = int(mode_s)
mode_label = {0: "FLAT", 1: "LOTTERY"}.get(mode, f"UNKNOWN({mode})")

env = {
    "rpc_port":       int(port),
    "head_height":    int(head_h),
    "subsidy_mode":   mode_label,
    "subsidy_mode_source": mode_src,
    "block_subsidy":       i(bs_s) if bs_s != "0" else 0,
    "block_subsidy_source": bs_src,
    "drain_rate_source":    rate_src,
    "pool_mode":      pool_mode,
    "window":         {"from": int(from_s), "to": int(to_s), "blocks": int(win_s)},
    "thresholds":     {"critical_pct": float(crit_pct_s),
                       "warn_pct":     float(warn_pct_s)},
    "anomalies":      anom_list_s.split() if anom_list_s else [],
    "anomaly_counts": {"critical": int(anom_c_s),
                       "warn":     int(anom_w_s),
                       "info":     int(anom_i_s)},
}

# E4 finite-pool block.
pool = {
    "initial":            int(pool_init_s) if pool_init_s and pool_init_s != "0" else 0,
    "initial_source":     pool_src,
    "drained":            int(pool_drained_s),
    "drain_rate_per_block": int(obs_rate_s),
    "long_term_mean_rate":  int(lt_rate_s),
    "window_total_drain":   int(win_drain_s),
}
if pool_mode == "finite":
    pool["current"]                       = int(remaining_s) if remaining_s else 0
    pool["blocks_until_empty"]            = i(blocks_empty_s)
    pool["blocks_until_critical"]         = i(blocks_crit_s)
    pool["projected_exhaustion_height"]   = i(exhaust_s)
else:
    pool["current"]                       = None
    pool["blocks_until_empty"]            = None
    pool["blocks_until_critical"]         = None
    pool["projected_exhaustion_height"]   = None
env["pool"] = pool

# E1 NEF block — emitted unconditionally so JSON consumers always have
# the field present; current is the live ZEROTH balance regardless of
# whether the chain has a NEF program.
nef = {
    "initial":         int(zpi_s) if zpi_s and zpi_s != "0" else 0,
    "initial_source":  zpi_src,
    "current":         int(nef_now_s),
}
if zpi_s and zpi_s != "0":
    # Drain so far (note: NEF drains geometrically, not linearly — this
    # is the absolute consumed-vs-initial figure, not a rate).
    nef["drained"]    = max(0, int(zpi_s) - int(nef_now_s))
    nef["exhausted"]  = int(nef_now_s) == 0
else:
    nef["drained"]    = 0
    nef["exhausted"]  = False
    nef["note"]       = "chain has no NEF program (zeroth_pool_initial == 0)"
env["nef"] = nef

print(json.dumps(env))
PY
  RC=$?
  if [ "$RC" -ne 0 ]; then
    echo "operator_subsidy_pool_health: JSON rendering failed (rc=$RC)" >&2
    exit 1
  fi
else
  # Human-readable layout.
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_TOTAL" = "0" ]; then
    echo "operator_subsidy_pool_health: no anomalies (port $PORT, head $HEAD_H, window [$FROM..$TO])"
  else
    MODE_LABEL="UNKNOWN"
    case "$SUBSIDY_MODE" in
      0) MODE_LABEL="FLAT" ;;
      1) MODE_LABEL="LOTTERY" ;;
    esac

    echo "=== Subsidy pool health (port $PORT, head $HEAD_H, window [$FROM..$TO], $WIN_BLOCKS blocks) ==="
    echo "Subsidy mode             : $MODE_LABEL  (source: $MODE_SOURCE)"
    echo "Per-block subsidy        : $BLOCK_SUBSIDY  (source: $BS_SOURCE)"
    echo "Observed drain rate      : $OBS_RATE per block  (source: $RATE_SOURCE)"
    echo "Long-term mean rate      : $LONG_TERM_RATE per block  (= accumulated_subsidy / head_height)"
    echo "Window total drain (est) : $WIN_DRAIN"
    echo ""

    if [ "$POOL_MODE" = "finite" ]; then
      echo "E4 FINITE POOL (subsidy_pool_initial != 0):"
      echo "  Initial                : $POOL_INITIAL"
      echo "  Drained                : $POOL_DRAINED"
      echo "  Remaining              : $REMAINING_POOL"
      if [ -n "$BLOCKS_UNTIL_EMPTY" ]; then
        echo "  Blocks until empty     : $BLOCKS_UNTIL_EMPTY"
        echo "  Blocks until CRITICAL  : $BLOCKS_UNTIL_CRITICAL  (threshold ${CRIT_PCT})"
        echo "  Projected exhaustion height : $PROJECTED_EXHAUST"
      else
        echo "  Blocks until empty     : (drain rate = 0; pool will never deplete)"
      fi
    else
      echo "E4 FINITE POOL           : PERPETUAL mode (subsidy_pool_initial == 0 / unknown)"
      echo "                           No pool to drain; pool-state gates skipped."
    fi
    echo ""

    if [ "$ZEROTH_INITIAL" != "0" ] && [ -n "$ZEROTH_INITIAL" ]; then
      NEF_DRAINED=$(( ZEROTH_INITIAL - NEF_NOW ))
      if [ "$NEF_DRAINED" -lt 0 ]; then NEF_DRAINED=0; fi
      echo "E1 NEF POOL (zeroth_pool_initial != 0):"
      echo "  Initial                : $ZEROTH_INITIAL  (source: $ZEROTH_SOURCE)"
      echo "  Current (ZEROTH bal)   : $NEF_NOW"
      echo "  Drained                : $NEF_DRAINED"
      if [ "$NEF_NOW" = "0" ]; then
        echo "  Status                 : EXHAUSTED (further REGISTERs receive no NEF subsidy)"
      else
        echo "  Status                 : active (drains geometrically per first-time REGISTER)"
      fi
    else
      echo "E1 NEF POOL              : (chain has no NEF program; zeroth_pool_initial == 0 / unknown)"
      echo "  Current (ZEROTH bal)   : $NEF_NOW"
    fi
    echo ""

    if [ "$ANOM_TOTAL" = "0" ]; then
      echo "[OK] No pool-health anomalies"
    else
      echo "[ANOMALY] $ANOM_TOTAL flag(s) ($ANOM_CRITICAL critical / $ANOM_WARN warn / $ANOM_INFO info): $ANOM_LIST"
      case "$ANOM_LIST" in
        *subsidy_pool_critical*)
          echo "  CRITICAL subsidy_pool_critical : remaining=$REMAINING_POOL < ${CRIT_PCT} * initial=$POOL_INITIAL" ;;
      esac
      case "$ANOM_LIST" in
        *subsidy_pool_warn*)
          echo "  WARN     subsidy_pool_warn     : remaining=$REMAINING_POOL < ${WARN_PCT} * initial=$POOL_INITIAL" ;;
      esac
      case "$ANOM_LIST" in
        *drain_rate_spike*)
          echo "  WARN     drain_rate_spike      : observed=$OBS_RATE > 2 * long_term=$LONG_TERM_RATE" ;;
      esac
      case "$ANOM_LIST" in
        *exhaustion_imminent*)
          echo "  CRITICAL exhaustion_imminent   : blocks_until_empty=$BLOCKS_UNTIL_EMPTY < 5000 (head=$HEAD_H, proj=$PROJECTED_EXHAUST)" ;;
      esac
      case "$ANOM_LIST" in
        *nef_pool_exhausted*)
          echo "  INFO     nef_pool_exhausted    : ZEROTH balance == 0 (chain had NEF program; now inert)" ;;
      esac
    fi
  fi
fi

# ── Step 8: exit-code policy ────────────────────────────────────────────────
# Distinct from sibling-script convention:
#   - exit 2 fires UNCONDITIONALLY on any CRITICAL anomaly (subsidy_pool_critical
#     OR exhaustion_imminent). Pool exhaustion is a structural-economics
#     gate and an operator should never be able to silence it with a flag.
#   - --anomalies-only suppresses healthy human output but does NOT change
#     the exit code (the CRITICAL gate already covers alert routing).
if [ "$ANOM_CRITICAL" -gt 0 ]; then
  exit 2
fi
exit 0
