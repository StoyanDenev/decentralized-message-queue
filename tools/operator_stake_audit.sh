#!/usr/bin/env bash
# operator_stake_audit.sh — Comprehensive stake-position audit across the
# active validator set on a running determ daemon.
#
# Composes three read-only CLIs (no new RPC needed; safe against any
# running daemon):
#   - `determ head    --json --rpc-port P` → current_height
#   - `determ stakes  --json --rpc-port P` → array of {rank, domain, stake,
#                                              active_from, region, ed_pub}
#   - `determ stake_info <domain> --rpc-port P` (per entry, JSON dumped
#     verbatim) → {domain, locked, unlock_height}
#
# The user-side spec sketched `determ stakes --json` as returning
# {stakes:[{domain,locked,unlock_height},...], top_n, total_count}; the
# actual surface returns a flat JSON array sourced from the `validators`
# RPC with no unlock_height column. This script therefore loops one
# stake_info call per entry to recover unlock_height; cost is O(N)
# RPC calls but each is lock-free and ≤1ms per call.
#
# Per-entry status classification:
#   locked            unlock_height == UINT64_MAX (still registered, no
#                     deregister submitted) — healthy, normal validator
#   unlocking-pending unlock_height finite, > current_height — DEREGISTER
#                     observed; waiting out the unstake_delay before refund
#   unlocked-pending  unlock_height finite, ≤ current_height (anomaly:
#                     entry should have been UNSTAKE'd by now)
#
# Anomaly flags:
#   unlock_height_past   status == unlocked-pending (UNSTAKE delay /
#                        missed unstake op — operator should investigate)
#   below_threshold      locked < --threshold N (if --threshold provided);
#                        flags near-minimum stakers + zero-stake entries
#   zero_locked          locked == 0 but entry still present (post-slash
#                        zombie; pre-genesis registrant in DOMAIN_INCLUSION
#                        mode also lands here — operator-interpreted)
#
# Args:
#   [--rpc-port N]        RPC port to query (default: 7778)
#   [--json]              Emit structured JSON instead of human table
#   [--anomalies-only]    Suppress healthy entries; only print flagged ones
#   [--threshold N]       Flag entries with locked < N as below_threshold
#   [-h|--help]           Show this help
#
# Exit codes:
#   0   No anomalies detected (or --anomalies-only not set: informational)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only mode AND ≥1 anomaly detected (operator alert gate;
#       does NOT fire in default / informational mode)
set -u

usage() {
  cat <<'EOF'
Usage: operator_stake_audit.sh [--rpc-port N] [--json] [--anomalies-only]
                                [--threshold N]

Comprehensive stake-position audit. Cross-references the validator set
(`determ stakes`) with per-entry lock state (`determ stake_info`) and
chain head height (`determ head`), and classifies each entry as
locked / unlocking-pending / unlocked-pending plus any anomaly flags.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON: {stakers:[{domain, locked,
                      unlock_height, status, flags:[...]}, ...],
                      summary:{total_stakers, total_locked, locked_count,
                      unlocking_count, anomaly_count}}
  --anomalies-only    Print ONLY entries with ≥1 anomaly flag; in this
                      mode exit 2 if anomalies were found
  --threshold N       Flag entries with locked < N as below_threshold
  -h, --help          Show this help

Status classification:
  locked              unlock_height == UINT64_MAX (normal validator)
  unlocking-pending   unlock_height > current_height (DEREGISTER, waiting)
  unlocked-pending    unlock_height ≤ current_height (anomaly: missed UNSTAKE)

Exit codes:
  0   No anomalies (or default informational mode)
  1   RPC error / bad args
  2   --anomalies-only set AND ≥1 anomaly found
EOF
}

PORT=7778
JSON=0
ANOM_ONLY=0
THRESHOLD=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --rpc-port) PORT="$2"; shift 2 ;;
    --json) JSON=1; shift ;;
    --anomalies-only) ANOM_ONLY=1; shift ;;
    --threshold) THRESHOLD="$2"; shift 2 ;;
    *) echo "operator_stake_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied counts.
case "$PORT" in *[!0-9]*|"") echo "operator_stake_audit: --rpc-port must be a positive integer (got '$PORT')" >&2; exit 1 ;; esac
if [ -n "$THRESHOLD" ]; then
  case "$THRESHOLD" in *[!0-9]*|"") echo "operator_stake_audit: --threshold must be a non-negative integer (got '$THRESHOLD')" >&2; exit 1 ;; esac
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# UINT64_MAX literal — used to detect "still locked, no DEREGISTER yet".
# Snapshot/JSON serialization echoes the C++ UINT64_MAX as 18446744073709551615.
UINT64_MAX=18446744073709551615

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: current chain head ─────────────────────────────────────────────────
HEAD_OUT=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_stake_audit: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
  exit 1
}
if [ "$HAVE_JQ" = "1" ]; then
  CURRENT_HEIGHT=$(printf '%s' "$HEAD_OUT" | jq -r '.height')
else
  CURRENT_HEIGHT=$(printf '%s' "$HEAD_OUT" | grep -o '"height":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
fi
case "$CURRENT_HEIGHT" in *[!0-9]*|"") echo "operator_stake_audit: malformed head JSON (height not numeric: '$CURRENT_HEIGHT')" >&2; exit 1 ;; esac

# ── Step 2: stakes list (validators sorted by stake desc) ─────────────────────
STAKES_OUT=$("$DETERM" stakes --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_stake_audit: RPC error from \`determ stakes\` (port $PORT)" >&2
  exit 1
}

# Parse domain list (the only field we strictly need from stakes; locked
# is re-fetched per-entry via stake_info to get an internally-consistent
# {locked, unlock_height} pair from one snapshot of one shared_ptr load).
if [ "$HAVE_JQ" = "1" ]; then
  DOMAINS=$(printf '%s' "$STAKES_OUT" | jq -r '.[].domain' 2>/dev/null) || {
    echo "operator_stake_audit: malformed stakes JSON" >&2; exit 1;
  }
else
  DOMAINS=$(printf '%s' "$STAKES_OUT" | grep -o '"domain":"[^"]*"' | sed 's/"domain":"\([^"]*\)"/\1/')
fi

# ── Step 3: per-entry stake_info loop + classification ────────────────────────
# Accumulators emitted to a tmp file so the subshell-piped loop's state
# survives. Each line: domain<TAB>locked<TAB>unlock_height<TAB>status<TAB>flags(comma-sep or '-')
TMP_TABLE=$(mktemp)
TMP_SUMMARY=$(mktemp)
trap 'rm -f "$TMP_TABLE" "$TMP_SUMMARY"' EXIT

TOTAL_STAKERS=0
TOTAL_LOCKED=0
LOCKED_COUNT=0
UNLOCKING_COUNT=0
ANOMALY_COUNT=0

if [ -z "$DOMAINS" ]; then
  : # nothing to iterate; counters all stay at zero
else
  # Use while-read to preserve the outer-shell accumulators.
  while IFS= read -r DOM; do
    [ -z "$DOM" ] && continue
    SI=$("$DETERM" stake_info "$DOM" --rpc-port "$PORT" 2>/dev/null) || {
      echo "operator_stake_audit: RPC error from \`determ stake_info $DOM\` (port $PORT)" >&2
      exit 1
    }
    if [ "$HAVE_JQ" = "1" ]; then
      LOCKED=$(printf '%s' "$SI" | jq -r '.locked')
      UH=$(printf '%s' "$SI" | jq -r '.unlock_height')
    else
      LOCKED=$(printf '%s' "$SI" | grep -o '"locked":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
      UH=$(printf '%s' "$SI" | grep -o '"unlock_height":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
    fi
    case "$LOCKED" in *[!0-9]*|"") echo "operator_stake_audit: malformed stake_info for $DOM (locked='$LOCKED')" >&2; exit 1 ;; esac
    case "$UH"     in *[!0-9]*|"") echo "operator_stake_audit: malformed stake_info for $DOM (unlock_height='$UH')" >&2; exit 1 ;; esac

    # Status classification.
    if [ "$UH" = "$UINT64_MAX" ]; then
      STATUS="locked"
    else
      # bash int compare safe up to 2^63; UH < UINT64_MAX guarantees it
      # fits if we got here.
      if [ "$UH" -gt "$CURRENT_HEIGHT" ]; then
        STATUS="unlocking-pending"
      else
        STATUS="unlocked-pending"
      fi
    fi

    # Anomaly flags.
    FLAGS=""
    add_flag() { if [ -z "$FLAGS" ]; then FLAGS="$1"; else FLAGS="$FLAGS,$1"; fi; }
    [ "$STATUS" = "unlocked-pending" ]      && add_flag "unlock_height_past"
    [ "$LOCKED" = "0" ]                     && add_flag "zero_locked"
    if [ -n "$THRESHOLD" ] && [ "$LOCKED" -lt "$THRESHOLD" ]; then
      add_flag "below_threshold"
    fi

    # Update accumulators.
    TOTAL_STAKERS=$((TOTAL_STAKERS + 1))
    TOTAL_LOCKED=$((TOTAL_LOCKED + LOCKED))
    case "$STATUS" in
      locked)            LOCKED_COUNT=$((LOCKED_COUNT + 1)) ;;
      unlocking-pending) UNLOCKING_COUNT=$((UNLOCKING_COUNT + 1)) ;;
    esac
    [ -n "$FLAGS" ] && ANOMALY_COUNT=$((ANOMALY_COUNT + 1))

    # Skip healthy rows in --anomalies-only mode.
    if [ "$ANOM_ONLY" = "1" ] && [ -z "$FLAGS" ]; then
      continue
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$DOM" "$LOCKED" "$UH" "$STATUS" "${FLAGS:--}" >>"$TMP_TABLE"
  done <<EOF
$DOMAINS
EOF
fi

# ── Step 4: emit output ──────────────────────────────────────────────────────
if [ "$JSON" = "1" ]; then
  # Emit structured JSON. Build the stakers array line-by-line.
  printf '{"stakers":['
  FIRST=1
  if [ -s "$TMP_TABLE" ]; then
    while IFS=$'\t' read -r D L U S F; do
      [ "$FIRST" = "1" ] || printf ','
      FIRST=0
      # Flags column: '-' sentinel → empty array; else split on comma.
      if [ "$F" = "-" ]; then
        FJSON='[]'
      else
        FJSON=$(printf '%s' "$F" | awk -F, '{printf "["; for(i=1;i<=NF;i++){if(i>1)printf ","; printf "\"%s\"",$i}; printf "]"}')
      fi
      printf '{"domain":"%s","locked":%s,"unlock_height":%s,"status":"%s","flags":%s}' "$D" "$L" "$U" "$S" "$FJSON"
    done <"$TMP_TABLE"
  fi
  printf '],"summary":{"total_stakers":%s,"total_locked":%s,"locked_count":%s,"unlocking_count":%s,"anomaly_count":%s,"current_height":%s,"rpc_port":%s}}\n' \
    "$TOTAL_STAKERS" "$TOTAL_LOCKED" "$LOCKED_COUNT" "$UNLOCKING_COUNT" "$ANOMALY_COUNT" "$CURRENT_HEIGHT" "$PORT"
else
  # Human-readable table + summary footer.
  echo "operator_stake_audit (port $PORT, height $CURRENT_HEIGHT):"
  if [ "$ANOM_ONLY" = "1" ]; then
    echo "  mode: anomalies-only"
  fi
  if [ -n "$THRESHOLD" ]; then
    echo "  threshold: locked < $THRESHOLD flagged as below_threshold"
  fi
  if [ -s "$TMP_TABLE" ]; then
    printf '\n  %-24s %-14s %-22s %-20s %s\n' "DOMAIN" "LOCKED" "UNLOCK_HEIGHT" "STATUS" "FLAGS"
    printf '  %-24s %-14s %-22s %-20s %s\n'   "------" "------" "-------------" "------" "-----"
    # Sort table by locked descending, ties by domain asc, for stable
    # output. Use sort -k2 -n -r (numeric desc on locked), with -t TAB.
    sort -t $'\t' -k2,2nr -k1,1 "$TMP_TABLE" | while IFS=$'\t' read -r D L U S F; do
      # Render UINT64_MAX as a recognisable token in the human view.
      UH_DISPLAY="$U"
      [ "$U" = "$UINT64_MAX" ] && UH_DISPLAY="(never / UINT64_MAX)"
      printf '  %-24s %-14s %-22s %-20s %s\n' "$D" "$L" "$UH_DISPLAY" "$S" "$F"
    done
  else
    if [ "$ANOM_ONLY" = "1" ] && [ "$TOTAL_STAKERS" -gt 0 ]; then
      echo "  (no anomalies)"
    elif [ "$TOTAL_STAKERS" = "0" ]; then
      echo "  (no validators with stake)"
    fi
  fi
  echo
  echo "  Summary:"
  echo "    total_stakers   : $TOTAL_STAKERS"
  echo "    total_locked    : $TOTAL_LOCKED"
  echo "    locked_count    : $LOCKED_COUNT"
  echo "    unlocking_count : $UNLOCKING_COUNT"
  echo "    anomaly_count   : $ANOMALY_COUNT"
fi

# ── Step 5: exit code policy ─────────────────────────────────────────────────
# Design choice: exit 2 ONLY fires in --anomalies-only mode. Default
# mode is informational and always exits 0 (provided RPC layer was
# healthy); operator alerting is opt-in via --anomalies-only so that
# scheduled cron audits can choose between "report-only" and "page on
# anomaly" via the same script.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOMALY_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
