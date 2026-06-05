#!/usr/bin/env bash
# operator_stake_activation_audit.sh — REGISTER-side activation-lifecycle
# audit across the validator set on a running determ daemon. Read-only RPC
# composition; safe against a producing chain. Single query then exit
# (no --watch).
#
# Determ's validator-ENTRY pipeline (the mirror image of the UNSTAKE /
# DEREGISTER exit pipeline) is one randomized step:
#
#   REGISTER tx (TxType=1) applied at height H sets, per
#   src/chain/chain.cpp:800-802:
#
#       RegistryEntry.registered_at = H
#       RegistryEntry.active_from   = H + derive_delay(cumulative_rand, tx.hash)
#       RegistryEntry.inactive_from = UINT64_MAX
#
#   where derive_delay returns 1 + (seed % REGISTRATION_DELAY_WINDOW)
#   (src/chain/chain.cpp:42-47), so the per-validator ACTIVATION LATENCY
#
#       latency = active_from - registered_at  ∈  [1, REGISTRATION_DELAY_WINDOW]
#
#   with REGISTRATION_DELAY_WINDOW = 10 (include/determ/node/registry.hpp:15).
#   The randomized delay is what stops an attacker from predicting (and
#   front-running) exactly which block their freshly-registered validator
#   becomes committee-eligible in. A validator is committee-eligible only
#   once head_height >= active_from; before that it is REGISTERED-BUT-DORMANT.
#
# THE OPERATOR QUESTION THIS ANSWERS
#   "Which of my registered validators are still in the activation-delay
#    window (registered but not yet committee-eligible), how many blocks
#    until each goes live, and does every entry's activation latency sit
#    inside the protocol's [1, REGISTRATION_DELAY_WINDOW] envelope?"
#
#   Concretely, per registered validator domain D the script reads the
#   registry sub-block (registered_at, active_from) via
#   `determ show-account D --json` plus locked stake via
#   `determ stake_info D`, and classifies:
#
#     pending-activation  active_from >  current_height — registered, in
#                         the delay window, NOT yet committee-eligible.
#                         Reports blocks_to_active = active_from - height.
#     active              active_from <= current_height AND
#                         inactive_from == UINT64_MAX — live validator.
#     exiting             inactive_from != UINT64_MAX — a DEREGISTER has
#                         landed; the entry is on the exit pipeline
#                         (covered in detail by the exit-side scripts;
#                         surfaced here only so the entry-side census is
#                         exhaustive).
#
#   Activation-latency reconciliation (the soundness check):
#
#       latency = active_from - registered_at
#
#   The healthy envelope is 1 <= latency <= REGISTRATION_DELAY_WINDOW.
#   A latency of 0 (active_from <= registered_at), or a latency above the
#   window ceiling, means the entry was not produced by the standard
#   apply path (genesis-injected validators land here legitimately —
#   their RegistryEntry is seeded directly with registered_at == active_from
#   == 0, NOT via derive_delay — so a latency-0 row at height 0 / genesis
#   domains is expected and is reported as `genesis_seeded`, not an
#   anomaly).
#
# Sibling-script positioning (this script is the ENTRY-side counterpart to
# the existing EXIT-side suite — none of them audit registered_at →
# active_from):
#
#   operator_stake_audit.sh           Set-wide locked/unlock_height
#                                     classification (the EXIT side:
#                                     locked / unlocking-pending /
#                                     unlocked-pending). Does not read
#                                     registered_at / active_from.
#
#   operator_unstake_timeline.sh      Per-domain pending-UNSTAKE ETA
#                                     (EXIT side, single domain).
#
#   operator_validator_unstake_pipeline.sh
#                                     Cross-block DEREGISTER→UNSTAKE
#                                     pairing (EXIT side, window walk).
#
#   operator_nef_drain_audit.sh       Reconciles the NEF geometric pool
#                                     drain against REGISTER COUNT — cares
#                                     about how many REGISTERs happened,
#                                     not about each entry's activation
#                                     latency or pending-activation state.
#
#   operator_governance_history.sh    Counts REGISTER events over a window;
#                                     no per-validator activation-latency
#                                     computation, no pending-activation
#                                     classification.
#
#   operator_stake_activation_audit.sh (THIS)
#                                     The ENTRY-side census: who is
#                                     registered-but-dormant, blocks until
#                                     each goes committee-eligible, and a
#                                     soundness check that every activation
#                                     latency sits inside [1,
#                                     REGISTRATION_DELAY_WINDOW].
#
# Cost is O(N) lock-free RPC calls (one show-account + one stake_info per
# validator surfaced by `determ stakes`); each call is ≤1ms and acquires
# no state_mutex_.
#
# Args:
#   [--rpc-port N]        RPC port to query (default: 7778)
#   [--json]              Emit structured JSON instead of the human table
#   [--pending-only]      Print ONLY pending-activation entries (the
#                         registered-but-dormant set); in this mode the
#                         exit code reflects whether any latency anomaly
#                         was found among them
#   [--delay-window N]    Override the activation-latency ceiling used for
#                         the soundness check (default 10 =
#                         REGISTRATION_DELAY_WINDOW). Use this if the chain
#                         was built with a non-default constant.
#   [-h|--help]           Show this help
#
# Exit codes:
#   0   No latency anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --pending-only set AND >=1 latency anomaly detected (operator
#       alert gate; does NOT fire in default / informational mode)
set -u

usage() {
  cat <<'EOF'
Usage: operator_stake_activation_audit.sh [--rpc-port N] [--json]
                                          [--pending-only] [--delay-window N]

REGISTER-side activation-lifecycle audit. Enumerates validators via
`determ stakes --json`, reads each registry sub-block (registered_at,
active_from, inactive_from) via `determ show-account <domain> --json` plus
locked stake via `determ stake_info <domain>`, and against the chain head
classifies each as pending-activation / active / exiting, reports
blocks_to_active for the dormant set, and reconciles every entry's
activation latency (active_from - registered_at) against the protocol's
[1, REGISTRATION_DELAY_WINDOW] envelope.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON: {validators:[{domain, locked,
                      registered_at, active_from, inactive_from, latency,
                      status, blocks_to_active, flags:[...]}, ...],
                      summary:{total, pending_count, active_count,
                      exiting_count, genesis_seeded_count, anomaly_count,
                      current_height, delay_window, rpc_port}}
  --pending-only      Print ONLY pending-activation entries; in this mode
                      exit 2 if any latency anomaly was found
  --delay-window N    Override the activation-latency ceiling for the
                      soundness check (default 10 = REGISTRATION_DELAY_WINDOW)
  -h, --help          Show this help

Status classification:
  pending-activation  active_from > current_height (registered, dormant)
  active              active_from <= current_height, inactive_from == MAX
  exiting             inactive_from != UINT64_MAX (DEREGISTER landed)

Latency anomaly flags:
  latency_zero        latency == 0 and NOT a genesis-seeded entry
                      (registered_at == active_from at a non-genesis height)
  latency_overshoot   latency > --delay-window (above the randomized ceiling)
  genesis_seeded      registered_at == active_from == 0 (INFO, not anomaly)

Exit codes:
  0   No latency anomalies (or default informational mode)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   --pending-only set AND >=1 latency anomaly found
EOF
}

PORT=7778
JSON=0
PENDING_ONLY=0
DELAY_WINDOW=10
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --rpc-port) PORT="${2:-}"; shift 2 ;;
    --json) JSON=1; shift ;;
    --pending-only) PENDING_ONLY=1; shift ;;
    --delay-window) DELAY_WINDOW="${2:-}"; shift 2 ;;
    *) echo "operator_stake_activation_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards on user-supplied values.
case "$PORT" in *[!0-9]*|"") echo "operator_stake_activation_audit: --rpc-port must be a positive integer (got '$PORT')" >&2; exit 1 ;; esac
case "$DELAY_WINDOW" in *[!0-9]*|"") echo "operator_stake_activation_audit: --delay-window must be a positive integer (got '$DELAY_WINDOW')" >&2; exit 1 ;; esac
if [ "$DELAY_WINDOW" -lt 1 ]; then
  echo "operator_stake_activation_audit: --delay-window must be >= 1 (got '$DELAY_WINDOW')" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# UINT64_MAX literal — RegistryEntry.inactive_from == UINT64_MAX means the
# entry has NOT been deregistered (so it is either pending-activation or
# active). The JSON serializer echoes the C++ UINT64_MAX as its decimal form.
UINT64_MAX=18446744073709551615

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: current chain head ─────────────────────────────────────────────────
HEAD_OUT=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_stake_activation_audit: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
  exit 1
}
if [ "$HAVE_JQ" = "1" ]; then
  CURRENT_HEIGHT=$(printf '%s' "$HEAD_OUT" | jq -r '.height')
else
  CURRENT_HEIGHT=$(printf '%s' "$HEAD_OUT" | grep -o '"height":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
fi
case "$CURRENT_HEIGHT" in *[!0-9]*|"") echo "operator_stake_activation_audit: malformed head JSON (height not numeric: '$CURRENT_HEIGHT')" >&2; exit 1 ;; esac

# ── Step 2: validator set ──────────────────────────────────────────────────────
STAKES_OUT=$("$DETERM" stakes --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_stake_activation_audit: RPC error from \`determ stakes\` (port $PORT)" >&2
  exit 1
}
if [ "$HAVE_JQ" = "1" ]; then
  DOMAINS=$(printf '%s' "$STAKES_OUT" | jq -r '.[].domain' 2>/dev/null) || {
    echo "operator_stake_activation_audit: malformed stakes JSON" >&2; exit 1;
  }
else
  DOMAINS=$(printf '%s' "$STAKES_OUT" | grep -o '"domain":"[^"]*"' | sed 's/"domain":"\([^"]*\)"/\1/')
fi

# ── Step 3: per-entry registry pull + classification ──────────────────────────
# Each table line: domain<TAB>locked<TAB>registered_at<TAB>active_from<TAB>inactive_from<TAB>latency<TAB>blocks_to_active<TAB>status<TAB>flags(comma-sep or '-')
TMP_TABLE=$(mktemp)
trap 'rm -f "$TMP_TABLE"' EXIT

TOTAL=0
PENDING_COUNT=0
ACTIVE_COUNT=0
EXITING_COUNT=0
GENESIS_COUNT=0
ANOMALY_COUNT=0

if [ -z "$DOMAINS" ]; then
  : # nothing to iterate; counters all stay at zero
else
  while IFS= read -r DOM; do
    [ -z "$DOM" ] && continue

    AC=$("$DETERM" show-account "$DOM" --json --rpc-port "$PORT" 2>/dev/null) || {
      echo "operator_stake_activation_audit: RPC error from \`determ show-account $DOM\` (port $PORT)" >&2
      exit 1
    }
    SI=$("$DETERM" stake_info "$DOM" --rpc-port "$PORT" 2>/dev/null) || {
      echo "operator_stake_activation_audit: RPC error from \`determ stake_info $DOM\` (port $PORT)" >&2
      exit 1
    }

    # Extract the registry sub-block fields + locked stake. A validator
    # surfaced by `stakes` may carry a null registry only in the degenerate
    # genesis-DOMAIN_INCLUSION corner; treat absent fields as 0 / MAX.
    if [ "$HAVE_JQ" = "1" ]; then
      REG_AT=$(printf '%s' "$AC" | jq -r '(.registry.registered_at) // 0')
      ACT_FROM=$(printf '%s' "$AC" | jq -r '(.registry.active_from) // 0')
      INACT_FROM=$(printf '%s' "$AC" | jq -r "(.registry.inactive_from) // $UINT64_MAX")
      HAS_REG=$(printf '%s' "$AC" | jq -r 'if (.registry == null) then "0" else "1" end')
      LOCKED=$(printf '%s' "$SI" | jq -r '.locked')
    else
      # Without jq, parse the registry sub-object via flat grep. The
      # registry block emits registered_at/active_from/inactive_from in
      # that order inside "registry":{...}; the simple greps pick the
      # first occurrence of each key which is unambiguous in this shape.
      if printf '%s' "$AC" | grep -q '"registry":null'; then
        HAS_REG=0; REG_AT=0; ACT_FROM=0; INACT_FROM=$UINT64_MAX
      else
        HAS_REG=1
        REG_AT=$(printf '%s' "$AC" | grep -o '"registered_at":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
        ACT_FROM=$(printf '%s' "$AC" | grep -o '"active_from":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
        INACT_FROM=$(printf '%s' "$AC" | grep -o '"inactive_from":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
        [ -z "$REG_AT" ]     && REG_AT=0
        [ -z "$ACT_FROM" ]   && ACT_FROM=0
        [ -z "$INACT_FROM" ] && INACT_FROM=$UINT64_MAX
      fi
      LOCKED=$(printf '%s' "$SI" | grep -o '"locked":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
    fi

    # Numeric guards.
    case "$REG_AT"     in *[!0-9]*|"") echo "operator_stake_activation_audit: malformed registered_at for $DOM ('$REG_AT')" >&2; exit 1 ;; esac
    case "$ACT_FROM"   in *[!0-9]*|"") echo "operator_stake_activation_audit: malformed active_from for $DOM ('$ACT_FROM')" >&2; exit 1 ;; esac
    case "$INACT_FROM" in *[!0-9]*|"") echo "operator_stake_activation_audit: malformed inactive_from for $DOM ('$INACT_FROM')" >&2; exit 1 ;; esac
    case "$LOCKED"     in *[!0-9]*|"") echo "operator_stake_activation_audit: malformed stake_info for $DOM (locked='$LOCKED')" >&2; exit 1 ;; esac

    # A validator in the stakes RPC with a null registry is the degenerate
    # genesis-stake-without-registrant corner. Surface it but skip the
    # latency math (no registry sub-block to reconcile).
    if [ "$HAS_REG" = "0" ]; then
      STATUS="no-registry"
      LATENCY="-"
      BTA="-"
      FLAGS="-"
      TOTAL=$((TOTAL + 1))
      if [ "$PENDING_ONLY" = "1" ]; then
        continue   # not pending-activation; suppressed in pending-only mode
      fi
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$DOM" "$LOCKED" "$REG_AT" "$ACT_FROM" "$INACT_FROM" "$LATENCY" "$BTA" "$STATUS" "$FLAGS" >>"$TMP_TABLE"
      continue
    fi

    # Status classification (exit-side check first: a deregister wins).
    if [ "$INACT_FROM" != "$UINT64_MAX" ]; then
      STATUS="exiting"
    elif [ "$ACT_FROM" -gt "$CURRENT_HEIGHT" ]; then
      STATUS="pending-activation"
    else
      STATUS="active"
    fi

    # Blocks-to-active (only meaningful for pending-activation).
    if [ "$STATUS" = "pending-activation" ]; then
      BTA=$((ACT_FROM - CURRENT_HEIGHT))
    else
      BTA=0
    fi

    # Activation latency + flags.
    # latency = active_from - registered_at, guarded against underflow
    # (active_from < registered_at would mean an out-of-order entry; we
    # report latency 0 + the latency_zero anomaly in that case).
    FLAGS=""
    add_flag() { if [ -z "$FLAGS" ]; then FLAGS="$1"; else FLAGS="$FLAGS,$1"; fi; }

    if [ "$ACT_FROM" -ge "$REG_AT" ]; then
      LATENCY=$((ACT_FROM - REG_AT))
    else
      LATENCY=0
    fi

    if [ "$REG_AT" = "0" ] && [ "$ACT_FROM" = "0" ]; then
      # Genesis-seeded validator: registered_at == active_from == 0,
      # injected directly (not via derive_delay). INFO, not an anomaly.
      add_flag "genesis_seeded"
      GENESIS_COUNT=$((GENESIS_COUNT + 1))
    else
      if [ "$LATENCY" -eq 0 ]; then
        add_flag "latency_zero"
      elif [ "$LATENCY" -gt "$DELAY_WINDOW" ]; then
        add_flag "latency_overshoot"
      fi
    fi

    # Update accumulators.
    TOTAL=$((TOTAL + 1))
    case "$STATUS" in
      pending-activation) PENDING_COUNT=$((PENDING_COUNT + 1)) ;;
      active)             ACTIVE_COUNT=$((ACTIVE_COUNT + 1)) ;;
      exiting)            EXITING_COUNT=$((EXITING_COUNT + 1)) ;;
    esac
    # Anomaly = a real latency violation (genesis_seeded alone is INFO).
    case "$FLAGS" in
      *latency_zero*|*latency_overshoot*) ANOMALY_COUNT=$((ANOMALY_COUNT + 1)) ;;
    esac

    # In --pending-only mode, suppress everything but pending-activation rows.
    if [ "$PENDING_ONLY" = "1" ] && [ "$STATUS" != "pending-activation" ]; then
      continue
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$DOM" "$LOCKED" "$REG_AT" "$ACT_FROM" "$INACT_FROM" "$LATENCY" "$BTA" "$STATUS" "${FLAGS:--}" >>"$TMP_TABLE"
  done <<EOF
$DOMAINS
EOF
fi

# ── Step 4: emit output ──────────────────────────────────────────────────────
if [ "$JSON" = "1" ]; then
  printf '{"validators":['
  FIRST=1
  if [ -s "$TMP_TABLE" ]; then
    while IFS=$'\t' read -r D L RA AF IF LAT BTA S F; do
      [ "$FIRST" = "1" ] || printf ','
      FIRST=0
      if [ "$F" = "-" ]; then
        FJSON='[]'
      else
        FJSON=$(printf '%s' "$F" | awk -F, '{printf "["; for(i=1;i<=NF;i++){if(i>1)printf ","; printf "\"%s\"",$i}; printf "]"}')
      fi
      # latency / blocks_to_active are '-' for no-registry rows; emit null then.
      LAT_J="$LAT"; [ "$LAT" = "-" ] && LAT_J="null"
      BTA_J="$BTA"; [ "$BTA" = "-" ] && BTA_J="null"
      printf '{"domain":"%s","locked":%s,"registered_at":%s,"active_from":%s,"inactive_from":%s,"latency":%s,"blocks_to_active":%s,"status":"%s","flags":%s}' \
        "$D" "$L" "$RA" "$AF" "$IF" "$LAT_J" "$BTA_J" "$S" "$FJSON"
    done <"$TMP_TABLE"
  fi
  printf '],"summary":{"total":%s,"pending_count":%s,"active_count":%s,"exiting_count":%s,"genesis_seeded_count":%s,"anomaly_count":%s,"current_height":%s,"delay_window":%s,"rpc_port":%s}}\n' \
    "$TOTAL" "$PENDING_COUNT" "$ACTIVE_COUNT" "$EXITING_COUNT" "$GENESIS_COUNT" "$ANOMALY_COUNT" "$CURRENT_HEIGHT" "$DELAY_WINDOW" "$PORT"
else
  echo "operator_stake_activation_audit (port $PORT, height $CURRENT_HEIGHT, delay_window $DELAY_WINDOW):"
  if [ "$PENDING_ONLY" = "1" ]; then
    echo "  mode: pending-activation-only"
  fi
  if [ -s "$TMP_TABLE" ]; then
    printf '\n  %-24s %-12s %-12s %-12s %-9s %-8s %-20s %s\n' "DOMAIN" "LOCKED" "REGISTERED" "ACTIVE_FROM" "LATENCY" "TO_LIVE" "STATUS" "FLAGS"
    printf '  %-24s %-12s %-12s %-12s %-9s %-8s %-20s %s\n'   "------" "------" "----------" "-----------" "-------" "-------" "------" "-----"
    # Sort: pending-activation first (most imminent = smallest blocks_to_active
    # at the top), then the rest by domain. Sort key: status-rank then
    # blocks_to_active asc then domain asc. Use a synthetic prefix.
    while IFS=$'\t' read -r D L RA AF IF LAT BTA S F; do
      case "$S" in
        pending-activation) RANK=0 ;;
        active)             RANK=1 ;;
        exiting)            RANK=2 ;;
        *)                  RANK=3 ;;
      esac
      # blocks_to_active may be '-' (no-registry); coerce to a big number
      # so those sink to the bottom of their rank bucket.
      BTA_SORT="$BTA"; [ "$BTA" = "-" ] && BTA_SORT=999999999
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$RANK" "$BTA_SORT" "$D" "$L" "$RA" "$AF" "$IF" "$LAT" "$BTA" "$S$([ "$F" != "-" ] && printf '\t%s' "$F" || printf '\t-')"
    done <"$TMP_TABLE" | sort -t $'\t' -k1,1n -k2,2n -k3,3 | while IFS=$'\t' read -r RANK BTA_SORT D L RA AF IF LAT BTA S F; do
      # Render UINT64_MAX inactive_from + the never-active sentinel readably.
      printf '  %-24s %-12s %-12s %-12s %-9s %-8s %-20s %s\n' "$D" "$L" "$RA" "$AF" "$LAT" "$BTA" "$S" "$F"
    done
  else
    if [ "$PENDING_ONLY" = "1" ] && [ "$TOTAL" -gt 0 ]; then
      echo "  (no pending-activation validators — all registered entries are live or exiting)"
    elif [ "$TOTAL" = "0" ]; then
      echo "  (no validators with stake)"
    fi
  fi
  echo
  echo "  Summary:"
  echo "    total                : $TOTAL"
  echo "    pending-activation   : $PENDING_COUNT"
  echo "    active               : $ACTIVE_COUNT"
  echo "    exiting              : $EXITING_COUNT"
  echo "    genesis-seeded       : $GENESIS_COUNT"
  echo "    latency anomalies    : $ANOMALY_COUNT"
fi

# ── Step 5: exit code policy ─────────────────────────────────────────────────
# Design choice (mirrors operator_stake_audit.sh): exit 2 ONLY fires in
# --pending-only mode. Default mode is informational and always exits 0
# (provided the RPC layer was healthy), so a scheduled census can report
# without paging; operator alerting is opt-in via --pending-only.
if [ "$PENDING_ONLY" = "1" ] && [ "$ANOMALY_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
