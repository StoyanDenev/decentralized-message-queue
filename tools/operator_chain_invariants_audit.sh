#!/usr/bin/env bash
# operator_chain_invariants_audit.sh — RPC-level chain-integrity audit.
#
# Audit a LIVE production daemon for any of the chain-integrity
# invariants being violated AT REST (i.e. examine the chain via RPC,
# not the in-memory state machine). Operator-side equivalent of the
# in-process test_chain_*.sh scripts in this tree.
#
# Invariants enforced at multiple layers in the codebase and checked
# here:
#
#   (A) prev_hash chain link
#       For every block h in the sampled window:
#           block[h].prev_hash == block[h-1].block_hash
#       Enforced in Chain::append (src/chain/chain.cpp:54-58) and
#       BlockValidator::check_prev_hash (src/node/validator.cpp:43).
#       A mismatch is CATASTROPHIC — the FA1 chain anchor is broken;
#       fires anomaly `prev_hash_chain_broken` at MAX severity.
#
#   (B) state_root presence on recent blocks
#       Post S-038 (producer-side state_root wiring) every block at
#       height >= 1 should have a non-empty state_root. Pre-S-038
#       blocks (very old chains that pre-date the wiring) may legitimately
#       have empty state_root, so the script ALERTS only on RECENT
#       blocks (within the last 100 of the audited window) with an
#       empty state_root — that's the S-038 closure regression signal.
#       Anomaly: `state_root_missing_recent`.
#
#   (C) head_hash consistency at the chain tail
#       The daemon's `head` RPC returns the chain's current head_hash;
#       it must match block-info at TIP's block_hash field. A mismatch
#       points at a stale cache, mid-finalize torn read, or chain
#       inconsistency. Anomaly: `head_hash_mismatch` (MAX severity).
#
#   (D) timestamp monotonicity (advisory)
#       The validator V14 window only enforces wall-clock ±30s of NOW;
#       inter-block monotonicity is NOT a hard rule (a small NTP backjump
#       can in principle produce block[h].timestamp < block[h-1].timestamp).
#       But it IS anomalous and worth flagging — operators want to know
#       about clock drift on their producers. Anomaly:
#       `timestamp_regression`.
#
#   (E) per-block transaction reasonableness (advisory)
#       The block RPC does not expose tx_root in the default JSON
#       (tx_root is bound by compute_block_digest as the committee
#       signature target, but the RPC surface returns the materialized
#       `transactions` array, not its Merkle root). For this script we
#       verify the `transactions` array length is reasonable (<= a
#       per-message cap proxy) and that per-tx hashes within a block
#       are unique. This is a lightweight sanity check, not a full
#       tx_root verification. Anomaly: `tx_duplicate_in_block`.
#
# Sibling positioning vs. existing scripts:
#   operator_chain_verify.sh    — Walks the FULL chain via paged
#                                 `verify-headers` to assert (A) globally.
#                                 Stricter on (A), but doesn't check
#                                 (B)/(C)/(D)/(E).
#   operator_replay_validation.sh — State-divergence diagnostic; runs
#                                 a snapshot-restore round-trip and
#                                 probes state_root + block_hash twice
#                                 for RPC determinism. Orthogonal:
#                                 that script catches APPLY-PATH
#                                 non-determinism; THIS script catches
#                                 STORED chain-data tampering.
#
# Read-only RPC; safe against any running daemon. Daemon must already
# be listening on --rpc-port.
#
# Usage:
#   tools/operator_chain_invariants_audit.sh [--rpc-port N]
#                                            [--from H] [--to H]
#                                            [--stride N]
#                                            [--json]
#                                            [--anomalies-only]
#
# Exit codes:
#   0 — every invariant holds across the audited window
#   1 — RPC error / args error / malformed response / advisory-only
#       anomaly (state_root_missing_recent, timestamp_regression,
#       tx_duplicate_in_block)
#   2 — MAX-severity chain-integrity break: prev_hash_chain_broken OR
#       head_hash_mismatch
set -u

usage() {
  cat <<'EOF'
Usage: operator_chain_invariants_audit.sh [--rpc-port N]
                                          [--from H] [--to H]
                                          [--stride N]
                                          [--json]
                                          [--anomalies-only]

RPC-level chain-integrity audit. For each block in the sampled window
(stride-spaced), verify:

  (A) prev_hash chain link        block[h].prev_hash == block[h-1].hash
  (B) state_root presence         block[h].state_root non-empty for
                                  recent blocks (h >= TO-100); pre-S-038
                                  early-chain headers exempt.
  (C) head_hash consistency       head RPC's head_hash == block-info
                                  at chain tip's block_hash.
  (D) timestamp monotonicity      block[h].timestamp >= block[h-1].ts
  (E) tx-list reasonableness      per-block tx_hash uniqueness.

Options:
  --rpc-port N         RPC port to query (default: 8081)
  --from H             Lower window bound, inclusive (default: 0)
  --to H               Upper window bound, inclusive (default: chain tip)
  --stride N           Sample every Nth block. Default: 100 if window
                       size > 100, else 1. Min: 1.
  --json               Emit structured JSON envelope (machine-readable).
  --anomalies-only     Suppress per-block "OK" lines; print only
                       divergent samples + the summary.
  -h, --help           Show this help.

JSON envelope (--json):
  {"rpc_port":N,
   "window":{"from":H,"to":H,"stride":N},
   "sampled_blocks":N,
   "samples":[
     {"height":H,
      "prev_hash_ok":true|false,
      "state_root_present":true|false,
      "timestamp_ok":true|false},
     ...
   ],
   "head_hash_match":true|false,
   "anomalies":[
     "prev_hash_chain_broken" | "state_root_missing_recent" |
     "head_hash_mismatch"     | "timestamp_regression"     |
     "tx_duplicate_in_block",
     ...
   ],
   "summary":{
     "prev_hash_breaks":N,
     "state_root_missing_recent":N,
     "timestamp_regressions":N,
     "tx_duplicate_blocks":N,
     "head_hash_match":true|false
   }}

Exit codes:
  0   audited window clean
  1   RPC / args error, OR advisory-only anomaly fired
      (state_root_missing_recent, timestamp_regression,
       tx_duplicate_in_block)
  2   MAX-severity chain-integrity break detected
      (prev_hash_chain_broken OR head_hash_mismatch)

Examples:
  # Default: sample every 100th block on port 8081.
  tools/operator_chain_invariants_audit.sh

  # Audit a suspect range with every-block sampling.
  tools/operator_chain_invariants_audit.sh --rpc-port 7778 \
      --from 5000 --to 5100 --stride 1

  # CI: capture machine-readable result.
  tools/operator_chain_invariants_audit.sh --json --rpc-port 7778
EOF
}

PORT="8081"
FROM=""
TO=""
STRIDE=""
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="${2:-}";   shift 2 ;;
    --from)            FROM="${2:-}";   shift 2 ;;
    --to)              TO="${2:-}";     shift 2 ;;
    --stride)          STRIDE="${2:-}"; shift 2 ;;
    --json)            JSON_OUT=1;      shift ;;
    --anomalies-only)  ANOM_ONLY=1;     shift ;;
    *) echo "operator_chain_invariants_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# ── Arg validation. ──────────────────────────────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_chain_invariants_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for V in "$FROM" "$TO" "$STRIDE"; do
  if [ -n "$V" ]; then
    case "$V" in *[!0-9]*)
      echo "operator_chain_invariants_audit: --from/--to/--stride must be non-negative integers (got '$V')" >&2
      exit 1 ;;
    esac
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_chain_invariants_audit: jq is required (not on PATH)" >&2
  exit 1
fi

# ── Resolve chain head. ──────────────────────────────────────────────────────
HEAD_OUT=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_chain_invariants_audit: RPC error (is daemon running on port $PORT?)" >&2
  exit 1
}
HEAD_HEIGHT=$(printf '%s' "$HEAD_OUT" | jq -r '.height // 0')
HEAD_HASH_REPORTED=$(printf '%s' "$HEAD_OUT" | jq -r '.head_hash // ""')
case "$HEAD_HEIGHT" in *[!0-9]*|"")
  echo "operator_chain_invariants_audit: head height not numeric (got '$HEAD_HEIGHT')" >&2
  exit 1 ;;
esac
if [ "$HEAD_HEIGHT" = "0" ]; then
  echo "operator_chain_invariants_audit: chain empty (height=0); nothing to audit" >&2
  exit 1
fi
TIP=$(( HEAD_HEIGHT - 1 ))

# Resolve window.
if [ -z "$FROM" ]; then FROM=0; fi
if [ -z "$TO" ];   then TO=$TIP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_chain_invariants_audit: invalid window: --from $FROM > --to $TO" >&2
  exit 1
fi
if [ "$TO" -gt "$TIP" ]; then
  echo "operator_chain_invariants_audit: --to $TO exceeds chain tip $TIP (height=$HEAD_HEIGHT)" >&2
  exit 1
fi

WINDOW_LEN=$(( TO - FROM + 1 ))
if [ -z "$STRIDE" ]; then
  if [ "$WINDOW_LEN" -gt 100 ]; then STRIDE=100; else STRIDE=1; fi
fi
if [ "$STRIDE" -le 0 ]; then
  echo "operator_chain_invariants_audit: --stride must be > 0 (got $STRIDE)" >&2
  exit 1
fi

# ── Scratch storage. ─────────────────────────────────────────────────────────
SAMPLES_FILE=$(mktemp 2>/dev/null) || { echo "operator_chain_invariants_audit: cannot create tmp file" >&2; exit 1; }
ANOMALIES_FILE=$(mktemp 2>/dev/null) || { echo "operator_chain_invariants_audit: cannot create tmp file" >&2; exit 1; }
NOTES_FILE=$(mktemp 2>/dev/null)     || { echo "operator_chain_invariants_audit: cannot create tmp file" >&2; exit 1; }
trap 'rm -f "$SAMPLES_FILE" "$ANOMALIES_FILE" "$NOTES_FILE"' EXIT

push_anomaly() {
  # Dedup at insert time so we only get one entry per anomaly kind.
  if ! grep -Fxq "$1" "$ANOMALIES_FILE" 2>/dev/null; then
    printf '%s\n' "$1" >> "$ANOMALIES_FILE"
  fi
}

# Counters (rolled up after the walk for the JSON / human render).
PREV_HASH_BREAKS=0
STATE_ROOT_MISSING_RECENT=0
TIMESTAMP_REGRESSIONS=0
TX_DUP_BLOCKS=0

# Recent-window cutoff for (B) state_root presence check. Any sample
# in [RECENT_FROM..TO] with empty state_root is the S-038 regression
# signal; older samples get a pass (legitimately pre-S-038).
RECENT_FROM=$(( TO - 100 ))
if [ "$RECENT_FROM" -lt "$FROM" ]; then RECENT_FROM=$FROM; fi

# ── Per-sample fetch helper. ────────────────────────────────────────────────
# Returns 4 newline-separated fields: prev_hash, timestamp, state_root,
# block_hash. Empty fields are returned as empty lines (still 4 lines).
fetch_block_fields() {
  # Args: <height>
  local h="$1"
  local out
  out=$("$DETERM" block-info "$h" --json --rpc-port "$PORT" 2>/dev/null) || return 1
  printf '%s' "$out" | jq -r '
    [.prev_hash // "",
     (.timestamp // 0 | tostring),
     .state_root // "",
     .hash // ""]
    | .[]
  '
}

# Per-block tx-hash uniqueness check. Returns 0 if all hashes unique
# (or the block has 0 transactions), 1 if a duplicate is detected.
check_tx_uniqueness() {
  # Args: <height>
  local h="$1"
  local out
  out=$("$DETERM" block-info "$h" --json --rpc-port "$PORT" 2>/dev/null) || return 0
  local n_total n_uniq
  n_total=$(printf '%s' "$out" | jq -r '(.transactions // []) | length')
  if [ "$n_total" = "0" ] || [ -z "$n_total" ]; then return 0; fi
  n_uniq=$(printf '%s' "$out" | jq -r '
    (.transactions // [])
    | map(.hash // "")
    | unique
    | length
  ')
  if [ "$n_total" != "$n_uniq" ]; then return 1; fi
  return 0
}

# ── Walk. ────────────────────────────────────────────────────────────────────
# State carried block-to-block:
#   PREV_BLOCK_HASH   — block_hash from the prior sample (or genesis sentinel)
#   PREV_TS           — timestamp from the prior sample
#   PREV_H            — height of the prior sample (for adjacency check)
PREV_BLOCK_HASH=""
PREV_TS=""
PREV_H=""
SAMPLED=0

H=$FROM
while [ "$H" -le "$TO" ]; do
  # Single fetch (read-only RPC; idempotent — replay_validation.sh
  # already covers the determinism axis).
  RAW=$(fetch_block_fields "$H") || {
    echo "operator_chain_invariants_audit: RPC error fetching block-info $H (port $PORT)" >&2
    exit 1
  }
  P_HASH=$(printf '%s' "$RAW" | sed -n '1p')
  TS=$(printf     '%s' "$RAW" | sed -n '2p')
  S_ROOT=$(printf '%s' "$RAW" | sed -n '3p')
  B_HASH=$(printf '%s' "$RAW" | sed -n '4p')

  if [ -z "$B_HASH" ]; then
    echo "operator_chain_invariants_audit: block $H missing 'hash' field in JSON" >&2
    exit 1
  fi

  # ── (A) prev_hash chain link ───────────────────────────────────────────────
  # Only meaningful when this sample is directly adjacent to the previous
  # sample (stride == 1, OR H == FROM+1 trip). For stride > 1 we fetch the
  # IMMEDIATE predecessor explicitly when H > 0, so the chain-link assertion
  # remains valid sample-by-sample. The stride controls SAMPLING density,
  # not which neighbor we cross-check.
  PREV_OK=1
  if [ "$H" -gt 0 ]; then
    if [ -n "$PREV_H" ] && [ "$PREV_H" = "$(( H - 1 ))" ]; then
      # Direct neighbor — use cached PREV_BLOCK_HASH.
      EXPECT="$PREV_BLOCK_HASH"
    else
      # Not adjacent — fetch the h-1 block_hash explicitly.
      EXPECT=$("$DETERM" block-info $(( H - 1 )) --field block_hash --rpc-port "$PORT" 2>/dev/null | tr -d '[:space:]') || {
        echo "operator_chain_invariants_audit: RPC error fetching block-info $(( H - 1 )) for prev_hash check" >&2
        exit 1
      }
    fi
    if [ -n "$EXPECT" ] && [ "$P_HASH" != "$EXPECT" ]; then
      PREV_OK=0
      PREV_HASH_BREAKS=$(( PREV_HASH_BREAKS + 1 ))
      push_anomaly "prev_hash_chain_broken"
      printf '[!] block %s prev_hash MISMATCH: got=%s expected=%s\n' "$H" "$P_HASH" "$EXPECT" >> "$NOTES_FILE"
    fi
  else
    # Block 0: prev_hash MUST be the 64-zero genesis sentinel.
    case "$P_HASH" in
      0000000000000000000000000000000000000000000000000000000000000000) ;;
      *) PREV_OK=0
         PREV_HASH_BREAKS=$(( PREV_HASH_BREAKS + 1 ))
         push_anomaly "prev_hash_chain_broken"
         printf '[!] block 0 prev_hash NON-ZERO (genesis-sentinel violation): %s\n' "$P_HASH" >> "$NOTES_FILE"
         ;;
    esac
  fi

  # ── (B) state_root presence on recent blocks ───────────────────────────────
  SR_OK=1
  SR_PRESENT=1
  if [ -z "$S_ROOT" ]; then
    SR_PRESENT=0
    # Heights 0 (genesis) are exempt — pre-A9 the genesis block may legitimately
    # ship without state_root populated. For h >= 1 inside the RECENT window,
    # an empty state_root means S-038 producer-side wiring regressed.
    if [ "$H" -ge 1 ] && [ "$H" -ge "$RECENT_FROM" ]; then
      SR_OK=0
      STATE_ROOT_MISSING_RECENT=$(( STATE_ROOT_MISSING_RECENT + 1 ))
      push_anomaly "state_root_missing_recent"
      printf '[!] block %s state_root EMPTY (within recent window, h >= %s) — S-038 regression signal\n' "$H" "$RECENT_FROM" >> "$NOTES_FILE"
    fi
  fi

  # ── (D) timestamp monotonicity (advisory) ──────────────────────────────────
  TS_OK=1
  if [ -n "$PREV_TS" ] && [ -n "$TS" ]; then
    case "$TS$PREV_TS" in
      *[!0-9]*) ;;
      *)
        if [ "$TS" -lt "$PREV_TS" ]; then
          TS_OK=0
          TIMESTAMP_REGRESSIONS=$(( TIMESTAMP_REGRESSIONS + 1 ))
          push_anomaly "timestamp_regression"
          printf '[!] block %s timestamp REGRESSION: %s < prev (block %s) %s\n' "$H" "$TS" "$PREV_H" "$PREV_TS" >> "$NOTES_FILE"
        fi ;;
    esac
  fi

  # ── (E) per-block tx-hash uniqueness ──────────────────────────────────────
  if ! check_tx_uniqueness "$H"; then
    TX_DUP_BLOCKS=$(( TX_DUP_BLOCKS + 1 ))
    push_anomaly "tx_duplicate_in_block"
    printf '[!] block %s contains DUPLICATE tx_hash entries\n' "$H" >> "$NOTES_FILE"
  fi

  # Record the per-sample row.
  printf '%s\t%s\t%s\t%s\n' "$H" "$PREV_OK" "$SR_PRESENT" "$TS_OK" >> "$SAMPLES_FILE"
  SAMPLED=$(( SAMPLED + 1 ))

  # Carry state.
  PREV_BLOCK_HASH="$B_HASH"
  PREV_TS="$TS"
  PREV_H="$H"

  H=$(( H + STRIDE ))
done

# ── (C) head_hash consistency at the tip ─────────────────────────────────────
TIP_BLOCK_HASH=$("$DETERM" block-info "$TIP" --field block_hash --rpc-port "$PORT" 2>/dev/null | tr -d '[:space:]') || {
  echo "operator_chain_invariants_audit: RPC error fetching block-info $TIP for tail check" >&2
  exit 1
}
HEAD_MATCH=1
if [ -n "$HEAD_HASH_REPORTED" ] && [ -n "$TIP_BLOCK_HASH" ] \
   && [ "$HEAD_HASH_REPORTED" != "$TIP_BLOCK_HASH" ]; then
  HEAD_MATCH=0
  push_anomaly "head_hash_mismatch"
  printf '[!] head_hash MISMATCH: head RPC=%s block-info(%s)=%s\n' "$HEAD_HASH_REPORTED" "$TIP" "$TIP_BLOCK_HASH" >> "$NOTES_FILE"
fi

# ── Severity gating. ─────────────────────────────────────────────────────────
ANOM_COUNT=0
if [ -s "$ANOMALIES_FILE" ]; then
  ANOM_COUNT=$(wc -l < "$ANOMALIES_FILE" | tr -d '[:space:]')
fi
RC=0
# MAX-severity anomalies (chain integrity broken):
if grep -Fxq "prev_hash_chain_broken" "$ANOMALIES_FILE" 2>/dev/null \
   || grep -Fxq "head_hash_mismatch"     "$ANOMALIES_FILE" 2>/dev/null; then
  RC=2
elif [ "$ANOM_COUNT" -gt 0 ]; then
  RC=1
fi

# ── Emit. ────────────────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  # Build samples JSON via jq. Each line is "h\tprev_ok\tsr_present\tts_ok".
  SAMPLES_JSON=$(awk -F'\t' '
    BEGIN { n=0 }
    NF==4 {
      if (n>0) printf ",";
      printf "{\"height\":%s,\"prev_hash_ok\":%s,\"state_root_present\":%s,\"timestamp_ok\":%s}",
             $1,
             ($2=="1"?"true":"false"),
             ($3=="1"?"true":"false"),
             ($4=="1"?"true":"false");
      n++;
    }
    END { }
  ' "$SAMPLES_FILE")
  SAMPLES_JSON="[$SAMPLES_JSON]"

  ANOM_JSON="[]"
  if [ "$ANOM_COUNT" -gt 0 ]; then
    ANOM_JSON=$(jq -R -s 'split("\n") | map(select(length > 0))' < "$ANOMALIES_FILE")
  fi
  HEAD_MATCH_JS="false"
  [ "$HEAD_MATCH" = "1" ] && HEAD_MATCH_JS="true"

  cat <<EOF
{"rpc_port":$PORT,"window":{"from":$FROM,"to":$TO,"stride":$STRIDE},"sampled_blocks":$SAMPLED,"samples":$SAMPLES_JSON,"head_hash_match":$HEAD_MATCH_JS,"anomalies":$ANOM_JSON,"summary":{"prev_hash_breaks":$PREV_HASH_BREAKS,"state_root_missing_recent":$STATE_ROOT_MISSING_RECENT,"timestamp_regressions":$TIMESTAMP_REGRESSIONS,"tx_duplicate_blocks":$TX_DUP_BLOCKS,"head_hash_match":$HEAD_MATCH_JS}}
EOF
  exit "$RC"
fi

# Human render.
echo ""
echo "=== Chain-integrity audit (port $PORT) ==="
echo "Window:        [$FROM..$TO]  (size $WINDOW_LEN, stride $STRIDE => $SAMPLED samples)"
echo "Recent cutoff: h >= $RECENT_FROM  (B: state_root must be non-empty)"
echo ""

if [ "$ANOM_ONLY" = "0" ]; then
  printf '  %-10s %-10s %-15s %-10s\n' "height" "prev_hash" "state_root" "timestamp"
  printf '  %-10s %-10s %-15s %-10s\n' "------" "---------" "----------" "---------"
  while IFS=$'\t' read -r h p s t; do
    [ -z "$h" ] && continue
    [ "$p" = "1" ] && pm="OK"   || pm="!!"
    [ "$s" = "1" ] && sm="OK"   || sm=".."
    [ "$t" = "1" ] && tm="OK"   || tm="!!"
    printf '  %-10s %-10s %-15s %-10s\n' "$h" "$pm" "$sm" "$tm"
  done < "$SAMPLES_FILE"
  echo ""
else
  # Anomalies-only: show only divergent samples.
  printed=0
  while IFS=$'\t' read -r h p s t; do
    [ -z "$h" ] && continue
    if [ "$p" = "0" ] || [ "$s" = "0" ] || [ "$t" = "0" ]; then
      if [ "$printed" = "0" ]; then
        printf '  %-10s %-10s %-15s %-10s\n' "height" "prev_hash" "state_root" "timestamp"
        printf '  %-10s %-10s %-15s %-10s\n' "------" "---------" "----------" "---------"
        printed=1
      fi
      [ "$p" = "1" ] && pm="OK"   || pm="!!"
      [ "$s" = "1" ] && sm="OK"   || sm=".."
      [ "$t" = "1" ] && tm="OK"   || tm="!!"
      printf '  %-10s %-10s %-15s %-10s\n' "$h" "$pm" "$sm" "$tm"
    fi
  done < "$SAMPLES_FILE"
  [ "$printed" = "1" ] && echo ""
fi

echo "Head-hash check:"
if [ "$HEAD_MATCH" = "1" ]; then
  echo "  head RPC head_hash matches block-info($TIP).block_hash  [OK]"
else
  echo "  head RPC head_hash:           ${HEAD_HASH_REPORTED:0:24}..."
  echo "  block-info($TIP).block_hash:  ${TIP_BLOCK_HASH:0:24}..."
  echo "  MISMATCH detected — head_hash_mismatch"
fi
echo ""

echo "Summary:"
echo "  prev_hash_breaks:            $PREV_HASH_BREAKS"
echo "  state_root_missing_recent:   $STATE_ROOT_MISSING_RECENT"
echo "  timestamp_regressions:       $TIMESTAMP_REGRESSIONS"
echo "  tx_duplicate_blocks:         $TX_DUP_BLOCKS"
echo "  head_hash_match:             $( [ "$HEAD_MATCH" = "1" ] && echo "yes" || echo "no" )"

if [ -s "$NOTES_FILE" ]; then
  echo ""
  echo "Notes:"
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "  $line"
  done < "$NOTES_FILE"
fi

if [ "$ANOM_COUNT" -gt 0 ]; then
  echo ""
  echo "Anomalies ($ANOM_COUNT):"
  while IFS= read -r a; do
    [ -z "$a" ] && continue
    echo "  [X] $a"
  done < "$ANOMALIES_FILE"
fi

echo ""
case "$RC" in
  0) echo "[OK] No chain-integrity anomaly detected." ;;
  1) echo "[!]  Advisory anomaly fired (no chain-integrity break)." ;;
  2) echo "[X]  MAX-severity chain-integrity break detected (prev_hash_chain_broken OR head_hash_mismatch)." ;;
esac
exit "$RC"
