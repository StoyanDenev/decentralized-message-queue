#!/usr/bin/env bash
# operator_committee_audit.sh — Read-only audit of the active K-of-K
# consensus committee on a running determ daemon. Cross-references the
# `committee` RPC (current selected K creators) with the `stakes` RPC
# (eligible registry — the only surface that carries the per-validator
# region tag) and the chain head, classifies committee health against
# operator thresholds, and emits a human table or JSON envelope.
#
# Why three RPCs instead of one:
#   - committee RPC returns {domain, ed_pub, active_from, stake} but
#     omits the rev.9 R1 `region` field — committee selection consumes
#     pool ordering, not regional tags directly. To answer "is this
#     committee regionally concentrated?" we must rejoin against the
#     stakes RPC which DOES carry region. The rejoin is also how we
#     detect committee/registry desync (a committee entry that's not
#     in active stakes — should not happen on a correctly-running
#     daemon; flagged as anomaly if it does).
#   - head RPC pins the height the audit is reporting on so the JSON
#     envelope is self-describing (committees can shift epoch-to-epoch).
#
# Anomaly flags:
#   committee_below_threshold  — K < --threshold (default 3 ≡ smallest
#                                quorum-eligible committee; below this
#                                BFT k_bft = ceil(2K/3) collapses to <2
#                                and MD-mode safety degrades)
#   committee_not_in_stakes    — a committee entry's domain is missing
#                                from the active stakes registry
#                                (registry/committee desync — would
#                                indicate a stake refund or DEREGISTER
#                                that should have evicted the entry)
#   regional_concentration     — INFORMATIONAL only: every committee
#                                member shares the same region tag
#                                (or all have empty region, i.e. pre-R1
#                                chain). Not an error in cluster
#                                deployments; flagged for regional/
#                                global-profile operators to confirm
#                                expected partner_subset spread.
#
# Args:
#   [--rpc-port N]         RPC port to query (default: 7778)
#   [--json]               Emit structured JSON instead of human output
#   [--anomalies-only]     Suppress normal output unless an anomaly was
#                          found; exit 2 if anomalies were detected
#   [--threshold N]        Minimum committee size to call "healthy"
#                          (default: 3). K < threshold ⇒ anomaly.
#   [-h|--help]            Show this help
#
# Exit codes:
#   0   audit ran, no anomalies (or default informational mode)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly detected (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_committee_audit.sh [--rpc-port N] [--json]
                                   [--anomalies-only] [--threshold N]

Audit the active K-of-K consensus committee on a running determ
daemon. Cross-references three read-only RPCs:
  - `determ committee --json`  current K creators (domain, ed_pub,
                               active_from, stake)
  - `determ head --json`       current height + head_hash
  - `determ stakes --json`     eligible registry (adds region tag +
                               desync detection)

Computes committee size K and threshold quorums (MD = K, BFT k_bft =
ceil(2K/3)), lists each member with region (rejoined from stakes),
tallies regional distribution, and classifies anomalies:
  - committee_below_threshold: K < --threshold (default 3)
  - committee_not_in_stakes:   committee domain not in active stakes
                               (registry/committee desync)
  - regional_concentration:    INFORMATIONAL — all members in one
                               region (or all empty pre-R1 chain)

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit structured JSON envelope (see shape below)
  --anomalies-only    Suppress normal output unless an anomaly was
                      found. In this mode exit 2 if anomalies present.
  --threshold N       Minimum committee size considered healthy
                      (default: 3). K < N raises committee_below_threshold.
  -h, --help          Show this help

JSON shape:
  {"committee_size":K,
   "members":[{"domain":"…","region":"…","stake":N,"in_stakes":true|false},…],
   "thresholds":{"md":K,"bft":ceil(2K/3)},
   "height":H,
   "head_hash":"…",
   "anomalies":["…",…],
   "regional_distribution":{"region":count,…},
   "rpc_port":N}

Exit codes:
  0   audit ran, no anomalies (or default informational mode)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   --anomalies-only AND ≥1 anomaly detected
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
THRESHOLD=3
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";       shift 2 ;;
    --json)           JSON_OUT=1;          shift ;;
    --anomalies-only) ANOM_ONLY=1;         shift ;;
    --threshold)      THRESHOLD="${2:-}";  shift 2 ;;
    *) echo "operator_committee_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards.
case "$PORT" in
  *[!0-9]*|"") echo "operator_committee_audit: --rpc-port must be a positive integer (got '$PORT')" >&2; exit 1 ;;
esac
case "$THRESHOLD" in
  *[!0-9]*|"") echo "operator_committee_audit: --threshold must be a non-negative integer (got '$THRESHOLD')" >&2; exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: chain head (height + head_hash) ───────────────────────────────────
HEAD_OUT=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_committee_audit: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
  exit 1
}
if [ "$HAVE_JQ" = "1" ]; then
  HEIGHT=$(printf '%s' "$HEAD_OUT"    | jq -r '.height // empty')
  HEAD_HASH=$(printf '%s' "$HEAD_OUT" | jq -r '.head_hash // ""')
else
  HEIGHT=$(printf '%s' "$HEAD_OUT" | grep -o '"height":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//')
  HEAD_HASH=$(printf '%s' "$HEAD_OUT" | grep -o '"head_hash":"[^"]*"' | head -1 | sed 's/.*:"\([^"]*\)"/\1/')
fi
case "$HEIGHT" in *[!0-9]*|"") echo "operator_committee_audit: malformed head JSON (height='$HEIGHT')" >&2; exit 1 ;; esac

# ── Step 2: committee (the K-of-K active creators for the current epoch) ─────
# Handle older daemons missing the `committee` RPC method gracefully: a
# method-not-found JSON-RPC error is propagated as exit code 1 from the
# CLI with stderr "Error: …". We catch that and emit a clearer message.
CMT_OUT=$("$DETERM" committee --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_committee_audit: RPC error from \`determ committee\` (port $PORT — older daemon may not implement the committee method)" >&2
  exit 1
}

# Committee JSON is an array. Empty is legal (genesis state with no
# eligible validators yet — handled below).
if [ "$HAVE_JQ" = "1" ]; then
  CMT_TYPE=$(printf '%s' "$CMT_OUT" | jq -r 'type' 2>/dev/null || true)
  if [ "$CMT_TYPE" != "array" ]; then
    echo "operator_committee_audit: malformed committee response (expected array, got '$CMT_TYPE')" >&2
    exit 1
  fi
  K=$(printf '%s' "$CMT_OUT" | jq -r 'length')
  CMT_DOMAINS=$(printf '%s' "$CMT_OUT" | jq -r '.[].domain')
else
  # Fallback: count domains via grep — committee shape uses one
  # "domain":"…" per member.
  CMT_DOMAINS=$(printf '%s' "$CMT_OUT" | grep -o '"domain":"[^"]*"' | sed 's/"domain":"\([^"]*\)"/\1/')
  K=0
  [ -n "$CMT_DOMAINS" ] && K=$(printf '%s\n' "$CMT_DOMAINS" | grep -c .)
fi
case "$K" in *[!0-9]*|"") echo "operator_committee_audit: cannot determine committee size (K='$K')" >&2; exit 1 ;; esac

# Threshold quorums:
#   MD-mode (multi-domain consensus): all K signatures required (single
#     mode at K=1; otherwise this is the multi-domain quorum).
#   BFT-mode: k_bft = ceil(2K/3) (the trimmed committee that produces
#     signed blocks under BFT escalation per PROTOCOL.md §5.3).
MD=$K
# Integer ceil(2K/3): (2K + 2) / 3 — bash arithmetic.
if [ "$K" = "0" ]; then BFT=0; else BFT=$(( (2 * K + 2) / 3 )); fi

# ── Step 3: stakes (for region rejoin + desync detection) ────────────────────
STAKES_OUT=$("$DETERM" stakes --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_committee_audit: RPC error from \`determ stakes\` (port $PORT)" >&2
  exit 1
}

# Build domain → region lookup. Older chains pre-R1 have no region
# field; treat missing/null as empty string.
TMP_STAKES=$(mktemp)
trap 'rm -f "$TMP_STAKES" "$TMP_MEMBERS"' EXIT
if [ "$HAVE_JQ" = "1" ]; then
  printf '%s' "$STAKES_OUT" | jq -r '.[] | "\(.domain)\t\(.region // "")"' >"$TMP_STAKES" 2>/dev/null || {
    echo "operator_committee_audit: malformed stakes JSON" >&2; exit 1;
  }
else
  # No jq: assume committee_not_in_stakes can't be reliably computed.
  # We still produce a usable table by using an empty stakes set; the
  # in_stakes flag will be false for every member in that mode and a
  # warning is emitted.
  echo "operator_committee_audit: warning: jq not found, region rejoin and desync detection disabled" >&2
fi

# Look up region + active-stake membership for a given domain.
# Echoes: "<region>\t<in_stakes:0|1>"
lookup_stake() {
  local d="$1"
  if [ "$HAVE_JQ" = "1" ] && [ -s "$TMP_STAKES" ]; then
    # Pick the first matching line; tab-separated.
    local line
    line=$(awk -F'\t' -v D="$d" '$1 == D { print; exit }' "$TMP_STAKES")
    if [ -n "$line" ]; then
      local reg
      reg=$(printf '%s' "$line" | awk -F'\t' '{print $2}')
      printf '%s\t1\n' "$reg"
      return
    fi
  fi
  printf '\t0\n'
}

# ── Step 4: per-member rejoin + anomaly accumulation ─────────────────────────
TMP_MEMBERS=$(mktemp)
ANOMALIES=""
add_anomaly() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}

# Regional distribution counter — emitted as space-separated "region:N"
# pairs in TMP_DIST so the human/JSON renderers can format consistently.
declare -A REGION_COUNT 2>/dev/null || true
if [ -n "$CMT_DOMAINS" ]; then
  # We can't rely on associative arrays existing in every bash (e.g.
  # macOS bash 3.2). Use a tmp file as the canonical counter.
  TMP_DIST=$(mktemp)
  trap 'rm -f "$TMP_STAKES" "$TMP_MEMBERS" "$TMP_DIST"' EXIT
  IDX=0
  while IFS= read -r DOM; do
    [ -z "$DOM" ] && continue
    IDX=$((IDX + 1))

    # Stake for this committee member (from the committee RPC itself).
    if [ "$HAVE_JQ" = "1" ]; then
      STAKE=$(printf '%s' "$CMT_OUT" | jq -r --arg D "$DOM" '.[] | select(.domain==$D) | .stake' | head -1)
    else
      STAKE="?"
    fi
    [ -z "$STAKE" ] && STAKE=0

    INFO=$(lookup_stake "$DOM")
    REG=$(printf '%s' "$INFO" | awk -F'\t' '{print $1}')
    IN_STAKES=$(printf '%s' "$INFO" | awk -F'\t' '{print $2}')

    if [ "$IN_STAKES" = "0" ]; then
      add_anomaly "committee_not_in_stakes:$DOM"
    fi

    # Tally region: empty region tracked as "(none)" sentinel.
    REGION_KEY="${REG:-(none)}"
    printf '%s\n' "$REGION_KEY" >>"$TMP_DIST"

    # One row: idx <TAB> domain <TAB> region <TAB> in_stakes <TAB> stake
    printf '%s\t%s\t%s\t%s\t%s\n' "$IDX" "$DOM" "$REG" "$IN_STAKES" "$STAKE" >>"$TMP_MEMBERS"
  done <<EOF
$CMT_DOMAINS
EOF
else
  TMP_DIST=$(mktemp)
  trap 'rm -f "$TMP_STAKES" "$TMP_MEMBERS" "$TMP_DIST"' EXIT
fi

# Committee size anomaly.
if [ "$K" -lt "$THRESHOLD" ]; then
  add_anomaly "committee_below_threshold"
fi

# Regional concentration (informational anomaly only — included in the
# anomalies list so JSON consumers can see it, but it does NOT gate
# --anomalies-only exit code 2 because cluster deployments
# legitimately have all members in one region).
DIST_RAW=""
if [ -s "$TMP_DIST" ]; then
  DIST_RAW=$(sort "$TMP_DIST" | uniq -c | awk '{
    cnt=$1; $1=""; sub(/^ /, ""); printf "%s:%s\n", $0, cnt
  }')
fi
UNIQUE_REGIONS=0
if [ -n "$DIST_RAW" ]; then
  UNIQUE_REGIONS=$(printf '%s\n' "$DIST_RAW" | grep -c .)
fi
if [ "$K" -gt 0 ] && [ "$UNIQUE_REGIONS" = "1" ]; then
  add_anomaly "regional_concentration"
fi

# Determine "alert-worthy" anomaly count — excludes the informational
# regional_concentration flag.
ALERT_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ALERT_COUNT=$(printf '%s' "$ANOMALIES" | tr ',' '\n' | grep -cv '^regional_concentration$' || true)
fi
case "$ALERT_COUNT" in *[!0-9]*|"") ALERT_COUNT=0 ;; esac

# ── Step 5: rendering ────────────────────────────────────────────────────────
emit_json() {
  # Build members array.
  printf '{"committee_size":%s,"members":[' "$K"
  FIRST=1
  if [ -s "$TMP_MEMBERS" ]; then
    while IFS=$'\t' read -r I D R S STK; do
      [ "$FIRST" = "1" ] || printf ','
      FIRST=0
      # in_stakes as JSON boolean
      if [ "$S" = "1" ]; then IS_BOOL="true"; else IS_BOOL="false"; fi
      printf '{"domain":"%s","region":"%s","stake":%s,"in_stakes":%s}' "$D" "$R" "$STK" "$IS_BOOL"
    done <"$TMP_MEMBERS"
  fi
  printf '],"thresholds":{"md":%s,"bft":%s},"height":%s,"head_hash":"%s","anomalies":[' "$MD" "$BFT" "$HEIGHT" "$HEAD_HASH"
  if [ -n "$ANOMALIES" ]; then
    AFIRST=1
    printf '%s' "$ANOMALIES" | tr ',' '\n' | while IFS= read -r A; do
      [ -z "$A" ] && continue
      [ "$AFIRST" = "1" ] || printf ','
      AFIRST=0
      printf '"%s"' "$A"
    done
  fi
  printf '],"regional_distribution":{'
  if [ -n "$DIST_RAW" ]; then
    DFIRST=1
    printf '%s\n' "$DIST_RAW" | while IFS= read -r ENTRY; do
      [ -z "$ENTRY" ] && continue
      RG=$(printf '%s' "$ENTRY" | awk -F: '{ for(i=1;i<NF;i++){ if(i>1) printf ":"; printf "%s", $i } }')
      CN=$(printf '%s' "$ENTRY" | awk -F: '{ print $NF }')
      [ "$DFIRST" = "1" ] || printf ','
      DFIRST=0
      printf '"%s":%s' "$RG" "$CN"
    done
  fi
  printf '},"rpc_port":%s}\n' "$PORT"
}

emit_human() {
  # Pretty short hash: first 8 hex chars + ellipsis (only if non-empty).
  HASH_SHORT="(empty)"
  [ -n "$HEAD_HASH" ] && HASH_SHORT="$(printf '%s' "$HEAD_HASH" | cut -c1-8)..."

  echo "=== Committee audit (port $PORT, height $HEIGHT, head=$HASH_SHORT) ==="
  echo "Committee size: K=$K"
  echo "Threshold quorums: MD=$MD, BFT=$BFT"

  if [ "$K" = "0" ]; then
    echo "Members: (empty committee — no eligible validators at this height)"
  else
    echo "Members:"
    if [ -s "$TMP_MEMBERS" ]; then
      while IFS=$'\t' read -r I D R IS STK; do
        REG_DISP="$R"
        [ -z "$REG_DISP" ] && REG_DISP="(none)"
        TAG=""
        [ "$IS" = "0" ] && TAG=" [NOT IN STAKES]"
        printf '  %s. %-24s (region: %s, stake: %s)%s\n' "$I" "$D" "$REG_DISP" "$STK" "$TAG"
      done <"$TMP_MEMBERS"
    fi
  fi

  # Status lines.
  if [ "$ALERT_COUNT" = "0" ] && [ -n "$CMT_DOMAINS" ]; then
    # Specific OK markers — one for membership, one for size.
    case ",$ANOMALIES," in
      *,committee_not_in_stakes:*) ;;  # not OK; handled below
      *) echo "[OK]   All members present in active stakes" ;;
    esac
    if [ "$K" -ge "$THRESHOLD" ]; then
      echo "[OK]   Committee size >= threshold ($K >= $THRESHOLD)"
    fi
  fi

  # Anomalies (non-empty list).
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | tr ',' '\n' | while IFS= read -r A; do
      [ -z "$A" ] && continue
      case "$A" in
        committee_below_threshold)
          echo "[WARN] Committee size below threshold (K=$K < $THRESHOLD)"
          ;;
        committee_not_in_stakes:*)
          MISSING_DOM=${A#committee_not_in_stakes:}
          echo "[WARN] Committee member not in active stakes: $MISSING_DOM"
          ;;
        regional_concentration)
          echo "[INFO] Regional concentration: all members share one region"
          ;;
      esac
    done
  fi

  # Regional distribution line.
  if [ -n "$DIST_RAW" ]; then
    printf '[INFO] Regional distribution:'
    printf '%s\n' "$DIST_RAW" | while IFS= read -r ENTRY; do
      [ -z "$ENTRY" ] && continue
      RG=$(printf '%s' "$ENTRY" | awk -F: '{ for(i=1;i<NF;i++){ if(i>1) printf ":"; printf "%s", $i } }')
      CN=$(printf '%s' "$ENTRY" | awk -F: '{ print $NF }')
      printf ' %s=%s' "$RG" "$CN"
    done
    printf '\n'
  fi
}

# --anomalies-only mode: suppress all normal output unless an alert
# anomaly was detected. regional_concentration alone is treated as
# informational and does NOT trigger output in this mode.
if [ "$ANOM_ONLY" = "1" ]; then
  if [ "$ALERT_COUNT" -gt 0 ]; then
    if [ "$JSON_OUT" = "1" ]; then emit_json; else emit_human; fi
    exit 2
  fi
  # silent success
  exit 0
fi

if [ "$JSON_OUT" = "1" ]; then emit_json; else emit_human; fi
exit 0
