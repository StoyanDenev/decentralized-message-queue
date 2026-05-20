#!/usr/bin/env bash
# operator_validator_history.sh — Per-validator behavior history audit
# across a window of finalized blocks on a running determ daemon.
#
# Walks blocks via `determ block-info <i> --json` and aggregates, per
# validator domain D:
#   * REGISTER tx events sent by D       → (block_index, region)
#   * DEREGISTER tx events sent by D     → (block_index, post-dereg
#                                           unlock_height via stake_info)
#   * Times D appeared in block.creators[]    (committee appearances)
#   * Times D's parallel creator_block_sigs[] entry is NON-ZERO
#                                              (signature participations)
#   * abort_events.aborting_node == D    (round-1 abort attribution)
#   * equivocation_events.equivocator == D     (FA6 attribution)
#
# Then classifies behavior:
#   participation_rate = sig_participations / committee_appearances
#   total_slashed      = sum(abort_events.slashed_amount default 0)
#                      + sum(equivocation_events.slashed_amount default 0)
#   status:  active            (in stakes, unlock_height == UINT64_MAX)
#            pending-unlock    (in stakes, unlock_height > current head)
#            unlocked-pending  (in stakes, unlock_height ≤ current head;
#                               UNSTAKE has not landed yet — usually
#                               equivalent to "fully deregistered" but
#                               with stake refund still owed)
#            deregistered      (not present in stakes RPC)
#
# Modes:
#   --domain D   audit a single validator
#   --all        audit every validator surfaced by `determ stakes`
#                (sorted per --sort-by; default appearances desc)
#
# Window: --from H --to H (inclusive). Default = last 1000 blocks ending
# at current head, clamped to genesis.
#
# Anomaly conditions (--anomalies-only filters to only these):
#   * participation_rate < 80% (offline / stake-without-presence)
#   * any non-zero slashing (total_slashed > 0)
#   * status == pending-unlock (DEREGISTER staged, awaiting refund)
#
# Exit codes:
#   0   success (no anomalies, or --anomalies-only not asserted)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only set AND ≥1 anomaly detected
#
# Read-only RPC; safe against any running daemon. Requires `jq` for
# JSON traversal of nested block payloads; the per-block walk is driven
# from a Python heredoc to keep wall-clock acceptable on wide windows
# (one subprocess per block instead of jq + bash for each).
set -u

usage() {
  cat <<'EOF'
Usage: operator_validator_history.sh [--rpc-port N] [--json]
                                     [--domain D | --all]
                                     [--from H] [--to H]
                                     [--anomalies-only]
                                     [--sort-by {appearances|participation|slashed}]

Aggregate per-validator behavior history (REGISTER/DEREGISTER events,
committee appearances, signature participations, abort/equivocation
attributions, total slashed amount, current registry status) over a
window of finalized blocks.

Options:
  --rpc-port N         RPC port to query (default: 7778)
  --json               Emit structured JSON envelope (single object for
                       --domain mode; array of objects for --all mode)
  --domain D           Audit only the validator with this domain
  --all                Audit every validator returned by `determ stakes`
                       (exclusive with --domain; must specify exactly one)
  --from H             Lower window bound (inclusive). Default:
                       max(0, head - 1000 + 1).
  --to H               Upper window bound (inclusive). Default: current
                       head (= chain.height - 1).
  --anomalies-only     Print only validators with ≥1 anomaly flag; in
                       this mode exit 2 if any anomaly was found.
  --sort-by KEY        Sort order under --all mode. One of:
                         appearances    (committee appearances desc)  [default]
                         participation  (participation_rate desc)
                         slashed        (total_slashed desc)
  -h, --help           Show this help

Status classification:
  active            in stakes, unlock_height == UINT64_MAX
  pending-unlock    in stakes, unlock_height > current head
  unlocked-pending  in stakes, unlock_height ≤ current head
                    (UNSTAKE delay missed)
  deregistered      not present in `determ stakes`

Anomaly flags:
  low_participation       participation_rate < 80%
  slashed_in_window       total_slashed > 0 over scan range
  pending_unlock_state    status == pending-unlock

Exit codes:
  0   success
  1   RPC error / bad args
  2   --anomalies-only AND ≥1 anomaly found
EOF
}

PORT=7778
JSON_OUT=0
DOMAIN=""
ALL=0
FROM=""
TO=""
ANOM_ONLY=0
SORT_BY="appearances"
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";    shift 2 ;;
    --json)           JSON_OUT=1;       shift ;;
    --domain)         DOMAIN="${2:-}";  shift 2 ;;
    --all)            ALL=1;            shift ;;
    --from)           FROM="${2:-}";    shift 2 ;;
    --to)             TO="${2:-}";      shift 2 ;;
    --anomalies-only) ANOM_ONLY=1;      shift ;;
    --sort-by)        SORT_BY="${2:-}"; shift 2 ;;
    *) echo "operator_validator_history: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# Mode mutual-exclusion + required-one guard.
if [ -n "$DOMAIN" ] && [ "$ALL" = "1" ]; then
  echo "operator_validator_history: --domain and --all are mutually exclusive" >&2
  exit 1
fi
if [ -z "$DOMAIN" ] && [ "$ALL" = "0" ]; then
  echo "operator_validator_history: must specify either --domain D or --all" >&2
  exit 1
fi

# Numeric guards.
case "$PORT" in *[!0-9]*|"")
  echo "operator_validator_history: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM" "$TO"; do
  [ -z "$v" ] && continue
  case "$v" in *[!0-9]*)
    echo "operator_validator_history: --from / --to must be unsigned integers (got '$v')" >&2
    exit 1 ;;
  esac
done
case "$SORT_BY" in
  appearances|participation|slashed) ;;
  *) echo "operator_validator_history: --sort-by must be one of {appearances|participation|slashed} (got '$SORT_BY')" >&2
     exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v jq >/dev/null 2>&1; then
  echo "operator_validator_history: jq is required (block JSON is too nested for the grep fallback)" >&2
  exit 1
fi
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_validator_history: python (or python3) is required for the per-block walk" >&2
  exit 1
fi
PYTHON=python
command -v python >/dev/null 2>&1 || PYTHON=python3

UINT64_MAX=18446744073709551615

# ── Step 1: chain head ─────────────────────────────────────────────────────────
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_validator_history: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | jq -r '.height')
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_validator_history: malformed head JSON (height='$HEIGHT')" >&2
  exit 1 ;;
esac

# Highest finalized index = height - 1 (height is the NEXT-to-produce).
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))
if [ -z "$TO" ]; then TO=$TOP; fi
if [ -z "$FROM" ]; then
  FROM=$(( TOP > 1000 ? TOP - 1000 + 1 : 0 ))
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_validator_history: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi

# ── Step 2: stakes table (status + region rejoin) ────────────────────────────
STAKES_JSON=$("$DETERM" stakes --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_validator_history: RPC error from \`determ stakes\` (port $PORT)" >&2
  exit 1
}

# Build target domain list.
if [ "$ALL" = "1" ]; then
  TARGETS=$(printf '%s' "$STAKES_JSON" | jq -r '.[].domain')
else
  TARGETS="$DOMAIN"
fi
if [ -z "$TARGETS" ]; then
  # --all on a chain with no validators is success-with-empty.
  if [ "$JSON_OUT" = "1" ]; then
    printf '[]\n'
  else
    echo "operator_validator_history: no validators in active stakes (port $PORT, window [$FROM..$TO])"
  fi
  exit 0
fi

# Resolve per-domain {locked, unlock_height, region, in_stakes}. For
# --domain mode the domain may be deregistered → stake_info returns
# null/error, which we map to {in_stakes: false}.
TMP_TARGETS=$(mktemp)
trap 'rm -f "$TMP_TARGETS" "$TMP_AGG"' EXIT
while IFS= read -r D; do
  [ -z "$D" ] && continue
  REGION=$(printf '%s' "$STAKES_JSON" | jq -r --arg D "$D" '
    map(select(.domain == $D)) | (.[0].region // "")
  ')
  IN_STAKES=$(printf '%s' "$STAKES_JSON" | jq -r --arg D "$D" '
    if (map(select(.domain == $D)) | length) > 0 then "1" else "0" end
  ')
  LOCKED=0
  UH="$UINT64_MAX"
  if [ "$IN_STAKES" = "1" ]; then
    SI=$("$DETERM" stake_info "$D" --rpc-port "$PORT" 2>/dev/null) || {
      echo "operator_validator_history: RPC error from \`determ stake_info $D\` (port $PORT)" >&2
      exit 1
    }
    LOCKED=$(printf '%s' "$SI" | jq -r '.locked // 0')
    UH=$(printf '%s' "$SI" | jq -r '.unlock_height // "18446744073709551615"')
  fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$D" "$REGION" "$IN_STAKES" "$LOCKED" "$UH" >>"$TMP_TARGETS"
done <<EOF
$TARGETS
EOF

# ── Step 3: per-block walk + aggregation (Python) ─────────────────────────────
TMP_AGG=$(mktemp)
# Drive the walk in Python so one subprocess per block is the only RPC
# cost — jq + bash per block would multiply that 3-4×. The walk
# accumulates per-domain counters in a single dict and writes one TSV
# row per target domain plus one JSON-blob row per event.
"$PYTHON" - "$DETERM" "$PORT" "$FROM" "$TO" "$TMP_TARGETS" "$TMP_AGG" <<'PY' || {
  echo "operator_validator_history: block walk failed" >&2; exit 1;
}
import json, subprocess, sys

determ, port, from_h, to_h, targets_path, out_path = sys.argv[1:7]
from_h, to_h = int(from_h), int(to_h)

# Load target {domain → (region, in_stakes, locked, unlock_height)}.
targets = {}  # domain → dict
order   = []  # preserve input order for --all sort-by stability
with open(targets_path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line: continue
        parts = line.split("\t")
        if len(parts) != 5: continue
        d, region, in_stakes, locked, uh = parts
        targets[d] = {
            "region":           region,
            "in_stakes":        in_stakes == "1",
            "locked":           int(locked),
            "unlock_height":    int(uh),
            "appearances":      0,
            "sig_participations": 0,
            "abort_count":      0,
            "equivocation_count": 0,
            "total_slashed":    0,
            "events":           [],   # chronological history
            "first_seen_block": None,
            "last_seen_block":  None,
        }
        order.append(d)

ZERO_SIG_HEX = "0" * 128  # 64 bytes of zero = "didn't sign"

def is_tx_type(t, target_int):
    if isinstance(t, int):    return t == target_int
    if isinstance(t, str):    return t == str(target_int)
    return False

def decode_register_region(payload_hex):
    # REGISTER payload: [pubkey: 32B][region_len: u8][region: utf8]
    # Legacy = 32B pubkey only → empty region.
    try:
        p = bytes.fromhex(payload_hex)
    except Exception:
        return ""
    if len(p) < 32: return ""
    if len(p) == 32: return ""
    rlen = p[32]
    if len(p) != 33 + rlen: return ""
    return p[33:33+rlen].decode("utf-8", errors="replace")

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=10
        )
    except Exception as e:
        sys.stderr.write(f"operator_validator_history: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_validator_history: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_validator_history: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict): continue

    # Committee appearances + signature participations.
    creators = blk.get("creators") or []
    sigs     = blk.get("creator_block_sigs") or []
    for idx, dom in enumerate(creators):
        if dom in targets:
            targets[dom]["appearances"] += 1
            if targets[dom]["first_seen_block"] is None:
                targets[dom]["first_seen_block"] = h
            targets[dom]["last_seen_block"] = h
            if idx < len(sigs) and isinstance(sigs[idx], str) \
               and sigs[idx] and sigs[idx] != ZERO_SIG_HEX:
                targets[dom]["sig_participations"] += 1

    # REGISTER / DEREGISTER events from tx.from.
    for tx in (blk.get("transactions") or []):
        if not isinstance(tx, dict): continue
        sender = tx.get("from", "")
        if sender not in targets: continue
        t = tx.get("type")
        if is_tx_type(t, 1):  # REGISTER
            region = decode_register_region(tx.get("payload", ""))
            targets[sender]["events"].append({
                "block":  h,
                "kind":   "REGISTER",
                "region": region,
            })
        elif is_tx_type(t, 2):  # DEREGISTER
            # post-dereg unlock_height isn't stamped on the block; it's
            # computable as `inactive_from + unstake_delay`, but
            # inactive_from is derived from a randomized delay we can't
            # reconstruct without replay. Surface the current registry
            # unlock_height (snapshot at audit time) instead.
            targets[sender]["events"].append({
                "block":               h,
                "kind":                "DEREGISTER",
                "current_unlock_height": targets[sender]["unlock_height"],
            })

    # Abort attribution.
    for ae in (blk.get("abort_events") or []):
        if not isinstance(ae, dict): continue
        dom = ae.get("aborting_node", "")
        if dom in targets:
            targets[dom]["abort_count"] += 1
            slashed = int(ae.get("slashed_amount", 0) or 0)
            targets[dom]["total_slashed"] += slashed
            targets[dom]["events"].append({
                "block":   h,
                "kind":    "ABORT",
                "round":   ae.get("round", 0),
                "slashed": slashed,
            })

    # Equivocation attribution.
    for ev in (blk.get("equivocation_events") or []):
        if not isinstance(ev, dict): continue
        dom = ev.get("equivocator", "")
        if dom in targets:
            targets[dom]["equivocation_count"] += 1
            slashed = int(ev.get("slashed_amount", 0) or 0)
            targets[dom]["total_slashed"] += slashed
            targets[dom]["events"].append({
                "block":   h,
                "kind":    "EQUIVOCATE",
                "height":  ev.get("block_index", 0),
                "slashed": slashed,
            })

# Emit one TSV row per domain as JSON-blob (single field) so the bash
# renderer can pass it straight to jq.
with open(out_path, "w", encoding="utf-8") as f:
    for d in order:
        t = targets[d]
        rec = {
            "domain":              d,
            "region":              t["region"],
            "in_stakes":           t["in_stakes"],
            "locked":              t["locked"],
            "unlock_height":       t["unlock_height"],
            "appearances":         t["appearances"],
            "sig_participations":  t["sig_participations"],
            "abort_count":         t["abort_count"],
            "equivocation_count":  t["equivocation_count"],
            "total_slashed":       t["total_slashed"],
            "events":              t["events"],
            "first_seen_block":    t["first_seen_block"],
            "last_seen_block":     t["last_seen_block"],
        }
        f.write(json.dumps(rec) + "\n")
PY

# ── Step 4: classify + emit ──────────────────────────────────────────────────
# Reload aggregated rows and produce the final per-domain record with
# status, participation_rate, anomaly flags, and an "anomaly" boolean
# for filter/sort.
UINT64_MAX_LOCAL="$UINT64_MAX"
ROWS_JSON=$(jq -c -s --argjson head "$HEIGHT" --arg umax "$UINT64_MAX_LOCAL" '
  map(
    . as $row
    | (if .appearances > 0 then (.sig_participations / .appearances) else 0 end) as $rate
    | (if (.in_stakes | not)                            then "deregistered"
       elif .unlock_height == ($umax | tonumber)        then "active"
       elif .unlock_height >  $head                     then "pending-unlock"
       else                                                  "unlocked-pending"
       end) as $status
    | ((($row.appearances > 0) and ($rate < 0.80)))                as $low_part
    | ($row.total_slashed > 0)                                     as $slashed_any
    | ($status == "pending-unlock")                                as $pending
    | (([$low_part, $slashed_any, $pending]) | map(select(.)) | length > 0) as $anom_any
    | (
        ([
          (if $low_part    then "low_participation"     else empty end),
          (if $slashed_any then "slashed_in_window"     else empty end),
          (if $pending     then "pending_unlock_state"  else empty end)
        ])
      ) as $flags
    | $row + {
        status:             $status,
        participation_rate: $rate,
        flags:              $flags,
        anomaly:            $anom_any
      }
  )
' <"$TMP_AGG")

# Sort under --all per --sort-by; tie-break by domain ascending for stability.
case "$SORT_BY" in
  appearances)
    ROWS_JSON=$(printf '%s' "$ROWS_JSON" | jq -c '
      sort_by(-(.appearances), .domain)
    ') ;;
  participation)
    ROWS_JSON=$(printf '%s' "$ROWS_JSON" | jq -c '
      sort_by(-(.participation_rate), -(.appearances), .domain)
    ') ;;
  slashed)
    ROWS_JSON=$(printf '%s' "$ROWS_JSON" | jq -c '
      sort_by(-(.total_slashed), -(.appearances), .domain)
    ') ;;
esac

# Anomaly filter (cosmetic; alert gate uses pre-filter counts).
ANOM_COUNT=$(printf '%s' "$ROWS_JSON" | jq '[.[] | select(.anomaly)] | length')
if [ "$ANOM_ONLY" = "1" ]; then
  ROWS_JSON=$(printf '%s' "$ROWS_JSON" | jq -c '[.[] | select(.anomaly)]')
fi

WINDOW=$(( TO - FROM + 1 ))

# ── Step 5: rendering ────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  if [ "$ALL" = "1" ]; then
    # Wrap each entry with window + rpc_port for self-describing envelope.
    printf '%s' "$ROWS_JSON" | jq --argjson from "$FROM" --argjson to "$TO" --argjson port "$PORT" '
      map(. + {window: {from: $from, to: $to, blocks: ($to - $from + 1)}, rpc_port: $port})
    '
  else
    # --domain mode: single object (first / only entry).
    if [ "$(printf '%s' "$ROWS_JSON" | jq 'length')" = "0" ]; then
      # Shouldn't happen for --domain unless --anomalies-only filtered
      # the entry out; emit a clean null-record so JSON consumers don't
      # break.
      jq -n --arg d "$DOMAIN" --argjson from "$FROM" --argjson to "$TO" --argjson port "$PORT" '
        {domain: $d, status: "deregistered", window: {from: $from, to: $to, blocks: ($to - $from + 1)}, rpc_port: $port,
         appearances: 0, sig_participations: 0, participation_rate: 0, abort_count: 0, equivocation_count: 0,
         total_slashed: 0, events: [], flags: [], anomaly: false}
      '
    else
      printf '%s' "$ROWS_JSON" | jq --argjson from "$FROM" --argjson to "$TO" --argjson port "$PORT" '
        .[0] + {window: {from: $from, to: $to, blocks: ($to - $from + 1)}, rpc_port: $port}
      '
    fi
  fi
else
  # Human renderer.
  COUNT=$(printf '%s' "$ROWS_JSON" | jq 'length')

  if [ "$COUNT" = "0" ]; then
    if [ "$ANOM_ONLY" = "1" ]; then
      echo "operator_validator_history: no anomalies in window [$FROM..$TO] ($WINDOW blocks, port $PORT)"
    else
      echo "operator_validator_history: no matching validators in window [$FROM..$TO] (port $PORT)"
    fi
  else
    # Iterate; one block of output per validator.
    IDX=0
    while [ "$IDX" -lt "$COUNT" ]; do
      ROW=$(printf '%s' "$ROWS_JSON" | jq -c ".[$IDX]")
      D=$(printf '%s' "$ROW" | jq -r '.domain')
      REGION=$(printf '%s' "$ROW" | jq -r '.region')
      STATUS=$(printf '%s' "$ROW" | jq -r '.status')
      LOCKED=$(printf '%s' "$ROW" | jq -r '.locked')
      UH=$(printf '%s' "$ROW" | jq -r '.unlock_height')
      APP=$(printf '%s' "$ROW" | jq -r '.appearances')
      SIG=$(printf '%s' "$ROW" | jq -r '.sig_participations')
      RATE=$(printf '%s' "$ROW" | jq -r '.participation_rate')
      ABT=$(printf '%s' "$ROW" | jq -r '.abort_count')
      EQ=$(printf '%s' "$ROW" | jq -r '.equivocation_count')
      SLASH=$(printf '%s' "$ROW" | jq -r '.total_slashed')
      ANOM=$(printf '%s' "$ROW" | jq -r '.anomaly')

      echo "=== Validator history (domain=$D, port $PORT, window [$FROM..$TO]) ==="

      # Status line.
      case "$STATUS" in
        active)
          if [ "$UH" = "$UINT64_MAX" ]; then
            echo "Status: ACTIVE (in stakes, locked=$LOCKED, no unlock_height set)"
          else
            echo "Status: ACTIVE (in stakes, locked=$LOCKED)"
          fi
          ;;
        pending-unlock)
          echo "Status: PENDING-UNLOCK (in stakes, locked=$LOCKED, unlock_height=$UH, head=$HEIGHT)"
          ;;
        unlocked-pending)
          echo "Status: UNLOCKED-PENDING (in stakes, locked=$LOCKED, unlock_height=$UH ≤ head=$HEIGHT — UNSTAKE missed)"
          ;;
        deregistered)
          echo "Status: DEREGISTERED (not present in active stakes)"
          ;;
      esac

      # Region.
      if [ -n "$REGION" ]; then
        echo "Region: $REGION"
      else
        echo "Region: (none / global pool)"
      fi

      # Participation.
      if [ "$APP" = "0" ]; then
        echo "Committee appearances: 0 / $WINDOW blocks (0.0%)"
        echo "Signature participation: n/a (no appearances)"
      else
        # 1-decimal percentages computed in jq (bash lacks float).
        APP_PCT=$(jq -n --argjson a "$APP" --argjson w "$WINDOW" '($a / $w) * 100 | . * 10 | round / 10')
        SIG_PCT=$(jq -n --argjson s "$SIG" --argjson a "$APP" '($s / $a) * 100 | . * 10 | round / 10')
        echo "Committee appearances: $APP / $WINDOW blocks ($APP_PCT%)"
        echo "Signature participation: $SIG / $APP ($SIG_PCT%)"
      fi
      echo "Slashing events: $ABT abort, $EQ equivocation"
      echo "Total slashed in window: $SLASH"

      # Recent history (last 10 events).
      EVT_COUNT=$(printf '%s' "$ROW" | jq '.events | length')
      if [ "$EVT_COUNT" != "0" ]; then
        echo "Recent history:"
        printf '%s' "$ROW" | jq -r '
          .events
          | sort_by(.block)
          | (if length > 10 then .[length - 10:] else . end)[]
          | (
              if .kind == "REGISTER"   then "  block " + (.block|tostring) + ": REGISTER (region=" + (.region // "" | tostring) + ")"
              elif .kind == "DEREGISTER" then "  block " + (.block|tostring) + ": DEREGISTER (current_unlock_height=" + (.current_unlock_height|tostring) + ")"
              elif .kind == "ABORT"      then "  block " + (.block|tostring) + ": ABORT round=" + (.round|tostring) + " slashed=" + (.slashed|tostring)
              elif .kind == "EQUIVOCATE" then "  block " + (.block|tostring) + ": EQUIVOCATE at height=" + (.height|tostring) + " slashed=" + (.slashed|tostring)
              else "  block " + (.block|tostring) + ": " + (.kind|tostring)
              end
            )
        '
      fi

      # Health verdict.
      if [ "$ANOM" = "false" ]; then
        if [ "$APP" = "0" ]; then
          echo "[INFO] Validator did not appear in any committee over this window"
        else
          echo "[OK]   Healthy participation"
        fi
      else
        printf '%s' "$ROW" | jq -r '.flags[]' | while IFS= read -r F; do
          case "$F" in
            low_participation)
              echo "[WARN] Low participation rate (< 80%)"
              ;;
            slashed_in_window)
              echo "[WARN] Validator was slashed in this window (abort or equivocation)"
              ;;
            pending_unlock_state)
              echo "[INFO] Validator is in pending-unlock state (DEREGISTER staged)"
              ;;
          esac
        done
      fi

      echo
      IDX=$((IDX + 1))
    done

    if [ "$ALL" = "1" ]; then
      echo "Scanned $WINDOW blocks ([$FROM..$TO]) across $COUNT validator(s); sort=$SORT_BY; anomalies=$ANOM_COUNT"
    fi
  fi
fi

# Exit-code policy mirrors operator_stake_audit: --anomalies-only set
# AND ≥1 anomaly (pre-filter) → exit 2; otherwise exit 0.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
