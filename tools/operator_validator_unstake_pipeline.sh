#!/usr/bin/env bash
# operator_validator_unstake_pipeline.sh — Track the pending UNSTAKE /
# DEREGISTER pipeline on a running determ daemon with per-entry
# unlock_height countdowns + completed-pipeline audit trail.
#
# Determ's validator-exit pipeline is two-step:
#   1. DEREGISTER tx (TxType=2) — sets RegistryEntry.inactive_from to
#      a randomized future height; chain.apply_transactions schedules
#      StakeEntry.unlock_height = inactive_from + unstake_delay (see
#      src/chain/chain.cpp:851).
#   2. UNSTAKE tx (TxType=4) — refunds StakeEntry.locked to the
#      validator's balance, gated by `height >= unlock_height` per
#      S-017 (validator.cpp:597 + chain.cpp:881).
#
# Operators need visibility into who's currently mid-pipeline (DEREGISTER
# applied but unlock_height not yet reached), who's eligible to UNSTAKE
# right now (unlock_height passed but no UNSTAKE tx submitted), and how
# the recent-window throughput looks (avg blocks-in-pipeline for
# completed exits, oldest still-pending exit, anomalies).
#
# Sibling-script positioning:
#
#   operator_governance_history.sh    Generic governance event timeline
#                                     (PARAM_CHANGE + DEREGISTER + REGISTER).
#                                     Surfaces DEREGISTER count + chronology
#                                     but doesn't track unlock_height
#                                     countdowns or completed-pipeline
#                                     pairing.
#
#   operator_stake_concentration.sh   Gini / top-N concentration on live
#                                     stake. Orthogonal: this script
#                                     covers EXITING stake, not the
#                                     distribution of remaining stake.
#
#   operator_validator_history.sh     Per-validator behavior history
#                                     (committee + sigs + slashing + status).
#                                     Doesn't track the exit pipeline.
#
#   operator_validator_unstake_pipeline.sh (THIS)
#                                     Cross-block pairing: DEREGISTER tx
#                                     in window W -> projected unlock_height
#                                     U = block + unstake_delay -> matching
#                                     UNSTAKE tx (if any) in the recent
#                                     completion window. Surfaces three
#                                     states (PENDING_DEREGISTER /
#                                     READY_TO_UNSTAKE / UNSTAKED_RECENT)
#                                     + anomaly flags for stuck / coordinated
#                                     / clogged pipeline events.
#
# Read-only RPC composition; safe against a running daemon.
#
# Usage:
#   tools/operator_validator_unstake_pipeline.sh --rpc-port N
#                                                [--unstake-delay N]
#                                                [--from H] [--to H]
#                                                [--include-unstaked-recently N]
#                                                [--json] [--anomalies-only]
#
# Options:
#   --rpc-port N                  RPC port to query (REQUIRED)
#   --unstake-delay N             Override the chain's unstake_delay
#                                 (default: discover via `snapshot
#                                 inspect` — same pattern as
#                                 operator_stake_concentration.sh)
#   --from H                      Start of DEREGISTER scan range
#                                 (inclusive; default: head-5000)
#   --to H                        End of DEREGISTER scan range
#                                 (inclusive; default: head)
#   --include-unstaked-recently N Also include UNSTAKE events from the
#                                 last N blocks for completed-pipeline
#                                 audit (default: 100; pass 0 to disable)
#   --json                        Emit structured JSON envelope
#   --anomalies-only              Suppress normal output unless ≥1
#                                 anomaly fires; exit 2 then
#   -h, --help                    Show this help
#
# Per-row report:
#   domain            validator domain (tx.from of DEREGISTER / UNSTAKE)
#   state             PENDING_DEREGISTER  blocks_to_unlock > 0
#                     READY_TO_UNSTAKE    blocks_to_unlock <= 0 (eligible
#                                         but UNSTAKE tx not yet seen)
#                     UNSTAKED_RECENT     UNSTAKE tx observed in the
#                                         --include-unstaked-recently window
#   dereg_block       block.index of the DEREGISTER tx (or empty for
#                     UNSTAKED_RECENT rows where DEREGISTER is outside
#                     the --from window)
#   unlock_height     dereg_block + unstake_delay (or empty for the
#                     orphan-UNSTAKE case above)
#   blocks_to_unlock  unlock_height - head_height (negative if past)
#   stake_locked      StakeEntry.locked from `determ validators --json`
#                     (0 for fully-unstaked validators)
#   unstaked_at       block.index of the UNSTAKE tx (UNSTAKED_RECENT only)
#
# Window-wide summary footer:
#   pending           count of PENDING_DEREGISTER rows
#   ready_to_unstake  count of READY_TO_UNSTAKE rows
#   unstaked_recent   count of UNSTAKED_RECENT rows
#   avg_blocks_in_pipeline   mean (unstake_block - dereg_block) over
#                            completed pairings (UNSTAKED_RECENT with
#                            matching DEREGISTER in window); none if
#                            no pairings closed in window
#   oldest_pending    smallest dereg_block of any PENDING_DEREGISTER /
#                     READY_TO_UNSTAKE row (i.e. the validator that's
#                     been in the pipeline the longest)
#
# Anomalies:
#   stuck_unstake             any READY_TO_UNSTAKE row > 1000 blocks past
#                             unlock_height — validator never claimed;
#                             either operator went dark or validator-
#                             private-key was lost. Worth review for the
#                             delegated-stake reclaim path.
#   mass_deregister_burst     > 5 PENDING_DEREGISTER entries within a
#                             100-block sub-window — coordinated
#                             validator exodus signal.
#   unstake_clog              > 20 READY_TO_UNSTAKE rows accumulated
#                             without an UNSTAKE tx in the last 100
#                             blocks — fee/subsidy underutilization.
#
# RPC dependencies (all read-only):
#   - head                        current chain height
#   - block-info <h> --json       per-block walk (DEREGISTER + UNSTAKE txs)
#   - validators --json           stake_locked per domain
#   - snapshot create + inspect   one-shot unstake_delay recovery
#                                 (skipped when --unstake-delay is passed)
#
# Exit codes:
#   0   walk completed; no anomalies (or default mode without
#       --anomalies-only)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND ≥1 anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_validator_unstake_pipeline.sh --rpc-port N
                                              [--unstake-delay N]
                                              [--from H] [--to H]
                                              [--include-unstaked-recently N]
                                              [--json] [--anomalies-only]

Track the pending UNSTAKE / DEREGISTER pipeline on a running determ
daemon with per-entry unlock_height countdowns + completed-pipeline
audit trail. Walks a window of finalized blocks, pairs DEREGISTER txs
with matching UNSTAKE txs (if any), and classifies each row into one of
three states: PENDING_DEREGISTER (unlock_height not yet reached),
READY_TO_UNSTAKE (eligible but UNSTAKE tx not yet seen), or
UNSTAKED_RECENT (UNSTAKE tx observed within the --include-unstaked-recently
window).

Options:
  --rpc-port N                  RPC port to query (REQUIRED)
  --unstake-delay N             Override chain unstake_delay (default:
                                discover via snapshot inspect)
  --from H                      Start of DEREGISTER scan range
                                (inclusive; default: head-5000)
  --to H                        End of DEREGISTER scan range
                                (inclusive; default: head)
  --include-unstaked-recently N Also surface UNSTAKE events from the
                                last N blocks (default: 100; 0 disables)
  --json                        Emit structured JSON envelope
  --anomalies-only              Suppress output unless ≥1 anomaly fires;
                                exit 2 then
  -h, --help                    Show this help

States:
  PENDING_DEREGISTER  unlock_height > head; blocks_to_unlock > 0
  READY_TO_UNSTAKE    unlock_height <= head; no UNSTAKE tx seen yet
  UNSTAKED_RECENT     UNSTAKE tx observed within the recent window

Anomalies:
  stuck_unstake            READY_TO_UNSTAKE row > 1000 blocks past unlock
  mass_deregister_burst    > 5 PENDING_DEREGISTER rows in any 100-block
                           sub-window (coordinated exit signal)
  unstake_clog             > 20 READY_TO_UNSTAKE rows accumulated in the
                           last 100 blocks (fee/subsidy underutilization)

Exit codes:
  0   walk completed; no anomalies (or default mode)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   --anomalies-only AND ≥1 anomaly fired
EOF
}

PORT=""
UNSTAKE_DELAY_OVERRIDE=""
FROM_H=""
TO_H=""
RECENT_N="100"
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                       usage; exit 0 ;;
    --rpc-port)                      PORT="${2:-}";                  shift 2 ;;
    --unstake-delay)                 UNSTAKE_DELAY_OVERRIDE="${2:-}";shift 2 ;;
    --from)                          FROM_H="${2:-}";                shift 2 ;;
    --to)                            TO_H="${2:-}";                  shift 2 ;;
    --include-unstaked-recently)     RECENT_N="${2:-}";              shift 2 ;;
    --json)                          JSON_OUT=1;                     shift ;;
    --anomalies-only)                ANOM_ONLY=1;                    shift ;;
    *) echo "operator_validator_unstake_pipeline: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# --rpc-port is required (sibling-script convention; refuses to guess
# the daemon on multi-instance hosts).
if [ -z "$PORT" ]; then
  echo "operator_validator_unstake_pipeline: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_validator_unstake_pipeline: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

# Numeric guards on remaining user-supplied integers.
for v in "$UNSTAKE_DELAY_OVERRIDE" "$FROM_H" "$TO_H" "$RECENT_N"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_validator_unstake_pipeline: --unstake-delay / --from / --to / --include-unstaked-recently must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote $DETERM to absolute (Git Bash on Windows can fail subprocess.run
# with relative paths; mirrors operator_dapp_inventory.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: resolve current head height ───────────────────────────────────────
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_validator_unstake_pipeline: cannot reach daemon on rpc-port $PORT" >&2
  exit 1
}
HEAD_H=$(printf '%s' "$HEAD_H" | tr -d '[:space:]')
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_validator_unstake_pipeline: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# ── Step 2: resolve unstake_delay ─────────────────────────────────────────────
# --unstake-delay overrides the chain reading (operators who already
# know it can avoid the snapshot round-trip). Otherwise pull via
# `snapshot inspect` (same pattern as operator_stake_concentration.sh).
UNSTAKE_DELAY=""
TMP_SNAP=""
if [ -n "$UNSTAKE_DELAY_OVERRIDE" ]; then
  UNSTAKE_DELAY="$UNSTAKE_DELAY_OVERRIDE"
else
  TMP_SNAP=$(mktemp --suffix=.json 2>/dev/null || mktemp 2>/dev/null) || {
    echo "operator_validator_unstake_pipeline: cannot create temp file" >&2
    exit 1
  }
  if ! "$DETERM" snapshot create --out "$TMP_SNAP" --rpc-port "$PORT" >/dev/null 2>&1; then
    echo "operator_validator_unstake_pipeline: snapshot create failed (port $PORT); pass --unstake-delay to bypass" >&2
    rm -f "$TMP_SNAP" 2>/dev/null
    exit 1
  fi
  INSPECT_OUT=$("$DETERM" snapshot inspect --in "$TMP_SNAP" --json 2>&1) || {
    echo "operator_validator_unstake_pipeline: snapshot inspect failed; pass --unstake-delay to bypass" >&2
    echo "$INSPECT_OUT" >&2
    rm -f "$TMP_SNAP" 2>/dev/null
    exit 1
  }
  rm -f "$TMP_SNAP" 2>/dev/null
  if [ "$HAVE_JQ" = "1" ]; then
    UNSTAKE_DELAY=$(printf '%s' "$INSPECT_OUT" | jq -r '.unstake_delay // 0')
  else
    UNSTAKE_DELAY=$(printf '%s' "$INSPECT_OUT" | grep -o '"unstake_delay":[ ]*[0-9]*' | head -1 | sed 's/.*:[ ]*//')
  fi
  case "$UNSTAKE_DELAY" in *[!0-9]*|"")
    echo "operator_validator_unstake_pipeline: snapshot inspect returned non-numeric unstake_delay; pass --unstake-delay to bypass" >&2
    exit 1 ;;
  esac
  if [ "$UNSTAKE_DELAY" = "0" ]; then
    echo "operator_validator_unstake_pipeline: snapshot reports unstake_delay=0 (bootstrap state); pass --unstake-delay to override" >&2
    exit 1
  fi
fi

# ── Step 3: resolve [FROM..TO] DEREGISTER scan window ─────────────────────────
# Default: last 5000 blocks ending at head (matches the governance-history
# sibling).
FROM=${FROM_H:-$(( HEAD_H > 5000 ? HEAD_H - 5000 : 0 ))}
TO=${TO_H:-$HEAD_H}
if [ "$TO" -gt "$HEAD_H" ]; then TO=$HEAD_H; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_validator_unstake_pipeline: --from ($FROM) > --to ($TO); nothing to scan" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# Recent-UNSTAKE window: [HEAD_H - RECENT_N + 1 .. HEAD_H] (or empty if 0).
# Bounded by genesis at the low end.
if [ "$RECENT_N" -gt 0 ]; then
  if [ "$HEAD_H" -ge "$RECENT_N" ]; then
    REC_FROM=$(( HEAD_H - RECENT_N + 1 ))
  else
    REC_FROM=0
  fi
  REC_TO=$HEAD_H
else
  REC_FROM=0
  REC_TO=0  # signals "disabled" to the python pass
fi

# ── Step 4: validators snapshot for stake_locked lookup ───────────────────────
VAL_JSON=$("$DETERM" validators --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_validator_unstake_pipeline: RPC error from \`determ validators\` (port $PORT)" >&2
  exit 1
}

# ── Step 5: per-block walk + tx classification (Python) ───────────────────────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_validator_unstake_pipeline: cannot create temp file" >&2
  exit 1
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$REC_FROM" "$REC_TO" "$RECENT_N" \
        "$HEAD_H" "$UNSTAKE_DELAY" "$TMP_OUT" <<PY
import json, subprocess, sys

determ, port, from_h, to_h, rec_from, rec_to, recent_n, head_h, unstake_delay, out_path = sys.argv[1:11]
from_h        = int(from_h);    to_h        = int(to_h)
rec_from      = int(rec_from);  rec_to      = int(rec_to)
recent_n      = int(recent_n)
head_h        = int(head_h)
unstake_delay = int(unstake_delay)

# Validators snapshot fed via heredoc env-var.
val_json = '''$VAL_JSON'''
try:
    validators = json.loads(val_json)
except Exception:
    sys.stderr.write("operator_validator_unstake_pipeline: malformed validators JSON\n")
    sys.exit(1)
if not isinstance(validators, list):
    sys.stderr.write("operator_validator_unstake_pipeline: validators RPC returned non-array\n")
    sys.exit(1)

# Domain -> stake_locked map. The validators RPC emits "stake" which is
# the locked amount (see Node::rpc_validators(); chain_.stake(domain)
# returns StakeEntry.locked).
stake_map = {}
for v in validators:
    if not isinstance(v, dict): continue
    dom = v.get("domain")
    if not isinstance(dom, str) or not dom: continue
    try:
        st = int(v.get("stake", 0) or 0)
    except Exception:
        st = 0
    stake_map[dom] = st

# TxType enum values per include/determ/chain/block.hpp:
#   REGISTER       = 1,
#   DEREGISTER     = 2,
#   UNSTAKE        = 4,
TX_DEREGISTER = 2
TX_UNSTAKE    = 4

def tx_type_int(t):
    # tx.type emitted as int per Transaction::to_json (block.cpp:38).
    if isinstance(t, int):
        return t
    if isinstance(t, str):
        try:    return int(t)
        except Exception: return -1
    return -1

# Scan range = union of [from_h..to_h] (DEREGISTER scan) ∪
# [rec_from..rec_to] (UNSTAKE recent window). Walk each block once via
# block-info, classify any matching tx into either the DEREGISTER or
# UNSTAKE bucket.
scan_lo = from_h
scan_hi = to_h
if recent_n > 0:
    scan_lo = min(scan_lo, rec_from)
    scan_hi = max(scan_hi, rec_to)
# Clamp to [0..head_h] just in case.
if scan_lo < 0:       scan_lo = 0
if scan_hi > head_h:  scan_hi = head_h

# block.index -> [(actor, tx_type)] for DEREGISTER and UNSTAKE entries.
# We also keep a per-actor map for pairing.
dereg_events  = []  # list of {actor, block}
unstake_events_recent = []  # list of {actor, block}  -- only those in [rec_from..rec_to]
# We also need to know if an actor UNSTAKEd anywhere in the scan range
# (not just the recent window) so we can suppress READY_TO_UNSTAKE rows
# that have already completed earlier. Specifically: a DEREGISTER at
# block B implies unlock_height = B + unstake_delay; if an UNSTAKE for
# the same actor lands at any block ≥ unlock_height (in scan range or
# the recent window), the row should be UNSTAKED_RECENT (if in recent)
# or excluded (if outside recent — already-completed, audit-trail
# off-window).
unstake_events_all = []  # all UNSTAKE in scan range (for pairing)

for h in range(scan_lo, scan_hi + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_validator_unstake_pipeline: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_validator_unstake_pipeline: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_validator_unstake_pipeline: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict): continue

    for tx in (blk.get("transactions") or []):
        if not isinstance(tx, dict): continue
        ti = tx_type_int(tx.get("type"))
        if ti not in (TX_DEREGISTER, TX_UNSTAKE):
            continue
        actor = tx.get("from")
        if not isinstance(actor, str) or not actor:
            continue
        if ti == TX_DEREGISTER:
            # Only count DEREGISTER inside [from_h..to_h] (the user's
            # scan window). DEREGISTER events in the recent-only
            # extension are ignored to avoid double-counting / scope creep.
            if from_h <= h <= to_h:
                dereg_events.append({"actor": actor, "block": h})
        else:  # TX_UNSTAKE
            unstake_events_all.append({"actor": actor, "block": h})
            if recent_n > 0 and rec_from <= h <= rec_to:
                unstake_events_recent.append({"actor": actor, "block": h})

# Build rows.
# 1. For every DEREGISTER, compute unlock_height = dereg_block + unstake_delay.
#    Pair with the first UNSTAKE of the same actor at block >= unlock_height
#    AND in the recent window -> UNSTAKED_RECENT row. If any UNSTAKE for the
#    actor lands at >= unlock_height OUTSIDE the recent window, mark the row
#    as completed-out-of-window and suppress (the pipeline closed; not
#    operator-actionable).
#    Otherwise classify by head_h vs unlock_height:
#      head_h >= unlock_height  -> READY_TO_UNSTAKE
#      head_h <  unlock_height  -> PENDING_DEREGISTER
# 2. Any UNSTAKE in the recent window whose actor has NO matching
#    DEREGISTER in the scan range is surfaced as an orphan UNSTAKED_RECENT
#    row (dereg_block / unlock_height empty) so operators see the full
#    completion picture even when DEREGISTER predates --from.
#
# Per-actor most-recent DEREGISTER wins (validators can re-register and
# re-deregister; we track the most recent pipeline). Sort dereg_events
# DESC by block so the first hit per actor is the latest.
dereg_events.sort(key=lambda d: (-d["block"], d["actor"]))
seen_actors = set()
latest_dereg = []
for d in dereg_events:
    if d["actor"] in seen_actors: continue
    seen_actors.add(d["actor"])
    latest_dereg.append(d)

# Per-actor UNSTAKE lookup: actor -> list of blocks ASC.
from collections import defaultdict
unstake_by_actor = defaultdict(list)
for u in unstake_events_all:
    unstake_by_actor[u["actor"]].append(u["block"])
for k in unstake_by_actor:
    unstake_by_actor[k].sort()

rows = []
paired_completion_deltas = []  # for avg_blocks_in_pipeline

for d in latest_dereg:
    actor   = d["actor"]
    db      = d["block"]
    unlock  = db + unstake_delay
    btu     = unlock - head_h  # blocks_to_unlock (negative => past)
    # Find matching UNSTAKE: first block >= unlock among unstake_by_actor.
    match_block = None
    for ub in unstake_by_actor.get(actor, []):
        if ub >= unlock:
            match_block = ub
            break
    state = ""
    unstaked_at = None
    if match_block is not None:
        # Completed pipeline. Surface only if the UNSTAKE landed in the
        # recent window (operator-visible audit trail); else completion
        # is off-window and operator-not-actionable -> skip.
        if recent_n > 0 and rec_from <= match_block <= rec_to:
            state = "UNSTAKED_RECENT"
            unstaked_at = match_block
            paired_completion_deltas.append(match_block - db)
        else:
            # Pipeline completed but completion is outside the recent
            # window: drop entirely (it's an audit-trail miss, not an
            # alert). The DEREGISTER block is still in scan range but
            # the pipeline is closed.
            continue
    else:
        if btu > 0:
            state = "PENDING_DEREGISTER"
        else:
            state = "READY_TO_UNSTAKE"
    rows.append({
        "domain":           actor,
        "state":            state,
        "dereg_block":      db,
        "unlock_height":    unlock,
        "blocks_to_unlock": btu,
        "stake_locked":     stake_map.get(actor, 0),
        "unstaked_at":      unstaked_at,
    })

# Orphan UNSTAKED_RECENT rows (no matching DEREGISTER in scan range).
dereg_actor_set = {d["actor"] for d in latest_dereg}
for u in unstake_events_recent:
    if u["actor"] in dereg_actor_set:
        # already paired (UNSTAKED_RECENT row above)
        continue
    rows.append({
        "domain":           u["actor"],
        "state":            "UNSTAKED_RECENT",
        "dereg_block":      None,
        "unlock_height":    None,
        "blocks_to_unlock": None,
        "stake_locked":     stake_map.get(u["actor"], 0),
        "unstaked_at":      u["block"],
    })

# Sort: ascending by unlock_height for PENDING / READY rows (most-imminent
# first); UNSTAKED_RECENT rows trail at the bottom sorted by unstaked_at ASC
# (oldest completion first). Rows with None unlock (orphans) sort to the
# very bottom.
def sort_key(r):
    # Tier 0: PENDING / READY with concrete unlock_height
    # Tier 1: UNSTAKED_RECENT (completed; less urgent)
    if r["state"] in ("PENDING_DEREGISTER", "READY_TO_UNSTAKE"):
        return (0, r["unlock_height"] if r["unlock_height"] is not None else 1<<62, r["domain"])
    # UNSTAKED_RECENT
    return (1, r["unstaked_at"] if r["unstaked_at"] is not None else 1<<62, r["domain"])
rows.sort(key=sort_key)

# Counts.
n_pending  = sum(1 for r in rows if r["state"] == "PENDING_DEREGISTER")
n_ready    = sum(1 for r in rows if r["state"] == "READY_TO_UNSTAKE")
n_unstaked = sum(1 for r in rows if r["state"] == "UNSTAKED_RECENT")

if paired_completion_deltas:
    avg_blocks_in_pipeline = sum(paired_completion_deltas) / len(paired_completion_deltas)
else:
    avg_blocks_in_pipeline = None

# Oldest pending: smallest dereg_block among PENDING_DEREGISTER /
# READY_TO_UNSTAKE rows.
oldest_pending = None
for r in rows:
    if r["state"] in ("PENDING_DEREGISTER", "READY_TO_UNSTAKE"):
        if oldest_pending is None or r["dereg_block"] < oldest_pending:
            oldest_pending = r["dereg_block"]

# ── Anomaly classification ──────────────────────────────────────────────────
anomalies = []

# stuck_unstake: any READY_TO_UNSTAKE entry > 1000 blocks past unlock.
STUCK_PAST_UNLOCK = 1000
stuck_domains = [r["domain"] for r in rows
                 if r["state"] == "READY_TO_UNSTAKE"
                 and r["blocks_to_unlock"] is not None
                 and r["blocks_to_unlock"] < -STUCK_PAST_UNLOCK]
if stuck_domains:
    anomalies.append("stuck_unstake")

# mass_deregister_burst: > 5 PENDING_DEREGISTER entries within a sliding
# 100-block sub-window. Iterate sorted dereg_block ASC over the
# PENDING_DEREGISTER subset; two-pointer scan.
MASS_BURST_THRESHOLD = 5
MASS_BURST_WINDOW    = 100
pending_blocks = sorted(r["dereg_block"] for r in rows
                        if r["state"] == "PENDING_DEREGISTER")
burst_hit = False
if len(pending_blocks) > MASS_BURST_THRESHOLD:
    lo = 0
    for hi in range(len(pending_blocks)):
        while pending_blocks[hi] - pending_blocks[lo] > MASS_BURST_WINDOW:
            lo += 1
        if (hi - lo + 1) > MASS_BURST_THRESHOLD:
            burst_hit = True
            break
if burst_hit:
    anomalies.append("mass_deregister_burst")

# unstake_clog: > 20 READY_TO_UNSTAKE rows accumulated AND no UNSTAKE
# tx in the last 100 blocks. Interpretation per spec: "haven't been
# claimed in the last 100 blocks" — the operator hasn't sent any
# UNSTAKE recently AND the queue is large.
CLOG_THRESHOLD     = 20
CLOG_RECENT_WINDOW = 100
recent_unstake_count = sum(1 for u in unstake_events_all
                            if u["block"] > head_h - CLOG_RECENT_WINDOW)
if n_ready > CLOG_THRESHOLD and recent_unstake_count == 0:
    anomalies.append("unstake_clog")

# ── Envelope ─────────────────────────────────────────────────────────────────
envelope = {
    "window":        {"from": from_h, "to": to_h, "block_count": (to_h - from_h + 1)},
    "head_height":   head_h,
    "unstake_delay": unstake_delay,
    "recent_window": ({"from": rec_from, "to": rec_to} if recent_n > 0 else None),
    "validators":    rows,
    "summary": {
        "pending":                n_pending,
        "ready_to_unstake":       n_ready,
        "unstaked_recent":        n_unstaked,
        "avg_blocks_in_pipeline": avg_blocks_in_pipeline,
        "oldest_pending":         oldest_pending,
    },
    "anomalies":     anomalies,
    "rpc_port":      int(port),
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(envelope, f)
PY
if [ "$?" -ne 0 ]; then exit 1; fi

# ── Step 6: render envelope ──────────────────────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" <<'PY'
import json, sys

json_out  = sys.argv[1] == "1"
anom_only = sys.argv[2] == "1"
out_path  = sys.argv[3]

with open(out_path, "r", encoding="utf-8") as f:
    env = json.load(f)

anomalies = env.get("anomalies") or []
n_anom    = len(anomalies)

if json_out:
    print(json.dumps(env))
    sys.exit(0)

port     = env["rpc_port"]
window   = env["window"]
from_h   = window["from"]
to_h     = window["to"]
win_blk  = window["block_count"]
head_h   = env["head_height"]
ud       = env["unstake_delay"]
rec      = env.get("recent_window")
rows     = env["validators"]
summary  = env["summary"]

# --anomalies-only: suppress normal output unless ≥1 anomaly fired.
if anom_only and n_anom == 0:
    print(f"operator_validator_unstake_pipeline: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}], {win_blk} blocks, "
          f"pending={summary['pending']}, ready={summary['ready_to_unstake']}, "
          f"recent={summary['unstaked_recent']})")
    sys.exit(0)

print(f"=== Validator UNSTAKE pipeline (port {port}, window [{from_h}..{to_h}], "
      f"{win_blk} blocks) ===")
print(f"head_height: {head_h}    unstake_delay: {ud}")
if rec:
    print(f"recent UNSTAKE window: [{rec['from']}..{rec['to']}]")
else:
    print("recent UNSTAKE window: (disabled)")
print()

if not rows:
    print("(no validators in DEREGISTER / UNSTAKE pipeline)")
else:
    print(f"{'domain':<28}  {'state':<18}  {'dereg_blk':>10}  "
          f"{'unlock_at':>10}  {'blks_to_unl':>11}  {'stake_lock':>12}  {'unstaked_at':>11}")
    print(f"{'-'*28:<28}  {'-'*18:<18}  {'-'*10:>10}  "
          f"{'-'*10:>10}  {'-'*11:>11}  {'-'*12:>12}  {'-'*11:>11}")
    for r in rows:
        dom = r["domain"]
        if len(dom) > 28: dom = dom[:25] + "..."
        state = r["state"]
        db = r["dereg_block"] if r["dereg_block"] is not None else "-"
        ul = r["unlock_height"] if r["unlock_height"] is not None else "-"
        btu = r["blocks_to_unlock"] if r["blocks_to_unlock"] is not None else "-"
        if isinstance(btu, int) and btu < 0:
            btu_s = f"{btu}"  # negative -> past unlock
        else:
            btu_s = str(btu)
        sl = r["stake_locked"]
        ua = r["unstaked_at"] if r["unstaked_at"] is not None else "-"
        print(f"{dom:<28}  {state:<18}  {str(db):>10}  "
              f"{str(ul):>10}  {btu_s:>11}  {sl:>12}  {str(ua):>11}")

print()
avg = summary["avg_blocks_in_pipeline"]
if avg is None:
    avg_s = "(no completed pipelines in window)"
else:
    avg_s = f"{avg:.1f} blocks"
op = summary["oldest_pending"]
op_s = str(op) if op is not None else "(none)"
print(f"Summary: pending={summary['pending']}, "
      f"ready_to_unstake={summary['ready_to_unstake']}, "
      f"unstaked_recent={summary['unstaked_recent']}")
print(f"         avg_blocks_in_pipeline={avg_s}    oldest_pending_dereg_block={op_s}")

print()
if n_anom == 0:
    print("[OK] No pipeline anomalies detected")
else:
    for a in anomalies:
        if a == "stuck_unstake":
            stuck = [r for r in rows
                     if r["state"] == "READY_TO_UNSTAKE"
                     and r.get("blocks_to_unlock") is not None
                     and r["blocks_to_unlock"] < -1000]
            doms = [r["domain"] for r in stuck]
            disp = ", ".join(doms[:3])
            if len(doms) > 3: disp += f", +{len(doms)-3} more"
            print(f"[WARN] stuck_unstake — {len(stuck)} READY_TO_UNSTAKE row(s) > 1000 blocks past unlock_height: {disp}")
        elif a == "mass_deregister_burst":
            print(f"[WARN] mass_deregister_burst — > 5 PENDING_DEREGISTER entries within a 100-block sub-window (coordinated exit signal)")
        elif a == "unstake_clog":
            print(f"[WARN] unstake_clog — {summary['ready_to_unstake']} READY_TO_UNSTAKE rows accumulated with no UNSTAKE tx in last 100 blocks")
        else:
            print(f"[WARN] {a}")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_validator_unstake_pipeline: render failed" >&2
  exit 1
fi

# ── Step 7: exit-code policy ─────────────────────────────────────────────────
# Same convention as sibling scripts: --anomalies-only AND ≥1 anomaly
# fires → exit 2. Default mode always exits 0 if the walk succeeded.
ANOM_COUNT=$(python - "$TMP_OUT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f: env = json.load(f)
print(len(env.get("anomalies") or []))
PY
)
if [ "$ANOM_ONLY" = "1" ] && [ "${ANOM_COUNT:-0}" -gt 0 ]; then
  exit 2
fi
exit 0
