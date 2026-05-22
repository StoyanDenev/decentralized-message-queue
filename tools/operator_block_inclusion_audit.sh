#!/usr/bin/env bash
# operator_block_inclusion_audit.sh — Per-validator participation audit
# over a window of finalized blocks. Given that selection picked a
# validator for a committee, did that validator actually contribute a
# block-signature in the gather step? Anchors a separate operator
# concern from selection-fairness: SELECTION (the lottery) vs.
# PARTICIPATION (the duty).
#
# Sibling positioning:
#   operator_committee_audit.sh
#       Selection-fairness: "given stake_i, did validator i get drawn
#       in proportion to its share?" Walks creators[] only.
#   operator_validator_uptime.sh
#       Sign-participation rate bucketed into high/moderate/low tiers
#       with abort_event cross-reference. Mostly overlaps THIS script
#       on the participation axis but lacks the
#         - per-validator longest-consecutive-missed streak,
#         - single-validator filter,
#         - BFT-mode proposer-concentration tracking,
#       which are the three differentiating concerns this audit was
#       commissioned for.
#   operator_consensus_lag.sh
#       Inter-node height-divergence — orthogonal: it asks "are these
#       N nodes synced?" while this script asks "of the validators
#       selected by THIS node's chain, who actually signed?"
#
# Model:
#   For each block in the window, parse `creators[]` (the K committee
#   members) + `creator_block_sigs[]` (parallel array; each slot is a
#   64-byte Ed25519 sig or the all-zero sentinel meaning "did not
#   sign"). Per-validator across the window:
#
#       selections   = number of blocks where validator appeared in
#                      creators[]
#       signs        = number of blocks where validator's slot had a
#                      non-zero signature
#       missed       = selections - signs
#       miss_rate    = missed / selections        (undefined if 0)
#       streak       = longest run of consecutive blocks in which the
#                      validator was SELECTED but did NOT sign. The
#                      streak counter increments only on selected
#                      blocks; non-selected blocks neither extend nor
#                      reset (they are off-duty rounds for that
#                      validator). This matches how an operator
#                      thinks about downtime: "I missed 5 rounds in a
#                      row that I was responsible for."
#       proposed     = number of blocks where validator was the BFT
#                      proposer (consensus_mode == BFT; the
#                      bft_proposer field on Block names the proposer
#                      drawn from the K-of-K committee).
#
# Empty-signature sentinel:
#   block.creator_block_sigs[i] is an std::array<uint8_t,64> serialized
#   to JSON as a 128-character hex string. The all-zero sentinel
#   ("0"*128) means "validator did not sign / signature was not
#   gathered in time". Any other valid 128-char hex string counts as a
#   participation. Block.cpp's to_hex emits lowercase; we compare
#   case-insensitively as a defensive guard.
#
# BFT-mode proposer concentration:
#   Under BFT escalation (PROTOCOL.md §5.3), the producer rotates to
#   bft_proposer chosen from the smaller k_bft committee. If a single
#   validator's bft_proposer share exceeds 50% of the BFT-mode blocks
#   in the window, that's a centralization signal worth flagging —
#   either selection rotation is broken OR the operator is running a
#   degenerate committee size where one node naturally dominates.
#
# Args:
#   [--rpc-port N]                 RPC port to query (REQUIRED)
#   [--from H]                     Lower window bound, inclusive
#                                  (default: max(0, head - 999))
#   [--to H]                       Upper window bound, inclusive
#                                  (default: head)
#   [--last N]                     Shorthand for --from (head-N+1)
#                                  --to head; exclusive with --from/--to
#   [--validator <domain>]         Restrict output to a single
#                                  validator's row (everyone else
#                                  still counts toward summary
#                                  totals — the filter is cosmetic on
#                                  by_validator only)
#   [--missed-streak-threshold N]  Streak length (default 5) above
#                                  which a validator's run gets the
#                                  validator_missing_streak flag
#   [--json]                       Emit structured JSON envelope
#   [--anomalies-only]             Print only when ≥1 anomaly fires
#   [-h|--help]                    Show this help
#
# Anomaly flags:
#   validator_missing_streak  any validator's longest miss-streak
#                             exceeds --missed-streak-threshold (a
#                             potential downtime / liveness concern;
#                             validator was selected ≥ threshold+1
#                             times in a row and signed none of them)
#   validator_high_miss_rate  any validator's miss_rate > 0.20 across
#                             the window (persistent under-signing
#                             worth investigating even without a
#                             concentrated streak)
#   bft_proposer_concentration
#                             BFT mode entered for ≥1 block in the
#                             window AND a single validator was the
#                             bft_proposer for > 50% of those BFT
#                             blocks (consensus-centralization signal)
#
# Exit codes:
#   0   audit ran; no anomalies (or default informational mode)
#   1   bad args / RPC error / malformed response
#   2   --anomalies-only AND ≥1 anomaly detected
set -u

usage() {
  cat <<'EOF'
Usage: operator_block_inclusion_audit.sh --rpc-port N
                                         [--from H] [--to H] [--last N]
                                         [--validator <domain>]
                                         [--missed-streak-threshold N]
                                         [--json] [--anomalies-only]

Audit per-validator participation in block signatures over a window of
finalized blocks. For each validator that appeared on at least one
committee, tally:
  selections  — blocks where they were drawn
  signs       — blocks where their slot had a non-zero signature
  missed      — selections - signs
  miss_rate   — missed / selections
  streak      — longest run of consecutive SELECTED blocks they did
                NOT sign (off-duty rounds don't extend or reset)
  proposed    — blocks where consensus_mode == BFT AND they were
                bft_proposer

Validators are discovered from observed committees in the window
(not from the current `determ stakes` snapshot) so anyone who
deregistered mid-window is still surfaced if they have a participation
gap.

Options:
  --rpc-port N                  RPC port (REQUIRED)
  --from H                      Lower window bound, inclusive
                                (default: max(0, head - 999))
  --to H                        Upper window bound, inclusive
                                (default: head)
  --last N                      Shorthand for [head-N+1, head]
                                (exclusive with --from/--to)
  --validator <domain>          Limit per-validator output to this
                                domain; summary + anomalies still
                                computed across the full population
  --missed-streak-threshold N   Flag streaks longer than N (default: 5)
  --json                        Emit structured JSON envelope
  --anomalies-only              Print only when ≥1 anomaly fires
                                (exit 2 then)
  -h, --help                    Show this help

Anomalies:
  validator_missing_streak    longest streak > --missed-streak-threshold
  validator_high_miss_rate    miss_rate > 0.20 across the window
  bft_proposer_concentration  any single validator proposed > 50% of
                              BFT-mode blocks in the window

JSON shape:
  {"window": {"from": F, "to": T, "block_count": W,
              "bft_blocks": B},
   "rpc_port": P,
   "missed_streak_threshold": N,
   "by_validator": [
     {"domain": "...",
      "selections": S, "signs": G, "missed": M,
      "miss_rate": R, "streak": L,
      "proposed": P}, ...],
   "summary": {"n_validators": N,
               "total_signs_missed": M,
               "max_streak": L},
   "anomalies": [...]}

Exit codes:
  0   success, no anomalies (or default informational mode)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   --anomalies-only AND ≥1 anomaly detected
EOF
}

PORT=""
FROM=""
TO=""
LAST=""
VALIDATOR=""
STREAK_THRESHOLD=5
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                  usage; exit 0 ;;
    --rpc-port)                 PORT="${2:-}";              shift 2 ;;
    --from)                     FROM="${2:-}";              shift 2 ;;
    --to)                       TO="${2:-}";                shift 2 ;;
    --last)                     LAST="${2:-}";              shift 2 ;;
    --validator)                VALIDATOR="${2:-}";         shift 2 ;;
    --missed-streak-threshold)  STREAK_THRESHOLD="${2:-}";  shift 2 ;;
    --json)                     JSON_OUT=1;                 shift ;;
    --anomalies-only)           ANOM_ONLY=1;                shift ;;
    *) echo "operator_block_inclusion_audit: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

if [ -z "$PORT" ]; then
  echo "operator_block_inclusion_audit: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_block_inclusion_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

if [ -n "$LAST" ] && { [ -n "$FROM" ] || [ -n "$TO" ]; }; then
  echo "operator_block_inclusion_audit: --last cannot be combined with --from/--to" >&2
  exit 1
fi
for v in "$FROM" "$TO" "$LAST"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_block_inclusion_audit: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST" ] && [ "$LAST" = "0" ]; then
  echo "operator_block_inclusion_audit: --last must be >= 1" >&2
  exit 1
fi
case "$STREAK_THRESHOLD" in *[!0-9]*|"")
  echo "operator_block_inclusion_audit: --missed-streak-threshold must be a non-negative integer (got '$STREAK_THRESHOLD')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to absolute path so subprocess.run from Python works the
# same on Linux/Mac/Git Bash (matches operator_committee_audit.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve chain head ────────────────────────────────────────────────
HEAD_JSON=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_block_inclusion_audit: RPC error from \`determ head\` (is daemon running on port $PORT?)" >&2
  exit 1
}
HEIGHT=$(printf '%s' "$HEAD_JSON" | python -c "
import sys, json
try:
    j = json.load(sys.stdin)
    print(int(j.get('height', 0)))
except Exception:
    print('')")
case "$HEIGHT" in *[!0-9]*|"")
  echo "operator_block_inclusion_audit: malformed head JSON (height='$HEIGHT')" >&2
  exit 1 ;;
esac

# Highest finalized index = height - 1 (height is the NEXT-to-produce).
TOP=$(( HEIGHT > 0 ? HEIGHT - 1 : 0 ))

# Resolve window bounds. --last > (--from/--to) > defaults.
if [ -n "$LAST" ]; then
  if [ "$LAST" -gt $(( TOP + 1 )) ]; then
    FROM=0
  else
    FROM=$(( TOP - LAST + 1 ))
  fi
  TO=$TOP
else
  if [ -z "$TO" ]; then TO=$TOP; fi
  if [ -z "$FROM" ]; then
    if [ "$TOP" -gt 999 ]; then
      FROM=$(( TOP - 999 ))
    else
      FROM=0
    fi
  fi
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$TO" -lt "$FROM" ]; then
  echo "operator_block_inclusion_audit: --to ($TO) must be >= --from ($FROM)" >&2
  exit 1
fi
WINDOW=$(( TO - FROM + 1 ))

# ── Step 2: per-block walk + tally (driven from Python) ──────────────────────
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_block_inclusion_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_OUT" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_OUT" "$STREAK_THRESHOLD" <<'PY'
import json, subprocess, sys

determ, port, from_h, to_h, out_path, streak_t_s = sys.argv[1:7]
from_h, to_h = int(from_h), int(to_h)
streak_threshold = int(streak_t_s)

ZERO_SIG_HEX = "0" * 128  # 64 bytes of zero (canonical "didn't sign")

# Per-validator counters; lazy-populated on first observation.
#   selections  — committee draws
#   signs       — non-zero sig at parallel slot
#   missed      — selections - signs
#   proposed    — bft_proposer counter (BFT mode blocks only)
#   cur_streak  — running consecutive-missed streak counter
#   max_streak  — longest streak observed so far
# Off-duty blocks (validator not in creators[]) do NOT update streak;
# only blocks where they were SELECTED extend or reset it.
stats = {}

def get(dom):
    if dom not in stats:
        stats[dom] = {
            "selections": 0,
            "signs":      0,
            "proposed":   0,
            "cur_streak": 0,
            "max_streak": 0,
        }
    return stats[dom]

bft_blocks   = 0
bft_proposer_counts = {}    # domain -> count of bft_proposer rounds
total_signs_missed = 0
W = to_h - from_h + 1

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_block_inclusion_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_block_inclusion_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_block_inclusion_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    creators = blk.get("creators") or []
    sigs     = blk.get("creator_block_sigs") or []
    if not isinstance(creators, list): creators = []
    if not isinstance(sigs,     list): sigs     = []

    # consensus_mode is the raw uint8 enum value (MD vs BFT). Per
    # ConsensusMode in block.hpp, MD=0, BFT=1. Treat any non-zero as
    # BFT to be forward-compatible with future modes that still use a
    # named bft_proposer.
    consensus_mode = blk.get("consensus_mode", 0)
    try:
        consensus_mode = int(consensus_mode)
    except Exception:
        consensus_mode = 0
    is_bft = consensus_mode != 0
    bft_proposer = blk.get("bft_proposer", "") or ""
    if not isinstance(bft_proposer, str):
        bft_proposer = ""

    if is_bft:
        bft_blocks += 1
        if bft_proposer:
            bft_proposer_counts[bft_proposer] = \
                bft_proposer_counts.get(bft_proposer, 0) + 1

    # Per-validator update for this block. Two passes so we can rule
    # whether each entry is "selected this block" before touching its
    # streak counter.
    selected_set = set()
    for idx, dom in enumerate(creators):
        if not isinstance(dom, str) or not dom:
            continue
        selected_set.add(dom)
        s = get(dom)
        s["selections"] += 1
        signed = False
        if idx < len(sigs) and isinstance(sigs[idx], str):
            sig_hex = sigs[idx]
            # Defensive case-insensitive compare; block.cpp's to_hex
            # emits lowercase but we shouldn't rely on that.
            if sig_hex and sig_hex.lower() != ZERO_SIG_HEX:
                signed = True
        if signed:
            s["signs"] += 1
            # Selected + signed = streak resets.
            s["cur_streak"] = 0
        else:
            # Selected + missed = streak extends.
            s["cur_streak"] += 1
            if s["cur_streak"] > s["max_streak"]:
                s["max_streak"] = s["cur_streak"]
            total_signs_missed += 1

        # Off-duty blocks (validator not in creators[]) do NOT update
        # their streak — see header comment for the rationale.

    # If this block had a bft_proposer and that proposer happened to be
    # one of the validators we tally, attribute the proposed count on
    # their stats row. Note: a bft_proposer should always be in
    # creators[] (the proposer is drawn from the K-of-K committee),
    # but we add a lazy-init here in case of malformed input.
    if is_bft and bft_proposer:
        s = get(bft_proposer)
        s["proposed"] += 1

# Build per-validator records.
rows = []
for dom, s in stats.items():
    selections = s["selections"]
    signs      = s["signs"]
    missed     = selections - signs
    miss_rate  = (missed / selections) if selections > 0 else 0.0
    rows.append({
        "domain":      dom,
        "selections":  selections,
        "signs":       signs,
        "missed":      missed,
        "miss_rate":   miss_rate,
        "streak":      s["max_streak"],
        "proposed":    s["proposed"],
    })

# Rank by miss_rate desc, ties by streak desc, then domain asc. This
# puts the worst-participating validators at the top of human output.
rows.sort(key=lambda r: (-r["miss_rate"], -r["streak"], r["domain"]))

# ── Anomaly classification ──────────────────────────────────────────────────
anomalies = []

# validator_missing_streak: any row with max_streak > threshold.
if any(r["streak"] > streak_threshold for r in rows):
    anomalies.append("validator_missing_streak")

# validator_high_miss_rate: miss_rate > 0.20 AND at least one selection
# (a validator with selections=0 doesn't have a defined miss rate).
if any(r["selections"] > 0 and r["miss_rate"] > 0.20 for r in rows):
    anomalies.append("validator_high_miss_rate")

# bft_proposer_concentration: any single validator proposed > 50% of
# the BFT-mode blocks. Skipped if bft_blocks == 0 (chain never escalated
# during the window — common on healthy nets).
if bft_blocks > 0:
    for dom, cnt in bft_proposer_counts.items():
        if cnt > bft_blocks * 0.5:
            anomalies.append("bft_proposer_concentration")
            break

# Summary row.
max_streak_all = max((r["streak"] for r in rows), default=0)
summary = {
    "n_validators":       len(rows),
    "total_signs_missed": total_signs_missed,
    "max_streak":         max_streak_all,
}

envelope = {
    "window": {
        "from":        from_h,
        "to":          to_h,
        "block_count": W,
        "bft_blocks":  bft_blocks,
    },
    "missed_streak_threshold": streak_threshold,
    "by_validator":            rows,
    "summary":                 summary,
    "anomalies":               anomalies,
}

with open(out_path, "w", encoding="utf-8") as f:
    json.dump(envelope, f, allow_nan=False)
PY
if [ "$?" -ne 0 ]; then exit 1; fi

# ── Step 3: render ───────────────────────────────────────────────────────────
python - "$JSON_OUT" "$ANOM_ONLY" "$TMP_OUT" "$PORT" "$FROM" "$TO" "$WINDOW" "$STREAK_THRESHOLD" "$VALIDATOR" <<'PY'
import json, sys

json_out   = sys.argv[1] == "1"
anom_only  = sys.argv[2] == "1"
out_path   = sys.argv[3]
port       = int(sys.argv[4])
from_h     = int(sys.argv[5])
to_h       = int(sys.argv[6])
window     = int(sys.argv[7])
streak_t   = int(sys.argv[8])
validator  = sys.argv[9] if len(sys.argv) > 9 else ""

with open(out_path, "r", encoding="utf-8") as f:
    env = json.load(f)
env["rpc_port"] = port

anomalies = env.get("anomalies", []) or []
n_anom    = len(anomalies)
bft_blocks = env["window"].get("bft_blocks", 0)

# Single-validator filter is cosmetic on by_validator only; summary +
# anomalies still reflect the full population because the operator
# usually wants "show me X but tell me if the cluster has a problem
# elsewhere."
if validator:
    env["by_validator"] = [
        r for r in env["by_validator"] if r.get("domain") == validator
    ]
    env["filter_validator"] = validator

if json_out:
    print(json.dumps(env))
    sys.exit(0)

# --anomalies-only: suppress normal output unless an anomaly fired.
if anom_only and n_anom == 0:
    print(f"operator_block_inclusion_audit: no anomalies "
          f"(port {port}, window [{from_h}..{to_h}], {window} blocks)")
    sys.exit(0)

rows    = env["by_validator"]
summary = env["summary"]

print(f"=== Block inclusion audit (port {port}, window [{from_h}..{to_h}], "
      f"{window} blocks) ===")
print(f"Validators observed: {summary['n_validators']}    "
      f"Total signs missed: {summary['total_signs_missed']}    "
      f"BFT blocks: {bft_blocks}")
print(f"Missed-streak threshold: {streak_t}")
if validator:
    print(f"Filter: validator='{validator}'")
print()

if not rows:
    if validator:
        print(f"[INFO] No committee appearances by '{validator}' in window")
    else:
        print("[INFO] No committee activity observed in window")
else:
    print("Per-validator participation (ranked by miss_rate, worst first):")
    print(f"  {'domain':<28} {'selected':>8} {'signed':>7} {'missed':>7} "
          f"{'miss%':>7} {'streak':>7} {'proposed':>8}")
    print(f"  {'-'*28} {'-'*8} {'-'*7} {'-'*7} {'-'*7} {'-'*7} {'-'*8}")
    for r in rows:
        dom = r["domain"][:28]
        sel = r["selections"]
        sig = r["signs"]
        mis = r["missed"]
        mr  = f"{r['miss_rate']*100:.1f}%"
        st  = r["streak"]
        pr  = r["proposed"]
        print(f"  {dom:<28} {sel:>8} {sig:>7} {mis:>7} {mr:>7} {st:>7} {pr:>8}")

print()
print(f"Max streak across all validators: {summary['max_streak']}")

print()
if n_anom == 0:
    print("[OK] No participation anomalies")
else:
    for a in anomalies:
        if a == "validator_missing_streak":
            # Find offenders so the warning message names them.
            # Note: we use env["by_validator"] AFTER the optional
            # validator filter; that's fine because the original
            # full-population check fired before filtering, and the
            # render-side message just enumerates whatever rows are
            # left to show. If the operator filtered out the offender
            # the anomaly still surfaces as the flag — that's the
            # contract for "filter is cosmetic".
            offenders = [
                f"{r['domain']} (streak={r['streak']})"
                for r in env["by_validator"]
                if r["streak"] > streak_t
            ]
            disp = ", ".join(offenders[:3])
            if len(offenders) > 3:
                disp += f", +{len(offenders)-3} more"
            elif not offenders:
                disp = "(filtered out; see envelope without --validator)"
            print(f"[WARN] validator_missing_streak — streak > {streak_t}: {disp}")
        elif a == "validator_high_miss_rate":
            offenders = [
                f"{r['domain']} ({r['miss_rate']*100:.1f}%)"
                for r in env["by_validator"]
                if r["selections"] > 0 and r["miss_rate"] > 0.20
            ]
            disp = ", ".join(offenders[:3])
            if len(offenders) > 3:
                disp += f", +{len(offenders)-3} more"
            elif not offenders:
                disp = "(filtered out; see envelope without --validator)"
            print(f"[WARN] validator_high_miss_rate — miss_rate > 20%: {disp}")
        elif a == "bft_proposer_concentration":
            print(f"[WARN] bft_proposer_concentration — a single validator "
                  f"proposed > 50% of {bft_blocks} BFT-mode block(s)")
        else:
            print(f"[WARN] {a}")
PY
PY_RC=$?
if [ "$PY_RC" -ne 0 ]; then
  echo "operator_block_inclusion_audit: rendering failed (rc=$PY_RC)" >&2
  exit 1
fi

# ── Step 4: exit-code policy ────────────────────────────────────────────────
ANOM_COUNT=$(python - "$TMP_OUT" <<'PY'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f: env = json.load(f)
print(len(env.get("anomalies") or []))
PY
)
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
