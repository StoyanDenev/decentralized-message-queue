#!/usr/bin/env bash
# operator_randomness_beacon_audit.sh — Consensus randomness-beacon health
# audit over a window of finalized blocks. Verifies the per-block
# `cumulative_rand` beacon chain is (a) RECURRENCE-CORRECT, (b)
# NON-REPEATING, and (c) WELL-DISTRIBUTED — the three failure modes that
# signal a stuck RNG, a beacon replay, or a randomness-grinding attack.
#
# Read-only RPC composition; safe against any running daemon. The daemon
# must already be listening on --rpc-port.
#
# ── Why this tool exists (sibling positioning) ────────────────────────────────
# Determ's consensus randomness is a hash-chained beacon. Every block
# carries a 32-byte `cumulative_rand` derived from the prior block's
# beacon and the block's commit-reveal `delay_output`:
#
#     cumulative_rand[h] = SHA256( cumulative_rand[h-1] || delay_output[h] )
#
# (src/node/validator.cpp::check_cumulative_rand, lines 468-478; the
# producer side rolls the same recurrence forward). That beacon is the
# load-bearing entropy source for THREE separate consensus surfaces:
#   * committee selection (stake-weighted Fisher-Yates seed),
#   * REGISTER/DEREGISTER activation delay
#     (chain.cpp::derive_delay(cumulative_rand, tx.hash)),
#   * E3 subsidy-lottery draws
#     (chain.cpp::apply_block, lottery = first8(cumulative_rand) % M).
#
# Two existing tools merely CONSUME the beacon for a downstream metric
# and never audit the beacon stream itself:
#
#   operator_subsidy_lottery_audit.sh
#       Reads first-8-bytes(cumulative_rand) % M to classify jackpot vs
#       miss blocks. Audits the LOTTERY OUTCOME distribution, not the
#       beacon's own recurrence/uniqueness/entropy.
#
#   operator_stake_activation_audit.sh
#       Reasons about derive_delay(cumulative_rand, tx.hash) activation
#       offsets. Audits the ACTIVATION PIPELINE, not the beacon stream.
#
# Nothing in tools/ verifies the beacon chain itself. If the beacon ever
# REPEATS a value (stuck delay_output / replayed reveal), STALLS (same
# cumulative_rand across consecutive blocks), or DRIFTS off its recurrence
# (a tampered or mis-restored chain), every downstream draw above silently
# inherits a predictable or grindable seed — a quiet catastrophe no
# committee-fairness or lottery-fairness audit would attribute to its real
# cause. THIS tool is the dedicated beacon-stream health surface.
#
# ── Checks (all derived from `block-info <h> --json`) ─────────────────────────
#   (A) recurrence_correctness   For every adjacent pair (h-1, h) inside the
#                                window, recompute
#                                SHA256(cumulative_rand[h-1] || delay_output[h])
#                                and assert it equals cumulative_rand[h].
#                                A mismatch means the stored beacon does not
#                                satisfy the protocol recurrence — tampered
#                                chain data, a mis-restored snapshot, or a
#                                consensus bug. Anomaly: beacon_recurrence_break
#                                (MAX severity). Requires SHA-256 in Python
#                                hashlib (always present); the FIRST block of
#                                the window has no in-window predecessor, so
#                                recurrence is checked for pairs only — the
#                                window's opening block is the recurrence base.
#                                If --from is 0 (genesis) the genesis beacon
#                                has no delay_output predecessor and is skipped
#                                for (A) (genesis cumulative_rand is computed
#                                from genesis fields, not the recurrence).
#
#   (B) non_repetition           No two blocks in the window may share the
#                                same cumulative_rand, and no two may share
#                                the same NON-ZERO delay_output. A repeated
#                                cumulative_rand is a stalled/replayed beacon;
#                                a repeated delay_output is a replayed
#                                commit-reveal (grinding signal). The all-zero
#                                delay_output sentinel (empty-creator / genesis
#                                blocks) is exempt from the delay_output
#                                uniqueness check — multiple legitimately-empty
#                                blocks share the zero sentinel. Anomalies:
#                                beacon_value_repeat / delay_output_repeat.
#
#   (C) entropy_floor            Aggregate the per-nibble (4-bit) distribution
#                                across all cumulative_rand bytes in the window
#                                and compute the normalized Shannon entropy
#                                (in [0,1], where 1.0 == perfectly uniform over
#                                the 16 nibble values). A healthy SHA-256
#                                beacon stream sits ~1.0; a value materially
#                                below the floor (default 0.90) over a
#                                reasonable window suggests a degenerate /
#                                low-entropy beacon. Advisory by nature (a
#                                short window has high sampling variance), so
#                                the floor only fires when the sampled nibble
#                                count is large enough to be meaningful
#                                (>= --min-entropy-samples nibbles, default
#                                512 == 64 cumulative_rand bytes). Anomaly:
#                                beacon_entropy_low.
#
# ── Index semantics ──────────────────────────────────────────────────────────
# `head --field height` returns the total block COUNT (block 0 == genesis;
# highest valid index == height - 1). Mirrors operator_reward_budget.sh /
# operator_subsidy_audit.sh.
#
# Usage:
#   tools/operator_randomness_beacon_audit.sh [--rpc-port N] [--json]
#                                             [--from H] [--to H] [--last N]
#                                             [--entropy-floor PCT]
#                                             [--min-entropy-samples N]
#                                             [--anomalies-only]
#
# Options:
#   --rpc-port N             RPC port to query (default: 7778)
#   --json                   Emit a structured JSON envelope instead of human
#   --from H                 Start of window (inclusive; default: max(0, tip-1000))
#   --to H                   End of window (inclusive; default: tip)
#   --last N                 Shorthand for [tip-N+1, tip]
#                            (mutually exclusive with --from / --to)
#   --entropy-floor PCT      Normalized-entropy floor as integer percent
#                            (0..100, default 90). Below it, given enough
#                            samples, fires beacon_entropy_low.
#   --min-entropy-samples N  Minimum nibble count before the entropy floor is
#                            evaluated (default 512 == 64 beacon bytes). Below
#                            it the entropy check is reported informationally
#                            and never fires (too few samples to be meaningful).
#   --anomalies-only         Print only anomalies; exit 2 if any fire
#   -h, --help               Show this help
#
# RPC dependencies (all read-only):
#   - head        (--field height)        current chain height / tip
#   - block-info <h> --json               per-block cumulative_rand + delay_output
#
# Anomaly flags (each adds an entry to anomalies[]):
#   beacon_recurrence_break   a block's cumulative_rand != SHA256(prev || delay_output)
#   beacon_value_repeat       two blocks in the window share a cumulative_rand
#   delay_output_repeat       two blocks share a non-zero delay_output (replay/grind)
#   beacon_entropy_low        normalized nibble-entropy < floor (enough samples)
#
# Exit codes:
#   0   audit ran successfully, no anomalies (or default informational mode);
#       ALSO the clean SKIP path when the daemon is unreachable or the chain
#       has no produced blocks (INFO + exit 0)
#   1   RPC error / malformed response / bad args
#   2   --anomalies-only set AND >= 1 anomaly fired (operator alert gate)
set -u

usage() {
  cat <<'EOF'
Usage: operator_randomness_beacon_audit.sh [--rpc-port N] [--json]
                                           [--from H] [--to H] [--last N]
                                           [--entropy-floor PCT]
                                           [--min-entropy-samples N]
                                           [--anomalies-only]

Consensus randomness-beacon health audit. Walks a window of finalized
blocks via block-info and verifies the per-block `cumulative_rand` beacon
chain on three axes:
  (A) recurrence  cumulative_rand[h] == SHA256(cumulative_rand[h-1] || delay_output[h])
  (B) uniqueness  no repeated cumulative_rand; no repeated non-zero delay_output
  (C) entropy     normalized per-nibble Shannon entropy of the beacon stream

This is the dedicated beacon-stream surface that operator_subsidy_lottery_audit.sh
(lottery outcome) and operator_stake_activation_audit.sh (activation delay)
both CONSUME the beacon for but never audit. A stuck / repeated / off-recurrence
beacon silently poisons committee selection, activation delay, and the subsidy
lottery alike.

Options:
  --rpc-port N             RPC port to query (default: 7778)
  --json                   Emit a structured JSON envelope instead of human
  --from H                 Start of window (default: max(0, tip-1000))
  --to H                   End of window (default: tip)
  --last N                 Shorthand for [tip-N+1, tip] (excl. --from/--to)
  --entropy-floor PCT      Normalized-entropy floor percent 0..100 (default 90)
  --min-entropy-samples N  Min nibble count before entropy floor fires
                           (default 512 == 64 beacon bytes)
  --anomalies-only         Print only anomalies; exit 2 if any fire
  -h, --help               Show this help

RPC dependencies (read-only): head, block-info.

Anomaly flags:
  beacon_recurrence_break   cumulative_rand != SHA256(prev || delay_output)
  beacon_value_repeat       two blocks share a cumulative_rand
  delay_output_repeat       two blocks share a non-zero delay_output
  beacon_entropy_low        normalized nibble-entropy below floor (enough samples)

Exit codes:
  0   success / informational / clean SKIP (daemon unreachable or no blocks)
  1   RPC error / bad args / malformed response
  2   --anomalies-only AND >= 1 anomaly fired
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
FROM_H=""
TO_H=""
LAST_N=""
ENTROPY_FLOOR=90
MIN_ENTROPY_SAMPLES=512
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)              usage; exit 0 ;;
    --rpc-port)             PORT="${2:-}";                shift 2 ;;
    --json)                 JSON_OUT=1;                   shift ;;
    --from)                 FROM_H="${2:-}";              shift 2 ;;
    --to)                   TO_H="${2:-}";                shift 2 ;;
    --last)                 LAST_N="${2:-}";              shift 2 ;;
    --entropy-floor)        ENTROPY_FLOOR="${2:-}";       shift 2 ;;
    --min-entropy-samples)  MIN_ENTROPY_SAMPLES="${2:-}"; shift 2 ;;
    --anomalies-only)       ANOM_ONLY=1;                  shift ;;
    *) echo "operator_randomness_beacon_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Arg validation ────────────────────────────────────────────────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_randomness_beacon_audit: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for v in "$FROM_H" "$TO_H" "$LAST_N"; do
  if [ -n "$v" ]; then
    case "$v" in *[!0-9]*)
      echo "operator_randomness_beacon_audit: --from / --to / --last must be unsigned integers (got '$v')" >&2
      exit 1 ;;
    esac
  fi
done
if [ -n "$LAST_N" ] && { [ -n "$FROM_H" ] || [ -n "$TO_H" ]; }; then
  echo "operator_randomness_beacon_audit: --last cannot be combined with --from / --to" >&2
  exit 1
fi
case "$ENTROPY_FLOOR" in *[!0-9]*|"")
  echo "operator_randomness_beacon_audit: --entropy-floor must be an integer percent 0..100 (got '$ENTROPY_FLOOR')" >&2
  exit 1 ;;
esac
if [ "$ENTROPY_FLOOR" -gt 100 ]; then
  echo "operator_randomness_beacon_audit: --entropy-floor must be <= 100 (got '$ENTROPY_FLOOR')" >&2
  exit 1
fi
case "$MIN_ENTROPY_SAMPLES" in *[!0-9]*|"")
  echo "operator_randomness_beacon_audit: --min-entropy-samples must be a non-negative integer (got '$MIN_ENTROPY_SAMPLES')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# Promote DETERM to an absolute path so subprocess.run from Python works the
# same on Linux/Mac/Git Bash (matches operator_reward_budget.sh /
# operator_subsidy_audit.sh).
if [ -n "${DETERM:-}" ] && [ -x "$DETERM" ] && [ -n "${PROJECT_ROOT:-}" ]; then
  case "$DETERM" in
    /*|?:*|?:/*) DETERM_ABS="$DETERM" ;;
    *)           DETERM_ABS="$PROJECT_ROOT/$DETERM" ;;
  esac
else
  DETERM_ABS="$DETERM"
fi

# ── Step 1: resolve current tip ───────────────────────────────────────────────
# Clean SKIP (INFO + exit 0) when the daemon is unreachable — an operator
# running this in a health loop against a not-yet-started node should not see
# a hard failure. A genuine RPC error after a reachable head still exits 1.
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_randomness_beacon_audit: INFO daemon unreachable on rpc-port $PORT; nothing to audit (SKIP)"
  exit 0
}
HEAD_H=$(printf '%s' "$HEAD_H" | tr -d '[:space:]')
case "$HEAD_H" in *[!0-9]*|"")
  echo "operator_randomness_beacon_audit: head returned non-numeric '$HEAD_H' (port $PORT)" >&2
  exit 1 ;;
esac

# Empty chain (genesis only): no produced blocks to audit. INFO + SKIP.
if [ "$HEAD_H" -le 1 ]; then
  echo "operator_randomness_beacon_audit: INFO chain has no produced blocks (height=$HEAD_H); nothing to audit (SKIP)"
  exit 0
fi

# ── Step 2: resolve window bounds ─────────────────────────────────────────────
TOP=$(( HEAD_H > 0 ? HEAD_H - 1 : 0 ))
if [ -n "$LAST_N" ]; then
  if [ "$LAST_N" -lt 1 ]; then LAST_N=1; fi
  if [ "$LAST_N" -gt $(( TOP + 1 )) ]; then LAST_N=$(( TOP + 1 )); fi
  FROM=$(( TOP + 1 - LAST_N ))
  TO=$TOP
else
  FROM=${FROM_H:-$(( TOP > 1000 ? TOP - 1000 : 0 ))}
  TO=${TO_H:-$TOP}
fi
if [ "$TO" -gt "$TOP" ]; then TO=$TOP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_randomness_beacon_audit: --from ($FROM) > --to ($TO); nothing to audit" >&2
  exit 1
fi
WIN_BLOCKS=$(( TO - FROM + 1 ))

# ── Step 3: walk window + run the three beacon checks in Python ───────────────
# One block-info round-trip per block. Python recomputes the SHA-256
# recurrence, tracks value/delay_output uniqueness, and accumulates the
# nibble histogram for entropy. Emits a single TSV stats line + a small
# TSV of up to the first few recurrence-break offenders for the digest.
TMP_STATS=$(mktemp 2>/dev/null) || {
  echo "operator_randomness_beacon_audit: cannot create temp file" >&2; exit 1;
}
TMP_BREAKS=$(mktemp 2>/dev/null) || {
  echo "operator_randomness_beacon_audit: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$TMP_STATS" "$TMP_BREAKS" 2>/dev/null' EXIT

python - "$DETERM_ABS" "$PORT" "$FROM" "$TO" "$TMP_STATS" "$TMP_BREAKS" <<'PY'
import json, subprocess, sys, hashlib, math

determ, port, from_h, to_h, stats_path, breaks_path = sys.argv[1:7]
from_h = int(from_h)
to_h   = int(to_h)

ZERO64 = "0" * 64  # all-zero 32-byte (64 hex chars) delay_output sentinel

def norm_hex(s):
    if not isinstance(s, str):
        return ""
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s

def hex_bytes(s):
    """Return bytes for a hex string, or None if it isn't valid hex."""
    try:
        return bytes.fromhex(s)
    except Exception:
        return None

# Per-block parallel data, in chain order.
heights      = []
cum_list     = []   # normalized cumulative_rand hex per block
delay_list   = []   # normalized delay_output hex per block

for h in range(from_h, to_h + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_randomness_beacon_audit: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_randomness_beacon_audit: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_randomness_beacon_audit: block-info {h} returned non-JSON\n")
        sys.exit(1)
    if not isinstance(blk, dict):
        continue

    cum   = norm_hex(blk.get("cumulative_rand"))
    delay = norm_hex(blk.get("delay_output"))
    heights.append(h)
    cum_list.append(cum)
    delay_list.append(delay)

total_blocks = len(heights)
if total_blocks == 0:
    # Should not happen (FROM<=TO guaranteed above), but stay defensive.
    with open(stats_path, "w", encoding="utf-8") as f:
        f.write("\t".join(["0"] * 9) + "\n")
    open(breaks_path, "w", encoding="utf-8").close()
    sys.exit(0)

# ── (A) recurrence correctness ────────────────────────────────────────────────
# cumulative_rand[h] == SHA256( cumulative_rand[h-1] || delay_output[h] )
# Checked for adjacent in-window pairs only. The window's opening block is the
# recurrence base (its predecessor may be outside the window). When the opening
# block is genesis (height 0) there is no recurrence predecessor at all, which
# is fine — we simply have no pair starting before it.
recurrence_breaks = []   # list of (height, expected_hex, actual_hex)
for i in range(1, total_blocks):
    prev_cum = cum_list[i - 1]
    this_cum = cum_list[i]
    this_delay = delay_list[i]
    pb = hex_bytes(prev_cum)
    db = hex_bytes(this_delay)
    if pb is None or db is None or this_cum == "":
        # Missing / malformed beacon material — can't verify this pair. Treat
        # as a break (the beacon fields are mandatory on every produced block).
        recurrence_breaks.append((heights[i], "(unverifiable)", this_cum or "(empty)"))
        continue
    expected = hashlib.sha256(pb + db).hexdigest()
    if expected != this_cum:
        recurrence_breaks.append((heights[i], expected, this_cum))

# ── (B) non-repetition ────────────────────────────────────────────────────────
# cumulative_rand: any repeat is a stalled / replayed beacon.
cum_seen = {}
cum_repeat_pairs = []   # (first_height, dup_height, value)
for i, c in enumerate(cum_list):
    if c == "":
        continue
    if c in cum_seen:
        cum_repeat_pairs.append((cum_seen[c], heights[i], c))
    else:
        cum_seen[c] = heights[i]

# delay_output: any repeat of a NON-ZERO value is a replayed commit-reveal.
delay_seen = {}
delay_repeat_pairs = []
for i, d in enumerate(delay_list):
    if d == "" or d == ZERO64:
        continue
    if d in delay_seen:
        delay_repeat_pairs.append((delay_seen[d], heights[i], d))
    else:
        delay_seen[d] = heights[i]

# ── (C) entropy floor ─────────────────────────────────────────────────────────
# Per-nibble (4-bit symbol) Shannon entropy over all cumulative_rand bytes in
# the window, normalized to [0,1] against the log2(16)=4-bit maximum.
nibble_counts = [0] * 16
nibble_total = 0
for c in cum_list:
    for ch in c:
        v = "0123456789abcdef".find(ch)
        if v >= 0:
            nibble_counts[v] += 1
            nibble_total += 1

if nibble_total > 0:
    H = 0.0
    for cnt in nibble_counts:
        if cnt > 0:
            p = cnt / nibble_total
            H -= p * math.log2(p)
    norm_entropy = H / 4.0   # 4 bits == log2(16) is the max for 16 symbols
else:
    norm_entropy = 0.0
# Express normalized entropy in basis points (0..10000) so it round-trips
# through the shell as an integer without floats.
entropy_bp = int(round(norm_entropy * 10000))
if entropy_bp < 0:
    entropy_bp = 0
if entropy_bp > 10000:
    entropy_bp = 10000

with open(breaks_path, "w", encoding="utf-8") as f:
    # Up to the first 5 recurrence breaks for the human digest.
    for (hh, exp, act) in recurrence_breaks[:5]:
        f.write(f"{hh}\t{exp[:16]}\t{act[:16]}\n")

with open(stats_path, "w", encoding="utf-8") as f:
    f.write("\t".join(str(x) for x in [
        total_blocks,
        len(recurrence_breaks),
        len(cum_repeat_pairs),
        len(delay_repeat_pairs),
        nibble_total,
        entropy_bp,
        # First repeat pair samples for the digest (or 0 / "" sentinels).
        (cum_repeat_pairs[0][1]   if cum_repeat_pairs   else 0),
        (delay_repeat_pairs[0][1] if delay_repeat_pairs else 0),
        (recurrence_breaks[0][0]  if recurrence_breaks  else 0),
    ]) + "\n")
PY
if [ "$?" -ne 0 ]; then
  echo "operator_randomness_beacon_audit: beacon walk failed" >&2
  exit 1
fi

# ── Step 4: read stats back ───────────────────────────────────────────────────
STATS_LINE=$(head -1 "$TMP_STATS" 2>/dev/null || echo "")
if [ -z "$STATS_LINE" ]; then
  echo "operator_randomness_beacon_audit: empty stats payload" >&2
  exit 1
fi
TOTAL_BLOCKS=$(printf '%s'   "$STATS_LINE" | cut -f1)
RECUR_BREAKS=$(printf '%s'   "$STATS_LINE" | cut -f2)
CUM_REPEATS=$(printf '%s'    "$STATS_LINE" | cut -f3)
DELAY_REPEATS=$(printf '%s'  "$STATS_LINE" | cut -f4)
NIBBLE_TOTAL=$(printf '%s'   "$STATS_LINE" | cut -f5)
ENTROPY_BP=$(printf '%s'     "$STATS_LINE" | cut -f6)
FIRST_CUM_REPEAT=$(printf '%s'   "$STATS_LINE" | cut -f7)
FIRST_DELAY_REPEAT=$(printf '%s' "$STATS_LINE" | cut -f8)
FIRST_RECUR_BREAK=$(printf '%s'  "$STATS_LINE" | cut -f9)

# Render a basis-point value (0..10000) as "NN.NN".
render_bp() {
  local bp="$1"
  case "$bp" in *[!0-9]*|"") echo "0.00"; return ;; esac
  local whole=$(( bp / 100 ))
  local frac=$(( bp % 100 ))
  printf '%d.%02d' "$whole" "$frac"
}

# ── Step 5: anomaly classification ────────────────────────────────────────────
ANOMALIES=""
add_anom() {
  if [ -z "$ANOMALIES" ]; then ANOMALIES="$1"; else ANOMALIES="$ANOMALIES,$1"; fi
}

if [ "${RECUR_BREAKS:-0}" -gt 0 ] 2>/dev/null;  then add_anom "beacon_recurrence_break"; fi
if [ "${CUM_REPEATS:-0}" -gt 0 ] 2>/dev/null;   then add_anom "beacon_value_repeat"; fi
if [ "${DELAY_REPEATS:-0}" -gt 0 ] 2>/dev/null; then add_anom "delay_output_repeat"; fi

# Entropy floor only fires with enough samples to be meaningful.
ENTROPY_EVALUATED=0
if [ "${NIBBLE_TOTAL:-0}" -ge "$MIN_ENTROPY_SAMPLES" ] 2>/dev/null; then
  ENTROPY_EVALUATED=1
  FLOOR_BP=$(( ENTROPY_FLOOR * 100 ))
  if [ "${ENTROPY_BP:-0}" -lt "$FLOOR_BP" ] 2>/dev/null; then add_anom "beacon_entropy_low"; fi
fi

ANOM_COUNT=0
if [ -n "$ANOMALIES" ]; then
  ANOM_COUNT=$(printf '%s' "$ANOMALIES" | awk -F, '{print NF}')
fi

# ── Step 6: emit output ───────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  printf '{"window":{"from":%s,"to":%s,"blocks":%s},' "$FROM" "$TO" "$WIN_BLOCKS"
  printf '"total_blocks":%s,' "$TOTAL_BLOCKS"
  printf '"recurrence_breaks":%s,"cumulative_rand_repeats":%s,"delay_output_repeats":%s,' \
    "$RECUR_BREAKS" "$CUM_REPEATS" "$DELAY_REPEATS"
  printf '"nibble_samples":%s,"normalized_entropy_bp":%s,' "$NIBBLE_TOTAL" "$ENTROPY_BP"
  printf '"entropy_floor_pct":%s,"entropy_evaluated":%s,' "$ENTROPY_FLOOR" "$ENTROPY_EVALUATED"
  printf '"first_recurrence_break_height":%s,' "$FIRST_RECUR_BREAK"
  printf '"first_cumulative_rand_repeat_height":%s,' "$FIRST_CUM_REPEAT"
  printf '"first_delay_output_repeat_height":%s,' "$FIRST_DELAY_REPEAT"
  printf '"anomalies":['
  if [ -n "$ANOMALIES" ]; then
    printf '%s' "$ANOMALIES" | awk -F, '{
      for(i=1;i<=NF;i++){ if(i>1)printf ","; printf "\"%s\"",$i }
    }'
  fi
  printf '],"rpc_port":%s,"head_height":%s}\n' "$PORT" "$HEAD_H"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_randomness_beacon_audit: no anomalies (port $PORT, window [$FROM..$TO], $TOTAL_BLOCKS blocks)"
  else
    echo "=== Randomness-beacon audit (port $PORT, window [$FROM..$TO], $TOTAL_BLOCKS blocks) ==="
    echo "Recurrence breaks:        $RECUR_BREAKS  (cumulative_rand[h] vs SHA256(prev || delay_output[h]))"
    echo "Repeated cumulative_rand: $CUM_REPEATS"
    echo "Repeated delay_output:    $DELAY_REPEATS  (non-zero only)"
    if [ "$ENTROPY_EVALUATED" = "1" ]; then
      printf "Beacon nibble entropy:    %s%% normalized (floor %s%%, %s nibble samples)\n" \
        "$(render_bp "$ENTROPY_BP")" "$ENTROPY_FLOOR" "$NIBBLE_TOTAL"
    else
      printf "Beacon nibble entropy:    %s%% normalized (NOT evaluated — %s < %s sample floor)\n" \
        "$(render_bp "$ENTROPY_BP")" "$NIBBLE_TOTAL" "$MIN_ENTROPY_SAMPLES"
    fi
    if [ "$ANOM_ONLY" != "1" ] && [ -s "$TMP_BREAKS" ]; then
      echo "First recurrence break(s):"
      while IFS=$'\t' read -r BH BEXP BACT; do
        printf "  block %s: expected %s... got %s...\n" "$BH" "$BEXP" "$BACT"
      done <"$TMP_BREAKS"
    fi
    if [ "$ANOM_COUNT" = "0" ]; then
      echo "[OK] beacon healthy; recurrence holds, no repeats, entropy nominal"
    else
      echo "[ANOMALY] $ANOM_COUNT flag(s): $ANOMALIES"
      case ",$ANOMALIES," in
        *,beacon_recurrence_break,*)
          echo "  beacon_recurrence_break : $RECUR_BREAKS block(s) off the SHA256 recurrence (first @ block $FIRST_RECUR_BREAK) — tampered/mis-restored chain or consensus bug" ;;
      esac
      case ",$ANOMALIES," in
        *,beacon_value_repeat,*)
          echo "  beacon_value_repeat     : $CUM_REPEATS repeated cumulative_rand value(s) (first dup @ block $FIRST_CUM_REPEAT) — stalled/replayed beacon" ;;
      esac
      case ",$ANOMALIES," in
        *,delay_output_repeat,*)
          echo "  delay_output_repeat     : $DELAY_REPEATS repeated non-zero delay_output (first dup @ block $FIRST_DELAY_REPEAT) — replayed commit-reveal (grinding signal)" ;;
      esac
      case ",$ANOMALIES," in
        *,beacon_entropy_low,*)
          printf "  beacon_entropy_low      : normalized nibble entropy %s%% < %s%% floor over %s samples\n" \
            "$(render_bp "$ENTROPY_BP")" "$ENTROPY_FLOOR" "$NIBBLE_TOTAL" ;;
      esac
    fi
  fi
fi

# ── Step 7: exit-code policy ──────────────────────────────────────────────────
# Same convention as the sibling audits: exit 2 only when --anomalies-only is
# set AND >= 1 anomaly fired. Default informational mode always exits 0 if the
# RPC walk succeeded.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
