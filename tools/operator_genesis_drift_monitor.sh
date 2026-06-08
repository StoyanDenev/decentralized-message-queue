#!/usr/bin/env bash
# operator_genesis_drift_monitor.sh — Read-only RUNTIME genesis-mutation
# monitor. Polls a running determ daemon's `status` RPC `genesis` field
# repeatedly across a measurement window and ALERTS if the value ever
# changes mid-runtime.
#
# THE OPERATOR QUESTION
#   "Is the chain this daemon serves STILL the same chain it was a minute
#   ago?" The `status.genesis` field is `to_hex(chain_.at(0).compute_hash())`
#   — the live block-0 hash (see Node::rpc_status in src/node/node.cpp). On
#   a correctly-running daemon this is an immutable constant for the
#   process lifetime: the genesis block never changes once loaded. If the
#   value MUTATES while the daemon keeps serving, something illegitimate
#   happened — an illegal chain reload onto a different genesis, a block-0
#   tamper followed by a reload, or a configuration-swap attack that
#   repointed the daemon at a different chain file. None of those should
#   ever be observable on a healthy node, so any drift is a hard alert.
#
# Scope contrast with the three neighbouring genesis scripts (keep lanes
# distinct — none of them watches `status.genesis` for mutation OVER TIME):
#   operator_genesis_verify_live.sh
#       ONE-TIME: live daemon's genesis_hash (via chain-id RPC) vs the
#       hash computed from an expected genesis.json FILE. Binary pass/fail
#       on chain identity at a single instant. Answers "does this daemon
#       match my pinned genesis file right now?" — not "did it change
#       while I was watching?".
#   operator_genesis_audit.sh
#       ONE-TIME: live daemon's effective S-039 operational params
#       (m_creators, k_block_sigs, bft_enabled, ...) cross-checked against
#       a reference genesis.json. Per-parameter MATCH/DRIFT verdict at a
#       single instant. No temporal sampling.
#   operator_genesis_diff.sh / operator_genesis_dump.sh / _inspect.sh
#       FILE-only inspection / file-vs-file diff. No daemon involved.
#   operator_genesis_drift_monitor.sh
#       THIS — the temporal monitor. Samples `status.genesis` N times
#       across a bounded window and fires `genesis_drift` if ANY sample
#       differs from the established baseline. The defining behaviour is
#       repeated sampling + first-seen baseline + mutation alert, which
#       none of the one-shot scripts above provides. Optionally an
#       operator-supplied --expected-genesis <hex> pins the baseline up
#       front (so even the FIRST sample is checked, not just later ones).
#
# WHY status.genesis (not chain-id)
#   `determ status --field genesis` prints the bare 64-hex block-0 hash
#   with NO JSON envelope and exits 0 even when the chain is empty (it
#   prints a blank line in that case — see cmd_status in src/main.cpp).
#   That makes it the cheapest single-value poll. We treat an empty value
#   as "no genesis loaded yet" (a transient startup state, reported as
#   `genesis_empty`, NOT drift) so a daemon polled during boot doesn't
#   produce a false drift alert. The `chain-id` CLI returns the same hash
#   but errors out (exit 1) on the empty case, which would abort the whole
#   monitor on a mid-boot sample; `status --field genesis` is the robust
#   choice for a sampling loop.
#
# WHAT COUNTS AS DRIFT
#   Baseline = --expected-genesis if supplied, else the FIRST non-empty
#   sample observed. A sample is a DRIFT if it is non-empty AND differs
#   from the baseline. Empty samples are recorded as `genesis_empty` and
#   never establish or violate the baseline (a chain can momentarily
#   report empty during a reload window; the alert fires on the FIRST
#   non-empty sample that disagrees). If --expected-genesis was supplied
#   and the very first non-empty sample already disagrees, that is itself
#   a drift (the daemon is not serving the chain the operator pinned).
#
# Read-only RPC; safe against any running daemon. Daemon must already be
# listening on --rpc-port. No jq dependency.
#
# Usage:
#   tools/operator_genesis_drift_monitor.sh [--rpc-port N]
#                                           [--expected-genesis <hex>]
#                                           [--samples N] [--interval S]
#                                           [--json] [--anomalies-only]
#
# Options:
#   --rpc-port N            RPC port to query (default: 7778)
#   --expected-genesis HEX  Pin the baseline to a known-good 64-hex
#                           genesis hash up front (case-insensitive;
#                           normalized to lowercase). When omitted, the
#                           first non-empty sample becomes the baseline.
#   --samples N             Number of polls across the window
#                           (1..MAX_SAMPLES; default 12).
#   --interval S            Seconds to sleep between samples
#                           (0..MAX_INTERVAL; default 5). 0 = back-to-back
#                           polls (a tight burst rather than a window).
#   --json                  Emit a single-line JSON envelope.
#   --anomalies-only        Suppress healthy output; only print on drift.
#                           Exit 2 if any drift fired.
#   -h, --help              Show this help.
#
# Anomalies:
#   genesis_drift   CRITICAL — at least one sample's genesis differed from
#                              the baseline. Illegal chain reload / block-0
#                              tamper / config-swap alert.
#   genesis_empty   INFO     — at least one sample reported an empty
#                              genesis (chain not loaded / mid-reload).
#                              Informational; does NOT gate the exit code.
#
# Exit codes:
#   0   no drift (baseline held across every non-empty sample)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   genesis_drift detected (operator alert gate)
set -u

# Anti-hang hard caps. The sampling loop must terminate: --samples is
# bounded so the loop runs a fixed, finite number of times, and --interval
# is bounded so a single sleep can't wedge the script. There is no
# "follow forever" mode — operators wanting continuous monitoring wrap a
# single invocation in their own supervisor (cron / systemd timer).
MAX_SAMPLES=4320
MAX_INTERVAL=3600

usage() {
  cat <<'EOF'
Usage: operator_genesis_drift_monitor.sh [--rpc-port N]
                                         [--expected-genesis <hex>]
                                         [--samples N] [--interval S]
                                         [--json] [--anomalies-only]

Read-only RUNTIME monitor that polls a running determ daemon's
status.genesis (block-0 hash) repeatedly across a measurement window and
ALERTS if the value mutates mid-runtime. A changing genesis on a live
daemon indicates an illegal chain reload onto a different genesis, a
block-0 tamper, or a config-swap attack — none of which should ever be
observable on a healthy node.

Distinct from operator_genesis_verify_live.sh (one-time file cross-check)
and operator_genesis_audit.sh (one-time op-param cross-check): THIS script
samples over TIME and fires on mutation, which neither one-shot tool does.

Options:
  --rpc-port N            RPC port to query (default: 7778)
  --expected-genesis HEX  Pin the baseline to a known-good 64-hex hash up
                          front (case-insensitive). When omitted, the
                          first non-empty sample becomes the baseline.
  --samples N             Number of polls (1..4320; default 12)
  --interval S            Seconds between samples (0..3600; default 5;
                          0 = back-to-back burst)
  --json                  Emit a single-line JSON envelope
  --anomalies-only        Suppress healthy output; exit 2 on any drift
  -h, --help              Show this help

Anomalies:
  genesis_drift   CRITICAL — a sample's genesis differed from the baseline
  genesis_empty   INFO     — a sample reported an empty genesis (mid-load)

Exit codes:
  0   no drift (baseline held across every non-empty sample)
  1   RPC error / daemon unreachable / malformed response / bad args
  2   genesis_drift detected (operator alert gate)

JSON shape (--json):
  {"rpc_port":     P,
   "samples":      N,
   "interval":     S,
   "baseline":     "<64hex>|null",
   "baseline_source": "expected|first_sample|none",
   "observed": ["<64hex>"|"", ...],
   "distinct_genesis": ["<64hex>", ...],
   "drift_count":   int,
   "empty_count":   int,
   "first_drift_sample": int|null,
   "anomalies":    ["genesis_drift"|"genesis_empty", ...]}
EOF
}

PORT=7778
EXPECTED=""
SAMPLES=12
INTERVAL=5
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)           usage; exit 0 ;;
    --rpc-port)          PORT="${2:-}";     shift 2 ;;
    --expected-genesis)  EXPECTED="${2:-}"; shift 2 ;;
    --samples)           SAMPLES="${2:-}";  shift 2 ;;
    --interval)          INTERVAL="${2:-}"; shift 2 ;;
    --json)              JSON_OUT=1;        shift ;;
    --anomalies-only)    ANOM_ONLY=1;       shift ;;
    *) echo "operator_genesis_drift_monitor: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Argument validation (post --help so --help never trips it) ────────────────
case "$PORT" in *[!0-9]*|"")
  echo "operator_genesis_drift_monitor: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac

case "$SAMPLES" in *[!0-9]*|"")
  echo "operator_genesis_drift_monitor: --samples must be a positive integer (got '$SAMPLES')" >&2
  exit 1 ;;
esac
if [ "$SAMPLES" -lt 1 ] || [ "$SAMPLES" -gt "$MAX_SAMPLES" ]; then
  echo "operator_genesis_drift_monitor: --samples must be in 1..$MAX_SAMPLES (got '$SAMPLES')" >&2
  exit 1
fi

# --interval may be 0 (back-to-back burst); only the upper bound + the
# non-numeric guard apply.
case "$INTERVAL" in *[!0-9]*|"")
  echo "operator_genesis_drift_monitor: --interval must be a non-negative integer (got '$INTERVAL')" >&2
  exit 1 ;;
esac
if [ "$INTERVAL" -gt "$MAX_INTERVAL" ]; then
  echo "operator_genesis_drift_monitor: --interval must be in 0..$MAX_INTERVAL (got '$INTERVAL')" >&2
  exit 1
fi

# --expected-genesis, if supplied, must be exactly 64 hex chars. Normalize
# to lowercase so the comparison is case-insensitive (status emits
# lowercase via to_hex, but an operator may paste an uppercased value).
if [ -n "$EXPECTED" ]; then
  EXPECTED=$(printf '%s' "$EXPECTED" | tr 'A-Z' 'a-z' | tr -d '[:space:]')
  case "$EXPECTED" in
    *[!0-9a-f]*|"")
      echo "operator_genesis_drift_monitor: --expected-genesis must be 64 hex chars (got non-hex content)" >&2
      exit 1 ;;
  esac
  if [ ${#EXPECTED} -ne 64 ]; then
    echo "operator_genesis_drift_monitor: --expected-genesis must be exactly 64 hex chars (got ${#EXPECTED})" >&2
    exit 1
  fi
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── sample_genesis: one poll of status.genesis ────────────────────────────────
# `determ status --field genesis` prints the bare block-0 hash (no JSON
# envelope) on stdout and exits 0 even when the chain is empty (blank
# line). We distinguish three outcomes:
#   * non-empty 64-hex   -> a real genesis value (printed to stdout)
#   * empty              -> chain not loaded / mid-reload (stdout empty)
#   * RPC failure        -> non-zero exit from the CLI (daemon unreachable)
# Returns the CLI exit code; the caller treats non-zero as a hard RPC
# error and aborts (an unreachable daemon must not silently loop).
sample_genesis() {
  "$DETERM" status --field genesis --rpc-port "$PORT" 2>/dev/null
}

# ── Sampling loop ─────────────────────────────────────────────────────────────
# Collect every observed value (empty string for a blank sample) into a
# parallel array. The first non-empty sample establishes the baseline
# unless --expected-genesis pinned it up front. Any later non-empty
# sample that disagrees is a drift.
OBSERVED=()          # raw per-sample values ("" for empty)
BASELINE="$EXPECTED" # may be empty -> set from first non-empty sample
if [ -n "$EXPECTED" ]; then
  BASELINE_SOURCE="expected"
else
  BASELINE_SOURCE="none"
fi
DRIFT_COUNT=0
EMPTY_COUNT=0
FIRST_DRIFT_SAMPLE=""   # 1-based index of the first drifting sample

i=1
while [ "$i" -le "$SAMPLES" ]; do
  raw=$(sample_genesis)
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "operator_genesis_drift_monitor: RPC error from \`determ status\` (is daemon running on port $PORT?)" >&2
    exit 1
  fi
  # Normalize: strip whitespace, lowercase.
  val=$(printf '%s' "$raw" | tr 'A-Z' 'a-z' | tr -d '[:space:]')

  # Defensive: a non-empty value must be a 64-hex string. Anything else
  # means the RPC surface changed shape — treat as a hard error rather
  # than silently mis-classifying it.
  if [ -n "$val" ]; then
    case "$val" in
      *[!0-9a-f]*)
        echo "operator_genesis_drift_monitor: status.genesis returned non-hex value '$val' (port $PORT)" >&2
        exit 1 ;;
    esac
    if [ ${#val} -ne 64 ]; then
      echo "operator_genesis_drift_monitor: status.genesis returned malformed value (len ${#val}, expected 64) (port $PORT)" >&2
      exit 1
    fi
  fi

  OBSERVED+=("$val")

  if [ -z "$val" ]; then
    EMPTY_COUNT=$(( EMPTY_COUNT + 1 ))
  else
    if [ -z "$BASELINE" ]; then
      # First non-empty sample establishes the baseline.
      BASELINE="$val"
      BASELINE_SOURCE="first_sample"
    elif [ "$val" != "$BASELINE" ]; then
      DRIFT_COUNT=$(( DRIFT_COUNT + 1 ))
      if [ -z "$FIRST_DRIFT_SAMPLE" ]; then
        FIRST_DRIFT_SAMPLE="$i"
      fi
    fi
  fi

  if [ "$i" -lt "$SAMPLES" ]; then
    [ "$INTERVAL" -gt 0 ] && sleep "$INTERVAL"
  fi
  i=$(( i + 1 ))
done

# ── Analysis + emit (python: distinct-set + envelope off one accessor) ────────
python - "$JSON_OUT" "$ANOM_ONLY" "$PORT" "$SAMPLES" "$INTERVAL" \
         "$BASELINE" "$BASELINE_SOURCE" "$DRIFT_COUNT" "$EMPTY_COUNT" \
         "$FIRST_DRIFT_SAMPLE" "${OBSERVED[@]}" <<'PY'
import json, sys

json_out      = sys.argv[1] == "1"
anom_only     = sys.argv[2] == "1"
port          = int(sys.argv[3])
samples       = int(sys.argv[4])
interval      = int(sys.argv[5])
baseline      = sys.argv[6] or None
baseline_src  = sys.argv[7]
drift_count   = int(sys.argv[8])
empty_count   = int(sys.argv[9])
first_drift   = int(sys.argv[10]) if sys.argv[10] else None
observed      = list(sys.argv[11:11 + samples])

# Distinct non-empty genesis values seen, in first-seen order. On a
# healthy chain this is exactly one element (or zero if every sample was
# empty); two or more distinct values is the smoking gun for drift.
distinct = []
for v in observed:
    if v and v not in distinct:
        distinct.append(v)

anomalies = []
if drift_count > 0:
    anomalies.append("genesis_drift")
if empty_count > 0:
    anomalies.append("genesis_empty")

envelope = {
    "rpc_port":           port,
    "samples":            samples,
    "interval":           interval,
    "baseline":           baseline,
    "baseline_source":    baseline_src,
    "observed":           observed,
    "distinct_genesis":   distinct,
    "drift_count":        drift_count,
    "empty_count":        empty_count,
    "first_drift_sample": first_drift,
    "anomalies":          anomalies,
}

drift_fired = drift_count > 0

if json_out:
    print(json.dumps(envelope))
    if drift_fired:
        sys.exit(2)
    sys.exit(0)

# ── Human render ──────────────────────────────────────────────────────────────
# --anomalies-only suppresses the table when nothing drifted. genesis_empty
# alone does NOT gate the exit code, but under --anomalies-only we still
# surface a one-liner if any empty samples appeared (operator visibility).
if anom_only and not drift_fired:
    bl_disp = baseline if baseline else "(none — every sample empty)"
    if empty_count > 0:
        print(f"operator_genesis_drift_monitor: no drift "
              f"(port {port}, {samples} samples, baseline {bl_disp}; "
              f"{empty_count} empty sample(s) observed)")
    else:
        print(f"operator_genesis_drift_monitor: no drift "
              f"(port {port}, {samples} samples, baseline {bl_disp})")
    sys.exit(0)

print(f"=== Genesis drift monitor (port {port}, {samples} samples, "
      f"interval {interval}s) ===")
if baseline:
    print(f"Baseline genesis ({baseline_src}): {baseline}")
else:
    print("Baseline genesis: (none — every sample reported empty)")
print()

# Per-sample table.
idx_w = max(6, len(str(samples)))
print(f"{'sample':<{idx_w}}  {'genesis':<64}  status")
print(f"{'-'*idx_w:<{idx_w}}  {'-'*64:<64}  {'-'*6}")
for n, v in enumerate(observed, start=1):
    if not v:
        disp = "(empty)"
        st = "EMPTY"
    elif baseline is None:
        # Should not occur (a non-empty value would have set the baseline),
        # but render defensively.
        disp = v
        st = "BASE"
    elif v == baseline:
        disp = v
        st = "OK"
    else:
        disp = v
        st = "DRIFT"
    print(f"{n:<{idx_w}}  {disp:<64}  {st}")
print()

print(f"Summary: {samples} sample(s); {drift_count} drifted, "
      f"{empty_count} empty; {len(distinct)} distinct genesis value(s) seen")

if not drift_fired:
    if empty_count == samples:
        print("[OK] No drift — but every sample reported an empty genesis "
              "(chain not loaded; nothing to compare)")
    elif empty_count > 0:
        print(f"[OK] No drift — baseline held across every non-empty sample "
              f"({empty_count} empty sample(s) ignored)")
    else:
        print("[OK] No drift — genesis stable across the measurement window")
else:
    print(f"[CRITICAL] genesis_drift — {drift_count} sample(s) reported a "
          f"genesis differing from the baseline")
    print(f"           first drift at sample {first_drift}; "
          f"distinct values seen: {len(distinct)}")
    for d in distinct:
        marker = "  (baseline)" if d == baseline else "  (UNEXPECTED)"
        print(f"             {d}{marker}")
    print("           -> illegal chain reload / block-0 tamper / "
          "config-swap. Investigate immediately.")

# Exit-code policy: 2 only when genesis_drift fired. genesis_empty is
# informational and never gates the exit code. RPC errors already exited 1.
if drift_fired:
    sys.exit(2)
sys.exit(0)
PY
exit $?
