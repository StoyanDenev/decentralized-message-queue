#!/usr/bin/env bash
# operator_chain_replay_speedometer.sh — Wall-clock throughput
# benchmark for a running determ daemon. Polls `head` over a fixed
# measurement window and reports blocks/sec + txs/sec aggregated +
# per-sample, so an operator commissioning a new node can answer the
# question "how fast does this hardware actually finalize blocks?"
#
# Operator pitch:
#   Sibling operator_chain_health checks "is the daemon up?"; sibling
#   operator_consensus_lag checks "is this peer behind the fleet?";
#   this script answers a third orthogonal question: "what's the
#   real-world throughput right now, measured in blocks/sec + txs/sec,
#   on this exact hardware + I/O + memory configuration?". The answer
#   exposes CPU bottlenecks, slow disks, swap pressure, or simply a
#   slow upstream chain (low real-time tx demand). Throughput is a
#   non-trivial concept under BFT consensus — block cadence is bounded
#   from above by the round timer, so observing close-to-ceiling
#   blocks/sec is healthy; observing well-below-ceiling is the
#   alertable case (chain falling behind, or this node falling behind
#   the chain).
#
# Algorithm:
#   1. Snapshot start head + start_time.
#   2. Loop for --duration-sec polling `determ head --field height`
#      every --sample-interval-sec. Record (timestamp, head) tuples.
#   3. For each newly-finalized block in the window
#      (head_at_t > head_at_prev_t), call `block-info <h> --json` and
#      sum tx_count.
#   4. Compute:
#        blocks_per_sec_avg = (head_end - head_start) / duration
#        txs_per_sec_avg    = total_txs / duration
#        per-sample blocks_per_sec  (delta / interval)
#        stddev of per-sample throughput
#
# Read-only RPC composition; safe against a running daemon. Daemon
# must already be listening on --rpc-port.
#
# Usage:
#   tools/operator_chain_replay_speedometer.sh --rpc-port N
#                                              [--duration-sec N]
#                                              [--sample-interval-sec N]
#                                              [--target-blocks-per-sec N]
#                                              [--json]
#                                              [--anomalies-only]
#
# Options:
#   --rpc-port N                 RPC port to query (required)
#   --duration-sec N             How long to measure, in seconds (default: 30)
#   --sample-interval-sec N      Poll interval, in seconds (default: 1)
#   --target-blocks-per-sec N    WARN threshold; 0 disables (default: 0)
#   --json                       Emit structured JSON envelope
#   --anomalies-only             Suppress healthy per-sample rows
#   -h, --help                   Show this help
#
# Anomalies (each adds an entry to anomalies[]):
#   throughput_below_target   (WARN)     blocks_per_sec_avg < --target-blocks-per-sec
#                                         (only fires when target > 0)
#   throughput_high_variance  (INFO)     per-sample stddev > 50% of mean
#                                         (bursty production)
#   chain_stalled             (CRITICAL) head delta == 0 across any
#                                         5-second sub-window
#
# Exit codes:
#   0   healthy (no anomalies, or only INFO anomalies)
#   1   RPC error / bad args / malformed response
#   2   anomaly fired (CRITICAL chain_stalled OR WARN throughput_below_target)
set -u

usage() {
  cat <<'EOF'
Usage: operator_chain_replay_speedometer.sh --rpc-port N
                                            [--duration-sec N]
                                            [--sample-interval-sec N]
                                            [--target-blocks-per-sec N]
                                            [--json]
                                            [--anomalies-only]

Benchmark chain-apply throughput by polling `determ head` over a fixed
window and reporting blocks/sec + txs/sec, per-sample + aggregated.
Per newly-finalized block in the window, fetches block-info and sums
the embedded transactions[] array length.

Required:
  --rpc-port N                 RPC port to query

Options:
  --duration-sec N             Measurement window in seconds (default: 30)
  --sample-interval-sec N      Poll interval in seconds (default: 1)
  --target-blocks-per-sec N    WARN below this avg rate; 0 = no threshold
                               (default: 0)
  --json                       Emit structured JSON envelope instead of
                               human table
  --anomalies-only             Suppress healthy per-sample rows; aggregate
                               row + anomalies always print
  -h, --help                   Show this help

Anomaly flags:
  throughput_below_target      (WARN)     avg blocks/sec < --target
  throughput_high_variance     (INFO)     per-sample stddev > 50% of mean
  chain_stalled                (CRITICAL) head delta == 0 over any 5s window

Exit codes:
  0   healthy (no anomalies, or only INFO anomalies)
  1   RPC error / bad args / malformed response
  2   anomaly fired (CRITICAL or WARN)
EOF
}

PORT=""
DURATION_SEC=30
INTERVAL_SEC=1
TARGET_BPS=0
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                  usage; exit 0 ;;
    --rpc-port)                 PORT="${2:-}";          shift 2 ;;
    --duration-sec)             DURATION_SEC="${2:-}";  shift 2 ;;
    --sample-interval-sec)      INTERVAL_SEC="${2:-}";  shift 2 ;;
    --target-blocks-per-sec)    TARGET_BPS="${2:-}";    shift 2 ;;
    --json)                     JSON_OUT=1;             shift ;;
    --anomalies-only)           ANOM_ONLY=1;            shift ;;
    *)
      echo "operator_chain_replay_speedometer: unknown argument: $1" >&2
      usage >&2
      exit 1 ;;
  esac
done

# ── argument validation ──────────────────────────────────────────────────────
if [ -z "$PORT" ]; then
  echo "operator_chain_replay_speedometer: --rpc-port is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_chain_replay_speedometer: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "operator_chain_replay_speedometer: --rpc-port must be 1..65535 (got '$PORT')" >&2
  exit 1
fi
case "$DURATION_SEC" in *[!0-9]*|"")
  echo "operator_chain_replay_speedometer: --duration-sec must be a positive integer (got '$DURATION_SEC')" >&2
  exit 1 ;;
esac
if [ "$DURATION_SEC" -lt 1 ]; then
  echo "operator_chain_replay_speedometer: --duration-sec must be >= 1 (got '$DURATION_SEC')" >&2
  exit 1
fi
case "$INTERVAL_SEC" in *[!0-9]*|"")
  echo "operator_chain_replay_speedometer: --sample-interval-sec must be a positive integer (got '$INTERVAL_SEC')" >&2
  exit 1 ;;
esac
if [ "$INTERVAL_SEC" -lt 1 ]; then
  echo "operator_chain_replay_speedometer: --sample-interval-sec must be >= 1 (got '$INTERVAL_SEC')" >&2
  exit 1
fi
if [ "$INTERVAL_SEC" -gt "$DURATION_SEC" ]; then
  echo "operator_chain_replay_speedometer: --sample-interval-sec ($INTERVAL_SEC) > --duration-sec ($DURATION_SEC); window too short to sample" >&2
  exit 1
fi
case "$TARGET_BPS" in *[!0-9]*|"")
  echo "operator_chain_replay_speedometer: --target-blocks-per-sec must be a non-negative integer (got '$TARGET_BPS')" >&2
  exit 1 ;;
esac

cd "$(dirname "$0")/.."
source tools/common.sh

# ── helper: extract head height ──────────────────────────────────────────────
# Bare-int via `head --field height`. Empty output => RPC error or empty
# chain. Returns "" on either failure so the caller can decide.
read_head_height() {
  local raw h
  raw=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null || true)
  h=$(printf '%s' "$raw" | tr -d '[:space:]')
  case "$h" in
    ""|*[!0-9]*) printf '' ;;
    *)           printf '%s' "$h" ;;
  esac
}

# ── pre-flight: confirm RPC reachable + read start head ──────────────────────
START_HEAD=$(read_head_height)
if [ -z "$START_HEAD" ]; then
  echo "operator_chain_replay_speedometer: cannot reach daemon on rpc-port $PORT (or chain is empty)" >&2
  exit 1
fi

# Wall-clock start. We use date +%s for second-granularity sample times;
# the duration arithmetic stays integer. The polling loop sleeps for
# --sample-interval-sec between samples; the (timestamp, head) tuples
# emitted to the pipe-delimited samples file form the row series.
START_TS=$(date -u +%s)

# Compose sample series in a temp file: one line per sample
# (sample_idx<TAB>elapsed_sec<TAB>head<TAB>delta_head). The first row
# (sample_idx=0) has delta_head=0 since there's no prior to delta
# against.
TMP_SAMPLES=$(mktemp 2>/dev/null) || {
  echo "operator_chain_replay_speedometer: cannot create temp file for samples" >&2
  exit 1
}
TMP_BLOCKS=$(mktemp 2>/dev/null) || {
  echo "operator_chain_replay_speedometer: cannot create temp file for blocks" >&2
  rm -f "$TMP_SAMPLES" 2>/dev/null
  exit 1
}
trap 'rm -f "$TMP_SAMPLES" "$TMP_BLOCKS" 2>/dev/null' EXIT

# Sample #0: snapshot at t=0 with no prior delta.
printf '0\t0\t%s\t0\n' "$START_HEAD" >>"$TMP_SAMPLES"

# Loop body. Total samples after sample-0 = floor(duration / interval).
# We sleep first then poll, so sample-1 lands at t=interval, sample-N
# lands at t=N*interval, and the final sample lands no later than
# t=duration.
SAMPLE_IDX=0
PREV_HEAD="$START_HEAD"
N_SAMPLES=$(( DURATION_SEC / INTERVAL_SEC ))

while [ "$SAMPLE_IDX" -lt "$N_SAMPLES" ]; do
  sleep "$INTERVAL_SEC"
  SAMPLE_IDX=$(( SAMPLE_IDX + 1 ))
  ELAPSED=$(( SAMPLE_IDX * INTERVAL_SEC ))
  CUR_HEAD=$(read_head_height)
  if [ -z "$CUR_HEAD" ]; then
    # Mid-window RPC failure is fatal — we'd otherwise extrapolate over a
    # gap and report bogus rates. The operator needs to know the daemon
    # vanished, not see a "throughput dropped" anomaly.
    echo "operator_chain_replay_speedometer: RPC failed mid-window at sample $SAMPLE_IDX (port $PORT)" >&2
    exit 1
  fi
  # Defensive: head shouldn't decrease (chain reorgs are bounded and
  # any drop here means a snapshot rollback). Clamp delta at 0 rather
  # than reporting negative throughput, but record the event in the
  # samples log via a 0-delta row.
  if [ "$CUR_HEAD" -ge "$PREV_HEAD" ]; then
    DELTA=$(( CUR_HEAD - PREV_HEAD ))
  else
    DELTA=0
  fi
  printf '%s\t%s\t%s\t%s\n' "$SAMPLE_IDX" "$ELAPSED" "$CUR_HEAD" "$DELTA" >>"$TMP_SAMPLES"
  PREV_HEAD="$CUR_HEAD"
done

END_HEAD="$PREV_HEAD"
END_TS=$(date -u +%s)
TOTAL_BLOCKS=$(( END_HEAD - START_HEAD ))
if [ "$TOTAL_BLOCKS" -lt 0 ]; then TOTAL_BLOCKS=0; fi

# ── fetch tx counts for each newly-finalized block ───────────────────────────
# block-info <h> --json includes a transactions[] array; we just count
# entries. Walking [START_HEAD .. END_HEAD-1] inclusive (head_index =
# height-1 convention) — actually the head value IS the height, and
# block-info accepts the index. The first newly-finalized block is
# START_HEAD (the block-at-height-START_HEAD); we fetch up to but not
# including END_HEAD (since head==END_HEAD means height==END_HEAD,
# blocks 0..END_HEAD-1 exist). Block index range: [START_HEAD .. END_HEAD-1].
#
# This matches the operator_tx_throughput.sh convention: from..to
# inclusive, where to <= height-1.
TOTAL_TXS=0
if [ "$TOTAL_BLOCKS" -gt 0 ]; then
  RANGE_FROM="$START_HEAD"
  RANGE_TO=$(( END_HEAD - 1 ))
  python - "$DETERM" "$PORT" "$RANGE_FROM" "$RANGE_TO" "$TMP_BLOCKS" <<'PY'
import json, subprocess, sys
determ, port, frm, to, out_path = sys.argv[1:6]
frm = int(frm); to = int(to)
total_txs = 0
rows = []
for h in range(frm, to + 1):
    try:
        r = subprocess.run(
            [determ, "block-info", str(h), "--json", "--rpc-port", port],
            capture_output=True, text=True, timeout=15
        )
    except Exception as e:
        sys.stderr.write(f"operator_chain_replay_speedometer: block-info {h} failed: {e}\n")
        sys.exit(1)
    if r.returncode != 0:
        sys.stderr.write(f"operator_chain_replay_speedometer: block-info {h} rc={r.returncode}\n")
        sys.stderr.write(r.stderr)
        sys.exit(1)
    try:
        blk = json.loads(r.stdout)
    except Exception:
        sys.stderr.write(f"operator_chain_replay_speedometer: block-info {h} returned non-JSON\n")
        sys.exit(1)
    txs = blk.get("transactions") or []
    if not isinstance(txs, list):
        txs = []
    n = len(txs)
    rows.append((h, n))
    total_txs += n
with open(out_path, "w", encoding="utf-8") as f:
    f.write(f"{total_txs}\n")
    for h, n in rows:
        f.write(f"{h}\t{n}\n")
PY
  PY_RC=$?
  if [ "$PY_RC" -ne 0 ]; then
    echo "operator_chain_replay_speedometer: block-info walk failed" >&2
    exit 1
  fi
  # First line of TMP_BLOCKS is total_txs; rest is per-height tx-count
  # (in case downstream wants to attribute txs to samples).
  TOTAL_TXS=$(head -1 "$TMP_BLOCKS" 2>/dev/null || echo 0)
  case "$TOTAL_TXS" in *[!0-9]*|"") TOTAL_TXS=0 ;; esac
fi

# ── stats: compute aggregates + per-sample throughput + anomalies ────────────
# Python summarizer: stddev, mean, chain-stalled sub-window detection,
# JSON / human rendering. We pass TMP_SAMPLES + TMP_BLOCKS contents
# already in temp files; the script writes its output to stdout.
python - \
  "$TMP_SAMPLES" "$TMP_BLOCKS" \
  "$PORT" "$DURATION_SEC" "$INTERVAL_SEC" "$TARGET_BPS" \
  "$START_HEAD" "$END_HEAD" "$TOTAL_BLOCKS" "$TOTAL_TXS" \
  "$START_TS" "$END_TS" \
  "$JSON_OUT" "$ANOM_ONLY" <<'PY'
import json, math, sys

(samples_path, blocks_path,
 port_s, duration_s, interval_s, target_s,
 start_head_s, end_head_s, total_blocks_s, total_txs_s,
 start_ts_s, end_ts_s,
 json_out_s, anom_only_s) = sys.argv[1:15]

port         = int(port_s)
duration     = int(duration_s)
interval     = int(interval_s)
target_bps   = int(target_s)
start_head   = int(start_head_s)
end_head     = int(end_head_s)
total_blocks = int(total_blocks_s)
total_txs    = int(total_txs_s)
start_ts     = int(start_ts_s)
end_ts       = int(end_ts_s)
json_out     = json_out_s == "1"
anom_only    = anom_only_s == "1"

# Per-height tx counts for downstream attribution (per-sample tx delta).
# Map: height -> tx_count.
heights_to_txs = {}
try:
    with open(blocks_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    # First line is the running total_txs (skip).
    for ln in lines[1:]:
        parts = ln.rstrip("\n").split("\t")
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            heights_to_txs[int(parts[0])] = int(parts[1])
except FileNotFoundError:
    # No blocks finalized in the window.
    pass

# Walk samples: each row is (sample_idx, elapsed_sec, head, delta_head).
samples = []
with open(samples_path, "r", encoding="utf-8") as f:
    for ln in f:
        parts = ln.rstrip("\n").split("\t")
        if len(parts) != 4:
            continue
        idx, elapsed, head, delta = (int(parts[0]), int(parts[1]),
                                     int(parts[2]), int(parts[3]))
        samples.append({"idx": idx, "elapsed_sec": elapsed,
                        "head": head, "delta_head": delta})

# Per-sample tx delta — sum the per-height tx counts for blocks that
# arrived between the previous sample and this one. The first sample
# (idx 0) has no prior delta (txs_since_prev = 0).
for i, s in enumerate(samples):
    if i == 0:
        s["txs_since_prev"] = 0
        continue
    prev = samples[i-1]
    prev_h = prev["head"]
    cur_h  = s["head"]
    sum_txs = 0
    if cur_h > prev_h:
        for h in range(prev_h, cur_h):
            sum_txs += heights_to_txs.get(h, 0)
    s["txs_since_prev"] = sum_txs

# Per-sample blocks/sec (delta / interval). Skip the first sample (no
# prior delta defined) — we compute stddev across the N samples that
# actually carry a delta. With duration=30s and interval=1s that's 30
# samples; with duration=30s and interval=5s that's 6 samples.
per_sample_bps = []
for s in samples[1:]:
    per_sample_bps.append(s["delta_head"] / interval)

# Aggregate blocks/sec + txs/sec — averaged across the wall-clock
# duration (NOT across the per-sample series; per-sample is a noisy
# observation of the same underlying rate).
duration_eff = max(1, duration)  # guard against div-by-zero
avg_bps = total_blocks / duration_eff
avg_tps = total_txs    / duration_eff

# Stddev across per-sample blocks/sec.
if per_sample_bps:
    mean_ps = sum(per_sample_bps) / len(per_sample_bps)
    if len(per_sample_bps) > 1:
        var = sum((x - mean_ps) ** 2 for x in per_sample_bps) / (len(per_sample_bps) - 1)
        stddev_ps = math.sqrt(var)
    else:
        stddev_ps = 0.0
else:
    mean_ps   = 0.0
    stddev_ps = 0.0

# ── anomalies ────────────────────────────────────────────────────────────────
anomalies = []

# (a) throughput_below_target — only fires when target_bps > 0. Severity WARN.
if target_bps > 0 and avg_bps < target_bps:
    anomalies.append({
        "code": "throughput_below_target",
        "severity": "WARN",
        "detail": f"avg blocks/sec {avg_bps:.3f} < target {target_bps}",
    })

# (b) throughput_high_variance — stddev > 50% of mean. Mean must be > 0
# for the ratio to be defined; we don't fire on a zero-rate chain (that's
# either chain_stalled or no traffic — caller's other gates pick it up).
if mean_ps > 0 and stddev_ps > 0.5 * mean_ps:
    anomalies.append({
        "code": "throughput_high_variance",
        "severity": "INFO",
        "detail": f"per-sample stddev {stddev_ps:.3f} > 50% of mean {mean_ps:.3f}",
    })

# (c) chain_stalled — head delta == 0 over any 5-second sub-window.
# We slide a window of size ceil(5 / interval) across the per-sample
# series and check whether the sum of deltas across that window is 0.
# If interval > 5, a single zero-delta sample already represents a
# >= 5s stall (since interval samples are >= 5s apart).
stall_window = max(1, math.ceil(5 / interval))
stall_hit = False
stall_at  = None
if len(samples) > 1:  # need at least one delta row
    # Per-sample deltas (skip sample 0).
    deltas = [s["delta_head"] for s in samples[1:]]
    if len(deltas) >= stall_window:
        for i in range(len(deltas) - stall_window + 1):
            window_sum = sum(deltas[i:i + stall_window])
            if window_sum == 0:
                stall_hit = True
                # Sub-window covers samples[i+1] .. samples[i+stall_window]
                # (1-indexed into the delta series, which itself was
                # samples[1:]). Report the elapsed timestamp at the
                # window's start.
                stall_at = samples[i + 1]["elapsed_sec"]
                break
    else:
        # Window doesn't fit (e.g. duration<5s + interval=1s). Skip the
        # check rather than flagging false positives — operator chose a
        # window too short for the stall heuristic.
        pass
if stall_hit:
    anomalies.append({
        "code": "chain_stalled",
        "severity": "CRITICAL",
        "detail": f"head delta == 0 over 5s sub-window starting at t={stall_at}s",
    })

# Exit code: 2 iff any CRITICAL or WARN anomaly fired. INFO doesn't
# trip the alert gate (it's informational about bursty production,
# which is operationally normal under low-traffic chains).
exit_code = 0
for a in anomalies:
    if a["severity"] in ("CRITICAL", "WARN"):
        exit_code = 2
        break

# ── output ───────────────────────────────────────────────────────────────────
if json_out:
    envelope = {
        "rpc_port":               port,
        "duration_sec":           duration,
        "sample_interval_sec":    interval,
        "target_blocks_per_sec":  target_bps,
        "start_head":             start_head,
        "end_head":               end_head,
        "start_ts_unix":          start_ts,
        "end_ts_unix":            end_ts,
        "samples": [
            {
                "idx":            s["idx"],
                "elapsed_sec":    s["elapsed_sec"],
                "head":           s["head"],
                "blocks_since_prev": s["delta_head"],
                "txs_since_prev": s["txs_since_prev"],
            }
            for s in samples
        ],
        "aggregate": {
            "blocks_per_sec_avg":  round(avg_bps, 6),
            "txs_per_sec_avg":     round(avg_tps, 6),
            "per_sample_mean_bps": round(mean_ps,  6),
            "per_sample_stddev":   round(stddev_ps, 6),
            "total_blocks":        total_blocks,
            "total_txs":           total_txs,
        },
        "anomalies": anomalies,
    }
    print(json.dumps(envelope))
    sys.exit(exit_code)

# Human output.
print(f"=== Chain replay speedometer (port {port}) ===")
print(f"Window: {duration}s, sample interval: {interval}s, target: "
      f"{target_bps if target_bps > 0 else 'none'} blocks/sec")
print(f"Head: {start_head} -> {end_head}  (delta = {total_blocks} blocks, "
      f"{total_txs} txs)")
print()

# Per-sample table. If --anomalies-only we skip the per-sample rows but
# still print the aggregate + anomaly stanzas (operator still needs the
# top-line numbers to triage).
if not anom_only:
    print(f"  {'t(s)':>6}  {'head':>11}  {'blk/Δ':>7}  {'tx/Δ':>7}")
    print(f"  {'-'*6}  {'-'*11}  {'-'*7}  {'-'*7}")
    for s in samples:
        print(f"  {s['elapsed_sec']:>6}  {s['head']:>11}  "
              f"{s['delta_head']:>7}  {s['txs_since_prev']:>7}")
    print()

# Aggregate row.
print("Aggregate:")
print(f"  avg blocks/sec        : {avg_bps:.3f}")
print(f"  avg txs/sec           : {avg_tps:.3f}")
print(f"  per-sample mean bps   : {mean_ps:.3f}")
print(f"  per-sample stddev bps : {stddev_ps:.3f}")
print(f"  total blocks          : {total_blocks}")
print(f"  total txs             : {total_txs}")
print()

if not anomalies:
    print("[OK] no anomalies fired")
else:
    print(f"[ANOMALY] {len(anomalies)} flag(s):")
    for a in anomalies:
        print(f"  [{a['severity']}] {a['code']:<26} {a['detail']}")

sys.exit(exit_code)
PY
RC=$?
exit $RC
