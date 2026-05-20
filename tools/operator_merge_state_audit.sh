#!/usr/bin/env bash
# operator_merge_state_audit.sh — R7 under-quorum-merge audit. Probes a
# running determ daemon for:
#   1. Currently-merged shard pairs (from chain.merge_state — sourced via
#      a transient `determ snapshot create` since `status --json` does
#      NOT expose merge_state).
#   2. Recent MERGE_EVENT transactions (TxType == 7) in the chain's block
#      tail; classifies each as MERGE_BEGIN (event_type=0) or MERGE_END
#      (event_type=1), decodes the canonical wire format
#      (see src/chain/block.cpp::MergeEvent::encode/decode).
#   3. Anomalies: long-running merges (> threshold blocks since BEGIN
#      with no END), unmatched BEGINs (potentially stuck), and
#      instability (multiple BEGIN/END cycles for the same shard pair
#      within a short window).
#
# R7 background: under EXTENDED sharding, when shard S's eligible pool
# in its region falls below 2K, the beacon may emit MERGE_BEGIN(S, S+1)
# to temporarily route S's committee operations through its modular-next
# partner shard. A later MERGE_END(S, S+1) reverts. Both txs ride inside
# beacon blocks (no per-tx multisig — they piggyback the K-of-K block
# sigs). The chain's merge_state map is the apply-time projection: BEGIN
# inserts, END erases.
#
# Mode gate: this primitive ONLY exists under sharding_mode=extended.
# Under sharding_mode=current (single-shard or default-shard) the
# daemon's `validator.cpp` rejects MERGE_EVENT outright; merge_state is
# permanently empty. The script detects this from `status --json` /
# `summary.protections.sharding_mode` and short-circuits with an INFO.
# Single-shard (shard_count <= 1) deployments also short-circuit since
# the modular-next partner is the shard itself — merges are structurally
# impossible.
#
# Usage:
#   tools/operator_merge_state_audit.sh [--rpc-port N] [--json]
#                                       [--anomalies-only]
#                                       [--window N]
#                                       [--long-merge-threshold N]
#                                       [--instability-window N]
#                                       [--instability-min-cycles N]
#
# Options:
#   --rpc-port N                RPC port to query (default: 7778)
#   --json                      Emit structured JSON envelope
#   --anomalies-only            Suppress normal output unless an anomaly
#                                fired; exit 2 if anomalies present
#   --window N                  Block window to scan for MERGE_EVENT txs
#                                (default: 1000; clamped to chain height)
#   --long-merge-threshold N    Anomaly: BEGIN with no matching END for
#                                more than N blocks (default: 1000)
#   --instability-window N      Sliding window in blocks for the
#                                instability anomaly (default: matches
#                                --window)
#   --instability-min-cycles N  Anomaly threshold: >= N BEGIN/END cycles
#                                for the same shard pair inside the
#                                instability window (default: 3)
#
# RPC dependencies (all read-only):
#   - status   (sharding_mode under .protections.sharding_mode; shard_id)
#   - snapshot (carries merge_state[]; called with --headers 0 to minimize
#                payload — only chain-state needed, no block tail)
#   - head     (chain height, for default window upper bound)
#   - block    (per-block JSON; via `determ block-info <i> --json` so the
#                `transactions` field is preserved — note: the headers
#                RPC strips transactions for light-client sync, so we
#                MUST go one block at a time)
#
# Anomaly catalogue:
#   long_running_merge   BEGIN(shard,partner) at height H with no END
#                        in (H, H + --long-merge-threshold] AND current
#                        merge_state still has shard merged. (Operators
#                        should investigate the refugee shard's pool
#                        recovery.)
#   stuck_merge          BEGIN(shard,partner) at height H older than
#                        --long-merge-threshold blocks with NO matching
#                        END found anywhere in the scan window AND
#                        merge_state still has shard merged. (Functional
#                        subset of long_running_merge — surfaces
#                        separately for operators tracking unmatched
#                        BEGINs in case the scan window happens to
#                        truncate an END that exists.)
#   instability          For any (shard, partner) pair, >= --instability-
#                        min-cycles BEGIN/END pairs inside any
#                        instability_window. Signals committee health
#                        oscillating around the 2K threshold.
#
# Exit codes:
#   0   audit completed; no anomalies (or single-shard / non-extended skip)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   --anomalies-only AND >= 1 anomaly detected
set -u

usage() {
  cat <<'EOF'
Usage: operator_merge_state_audit.sh [--rpc-port N] [--json]
                                     [--anomalies-only]
                                     [--window N]
                                     [--long-merge-threshold N]
                                     [--instability-window N]
                                     [--instability-min-cycles N]

R7 under-quorum-merge audit. Probes a running determ daemon for current
merge_state (which shards are merged into which partners) and recent
MERGE_EVENT transactions (MERGE_BEGIN + MERGE_END), then flags anomalies
indicative of committee-health problems.

Single-shard (shard_count <= 1) and non-extended (sharding_mode !=
extended) deployments exit 0 with an INFO since the R7 primitive is
inactive on those configurations.

Options:
  --rpc-port N                RPC port to query (default: 7778)
  --json                      Emit structured JSON envelope
  --anomalies-only            Suppress output unless anomalies fired;
                               exit 2 if anomalies present
  --window N                  Blocks to scan for MERGE_EVENT txs
                               (default: 1000)
  --long-merge-threshold N    BEGIN with no END within N blocks ->
                               long_running_merge anomaly (default: 1000)
  --instability-window N      Sliding window for instability check
                               (default: same as --window)
  --instability-min-cycles N  Cycles within instability window to flag
                               an instability anomaly (default: 3)
  -h, --help                  Show this help

Anomalies:
  long_running_merge   BEGIN > threshold blocks ago, no matching END,
                       shard still in merge_state
  stuck_merge          BEGIN with no END anywhere in the scan window,
                       shard still in merge_state
  instability          >= N BEGIN/END cycles for same (shard,partner)
                       within instability_window

JSON shape:
  {
    "rpc_port": P,
    "sharding_mode": "current|extended|none",
    "shard_count": S,
    "my_shard_id": I,
    "height": H,
    "scan_from": F,
    "scan_to": T,
    "current_merges":   [{"shard_id":S,"partner_id":P,"refugee_region":"..."}],
    "begin_events":     [{"block_index":B,"shard_id":S,"partner_id":P,
                          "effective_height":E,"refugee_region":"...",
                          "evidence_window_start":W,"terminator":"..."}],
    "end_events":       [{"block_index":B,"shard_id":S,"partner_id":P,
                          "effective_height":E,"terminator":"...",
                          "matched_begin_block":B0,"duration_blocks":D}],
    "anomalies":        ["..."],
    "anomaly_details":  {
        "long_running_merge": [{"shard_id":S,"partner_id":P,
                                "begin_block":B,"age_blocks":A}],
        "stuck_merge":        [{"shard_id":S,"partner_id":P,"begin_block":B}],
        "instability":        [{"shard_id":S,"partner_id":P,"cycles":N,
                                "window":[F,T]}]
    }
  }

Exit codes:
  0   audit completed; no anomalies (or single-shard / non-extended skip)
  1   RPC / args / decode failure
  2   --anomalies-only AND >= 1 anomaly detected
EOF
}

PORT=7778
JSON_OUT=0
ANOM_ONLY=0
WINDOW=1000
LONG_THRESHOLD=1000
INSTABILITY_WINDOW=""
INSTABILITY_MIN_CYCLES=3
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                 usage; exit 0 ;;
    --rpc-port)                PORT="${2:-}";                  shift 2 ;;
    --json)                    JSON_OUT=1;                     shift ;;
    --anomalies-only)          ANOM_ONLY=1;                    shift ;;
    --window)                  WINDOW="${2:-}";                shift 2 ;;
    --long-merge-threshold)    LONG_THRESHOLD="${2:-}";        shift 2 ;;
    --instability-window)      INSTABILITY_WINDOW="${2:-}";    shift 2 ;;
    --instability-min-cycles)  INSTABILITY_MIN_CYCLES="${2:-}";shift 2 ;;
    *) echo "operator_merge_state_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guards.
for pair in "PORT=$PORT" "WINDOW=$WINDOW" "LONG_THRESHOLD=$LONG_THRESHOLD" \
            "INSTABILITY_MIN_CYCLES=$INSTABILITY_MIN_CYCLES"; do
  name="${pair%%=*}"; val="${pair#*=}"
  case "$val" in
    *[!0-9]*|"")
      echo "operator_merge_state_audit: --$(echo "$name" | tr '[:upper:]_' '[:lower:]-') must be a positive integer (got '$val')" >&2
      exit 1 ;;
  esac
done
if [ -n "$INSTABILITY_WINDOW" ]; then
  case "$INSTABILITY_WINDOW" in
    *[!0-9]*) echo "operator_merge_state_audit: --instability-window must be a positive integer" >&2; exit 1 ;;
  esac
fi
if [ "$PORT" -lt 1 ];                   then echo "operator_merge_state_audit: --rpc-port must be >= 1" >&2; exit 1; fi
if [ "$WINDOW" -lt 1 ];                 then echo "operator_merge_state_audit: --window must be >= 1" >&2; exit 1; fi
if [ "$LONG_THRESHOLD" -lt 1 ];         then echo "operator_merge_state_audit: --long-merge-threshold must be >= 1" >&2; exit 1; fi
if [ "$INSTABILITY_MIN_CYCLES" -lt 1 ]; then echo "operator_merge_state_audit: --instability-min-cycles must be >= 1" >&2; exit 1; fi

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_merge_state_audit: python (or python3) is required for MERGE_EVENT payload decoding" >&2
  exit 1
fi
PY_BIN=python
command -v python >/dev/null 2>&1 || PY_BIN=python3

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: probe sharding_mode + shard_id from status --json ─────────────────
STATUS_OUT=$("$DETERM" status --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_merge_state_audit: RPC error from \`determ status\` (is daemon running on port $PORT?)" >&2
  exit 1
}
if [ "$HAVE_JQ" = "1" ]; then
  SHARDING_MODE=$(printf '%s' "$STATUS_OUT" | jq -r '.protections.sharding_mode // "current"')
  MY_SHARD_ID=$(printf '%s' "$STATUS_OUT"   | jq -r '.shard_id // 0')
else
  # Best-effort grep fallback — protections is a nested object so we
  # match the field directly. Both keys appear once in status JSON.
  SHARDING_MODE=$(printf '%s' "$STATUS_OUT" | grep -o '"sharding_mode":"[^"]*"' | head -1 | sed 's/.*:"\([^"]*\)".*/\1/')
  [ -z "$SHARDING_MODE" ] && SHARDING_MODE="current"
  MY_SHARD_ID=$(printf '%s' "$STATUS_OUT" | grep -o '"shard_id":[0-9]*' | head -1 | sed 's/.*: *//')
  [ -z "$MY_SHARD_ID" ] && MY_SHARD_ID=0
fi
case "$MY_SHARD_ID" in *[!0-9]*|"") MY_SHARD_ID=0 ;; esac

# ── Step 2: fetch chain-state snapshot for merge_state + shard_count ──────────
# `status --json` does not surface shard_count or merge_state; the
# canonical snapshot does (serialize_state). Pass --headers 0 to avoid
# emitting a 16-header tail we don't need.
#
# `snapshot create` without --out prints the snapshot JSON to stdout
# (pretty-printed with indent=2).
SNAP_JSON=$("$DETERM" snapshot create --headers 0 --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_merge_state_audit: RPC error from \`determ snapshot create\` (port $PORT)" >&2
  exit 1
}
# `snapshot create` may print informational lines before/after when
# writing to a file; with no --out it emits ONLY the JSON document.
# Sanity-check by looking for the opening `{`.
case "$SNAP_JSON" in
  '{'*) : ;;
  *)
    # Drop any leading non-JSON lines (defensive — shouldn't happen with
    # current main.cpp behavior but pinned here for robustness).
    SNAP_JSON=$(printf '%s' "$SNAP_JSON" | sed -n '/^{/,$p')
    case "$SNAP_JSON" in
      '{'*) : ;;
      *) echo "operator_merge_state_audit: snapshot output is not JSON (port $PORT)" >&2; exit 1 ;;
    esac
    ;;
esac

# Resolve current head height (drives default scan window upper bound).
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null | tr -d '\r\n ') || {
  echo "operator_merge_state_audit: RPC error from \`determ head\`" >&2; exit 1;
}
case "$HEAD_H" in *[!0-9]*|"") echo "operator_merge_state_audit: head returned non-numeric '$HEAD_H'" >&2; exit 1 ;; esac

# Default instability window mirrors --window so operators only have to
# tune one knob unless they care about the distinction.
[ -z "$INSTABILITY_WINDOW" ] && INSTABILITY_WINDOW="$WINDOW"

# Compute scan range [SCAN_FROM, SCAN_TO]. `head --field height` returns
# the count of finalized blocks (= next-to-produce index); the highest
# finalized index is HEAD_H - 1. Empty chain (HEAD_H = 0) handled in
# Python below.
SCAN_TO=$(( HEAD_H > 0 ? HEAD_H - 1 : 0 ))
SCAN_FROM=$(( SCAN_TO + 1 > WINDOW ? SCAN_TO + 1 - WINDOW : 0 ))

# ── Step 3: Python-driven block walk + decode + render ────────────────────────
# Wire format of MERGE_EVENT payload (src/chain/block.cpp::MergeEvent::encode):
#   [0]      event_type (0=BEGIN, 1=END)
#   [1..4]   shard_id            (u32 LE)
#   [5..8]   partner_id          (u32 LE)
#   [9..16]  effective_height    (u64 LE)
#   [17..24] evidence_window_start (u64 LE; 0 for END)
#   [25]     region_len (max 32)
#   [26..]   refugee region (UTF-8)
#
# `determ block-info <i> --json` emits the full Block JSON (block RPC
# keeps `transactions` — unlike `headers` RPC which strips them for
# light-client sync). Each tx has `type` (int 0..N), `from`, `payload`
# (hex), etc.
"$PY_BIN" - \
  "$DETERM" "$PORT" \
  "$SCAN_FROM" "$SCAN_TO" "$HEAD_H" \
  "$SHARDING_MODE" "$MY_SHARD_ID" \
  "$WINDOW" "$LONG_THRESHOLD" \
  "$INSTABILITY_WINDOW" "$INSTABILITY_MIN_CYCLES" \
  "$ANOM_ONLY" "$JSON_OUT" \
  "$SNAP_JSON" <<'PY'
import json, sys, subprocess

(determ, port,
 scan_from_s, scan_to_s, head_h_s,
 sharding_mode, my_shard_id_s,
 window_s, long_threshold_s,
 inst_window_s, inst_min_cycles_s,
 anom_only_s, json_out_s,
 snap_json_text) = sys.argv[1:15]

scan_from        = int(scan_from_s)
scan_to          = int(scan_to_s)
head_h           = int(head_h_s)
my_shard_id      = int(my_shard_id_s)
window           = int(window_s)
long_threshold   = int(long_threshold_s)
inst_window      = int(inst_window_s)
inst_min_cycles  = int(inst_min_cycles_s)
anom_only        = anom_only_s == "1"
json_out         = json_out_s == "1"

# Parse snapshot for shard_count + merge_state.
try:
    snap = json.loads(snap_json_text)
except Exception as e:
    sys.stderr.write(f"operator_merge_state_audit: snapshot is not JSON: {e}\n")
    sys.exit(1)

shard_count = int(snap.get("shard_count", 1) or 1)

# current_merges from snapshot.merge_state[]: each entry is
# {shard_id, partner_id, refugee_region}. Sort by shard_id for stable
# output across runs.
current_merges = []
for m in (snap.get("merge_state") or []):
    if not isinstance(m, dict): continue
    current_merges.append({
        "shard_id":       int(m.get("shard_id", 0)),
        "partner_id":     int(m.get("partner_id", 0)),
        "refugee_region": m.get("refugee_region", "") or "",
    })
current_merges.sort(key=lambda e: e["shard_id"])

# ── Mode gates: short-circuit for inactive R7 deployments ─────────────────────
def emit_skip(reason_human, reason_code):
    if json_out:
        env = {
            "rpc_port":        int(port),
            "sharding_mode":   sharding_mode,
            "shard_count":     shard_count,
            "my_shard_id":     my_shard_id,
            "height":          head_h,
            "scan_from":       scan_from,
            "scan_to":         scan_to,
            "current_merges":  current_merges,  # always [] in skip cases
            "begin_events":    [],
            "end_events":      [],
            "anomalies":       [],
            "anomaly_details": {
                "long_running_merge": [],
                "stuck_merge":        [],
                "instability":        [],
            },
            "skipped":         reason_code,
        }
        print(json.dumps(env))
    elif not anom_only:
        print(f"=== Merge state audit (port {port}) ===")
        print(f"Sharding mode: {sharding_mode}")
        print(f"Shard count: {shard_count} (my shard: {my_shard_id})")
        print(f"[INFO] {reason_human}")
    sys.exit(0)

if sharding_mode != "extended":
    emit_skip(
        f"sharding_mode={sharding_mode} — MERGE_EVENT only emitted under "
        f"sharding_mode=extended; no merge activity by construction",
        "non_extended_sharding_mode",
    )

if shard_count <= 1:
    emit_skip(
        f"shard_count={shard_count} (single-shard) — no modular-next "
        f"partner exists; no merge activity by construction",
        "single_shard",
    )

# ── Block walk: scan [scan_from, scan_to] for MERGE_EVENT txs ────────────────
TX_TYPE_MERGE_EVENT = 7  # src/chain/block.hpp::TxType::MERGE_EVENT

def is_merge_event(tx_type):
    # Tolerate both int and string encodings (block RPC currently emits
    # int; future schema bumps may switch to enum names).
    if isinstance(tx_type, int):  return tx_type == TX_TYPE_MERGE_EVENT
    if isinstance(tx_type, str):  return tx_type in ("7", "MERGE_EVENT")
    return False

def decode_merge_event(hex_str):
    # Mirror src/chain/block.cpp::MergeEvent::decode. Returns None on
    # any size/format violation (the block-level validator already
    # caught these, but defensive code keeps the audit honest on
    # forward-compat schema drift).
    try:
        p = bytes.fromhex(hex_str)
    except Exception:
        return None
    if len(p) < 26: return None
    event_type = p[0]
    if event_type > 1: return None
    region_len = p[25]
    if region_len > 32: return None
    if len(p) != 26 + region_len: return None
    shard_id   = int.from_bytes(p[1:5],   "little")
    partner_id = int.from_bytes(p[5:9],   "little")
    eff_h      = int.from_bytes(p[9:17],  "little")
    evidence_h = int.from_bytes(p[17:25], "little")
    try:
        region = p[26:26 + region_len].decode("utf-8")
    except Exception:
        region = ""
    return {
        "event_type":            event_type,       # 0=BEGIN, 1=END
        "shard_id":               shard_id,
        "partner_id":             partner_id,
        "effective_height":       eff_h,
        "evidence_window_start":  evidence_h,
        "refugee_region":         region,
    }

# Tolerate empty chain.
begin_events = []
end_events_raw = []  # decoded but unmatched; matched pass adds duration

if head_h > 0:
    for h in range(scan_from, scan_to + 1):
        try:
            r = subprocess.run(
                [determ, "block-info", str(h), "--json", "--rpc-port", port],
                capture_output=True, text=True, timeout=10,
            )
        except Exception as e:
            sys.stderr.write(f"operator_merge_state_audit: block-info {h} failed: {e}\n")
            sys.exit(1)
        if r.returncode != 0:
            sys.stderr.write(
                f"operator_merge_state_audit: block-info {h} rc={r.returncode}\n"
                f"{r.stderr}"
            )
            sys.exit(1)
        try:
            blk = json.loads(r.stdout)
        except Exception:
            sys.stderr.write(
                f"operator_merge_state_audit: block-info {h} returned non-JSON\n"
            )
            sys.exit(1)
        if not isinstance(blk, dict): continue
        txs = blk.get("transactions") or []
        for tx in txs:
            if not isinstance(tx, dict): continue
            if not is_merge_event(tx.get("type")): continue
            ev = decode_merge_event(tx.get("payload", ""))
            if ev is None: continue
            entry = {
                "block_index":            h,
                "shard_id":               ev["shard_id"],
                "partner_id":             ev["partner_id"],
                "effective_height":       ev["effective_height"],
                "refugee_region":         ev["refugee_region"],
                "evidence_window_start":  ev["evidence_window_start"],
                "terminator":             tx.get("from", "") or "",
            }
            if ev["event_type"] == 0:
                begin_events.append(entry)
            else:
                end_events_raw.append(entry)

# Sort chronologically.
begin_events.sort(key=lambda e: e["block_index"])
end_events_raw.sort(key=lambda e: e["block_index"])

# ── Pair BEGINs with their later ENDs (same shard_id + partner_id) ───────────
# A pair is established by walking BEGINs in chronological order and
# matching each to the FIRST END with the same (shard_id, partner_id)
# that appears after the BEGIN and has not already been matched. This
# is the most natural read of merge_state mutation semantics
# (BEGIN inserts -> END erases; one-to-one across the chain's history).
end_events_matched = []
unmatched_end_indices = set(range(len(end_events_raw)))
matched_begins = {}  # id(begin_entry) -> matching end entry

for be in begin_events:
    matching_idx = None
    for idx in sorted(unmatched_end_indices):
        ee = end_events_raw[idx]
        if (ee["shard_id"]   == be["shard_id"]
            and ee["partner_id"] == be["partner_id"]
            and ee["block_index"] > be["block_index"]):
            matching_idx = idx
            break
    if matching_idx is not None:
        unmatched_end_indices.remove(matching_idx)
        ee = end_events_raw[matching_idx]
        ee_out = dict(ee)
        ee_out["matched_begin_block"] = be["block_index"]
        ee_out["duration_blocks"]     = ee["block_index"] - be["block_index"]
        end_events_matched.append(ee_out)
        matched_begins[id(be)] = ee_out

# Any END not matched by an earlier BEGIN in the window keeps duration
# unknown — it was paired with a BEGIN outside the scan window. Surface
# it without a duration so operators can still see when the merge
# terminated.
for idx in sorted(unmatched_end_indices):
    ee = end_events_raw[idx]
    ee_out = dict(ee)
    ee_out["matched_begin_block"] = None
    ee_out["duration_blocks"]     = None
    end_events_matched.append(ee_out)

end_events_matched.sort(key=lambda e: e["block_index"])

# ── Anomaly detection ─────────────────────────────────────────────────────────
# Build a fast lookup of "is (shard_id, partner_id) currently merged?"
current_keys = {(m["shard_id"], m["partner_id"]) for m in current_merges}

anomaly_long_running = []
anomaly_stuck        = []
anomaly_instability  = []

# long_running_merge + stuck_merge: walk each unmatched BEGIN (BEGIN with
# no END pair within the scan window). If the (shard, partner) is still
# in current_merges:
#   - if the BEGIN's block index is older than long_threshold blocks
#     before head, mark stuck_merge (no END seen + clearly long).
#   - regardless, if age > long_threshold mark long_running_merge.
# Both can fire on the same BEGIN; stuck_merge is the strictly stronger
# condition.
for be in begin_events:
    if id(be) in matched_begins: continue
    if (be["shard_id"], be["partner_id"]) not in current_keys: continue
    # `head_h - 1` is the highest finalized block; age relative to that.
    age = (head_h - 1) - be["block_index"] if head_h > 0 else 0
    if age > long_threshold:
        anomaly_long_running.append({
            "shard_id":    be["shard_id"],
            "partner_id":  be["partner_id"],
            "begin_block": be["block_index"],
            "age_blocks":  age,
        })
        anomaly_stuck.append({
            "shard_id":    be["shard_id"],
            "partner_id":  be["partner_id"],
            "begin_block": be["block_index"],
        })

# instability: for any (shard, partner), if there exist >= min_cycles
# BEGIN events whose block_index falls inside any sliding window of
# inst_window blocks. Use a per-pair sorted list of BEGIN heights;
# the sliding window passes if begins[i + min_cycles - 1] - begins[i]
# < inst_window (inclusive interval shorter than the window).
by_pair = {}
for be in begin_events:
    by_pair.setdefault((be["shard_id"], be["partner_id"]), []).append(be["block_index"])

for (sid, pid), heights in by_pair.items():
    heights.sort()
    if len(heights) < inst_min_cycles: continue
    n = len(heights)
    found = None
    for i in range(0, n - inst_min_cycles + 1):
        j = i + inst_min_cycles - 1
        if heights[j] - heights[i] < inst_window:
            found = (heights[i], heights[j])
            break
    if found is not None:
        anomaly_instability.append({
            "shard_id":   sid,
            "partner_id": pid,
            "cycles":     len(heights),
            "window":     [found[0], found[1]],
        })

anomalies = []
if anomaly_long_running: anomalies.append("long_running_merge")
if anomaly_stuck:        anomalies.append("stuck_merge")
if anomaly_instability:  anomalies.append("instability")

# ── Rendering ─────────────────────────────────────────────────────────────────
def emit_json():
    env = {
        "rpc_port":        int(port),
        "sharding_mode":   sharding_mode,
        "shard_count":     shard_count,
        "my_shard_id":     my_shard_id,
        "height":          head_h,
        "scan_from":       scan_from,
        "scan_to":         scan_to,
        "current_merges":  current_merges,
        "begin_events":    begin_events,
        "end_events":      end_events_matched,
        "anomalies":       anomalies,
        "anomaly_details": {
            "long_running_merge": anomaly_long_running,
            "stuck_merge":        anomaly_stuck,
            "instability":        anomaly_instability,
        },
    }
    print(json.dumps(env))

def emit_human():
    print(f"=== Merge state audit (port {port}) ===")
    print(f"Sharding mode: {sharding_mode}")
    print(f"Shard count: {shard_count} (my shard: {my_shard_id})")
    print(f"Currently merged: {len(current_merges)} pair" +
          ("" if len(current_merges) == 1 else "s"))
    for m in current_merges:
        region = m["refugee_region"] if m["refugee_region"] else "(global)"
        print(f"  shard {m['shard_id']} -> shard {m['partner_id']} "
              f"(refugee region: {region})")
    if head_h == 0:
        print("Recent merge events: (chain is empty)")
    else:
        scan_size = scan_to - scan_from + 1
        print(f"Recent merge events (scan [{scan_from}..{scan_to}], "
              f"{scan_size} block" + ("" if scan_size == 1 else "s") + "):")
        # Interleave BEGIN + END by block_index for chronological read.
        flat = []
        for be in begin_events:
            flat.append(("BEGIN", be))
        for ee in end_events_matched:
            flat.append(("END", ee))
        flat.sort(key=lambda x: x[1]["block_index"])
        if not flat:
            print("  (none)")
        for kind, e in flat:
            if kind == "BEGIN":
                region = e["refugee_region"] if e["refugee_region"] else "(global)"
                print(f"  block {e['block_index']}: MERGE_BEGIN "
                      f"shard {e['shard_id']} -> shard {e['partner_id']} "
                      f"(region {region})")
            else:
                dur = e.get("duration_blocks")
                term = e.get("terminator") or ""
                term_suffix = f" by {term}" if term else ""
                if dur is not None:
                    print(f"  block {e['block_index']}: MERGE_END   "
                          f"shard {e['shard_id']} <- shard {e['partner_id']} "
                          f"({dur} block" + ("" if dur == 1 else "s")
                          + f" duration{term_suffix})")
                else:
                    print(f"  block {e['block_index']}: MERGE_END   "
                          f"shard {e['shard_id']} <- shard {e['partner_id']} "
                          f"(BEGIN outside scan window{term_suffix})")
    if not anomalies:
        print("[OK] No long-running, stuck, or unstable merges")
    else:
        for a in anomalies:
            if a == "long_running_merge":
                for d in anomaly_long_running:
                    print(f"[WARN] long_running_merge: shard {d['shard_id']} "
                          f"merged into {d['partner_id']} since block "
                          f"{d['begin_block']} ({d['age_blocks']} blocks ago)")
            elif a == "stuck_merge":
                for d in anomaly_stuck:
                    print(f"[WARN] stuck_merge: shard {d['shard_id']} BEGIN at "
                          f"block {d['begin_block']} with no END in the scan "
                          f"window; still in merge_state")
            elif a == "instability":
                for d in anomaly_instability:
                    print(f"[WARN] instability: shard {d['shard_id']}/"
                          f"{d['partner_id']} had {d['cycles']} BEGIN events "
                          f"clustered in blocks {d['window'][0]}..{d['window'][1]}")

# --anomalies-only mode: silent unless an anomaly fired.
if anom_only:
    if anomalies:
        if json_out: emit_json()
        else:        emit_human()
        sys.exit(2)
    sys.exit(0)

if json_out: emit_json()
else:        emit_human()
sys.exit(0)
PY
RC=$?
exit "$RC"
