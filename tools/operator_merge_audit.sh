#!/usr/bin/env bash
# operator_merge_audit.sh — R7 under-quorum-merge THRESHOLD + WINDOW audit
# on a running determ daemon.
#
# THE OPERATOR QUESTION
#   "Is any shard currently merged into its partner, and — given THIS
#   chain's merge/revert/grace thresholds — has any of those merges
#   overstayed the window in which it was supposed to have been reverted?"
#
# R7 background: under sharding_mode=extended, when shard S's eligible
# committee pool in its region falls below 2K, a beacon block may carry a
# MERGE_BEGIN(S, (S+1) mod shard_count) MERGE_EVENT (TxType==7) that
# routes S's committee operations through its modular-next partner shard.
# A later MERGE_END(S, partner) reverts. The chain's merge_state_ map is
# the apply-time projection (BEGIN inserts, END erases). Three constants
# (src/chain/chain.cpp; build_state_leaves k: namespace; persisted in the
# snapshot since the S-037-class fix at chain.cpp serialize_snapshot)
# govern the lifecycle:
#   merge_threshold_blocks   evidence-window length the BEGIN's
#                            evidence_window_start must sit fully inside
#                            (validator.cpp MERGE_EVENT bounds check).
#   merge_grace_blocks       a MERGE_EVENT's effective_height must be
#                            >= containing-block.index + grace, so every
#                            committee observes the transition before it
#                            fires (validator.cpp:753).
#   revert_threshold_blocks  the budget after a BEGIN takes effect within
#                            which a healthy chain is expected to emit the
#                            matching MERGE_END. A merge still active far
#                            past effective_height + revert_threshold has
#                            overstayed its window — the genuine anomaly
#                            this tool gates on (exit 2).
#
# WHAT THIS TOOL REPORTS (read-only):
#   1. The three thresholds, shard_count, and this node's shard_id.
#   2. Every active merge from merge_state_: shard_id -> partner_id +
#      refugee_region.
#   3. For each active merge, the most-recent in-flight MERGE_BEGIN found
#      in a bounded recent-block scan, its effective_height, and the
#      live window status:
#         pending   effective_height not yet reached (still in grace)
#         active    within [effective_height, +revert_threshold]
#         OVERDUE   age past effective_height exceeds revert_threshold
#                   -> stuck past its revert window (ANOMALY, exit 2)
#   4. In-flight MERGE_BEGIN / MERGE_END events seen in the scan window.
#
# HOW THIS DIFFERS FROM THE SIBLING TOOL
#   operator_merge_state_audit.sh
#       Event-history forensics: scans a (default 1000-block) window for
#       every MERGE_BEGIN/MERGE_END, pairs them, and flags long-running /
#       stuck / instability anomalies by BLOCK-COUNT-since-BEGIN heuristics
#       — it does NOT read the chain's merge/revert/grace threshold
#       constants and does NOT reason about a BEGIN's on-chain
#       effective_height. THIS tool leads with those three threshold
#       constants and judges each active merge against its OWN
#       effective_height + revert_threshold_blocks budget (the
#       protocol-defined revert window), giving an operator the
#       config-relative "is this merge overdue?" answer rather than a
#       fixed block-count heuristic. Run the sibling for the full
#       event ledger; run THIS for the threshold-relative health gate.
#
# Mode gate: the R7 primitive only exists under sharding_mode=extended
# with shard_count > 1. On any other configuration merge_state_ is
# permanently empty by construction; this tool short-circuits with an
# INFO and exit 0.
#
# ANTI-HANG: no node spawning, no --watch, no unbounded loops. A single
# bounded query (status + snapshot + head + at most --window block-info
# calls, each with a per-call RPC timeout) then exit.
#
# RPC dependencies (all read-only; NO mutating endpoints):
#   status          .protections.sharding_mode + .shard_id
#   snapshot create merge_threshold_blocks / revert_threshold_blocks /
#                   merge_grace_blocks / shard_count / merge_state[]
#                   (--headers 0 to keep the payload to chain-state only)
#   head            chain height (scan-window upper bound)
#   block-info      per-block JSON retaining transactions[] (the headers
#                   RPC strips them for light-client sync, so the
#                   MERGE_EVENT payload must be read one block at a time)
#
# Usage:
#   tools/operator_merge_audit.sh [--rpc-port N] [--json]
#                                 [--window N] [--block-timeout S]
#
# Options:
#   --rpc-port N        RPC port to query (default: 7778)
#   --json              Emit a structured JSON envelope
#   --window N          Recent blocks to scan for in-flight MERGE_EVENT
#                       txs (default: 500; clamped to chain height). The
#                       most-recent BEGIN per active (shard,partner) pair
#                       inside this window drives the window-status check.
#   --block-timeout S   Per-block-info RPC timeout in seconds (default: 10)
#   -h, --help          Show this help
#
# Exit codes:
#   0   audit completed; no overdue merge (or non-extended / single-shard
#       skip)
#   1   RPC error / daemon unreachable / malformed response / bad args
#   2   at least one active merge is OVERDUE (past effective_height +
#       revert_threshold_blocks) — operator alert gate
set -u

usage() {
  cat <<'EOF'
Usage: operator_merge_audit.sh [--rpc-port N] [--json]
                               [--window N] [--block-timeout S]

R7 under-quorum-merge threshold + window audit. Probes a running determ
daemon for the merge/revert/grace threshold constants, every active merge
(shard -> partner + refugee_region), and judges each active merge against
its own effective_height + revert_threshold_blocks budget. Flags any merge
that has overstayed its revert window (exit 2).

Non-extended (sharding_mode != extended) and single-shard (shard_count
<= 1) deployments exit 0 with an INFO since the R7 primitive is inactive
on those configurations.

Options:
  --rpc-port N        RPC port to query (default: 7778)
  --json              Emit a structured JSON envelope
  --window N          Recent blocks to scan for in-flight MERGE_EVENT txs
                      (default: 500; clamped to chain height)
  --block-timeout S   Per-block-info RPC timeout in seconds (default: 10)
  -h, --help          Show this help

Window status per active merge:
  pending   effective_height not yet reached (still inside grace)
  active    within [effective_height, effective_height + revert_threshold]
  OVERDUE   age past effective_height exceeds revert_threshold_blocks
            -> stuck past its revert window (ANOMALY -> exit 2)
  unknown   no MERGE_BEGIN for this pair found in the scan window
            (widen --window to locate it; not treated as an anomaly)

JSON shape:
  {
    "rpc_port": P,
    "sharding_mode": "current|extended|none",
    "shard_count": S,
    "my_shard_id": I,
    "height": H,
    "scan_from": F,
    "scan_to": T,
    "thresholds": {
      "merge_threshold_blocks":  M,
      "revert_threshold_blocks": R,
      "merge_grace_blocks":      G
    },
    "active_merges": [
      {"shard_id":S,"partner_id":P,"refugee_region":"...",
       "begin_block":B|null,"effective_height":E|null,
       "blocks_since_effective":A|null,"window_status":"...",
       "revert_deadline":D|null,"overdue_by":O|null}
    ],
    "in_flight_events": [
      {"block_index":B,"event":"MERGE_BEGIN|MERGE_END","shard_id":S,
       "partner_id":P,"effective_height":E,"refugee_region":"..."}
    ],
    "overdue": ["shard S -> P overdue by N blocks", ...],
    "skipped": "non_extended_sharding_mode|single_shard"   (skip only)
  }

Exit codes:
  0   audit completed; no overdue merge (or non-extended / single-shard skip)
  1   RPC / args / decode failure
  2   at least one active merge OVERDUE past its revert window
EOF
}

PORT=7778
JSON_OUT=0
WINDOW=500
BLOCK_TIMEOUT=10
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)        usage; exit 0 ;;
    --rpc-port)       PORT="${2:-}";          shift 2 ;;
    --json)           JSON_OUT=1;             shift ;;
    --window)         WINDOW="${2:-}";        shift 2 ;;
    --block-timeout)  BLOCK_TIMEOUT="${2:-}"; shift 2 ;;
    *) echo "operator_merge_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Numeric guards (post --help so --help never trips them) ───────────────────
for pair in "PORT=$PORT" "WINDOW=$WINDOW" "BLOCK_TIMEOUT=$BLOCK_TIMEOUT"; do
  name="${pair%%=*}"; val="${pair#*=}"
  case "$val" in
    *[!0-9]*|"")
      flag=$(printf '%s' "$name" | tr '[:upper:]_' '[:lower:]-')
      echo "operator_merge_audit: --$flag must be a positive integer (got '$val')" >&2
      exit 1 ;;
  esac
done
if [ "$PORT" -lt 1 ];          then echo "operator_merge_audit: --rpc-port must be >= 1" >&2; exit 1; fi
if [ "$WINDOW" -lt 1 ];        then echo "operator_merge_audit: --window must be >= 1" >&2; exit 1; fi
if [ "$BLOCK_TIMEOUT" -lt 1 ]; then echo "operator_merge_audit: --block-timeout must be >= 1" >&2; exit 1; fi

cd "$(dirname "$0")/.."
source tools/common.sh

if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "operator_merge_audit: python (or python3) is required for MERGE_EVENT payload decoding" >&2
  exit 1
fi
PY_BIN=python
command -v python >/dev/null 2>&1 || PY_BIN=python3

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# ── Step 1: probe sharding_mode + shard_id from status --json ─────────────────
STATUS_OUT=$("$DETERM" status --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_merge_audit: RPC error from \`determ status\` (is daemon running on port $PORT?)" >&2
  exit 1
}
if [ "$HAVE_JQ" = "1" ]; then
  SHARDING_MODE=$(printf '%s' "$STATUS_OUT" | jq -r '.protections.sharding_mode // "current"')
  MY_SHARD_ID=$(printf '%s' "$STATUS_OUT"   | jq -r '.shard_id // 0')
else
  SHARDING_MODE=$(printf '%s' "$STATUS_OUT" | grep -o '"sharding_mode":"[^"]*"' | head -1 | sed 's/.*:"\([^"]*\)".*/\1/')
  [ -z "$SHARDING_MODE" ] && SHARDING_MODE="current"
  MY_SHARD_ID=$(printf '%s' "$STATUS_OUT" | grep -o '"shard_id":[0-9]*' | head -1 | sed 's/.*: *//')
  [ -z "$MY_SHARD_ID" ] && MY_SHARD_ID=0
fi
case "$MY_SHARD_ID" in *[!0-9]*|"") MY_SHARD_ID=0 ;; esac

# ── Step 2: fetch chain-state snapshot for thresholds + merge_state ───────────
# `status --json` does not surface the merge thresholds, shard_count, or
# merge_state; the canonical snapshot does (serialize_snapshot). Pass
# --headers 0 to keep the payload to chain-state only.
SNAP_JSON=$("$DETERM" snapshot create --headers 0 --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_merge_audit: RPC error from \`determ snapshot create\` (port $PORT)" >&2
  exit 1
}
case "$SNAP_JSON" in
  '{'*) : ;;
  *)
    # Drop any leading non-JSON lines (defensive — current main.cpp with
    # no --out emits ONLY the JSON document).
    SNAP_JSON=$(printf '%s' "$SNAP_JSON" | sed -n '/^{/,$p')
    case "$SNAP_JSON" in
      '{'*) : ;;
      *) echo "operator_merge_audit: snapshot output is not JSON (port $PORT)" >&2; exit 1 ;;
    esac
    ;;
esac

# Resolve current head height (drives the scan-window upper bound).
HEAD_H=$("$DETERM" head --field height --rpc-port "$PORT" 2>/dev/null | tr -d '\r\n ') || {
  echo "operator_merge_audit: RPC error from \`determ head\` (port $PORT)" >&2; exit 1;
}
case "$HEAD_H" in *[!0-9]*|"") echo "operator_merge_audit: head returned non-numeric '$HEAD_H'" >&2; exit 1 ;; esac

# Scan range [SCAN_FROM, SCAN_TO]. `head --field height` returns the count
# of finalized blocks (= next-to-produce index); the highest finalized
# index is HEAD_H - 1. Empty chain (HEAD_H = 0) handled in Python.
SCAN_TO=$(( HEAD_H > 0 ? HEAD_H - 1 : 0 ))
SCAN_FROM=$(( SCAN_TO + 1 > WINDOW ? SCAN_TO + 1 - WINDOW : 0 ))

# ── Step 3: Python-driven decode + window evaluation + render ─────────────────
# Wire format of MERGE_EVENT payload (src/chain/block.cpp MergeEvent::encode):
#   [0]       event_type (0=BEGIN, 1=END)
#   [1..4]    shard_id              (u32 LE)
#   [5..8]    partner_id            (u32 LE)
#   [9..16]   effective_height      (u64 LE)
#   [17..24]  evidence_window_start (u64 LE; 0 for END)
#   [25]      region_len (max 32)
#   [26..]    refugee region (UTF-8)
"$PY_BIN" - \
  "$DETERM" "$PORT" \
  "$SCAN_FROM" "$SCAN_TO" "$HEAD_H" \
  "$SHARDING_MODE" "$MY_SHARD_ID" \
  "$WINDOW" "$BLOCK_TIMEOUT" \
  "$JSON_OUT" \
  "$SNAP_JSON" <<'PY'
import json, sys, subprocess

(determ, port,
 scan_from_s, scan_to_s, head_h_s,
 sharding_mode, my_shard_id_s,
 window_s, block_timeout_s,
 json_out_s,
 snap_json_text) = sys.argv[1:12]

scan_from     = int(scan_from_s)
scan_to       = int(scan_to_s)
head_h        = int(head_h_s)
my_shard_id   = int(my_shard_id_s)
window        = int(window_s)
block_timeout = int(block_timeout_s)
json_out      = json_out_s == "1"

def die(msg, code=1):
    sys.stderr.write(f"operator_merge_audit: {msg}\n")
    sys.exit(code)

# Parse snapshot for thresholds + shard_count + merge_state.
try:
    snap = json.loads(snap_json_text)
except Exception as e:
    die(f"snapshot is not JSON: {e}")
if not isinstance(snap, dict):
    die("snapshot JSON is not an object")

def u(d, k, default):
    v = d.get(k, default)
    try:
        return int(v)
    except Exception:
        return default

shard_count    = u(snap, "shard_count", 1) or 1
merge_thr      = u(snap, "merge_threshold_blocks", 100)
revert_thr     = u(snap, "revert_threshold_blocks", 200)
grace_blocks   = u(snap, "merge_grace_blocks", 10)

thresholds = {
    "merge_threshold_blocks":  merge_thr,
    "revert_threshold_blocks": revert_thr,
    "merge_grace_blocks":      grace_blocks,
}

# active merges from snapshot.merge_state[]: each {shard_id, partner_id,
# refugee_region}. Sort by shard_id for stable output.
active_merges = []
for m in (snap.get("merge_state") or []):
    if not isinstance(m, dict): continue
    active_merges.append({
        "shard_id":       int(m.get("shard_id", 0)),
        "partner_id":     int(m.get("partner_id", 0)),
        "refugee_region": m.get("refugee_region", "") or "",
    })
active_merges.sort(key=lambda e: e["shard_id"])

# ── Mode gates: short-circuit for inactive R7 deployments ─────────────────────
def emit_skip(reason_human, reason_code):
    if json_out:
        env = {
            "rpc_port":         int(port),
            "sharding_mode":    sharding_mode,
            "shard_count":      shard_count,
            "my_shard_id":      my_shard_id,
            "height":           head_h,
            "scan_from":        scan_from,
            "scan_to":          scan_to,
            "thresholds":       thresholds,
            "active_merges":    [],
            "in_flight_events": [],
            "overdue":          [],
            "skipped":          reason_code,
        }
        print(json.dumps(env))
    else:
        print(f"=== Merge audit (port {port}) ===")
        print(f"Sharding mode: {sharding_mode}")
        print(f"Shard count: {shard_count} (my shard: {my_shard_id})")
        print(f"Thresholds: merge={merge_thr} revert={revert_thr} grace={grace_blocks} blocks")
        print(f"[INFO] {reason_human}")
    sys.exit(0)

if sharding_mode != "extended":
    emit_skip(
        f"sharding_mode={sharding_mode} -- MERGE_EVENT only valid under "
        f"sharding_mode=extended; no merge activity by construction",
        "non_extended_sharding_mode",
    )

if shard_count <= 1:
    emit_skip(
        f"shard_count={shard_count} (single-shard) -- no modular-next "
        f"partner exists; no merge activity by construction",
        "single_shard",
    )

# ── Decode helpers ────────────────────────────────────────────────────────────
TX_TYPE_MERGE_EVENT = 7  # src/chain/block.hpp TxType::MERGE_EVENT

def is_merge_event(tx_type):
    if isinstance(tx_type, int): return tx_type == TX_TYPE_MERGE_EVENT
    if isinstance(tx_type, str): return tx_type in ("7", "MERGE_EVENT")
    return False

def decode_merge_event(hex_str):
    # Mirror src/chain/block.cpp MergeEvent::decode. Returns None on any
    # size/format violation (the validator already rejected these; the
    # defensive parse keeps the audit honest under forward-compat drift).
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
    return {
        "event_type":            event_type,                          # 0=BEGIN 1=END
        "shard_id":               int.from_bytes(p[1:5],  "little"),
        "partner_id":             int.from_bytes(p[5:9],  "little"),
        "effective_height":       int.from_bytes(p[9:17], "little"),
        "evidence_window_start":  int.from_bytes(p[17:25],"little"),
        "refugee_region":         (lambda: p[26:26+region_len].decode("utf-8", "replace"))(),
    }

# ── Bounded block walk: collect in-flight MERGE_BEGIN/MERGE_END events ─────────
in_flight = []
# most_recent_begin[(shard,partner)] -> {block_index, effective_height, region}
most_recent_begin = {}

if head_h > 0:
    for h in range(scan_from, scan_to + 1):
        try:
            r = subprocess.run(
                [determ, "block-info", str(h), "--json", "--rpc-port", port],
                capture_output=True, text=True, timeout=block_timeout,
            )
        except subprocess.TimeoutExpired:
            die(f"block-info {h} timed out after {block_timeout}s (port {port})")
        except Exception as e:
            die(f"block-info {h} failed: {e}")
        if r.returncode != 0:
            die(f"block-info {h} rc={r.returncode}\n{r.stderr}")
        try:
            blk = json.loads(r.stdout)
        except Exception:
            die(f"block-info {h} returned non-JSON")
        if not isinstance(blk, dict): continue
        for tx in (blk.get("transactions") or []):
            if not isinstance(tx, dict): continue
            if not is_merge_event(tx.get("type")): continue
            ev = decode_merge_event(tx.get("payload", ""))
            if ev is None: continue
            in_flight.append({
                "block_index":       h,
                "event":             "MERGE_BEGIN" if ev["event_type"] == 0 else "MERGE_END",
                "shard_id":          ev["shard_id"],
                "partner_id":        ev["partner_id"],
                "effective_height":  ev["effective_height"],
                "refugee_region":    ev["refugee_region"],
            })
            if ev["event_type"] == 0:  # BEGIN — keep the latest per pair
                key = (ev["shard_id"], ev["partner_id"])
                prev = most_recent_begin.get(key)
                if prev is None or h > prev["block_index"]:
                    most_recent_begin[key] = {
                        "block_index":      h,
                        "effective_height": ev["effective_height"],
                        "refugee_region":   ev["refugee_region"],
                    }

in_flight.sort(key=lambda e: e["block_index"])

# ── Window evaluation: judge each active merge against its revert budget ──────
# highest finalized block index:
tip = (head_h - 1) if head_h > 0 else 0
overdue_msgs = []

for m in active_merges:
    key = (m["shard_id"], m["partner_id"])
    be = most_recent_begin.get(key)
    if be is None:
        m["begin_block"]            = None
        m["effective_height"]       = None
        m["blocks_since_effective"] = None
        m["revert_deadline"]        = None
        m["overdue_by"]             = None
        m["window_status"]          = "unknown"
        continue
    eff = be["effective_height"]
    m["begin_block"]      = be["block_index"]
    m["effective_height"] = eff
    m["revert_deadline"]  = eff + revert_thr
    if tip < eff:
        # effective_height not yet reached — still in grace.
        m["blocks_since_effective"] = None
        m["overdue_by"]             = None
        m["window_status"]          = "pending"
    else:
        since = tip - eff
        m["blocks_since_effective"] = since
        if since > revert_thr:
            m["overdue_by"]    = since - revert_thr
            m["window_status"] = "OVERDUE"
            overdue_msgs.append(
                f"shard {m['shard_id']} -> {m['partner_id']} overdue by "
                f"{m['overdue_by']} blocks (effective at {eff}, revert "
                f"deadline {m['revert_deadline']}, tip {tip})"
            )
        else:
            m["overdue_by"]    = None
            m["window_status"] = "active"

# ── Rendering ─────────────────────────────────────────────────────────────────
def emit_json():
    env = {
        "rpc_port":         int(port),
        "sharding_mode":    sharding_mode,
        "shard_count":      shard_count,
        "my_shard_id":      my_shard_id,
        "height":           head_h,
        "scan_from":        scan_from,
        "scan_to":          scan_to,
        "thresholds":       thresholds,
        "active_merges":    active_merges,
        "in_flight_events": in_flight,
        "overdue":          overdue_msgs,
    }
    print(json.dumps(env))

def emit_human():
    print(f"=== Merge audit (port {port}) ===")
    print(f"Sharding mode: {sharding_mode}")
    print(f"Shard count: {shard_count} (my shard: {my_shard_id})")
    print(f"Thresholds: merge={merge_thr} revert={revert_thr} grace={grace_blocks} blocks")
    if head_h == 0:
        print("Active merges: (chain is empty)")
    else:
        scan_size = scan_to - scan_from + 1
        print(f"Scan window: blocks [{scan_from}..{scan_to}] "
              f"({scan_size} block" + ("" if scan_size == 1 else "s")
              + f"); tip {tip}")
        print(f"Active merges: {len(active_merges)} pair"
              + ("" if len(active_merges) == 1 else "s"))
        for m in active_merges:
            region = m["refugee_region"] if m["refugee_region"] else "(global)"
            status = m["window_status"]
            tag = "[OVERDUE]" if status == "OVERDUE" else "[OK]" if status in ("active","pending") else "[?]"
            line = (f"  {tag} shard {m['shard_id']} -> shard {m['partner_id']} "
                    f"(refugee region: {region}); status={status}")
            if m["begin_block"] is not None:
                line += (f"; BEGIN@block {m['begin_block']} "
                         f"effective@{m['effective_height']}")
                if m["window_status"] == "OVERDUE":
                    line += (f"; OVERDUE by {m['overdue_by']} blocks past "
                             f"revert deadline {m['revert_deadline']}")
                elif m["window_status"] == "active":
                    line += (f"; {m['blocks_since_effective']}/{revert_thr} blocks "
                             f"into revert budget")
                elif m["window_status"] == "pending":
                    line += "; effective_height not yet reached (grace)"
            else:
                line += (f"; no MERGE_BEGIN in scan window "
                         f"[{scan_from}..{scan_to}] (widen --window)")
            print(line)
        # In-flight events for chronological context.
        if in_flight:
            print(f"In-flight MERGE_EVENT txs in scan window: {len(in_flight)}")
            for e in in_flight:
                region = e["refugee_region"] if e["refugee_region"] else "(global)"
                print(f"  block {e['block_index']}: {e['event']:<11} "
                      f"shard {e['shard_id']} / partner {e['partner_id']} "
                      f"(effective@{e['effective_height']}, region {region})")
        else:
            print("In-flight MERGE_EVENT txs in scan window: (none)")
    if overdue_msgs:
        for msg in overdue_msgs:
            print(f"[ANOMALY] {msg}")
    else:
        print("[OK] No active merge has overstayed its revert window")

if json_out: emit_json()
else:        emit_human()

# Exit 2 iff at least one active merge is OVERDUE past its revert window.
sys.exit(2 if overdue_msgs else 0)
PY
RC=$?
exit "$RC"
