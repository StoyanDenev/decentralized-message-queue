#!/usr/bin/env bash
# operator_snapshot_lineage.sh — Snapshot directory audit + freshness +
# gap detection.
#
# Walks a directory of snapshot files (typically `*.snapshot.json` or
# any `.json` produced by `determ snapshot create`), classifies each
# file, and emits a per-snapshot table + summary + anomalies envelope.
# Optionally cross-references the lineage against a live daemon to
# flag the most-recent snapshot as STALE.
#
# Sibling positioning:
#   * operator_snapshot_check.sh        — one snapshot vs daemon (live).
#   * operator_snapshot_diff_report.sh  — two snapshots, grouped diff
#                                         (incident / post-mortem).
#   * operator_snapshot_lineage.sh (this) — META: directory walk +
#                                         per-snapshot classification +
#                                         freshness + gap detection.
#
# Snapshot envelope (what we read):
#   `determ snapshot create` writes a JSON object whose top-level scalars
#   include `version`, `block_index`, `head_hash`, and the per-domain
#   arrays `accounts[] / stakes[] / registrants[]` (see
#   Chain::serialize_state in src/chain/chain.cpp). The CRYPTOGRAPHIC
#   state_root is NOT a top-level field — it is RECOMPUTED on restore
#   via Chain::restore_from_snapshot (the S-033 / S-038 gate). To get
#   the canonical state_root for each file, we invoke
#   `determ snapshot inspect --in <file> --json` which runs the full
#   restore pipeline and emits {block_index, head_hash, state_root,
#   accounts, stakes, registrants, ...}. A non-zero exit from `inspect`
#   is the integrity signal — that file becomes an INVALID classification.
#
# Algorithm:
#   1. Enumerate `*.json` files in --dir.
#   2. For each: run `determ snapshot inspect --in <file> --json`.
#      OK ⇒ extract block_index + head_hash + state_root + file mtime
#           (creation_time). VALID classification.
#      Non-zero exit ⇒ classify INVALID. Records the file but does not
#                      contribute to gap/staleness math.
#   3. Sort VALID rows by block_index ascending.
#   4. Walk adjacent pairs; emit GAP anomaly when
#      s[i+1].block_index - s[i].block_index > --gap-threshold-blocks.
#   5. Walk all VALID rows; group by block_index; emit
#      duplicate_block_index anomaly per duplicate group (records the
#      colliding files + whether state_roots agree).
#   6. If --rpc-port supplied: fetch daemon head via
#      `determ head --field height --rpc-port N`, then compare the
#      most-recent snapshot's block_index against (daemon_head - threshold).
#
# Anomalies emitted (rolled up into JSON `anomalies[]`):
#   snapshot_stale          WARN     most-recent VALID snapshot's
#                                    block_index < (daemon_head - threshold)
#   snapshot_gap            WARN     consecutive snapshots gap exceeds
#                                    --gap-threshold-blocks
#   snapshot_invalid        CRITICAL any file in --dir failed `inspect`
#   duplicate_block_index   WARN     two distinct files report the same
#                                    block_index (different state_roots
#                                    ⇒ chain reorg history; same
#                                    state_roots ⇒ duplicate files —
#                                    JSON detail records both cases)
#
# Output:
#   default (human):
#     - Per-snapshot table (file, block_index, head_hash[:8],
#       head_state_root[:8], age_blocks_from_head, creation_time).
#     - Summary line (count VALID + INVALID, oldest + newest
#       block_index, daemon_head if --rpc-port supplied).
#     - Anomalies block (one line per anomaly).
#     - Verdict line.
#   --json:
#     {dir, daemon_head (or null), snapshots: [...], gaps: [...],
#      anomalies: [...], summary: {...}}.
#
# Exit codes:
#   0   healthy (no anomalies)
#   1   args error / dir unreadable / RPC error / binary missing
#   2   anomaly fired (any of snapshot_stale, snapshot_gap,
#       snapshot_invalid, duplicate_block_index)
#
# Note: per the spec, CRITICAL maps to snapshot_invalid; all anomalies
# share the same exit-2 escalation. Operators differentiate CRITICAL
# from WARN by inspecting the `severity` field on each anomaly entry
# in the JSON envelope (or the [X]/[!] markers in the human verdict).
set -u

usage() {
  cat <<'EOF'
Usage: operator_snapshot_lineage.sh --dir <path>
                                    [--rpc-port N]
                                    [--stale-threshold-blocks N]
                                    [--gap-threshold-blocks N]
                                    [--json] [--anomalies-only]

Walks --dir for *.json snapshot envelopes, classifies each (VALID via
`determ snapshot inspect` or INVALID on parse/integrity failure), then
checks adjacent-pair gaps + optional staleness against a live daemon.

Required:
  --dir <path>              Directory containing snapshot files
                            (any `.json` file matching the snapshot
                            envelope; non-snapshot JSON files surface
                            as snapshot_invalid).

Options:
  --rpc-port N              If supplied, cross-check the daemon's
                            current head_height against the most-recent
                            VALID snapshot for staleness. Without this,
                            snapshot_stale cannot fire.
  --stale-threshold-blocks N  Most-recent snapshot is STALE when its
                            block_index < (daemon_head - N). Only fires
                            with --rpc-port. Default: 5000.
  --gap-threshold-blocks N  Adjacent-pair gap > N triggers snapshot_gap.
                            Default: 10000.
  --json                    Emit single-line JSON envelope.
  --anomalies-only          Suppress healthy (no-anomaly) rows in the
                            per-snapshot human table; rows tied to an
                            anomaly stay. JSON output is unaffected.
  -h, --help                Show this help.

Exit codes:
  0   healthy (no anomalies)
  1   bad args / --dir unreadable / RPC error / determ binary missing
  2   anomaly fired (snapshot_stale, snapshot_gap, snapshot_invalid,
      duplicate_block_index). snapshot_invalid is CRITICAL severity;
      the other three are WARN. Severity is exposed per-anomaly in
      both human + JSON output.

JSON envelope (--json):
  {"dir":               "<path>",
   "rpc_port":          <N> | null,
   "daemon_head":       <u64> | null,
   "stale_threshold":   <N>,
   "gap_threshold":     <N>,
   "snapshots":  [{"file":"<basename>", "path":"<abs>",
                   "valid": <bool>,
                   "block_index": <u64> | null,
                   "head_hash":   "<hex>" | null,
                   "state_root":  "<hex>" | null,
                   "creation_time": "<ISO8601>",
                   "creation_time_epoch": <u64>,
                   "age_blocks_from_head": <i64> | null,
                   "error": "<string>" | null}, ...],
   "gaps":       [{"from_file":"<basename>","to_file":"<basename>",
                   "from_block_index": <u64>, "to_block_index": <u64>,
                   "gap_blocks": <u64>}, ...],
   "anomalies":  [{"type":"snapshot_stale|snapshot_gap|snapshot_invalid|duplicate_block_index",
                   "severity":"CRITICAL|WARN",
                   "detail": "<string>",
                   "context": {...}}, ...],
   "summary":    {"total_files": <N>, "valid": <N>, "invalid": <N>,
                  "oldest_block_index": <u64> | null,
                  "newest_block_index": <u64> | null}}
EOF
}

DIR=""
RPC_PORT=""
STALE_THRESHOLD=5000
GAP_THRESHOLD=10000
JSON_OUT=0
ANOMALIES_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)                  usage; exit 0 ;;
    --dir)                      DIR="$2";              shift 2 ;;
    --rpc-port)                 RPC_PORT="$2";         shift 2 ;;
    --stale-threshold-blocks)   STALE_THRESHOLD="$2";  shift 2 ;;
    --gap-threshold-blocks)     GAP_THRESHOLD="$2";    shift 2 ;;
    --json)                     JSON_OUT=1;            shift ;;
    --anomalies-only)           ANOMALIES_ONLY=1;      shift ;;
    *) echo "operator_snapshot_lineage: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Argument validation ────────────────────────────────────────────────────────
if [ -z "$DIR" ]; then
  echo "operator_snapshot_lineage: --dir <path> is required" >&2
  usage >&2
  exit 1
fi
if [ ! -d "$DIR" ]; then
  echo "operator_snapshot_lineage: --dir not a directory: $DIR" >&2
  exit 1
fi
if [ ! -r "$DIR" ]; then
  echo "operator_snapshot_lineage: --dir not readable: $DIR" >&2
  exit 1
fi

# Numeric guards on every numeric option (protects shell arithmetic and
# the JSON emitter from a non-numeric value sneaking through).
for nv in "rpc-port:$RPC_PORT" \
          "stale-threshold-blocks:$STALE_THRESHOLD" \
          "gap-threshold-blocks:$GAP_THRESHOLD"; do
  label=${nv%%:*}
  val=${nv#*:}
  [ -z "$val" ] && continue
  case "$val" in
    *[!0-9]*)
      echo "operator_snapshot_lineage: --$label must be a non-negative integer (got '$val')" >&2
      exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Snapshot enumeration ───────────────────────────────────────────────────────
# Enumerate `*.json` files in --dir. We do NOT recurse (operators
# typically keep their snapshot archive flat; recursing would risk
# pulling in unrelated JSON from sibling tools like chain exports).
# Empty directory is a healthy "nothing to audit" — exit 0 with a
# diagnostic note rather than 1, since the operator may be checking a
# freshly-provisioned archive root.
SNAP_FILES=()
while IFS= read -r -d '' f; do
  SNAP_FILES+=("$f")
done < <(find "$DIR" -maxdepth 1 -type f -name '*.json' -print0 2>/dev/null | sort -z)

# ── Daemon head fetch (optional) ───────────────────────────────────────────────
DAEMON_HEAD=""
if [ -n "$RPC_PORT" ]; then
  DAEMON_HEAD=$("$DETERM" head --field height --rpc-port "$RPC_PORT" 2>/dev/null) || {
    echo "operator_snapshot_lineage: cannot reach daemon on rpc-port $RPC_PORT" >&2
    exit 1
  }
  DAEMON_HEAD=$(printf '%s' "$DAEMON_HEAD" | tr -d '[:space:]')
  case "$DAEMON_HEAD" in
    *[!0-9]*|"")
      echo "operator_snapshot_lineage: daemon returned non-numeric head '$DAEMON_HEAD' (port $RPC_PORT)" >&2
      exit 1 ;;
  esac
fi

# ── Per-file inspect pass ──────────────────────────────────────────────────────
# Build two parallel arrays (one per file) of NDJSON-style records that
# the Python aggregator below ingests. We keep this loop in bash so the
# `determ snapshot inspect` invocation stays close to the file walk and
# any operator-relevant diagnostic surfaces immediately. Each record:
#   {"file":<base>,"path":<abs>,"valid":<bool>,
#    "block_index":<u64|null>,"head_hash":<hex|null>,
#    "state_root":<hex|null>,"creation_time_epoch":<u64>,
#    "error":<str|null>}
#
# We DON'T pre-compute age_blocks_from_head or sort here — both are the
# Python pass's job (it has the daemon head + the full lineage view).
RECORDS=()
for f in "${SNAP_FILES[@]}"; do
  base=$(basename -- "$f")
  # File mtime (epoch seconds). `stat -c %Y` is GNU; `stat -f %m` is BSD.
  # Try GNU first, fall back to BSD. Failure ⇒ epoch=0 (file is still
  # included in the audit but creation_time becomes a sentinel).
  mtime=$(stat -c %Y -- "$f" 2>/dev/null) || mtime=$(stat -f %m -- "$f" 2>/dev/null) || mtime=0

  # Run the heavy restore + state_root recompute pipeline. Any non-zero
  # exit ⇒ INVALID classification. We capture stderr too so the error
  # field carries the binary's diagnostic for the operator.
  INSPECT_OUT=$("$DETERM" snapshot inspect --in "$f" --json 2>&1)
  INSPECT_RC=$?

  if [ "$INSPECT_RC" -ne 0 ]; then
    # INVALID. Quote-escape the error text so it survives the JSON
    # passthrough (Python's json.loads handles standard JSON escapes).
    err_escaped=$(printf '%s' "$INSPECT_OUT" \
      | head -c 2000 \
      | python -c 'import sys,json; sys.stdout.write(json.dumps(sys.stdin.read()))' 2>/dev/null)
    [ -z "$err_escaped" ] && err_escaped='"inspect failed"'
    RECORDS+=("$(printf '{"file":%s,"path":%s,"valid":false,"block_index":null,"head_hash":null,"state_root":null,"creation_time_epoch":%s,"error":%s}' \
      "$(printf '%s' "$base" | python -c 'import sys,json; sys.stdout.write(json.dumps(sys.stdin.read()))')" \
      "$(printf '%s' "$f"    | python -c 'import sys,json; sys.stdout.write(json.dumps(sys.stdin.read()))')" \
      "$mtime" \
      "$err_escaped")")
    continue
  fi

  # VALID. Pull block_index + head_hash + state_root from the inspect
  # envelope. Prefer jq when available; fall back to python (no grep/sed
  # here because the field set is small and python is already required
  # downstream for the aggregator).
  if command -v jq >/dev/null 2>&1; then
    bi=$(printf '%s' "$INSPECT_OUT" | jq -r '.block_index')
    hh=$(printf '%s' "$INSPECT_OUT" | jq -r '.head_hash')
    sr=$(printf '%s' "$INSPECT_OUT" | jq -r '.state_root')
  else
    parsed=$(printf '%s' "$INSPECT_OUT" | python -c '
import sys, json
o = json.load(sys.stdin)
print(o.get("block_index", ""))
print(o.get("head_hash",   ""))
print(o.get("state_root",  ""))
' 2>/dev/null) || parsed=""
    bi=$(printf '%s' "$parsed" | sed -n '1p')
    hh=$(printf '%s' "$parsed" | sed -n '2p')
    sr=$(printf '%s' "$parsed" | sed -n '3p')
  fi

  # Treat "null" / "" from the parsers as missing — defensive: a snapshot
  # whose inspect output came back missing any of these three fields is
  # better reclassified as INVALID than carried forward as VALID with
  # bogus zeros.
  if [ -z "$bi" ] || [ "$bi" = "null" ] || \
     [ -z "$hh" ] || [ "$hh" = "null" ] || \
     [ -z "$sr" ] || [ "$sr" = "null" ]; then
    RECORDS+=("$(printf '{"file":%s,"path":%s,"valid":false,"block_index":null,"head_hash":null,"state_root":null,"creation_time_epoch":%s,"error":"inspect returned malformed envelope"}' \
      "$(printf '%s' "$base" | python -c 'import sys,json; sys.stdout.write(json.dumps(sys.stdin.read()))')" \
      "$(printf '%s' "$f"    | python -c 'import sys,json; sys.stdout.write(json.dumps(sys.stdin.read()))')" \
      "$mtime")")
    continue
  fi

  RECORDS+=("$(printf '{"file":%s,"path":%s,"valid":true,"block_index":%s,"head_hash":"%s","state_root":"%s","creation_time_epoch":%s,"error":null}' \
    "$(printf '%s' "$base" | python -c 'import sys,json; sys.stdout.write(json.dumps(sys.stdin.read()))')" \
    "$(printf '%s' "$f"    | python -c 'import sys,json; sys.stdout.write(json.dumps(sys.stdin.read()))')" \
    "$bi" "$hh" "$sr" "$mtime")")
done

# Join the records with newlines for stdin transport into the python
# aggregator. The aggregator parses each line as an independent JSON
# object (NDJSON-style).
RECORDS_JOINED=$(printf '%s\n' "${RECORDS[@]}")

# ── Aggregation + anomaly detection in Python ─────────────────────────────────
# Python is the right tool here because:
#   - we need to sort by block_index, detect duplicates, walk adjacent
#     pairs for gaps, and compute age_blocks_from_head — all natural
#     list operations;
#   - we need to keep two output paths (human table vs JSON envelope)
#     feeding off the same data structure;
#   - the anomaly rules are simple but multi-pass (per-pair gaps,
#     per-group dupes, single-row staleness, count-based invalid).
python - "$DIR" "$RPC_PORT" "$DAEMON_HEAD" "$STALE_THRESHOLD" "$GAP_THRESHOLD" \
              "$JSON_OUT" "$ANOMALIES_ONLY" "$RECORDS_JOINED" <<'PY'
import json, sys, time
from datetime import datetime, timezone

dir_path        = sys.argv[1]
rpc_port_raw    = sys.argv[2]
daemon_head_raw = sys.argv[3]
stale_threshold = int(sys.argv[4])
gap_threshold   = int(sys.argv[5])
json_out        = sys.argv[6] == "1"
anomalies_only  = sys.argv[7] == "1"
records_raw     = sys.argv[8]

def die(msg, rc=1):
    sys.stderr.write(f"operator_snapshot_lineage: {msg}\n")
    sys.exit(rc)

rpc_port    = int(rpc_port_raw) if rpc_port_raw else None
daemon_head = int(daemon_head_raw) if daemon_head_raw else None

# ── Parse the per-file NDJSON records ──────────────────────────────────────────
snapshots = []
for line in records_raw.splitlines():
    line = line.strip()
    if not line:
        continue
    try:
        snapshots.append(json.loads(line))
    except Exception as e:
        die(f"internal record parse error: {e} (line='{line[:200]}')")

# Add a human-readable creation_time and derive age_blocks_from_head.
for s in snapshots:
    epoch = s.get("creation_time_epoch", 0) or 0
    if epoch > 0:
        # UTC ISO8601 — operators correlating with logs prefer UTC over
        # local-machine timezone. The trailing "Z" is the standard
        # zulu marker.
        s["creation_time"] = datetime.fromtimestamp(epoch, tz=timezone.utc) \
                                     .strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        s["creation_time"] = "unknown"
    if s.get("valid") and daemon_head is not None and s.get("block_index") is not None:
        # daemon_head is the NEXT-to-be-produced index; the head block
        # lives at (daemon_head - 1). For age math we compute
        # (daemon_head - 1) - snapshot_block_index — a snapshot taken
        # at the current head shows age=0, an older snapshot shows
        # positive age, and a snapshot AHEAD of the daemon (rare;
        # daemon was rolled back) shows negative age.
        s["age_blocks_from_head"] = (daemon_head - 1) - int(s["block_index"])
    else:
        s["age_blocks_from_head"] = None

# Stable separation of VALID and INVALID, then sort VALID by
# block_index ascending. INVALID rows are appended after.
valid_snaps   = [s for s in snapshots if s.get("valid")]
invalid_snaps = [s for s in snapshots if not s.get("valid")]
valid_snaps.sort(key=lambda s: (int(s.get("block_index") or 0), s.get("file", "")))

# Final ordered list for emit (sorted VALID then INVALID).
ordered = valid_snaps + invalid_snaps

# ── Gap detection (adjacent-pair walk over sorted VALID rows) ─────────────────
gaps = []
for i in range(len(valid_snaps) - 1):
    a, b = valid_snaps[i], valid_snaps[i + 1]
    delta = int(b["block_index"]) - int(a["block_index"])
    if delta > gap_threshold:
        gaps.append({
            "from_file":         a["file"],
            "to_file":           b["file"],
            "from_block_index":  int(a["block_index"]),
            "to_block_index":    int(b["block_index"]),
            "gap_blocks":        delta,
        })

# ── Duplicate-block_index detection ───────────────────────────────────────────
# Group VALID rows by block_index. A group of size > 1 emits a single
# duplicate_block_index anomaly. We also surface whether the colliding
# files agree on state_root (different roots ⇒ legitimate fork-history
# preservation; same roots ⇒ filesystem duplication).
dupe_groups = {}
for s in valid_snaps:
    bi = int(s["block_index"])
    dupe_groups.setdefault(bi, []).append(s)
duplicates = []
for bi, group in dupe_groups.items():
    if len(group) > 1:
        roots = sorted({s["state_root"] for s in group})
        duplicates.append({
            "block_index":       bi,
            "files":             [s["file"] for s in group],
            "state_roots":       roots,
            "state_roots_agree": len(roots) == 1,
        })

# ── Anomaly assembly ──────────────────────────────────────────────────────────
anomalies = []

# (1) Any INVALID file ⇒ CRITICAL. One anomaly per file so operators
# can drill into each diagnostic individually.
for s in invalid_snaps:
    anomalies.append({
        "type":     "snapshot_invalid",
        "severity": "CRITICAL",
        "detail":   f"failed `determ snapshot inspect`: {s.get('error') or 'unknown error'}",
        "context":  {"file": s["file"], "path": s["path"]},
    })

# (2) snapshot_stale — only when --rpc-port supplied AND we have at
# least one VALID snapshot AND the newest one is older than the
# threshold. The newest VALID snapshot is the last entry in the sorted
# valid_snaps list (sorted ascending by block_index).
if daemon_head is not None and valid_snaps:
    newest = valid_snaps[-1]
    cutoff = max(0, (daemon_head - 1) - stale_threshold)
    if int(newest["block_index"]) < cutoff:
        anomalies.append({
            "type":     "snapshot_stale",
            "severity": "WARN",
            "detail":   (f"most-recent snapshot block_index "
                         f"{newest['block_index']} < cutoff {cutoff} "
                         f"(daemon_head={daemon_head}, threshold={stale_threshold})"),
            "context":  {"file": newest["file"],
                         "block_index": int(newest["block_index"]),
                         "daemon_head": daemon_head,
                         "stale_threshold": stale_threshold},
        })

# (3) snapshot_gap — one anomaly per gap exceeding threshold.
for g in gaps:
    anomalies.append({
        "type":     "snapshot_gap",
        "severity": "WARN",
        "detail":   (f"gap of {g['gap_blocks']} blocks between "
                     f"{g['from_file']} (block_index {g['from_block_index']}) "
                     f"and {g['to_file']} (block_index {g['to_block_index']}); "
                     f"threshold={gap_threshold}"),
        "context":  g,
    })

# (4) duplicate_block_index — one anomaly per dupe group.
for d in duplicates:
    if d["state_roots_agree"]:
        sub = "identical state_roots — likely duplicate file"
    else:
        sub = "divergent state_roots — likely chain reorg history"
    anomalies.append({
        "type":     "duplicate_block_index",
        "severity": "WARN",
        "detail":   (f"block_index {d['block_index']} shared by "
                     f"{len(d['files'])} files ({sub})"),
        "context":  d,
    })

# Exit code: any anomaly ⇒ 2; otherwise 0.
exit_code = 2 if anomalies else 0

# ── Summary roll-up ───────────────────────────────────────────────────────────
summary = {
    "total_files":        len(snapshots),
    "valid":              len(valid_snaps),
    "invalid":            len(invalid_snaps),
    "oldest_block_index": int(valid_snaps[0]["block_index"])  if valid_snaps else None,
    "newest_block_index": int(valid_snaps[-1]["block_index"]) if valid_snaps else None,
}

# ── JSON emit ─────────────────────────────────────────────────────────────────
if json_out:
    env = {
        "dir":              dir_path,
        "rpc_port":         rpc_port,
        "daemon_head":      daemon_head,
        "stale_threshold":  stale_threshold,
        "gap_threshold":    gap_threshold,
        "snapshots":        ordered,
        "gaps":             gaps,
        "anomalies":        anomalies,
        "summary":          summary,
    }
    print(json.dumps(env))
    sys.exit(exit_code)

# ── Human render ──────────────────────────────────────────────────────────────
def short(h, n=8):
    if not isinstance(h, str) or not h:
        return "-"
    return h[:n] if len(h) > n else h

# Identify which snapshots are tied to an anomaly — used by
# --anomalies-only to filter the per-snapshot table.
anomaly_files = set()
for a in anomalies:
    ctx = a.get("context") or {}
    if "file" in ctx:
        anomaly_files.add(ctx["file"])
    if "from_file" in ctx:
        anomaly_files.add(ctx["from_file"])
    if "to_file" in ctx:
        anomaly_files.add(ctx["to_file"])
    for fn in (ctx.get("files") or []):
        anomaly_files.add(fn)

print(f"Snapshot lineage audit: {dir_path}")
print("=" * 70)
if daemon_head is not None:
    print(f"Daemon head: {daemon_head}  (rpc-port {rpc_port}, stale-threshold {stale_threshold}, gap-threshold {gap_threshold})")
else:
    print(f"Daemon head: (not queried — pass --rpc-port to enable staleness check; gap-threshold {gap_threshold})")
print()

# Per-snapshot table.
if not ordered:
    print("(no *.json files in --dir; nothing to audit)")
else:
    # Adaptive column widths so long filenames don't break the layout
    # while staying readable on a wide terminal.
    file_w = max(4, min(40, max(len(s["file"]) for s in ordered)))
    age_header = "age_blocks"
    cols = ["file", "block_index", "head[:8]", "state[:8]", age_header, "creation_time", "status"]
    fmt  = f"{{:<{file_w}}}  {{:>11}}  {{:<10}}  {{:<10}}  {{:>10}}  {{:<20}}  {{}}"
    print(fmt.format(*cols))
    print("-" * (file_w + 11 + 10 + 10 + 10 + 20 + 8 + 14))
    shown = 0
    for s in ordered:
        if anomalies_only and s["file"] not in anomaly_files:
            continue
        shown += 1
        bi  = s["block_index"] if s["block_index"] is not None else "-"
        hh  = short(s.get("head_hash"))
        sr  = short(s.get("state_root"))
        age = s["age_blocks_from_head"]
        age_str = "-" if age is None else str(age)
        ct  = s["creation_time"]
        status = "VALID" if s.get("valid") else "INVALID"
        print(fmt.format(s["file"][:file_w], str(bi), hh, sr, age_str, ct, status))
    if anomalies_only and shown == 0:
        print("(no snapshots tied to anomalies; --anomalies-only suppressed all rows)")

print()
print("Summary:")
print(f"  total files:        {summary['total_files']}")
print(f"  valid snapshots:    {summary['valid']}")
print(f"  invalid snapshots:  {summary['invalid']}")
if summary["valid"] > 0:
    print(f"  oldest block_index: {summary['oldest_block_index']}")
    print(f"  newest block_index: {summary['newest_block_index']}")

if gaps:
    print()
    print(f"Gaps detected (> {gap_threshold} blocks):")
    for g in gaps:
        print(f"  {g['from_file']} (block {g['from_block_index']}) -> "
              f"{g['to_file']} (block {g['to_block_index']}): "
              f"gap = {g['gap_blocks']} blocks")

print()
if not anomalies:
    print("Anomalies: (none)")
    print()
    print("[OK] Snapshot lineage healthy.")
else:
    print("Anomalies:")
    for a in anomalies:
        marker = "[X]" if a["severity"] == "CRITICAL" else "[!]"
        print(f"  {marker} {a['type']} ({a['severity']}): {a['detail']}")
    crit = sum(1 for a in anomalies if a["severity"] == "CRITICAL")
    warn = sum(1 for a in anomalies if a["severity"] == "WARN")
    print()
    print(f"[X]  {len(anomalies)} anomaly(ies) detected — {crit} CRITICAL, {warn} WARN.")

sys.exit(exit_code)
PY
PY_RC=$?
exit "$PY_RC"
