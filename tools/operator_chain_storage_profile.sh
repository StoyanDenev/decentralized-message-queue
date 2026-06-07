#!/usr/bin/env bash
# operator_chain_storage_profile.sh — OFFLINE per-block storage profile of
# a local chain.json. Answers "what is bloating my chain.json on disk?"
# without contacting (or even requiring) a running daemon.
#
# A long-running node's chain.json grows monotonically. The existing
# storage tooling tells the operator the WHOLE-FILE size and a flat
# bytes/block AVERAGE, but never WHICH blocks are heavy or HOW skewed the
# per-block size distribution is. A handful of fat blocks (large tx
# batches, dense abort_events / equivocation_events / cross_shard_receipts
# collections, or F2 per-creator view lists) can dominate the file while
# the average stays small. This script profiles the on-disk JSON byte
# footprint of every block and surfaces the distribution + the heaviest
# blocks, so the operator can reason about compaction / snapshot timing
# from real per-block evidence rather than a single average.
#
# Sibling positioning (deliberately DISTINCT from each):
#   * operator_storage_growth.sh         — DAEMON-required. Whole-file
#                                          byte counts of every data-dir
#                                          file + a flat bytes/block avg.
#   * operator_chain_compaction_audit.sh — DAEMON-required. Whole-file
#                                          chain.json size vs warn/critical
#                                          thresholds + snapshot-recommend.
#   * operator_block_size_audit.sh       — DAEMON-required. Per-block size
#                                          via the `block-info` RPC — measures
#                                          the RPC-SERIALIZED block, NOT the
#                                          on-disk JSON bytes, and cannot run
#                                          against a stopped node / a backup.
#   * operator_chain_orphan_check.sh      — OFFLINE continuity (index gaps,
#                                          duplicate indices, prev_hash
#                                          linkage). Says nothing about SIZE.
#   * operator_chain_storage_profile.sh (THIS) — OFFLINE per-block on-disk
#                                          BYTE profile: min / mean / median /
#                                          p95 / max block size, the top-N
#                                          heaviest blocks by index, and a
#                                          per-field byte breakdown of the
#                                          single largest block. No daemon.
#
# Pure file inspector: reads only --chain-file (read-only). Never writes,
# never opens a socket, never launches the daemon. Safe to run against a
# backup, a crashed node's data dir, or a live node's chain.json (a
# concurrent atomic rename by the daemon's save worker is harmless — we
# either read the old or the new file whole, never a torn write).
#
# On-disk format (verified against src/chain/chain.cpp::save / ::load and
# src/chain/block.cpp::Block::to_json):
#   * S-021 wrapped form:  { "head_hash": "<hex>", "blocks": [ <block>, ... ] }
#   * legacy bare-array form: [ <block>, ... ]   (pre-S-021; still loadable)
#   Each <block> is Block::to_json() — an object whose per-field byte
#   weight we measure by re-serializing each top-level key compactly.
#
# Algorithm:
#   1. Resolve + stat --chain-file. Absent/unreadable ⇒ clean INFO + SKIP
#      (exit 0) — an operator scheduling this on cron across many hosts
#      shouldn't get a hard failure on a node that hasn't created
#      chain.json yet (matches the SKIP convention of the read-only family).
#   2. Parse JSON. Accept wrapped OR bare-array form. Empty blocks list ⇒
#      INFO (nothing to profile) + exit 0.
#   3. For each block: measure its compact-serialized byte size; track the
#      max-size block and accumulate the per-top-level-field byte total for
#      that single heaviest block.
#   4. Compute min / mean / median / p95 / max + the top-N heaviest blocks.
#   5. Flag anomalies:
#        block_size_skew    — max block size > --skew-factor × mean
#                             (default 50×). A single block dwarfs the
#                             rest; investigate before it recurs.
#        oversize_block     — any block's on-disk size > --max-block-kb
#                             (default 4096 KB = 4 MB, the S-022 BLOCK/
#                             HEADER body cap). On-disk JSON is larger than
#                             the wire binary, so this is an EARLY warning
#                             that the block is near the wire ceiling.
#      Both are advisory (WARN); neither implies corruption. Exit stays 0
#      unless --anomalies-only gates it to 2.
#
# Usage:
#   tools/operator_chain_storage_profile.sh --chain-file PATH
#                                           [--top N] [--skew-factor N]
#                                           [--max-block-kb N]
#                                           [--json] [--anomalies-only]
#                                           [-h|--help]
#
# Exit codes:
#   0   success (profile printed), OR clean SKIP (file absent/unreadable/
#       empty-chain), OR anomalies present without --anomalies-only.
#   1   args error / malformed (non-JSON, or JSON that is neither a
#       wrapped object with a 'blocks' array nor a bare array) / missing
#       python interpreter.
#   2   --anomalies-only set AND >=1 anomaly fired (operator alert gate).
set -u

usage() {
  cat <<'EOF'
Usage: operator_chain_storage_profile.sh --chain-file PATH
                                         [--top N] [--skew-factor N]
                                         [--max-block-kb N]
                                         [--json] [--anomalies-only]
                                         [-h|--help]

OFFLINE per-block storage profile of a local chain.json. No daemon
required. Measures the on-disk JSON byte footprint of every block and
reports the size distribution + heaviest blocks + a per-field byte
breakdown of the single largest block.

Required:
  --chain-file PATH    Path to a chain.json (S-021 wrapped form
                       {head_hash, blocks:[...]} OR legacy bare array).
                       Absent / unreadable ⇒ clean INFO + SKIP (exit 0).

Options:
  --top N              Show the N heaviest blocks by on-disk size
                       (default: 10). Capped at the block count.
  --skew-factor N      Flag block_size_skew when max block size >
                       N × mean block size (default: 50).
  --max-block-kb N     Flag oversize_block when any block's on-disk size
                       exceeds N KB (default: 4096 = the S-022 4 MB
                       BLOCK/HEADER body cap). On-disk JSON > wire binary,
                       so this is an early near-ceiling warning.
  --json               Emit single-line machine-readable JSON envelope.
  --anomalies-only     Suppress the full profile; print only flagged
                       anomalies. Exit 2 if any fired, else 0.
  -h, --help           Show this help.

Anomaly flags (both advisory WARN — never imply corruption):
  block_size_skew      max block size > --skew-factor × mean
  oversize_block       a block's on-disk size > --max-block-kb

Exit codes:
  0   profile printed, OR clean SKIP (file absent/unreadable/empty),
      OR anomalies present without --anomalies-only.
  1   args error / malformed input / missing python interpreter.
  2   --anomalies-only AND >=1 anomaly fired.
EOF
}

CHAIN_FILE=""
TOP=10
SKEW_FACTOR=50
MAX_BLOCK_KB=4096
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --chain-file)      CHAIN_FILE="${2:-}";  shift 2 ;;
    --top)             TOP="${2:-}";         shift 2 ;;
    --skew-factor)     SKEW_FACTOR="${2:-}"; shift 2 ;;
    --max-block-kb)    MAX_BLOCK_KB="${2:-}";shift 2 ;;
    --json)            JSON_OUT=1;           shift ;;
    --anomalies-only)  ANOM_ONLY=1;          shift ;;
    *) echo "operator_chain_storage_profile: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --chain-file is required (this is a pure file inspector; there is no
# RPC fallback by design).
if [ -z "$CHAIN_FILE" ]; then
  echo "operator_chain_storage_profile: --chain-file is required" >&2
  usage >&2
  exit 1
fi

# Numeric guards on user-supplied values.
for label_val in "top:$TOP" "skew-factor:$SKEW_FACTOR" "max-block-kb:$MAX_BLOCK_KB"; do
  label=${label_val%%:*}
  v=${label_val#*:}
  case "$v" in *[!0-9]*|"")
    echo "operator_chain_storage_profile: --$label must be a positive integer (got '$v')" >&2
    exit 1 ;;
  esac
done
if [ "$TOP" -lt 1 ];          then echo "operator_chain_storage_profile: --top must be >= 1" >&2; exit 1; fi
if [ "$SKEW_FACTOR" -lt 1 ];  then echo "operator_chain_storage_profile: --skew-factor must be >= 1" >&2; exit 1; fi
if [ "$MAX_BLOCK_KB" -lt 1 ]; then echo "operator_chain_storage_profile: --max-block-kb must be >= 1" >&2; exit 1; fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: stat the file. Absent / unreadable ⇒ clean SKIP (exit 0). ────────
# Cron-friendly: a node that hasn't written chain.json yet, or a path the
# operator pointed wrong, should not hard-fail the whole monitoring run.
if [ ! -e "$CHAIN_FILE" ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"chain_file":"%s","status":"skip","reason":"file_not_found","anomalies":[]}\n' "$CHAIN_FILE"
  else
    echo "operator_chain_storage_profile: [INFO] chain-file not found: $CHAIN_FILE (SKIP)"
  fi
  exit 0
fi
if [ ! -f "$CHAIN_FILE" ] || [ ! -r "$CHAIN_FILE" ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"chain_file":"%s","status":"skip","reason":"not_a_readable_file","anomalies":[]}\n' "$CHAIN_FILE"
  else
    echo "operator_chain_storage_profile: [INFO] chain-file not a readable regular file: $CHAIN_FILE (SKIP)"
  fi
  exit 0
fi

# ── Step 2: locate a python interpreter (parse + distribution math). ─────────
PYEXE=""
if   command -v python3 >/dev/null 2>&1; then PYEXE=python3
elif command -v python  >/dev/null 2>&1; then PYEXE=python
fi
if [ -z "$PYEXE" ]; then
  echo "operator_chain_storage_profile: requires python (python3 or python) for JSON parsing" >&2
  exit 1
fi

# ── Step 3: parse + profile, in one python pass. ─────────────────────────────
# The python core does all the heavy lifting: format detection, per-block
# compact-serialize byte measurement, distribution stats, top-N selection,
# heaviest-block per-field breakdown, and anomaly classification. It emits a
# single compact JSON object on stdout (machine envelope), which the bash
# layer either prints verbatim (--json) or renders into the human digest.
#
# We pass tunables as argv so the python stays a static heredoc (no shell
# interpolation into the program body — avoids quoting hazards).
PROFILE_JSON=$("$PYEXE" - "$CHAIN_FILE" "$TOP" "$SKEW_FACTOR" "$MAX_BLOCK_KB" <<'PY'
import json, sys

chain_file   = sys.argv[1]
top_n        = int(sys.argv[2])
skew_factor  = int(sys.argv[3])
max_block_kb = int(sys.argv[4])

def fail(reason):
    # Structured failure the bash layer maps to exit 1.
    sys.stdout.write(json.dumps({"status": "error", "reason": reason}))
    sys.exit(0)

try:
    with open(chain_file, "rb") as fh:
        raw = fh.read()
except Exception as e:
    fail("read_failed: %s" % e)

try:
    doc = json.loads(raw)
except Exception as e:
    fail("not_json: %s" % e)

# Accept both on-disk forms (src/chain/chain.cpp::load):
#   * wrapped object { "head_hash": "<hex>", "blocks": [...] }
#   * legacy bare array of blocks.
head_hash = ""
if isinstance(doc, list):
    blocks = doc
    fmt = "legacy-array"
elif isinstance(doc, dict):
    if "blocks" not in doc or not isinstance(doc["blocks"], list):
        fail("wrapped form missing 'blocks' array")
    blocks = doc["blocks"]
    head_hash = doc.get("head_hash", "") or ""
    fmt = "wrapped"
else:
    fail("expected JSON array or object")

n = len(blocks)
if n == 0:
    sys.stdout.write(json.dumps({
        "status": "empty", "format": fmt, "head_hash": head_hash,
        "block_count": 0,
    }))
    sys.exit(0)

# Compact serializer — measure on-disk-equivalent byte weight without the
# pretty-print whitespace that nlohmann::json::dump(2) adds. Using a
# canonical compact form makes per-block numbers comparable run-to-run and
# host-to-host (the absolute bytes differ from the indented file, but the
# RELATIVE distribution + per-field breakdown — the operator-actionable
# signal — is stable). We report this explicitly in the output.
def csize(obj):
    return len(json.dumps(obj, separators=(",", ":")).encode("utf-8"))

sizes = []
max_size = -1
max_idx_pos = -1          # position in the blocks array of the heaviest block
for i, b in enumerate(blocks):
    s = csize(b)
    sizes.append(s)
    if s > max_size:
        max_size = s
        max_idx_pos = i

total = sum(sizes)
mean = total / n

# Median + p95 over the sorted size vector. For n==1 both collapse to the
# single value, which is correct.
ssorted = sorted(sizes)
def pct(p):
    if n == 1:
        return ssorted[0]
    # Nearest-rank percentile (no interpolation) — simple + defensible for
    # an operator profile.
    import math
    rank = max(1, math.ceil(p / 100.0 * n))
    return ssorted[rank - 1]
median = pct(50)
p95    = pct(95)
min_size = ssorted[0]

# Per-field byte breakdown of the single heaviest block. We re-serialize
# each TOP-LEVEL key's value compactly. The numbers won't sum exactly to
# the block's own csize (keys + structural punctuation are excluded), but
# they rank the contributors, which is what the operator wants ("the fat
# block is fat because of cross_shard_receipts").
heaviest_block = blocks[max_idx_pos]
hb_index = heaviest_block.get("index", None) if isinstance(heaviest_block, dict) else None
field_bytes = []
if isinstance(heaviest_block, dict):
    for k, v in heaviest_block.items():
        field_bytes.append((k, csize(v)))
    field_bytes.sort(key=lambda kv: kv[1], reverse=True)

# Top-N heaviest blocks (by on-disk size), reported by their .index field
# (falling back to array position when a block lacks an index — shouldn't
# happen for a real chain.json but we stay defensive).
order = sorted(range(n), key=lambda i: sizes[i], reverse=True)[:top_n]
top_blocks = []
for i in order:
    b = blocks[i]
    bidx = b.get("index", i) if isinstance(b, dict) else i
    top_blocks.append({"index": bidx, "bytes": sizes[i]})

# ── Anomaly classification. ──────────────────────────────────────────────
anomalies = []
# block_size_skew: one block dwarfs the mean. Only meaningful for n>=2.
if n >= 2 and max_size > skew_factor * mean:
    anomalies.append({
        "kind": "block_size_skew",
        "severity": "WARN",
        "detail": "max block %d bytes > %dx mean (%.0f bytes); block index=%s"
                  % (max_size, skew_factor, mean,
                     str(hb_index) if hb_index is not None else "?"),
    })
# oversize_block: any block over the byte ceiling.
max_block_bytes = max_block_kb * 1024
oversize = [(blocks[i].get("index", i) if isinstance(blocks[i], dict) else i, sizes[i])
            for i in range(n) if sizes[i] > max_block_bytes]
if oversize:
    sample = oversize[:5]
    anomalies.append({
        "kind": "oversize_block",
        "severity": "WARN",
        "detail": "%d block(s) > %d KB on disk; e.g. %s"
                  % (len(oversize), max_block_kb,
                     ", ".join("index=%s(%dB)" % (ix, by) for ix, by in sample)),
    })

out = {
    "status": "ok",
    "format": fmt,
    "head_hash": head_hash,
    "block_count": n,
    "size_unit": "compact-json-bytes",
    "total_bytes": total,
    "min_bytes": min_size,
    "mean_bytes": int(round(mean)),
    "median_bytes": median,
    "p95_bytes": p95,
    "max_bytes": max_size,
    "max_block_index": hb_index,
    "top_blocks": top_blocks,
    "heaviest_block_fields": [{"field": k, "bytes": b} for k, b in field_bytes],
    "skew_factor": skew_factor,
    "max_block_kb": max_block_kb,
    "anomalies": anomalies,
}
sys.stdout.write(json.dumps(out))
PY
)

# Python failure (interpreter crash etc.) — empty stdout means the program
# never reached its single json write. Treat as a hard error.
if [ -z "$PROFILE_JSON" ]; then
  echo "operator_chain_storage_profile: profiler produced no output (parse failed?)" >&2
  exit 1
fi

# Materialize the envelope to a temp file. Every downstream python step
# reads it via argv rather than stdin. This is deliberate: the human-render
# step uses a heredoc for its program body, and on a command that has BOTH
# a heredoc AND a stdin pipe the heredoc wins as stdin — so a piped
# `printf "$PROFILE_JSON" | python ... <<'PY'` would feed the program text,
# not the JSON, into json.load(sys.stdin). Passing the envelope by file
# path sidesteps that entirely and is portable across MSYS / Cygwin / POSIX.
ENV_FILE=$(mktemp 2>/dev/null) || {
  echo "operator_chain_storage_profile: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$ENV_FILE"' EXIT
printf '%s' "$PROFILE_JSON" > "$ENV_FILE"

# Pull the status field out so the bash layer can branch (error / skip /
# empty / ok) without a second full parse.
STATUS=$("$PYEXE" -c \
  'import json,sys; print(json.load(open(sys.argv[1])).get("status",""))' "$ENV_FILE" 2>/dev/null)

case "$STATUS" in
  error)
    REASON=$("$PYEXE" -c \
      'import json,sys; print(json.load(open(sys.argv[1])).get("reason",""))' "$ENV_FILE" 2>/dev/null)
    echo "operator_chain_storage_profile: cannot profile $CHAIN_FILE: $REASON" >&2
    exit 1 ;;
  empty)
    if [ "$JSON_OUT" = "1" ]; then
      printf '%s\n' "$PROFILE_JSON"
    else
      echo "operator_chain_storage_profile: [INFO] chain-file has 0 blocks: $CHAIN_FILE (nothing to profile)"
    fi
    exit 0 ;;
  ok)
    : ;;  # fall through to rendering
  *)
    echo "operator_chain_storage_profile: profiler returned unexpected status '$STATUS'" >&2
    exit 1 ;;
esac

# Anomaly count drives the exit gate.
ANOM_COUNT=$("$PYEXE" -c \
  'import json,sys; print(len(json.load(open(sys.argv[1])).get("anomalies",[])))' "$ENV_FILE" 2>/dev/null)
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac

# ── Step 4: emit. ────────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  # The python envelope is already the machine contract; print it verbatim
  # (with the chain_file path injected so the JSON is self-describing).
  "$PYEXE" -c '
import json, sys
d = json.load(open(sys.argv[1]))
d["chain_file"] = sys.argv[2]
sys.stdout.write(json.dumps(d) + "\n")
' "$ENV_FILE" "$CHAIN_FILE"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_chain_storage_profile: no anomalies ($CHAIN_FILE)"
  else
    # Human digest, rendered from the envelope by python (so the byte-count
    # formatting + table layout lives in one place). The envelope arrives
    # via argv (a file path) — NOT via a stdin pipe — because this command
    # carries a heredoc program body, and a heredoc shadows any stdin pipe.
    "$PYEXE" - "$ENV_FILE" "$CHAIN_FILE" "$ANOM_ONLY" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
chain_file = sys.argv[2]
anom_only  = sys.argv[3] == "1"

def human(b):
    b = float(b)
    if b < 1024:               return "%d B" % int(b)
    if b < 1048576:            return "%.1f KB" % (b / 1024)
    if b < 1073741824:         return "%.1f MB" % (b / 1048576)
    return "%.1f GB" % (b / 1073741824)

anomalies = d.get("anomalies", [])

if not anom_only:
    print("=== Chain storage profile (offline) ===")
    print("chain-file:    %s" % chain_file)
    print("format:        %s" % d.get("format", "?"))
    hh = d.get("head_hash", "")
    print("head_hash:     %s" % (hh if hh else "(none / legacy array form)"))
    print("blocks:        %d" % d.get("block_count", 0))
    print("size unit:     %s (compact, whitespace-stripped; relative profile is stable)"
          % d.get("size_unit", "bytes"))
    print("total:         %s (%d bytes, compact)"
          % (human(d.get("total_bytes", 0)), d.get("total_bytes", 0)))
    print("per-block size distribution:")
    print("  min:    %s" % human(d.get("min_bytes", 0)))
    print("  mean:   %s" % human(d.get("mean_bytes", 0)))
    print("  median: %s" % human(d.get("median_bytes", 0)))
    print("  p95:    %s" % human(d.get("p95_bytes", 0)))
    print("  max:    %s  (block index %s)"
          % (human(d.get("max_bytes", 0)), str(d.get("max_block_index"))))
    print("")
    tb = d.get("top_blocks", [])
    print("top %d heaviest blocks (by on-disk size):" % len(tb))
    for row in tb:
        print("  index %-10s %s" % (row.get("index"), human(row.get("bytes", 0))))
    print("")
    fields = d.get("heaviest_block_fields", [])
    if fields:
        print("heaviest block (index %s) per-field byte breakdown:"
              % str(d.get("max_block_index")))
        for fb in fields[:12]:
            print("  %-26s %s" % (fb.get("field"), human(fb.get("bytes", 0))))
        print("")

if not anomalies:
    print("[OK] no storage anomalies (skew-factor=%dx, max-block-kb=%d)"
          % (d.get("skew_factor", 0), d.get("max_block_kb", 0)))
else:
    print("[ANOMALY] %d flag(s):" % len(anomalies))
    mark = {"CRITICAL": "[X]", "WARN": "[!]", "INFO": "[i]"}
    for a in anomalies:
        print("  %s %s (%s): %s"
              % (mark.get(a.get("severity", ""), "[?]"),
                 a.get("kind"), a.get("severity"), a.get("detail")))
PY
  fi
fi

# ── Step 5: exit-code policy. ────────────────────────────────────────────────
# Anomalies are advisory WARN-level; they only force a non-zero exit under
# the explicit --anomalies-only operator gate (matches the read-only
# family convention). Without the gate, a printed profile + present
# anomalies still exits 0 (the operator asked for a report, and got one).
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
