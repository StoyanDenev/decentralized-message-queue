#!/usr/bin/env bash
# operator_snapshot_field_coverage.sh — Pure-offline snapshot SCHEMA /
# field-completeness audit. Parses a `determ snapshot create` file and
# checks its TOP-LEVEL key set against the exact field set that
# Chain::serialize_state emits (src/chain/chain.cpp lines 1541-1709),
# flagging S-037-class omissions: state-root-bearing fields whose absence
# makes Chain::restore_from_snapshot silently fall back to a default and
# recompute a DIVERGENT state_root, tripping the S-033 gate on the very
# block that follows the restore.
#
# Why this is a distinct lane (NOT a dup of the existing snapshot tools):
#   * operator_snapshot_check.sh       — runs `determ snapshot inspect`,
#                                        i.e. the full restore + state_root
#                                        verify pipeline (needs the binary;
#                                        a structural failure aborts the
#                                        whole inspect, it does not tell the
#                                        operator WHICH fields were missing).
#   * operator_snapshot_diff_report.sh — two snapshots, field-level DELTA.
#   * operator_snapshot_lineage.sh     — directory walk + freshness + gaps.
#   * operator_backup_health.sh        — backup file mtime / size freshness.
#   * `determ snapshot stats`          — reports ONLY version, block_index,
#                                        head_hash, accounts/stakes/registrants
#                                        COUNTS, and the 5 A1 counters
#                                        (src/main.cpp cmd_snapshot_stats,
#                                        lines 4226-4241). It is SILENT on
#                                        the ~20 other top-level fields —
#                                        including every S-037-class field.
#
# None of the above answers "is THIS snapshot file structurally complete
# vs the current serializer, and which specific fields would default on
# restore?" — and they all need either the daemon or a second file. This
# tool is the static, single-file, binary-free completeness gate.
#
# What it reads (pure JSON parse — NO daemon, NO restore, NO mutation):
#   The top-level keys of the snapshot object. The authoritative emitted
#   set is mirrored from Chain::serialize_state:
#     version, block_index, head_hash,
#     accounts, stakes, registrants, applied_inbound_receipts,
#     block_subsidy, subsidy_pool_initial, subsidy_mode,
#     lottery_jackpot_multiplier, min_stake,
#     suspension_slash, unstake_delay,
#     merge_threshold_blocks, revert_threshold_blocks, merge_grace_blocks,
#     shard_count, shard_salt, shard_id,
#     genesis_total, accumulated_subsidy, accumulated_slashed,
#     accumulated_inbound, accumulated_outbound,
#     abort_records, merge_state, dapp_registry, pending_param_changes,
#     headers.
#
#   Each key is classified by whether its ABSENCE changes the restored
#   chain's compute_state_root() result (a state-root-bearing field) or is
#   merely informational. The state-root-bearing set is the S-037 surface:
#   restore_from_snapshot defaults a missing field, so its leaf vanishes /
#   diverges in build_state_leaves and the S-033 gate rejects the next
#   block. The classification mirrors the source comments at
#   chain.cpp:1606-1613 (merge thresholds, k: namespace) and
#   chain.cpp:1655-1677 (dapp_registry, d: namespace).
#
# Usage:
#   tools/operator_snapshot_field_coverage.sh --snapshot-file <path>
#                                             [--json] [--anomalies-only]
#
# Anomalies (flagged in the envelope + human verdict):
#   missing_state_root_field   (CRITICAL)
#     A state-root-bearing field is absent. On restore the field defaults
#     and the recomputed state_root diverges from the tail header's stored
#     value — the S-033 gate rejects the first post-restore block. This is
#     the exact S-037 failure mode (dapp_registry was such a field before
#     its closure). Each flagged field names the namespace it feeds.
#   missing_informational_field  (WARN)
#     A non-state-root field is absent (e.g. a count-only or continuity
#     field). The chain still restores, but a downstream tool reading that
#     field gets a default. Advisory.
#   wrong_version  (CRITICAL)
#     version != 1. restore_from_snapshot hard-rejects anything but 1
#     (chain.cpp:1714-1717); the file will not load at all.
#   unknown_extra_field  (WARN)
#     A top-level key not in the serializer's emitted set. Either the file
#     was produced by a NEWER determ than this tool knows about (schema
#     drift — update the tool) or it was hand-edited / corrupted.
#   empty_chain_snapshot   (INFO, not gated)
#     block_index == 0 AND head_hash empty — a genesis-only snapshot.
#     Reported so the operator distinguishes it from a truncated file.
#
# Exit codes (read-only family convention):
#   0   audit completed (even with anomalies, unless --anomalies-only)
#   1   bad args / missing python / file present but unparseable
#   2   --anomalies-only AND >= 1 anomaly fired
#
#   Absent / unreadable --snapshot-file ⇒ clean INFO + SKIP, exit 0
#   (cron-friendly: a node that has not written a snapshot yet, or a
#   mis-pointed path, must not hard-fail a monitoring run).
set -u

usage() {
  cat <<'EOF'
Usage: operator_snapshot_field_coverage.sh --snapshot-file <path>
                                           [--json] [--anomalies-only]

Offline snapshot field-completeness audit. Compares a snapshot file's
top-level key set against the exact set Chain::serialize_state emits and
flags S-037-class omissions (state-root-bearing fields that would default
on restore and trip the S-033 state_root gate).

Required:
  --snapshot-file <path>   Snapshot JSON from `determ snapshot create`.
                           Absent / unreadable ⇒ clean INFO + SKIP (exit 0).

Options:
  --json                   Emit the structured JSON envelope (one line).
  --anomalies-only         Suppress the full coverage table; print only
                           flagged anomalies. Exit 2 if any fired.
  -h, --help               Show this help and exit 0.

Exit codes:
  0   audit completed (anomalies allowed unless --anomalies-only)
  1   bad args / missing python / file present but unparseable
  2   --anomalies-only AND >= 1 anomaly fired

JSON envelope (--json):
  {"snapshot_file": "<path>",
   "status": "ok",
   "version": <int>,
   "block_index": <int>,
   "head_hash": "<hex>",
   "present_fields": ["..."],
   "missing_state_root_fields": ["..."],
   "missing_informational_fields": ["..."],
   "unknown_extra_fields": ["..."],
   "coverage_pct": <float 0..100>,
   "anomalies": [{"kind":"...","severity":"...","detail":"..."}]}
EOF
}

SNAP_FILE=""
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --snapshot-file)   SNAP_FILE="${2:-}";  shift 2 ;;
    --json)            JSON_OUT=1;          shift ;;
    --anomalies-only)  ANOM_ONLY=1;         shift ;;
    *) echo "operator_snapshot_field_coverage: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --snapshot-file is required (pure file inspector; no RPC fallback).
if [ -z "$SNAP_FILE" ]; then
  echo "operator_snapshot_field_coverage: --snapshot-file is required" >&2
  usage >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# ── Step 1: stat the file. Absent / unreadable ⇒ clean SKIP (exit 0). ────────
if [ ! -e "$SNAP_FILE" ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"snapshot_file":"%s","status":"skip","reason":"file_not_found","skipped":true,"anomalies":[]}\n' "$SNAP_FILE"
  else
    echo "operator_snapshot_field_coverage: [INFO] snapshot-file not found: $SNAP_FILE (SKIP)"
  fi
  exit 0
fi
if [ ! -f "$SNAP_FILE" ] || [ ! -r "$SNAP_FILE" ]; then
  if [ "$JSON_OUT" = "1" ]; then
    printf '{"snapshot_file":"%s","status":"skip","reason":"not_a_readable_file","skipped":true,"anomalies":[]}\n' "$SNAP_FILE"
  else
    echo "operator_snapshot_field_coverage: [INFO] snapshot-file not a readable regular file: $SNAP_FILE (SKIP)"
  fi
  exit 0
fi

# ── Step 2: locate a python interpreter (JSON parse + classification). ───────
PYEXE=""
if   command -v python3 >/dev/null 2>&1; then PYEXE=python3
elif command -v python  >/dev/null 2>&1; then PYEXE=python
fi
if [ -z "$PYEXE" ]; then
  echo "operator_snapshot_field_coverage: requires python (python3 or python) for JSON parsing" >&2
  exit 1
fi

# ── Step 3: parse + classify, in one python pass. ────────────────────────────
# The field taxonomy below is the contract — it mirrors the keys written
# by Chain::serialize_state (src/chain/chain.cpp 1541-1709). Two buckets:
#
#   STATE_ROOT_FIELDS — absence changes the restored chain's
#     compute_state_root() output, so a missing one trips the S-033 gate
#     on the first post-restore block (the S-037 failure class). The
#     namespace each feeds is annotated for the operator (matches
#     build_state_leaves: a:/s:/r:/d:/i:/b:/m:/p:/k:/c: per chain.cpp).
#
#   INFO_FIELDS — restored by restore_from_snapshot for continuity /
#     bookkeeping but NOT a state_root leaf input (headers are tail
#     continuity; the A1 counters seed expected_total but are not hashed
#     into the root; shard identity / genesis-pinned scalars are config
#     the restorer needs but recomputes the root from leaves, not these
#     scalars directly). Their absence is advisory, not a state_root break.
#
# We pass nothing as argv beyond the file path so the program body stays a
# static heredoc (no shell interpolation into python — quoting-hazard free).
COVERAGE_JSON=$("$PYEXE" - "$SNAP_FILE" <<'PY'
import json, sys

snap_file = sys.argv[1]

def fail(reason):
    sys.stdout.write(json.dumps({"status": "error", "reason": reason}))
    sys.exit(0)

try:
    with open(snap_file, "rb") as fh:
        raw = fh.read()
except Exception as e:
    fail("read_failed: %s" % e)

try:
    doc = json.loads(raw)
except Exception as e:
    fail("not_json: %s" % e)

if not isinstance(doc, dict):
    fail("snapshot is not a JSON object")

# State-root-bearing fields → namespace they feed in build_state_leaves.
# Absence ⇒ restore_from_snapshot defaults the field ⇒ a leaf diverges ⇒
# compute_state_root() != tail-header state_root ⇒ S-033 gate rejects the
# first post-restore block. This is the S-037 class.
STATE_ROOT_FIELDS = {
    "accounts":               "a: (balance/nonce)",
    "stakes":                 "s: (locked/unlock_height)",
    "registrants":            "r: (ed_pub/active/inactive/region)",
    "dapp_registry":          "d: (S-037 surface)",
    "applied_inbound_receipts":"i: (applied receipts)",
    "abort_records":          "b: (S-032 abort accumulator)",
    "merge_state":            "m: (R4 mid-merge state)",
    "pending_param_changes":  "p: (A5 pending PARAM_CHANGE)",
    "merge_threshold_blocks": "k: (R7 merge threshold)",
    "revert_threshold_blocks":"k: (R7 revert threshold)",
    "merge_grace_blocks":     "k: (R7 merge grace)",
    "min_stake":              "k: (constants)",
}

# Informational / continuity fields restored for bookkeeping but NOT
# hashed into state_root. Absence is advisory only.
INFO_FIELDS = {
    "version", "block_index", "head_hash",
    "block_subsidy", "subsidy_pool_initial", "subsidy_mode",
    "lottery_jackpot_multiplier",
    "suspension_slash", "unstake_delay",
    "shard_count", "shard_salt", "shard_id",
    "genesis_total", "accumulated_subsidy", "accumulated_slashed",
    "accumulated_inbound", "accumulated_outbound",
    "headers",
}

EMITTED = set(STATE_ROOT_FIELDS) | INFO_FIELDS

present = set(doc.keys())

missing_state = sorted(set(STATE_ROOT_FIELDS) - present)
missing_info  = sorted(INFO_FIELDS - present)
unknown_extra = sorted(present - EMITTED)

version     = doc.get("version", 0)
block_index = doc.get("block_index", 0)
head_hash   = doc.get("head_hash", "") or ""

covered = len(present & EMITTED)
coverage_pct = round(100.0 * covered / len(EMITTED), 1) if EMITTED else 0.0

anomalies = []
for f in missing_state:
    anomalies.append({
        "kind": "missing_state_root_field",
        "severity": "CRITICAL",
        "detail": "field '%s' (feeds %s) absent -- restore defaults it and "
                  "recomputes a divergent state_root (S-033 gate trips on the "
                  "first post-restore block; S-037 class)"
                  % (f, STATE_ROOT_FIELDS[f]),
    })
for f in missing_info:
    anomalies.append({
        "kind": "missing_informational_field",
        "severity": "WARN",
        "detail": "field '%s' absent -- restored via default; not a state_root "
                  "leaf, advisory only" % f,
    })
if version != 1:
    anomalies.append({
        "kind": "wrong_version",
        "severity": "CRITICAL",
        "detail": "version=%s -- restore_from_snapshot hard-rejects anything "
                  "but 1; this file will not load" % str(version),
    })
for f in unknown_extra:
    anomalies.append({
        "kind": "unknown_extra_field",
        "severity": "WARN",
        "detail": "top-level key '%s' not in this tool's known serialize_state "
                  "field set — newer determ schema (update the tool) or a "
                  "hand-edited / corrupted file" % f,
    })

# Genesis-only snapshot note (informational, not gated as an anomaly).
empty_chain = (str(block_index) == "0") and (head_hash == "")

out = {
    "status": "ok",
    "version": version if isinstance(version, int) else 0,
    "block_index": block_index if isinstance(block_index, int) else 0,
    "head_hash": head_hash,
    "present_fields": sorted(present & EMITTED),
    "missing_state_root_fields": missing_state,
    "missing_informational_fields": missing_info,
    "unknown_extra_fields": unknown_extra,
    "coverage_pct": coverage_pct,
    "emitted_field_count": len(EMITTED),
    "empty_chain_snapshot": empty_chain,
    "anomalies": anomalies,
}
sys.stdout.write(json.dumps(out))
PY
)

if [ -z "$COVERAGE_JSON" ]; then
  echo "operator_snapshot_field_coverage: auditor produced no output (parse failed?)" >&2
  exit 1
fi

# Materialize the envelope to a temp file so the human-render heredoc step
# reads it via argv (a heredoc shadows any stdin pipe — same rationale as
# operator_chain_storage_profile.sh).
ENV_FILE=$(mktemp 2>/dev/null) || {
  echo "operator_snapshot_field_coverage: cannot create temp file" >&2; exit 1;
}
trap 'rm -f "$ENV_FILE"' EXIT
printf '%s' "$COVERAGE_JSON" > "$ENV_FILE"

STATUS=$("$PYEXE" -c \
  'import json,sys; print(json.load(open(sys.argv[1])).get("status",""))' "$ENV_FILE" 2>/dev/null)

case "$STATUS" in
  error)
    REASON=$("$PYEXE" -c \
      'import json,sys; print(json.load(open(sys.argv[1])).get("reason",""))' "$ENV_FILE" 2>/dev/null)
    echo "operator_snapshot_field_coverage: cannot audit $SNAP_FILE: $REASON" >&2
    exit 1 ;;
  ok)
    : ;;  # fall through to rendering
  *)
    echo "operator_snapshot_field_coverage: auditor returned unexpected status '$STATUS'" >&2
    exit 1 ;;
esac

ANOM_COUNT=$("$PYEXE" -c \
  'import json,sys; print(len(json.load(open(sys.argv[1])).get("anomalies",[])))' "$ENV_FILE" 2>/dev/null)
case "$ANOM_COUNT" in *[!0-9]*|"") ANOM_COUNT=0 ;; esac

# ── Step 4: emit. ────────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  "$PYEXE" -c '
import json, sys
d = json.load(open(sys.argv[1]))
d["snapshot_file"] = sys.argv[2]
sys.stdout.write(json.dumps(d) + "\n")
' "$ENV_FILE" "$SNAP_FILE"
else
  if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" = "0" ]; then
    echo "operator_snapshot_field_coverage: no anomalies ($SNAP_FILE)"
  else
    "$PYEXE" - "$ENV_FILE" "$SNAP_FILE" "$ANOM_ONLY" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
snap_file = sys.argv[2]
anom_only = sys.argv[3] == "1"

anomalies = d.get("anomalies", [])

if not anom_only:
    print("=== Snapshot field-coverage audit (offline) ===")
    print("snapshot-file: %s" % snap_file)
    print("version:       %s" % str(d.get("version")))
    print("block_index:   %s" % str(d.get("block_index")))
    hh = d.get("head_hash", "")
    print("head_hash:     %s" % (hh if hh else "(empty / genesis-only)"))
    if d.get("empty_chain_snapshot"):
        print("note:          genesis-only snapshot (block_index 0, no head)")
    pf = d.get("present_fields", [])
    print("coverage:      %s%% (%d of %d serialize_state fields present)"
          % (str(d.get("coverage_pct")), len(pf), d.get("emitted_field_count", 0)))
    msr = d.get("missing_state_root_fields", [])
    mif = d.get("missing_informational_fields", [])
    uxf = d.get("unknown_extra_fields", [])
    print("missing state-root fields:    %s" % (", ".join(msr) if msr else "(none)"))
    print("missing informational fields: %s" % (", ".join(mif) if mif else "(none)"))
    print("unknown extra fields:         %s" % (", ".join(uxf) if uxf else "(none)"))
    print("")

if not anomalies:
    print("[OK] snapshot field coverage complete vs Chain::serialize_state")
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
# Anomalies are advisory in default mode (the operator asked for a report
# and got one). Only the explicit --anomalies-only gate forces exit 2.
if [ "$ANOM_ONLY" = "1" ] && [ "$ANOM_COUNT" -gt 0 ]; then
  exit 2
fi
exit 0
