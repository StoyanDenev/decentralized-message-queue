#!/usr/bin/env bash
# operator_backup_health.sh — Check the freshness + integrity of an
# operator's chain backups against the active data directory.
#
# Most determ operators run an out-of-band backup job (cron / systemd
# timer / rsync) that copies the active chain.json + snapshot.json into
# a sibling backup directory. The risk is silent backup failure: the
# backup directory still exists, but its files are days old, or have
# been truncated by a partial copy, or have fallen behind the active
# chain by tens of thousands of blocks. Without an explicit health
# check the operator only learns about the staleness during a restore
# attempt — which is the worst possible time.
#
# This script is a pure local-file linter (no determ binary required,
# no running daemon required). It inspects four files on disk:
#
#   <data>/chain.json       active chain (live writes)
#   <data>/snapshot.json    active snapshot (optional)
#   <backup>/chain.json     last backup of the chain
#   <backup>/snapshot.json  last backup of the snapshot (optional)
#
# Detected anomalies (with --anomalies-only the script exits 2 if any
# CRITICAL fires):
#
#   missing_backup_chain        CRITICAL  backup chain.json absent.
#
#   stale_backup                CRITICAL  backup chain.json mtime older
#                                         than --threshold-hours (default
#                                         24).  Default detector — flags
#                                         the most common silent-failure
#                                         mode (cron job stopped firing).
#
#   truncated_backup            CRITICAL  backup file > 50% smaller than
#                                         the active sibling.  Indicates
#                                         a partial / interrupted copy
#                                         (rsync killed mid-transfer,
#                                         destination disk filled, etc.).
#
#   backup_skew                 CRITICAL  active chain.json has > 1000
#                                         more blocks than the backup
#                                         chain.json.  Cron job is firing
#                                         but the backup is no longer
#                                         keeping up with chain growth.
#
#   missing_backup_snapshot     WARN      backup snapshot.json absent
#                                         when active snapshot.json
#                                         exists.  Not strictly required
#                                         (chain.json is sufficient for
#                                         full replay) but the operator
#                                         loses the fast-restore path.
#
#   missing_active_chain        WARN      active chain.json absent.  May
#                                         indicate the active daemon
#                                         was uninstalled / data-dir
#                                         changed without updating the
#                                         backup config.
#
# Block-count extraction:
#
# Per S-021, chain.json is wrapped as `{head_hash, blocks: [...]}` so we
# count `blocks` directly via Python json.load.  Legacy array-form
# (pre-S-021) is supported too — the array length is the block count.
# This works without a running daemon; the file is the ground truth.
#
# Usage:
#   tools/operator_backup_health.sh [--backup-dir <dir>] [--data-dir <dir>]
#                                   [--threshold-hours N] [--anomalies-only]
#                                   [--json]
#
# Exit codes:
#   0   audit ran; no CRITICAL anomalies (WARN entries may still appear)
#   1   bad args / unreadable directory / malformed chain.json
#   2   --anomalies-only AND >= 1 CRITICAL anomaly fired
set -u

usage() {
  cat <<'EOF'
Usage: operator_backup_health.sh [--backup-dir <dir>] [--data-dir <dir>]
                                 [--threshold-hours N] [--anomalies-only]
                                 [--json]

Check the freshness + integrity of an operator's chain backups. Pure
local-file linter: no determ binary required, no running daemon
required. Inspects chain.json + snapshot.json in both the active data
dir and the operator's backup dir, reports mtime / size / block-count
deltas, and flags CRITICAL anomalies (stale backup, truncated backup,
backup-skew > 1000 blocks, missing backup chain).

Options:
  --backup-dir <dir>     Operator's backup target (default: $HOME/.determ-backup)
  --data-dir <dir>       Active determ data dir   (default: $HOME/.determ)
  --threshold-hours N    Backup-age threshold in hours (default: 24)
  --anomalies-only       Print only flagged anomalies; exit 2 if any
                         CRITICAL anomaly fired
  --json                 Emit single-line JSON envelope instead of human digest
  -h, --help             Show this help

Anomaly flags:
  missing_backup_chain    CRITICAL  backup chain.json absent
  stale_backup            CRITICAL  backup chain.json older than threshold
  truncated_backup        CRITICAL  backup file > 50% smaller than active
  backup_skew             CRITICAL  active is > 1000 blocks ahead of backup
  missing_backup_snapshot WARN      backup snapshot.json absent (active present)
  missing_active_chain    WARN      active chain.json absent

Exit codes:
  0   no CRITICAL anomalies
  1   bad args / unreadable dir / malformed chain.json
  2   --anomalies-only AND >= 1 CRITICAL anomaly fired

JSON shape (--json):
  {"data_dir":"<path>","backup_dir":"<path>","threshold_hours":N,
   "now_unix":<u64>,
   "active":{
     "chain":{"present":<bool>,"path":"<p>","size":<u64>,"mtime":<u64>,"blocks":<u64>|null},
     "snapshot":{"present":<bool>,"path":"<p>","size":<u64>,"mtime":<u64>}
   },
   "backup":{
     "chain":{"present":<bool>,"path":"<p>","size":<u64>,"mtime":<u64>,"blocks":<u64>|null},
     "snapshot":{"present":<bool>,"path":"<p>","size":<u64>,"mtime":<u64>}
   },
   "deltas":{
     "backup_age_seconds":<u64>|null,
     "chain_size_delta_bytes":<i64>|null,"chain_size_delta_pct_bps":<i64>|null,
     "snapshot_size_delta_bytes":<i64>|null,"snapshot_size_delta_pct_bps":<i64>|null,
     "blocks_skew":<i64>|null
   },
   "anomalies":[{"name":"...","severity":"CRITICAL"|"WARN","message":"..."}],
   "summary":{"critical":N,"warn":N},
   "exit_code":0|2}
EOF
}

BACKUP_DIR="${HOME:-}/.determ-backup"
DATA_DIR="${HOME:-}/.determ"
THRESHOLD_HOURS=24
ANOM_ONLY=0
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)            usage; exit 0 ;;
    --backup-dir)         BACKUP_DIR="$2";       shift 2 ;;
    --data-dir)           DATA_DIR="$2";         shift 2 ;;
    --threshold-hours)    THRESHOLD_HOURS="$2";  shift 2 ;;
    --anomalies-only)     ANOM_ONLY=1;           shift ;;
    --json)               JSON_OUT=1;            shift ;;
    *) echo "operator_backup_health: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# Numeric guard on threshold-hours. Accept positive integers only;
# fractional thresholds would need different reasoning around mtime
# precision (some filesystems still have 1s mtime granularity).
case "$THRESHOLD_HOURS" in
  *[!0-9]*|"")
    echo "operator_backup_health: --threshold-hours must be a positive integer (got '$THRESHOLD_HOURS')" >&2
    exit 1 ;;
esac
if [ "$THRESHOLD_HOURS" -le 0 ]; then
  echo "operator_backup_health: --threshold-hours must be >= 1 (got $THRESHOLD_HOURS)" >&2
  exit 1
fi

if [ -z "$BACKUP_DIR" ] || [ -z "$DATA_DIR" ]; then
  echo "operator_backup_health: --backup-dir and --data-dir cannot be empty (HOME unset?)" >&2
  exit 1
fi

# --backup-dir absence is itself an anomaly (we still emit a report
# saying "no backup directory at all"); --data-dir absence is operator
# error (can't compare against active state we can't see).
if [ ! -d "$DATA_DIR" ]; then
  echo "operator_backup_health: --data-dir not found or not a directory: $DATA_DIR" >&2
  exit 1
fi
if [ ! -r "$DATA_DIR" ]; then
  echo "operator_backup_health: --data-dir not readable: $DATA_DIR" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
# Pure local-file linter — no determ binary needed. Pre-set DETERM_BIN
# to the POSIX no-op so common.sh's binary-presence check succeeds on
# audit workstations that don't have a built determ.exe. Same trick as
# operator_config_audit.sh.
: "${DETERM_BIN:=:}"
export DETERM_BIN
source tools/common.sh

# Drive size / mtime inspection + chain.json block counting + anomaly
# evaluation in Python. The chain.json file may be large (multi-MB to
# multi-GB on a long-running chain), but the only data we care about is
# the length of the top-level `blocks` array, which json.load handles
# correctly even at multi-GB sizes (memory is the only constraint).
#
# Python emits the script's final exit code (0 on no-CRITICAL or
# default mode; 2 on --anomalies-only AND >= 1 CRITICAL). Capture rc
# and forward — same fan-out pattern as operator_config_audit.sh.
python - "$DATA_DIR" "$BACKUP_DIR" "$THRESHOLD_HOURS" \
         "$ANOM_ONLY" "$JSON_OUT" <<'PY'
import json, os, sys, time

data_dir         = sys.argv[1]
backup_dir       = sys.argv[2]
threshold_hours  = int(sys.argv[3])
anom_only        = sys.argv[4] == "1"
json_out         = sys.argv[5] == "1"

now = int(time.time())
threshold_seconds = threshold_hours * 3600

# ── File inspection helpers ──────────────────────────────────────────
# Per-file struct: { present, path, size, mtime }. mtime is unix
# seconds (int). Absent files report present=False, size=0, mtime=0.
def stat_file(path):
    try:
        st = os.stat(path)
        return {
            "present": True,
            "path":    path,
            "size":    int(st.st_size),
            "mtime":   int(st.st_mtime),
        }
    except FileNotFoundError:
        return {"present": False, "path": path, "size": 0, "mtime": 0}
    except OSError as e:
        sys.stderr.write(f"operator_backup_health: stat({path}) failed: {e}\n")
        sys.exit(1)

# Block-count extraction from a chain.json file.
#
# Supports both formats (S-021 introduced the wrapped form):
#   * wrapped: { "head_hash": "<hex>", "blocks": [ ... ] }
#   * legacy : [ ... ]   (bare array — pre-S-021)
#
# Returns the block count as int, or None on missing / malformed file.
# A malformed file (parse error) is treated as a hard error — emit
# diagnostic to stderr + exit 1.  Missing file => None (anomaly path
# will catch this separately).
def count_blocks(path):
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"operator_backup_health: cannot parse chain.json at {path}: {e}\n")
        sys.exit(1)
    except OSError as e:
        sys.stderr.write(f"operator_backup_health: cannot read {path}: {e}\n")
        sys.exit(1)
    if isinstance(data, dict):
        blocks = data.get("blocks")
        if isinstance(blocks, list):
            return len(blocks)
        # Wrapped form with empty / malformed blocks field.
        return 0
    if isinstance(data, list):
        return len(data)
    sys.stderr.write(f"operator_backup_health: chain.json at {path} is neither object nor array\n")
    sys.exit(1)

active_chain_path    = os.path.join(data_dir,   "chain.json")
active_snapshot_path = os.path.join(data_dir,   "snapshot.json")
backup_chain_path    = os.path.join(backup_dir, "chain.json")
backup_snapshot_path = os.path.join(backup_dir, "snapshot.json")

# Backup-dir absence is observable but not fatal — we still emit a
# report ("backup dir does not exist") and let the anomaly evaluator
# flag missing_backup_chain. Active-dir absence was already a hard
# error in the shell preamble.
backup_dir_exists = os.path.isdir(backup_dir)

active = {
    "chain":    stat_file(active_chain_path),
    "snapshot": stat_file(active_snapshot_path),
}
backup = {
    "chain":    stat_file(backup_chain_path),
    "snapshot": stat_file(backup_snapshot_path),
}

# Block counts: only attempt the (potentially expensive) JSON parse on
# files we know are present. Absent => None.
active["chain"]["blocks"] = count_blocks(active_chain_path) if active["chain"]["present"] else None
backup["chain"]["blocks"] = count_blocks(backup_chain_path) if backup["chain"]["present"] else None

# ── Delta computation ────────────────────────────────────────────────
# Each delta is None if at least one side is absent (no meaningful
# comparison possible). Percentages are reported in basis points
# (1/10000) to avoid float ambiguity in the JSON envelope — a -4.2%
# delta is -420 bps.
def size_delta(active_present, active_size, backup_present, backup_size):
    if not active_present or not backup_present:
        return (None, None)
    delta = backup_size - active_size
    if active_size > 0:
        pct_bps = int(round(delta * 10000 / active_size))
    else:
        pct_bps = None
    return (delta, pct_bps)

chain_dbytes,    chain_dbps    = size_delta(active["chain"]["present"],    active["chain"]["size"],
                                            backup["chain"]["present"],    backup["chain"]["size"])
snap_dbytes,     snap_dbps     = size_delta(active["snapshot"]["present"], active["snapshot"]["size"],
                                            backup["snapshot"]["present"], backup["snapshot"]["size"])

backup_age_seconds = None
if backup["chain"]["present"]:
    backup_age_seconds = max(0, now - backup["chain"]["mtime"])

blocks_skew = None
if active["chain"]["blocks"] is not None and backup["chain"]["blocks"] is not None:
    # Positive: active is AHEAD of backup (the expected direction).
    # Negative: backup somehow has more blocks than active (operator
    # restored from backup without re-pointing active, or copied the
    # wrong direction); reported as-is so the operator can see it.
    blocks_skew = active["chain"]["blocks"] - backup["chain"]["blocks"]

deltas = {
    "backup_age_seconds":          backup_age_seconds,
    "chain_size_delta_bytes":      chain_dbytes,
    "chain_size_delta_pct_bps":    chain_dbps,
    "snapshot_size_delta_bytes":   snap_dbytes,
    "snapshot_size_delta_pct_bps": snap_dbps,
    "blocks_skew":                 blocks_skew,
}

# ── Anomaly evaluation ──────────────────────────────────────────────
anomalies = []
def flag(name, severity, message):
    anomalies.append({"name": name, "severity": severity, "message": message})

# missing_backup_chain — backup chain.json is the canonical recovery
# artifact; its absence is always CRITICAL.
if not backup["chain"]["present"]:
    if backup_dir_exists:
        flag("missing_backup_chain", "CRITICAL",
             f"backup chain.json not found at {backup_chain_path}")
    else:
        flag("missing_backup_chain", "CRITICAL",
             f"backup directory does not exist: {backup_dir}")
else:
    # stale_backup — only meaningful when the backup chain.json exists.
    if backup_age_seconds is not None and backup_age_seconds > threshold_seconds:
        hrs = backup_age_seconds / 3600.0
        flag("stale_backup", "CRITICAL",
             f"backup chain.json is {hrs:.1f} hours old (threshold {threshold_hours})")

    # truncated_backup — backup is > 50% smaller than the active file.
    # Indicates a partial copy.  Only flagged when both files exist
    # AND the active file is non-empty (a 0-byte active is operator
    # state we can't infer truncation from).
    if active["chain"]["present"] and active["chain"]["size"] > 0:
        if backup["chain"]["size"] * 2 < active["chain"]["size"]:
            pct = backup["chain"]["size"] * 100.0 / active["chain"]["size"]
            flag("truncated_backup", "CRITICAL",
                 f"backup chain.json is {pct:.1f}% the size of active "
                 f"(active={active['chain']['size']}B, "
                 f"backup={backup['chain']['size']}B)")

    # backup_skew — active is > 1000 blocks ahead of backup. The 1000
    # threshold is a fixed heuristic: at typical 200ms block timing
    # (web profile) that's ~3 minutes of chain growth, well inside any
    # sensible backup cadence.  At slower profiles (global=600ms)
    # it's ~10 minutes — still well inside an hourly backup window.
    if blocks_skew is not None and blocks_skew > 1000:
        flag("backup_skew", "CRITICAL",
             f"active is {blocks_skew} blocks ahead of backup "
             f"(active={active['chain']['blocks']}, "
             f"backup={backup['chain']['blocks']})")

# Snapshot file is optional — its absence is WARN, not CRITICAL,
# because chain.json alone supports full replay.  We only flag the
# missing backup snapshot if the ACTIVE snapshot exists (the operator
# clearly is using snapshots, so they want the backup too).
if active["snapshot"]["present"] and not backup["snapshot"]["present"]:
    flag("missing_backup_snapshot", "WARN",
         f"active snapshot.json present but backup snapshot.json missing "
         f"({backup_snapshot_path})")

# Truncated-backup also applies to snapshot.json when both exist.
if (active["snapshot"]["present"] and backup["snapshot"]["present"]
        and active["snapshot"]["size"] > 0):
    if backup["snapshot"]["size"] * 2 < active["snapshot"]["size"]:
        pct = backup["snapshot"]["size"] * 100.0 / active["snapshot"]["size"]
        flag("truncated_backup", "CRITICAL",
             f"backup snapshot.json is {pct:.1f}% the size of active "
             f"(active={active['snapshot']['size']}B, "
             f"backup={backup['snapshot']['size']}B)")

# missing_active_chain — operator may have moved their data-dir
# without updating their backup config.  Less severe than a missing
# backup (the daemon's current state isn't where we're looking) but
# still worth surfacing.
if not active["chain"]["present"]:
    flag("missing_active_chain", "WARN",
         f"active chain.json not found at {active_chain_path}")

# ── Summary + exit code ─────────────────────────────────────────────
summary = {"critical": 0, "warn": 0}
for a in anomalies:
    if a["severity"] == "CRITICAL": summary["critical"] += 1
    elif a["severity"] == "WARN":   summary["warn"]     += 1

exit_code = 2 if (anom_only and summary["critical"] > 0) else 0

# ── Output ───────────────────────────────────────────────────────────
if json_out:
    print(json.dumps({
        "data_dir":         data_dir,
        "backup_dir":       backup_dir,
        "threshold_hours":  threshold_hours,
        "now_unix":         now,
        "active":           active,
        "backup":           backup,
        "deltas":           deltas,
        "anomalies":        anomalies,
        "summary":          summary,
        "exit_code":        exit_code,
    }))
    sys.exit(exit_code)

# Human-readable formatters.
def human_size(n):
    if n is None: return "?"
    if n < 1024:                 return f"{n} B"
    if n < 1048576:              return f"{n/1024:.1f} KB"
    if n < 1073741824:           return f"{n/1048576:.1f} MB"
    return f"{n/1073741824:.1f} GB"

def human_age(seconds):
    if seconds is None: return "?"
    if seconds < 60:    return f"{seconds} seconds"
    if seconds < 3600:  return f"{seconds/60:.1f} minutes"
    if seconds < 86400: return f"{seconds/3600:.1f} hours"
    return f"{seconds/86400:.1f} days"

def human_pct(bps):
    if bps is None: return "n/a"
    sign = "+" if bps >= 0 else "-"
    abs_bps = abs(bps)
    return f"{sign}{abs_bps // 100}.{(abs_bps % 100) // 10}%"

def render_line(label, active_size, backup_size, pct_bps):
    a_h = human_size(active_size) if active_size is not None else "missing"
    b_h = human_size(backup_size) if backup_size is not None else "missing"
    if pct_bps is None:
        delta_str = ""
    else:
        delta_str = f" ({human_pct(pct_bps)})"
    return f"  {label}  active={a_h}, backup={b_h}{delta_str}"

# Suppress informational sections under --anomalies-only when there
# are no anomalies; mirror operator_block_size_audit's behaviour.
total_anom = len(anomalies)

if anom_only and total_anom == 0:
    print(f"operator_backup_health: no anomalies (data={data_dir}, backup={backup_dir})")
    sys.exit(exit_code)

print(f"=== Backup health (data={data_dir}, backup={backup_dir}) ===")
if anom_only != True:
    if backup_age_seconds is not None:
        print(f"Backup age: {human_age(backup_age_seconds)}")
        mtime_str = time.strftime("%Y-%m-%d %H:%M:%S UTC",
                                  time.gmtime(backup["chain"]["mtime"]))
        print(f"Last backup at: {mtime_str}")
    else:
        print("Backup age: n/a (backup chain.json not found)")
    print("Active vs backup:")
    print(render_line("chain.json:   ",
                      active["chain"]["size"]    if active["chain"]["present"]    else None,
                      backup["chain"]["size"]    if backup["chain"]["present"]    else None,
                      chain_dbps))
    print(render_line("snapshot.json:",
                      active["snapshot"]["size"] if active["snapshot"]["present"] else None,
                      backup["snapshot"]["size"] if backup["snapshot"]["present"] else None,
                      snap_dbps))
    if active["chain"]["blocks"] is not None or backup["chain"]["blocks"] is not None:
        a_b = active["chain"]["blocks"] if active["chain"]["blocks"] is not None else "?"
        b_b = backup["chain"]["blocks"] if backup["chain"]["blocks"] is not None else "?"
        skew_str = f" (skew={blocks_skew})" if blocks_skew is not None else ""
        print(f"  block counts:   active={a_b}, backup={b_b}{skew_str}")

if total_anom == 0:
    if backup_age_seconds is not None and backup_age_seconds <= threshold_seconds:
        print(f"[OK] backup fresh (< {threshold_hours} hours)")
    else:
        print("[OK] no anomalies")
else:
    print(f"[ANOMALY] {total_anom} flag(s): "
          f"{summary['critical']} CRITICAL, {summary['warn']} WARN")
    for a in anomalies:
        sev_tag = "[CRIT]" if a["severity"] == "CRITICAL" else "[WARN]"
        print(f"  {sev_tag} {a['name']:<24} {a['message']}")

sys.exit(exit_code)
PY
PY_RC=$?
# Forward Python's rc verbatim — same fan-out as operator_config_audit:
# Python exits 1 on its own internal errors (already emitted to stderr),
# 0 on no-CRITICAL or default mode, 2 on --anomalies-only AND >=1
# CRITICAL.  Preserve the operator-alert gate at exit 2.
exit "$PY_RC"
