#!/usr/bin/env bash
# operator_keystore_audit.sh — operator-side keyfile presence + POSIX
# permission + leak-hazard audit for keystore directories.
#
# Determ operators store key material on disk in several distinct
# formats. The chain daemon emits `node_key.json` (plaintext JSON with
# `pubkey` + `priv_seed` hex strings) under its --data-dir. The wallet
# binary emits per-account JSON keyfiles in either single-account shape
# (`{address, privkey_hex}`) or batch shape (`{accounts: [...]}`),
# alongside encrypted node-key keyfiles (the 2-line "DETERM-NODE-V1
# <pubkey>\n<DWE1 envelope>\n" format from S-004), Shamir share files
# (`{shares: [{x, y_hex}, ...]}`), and bare AEAD envelope blobs (the
# canonical 6-part dot-separated DWE1 hex serialization).
#
# Operator hygiene risk: when a fleet of accounts accumulates across
# host migrations / OPS rotations / staged operator handoffs, the
# keystore directory ends up holding a MIX of these — some plaintext,
# some encrypted, some Shamir shares, some unknown housekeeping files.
# The high-value failure modes are:
#
#   (1) A plaintext keyfile sitting in a world-readable (0644 / 0755)
#       directory. Anyone with shell access to the box can `cat` it.
#   (2) A passphrase-encrypted variant of a keyfile co-exists with its
#       plaintext sibling for the same address — operator is mid-
#       migration to S-004 but forgot to delete the plaintext.
#   (3) A Shamir share file is group/world-writable — supply-chain
#       attacker can swap shares before the next combine.
#   (4) Mystery non-keyfile files sitting in what is supposed to be a
#       pure keystore directory — housekeeping accumulation.
#
# This script is a pure local-file linter. It does NOT decrypt any
# encrypted keyfile, does NOT contact the daemon, and does NOT mutate
# any file under the target directory. The output is a per-file
# classification table + per-type summary + anomaly list. The audit
# pairs with `determ-wallet keyfile-info` (passive metadata inspector)
# and `determ-wallet account-list` (enumerate keyfiles) but focuses on
# the operator-perspective HAZARD axis rather than the
# wallet-perspective LIST axis.
#
# Detection rules:
#
#   PLAINTEXT_KEYFILE      JSON object whose top level matches either:
#                          - {address: "0x"+64hex, privkey_hex: 64hex}
#                          - {pubkey: 64hex, priv_seed: 64hex}
#                            (chain daemon node_key.json shape)
#                          - {accounts: [{address, privkey_hex}, ...]}
#                            (wallet batch shape)
#
#   ENCRYPTED_KEYFILE      Line 1 starts with "DETERM-NODE-V1 " followed
#                          by 64 hex chars. Line 2 is a dot-separated
#                          DWE1 envelope blob. This is the S-004
#                          passphrase-encrypted node keyfile.
#
#   RECOVERY_SHARE_FILE    JSON object with top-level "shares" array
#                          whose entries have integer `x` (1..255) and
#                          string `y_hex` (even-length hex).
#
#   AEAD_ENVELOPE          Bare DWE1 envelope: 6 dot-separated hex
#                          fields, first field decodes to 4 bytes whose
#                          little-endian value is 0x31455744 ("DWE1").
#                          This appears when an envelope was extracted
#                          out of its node-key header (e.g., for
#                          standalone backup) — operationally the same
#                          sensitivity as an ENCRYPTED_KEYFILE, but the
#                          header (and therefore the pubkey for
#                          cross-reference) is absent.
#
#   UNKNOWN_NON_KEYFILE    Anything else. README files, leftover logs,
#                          tarball artifacts, .git internals, etc.
#
# POSIX permission read:
#   * On Linux / macOS: parses the 4-digit octal mode via `stat`. The
#     security-critical comparison is "other-readable" (mode & 0004).
#     Plaintext keyfiles should be 0600 (owner-rw, no group, no other);
#     anything wider is logged with the `mode_not_0600` hazard tag and
#     triggers the CRITICAL anomaly if other-readable.
#   * On Windows (Git Bash / Cygwin): NTFS ACLs aren't expressible as
#     POSIX bits. We report mode="n/a" and skip the bit-level check.
#     Hazards specific to POSIX bits are not raised on Windows; the
#     mixed-mode and unknown-files anomalies still fire.
#
# Anomalies:
#
#   plaintext_keyfile_other_readable    CRITICAL
#     A PLAINTEXT_KEYFILE with mode != 0600 AND other-readable bit set.
#     Immediate operator action: `chmod 600 <file>` and rotate the key
#     (since you don't know who has already read it).
#
#   mixed_plaintext_and_encrypted       WARN
#     A directory holds BOTH a PLAINTEXT_KEYFILE and an
#     ENCRYPTED_KEYFILE for the same address / pubkey. Operator
#     migration in progress (S-004 adoption) or an accidental backup
#     left the plaintext on disk. Either delete the plaintext (after
#     verifying the encrypted variant decrypts) or move it to a sealed
#     location.
#
#   recovery_share_world_writable       WARN
#     A RECOVERY_SHARE_FILE with mode & 0002 set. An attacker with
#     shell access can swap the share contents and the next
#     `determ-wallet shamir-combine` will reconstruct the WRONG secret.
#     Supply-chain risk; rotate ASAP.
#
#   unknown_files_in_keystore_dir       INFO
#     The audited directory holds >= 1 keyfile AND >= 1
#     UNKNOWN_NON_KEYFILE. Housekeeping recommendation; non-keyfile
#     content has no business in a keystore dir.
#
# CLI:
#   --dir <path>          REQUIRED. Directory to audit.
#   --recursive           Walk subdirectories (default: shallow).
#   --max-files <N>       Safety cap, default 1000. Audit stops after
#                         this many regular files have been considered.
#   --json                Emit single-line JSON envelope.
#   --anomalies-only      Print only flagged anomalies; exit 2 if any
#                         CRITICAL anomaly fired.
#   -h, --help            Show this help.
#
# Exit codes:
#   0   audit ran; no CRITICAL anomalies (WARN / INFO may be present)
#   1   bad args / --dir missing / --dir unreadable / classifier error
#   2   at least one CRITICAL anomaly fired
#       (plaintext_keyfile_other_readable)
set -u

usage() {
  cat <<'EOF'
Usage: operator_keystore_audit.sh --dir <path> [--recursive]
                                  [--max-files <N>] [--json]
                                  [--anomalies-only]

Audits an operator's keystore directory for keyfile presence + POSIX
permission hygiene + leak hazards. Pure local-file linter; no daemon
RPC, no decryption, no mutation of any audited file.

Per-file classification:
  PLAINTEXT_KEYFILE      JSON with {address, privkey_hex} or
                         {pubkey, priv_seed} or {accounts:[...]}
  ENCRYPTED_KEYFILE      2-line: "DETERM-NODE-V1 <pubkey_hex>"
                         + DWE1 envelope blob (S-004)
  RECOVERY_SHARE_FILE    JSON with {shares:[{x, y_hex}, ...]}
  AEAD_ENVELOPE          Bare 6-part dot-separated DWE1 envelope
  UNKNOWN_NON_KEYFILE    Anything else

Anomalies:
  plaintext_keyfile_other_readable    CRITICAL  plaintext keyfile
                                                world-readable
  mixed_plaintext_and_encrypted       WARN      same-address mix
  recovery_share_world_writable       WARN      share is world-writable
  unknown_files_in_keystore_dir       INFO      housekeeping

Options:
  --dir <path>          REQUIRED. Directory to audit.
  --recursive           Walk subdirectories (default: shallow)
  --max-files <N>       Cap files considered (default: 1000)
  --json                Emit single-line JSON envelope
  --anomalies-only      Print only anomalies; exit 2 on CRITICAL
  -h, --help            Show this help

Exit codes:
  0   no CRITICAL anomalies (WARN / INFO may still be present)
  1   bad args, unreadable directory, classifier failure
  2   at least one CRITICAL anomaly fired
EOF
}

DIR=""
RECURSIVE=0
MAX_FILES=1000
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --dir)             DIR="${2:-}";         shift 2 ;;
    --recursive)       RECURSIVE=1;          shift ;;
    --max-files)       MAX_FILES="${2:-}";   shift 2 ;;
    --json)            JSON_OUT=1;           shift ;;
    --anomalies-only)  ANOM_ONLY=1;          shift ;;
    *) echo "operator_keystore_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$DIR" ]; then
  echo "operator_keystore_audit: --dir is required" >&2
  usage >&2
  exit 1
fi
case "$MAX_FILES" in *[!0-9]*|"")
  echo "operator_keystore_audit: --max-files must be a positive integer (got '$MAX_FILES')" >&2
  exit 1 ;;
esac
if [ "$MAX_FILES" -lt 1 ]; then
  echo "operator_keystore_audit: --max-files must be >= 1 (got '$MAX_FILES')" >&2
  exit 1
fi

if [ ! -d "$DIR" ]; then
  echo "operator_keystore_audit: --dir does not exist or is not a directory: $DIR" >&2
  exit 1
fi
if [ ! -r "$DIR" ]; then
  echo "operator_keystore_audit: --dir is not readable: $DIR" >&2
  exit 1
fi

# Normalize $DIR for Python consumption (Windows-style on Git Bash).
# The bash-side `-d` / `-r` tests work fine with MSYS paths because
# they go through the MSYS path-translation layer, but Python is
# native Windows and won't grok /tmp/... or /c/...
if command -v cygpath >/dev/null 2>&1; then
  DIR_FOR_PY=$(cygpath -m -- "$DIR" 2>/dev/null || printf '%s' "$DIR")
else
  DIR_FOR_PY="$DIR"
fi

# ── Detect platform for mode reading ────────────────────────────────────────
# Git Bash on Windows reports MINGW64_NT / MSYS_NT / CYGWIN_NT for uname.
# In those cases we still try `stat -c %a` (which works in Git Bash but
# returns the synthesized 0777 for NTFS — operationally meaningless),
# so we explicitly switch to "n/a" mode on those platforms.
IS_WINDOWS=0
case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=1 ;;
esac

# ── Enumerate files ─────────────────────────────────────────────────────────
# Use `find` for cross-platform glob behavior. Limit depth to 1 unless
# --recursive. -type f filters out subdirs / symlinks-to-dirs / sockets.
# The output is NUL-separated to handle weird filenames; we pass the
# list to Python via a tempfile to avoid argv length limits.
TMP_LIST=$(mktemp 2>/dev/null) || {
  echo "operator_keystore_audit: cannot create temp file" >&2; exit 1;
}
TMP_OUT=$(mktemp 2>/dev/null) || {
  echo "operator_keystore_audit: cannot create temp file" >&2; rm -f "$TMP_LIST"; exit 1;
}
trap 'rm -f "$TMP_LIST" "$TMP_OUT" 2>/dev/null' EXIT

# On Git Bash for Windows the standard `find` emits MSYS paths
# (/tmp/foo, /c/sauromatae/...). The Python below is native Windows
# (os.name == "nt") and cannot os.stat() those paths. Convert each
# entry to a Windows-style path via cygpath -m where available,
# otherwise pass through unchanged (Linux / macOS native path).
#
# We post-process the find output rather than asking find for a
# different format so the NUL-separated record layout stays the same
# regardless of platform.
emit_paths() {
  if [ "$RECURSIVE" = "1" ]; then
    find "$DIR" -type f -print0 2>/dev/null
  else
    find "$DIR" -maxdepth 1 -type f -print0 2>/dev/null
  fi
}

if command -v cygpath >/dev/null 2>&1; then
  # cygpath -m converts each MSYS path to a forward-slash Windows path
  # (C:/sauromatae/...). The xargs -0 + -I {} idiom preserves the
  # NUL separator on input but emits LF-separated output, which we
  # convert back to NUL for the Python side.
  emit_paths | xargs -0 -I {} cygpath -m -- "{}" | tr '\n' '\0' > "$TMP_LIST"
else
  emit_paths > "$TMP_LIST"
fi

# ── Classify + render in Python ─────────────────────────────────────────────
# Python is already an established dependency across operator_*.sh
# (operator_dust_audit.sh, operator_backup_health.sh). One render pass
# keeps the JSON envelope and the human table consistent.
python - "$TMP_LIST" "$TMP_OUT" "$DIR_FOR_PY" "$RECURSIVE" "$MAX_FILES" "$JSON_OUT" "$ANOM_ONLY" "$IS_WINDOWS" <<'PY'
import json, os, stat, sys
from collections import defaultdict

list_path, out_path, audit_dir, recursive_s, max_files_s, json_out_s, anom_only_s, is_windows_s = sys.argv[1:9]
recursive  = recursive_s  == "1"
max_files  = int(max_files_s)
json_out   = json_out_s   == "1"
anom_only  = anom_only_s  == "1"
is_windows = is_windows_s == "1"

# Read NUL-separated file list.
try:
    with open(list_path, "rb") as f:
        raw = f.read()
except Exception as e:
    sys.stderr.write(f"operator_keystore_audit: cannot read file list: {e}\n")
    sys.exit(1)

paths = []
for chunk in raw.split(b"\0"):
    if not chunk:
        continue
    try:
        paths.append(chunk.decode("utf-8"))
    except UnicodeDecodeError:
        # Skip filenames that can't be UTF-8 decoded; record an
        # unknown row for them so the operator at least sees the
        # count. Mojibake-renamed key material is a real operator
        # foot-gun.
        paths.append(chunk.decode("utf-8", errors="replace"))

# Apply --max-files cap deterministically: sort then truncate.
paths.sort()
truncated = False
if len(paths) > max_files:
    paths = paths[:max_files]
    truncated = True

# ── Helpers ─────────────────────────────────────────────────────────────────
HEX_LOWER = "0123456789abcdef"

def is_hex(s, exact_len=None):
    if not isinstance(s, str):
        return False
    if exact_len is not None and len(s) != exact_len:
        return False
    if len(s) == 0 or len(s) % 2 != 0:
        return False
    s_lower = s.lower()
    for c in s_lower:
        if c not in HEX_LOWER:
            return False
    return True

def is_anon_address(s):
    # 0x prefix + 64 hex chars
    return (isinstance(s, str)
            and len(s) == 66
            and s.startswith("0x")
            and is_hex(s[2:], 64))

def mode_str(p):
    if is_windows:
        return "n/a"
    try:
        st = os.stat(p)
    except OSError:
        return "n/a"
    bits = stat.S_IMODE(st.st_mode)
    return f"{bits:04o}"

def mode_bits(p):
    # Returns integer mode bits, or None if unavailable.
    if is_windows:
        return None
    try:
        st = os.stat(p)
    except OSError:
        return None
    return stat.S_IMODE(st.st_mode)

def classify_dwe1_envelope(blob):
    # Canonical DWE1 envelope serialization: 6 dot-separated hex parts.
    # Part 0 must decode to the 4-byte LE magic 0x31455744 = "DWE1".
    parts = blob.split(".")
    if len(parts) != 6:
        return False
    for p in parts:
        if not is_hex(p):
            return False
    magic_hex = parts[0]
    if len(magic_hex) != 8:
        return False
    # bytes 0..3 = "DWE1" in ASCII (little-endian uint32 0x31455744).
    # The hex form is the bytes 0x44 0x57 0x45 0x31 = "44574531".
    return magic_hex.lower() == "44574531"

def classify_file(path):
    """Returns dict with at least 'type', 'path'. May add address/pubkey
       depending on type."""
    rec = {
        "path":       path,
        "type":       "UNKNOWN_NON_KEYFILE",
        "size_bytes": 0,
        "mode":       mode_str(path),
        "address":    None,
        "pubkey":     None,
        "hazards":    [],
    }
    try:
        sz = os.path.getsize(path)
    except OSError:
        rec["hazards"].append("read_failed")
        return rec
    rec["size_bytes"] = sz

    # Hard cap: anything > 16 MB is not plausibly a wallet keyfile.
    # account-list uses the same cap; this matches its behavior.
    MAX_READ = 16 * 1024 * 1024
    if sz > MAX_READ:
        rec["hazards"].append("file_too_large")
        return rec

    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        rec["hazards"].append("read_failed")
        return rec

    # Try UTF-8 decode. Binary garbage stays UNKNOWN.
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return rec

    # ── Detection #1: encrypted DETERM-NODE-V1 (2-line text format) ────────
    HEADER_MAGIC = "DETERM-NODE-V1 "
    if text.startswith(HEADER_MAGIC):
        # Line 1: header. Line 2: DWE1 envelope blob.
        nl = text.find("\n")
        if nl > 0:
            header_line = text[:nl].rstrip("\r\n")
            rest = text[nl + 1:]
            nl2 = rest.find("\n")
            blob_line = rest if nl2 < 0 else rest[:nl2]
            blob_line = blob_line.rstrip("\r\n")
            pubkey_hex = header_line[len(HEADER_MAGIC):]
            if is_hex(pubkey_hex, 64) and classify_dwe1_envelope(blob_line):
                rec["type"]    = "ENCRYPTED_KEYFILE"
                rec["pubkey"]  = pubkey_hex.lower()
                rec["address"] = "0x" + pubkey_hex.lower()
                return rec
            # Header looked like ours but malformed: still UNKNOWN.
            rec["hazards"].append("encrypted_keyfile_malformed")
            return rec

    # ── Detection #2: bare DWE1 envelope (single dot-separated line) ───────
    # Strip outer whitespace; tolerate a trailing newline.
    stripped = text.strip()
    if "\n" not in stripped and classify_dwe1_envelope(stripped):
        rec["type"] = "AEAD_ENVELOPE"
        return rec

    # ── Detection #3: JSON shapes ──────────────────────────────────────────
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return rec

    if not isinstance(doc, dict):
        return rec

    # 3a. plaintext-single (wallet): {address, privkey_hex}
    addr = doc.get("address")
    priv = doc.get("privkey_hex")
    if (isinstance(addr, str) and is_anon_address(addr)
        and isinstance(priv, str) and is_hex(priv, 64)):
        rec["type"]    = "PLAINTEXT_KEYFILE"
        rec["address"] = addr.lower()
        rec["pubkey"]  = addr[2:].lower()
        return rec

    # 3b. node_key.json (chain daemon): {pubkey, priv_seed}
    pub  = doc.get("pubkey")
    seed = doc.get("priv_seed")
    if (isinstance(pub, str) and is_hex(pub, 64)
        and isinstance(seed, str) and is_hex(seed, 64)):
        rec["type"]    = "PLAINTEXT_KEYFILE"
        rec["pubkey"]  = pub.lower()
        rec["address"] = "0x" + pub.lower()
        return rec

    # 3c. plaintext-batch (wallet): {accounts: [{address, privkey_hex}, ...]}
    accounts = doc.get("accounts")
    if isinstance(accounts, list) and accounts:
        all_ok = True
        first_addr = None
        for entry in accounts:
            if not isinstance(entry, dict):
                all_ok = False; break
            ea = entry.get("address")
            ep = entry.get("privkey_hex")
            if not (isinstance(ea, str) and is_anon_address(ea)
                    and isinstance(ep, str) and is_hex(ep, 64)):
                all_ok = False; break
            if first_addr is None:
                first_addr = ea
        if all_ok:
            rec["type"]    = "PLAINTEXT_KEYFILE"
            rec["address"] = (first_addr.lower() if first_addr else None)
            if first_addr:
                rec["pubkey"] = first_addr[2:].lower()
            # For batch files there's no single address — record the
            # first one for cross-reference, with a count hazard.
            if len(accounts) > 1:
                rec["hazards"].append(f"batch_{len(accounts)}_accounts")
            return rec

    # 3d. Shamir share file: {shares: [{x, y_hex}, ...]}
    shares = doc.get("shares")
    if isinstance(shares, list) and shares:
        all_ok = True
        for s in shares:
            if not isinstance(s, dict):
                all_ok = False; break
            sx = s.get("x")
            sy = s.get("y_hex")
            if not (isinstance(sx, int) and 1 <= sx <= 255
                    and isinstance(sy, str) and is_hex(sy)):
                all_ok = False; break
        if all_ok:
            rec["type"] = "RECOVERY_SHARE_FILE"
            return rec

    return rec

# ── Walk the file list ──────────────────────────────────────────────────────
files = []
counts = {
    "PLAINTEXT_KEYFILE":   0,
    "ENCRYPTED_KEYFILE":   0,
    "RECOVERY_SHARE_FILE": 0,
    "AEAD_ENVELOPE":       0,
    "UNKNOWN_NON_KEYFILE": 0,
}
# Per-address index: address -> list of (type, path)
address_index = defaultdict(list)

for p in paths:
    try:
        rec = classify_file(p)
    except Exception as e:
        # Defensive: a single corrupt file shouldn't kill the audit.
        # Treat as UNKNOWN_NON_KEYFILE with a hazard tag.
        rec = {
            "path":       p,
            "type":       "UNKNOWN_NON_KEYFILE",
            "size_bytes": 0,
            "mode":       "n/a",
            "address":    None,
            "pubkey":     None,
            "hazards":    [f"classify_error:{type(e).__name__}"],
        }
    files.append(rec)
    counts[rec["type"]] = counts.get(rec["type"], 0) + 1
    if rec["address"]:
        address_index[rec["address"]].append((rec["type"], rec["path"]))

# ── Per-file hazard population (POSIX bits) ─────────────────────────────────
# mode_not_0600: plaintext keyfile with mode != 0600. Records the
# specific failing path so the operator can directly chmod it.
for rec in files:
    if rec["type"] == "PLAINTEXT_KEYFILE":
        bits = mode_bits(rec["path"])
        if bits is not None:
            if bits != 0o600:
                rec["hazards"].append(f"mode_not_0600({rec['mode']})")
            if bits & 0o004:
                rec["hazards"].append("other_readable")
    if rec["type"] == "RECOVERY_SHARE_FILE":
        bits = mode_bits(rec["path"])
        if bits is not None:
            if bits & 0o002:
                rec["hazards"].append("world_writable")

# ── Anomaly detection ───────────────────────────────────────────────────────
anomalies = []  # list of {tag, severity, files, info}

# (1) plaintext_keyfile_other_readable: CRITICAL.
plaintext_world_readable_paths = [
    rec["path"] for rec in files
    if rec["type"] == "PLAINTEXT_KEYFILE"
       and "other_readable" in rec["hazards"]
]
if plaintext_world_readable_paths:
    anomalies.append({
        "tag":      "plaintext_keyfile_other_readable",
        "severity": "CRITICAL",
        "count":    len(plaintext_world_readable_paths),
        "files":    plaintext_world_readable_paths,
        "info":     ("plaintext keyfile is world-readable (mode & 0004 set); "
                     "immediate operator action: chmod 600 + rotate the key"),
    })

# (2) mixed_plaintext_and_encrypted: WARN.
# Same address present as BOTH PLAINTEXT_KEYFILE and ENCRYPTED_KEYFILE.
mixed_addresses = []
for addr, entries in address_index.items():
    types_at_addr = {t for t, _p in entries}
    if "PLAINTEXT_KEYFILE" in types_at_addr and "ENCRYPTED_KEYFILE" in types_at_addr:
        mixed_addresses.append({
            "address": addr,
            "files":   [path for _t, path in entries],
        })
if mixed_addresses:
    anomalies.append({
        "tag":       "mixed_plaintext_and_encrypted",
        "severity":  "WARN",
        "count":     len(mixed_addresses),
        "addresses": mixed_addresses,
        "info":      ("same address has both plaintext and encrypted "
                      "variants; finish S-004 migration by deleting the "
                      "plaintext (after verifying the encrypted decrypts)"),
    })

# (3) recovery_share_world_writable: WARN.
share_writable_paths = [
    rec["path"] for rec in files
    if rec["type"] == "RECOVERY_SHARE_FILE"
       and "world_writable" in rec["hazards"]
]
if share_writable_paths:
    anomalies.append({
        "tag":      "recovery_share_world_writable",
        "severity": "WARN",
        "count":    len(share_writable_paths),
        "files":    share_writable_paths,
        "info":     ("Shamir share file is world-writable; attacker with "
                     "shell access can swap share contents and the next "
                     "combine reconstructs the wrong secret"),
    })

# (4) unknown_files_in_keystore_dir: INFO.
# Only fires when the dir holds >= 1 keyfile-type AND >= 1 unknown.
keyfile_total = (counts["PLAINTEXT_KEYFILE"]
                  + counts["ENCRYPTED_KEYFILE"]
                  + counts["RECOVERY_SHARE_FILE"]
                  + counts["AEAD_ENVELOPE"])
unknown_paths = [rec["path"] for rec in files if rec["type"] == "UNKNOWN_NON_KEYFILE"]
if keyfile_total >= 1 and unknown_paths:
    anomalies.append({
        "tag":      "unknown_files_in_keystore_dir",
        "severity": "INFO",
        "count":    len(unknown_paths),
        "files":    unknown_paths,
        "info":     ("non-keyfile files in a directory primarily holding "
                     "keyfiles; housekeeping recommendation"),
    })

critical_count = sum(1 for a in anomalies if a["severity"] == "CRITICAL")

# ── Render ──────────────────────────────────────────────────────────────────
summary = {
    "plaintext_count":  counts["PLAINTEXT_KEYFILE"],
    "encrypted_count":  counts["ENCRYPTED_KEYFILE"],
    "recovery_count":   counts["RECOVERY_SHARE_FILE"],
    "envelope_count":   counts["AEAD_ENVELOPE"],
    "unknown_count":    counts["UNKNOWN_NON_KEYFILE"],
}

if json_out:
    envelope = {
        "dir":        audit_dir,
        "recursive":  recursive,
        "max_files":  max_files,
        "truncated":  truncated,
        "files":      files,
        "summary":    summary,
        "anomalies":  anomalies,
    }
    print(json.dumps(envelope))
    # Write the anom count to the side channel so the bash exit-code
    # policy below can read it without a re-parse.
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"critical": critical_count, "total": len(anomalies)}, f)
    sys.exit(0)

# Human-readable rendering.
def short_path(p, base):
    # Display relative-to-base path when possible (cleaner column).
    try:
        rel = os.path.relpath(p, base)
        # On Windows the relpath may go up the tree (..\..\..\foo); fall
        # back to absolute if so.
        if rel.startswith(".."):
            return p
        return rel
    except ValueError:
        return p

def short_addr(a):
    if not a:
        return "-"
    if a.startswith("0x") and len(a) >= 12:
        return a[:10] + ".." + a[-4:]
    return a

def fmt_hazards(hs):
    if not hs:
        return "-"
    return ",".join(hs)

if anom_only:
    if not anomalies:
        print(f"operator_keystore_audit: no anomalies ({audit_dir})")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({"critical": 0, "total": 0}, f)
        sys.exit(0)
    print(f"=== Keystore audit anomalies ({audit_dir}) ===")
    for a in anomalies:
        print(f"[{a['severity']}] {a['tag']}: {a['count']} entry(ies)")
        print(f"  {a['info']}")
        if "files" in a:
            for fp in a["files"][:20]:
                print(f"    file: {short_path(fp, audit_dir)}")
            if len(a["files"]) > 20:
                print(f"    ... and {len(a['files']) - 20} more")
        if "addresses" in a:
            for am in a["addresses"][:20]:
                print(f"    address: {short_addr(am['address'])}")
                for fp in am["files"]:
                    print(f"      file: {short_path(fp, audit_dir)}")
            if len(a["addresses"]) > 20:
                print(f"    ... and {len(a['addresses']) - 20} more")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"critical": critical_count, "total": len(anomalies)}, f)
    sys.exit(0)

print(f"=== Keystore audit ({audit_dir}) ===")
print(f"Recursive: {'yes' if recursive else 'no'}    "
      f"Max files: {max_files}    "
      f"Considered: {len(files)}{'  (truncated)' if truncated else ''}")
print()
if files:
    # Per-file table.
    print("Per-file:")
    hdr_fmt = "  {:<40} {:<22} {:<6} {:<18} {}"
    row_fmt = "  {:<40} {:<22} {:<6} {:<18} {}"
    print(hdr_fmt.format("path", "type", "mode", "address", "hazards"))
    print(hdr_fmt.format("----", "----", "----", "-------", "-------"))
    for rec in files:
        p_short = short_path(rec["path"], audit_dir)
        if len(p_short) > 38:
            p_short = "..." + p_short[-35:]
        print(row_fmt.format(
            p_short,
            rec["type"],
            rec["mode"],
            short_addr(rec["address"]),
            fmt_hazards(rec["hazards"]),
        ))
    print()

print("Summary:")
print(f"  plaintext keyfiles    : {summary['plaintext_count']}")
print(f"  encrypted keyfiles    : {summary['encrypted_count']}")
print(f"  recovery share files  : {summary['recovery_count']}")
print(f"  AEAD envelope blobs   : {summary['envelope_count']}")
print(f"  unknown non-keyfiles  : {summary['unknown_count']}")

print()
if not anomalies:
    print("[OK] No anomalies detected")
else:
    print(f"Anomalies ({len(anomalies)}; CRITICAL={critical_count}):")
    for a in anomalies:
        print(f"  [{a['severity']}] {a['tag']}: {a['count']} entry(ies)")
        print(f"    {a['info']}")
        if "files" in a:
            for fp in a["files"][:10]:
                print(f"    - {short_path(fp, audit_dir)}")
            if len(a["files"]) > 10:
                print(f"    ... and {len(a['files']) - 10} more")
        if "addresses" in a:
            for am in a["addresses"][:10]:
                print(f"    - address {short_addr(am['address'])}:")
                for fp in am["files"]:
                    print(f"        {short_path(fp, audit_dir)}")
            if len(a["addresses"]) > 10:
                print(f"    ... and {len(a['addresses']) - 10} more")

with open(out_path, "w", encoding="utf-8") as f:
    json.dump({"critical": critical_count, "total": len(anomalies)}, f)
PY
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "operator_keystore_audit: classification pass failed" >&2
  exit 1
fi

# ── Exit-code policy ────────────────────────────────────────────────────────
# CRITICAL anomaly always triggers exit 2 (operator alert gate). This
# matches operator_config_audit.sh which exits 2 on CRITICAL findings
# regardless of --anomalies-only. WARN / INFO do NOT trigger exit 2 by
# themselves; --anomalies-only --json-and-friends still report them.
CRITICAL=$(python -c '
import json,sys
with open(sys.argv[1],"r",encoding="utf-8") as f:
    r = json.load(f)
print(r.get("critical", 0))
' "$TMP_OUT" 2>/dev/null)
case "$CRITICAL" in *[!0-9]*|"") CRITICAL=0 ;; esac

if [ "$CRITICAL" -gt 0 ]; then
  exit 2
fi
exit 0
