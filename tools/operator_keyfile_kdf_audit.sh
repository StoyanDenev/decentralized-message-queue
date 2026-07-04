#!/usr/bin/env bash
# operator_keyfile_kdf_audit.sh — READ-ONLY KDF-migration audit for Determ
# passphrase-encrypted keyfiles / envelope blobs (R58 PBKDF2 -> Argon2id).
#
# After R58 the passphrase envelope defaults to a memory-hard Argon2id KDF
# (the DWE2 wire layout). Legacy DWE1 files (PBKDF2-HMAC-SHA-256) still decrypt
# but SHOULD be upgraded to Argon2id via `determ-wallet keyfile-reencrypt`.
# This tool scans a directory (or explicit --in files) of keyfiles / envelope
# blobs and reports each one's KDF, flagging any legacy DWE1/PBKDF2 file so an
# operator can rotate it before the weak-KDF material lingers on disk.
#
# It handles BOTH on-disk shapes the wallet produces:
#   - NODE keyfile   ("DETERM-NODE-V1 <pubkey>\n<envelope_blob>") — read via
#     `determ-wallet keyfile-info --in <f> --json` (.envelope.{format,kdf}).
#   - RAW envelope   (dot-separated hex, no header) — read via
#     `determ-wallet inspect-envelope --in <f> --json` (.{format,kdf}).
# For each file it tries keyfile-info first; if that fails structurally it
# tries inspect-envelope; if both fail the file is counted "unparseable"
# (skipped, NOT an error — the directory may hold unrelated files).
#
# ── SAFETY: strictly READ-ONLY ────────────────────────────────────────────────
#   Both keyfile-info and inspect-envelope report envelope METADATA (format,
#   kdf, salt/nonce lengths, cost params) WITHOUT decrypting. This tool never
#   supplies a passphrase, never decrypts, and never writes any file. It only
#   reads the inputs and prints a report.
#
# Usage:
#   tools/operator_keyfile_kdf_audit.sh --dir <D>
#   tools/operator_keyfile_kdf_audit.sh --in <f> [--in <f> ...]
#   tools/operator_keyfile_kdf_audit.sh --dir <D> [--json]
#
# Options:
#   --dir <D>    Scan <D> for *.enc, *.keyfile and *.json (NON-recursive; the
#                immediate directory only). Repeatable? No — a single --dir.
#   --in <f>     Audit an explicit file. Repeatable; may be combined with --dir.
#   --json       Emit a machine-readable JSON envelope instead of the human
#                per-file lines + digest.
#   -h, --help   Show this help.
#
# Human output: one line per file
#     <path> -> DWE2/argon2id OK
#     <path> -> DWE1/pbkdf2 LEGACY
#     <path> -> unparseable
#   followed by the digest:
#     keyfile-kdf-audit: N files, A argon2id, L legacy(pbkdf2), U unparseable
#
# JSON output:
#   {"scanned":N,"argon2id":A,"pbkdf2_legacy":L,"unparseable":U,
#    "files":[{"path","format","kdf","status"}, ...]}
#
# EXIT CODES (alert gate):
#   0   all parseable keyfiles are Argon2id (no legacy DWE1/pbkdf2 file found)
#   2   at least one LEGACY DWE1/pbkdf2 file found (operator should upgrade)
#   1   args / usage error (bad --dir, no inputs) — also SKIP-clean returns 0
set -u

usage() {
  cat <<'EOF'
Usage: operator_keyfile_kdf_audit.sh --dir <D>
       operator_keyfile_kdf_audit.sh --in <f> [--in <f> ...]
       operator_keyfile_kdf_audit.sh --dir <D> [--in <f> ...] [--json]

READ-ONLY KDF-migration audit for Determ passphrase-encrypted keyfiles /
envelope blobs (R58 PBKDF2 -> Argon2id). Reports each file's KDF and flags
legacy DWE1/PBKDF2 files that should be upgraded to Argon2id via
`determ-wallet keyfile-reencrypt`. Never decrypts, never writes.

Handles both on-disk shapes: NODE keyfiles (via keyfile-info) and RAW envelope
blobs (via inspect-envelope). Files that parse as neither are counted
"unparseable" (skipped, not an error).

Options:
  --dir <D>    Scan <D> for *.enc, *.keyfile, *.json (non-recursive)
  --in <f>     Audit an explicit file (repeatable; combinable with --dir)
  --json       Emit a machine-readable JSON envelope
  -h, --help   Show this help

Human digest:
  keyfile-kdf-audit: N files, A argon2id, L legacy(pbkdf2), U unparseable

JSON:
  {"scanned","argon2id","pbkdf2_legacy","unparseable","files":[
     {"path","format","kdf","status"}]}

Exit codes:
  0   all parseable keyfiles are Argon2id (no legacy found)
  1   args/usage error (bad --dir, no inputs)
  2   at least one LEGACY DWE1/pbkdf2 file found (operator should upgrade)
EOF
}

DIR=""
JSON_OUT=0
IN_FILES=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --dir)     DIR="${2:-}"; shift 2 ;;
    --in)      IN_FILES+=("${2:-}"); shift 2 ;;
    --json)    JSON_OUT=1; shift ;;
    *) echo "operator_keyfile_kdf_audit: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

cd "$(dirname "$0")/.."
source tools/common.sh

# SKIP-clean if the wallet binary is not available (mirrors the test-house
# convention: an absent optional binary is not a failure).
if [ -z "${DETERM_WALLET:-}" ] || [ ! -x "$DETERM_WALLET" ]; then
  echo "operator_keyfile_kdf_audit: SKIP — determ-wallet binary not found (build with"
  echo "        cmake --build build --config Release --target determ-wallet)"
  exit 0
fi
WALLET="$DETERM_WALLET"

PY=python
command -v python >/dev/null 2>&1 || PY=python3

# ── Assemble the file list ────────────────────────────────────────────────────
FILES=()

if [ -n "$DIR" ]; then
  if [ ! -d "$DIR" ]; then
    echo "operator_keyfile_kdf_audit: --dir is not a directory: $DIR" >&2
    exit 1
  fi
  # Non-recursive glob of the three candidate extensions. nullglob so an empty
  # match yields nothing (not the literal pattern). An empty directory is a
  # valid audit of zero files — not an error.
  shopt -s nullglob
  for f in "$DIR"/*.enc "$DIR"/*.keyfile "$DIR"/*.json; do
    [ -f "$f" ] && FILES+=("$f")
  done
  shopt -u nullglob
fi

if [ "${#IN_FILES[@]}" -gt 0 ]; then
  for f in "${IN_FILES[@]}"; do
    FILES+=("$f")
  done
fi

# No --dir and no --in is a usage error.
if [ -z "$DIR" ] && [ "${#IN_FILES[@]}" -eq 0 ]; then
  echo "operator_keyfile_kdf_audit: no inputs — pass --dir <D> and/or --in <f>" >&2
  usage >&2
  exit 1
fi

# ── classify_one <file> ───────────────────────────────────────────────────────
# Echoes "<format>\t<kdf>\t<status>" for the file. status is one of
#   argon2id | pbkdf2_legacy | unparseable
# Never decrypts. Tries the node-keyfile reader first, then the raw-envelope
# reader; a file that parses as neither is unparseable (skipped, not fatal).
#
# The envelope JSON reports format ("DWE1"/"DWE2") and kdf
# ("pbkdf2-hmac-sha256"/"argon2id"); we key the LEGACY decision on the KDF/format
# so a future DWE3 would be classified by its actual kdf string, not assumed.
classify_one() {
  local f="$1"
  local out rc

  # Attempt 1: node keyfile shape.
  out=$("$WALLET" keyfile-info --in "$f" --json 2>/dev/null); rc=$?
  if [ "$rc" -eq 0 ] && [ -n "$out" ]; then
    local parsed
    parsed=$(printf '%s' "$out" | tr -d '\r' | "$PY" -c '
import json, sys
try:
    j = json.loads(sys.stdin.read())
    env = j.get("envelope") if isinstance(j, dict) else None
    if isinstance(env, dict):
        fmt = str(env.get("format", ""))
        kdf = str(env.get("kdf", ""))
        if fmt or kdf:
            print(fmt + "\t" + kdf)
            sys.exit(0)
except Exception:
    pass
sys.exit(1)
' 2>/dev/null)
    if [ -n "$parsed" ]; then
      classify_emit "$parsed"
      return 0
    fi
  fi

  # Attempt 2: raw envelope shape.
  out=$("$WALLET" inspect-envelope --in "$f" --json 2>/dev/null); rc=$?
  if [ "$rc" -eq 0 ] && [ -n "$out" ]; then
    local parsed
    parsed=$(printf '%s' "$out" | tr -d '\r' | "$PY" -c '
import json, sys
try:
    j = json.loads(sys.stdin.read())
    if isinstance(j, dict):
        fmt = str(j.get("format", ""))
        kdf = str(j.get("kdf", ""))
        if fmt or kdf:
            print(fmt + "\t" + kdf)
            sys.exit(0)
except Exception:
    pass
sys.exit(1)
' 2>/dev/null)
    if [ -n "$parsed" ]; then
      classify_emit "$parsed"
      return 0
    fi
  fi

  # Neither shape parsed — unparseable (skipped, not an error).
  printf '%s\t%s\t%s' "-" "-" "unparseable"
}

# classify_emit "<fmt>\t<kdf>" -> "<fmt>\t<kdf>\t<status>"
classify_emit() {
  local fmt kdf status
  fmt=$(printf '%s' "$1" | cut -f1)
  kdf=$(printf '%s' "$1" | cut -f2)
  case "$kdf" in
    argon2id)            status="argon2id" ;;
    pbkdf2-hmac-sha256)  status="pbkdf2_legacy" ;;
    *)
      # Unknown KDF string — fall back to the format magic so a DWE1 with an
      # unexpected kdf label is still flagged legacy, and anything else is
      # unparseable rather than silently "OK".
      case "$fmt" in
        DWE2) status="argon2id" ;;
        DWE1) status="pbkdf2_legacy" ;;
        *)    status="unparseable" ;;
      esac
      ;;
  esac
  printf '%s\t%s\t%s' "$fmt" "$kdf" "$status"
}

# ── Scan ──────────────────────────────────────────────────────────────────────
argon2id_count=0
pbkdf2_count=0
unparseable_count=0

# Parallel arrays for JSON emission (associative arrays are avoided for
# portability across bash versions).
PATHS=()
FMTS=()
KDFS=()
STATUSES=()

for f in "${FILES[@]}"; do
  res=$(classify_one "$f")
  fmt=$(printf '%s' "$res" | cut -f1)
  kdf=$(printf '%s' "$res" | cut -f2)
  status=$(printf '%s' "$res" | cut -f3)

  PATHS+=("$f")
  FMTS+=("$fmt")
  KDFS+=("$kdf")
  STATUSES+=("$status")

  case "$status" in
    argon2id)      argon2id_count=$((argon2id_count+1)) ;;
    pbkdf2_legacy) pbkdf2_count=$((pbkdf2_count+1)) ;;
    *)             unparseable_count=$((unparseable_count+1)) ;;
  esac
done

scanned="${#FILES[@]}"

# ── Render ────────────────────────────────────────────────────────────────────
if [ "$JSON_OUT" = "1" ]; then
  # Build the JSON in python so paths/strings are escaped correctly.
  {
    printf '%s\n' "$scanned" "$argon2id_count" "$pbkdf2_count" "$unparseable_count"
    i=0
    while [ "$i" -lt "$scanned" ]; do
      printf '%s\n' "${PATHS[$i]}" "${FMTS[$i]}" "${KDFS[$i]}" "${STATUSES[$i]}"
      i=$((i+1))
    done
  } | "$PY" -c '
import json, sys
lines = sys.stdin.read().split("\n")
idx = 0
def nxt():
    global idx
    v = lines[idx]; idx += 1; return v
scanned = int(nxt()); a = int(nxt()); l = int(nxt()); u = int(nxt())
files = []
for _ in range(scanned):
    p = nxt(); fmt = nxt(); kdf = nxt(); st = nxt()
    files.append({
        "path": p,
        "format": (fmt if fmt != "-" else None),
        "kdf": (kdf if kdf != "-" else None),
        "status": st,
    })
print(json.dumps({
    "scanned": scanned,
    "argon2id": a,
    "pbkdf2_legacy": l,
    "unparseable": u,
    "files": files,
}))
'
else
  i=0
  while [ "$i" -lt "$scanned" ]; do
    p="${PATHS[$i]}"; fmt="${FMTS[$i]}"; kdf="${KDFS[$i]}"; st="${STATUSES[$i]}"
    case "$st" in
      argon2id)      echo "$p -> $fmt/$kdf OK" ;;
      pbkdf2_legacy) echo "$p -> $fmt/$kdf LEGACY" ;;
      *)             echo "$p -> unparseable" ;;
    esac
    i=$((i+1))
  done
  echo "keyfile-kdf-audit: $scanned files, $argon2id_count argon2id, $pbkdf2_count legacy(pbkdf2), $unparseable_count unparseable"
fi

# ── Exit gate ─────────────────────────────────────────────────────────────────
# Any legacy file present -> exit 2 (operator should upgrade). Otherwise 0.
if [ "$pbkdf2_count" -gt 0 ]; then
  exit 2
fi
exit 0
