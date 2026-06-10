#!/usr/bin/env bash
# operator_anchor_audit.sh — Audit the determ-light persisted anchor cache
# (the --resume state file written by `verify-chain --persist`).
#
# THE OPERATOR QUESTION
#   "Is the anchor my light client will --resume from actually usable —
#    well-formed, schema-current, pinned to MY chain, not ahead of the
#    daemon it will sync against, and not stale?"
#
# The cache (light/persist.cpp) is the trust foundation of every
# `--resume` invocation: the light client skips re-verifying 0..H from
# genesis and instead chains committee-signature verification forward
# from the cached (head_height, head_block_hash). A wrong-chain, corrupt,
# or future-dated cache makes resume fail-closed at best and confusing at
# worst — this audit surfaces those states BEFORE the next resume.
#
# Checks (each prints ok:/bad:/warn:):
#   1. state file exists and parses as JSON
#      (absent file -> exit 2 with a clear "no cache" message — absence
#       is a fresh-install state, not an audit failure)
#   2. schema_version matches the current one in light/persist.cpp
#   3. hex-shape sanity: genesis_hash + head_block_hash are 64-hex,
#      head_height is an unsigned number, head_state_root is empty
#      (pre-S-033 chain) or 64-hex
#   4. (--genesis) genesis re-pin via `determ-light state --verify-anchor`
#      (light/main.cpp cmd_state): the cached genesis_hash pin must equal
#      the LOCALLY recomputed hash of the operator-supplied genesis file
#      (exit 0 PASS / exit 2 MISMATCH = different chain / exit 1 error)
#   5. (--rpc-port) monotonicity cross-check via `determ head --json`
#      (same probe as operator_chain_health.sh): the live daemon's head
#      height must be >= the cached head_height. A daemon BELOW the
#      verified anchor means the daemon's chain was truncated/replaced or
#      the cache belongs to a different (longer) history — resume against
#      it would fail prev_hash continuity.
#   6. file age: warn (never fail) if mtime is older than 7 days
#
# Usage:
#   tools/operator_anchor_audit.sh [--state <path>] [--genesis <file>]
#                                  [--rpc-port <N>]
#
# RELATION TO operator_light_anchor_audit.sh (the OFFLINE FLEET audit):
#   that script classifies MANY caches (repeatable --state) into
#   ABSENT / VALID+PINNED / VALID+WRONG-CHAIN / CORRUPT using only the
#   determ-light binary's own loader — a breadth pass, no daemon ever.
#   THIS script is the single-target DEPTH audit: it parses the JSON
#   independently of the binary (schema/hex shape checks work even with
#   no determ-light built), adds the LIVE daemon monotonicity cross-check
#   (the operator-side view of the LSP-7 anchored_head gate: a daemon head
#   BELOW the cached committee-verified height = stale/truncated state),
#   and the mtime staleness warning. Run the fleet audit broadly; run this
#   one when a specific cache/daemon pair needs a verdict.
#
# Default --state mirrors light/persist.cpp default_state_path():
#   $DETERM_LIGHT_STATE if set, else <home>/.determ-light/state.json
#   (home = USERPROFILE, else HOMEDRIVE+HOMEPATH, else HOME, else ".")
#
# Binary resolution (only resolved when a check needs it):
#   determ-light (for --genesis): $DETERM_LIGHT_BIN, else
#     build/Release/determ-light.exe, build/determ-light.exe,
#     build/determ-light, build/Release/determ-light  (common.sh order)
#   determ (for --rpc-port): $DETERM_BIN, else the same probe order over
#     the determ binary names
#
# Exit codes:
#   0   all checks ok (warns allowed)
#   1   at least one bad: finding (or an argument/usage error)
#   2   no cache at the state path, a required binary is missing, or the
#       daemon is unreachable (missing prerequisite — audit incomplete,
#       message says exactly what to do; bad: findings dominate this)
set -u

SCRIPT=operator_anchor_audit

# Current persisted-anchor schema version — must mirror light/persist.cpp
# (LightState::schema_version default AND the load_light_state gate; both 1).
CURRENT_SCHEMA=1

usage() {
  cat <<'EOF'
Usage: operator_anchor_audit.sh [--state <path>] [--genesis <file>]
                                [--rpc-port <N>]

Audit the determ-light persisted anchor cache (the --resume state file
written by `verify-chain --persist`). Reports per-check ok:/bad:/warn:
lines and an overall PASS/FAIL:
  1. state file exists + is valid JSON (absent -> exit 2 "no cache")
  2. schema_version matches the current build (1)
  3. genesis_hash / head_block_hash are 64-hex; head_height is a number;
     head_state_root is empty (pre-S-033) or 64-hex
  4. (with --genesis) genesis re-pin: cached pin equals the locally
     recomputed genesis hash (`determ-light state --verify-anchor`)
  5. (with --rpc-port) monotonicity: live daemon head height >= cached
     head_height (a daemon BELOW the verified anchor is flagged bad)
  6. file age: warn (not fail) if older than 7 days

Options:
  --state <path>    Anchor cache to audit (default: $DETERM_LIGHT_STATE
                    if set, else <home>/.determ-light/state.json — the
                    same default the determ-light binary uses)
  --genesis <file>  Enable the genesis re-pin check (requires the
                    determ-light binary; $DETERM_LIGHT_BIN overrides
                    the build-tree probe)
  --rpc-port <N>    Enable the live monotonicity cross-check (requires
                    the determ binary + a daemon listening on N;
                    $DETERM_BIN overrides the build-tree probe)
  -h, --help        Show this help

Exit codes:
  0   all checks ok (warns allowed)
  1   at least one bad: finding (or argument error)
  2   no cache / required binary missing / daemon unreachable
      (missing prerequisite; bad: findings dominate this)
EOF
}

# ── helpers ───────────────────────────────────────────────────────────────────
OK=0; BAD=0; WARN=0; PREREQ_FAIL=0
ok()   { echo "ok:   $1"; OK=$((OK + 1)); }
bad()  { echo "bad:  $1"; BAD=$((BAD + 1)); }
warn() { echo "warn: $1"; WARN=$((WARN + 1)); }

is_hex64() {
  case "$1" in *[!0-9a-fA-F]*|"") return 1 ;; esac
  [ "${#1}" -eq 64 ]
}

# Absolutize a user-supplied path against the INVOCATION cwd, so paths
# still resolve after we cd to the repo root. Handles POSIX absolute
# paths and Windows drive-letter paths (git-bash).
abspath() {
  case "$1" in
    /*|[A-Za-z]:*) printf '%s\n' "$1" ;;
    *)             printf '%s/%s\n' "$PWD" "$1" ;;
  esac
}

# Mirror light/persist.cpp default_state_path(): $DETERM_LIGHT_STATE wins,
# else <home>/.determ-light/state.json. The binary's home_dir() prefers
# USERPROFILE on Win32 and HOME on POSIX; probing USERPROFILE first here
# matches both (USERPROFILE is unset on plain POSIX), and keeps the path
# in a form the NATIVE binary also understands under git-bash.
default_state_path() {
  if [ -n "${DETERM_LIGHT_STATE:-}" ]; then
    printf '%s\n' "$DETERM_LIGHT_STATE"
    return
  fi
  local home=""
  if [ -n "${USERPROFILE:-}" ]; then
    home="${USERPROFILE//\\//}"
  elif [ -n "${HOMEDRIVE:-}" ] && [ -n "${HOMEPATH:-}" ]; then
    home="${HOMEDRIVE}${HOMEPATH//\\//}"
  elif [ -n "${HOME:-}" ]; then
    home="$HOME"
  else
    home="."
  fi
  printf '%s/.determ-light/state.json\n' "$home"
}

# ── arg parse (--help first so it never trips validation) ─────────────────────
STATE_FLAG=""
GENESIS=""
PORT=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)  usage; exit 0 ;;
    --state|--genesis|--rpc-port)
      # `shift 2` with only the flag left FAILS WITHOUT SHIFTING in bash,
      # which would spin this loop forever — require the value explicitly.
      if [ $# -lt 2 ]; then
        echo "$SCRIPT: $1 requires a value" >&2
        exit 1
      fi
      case "$1" in
        --state)    STATE_FLAG="$2" ;;
        --genesis)  GENESIS="$2"    ;;
        --rpc-port) PORT="$2"       ;;
      esac
      shift 2 ;;
    *) echo "$SCRIPT: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

if [ -n "$PORT" ]; then
  case "$PORT" in *[!0-9]*|"")
    echo "$SCRIPT: --rpc-port must be a positive integer (got '$PORT')" >&2
    exit 1 ;;
  esac
fi

[ -n "$STATE_FLAG" ] && STATE_FLAG=$(abspath "$STATE_FLAG")
[ -n "$GENESIS" ]    && GENESIS=$(abspath "$GENESIS")
if [ -n "$GENESIS" ] && [ ! -f "$GENESIS" ]; then
  echo "$SCRIPT: genesis file not found: $GENESIS" >&2
  exit 1
fi

cd "$(dirname "$0")/.."

if [ -n "$STATE_FLAG" ]; then
  STATE="$STATE_FLAG"
else
  STATE=$(default_state_path)
fi

# ── binary resolution (only for the checks actually requested) ────────────────
# Missing binary = missing prerequisite -> exit 2 (distinct from a bad:
# audit finding), with build guidance, BEFORE any checks run.
LIGHT=""
if [ -n "$GENESIS" ]; then
  if [ -n "${DETERM_LIGHT_BIN:-}" ]; then
    LIGHT="$DETERM_LIGHT_BIN"
    if [ ! -x "$LIGHT" ]; then
      echo "$SCRIPT: \$DETERM_LIGHT_BIN '$LIGHT' is not an executable file" >&2
      exit 2
    fi
  else
    for cand in build/Release/determ-light.exe build/determ-light.exe \
                build/determ-light build/Release/determ-light; do
      if [ -x "$cand" ]; then LIGHT="$cand"; break; fi
    done
    if [ -z "$LIGHT" ]; then
      echo "$SCRIPT: determ-light binary not found (required for --genesis). Build it with" >&2
      echo "    cmake --build build --config Release --target determ-light" >&2
      echo "  or point at one via \$DETERM_LIGHT_BIN." >&2
      exit 2
    fi
  fi
fi

DETERM=""
if [ -n "$PORT" ]; then
  if [ -n "${DETERM_BIN:-}" ]; then
    DETERM="$DETERM_BIN"
    if [ ! -x "$DETERM" ]; then
      echo "$SCRIPT: \$DETERM_BIN '$DETERM' is not an executable file" >&2
      exit 2
    fi
  else
    for cand in build/Release/determ.exe build/determ.exe \
                build/determ build/Release/determ; do
      if [ -x "$cand" ]; then DETERM="$cand"; break; fi
    done
    if [ -z "$DETERM" ]; then
      echo "$SCRIPT: determ binary not found (required for --rpc-port). Build it with" >&2
      echo "    cmake --build build --config Release --target determ" >&2
      echo "  or point at one via \$DETERM_BIN." >&2
      exit 2
    fi
  fi
fi

echo "=== determ-light anchor cache audit ==="
echo "state: $STATE"

# ── check 1: state file exists + valid JSON ───────────────────────────────────
if [ ! -f "$STATE" ]; then
  echo "$SCRIPT: no anchor cache at $STATE"
  echo "  (not an error — nothing has been persisted yet; create one with"
  echo "   \`determ-light verify-chain --rpc-port <N> --genesis <file> --persist\`)"
  exit 2
fi

# Field names per light/persist.cpp save/load: schema_version, genesis_hash,
# head_height, head_block_hash, head_state_root.
# Preferred parser: python (the operator_*.sh house pattern) for real JSON
# parsing. Fallback: grep/sed over the pretty-printed (one key per line)
# shape the binary itself writes (nlohmann dump(2)). Both emit "key value"
# lines; ALL validation happens in bash below so the parsers cannot
# diverge on policy.
PY=""
if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
fi

JSON_OK=0
PARSED=""
if [ -n "$PY" ]; then
  PARSED=$(
    "$PY" - "$STATE" <<'PYEOF'
import json, sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    sys.stderr.write("%s\n" % e)
    sys.exit(1)
if not isinstance(data, dict):
    sys.stderr.write("top-level value is not an object\n")
    sys.exit(1)
for k in ("schema_version", "genesis_hash", "head_height",
          "head_block_hash", "head_state_root"):
    if k not in data:
        print("%s __MISSING__" % k)
        continue
    v = data[k]
    if isinstance(v, bool) or not isinstance(v, (int, str)):
        print("%s __INVALID__" % k)
    else:
        print("%s %s" % (k, v))
PYEOF
  ) && JSON_OK=1
  if [ "$JSON_OK" = "1" ]; then
    ok "state file exists and is valid JSON"
  else
    bad "state file is not valid JSON — corrupt cache; clear it with \`determ-light state --clear --state $STATE\`"
  fi
else
  # No python on PATH: shape check + line-oriented extraction. The binary
  # writes pretty JSON (one key per line), so this handles every file the
  # binary itself produced; hand-mangled files may need python for a
  # precise verdict.
  FIRST=$(sed 's/^[[:space:]]*//' "$STATE" | head -1 | cut -c1)
  if [ "$FIRST" = "{" ]; then
    JSON_OK=1
    ok "state file exists and looks like JSON (shape check only — install python3 for strict parsing)"
    for k in schema_version genesis_hash head_height head_block_hash head_state_root; do
      line=$(grep -o "\"$k\"[[:space:]]*:[[:space:]]*\(\"[^\"]*\"\|[0-9][0-9]*\)" "$STATE" | head -1)
      if [ -z "$line" ]; then
        v="__MISSING__"
      else
        v=$(printf '%s\n' "$line" | sed 's/^"[^"]*"[[:space:]]*:[[:space:]]*//; s/^"//; s/"$//')
      fi
      PARSED="$PARSED$k $v
"
    done
  else
    bad "state file does not look like JSON — corrupt cache; clear it with \`determ-light state --clear --state $STATE\`"
  fi
fi

# ── parse the "key value" lines into shell variables ──────────────────────────
SV="__MISSING__"; GH="__MISSING__"; HH="__MISSING__"
HBH="__MISSING__"; HSR="__MISSING__"
if [ "$JSON_OK" = "1" ]; then
  while IFS= read -r line; do
    # Strip a trailing CR — Windows python emits CRLF line endings.
    line=${line%$'\r'}
    [ -z "$line" ] && continue
    k="${line%% *}"
    case "$line" in
      *" "*) v="${line#* }" ;;
      *)     v="" ;;
    esac
    case "$k" in
      schema_version)  SV="$v" ;;
      genesis_hash)    GH="$v" ;;
      head_height)     HH="$v" ;;
      head_block_hash) HBH="$v" ;;
      head_state_root) HSR="$v" ;;
    esac
  done <<PARSED_EOF
$PARSED
PARSED_EOF
fi

if [ "$JSON_OK" = "1" ]; then
  # ── check 2: schema_version matches light/persist.cpp ─────────────────────
  if [ "$SV" = "$CURRENT_SCHEMA" ]; then
    ok "schema_version matches current ($CURRENT_SCHEMA)"
  elif [ "$SV" = "__MISSING__" ]; then
    bad "schema_version is missing from the state file"
  else
    bad "schema_version is '$SV' but this build understands $CURRENT_SCHEMA — clear the cache and re-persist"
  fi

  # ── check 3: hex-shape sanity ──────────────────────────────────────────────
  if [ "$GH" = "__MISSING__" ]; then
    bad "genesis_hash is missing from the state file"
  elif is_hex64 "$GH"; then
    ok "genesis_hash is 64-hex"
  else
    bad "genesis_hash is not a 64-hex string (got '${GH:0:24}...')"
  fi

  if [ "$HBH" = "__MISSING__" ]; then
    bad "head_block_hash is missing from the state file"
  elif is_hex64 "$HBH"; then
    ok "head_block_hash is 64-hex"
  else
    bad "head_block_hash is not a 64-hex string (got '${HBH:0:24}...')"
  fi

  case "$HH" in
    ""|__MISSING__) bad "head_height is missing from the state file" ;;
    *[!0-9]*)       bad "head_height is not an unsigned number (got '$HH')" ;;
    *)              ok  "head_height is a number ($HH)" ;;
  esac

  if [ "$HSR" = "__MISSING__" ]; then
    bad "head_state_root is missing from the state file"
  elif [ -z "$HSR" ]; then
    ok "head_state_root is empty (pre-S-033 chain form — allowed)"
  elif is_hex64 "$HSR"; then
    ok "head_state_root is 64-hex"
  else
    bad "head_state_root is neither empty nor 64-hex (got '${HSR:0:24}...')"
  fi
fi

# ── check 4 (--genesis): genesis re-pin via `state --verify-anchor` ───────────
# light/main.cpp cmd_state recomputes the genesis hash LOCALLY from the
# operator-supplied file (compute_genesis_hash, no daemon) and compares it
# to the cached pin. Exit contract: 0 PASS / 2 MISMATCH (different chain) /
# 1 error (corrupt state, bad genesis file).
if [ -n "$GENESIS" ]; then
  VOUT=$("$LIGHT" state --verify-anchor --genesis "$GENESIS" --state "$STATE" 2>&1)
  vrc=$?
  case "$vrc" in
    0) ok "genesis re-pin: cached pin equals the locally recomputed genesis hash" ;;
    2) bad "genesis re-pin: cached anchor is for a DIFFERENT chain than $GENESIS — clear the cache before resuming"
       printf '%s\n' "$VOUT" | grep -E 'genesis_hash|recompute' | sed 's/^/      /' ;;
    *) bad "genesis re-pin errored (rc=$vrc): $(printf '%s\n' "$VOUT" | head -1)" ;;
  esac
fi

# ── check 5 (--rpc-port): monotonicity cross-check against the live daemon ────
# Probe copied from operator_chain_health.sh: `determ head --json` over the
# raw line-delimited JSON-over-TCP RPC. The daemon's current head must be
# at (or above) the cached, committee-VERIFIED anchor height — a daemon
# below it cannot extend the anchor's history.
if [ -n "$PORT" ]; then
  HEAD_OUT=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null)
  hrc=$?
  if [ "$hrc" != "0" ]; then
    echo "$SCRIPT: RPC error (is the daemon running on port $PORT?) — monotonicity check skipped" >&2
    PREREQ_FAIL=1
  else
    if command -v jq >/dev/null 2>&1; then
      DH=$(printf '%s' "$HEAD_OUT" | jq -r '.height')
    else
      DH=$(printf '%s' "$HEAD_OUT" | grep -o '"height":[^,}]*' | head -1 | sed 's/.*: *//; s/[",]//g')
    fi
    case "$DH" in
      ""|*[!0-9]*)
        bad "daemon head response is malformed (no numeric height in: $(printf '%s' "$HEAD_OUT" | head -c 80))" ;;
      *)
        case "$HH" in
          ""|__MISSING__|*[!0-9]*)
            echo "note: cached head_height is unusable (see check 3) — monotonicity check skipped" ;;
          *)
            if [ "$DH" -ge "$HH" ]; then
              ok "monotonicity: daemon head ($DH) >= cached verified anchor ($HH)"
            else
              bad "daemon head regressed below verified anchor (stale/truncated state) — daemon=$DH < cached=$HH"
            fi ;;
        esac ;;
    esac
  fi
fi

# ── check 6: file age (warn-only) ─────────────────────────────────────────────
MTIME=$(stat -c %Y "$STATE" 2>/dev/null)
if [ -z "$MTIME" ]; then
  MTIME=$(stat -f %m "$STATE" 2>/dev/null)   # BSD/macOS stat
fi
case "${MTIME:-}" in
  ""|*[!0-9]*)
    echo "note: cannot determine state file mtime (stat unsupported) — age check skipped" ;;
  *)
    NOW=$(date +%s)
    AGE=$((NOW - MTIME))
    DAYS=$((AGE / 86400))
    if [ "$AGE" -gt 604800 ]; then
      warn "state file is $DAYS day(s) old (> 7) — anchor may be far behind; refresh via \`verify-chain --resume --persist\`"
    else
      ok "state file age is $DAYS day(s) (<= 7)"
    fi ;;
esac

# ── summary + exit policy ─────────────────────────────────────────────────────
# bad: findings (1) dominate missing prerequisites (2); all-ok is 0
# regardless of warns.
echo "Summary: $OK ok, $BAD bad, $WARN warn"
if [ "$BAD" -gt 0 ]; then
  echo "[FAIL] anchor cache audit found $BAD problem(s)"
  exit 1
elif [ "$PREREQ_FAIL" = "1" ]; then
  echo "[INCOMPLETE] prerequisites missing for at least one requested check (see messages above)"
  exit 2
else
  echo "[PASS] anchor cache is well-formed$([ "$WARN" -gt 0 ] && echo " ($WARN warning(s))")"
  exit 0
fi
