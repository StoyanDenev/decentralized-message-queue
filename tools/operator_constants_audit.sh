#!/usr/bin/env bash
# operator_constants_audit.sh — Trust-minimized governance-parameter audit:
# loop the determ-light `verify-constant` reader over an operator-supplied
# set of expected chain constants and emit a per-constant CONFIRMED /
# MISMATCH / UNVERIFIABLE table plus an overall PASS/FAIL gate.
#
# THE OPERATOR QUESTION
#   "Does the chain my daemon is following ACTUALLY run the governance
#    parameters I expect (min_stake, unstake_delay, subsidy schedule,
#    shard topology) — proven against the committee-signed state_root,
#    not asserted by the daemon's config or logs?"
#
# This is the trust-minimized complement to config inspection:
#   operator_config_audit.sh          lints what the CONFIG FILE claims
#                                     (local-file linter, no proof)
#   operator_effective_param_audit.sh proves the 3 governance-activatable
#                                     scalars + cross-refs pending changes
#                                     (on-daemon `k:`/`p:` probe)
#   operator_constants_audit.sh (THIS) drives the determ-light binary's
#                                     `verify-constant` reader — the FULL
#                                     light-client path (pinned genesis →
#                                     committee-verified header chain →
#                                     committee_bound_state_root (S-042) →
#                                     key-bound `k:` Merkle proof) — over
#                                     ANY subset of the 13 chain constants.
#
# Every per-constant verdict is CRYPTOGRAPHIC (light/main.cpp ::
# cmd_verify_constant): the `k:` leaf is key-bound to "k:"+name, the proof
# is Merkle-bound to a committee-attested state_root, and value_hash =
# SHA256(u64_be(value)) (u64 constants) / SHA256(salt_32) (shard_salt).
# CONFIRMED means the committee attests EXACTLY the expected value;
# MISMATCH means it attests a DIFFERENT one (sound under A2). Constants
# are unconditionally committed on an S-033 chain, so a daemon refusing
# the `k:` proof is UNVERIFIABLE (legacy or lying daemon) — never a
# negative.
#
# GOVERNANCE-MUTABLE CAVEAT (the one nuance an operator must know):
#   min_stake / suspension_slash / unstake_delay are PARAM_CHANGE-mutable:
#   governance can legitimately move them after genesis (chain.cpp ::
#   activate_pending_params). A MISMATCH on those three against a
#   genesis-derived expectation is NOT automatically an attack — it may be
#   an activated PARAM_CHANGE the operator's expectations file predates.
#   Those rows are flagged "governance-mutable" in the output, and any
#   mismatch on them prints a pointer to `determ-light verify-param-change`
#   / `determ pending-params` for the legitimacy check. The other
#   constants are genesis-pinned (my_shard_id is per-daemon: each daemon
#   commits its OWN shard id, so audit it against the shard THIS daemon
#   is supposed to serve).
#
# EXPECTED-VALUES FILE (--expected): a flat JSON object mapping constant
# names to expected values. Only the names present in the file are audited
# (operators audit what they care about). Example:
#
#   {
#     "min_stake": 1000,
#     "unstake_delay": 1000,
#     "block_subsidy": 50,
#     "shard_count": 1,
#     "shard_salt": "0000...64-hex...0000"
#   }
#
# Canonical names (13 — must match light/main.cpp kKnownU64Constants):
#   u64 (audited via --value):
#     block_subsidy subsidy_pool_initial subsidy_mode
#     lottery_jackpot_multiplier min_stake suspension_slash unstake_delay
#     merge_threshold_blocks revert_threshold_blocks merge_grace_blocks
#     shard_count my_shard_id
#   32-byte (audited via --value-hex, 64 hex chars):
#     shard_salt
# Unknown names in --expected are a usage error listing this set.
#
# Per-row verdict (verify-constant's exit-code contract, verbatim):
#   CONFIRMED      exit 0 — committee attests exactly the expected value
#   MISMATCH       exit 2 — committee attests a DIFFERENT value (sound)
#   UNVERIFIABLE   exit 3 — daemon refused the `k:` proof (legacy/lying)
#   ERROR          exit 1 (or other) — args / genesis / transport error
#                  (daemon down fails fast here; the audit never hangs)
#
# Usage:
#   tools/operator_constants_audit.sh --rpc-port N --genesis <file>
#                                     --expected <file.json>
#                                     [--light <path>] [--wait <seconds>]
#                                     [--json]
#
# determ-light binary resolution (first hit wins):
#   1. --light <path>
#   2. $DETERM_LIGHT (env)
#   3. build/Release/determ-light.exe
#   4. build/determ-light
#   (plus the build/determ-light.exe + build/Release/determ-light siblings
#    common.sh also probes). Errors out with build guidance if none is
#   executable — this audit is meaningless without the light client.
#
# Exit codes:
#   0   every audited constant CONFIRMED (overall PASS)
#   2   >=1 MISMATCH (note: governance-mutable mismatches may be
#       legitimate — check pending/activated PARAM_CHANGEs via
#       `determ-light verify-param-change` / `determ pending-params`)
#   3   >=1 UNVERIFIABLE and no MISMATCH
#   1   args/setup error, or >=1 per-row ERROR with no MISMATCH and no
#       UNVERIFIABLE
set -u

SCRIPT=operator_constants_audit

# Canonical u64 constants — must mirror light/main.cpp kKnownU64Constants.
U64_CONSTANTS="block_subsidy subsidy_pool_initial subsidy_mode lottery_jackpot_multiplier min_stake suspension_slash unstake_delay merge_threshold_blocks revert_threshold_blocks merge_grace_blocks shard_count my_shard_id"

usage() {
  cat <<'EOF'
Usage: operator_constants_audit.sh --rpc-port N --genesis <file>
                                   --expected <file.json>
                                   [--light <path>] [--wait <seconds>]
                                   [--json]

Trust-minimized governance-parameter audit: loops the determ-light
`verify-constant` reader over the constants named in --expected and
reports a per-constant CONFIRMED / MISMATCH / UNVERIFIABLE table plus an
overall PASS/FAIL. Every verdict is proven against the committee-signed
state_root (pinned genesis -> verified header chain -> key-bound `k:`
Merkle proof) — it shows what parameters the chain ACTUALLY runs, not
what the daemon's config claims.

Required:
  --rpc-port N       RPC port of the daemon to audit
  --genesis <file>   Genesis descriptor to pin the light client to
  --expected <file>  Flat JSON object {name: expected_value, ...}.
                     u64 constants take a number; shard_salt takes a
                     64-hex string. Only names present are audited.

Options:
  --light <path>     determ-light binary (else $DETERM_LIGHT, else
                     build/Release/determ-light.exe, else
                     build/determ-light)
  --wait <seconds>   Forwarded to verify-constant (S-042 sig-quorum wait)
  --json             Emit one machine-readable JSON object and nothing
                     else on stdout:
                     {"audit":...,"passed":N,"mismatched":N,
                      "unverifiable":N,"errors":N,"overall":"PASS|FAIL",
                      "rows":[{"name":...,"verdict":...,"expected":...,
                               "governance_mutable":true|false},...]}
  -h, --help         Show this help

Canonical constant names (13):
  u64:      block_subsidy subsidy_pool_initial subsidy_mode
            lottery_jackpot_multiplier min_stake suspension_slash
            unstake_delay merge_threshold_blocks revert_threshold_blocks
            merge_grace_blocks shard_count my_shard_id
  64-hex:   shard_salt

Governance-mutable caveat:
  min_stake / suspension_slash / unstake_delay can be changed by an
  activated PARAM_CHANGE after genesis, so a MISMATCH on those three
  against a genesis-derived expectation may be LEGITIMATE — those rows
  are flagged "governance-mutable"; verify via
  `determ-light verify-param-change` / `determ pending-params` before
  treating the mismatch as an alert. my_shard_id is per-daemon. All
  other constants are genesis-pinned.

Per-row verdicts (verify-constant exit codes):
  CONFIRMED      exit 0 — committee attests exactly the expected value
  MISMATCH       exit 2 — committee attests a DIFFERENT value (sound)
  UNVERIFIABLE   exit 3 — daemon refused the `k:` proof (legacy/lying)
  ERROR          exit 1/other — args / genesis / transport error
                 (a down daemon fails fast — no hangs)

Exit codes:
  0   every audited constant CONFIRMED (PASS)
  2   >=1 MISMATCH (governance-mutable mismatches may be legitimate)
  3   >=1 UNVERIFIABLE and no MISMATCH
  1   args/setup error, or >=1 row ERROR with no MISMATCH/UNVERIFIABLE
EOF
}

# ── helpers ───────────────────────────────────────────────────────────────────
is_u64_constant() {
  local n
  for n in $U64_CONSTANTS; do
    [ "$n" = "$1" ] && return 0
  done
  return 1
}

is_gov_mutable() {
  case "$1" in
    min_stake|suspension_slash|unstake_delay) return 0 ;;
  esac
  return 1
}

unknown_name_error() {
  echo "$SCRIPT: unknown constant '$1' in --expected. Canonical names:" >&2
  echo "  u64 (number):        $U64_CONSTANTS" >&2
  echo "  32-byte (64-hex):    shard_salt" >&2
  exit 1
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

# ── arg parse (--help first so it never trips validation) ─────────────────────
PORT=""
GENESIS=""
EXPECTED=""
LIGHT_FLAG=""
WAIT=""
JSON_OUT=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)   usage; exit 0 ;;
    --rpc-port)  PORT="${2:-}";       shift 2 ;;
    --genesis)   GENESIS="${2:-}";    shift 2 ;;
    --expected)  EXPECTED="${2:-}";   shift 2 ;;
    --light)     LIGHT_FLAG="${2:-}"; shift 2 ;;
    --wait)      WAIT="${2:-}";       shift 2 ;;
    --json)      JSON_OUT=1;          shift ;;
    *) echo "$SCRIPT: unknown argument: $1" >&2
       usage >&2; exit 1 ;;
  esac
done

# ── argument validation ───────────────────────────────────────────────────────
if [ -z "$PORT" ] || [ -z "$GENESIS" ] || [ -z "$EXPECTED" ]; then
  echo "$SCRIPT: --rpc-port, --genesis, --expected are all required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "$SCRIPT: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
if [ -n "$WAIT" ]; then
  case "$WAIT" in *[!0-9]*)
    echo "$SCRIPT: --wait must be an unsigned integer (got '$WAIT')" >&2
    exit 1 ;;
  esac
fi

GENESIS=$(abspath "$GENESIS")
EXPECTED=$(abspath "$EXPECTED")
[ -n "$LIGHT_FLAG" ] && LIGHT_FLAG=$(abspath "$LIGHT_FLAG")

if [ ! -f "$GENESIS" ]; then
  echo "$SCRIPT: genesis file not found: $GENESIS" >&2
  exit 1
fi
if [ ! -f "$EXPECTED" ]; then
  echo "$SCRIPT: expected-values file not found: $EXPECTED" >&2
  exit 1
fi

cd "$(dirname "$0")/.."

# ── determ-light binary resolution ────────────────────────────────────────────
# --light flag > $DETERM_LIGHT env > standard build locations. An explicit
# choice (flag/env) that is not executable is an ERROR, not a fall-through:
# silently auditing with a different binary than the operator named would
# undermine the audit.
LIGHT=""
if [ -n "$LIGHT_FLAG" ]; then
  LIGHT="$LIGHT_FLAG"
  if [ ! -x "$LIGHT" ]; then
    echo "$SCRIPT: --light '$LIGHT' is not an executable file" >&2
    exit 1
  fi
elif [ -n "${DETERM_LIGHT:-}" ]; then
  LIGHT="$DETERM_LIGHT"
  if [ ! -x "$LIGHT" ]; then
    echo "$SCRIPT: \$DETERM_LIGHT '$LIGHT' is not an executable file" >&2
    exit 1
  fi
else
  for cand in build/Release/determ-light.exe build/determ-light \
              build/determ-light.exe build/Release/determ-light; do
    if [ -x "$cand" ]; then
      LIGHT="$cand"
      break
    fi
  done
  if [ -z "$LIGHT" ]; then
    echo "$SCRIPT: determ-light binary not found. Build it with" >&2
    echo "    cmake --build build --config Release --target determ-light" >&2
    echo "  or point at one via --light <path> or \$DETERM_LIGHT." >&2
    exit 1
  fi
fi

# ── parse the expected-values file ────────────────────────────────────────────
# Preferred: python (the operator_*.sh house pattern — see
# operator_pending_param_proof_audit.sh) for real JSON parsing.
# Fallback: a conservative grep/sed extractor that requires a FLAT object
# with each "name": value pair on one line (the documented file shape).
# Both paths emit "name value" lines; ALL validation (canonical names,
# value form, duplicates) happens in bash below so the two parsers cannot
# diverge on policy.
PY=""
if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
fi

if [ -n "$PY" ]; then
  PARSED=$(
    "$PY" - "$EXPECTED" <<'PYEOF'
import json, sys

path = sys.argv[1]
try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    sys.stderr.write(
        "operator_constants_audit: --expected is not valid JSON (%s)\n" % e)
    sys.exit(1)
if not isinstance(data, dict):
    sys.stderr.write(
        "operator_constants_audit: --expected must be a JSON object "
        "mapping constant names to expected values\n")
    sys.exit(1)
if not data:
    sys.stderr.write(
        "operator_constants_audit: --expected contains no constants to "
        "audit\n")
    sys.exit(1)
for name, v in data.items():
    if isinstance(v, bool) or not isinstance(v, (int, str)):
        sys.stderr.write(
            "operator_constants_audit: value for '%s' must be a u64 "
            "number or a 64-hex string\n" % name)
        sys.exit(1)
    print("%s %s" % (name, v))
PYEOF
  ) || exit 1
else
  # Conservative fallback (no python on PATH): flat object, one pair per
  # line. Anything fancier (nesting, multi-line pairs) is rejected via the
  # value-form validation below rather than misparsed.
  RAW=$(cat "$EXPECTED") || {
    echo "$SCRIPT: cannot read $EXPECTED" >&2
    exit 1
  }
  KEYS=$(printf '%s\n' "$RAW" \
    | grep -o '"[A-Za-z_][A-Za-z0-9_]*"[[:space:]]*:' \
    | sed 's/^"//; s/"[[:space:]]*:$//')
  if [ -z "$KEYS" ]; then
    echo "$SCRIPT: no \"name\": value entries found in $EXPECTED" >&2
    echo "  (fallback parser needs a flat JSON object with each pair on one line;" >&2
    echo "   install python3 for full JSON parsing)" >&2
    exit 1
  fi
  PARSED=""
  for k in $KEYS; do
    v=$(printf '%s\n' "$RAW" \
      | grep -o "\"$k\"[[:space:]]*:[[:space:]]*[^,}]*" | head -1 \
      | sed 's/^"[^"]*"[[:space:]]*:[[:space:]]*//; s/^"//; s/"[[:space:]]*$//; s/[[:space:]]*$//')
    PARSED="$PARSED$k $v
"
  done
fi

# ── validate the parsed pairs (shared policy for both parsers) ────────────────
NAMES=()
VALUES=()
SEEN=" "
while IFS= read -r line; do
  # Strip a trailing CR — Windows python emits CRLF line endings, and the
  # --expected file itself may be CRLF on this platform.
  line=${line%$'\r'}
  [ -z "$line" ] && continue
  case "$line" in
    *" "*) ;;
    *) echo "$SCRIPT: malformed entry in --expected: '$line' (missing value)" >&2
       exit 1 ;;
  esac
  name="${line%% *}"
  value="${line#* }"
  case "$SEEN" in *" $name "*)
    echo "$SCRIPT: duplicate constant '$name' in --expected" >&2
    exit 1 ;;
  esac
  SEEN="$SEEN$name "
  if [ "$name" = "shard_salt" ]; then
    case "$value" in
      *[!0-9a-fA-F]*|"")
        echo "$SCRIPT: shard_salt expected value must be a 64-hex string (got '$value')" >&2
        exit 1 ;;
    esac
    if [ "${#value}" -ne 64 ]; then
      echo "$SCRIPT: shard_salt expected value must be exactly 64 hex chars (got ${#value})" >&2
      exit 1
    fi
  elif is_u64_constant "$name"; then
    case "$value" in
      ""|*[!0-9]*)
        echo "$SCRIPT: expected value for u64 constant '$name' must be an unsigned integer (got '$value')" >&2
        exit 1 ;;
    esac
  else
    unknown_name_error "$name"
  fi
  NAMES+=("$name")
  VALUES+=("$value")
done <<PARSED_EOF
$PARSED
PARSED_EOF

TOTAL=${#NAMES[@]}
if [ "$TOTAL" -eq 0 ]; then
  echo "$SCRIPT: --expected contains no constants to audit" >&2
  exit 1
fi

# ── audit loop: one verify-constant invocation per expected constant ──────────
CONFIRMED=0
MISMATCHED=0
UNVERIF=0
ERRORS=0
GOV_MISMATCH=0
ROWS_JSON=""

if [ "$JSON_OUT" = "0" ]; then
  echo "=== Trust-minimized constants audit (port $PORT) ==="
  echo "genesis:  $GENESIS"
  echo "light:    $LIGHT"
  echo "expected: $EXPECTED ($TOTAL constant(s))"
  printf '  %-28s%-14s%-20s%s\n' "constant" "verdict" "notes" "expected"
fi

i=0
while [ "$i" -lt "$TOTAL" ]; do
  name="${NAMES[$i]}"
  value="${VALUES[$i]}"
  i=$((i + 1))

  CMD=("$LIGHT" verify-constant --rpc-port "$PORT" --genesis "$GENESIS" \
       --name "$name")
  if [ "$name" = "shard_salt" ]; then
    CMD+=(--value-hex "$value")
  else
    CMD+=(--value "$value")
  fi
  [ -n "$WAIT" ] && CMD+=(--wait "$WAIT")

  OUT=$("${CMD[@]}" 2>&1)
  rc=$?
  case "$rc" in
    0) verdict="CONFIRMED";    CONFIRMED=$((CONFIRMED + 1)) ;;
    2) verdict="MISMATCH";     MISMATCHED=$((MISMATCHED + 1))
       is_gov_mutable "$name" && GOV_MISMATCH=$((GOV_MISMATCH + 1)) ;;
    3) verdict="UNVERIFIABLE"; UNVERIF=$((UNVERIF + 1)) ;;
    *) verdict="ERROR";        ERRORS=$((ERRORS + 1)) ;;
  esac

  gm="false"
  is_gov_mutable "$name" && gm="true"
  if [ "$name" = "shard_salt" ]; then
    exp_json="\"$value\""
  else
    exp_json="$value"
  fi
  row="{\"name\":\"$name\",\"verdict\":\"$verdict\",\"expected\":$exp_json,\"governance_mutable\":$gm}"
  if [ -z "$ROWS_JSON" ]; then ROWS_JSON="$row"; else ROWS_JSON="$ROWS_JSON,$row"; fi

  if [ "$JSON_OUT" = "0" ]; then
    note="genesis-pinned"
    is_gov_mutable "$name" && note="governance-mutable"
    [ "$name" = "my_shard_id" ] && note="per-daemon"
    printf '  %-28s%-14s%-20s%s\n' "$name" "$verdict" "$note" "$value"
    if [ "$verdict" != "CONFIRMED" ]; then
      detail=$(printf '%s\n' "$OUT" | head -1)
      [ "$verdict" = "ERROR" ] && detail="rc=$rc: $detail"
      printf '      detail: %s\n' "$detail"
    fi
  fi
done

# ── overall verdict + exit policy ─────────────────────────────────────────────
# MISMATCH (2) dominates UNVERIFIABLE (3) dominates ERROR (1); all-CONFIRMED
# is the only PASS (0).
if [ "$MISMATCHED" -gt 0 ]; then
  EXIT=2
elif [ "$UNVERIF" -gt 0 ]; then
  EXIT=3
elif [ "$ERRORS" -gt 0 ]; then
  EXIT=1
else
  EXIT=0
fi
OVERALL=$([ "$EXIT" = "0" ] && echo PASS || echo FAIL)

if [ "$JSON_OUT" = "1" ]; then
  printf '{"audit":"%s","rpc_port":%s,"total":%s,"passed":%s,"mismatched":%s,"unverifiable":%s,"errors":%s,"governance_mutable_mismatches":%s,"overall":"%s","rows":[%s]}\n' \
    "$SCRIPT" "$PORT" "$TOTAL" "$CONFIRMED" "$MISMATCHED" "$UNVERIF" \
    "$ERRORS" "$GOV_MISMATCH" "$OVERALL" "$ROWS_JSON"
else
  echo "Summary: $TOTAL audited — $CONFIRMED CONFIRMED, $MISMATCHED MISMATCH, $UNVERIF UNVERIFIABLE, $ERRORS ERROR"
  if [ "$EXIT" = "0" ]; then
    echo "[PASS] every audited constant is committee-CONFIRMED — the chain runs exactly these parameters"
  else
    echo "[FAIL] overall exit $EXIT ($([ "$EXIT" = "2" ] && echo 'mismatch' || { [ "$EXIT" = "3" ] && echo 'unverifiable' || echo 'error'; }))"
  fi
  if [ "$GOV_MISMATCH" -gt 0 ]; then
    echo "note: $GOV_MISMATCH MISMATCH(es) on governance-mutable constant(s) (min_stake /"
    echo "      suspension_slash / unstake_delay). These may be LEGITIMATE if a PARAM_CHANGE"
    echo "      activated since your expectations were written — check via"
    echo "      \`determ-light verify-param-change\` / \`determ pending-params\` before alarm."
  fi
fi

exit "$EXIT"
