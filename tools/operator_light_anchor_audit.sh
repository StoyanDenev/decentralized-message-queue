#!/usr/bin/env bash
# operator_light_anchor_audit.sh — Offline fleet audit of determ-light
# persisted anchor caches. NO daemon contact: every check is a wrapper
# around the fully-offline `determ-light state` surface (see
# light/main.cpp::cmd_state + light/persist.cpp), so this tool is
# deterministic on every host that has the binary, exactly like
# tools/test_light_state.sh.
#
# What it audits:
#   A persisted anchor (light/persist.hpp LightState) pins a light client
#   to ONE chain: it stores the genesis_hash plus the last committee-
#   verified head (height / block_hash / state_root). An operator running
#   a fleet of light clients wants a single offline command that answers,
#   per cache file: "is this anchor present, healthy, and pinned to the
#   chain my --genesis describes — or is it stale / wrong-chain / corrupt?"
#   That is exactly the pre-resume gate `verify-chain --resume` will need.
#
# Per-target classification (wraps the cmd_state contract verbatim):
#   ABSENT            `state --show` exits 0 AND reports "no persisted
#                     anchor" — informational, NOT a failure. A light
#                     client that has never run `verify-chain --persist`
#                     legitimately has no cache.
#   VALID+PINNED      `state --show` exits 0 with a real anchor AND
#                     `state --verify-anchor --genesis <file>` exits 0
#                     (PASS) — the cache is well-formed and pinned to the
#                     operator's chain. The only healthy present state.
#   VALID+WRONG-CHAIN `state --show` exits 0 with a real anchor BUT
#                     `state --verify-anchor` exits 2 (MISMATCH) — the
#                     cache parses, but its genesis_hash is for a
#                     DIFFERENT chain than --genesis. A resume that trusted
#                     it would verify against the wrong chain → must be
#                     cleared.
#   CORRUPT           `state --show` exits 1 — load_light_state threw
#                     (malformed JSON, bad schema_version, short/non-hex
#                     field, missing field). The persist module fails
#                     CLOSED, so a corrupt cache is never silently treated
#                     as "no anchor".
#
# Fleet exit policy:
#   0   every PRESENT anchor is VALID+PINNED (ABSENT targets are
#       informational and do NOT fail the fleet — a never-initialized
#       light client is not an error).
#   1   any target is CORRUPT or VALID+WRONG-CHAIN, OR a usage / argument
#       error (missing --genesis, unreadable genesis, bad flag).
#
# SKIP policy (mirrors tools/test_light_state.sh):
#   If DETERM_LIGHT is unset or the binary is not executable, print a SKIP
#   line and exit 0 — the audit is a no-op on a host without the binary,
#   not a failure. `--help` is answered BEFORE the SKIP gate so it works
#   with no binary present.
set -u

usage() {
  cat <<'EOF'
Usage: operator_light_anchor_audit.sh --genesis <file>
                                      [--state <path>]...

Offline audit of determ-light persisted anchor caches (no daemon). For
each --state target it runs `determ-light state --show` then, if an
anchor is present, `determ-light state --verify-anchor --genesis <file>
--state <path>`, and classifies the cache as ABSENT / VALID+PINNED /
VALID+WRONG-CHAIN / CORRUPT. Prints a per-target line plus a fleet
summary.

Required:
  --genesis <file>     Genesis descriptor for the chain the fleet should
                       be pinned to. Its local genesis hash
                       (compute_genesis_hash) is the comparison target for
                       every anchor's stored genesis_hash.

Options:
  --state <path>       A persisted-anchor cache to audit. Repeatable —
                       pass once per light client. If given zero times,
                       the determ-light default cache is audited
                       ($DETERM_LIGHT_STATE if set, else
                       ~/.determ-light/state.json).
  -h, --help           Show this help (works without the binary).

Classification:
  ABSENT             no cache at the path (state --show exit 0, "no
                     persisted anchor") — informational, not a failure
  VALID+PINNED       anchor present AND verify-anchor PASS (exit 0)
  VALID+WRONG-CHAIN  anchor present BUT verify-anchor MISMATCH (exit 2)
  CORRUPT            state --show exit 1 (fail-closed load reject)

Exit codes:
  0   every present anchor is VALID+PINNED (absent targets ignored)
  1   any CORRUPT or VALID+WRONG-CHAIN target, or a usage/argument error

SKIP:
  Exits 0 with a SKIP line if the determ-light binary is unavailable
  (DETERM_LIGHT unset / not executable), mirroring tools/test_light_state.sh.
EOF
}

# ── arg parse ────────────────────────────────────────────────────────────────
# --help is handled BEFORE sourcing common.sh / the SKIP gate so it works
# on a host with no binary built.
GENESIS=""
STATES=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --genesis)
      GENESIS="${2:-}"
      if [ -z "$GENESIS" ]; then
        echo "operator_light_anchor_audit: --genesis requires a file argument" >&2
        exit 1
      fi
      shift 2 ;;
    --state)
      if [ -z "${2:-}" ]; then
        echo "operator_light_anchor_audit: --state requires a path argument" >&2
        exit 1
      fi
      STATES+=("$2")
      shift 2 ;;
    *)
      echo "operator_light_anchor_audit: unknown argument: $1" >&2
      usage >&2
      exit 1 ;;
  esac
done

if [ -z "$GENESIS" ]; then
  echo "operator_light_anchor_audit: --genesis <file> is required" >&2
  usage >&2
  exit 1
fi
if [ ! -f "$GENESIS" ]; then
  echo "operator_light_anchor_audit: genesis file not found: $GENESIS" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
source tools/common.sh

# SKIP gate — identical to tools/test_light_state.sh.
if [ -z "${DETERM_LIGHT:-}" ] || [ ! -x "$DETERM_LIGHT" ]; then
  echo "  SKIP: determ-light binary not found; build with"
  echo "        cmake --build build --config Release --target determ-light"
  exit 0
fi

# No explicit --state → audit the determ-light default cache. An empty
# path string makes `state` fall back to default_state_path() internally
# (DETERM_LIGHT_STATE or ~/.determ-light/state.json), matching the binary's
# own default and test_light_state.sh case #8.
if [ "${#STATES[@]}" -eq 0 ]; then
  STATES=("")
fi

# ── per-target audit ─────────────────────────────────────────────────────────
# Classify one target. Echoes the verdict token; sets no globals.
#   $1 = state path ("" → binary default)
classify_target() {
  local sp="$1"
  local show_out show_rc
  if [ -n "$sp" ]; then
    show_out=$("$DETERM_LIGHT" state --show --state "$sp" 2>&1); show_rc=$?
  else
    show_out=$("$DETERM_LIGHT" state --show 2>&1); show_rc=$?
  fi

  # exit 1 from --show = fail-closed load reject = CORRUPT.
  if [ "$show_rc" -eq 1 ]; then
    echo "CORRUPT"
    return
  fi
  # Any exit code other than 0 here is unexpected from the cmd_state
  # contract (--show is only ever 0 or 1); treat as CORRUPT defensively so
  # the fleet fails closed rather than mis-reporting a healthy anchor.
  if [ "$show_rc" -ne 0 ]; then
    echo "CORRUPT"
    return
  fi
  # exit 0 + the absence marker = ABSENT (cmd_state prints exactly
  # "no persisted anchor at <path>" on a missing cache, exit 0).
  case "$show_out" in
    *"no persisted anchor"*)
      echo "ABSENT"
      return ;;
  esac

  # Present + well-formed anchor: pin it against --genesis. verify-anchor
  # is 0 (PASS) / 2 (MISMATCH); other codes (e.g. 1 from a vanished cache
  # in a TOCTOU race, or an unreadable genesis) are reported as an error.
  local va_rc
  if [ -n "$sp" ]; then
    "$DETERM_LIGHT" state --verify-anchor --genesis "$GENESIS" --state "$sp" >/dev/null 2>&1
    va_rc=$?
  else
    "$DETERM_LIGHT" state --verify-anchor --genesis "$GENESIS" >/dev/null 2>&1
    va_rc=$?
  fi
  case "$va_rc" in
    0) echo "VALID+PINNED" ;;
    2) echo "VALID+WRONG-CHAIN" ;;
    *) echo "VERIFY-ERROR" ;;
  esac
}

GH_LOCAL=""  # filled lazily on first WRONG-CHAIN for the operator message

n_absent=0
n_pinned=0
n_wrong=0
n_corrupt=0
n_error=0
fleet_fail=0

echo "=== determ-light anchor audit (genesis: $GENESIS) ==="
printf '  %-40s %s\n' "TARGET" "VERDICT"
printf '  %-40s %s\n' "----------------------------------------" "-------"

for sp in "${STATES[@]}"; do
  label="$sp"
  [ -z "$label" ] && label="(default cache)"
  verdict=$(classify_target "$sp")
  case "$verdict" in
    ABSENT)
      n_absent=$((n_absent+1))
      printf '  %-40s %s\n' "$label" "ABSENT (informational — no cache)" ;;
    VALID+PINNED)
      n_pinned=$((n_pinned+1))
      printf '  %-40s %s\n' "$label" "VALID+PINNED" ;;
    VALID+WRONG-CHAIN)
      n_wrong=$((n_wrong+1))
      fleet_fail=1
      printf '  %-40s %s\n' "$label" "VALID+WRONG-CHAIN (anchor is for a DIFFERENT chain)" ;;
    CORRUPT)
      n_corrupt=$((n_corrupt+1))
      fleet_fail=1
      printf '  %-40s %s\n' "$label" "CORRUPT (fail-closed load reject)" ;;
    *)
      # VERIFY-ERROR — verify-anchor returned a non-{0,2} code on a cache
      # that --show accepted. Could not classify; treat as a fleet failure.
      n_error=$((n_error+1))
      fleet_fail=1
      printf '  %-40s %s\n' "$label" "ERROR (verify-anchor could not classify)" ;;
  esac
done

total=${#STATES[@]}
echo ""
echo "=== Fleet summary ==="
echo "  targets:           $total"
echo "  VALID+PINNED:      $n_pinned"
echo "  ABSENT:            $n_absent (informational)"
echo "  VALID+WRONG-CHAIN: $n_wrong"
echo "  CORRUPT:           $n_corrupt"
if [ "$n_error" -gt 0 ]; then
  echo "  ERROR:             $n_error"
fi

echo ""
if [ "$fleet_fail" -eq 0 ]; then
  echo "  PASS: all present anchors are VALID+PINNED"
  exit 0
else
  echo "  FAIL: $((n_wrong + n_corrupt + n_error)) target(s) need attention"
  exit 1
fi
