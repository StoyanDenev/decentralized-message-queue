#!/usr/bin/env bash
# operator_liveness_posture.sh — OFFLINE S-044 / S-045 liveness-posture
# audit of a deployment's genesis.json (and optionally a node config.json).
#
# THE OPERATOR QUESTION
#   "Given my committee parameters (M pool, K committee), can ordinary
#    timing skew wedge this chain permanently — and is BFT escalation
#    actually reachable when it must rescue a stuck height?"
#
# Pure read-only file inspection: no RPC, no daemon, no cluster, no chain
# mutation. Parsing is Python (the operator_*.sh house pattern, mirroring
# operator_genesis_inspect.sh / operator_anchor_audit.sh); all arithmetic
# and verdict policy live in bash below so the parser carries no policy.
#
# THE ARITHMETIC (each value pinned to the code that makes it true)
#
#   K  = k_block_sigs   committee size per round
#                       (src/node/node.cpp:756 — k_target = cfg_.k_block_sigs;
#                        genesis default: src/chain/genesis.cpp:116-117 —
#                        m_creators default 3, k_block_sigs default = M)
#   M  = m_creators     eligible pool per height (per shard/region)
#
#   claim quorum q = K - 1
#       An abort quorum against a "missing" member needs only
#       committee_size - 1 distinct claims: built in on_abort_claim
#       (src/node/node.cpp:1274-1277, AbortEvent assembled :1279-1295) and
#       re-validated on gossip adoption in on_abort_event
#       (src/node/node.cpp:1325-1331 + :1354). At K=2, q=1: ONE peer's
#       claim — no corroboration — excludes a member for the height.
#
#   exclusion accumulation
#       check_if_selected (src/node/node.cpp:729) drops every domain in
#       current_aborts_ from the pool (:762-768). current_aborts_ clears
#       ONLY on block accept (src/node/node.cpp:1856 — the sole clear
#       site); there is no decay, expiry, or retry. Each abort also bumps
#       the abort generation, and contribs whose aborts_gen mismatches are
#       dropped (src/node/node.cpp:2113-2116) — the desync that makes the
#       next straggle likely (the S-044 cascade).
#
#   k_bft = (2K + 2) / 3  [integer division] = ceil(2K/3)
#       (src/node/node.cpp:778). Escalation to a BFT round fires only when
#       ALL of (src/node/node.cpp:781-787):
#           avail < k_target  AND  bft_enabled
#           AND total_aborts >= bft_escalation_threshold
#           AND avail >= k_bft
#       Otherwise, with avail < k_use, check_if_selected SILENTLY returns
#       (src/node/node.cpp:788) — no round, no new abort claims, counter
#       frozen: the S-045 halt.
#
#   single-abort margin    = M - K      distinct exclusions tolerated while
#                                       still forming a full MD committee
#   escalation headroom    = M - k_bft  max distinct exclusions under which
#                                       a BFT committee can still form
#   wedge_min_distinct     = M - K + 1  minimum count of DISTINCT excluded
#                                       members that blocks all rounds
#                                       (k_use = K pre-escalation); it is
#                                       PERMANENT unless escalation is
#                                       reachable at that moment
#
# VERDICTS (exit code = verdict tier)
#   CRITICAL (exit 2) — K == 2 (S-044): q = 1 single-claim abort quorum;
#       k_bft = ceil(4/3) = 2 = K, so NO escalation headroom exists by
#       construction; every straggle is an exclusion; permanent wedge under
#       ordinary timing skew. The shipped `web` profile — the `determ init`
#       DEFAULT — is M=3/K=2 (include/determ/chain/params.hpp:142-145);
#       `web_test` inherits the posture (:216-220).
#   WARNING (exit 1) — K >= 3 and escalation headroom M - k_bft < 2
#       (S-045): two distinct straggles at one height drop avail below
#       k_bft before total_aborts can plausibly reach the threshold =
#       permanent halt. M=K=3 (cluster :138-141, tactical :178-181) lands
#       here: k_bft = 2, headroom 1. Also WARNING: bft_enabled=false with
#       K >= 3 — escalation is impossible outright, so wedge_min_distinct
#       exclusions at one height halt the chain with no rescue path.
#   OK (exit 0) — K >= 3 and headroom >= 2 with escalation enabled, e.g.
#       regional M=5/K=4 (params.hpp:146-149, headroom 5-3=2) and global
#       M=7/K=5 (:150-153, headroom 7-4=3). K <= 1 is also OK-with-note:
#       a single-creator committee has no peers to claim aborts, so the
#       cascade machinery never engages.
#
# EVIDENCE (live cluster runs, 2026-06-11 — see docs/SECURITY.md S-044):
#   tools/test_weak_3node.sh (header :8-18) documents the observed K=2
#   cascade; tools/test_web_hybrid.sh (:118) + tools/test_regional_shards.sh
#   (:154) carry KNOWN-BUG S-044 notes in place of their sustained-
#   production bars; tools/test_bft_escalation.sh is the GREEN single-dead-
#   member case (same-member aborts keep avail = M-1 >= k_bft, the counter
#   climbs, escalation fires) — the gap is MULTI-member exclusion.
#
# Canonical finding descriptions: docs/SECURITY.md sections S-044 (Open,
# High, liveness) and S-045 (Open, Medium, liveness).
#
# --config notes: check_if_selected reads cfg_ — the NODE config — not the
# genesis (node.cpp:756 k_target, :782 bft_enabled, :783 threshold). When
# --config is given, keys PRESENT in it (m_creators / k_block_sigs /
# bft_enabled / bft_escalation_threshold, src/node/node.cpp:85-88) override
# the genesis values as the EFFECTIVE posture, a genesis/config M-K
# mismatch is flagged, and sharding_mode (:95; 0=none 1=current 2=extended,
# include/determ/types.hpp:46-50) is reported for context (EXTENDED
# postures wedge per-shard/region pool).
#
# Usage:
#   tools/operator_liveness_posture.sh --genesis <gen.json>
#                                      [--config <config.json>] [--json]
#
# Exit codes:
#   0   OK       — posture tolerates single straggles + has escalation headroom
#   1   WARNING  — S-045 exposure (headroom < 2, or escalation disabled)
#   2   CRITICAL — S-044 exposure (K == 2)
#   3   usage / file / parse error (verdict could not be computed —
#       deliberately distinct from the verdict tiers so a missing python
#       can never read as "OK posture")
set -u

SCRIPT=operator_liveness_posture

usage() {
  cat <<'EOF'
Usage: operator_liveness_posture.sh --genesis <gen.json>
                                    [--config <config.json>] [--json]

OFFLINE S-044/S-045 liveness-posture audit (docs/SECURITY.md). Reads
committee parameters from a genesis file (and optionally a node
config.json, whose present keys override — cfg_ is what
check_if_selected actually reads) and reports:

  K (k_block_sigs), M (m_creators pool), abort-claim quorum q = K-1,
  k_bft = ceil(2K/3), single-abort margin M-K, escalation headroom
  M-k_bft, and the minimum distinct-exclusion count that wedges the
  height (M-K+1), plus the posture verdict.

No RPC, no daemon, no writes — pure file inspection.

Options:
  --genesis <file>   Genesis JSON to audit (required)
  --config <file>    Node config.json — fold effective overrides +
                     sharding_mode/bft_enabled into the verdict
  --json             Emit a machine-readable JSON object
  -h, --help         Show this help

Exit codes:
  0   OK       (tolerates single straggles; escalation headroom >= 2)
  1   WARNING  (S-045: headroom < 2 distinct members, or BFT disabled)
  2   CRITICAL (S-044: K == 2 — permanent wedge under timing skew)
  3   usage / file / parse error
EOF
}

# Absolutize a user-supplied path against the INVOCATION cwd, so paths
# still resolve after we cd to the repo root (operator_anchor_audit.sh
# pattern). Handles POSIX absolute paths and Windows drive-letter paths.
abspath() {
  case "$1" in
    /*|[A-Za-z]:*) printf '%s\n' "$1" ;;
    *)             printf '%s/%s\n' "$PWD" "$1" ;;
  esac
}

GENESIS=""
CONFIG=""
JSON=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --json) JSON=1; shift ;;
    --genesis|--config)
      # `shift 2` with only the flag left FAILS WITHOUT SHIFTING in bash,
      # which would spin this loop forever — require the value explicitly.
      if [ $# -lt 2 ]; then
        echo "$SCRIPT: $1 requires a value" >&2
        exit 3
      fi
      case "$1" in
        --genesis) GENESIS="$2" ;;
        --config)  CONFIG="$2"  ;;
      esac
      shift 2 ;;
    *) echo "$SCRIPT: unknown argument: $1" >&2; usage >&2; exit 3 ;;
  esac
done

if [ -z "$GENESIS" ]; then
  echo "$SCRIPT: --genesis is required" >&2
  usage >&2
  exit 3
fi

GENESIS=$(abspath "$GENESIS")
[ -n "$CONFIG" ] && CONFIG=$(abspath "$CONFIG")

if [ ! -f "$GENESIS" ]; then
  echo "$SCRIPT: genesis file not found: $GENESIS" >&2
  exit 3
fi
if [ -n "$CONFIG" ] && [ ! -f "$CONFIG" ]; then
  echo "$SCRIPT: config file not found: $CONFIG" >&2
  exit 3
fi

cd "$(dirname "$0")/.."

PY=""
if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
fi
if [ -z "$PY" ]; then
  echo "$SCRIPT: a Python interpreter is required to parse the JSON inputs" >&2
  exit 3
fi

# ── parse (python emits "key value" lines; ALL policy stays in bash) ──────────
# Genesis defaults mirror src/chain/genesis.cpp:116-117 (m_creators 3,
# k_block_sigs = m_creators) and :172-173 (bft_enabled true,
# bft_escalation_threshold 5). Config keys mirror src/node/node.cpp:85-88
# + :95; only keys PRESENT in the config are emitted (as cfg_* lines) so
# bash can distinguish "override" from "config silent on this knob".
PARSED=$(
  "$PY" - "$GENESIS" ${CONFIG:+"$CONFIG"} <<'PYEOF'
import json, sys

def load(path):
    with open(path, "r", encoding="utf-8") as f:
        d = json.load(f)
    if not isinstance(d, dict):
        raise ValueError("top-level value is not an object: %s" % path)
    return d

def need_uint(d, key, default):
    v = d.get(key, default)
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise ValueError("%r is not an unsigned integer (got %r)" % (key, v))
    return v

def need_bool(d, key, default):
    v = d.get(key, default)
    if not isinstance(v, bool):
        raise ValueError("%r is not a boolean (got %r)" % (key, v))
    return v

try:
    g = load(sys.argv[1])
    m = need_uint(g, "m_creators", 3)            # genesis.cpp:116
    k = need_uint(g, "k_block_sigs", m)          # genesis.cpp:117 (default = M)
    print("gen_m %d" % m)
    print("gen_k %d" % k)
    print("gen_bft_enabled %s"
          % ("true" if need_bool(g, "bft_enabled", True) else "false"))
    print("gen_bft_threshold %d"
          % need_uint(g, "bft_escalation_threshold", 5))

    if len(sys.argv) > 2:
        c = load(sys.argv[2])
        # Emit ONLY keys present in the file — presence drives override.
        if "m_creators" in c:
            print("cfg_m %d" % need_uint(c, "m_creators", 0))
        if "k_block_sigs" in c:
            print("cfg_k %d" % need_uint(c, "k_block_sigs", 0))
        if "bft_enabled" in c:
            print("cfg_bft_enabled %s"
                  % ("true" if need_bool(c, "bft_enabled", True) else "false"))
        if "bft_escalation_threshold" in c:
            print("cfg_bft_threshold %d"
                  % need_uint(c, "bft_escalation_threshold", 0))
        if "sharding_mode" in c:
            sm = need_uint(c, "sharding_mode", 1)
            names = {0: "none", 1: "current", 2: "extended"}  # types.hpp:46-50
            print("cfg_sharding_mode %s" % names.get(sm, "unknown(%d)" % sm))
except Exception as e:
    sys.stderr.write("%s\n" % e)
    sys.exit(1)
PYEOF
) || {
  echo "$SCRIPT: failed to parse input JSON (see message above)" >&2
  exit 3
}

GEN_M=""; GEN_K=""; GEN_BFT_ENABLED=""; GEN_BFT_THRESHOLD=""
CFG_M=""; CFG_K=""; CFG_BFT_ENABLED=""; CFG_BFT_THRESHOLD=""; CFG_SHARDING=""
while IFS= read -r line; do
  line=${line%$'\r'}            # Windows python emits CRLF
  [ -z "$line" ] && continue
  k="${line%% *}"; v="${line#* }"
  case "$k" in
    gen_m)             GEN_M="$v" ;;
    gen_k)             GEN_K="$v" ;;
    gen_bft_enabled)   GEN_BFT_ENABLED="$v" ;;
    gen_bft_threshold) GEN_BFT_THRESHOLD="$v" ;;
    cfg_m)             CFG_M="$v" ;;
    cfg_k)             CFG_K="$v" ;;
    cfg_bft_enabled)   CFG_BFT_ENABLED="$v" ;;
    cfg_bft_threshold) CFG_BFT_THRESHOLD="$v" ;;
    cfg_sharding_mode) CFG_SHARDING="$v" ;;
  esac
done <<PARSED_EOF
$PARSED
PARSED_EOF

if [ -z "$GEN_M" ] || [ -z "$GEN_K" ]; then
  echo "$SCRIPT: parser produced no committee parameters (malformed genesis?)" >&2
  exit 3
fi

# ── effective posture: config keys (when present) override the genesis ───────
# check_if_selected reads cfg_, the node config (node.cpp:756/:782/:783).
M="$GEN_M"; K="$GEN_K"
BFT_ENABLED="$GEN_BFT_ENABLED"; BFT_THRESHOLD="$GEN_BFT_THRESHOLD"
[ -n "$CFG_M" ]             && M="$CFG_M"
[ -n "$CFG_K" ]             && K="$CFG_K"
[ -n "$CFG_BFT_ENABLED" ]   && BFT_ENABLED="$CFG_BFT_ENABLED"
[ -n "$CFG_BFT_THRESHOLD" ] && BFT_THRESHOLD="$CFG_BFT_THRESHOLD"

MISMATCH="false"
if [ -n "$CONFIG" ]; then
  if { [ -n "$CFG_M" ] && [ "$CFG_M" != "$GEN_M" ]; } \
  || { [ -n "$CFG_K" ] && [ "$CFG_K" != "$GEN_K" ]; }; then
    MISMATCH="true"
  fi
fi

# Sanity: the genesis constraint is 1 <= K <= M (genesis.hpp:101). A
# violated input cannot yield a meaningful posture verdict.
if [ "$K" -lt 1 ] 2>/dev/null; then
  echo "$SCRIPT: invalid posture: k_block_sigs=$K < 1" >&2
  exit 3
fi
if [ "$K" -gt "$M" ] 2>/dev/null; then
  echo "$SCRIPT: invalid posture: k_block_sigs=$K > m_creators=$M (violates 1 <= K <= M)" >&2
  exit 3
fi

# ── the arithmetic (header comment carries the node.cpp pins) ─────────────────
Q=$(( K - 1 ))                          # abort-claim quorum (node.cpp:1274-1277)
K_BFT=$(( (2 * K + 2) / 3 ))            # ceil(2K/3)        (node.cpp:778)
MARGIN=$(( M - K ))                     # single-abort margin
HEADROOM=$(( M - K_BFT ))               # escalation headroom
WEDGE_MIN=$(( M - K + 1 ))              # min distinct exclusions that wedge

# ── verdict ───────────────────────────────────────────────────────────────────
NOTES=()
if [ "$K" -eq 2 ]; then
  VERDICT="CRITICAL"
  FINDING="S-044"
  RC=2
  MESSAGE="CRITICAL EXPOSURE (S-044): single-claim abort quorum (q=1); permanent wedge under ordinary timing skew; deploy K >= 3"
  if [ "$BFT_ENABLED" != "true" ]; then
    NOTES+=("bft_enabled=false is moot at K=2 — k_bft=2=K leaves no escalation headroom even when enabled")
  fi
elif [ "$K" -le 1 ]; then
  VERDICT="OK"
  FINDING="none"
  RC=0
  MESSAGE="OK: K=$K single-creator committee — no peers to claim aborts; the S-044/S-045 cascade machinery never engages"
elif [ "$BFT_ENABLED" != "true" ]; then
  VERDICT="WARNING"
  FINDING="S-045"
  RC=1
  MESSAGE="WARNING (S-045, elevated): bft_enabled=false — escalation impossible; $WEDGE_MIN distinct abort-excluded members at one height = permanent halt with no rescue path"
elif [ "$HEADROOM" -lt 2 ]; then
  VERDICT="WARNING"
  FINDING="S-045"
  RC=1
  MESSAGE="WARNING (S-045): escalation headroom < 2 distinct members; two distinct straggles at one height = permanent halt"
else
  VERDICT="OK"
  FINDING="none"
  RC=0
  MESSAGE="OK: posture tolerates single straggles and has escalation headroom $HEADROOM"
fi

[ "$MISMATCH" = "true" ] && \
  NOTES+=("config M/K override differs from genesis (genesis M=$GEN_M/K=$GEN_K vs effective M=$M/K=$K) — check_if_selected runs on the config values; a fleet with mixed configs will not converge")
[ "$CFG_SHARDING" = "extended" ] && \
  NOTES+=("sharding_mode=extended — M is the per-shard/per-region pool; each shard wedges independently at $WEDGE_MIN distinct exclusions")

# ── output ────────────────────────────────────────────────────────────────────
if [ "$JSON" = "1" ]; then
  NOTES_JSON="["
  sep=""
  for n in "${NOTES[@]:-}"; do
    [ -z "$n" ] && continue
    esc=${n//\\/\\\\}; esc=${esc//\"/\\\"}
    NOTES_JSON="$NOTES_JSON$sep\"$esc\""
    sep=", "
  done
  NOTES_JSON="$NOTES_JSON]"
  cat <<EOF
{"tool": "$SCRIPT", "genesis": "${GENESIS//\\//}", "config": $( [ -n "$CONFIG" ] && printf '"%s"' "${CONFIG//\\//}" || printf 'null' ), "m_creators": $M, "k_block_sigs": $K, "claim_quorum": $Q, "k_bft": $K_BFT, "single_abort_margin": $MARGIN, "escalation_headroom": $HEADROOM, "wedge_min_distinct_exclusions": $WEDGE_MIN, "bft_enabled": $BFT_ENABLED, "bft_escalation_threshold": $BFT_THRESHOLD, "sharding_mode": $( [ -n "$CFG_SHARDING" ] && printf '"%s"' "$CFG_SHARDING" || printf 'null' ), "config_genesis_mismatch": $MISMATCH, "verdict": "$VERDICT", "finding": "$FINDING", "message": "$MESSAGE", "notes": $NOTES_JSON, "reference": "docs/SECURITY.md S-044 + S-045", "exit_code": $RC}
EOF
  exit $RC
fi

echo "=== determ liveness-posture audit (S-044 / S-045, docs/SECURITY.md) ==="
echo "genesis: $GENESIS"
[ -n "$CONFIG" ] && echo "config:  $CONFIG (present keys override — cfg_ is what check_if_selected reads)"
echo
echo "  committee size K (k_block_sigs)        = $K"
echo "  eligible pool  M (m_creators)          = $M"
echo "  abort-claim quorum q = K-1             = $Q     (node.cpp on_abort_claim/on_abort_event)"
echo "  k_bft = ceil(2K/3) = (2K+2)/3          = $K_BFT     (node.cpp check_if_selected)"
echo "  single-abort margin M-K                = $MARGIN     (distinct exclusions before MD formation fails)"
echo "  escalation headroom M-k_bft            = $HEADROOM     (distinct exclusions a BFT committee survives)"
echo "  wedge threshold M-K+1 (k_use=K)        = $WEDGE_MIN     (distinct exclusions at one height -> no rounds)"
echo "  bft_enabled                            = $BFT_ENABLED"
echo "  bft_escalation_threshold               = $BFT_THRESHOLD"
[ -n "$CFG_SHARDING" ] && \
echo "  sharding_mode (config)                 = $CFG_SHARDING"
echo
for n in "${NOTES[@]:-}"; do
  [ -n "$n" ] && echo "  note: $n"
done
echo "$MESSAGE"
echo "  (see docs/SECURITY.md S-044 — K=2 abort-cascade wedge — and S-045 —"
echo "   BFT escalation unreachable under multi-member abort exclusion)"
exit $RC
