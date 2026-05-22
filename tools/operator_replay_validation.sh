#!/usr/bin/env bash
# operator_replay_validation.sh — Replay-time state-divergence diagnostic.
#
# Validates that the reference daemon's per-block state commitments
# (state_root, head_hash, supply counters) are internally consistent
# and that a snapshot-restore round-trip recomputes byte-identical
# state. Catches three classes of bug:
#
#   1. Apply-path non-determinism — if Chain::apply_block depends on
#      anything outside the canonical block input (system time, map
#      iteration order, uninitialized memory), the snapshot restore
#      pipeline (which re-walks the tail headers via apply_block) will
#      compute a different state_root than the producer originally
#      stored. This script's PRIMARY catch.
#   2. state_root computation drift — if compute_state_root changes
#      between commits without a network-wide upgrade, the snapshot's
#      recomputed root won't match the head block's stored state_root.
#   3. RPC read-path drift — block-info called twice for the same height
#      MUST return identical values. Any divergence here points at a
#      stale cache, mutable shared state, or a producer that's still
#      reorging committed blocks (FA1 violation).
#
# Approach used (the actual "replay" mechanism):
#
#   Hybrid C-lite — combines a snapshot-restore round-trip with
#   per-block field consistency probing on the reference daemon. We
#   don't bootstrap a fresh determ daemon mid-script (Approach A would
#   be the only true "replay from zero" but is hundreds of LOC of
#   orchestration). Instead:
#
#   * snapshot create → snapshot inspect — the inspect pipeline calls
#     Chain::restore_from_snapshot which exercises the SAME apply_block
#     code path the producer ran, recomputes state_root via the SAME
#     compute_state_root function, then verifies it byte-matches the
#     head block's stored state_root. This IS replay-determinism
#     validation — the apply layer literally runs again on tail headers
#     during restore (see Chain::restore_from_snapshot, S-033 / S-038
#     state_root gate).
#   * Per-block field probes — for every block in [from..to] (or every
#     Nth in stride mode), call `block-info --field state_root` and
#     `block-info --field block_hash`. Then call them AGAIN and verify
#     identical values. This is the consistency-pass guard against
#     RPC-layer non-determinism.
#   * Genesis pin — `determ chain-id` returns the genesis block's hash.
#     Probed twice (must agree) AND cross-checked against the snapshot's
#     embedded block-0 head_hash.
#   * Supply counters — `determ supply --json` probed twice (must agree)
#     AND cross-checked against the snapshot's serialized counter set.
#
# A real "replay from genesis" would require running a fresh determ
# init + start with a separate data-dir, syncing the same genesis, and
# feeding it the reference daemon's block stream — out of scope for a
# ~300 LOC operator script. The snapshot-restore round-trip catches
# the same class of bug because Chain::restore_from_snapshot exercises
# apply_block on every tail header it restores, with the state_root
# gate at the end (S-033 / S-038). The script's exit code 2 fires when
# any of the above divergences is detected.
#
# Read-only RPC; safe against any running daemon. Daemon must already
# be listening on --rpc-port.
#
# Usage:
#   tools/operator_replay_validation.sh --rpc-port N
#                                       [--from H] [--to H]
#                                       [--genesis-only]
#                                       [--stride N]
#                                       [--json] [--anomalies-only]
#
# Exit codes:
#   0 — no divergence detected (chain replays cleanly)
#   1 — RPC error / args error / malformed response
#   2 — divergence detected (operator alert gate) — state_root /
#       block_hash / genesis / supply mismatch
set -u

usage() {
  cat <<'EOF'
Usage: operator_replay_validation.sh --rpc-port N
                                     [--from H] [--to H]
                                     [--genesis-only]
                                     [--stride N]
                                     [--json] [--anomalies-only]

Replay-time state-divergence diagnostic. Verifies the reference
daemon's per-block state commitments are internally consistent and
that a snapshot-restore round-trip recomputes byte-identical state.

Required:
  --rpc-port N        Reference daemon RPC port to compare against

Options:
  --from H            Start replay at block height H (default: 0)
  --to H              Stop at height H (default: chain head height)
  --genesis-only      Skip the per-block walk; only verify the chain's
                      genesis hash is internally consistent (chain-id
                      probed twice, plus snapshot block-0 head_hash).
                      Fast smoke check (~2 RPCs).
  --stride N          Probe every Nth block instead of every block.
                      Default 100 for large ranges, 1 for ranges <= 100
                      blocks. Use --stride 1 to force every-block check.
  --json              Emit single-line JSON envelope (see below)
  --anomalies-only    Suppress per-block "OK" lines; only print
                      divergences + summary. Default still emits a
                      progress digest every stride blocks.
  -h, --help          Show this help

Exit codes:
  0   no divergence
  1   RPC error / args error / malformed response
  2   divergence detected

JSON envelope (--json):
  {"rpc_port":N,
   "from":H,
   "to":H,
   "blocks_checked":N,
   "stride":N,
   "genesis_hash":"<hex>",
   "snapshot": {
     "block_index":N, "head_hash":"<hex>", "state_root":"<hex>",
     "size_bytes":N
   } | null,
   "divergences":[
     {"height":H, "field":"state_root|block_hash|...",
      "reference":"...", "replayed":"..."},
     ...
   ],
   "anomalies":[
     "state_root_divergence" | "block_hash_divergence" |
     "supply_counter_divergence" | "genesis_hash_divergence",
     ...
   ],
   "summary":{
     "state_root_checks":N, "block_hash_checks":N,
     "supply_probes":N, "genesis_probes":N
   }}

Examples:
  # Full chain validation, every 100th block, default stride.
  tools/operator_replay_validation.sh --rpc-port 7778

  # Force every-block check on a short suspect range.
  tools/operator_replay_validation.sh --rpc-port 7778 \
      --from 5000 --to 5100 --stride 1

  # Fast smoke test — just verify genesis pin.
  tools/operator_replay_validation.sh --rpc-port 7778 --genesis-only
EOF
}

PORT=""
FROM=""
TO=""
STRIDE=""
GENESIS_ONLY=0
JSON_OUT=0
ANOM_ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)         usage; exit 0 ;;
    --rpc-port)        PORT="$2";   shift 2 ;;
    --from)            FROM="$2";   shift 2 ;;
    --to)              TO="$2";     shift 2 ;;
    --stride)          STRIDE="$2"; shift 2 ;;
    --genesis-only)    GENESIS_ONLY=1; shift ;;
    --json)            JSON_OUT=1;  shift ;;
    --anomalies-only)  ANOM_ONLY=1; shift ;;
    *) echo "operator_replay_validation: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$PORT" ]; then
  echo "operator_replay_validation: --rpc-port N is required" >&2
  usage >&2
  exit 1
fi
case "$PORT" in *[!0-9]*|"")
  echo "operator_replay_validation: --rpc-port must be a positive integer (got '$PORT')" >&2
  exit 1 ;;
esac
for V in "$FROM" "$TO" "$STRIDE"; do
  if [ -n "$V" ]; then
    case "$V" in *[!0-9]*)
      echo "operator_replay_validation: --from/--to/--stride must be non-negative integers (got '$V')" >&2
      exit 1 ;;
    esac
  fi
done

cd "$(dirname "$0")/.."
source tools/common.sh

HAVE_JQ=0
command -v jq >/dev/null 2>&1 && HAVE_JQ=1

# Minimal JSON scrapers — match the operator_*.sh family pattern.
extract_str() {
  # extract_str <json> <key>
  if [ "$HAVE_JQ" = "1" ]; then
    printf '%s' "$1" | jq -r ".${2} // \"\""
  else
    printf '%s' "$1" | grep -o "\"${2}\":\"[^\"]*\"" | head -1 | sed 's/.*: *//; s/"//g'
  fi
}
extract_num() {
  # extract_num <json> <key>
  if [ "$HAVE_JQ" = "1" ]; then
    printf '%s' "$1" | jq -r ".${2} // 0"
  else
    printf '%s' "$1" | grep -o "\"${2}\":[^,}]*" | head -1 | sed 's/.*: *//; s/[",]//g; s/^ *//; s/ *$//'
  fi
}

# ── Probe 1: chain head + tip resolution. ────────────────────────────────────
HEAD_OUT=$("$DETERM" head --json --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_replay_validation: RPC error (is daemon running on port $PORT?)" >&2
  exit 1
}
HEAD_HEIGHT=$(extract_num "$HEAD_OUT" height)
DAEMON_HEAD_HASH=$(extract_str "$HEAD_OUT" head_hash)
case "$HEAD_HEIGHT" in *[!0-9]*|"")
  echo "operator_replay_validation: head height not numeric (got '$HEAD_HEIGHT')" >&2
  exit 1 ;;
esac
if [ "$HEAD_HEIGHT" = "0" ]; then
  echo "operator_replay_validation: chain empty (height=0); nothing to validate" >&2
  exit 1
fi
TIP=$(( HEAD_HEIGHT - 1 ))

# Resolve window. Default [0..TIP].
if [ -z "$FROM" ]; then FROM=0; fi
if [ -z "$TO" ];   then TO=$TIP; fi
if [ "$FROM" -gt "$TO" ]; then
  echo "operator_replay_validation: invalid window: --from $FROM > --to $TO" >&2
  exit 1
fi
if [ "$TO" -gt "$TIP" ]; then
  echo "operator_replay_validation: --to $TO exceeds chain tip $TIP (height=$HEAD_HEIGHT)" >&2
  exit 1
fi

# Default stride: 100 for ranges > 100 blocks, 1 otherwise.
WINDOW_LEN=$(( TO - FROM + 1 ))
if [ -z "$STRIDE" ]; then
  if [ "$WINDOW_LEN" -gt 100 ]; then STRIDE=100; else STRIDE=1; fi
fi
if [ "$STRIDE" -le 0 ]; then
  echo "operator_replay_validation: --stride must be > 0 (got $STRIDE)" >&2
  exit 1
fi

# ── Probe 2: genesis pin (chain-id RPC, twice — must agree). ─────────────────
GEN_A=$("$DETERM" chain-id --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_replay_validation: RPC error (chain-id, port $PORT)" >&2
  exit 1
}
GEN_A=$(printf '%s' "$GEN_A" | tr -d '[:space:]')
GEN_B=$("$DETERM" chain-id --rpc-port "$PORT" 2>/dev/null) || {
  echo "operator_replay_validation: RPC error on second chain-id probe" >&2
  exit 1
}
GEN_B=$(printf '%s' "$GEN_B" | tr -d '[:space:]')

DIVERGENCES_FILE=$(mktemp 2>/dev/null) || { echo "operator_replay_validation: cannot create tmp file" >&2; exit 1; }
ANOMALIES_FILE=$(mktemp 2>/dev/null) || { echo "operator_replay_validation: cannot create tmp file" >&2; exit 1; }
TMPDIR=$(mktemp -d 2>/dev/null)      || { echo "operator_replay_validation: cannot create tmp dir" >&2; exit 1; }
trap 'rm -rf "$TMPDIR" "$DIVERGENCES_FILE" "$ANOMALIES_FILE"' EXIT

push_divergence() {
  # push_divergence <height> <field> <reference> <replayed>
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$DIVERGENCES_FILE"
}
push_anomaly() {
  printf '%s\n' "$1" >> "$ANOMALIES_FILE"
}
has_anomaly() {
  grep -Fxq "$1" "$ANOMALIES_FILE" 2>/dev/null
}

GENESIS_PROBES=2
if [ "$GEN_A" != "$GEN_B" ]; then
  push_divergence 0 "genesis_hash" "$GEN_A" "$GEN_B"
  push_anomaly "genesis_hash_divergence"
fi

# ── Probe 3: snapshot create + inspect (the real replay round-trip). ─────────
# snapshot create dumps current state to JSON via Chain::serialize_state;
# snapshot inspect calls Chain::restore_from_snapshot which re-walks tail
# headers via apply_block AND recomputes state_root, gating on the
# embedded head block's stored value (S-033 / S-038). A failure here is
# the canonical "apply path is non-deterministic" signal.
SNAPSHOT_PATH=""
SNAP_INDEX=""
SNAP_HEAD=""
SNAP_ROOT=""
SNAP_SIZE=""
SNAP_GEN_TOTAL=""
SNAP_ACC_SUB=""
SNAP_ACC_IN=""
SNAP_ACC_OUT=""
SNAP_ACC_SLASH=""

if [ "$GENESIS_ONLY" = "0" ]; then
  SNAPSHOT_PATH="$TMPDIR/replay_validation_snapshot.json"
  CREATE_OUT=$("$DETERM" snapshot create --out "$SNAPSHOT_PATH" --rpc-port "$PORT" 2>&1)
  CREATE_RC=$?
  if [ "$CREATE_RC" -ne 0 ]; then
    echo "operator_replay_validation: snapshot create failed (rc=$CREATE_RC, port=$PORT)" >&2
    echo "$CREATE_OUT" >&2
    exit 1
  fi
  if [ ! -f "$SNAPSHOT_PATH" ]; then
    echo "operator_replay_validation: snapshot create returned 0 but file missing: $SNAPSHOT_PATH" >&2
    exit 1
  fi

  INSPECT_OUT=$("$DETERM" snapshot inspect --in "$SNAPSHOT_PATH" --json 2>&1)
  INSPECT_RC=$?
  if [ "$INSPECT_RC" -ne 0 ]; then
    # The S-033 / S-038 state_root gate fires inside restore_from_snapshot.
    # A non-zero rc here IS the catastrophic signal — replay computed a
    # state_root that disagrees with the producer's stored value.
    echo "operator_replay_validation: snapshot inspect REJECTED snapshot (rc=$INSPECT_RC) — replay-time state_root divergence" >&2
    echo "$INSPECT_OUT" >&2
    push_divergence "$TIP" "state_root" "$DAEMON_HEAD_HASH (head)" "snapshot restore failed"
    push_anomaly "state_root_divergence"
  else
    SNAP_INDEX=$(extract_num "$INSPECT_OUT" block_index)
    SNAP_HEAD=$(extract_str  "$INSPECT_OUT" head_hash)
    SNAP_ROOT=$(extract_str  "$INSPECT_OUT" state_root)
    if [ -f "$SNAPSHOT_PATH" ]; then
      SNAP_SIZE=$(wc -c < "$SNAPSHOT_PATH" 2>/dev/null | tr -d '[:space:]')
    fi

    # The snapshot's restored head MUST match the daemon's reported head.
    # (The snapshot was created from the same daemon a fraction of a
    # second ago — if the heights drifted, the daemon advanced; that's
    # allowed, but the snapshot's head_hash must STILL match the
    # corresponding block-info on the reference daemon at the snapshot's
    # block_index.)
    if [ -n "$SNAP_HEAD" ] && [ -n "$SNAP_INDEX" ]; then
      REF_HEAD=$("$DETERM" block-info "$SNAP_INDEX" --field block_hash --rpc-port "$PORT" 2>/dev/null | tr -d '[:space:]')
      if [ -n "$REF_HEAD" ] && [ "$REF_HEAD" != "$SNAP_HEAD" ]; then
        push_divergence "$SNAP_INDEX" "block_hash" "$REF_HEAD" "$SNAP_HEAD"
        push_anomaly "block_hash_divergence"
      fi
      REF_ROOT=$("$DETERM" block-info "$SNAP_INDEX" --field state_root --rpc-port "$PORT" 2>/dev/null | tr -d '[:space:]')
      # Treat unset / "0" state_root on the reference as "no replay
      # comparison possible at this height" rather than divergence —
      # very-early-chain headers can ship with state_root unbound when
      # serialize_state skipped it for backward compat. We still verify
      # equality when both sides report a non-empty value.
      if [ -n "$REF_ROOT" ] && [ -n "$SNAP_ROOT" ] && [ "$REF_ROOT" != "$SNAP_ROOT" ]; then
        push_divergence "$SNAP_INDEX" "state_root" "$REF_ROOT" "$SNAP_ROOT"
        push_anomaly "state_root_divergence"
      fi
    fi

    # Pull A1 counters from the raw snapshot JSON (top-level scalars per
    # Chain::serialize_state).
    if [ "$HAVE_JQ" = "1" ]; then
      SNAP_GEN_TOTAL=$(jq -r '.genesis_total       // 0' "$SNAPSHOT_PATH")
      SNAP_ACC_SUB=$(jq -r   '.accumulated_subsidy  // 0' "$SNAPSHOT_PATH")
      SNAP_ACC_IN=$(jq -r    '.accumulated_inbound  // 0' "$SNAPSHOT_PATH")
      SNAP_ACC_OUT=$(jq -r   '.accumulated_outbound // 0' "$SNAPSHOT_PATH")
      SNAP_ACC_SLASH=$(jq -r '.accumulated_slashed  // 0' "$SNAPSHOT_PATH")
    fi
  fi
fi

# Genesis cross-check vs snapshot block-0.
if [ "$GENESIS_ONLY" = "0" ] && [ -n "$GEN_A" ]; then
  # Pull block-0 hash via block-info on the reference daemon. (It's the
  # genesis block; its compute_hash IS the chain-id.)
  REF_BLOCK0=$("$DETERM" block-info 0 --field block_hash --rpc-port "$PORT" 2>/dev/null | tr -d '[:space:]')
  if [ -n "$REF_BLOCK0" ] && [ "$REF_BLOCK0" != "$GEN_A" ]; then
    push_divergence 0 "genesis_hash" "$GEN_A" "$REF_BLOCK0"
    has_anomaly "genesis_hash_divergence" || push_anomaly "genesis_hash_divergence"
  fi
fi

# ── Probe 4: supply counters probed twice + cross-check vs snapshot. ─────────
# The four A1 counters (accumulated_subsidy/inbound/outbound/slashed) and
# genesis_total are MONOTONIC NON-DECREASING — once apply_block credits
# any of them, they never roll back. Two back-to-back probes can legitimately
# see different values if a block was finalized between the RPCs (subsidy
# block credits accumulated_subsidy + balance). So the rule is: counter
# probe B must be >= probe A. A DECREASE between back-to-back probes is
# the real divergence signal — a counter rolling back means apply-path
# corruption or a reorg of a finalized block (FA1 violation).
SUPPLY_PROBES=0
if [ "$GENESIS_ONLY" = "0" ]; then
  SUP_A=$("$DETERM" supply --json --rpc-port "$PORT" 2>/dev/null) ; SUP_A_RC=$?
  SUP_B=$("$DETERM" supply --json --rpc-port "$PORT" 2>/dev/null) ; SUP_B_RC=$?
  # `determ supply` exits 2 on A1 violation but still emits the JSON;
  # treat 0 and 2 as "valid output, parse it".
  if { [ "$SUP_A_RC" = "0" ] || [ "$SUP_A_RC" = "2" ]; } && \
     { [ "$SUP_B_RC" = "0" ] || [ "$SUP_B_RC" = "2" ]; }; then
    SUPPLY_PROBES=2
    for f in accumulated_subsidy accumulated_inbound accumulated_outbound accumulated_slashed genesis_total; do
      VA=$(extract_num "$SUP_A" "$f")
      VB=$(extract_num "$SUP_B" "$f")
      # Monotonicity check: counter B must be >= counter A. A decrease
      # signals real apply-path corruption (counter rollback on a
      # finalized block — fundamental safety violation per FA1).
      if [ -n "$VA" ] && [ -n "$VB" ]; then
        case "$VA$VB" in
          *[!0-9]*) ;;  # non-numeric, skip
          *)
            if [ "$VB" -lt "$VA" ]; then
              push_divergence "$TIP" "supply.$f" "$VA" "$VB"
              has_anomaly "supply_counter_divergence" || push_anomaly "supply_counter_divergence"
            fi ;;
        esac
      fi
    done

    # Cross-check against snapshot's serialized counters. The snapshot
    # was taken at SNAP_INDEX (which may be > the daemon's reported
    # head at the very first HEAD probe, if a block landed between
    # then and the snapshot pass). The daemon's CURRENT counters must
    # be >= snapshot's counters (snapshot is a strict prefix in time).
    # A snapshot counter ABOVE the live daemon's is the divergence —
    # snapshot was taken from a state the daemon has since rolled back.
    if [ -n "$SNAP_INDEX" ] && [ -n "$SNAP_GEN_TOTAL" ]; then
      for kv in "accumulated_subsidy:$SNAP_ACC_SUB" \
                "accumulated_inbound:$SNAP_ACC_IN" \
                "accumulated_outbound:$SNAP_ACC_OUT" \
                "accumulated_slashed:$SNAP_ACC_SLASH"; do
        f=${kv%%:*}
        sv=${kv#*:}
        dv=$(extract_num "$SUP_B" "$f")
        if [ -n "$sv" ] && [ -n "$dv" ]; then
          case "$sv$dv" in
            *[!0-9]*) ;;
            *)
              if [ "$sv" -gt "$dv" ]; then
                push_divergence "$SNAP_INDEX" "supply.$f" "$dv" "$sv"
                has_anomaly "supply_counter_divergence" || push_anomaly "supply_counter_divergence"
              fi ;;
          esac
        fi
      done
      # genesis_total is fixed by the genesis config — it must MATCH
      # exactly between snapshot and live daemon (not just be >=).
      sv="$SNAP_GEN_TOTAL"
      dv=$(extract_num "$SUP_B" genesis_total)
      if [ -n "$sv" ] && [ -n "$dv" ]; then
        case "$sv$dv" in
          *[!0-9]*) ;;
          *)
            if [ "$sv" != "$dv" ]; then
              push_divergence "$SNAP_INDEX" "supply.genesis_total" "$dv" "$sv"
              has_anomaly "supply_counter_divergence" || push_anomaly "supply_counter_divergence"
            fi ;;
        esac
      fi
    fi
  fi
fi

# ── Probe 5: per-block state_root + block_hash consistency walk. ─────────────
BLOCKS_CHECKED=0
STATE_ROOT_CHECKS=0
BLOCK_HASH_CHECKS=0

emit_progress() {
  [ "$JSON_OUT" = "1" ] && return 0
  if [ "$ANOM_ONLY" = "1" ]; then return 0; fi
  printf '%s\n' "$1"
}

if [ "$GENESIS_ONLY" = "0" ]; then
  H=$FROM
  while [ "$H" -le "$TO" ]; do
    # Two probes for state_root: must agree.
    SR_A=$("$DETERM" block-info "$H" --field state_root --rpc-port "$PORT" 2>/dev/null | tr -d '[:space:]')
    SR_RC=$?
    if [ "$SR_RC" -ne 0 ]; then
      echo "operator_replay_validation: RPC error fetching block-info $H state_root (port $PORT)" >&2
      exit 1
    fi
    SR_B=$("$DETERM" block-info "$H" --field state_root --rpc-port "$PORT" 2>/dev/null | tr -d '[:space:]')
    STATE_ROOT_CHECKS=$(( STATE_ROOT_CHECKS + 2 ))
    if [ "$SR_A" != "$SR_B" ]; then
      push_divergence "$H" "state_root" "$SR_A" "$SR_B"
      has_anomaly "state_root_divergence" || push_anomaly "state_root_divergence"
    fi

    # Two probes for block_hash: must agree.
    BH_A=$("$DETERM" block-info "$H" --field block_hash --rpc-port "$PORT" 2>/dev/null | tr -d '[:space:]')
    BH_B=$("$DETERM" block-info "$H" --field block_hash --rpc-port "$PORT" 2>/dev/null | tr -d '[:space:]')
    BLOCK_HASH_CHECKS=$(( BLOCK_HASH_CHECKS + 2 ))
    if [ "$BH_A" != "$BH_B" ]; then
      push_divergence "$H" "block_hash" "$BH_A" "$BH_B"
      has_anomaly "block_hash_divergence" || push_anomaly "block_hash_divergence"
    fi

    BLOCKS_CHECKED=$(( BLOCKS_CHECKED + 1 ))

    # Progress line every stride blocks (or every block when stride=1).
    if [ "$ANOM_ONLY" = "0" ] && [ "$JSON_OUT" = "0" ]; then
      # Cap chatter — only print every Nth block where N is stride OR
      # 100 (whichever is larger), so stride=1 doesn't spam thousands of
      # lines on a long chain.
      CHATTER=$STRIDE
      if [ "$CHATTER" -lt 100 ]; then CHATTER=100; fi
      if [ "$(( H % CHATTER ))" = "0" ] || [ "$H" = "$TO" ]; then
        printf 'block %s: state_root=%.16s... block_hash=%.16s... [OK]\n' "$H" "$SR_A" "$BH_A"
      fi
    fi

    H=$(( H + STRIDE ))
  done
fi

# ── Summary + emit ───────────────────────────────────────────────────────────
DIV_COUNT=0
if [ -s "$DIVERGENCES_FILE" ]; then
  DIV_COUNT=$(wc -l < "$DIVERGENCES_FILE" | tr -d '[:space:]')
fi
ANOM_COUNT=0
if [ -s "$ANOMALIES_FILE" ]; then
  # Dedup anomalies.
  sort -u "$ANOMALIES_FILE" > "$ANOMALIES_FILE.dedup"
  mv "$ANOMALIES_FILE.dedup" "$ANOMALIES_FILE"
  ANOM_COUNT=$(wc -l < "$ANOMALIES_FILE" | tr -d '[:space:]')
fi
RC=0
[ "$ANOM_COUNT" -gt 0 ] && RC=2

if [ "$JSON_OUT" = "1" ]; then
  # Build divergences JSON array.
  DIV_JSON="[]"
  if [ -s "$DIVERGENCES_FILE" ]; then
    # python is the only portable way to escape arbitrary content into
    # JSON strings without jq.
    if command -v python3 >/dev/null 2>&1; then
      DIV_JSON=$(python3 - "$DIVERGENCES_FILE" <<'PY'
import json, sys
rows = []
with open(sys.argv[1]) as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t", 3)
        if len(parts) < 4:
            continue
        rows.append({
            "height":    int(parts[0]) if parts[0].lstrip("-").isdigit() else parts[0],
            "field":     parts[1],
            "reference": parts[2],
            "replayed":  parts[3],
        })
print(json.dumps(rows, separators=(",", ":")))
PY
)
    elif command -v python >/dev/null 2>&1; then
      DIV_JSON=$(python - "$DIVERGENCES_FILE" <<'PY'
import json, sys
rows = []
with open(sys.argv[1]) as f:
    for line in f:
        line = line.rstrip("\n")
        if not line:
            continue
        parts = line.split("\t", 3)
        if len(parts) < 4:
            continue
        rows.append({
            "height":    int(parts[0]) if parts[0].lstrip("-").isdigit() else parts[0],
            "field":     parts[1],
            "reference": parts[2],
            "replayed":  parts[3],
        })
print(json.dumps(rows, separators=(",", ":")))
PY
)
    else
      # Hand-rolled fallback (assumes no quotes / control chars in the
      # field/value pairs — they're hashes + integers + RPC-safe names).
      DIV_JSON="["
      first=1
      while IFS=$'\t' read -r h f r p; do
        [ -z "$h" ] && continue
        if [ "$first" = "1" ]; then first=0; else DIV_JSON="$DIV_JSON,"; fi
        DIV_JSON="$DIV_JSON{\"height\":$h,\"field\":\"$f\",\"reference\":\"$r\",\"replayed\":\"$p\"}"
      done < "$DIVERGENCES_FILE"
      DIV_JSON="$DIV_JSON]"
    fi
  fi

  ANOM_JSON="[]"
  if [ "$ANOM_COUNT" -gt 0 ]; then
    ANOM_JSON="["
    first=1
    while IFS= read -r a; do
      [ -z "$a" ] && continue
      if [ "$first" = "1" ]; then first=0; else ANOM_JSON="$ANOM_JSON,"; fi
      ANOM_JSON="$ANOM_JSON\"$a\""
    done < "$ANOMALIES_FILE"
    ANOM_JSON="$ANOM_JSON]"
  fi

  if [ "$GENESIS_ONLY" = "1" ] || [ -z "$SNAP_INDEX" ]; then
    SNAP_JSON="null"
  else
    SNAP_JSON=$(printf '{"block_index":%s,"head_hash":"%s","state_root":"%s","size_bytes":%s}' \
                "${SNAP_INDEX:-0}" "${SNAP_HEAD:-}" "${SNAP_ROOT:-}" "${SNAP_SIZE:-0}")
  fi
  cat <<EOF
{"rpc_port":$PORT,"from":$FROM,"to":$TO,"blocks_checked":$BLOCKS_CHECKED,"stride":$STRIDE,"genesis_hash":"$GEN_A","snapshot":$SNAP_JSON,"divergences":$DIV_JSON,"anomalies":$ANOM_JSON,"summary":{"state_root_checks":$STATE_ROOT_CHECKS,"block_hash_checks":$BLOCK_HASH_CHECKS,"supply_probes":$SUPPLY_PROBES,"genesis_probes":$GENESIS_PROBES}}
EOF
  exit $RC
fi

# Human render.
echo ""
echo "=== Replay validation (port $PORT) ==="
if [ "$GENESIS_ONLY" = "1" ]; then
  echo "Mode: genesis-only"
else
  echo "Window: [$FROM..$TO]  ($WINDOW_LEN blocks, stride $STRIDE => $BLOCKS_CHECKED checked)"
fi
echo "Genesis hash: ${GEN_A:0:24}... (probed $GENESIS_PROBES times)"
if [ -n "$SNAP_INDEX" ]; then
  echo "Snapshot round-trip:"
  echo "  block_index: $SNAP_INDEX"
  echo "  head_hash:   ${SNAP_HEAD:0:24}..."
  echo "  state_root:  ${SNAP_ROOT:0:24}..."
  if [ -n "$SNAP_SIZE" ]; then
    echo "  size_bytes:  $SNAP_SIZE"
  fi
fi
echo "Counts: state_root_checks=$STATE_ROOT_CHECKS  block_hash_checks=$BLOCK_HASH_CHECKS  supply_probes=$SUPPLY_PROBES"

if [ "$DIV_COUNT" -gt 0 ]; then
  echo ""
  echo "Divergences ($DIV_COUNT):"
  while IFS=$'\t' read -r h f r p; do
    [ -z "$h" ] && continue
    echo "  [!] block $h field=$f reference=$r replayed=$p"
  done < "$DIVERGENCES_FILE"
fi

if [ "$ANOM_COUNT" -gt 0 ]; then
  echo ""
  echo "Anomalies ($ANOM_COUNT):"
  while IFS= read -r a; do
    [ -z "$a" ] && continue
    echo "  [X] $a"
  done < "$ANOMALIES_FILE"
fi

echo ""
if [ "$RC" = "0" ]; then
  echo "[OK] No replay-time divergence detected."
else
  echo "[X]  Replay-time divergence detected — see anomalies above."
fi
exit $RC
