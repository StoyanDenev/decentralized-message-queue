#!/usr/bin/env bash
# OPERATOR-UNREACHABLE-CONTRACT — no security-assurance operator tool may emit a
# SILENT all-clear when it never reached the chain.
#
# THE INVARIANT (a real provable-security property of the read-only operator
# suite, previously enforced by nothing): when the daemon is unreachable, a
# security-assurance audit tool must do exactly one of two things —
#
#   Convention A (fail-closed RPC error): exit NON-ZERO. The operator's
#     scheduled audit visibly errors; it never reads as "audited, all clean."
#
#   Convention B (documented clean SKIP): exit ZERO, but ONLY together with an
#     explicit skip/unreachable marker on stdout/stderr ("... daemon unreachable
#     ... SKIP", "N/A"), so an exit-0 is an HONEST "not applicable, no data",
#     never a silent false-clear.
#
# What NO tool may do is exit 0 with no marker after failing to reach the chain —
# that is a false assurance an operator reads as "nothing wrong." This guard runs
# each curated tool against a KNOWN-DEAD RPC port and asserts its convention.
#
# FALSIFY-ON-MUTANT:
#   * change a Convention-A tool's unreachable guard from `exit 1` to `exit 0`
#     (dropping its marker) -> it becomes a silent false-clear -> this guard RED.
#   * strip a Convention-B tool's SKIP/unreachable marker -> its exit-0 is now
#     silent -> this guard RED.
#
# SCOPE (curated crown-jewels, NOT all 156 operator_*.sh — that would be brittle
# aspirational surface). Every listed tool was verified by direct probe to reach
# its convention via the UNREACHABLE path specifically (not an incidental
# arg-parse / missing-file / missing-jq early exit), and to do so identically
# regardless of whether `jq` is present, so the contract holds on every platform.
#
# DELIBERATELY EXCLUDED (their unreachable behavior is not portably assertable
# by a single --rpc-port probe; documented here so the omission is not silent):
#   operator_fork_watch ............ two-node tool (--node-a/--node-b); no single
#                                    --rpc-port reachability model.
#   operator_anchor_audit .......... audits a LOCAL determ-light anchor cache;
#                                    its live cross-check needs a persisted cache
#                                    fixture, so a fresh box hits the local
#                                    "no cache" path (exit 2), not unreachable.
#   operator_chain_invariants_audit  require `jq`; on a jq-less runner they exit
#   operator_inbound_reconciliation_audit  non-zero on the jq guard BEFORE the
#   operator_receipt_proof_audit ... RPC probe, so their unreachable exit is not
#                                    platform-robustly assertable here. (They DO
#                                    fail-closed when jq is present + daemon down;
#                                    this guard just can't portably prove it.)
#
# FAST + OFFLINE: nothing is ever started on the dead port; every invocation is a
# localhost connection-refused, so the whole guard is sub-second.
# Run from repo root: bash tools/test_operator_unreachable_contract.sh
set -u
cd "$(dirname "$0")/.."
source tools/common.sh

# Operator tools resolve their daemon binary from $DETERM (and common.sh honors
# $DETERM_BIN); export both so a child tool inherits the same build this guard
# resolved, regardless of which one it reads.
export DETERM
export DETERM_BIN="${DETERM_BIN:-$DETERM}"

DEAD_PORT=59087

# ── precondition: the dead port must actually be dead ──────────────────────────
# If something is listening on DEAD_PORT we cannot test the unreachable path;
# SKIP rather than emit a false result.
set +e
"$DETERM" status --rpc-port "$DEAD_PORT" >/dev/null 2>&1
PRECHECK=$?
set -e
if [ "$PRECHECK" = "0" ]; then
  echo "  SKIP: something is listening on port $DEAD_PORT — cannot test unreachable path"
  exit 0
fi

# Convention A: unreachable -> NON-ZERO exit (fail-closed).
CONV_A=(
  operator_supply_check
  operator_slashing_ledger
  operator_committee_audit
  operator_chain_verify
  operator_anon_canonicalization_audit
  operator_block_inclusion_audit
  operator_chain_orphan_check
  operator_escalation_consistency
  operator_chain_health
  operator_subsidy_lottery_audit
)

# Convention B: unreachable -> ZERO exit, but WITH an explicit skip/unreachable
# marker (honest "N/A, no data" — never a silent all-clear).
CONV_B=(
  operator_peer_connectivity_health
  operator_rpc_method_surface
  operator_committee_capture_margin
  operator_block_cadence_regularity
  operator_emission_reconcile
  operator_reorg_resilience
)

MARKER_RE="skip|unreachable|not applicable|N/A|no data|INFO:"

fails=0
checked=0

for t in "${CONV_A[@]}"; do
  f="tools/$t.sh"
  if [ ! -f "$f" ]; then echo "  note: $t missing — skipped"; continue; fi
  checked=$((checked+1))
  set +e
  timeout 30 bash "$f" --rpc-port "$DEAD_PORT" >/dev/null 2>&1
  rc=$?
  set -e
  if [ "$rc" != "0" ]; then
    echo "  ok:   [A] $t fail-closed on unreachable (exit $rc)"
  else
    echo "  FAIL: [A] $t exited 0 on unreachable — SILENT FALSE-CLEAR"
    fails=$((fails+1))
  fi
done

for t in "${CONV_B[@]}"; do
  f="tools/$t.sh"
  if [ ! -f "$f" ]; then echo "  note: $t missing — skipped"; continue; fi
  checked=$((checked+1))
  set +e
  OUT=$(timeout 30 bash "$f" --rpc-port "$DEAD_PORT" 2>&1)
  rc=$?
  set -e
  MARK=$(printf '%s' "$OUT" | grep -ciE "$MARKER_RE" || true)
  if [ "$rc" = "0" ] && [ "$MARK" -ge 1 ]; then
    echo "  ok:   [B] $t clean SKIP on unreachable (exit 0 + marker)"
  elif [ "$rc" != "0" ]; then
    # A Convention-B tool erroring is fail-SAFE (never a false-clear); accept it
    # but note the drift so a convention change is visible.
    echo "  ok:   [B] $t exited $rc on unreachable (fail-safe; was documented exit-0 SKIP)"
  else
    echo "  FAIL: [B] $t exited 0 on unreachable with NO skip marker — SILENT FALSE-CLEAR"
    fails=$((fails+1))
  fi
done

echo "  $((checked - fails)) pass / $fails fail  (of $checked security-assurance tools)"
if [ "$fails" = "0" ] && [ "$checked" -ge 12 ]; then
  echo "  PASS: test_operator_unreachable_contract"
  exit 0
else
  echo "  FAIL: test_operator_unreachable_contract ($fails fail, $checked checked)"
  exit 1
fi
