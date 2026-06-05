#!/usr/bin/env bash
# S-035 Path 3 follow-on: run the full regression suite + summarize.
#
# Iterates every tools/test_*.sh script, captures PASS / FAIL per
# test, and prints a summary table at the end. Exits non-zero if any
# test failed.
#
# Each test is run independently (a failure in one doesn't stop the
# suite) so an operator gets the full failure picture in one run
# rather than having to fix-and-retry one-at-a-time.
#
# Output format:
#
#   === tools/test_NAME.sh ===
#   [test stdout/stderr]
#   ...
#
#   ──────────────────────────────────────────────
#   PASS: N tests
#   FAIL: M tests
#   ──────────────────────────────────────────────
#   Failed tests:
#     - tools/test_FAILED1.sh
#     - tools/test_FAILED2.sh
#
# Per-test outcome detection: the script grep's the last 10 lines of
# each test's output for a "PASS:" or "FAIL:" line. Every existing
# test follows the convention of a final-line PASS / FAIL marker, so
# this is robust to test-specific output noise above it.
#
# Run from repo root: bash tools/run_all.sh
#
# Override hooks (passed through to each test via tools/common.sh):
#   DETERM_BIN=/path/to/determ         # custom chain-daemon binary
#   DETERM_WALLET_BIN=/path/to/wallet  # custom wallet binary
#
# Environment knobs:
#   SKIP_PATTERN='regex'  Skip tests whose path matches this regex
#                         (useful for skipping known-flaky tests on
#                         specific platforms).
#   ONLY_PATTERN='regex'  Only run tests whose path matches.
#   QUIET=1               Suppress per-test stdout; only print
#                         summary at the end.
#   FAST=1                Run ONLY the deterministic in-process tests
#                         (no multi-node clusters, no network). These
#                         are the `determ test-*` subcommand wrappers:
#                         atomic_scope, composable_batch, dapp_register,
#                         dapp_call, s018_json_validation, merkle,
#                         committee_selection, abort_reselection,
#                         shard_routing, ed25519,
#                         sha256, anon_address, genesis_message,
#                         state_root_unit, block_rand, rate_limiter,
#                         block_digest, block_hash, binary_codec,
#                         wire_types, transaction, merge_event_codec,
#                         consensus_msgs, tx_root, genesis, envelope,
#                         resolve_fork, shamir, random_state,
#                         snapshot_defense, encoding, chain_helpers,
#                         json_validate, block_roundtrip,
#                         config_roundtrip, tx_binary_codec,
#                         chain_append, state_types, validator_config,
#                         timing_profiles, params_constants,
#                         supply_invariant, enum_values,
#                         block_accessors, make_block_sig,
#                         domain_separation, tx_signing_bytes,
#                         merge_event_bytes, frost_types,
#                         make_contrib_commitment_distinct,
#                         state_proof_value_hash. Each runs in <5s with no
#                         flakes. Useful for quick iteration during
#                         development.

set -u
cd "$(dirname "$0")/.."

# Daemon hygiene: reap any stray determ-family daemons before the suite.
# Cluster tests boot determ.exe nodes; their per-PID kill traps are
# unreliable on Windows/Git-Bash (wrong PID captured, trap skipped on
# timeout/interrupt), so leaked nodes can accumulate across runs, peg the
# CPU, and lock build-output binaries. Reaping by image name gives a clean
# slate. No-op if none are running; never fails the suite. Opt out with
# REAP_DAEMONS=0 (e.g. if you intentionally run a daemon alongside the suite).
if [ "${REAP_DAEMONS:-1}" = "1" ]; then
    bash "$(dirname "$0")/reap_daemons.sh" 2>/dev/null || true
fi

# Verify binaries are findable before iterating (saves running 49
# tests just to see them all fail on the same missing binary).
source tools/common.sh
echo "Using DETERM=$DETERM"
echo "Using DETERM_WALLET=${DETERM_WALLET:-<none>}"
echo "Using PROJECT_ROOT=$PROJECT_ROOT"
echo

PASS_COUNT=0
FAIL_COUNT=0
FAILED_TESTS=()
START_TIME=$(date +%s)

SKIP_PATTERN="${SKIP_PATTERN:-}"
ONLY_PATTERN="${ONLY_PATTERN:-}"

# FAST=1 short-circuits to the deterministic in-process subset.
# These are wrappers around `determ test-*` subcommands — no network,
# no clusters, <5s each, no flakes. Useful for dev iteration.
if [ "${FAST:-0}" = "1" ]; then
    ONLY_PATTERN='test_(atomic_scope|composable_batch|dapp_register|dapp_call|s018_json_validation|merkle|committee_selection|abort_reselection|shard_routing|ed25519|sha256|anon_address|genesis_message|state_root_unit|block_rand|rate_limiter|block_digest|block_hash|binary_codec|wire_types|transaction|merge_event_codec|merge_event_bytes|consensus_msgs|tx_root|genesis|envelope|resolve_fork|shamir|random_state|snapshot_defense|encoding|chain_helpers|json_validate|block_roundtrip|config_roundtrip|tx_binary_codec|chain_append|state_types|validator_config|timing_profiles|params_constants|supply_invariant|enum_values|block_accessors|make_block_sig|domain_separation|tx_signing_bytes|make_genesis_block|pending_param_changes|merge_state|chain_apply_block|snapshot_roundtrip|state_proof_unit|abort_event_apply|equivocation_apply|unstake_deregister_apply|cross_shard_receipt_apply|param_change_apply|pending_param_change_determinism|subsidy_distribution|merge_event_apply|cross_shard_outbound_apply|supply_lifecycle|supply_invariant_fuzz|dapp_state_transition|dapp_registry_determinism|governance_param_determinism|overflow_paths|state_root_namespaces|multi_tx_block|state_proof_namespaces|state_proof_composite_key|state_proof_value_hash|applied_receipt_restore|applied_receipt_snapshot|stake_accounting|fee_distribution_edge|fee_edge_cases|equivocation_multi|cross_shard_multi_receipt|multi_block_chain|tx_edge_cases|snapshot_then_apply|genesis_with_region|anon_routing|merge_event_apply_edge|block_event_composition|nef_pool_drain|tx_payload_bounds|empty_block_apply|account_create_on_credit|randomized_delay|block_timestamp|node_registry|tx_replay_protection|chain_save_load|block_validator_basic|genesis_sharded|cross_shard_atomicity|cross_shard_supply_invariant|chain_ctor_bootstrap|snapshot_version_rejection|config_defaults|required_block_sigs|config_load_save|block_from_json_minimal|config_permissive|chain_shard_routing_config|view_root|frost_types|make_contrib_commitment_distinct|rate_limiter_bucket|merkle_proof_tampering|merkle_tree_balanced|protocol_version_pinning|binary_codec_roundtrip_exhaustive|time_monotonicity|chain_prev_hash_link|block_validator_extensive|state_root_determinism|tx_signing_determinism|merge_event_determinism|merge_state_determinism|snapshot_full_determinism|block_rand_distribution|config_determinism|hello_handshake_determinism|genesis_determinism|shard_routing_determinism|anon_address_derivation|config_knob_completeness|empty_genesis_edge|wallet_tx_batch_sign|wallet_account_import_many|wallet_keyfile_reencrypt|wallet_verify_batch|wallet_batch_nonce_assign|wallet_tx_batch_summary)\.sh$'
    echo "FAST=1 mode: ONLY_PATTERN set to in-process tests only"
    echo
fi

for t in tools/test_*.sh; do
    # Filtering knobs.
    if [ -n "$ONLY_PATTERN" ] && [[ ! "$t" =~ $ONLY_PATTERN ]]; then
        continue
    fi
    if [ -n "$SKIP_PATTERN" ] && [[ "$t" =~ $SKIP_PATTERN ]]; then
        echo "=== SKIP: $t (matched SKIP_PATTERN) ==="
        continue
    fi

    echo "=== $t ==="
    if [ "${QUIET:-0}" = "1" ]; then
        OUT=$(bash "$t" 2>&1)
    else
        OUT=$(bash "$t" 2>&1 | tee /dev/stderr)
    fi

    # Outcome detection: look at the final 10 lines for a clear
    # PASS / FAIL marker. Tests use either:
    #   "  PASS: <description>"  on success
    #   "  FAIL: <description>"  on failure
    # Both with a leading space (the existing test convention).
    LAST=$(echo "$OUT" | tail -10)
    if echo "$LAST" | grep -qE "^\s*PASS:"; then
        PASS_COUNT=$((PASS_COUNT + 1))
    elif echo "$LAST" | grep -qE "^\s*FAIL:"; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$t")
    else
        # Ambiguous outcome — count as failure for safety.
        echo "  (no PASS:/FAIL: marker in final 10 lines — counted as failure)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$t (no marker)")
    fi
    echo
done

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo "──────────────────────────────────────────────"
echo "Regression suite summary (${ELAPSED}s)"
echo "──────────────────────────────────────────────"
echo "PASS: $PASS_COUNT tests"
echo "FAIL: $FAIL_COUNT tests"
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "──────────────────────────────────────────────"
    echo "Failed tests:"
    for ft in "${FAILED_TESTS[@]}"; do
        echo "  - $ft"
    done
fi

# Exit non-zero if anything failed.
[ "$FAIL_COUNT" -eq 0 ] || exit 1
