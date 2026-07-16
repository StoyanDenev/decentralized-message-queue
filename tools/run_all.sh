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
#                         sha256, anon_address, anon_address_fragmentation,
#                         genesis_message,
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
#                         merge_event_bytes,
#                         make_contrib_commitment_distinct,
#                         state_proof_value_hash,
#                         dapp_registry_trustless_read, unstake_eligibility,
#                         rpc_auth_hmac. Each runs in <5s
#                         with no flakes. Useful for quick iteration
#                         during development.

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
    ONLY_PATTERN='test_(atomic_scope|composable_batch|dapp_register|dapp_call|s018_json_validation|merkle|committee_selection|abort_reselection|shard_routing|ed25519|ed25519_vectors|sha256|sha2_c99|chacha20_c99|aes_c99|ed25519_c99|ed25519_scalar_reduce_edge|x25519_c99|blake2b_c99|sha3_c99|mldsa_c99|xchacha_c99|argon2id_c99|p256_c99|p256_h2c_c99|p256_oprf_c99|pedersen_c99|bp_ipa_c99|bp_rangeproof_c99|bp_agg_rangeproof_c99|p256_balance_c99|p256_confidential_tx_c99|p256_ctx_bundle|ct_c99|rng_c99|view_key_c99|c99_vectors|c99_api|ct_timing_selftest|anon_address|genesis_message|state_root_unit|block_rand|rate_limiter|block_digest|block_hash|binary_codec|wire_types|transaction|merge_event_codec|merge_event_bytes|consensus_msgs|tx_root|genesis|envelope|resolve_fork|shamir|random_state|snapshot_defense|encoding|chain_helpers|json_validate|block_roundtrip|config_roundtrip|tx_binary_codec|chain_append|state_types|validator_config|timing_profiles|params_constants|supply_invariant|enum_values|block_accessors|make_block_sig|domain_separation|tx_signing_bytes|make_genesis_block|pending_param_changes|merge_state|chain_apply_block|snapshot_roundtrip|state_proof_unit|abort_event_apply|equivocation_apply|equivocation_evidence|fa_equivocation_trace|fa_abort_trace|fa_cross_shard_trace|fa_multi_event_trace|fa_merge_trace|unstake_deregister_apply|cross_shard_receipt_apply|param_change_apply|pending_param_change_determinism|subsidy_distribution|subsidy_pool_clamp|merge_event_apply|cross_shard_outbound_apply|supply_lifecycle|supply_invariant_fuzz|dapp_state_transition|dapp_registry_determinism|governance_param_determinism|overflow_paths|state_root_namespaces|multi_tx_block|state_proof_namespaces|state_proof_composite_key|state_proof_value_hash|dapp_registry_trustless_read|applied_receipt_restore|applied_receipt_snapshot|stake_accounting|unstake_eligibility|fee_distribution_edge|fee_edge_cases|value_overflow_mint|ct_disable_flag|equivocation_multi|cross_shard_multi_receipt|multi_block_chain|chain_revert_head|chain_reorg_save_crash|shard_tip_record|shard_tip_records|shard_tip_namespace|committee_checkpoint|committee_fold|shard_tip_fold|shardtip_reconciliation|shardtip_witness_codec|shardtip_witness_verify|s036_merge_witness|committee_pin|tx_edge_cases|snapshot_then_apply|genesis_with_region|anon_routing|anon_address_fragmentation|merge_event_apply_edge|merge_ring_topology|block_event_composition|nef_pool_drain|tx_payload_bounds|empty_block_apply|account_create_on_credit|randomized_delay|block_timestamp|timestamp_reconciliation|node_registry|tx_replay_protection|chain_save_load|chain_store|block_validator_basic|genesis_sharded|cross_shard_atomicity|cross_shard_supply_invariant|chain_ctor_bootstrap|snapshot_version_rejection|config_defaults|required_block_sigs|config_load_save|block_from_json_minimal|config_permissive|chain_shard_routing_config|view_root|make_contrib_commitment_distinct|contrib_wire_verify|rate_limiter_bucket|merkle_proof_tampering|merkle_tree_balanced|protocol_version_pinning|binary_codec_roundtrip_exhaustive|time_monotonicity|chain_prev_hash_link|block_validator_extensive|state_root_determinism|consensus_vectors|tx_signing_determinism|merge_event_determinism|merge_state_determinism|snapshot_full_determinism|block_rand_distribution|config_determinism|hello_handshake_determinism|wire_negotiation|genesis_determinism|shard_routing_determinism|anon_address_derivation|config_knob_completeness|empty_genesis_edge|wallet_tx_batch_sign|wallet_account_import_many|wallet_keyfile_reencrypt|wallet_keyfile_argon2|operator_keyfile_kdf_audit|wallet_envelope_compat|wallet_verify_batch|wallet_batch_nonce_assign|wallet_tx_batch_summary|rpc_auth_hmac|dsf_core|dsf_inc2|dsf_inc3|dsf_inc4|dsf_inc5|dsf_inc6|dsf_inc7|minix_dependency_surface|net_native|net_virtual|scheduler_timers|scheduler_external|scheduler_multiloop|node_reorg_s048|fa_liveness_virtual|fa_partition_virtual|fa_adversarial_deterministic|virtual_clock|light_pq_sign|pq_transaction|pq_transfer_e2e|shield|unshield|confidential_transfer|audit_keys|light_verify_ct|block_signature_form|eligible_count|light_audit_tx|light_ct_tx|light_ct_transfer)\.sh$'
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
    #
    # FAIL is checked FIRST (fail-closed): many tests print per-check
    # "PASS: <desc>" lines via assert helpers, and a late passing check can
    # land inside a FAILING run's tail window alongside the terminal
    # "FAIL: <name>" marker. With PASS checked first, that combination
    # counted GREEN (a real observed false-green class — see
    # tools/test_cluster_output_discipline.sh). A FAIL marker in the tail
    # always wins; a passing run prints no FAIL: line, so this cannot
    # false-RED a healthy test.
    LAST=$(echo "$OUT" | tail -10)
    if echo "$LAST" | grep -qE "^\s*FAIL:"; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$t")
        # QUIET captures output instead of teeing it — but a FAILING test's
        # output is the diagnosis, and swallowing it leaves a CI log that
        # names the red test with zero evidence of WHICH assertion fired
        # (observed live: the fa-partition-virtual CI red was undebuggable
        # from the Actions log). Failures always print.
        if [ "${QUIET:-0}" = "1" ]; then
            echo "  ── failing test output (QUIET=1 suppressed the live tee) ──"
            echo "$OUT"
        fi
    elif echo "$LAST" | grep -qE "^\s*PASS:"; then
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        # Ambiguous outcome — count as failure for safety.
        echo "  (no PASS:/FAIL: marker in final 10 lines — counted as failure)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS+=("$t (no marker)")
        if [ "${QUIET:-0}" = "1" ]; then
            echo "  ── markerless test output (QUIET=1 suppressed the live tee) ──"
            echo "$OUT"
        fi
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
