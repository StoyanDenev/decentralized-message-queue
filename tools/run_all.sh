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
#   RUN:  R wrappers  (= PASS + FAIL + PLATFORM-SKIP)
#   PASS: N tests
#   FAIL: M tests
#   PLATFORM-SKIP: P wrappers skipped ENTIRELY
#   SKIP: D of the N passing wrappers declined at least one section
#   ──────────────────────────────────────────────
#   Failed tests:
#     - tools/test_FAILED1.sh
#     - tools/test_FAILED2.sh
#
# Per-test outcome detection: the script grep's the last 10 lines of
# each test's output for a "PASS:", "FAIL:" or "PLATFORM-SKIP:" line.
# Every existing test follows the convention of a final-line marker, so
# this is robust to test-specific output noise above it.
#
# ── THE SKIP CONVENTION (repo-wide; 2026-09-18) ────────────────────────
# A wrapper that DECLINES a check — no strace, no compiler, no binary,
# a POSIX-only assertion on Windows — prints a line beginning with
# "SKIP: " naming the cause, and MUST NOT bank a pass for it. Lesson 15
# of the wave doctrine: `fail_count == 0` is not a verdict, and a SKIP
# that increments pass_count makes "N pass" mean two different things in
# two adjacent files. The per-wrapper shape, defined in tools/common.sh
# and used verbatim by eight wrappers today, is:
#
#     pass_count=0; fail_count=0; skip_count=0
#     skip() { echo "  SKIP: $1"; skip_count=$((skip_count + 1)); }
#     ...
#     echo "  $pass_count pass / $fail_count fail / $skip_count skip"
#     if [ "$pass_count" -eq 0 ]; then ... FAIL ... exit 1   # the floor
#     elif [ "$fail_count" -eq 0 ]; then ... PASS ... exit 0
#     else ... FAIL ... exit 1; fi
#
# THIS runner counts WRAPPERS, not assertions, so its own skip column is
# derived from the SKIP: markers a wrapper printed. It is ADDITIVE: a
# wrapper that declined a section still scores exactly as it did before —
# the column says how much of the green was declined rather than checked.
#
# ── THE WRAPPER-LEVEL SKIP: "PLATFORM-SKIP:" (2026-09-18) ──────────────
# A DECLINED SECTION and a WRAPPER WITH NOTHING TO ASSERT HERE are two
# different facts and this runner needs both. The first is above: the
# wrapper asserted something and says how much it did not check. The
# second is a wrapper whose PROPERTY DOES NOT EXIST ON THIS PLATFORM —
# `tools/test_wallet_out_perms.sh` and `tools/test_node_key_perms.sh`
# gate the mode a key file ends at, and Windows has no POSIX file mode
# at all. Every section declines, the wrapper's (correct) `pass_count > 0`
# floor calls that a failure, and the windows-2022 CI job goes red for a
# gate whose subject is absent there. Reporting the product broken is a
# lie; reporting PASS is a worse one.
#
# Such a wrapper prints, as its TERMINAL marker and in place of both
# PASS: and FAIL:,
#
#     PLATFORM-SKIP: <name> — <why the property does not exist here>
#
# and exits 0. The cause after the colon is REQUIRED: the detection grep
# demands a non-blank character after it, so a bare `PLATFORM-SKIP:` is
# no marker at all and falls through to the markerless (failure) branch.
# This outcome is for a PROPERTY THAT DOES NOT EXIST, never for a TOOL
# THAT IS MISSING: no strace on a Linux box, no C compiler, no ptrace
# permission are all "declined a section" — the property is real there
# and the wrapper must still assert what it can, or fail closed having
# asserted nothing. A wrapper that claims this marker while ALSO printing
# assertion-level `PASS:` lines did assert something and is lying about
# it; that is scored a FAILURE, not a skip.
#
# The arithmetic is self-checked below (PASS + FAIL + PLATFORM-SKIP ==
# RUN, SKIP <= PASS, VACUOUS <= SKIP) and a mismatch is a hard FAIL,
# because a summary nobody can verify is the same defect class as a gate
# that cannot fail. The suite still exits non-zero ONLY when FAIL > 0.
# `tools/test_gates_can_fail.sh` drives this runner over synthetic
# wrappers and falsifies every one of those identities.
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
# PSKIP_COUNT is the THIRD per-wrapper outcome: the wrapper skipped ENTIRELY
# because the property it gates does not exist on this platform (see THE
# WRAPPER-LEVEL SKIP in the header). It is NOT a pass and NOT a failure, and it
# is the only other bucket a wrapper that RAN can land in.
PSKIP_COUNT=0
# RUN_COUNT is the number of wrappers actually executed; the summary asserts
# PASS + FAIL + PSKIP == RUN so no wrapper can fall out of the accounting unseen.
RUN_COUNT=0
# SKIP_COUNT / VACUOUS_COUNT are ADDITIVE reporting over the passing wrappers —
# see THE SKIP CONVENTION in the header. They change no verdict.
SKIP_COUNT=0
VACUOUS_COUNT=0
FAILED_TESTS=()
PLATFORM_SKIPPED_TESTS=()
SKIPPED_TESTS=()
VACUOUS_TESTS=()
START_TIME=$(date +%s)

SKIP_PATTERN="${SKIP_PATTERN:-}"
ONLY_PATTERN="${ONLY_PATTERN:-}"

# FAST=1 short-circuits to the deterministic in-process subset.
# These are wrappers around `determ test-*` subcommands — no network,
# no clusters, <5s each, no flakes. Useful for dev iteration.
if [ "${FAST:-0}" = "1" ]; then
    ONLY_PATTERN='test_(atomic_scope|composable_batch|dapp_register|dapp_call|s018_json_validation|merkle|committee_selection|abort_reselection|shard_routing|ed25519|ed25519_vectors|sha256|sha2_c99|chacha20_c99|aes_c99|ed25519_c99|ed25519_scalar_reduce_edge|x25519_c99|blake2b_c99|sha3_c99|mldsa_c99|xchacha_c99|argon2id_c99|p256_c99|p256_h2c_c99|p256_oprf_c99|pedersen_c99|bp_ipa_c99|bp_rangeproof_c99|bp_agg_rangeproof_c99|p256_balance_c99|p256_confidential_tx_c99|p256_ctx_bundle|dsso_threshold_oprf|dsso_assertion|dsso_opaque3dh|dsso_login_e2e|dsso_core|dsso_authn|dsso_pid|dsso_assertion_module|d5_draw|d5_codec|d5rp|d5_selection_e2e|ct_c99|rng_c99|view_key_c99|enote_c99|notekey_modern_c99|notekey_fips_c99|c99_vectors|c99_api|ct_timing_selftest|anon_address|genesis_message|state_root_unit|block_rand|rate_limiter|block_digest|block_hash|binary_codec|block_binary_codec|genesis_binary_codec|snapshot_binary_codec|wire_payload_frames|headers_frame_codec|snapshot_response_frame_codec|wire_types|transaction|merge_event_codec|merge_event_bytes|consensus_msgs|tx_root|genesis|envelope|resolve_fork|shamir|random_state|node_key_perms|snapshot_defense|encoding|chain_helpers|json_validate|block_roundtrip|config_roundtrip|tx_binary_codec|chain_append|state_types|validator_config|timing_profiles|params_constants|supply_invariant|enum_values|block_accessors|make_block_sig|domain_separation|tx_signing_bytes|make_genesis_block|pending_param_changes|merge_state|chain_apply_block|snapshot_roundtrip|state_proof_unit|abort_event_apply|abort_claims_canonical|abort_cert_validation|al3_unknown_tx_type|producer_admit|mempool_admit_eviction|mempool_admit_affordability|contrib_trigger_membership|contrib_view_root_admit|evidence_admit|register_create_only|register_small_order_key|zeroth_pool_inner_batch|abort_event_canonical|sr5_misroute_receipt|equivocation_apply|equivocation_evidence|equivocation_detect_oob|equivocation_dedup_identity|fa_equivocation_trace|fa_abort_trace|fa_cross_shard_trace|fa_multi_event_trace|fa_merge_trace|unstake_deregister_apply|cross_shard_receipt_apply|param_change_apply|pending_param_change_determinism|subsidy_distribution|subsidy_pool_clamp|merge_event_apply|cross_shard_outbound_apply|supply_lifecycle|supply_invariant_fuzz|dapp_state_transition|dapp_registry_determinism|governance_param_determinism|overflow_paths|state_root_namespaces|multi_tx_block|state_proof_namespaces|state_proof_composite_key|state_proof_value_hash|dapp_registry_trustless_read|applied_receipt_restore|applied_receipt_snapshot|stake_accounting|unstake_eligibility|fee_distribution_edge|fee_edge_cases|value_overflow_mint|ct_disable_flag|crypto_profile|determ_json|determ_json_surfaces|determ_json_fuzz|determ_json_adversarial|ctx_enote|scan_enotes|register_note_key|equivocation_multi|cross_shard_multi_receipt|multi_block_chain|chain_revert_head|chain_reorg_save_crash|shard_tip_record|shard_tip_records|shard_tip_namespace|committee_checkpoint|committee_fold|shard_tip_fold|shardtip_reconciliation|shardtip_witness_codec|shardtip_witness_verify|s036_merge_witness|committee_pin|tx_edge_cases|snapshot_then_apply|genesis_with_region|anon_routing|anon_address_fragmentation|merge_event_apply_edge|merge_ring_topology|block_event_composition|nef_pool_drain|tx_payload_bounds|empty_block_apply|account_create_on_credit|account_create_perms|randomized_delay|block_timestamp|timestamp_reconciliation|node_registry|eligibility_floor|tx_replay_protection|chain_save_load|chain_load_genesis_params|chain_store|block_validator_basic|genesis_sharded|cross_shard_atomicity|cross_shard_supply_invariant|chain_ctor_bootstrap|snapshot_version_rejection|config_defaults|required_block_sigs|config_load_save|block_from_json_minimal|config_permissive|chain_shard_routing_config|view_root|make_contrib_commitment_distinct|contrib_wire_verify|rate_limiter_bucket|merkle_proof_tampering|merkle_tree_balanced|protocol_version_pinning|binary_codec_roundtrip_exhaustive|time_monotonicity|chain_prev_hash_link|block_validator_extensive|state_root_determinism|consensus_vectors|tx_signing_determinism|merge_event_determinism|merge_state_determinism|snapshot_full_determinism|block_rand_distribution|config_determinism|hello_handshake_determinism|wire_caps_discriminator|genesis_determinism|shard_routing_determinism|anon_address_derivation|config_knob_completeness|empty_genesis_edge|wallet_tx_batch_sign|wallet_out_perms|wallet_account_import_many|wallet_keyfile_reencrypt|wallet_keyfile_argon2|operator_keyfile_kdf_audit|wallet_envelope_compat|wallet_envelope_bytes|wallet_keyfile_binary|wallet_backup_binary|wallet_verify_batch|wallet_committee_quorum|wallet_batch_nonce_assign|wallet_tx_batch_summary|rpc_auth_hmac|rpc_tx_sig_admit|inbound_receipt_cap|beacon_header_committee|straggler_resync|chain_summary_cap|snapshot_header_cap|snapshot_a1_revalidate|dsf_core|dsf_inc2|dsf_inc3|dsf_inc4|dsf_inc5|dsf_inc6|dsf_inc7|dsf_inc8|dsf_inc9|dsf_inc10|dsf_inc11|dsf_inc12|dsf_inc13|dsf_inc14|minix_dependency_surface|minix_sbom|operator_unreachable_contract|net_native|net_virtual|rl2_hello_exempt|scheduler_timers|scheduler_external|scheduler_multiloop|node_reorg_s048|node_reorg_guard|fa_liveness_virtual|fa_partition_virtual|fa_adversarial_deterministic|fa_crash_deterministic|virtual_clock|light_pq_sign|light_pq_addr_bind|light_seed_source|pq_transaction|pq_transfer_e2e|shield|unshield|confidential_transfer|audit_keys|light_verify_ct|light_verify_equivocation|light_verify_notekey|light_verify_empty_committee|light_verify_state_bundle_anchor_index|light_verify_state_bundle_committee_size|light_verify_committee_size|light_verify_archive_range_bind|light_rpc_readline_cap|light_verify_tx_inclusion_height|light_watch_head_label|light_account_history_genesis_root|light_account_history_label|light_verify_rand|light_verify_selection|light_committee_auth|light_verify_enote_inclusion|light_register_note_key|block_signature_form|eligible_count|light_audit_tx|light_ct_tx|light_ct_transfer|light_outbox|gates_can_fail)\.sh$'
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
    RUN_COUNT=$((RUN_COUNT + 1))
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
    elif echo "$LAST" | grep -qE "^[[:space:]]*PLATFORM-SKIP:[[:space:]]*[^[:space:]]"; then
        # ── THE WRAPPER-LEVEL SKIP (see the header). Checked AFTER FAIL: so a
        # wrapper that manages to print both is still fail-closed, and BEFORE
        # PASS: so the marker is what decides — a wrapper cannot reach this
        # branch and the PASS branch at once. Spelled with POSIX [[:space:]]
        # classes, not \s, so test_cluster_output_discipline.sh's D5 fixed-string
        # search for the two original detection greps still finds those two and
        # only those, in that order, and keeps pinning the real greps rather
        # than a comment that happens to quote them.
        #
        # The cause is REQUIRED: [[:space:]]*[^[:space:]] after the colon. A bare
        # `PLATFORM-SKIP:` names nothing, matches nothing here, and lands in the
        # markerless branch below as a failure — a skip nobody can audit is not a
        # skip.
        ASSERTED=$(echo "$OUT" | grep -cE "^[[:space:]]*PASS:")
        if [ "$ASSERTED" -eq 0 ]; then
            PSKIP_COUNT=$((PSKIP_COUNT + 1))
            PLATFORM_SKIPPED_TESTS+=("$t")
        else
            # It claimed to have asserted nothing and then printed assertion-level
            # PASS: lines. One of the two is false and the runner cannot tell
            # which, so it fails closed: a wrapper allowed to bank the quiet
            # outcome while actually asserting is a new way to go green.
            echo "  (PLATFORM-SKIP: claimed, but the wrapper printed assertion-level PASS: lines — counted as failure)"
            FAIL_COUNT=$((FAIL_COUNT + 1))
            FAILED_TESTS+=("$t (PLATFORM-SKIP claimed by a wrapper that asserted)")
            if [ "${QUIET:-0}" = "1" ]; then
                echo "  ── output of the wrapper that claimed PLATFORM-SKIP (QUIET=1 suppressed the live tee) ──"
                echo "$OUT"
            fi
        fi
    elif echo "$LAST" | grep -qE "^\s*PASS:"; then
        PASS_COUNT=$((PASS_COUNT + 1))
        # ── ADDITIVE skip accounting (see THE SKIP CONVENTION in the header).
        # The verdict above is final and unchanged; what follows only records
        # how much of this green was DECLINED rather than checked, so a reader
        # of the summary can tell the two apart. Deliberately spelled with
        # POSIX [[:space:]] classes, not \s, so tools/test_cluster_output_
        # discipline.sh's D5 fixed-string search for the detection greps
        # ("^\s*FAIL:" before "^\s*PASS:") still finds those two and only those.
        if echo "$OUT" | grep -qE "^[[:space:]]*SKIP:"; then
            SKIP_COUNT=$((SKIP_COUNT + 1))
            SKIPPED_TESTS+=("$t")
            # VACUOUS: the wrapper declined AND printed no assertion-level
            # PASS line — its only "PASS:" is the terminal marker run_all
            # scored. That is a wrapper reporting green having asserted
            # nothing (wave-doctrine lesson 15) and is the shape worth a name.
            # HEURISTIC, and it under-reports on purpose: a wrapper whose tail
            # carries two PASS: lines (an in-process "PASS: x all assertions"
            # plus the wrapper's own) is not flagged. It never over-reports.
            if [ "$(echo "$OUT" | grep -cE "^[[:space:]]*PASS:")" -le 1 ]; then
                VACUOUS_COUNT=$((VACUOUS_COUNT + 1))
                VACUOUS_TESTS+=("$t")
            fi
        fi
    else
        # Ambiguous outcome — count as failure for safety.
        echo "  (no PASS:/FAIL:/PLATFORM-SKIP: marker in final 10 lines — counted as failure)"
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
echo "RUN:  $RUN_COUNT wrappers"
echo "PASS: $PASS_COUNT tests"
echo "FAIL: $FAIL_COUNT tests"
echo "PLATFORM-SKIP: $PSKIP_COUNT wrappers skipped ENTIRELY on $(uname -s 2>/dev/null || echo unknown) (the property they gate does not exist here; nothing was asserted and no pass was banked)"
echo "SKIP: $SKIP_COUNT of the $PASS_COUNT passing wrappers declined at least one section ($VACUOUS_COUNT of those asserted nothing)"
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "──────────────────────────────────────────────"
    echo "Failed tests:"
    for ft in "${FAILED_TESTS[@]}"; do
        echo "  - $ft"
    done
fi
if [ "$PSKIP_COUNT" -gt 0 ]; then
    echo "──────────────────────────────────────────────"
    echo "Skipped entirely — NOT GATED ON THIS PLATFORM (each named its cause above):"
    for pt in "${PLATFORM_SKIPPED_TESTS[@]}"; do
        echo "  - $pt"
    done
fi
if [ "$SKIP_COUNT" -gt 0 ] && [ "${SHOW_SKIPPED:-1}" = "1" ]; then
    echo "──────────────────────────────────────────────"
    echo "Passed with at least one declined section (SKIP:):"
    for st in "${SKIPPED_TESTS[@]}"; do
        echo "  - $st"
    done
    if [ "$VACUOUS_COUNT" -gt 0 ]; then
        echo "  …of which these asserted nothing at all:"
        for vt in "${VACUOUS_TESTS[@]}"; do
            echo "    ! $vt"
        done
    fi
fi

# ── Summary arithmetic, self-checked ──────────────────────────────────────
# A summary a reader cannot verify is the same defect class as a gate that
# cannot fail, so the runner falsifies its own accounting before it reports:
#   (i)   every wrapper that RAN landed in exactly one of PASS / FAIL /
#         PLATFORM-SKIP. The identity is WIDENED, not dropped: a third outcome
#         that did not have to balance would be a hole big enough to lose a
#         wrapper in, which is the whole reason the check exists;
#   (ii)  the declined set is a SUBSET of the passing set (a declined wrapper
#         still passed — this column is additive reporting, not a re-tiering);
#   (iii) the asserted-nothing set is a subset of the declined set.
# Any mismatch is a hard FAIL with the numbers printed, not a silent skew.
ARITH_OK=1
if [ "$((PASS_COUNT + FAIL_COUNT + PSKIP_COUNT))" -ne "$RUN_COUNT" ]; then
    echo "  FAIL: run_all summary arithmetic — PASS($PASS_COUNT) + FAIL($FAIL_COUNT) + PLATFORM-SKIP($PSKIP_COUNT) = $((PASS_COUNT + FAIL_COUNT + PSKIP_COUNT)), but RUN = $RUN_COUNT wrappers"
    ARITH_OK=0
fi
if [ "$SKIP_COUNT" -gt "$PASS_COUNT" ]; then
    echo "  FAIL: run_all summary arithmetic — SKIP($SKIP_COUNT) exceeds PASS($PASS_COUNT); the declined set must be a subset of the passing set"
    ARITH_OK=0
fi
if [ "$VACUOUS_COUNT" -gt "$SKIP_COUNT" ]; then
    echo "  FAIL: run_all summary arithmetic — asserted-nothing($VACUOUS_COUNT) exceeds SKIP($SKIP_COUNT)"
    ARITH_OK=0
fi
[ "$ARITH_OK" -eq 1 ] || exit 1

# Exit non-zero if anything FAILED. A wrapper that skipped entirely is not a
# failure — it is the absence of a judgement, and the summary above says so by
# name. This is the ONLY verdict-bearing line in the file.
[ "$FAIL_COUNT" -eq 0 ] || exit 1
