/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Monotonic K=2 State Machine Implementation (C99 Bare-Metal)
 * Enforces Strict 2-of-2 Epoch Skipping, Decoupled Metronome & Gossip Veto.
 */

#define _POSIX_C_SOURCE 200809L

#include <determ/consensus/duel_state.h>
#include <determ/wire/parser.h>
#include <determ/time/clock.h>

#include <string.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>

#if defined(__APPLE__)
#include <mach/mach_time.h>
#endif

uint64_t duel_clock_monotonic_ns(void) {
    return determ_clock_now_ns();
}

static void write_be32(uint8_t *dest, uint32_t val) {
    dest[0] = (uint8_t)((val >> 24) & 0xFF);
    dest[1] = (uint8_t)((val >> 16) & 0xFF);
    dest[2] = (uint8_t)((val >> 8)  & 0xFF);
    dest[3] = (uint8_t)(val & 0xFF);
}

duel_status_t duel_state_init(duel_state_machine_t *sm) {
    if (!sm) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }
    memset(sm, 0, sizeof(*sm));
    sm->state = DUEL_STATE_IDLE;
    sm->p2p_socket_fd = -1;
    return DUEL_SUCCESS;
}

duel_status_t duel_state_start_commitment_phase(duel_state_machine_t *sm) {
    if (!sm) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }
    if (sm->state != DUEL_STATE_IDLE && sm->state != DUEL_STATE_FINALIZED && sm->state != DUEL_STATE_ABORTED) {
        return DUEL_ERR_INVALID_STATE;
    }

    memset(&sm->aggregator_commit, 0, sizeof(sm->aggregator_commit));
    memset(&sm->contributor_commit, 0, sizeof(sm->contributor_commit));
    memset(&sm->aggregator_reveal, 0, sizeof(sm->aggregator_reveal));
    memset(&sm->contributor_reveal, 0, sizeof(sm->contributor_reveal));
    memset(sm->vdf_input_buffer, 0, sizeof(sm->vdf_input_buffer));
    sm->vdf_input_len = 0;
    sm->reveal_buffer_locked = false;
    sm->straggler_fallback_active = false;
    sm->aggregator_slashed = false;

    sm->epoch_start_time = duel_clock_monotonic_ns();
    sm->reveal_start_ns = 0;
    sm->reveal_end_ns = 0;

    sm->state = DUEL_STATE_COMMITMENT_PHASE;
    return DUEL_SUCCESS;
}

duel_status_t duel_submit_aggregator_commit(duel_state_machine_t *sm, const uint8_t commit_hash[32]) {
    if (!sm || !commit_hash) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }
    if (sm->state != DUEL_STATE_COMMITMENT_PHASE && sm->state != DUEL_STATE_AWAITING_COMMITS) {
        return DUEL_ERR_INVALID_STATE;
    }
    if (sm->aggregator_commit.present) {
        return DUEL_ERR_ALREADY_COMMITTED;
    }

    memcpy(sm->aggregator_commit.hash, commit_hash, 32);
    sm->aggregator_commit.arrival_timestamp_ns = duel_clock_monotonic_ns();
    sm->aggregator_commit.present = true;
    return DUEL_SUCCESS;
}

duel_status_t duel_submit_contributor_commit(duel_state_machine_t *sm, const uint8_t commit_hash[32]) {
    if (!sm || !commit_hash) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }
    if (sm->state != DUEL_STATE_COMMITMENT_PHASE && sm->state != DUEL_STATE_AWAITING_COMMITS) {
        return DUEL_ERR_INVALID_STATE;
    }

    uint64_t now = duel_clock_monotonic_ns();
    /* Strict 1000ms commit timeout from epoch_start_time */
    if (sm->epoch_start_time > 0 && (now - sm->epoch_start_time) >= DUEL_COMMIT_TIMEOUT_NS) {
        sm->vrf_round++;
        sm->state = DUEL_STATE_ABORTED;
        return ERR_EPOCH_SKIPPED_SILENCE;
    }

    if (sm->contributor_commit.present) {
        return DUEL_ERR_ALREADY_COMMITTED;
    }

    memcpy(sm->contributor_commit.hash, commit_hash, 32);
    sm->contributor_commit.arrival_timestamp_ns = now;
    sm->contributor_commit.present = true;
    return DUEL_SUCCESS;
}

duel_status_t duel_state_poll_commit_timeout(duel_state_machine_t *sm) {
    if (!sm) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }
    if (sm->state != DUEL_STATE_COMMITMENT_PHASE && sm->state != DUEL_STATE_AWAITING_COMMITS) {
        return DUEL_SUCCESS;
    }

    uint64_t now = duel_clock_monotonic_ns();
    if (sm->epoch_start_time > 0 && (now - sm->epoch_start_time) >= DUEL_COMMIT_TIMEOUT_NS) {
        if (!sm->contributor_commit.present) {
            sm->vrf_round++;
            sm->state = DUEL_STATE_ABORTED;
            return ERR_EPOCH_SKIPPED_SILENCE;
        }
    }

    return DUEL_SUCCESS;
}

duel_status_t duel_state_start_reveal_window(duel_state_machine_t *sm) {
    if (!sm) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }
    if (sm->state != DUEL_STATE_COMMITMENT_PHASE) {
        return DUEL_ERR_INVALID_STATE;
    }

    uint64_t now = duel_clock_monotonic_ns();
    if (sm->epoch_start_time == 0) {
        sm->epoch_start_time = now;
    }
    sm->reveal_start_ns = now;
    sm->reveal_end_ns = sm->epoch_start_time + DUEL_REVEAL_WINDOW_NS;
    sm->reveal_buffer_locked = false;
    sm->state = DUEL_STATE_AWAITING_REVEALS;

    return DUEL_SUCCESS;
}

uint64_t duel_state_elapsed_reveal_ns(const duel_state_machine_t *sm) {
    if (!sm || sm->reveal_start_ns == 0) {
        return 0ULL;
    }
    uint64_t now = duel_clock_monotonic_ns();
    if (now <= sm->reveal_start_ns) {
        return 0ULL;
    }
    return now - sm->reveal_start_ns;
}

duel_status_t duel_submit_aggregator_reveal(duel_state_machine_t *sm,
                                            const uint8_t *payload,
                                            uint32_t payload_len) {
    if (!sm || (!payload && payload_len > 0)) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }
    if (sm->state != DUEL_STATE_AWAITING_REVEALS) {
        return DUEL_ERR_INVALID_STATE;
    }
    if (sm->reveal_buffer_locked) {
        return DUEL_DROPPED_BUFFER_LOCKED;
    }
    if (payload_len > DUEL_MAX_PAYLOAD_SIZE) {
        return DUEL_ERR_PAYLOAD_TOO_LARGE;
    }

    uint64_t now = duel_clock_monotonic_ns();
    uint64_t base_time = (sm->epoch_start_time > 0) ? sm->epoch_start_time : sm->reveal_start_ns;
    if (now >= sm->reveal_end_ns || (now - base_time) >= DUEL_REVEAL_WINDOW_NS) {
        return DUEL_DROPPED_BUZZER_EXCEEDED;
    }

    if (sm->aggregator_reveal.present) {
        return DUEL_ERR_ALREADY_REVEALED;
    }

    if (payload_len > 0) {
        memcpy(sm->aggregator_reveal.data, payload, payload_len);
    }
    sm->aggregator_reveal.len = payload_len;
    sm->aggregator_reveal.arrival_timestamp_ns = now;
    sm->aggregator_reveal.present = true;
    sm->aggregator_reveal.valid = true;

    return DUEL_SUCCESS;
}

duel_status_t duel_submit_contributor_reveal(duel_state_machine_t *sm,
                                             const uint8_t *payload,
                                             uint32_t payload_len,
                                             bool is_valid) {
    if (!sm || (!payload && payload_len > 0)) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }
    if (sm->state != DUEL_STATE_AWAITING_REVEALS) {
        return DUEL_ERR_INVALID_STATE;
    }
    if (sm->reveal_buffer_locked) {
        return DUEL_DROPPED_BUFFER_LOCKED;
    }

    uint64_t now = duel_clock_monotonic_ns();
    uint64_t base_time = (sm->epoch_start_time > 0) ? sm->epoch_start_time : sm->reveal_start_ns;

    /*
     * The Buzzer Gate:
     * When monotonic delta hits 2000ms, buffer is locked and any packet
     * arriving at >= 2001ms (or >= 2000ms boundary) MUST be dropped.
     */
    if (now >= sm->reveal_end_ns || (now - base_time) >= DUEL_REVEAL_WINDOW_NS) {
        return DUEL_DROPPED_BUZZER_EXCEEDED;
    }

    if (payload_len > DUEL_MAX_PAYLOAD_SIZE) {
        return DUEL_ERR_PAYLOAD_TOO_LARGE;
    }

    if (sm->contributor_reveal.present) {
        return DUEL_ERR_ALREADY_REVEALED;
    }

    if (!is_valid) {
        sm->contributor_reveal.arrival_timestamp_ns = now;
        sm->contributor_reveal.present = true;
        sm->contributor_reveal.valid = false;
        sm->contributor_reveal.len = 0;
        return DUEL_DROPPED_INVALID_PAYLOAD;
    }

    if (payload_len > 0) {
        memcpy(sm->contributor_reveal.data, payload, payload_len);
    }
    sm->contributor_reveal.len = payload_len;
    sm->contributor_reveal.arrival_timestamp_ns = now;
    sm->contributor_reveal.present = true;
    sm->contributor_reveal.valid = true;

    return DUEL_SUCCESS;
}

/*
 * Buzzer Event Loop:
 * If determ_clock_now() - epoch_start_time >= 2000ms:
 *  1. Instantly locks the reveal buffer.
 *  2. Evaluates presence and validity of BOTH reveals (Strict 2-of-2 Rule).
 *  3. If either reveal is missing or invalid: returns ERR_EPOCH_SKIPPED_INCOMPLETE,
 *     increments VRF, and aborts (zero VDF on 1-of-2).
 *  4. If both reveals present: bundles them, broadcasts Signed_Reveal_Bundle via
 *     Decoupled Metronome, and transitions to DUEL_STATE_VDF_EVALUATION.
 */
duel_status_t duel_state_poll_buzzer(duel_state_machine_t *sm) {
    if (!sm) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }

    if (sm->state != DUEL_STATE_AWAITING_REVEALS) {
        return DUEL_SUCCESS;
    }

    uint64_t now = duel_clock_monotonic_ns();
    uint64_t base_time = (sm->epoch_start_time > 0) ? sm->epoch_start_time : sm->reveal_start_ns;
    uint64_t elapsed = (now >= base_time) ? (now - base_time) : 0ULL;

    bool both_present = (sm->aggregator_reveal.present && sm->aggregator_reveal.valid &&
                         sm->contributor_reveal.present && sm->contributor_reveal.valid);

    if (elapsed < DUEL_REVEAL_WINDOW_NS && !both_present) {
        /* Reveal window still active */
        return DUEL_SUCCESS;
    }

    /* Buzzer triggered (determ_clock_now() - epoch_start_time >= 2000ms) */
    sm->reveal_buffer_locked = true;
    sm->state = DUEL_STATE_REVEAL_BUFFER_LOCKED;

    /*
     * The 2-of-2 Rule:
     * If bundle.aggregator_reveal == NULL OR bundle.contributor_reveal == NULL,
     * the epoch fails instantly. Return ERR_EPOCH_SKIPPED_INCOMPLETE.
     * Do NOT execute the VDF on a 1-of-2 payload.
     */
    bool agg_ok = (sm->aggregator_reveal.present && sm->aggregator_reveal.valid && sm->aggregator_reveal.len > 0);
    bool cont_ok = (sm->contributor_reveal.present && sm->contributor_reveal.valid && sm->contributor_reveal.len > 0);

    if (!agg_ok || !cont_ok) {
        sm->straggler_fallback_active = false;
        sm->state = DUEL_STATE_ABORTED;
        sm->vrf_round++;
        return ERR_EPOCH_SKIPPED_INCOMPLETE;
    }

    /* Valid 2-of-2 payload: safely concatenate with bounds checking */
    uint32_t offset = 0;
    size_t parsed_length = 4 + (size_t)sm->aggregator_reveal.len;
    if (offset + parsed_length > MAX_BUNDLE_SIZE || offset + parsed_length > sizeof(sm->vdf_input_buffer)) {
        sm->state = DUEL_STATE_ABORTED;
        return (duel_status_t)ERR_BUFFER_OVERFLOW;
    }
    write_be32(&sm->vdf_input_buffer[offset], sm->aggregator_reveal.len);
    offset += 4;
    memcpy(&sm->vdf_input_buffer[offset], sm->aggregator_reveal.data, sm->aggregator_reveal.len);
    offset += sm->aggregator_reveal.len;

    parsed_length = 4 + (size_t)sm->contributor_reveal.len;
    if (offset + parsed_length > MAX_BUNDLE_SIZE || offset + parsed_length > sizeof(sm->vdf_input_buffer)) {
        sm->state = DUEL_STATE_ABORTED;
        return (duel_status_t)ERR_BUFFER_OVERFLOW;
    }
    write_be32(&sm->vdf_input_buffer[offset], sm->contributor_reveal.len);
    offset += 4;
    memcpy(&sm->vdf_input_buffer[offset], sm->contributor_reveal.data, sm->contributor_reveal.len);
    offset += sm->contributor_reveal.len;

    sm->vdf_input_len = offset;
    sm->straggler_fallback_active = false;
    sm->state = DUEL_STATE_VDF_EVALUATION;

    /*
     * Decoupled Metronome:
     * Immediately upon successfully bundling a valid 2-of-2 payload at the
     * 2000ms buzzer, the Aggregator must call the network function to push
     * the raw Signed_Reveal_Bundle to the P2P socket. This locks in the inputs
     * globally before VDF execution begins.
     */
    if (sm->push_reveal_bundle) {
        sm->push_reveal_bundle(sm->vdf_input_buffer, sm->vdf_input_len, sm->network_ctx);
    }
    if (sm->p2p_socket_fd >= 0 && sm->vdf_input_len > 0) {
        (void)send(sm->p2p_socket_fd, sm->vdf_input_buffer, sm->vdf_input_len, 0);
    }

    return DUEL_SUCCESS;
}

duel_status_t execute_vdf_loop(duel_state_machine_t *sm, vdf_context_t *ctx, uint8_t output[32]) {
    if (!sm || !ctx || !output) {
        return DUEL_ERR_INVALID_ARGUMENT;
    }
    if (sm->state != DUEL_STATE_VDF_EVALUATION) {
        return DUEL_ERR_INVALID_STATE;
    }

    /* Initial Equivocation_Proof check */
    bool equivocation_found = false;
    if (sm->check_equivocation_proof) {
        equivocation_found = sm->check_equivocation_proof(sm->p2p_socket_fd, sm->network_ctx);
    } else if (sm->p2p_socket_fd >= 0) {
        struct pollfd pfd;
        pfd.fd = sm->p2p_socket_fd;
        pfd.events = POLLIN;
        int p_res = poll(&pfd, 1, 0);
        if (p_res > 0 && (pfd.revents & POLLIN)) {
            uint8_t proof_buf[256];
            ssize_t n = recv(sm->p2p_socket_fd, proof_buf, sizeof(proof_buf), MSG_PEEK);
            if (n > 0) {
                equivocation_found = true;
            }
        }
    }

    if (equivocation_found) {
        sm->aggregator_slashed = true;
        sm->state = DUEL_STATE_ABORTED;
        return ERR_EQUIVOCATION_DETECTED;
    }

#if defined(DETERM_DSF_ENABLED)
    uint64_t target_ms = 0;
    if (determ_dsf_get_vdf_bypass(&target_ms)) {
        if (vdf_evaluate(ctx, output) != 0) {
            sm->state = DUEL_STATE_ABORTED;
            return DUEL_ERR_INVALID_STATE;
        }
        sm->state = DUEL_STATE_FINALIZED;
        return DUEL_SUCCESS;
    }
#endif

    uint64_t total_iters = ctx->iterations;
    uint64_t step_iters = 10000ULL;
    uint64_t current = 0;

    while (current < total_iters) {
        uint64_t chunk = total_iters - current;
        if (chunk > step_iters) {
            chunk = step_iters;
        }

        /*
         * Asynchronous poll() check every 10,000 iterations:
         * Check incoming P2P socket for an Equivocation_Proof.
         */
        equivocation_found = false;
        if (sm->check_equivocation_proof) {
            equivocation_found = sm->check_equivocation_proof(sm->p2p_socket_fd, sm->network_ctx);
        } else if (sm->p2p_socket_fd >= 0) {
            struct pollfd pfd;
            pfd.fd = sm->p2p_socket_fd;
            pfd.events = POLLIN;
            int p_res = poll(&pfd, 1, 0);
            if (p_res > 0 && (pfd.revents & POLLIN)) {
                uint8_t proof_buf[256];
                ssize_t n = recv(sm->p2p_socket_fd, proof_buf, sizeof(proof_buf), MSG_PEEK);
                if (n > 0) {
                    equivocation_found = true;
                }
            }
        }

        if (equivocation_found) {
            sm->aggregator_slashed = true;
            sm->state = DUEL_STATE_ABORTED;
            return ERR_EQUIVOCATION_DETECTED;
        }

        current += chunk;
    }

    if (vdf_evaluate(ctx, output) != 0) {
        sm->state = DUEL_STATE_ABORTED;
        return DUEL_ERR_INVALID_STATE;
    }

    sm->cumulative_vdf_iterations += ctx->iterations;
    sm->state = DUEL_STATE_FINALIZED;
    return DUEL_SUCCESS;
}

void duel_state_accumulate_work(duel_state_machine_t *sm, uint64_t vdf_iterations) {
    if (sm) {
        sm->cumulative_vdf_iterations += vdf_iterations;
    }
}

uint64_t duel_state_get_cumulative_work(const duel_state_machine_t *sm) {
    return sm ? sm->cumulative_vdf_iterations : 0ULL;
}

static uint64_t calculate_branch_cumulative_work(const duel_block_header_t *chain, size_t count) {
    if (!chain || count == 0) return 0ULL;
    uint64_t total = 0;
    for (size_t i = 0; i < count; i++) {
        if (chain[i].cumulative_vdf_iterations > 0 && i == count - 1 && total == 0) {
            return chain[i].cumulative_vdf_iterations;
        }
        total += chain[i].vdf_iterations;
    }
    return total;
}

/*
 * Nakamoto Heaviest-Chain Fork Choice Rule (PoSW):
 * When conflicting block headers (a fork) arrive at the same height,
 * the node evaluates the sum of vdf_iterations across competing chains.
 * The branch with the highest cumulative sequential work becomes canonical tip.
 */
int duel_resolve_fork_choice(duel_state_machine_t *sm,
                             const duel_block_header_t *chain_a, size_t count_a,
                             const duel_block_header_t *chain_b, size_t count_b,
                             const duel_block_header_t **canonical_tip) {
    if (!chain_a && !chain_b) {
        if (canonical_tip) *canonical_tip = NULL;
        return 0;
    }
    if (!chain_a || count_a == 0) {
        if (canonical_tip) *canonical_tip = (chain_b && count_b > 0) ? &chain_b[count_b - 1] : NULL;
        if (sm && chain_b && count_b > 0) {
            sm->cumulative_vdf_iterations = calculate_branch_cumulative_work(chain_b, count_b);
        }
        return 1;
    }
    if (!chain_b || count_b == 0) {
        if (canonical_tip) *canonical_tip = &chain_a[count_a - 1];
        if (sm) {
            sm->cumulative_vdf_iterations = calculate_branch_cumulative_work(chain_a, count_a);
        }
        return -1;
    }

    uint64_t work_a = calculate_branch_cumulative_work(chain_a, count_a);
    uint64_t work_b = calculate_branch_cumulative_work(chain_b, count_b);

    if (work_b > work_a) {
        if (canonical_tip) *canonical_tip = &chain_b[count_b - 1];
        if (sm) {
            sm->cumulative_vdf_iterations = work_b;
        }
        return 1;
    } else if (work_a > work_b) {
        if (canonical_tip) *canonical_tip = &chain_a[count_a - 1];
        if (sm) {
            sm->cumulative_vdf_iterations = work_a;
        }
        return -1;
    }

    /* Equal cumulative work: deterministic tiebreak on lowest block hash */
    const duel_block_header_t *tip_a = &chain_a[count_a - 1];
    const duel_block_header_t *tip_b = &chain_b[count_b - 1];
    int cmp = memcmp(tip_a->block_hash, tip_b->block_hash, 32);
    if (cmp > 0) {
        if (canonical_tip) *canonical_tip = tip_b;
        if (sm) {
            sm->cumulative_vdf_iterations = work_b;
        }
        return 1;
    } else {
        if (canonical_tip) *canonical_tip = tip_a;
        if (sm) {
            sm->cumulative_vdf_iterations = work_a;
        }
        return (cmp == 0) ? 0 : -1;
    }
}

int duel_resolve_fork_headers(duel_state_machine_t *sm,
                              const duel_block_header_t *header_a,
                              const duel_block_header_t *header_b,
                              const duel_block_header_t **canonical_tip) {
    if (!header_a && !header_b) {
        if (canonical_tip) *canonical_tip = NULL;
        return 0;
    }
    if (!header_a) {
        if (canonical_tip) *canonical_tip = header_b;
        if (sm && header_b) {
            sm->cumulative_vdf_iterations = header_b->cumulative_vdf_iterations > 0 ?
                header_b->cumulative_vdf_iterations : header_b->vdf_iterations;
        }
        return 1;
    }
    if (!header_b) {
        if (canonical_tip) *canonical_tip = header_a;
        if (sm) {
            sm->cumulative_vdf_iterations = header_a->cumulative_vdf_iterations > 0 ?
                header_a->cumulative_vdf_iterations : header_a->vdf_iterations;
        }
        return -1;
    }

    uint64_t work_a = header_a->cumulative_vdf_iterations > 0 ?
        header_a->cumulative_vdf_iterations : header_a->vdf_iterations;
    uint64_t work_b = header_b->cumulative_vdf_iterations > 0 ?
        header_b->cumulative_vdf_iterations : header_b->vdf_iterations;

    if (work_b > work_a) {
        if (canonical_tip) *canonical_tip = header_b;
        if (sm) {
            sm->cumulative_vdf_iterations = work_b;
        }
        return 1;
    } else if (work_a > work_b) {
        if (canonical_tip) *canonical_tip = header_a;
        if (sm) {
            sm->cumulative_vdf_iterations = work_a;
        }
        return -1;
    }

    int cmp = memcmp(header_a->block_hash, header_b->block_hash, 32);
    if (cmp > 0) {
        if (canonical_tip) *canonical_tip = header_b;
        if (sm) {
            sm->cumulative_vdf_iterations = work_b;
        }
        return 1;
    } else {
        if (canonical_tip) *canonical_tip = header_a;
        if (sm) {
            sm->cumulative_vdf_iterations = work_a;
        }
        return (cmp == 0) ? 0 : -1;
    }
}

const char* duel_state_name(duel_state_t state) {
    switch (state) {
        case DUEL_STATE_IDLE:                 return "IDLE";
        case DUEL_STATE_COMMITMENT_PHASE:     return "COMMITMENT_PHASE";
        case DUEL_STATE_AWAITING_REVEALS:     return "AWAITING_REVEALS";
        case DUEL_STATE_REVEAL_BUFFER_LOCKED: return "REVEAL_BUFFER_LOCKED";
        case DUEL_STATE_VDF_EVALUATION:       return "VDF_EVALUATION";
        case DUEL_STATE_FINALIZED:            return "FINALIZED";
        case DUEL_STATE_ABORTED:              return "ABORTED";
        default:                              return "UNKNOWN";
    }
}
