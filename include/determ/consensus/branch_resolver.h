/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Determ PoSW Heaviest-Chain Branch Resolver (Pure C99).
 * Implements Nakamoto-style heaviest-chain fork choice rule:
 * When competing blocks/branches are received at the same height, the node
 * strictly adopts the branch with the highest cumulative VDF iterations.
 */

#ifndef DETERMINISTIC_CONSENSUS_BRANCH_RESOLVER_H
#define DETERMINISTIC_CONSENSUS_BRANCH_RESOLVER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t height;
    uint8_t  block_hash[32];
    uint8_t  prev_hash[32];
    uint64_t cumulative_vdf_iterations;
    uint64_t timestamp;
} posw_block_candidate_t;

typedef struct {
    posw_block_candidate_t canonical_tip;
    bool                   has_tip;
} posw_branch_resolver_t;

/*
 * Initialize the branch resolver.
 * If initial_tip is non-NULL, sets the canonical tip to initial_tip.
 */
void posw_branch_resolver_init(posw_branch_resolver_t *resolver,
                               const posw_block_candidate_t *initial_tip);

/*
 * Compare two candidate blocks / branches.
 * Returns:
 *   1 if a is heavier than b (higher cumulative_vdf_iterations, or tie-break won)
 *  -1 if b is heavier than a
 *   0 if identical in weight and hash
 */
int posw_compare_candidates(const posw_block_candidate_t *a,
                            const posw_block_candidate_t *b);

/*
 * Consider a candidate block for adoption into the canonical chain.
 * If the candidate has higher cumulative_vdf_iterations than the current tip
 * (or wins tie-break on equal weight), the resolver adopts it as the new canonical tip.
 *
 * Returns:
 *   true  - candidate was adopted as the new canonical tip.
 *   false - candidate was rejected (lighter or equal-and-lost tie-break).
 */
bool posw_branch_resolver_consider(posw_branch_resolver_t *resolver,
                                   const posw_block_candidate_t *candidate);

/*
 * Get the current canonical tip. Returns NULL if no tip has been set.
 */
const posw_block_candidate_t *posw_branch_resolver_get_tip(const posw_branch_resolver_t *resolver);

#ifdef __cplusplus
}
#endif

#endif /* DETERMINISTIC_CONSENSUS_BRANCH_RESOLVER_H */
