/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Determ PoSW Heaviest-Chain Branch Resolver (Pure C99).
 */

#include <determ/consensus/branch_resolver.h>
#include <string.h>

void posw_branch_resolver_init(posw_branch_resolver_t *resolver,
                               const posw_block_candidate_t *initial_tip) {
    if (!resolver) return;
    memset(resolver, 0, sizeof(*resolver));
    if (initial_tip) {
        resolver->canonical_tip = *initial_tip;
        resolver->has_tip = true;
    }
}

int posw_compare_candidates(const posw_block_candidate_t *a,
                            const posw_block_candidate_t *b) {
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;

    /* Rule 1: Highest cumulative VDF iterations strictly wins (Heaviest-Chain) */
    if (a->cumulative_vdf_iterations > b->cumulative_vdf_iterations) {
        return 1;
    }
    if (a->cumulative_vdf_iterations < b->cumulative_vdf_iterations) {
        return -1;
    }

    /* Rule 2: Deterministic tie-breaker on identical cumulative weight */
    /* Lexicographically smaller block hash wins */
    int cmp = memcmp(a->block_hash, b->block_hash, sizeof(a->block_hash));
    if (cmp < 0) return 1;
    if (cmp > 0) return -1;

    return 0;
}

bool posw_branch_resolver_consider(posw_branch_resolver_t *resolver,
                                   const posw_block_candidate_t *candidate) {
    if (!resolver || !candidate) return false;

    if (!resolver->has_tip) {
        resolver->canonical_tip = *candidate;
        resolver->has_tip = true;
        return true;
    }

    /* Compare candidate against current canonical tip */
    int cmp = posw_compare_candidates(candidate, &resolver->canonical_tip);
    if (cmp > 0) {
        /* Candidate is heavier: re-org / extend tip to candidate */
        resolver->canonical_tip = *candidate;
        return true;
    }

    /* Lighter or lost tie-break: retain existing tip */
    return false;
}

const posw_block_candidate_t *posw_branch_resolver_get_tip(const posw_branch_resolver_t *resolver) {
    if (!resolver || !resolver->has_tip) return NULL;
    return &resolver->canonical_tip;
}
