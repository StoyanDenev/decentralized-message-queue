// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// The randomized registration/deregistration activation delay — the ONE
// formula (S-043 discipline: every consensus formula gets exactly one
// definition), extracted from src/chain/chain.cpp's former static
// derive_delay in R52 so the light client's registry tracking
// (light/trustless_read.cpp --track-registry) computes the SAME
// activation heights the full node's apply does, by construction rather
// than by mirrored reimplementation.
//
// Header-only (inline) because determ-light deliberately does NOT link
// chain/chain.cpp (its CMake reuse list is explicit + minimal); an inline
// definition in a shared header is linked into both binaries from one
// token sequence. CONSENSUS-CRITICAL: `active_from`/`inactive_from` are
// committed into the r: state namespace (state_root), so any change to
// this formula is a consensus change.
#pragma once
#include <determ/types.hpp>
#include <determ/crypto/sha256.hpp>

namespace determ::chain {

// Window duplicated from node/registry.hpp REGISTRATION_DELAY_WINDOW (the
// same duplication note chain.cpp carried; the value is genesis-frozen).
inline constexpr uint64_t REGISTRATION_DELAY_WINDOW_BLOCKS = 10;

// Compute the randomized 1..REGISTRATION_DELAY_WINDOW delay, deterministically
// derived from the block's cumulative_rand and the tx hash so all nodes agree
// and the operator can't pick their own activation height.
inline uint64_t derive_registration_delay(const Hash& cumulative_rand,
                                          const Hash& tx_hash) {
    Hash seed = crypto::sha256(tx_hash, cumulative_rand);
    uint64_t v = 0;
    for (int b = 0; b < 8; ++b) v = (v << 8) | seed[b];
    return 1 + (v % REGISTRATION_DELAY_WINDOW_BLOCKS);
}

} // namespace determ::chain
