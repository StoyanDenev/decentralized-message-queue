// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// crypto::RngSource — the consensus RNG injection seam (the entropy analogue of
// the §Q1 time::Clock seam, docs/proofs/ClockInjectionSeam.md). It exists for
// the SAME reason: to let the ONE piece of per-round randomness that enters
// block content be INJECTED, so the FA harness can drive the real engine under
// a deterministic source and replay a Byzantine schedule byte-for-byte (the
// A4 S-048 reorg reproduction — DeterministicSchedulerDesign.md §3, inc.5).
//
// The single consensus draw is the Phase-1 commit-reveal dh_secret in
// Node::start_contrib_phase (src/node/node.cpp): 32 fresh bytes per round,
// revealed in the BlockSigMsg and folded into the block's cumulative_rand, so
// they are the ONLY thing that makes two honest runs of the same schedule
// diverge in block bytes. Every other entropy call is off the consensus path
// (node key generation is once-per-setup; the dapp-subscriber session id and
// the genesis shard-address salt never enter a block or state root).
//
// The production default, RealRng, delegates to determ_rng_bytes VERBATIM (the
// §3.15 OS-CSPRNG shim) — a literal one-line forward — so the default consensus
// path stays BYTE-IDENTICAL to today (goldens + every determinism vector
// unchanged). Only a test harness ever constructs a different source; the Node
// ctor defaults this parameter to RealRng, so the daemon is untouched.
#pragma once
#include <cstddef>
#include <cstdint>
#include <determ/crypto/rng/rng.h>   // determ_rng_bytes (C99 OS-entropy shim)

namespace determ::crypto {

// Consensus RNG consumer interface. fill() mirrors determ_rng_bytes's contract
// EXACTLY so the single call site's fail-closed check is unchanged: fill
// buf[0..n) and return 0 on success; on failure return non-zero and leave buf
// undefined (the caller MUST NOT use it). n == 0 is a no-op success.
class RngSource {
public:
    virtual ~RngSource() = default;
    virtual int fill(uint8_t* buf, std::size_t n) = 0;
};

// Production RNG — a VERBATIM one-line delegate to determ_rng_bytes (the OS
// CSPRNG). This equality is the entire byte-invariance guarantee for the
// default consensus path: with RealRng injected (the ctor default) the block
// bytes are produced by the exact same call as before the seam existed.
class RealRng final : public RngSource {
public:
    static RealRng& instance() {
        static RealRng r;
        return r;
    }
    int fill(uint8_t* buf, std::size_t n) override {
        return determ_rng_bytes(buf, n);
    }
};

} // namespace determ::crypto
