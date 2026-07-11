// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// crypto::SeededRng — the TEST-ONLY deterministic RngSource (the entropy
// analogue of time::VirtualClock). It lets an FA harness give the real engine a
// reproducible per-round dh_secret so a Byzantine schedule replays byte-for-byte
// — the deterministic S-048 reorg reproduction gate (DeterministicScheduler
// Design.md §3, inc.5). NEVER wired into the daemon: the Node ctor defaults to
// RealRng (rng_source.hpp); only a harness constructs this.
//
// Byte-portability is the whole point — goldens are compared across MSVC and
// GCC — so the stream is built from the in-tree determ::c99 SHA-256 (an exact,
// platform-independent function), NOT std::mt19937 or any libstdc++ engine.
// Each 32-byte output block is SHA256(seed32 || counter) where the counter is
// appended via SHA256Builder::append(uint64_t) — a FIXED big-endian encoding,
// so the stream is byte-identical on every platform; fill() streams consecutive
// blocks and copies the first n bytes. A fresh SeededRng(seed)
// therefore produces one fixed byte sequence on every platform and every run.
//
// This is deliberately NOT a cryptographically strong DRBG (no reseed, no
// backtracking resistance): its only job is reproducibility for a test. A
// distinct seed per node yields a distinct, fixed dh_secret stream — exactly
// what a same-height fork repro needs (two creators, two known secrets, so the
// resolve_fork "smallest block hash" tie-break is itself deterministic).
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <determ/crypto/rng_source.hpp>
#include <determ/crypto/sha256.hpp>   // determ::crypto::SHA256Builder
#include <determ/types.hpp>           // determ::Hash

namespace determ::crypto {

class SeededRng final : public RngSource {
public:
    explicit SeededRng(const std::array<uint8_t, 32>& seed) : seed_(seed) {}

    // Convenience: seed from a small integer (the low 8 bytes, little-endian;
    // the rest zero). Distinct integers give distinct streams.
    explicit SeededRng(uint64_t seed) {
        seed_.fill(0);
        for (int i = 0; i < 8; ++i)
            seed_[static_cast<std::size_t>(i)] =
                static_cast<uint8_t>(seed >> (8 * i));
    }

    int fill(uint8_t* buf, std::size_t n) override {
        std::size_t off = 0;
        while (off < n) {
            // block = SHA256(seed || counter). Hash overload + uint64_t overload
            // give a fixed, cross-platform encoding (determ::c99, not libstdc++).
            Hash block = SHA256Builder{}
                             .append(seed_)
                             .append(counter_)
                             .finalize();
            ++counter_;
            std::size_t take = (n - off < 32) ? (n - off) : 32;
            std::memcpy(buf + off, block.data(), take);
            off += take;
        }
        return 0;   // deterministic source never fails
    }

private:
    std::array<uint8_t, 32> seed_{};
    uint64_t                counter_ = 0;
};

} // namespace determ::crypto
