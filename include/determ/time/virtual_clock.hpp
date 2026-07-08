// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// §Q1 VirtualClock — a test/DSF-driven Clock whose unix time is injected and
// advanced by the harness rather than read from the OS. It exists ONLY to drive
// the real engine under a chosen wall time; it is never the production default
// (RealClock is). Because the consensus digest binds the int64 SECONDS value and
// nothing about how that value was sourced (see clock.hpp), a Node constructed
// with a VirtualClock produces blocks whose digest-bound timestamps equal the
// injected virtual time exactly — the property test-virtual-clock demonstrates.
//
// Thread-safety: unix_ is a std::atomic, so set_unix/advance from a harness
// thread and unix_seconds()/steady_now() from the engine's loop thread are
// data-race-free. Ordering across the two is the harness's responsibility (a
// virtual-time harness advances the clock at quiescent points).
#pragma once
#include <atomic>
#include <chrono>
#include <cstdint>
#include <determ/time/clock.hpp>

namespace determ::time {

class VirtualClock final : public Clock {
public:
    // WARNING (harness footgun): seed a REALISTIC non-zero epoch (e.g. ≥1.5e9).
    // proposer_time == 0 is the consensus LEGACY SENTINEL — a block whose lone/
    // all committed proposer_times are 0 has reconciliation DISABLED (the vector
    // is cleared, timestamp falls back to the producer's real now_unix() and is
    // left UNBOUND), and the ±30s freshness gate (|0 - real_now| ≈ 1.7e9) rejects
    // it. start_unix=0 is fine ONLY for tests that never drive block production.
    explicit VirtualClock(int64_t start_unix = 0) : unix_(start_unix) {}

    // CONSENSUS-bound read. Returns the injected virtual seconds verbatim; this
    // is the value that flows proposer_time -> block.timestamp -> digest.
    int64_t unix_seconds() const override { return unix_.load(std::memory_order_acquire); }

    // NON-digest scheduling read. Derived deterministically from the same
    // injected unix value so a virtual-time harness sees a single, controllable
    // time base. Never enters a digest, so the epoch offset is immaterial.
    std::chrono::steady_clock::time_point steady_now() const override {
        return std::chrono::steady_clock::time_point{} +
               std::chrono::seconds(unix_.load(std::memory_order_acquire));
    }

    // Harness controls. set_unix pins an absolute virtual time; advance moves it
    // forward (or back, for adversarial tests) by delta seconds.
    void set_unix(int64_t v) { unix_.store(v, std::memory_order_release); }
    void advance(int64_t delta) { unix_.fetch_add(delta, std::memory_order_acq_rel); }

private:
    std::atomic<int64_t> unix_;
};

} // namespace determ::time
