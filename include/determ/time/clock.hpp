// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// §Q1 time::Clock — the consensus/production wall-clock injection seam
// (docs/proofs/DSF-SPEC.md §Q1; DSF §Q1/§Q2 dependency injection).
//
// The ENTIRE consensus tree reads wall time through ONE helper,
// determ::now_unix() (include/determ/types.hpp): int64 seconds since the Unix
// epoch, from std::chrono::system_clock. Every digest-bound timestamp
// (proposer_time and abort-event ts -> block digest -> K-of-K signatures ->
// state roots) is a plain integer derived from that helper, so the digest bytes
// depend ONLY on the integer, never on how it was sourced.
//
// This interface lets that single source be INJECTED so the DSF can eventually
// drive the real engine under a deterministic virtual clock. The production
// default, RealClock, delegates to determ::now_unix() VERBATIM — a literal
// one-line forward — so the default path stays BYTE-IDENTICAL to today (goldens
// + all determinism vectors unchanged). See docs/proofs/ClockInjectionSeam.md.
#pragma once
#include <chrono>
#include <cstdint>
#include <determ/types.hpp>

namespace determ::time {

// Read-only clock consumer interface. Two reads, deliberately separated so the
// consensus read can NEVER be routed through a monotonic/epoch-less source:
//   - unix_seconds(): CONSENSUS-bound wall time. MUST be byte-identical to
//     determ::now_unix() on the production path (int64 seconds, system_clock).
//   - steady_now(): NON-digest scheduling time (timeouts, freshness deltas,
//     profiling). Monotonic; never enters a digest.
class Clock {
public:
    virtual ~Clock() = default;
    virtual int64_t unix_seconds() const = 0;
    virtual std::chrono::steady_clock::time_point steady_now() const = 0;
};

// Production clock. unix_seconds() is a VERBATIM one-line delegate to
// determ::now_unix(): same clock (system_clock, NOT steady_clock), same
// duration_cast<seconds> truncation, same int64_t width. This equality is the
// entire byte-invariance guarantee for the default consensus path.
class RealClock final : public Clock {
public:
    static RealClock& instance() {
        static RealClock c;
        return c;
    }
    int64_t unix_seconds() const override { return determ::now_unix(); }
    std::chrono::steady_clock::time_point steady_now() const override {
        return std::chrono::steady_clock::now();
    }
};

} // namespace determ::time
