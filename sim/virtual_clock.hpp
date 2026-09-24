// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// DSF (Deterministic-Simulation Framework) INCREMENT 1 — virtual clock.
// Per docs/proofs/DSF-SPEC.md §1 substitution 1 and §4.1.
//
// A deterministic, monotonic virtual clock. Time NEVER advances on its own:
// no std::chrono::steady_clock::now(), no wall-clock reads. The scheduler
// (sim/scheduler.hpp) advances this clock to the timestamp of the next event
// it pops. Because advance is driven only by scheduled events, a fixed seed
// produces a byte-identical sequence of clock values across runs and hosts.
//
// SCOPE (increment 1): this is the SIM-CORE clock — a standalone virtual time
// source for the discrete-event simulator. It is intentionally NOT the
// production determ::time::Clock interface sketched in DSF-SPEC §Q1 (that
// dependency-injection refactor of Node/Validator/Producer threads a Clock&
// through real consensus code and lands in a LATER increment). Keeping this
// self-contained lets the framework compile + run in isolation.
#pragma once
#include <cstdint>

namespace determ::sim {

// Virtual timestamp: nanoseconds since sim start (arbitrary origin = 0).
// Unsigned 64-bit; monotonic non-decreasing over a run.
using VTime = uint64_t;

// Convenience virtual-duration constructors (all -> VTime nanoseconds).
// These are pure integer conversions — no wall-clock involved.
constexpr VTime vt_ns(uint64_t n)  { return n; }
constexpr VTime vt_us(uint64_t n)  { return n * 1000ull; }
constexpr VTime vt_ms(uint64_t n)  { return n * 1000000ull; }
constexpr VTime vt_s(uint64_t n)   { return n * 1000000000ull; }

// Deterministic monotonic virtual clock.
//
// Invariant: now() is non-decreasing. advance_to() may only move time
// forward (or hold it); moving backward is a caller bug and is rejected
// (the value is clamped to the current time, never regressed). This keeps
// the event ordering total and reproducible even if a scenario schedules a
// stale event.
class VirtualClock {
public:
    VirtualClock() = default;

    // Current virtual time (nanoseconds since origin).
    VTime now() const { return now_; }

    // Advance to an absolute virtual timestamp. Monotonic: never regresses.
    // Returns the resulting (possibly clamped) time.
    VTime advance_to(VTime t) {
        if (t > now_) now_ = t;
        return now_;
    }

    // Advance by a relative virtual duration.
    VTime advance_by(VTime delta) {
        now_ += delta;
        return now_;
    }

    // Reset to origin (used between scenario runs on a reused clock).
    void reset() { now_ = 0; }

private:
    VTime now_ = 0;
};

} // namespace determ::sim
