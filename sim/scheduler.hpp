// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// DSF (Deterministic-Simulation Framework) INCREMENT 1 — discrete-event
// scheduler + seeded PRNG. Per docs/proofs/DSF-SPEC.md §4.3.
//
// The scheduler is the deterministic heart of the simulator. It holds a
// priority queue of events keyed on (VTime, insertion_seq). Ties in virtual
// time break on insertion_seq, which is a strictly increasing counter — so
// event ordering is TOTAL and reproducible. There is no wall-clock, no thread
// scheduling, no real RNG: given the same seed and the same scenario, the pop
// order is byte-identical on every host.
//
// The PRNG (splitmix64) is written inline and threaded EXPLICITLY through the
// scheduler. Scenario code draws randomness only via Scheduler::rng() so that
// every random choice routes through the seed (DSF-SPEC §Q5 reproducibility).
#pragma once
#include <cstdint>
#include <functional>
#include <queue>
#include <vector>
#include "virtual_clock.hpp"

namespace determ::sim {

// ---------------------------------------------------------------------------
// splitmix64 — a tiny, fast, well-distributed seeded PRNG. Written inline so
// the sim core has NO external RNG dependency and NO OS entropy. Every draw is
// a pure function of the internal 64-bit state, which is seeded once from the
// run seed. Same seed => identical stream, on any platform / compiler.
// Reference: Steele, Lea, Flood (2014) "Fast splittable pseudorandom
// number generators". Public-domain algorithm.
// ---------------------------------------------------------------------------
class SplitMix64 {
public:
    explicit SplitMix64(uint64_t seed) : state_(seed) {}

    // Next 64-bit value. Deterministic; advances state.
    uint64_t next_u64() {
        uint64_t z = (state_ += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }

    // Uniform in [0, bound). bound must be > 0. Uses rejection sampling to
    // avoid modulo bias — deterministic and unbiased across the full range.
    uint64_t next_below(uint64_t bound) {
        if (bound == 0) return 0;
        uint64_t threshold = -bound % bound; // == (2^64 - bound) % bound
        for (;;) {
            uint64_t r = next_u64();
            if (r >= threshold) return r % bound;
        }
    }

    // Uniform double in [0, 1). Deterministic; uses the top 53 bits.
    double next_unit() {
        return (next_u64() >> 11) * (1.0 / 9007199254740992.0); // 2^53
    }

    // Deterministic Bernoulli trial: true with probability p (clamped [0,1]).
    bool bernoulli(double p) {
        if (p <= 0.0) return false;
        if (p >= 1.0) return true;
        return next_unit() < p;
    }

    uint64_t state() const { return state_; }

private:
    uint64_t state_;
};

// ---------------------------------------------------------------------------
// Event — a callback scheduled to fire at a virtual timestamp. The scheduler
// owns the callback and invokes it once when popped.
// ---------------------------------------------------------------------------
using EventFn = std::function<void()>;

struct Event {
    VTime    at;          // virtual time the event fires
    uint64_t seq;         // insertion order — deterministic tie-break
    EventFn  fn;          // the action

    // Min-heap ordering: earlier time first, then lower seq first. Note the
    // reversed comparison because std::priority_queue is a MAX-heap.
    bool operator<(const Event& o) const {
        if (at != o.at) return at > o.at;
        return seq > o.seq;
    }
};

// ---------------------------------------------------------------------------
// Scheduler — deterministic discrete-event loop. run() pops events in
// (VTime, seq) order, advancing the virtual clock to each event's timestamp,
// until the queue drains or a stop condition trips.
// ---------------------------------------------------------------------------
class Scheduler {
public:
    explicit Scheduler(uint64_t seed)
        : rng_(seed), seed_(seed) {}

    VirtualClock& clock()       { return clock_; }
    SplitMix64&   rng()         { return rng_; }
    uint64_t      seed() const  { return seed_; }
    VTime         now() const   { return clock_.now(); }

    // Schedule fn to fire at absolute virtual time `at`. If `at` is in the
    // past (< now), it is clamped to now — the event fires immediately after
    // the current one, preserving monotonicity. Returns the event seq.
    uint64_t schedule_at(VTime at, EventFn fn) {
        VTime t = at < clock_.now() ? clock_.now() : at;
        uint64_t s = next_seq_++;
        pq_.push(Event{t, s, std::move(fn)});
        return s;
    }

    // Schedule fn to fire `delay` after the current virtual time.
    uint64_t schedule_after(VTime delay, EventFn fn) {
        return schedule_at(clock_.now() + delay, std::move(fn));
    }

    // Request the run loop stop after the current event completes.
    void stop() { stop_requested_ = true; }

    // Number of pending events (does not fire them).
    size_t pending() const { return pq_.size(); }

    // Total events fired so far this run.
    uint64_t fired() const { return fired_; }

    // Run to completion (or until stop() / max_events). Fires events in
    // deterministic (VTime, seq) order, advancing the clock to each event.
    // `max_events` guards against runaway self-rescheduling scenarios; 0 =
    // unbounded. Returns the number of events fired.
    uint64_t run(uint64_t max_events = 0) {
        stop_requested_ = false;
        while (!pq_.empty()) {
            if (stop_requested_) break;
            if (max_events != 0 && fired_ >= max_events) break;
            Event ev = pq_.top();
            pq_.pop();
            clock_.advance_to(ev.at);
            ++fired_;
            ev.fn(); // may schedule further events
        }
        return fired_;
    }

    // Reset for reuse on a fresh run of the same or a different seed.
    void reseed(uint64_t seed) {
        rng_  = SplitMix64(seed);
        seed_ = seed;
        clock_.reset();
        // drain queue
        while (!pq_.empty()) pq_.pop();
        next_seq_       = 0;
        fired_          = 0;
        stop_requested_ = false;
    }

private:
    VirtualClock clock_;
    SplitMix64   rng_;
    uint64_t     seed_;
    std::priority_queue<Event> pq_;
    uint64_t     next_seq_       = 0;
    uint64_t     fired_          = 0;
    bool         stop_requested_ = false;
};

} // namespace determ::sim
