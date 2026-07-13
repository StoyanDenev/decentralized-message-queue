// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// GlobalScheduler — the deterministic global multi-loop driver
// (DeterministicSchedulerDesign.md §3.4 / increment 4). Given N
// VirtualEventLoops (each in virtual-time mode), it imposes ONE global
// logical-time order over them:
//   (a) FIXPOINT-drain ready work across ALL loops in index order until a full
//       sweep runs zero closures. Cross-loop transport deliveries are ready
//       work (a State::post onto the peer loop's FIFO — NOT a timer), so the
//       fixpoint sweep settles every in-flight message before time advances.
//   (b) When no loop has ready work, peek every loop's next virtual-timer
//       deadline and fire the SINGLE global-earliest (tie-break: lowest loop
//       index). Before firing, lockstep EVERY loop's virtual `now` forward to
//       that deadline so a loop that arms a timer during the ensuing drain
//       dates it from the GLOBAL clock, not a stale per-loop now (which would
//       past-date the deadline and move logical time backwards — §3.4 hazard).
//   (c) Stop when a `done` predicate holds, or the cluster goes quiescent
//       (no ready work AND no pending timers anywhere).
//
// DETERMINISM. The fixed loop-index fixpoint sweep + per-loop FIFO drain +
// global-earliest-timer selection is a pure function of (initial queues, timer
// schedule) — a single total order that replays identically from the same
// seeds, with ZERO change to State::post (no global sequence stamp needed for
// inc.4; the design defers that + per-link latency to inc.5). It accumulates a
// compact action trace — "D<n>;" per non-empty drain sweep, "T<loop>@<ms>;"
// per fired timer — that the harness hashes as the REPLAY SIGNATURE: the only
// signal that catches a schedule interleave which diverges yet converges to the
// same chain (which is precisely the determinism inc.4 introduces).
//
// TEST-ONLY. Drives concrete VirtualEventLoops single-threaded; never used in
// production (which always uses the threaded run()). NOT thread-safe against a
// concurrent run() on any driven loop. The two VirtualEventLoop accessors it
// relies on (next_virtual_deadline_ms / set_virtual_now_ms) are virtual-time
// mode only and have no production caller, so run() stays byte-invariant.
#pragma once
#include <determ/net/virtual_transport.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace determ::net {

class GlobalScheduler {
public:
    explicit GlobalScheduler(std::vector<VirtualEventLoop*> loops)
        : loops_(std::move(loops)) {}

    // The furthest global logical time (ms) advanced to so far.
    uint64_t now_ms() const { return global_now_ms_; }
    // The accumulated action trace — hash it for the replay signature.
    const std::string& trace() const { return trace_; }

    // Drive until `done()` returns true, or the cluster goes quiescent — the
    // final value of done() is returned either way. `batch` bounds each per-loop
    // run_ready step so a self-producing loop (finalize re-posts the next round
    // with no timer gate) cannot hang the drain; done() is checked each sweep so
    // it is the real terminator. `max_steps` is a runaway guard.
    template <class Pred>
    bool run_until(Pred done, std::size_t batch = 4096,
                   std::size_t max_steps = 5000000) {
        for (std::size_t step = 0; step < max_steps; ++step) {
            // (a) fixpoint-drain ready work across ALL loops
            for (;;) {
                if (done()) return true;
                std::size_t ran = 0;
                for (auto* lp : loops_) ran += lp->run_ready(batch);
                if (ran == 0) break;
                trace_ += 'D';
                trace_ += std::to_string(ran);
                trace_ += ';';
            }
            if (done()) return true;
            // (b) fire the SINGLE global-earliest virtual timer
            std::size_t best_i = kNone;
            uint64_t    best_d = 0, d = 0;
            for (std::size_t i = 0; i < loops_.size(); ++i)
                if (loops_[i]->next_virtual_deadline_ms(d) &&
                    (best_i == kNone || d < best_d)) { best_d = d; best_i = i; }
            if (best_i == kNone) return done();   // (c) quiescent
            global_now_ms_ = best_d;
            for (auto* lp : loops_) lp->set_virtual_now_ms(best_d);
            trace_ += 'T';
            trace_ += std::to_string(best_i);
            trace_ += '@';
            trace_ += std::to_string(best_d);
            trace_ += ';';
            loops_[best_i]->advance_to_next_timer();
        }
        return done();
    }

private:
    static constexpr std::size_t kNone = static_cast<std::size_t>(-1);
    std::vector<VirtualEventLoop*> loops_;
    uint64_t    global_now_ms_ = 0;
    std::string trace_;
};

} // namespace determ::net
