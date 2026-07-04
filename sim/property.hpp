// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// DSF (Deterministic-Simulation Framework) INCREMENT 1 — property checker.
// Per docs/proofs/DSF-SPEC.md §Q4 and §4.4.
//
// A small invariant-checker framework. A scenario registers named invariants;
// the simulator runs them after every step (safety) and once at the end
// (liveness). On a violation the checker captures enough to reproduce:
// the invariant name, the offending detail, the virtual time, and (via the
// Scenario runner) the reproducing seed + the trace path.
//
// SAFETY vs LIVENESS (DSF-SPEC §Q4):
//   - SAFETY  invariants must hold at EVERY step ("nothing bad happens").
//             A single false at any step is a violation.
//   - LIVENESS invariants must hold by the END of the run ("something good
//             eventually happens"). They may be transiently false mid-run;
//             only the terminal evaluation counts.
//
// Increment-1 scope: the framework + the safety/liveness distinction + a
// violation record. The four production invariants (FA1 single-block-per-
// height, A1 unitary-supply, FA6 equivocation-slashing, FA7 cross-shard
// atomicity) from DSF-SPEC §Q4 are wired in a LATER increment, once the real
// consensus engine runs inside the sim. Increment-1 scenarios register
// framework-demonstration invariants over the toy SimState.
#pragma once
#include <functional>
#include <string>
#include <vector>

namespace determ::sim {

// Forward-declared; defined in scenario.hpp. The invariant predicate reads
// the current simulation state.
struct SimState;

enum class PropKind {
    SAFETY,   // must hold at every step
    LIVENESS, // must hold by end of run
};

inline const char* to_string(PropKind k) {
    return k == PropKind::SAFETY ? "SAFETY" : "LIVENESS";
}

// An invariant: a named predicate over SimState. Returning false == violated.
// `detail` is filled by the predicate with a human-readable reason on failure
// (left empty on success). The predicate must be a PURE function of SimState
// so evaluation is deterministic.
struct Invariant {
    std::string name;
    PropKind    kind;
    // predicate: returns true if holds; on false, may set *detail_out.
    std::function<bool(const SimState&, std::string* detail_out)> pred;
};

// A recorded violation — enough to reproduce and diagnose.
struct Violation {
    std::string name;     // invariant name
    PropKind    kind;     // safety or liveness
    std::string detail;   // reason captured by the predicate
    uint64_t    vtime;    // virtual time at violation
    uint64_t    step;     // step index (safety) or 0 (end-of-run liveness)
};

// Registry + evaluator. A scenario populates this with add(); the runner calls
// check_safety() after each step and check_liveness() once at the end.
class PropertySet {
public:
    void add(const std::string& name, PropKind kind,
             std::function<bool(const SimState&, std::string*)> pred) {
        invariants_.push_back(Invariant{name, kind, std::move(pred)});
    }

    // Convenience: predicate that ignores the detail-out param.
    void add_simple(const std::string& name, PropKind kind,
                    std::function<bool(const SimState&)> pred) {
        invariants_.push_back(Invariant{
            name, kind,
            [pred = std::move(pred)](const SimState& s, std::string*) {
                return pred(s);
            }});
    }

    // Evaluate all SAFETY invariants against `st` at the given step/vtime.
    // Appends any violations to violations_. Returns true if all held.
    bool check_safety(const SimState& st, uint64_t step, uint64_t vtime) {
        bool ok = true;
        for (const auto& inv : invariants_) {
            if (inv.kind != PropKind::SAFETY) continue;
            std::string detail;
            if (!inv.pred(st, &detail)) {
                violations_.push_back(
                    Violation{inv.name, inv.kind, detail, vtime, step});
                ok = false;
            }
        }
        return ok;
    }

    // Evaluate all LIVENESS invariants once at end of run.
    bool check_liveness(const SimState& st, uint64_t vtime) {
        bool ok = true;
        for (const auto& inv : invariants_) {
            if (inv.kind != PropKind::LIVENESS) continue;
            std::string detail;
            if (!inv.pred(st, &detail)) {
                violations_.push_back(
                    Violation{inv.name, inv.kind, detail, vtime, 0});
                ok = false;
            }
        }
        return ok;
    }

    bool                          any_violation() const { return !violations_.empty(); }
    const std::vector<Violation>& violations()    const { return violations_; }
    size_t                        count()          const { return invariants_.size(); }

    void reset() { violations_.clear(); }

private:
    std::vector<Invariant> invariants_;
    std::vector<Violation> violations_;
};

} // namespace determ::sim
