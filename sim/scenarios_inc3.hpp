// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// DSF (Deterministic-Simulation Framework) INCREMENT 3 — more adversarial
// scenarios. Extends increment-2 with three further DSF-SPEC §Q7 families, each
// with an `expect_violation` SELF-TEST proving its checker fires on a planted
// bug. Toy-model over the generic SimState (real consensus wiring is a later
// increment).
//
//   §Q7 DKG                -> dkg_all_commit          + dkg_below_threshold
//   §Q7 F2 view-reconcile  -> f2_reconcile_intersect  + f2_phantom_evidence
//   §Q7 network partition  -> partition_minority_stalls + partition_split_brain
//
// As with every DSF scenario: identical (scenario, seed) => byte-identical
// trace on any host/compiler.
#pragma once
#include <string>
#include <vector>
#include "scenario.hpp"

namespace determ::sim {

// ===========================================================================
// Family 5 — DKG threshold completion (DSF-SPEC §Q7 DKG).
// A coordinator collects share-commitments from members. The distributed key
// is only "complete" once a threshold t of members have committed. The toy
// analog of the v2.10 DKG safety rule: never finalize below threshold.
// ===========================================================================
constexpr int64_t kDkgThreshold = 3;   // t-of-K, K=5

inline void install_dkg_coordinator(Simulator& sim, bool buggy) {
    sim.add_node("coord", [&sim, buggy](const Message& m) {
        if (m.kind != "COMMIT") return;
        Node& c = sim.state().nodes["coord"];
        c.kv["commits"] += 1;
        sim.log("coord", "COMMIT",
                m.from + " (" + std::to_string(c.kv["commits"]) + " total)");
        if (buggy) {
            // BUG: mark the DKG complete on ANY commit, ignoring the threshold.
            c.kv["complete"] = 1;
            sim.log("coord", "DKG-COMPLETE",
                    "declared at commits=" + std::to_string(c.kv["commits"]) +
                    " (INTENTIONAL BUG: below threshold)");
        } else if (c.kv["commits"] >= kDkgThreshold && c.kv["complete"] == 0) {
            c.kv["complete"] = 1;
            sim.log("coord", "DKG-COMPLETE",
                    "threshold reached at commits=" +
                    std::to_string(c.kv["commits"]));
        }
    });
}

inline void add_dkg_threshold_invariant(Simulator& sim) {
    // SAFETY: if the DKG is marked complete, at least `t` members committed.
    sim.props().add("dkg_needs_threshold", PropKind::SAFETY,
        [](const SimState& st, std::string* d) {
            auto it = st.nodes.find("coord");
            if (it == st.nodes.end()) return true;
            const auto& kv = it->second.kv;
            const bool complete = kv.count("complete") && kv.at("complete") == 1;
            const int64_t commits = kv.count("commits") ? kv.at("commits") : 0;
            if (complete && commits < kDkgThreshold) {
                if (d) *d = "DKG complete with commits=" +
                            std::to_string(commits) + " < t=" +
                            std::to_string(kDkgThreshold);
                return false;
            }
            return true;
        });
}

// `committers`: how many of the 5 members actually send their COMMIT.
inline void run_dkg(Simulator& sim, int committers) {
    const char* members[5] = {"m1", "m2", "m3", "m4", "m5"};
    for (int i = 0; i < committers && i < 5; ++i) {
        const std::string who = members[i];
        sim.after(vt_ms(10 * (i + 1)), [&sim, who]() {
            sim.send(who, "coord", "COMMIT", 1);
        });
    }
}

// ===========================================================================
// Family 6 — F2 view reconciliation (DSF-SPEC §Q7 F2).
// Two validators reconcile their evidence sets into an agreed view. The agreed
// view must contain no "phantom" evidence — every reconciled id must have been
// observed by BOTH validators (the F2 no-fabrication rule).
// ===========================================================================
inline void add_no_phantom_evidence_invariant(Simulator& sim) {
    sim.props().add("no_phantom_evidence", PropKind::SAFETY,
        [](const SimState& st, std::string* d) {
            auto n1 = st.nodes.find("v1");
            auto n2 = st.nodes.find("v2");
            if (n1 == st.nodes.end() || n2 == st.nodes.end()) return true;
            for (const auto& [k, v] : st.scalars) {
                if (v != 1 || k.rfind("agreed:", 0) != 0) continue;
                const std::string id = k.substr(7);           // "agreed:<id>"
                const std::string ek = "ev:" + id;
                const bool in1 = n1->second.kv.count(ek) && n1->second.kv.at(ek) == 1;
                const bool in2 = n2->second.kv.count(ek) && n2->second.kv.at(ek) == 1;
                if (!(in1 && in2)) {
                    if (d) *d = "agreed evidence " + id +
                                " not observed by both (v1=" +
                                std::to_string(in1) + " v2=" +
                                std::to_string(in2) + ")";
                    return false;
                }
            }
            return true;
        });
}

// v1 sees {1,2,3}, v2 sees {2,3,4}. Reconcile computes the intersection {2,3}.
// `phantom`: additionally inject an id (9) that neither validator observed.
inline void run_f2_reconcile(Simulator& sim, bool phantom) {
    sim.after(vt_ms(5), [&sim]() {
        for (int id : {1, 2, 3}) sim.state().nodes["v1"].kv["ev:" + std::to_string(id)] = 1;
        for (int id : {2, 3, 4}) sim.state().nodes["v2"].kv["ev:" + std::to_string(id)] = 1;
        sim.log("-", "EVIDENCE", "v1={1,2,3} v2={2,3,4}");
    });
    sim.after(vt_ms(10), [&sim, phantom]() {
        // Reconcile = intersection of the two evidence sets.
        for (int id : {2, 3}) sim.state().scalars["agreed:" + std::to_string(id)] = 1;
        sim.log("-", "RECONCILE", "agreed=intersection={2,3}");
        if (phantom) {
            sim.state().scalars["agreed:9"] = 1;   // BUG: fabricated evidence
            sim.log("-", "PHANTOM", "agreed:9 not seen by either (INTENTIONAL BUG)");
        }
    });
}

// ===========================================================================
// Family 7 — Partition quorum / split-brain (DSF-SPEC §Q7 network partition).
// A 5-node committee splits into a majority (3) and a minority (2). Only a side
// holding a quorum (3) may decide. A single-decision safety rule must hold: at
// most one side ever decides. Lowering the minority's effective quorum causes
// split-brain — two decisions — which the checker catches.
// ===========================================================================
constexpr int64_t kQuorum = 3;   // of 5

inline void add_single_decision_invariant(Simulator& sim) {
    sim.props().add("single_decision", PropKind::SAFETY,
        [](const SimState& st, std::string* d) {
            const int64_t dm = st.scalars.count("decided_maj")
                               ? st.scalars.at("decided_maj") : 0;
            const int64_t dn = st.scalars.count("decided_min")
                               ? st.scalars.at("decided_min") : 0;
            if (dm + dn > 1) {
                if (d) *d = "split-brain: majority-decided=" + std::to_string(dm) +
                            " minority-decided=" + std::to_string(dn);
                return false;
            }
            return true;
        });
}

// `min_quorum`: the effective quorum applied to the minority side. Honest = 3
// (minority of 2 can never reach it). The split-brain bug sets it to 2.
inline void run_partition_quorum(Simulator& sim, int64_t min_quorum) {
    // Majority side {A,B,C} accrues 3 votes; decides when votes >= kQuorum.
    for (int i = 0; i < 3; ++i)
        sim.after(vt_ms(10 * (i + 1)), [&sim]() {
            int64_t& v = sim.state().scalars["votes_maj"];
            v += 1;
            if (v >= kQuorum && sim.state().scalars["decided_maj"] == 0) {
                sim.state().scalars["decided_maj"] = 1;
                sim.log("majority", "DECIDE", "votes=" + std::to_string(v));
            }
        });
    // Minority side {D,E} accrues 2 votes; decides only if it reaches its
    // (mis)configured quorum.
    for (int i = 0; i < 2; ++i)
        sim.after(vt_ms(10 * (i + 1) + 5), [&sim, min_quorum]() {
            int64_t& v = sim.state().scalars["votes_min"];
            v += 1;
            if (v >= min_quorum && sim.state().scalars["decided_min"] == 0) {
                sim.state().scalars["decided_min"] = 1;
                sim.log("minority", "DECIDE",
                        "votes=" + std::to_string(v) + " quorum=" +
                        std::to_string(min_quorum));
            }
        });
}

// ===========================================================================
// register_inc3_scenarios — append the 6 increment-3 scenarios to `out`.
// ===========================================================================
inline void register_inc3_scenarios(std::vector<Scenario>& out) {

    // --- 9. dkg_all_commit (normal) --------------------------------------
    {
        Scenario s;
        s.name = "dkg_all_commit";
        s.description =
            "All 5 members commit; the DKG completes only after the t=3 "
            "threshold is reached. dkg_needs_threshold holds.";
        s.setup = [](Simulator& sim) {
            install_dkg_coordinator(sim, /*buggy=*/false);
            for (auto m : {"m1", "m2", "m3", "m4", "m5"}) sim.add_node(m);
            add_dkg_threshold_invariant(sim);
        };
        s.run = [](Simulator& sim) { run_dkg(sim, /*committers=*/5); };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 10. dkg_below_threshold (SELF-TEST, expect_violation) -----------
    {
        Scenario s;
        s.name = "dkg_below_threshold";
        s.expect_violation = true;
        s.description =
            "SELF-TEST: only 2 of 5 commit, but a buggy coordinator declares "
            "the DKG complete anyway. dkg_needs_threshold MUST fire.";
        s.setup = [](Simulator& sim) {
            install_dkg_coordinator(sim, /*buggy=*/true);
            for (auto m : {"m1", "m2", "m3", "m4", "m5"}) sim.add_node(m);
            add_dkg_threshold_invariant(sim);
        };
        s.run = [](Simulator& sim) { run_dkg(sim, /*committers=*/2); };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 11. f2_reconcile_intersect (normal) -----------------------------
    {
        Scenario s;
        s.name = "f2_reconcile_intersect";
        s.description =
            "Two validators reconcile evidence to the intersection {2,3}; every "
            "agreed id was seen by both. no_phantom_evidence holds.";
        s.setup = [](Simulator& sim) {
            sim.add_node("v1"); sim.add_node("v2");
            add_no_phantom_evidence_invariant(sim);
        };
        s.run = [](Simulator& sim) { run_f2_reconcile(sim, /*phantom=*/false); };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 12. f2_phantom_evidence (SELF-TEST, expect_violation) -----------
    {
        Scenario s;
        s.name = "f2_phantom_evidence";
        s.expect_violation = true;
        s.description =
            "SELF-TEST: reconciliation fabricates evidence id 9 that neither "
            "validator observed. no_phantom_evidence MUST fire.";
        s.setup = [](Simulator& sim) {
            sim.add_node("v1"); sim.add_node("v2");
            add_no_phantom_evidence_invariant(sim);
        };
        s.run = [](Simulator& sim) { run_f2_reconcile(sim, /*phantom=*/true); };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 13. partition_minority_stalls (normal) --------------------------
    {
        Scenario s;
        s.name = "partition_minority_stalls";
        s.description =
            "A 3|2 partition: the majority (3) reaches quorum and decides; the "
            "minority (2) cannot. single_decision holds (exactly one side).";
        s.setup = [](Simulator& sim) {
            sim.add_node("majority"); sim.add_node("minority");
            sim.state().scalars["votes_maj"]   = 0;
            sim.state().scalars["votes_min"]   = 0;
            sim.state().scalars["decided_maj"] = 0;
            sim.state().scalars["decided_min"] = 0;
            add_single_decision_invariant(sim);
        };
        s.run = [](Simulator& sim) { run_partition_quorum(sim, /*min_quorum=*/kQuorum); };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 14. partition_split_brain (SELF-TEST, expect_violation) ---------
    {
        Scenario s;
        s.name = "partition_split_brain";
        s.expect_violation = true;
        s.description =
            "SELF-TEST: the minority's effective quorum is mis-set to 2, so BOTH "
            "sides decide across the partition. single_decision MUST fire.";
        s.setup = [](Simulator& sim) {
            sim.add_node("majority"); sim.add_node("minority");
            sim.state().scalars["votes_maj"]   = 0;
            sim.state().scalars["votes_min"]   = 0;
            sim.state().scalars["decided_maj"] = 0;
            sim.state().scalars["decided_min"] = 0;
            add_single_decision_invariant(sim);
        };
        s.run = [](Simulator& sim) { run_partition_quorum(sim, /*min_quorum=*/2); };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }
}

} // namespace determ::sim
