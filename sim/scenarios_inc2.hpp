// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// DSF (Deterministic-Simulation Framework) INCREMENT 2 — adversarial scenarios.
//
// Increment 1 shipped the sim core (clock + scheduler + net-seam + trace +
// property loop) with 6 framework-demonstration scenarios. Increment 2 adds a
// batch of ADVERSARIAL scenarios drawn from the DSF-SPEC §Q7 families, each
// paired with an `expect_violation` SELF-TEST that plants the corresponding bug
// and proves the checker fires (the discipline established by increment-1's
// `falsifiable_supply`). Still TOY-MODEL over the generic SimState — real
// consensus wiring (time::Clock + net::Transport injection, DSF-SPEC §Q1/§Q2)
// is a later increment; these exercise the property-checker patterns the four
// production invariants (FA1 / A1 / FA6 / FA7) will later use.
//
//   §Q7 equivocation      -> equivocation_slash      + equivocation_unslashed
//   §Q7 cross-shard       -> cross_shard_conserve    + cross_shard_double_credit
//   §Q7 selective-abort   -> selective_abort_fair    + selective_abort_bias
//   §Q7 BFT escalation    -> bft_escalation_monotone + bft_escalation_regress
//
// Every scenario is a pure function of (scenario, seed): identical inputs
// produce a byte-identical trace on any host/compiler (the increment-1
// determinism contract, extended).
#pragma once
#include <string>
#include <vector>
#include "scenario.hpp"

namespace determ::sim {

// ===========================================================================
// Family 1 — Equivocation detection + slashing (DSF-SPEC §Q7, FA6 pattern).
// A Byzantine member casts two conflicting VOTEs for the same height. A witness
// "detector" records the first vote per member and flags a second, distinct one
// as equivocation. The production FA6 invariant is "an equivocator is in the
// slashed set by the next epoch boundary"; the toy analog is checked here.
// ===========================================================================
inline void install_equiv_detector(Simulator& sim, bool slash_enabled) {
    sim.add_node("detector", [&sim, slash_enabled](const Message& m) {
        if (m.kind != "VOTE") return;
        Node& det = sim.state().nodes["detector"];
        const std::string seen_key = "seen:" + m.from;   // stores value+1
        const int64_t     stamped  = static_cast<int64_t>(m.payload) + 1;
        auto it = det.kv.find(seen_key);
        if (it == det.kv.end() || it->second == 0) {
            det.kv[seen_key] = stamped;                  // first vote from m.from
        } else if (it->second != stamped) {             // a second, DISTINCT vote
            det.kv["equiv:" + m.from] = 1;
            sim.log("detector", "EQUIV",
                    m.from + " voted " + std::to_string(it->second - 1) +
                    " and " + std::to_string(m.payload));
            if (slash_enabled)
                sim.state().scalars["slashed:" + m.from] = 1;
        }
    });
}

// SAFETY: every flagged equivocator must appear in the slashed set. Reads the
// detector's kv for "equiv:<m>" markers and the scalar bag for "slashed:<m>".
inline void add_equivocator_slashed_invariant(Simulator& sim) {
    sim.props().add("equivocator_slashed", PropKind::SAFETY,
        [](const SimState& st, std::string* d) {
            auto nit = st.nodes.find("detector");
            if (nit == st.nodes.end()) return true;
            for (const auto& [k, v] : nit->second.kv) {
                if (v == 1 && k.rfind("equiv:", 0) == 0) {
                    const std::string member = k.substr(6);
                    const std::string sk = "slashed:" + member;
                    auto sit = st.scalars.find(sk);
                    if (sit == st.scalars.end() || sit->second != 1) {
                        if (d) *d = "equivocator " + member +
                                    " not in slashed set";
                        return false;
                    }
                }
            }
            return true;
        });
}

// A run body shared by both equivocation scenarios: p1/p3 vote once (value 100);
// Byzantine p2 votes 100 then a conflicting 200 for the same height.
inline void run_equivocation_votes(Simulator& sim) {
    sim.after(vt_ms(10), [&sim]() { sim.send("p1", "detector", "VOTE", 100); });
    sim.after(vt_ms(20), [&sim]() { sim.send("p2", "detector", "VOTE", 100); });
    sim.after(vt_ms(30), [&sim]() { sim.send("p2", "detector", "VOTE", 200); });
    sim.after(vt_ms(40), [&sim]() { sim.send("p3", "detector", "VOTE", 100); });
}

// ===========================================================================
// Family 2 — Cross-shard receipt conservation (DSF-SPEC §Q7, FA7 pattern).
// Shard A emits an outbound debit (a receipt id); shard B credits it. The net
// model DUPLICATES the receipt, so an idempotent B credits it exactly once and
// a buggy B double-credits. FA7's toy analogs: "no credit without a matching
// debit" and "each receipt credited at most once".
// ===========================================================================
inline void install_shard_b(Simulator& sim, bool idempotent) {
    sim.add_node("shardB", [&sim, idempotent](const Message& m) {
        if (m.kind != "RECEIPT") return;
        Node& B = sim.state().nodes["shardB"];
        const std::string ck = "credited:" + std::to_string(m.payload);
        if (idempotent) {
            if (B.kv[ck] == 0) {                  // credit once per receipt id
                B.kv[ck] = 1;
                sim.log("shardB", "CREDIT", "receipt=" + std::to_string(m.payload));
            } else {
                sim.log("shardB", "IDEMPOTENT",
                        "receipt=" + std::to_string(m.payload) + " already credited");
            }
        } else {
            B.kv[ck] += 1;                        // BUG: no dedup -> double credit
            sim.log("shardB", "CREDIT",
                    "receipt=" + std::to_string(m.payload) +
                    " count=" + std::to_string(B.kv[ck]));
        }
    });
}

inline void add_cross_shard_invariants(Simulator& sim) {
    // SAFETY: each receipt credited at most once.
    sim.props().add("no_double_credit", PropKind::SAFETY,
        [](const SimState& st, std::string* d) {
            auto nit = st.nodes.find("shardB");
            if (nit == st.nodes.end()) return true;
            for (const auto& [k, v] : nit->second.kv) {
                if (k.rfind("credited:", 0) == 0 && v > 1) {
                    if (d) *d = k + " credited " + std::to_string(v) + " times";
                    return false;
                }
            }
            return true;
        });
    // SAFETY: no credit exists on B without a matching debit emitted by A.
    sim.props().add("no_credit_without_debit", PropKind::SAFETY,
        [](const SimState& st, std::string* d) {
            auto nit = st.nodes.find("shardB");
            if (nit == st.nodes.end()) return true;
            for (const auto& [k, v] : nit->second.kv) {
                if (k.rfind("credited:", 0) == 0 && v >= 1) {
                    const std::string rid = k.substr(9);
                    const std::string dk  = "debit:" + rid;
                    auto dit = st.scalars.find(dk);
                    if (dit == st.scalars.end() || dit->second != 1) {
                        if (d) *d = "credit for receipt " + rid + " has no debit";
                        return false;
                    }
                }
            }
            return true;
        });
}

inline void run_cross_shard_receipt(Simulator& sim) {
    // A emits the outbound debit for receipt id 1, then sends it to B. The net
    // model duplicates every delivery (dup_rate=1.0), so B sees it twice.
    sim.after(vt_ms(10), [&sim]() {
        sim.state().scalars["debit:1"] = 1;
        sim.log("shardA", "DEBIT", "receipt=1 outbound");
        sim.send("shardA", "shardB", "RECEIPT", 1);
    });
}

// ===========================================================================
// Family 3 — Selective-abort committee bias (DSF-SPEC §Q7, FA8 pattern).
// A proposer may abort a round it dislikes, forcing a re-selection. An honest
// proposer never aborts, so favorable outcomes track the (deterministic,
// balanced) coin ~= half the rounds. A Byzantine proposer aborts every
// unfavorable round, biasing the accepted outcomes toward "favorable". The
// invariant caps the favorable share; gross bias trips it.
// ===========================================================================
constexpr int64_t kSelRounds  = 40;
constexpr int64_t kSelFavCap  = kSelRounds * 3 / 4;   // 30 of 40

inline void add_selection_bias_invariant(Simulator& sim) {
    sim.props().add("no_selection_bias", PropKind::SAFETY,
        [](const SimState& st, std::string* d) {
            auto fit = st.scalars.find("fav_count");
            const int64_t fav = fit == st.scalars.end() ? 0 : fit->second;
            if (fav > kSelFavCap) {
                if (d) *d = "favorable=" + std::to_string(fav) + " > cap=" +
                            std::to_string(kSelFavCap) + " (selection biased)";
                return false;
            }
            return true;
        });
}

// `biased`: honest = accept the balanced parity coin (exactly half favorable);
// Byzantine = abort every unfavorable round and re-select favorable (all rounds
// favorable). The seeded RNG is consulted for a trace-flavor tie-break only, so
// the accepted-favorable COUNT stays a deterministic function of the strategy.
inline void run_selective_abort(Simulator& sim, bool biased) {
    for (int64_t r = 0; r < kSelRounds; ++r) {
        sim.after(vt_ms(static_cast<uint64_t>(r + 1)), [&sim, r, biased]() {
            sim.state().scalars["round_count"] += 1;
            const bool coin_favorable = (r % 2 == 0);   // balanced honest coin
            if (biased) {
                if (!coin_favorable)
                    sim.log("proposer", "ABORT",
                            "round " + std::to_string(r) + " unfavorable, re-select");
                sim.state().scalars["fav_count"] += 1;   // always accept favorable
            } else if (coin_favorable) {
                sim.state().scalars["fav_count"] += 1;
            }
        });
    }
}

// ===========================================================================
// Family 4 — BFT-escalation monotonicity (DSF-SPEC §Q7 BFT escalation).
// Persistent aborts raise an escalation level, capped at a maximum. The level
// is monotone non-decreasing within a round (once escalated you don't silently
// de-escalate) and bounded. A bug that regresses the level is caught.
// ===========================================================================
constexpr int64_t kEscMax = 3;

inline void add_escalation_invariants(Simulator& sim) {
    // SAFETY: the escalation high-water mark never exceeds the ceiling.
    sim.props().add("escalation_bounded", PropKind::SAFETY,
        [](const SimState& st, std::string* d) {
            auto it = st.scalars.find("esc_hwm");
            const int64_t hwm = it == st.scalars.end() ? 0 : it->second;
            if (hwm > kEscMax) {
                if (d) *d = "esc_hwm=" + std::to_string(hwm) + " > max=" +
                            std::to_string(kEscMax);
                return false;
            }
            return true;
        });
    // SAFETY: the current level never drops below the high-water mark
    // (monotone non-decreasing within the round).
    sim.props().add("escalation_no_regress", PropKind::SAFETY,
        [](const SimState& st, std::string* d) {
            auto lit = st.scalars.find("esc_level");
            auto hit = st.scalars.find("esc_hwm");
            const int64_t lvl = lit == st.scalars.end() ? 0 : lit->second;
            const int64_t hwm = hit == st.scalars.end() ? 0 : hit->second;
            if (lvl < hwm) {
                if (d) *d = "esc_level=" + std::to_string(lvl) +
                            " regressed below hwm=" + std::to_string(hwm);
                return false;
            }
            return true;
        });
}

inline void escalate_once(Simulator& sim) {
    int64_t& lvl = sim.state().scalars["esc_level"];
    if (lvl < kEscMax) lvl += 1;
    int64_t& hwm = sim.state().scalars["esc_hwm"];
    if (lvl > hwm) hwm = lvl;
    sim.log("bft", "ESCALATE", "level=" + std::to_string(lvl));
}

// ===========================================================================
// register_inc2_scenarios — append the 8 increment-2 scenarios to `out`.
// ===========================================================================
inline void register_inc2_scenarios(std::vector<Scenario>& out) {

    // --- 1. equivocation_slash (normal) ----------------------------------
    {
        Scenario s;
        s.name = "equivocation_slash";
        s.description =
            "Byzantine p2 casts two conflicting votes for one height; the "
            "detector flags it AND slashes. FA6 toy: equivocator is slashed.";
        s.setup = [](Simulator& sim) {
            sim.add_node("p1"); sim.add_node("p2"); sim.add_node("p3");
            install_equiv_detector(sim, /*slash_enabled=*/true);
            add_equivocator_slashed_invariant(sim);
        };
        s.run = [](Simulator& sim) { run_equivocation_votes(sim); };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 2. equivocation_unslashed (SELF-TEST, expect_violation) ---------
    {
        Scenario s;
        s.name = "equivocation_unslashed";
        s.expect_violation = true;
        s.description =
            "SELF-TEST: same double-vote, but slashing is DISABLED (planted "
            "bug: detect without slash). equivocator_slashed MUST fire.";
        s.setup = [](Simulator& sim) {
            sim.add_node("p1"); sim.add_node("p2"); sim.add_node("p3");
            install_equiv_detector(sim, /*slash_enabled=*/false);
            add_equivocator_slashed_invariant(sim);
        };
        s.run = [](Simulator& sim) { run_equivocation_votes(sim); };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 3. cross_shard_conserve (normal) --------------------------------
    {
        Scenario s;
        s.name = "cross_shard_conserve";
        s.description =
            "Shard A debits receipt 1; the net model duplicates delivery; an "
            "idempotent shard B credits exactly once. FA7 toy: conservation.";
        s.setup = [](Simulator& sim) {
            sim.add_node("shardA");
            install_shard_b(sim, /*idempotent=*/true);
            sim.net().set_dup_rate(1.0);           // duplicate every delivery
            add_cross_shard_invariants(sim);
        };
        s.run = [](Simulator& sim) { run_cross_shard_receipt(sim); };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 4. cross_shard_double_credit (SELF-TEST, expect_violation) ------
    {
        Scenario s;
        s.name = "cross_shard_double_credit";
        s.expect_violation = true;
        s.description =
            "SELF-TEST: a non-idempotent shard B credits the DUPLICATED receipt "
            "twice (planted double-spend). no_double_credit MUST fire.";
        s.setup = [](Simulator& sim) {
            sim.add_node("shardA");
            install_shard_b(sim, /*idempotent=*/false);
            sim.net().set_dup_rate(1.0);
            add_cross_shard_invariants(sim);
        };
        s.run = [](Simulator& sim) { run_cross_shard_receipt(sim); };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 5. selective_abort_fair (normal) --------------------------------
    {
        Scenario s;
        s.name = "selective_abort_fair";
        s.description =
            "An honest proposer never aborts; favorable outcomes track the "
            "balanced coin (~half). no_selection_bias holds.";
        s.setup = [](Simulator& sim) {
            sim.add_node("proposer");
            sim.state().scalars["fav_count"]   = 0;
            sim.state().scalars["round_count"] = 0;
            add_selection_bias_invariant(sim);
        };
        s.run = [](Simulator& sim) { run_selective_abort(sim, /*biased=*/false); };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 6. selective_abort_bias (SELF-TEST, expect_violation) -----------
    {
        Scenario s;
        s.name = "selective_abort_bias";
        s.expect_violation = true;
        s.description =
            "SELF-TEST: a Byzantine proposer aborts every unfavorable round "
            "(planted committee-selection bias). no_selection_bias MUST fire.";
        s.setup = [](Simulator& sim) {
            sim.add_node("proposer");
            sim.state().scalars["fav_count"]   = 0;
            sim.state().scalars["round_count"] = 0;
            add_selection_bias_invariant(sim);
        };
        s.run = [](Simulator& sim) { run_selective_abort(sim, /*biased=*/true); };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 7. bft_escalation_monotone (normal) -----------------------------
    {
        Scenario s;
        s.name = "bft_escalation_monotone";
        s.description =
            "Persistent aborts raise the escalation level toward the ceiling; "
            "it never regresses or overshoots. escalation_bounded + _no_regress.";
        s.setup = [](Simulator& sim) {
            sim.add_node("bft");
            sim.state().scalars["esc_level"] = 0;
            sim.state().scalars["esc_hwm"]   = 0;
            add_escalation_invariants(sim);
        };
        s.run = [](Simulator& sim) {
            // Five persistent aborts: level climbs 1,2,3 then holds at the cap.
            for (int i = 0; i < 5; ++i)
                sim.after(vt_ms(10 * (i + 1)), [&sim]() { escalate_once(sim); });
        };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 8. bft_escalation_regress (SELF-TEST, expect_violation) ---------
    {
        Scenario s;
        s.name = "bft_escalation_regress";
        s.expect_violation = true;
        s.description =
            "SELF-TEST: after escalating to the cap, a bug silently drops the "
            "level below the high-water mark. escalation_no_regress MUST fire.";
        s.setup = [](Simulator& sim) {
            sim.add_node("bft");
            sim.state().scalars["esc_level"] = 0;
            sim.state().scalars["esc_hwm"]   = 0;
            add_escalation_invariants(sim);
        };
        s.run = [](Simulator& sim) {
            for (int i = 0; i < 3; ++i)
                sim.after(vt_ms(10 * (i + 1)), [&sim]() { escalate_once(sim); });
            // THE BUG: regress the level without lowering the high-water mark.
            sim.after(vt_ms(40), [&sim]() {
                sim.state().scalars["esc_level"] = kEscMax - 1;   // 3 -> 2
                sim.log("bft", "REGRESS", "level dropped to 2 (INTENTIONAL BUG)");
            });
        };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }
}

} // namespace determ::sim
