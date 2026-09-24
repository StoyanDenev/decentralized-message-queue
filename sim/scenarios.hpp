// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// DSF (Deterministic-Simulation Framework) INCREMENT 1 — seed scenarios.
//
// These are FRAMEWORK-DEMONSTRATION scenarios. They exercise the full
// clock + scheduler + net-seam + trace + property loop end-to-end WITHOUT the
// real Determ consensus engine. Wiring real consensus (Node/Validator/Producer
// via the time::Clock + net::Transport injection of DSF-SPEC §Q1/§Q2) into
// these scenarios is a LATER increment; see DSF-SPEC §4.1/§4.2.
//
// The scenarios are drawn from the DSF-SPEC §Q7 families that DON'T need the
// consensus engine yet:
//   1. replicated_counter   — happy-path fan-out; total-delivery liveness.
//   2. message_reorder      — jitter reorders delivery; final state converges.
//   3. partition_heal       — partition blocks delivery, heal restores it.
//   4. duplicate_delivery   — duplicates must not double-count (idempotence).
//   5. leader_timeout       — a heartbeat timer fires deterministically.
//   6. falsifiable_supply   — DELIBERATELY violates a safety invariant, to
//                             prove the checker fires + reports the seed.
#pragma once
#include <vector>
#include "scenario.hpp"

namespace determ::sim {

// ---------------------------------------------------------------------------
// A toy replicated counter: a leader broadcasts INC to N-1 followers; each
// follower applies it to its local kv["count"]. Idempotent on msg_id so a
// duplicated INC is applied once (relevant to the duplicate scenario).
// ---------------------------------------------------------------------------
inline void install_counter_follower(Simulator& sim, const NodeId& id) {
    // Capture id; the handler dedups on msg_id via a per-node "seen" scalar set
    // encoded in kv (kv["seen:<id>"] = 1).
    sim.add_node(id, [&sim, id](const Message& m) {
        Node& self = sim.state().nodes[id];
        if (m.kind == "INC") {
            std::string seen_key = "seen:" + std::to_string(m.msg_id);
            if (self.kv[seen_key]) {
                sim.log(id, "IDEMPOTENT", "already-applied id=" +
                        std::to_string(m.msg_id));
                return; // duplicate — do not double-count
            }
            self.kv[seen_key] = 1;
            self.kv["count"] += static_cast<int64_t>(m.payload);
            sim.log(id, "APPLY", "count=" + std::to_string(self.kv["count"]));
        }
    });
}

// Register the 6 increment-1 seed scenarios into `out`.
inline void register_seed_scenarios(std::vector<Scenario>& out) {

    // --- 1. replicated_counter -------------------------------------------
    {
        Scenario s;
        s.name = "replicated_counter";
        s.description =
            "Leader broadcasts INC to 3 followers; every follower converges "
            "to the same count. Liveness: all sends are delivered.";
        s.setup = [](Simulator& sim) {
            sim.add_node("leader");
            for (auto f : {"f1", "f2", "f3"}) install_counter_follower(sim, f);
            // Safety: no follower's count ever exceeds the leader's issued total.
            sim.state().scalars["issued"] = 0;
            sim.props().add("count_le_issued", PropKind::SAFETY,
                [](const SimState& st, std::string* d) {
                    int64_t issued = st.scalars.count("issued")
                                     ? st.scalars.at("issued") : 0;
                    for (auto& [id, n] : st.nodes) {
                        auto it = n.kv.find("count");
                        int64_t c = it == n.kv.end() ? 0 : it->second;
                        if (c > issued) {
                            if (d) *d = id + " count=" + std::to_string(c) +
                                        " > issued=" + std::to_string(issued);
                            return false;
                        }
                    }
                    return true;
                });
            // Liveness: every follower ends at the full issued total.
            sim.props().add("all_followers_converged", PropKind::LIVENESS,
                [](const SimState& st, std::string* d) {
                    int64_t issued = st.scalars.count("issued")
                                     ? st.scalars.at("issued") : 0;
                    for (auto& [id, n] : st.nodes) {
                        if (id == "leader") continue;
                        auto it = n.kv.find("count");
                        int64_t c = it == n.kv.end() ? 0 : it->second;
                        if (c != issued) {
                            if (d) *d = id + " count=" + std::to_string(c) +
                                        " != issued=" + std::to_string(issued);
                            return false;
                        }
                    }
                    return true;
                });
        };
        s.run = [](Simulator& sim) {
            // Leader issues 5 increments of value 1, one every 10ms.
            for (int i = 0; i < 5; ++i) {
                sim.after(vt_ms(10 * (i + 1)), [&sim]() {
                    sim.state().scalars["issued"] += 1;
                    for (auto f : {"f1", "f2", "f3"})
                        sim.send("leader", f, "INC", 1);
                });
            }
        };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 2. message_reorder ----------------------------------------------
    {
        Scenario s;
        s.name = "message_reorder";
        s.description =
            "Latency jitter reorders delivery order; commutative INC updates "
            "still converge. Proves ordering is seed-deterministic.";
        s.setup = [](Simulator& sim) {
            for (auto f : {"f1", "f2"}) install_counter_follower(sim, f);
            sim.net().set_base_latency(vt_ms(5));
            sim.net().set_jitter(vt_ms(20)); // reorders relative to send order
            sim.state().scalars["issued"] = 0;
            sim.props().add("no_negative_count", PropKind::SAFETY,
                [](const SimState& st, std::string* d) {
                    for (auto& [id, n] : st.nodes) {
                        auto it = n.kv.find("count");
                        if (it != n.kv.end() && it->second < 0) {
                            if (d) *d = id + " went negative";
                            return false;
                        }
                    }
                    return true;
                });
            sim.props().add("both_converge", PropKind::LIVENESS,
                [](const SimState& st, std::string* d) {
                    int64_t issued = st.scalars.at("issued");
                    for (auto id : {"f1", "f2"}) {
                        auto& n = st.nodes.at(id);
                        int64_t c = n.kv.count("count") ? n.kv.at("count") : 0;
                        if (c != issued) {
                            if (d) *d = std::string(id) + " c=" +
                                        std::to_string(c);
                            return false;
                        }
                    }
                    return true;
                });
        };
        s.run = [](Simulator& sim) {
            for (int i = 0; i < 8; ++i) {
                sim.after(vt_ms(2 * (i + 1)), [&sim]() {
                    sim.state().scalars["issued"] += 1;
                    for (auto f : {"f1", "f2"}) sim.send("leader", f, "INC", 1);
                });
            }
            sim.add_node("leader");
        };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 3. partition_heal -----------------------------------------------
    {
        Scenario s;
        s.name = "partition_heal";
        s.description =
            "leader|f2 partitioned during the first burst, healed before the "
            "second. After heal, f2 receives the retransmit and converges.";
        s.setup = [](Simulator& sim) {
            sim.add_node("leader");
            for (auto f : {"f1", "f2"}) install_counter_follower(sim, f);
            sim.net().partition("leader", "f2");
            sim.state().scalars["issued"] = 0;
            // Liveness: after heal + retransmit, f2 catches up to f1.
            sim.props().add("converge_after_heal", PropKind::LIVENESS,
                [](const SimState& st, std::string* d) {
                    int64_t c1 = st.nodes.at("f1").kv.count("count")
                                 ? st.nodes.at("f1").kv.at("count") : 0;
                    int64_t c2 = st.nodes.at("f2").kv.count("count")
                                 ? st.nodes.at("f2").kv.at("count") : 0;
                    if (c1 != c2) {
                        if (d) *d = "f1=" + std::to_string(c1) +
                                    " f2=" + std::to_string(c2);
                        return false;
                    }
                    return true;
                });
        };
        s.run = [](Simulator& sim) {
            // First burst (f2 partitioned -> dropped for f2).
            for (int i = 0; i < 3; ++i)
                sim.after(vt_ms(10 * (i + 1)), [&sim]() {
                    sim.state().scalars["issued"] += 1;
                    sim.send("leader", "f1", "INC", 1);
                    sim.send("leader", "f2", "INC", 1);
                });
            // Heal at 100ms.
            sim.after(vt_ms(100), [&sim]() {
                sim.net().heal("leader", "f2");
                sim.log("-", "HEAL", "leader|f2");
            });
            // Retransmit the full total to f2 after heal (leader replays).
            sim.after(vt_ms(120), [&sim]() {
                int64_t total = sim.state().scalars["issued"];
                int64_t have  = sim.state().nodes["f2"].kv.count("count")
                                ? sim.state().nodes["f2"].kv["count"] : 0;
                if (total > have)
                    sim.send("leader", "f2", "INC",
                             static_cast<uint64_t>(total - have));
            });
        };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 4. duplicate_delivery -------------------------------------------
    {
        Scenario s;
        s.name = "duplicate_delivery";
        s.description =
            "Every message is duplicated by the net model; msg_id idempotence "
            "means the count is applied once. Safety: count never exceeds "
            "issued despite duplicates.";
        s.setup = [](Simulator& sim) {
            sim.add_node("leader");
            install_counter_follower(sim, "f1");
            sim.net().set_dup_rate(1.0); // duplicate everything
            sim.state().scalars["issued"] = 0;
            sim.props().add("dup_no_overcount", PropKind::SAFETY,
                [](const SimState& st, std::string* d) {
                    int64_t issued = st.scalars.count("issued")
                                     ? st.scalars.at("issued") : 0;
                    int64_t c = st.nodes.at("f1").kv.count("count")
                                ? st.nodes.at("f1").kv.at("count") : 0;
                    if (c > issued) {
                        if (d) *d = "f1 count=" + std::to_string(c) +
                                    " > issued=" + std::to_string(issued);
                        return false;
                    }
                    return true;
                });
            sim.props().add("final_exact", PropKind::LIVENESS,
                [](const SimState& st, std::string* d) {
                    int64_t issued = st.scalars.at("issued");
                    int64_t c = st.nodes.at("f1").kv.count("count")
                                ? st.nodes.at("f1").kv.at("count") : 0;
                    if (c != issued) {
                        if (d) *d = "f1=" + std::to_string(c) +
                                    " issued=" + std::to_string(issued);
                        return false;
                    }
                    return true;
                });
        };
        s.run = [](Simulator& sim) {
            for (int i = 0; i < 4; ++i)
                sim.after(vt_ms(10 * (i + 1)), [&sim]() {
                    sim.state().scalars["issued"] += 1;
                    sim.send("leader", "f1", "INC", 1);
                });
        };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 5. leader_timeout -----------------------------------------------
    {
        Scenario s;
        s.name = "leader_timeout";
        s.description =
            "A follower arms a 50ms heartbeat-timeout timer. The leader's "
            "heartbeat arrives at 30ms and cancels it; timer fires "
            "deterministically only if the heartbeat is missing.";
        s.setup = [](Simulator& sim) {
            sim.add_node("leader");
            sim.add_node("f1", [&sim](const Message& m) {
                if (m.kind == "HEARTBEAT")
                    sim.state().nodes["f1"].kv["last_hb_ms"] =
                        static_cast<int64_t>(sim.now() / 1000000ull);
            });
            // Safety: the timeout must NOT declare the leader dead while a
            // heartbeat was received within the window.
            sim.props().add("no_false_timeout", PropKind::SAFETY,
                [](const SimState& st, std::string* d) {
                    auto& f = st.nodes.at("f1");
                    bool timed_out = f.kv.count("leader_dead") &&
                                     f.kv.at("leader_dead");
                    bool got_hb    = f.kv.count("last_hb_ms");
                    if (timed_out && got_hb) {
                        if (d) *d = "declared dead despite heartbeat";
                        return false;
                    }
                    return true;
                });
        };
        s.run = [](Simulator& sim) {
            // Heartbeat arrives at 30ms.
            sim.after(vt_ms(30), [&sim]() {
                sim.send("leader", "f1", "HEARTBEAT", 0);
            });
            // Timeout timer fires at 50ms; declares dead only if no HB seen.
            sim.after(vt_ms(50), [&sim]() {
                auto& f = sim.state().nodes["f1"];
                if (!f.kv.count("last_hb_ms")) {
                    f.kv["leader_dead"] = 1;
                    sim.log("f1", "TIMEOUT", "leader declared dead");
                } else {
                    sim.log("f1", "TIMEOUT-CANCELLED",
                            "heartbeat seen at " +
                            std::to_string(f.kv["last_hb_ms"]) + "ms");
                }
            });
        };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }

    // --- 6. falsifiable_supply (DELIBERATELY VIOLATES) -------------------
    {
        Scenario s;
        s.name = "falsifiable_supply";
        s.description =
            "SELF-TEST: a toy unitary-supply invariant is deliberately broken "
            "(a phantom credit with no matching debit). The checker MUST fire "
            "and report the reproducing seed. expect_violation=true.";
        s.expect_violation = true;
        s.setup = [](Simulator& sim) {
            sim.add_node("mint");
            sim.add_node("acct");
            // Toy A1-style invariant: sum of balances must equal the constant
            // total supply. We seed a total of 100 across the two accounts.
            sim.state().nodes["mint"].kv["bal"]  = 100;
            sim.state().nodes["acct"].kv["bal"]  = 0;
            sim.state().scalars["total_supply"]  = 100;
            sim.props().add("unitary_supply", PropKind::SAFETY,
                [](const SimState& st, std::string* d) {
                    int64_t total = st.scalars.at("total_supply");
                    int64_t sum = 0;
                    for (auto& [id, n] : st.nodes)
                        if (n.kv.count("bal")) sum += n.kv.at("bal");
                    if (sum != total) {
                        if (d) *d = "sum(bal)=" + std::to_string(sum) +
                                    " != total_supply=" + std::to_string(total);
                        return false;
                    }
                    return true;
                });
        };
        s.run = [](Simulator& sim) {
            // A correct transfer: debit mint, credit acct — invariant holds.
            sim.after(vt_ms(10), [&sim]() {
                sim.state().nodes["mint"].kv["bal"] -= 30;
                sim.state().nodes["acct"].kv["bal"] += 30;
                sim.log("-", "TRANSFER", "30 mint->acct (balanced)");
            });
            // THE BUG: a phantom credit with NO matching debit. Supply now
            // exceeds total_supply -> unitary_supply invariant is violated.
            sim.after(vt_ms(20), [&sim]() {
                sim.state().nodes["acct"].kv["bal"] += 7; // conjured from air
                sim.log("-", "PHANTOM", "+7 credit, no debit (INTENTIONAL BUG)");
            });
        };
        s.check = [](Simulator&) {};
        out.push_back(std::move(s));
    }
}

} // namespace determ::sim
