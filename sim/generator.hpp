// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// DSF (Deterministic-Simulation Framework) INCREMENT 4 — randomized scenario
// generator. Per docs/proofs/DSF-SPEC.md §Q5 / §4.5.
//
// The generator turns a single generator-seed into N reproducible VARIANTS of a
// base template, each with a distinct fault profile (follower count, per-link
// latency, jitter, drop rate, duplicate rate) drawn from a seeded splitmix64.
// Same generator-seed => the same N variants, byte-for-byte, on any host. This
// is the §Q5 deliverable: "CI runs N variants overnight; a failed variant
// prints its seed; the seed reproduces the variant bit-for-bit."
//
// The base template is a RELIABLE broadcast: a leader repeatedly broadcasts the
// current issued total as an idempotent, monotone SET(total); a follower keeps
// count = max(count, total). Under ANY drawn drop/dup/latency/jitter profile it
// (a) never overcounts (count = max is bounded by the issued total) and
// (b) eventually converges (some late SET carrying the final total gets through).
// So every generated variant is expected to PASS — the point of this increment
// is to demonstrate deterministic generation over a spread of fault profiles.
// A companion `gen_overcount_selftest` (expect_violation) proves a generated
// fault profile DOES surface a real bug when the apply is not idempotent.
//
// NOTE on the two seeds: the fault PARAMETERS (drop rate, follower count, …) are
// a function of the GENERATOR seed baked in at registration; the fault
// REALIZATION (which individual messages drop) is a function of the run --seed,
// as for every DSF scenario. Both are deterministic.
#pragma once
#include <cstdio>
#include <string>
#include <vector>
#include "scenario.hpp"

namespace determ::sim {

// A drawn fault profile for one generated variant.
struct GenParams {
    int    followers    = 2;
    VTime  base_latency = 0;
    VTime  jitter       = 0;
    double drop         = 0.0;
    double dup          = 0.0;
};

// Draw a fault profile from the generator PRNG. Every field routes through `g`,
// so the whole profile is a deterministic function of the generator seed.
inline GenParams draw_params(SplitMix64& g) {
    static const double kDrops[] = {0.0, 0.1, 0.2, 0.3, 0.4, 0.5};
    static const double kDups[]  = {0.0, 0.5, 1.0};
    GenParams p;
    p.followers    = 2 + static_cast<int>(g.next_below(3));        // 2..4
    p.base_latency = vt_ms(g.next_below(3) * 5);                   // 0/5/10 ms
    p.jitter       = vt_ms(g.next_below(3) * 5);                   // 0/5/10 ms
    p.drop         = kDrops[g.next_below(6)];
    p.dup          = kDups[g.next_below(3)];
    return p;
}

inline std::string gen_params_str(const GenParams& p) {
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "followers=%d latency=%llums jitter=%llums drop=%.1f dup=%.1f",
                  p.followers,
                  static_cast<unsigned long long>(p.base_latency / 1000000ull),
                  static_cast<unsigned long long>(p.jitter / 1000000ull),
                  p.drop, p.dup);
    return std::string(buf);
}

// Build one reliable-broadcast variant with the given fault profile. `idempotent`
// controls the follower's apply: true = monotone max (correct); false = additive
// (the planted bug used by the self-test).
inline Scenario make_broadcast_variant(int idx, const GenParams& p,
                                       bool idempotent, bool self_test,
                                       const char* name_prefix = "gen_broadcast") {
    Scenario s;
    char nm[48];
    if (self_test) std::snprintf(nm, sizeof(nm), "gen_overcount_selftest");
    else           std::snprintf(nm, sizeof(nm), "%s_%02d", name_prefix, idx);
    s.name = nm;
    s.description = (self_test
        ? std::string("SELF-TEST: a generated fault profile (forced dup) over a "
                      "NON-idempotent (additive) apply overcounts. gen_no_overcount "
                      "MUST fire. ")
        : std::string("generated reliable-broadcast variant — ")) +
        gen_params_str(p);
    s.expect_violation = self_test;

    s.setup = [p, idempotent](Simulator& sim) {
        sim.add_node("leader");
        for (int i = 0; i < p.followers; ++i) {
            const std::string f = "f" + std::to_string(i);
            sim.add_node(f, [&sim, f, idempotent](const Message& m) {
                if (m.kind != "SET") return;
                Node& self = sim.state().nodes[f];
                const int64_t v = static_cast<int64_t>(m.payload);
                if (idempotent) {
                    if (v > self.kv["count"]) self.kv["count"] = v;   // monotone max
                } else {
                    self.kv["count"] += v;                            // BUG: additive
                }
            });
        }
        sim.net().set_base_latency(p.base_latency);
        sim.net().set_jitter(p.jitter);
        sim.net().set_drop_rate(p.drop);
        sim.net().set_dup_rate(p.dup);
        sim.state().scalars["issued"] = 0;
        const int followers = p.followers;

        // SAFETY: no follower's count ever exceeds the issued total.
        sim.props().add("gen_no_overcount", PropKind::SAFETY,
            [](const SimState& st, std::string* d) {
                const int64_t issued = st.scalars.count("issued")
                                       ? st.scalars.at("issued") : 0;
                for (const auto& [id, n] : st.nodes) {
                    if (id == "leader") continue;
                    auto it = n.kv.find("count");
                    const int64_t c = it == n.kv.end() ? 0 : it->second;
                    if (c > issued) {
                        if (d) *d = id + " count=" + std::to_string(c) +
                                    " > issued=" + std::to_string(issued);
                        return false;
                    }
                }
                return true;
            });
        // LIVENESS: every follower converges to the final issued total.
        sim.props().add("gen_all_converge", PropKind::LIVENESS,
            [followers](const SimState& st, std::string* d) {
                const int64_t issued = st.scalars.count("issued")
                                       ? st.scalars.at("issued") : 0;
                int seen = 0;
                for (const auto& [id, n] : st.nodes) {
                    if (id == "leader") continue;
                    ++seen;
                    auto it = n.kv.find("count");
                    const int64_t c = it == n.kv.end() ? 0 : it->second;
                    if (c != issued) {
                        if (d) *d = id + " count=" + std::to_string(c) +
                                    " != issued=" + std::to_string(issued);
                        return false;
                    }
                }
                return seen == followers;
            });
    };

    s.run = [p](Simulator& sim) {
        // Issue 5 increments, one every 20ms (issued reaches 5 by 100ms).
        for (int i = 0; i < 5; ++i)
            sim.after(vt_ms(20 * (i + 1)),
                      [&sim]() { sim.state().scalars["issued"] += 1; });
        // Reliably re-broadcast the current issued total 30 times (every 25ms).
        // Under any drop <= 0.5 a late SET(final) is overwhelmingly likely to
        // land — and, being seeded, it either does or doesn't DETERMINISTICALLY.
        for (int t = 0; t < 30; ++t)
            sim.after(vt_ms(25 * (t + 1)), [&sim, p]() {
                const int64_t total = sim.state().scalars["issued"];
                for (int i = 0; i < p.followers; ++i)
                    sim.send("leader", "f" + std::to_string(i), "SET",
                             static_cast<uint64_t>(total));
            });
    };
    s.check = [](Simulator&) {};
    return s;
}

// ── Increment 6: a SECOND generator template — single-value-flood AGREEMENT ──
//
// A DIFFERENT §Q7 checker family (network-partition / equivocation) exercised
// under the same randomized fault profiles. A leader floods one decision value
// V to every follower; each follower latches the FIRST value it sees and never
// changes it (first-write-wins). Under any drawn drop/dup/latency/jitter profile
// this (a) never splits (only V is ever sent, so all non-zero deciders agree)
// and (b) eventually decides (a late DECIDE(V) reaches every follower). So every
// generated variant is expected to PASS. `correct` controls the leader: true =
// honest single-value flood; false = Byzantine equivocation (V to even nodes,
// V' to odd nodes) — the planted bug used by the self-test, which makes even and
// odd followers latch DIFFERENT values so `agree_no_split` MUST fire.
inline Scenario make_agreement_variant(int idx, const GenParams& p,
                                       bool correct, bool self_test,
                                       const char* name_prefix = "gen_agree") {
    Scenario s;
    char nm[48];
    if (self_test) std::snprintf(nm, sizeof(nm), "gen_disagree_selftest");
    else           std::snprintf(nm, sizeof(nm), "%s_%02d", name_prefix, idx);
    s.name = nm;
    s.description = (self_test
        ? std::string("SELF-TEST: a Byzantine leader equivocates (floods value V "
                      "to even nodes, V' to odd nodes) over first-write-wins "
                      "deciders. agree_no_split MUST fire. ")
        : std::string("generated single-value-flood agreement variant — ")) +
        gen_params_str(p);
    s.expect_violation = self_test;

    s.setup = [p](Simulator& sim) {
        sim.add_node("leader");
        for (int i = 0; i < p.followers; ++i) {
            const std::string f = "f" + std::to_string(i);
            sim.add_node(f, [&sim, f](const Message& m) {
                if (m.kind != "DECIDE") return;
                Node& self = sim.state().nodes[f];
                // First-write-wins: latch the first decision, never change it.
                if (self.kv["decided"] == 0)
                    self.kv["decided"] = static_cast<int64_t>(m.payload);
            });
        }
        sim.net().set_base_latency(p.base_latency);
        sim.net().set_jitter(p.jitter);
        sim.net().set_drop_rate(p.drop);
        sim.net().set_dup_rate(p.dup);
        sim.state().scalars["V"] = 42;      // the honest decided value
        const int followers = p.followers;

        // SAFETY: no two followers hold different (non-zero) decided values.
        sim.props().add("agree_no_split", PropKind::SAFETY,
            [](const SimState& st, std::string* d) {
                int64_t ref = 0; std::string ref_id;
                for (const auto& [id, n] : st.nodes) {
                    if (id == "leader") continue;
                    auto it = n.kv.find("decided");
                    const int64_t v = it == n.kv.end() ? 0 : it->second;
                    if (v == 0) continue;                 // undecided — skip
                    if (ref == 0) { ref = v; ref_id = id; continue; }
                    if (v != ref) {
                        if (d) *d = id + " decided=" + std::to_string(v) +
                                    " != " + ref_id + " decided=" +
                                    std::to_string(ref);
                        return false;
                    }
                }
                return true;
            });
        // LIVENESS: every follower eventually decides the honest value V.
        sim.props().add("agree_all_decided", PropKind::LIVENESS,
            [followers](const SimState& st, std::string* d) {
                const int64_t V = st.scalars.count("V") ? st.scalars.at("V") : 0;
                int seen = 0;
                for (const auto& [id, n] : st.nodes) {
                    if (id == "leader") continue;
                    ++seen;
                    auto it = n.kv.find("decided");
                    const int64_t v = it == n.kv.end() ? 0 : it->second;
                    if (v != V) {
                        if (d) *d = id + " decided=" + std::to_string(v) +
                                    " != V=" + std::to_string(V);
                        return false;
                    }
                }
                return seen == followers;
            });
    };

    s.run = [p, correct](Simulator& sim) {
        const int64_t V = 42, Vbad = 43;
        // Flood the decision 30 times (every 25ms). Honest: same V to all.
        // Byzantine (self-test): V to even nodes, V' to odd nodes.
        for (int t = 0; t < 30; ++t)
            sim.after(vt_ms(25 * (t + 1)), [&sim, p, correct, V, Vbad]() {
                for (int i = 0; i < p.followers; ++i) {
                    const int64_t val = correct ? V
                                                : ((i % 2 == 0) ? V : Vbad);
                    sim.send("leader", "f" + std::to_string(i), "DECIDE",
                             static_cast<uint64_t>(val));
                }
            });
    };
    s.check = [](Simulator&) {};
    return s;
}

// ── Increment 7: a THIRD generator template — monotone RATCHET (non-regression) ──
//
// The §Q7 BFT-escalation / commit-index family: a value that must only ever
// ADVANCE, never regress, even under Byzantine leader + faults. A leader ramps
// a ceiling 0→CEIL and re-floods it; each follower keeps a monotone high-water
// mark `hi = max(hi, v)` AND a "committed" value `cur`. An HONEST follower sets
// `cur = hi` (commit the high-water), so `cur == hi` always and the committed
// value never regresses — robust by construction under any drawn drop/dup/
// latency/jitter profile (max-latching is idempotent + reorder-immune, exactly
// like Broadcast's SET(total) and Agreement's first-write-wins). So every
// generated variant PASSES. `correct` controls the FOLLOWER apply + the leader
// tail: true = honest (commit = high-water; leader ramps then holds CEIL);
// false = the planted bug used by the self-test — the follower commits the RAW
// last-seen value (`cur = v`, no max) AND the Byzantine leader sends a DECREASING
// tail after the ceiling, so a raw committer's `cur` drops BELOW its own
// high-water: `ratchet_no_regress` MUST fire (deterministically, on a fixed
// zero-latency profile — no network reorder needed).
inline Scenario make_ratchet_variant(int idx, const GenParams& p,
                                     bool correct, bool self_test,
                                     const char* name_prefix = "gen_ratchet") {
    Scenario s;
    char nm[48];
    if (self_test) std::snprintf(nm, sizeof(nm), "gen_regress_selftest");
    else           std::snprintf(nm, sizeof(nm), "%s_%02d", name_prefix, idx);
    s.name = nm;
    s.description = (self_test
        ? std::string("SELF-TEST: a follower commits the RAW last-seen value (no "
                      "max) and a Byzantine leader sends a decreasing tail, so the "
                      "committed value regresses below its high-water. "
                      "ratchet_no_regress MUST fire. ")
        : std::string("generated monotone-ratchet variant — ")) +
        gen_params_str(p);
    s.expect_violation = self_test;

    s.setup = [p, correct](Simulator& sim) {
        sim.add_node("leader");
        for (int i = 0; i < p.followers; ++i) {
            const std::string f = "f" + std::to_string(i);
            sim.add_node(f, [&sim, f, correct](const Message& m) {
                if (m.kind != "ADVANCE") return;
                Node& self = sim.state().nodes[f];
                const int64_t v = static_cast<int64_t>(m.payload);
                if (v > self.kv["hi"]) self.kv["hi"] = v;      // monotone high-water
                self.kv["cur"] = correct ? self.kv["hi"]       // honest: commit HW
                                         : v;                  // BUG: commit raw
            });
        }
        sim.net().set_base_latency(p.base_latency);
        sim.net().set_jitter(p.jitter);
        sim.net().set_drop_rate(p.drop);
        sim.net().set_dup_rate(p.dup);
        sim.state().scalars["ceil"] = 0;
        const int followers = p.followers;

        // SAFETY: no follower's committed value is below its own high-water mark
        // (i.e. the commit never regressed). Honest commit == hi; the raw-commit
        // bug lets cur < hi after a lower value arrives post-higher.
        sim.props().add("ratchet_no_regress", PropKind::SAFETY,
            [](const SimState& st, std::string* d) {
                for (const auto& [id, n] : st.nodes) {
                    if (id == "leader") continue;
                    auto ih = n.kv.find("hi"), ic = n.kv.find("cur");
                    const int64_t hi  = ih == n.kv.end() ? 0 : ih->second;
                    const int64_t cur = ic == n.kv.end() ? 0 : ic->second;
                    if (cur < hi) {
                        if (d) *d = id + " cur=" + std::to_string(cur) +
                                    " < high-water=" + std::to_string(hi) +
                                    " (regressed)";
                        return false;
                    }
                }
                return true;
            });
        // LIVENESS: every follower's high-water advances to the leader's ceiling.
        sim.props().add("ratchet_advanced", PropKind::LIVENESS,
            [followers](const SimState& st, std::string* d) {
                const int64_t ceil = st.scalars.count("ceil")
                                     ? st.scalars.at("ceil") : 0;
                int seen = 0;
                for (const auto& [id, n] : st.nodes) {
                    if (id == "leader") continue;
                    ++seen;
                    auto it = n.kv.find("hi");
                    const int64_t hi = it == n.kv.end() ? 0 : it->second;
                    if (hi != ceil) {
                        if (d) *d = id + " high-water=" + std::to_string(hi) +
                                    " != ceil=" + std::to_string(ceil);
                        return false;
                    }
                }
                return seen == followers;
            });
    };

    s.run = [p, correct](Simulator& sim) {
        // Ramp the ceiling 0 -> 30 (5 steps of 6, by 100ms), then re-flood it
        // 30x (every 25ms) — drop-tolerant convergence, same shape as Broadcast.
        for (int i = 0; i < 5; ++i)
            sim.after(vt_ms(20 * (i + 1)),
                      [&sim]() { sim.state().scalars["ceil"] += 6; });
        for (int t = 0; t < 30; ++t)
            sim.after(vt_ms(25 * (t + 1)), [&sim, p]() {
                const int64_t c = sim.state().scalars["ceil"];
                for (int i = 0; i < p.followers; ++i)
                    sim.send("leader", "f" + std::to_string(i), "ADVANCE",
                             static_cast<uint64_t>(c));
            });
        // Byzantine (self-test): after the ceiling holds, send a DECREASING tail.
        // A raw committer ends BELOW its high-water; a monotone one is immune.
        if (!correct)
            for (int t = 0; t < 10; ++t)
                sim.after(vt_ms(25 * (31 + t)), [&sim, p]() {
                    for (int i = 0; i < p.followers; ++i)
                        sim.send("leader", "f" + std::to_string(i), "ADVANCE", 3u);
                });
    };
    s.check = [](Simulator&) {};
    return s;
}

// The generator's template catalogue. Broadcast = §Q7 reliable-broadcast
// (no-overcount + convergence); Agreement = §Q7 equivocation/partition
// (no-split + decide); Ratchet = §Q7 BFT-escalation/commit-index
// (no-regress + advance). All draw the SAME randomized fault profiles.
enum class GenTemplate { Broadcast, Agreement, Ratchet };

inline Scenario make_variant(GenTemplate tmpl, int idx, const GenParams& p,
                             bool correct, bool self_test, const char* prefix) {
    switch (tmpl) {
        case GenTemplate::Agreement:
            return make_agreement_variant(idx, p, correct, self_test, prefix);
        case GenTemplate::Ratchet:
            return make_ratchet_variant(idx, p, correct, self_test, prefix);
        default:
            return make_broadcast_variant(idx, p, correct, self_test, prefix);
    }
}

// Register `count` generated variants of `tmpl` from `gen_seed`, plus (unless
// with_selftest is false) a single template-specific self-test that proves a
// generated fault profile surfaces a real bug: `gen_overcount_selftest`
// (Broadcast, non-idempotent apply under forced dup) or `gen_disagree_selftest`
// (Agreement, an equivocating leader over first-write-wins deciders).
inline void register_generated_scenarios(std::vector<Scenario>& out,
                                         uint64_t gen_seed, int count,
                                         const char* name_prefix = "gen_broadcast",
                                         bool with_selftest = true,
                                         GenTemplate tmpl = GenTemplate::Broadcast) {
    SplitMix64 g(gen_seed);
    for (int i = 0; i < count; ++i) {
        GenParams p = draw_params(g);
        out.push_back(make_variant(tmpl, i, p, /*correct=*/true,
                                   /*self_test=*/false, name_prefix));
    }
    if (!with_selftest) return;
    // Self-test on a FIXED profile so the violation is guaranteed (not seed-luck).
    GenParams bug;
    bug.base_latency = 0; bug.jitter = 0;
    if (tmpl == GenTemplate::Agreement) {
        bug.followers = 4; bug.drop = 0.0; bug.dup = 0.0;   // clean delivery; equivocation is the bug
    } else if (tmpl == GenTemplate::Ratchet) {
        bug.followers = 2; bug.drop = 0.0; bug.dup = 0.0;   // clean delivery; raw-commit + decreasing tail is the bug
    } else {
        bug.followers = 2; bug.drop = 0.0; bug.dup = 1.0;   // duplicate everything
    }
    out.push_back(make_variant(tmpl, 0, bug, /*correct=*/false,
                               /*self_test=*/true, name_prefix));
}

} // namespace determ::sim
