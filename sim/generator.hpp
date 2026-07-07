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
                                       bool idempotent, bool self_test) {
    Scenario s;
    char nm[40];
    std::snprintf(nm, sizeof(nm), self_test ? "gen_overcount_selftest"
                                            : "gen_broadcast_%02d", idx);
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

// Register `count` reliable-broadcast variants generated from `gen_seed`, plus a
// single `gen_overcount_selftest` that proves a generated fault profile surfaces
// a real (non-idempotent-apply) bug.
inline void register_generated_scenarios(std::vector<Scenario>& out,
                                         uint64_t gen_seed, int count) {
    SplitMix64 g(gen_seed);
    for (int i = 0; i < count; ++i) {
        GenParams p = draw_params(g);
        out.push_back(make_broadcast_variant(i, p, /*idempotent=*/true,
                                             /*self_test=*/false));
    }
    // Self-test: a non-idempotent apply under a forced-duplicate profile
    // overcounts. Fixed profile so the violation is guaranteed (not seed-luck).
    GenParams bug;
    bug.followers = 2; bug.base_latency = 0; bug.jitter = 0;
    bug.drop = 0.0; bug.dup = 1.0;                 // duplicate everything
    out.push_back(make_broadcast_variant(0, bug, /*idempotent=*/false,
                                         /*self_test=*/true));
}

} // namespace determ::sim
