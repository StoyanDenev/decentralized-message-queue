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
#include <cctype>
#include <cstdio>
#include <cstdlib>
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

// ── Increment 8: a FOURTH generator template — quorum/threshold COMMIT ──
//
// The §Q7 quorum/threshold family: an action fires only once a THRESHOLD of
// DISTINCT participants has assented (DKG needs T shares; BFT-commit needs
// 2f+1 pre-votes; a merge needs a quorum). A set of ACK sources each ack a
// single "collector"; the collector counts DISTINCT senders (a set keyed on
// the sender id, so duplicate acks from the same source do NOT inflate the
// tally) and commits exactly once that distinct count reaches quorum
// K = floor(N/2)+1. Distinct-set insertion is idempotent under duplication
// and order-immune, so — like Broadcast's monotone-max and Agreement's
// first-write-wins — every generated variant is robust under any drawn
// drop/dup/latency/jitter profile and is expected to PASS (it eventually
// reaches quorum, and it never commits below it). `correct` controls the
// collector's tally: true = count DISTINCT senders (honest); false = the
// planted bug used by the self-test — the collector counts RAW acks
// (duplicates included), so under forced duplication a SINGLE source's acks
// drive the raw tally to K while only ONE distinct sender has assented, and
// the collector commits below quorum: `quorum_no_early_commit` MUST fire.
inline Scenario make_quorum_variant(int idx, const GenParams& p,
                                    bool correct, bool self_test,
                                    const char* name_prefix = "gen_quorum") {
    Scenario s;
    char nm[48];
    if (self_test) std::snprintf(nm, sizeof(nm), "gen_underquorum_selftest");
    else           std::snprintf(nm, sizeof(nm), "%s_%02d", name_prefix, idx);
    s.name = nm;
    s.description = (self_test
        ? std::string("SELF-TEST: a collector counts RAW acks (duplicates "
                      "included) instead of distinct senders, so forced "
                      "duplication drives a single source's acks to quorum and "
                      "it commits below the distinct threshold. "
                      "quorum_no_early_commit MUST fire. ")
        : std::string("generated quorum/threshold-commit variant — ")) +
        gen_params_str(p);
    s.expect_violation = self_test;

    s.setup = [p, correct](Simulator& sim) {
        const int64_t K = p.followers / 2 + 1;   // simple-majority quorum
        // The collector counts assent and commits at quorum. Honest: tally =
        // DISTINCT senders (a set); bug: tally = RAW acks (dup-inflatable).
        // committed_distinct records the TRUE distinct count at commit time
        // (the same set-scan for both variants), which is what SAFETY audits.
        sim.add_node("collector", [&sim, K, correct](const Message& m) {
            if (m.kind != "ACK") return;
            Node& self = sim.state().nodes["collector"];
            self.kv["src_" + m.from] = 1;            // record distinct sender
            self.kv["raw"] += 1;                     // raw acks (dup-inflatable)
            int64_t distinct = 0;                    // true distinct-set size
            for (const auto& [k, v] : self.kv)
                if (v != 0 && k.rfind("src_", 0) == 0) ++distinct;
            const int64_t tally = correct ? distinct : self.kv["raw"];
            if (self.kv["committed"] == 0 && tally >= K) {
                self.kv["committed"] = 1;
                self.kv["committed_distinct"] = distinct;
            }
        });
        for (int i = 0; i < p.followers; ++i)
            sim.add_node("f" + std::to_string(i));   // ack sources (send only)
        sim.net().set_base_latency(p.base_latency);
        sim.net().set_jitter(p.jitter);
        sim.net().set_drop_rate(p.drop);
        sim.net().set_dup_rate(p.dup);

        // SAFETY: the collector never commits with fewer than K DISTINCT
        // assenters. The raw-counting bug lets duplicates carry it over the
        // line with only one true sender.
        sim.props().add("quorum_no_early_commit", PropKind::SAFETY,
            [K](const SimState& st, std::string* d) {
                auto it = st.nodes.find("collector");
                if (it == st.nodes.end()) return true;
                const Node& c = it->second;
                auto cm = c.kv.find("committed");
                if (cm == c.kv.end() || cm->second == 0) return true; // not yet
                auto cd = c.kv.find("committed_distinct");
                const int64_t distinct = cd == c.kv.end() ? 0 : cd->second;
                if (distinct < K) {
                    if (d) *d = "collector committed at distinct=" +
                                std::to_string(distinct) + " < quorum K=" +
                                std::to_string(K);
                    return false;
                }
                return true;
            });
        // LIVENESS: the collector eventually reaches quorum and commits.
        sim.props().add("quorum_commits", PropKind::LIVENESS,
            [](const SimState& st, std::string* d) {
                auto it = st.nodes.find("collector");
                if (it == st.nodes.end()) {
                    if (d) *d = "no collector node";
                    return false;
                }
                auto cm = it->second.kv.find("committed");
                if (cm == it->second.kv.end() || cm->second == 0) {
                    if (d) *d = "collector never reached quorum";
                    return false;
                }
                return true;
            });
    };

    s.run = [p, correct](Simulator& sim) {
        // Each source re-acks the collector 30x (every 25ms), drop-tolerant.
        // Honest: all N sources ack -> distinct reaches N >= K -> quorum.
        // Bug (self-test): ONLY f0 acks, but forced dup inflates the RAW
        // counter to K while distinct stays 1 -> a raw-counting collector
        // commits below quorum -> quorum_no_early_commit fires.
        const int sources = correct ? p.followers : 1;
        for (int t = 0; t < 30; ++t)
            sim.after(vt_ms(25 * (t + 1)), [&sim, sources]() {
                for (int i = 0; i < sources; ++i)
                    sim.send("f" + std::to_string(i), "collector", "ACK", 0);
            });
    };
    s.check = [](Simulator&) {};
    return s;
}

// ── Increment 9: a FIFTH generator template — cross-shard receipt CONSERVATION ──
//
// The §Q7 cross-shard receipt-conservation family (the production FA7
// no-double-credit rule: an applied-receipt registry keyed on receipt id).
// A source issues receipts with unique ids and re-floods them; each ledger
// credits a receipt EXACTLY ONCE, keyed on its id (`r_<id>`), so a duplicated
// or re-delivered receipt never inflates the credited total — robust by
// construction under any drawn drop/dup/latency/jitter profile (per-id
// dedup is idempotent under duplication and reorder-immune; the re-flood
// makes it drop-tolerant, exactly like Broadcast's SET(total)). So every
// generated variant PASSES: it never credits more than was issued, and it
// eventually credits everything. `correct` controls the ledger's apply:
// true = credit-once keyed on receipt id (honest); false = the planted bug
// used by the self-test — the ledger counts RAW deliveries (no id dedup),
// so the very first re-delivery (forced dup and/or the re-flood) drives
// `credited` above the issued total: `conserve_no_double_credit` MUST fire.
inline Scenario make_conservation_variant(int idx, const GenParams& p,
                                          bool correct, bool self_test,
                                          const char* name_prefix = "gen_conserve") {
    Scenario s;
    char nm[48];
    if (self_test) std::snprintf(nm, sizeof(nm), "gen_doublecredit_selftest");
    else           std::snprintf(nm, sizeof(nm), "%s_%02d", name_prefix, idx);
    s.name = nm;
    s.description = (self_test
        ? std::string("SELF-TEST: a ledger counts RAW receipt deliveries (no "
                      "id dedup) under forced duplication, so a re-delivered "
                      "receipt double-credits and the credited total exceeds "
                      "what was issued. conserve_no_double_credit MUST fire. ")
        : std::string("generated receipt-conservation variant — ")) +
        gen_params_str(p);
    s.expect_violation = self_test;

    s.setup = [p, correct](Simulator& sim) {
        sim.add_node("source");
        for (int i = 0; i < p.followers; ++i) {
            const std::string f = "f" + std::to_string(i);
            sim.add_node(f, [&sim, f, correct](const Message& m) {
                if (m.kind != "CREDIT") return;
                Node& self = sim.state().nodes[f];
                const std::string key = "r_" + std::to_string(m.payload);
                if (correct) {
                    // Credit-once keyed on receipt id (the FA7 registry rule).
                    if (self.kv[key] == 0) {
                        self.kv[key] = 1;
                        self.kv["credited"] += 1;
                    }
                } else {
                    self.kv[key] = 1;
                    self.kv["credited"] += 1;   // BUG: raw count, dup-inflatable
                }
            });
        }
        sim.net().set_base_latency(p.base_latency);
        sim.net().set_jitter(p.jitter);
        sim.net().set_drop_rate(p.drop);
        sim.net().set_dup_rate(p.dup);
        sim.state().scalars["issued_receipts"] = 0;
        const int followers = p.followers;

        // SAFETY: no ledger's credited total ever exceeds the receipts issued.
        sim.props().add("conserve_no_double_credit", PropKind::SAFETY,
            [](const SimState& st, std::string* d) {
                const int64_t issued = st.scalars.count("issued_receipts")
                                       ? st.scalars.at("issued_receipts") : 0;
                for (const auto& [id, n] : st.nodes) {
                    if (id == "source") continue;
                    auto it = n.kv.find("credited");
                    const int64_t c = it == n.kv.end() ? 0 : it->second;
                    if (c > issued) {
                        if (d) *d = id + " credited=" + std::to_string(c) +
                                    " > issued=" + std::to_string(issued) +
                                    " (double-credit)";
                        return false;
                    }
                }
                return true;
            });
        // LIVENESS: every ledger eventually credits every issued receipt.
        sim.props().add("conserve_all_credited", PropKind::LIVENESS,
            [followers](const SimState& st, std::string* d) {
                const int64_t issued = st.scalars.count("issued_receipts")
                                       ? st.scalars.at("issued_receipts") : 0;
                int seen = 0;
                for (const auto& [id, n] : st.nodes) {
                    if (id == "source") continue;
                    ++seen;
                    auto it = n.kv.find("credited");
                    const int64_t c = it == n.kv.end() ? 0 : it->second;
                    if (c != issued) {
                        if (d) *d = id + " credited=" + std::to_string(c) +
                                    " != issued=" + std::to_string(issued);
                        return false;
                    }
                }
                return seen == followers;
            });
    };

    s.run = [p](Simulator& sim) {
        // Issue 5 receipts (ids 1..5), one every 20ms.
        for (int i = 0; i < 5; ++i)
            sim.after(vt_ms(20 * (i + 1)),
                      [&sim]() { sim.state().scalars["issued_receipts"] += 1; });
        // Re-flood every issued receipt id 30x (every 25ms) — drop-tolerant;
        // re-delivery is harmless for an honest credit-once ledger and is
        // exactly what detonates the raw-counting bug.
        for (int t = 0; t < 30; ++t)
            sim.after(vt_ms(25 * (t + 1)), [&sim, p]() {
                const int64_t issued = sim.state().scalars["issued_receipts"];
                for (int64_t id = 1; id <= issued; ++id)
                    for (int i = 0; i < p.followers; ++i)
                        sim.send("source", "f" + std::to_string(i), "CREDIT",
                                 static_cast<uint64_t>(id));
            });
    };
    s.check = [](Simulator&) {};
    return s;
}

// ── Increment 10: a SIXTH generator template — F2 view RECONCILIATION ──
//
// The §Q7 F2 view-reconciliation family (the production no_phantom_evidence
// rule: a reconciler merging two peers' views must never hold evidence that
// exists in NEITHER source view). Two sources each flood their half of a
// growing entry universe (src_a the odd ids, src_b the even ids); each
// reconciler merges by union-keyed-on-entry-id (`e_<id>`), so re-delivery
// and reorder never fabricate or duplicate evidence — robust by construction
// under any drawn drop/dup/latency/jitter profile (union-by-id is idempotent
// under duplication and reorder-immune; the re-flood makes it drop-tolerant).
// So every generated variant PASSES: it never holds an entry outside the
// issued universe, and it eventually merges the complete universe from both
// sources. `correct` controls the reconciler's apply: true = honest
// union-by-id; false = the planted bug used by the self-test — on every
// merge the reconciler ALSO fabricates a phantom entry (id+100) that no
// source ever issued: `recon_no_phantom` MUST fire (deterministically, on a
// clean-delivery profile — the bug is in the apply, not the network).
inline Scenario make_reconcile_variant(int idx, const GenParams& p,
                                       bool correct, bool self_test,
                                       const char* name_prefix = "gen_recon") {
    Scenario s;
    char nm[48];
    if (self_test) std::snprintf(nm, sizeof(nm), "gen_phantom_selftest");
    else           std::snprintf(nm, sizeof(nm), "%s_%02d", name_prefix, idx);
    s.name = nm;
    s.description = (self_test
        ? std::string("SELF-TEST: a reconciler fabricates a phantom entry "
                      "(id+100, issued by NO source view) on every merge. "
                      "recon_no_phantom MUST fire. ")
        : std::string("generated view-reconciliation variant — ")) +
        gen_params_str(p);
    s.expect_violation = self_test;

    s.setup = [p, correct](Simulator& sim) {
        sim.add_node("src_a");
        sim.add_node("src_b");
        for (int i = 0; i < p.followers; ++i) {
            const std::string f = "f" + std::to_string(i);
            sim.add_node(f, [&sim, f, correct](const Message& m) {
                if (m.kind != "ENTRY") return;
                Node& self = sim.state().nodes[f];
                const int64_t id = static_cast<int64_t>(m.payload);
                // Honest: union keyed on entry id (idempotent, reorder-immune).
                const std::string key = "e_" + std::to_string(id);
                if (self.kv[key] == 0) {
                    self.kv[key] = 1;
                    self.kv["merged"] += 1;
                }
                if (!correct) {
                    // BUG: fabricate evidence present in NO source view.
                    const std::string ph = "e_" + std::to_string(id + 100);
                    if (self.kv[ph] == 0) {
                        self.kv[ph] = 1;
                        self.kv["merged"] += 1;
                    }
                }
            });
        }
        sim.net().set_base_latency(p.base_latency);
        sim.net().set_jitter(p.jitter);
        sim.net().set_drop_rate(p.drop);
        sim.net().set_dup_rate(p.dup);
        sim.state().scalars["issued_hi"] = 0;   // issued universe = ids 1..issued_hi
        const int followers = p.followers;

        // SAFETY: no reconciler holds an entry outside the issued universe.
        sim.props().add("recon_no_phantom", PropKind::SAFETY,
            [](const SimState& st, std::string* d) {
                const int64_t hi = st.scalars.count("issued_hi")
                                   ? st.scalars.at("issued_hi") : 0;
                for (const auto& [id, n] : st.nodes) {
                    if (id == "src_a" || id == "src_b") continue;
                    for (const auto& [k, v] : n.kv) {
                        // Entry keys are exactly "e_<digits>"; the digit guard
                        // keeps a future non-entry "e_*" bookkeeping key from
                        // parsing to 0 and false-firing the invariant.
                        if (v == 0 || k.rfind("e_", 0) != 0 || k.size() < 3 ||
                            !std::isdigit(static_cast<unsigned char>(k[2])))
                            continue;
                        const int64_t eid = std::strtoll(k.c_str() + 2,
                                                         nullptr, 10);
                        if (eid < 1 || eid > hi) {
                            if (d) *d = id + " holds phantom entry e_" +
                                        std::to_string(eid) +
                                        " outside issued 1.." +
                                        std::to_string(hi);
                            return false;
                        }
                    }
                }
                return true;
            });
        // LIVENESS: every reconciler merges the complete issued universe.
        sim.props().add("recon_complete", PropKind::LIVENESS,
            [followers](const SimState& st, std::string* d) {
                const int64_t hi = st.scalars.count("issued_hi")
                                   ? st.scalars.at("issued_hi") : 0;
                int seen = 0;
                for (const auto& [id, n] : st.nodes) {
                    if (id == "src_a" || id == "src_b") continue;
                    ++seen;
                    auto it = n.kv.find("merged");
                    const int64_t m = it == n.kv.end() ? 0 : it->second;
                    if (m != hi) {
                        if (d) *d = id + " merged=" + std::to_string(m) +
                                    " != issued=" + std::to_string(hi);
                        return false;
                    }
                }
                return seen == followers;
            });
    };

    s.run = [p](Simulator& sim) {
        // Grow the issued universe to 6 entries (one every 20ms). src_a owns
        // the odd ids, src_b the even ids — two genuinely distinct views.
        for (int i = 0; i < 6; ++i)
            sim.after(vt_ms(20 * (i + 1)),
                      [&sim]() { sim.state().scalars["issued_hi"] += 1; });
        // Each source re-floods its half of the issued universe 30x (every
        // 25ms) — drop-tolerant; re-delivery is harmless for union-by-id.
        for (int t = 0; t < 30; ++t)
            sim.after(vt_ms(25 * (t + 1)), [&sim, p]() {
                const int64_t hi = sim.state().scalars["issued_hi"];
                for (int64_t id = 1; id <= hi; ++id) {
                    const char* src = (id % 2 == 1) ? "src_a" : "src_b";
                    for (int i = 0; i < p.followers; ++i)
                        sim.send(src, "f" + std::to_string(i), "ENTRY",
                                 static_cast<uint64_t>(id));
                }
            });
    };
    s.check = [](Simulator&) {};
    return s;
}

// ── Increment 11: a SEVENTH generator template — CRASH/RECOVER replay ──
//
// The §Q7 crash-recovery family — the first generated template to exercise
// the simulator's crash/recover seam (Node::alive; deliveries to a crashed
// node are dropped, its kv PERSISTS). Because state persists, the HONEST
// recovery procedure is to do NOTHING: a monotone-max follower that missed
// messages while down is healed by the leader's re-flood, exactly like a
// transient drop burst. The real-world bug class this template targets is
// the NON-IDEMPOTENT RECOVERY REPLAY: a node that re-applies its pre-crash
// journal ON TOP of already-persisted state after restart. Every follower
// crashes and recovers on a DETERMINISTIC schedule (a function of its index,
// consuming no PRNG — generation stays byte-stable and the crash path is
// non-vacuous by construction), layered under the drawn drop/dup/latency/
// jitter profile. `correct` controls the recovery procedure: true = honest
// (persisted state stands, nothing replayed); false = the planted bug used
// by the self-test — at crash the follower snapshots its count, at recovery
// it ADDS the snapshot back (`count += saved`, the classic redo-log
// double-apply), driving count above the issued total:
// `crashrec_no_replay` MUST fire.
inline Scenario make_crashrec_variant(int idx, const GenParams& p,
                                      bool correct, bool self_test,
                                      const char* name_prefix = "gen_crashrec") {
    Scenario s;
    char nm[48];
    if (self_test) std::snprintf(nm, sizeof(nm), "gen_replay_selftest");
    else           std::snprintf(nm, sizeof(nm), "%s_%02d", name_prefix, idx);
    s.name = nm;
    s.description = (self_test
        ? std::string("SELF-TEST: a follower's recovery procedure re-applies "
                      "its pre-crash journal ON TOP of persisted state "
                      "(count += saved, a non-idempotent redo-log replay), "
                      "driving the count above the issued total. "
                      "crashrec_no_replay MUST fire. ")
        : std::string("generated crash/recover replay variant — ")) +
        gen_params_str(p);
    s.expect_violation = self_test;

    s.setup = [p](Simulator& sim) {
        sim.add_node("leader");
        for (int i = 0; i < p.followers; ++i) {
            const std::string f = "f" + std::to_string(i);
            sim.add_node(f, [&sim, f](const Message& m) {
                if (m.kind != "SET") return;
                Node& self = sim.state().nodes[f];
                const int64_t v = static_cast<int64_t>(m.payload);
                if (v > self.kv["count"]) self.kv["count"] = v;   // monotone max
            });
        }
        sim.net().set_base_latency(p.base_latency);
        sim.net().set_jitter(p.jitter);
        sim.net().set_drop_rate(p.drop);
        sim.net().set_dup_rate(p.dup);
        sim.state().scalars["issued"]     = 0;
        sim.state().scalars["crashes"]    = 0;
        sim.state().scalars["recoveries"] = 0;
        const int followers = p.followers;

        // SAFETY: no follower's count ever exceeds the issued total — the
        // replay bug pushes a recovered follower's count above it.
        sim.props().add("crashrec_no_replay", PropKind::SAFETY,
            [](const SimState& st, std::string* d) {
                const int64_t issued = st.scalars.count("issued")
                                       ? st.scalars.at("issued") : 0;
                for (const auto& [id, n] : st.nodes) {
                    if (id == "leader") continue;
                    auto it = n.kv.find("count");
                    const int64_t c = it == n.kv.end() ? 0 : it->second;
                    if (c > issued) {
                        if (d) *d = id + " count=" + std::to_string(c) +
                                    " > issued=" + std::to_string(issued) +
                                    " (recovery replay)";
                        return false;
                    }
                }
                return true;
            });
        // LIVENESS: every follower crashed once, recovered once, AND still
        // converged to the final issued total (the re-flood healed the gap).
        sim.props().add("crashrec_all_converged", PropKind::LIVENESS,
            [followers](const SimState& st, std::string* d) {
                const int64_t issued = st.scalars.count("issued")
                                       ? st.scalars.at("issued") : 0;
                const int64_t cr = st.scalars.count("crashes")
                                   ? st.scalars.at("crashes") : 0;
                const int64_t rc = st.scalars.count("recoveries")
                                   ? st.scalars.at("recoveries") : 0;
                if (cr != followers || rc != followers) {
                    if (d) *d = "crash path vacuous: crashes=" +
                                std::to_string(cr) + " recoveries=" +
                                std::to_string(rc) + " != followers=" +
                                std::to_string(followers);
                    return false;
                }
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

    s.run = [p, correct](Simulator& sim) {
        // Issue 5 increments (issued reaches 5 by 100ms).
        for (int i = 0; i < 5; ++i)
            sim.after(vt_ms(20 * (i + 1)),
                      [&sim]() { sim.state().scalars["issued"] += 1; });
        // Deterministic staggered crash/recover schedule (no PRNG): follower
        // i is down for vt [110+30i, 230+30i) ms. Worst-case recovery is
        // 320ms; the re-flood runs to 1000ms, so a recovered follower has
        // >= 27 heal attempts even at drop=0.5.
        for (int i = 0; i < p.followers; ++i) {
            const std::string f = "f" + std::to_string(i);
            sim.after(vt_ms(110 + 30 * i), [&sim, f, correct]() {
                Node& n = sim.state().nodes[f];
                if (!correct) n.kv["saved"] = n.kv["count"];  // journal snapshot
                sim.crash(f);
                sim.state().scalars["crashes"] += 1;
            });
            sim.after(vt_ms(230 + 30 * i), [&sim, f, correct]() {
                sim.recover(f);
                sim.state().scalars["recoveries"] += 1;
                if (!correct) {
                    // BUG: non-idempotent redo-log replay on restart — the
                    // journal is re-applied ON TOP of the persisted state.
                    Node& n = sim.state().nodes[f];
                    n.kv["count"] += n.kv["saved"];
                }
            });
        }
        // Re-flood the current issued total 40x (every 25ms) — heals every
        // recovered follower; harmless to an idempotent monotone-max apply.
        for (int t = 0; t < 40; ++t)
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

// The generator's template catalogue. Broadcast = §Q7 reliable-broadcast
// (no-overcount + convergence); Agreement = §Q7 equivocation/partition
// (no-split + decide); Ratchet = §Q7 BFT-escalation/commit-index
// (no-regress + advance); Quorum = §Q7 quorum/threshold-commit
// (no-early-commit + reaches-quorum); Conservation = §Q7 cross-shard
// receipt conservation (no-double-credit + all-credited); Reconcile = §Q7
// F2 view reconciliation (no-phantom + complete-merge); CrashRecover = §Q7
// crash-recovery replay (no-replay + converge-after-recovery). All draw the
// SAME randomized fault profiles.
enum class GenTemplate { Broadcast, Agreement, Ratchet, Quorum, Conservation,
                         Reconcile, CrashRecover };

inline Scenario make_variant(GenTemplate tmpl, int idx, const GenParams& p,
                             bool correct, bool self_test, const char* prefix) {
    switch (tmpl) {
        case GenTemplate::Agreement:
            return make_agreement_variant(idx, p, correct, self_test, prefix);
        case GenTemplate::Ratchet:
            return make_ratchet_variant(idx, p, correct, self_test, prefix);
        case GenTemplate::Quorum:
            return make_quorum_variant(idx, p, correct, self_test, prefix);
        case GenTemplate::Conservation:
            return make_conservation_variant(idx, p, correct, self_test, prefix);
        case GenTemplate::Reconcile:
            return make_reconcile_variant(idx, p, correct, self_test, prefix);
        case GenTemplate::CrashRecover:
            return make_crashrec_variant(idx, p, correct, self_test, prefix);
        default:
            return make_broadcast_variant(idx, p, correct, self_test, prefix);
    }
}

// Register `count` generated variants of `tmpl` from `gen_seed`, plus (unless
// with_selftest is false) a single template-specific self-test that proves the
// template's checker fires on the planted bug it targets — one twin per
// template, on the FIXED profile chosen in the per-template branch below (so
// the violation is guaranteed by construction, never seed-luck).
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
    } else if (tmpl == GenTemplate::Quorum) {
        bug.followers = 2; bug.drop = 0.0; bug.dup = 1.0;   // dup everything; a single source's raw acks reach K=2 at distinct=1
    } else if (tmpl == GenTemplate::Conservation) {
        bug.followers = 2; bug.drop = 0.0; bug.dup = 1.0;   // dup everything; raw counting credits the first re-delivery
    } else if (tmpl == GenTemplate::Reconcile) {
        bug.followers = 2; bug.drop = 0.0; bug.dup = 0.0;   // clean delivery; the fabricated phantom entry is the bug
    } else if (tmpl == GenTemplate::CrashRecover) {
        bug.followers = 2; bug.drop = 0.0; bug.dup = 0.0;   // clean delivery; the recovery replay double-apply is the bug
    } else {
        bug.followers = 2; bug.drop = 0.0; bug.dup = 1.0;   // duplicate everything
    }
    out.push_back(make_variant(tmpl, 0, bug, /*correct=*/false,
                               /*self_test=*/true, name_prefix));
}

} // namespace determ::sim
