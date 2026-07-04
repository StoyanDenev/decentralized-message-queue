// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// DSF (Deterministic-Simulation Framework) INCREMENT 1 — scenario DSL +
// simulator core. Per docs/proofs/DSF-SPEC.md §Q3, §4.2 (net seam), §4.3.
//
// A Scenario is: a name + a setup lambda + a set of nodes + injected faults
// (drop / delay / partition / duplicate at the abstraction level) + property
// assertions. The Simulator ties together the virtual clock, the deterministic
// scheduler, the byte-stable trace, the virtual-network SEAM, and the property
// checker into one run-to-completion loop.
//
// VIRTUAL-NETWORK SEAM (increment 1). DSF-SPEC §Q2/§4.2 calls for a full
// net::Transport abstraction wrapping asio, with per-link latency/drop/
// partition/duplicate/tamper controls, wired to real Determ Gossip. That is a
// LATER increment. Here we ship the SEAM: a NetModel that the simulator
// consults for every message to decide DROP / DELAY / DUPLICATE / PARTITION.
// Scenarios drive it deterministically (fault decisions route through the
// scheduler's seeded PRNG). Swapping the toy in-process message bus for real
// gossip later means implementing this same seam against VirtualTransport.
#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include "scheduler.hpp"
#include "trace.hpp"
#include "property.hpp"

namespace determ::sim {

using NodeId = std::string;

// A framework-demonstration message. In a later increment this carries real
// serialized consensus bytes; here it is a kind token + a 64-bit payload,
// enough to drive the toy scenarios (counter increments, heartbeats, votes).
struct Message {
    NodeId   from;
    NodeId   to;
    std::string kind;    // e.g. "INC", "HEARTBEAT", "VOTE"
    uint64_t payload = 0;
    uint64_t msg_id  = 0; // unique per send; used for dedup / duplicate faults
};

// Per-node scriptable state. Increment-1 nodes hold a small generic key/value
// store plus an "alive" flag; a later increment replaces this with a real
// Validator instance. `on_recv` is the node's message handler, installed by
// the scenario setup.
struct Node {
    NodeId                          id;
    bool                            alive = true;
    std::map<std::string, int64_t>  kv;   // generic scriptable state
    std::function<void(const Message&)> on_recv;
};

// The full simulation state a property invariant reads. Deliberately concrete
// and copy-cheap so invariants stay pure functions of it. Later increments add
// chain/committee/supply views; increment-1 invariants read nodes + counters.
struct SimState {
    std::map<NodeId, Node> nodes;
    uint64_t messages_sent      = 0;
    uint64_t messages_delivered = 0;
    uint64_t messages_dropped   = 0;
    uint64_t messages_duplicated = 0;
    uint64_t step               = 0;
    // Scenario-specific scalar bag (e.g. "expected_total", "commit_height").
    std::map<std::string, int64_t> scalars;
};

// ---------------------------------------------------------------------------
// NetModel — the virtual-network fault SEAM. For each message the simulator
// asks the model: is the link partitioned? should this message be dropped?
// what extra latency applies? should it be duplicated? All decisions are
// deterministic functions of the scheduler's seeded PRNG + the configured
// fault parameters, so a fixed seed reproduces the exact fault pattern.
// ---------------------------------------------------------------------------
class NetModel {
public:
    // Base per-link latency added to every delivered message.
    void set_base_latency(VTime lat) { base_latency_ = lat; }
    VTime base_latency() const { return base_latency_; }

    // Probabilistic drop applied to every link (0..1).
    void set_drop_rate(double r) { drop_rate_ = r; }

    // Probabilistic duplicate applied to every delivered message (0..1). A
    // duplicated message is delivered a second time after an extra latency.
    void set_dup_rate(double r) { dup_rate_ = r; }

    // Extra random jitter added to latency, uniform in [0, jitter].
    void set_jitter(VTime j) { jitter_ = j; }

    // Bidirectional partition between two nodes: messages either way are
    // dropped until the partition is healed.
    void partition(const NodeId& a, const NodeId& b) {
        partitioned_.insert(link_key(a, b));
    }
    void heal(const NodeId& a, const NodeId& b) {
        partitioned_.erase(link_key(a, b));
    }
    void heal_all() { partitioned_.clear(); }

    bool is_partitioned(const NodeId& a, const NodeId& b) const {
        return partitioned_.count(link_key(a, b)) != 0;
    }

    // Decide the fate of a message. Returns:
    //   deliver  : false => dropped (partition or drop-rate).
    //   latency  : virtual delay before delivery.
    //   duplicate: true => deliver a second copy after `dup_latency`.
    struct Decision {
        bool  deliver   = true;
        VTime latency   = 0;
        bool  duplicate = false;
        VTime dup_latency = 0;
        const char* reason = "ok";
    };

    Decision decide(const Message& m, SplitMix64& rng) const {
        Decision d;
        if (is_partitioned(m.from, m.to)) {
            d.deliver = false;
            d.reason = "partition";
            return d;
        }
        if (rng.bernoulli(drop_rate_)) {
            d.deliver = false;
            d.reason = "droprate";
            return d;
        }
        d.latency = base_latency_;
        if (jitter_ > 0) d.latency += rng.next_below(jitter_ + 1);
        if (rng.bernoulli(dup_rate_)) {
            d.duplicate = true;
            d.dup_latency = d.latency + (base_latency_ > 0 ? base_latency_ : 1);
            d.reason = "dup";
        }
        return d;
    }

private:
    static std::string link_key(const NodeId& a, const NodeId& b) {
        // Order-independent key so partition(a,b) == partition(b,a).
        return a < b ? a + "|" + b : b + "|" + a;
    }
    VTime  base_latency_ = 0;
    VTime  jitter_       = 0;
    double drop_rate_    = 0.0;
    double dup_rate_     = 0.0;
    std::set<std::string> partitioned_;
};

// Forward decl.
class Simulator;

// ---------------------------------------------------------------------------
// Scenario — the DSL surface. A scenario is registered with a name + three
// lifecycle hooks (setup / run / check) matching DSF-SPEC §Q3. `properties`
// carries the registered invariants. `expect_violation` marks a deliberately-
// falsifiable scenario (used to prove the checker actually catches failures).
// ---------------------------------------------------------------------------
struct Scenario {
    std::string name;
    std::string description;
    // If true, the runner EXPECTS a property violation (a self-test that the
    // checker fires). Exit code semantics in dsf_main invert accordingly.
    bool expect_violation = false;

    // Lifecycle hooks. All receive the Simulator so they can add nodes,
    // schedule events, and configure the net model. `check` may register
    // end-of-run liveness assertions or inspect final state directly.
    std::function<void(Simulator&)> setup;
    std::function<void(Simulator&)> run;
    std::function<void(Simulator&)> check;
};

// ---------------------------------------------------------------------------
// Simulator — the run-to-completion core. Owns the scheduler (clock + rng),
// the net model, the trace writer, the property set, and the sim state.
// ---------------------------------------------------------------------------
class Simulator {
public:
    Simulator(uint64_t seed, TraceWriter& trace)
        : sched_(seed), trace_(trace) {}

    // ---- accessors used by scenario lambdas ----
    Scheduler&   sched()  { return sched_; }
    SplitMix64&  rng()    { return sched_.rng(); }
    VTime        now()    { return sched_.now(); }
    NetModel&    net()    { return net_; }
    PropertySet& props()  { return props_; }
    SimState&    state()  { return state_; }
    TraceWriter& trace()  { return trace_; }
    uint64_t     seed()   { return sched_.seed(); }

    // Register a node with a receive handler.
    Node& add_node(const NodeId& id,
                   std::function<void(const Message&)> on_recv = {}) {
        Node n;
        n.id      = id;
        n.on_recv = std::move(on_recv);
        auto [it, ins] = state_.nodes.emplace(id, std::move(n));
        trace_.emit(now(), id, "NODE",
                    ins ? "registered" : "duplicate-id");
        return it->second;
    }

    // Convenience: mark a node crashed / recovered.
    void crash(const NodeId& id) {
        auto it = state_.nodes.find(id);
        if (it != state_.nodes.end()) it->second.alive = false;
        trace_.emit(now(), id, "CRASH", "-");
    }
    void recover(const NodeId& id) {
        auto it = state_.nodes.find(id);
        if (it != state_.nodes.end()) it->second.alive = true;
        trace_.emit(now(), id, "RECOVER", "-");
    }

    // Send a message from -> to. The net model decides drop / latency /
    // duplicate; delivery is scheduled on the scheduler so ordering stays
    // deterministic. Every decision is traced.
    void send(const NodeId& from, const NodeId& to,
              const std::string& kind, uint64_t payload = 0) {
        Message m{from, to, kind, payload, next_msg_id_++};
        state_.messages_sent++;
        trace_.emit(now(), from, "SEND",
                    to + " " + kind + " p=" + std::to_string(payload) +
                    " id=" + std::to_string(m.msg_id));

        NetModel::Decision d = net_.decide(m, rng());
        if (!d.deliver) {
            state_.messages_dropped++;
            trace_.emit(now(), to, "DROP",
                        std::string(d.reason) + " id=" + std::to_string(m.msg_id));
            return;
        }
        schedule_delivery(m, d.latency, /*is_dup=*/false);
        if (d.duplicate) {
            state_.messages_duplicated++;
            schedule_delivery(m, d.dup_latency, /*is_dup=*/true);
        }
    }

    // Schedule an arbitrary action (used by scenarios for timers/ticks).
    void at(VTime t, EventFn fn)      { sched_.schedule_at(t, std::move(fn)); }
    void after(VTime d, EventFn fn)   { sched_.schedule_after(d, std::move(fn)); }

    // Trace a scenario-defined event (STATE, TICK, etc.).
    void log(const NodeId& node, const std::string& kind,
             const std::string& detail) {
        trace_.emit(now(), node, kind, detail);
    }

    // Run the loop. After each delivered event, SAFETY invariants are checked.
    // Returns false if any safety invariant was violated during the run.
    // `max_events` bounds runaway scenarios (0 = unbounded, capped internally).
    bool run_loop(uint64_t max_events = 0) {
        const uint64_t cap = max_events ? max_events : DEFAULT_EVENT_CAP;
        // We drive the scheduler one event at a time so we can interleave the
        // per-step safety check. This keeps the (VTime, seq) pop order intact.
        while (sched_.pending() > 0) {
            if (state_.step >= cap) {
                trace_.emit(now(), "-", "CAP",
                            "event-cap " + std::to_string(cap) + " reached");
                break;
            }
            sched_.run(sched_.fired() + 1); // fire exactly one event
            state_.step++;
            if (!props_.check_safety(state_, state_.step, now())) {
                // Record but keep running so the trace shows the full picture;
                // the runner decides exit code from props_.any_violation().
                for (const auto& v : props_.violations()) {
                    trace_.emit(now(), "-", "VIOLATION",
                                std::string(to_string(v.kind)) + " " +
                                v.name + " :: " + v.detail);
                }
                trace_.flush();
                return false;
            }
        }
        return true;
    }

    static constexpr uint64_t DEFAULT_EVENT_CAP = 1000000;

private:
    void schedule_delivery(const Message& m, VTime latency, bool is_dup) {
        Message copy = m;
        sched_.schedule_after(latency, [this, copy, is_dup]() {
            auto it = state_.nodes.find(copy.to);
            if (it == state_.nodes.end() || !it->second.alive) {
                trace_.emit(now(), copy.to, "DROP",
                            "unreachable id=" + std::to_string(copy.msg_id));
                state_.messages_dropped++;
                return;
            }
            state_.messages_delivered++;
            trace_.emit(now(), copy.to, is_dup ? "RECV-DUP" : "RECV",
                        copy.from + " " + copy.kind +
                        " p=" + std::to_string(copy.payload) +
                        " id=" + std::to_string(copy.msg_id));
            if (it->second.on_recv) it->second.on_recv(copy);
        });
    }

    Scheduler   sched_;
    NetModel    net_;
    TraceWriter& trace_;
    PropertySet props_;
    SimState    state_;
    uint64_t    next_msg_id_ = 1;
};

} // namespace determ::sim
