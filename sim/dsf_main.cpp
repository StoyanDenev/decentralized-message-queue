// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// DSF (Deterministic-Simulation Framework) INCREMENT 1 — determ-dsf runner.
// Per docs/proofs/DSF-SPEC.md §Q6 replay tooling and §4.6.
//
// Usage:
//   determ-dsf --list
//   determ-dsf --scenario <name> [--seed <hex|dec>] [--trace <path|-|off>]
//                                 [--max-events N] [--quiet]
//
// Exit codes:
//   0  scenario ran and its property expectation held
//        (no violation for a normal scenario; a violation DID occur for a
//         scenario marked expect_violation, i.e. the checker self-test passed).
//   1  a property invariant was violated unexpectedly (or a required violation
//      did NOT occur). The reproducing seed + trace path are printed.
//   2  usage / unknown-scenario error.
//
// DETERMINISM CONTRACT: identical (--scenario, --seed) => byte-identical trace.
// No wall-clock, no OS RNG anywhere in the loop. Re-run with the printed seed
// to reproduce any failure exactly.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include "scenario.hpp"
#include "scenarios.hpp"
#include "scenarios_inc2.hpp"
#include "scenarios_inc3.hpp"
#include "generator.hpp"

namespace {

using namespace determ::sim;

// Parse a seed given as 0x-hex or decimal. Returns false on garbage.
bool parse_seed(const std::string& s, uint64_t& out) {
    try {
        size_t pos = 0;
        if (s.size() > 2 && (s[0] == '0') && (s[1] == 'x' || s[1] == 'X')) {
            out = std::stoull(s.substr(2), &pos, 16);
            return pos == s.size() - 2;
        }
        out = std::stoull(s, &pos, 10);
        return pos == s.size();
    } catch (...) {
        return false;
    }
}

const Scenario* find_scenario(const std::vector<Scenario>& v,
                              const std::string& name) {
    for (const auto& s : v)
        if (s.name == name) return &s;
    return nullptr;
}

void print_list(const std::vector<Scenario>& v) {
    std::cout << "DSF scenarios (" << v.size() << " registered):\n";
    for (const auto& s : v) {
        std::cout << "  " << s.name;
        if (s.expect_violation) std::cout << "  [expect-violation self-test]";
        std::cout << "\n      " << s.description << "\n";
    }
}

void print_usage() {
    std::cout <<
        "determ-dsf — Deterministic-Simulation Framework runner (increment 1)\n"
        "\n"
        "  determ-dsf --list\n"
        "  determ-dsf --scenario <name> [--seed <hex|dec>] "
        "[--trace <path|-|off>] [--max-events N] [--quiet]\n"
        "  determ-dsf --generate N [--seed <hex|dec>] --list   "
        "(register + list/run N seed-driven variants)\n"
        "\n"
        "Same --scenario + --seed => byte-identical trace. Re-run the printed\n"
        "seed to reproduce any failure.\n";
}

} // namespace

int main(int argc, char** argv) {
    std::vector<Scenario> scenarios;
    register_seed_scenarios(scenarios);
    register_inc2_scenarios(scenarios);   // increment-2 adversarial scenarios
    register_inc3_scenarios(scenarios);   // increment-3 adversarial scenarios
    register_generated_scenarios(scenarios, 0x9E5C6Eull, 6); // increment-4 §Q5 generated variants

    std::string scenario_name;
    std::string trace_path = "off";     // default: no trace file
    std::string seed_str    = "0x1";    // default deterministic seed
    uint64_t    max_events  = 0;         // 0 => framework default cap
    bool        quiet       = false;
    bool        want_list   = false;
    uint64_t    generate_count = 0;      // --generate N: N seed-driven variants

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* flag) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "error: " << flag << " requires an argument\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--list")          { want_list = true; }
        else if (a == "--generate") { generate_count = std::stoull(need("--generate")); }
        else if (a == "--help" || a == "-h") { print_usage(); return 0; }
        else if (a == "--scenario") { scenario_name = need("--scenario"); }
        else if (a == "--seed")     { seed_str      = need("--seed"); }
        else if (a == "--trace")    { trace_path    = need("--trace"); }
        else if (a == "--max-events") { max_events  = std::stoull(need("--max-events")); }
        else if (a == "--quiet")    { quiet = true; }
        else {
            std::cerr << "error: unknown argument '" << a << "'\n";
            print_usage();
            return 2;
        }
    }

    uint64_t seed = 0;
    if (!parse_seed(seed_str, seed)) {
        std::cerr << "error: bad --seed '" << seed_str
                  << "' (want 0xHEX or decimal)\n";
        return 2;
    }

    // §Q5/§Q6: --generate N registers N reliable-broadcast variants seeded by
    // the run --seed, named gen_run_00..0(N-1). Same (--generate N, --seed S)
    // => the same variant set on any host; each is then runnable / listable.
    if (generate_count > 0)
        register_generated_scenarios(scenarios, seed,
                                     static_cast<int>(generate_count),
                                     "gen_run", /*with_selftest=*/false);

    if (want_list) { print_list(scenarios); return 0; }

    if (scenario_name.empty()) {
        std::cerr << "error: --scenario <name> is required (see --list)\n";
        return 2;
    }

    const Scenario* sc = find_scenario(scenarios, scenario_name);
    if (!sc) {
        std::cerr << "error: unknown scenario '" << scenario_name
                  << "' (see --list)\n";
        return 2;
    }

    // Format the seed canonically as 0x-hex for reproducibility messages.
    auto hex_seed = [](uint64_t s) {
        char buf[19];
        std::snprintf(buf, sizeof(buf), "0x%llx",
                      static_cast<unsigned long long>(s));
        return std::string(buf);
    };

    // Wire the trace writer.
    TraceWriter trace;
    if (trace_path == "-") {
        trace.set_mirror(&std::cout);
    } else if (trace_path != "off") {
        if (!trace.open(trace_path)) {
            std::cerr << "error: cannot open trace file '" << trace_path
                      << "'\n";
            return 2;
        }
    }

    if (!quiet) {
        std::cout << "[seed " << hex_seed(seed) << "] running "
                  << sc->name << "...\n";
    }

    // Build the simulator and run the scenario lifecycle deterministically.
    Simulator sim(seed, trace);
    trace.emit(0, "-", "SCENARIO", sc->name + " seed=" + hex_seed(seed));

    if (sc->setup) sc->setup(sim);
    if (sc->run)   sc->run(sim);

    bool safety_ok = sim.run_loop(max_events);

    // End-of-run liveness check (only meaningful if safety survived; a safety
    // break already short-circuits, but we still evaluate liveness for the
    // report unless we're in the expect-violation self-test path).
    bool liveness_ok = sim.props().check_liveness(sim.state(), sim.now());

    if (sc->check) sc->check(sim);

    trace.emit(sim.now(), "-", "END",
               "steps=" + std::to_string(sim.state().step) +
               " sent=" + std::to_string(sim.state().messages_sent) +
               " delivered=" + std::to_string(sim.state().messages_delivered) +
               " dropped=" + std::to_string(sim.state().messages_dropped) +
               " dup=" + std::to_string(sim.state().messages_duplicated));
    trace.flush();

    bool violated = sim.props().any_violation() || !safety_ok || !liveness_ok;

    // ---- Report + exit-code logic ---------------------------------------
    if (sc->expect_violation) {
        // Self-test: a violation is the SUCCESS condition.
        if (violated) {
            if (!quiet) {
                std::cout << "[seed " << hex_seed(seed)
                          << "] PASS (self-test): expected violation fired\n";
                for (const auto& v : sim.props().violations())
                    std::cout << "    [" << to_string(v.kind) << "] "
                              << v.name << " @vtime=" << v.vtime
                              << " step=" << v.step << " :: " << v.detail
                              << "\n";
            }
            trace.close();
            return 0;
        }
        std::cerr << "[seed " << hex_seed(seed)
                  << "] FAIL: expected a violation but none fired "
                     "(checker did not catch the planted bug)\n";
        trace.close();
        return 1;
    }

    // Normal scenario: any violation is a failure.
    if (violated) {
        std::cerr << "[seed " << hex_seed(seed) << "] FAIL: "
                  << sim.props().violations().size()
                  << " invariant violation(s) in " << sc->name << "\n";
        for (const auto& v : sim.props().violations()) {
            std::cerr << "    [" << to_string(v.kind) << "] " << v.name
                      << " @vtime=" << v.vtime << " step=" << v.step
                      << " :: " << v.detail << "\n";
        }
        std::cerr << "  reproduce with: determ-dsf --scenario " << sc->name
                  << " --seed " << hex_seed(seed);
        if (trace_path != "off" && trace_path != "-")
            std::cerr << " --trace " << trace_path;
        std::cerr << "\n";
        trace.close();
        return 1;
    }

    if (!quiet) {
        std::cout << "[seed " << hex_seed(seed) << "] OK: " << sc->name
                  << " — " << sim.props().count()
                  << " invariant(s) held over " << sim.state().step
                  << " steps\n";
    }
    trace.close();
    return 0;
}
