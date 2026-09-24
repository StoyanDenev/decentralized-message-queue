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
        "  determ-dsf --generate N [--seed <hex|dec>] [--gen-seed <hex|dec>] [--template broadcast|agree|ratchet|quorum|conserve|recon|crashrec|partition|rotation] --list\n"
        "                                 (register + list/run N seed-driven variants;\n"
        "                                  --gen-seed pins the drawn fault PROFILES so\n"
        "                                  --seed can vary the fault REALIZATION alone —\n"
        "                                  omitted, both collapse to --seed as before)\n"
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
    register_generated_scenarios(scenarios, 0x4A17E5ull, 6,   // increment-6 §Q5 2nd template (agreement)
                                 "gen_agree", true,
                                 determ::sim::GenTemplate::Agreement);
    register_generated_scenarios(scenarios, 0x7B3D91ull, 6,   // increment-7 §Q5 3rd template (ratchet)
                                 "gen_ratchet", true,
                                 determ::sim::GenTemplate::Ratchet);
    register_generated_scenarios(scenarios, 0x2C9F44ull, 6,   // increment-8 §Q5 4th template (quorum/threshold)
                                 "gen_quorum", true,
                                 determ::sim::GenTemplate::Quorum);
    register_generated_scenarios(scenarios, 0x5D21A7ull, 6,   // increment-9 §Q5 5th template (receipt conservation)
                                 "gen_conserve", true,
                                 determ::sim::GenTemplate::Conservation);
    register_generated_scenarios(scenarios, 0x6E8B29ull, 6,   // increment-10 §Q5 6th template (F2 view reconciliation)
                                 "gen_recon", true,
                                 determ::sim::GenTemplate::Reconcile);
    register_generated_scenarios(scenarios, 0x7F44D3ull, 6,   // increment-11 §Q5 7th template (crash/recover replay)
                                 "gen_crashrec", true,
                                 determ::sim::GenTemplate::CrashRecover);
    register_generated_scenarios(scenarios, 0x8A15C6ull, 6,   // increment-12 §Q5 8th template (partition/heal split-brain)
                                 "gen_partition", true,
                                 determ::sim::GenTemplate::PartitionHeal);
    register_generated_scenarios(scenarios, 0x9B27E1ull, 6,   // increment-14 §Q5 9th template (rotation fairness)
                                 "gen_rotation", true,
                                 determ::sim::GenTemplate::Rotation);

    std::string scenario_name;
    std::string trace_path = "off";     // default: no trace file
    std::string seed_str    = "0x1";    // default deterministic seed
    std::string gen_seed_str;            // --gen-seed: pin the profile draw
    bool        gen_seed_given = false;  // set in the parse loop (an empty
                                         // value must error, not silently
                                         // collapse to --seed)
    uint64_t    max_events  = 0;         // 0 => framework default cap
    bool        quiet       = false;
    bool        want_list   = false;
    uint64_t    generate_count = 0;      // --generate N: N seed-driven variants
    std::string template_name = "broadcast";  // --template (see print_usage for the alias list)

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
        else if (a == "--generate") {
            const std::string v = need("--generate");
            if (!parse_seed(v, generate_count)) {
                std::cerr << "error: bad --generate '" << v
                          << "' (want a count)\n";
                return 2;
            }
        }
        else if (a == "--template") { template_name = need("--template"); }
        else if (a == "--help" || a == "-h") { print_usage(); return 0; }
        else if (a == "--scenario") { scenario_name = need("--scenario"); }
        else if (a == "--seed")     { seed_str      = need("--seed"); }
        else if (a == "--gen-seed") { gen_seed_str  = need("--gen-seed");
                                      gen_seed_given = true; }
        else if (a == "--trace")    { trace_path    = need("--trace"); }
        else if (a == "--max-events") {
            const std::string v = need("--max-events");
            if (!parse_seed(v, max_events)) {
                std::cerr << "error: bad --max-events '" << v
                          << "' (want a count)\n";
                return 2;
            }
        }
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

    // --gen-seed is validated UNCONDITIONALLY (symmetric with --seed: garbage
    // — including an explicitly empty value — always exits 2, even when the
    // flag is inert because --generate is absent). It defaults to the run
    // seed: the classic collapsed single-seed form.
    uint64_t gen_seed = seed;
    if (gen_seed_given && !parse_seed(gen_seed_str, gen_seed)) {
        std::cerr << "error: bad --gen-seed '" << gen_seed_str
                  << "' (want 0xHEX or decimal)\n";
        return 2;
    }

    // §Q5/§Q6: --generate N registers N variants named gen_run_00..0(N-1).
    // --template picks the generator template (the alias chain below is the
    // authoritative map; print_usage lists the names). The PROFILE draw is
    // seeded by --gen-seed when given, else by the run --seed (the classic
    // collapsed single-seed form) — so `--gen-seed G --seed S` pins one drawn
    // profile set G while varying the fault REALIZATION S independently:
    // same (--generate N, --gen-seed G, --template T) => the same variant set
    // on any host, runnable under any number of run seeds. An unknown
    // template name falls back to Broadcast — operator tooling validates
    // names locally (operator_dsf_sweep).
    if (generate_count > 0) {
        const determ::sim::GenTemplate tmpl =
            (template_name == "agree" || template_name == "agreement")
                ? determ::sim::GenTemplate::Agreement
          : (template_name == "ratchet")
                ? determ::sim::GenTemplate::Ratchet
          : (template_name == "quorum")
                ? determ::sim::GenTemplate::Quorum
          : (template_name == "conserve" || template_name == "conservation")
                ? determ::sim::GenTemplate::Conservation
          : (template_name == "recon" || template_name == "reconcile"
             || template_name == "reconciliation")
                ? determ::sim::GenTemplate::Reconcile
          : (template_name == "crashrec" || template_name == "crashrecover")
                ? determ::sim::GenTemplate::CrashRecover
          : (template_name == "partition" || template_name == "partheal")
                ? determ::sim::GenTemplate::PartitionHeal
          : (template_name == "rotation" || template_name == "rotate")
                ? determ::sim::GenTemplate::Rotation
                : determ::sim::GenTemplate::Broadcast;
        register_generated_scenarios(scenarios, gen_seed,
                                     static_cast<int>(generate_count),
                                     "gen_run", /*with_selftest=*/false, tmpl);
    }

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
    // Banner seed token: when a --gen-seed was EXPLICITLY given on a generate
    // run, surface it alongside the run seed so a failing generated variant's
    // output carries the full reproducing pair. The collapsed / baked paths
    // print exactly the classic single-seed token (byte-identical output).
    const std::string seed_banner =
        (gen_seed_given && generate_count > 0)
            ? hex_seed(seed) + " gen-seed " + hex_seed(gen_seed)
            : hex_seed(seed);

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
        std::cout << "[seed " << seed_banner << "] running "
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
                std::cout << "[seed " << seed_banner
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
        std::cerr << "[seed " << seed_banner
                  << "] FAIL: expected a violation but none fired "
                     "(checker did not catch the planted bug)\n";
        trace.close();
        return 1;
    }

    // Normal scenario: any violation is a failure.
    if (violated) {
        std::cerr << "[seed " << seed_banner << "] FAIL: "
                  << sim.props().violations().size()
                  << " invariant violation(s) in " << sc->name << "\n";
        for (const auto& v : sim.props().violations()) {
            std::cerr << "    [" << to_string(v.kind) << "] " << v.name
                      << " @vtime=" << v.vtime << " step=" << v.step
                      << " :: " << v.detail << "\n";
        }
        // The hint must be the FULL reproducing tuple: a generated variant
        // does not exist without its --generate/--gen-seed/--template args.
        std::cerr << "  reproduce with: determ-dsf ";
        if (generate_count > 0) {
            std::cerr << "--generate " << generate_count
                      << " --gen-seed " << hex_seed(gen_seed) << " ";
            if (template_name != "broadcast")
                std::cerr << "--template " << template_name << " ";
        }
        std::cerr << "--scenario " << sc->name
                  << " --seed " << hex_seed(seed);
        if (trace_path != "off" && trace_path != "-")
            std::cerr << " --trace " << trace_path;
        std::cerr << "\n";
        trace.close();
        return 1;
    }

    if (!quiet) {
        std::cout << "[seed " << seed_banner << "] OK: " << sc->name
                  << " — " << sim.props().count()
                  << " invariant(s) held over " << sim.state().step
                  << " steps\n";
    }
    trace.close();
    return 0;
}
