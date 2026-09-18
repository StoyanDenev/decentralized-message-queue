// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// S-110 — see seed_source.hpp for the problem statement, the convention this
// mirrors (determ-wallet's --passphrase-from), and why the MECHANISM moved to
// include/determ/util/secret_source.hpp on 2026-09-18.
//
// What is left here is the light-client-facing naming layer: five one-line
// forwarders that bind determ-light's spellings to the shared primitive under
// the SEED policy. Every diagnostic string, the return convention and the exit
// codes are the ones tools/test_light_seed_source.sh has pinned since
// 2026-09-17; that gate is UNCHANGED by the move and is the proof of it.
//
// This translation unit is deliberately kept (rather than deleted and the
// header made inline): determ-light's CMake source list names it, light/ keeps
// its own TU boundary, and the forwarders stay externally linked exactly as the
// callers in light/main.cpp and light/pq_sign_tx.cpp saw them.

#include "seed_source.hpp"

namespace determ::light {

void zero_secret_bytes(void* p, std::size_t n) {
    determ::util::zero_secret_bytes(p, n);
}

void zero_secret_string(std::string& s) {
    determ::util::zero_secret_string(s);
}

std::string seed_hex_from_source(const std::string& spec, std::string& err) {
    return determ::util::secret_from_source(spec, SEED_POLICY, err);
}

void warn_seed_on_command_line(const char* cmd, const char* raw_flag,
                               const char* from_flag) {
    determ::util::warn_secret_on_command_line(cmd, raw_flag, from_flag, SEED_POLICY);
}

bool resolve_seed_hex(const char* cmd, const char* raw_flag, const char* from_flag,
                      const std::string& raw_hex, const std::string& from_spec,
                      std::string& out_hex) {
    return determ::util::resolve_secret(cmd, raw_flag, from_flag,
                                        raw_hex, from_spec, SEED_POLICY, out_hex);
}

} // namespace determ::light
