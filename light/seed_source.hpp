// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// S-110 — off-the-command-line secret-seed input for determ-light.
//
// PROBLEM. Every determ-light subcommand that takes a private seed took it as a
// command-line ARGUMENT (`--mldsa-seed <hex32>`, `--ed-seed <hex32>`,
// `--blind-seed <hex>`). On Linux the argument vector of a running process is
// world-readable at /proc/<pid>/cmdline, `ps` prints it to every user on the
// host, and the operator's interactive shell writes it verbatim into the
// history file. For the ML-DSA / Ed25519 seeds that IS the private key: whoever
// reads it signs as that identity.
//
// THE CONVENTION. This mirrors `determ-wallet keyfile-create --passphrase-from
// <file:path|env:NAME|prompt>` (wallet/main.cpp::passphrase_from_source) rather
// than inventing a second one: same three source forms, same diagnostic shape,
// same exit code (1) on a bad source. That helper lives in the wallet binary's
// own translation unit and is NOT reachable from determ-light (separate CMake
// targets, no shared library between them), so the parsing is re-implemented
// here instead of dragging wallet/main.cpp across the binary boundary.
//
// ONE DELIBERATE DIVERGENCE from the wallet helper: a passphrase may legitimately
// contain leading/trailing spaces, so the wallet strips only CR/LF; a hex seed
// never can, so seed_hex_from_source() trims ASCII whitespace at both ends. Every
// other rejection (empty spec, empty path, unopenable file, empty file, empty
// first line, empty/unset variable, empty prompt, unknown scheme) mirrors the
// wallet's wording and returns the same way.
//
// WHAT THIS DOES NOT CLOSE. The raw `--mldsa-seed` / `--ed-seed` / `--blind-seed`
// flags still exist and still behave exactly as before (three shipped test
// scripts use them; removing them is an owner decision). A caller that keeps
// using the raw form keeps the exposure — it only gains a named stderr warning.

#ifndef DETERM_LIGHT_SEED_SOURCE_HPP
#define DETERM_LIGHT_SEED_SOURCE_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace determ::light {

// Resolve a `--<flag>-from <source>` specifier to the hex seed text it names:
//
//   "file:<path>"  — first line of the file (whitespace-trimmed). A file that
//                    cannot be opened, is empty, or whose first line is blank
//                    after trimming is REFUSED.
//   "env:<NAME>"   — value of environment variable NAME. Unset or empty is
//                    REFUSED. (The value is still visible in /proc/<pid>/environ
//                    to the same UID — `file:` with 0600 perms is stronger — but
//                    it is out of the process table and out of shell history.)
//   "prompt"       — one line read from stdin with terminal echo disabled
//                    (best-effort: POSIX termios / Windows console). Falls back
//                    to a plain getline where echo cannot be disabled.
//
// Returns the hex text on success. On failure returns "" and sets `err` to a
// single-line diagnostic the caller prints as "<subcommand>: <err>" before
// exiting 1 — the same shape determ-wallet's keyfile-create uses.
//
// The returned string holds SECRET material: the caller converts it to bytes and
// then zeroes it (see zero_secret_string).
std::string seed_hex_from_source(const std::string& spec, std::string& err);

// Best-effort scrub of a heap buffer holding secret material. Wraps
// determ_secure_zero (include/determ/crypto/secure_zero.h) — the same primitive
// light/keyfile.cpp uses on a decrypted private seed.
void zero_secret_bytes(void* p, std::size_t n);

// zero_secret_bytes over a std::string's buffer, then clear() it.
void zero_secret_string(std::string& s);

// The named stderr warning emitted when a seed arrives as a raw command-line
// argument. Stable marker `WARNING[seed-on-command-line]` so operators (and the
// gate) can match it; `cmd` is the subcommand, `raw_flag` the flag that was used
// and `from_flag` the off-the-command-line alternative to name. Warning ONLY —
// the command proceeds and its exit code is unchanged.
void warn_seed_on_command_line(const char* cmd, const char* raw_flag,
                               const char* from_flag);

// Resolve ONE seed flag pair — the raw `--<name>` and the off-the-command-line
// `--<name>-from <file:path|env:NAME|prompt>` — into hex text:
//
//   both given   -> REFUSED (caller exits 1): silently preferring one would hide
//                   which key actually signed.
//   raw given    -> warn_seed_on_command_line(), then the value UNCHANGED. The
//                   raw flag keeps working exactly as it did.
//   -from given  -> seed_hex_from_source(); a bad source is refused with the
//                   wallet's diagnostic shape and the caller's exit code 1.
//   neither      -> out_hex is cleared; the caller's required-argument check fires.
//
// Returns false when the caller must exit 1 — the diagnostic is already printed
// to stderr as "<cmd>: …".
bool resolve_seed_hex(const char* cmd, const char* raw_flag, const char* from_flag,
                      const std::string& raw_hex, const std::string& from_spec,
                      std::string& out_hex);

// Scope guard: scrub a secret buffer on EVERY exit from the enclosing scope,
// including the throwing ones. Matches light/keyfile.cpp's determ_secure_zero
// discipline on a decrypted private seed.
//
// A guard aimed at a std::string / std::vector holds the CONTAINER, not a
// pointer into it, so a later reallocation cannot leave it scrubbing freed
// memory. Declare the guard AFTER the container it protects, so the guard is
// destroyed first.
struct SeedScrub {
    void*                 p   = nullptr;   // fixed-extent buffer (e.g. std::array)
    std::size_t           n   = 0;
    std::string*          str = nullptr;   // or a string, scrubbed at its current buffer
    std::vector<uint8_t>* vec = nullptr;   // or a byte vector
    SeedScrub() = default;
    SeedScrub(void* pp, std::size_t nn) : p(pp), n(nn) {}
    SeedScrub(const SeedScrub&) = delete;
    SeedScrub& operator=(const SeedScrub&) = delete;
    ~SeedScrub() {
        zero_secret_bytes(p, n);
        if (str) zero_secret_string(*str);
        if (vec && !vec->empty()) { zero_secret_bytes(vec->data(), vec->size()); vec->clear(); }
    }
};

// Aim a SeedScrub at a container holding secret bytes.
inline void scrub_on_scope_exit(SeedScrub& g, std::string& s)          { g.str = &s; }
inline void scrub_on_scope_exit(SeedScrub& g, std::vector<uint8_t>& v) { g.vec = &v; }

} // namespace determ::light

#endif // DETERM_LIGHT_SEED_SOURCE_HPP
