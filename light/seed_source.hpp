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
// THE CONVENTION, AND WHERE IT NOW LIVES. `--<flag>-from
// <file:path|env:NAME|prompt>`, the raw flag kept working but printing
// `WARNING[seed-on-command-line]`. Written here on 2026-09-17 as a second copy
// of `determ-wallet keyfile-create --passphrase-from`, because that helper lives
// in the wallet binary's own translation unit and the two are separate CMake
// targets with no shared library between them.
//
// On 2026-09-18 the mechanism moved, VERBATIM, into
// include/determ/util/secret_source.hpp — a header-only primitive all three
// binaries can include — because S-114 / S-115 needed it in the OTHER two, and
// a third hand-rolled copy of a primitive that had already been written twice
// is how this repo's restricted-write loops drifted twice in two days. This
// file is what remains: the light-client-facing NAMES and the SEED policy
// (noun "seed", prompt label "Seed (hex): ", whitespace-trimmed values), so no
// determ-light behaviour, diagnostic string or exit code changes and
// tools/test_light_seed_source.sh stays green UNCHANGED.
//
// ONE DELIBERATE DIVERGENCE from the wallet's passphrase reader, preserved by
// that policy: a passphrase may legitimately contain leading/trailing spaces,
// so the wallet strips only CR/LF; a hex seed never can, so the seed sources
// trim ASCII whitespace at both ends.
//
// WHAT THIS DOES NOT CLOSE. The raw `--mldsa-seed` / `--ed-seed` / `--blind-seed`
// flags still exist and still behave exactly as before (three shipped test
// scripts use them; removing them is an owner decision). A caller that keeps
// using the raw form keeps the exposure — it only gains a named stderr warning.

#ifndef DETERM_LIGHT_SEED_SOURCE_HPP
#define DETERM_LIGHT_SEED_SOURCE_HPP

#include <determ/util/secret_source.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace determ::light {

// THREE OF THE FIVE FUNCTIONS BELOW ARE NO LONGER ON ANY CALL PATH INSIDE
// determ-light, and that is written down here rather than left to be discovered:
// light/main.cpp and light/pq_sign_tx.cpp reach resolve_seed_hex(),
// zero_secret_bytes(), SeedScrub and scrub_on_scope_exit(), while
// seed_hex_from_source(), zero_secret_string() and warn_seed_on_command_line()
// are now reached only THROUGH the shared primitive — so a change made inside one
// of those three bodies would be invisible to tools/test_light_seed_source.sh.
// Measured, not assumed: a mutant aimed at seed_hex_from_source() left that gate
// GREEN. They are kept because they are the documented S-110 names of these
// operations and deleting declarations is not part of a behaviour-preserving
// move, and each is one line that holds no logic of its own. The one place where
// determ-light's behaviour can still drift is SEED_POLICY, which BOTH live entry
// points share — the mutant that flips it turns that unchanged gate RED.

// The policy that reproduces every S-110 diagnostic byte-for-byte.
inline constexpr determ::util::SecretPolicy SEED_POLICY = determ::util::SEED;

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
// destroyed first. (The type and both aiming overloads are the shared
// primitive's, under the name light/ has always used for them.)
using SeedScrub = determ::util::SecretScrub;
using determ::util::scrub_on_scope_exit;

} // namespace determ::light

#endif // DETERM_LIGHT_SEED_SOURCE_HPP
