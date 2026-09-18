// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once

// The ONE off-the-command-line secret-input primitive: take a secret from
// `file:<path>` | `env:<NAME>` | `prompt` instead of from argv, keep the raw
// flag working, and say — once, in a named and greppable way — why the raw flag
// is the unsafe one.
//
// THE DEFECT IT EXISTS FOR (S-110 / S-114 / S-115, each REPRODUCED by execution
// before it was written down). A running process's argument vector is
// world-readable at /proc/<pid>/cmdline, `ps` prints it to every user on the
// host, and the operator's interactive shell writes it verbatim into the
// history file. For a private seed, a private key hex, an RPC HMAC secret or a
// keyfile passphrase that string IS the secret: whoever reads it signs as that
// identity, or opens that container.
//
// WHY IT LIVES HERE AND NOT IN light/. The convention was written twice before
// this header existed and the two copies were ALREADY diverging:
//   * `wallet/main.cpp::passphrase_from_source` (the original, for
//     `determ-wallet keyfile-create --passphrase-from`), and
//   * `light/seed_source.cpp` (S-110, 2026-09-17), which re-implemented it
//     because the wallet's copy lives in another binary's translation unit and
//     said so at the locus.
// They agreed on every diagnostic string, on the three source forms and on the
// exit code, and disagreed — deliberately, and documented — on exactly three
// things: the noun in the diagnostics, the prompt label, and whether the value
// is whitespace-trimmed. Those three are the PARAMETERS below; everything else
// is the mechanism and now exists once. The third and fourth consumers (the
// `determ-wallet` argument parsers, the `determ` daemon's) are what forced the
// extraction rather than a fifth copy.
//
// HEADER-ONLY, deliberately, and checked against CMakeLists.txt rather than
// assumed — the same reasoning include/determ/util/restricted_write.hpp records:
// `determ`, `determ-wallet` and `determ-light` are three separate
// add_executable targets, and the only library between them is
// `determ-crypto-c99`, whose source list is exclusively `.c` under the C99 /
// Minix-portable discipline (CRYPTO-C99-SPEC.md), so a C++ translation unit
// cannot be added there. Everything below is `inline`. The one non-inline
// symbol used is `determ_secure_zero` (include/determ/crypto/secure_zero.h),
// which lives in that C library and is already linked into all three.
//
// WHAT THIS PRIMITIVE OWNS:
//   * parsing the three source specifiers and every refusal, with a named
//     single-line diagnostic and NO fallback (an unreadable source is refused,
//     never silently replaced by a prompt or an empty secret);
//   * the no-echo prompt read, best-effort across POSIX termios and the Windows
//     console, falling back to a plain getline where echo cannot be disabled
//     (the operator may be piping in from an ops script);
//   * scrubbing the intermediate buffers it allocates, and the scope guard
//     callers use for theirs;
//   * the named `WARNING[seed-on-command-line]` marker and its text;
//   * the raw-flag / -from-flag mutual exclusion.
//
// WHAT IT DELIBERATELY DOES NOT OWN:
//   * the VALIDATION of the resolved text (hex length, charset, checksums).
//     That is the caller's, unchanged, and it must stay unchanged: the
//     equivalence property this primitive is gated on is that the raw form and
//     the `-from` form take the SAME path from that point on.
//   * the caller's exit code. Every function here reports; the caller returns 1.
//
// WHAT IT DOES NOT CLOSE, and the reason the ledger rows say "partially":
// the raw flags still exist and still work. A caller that keeps using them
// keeps the exposure; it only gains a named stderr warning. Removing them is an
// owner decision (shipped scripts and fixtures pass them).

#include <determ/crypto/secure_zero.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX   // keep windows.h's min/max macros away from std::min
#  endif
// BOTH defines are load-bearing and neither implies the other.
// WIN32_LEAN_AND_MEAN suppresses the <winsock.h> pull-in, which is the one the
// wallet's own include block reasons about. NOMINMAX suppresses the
// function-like `min(a,b)` / `max(a,b)` MACROS in <minwindef.h>, which is a
// different hazard entirely: they expand at any later `std::min(` in the
// including translation unit and the TU stops compiling. This header is
// included LAST in src/main.cpp, ahead of thirteen top-level std::min/std::max
// call sites (src/main.cpp:4121, :34637, :35019, :35033, :35636, :36104,
// :36458, :36569, :36590, :36616, :36910, :36997, :51176) — that TU saw no
// <windows.h> at all before this header existed, so the guard is this header's
// to carry. The repo already carries it at the two other places where
// windows.h meets std::min: src/net/iocp_detail.hpp:15-16 and
// src/net/sync_client.cpp:23-24, both with this same comment; light/main.cpp
// documents the hazard a third time. NOT EXECUTED on Windows — there is no
// MSVC/MinGW toolchain on the box this was written on; it is the guard the
// three existing sites prove is needed, applied to the fourth.
#  include <windows.h>
#else
#  include <termios.h>
#  include <unistd.h>
#endif

namespace determ::util {

// The three things the two pre-existing copies of this convention disagreed on,
// and nothing else. A policy is a compile-time constant per flag, not state.
struct SecretPolicy {
    // The noun in every source diagnostic: "cannot open <noun> file: …",
    // "<noun> file is empty: …", "unknown <noun> source '…'". It is what makes
    // `--priv-from` say "private key" where `--seed-from` says "seed", so an
    // operator with two flags on one command line can tell which one refused.
    const char* noun;
    // The noun in the raw-flag WARNING sentence, which reads differently: the
    // S-110 text is "puts the raw secret seed in this process's command line"
    // and is kept byte-identical here, so `warn_noun` is "secret seed" where
    // `noun` is "seed". Pinned by tools/test_light_seed_source.sh section C.
    const char* warn_noun;
    // The `prompt` label written to stderr before the no-echo read.
    const char* prompt_label;
    // TRIMMING, the one behavioural difference, and it is not cosmetic:
    //   true  — trim ASCII whitespace at BOTH ends of file, env and prompt
    //           values. Correct for hex material, which can never contain
    //           whitespace, and a trailing space left by an editor is the most
    //           common way a `file:` source fails.
    //   false — a passphrase MAY legitimately begin or end with a space, so
    //           trimming it would silently change the secret and produce a
    //           container nobody can open. Only the line terminator the file
    //           format itself adds is removed (trailing CR/LF, so a CRLF file
    //           written on Windows works), and `env:` / `prompt` values are
    //           taken verbatim. This is `wallet/main.cpp::passphrase_from_source`
    //           as it shipped, preserved exactly.
    bool trim_all_ws;
};

// The policies in use. Each names its material; the three fields are as above.
inline constexpr SecretPolicy SEED       {"seed",        "secret seed", "Seed (hex): ",        true};
inline constexpr SecretPolicy PRIVATE_KEY{"private key", "private key", "Private key (hex): ", true};
inline constexpr SecretPolicy SECRET     {"secret",      "secret",      "Secret (hex): ",      true};
inline constexpr SecretPolicy PASSPHRASE {"passphrase",  "passphrase",  "Passphrase: ",        false};
inline constexpr SecretPolicy PASSWORD   {"password",    "password",    "Password: ",          false};

// Best-effort scrub of a heap buffer holding secret material. Wraps
// determ_secure_zero, which writes through a volatile indirection so the stores
// are not dead-store-eliminated.
inline void zero_secret_bytes(void* p, std::size_t n) {
    if (p && n) determ_secure_zero(p, n);
}

// zero_secret_bytes over a std::string's buffer, then clear() it.
inline void zero_secret_string(std::string& s) {
    if (!s.empty()) determ_secure_zero(&s[0], s.size());
    s.clear();
}

namespace detail {

inline bool is_ws(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

inline std::string trim_ws(const std::string& s) {
    std::size_t b = 0, e = s.size();
    while (b < e && is_ws(s[b])) ++b;
    while (e > b && is_ws(s[e - 1])) --e;
    return s.substr(b, e - b);
}

// Strip the trailing line terminator a text file carries, and nothing else.
inline std::string strip_eol(const std::string& s) {
    std::string out = s;
    while (!out.empty() && (out.back() == '\r' || out.back() == '\n')) out.pop_back();
    return out;
}

// The file: form's normalization — trimmed or EOL-stripped per the policy.
inline std::string normalize_line(const std::string& s, const SecretPolicy& pol) {
    return pol.trim_all_ws ? trim_ws(s) : strip_eol(s);
}

// The env: / prompt forms' normalization — trimmed, or VERBATIM. A passphrase
// read from a variable or typed at a prompt is taken exactly as given.
inline std::string normalize_value(const std::string& s, const SecretPolicy& pol) {
    return pol.trim_all_ws ? trim_ws(s) : s;
}

// How much of an UNRECOGNISED source specifier may be echoed back in the
// refusal.
//
// The spec that reaches the refusal may BE the secret. The likeliest way to get
// there is `--priv-from <64-hex-key>` — one character away from `--priv <key>`,
// and the two flags now sit next to each other in every usage string. argv is a
// transient exposure: /proc/<pid>/cmdline dies with the process. stderr is a
// PERSISTENT one — CI logs, ticket attachments, terminal scrollback, `script`
// transcripts — so echoing the spec whole converts the leak this primitive
// exists to close into a stored one. That is a different and worse thing, even
// though the same invocation also put it on argv.
//
// The rule, chosen so no shipped diagnostic changes:
//   * 16 characters or fewer  -> VERBATIM. Every refusal any gate greps for is
//     inside this bound (tools/test_light_seed_source.sh B9 and
//     tools/test_secret_on_argv.sh B21/B24 grep `... source 'bogus:x'`, seven
//     characters), and a short typo is the case where seeing it helps.
//   * longer, with a ':' in the first 16 characters -> the scheme-looking
//     prefix up to and including the colon, then a count. That keeps the one
//     diagnostically useful case — a mistyped scheme, `fille:/etc/key` — while
//     dropping the rest.
//   * longer, with no colon -> NOTHING of it, just the length. A bare hex key,
//     a bare passphrase.
// Residual, stated rather than discovered later: a long value that happens to
// contain a colon in its first 16 characters still has that much echoed.
inline std::string elide_spec(const std::string& spec) {
    if (spec.size() <= 16) return spec;
    const std::size_t c = spec.find(':');
    if (c != std::string::npos && c < 16)
        return spec.substr(0, c + 1) + "<" + std::to_string(spec.size() - c - 1)
             + " chars elided>";
    return "<" + std::to_string(spec.size()) + " chars elided>";
}

} // namespace detail

// Resolve a `--<name>-from <source>` specifier to the secret text it names:
//
//   "file:<path>"  — first line of the file, normalized per the policy. A file
//                    that cannot be opened, is empty, or whose first line is
//                    empty after normalization is REFUSED.
//   "env:<NAME>"   — value of environment variable NAME. Unset or empty is
//                    REFUSED. (The value is still visible in /proc/<pid>/environ
//                    to the same UID — `file:` with 0600 perms is stronger — but
//                    it is out of the process table and out of shell history.)
//   "prompt"       — one line read from stdin with terminal echo disabled
//                    (best-effort). Falls back to a plain getline where echo
//                    cannot be disabled.
//
// Returns the secret text on success. On failure returns "" and sets `err` to a
// single-line diagnostic the caller prints as "<subcommand>: <err>" before
// exiting 1.
//
// The returned string holds SECRET material: the caller consumes it and then
// zeroes it (see SecretScrub / zero_secret_string).
inline std::string secret_from_source(const std::string& spec,
                                      const SecretPolicy& pol,
                                      std::string& err) {
    const std::string noun = pol.noun;
    err.clear();
    if (spec.empty()) {
        err = noun + " source is empty";
        return "";
    }
    if (spec.rfind("file:", 0) == 0) {
        std::string path = spec.substr(5);
        if (path.empty()) { err = "file: source has empty path"; return ""; }
        std::ifstream f(path);
        if (!f) {
            err = "cannot open " + noun + " file: " + path;
            return "";
        }
        std::string line;
        if (!std::getline(f, line)) {
            err = noun + " file is empty: " + path;
            return "";
        }
        std::string out = detail::normalize_line(line, pol);
        zero_secret_string(line);            // the raw line held the secret too
        if (out.empty()) {
            err = noun + " file first line is empty: " + path;
            return "";
        }
        return out;
    }
    if (spec.rfind("env:", 0) == 0) {
        std::string name = spec.substr(4);
        if (name.empty()) { err = "env: source has empty variable name"; return ""; }
        const char* v = std::getenv(name.c_str());
        if (!v || !*v) {
            err = "environment variable not set or empty: " + name;
            return "";
        }
        std::string out = detail::normalize_value(v, pol);
        if (out.empty()) {
            err = "environment variable not set or empty: " + name;
            return "";
        }
        return out;
    }
    if (spec == "prompt") {
        // Interactive no-echo read. Best-effort across platforms; if echo cannot
        // be disabled we still read the line (the operator may be piping into a
        // non-tty, e.g. a test harness or an ops script).
        std::cerr << pol.prompt_label << std::flush;
#ifdef _WIN32
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD orig = 0;
        bool echo_off = (hStdin != INVALID_HANDLE_VALUE
                         && GetConsoleMode(hStdin, &orig)
                         && SetConsoleMode(hStdin, orig & ~ENABLE_ECHO_INPUT));
        std::string line;
        std::getline(std::cin, line);
        if (echo_off) SetConsoleMode(hStdin, orig);
        std::cerr << "\n";
#else
        termios old_t{}, new_t{};
        bool echo_off = (tcgetattr(STDIN_FILENO, &old_t) == 0);
        if (echo_off) {
            new_t = old_t;
            new_t.c_lflag &= ~ECHO;
            if (tcsetattr(STDIN_FILENO, TCSANOW, &new_t) != 0) echo_off = false;
        }
        std::string line;
        std::getline(std::cin, line);
        if (echo_off) tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
        std::cerr << "\n";
#endif
        std::string out = detail::normalize_value(line, pol);
        zero_secret_string(line);
        if (out.empty()) { err = "empty " + noun + " from prompt"; return ""; }
        return out;
    }
    // The spec is ELIDED above 16 characters — it may be the secret itself.
    // See detail::elide_spec for the rule and why stderr is worse than argv.
    err = "unknown " + noun + " source '" + detail::elide_spec(spec)
        + "'; expected file:<path>, env:<NAME>, or prompt";
    return "";
}

// The named stderr warning emitted when a secret arrives as a raw command-line
// argument.
//
// ONE marker for the whole tree — `WARNING[seed-on-command-line]` — and it keeps
// the historical noun on purpose even where the material is a passphrase or an
// HMAC secret. It is the spelling S-110 shipped, the one docs/SECURITY.md
// documents and the one an operator greps their logs for; a second spelling
// would mean a grep for the documented marker silently misses two binaries. The
// SENTENCE names the actual material and the actual flags.
//
// Warning ONLY — the command proceeds and its exit code is unchanged.
inline void warn_secret_on_command_line(const char* cmd, const char* raw_flag,
                                        const char* from_flag,
                                        const SecretPolicy& pol) {
    std::cerr
        << "WARNING[seed-on-command-line]: " << cmd << ": " << raw_flag
        << " puts the raw " << pol.warn_noun << " in this process's command line.\n"
        << "  It is readable by any local process in /proc/<pid>/cmdline, is shown by `ps`\n"
        << "  to every user on this host, and your shell writes it verbatim into the shell\n"
        << "  history file. Use " << from_flag
        << " <file:path|env:NAME|prompt> instead.\n";
}

// Resolve ONE flag pair — the raw `--<name>` and the off-the-command-line
// `--<name>-from <file:path|env:NAME|prompt>` — into the secret text:
//
//   both given   -> REFUSED (caller exits 1): silently preferring one would hide
//                   which secret was actually used.
//   raw given    -> warn_secret_on_command_line(), then the value UNCHANGED. The
//                   raw flag keeps working exactly as it did.
//   -from given  -> secret_from_source(); a bad source is refused with a named
//                   diagnostic and the caller's exit code 1.
//   neither      -> out is cleared; the caller's required-argument check fires.
//
// Returns false when the caller must exit 1 — the diagnostic is already printed
// to stderr as "<cmd>: …".
inline bool resolve_secret(const char* cmd, const char* raw_flag, const char* from_flag,
                           const std::string& raw, const std::string& from_spec,
                           const SecretPolicy& pol, std::string& out) {
    if (!raw.empty() && !from_spec.empty()) {
        std::cerr << cmd << ": " << raw_flag << " and " << from_flag
                  << " are mutually exclusive; pass exactly one\n";
        return false;
    }
    if (!raw.empty()) {
        warn_secret_on_command_line(cmd, raw_flag, from_flag, pol);
        out = raw;
        return true;
    }
    if (!from_spec.empty()) {
        std::string err;
        out = secret_from_source(from_spec, pol, err);
        if (out.empty()) {
            std::cerr << cmd << ": " << from_flag << ": " << err << "\n";
            return false;
        }
        return true;
    }
    out.clear();
    return true;
}

// Scope guard: scrub a secret buffer on EVERY exit from the enclosing scope,
// including the throwing ones.
//
// A guard aimed at a std::string / std::vector holds the CONTAINER, not a
// pointer into it, so a later reallocation cannot leave it scrubbing freed
// memory. Declare the guard AFTER the container it protects, so the guard is
// destroyed first.
struct SecretScrub {
    void*                 p   = nullptr;   // fixed-extent buffer (e.g. std::array)
    std::size_t           n   = 0;
    std::string*          str = nullptr;   // or a string, scrubbed at its current buffer
    std::vector<uint8_t>* vec = nullptr;   // or a byte vector
    SecretScrub() = default;
    SecretScrub(void* pp, std::size_t nn) : p(pp), n(nn) {}
    SecretScrub(const SecretScrub&) = delete;
    SecretScrub& operator=(const SecretScrub&) = delete;
    ~SecretScrub() {
        zero_secret_bytes(p, n);
        if (str) zero_secret_string(*str);
        if (vec && !vec->empty()) { zero_secret_bytes(vec->data(), vec->size()); vec->clear(); }
    }
};

// Aim a SecretScrub at a container holding secret bytes.
inline void scrub_on_scope_exit(SecretScrub& g, std::string& s)          { g.str = &s; }
inline void scrub_on_scope_exit(SecretScrub& g, std::vector<uint8_t>& v) { g.vec = &v; }

} // namespace determ::util
