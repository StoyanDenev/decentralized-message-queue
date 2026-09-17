// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// S-110 — see seed_source.hpp for the problem statement and the convention this
// mirrors (determ-wallet's --passphrase-from).

#include "seed_source.hpp"

#include <determ/crypto/secure_zero.h>

#include <cstdlib>
#include <fstream>
#include <iostream>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <termios.h>
#  include <unistd.h>
#endif

namespace determ::light {
namespace {

bool is_ws(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

// Trim ASCII whitespace at both ends. The wallet's passphrase reader strips only
// CR/LF because a passphrase may contain spaces; a hex seed cannot, and a
// trailing space from an editor is the most common way a `file:` source fails.
std::string trim_ws(const std::string& s) {
    std::size_t b = 0, e = s.size();
    while (b < e && is_ws(s[b])) ++b;
    while (e > b && is_ws(s[e - 1])) --e;
    return s.substr(b, e - b);
}

} // namespace

void zero_secret_bytes(void* p, std::size_t n) {
    if (p && n) determ_secure_zero(p, n);
}

void zero_secret_string(std::string& s) {
    if (!s.empty()) determ_secure_zero(&s[0], s.size());
    s.clear();
}

std::string seed_hex_from_source(const std::string& spec, std::string& err) {
    err.clear();
    if (spec.empty()) {
        err = "seed source is empty";
        return "";
    }
    if (spec.rfind("file:", 0) == 0) {
        std::string path = spec.substr(5);
        if (path.empty()) { err = "file: source has empty path"; return ""; }
        std::ifstream f(path);
        if (!f) {
            err = "cannot open seed file: " + path;
            return "";
        }
        std::string line;
        if (!std::getline(f, line)) {
            err = "seed file is empty: " + path;
            return "";
        }
        std::string hex = trim_ws(line);
        zero_secret_string(line);            // the raw line held the seed too
        if (hex.empty()) {
            err = "seed file first line is empty: " + path;
            return "";
        }
        return hex;
    }
    if (spec.rfind("env:", 0) == 0) {
        std::string name = spec.substr(4);
        if (name.empty()) { err = "env: source has empty variable name"; return ""; }
        const char* v = std::getenv(name.c_str());
        if (!v || !*v) {
            err = "environment variable not set or empty: " + name;
            return "";
        }
        std::string hex = trim_ws(v);
        if (hex.empty()) {
            err = "environment variable not set or empty: " + name;
            return "";
        }
        return hex;
    }
    if (spec == "prompt") {
        // Interactive no-echo read. Best-effort across platforms; if echo cannot
        // be disabled we still read the line (the operator may be piping into a
        // non-tty, e.g. a test harness or an ops script).
        std::cerr << "Seed (hex): " << std::flush;
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
        std::string hex = trim_ws(line);
        zero_secret_string(line);
        if (hex.empty()) { err = "empty seed from prompt"; return ""; }
        return hex;
    }
    err = "unknown seed source '" + spec
        + "'; expected file:<path>, env:<NAME>, or prompt";
    return "";
}

bool resolve_seed_hex(const char* cmd, const char* raw_flag, const char* from_flag,
                      const std::string& raw_hex, const std::string& from_spec,
                      std::string& out_hex) {
    if (!raw_hex.empty() && !from_spec.empty()) {
        std::cerr << cmd << ": " << raw_flag << " and " << from_flag
                  << " are mutually exclusive; pass exactly one\n";
        return false;
    }
    if (!raw_hex.empty()) {
        warn_seed_on_command_line(cmd, raw_flag, from_flag);
        out_hex = raw_hex;
        return true;
    }
    if (!from_spec.empty()) {
        std::string err;
        out_hex = seed_hex_from_source(from_spec, err);
        if (out_hex.empty()) {
            std::cerr << cmd << ": " << from_flag << ": " << err << "\n";
            return false;
        }
        return true;
    }
    out_hex.clear();
    return true;
}

void warn_seed_on_command_line(const char* cmd, const char* raw_flag,
                               const char* from_flag) {
    std::cerr
        << "WARNING[seed-on-command-line]: " << cmd << ": " << raw_flag
        << " puts the raw secret seed in this process's command line.\n"
        << "  It is readable by any local process in /proc/<pid>/cmdline, is shown by `ps`\n"
        << "  to every user on this host, and your shell writes it verbatim into the shell\n"
        << "  history file. Use " << from_flag
        << " <file:path|env:NAME|prompt> instead.\n";
}

} // namespace determ::light
