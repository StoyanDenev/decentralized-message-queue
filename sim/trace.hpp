// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// DSF (Deterministic-Simulation Framework) INCREMENT 1 — byte-stable trace
// writer. Per docs/proofs/DSF-SPEC.md §Q6 replay tooling and §4.6.
//
// Every simulation event is appended as ONE canonical line:
//
//     <seq> <vtime> <node> <kind> <detail>
//
// - seq    : zero-padded 8-digit event ordinal (monotonic; the replay key).
// - vtime  : zero-padded 20-digit virtual timestamp in ns (fixed width so the
//            trace is column-stable and diff-friendly regardless of magnitude).
// - node   : node id string ("-" if not node-scoped).
// - kind   : short event kind token (e.g. SEND, RECV, DROP, TICK, STATE).
// - detail : free-form single-line detail (newlines/tabs are escaped).
//
// Fields are single-space separated; the format is ASCII-only and contains no
// wall-clock, no host paths, no pointer values — so two runs of the same seed
// produce a BYTE-IDENTICAL trace that `diff` reports as clean. That is the
// replay contract (DSF-SPEC §3): same seed in => same trace out.
#pragma once
#include <cstdint>
#include <fstream>
#include <ostream>
#include <sstream>
#include <string>
#include "virtual_clock.hpp"

namespace determ::sim {

// Escape a detail/field string to keep each trace line single-line and
// column-stable: TAB and newline become \t / \n literals, backslash doubles.
// Pure function of input — deterministic.
inline std::string trace_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:   out += c;      break;
        }
    }
    return out;
}

// Zero-pad an unsigned value to a fixed width (decimal). Deterministic and
// locale-independent (no std::setw/locale surprises).
inline std::string zpad(uint64_t v, int width) {
    std::string s = std::to_string(v);
    if (static_cast<int>(s.size()) < width)
        s.insert(s.begin(), width - s.size(), '0');
    return s;
}

// Byte-stable trace writer. Writes to an owned ofstream (a file) and/or an
// optional mirror ostream (e.g. std::cout for --trace -). The line format is
// fixed; see file header.
class TraceWriter {
public:
    TraceWriter() = default;

    // Open a trace file at `path`. Truncates any existing file. Returns
    // false if the file could not be opened.
    bool open(const std::string& path) {
        // std::ios::binary so no CRLF translation on Windows — keeps the
        // trace byte-identical across platforms.
        file_.open(path, std::ios::out | std::ios::binary | std::ios::trunc);
        return file_.is_open();
    }

    // Mirror every line to an additional stream (not owned). Pass nullptr to
    // disable. Used for --trace - (stdout) and for tests.
    void set_mirror(std::ostream* os) { mirror_ = os; }

    bool is_open() const { return file_.is_open(); }

    // Emit one canonical trace line. `node` "-" means not node-scoped.
    // Returns the line's seq (== the count before increment).
    uint64_t emit(VTime vtime,
                  const std::string& node,
                  const std::string& kind,
                  const std::string& detail) {
        uint64_t seq = seq_++;
        std::ostringstream ln;
        ln << zpad(seq, 8) << ' '
           << zpad(vtime, 20) << ' '
           << (node.empty() ? "-" : trace_escape(node)) << ' '
           << (kind.empty() ? "-" : trace_escape(kind)) << ' '
           << (detail.empty() ? "-" : trace_escape(detail)) << '\n';
        const std::string s = ln.str();
        if (file_.is_open()) file_ << s;
        if (mirror_)         (*mirror_) << s;
        return seq;
    }

    // Number of lines emitted so far.
    uint64_t count() const { return seq_; }

    void flush() {
        if (file_.is_open()) file_.flush();
        if (mirror_)         mirror_->flush();
    }

    void close() {
        if (file_.is_open()) file_.close();
    }

private:
    std::ofstream file_;
    std::ostream* mirror_ = nullptr;
    uint64_t      seq_    = 0;
};

} // namespace determ::sim
