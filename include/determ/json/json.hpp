// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once

// determ::json — minix JSON phase 2, increment 1.
//
// A self-contained, dependency-free JSON value model with a strict parser
// and a CANONICAL compact serializer whose byte output is designed to match
// nlohmann::json's default `dump()` on the narrow subset the daemon puts on
// a consensus/HMAC path (see docs/proofs/MinixTacticalProfile.md §5):
//
//   * CONSENSUS DIGEST: hash_abort_event() SHA-256s `claims_json.dump()`
//     (src/node/producer.cpp, mirrored in light/verify.cpp) → abort view
//     root → the K-of-K-signed block digest. A one-byte writer divergence
//     forks abort-carrying chains across a mixed-implementation fleet.
//   * RPC HMAC over `method + "|" + params.dump()` (src/rpc/rpc.cpp),
//     computed independently by the server and by wallet/light clients.
//
// The load-bearing property is therefore byte-exact `dump()` parity with
// nlohmann on that subset: sorted-key objects, arrays, booleans, null,
// unsigned/signed 64-bit integers, and ASCII/UTF-8 strings. This module is
// ADDITIVE — increment 1 introduces it and proves the parity property under
// a dual-oracle gate (`determ test-determ-json`) against the vendored
// nlohmann; no production consumer is swapped onto it yet. Swapping the two
// byte-critical sites is the owner-gated serial follow-on increment.
//
// Canonical `dump()` form (matches nlohmann's default compact dump):
//   * objects  {"a":1,"b":2}  — keys in byte-lexicographic (std::map) order,
//     no spaces after ':' or ','.
//   * arrays   [1,2,3]        — no spaces.
//   * strings  escaped per RFC 8259: " \ \b \f \n \r \t are two-char
//     escapes; other control chars < 0x20 become \u00xx (lowercase hex);
//     every other byte (including multi-byte UTF-8) is emitted literally
//     (nlohmann's default `ensure_ascii=false`). Forward slash is NOT
//     escaped. Invalid UTF-8 THROWS on dump (nlohmann's strict handler),
//     which is what makes the abort-path binary leaf keys fail closed.
//   * integers plain decimal; unsigned and signed dump identically.
//
// SCOPE / non-parity (documented, not silently dropped): doubles are stored
// and dumped best-effort but are NOT YET byte-identical to nlohmann's
// shortest-round-trip dtoa (dump_double uses %.17g, e.g. 0.1 -> "0.10000...1"
// vs nlohmann's "0.1"). Double dump-parity is a SWAP-BLOCKER, NOT out of
// scope: a double IS adversarially reachable on the abort-event consensus
// digest — src/chain/block.cpp stores AbortEvent::claims_json VERBATIM from
// peer JSON (unknown members kept), the per-claim Ed25519 signature covers
// only typed scalars (not the JSON), and hash_abort_event() SHA-256s
// claims_json.dump() into the K-of-K block digest, so an attacker can inject
// `"z":0.1` into a valid claim and it rides the digest. The consumer swap
// (owner-gated) must therefore either (a) give dump_double a shortest-round-
// trip serializer matching nlohmann byte for byte, or (b) re-canonicalize
// claims_json from typed AbortClaimMsg fields before hashing (stripping
// unknown members). test-determ-json WITNESSES the current double gap so it
// cannot be forgotten. The parser also enforces a nesting DEPTH CAP
// (peer-facing hardening) that nlohmann does not; inputs deeper than the cap
// are rejected by intent (the consensus subset never nests that deep). A
// leading UTF-8 BOM is skipped (matching nlohmann, RFC 8259 §8.1).

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// The C++ namespace is `determ::djson` (not `determ::json`): the codebase has
// a pervasive file-level `using json = nlohmann::json;` alias plus many
// `using namespace determ;` blocks, so a `determ::json` namespace would make
// the bare name `json` ambiguous everywhere. `djson` sidesteps that while the
// module keeps its descriptive name "the in-tree determ JSON module".
namespace determ::djson {

// Thrown on any malformed-input parse failure. A peer-supplied byte stream
// that does not conform to strict RFC 8259 (plus the depth cap) lands here.
struct parse_error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Thrown when serializing a string that is not valid UTF-8 — the fail-closed
// behavior nlohmann's strict error handler gives, load-bearing for the
// abort-path binary leaf keys.
struct dump_error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Default nesting depth cap for parse(). The consensus subset (abort claims
// arrays, RPC params, HELLO, snapshots) nests only a handful deep; 64 is a
// generous ceiling that still bounds adversarial peer input.
inline constexpr size_t kDefaultMaxDepth = 64;

class Value {
public:
    enum class Type { Null, Boolean, Integer, Unsigned, Double, String, Array, Object };

    // ── constructors / factories ──────────────────────────────────────────
    Value() : type_(Type::Null) {}

    static Value null() { return Value(); }
    static Value boolean(bool b) { Value v; v.type_ = Type::Boolean; v.bool_ = b; return v; }
    static Value integer(int64_t i) { Value v; v.type_ = Type::Integer; v.int_ = i; return v; }
    static Value uint(uint64_t u) { Value v; v.type_ = Type::Unsigned; v.uint_ = u; return v; }
    static Value real(double d) { Value v; v.type_ = Type::Double; v.dbl_ = d; return v; }
    static Value str(std::string s) { Value v; v.type_ = Type::String; v.str_ = std::move(s); return v; }
    static Value array() { Value v; v.type_ = Type::Array; return v; }
    static Value object() { Value v; v.type_ = Type::Object; return v; }

    // ── builders ─────────────────────────────────────────────────────────
    void push_back(Value v) { arr_.push_back(std::move(v)); }         // array
    void set(const std::string& key, Value v) { obj_[key] = std::move(v); } // object (sorted)

    // ── introspection ────────────────────────────────────────────────────
    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_bool() const { return type_ == Type::Boolean; }
    bool is_integer() const { return type_ == Type::Integer; }
    bool is_unsigned() const { return type_ == Type::Unsigned; }
    bool is_double() const { return type_ == Type::Double; }
    bool is_number() const { return type_ == Type::Integer || type_ == Type::Unsigned || type_ == Type::Double; }
    bool is_string() const { return type_ == Type::String; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_object() const { return type_ == Type::Object; }

    bool as_bool() const { return bool_; }
    int64_t as_int() const { return int_; }
    uint64_t as_uint() const { return uint_; }
    double as_double() const { return dbl_; }
    const std::string& as_string() const { return str_; }
    const std::vector<Value>& items() const { return arr_; }
    const std::map<std::string, Value>& members() const { return obj_; }
    size_t size() const { return type_ == Type::Array ? arr_.size() : (type_ == Type::Object ? obj_.size() : 0); }

    // ── serialize ────────────────────────────────────────────────────────
    // Canonical compact dump. Throws dump_error if a String node (or object
    // key) holds bytes that are not valid UTF-8.
    std::string dump() const {
        std::string out;
        dump_into(out);
        return out;
    }

    // ── parse ────────────────────────────────────────────────────────────
    // Strict RFC 8259 parse with a nesting depth cap. Throws parse_error on
    // any malformed input (trailing bytes, bare control chars in strings,
    // invalid escapes/UTF-8, leading zeros, '+' signs, lone surrogates,
    // over-deep nesting, ...).
    static Value parse(const std::string& text, size_t max_depth = kDefaultMaxDepth) {
        Parser p(text, max_depth);
        // Skip a single leading UTF-8 BOM (EF BB BF) if present, matching
        // nlohmann (RFC 8259 §8.1 permits ignoring it) so the two parsers
        // AGREE on this input rather than one accepting and one rejecting.
        if (text.size() >= 3 &&
            static_cast<unsigned char>(text[0]) == 0xEF &&
            static_cast<unsigned char>(text[1]) == 0xBB &&
            static_cast<unsigned char>(text[2]) == 0xBF) {
            p.pos = 3;
        }
        p.skip_ws();
        Value v = p.parse_value(0);
        p.skip_ws();
        if (!p.at_end())
            throw parse_error("trailing content after JSON value");
        return v;
    }

private:
    Type type_;
    bool bool_ = false;
    int64_t int_ = 0;
    uint64_t uint_ = 0;
    double dbl_ = 0.0;
    std::string str_;
    std::vector<Value> arr_;
    std::map<std::string, Value> obj_;

    // ── UTF-8 helpers ────────────────────────────────────────────────────
    // Decode one UTF-8 code point starting at s[i]; advance i past it.
    // Returns the code point. Throws on any invalid/overlong/surrogate/
    // out-of-range sequence. Shared by dump (validation) and the raw-byte
    // string scan in parse.
    static uint32_t utf8_decode(const std::string& s, size_t& i, const char* ctx) {
        const size_t n = s.size();
        auto fail = [&]() -> uint32_t { throw dump_error(std::string("invalid UTF-8 in ") + ctx); };
        unsigned char c0 = static_cast<unsigned char>(s[i]);
        if (c0 < 0x80) { i += 1; return c0; }
        int len;
        uint32_t cp;
        uint32_t lo;  // minimum legal code point for this length (overlong guard)
        if ((c0 & 0xE0) == 0xC0) { len = 2; cp = c0 & 0x1F; lo = 0x80; }
        else if ((c0 & 0xF0) == 0xE0) { len = 3; cp = c0 & 0x0F; lo = 0x800; }
        else if ((c0 & 0xF8) == 0xF0) { len = 4; cp = c0 & 0x07; lo = 0x10000; }
        else return fail();  // 0x80-0xBF stray continuation, or 0xF8-0xFF
        if (i + static_cast<size_t>(len) > n) return fail();
        for (int k = 1; k < len; ++k) {
            unsigned char ck = static_cast<unsigned char>(s[i + static_cast<size_t>(k)]);
            if ((ck & 0xC0) != 0x80) return fail();
            cp = (cp << 6) | (ck & 0x3F);
        }
        if (cp < lo) return fail();                       // overlong
        if (cp > 0x10FFFF) return fail();                 // out of range
        if (cp >= 0xD800 && cp <= 0xDFFF) return fail();  // UTF-16 surrogate
        i += static_cast<size_t>(len);
        return cp;
    }

    // Encode a code point as UTF-8 onto out. Used by the parser for \u
    // escapes. cp is already range/surrogate-checked by the caller.
    static void utf8_encode(uint32_t cp, std::string& out) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    // ── serialize impl ───────────────────────────────────────────────────
    void dump_into(std::string& out) const {
        switch (type_) {
            case Type::Null:    out += "null"; break;
            case Type::Boolean: out += (bool_ ? "true" : "false"); break;
            case Type::Integer: out += std::to_string(int_); break;
            case Type::Unsigned: out += std::to_string(uint_); break;
            case Type::Double:  dump_double(out); break;
            case Type::String:  dump_string(str_, out); break;
            case Type::Array: {
                out.push_back('[');
                bool first = true;
                for (const auto& e : arr_) {
                    if (!first) out.push_back(',');
                    first = false;
                    e.dump_into(out);
                }
                out.push_back(']');
                break;
            }
            case Type::Object: {
                out.push_back('{');
                bool first = true;
                for (const auto& kv : obj_) {   // std::map ⇒ sorted keys
                    if (!first) out.push_back(',');
                    first = false;
                    dump_string(kv.first, out);
                    out.push_back(':');
                    kv.second.dump_into(out);
                }
                out.push_back('}');
                break;
            }
        }
    }

    static void dump_hex4(uint32_t v, std::string& out) {
        static const char* h = "0123456789abcdef";  // nlohmann uses lowercase
        out += "\\u";
        out.push_back(h[(v >> 12) & 0xF]);
        out.push_back(h[(v >> 8) & 0xF]);
        out.push_back(h[(v >> 4) & 0xF]);
        out.push_back(h[v & 0xF]);
    }

    // Serialize a JSON string with nlohmann-default escaping. Validates UTF-8
    // for every multi-byte sequence (throws dump_error on invalid).
    static void dump_string(const std::string& s, std::string& out) {
        out.push_back('"');
        size_t i = 0;
        const size_t n = s.size();
        while (i < n) {
            unsigned char c = static_cast<unsigned char>(s[i]);
            if (c < 0x80) {
                switch (c) {
                    case '"':  out += "\\\""; break;
                    case '\\': out += "\\\\"; break;
                    case '\b': out += "\\b"; break;
                    case '\f': out += "\\f"; break;
                    case '\n': out += "\\n"; break;
                    case '\r': out += "\\r"; break;
                    case '\t': out += "\\t"; break;
                    default:
                        if (c < 0x20) dump_hex4(c, out);
                        else out.push_back(static_cast<char>(c));
                        break;
                }
                i += 1;
            } else {
                // Multi-byte: validate + emit the exact source bytes.
                size_t start = i;
                (void)utf8_decode(s, i, "string on dump");  // throws on invalid
                out.append(s, start, i - start);
            }
        }
        out.push_back('"');
    }

    // Best-effort double serialization. NOT claimed byte-identical to
    // nlohmann (shortest-round-trip dtoa) — doubles are off every consensus
    // path and excluded from the parity corpus.
    void dump_double(std::string& out) const {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%.17g", dbl_);
        out += buf;
    }

    // ── parser ───────────────────────────────────────────────────────────
    struct Parser {
        const std::string& s;
        size_t pos = 0;
        size_t max_depth;
        Parser(const std::string& text, size_t md) : s(text), max_depth(md) {}

        bool at_end() const { return pos >= s.size(); }
        char peek() const { return s[pos]; }

        void skip_ws() {
            while (pos < s.size()) {
                char c = s[pos];
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++pos;
                else break;
            }
        }

        [[noreturn]] void fail(const char* msg) const { throw parse_error(msg); }

        Value parse_value(size_t depth) {
            if (pos >= s.size()) fail("unexpected end of input");
            char c = s[pos];
            switch (c) {
                case '{': return parse_object(depth);
                case '[': return parse_array(depth);
                case '"': return Value::str(parse_string());
                case 't': return parse_lit("true", Value::boolean(true));
                case 'f': return parse_lit("false", Value::boolean(false));
                case 'n': return parse_lit("null", Value::null());
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) return parse_number();
                    fail("unexpected character");
            }
        }

        Value parse_lit(const char* lit, Value v) {
            size_t len = std::char_traits<char>::length(lit);
            if (pos + len > s.size() || s.compare(pos, len, lit) != 0)
                fail("invalid literal");
            pos += len;
            return v;
        }

        void check_depth(size_t depth) {
            if (depth >= max_depth) fail("maximum nesting depth exceeded");
        }

        Value parse_object(size_t depth) {
            check_depth(depth);
            ++pos;  // consume '{'
            Value obj = Value::object();
            skip_ws();
            if (pos < s.size() && s[pos] == '}') { ++pos; return obj; }
            for (;;) {
                skip_ws();
                if (pos >= s.size() || s[pos] != '"') fail("expected object key string");
                std::string key = parse_string();
                skip_ws();
                if (pos >= s.size() || s[pos] != ':') fail("expected ':' after object key");
                ++pos;
                skip_ws();
                obj.set(key, parse_value(depth + 1));
                skip_ws();
                if (pos >= s.size()) fail("unterminated object");
                if (s[pos] == ',') { ++pos; continue; }
                if (s[pos] == '}') { ++pos; break; }
                fail("expected ',' or '}' in object");
            }
            return obj;
        }

        Value parse_array(size_t depth) {
            check_depth(depth);
            ++pos;  // consume '['
            Value arr = Value::array();
            skip_ws();
            if (pos < s.size() && s[pos] == ']') { ++pos; return arr; }
            for (;;) {
                skip_ws();
                arr.push_back(parse_value(depth + 1));
                skip_ws();
                if (pos >= s.size()) fail("unterminated array");
                if (s[pos] == ',') { ++pos; continue; }
                if (s[pos] == ']') { ++pos; break; }
                fail("expected ',' or ']' in array");
            }
            return arr;
        }

        // Parse a JSON string token (leading '"' at pos). Returns the decoded
        // UTF-8 bytes. Strict: rejects bare control chars, bad escapes,
        // invalid \u surrogates, and invalid raw UTF-8.
        std::string parse_string() {
            ++pos;  // consume opening '"'
            std::string out;
            for (;;) {
                if (pos >= s.size()) fail("unterminated string");
                unsigned char c = static_cast<unsigned char>(s[pos]);
                if (c == '"') { ++pos; return out; }
                if (c == '\\') {
                    ++pos;
                    if (pos >= s.size()) fail("unterminated escape");
                    char e = s[pos];
                    switch (e) {
                        case '"':  out.push_back('"'); ++pos; break;
                        case '\\': out.push_back('\\'); ++pos; break;
                        case '/':  out.push_back('/'); ++pos; break;
                        case 'b':  out.push_back('\b'); ++pos; break;
                        case 'f':  out.push_back('\f'); ++pos; break;
                        case 'n':  out.push_back('\n'); ++pos; break;
                        case 'r':  out.push_back('\r'); ++pos; break;
                        case 't':  out.push_back('\t'); ++pos; break;
                        case 'u':  parse_unicode_escape(out); break;
                        default:   fail("invalid string escape");
                    }
                } else if (c < 0x20) {
                    fail("unescaped control character in string");
                } else if (c < 0x80) {
                    out.push_back(static_cast<char>(c));
                    ++pos;
                } else {
                    // Raw multi-byte UTF-8: validate + copy the exact bytes.
                    // utf8_decode throws dump_error on invalid; on the PARSE
                    // path that must surface as parse_error per parse()'s
                    // documented contract (a malformed peer byte is a parse
                    // failure, not a serialize failure).
                    size_t start = pos;
                    try {
                        (void)Value::utf8_decode(s, pos, "string");
                    } catch (const dump_error& e) {
                        throw parse_error(e.what());
                    }
                    out.append(s, start, pos - start);
                }
            }
        }

        // At '\uXXXX' with pos on the 'u'. Handles surrogate pairs.
        void parse_unicode_escape(std::string& out) {
            uint32_t hi = read_hex4();
            if (hi >= 0xD800 && hi <= 0xDBFF) {
                // high surrogate — must be followed by \u low surrogate
                if (pos + 1 >= s.size() || s[pos] != '\\' || s[pos + 1] != 'u')
                    fail("unpaired high surrogate");
                ++pos;  // consume '\'; leave pos on 'u' for read_hex4 to consume
                uint32_t lo = read_hex4();
                if (lo < 0xDC00 || lo > 0xDFFF) fail("invalid low surrogate");
                uint32_t cp = 0x10000 + (((hi - 0xD800) << 10) | (lo - 0xDC00));
                Value::utf8_encode(cp, out);
            } else if (hi >= 0xDC00 && hi <= 0xDFFF) {
                fail("unexpected low surrogate");
            } else {
                Value::utf8_encode(hi, out);
            }
        }

        // At 'u' (or the second 'u' of a pair); reads exactly 4 hex digits.
        uint32_t read_hex4() {
            ++pos;  // consume 'u'
            if (pos + 4 > s.size()) fail("truncated \\u escape");
            uint32_t v = 0;
            for (int k = 0; k < 4; ++k) {
                char h = s[pos + static_cast<size_t>(k)];
                v <<= 4;
                if (h >= '0' && h <= '9') v |= static_cast<uint32_t>(h - '0');
                else if (h >= 'a' && h <= 'f') v |= static_cast<uint32_t>(h - 'a' + 10);
                else if (h >= 'A' && h <= 'F') v |= static_cast<uint32_t>(h - 'A' + 10);
                else fail("invalid hex digit in \\u escape");
            }
            pos += 4;
            return v;
        }

        // Parse a JSON number. Classifies into Unsigned (non-negative int),
        // Integer (negative int), or Double (has '.'/'e'/'E' or overflows).
        Value parse_number() {
            size_t start = pos;
            bool neg = false;
            if (s[pos] == '-') { neg = true; ++pos; }
            if (pos >= s.size()) fail("bare '-' with no digits");
            // integer part
            if (s[pos] == '0') {
                ++pos;
                // leading zero must not be followed by another digit
                if (pos < s.size() && s[pos] >= '0' && s[pos] <= '9')
                    fail("leading zero in number");
            } else if (s[pos] >= '1' && s[pos] <= '9') {
                while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') ++pos;
            } else {
                fail("invalid number: expected digit");
            }
            bool is_double = false;
            // fraction
            if (pos < s.size() && s[pos] == '.') {
                is_double = true;
                ++pos;
                if (pos >= s.size() || s[pos] < '0' || s[pos] > '9')
                    fail("number: '.' not followed by digit");
                while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') ++pos;
            }
            // exponent
            if (pos < s.size() && (s[pos] == 'e' || s[pos] == 'E')) {
                is_double = true;
                ++pos;
                if (pos < s.size() && (s[pos] == '+' || s[pos] == '-')) ++pos;
                if (pos >= s.size() || s[pos] < '0' || s[pos] > '9')
                    fail("number: exponent not followed by digit");
                while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') ++pos;
            }
            std::string tok = s.substr(start, pos - start);
            if (is_double) {
                return Value::real(std::strtod(tok.c_str(), nullptr));
            }
            // Integer token. Parse magnitude (digits after optional '-').
            const char* dp = tok.c_str() + (neg ? 1 : 0);
            uint64_t mag = 0;
            bool overflow = false;
            for (const char* q = dp; *q; ++q) {
                unsigned d = static_cast<unsigned>(*q - '0');
                if (mag > (UINT64_MAX - d) / 10ULL) { overflow = true; break; }
                mag = mag * 10ULL + d;
            }
            if (neg) {
                // magnitude must fit in [0, 2^63] (2^63 == -INT64_MIN)
                const uint64_t kMaxNegMag = 9223372036854775808ULL;  // 2^63
                if (overflow || mag > kMaxNegMag)
                    return Value::real(std::strtod(tok.c_str(), nullptr));
                if (mag == kMaxNegMag) return Value::integer(INT64_MIN);
                return Value::integer(-static_cast<int64_t>(mag));
            } else {
                if (overflow) return Value::real(std::strtod(tok.c_str(), nullptr));
                return Value::uint(mag);
            }
        }
    };
};

}  // namespace determ::djson
