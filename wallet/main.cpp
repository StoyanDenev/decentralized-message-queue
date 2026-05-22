// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
// A2 — determ-wallet binary
//
// v1.x scope (Phase 1, this commit):
//   * shamir split <secret-hex> -t N -n M         → write N shares to stdout
//   * shamir combine <share> [<share> ...]        → recover the secret
//   * version                                     → print build banner
//
// v1.x scope (Phase 2, follow-on):
//   * envelope encrypt / decrypt (AEAD wrapping)
//   * OPAQUE registration + AKE (via libopaque)
//   * create-recovery / recover end-to-end flows
//
// Build target: determ-wallet (separate from `determ` daemon binary).
//
// Why a separate binary: the wallet handles secret material that should
// never share an address space with a networked daemon. The wallet must
// be auditable in isolation; coupling it to the chain binary's RPC and
// gossip surfaces would broaden the trusted compute base unnecessarily.

#include "shamir.hpp"
#include "envelope.hpp"
#include "recovery.hpp"
#include "opaque_primitives.hpp"
#include "opaque_adapter.hpp"
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sodium.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <ctime>
#ifdef _WIN32
// winsock2.h MUST be included before windows.h — otherwise windows.h
// drags in the older winsock.h via windef.h and you get redefinition
// errors. anon-batch-balance is the first wallet command that opens a
// raw TCP socket (others either don't need RPC or shell out for it);
// the winsock pull-in here is gated to _WIN32 only.
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
#else
#  include <unistd.h>
#  include <termios.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <errno.h>
#endif

using namespace determ::wallet;

namespace {

std::string to_hex(const std::vector<uint8_t>& v) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (auto b : v) o << std::setw(2) << static_cast<int>(b);
    return o.str();
}

// Fixed-size overload used by the Ed25519 keygen path (pubkey and
// priv-seed are both exactly 32 bytes). Returns 64 lowercase hex chars.
template <size_t N>
std::string to_hex(const std::array<uint8_t, N>& a) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (auto b : a) o << std::setw(2) << static_cast<int>(b);
    return o.str();
}

std::vector<uint8_t> from_hex(const std::string& s) {
    if (s.size() % 2 != 0)
        throw std::invalid_argument("from_hex: odd length");
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        unsigned int byte;
        std::istringstream ss(s.substr(i, 2));
        ss >> std::hex >> byte;
        if (ss.fail())
            throw std::invalid_argument("from_hex: non-hex char");
        out.push_back(static_cast<uint8_t>(byte));
    }
    return out;
}

// Share wire format: "<x_hex>:<y_hex>", e.g. "01:abcdef" for x=1.
// Compact and easy to copy/paste between guardians.
std::string serialize_share(const shamir::Share& s) {
    std::ostringstream o;
    o << std::hex << std::setfill('0') << std::setw(2)
      << static_cast<int>(s.x) << ":" << to_hex(s.y);
    return o.str();
}

shamir::Share parse_share(const std::string& blob) {
    auto colon = blob.find(':');
    if (colon == std::string::npos)
        throw std::invalid_argument("share missing ':' separator");
    shamir::Share s;
    auto x_bytes = from_hex(blob.substr(0, colon));
    if (x_bytes.size() != 1)
        throw std::invalid_argument("share x-coordinate must be 1 byte");
    s.x = x_bytes[0];
    s.y = from_hex(blob.substr(colon + 1));
    return s;
}

int cmd_shamir_split(int argc, char** argv) {
    std::string secret_hex;
    int threshold = 0, share_count = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "-t" && i + 1 < argc) threshold   = std::stoi(argv[++i]);
        else if (a == "-n" && i + 1 < argc) share_count = std::stoi(argv[++i]);
        else if (a.size() && a[0] != '-')   secret_hex  = a;
    }
    if (secret_hex.empty() || threshold <= 0 || share_count <= 0) {
        std::cerr << "Usage: determ-wallet shamir split <secret_hex> "
                     "-t <threshold> -n <share_count>\n";
        return 1;
    }
    if (threshold > 255 || share_count > 255) {
        std::cerr << "shamir split: t and n must each be <= 255\n";
        return 1;
    }
    std::vector<uint8_t> secret;
    try { secret = from_hex(secret_hex); }
    catch (std::exception& e) {
        std::cerr << "Invalid secret hex: " << e.what() << "\n"; return 1;
    }
    if (secret.empty()) {
        std::cerr << "Secret must be non-empty\n"; return 1;
    }
    std::vector<shamir::Share> shares;
    try {
        shares = shamir::split(secret,
                                  static_cast<uint8_t>(threshold),
                                  static_cast<uint8_t>(share_count));
    } catch (std::exception& e) {
        std::cerr << "shamir split error: " << e.what() << "\n"; return 1;
    }
    for (auto& s : shares) std::cout << serialize_share(s) << "\n";
    return 0;
}

int cmd_shamir_combine(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ-wallet shamir combine <share> "
                     "[<share> ...]\n";
        return 1;
    }
    std::vector<shamir::Share> shares;
    for (int i = 0; i < argc; ++i) {
        try { shares.push_back(parse_share(argv[i])); }
        catch (std::exception& e) {
            std::cerr << "Invalid share '" << argv[i] << "': "
                      << e.what() << "\n";
            return 1;
        }
    }
    auto secret = shamir::combine(shares);
    if (!secret) {
        std::cerr << "shamir combine: shares inconsistent "
                     "(duplicate x, mismatched lengths, or empty)\n";
        return 1;
    }
    std::cout << to_hex(*secret) << "\n";
    return 0;
}

int cmd_shamir(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ-wallet shamir {split|combine} ...\n";
        return 1;
    }
    std::string sub = argv[0];
    if (sub == "split")   return cmd_shamir_split  (argc - 1, argv + 1);
    if (sub == "combine") return cmd_shamir_combine(argc - 1, argv + 1);
    std::cerr << "Unknown shamir subcommand: " << sub << "\n";
    return 1;
}

// Raw-primitive CLIs: expose shamir::split / ::combine directly with
// JSON-first output, independent of the recovery envelope flow. Useful
// for operator workflows that need to print physical shares, split a
// non-wallet secret, or feed shares into a different transport. The
// legacy `shamir {split|combine}` subcommand group above stays for
// backward compatibility with existing test fixtures + the
// colon-separated wire format.
int cmd_shamir_split_raw(int argc, char** argv) {
    std::string secret_hex;
    int threshold = -1, shares = -1;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--secret"    && i + 1 < argc) secret_hex = argv[++i];
        else if (a == "--threshold" && i + 1 < argc) threshold  = std::stoi(argv[++i]);
        else if (a == "--shares"    && i + 1 < argc) shares     = std::stoi(argv[++i]);
        else if (a == "--json")                      json_out   = true;
    }
    if (secret_hex.empty() || threshold < 0 || shares < 0) {
        std::cerr << "Usage: determ-wallet shamir-split --secret <hex> "
                     "--threshold T --shares N [--json]\n";
        return 1;
    }
    if (threshold < 1) {
        std::cerr << "shamir-split: --threshold must be >= 1\n"; return 1;
    }
    if (shares < threshold) {
        std::cerr << "shamir-split: --shares (" << shares
                  << ") must be >= --threshold (" << threshold << ")\n";
        return 1;
    }
    if (shares > 255) {
        std::cerr << "shamir-split: --shares must be <= 255\n"; return 1;
    }
    if (secret_hex.size() % 2 != 0) {
        std::cerr << "shamir-split: --secret hex must have even length\n";
        return 1;
    }
    std::vector<uint8_t> secret;
    try { secret = from_hex(secret_hex); }
    catch (std::exception& e) {
        std::cerr << "shamir-split: invalid --secret hex: " << e.what() << "\n";
        return 1;
    }
    if (secret.empty()) {
        std::cerr << "shamir-split: --secret must be non-empty\n"; return 1;
    }
    std::vector<shamir::Share> out;
    try {
        out = shamir::split(secret,
                              static_cast<uint8_t>(threshold),
                              static_cast<uint8_t>(shares));
    } catch (std::exception& e) {
        std::cerr << "shamir-split: " << e.what() << "\n"; return 1;
    }
    if (json_out) {
        nlohmann::json j;
        j["shares"] = nlohmann::json::array();
        for (auto& s : out) {
            j["shares"].push_back({
                {"x",      static_cast<int>(s.x)},
                {"y_hex",  to_hex(s.y)},
            });
        }
        std::cout << j.dump() << "\n";
    } else {
        for (size_t i = 0; i < out.size(); ++i) {
            std::cout << "Share " << (i + 1) << ": x="
                      << static_cast<int>(out[i].x) << " y="
                      << to_hex(out[i].y) << "\n";
        }
    }
    return 0;
}

int cmd_shamir_combine_raw(int argc, char** argv) {
    std::string shares_path;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--shares" && i + 1 < argc) shares_path = argv[++i];
        else if (a == "--json")                   json_out    = true;
    }
    if (shares_path.empty()) {
        std::cerr << "Usage: determ-wallet shamir-combine --shares <file> "
                     "[--json]\n";
        return 1;
    }
    std::ifstream f(shares_path);
    if (!f) {
        std::cerr << "shamir-combine: cannot open --shares file: "
                  << shares_path << "\n";
        return 1;
    }
    std::string blob((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
    nlohmann::json j;
    try { j = nlohmann::json::parse(blob); }
    catch (std::exception& e) {
        std::cerr << "shamir-combine: JSON parse failed: " << e.what() << "\n";
        return 1;
    }
    if (!j.contains("shares") || !j["shares"].is_array()) {
        std::cerr << "shamir-combine: JSON missing 'shares' array\n";
        return 1;
    }
    std::vector<shamir::Share> in;
    std::set<int> seen_x;
    size_t y_len = 0;
    for (auto& el : j["shares"]) {
        if (!el.is_object()
            || !el.contains("x")     || !el["x"].is_number_integer()
            || !el.contains("y_hex") || !el["y_hex"].is_string()) {
            std::cerr << "shamir-combine: each share must have integer 'x' "
                         "and string 'y_hex'\n";
            return 1;
        }
        int x = el["x"].get<int>();
        if (x < 1 || x > 255) {
            std::cerr << "shamir-combine: x must be in [1,255], got "
                      << x << "\n";
            return 1;
        }
        if (!seen_x.insert(x).second) {
            std::cerr << "shamir-combine: duplicate x = " << x << "\n";
            return 1;
        }
        std::string y_hex = el["y_hex"].get<std::string>();
        if (y_hex.size() % 2 != 0) {
            std::cerr << "shamir-combine: y_hex must have even length "
                         "(x=" << x << ")\n";
            return 1;
        }
        shamir::Share s;
        s.x = static_cast<uint8_t>(x);
        try { s.y = from_hex(y_hex); }
        catch (std::exception& e) {
            std::cerr << "shamir-combine: y_hex parse failed (x=" << x
                      << "): " << e.what() << "\n";
            return 1;
        }
        if (s.y.empty()) {
            std::cerr << "shamir-combine: y_hex empty (x=" << x << ")\n";
            return 1;
        }
        if (y_len == 0) y_len = s.y.size();
        else if (s.y.size() != y_len) {
            std::cerr << "shamir-combine: share y lengths mismatch "
                         "(x=" << x << ": " << s.y.size()
                      << " vs first: " << y_len << ")\n";
            return 1;
        }
        in.push_back(std::move(s));
    }
    if (in.empty()) {
        std::cerr << "shamir-combine: 'shares' array is empty\n"; return 1;
    }
    auto out = shamir::combine(in);
    if (!out) {
        std::cerr << "shamir-combine: reconstruction failed (shares "
                     "inconsistent at the shamir layer)\n";
        return 1;
    }
    if (json_out) {
        nlohmann::json r;
        r["secret_hex"] = to_hex(*out);
        std::cout << r.dump() << "\n";
    } else {
        std::cout << to_hex(*out) << "\n";
    }
    return 0;
}

// Diagnostic CLI: structural verification of a Shamir share-set file
// WITHOUT reconstructing the secret.
//
// Use cases:
//   * Operators distributing physical shares — verify a share envelope
//     is well-formed before mailing it.
//   * Pre-reconstruction sanity check — before attempting a costly
//     T-of-N combine (which may need T-1 other shares hand-delivered),
//     verify that the shares already on hand are structurally consistent.
//   * Tooling (operator scripts, monitoring) that wants share-set
//     metadata in structured form (--json) without leaking the secret.
//
// Verification checks (all structural; no GF(2^8) reconstruction):
//   1. JSON parseable.
//   2. Top-level is object with "shares" array.
//   3. shares array non-empty.
//   4. Each share has integer x in [1, 255] and string y_hex with even length.
//   5. All x values DISTINCT (Shamir invariant — same x = same point on the
//      polynomial; reconstruction would fail at the Lagrange step).
//   6. All y_hex values share the SAME byte length (Shamir invariant —
//      every share is derived from a polynomial over the same secret-size
//      domain).
//   7. y_hex contains only hex characters [0-9a-fA-F].
//   8. If --threshold T is supplied, also report whether share count >= T
//      (informational; insufficient share count is NOT a structural error).
//
// Exit codes:
//   0  structurally valid (and threshold met if --threshold supplied)
//   1  bad args / missing file / JSON parse error
//   2  structurally invalid (operator alert gate — one of checks 2-7 failed)
//
// Insufficient-share-count when --threshold is supplied returns 0 with an
// [INFO] line (it's diagnostic, not a structural defect).
int cmd_shamir_verify(int argc, char** argv) {
    std::string shares_path;
    int threshold = -1;       // -1 sentinel = not supplied
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--shares"    && i + 1 < argc) shares_path = argv[++i];
        else if (a == "--threshold" && i + 1 < argc) threshold   = std::stoi(argv[++i]);
        else if (a == "--json")                       json_out    = true;
    }
    if (shares_path.empty()) {
        std::cerr << "Usage: determ-wallet shamir-verify --shares <file> "
                     "[--threshold T] [--json]\n";
        return 1;
    }
    std::ifstream f(shares_path);
    if (!f) {
        if (json_out) {
            std::cout << "{\"valid\":false,\"errors\":[\"cannot open file\"]}\n";
        } else {
            std::cerr << "shamir-verify: cannot open --shares file: "
                      << shares_path << "\n";
        }
        return 1;
    }
    std::string blob((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
    nlohmann::json j;
    try { j = nlohmann::json::parse(blob); }
    catch (std::exception& e) {
        if (json_out) {
            nlohmann::json r;
            r["valid"] = false;
            r["errors"] = nlohmann::json::array({std::string("JSON parse error: ") + e.what()});
            std::cout << r.dump() << "\n";
        } else {
            std::cerr << "shamir-verify: JSON parse failed: " << e.what() << "\n";
        }
        return 1;
    }

    auto report_fail = [&](const std::string& reason) {
        if (json_out) {
            nlohmann::json r;
            r["valid"] = false;
            r["errors"] = nlohmann::json::array({reason});
            std::cout << r.dump() << "\n";
        } else {
            std::cerr << "[FAIL] " << reason << "\n";
        }
    };

    if (!j.is_object() || !j.contains("shares") || !j["shares"].is_array()) {
        report_fail("top-level must be object with 'shares' array");
        return 2;
    }
    const auto& arr = j["shares"];
    if (arr.empty()) {
        report_fail("shares array is empty");
        return 2;
    }

    // Cheap hex-validity check (independent of from_hex which throws on
    // odd length; we want to distinguish bad-char from odd-length so the
    // operator gets a precise diagnostic).
    auto is_hex_char = [](char c) {
        return (c >= '0' && c <= '9')
            || (c >= 'a' && c <= 'f')
            || (c >= 'A' && c <= 'F');
    };

    std::set<int> seen_x;
    int x_min = 256, x_max = -1;
    size_t y_byte_len = 0;
    bool y_len_consistent = true;

    for (size_t i = 0; i < arr.size(); ++i) {
        const auto& el = arr[i];
        if (!el.is_object()
            || !el.contains("x")     || !el["x"].is_number_integer()
            || !el.contains("y_hex") || !el["y_hex"].is_string()) {
            report_fail("share #" + std::to_string(i)
                        + ": must have integer 'x' and string 'y_hex'");
            return 2;
        }
        int x = el["x"].get<int>();
        if (x < 1 || x > 255) {
            report_fail("share #" + std::to_string(i) + ": x = "
                        + std::to_string(x) + " out of range [1, 255]");
            return 2;
        }
        if (!seen_x.insert(x).second) {
            report_fail("duplicate x = " + std::to_string(x)
                        + " (Shamir invariant: all x must be distinct)");
            return 2;
        }
        if (x < x_min) x_min = x;
        if (x > x_max) x_max = x;

        std::string y_hex = el["y_hex"].get<std::string>();
        if (y_hex.size() % 2 != 0) {
            report_fail("share x=" + std::to_string(x)
                        + ": y_hex has odd length (" + std::to_string(y_hex.size()) + ")");
            return 2;
        }
        for (char c : y_hex) {
            if (!is_hex_char(c)) {
                report_fail("share x=" + std::to_string(x)
                            + ": y_hex contains non-hex character");
                return 2;
            }
        }
        size_t this_y_len = y_hex.size() / 2;
        if (this_y_len == 0) {
            report_fail("share x=" + std::to_string(x) + ": y_hex is empty");
            return 2;
        }
        if (y_byte_len == 0) {
            y_byte_len = this_y_len;
        } else if (this_y_len != y_byte_len) {
            // Flag the inconsistency precisely; reject (operator alert).
            report_fail("share x=" + std::to_string(x) + ": y_hex length "
                        + std::to_string(this_y_len)
                        + " bytes differs from first share's "
                        + std::to_string(y_byte_len)
                        + " bytes (Shamir invariant: all shares must share "
                        + "the same secret-size domain)");
            y_len_consistent = false;
            return 2;
        }
    }

    const int share_count    = static_cast<int>(arr.size());
    const int distinct_x_cnt = static_cast<int>(seen_x.size());
    // threshold_satisfied tri-state: nullopt = not supplied, true = met,
    // false = supplied but insufficient. The supplied-but-insufficient
    // case is INFORMATIONAL (exit 0) — see header doc for rationale.
    std::optional<bool> threshold_satisfied;
    if (threshold >= 0) threshold_satisfied = (share_count >= threshold);

    if (json_out) {
        nlohmann::json r;
        r["valid"]              = true;
        r["share_count"]        = share_count;
        r["distinct_x"]         = distinct_x_cnt;
        r["x_range"]            = nlohmann::json::array({x_min, x_max});
        r["y_byte_length"]      = y_byte_len;
        r["consistent_lengths"] = y_len_consistent;  // always true at this point
        if (threshold_satisfied.has_value()) {
            r["threshold_satisfied"] = *threshold_satisfied;
        } else {
            r["threshold_satisfied"] = nullptr;
        }
        r["errors"] = nlohmann::json::array();
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "=== shamir share-set verification ===\n";
        std::cout << "Shares present: "      << share_count << "\n";
        std::cout << "Distinct x values: "   << distinct_x_cnt
                  << " (range: " << x_min << ".." << x_max << ")\n";
        std::cout << "y_hex byte-length: "   << y_byte_len
                  << " bytes (consistent across all shares)\n";
        std::cout << "[OK] Structural verification passed\n";
        if (threshold_satisfied.has_value()) {
            if (*threshold_satisfied) {
                std::cout << "[OK] Share count (" << share_count
                          << ") >= threshold (" << threshold
                          << ") -- sufficient for reconstruction\n";
            } else {
                std::cout << "[INFO] Share count (" << share_count
                          << ") < threshold (" << threshold
                          << ") -- insufficient for reconstruction\n";
            }
        }
    }
    return 0;
}

// ── shamir-rotate — Proactive Secret Sharing (PSS) polynomial refresh ─────
//
// Refresh the Shamir polynomial WITHOUT changing the underlying secret.
// Defense against share leakage over time: a keyholder periodically
// rotates their physical share so accumulated compromise of any prior
// snapshot of < T shares conveys nothing about the current share set.
//
// Mechanism (Herzberg-style "share refresh"):
//   1. Read --shares file (same `{"shares":[{x, y_hex}, ...]}` shape as
//      shamir-split / backup-create output).
//   2. Structurally validate (distinct x in [1,255], consistent y-byte
//      lengths, even-length lowercase hex, non-empty).
//   3. Require length(shares) >= T (insufficient = exit 2 with diagnostic
//      mirroring the shamir-verify convention for under-threshold gates
//      that are NOT structural defects — but for ROTATE the threshold IS
//      a precondition: we must reconstruct to refresh, so insufficient
//      input is a hard failure, not informational).
//   4. Reconstruct the secret via shamir::combine (Lagrange at x=0).
//   5. Run a FRESH shamir::split of the SAME secret with N = max(input.x)
//      and threshold T. shamir::split always emits x = 1..N consecutively;
//      because operators expect "Share-K's holder remains Share-K", we
//      preserve x-coordinates by filtering the freshly-split shares down
//      to the input's x-set. (The discarded shares for x not in the input
//      set are never written anywhere.)
//   6. Verify (belt-and-suspenders): the new shares' combine() recovers
//      the SAME secret as the input. Mismatch is an internal-error exit 1
//      (would indicate a shamir-layer regression — not expected to fire).
//   7. Write the new share-set to --shares-out using the same JSON shape
//      as the input. Refuses overwrite without --force.
//
// Security property: the new shares lie on a DIFFERENT polynomial than
// the input (T-1 fresh random coefficients drawn from OpenSSL RAND_bytes
// inside shamir::split). Combining T old shares yields S; combining T
// new shares yields S; combining a mix of old + new (any T-1 from one,
// 1 from the other) yields garbage indistinguishable from a wrong secret
// (information-theoretic property of SSS over GF(2^8)). That mix-failure
// is what makes "rotate" meaningful: an attacker who held a stale subset
// of < T shares cannot combine them with one new share to recover S.
//
// Exit codes:
//   0  rotated successfully; --shares-out written.
//   1  bad args, file I/O error, JSON parse error, structural malformedness,
//      output already exists without --force.
//   2  insufficient input shares (< T supplied). Diagnostic gate: rotate
//      cannot proceed without crossing the threshold.
//
// What this CLI does NOT do:
//   * Change N or T. The output set has the SAME size and threshold as
//     the input.
//   * Touch envelopes. Only the bare share file is rotated. Operators
//     re-wrap each new share via `backup-create` (or equivalent) under
//     the same per-keyholder passphrases as the prior backup if they
//     want a refreshed envelope artifact.
//   * Change the secret. Rotating a share-set never alters the secret
//     it reconstructs.
int cmd_shamir_rotate(int argc, char** argv) {
    std::string shares_path, shares_out;
    int threshold = -1;
    bool force = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--shares"     && i + 1 < argc) shares_path = argv[++i];
        else if (a == "--threshold"  && i + 1 < argc) {
            try { threshold = std::stoi(argv[++i]); }
            catch (...) {
                std::cerr << "shamir-rotate: --threshold must be an integer\n";
                return 1;
            }
        }
        else if (a == "--shares-out" && i + 1 < argc) shares_out = argv[++i];
        else if (a == "--force")                      force      = true;
        else if (a == "--json")                       json_out   = true;
        else {
            std::cerr << "shamir-rotate: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet shamir-rotate --shares <file> "
                         "--threshold T --shares-out <file> [--force] [--json]\n";
            return 1;
        }
    }
    if (shares_path.empty() || threshold < 0 || shares_out.empty()) {
        std::cerr << "Usage: determ-wallet shamir-rotate --shares <file> "
                     "--threshold T --shares-out <file> [--force] [--json]\n";
        return 1;
    }
    if (threshold < 1) {
        std::cerr << "shamir-rotate: --threshold must be >= 1 (got "
                  << threshold << ")\n";
        return 1;
    }
    if (threshold > 255) {
        std::cerr << "shamir-rotate: --threshold must be <= 255 (got "
                  << threshold << ")\n";
        return 1;
    }
    if (shares_path == shares_out) {
        std::cerr << "shamir-rotate: --shares and --shares-out must not "
                     "point at the same file (cannot rotate in place; "
                     "the read pass and write pass would collide)\n";
        return 1;
    }

    // ── Read + parse input shares file ───────────────────────────────────
    std::ifstream f(shares_path);
    if (!f) {
        std::cerr << "shamir-rotate: cannot open --shares file: "
                  << shares_path << "\n";
        return 1;
    }
    std::string blob((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
    nlohmann::json j;
    try { j = nlohmann::json::parse(blob); }
    catch (std::exception& e) {
        std::cerr << "shamir-rotate: JSON parse failed: " << e.what() << "\n";
        return 1;
    }
    if (!j.is_object() || !j.contains("shares") || !j["shares"].is_array()) {
        std::cerr << "shamir-rotate: --shares JSON must be object with "
                     "'shares' array\n";
        return 1;
    }
    const auto& arr = j["shares"];
    if (arr.empty()) {
        std::cerr << "shamir-rotate: --shares array is empty\n"; return 1;
    }

    // Structural validation mirrors shamir-combine + shamir-verify so the
    // rotate CLI never reaches the cryptographic layer with malformed
    // input. Diagnostics are precise so operators can fix shares files
    // before a costly distribution event.
    std::vector<shamir::Share> in_shares;
    std::set<int> seen_x;
    int x_max_in = 0;
    size_t y_len = 0;
    for (size_t i = 0; i < arr.size(); ++i) {
        const auto& el = arr[i];
        if (!el.is_object()
            || !el.contains("x")     || !el["x"].is_number_integer()
            || !el.contains("y_hex") || !el["y_hex"].is_string()) {
            std::cerr << "shamir-rotate: share #" << i
                      << " must have integer 'x' and string 'y_hex'\n";
            return 1;
        }
        int x = el["x"].get<int>();
        if (x < 1 || x > 255) {
            std::cerr << "shamir-rotate: x = " << x << " out of range "
                         "[1, 255]\n";
            return 1;
        }
        if (!seen_x.insert(x).second) {
            std::cerr << "shamir-rotate: duplicate x = " << x
                      << " (Shamir invariant: all x must be distinct)\n";
            return 1;
        }
        if (x > x_max_in) x_max_in = x;
        std::string y_hex = el["y_hex"].get<std::string>();
        if (y_hex.size() % 2 != 0) {
            std::cerr << "shamir-rotate: y_hex for x=" << x
                      << " has odd length\n";
            return 1;
        }
        shamir::Share s;
        s.x = static_cast<uint8_t>(x);
        try { s.y = from_hex(y_hex); }
        catch (std::exception& e) {
            std::cerr << "shamir-rotate: y_hex parse failed for x=" << x
                      << ": " << e.what() << "\n";
            return 1;
        }
        if (s.y.empty()) {
            std::cerr << "shamir-rotate: y_hex empty for x=" << x << "\n";
            return 1;
        }
        if (y_len == 0) y_len = s.y.size();
        else if (s.y.size() != y_len) {
            std::cerr << "shamir-rotate: share x=" << x
                      << " y-length " << s.y.size()
                      << " differs from first share's " << y_len << "\n";
            return 1;
        }
        in_shares.push_back(std::move(s));
    }

    const int n_in = static_cast<int>(in_shares.size());

    // ── Threshold precondition: rotation requires reconstruction ─────────
    // Unlike shamir-verify (where under-threshold is informational), here
    // we MUST cross the threshold to recover the secret. Exit 2 is the
    // operator-alert gate documented in the header.
    if (n_in < threshold) {
        std::cerr << "shamir-rotate: insufficient input shares ("
                  << n_in << " supplied, --threshold " << threshold
                  << " required for reconstruction); rotation cannot "
                     "proceed\n";
        return 2;
    }

    // ── Reconstruct the secret via existing combine ──────────────────────
    auto secret_opt = shamir::combine(in_shares);
    if (!secret_opt) {
        // shamir::combine rejects on (duplicate x | mismatched y sizes |
        // empty) — all of which the structural pass above already filters.
        // Reaching here implies a deeper inconsistency; surface verbatim.
        std::cerr << "shamir-rotate: secret reconstruction failed at the "
                     "shamir layer (shares structurally valid but mutually "
                     "inconsistent — corrupt y values?)\n";
        return 1;
    }
    const std::vector<uint8_t>& secret = *secret_opt;

    // ── Fresh split preserving input x-coordinates ───────────────────────
    // shamir::split assigns x = 1..N consecutively. To preserve arbitrary
    // input x-coordinates (operators expect "Share-K's holder stays
    // Share-K"), split with N = max(input.x) and then filter down to the
    // input x-set. The freshly-drawn polynomial is the same for all x
    // (shamir::split builds ONE polynomial per secret byte using fresh
    // T-1 random coefficients), so the kept shares are mathematically
    // equivalent to those that would have been emitted by a hypothetical
    // split-at-arbitrary-x routine.
    std::vector<shamir::Share> all_new;
    try {
        all_new = shamir::split(secret,
                                  static_cast<uint8_t>(threshold),
                                  static_cast<uint8_t>(x_max_in));
    } catch (std::exception& e) {
        std::cerr << "shamir-rotate: shamir::split failed: " << e.what() << "\n";
        return 1;
    }

    // Filter all_new down to input x-set, preserving the input order so
    // the output JSON layout matches the input layout 1:1.
    std::vector<shamir::Share> new_shares;
    new_shares.reserve(n_in);
    for (const auto& src : in_shares) {
        bool found = false;
        for (const auto& cand : all_new) {
            if (cand.x == src.x) {
                new_shares.push_back(cand);
                found = true;
                break;
            }
        }
        if (!found) {
            // shamir::split always emits x = 1..x_max_in, and every input
            // x is in [1, x_max_in] by construction, so this branch is
            // unreachable. Guard anyway — internal-error gate.
            std::cerr << "shamir-rotate: internal: x=" << static_cast<int>(src.x)
                      << " not present in fresh split output\n";
            return 1;
        }
    }

    // ── Verification round-trip ──────────────────────────────────────────
    // Belt-and-suspenders check: the new share-set must reconstruct the
    // SAME secret as the input. A mismatch would indicate a shamir-layer
    // regression (shouldn't fire); treat as internal-error exit 1.
    auto verify_opt = shamir::combine(new_shares);
    if (!verify_opt) {
        std::cerr << "shamir-rotate: internal: fresh share-set failed to "
                     "combine (shamir layer rejected its own output)\n";
        return 1;
    }
    if (*verify_opt != secret) {
        std::cerr << "shamir-rotate: internal: fresh share-set combines to "
                     "a different secret (shamir layer regression)\n";
        return 1;
    }

    // ── Output overwrite gate ────────────────────────────────────────────
    if (std::filesystem::exists(shares_out) && !force) {
        std::cerr << "shamir-rotate: --shares-out file already exists: "
                  << shares_out
                  << " (use --force to overwrite; refusing by default to "
                     "avoid destroying a prior rotated share-set)\n";
        return 1;
    }

    // ── Write the new share-set ──────────────────────────────────────────
    nlohmann::json out_doc;
    out_doc["shares"] = nlohmann::json::array();
    for (const auto& s : new_shares) {
        out_doc["shares"].push_back({
            {"x",     static_cast<int>(s.x)},
            {"y_hex", to_hex(s.y)},
        });
    }
    {
        std::ofstream of(shares_out);
        if (!of) {
            std::cerr << "shamir-rotate: cannot open --shares-out for write: "
                      << shares_out << "\n";
            return 1;
        }
        of << out_doc.dump() << "\n";
        if (!of) {
            std::cerr << "shamir-rotate: write failed on --shares-out: "
                      << shares_out << "\n";
            return 1;
        }
    }
    // Owner-only perms (POSIX); no-op on Windows.
    {
        std::error_code perm_ec;
        std::filesystem::permissions(
            shares_out,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
    }

    // ── Summary ──────────────────────────────────────────────────────────
    if (json_out) {
        nlohmann::json r;
        r["share_count"]   = n_in;
        r["threshold"]     = threshold;
        r["secret_bytes"]  = secret.size();
        r["shares_file"]   = shares_out;
        r["rotated"]       = true;
        // NEVER emit secret material in the summary. The whole point of
        // rotation is to refresh the polynomial without exposing the
        // secret; leaking it here would defeat the purpose.
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "=== shamir-rotate (PSS polynomial refresh) ===\n";
        std::cout << "Input shares:    " << n_in << " (>= threshold "
                  << threshold << ")\n";
        std::cout << "Secret bytes:    " << secret.size()
                  << " (reconstructed and verified)\n";
        std::cout << "Output shares:   " << n_in
                  << " (same N, same x-coordinates, fresh polynomial)\n";
        std::cout << "Written to:      " << shares_out << "\n";
        std::cout << "[OK] Polynomial refreshed; secret invariant.\n";
    }
    return 0;
}

int cmd_envelope_encrypt(int argc, char** argv) {
    std::string plaintext_hex, password, aad_hex;
    uint32_t iters = envelope::DEFAULT_PBKDF2_ITERS;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--plaintext" && i + 1 < argc) plaintext_hex = argv[++i];
        else if (a == "--password"  && i + 1 < argc) password      = argv[++i];
        else if (a == "--aad"       && i + 1 < argc) aad_hex       = argv[++i];
        else if (a == "--iters"     && i + 1 < argc) iters         = static_cast<uint32_t>(std::stoul(argv[++i]));
    }
    if (plaintext_hex.empty() || password.empty()) {
        std::cerr << "Usage: determ-wallet envelope encrypt "
                     "--plaintext <hex> --password <str> "
                     "[--aad <hex>] [--iters <N>]\n";
        return 1;
    }
    std::vector<uint8_t> pt, aad;
    try {
        pt = from_hex(plaintext_hex);
        if (!aad_hex.empty()) aad = from_hex(aad_hex);
    } catch (std::exception& e) {
        std::cerr << "hex parse: " << e.what() << "\n"; return 1;
    }
    try {
        auto env = envelope::encrypt(pt, password, aad, iters);
        std::cout << envelope::serialize(env) << "\n";
    } catch (std::exception& e) {
        std::cerr << "encrypt: " << e.what() << "\n"; return 1;
    }
    return 0;
}

int cmd_envelope_decrypt(int argc, char** argv) {
    std::string blob, password, aad_hex;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--envelope" && i + 1 < argc) blob     = argv[++i];
        else if (a == "--password" && i + 1 < argc) password = argv[++i];
        else if (a == "--aad"      && i + 1 < argc) aad_hex  = argv[++i];
    }
    if (blob.empty() || password.empty()) {
        std::cerr << "Usage: determ-wallet envelope decrypt "
                     "--envelope <blob> --password <str> [--aad <hex>]\n";
        return 1;
    }
    auto env_opt = envelope::deserialize(blob);
    if (!env_opt) {
        std::cerr << "decrypt: envelope deserialize failed (malformed blob)\n";
        return 1;
    }
    std::vector<uint8_t> aad;
    if (!aad_hex.empty()) {
        try { aad = from_hex(aad_hex); }
        catch (std::exception& e) {
            std::cerr << "aad hex: " << e.what() << "\n"; return 1;
        }
    }
    auto pt_opt = envelope::decrypt(*env_opt, password, aad);
    if (!pt_opt) {
        std::cerr << "decrypt: AEAD tag failure "
                     "(wrong password, tampered ciphertext, or mismatched AAD)\n";
        return 2;
    }
    std::cout << to_hex(*pt_opt) << "\n";
    return 0;
}

int cmd_envelope(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "Usage: determ-wallet envelope {encrypt|decrypt} ...\n";
        return 1;
    }
    std::string sub = argv[0];
    if (sub == "encrypt") return cmd_envelope_encrypt(argc - 1, argv + 1);
    if (sub == "decrypt") return cmd_envelope_decrypt(argc - 1, argv + 1);
    std::cerr << "Unknown envelope subcommand: " << sub << "\n";
    return 1;
}

// Diagnostic CLI: inspect an envelope file without decrypting.
//
// Use cases:
//   * Forensic inspection of stale recovery artifacts on disk.
//   * Operators verifying a candidate file is actually an envelope
//     (right magic + sane salt/nonce sizes) before paying the PBKDF2
//     cost of a decrypt attempt.
//   * Tooling (monitoring scripts, log aggregators) that wants the
//     KDF parameters in structured form (--json).
//
// Parses the canonical serialized blob via envelope::deserialize and
// reports the header fields. NEVER calls AES-GCM — no key derivation,
// no tag verification, no plaintext recovery. A password is therefore
// not required and not accepted.
//
// Wire format (recap from envelope.hpp):
//   "DWE1" magic (4B) | salt_len/salt | pbkdf2_iters (u32 LE)
//   | nonce (12B) | aad_len/aad | ct_len/(ciphertext || 16B tag)
// The serialized form is dot-separated lowercase hex of those fields.
int cmd_inspect_envelope(int argc, char** argv) {
    std::string in_path;
    bool json_output = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"   && i + 1 < argc) in_path = argv[++i];
        else if (a == "--json")                 json_output = true;
    }
    if (in_path.empty()) {
        std::cerr << "Usage: determ-wallet inspect-envelope --in <file> [--json]\n";
        return 1;
    }
    std::ifstream f(in_path);
    if (!f) {
        std::cerr << "inspect-envelope: cannot open --in: " << in_path << "\n";
        return 1;
    }
    std::string blob((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
    // Strip surrounding whitespace and any trailing CR/LF — the file may
    // have been written via shell redirection which appends a newline.
    auto is_ws = [](char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    };
    while (!blob.empty() && is_ws(blob.front())) blob.erase(blob.begin());
    while (!blob.empty() && is_ws(blob.back()))  blob.pop_back();
    if (blob.empty()) {
        std::cerr << "inspect-envelope: file is empty: " << in_path << "\n";
        return 1;
    }

    auto env_opt = envelope::deserialize(blob);
    if (!env_opt) {
        std::cerr << "inspect-envelope: malformed envelope "
                     "(bad magic, truncated, or non-hex content)\n";
        return 2;
    }
    const auto& env = *env_opt;

    // ciphertext stored as (body || 16B tag). Report them separately so
    // operators can sanity-check both the body length and the tag.
    constexpr size_t TAG_LEN = 16;
    const size_t ct_total = env.ciphertext.size();
    const size_t ct_body  = ct_total - TAG_LEN;
    const bool   aad_present = !env.aad.empty();

    if (json_output) {
        // Hand-built JSON: deliberately minimal — no nested objects, no
        // arrays of bytes. Keep the schema flat so monitoring scripts can
        // parse with jq/Python json with zero ambiguity. Hex strings are
        // lowercase to match envelope::serialize convention.
        std::cout << "{"
                  << "\"format\":\"DWE1\","
                  << "\"version\":1,"
                  << "\"pbkdf2_iters\":" << env.pbkdf2_iters << ","
                  << "\"salt_len\":"     << env.salt.size()  << ","
                  << "\"salt_hex\":\""   << to_hex(env.salt) << "\","
                  << "\"nonce_len\":"    << env.nonce.size() << ","
                  << "\"nonce_hex\":\""  << to_hex(env.nonce)<< "\","
                  << "\"aad_present\":"  << (aad_present ? "true" : "false") << ","
                  << "\"aad_len\":"      << env.aad.size()   << ","
                  << "\"aad_hex\":\""    << to_hex(env.aad)  << "\","
                  << "\"ciphertext_len\":" << ct_total       << ","
                  << "\"ciphertext_body_len\":" << ct_body   << ","
                  << "\"tag_len\":"      << TAG_LEN
                  << "}\n";
    } else {
        std::cout << "envelope file:   " << in_path           << "\n";
        std::cout << "format:          DWE1 (version 1)\n";
        std::cout << "pbkdf2_iters:    " << env.pbkdf2_iters  << "\n";
        std::cout << "salt_len:        " << env.salt.size()   << " bytes\n";
        std::cout << "salt_hex:        " << to_hex(env.salt)  << "\n";
        std::cout << "nonce_len:       " << env.nonce.size()  << " bytes\n";
        std::cout << "nonce_hex:       " << to_hex(env.nonce) << "\n";
        std::cout << "aad_present:     " << (aad_present ? "true" : "false") << "\n";
        std::cout << "aad_len:         " << env.aad.size()    << " bytes\n";
        if (aad_present)
            std::cout << "aad_hex:         " << to_hex(env.aad) << "\n";
        std::cout << "ciphertext_len:  " << ct_total          << " bytes\n";
        std::cout << "  body:          " << ct_body           << " bytes\n";
        std::cout << "  tag:           " << TAG_LEN           << " bytes (GCM)\n";
    }
    return 0;
}

// Operator-workflow CLI: batch-generate N fresh anonymous account keypairs
// in one invocation. Useful for:
//   * Cold-storage provisioning (mint a batch of receive addresses to
//     distribute to clients, with privkeys kept offline).
//   * Faucet bootstrapping (pre-mint addresses to fund + hand out).
//   * Test-fixture generation (deterministic build of test corpora —
//     each call still produces fresh randomness; the "deterministic"
//     part is the on-disk JSON shape, not the values).
//
// Each entry: Ed25519 keypair (OpenSSL EVP) → anon-address derivation
// ("0x" + lowercase hex(pubkey)). Mirrors the shape produced by the
// `determ account create` command but batched, so an operator doesn't
// pay process-startup cost per account.
//
// Output modes (mutually-exclusive precedence):
//   default (no flags) — human format to stdout, one block per account:
//       Account 1:
//         address:     0x...
//         privkey_hex: ...
//   --out <file>        — write a JSON file {accounts: [{address, privkey_hex}, ...]}
//                         and print only a one-line confirmation to stdout.
//                         The privkey material lives in the file, not the terminal.
//   --json (no --out)   — write the same JSON shape to stdout.
//   --out + --json      — --out wins (explicit operator choice; no
//                         JSON to stdout even though --json was set).
//
// Safety guards:
//   * 1 <= N <= 10000. Operator-side cap; generating > 10k keypairs in
//     one call is almost certainly an automation bug (a power-of-ten
//     fat-finger), not a real workflow. Belt-and-suspenders against
//     accidentally writing a 5-MB privkey blob.
//   * --out file overwrite refused unless --force. Privkey loss via
//     accidental overwrite is unrecoverable; force a deliberate ack.
//   * --out parent directory must exist (no mkdirp). Surfacing the
//     missing-directory error early is friendlier than silently
//     creating an unintended directory tree.
//
// Privkey emission:
//   Unlike `determ account create` (which gates plaintext stdout
//   behind --allow-plaintext-stdout due to S-004), this command's
//   default human mode emits plaintext privkeys because the typical
//   workflow REDIRECTS to a file (`> accounts.txt`) or pipes to a
//   processing tool. For terminal-leakage-sensitive use, operators
//   should pass --out <file> (which gets owner-only permissions on
//   POSIX via std::filesystem::permissions; on Windows we rely on
//   the default ACL of the parent directory). This deviation is
//   intentional: batch generation has no sensible "encrypt at rest"
//   default because the operator's intent is downstream automation.
int cmd_account_create_batch(int argc, char** argv) {
    int count = 0;
    std::string out_path;
    bool json_out = false;
    bool force = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--count" && i + 1 < argc) {
            try { count = std::stoi(argv[++i]); }
            catch (std::exception&) {
                std::cerr << "account-create-batch: --count must be an integer\n";
                return 1;
            }
        }
        else if (a == "--out"   && i + 1 < argc) out_path = argv[++i];
        else if (a == "--json")                  json_out = true;
        else if (a == "--force")                 force    = true;
        else {
            std::cerr << "account-create-batch: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet account-create-batch --count N "
                         "[--out <file>] [--json] [--force]\n";
            return 1;
        }
    }
    if (count <= 0) {
        std::cerr << "account-create-batch: --count must be >= 1 (got "
                  << count << ")\n";
        return 1;
    }
    constexpr int MAX_COUNT = 10000;
    if (count > MAX_COUNT) {
        std::cerr << "account-create-batch: --count must be <= " << MAX_COUNT
                  << " (got " << count << "). If you genuinely need more, "
                     "invoke the command multiple times and concatenate; "
                     "the cap is an operator safety net against fat-finger "
                     "automation errors.\n";
        return 1;
    }
    // --out preconditions: parent dir must exist; destination file
    // must not exist (unless --force). Surfacing these before keygen
    // means we don't generate N keypairs and then discard them.
    if (!out_path.empty()) {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "account-create-batch: --out parent directory does "
                         "not exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "account-create-batch: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // Build the accounts array via OpenSSL Ed25519 keygen. EVP_PKEY_keygen
    // ultimately pulls from OpenSSL's CSPRNG (seeded from the OS RNG at
    // library init), so each iteration gets fresh material.
    nlohmann::json arr = nlohmann::json::array();
    for (int i = 0; i < count; ++i) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (!ctx) {
            std::cerr << "account-create-batch: EVP_PKEY_CTX_new_id failed\n";
            return 1;
        }
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            std::cerr << "account-create-batch: EVP_PKEY_keygen_init failed\n";
            return 1;
        }
        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            std::cerr << "account-create-batch: EVP_PKEY_keygen failed\n";
            return 1;
        }
        EVP_PKEY_CTX_free(ctx);
        std::array<uint8_t, 32> pub{};
        std::array<uint8_t, 32> priv_seed{};
        size_t len = pub.size();
        if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) <= 0
            || len != 32) {
            EVP_PKEY_free(pkey);
            std::cerr << "account-create-batch: get_raw_public_key failed\n";
            return 1;
        }
        len = priv_seed.size();
        if (EVP_PKEY_get_raw_private_key(pkey, priv_seed.data(), &len) <= 0
            || len != 32) {
            EVP_PKEY_free(pkey);
            std::cerr << "account-create-batch: get_raw_private_key failed\n";
            return 1;
        }
        EVP_PKEY_free(pkey);

        std::string address = "0x" + to_hex(pub);           // matches make_anon_address
        std::string privkey_hex = to_hex(priv_seed);        // 64 lowercase hex
        arr.push_back({
            {"address",     address},
            {"privkey_hex", privkey_hex},
        });
    }

    // Dispatch on output mode.
    if (!out_path.empty()) {
        nlohmann::json doc;
        doc["accounts"] = std::move(arr);
        std::ofstream f(out_path);
        if (!f) {
            std::cerr << "account-create-batch: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        f << doc.dump(2) << "\n";
        f.close();
        // POSIX permissions tightening — owner-only read/write. On
        // Windows the call is a no-op for the read/write bits (NTFS
        // ACL inherits from parent); we ignore the error code there.
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        // Intentionally non-fatal on perm-set failure: file is written;
        // operator may need to chmod manually on exotic filesystems.
        std::cout << "wrote " << count << " accounts to " << out_path << "\n";
        return 0;
    }
    if (json_out) {
        nlohmann::json doc;
        doc["accounts"] = std::move(arr);
        std::cout << doc.dump(2) << "\n";
        return 0;
    }
    // Default human format.
    for (size_t i = 0; i < arr.size(); ++i) {
        std::cout << "Account " << (i + 1) << ":\n"
                  << "  address:     " << arr[i]["address"].get<std::string>()     << "\n"
                  << "  privkey_hex: " << arr[i]["privkey_hex"].get<std::string>() << "\n";
    }
    return 0;
}

// ── account-derive-batch — deterministic batch derivation from a master seed ─
//
// Sibling of `account-create-batch`. Where account-create-batch generates N
// keypairs from fresh CSPRNG draws (so back-to-back invocations produce
// disjoint sets), account-derive-batch derives N keypairs from a single
// 32-byte master seed using SHA-256 domain separation. The same master
// seed ALWAYS produces the same N accounts; different seeds always produce
// disjoint sets (with cryptographic probability).
//
// Algorithm (SLIP-0010-style hardened-only derivation, flat array — no
// hierarchical paths):
//
//     for i in 0..N-1:
//         seed_i      = SHA-256(master_seed || u32_le(i))
//         keypair_i   = crypto_sign_ed25519_seed_keypair(seed_i)
//         address_i   = "0x" + lowercase hex(pubkey_i)
//
// The little-endian u32 width (NOT a variable-length encoding) keeps the
// pre-image deterministic across platforms. Caller's master seed enters
// the SHA-256 as a domain separator: an adversary who learns seed_i for
// some i still cannot derive seed_j for j != i (SHA-256 one-wayness),
// and cannot derive the master seed itself.
//
// Operator use cases:
//   1. Cold-wallet provisioning from a single backed-up seed. The operator
//      stores ONE 32-byte secret offline; on-demand they derive N receive
//      addresses, fund them, and never need to back up the per-account
//      private keys. Recovery only requires the master seed.
//   2. Test-fixture generation. CI pipelines pin a fixed master seed and
//      get reproducible account sets across machines and runs.
//   3. Recovery scenarios. If individual per-account privkeys are lost,
//      the entire set is recoverable from the master seed alone.
//
// CLI:
//   --seed <hex>:  REQUIRED. Exactly 64 hex chars (32 bytes).
//   --count N:     REQUIRED. 1 <= N <= 10000 (same cap as
//                  account-create-batch — operator safety net).
//   --out <file>:  optional. Writes JSON to file with 0600 perms (refuses
//                  overwrite without --force).
//   --json:        prints the same JSON to stdout (ignored if --out is set).
//   --force:       overwrite an existing --out.
//
// Output JSON shape (--out / --json):
//   {
//     "master_seed_hash_hex": "<64-hex SHA-256 of the master seed>",
//     "count":                N,
//     "accounts": [
//       {"index": 0, "address": "0x...", "privkey_hex": "..."},
//       ...
//     ]
//   }
//
// The `master_seed_hash_hex` field lets the operator verify (out-of-band)
// that a derivation run matches an expected master seed WITHOUT exposing
// the seed itself in the output file. This is the SHA-256 of the raw seed
// bytes (NOT a derived sub-seed). Knowledge of this hash alone reveals no
// information about the master seed beyond what a brute-force preimage
// search would require.
//
// Default human format (no --out, no --json) mirrors account-create-batch:
//     account[i]: address=0x... privkey_hex=...
// One line per account, deterministic order (i = 0..N-1).
//
// Exit codes:
//   0 = success
//   1 = argument / validation / I/O error
int cmd_account_derive_batch(int argc, char** argv) {
    std::string seed_hex;
    int count = 0;
    std::string out_path;
    bool json_out = false;
    bool force    = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--seed"  && i + 1 < argc) seed_hex = argv[++i];
        else if (a == "--count" && i + 1 < argc) {
            try { count = std::stoi(argv[++i]); }
            catch (std::exception&) {
                std::cerr << "account-derive-batch: --count must be an integer\n";
                return 1;
            }
        }
        else if (a == "--out"   && i + 1 < argc) out_path = argv[++i];
        else if (a == "--json")                  json_out = true;
        else if (a == "--force")                 force    = true;
        else {
            std::cerr << "account-derive-batch: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet account-derive-batch --seed <hex> "
                         "--count N [--out <file>] [--json] [--force]\n";
            return 1;
        }
    }

    // ── Validate --seed (exactly 64 hex chars = 32 bytes) ───────────────────
    if (seed_hex.empty()) {
        std::cerr << "account-derive-batch: --seed is required (32-byte master "
                     "seed = exactly 64 hex chars)\n";
        std::cerr << "Usage: determ-wallet account-derive-batch --seed <hex> "
                     "--count N [--out <file>] [--json] [--force]\n";
        return 1;
    }
    if (seed_hex.size() != 64) {
        std::cerr << "account-derive-batch: --seed must be exactly 64 hex chars "
                     "(32-byte master seed); got " << seed_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> seed_bytes;
    try { seed_bytes = from_hex(seed_hex); }
    catch (std::exception& e) {
        std::cerr << "account-derive-batch: invalid --seed hex: "
                  << e.what() << "\n";
        return 1;
    }
    if (seed_bytes.size() != 32) {
        // Belt-and-suspenders; the 64-char check above already covered it.
        std::cerr << "account-derive-batch: --seed decoded length must be 32; "
                     "got " << seed_bytes.size() << "\n";
        return 1;
    }

    // ── Validate --count ────────────────────────────────────────────────────
    if (count <= 0) {
        std::cerr << "account-derive-batch: --count must be >= 1 (got "
                  << count << ")\n";
        return 1;
    }
    constexpr int MAX_COUNT = 10000;
    if (count > MAX_COUNT) {
        std::cerr << "account-derive-batch: --count must be <= " << MAX_COUNT
                  << " (got " << count << "). If you genuinely need more, "
                     "invoke the command multiple times and concatenate; "
                     "the cap is an operator safety net against fat-finger "
                     "automation errors.\n";
        return 1;
    }

    // ── --out preconditions checked BEFORE derivation ───────────────────────
    if (!out_path.empty()) {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "account-derive-batch: --out parent directory does "
                         "not exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "account-derive-batch: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Init libsodium for the Ed25519 seed-keypair primitive ───────────────
    if (!primitives::init_libsodium()) {
        std::cerr << "account-derive-batch: libsodium init failed\n";
        return 1;
    }
    static_assert(crypto_sign_PUBLICKEYBYTES == 32, "Ed25519 pk size mismatch");
    static_assert(crypto_sign_SECRETKEYBYTES == 64, "Ed25519 sk size mismatch");
    static_assert(crypto_sign_SEEDBYTES      == 32, "Ed25519 seed size mismatch");

    // ── Compute master_seed_hash for output (does NOT leak the seed) ────────
    std::array<uint8_t, 32> master_hash{};
    SHA256(seed_bytes.data(), seed_bytes.size(), master_hash.data());

    // ── Derive accounts deterministically ───────────────────────────────────
    // seed_i = SHA-256(master_seed || u32_le(i))
    //
    // The u32_le encoding is fixed-width (4 bytes) and platform-independent
    // — this is what makes the derivation reproducible across machines.
    // A variable-width encoding (e.g. varint) could shift collision domains
    // between caller environments.
    nlohmann::json arr = nlohmann::json::array();
    for (int i = 0; i < count; ++i) {
        // Build preimage: master_seed (32 B) || u32_le(i) (4 B) = 36 B.
        std::array<uint8_t, 36> preimage{};
        std::memcpy(preimage.data(), seed_bytes.data(), 32);
        uint32_t idx = static_cast<uint32_t>(i);
        preimage[32] = static_cast<uint8_t>((idx >>  0) & 0xff);
        preimage[33] = static_cast<uint8_t>((idx >>  8) & 0xff);
        preimage[34] = static_cast<uint8_t>((idx >> 16) & 0xff);
        preimage[35] = static_cast<uint8_t>((idx >> 24) & 0xff);

        std::array<uint8_t, 32> sub_seed{};
        SHA256(preimage.data(), preimage.size(), sub_seed.data());

        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pub{};
        std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
        if (crypto_sign_ed25519_seed_keypair(pub.data(), sk.data(),
                                             sub_seed.data()) != 0) {
            // SHA-256 outputs are uniformly distributed over a 256-bit
            // range; the probability that a single output happens to be
            // rejected by ed25519 keygen is effectively zero. If we ever
            // hit this, the OS RNG / SHA-256 / libsodium are mis-wired.
            sodium_memzero(sub_seed.data(), sub_seed.size());
            sodium_memzero(sk.data(),       sk.size());
            std::cerr << "account-derive-batch: crypto_sign_ed25519_seed_"
                         "keypair failed at index " << i
                      << " (this is essentially impossible for SHA-256-"
                         "uniform input — investigate the build)\n";
            return 1;
        }
        // Per-account secret material lives in two places now: sub_seed
        // and the leading 32 B of sk. Zero the libsodium sk; serialize
        // the sub_seed as the privkey_hex (the canonical wallet-format
        // 32-byte seed, matching account-create-batch).
        sodium_memzero(sk.data(), sk.size());

        std::string address = "0x" + to_hex(pub);
        std::string privkey_hex = to_hex(sub_seed);
        arr.push_back({
            {"index",       i},
            {"address",     address},
            {"privkey_hex", privkey_hex},
        });
        sodium_memzero(sub_seed.data(), sub_seed.size());
    }

    // ── Build the output JSON document ──────────────────────────────────────
    nlohmann::json doc;
    doc["master_seed_hash_hex"] = to_hex(master_hash);
    doc["count"]                = count;
    doc["accounts"]             = std::move(arr);

    // ── Zero the master seed bytes now that derivation is done ─────────────
    // doc still holds the per-account privkey_hex strings (which is the
    // intended output); only the original master seed is wiped here.
    sodium_memzero(seed_bytes.data(), seed_bytes.size());

    // ── Dispatch on output mode ─────────────────────────────────────────────
    if (!out_path.empty()) {
        std::ofstream f(out_path);
        if (!f) {
            std::cerr << "account-derive-batch: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        f << doc.dump(2) << "\n";
        f.close();
        // 0600 owner-only perms. On Windows the call is a no-op for the
        // read/write bits (NTFS ACL inherits from parent); non-fatal.
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        std::cout << "derived " << count << " accounts to " << out_path << "\n";
        return 0;
    }
    if (json_out) {
        std::cout << doc.dump(2) << "\n";
        return 0;
    }
    // Default human format — one line per account.
    // Matches the task spec verbatim: "account[i]: address=0x... privkey_hex=..."
    for (int i = 0; i < count; ++i) {
        std::cout << "account[" << i << "]: address="
                  << doc["accounts"][i]["address"].get<std::string>()
                  << " privkey_hex="
                  << doc["accounts"][i]["privkey_hex"].get<std::string>()
                  << "\n";
    }
    return 0;
}

// ── account-import — import an existing Ed25519 privkey as a wallet account ─
//
// Companion to `account-create-batch`. Where account-create-batch generates
// fresh CSPRNG-drawn material, account-import accepts a pre-existing private
// key supplied by the operator and converts it to the wallet's anon-account
// JSON shape. Typical use cases:
//
//   1. Shamir recovery — operator runs `shamir-combine` to reconstruct a
//      32-byte seed, then pipes the hex into account-import to materialize
//      the wallet-format JSON file the daemon and tooling consume.
//   2. Cross-wallet migration — any external Ed25519-compatible wallet that
//      can export a 32-byte seed (or 64-byte seed||pubkey concatenation) can
//      be transplanted into Determ's anon-account format with a single call.
//   3. Test-fixture creation — supplying a deterministic seed lets test
//      suites pin reproducible addresses without bringing the CSPRNG into
//      the test's trusted boundary.
//
// CLI:
//   --priv <hex>: 64 hex chars (32-byte seed) OR 128 hex chars (seed || pub).
//                 The 64-byte form is supported for symmetry with external
//                 wallets that export the libsodium-shaped secret key
//                 (seed concatenated with the derived pubkey). When 64 bytes
//                 are supplied, we verify that the seed-derived pubkey
//                 matches the supplied tail-32 bytes; mismatch is rejected
//                 because it almost always means the operator concatenated
//                 the wrong pubkey or hit a transcription error.
//   --out <file>: optional. If set, writes a single-account JSON file with
//                 0600 permissions (best-effort on Windows; NTFS ACL).
//                 Refuses overwrite without --force. Parent dir must exist.
//   --force:      required to overwrite an existing --out.
//   --json:       prints {"address":..., "privkey_hex":...} to stdout
//                 instead of the human-readable two-line format. Ignored
//                 if --out is also set.
//
// Output JSON shape (matches a single element of account-create-batch's array):
//   { "address": "0x<64-hex-of-pubkey>", "privkey_hex": "<64-hex-of-seed>" }
//
// Exit codes:
//   0 = success
//   1 = argument / validation / I/O error (including mismatched 64-byte form)
int cmd_account_import(int argc, char** argv) {
    std::string priv_hex, out_path;
    bool force    = false;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--priv"  && i + 1 < argc) priv_hex = argv[++i];
        else if (a == "--out"   && i + 1 < argc) out_path = argv[++i];
        else if (a == "--force")                 force    = true;
        else if (a == "--json")                  json_out = true;
        else {
            std::cerr << "account-import: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet account-import --priv <hex> "
                         "[--out <file>] [--force] [--json]\n";
            return 1;
        }
    }
    if (priv_hex.empty()) {
        std::cerr << "account-import: --priv is required (32-byte seed = 64 "
                     "hex chars, or 64-byte keypair = 128 hex chars)\n";
        std::cerr << "Usage: determ-wallet account-import --priv <hex> "
                     "[--out <file>] [--force] [--json]\n";
        return 1;
    }

    // ── Validate --priv length (must be 32 B seed or 64 B keypair) ──────────
    // Same convention as keyfile-create. Surfacing this before from_hex
    // gives a more actionable error message than "odd length" on, say,
    // a 65-char paste.
    if (priv_hex.size() != 64 && priv_hex.size() != 128) {
        std::cerr << "account-import: --priv must be 64 hex chars (32-byte "
                     "seed) or 128 hex chars (32-byte seed || 32-byte pubkey); "
                     "got " << priv_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> priv_bytes;
    try { priv_bytes = from_hex(priv_hex); }
    catch (std::exception& e) {
        std::cerr << "account-import: invalid --priv hex: " << e.what() << "\n";
        return 1;
    }
    if (priv_bytes.size() != 32 && priv_bytes.size() != 64) {
        // Belt-and-suspenders; the size check above already covered this.
        std::cerr << "account-import: --priv decoded length must be 32 or 64; "
                     "got " << priv_bytes.size() << "\n";
        return 1;
    }

    // ── --out preconditions checked BEFORE keygen ───────────────────────────
    // Surfacing parent-dir-missing / file-exists errors before the
    // libsodium call means we don't burn cycles on derivation only to
    // discard the result. (For account-import this is cheap, but it
    // matches the account-create-batch ergonomics — fail fast on the
    // operator's I/O misconfig.)
    if (!out_path.empty()) {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "account-import: --out parent directory does not "
                         "exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "account-import: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Init libsodium + derive keypair from seed ───────────────────────────
    // Task spec: use crypto_sign_ed25519_seed_keypair. This is functionally
    // equivalent to crypto_sign_seed_keypair (both produce the same Ed25519
    // pub/sk from a 32-byte seed) but the _ed25519_ form is the explicit
    // alias for cases where the caller wants to be unambiguous about the
    // curve. Using the same primitive that message-sign uses keeps the
    // wallet's secret-handling surface uniform on libsodium.
    if (!primitives::init_libsodium()) {
        std::cerr << "account-import: libsodium init failed\n";
        return 1;
    }
    std::array<uint8_t, 32> seed{};
    std::memcpy(seed.data(), priv_bytes.data(), 32);
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> derived_pub{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    static_assert(crypto_sign_PUBLICKEYBYTES == 32, "Ed25519 pk size mismatch");
    static_assert(crypto_sign_SECRETKEYBYTES == 64, "Ed25519 sk size mismatch");
    static_assert(crypto_sign_SEEDBYTES      == 32, "Ed25519 seed size mismatch");
    if (crypto_sign_ed25519_seed_keypair(derived_pub.data(), sk.data(),
                                         seed.data()) != 0) {
        std::cerr << "account-import: crypto_sign_ed25519_seed_keypair failed "
                     "(seed not a valid Ed25519 private key)\n";
        return 1;
    }
    // Zero the libsodium-derived 64-byte sk — it contains seed||pubkey, both
    // of which already live in `seed` / `derived_pub`, so the duplicate is
    // unnecessary post-derivation. seed itself stays live for the JSON emit.
    sodium_memzero(sk.data(), sk.size());

    // ── 64-byte-form pubkey mismatch check (defense-in-depth) ───────────────
    // Same logic as keyfile-create: if the operator pasted a 64-byte form,
    // the trailing 32 bytes MUST match the seed-derived pubkey. A mismatch
    // is almost always a transcription error or a mixed-up keypair.
    if (priv_bytes.size() == 64) {
        std::array<uint8_t, 32> supplied_pub{};
        std::memcpy(supplied_pub.data(), priv_bytes.data() + 32, 32);
        if (supplied_pub != derived_pub) {
            std::cerr << "account-import: --priv mismatch: 64-byte form's "
                         "tail 32 bytes don't match the pubkey derived from "
                         "the seed (operator likely concatenated the wrong "
                         "pubkey, or copy-paste hit a transcription error)\n";
            return 1;
        }
    }

    // ── Build the anon-account record ───────────────────────────────────────
    // Matches account-create-batch byte-for-byte: address is "0x" + lowercase
    // hex of the 32-byte pubkey (the canonical anon-address derivation in
    // src/wallet/account.cpp::make_anon_address); privkey_hex is the 32-byte
    // seed (NOT the 64-byte libsodium sk).
    std::string address     = "0x" + to_hex(derived_pub);
    std::string privkey_hex = to_hex(seed);
    nlohmann::json record = {
        {"address",     address},
        {"privkey_hex", privkey_hex},
    };

    // ── Dispatch on output mode ─────────────────────────────────────────────
    if (!out_path.empty()) {
        std::ofstream f(out_path);
        if (!f) {
            std::cerr << "account-import: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        f << record.dump(2) << "\n";
        f.close();
        if (!f) {
            std::cerr << "account-import: write failed on --out: "
                      << out_path << "\n";
            return 1;
        }
        // 0600 permissions — owner-only read/write. On Windows the
        // read/write bits are a no-op (NTFS ACL inherits from parent);
        // we ignore the error code as non-fatal there.
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
        std::cout << "imported account: " << address << "\n";
        return 0;
    }
    if (json_out) {
        std::cout << record.dump() << "\n";
        return 0;
    }
    // Default human format — same two-field layout as account-create-batch's
    // per-account block, sans the "Account N:" header (since import always
    // produces exactly one account).
    std::cout << "address:     " << address     << "\n";
    std::cout << "privkey_hex: " << privkey_hex << "\n";
    return 0;
}

// ── account-export — re-emit a wallet account file in various formats ──────
//
// Inverse of `account-create-batch` / `account-import` / `account-recover`:
// reads an existing single-account JSON file (the canonical wallet shape
//   { "address": "0x...", "privkey_hex": "..." })
// and re-emits it in one of three external formats. Useful when an operator
// needs to feed the secret material into a downstream tool with a different
// expected shape (e.g., piping into `backup-create --secret`, or printing the
// raw hex to a shell variable, or copy-pasting the full JSON into a hex
// inspector).
//
// CLI:
//   --in <file>: required. The single-account JSON file. Must contain at
//                least `address` (string, "0x" + 64 lowercase hex) and
//                `privkey_hex` (64-char lowercase hex). Extra fields are
//                tolerated (they are ignored on `raw-hex` output, preserved
//                on `json` passthrough, and dropped on `backup-bundle`).
//   --format <name>: optional, default `raw-hex`. One of:
//                * raw-hex       — print the 64-char privkey hex on stdout,
//                                  followed by a single newline. Useful for
//                                  shell substitution: `KEY=$(determ-wallet
//                                  account-export --in acc.json)`.
//                * json          — print the input account JSON verbatim
//                                  (re-serialized with consistent shape).
//                                  Useful for inspection / re-parsing in a
//                                  different toolchain.
//                * backup-bundle — print a JSON envelope of the shape
//                                  { "seed_hex":      "<64 hex>",
//                                    "pubkey_hex":    "<64 hex>",
//                                    "anon_address":  "0x...",
//                                    "derived_at_utc":"YYYY-MM-DDTHH:MM:SSZ" }
//                                  ready to feed into `backup-create --secret
//                                  <seed_hex>` (the seed_hex field is the
//                                  required parameter for that CLI). The
//                                  envelope is plaintext — actual AEAD
//                                  wrapping requires a passphrase and lives
//                                  in backup-create.
//   --out <file>: optional. If set, writes the chosen format to file with
//                 0600 permissions (best-effort on Windows; NTFS ACL).
//                 Refuses overwrite without --force. Parent dir must exist.
//   --force:      required to overwrite an existing --out.
//   --json:       when set together with --format raw-hex, additionally
//                 wraps the hex in a {"privkey_hex": "..."} JSON object
//                 for parsing convenience. Ignored if --format is json or
//                 backup-bundle (those formats are already JSON). Ignored
//                 if --out is set without --format raw-hex.
//
// Output emission (stdout vs --out, mirrors account-create-batch / -import):
//   default (no --out)  — emits format to stdout
//   --out <file>        — writes format to file (0600); stdout shows a
//                         one-line confirmation "exported <format>: <path>"
//   The privkey_hex (or the bundle containing it) lives in the file rather
//   than the terminal when --out is used, matching the wallet's existing
//   "secret material to file by default, terminal only when explicit"
//   convention.
//
// Exit codes:
//   0 = success
//   1 = argument / validation / I/O error (missing --in, bad format,
//       malformed account JSON, missing parent dir, file-exists no --force,
//       etc.)
int cmd_account_export(int argc, char** argv) {
    std::string in_path, format = "raw-hex", out_path;
    bool force    = false;
    bool json_out = false;
    bool format_set_explicitly = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"     && i + 1 < argc) in_path  = argv[++i];
        else if (a == "--format" && i + 1 < argc) {
            format = argv[++i];
            format_set_explicitly = true;
        }
        else if (a == "--out"    && i + 1 < argc) out_path = argv[++i];
        else if (a == "--force")                  force    = true;
        else if (a == "--json")                   json_out = true;
        else {
            std::cerr << "account-export: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet account-export --in <file> "
                         "[--format raw-hex|json|backup-bundle] "
                         "[--out <file>] [--force] [--json]\n";
            return 1;
        }
    }
    if (in_path.empty()) {
        std::cerr << "account-export: --in is required (path to a "
                     "single-account JSON file)\n";
        std::cerr << "Usage: determ-wallet account-export --in <file> "
                     "[--format raw-hex|json|backup-bundle] "
                     "[--out <file>] [--force] [--json]\n";
        return 1;
    }
    // Validate --format up front so we don't read the input file just to
    // reject a typo'd format. Suppress this check for the silent default
    // so the diagnostic actually fires when format_set_explicitly is true.
    if (format != "raw-hex" && format != "json" && format != "backup-bundle") {
        std::cerr << "account-export: --format must be one of "
                     "{raw-hex, json, backup-bundle}; got '"
                  << format << "'\n";
        (void)format_set_explicitly;
        return 1;
    }

    // ── Read + parse the input account file ─────────────────────────────────
    // File-level failures (missing, unreadable) and structural failures
    // (bad JSON, missing required keys) both exit 1. We don't split into
    // 1/2 here because account-export is a passive transform — operators
    // pointing it at the wrong file get the same "fix your input" feedback
    // either way.
    std::ifstream in_f(in_path);
    if (!in_f) {
        std::cerr << "account-export: cannot open --in: " << in_path << "\n";
        return 1;
    }
    nlohmann::json acc_doc;
    try {
        in_f >> acc_doc;
    } catch (std::exception& e) {
        std::cerr << "account-export: --in is not valid JSON: "
                  << e.what() << "\n";
        return 1;
    }
    if (!acc_doc.is_object()) {
        std::cerr << "account-export: --in must be a JSON object "
                     "{\"address\":..., \"privkey_hex\":...}; got non-object\n";
        return 1;
    }
    if (!acc_doc.contains("address") || !acc_doc["address"].is_string()) {
        std::cerr << "account-export: --in missing required string field "
                     "'address'\n";
        return 1;
    }
    if (!acc_doc.contains("privkey_hex")
        || !acc_doc["privkey_hex"].is_string()) {
        std::cerr << "account-export: --in missing required string field "
                     "'privkey_hex'\n";
        return 1;
    }
    std::string address     = acc_doc["address"].get<std::string>();
    std::string privkey_hex = acc_doc["privkey_hex"].get<std::string>();

    // ── Validate shape: address is 0x + 64 lowercase hex; privkey is 64 hex ─
    // We deliberately accept exactly the canonical wallet shape here. If a
    // future format adds longer or shorter forms, those callers should round-
    // trip through account-import (which already supports the 128-hex form)
    // before export.
    if (address.size() != 66 || address.substr(0, 2) != "0x") {
        std::cerr << "account-export: 'address' must be \"0x\" + 64 hex "
                     "chars; got length " << address.size() << "\n";
        return 1;
    }
    try { (void)from_hex(address.substr(2)); }
    catch (std::exception& e) {
        std::cerr << "account-export: 'address' hex body is not valid hex: "
                  << e.what() << "\n";
        return 1;
    }
    if (privkey_hex.size() != 64) {
        std::cerr << "account-export: 'privkey_hex' must be 64 hex chars "
                     "(32-byte seed); got length " << privkey_hex.size()
                  << "\n";
        return 1;
    }
    std::vector<uint8_t> priv_bytes;
    try { priv_bytes = from_hex(privkey_hex); }
    catch (std::exception& e) {
        std::cerr << "account-export: 'privkey_hex' is not valid hex: "
                  << e.what() << "\n";
        return 1;
    }
    if (priv_bytes.size() != 32) {
        std::cerr << "account-export: 'privkey_hex' decoded length must be "
                     "32; got " << priv_bytes.size() << "\n";
        return 1;
    }

    // ── --out preconditions ─────────────────────────────────────────────────
    // Mirrors account-create-batch / account-import: parent dir must exist;
    // destination must not exist unless --force. Surfaced before any output
    // serialization so a misconfigured operator gets feedback fast.
    if (!out_path.empty()) {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "account-export: --out parent directory does not "
                         "exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "account-export: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Build the output payload per --format ───────────────────────────────
    // raw-hex:        plain 64-char hex (optionally JSON-wrapped if --json)
    // json:           passthrough — re-serialize the input account JSON
    // backup-bundle:  {seed_hex, pubkey_hex, anon_address, derived_at_utc}
    //                 ready for `backup-create --secret <seed_hex>`
    std::string payload;
    if (format == "raw-hex") {
        if (json_out) {
            nlohmann::json doc = { {"privkey_hex", privkey_hex} };
            payload = doc.dump();
        } else {
            payload = privkey_hex;
        }
    } else if (format == "json") {
        // Passthrough — but emit with a deterministic key order so
        // downstream diffs and round-trip tests are stable. nlohmann/json's
        // default ordering is lexicographic for std::map-backed objects.
        payload = acc_doc.dump(2);
    } else {
        // backup-bundle: derive an ISO-8601 UTC timestamp + emit the
        // envelope-ready JSON. The seed_hex field is named to match
        // backup-create's --secret <hex> input (which accepts the privkey
        // seed verbatim).
        // pubkey_hex is the address minus the "0x" prefix; we already
        // validated it as 64 lowercase hex above.
        std::string pubkey_hex = address.substr(2);

        // ISO 8601 UTC. Use gmtime_r/gmtime_s for thread-safety where
        // available; on MSVC the _s suffix is the canonical form, on
        // POSIX it's the _r suffix.
        auto now = std::time(nullptr);
        std::tm tm_buf{};
#ifdef _WIN32
        gmtime_s(&tm_buf, &now);
#else
        gmtime_r(&now, &tm_buf);
#endif
        char ts[32] = {};
        std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

        nlohmann::json bundle = {
            {"seed_hex",       privkey_hex},
            {"pubkey_hex",     pubkey_hex},
            {"anon_address",   address},
            {"derived_at_utc", std::string(ts)},
        };
        payload = bundle.dump(2);
    }

    // ── Dispatch on output destination ─────────────────────────────────────
    if (!out_path.empty()) {
        std::ofstream f(out_path);
        if (!f) {
            std::cerr << "account-export: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        f << payload;
        // raw-hex is single-line; the JSON formats already include their
        // own internal newlines from dump(2). Either way, always finish
        // the file with a trailing newline so POSIX tools don't complain.
        if (payload.empty() || payload.back() != '\n') f << "\n";
        f.close();
        if (!f) {
            std::cerr << "account-export: write failed on --out: "
                      << out_path << "\n";
            return 1;
        }
        // 0600 permissions — owner-only read/write. On Windows the
        // read/write bits are a no-op (NTFS ACL inherits from parent);
        // we ignore the error code as non-fatal there.
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
        std::cout << "exported " << format << ": " << out_path << "\n";
        return 0;
    }
    // stdout — payload + single trailing newline (raw-hex needs the LF for
    // shell-script ergonomics; the JSON formats look more natural with one
    // too).
    std::cout << payload;
    if (payload.empty() || payload.back() != '\n') std::cout << "\n";
    return 0;
}

// Diagnostic CLI: structural verification of a complete wallet backup
// (Shamir share-set + per-share AEAD envelopes) WITHOUT decrypting.
//
// A "backup" in the Determ wallet model is the combination of:
//   1. A Shamir share-set file (output of `shamir-split --json`):
//        {"shares": [{"x": int, "y_hex": "..."}, ...]}
//   2. A per-share AEAD envelopes file (one envelope per share, each
//      wrapped with a per-keyholder passphrase). No prior CLI emits this
//      composite, so this command defines the canonical shape:
//        {"envelopes": [{"share_index": int,
//                        "envelope_blob": "<canonical envelope blob>"},
//                       ...]}
//      `share_index` corresponds 1:1 to the Shamir share's `x` field;
//      `envelope_blob` is the dot-separated canonical form emitted by
//      `envelope encrypt` / serialize().
//
// Together the two files let any T-of-N keyholders decrypt their share
// (each with their own passphrase) and feed the resulting plaintext
// shares to `shamir-combine` for secret reconstruction. This CLI
// verifies the two files are STRUCTURALLY consistent (every share has
// a matching envelope, no duplicates, no gaps, every envelope blob
// deserializes and has sane metadata) — WITHOUT requiring any
// passphrase and WITHOUT performing AES-GCM.
//
// Use cases:
//   * Pre-distribution sanity check by the secret owner — confirm the
//     pair was written correctly before mailing physical copies.
//   * Pre-recovery validation by the coordinator — confirm the
//     recovered files are well-formed before convening T keyholders.
//   * Operator tooling — monitoring scripts that want backup health
//     in structured form (--json) without secret material.
//
// Verification checks (all structural; no AEAD, no Shamir recovery):
//   1. Both files parse as JSON.
//   2. Shares file has expected shape (mirrors shamir-verify checks:
//      object with non-empty "shares" array; each entry has int x in
//      [1, 255] and hex y_hex with consistent even length).
//   3. Envelopes file has expected shape (object with "envelopes" array;
//      each entry has int share_index in [1, 255] and string envelope_blob).
//   4. share_count == envelope_count.
//   5. Share x-values match envelope share_index values 1:1 (no
//      duplicates, no gaps, full bijection).
//   6. Each envelope_blob deserializes via envelope::deserialize.
//   7. Each envelope's metadata is structurally valid:
//      PBKDF2 iters > 0, salt non-empty, nonce exactly 12B,
//      ciphertext >= 16B (so the GCM tag fits).
//   8. If --threshold T is supplied: also report whether share count
//      >= T (informational; insufficient share count is NOT a
//      structural error — same convention as shamir-verify).
//
// Exit codes:
//   0  structurally valid (and threshold met if --threshold supplied)
//   1  bad args / missing file / JSON parse error
//   2  structurally invalid (operator alert gate — any of checks 2-7 failed)
//
// Insufficient-share-count when --threshold is supplied returns 0
// (informational), matching shamir-verify's convention.
int cmd_backup_verify(int argc, char** argv) {
    std::string shares_path, envelopes_path;
    int threshold = -1;       // -1 sentinel = not supplied
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--shares"    && i + 1 < argc) shares_path    = argv[++i];
        else if (a == "--envelopes" && i + 1 < argc) envelopes_path = argv[++i];
        else if (a == "--threshold" && i + 1 < argc) threshold      = std::stoi(argv[++i]);
        else if (a == "--json")                       json_out       = true;
    }
    if (shares_path.empty() || envelopes_path.empty()) {
        std::cerr << "Usage: determ-wallet backup-verify "
                     "--shares <file> --envelopes <file> "
                     "[--threshold T] [--json]\n"
                     "\n"
                     "  Verifies structural integrity of a complete wallet backup\n"
                     "  (Shamir shares + per-share AEAD envelopes) without decrypting.\n"
                     "\n"
                     "  Shares file shape:    {\"shares\":    [{\"x\": int, \"y_hex\": \"...\"}, ...]}\n"
                     "  Envelopes file shape: {\"envelopes\": [{\"share_index\": int, "
                     "\"envelope_blob\": \"...\"}, ...]}\n";
        return 1;
    }

    // Helper: structured error reporter. In --json mode emits the JSON
    // doc to stdout (so monitoring scripts see a complete result on
    // every invocation, success or fail); in human mode emits the
    // [FAIL] line to stderr.
    auto report_fail = [&](const std::string& reason,
                           const std::string& share_count_hint = "") {
        if (json_out) {
            nlohmann::json r;
            r["valid"]               = false;
            r["shares_file"]         = shares_path;
            r["envelopes_file"]      = envelopes_path;
            r["share_count"]         = 0;
            r["envelope_count"]      = 0;
            r["mapping_consistent"]  = false;
            r["envelope_details"]    = nlohmann::json::array();
            r["threshold_satisfied"] = nullptr;
            r["errors"]              = nlohmann::json::array({reason});
            std::cout << r.dump() << "\n";
        } else {
            std::cerr << "[FAIL] " << reason << "\n";
        }
        (void)share_count_hint;
    };

    // ── Load + parse the shares file ────────────────────────────────────
    std::ifstream sf(shares_path);
    if (!sf) {
        if (json_out) {
            nlohmann::json r;
            r["valid"]  = false;
            r["errors"] = nlohmann::json::array(
                {std::string("cannot open --shares file: ") + shares_path});
            std::cout << r.dump() << "\n";
        } else {
            std::cerr << "backup-verify: cannot open --shares file: "
                      << shares_path << "\n";
        }
        return 1;
    }
    std::string shares_blob((std::istreambuf_iterator<char>(sf)),
                              std::istreambuf_iterator<char>());
    nlohmann::json sj;
    try { sj = nlohmann::json::parse(shares_blob); }
    catch (std::exception& e) {
        if (json_out) {
            nlohmann::json r;
            r["valid"]  = false;
            r["errors"] = nlohmann::json::array(
                {std::string("shares JSON parse error: ") + e.what()});
            std::cout << r.dump() << "\n";
        } else {
            std::cerr << "backup-verify: shares JSON parse failed: "
                      << e.what() << "\n";
        }
        return 1;
    }

    // ── Load + parse the envelopes file ─────────────────────────────────
    std::ifstream ef(envelopes_path);
    if (!ef) {
        if (json_out) {
            nlohmann::json r;
            r["valid"]  = false;
            r["errors"] = nlohmann::json::array(
                {std::string("cannot open --envelopes file: ") + envelopes_path});
            std::cout << r.dump() << "\n";
        } else {
            std::cerr << "backup-verify: cannot open --envelopes file: "
                      << envelopes_path << "\n";
        }
        return 1;
    }
    std::string envs_blob((std::istreambuf_iterator<char>(ef)),
                            std::istreambuf_iterator<char>());
    nlohmann::json ej;
    try { ej = nlohmann::json::parse(envs_blob); }
    catch (std::exception& e) {
        if (json_out) {
            nlohmann::json r;
            r["valid"]  = false;
            r["errors"] = nlohmann::json::array(
                {std::string("envelopes JSON parse error: ") + e.what()});
            std::cout << r.dump() << "\n";
        } else {
            std::cerr << "backup-verify: envelopes JSON parse failed: "
                      << e.what() << "\n";
        }
        return 1;
    }

    // ── Validate shares file shape ──────────────────────────────────────
    if (!sj.is_object() || !sj.contains("shares") || !sj["shares"].is_array()) {
        report_fail("shares file: top-level must be object with 'shares' array");
        return 2;
    }
    const auto& shares_arr = sj["shares"];
    if (shares_arr.empty()) {
        report_fail("shares file: 'shares' array is empty");
        return 2;
    }

    auto is_hex_char = [](char c) {
        return (c >= '0' && c <= '9')
            || (c >= 'a' && c <= 'f')
            || (c >= 'A' && c <= 'F');
    };

    std::set<int> share_x;
    int x_min = 256, x_max = -1;
    size_t y_byte_len = 0;
    for (size_t i = 0; i < shares_arr.size(); ++i) {
        const auto& el = shares_arr[i];
        if (!el.is_object()
            || !el.contains("x")     || !el["x"].is_number_integer()
            || !el.contains("y_hex") || !el["y_hex"].is_string()) {
            report_fail("shares file: share #" + std::to_string(i)
                        + " must have integer 'x' and string 'y_hex'");
            return 2;
        }
        int x = el["x"].get<int>();
        if (x < 1 || x > 255) {
            report_fail("shares file: share #" + std::to_string(i)
                        + ": x = " + std::to_string(x)
                        + " out of range [1, 255]");
            return 2;
        }
        if (!share_x.insert(x).second) {
            report_fail("shares file: duplicate x = " + std::to_string(x));
            return 2;
        }
        if (x < x_min) x_min = x;
        if (x > x_max) x_max = x;

        std::string y_hex = el["y_hex"].get<std::string>();
        if (y_hex.size() % 2 != 0) {
            report_fail("shares file: share x=" + std::to_string(x)
                        + ": y_hex has odd length");
            return 2;
        }
        for (char c : y_hex) {
            if (!is_hex_char(c)) {
                report_fail("shares file: share x=" + std::to_string(x)
                            + ": y_hex contains non-hex character");
                return 2;
            }
        }
        size_t this_y_len = y_hex.size() / 2;
        if (this_y_len == 0) {
            report_fail("shares file: share x=" + std::to_string(x)
                        + ": y_hex is empty");
            return 2;
        }
        if (y_byte_len == 0) y_byte_len = this_y_len;
        else if (this_y_len != y_byte_len) {
            report_fail("shares file: share x=" + std::to_string(x)
                        + ": y_hex length differs from first share");
            return 2;
        }
    }

    // ── Validate envelopes file shape ───────────────────────────────────
    if (!ej.is_object() || !ej.contains("envelopes") || !ej["envelopes"].is_array()) {
        report_fail("envelopes file: top-level must be object with 'envelopes' array");
        return 2;
    }
    const auto& env_arr = ej["envelopes"];
    if (env_arr.empty()) {
        report_fail("envelopes file: 'envelopes' array is empty");
        return 2;
    }

    // Parse each envelope entry; collect per-entry diagnostics for the
    // envelope_details JSON output.
    struct EnvDetail {
        int      share_index{0};
        uint32_t pbkdf2_iters{0};
        size_t   salt_len{0};
        size_t   nonce_len{0};
        size_t   aad_len{0};
        size_t   ct_len{0};
        bool     ok{false};
    };
    std::vector<EnvDetail> details;
    std::set<int> env_idx;
    for (size_t i = 0; i < env_arr.size(); ++i) {
        const auto& el = env_arr[i];
        if (!el.is_object()
            || !el.contains("share_index")
            || !el["share_index"].is_number_integer()
            || !el.contains("envelope_blob")
            || !el["envelope_blob"].is_string()) {
            report_fail("envelopes file: entry #" + std::to_string(i)
                        + " must have integer 'share_index' and string 'envelope_blob'");
            return 2;
        }
        int idx = el["share_index"].get<int>();
        if (idx < 1 || idx > 255) {
            report_fail("envelopes file: entry #" + std::to_string(i)
                        + ": share_index = " + std::to_string(idx)
                        + " out of range [1, 255]");
            return 2;
        }
        if (!env_idx.insert(idx).second) {
            report_fail("envelopes file: duplicate share_index = "
                        + std::to_string(idx));
            return 2;
        }
        std::string blob = el["envelope_blob"].get<std::string>();
        auto env_opt = envelope::deserialize(blob);
        if (!env_opt) {
            report_fail("envelopes file: entry share_index="
                        + std::to_string(idx)
                        + ": envelope_blob deserialize failed "
                        + "(bad magic, truncated, or non-hex content)");
            return 2;
        }
        const auto& env = *env_opt;
        // Per-envelope structural sanity checks. envelope::deserialize
        // already enforces salt >= 8B, nonce == 12B, ciphertext >= 16B,
        // but recheck here so the JSON output reports the actual values
        // and a future deserialize-relaxation doesn't silently bypass.
        if (env.pbkdf2_iters == 0) {
            report_fail("envelopes file: entry share_index="
                        + std::to_string(idx) + ": pbkdf2_iters is zero");
            return 2;
        }
        if (env.salt.empty()) {
            report_fail("envelopes file: entry share_index="
                        + std::to_string(idx) + ": salt is empty");
            return 2;
        }
        if (env.nonce.size() != 12) {
            report_fail("envelopes file: entry share_index="
                        + std::to_string(idx) + ": nonce is not 12 bytes");
            return 2;
        }
        if (env.ciphertext.size() < 16) {
            report_fail("envelopes file: entry share_index="
                        + std::to_string(idx)
                        + ": ciphertext too short to contain GCM tag");
            return 2;
        }
        details.push_back({idx, env.pbkdf2_iters,
                            env.salt.size(), env.nonce.size(),
                            env.aad.size(),  env.ciphertext.size(),
                            true});
    }

    // ── Cross-file consistency: counts + 1:1 index mapping ──────────────
    const int share_count    = static_cast<int>(shares_arr.size());
    const int envelope_count = static_cast<int>(env_arr.size());
    bool mapping_consistent = true;
    if (share_count != envelope_count) {
        report_fail("share count (" + std::to_string(share_count)
                    + ") != envelope count (" + std::to_string(envelope_count) + ")");
        return 2;
    }
    if (share_x != env_idx) {
        mapping_consistent = false;
        report_fail("share x-values do not match envelope share_index values 1:1 "
                    "(some shares lack an envelope, or vice versa)");
        return 2;
    }

    // Threshold tri-state: nullopt = not supplied, true = met,
    // false = supplied but insufficient. Insufficient is INFORMATIONAL
    // (exit 0), matching shamir-verify convention.
    std::optional<bool> threshold_satisfied;
    if (threshold >= 0) threshold_satisfied = (share_count >= threshold);

    // ── Emit result ─────────────────────────────────────────────────────
    if (json_out) {
        nlohmann::json r;
        r["valid"]              = true;
        r["shares_file"]        = shares_path;
        r["envelopes_file"]     = envelopes_path;
        r["share_count"]        = share_count;
        r["envelope_count"]     = envelope_count;
        r["mapping_consistent"] = mapping_consistent;
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& d : details) {
            arr.push_back({
                {"share_index",  d.share_index},
                {"pbkdf2_iters", d.pbkdf2_iters},
                {"salt_len",     d.salt_len},
                {"nonce_len",    d.nonce_len},
                {"aad_len",      d.aad_len},
                {"ciphertext_len", d.ct_len},
            });
        }
        r["envelope_details"] = std::move(arr);
        if (threshold_satisfied.has_value()) {
            r["threshold_satisfied"] = *threshold_satisfied;
        } else {
            r["threshold_satisfied"] = nullptr;
        }
        r["errors"] = nlohmann::json::array();
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "=== Wallet backup verification ===\n";
        std::cout << "Shares file:    " << shares_path
                  << " (" << share_count << " shares, x range "
                  << x_min << ".." << x_max << ")\n";
        std::cout << "Envelopes file: " << envelopes_path
                  << " (" << envelope_count << " envelopes)\n";
        std::cout << "Share-to-envelope mapping: [OK] 1:1 by share_index\n";
        std::cout << "Envelope structural integrity:\n";
        for (const auto& d : details) {
            std::cout << "  Envelope " << d.share_index
                      << ": PBKDF2=" << d.pbkdf2_iters
                      << ", salt="   << d.salt_len  << "B"
                      << ", nonce="  << d.nonce_len << "B"
                      << ", ct="     << d.ct_len    << "B [OK]\n";
        }
        std::cout << "[OK] Backup structurally valid ("
                  << envelope_count << " envelopes, threshold-ready)\n";
        if (threshold_satisfied.has_value()) {
            if (*threshold_satisfied) {
                std::cout << "[OK] Share count (" << share_count
                          << ") >= threshold (" << threshold
                          << ") -- sufficient for recovery\n";
            } else {
                std::cout << "[INFO] Share count (" << share_count
                          << ") < threshold (" << threshold
                          << ") -- insufficient for recovery\n";
            }
        }
    }
    return 0;
}

// Composite-backup CONSTRUCTOR (inverse of backup-verify).
//
// `backup-create` produces the two canonical backup artifacts in one call:
//   1. A Shamir share-set file (shape: {"shares": [{"x": int, "y_hex": "..."}, ...]},
//      identical to `shamir-split --json` output).
//   2. A per-share AEAD envelopes file (shape: {"envelopes": [{"share_index": int,
//      "envelope_blob": "<canonical dot-separated hex>"}, ...]}, identical to
//      the shape consumed by `backup-verify`).
//
// Inputs:
//   --secret <hex>:        hex-encoded secret (wallet seed, key, etc.)
//   --threshold <T>:       Shamir threshold (any T-of-N reconstructs)
//   --keyholders <file>:   JSON file
//                          {"keyholders": [{"share_index": int, "passphrase": "..."}, ...]}
//                          where N = length(keyholders).
//   --shares-out <file>:   destination for the shares file
//   --envelopes-out <file>:destination for the envelopes file
//   --force:               overwrite existing output files
//   --json:                emit a JSON summary instead of the human one-liner
//
// Validation:
//   * --secret hex valid + non-empty
//   * 1 <= T <= N <= 255
//   * keyholders.share_index values are distinct, all in [1, N], no gaps
//     (must be a permutation of {1..N})
//   * each keyholder.passphrase is non-empty
//   * output paths' parent directories must exist (no mkdirp); refusing to
//     overwrite without --force matches account-create-batch convention
//
// Process:
//   1. from_hex(--secret) → raw bytes
//   2. shamir::split(secret, T, N) → N shares with x = 1..N
//   3. For each share i: passphrase = keyholders[share_index == share.x].passphrase;
//      env = envelope::encrypt(plaintext = share.y, passphrase),
//      blob = envelope::serialize(env)
//   4. Write the shares file (atomic semantics — write then close before
//      writing the envelopes file, so a half-baked first file doesn't
//      mislead an observer about backup completeness)
//   5. Write the envelopes file
//   6. Emit summary
//
// Notes on share→keyholder pairing:
//   Each Shamir share's x-coordinate (1..N from shamir::split) is the
//   `share_index` used to look up the keyholder's passphrase. The
//   keyholders array doesn't need to be sorted in the input file — we
//   index by share_index, not by position. This matches the way
//   backup-verify treats envelope share_index as the bijection key.
//
// AAD note:
//   This CLI does NOT bind any AAD into the envelope (consistent with
//   `envelope encrypt --plaintext --password` invocations elsewhere in
//   the test fixtures). The OPAQUE-guarded recovery flow uses AAD
//   (recovery::create with version+index), but the operator-workflow
//   composite-backup case stays AAD-free so plain `envelope decrypt`
//   on the resulting blob round-trips without an --aad arg.
int cmd_backup_create(int argc, char** argv) {
    std::string secret_hex, keyholders_path, shares_out, envs_out;
    int threshold = -1;
    bool force = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--secret"        && i + 1 < argc) secret_hex      = argv[++i];
        else if (a == "--threshold"     && i + 1 < argc) {
            try { threshold = std::stoi(argv[++i]); }
            catch (std::exception&) {
                std::cerr << "backup-create: --threshold must be an integer\n";
                return 1;
            }
        }
        else if (a == "--keyholders"    && i + 1 < argc) keyholders_path = argv[++i];
        else if (a == "--shares-out"    && i + 1 < argc) shares_out      = argv[++i];
        else if (a == "--envelopes-out" && i + 1 < argc) envs_out        = argv[++i];
        else if (a == "--force")                         force           = true;
        else if (a == "--json")                          json_out        = true;
        else {
            std::cerr << "backup-create: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet backup-create --secret <hex> "
                         "--threshold T --keyholders <file> "
                         "--shares-out <file> --envelopes-out <file> "
                         "[--force] [--json]\n";
            return 1;
        }
    }
    if (secret_hex.empty() || threshold < 0 || keyholders_path.empty()
        || shares_out.empty() || envs_out.empty()) {
        std::cerr << "Usage: determ-wallet backup-create --secret <hex> "
                     "--threshold T --keyholders <file> "
                     "--shares-out <file> --envelopes-out <file> "
                     "[--force] [--json]\n"
                     "\n"
                     "  Produces a complete wallet backup (Shamir shares + per-share\n"
                     "  AEAD envelopes) from a secret + per-keyholder passphrases.\n"
                     "\n"
                     "  Keyholders file shape:\n"
                     "    {\"keyholders\": [{\"share_index\": int, \"passphrase\": \"...\"}, ...]}\n"
                     "  N (share count) is length(keyholders). 1 <= T <= N <= 255.\n";
        return 1;
    }

    // ── Decode --secret ─────────────────────────────────────────────────
    if (secret_hex.size() % 2 != 0) {
        std::cerr << "backup-create: --secret hex must have even length\n";
        return 1;
    }
    std::vector<uint8_t> secret;
    try { secret = from_hex(secret_hex); }
    catch (std::exception& e) {
        std::cerr << "backup-create: invalid --secret hex: " << e.what() << "\n";
        return 1;
    }
    if (secret.empty()) {
        std::cerr << "backup-create: --secret must be non-empty\n";
        return 1;
    }

    // ── Threshold sanity ─────────────────────────────────────────────────
    if (threshold < 1) {
        std::cerr << "backup-create: --threshold must be >= 1 (got "
                  << threshold << ")\n";
        return 1;
    }
    if (threshold > 255) {
        std::cerr << "backup-create: --threshold must be <= 255 (got "
                  << threshold << ")\n";
        return 1;
    }

    // ── Load + parse keyholders file ─────────────────────────────────────
    std::ifstream kf(keyholders_path);
    if (!kf) {
        std::cerr << "backup-create: cannot open --keyholders file: "
                  << keyholders_path << "\n";
        return 1;
    }
    std::string kh_blob((std::istreambuf_iterator<char>(kf)),
                          std::istreambuf_iterator<char>());
    nlohmann::json kj;
    try { kj = nlohmann::json::parse(kh_blob); }
    catch (std::exception& e) {
        std::cerr << "backup-create: keyholders JSON parse failed: "
                  << e.what() << "\n";
        return 1;
    }
    if (!kj.is_object() || !kj.contains("keyholders") || !kj["keyholders"].is_array()) {
        std::cerr << "backup-create: keyholders file must be an object with "
                     "'keyholders' array\n";
        return 1;
    }
    const auto& kh_arr = kj["keyholders"];
    if (kh_arr.empty()) {
        std::cerr << "backup-create: 'keyholders' array is empty\n";
        return 1;
    }
    if (kh_arr.size() > 255) {
        std::cerr << "backup-create: 'keyholders' array has "
                  << kh_arr.size() << " entries (max 255)\n";
        return 1;
    }
    const int share_count = static_cast<int>(kh_arr.size());
    if (threshold > share_count) {
        std::cerr << "backup-create: --threshold (" << threshold
                  << ") > keyholder count (" << share_count << ")\n";
        return 1;
    }

    // Build index → passphrase map. share_index must be a permutation of
    // {1..N} (no gaps, no duplicates, in [1,N]). This matches the
    // bijection that `shamir::split` produces (shares get x = 1..N) and
    // that `backup-verify` enforces post-hoc.
    std::vector<std::string> pw_by_index(share_count + 1);   // 1-indexed
    std::set<int> seen_idx;
    for (size_t i = 0; i < kh_arr.size(); ++i) {
        const auto& el = kh_arr[i];
        if (!el.is_object()
            || !el.contains("share_index")
            || !el["share_index"].is_number_integer()
            || !el.contains("passphrase")
            || !el["passphrase"].is_string()) {
            std::cerr << "backup-create: keyholders entry #" << i
                      << " must have integer 'share_index' and string "
                         "'passphrase'\n";
            return 1;
        }
        int idx = el["share_index"].get<int>();
        if (idx < 1 || idx > share_count) {
            std::cerr << "backup-create: keyholders entry #" << i
                      << ": share_index = " << idx
                      << " out of range [1, " << share_count << "]\n";
            return 1;
        }
        if (!seen_idx.insert(idx).second) {
            std::cerr << "backup-create: duplicate share_index = " << idx
                      << " in keyholders file\n";
            return 1;
        }
        std::string pw = el["passphrase"].get<std::string>();
        if (pw.empty()) {
            std::cerr << "backup-create: keyholders entry share_index="
                      << idx << ": passphrase is empty\n";
            return 1;
        }
        pw_by_index[idx] = std::move(pw);
    }
    // Bijection assertion: seen_idx == {1..N}. The duplicate check above
    // plus the [1,N] range bound + size N guarantees this; double-check
    // defensively to surface any future regression precisely.
    if (static_cast<int>(seen_idx.size()) != share_count) {
        std::cerr << "backup-create: share_index set is not "
                     "{1.." << share_count << "} "
                     "(missing or extra indices)\n";
        return 1;
    }

    // ── Output path preconditions ────────────────────────────────────────
    auto check_out_path = [&](const std::string& p,
                              const char* label) -> int {
        std::filesystem::path fp(p);
        auto parent = fp.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "backup-create: " << label
                      << " parent directory does not exist: "
                      << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(fp) && !force) {
            std::cerr << "backup-create: " << label << " file already exists: "
                      << p
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
        return 0;
    };
    if (int rc = check_out_path(shares_out, "--shares-out");      rc != 0) return rc;
    if (int rc = check_out_path(envs_out,   "--envelopes-out");   rc != 0) return rc;

    // Also reject pointing both outputs at the same file — silent
    // overwrite of the first by the second would be data loss with
    // zero diagnostic.
    if (std::filesystem::weakly_canonical(std::filesystem::path(shares_out))
        == std::filesystem::weakly_canonical(std::filesystem::path(envs_out))) {
        std::cerr << "backup-create: --shares-out and --envelopes-out "
                     "point at the same file\n";
        return 1;
    }

    // ── Shamir split ─────────────────────────────────────────────────────
    std::vector<shamir::Share> shares;
    try {
        shares = shamir::split(secret,
                                  static_cast<uint8_t>(threshold),
                                  static_cast<uint8_t>(share_count));
    } catch (std::exception& e) {
        std::cerr << "backup-create: shamir::split failed: "
                  << e.what() << "\n";
        return 1;
    }
    // shamir::split guarantees shares[i].x = i+1 (1..N), but rely only on
    // the documented invariant that x is in [1,N] and distinct; look up
    // the passphrase by share.x.

    // ── Per-share AEAD wrap ──────────────────────────────────────────────
    nlohmann::json envs_arr = nlohmann::json::array();
    nlohmann::json shares_arr = nlohmann::json::array();
    for (const auto& s : shares) {
        int idx = static_cast<int>(s.x);
        if (idx < 1 || idx > share_count || pw_by_index[idx].empty()) {
            std::cerr << "backup-create: internal: share x=" << idx
                      << " has no passphrase in keyholders map\n";
            return 1;
        }
        envelope::Envelope env;
        try {
            env = envelope::encrypt(s.y, pw_by_index[idx]);
        } catch (std::exception& e) {
            std::cerr << "backup-create: envelope::encrypt failed (x="
                      << idx << "): " << e.what() << "\n";
            return 1;
        }
        std::string blob = envelope::serialize(env);
        envs_arr.push_back({
            {"share_index",   idx},
            {"envelope_blob", blob},
        });
        shares_arr.push_back({
            {"x",     idx},
            {"y_hex", to_hex(s.y)},
        });
    }

    // ── Write shares file ────────────────────────────────────────────────
    {
        std::ofstream f(shares_out);
        if (!f) {
            std::cerr << "backup-create: cannot open --shares-out for write: "
                      << shares_out << "\n";
            return 1;
        }
        nlohmann::json doc;
        doc["shares"] = std::move(shares_arr);
        f << doc.dump() << "\n";
        if (!f) {
            std::cerr << "backup-create: write failed on --shares-out: "
                      << shares_out << "\n";
            return 1;
        }
    }
    // Owner-only perms on POSIX; no-op on Windows (NTFS ACL inherits).
    {
        std::error_code perm_ec;
        std::filesystem::permissions(
            shares_out,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
    }

    // ── Write envelopes file ─────────────────────────────────────────────
    {
        std::ofstream f(envs_out);
        if (!f) {
            std::cerr << "backup-create: cannot open --envelopes-out for write: "
                      << envs_out << "\n";
            return 1;
        }
        nlohmann::json doc;
        doc["envelopes"] = std::move(envs_arr);
        f << doc.dump() << "\n";
        if (!f) {
            std::cerr << "backup-create: write failed on --envelopes-out: "
                      << envs_out << "\n";
            return 1;
        }
    }
    {
        std::error_code perm_ec;
        std::filesystem::permissions(
            envs_out,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
    }

    // ── Summary ──────────────────────────────────────────────────────────
    if (json_out) {
        nlohmann::json r;
        r["share_count"]    = share_count;
        r["threshold"]      = threshold;
        r["shares_file"]    = shares_out;
        r["envelopes_file"] = envs_out;
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "wrote " << share_count << " shares + "
                  << share_count << " envelopes (threshold "
                  << threshold << ")\n";
    }
    return 0;
}

// ── keyfile-create — S-004 encrypted node_key.json producer ────────────────
//
// `determ` daemon supports loading both plaintext and passphrase-encrypted
// node_key.json files (the latter closes S-004: validator private key
// exposed at rest). This CLI is the operator-side workflow for producing
// the encrypted form OFFLINE on a wallet host that doesn't share an
// address space with the networked daemon.
//
// Inputs:
//   --priv <hex>          : Ed25519 seed (32 B = 64 hex) OR full keypair
//                            (64 B = 128 hex: 32 seed || 32 pub). Both
//                            accepted; the pubkey is derived/verified.
//   --passphrase-from src : `file:<path>` — first line of file
//                           `env:<VARNAME>` — environment variable
//                           `prompt` — interactive stdin no-echo prompt
//   --out <file>          : output path (refuses overwrite without --force)
//   [--force]             : permit overwriting an existing --out file
//   [--json]              : emit a structured summary on stdout
//
// Canonical encrypted-keyfile shape (mirrors `determ account create
// --passphrase` from src/main.cpp::cmd_account_create — established
// precedent for envelope-wrapped key files):
//
//   line 1: "DETERM-NODE-V1 <pubkey_hex>\n"
//   line 2: "<envelope_blob>\n"
//
//   <pubkey_hex>   = 64-char lowercase hex of the Ed25519 public key.
//                    Stored in plaintext so operators can identify which
//                    validator the file belongs to without decrypting.
//                    Also bound into the envelope AAD as a tamper-evident
//                    anchor — substituting another validator's encrypted
//                    blob under the same passphrase will fail GCM tag
//                    verification.
//   <envelope_blob> = canonical DWE1 envelope serialization (dot-separated
//                     lowercase hex; see wallet/envelope.hpp). The
//                     plaintext inside the envelope is the same JSON the
//                     daemon's plaintext load path consumes:
//                       {"pubkey": "<hex>", "priv_seed": "<hex>"}
//                     which matches src/crypto/keys.cpp::load_node_key
//                     byte-for-byte (S-018 field validation applies).
//   AAD            = pubkey_hex bytes (ASCII, lowercase, 64 bytes).
//
// File permissions: best-effort 0600 (owner read+write only). On Unix
// this is a real chmod via std::filesystem::permissions; on Windows the
// call resolves to a best-effort owner-only ACL.
//
// Round-trip note: the test wrapper exercises decrypt via the wallet's
// own `envelope decrypt` CLI (the same envelope library the daemon's
// encrypted-keyfile load path uses), so the entire produce→consume loop
// is verified without touching `src/`.

// passphrase_from_source — read the operator passphrase per --passphrase-from.
//
// Supported source specifiers:
//   "file:<path>"  — first line of the file (newline-stripped). Empty
//                    file or empty first line is rejected. Convenient
//                    for ops scripts: the passphrase lives in a
//                    permission-restricted file, not on the CLI.
//   "env:<NAME>"   — value of environment variable <NAME>. Empty value
//                    is rejected. Variable must be exported in the
//                    shell environment.
//   "prompt"       — interactive read from stdin with terminal echo
//                    disabled (best-effort: Windows + POSIX termios).
//                    Falls back to plain getline if no tty / no termios
//                    available.
//
// Returns the passphrase on success; sets `err` and returns empty on
// failure. Caller surfaces `err` on stderr.
std::string passphrase_from_source(const std::string& spec, std::string& err) {
    err.clear();
    if (spec.empty()) {
        err = "passphrase source is empty";
        return "";
    }
    if (spec.rfind("file:", 0) == 0) {
        std::string path = spec.substr(5);
        if (path.empty()) { err = "file: source has empty path"; return ""; }
        std::ifstream f(path);
        if (!f) {
            err = "cannot open passphrase file: " + path;
            return "";
        }
        std::string line;
        if (!std::getline(f, line)) {
            err = "passphrase file is empty: " + path;
            return "";
        }
        // Strip trailing CR (Windows-style line endings) but preserve
        // intentional internal whitespace — the operator may have
        // chosen a passphrase containing spaces.
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        if (line.empty()) {
            err = "passphrase file first line is empty: " + path;
            return "";
        }
        return line;
    }
    if (spec.rfind("env:", 0) == 0) {
        std::string name = spec.substr(4);
        if (name.empty()) { err = "env: source has empty variable name"; return ""; }
        const char* v = std::getenv(name.c_str());
        if (!v || !*v) {
            err = "environment variable not set or empty: " + name;
            return "";
        }
        return std::string(v);
    }
    if (spec == "prompt") {
        // Interactive no-echo read. Best-effort across platforms; if
        // disabling echo fails we still read the line (operator may be
        // running in a non-tty context — they're warned via stderr).
        std::cerr << "Passphrase: " << std::flush;
#ifdef _WIN32
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        DWORD orig = 0;
        bool echo_off = (hStdin != INVALID_HANDLE_VALUE
                         && GetConsoleMode(hStdin, &orig)
                         && SetConsoleMode(hStdin, orig & ~ENABLE_ECHO_INPUT));
        std::string pw;
        std::getline(std::cin, pw);
        if (echo_off) SetConsoleMode(hStdin, orig);
        std::cerr << "\n";
        if (pw.empty()) { err = "empty passphrase from prompt"; return ""; }
        return pw;
#else
        termios old_t{}, new_t{};
        bool echo_off = (tcgetattr(STDIN_FILENO, &old_t) == 0);
        if (echo_off) {
            new_t = old_t;
            new_t.c_lflag &= ~ECHO;
            if (tcsetattr(STDIN_FILENO, TCSANOW, &new_t) != 0) echo_off = false;
        }
        std::string pw;
        std::getline(std::cin, pw);
        if (echo_off) tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
        std::cerr << "\n";
        if (pw.empty()) { err = "empty passphrase from prompt"; return ""; }
        return pw;
#endif
    }
    err = "unknown passphrase source '" + spec
        + "'; expected file:<path>, env:<NAME>, or prompt";
    return "";
}

int cmd_keyfile_create(int argc, char** argv) {
    std::string priv_hex, pass_src, out_path;
    bool force = false;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--priv"            && i + 1 < argc) priv_hex = argv[++i];
        else if (a == "--passphrase-from" && i + 1 < argc) pass_src = argv[++i];
        else if (a == "--out"             && i + 1 < argc) out_path = argv[++i];
        else if (a == "--force")                           force    = true;
        else if (a == "--json")                            json_out = true;
        else {
            std::cerr << "keyfile-create: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet keyfile-create --priv <hex> "
                         "--passphrase-from <file:path|env:NAME|prompt> "
                         "--out <file> [--force] [--json]\n";
            return 1;
        }
    }
    if (priv_hex.empty() || pass_src.empty() || out_path.empty()) {
        std::cerr << "Usage: determ-wallet keyfile-create --priv <hex> "
                     "--passphrase-from <file:path|env:NAME|prompt> "
                     "--out <file> [--force] [--json]\n";
        return 1;
    }

    // ── Validate --priv length (must be 32 B seed or 64 B keypair) ──────────
    if (priv_hex.size() != 64 && priv_hex.size() != 128) {
        std::cerr << "keyfile-create: --priv must be 64 hex chars (32-byte seed) "
                     "or 128 hex chars (32-byte seed || 32-byte pubkey); got "
                  << priv_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> priv_bytes;
    try { priv_bytes = from_hex(priv_hex); }
    catch (std::exception& e) {
        std::cerr << "keyfile-create: invalid --priv hex: " << e.what() << "\n";
        return 1;
    }
    if (priv_bytes.size() != 32 && priv_bytes.size() != 64) {
        // Belt-and-suspenders; the size check above already covered this.
        std::cerr << "keyfile-create: --priv decoded length must be 32 or 64; "
                     "got " << priv_bytes.size() << "\n";
        return 1;
    }

    // ── Derive / verify pubkey from seed ────────────────────────────────────
    // Ed25519 layout: the 32-byte seed deterministically derives the
    // 32-byte public key. If the operator passed a 64-byte form, we
    // still derive from the seed and verify the supplied pubkey
    // matches — a mismatch is almost always operator error (mixed up
    // two key pairs).
    std::array<uint8_t, 32> seed{};
    std::memcpy(seed.data(), priv_bytes.data(), 32);
    std::array<uint8_t, 32> derived_pub{};
    {
        EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, nullptr, seed.data(), 32);
        if (!pkey) {
            std::cerr << "keyfile-create: EVP_PKEY_new_raw_private_key failed "
                         "(seed not a valid Ed25519 private key)\n";
            return 1;
        }
        size_t pub_len = derived_pub.size();
        if (EVP_PKEY_get_raw_public_key(pkey, derived_pub.data(), &pub_len) <= 0
            || pub_len != 32) {
            EVP_PKEY_free(pkey);
            std::cerr << "keyfile-create: EVP_PKEY_get_raw_public_key failed\n";
            return 1;
        }
        EVP_PKEY_free(pkey);
    }
    if (priv_bytes.size() == 64) {
        std::array<uint8_t, 32> supplied_pub{};
        std::memcpy(supplied_pub.data(), priv_bytes.data() + 32, 32);
        if (supplied_pub != derived_pub) {
            std::cerr << "keyfile-create: --priv mismatch: 64-byte form's tail "
                         "32 bytes don't match the pubkey derived from the "
                         "seed (operator likely concatenated the wrong "
                         "pubkey)\n";
            return 1;
        }
    }
    std::string pubkey_hex   = to_hex(derived_pub);
    std::string priv_seed_hex = to_hex(seed);

    // ── Read passphrase from configured source ──────────────────────────────
    std::string err;
    std::string passphrase = passphrase_from_source(pass_src, err);
    if (passphrase.empty()) {
        std::cerr << "keyfile-create: " << err << "\n";
        return 1;
    }

    // ── --out preconditions: parent dir exists; file absent (or --force) ────
    {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "keyfile-create: --out parent directory does not "
                         "exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "keyfile-create: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Build the canonical keyfile JSON (plaintext-inside-envelope) ────────
    // Matches src/crypto/keys.cpp::load_node_key exactly: top-level
    // object with `pubkey` (64-hex) and `priv_seed` (64-hex) string
    // fields. Both are required + S-018 length-validated by the daemon.
    nlohmann::json keyfile_json = {
        {"pubkey",    pubkey_hex},
        {"priv_seed", priv_seed_hex}
    };
    std::string pt_str = keyfile_json.dump(2);
    std::vector<uint8_t> pt_bytes(pt_str.begin(), pt_str.end());

    // AAD = ASCII bytes of pubkey hex. Binds the envelope to this
    // validator's public key — a tampered envelope substituted from
    // another validator (same passphrase) will fail GCM tag verification.
    std::vector<uint8_t> aad(pubkey_hex.begin(), pubkey_hex.end());

    // ── Encrypt + write the canonical 2-line file ───────────────────────────
    std::string blob;
    try {
        auto env  = envelope::encrypt(pt_bytes, passphrase, aad);
        blob      = envelope::serialize(env);
    } catch (std::exception& e) {
        std::cerr << "keyfile-create: envelope encrypt failed: "
                  << e.what() << "\n";
        return 1;
    }

    // ── Self-test round-trip: decrypt the freshly-written envelope ──────────
    // Catches any drift between encrypt + decrypt paths before the
    // operator ships the file. Cheap belt-and-suspenders: a wrong
    // passphrase / corrupted blob fails here BEFORE we touch --out.
    {
        auto roundtrip_env = envelope::deserialize(blob);
        if (!roundtrip_env) {
            std::cerr << "keyfile-create: internal: just-emitted envelope "
                         "blob fails deserialize\n";
            return 1;
        }
        auto rt_pt = envelope::decrypt(*roundtrip_env, passphrase, aad);
        if (!rt_pt) {
            std::cerr << "keyfile-create: internal: just-emitted envelope "
                         "fails decrypt round-trip\n";
            return 1;
        }
        if (*rt_pt != pt_bytes) {
            std::cerr << "keyfile-create: internal: round-trip plaintext "
                         "mismatch\n";
            return 1;
        }
    }

    {
        std::ofstream f(out_path);
        if (!f) {
            std::cerr << "keyfile-create: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        f << "DETERM-NODE-V1 " << pubkey_hex << "\n";
        f << blob << "\n";
        f.close();
        if (!f) {
            std::cerr << "keyfile-create: write failed on --out: "
                      << out_path << "\n";
            return 1;
        }
    }

    // 0600 permissions tightening — best-effort on Windows.
    {
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
    }

    if (json_out) {
        nlohmann::json r;
        r["pubkey"]      = pubkey_hex;
        r["out"]         = out_path;
        r["format"]      = "DETERM-NODE-V1";
        r["envelope"]    = "DWE1";
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "wrote encrypted node keyfile to " << out_path << "\n";
        std::cout << "  pubkey: " << pubkey_hex << "\n";
        std::cout << "  format: DETERM-NODE-V1 (header) + DWE1 envelope\n";
    }
    return 0;
}

// ── keyfile-decrypt — S-004 encrypted node_key.json reverse path ───────────
//
// Inverse of `cmd_keyfile_create`. Operator workflow for one-shot offline
// operations: migrate an encrypted validator key to a different node,
// recover from a passphrase-protected backup, or debug a key that the
// daemon refuses to load. The daemon itself supports loading the
// encrypted form directly at runtime — this CLI exists for the cases
// where the plaintext form is required (e.g., reviewing the key
// material, exporting to a different runtime, key-archive workflow).
//
// Inputs:
//   --in <file>           : encrypted keyfile produced by keyfile-create.
//                           Canonical 2-line format:
//                              line 1: "DETERM-NODE-V1 <pubkey_hex>\n"
//                              line 2: "<DWE1 envelope blob>\n"
//   --passphrase-from src : same as keyfile-create — `file:<path>`,
//                           `env:<NAME>`, or `prompt` (no-echo interactive)
//   --out <file>          : output path for the plaintext node_key.json.
//                           Daemon loader: src/crypto/keys.cpp::load_node_key
//   [--force]             : permit overwriting an existing --out file
//   [--json]              : emit a structured summary on stdout
//
// Process:
//   1. Read --in; parse the 2-line canonical format (header + blob).
//   2. Resolve --passphrase-from to passphrase bytes.
//   3. envelope::decrypt(blob, passphrase, aad=pubkey_hex_bytes).
//      AAD binding from keyfile-create ensures the envelope is bound to
//      the validator pubkey — tampering with the header line (e.g.,
//      substituting another validator's pubkey) breaks AEAD verification.
//   4. Parse decrypted plaintext as {"pubkey": "<hex>", "priv_seed": "<hex>"}.
//   5. Verify inner pubkey matches header pubkey (defense-in-depth — they
//      must match by construction; mismatch indicates a corrupted file
//      or a deliberately-malformed keyfile produced outside the canonical
//      keyfile-create path).
//   6. Write a canonical plaintext node_key.json matching
//      src/crypto/keys.cpp::save_node_key byte-for-byte (j.dump(2)).
//   7. Apply 0600 owner-only permissions (best-effort).
//
// Diagnostic policy:
//   * Wrong passphrase OR tampered envelope OR mismatched AAD →
//     **exit 2** with a single "wrong passphrase or corrupted keyfile"
//     diagnostic. We deliberately do NOT distinguish these cases on
//     stderr — an attacker probing with various passphrases must not
//     be able to distinguish "your passphrase is wrong" from "the file
//     I gave you is malformed". They are indistinguishable to a
//     plaintext-recovering oracle.
//   * Structural problems with the --in file (wrong header magic,
//     malformed blob, unparseable plaintext JSON, mismatched pubkey
//     after decrypt) → **exit 1** with a specific diagnostic.
//     Distinguishing these is fine because they don't depend on
//     passphrase knowledge: an attacker who already has the file
//     can see them locally.
int cmd_keyfile_decrypt(int argc, char** argv) {
    std::string in_path, pass_src, out_path;
    bool force = false;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"              && i + 1 < argc) in_path  = argv[++i];
        else if (a == "--passphrase-from" && i + 1 < argc) pass_src = argv[++i];
        else if (a == "--out"             && i + 1 < argc) out_path = argv[++i];
        else if (a == "--force")                           force    = true;
        else if (a == "--json")                            json_out = true;
        else {
            std::cerr << "keyfile-decrypt: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet keyfile-decrypt --in <file> "
                         "--passphrase-from <file:path|env:NAME|prompt> "
                         "--out <file> [--force] [--json]\n";
            return 1;
        }
    }
    if (in_path.empty() || pass_src.empty() || out_path.empty()) {
        std::cerr << "Usage: determ-wallet keyfile-decrypt --in <file> "
                     "--passphrase-from <file:path|env:NAME|prompt> "
                     "--out <file> [--force] [--json]\n";
        return 1;
    }

    // ── Read --in and parse the canonical 2-line format ────────────────────
    std::string header_line, blob_line;
    {
        std::ifstream f(in_path);
        if (!f) {
            std::cerr << "keyfile-decrypt: cannot open --in: " << in_path << "\n";
            return 1;
        }
        if (!std::getline(f, header_line)) {
            std::cerr << "keyfile-decrypt: --in is empty: " << in_path << "\n";
            return 1;
        }
        if (!std::getline(f, blob_line)) {
            std::cerr << "keyfile-decrypt: --in is missing the envelope-blob "
                         "line (expected 2-line format: header + blob): "
                      << in_path << "\n";
            return 1;
        }
        // Strip trailing CR (Windows-style line endings) for portability.
        while (!header_line.empty()
               && (header_line.back() == '\r' || header_line.back() == '\n'))
            header_line.pop_back();
        while (!blob_line.empty()
               && (blob_line.back() == '\r' || blob_line.back() == '\n'))
            blob_line.pop_back();
    }

    // Header shape: "DETERM-NODE-V1 <pubkey_hex>"
    const std::string header_magic = "DETERM-NODE-V1 ";
    if (header_line.rfind(header_magic, 0) != 0) {
        std::cerr << "keyfile-decrypt: --in header does not start with "
                     "'DETERM-NODE-V1 ' (not a canonical encrypted node "
                     "keyfile)\n";
        return 1;
    }
    std::string header_pubkey_hex = header_line.substr(header_magic.size());
    if (header_pubkey_hex.size() != 64) {
        std::cerr << "keyfile-decrypt: --in header pubkey must be 64 hex "
                     "chars (32-byte Ed25519 pubkey); got "
                  << header_pubkey_hex.size() << "\n";
        return 1;
    }
    // Validate the header pubkey is well-formed hex. Done before passphrase
    // read so a structurally-broken file fails fast without prompting.
    try { (void)from_hex(header_pubkey_hex); }
    catch (std::exception& e) {
        std::cerr << "keyfile-decrypt: --in header pubkey is not valid hex: "
                  << e.what() << "\n";
        return 1;
    }
    if (blob_line.empty()) {
        std::cerr << "keyfile-decrypt: --in envelope blob line is empty\n";
        return 1;
    }

    // ── Read passphrase ────────────────────────────────────────────────────
    std::string err;
    std::string passphrase = passphrase_from_source(pass_src, err);
    if (passphrase.empty()) {
        std::cerr << "keyfile-decrypt: " << err << "\n";
        return 1;
    }

    // ── --out preconditions ────────────────────────────────────────────────
    {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "keyfile-decrypt: --out parent directory does not "
                         "exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "keyfile-decrypt: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Deserialize envelope blob ──────────────────────────────────────────
    // A blob that fails to deserialize is a structural problem with the
    // --in file — exit 1 with a specific diagnostic. Distinguishing from
    // wrong-passphrase here is fine because it doesn't depend on
    // passphrase knowledge.
    auto env_opt = envelope::deserialize(blob_line);
    if (!env_opt) {
        std::cerr << "keyfile-decrypt: --in envelope blob is malformed "
                     "(not a valid DWE1 serialization)\n";
        return 1;
    }

    // ── Decrypt with pubkey_hex as AAD ─────────────────────────────────────
    // AAD binding: keyfile-create binds the header pubkey into the GCM
    // AAD. Any tampering with the header pubkey (or substitution of an
    // envelope from a different validator) breaks AEAD verification
    // here — same exit code / diagnostic as wrong passphrase, so an
    // attacker cannot distinguish.
    std::vector<uint8_t> aad(header_pubkey_hex.begin(), header_pubkey_hex.end());
    auto pt_opt = envelope::decrypt(*env_opt, passphrase, aad);
    if (!pt_opt) {
        std::cerr << "keyfile-decrypt: wrong passphrase or corrupted "
                     "keyfile\n";
        return 2;
    }
    std::string pt_str(pt_opt->begin(), pt_opt->end());

    // ── Parse decrypted plaintext as canonical node_key JSON ───────────────
    // The decrypted plaintext is the same {"pubkey","priv_seed"} JSON the
    // daemon's load_node_key path consumes. Bad JSON here is a structural
    // problem (caller used keyfile-decrypt on a non-keyfile-create envelope)
    // — exit 1 with a specific diagnostic.
    nlohmann::json keyfile_json;
    try {
        keyfile_json = nlohmann::json::parse(pt_str);
    } catch (std::exception& e) {
        std::cerr << "keyfile-decrypt: decrypted plaintext is not valid JSON "
                     "(this is not a canonical encrypted node keyfile): "
                  << e.what() << "\n";
        return 1;
    }
    if (!keyfile_json.is_object()
        || !keyfile_json.contains("pubkey")
        || !keyfile_json.contains("priv_seed")
        || !keyfile_json["pubkey"].is_string()
        || !keyfile_json["priv_seed"].is_string()) {
        std::cerr << "keyfile-decrypt: decrypted plaintext is missing the "
                     "required 'pubkey' / 'priv_seed' string fields\n";
        return 1;
    }
    std::string inner_pubkey_hex = keyfile_json["pubkey"].get<std::string>();
    std::string priv_seed_hex    = keyfile_json["priv_seed"].get<std::string>();
    if (inner_pubkey_hex.size() != 64) {
        std::cerr << "keyfile-decrypt: inner 'pubkey' must be 64 hex chars; "
                     "got " << inner_pubkey_hex.size() << "\n";
        return 1;
    }
    if (priv_seed_hex.size() != 64) {
        std::cerr << "keyfile-decrypt: inner 'priv_seed' must be 64 hex "
                     "chars; got " << priv_seed_hex.size() << "\n";
        return 1;
    }
    // Hex validation (defense-in-depth — the daemon's S-018 path enforces
    // this, but the operator probably wants the wallet to catch it first).
    try { (void)from_hex(inner_pubkey_hex); (void)from_hex(priv_seed_hex); }
    catch (std::exception& e) {
        std::cerr << "keyfile-decrypt: inner JSON contains invalid hex: "
                  << e.what() << "\n";
        return 1;
    }

    // ── Header-vs-inner pubkey defense-in-depth check ──────────────────────
    // The AAD already ties the header pubkey to the ciphertext, so a
    // mismatch here can only happen if a keyfile was hand-crafted outside
    // the canonical keyfile-create path. We surface it as a structural
    // problem with a clear diagnostic rather than silently using one or
    // the other — the operator should investigate provenance.
    if (inner_pubkey_hex != header_pubkey_hex) {
        std::cerr << "keyfile-decrypt: inner 'pubkey' (" << inner_pubkey_hex
                  << ") does not match header pubkey (" << header_pubkey_hex
                  << "); the encrypted blob was not produced by the "
                     "canonical keyfile-create path\n";
        return 1;
    }

    // ── Format canonical plaintext node_key.json ───────────────────────────
    // Matches src/crypto/keys.cpp::save_node_key byte-for-byte: nlohmann
    // dump with indent=2, fields {"pubkey","priv_seed"} as 64-hex strings.
    // The daemon's load_node_key only requires the two named fields to be
    // present, but we preserve the indented canonical shape so an operator
    // diffing wallet-decrypted vs. daemon-saved outputs sees equality.
    nlohmann::json out_json = {
        {"pubkey",    inner_pubkey_hex},
        {"priv_seed", priv_seed_hex}
    };
    std::string out_str = out_json.dump(2);

    {
        std::ofstream f(out_path);
        if (!f) {
            std::cerr << "keyfile-decrypt: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        f << out_str;
        f.close();
        if (!f) {
            std::cerr << "keyfile-decrypt: write failed on --out: "
                      << out_path << "\n";
            return 1;
        }
    }

    // 0600 permissions tightening — best-effort on Windows.
    {
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
    }

    if (json_out) {
        nlohmann::json r;
        r["pubkey"]   = inner_pubkey_hex;
        r["out"]      = out_path;
        r["format"]   = "node_key.json";
        r["from"]     = "DETERM-NODE-V1";
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "wrote plaintext node keyfile to " << out_path << "\n";
        std::cout << "  pubkey: " << inner_pubkey_hex << "\n";
        std::cout << "  format: node_key.json (daemon plaintext load path)\n";
    }
    return 0;
}

// ── keyfile-recover — high-level T-of-N backup recovery CLI ────────────────
//
// `keyfile-recover` is the operator inverse of `backup-create`. It composes
// `envelope::decrypt` + `shamir::combine` into a single call: given the
// canonical pair of backup artifacts (shares + envelopes file produced
// by `backup-create`) and a JSON file listing a T-of-N subset of
// keyholder passphrases, recover the original secret and print it as hex.
//
// Inputs:
//   --backup-shares    <file>: shares file emitted by backup-create's
//                              --shares-out (shape: {"shares":[{"x":int,
//                              "y_hex":"..."}, ...]}). Read for cross-
//                              verification — we confirm each decrypted
//                              y-bytes matches the shares-file entry.
//   --backup-envelopes <file>: envelopes file emitted by backup-create's
//                              --envelopes-out (shape: {"envelopes":
//                              [{"share_index":int,"envelope_blob":"..."},
//                              ...]}).
//   --keyholders       <file>: SAME shape as backup-create's --keyholders
//                              input but with ONLY a T-of-N subset of
//                              passphrases supplied:
//                              {"keyholders":[{"share_index":int,
//                              "passphrase":"..."}, ...]}
//   [--out  <file>]          : if supplied, write {"secret_hex":"..."} JSON
//                              to <file> instead of emitting the hex to
//                              stdout
//   [--force]                : permit overwriting an existing --out file
//   [--json]                 : print the JSON {"secret_hex":"..."} doc to
//                              stdout (ignored if --out is supplied; --out
//                              always writes JSON)
//
// Process:
//   1. Parse the three input files.
//   2. For each keyholder entry: look up the corresponding envelope by
//      share_index, deserialize the envelope blob, decrypt with the
//      keyholder's passphrase (NO AAD — backup-create produces AAD-free
//      envelopes; the recovery composition mirrors that).
//   3. Cross-verify the recovered y-bytes against the shares-file
//      entry for the same share_index (defense-in-depth — catches a
//      shares/envelopes file mismatch before Shamir reconstruction
//      silently emits a garbage secret).
//   4. Feed the T recovered shamir::Share values into shamir::combine.
//   5. Output the recovered secret as hex (or JSON with --out / --json).
//
// Composition design:
//   This CLI is intentionally THIN — it composes existing primitives
//   (envelope::decrypt, shamir::combine) and existing file-shape
//   conventions (matched against backup-create + shamir-combine). No
//   crypto logic is duplicated; if envelope::decrypt or shamir::combine
//   change, this CLI follows transparently.
//
// Failure modes (all exit 2 with a diagnostic):
//   * Wrong passphrase: envelope::decrypt returns nullopt for an AEAD
//     tag mismatch. Same exit code as `keyfile-decrypt` for consistency.
//   * Insufficient shares (< T): shamir::combine returns nullopt or the
//     reconstruction yields a different secret. We can't tell T from the
//     inputs (the shares file doesn't carry threshold; the operator must
//     supply >= T keyholders), so we treat "shamir::combine returned
//     nullopt" as "insufficient or inconsistent shares". A reconstruction
//     run with fewer than T shares may also return a syntactically-valid
//     but wrong secret (Shamir's information-theoretic security property)
//     — the shares-file cross-verification in step 3 catches that case.
//   * Malformed inputs (missing files, bad JSON, share_index gap):
//     exit 2 with a specific diagnostic.
//
// Structural errors (missing required flags, can't open files for read,
// --out exists without --force) exit 1 — same convention as the other
// wallet CLIs.
int cmd_keyfile_recover(int argc, char** argv) {
    std::string shares_path, envelopes_path, keyholders_path, out_path;
    int threshold = -1;             // -1 sentinel = not supplied
    bool force = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--backup-shares"    && i + 1 < argc) shares_path     = argv[++i];
        else if (a == "--backup-envelopes" && i + 1 < argc) envelopes_path  = argv[++i];
        else if (a == "--keyholders"       && i + 1 < argc) keyholders_path = argv[++i];
        else if (a == "--out"              && i + 1 < argc) out_path        = argv[++i];
        else if (a == "--threshold"        && i + 1 < argc) {
            try { threshold = std::stoi(argv[++i]); }
            catch (std::exception&) {
                std::cerr << "keyfile-recover: --threshold must be an integer\n";
                return 1;
            }
        }
        else if (a == "--force")                            force           = true;
        else if (a == "--json")                             json_out        = true;
        else {
            std::cerr << "keyfile-recover: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet keyfile-recover "
                         "--backup-shares <file> --backup-envelopes <file> "
                         "--keyholders <file> [--threshold T] "
                         "[--out <file>] [--force] [--json]\n";
            return 1;
        }
    }
    if (shares_path.empty() || envelopes_path.empty()
        || keyholders_path.empty()) {
        std::cerr << "Usage: determ-wallet keyfile-recover "
                     "--backup-shares <file> --backup-envelopes <file> "
                     "--keyholders <file> [--threshold T] "
                     "[--out <file>] [--force] [--json]\n"
                     "\n"
                     "  High-level T-of-N recovery: composes envelope::decrypt\n"
                     "  + shamir::combine. Reads the (shares, envelopes) pair\n"
                     "  produced by `backup-create` and a T-of-N subset of\n"
                     "  keyholder passphrases; reconstructs the original secret.\n"
                     "\n"
                     "  Keyholders file shape (SAME as backup-create input but\n"
                     "  with only T of N entries supplied):\n"
                     "    {\"keyholders\": [{\"share_index\": int, "
                     "\"passphrase\": \"...\"}, ...]}\n"
                     "\n"
                     "  --threshold T (optional): explicitly check that the\n"
                     "    keyholders subset has at least T entries before the\n"
                     "    decrypt loop. The shares file does NOT carry T, so\n"
                     "    without --threshold the CLI cannot detect an under-\n"
                     "    threshold subset (Shamir's information-theoretic\n"
                     "    security property means combining < T shares yields\n"
                     "    a syntactically-valid but wrong secret, with no\n"
                     "    failure signal at the shamir layer).\n";
        return 1;
    }
    if (threshold == 0) {
        std::cerr << "keyfile-recover: --threshold must be >= 1 (got 0)\n";
        return 1;
    }
    if (threshold > 255) {
        std::cerr << "keyfile-recover: --threshold must be <= 255 (got "
                  << threshold << ")\n";
        return 1;
    }

    // ── Load + parse shares file ────────────────────────────────────────
    std::ifstream sf(shares_path);
    if (!sf) {
        std::cerr << "keyfile-recover: cannot open --backup-shares file: "
                  << shares_path << "\n";
        return 1;
    }
    std::string shares_blob((std::istreambuf_iterator<char>(sf)),
                              std::istreambuf_iterator<char>());
    nlohmann::json sj;
    try { sj = nlohmann::json::parse(shares_blob); }
    catch (std::exception& e) {
        std::cerr << "keyfile-recover: shares JSON parse failed: "
                  << e.what() << "\n";
        return 2;
    }
    if (!sj.is_object() || !sj.contains("shares") || !sj["shares"].is_array()) {
        std::cerr << "keyfile-recover: shares file must be an object with "
                     "'shares' array\n";
        return 2;
    }
    const auto& shares_arr = sj["shares"];
    if (shares_arr.empty()) {
        std::cerr << "keyfile-recover: 'shares' array is empty\n";
        return 2;
    }
    // Build x → y_hex map for the cross-verification check in step 3.
    std::map<int, std::string> shares_y_by_x;
    for (size_t i = 0; i < shares_arr.size(); ++i) {
        const auto& el = shares_arr[i];
        if (!el.is_object()
            || !el.contains("x")     || !el["x"].is_number_integer()
            || !el.contains("y_hex") || !el["y_hex"].is_string()) {
            std::cerr << "keyfile-recover: shares entry #" << i
                      << " must have integer 'x' and string 'y_hex'\n";
            return 2;
        }
        int x = el["x"].get<int>();
        if (x < 1 || x > 255) {
            std::cerr << "keyfile-recover: shares entry #" << i
                      << ": x = " << x << " out of range [1, 255]\n";
            return 2;
        }
        if (shares_y_by_x.count(x)) {
            std::cerr << "keyfile-recover: duplicate x = " << x
                      << " in shares file\n";
            return 2;
        }
        shares_y_by_x[x] = el["y_hex"].get<std::string>();
    }

    // ── Load + parse envelopes file ─────────────────────────────────────
    std::ifstream ef(envelopes_path);
    if (!ef) {
        std::cerr << "keyfile-recover: cannot open --backup-envelopes file: "
                  << envelopes_path << "\n";
        return 1;
    }
    std::string env_blob((std::istreambuf_iterator<char>(ef)),
                           std::istreambuf_iterator<char>());
    nlohmann::json ej;
    try { ej = nlohmann::json::parse(env_blob); }
    catch (std::exception& e) {
        std::cerr << "keyfile-recover: envelopes JSON parse failed: "
                  << e.what() << "\n";
        return 2;
    }
    if (!ej.is_object() || !ej.contains("envelopes") || !ej["envelopes"].is_array()) {
        std::cerr << "keyfile-recover: envelopes file must be an object with "
                     "'envelopes' array\n";
        return 2;
    }
    const auto& env_arr = ej["envelopes"];
    if (env_arr.empty()) {
        std::cerr << "keyfile-recover: 'envelopes' array is empty\n";
        return 2;
    }
    // Build share_index → envelope_blob map.
    std::map<int, std::string> env_blob_by_idx;
    for (size_t i = 0; i < env_arr.size(); ++i) {
        const auto& el = env_arr[i];
        if (!el.is_object()
            || !el.contains("share_index")
            || !el["share_index"].is_number_integer()
            || !el.contains("envelope_blob")
            || !el["envelope_blob"].is_string()) {
            std::cerr << "keyfile-recover: envelopes entry #" << i
                      << " must have integer 'share_index' and string "
                         "'envelope_blob'\n";
            return 2;
        }
        int idx = el["share_index"].get<int>();
        if (idx < 1 || idx > 255) {
            std::cerr << "keyfile-recover: envelopes entry #" << i
                      << ": share_index = " << idx
                      << " out of range [1, 255]\n";
            return 2;
        }
        if (env_blob_by_idx.count(idx)) {
            std::cerr << "keyfile-recover: duplicate share_index = " << idx
                      << " in envelopes file\n";
            return 2;
        }
        env_blob_by_idx[idx] = el["envelope_blob"].get<std::string>();
    }

    // ── Load + parse keyholders file (T-of-N subset) ────────────────────
    std::ifstream kf(keyholders_path);
    if (!kf) {
        std::cerr << "keyfile-recover: cannot open --keyholders file: "
                  << keyholders_path << "\n";
        return 1;
    }
    std::string kh_blob((std::istreambuf_iterator<char>(kf)),
                          std::istreambuf_iterator<char>());
    nlohmann::json kj;
    try { kj = nlohmann::json::parse(kh_blob); }
    catch (std::exception& e) {
        std::cerr << "keyfile-recover: keyholders JSON parse failed: "
                  << e.what() << "\n";
        return 2;
    }
    if (!kj.is_object() || !kj.contains("keyholders") || !kj["keyholders"].is_array()) {
        std::cerr << "keyfile-recover: keyholders file must be an object with "
                     "'keyholders' array\n";
        return 2;
    }
    const auto& kh_arr = kj["keyholders"];
    if (kh_arr.empty()) {
        std::cerr << "keyfile-recover: 'keyholders' array is empty (need at "
                     "least 1 entry to attempt recovery)\n";
        return 2;
    }

    // Parse each keyholder entry. Tracks share_index → passphrase mapping
    // for the decrypt loop, and validates each share_index actually exists
    // in BOTH the shares and envelopes files before any crypto work.
    std::vector<std::pair<int, std::string>> kh_entries;
    std::set<int> seen_kh_idx;
    for (size_t i = 0; i < kh_arr.size(); ++i) {
        const auto& el = kh_arr[i];
        if (!el.is_object()
            || !el.contains("share_index")
            || !el["share_index"].is_number_integer()
            || !el.contains("passphrase")
            || !el["passphrase"].is_string()) {
            std::cerr << "keyfile-recover: keyholders entry #" << i
                      << " must have integer 'share_index' and string "
                         "'passphrase'\n";
            return 2;
        }
        int idx = el["share_index"].get<int>();
        std::string pw = el["passphrase"].get<std::string>();
        if (pw.empty()) {
            std::cerr << "keyfile-recover: keyholders entry share_index="
                      << idx << ": passphrase is empty\n";
            return 2;
        }
        if (!seen_kh_idx.insert(idx).second) {
            std::cerr << "keyfile-recover: duplicate share_index = " << idx
                      << " in keyholders file\n";
            return 2;
        }
        if (!env_blob_by_idx.count(idx)) {
            std::cerr << "keyfile-recover: keyholders share_index=" << idx
                      << " has no matching envelope in --backup-envelopes\n";
            return 2;
        }
        if (!shares_y_by_x.count(idx)) {
            std::cerr << "keyfile-recover: keyholders share_index=" << idx
                      << " has no matching share in --backup-shares\n";
            return 2;
        }
        kh_entries.emplace_back(idx, std::move(pw));
    }

    // ── Threshold check (if --threshold supplied) ────────────────────────
    // Without --threshold the shares file carries no T, so Shamir's
    // information-theoretic security property means combining < T shares
    // yields a syntactically-valid but wrong secret. When the operator
    // supplies T explicitly we can detect insufficient-share subsets
    // BEFORE any crypto work — fail fast and clear rather than emit
    // garbage. Same exit-2 convention as "wrong passphrase" / other
    // recovery failures.
    if (threshold > 0
        && static_cast<int>(kh_entries.size()) < threshold) {
        std::cerr << "keyfile-recover: insufficient shares for threshold "
                     "reconstruction: " << kh_entries.size()
                  << " keyholders supplied, --threshold = " << threshold
                  << "\n";
        return 2;
    }

    // ── --out preconditions (if supplied) ────────────────────────────────
    if (!out_path.empty()) {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "keyfile-recover: --out parent directory does not "
                         "exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "keyfile-recover: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Decrypt each envelope; collect shamir::Share entries ─────────────
    std::vector<shamir::Share> recovered_shares;
    recovered_shares.reserve(kh_entries.size());
    for (const auto& [idx, pw] : kh_entries) {
        const std::string& blob = env_blob_by_idx[idx];
        auto env_opt = envelope::deserialize(blob);
        if (!env_opt) {
            std::cerr << "keyfile-recover: envelope share_index=" << idx
                      << ": envelope_blob deserialize failed "
                         "(malformed envelope in --backup-envelopes)\n";
            return 2;
        }
        // backup-create produces AAD-free envelopes — same here (empty aad).
        auto pt_opt = envelope::decrypt(*env_opt, pw, {});
        if (!pt_opt) {
            std::cerr << "keyfile-recover: envelope share_index=" << idx
                      << ": decrypt failed (wrong passphrase or corrupted "
                         "envelope)\n";
            return 2;
        }
        const auto& y_bytes = *pt_opt;
        if (y_bytes.empty()) {
            std::cerr << "keyfile-recover: envelope share_index=" << idx
                      << ": decrypted plaintext is empty\n";
            return 2;
        }
        // Cross-verify decrypted y against the shares-file y_hex. Catches
        // a shares/envelopes file mismatch before Shamir reconstruction
        // silently emits a garbage secret.
        std::string y_hex_decrypted = to_hex(y_bytes);
        const std::string& y_hex_expected = shares_y_by_x[idx];
        if (y_hex_decrypted != y_hex_expected) {
            std::cerr << "keyfile-recover: envelope share_index=" << idx
                      << ": decrypted y-bytes do NOT match the y_hex in "
                         "--backup-shares (envelope/shares file mismatch — "
                         "the two files were likely produced by different "
                         "backup-create runs)\n";
            return 2;
        }
        shamir::Share s;
        if (idx < 1 || idx > 255) {
            std::cerr << "keyfile-recover: internal: share_index=" << idx
                      << " out of byte range\n";
            return 2;
        }
        s.x = static_cast<uint8_t>(idx);
        s.y = y_bytes;
        recovered_shares.push_back(std::move(s));
    }

    if (recovered_shares.empty()) {
        std::cerr << "keyfile-recover: no shares recovered (internal — "
                     "keyholders array was already validated as non-empty)\n";
        return 2;
    }

    // ── Shamir reconstruction ───────────────────────────────────────────
    auto secret_opt = shamir::combine(recovered_shares);
    if (!secret_opt) {
        std::cerr << "keyfile-recover: shamir::combine returned nullopt "
                     "(insufficient shares for threshold reconstruction, or "
                     "shares were structurally inconsistent at the shamir "
                     "layer)\n";
        return 2;
    }
    std::string secret_hex = to_hex(*secret_opt);

    // ── Emit result ─────────────────────────────────────────────────────
    if (!out_path.empty()) {
        nlohmann::json doc;
        doc["secret_hex"] = secret_hex;
        std::ofstream of(out_path);
        if (!of) {
            std::cerr << "keyfile-recover: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        of << doc.dump() << "\n";
        if (!of) {
            std::cerr << "keyfile-recover: write failed on --out: "
                      << out_path << "\n";
            return 1;
        }
        of.close();
        // 0600 permissions tightening — best-effort on Windows.
        {
            std::error_code perm_ec;
            std::filesystem::permissions(
                out_path,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace,
                perm_ec);
            (void)perm_ec;
        }
        if (json_out) {
            // --json + --out: also echo the JSON doc to stdout so the
            // operator's pipe-driven workflow sees the result.
            std::cout << doc.dump() << "\n";
        } else {
            std::cout << "recovered secret written to " << out_path
                      << " (" << recovered_shares.size()
                      << " shares combined)\n";
        }
    } else if (json_out) {
        nlohmann::json doc;
        doc["secret_hex"] = secret_hex;
        std::cout << doc.dump() << "\n";
    } else {
        std::cout << secret_hex << "\n";
    }
    return 0;
}

// ── account-recover — composite T-of-N wallet recovery CLI ─────────────────
//
// `account-recover` is the operator-facing "give me back my wallet account"
// CLI: it composes `keyfile-recover` (Shamir + envelope) with `account-import`
// (Ed25519 seed → anon-account JSON) into a SINGLE call, so the operator
// runs ONE command instead of two.
//
// Pipeline:
//   1. Run the keyfile-recover steps verbatim: decrypt T envelopes via
//      passphrases, cross-verify against shares, run shamir::combine →
//      recover a 32-byte secret (Ed25519 seed).
//   2. Treat the recovered secret as a 32-byte Ed25519 seed.
//   3. Derive the public key via libsodium crypto_sign_ed25519_seed_keypair
//      (same primitive used by account-import — keeps the wallet's
//      secret-handling surface uniform on libsodium).
//   4. Emit the anon-account JSON {"address":"0x..","privkey_hex":".."}
//      (same shape as account-import / account-create-batch single record).
//
// CLI:
//   --shares      <file>: shares file emitted by backup-create's
//                         --shares-out (shape: {"shares":[{"x":int,
//                         "y_hex":"..."}, ...]}).
//   --envelopes   <file>: envelopes file emitted by backup-create's
//                         --envelopes-out (shape: {"envelopes":
//                         [{"share_index":int,"envelope_blob":"..."}, ...]}).
//   --keyholders  <file>: T-of-N subset of keyholder passphrases (shape:
//                         {"keyholders":[{"share_index":int,
//                         "passphrase":"..."}, ...]}). MUST have >= T entries.
//   --threshold  T      : required (unlike keyfile-recover where it's
//                         optional). The seed-derivation step requires the
//                         RIGHT seed — Shamir's information-theoretic
//                         security means combining < T shares yields a
//                         syntactically-valid but wrong 32-byte secret, and
//                         account-recover MUST NOT silently emit a wrong
//                         wallet account. T is required so we can hard-fail
//                         under-threshold subsets before any keygen.
//   [--out  <file>]     : if supplied, write the anon-account JSON
//                         {"address":"0x..","privkey_hex":".."} to <file>
//                         with 0600 perms instead of stdout.
//   [--force]           : permit overwriting an existing --out file.
//   [--json]            : print the JSON doc to stdout (ignored if --out
//                         is supplied; --out always writes JSON).
//
// Output (default human): "recovered account: address=0x... privkey_hex=..."
// Output (--out):         {"address":"0x..","privkey_hex":".."} to file, 0600
// Output (--json):        same JSON to stdout
//
// Exit codes:
//   0 — success.
//   1 — args / file I/O / --out preconditions (matches keyfile-recover +
//       account-import structural-error convention).
//   2 — recovery failure (wrong passphrase, insufficient shares, share/
//       envelope mismatch, malformed inputs). SAME exit-2 convention as
//       keyfile-recover so monitoring scripts that already alert on the
//       inner CLI's exit 2 will continue to fire correctly when wrapped.
//
// Composition design:
//   This CLI is intentionally THIN — it composes the SAME primitives
//   (envelope::decrypt, shamir::combine, crypto_sign_ed25519_seed_keypair)
//   that the constituent CLIs use. No crypto logic is duplicated. If
//   keyfile-recover or account-import change, this CLI follows transparently.
//
// Seed-length contract:
//   The recovered Shamir secret MUST be exactly 32 bytes (= Ed25519 seed
//   size). If a 16-byte / 64-byte / other-length secret is recovered, we
//   reject with exit 2 — that's not an Ed25519 seed, so this is the wrong
//   recovery flow for that backup. Operators with non-32-byte backups
//   should use `keyfile-recover` directly + `account-import` separately.
int cmd_account_recover(int argc, char** argv) {
    std::string shares_path, envelopes_path, keyholders_path, out_path;
    int threshold = -1;             // -1 sentinel = not supplied
    bool force = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--shares"     && i + 1 < argc) shares_path     = argv[++i];
        else if (a == "--envelopes"  && i + 1 < argc) envelopes_path  = argv[++i];
        else if (a == "--keyholders" && i + 1 < argc) keyholders_path = argv[++i];
        else if (a == "--out"        && i + 1 < argc) out_path        = argv[++i];
        else if (a == "--threshold"  && i + 1 < argc) {
            try { threshold = std::stoi(argv[++i]); }
            catch (std::exception&) {
                std::cerr << "account-recover: --threshold must be an integer\n";
                return 1;
            }
        }
        else if (a == "--force")                      force           = true;
        else if (a == "--json")                       json_out        = true;
        else {
            std::cerr << "account-recover: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet account-recover "
                         "--shares <file> --envelopes <file> "
                         "--keyholders <file> --threshold T "
                         "[--out <file>] [--force] [--json]\n";
            return 1;
        }
    }
    if (shares_path.empty() || envelopes_path.empty()
        || keyholders_path.empty() || threshold < 0) {
        std::cerr << "Usage: determ-wallet account-recover "
                     "--shares <file> --envelopes <file> "
                     "--keyholders <file> --threshold T "
                     "[--out <file>] [--force] [--json]\n"
                     "\n"
                     "  Composite wallet recovery: composes keyfile-recover\n"
                     "  (Shamir + envelope) with account-import (Ed25519 seed\n"
                     "  -> anon-account JSON). Reads the (shares, envelopes)\n"
                     "  pair produced by `backup-create` and a T-of-N subset\n"
                     "  of keyholder passphrases; emits the recovered wallet\n"
                     "  account as JSON {\"address\":\"0x..\",\"privkey_hex\":\"..\"}.\n"
                     "\n"
                     "  --threshold T is REQUIRED (unlike keyfile-recover where\n"
                     "  it is optional): account-recover MUST NOT silently emit\n"
                     "  a wrong wallet account, and Shamir's info-theoretic\n"
                     "  security means combining < T shares yields a wrong but\n"
                     "  syntactically-valid 32-byte secret. T lets us hard-fail\n"
                     "  under-threshold subsets before any keygen.\n";
        return 1;
    }
    if (threshold == 0) {
        std::cerr << "account-recover: --threshold must be >= 1 (got 0)\n";
        return 1;
    }
    if (threshold > 255) {
        std::cerr << "account-recover: --threshold must be <= 255 (got "
                  << threshold << ")\n";
        return 1;
    }

    // ── Load + parse shares file ────────────────────────────────────────
    std::ifstream sf(shares_path);
    if (!sf) {
        std::cerr << "account-recover: cannot open --shares file: "
                  << shares_path << "\n";
        return 1;
    }
    std::string shares_blob((std::istreambuf_iterator<char>(sf)),
                              std::istreambuf_iterator<char>());
    nlohmann::json sj;
    try { sj = nlohmann::json::parse(shares_blob); }
    catch (std::exception& e) {
        std::cerr << "account-recover: shares JSON parse failed: "
                  << e.what() << "\n";
        return 2;
    }
    if (!sj.is_object() || !sj.contains("shares") || !sj["shares"].is_array()) {
        std::cerr << "account-recover: shares file must be an object with "
                     "'shares' array\n";
        return 2;
    }
    const auto& shares_arr = sj["shares"];
    if (shares_arr.empty()) {
        std::cerr << "account-recover: 'shares' array is empty\n";
        return 2;
    }
    // Build x → y_hex map for the cross-verification step.
    std::map<int, std::string> shares_y_by_x;
    for (size_t i = 0; i < shares_arr.size(); ++i) {
        const auto& el = shares_arr[i];
        if (!el.is_object()
            || !el.contains("x")     || !el["x"].is_number_integer()
            || !el.contains("y_hex") || !el["y_hex"].is_string()) {
            std::cerr << "account-recover: shares entry #" << i
                      << " must have integer 'x' and string 'y_hex'\n";
            return 2;
        }
        int x = el["x"].get<int>();
        if (x < 1 || x > 255) {
            std::cerr << "account-recover: shares entry #" << i
                      << ": x = " << x << " out of range [1, 255]\n";
            return 2;
        }
        if (shares_y_by_x.count(x)) {
            std::cerr << "account-recover: duplicate x = " << x
                      << " in shares file\n";
            return 2;
        }
        shares_y_by_x[x] = el["y_hex"].get<std::string>();
    }

    // ── Load + parse envelopes file ─────────────────────────────────────
    std::ifstream ef(envelopes_path);
    if (!ef) {
        std::cerr << "account-recover: cannot open --envelopes file: "
                  << envelopes_path << "\n";
        return 1;
    }
    std::string env_blob((std::istreambuf_iterator<char>(ef)),
                           std::istreambuf_iterator<char>());
    nlohmann::json ej;
    try { ej = nlohmann::json::parse(env_blob); }
    catch (std::exception& e) {
        std::cerr << "account-recover: envelopes JSON parse failed: "
                  << e.what() << "\n";
        return 2;
    }
    if (!ej.is_object() || !ej.contains("envelopes") || !ej["envelopes"].is_array()) {
        std::cerr << "account-recover: envelopes file must be an object with "
                     "'envelopes' array\n";
        return 2;
    }
    const auto& env_arr = ej["envelopes"];
    if (env_arr.empty()) {
        std::cerr << "account-recover: 'envelopes' array is empty\n";
        return 2;
    }
    std::map<int, std::string> env_blob_by_idx;
    for (size_t i = 0; i < env_arr.size(); ++i) {
        const auto& el = env_arr[i];
        if (!el.is_object()
            || !el.contains("share_index")
            || !el["share_index"].is_number_integer()
            || !el.contains("envelope_blob")
            || !el["envelope_blob"].is_string()) {
            std::cerr << "account-recover: envelopes entry #" << i
                      << " must have integer 'share_index' and string "
                         "'envelope_blob'\n";
            return 2;
        }
        int idx = el["share_index"].get<int>();
        if (idx < 1 || idx > 255) {
            std::cerr << "account-recover: envelopes entry #" << i
                      << ": share_index = " << idx
                      << " out of range [1, 255]\n";
            return 2;
        }
        if (env_blob_by_idx.count(idx)) {
            std::cerr << "account-recover: duplicate share_index = " << idx
                      << " in envelopes file\n";
            return 2;
        }
        env_blob_by_idx[idx] = el["envelope_blob"].get<std::string>();
    }

    // ── Load + parse keyholders file (T-of-N subset) ────────────────────
    std::ifstream kf(keyholders_path);
    if (!kf) {
        std::cerr << "account-recover: cannot open --keyholders file: "
                  << keyholders_path << "\n";
        return 1;
    }
    std::string kh_blob((std::istreambuf_iterator<char>(kf)),
                          std::istreambuf_iterator<char>());
    nlohmann::json kj;
    try { kj = nlohmann::json::parse(kh_blob); }
    catch (std::exception& e) {
        std::cerr << "account-recover: keyholders JSON parse failed: "
                  << e.what() << "\n";
        return 2;
    }
    if (!kj.is_object() || !kj.contains("keyholders") || !kj["keyholders"].is_array()) {
        std::cerr << "account-recover: keyholders file must be an object with "
                     "'keyholders' array\n";
        return 2;
    }
    const auto& kh_arr = kj["keyholders"];
    if (kh_arr.empty()) {
        std::cerr << "account-recover: 'keyholders' array is empty (need at "
                     "least 1 entry to attempt recovery)\n";
        return 2;
    }

    std::vector<std::pair<int, std::string>> kh_entries;
    std::set<int> seen_kh_idx;
    for (size_t i = 0; i < kh_arr.size(); ++i) {
        const auto& el = kh_arr[i];
        if (!el.is_object()
            || !el.contains("share_index")
            || !el["share_index"].is_number_integer()
            || !el.contains("passphrase")
            || !el["passphrase"].is_string()) {
            std::cerr << "account-recover: keyholders entry #" << i
                      << " must have integer 'share_index' and string "
                         "'passphrase'\n";
            return 2;
        }
        int idx = el["share_index"].get<int>();
        std::string pw = el["passphrase"].get<std::string>();
        if (pw.empty()) {
            std::cerr << "account-recover: keyholders entry share_index="
                      << idx << ": passphrase is empty\n";
            return 2;
        }
        if (!seen_kh_idx.insert(idx).second) {
            std::cerr << "account-recover: duplicate share_index = " << idx
                      << " in keyholders file\n";
            return 2;
        }
        if (!env_blob_by_idx.count(idx)) {
            std::cerr << "account-recover: keyholders share_index=" << idx
                      << " has no matching envelope in --envelopes\n";
            return 2;
        }
        if (!shares_y_by_x.count(idx)) {
            std::cerr << "account-recover: keyholders share_index=" << idx
                      << " has no matching share in --shares\n";
            return 2;
        }
        kh_entries.emplace_back(idx, std::move(pw));
    }

    // ── Threshold check (REQUIRED here, unlike keyfile-recover) ─────────
    // Under-threshold subsets MUST hard-fail before keygen. Shamir's
    // information-theoretic security means combining < T shares yields a
    // syntactically-valid 32-byte but WRONG secret — and account-recover
    // would happily derive a wallet account from that wrong secret. The
    // operator would then have a working-looking account file for an
    // address that owns no funds. Exit 2 here matches the wrong-passphrase
    // exit code (both mean "recovery failed").
    if (static_cast<int>(kh_entries.size()) < threshold) {
        std::cerr << "account-recover: insufficient shares for threshold "
                     "reconstruction: " << kh_entries.size()
                  << " keyholders supplied, --threshold = " << threshold
                  << "\n";
        return 2;
    }

    // ── --out preconditions (if supplied) ────────────────────────────────
    if (!out_path.empty()) {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "account-recover: --out parent directory does not "
                         "exist: " << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            std::cerr << "account-recover: --out file already exists: "
                      << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Decrypt each envelope; collect shamir::Share entries ─────────────
    std::vector<shamir::Share> recovered_shares;
    recovered_shares.reserve(kh_entries.size());
    for (const auto& [idx, pw] : kh_entries) {
        const std::string& blob = env_blob_by_idx[idx];
        auto env_opt = envelope::deserialize(blob);
        if (!env_opt) {
            std::cerr << "account-recover: envelope share_index=" << idx
                      << ": envelope_blob deserialize failed "
                         "(malformed envelope in --envelopes)\n";
            return 2;
        }
        // backup-create produces AAD-free envelopes — same here (empty aad).
        auto pt_opt = envelope::decrypt(*env_opt, pw, {});
        if (!pt_opt) {
            std::cerr << "account-recover: envelope share_index=" << idx
                      << ": decrypt failed (wrong passphrase or corrupted "
                         "envelope)\n";
            return 2;
        }
        const auto& y_bytes = *pt_opt;
        if (y_bytes.empty()) {
            std::cerr << "account-recover: envelope share_index=" << idx
                      << ": decrypted plaintext is empty\n";
            return 2;
        }
        // Cross-verify decrypted y against the shares-file y_hex. Catches
        // a shares/envelopes file mismatch before Shamir reconstruction
        // silently emits a garbage secret.
        std::string y_hex_decrypted = to_hex(y_bytes);
        const std::string& y_hex_expected = shares_y_by_x[idx];
        if (y_hex_decrypted != y_hex_expected) {
            std::cerr << "account-recover: envelope share_index=" << idx
                      << ": decrypted y-bytes do NOT match the y_hex in "
                         "--shares (envelope/shares file mismatch — the "
                         "two files were likely produced by different "
                         "backup-create runs)\n";
            return 2;
        }
        shamir::Share s;
        if (idx < 1 || idx > 255) {
            std::cerr << "account-recover: internal: share_index=" << idx
                      << " out of byte range\n";
            return 2;
        }
        s.x = static_cast<uint8_t>(idx);
        s.y = y_bytes;
        recovered_shares.push_back(std::move(s));
    }

    if (recovered_shares.empty()) {
        std::cerr << "account-recover: no shares recovered (internal — "
                     "keyholders array was already validated as non-empty)\n";
        return 2;
    }

    // ── Shamir reconstruction ───────────────────────────────────────────
    auto secret_opt = shamir::combine(recovered_shares);
    if (!secret_opt) {
        std::cerr << "account-recover: shamir::combine returned nullopt "
                     "(insufficient shares for threshold reconstruction, or "
                     "shares were structurally inconsistent at the shamir "
                     "layer)\n";
        return 2;
    }
    const std::vector<uint8_t>& secret = *secret_opt;

    // ── Seed-length contract: Ed25519 requires exactly 32 bytes ─────────
    // A non-32-byte recovered secret means this backup wasn't created
    // from a wallet-account Ed25519 seed — operator should use
    // keyfile-recover directly. We refuse to feed a wrong-sized secret
    // into crypto_sign_ed25519_seed_keypair (which expects exactly 32).
    static_assert(crypto_sign_SEEDBYTES == 32, "Ed25519 seed size mismatch");
    if (secret.size() != crypto_sign_SEEDBYTES) {
        std::cerr << "account-recover: recovered secret is " << secret.size()
                  << " bytes, but Ed25519 seed requires exactly 32 bytes. "
                     "This backup was likely created from a non-wallet "
                     "secret (use `keyfile-recover` directly instead).\n";
        return 2;
    }

    // ── Init libsodium + derive Ed25519 keypair from the recovered seed ─
    // Same primitive as account-import (crypto_sign_ed25519_seed_keypair).
    // The 64-byte sk it produces is seed||pubkey; we hold both halves
    // separately so we zero sk immediately after the call.
    if (!primitives::init_libsodium()) {
        std::cerr << "account-recover: libsodium init failed\n";
        return 1;
    }
    std::array<uint8_t, 32> seed{};
    std::memcpy(seed.data(), secret.data(), 32);
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> derived_pub{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    static_assert(crypto_sign_PUBLICKEYBYTES == 32, "Ed25519 pk size mismatch");
    static_assert(crypto_sign_SECRETKEYBYTES == 64, "Ed25519 sk size mismatch");
    if (crypto_sign_ed25519_seed_keypair(derived_pub.data(), sk.data(),
                                         seed.data()) != 0) {
        std::cerr << "account-recover: crypto_sign_ed25519_seed_keypair failed "
                     "(recovered seed not a valid Ed25519 private key — "
                     "almost certainly a corrupted Shamir reconstruction)\n";
        sodium_memzero(seed.data(), seed.size());
        return 2;
    }
    // Zero the libsodium 64-byte sk — its content (seed||pubkey) is already
    // held in `seed` / `derived_pub`, so the duplicate is unnecessary.
    sodium_memzero(sk.data(), sk.size());

    // ── Build the anon-account record ──────────────────────────────────
    // Matches account-import / account-create-batch byte-for-byte:
    // address is "0x" + lowercase hex of the 32-byte pubkey; privkey_hex
    // is the 32-byte seed (NOT the 64-byte libsodium sk).
    std::string address     = "0x" + to_hex(derived_pub);
    std::string privkey_hex = to_hex(seed);
    nlohmann::json record = {
        {"address",     address},
        {"privkey_hex", privkey_hex},
    };

    // Zero the local seed copy now that we've serialized it to hex.
    sodium_memzero(seed.data(), seed.size());

    // ── Emit result ────────────────────────────────────────────────────
    if (!out_path.empty()) {
        std::ofstream f(out_path);
        if (!f) {
            std::cerr << "account-recover: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        f << record.dump(2) << "\n";
        f.close();
        if (!f) {
            std::cerr << "account-recover: write failed on --out: "
                      << out_path << "\n";
            return 1;
        }
        // 0600 permissions — owner-only read/write. Best-effort on Windows
        // (NTFS ACL inherits from parent); non-fatal on perm-set failure.
        std::error_code perm_ec;
        std::filesystem::permissions(
            out_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            perm_ec);
        (void)perm_ec;
        if (json_out) {
            // --json + --out: also echo to stdout for pipe-driven workflows.
            std::cout << record.dump() << "\n";
        } else {
            std::cout << "recovered account written to " << out_path
                      << " (" << recovered_shares.size()
                      << " shares combined): address=" << address << "\n";
        }
        return 0;
    }
    if (json_out) {
        std::cout << record.dump() << "\n";
        return 0;
    }
    // Default human format — single line, both fields, no header (since
    // recovery always yields exactly one account).
    std::cout << "recovered account: address=" << address
              << " privkey_hex=" << privkey_hex << "\n";
    return 0;
}

// ── keyfile-info — passive diagnostic for an encrypted node keyfile ─────────
//
// S-004 keyfile-shape complement to `inspect-envelope`. Reads a 2-line
// encrypted node keyfile (DETERM-NODE-V1 header + DWE1 envelope blob),
// parses both, and emits the combined metadata WITHOUT decrypting (no
// passphrase, no AEAD, no plaintext recovery).
//
// Use cases:
//   * Operator sanity check before attempting decrypt (correct file? right
//     validator pubkey? PBKDF2 iters consistent with the deployment policy?).
//   * Fleet inventory: enumerate all encrypted keyfiles, dump (pubkey,
//     anon-address) without ever needing the passphrase.
//   * Forensic triage: a tampered file is rejected with a distinguishing
//     exit code (2) so monitoring can route alerts.
//
// Exit codes:
//   0 — valid keyfile shape, metadata emitted.
//   1 — file-system error (missing file, parent dir issue, argparse).
//   2 — structural malformation (wrong header magic, bad pubkey hex, bad
//        envelope serialization). Distinguishes "operator pointed at a
//        non-keyfile" or "tampering" from "file not found".
//
// Output (default human form):
//   keyfile:           <path>
//   header_version:    DETERM-NODE-V1
//   pubkey_hex:        <64-hex>
//   anon_address:      0x<64-hex>
//   envelope:
//     format:          DWE1 (version 1)
//     pbkdf2_iters:    <N>
//     salt_len:        <n> bytes
//     nonce_len:       12 bytes
//     ciphertext_len:  <n> bytes
//     aad_present:     true|false
//
// JSON shape (--json):
//   {"valid":true,
//    "header_version":"DETERM-NODE-V1",
//    "pubkey_hex":"...",
//    "anon_address":"0x...",
//    "envelope":{
//      "pbkdf2_iters":<N>,
//      "salt_len":<n>,
//      "nonce_len":12,
//      "ct_len":<n>,
//      "aad_present":false}}
//
// Anon-address derivation: matches `make_anon_address` (and the
// `account-create-batch` precedent in this same binary): the address is
// simply "0x" followed by the lowercase hex of the 32-byte pubkey. The
// hex is already present in the header byte-for-byte; the "0x" prefix is
// the only addition. This is a sanity-check column for operators eyeballing
// fleet inventories: header pubkey + derived address always line up unless
// the header was hand-tampered (in which case the hex-validation step
// above rejects with exit 2).
int cmd_keyfile_info(int argc, char** argv) {
    std::string in_path;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in" && i + 1 < argc) in_path = argv[++i];
        else if (a == "--json")                json_out = true;
        else {
            std::cerr << "keyfile-info: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet keyfile-info --in <file> [--json]\n";
            return 1;
        }
    }
    if (in_path.empty()) {
        std::cerr << "Usage: determ-wallet keyfile-info --in <file> [--json]\n";
        return 1;
    }

    // ── Read --in and parse the canonical 2-line format ────────────────────
    // File-level failures (missing, unreadable) exit 1. Structural failures
    // (wrong header magic, truncated, bad hex, bad envelope) exit 2. The
    // split lets monitoring scripts distinguish "pointed at the wrong
    // path" from "file is corrupted / not a keyfile".
    std::string header_line, blob_line;
    {
        std::ifstream f(in_path);
        if (!f) {
            std::cerr << "keyfile-info: cannot open --in: " << in_path << "\n";
            return 1;
        }
        if (!std::getline(f, header_line)) {
            // Empty file is structurally malformed — there's no header line
            // at all. Use exit 2 (malformed) rather than 1, since the file
            // is reachable but its shape is wrong.
            std::cerr << "keyfile-info: --in is empty (no header line): "
                      << in_path << "\n";
            return 2;
        }
        if (!std::getline(f, blob_line)) {
            std::cerr << "keyfile-info: --in is missing the envelope-blob "
                         "line (expected 2-line format: header + blob): "
                      << in_path << "\n";
            return 2;
        }
        // Strip trailing CR (Windows-style line endings) for portability.
        while (!header_line.empty()
               && (header_line.back() == '\r' || header_line.back() == '\n'))
            header_line.pop_back();
        while (!blob_line.empty()
               && (blob_line.back() == '\r' || blob_line.back() == '\n'))
            blob_line.pop_back();
    }

    // ── Header shape: "DETERM-NODE-V1 <pubkey_hex>" ─────────────────────────
    const std::string header_magic = "DETERM-NODE-V1 ";
    if (header_line.rfind(header_magic, 0) != 0) {
        std::cerr << "keyfile-info: --in header does not start with "
                     "'DETERM-NODE-V1 ' (not a canonical encrypted node "
                     "keyfile)\n";
        return 2;
    }
    std::string pubkey_hex = header_line.substr(header_magic.size());
    if (pubkey_hex.size() != 64) {
        std::cerr << "keyfile-info: --in header pubkey must be 64 hex "
                     "chars (32-byte Ed25519 pubkey); got "
                  << pubkey_hex.size() << "\n";
        return 2;
    }
    try { (void)from_hex(pubkey_hex); }
    catch (std::exception& e) {
        std::cerr << "keyfile-info: --in header pubkey is not valid hex: "
                  << e.what() << "\n";
        return 2;
    }
    if (blob_line.empty()) {
        std::cerr << "keyfile-info: --in envelope blob line is empty\n";
        return 2;
    }

    // ── Deserialize envelope blob (no AEAD, no key derivation) ─────────────
    auto env_opt = envelope::deserialize(blob_line);
    if (!env_opt) {
        std::cerr << "keyfile-info: --in envelope blob is malformed "
                     "(not a valid DWE1 serialization)\n";
        return 2;
    }
    const auto& env = *env_opt;

    // Anon-address: matches src/main.cpp::make_anon_address and the
    // account-create-batch precedent above — "0x" + lowercase hex(pub).
    std::string anon_address = "0x" + pubkey_hex;

    const bool aad_present = !env.aad.empty();

    if (json_out) {
        // Flat schema for monitoring scripts. The nested "envelope"
        // sub-object mirrors the spec in the command's doc-block above.
        std::cout << "{"
                  << "\"valid\":true,"
                  << "\"header_version\":\"DETERM-NODE-V1\","
                  << "\"pubkey_hex\":\""   << pubkey_hex   << "\","
                  << "\"anon_address\":\"" << anon_address << "\","
                  << "\"envelope\":{"
                  << "\"pbkdf2_iters\":"   << env.pbkdf2_iters << ","
                  << "\"salt_len\":"       << env.salt.size()  << ","
                  << "\"nonce_len\":"      << env.nonce.size() << ","
                  << "\"ct_len\":"         << env.ciphertext.size() << ","
                  << "\"aad_present\":"    << (aad_present ? "true" : "false")
                  << "}"
                  << "}\n";
    } else {
        std::cout << "keyfile:           " << in_path           << "\n";
        std::cout << "header_version:    DETERM-NODE-V1\n";
        std::cout << "pubkey_hex:        " << pubkey_hex        << "\n";
        std::cout << "anon_address:      " << anon_address      << "\n";
        std::cout << "envelope:\n";
        std::cout << "  format:          DWE1 (version 1)\n";
        std::cout << "  pbkdf2_iters:    " << env.pbkdf2_iters  << "\n";
        std::cout << "  salt_len:        " << env.salt.size()   << " bytes\n";
        std::cout << "  nonce_len:       " << env.nonce.size()  << " bytes\n";
        std::cout << "  ciphertext_len:  " << env.ciphertext.size() << " bytes\n";
        std::cout << "  aad_present:     " << (aad_present ? "true" : "false")
                  << "\n";
    }
    return 0;
}

// ── account-list — enumerate keyfiles in a directory with metadata ──────────
//
// Pure local computation: walks --keyfiles-dir, classifies each regular file
// as one of {plaintext-single, plaintext-batch, encrypted-DETERM-NODE-V1,
// unknown}, and emits a per-file metadata record. No daemon RPC, no
// decryption, no passphrase required.
//
// Detection rules (each file is read until a definitive classification or
// the rules give up):
//   * Read the first line as text. If it starts with "DETERM-NODE-V1 " AND
//     the second line is a parseable DWE1 envelope blob, it's encrypted.
//   * Otherwise try JSON parse on the full content:
//       - JSON object with string `address` (66 char "0x"+64hex) AND string
//         `privkey_hex` (64 hex chars): plaintext-single
//       - JSON object with array `accounts` whose entries match the
//         single-account shape (or contain {address, privkey_hex}):
//         plaintext-batch
//   * Anything else: "unknown" — recorded but skipped from the address
//     extraction. By default unknown rows are still listed (so the operator
//     can see what's in the dir); the `--include-encrypted` and
//     `--include-plaintext` flags only gate the keyfile-typed rows.
//
// Encrypted keyfile metadata mirrors `keyfile-info`: header_tag (the
// "DETERM-NODE-V1" magic), pbkdf2_iters, salt_hex, nonce_hex. No decrypt is
// performed, so this is safe to run on a directory of production keyfiles
// without passphrases on hand.
//
// File mode reporting:
//   * On POSIX: rwx triplet rendered as a 4-digit octal ("0600", "0644",
//     etc.). The "0600" string is the security-critical value for plaintext
//     keyfiles — anything else triggers a `mode_not_0600` warning.
//   * On Windows: NTFS doesn't have a Unix-style mode bit; we report "n/a"
//     and skip the mode_not_0600 warning entirely (operator hygiene there
//     is enforced via NTFS ACL inheritance, not visible here).
//
// Summary warnings:
//   * mode_not_0600 — any plaintext keyfile on POSIX with mode != 0600.
//   * mixed_encrypted_and_plaintext_in_same_dir — operator hygiene; a single
//     directory containing both encrypted node keyfiles and plaintext
//     account JSON probably represents an accidental cross-contamination.
//
// CLI:
//   --keyfiles-dir <path>     REQUIRED. Directory to enumerate.
//   --recursive               Walk subdirectories (default off).
//   --include-encrypted       Include encrypted keyfiles (default on).
//   --include-plaintext       Include plaintext single + batch (default on).
//   --json                    JSON output (default on — only the default
//                             output shape is documented; non-JSON form is
//                             not provided).
//   --help                    Print usage and exit 0.
//
// Negation forms `--include-encrypted=off` and `--include-plaintext=off`
// (and equivalently `--no-include-encrypted` / `--no-include-plaintext`)
// disable the respective inclusion. The flags are independent: turning
// both off yields a summary-only output with an empty keyfiles array.
//
// Exit codes:
//   0  success
//   1  bad args, missing directory, unreadable directory
int cmd_account_list(int argc, char** argv) {
    std::string keyfiles_dir;
    bool recursive          = false;
    bool include_encrypted  = true;
    bool include_plaintext  = true;
    bool json_out           = true;  // default on per spec

    auto parse_onoff = [](const std::string& v, bool& out) -> bool {
        if (v == "on" || v == "1" || v == "true" || v == "yes")  { out = true;  return true; }
        if (v == "off"|| v == "0" || v == "false"|| v == "no")   { out = false; return true; }
        return false;
    };

    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--keyfiles-dir" && i + 1 < argc) keyfiles_dir = argv[++i];
        else if (a == "--recursive")                    recursive = true;
        else if (a == "--include-encrypted")            include_encrypted = true;
        else if (a == "--no-include-encrypted")         include_encrypted = false;
        else if (a.rfind("--include-encrypted=", 0) == 0) {
            if (!parse_onoff(a.substr(20), include_encrypted)) {
                std::cerr << "account-list: --include-encrypted= must be on|off (got '"
                          << a.substr(20) << "')\n";
                return 1;
            }
        }
        else if (a == "--include-plaintext")            include_plaintext = true;
        else if (a == "--no-include-plaintext")         include_plaintext = false;
        else if (a.rfind("--include-plaintext=", 0) == 0) {
            if (!parse_onoff(a.substr(20), include_plaintext)) {
                std::cerr << "account-list: --include-plaintext= must be on|off (got '"
                          << a.substr(20) << "')\n";
                return 1;
            }
        }
        else if (a == "--json")                         json_out = true;
        else if (a == "--no-json")                      json_out = false;
        else if (a == "--help" || a == "-h") {
            std::cout <<
                "Usage: determ-wallet account-list --keyfiles-dir <path> "
                "[--recursive] [--include-encrypted[=on|off]] "
                "[--include-plaintext[=on|off]] [--json] [--help]\n"
                "\n"
                "Enumerate keyfiles in a directory and emit per-file\n"
                "metadata (type, address(es), file size, mode). Pure local\n"
                "computation; no daemon RPC; no decryption.\n"
                "\n"
                "Detected types:\n"
                "  plaintext-single             {\"address\":..., \"privkey_hex\":...}\n"
                "  plaintext-batch              {\"accounts\":[{\"address\":..., ...}, ...]}\n"
                "  encrypted-DETERM-NODE-V1     2-line: header + DWE1 envelope\n"
                "  unknown                      neither JSON nor canonical keyfile\n"
                "\n"
                "Summary warnings:\n"
                "  mode_not_0600                       plaintext keyfile with mode != 0600 (POSIX)\n"
                "  mixed_encrypted_and_plaintext_in_same_dir  hygiene flag\n";
            return 0;
        }
        else {
            std::cerr << "account-list: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet account-list --keyfiles-dir <path> "
                         "[--recursive] [--include-encrypted[=on|off]] "
                         "[--include-plaintext[=on|off]] [--json] [--help]\n";
            return 1;
        }
    }

    if (keyfiles_dir.empty()) {
        std::cerr << "account-list: --keyfiles-dir is required\n";
        std::cerr << "Usage: determ-wallet account-list --keyfiles-dir <path> "
                     "[--recursive] [--include-encrypted[=on|off]] "
                     "[--include-plaintext[=on|off]] [--json] [--help]\n";
        return 1;
    }

    std::error_code ec;
    if (!std::filesystem::exists(keyfiles_dir, ec) || ec) {
        std::cerr << "account-list: --keyfiles-dir does not exist: "
                  << keyfiles_dir << "\n";
        return 1;
    }
    if (!std::filesystem::is_directory(keyfiles_dir, ec) || ec) {
        std::cerr << "account-list: --keyfiles-dir is not a directory: "
                  << keyfiles_dir << "\n";
        return 1;
    }

    // ── Helper: render file mode as a 4-digit octal string ─────────────────
    // On POSIX we read st_mode permission bits and emit "0600" et al.
    // On Windows std::filesystem::permissions returns the read/write/execute
    // synthesized triplet which does not reflect NTFS ACL; rather than
    // emitting a misleading "0666", we report "n/a" so the warning logic
    // skips the mode_not_0600 check there.
    auto file_mode_str = [](const std::filesystem::path& p) -> std::string {
#ifdef _WIN32
        (void)p;
        return "n/a";
#else
        std::error_code mec;
        auto perms = std::filesystem::status(p, mec).permissions();
        if (mec) return "n/a";
        unsigned v = 0;
        using std::filesystem::perms;
        if ((perms & perms::owner_read)   != perms::none) v |= 0400;
        if ((perms & perms::owner_write)  != perms::none) v |= 0200;
        if ((perms & perms::owner_exec)   != perms::none) v |= 0100;
        if ((perms & perms::group_read)   != perms::none) v |= 0040;
        if ((perms & perms::group_write)  != perms::none) v |= 0020;
        if ((perms & perms::group_exec)   != perms::none) v |= 0010;
        if ((perms & perms::others_read)  != perms::none) v |= 0004;
        if ((perms & perms::others_write) != perms::none) v |= 0002;
        if ((perms & perms::others_exec)  != perms::none) v |= 0001;
        char buf[8]{};
        std::snprintf(buf, sizeof(buf), "%04o", v);
        return std::string(buf);
#endif
    };

    // ── Helper: validate "0x" + 64 lowercase hex (anon-address shape) ──────
    auto is_anon_address = [](const std::string& s) -> bool {
        if (s.size() != 66) return false;
        if (s[0] != '0' || s[1] != 'x') return false;
        for (size_t i = 2; i < s.size(); ++i) {
            char c = s[i];
            bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!hex) return false;
        }
        return true;
    };

    // ── Helper: classify a single file ─────────────────────────────────────
    // Returns a JSON record per the output schema. The "type" field is
    // always present; type-specific fields follow. Errors during read are
    // recorded as type="unknown" with a "skip_reason" field; the caller
    // decides whether to include them in the output array.
    auto classify = [&](const std::filesystem::path& path) -> nlohmann::json {
        nlohmann::json rec;
        // Canonicalize the path for the output. lexically_normal keeps it
        // readable across platforms; the generic_string() form uses forward
        // slashes uniformly (matters on Windows for test grep-ability).
        rec["path"] = path.lexically_normal().generic_string();
        std::error_code sec;
        auto sz = std::filesystem::file_size(path, sec);
        rec["size_bytes"] = sec ? 0 : static_cast<uint64_t>(sz);
        rec["mode"] = file_mode_str(path);

        // Read up to 16 MB. Anything larger isn't plausibly a wallet
        // keyfile (largest plaintext-batch caps at 10_000 accounts ~ 1.5 MB;
        // encrypted envelope is two lines under 2 KB).
        constexpr std::uintmax_t MAX_READ = 16 * 1024 * 1024;
        if (rec["size_bytes"].get<uint64_t>() > MAX_READ) {
            rec["type"] = "unknown";
            rec["skip_reason"] = "file_too_large";
            return rec;
        }
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            rec["type"] = "unknown";
            rec["skip_reason"] = "open_failed";
            return rec;
        }
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());

        // ── Detection #1: encrypted DETERM-NODE-V1 (2-line text format) ────
        // The header magic is a tight prefix match; we only treat the file
        // as encrypted if the header is well-formed AND the second line
        // deserializes as a DWE1 envelope. Anything else falls through to
        // the JSON detector.
        const std::string header_magic = "DETERM-NODE-V1 ";
        if (content.size() > header_magic.size()
            && content.compare(0, header_magic.size(), header_magic) == 0) {
            // Split on first newline.
            auto nl = content.find('\n');
            if (nl != std::string::npos) {
                std::string header_line = content.substr(0, nl);
                while (!header_line.empty()
                       && (header_line.back() == '\r' || header_line.back() == '\n'))
                    header_line.pop_back();
                // Find the blob line (skip the LF + take until next LF or EOF).
                std::string blob_line;
                auto rest_start = nl + 1;
                auto nl2 = content.find('\n', rest_start);
                if (nl2 == std::string::npos) blob_line = content.substr(rest_start);
                else                          blob_line = content.substr(rest_start,
                                                                          nl2 - rest_start);
                while (!blob_line.empty()
                       && (blob_line.back() == '\r' || blob_line.back() == '\n'))
                    blob_line.pop_back();

                std::string pubkey_hex = header_line.substr(header_magic.size());
                bool hdr_pub_ok = (pubkey_hex.size() == 64);
                if (hdr_pub_ok) {
                    try { (void)from_hex(pubkey_hex); }
                    catch (...) { hdr_pub_ok = false; }
                }
                auto env_opt = envelope::deserialize(blob_line);
                if (hdr_pub_ok && env_opt) {
                    rec["type"]         = "encrypted-DETERM-NODE-V1";
                    rec["header_tag"]   = "DETERM-NODE-V1";
                    rec["pubkey_hex"]   = pubkey_hex;
                    rec["address"]      = "0x" + pubkey_hex;
                    rec["pbkdf2_iters"] = env_opt->pbkdf2_iters;
                    rec["salt_hex"]     = to_hex(env_opt->salt);
                    rec["nonce_hex"]    = to_hex(env_opt->nonce);
                    return rec;
                }
                // Header looked like ours but the envelope failed — fall
                // through to "unknown". An operator-friendly skip_reason
                // helps debug accidentally-corrupted keyfiles.
                rec["type"]        = "unknown";
                rec["skip_reason"] = "encrypted_keyfile_malformed";
                return rec;
            }
        }

        // ── Detection #2: plaintext JSON shapes (single + batch) ───────────
        nlohmann::json doc;
        try {
            doc = nlohmann::json::parse(content);
        } catch (...) {
            rec["type"]        = "unknown";
            rec["skip_reason"] = "not_json";
            return rec;
        }

        // Single-account shape: top-level {address, privkey_hex} strings.
        if (doc.is_object()
            && doc.contains("address") && doc["address"].is_string()
            && doc.contains("privkey_hex") && doc["privkey_hex"].is_string()
            && is_anon_address(doc["address"].get<std::string>())) {
            rec["type"]    = "plaintext-single";
            rec["address"] = doc["address"].get<std::string>();
            return rec;
        }

        // Batch shape: top-level {accounts: [{address, privkey_hex}, ...]}.
        // Matches account-create-batch / account-derive-batch output. We
        // accept either pure single-account entries or the derive-batch
        // shape that adds an "index" field (so account-derive-batch output
        // is recognized too).
        if (doc.is_object() && doc.contains("accounts")
            && doc["accounts"].is_array()) {
            nlohmann::json addrs = nlohmann::json::array();
            bool all_ok = true;
            for (const auto& a : doc["accounts"]) {
                if (!a.is_object()
                    || !a.contains("address") || !a["address"].is_string()) {
                    all_ok = false; break;
                }
                std::string addr = a["address"].get<std::string>();
                if (!is_anon_address(addr)) { all_ok = false; break; }
                addrs.push_back(addr);
            }
            if (all_ok && !addrs.empty()) {
                rec["type"]      = "plaintext-batch";
                rec["addresses"] = std::move(addrs);
                return rec;
            }
        }

        // ── Detection #3: pubkey/priv_seed shape (decrypted node keyfile) ──
        // This is the plaintext form keyfile-decrypt emits — it matches
        // src/crypto/keys.cpp::save_node_key. Treat it as plaintext-single
        // with the derived anon-address ("0x" + pubkey_hex). We DON'T require
        // priv_seed to validate; the type is determined by the pubkey field.
        if (doc.is_object()
            && doc.contains("pubkey") && doc["pubkey"].is_string()
            && doc.contains("priv_seed") && doc["priv_seed"].is_string()
            && doc["pubkey"].get<std::string>().size() == 64) {
            std::string pub = doc["pubkey"].get<std::string>();
            bool pub_hex_ok = true;
            try { (void)from_hex(pub); } catch (...) { pub_hex_ok = false; }
            if (pub_hex_ok) {
                rec["type"]    = "plaintext-single";
                rec["address"] = "0x" + pub;
                return rec;
            }
        }

        rec["type"]        = "unknown";
        rec["skip_reason"] = "json_shape_not_recognized";
        return rec;
    };

    // ── Walk the directory ─────────────────────────────────────────────────
    std::vector<nlohmann::json> entries;
    entries.reserve(64);

    auto walk = [&](auto&& self, const std::filesystem::path& root, bool rec) -> void {
        std::error_code wec;
        std::filesystem::directory_iterator it(root, wec);
        if (wec) return;
        for (auto end = std::filesystem::directory_iterator{}; it != end;
             it.increment(wec)) {
            if (wec) break;
            const auto& entry = *it;
            std::error_code tec;
            if (entry.is_regular_file(tec) && !tec) {
                entries.push_back(classify(entry.path()));
            } else if (rec && entry.is_directory(tec) && !tec) {
                self(self, entry.path(), rec);
            }
        }
    };
    walk(walk, std::filesystem::path(keyfiles_dir), recursive);

    // Deterministic order — sort by path so the output is stable across
    // platforms regardless of the directory iterator's order. Operator
    // diffs and regression tests depend on this.
    std::sort(entries.begin(), entries.end(),
              [](const nlohmann::json& a, const nlohmann::json& b) {
                  return a.value("path", "") < b.value("path", "");
              });

    // ── Filter per --include-* flags and tally ─────────────────────────────
    std::map<std::string, int> by_type;
    int n_addresses                 = 0;
    int n_encrypted_kept            = 0;
    int n_plaintext_kept            = 0;
    int n_plaintext_mode_violations = 0;
    bool encrypted_seen_anywhere    = false;
    bool plaintext_seen_anywhere    = false;

    nlohmann::json kept = nlohmann::json::array();
    for (const auto& e : entries) {
        std::string t = e.value("type", "unknown");
        if (t == "encrypted-DETERM-NODE-V1") {
            encrypted_seen_anywhere = true;
            if (!include_encrypted) continue;
            ++n_encrypted_kept;
            by_type[t] += 1;
            ++n_addresses;
        } else if (t == "plaintext-single") {
            plaintext_seen_anywhere = true;
            if (!include_plaintext) continue;
            ++n_plaintext_kept;
            by_type[t] += 1;
            ++n_addresses;
            // Mode warning: only meaningful on POSIX. "n/a" mode means
            // Windows; skip the check there (NTFS ACL is the real gate).
            std::string m = e.value("mode", "n/a");
            if (m != "n/a" && m != "0600") ++n_plaintext_mode_violations;
        } else if (t == "plaintext-batch") {
            plaintext_seen_anywhere = true;
            if (!include_plaintext) continue;
            ++n_plaintext_kept;
            by_type[t] += 1;
            if (e.contains("addresses") && e["addresses"].is_array())
                n_addresses += static_cast<int>(e["addresses"].size());
            std::string m = e.value("mode", "n/a");
            if (m != "n/a" && m != "0600") ++n_plaintext_mode_violations;
        } else {
            // "unknown" — always include (operator wants to see what's there)
            by_type[t] += 1;
        }
        kept.push_back(e);
    }

    nlohmann::json by_type_obj = nlohmann::json::object();
    for (const auto& kv : by_type) by_type_obj[kv.first] = kv.second;

    nlohmann::json warnings = nlohmann::json::array();
    if (n_plaintext_mode_violations > 0) warnings.push_back("mode_not_0600");
    if (encrypted_seen_anywhere && plaintext_seen_anywhere)
        warnings.push_back("mixed_encrypted_and_plaintext_in_same_dir");

    nlohmann::json out;
    out["keyfiles_dir"] = std::filesystem::path(keyfiles_dir)
                              .lexically_normal().generic_string();
    out["recursive"]    = recursive;
    out["keyfiles"]     = std::move(kept);
    nlohmann::json summary;
    summary["total_files"]  = static_cast<int>(out["keyfiles"].size());
    summary["by_type"]      = std::move(by_type_obj);
    summary["n_addresses"]  = n_addresses;
    summary["warnings"]     = std::move(warnings);
    out["summary"]          = std::move(summary);

    if (json_out) {
        std::cout << out.dump(2) << "\n";
    } else {
        // Compact non-JSON fallback for ad-hoc terminal use. The default is
        // JSON per spec; this branch only fires when --no-json is passed.
        std::cout << "keyfiles_dir: " << out["keyfiles_dir"].get<std::string>()
                  << "  (recursive=" << (recursive ? "true" : "false") << ")\n";
        for (const auto& e : out["keyfiles"]) {
            std::cout << "  " << e.value("path", "") << "  type="
                      << e.value("type", "?");
            if (e.contains("address"))
                std::cout << "  address=" << e["address"].get<std::string>();
            if (e.contains("addresses"))
                std::cout << "  n_addresses="
                          << e["addresses"].size();
            std::cout << "  mode=" << e.value("mode", "n/a")
                      << "  size=" << e.value("size_bytes", uint64_t(0));
            std::cout << "\n";
        }
        std::cout << "summary: total_files="
                  << out["summary"]["total_files"].get<int>()
                  << "  n_addresses="
                  << out["summary"]["n_addresses"].get<int>();
        if (!out["summary"]["warnings"].empty()) {
            std::cout << "  warnings=";
            bool first = true;
            for (const auto& w : out["summary"]["warnings"]) {
                if (!first) std::cout << ",";
                std::cout << w.get<std::string>();
                first = false;
            }
        }
        std::cout << "\n";
    }
    return 0;
}

int cmd_create_recovery(int argc, char** argv) {
    std::string seed_hex, password, out_path, scheme = "passphrase";
    int threshold = 0, share_count = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--seed"     && i + 1 < argc) seed_hex    = argv[++i];
        else if (a == "--password" && i + 1 < argc) password    = argv[++i];
        else if (a == "--out"      && i + 1 < argc) out_path    = argv[++i];
        else if (a == "--scheme"   && i + 1 < argc) scheme      = argv[++i];
        else if (a == "-t"         && i + 1 < argc) threshold   = std::stoi(argv[++i]);
        else if (a == "-n"         && i + 1 < argc) share_count = std::stoi(argv[++i]);
    }
    if (seed_hex.empty() || password.empty() || out_path.empty()
        || threshold <= 0 || share_count <= 0) {
        std::cerr << "Usage: determ-wallet create-recovery "
                     "--seed <hex> --password <str> -t T -n N --out <file> "
                     "[--scheme {passphrase|opaque}]\n";
        return 1;
    }
    if (scheme != "passphrase" && scheme != "opaque") {
        std::cerr << "--scheme must be 'passphrase' or 'opaque'\n"; return 1;
    }
    std::vector<uint8_t> seed;
    try { seed = from_hex(seed_hex); }
    catch (std::exception& e) {
        std::cerr << "Invalid --seed hex: " << e.what() << "\n"; return 1;
    }
    if (seed.empty()) {
        std::cerr << "--seed must be non-empty\n"; return 1;
    }
    auto checksum = recovery::seed_pubkey_checksum(seed);   // empty if seed != 32B
    try {
        auto setup = (scheme == "opaque")
            ? recovery::create_opaque(seed, password,
                                        static_cast<uint8_t>(threshold),
                                        static_cast<uint8_t>(share_count),
                                        checksum)
            : recovery::create       (seed, password,
                                        static_cast<uint8_t>(threshold),
                                        static_cast<uint8_t>(share_count),
                                        checksum);
        std::ofstream f(out_path);
        if (!f) { std::cerr << "Cannot open --out for write: " << out_path << "\n"; return 1; }
        f << recovery::to_json(setup);
        std::cout << "wrote " << out_path << "\n";
        std::cout << "  scheme:        " << setup.scheme       << "\n";
        std::cout << "  threshold:     " << int(setup.threshold)   << " of "
                  << int(setup.share_count) << "\n";
        std::cout << "  secret bytes:  " << setup.secret_len   << "\n";
        std::cout << "  checksum:      " << to_hex(checksum)   << "\n";
    } catch (std::exception& e) {
        std::cerr << "create-recovery error: " << e.what() << "\n"; return 1;
    }
    return 0;
}

int cmd_recover(int argc, char** argv) {
    std::string in_path, password, guardians_csv;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"        && i + 1 < argc) in_path        = argv[++i];
        else if (a == "--password"  && i + 1 < argc) password       = argv[++i];
        else if (a == "--guardians" && i + 1 < argc) guardians_csv  = argv[++i];
    }
    if (in_path.empty() || password.empty()) {
        std::cerr << "Usage: determ-wallet recover --in <file> --password <str> "
                     "[--guardians <csv of 0..N-1 indices>]\n";
        return 1;
    }
    std::ifstream f(in_path);
    if (!f) { std::cerr << "Cannot open --in: " << in_path << "\n"; return 1; }
    std::string blob((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
    auto setup_opt = recovery::from_json(blob);
    if (!setup_opt) {
        std::cerr << "recover: failed to parse recovery setup\n"; return 1;
    }
    std::vector<uint8_t> guardian_indices;
    if (guardians_csv.empty()) {
        for (uint8_t i = 0; i < setup_opt->share_count; ++i)
            guardian_indices.push_back(i);
    } else {
        std::stringstream ss(guardians_csv);
        std::string item;
        while (std::getline(ss, item, ',')) {
            if (item.empty()) continue;
            guardian_indices.push_back(static_cast<uint8_t>(std::stoul(item)));
        }
    }
    auto secret = recovery::recover(*setup_opt, password, guardian_indices);
    if (!secret) {
        std::cerr << "recover: reconstruction failed "
                     "(wrong password, insufficient envelopes decrypted, "
                     "or pubkey checksum mismatch)\n";
        return 2;
    }
    std::cout << to_hex(*secret) << "\n";
    return 0;
}

// A2 Phase 4: smoke test for the libsodium primitives that libopaque
// (Phase 5) will compose. Verifies the FetchContent integration is
// wired correctly + the OPRF math works deterministically.
int cmd_oprf_smoke(int argc, char** argv) {
    (void)argc; (void)argv;
    if (!primitives::init_libsodium()) {
        std::cerr << "init_libsodium failed\n"; return 1;
    }
    // 1. Generate two random ristretto255 scalars (the user's blind r
    //    and the simulated server's key k).
    auto r = primitives::ristretto255_scalar_random();
    auto k = primitives::ristretto255_scalar_random();
    if (r.size() != 32 || k.size() != 32) {
        std::cerr << "scalar_random returned wrong size\n"; return 1;
    }
    // 2. Blind a password into a point (mock client-side OPRF step).
    std::vector<uint8_t> password = {'h','u','n','t','e','r','2'};
    auto blinded = primitives::ristretto255_point_blind(password, r);
    if (blinded.size() != 32) {
        std::cerr << "point_blind failed\n"; return 1;
    }
    // 3. Argon2id stretch (mock OPAQUE password stretching). Uses
    //    libsodium-required 16-byte salt and minimum opslimit for
    //    quick smoke testing.
    auto salt = primitives::random_bytes(16);
    auto stretched = primitives::argon2id(password, salt, 32, 1, 8 * 1024 * 1024);
    if (stretched.size() != 32) {
        std::cerr << "argon2id failed\n"; return 1;
    }
    std::cout << "scalar_r  (32B):  " << to_hex(r) << "\n";
    std::cout << "scalar_k  (32B):  " << to_hex(k) << "\n";
    std::cout << "blinded   (32B):  " << to_hex(blinded) << "\n";
    std::cout << "argon2id  (32B):  " << to_hex(stretched) << "\n";
    std::cout << "libsodium primitives OK\n";
    return 0;
}

// A2 Phase 5: exercise the OPAQUE adapter directly. Used by the
// regression test to confirm the adapter's register/authenticate
// round-trip works and that wrong passwords are rejected.
int cmd_opaque_handshake(int argc, char** argv) {
    std::string mode, password, record_hex;
    int guardian_id = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--mode"        && i + 1 < argc) mode        = argv[++i];
        else if (a == "--password"    && i + 1 < argc) password    = argv[++i];
        else if (a == "--guardian-id" && i + 1 < argc) guardian_id = std::stoi(argv[++i]);
        else if (a == "--record"      && i + 1 < argc) record_hex  = argv[++i];
    }
    if (mode.empty() || password.empty() || guardian_id < 0 || guardian_id > 255) {
        std::cerr << "Usage: determ-wallet opaque-handshake "
                     "--mode {register|authenticate} --password <str> "
                     "--guardian-id <0..255> [--record <hex>]\n";
        return 1;
    }
    if (mode == "register") {
        auto r = opaque_adapter::register_password(password,
                       static_cast<uint8_t>(guardian_id));
        if (!r) { std::cerr << "register failed\n"; return 1; }
        std::cout << "suite:      " << opaque_adapter::suite_name() << "\n";
        std::cout << "is_stub:    " << (opaque_adapter::is_stub() ? "true" : "false") << "\n";
        std::cout << "record:     " << to_hex(r->record)     << "\n";
        std::cout << "export_key: " << to_hex(r->export_key) << "\n";
        return 0;
    }
    if (mode == "authenticate") {
        if (record_hex.empty()) {
            std::cerr << "authenticate requires --record\n"; return 1;
        }
        std::vector<uint8_t> record;
        try { record = from_hex(record_hex); }
        catch (std::exception& e) {
            std::cerr << "record hex: " << e.what() << "\n"; return 1;
        }
        auto k = opaque_adapter::authenticate_password(password, record,
                       static_cast<uint8_t>(guardian_id));
        if (!k) { std::cerr << "authenticate failed\n"; return 2; }
        std::cout << "export_key: " << to_hex(*k) << "\n";
        return 0;
    }
    std::cerr << "Unknown --mode: " << mode << "\n";
    return 1;
}

// Read a `--message <spec>` arg. The spec is either an inline string or
// "file:<path>" to slurp the file's bytes verbatim (binary-safe — no UTF-8
// validation, no newline stripping). Returns false on file-open failure.
//
// Why support file input: message-signing workflows often deal with
// content too large for a command-line arg (full attestation JSON, signed
// release manifest, large SIWE challenge bodies) or that contains shell-
// hostile bytes (NUL, embedded quotes). The `file:` prefix lets operators
// keep the message verbatim in a file and pass the path; the file's
// content is hashed byte-for-byte exactly as it sits on disk.
//
// Newline handling: NO trimming. If an operator wrote the message with
// `echo "foo" > msg.txt`, the trailing '\n' is part of the signed
// content. This is by design — domain-separation only guarantees no
// cross-domain replay; within a domain, callers control the canonical
// byte form.
bool read_message_spec(const std::string& spec,
                       std::vector<uint8_t>& out_bytes,
                       std::string& err) {
    constexpr const char* kFilePrefix = "file:";
    if (spec.size() >= 5 && spec.compare(0, 5, kFilePrefix) == 0) {
        std::string path = spec.substr(5);
        if (path.empty()) {
            err = "--message file: prefix supplied without a path";
            return false;
        }
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            err = std::string("cannot open --message file: ") + path;
            return false;
        }
        std::vector<uint8_t> buf(
            (std::istreambuf_iterator<char>(f)),
             std::istreambuf_iterator<char>());
        out_bytes = std::move(buf);
        return true;
    }
    // Inline string. Bytes are exactly the literal arg passed by the shell.
    out_bytes.assign(spec.begin(), spec.end());
    return true;
}

// Compute the 32-byte SHA-256 commitment that gets signed.
//
// Domain-separation: the hashed pre-image is `domain_tag_bytes || message_bytes`.
// The domain_tag is UTF-8 bytes of the arg as-is (the operator picks the
// canonical form; we don't normalize). Concatenation, not HMAC, because:
//   * the goal is replay-prevention across domains, not authentication of
//     the tag itself (we already authenticate via the Ed25519 signature
//     over the entire pre-image);
//   * SHA-256(tag || msg) is collision-equivalent to (tag, msg) at the
//     security level of SHA-256 — second-preimage resistance dominates;
//   * the protocol-wide convention is SHA-256 + concatenation (matches
//     the `signing_bytes` pattern in PROTOCOL.md).
//
// Length-extension is not a concern here: we never expose the SHA-256
// state, only its final 32-byte digest fed into Ed25519, which is
// itself a hash-and-sign scheme — no raw SHA-256 output is ever
// returned to a third party who could then forge a longer pre-image.
std::array<uint8_t, 32> domain_commit(const std::string& domain_tag,
                                      const std::vector<uint8_t>& msg) {
    std::vector<uint8_t> buf;
    buf.reserve(domain_tag.size() + msg.size());
    buf.insert(buf.end(), domain_tag.begin(), domain_tag.end());
    buf.insert(buf.end(), msg.begin(),        msg.end());
    std::array<uint8_t, 32> out{};
    SHA256(buf.data(), buf.size(), out.data());
    return out;
}

// determ-wallet message-sign — Sign an arbitrary message with an Ed25519
// private key, using a domain-separated SHA-256 commitment as the
// signed pre-image.
//
// Use cases (all OFF-CHAIN — this CLI does NOT produce a transaction):
//   * SIWE-style ("Sign-In With Ethereum") auth challenges, where a
//     web/dapp service issues a nonce and the wallet signs it to prove
//     control of an account address.
//   * Off-chain attestations (operator-signed announcements, version
//     manifests, release artifacts) where a verifier wants to confirm
//     a specific party endorsed a specific message.
//   * Pre-image binding for ZK proofs or commit-reveal protocols where
//     the signed value is later revealed in another protocol step.
//
// Domain separation rationale:
//   A raw Ed25519 signature over `H(message)` would be replay-vulnerable
//   across context: a signature collected for "I authorize transfer X"
//   would validate as "I attest to chain state Y" if both contexts share
//   the same hash. Prepending an unambiguous domain tag before hashing
//   ensures the same message bytes in different domains produce different
//   commitments. Operators pick the tag (e.g. "siwe", "attestation",
//   "op-announcement"); verifiers MUST agree on the tag a priori.
//
// Signed pre-image: SHA-256(domain_tag_utf8_bytes || message_bytes)
// Output: 64-byte Ed25519 signature, hex-encoded (128 chars).
//
// CLI:
//   --priv <hex>:       32-byte Ed25519 seed (64 hex chars). Matches the
//                       `privkey_hex` field emitted by `account create`
//                       or `account-create-batch`.
//   --message <spec>:   inline string OR "file:<path>" to read bytes from
//                       a file. File mode is binary-safe (no newline strip).
//   --domain-tag <tag>: arbitrary domain-separation tag (typically a short
//                       ASCII slug). Required — there's no sensible default.
//   --json:             emit a JSON document instead of human lines.
//
// Output:
//   Human mode (default):
//     signature_hex:    <128 hex chars>
//     pubkey_hex:       <64 hex chars derived from the priv seed>
//     message_hash_hex: <64 hex chars = SHA-256 commitment>
//     domain_tag:       <tag verbatim>
//   --json mode:
//     {"signature_hex": "...", "pubkey_hex": "...",
//      "message_hash_hex": "...", "domain_tag": "..."}
//
// Exit codes:
//   0  signature emitted
//   1  args / parse / libsodium-init error
int cmd_message_sign(int argc, char** argv) {
    std::string priv_hex, message_spec, domain_tag;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--priv"       && i + 1 < argc) priv_hex     = argv[++i];
        else if (a == "--message"    && i + 1 < argc) message_spec = argv[++i];
        else if (a == "--domain-tag" && i + 1 < argc) domain_tag   = argv[++i];
        else if (a == "--json")                       json_out     = true;
        else {
            std::cerr << "message-sign: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet message-sign --priv <hex> "
                         "--message <string|file:path> --domain-tag <tag> [--json]\n";
            return 1;
        }
    }
    if (priv_hex.empty() || message_spec.empty() || domain_tag.empty()) {
        std::cerr << "Usage: determ-wallet message-sign --priv <hex> "
                     "--message <string|file:path> --domain-tag <tag> [--json]\n"
                     "\n"
                     "  Signs message with an Ed25519 private key using a\n"
                     "  domain-separated SHA-256 commitment as the signed\n"
                     "  pre-image: H = SHA-256(domain_tag || message_bytes).\n"
                     "  This is OFF-CHAIN signing — does not produce a tx.\n";
        return 1;
    }

    // Decode the priv seed (must be exactly 32 bytes = 64 hex chars).
    if (priv_hex.size() != 64) {
        std::cerr << "message-sign: --priv must be exactly 64 hex chars "
                     "(32-byte Ed25519 seed); got " << priv_hex.size() << " chars\n";
        return 1;
    }
    std::vector<uint8_t> priv_seed;
    try { priv_seed = from_hex(priv_hex); }
    catch (std::exception& e) {
        std::cerr << "message-sign: invalid --priv hex: " << e.what() << "\n";
        return 1;
    }
    if (priv_seed.size() != 32) {
        std::cerr << "message-sign: --priv decoded to " << priv_seed.size()
                  << " bytes (expected 32)\n";
        return 1;
    }

    // Load the message bytes (inline or file).
    std::vector<uint8_t> msg;
    {
        std::string err;
        if (!read_message_spec(message_spec, msg, err)) {
            std::cerr << "message-sign: " << err << "\n";
            return 1;
        }
    }
    // Empty message is permitted (an attestation might sign just the
    // domain tag itself — a "I am present in domain X" beacon).

    // Init libsodium (idempotent; safe to call repeatedly).
    if (!primitives::init_libsodium()) {
        std::cerr << "message-sign: libsodium init failed\n";
        return 1;
    }

    // Derive the Ed25519 keypair from the 32-byte seed. libsodium's
    // crypto_sign_detached needs the 64-byte secret key (seed || pubkey);
    // crypto_sign_seed_keypair fills both pubkey and sk from the seed.
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pub{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    static_assert(crypto_sign_PUBLICKEYBYTES == 32, "Ed25519 pk size mismatch");
    static_assert(crypto_sign_SECRETKEYBYTES == 64, "Ed25519 sk size mismatch");
    static_assert(crypto_sign_SEEDBYTES      == 32, "Ed25519 seed size mismatch");
    if (crypto_sign_seed_keypair(pub.data(), sk.data(), priv_seed.data()) != 0) {
        std::cerr << "message-sign: crypto_sign_seed_keypair failed\n";
        return 1;
    }

    // Compute the domain-separated commitment.
    auto hash = domain_commit(domain_tag, msg);

    // Sign the commitment with crypto_sign_detached (deterministic per
    // RFC 8032 — no nonce input, same priv+msg always yields same sig).
    std::array<uint8_t, crypto_sign_BYTES> sig{};
    static_assert(crypto_sign_BYTES == 64, "Ed25519 sig size mismatch");
    unsigned long long sig_len = 0;
    if (crypto_sign_detached(sig.data(), &sig_len,
                              hash.data(), hash.size(),
                              sk.data()) != 0) {
        std::cerr << "message-sign: crypto_sign_detached failed\n";
        return 1;
    }
    if (sig_len != crypto_sign_BYTES) {
        std::cerr << "message-sign: unexpected sig length " << sig_len << "\n";
        return 1;
    }

    // Zero the secret-key buffer before returning. The seed remains in
    // priv_seed (operator-supplied), but the libsodium-derived sk
    // contains the seed concatenated with the pubkey; sodium_memzero
    // is the libsodium-blessed scrub.
    sodium_memzero(sk.data(), sk.size());

    if (json_out) {
        nlohmann::json r;
        r["signature_hex"]    = to_hex(sig);
        r["pubkey_hex"]       = to_hex(pub);
        r["message_hash_hex"] = to_hex(hash);
        r["domain_tag"]       = domain_tag;
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "signature_hex:    " << to_hex(sig)  << "\n";
        std::cout << "pubkey_hex:       " << to_hex(pub)  << "\n";
        std::cout << "message_hash_hex: " << to_hex(hash) << "\n";
        std::cout << "domain_tag:       " << domain_tag   << "\n";
    }
    return 0;
}

// determ-wallet message-verify — Verify an Ed25519 signature over a
// domain-separated SHA-256 commitment of a message.
//
// Inverse of message-sign. Verifier reconstructs the same commitment
// (SHA-256(domain_tag || message_bytes)) and checks crypto_sign_verify_detached
// against the supplied pubkey.
//
// CLI:
//   --pubkey <hex>:     32-byte Ed25519 public key (64 hex chars).
//   --message <spec>:   inline string OR "file:<path>" — same convention as
//                       message-sign. Must be byte-identical to what was signed.
//   --domain-tag <tag>: MUST exactly match the tag used at sign time.
//                       Any deviation produces a different commitment and
//                       the signature fails to verify (the protective property).
//   --signature <hex>:  128 hex chars (64-byte Ed25519 sig).
//   --json:             emit a JSON document instead of human "valid: ..." text.
//
// Exit codes:
//   0  signature valid (PASS)
//   1  args / parse error (operator error, not auth failure)
//   2  signature invalid — auth-style alert gate (distinct from arg errors
//      so monitoring scripts can branch on auth-fail vs. tooling-fail)
//
// Why exit 2 for invalid: matches the convention used by envelope decrypt
// and inspect-envelope when the artifact is structurally fine but
// authentication fails. Exit-1-for-everything would force every consumer
// to grep stderr to distinguish "bad args" from "signature rejected."
int cmd_message_verify(int argc, char** argv) {
    std::string pubkey_hex, message_spec, domain_tag, signature_hex;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--pubkey"     && i + 1 < argc) pubkey_hex     = argv[++i];
        else if (a == "--message"    && i + 1 < argc) message_spec   = argv[++i];
        else if (a == "--domain-tag" && i + 1 < argc) domain_tag     = argv[++i];
        else if (a == "--signature"  && i + 1 < argc) signature_hex  = argv[++i];
        else if (a == "--json")                       json_out       = true;
        else {
            std::cerr << "message-verify: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet message-verify --pubkey <hex> "
                         "--message <string|file:path> --domain-tag <tag> "
                         "--signature <hex> [--json]\n";
            return 1;
        }
    }
    if (pubkey_hex.empty() || message_spec.empty()
        || domain_tag.empty() || signature_hex.empty()) {
        std::cerr << "Usage: determ-wallet message-verify --pubkey <hex> "
                     "--message <string|file:path> --domain-tag <tag> "
                     "--signature <hex> [--json]\n"
                     "\n"
                     "  Verifies an Ed25519 signature was produced over\n"
                     "  H = SHA-256(domain_tag || message_bytes). Inverse of\n"
                     "  message-sign. Exit 0 = valid, 2 = invalid (auth-style\n"
                     "  alert), 1 = args/parse error.\n";
        return 1;
    }

    if (pubkey_hex.size() != 64) {
        std::cerr << "message-verify: --pubkey must be exactly 64 hex chars "
                     "(32-byte Ed25519 pubkey); got " << pubkey_hex.size() << "\n";
        return 1;
    }
    if (signature_hex.size() != 128) {
        std::cerr << "message-verify: --signature must be exactly 128 hex chars "
                     "(64-byte Ed25519 signature); got "
                  << signature_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> pub_bytes, sig_bytes;
    try { pub_bytes = from_hex(pubkey_hex);    }
    catch (std::exception& e) {
        std::cerr << "message-verify: invalid --pubkey hex: " << e.what() << "\n";
        return 1;
    }
    try { sig_bytes = from_hex(signature_hex); }
    catch (std::exception& e) {
        std::cerr << "message-verify: invalid --signature hex: " << e.what() << "\n";
        return 1;
    }
    if (pub_bytes.size() != 32) {
        std::cerr << "message-verify: pubkey decoded to " << pub_bytes.size()
                  << " bytes (expected 32)\n";
        return 1;
    }
    if (sig_bytes.size() != 64) {
        std::cerr << "message-verify: signature decoded to " << sig_bytes.size()
                  << " bytes (expected 64)\n";
        return 1;
    }

    std::vector<uint8_t> msg;
    {
        std::string err;
        if (!read_message_spec(message_spec, msg, err)) {
            std::cerr << "message-verify: " << err << "\n";
            return 1;
        }
    }

    if (!primitives::init_libsodium()) {
        std::cerr << "message-verify: libsodium init failed\n";
        return 1;
    }

    auto hash = domain_commit(domain_tag, msg);

    // crypto_sign_verify_detached returns 0 on valid, -1 on invalid.
    // It is the constant-time verifier that should be used here.
    int rc = crypto_sign_verify_detached(sig_bytes.data(),
                                          hash.data(), hash.size(),
                                          pub_bytes.data());
    const bool valid = (rc == 0);

    if (json_out) {
        nlohmann::json r;
        r["valid"]            = valid;
        r["message_hash_hex"] = to_hex(hash);
        r["domain_tag"]       = domain_tag;
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "valid:            " << (valid ? "true" : "false") << "\n";
        std::cout << "message_hash_hex: " << to_hex(hash) << "\n";
        std::cout << "domain_tag:       " << domain_tag   << "\n";
    }
    return valid ? 0 : 2;
}

// determ-wallet derive-shared-secret — X25519 Diffie-Hellman shared-secret
// agreement between two anon-address holders, for off-chain message
// encryption.
//
// Use case:
//   Two anon-address holders (each with an Ed25519 keypair on-chain) want
//   to send each other end-to-end encrypted off-chain messages WITHOUT
//   negotiating a fresh session key over the network. Each party can
//   independently compute the same 32-byte shared secret from
//     - their own Ed25519 priv_seed (kept private), and
//     - the peer's Ed25519 pubkey (public, IS the peer's anon-address).
//   The shared secret is then used as a KDF input (e.g. HKDF-SHA-256) to
//   derive symmetric AEAD keys for the actual ciphertext layer. This CLI
//   does NOT do the KDF or AEAD itself — it just emits the raw X25519
//   shared secret. The caller composes that with a KDF + AEAD primitive
//   of their choice.
//
// Mechanism:
//   1. Load the operator's wallet account JSON ({"address":"0x..",
//      "privkey_hex":".."}, same shape account-export reads). The
//      privkey_hex is a 32-byte Ed25519 priv_seed.
//   2. Run crypto_sign_ed25519_seed_keypair to materialize the 64-byte
//      Ed25519 SK (seed||pubkey).
//   3. crypto_sign_ed25519_sk_to_curve25519 maps the Ed25519 SK to a
//      32-byte X25519 SK. The libsodium primitive performs the standard
//      RFC-7748 / RFC-8032 transform: SHA-512(priv_seed)[0..32] then
//      clamp (clear bits 0-2 of byte 0, clear bit 7 of byte 31, set bit
//      6 of byte 31).
//   4. crypto_sign_ed25519_pk_to_curve25519 maps the peer's Ed25519 PK
//      to a 32-byte X25519 PK (Edwards-curve y-coordinate -> Montgomery
//      u-coordinate via (1+y)/(1-y) mod p).
//   5. crypto_scalarmult(shared, my_x25519_sk, peer_x25519_pk) computes
//      the 32-byte raw X25519 shared point. This IS the shared secret;
//      DH symmetry guarantees A computing scalarmult(sk_A, pk_B) and B
//      computing scalarmult(sk_B, pk_A) yield byte-identical outputs.
//
// CLI:
//   --priv-keyfile <path>: path to a wallet account JSON file with
//                          {"address":"0x..","privkey_hex":".."} shape
//                          (same as account-export consumes). The
//                          privkey_hex is the operator's 32-byte Ed25519
//                          priv_seed.
//   --pubkey <hex>:        peer's 32-byte Ed25519 pubkey (64 lowercase
//                          hex chars). For anon-address holders this is
//                          their anon-address minus the "0x" prefix.
//   --json:                emit {"shared_secret_hex":"..."} on stdout
//                          (default — task spec calls for the one-line
//                          JSON form; the --json flag here is for parity
//                          with sibling CLIs and is effectively a no-op).
//
// Output:
//   {"shared_secret_hex": "<64 lowercase hex chars>"}
//   exactly one line on stdout, terminated by LF.
//
// Exit codes:
//   0  success
//   1  args / IO / parse / hex-decode / shape error
//   2  crypto failure (curve25519 conversion or scalarmult returned
//      non-zero — should not happen with well-formed Ed25519 inputs;
//      surfaced for defense-in-depth)
//
// Security notes:
//   * The raw X25519 output should NOT be used as an AEAD key directly.
//     Always feed it through a KDF first (HKDF-SHA-256, BLAKE2b, etc.)
//     with a domain-separation tag binding the protocol context.
//   * The shared secret IS deterministic from (priv_A, pub_B): two
//     invocations with the same inputs always yield the same output.
//     This is the DH-symmetry property the test exercises.
//   * sodium_memzero is called on every intermediate SK buffer before
//     return; the shared secret itself is the function's output so we
//     don't scrub it (the caller is responsible for downstream handling).
//
// Why no AAD / no domain tag here:
//   The raw X25519 primitive has no notion of context. Domain separation
//   belongs in the KDF step the caller layers on top. Bundling a domain
//   tag into THIS CLI would conflate the DH primitive with the higher-
//   level protocol — those are separately-specified concerns.
int cmd_derive_shared_secret(int argc, char** argv) {
    std::string priv_keyfile, peer_pubkey_hex;
    bool json_out = false;  // reserved for parity; output is always JSON
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--priv-keyfile" && i + 1 < argc) priv_keyfile    = argv[++i];
        else if (a == "--pubkey"       && i + 1 < argc) peer_pubkey_hex = argv[++i];
        else if (a == "--json")                         json_out        = true;
        else {
            std::cerr << "derive-shared-secret: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet derive-shared-secret "
                         "--priv-keyfile <path> --pubkey <hex> [--json]\n";
            return 1;
        }
    }
    (void)json_out;  // output is always one-line JSON per task spec
    if (priv_keyfile.empty() || peer_pubkey_hex.empty()) {
        std::cerr << "Usage: determ-wallet derive-shared-secret "
                     "--priv-keyfile <path> --pubkey <hex> [--json]\n"
                     "\n"
                     "  Computes a 32-byte X25519 Diffie-Hellman shared\n"
                     "  secret between the priv-keyfile holder and the\n"
                     "  --pubkey peer. Suitable as a KDF input for off-\n"
                     "  chain message encryption between two anon-address\n"
                     "  holders. Output: {\"shared_secret_hex\":\"...\"} JSON.\n";
        return 1;
    }

    // ── Load the priv keyfile ──────────────────────────────────────────────
    // Same shape as cmd_account_export consumes: a single-account JSON file
    // with {"address":"0x..","privkey_hex":".."} where privkey_hex is the
    // 32-byte Ed25519 priv_seed.
    std::ifstream in_f(priv_keyfile);
    if (!in_f) {
        std::cerr << "derive-shared-secret: cannot open --priv-keyfile: "
                  << priv_keyfile << "\n";
        return 1;
    }
    nlohmann::json acc_doc;
    try {
        in_f >> acc_doc;
    } catch (std::exception& e) {
        std::cerr << "derive-shared-secret: --priv-keyfile is not valid JSON: "
                  << e.what() << "\n";
        return 1;
    }
    if (!acc_doc.is_object()) {
        std::cerr << "derive-shared-secret: --priv-keyfile must be a JSON "
                     "object {\"address\":..., \"privkey_hex\":...}; got non-"
                     "object\n";
        return 1;
    }
    if (!acc_doc.contains("privkey_hex")
        || !acc_doc["privkey_hex"].is_string()) {
        std::cerr << "derive-shared-secret: --priv-keyfile missing required "
                     "string field 'privkey_hex'\n";
        return 1;
    }
    std::string priv_hex = acc_doc["privkey_hex"].get<std::string>();
    if (priv_hex.size() != 64) {
        std::cerr << "derive-shared-secret: 'privkey_hex' must be 64 hex "
                     "chars (32-byte Ed25519 priv_seed); got length "
                  << priv_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> priv_seed;
    try { priv_seed = from_hex(priv_hex); }
    catch (std::exception& e) {
        std::cerr << "derive-shared-secret: 'privkey_hex' is not valid hex: "
                  << e.what() << "\n";
        return 1;
    }
    if (priv_seed.size() != 32) {
        std::cerr << "derive-shared-secret: 'privkey_hex' decoded length "
                     "must be 32; got " << priv_seed.size() << "\n";
        return 1;
    }

    // ── Parse the peer pubkey hex ──────────────────────────────────────────
    // 32-byte Ed25519 pubkey = 64 lowercase hex chars. We do NOT accept the
    // "0x" prefix here — callers extracting from an anon-address must strip
    // the prefix first. This matches the message-verify --pubkey convention.
    if (peer_pubkey_hex.size() != 64) {
        std::cerr << "derive-shared-secret: --pubkey must be 64 hex chars "
                     "(32-byte Ed25519 pubkey); got length "
                  << peer_pubkey_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> peer_pub_bytes;
    try { peer_pub_bytes = from_hex(peer_pubkey_hex); }
    catch (std::exception& e) {
        std::cerr << "derive-shared-secret: --pubkey is not valid hex: "
                  << e.what() << "\n";
        return 1;
    }
    if (peer_pub_bytes.size() != 32) {
        std::cerr << "derive-shared-secret: --pubkey decoded length must "
                     "be 32; got " << peer_pub_bytes.size() << "\n";
        return 1;
    }

    // ── Init libsodium ─────────────────────────────────────────────────────
    if (!primitives::init_libsodium()) {
        std::cerr << "derive-shared-secret: libsodium init failed\n";
        return 1;
    }

    // ── Step 1: derive the operator's Ed25519 64-byte SK from the seed ─────
    // libsodium's crypto_sign_ed25519_sk_to_curve25519 needs the full
    // 64-byte SK (seed||pubkey), not just the 32-byte seed. Derive both
    // halves from the 32-byte seed via crypto_sign_ed25519_seed_keypair —
    // same primitive used by message-sign / account-import. The pubkey
    // half is discarded (we only need the SK for the curve25519 transform).
    static_assert(crypto_sign_PUBLICKEYBYTES == 32, "Ed25519 pk size mismatch");
    static_assert(crypto_sign_SECRETKEYBYTES == 64, "Ed25519 sk size mismatch");
    static_assert(crypto_sign_SEEDBYTES      == 32, "Ed25519 seed size mismatch");
    static_assert(crypto_scalarmult_BYTES    == 32, "X25519 output size mismatch");
    static_assert(crypto_scalarmult_SCALARBYTES == 32,
                  "X25519 scalar size mismatch");

    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> ed_pub{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> ed_sk{};
    if (crypto_sign_ed25519_seed_keypair(ed_pub.data(), ed_sk.data(),
                                         priv_seed.data()) != 0) {
        std::cerr << "derive-shared-secret: crypto_sign_ed25519_seed_keypair "
                     "failed (priv_seed not a valid Ed25519 seed)\n";
        return 1;
    }

    // ── Step 2: Ed25519 SK -> X25519 SK ────────────────────────────────────
    // RFC-7748-style transform: SHA-512(priv_seed)[0..32], clamp per spec.
    // libsodium does this internally and returns a clamped 32-byte X25519
    // secret scalar suitable for crypto_scalarmult.
    std::array<uint8_t, crypto_scalarmult_SCALARBYTES> my_x25519_sk{};
    if (crypto_sign_ed25519_sk_to_curve25519(my_x25519_sk.data(),
                                              ed_sk.data()) != 0) {
        sodium_memzero(ed_sk.data(),         ed_sk.size());
        sodium_memzero(my_x25519_sk.data(),  my_x25519_sk.size());
        std::cerr << "derive-shared-secret: crypto_sign_ed25519_sk_to_"
                     "curve25519 failed\n";
        return 2;
    }
    // ed_sk is no longer needed (X25519 SK already derived). Scrub it.
    sodium_memzero(ed_sk.data(), ed_sk.size());

    // ── Step 3: peer Ed25519 PK -> peer X25519 PK ──────────────────────────
    // Maps the Edwards-curve y-coordinate to the Montgomery u-coordinate
    // via (1+y)/(1-y) mod p. Returns non-zero if the pubkey is malformed
    // (e.g. not a valid Edwards point); we surface that as exit 2.
    std::array<uint8_t, crypto_scalarmult_BYTES> peer_x25519_pk{};
    if (crypto_sign_ed25519_pk_to_curve25519(peer_x25519_pk.data(),
                                              peer_pub_bytes.data()) != 0) {
        sodium_memzero(my_x25519_sk.data(), my_x25519_sk.size());
        std::cerr << "derive-shared-secret: crypto_sign_ed25519_pk_to_"
                     "curve25519 failed (peer pubkey not a valid Ed25519 "
                     "pubkey)\n";
        return 2;
    }

    // ── Step 4: X25519 scalarmult ──────────────────────────────────────────
    // crypto_scalarmult(out, sk, pk) computes the raw X25519 DH output.
    // Returns non-zero ONLY if the result is the all-zero point (a small-
    // subgroup attack indicator); libsodium rejects those automatically.
    std::array<uint8_t, crypto_scalarmult_BYTES> shared{};
    if (crypto_scalarmult(shared.data(),
                           my_x25519_sk.data(),
                           peer_x25519_pk.data()) != 0) {
        sodium_memzero(my_x25519_sk.data(), my_x25519_sk.size());
        sodium_memzero(shared.data(),       shared.size());
        std::cerr << "derive-shared-secret: crypto_scalarmult failed "
                     "(degenerate shared point — peer pubkey likely in a "
                     "small subgroup)\n";
        return 2;
    }
    // Scrub the X25519 SK now that the shared secret is computed.
    sodium_memzero(my_x25519_sk.data(), my_x25519_sk.size());

    // ── Emit the one-line JSON output ──────────────────────────────────────
    // {"shared_secret_hex":"<64 lowercase hex>"}
    // Use nlohmann::json::dump() (no indent) for compact single-line form.
    nlohmann::json out_doc = { {"shared_secret_hex", to_hex(shared)} };
    std::cout << out_doc.dump() << "\n";
    return 0;
}

// ── Helpers shared by encrypt-message / decrypt-message ────────────────────────
//
// These build on the X25519 DH machinery already exercised by
// cmd_derive_shared_secret, then HKDF-SHA-256 the raw DH output into a
// 32-byte AEAD key. The same code path runs on both sides of the
// conversation: DH symmetry guarantees A's and B's `shared` bytes match,
// and the HKDF salt is constructed from BOTH parties' pubkeys in a
// canonical (byte-lex-min || byte-lex-max) order so the derived AEAD
// key is identical regardless of which side initiates.
//
// Why HKDF + a 32-byte key (rather than feeding the raw X25519 output
// directly into AES-GCM):
//   * The raw X25519 output is not uniformly distributed — it's a point
//     on the curve and small-subgroup attacks can bias certain bits.
//     RFC 7748 §6.1 explicitly recommends "hashing the secret with
//     other inputs" before using it as a symmetric key. HKDF-SHA-256
//     is the canonical NIST SP 800-56C extract-then-expand instance
//     and what FIPS-mode deployments are expected to use.
//   * Salt = concat(min(pub_a, pub_b), max(pub_a, pub_b)) binds the
//     KDF output to BOTH parties' identities. Without salt, an
//     adversary who somehow recovered the DH secret could replay it
//     into a different protocol context. With salt, derived keys are
//     pinned to this exact pair-and-protocol triple.
//   * Info = "DETERM-CHAT-AEAD-v1" provides explicit domain separation:
//     even if the same DH secret were reused in a future protocol
//     (it shouldn't be, but defense-in-depth), the HKDF info tag
//     ensures derived keys diverge.
//
// HKDF-SHA-256 is implemented inline via OpenSSL's HMAC (extract +
// expand are both HMAC-SHA-256 calls). For a 32-byte output we need
// exactly ONE expand iteration (HashLen = 32, L <= HashLen), so the
// implementation collapses to: PRK = HMAC(salt, IKM); OKM = HMAC(PRK,
// info || 0x01)[:32]. RFC 5869 §2 spells out the construction.
namespace {

// Run the same X25519 DH dance as cmd_derive_shared_secret but as a
// reusable function. Inputs are validated by the caller (size, hex
// shape); this just runs the libsodium calls and returns the 32-byte
// shared secret. `my_pub_out` echoes back the caller's own Ed25519
// pubkey (derived from the seed) so the salt computation can compare
// it against the peer pubkey. On any failure, returns false and
// scrubs intermediates; the caller emits the appropriate diagnostic.
bool derive_shared_secret_bytes(
        const std::vector<uint8_t>&          priv_seed,    // 32B Ed25519 seed
        const std::vector<uint8_t>&          peer_pub,     // 32B Ed25519 pub
        std::array<uint8_t, 32>&             shared_out,   // 32B X25519 out
        std::array<uint8_t, 32>&             my_pub_out,   // 32B Ed25519 pub
        std::string&                          err_kind_out) {
    static_assert(crypto_sign_PUBLICKEYBYTES   == 32, "Ed25519 pk size");
    static_assert(crypto_sign_SECRETKEYBYTES   == 64, "Ed25519 sk size");
    static_assert(crypto_sign_SEEDBYTES        == 32, "Ed25519 seed size");
    static_assert(crypto_scalarmult_BYTES      == 32, "X25519 output size");
    static_assert(crypto_scalarmult_SCALARBYTES== 32, "X25519 scalar size");

    if (priv_seed.size() != 32 || peer_pub.size() != 32) {
        err_kind_out = "bad-input-size";
        return false;
    }

    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> ed_sk{};
    if (crypto_sign_ed25519_seed_keypair(my_pub_out.data(), ed_sk.data(),
                                          priv_seed.data()) != 0) {
        err_kind_out = "seed-keypair-failed";
        return false;
    }

    std::array<uint8_t, crypto_scalarmult_SCALARBYTES> my_x25519_sk{};
    if (crypto_sign_ed25519_sk_to_curve25519(my_x25519_sk.data(),
                                              ed_sk.data()) != 0) {
        sodium_memzero(ed_sk.data(),        ed_sk.size());
        sodium_memzero(my_x25519_sk.data(), my_x25519_sk.size());
        err_kind_out = "sk-to-curve25519-failed";
        return false;
    }
    sodium_memzero(ed_sk.data(), ed_sk.size());

    std::array<uint8_t, crypto_scalarmult_BYTES> peer_x25519_pk{};
    if (crypto_sign_ed25519_pk_to_curve25519(peer_x25519_pk.data(),
                                              peer_pub.data()) != 0) {
        sodium_memzero(my_x25519_sk.data(), my_x25519_sk.size());
        err_kind_out = "pk-to-curve25519-failed";
        return false;
    }

    if (crypto_scalarmult(shared_out.data(),
                           my_x25519_sk.data(),
                           peer_x25519_pk.data()) != 0) {
        sodium_memzero(my_x25519_sk.data(), my_x25519_sk.size());
        sodium_memzero(shared_out.data(),    shared_out.size());
        err_kind_out = "scalarmult-failed";
        return false;
    }
    sodium_memzero(my_x25519_sk.data(), my_x25519_sk.size());
    return true;
}

// HKDF-SHA-256 specialized for L = 32 bytes (= HashLen, so one HMAC
// expand iteration suffices). RFC 5869 §2 construction:
//   PRK = HMAC-SHA-256(salt, IKM)
//   OKM = HMAC-SHA-256(PRK, info || 0x01)
// Both sides MUST compute the same salt (canonical byte-min || byte-max
// of the two pubkeys) for the output key to match.
//
// Returns true on success; on failure scrubs PRK + key_out and sets
// err_kind_out for the caller's diagnostic.
bool hkdf_sha256_32(const std::array<uint8_t, 32>& ikm,
                      const std::vector<uint8_t>&   salt,
                      const std::string&             info,
                      std::array<uint8_t, 32>&       key_out,
                      std::string&                   err_kind_out) {
    // Extract: PRK = HMAC-SHA-256(salt, IKM)
    unsigned char prk[32]{};
    unsigned int  prk_len = 0;
    if (!HMAC(EVP_sha256(),
              salt.data(), static_cast<int>(salt.size()),
              ikm.data(),  ikm.size(),
              prk, &prk_len)
        || prk_len != 32) {
        sodium_memzero(prk, sizeof(prk));
        err_kind_out = "hkdf-extract-failed";
        return false;
    }

    // Expand: OKM_1 = HMAC-SHA-256(PRK, info || 0x01)
    //   For L = 32 = HashLen, one block is sufficient.
    std::vector<uint8_t> expand_msg;
    expand_msg.reserve(info.size() + 1);
    for (char c : info) expand_msg.push_back(static_cast<uint8_t>(c));
    expand_msg.push_back(0x01);

    unsigned char okm[32]{};
    unsigned int  okm_len = 0;
    if (!HMAC(EVP_sha256(),
              prk, prk_len,
              expand_msg.data(), expand_msg.size(),
              okm, &okm_len)
        || okm_len != 32) {
        sodium_memzero(prk, sizeof(prk));
        sodium_memzero(okm, sizeof(okm));
        err_kind_out = "hkdf-expand-failed";
        return false;
    }
    sodium_memzero(prk, sizeof(prk));

    std::memcpy(key_out.data(), okm, 32);
    sodium_memzero(okm, sizeof(okm));
    return true;
}

// Build the canonical HKDF salt: byte-lex-min(pub_a, pub_b) ||
// byte-lex-max(pub_a, pub_b). Symmetric in the inputs, so A and B
// derive the same salt regardless of which side initiates.
std::vector<uint8_t> chat_aead_salt(const std::array<uint8_t, 32>& my_pub,
                                       const std::vector<uint8_t>&    peer_pub) {
    std::vector<uint8_t> salt(64);
    // Compare byte-by-byte (C++ <=> on arrays of unsigned bytes).
    bool peer_lower = false;
    for (size_t i = 0; i < 32; ++i) {
        if (peer_pub[i] < my_pub[i]) { peer_lower = true;  break; }
        if (peer_pub[i] > my_pub[i]) { peer_lower = false; break; }
    }
    const uint8_t* lo = peer_lower ? peer_pub.data() : my_pub.data();
    const uint8_t* hi = peer_lower ? my_pub.data()   : peer_pub.data();
    std::memcpy(salt.data(),       lo, 32);
    std::memcpy(salt.data() + 32,  hi, 32);
    return salt;
}

// AES-256-GCM raw encrypt with a caller-supplied 32-byte key and 12-byte
// nonce. Returns ciphertext_with_tag (plaintext.size() + 16 bytes).
// On any OpenSSL failure throws std::runtime_error; the caller's
// outer try/catch surfaces it as exit-1 JSON-error output.
std::vector<uint8_t> aes256_gcm_encrypt_raw(
        const std::array<uint8_t, 32>& key,
        const std::array<uint8_t, 12>& nonce,
        const std::vector<uint8_t>&     plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("aead: EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                              nullptr, nullptr) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1
        || EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                                  key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("aead: EncryptInit failed");
    }

    std::vector<uint8_t> out(plaintext.size() + 16);
    int outlen = 0;
    if (!plaintext.empty()
        && EVP_EncryptUpdate(ctx, out.data(), &outlen,
                                plaintext.data(),
                                static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("aead: EncryptUpdate failed");
    }
    int ct_len = outlen;

    if (EVP_EncryptFinal_ex(ctx, out.data() + ct_len, &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("aead: EncryptFinal failed");
    }
    ct_len += outlen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                                out.data() + ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("aead: GET_TAG failed");
    }
    ct_len += 16;
    out.resize(static_cast<size_t>(ct_len));

    EVP_CIPHER_CTX_free(ctx);
    return out;
}

// AES-256-GCM raw decrypt. Returns std::nullopt on tag-verify failure
// (tampered ciphertext, wrong key, wrong nonce); throws on hard
// OpenSSL failure. ciphertext_with_tag must include the trailing
// 16-byte GCM tag.
std::optional<std::vector<uint8_t>> aes256_gcm_decrypt_raw(
        const std::array<uint8_t, 32>&  key,
        const std::array<uint8_t, 12>&  nonce,
        const std::vector<uint8_t>&     ciphertext_with_tag) {
    if (ciphertext_with_tag.size() < 16) return std::nullopt;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("aead: EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                              nullptr, nullptr) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1
        || EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                                  key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("aead: DecryptInit failed");
    }

    const size_t ct_body_len = ciphertext_with_tag.size() - 16;
    std::vector<uint8_t> pt(ct_body_len);
    int outlen = 0;
    if (ct_body_len > 0
        && EVP_DecryptUpdate(ctx, pt.data(), &outlen,
                                ciphertext_with_tag.data(),
                                static_cast<int>(ct_body_len)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("aead: DecryptUpdate failed");
    }
    int pt_len = outlen;

    // Set expected tag from the trailing 16 bytes of the input buffer.
    std::vector<uint8_t> tag(ciphertext_with_tag.end() - 16,
                                ciphertext_with_tag.end());
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("aead: SET_TAG failed");
    }

    int rc = EVP_DecryptFinal_ex(ctx, pt.data() + pt_len, &outlen);
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 1) return std::nullopt;     // tag verify failed
    pt_len += outlen;
    pt.resize(static_cast<size_t>(pt_len));
    return pt;
}

// Read an entire file into a byte vector. Returns std::nullopt on
// open/read failure; the caller emits the appropriate diagnostic.
// Streaming would matter for large files, but for off-chain message
// payloads we're firmly in "small enough to fit in RAM" territory.
std::optional<std::vector<uint8_t>> read_file_bytes(const std::string& path) {
    std::ifstream in_f(path, std::ios::binary);
    if (!in_f) return std::nullopt;
    in_f.seekg(0, std::ios::end);
    std::streamoff sz = in_f.tellg();
    if (sz < 0) return std::nullopt;
    in_f.seekg(0, std::ios::beg);
    std::vector<uint8_t> out(static_cast<size_t>(sz));
    if (sz > 0)
        in_f.read(reinterpret_cast<char*>(out.data()), sz);
    if (in_f.fail() && !in_f.eof()) return std::nullopt;
    return out;
}

// Write a byte vector to a file, truncating any existing content.
// Returns true on success.
bool write_file_bytes(const std::string& path,
                       const std::vector<uint8_t>& data) {
    std::ofstream out_f(path, std::ios::binary | std::ios::trunc);
    if (!out_f) return false;
    if (!data.empty())
        out_f.write(reinterpret_cast<const char*>(data.data()),
                    static_cast<std::streamsize>(data.size()));
    return out_f.good();
}

// Load the operator's priv_seed + Ed25519 pubkey from a single-account
// JSON keyfile ({"address":"0x..","privkey_hex":".."}). Used by both
// encrypt-message and decrypt-message. On any error, prints a
// diagnostic (prefixed by `cmd_label`) and returns false.
bool load_priv_keyfile(const std::string& path,
                         const std::string& cmd_label,
                         std::vector<uint8_t>& priv_seed_out) {
    std::ifstream in_f(path);
    if (!in_f) {
        std::cerr << cmd_label << ": cannot open --priv-keyfile: "
                  << path << "\n";
        return false;
    }
    nlohmann::json acc_doc;
    try { in_f >> acc_doc; }
    catch (std::exception& e) {
        std::cerr << cmd_label << ": --priv-keyfile is not valid JSON: "
                  << e.what() << "\n";
        return false;
    }
    if (!acc_doc.is_object()) {
        std::cerr << cmd_label << ": --priv-keyfile must be a JSON object "
                     "{\"address\":..., \"privkey_hex\":...}; got non-object\n";
        return false;
    }
    if (!acc_doc.contains("privkey_hex")
        || !acc_doc["privkey_hex"].is_string()) {
        std::cerr << cmd_label << ": --priv-keyfile missing required string "
                     "field 'privkey_hex'\n";
        return false;
    }
    std::string priv_hex = acc_doc["privkey_hex"].get<std::string>();
    if (priv_hex.size() != 64) {
        std::cerr << cmd_label << ": 'privkey_hex' must be 64 hex chars "
                     "(32-byte Ed25519 priv_seed); got length "
                  << priv_hex.size() << "\n";
        return false;
    }
    try { priv_seed_out = from_hex(priv_hex); }
    catch (std::exception& e) {
        std::cerr << cmd_label << ": 'privkey_hex' is not valid hex: "
                  << e.what() << "\n";
        return false;
    }
    if (priv_seed_out.size() != 32) {
        std::cerr << cmd_label << ": 'privkey_hex' decoded length must be 32; "
                     "got " << priv_seed_out.size() << "\n";
        return false;
    }
    return true;
}

} // namespace

// determ-wallet encrypt-message — End-to-end encrypt an off-chain message
// between two anon-address holders using their X25519-derived shared
// secret as the AEAD key.
//
// Use case:
//   Alice (priv-keyfile holder) wants to send Bob (--peer-pubkey holder)
//   an encrypted off-chain message. Each side independently derives the
//   same 32-byte AEAD key from their own privkey + the other side's
//   pubkey via X25519 + HKDF-SHA-256 (composition with derive-shared-
//   secret). The wire format is a tiny binary blob:
//
//     [nonce: 12 B] || [ciphertext + 16-byte AES-GCM tag]
//
//   Both parties' encrypt/decrypt calls use the SAME AEAD key (HKDF salt
//   is symmetric in the pubkey pair); the nonce is freshly random per
//   message so identical plaintexts produce different ciphertexts.
//
// CLI:
//   --priv-keyfile <path>: path to operator's single-account JSON keyfile
//                          ({"address":"0x..","privkey_hex":".."}, same
//                          format account-export reads).
//   --peer-pubkey <hex>:   peer's 32-byte Ed25519 pubkey (64 lowercase
//                          hex chars; this IS the peer's anon-address
//                          minus the "0x" prefix).
//   --in <path>:           plaintext input file (read in binary, byte-
//                          for-byte).
//   --out <path>:          ciphertext output file (binary).
//
// Output (stdout, one line):
//   {"status":"ok","out":"<path>","ciphertext_bytes":<N>}
//
// Exit codes:
//   0  success
//   1  args / IO / parse / hex-decode / shape / OpenSSL failure
//   2  crypto failure (curve25519 conversion or scalarmult returned
//      non-zero — peer pubkey malformed or in small subgroup)
int cmd_encrypt_message(int argc, char** argv) {
    std::string priv_keyfile, peer_pubkey_hex, in_path, out_path;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--priv-keyfile" && i + 1 < argc) priv_keyfile    = argv[++i];
        else if (a == "--peer-pubkey"  && i + 1 < argc) peer_pubkey_hex = argv[++i];
        else if (a == "--in"           && i + 1 < argc) in_path         = argv[++i];
        else if (a == "--out"          && i + 1 < argc) out_path        = argv[++i];
        else {
            std::cerr << "encrypt-message: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet encrypt-message "
                         "--priv-keyfile <path> --peer-pubkey <hex> "
                         "--in <plaintext> --out <ciphertext>\n";
            return 1;
        }
    }
    if (priv_keyfile.empty() || peer_pubkey_hex.empty()
        || in_path.empty() || out_path.empty()) {
        std::cerr << "Usage: determ-wallet encrypt-message "
                     "--priv-keyfile <path> --peer-pubkey <hex> "
                     "--in <plaintext> --out <ciphertext>\n"
                     "\n"
                     "  Encrypts <plaintext> under a 32-byte AEAD key derived\n"
                     "  via X25519 + HKDF-SHA-256 from the priv-keyfile holder\n"
                     "  and the --peer-pubkey peer. Output file format:\n"
                     "  nonce(12) || ciphertext_with_gcm_tag(N+16).\n";
        return 1;
    }

    // ── Load priv keyfile ──────────────────────────────────────────────────
    std::vector<uint8_t> priv_seed;
    if (!load_priv_keyfile(priv_keyfile, "encrypt-message", priv_seed))
        return 1;

    // ── Parse peer pubkey hex ──────────────────────────────────────────────
    if (peer_pubkey_hex.size() != 64) {
        std::cerr << "encrypt-message: --peer-pubkey must be 64 hex chars "
                     "(32-byte Ed25519 pubkey); got length "
                  << peer_pubkey_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> peer_pub_bytes;
    try { peer_pub_bytes = from_hex(peer_pubkey_hex); }
    catch (std::exception& e) {
        std::cerr << "encrypt-message: --peer-pubkey is not valid hex: "
                  << e.what() << "\n";
        return 1;
    }
    if (peer_pub_bytes.size() != 32) {
        std::cerr << "encrypt-message: --peer-pubkey decoded length must "
                     "be 32; got " << peer_pub_bytes.size() << "\n";
        return 1;
    }

    // ── Read plaintext ─────────────────────────────────────────────────────
    auto pt_opt = read_file_bytes(in_path);
    if (!pt_opt) {
        std::cerr << "encrypt-message: cannot read --in: " << in_path << "\n";
        return 1;
    }
    std::vector<uint8_t> plaintext = std::move(*pt_opt);

    // ── Init libsodium + derive X25519 shared secret ──────────────────────
    if (!primitives::init_libsodium()) {
        std::cerr << "encrypt-message: libsodium init failed\n";
        return 1;
    }
    std::array<uint8_t, 32> shared{};
    std::array<uint8_t, 32> my_pub{};
    std::string err_kind;
    if (!derive_shared_secret_bytes(priv_seed, peer_pub_bytes,
                                      shared, my_pub, err_kind)) {
        sodium_memzero(shared.data(), shared.size());
        std::cerr << "encrypt-message: X25519 derivation failed ("
                  << err_kind << ")\n";
        return 2;
    }

    // ── HKDF-SHA-256 -> 32-byte AEAD key ──────────────────────────────────
    // Salt = byte-min(my_pub, peer_pub) || byte-max(my_pub, peer_pub).
    // Info = "DETERM-CHAT-AEAD-v1" (domain separation tag).
    std::vector<uint8_t> salt = chat_aead_salt(my_pub, peer_pub_bytes);
    std::array<uint8_t, 32> aead_key{};
    if (!hkdf_sha256_32(shared, salt,
                         std::string("DETERM-CHAT-AEAD-v1"),
                         aead_key, err_kind)) {
        sodium_memzero(shared.data(),    shared.size());
        sodium_memzero(aead_key.data(),  aead_key.size());
        std::cerr << "encrypt-message: HKDF derivation failed ("
                  << err_kind << ")\n";
        return 1;
    }
    sodium_memzero(shared.data(), shared.size());

    // ── Generate fresh random 12-byte nonce ────────────────────────────────
    // Fresh nonce per message: identical plaintexts produce different
    // ciphertexts, and nonce-reuse-with-same-key (catastrophic for GCM)
    // is impossible by construction.
    std::array<uint8_t, 12> nonce{};
    if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
        sodium_memzero(aead_key.data(), aead_key.size());
        std::cerr << "encrypt-message: RAND_bytes failed for nonce\n";
        return 1;
    }

    // ── AES-256-GCM encrypt ───────────────────────────────────────────────
    std::vector<uint8_t> ciphertext;
    try {
        ciphertext = aes256_gcm_encrypt_raw(aead_key, nonce, plaintext);
    } catch (std::exception& e) {
        sodium_memzero(aead_key.data(), aead_key.size());
        std::cerr << "encrypt-message: " << e.what() << "\n";
        return 1;
    }
    sodium_memzero(aead_key.data(), aead_key.size());

    // ── Compose wire format: nonce(12) || ciphertext_with_tag ─────────────
    std::vector<uint8_t> wire;
    wire.reserve(nonce.size() + ciphertext.size());
    wire.insert(wire.end(), nonce.begin(), nonce.end());
    wire.insert(wire.end(), ciphertext.begin(), ciphertext.end());

    if (!write_file_bytes(out_path, wire)) {
        std::cerr << "encrypt-message: cannot write --out: " << out_path << "\n";
        return 1;
    }

    nlohmann::json out_doc = {
        {"status",           "ok"},
        {"out",              out_path},
        {"ciphertext_bytes", static_cast<int64_t>(wire.size())},
    };
    std::cout << out_doc.dump() << "\n";
    return 0;
}

// determ-wallet decrypt-message — Inverse of encrypt-message. Reads a
// nonce(12)||ciphertext_with_tag file produced by encrypt-message,
// derives the same 32-byte AEAD key via X25519 + HKDF-SHA-256
// (symmetric in the pubkey pair, so either side decrypts), and writes
// the plaintext to --out.
//
// CLI:
//   --priv-keyfile <path>: operator's single-account JSON keyfile.
//   --peer-pubkey <hex>:   peer's 32-byte Ed25519 pubkey.
//   --in <path>:           ciphertext input file (nonce(12)||CT+tag).
//   --out <path>:          plaintext output file (binary).
//
// Output (stdout, one line):
//   success: {"status":"ok","out":"<path>","plaintext_bytes":<N>}
//   tamper:  {"status":"error","reason":"aead_tag_verify_failed"}
//
// Exit codes:
//   0  success
//   1  args / IO / parse error
//   2  AEAD tag-verify failed (tampered ciphertext, wrong key, wrong
//      nonce, or wrong peer pubkey). Also covers X25519 cryptographic
//      failures (curve25519 conversion / scalarmult).
int cmd_decrypt_message(int argc, char** argv) {
    std::string priv_keyfile, peer_pubkey_hex, in_path, out_path;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--priv-keyfile" && i + 1 < argc) priv_keyfile    = argv[++i];
        else if (a == "--peer-pubkey"  && i + 1 < argc) peer_pubkey_hex = argv[++i];
        else if (a == "--in"           && i + 1 < argc) in_path         = argv[++i];
        else if (a == "--out"          && i + 1 < argc) out_path        = argv[++i];
        else {
            std::cerr << "decrypt-message: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet decrypt-message "
                         "--priv-keyfile <path> --peer-pubkey <hex> "
                         "--in <ciphertext> --out <plaintext>\n";
            return 1;
        }
    }
    if (priv_keyfile.empty() || peer_pubkey_hex.empty()
        || in_path.empty() || out_path.empty()) {
        std::cerr << "Usage: determ-wallet decrypt-message "
                     "--priv-keyfile <path> --peer-pubkey <hex> "
                     "--in <ciphertext> --out <plaintext>\n"
                     "\n"
                     "  Decrypts a nonce(12)||CT+tag blob written by\n"
                     "  encrypt-message. The AEAD key derives via X25519 +\n"
                     "  HKDF-SHA-256 (symmetric in the pubkey pair). On tag-\n"
                     "  verify failure (tampering / wrong key / wrong peer)\n"
                     "  emits {\"status\":\"error\",\"reason\":\n"
                     "  \"aead_tag_verify_failed\"} and exits 2.\n";
        return 1;
    }

    // ── Load priv keyfile ──────────────────────────────────────────────────
    std::vector<uint8_t> priv_seed;
    if (!load_priv_keyfile(priv_keyfile, "decrypt-message", priv_seed))
        return 1;

    // ── Parse peer pubkey hex ──────────────────────────────────────────────
    if (peer_pubkey_hex.size() != 64) {
        std::cerr << "decrypt-message: --peer-pubkey must be 64 hex chars "
                     "(32-byte Ed25519 pubkey); got length "
                  << peer_pubkey_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> peer_pub_bytes;
    try { peer_pub_bytes = from_hex(peer_pubkey_hex); }
    catch (std::exception& e) {
        std::cerr << "decrypt-message: --peer-pubkey is not valid hex: "
                  << e.what() << "\n";
        return 1;
    }
    if (peer_pub_bytes.size() != 32) {
        std::cerr << "decrypt-message: --peer-pubkey decoded length must "
                     "be 32; got " << peer_pub_bytes.size() << "\n";
        return 1;
    }

    // ── Read ciphertext blob ──────────────────────────────────────────────
    auto ct_opt = read_file_bytes(in_path);
    if (!ct_opt) {
        std::cerr << "decrypt-message: cannot read --in: " << in_path << "\n";
        return 1;
    }
    std::vector<uint8_t> wire = std::move(*ct_opt);

    // Minimum size: 12 (nonce) + 16 (tag) = 28 bytes. Anything smaller
    // is definitionally malformed.
    if (wire.size() < 28) {
        std::cerr << "decrypt-message: ciphertext too short (" << wire.size()
                  << " bytes); minimum is 28 (12-byte nonce + 16-byte tag)\n";
        return 1;
    }
    std::array<uint8_t, 12> nonce{};
    std::memcpy(nonce.data(), wire.data(), 12);
    std::vector<uint8_t> ct_with_tag(wire.begin() + 12, wire.end());

    // ── Init libsodium + derive X25519 shared secret ──────────────────────
    if (!primitives::init_libsodium()) {
        std::cerr << "decrypt-message: libsodium init failed\n";
        return 1;
    }
    std::array<uint8_t, 32> shared{};
    std::array<uint8_t, 32> my_pub{};
    std::string err_kind;
    if (!derive_shared_secret_bytes(priv_seed, peer_pub_bytes,
                                      shared, my_pub, err_kind)) {
        sodium_memzero(shared.data(), shared.size());
        std::cerr << "decrypt-message: X25519 derivation failed ("
                  << err_kind << ")\n";
        return 2;
    }

    // ── HKDF-SHA-256 -> 32-byte AEAD key ──────────────────────────────────
    std::vector<uint8_t> salt = chat_aead_salt(my_pub, peer_pub_bytes);
    std::array<uint8_t, 32> aead_key{};
    if (!hkdf_sha256_32(shared, salt,
                         std::string("DETERM-CHAT-AEAD-v1"),
                         aead_key, err_kind)) {
        sodium_memzero(shared.data(),    shared.size());
        sodium_memzero(aead_key.data(),  aead_key.size());
        std::cerr << "decrypt-message: HKDF derivation failed ("
                  << err_kind << ")\n";
        return 1;
    }
    sodium_memzero(shared.data(), shared.size());

    // ── AES-256-GCM decrypt (tag-verify or fail closed) ───────────────────
    std::optional<std::vector<uint8_t>> pt_opt;
    try {
        pt_opt = aes256_gcm_decrypt_raw(aead_key, nonce, ct_with_tag);
    } catch (std::exception& e) {
        sodium_memzero(aead_key.data(), aead_key.size());
        std::cerr << "decrypt-message: " << e.what() << "\n";
        return 1;
    }
    sodium_memzero(aead_key.data(), aead_key.size());

    if (!pt_opt) {
        // Tag-verify failure — emit the canonical error JSON and exit 2.
        // Exit code 2 is the "auth-style alert" convention this codebase
        // uses for cryptographic-verification failures (see message-
        // verify and tx-sign-verify). Distinct from exit 1 (operator
        // error) so callers can branch on it.
        nlohmann::json err_doc = {
            {"status", "error"},
            {"reason", "aead_tag_verify_failed"},
        };
        std::cout << err_doc.dump() << "\n";
        return 2;
    }

    if (!write_file_bytes(out_path, *pt_opt)) {
        std::cerr << "decrypt-message: cannot write --out: " << out_path << "\n";
        return 1;
    }

    nlohmann::json out_doc = {
        {"status",          "ok"},
        {"out",             out_path},
        {"plaintext_bytes", static_cast<int64_t>(pt_opt->size())},
    };
    std::cout << out_doc.dump() << "\n";
    return 0;
}

// determ-wallet tx-sign-verify — Verify the Ed25519 signature on a
// Transaction JSON file using the chain's CANONICAL signing_bytes scheme
// (NOT the off-chain domain-separated SHA-256 commitment used by
// message-sign / message-verify).
//
// Use cases:
//   * Operator receives a signed Transaction off the wire (RPC submit
//     queue, manual relay, off-chain batch packaging) and wants to
//     confirm the sig is valid before broadcasting / submitting.
//   * Inspect-before-submit: a signing-tier wallet hands a fully signed
//     tx to an operator who wants to verify byte-for-byte that the sig
//     binds the body fields they're about to broadcast.
//   * Forensic post-mortem: a tx was rejected at the validator; reproduce
//     the validator's verify call locally to confirm whether the sig was
//     malformed vs. some other validation gate failed.
//
// Distinction from message-sign / message-verify:
//   - message-sign signs SHA-256(domain_tag || message_bytes) for off-chain
//     uses (SIWE auth, attestations); the on-chain Transaction sig scheme
//     is a different, protocol-pinned canonical form. The two are NOT
//     interchangeable: a message-sign sig is NOT a valid tx sig and vice
//     versa, by design (cross-context replay prevention).
//
// Canonical signing_bytes layout (matches src/chain/block.cpp Transaction::signing_bytes):
//   [type:                u8 — TxType enum value]
//   [from:                utf8 bytes verbatim, NO len prefix]
//   [0x00:                NUL terminator separating from from to]
//   [to:                  utf8 bytes verbatim, NO len prefix]
//   [0x00:                NUL terminator after to]
//   [amount:              u64 BIG-ENDIAN (8 bytes, MSB first)]
//   [fee:                 u64 BIG-ENDIAN]
//   [nonce:               u64 BIG-ENDIAN]
//   [payload:             raw bytes (already-decoded hex from JSON)]
//
// Sender pubkey resolution:
//   The Transaction JSON does NOT carry the sender's pubkey explicitly
//   (the chain looks it up via the registry for domain senders, or
//   parses it out of the anon-address for anon senders). For this CLI,
//   we deliberately REQUIRE --pubkey to be supplied explicitly, because:
//     * The wallet binary has no chain registry to consult.
//     * Anon-address senders carry the pubkey IN their address (the
//       `0x` + 64 hex chars = the Ed25519 pubkey), but rather than
//       silently auto-derive we make the operator pass it explicitly —
//       this prevents an off-by-one-style mistake where the verifier
//       trusts the address-derived pubkey when the operator actually
//       meant to verify against a registry-bound key.
//     * Cross-binary surface invariant: --pubkey ALWAYS comes from
//       outside the JSON, so the verifier can't be fooled by a forged
//       JSON that names a different signer.
//
// CLI:
//   --tx <file>:     path to a JSON file containing a Transaction
//                    (fields: type, from, to, amount, fee, nonce,
//                    payload, sig, hash). The same shape `account-
//                    create-batch` test wrappers produce + the same
//                    shape `Transaction::to_json` emits.
//   --pubkey <hex>:  64 hex chars (32-byte Ed25519 pubkey) of the
//                    presumed signer. REQUIRED.
//   --json:          emit a JSON document; otherwise human lines.
//
// Output:
//   Human mode:
//     valid:                             true | false
//     tx_hash_hex:                       <64 hex chars>
//     computed_signing_bytes_sha256:     <64 hex chars>
//   --json mode:
//     {"valid": bool,
//      "tx_hash_hex": "<64 hex>",
//      "computed_signing_bytes_sha256": "<64 hex>"}
//
// Exit codes:
//   0  signature valid
//   1  args / parse / IO / JSON-shape / hex-decode error
//   2  signature invalid — auth-style alert (distinct from arg errors
//      so monitoring scripts can differentiate "bad input" from
//      "input shape is fine but the sig doesn't validate")
//
// Why exit 2 for invalid: matches the convention used by message-verify,
// keyfile-decrypt, envelope decrypt — all use 2 for "structurally fine,
// authentication failed."
//
// Output field rationale:
//   - `tx_hash_hex` is the SHA-256(signing_bytes) value the chain
//     computes as Transaction::compute_hash. This is the value that
//     appears as `hash` on the JSON and as the leaf in tx_root. We
//     compute + report it independently to let operators cross-check
//     the JSON-supplied `hash` field is consistent with the body.
//   - `computed_signing_bytes_sha256` is the same value (SHA-256 of
//     signing_bytes); it's exposed under a distinct field name so a
//     consumer that just wants "the hash of what was signed" can grab
//     it without conflating it with the tx's identity hash (they happen
//     to coincide for tx sigs, but that's a property of the scheme, not
//     a definition — message-verify's analogous field is named
//     message_hash_hex; keeping a parallel name keeps the JSON-shape
//     convention consistent).
int cmd_tx_sign_verify(int argc, char** argv) {
    std::string tx_path, pubkey_hex;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--tx"     && i + 1 < argc) tx_path    = argv[++i];
        else if (a == "--pubkey" && i + 1 < argc) pubkey_hex = argv[++i];
        else if (a == "--json")                   json_out   = true;
        else {
            std::cerr << "tx-sign-verify: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet tx-sign-verify --tx <file> "
                         "--pubkey <hex> [--json]\n";
            return 1;
        }
    }
    if (tx_path.empty() || pubkey_hex.empty()) {
        std::cerr << "Usage: determ-wallet tx-sign-verify --tx <file> "
                     "--pubkey <hex> [--json]\n"
                     "\n"
                     "  Verifies the Ed25519 sig on a Transaction JSON file\n"
                     "  using the chain's canonical signing_bytes scheme\n"
                     "  (matches src/chain/block.cpp Transaction::signing_bytes).\n"
                     "  Distinct from message-sign (off-chain domain-separated\n"
                     "  scheme). Exit 0 valid, 2 invalid (auth-style alert),\n"
                     "  1 args/parse/IO error.\n";
        return 1;
    }

    if (pubkey_hex.size() != 64) {
        std::cerr << "tx-sign-verify: --pubkey must be exactly 64 hex chars "
                     "(32-byte Ed25519 pubkey); got " << pubkey_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> pub_bytes;
    try { pub_bytes = from_hex(pubkey_hex); }
    catch (std::exception& e) {
        std::cerr << "tx-sign-verify: invalid --pubkey hex: " << e.what() << "\n";
        return 1;
    }
    if (pub_bytes.size() != 32) {
        std::cerr << "tx-sign-verify: --pubkey decoded to " << pub_bytes.size()
                  << " bytes (expected 32)\n";
        return 1;
    }

    // Read and parse the Transaction JSON. We do the parse here rather than
    // delegating to determ::chain::Transaction::from_json because we want
    // the wallet binary to stay decoupled from the chain library (the
    // wallet target deliberately doesn't link against the chain lib in
    // CMakeLists.txt — separation-of-concerns; wallet handles secrets,
    // chain handles consensus). Re-encoding signing_bytes in ~20 lines
    // here is the cheaper trade-off vs. dragging the chain lib into the
    // wallet's TCB.
    std::ifstream tx_f(tx_path);
    if (!tx_f) {
        std::cerr << "tx-sign-verify: cannot open --tx file: " << tx_path << "\n";
        return 1;
    }
    nlohmann::json j;
    try { tx_f >> j; }
    catch (std::exception& e) {
        std::cerr << "tx-sign-verify: --tx file is not valid JSON: " << e.what() << "\n";
        return 1;
    }

    // Required fields. Treat missing or wrong-typed as a parse error
    // (rc=1), not an auth failure (rc=2): the JSON shape is broken,
    // not the sig.
    int      tx_type;
    std::string from_str, to_str, payload_hex, sig_hex;
    uint64_t amount, fee, nonce;
    try {
        if (!j.contains("type")    || !j["type"].is_number())     throw std::runtime_error("missing/wrong-typed 'type' (expected integer)");
        if (!j.contains("from")    || !j["from"].is_string())     throw std::runtime_error("missing/wrong-typed 'from' (expected string)");
        if (!j.contains("to")      || !j["to"].is_string())       throw std::runtime_error("missing/wrong-typed 'to' (expected string)");
        if (!j.contains("amount")  || !j["amount"].is_number())   throw std::runtime_error("missing/wrong-typed 'amount' (expected integer)");
        if (!j.contains("nonce")   || !j["nonce"].is_number())    throw std::runtime_error("missing/wrong-typed 'nonce' (expected integer)");
        if (!j.contains("payload") || !j["payload"].is_string())  throw std::runtime_error("missing/wrong-typed 'payload' (expected hex string)");
        if (!j.contains("sig")     || !j["sig"].is_string())      throw std::runtime_error("missing/wrong-typed 'sig' (expected hex string)");

        tx_type     = j["type"].get<int>();
        from_str    = j["from"].get<std::string>();
        to_str      = j["to"].get<std::string>();
        amount      = j["amount"].get<uint64_t>();
        // `fee` is optional (matches chain's Transaction::from_json which
        // defaults to 0); the chain's signing_bytes always includes the
        // 8-byte fee field, so a missing JSON field == fee=0.
        fee         = j.value("fee", uint64_t{0});
        nonce       = j["nonce"].get<uint64_t>();
        payload_hex = j["payload"].get<std::string>();
        sig_hex     = j["sig"].get<std::string>();
    } catch (std::exception& e) {
        std::cerr << "tx-sign-verify: --tx JSON shape error: " << e.what() << "\n";
        return 1;
    }

    // Range-check the type byte. TxType is a u8 in the wire encoding;
    // values outside [0, 255] would corrupt the first byte of
    // signing_bytes silently. Reject them up front with a clean diagnostic.
    if (tx_type < 0 || tx_type > 255) {
        std::cerr << "tx-sign-verify: 'type' value " << tx_type
                  << " out of range (expected 0..255 for u8 wire encoding)\n";
        return 1;
    }

    // Decode the hex-encoded fields.
    std::vector<uint8_t> payload_bytes, sig_bytes;
    try { payload_bytes = from_hex(payload_hex); }
    catch (std::exception& e) {
        std::cerr << "tx-sign-verify: invalid 'payload' hex: " << e.what() << "\n";
        return 1;
    }
    if (sig_hex.size() != 128) {
        std::cerr << "tx-sign-verify: 'sig' must be exactly 128 hex chars "
                     "(64-byte Ed25519 signature); got " << sig_hex.size() << "\n";
        return 1;
    }
    try { sig_bytes = from_hex(sig_hex); }
    catch (std::exception& e) {
        std::cerr << "tx-sign-verify: invalid 'sig' hex: " << e.what() << "\n";
        return 1;
    }
    if (sig_bytes.size() != 64) {
        std::cerr << "tx-sign-verify: sig decoded to " << sig_bytes.size()
                  << " bytes (expected 64)\n";
        return 1;
    }

    // Reconstruct signing_bytes — byte-for-byte identical to what
    // src/chain/block.cpp Transaction::signing_bytes produces. Any drift
    // here would make every wallet-verified tx fail the chain's verify,
    // so the layout below is intentionally simple + reviewable.
    std::vector<uint8_t> sb;
    sb.reserve(1 + from_str.size() + 1 + to_str.size() + 1 + 24 + payload_bytes.size());
    sb.push_back(static_cast<uint8_t>(tx_type));
    sb.insert(sb.end(), from_str.begin(), from_str.end());
    sb.push_back(0);
    sb.insert(sb.end(), to_str.begin(), to_str.end());
    sb.push_back(0);
    // u64 BIG-ENDIAN encodings of amount / fee / nonce, in that order.
    // Chain code does the same shift-pattern (`(x >> (i*8)) & 0xFF` for
    // i = 7 down to 0). Keep the loops explicit rather than using a
    // helper — copy-paste hazard vs. one canonical reference.
    for (int i = 7; i >= 0; --i) sb.push_back((amount >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) sb.push_back((fee    >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) sb.push_back((nonce  >> (i * 8)) & 0xFF);
    sb.insert(sb.end(), payload_bytes.begin(), payload_bytes.end());

    // Compute SHA-256(signing_bytes) — this is BOTH the chain's
    // Transaction::compute_hash result (the value that appears as `hash`
    // in the JSON + as the tx_root leaf) AND the value we expose as
    // computed_signing_bytes_sha256 for the operator to cross-check.
    std::array<uint8_t, 32> sb_sha{};
    SHA256(sb.data(), sb.size(), sb_sha.data());

    // Init libsodium (idempotent) and verify the sig.
    if (!primitives::init_libsodium()) {
        std::cerr << "tx-sign-verify: libsodium init failed\n";
        return 1;
    }
    // crypto_sign_verify_detached signs/verifies the message bytes
    // directly (Ed25519 is hash-and-sign internally — it hashes with
    // SHA-512 as part of the algorithm). The chain's verify path
    // (src/crypto/keys.cpp::verify via EVP_DigestVerify on EVP_PKEY_ED25519)
    // does the same thing: both operate on the raw signing_bytes message,
    // NOT on a pre-hashed digest. A sig produced by either path is
    // verifiable by the other.
    int rc = crypto_sign_verify_detached(sig_bytes.data(),
                                          sb.data(), sb.size(),
                                          pub_bytes.data());
    const bool valid = (rc == 0);

    if (json_out) {
        nlohmann::json r;
        r["valid"]                          = valid;
        r["tx_hash_hex"]                    = to_hex(sb_sha);
        r["computed_signing_bytes_sha256"]  = to_hex(sb_sha);
        std::cout << r.dump() << "\n";
    } else {
        std::cout << "valid:                          " << (valid ? "true" : "false") << "\n";
        std::cout << "tx_hash_hex:                    " << to_hex(sb_sha) << "\n";
        std::cout << "computed_signing_bytes_sha256:  " << to_hex(sb_sha) << "\n";
    }
    return valid ? 0 : 2;
}

// determ-wallet cold-sign — Offline transaction signing for the
// air-gapped cold-wallet workflow.
//
// Workflow (3 machines / 2 transfers):
//   1. HOT machine prepares an unsigned tx JSON (hand-crafted, or via an
//      RPC helper that emits {type, from, to, amount, fee, nonce,
//      payload, sig:""} — every field bound into signing_bytes is
//      already populated; the `sig` slot is intentionally empty).
//   2. Operator transfers that JSON to an AIR-GAPPED cold machine (USB,
//      QR code, sneakernet — never over a network).
//   3. Cold machine runs:
//        determ-wallet cold-sign --tx-json <unsigned.json>
//                                --priv-keyfile <keyfile.json>
//                                --out <signed.json>
//      The private key never leaves the cold machine; the signed JSON
//      goes back to the hot machine.
//   4. Hot machine submits via `determ submit-tx --in signed.json` or
//      the submit_tx RPC.
//
// Distinction from tx-sign-verify (Round 17):
//   * tx-sign-verify VERIFIES a sig — read-only diagnostic, no signing,
//     no private material on the box running it.
//   * cold-sign SIGNS — produces a brand-new `sig` field. Refuses to
//     overwrite an existing signature, refuses to sign on behalf of a
//     keyfile whose address doesn't match tx.from (defense against
//     accidentally signing someone else's tx). No RPC, no daemon, no
//     network — strictly file-in / file-out.
//
// Why a dedicated CLI rather than reusing tx-sign-verify in reverse:
//   * Operational guard rails — sign-and-verify-in-one-shot makes sense
//     on a hot test machine; cold-wallet flows demand a refusal-heavy
//     CLI that errors loudly before touching the keyfile.
//   * Output discipline — the signed envelope must be byte-stable so
//     the hot machine's submit_tx serializer doesn't re-canonicalize
//     it; we preserve every input field verbatim and only ADD `sig`
//     (and `hash` if missing — the chain recomputes anyway, but
//     emitting it for round-trip parity is the standard shape).
//   * Stdout refusal by default — a signed tx written to a terminal
//     scrollback / pipe / log buffer is an exfil hazard. We force
//     --out by default; --allow-stdout is an explicit operator
//     opt-in.
//
// CLI:
//   --tx-json <file>:      REQUIRED. Path to the unsigned tx JSON. Same
//                          shape `Transaction::to_json` emits, with
//                          `sig` absent OR empty string OR a 128-char
//                          all-zero hex string. Any other non-empty
//                          `sig` triggers tx_already_signed refusal.
//                          `hash` is optional on input (we ignore it
//                          and recompute).
//   --priv-keyfile <file>: REQUIRED. Single-account JSON {address,
//                          privkey_hex} (the shape `account-export`
//                          emits, same as every other wallet command's
//                          --priv-keyfile).
//   --out <file>:          REQUIRED unless --allow-stdout. Output path
//                          for the signed JSON. Refuses to overwrite
//                          unless --force is set; written with 0600
//                          permissions (POSIX chmod; on Windows the
//                          read/write bits are a no-op — ACL inherits
//                          from parent).
//   --allow-stdout:        Permit emitting the signed JSON to stdout
//                          instead of a file. Default off as an
//                          exfiltration guard rail.
//   --force:               Overwrite an existing --out file.
//   --json:                Accepted for parity with sibling commands;
//                          the status line is always one-line JSON
//                          regardless.
//
// Refusals (exit 1 with a structured one-line JSON error doc on stdout
// AND a human diagnostic on stderr):
//   tx_already_signed         — input tx already carries a non-empty,
//                               non-all-zero `sig`. We never overwrite
//                               an existing sig: the operator could be
//                               trying to double-sign, replay-sign, or
//                               mistakenly sign the wrong tx version.
//   keyfile_address_mismatch  — keyfile.address != tx.from. Prevents
//                               accidentally signing on the wrong
//                               account; the keyfile is correct but
//                               it's the wrong keyfile for THIS tx.
//   output_exists             — --out file exists and --force was not
//                               supplied. Refuses to overwrite.
//
// Success output (stdout, one-line JSON):
//   {"status":"ok","tx_hash_hex":"<64 hex>","out":"<path>"}
// (When --allow-stdout is supplied without --out, the signed JSON is
// emitted to stdout as a single line, followed by the status line on
// stderr so the two streams are unambiguous.)
//
// Exit codes:
//   0  signed envelope emitted
//   1  args / parse / IO / refusal / libsodium error
int cmd_cold_sign(int argc, char** argv) {
    std::string tx_path, priv_keyfile, out_path;
    bool allow_stdout = false;
    bool force        = false;
    bool json_out     = false;  // accepted but currently always-on
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--tx-json"      && i + 1 < argc) tx_path      = argv[++i];
        else if (a == "--priv-keyfile" && i + 1 < argc) priv_keyfile = argv[++i];
        else if (a == "--out"          && i + 1 < argc) out_path     = argv[++i];
        else if (a == "--allow-stdout")                 allow_stdout = true;
        else if (a == "--force")                        force        = true;
        else if (a == "--json")                         json_out     = true;
        else if (a == "--help" || a == "-h") {
            std::cout <<
                "Usage: determ-wallet cold-sign --tx-json <file> "
                "--priv-keyfile <file> (--out <file> | --allow-stdout) "
                "[--force] [--json]\n"
                "\n"
                "  Offline transaction signing for the air-gapped cold-\n"
                "  wallet workflow. Reads an unsigned tx JSON, signs it\n"
                "  with the keyfile's Ed25519 priv_seed using the chain's\n"
                "  canonical signing_bytes scheme, and writes the signed\n"
                "  envelope to --out (or stdout with --allow-stdout).\n"
                "  No network, no RPC, no daemon — strictly file-in /\n"
                "  file-out for use on an air-gapped machine.\n"
                "\n"
                "  Refusals (exit 1, one-line JSON error doc):\n"
                "    tx_already_signed         — input tx has a non-empty sig\n"
                "    keyfile_address_mismatch  — keyfile.address != tx.from\n"
                "    output_exists             — --out file exists; pass --force\n";
            return 0;
        }
        else {
            std::cerr << "cold-sign: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet cold-sign --tx-json <file> "
                         "--priv-keyfile <file> (--out <file> | --allow-stdout) "
                         "[--force] [--json]\n";
            return 1;
        }
    }
    (void)json_out;
    if (tx_path.empty() || priv_keyfile.empty()) {
        std::cerr << "Usage: determ-wallet cold-sign --tx-json <file> "
                     "--priv-keyfile <file> (--out <file> | --allow-stdout) "
                     "[--force] [--json]\n";
        return 1;
    }
    if (out_path.empty() && !allow_stdout) {
        std::cerr << "cold-sign: --out is required unless --allow-stdout is "
                     "supplied (refusing to write secret-derived material to "
                     "stdout by default; pass --allow-stdout to override)\n";
        return 1;
    }

    // ── --out preconditions (check BEFORE loading the priv keyfile so a
    //     misconfigured operator doesn't read secret material before
    //     hitting the refusal) ────────────────────────────────────────
    if (!out_path.empty()) {
        std::filesystem::path p(out_path);
        auto parent = p.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent)) {
            std::cerr << "cold-sign: --out parent directory does not exist: "
                      << parent.string()
                      << "\n  (operator must pre-create; no mkdirp)\n";
            return 1;
        }
        if (std::filesystem::exists(p) && !force) {
            nlohmann::json err_doc = {
                {"status", "error"},
                {"reason", "output_exists"},
                {"out",    out_path},
            };
            std::cout << err_doc.dump() << "\n";
            std::cerr << "cold-sign: --out file already exists: " << out_path
                      << "\n  (refusing to overwrite; pass --force to override)\n";
            return 1;
        }
    }

    // ── Load + parse the unsigned tx JSON ─────────────────────────────
    // Same JSON shape Transaction::to_json emits, but the `sig` slot is
    // intentionally absent / empty / all-zero. `hash` is optional —
    // if present we ignore it and recompute (the chain recomputes from
    // signing_bytes on submit anyway; including it in the output is for
    // round-trip parity).
    std::ifstream tx_f(tx_path);
    if (!tx_f) {
        std::cerr << "cold-sign: cannot open --tx-json file: " << tx_path << "\n";
        return 1;
    }
    nlohmann::json j;
    try { tx_f >> j; }
    catch (std::exception& e) {
        std::cerr << "cold-sign: --tx-json file is not valid JSON: "
                  << e.what() << "\n";
        return 1;
    }
    if (!j.is_object()) {
        std::cerr << "cold-sign: --tx-json must be a JSON object\n";
        return 1;
    }

    // Required fields. Mirrors src/chain/block.cpp Transaction::from_json
    // schema — type/from/to/amount/nonce/payload required, fee optional
    // (default 0), sig optional (must be absent or empty).
    int      tx_type;
    std::string from_str, to_str, payload_hex;
    uint64_t amount, fee, nonce;
    try {
        if (!j.contains("type")    || !j["type"].is_number())    throw std::runtime_error("missing/wrong-typed 'type' (expected integer)");
        if (!j.contains("from")    || !j["from"].is_string())    throw std::runtime_error("missing/wrong-typed 'from' (expected string)");
        if (!j.contains("to")      || !j["to"].is_string())      throw std::runtime_error("missing/wrong-typed 'to' (expected string)");
        if (!j.contains("amount")  || !j["amount"].is_number())  throw std::runtime_error("missing/wrong-typed 'amount' (expected integer)");
        if (!j.contains("nonce")   || !j["nonce"].is_number())   throw std::runtime_error("missing/wrong-typed 'nonce' (expected integer)");
        if (!j.contains("payload") || !j["payload"].is_string()) throw std::runtime_error("missing/wrong-typed 'payload' (expected hex string)");
        tx_type     = j["type"].get<int>();
        from_str    = j["from"].get<std::string>();
        to_str      = j["to"].get<std::string>();
        amount      = j["amount"].get<uint64_t>();
        fee         = j.value("fee", uint64_t{0});
        nonce       = j["nonce"].get<uint64_t>();
        payload_hex = j["payload"].get<std::string>();
    } catch (std::exception& e) {
        std::cerr << "cold-sign: --tx-json shape error: " << e.what() << "\n";
        return 1;
    }
    if (tx_type < 0 || tx_type > 255) {
        std::cerr << "cold-sign: 'type' value " << tx_type
                  << " out of range (expected 0..255 for u8 wire encoding)\n";
        return 1;
    }

    // ── Refusal: tx_already_signed ──────────────────────────────────────
    // A non-empty, non-all-zero `sig` field means the tx is already
    // signed. We never overwrite — could be a double-sign mistake, a
    // replay against a different tx body, or signing the wrong version.
    // Treat empty string and all-zero 128-hex as "unsigned slot" (some
    // emitters preserve the field shape with a placeholder).
    if (j.contains("sig") && j["sig"].is_string()) {
        std::string existing_sig = j["sig"].get<std::string>();
        bool all_zero_or_empty = existing_sig.empty();
        if (!all_zero_or_empty && existing_sig.size() == 128) {
            all_zero_or_empty = true;
            for (char c : existing_sig) {
                if (c != '0') { all_zero_or_empty = false; break; }
            }
        }
        if (!all_zero_or_empty) {
            nlohmann::json err_doc = {
                {"status", "error"},
                {"reason", "tx_already_signed"},
            };
            std::cout << err_doc.dump() << "\n";
            std::cerr << "cold-sign: input tx already carries a non-empty "
                         "'sig' field — refusing to overwrite\n";
            return 1;
        }
    }

    // Decode payload hex now (so a malformed hex string fails before we
    // touch the keyfile).
    std::vector<uint8_t> payload_bytes;
    try { payload_bytes = from_hex(payload_hex); }
    catch (std::exception& e) {
        std::cerr << "cold-sign: invalid 'payload' hex: " << e.what() << "\n";
        return 1;
    }

    // ── Load the priv keyfile ──────────────────────────────────────────
    // Same single-account JSON shape account-export emits.
    std::ifstream kf(priv_keyfile);
    if (!kf) {
        std::cerr << "cold-sign: cannot open --priv-keyfile: "
                  << priv_keyfile << "\n";
        return 1;
    }
    nlohmann::json acc_doc;
    try { kf >> acc_doc; }
    catch (std::exception& e) {
        std::cerr << "cold-sign: --priv-keyfile is not valid JSON: "
                  << e.what() << "\n";
        return 1;
    }
    if (!acc_doc.is_object()
        || !acc_doc.contains("address")
        || !acc_doc["address"].is_string()
        || !acc_doc.contains("privkey_hex")
        || !acc_doc["privkey_hex"].is_string()) {
        std::cerr << "cold-sign: --priv-keyfile must be a JSON object with "
                     "string fields 'address' and 'privkey_hex' "
                     "(account-export shape)\n";
        return 1;
    }
    std::string keyfile_address = acc_doc["address"].get<std::string>();
    std::string priv_hex        = acc_doc["privkey_hex"].get<std::string>();
    if (priv_hex.size() != 64) {
        std::cerr << "cold-sign: 'privkey_hex' must be 64 hex chars "
                     "(32-byte Ed25519 priv_seed); got length "
                  << priv_hex.size() << "\n";
        return 1;
    }
    std::vector<uint8_t> priv_seed;
    try { priv_seed = from_hex(priv_hex); }
    catch (std::exception& e) {
        std::cerr << "cold-sign: 'privkey_hex' is not valid hex: "
                  << e.what() << "\n";
        return 1;
    }
    if (priv_seed.size() != 32) {
        std::cerr << "cold-sign: 'privkey_hex' decoded length must be 32; got "
                  << priv_seed.size() << "\n";
        return 1;
    }

    // ── Refusal: keyfile_address_mismatch ──────────────────────────────
    // tx.from must equal keyfile.address. Defense against accidentally
    // signing a tx that belongs to a different account — the cold
    // machine often holds multiple keyfiles and the operator must point
    // at the right one. We compare verbatim (no case normalization)
    // because the chain's anon-address canonical form is lowercase per
    // S-028; either side mis-casing it is a real bug the operator
    // should fix at the source.
    if (from_str != keyfile_address) {
        nlohmann::json err_doc = {
            {"status",          "error"},
            {"reason",          "keyfile_address_mismatch"},
            {"tx_from",         from_str},
            {"keyfile_address", keyfile_address},
        };
        std::cout << err_doc.dump() << "\n";
        std::cerr << "cold-sign: keyfile.address does not match tx.from "
                     "(keyfile=" << keyfile_address
                  << " tx.from=" << from_str << ")\n";
        sodium_memzero(priv_seed.data(), priv_seed.size());
        return 1;
    }

    // ── Reconstruct signing_bytes — byte-identical to chain's
    //    Transaction::signing_bytes ────────────────────────────────────
    // Same layout `cmd_tx_sign_verify` reconstructs above; keep this
    // copy in sync with that one rather than DRY'ing into a helper —
    // a one-line drift here would silently produce sigs that the chain
    // rejects, and an inline encoding is easier to review than a
    // helper call.
    std::vector<uint8_t> sb;
    sb.reserve(1 + from_str.size() + 1 + to_str.size() + 1 + 24 + payload_bytes.size());
    sb.push_back(static_cast<uint8_t>(tx_type));
    sb.insert(sb.end(), from_str.begin(), from_str.end());
    sb.push_back(0);
    sb.insert(sb.end(), to_str.begin(), to_str.end());
    sb.push_back(0);
    for (int i = 7; i >= 0; --i) sb.push_back((amount >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) sb.push_back((fee    >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) sb.push_back((nonce  >> (i * 8)) & 0xFF);
    sb.insert(sb.end(), payload_bytes.begin(), payload_bytes.end());

    // SHA-256(signing_bytes) — both the chain's Transaction::compute_hash
    // result AND what we emit in the success status line as tx_hash_hex.
    std::array<uint8_t, 32> sb_sha{};
    SHA256(sb.data(), sb.size(), sb_sha.data());

    // ── Ed25519 sign over signing_bytes ─────────────────────────────────
    if (!primitives::init_libsodium()) {
        sodium_memzero(priv_seed.data(), priv_seed.size());
        std::cerr << "cold-sign: libsodium init failed\n";
        return 1;
    }
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pub{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    if (crypto_sign_seed_keypair(pub.data(), sk.data(), priv_seed.data()) != 0) {
        sodium_memzero(priv_seed.data(), priv_seed.size());
        sodium_memzero(sk.data(), sk.size());
        std::cerr << "cold-sign: crypto_sign_seed_keypair failed\n";
        return 1;
    }
    // priv_seed not needed past keypair derivation; scrub.
    sodium_memzero(priv_seed.data(), priv_seed.size());

    std::array<uint8_t, crypto_sign_BYTES> sig{};
    unsigned long long sig_len = 0;
    if (crypto_sign_detached(sig.data(), &sig_len,
                              sb.data(), sb.size(),
                              sk.data()) != 0) {
        sodium_memzero(sk.data(), sk.size());
        std::cerr << "cold-sign: crypto_sign_detached failed\n";
        return 1;
    }
    sodium_memzero(sk.data(), sk.size());
    if (sig_len != crypto_sign_BYTES) {
        std::cerr << "cold-sign: unexpected sig length " << sig_len << "\n";
        return 1;
    }

    // ── Build signed envelope JSON ─────────────────────────────────────
    // Preserve every input field verbatim (so the hot machine sees the
    // exact body it built, minus the empty-sig slot) and ADD `sig` +
    // `hash`. We deliberately do NOT add a fee field if the input
    // omitted it — `from_json` defaults to 0 and emitting only what
    // the operator put in keeps round-trip diffs clean.
    nlohmann::json signed_doc = j;  // start from input; preserves unknown fields
    signed_doc["sig"]  = to_hex(sig);
    signed_doc["hash"] = to_hex(sb_sha);

    std::string signed_text = signed_doc.dump();

    if (out_path.empty()) {
        // --allow-stdout path. Emit the signed JSON on stdout, then
        // emit the status line on stderr so the two streams are
        // unambiguous (a downstream pipe captures the envelope; the
        // status line is for the human / wrapper script).
        std::cout << signed_text << "\n";
        nlohmann::json status = {
            {"status",      "ok"},
            {"tx_hash_hex", to_hex(sb_sha)},
            {"out",         "<stdout>"},
        };
        std::cerr << status.dump() << "\n";
        return 0;
    }

    // --out path. Write the signed JSON file, then set 0600 perms.
    {
        std::ofstream of(out_path);
        if (!of) {
            std::cerr << "cold-sign: cannot open --out for write: "
                      << out_path << "\n";
            return 1;
        }
        of << signed_text << "\n";
        if (!of) {
            std::cerr << "cold-sign: write failed on --out: "
                      << out_path << "\n";
            return 1;
        }
    }
    // 0600 — owner-only read/write. POSIX semantic; on Windows the
    // read/write bits are a no-op (NTFS ACL inherits from parent), same
    // convention every other wallet command that writes secret-derived
    // output follows (account-export, keyfile-create, etc.).
    std::error_code perm_ec;
    std::filesystem::permissions(
        out_path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace,
        perm_ec);
    (void)perm_ec;

    nlohmann::json status = {
        {"status",      "ok"},
        {"tx_hash_hex", to_hex(sb_sha)},
        {"out",         out_path},
    };
    std::cout << status.dump() << "\n";
    return 0;
}

// ── sign-arbitrary / verify-arbitrary ────────────────────────────────────────
//
// Paired commands for OFF-CHAIN, arbitrary-message Ed25519 signing using a
// fixed domain separator. Distinct from:
//   * message-sign / message-verify — uses the LEGACY domain-tagged
//     SHA-256 commitment scheme (H = SHA-256(operator_tag || msg)); the
//     operator picks the tag and verifier must agree out-of-band. Useful
//     for multi-tenant SIWE-style flows where each domain wants its own
//     replay barrier.
//   * tx-sign-verify — verifies the chain's CANONICAL transaction-signing
//     scheme (TxType byte, NUL-terminated from/to, big-endian u64s).
//
// sign-arbitrary / verify-arbitrary fill the gap between the two: a SINGLE
// well-known domain separator ("DETERM-MSG-v1") that's baked into the CLI,
// so both signer + verifier know exactly what was signed without sharing
// configuration. The signed bytes are the literal byte string
// `domain_sep || msg_bytes` — Ed25519 hashes internally per RFC 8032; we
// do NOT pre-hash with SHA-256 (the message-sign legacy command does
// pre-hash; this newer command treats the prefixed message as a flat
// byte stream, matching what most SIWE-class verifiers expect).
//
// Use case: an attestation of the form
//   "I, the holder of anon-address 0xABC, certify the following statement"
// where the verifier reads only this binary + the public bundle (no chain,
// no external configuration). Producing a sig with sign-arbitrary and a
// sig with tx-sign produces TWO different signatures over different byte
// strings — there is no cross-context replay risk.
//
// Domain separator constant — pinned here (not configurable) so a sig
// produced by determ-wallet sign-arbitrary is byte-equivalent across
// every operator's invocation.
constexpr const char* kArbitraryMsgDomainSep = "DETERM-MSG-v1";

// Slurp a file's bytes verbatim into `out`. Binary-safe (no newline strip,
// no encoding interpretation). Returns false + err on failure.
bool slurp_file_bytes(const std::string& path,
                      std::vector<uint8_t>& out,
                      std::string& err) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        err = std::string("cannot open file: ") + path;
        return false;
    }
    out.assign((std::istreambuf_iterator<char>(f)),
                std::istreambuf_iterator<char>());
    return true;
}

// Build the signed pre-image: domain_sep || msg_bytes. Concatenation, no
// pre-hash (Ed25519's internal SHA-512 handles the digest step per RFC
// 8032). Pinning the separator inside the binary means signer + verifier
// don't need to negotiate it — the protocol IS "the determ-wallet
// arbitrary-message convention."
std::vector<uint8_t> build_signing_bytes(const std::vector<uint8_t>& msg) {
    std::vector<uint8_t> sb;
    const std::string sep(kArbitraryMsgDomainSep);
    sb.reserve(sep.size() + msg.size());
    sb.insert(sb.end(), sep.begin(), sep.end());
    sb.insert(sb.end(), msg.begin(), msg.end());
    return sb;
}

// Base64-encode bytes (URL-safe variant disabled — use standard Base64
// with '+' '/' '=' so the bundle round-trips through any JSON decoder
// + any base64 library without configuration). libsodium ships
// sodium_bin2base64 / sodium_base642bin which we use for FIPS-friendly
// portable Base64 (avoids dragging in another dependency).
std::string b64_encode(const std::vector<uint8_t>& bytes) {
    const size_t enc_len = sodium_base64_ENCODED_LEN(bytes.size(),
                                                      sodium_base64_VARIANT_ORIGINAL);
    std::string out(enc_len, '\0');
    sodium_bin2base64(out.data(), enc_len,
                       bytes.data(), bytes.size(),
                       sodium_base64_VARIANT_ORIGINAL);
    // sodium writes a trailing NUL inside the buffer; std::string size
    // already accounts for it, strip the trailing '\0' for clean output.
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

// Inverse of b64_encode. Returns false on malformed input.
bool b64_decode(const std::string& s, std::vector<uint8_t>& out,
                 std::string& err) {
    out.assign(s.size(), 0);
    size_t decoded_len = 0;
    if (sodium_base642bin(out.data(), out.size(),
                           s.data(), s.size(),
                           /*ignore=*/nullptr,
                           &decoded_len,
                           /*end=*/nullptr,
                           sodium_base64_VARIANT_ORIGINAL) != 0) {
        err = "base64 decode failed (malformed input)";
        return false;
    }
    out.resize(decoded_len);
    return true;
}

// Read the priv-keyfile JSON ({address, privkey_hex}; the same shape
// `account-export` emits and `account-import` accepts) and return the
// 32-byte Ed25519 seed. Returns false + err on any structural failure.
bool load_priv_keyfile(const std::string& path,
                        std::vector<uint8_t>& seed_out,
                        std::string& address_out,
                        std::string& err) {
    std::ifstream f(path);
    if (!f) {
        err = std::string("cannot open --priv-keyfile: ") + path;
        return false;
    }
    nlohmann::json doc;
    try { f >> doc; }
    catch (std::exception& e) {
        err = std::string("--priv-keyfile is not valid JSON: ") + e.what();
        return false;
    }
    if (!doc.is_object()
        || !doc.contains("privkey_hex")
        || !doc["privkey_hex"].is_string()
        || !doc.contains("address")
        || !doc["address"].is_string()) {
        err = "--priv-keyfile must be a JSON object with string fields "
              "'address' and 'privkey_hex' (account-export shape)";
        return false;
    }
    address_out = doc["address"].get<std::string>();
    std::string priv_hex = doc["privkey_hex"].get<std::string>();
    if (priv_hex.size() != 64) {
        err = "--priv-keyfile 'privkey_hex' must be 64 hex chars (32-byte seed)";
        return false;
    }
    try { seed_out = from_hex(priv_hex); }
    catch (std::exception& e) {
        err = std::string("--priv-keyfile 'privkey_hex' invalid: ") + e.what();
        return false;
    }
    if (seed_out.size() != 32) {
        err = "--priv-keyfile 'privkey_hex' decoded to non-32 bytes";
        return false;
    }
    return true;
}

// determ-wallet sign-arbitrary — Ed25519 sign an arbitrary text/binary
// message with a fixed "DETERM-MSG-v1" domain separator. OFF-CHAIN; does
// not produce a transaction.
//
// CLI:
//   --priv-keyfile <path>: REQUIRED. JSON keyfile with {address, privkey_hex}
//                          (the shape `account-export` emits).
//   --msg <inline>:        OR
//   --msg-file <path>:     exactly one of these (--msg-file is binary-safe).
//   --out <file>:          optional. With --detached, writes the raw 64-byte
//                          sig binary; with --bundle, writes the JSON bundle.
//                          Without --out, output goes to stdout.
//   --detached:            default. Output = 64-byte sig hex (stdout) or
//                          raw 64 bytes (file when --out set).
//   --bundle:              output a self-contained JSON
//                          {"address","ed_pub_hex","domain","msg_b64","sig_hex"}
//                          (mutually exclusive with --detached).
//
// Exit codes:
//   0  signature emitted
//   1  args / parse / IO / libsodium error
int cmd_sign_arbitrary(int argc, char** argv) {
    std::string priv_keyfile, msg_inline, msg_file, out_path;
    bool detached = false, bundle = false;
    bool msg_inline_set = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--priv-keyfile" && i + 1 < argc) priv_keyfile = argv[++i];
        else if (a == "--msg"          && i + 1 < argc) { msg_inline = argv[++i]; msg_inline_set = true; }
        else if (a == "--msg-file"     && i + 1 < argc) msg_file     = argv[++i];
        else if (a == "--out"          && i + 1 < argc) out_path     = argv[++i];
        else if (a == "--detached")                     detached     = true;
        else if (a == "--bundle")                       bundle       = true;
        else {
            std::cerr << "sign-arbitrary: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet sign-arbitrary --priv-keyfile <path> "
                         "(--msg <str> | --msg-file <path>) [--out <file>] "
                         "[--detached | --bundle]\n";
            return 1;
        }
    }
    if (priv_keyfile.empty()) {
        std::cerr << "sign-arbitrary: --priv-keyfile is required\n";
        std::cerr << "Usage: determ-wallet sign-arbitrary --priv-keyfile <path> "
                     "(--msg <str> | --msg-file <path>) [--out <file>] "
                     "[--detached | --bundle]\n";
        return 1;
    }
    if (msg_inline_set == (!msg_file.empty())) {
        // Either both set or neither — both are invalid.
        std::cerr << "sign-arbitrary: exactly one of --msg or --msg-file is required\n";
        return 1;
    }
    if (detached && bundle) {
        std::cerr << "sign-arbitrary: --detached and --bundle are mutually exclusive\n";
        return 1;
    }
    // Default to --detached if neither flag was set.
    if (!detached && !bundle) detached = true;

    // ── Load priv-keyfile ───────────────────────────────────────────────────
    std::vector<uint8_t> seed;
    std::string address, err;
    if (!load_priv_keyfile(priv_keyfile, seed, address, err)) {
        std::cerr << "sign-arbitrary: " << err << "\n";
        return 1;
    }

    // ── Read the message bytes ──────────────────────────────────────────────
    std::vector<uint8_t> msg;
    if (msg_inline_set) {
        msg.assign(msg_inline.begin(), msg_inline.end());
    } else {
        if (!slurp_file_bytes(msg_file, msg, err)) {
            std::cerr << "sign-arbitrary: " << err << "\n";
            return 1;
        }
    }
    // Empty message is permitted (a sig of just the domain separator is
    // a perfectly well-defined "I am present in this domain" beacon).

    // ── Build signing_bytes = domain_sep || msg ─────────────────────────────
    std::vector<uint8_t> signing_bytes = build_signing_bytes(msg);

    // ── Ed25519 sign over signing_bytes ─────────────────────────────────────
    if (!primitives::init_libsodium()) {
        std::cerr << "sign-arbitrary: libsodium init failed\n";
        return 1;
    }
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pub{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    if (crypto_sign_seed_keypair(pub.data(), sk.data(), seed.data()) != 0) {
        std::cerr << "sign-arbitrary: crypto_sign_seed_keypair failed\n";
        return 1;
    }
    std::array<uint8_t, crypto_sign_BYTES> sig{};
    unsigned long long sig_len = 0;
    if (crypto_sign_detached(sig.data(), &sig_len,
                              signing_bytes.data(), signing_bytes.size(),
                              sk.data()) != 0) {
        sodium_memzero(sk.data(), sk.size());
        std::cerr << "sign-arbitrary: crypto_sign_detached failed\n";
        return 1;
    }
    sodium_memzero(sk.data(), sk.size());
    if (sig_len != crypto_sign_BYTES) {
        std::cerr << "sign-arbitrary: unexpected sig length " << sig_len << "\n";
        return 1;
    }

    // ── Emit ────────────────────────────────────────────────────────────────
    if (bundle) {
        nlohmann::json b;
        b["address"]    = address;
        b["ed_pub_hex"] = to_hex(pub);
        b["domain"]     = kArbitraryMsgDomainSep;
        b["msg_b64"]    = b64_encode(msg);
        b["sig_hex"]    = to_hex(sig);
        std::string text = b.dump();
        if (!out_path.empty()) {
            std::ofstream of(out_path, std::ios::binary);
            if (!of) {
                std::cerr << "sign-arbitrary: cannot open --out: " << out_path << "\n";
                return 1;
            }
            of << text << "\n";
            if (!of) {
                std::cerr << "sign-arbitrary: write failed on --out: " << out_path << "\n";
                return 1;
            }
        } else {
            std::cout << text << "\n";
        }
        return 0;
    }

    // --detached path
    if (!out_path.empty()) {
        // Binary mode: write the raw 64 sig bytes verbatim. Operators who
        // want the hex form can pass `--out` of an unset path and pipe
        // stdout, or read the file with their own hex-encoder.
        std::ofstream of(out_path, std::ios::binary);
        if (!of) {
            std::cerr << "sign-arbitrary: cannot open --out: " << out_path << "\n";
            return 1;
        }
        of.write(reinterpret_cast<const char*>(sig.data()),
                 static_cast<std::streamsize>(sig.size()));
        if (!of) {
            std::cerr << "sign-arbitrary: write failed on --out: " << out_path << "\n";
            return 1;
        }
    } else {
        std::cout << to_hex(sig) << "\n";
    }
    return 0;
}

// determ-wallet verify-arbitrary — Verify a signature produced by
// sign-arbitrary (Ed25519 over "DETERM-MSG-v1" || msg_bytes). Accepts
// either a detached sig + pubkey + msg combo OR a bundle file.
//
// CLI (detached mode):
//   --ed-pub <hex32>:      32-byte Ed25519 pubkey (64 hex chars).
//   --msg <inline> | --msg-file <path>:  exactly one.
//   --sig-hex <hex64>:     64-byte sig (128 hex chars).
// CLI (bundle mode):
//   --bundle <path>:       JSON file with {address,ed_pub_hex,domain,msg_b64,sig_hex}.
//
// Output (one-line JSON on stdout):
//   {"status":"ok","result":"VALID"|"INVALID"}
// Exit:
//   0  VALID
//   2  INVALID
//   1  args/parse/IO error
int cmd_verify_arbitrary(int argc, char** argv) {
    std::string ed_pub_hex, msg_inline, msg_file, sig_hex, bundle_path;
    bool msg_inline_set = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--ed-pub"   && i + 1 < argc) ed_pub_hex  = argv[++i];
        else if (a == "--msg"      && i + 1 < argc) { msg_inline = argv[++i]; msg_inline_set = true; }
        else if (a == "--msg-file" && i + 1 < argc) msg_file    = argv[++i];
        else if (a == "--sig-hex"  && i + 1 < argc) sig_hex     = argv[++i];
        else if (a == "--bundle"   && i + 1 < argc) bundle_path = argv[++i];
        else {
            std::cerr << "verify-arbitrary: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet verify-arbitrary "
                         "(--ed-pub <hex32> (--msg <s> | --msg-file <p>) --sig-hex <hex64>) | "
                         "(--bundle <path>)\n";
            return 1;
        }
    }

    std::vector<uint8_t> pub_bytes, sig_bytes, msg;
    std::string err;

    if (!bundle_path.empty()) {
        // Bundle mode — extract every field from the JSON.
        if (!ed_pub_hex.empty() || msg_inline_set || !msg_file.empty() || !sig_hex.empty()) {
            std::cerr << "verify-arbitrary: --bundle is mutually exclusive with "
                         "--ed-pub / --msg* / --sig-hex\n";
            return 1;
        }
        std::ifstream f(bundle_path);
        if (!f) {
            std::cerr << "verify-arbitrary: cannot open --bundle: " << bundle_path << "\n";
            return 1;
        }
        nlohmann::json b;
        try { f >> b; }
        catch (std::exception& e) {
            std::cerr << "verify-arbitrary: --bundle is not valid JSON: " << e.what() << "\n";
            return 1;
        }
        if (!b.is_object()
            || !b.contains("ed_pub_hex") || !b["ed_pub_hex"].is_string()
            || !b.contains("domain")      || !b["domain"].is_string()
            || !b.contains("msg_b64")     || !b["msg_b64"].is_string()
            || !b.contains("sig_hex")     || !b["sig_hex"].is_string()) {
            std::cerr << "verify-arbitrary: --bundle missing required string "
                         "fields (ed_pub_hex, domain, msg_b64, sig_hex)\n";
            return 1;
        }
        // Pin the domain separator at verify time — a bundle whose
        // domain field has been swapped to something other than the
        // canonical "DETERM-MSG-v1" is rejected as INVALID rather than
        // recomputed against the bundle's claim. This blocks an
        // attacker who controls the bundle from substituting their own
        // domain string to fish for a sig that validates under a
        // different pre-image.
        std::string bundle_domain = b["domain"].get<std::string>();
        if (bundle_domain != kArbitraryMsgDomainSep) {
            // Treat as INVALID (auth-style alert) rather than args error:
            // the bundle is well-formed but its domain doesn't match what
            // this binary signs over, so any sig in it can't validate
            // against our reconstructed signing_bytes.
            nlohmann::json r;
            r["status"] = "ok";
            r["result"] = "INVALID";
            std::cout << r.dump() << "\n";
            return 2;
        }
        ed_pub_hex = b["ed_pub_hex"].get<std::string>();
        sig_hex    = b["sig_hex"].get<std::string>();
        std::string msg_b64 = b["msg_b64"].get<std::string>();
        if (!b64_decode(msg_b64, msg, err)) {
            std::cerr << "verify-arbitrary: --bundle msg_b64: " << err << "\n";
            return 1;
        }
    } else {
        // Detached mode.
        if (ed_pub_hex.empty() || sig_hex.empty()) {
            std::cerr << "verify-arbitrary: --ed-pub and --sig-hex are required "
                         "(or use --bundle <path>)\n";
            return 1;
        }
        if (msg_inline_set == (!msg_file.empty())) {
            std::cerr << "verify-arbitrary: exactly one of --msg or --msg-file is required\n";
            return 1;
        }
        if (msg_inline_set) {
            msg.assign(msg_inline.begin(), msg_inline.end());
        } else {
            if (!slurp_file_bytes(msg_file, msg, err)) {
                std::cerr << "verify-arbitrary: " << err << "\n";
                return 1;
            }
        }
    }

    // Length checks.
    if (ed_pub_hex.size() != 64) {
        std::cerr << "verify-arbitrary: --ed-pub must be 64 hex chars; got "
                  << ed_pub_hex.size() << "\n";
        return 1;
    }
    if (sig_hex.size() != 128) {
        std::cerr << "verify-arbitrary: --sig-hex must be 128 hex chars; got "
                  << sig_hex.size() << "\n";
        return 1;
    }
    try { pub_bytes = from_hex(ed_pub_hex); }
    catch (std::exception& e) {
        std::cerr << "verify-arbitrary: --ed-pub hex invalid: " << e.what() << "\n";
        return 1;
    }
    try { sig_bytes = from_hex(sig_hex); }
    catch (std::exception& e) {
        std::cerr << "verify-arbitrary: --sig-hex hex invalid: " << e.what() << "\n";
        return 1;
    }
    if (pub_bytes.size() != 32 || sig_bytes.size() != 64) {
        std::cerr << "verify-arbitrary: decoded pubkey/sig wrong length\n";
        return 1;
    }

    // Reconstruct signing_bytes = domain_sep || msg, then verify.
    std::vector<uint8_t> signing_bytes = build_signing_bytes(msg);

    if (!primitives::init_libsodium()) {
        std::cerr << "verify-arbitrary: libsodium init failed\n";
        return 1;
    }
    int rc = crypto_sign_verify_detached(sig_bytes.data(),
                                          signing_bytes.data(),
                                          signing_bytes.size(),
                                          pub_bytes.data());
    const bool valid = (rc == 0);

    nlohmann::json r;
    r["status"] = "ok";
    r["result"] = valid ? "VALID" : "INVALID";
    std::cout << r.dump() << "\n";
    return valid ? 0 : 2;
}

// ── RPC socket helpers for cmd_anon_batch_balance ───────────────────────────
//
// The wallet doesn't link asio, so we drop down to BSD sockets / Winsock for
// the one command (anon-batch-balance) that genuinely needs RPC access. The
// chain's RPC protocol is JSON-over-TCP line-framed: send one
// `{"method":...,"params":{...}}\n` per request; receive one `{"result":...,
// "error":...}\n`. Multiple requests CAN share a single TCP connection — the
// server's handle_session loops on read_until('\n'), so we batch all
// per-address queries (balance, optional nonce, optional stake_info) over
// ONE socket to minimize connect()/accept() churn for large address lists.

#ifdef _WIN32
struct WinsockInit {
    WinsockInit() : ok(false) {
        WSADATA wsa{};
        ok = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
    }
    ~WinsockInit() { if (ok) WSACleanup(); }
    bool ok;
};
using sock_t = SOCKET;
constexpr sock_t kInvalidSock = INVALID_SOCKET;
inline void close_sock(sock_t s) { closesocket(s); }
#else
using sock_t = int;
constexpr sock_t kInvalidSock = -1;
inline void close_sock(sock_t s) { ::close(s); }
#endif

// Open a TCP connection to 127.0.0.1:<port>. Returns kInvalidSock on
// failure (with `err_out` populated). The caller must close_sock() on
// success.
sock_t rpc_connect_localhost(uint16_t port, std::string& err_out) {
    sock_t s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s == kInvalidSock) {
        err_out = "socket() failed";
        return kInvalidSock;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    // 127.0.0.1 in network byte order.
#ifdef _WIN32
    addr.sin_addr.s_addr = htonl(0x7F000001UL);
#else
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#endif
    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close_sock(s);
        err_out = "connect() to 127.0.0.1:" + std::to_string(port) +
                  " failed (daemon not running?)";
        return kInvalidSock;
    }
    return s;
}

// Send `line + \n` over the open socket. Returns false on any short
// write or socket error.
bool rpc_send_line(sock_t s, const std::string& payload) {
    std::string buf = payload;
    if (buf.empty() || buf.back() != '\n') buf.push_back('\n');
    size_t sent = 0;
    while (sent < buf.size()) {
#ifdef _WIN32
        int n = ::send(s, buf.data() + sent,
                        static_cast<int>(buf.size() - sent), 0);
#else
        ssize_t n = ::send(s, buf.data() + sent, buf.size() - sent, 0);
#endif
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

// Read bytes until we see a '\n', return everything up to (and not
// including) it. Returns std::nullopt on socket error / EOF before
// newline. Buffers leftover bytes in `inbuf` so subsequent reads in the
// same session pick up where this one left off.
std::optional<std::string> rpc_read_line(sock_t s, std::string& inbuf) {
    while (true) {
        auto nl = inbuf.find('\n');
        if (nl != std::string::npos) {
            std::string line = inbuf.substr(0, nl);
            inbuf.erase(0, nl + 1);
            return line;
        }
        char tmp[4096];
#ifdef _WIN32
        int n = ::recv(s, tmp, sizeof(tmp), 0);
#else
        ssize_t n = ::recv(s, tmp, sizeof(tmp), 0);
#endif
        if (n <= 0) return std::nullopt;
        inbuf.append(tmp, static_cast<size_t>(n));
    }
}

// Issue one JSON-RPC call over an already-open socket and return the
// parsed result. Throws std::runtime_error on transport / parse / RPC-
// error. The exception text is the diagnostic surface the caller emits.
nlohmann::json rpc_call_over_socket(sock_t s,
                                     std::string& inbuf,
                                     const std::string& method,
                                     const nlohmann::json& params) {
    nlohmann::json req = {{"method", method}, {"params", params}};
    if (!rpc_send_line(s, req.dump()))
        throw std::runtime_error("send failed for " + method);
    auto line = rpc_read_line(s, inbuf);
    if (!line)
        throw std::runtime_error("no response for " + method +
                                  " (daemon closed connection?)");
    nlohmann::json resp;
    try { resp = nlohmann::json::parse(*line); }
    catch (std::exception& e) {
        throw std::runtime_error("malformed response for " + method + ": " +
                                  e.what());
    }
    if (!resp.contains("error") || !resp["error"].is_null()) {
        std::string err = resp.value("error",
            nlohmann::json("unknown_error")).dump();
        throw std::runtime_error("RPC error on " + method + ": " + err);
    }
    return resp.value("result", nlohmann::json());
}

// determ-wallet anon-batch-balance — query balances + nonces + stakes
// for a batch of anon addresses against a running daemon's RPC.
//
// Use case:
//   Wallet UIs displaying a portfolio across many anon addresses;
//   operator accounting tools auditing a known set of bearer addresses;
//   CI fixtures asserting a multi-address test scenario.
//
// CLI:
//   --rpc-port N             (required) daemon RPC port (e.g. 8830)
//   --addresses <list|@file> (required) comma-separated addresses, or
//                            @path to read one-per-line from a file
//   --include-nonce          also fetch next_nonce per address (off)
//   --include-stake          also fetch stake_locked per address (off)
//   --json                   ignored (output is always JSON)
//   --help                   print this usage and exit 0
//
// Wire pattern: opens ONE TCP connection to 127.0.0.1:<rpc_port>; sends
// `status` once for chain_height; then pipelines `balance` (+ optional
// `nonce` + optional `stake_info`) for each address; closes the socket.
//
// Output (one-line JSON to stdout):
//   {"rpc_port": N, "chain_height": N, "addresses": [
//     {"address":"0x..", "balance": N, "nonce": N, "stake": N,
//      "exists": true},
//     ...
//   ], "summary": {"total_addresses": N, "total_balance": N,
//                   "total_stake": N, "exists_count": N}}
//
// `nonce` / `stake` fields are present only when --include-nonce /
// --include-stake are passed. `exists` is true iff balance > 0 OR
// nonce > 0 OR stake > 0 (any non-zero footprint on chain); for the
// balance-only path it is balance > 0.
//
// Exit codes:
//   0 success
//   1 args / IO / RPC transport / JSON-parse failure
int cmd_anon_batch_balance(int argc, char** argv) {
    int rpc_port = -1;
    std::string addrs_in;
    bool include_nonce = false;
    bool include_stake = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) rpc_port = std::atoi(argv[++i]);
        else if (a == "--addresses" && i + 1 < argc) addrs_in = argv[++i];
        else if (a == "--include-nonce") include_nonce = true;
        else if (a == "--include-stake") include_stake = true;
        else if (a == "--json") {/* default; no-op */}
        else if (a == "--help" || a == "-h") {
            std::cout <<
                "Usage: determ-wallet anon-batch-balance "
                "--rpc-port <N> --addresses <list|@file>\n"
                "       [--include-nonce] [--include-stake] [--json]\n"
                "\n"
                "  Batch-query balances (and optionally nonces + stakes) for\n"
                "  a list of anon addresses against a running daemon's RPC.\n"
                "  --addresses accepts comma-separated values or @<path> to\n"
                "  read one address per line from a file. All addresses are\n"
                "  normalized to lowercase before query (S-028 case-insensitive\n"
                "  parity). Output is one-line JSON.\n";
            return 0;
        }
        else {
            std::cerr << "anon-batch-balance: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet anon-batch-balance "
                         "--rpc-port <N> --addresses <list|@file> "
                         "[--include-nonce] [--include-stake] [--json]\n";
            return 1;
        }
    }
    if (rpc_port <= 0 || rpc_port > 65535) {
        std::cerr << "anon-batch-balance: --rpc-port <N> is required "
                     "(1..65535)\n";
        return 1;
    }
    if (addrs_in.empty()) {
        std::cerr << "anon-batch-balance: --addresses <list|@file> is "
                     "required\n";
        return 1;
    }

    // ── Resolve addresses ──────────────────────────────────────────────────
    // Accept either comma-separated inline, or @<path> (one per line).
    std::vector<std::string> addrs_raw;
    if (!addrs_in.empty() && addrs_in[0] == '@') {
        std::string path = addrs_in.substr(1);
        std::ifstream in_f(path);
        if (!in_f) {
            std::cerr << "anon-batch-balance: cannot open --addresses file: "
                      << path << "\n";
            return 1;
        }
        std::string line;
        while (std::getline(in_f, line)) {
            // Trim CR (Windows line endings) and surrounding whitespace.
            while (!line.empty() &&
                   (line.back() == '\r' || line.back() == ' ' ||
                    line.back() == '\t' || line.back() == '\n'))
                line.pop_back();
            size_t pos = 0;
            while (pos < line.size() &&
                   (line[pos] == ' ' || line[pos] == '\t'))
                ++pos;
            if (pos > 0) line.erase(0, pos);
            if (line.empty()) continue;
            if (line[0] == '#') continue;   // allow comments
            addrs_raw.push_back(line);
        }
    } else {
        std::stringstream ss(addrs_in);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            while (!tok.empty() &&
                   (tok.back() == ' ' || tok.back() == '\t'))
                tok.pop_back();
            size_t pos = 0;
            while (pos < tok.size() &&
                   (tok[pos] == ' ' || tok[pos] == '\t'))
                ++pos;
            if (pos > 0) tok.erase(0, pos);
            if (!tok.empty()) addrs_raw.push_back(tok);
        }
    }
    if (addrs_raw.empty()) {
        std::cerr << "anon-batch-balance: --addresses resolved to zero "
                     "entries (empty file or empty list)\n";
        return 1;
    }

    // Normalize each address: lowercase hex tail (S-028 parity). We
    // accept the relaxed "0x" + 64 hex shape (either case) and lowercase
    // it. Non-anon-shape inputs pass through verbatim (mirroring the
    // chain's normalize_anon_address contract — domain names are
    // unchanged so the same RPC handler can resolve them too).
    auto normalize_anon = [](std::string s) {
        if (s.size() == 66 && s[0] == '0' && s[1] == 'x') {
            bool all_hex = true;
            for (size_t i = 2; i < s.size(); ++i) {
                char c = s[i];
                bool ok = (c >= '0' && c <= '9') ||
                          (c >= 'a' && c <= 'f') ||
                          (c >= 'A' && c <= 'F');
                if (!ok) { all_hex = false; break; }
            }
            if (all_hex) {
                for (size_t i = 2; i < s.size(); ++i) {
                    char c = s[i];
                    if (c >= 'A' && c <= 'F')
                        s[i] = static_cast<char>(c - 'A' + 'a');
                }
            }
        }
        return s;
    };
    std::vector<std::string> addrs;
    addrs.reserve(addrs_raw.size());
    for (auto& a : addrs_raw) addrs.push_back(normalize_anon(a));

    // ── Winsock init + socket connect ──────────────────────────────────────
#ifdef _WIN32
    WinsockInit wsa;
    if (!wsa.ok) {
        std::cerr << "anon-batch-balance: WSAStartup failed\n";
        return 1;
    }
#endif
    std::string conn_err;
    sock_t s = rpc_connect_localhost(
        static_cast<uint16_t>(rpc_port), conn_err);
    if (s == kInvalidSock) {
        std::cerr << "anon-batch-balance: " << conn_err << "\n";
        return 1;
    }

    std::string inbuf;
    nlohmann::json out;
    out["rpc_port"] = rpc_port;
    nlohmann::json addr_arr = nlohmann::json::array();

    uint64_t total_balance  = 0;
    uint64_t total_stake    = 0;
    size_t   exists_count   = 0;
    uint64_t chain_height   = 0;

    try {
        // Fetch chain_height once for the output envelope. `status` is a
        // cheap RPC and gives operators something concrete to anchor the
        // snapshot at (multiple calls to anon-batch-balance from different
        // times can be diffed against each other via chain_height).
        auto st = rpc_call_over_socket(s, inbuf, "status", nlohmann::json::object());
        if (st.contains("height") && st["height"].is_number_unsigned())
            chain_height = st["height"].get<uint64_t>();
        else if (st.contains("height") && st["height"].is_number_integer())
            chain_height = static_cast<uint64_t>(st["height"].get<int64_t>());

        for (auto& addr : addrs) {
            nlohmann::json row;
            row["address"] = addr;

            // balance is the always-on field.
            auto bal_resp = rpc_call_over_socket(
                s, inbuf, "balance", {{"domain", addr}});
            uint64_t bal = 0;
            if (bal_resp.contains("balance") &&
                bal_resp["balance"].is_number()) {
                bal = bal_resp["balance"].is_number_unsigned()
                    ? bal_resp["balance"].get<uint64_t>()
                    : static_cast<uint64_t>(
                        bal_resp["balance"].get<int64_t>());
            }
            row["balance"] = bal;
            total_balance += bal;

            uint64_t nce = 0;
            bool nce_seen = false;
            if (include_nonce) {
                auto n_resp = rpc_call_over_socket(
                    s, inbuf, "nonce", {{"domain", addr}});
                if (n_resp.contains("next_nonce") &&
                    n_resp["next_nonce"].is_number()) {
                    nce = n_resp["next_nonce"].is_number_unsigned()
                        ? n_resp["next_nonce"].get<uint64_t>()
                        : static_cast<uint64_t>(
                            n_resp["next_nonce"].get<int64_t>());
                }
                row["nonce"] = nce;
                nce_seen = true;
            }

            uint64_t stk = 0;
            bool stk_seen = false;
            if (include_stake) {
                auto st_resp = rpc_call_over_socket(
                    s, inbuf, "stake_info", {{"domain", addr}});
                if (st_resp.contains("locked") &&
                    st_resp["locked"].is_number()) {
                    stk = st_resp["locked"].is_number_unsigned()
                        ? st_resp["locked"].get<uint64_t>()
                        : static_cast<uint64_t>(
                            st_resp["locked"].get<int64_t>());
                }
                row["stake"] = stk;
                stk_seen = true;
                total_stake += stk;
            }

            // `exists` = any non-zero footprint we observed. For the
            // balance-only path it collapses to balance > 0; with
            // --include-nonce / --include-stake it picks up addresses
            // that have been used (nonce advanced) or have stake locked
            // even at zero balance.
            bool exists = (bal > 0) ||
                          (nce_seen && nce > 0) ||
                          (stk_seen && stk > 0);
            row["exists"] = exists;
            if (exists) ++exists_count;

            addr_arr.push_back(row);
        }
    } catch (std::exception& e) {
        close_sock(s);
        std::cerr << "anon-batch-balance: " << e.what() << "\n";
        return 1;
    }
    close_sock(s);

    out["chain_height"] = chain_height;
    out["addresses"]    = addr_arr;
    out["summary"] = {
        {"total_addresses", addrs.size()},
        {"total_balance",   total_balance},
        {"total_stake",     total_stake},
        {"exists_count",    exists_count},
    };
    std::cout << out.dump() << "\n";
    return 0;
}

// determ-wallet bulk-send — Batch TRANSFER submission from a single
// keyfile to many recipients via the daemon's RPC, with per-recipient
// nonce sequencing.
//
// Use case: payroll / airdrop / mass-distribution from a hot wallet.
// Operator prepares a batch file (JSON array or CSV) of
// {recipient, amount, fee?} rows, runs `wallet bulk-send`, and gets back
// a per-row submission result. Each row consumes the next nonce in
// sequence starting from the address's current next_nonce — so a single
// invocation can submit N transactions in one shot without round-tripping
// to the daemon for each nonce.
//
// CLI:
//   --priv-keyfile <path>      REQUIRED. Single-account JSON
//                              {address, privkey_hex} (account-export
//                              shape; same as every other wallet command).
//   --batch-file <path>        REQUIRED. JSON array of objects with keys
//                              {"to": "0x...", "amount": N, "fee": N
//                              (optional)} OR CSV with header-less rows
//                              `to,amount[,fee]`. Format is auto-detected
//                              by extension (.json vs .csv); files with
//                              other extensions are parsed as JSON if the
//                              first non-whitespace byte is '[', else CSV.
//   --rpc-port <N>             REQUIRED unless --dry-run. Daemon RPC port.
//   --fee <N>                  Default fee applied to rows that don't
//                              specify one. Defaults to 0.
//   --dry-run                  Skip RPC submission. Each row is built +
//                              signed + the hash is computed, but nothing
//                              is sent to the daemon. The result row
//                              still carries tx_hash, plus the signed tx
//                              JSON in a new "signed_tx" field, so the
//                              operator can pipe the output to a cold-
//                              wallet workflow. Starting nonce is fetched
//                              via RPC if --rpc-port is supplied; otherwise
//                              defaults to 0 (operator can override the
//                              starting nonce with --starting-nonce).
//   --starting-nonce <N>       Override the starting nonce instead of
//                              fetching from the daemon. Useful for
//                              --dry-run workflows that haven't connected
//                              to a daemon, OR for pipelined submission
//                              where a prior batch hasn't yet landed
//                              on-chain (the operator picks up where the
//                              previous batch left off).
//   --continue-on-error        Keep submitting subsequent rows even if a
//                              row fails. Default is abort-on-first-error
//                              (matches payroll semantics — a mistake at
//                              row K should NOT silently fan out to
//                              every subsequent row).
//   --json                     Accepted for parity; output is always JSON.
//
// Output (one-line JSON on stdout):
//   {"keyfile": "...", "batch_size": N, "submitted": N, "failed": N,
//    "starting_nonce": N, "ending_nonce": N,
//    "results": [
//      {"row": 0, "to": "0x...", "amount": N, "fee": N, "nonce": N,
//       "tx_hash": "...", "status": "ok"|"error",
//       "reason": "..." (only on error),
//       "signed_tx": {...} (only with --dry-run)},
//      ...
//    ]}
//
// Exit codes:
//   0  every row succeeded (no failures recorded)
//   1  args / parse / IO / libsodium / RPC-connect error before any row
//      could be attempted
//   2  at least one row failed (whether the run aborted on first error
//      or continued through — the exit code reports the outcome)
int cmd_bulk_send(int argc, char** argv) {
    std::string priv_keyfile;
    std::string batch_file;
    int      rpc_port = -1;
    uint64_t default_fee = 0;
    bool     dry_run = false;
    bool     continue_on_error = false;
    int64_t  starting_nonce_override = -1;
    bool     json_out = false;  // accepted; output is always JSON
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--priv-keyfile"  && i + 1 < argc) priv_keyfile = argv[++i];
        else if (a == "--batch-file"    && i + 1 < argc) batch_file   = argv[++i];
        else if (a == "--rpc-port"      && i + 1 < argc) rpc_port     = std::atoi(argv[++i]);
        else if (a == "--fee"           && i + 1 < argc) default_fee  = std::stoull(argv[++i]);
        else if (a == "--starting-nonce" && i + 1 < argc) starting_nonce_override = std::stoll(argv[++i]);
        else if (a == "--dry-run")                        dry_run             = true;
        else if (a == "--continue-on-error")              continue_on_error   = true;
        else if (a == "--json")                           json_out            = true;
        else if (a == "--help" || a == "-h") {
            std::cout <<
                "Usage: determ-wallet bulk-send --priv-keyfile <path> "
                "--batch-file <path> --rpc-port <N>\n"
                "       [--fee <N>] [--dry-run] [--starting-nonce <N>] "
                "[--continue-on-error] [--json]\n"
                "\n"
                "  Batch TRANSFER submission from a single keyfile to many\n"
                "  recipients with per-recipient nonce sequencing. --batch-file\n"
                "  accepts JSON array [{\"to\":..,\"amount\":..,\"fee\":..}, ...]\n"
                "  or CSV (to,amount[,fee]) — auto-detected by extension.\n"
                "  --dry-run builds + signs every tx without submission (for\n"
                "  cold-wallet pipelines). --continue-on-error keeps going\n"
                "  past a failed row; default is abort-on-first-error.\n";
            return 0;
        }
        else {
            std::cerr << "bulk-send: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet bulk-send --priv-keyfile <path> "
                         "--batch-file <path> --rpc-port <N> "
                         "[--fee <N>] [--dry-run] [--starting-nonce <N>] "
                         "[--continue-on-error] [--json]\n";
            return 1;
        }
    }
    (void)json_out;
    if (priv_keyfile.empty() || batch_file.empty()) {
        std::cerr << "bulk-send: --priv-keyfile and --batch-file are required\n";
        return 1;
    }
    if (!dry_run && (rpc_port <= 0 || rpc_port > 65535)) {
        std::cerr << "bulk-send: --rpc-port <N> is required (1..65535) "
                     "unless --dry-run is supplied\n";
        return 1;
    }

    // ── Load priv keyfile ──────────────────────────────────────────────────
    std::vector<uint8_t> priv_seed;
    std::string keyfile_address;
    {
        std::string err;
        if (!load_priv_keyfile(priv_keyfile, priv_seed, keyfile_address, err)) {
            std::cerr << "bulk-send: " << err << "\n";
            return 1;
        }
    }

    // ── Parse batch file ──────────────────────────────────────────────────
    // Auto-detect format: extension wins; otherwise sniff first non-ws byte.
    struct BatchRow {
        std::string to;
        uint64_t    amount;
        uint64_t    fee;          // resolved (row.fee || default_fee)
        bool        fee_explicit; // whether row carried its own fee
    };
    std::vector<BatchRow> rows;

    auto resolve_fee = [&](std::optional<uint64_t> row_fee) -> std::pair<uint64_t, bool> {
        if (row_fee.has_value()) return {*row_fee, true};
        return {default_fee, false};
    };

    auto ends_with_ci = [](const std::string& s, const std::string& suf) {
        if (s.size() < suf.size()) return false;
        for (size_t i = 0; i < suf.size(); ++i) {
            char a = s[s.size() - suf.size() + i];
            char b = suf[i];
            if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
            if (a != b) return false;
        }
        return true;
    };

    // Slurp the batch file into memory once; large operator batches still fit
    // comfortably (a 10000-row payroll JSON is ~700KB).
    std::ifstream bf(batch_file, std::ios::binary);
    if (!bf) {
        std::cerr << "bulk-send: cannot open --batch-file: " << batch_file << "\n";
        return 1;
    }
    std::string body((std::istreambuf_iterator<char>(bf)),
                      std::istreambuf_iterator<char>());

    bool is_json = false;
    if (ends_with_ci(batch_file, ".json")) {
        is_json = true;
    } else if (ends_with_ci(batch_file, ".csv")) {
        is_json = false;
    } else {
        // Sniff first non-whitespace byte.
        size_t p = 0;
        while (p < body.size() &&
               (body[p] == ' ' || body[p] == '\t' || body[p] == '\r' ||
                body[p] == '\n')) ++p;
        is_json = (p < body.size() && body[p] == '[');
    }

    if (is_json) {
        nlohmann::json arr;
        try { arr = nlohmann::json::parse(body); }
        catch (std::exception& e) {
            std::cerr << "bulk-send: --batch-file JSON parse error: "
                      << e.what() << "\n";
            return 1;
        }
        if (!arr.is_array()) {
            std::cerr << "bulk-send: --batch-file JSON must be an array "
                         "of {to, amount, fee?} objects\n";
            return 1;
        }
        for (size_t i = 0; i < arr.size(); ++i) {
            const auto& row = arr[i];
            if (!row.is_object()) {
                std::cerr << "bulk-send: --batch-file row " << i
                          << " is not a JSON object\n";
                return 1;
            }
            if (!row.contains("to") || !row["to"].is_string()) {
                std::cerr << "bulk-send: --batch-file row " << i
                          << " missing string field 'to'\n";
                return 1;
            }
            if (!row.contains("amount") || !row["amount"].is_number()) {
                std::cerr << "bulk-send: --batch-file row " << i
                          << " missing numeric field 'amount'\n";
                return 1;
            }
            BatchRow br;
            br.to     = row["to"].get<std::string>();
            br.amount = row["amount"].is_number_unsigned()
                          ? row["amount"].get<uint64_t>()
                          : static_cast<uint64_t>(row["amount"].get<int64_t>());
            std::optional<uint64_t> row_fee;
            if (row.contains("fee") && row["fee"].is_number()) {
                row_fee = row["fee"].is_number_unsigned()
                            ? row["fee"].get<uint64_t>()
                            : static_cast<uint64_t>(row["fee"].get<int64_t>());
            }
            auto rf = resolve_fee(row_fee);
            br.fee = rf.first;
            br.fee_explicit = rf.second;
            rows.push_back(br);
        }
    } else {
        // CSV: header-less; each non-empty, non-comment line is
        // `to,amount[,fee]`. Lines starting with '#' are comments
        // (so operators can annotate payroll runs). A leading line
        // matching `to,amount` (case-insensitive) is also treated as
        // a header and skipped — convenience for spreadsheet exports.
        std::istringstream iss(body);
        std::string line;
        size_t lineno = 0;
        while (std::getline(iss, line)) {
            ++lineno;
            // Strip CR + leading/trailing whitespace.
            while (!line.empty() &&
                   (line.back() == '\r' || line.back() == ' ' ||
                    line.back() == '\t')) line.pop_back();
            size_t pos = 0;
            while (pos < line.size() &&
                   (line[pos] == ' ' || line[pos] == '\t')) ++pos;
            if (pos > 0) line.erase(0, pos);
            if (line.empty()) continue;
            if (line[0] == '#') continue;

            // Header sniff: if the first non-empty line starts with a
            // letter (not 0/1/2... or 0x for an address), treat as header.
            // We accept either "to,amount" or "to,amount,fee".
            if (rows.empty() && !line.empty() &&
                ((line[0] >= 'A' && line[0] <= 'Z') ||
                 (line[0] >= 'a' && line[0] <= 'z'))) {
                // Could be a literal "to" header OR an address starting
                // with a letter — but anon addresses always start with
                // "0x", so a leading letter is unambiguously a header.
                // (Domain-name recipients also start with a letter; those
                // can't be common in CSV bulk-send the same way payroll
                // anon-addresses are. Still, prefer correctness: only
                // skip if the line is literally "to,..." or "TO,...".)
                std::string lowfirst;
                for (size_t k = 0; k < line.size() && line[k] != ','; ++k) {
                    char c = line[k];
                    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
                    lowfirst.push_back(c);
                }
                if (lowfirst == "to") continue;
            }

            std::vector<std::string> cols;
            {
                std::string cur;
                for (char c : line) {
                    if (c == ',') { cols.push_back(cur); cur.clear(); }
                    else          { cur.push_back(c); }
                }
                cols.push_back(cur);
            }
            if (cols.size() < 2) {
                std::cerr << "bulk-send: --batch-file CSV line " << lineno
                          << " expected `to,amount[,fee]`; got '" << line << "'\n";
                return 1;
            }
            // Trim each column.
            for (auto& c : cols) {
                while (!c.empty() && (c.back() == ' ' || c.back() == '\t'))
                    c.pop_back();
                size_t pp = 0;
                while (pp < c.size() && (c[pp] == ' ' || c[pp] == '\t')) ++pp;
                if (pp > 0) c.erase(0, pp);
            }
            BatchRow br;
            br.to = cols[0];
            try {
                br.amount = std::stoull(cols[1]);
            } catch (std::exception&) {
                std::cerr << "bulk-send: --batch-file CSV line " << lineno
                          << " amount '" << cols[1] << "' is not a u64\n";
                return 1;
            }
            std::optional<uint64_t> row_fee;
            if (cols.size() >= 3 && !cols[2].empty()) {
                try { row_fee = std::stoull(cols[2]); }
                catch (std::exception&) {
                    std::cerr << "bulk-send: --batch-file CSV line " << lineno
                              << " fee '" << cols[2] << "' is not a u64\n";
                    return 1;
                }
            }
            auto rf = resolve_fee(row_fee);
            br.fee = rf.first;
            br.fee_explicit = rf.second;
            rows.push_back(br);
        }
    }

    if (rows.empty()) {
        std::cerr << "bulk-send: --batch-file parsed to zero rows\n";
        sodium_memzero(priv_seed.data(), priv_seed.size());
        return 1;
    }

    // ── Init libsodium + derive keypair from the priv seed ────────────────
    if (!primitives::init_libsodium()) {
        sodium_memzero(priv_seed.data(), priv_seed.size());
        std::cerr << "bulk-send: libsodium init failed\n";
        return 1;
    }
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pub{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    if (crypto_sign_seed_keypair(pub.data(), sk.data(), priv_seed.data()) != 0) {
        sodium_memzero(priv_seed.data(), priv_seed.size());
        sodium_memzero(sk.data(), sk.size());
        std::cerr << "bulk-send: crypto_sign_seed_keypair failed\n";
        return 1;
    }
    // Sanity-check the derived address against the keyfile-claimed address.
    // make_anon_address is "0x" + lowercase 64-hex of the pubkey.
    std::string derived_addr = "0x" + to_hex(pub);
    if (derived_addr != keyfile_address) {
        sodium_memzero(priv_seed.data(), priv_seed.size());
        sodium_memzero(sk.data(), sk.size());
        std::cerr << "bulk-send: --priv-keyfile address mismatch: "
                     "keyfile.address=" << keyfile_address
                  << " derived=" << derived_addr
                  << " (keyfile is corrupt or wrong shape)\n";
        return 1;
    }
    // priv_seed not needed past keypair derivation; scrub.
    sodium_memzero(priv_seed.data(), priv_seed.size());

    // ── Optional: connect to RPC, fetch starting nonce ────────────────────
#ifdef _WIN32
    WinsockInit wsa;
    if (!wsa.ok && !dry_run) {
        sodium_memzero(sk.data(), sk.size());
        std::cerr << "bulk-send: WSAStartup failed\n";
        return 1;
    }
#endif
    sock_t rpc_sock = kInvalidSock;
    std::string inbuf;
    uint64_t starting_nonce = 0;
    bool nonce_fetched = false;
    if (rpc_port > 0) {
        std::string conn_err;
        rpc_sock = rpc_connect_localhost(
            static_cast<uint16_t>(rpc_port), conn_err);
        if (rpc_sock == kInvalidSock) {
            // For --dry-run with no daemon available, fall back to nonce=0
            // (or operator-supplied --starting-nonce). For real submission
            // we cannot proceed.
            if (!dry_run) {
                sodium_memzero(sk.data(), sk.size());
                std::cerr << "bulk-send: " << conn_err << "\n";
                return 1;
            }
        } else {
            try {
                auto n_resp = rpc_call_over_socket(
                    rpc_sock, inbuf, "nonce", {{"domain", keyfile_address}});
                if (n_resp.contains("next_nonce") && n_resp["next_nonce"].is_number()) {
                    starting_nonce = n_resp["next_nonce"].is_number_unsigned()
                        ? n_resp["next_nonce"].get<uint64_t>()
                        : static_cast<uint64_t>(n_resp["next_nonce"].get<int64_t>());
                }
                nonce_fetched = true;
            } catch (std::exception& e) {
                if (!dry_run) {
                    close_sock(rpc_sock);
                    sodium_memzero(sk.data(), sk.size());
                    std::cerr << "bulk-send: nonce query failed: "
                              << e.what() << "\n";
                    return 1;
                }
                // dry-run: tolerate nonce-query failure; fall through.
            }
        }
    }
    if (starting_nonce_override >= 0) {
        starting_nonce = static_cast<uint64_t>(starting_nonce_override);
        nonce_fetched = true;
    }
    if (!nonce_fetched) {
        // dry-run without daemon and without --starting-nonce: default to 0.
        starting_nonce = 0;
    }

    // ── Per-row build / sign / submit ─────────────────────────────────────
    nlohmann::json results = nlohmann::json::array();
    size_t submitted = 0;
    size_t failed    = 0;
    bool   aborted   = false;
    uint64_t ending_nonce = starting_nonce;  // advances per row submitted

    for (size_t i = 0; i < rows.size(); ++i) {
        const auto& br = rows[i];
        uint64_t row_nonce = starting_nonce + static_cast<uint64_t>(i);

        nlohmann::json row_out;
        row_out["row"]    = i;
        row_out["to"]     = br.to;
        row_out["amount"] = br.amount;
        row_out["fee"]    = br.fee;
        row_out["nonce"]  = row_nonce;

        // Build canonical signing_bytes (matches src/chain/block.cpp
        // Transaction::signing_bytes; same encoding as cmd_cold_sign /
        // cmd_tx_sign_verify above). TRANSFER has empty payload.
        std::vector<uint8_t> sb;
        sb.reserve(1 + keyfile_address.size() + 1 + br.to.size() + 1 + 24);
        sb.push_back(static_cast<uint8_t>(0));  // TxType::TRANSFER == 0
        sb.insert(sb.end(), keyfile_address.begin(), keyfile_address.end());
        sb.push_back(0);
        sb.insert(sb.end(), br.to.begin(), br.to.end());
        sb.push_back(0);
        for (int j = 7; j >= 0; --j) sb.push_back((br.amount   >> (j * 8)) & 0xFF);
        for (int j = 7; j >= 0; --j) sb.push_back((br.fee      >> (j * 8)) & 0xFF);
        for (int j = 7; j >= 0; --j) sb.push_back((row_nonce   >> (j * 8)) & 0xFF);
        // payload = empty for TRANSFER; nothing appended.

        std::array<uint8_t, 32> sb_sha{};
        SHA256(sb.data(), sb.size(), sb_sha.data());

        std::array<uint8_t, crypto_sign_BYTES> sig{};
        unsigned long long sig_len = 0;
        if (crypto_sign_detached(sig.data(), &sig_len,
                                  sb.data(), sb.size(),
                                  sk.data()) != 0 ||
            sig_len != crypto_sign_BYTES) {
            row_out["status"]  = "error";
            row_out["reason"]  = "crypto_sign_detached failed";
            row_out["tx_hash"] = to_hex(sb_sha);
            ++failed;
            results.push_back(row_out);
            if (!continue_on_error) { aborted = true; break; }
            continue;
        }

        // Build the Transaction JSON envelope (matches Transaction::to_json
        // shape exactly so the chain's submit_tx parses it via from_json).
        nlohmann::json tx_json = {
            {"type",    0},                  // TxType::TRANSFER
            {"from",    keyfile_address},
            {"to",      br.to},
            {"amount",  br.amount},
            {"fee",     br.fee},
            {"nonce",   row_nonce},
            {"payload", ""},                 // empty hex payload
            {"sig",     to_hex(sig)},
            {"hash",    to_hex(sb_sha)},
        };

        row_out["tx_hash"] = to_hex(sb_sha);

        if (dry_run) {
            // Don't submit; just emit the signed tx for cold-wallet pipelines.
            row_out["signed_tx"] = tx_json;
            row_out["status"]    = "ok";
            ++submitted;
            ending_nonce = row_nonce + 1;
            results.push_back(row_out);
            continue;
        }

        // Live submission via RPC. rpc_call_over_socket throws on RPC
        // error; we catch + record reason. On a connection-level failure
        // (socket closed mid-batch) we abort the loop unconditionally —
        // re-establishing mid-batch invites pipelined-nonce confusion.
        try {
            auto resp = rpc_call_over_socket(
                rpc_sock, inbuf, "submit_tx", {{"tx", tx_json}});
            // Server returns {"status":"queued","hash":"..."} on success.
            std::string server_status = resp.value("status", std::string{});
            std::string server_hash   = resp.value("hash",   std::string{});
            if (server_status == "queued") {
                row_out["status"] = "ok";
                if (!server_hash.empty()) row_out["tx_hash"] = server_hash;
                ++submitted;
                ending_nonce = row_nonce + 1;
            } else {
                row_out["status"] = "error";
                row_out["reason"] = "unexpected submit_tx response: " + resp.dump();
                ++failed;
            }
        } catch (std::exception& e) {
            row_out["status"] = "error";
            row_out["reason"] = e.what();
            ++failed;
            results.push_back(row_out);
            if (!continue_on_error) { aborted = true; break; }
            continue;
        }

        results.push_back(row_out);
    }

    if (rpc_sock != kInvalidSock) close_sock(rpc_sock);
    sodium_memzero(sk.data(), sk.size());

    nlohmann::json out;
    out["keyfile"]        = priv_keyfile;
    out["batch_size"]     = rows.size();
    out["submitted"]      = submitted;
    out["failed"]         = failed;
    out["starting_nonce"] = starting_nonce;
    out["ending_nonce"]   = ending_nonce;
    out["dry_run"]        = dry_run;
    out["aborted"]        = aborted;
    out["results"]        = results;
    std::cout << out.dump() << "\n";

    if (failed > 0) return 2;
    return 0;
}

// determ-wallet stake-bulk-query — bulk-query validator stake info for
// many domain names against a running daemon's RPC.
//
// Use case:
//   Operator dashboards listing stake / region / activation-height
//   across a known validator roster; on-call tooling auditing a
//   subset of mainnet validators in one shot; CI fixtures asserting a
//   multi-validator test scenario.
//
// Difference from anon-batch-balance:
//   anon-batch-balance targets anon-addresses (`0x` + 64 hex) and
//   returns balance/nonce/stake; stake-bulk-query targets validator
//   DOMAINS (e.g. "alice.v") and returns the full per-validator
//   stake row {stake_locked, accumulated_slashed, active_from,
//   region, ed_pub, exists}. accumulated_slashed is chain-global
//   today (no per-domain accounting exists in chain state — see
//   chain::accumulated_slashed_), so it surfaces as 0 per row.
//
// CLI:
//   --rpc-port N         (required) daemon RPC port (e.g. 8830)
//   --domains <list|@f>  (required) comma-separated domains, or
//                        @path to read one-per-line from a file
//                        (lines starting with # are skipped,
//                        blank lines ignored)
//   --json               emit one-line JSON envelope on stdout
//                        instead of a human-readable table
//   --help               print this usage and exit 0
//
// Wire pattern: opens ONE TCP connection to 127.0.0.1:<rpc_port>;
// sends `status` once for chain_height; sends `validators` once to
// collect ed_pub/active_from/region per validator; sends
// `stake_info` per requested domain (the per-domain stake_locked
// path that the test asserts against `determ stake_info <domain>`).
//
// Default output (human-readable, sorted by stake_locked desc):
//   chain_height: N (rpc_port=N)
//   DOMAIN                          STAKE_LOCKED  ACTIVE_FROM  REGION  EXISTS
//   alice.v                            3000000000           0    us-east  YES
//   bob.v                              2000000000           0           YES
//   nobody.v                                    0           -           NO
//   (3 domains, 2 exist, total_stake_locked=5000000000)
//
// --json envelope (one-line JSON on stdout):
//   {"rpc_port": N, "chain_height": N, "domains": [
//     {"domain": "alice.v", "stake_locked": N,
//      "accumulated_slashed": 0, "active_from": N,
//      "region": "us-east", "ed_pub": "<hex>", "exists": true},
//     ...
//   ], "summary": {"total_domains": N, "total_stake_locked": N,
//                   "total_accumulated_slashed": 0,
//                   "exists_count": N}}
//
// `exists` per row: true iff the domain appears in the validator
// registrant table OR has non-zero stake_locked. (Either condition
// implies the domain has been on-chain; both are kept so that a
// domain registered without a stake — rare but legal — and a
// staked-but-deregistered domain both surface as "exists".)
//
// Exit codes:
//   0 success
//   1 args / IO / RPC transport / JSON-parse failure
int cmd_stake_bulk_query(int argc, char** argv) {
    int rpc_port = -1;
    std::string domains_in;
    bool want_json = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) rpc_port = std::atoi(argv[++i]);
        else if (a == "--domains"  && i + 1 < argc) domains_in = argv[++i];
        else if (a == "--json")    want_json = true;
        else if (a == "--help" || a == "-h") {
            std::cout <<
                "Usage: determ-wallet stake-bulk-query "
                "--rpc-port <N> --domains <list|@file>\n"
                "       [--json]\n"
                "\n"
                "  Batch-query validator stake info for a list of\n"
                "  domain names against a running daemon's RPC.\n"
                "  --domains accepts comma-separated values or @<path>\n"
                "  to read one domain per line from a file (lines\n"
                "  starting with '#' and blank lines are skipped).\n"
                "  Default output is a human-readable table sorted by\n"
                "  stake_locked desc; --json emits one-line JSON.\n";
            return 0;
        }
        else {
            std::cerr << "stake-bulk-query: unknown argument '" << a << "'\n";
            std::cerr << "Usage: determ-wallet stake-bulk-query "
                         "--rpc-port <N> --domains <list|@file> "
                         "[--json]\n";
            return 1;
        }
    }
    if (rpc_port <= 0 || rpc_port > 65535) {
        std::cerr << "stake-bulk-query: --rpc-port <N> is required "
                     "(1..65535)\n";
        return 1;
    }
    if (domains_in.empty()) {
        std::cerr << "stake-bulk-query: --domains <list|@file> is "
                     "required\n";
        return 1;
    }

    // ── Resolve domain list ───────────────────────────────────────────────
    // Accept either comma-separated inline, or @<path> (one per line).
    // Mirrors the anon-batch-balance file-parse contract (# comments,
    // blank lines ignored, surrounding whitespace trimmed).
    std::vector<std::string> domains;
    if (!domains_in.empty() && domains_in[0] == '@') {
        std::string path = domains_in.substr(1);
        std::ifstream in_f(path);
        if (!in_f) {
            std::cerr << "stake-bulk-query: cannot open --domains file: "
                      << path << "\n";
            return 1;
        }
        std::string line;
        while (std::getline(in_f, line)) {
            while (!line.empty() &&
                   (line.back() == '\r' || line.back() == ' ' ||
                    line.back() == '\t' || line.back() == '\n'))
                line.pop_back();
            size_t pos = 0;
            while (pos < line.size() &&
                   (line[pos] == ' ' || line[pos] == '\t'))
                ++pos;
            if (pos > 0) line.erase(0, pos);
            if (line.empty()) continue;
            if (line[0] == '#') continue;
            domains.push_back(line);
        }
    } else {
        std::stringstream ss(domains_in);
        std::string tok;
        while (std::getline(ss, tok, ',')) {
            while (!tok.empty() &&
                   (tok.back() == ' ' || tok.back() == '\t'))
                tok.pop_back();
            size_t pos = 0;
            while (pos < tok.size() &&
                   (tok[pos] == ' ' || tok[pos] == '\t'))
                ++pos;
            if (pos > 0) tok.erase(0, pos);
            if (!tok.empty()) domains.push_back(tok);
        }
    }
    if (domains.empty()) {
        std::cerr << "stake-bulk-query: --domains resolved to zero "
                     "entries (empty file or empty list)\n";
        return 1;
    }

    // ── Winsock init + socket connect ─────────────────────────────────────
#ifdef _WIN32
    WinsockInit wsa;
    if (!wsa.ok) {
        std::cerr << "stake-bulk-query: WSAStartup failed\n";
        return 1;
    }
#endif
    std::string conn_err;
    sock_t s = rpc_connect_localhost(
        static_cast<uint16_t>(rpc_port), conn_err);
    if (s == kInvalidSock) {
        std::cerr << "stake-bulk-query: " << conn_err << "\n";
        return 1;
    }

    std::string inbuf;
    uint64_t chain_height = 0;
    // Per-domain validator metadata (ed_pub / active_from / region)
    // sourced from the `validators` RPC. Missing entries → domain is
    // not a registered validator (exists may still be true via the
    // stake_info path if it has stake locked).
    struct ValidatorMeta {
        std::string ed_pub;
        uint64_t    active_from{0};
        std::string region;
        bool        in_registry{false};
    };
    std::map<std::string, ValidatorMeta> registry;

    struct Row {
        std::string domain;
        uint64_t    stake_locked{0};
        uint64_t    accumulated_slashed{0};  // chain-global today; 0 per-row
        uint64_t    active_from{0};
        std::string region;
        std::string ed_pub;
        bool        exists{false};
    };
    std::vector<Row> rows;
    rows.reserve(domains.size());

    try {
        // ── status: chain_height for the envelope ─────────────────────────
        auto st = rpc_call_over_socket(
            s, inbuf, "status", nlohmann::json::object());
        if (st.contains("height") && st["height"].is_number_unsigned())
            chain_height = st["height"].get<uint64_t>();
        else if (st.contains("height") && st["height"].is_number_integer())
            chain_height = static_cast<uint64_t>(st["height"].get<int64_t>());

        // ── validators: collect per-domain ed_pub/active_from/region ─────
        auto vals = rpc_call_over_socket(
            s, inbuf, "validators", nlohmann::json::object());
        if (vals.is_array()) {
            for (auto& v : vals) {
                if (!v.is_object()) continue;
                ValidatorMeta m;
                m.in_registry = true;
                if (v.contains("ed_pub") && v["ed_pub"].is_string())
                    m.ed_pub = v["ed_pub"].get<std::string>();
                if (v.contains("active_from") && v["active_from"].is_number()) {
                    m.active_from = v["active_from"].is_number_unsigned()
                        ? v["active_from"].get<uint64_t>()
                        : static_cast<uint64_t>(
                            v["active_from"].get<int64_t>());
                }
                if (v.contains("region") && v["region"].is_string())
                    m.region = v["region"].get<std::string>();
                std::string d = v.value("domain", std::string());
                if (!d.empty()) registry[d] = m;
            }
        }

        // ── stake_info per requested domain ───────────────────────────────
        // The locked field is the authoritative source for stake_locked
        // (matches `determ stake_info <domain>` exactly — both call
        // chain_.stake_lockfree under the hood per node.cpp:2974).
        for (auto& d : domains) {
            Row r;
            r.domain = d;
            auto sr = rpc_call_over_socket(
                s, inbuf, "stake_info", {{"domain", d}});
            uint64_t locked = 0;
            if (sr.contains("locked") && sr["locked"].is_number()) {
                locked = sr["locked"].is_number_unsigned()
                    ? sr["locked"].get<uint64_t>()
                    : static_cast<uint64_t>(sr["locked"].get<int64_t>());
            }
            r.stake_locked = locked;
            auto it = registry.find(d);
            if (it != registry.end()) {
                r.active_from = it->second.active_from;
                r.region      = it->second.region;
                r.ed_pub      = it->second.ed_pub;
                r.exists      = true;
            }
            // S-028 parity / safety net: also flag as existing if there
            // is any stake locked even without a registry entry (a
            // deregistered-but-not-yet-unlocked domain can land here).
            if (locked > 0) r.exists = true;
            rows.push_back(r);
        }
    } catch (std::exception& e) {
        close_sock(s);
        std::cerr << "stake-bulk-query: " << e.what() << "\n";
        return 1;
    }
    close_sock(s);

    // ── Summary aggregates ────────────────────────────────────────────────
    uint64_t total_stake     = 0;
    uint64_t total_slashed   = 0;
    size_t   exists_count    = 0;
    for (auto& r : rows) {
        total_stake   += r.stake_locked;
        total_slashed += r.accumulated_slashed;
        if (r.exists) ++exists_count;
    }

    if (want_json) {
        nlohmann::json out;
        out["rpc_port"]     = rpc_port;
        out["chain_height"] = chain_height;
        nlohmann::json arr  = nlohmann::json::array();
        for (auto& r : rows) {
            nlohmann::json row;
            row["domain"]              = r.domain;
            row["stake_locked"]        = r.stake_locked;
            row["accumulated_slashed"] = r.accumulated_slashed;
            row["active_from"]         = r.active_from;
            row["region"]              = r.region;
            row["ed_pub"]              = r.ed_pub;
            row["exists"]              = r.exists;
            arr.push_back(row);
        }
        out["domains"] = arr;
        out["summary"] = {
            {"total_domains",             rows.size()},
            {"total_stake_locked",        total_stake},
            {"total_accumulated_slashed", total_slashed},
            {"exists_count",              exists_count},
        };
        std::cout << out.dump() << "\n";
    } else {
        // Human-readable table, sorted by stake_locked desc (ties broken
        // by domain name asc for stable output).
        std::vector<Row> sorted = rows;
        std::sort(sorted.begin(), sorted.end(),
            [](const Row& a, const Row& b) {
                if (a.stake_locked != b.stake_locked)
                    return a.stake_locked > b.stake_locked;
                return a.domain < b.domain;
            });
        std::cout << "chain_height: " << chain_height
                  << " (rpc_port=" << rpc_port << ")\n";
        std::cout << "DOMAIN"
                  << std::string(26, ' ')
                  << "STAKE_LOCKED  ACTIVE_FROM  REGION   EXISTS\n";
        for (auto& r : sorted) {
            std::ostringstream line;
            line << std::left << std::setw(32) << r.domain
                 << std::right << std::setw(12) << r.stake_locked
                 << std::setw(13)  << (r.exists ? std::to_string(r.active_from) : std::string("-"))
                 << "  "
                 << std::left << std::setw(7) << (r.region.empty() ? std::string("-") : r.region)
                 << "  " << (r.exists ? "YES" : "NO");
            std::cout << line.str() << "\n";
        }
        std::cout << "(" << rows.size()
                  << " domains, " << exists_count << " exist, total_stake_locked="
                  << total_stake << ")\n";
    }
    return 0;
}

int cmd_validator_roster_snapshot(int argc, char** argv) {
    int rpc_port = -1;
    std::string out_path;
    bool include_stake_history = false;
    bool force = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) rpc_port = std::atoi(argv[++i]);
        else if (a == "--out"      && i + 1 < argc) out_path = argv[++i];
        else if (a == "--include-stake-history")    include_stake_history = true;
        else if (a == "--force")                    force = true;
        else if (a == "--json") {/* default; no-op */}
        else if (a == "--help" || a == "-h") {
            std::cout <<
                "Usage: determ-wallet validator-roster-snapshot "
                "--rpc-port <N> --out <file>\n"
                "       [--include-stake-history] [--force] [--json]\n"
                "\n"
                "  Capture a point-in-time JSON snapshot of the active\n"
                "  validator set (from the `validators` RPC) for offline\n"
                "  audit, monitoring, or diff tooling. Output is written\n"
                "  atomically to --out (via <out>.tmp + rename); refuses to\n"
                "  overwrite an existing --out without --force.\n"
                "\n"
                "  Snapshot envelope:\n"
                "    {snapshot_format_version, captured_at_unix, rpc_port,\n"
                "     chain_height, chain_id, total_validators,\n"
                "     total_stake_locked, validators: [{rank, domain,\n"
                "     ed_pub, region, active_from, [stake_locked,\n"
                "     accumulated_slashed]}, ...]}\n"
                "\n"
                "  --include-stake-history adds stake_locked +\n"
                "  accumulated_slashed per row (one extra stake_info RPC\n"
                "  per validator). Validators are sorted by ascending\n"
                "  rank for stable diff-friendly output.\n";
            return 0;
        }
        else {
            std::cerr << "validator-roster-snapshot: unknown argument '"
                      << a << "'\n";
            std::cerr << "Usage: determ-wallet validator-roster-snapshot "
                         "--rpc-port <N> --out <file> [--include-stake-history] "
                         "[--force] [--json]\n";
            return 1;
        }
    }
    if (rpc_port <= 0 || rpc_port > 65535) {
        std::cerr << "validator-roster-snapshot: --rpc-port <N> is required "
                     "(1..65535)\n";
        return 1;
    }
    if (out_path.empty()) {
        std::cerr << "validator-roster-snapshot: --out <file> is required\n";
        return 1;
    }

    // ── Overwrite guard ───────────────────────────────────────────────────
    // Mirrors account-create-batch / backup-create / keyfile-create
    // overwrite semantics: the snapshot file is a record of the
    // validator set at a specific point in time; silently clobbering
    // a previously-captured snapshot would lose audit history. --force
    // is the explicit opt-in.
    namespace fs = std::filesystem;
    std::error_code probe_ec;
    if (fs::exists(out_path, probe_ec) && !force) {
        std::cerr << "validator-roster-snapshot: refusing to overwrite "
                  << "existing file '" << out_path
                  << "' (pass --force to allow)\n";
        return 1;
    }

    // ── Winsock init + socket connect ─────────────────────────────────────
#ifdef _WIN32
    WinsockInit wsa;
    if (!wsa.ok) {
        std::cerr << "validator-roster-snapshot: WSAStartup failed\n";
        return 1;
    }
#endif
    std::string conn_err;
    sock_t s = rpc_connect_localhost(
        static_cast<uint16_t>(rpc_port), conn_err);
    if (s == kInvalidSock) {
        std::cerr << "validator-roster-snapshot: " << conn_err << "\n";
        return 1;
    }

    std::string inbuf;
    uint64_t    chain_height = 0;
    std::string chain_id;

    // Per-validator row, populated from `validators` RPC; stake_locked
    // + accumulated_slashed only populated under --include-stake-history.
    struct Row {
        uint64_t    rank{0};
        std::string domain;
        std::string ed_pub;
        std::string region;
        uint64_t    active_from{0};
        uint64_t    stake_locked{0};
        uint64_t    accumulated_slashed{0};  // chain-global; 0 per-row today
        bool        have_stake_history{false};
    };
    std::vector<Row> rows;

    try {
        // ── status: chain_height + genesis hash (chain_id) ──────────────
        auto st = rpc_call_over_socket(
            s, inbuf, "status", nlohmann::json::object());
        if (st.contains("height") && st["height"].is_number_unsigned())
            chain_height = st["height"].get<uint64_t>();
        else if (st.contains("height") && st["height"].is_number_integer())
            chain_height = static_cast<uint64_t>(st["height"].get<int64_t>());
        // `genesis` field is the hex of the genesis block's compute_hash —
        // the natural chain-identifier. Two snapshots from different
        // chains (different genesis configs) will have different chain_id
        // strings; downstream diff tooling can refuse cross-chain diffs.
        if (st.contains("genesis") && st["genesis"].is_string())
            chain_id = st["genesis"].get<std::string>();

        // ── validators: roster ──────────────────────────────────────────
        auto vals = rpc_call_over_socket(
            s, inbuf, "validators", nlohmann::json::object());
        if (!vals.is_array()) {
            throw std::runtime_error(
                "validators RPC returned non-array result");
        }
        uint64_t rank = 0;
        for (auto& v : vals) {
            if (!v.is_object()) continue;
            Row r;
            r.rank   = rank++;
            r.domain = v.value("domain", std::string{});
            r.ed_pub = v.value("ed_pub", std::string{});
            r.region = v.value("region", std::string{});
            if (v.contains("active_from") && v["active_from"].is_number()) {
                r.active_from = v["active_from"].is_number_unsigned()
                    ? v["active_from"].get<uint64_t>()
                    : static_cast<uint64_t>(
                        v["active_from"].get<int64_t>());
            }
            // The validators RPC already surfaces `stake` per row — use
            // it as the default stake_locked value when --include-stake-
            // history is OFF too (it's the same number stake_info would
            // return, sourced from chain_.stake(domain) under the
            // state_mutex_), but only EMIT it in the snapshot when the
            // flag is set, to keep the off-by-default footprint smaller.
            if (v.contains("stake") && v["stake"].is_number()) {
                r.stake_locked = v["stake"].is_number_unsigned()
                    ? v["stake"].get<uint64_t>()
                    : static_cast<uint64_t>(v["stake"].get<int64_t>());
            }
            rows.push_back(r);
        }

        // ── Optional per-validator stake_info ─────────────────────────
        // The validators RPC's `stake` field is already an authoritative
        // snapshot of chain_.stake(domain) at call time. We requery
        // stake_info here only when --include-stake-history is on to
        // ALSO surface `accumulated_slashed` (chain-global today, 0
        // per-row in this transitional shape) and re-confirm stake_locked
        // from the alternate code path. The two queries land on the same
        // mutex-protected source and should always agree.
        if (include_stake_history) {
            for (auto& r : rows) {
                if (r.domain.empty()) continue;
                auto sr = rpc_call_over_socket(
                    s, inbuf, "stake_info", {{"domain", r.domain}});
                uint64_t locked = 0;
                if (sr.contains("locked") && sr["locked"].is_number()) {
                    locked = sr["locked"].is_number_unsigned()
                        ? sr["locked"].get<uint64_t>()
                        : static_cast<uint64_t>(sr["locked"].get<int64_t>());
                }
                r.stake_locked       = locked;
                r.accumulated_slashed = 0; // chain-global; per-row 0 today
                r.have_stake_history  = true;
            }
        }
    } catch (std::exception& e) {
        close_sock(s);
        std::cerr << "validator-roster-snapshot: " << e.what() << "\n";
        return 1;
    }
    close_sock(s);

    // ── Sort by ascending rank for stable diff-friendly output ────────────
    // (Rank was assigned in the order the RPC returned, which is
    // already NodeRegistry::sorted_nodes — alphabetical by domain — so
    // this sort is structurally a no-op against the current RPC. The
    // explicit sort guards against any future drift in the RPC's
    // return ordering.)
    std::sort(rows.begin(), rows.end(),
        [](const Row& a, const Row& b) { return a.rank < b.rank; });

    // ── Aggregate ─────────────────────────────────────────────────────────
    uint64_t total_stake_locked = 0;
    for (auto& r : rows) total_stake_locked += r.stake_locked;

    // ── Build the envelope ────────────────────────────────────────────────
    nlohmann::json snap;
    snap["snapshot_format_version"] = 1;
    snap["captured_at_unix"]        = static_cast<int64_t>(std::time(nullptr));
    snap["rpc_port"]                = rpc_port;
    snap["chain_height"]            = chain_height;
    snap["chain_id"]                = chain_id;
    snap["total_validators"]        = rows.size();
    snap["total_stake_locked"]      = total_stake_locked;

    nlohmann::json arr = nlohmann::json::array();
    for (auto& r : rows) {
        nlohmann::json e;
        e["rank"]        = r.rank;
        e["domain"]      = r.domain;
        e["ed_pub"]      = r.ed_pub;
        e["region"]      = r.region;
        e["active_from"] = r.active_from;
        if (include_stake_history) {
            e["stake_locked"]        = r.stake_locked;
            e["accumulated_slashed"] = r.accumulated_slashed;
        }
        arr.push_back(e);
    }
    snap["validators"] = arr;

    // ── Atomic write: <out>.tmp + rename ──────────────────────────────────
    // Mirrors chain.cpp::save: write to a tmp file first, flush, then
    // rename. std::filesystem::rename is atomic for same-volume
    // targets on both Windows (MoveFileExA implicit REPLACE_EXISTING
    // when overwriting) and POSIX (::rename(2)).
    std::string tmp_path = out_path + ".tmp";
    {
        std::error_code mkdir_ec;
        fs::create_directories(fs::path(tmp_path).parent_path(), mkdir_ec);
        std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
        if (!f) {
            std::cerr << "validator-roster-snapshot: cannot open tmp file '"
                      << tmp_path << "' for writing\n";
            return 1;
        }
        f << snap.dump(2);
        f.flush();
        if (!f) {
            std::cerr << "validator-roster-snapshot: failed to flush tmp "
                         "file '" << tmp_path << "'\n";
            std::error_code rm_ec;
            fs::remove(tmp_path, rm_ec);
            return 1;
        }
    }
    std::error_code rename_ec;
    fs::rename(tmp_path, out_path, rename_ec);
    if (rename_ec) {
        std::cerr << "validator-roster-snapshot: cannot rename tmp "
                  << tmp_path << " → " << out_path << ": "
                  << rename_ec.message() << "\n";
        std::error_code rm_ec;
        fs::remove(tmp_path, rm_ec);
        return 1;
    }

    // ── Status line on stdout ─────────────────────────────────────────────
    nlohmann::json status;
    status["status"]               = "ok";
    status["out"]                  = out_path;
    status["chain_height"]         = chain_height;
    status["total_validators"]     = rows.size();
    status["include_stake_history"] = include_stake_history;
    std::cout << status.dump() << "\n";
    return 0;
}

void print_usage() {
    std::cerr <<
        "Usage: determ-wallet <command> ...\n"
        "\n"
        "Commands:\n"
        "  shamir split <hex> -t <T> -n <N>           Split secret into N shares\n"
        "  shamir combine <share> ...                 Reconstruct secret from >=T shares\n"
        "  shamir-split --secret <hex> --threshold T --shares N [--json]\n"
        "                                             Raw-primitive split (JSON-first output)\n"
        "  shamir-combine --shares <file> [--json]    Raw-primitive combine from JSON share file\n"
        "  shamir-verify --shares <file> [--threshold T] [--json]\n"
        "                                             Structural verification of a share-set\n"
        "                                             (no reconstruction; no secret material)\n"
        "  shamir-rotate --shares <file> --threshold T --shares-out <file>\n"
        "                [--force] [--json]\n"
        "                                             Proactive Secret Sharing (PSS) polynomial\n"
        "                                             refresh. Reconstructs the secret from >= T\n"
        "                                             input shares, then draws a FRESH polynomial\n"
        "                                             and emits a new share-set with the SAME N\n"
        "                                             and SAME x-coordinates. Old shares become\n"
        "                                             useless (different polynomial); new shares\n"
        "                                             reconstruct the SAME secret. Defense against\n"
        "                                             share leakage over time. Insufficient input\n"
        "                                             (< T) exits 2.\n"
        "  envelope encrypt --plaintext <hex>         AEAD-wrap a share or seed\n"
        "                    --password <str> [--aad <hex>] [--iters <N>]\n"
        "  envelope decrypt --envelope <blob>         Unwrap an envelope\n"
        "                    --password <str> [--aad <hex>]\n"
        "  inspect-envelope --in <file> [--json]      Dump envelope header metadata\n"
        "                                             (no decryption, no password)\n"
        "  account-create-batch --count N             Batch-generate N anonymous account\n"
        "                       [--out <file>] [--json] [--force]\n"
        "                                             keypairs (Ed25519 -> anon-address).\n"
        "                                             Default human output; --out writes a\n"
        "                                             JSON file (refuses overwrite without\n"
        "                                             --force); --json prints JSON to stdout\n"
        "                                             (ignored if --out is set). 1<=N<=10000.\n"
        "  account-derive-batch --seed <hex>          DETERMINISTIC sibling of account-create-\n"
        "                       --count N            batch: derive N accounts from a single\n"
        "                       [--out <file>] [--json] [--force]\n"
        "                                             32-byte master seed (64 hex). Algorithm:\n"
        "                                             seed_i = SHA-256(master_seed || u32_le(i));\n"
        "                                             keypair_i = ed25519_seed_keypair(seed_i).\n"
        "                                             Same master seed always produces the same\n"
        "                                             accounts; different seeds produce disjoint\n"
        "                                             sets. Use for cold-wallet provisioning\n"
        "                                             from a single backed-up seed, reproducible\n"
        "                                             test fixtures, or recovery from a master\n"
        "                                             seed. Default human prints one line per\n"
        "                                             account; --out writes JSON file (0600)\n"
        "                                             with {master_seed_hash_hex, count,\n"
        "                                             accounts:[{index,address,privkey_hex}]}\n"
        "                                             (the master seed itself is NEVER emitted).\n"
        "                                             --json same JSON to stdout. 1<=N<=10000.\n"
        "  account-import --priv <hex>                Import an existing Ed25519 private key\n"
        "                 [--out <file>] [--force] [--json]\n"
        "                                             into the wallet's anon-account JSON\n"
        "                                             format (companion to account-create-\n"
        "                                             batch, which generates fresh keys).\n"
        "                                             --priv accepts 64 hex chars (32-byte\n"
        "                                             seed) or 128 hex chars (32-byte seed ||\n"
        "                                             32-byte pubkey); 64-byte form is\n"
        "                                             validated against the seed-derived\n"
        "                                             pubkey. --out writes the JSON to file\n"
        "                                             with 0600 perms (refuses overwrite\n"
        "                                             without --force); --json prints JSON to\n"
        "                                             stdout. Output shape (single account):\n"
        "                                             {\"address\":\"0x..\",\"privkey_hex\":\"..\"}.\n"
        "  account-export --in <file>                 Re-emit a single-account JSON file in\n"
        "                 [--format raw-hex|json|backup-bundle]\n"
        "                 [--out <file>] [--force] [--json]\n"
        "                                             one of three external formats:\n"
        "                                              * raw-hex (default) prints the 64-char\n"
        "                                                privkey hex on stdout (one line);\n"
        "                                              * json passes the input account JSON\n"
        "                                                through verbatim;\n"
        "                                              * backup-bundle emits a JSON envelope\n"
        "                                                {seed_hex, pubkey_hex, anon_address,\n"
        "                                                derived_at_utc} ready for\n"
        "                                                backup-create --secret <seed_hex>.\n"
        "                                             --out writes to file (0600; refuses\n"
        "                                             overwrite without --force). --json with\n"
        "                                             --format raw-hex wraps the hex in a\n"
        "                                             {\"privkey_hex\":\"...\"} JSON object.\n"
        "  backup-verify --shares <file> --envelopes <file> [--threshold T] [--json]\n"
        "                                             Composite structural verification of a\n"
        "                                             wallet backup (Shamir shares + per-share\n"
        "                                             AEAD envelopes). No decryption, no\n"
        "                                             password required. Shares file shape:\n"
        "                                             {\"shares\": [{\"x\": int, \"y_hex\": \"...\"}, ...]}.\n"
        "                                             Envelopes file shape:\n"
        "                                             {\"envelopes\": [{\"share_index\": int,\n"
        "                                             \"envelope_blob\": \"...\"}, ...]}.\n"
        "  backup-create --secret <hex> --threshold T --keyholders <file>\n"
        "                --shares-out <file> --envelopes-out <file> [--force] [--json]\n"
        "                                             Produce a complete wallet backup\n"
        "                                             (Shamir shares + per-share AEAD envelopes)\n"
        "                                             from a secret + per-keyholder passphrases.\n"
        "                                             Inverse of backup-verify (writes the two\n"
        "                                             files backup-verify reads). Keyholders\n"
        "                                             file shape: {\"keyholders\": [{\"share_index\":\n"
        "                                             int, \"passphrase\": \"...\"}, ...]}; N is\n"
        "                                             length(keyholders); 1<=T<=N<=255.\n"
        "                                             Refuses to overwrite existing output files\n"
        "                                             without --force.\n"
        "  keyfile-create --priv <hex>                Produce a passphrase-encrypted\n"
        "                 --passphrase-from <src>     node_key.json for the determ daemon\n"
        "                 --out <file> [--force] [--json]\n"
        "                                             (S-004: validator key at rest). --priv\n"
        "                                             is a 32-byte seed (64 hex) or 64-byte\n"
        "                                             keypair (128 hex). --passphrase-from is\n"
        "                                             file:<path>, env:<NAME>, or prompt.\n"
        "                                             Output shape: header line\n"
        "                                             'DETERM-NODE-V1 <pubkey_hex>' followed\n"
        "                                             by a DWE1 envelope blob (plaintext =\n"
        "                                             {\"pubkey\": \"...\", \"priv_seed\": \"...\"}).\n"
        "  keyfile-decrypt --in <file>                Inverse of keyfile-create. Decrypts a\n"
        "                  --passphrase-from <src>    passphrase-encrypted node_key.json back to\n"
        "                  --out <file> [--force] [--json]\n"
        "                                             plaintext for offline operator workflows\n"
        "                                             (migration, recovery, debugging). --in is\n"
        "                                             the 2-line canonical format produced by\n"
        "                                             keyfile-create. --out is written matching\n"
        "                                             src/crypto/keys.cpp::save_node_key byte-\n"
        "                                             for-byte. Wrong passphrase or tampered\n"
        "                                             envelope exits 2 (indistinguishable on\n"
        "                                             stderr); malformed --in exits 1.\n"
        "  keyfile-recover --backup-shares <file>     High-level T-of-N recovery CLI: composes\n"
        "                  --backup-envelopes <file>  envelope::decrypt + shamir::combine into a\n"
        "                  --keyholders <file>        single call. Reads the (shares, envelopes)\n"
        "                  [--threshold T]            pair produced by backup-create and a T-of-N\n"
        "                  [--out <file>] [--force]   subset of keyholder passphrases; recovers\n"
        "                  [--json]                   the original secret. Keyholders file shape\n"
        "                                             is SAME as backup-create input but with\n"
        "                                             only T of N entries supplied:\n"
        "                                             {\"keyholders\": [{\"share_index\": int,\n"
        "                                             \"passphrase\": \"...\"}, ...]}. --threshold\n"
        "                                             is optional; when supplied, enforces that\n"
        "                                             the keyholders subset has at least T entries\n"
        "                                             (Shamir's info-theoretic security means an\n"
        "                                             under-threshold subset would otherwise emit\n"
        "                                             a syntactically-valid but wrong secret). By\n"
        "                                             default prints the recovered secret hex to\n"
        "                                             stdout; --out writes {\"secret_hex\": \"...\"}\n"
        "                                             JSON; --json emits the same JSON to stdout.\n"
        "                                             All failure modes (wrong passphrase,\n"
        "                                             insufficient shares, share/envelope mismatch,\n"
        "                                             malformed files) exit 2 with a diagnostic.\n"
        "  account-recover --shares <file>            Composite wallet recovery: composes\n"
        "                  --envelopes <file>         keyfile-recover (Shamir + envelope) with\n"
        "                  --keyholders <file>        account-import (Ed25519 seed -> anon-account\n"
        "                  --threshold T              JSON) in a single call. Reads the (shares,\n"
        "                  [--out <file>] [--force]   envelopes) pair produced by backup-create\n"
        "                  [--json]                   and a T-of-N subset of keyholder passphrases;\n"
        "                                             recovers the original 32-byte Ed25519 seed\n"
        "                                             and emits the wallet anon-account JSON\n"
        "                                             {\"address\":\"0x..\",\"privkey_hex\":\"..\"}.\n"
        "                                             --threshold T is REQUIRED (Shamir's info-\n"
        "                                             theoretic security means combining < T shares\n"
        "                                             would silently emit a wrong-but-syntactically-\n"
        "                                             valid wallet account). Default human prints\n"
        "                                             one line; --out writes the JSON to file with\n"
        "                                             0600 perms; --json prints JSON to stdout. All\n"
        "                                             failure modes (wrong passphrase, insufficient\n"
        "                                             shares, mismatch, non-32-byte recovered\n"
        "                                             secret) exit 2 with a diagnostic.\n"
        "  keyfile-info --in <file> [--json]          Passive diagnostic for an encrypted node\n"
        "                                             keyfile (S-004). Parses the 2-line\n"
        "                                             DETERM-NODE-V1 + DWE1 envelope shape and\n"
        "                                             dumps header pubkey, derived anon-address,\n"
        "                                             and envelope metadata (pbkdf2_iters,\n"
        "                                             salt/nonce/ct lengths, AAD presence)\n"
        "                                             WITHOUT decrypting (no passphrase, no\n"
        "                                             plaintext recovery). Exit 0 valid, 1 file\n"
        "                                             error, 2 malformed.\n"
        "  account-list --keyfiles-dir <path>         Enumerate keyfiles in a directory with\n"
        "               [--recursive]                 per-file metadata. Pure local computation\n"
        "               [--include-encrypted[=on|off]] (no daemon RPC, no decryption). Each\n"
        "               [--include-plaintext[=on|off]] regular file is classified as one of:\n"
        "               [--json]                       plaintext-single ({\"address\":..,\n"
        "                                             \"privkey_hex\":..}),\n"
        "                                             plaintext-batch ({\"accounts\":[...]}),\n"
        "                                             encrypted-DETERM-NODE-V1 (2-line header +\n"
        "                                             DWE1 envelope), or unknown (skipped from\n"
        "                                             address extraction but still listed). For\n"
        "                                             encrypted keyfiles the metadata mirrors\n"
        "                                             keyfile-info (header_tag, pbkdf2_iters,\n"
        "                                             salt_hex, nonce_hex). File mode is\n"
        "                                             reported as a 4-digit octal on POSIX,\n"
        "                                             'n/a' on Windows (no Unix-style mode bit).\n"
        "                                             Summary warnings: mode_not_0600 (plaintext\n"
        "                                             keyfile not at 0600 on POSIX) and\n"
        "                                             mixed_encrypted_and_plaintext_in_same_dir\n"
        "                                             (operator hygiene). Exit 0 success, 1\n"
        "                                             args / missing or non-directory path.\n"
        "  message-sign --priv <hex> --message <string|file:path>\n"
        "               --domain-tag <tag> [--json]\n"
        "                                             Sign a message with an Ed25519 priv key.\n"
        "                                             OFF-CHAIN (not a transaction). Uses a\n"
        "                                             domain-separated SHA-256 commitment:\n"
        "                                             H = SHA-256(domain_tag || message_bytes).\n"
        "                                             Useful for SIWE-style auth challenges,\n"
        "                                             off-chain attestations, operator-signed\n"
        "                                             announcements. --message file:<path> reads\n"
        "                                             bytes verbatim from a file (binary-safe).\n"
        "  message-verify --pubkey <hex> --message <string|file:path>\n"
        "                 --domain-tag <tag> --signature <hex> [--json]\n"
        "                                             Verify an Ed25519 signature produced by\n"
        "                                             message-sign. Exit 0 valid, 2 invalid\n"
        "                                             (auth-style alert), 1 args/parse error.\n"
        "                                             --domain-tag MUST match the sign-time tag.\n"
        "  derive-shared-secret --priv-keyfile <path>\n"
        "                       --pubkey <hex> [--json]\n"
        "                                             Compute a 32-byte X25519 Diffie-Hellman\n"
        "                                             shared secret between the priv-keyfile\n"
        "                                             holder and the --pubkey peer. Suitable as a\n"
        "                                             KDF input for off-chain message encryption\n"
        "                                             between two anon-address holders. Uses\n"
        "                                             libsodium's Ed25519->Curve25519 transform\n"
        "                                             (crypto_sign_ed25519_sk_to_curve25519 +\n"
        "                                             crypto_sign_ed25519_pk_to_curve25519) then\n"
        "                                             crypto_scalarmult. DH-symmetric: A using\n"
        "                                             (sk_A, pk_B) and B using (sk_B, pk_A) yield\n"
        "                                             byte-identical secrets. Output:\n"
        "                                             {\"shared_secret_hex\":\"...\"} one-line JSON.\n"
        "  encrypt-message --priv-keyfile <path> --peer-pubkey <hex>\n"
        "                  --in <plaintext> --out <ciphertext>\n"
        "                                             End-to-end encrypt an off-chain message\n"
        "                                             between two anon-address holders. Builds\n"
        "                                             on derive-shared-secret: same X25519 DH\n"
        "                                             then HKDF-SHA-256 (info=\"DETERM-CHAT-\n"
        "                                             AEAD-v1\"; salt=byte-min(pubA,pubB)||byte-\n"
        "                                             max(pubA,pubB)) ⇒ 32-byte AEAD key.\n"
        "                                             Wire format: nonce(12)||CT+gcm_tag(N+16).\n"
        "                                             Both sides derive the same key (HKDF salt\n"
        "                                             is symmetric in the pubkey pair). Fresh\n"
        "                                             12-byte random nonce per message ⇒ same\n"
        "                                             plaintext gives different ciphertexts.\n"
        "                                             Output: {\"status\":\"ok\",\"out\":...,\n"
        "                                             \"ciphertext_bytes\":N} one-line JSON.\n"
        "  decrypt-message --priv-keyfile <path> --peer-pubkey <hex>\n"
        "                  --in <ciphertext> --out <plaintext>\n"
        "                                             Inverse of encrypt-message. Reads the\n"
        "                                             nonce(12)||CT+tag blob, re-derives the\n"
        "                                             same 32-byte AEAD key, AES-256-GCM\n"
        "                                             verifies + decrypts. On tag-verify failure\n"
        "                                             (tampering, wrong key, wrong peer pubkey)\n"
        "                                             emits {\"status\":\"error\",\"reason\":\n"
        "                                             \"aead_tag_verify_failed\"} and exits 2.\n"
        "                                             On success: {\"status\":\"ok\",\"out\":...,\n"
        "                                             \"plaintext_bytes\":N}.\n"
        "  tx-sign-verify --tx <file> --pubkey <hex> [--json]\n"
        "                                             Verify the Ed25519 signature on a Transaction\n"
        "                                             JSON file using the chain's canonical\n"
        "                                             signing_bytes scheme (matches src/chain/\n"
        "                                             block.cpp Transaction::signing_bytes). Reads\n"
        "                                             a JSON {type,from,to,amount,fee,nonce,\n"
        "                                             payload,sig,hash} record, reconstructs\n"
        "                                             signing_bytes byte-for-byte, and checks the\n"
        "                                             sig against --pubkey. --pubkey is REQUIRED:\n"
        "                                             the wallet has no chain registry to look up\n"
        "                                             the sender's key; anon-addr senders' pubkey\n"
        "                                             IS their address (drop 0x prefix) but must\n"
        "                                             be passed explicitly to prevent off-by-one\n"
        "                                             trust mistakes. Distinct from message-sign\n"
        "                                             (off-chain domain-separated scheme); sigs\n"
        "                                             are NOT interchangeable. Exit 0 valid, 2\n"
        "                                             invalid (auth-style alert), 1 args/parse/\n"
        "                                             IO error. Output: {valid, tx_hash_hex,\n"
        "                                             computed_signing_bytes_sha256}.\n"
        "  cold-sign --tx-json <file> --priv-keyfile <file>\n"
        "            (--out <file> | --allow-stdout)\n"
        "            [--force] [--json]\n"
        "                                             OFFLINE transaction signing for the air-\n"
        "                                             gapped cold-wallet workflow. Reads an\n"
        "                                             unsigned tx JSON (Transaction::to_json\n"
        "                                             shape with sig absent/empty/all-zero),\n"
        "                                             signs with the keyfile's Ed25519 priv_seed\n"
        "                                             using the chain's canonical signing_bytes,\n"
        "                                             writes the signed envelope to --out (0600\n"
        "                                             on POSIX). No network, no RPC, no daemon —\n"
        "                                             pure file-in / file-out. Refuses to (a)\n"
        "                                             overwrite an existing 'sig' field, (b) sign\n"
        "                                             when keyfile.address != tx.from, (c)\n"
        "                                             overwrite --out without --force. --allow-\n"
        "                                             stdout emits to stdout (off by default —\n"
        "                                             exfil guard). Output (stdout): {status:ok,\n"
        "                                             tx_hash_hex, out}. Refusal exits emit a\n"
        "                                             {status:error,reason:...} JSON on stdout.\n"
        "  sign-arbitrary --priv-keyfile <path>\n"
        "                 (--msg <str> | --msg-file <path>)\n"
        "                 [--out <file>] [--detached | --bundle]\n"
        "                                             Ed25519 sign arbitrary text or binary with a\n"
        "                                             FIXED domain separator (\"DETERM-MSG-v1\").\n"
        "                                             OFF-CHAIN — distinct from tx-sign-verify\n"
        "                                             (canonical tx signing) and from message-\n"
        "                                             sign (operator-supplied domain tag + SHA-\n"
        "                                             256 commitment). --priv-keyfile points at\n"
        "                                             a JSON {address, privkey_hex} (the shape\n"
        "                                             account-export emits). --detached (default)\n"
        "                                             prints the 64-byte sig hex on stdout, or\n"
        "                                             raw 64 bytes to --out. --bundle emits a\n"
        "                                             self-contained JSON {address, ed_pub_hex,\n"
        "                                             domain, msg_b64, sig_hex} verifiable\n"
        "                                             without sharing the message separately.\n"
        "  verify-arbitrary (--ed-pub <hex32>\n"
        "                    (--msg <str> | --msg-file <path>)\n"
        "                    --sig-hex <hex64>)\n"
        "                   | (--bundle <path>)\n"
        "                                             Verify a signature produced by sign-\n"
        "                                             arbitrary. Emits one-line JSON\n"
        "                                             {\"status\":\"ok\",\"result\":\"VALID\"|\"INVALID\"}\n"
        "                                             on stdout. Exit 0 VALID, 2 INVALID, 1\n"
        "                                             args/parse error. --bundle mode reads every\n"
        "                                             field from the JSON bundle and pins the\n"
        "                                             domain separator (a bundle with a non-\n"
        "                                             canonical domain field is reported INVALID).\n"
        "  anon-batch-balance --rpc-port <N>          Query balances (+ optional nonces / stakes)\n"
        "                     --addresses <list|@file>  for a batch of anon addresses against a\n"
        "                     [--include-nonce] [--include-stake] [--json]\n"
        "                                             running daemon's RPC. --addresses accepts\n"
        "                                             comma-separated (0xABC,0xDEF,...) or\n"
        "                                             @<path> (one per line). All addresses are\n"
        "                                             normalized to lowercase (S-028 parity)\n"
        "                                             before query. Opens ONE TCP connection and\n"
        "                                             pipelines balance + optional nonce +\n"
        "                                             stake_info per address. Output (one-line\n"
        "                                             JSON): {rpc_port, chain_height, addresses:\n"
        "                                             [{address, balance, [nonce], [stake],\n"
        "                                             exists}], summary:{total_addresses,\n"
        "                                             total_balance, total_stake, exists_count}}.\n"
        "                                             Use cases: wallet UIs displaying portfolio,\n"
        "                                             operator-accounting audits of known bearer\n"
        "                                             address sets, CI fixtures verifying multi-\n"
        "                                             address scenarios. Exit 0 success, 1 args/\n"
        "                                             IO/RPC failure.\n"
        "  bulk-send --priv-keyfile <path>            Batch TRANSFER submission from a single\n"
        "            --batch-file <path> --rpc-port <N>\n"
        "            [--fee <N>] [--dry-run] [--starting-nonce <N>]\n"
        "            [--continue-on-error] [--json]\n"
        "                                             keyfile to many recipients via RPC, with\n"
        "                                             per-recipient nonce sequencing. Use case:\n"
        "                                             payroll / airdrop / mass-distribution from\n"
        "                                             a hot wallet. --batch-file accepts JSON\n"
        "                                             array [{\"to\":..,\"amount\":..,\"fee\":..}, ...]\n"
        "                                             or CSV `to,amount[,fee]` (auto-detected by\n"
        "                                             extension; sniffed by first non-ws byte\n"
        "                                             otherwise). --fee sets the default fee for\n"
        "                                             rows that omit one. --dry-run builds + signs\n"
        "                                             each tx but skips RPC submission (each row\n"
        "                                             gains a 'signed_tx' field for cold-wallet\n"
        "                                             pipelining). --starting-nonce overrides the\n"
        "                                             daemon-fetched start (useful for pipelined\n"
        "                                             submission across batches before the prior\n"
        "                                             batch lands on-chain). --continue-on-error\n"
        "                                             keeps submitting subsequent rows after a\n"
        "                                             failed one; default aborts. Output (one-\n"
        "                                             line JSON): {keyfile, batch_size, submitted,\n"
        "                                             failed, starting_nonce, ending_nonce,\n"
        "                                             dry_run, aborted, results:[{row, to,\n"
        "                                             amount, fee, nonce, tx_hash, status:ok|\n"
        "                                             error, reason?, signed_tx?}]}. Exit 0 all\n"
        "                                             rows succeeded, 1 args/parse/IO/RPC-connect\n"
        "                                             error before any row, 2 at least one row\n"
        "                                             failed.\n"
        "  stake-bulk-query --rpc-port <N>            Batch-query validator stake info for a list\n"
        "                   --domains <list|@file> [--json]\n"
        "                                             of domain names against a running daemon's\n"
        "                                             RPC. --domains accepts comma-separated\n"
        "                                             (alice.v,bob.v,...) or @<path> (one per\n"
        "                                             line, # comments + blank lines skipped).\n"
        "                                             Opens ONE TCP connection and pipelines\n"
        "                                             status + validators + per-domain stake_info\n"
        "                                             over it. Default output: human-readable\n"
        "                                             table sorted by stake_locked descending.\n"
        "                                             --json emits {rpc_port, chain_height,\n"
        "                                             domains:[{domain, stake_locked,\n"
        "                                             accumulated_slashed, active_from, region,\n"
        "                                             ed_pub, exists}], summary:{total_domains,\n"
        "                                             total_stake_locked,\n"
        "                                             total_accumulated_slashed, exists_count}}.\n"
        "                                             Per-row exists=true iff domain is in the\n"
        "                                             validator registry OR has non-zero stake.\n"
        "                                             accumulated_slashed is chain-global today\n"
        "                                             (per-domain accounting deferred); surfaces\n"
        "                                             as 0 per row. Use cases: operator dashboards\n"
        "                                             auditing a validator roster, on-call tooling\n"
        "                                             checking a subset of validators in one shot.\n"
        "                                             Exit 0 success, 1 args/IO/RPC failure.\n"
        "  validator-roster-snapshot --rpc-port <N>   Capture a point-in-time JSON snapshot of\n"
        "                            --out <file>     the active validator set for offline audit /\n"
        "                            [--include-stake-history] [--force] [--json]\n"
        "                                             monitoring / diff tooling. Opens ONE TCP\n"
        "                                             connection and pipelines `status` (for\n"
        "                                             chain_height + genesis-as-chain_id) +\n"
        "                                             `validators` (for the roster) + optionally\n"
        "                                             per-validator `stake_info` calls. Output is\n"
        "                                             written ATOMICALLY to --out (via <out>.tmp\n"
        "                                             + rename); refuses to overwrite an existing\n"
        "                                             --out without --force. Envelope:\n"
        "                                             {snapshot_format_version, captured_at_unix,\n"
        "                                             rpc_port, chain_height, chain_id,\n"
        "                                             total_validators, total_stake_locked,\n"
        "                                             validators:[{rank, domain, ed_pub, region,\n"
        "                                             active_from, [stake_locked,\n"
        "                                             accumulated_slashed]}, ...]}. validators[]\n"
        "                                             is sorted by ascending rank for stable\n"
        "                                             diff-friendly output. --include-stake-\n"
        "                                             history adds the stake_locked +\n"
        "                                             accumulated_slashed fields per row (one\n"
        "                                             extra stake_info RPC per validator).\n"
        "                                             Use cases: operator dashboards capturing a\n"
        "                                             versioned validator-set artifact for diff\n"
        "                                             over time (REGISTER / DEREGISTER / region\n"
        "                                             churn), CI / regression fixtures pinning a\n"
        "                                             known-good roster. Exit 0 success, 1 args/\n"
        "                                             IO/RPC failure.\n"
        "  create-recovery --seed <hex> --password <str>  Persist a T-of-N recovery setup\n"
        "                  -t T -n N --out <file>\n"
        "                  [--scheme {passphrase|opaque}]\n"
        "  recover --in <file> --password <str>       Reconstruct the secret\n"
        "          [--guardians <i,j,k,...>]\n"
        "  oprf-smoke                                 Verify libsodium primitives wired\n"
        "  opaque-handshake --mode {register|authenticate}\n"
        "                   --password <str> --guardian-id <0..255> [--record <hex>]\n"
        "                                             Exercise the OPAQUE adapter (stub in Phase 5)\n"
        "  version                                    Print version banner\n"
        "\n"
        "Pending (Phase 4):\n"
        "  OPAQUE per-guardian AKE replaces passphrase-only authentication\n"
        "  for create-recovery / recover (libopaque + libsodium integration).\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { print_usage(); return 1; }
    std::string cmd = argv[1];
    if (cmd == "shamir")          return cmd_shamir         (argc - 2, argv + 2);
    if (cmd == "shamir-split")    return cmd_shamir_split_raw  (argc - 2, argv + 2);
    if (cmd == "shamir-combine")  return cmd_shamir_combine_raw(argc - 2, argv + 2);
    if (cmd == "shamir-verify")   return cmd_shamir_verify   (argc - 2, argv + 2);
    if (cmd == "shamir-rotate")   return cmd_shamir_rotate   (argc - 2, argv + 2);
    if (cmd == "envelope")        return cmd_envelope       (argc - 2, argv + 2);
    if (cmd == "inspect-envelope") return cmd_inspect_envelope(argc - 2, argv + 2);
    if (cmd == "account-create-batch") return cmd_account_create_batch(argc - 2, argv + 2);
    if (cmd == "account-derive-batch") return cmd_account_derive_batch(argc - 2, argv + 2);
    if (cmd == "account-import")  return cmd_account_import (argc - 2, argv + 2);
    if (cmd == "account-export")  return cmd_account_export (argc - 2, argv + 2);
    if (cmd == "backup-verify")   return cmd_backup_verify  (argc - 2, argv + 2);
    if (cmd == "backup-create")   return cmd_backup_create  (argc - 2, argv + 2);
    if (cmd == "keyfile-create")  return cmd_keyfile_create (argc - 2, argv + 2);
    if (cmd == "keyfile-decrypt") return cmd_keyfile_decrypt(argc - 2, argv + 2);
    if (cmd == "keyfile-recover") return cmd_keyfile_recover(argc - 2, argv + 2);
    if (cmd == "account-recover") return cmd_account_recover(argc - 2, argv + 2);
    if (cmd == "keyfile-info")    return cmd_keyfile_info   (argc - 2, argv + 2);
    if (cmd == "account-list")    return cmd_account_list   (argc - 2, argv + 2);
    if (cmd == "message-sign")    return cmd_message_sign   (argc - 2, argv + 2);
    if (cmd == "message-verify")  return cmd_message_verify (argc - 2, argv + 2);
    if (cmd == "derive-shared-secret") return cmd_derive_shared_secret(argc - 2, argv + 2);
    if (cmd == "encrypt-message") return cmd_encrypt_message(argc - 2, argv + 2);
    if (cmd == "decrypt-message") return cmd_decrypt_message(argc - 2, argv + 2);
    if (cmd == "tx-sign-verify")  return cmd_tx_sign_verify (argc - 2, argv + 2);
    if (cmd == "cold-sign")       return cmd_cold_sign      (argc - 2, argv + 2);
    if (cmd == "sign-arbitrary")  return cmd_sign_arbitrary (argc - 2, argv + 2);
    if (cmd == "verify-arbitrary") return cmd_verify_arbitrary(argc - 2, argv + 2);
    if (cmd == "anon-batch-balance") return cmd_anon_batch_balance(argc - 2, argv + 2);
    if (cmd == "bulk-send")       return cmd_bulk_send       (argc - 2, argv + 2);
    if (cmd == "stake-bulk-query") return cmd_stake_bulk_query(argc - 2, argv + 2);
    if (cmd == "validator-roster-snapshot") return cmd_validator_roster_snapshot(argc - 2, argv + 2);
    if (cmd == "create-recovery") return cmd_create_recovery(argc - 2, argv + 2);
    if (cmd == "recover")         return cmd_recover        (argc - 2, argv + 2);
    if (cmd == "oprf-smoke")      return cmd_oprf_smoke     (argc - 2, argv + 2);
    if (cmd == "opaque-handshake") return cmd_opaque_handshake(argc - 2, argv + 2);
    if (cmd == "version") {
        std::cout << "determ-wallet v1.x Phase 5 (Shamir + AEAD envelope + "
                     "passphrase recovery + libsodium primitives + "
                     "OPAQUE adapter interface [stub]; libopaque vendoring "
                     "pending Phase 6)\n";
        return 0;
    }
    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        print_usage(); return 0;
    }
    std::cerr << "Unknown command: " << cmd << "\n";
    print_usage();
    return 1;
}
