// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/crypto/pq_address.hpp>
#include <determ/crypto.hpp>   // determ::c99::mldsa::pk_bytes
#include <determ/types.hpp>    // to_hex, from_hex
#include <stdexcept>

namespace determ {

namespace {
bool is_hex_ch(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
} // namespace

size_t pq_form_pk_bytes(uint8_t form) {
    using PS = determ::c99::mldsa::ParamSet;
    switch (form) {
        case 0x01: return determ::c99::mldsa::pk_bytes(PS::ML_DSA_44);
        case 0x02: return determ::c99::mldsa::pk_bytes(PS::ML_DSA_65);
        case 0x03: return determ::c99::mldsa::pk_bytes(PS::ML_DSA_87);
    }
    return 0;
}

bool is_pq_anon_address(const std::string& s) {
    // "0x" + 2 hex form digits + exactly 2*pk_bytes(form) hex body digits.
    if (s.size() < 4) return false;
    if (s[0] != '0' || s[1] != 'x') return false;
    if (!is_hex_ch(s[2]) || !is_hex_ch(s[3])) return false;
    const uint8_t form = static_cast<uint8_t>(std::stoul(s.substr(2, 2), nullptr, 16));
    const size_t pkb = pq_form_pk_bytes(form);
    if (pkb == 0) return false;
    if (s.size() != 2 + 2 + 2 * pkb) return false;   // 0x | form | body — fixed per form
    for (size_t i = 4; i < s.size(); ++i)
        if (!is_hex_ch(s[i])) return false;
    return true;
}

int pq_anon_address_form(const std::string& s) {
    if (!is_pq_anon_address(s)) return -1;
    return static_cast<int>(std::stoul(s.substr(2, 2), nullptr, 16));
}

std::vector<uint8_t> parse_pq_anon_pubkey(const std::string& s) {
    if (!is_pq_anon_address(s))
        throw std::invalid_argument("not a pq anon address: " + s.substr(0, 12) + "...");
    return from_hex(s.substr(4));   // from_hex is case-insensitive (std::stoul base 16)
}

std::string make_pq_anon_address(uint8_t form, const std::vector<uint8_t>& pubkey) {
    if (pq_form_pk_bytes(form) == 0)
        throw std::invalid_argument("pq address: unknown form byte");
    if (pubkey.size() != pq_form_pk_bytes(form))
        throw std::invalid_argument("pq address: pubkey length != form pk_bytes");
    return "0x" + to_hex(&form, 1) + to_hex(pubkey.data(), pubkey.size());
}

std::string normalize_pq_anon_address(const std::string& s) {
    if (!is_pq_anon_address(s)) return s;
    std::string out = s;
    for (size_t i = 2; i < out.size(); ++i) {
        char c = out[i];
        if (c >= 'A' && c <= 'F') out[i] = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

} // namespace determ
