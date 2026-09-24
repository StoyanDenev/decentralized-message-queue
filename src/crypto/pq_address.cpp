// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/crypto/pq_address.hpp>
#include <determ/crypto.hpp>       // determ::c99::mldsa::pk_bytes
#include <determ/crypto/sha256.hpp>
#include <determ/types.hpp>        // to_hex
#include <stdexcept>

// A5 hash PQ address (Option A, frozen at genesis 2026-07-09). The address
// formula is byte-identical to the python oracle tools/verify_pq_address.py
// (frozen corpus tools/vectors/pq_address.json) — this C is the shipped
// implementation; the vector-file gate (test_c99_vector_files.sh pq_address
// checker) is the dual-oracle. See include/determ/crypto/pq_address.hpp.

namespace determ {

namespace {
constexpr char PQ_ADDR_DST[] = "determ-pq-anon-addr-v1";
constexpr size_t PQ_ADDR_DST_LEN = sizeof(PQ_ADDR_DST) - 1;   // no NUL: 22

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

uint8_t pq_scheme_to_form(uint8_t scheme) {
    // pqauth pure ML-DSA scheme bytes 0x01/0x02/0x03 map 1:1 to the address
    // form bytes; hybrid schemes (0x10+) and everything else map to 0 (an
    // invalid form — a PQ-native account has no Ed25519 in its trust path).
    switch (scheme) {
        case 0x01: return 0x01;
        case 0x02: return 0x02;
        case 0x03: return 0x03;
    }
    return 0;
}

bool is_pq_anon_address(const std::string& s) {
    // The hash address shape: "0x" + exactly 64 hex digits (case-insensitive).
    // Deliberately identical to the Ed25519 anon-address shape — routing is by
    // tx type, never by this predicate (see the header note).
    if (s.size() != 66) return false;
    if (s[0] != '0' || s[1] != 'x') return false;
    for (size_t i = 2; i < s.size(); ++i)
        if (!is_hex_ch(s[i])) return false;
    return true;
}

std::string make_pq_anon_address(uint8_t form, const std::vector<uint8_t>& pubkey) {
    const size_t pkb = pq_form_pk_bytes(form);
    if (pkb == 0)
        throw std::invalid_argument("pq address: unknown form byte");
    if (pubkey.size() != pkb)
        throw std::invalid_argument("pq address: pubkey length != form pk_bytes");

    // preimage = u8(len(DST)) || DST || u8(form) || u32_be(len(pk)) || pk
    crypto::SHA256Builder b;
    const uint8_t dst_len = static_cast<uint8_t>(PQ_ADDR_DST_LEN);
    b.append(&dst_len, 1);
    b.append(reinterpret_cast<const uint8_t*>(PQ_ADDR_DST), PQ_ADDR_DST_LEN);
    b.append(&form, 1);
    const uint32_t pklen = static_cast<uint32_t>(pubkey.size());
    const uint8_t pklen_be[4] = {
        static_cast<uint8_t>(pklen >> 24), static_cast<uint8_t>(pklen >> 16),
        static_cast<uint8_t>(pklen >> 8),  static_cast<uint8_t>(pklen)
    };
    b.append(pklen_be, 4);
    b.append(pubkey.data(), pubkey.size());
    Hash h = b.finalize();
    return "0x" + to_hex(h.data(), h.size());
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
