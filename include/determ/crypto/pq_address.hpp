// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
// PQ-native bearer address (CRYPTO-C99-SPEC §3.21, AnonAddressDerivationMigration
// Option B). Layout:  "0x" + hex(form) + hex(ML-DSA public key)
//   form 0x01 = ML-DSA-44, 0x02 = ML-DSA-65, 0x03 = ML-DSA-87.
// The address IS the public key (bearer semantics, like the Ed25519 anon
// address) — but form-prefixed so the parameter set + pubkey length are
// self-describing, and quantum-resistant because the address commits to the
// ML-DSA key (no Ed25519 in the trust path). The length (2628 / 3908 / 5188
// chars) can never alias the fixed 66-char Ed25519 anon address, so the two
// address spaces are disjoint and the existing is_anon_address path is
// untouched. Case-insensitive on read (S-028); make_* emits canonical lowercase.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace determ {

// ML-DSA public-key length for a form byte; 0 if the form is not 0x01/0x02/0x03.
size_t pq_form_pk_bytes(uint8_t form);

// Shape recognizer: "0x" + 2 form hex (in {01,02,03}) + exactly 2*pk_bytes(form)
// hex. Case-insensitive. Disjoint from is_anon_address (which is exactly 66).
bool is_pq_anon_address(const std::string& s);

// The form byte of a PQ address, or -1 if `s` is not a PQ address.
int pq_anon_address_form(const std::string& s);

// Recover the ML-DSA public key bytes from a PQ address. Throws std::invalid_argument
// if `s` is not a valid PQ address.
std::vector<uint8_t> parse_pq_anon_pubkey(const std::string& s);

// Build the canonical (lowercase) PQ address for a form + pubkey. Throws if the
// pubkey length does not match the form.
std::string make_pq_anon_address(uint8_t form, const std::vector<uint8_t>& pubkey);

// Lowercase the hex tail of a PQ address (S-028 canonical form). Returns the
// input unchanged if it is not PQ-address-shaped.
std::string normalize_pq_anon_address(const std::string& s);

} // namespace determ
