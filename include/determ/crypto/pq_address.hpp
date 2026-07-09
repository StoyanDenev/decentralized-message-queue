// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
// PQ-native anon address (CRYPTO-C99-SPEC §3.21) — HASH form (Option A),
// frozen at genesis per pre-launch register A5 (owner 2026-07-09).
//
//   addr = "0x" + hex(SHA256( u8(len(DST)) || DST || u8(form)
//                           || u32_be(len(pk)) || pk ))
//   DST  = "determ-pq-anon-addr-v1"; form 0x01=ML-DSA-44 / 0x02=65 / 0x03=87.
//
// The address is a 66-char (0x + 64 hex) COMMITMENT to (form, ML-DSA pubkey),
// NOT the bearer key itself (that was the removed Option B). Consequences,
// all deliberate:
//   * NON-INVERTIBLE — you cannot recover the pubkey OR the form from the
//     address. Verification recomputes the address from a CARRIED pubkey +
//     form (the DPQ1 `pq_auth` envelope carries both) and compares — see
//     `verify_pq_transaction`. There is therefore no `parse_pq_anon_pubkey`
//     or `pq_anon_address_form`; they cannot exist for a hash.
//   * SHAPE-COLLIDES with the 66-char Ed25519 anon address on purpose. The
//     two families are NOT distinguished by address shape (they can't be) —
//     they are distinguished by TRANSACTION TYPE at the consensus router
//     (PQ_TRANSFER → the PQ path; everything else → the Ed25519 path). The
//     account namespaces safely coexist: spending value at a hash address via
//     the "wrong" mechanism requires either the Ed25519 private key for a
//     hash-looking pubkey (unknown) or an ML-DSA preimage of a pubkey (2^256).
// Quantum-resistant: the address commits to the ML-DSA key with no Ed25519 in
// the trust path. Case-insensitive on read (S-028); make_* emits lowercase.
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace determ {

// ML-DSA public-key length for a form byte; 0 if the form is not 0x01/0x02/0x03.
size_t pq_form_pk_bytes(uint8_t form);

// Map a DPQ1 pqauth scheme byte (0x01/0x02/0x03 = ML-DSA-44/65/87) to the PQ
// address form byte. Returns 0 for any hybrid or unknown scheme (a PQ-native
// account admits only the three pure ML-DSA schemes).
uint8_t pq_scheme_to_form(uint8_t scheme);

// Shape recognizer for the HASH address: exactly "0x" + 64 hex digits,
// case-insensitive. (Identical to the Ed25519 anon-address shape by design —
// see the header note; routing is by tx type, never by this predicate.)
bool is_pq_anon_address(const std::string& s);

// Build the canonical (lowercase) hash PQ address for a form + pubkey.
// Throws std::invalid_argument if the form is unknown or the pubkey length
// does not match the form.
std::string make_pq_anon_address(uint8_t form, const std::vector<uint8_t>& pubkey);

// Lowercase the 0x-hex tail (S-028 canonical form). Returns the input
// unchanged if it is not hash-PQ-address-shaped.
std::string normalize_pq_anon_address(const std::string& s);

} // namespace determ
