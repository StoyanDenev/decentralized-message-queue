// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light CTX-2 confidential on/off-ramp tx builders (§3.22 / §3.22b). The
// CLIENT half of the shielded-pool ramp whose consensus accept-rules already
// ship (src/chain/chain.cpp SHIELD/UNSHIELD apply + src/node/validator.cpp
// determ_shield_verify / determ_unshield_verify; light-side re-verify in
// light/verify_ct.cpp). Builds + signs a submittable SHIELD (TxType 12) or
// UNSHIELD (TxType 13) from an account's Ed25519 keyfile.
//
// The confidential note's blinding factor r is DERIVED from a caller-supplied
// `blind_seed` (r = P256 hash_to_scalar over the seed, always a valid nonzero
// scalar < n). The caller SAVES the seed + amount: the same (amount, seed)
// re-derives the same note commitment C to later UNSHIELD/spend it. No RNG —
// the proof nonce is derived deterministically from (r, E[, ctx]) so a build is
// fully deterministic and byte-reproducible from its inputs. Output is a
// `Transaction::from_json`-compatible envelope (verify with
// `determ-light verify-ct-tx` / `determ verify-ct-tx`; submit via `submit-tx`).
//
// CALLER RESPONSIBILITIES (the builder cannot enforce these offline):
//   * `blind_seed` MUST be >= 32 bytes of HIGH-ENTROPY randomness, UNIQUE per
//     note. A reused/low-entropy seed defeats amount confidentiality (a reused
//     seed makes C1-C2 = (v1-v2)*G leak the amount difference, and even yields
//     byte-identical SHIELD proofs). A >=32-byte floor is enforced; uniqueness
//     is the caller's job.
//   * `to` (UNSHIELD) must be CANONICAL (lowercase anon-shape; the CLI rejects
//     non-canonical) and route to the tx's OWN shard — UNSHIELD is single-shard
//     in v1 (validator rejects cross-shard). An offline builder has no shard
//     map, so routing is the caller's responsibility.
// SHIELD amount-binding rests on the E-recompute + the Ed25519 envelope
// signature (which covers the amount) + the knowledge-of-r spend gate, NOT on
// the balance proof being non-malleable in the amount.
#pragma once
#include "keyfile.hpp"
#include <nlohmann/json.hpp>
#include <cstdint>
#include <string>
#include <vector>

namespace determ::light {

// SHIELD (TxType 12): transparent -> confidential on-ramp. Debits the PUBLIC
// `amount` (+ `fee`) from the account's transparent balance and mints a fresh
// confidential note committing to `amount` with blinding derived from
// `blind_seed`. Account-Ed25519-signed. Throws on amount==0.
nlohmann::json build_shield_tx(const LightKeyfile& kf, uint64_t amount,
                               const std::vector<uint8_t>& blind_seed,
                               uint64_t fee, uint64_t nonce);

// UNSHIELD (TxType 13): confidential -> transparent withdraw of the note
// (amount, blind_seed) back to transparent `to`, credited `amount - fee`. The
// balance proof is CONTEXT-BOUND to (from, to, nonce, amount) so a captured
// proof cannot be replayed/redirected. Throws on amount==0, amount<fee, or
// empty `to`.
nlohmann::json build_unshield_tx(const LightKeyfile& kf, uint64_t amount,
                                 const std::vector<uint8_t>& blind_seed,
                                 const std::string& to,
                                 uint64_t fee, uint64_t nonce);

} // namespace determ::light
