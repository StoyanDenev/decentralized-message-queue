// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once
// §3.22b shielded-pool spend-binding context (UNSHIELD, and later
// CONFIDENTIAL_TRANSFER). See docs/proofs/ShieldedPoolSoundness.md.
#include <cstdint>
#include <string>
#include <determ/types.hpp>
#include <determ/crypto/sha256.hpp>

namespace determ::chain {

// The UNSHIELD spend-binding context DIGEST. A confidential withdraw proves
// knowledge of the note blinding r (which authorizes the spend), but a bare
// proof-of-knowledge is replayable — a mempool observer could copy the public
// commitment+proof into their OWN tx and redirect the credit (front-running
// theft). To stop that, the withdraw's balance proof is CONTEXT-BOUND: its
// Fiat-Shamir challenge is c = hash_to_scalar(E || T || ctx32) where
// ctx32 = this digest over the exact withdrawing tx's (from, to, nonce, amount).
// Any change to those fields changes the digest and invalidates the proof, so a
// captured proof cannot be redirected or replayed at a different nonce.
//
// Encoding is length-prefixed (u64 length before each variable-width string) so
// distinct (from, to) can never alias. This helper is the SINGLE source of the
// context on all three sides — the client prover, the validator accept-rule, and
// the apply-time re-verify — so they cannot drift (the S-043 one-formula-one-
// function rule).
inline Hash unshield_spend_ctx_hash(const std::string& from, const std::string& to,
                                    uint64_t nonce, uint64_t amount) {
    static const char DST[] = "determ-unshield-v1";
    crypto::SHA256Builder b;
    b.append(reinterpret_cast<const uint8_t*>(DST), sizeof(DST) - 1);
    b.append(static_cast<uint64_t>(from.size())); b.append(from);
    b.append(static_cast<uint64_t>(to.size()));   b.append(to);
    b.append(nonce);
    b.append(amount);
    return b.finalize();
}

}  // namespace determ::chain
