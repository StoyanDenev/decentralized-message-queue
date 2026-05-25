// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light verifier — header-chain, committee-sig, merkle-proof
// verification primitives. All operate on already-parsed JSON shapes
// returned by the daemon's RPCs (or piped on stdin), so the same
// helpers are reusable by both the standalone `verify-*` subcommands
// AND the composite trustless-read flow.
//
// Trust model: every function here is a pure verifier. Each takes
// untrusted JSON input and an anchor (genesis hash, prior block_hash,
// or trusted state_root) and returns a structured VerifyResult.
// Nothing in this header phones home or touches a daemon.

#pragma once
#include <determ/chain/block.hpp>
#include <determ/types.hpp>
#include <nlohmann/json.hpp>
#include <map>
#include <string>
#include <vector>

namespace determ::light {

// Structured result for any verifier. `ok == true` means the input
// validates against the supplied anchor(s). On failure, `detail`
// names the field / index / hash that broke the chain.
struct VerifyResult {
    bool        ok{false};
    std::string detail;
    // Optional informational fields populated on success:
    size_t      count{0};       // how many headers / sigs / leaves verified
    std::string block_hash_hex; // last header's block_hash (verify-headers)
    std::string state_root_hex; // for verify-state-proof / verify-block-sigs
    std::string digest_hex;     // computed block_digest (verify-block-sigs)
};

// Verify the prev_hash chain in a `rpc_headers` response.
//   headers_json: the daemon's `rpc_headers` reply (i.e. `{headers: [...],
//                 from, count, height}`).
//   genesis_hash_hex: optional. If non-empty AND the slice starts at
//                    index 0, also verifies header[0].block_hash equals
//                    this value (the operator's pinned genesis anchor).
//   prev_hash_hex: optional. If non-empty AND the slice starts at
//                  index > 0, the first header's prev_hash must equal
//                  this value (a previously-verified anchor).
//
// On success: result.count = number of headers verified, result.block_hash_hex
// = block_hash of the last header (suitable for chaining the next fetch).
VerifyResult verify_headers(const nlohmann::json& headers_json,
                            const std::string& genesis_hash_hex,
                            const std::string& prev_hash_hex);

// Verify K-of-K (MD mode) or ceil(2K/3) (BFT mode) Ed25519 committee
// signatures over compute_block_digest(block).
//   header_json: a single header from rpc_headers (after stripping the
//                envelope). Both stripped (no transactions) and full
//                Block JSON shapes work — compute_block_digest doesn't
//                touch the stripped fields.
//   committee_json: a JSON array OR `{members: [...]}` envelope where each
//                  member is `{domain: "...", ed_pub: "<64-hex>"}`.
//   bft_mode: when true, threshold = ceil(2K/3) with sentinel-zero
//             allowed; when false, full K-of-K required.
//
// On success: result.count = number of valid sigs, result.digest_hex =
// compute_block_digest(header) hex, result.state_root_hex = header's
// state_root if non-zero (light client uses this to anchor subsequent
// state-proof verifications).
VerifyResult verify_block_sigs(const nlohmann::json& header_json,
                               const nlohmann::json& committee_json,
                               bool bft_mode);

// Verify a state-proof JSON (the daemon's `rpc_state_proof` reply
// shape) using a supplied trusted state_root.
//   proof_json: the daemon's `rpc_state_proof` reply (i.e. `{namespace,
//               key, key_bytes, value_hash, target_index, leaf_count,
//               proof, state_root, height}`).
//   expected_root_hex: optional. If non-empty, verify against THIS
//                     root rather than the proof's claimed root. (In
//                     trustless mode the operator always supplies a
//                     locally-recomputed root from a verified header.)
//
// On success: result.state_root_hex = the root verified against.
VerifyResult verify_state_proof(const nlohmann::json& proof_json,
                                const std::string& expected_root_hex);

// Helper: parse a committee-member array (with or without `{members: [...]}`
// envelope) into a domain → pubkey map. Throws std::runtime_error on
// malformed input. Exposed because verify-chain reuses this across
// multiple per-block verifications without re-parsing.
std::map<std::string, PubKey>
parse_committee(const nlohmann::json& committee_json);

// Helper: pad a stripped header (from rpc_headers) back to a shape
// Block::from_json can parse. The heavy collections that rpc_headers
// erases (`transactions`, `cross_shard_receipts`, `inbound_receipts`,
// `initial_state`) are NOT inputs to compute_block_digest, so empty
// arrays are semantically equivalent for the digest verification.
nlohmann::json pad_stripped_header(nlohmann::json h);

// Helper: compute the block_digest the K-of-K committee signs.
// COPY OF producer.cpp:577-591 — keep in sync if compute_block_digest
// changes upstream. Reproducing the byte order + field set inline so
// the light-client binary doesn't have to link node/producer.cpp
// (which pulls in chain.cpp + node.cpp + dozens of consensus headers).
Hash light_compute_block_digest(const determ::chain::Block& b);

} // namespace determ::light
