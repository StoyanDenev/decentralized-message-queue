// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light `account-history` subcommand — trustless verified
// balance/nonce trajectory for an account over a sequence of heights.
//
// Use case: an auditor wants a verified balance/nonce trajectory for a
// domain across an epoch (e.g. "show alice's verified state at heights
// 100, 110, 120, …, 200"). Each sampled height is anchored to a
// committee-signed block header, so the daemon cannot fabricate the
// trajectory — every row carries the on-chain committee-attested
// state_root at that height.
//
// Composition: this is a height-parameterized generalization of the
// `balance-trustless` / `nonce-trustless` flow. It REUSES the existing
// verification primitives (anchor_genesis, verify_headers,
// verify_block_sigs from verify.cpp, and read_account_trustless from
// trustless_read.cpp) rather than reimplementing any verification.
//
// Per sampled height h the command:
//   1. Fetches header[h] via the `headers` RPC.
//   2. Verifies the prev_hash chain from the genesis anchor up through h
//      (committee-attested chain continuity).
//   3. Verifies header[h]'s K-of-K (or BFT) committee Ed25519 sigs —
//      this proves the committee signed off on state_root_h.
//   4. Records (h, balance, next_nonce, state_root_h).
//
// RPC constraint (load-bearing for the trust model): the daemon's
// `state_proof` / `account` RPCs serve the CURRENT head only — neither
// takes a height parameter (see src/node/node.cpp::rpc_state_proof /
// rpc_account; both read chain_.compute_state_root() / committed view at
// the tip). So a Merkle inclusion proof of the (balance, next_nonce)
// leaf is only obtainable at the head. account-history therefore:
//   * Merkle-VERIFIES (balance, next_nonce) at the head row via the full
//     read_account_trustless path (proof rolls up to the committee-signed
//     head state_root, and the daemon's cleartext is hash-cross-checked).
//   * For every sampled height h < head, records the committee-VERIFIED
//     state_root_h (the on-chain commitment the committee signed at h)
//     and carries the head-anchored balance/nonce annotated with the
//     height at which they were Merkle-proven (`balance_proven_at_height`).
// A row's `balance_merkle_verified` flag is true ONLY when the daemon
// served a state-proof whose height equals that row's height — which,
// against a head-only daemon, is the head row. Every OTHER row carries
// the head-proven balance/nonce under an explicit `head@H` provenance
// label (JSON `balance_source`), so a reader can never mistake it for
// D's balance at that row's own height (they differ whenever D's balance
// changed between h and the head — even against an HONEST daemon). If the
// RPC ever grows a `height` parameter, extending the per-sample loop to
// fetch a per-height state-proof would let `balance_merkle_verified`
// engage at every row (the verification primitives are already
// height-generic).
//
// Trust model: --genesis pins chain identity (fail-closed if the
// daemon's block 0 doesn't hash to compute_genesis_hash). Each row's
// state_root is NOT the daemon's word — it is read from a header whose
// committee signatures this client verified locally. A daemon that lies
// about a historical state_root fails the committee-sig check and the
// command aborts.

#pragma once
#include <cstdint>
#include <string>

namespace determ::light {

// Options parsed from CLI flags. See main.cpp::cmd_account_history.
struct AccountHistoryOptions {
    uint16_t    rpc_port{0};
    std::string genesis_path;
    std::string domain;
    uint64_t    from{0};
    uint64_t    to{0};
    uint64_t    step{1};      // default stride is 1 (every height in range)
    bool        json_out{false};
    uint64_t    wait_seconds{0}; // --wait: hold-and-wait for the next block when
                                 // a sampled height is the chain head (0 = off,
                                 // fail-closed at the head, unchanged behaviour)
};

// Run the account-history flow. Returns 0 on success, non-zero on any
// failure (genesis-anchor mismatch, fetch failure, out-of-range height,
// committee-sig verification failure). Diagnostics go to stderr.
//
// Text output (default): a header line + one row per sampled height.
// Because the state_proof RPC is head-only, EVERY row carries the same
// head-proven balance/next_nonce; the balance_src column marks the
// provenance — head@H (the head value, NOT the value at that row's own
// height) vs merkle@H (Merkle-proven at the head row's own height H):
//   height   balance      next_nonce   state_root        balance_src
//   5        420          4            a1b2c3d4e5f6a7b8  head@31
//   10       420          4            d4c3b2a1f6e5d8c7  head@31
//   ...
//   30       420          4            9f8e7d6c5b4a3210  merkle@31
//
// JSON output (--json): a structured object:
//   {
//     "domain":      "<canonical-domain>",
//     "head_height": <H>,
//     "from": <H1>, "to": <H2>, "step": <S>,
//     "history": [
//       { "height": <h>, "balance": <b>, "next_nonce": <n>,
//         "state_root": "<64-hex>", "balance_merkle_verified": <bool>,
//         "balance_proven_at_height": <h_proof>,
//         "balance_source": "head@<H>" | "merkle@<H>" },
//       ...
//     ]
//   }
int run_account_history(const AccountHistoryOptions& opts);

// AH-1: the state_root reported for the GENESIS row (height 0). The genesis
// block carries NO committee-attested state_root — make_genesis_block never sets
// it, so `g.state_root` is the all-zero Hash{} by construction — and the daemon's
// served `state_root` FIELD at index 0 is unbound (genesis has zero
// creator_block_sigs; anchor_genesis binds only block-0's block_hash). So a
// hostile daemon could echo an arbitrary forged root on the h=0 row. This returns
// the GENUINE (empty) genesis state_root, DELIBERATELY IGNORING the served value;
// `served_state_root` is accepted only to make the "ignore the forgeable field"
// contract explicit and offline-testable. Exposed for the `selftest-genesis-row`
// self-test. Empty result → the row renders "(none)".
std::string genesis_row_state_root(const std::string& served_state_root);

// AH-1b: the provenance label for a row's balance/next_nonce. The daemon's
// state_proof/account RPCs are HEAD-ONLY, so balance/nonce are Merkle-proven
// only at the head; a non-head row carries the HEAD's value. Returns
//   "merkle@<H>"  when merkle_verified  (proven at this row's own height H), or
//   "head@<H>"    otherwise             (the head value proven at height H — NOT
//                                        proven at this row's height; a reader
//                                        must NOT read it as balance-at-this-height).
// Exposed for the offline `selftest-account-history-label` falsify gate.
std::string balance_source_label(bool merkle_verified, uint64_t proven_at_height);

} // namespace determ::light
