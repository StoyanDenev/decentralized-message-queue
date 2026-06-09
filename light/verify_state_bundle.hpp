// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light state-proof bundle — the state-side analog of the OFFLINE
// verify-archive (which only covers HEADERS). It lets a holder prove
//   "account/key K in namespace NS had value V at height H"
// to a third party who re-verifies it with NO daemon contact, trust-minimized.
//
// WHY IT IS SOUND OFFLINE (S-042 unblocks this):
//   state_root is NOT part of the committee-signed compute_block_digest; it
//   lives in Block::signing_bytes -> block_hash = compute_hash(). The committee
//   signs the SUCCESSOR block, whose digest binds its prev_hash =
//   block_hash(anchor). So a bundle carrying the FULL anchor block + the
//   committee-signed successor header lets a verifier recompute
//   compute_hash(anchor) and require it == successor.prev_hash, transitively
//   binding the anchor's state_root. This is exactly
//   trustless_read.cpp::committee_bound_state_root, but reading from bundle
//   bytes instead of a live RPC.
//
// EXPORT (online; needs a daemon) builds the bundle and — crucially —
// re-verifies the binding via committee_bound_state_root BEFORE writing, so an
// unbindable / chain-head bundle is never produced.
//
// VERIFY (offline; NO RpcClient, no network) mirrors committee_bound_state_root
// reading from the bundle: recompute compute_hash(anchor_block), verify the
// successor header's committee sigs, require successor.prev_hash == recomputed
// anchor block_hash (THE binding), require the anchor's state_root == the
// proof's root, Merkle-verify the proof against the BOUND root, and (ns=="a")
// recompute value_hash from the cleartext.
//
// Bundle JSON schema ("determ-light-state-bundle/1"):
//   {
//     "schema":            "determ-light-state-bundle/1",
//     "genesis_hash":      "<64-hex>",       // chain-identity pin
//     "namespace":         "<ns>",           // what is proven (e.g. "a")
//     "key":               "<key>",          //   e.g. "alice"
//     "anchor_index":      <H-1>,            // block whose state_root is proven
//     "anchor_block":      { ...FULL block JSON... },  // from the `block` RPC
//     "successor_header":  { ...header JSON... },      // block anchor_index+1
//     "state_proof":       { ...state_proof RPC reply... },
//     "account_cleartext": {"balance":N,"next_nonce":N}  // OPTIONAL, ns=="a"
//   }
//
// Trust model: the --genesis file is the SOLE trust anchor at verify time (the
// committee is derived from it). Mid-chain REGISTER committee rotation is out of
// scope, mirroring trustless_read.hpp (genesis-seeded committee).

#pragma once
#include <cstdint>
#include <string>

namespace determ::light {

// ── EXPORT options (online; produces a bundle) ──────────────────────────────
struct ExportStateBundleOptions {
    uint16_t    rpc_port{0};
    std::string genesis_path;   // --genesis <file>  (chain-identity pin)
    std::string ns;             // --namespace <ns>  (a|s|r|d|b|k|c)
    std::string key;            // --key <K>
    std::string out_path;       // --out <file>
};

// Build a state-proof bundle from a live daemon and write it to opts.out_path.
//
// Flow (see verify_state_bundle.cpp for the load-bearing detail):
//   1. RpcClient; load_genesis; genesis_hash = compute_genesis_hash(genesis).
//   2. proof = state_proof(ns, key); anchor_index = proof.height - 1.
//   3. anchor_block = block(anchor_index)   (FULL body).
//   4. successor_header = headers(anchor_index+1, 1); empty -> ERROR (the
//      state is at the chain head and has no committee-signed successor yet).
//   5. VERIFY THE BINDING via committee_bound_state_root(rpc, committee,
//      anchor_index) == proof.state_root BEFORE writing — reuses the online
//      helper so the export side never duplicates the binding logic.
//   6. ns=="a": fetch account(key) cleartext and store {balance,next_nonce}.
//   7. Write the bundle; print a one-line OK with anchor_index + state_root.
//
// Returns 0 on success; non-zero on any failure (args/IO/RPC/binding). Errors
// go to stderr. This subcommand REQUIRES a daemon (it is the producer side).
int run_export_state_bundle(const ExportStateBundleOptions& opts);

// ── VERIFY options (offline; consumes a bundle) ─────────────────────────────
struct VerifyStateBundleOptions {
    std::string in_path;        // --in <bundle.json>  (required)
    std::string genesis_path;   // --genesis <file>    (required)
    bool        json_out{false};// --json
};

// Verify a state-proof bundle entirely OFFLINE (NO RpcClient, no network).
//
// Exit-code convention (matches the InclusionVerdict family):
//   * VERIFIED                                  -> 0
//   * any tamper / malformed / sig-fail /
//     binding-fail (UNVERIFIABLE)               -> 3
//   * args / IO error                           -> 1
//
// The chain-identity pin (compute_genesis_hash(--genesis) ==
// bundle.genesis_hash) is the SOLE trust anchor. compute_genesis_hash has a
// known Windows edge, so that single leg may SKIP on this box (see the test);
// the binding legs below do NOT use it and ARE testable here:
//   * recompute compute_hash(anchor_block),
//   * verify successor_header committee sigs,
//   * require successor.prev_hash == recomputed anchor block_hash (THE binding),
//   * require anchor.state_root == proof.state_root,
//   * Merkle-verify the proof against the BOUND root,
//   * (ns=="a") recompute value_hash from the cleartext and match.
int verify_state_bundle(const VerifyStateBundleOptions& opts);

} // namespace determ::light
