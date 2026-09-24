// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light `verify-archive` subcommand — OFFLINE re-verification of
// a header archive produced by `determ-light export-headers`.
//
// Use case: an auditor captured a verifiable header archive months ago
// (via export-headers). Now they re-verify it offline against a pinned
// genesis, with ZERO trust in any live daemon — pure local cryptographic
// re-check. This closes the audit loop: export-headers verified at
// CAPTURE time against a daemon; verify-archive re-verifies at AUDIT time
// against nothing but the genesis file and the archive bytes.
//
// Composition: this is LOAD → ANCHOR → CHAIN-CHECK → SIG-CHECK. It opens
// NO RpcClient and touches NO network. It reuses:
//   * load_genesis + compute_genesis_hash (trustless_read.cpp / genesis)
//     for the chain-identity anchor,
//   * build_genesis_committee (trustless_read.cpp) for the committee seed,
//   * verify_headers (verify.cpp) for the prev_hash chain, and
//   * verify_block_sigs (verify.cpp) for the committee Ed25519 sigs.
// Nothing here re-implements a primitive already living in verify.cpp.
//
// Trust model: the genesis file is the sole trust anchor. Step 1 asserts
// compute_genesis_hash(genesis) == archive.genesis_hash — if the archive
// claims a different chain, verification refuses. From there the prev_hash
// chain + committee sigs are re-checked from the archive bytes alone.
//
// Archive schema (produced by export.cpp::run_export_headers):
//   {
//     "exported_at_height": <H>,
//     "from":               <F>,
//     "count":              <M>,
//     "genesis_hash":       "<64-hex>",
//     "headers": [
//       { "index": <I>,
//         "header_json": { ...header... },        // minus creator_block_sigs
//         "verified_committee_sigs": <bool> },    //   unless --include-committee-sigs
//       ...
//     ]
//   }

#pragma once
#include <cstdint>
#include <string>

namespace determ::light {

// Options parsed from CLI flags. See main.cpp::cmd_verify_archive.
struct VerifyArchiveOptions {
    std::string in_path;       // --in <archive.json>   (required)
    std::string genesis_path;  // --genesis <file>      (required)
    // When true, committee-sig re-verification is mandatory: an archive
    // exported WITHOUT --include-committee-sigs (i.e. creator_block_sigs
    // stripped from its non-genesis headers) fails with a clear
    // "archive has no committee sigs" diagnostic. When false, sigs are
    // re-verified opportunistically — if the archive retained them, they
    // are checked; if not, that check is skipped (the genesis anchor +
    // prev_hash chain still run).
    bool        require_sigs{false};
};

// Run the verify-archive flow. Returns 0 on success, non-zero on any
// failure (file/parse error, schema mismatch, genesis-hash mismatch,
// prev_hash chain break, committee-sig failure, or --require-sigs on a
// sigs-stripped archive). Diagnostics go to stderr; on the bad-header
// paths the diagnostic names the offending archive index.
//
// On success prints (to stdout) a summary line:
//   OK: N headers verified (genesis anchored, prev_hash chain intact,
//       K committee-sig sets valid)
int run_verify_archive(const VerifyArchiveOptions& opts);

} // namespace determ::light
