// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light `export-headers` subcommand — verifiable header archive
// for off-chain audit / long-term storage.
//
// Use case: an auditor wants to capture an immutable record of the
// chain state across a specific epoch (e.g. one fiscal quarter). Fetch
// headers H1..H2 from a daemon, verify committee sigs + prev_hash
// continuity, then write the verified archive to a JSON file. The
// archive can be re-verified offline at any later date (re-run
// `verify-headers` + `verify-block-sigs` on the archive) without
// re-contacting the daemon.
//
// Composition: this is FETCH → VERIFY → EXPORT. Reuses
// rpc_client::call("headers", ...) for fetch, verify_headers /
// verify_block_sigs for verification, and writes a structured JSON
// envelope to disk. The archive shape is forward-compatible with
// `determ-light verify-headers --in <archive>` so a third-party
// auditor can re-run the verification without any other input.
//
// Trust model: every header committed to the archive is verified
// AT EXPORT TIME against the genesis-seeded committee. The
// `verified_committee_sigs` flag in each record reflects this. With
// `--include-committee-sigs`, the full `creator_block_sigs` array is
// preserved in each header_json for later re-verification; otherwise
// only the digest is kept (smaller archive — re-verification still
// works for the prev_hash chain but committee-sig recomputation
// requires the sigs to be present).

#pragma once
#include <cstdint>
#include <string>

namespace determ::light {

// Options parsed from CLI flags. See main.cpp::cmd_export_headers.
struct ExportOptions {
    uint16_t    rpc_port{0};
    std::string genesis_path;
    uint64_t    from{0};
    uint64_t    count{0};
    std::string out_path;
    // When true, preserve full creator_block_sigs in each header_json.
    // When false (default), strip them after verification — only
    // creator_block_sigs is dropped; everything else needed for
    // prev_hash-chain re-verification stays.
    bool        include_committee_sigs{false};
};

// Run the export-headers flow. Returns 0 on success, non-zero on any
// failure (genesis-anchor mismatch, fetch failure, wrong-range request,
// verification failure, write failure). Diagnostics go to stderr.
//
// On success: writes a JSON archive to opts.out_path with the shape:
//   {
//     "exported_at_height": <head-height-at-export-time>,
//     "from":               <H1>,
//     "count":              <M>,
//     "genesis_hash":       "<64-hex>",
//     "headers": [
//       {
//         "index":                   H1,
//         "header_json":             { ...header... },
//         "verified_committee_sigs": true | false
//       },
//       ...
//     ]
//   }
int run_export_headers(const ExportOptions& opts);

} // namespace determ::light
