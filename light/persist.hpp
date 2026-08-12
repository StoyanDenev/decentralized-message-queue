// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light persisted-anchor cache (the "stateful sync client" foundation).
//
// The light client otherwise re-anchors from genesis on every invocation. This
// module persists the last committee-verified anchor so a future invocation can
// resume from it instead of re-verifying 0..H from scratch.
//
// TRUST MODEL (LightClientThreatModel.md §6 — trusted local environment): the
// state file lives on the operator's own machine. A locally-tampered state file
// is OUT of scope (a local attacker who can edit state.bin can edit the binary
// itself). What the code DOES enforce, so a stale or wrong-chain cache cannot
// silently mislead:
//   (1) genesis pin — on reuse, `genesis_hash` MUST equal the locally-recomputed
//       hash of the operator-supplied --genesis; a state from a different chain
//       is rejected (the call site checks this).
//   (2) forward re-verification — any resume re-verifies committee signatures of
//       the headers ABOVE `head_height`, chaining from `head_block_hash`; a
//       daemon serving a fork below the anchor breaks prev_hash continuity and
//       is caught (see verify-chain --resume / MultiPeer... follow-up).
//   (3) schema version — a state written by an incompatible build is rejected,
//       not misread.
//   (4) head monotonicity (LSP-7) — on reuse, a daemon whose head is BELOW the
//       cached committee-verified height is rejected (a fork-free chain never
//       regresses; stale/truncated state), and a daemon EXACTLY AT the cached
//       height must present the cached anchor block itself (anchored_head's
//       gates; the cache is load-bearing evidence, not just an optimization).
//
// AT-REST FORM (D2, canonical binary — the JSON document is deleted): the
// DLS1 container, byte-exact (integers LE; decode requires the EXACT total
// length of 81 or 113 bytes; every bound refuses, never clamps):
//
//   [0..3]    "DLS1"            magic
//   [4..7]    schema_version    u32 LE (== 1)
//   [8..39]   genesis_hash      32 bytes raw
//   [40..47]  head_height       u64 LE
//   [48..79]  head_block_hash   32 bytes raw
//   [80]      has_state_root    u8 (0 | 1)
//   [81..112] head_state_root   32 bytes raw, present iff flag == 1

#pragma once
#include <cstdint>
#include <string>

namespace determ::light {

// The locally-cached, committee-verified light-client anchor. Hash fields
// stay lowercase-hex strings in memory (the call sites are hex-based); the
// AT-REST form is the raw-byte DLS1 container above.
struct LightState {
    uint32_t    schema_version = 1;   // bump on any field-set change
    std::string genesis_hash;         // 64-hex; pins the chain identity
    uint64_t    head_height = 0;
    std::string head_block_hash;      // 64-hex
    std::string head_state_root;      // 64-hex, or "" on a pre-S-033 chain
};

// Default state path: $DETERM_LIGHT_STATE if set, else
// <home>/.determ-light/state.bin (USERPROFILE on Win32, HOME on POSIX; "."
// as a last resort if neither is set).
std::string default_state_path();

// Write `s` to `path` as the canonical binary DLS1 container, creating
// parent directories. Throws std::runtime_error on IO failure or when a
// hash field is not exactly 64 hex chars (head_state_root may be "").
void save_light_state(const std::string& path, const LightState& s);

// Read + VALIDATE `path`. Throws std::runtime_error with a field-naming
// diagnostic on: missing file, wrong magic, unknown schema_version,
// truncation at any field boundary, a bad has_state_root flag, or trailing
// bytes. A clean return is a well-formed, schema-current state — never a
// partially-populated one.
LightState load_light_state(const std::string& path);

// Cheap existence check (for --show / resume gating). No validation.
bool light_state_exists(const std::string& path);

} // namespace determ::light
