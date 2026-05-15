# Determ Documentation

The protocol-level architecture and design rationale lives in the top-level [`README.md`](../README.md). This `docs/` directory holds operator + user-facing material.

## Index

- [QUICKSTART.md](QUICKSTART.md) — 5-minute walkthrough: build, run a 3-node cluster, send transactions, snapshot create + restore.
- [CLI-REFERENCE.md](CLI-REFERENCE.md) — every `determ` subcommand at a glance, grouped by purpose.
- [PROTOCOL.md](PROTOCOL.md) — formal v1 protocol specification: wire formats, hash inputs, consensus state machine, message types. What an external implementer needs to build a compatible client.
- [SECURITY.md](SECURITY.md) — canonical security posture. **27 findings mitigated in-session** + 4 partial (S-030 D1 effective + D2 partial via S-033 apply-layer with v2.7 F2 spec'd for full consensus-layer D2 closure; S-016 inbound-receipts via Option 2 time-ordered admission with v2.7 F2 closing fully via intersection commitment; S-035 Path 3 path-portability shipped in-session via `tools/common.sh` — Options 1 [gtest seed] + 2 [deterministic-simulation framework] outstanding as v1.x quality work; S-036 `EXTENDED`-mode-specific MERGE_BEGIN witness-window with v2.11 spec'd for full closure). **Zero fully-open findings in any severity tier — zero open Critical, zero open High, zero open Medium, zero fully-open Low/Op.** Track A (localized fixes) 14/14 complete. S-037 + S-038 (paired closures this session): S-037 was the `dapp_registry` snapshot-restore gap; testing it surfaced S-038 — the S-033 state_root verification gate was dormant on production blocks because `Node::try_finalize_round` never populated `body.state_root`. Both shipped; `tools/test_dapp_snapshot.sh` (12/12 PASS) now strictly verifies end-to-end state_root match through restore. **S-018 (final-open Medium) closed in-session**: `json_require<T>` / `json_require_hex` / `json_require_array` helpers (`include/determ/util/json_validate.hpp`) applied to every attack-relevant wire-format consumer (gossip envelope, Transaction/Block/AbortEvent/EquivocationEvent/GenesisAlloc, ContribMsg/AbortClaimMsg/BlockSigMsg, GenesisConfig, node_key.json); new regression `tools/test_s018_json_validation.sh` (10/10 PASS) exercises field-name diagnostics for missing-field / wrong-type / wrong-hex-length / non-array errors. **S-035 Path 3 (final-fully-open Low/Op) shipped in-session**: `tools/common.sh` helper + sed-conversion of all then-49 tests (now 53; new tests added in-session use the helper from the start) to portable `$DETERM` / `$PROJECT_ROOT` references; Linux/Mac/Windows runnable from the repo root. Reconciles the rev.7 audit (preserved out-of-tree) and the prior in-tree `OPEN-VULNERABILITIES.md` (superseded and removed) against current code. What a security reviewer should look at.

## Behavioral test suite

`tools/test_*.sh` currently holds **56 shell-driven regression tests** spanning the protocol surface — every protocol feature, security closure, and economic primitive has at least one paired test. Representative items:

| Test | Asserts |
|---|---|
| `test_bearer.sh` | Bearer-wallet TRANSFER round-trip across 3 nodes |
| `test_bft_escalation.sh` | K-of-K → BFT fallback when committee gets stuck |
| `test_sharded_smoke.sh` | Beacon + shard genesis hashes distinct; both chains advance independently |
| `test_domain_registry.sh` | DOMAIN_INCLUSION mode (no-stake validators agree on head) |
| `test_zero_trust_cross_chain.sh` | Cross-chain gossip plumbing (`BEACON_HEADER` ↔ `SHARD_TIP`) |
| `test_cross_shard_transfer.sh` | TRANSFER from shard 0 → shard 1 credits destination end-to-end |
| `test_equivocation_slashing.sh` | `submit_equivocation` RPC → bake evidence into block → stake forfeited |
| `test_snapshot_bootstrap.sh` | Receiver fast-bootstraps from donor's snapshot with no genesis required |
| `test_state_root.sh` | S-033 Merkle-root state commitment changes when state changes |
| `test_state_proof.sh` | v2.2 state_proof inclusion-proof RPC + leaf-hash validation |
| `test_verify_state_proof.sh` | v2.2 light-client demonstrator — fetches state-proof, verifies locally via `crypto::merkle_verify`; asserts tampered value_hash / sibling-hash / mismatched --state-root all FAIL while valid proofs PASS |
| `test_headers_rpc.sh` | v2.2 light-client header-sync — `headers` RPC + `determ headers` CLI + `determ verify-headers` chain-integrity CLI; asserts response shape, light-client field set present, heavy fields stripped, pagination, out-of-range handling, server-side count cap (256), `block_hash` field + prev_hash chain links, verify-headers OK on valid chains and FAIL on tampered prev_hash / wrong --prev-hash anchor |
| `test_verify_block_sigs.sh` | v2.2 light-client committee-signature verifier — `determ verify-block-sigs`; asserts K-of-K committee Ed25519 signatures verify against `compute_block_digest`, tampered signature / wrong committee pubkey / missing committee member all FAIL, accepts `determ headers` envelope shape |
| `test_json_cli.sh` | `--json` flag on info CLIs (validators / committee / peers / chain-summary); asserts each returns the expected JSON shape, validators --json entries are verify-block-sigs-compatible, default output is NOT JSON (--json required for machine consumption), and validators --json pipes directly into verify-block-sigs --committee for end-to-end light-client verification |
| `test_merkle.sh` | v2.1 Merkle primitives unit test (S-035 Option 1 seed) — in-process `crypto::merkle_root` + `merkle_proof` + `merkle_verify` + `merkle_leaf_hash` + `merkle_inner_hash`; 12 assertions covering empty-set, single-leaf, balanced + unbalanced trees, tampering detection (value_hash / sibling-hash / target_index), domain separation (leaf vs inner), determinism, and sort-invariance |
| `test_committee_selection.sh` | v2.1 committee-selection primitives unit test (S-035 Option 1 seed) — in-process `crypto::select_m_creators` (S-020 hybrid: both rejection-sampling and partial-Fisher-Yates branches), `select_after_abort_m`, and `epoch_committee_seed`; 13 assertions covering determinism, seed-sensitivity, branch coverage at both sides of the 2K vs N threshold, edge cases (K=N, K=1), distinct-without-replacement, in-range invariant. Foundation tests for FA1 / FA2 / FA5 / FA8 — every committee at every round is derived through these functions |
| `test_shard_routing.sh` | v2.1 cross-shard routing primitive unit test (S-035 Option 1 seed) — in-process `crypto::shard_id_for_address`; 7 assertions covering single-shard degenerate case, determinism, in-range invariant, salt-sensitivity, distribution uniformity (1000 addresses across 4 shards >5% per shard), case-sensitivity, empty-address handling. Foundation test for FA7 cross-shard receipt atomicity — every cross-shard tx's destination is derived through this function |
| `test_atomic_scope.sh` | A9 Phase 2D nested-scope rollback primitive |
| `test_composable_batch.sh` | COMPOSABLE_BATCH all-or-nothing semantics under partial-failure |
| `test_dapp_register.sh` / `test_dapp_call.sh` / `test_dapp_e2e.sh` | v2.18/v2.19 DApp substrate end-to-end |
| `test_dapp_snapshot.sh` | S-037 + S-038 joint surface: DApp registry survives snapshot bootstrap; producer's `body.state_root` matches receiver's recomputed root post-restore |
| `test_s018_json_validation.sh` | S-018 closure: `json_require<T>` / `json_require_hex` helpers + converted `from_json` paths across `chain/block.cpp` + `node/producer.cpp` + `chain/genesis.cpp` + `net/messages.cpp` + `crypto/keys.cpp` surface clear field-name diagnostics on malformed gossip / RPC / snapshot / keyfile input. 9 assertions cover missing-field, wrong-type, wrong-hex-length cases. |
| `test_account_encrypted.sh` | v2.17 AES-256-GCM keyfile envelope |
| `test_rpc_hmac_auth.sh` | v2.16 / S-001 HMAC-SHA-256 RPC auth |
| `test_mempool_bounds.sh` | S-008 mempool admission + fee-priority eviction |
| `test_rpc_rate_limit.sh` / `test_gossip_rate_limit.sh` | S-014 token-bucket rate-limit (RPC + gossip) |
| `test_chain_integrity.sh` | S-021 chain.json head_hash tampering detection |
| `test_anon_address_case.sh` | S-028 case-insensitive anon-address normalization |
| `test_governance_param_change.sh` | A5 PARAM_CHANGE multisig + whitelist end-to-end |
| `test_under_quorum_merge.sh` | R7 merge_state_ + MERGE_BEGIN/MERGE_END application |

Run the full suite with:

```bash
bash tools/run_all.sh                          # all tests + PASS/FAIL summary
FAST=1 bash tools/run_all.sh                   # in-process subset only (~3s, 5 tests, no flakes)
QUIET=1 bash tools/run_all.sh                  # summary only (no per-test stdout)
ONLY_PATTERN='test_dapp' bash tools/run_all.sh # subset by regex
SKIP_PATTERN='test_equiv' bash tools/run_all.sh # skip known-flaky on a platform
```

`tools/run_all.sh` iterates every `tools/test_*.sh`, captures per-test outcome via the suite's PASS/FAIL marker convention, and exits non-zero if anything failed. Per-test failures don't stop the suite — an operator gets the full failure picture in one run. **`FAST=1`** short-circuits to the deterministic in-process subset (`determ test-*` subcommand wrappers): atomic_scope, composable_batch, dapp_register, dapp_call, s018_json_validation, merkle, committee_selection, shard_routing. ~3 seconds total, no clusters, no network, no flakes — useful for dev iteration. The portable `DETERM_BIN` / `DETERM_WALLET_BIN` override hooks (see `tools/common.sh`) flow through automatically. Plain bash loop also still works:

```bash
for t in tools/test_*.sh; do bash "$t"; done
```

Note: multi-node tests share fixed ports (7771-3 / 8771-3 / 779x / 8830 / etc.) and have a documented Windows TIME_WAIT flake on back-to-back runs. In-process tests (state_root, atomic_scope, composable_batch, dapp_register, chain_integrity, s018_json_validation) are deterministic and complete in under 5 seconds each.

**Portability (S-035 Path 3 — shipped).** Every test sources `tools/common.sh` which platform-detects the determ + determ-wallet binaries (Windows MSVC multi-config, Linux/Mac single-config) and resolves `PROJECT_ROOT` to a Windows-style absolute path on Git Bash via `pwd -W`. Override via `DETERM_BIN=/path/to/determ` env var for CI runners with custom build layouts. The 53-test suite is now runnable on Linux/Mac/Windows from the repo root with no per-platform editing.

## Out of scope

Determ v1 is a payment + identity chain. **Not in scope**: smart contracts, EVM/WASM, gas, off-chain storage, oracles, bridges, ZK proofs, on-chain governance. See [`README.md` §15](../README.md) for the explicit non-goals list.
