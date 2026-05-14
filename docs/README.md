# Determ Documentation

The protocol-level architecture and design rationale lives in the top-level [`README.md`](../README.md). This `docs/` directory holds operator + user-facing material.

## Index

- [QUICKSTART.md](QUICKSTART.md) — 5-minute walkthrough: build, run a 3-node cluster, send transactions, snapshot create + restore.
- [CLI-REFERENCE.md](CLI-REFERENCE.md) — every `determ` subcommand at a glance, grouped by purpose.
- [PROTOCOL.md](PROTOCOL.md) — formal v1 protocol specification: wire formats, hash inputs, consensus state machine, message types. What an external implementer needs to build a compatible client.
- [SECURITY.md](SECURITY.md) — canonical security posture. 24 findings mitigated in-session + 3 partial (S-030 D2 via S-033 apply-layer with v2.7 F2 spec'd for full consensus-layer closure; S-016 inbound-receipts via Option 2 time-ordered admission with v2.7 F2 closing fully via intersection commitment; S-036 `EXTENDED`-mode-specific MERGE_BEGIN witness-window with v2.11 spec'd for full closure) + 1 open Medium (S-018 JSON schema validation, mechanical) + only S-035 open Low/Op (unit tests / CI — engineering culture, not a code-attack-surface item). Zero open Critical, zero open High. Track A (localized fixes) 14/14 complete. Reconciles the rev.7 audit and the prior `OPEN-VULNERABILITIES.md` against current code. What a security reviewer should look at.

## Behavioral test suite

`tools/test_*.sh` currently holds **45+ shell-driven regression tests** spanning the protocol surface — every protocol feature, security closure, and economic primitive has at least one paired test. Representative items:

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
| `test_atomic_scope.sh` | A9 Phase 2D nested-scope rollback primitive |
| `test_composable_batch.sh` | COMPOSABLE_BATCH all-or-nothing semantics under partial-failure |
| `test_dapp_register.sh` / `test_dapp_call.sh` / `test_dapp_e2e.sh` | v2.18/v2.19 DApp substrate end-to-end |
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
for t in tools/test_*.sh; do bash "$t"; done
```

Note: multi-node tests share fixed ports (7771-3 / 8771-3 / 779x / 8830 / etc.) and have a documented Windows TIME_WAIT flake on back-to-back runs. In-process tests (state_root, atomic_scope, composable_batch, dapp_register, chain_integrity) are deterministic and complete in under 5 seconds each.

## Out of scope

Determ v1 is a payment + identity chain. **Not in scope**: smart contracts, EVM/WASM, gas, off-chain storage, oracles, bridges, ZK proofs, on-chain governance. See [`README.md` §15](../README.md) for the explicit non-goals list.
