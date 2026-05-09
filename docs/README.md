# DHCoin Documentation

The protocol-level architecture and design rationale lives in the top-level [`README.md`](../README.md). This `docs/` directory holds operator + user-facing material.

## Index

- [QUICKSTART.md](QUICKSTART.md) — 5-minute walkthrough: build, run a 3-node cluster, send transactions, snapshot create + restore.
- [CLI-REFERENCE.md](CLI-REFERENCE.md) — every `dhcoin` subcommand at a glance, grouped by purpose.
- [PROTOCOL.md](PROTOCOL.md) — formal v1 protocol specification: wire formats, hash inputs, consensus state machine, message types. What an external implementer needs to build a compatible client.
- [SECURITY.md](SECURITY.md) — canonical security posture. 29 open findings (4 Critical / 8 High / 8 Medium / 9 Low) with severity, code evidence, ranked resolution options, and effort estimates. Reconciles the rev.7 audit and the prior `OPEN-VULNERABILITIES.md` against current code. What a security reviewer should look at.

## Behavioral test suite

Each protocol feature has a paired regression test in `tools/`:

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

Run all 8 with:

```bash
for t in tools/test_*.sh; do bash "$t"; done
```

## Out of scope

DHCoin v1 is a payment + identity chain. **Not in scope**: smart contracts, EVM/WASM, gas, off-chain storage, oracles, bridges, ZK proofs, on-chain governance. See [`README.md` §15](../README.md) for the explicit non-goals list.
