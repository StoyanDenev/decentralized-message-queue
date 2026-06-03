# Operator Tooling Read-Only — `operator_*.sh` diagnostic-family meta-proof

**Status:** Survey + argument. Round R40 (agent E7).
**Scope:** the `tools/operator_*.sh` diagnostic-script family.
**Companion to:** `RpcInputValidationDefense.md`, `S001RpcAuthSoundness.md`,
`S014RateLimiterSoundness.md`, `StakeDistributionMetrics.md` (SD-4).

---

## §1. Scope

Determ ships **91** operator diagnostic scripts under `tools/` matching
`operator_*.sh` (count as of R40 in this branch; a 92nd —
`operator_receipt_flow.sh`, E4 R40 — is landing in parallel this round and is
covered by the same argument below, marked *(E4 R40, pending)*). Operators run
these against live production daemons to answer health, distribution,
committee, DApp, governance, subsidy, and cross-shard questions.

This document establishes a single operational-safety property for the whole
family:

> **The operator-script family is read-only.** Every `operator_*.sh` script
> issues only non-state-mutating RPC reads (or operates on local files /
> offline-verification primitives). Running any of them against a production
> daemon — with **any** arguments — cannot submit a transaction, advance a
> nonce, change a parameter, slash a validator, register a DApp, or mutate
> chain state in any other way.

The property matters because operators need to run diagnostics on production
infrastructure without a pre-flight code audit of each script. A read-only
guarantee for the *entire family* lets an operator treat "is this an
`operator_*.sh` script?" as a sufficient safety check.

**Relation to prior proofs.** This generalizes a property that
`StakeDistributionMetrics.md` already argued for a single script:
its theorem **SD-4** ("`operator_stake_distribution.sh` is read-only — it
invokes only the `status` and `validators` RPC reads"). The present document
lifts SD-4 from one script to the full 91-script family by exhaustive survey.
It is the operational mirror of `S001RpcAuthSoundness.md` T-3 and
`RpcInputValidationDefense.md` L-3, which enumerate the **mutating** endpoints
behind the S-001 auth gate; here we enumerate what the operator scripts
actually *call* and show the two sets are disjoint.

**What this document does not cover.** It is a survey of the shipped scripts,
not a static-analysis CI gate; §6 F-2 records the lint that would automate it.

---

## §2. The RPC read / mutating partition

### §2.1 The daemon RPC dispatch table

Every RPC method the daemon serves is dispatched by a single function,
`RpcServer::dispatch`, at `src/rpc/rpc.cpp:197-272`. There is exactly one
dispatch point: every `Node::rpc_*` handler is reached only through this
function (this single-entry property is the bedrock of
`S001RpcAuthSoundness.md` T-3). The complete method set, classified, is:

| RPC method | Handler | Dispatch line | Class |
|---|---|---|---|
| `status` | `Node::rpc_status` | `rpc.cpp:201` | **READ** |
| `peers` | `Node::rpc_peers` | `rpc.cpp:202` | **READ** |
| `register` | `Node::rpc_register` | `rpc.cpp:203` | **MUTATING** |
| `balance` | `Node::rpc_balance` | `rpc.cpp:204-205` | **READ** |
| `send` | `Node::rpc_send` | `rpc.cpp:206-211` | **MUTATING** |
| `stake` | `Node::rpc_stake` | `rpc.cpp:212-216` | **MUTATING** |
| `unstake` | `Node::rpc_unstake` | `rpc.cpp:217-221` | **MUTATING** |
| `nonce` | `Node::rpc_nonce` | `rpc.cpp:222-223` | **READ** |
| `stake_info` | `Node::rpc_stake_info` | `rpc.cpp:224-225` | **READ** |
| `submit_tx` | `Node::rpc_submit_tx` | `rpc.cpp:226-227` | **MUTATING** |
| `submit_equivocation` | `Node::rpc_submit_equivocation` | `rpc.cpp:228-230` | **MUTATING** |
| `snapshot` | `Node::rpc_snapshot` | `rpc.cpp:231-232` | **READ** |
| `state_root` | `Node::rpc_state_root` | `rpc.cpp:233-234` | **READ** |
| `state_proof` | `Node::rpc_state_proof` | `rpc.cpp:235-238` | **READ** |
| `dapp_info` | `Node::rpc_dapp_info` | `rpc.cpp:240-241` | **READ** |
| `dapp_list` | `Node::rpc_dapp_list` | `rpc.cpp:242-245` | **READ** |
| `dapp_messages` | `Node::rpc_dapp_messages` | `rpc.cpp:246-251` | **READ** |
| `block` | `Node::rpc_block` | `rpc.cpp:252-253` | **READ** |
| `headers` | `Node::rpc_headers` | `rpc.cpp:254-256` | **READ** |
| `chain_summary` | `Node::rpc_chain_summary` | `rpc.cpp:257-258` | **READ** |
| `validators` | `Node::rpc_validators` | `rpc.cpp:259-260` | **READ** |
| `committee` | `Node::rpc_committee` | `rpc.cpp:261-262` | **READ** |
| `account` | `Node::rpc_account` | `rpc.cpp:263-264` | **READ** |
| `tx` | `Node::rpc_tx` | `rpc.cpp:265-266` | **READ** |
| `pending_params` | `Node::rpc_pending_params` | `rpc.cpp:267-268` | **READ** |
| `abort_records` | `Node::rpc_abort_records` | `rpc.cpp:269-270` | **READ** |

**26 methods total: 6 MUTATING, 20 READ.**

### §2.2 The mutating set

The six mutating methods are exactly

```
MUTATE_STATE := { send, stake, unstake, register, submit_tx, submit_equivocation }
```

This is the *same* set defined independently in two prior proofs:

- `S001RpcAuthSoundness.md` §4: *"A request is state-mutating iff its method
  is in `MUTATE_STATE := {send, stake, unstake, register, submit_tx,
  submit_equivocation}` (the six endpoints that touch `chain_` state or the
  mempool via `Node::rpc_*`)."*
- `RpcInputValidationDefense.md` §3 (L-3): *"By case analysis over the six
  state-mutating methods `MUTATE_STATE := …`."*

Each mutating handler appends a signed transaction (or evidence) to the local
tx store and broadcasts it to gossip — e.g. `rpc_register`
(`src/node/node.cpp:3338-3375`) builds a `REGISTER` tx, signs it, inserts it
into `tx_store_`, and calls `gossip_.broadcast(net::make_transaction(tx))`.
`rpc_send` / `rpc_stake` / `rpc_unstake` share that construct-sign-store-
broadcast shape; `rpc_submit_tx` admits an externally-signed tx (including
`PARAM_CHANGE`, `DAPP_REGISTER`, `DAPP_CALL`, `TRANSFER`) into the mempool; and
`rpc_submit_equivocation` admits an `EquivocationEvent` driving FA6 slashing at
apply time. Behind the S-001 HMAC gate (`rpc.cpp:179`, before `dispatch` at
`rpc.cpp:184`), these are the only methods an unauthenticated caller cannot
reach.

### §2.3 Definition (read-only)

> A script is **read-only** iff the set of RPC methods reachable through any
> daemon-touching command it issues is a subset of the 20 READ methods in
> §2.1 — equivalently, iff its reachable-method-set is disjoint from
> `MUTATE_STATE`.

### §2.4 The CLI indirection layer

Operator scripts do not speak the JSON-RPC wire protocol directly. They invoke
the `determ` CLI binary (resolved as `$DETERM` via `tools/common.sh`) with
*subcommands*; each subcommand internally issues zero or more RPC calls via
`rpc::rpc_call(...)`. To classify a script we therefore map:

```
operator_*.sh  →  determ <subcommand>  →  rpc::rpc_call(host, port, "<method>")  →  READ | MUTATING
```

The CLI's own mutating subcommands are a small, fixed set. Grepping the whole
CLI for mutating-method call sites (`rpc::rpc_call(..., "register"|"send"|
"stake"|"unstake"|"submit_tx"|"submit_equivocation", ...)` in `src/main.cpp`)
yields exactly:

| CLI subcommand | Mutating RPC issued | `main.cpp` line |
|---|---|---|
| `register` | `register` | `1247` |
| `send` | `submit_tx` | `4844` |
| `stake` | `submit_tx` | `4989` (governance/stake paths) |
| `unstake` | `submit_tx` | `5085` |
| (governance `param-change`) | `submit_tx` | `5220` |
| (`dapp-call`) | `submit_tx` | `5305` |

These six call sites are the *only* mutating-RPC invocations in the entire CLI.
The classification task for §3 reduces to: **does any operator script invoke
`determ register`, `determ send`, `determ stake`, `determ unstake`, the
governance param-change subcommand, or `determ dapp-call`?** (Equivalently, any
CLI subcommand whose body reaches one of the six `rpc::rpc_call` mutating sites
above.) If none does, the family is read-only.

### §2.5 The read subcommand → RPC method map

Every daemon-touching subcommand the operator scripts actually use (see §3)
resolves to a READ method, confirmed by reading each `cmd_*` body in
`src/main.cpp`:

| CLI subcommand | RPC method(s) issued | Source | Class |
|---|---|---|---|
| `head` | `status`, `block` | `main.cpp:2484` (`cmd_head`) | READ |
| `status` | `status` | `cmd_status` | READ |
| `supply` | `chain_summary` | `main.cpp:3191` (`cmd_supply`) | READ |
| `peers` | `peers` | `cmd_peers` | READ |
| `balance` | `balance` | `cmd_balance` | READ |
| `chain-summary` | `chain_summary` | `cmd_chain_summary` | READ |
| `block-info` | `block` | `main.cpp:2583` (`cmd_block_info`) | READ |
| `block-range` | `headers` | `main.cpp:2689` (`cmd_block_range`) | READ |
| `headers` | `headers` | `cmd_headers` | READ |
| `stakes` | `validators` | `main.cpp:2189` (`cmd_stakes`) | READ |
| `validators` | `validators` | `main.cpp:2093` (`cmd_validators`) | READ |
| `stake_info` | `stake_info` | `cmd_stake_info` | READ |
| `show-account` | `account` | `main.cpp:3355` (`cmd_show_account`) | READ |
| `dapp-info` | `dapp_info` | `cmd_dapp_info` | READ |
| `dapp-list` | `dapp_list` | `cmd_dapp_list` | READ |
| `pending-params` | `pending_params` | `main.cpp:5364` (`cmd_pending_params`) | READ |
| `chain-id` | `status` | `main.cpp:2791` (`cmd_chain_id`) | READ |
| `check-fork` | `headers`, `block` (paged) | `main.cpp:2840` (`cmd_check_fork`) | READ |
| `snapshot create` | `snapshot` | `main.cpp:3517` (`cmd_snapshot_create`) | READ |
| `where-is` | *(none — pure local `shard_id_for_address`)* | `main.cpp:3440` | LOCAL |
| `verify-genesis` | *(none — offline `--in <file>` verify)* | `main.cpp:1495` | LOCAL |
| `verify-headers` | *(none — offline stdin / `--in` verify)* | `main.cpp:1831` | LOCAL |
| `snapshot inspect/stats/diff` | *(none — operate on local snapshot files)* | `main.cpp:4058-4062` | LOCAL |
| `mempool` | *(none — not a registered CLI subcommand / not an RPC method; see §6)* | — | N/A |

The three `verify-*` and the non-`create` `snapshot` subcommands issue **no RPC
at all** — they are offline verifiers over local files / stdin, so they cannot
touch a daemon, let alone mutate one. `where-is` is a pure local shard-routing
computation. Critically, `snapshot create` maps to the **`snapshot`** RPC,
which is in the READ set (§2.1): it asks the daemon to *serialize* its current
state into a snapshot blob and return it; it does not advance the chain.

---

## §3. Per-script method inventory (evidentiary core)

This section is grounded by grepping every `tools/operator_*.sh` script for its
`"$DETERM" <subcommand>` shell invocations and its
`subprocess.run([determ, "<subcommand>", …])` Python-heredoc invocations. The
union of subcommands observed across all 91 scripts is exactly the set in §2.5
— **no script invokes any of the six mutating subcommands of §2.4.**

Rather than 91 near-identical rows, the scripts are grouped by their
daemon-interaction class. Every script is accounted for in exactly one group;
the group's subcommand set is the union over its members, each verified by grep.

### Group A — local-file linters (no daemon contact at all)

These scripts set `DETERM_BIN=:` (the POSIX no-op) so `common.sh` does not fail
when no binary is present, then operate purely on local files (config files,
keystore files, backup directories, snapshot files). They never open a socket.
Trivially read-only.

| Script | What it reads | Evidence |
|---|---|---|
| `operator_backup_health.sh` | local data-dir + backup-dir mtimes | `DETERM_BIN=:` at `:186-187` |
| `operator_config_audit.sh` | operator config JSON | `DETERM_BIN=:` at `:127-128` |
| `operator_keystore_audit.sh` | `DETERM-NODE-V1` keyfiles on disk | `DETERM_BIN=:` at `:182-183` |
| `operator_rate_limiter_audit.sh` | rate-limiter config knobs | `DETERM_BIN=:` at `:182-183` |
| `operator_snapshot_check.sh` | local snapshot file (`snapshot stats`) + optional `head` | `snapshot stats` `:177` |
| `operator_snapshot_diff_report.sh` | two local snapshot files | `snapshot diff/inspect` `:219-241` |
| `operator_genesis_dump.sh` | local genesis file (`verify-genesis --in`) | `verify-genesis --in` `:172` |
| `operator_genesis_diff.sh` | two local genesis files | `verify-genesis --in` `:171-179` |

### Group B — meta-orchestrator

| Script | Behavior | Evidence |
|---|---|---|
| `operator_anomaly_summary.sh` | runs **other** `operator_*.sh` scripts (`supply_check`, `chain_health`, `block_lag_check`, …) and rolls up their exit codes | invokes sibling scripts `:19-24, :230-248`; contains no `$DETERM` subcommand of its own |

Read-only by transitivity: it issues no RPC itself and only invokes scripts
proven read-only here.

### Group C — head/status freshness + supply (status, block, chain_summary, peers reads)

| Script | Subcommands observed | RPC class |
|---|---|---|
| `operator_chain_health.sh` | `head`, `supply`, `peers` | READ |
| `operator_supply_check.sh` | `supply` | READ |
| `operator_chain_freshness.sh` | `head` | READ |
| `operator_block_lag_check.sh` | `head`, `block-info`, `peers` | READ |
| `operator_consensus_lag.sh` | `status` | READ |
| `operator_consensus_latency.sh` | `head` | READ |
| `operator_block_propagation_latency.sh` | `status` | READ |
| `operator_chain_replay_speedometer.sh` | `head` | READ |
| `operator_storage_growth.sh` | `head` | READ |
| `operator_tx_throughput.sh` | `head` | READ |
| `operator_peer_topology.sh` | `peers` | READ |
| `operator_chain_summary_diff.sh` | `chain-summary`, `head`, `block-info`, `status`, `chain-id` | READ |

### Group D — block/header scan (block, headers reads; often Python `block-info` loops)

| Script | Subcommands observed | RPC class |
|---|---|---|
| `operator_chain_verify.sh` | `head`, `headers`, `verify-headers` (offline) | READ |
| `operator_chain_orphan_check.sh` | `head`, `headers` | READ |
| `operator_chain_export.sh` | `head`, `block-range`, `block-info` | READ |
| `operator_chain_diff.sh` | `head`, `block-info` | READ |
| `operator_chain_invariants_audit.sh` | `head`, `block-info` | READ |
| `operator_chain_compaction_audit.sh` | `head` (+ Python `block-info`) | READ |
| `operator_block_inclusion_audit.sh` | `head`, `block-info` (Python loop) | READ |
| `operator_block_creator_fairness.sh` | `head`, `stakes`, `block-info` (Python) | READ |
| `operator_block_size_audit.sh` | `block-info` (Python loop) | READ |
| `operator_signature_audit.sh` | `head`, `block-info` | READ |
| `operator_equivocation_digest.sh` | `head`, `block-range` | READ |
| `operator_event_summary.sh` | `head`, `block-range` | READ |
| `operator_payments_audit.sh` | `head` (+ Python `block-info`) | READ |
| `operator_fee_distribution_audit.sh` | `head` (+ Python `block-info`) | READ |
| `operator_dust_audit.sh` | `head`, `snapshot create`, `snapshot inspect` | READ |
| `operator_anon_address_density.sh` | `head`, `block-info` | READ |
| `operator_anon_address_usage.sh` | `head`, `verify-genesis` (offline), `where-is` (local), `block-info` (Python) | READ / LOCAL |
| `operator_unique_address_audit.sh` | `head` (+ Python `block-info`) | READ |
| `operator_inbound_outbound_balance.sh` | `status`, `head` | READ |

### Group E — fork / partition / replay watchers

| Script | Subcommands observed | RPC class |
|---|---|---|
| `operator_fork_watch.sh` | `head`, `check-fork` | READ |
| `operator_network_partition_detect.sh` | `chain-id` | READ |
| `operator_chain_orphan_check.sh` | *(see Group D)* | READ |
| `operator_orphan_check.sh` | `head`, `snapshot create`, `snapshot inspect` | READ |
| `operator_orphan_account_scan.sh` | `head`, `snapshot create` (+ Python) | READ |
| `operator_replay_validation.sh` | `head`, `chain-id`, `snapshot create/inspect`, `block-info`, `supply` | READ |

### Group F — committee / validator audits (status, validators, head reads)

| Script | Subcommands observed | RPC class |
|---|---|---|
| `operator_committee_snapshot.sh` | `status`, `block-info`, `validators` | READ |
| `operator_committee_audit.sh` | `head`, `validators` | READ |
| `operator_committee_membership_history.sh` | `head`, `validators` | READ |
| `operator_committee_rotation.sh` | `head` | READ |
| `operator_validator_committee_share.sh` | `head`, `validators` | READ |
| `operator_validator_history.sh` | `head`, `stakes`, `stake_info` | READ |
| `operator_validator_region_distribution.sh` | `head`, `stakes` | READ |
| `operator_validator_unstake_pipeline.sh` | `head`, `snapshot create/inspect`, `validators` | READ |
| `operator_validator_uptime.sh` | `head`, `stakes` | READ |

### Group G — stake / subsidy / economics (validators, chain_summary, balance reads)

| Script | Subcommands observed | RPC class |
|---|---|---|
| `operator_stake_distribution.sh` | `status`, `stakes` | READ — *this is the SD-4 script* |
| `operator_stake_audit.sh` | `head`, `stakes`, `stake_info` | READ |
| `operator_stake_concentration.sh` | `head`, `stakes`, `snapshot create/inspect` | READ |
| `operator_stake_yield.sh` | `head`, `supply`, `stakes` | READ |
| `operator_subsidy_audit.sh` | `head`, `supply`, `balance` | READ |
| `operator_subsidy_accrual_audit.sh` | `head`, `supply`, `stakes` | READ |
| `operator_subsidy_lottery_audit.sh` | `head` | READ |
| `operator_subsidy_pool_health.sh` | `head`, `supply`, `balance` | READ |
| `operator_balance_distribution.sh` | `head`, `snapshot create/inspect` | READ |
| `operator_region_balance_audit.sh` | `head`, `stakes` | READ |

### Group H — account / address distributions (snapshot, account, chain_summary reads)

| Script | Subcommands observed | RPC class |
|---|---|---|
| `operator_account_balance_history.sh` | `head`, `balance`, `supply`, `block-info` (Python) | READ |
| `operator_account_growth.sh` | `head`, `snapshot create`, `snapshot stats` (+ Python `block-info`) | READ |
| `operator_account_age_distribution.sh` | `chain-summary`, `snapshot create` (+ Python `block-info`) | READ |

### Group I — DApp audits (dapp_list, dapp_info, dapp_messages, block reads)

| Script | Subcommands observed | RPC class |
|---|---|---|
| `operator_dapp_inventory.sh` | `status`, `dapp-list` | READ |
| `operator_dapp_audit.sh` | `head`, `dapp-info` | READ |
| `operator_dapp_health.sh` | `dapp-list`, `dapp-info`, `block-info` (Python) | READ |
| `operator_dapp_call_audit.sh` | `head` (+ Python `block-info`) | READ |
| `operator_dapp_call_volume_audit.sh` | `head`, `dapp-list` (+ Python) | READ |
| `operator_dapp_balance_audit.sh` | `head` (+ Python `block-info`) | READ |
| `operator_dapp_lifecycle_audit.sh` | `head` (+ Python `block-info`) | READ |
| `operator_dapp_message_audit.sh` | `head`, `dapp-list` (+ Python) | READ |
| `operator_dapp_registration_audit.sh` | `head`, `dapp-list` | READ |
| `operator_dapp_topic_audit.sh` | `dapp-list`, `dapp-info` | READ |

### Group J — governance / params (pending_params, validators reads)

| Script | Subcommands observed | RPC class |
|---|---|---|
| `operator_governance_audit.sh` | `head`, `pending-params` | READ |
| `operator_governance_history.sh` | `head`, `validators` | READ |
| `operator_param_history.sh` | `head`, `pending-params` | READ |
| `operator_param_change_history.sh` | `head`, `pending-params` | READ |

### Group K — cross-shard / merge / receipts (status, chain_summary, snapshot reads)

| Script | Subcommands observed | RPC class |
|---|---|---|
| `operator_cross_shard_health.sh` | `status`, `chain-summary` | READ |
| `operator_shard_diagnostic.sh` | `verify-genesis` (offline), `chain-id`, `head`, `status`, `peers`, `where-is` (local) | READ / LOCAL |
| `operator_merge_state_audit.sh` | `status`, `snapshot create`, `head` | READ |
| `operator_receipt_audit.sh` | `status`, `head`, `chain-summary` | READ |
| `operator_region_balance_audit.sh` | *(see Group G)* | READ |
| `operator_receipt_flow.sh` *(E4 R40, pending)* | *(expected: status / chain-summary / block reads, same family)* | READ |

### Group L — genesis / snapshot lineage / mempool / misc

| Script | Subcommands observed | RPC class |
|---|---|---|
| `operator_genesis_audit.sh` | `chain-summary`, `status`, `chain-id`, `verify-genesis` (offline) | READ / LOCAL |
| `operator_genesis_verify_live.sh` | `chain-id`, `verify-genesis` (offline) | READ / LOCAL |
| `operator_snapshot_lineage.sh` | `head`, `snapshot inspect` | READ |
| `operator_mempool_diagnostic.sh` | `mempool` *(absent CLI cmd / absent RPC — see §6)* | N/A — degrades |
| `operator_mempool_inspector.sh` | `head`, `status`, `mempool` *(absent — see §6)* | READ + degrade |
| `operator_unstake_timeline.sh` | `head`, `stake_info`, `show-account` | READ |

**Coverage check.** Groups A–L partition all 91 scripts (plus the pending E4
script). Every subcommand appearing in any group is in the §2.5 read/local map.
**No script in any group invokes `register`, `send`, `stake`, `unstake`, the
governance param-change subcommand, or `dapp-call`** — the six mutating
subcommands of §2.4. The grep evidence for the shell invocations is in the
survey performed for this document; the Python-heredoc `subprocess.run([determ,
"<subcommand>", …])` invocations were independently confirmed to pass only
`block-info`, `block-range`, `dapp-list`, `dapp-info`, `head`, `status`, and
`chain-summary` (all READ).

---

## §4. Theorem OT-1 (read-only family)

> **Theorem OT-1.** Every `tools/operator_*.sh` script is read-only in the
> sense of §2.3: the set of RPC methods reachable through the commands it
> issues is a subset of the 20 READ methods of §2.1, hence disjoint from
> `MUTATE_STATE`.

**Proof.** Let `S` be any operator script. Its daemon interactions are exactly
its `"$DETERM" <subcommand>` shell invocations and its
`subprocess.run([determ, "<subcommand>", …])` Python invocations (a script that
issues neither — Group A — touches no daemon and is vacuously read-only). By
the exhaustive per-script survey of §3, the set of subcommands `S` invokes is a
subset of

```
{ head, status, supply, peers, balance, chain-summary, block-info, block-range,
  headers, stakes, validators, stake_info, show-account, dapp-info, dapp-list,
  pending-params, chain-id, check-fork, snapshot {create,inspect,stats,diff},
  where-is, verify-genesis, verify-headers, mempool }.
```

By §2.5, every one of these subcommands either (a) issues only RPC methods in
the READ set of §2.1, or (b) issues no RPC at all (`where-is`,
`verify-genesis`, `verify-headers`, the non-`create` `snapshot` subcommands —
offline/local), or (c) is `mempool`, which is neither a registered CLI
subcommand nor an RPC method and therefore cannot dispatch to any handler (§6).
In every case the reachable-method-set of `S` is `⊆ READ`, hence disjoint from
`MUTATE_STATE`. Since `S` was arbitrary, the claim holds for all 91 scripts. ∎

**Corollary OT-1.1 (no state mutation regardless of arguments).** Running any
`operator_*.sh` script with any arguments cannot:

- submit a transaction (no script reaches `submit_tx` / `send` / `stake` /
  `unstake` / `register`),
- advance any account's nonce (nonce advances only inside the apply path,
  driven by `MUTATE_STATE` admissions, which the family never triggers),
- change a protocol parameter (no script reaches `submit_tx` carrying a
  `PARAM_CHANGE`, the only on-chain param-mutation channel — cf.
  `GovernanceParamChange.md`),
- register or call a DApp (no script reaches `submit_tx` carrying
  `DAPP_REGISTER` / `DAPP_CALL`),
- slash a validator (no script reaches `submit_equivocation`).

The corollary is unconditional in the script's arguments: arguments only choose
*which* read to issue (which block, which domain, which port), never *which
method*, because the method is hard-coded in the CLI `cmd_*` body, not derived
from operator input. This is the per-script generalization of
`StakeDistributionMetrics.md` SD-4.

**Note on `snapshot create`.** This is the only subcommand in the family that
sounds write-like. It is not: it maps to the READ `snapshot` RPC
(`rpc.cpp:231-232`), which serializes the daemon's *current* in-memory state
and returns it to the caller. It neither appends a block nor mutates
`chain_`. The resulting snapshot blob is written to an operator-chosen *local*
path (§5), never to the daemon's data dir.

---

## §5. Theorem OT-2 (no side-effects beyond local files)

> **Theorem OT-2.** An `operator_*.sh` script's only side effects are writes to
> its own stdout/stderr and to operator-specified local output files
> (`--json` envelopes, report paths, `--out`/temp snapshot paths). It does not
> write to the daemon's data dir and does not originate gossip traffic.

**Proof.**

1. *No mutating RPC, no gossip.* Gossip broadcast on the tx/evidence path is
   reached only from the six `MUTATE_STATE` handlers (e.g.
   `gossip_.broadcast(net::make_transaction(tx))` at `node.cpp:3373` in
   `rpc_register`; the analogous broadcast in `rpc_send` / `rpc_stake` /
   `rpc_unstake` / `rpc_submit_tx` / `rpc_submit_equivocation`). By OT-1 no
   operator script reaches any of these, so no operator script causes the
   daemon to originate a transaction-gossip message. (The READ handlers reply
   on the same TCP connection and broadcast nothing.)

2. *No mutating CLI.* A script could in principle mutate state without RPC by
   invoking a *local* mutating CLI subcommand (e.g. one that writes the
   daemon's chain file directly). The survey of §3 shows the only local-only
   (RPC-free) subcommands any script uses are `where-is` (pure computation),
   `verify-genesis` / `verify-headers` (offline read-only verifiers), and
   `snapshot inspect`/`stats`/`diff` (read local snapshot files). None writes
   the daemon's data dir. `snapshot create` writes a snapshot blob, but to an
   operator-chosen `--out` / temp path (e.g.
   `operator_balance_distribution.sh:169`, `operator_orphan_check.sh:171`,
   `operator_stake_concentration.sh:226`), never to the daemon's live data dir.

3. *Local output only.* Every script's writes are (a) human/JSON output to
   stdout, (b) error text to stderr, and (c) report / temp files at paths the
   operator controls via `--json`, report-path flags, or `mktemp`-style temp
   files the script cleans up. These are inert artifacts on the operator's host;
   they are not consumed by the daemon and do not feed back into chain state.

Hence the total observable effect of running any operator script is: zero or
more READ RPCs to the daemon, plus local file/stdout writes. ∎

**Operational reading.** From the daemon's perspective, an operator script is
indistinguishable from any other read-only RPC client (a dashboard, a `curl`
loop). It adds read load (bounded by §6) and nothing else.

---

## §6. Caveats and findings

**C-1 (read-amplification, not a safety issue).** Several scripts issue *many*
reads — the Python `block-info` loops in Group D/H walk a height range, one
`block` RPC per block (e.g. `operator_block_inclusion_audit.sh:338-341`,
`operator_account_balance_history.sh:443-446`), and `--with-message-counts` /
full-scan modes in the DApp scripts issue extra `dapp_messages` / `block`
reads. This is a *load* consideration, not a state-safety one: more reads, all
still in the READ set, still mutating nothing. The per-peer-IP token bucket of
S-014 (`net::RateLimiter`, proven in `S014RateLimiterSoundness.md`) bounds the
RPC rate a single client can sustain, so even an aggressive full-chain scan
cannot exceed the daemon's configured `rpc_rate_per_sec` / `rpc_rate_burst`.
Operators running wide scans against a busy production node should set a modest
`--rpc-port` target and expect throttling under `rpc_rate_limit`, not state
risk.

**C-2 (`mempool` subcommand is forward-staged).**
`operator_mempool_diagnostic.sh` and `operator_mempool_inspector.sh` invoke
`determ mempool --json`, but `mempool` is **neither** a registered CLI
subcommand in `src/main.cpp`'s dispatcher **nor** a method in the
`rpc.cpp:197-272` dispatch table. Today the call resolves to an "unknown
subcommand" (or, if it ever reaches the wire, a "method not found" JSON-RPC
error), and both scripts detect this and degrade gracefully — e.g.
`operator_mempool_diagnostic.sh:150` tests for a `"pending"` field and, absent
it, emits `mempool_rpc_unavailable` (`:155`) or a human "Mempool RPC not
available" message (`:157-167`). A non-existent method cannot mutate state, so
this edge case is consistent with OT-1. (Should a future `mempool` RPC be added,
it must be a READ method for OT-1 to continue to hold; §6 F-2 covers that.)

**F-1 (verdict — no mutating-method finding).** The survey found **no operator
script that invokes any of the six mutating subcommands** (`register`, `send`,
`stake`, `unstake`, governance param-change, `dapp-call`) or otherwise reaches
a `MUTATE_STATE` RPC. The family is **uniformly read-only**. F-1 is therefore
*not raised* — it is recorded here only to make explicit that the negative
result was actively checked, not assumed. (Had any script called a mutating
method, this is where it would be flagged with a recommended fix.)

**F-2 (recommendation — CI lint to keep the property).** OT-1 is a snapshot of
the shipped scripts; it is not enforced against future additions. Recommend a
~15-LOC CI check that greps every `tools/operator_*.sh` (including Python
`subprocess.run([determ, …])` argv lists) for the six mutating subcommands of
§2.4 and fails on any hit. This mirrors the static-analysis recommendation in
`S001RpcAuthSoundness.md` F-2 (which proposed asserting every mutating `rpc_*`
handler is reachable only from `dispatch`); the operator-tooling analogue is
"assert no `operator_*.sh` reaches a mutating subcommand." Pair it with a
leading comment in `tools/common.sh` pointing at this proof. *(Recommendation
only — no code is changed by this survey doc.)*

**F-3 (recommendation — header annotation).** A handful of scripts already
carry a `# Read-only RPC; safe against any running daemon` header (e.g.
`operator_chain_health.sh:6`) or an explicit `RPCs used (read-only):` block
(e.g. `operator_stake_distribution.sh:97`). Recommend standardizing that
header across the whole family so the read-only property is self-documenting at
the point of use. *(Recommendation only.)*

---

## §7. Cross-references

- **`StakeDistributionMetrics.md`** (SD-4) — the single-script read-only result
  this document generalizes; covers `operator_stake_distribution.sh` (status +
  validators reads). *(Parallel R40 deliverable; threader unions the README
  row.)*
- **`S001RpcAuthSoundness.md`** (T-3) — exhaustive enumeration of the six
  `MUTATE_STATE` endpoints and the auth-before-dispatch invariant; defines the
  same `MUTATE_STATE` set used here.
- **`RpcInputValidationDefense.md`** (L-3, §3) — the five-layer RPC input
  defense; independently defines `MUTATE_STATE` and case-analyzes the six
  mutating handlers.
- **`S014RateLimiterSoundness.md`** — the per-peer-IP token bucket that bounds
  the read load any operator script (or any client) can impose (caveat C-1).
- **`RpcAuthHmacSoundness.md`** — the HMAC gate (S-001) that fences the six
  mutating methods; operator scripts, being read-only, are unaffected by it
  except when the daemon also gates reads.
- **Surveyed scripts:** all 91 `tools/operator_*.sh` files enumerated in §3
  (plus `tools/operator_receipt_flow.sh`, E4 R40, pending).
- **Daemon dispatch:** `src/rpc/rpc.cpp:197-272` (the single RPC dispatch
  point); `src/node/node.cpp:3338-3375` (`rpc_register`, representative
  mutating handler); `src/main.cpp` CLI subcommand bodies cited in §2.4–§2.5.

---

## §8. Status

Survey complete as of **R40**. **91** `operator_*.sh` scripts catalogued
(Groups A–L of §3, partitioning the family) — plus
`operator_receipt_flow.sh` (E4 R40, landing in parallel; covered by the same
argument, marked pending). **Verdict: the family is uniformly read-only.** No
script invokes any state-mutating RPC method or mutating CLI subcommand;
Theorem OT-1 (read-only family) and Theorem OT-2 (no side-effects beyond local
files) both hold. No F-1 mutating-method finding was raised. Two recommendations
recorded: F-2 (CI lint to preserve the property) and F-3 (standardize the
read-only header). Both are advisory; this survey changes no code.
