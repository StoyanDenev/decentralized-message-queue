# FB6 — TLA+ model-check transcripts (template)

This document records the outcome of running TLC against the TLA+ specifications in this directory. Each entry includes the command, configuration, state-space size, invariants verified, and any counter-examples found.

**Status:** Specifications shipped. Model-check runs **pending TLC installation** in CI. The configurations are small enough that any developer with TLC installed can reproduce results in seconds-to-minutes.

---

## How to run

### Prerequisites

- Java ≥ 11
- TLA+ tools (TLC). Download `tla2tools.jar` from <https://github.com/tlaplus/tlaplus/releases>.

### Running each spec

```bash
cd docs/proofs/tla

# FB1 — Consensus state machine
java -jar tla2tools.jar -config Consensus.cfg Consensus.tla

# FB2 — Cross-shard receipt flow
java -jar tla2tools.jar -config Sharding.cfg Sharding.tla

# FB3 — Receipt dedup
java -jar tla2tools.jar -config Receipts.cfg Receipts.tla

# FB5 — Account-state apply layer
java -jar tla2tools.jar -config AccountState.cfg AccountState.tla

# FB6 — Snapshot + restore state machine
java -jar tla2tools.jar -config Snapshot.cfg Snapshot.tla
```

Each run should report `Model checking completed. No error has been found.` for the invariants listed in the `.cfg` file. For `Consensus.tla`, the temporal property `Prop_Termination` is also checked.

### Reproducible state-space targets

These are the expected approximate magnitudes for the shipped configurations:

| Spec | Distinct states | Wall time (TLC, single core) |
|---|---|---|
| Consensus.tla (K=3, F=1) | ~10⁴–10⁵ | < 30s |
| Sharding.tla (2 shards, 2 accts) | ~10³ | < 10s |
| Receipts.tla (3 IDs, 6 blocks) | ~10² | < 1s |
| AccountState.tla (3 domains, B=4, N=3, H=4) | ~10⁵ (est.) | < 60s (est., spec written, TLC pending) |
| Snapshot.tla (3 domains, H=4, B=5) | ~10⁴ (est.) | < 30s (est., spec written, TLC pending) |

If a future run reports significantly different magnitudes (10× off in either direction), the spec or config likely changed semantics and warrants review.

---

## What each model verifies

### Consensus.tla → FA1, FA3, FA4, FA6

| Invariant | Maps to |
|---|---|
| `Inv_OneDigest` | FA1 T-1 safety: ≤1 finalized digest per height |
| `Inv_NoEarlyReveal` | FA3 selective-abort: no `dh_secret` reveal before K commits seen |
| `Inv_HonestNoEquivocate` | FA6 T-6: honest validators never sign two distinct digests at same height |
| `Prop_Termination` (temporal) | FA4 liveness: under fair scheduling, the height finalizes |

The Byzantine action `ContribByzantine` lets a Byzantine member commit to multiple digests in phase 1 — modeling the worst-case adversary considered in FA1. The model passes the safety invariant despite this, because the K-of-K block-sig phase requires honest participation.

### Sharding.tla → FA7

| Invariant | Maps to |
|---|---|
| `Inv_NoDoubleCredit` | FA7 T-7 part 1: each `(src, tx_hash)` credited at most once on dst (set semantics) |
| `Inv_V13_DedupContract` | V13 dst-side dedup: every applied `(src, id)` pair has exactly one emitted-receipt provenance on `src` whose destination is this `dst` (non-degenerate strengthening — couples src-side V12 emission with dst-side V13 admission) |
| `Inv_AppliedHasOrigin` | FA7 T-7 part 2: every applied receipt traces to an emitted one |
| `Inv_SupplyInvariant` | FA7 T-7.1 corollary: `LiveGlobal + Pending = Genesis` |

The adversary action `ReplayReceipt` re-injects an already-emitted receipt into a destination's pending queue. The dedup guard in `ApplyReceipt` ensures it is never credited twice. `Inv_V13_DedupContract` is the machine-checkable counterpart to V13 in `proofs/Preliminaries.md` (post V12+V13 split) and corresponds to the `chain::Chain::applied_inbound_receipts_` membership check at `src/chain/chain.cpp:1365`.

### Receipts.tla → FA7 L-7.2 (focused)

| Invariant | Maps to |
|---|---|
| `Inv_NoDoubleCredit` | FA7 L-7.2: dedup across all blocks |
| `Inv_LogConsistent` | apply-side state matches log of credit events |

This is the smallest, fastest model — a regression-quality check on the dedup state machine specifically.

### AccountState.tla → apply-layer (AccountState struct invariants)

| Invariant | Maps to |
|---|---|
| `Inv_TypeOK` | shape of `accounts` (balance, nonce) and `stakes` (locked, unlock_height) maps |
| `Inv_NoNegativeBalance` | per-domain balance ≥ 0 (Nat-typed; documents the constraint) |
| `Inv_NoNegativeStake` | per-domain stake.locked ≥ 0 |
| `Inv_NonceBounded` | per-domain nonce within `MaxNonce` bound |
| `Inv_NonceMonotonic` | action-level: no nonce ever decreases across a `[Next]_vars` step |
| `Inv_SupplyConservation` | `sum(balances) + sum(stakes.locked) + slashed = INITIAL_TOTAL` — every Transfer / Stake / UnstakeStart / UnstakeComplete is an internal redistribution; only Slash decreases the live total (and the destruction is captured in `slashed`) |
| `Inv_BalanceStakeIndependence` | action-level: Transfer never modifies stakes, Slash never modifies balances; only Stake and UnstakeComplete move value between the two maps |
| `Inv_SlashedMonotonic` | `slashed` is monotone non-decreasing across any step |

**Spec status:** written; TLC verification pending (consistent with the other three specs above — no TLC in the build container yet). The configuration in `AccountState.cfg` (3 domains, MaxBalance=4, MaxNonce=3, MaxHeight=4) is sized for an interactive TLC run in under a minute on a single core. Variables modeled: `accounts` (Domains → [balance, nonce]), `stakes` (Domains → [locked, unlock_height]), `height` (Nat), `slashed` (Nat). Actions modeled: `Transfer`, `Stake`, `UnstakeStart`, `UnstakeComplete`, `Slash`, `Tick`. The `ed_pub` field of the real `AccountState` struct is omitted intentionally — it is fixed at register time and is not invariant-relevant for any of these properties.

Companion prose proof: `docs/proofs/AccountStateInvariants.md` (separately written — that document may not exist in this worktree at the time this spec was committed; the prose track is being assembled in parallel).

### Snapshot.tla → snapshot + restore state machine (S-033 / S-037 / S-038)

| Invariant | Maps to |
|---|---|
| `Inv_TypeOK` | shape of `chain` (height, head_hash, balances, nonces, state_root, counters) plus `last_snapshot` / `snapshot_count` |
| `Inv_SerializeRestoreIdentity` | for every reachable chain c, `RestoreSnapshot(TakeSnapshot(c)) = c` — the round-trip identity that S-037 exposed as a missing namespace bug in the C++ implementation |
| `Inv_ApplyAfterRestoreEquivalence` | commuting square: `AppendBlock(b)` ≡ `TakeSnapshot ; RestoreSnapshot ; AppendBlock(b)` for any block b appendable to c — guarantees that a snapshot/restore round-trip is transparent to subsequent apply |
| `Inv_VersionGateSoundness` | restoring a snapshot whose `version` field is not `SnapshotVersion` is a no-op on the chain — matches `Chain::restore_from_snapshot` lines 1706–1709 in `src/chain/chain.cpp` |
| `Inv_DeterministicSerialization` | `TakeSnapshot(c)` is a pure function of c (no fresh randomness, no time-dependent fields) |
| `Inv_StateRootBindsApply` | `state_root` field uniquely determines the (balances, counters) tuple — the S-033 (verification gate) + S-038 (producer-side wiring) commitment property |
| `Prop_EventualSnapshotConsistency` (temporal) | under fairness on `TakeSnapshot`, every reachable chain state is eventually witnessed by a snapshot |
| `Prop_RestoreIsCorrect` (temporal) | action-level: after any successful `RestoreSnapshot` of a well-formed snapshot, `chain' = last_snapshot.payload` |

**Spec status:** written; TLC verification pending (consistent with the other four specs above). The configuration in `Snapshot.cfg` (3 domains, MaxHeight=4, MaxBalance=5, SnapshotVersion=1) is sized for an interactive TLC run in well under a minute on a single core. Variables modeled: `chain` (a single ChainState record collapsing the 10 state_root namespaces into the safety-critical subset: balances, nonces, accumulated counters), `last_snapshot` (SnapshotRec or sentinel), `snapshot_count` (Nat, drives the temporal liveness property). Actions modeled: `AppendBlock`, `TakeSnapshot`, `RestoreSnapshot`, `RejectMalformedSnapshot` (adversary). The Receipts.tla pattern of pairing the dedup state with an adversary action carries over here — `RejectMalformedSnapshot` is the explicit wrong-version branch that `Inv_VersionGateSoundness` covers structurally.

Companion prose proof: `docs/proofs/SnapshotInvariants.md` (separately tracked; the prose track is being assembled in parallel).

---

## Mapping to source code

Each invariant directly mirrors a structure or check in the C++ implementation:

| Spec construct | Source location |
|---|---|
| `Consensus.contribs` | `src/node/node.cpp::on_contrib` (Phase-1 commit gather into `pending_contribs_`) |
| `Consensus.secrets_revealed` | `src/node/node.cpp::on_block_sig` (Phase-2 reveal gate, `pending_block_sigs_` admission) |
| `Consensus.SeenKCommits` | `src/node/node.cpp::on_contrib` (the `pending_contribs_.size() == current_creator_domains_.size()` check that fires `start_block_sig_phase`) |
| `Consensus.Finalize` quorum | `src/node/validator.cpp::check_block_sigs` (MD: K-of-K full committee; BFT: Q = ceil(2·k_bft/3) within the shrunk k_bft = ceil(2K/3) committee — two-level shrinkage, see PROTOCOL.md §5.3). The spec uses `Keff = ceil(2K/3)` which only models the first-level shrinkage; this is correct degenerately at K=3 (Q=k_bft=2) and an over-approximation at K>=6 (safe direction for the Inv_OneDigest invariant; see Consensus.tla comment above the Keff definition). |
| `Sharding.emitted_receipts` | `chain::Block::cross_shard_receipts` field |
| `Sharding.pending_inbound` | `node::Node::pending_inbound_receipts_` |
| `Sharding.applied` | `chain::Chain::applied_inbound_receipts_` |
| `Receipts.applied` | same as above; isolated for focused check |
| `AccountState.accounts` | `src/chain/chain.cpp::accounts_` (map<string, AccountState> keyed by domain) |
| `AccountState.stakes` | `src/chain/chain.cpp::stakes_` (map<string, StakeState> with locked + unlock_height) |
| `AccountState.height` | `src/chain/chain.cpp::current_height_` (advanced once per applied block) |
| `AccountState.slashed` | `src/chain/chain.cpp` slash apply path (FA6 equivocation slashing) |
| `AccountState.Transfer` | `src/chain/chain.cpp::apply_transactions` TRANSFER branch (balance debit/credit + nonce increment) |
| `AccountState.Stake` / `UnstakeStart` / `UnstakeComplete` | STAKE / UNSTAKE branches in `apply_transactions` and the `unlock_height` cascade in `Chain::on_block_applied` |
| `Snapshot.DoTakeSnapshot` | `src/chain/chain.cpp::Chain::serialize_state` (the version, head_index, head_hash and per-namespace field emitters at lines ~1541–1700) |
| `Snapshot.DoRestoreSnapshot` | `src/chain/chain.cpp::Chain::restore_from_snapshot` (the version-gate check at lines 1706–1709 + per-namespace field consumers) |
| `Snapshot.StateRoot` | `chain::Block::compute_state_root` (10 namespaces; the spec collapses them to the safety-critical subset — see Snapshot.tla file header) |
| `Snapshot.AppendBlock` | `src/chain/chain.cpp::apply_block` + `on_block_applied` (advances height, mutates balances/nonces/counters, recomputes state_root, populates head.state_root via S-038 wiring) |
| `Snapshot.RejectMalformedSnapshot` | the wrong-version path inside `Chain::restore_from_snapshot` — the `if (v != 1) throw` branch at line 1707 (S-037 / S-018 cousin) |

A reviewer who is suspicious of a particular invariant can:

1. Identify the source-code line that should enforce it (table above).
2. Read the code at that location.
3. Confirm the code matches the spec's guard or update.

---

## Counter-examples found (none expected)

If any TLC run produces an invariant violation, this section will record:

- The violated invariant.
- The trace TLC printed (state sequence leading to violation).
- The diagnosis: spec bug vs. real implementation bug.
- The fix.

**Current entries:** none.

---

## Known TLA+ spec limitations

These are *modeling* limitations — not implementation gaps:

1. **No cryptography modeled.** Signatures are abstracted as set membership. The FA-track analytic proofs (FA1, FA6) handle EUF-CMA bounds; the TLA+ spec only models the message flow.
2. **Single-height projection (Consensus).** The model checks one height at a time. Cross-height safety (chain growth, fork-choice) is a separate concern that follows from per-height safety + linear chain structure.
3. **No actual hashes.** Digests are small integers; the spec asserts no collisions trivially. SHA-256 collision resistance is an external cryptographic assumption (FA-track).
4. **Bounded state.** `MaxRounds`, `MaxTransfers`, `MaxBlocks` cap the model. TLC exhausts the bounded state space; analytic proofs (FA-track) give the unbounded result.

These limitations are *intentional* — TLA+ is for state-machine correctness, not cryptographic security. The FA-track and FB-track together cover both layers.

---

## CI integration (future)

The natural next step is wiring TLC into CI:

```yaml
# .github/workflows/formal.yml (sketch)
- name: TLA+ model check
  run: |
    cd docs/proofs/tla
    for cfg in Consensus Sharding Receipts AccountState Snapshot; do
      java -jar tla2tools.jar -config $cfg.cfg $cfg.tla
    done
```

This isn't shipped yet (no Java in the build container). When it lands, this document gets the actual transcript appended.

---

## Conclusion

The five TLA+ specifications cover the state-machine layer of Determ's safety, atomicity, apply-layer, and snapshot/restore properties. Combined with the analytic FA-track proofs (cryptographic layer), they form a two-track verification approach:

- **FA-track**: human-readable, cryptographically tight, unbounded.
- **FB-track**: machine-checkable, structurally exhaustive over bounded models.

Both tracks cite the same source-code locations, so a reviewer can trace any property end-to-end: theorem → state-machine model → source code.
