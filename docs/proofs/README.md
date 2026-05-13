# Determ — Formal proofs index

This directory contains the per-property analytic proofs for Determ's consensus, sharding, and slashing mechanisms. Each proof is self-contained: a theorem statement, the cryptographic and behavioral assumptions it depends on, the proof itself, and an implementation cross-reference so a reviewer can match the math to the code.

The proofs target two audiences:

1. **Protocol reviewers** — to confirm the properties Determ claims are actually proved, not assumed.
2. **Implementers** — to confirm each invariant is enforced at the exact source location the proof cites.

The proofs are written in standard mathematical prose, not in a machine-checkable spec language. A future track (FB) will add TLA+ models for the consensus and sharding state machines; the FA-track documents here are the human-readable counterpart.

---

## Reading order

Start with **F0 Preliminaries**. Everything else cites its notation, assumptions, and validity predicates.

| # | File | Property | Status |
|---|---|---|---|
| F0 | [Preliminaries.md](Preliminaries.md) | Notation, assumptions, validity predicates | ✓ |
| FA1 | [Safety.md](Safety.md) | K-of-K mutual-distrust safety: ≤1 finalized digest per height | ✓ |
| FA2 | [Censorship.md](Censorship.md) | Censorship resistance: union-tx-root inclusion of any honest mempool tx | ✓ |
| FA3 | [SelectiveAbort.md](SelectiveAbort.md) | Selective-abort resistance: commit-reveal hides delay_output until phase-2 | ✓ |
| FA4 | [Liveness.md](Liveness.md) | Liveness: finalized block within geometric-bounded rounds | ✓ |
| FA5 | [BFTSafety.md](BFTSafety.md) | BFT-mode safety under f < K_eff/3; slashing recovery otherwise | ✓ |
| FA6 | [EquivocationSlashing.md](EquivocationSlashing.md) | Slashing soundness: honest never slashed for equivocation | ✓ |
| FA7 | [CrossShardReceipts.md](CrossShardReceipts.md) | Cross-shard atomicity: no double-credit, A1 invariant composes | ✓ |
| FA8 | [RegionalSharding.md](RegionalSharding.md) | Regional pinning preserves FA1/FA4/FA5/FA6/FA7 | ✓ |
| FA9 | [UnderQuorumMerge.md](UnderQuorumMerge.md) | R4 under-quorum merge preserves FA1/FA7 across BEGIN/END | ✓ |
| FA10 | [Governance.md](Governance.md) | A5 PARAM_CHANGE soundness: no unauthorized mutation, off-whitelist immunity | ✓ |
| FA11 | [EconomicSoundness.md](EconomicSoundness.md) | A1 unitary supply invariant + E1/E3/E4 preservation | ✓ |
| FA12 | [WalletRecovery.md](WalletRecovery.md) | A2 wallet recovery: Shamir ITS + AEAD + OPAQUE composition | ✓ |

FB-track (TLA+ machine-checkable):

| # | File | Status |
|---|---|---|
| FB1 | [tla/Consensus.tla](tla/Consensus.tla) — K-of-K consensus state machine | ✓ spec, model-check pending TLC install |
| FB2 | [tla/Sharding.tla](tla/Sharding.tla) — multi-shard receipt flow | ✓ spec, model-check pending TLC install |
| FB3 | [tla/Receipts.tla](tla/Receipts.tla) — receipt dedup state machine | ✓ spec, model-check pending TLC install |
| FB4 | [tla/CHECK-RESULTS.md](tla/CHECK-RESULTS.md) — model-check transcripts | ✓ template, transcripts pending |

---

## Cryptographic assumptions

All FA-track proofs reduce to one or more of:

- **(A1) Ed25519 EUF-CMA** — `Verify(pk, m, σ) = 1` implies the holder of `sk` signed `m`, except with probability `≤ 2⁻¹²⁸`. Used in FA1, FA5, FA6, FA7.
- **(A3) SHA-256 collision resistance** — finding `x ≠ y` with `SHA256(x) = SHA256(y)` is `≤ 2⁻¹²⁸`. Used in FA2 (tx_root commitment), FA7 (receipt binding).
- **(A4) SHA-256 preimage resistance** — finding `x` with `SHA256(x) = h` for adversary-chosen `h` is `≤ 2⁻²⁵⁶`. Used in FA3 (commit-reveal hiding).
- **(A5) SHA-256 as a random oracle** — used in FA3 (analytic) for the cleanest formulation; FA3 also gives a standard-model version with weaker constants.

The PQ degradation under Grover (square-root speedup) is discussed in each proof's "Concrete-security bound" section. Determ's design upgrades to post-quantum signatures (Dilithium / Falcon) would restore the classical bounds; this is a pre-planned migration path, not a current requirement.

---

## Behavioral assumptions

- **(H1)** Honest validators follow the protocol: produce phase-1 commits, reveal in phase-2, vote on valid blocks, gossip evidence.
- **(H2)** Honest validators sign at most one digest per `(height, round)` — the rule that makes equivocation detection trip on misbehavior, never on honest behavior.
- **(H3)** Honest validators do not censor: they include all mempool txs they observe in their phase-1 commit, subject to validation.
- **(H4)** Honest validators reveal `dh_secret` in phase-2 only after gathering K phase-1 commits.

These are not cryptographic assumptions; they define what "honest" *means* in the protocol. FA-track proofs target conditional properties: "given H1–H4 and A1/A3/A4/A5, the protocol satisfies property P with bound B."

---

## What the FA-track proofs do NOT cover

- **Pure economic incentives**: e.g., why a rational validator chooses honest behavior. The proofs assume `≥ 1` honest committee member (FA1 standard branch) or assume slashing makes equivocation economically irrational (FA6 motivation). A separate economic-security analysis is in `docs/SECURITY.md`.
- **Network-layer DoS resistance**: gossip flood control, peer reputation, eclipse attacks. These are operational concerns, not consensus-level invariants. `docs/SECURITY.md` covers them.
- **Implementation bugs**: the proofs cite source locations, but a reviewer must still confirm the code at those locations matches the proof's stated invariant. The TLA+ track (FB) will close the gap between proof and code by model-checking the abstract state machines that the C++ implementation tracks.
- **Cross-shard liveness under permanent regional silence**: FA7 covers safety; long-running silent shards strand value in `Pending`. Refund mechanism is a v2+ design item.

---

## Cross-references

Each per-property proof cites:

- F0 (Preliminaries) for notation and assumptions
- Other FA proofs where their results are used
- `src/` paths where the invariants are enforced
- `tools/test_*.sh` integration tests that exercise the invariant

A reviewer working bottom-up (code → proof) should be able to:

1. Read a `check_*` function in `src/node/validator.cpp`.
2. Identify which validity predicate (V1–V14 from F0) it enforces.
3. Trace which FA-track proof depends on that predicate.

A reviewer working top-down (theorem → code) should be able to:

1. Read a theorem statement in this directory.
2. Identify which validator check + apply-side state mutation upholds it.
3. Confirm in the cited source location.

If either direction fails — a check in code that no theorem references, or a theorem with no code-side enforcement — that's a gap worth raising.

---

## Concrete-security summary

Under standard assumptions (Ed25519 EUF-CMA, SHA-256 CR + preimage resistance, ROM where needed), every FA-track property holds with probability ≥ `1 - Q · 2⁻¹²⁸` over polynomial adversary budget `Q`. For `Q = 2⁶⁰`, the cumulative failure probability is `≤ 2⁻⁶⁸` — strongly negligible.

Per-property bounds:

| Property | Bound per attempt | Cumulative (Q = 2⁶⁰) |
|---|---|---|
| FA1 safety fork | 2⁻¹²⁸ | 2⁻⁶⁸ |
| FA2 censorship | 2⁻¹²⁸ (tx_root preimage) | 2⁻⁶⁸ |
| FA3 selective abort | 2⁻²⁵⁶ (commit preimage) | 2⁻¹⁹⁶ |
| FA5 BFT fork | 2⁻¹²⁸ · K_eff (forge intersection) | 2⁻⁶² for K_eff ≤ 64 |
| FA6 false-positive slash | 2⁻¹²⁸ | 2⁻⁶⁸ |
| FA7 receipt fabrication | K · 2⁻¹²⁸ | 2⁻⁶² for K ≤ 64 |
| FA10 unauthorized PARAM_CHANGE | 2⁻¹²⁸·(N−1) for N keyholders | 2⁻⁴⁵² for N = 5 |
| FA12 wallet recovery (real OPAQUE) | Q · 2⁻⁶⁰ + N · 2⁻¹²⁸ | 2⁻⁴⁴ with 60-bit pw, Q = 2¹⁶ |
| FA12 wallet recovery (stub adapter) | offline-grindable | NOT for production |

Under Grover (PQ), each `2⁻¹²⁸` degrades to `2⁻⁶⁴`. The protocol remains operationally secure but tighter PQ-signature migration is recommended.
