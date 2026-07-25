# Block-Ingress Gate-Gap Audit

**Status:** open (2026-07-25); 1 autonomous gate CLOSED. FIFTH code-surface register in the
falsify-on-mutant series, after [ProofClaimGateTraceability](ProofClaimGateTraceability.md),
[ConsensusValidatorGateAudit](ConsensusValidatorGateAudit.md) (19/19),
[RpcIngressGateAudit](RpcIngressGateAudit.md), and [SnapshotRestoreGateAudit](SnapshotRestoreGateAudit.md).

## 0. Surface & method

The **untrusted-block ingress path** — how a gossiped `chain::Block` becomes chain state or
forensic evidence: `Node::on_block` → `Node::apply_block_locked` (node.cpp:2353), its
duplicate/old-height branch (`b.index < chain_.height()`), the equivocation-detection + reorg
sub-paths, and the `Block::from_json` / binary decode that feeds them. This is the sibling of the
tx-ingress (RpcIngress MEM-tx-sig-admit), the RPC-ingress, and the snapshot-restore surfaces.

Unlike the prior four registers, the first gate here was found by **direct inspection**, not a
discovery workflow — a full finder → adversarial-verify sweep of this surface is a future step.

## 1. Verdict so far

The block **accept** path (`b.index >= height()` → `validator_.validate()` → `chain_.append`) is
covered by [ConsensusValidatorGateAudit](ConsensusValidatorGateAudit.md) (19/19) and enforces
`creator_block_sigs.size() == creators.size()` (validator.cpp:453) before it indexes that vector.
The gap is on the **pre-validation duplicate/old-height branch**, which runs *before* any
`validate()` call.

## 2. CLOSED — EQV-assemble-OOB (`test-equivocation-detect-oob`)

`apply_block_locked`'s duplicate/old-height branch assembles an `EquivocationEvent` when a peer
gossips a block at an already-committed height that conflicts with the block we stored there. The
inline code found the proposer's index in `b.creators` (`bidx`) and then read
`b.creator_block_sigs[bidx]` **with no bounds check**. That branch never validated `b`, and
`Block::from_json` (block.cpp:805-807) does **not** enforce
`creator_block_sigs.size() == creators.size()`, so a peer can gossip a BFT block whose
`creator_block_sigs` is **shorter** than the proposer's `creators`-position — e.g. `creators = [P]`
with `creator_block_sigs = []`. The result is an out-of-bounds read on
`std::vector::operator[]` → **remote crash / DoS** (a rebuilt binary segfaults, EXIT=139, on the
empty-vector case). Every sibling that indexes `creator_block_sigs` by a `creators`-position already
guards the size first — validator.cpp:453, `maybe_reorg` (node.cpp:2606), the beacon-header verifier
(node.cpp:1979), and shardtip_verify.cpp:103 — this forensic path was the sole omission.

Reachability: the branch fires only when both blocks are BFT-mode (non-empty `bft_proposer`) and name
the same proposer, so the surface is BFT-mode chains; the incoming block is fully attacker-controlled
and pre-validation.

**Fix (pure robustness, no accept-rule / consensus change).** The evidence assembly is factored out
of `apply_block_locked` into a pure, size-guarded free function
`node::detect_equivocation(stored, incoming, is_shard, shard_id, beacon_anchor_height)` →
`std::optional<EquivocationEvent>` (producer.hpp / producer.cpp, co-located with
`hash_equivocation_event`, mirroring the shardtip_verify free-function pattern). The refactor is
behavior-preserving on the honest path (same predicate order, same field assignment, same SHARD
provenance) and adds exactly one check before the indexing:
`if (sidx >= stored.creator_block_sigs.size() || bidx >= b.creator_block_sigs.size()) return nullopt;`.
A malformed/size-short block is dropped as a non-equivocating duplicate — which is what the validator
would do with it on the accept path anyway. The pool dedup + gossip + log side-effects stay in
`apply_block_locked`.

**Gate** = `test-equivocation-detect-oob` (drives the helper directly, no full Node needed):
- **Positive control** — a genuine same-height double-sign (two blocks by one proposer differing in
  `tx_root`, so distinct `compute_block_digest`s; `detect_equivocation` does not verify sigs
  cryptographically — that is the validator's job — so patterned bytes suffice) still assembles the
  event with the correct equivocator/height/digests/sigs.
- **The guard** — a size-short incoming block (empty `creator_block_sigs` with proposer@0; or
  proposer@1 with one sig) and a symmetric size-short **stored** block both return `nullopt` with no
  OOB.
- **Guard-independent negatives** (empty proposer, different proposer, identical block, same-digest
  different-sig, proposer absent from creators) return `nullopt`; SHARD-role provenance is threaded
  on a genuine detection.

**Falsify-on-mutant** (`if (false && (sidx >= … || bidx >= …))`): the guarded build passes 12/12
(EXIT=0); the mutant **segfaults** (EXIT=139) on the empty-vector read — the size-short asserts flip
(via crash on MSVC, or the ASan heap-overflow report on the Linux `ci_local` sanitizer build) while
the positive control + negatives stay green. Both platforms.

**Regression gate for the refactor:** `test-fa-equivocation-trace` (the live-engine harness that
exercises real equivocation detection + slashing) stays green on both platforms — the extraction did
not change honest detection behavior.

## 3. Follow-up (not yet this register)

A full finder → adversarial-verify discovery sweep of the block-ingress surface (the reorg path,
`on_block_sig` buffering/flooding, the F2 reconciliation admission on gossiped blocks, decode-side
bounds) is the natural next step; the accept path itself is already closed by
ConsensusValidatorGateAudit. Any consensus/accept-rule finding is owner-gated, as in the RpcIngress
register.
