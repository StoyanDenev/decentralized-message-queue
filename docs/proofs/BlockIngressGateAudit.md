# Block-Ingress Gate-Gap Audit

**Status:** open (2026-07-25, updated 2026-07-26); **3 autonomous gates CLOSED** (the discovery
sweep's autonomous-safe findings are exhausted). FIFTH code-surface
register in the falsify-on-mutant series, after [ProofClaimGateTraceability](ProofClaimGateTraceability.md),
[ConsensusValidatorGateAudit](ConsensusValidatorGateAudit.md) (19/19),
[RpcIngressGateAudit](RpcIngressGateAudit.md), and [SnapshotRestoreGateAudit](SnapshotRestoreGateAudit.md).

## 0. Surface & method

The **untrusted-block ingress path** — how a gossiped `chain::Block` (and its side-paths) becomes
chain state or forensic evidence: `Node::on_block` → `Node::apply_block_locked` (node.cpp:2353), its
duplicate/old-height branch (`b.index < chain_.height()`), the equivocation-detection + reorg
sub-paths, the gossip-fed pools (`pending_equivocation_evidence_`, `pending_inbound_receipts_`), and
the `Block::from_json` / binary decode that feeds them. This is the sibling of the tx-ingress
(RpcIngress MEM-tx-sig-admit), the RPC-ingress, and the snapshot-restore surfaces.

**Method.** The first gate (§2) was found by **direct inspection**. The rest of the surface was then
swept by a discovery workflow `wf_1061bad6-1fc` — 5 finders (pre-validation `apply_block_locked`,
`on_block_sig` buffering, `Block::from_json`/binary-decode bounds, the reorg path, F2 pools + gossip
work-amplification) → adversarial REFUTE-by-default verifiers that independently re-classified each
finding as autonomous-safe (pure robustness) vs owner-gated. Result: **2 confirmed autonomous-safe
(both closed — §2, §3), 1 refuted, 0 owner-gated**; the pre-validation, block-sig-buffering, and
decode-bounds sub-surfaces returned clean (covered by the 19/19 accept path, the §2 fix, and the
existing decode caps).

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

## 3. CLOSED — equiv-evidence dedup identity (`test-equivocation-dedup-identity`)

`pending_equivocation_evidence_` deduped inserts on `(equivocator, block_index)` at three sites
(`on_equivocation_evidence` gossip handler node.cpp:1922, the self-built detect path in
`apply_block_locked`, the `on_contrib` S-006 detect), and `rpc_submit_equivocation` inspected the
pool with the same key for its response. But **`EquivocationEvent.block_index` is bound by neither of
the two signatures** — only the two raw 32-byte digests are signed — so a single *valid* double-sign
`(digest_a, sig_a, digest_b, sig_b)` re-passes both `crypto::verify` calls when re-gossiped/
re-submitted with `block_index = 0, 1, 2, … 2⁶⁴-1`, each counting as a fresh `(equivocator,
block_index)` entry → **unbounded pool growth from ONE proof** (a node-local memory-exhaustion DoS).
This is DISTINCT from the owner-gated `EQV-height-unbound-forged-slash` consensus vuln
(RpcIngressGateAudit): here the impact is the *pool dedup key*, and the fix is a pool-dedup change,
not an accept-rule change. Tellingly, the credited-evidence prune (node.cpp:2454) already treats the
**equivocator alone** as the identity (`remove_if` by equivocator) — the insert dedup was simply
inconsistent with it.

**Fix (pure robustness, no accept-rule / consensus / wire change).** ONE shared identity predicate
`node::same_equivocation_identity(a, b) → a.equivocator == b.equivocator` (+ a
`pending_equivocation_contains` helper) in producer.hpp, used at **every** dedup / inspect / prune
site so they cannot drift. Dedup on the equivocator alone bounds the pool to |distinct equivocators|
(≤ |registrants|, since each insert requires a signature-verified proof against a *registered* key)
and defeats the replay amplification. Behavior-preserving on honest input: an equivocator is fully
slashed (full-stake forfeit + deregister) on the FIRST valid proof regardless of height, so a second
distinct-height proof for the same equivocator is redundant — exactly why the prune already erases by
equivocator. `rpc_submit_equivocation` now reports `accepted=true` idempotently for an already-pooled
equivocator (it *will* be slashed), `false` only for an invalid submission.

**Gate** = `test-equivocation-dedup-identity` (drives the shared predicate directly, no Node needed):
a replay with a different / far `block_index` is deduped (amplification defeated), a same-equivocator
different-proof-bytes submission is deduped, but a **different equivocator is NOT deduped** (distinct
equivocators each keep a pool entry → slashing coverage preserved); the predicate ignores
`block_index` and distinguishes equivocators; empty pool contains nothing. **Falsify-on-mutant**
(restore `&& a.block_index == b.block_index` to the identity): the four replay/ignore-block_index
asserts flip RED while the over-broadness guard + discriminator + empty-pool stay green — clean
directional split, both platforms. **Regression:** `test-fa-equivocation-trace` (live-engine
detection + slashing + pooling) stays green — the honest path is unchanged.

## 4. CLOSED — inbound-receipt-pool cap (`test-inbound-receipt-cap`)

`Node::on_cross_shard_receipt_bundle` (node.cpp:2277, SHARD-role branch) admitted every receipt of a
gossiped, **unsigned** `CROSS_SHARD_RECEIPT_BUNDLE` into `pending_inbound_receipts_` (keyed on
`(src_shard, tx_hash)`, with a parallel `pending_inbound_first_seen_`) with **no size cap**. Source-side
K-of-K verification is deferred to the B3.4 milestone, so this is documented "untrusted transit data";
but the pool is pruned **only** when a block this node applies actually credits a receipt
(node.cpp:2467) — so a junk receipt (a random `tx_hash` matching no real cross-shard TRANSFER) is
never baked into a valid block and never erased. A peer flooding distinct `tx_hash`es grows the pool
(and its parallel map) without bound = **remote memory-exhaustion DoS**. Reachable on a SHARD-role
multi-shard deployment, no stake/auth. This is the receipts sibling of the RpcIngress 256-page cap
family: the read/responder handlers are capped, this **write-side pool** was not.

**Fix (pure robustness, no accept-rule / consensus / state_root / wire change).** A public node-local
`MAX_PENDING_INBOUND_RECEIPTS = 10000` (same order as the S-008 mempool `MEMPOOL_MAX_TXS`) + a
`if (pending_inbound_receipts_.size() >= MAX_PENDING_INBOUND_RECEIPTS) break;` before the insert
(drop-newest). The cap sits after the dedup `continue` and before **both** map inserts, so the two
maps stay in lockstep and no orphan `first_seen` entry can form. The pool is node-local transit state
consumed by the producer and credited only after block validation, so bounding it changes no
consensus outcome. **★ Honest caveat (documented, not silent):** drop-newest is intentionally lossy —
because junk is never credited/erased, a *one-time* burst of MAX distinct `tx_hash`es leaves the pool
**permanently full**, blocking further inbound-receipt admission on this node until restart. That is a
**bounded-memory functional degradation**, strictly preferable to the pre-fix unbounded-memory OOM
crash. The complete, non-lossy fix (only authenticated receipts ever enter the pool) is the **B3.4
source-side K-of-K authentication — a consensus/protocol change, owner-gated**; an eviction policy
(FIFO-by-`first_seen`) is a possible future autonomous refinement that would recover after a one-time
burst, but adds churn and is moot once B3.4 lands.

**Gate** = `test-inbound-receipt-cap` (in-process SHARD-role Node harness; observable is
`rpc_status()["pending_inbound_receipts"]`): CONTROL — a 5-receipt bundle is admitted in full (pool
== 5, proves the SHARD ingest path is reached + admits); FLOOD — CAP+100 distinct `tx_hash`es cap the
pool at exactly `MAX_PENDING_INBOUND_RECEIPTS`; a second disjoint flood keeps it AT the cap (idempotent
ceiling). **Falsify-on-mutant** (`if (false && …) break`): the FLOOD asserts flip (pool grows to
10105 / 20205) while setup + CONTROL stay green — clean directional split, both platforms. A 3-lens
adversarial review (`wf_1cf9021d-82d`) returned **0 blocking defects** and confirmed the sole insert
site is capped (no bypass), the honest non-flood path is unbroken, and the gate is non-vacuous.

## 5. Follow-up

The discovery sweep (`wf_1061bad6-1fc`) is exhausted for autonomous-safe gaps: both confirmed findings
(§3, §4) are closed; the reorg path, `on_block_sig` buffering (S-013 bounded), and
`from_json`/binary decode returned no confirmed gaps. The remaining owner-gated item on this surface
is **B3.4 source-side receipt authentication** (the complete fix for §4), plus the two rank-1 consensus
vulns already escalated from the RpcIngress register. Any consensus/accept-rule finding is owner-gated.
