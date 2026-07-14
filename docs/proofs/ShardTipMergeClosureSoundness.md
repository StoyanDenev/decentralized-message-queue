# ShardTipMergeClosureSoundness — the SHIPPED S-036 Layer-1 closure (D3.4 + D3.5 + D3.6 + D3.8): a source-signed `eligible_count`, an order-independent `t:` distress-record fold, F2-reconciled digest determinism, and a two-gate MERGE_EVENT fail-close that STRONGLY MITIGATES the fabricated-distress attack — but does NOT trustlessly close it

This is the soundness argument for the **shipped consensus half** of the S-036
closure — the D3.4…D3.8 rows of `ShardTipMergeDesign.md` §9 that
`ShardTipMergeSoundness.md` (STMS-1…STMS-7) explicitly deferred to *future work*
in its LIMITS section. That companion document proved the byte-neutral
**substrate** (the `ShardTipRecord` codec, the `t:`/`cc:` state-root leaves, the
bounded rings, snapshot inheritance). This document proves the machinery that
now **consumes** that substrate: the source-signed distress count, the on-chain
distress-record set + its apply-path fold, the F2-style reconciliation that makes
the folded set deterministic across a K-of-K committee, and the MERGE_EVENT
admission gate that reads the committed records to fail-close a fabricated
under-quorum window.

S-036 (`docs/SECURITY.md` §S-036) is the Beacon-fabricated `MERGE_EVENT` BEGIN
evidence-window flaw: a BEGIN's under-quorum justification was a self-asserted
`evidence_window_start: u64` that pointed at *no committed record*, so a captured
beacon could claim a false distress window for a healthy source shard
(`A_beacon_forge`) and dilute a committee via an illegitimate merge. The shipped
mechanism makes the claim verifiable against committed, committee-bound distress
records — and, where it cannot be made trustlessly verifiable, **fail-closes the
reachable attack path entirely**.

**The honest posture this document defends is STRONGLY MITIGATED, NOT CLOSED**
(§LIMITS). The reachable exploit — a `MERGE_EVENT` submitted on a shard, which is
where the apply path actually lives — is now uniformly rejected. The residual
trustless-closure gap (a BEACON re-verifying a *source* committee's signature over
the distress records) is unimplementable on the shipped substrate and is the
owner-gated Layer-2 work item (D3.5e). Do **not** read this document as flipping
S-036 to CLOSED.

**PROVEN-in-code** = enforced by shipped source at the cited `file:line` and
witnessed by a named green assertion. Every `file:line` below was mapped from the
current tree and independently re-verified against the source (refute-by-default)
before entering this document. No new crypto is introduced; every argument is
structural, reducing to the block-hash / K-of-K-digest binding (A2 SHA-256 +
A1 Ed25519 EUF-CMA, `Preliminaries.md` §2.0) already relied on chain-wide.

The implementation surface is: the `eligible_count` field + its three digest
mirrors (`src/chain/block.cpp:429-431` signing-bytes, `src/node/producer.cpp:796-798`
K-of-K digest, `light/verify.cpp:214-216` light mirror) and its emission gate
(`src/node/node.cpp:1149`, `:1166-1169`); the `shard_tip_records` set + its
`compute_view_root` binding (`src/node/producer.cpp:408-427`, `:808-813`;
`src/chain/block.cpp:439-441`, `:282-293`) and content-driven apply-fold
(`src/chain/chain.cpp:1805-1809`) with its reorg-safe lazy capture
(`:850-853`, `:734-735`); the F2 reconciliation — signed view fields
(`include/determ/node/producer.hpp:65-66`), the `DTM-STV-v1` commitment
(`src/node/producer.cpp:295-309`, `:317-322`; `src/node/validator.cpp:207-214`),
the split presence-gated view validation (`src/node/producer.cpp:489-544`), the
`build_body` intersection fold (`src/node/producer.cpp:1239-1251`) fed a per-round
frozen candidate snapshot (`src/node/node.cpp:1070`,
`include/determ/node/node.hpp:767-777`), and the validator enforcement
(`src/node/validator.cpp:1466-1502`); and the MERGE_EVENT fail-close at both the
block validator (`src/node/validator.cpp:857-939`) and mempool admission
(`src/node/node.cpp:2509-2515`). Pinning tests, all in the FAST set:
`test-eligible-count` (14 assertions), `test-shard-tip-records` (15),
`test-shard-tip-fold` (11), `test-contrib-wire-verify` (18),
`test-shardtip-reconciliation` (11), and the falsifier `test-s036-merge-witness`
(8), plus the live regressions `tools/test_under_quorum_merge.sh` and
`tools/test_current_multishard_byte_neutral.sh`. FAST is 227/0 both platforms.

---

## STMC-1 — SOURCE-SIGNED DISTRESS COUNT: `eligible_count` binds zero-skip into all three digest mirrors, so a captured beacon cannot fabricate a healthy/distressed count on a source block (D3.4)

**Claim.** A source shard's contemporaneous `eligible_in_region` count is carried
as `Block::eligible_count` and bound — zero-skip, `u64`-widened, as the last
scalar before the shard-tip root — into all three digest surfaces: the block hash
(`signing_bytes`), the K-of-K committee-signed `compute_block_digest`, and the
light-client mirror. Because the count enters the digest the source committee's
K-of-K signatures cover, a captured beacon cannot forge or alter the count on the
source block without invalidating those signatures. The zero value is the
unpopulated sentinel and is elided everywhere, so a block that carries no count is
byte-identical to a pre-D3.4 block.

**Argument.** `signing_bytes` appends `if (eligible_count != 0) { b.append(
static_cast<uint64_t>(eligible_count)); }` (`src/chain/block.cpp:429-431`), after
`signature_form` and before the shard-tip root, and `compute_hash` consumes
`signing_bytes` (`:447-448`) — so the count enters block-hash identity.
`compute_block_digest` — the digest the committee signs — applies the identical
zero-skip append (`src/node/producer.cpp:796-798`), and the light mirror
`light_compute_block_digest`, a documented verbatim copy kept in sync
(`light/verify.cpp:106`, `:214-216`), applies it again; the cross-binary parity
guard `tools/test_block_digest_xbinary_parity.sh` pins node↔light byte-parity with
an explicit `ELIGIBLE_COUNT` token at position 17 of 18 in both `PRODUCER_SEQ` and
`LIGHT_SEQ` (`:119-120`) and an `awk` classifier that fails on any unclassified
append (`:193`, `:196`). On the wire, `to_json` emits the key only when non-zero
(`src/chain/block.cpp:619-620`) and `from_json` fails **closed** — it throws on a
value `> 0xFFFFFFFF` rather than truncating a large count into a small
(spuriously-distressed) one (`:794-798`). Emission is the source committee's own
count: `Node::current_source_eligible_count` returns
`registry_.eligible_in_region(cfg_.committee_region).size()` only under
`chain_role == SHARD && sharding_mode == EXTENDED`, else `0`
(`src/node/node.cpp:1149`, `:1166-1169`), threaded into `build_body` at all three
producer call sites (`:1257`, `:1374`, `:2839`).

**Excluded failure.** A beacon substituting a healthy count for a distressed one
(or vice-versa) on a source block to manufacture or suppress a distress record —
defeated because the count is inside the source K-of-K-signed digest, not a
beacon-side field. (The complementary threat — a beacon *omitting* an entire
distress record — is defeated by STMC-5's uniform absent-record fail-close, not
here.) **Honest scope:** the source committee signs `eligible_count` as a
*liveness/determinism* count; that the beacon re-verifies the *source* committee's
identity at fold-in is a Layer-2 property, NOT claimed here — see §LIMITS and
`ShardTipMergeSoundness.md` STMS-LIMITS "no unforgeability claim".

**Witness.** `test-eligible-count` (14 assertions, `src/main.cpp:39664-39750`):
JSON elision at count 0 (`:39684`), absent-key→0, non-zero round-trip, `u32`-max
no-truncation (`:39690-39695`), the `2^32`/`2^40` range-guard rejects
(`:39708-39709`); block-hash zero-skip identity `count 0 == pre-D3.4`
(`:39719`) and distinctness `count 0 != count 3` (`:39717`); digest zero-skip
identity (`:39723`) and forged-count digest change (`:39732-39734`).

## STMC-2 — DISTRESS-RECORD SET → `t:` FOLD: an order-independent `compute_view_root` binding + a content-driven apply-fold that binds `state_root` before the S-033 recompute, reorg-safe (D3.5a + D3.5b)

**Claim.** `Block::shard_tip_records` is bound as **one** order-independent root
(a dedup-sorted `std::set<Hash>` over per-record `hash_shard_tip = SHA256(encode)`,
rolled into a single SHA-256 == `compute_view_root`), appended empty-skip and last
in all three digest mirrors; its JSON round-trip is fail-closed; and
`apply_transactions` folds the set into the `t:` state namespace (STMS-2/STMS-3
ring) **before** the S-033 `state_root` recompute, content-driven (no
`shard_count_` gate), so an empty set is byte-identical and a non-empty set binds
into `state_root`. The fold is A4-reorg-safe.

**Argument.** `hash_shard_tip` is `SHA256(r.encode())`
(`src/node/producer.cpp:408-413`) and `compute_view_root` builds a
`std::set<Hash>` then a rolling SHA-256 (`:422-427`), so the root is a pure
function of the record *set*, insertion-order-independent. It is appended
empty-skip and last in `compute_block_digest` (`:808-813`), in the light mirror
(`light/verify.cpp:223-228`), and in `signing_bytes` via the `shard_tip_records_root`
replica (`src/chain/block.cpp:439-441`, `:282-293`). `to_json` elides an empty
set and hex-encodes each record's canonical `encode()` (`:623-630`); `from_json`
throws on any undecodable record hex rather than silently dropping it (`:802-808`).
`apply_transactions` folds `if (!b.shard_tip_records.empty()) { … add_shard_tip_record(rec); }`
(`src/chain/chain.cpp:1805-1809`) — guarded **only** by non-emptiness, no
`shard_count_` gate — and the S-033 recompute `if (b.state_root != zero) { computed
= compute_state_root(); if (computed != b.state_root) throw; }` runs *after* it
(`:1849-1865`, 1805 < 1849), so the new `t:` leaves bind into the declared
`state_root`. Reorg-safety: the lazy-capture twin `__ensure_shard_tip_records`
snapshots the pre-fold map exactly once, invoked inside the fold guard
(`:850-853`, `:1806`), and `restore_state_snapshot` move-restores it only when
`Some` (`:734-735`) — so a non-mutating block pays no snapshot copy and an A4
`revert_head` / failed-apply rolls the ring back exactly (discharging the
STMS-7 "dormant forward-safety substrate" into an active, witnessed path).

**Excluded failure.** A per-node `state_root` divergence from insertion-order
sensitivity or an unstable record encoding (the S-047-class fork STMS-2 warned of),
a silently-dropped malformed record on the JSON path, or a reverted-block distress
record leaking into H-1 state after a reorg.

**Witness.** `test-shard-tip-records` (15 assertions, `src/main.cpp:39751-39857`):
order-independence over digest (`:39825`) and block hash (`:39827`), empty-skip
identity (`:39811`/`:39815`), per-mirror binding (`:39809`/`:39813`),
fail-closed malformed-hex decode (`:39801`), tamper breaks both bindings
(`:39837`/`:39839`/`:39843`). `test-shard-tip-fold` (11 assertions,
`:11824-11946`): content-driven SINGLE-chain fold (`:11880`/`:11882`), empty-set
byte-neutral `state_root` (`:11892-11894`), a folded record changes `state_root`
(`:11902`), `Chain::load` replay re-folds identically (`:11920`/`:11922`), and
the reorg block — `revert_head` rolls the fold back to the empty pre-fold ring
(`:11934`) and re-append re-folds an identical record + `state_root` (`:11937`).

## STMC-3 — RECONCILIATION DETERMINISM (anti-S-047): the folded set is the full-K committee-view intersection over a per-round frozen candidate snapshot, with an S-043-symmetric signed view (D3.5d/c)

**Claim.** The distress records a producer folds are exactly
`reconcile_intersection(committee views) ∩ round_shard_tip_candidates_`, computed
over a candidate set **frozen once per round**, using the **full-K** intersection
(never a threshold). Because every co-creator signs the same Phase-1 view and folds
the same frozen candidates, all K producers compute a byte-identical
`shard_tip_records` set and hence a byte-identical digest — so the distress path
cannot wedge (the S-047 class). The signed Phase-1 view is authenticated with
S-043 symmetry.

**Argument.** *Signed view (S-043 symmetry).* `ContribMsg` carries
`view_shardtip_root` + `view_shardtip_list` (`include/determ/node/producer.hpp:65-66`),
emitted behind their own gate (`src/node/producer.cpp:73-78`).
`make_contrib_commitment` binds the root **only when non-zero**, behind its own
`DTM-STV-v1` domain tag, appended **after** the `DTM-TS-v1` proposer-time tail
(`:295-309`) — so every non-shard-tip / pre-D3.5 contrib keeps a byte-identical
commitment. The msg-form overload forwards `m.view_shardtip_root` (`:317-322`) and
the validator field-form recompute passes `vr_at(b.creator_view_shardtip_roots, i)`
as the trailing arg before `verify()` (`src/node/validator.cpp:207-214`) — the
explicit verifier edit that a defaulted trailing param would otherwise silently
break (the S-043 discipline). `validate_contrib_view_roots` is split into two
**independent presence-gated groups** — the F2 group (skipped when `f2_absent`,
`:489-495`) and the shard-tip group (skipped when `st_absent`, enforcing the V21
cap + V25 `compute_view_root(list) == root`, `:533-544`) — because
`compute_view_root([])` is a non-zero empty root, so a combined early-out would
false-reject a shard-tip-only contrib. *Deterministic fold.* `build_body` computes
`st_intersection = reconcile_intersection(b.creator_view_shardtip_lists)` and folds
each candidate that is both in the intersection and not already committed
(`src/node/producer.cpp:1239-1251`). *S-047 fix.* The candidate set is frozen once
at Phase-1 (`round_shard_tip_candidates_ = shard_tip_records_eligible_for_inclusion()`,
`src/node/node.cpp:1070`) and reused at all three `build_body` sites (`:1258`,
`:1375`, `:2840`), because `pending_shard_tip_records_` is pruned asynchronously
mid-round by `on_shard_tip`'s staleness window (`:1951-1962`) — reading it live at
each build site could drop a Phase-1-committed record from one co-creator's set and
diverge the digest. The frozen snapshot ⊇ the intersection structurally, so every
co-signer folds the identical full intersection. The `committee_sig_root` inside
each record is itself a deterministic pure function of the validated tip (binds the
K-of-K sig set order-independently, binds `source_shard_id`), so identical inputs
give an identical root across nodes.

**Excluded failure.** A CONFIRMED-HIGH S-047 liveness wedge (the review catch):
divergent per-creator `shard_tip_records` → the K-of-K digest never gathers → the
round stalls on the distress path. Frozen-candidate + full-K intersection is the
structural guarantee that every honest co-signer materializes the same set.

**Witness.** `test-contrib-wire-verify` (18 assertions, `src/main.cpp:45497-45651`):
both view keys on the wire + round-trip (`:45609-45614`), the `DTM-STV-v1` tail is
load-bearing — msg-form verifies (`:45617`), the pre-D3.5 8-arg recompute is
REJECTED (`:45625`), transit-tamper rejected (`:45631`) — and byte-neutrality of a
non-shard-tip contrib (`:45641`), plus the split-validate accept/reject
(`:45645`/`:45649`). `test-shardtip-reconciliation` (11 assertions,
`:11663-11821`): unanimous folds the full 3/3 intersection (`:11745`), a record
missing from one member's view is excluded — full-K, never a threshold (`:11754`),
no candidates folds nothing (`:11762`), one empty view empties the intersection —
fail-closed (`:11770`), and four `committee_sig_root` pure-function assertions
(`:11806-11814`).

## STMC-4 — VALIDATOR ENFORCEMENT + THE NON-EXTENDED SELF-HALT GUARD: the reconciliation check is EXTENDED-gated and its non-EXTENDED branch guards ONLY the record set, never the outer view vectors (D3.5d-ii)

**Claim.** `check_shardtip_reconciliation` re-derives the committee-view
intersection and rejects any block whose `shard_tip_records` is not a subset of it,
under `sharding_mode_ == EXTENDED`. Its non-EXTENDED branch guards **only**
`b.shard_tip_records` (the record set), never the outer `creator_view_shardtip_*`
vectors — because `build_body` unconditionally pushes one zero entry per creator
into those outer vectors, so an outer `.empty()` test would reject block 1 on every
SINGLE/CURRENT chain (the producer self-applies its in-memory body before `to_json`
strips the zero entries).

**Argument.** The check is wired into `check_transactions`
(`src/node/validator.cpp:55`). The non-EXTENDED branch is exactly `if (sharding_mode_
!= ShardingMode::EXTENDED) { if (!b.shard_tip_records.empty()) return {false, …};
return {true, ""}; }` (`:1466-1470`) — it inspects only the record set, with an
inline warning (`:1459-1465`) never to guard the outer vectors. The EXTENDED branch
then enforces `creator_view_shardtip_lists.size() == creators.size()` (`:1478-1479`),
authenticates each list against its signed root with a zero-root v1 sentinel
(`:1480-1494`), and rejects any committed record not in
`reconcile_intersection(b.creator_view_shardtip_lists)` (`:1496-1501`) — the same
full-K intersection the producer folded (STMC-3), so producer and validator share
`reconcile_intersection` + `hash_shard_tip` and a well-formed block always
validates while a fabricated-record block fails closed.

**Excluded failure.** A CRITICAL self-halt (the design-pass catch): a naive
non-EXTENDED guard testing the outer `creator_view_*` vectors would reject block 1
on *every* SINGLE/CURRENT chain — a total-liveness outage invisible to an
EXTENDED-only test plan. Mirrors the shipped `check_inbound_receipts`, which guards
only `b.inbound_receipts`.

**Witness.** `test-shardtip-reconciliation` (`src/main.cpp:11748-11771`): the
full-K exclusion + empty-view-empties-intersection assertions exercise the exact
predicate the EXTENDED branch enforces (`validator.cpp:1496-1501`); the
non-EXTENDED self-halt guard is covered live by every SINGLE/CURRENT FAST cluster
remaining green (a 3-node CURRENT cluster produces, self-applies, and agrees with
no fork — `tools/test_current_multishard_byte_neutral.sh`).

## STMC-5 — TWO-GATE MERGE_EVENT FAIL-CLOSE: the reachable attack path is rejected at both mempool admission and block validation; on a BEACON, a BEGIN requires contiguous sub-2K committed distress over the source-height window (D3.6 + D3.8)

**Claim.** A `MERGE_EVENT` is rejected on every non-`BEACON` chain and on a
`BEACON` that is not `EXTENDED`, at **both** the block validator and mempool
admission (matching gates), so the tx never enters the pool and never stalls the
chain. On a `BEACON+EXTENDED` chain a BEGIN is admitted only when the committed
`t:` records prove **contiguous sub-2K** distress across the **source-shard-height**
window `[evidence_window_start, evidence_window_start + merge_threshold_blocks)`;
the check is uniform-fail-closed on `threshold == 0`, a `u64`-overflowing terminus,
any absent in-window record (`A_beacon_omit`, which also covers a window predating
the retained ring), and any in-window record attesting health
(`eligible_count >= 2·k_block_sigs`).

**Argument.** *Block validator* (`src/node/validator.cpp:830-939`): the
`MERGE_EVENT` case fail-closes `if (chain_role_ != ChainRole::BEACON) return
{false, "… a shard cannot verify the historical distress witness"}` (`:857-861`)
and `if (sharding_mode_ != ShardingMode::EXTENDED) return {false, "… requires
sharding_mode=extended"}` (`:862-865`). For a BEGIN (`:893`) it rejects
`threshold == 0` (`:910-913`), guards `evidence_window_start + threshold` overflow
(`:917-921`), and walks `for (uint64_t h = evidence_window_start; h <
evidence_window_start + threshold; ++h)` (`:922-925`) over `chain.shard_tip_records()`,
rejecting an absent record `recs.find({ev->shard_id, h}) == end()` (`:926-933`,
`A_beacon_omit`) or a healthy one `it->second.eligible_count >= k2` where `k2 =
2·k_block_sigs_` (`:934-939`). The window is indexed in **source-shard height**;
the old `evidence_window_start ≤ b.index` beacon-height bound was an axis bug
(shards outrun the beacon) and is explicitly retired (`:905-909`). *Mempool*
(`src/node/node.cpp:2509-2515`): `mempool_admit_check` rejects a `MERGE_EVENT`
unless `chain_role == BEACON && sharding_mode == EXTENDED` — logically identical to
the two validator gates — on both the gossip `on_tx` (`:2589`) and RPC
`rpc_submit_tx` (`:4201`) channels. This second gate is load-bearing for
*liveness*: block validation rejects the *block*, not the pooled tx, so without the
mempool gate a queued-but-block-invalid `MERGE_EVENT` would be re-included every
round and stall production (the same class as uncontrolled REGION_CHANGE/PARAM_CHANGE
rejects).

**Excluded failure.** `A_beacon_forge` on the reachable path — a shard-submitted
`MERGE_EVENT` fabricating an under-quorum window — now rejected up-front;
`A_beacon_omit` — a BEGIN whose window has a gap in the committed distress record —
rejected; and the chain-stall class the block-only reject would have caused.

**Witness.** `test-s036-merge-witness` (8 assertions, `src/main.cpp:11527-11661`)
via the read-only `check_transactions_for_test` seam (STMC-7): A a genuine
contiguous sub-2K distress ACCEPTED; B1 no-records / B2 gap / B3 healthy-≥2K /
B4 pre-ring-pruned / B5 threshold==0 all REJECTED; C a non-`BEACON` (SHARD) chain
REJECTED (`:11642-11648`, directly falsifying the `:857` gate); A2 deterministic.
The `BEACON+non-EXTENDED` reject (`:862`) is not among the eight scenarios (all
B-cases are `BEACON+EXTENDED` to reach the witness loop, C is `SHARD+EXTENDED`) — it
is covered by the matching mempool gate. Live: `tools/test_under_quorum_merge.sh`
(4-node SHARD+EXTENDED cluster) submits a MERGE_BEGIN, asserts `merge_state` stays
empty (`MERGE_COUNT == 0`) and the chain advances past the submit (no stall).

## STMC-6 — BYTE-NEUTRALITY (the RP-4 gate discipline): every byte-affecting gate keys on `sharding_mode == EXTENDED`, so SINGLE / CURRENT-multishard / healthy-EXTENDED blocks are byte-identical

**Claim.** Every byte-affecting gate in the D3.4–D3.8 arc keys on
`sharding_mode == EXTENDED` (validator `sharding_mode_`, node `cfg_.sharding_mode`),
**never** on `shard_count() > 1` — because `ShardingMode::CURRENT` is a shipped
multi-shard mode (`PROFILE_REGIONAL` = SHARD+CURRENT, `shard_count > 1`). Every new
field uses a zero-skip or empty-skip conditional across all four identity surfaces
(block hash, K-of-K digest, JSON, `state_root`), so a SINGLE, a CURRENT-multishard,
or a *healthy* EXTENDED block is byte-identical to the pre-D3 encoding.

**Argument.** The EXTENDED-keyed byte-affecting gates: `current_source_eligible_count`
(`src/node/node.cpp:1166-1167`), `shard_tip_records_eligible_for_inclusion`
(`:1177-1178`), the `on_shard_tip` fold (`:1925`), the mempool MERGE_EVENT gate
(`:2509-2511`), the validator reconciliation branch
(`src/node/validator.cpp:1466`), and the MERGE_EVENT `sharding_mode` reject
(`:862`). The one byte-affecting gate that *textually* mentions `shard_count` — the
chain-layer `cc:` committee-checkpoint fold (`src/chain/chain.cpp:1830-1831`) — is
co-gated by `epoch_blocks_ > 0`, and the node hands `Chain` a non-zero epoch length
**only** under EXTENDED: `chain_epoch_blocks = (sharding_mode == EXTENDED) ?
cfg_.epoch_blocks : 0` (`src/node/node.cpp:484-485`, set at `:486-488`, `:499`,
`:568`), so a CURRENT chain keeps `epoch_blocks_ == 0` and the fold is inert. (The
sole `shard_count() > 1` *read* gate, `committee_pin_active` in
`src/node/committee_pool.cpp:7-10`, is non-byte-affecting: the checkpoint map is
empty under CURRENT, so it falls back to present-head selection.) Each new field is
conditional: `eligible_count` zero-skip in hash/digest/JSON
(`src/chain/block.cpp:429-431`, `src/node/producer.cpp:796-798`,
`src/chain/block.cpp:619-620`), `shard_tip_records` empty-skip in hash/digest/JSON/fold
(`:439-441`, `src/node/producer.cpp:808-813`, `src/chain/block.cpp:623-630`,
`src/chain/chain.cpp:1805-1808`), and the outer `creator_view_shardtip_*` vectors
behind an any-non-zero-root gate (`src/chain/block.cpp:538-540`).

**Excluded failure.** The RP-4 hazard: a byte-affecting field wrongly gated on
`shard_count() > 1` would break byte-neutrality on a CURRENT-multishard
(PROFILE_REGIONAL) chain and hard-fork a regional upgrade — the exact bug class the
D3.4 review caught and this discipline forbids.

**Witness.** `tools/test_current_multishard_byte_neutral.sh` (live 3-node
CURRENT+SHARD cluster, `initial_shard_count=3`, `epoch_blocks=4`, crossing an epoch
boundary): asserts no block carries `eligible_count` (`:146-160`) and all three
nodes agree on a settled block (`:163-185`) — RED pre-fix, GREEN after. The EXTENDED
twin `tools/test_extended_epoch_committee.sh` confirms the *only* difference is the
`sharding_mode == EXTENDED` handoff, not `shard_count`. `run_all.sh` FAST includes
`shardtip_reconciliation` + `s036_merge_witness` (`:107-108`); FAST is 227/0 both
platforms with every SINGLE/CURRENT golden byte-identical.

## STMC-7 — THE FALSIFIER SEAM: `test-s036-merge-witness` drives the real block-validator transaction check through a read-only const seam, with no production caller (D3.7)

**Claim.** `check_transactions_for_test` is a `const`, read-only seam that forwards
directly to the private `check_transactions` the block validator already runs (no
consensus-behaviour change), called **only** by the falsifier subcommand and never
on any production path — so the D3.6 beacon witness loop, otherwise dormant (no
beacon merge emitter exists), is exercised in isolation.

**Argument.** `include/determ/node/validator.hpp:72-75` defines
`Result check_transactions_for_test(...) const { return check_transactions(b,
chain, registry); }`. A tree-wide grep resolves the identifier to exactly two
source occurrences — the definition and the single call at `src/main.cpp:11598`
inside `test-s036-merge-witness` (the only other hit is a `docs/UNIT-TESTS.md`
mention, not a caller). No `node.cpp`/consensus caller exists, so production never
invokes the seam and FAST is unchanged by its presence.

**Excluded failure.** A test-only accessor silently altering the validated path,
or an unexercised (untested) fail-close branch shipping as dead code. The seam is a
pure forwarder and the eight scenarios drive every arm of the BEGIN witness loop.

**Witness.** The `test-s036-merge-witness` subcommand itself (STMC-5), constructing
a genesis `BEACON+EXTENDED` validator (`k=2 ⇒ 2K=4`), injecting `t:` records via the
public `add_shard_tip_record`, and driving one signed MERGE_BEGIN through
`check_transactions_for_test` per scenario.

---

## LIMITS — what this argument does NOT cover (S-036 is STRONGLY MITIGATED, not CLOSED)

- **This proves a STRONG MITIGATION, NOT a trustless closure.** The *reachable*
  attack — a `MERGE_EVENT` submitted on a shard (where the apply path lives, gated
  `shard_count() > 1`, not chain role) — is fail-closed at both mempool and block
  validation (STMC-5). But full trustless closure requires a BEACON to verify that
  the committed distress records were signed by the genuine *source* committee, and
  that is **not** dischargeable on the shipped substrate.
- **The beacon witness path is DORMANT.** The D3.6 BEGIN witness loop
  (`validator.cpp:922-939`) reads committed `t:` records, but no beacon merge-flow
  *emitter* exists — a BEACON never actually produces a `MERGE_EVENT` in the shipped
  code. STMC-5's beacon-side loop is proven correct and falsified in isolation
  (STMC-7), but it does not run on any live path today. Its live value is the
  fail-close (a fabricated merge is rejected wherever submitted), not an active
  verified-merge flow.
- **No source-committee re-verification at fold-in.** `on_shard_tip` builds a
  distress record from the beacon's OWN present-head registry and per-chain
  suspension state; the beacon's `committee_checkpoints_` (`cc:`) hold the BEACON
  committee, and beacon genesis pins no per-source-shard `K_0^s` trust root. So the
  beacon cannot trustlessly re-derive a *source* committee at a past height — the
  contemporaneous-honest-majority-beacon trust assumption of
  `[[determ-retroactive-committee-rederivation]]` (`ShardTipMergeDesign.md` §8/§8.1,
  `src/node/registry.cpp` `build_from_chain` reads present-head caches). STMC-1's
  `eligible_count` unforgeability is scoped to the *source block's* K-of-K digest,
  NOT to a beacon re-check of source identity.
- **Trustless closure is the Layer-2 work item (D3.5e) — UNDERWAY (2026-07-14).**
  **The migration framing above is SUPERSEDED:** the owner ruled the network launches
  only after the full design of all layers + DApps is complete, so genesis-format
  changes are ordinary pre-launch design work, not a migration; and a code-grounded
  design Workflow replaced the old `sc:`-transport + `K_0^s` sketch with a **BEACON-SIDE
  FREEZE** — the shard-tip verdict becomes a pure function of committed BEACON state
  (frozen `cc:[shard_epoch]` pool + genesis-committed region map + committed epoch rand
  + frozen ed_pubs), NO cross-chain protocol and NO per-shard trust root (see
  `ShardTipMergeDesign.md` §9.6, rewritten). **Shipped so far, all byte-neutral, FAST
  228/0 both platforms:** D3.5e-1 genesis-committed `beacon_shard_regions` map
  (`e488a73`); D3.5e-2 the map authoritative at beacon load (`97d4236`); D3.5e-3 the
  shard-side epoch-rand off-by-one seam repair (`c319ce5`); D3.5e-4 the `on_shard_tip`
  verdict pin onto frozen committed state (`80d3d97`). **Remaining:** e-5 the first live
  gate (a beacon verifying a shard tip across an epoch boundary — the empirical
  validation of e-3+e-4), e-6 `source_shard_id` digest binding, e-7 the witness-carrying
  fold re-verification (the actual CLOSED-maker: every honest full node re-verifies each
  folded record against committed `cc:` state on gossip-apply) + auditor CLI, e-8 the
  flip. Until e-8, `docs/SECURITY.md` §S-036 stays **STRONGLY MITIGATED**; do not flip it
  to CLOSED on this document.
- **`revert_threshold_blocks` ring depth vs. window.** STMC-5's fail-close on a
  window predating the retained ring is *correct* (an unprovable window is rejected),
  but this document does not argue that the ring depth (default 200) *suffices* to
  cover any particular legitimate merge window — that window+grace ≤ ring-depth
  budget is a deployment-tuning obligation, not a soundness property proven here.
- **Byte-neutrality is scoped to non-EXTENDED + healthy EXTENDED.** A *distressed*
  MULTI-shard EXTENDED chain legitimately accrues `t:` leaves and `eligible_count`
  fields, so its `state_root`/digest sequence differs from a pre-D3 chain by design;
  the hard byte-neutrality guarantee (STMC-6) is scoped to SINGLE, CURRENT-multishard,
  and healthy EXTENDED blocks — exactly the configurations every live chain runs
  today.

---

## Cross-references

- `ShardTipMergeSoundness.md` (STMS-1…STMS-7) — the byte-neutral **substrate** this
  document's consensus half consumes; STMC-2 discharges STMS-7's dormant
  atomic-apply-rollback substrate into an active witnessed path, and STMC-1 is the
  D3.4 field STMS-LIMITS deferred.
- `ShardTipMergeDesign.md` — the design + mechanism decision (§9 increment plan,
  §9.2/RP-4 the `sharding_mode == EXTENDED` gate discipline, §9.6 the Layer-1/Layer-2
  split and the retired §3.5 liveness-beacon aspiration).
- `S036UnderQuorumMerge.md` — the original R7 under-quorum-merge composition (T-1…T-5);
  its §1.4 MergeMonitor-FSM / `validate_merge_event_historical` FSM-replay design is
  **SUPERSEDED** — the as-built D3.6 reads committed `t:` records with no FSM.
- `[[determ-retroactive-committee-rederivation]]` — why a beacon cannot trustlessly
  re-derive a source committee at a past height, hence why closure needs the Layer-2
  `K_0^s` migration.
- `RoundStateRetrySoundness.md` / the S-047 wedge class — STMC-3's per-round frozen
  candidate snapshot is the shard-tip analogue of the S-047 rebroadcast fix.
- `TimestampReconciliationSoundness.md` — the F2 `DTM-TS-v1` proposer-time
  precedent whose `DTM-STV-v1` sibling STMC-3 binds (shared S-043 wire-verify
  discipline; `test-contrib-wire-verify` 18 assertions).
- `docs/SECURITY.md` §S-036 — the STRONGLY-MITIGATED entry this document's STMC-5
  fail-close discharges on the reachable path; Layer-2 D3.5e remains the CLOSED path.
