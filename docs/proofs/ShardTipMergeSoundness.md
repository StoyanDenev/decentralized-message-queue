# ShardTipMergeSoundness — the SHIPPED byte-neutral S-036 substrate (D3.1 + D3.2 + D3.3a): a codec bijection, deterministic `t:`/`cc:` state-root leaves, bounded rings, snapshot inheritance, and zero-leaf byte-neutrality on every non-EXTENDED chain

This is the soundness argument for the **shipped byte-neutral substrate** of the
S-036 closure (design `docs/proofs/ShardTipMergeDesign.md` §9 + §9.2; the D3.1 +
D3.2 + D3.3a rows of the §9 revised increment plan). S-036 is the
Beacon-fabricated `MERGE_EVENT` BEGIN evidence-window flaw
(`docs/SECURITY.md:1484`): a BEGIN's under-quorum justification is a self-asserted
`evidence_window_start: u64` that points at *no committed record*, so a captured
beacon can claim a false distress window for a healthy source shard
(`A_beacon_forge`). D3 closes it by committing the per-height distress
attestations and the per-epoch committee sets on-chain, so the claim becomes
verifiable. **This document scopes ONLY the three shipped, byte-neutral,
non-consensus pieces of that program**: the `ShardTipRecord` codec (D3.1), the
`t:` distress-record state namespace + bounded ring (D3.2), and the `cc:` epoch
committee-checkpoint substrate (D3.3a). It proves that these pieces are correct,
deterministic, bounded, snapshot-faithful, and — the load-bearing property — a
**strict no-op on every chain that never populates them** (which today is *every*
chain: the producers/validators that write these rings, D3.3b…D3.7, are not yet
built — see LIMITS). The implementation surface is:
`ShardTipRecord` + `ShardTipRecord::encode`/`decode`
(`include/determ/chain/block.hpp:437-451`, `src/chain/block.cpp:203-233`);
`Chain::shard_tip_records_` / `ShardTipRecordMap` / `add_shard_tip_record` and
`Chain::committee_checkpoints_` / `EpochCommitteeCheckpoint` / `CommitteeMember` /
`add_committee_checkpoint` / `kCommitteeCheckpointRing`
(`include/determ/chain/chain.hpp:386-422`, `:781`, `:786`, `:880-881`;
`src/chain/chain.cpp:268-296`); the `t:` / `cc:` leaf emission in
`build_state_leaves` (`src/chain/chain.cpp:400-442`); the `serialize_state`
persist + `restore_from_snapshot` restore for both rings
(`src/chain/chain.cpp:2057-2092`, `:2264-2296`); and the `StateSnapshot`
optional fields consumed by `restore_state_snapshot`
(`src/chain/chain.cpp:734-737`). Pinning tests, all in the FAST set:
`test-shard-tip-record` (`src/main.cpp:10987-11087`, 9 assertions),
`test-shard-tip-namespace` (`src/main.cpp:11090-11221`, 6 assertions),
`test-committee-checkpoint` (`src/main.cpp:11224-11358`, 6 assertions). FAST rose
+1 per increment (218 → 219 → 220, both platforms) with every pre-existing
state-root and snapshot golden byte-identical (`ShardTipMergeDesign.md:459-461`).

**PROVEN-in-code** = enforced by shipped source at the cited `file:line` and
witnessed by a named green assertion. No new crypto is introduced anywhere in
this substrate; every argument below is structural. The consensus half that
*consumes* this substrate (D3.3b…D3.7) is future work whose soundness is
explicitly NOT claimed here (LIMITS).

---

## STMS-1 — CODEC BIJECTION + GATE SOUNDNESS: `ShardTipRecord` encode↔decode is exact and rejects every malformed input (D3.1)

**Claim.** For every valid record (`region.size() ≤ 32`),
`decode(encode(r)) == r` field-for-field; the encoding is a fixed 49-byte base
plus the `region_len`-byte region; and `decode` returns `nullopt` on any buffer
that is short, claims `region_len > 32`, or whose total size disagrees with the
declared `region_len` — the exact-trailing-byte discipline of `MergeEvent::decode`.

**Argument.** `encode` (`src/chain/block.cpp:203-216`) writes a
length-fixed prefix — `source_shard_id` (4 LE), `height` (8 LE), `eligible_count`
(4 LE), `committee_sig_root` (32) — then a single `region_len` byte
(`:213`) and the region bytes (`:214`). The base is exactly `4+8+4+32+1 = 49`
bytes, matching the `reserve(49 + region.size())` (`:205`). `decode`
(`src/chain/block.cpp:218-233`) is the inverse over the identical field layout
and, being a same-file helper, cannot drift from the encoder (the §3.1 "one
byte-counting definition" discipline, `block.hpp:434-436`). Three gates precede
any field read and make decode a *partial* inverse that is total on valid inputs
and empty elsewhere: `p.size() < 49 → nullopt` (`:219`), `p[48] > 32 → nullopt`
(`:220-221`, the region-length rule), and `p.size() != 49 + region_len → nullopt`
(`:222`, the exact-trailing-byte gate — no stray suffix, no truncation). Past the
gates the reads are within-bounds by construction (`region_len ≤ 32` and
`size == 49 + region_len`), so the field copies at `:224-231` reconstruct each
value bit-exactly; endianness is fixed LE on both sides. Injectivity of `encode`
follows because the fields fully determine the bytes and the single-byte
`region_len` prefix makes the region boundary unambiguous.

**Excluded failure.** A malformed or adversarially-padded record that decodes to
a *different* record than it encodes (silent field corruption), or a
region-length overrun reading past the buffer — the classic length-prefix parser
bug. No semantic check (window/partner/attestation validity) is claimed here;
those are deliberately left to the caller, exactly as `MergeEvent::decode`
defers partner/window checks (`block.hpp:446-449`).

**Witness.** `test-shard-tip-record` (9 assertions, `src/main.cpp:10987-11087`):
encode size `== 49 + region_len` (`:11020`); full-field round-trip (`:11024`);
empty-region exactly 49 bytes + round-trips (`:11033`, `:11035`); all-`0xFF`
fields + 32-byte region round-trip with no truncation (`:11045`); deterministic
encode (`:11053`); and the three reject gates — short buffer (`:11060`),
`region_len = 33` (`:11070`), and one stray trailing byte (`:11079`).

## STMS-2 — `t:` STATE-ROOT DETERMINISM: identical record sets ⇒ identical `state_root`, order-independent

**Claim.** Two chains holding the same *set* of `ShardTipRecord`s produce the
identical `state_root`, regardless of the order in which the records were
inserted; the `t:` leaf value is a length-prefixed SHA256 over
(`eligible_count`, `region`, `committee_sig_root`).

**Argument.** `shard_tip_records_` is a
`std::map<std::pair<ShardId,uint64_t>, ShardTipRecord>`
(`include/determ/chain/chain.hpp:386`, `:781`) keyed by `(source_shard_id,
height)`, so iteration order is the map's total key order — independent of
insertion order. `build_state_leaves` iterates that map (`src/chain/chain.cpp:405`)
and, per record, emits a leaf whose **key** is `"t:" ‖ source_shard_id_be4 ‖
height_be8` (`:406-412`, big-endian, so the state-namespace key order matches the
map key order) and whose **value** is `SHA256(eligible_count_u64 ‖
len(region)_u64 ‖ region ‖ committee_sig_root)` (`:413-418`) — a length-prefixed
digest with no ambiguous concatenation boundary. Because the key set, the
per-key value, and the iteration order are each a pure function of the record set
alone, the leaf multiset (and hence the Merkle `state_root` built over it) is a
pure function of that set. Two nodes that folded in the same records — in any
order — compute byte-identical roots.

**Excluded failure.** A per-node `state_root` divergence from insertion-order
sensitivity or an unstable leaf encoding — the class that would fork honest
validators once D3.5 starts committing these records, and the reason the design
mirrors the `i:` receipt-dedup pattern verbatim (`ShardTipMergeDesign.md:106-107`,
`CrossShardReceiptDedup.md`).

**Witness.** `test-shard-tip-namespace`: the order-independence assertion inserts
the same three records in forward vs reverse order across two fresh chains and
asserts equal size and equal `compute_state_root()`
(`src/main.cpp:11148-11160`); the non-vacuity assertion confirms a record is
actually *bound* (adding one changes the root, `:11137-11143`).

## STMS-3 — `t:` BOUNDED RING: ≤ `revert_threshold_blocks` records per source shard, lowest-height pruned, other shards untouched

**Claim.** `add_shard_tip_record` retains at most `revert_threshold_blocks`
records per source shard; on overflow it deterministically drops that shard's
lowest-height record; records of other shards are never affected.

**Argument.** `add_shard_tip_record` (`src/chain/chain.cpp:268-282`) inserts the
record under its own `(source_shard_id, height)` key (`:270`), then counts only
that shard's records via the contiguous key range
`[lower_bound({s,0}), first key with a different shard)` (`:274-276`) — sound
because the map's lexicographic `(shard, height)` order groups a shard's records
contiguously and orders them by ascending height. While the count exceeds the
bound (`revert_threshold_blocks`, or 1 if that scalar is 0, `:272`) it erases
`lower_bound({s,0})` (`:278-279`) — that shard's *lowest* height, the oldest
record — and decrements. The prune touches only keys with first component `s`, so
every other shard's ring is invariant; and because the erase target is a pure
function of the committed map, all nodes prune identically (`:266-267`).

**Excluded failure.** Unbounded `t:`-namespace state growth (a state-bloat DoS),
or a nondeterministic/ cross-shard prune that would diverge `state_root` between
nodes.

**Witness.** `test-shard-tip-namespace` ring assertion: with
`set_revert_threshold_blocks(3)`, five records for shard 7 (heights 10–14) plus
one for shard 9 leave shard 7 pruned to its three highest heights {12,13,14}
(10 and 11 gone) and shard 9 untouched — a per-shard bound
(`src/main.cpp:11163-11181`).

## STMS-4 — `cc:` COMMITTEE-CHECKPOINT DETERMINISM + BOUNDED RING (D3.3a): member-order-independent leaf, 16-epoch bound, seed recomputable from the checkpoint alone

**Claim.** The `cc:` epoch committee-checkpoint is epoch-keyed; its leaf hash is
independent of the order in which the caller supplied the members
(`add_committee_checkpoint` canonicalizes them domain-sorted); the ring retains
at most `kCommitteeCheckpointRing = 16` epochs; and each checkpoint carries
`epoch_rand` so the committee seed is recomputable without the anchor header.

**Argument.** `committee_checkpoints_` is a
`std::map<EpochIndex, EpochCommitteeCheckpoint>`
(`include/determ/chain/chain.hpp:414`, `:786`), epoch-sorted. On insert,
`add_committee_checkpoint` (`src/chain/chain.cpp:288-296`) first `std::sort`s the
members by `domain` (`:289-292`), so the stored member vector is canonical
regardless of assembly order, then stores under `epoch` (`:293`) and prunes from
the map's lowest epoch while `size() > kCommitteeCheckpointRing` (`:294-295`,
constant `= 16` at `chain.hpp:422`). `build_state_leaves` emits one leaf per
epoch: key `"cc:" ‖ epoch_be8` (`src/chain/chain.cpp:426-430`) and value
`SHA256(epoch_rand ‖ len(members)_u64 ‖ (len(domain)_u64 ‖ domain ‖ ed_pub ‖
len(region)_u64 ‖ region)*)` (`:431-440`) — every field length-prefixed, and the
member iteration order is the canonical domain-sorted order, so the value is a
pure function of the *set* of members. `epoch_rand` is a stored field of the
checkpoint (`chain.hpp:411`) and is folded into the leaf (`:432`), which is the
substrate property that lets a snapshot-bootstrapped node — which keeps only the
tail-16 block headers and so lacks the epoch's rand-anchor header — still recover
the committee seed (`chain.hpp:400-402`). The prefix is `cc:` (not `c:`) to avoid
colliding with the A1 counter namespace `k:c:…` (`ShardTipMergeDesign.md:497-500`).

**Excluded failure.** A member-order-sensitive or seed-dropping checkpoint hash
that would (a) fork `state_root` between nodes that assembled the same committee
in different orders, or (b) leave a snapshot node unable to re-derive the
committee — either of which would break the D3.3b/D3.6 reconstruction the whole
S-036 closure rests on.

**Witness.** `test-committee-checkpoint`: member-order-independence (same three
members forward vs reverse → equal `state_root`, `src/main.cpp:11286-11298`);
bounded ring (`kCommitteeCheckpointRing + 4` epochs inserted → exactly 16 kept,
newest present, oldest pruned, `:11300-11315`); non-vacuity (`:11276-11284`).

## STMS-5 — EMPTY-SET / NON-EXTENDED BYTE-NEUTRALITY: empty `t:` and `cc:` rings emit ZERO leaves and are omitted from the snapshot

**Claim.** An empty `t:` ring and an empty `cc:` ring each contribute **zero**
state-root leaves and are omitted from `serialize_state`, so a chain that never
populates them has a `state_root` sequence and a snapshot byte-identical to a
pre-D3 chain — which is why every CURRENT/SINGLE chain, and today every chain, is
unaffected.

**Argument.** The leaf-emission loops in `build_state_leaves` iterate the two
maps directly (`src/chain/chain.cpp:405` for `t:`, `:425` for `cc:`); an empty
map yields zero iterations and thus zero appended leaves, so the Merkle input —
and the resulting `state_root` — is identical to the pre-D3 leaf set. On the
persistence side, both blocks are guarded: `serialize_state` writes
`shard_tip_records` only under `if (!shard_tip_records_.empty())`
(`:2057-2069`) and `committee_checkpoints` only under
`if (!committee_checkpoints_.empty())` (`:2075-2092`), so an empty ring adds *no*
JSON key — the snapshot object is byte-identical to pre-D3. The rings are
populated only by the not-yet-built EXTENDED-gated producers (D3.3b folds `cc:`,
D3.5 folds `t:`; `chain.hpp:402-404`, `:779`), so on every shipped chain both are
empty and this claim holds unconditionally. This is why FAST advanced 218 → 219 →
220 with all state-root and snapshot goldens unchanged
(`ShardTipMergeDesign.md:459-461`).

**Excluded failure.** A `t:` or `cc:` leaf (or a snapshot key) leaking into a
chain that recorded no distress / rotated no committee — a consensus-visible
regression that the golden corpus exists to catch, and the hard §0
non-EXTENDED byte-neutrality invariant (`ShardTipMergeDesign.md:36-45`).

**Witness.** The empty-set assertions in both namespace tests: two fresh chains
share a `state_root` with an empty `t:` ring (`src/main.cpp:11128-11134`) and an
empty `cc:` ring (`:11267-11274`); and the empty ring is omitted from
`serialize_state` — no `shard_tip_records` key (`:11209-11216`), no
`committee_checkpoints` key (`:11346-11353`). Plus the unchanged FAST goldens.

## STMS-6 — SNAPSHOT INHERITANCE: `serialize_state` → `restore_from_snapshot` round-trips both rings exactly

**Claim.** A chain reconstructed via `restore_from_snapshot(serialize_state(...))`
holds the identical `t:` records and `cc:` checkpoints as the original and
reproduces the same `state_root` — so a snapshot-bootstrapped node (which retains
only the tail-16 headers and cannot replay early blocks) inherits the committed
rings.

**Argument.** `serialize_state` persists each non-empty ring field-for-field:
every `ShardTipRecord`'s `source_shard_id`/`height`/`eligible_count`/`region`/
`committee_sig_root` (`src/chain/chain.cpp:2057-2069`) and every checkpoint's
`epoch` + `epoch_rand` + each member's `domain`/`ed_pub`/`region`
(`:2075-2092`) — exactly the fields the leaf hashes consume (STMS-2, STMS-4).
`restore_from_snapshot` reads them back through the *same* ring constructors:
`add_shard_tip_record` for each `t:` record (`:2264-2275`) and
`add_committee_checkpoint` for each `cc:` checkpoint (`:2278-2296`), so the
restored rings pass through the identical ring-bound + canonicalization logic
(a no-op here because the serialized set already respects them). Since the
restored maps equal the originals and `state_root` is a pure function of them
(STMS-2/STMS-4), the reconstructed chain's root matches. This is the property the
eventual S-036 reconstruction depends on: an admission gate must see the same
records on an archive node and a snapshot node (`chain.hpp:400-404`,
`ShardTipMergeDesign.md:404-418`).

**Excluded failure.** A snapshot-bootstrapped validator that reaches a *different*
merge-admission verdict than an archive node because it inherited a different (or
empty) ring — the M-A "snapshot node lacks early blocks ⇒ consensus split" hazard
the mechanism decision calls out (`ShardTipMergeDesign.md:400-406`).

**Witness.** The snapshot round-trip assertions: `test-shard-tip-namespace`
serializes three `t:` records, restores, and asserts the ring matches
field-for-field + `state_root` reproduced (`src/main.cpp:11184-11207`);
`test-committee-checkpoint` does the same for two checkpoints incl. per-member
equality (`:11317-11344`).

## STMS-7 — ATOMIC-APPLY ROLLBACK FIDELITY (forward-safety substrate): the `StateSnapshot` optional fields keep the A4/A9 rollback faithful once the rings are mutated in apply

**Claim.** The `StateSnapshot` optional fields
(`shard_tip_records` / `committee_checkpoints`) and their handling in
`restore_state_snapshot` are wired so that the A9 faithful-rollback / A4
`revert_head` machinery restores both rings exactly — *once* D3.3b/D3.5 begin
mutating them inside apply. Today the fields stay `nullopt` (apply never mutates
the rings), so this is dormant forward-safety substrate, not an active path.

**Argument.** The rollback image `StateSnapshot` carries
`std::optional<ShardTipRecordMap> shard_tip_records` and
`std::optional<CommitteeCheckpointMap> committee_checkpoints`
(`include/determ/chain/chain.hpp:880-881`), and `restore_state_snapshot` — the
move-restore called from `apply_transactions`'s catch block, after which "the
chain's observable state is byte-identical to before the failed apply"
(`src/chain/chain.cpp:711-719`) — restores each only when its optional holds a
value: `if (s.shard_tip_records) shard_tip_records_ = std::move(*s.shard_tip_records)`
(`:734-735`) and the matching `committee_checkpoints` branch (`:736-737`). This is
the lazy A9/AL-5 case split used by the other nine containers: `Some` = the ring
was captured before its first apply-time mutation, so move-restore is exact;
`nullopt` = the ring was untouched, so the live map already equals its pre-apply
value and skipping restore is exact. The two inline comments record the deferred
half explicitly — `Some only once D3.5 mutates it in apply` (`:734`) and
`Some only once D3.3b folds in apply` (`:736`) — and a grep confirms **no**
capture-side ensure-lambda exists yet (the only references to these snapshot
fields in `chain.cpp` are the two restore branches). So the restore contract is
in place ahead of the mutators, and when D3.3b/D3.5 add the capture-side
ensure-lambdas, `revert_head` (which reuses this exact snapshot image,
`BoundedReorgSoundness.md` REORG-2) and every failed-apply rollback will restore
the rings faithfully.

**Excluded failure.** A future increment that mutates a ring in apply but forgets
the capture side, so a failed apply (or an A4 reorg) leaves a distress record or
committee checkpoint from the reverted block leaking into the H-1 state — a
`state_root` fork against peers that never applied the loser. The wired restore
branch is what makes adding the capture-side lambda the *only* remaining step
rather than a two-sided change that could be half-done.

**Witness.** No dedicated assertion drives the capture side yet (there is no
apply-time mutator to trigger it); the restore branches are exercised indirectly
by every existing `restore_state_snapshot`/`revert_head` FAST test remaining
green with these fields present (they take the `nullopt` path today). This claim
is a *substrate-present* claim, not a behavioral one — see LIMITS.

---

## LIMITS — what this argument does NOT cover

> **UPDATE (D3.4–D3.8 shipped):** the consensus half enumerated below is now
> **built and proven separately** in `ShardTipMergeClosureSoundness.md`
> (STMC-1…STMC-7). This substrate document is unchanged in scope — it still proves
> ONLY the D3.1+D3.2+D3.3a byte-neutral substrate — but the "not built" / "future
> work" phrasing in the bullets below is superseded: read them as the *substrate's*
> boundary, and see the companion for the shipped closure. S-036 is now **STRONGLY
> MITIGATED** (the reachable exploit is fail-closed), **not CLOSED** — trustless
> closure remains the owner-gated Layer-2 D3.5e.

- **This proves only the shipped byte-neutral substrate, NOT the S-036 closure.**
  D3.1 + D3.2 + D3.3a give the *containers, codec, state-root leaves, rings, and
  snapshot round-trip*. The mechanism that closes `A_beacon_forge` on the reachable
  path — a merge validator fail-closing an under-quorum window against committed
  records — is proven in `ShardTipMergeClosureSoundness.md` (STMC-5), not here.
  S-036 is **STRONGLY MITIGATED** in SECURITY.md
  (`docs/SECURITY.md:1484`, `:1582`); do not read *this* document as closing it.
- **The consensus half is PENDING and its soundness is future work:**
  - **D3.3b** — the `sharding_mode == EXTENDED`-gated selection-pool pin +
    epoch-rotation `cc:` fold-in (`ShardTipMergeDesign.md:462`, §9.2). This is a
    **consensus-behavior change** whose non-EXTENDED byte-neutrality must be
    re-verified against the code before it lands (the pin must touch only the
    EXTENDED/shard-scoped selection, never SINGLE-mode production, or it breaks
    every existing golden, `ShardTipMergeDesign.md:448-453`).
  - **D3.4** — the `eligible_count` digest-bound source-block field
    (conditional-append gated `shard_count_ > 1`, threaded through
    `compute_block_digest`/json/light mirror). A net-new digest-bound field with
    its own empty-vector byte-neutrality obligation — not covered here.
  - **D3.5** — beacon producer emission + F2-style signed-Phase-1-shard-tip-view
    intersection reconciliation (the anti-S-047-wedge determinism obligation on
    the fold-in set) + fold-in re-derivation of the source committee from `cc:`.
  - **D3.6** — the `validate_merge_event_historical` MERGE_EVENT-BEGIN admission
    gate (contiguous sub-`2K` coverage; uniform fail-closed on any absent
    in-window record, `A_beacon_omit`; fail-closed when the window predates the
    ring).
  - **D3.7** — the deterministic S-036 falsifier (healthy-source false-window →
    rejected; genuine distress → accepted; rogue-registered-signer → rejected;
    snapshot-node vs archive-node identical verdict).
- **No unforgeability / attestation-soundness claim.** STMS-1…STMS-6 treat
  `committee_sig_root` and `eligible_count` as opaque committed bytes. Whether
  those bytes carry a *valid* source attestation — and the design-review finding
  that there is no source-committee signature over `eligible_count`, so it is a
  contemporaneously-verified determinism cache rather than a source attestation
  (`ShardTipMergeDesign.md:316-324`, findings 2–3) — is a D3.4/D3.5 property, not
  proven here.
- **Byte-neutrality is scoped to non-populated rings (today: all chains).**
  STMS-5 is unconditional now because nothing writes the rings. Once D3.3b/D3.5
  land, a *healthy MULTI-shard EXTENDED* chain will accrue periodic liveness
  leaves and its `state_root` will legitimately differ from a pre-D3 EXTENDED
  chain — the hard byte-neutrality guarantee is then scoped to NON-EXTENDED
  (SINGLE / `shard_count ≤ 1`) only (`ShardTipMergeDesign.md:340-346`,
  finding 5a). This document's STMS-5 covers the pre-population state.
- **STMS-7 is substrate-present, not behavior-tested.** The capture side of the
  atomic-apply rollback for these two rings does not exist yet (no apply-time
  mutator), so no assertion drives a ring through a failed apply or an A4 revert.
  The claim is that the *restore contract* is wired ahead of the mutators; the
  behavioral proof arrives with D3.3b/D3.5's capture-side ensure-lambdas.
- **`revert_threshold_blocks` semantics.** STMS-3 bounds the `t:` ring by that
  genesis scalar (default 200, `ShardTipMergeDesign.md:154-155`); this proof does
  not argue that 200 *suffices* to cover any particular merge window — that is a
  D3.6 admission-gate obligation (window + grace ≤ ring depth), not a substrate
  property.

---

## Cross-references

- `ShardTipMergeDesign.md` — the design + mechanism decision this substrate
  implements; §9 is the revised increment plan (D3.1/D3.2/D3.3a rows =
  `:459-461`), §9.2 the three feasibility-verdict corrections (pin reads the
  `cc:` checkpoint not `build_from_chain(anchor)`; gate on `sharding_mode ==
  EXTENDED`; prefix `cc:` not `c:`, `:476-508`). §8/§8.1 record why the `cc:`
  checkpoint must exist at all — **retroactive committee re-derivation is
  impossible** because `NodeRegistry::build_from_chain` reads present-head caches
  (`:279-299`, `src/node/registry.cpp:25-78`), so a frozen per-epoch eligible
  set is the only circularity-breaker.
- `CrossShardReceiptDedup.md` — the `i:`-namespace persistence pattern (state-root
  leaf + snapshot serialize/restore + bounded dedup) that the `t:`/`cc:` rings
  mirror verbatim (`ShardTipMergeDesign.md:106-107`, T-R1..T-R7).
- `BoundedReorgSoundness.md` REORG-2 — the A9 snapshot / `restore_state_snapshot`
  rollback machinery STMS-7 extends its two optional fields into (`revert_head`
  reuses the same `StateSnapshot` image).
- `docs/SECURITY.md:1484`, `:1582` — the S-036 partial-mitigation entry; this
  substrate is the first step of the "full closure via on-chain SHARD_TIP
  records" work item, still tracked as *partially mitigated* until D3.6/D3.7.
