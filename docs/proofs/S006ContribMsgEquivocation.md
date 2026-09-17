# S-006 — ContribMsg same-generation equivocation detection

> **RE-DERIVED 2026-09-17 (sequence step 3c; owner decision D4, DECISION-LOG 2026-09-16).** S-006's recorded closure was "route ContribMsg-level detection into the existing slashing apply path". **That apply path no longer exists** (`Chain::apply_transactions` reads nothing from `b.equivocation_events`). This section states what detection still buys and therefore what S-006 still closes.
>
> **What the S-006 finding actually was.** Two distinct `ContribMsg` from one signer at one `(block_index, prev_hash, aborts_gen)` were *silently dropped* by the receiver, so the second signature — the only proof the signer had split the round — **vanished**, and the split was invisible unless the same signer later double-signed at Phase 2. The finding is an OBSERVABILITY gap, not a punishment gap. S-006 closes it: the duplicate is now recomputed, compared, and, on inequality, turned into a V11-valid `EquivocationEvent` that is gossiped, baked and committed under the block hash.
>
> **What the closure buys today, precisely.** (i) **Detection** at the Phase-1 layer — T-1, T-2, T-4 below are unchanged, consume no consequence, and are the substance of the closure. (ii) **An on-chain record** — the event is V11-verified and committed; it is replicated and height-bound, and anyone can re-verify it from public bytes. (iii) **An L2 input** — under D4 that record is the declared input to the L2 bond/arbitration policy (D22, v1.1 DApp scope), which may act on evidence L1 provably cannot adjudicate. **What it no longer buys: anything on L1.** No stake moves, no registrant is deactivated, no committee changes. T-3's "and FA-Apply-10 T-E1/T-E2 fire" clause is VOID and is restated below; T-5 (replay-safety) is restated because its statement was about stake.
>
> **Ledger status.** S-006 stays ✅ Mitigated on the re-derived closure — detection + record + L2 input. It is NOT reopened: the defect it fixed (evidence destroyed at the receiver) is fixed, and re-opening it would mean claiming the second contrib is dropped again, which is false. What IS owed, and is owed by the O-1 sequence rather than by S-006, is the consumer (D22, not designed) and the record's bound (step 3b), completeness (S-090) and shard-identity (S-089) — all OPEN and named in §8.

This document formalizes the S-006 closure shipped in `src/node/node.cpp::on_contrib` (the receive path) and the structural argument that the closure adds a second equivocation-detection surface — at the Phase-1 commit layer — without introducing a new wire format, new validator predicate, or new apply-side branch. The detection mechanism reuses the `EquivocationEvent` struct (FA6, `EquivocationSlashing.md`) and the V11 validator predicate (`check_equivocation_events`) — substituting two `make_contrib_commitment` hashes for the two `compute_block_digest` hashes that V11's pre-S-006 form exercised. The substitution is sound because V11 accepts BOTH digest families through one predicate — since 2026-08-12 by an explicit `kind` discriminator rather than by digest-agnosticism (see the UPDATE box below). There is no apply-side branch to reuse: since D4 the apply path is state-neutral on the event (`EquivocationSlashingApply.md` T-E0).

The proof is short and structural. The pre-S-006 surface had a known gap: a Byzantine producer could send two distinct `ContribMsg` to two peers at Phase 1, both signed under their key, both at the same `(block_index, prev_hash, aborts_gen)`, with different `tx_hashes` or `dh_input` — and the gap would not be detected until (and unless) the producer subsequently signed two distinct `BlockSigMsg` at Phase 2. Honest peers each accepted the first `ContribMsg` they saw and silently dropped duplicates; the second contrib's signature evidence vanished. S-006 closes this by detecting the duplicate at receive time, constructing an `EquivocationEvent` whose two halves are the recomputed contrib commitments, and routing the event through the existing `pending_equivocation_evidence_` pool. The result is: every same-generation `ContribMsg` equivocation produces an `EquivocationEvent` in some honest peer's pool, which gossips, which gets baked into the next block, and which is then a permanent, V11-verified, publicly re-verifiable record of the split — and nothing more at L1 (FA-Apply-10 T-E0).

**Companion documents:** `Preliminaries.md` (F0) for notation, V11 and §9 (what an event does since D4); `EquivocationSlashing.md` (FA6) for the no-false-accusation bound (T-6, and its H3 boundary); `EquivocationSlashingApply.md` (FA-Apply-10) for the apply-side statement that now holds (T-E0, state neutrality); `MakeContribCommitmentBackwardCompat.md` for the v1/F2 commit primitive's domain-separation argument; `SECURITY.md` §S-006 for the audit-side closure record.


---

**UPDATE 2026-08-12 — the EQV-height-bind restructure (S-052).** This document's load-bearing premise
was "V11 is **digest-agnostic**". It no longer is, and the change strengthens rather than weakens the
S-006 reuse argument. `EquivocationEvent` now carries `kind` (0 = BLOCK_DIGEST, 1 = CONTRIB_COMMIT) plus a
per-side opening `(index, body_root)`; `digest_a`/`digest_b` are deleted and derived instead:

```
commit(cm)  =  SHA256("DTM-CONTRIB-v3" ‖ cm.block_index u64 BE ‖ cm.aborts_gen u64 BE ‖ body(cm))   // shipped bytes (corrected 2026-09-14)
body(cm)    =  make_contrib_body_root(cm)          // the legacy commit preimage minus the leading index
```

Three consequences for this proof:

1. **Everything below stated over `commit(cm)` still holds verbatim** — `commit` is still a single
   deterministic function of the `ContribMsg`, and `commit(cm_1) ≠ commit(cm_2) ⟺ body(cm_1) ≠ body(cm_2)`
   for two contribs at one `block_index` (the outer compose adds only the shared tag and index). Every
   distinctness / injectivity argument transfers by that equivalence. The commitment VALUES changed
   (pre-genesis, free); the structure of the argument did not.
2. **The "digest-agnostic" phrasing is retired.** V11 discriminates the family explicitly. This matters:
   under a SHARED tag, one honest block signature plus one honest contrib signature at one height would be
   a valid V11 event — a *new* forgery introduced by the very reuse this document argues for. The two
   distinct outer tags are therefore a **precondition of T-3**, not a stylistic choice.
3. **The event now binds height cryptographically.** T-1's construction sets
   `index_a = index_b = block_index`, which V11 asserts before verifying; see `EquivocationSlashing.md`
   §2 Case (b) for what that closes and §2 Case (c) for the same-height cross-round residual it does not.

Implementation: `src/node/node.cpp:3004` (the `kind = KIND_CONTRIB_COMMIT` assembly),
`src/node/producer.cpp:332` (`compose_contrib_commitment`) / `:252` (`make_contrib_body_root`).

---

## 1. Theorem statements

**Setup.** A `ContribMsg` is the Phase-1 broadcast message a committee member sends carrying their (sorted, deduped) view of the canonical transaction set and their DH-input contribution to the round's delay seed, signed under their Ed25519 key over `make_contrib_commitment(block_index, prev_hash, tx_hashes, dh_input, view_eq_root, view_abort_root, view_inbound_root)`. The signer field names a registered domain `signer`. The pre-S-006 receive path at `src/node/node.cpp::on_contrib` admitted the first `ContribMsg` for each `(signer, current_generation)` slot into `pending_contribs_[signer]`, dropping duplicates silently. The post-S-006 receive path, in addition, recomputes the existing entry's commit, compares it to the incoming message's commit, and on inequality constructs and routes an `EquivocationEvent`.

Let `commit(msg) := make_contrib_commitment(msg.block_index, msg.prev_hash, msg.tx_hashes, msg.dh_input, msg.view_eq_root, msg.view_abort_root, msg.view_inbound_root)` denote the canonical commit hash of a `ContribMsg`. Let `same_gen(cm_1, cm_2) := (cm_1.block_index == cm_2.block_index) ∧ (cm_1.prev_hash == cm_2.prev_hash) ∧ (cm_1.aborts_gen == cm_2.aborts_gen)`. Two contribs are "same-generation" iff they target the same round-state tuple. The current node's "current generation" at any moment is `current_aborts_.size()` per the gate at `node.cpp:2068`.

**Theorem T-1 (Same-generation duplicate detection).** For every pair of `ContribMsg` `(cm_1, cm_2)` arriving at an honest node in any order, with `cm_1.signer == cm_2.signer == d`, `cm_1.aborts_gen == cm_2.aborts_gen == current_aborts_.size()` (both messages pass the generation gate), and `commit(cm_1) ≠ commit(cm_2)` (content differs in any of `tx_hashes`, `dh_input`, or any of the three view-roots), the post-S-006 receive path at `on_contrib` constructs an `EquivocationEvent ev` with:

- `ev.equivocator = d`
- `ev.block_index = cm_1.block_index = cm_2.block_index`
- `ev.kind = KIND_CONTRIB_COMMIT (1)`
- `ev.index_a = cm_1.block_index`, `ev.body_root_a = body(cm_1)`, `ev.sig_a = cm_1.ed_sig`
- `ev.index_b = cm_2.block_index`, `ev.body_root_b = body(cm_2)`, `ev.sig_b = cm_2.ed_sig`
  (so `index_a = index_b = ev.block_index` holds by construction — the T-1 hypothesis already fixes both messages at one `block_index`)
- `ev.shard_id = cfg_.shard_id`
- `ev.beacon_anchor_height = beacon_headers_.back().index` (or `0` if absent)

and routes the event through `pending_equivocation_evidence_` and a gossip broadcast.

**Theorem T-2 (Different-generation drop, no false positive).** For every pair of `ContribMsg` `(cm_1, cm_2)` with `cm_1.signer == cm_2.signer == d` and `cm_1.aborts_gen ≠ cm_2.aborts_gen` (e.g., one before an abort-quorum, one after), the receive path does NOT construct an `EquivocationEvent`. The generation gate at `node.cpp:2068` (`if (msg.aborts_gen != current_aborts_.size()) return;`) drops the cross-generation message before the duplicate-detection branch is reached. An honest signer who legitimately retries at a higher `aborts_gen` is therefore not falsely accused.

**Theorem T-3 (Composition with FA6 + FA-Apply-10).** The `EquivocationEvent` constructed in T-1 satisfies V11's predicate (`check_equivocation_events`, `src/node/validator.cpp:380`): `kind = 1 ≤ 1`; `index_a = index_b = ev.block_index` (the height assert — satisfied by construction, since T-1's hypothesis fixes both contribs at one `block_index`); `body_root_a ≠ body_root_b`; `sig_a ≠ sig_b`; the equivocator is registered; both signatures verify against the digests V11 DERIVES as `SHA256("DTM-CONTRIB-v3" ‖ block_index u64 BE ‖ gen u64 BE ‖ body_root)`, which is exactly `commit(cm_i)` by definition of the two-level commitment; and the cross-shard `shard_id` / `beacon_anchor_height` fields are correctly populated. As a consequence, the event composes with FA6 T-6 (no false accusation: an honest validator satisfying H3 is never named as the equivocator) and with FA-Apply-10 **T-E0** (apply is state-neutral on the event). **Restated 2026-09-17:** this clause used to end "and FA-Apply-10 T-E1 (full stake forfeiture on apply)"; that theorem describes removed code (D4). T-3's content — the constructed event satisfies V11 and therefore becomes a committed record — is unchanged; only its terminal consequence is. No new wire format, validator predicate, or apply-side branch is introduced.

**Theorem T-4 (Two-sig proof soundness).** Both `sig_a := cm_1.ed_sig` and `sig_b := cm_2.ed_sig` are valid Ed25519 signatures by `d`'s registered key over the byte-distinct commits `commit(cm_1)` and `commit(cm_2)`. The pre-construction sig-verification step at `on_contrib` line 2089 (for `cm_2`, the incoming message) and the symmetric line that admitted `cm_1` on its earlier arrival ensure both signatures pass `crypto::verify(pubkey, commit, sig)`. The downstream V11 check, run when the event is baked into a block, re-verifies both signatures independently against `registry.find(d).pubkey`. The two-sig soundness reduces exactly to FA6 T-6: an honest `d` cannot produce two valid signatures over two distinct commits except with probability `≤ 2⁻¹²⁸` per attempt (EUF-CMA, Preliminaries §2.2).

**Theorem T-5 (Replay-safety) — RESTATED 2026-09-17.** *Was:* "a re-applied event contributes zero additional stake forfeiture beyond the first apply", resting on FA-Apply-10 T-E3. Both the quantity and its argument are gone: since D4 an applied event contributes zero *state change of any kind*, first time or n-th (FA-Apply-10 T-E0), so apply-layer replay-safety is trivial and needs no dedup to hold.

*Now:* **S-006's pool dedup is a resource bound, not a correctness bound.** The scan over `pending_equivocation_evidence_` in `Node::on_contrib` skips an incoming event whose `(equivocator, block_index)` is already pooled, which keeps one incident from depositing N entries when N peers each observe it and gossip it. That bounds the pool and the block's evidence list; it no longer preserves any apply-side precondition.

**And it has a cost that D4 makes load-bearing.** With no consequence to fire once, a second *genuinely distinct* incident against the same `(d, h)` is no longer redundant — it is additional evidence, and the record is D22's input. The dedup drops it. See §6.3, restated. The complementary block-side bound (a per-block cap + in-block duplicate rejection) does NOT exist yet and is sequence step 3b: with deregistration gone, nothing at the apply layer limits how often one valid proof is re-included.

---

## 2. Background

### 2.1 Pre-S-006 gap

Before S-006, the equivocation detection surface had two layers but only one was wired:

1. **BlockSigMsg-level (rev.8, shipped).** When two `BlockSigMsg` arrived at the same height with the same `signer` but different `block_hash` (the digest the sig covered), the receive path at `node.cpp::apply_block_locked`'s cross-block check constructed an `EquivocationEvent` with the two block digests as `digest_a` / `digest_b` and the two block-sig signatures as `sig_a` / `sig_b`. This is Phase-2 equivocation detection: the producer signed two different finalized blocks.

2. **ContribMsg-level (Phase-1, deferred).** The Phase-1 commit step at `Node::on_contrib` admitted the first `ContribMsg` per `(signer, current_generation)` into `pending_contribs_[signer]`, but silently dropped duplicates. A `contrib_equivocations_` field declared in `node.hpp` (per S-006 audit history) was never written to.

The gap: a Byzantine producer could send two distinct `ContribMsg` (different `tx_hashes` or `dh_input`) to two peers at Phase 1, both signed under their key, both passing the gen gate, both producing different `commit(cm)` values, and the duplicate-drop hid the evidence. Whether the gap later closed via the rev.8 BlockSigMsg layer depended on whether the producer then signed two distinct Phase-2 blocks — but a sophisticated attacker could partition peers at Phase 1 (sending `cm_A` to subset `S_A`, `cm_B` to `S_B`), let each subset converge on its own Phase-2 block, then sign only ONE of the two blocks themselves. The producer's Phase-2 signature evidence would be a single sig (no equivocation under V11), but the protocol's commitment to the union tx-set across the two subsets would have been split — a liveness + safety degradation without slashing. PROTOCOL.md §6.1 documents this as the historical motivation; the resolution-options table in `SECURITY.md` §S-006 enumerates four candidates of which Option 1 (generation-keyed `pending_contribs_`) shipped.

### 2.2 S-006 design rationale: reuse existing channel

Three structural facts make the reuse-of-existing-channel design clean:

- **The generation gate at `node.cpp:2068` already restricts `pending_contribs_` to current-gen-only.** A duplicate in `pending_contribs_[signer]` is necessarily same-generation (the cross-gen alternative is filtered before reaching the dedup branch). Therefore "same signer + duplicate in map + different commit hash" reduces to "same signer + same generation + different commit hash" — which is exactly Phase-1 equivocation under H2 (Preliminaries §4).

- **V11's predicate carries BOTH families through one gate** — since 2026-08-12 by an explicit `kind` discriminator (`src/node/validator.cpp:380`) rather than by being agnostic. It checks `kind ≤ 1`, the height assert, `body_root_a ≠ body_root_b`, `sig_a ≠ sig_b`, registry membership, and both signatures against digests DERIVED under the kind's domain tag. It still does not introspect what the *body* is over — the S-006 event slots in with `kind = 1` and no new validator predicate or event subtype. What changed is that the reuse is now **explicit and typed** instead of implicit; that is what forbids pairing a block signature with a contrib signature (see the UPDATE box).

- **The apply side is family-agnostic — trivially, since D4.** Apply reads no field of the event at all (FA-Apply-10 T-E0), so it cannot distinguish a `kind = 0` from a `kind = 1` event: the outcome (nothing) is identical for both families. This was the argument's weakest link before D4 and is now its strongest: the pre-D4 version relied on T-E1..T-E7 being stated on `ev.equivocator` alone, which was true but contingent. No new apply branch is introduced.

The closure is therefore additive at one site (`Node::on_contrib`) and uses zero new types, predicates, or apply paths. The price: ~55 LOC at the receive site + ~3 LOC of field/clear cleanup (the unused `contrib_equivocations_` field was deleted per `SECURITY.md` §S-006).

---

## 3. Implementation citation

### 3.1 The S-006 detection branch

Per `src/node/node.cpp:2094–2163` (excerpt for the structural facts; full source remains the canonical reference):

```cpp
// S-006 closure: same-signer duplicate at the SAME generation.
// ...
Hash commit = make_contrib_commitment(msg.block_index, msg.prev_hash,
                                        msg.tx_hashes, msg.dh_input,
                                        msg.view_eq_root,
                                        msg.view_abort_root,
                                        msg.view_inbound_root);
if (!crypto::verify(entry->pubkey, commit.data(), commit.size(), msg.ed_sig)) {
    return;  // line 2089: sig-verify gate
}

auto existing = pending_contribs_.find(msg.signer);
if (existing != pending_contribs_.end()) {
    Hash existing_commit = make_contrib_commitment(
        existing->second.block_index, existing->second.prev_hash,
        existing->second.tx_hashes,   existing->second.dh_input,
        existing->second.view_eq_root,
        existing->second.view_abort_root,
        existing->second.view_inbound_root);
    if (existing_commit != commit) {
        chain::EquivocationEvent ev;
        ev.equivocator          = msg.signer;
        ev.block_index          = msg.block_index;
        ev.kind                 = chain::EquivocationEvent::KIND_CONTRIB_COMMIT;
        ev.index_a              = existing->second.block_index;
        ev.body_root_a          = existing_body;   // make_contrib_body_root(existing)
        ev.sig_a                = existing->second.ed_sig;
        ev.index_b              = msg.block_index;
        ev.body_root_b          = new_body;        // make_contrib_body_root(msg)
        ev.sig_b                = msg.ed_sig;
        ev.shard_id             = cfg_.shard_id;
        ev.beacon_anchor_height = beacon_headers_.empty()
            ? 0 : beacon_headers_.back().index;

        bool dup = false;
        for (auto& e : pending_equivocation_evidence_) {
            if (e.equivocator == ev.equivocator
                && e.block_index == ev.block_index) {
                dup = true; break;
            }
        }
        if (!dup) {
            pending_equivocation_evidence_.push_back(ev);
            gossip_.broadcast(net::make_equivocation_evidence(ev));
        }
    }
    return;  // duplicate dropped from pending_contribs_ regardless
}
```

Five structural properties:

1. **Both commitments use the same F2-aware primitive.** The recomputed `commit` for the incoming `msg` and the `existing_commit` for the stored `pending_contribs_[msg.signer]` both call `make_contrib_commitment` with all seven arguments including the three view-roots. For v1 contribs (all view-roots zero) the short-circuit at `producer.cpp:242–248` fires and the result equals the pre-F2 byte-identical hash per `MakeContribCommitmentBackwardCompat.md` T-1. For F2 contribs (any view-root non-zero) the DTM-F2-v1 domain separator binds the view roots. Either way, two contribs with byte-identical `(tx_hashes, dh_input, view_eq_root, view_abort_root, view_inbound_root)` produce byte-identical commits; any difference produces distinct commits (by SHA-256 collision resistance, Preliminaries §2.1).

2. **The incoming sig is verified BEFORE the duplicate check.** Line 2089 (`crypto::verify(entry->pubkey, commit.data(), commit.size(), msg.ed_sig)`) ensures `msg.ed_sig` is a valid Ed25519 signature by `msg.signer`'s registered key over the byte sequence `commit`. The `existing` entry was admitted by the same path on its earlier arrival, so its `ed_sig` field also satisfies the corresponding sig-verify check — both halves of the eventual `EquivocationEvent` are pre-validated at construction time.

3. **The duplicate-content check is `existing_commit != commit`.** This is a 32-byte hash comparison. Equal commits → legitimate retry (same content, same key, same gen) → drop the duplicate `msg` and return without firing. Distinct commits → equivocation evidence → construct the event.

4. **The pool-dedup scan is `(equivocator, block_index)`-keyed.** Lines 2147–2153 iterate over `pending_equivocation_evidence_` and skip events sharing both fields with the new one. This prevents the same incident from landing twice in the pool (e.g., if a third `ContribMsg` from the same signer arrives later — possibly because gossip re-fetched the duplicate from a peer that hadn't seen the earlier two). The dedup is intentionally coarse-grained: any equivocation at `(d, h)` slashes `d`'s entire stake (FA-Apply-10 T-E1), so multiple distinct same-height equivocations against the same `d` contribute identically (T-E3 idempotence).

5. **The `return` at line 2162 drops the duplicate from `pending_contribs_`.** The earlier-arrived entry remains the canonical contrib for this signer this round. The evidence channel is decoupled from the contrib-set choice — the record lands when the next produced block bakes the evidence, which the producer's `build_body` does at `producer.cpp:452` (via `reconcile_union(eq_views)` for F2 contribs, or via direct `pending_equivocation_evidence_` consumption for v1). The decoupling preserves the F2-SPEC §Q1 reconciliation choice (canonical union over equivocation lists across committee members) while letting any single peer's detection seed the evidence pool.

### 3.2 Cross-references to FA6 and FA-Apply-10

| Layer | Pre-S-006 mechanism | S-006 addition |
|---|---|---|
| Detection at sender | n/a (Byzantine; ignored) | n/a (Byzantine; ignored) |
| Detection at honest receiver, Phase 1 | None — duplicate silently dropped at `on_contrib` | NEW: recompute commit + compare; on mismatch, build `EquivocationEvent` |
| Detection at honest receiver, Phase 2 | `apply_block_locked` cross-block check on two distinct `block_hash` at same height | Unchanged (this path remains the canonical block-digest detector) |
| Event struct | `EquivocationEvent` per `block.hpp:256–279` | Same struct; the two halves are contrib commits instead of block digests |
| Wire transport | `EQUIVOCATION_EVIDENCE` gossip message | Same gossip type |
| Pool buffer | `pending_equivocation_evidence_` | Same buffer |
| Block bake | `Producer::build_body` consumes `pending_equivocation_evidence_` | Same bake site |
| Validator check | `BlockValidator::check_equivocation_events` (V11) | Same check |
| Apply | `Chain::apply_transactions` — reads nothing from `b.equivocation_events` (D4, FA-Apply-10 T-E0) | Same: nothing |
| Consequence | None at L1 since 2026-09-16. The committed record is the L2 input (D22). | Same: none |

The S-006 contribution is exactly the second row. Every other row is unchanged — including the last two, which changed for BOTH families at once when D4 landed and are therefore still a *shared* pipeline, just a shorter one.

---

## 4. Proofs

### Proof of T-1 (same-generation duplicate detection)

Fix `(cm_1, cm_2)` as in the hypothesis: same signer `d`, same generation, distinct commits.

**Case A: `cm_1` arrives first, then `cm_2`.** At `cm_1`'s arrival, the receive path admits `cm_1` into `pending_contribs_[d]` (no existing entry — the `pending_contribs_.find(d)` returns end-iterator, the `if (existing != pending_contribs_.end())` branch is skipped, control falls through to the admit-line `pending_contribs_[msg.signer] = msg` at line 2165). At `cm_2`'s arrival, the same path:

- (a) Passes the basic guards: `cm_2.block_index == chain_.height()` (line 2060), `cm_2.prev_hash == chain_.head_hash()` (line 2063), `cm_2.aborts_gen == current_aborts_.size()` (line 2068 — the generation gate). By hypothesis, all three hold.
- (b) Passes the registry lookup at line 2076 (`signer` is registered).
- (c) Computes `commit := make_contrib_commitment(cm_2.*)` at line 2084 and passes the sig-verify at line 2089 (under hypothesis `cm_2.ed_sig` is a valid Ed25519 signature by `d`'s key over `commit`).
- (d) Reaches the duplicate-check at line 2122: `pending_contribs_.find(d) != end()` because `cm_1` was admitted in the earlier call. The `existing` iterator points to `cm_1`.
- (e) Recomputes `existing_commit := make_contrib_commitment(cm_1.*)` at lines 2127–2132.
- (f) Evaluates `existing_commit != commit` at line 2135. By hypothesis `commit(cm_1) ≠ commit(cm_2)`, and the recompute-then-recompute is the same primitive on each input, so `existing_commit = commit(cm_1)` and `commit = commit(cm_2)`. The inequality holds.
- (g) Constructs the event at lines 2136–2145 with the field assignments listed in the theorem statement.
- (h) Runs the pool-dedup scan at lines 2147–2153. If no prior event with `(d, cm_2.block_index)` is in the pool, the new event is appended and gossiped (lines 2154–2160).

**Case B: `cm_2` arrives first, then `cm_1`.** Symmetric — the roles of `existing` and `msg` swap. The event has `body_root_a = body(cm_2)`, `sig_a = cm_2.ed_sig`, `body_root_b = body(cm_1)`, `sig_b = cm_1.ed_sig`. By V11 the order doesn't matter (it checks `digest_a ≠ digest_b` and verifies both sigs; the labels `_a` / `_b` are positional, not semantic).

**Both cases:** The event satisfies all field-assignment claims in T-1. ∎

### Proof of T-2 (different-generation drop, no false positive)

Fix `(cm_1, cm_2)` as in the hypothesis: same signer `d`, different `aborts_gen` values.

Assume WLOG `cm_1.aborts_gen = g_1` and `cm_2.aborts_gen = g_2` with `g_1 < g_2` (the reverse is symmetric — the case differs only in whether the receiver has already advanced past `g_2`). The receiver's `current_aborts_.size()` evolves monotonically: each finalized abort-quorum at the current generation appends an entry to `current_aborts_` and increments the size by 1 (the abort-event apply path; see `AbortEventApply.md`). The size never decreases except via a chain reorg, which is FA1 / Safety scope and not relevant here.

There are three time-orderings to consider for the receiver:

- **(i) Both arrive when the receiver's `current_aborts_.size() == g_1`.** Then `cm_1` passes the gate (`g_1 == g_1`); `cm_2` fails the gate at line 2068 (`g_2 ≠ g_1`) and returns immediately at line 2068. `cm_2` is never seen by the duplicate-check branch. No `EquivocationEvent` is built.

- **(ii) Both arrive when the receiver's `current_aborts_.size() == g_2`.** Then `cm_1` fails the gate (`g_1 ≠ g_2`) and returns at line 2068; `cm_2` passes. No `EquivocationEvent` is built.

- **(iii) The receiver advances from `g_1` to `g_2` between the two arrivals.** Then `cm_1` arrived when size was `g_1`, was admitted to `pending_contribs_[d]`. Between arrivals, the receiver's apply of the round-`g_1` abort quorum increments `current_aborts_.size()` to `g_2`, which triggers a Phase-1 reset (the `reset_round` machinery at the top of the next round-prep path, which clears `pending_contribs_` per the protocol's per-round-state isolation). When `cm_2` arrives, `pending_contribs_.find(d)` returns end-iterator (the `cm_1` entry was cleared by the reset). The duplicate-check branch is skipped; `cm_2` is admitted as a fresh entry. No `EquivocationEvent` is built.

In all three orderings, the construction at lines 2136–2145 is not reached. The honest signer who legitimately retries at a higher generation (case iii — the canonical scenario of "abort, observe, retry") is not falsely accused. ∎

### Proof of T-3 (composition with FA6 + FA-Apply-10)

We show the constructed `EquivocationEvent` from T-1 satisfies V11's predicate. By inspection of `BlockValidator::check_equivocation_events` at `validator.cpp:307–322`:

- `ev.body_root_a == body(cm_1)`, `ev.body_root_b == body(cm_2)`, and by hypothesis `commit(cm_1) ≠ commit(cm_2)`, which at one `block_index` is equivalent to `body(cm_1) ≠ body(cm_2)` (the precondition of T-1). So `body_root_a != body_root_b` — that V11 clause satisfied.
- `ev.sig_a == cm_1.ed_sig`, `ev.sig_b == cm_2.ed_sig`. Distinct Ed25519 signatures over distinct messages by the same key are with overwhelming probability distinct as 64-byte byte-strings (RFC 8032: signatures include a deterministic per-message nonce derived from the SHA-512 of `prefix || message`, so distinct messages produce distinct nonces and hence distinct signatures with negligible collision probability). `sig_a != sig_b` — second V11 clause satisfied.
- `ev.equivocator = msg.signer`, which passed the registry lookup at `on_contrib` line 2076. So `registry.find(ev.equivocator)` returns a valid entry — third V11 clause satisfied.
- The V11 sig-verifies `Verify(pk_d, D(1, ev.index_a, ev.body_root_a), ev.sig_a)` and `Verify(pk_d, D(1, ev.index_b, ev.body_root_b), ev.sig_b)` — where the derived digests are exactly `commit(cm_1)` and `commit(cm_2)` — both pass: the corresponding pre-construction checks ran at `on_contrib` line 2089 for `cm_2` and at the analogous line on `cm_1`'s earlier arrival. (Note that V11 re-runs the verifies independently at validate-time, so the construction-time verifies are belt-and-suspenders — a propagated event survives even if the receiver who constructed it acted in bad faith on the pre-checks, because V11 will catch a fabricated sig at block-validate.) Fourth and fifth V11 clauses satisfied.
- Cross-shard `shard_id` and `beacon_anchor_height` are populated per the assignment at lines 2143–2145. V11's cross-shard handling at `validator.cpp` continues to behave per FA6 T-6.1.

Therefore the event survives V11 and gets baked into a finalized block per `Producer::build_body`. **The apply path then does nothing with it** (FA-Apply-10 T-E0, D4): `stakes_[d]`, `registrants_[d]` and all six A1 counters are byte-identical to an event-free twin, and A1 holds with `Δlive_total_supply = 0 = Δexpected_total`. What the event achieves is that it is *in* the block: inside `signing_bytes`, inside the block hash and inside the digest's reconciled eq-root, so it is replicated, K-of-K-attested and re-verifiable by anyone. That committed record is the terminus of the S-006 pipeline at L1 and the entry point of the L2 policy (D22). ∎

### Proof of T-4 (two-sig proof soundness)

The construction at lines 2136–2145 assigns `ev.sig_a := existing->second.ed_sig` and `ev.sig_b := msg.ed_sig`. Both fields were Ed25519-verified before reaching this point:

- `msg.ed_sig` was verified at line 2089 via `crypto::verify(entry->pubkey, commit.data(), commit.size(), msg.ed_sig)`. The `entry->pubkey` is `d`'s registered Ed25519 public key (looked up at line 2076 via `registry_.find(msg.signer)`).
- `existing->second.ed_sig` was verified at the analogous site when `cm_1` was admitted on its earlier arrival — the same `on_contrib` path applies the same sig-verify at line 2089 to every incoming ContribMsg before any admit or duplicate-check.

By FA6 T-6's argument (`EquivocationSlashing.md` §2), under EUF-CMA (Preliminaries §2.2) no polynomial-time adversary forges a signature by an honest key with probability non-negligibly better than `≤ 2⁻¹²⁸`. So if `d` is honest, the joint event "`d` produced two valid Ed25519 sigs over byte-distinct messages `commit(cm_1)` and `commit(cm_2)` at the same `(block_index, prev_hash, aborts_gen)`" is impossible under H2 (honest validators sign at most one contrib per `(height, aborts_gen)` tuple — Preliminaries §4, the S-006 closure clause). If `d` is Byzantine, the two sigs are genuinely `d`'s — the slash is correct.

The V11 re-verification at block-validate (`validator.cpp::check_equivocation_events`) provides independent confirmation, closing any path where the upstream sig-check could be bypassed (e.g., a malicious peer fabricating an event with a forged sig directly into the pool would have its event rejected at V11 before bake, never reaching the apply path). The two-layer check (construction-time at `on_contrib` + validate-time at V11) ensures the apply-side slash fires only on cryptographically-sound evidence. ∎

### Proof of T-5 (replay-safety)

Two replay surfaces to consider:

*(The two sub-cases below are retained as written; read "T-E3 preconditions" as "pool-size bound", per the restated T-5 above.)*

**Replay 1: Same incident produces multiple `EquivocationEvent`s in `pending_equivocation_evidence_`.** S-006's pool-dedup at `node.cpp:2147–2153` scans the pool for any existing event with `(equivocator, block_index)` matching the new event. On hit, the new event is silently not appended. This prevents the same Phase-1 equivocation incident from depositing N events into the pool when N different peers each observe the same `(cm_1, cm_2)` pair via gossip. (The N peers each construct an event; gossip propagation may bring up to N copies into any single peer's pool; the dedup ensures only the first survives per peer.) The pool therefore contains at most one event per `(d, h)` pair from S-006-class detection.

**Replay 2: Multiple `EquivocationEvent`s for the same `(d, h)` reach the apply path across blocks.** Even with S-006's pool-dedup, different shards' or different committee members' pool views may surface duplicate events across successive blocks (gossip propagation lag, multiple equivocations against the same `d` at the same height each triggering an independent event, etc.). FA-Apply-10 **T-E0** handles this case and every other: apply reads no field of the event, so the first, second and n-th application each change nothing, within a block or across blocks, and `accumulated_slashed_` advances by 0 in all cases. (The pre-D4 argument was T-E3: the second iteration read `locked == 0` and contributed zero. It is historical.) What duplicates still cost is block bytes and two Ed25519 verifies per copy at V11 — the step-3b bound, OPEN.

S-006's pool-dedup makes T-E3's preconditions easier to satisfy at the production layer (no duplicate events from the same peer's detection survive into a baked block), but T-E3 alone covers the cross-shard / cross-block replay case. The two layers compose: S-006 reduces the duplicate-event surface at the bake layer; FA-Apply-10 T-E3 makes the apply layer robust against any duplicates that slip through. ∎

---

## 5. Adversary model

The adversary considered in T-1 through T-5 is the **Byzantine producer with Phase-1 splitting**, with capabilities:

1. **Holds the secret key `sk_d`** for a registered domain `d`. By definition Byzantine, so producing two distinct valid Ed25519 sigs over two distinct commits is feasible (the adversary signs both themselves — no forgery needed).

2. **Sends two distinct ContribMsg to different peer subsets.** The adversary partitions the honest peer set into `S_A` (receives `cm_A` with `tx_hashes = T_A`, `dh_input = D_A`) and `S_B` (receives `cm_B` with `tx_hashes = T_B ≠ T_A`, `dh_input = D_B ≠ D_A`). Both messages pass V11's basic guards (same `block_index`, same `prev_hash`, same `aborts_gen`, both signed by `pk_d`). Pre-S-006 the partition was undetected; post-S-006 the partition is detected as soon as any honest peer receives both messages (i.e., as soon as gossip relay carries `cm_B` to any peer in `S_A` or vice versa).

3. **May attempt to escape detection by switching `aborts_gen`.** The adversary might claim "this is a legitimate retry after abort" by setting `cm_B.aborts_gen = cm_A.aborts_gen + 1`. T-2 covers this: an honest peer at `current_aborts_.size() == g_1` drops `cm_B` at the generation gate (it's not at the current generation yet). After the honest peer's `current_aborts_` advances to `g_2`, the prior `pending_contribs_[d]` entry was cleared by `reset_round`, so `cm_B`'s arrival at the new generation finds no duplicate to compare against. The adversary therefore cannot escape detection via gen-switch UNLESS they actually trigger the abort-quorum legitimately — and a legitimate abort means `cm_B` is at a genuinely-different round-state, which is not equivocation. So gen-switching either (a) fails the gen-gate and is dropped, or (b) corresponds to a real round-state transition and is not equivocation.

4. **May attempt to escape detection by partitioning peers so no honest peer sees both messages.** The closure is robust against this in the limit: any subsequent gossip carries the suppressed message into the peer's pool eventually (gossip is best-effort eventual). The window in which detection lags is bounded by gossip propagation time (~seconds in practice); the record lands in the next produced block AFTER detection reaches some honest producer's pool (and may not land at all — evidence gossip is one-hop with no relay or re-request, S-090 OPEN). A partition that lasts more than one round will eventually heal (peers re-fetch missing messages on STATUS_RESPONSE), and the suppressed contrib's existence may be witnessed indirectly via the K-of-K Phase-2 reveal if the adversary signs ANY Phase-2 block (the BlockSigMsg-level detector picks up the divergent finalize). The combination of Phase-1 (S-006) and Phase-2 (rev.8) detectors covers both halves of the partition surface.

The adversary cannot:

- **Forge a signature by an honest peer.** EUF-CMA (Preliminaries §2.2) — bounded by `≤ 2⁻¹²⁸` per attempt. T-4 reduces S-006's two-sig soundness to this.
- **Suppress an `EquivocationEvent` once gossiped.** The gossip layer's `EQUIVOCATION_EVIDENCE` message type is broadcast on construction (`gossip_.broadcast` at line 2156) and propagates to all peers. A single honest peer's detection produces a gossip wave; the evidence reaches every honest committee member's pool within bounded time.
- **Bias the bake decision to exclude the event.** The producer's `build_body` consumes `pending_equivocation_evidence_` directly (or reconciles across committee members' views per F2-SPEC §Q1's union reconciliation). A single honest committee member having the event in their view is sufficient for the event to land in the canonical block body. The adversary cannot prevent every committee member from holding the evidence — by the Phase-1 gossip propagation guarantee, the evidence reaches enough peers within one round's gossip window.

The composition of S-006 (Phase-1 detection) + rev.8 (Phase-2 detection) + FA6 no-false-accusation + FA-Apply-10 T-E0 produces the property the closure now claims: every same-generation Phase-1 equivocation that reaches an honest producer becomes a committed, publicly re-verifiable on-chain record naming the offender, with negligible cryptographic false-positive probability against honest peers — and no consequence. "Eventually slashes the offender" is the pre-D4 wording and is withdrawn; so, note, is "eventually" — see S-090.

---

## 6. Identified gaps + edge cases

### 6.1 Byte-identical retry — NOT equivocation

If a Byzantine peer sends the same `ContribMsg` twice (perhaps because of a network glitch or a deliberate retry to ensure delivery), the second arrival hits `pending_contribs_.find(msg.signer) != end()` (the duplicate path) but `existing_commit == commit` (the content is identical). The branch at line 2135 (`if (existing_commit != commit)`) is false, the `EquivocationEvent` construction is skipped, and the duplicate is silently dropped via the unconditional `return` at line 2162. This is the correct behavior — byte-identical retries are legitimate (a key's sig over a fixed message is deterministic per RFC 8032, so an honest peer retrying a message they've already signed produces a bit-identical message; an adversary retrying their own message similarly).

The protocol's invariant is "at most one signature per `(signer, block_index, prev_hash, aborts_gen, tx_hashes, dh_input, view_*_root)` tuple" — which is exactly what the byte-identical check exercises. Any two messages with all of those fields equal MUST produce the same commit (by the determinism lemma L-2 of `MakeContribCommitmentBackwardCompat.md`) and therefore the same Ed25519 signature; the two `ed_sig` fields would also be byte-identical, which V11 rejects (`sig_a == sig_b` clause at `validator.cpp:316`). The byte-identical case is therefore both NOT equivocation (T-1's "distinct commits" precondition fails) AND would be rejected by V11 even if construction proceeded — defense in depth.

### 6.2 Cross-generation equivocation — out of scope for S-006

A signer who aborts and retries at a higher `aborts_gen` legitimately sends a different contrib at the same height. T-2 covers the false-positive avoidance. The threat of a coordinating cartel that crosses abort generations (e.g., voting to abort at gen 0, then having one of their members switch contribs at gen 1 to bias the union tx-set) is a different threat model and is addressed by `SECURITY.md` §S-006's Option 2 (cross-generation hash binding via `prev_aborts_gen_hash`) — deferred. The generation gate at `on_contrib` line 2068 ensures honest peers cannot be tricked into accepting cross-gen contribs as the canonical view, so the cartel attack requires at least one member to commit same-gen equivocation, which IS detected by S-006.

### 6.3 Pool-dedup coarseness

The pool-dedup keys on the equivocator identity only — not on the specific openings `(body_root_a, body_root_b)`. Two distinct equivocations against the same `d` at the same `h` (e.g., `(cm_A, cm_B)` and `(cm_A, cm_C)` with distinct C ≠ B) would produce events with the same `(equivocator, block_index)` but distinct digest pairs; only the first survives in the pool. **RESTATED 2026-09-17 — this is no longer a free choice.** The original justification was "the slash is full-stake-forfeit (T-E1), so the second incident contributes nothing additional". Under D4 the first incident also contributes nothing, so the coarse key can no longer be defended as *harmless*: it is a deliberate LOSS of evidence in a channel whose only remaining product is evidence, and whose consumer (D22) is exactly a policy that may need incident counts, timing or distinct openings.

The honest statement: the coarse key is retained because it is the pool's memory bound and the only defence against evidence-replay amplification (`BlockIngressGateAudit.md` §3 — one valid proof replayed under varying `block_index` grew the pool without limit), and because a bounded per-equivocator multiset is a design with an owner-facing cost that has not been decided. Its price, stated: **within a shard, only the first-observed incident per `(d, h)` reaches the chain.** Whether that suffices is a D22 question, recorded there and NOT decided here. "A forensics audit can re-derive the evidence from gossip logs" remains true and remains worth nothing to an on-chain policy.

### 6.4 F2 view-root binding interaction

For F2-active contribs (any view-root non-zero), the commit includes the DTM-F2-v1 domain separator + the three view roots per `MakeContribCommitmentBackwardCompat.md` T-2. Two contribs with byte-identical `(tx_hashes, dh_input)` but distinct view-roots produce distinct commits — and the S-006 detector flags this as equivocation. This is the intended behavior: a Byzantine peer who commits to two different views (e.g., includes one equivocation event in `view_eq_root_A` and a different one in `view_eq_root_B`) has equivocated on their declared view, which is the F2 closure's target attack. The S-006 + F2 composition makes view-equivocation slashable by the same mechanism that catches tx-hash / dh-input equivocation.

For v1 contribs (all view-roots zero), the commit shape collapses to the pre-F2 4-element pre-image and the detector remains active on `(tx_hashes, dh_input)` differences alone. The mechanism is uniformly applicable across both regimes.

### 6.5 `contrib_equivocations_` field removed

Per the S-006 audit history (`SECURITY.md` §S-006 "Cleanup"), the unused `contrib_equivocations_` map declared in `node.hpp` was removed along with its `clear()` call in `reset_round`. The legacy field was a placeholder from an earlier design that intended a separate event subtype for ContribMsg equivocation; the shipped Option 1 reuses `EquivocationEvent` directly, making the legacy field dead code. A reviewer comparing pre-S-006 and post-S-006 source should not be surprised that `contrib_equivocations_` is absent — its functionality is subsumed by `pending_equivocation_evidence_` per the digest-agnostic argument in §2.2.

---

## 7. Test-suite citation

The S-006 closure is exercised end-to-end through the standard equivocation regression suite. The detection path is dormant on honest runs (no committee member equivocates), so the regression tests focus on the evidence pipeline rather than the detector itself; the detector's correctness is structural (the §3 source citation + the §4 proofs).

| Test | Source | Coverage |
|---|---|---|
| `tools/test_equivocation_slashing.sh` | `tools/test_equivocation_slashing.sh` | End-to-end network-level: 3-node M=K=3 cluster, synthesized two-sig evidence submitted via `submit_equivocation` RPC to **all three nodes simultaneously** (Round-20 race fix per memory: pre-fix the asymmetric pool views caused fork retries; now every node has the evidence in its pool before the next finalize). The evidence path is the same one S-006 feeds — gossip → pool → bake → apply — so the test validates the consumption layer for both detection sources. Since D4 its post-submission stake expectation is that node1 keeps exactly its pre-submission stake. |
| `determ test-equivocation-apply` (via `tools/test_equivocation_apply.sh`) | `src/main.cpp` apply-side in-process suite | FA-Apply-10 **T-E0** — state neutrality against an event-free twin, A1, and a positive control that the event really is in the applied block; mutants M1–M8 RED. The events constructed in this suite are synthesized in-process; the construction path mirrors S-006's `EquivocationEvent` assembly (same struct, same field semantics). |
| `determ test-equivocation-multi` (via `tools/test_equivocation_multi.sh`) | `src/main.cpp` multi-equivocation in-process suite | The multi-event composition arms, each asserting neutrality: two distinct equivocators in one block, the same equivocator twice (the apply-layer analogue of the restated T-5), an equivocator with no stake, a pre-deactivated equivocator, determinism across two chains. |
| Detection-specific test (deferred) | n/a | A dedicated test exercising the `on_contrib` S-006 detection branch directly (synthesizing two Byzantine ContribMsg with distinct commits + same gen and asserting `pending_equivocation_evidence_` gains an entry) would land naturally as part of the S-035 unit-test culture seeding. The detection logic is structurally short (~25 LOC at the lines 2122–2163 site) and exercised on every duplicate path; the absence of a dedicated test reflects S-006's "dormant on honest paths" property rather than test-coverage neglect. The downstream pipeline IS covered by the three tests above. |

The composition test-suite (apply-side neutrality for synthesized events covered by `test-equivocation-apply` + `test-equivocation-multi`; end-to-end network behavior covered by `test_equivocation_slashing.sh`) validates that any `EquivocationEvent` produced by S-006's detection branch traverses the pipeline correctly. The detection branch itself is small enough that the §3 source citation + §4 proofs constitute the primary correctness argument; future S-035 work may add a dedicated synthesis test for the detection branch in isolation.

---

## 8. Status

**Shipped, on the re-derived closure.** S-006 is recorded in `SECURITY.md` as ✅ Mitigated: the Phase-1 split is DETECTED, the two signatures are preserved as an authenticated on-chain RECORD, and that record is the L2 input (D22). The closure claims nothing about consequence.

**What is owed, and by whom (2026-09-17).** None of these is an S-006 defect; each is a named, open item of the O-1 sequence that the S-006 record now depends on for its value:

| Owed | Where it lives | Status |
|---|---|---|
| A consumer for the record | D22 — L2 bond / arbitration policy, v1.1 DApp scope | NOT DESIGNED. Until it exists, an S-006 detection has no effect anywhere. |
| A bound on the record | Sequence step 3b — per-block cap + in-block duplicate rejection on `equivocation_events` | OPEN. Deregistration was the only limiter. |
| Completeness of the record | S-090 — `on_equivocation_evidence` does not rebroadcast; gossip has no relay or re-request | OPEN |
| One event hash per incident on shards | S-089 — `beacon_anchor_height` / `shard_id` hashed but compared by nothing | OPEN |
| Per-incident (not per-`(d,h)`) evidence | §6.3 above; a D22 requirement question | NOT DECIDED |

Implementation surfaces:

- `src/node/node.cpp:2094–2163` — the detection branch (this proof's primary object).
- `include/determ/chain/block.hpp:256–279` — the `EquivocationEvent` struct (unchanged; reused as documented in §2.2 and §3.2).
- `src/node/validator.cpp:307–322` — V11's `check_equivocation_events` (unchanged; verifies the constructed event).
- `Chain::apply_transactions` (`src/chain/chain.cpp`) — reads NOTHING from `b.equivocation_events`; the identifier occurs there only in the comment block recording D4 (FA-Apply-10 T-E0).
- `include/determ/node/node.hpp` — `contrib_equivocations_` field removed per the cleanup recorded in `SECURITY.md` §S-006.
- `docs/PROTOCOL.md` §6.1 — documents the two detection paths (BlockSigMsg-level and ContribMsg same-generation).
- `docs/SECURITY.md` §S-006 — audit-side closure record with the four-row Option resolution table (Option 1 shipped, Option 2 deferred, Option 3 rejected).

The closure is **localized** in the sense of Track A (~55 LOC at a single site + ~3 LOC of cleanup), preserves wire-format compatibility (no new struct fields, no new message types, no new validator predicate, no new apply branch), and depends only on existing primitives (the `EquivocationEvent` struct, V11, the `pending_equivocation_evidence_` pool and the `Producer::build_body` consumption). FA6 T-6 (no false accusation, under its H3 boundary) and FA-Apply-10 T-E0 (apply neutrality) cover the downstream pipeline; S-006's contribution is the upstream detection branch that produces events on the Phase-1 surface in addition to the rev.8 Phase-2 surface.

---

## 9. References

- `src/node/node.cpp::on_contrib` (lines 2056–2168 in the current `main` branch) — the receive path with the S-006 detection branch at lines 2094–2163.
- `include/determ/chain/block.hpp::EquivocationEvent` (lines 256–279) — the event struct, unchanged from rev.8.
- `src/node/validator.cpp::check_equivocation_events` (lines 307–322 approximate) — V11's two-sig + distinct-digest check.
- `src/chain/chain.cpp::apply_transactions` — no equivocation branch since D4; the identifier `equivocation_events` appears there only in the comment recording the decision (FA-Apply-10 T-E0).
- `src/node/producer.cpp:252 make_contrib_body_root` + `:332 compose_contrib_commitment` — the two-level commit primitive feeding both openings of an S-006 event.
- `src/node/producer.cpp::build_body` (line 452 approximate) — the bake site that consumes `pending_equivocation_evidence_` into `b.equivocation_events`.
- `include/determ/node/producer.hpp::ContribMsg` (lines 36–62 approximate) — the wire struct including the F2 view-root fields.
- `docs/proofs/Preliminaries.md` (F0) — notation, V11, H2 (S-006 closure clause: at most one `make_contrib_commitment` per `(height, aborts_gen)`).
- `docs/proofs/EquivocationSlashing.md` (FA6) — no-false-accusation (T-6 + T-6.1), and its H3 boundary.
- `docs/proofs/EquivocationSlashingApply.md` (FA-Apply-10) — apply-side state neutrality (T-E0); T-E1..T-E7 are historical.
- `docs/proofs/MakeContribCommitmentBackwardCompat.md` — v1/F2 commit-primitive domain separation (T-1 v1 byte-identity, T-2 DTM-F2-v1 replay defense); the commits feeding S-006 events inherit T-2's distinct-pre-image property.
- `docs/proofs/F2-SPEC.md` §Q4 — design decision to extend `make_contrib_commitment` rather than introduce a separate primitive; the S-006 detector consumes the extended primitive uniformly.
- `docs/PROTOCOL.md` §6.1 — equivocation detection paths (BlockSigMsg + ContribMsg).
- `docs/SECURITY.md` §S-006 — audit-side closure record.
- `tools/test_equivocation_slashing.sh` — end-to-end 3-node submit (R20 race fix: all-3-node simultaneous submit) covering the evidence pipeline S-006 feeds; its post-submission stake expectation is now "unchanged".
- `tools/test_equivocation_apply.sh` (`determ test-equivocation-apply`) — apply-side T-E0 regression.
- `tools/test_equivocation_multi.sh` (`determ test-equivocation-multi`) — multi-equivocation edge cases including the apply-side replay-safety analog (T-5).
- RFC 8032 (Edwards-Curve Digital Signature Algorithm) — Ed25519 deterministic signature; backs the "distinct messages produce distinct sigs" argument in T-3's `sig_a != sig_b` clause.
- NIST FIPS 180-4 §5.1 — SHA-256 padding; backs the distinct-pre-image argument inherited from `MakeContribCommitmentBackwardCompat.md`'s L-3.
