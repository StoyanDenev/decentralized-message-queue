# EqAbortViewDigestExtension — closing the equivocation/abort dimension of S-030-D2 (v2.7 F2)

**Status:** Design spec, implementation-ready. Not yet shipped.
**Scope:** Extend the shipped inbound F2 carry→reconcile→digest pattern to the
`equivocation_events` and `abort_events` dimensions, using the **UNION**
reconciliation rule (per F2-SPEC §Q1) instead of inbound's INTERSECTION.
**Recommendation (see §5):** **GO** — bind the reconciled union into the digest.
The gossip-async safety gate is **passed** because reconciliation is a pure,
deterministic function of the K signed Phase-1 commits, computed *before*
digesting. This is the same property that makes the shipped inbound binding safe.

Companion docs:
- `docs/proofs/S030-D2-Analysis.md` — the residual D2 gap and the inbound closure (§3.5, §4 item 7).
- `docs/proofs/F2-SPEC.md` — §Q1 reconciliation rules, §Q4 commit binding, §Q5 Phase-2 semantics.
- `docs/proofs/F2ViewReconciliationAnalysis.md` — T-1..T-6 (purity/order-independence/idempotence of reconcile_union).
- `docs/proofs/MakeContribCommitmentBackwardCompat.md` — the DTM-F2-v1 commit shape + v1 short-circuit.
- `docs/proofs/EquivocationSlashingApply.md` (FA-Apply-10), `docs/proofs/AbortEventApply.md` (FA-Apply-11) — the apply paths these events feed.

---

## 1. Goal and what is already done

### 1.1 Goal

Close the consensus-layer S-030-D2 gap for the `equivocation_events` and
`abort_events` dimensions. Today, an honest assembler bakes its *local*
`pending_equivocation_evidence_` and `current_aborts_` pools into the block
body, but `compute_block_digest` does **not** cover those fields. Two distinct
committee-signed instances at the same height with different eq/abort lists share
the same digest, both pass K-of-K verification, and only the apply-layer S-033
state_root check (and the next block's `prev_hash`) separates them. The goal is
to make the eq/abort sets a **deterministic committee-wide reconciliation** of
the members' committed Phase-1 views, bound into the digest, so that two
divergent eq/abort sets can never both gather K-of-K signatures.

### 1.2 What is already done (verified against code)

The eq/abort dimension is partially scaffolded — strictly more than inbound was
before its closure, but with three load-bearing pieces missing.

Already present and verified:

- **Per-creator eq/abort ROOTS are carried in the Block and signature-bound.**
  `include/determ/chain/block.hpp:408-409` declares `creator_view_eq_roots` and
  `creator_view_abort_roots` (parallel to `creator_view_inbound_roots:410`). These
  roots are authenticated by `creator_ed_sigs` because the validator recomputes each
  creator's Phase-1 commit *with* all three roots:
  `src/node/validator.cpp:166-170` (`check_creator_tx_commitments`) calls
  `make_contrib_commitment(..., vr_at(creator_view_eq_roots,i),
  vr_at(creator_view_abort_roots,i), vr_at(creator_view_inbound_roots,i))`. The
  `vr_at` lambda (`validator.cpp:163-165`) returns `Hash{}` for missing indices, so
  pre-F2 blocks reproduce the byte-identical v1 commit.
- **ContribMsg carries `view_eq_list` / `view_abort_list`.** Already wire-defined
  and canonicalized in `make_contrib` (`src/node/producer.cpp:628-630, 659-664`); the
  three roots are folded into the commit via `make_contrib_commitment`
  (`producer.cpp:668-670`). Pre-F2 short-circuit at `producer.cpp:655-666` keeps the
  v1 commit when all lists empty.
- **Reconciliation primitives exist and are correct.** `reconcile_union`
  (`producer.cpp:345-351`) is a pure `std::set`-based union;
  `derive_canonical_view_lists` (`producer.cpp:438-456`) already applies
  `reconcile_union` to eq/abort (lines 452-453) and `reconcile_intersection` to
  inbound (line 454). `validate_view_reconciliation` (`producer.cpp:458-496`) already
  validates all three (V21-V26).
- **Canonical event hashers exist.** `hash_equivocation_event`
  (`producer.cpp:280-295`, domain `DTM-F2-EQ-v1`) and `hash_abort_event`
  (`producer.cpp:297-310`, domain `DTM-F2-ABORT-v1`) hash all consensus-bound fields
  in declared order. Cross-domain separators make the three view-list types
  un-mixable.
- **JSON backward-compat gating exists for roots.** `src/chain/block.cpp:401-425`
  emits the view roots (and `creator_view_inbound_lists`) only when at least one root
  is non-zero; `block.cpp:521-538` reads them back conditionally.

### 1.3 What is NOT done (the three blocking gaps)

The eq/abort roots are carried and sig-bound, **but they are always zero in
practice**, because none of the producer/validator wiring populates or enforces
them. The closure requires:

1. **The Phase-1 view is never populated for eq/abort.**
   `src/node/node.cpp:870-874` (`start_contrib_phase`) calls `make_contrib(...,
   {}, {}, f2_inbound_view)` — the first two args (eq, abort view lists) are always
   empty. So every creator's `view_eq_root`/`view_abort_root` is zero even at F2-active
   heights. **No eq/abort view is ever committed.**
2. **`build_body` does not reconcile eq/abort.**
   `src/node/producer.cpp:712-713` assigns `b.abort_events = aborts` and
   `b.equivocation_events = equivocation_events` directly from the assembler's local
   pool parameters (`pending_equivocation_evidence_`, `current_aborts_` — passed
   at the two `build_body` call sites: the `equivocation_events` arg at
   `node.cpp:997, 1113` and the `aborts` arg at `node.cpp:993, 1108`). There is no
   `reconcile_union` step, and
   `creator_view_eq_lists` / `creator_view_abort_lists` are not carried into the block.
   Contrast the inbound path at `producer.cpp:891-904`, which filters to
   `reconcile_intersection(b.creator_view_inbound_lists)`.
3. **`compute_block_digest` does not bind eq/abort, and the validator does not
   enforce them.** `producer.cpp:598-604` binds only `inbound_receipts`. The
   validator's `check_inbound_receipts` (`validator.cpp:1168-1185`) enforces only
   inbound; `validate_view_reconciliation` exists but is **not called** anywhere in the
   validator path.

Also missing (a Block-struct gap): there are **no** `creator_view_eq_lists` /
`creator_view_abort_lists` fields (block.hpp carries only
`creator_view_inbound_lists:416`). The validator cannot re-derive the canonical
eq/abort union from block data without them — exactly as it needs the inbound
lists to re-derive the intersection.

---

## 2. Exact ordered code changes

Implement in this order. Each step is independently compilable; the digest binding
(step 5) and validator enforcement (step 6) must land together with a flag-day
guard (see §4) so a partially-deployed network cannot stall.

### Step 0 — (prereq) populate the eq/abort Phase-1 view

**File:** `src/node/node.cpp` · **Symbol:** `Node::start_contrib_phase` (≈822-874).

Today only `f2_inbound_view` is built (lines 860-869). Add the symmetric eq/abort
view capture, height-gated on `chain_.f2_active_from_height()`, hashed via
`hash_equivocation_event` / `hash_abort_event`, sorted, capped at
`F2_VIEW_LIST_CAP` (=64, `producer.hpp:212`):

```cpp
std::vector<Hash> f2_eq_view, f2_abort_view;
if (block_index >= chain_.f2_active_from_height()) {
    for (const auto& e : pending_equivocation_evidence_)
        f2_eq_view.push_back(hash_equivocation_event(e));
    std::sort(f2_eq_view.begin(), f2_eq_view.end());
    if (f2_eq_view.size() > F2_VIEW_LIST_CAP) f2_eq_view.resize(F2_VIEW_LIST_CAP);

    for (const auto& a : current_aborts_)        // same source build_body bakes
        f2_abort_view.push_back(hash_abort_event(a));
    std::sort(f2_abort_view.begin(), f2_abort_view.end());
    if (f2_abort_view.size() > F2_VIEW_LIST_CAP) f2_abort_view.resize(F2_VIEW_LIST_CAP);
}
ContribMsg my_contrib = make_contrib(key_, cfg_.domain, block_index, prev_hash,
                                     current_aborts_.size(), snap, my_commit,
                                     f2_eq_view, f2_abort_view, f2_inbound_view);
```

`make_contrib` already canonicalizes + roots + binds these (no change there). The
`on_contrib` sig-verify path already threads all three roots
(`node.cpp:2109-2113`), so committed eq/abort roots now verify.

**Critical constraint (do NOT change):** the equivocation *detection* path in
`on_contrib` (`node.cpp:2171-2176`) must keep comparing the **v1 CORE commit**
(`make_contrib_commitment(block_index, prev_hash, tx_hashes, dh_input)` with no
view roots), NOT the F2-bound commit. A member's eq/abort pool view legitimately
varies across re-rounds at the same height (fresh evidence arrives); comparing the
full view-bound commit would false-positive an honest member that refreshed its
view as a self-equivocator. This is the same load-bearing carve-out that exists
for inbound today; the comment at `node.cpp:2161-2170` already documents it and
must remain valid.

### Step 1 — add per-creator eq/abort LISTS to the Block

**File:** `include/determ/chain/block.hpp` · **after line 416**
(`creator_view_inbound_lists`).

```cpp
// v2.7 F2 / S-030-D2 (eq/abort dimension): per-creator eq/abort view LISTS
// (the hashes behind creator_view_eq_roots[i] / creator_view_abort_roots[i]).
// Carried so the validator can re-derive reconcile_union and enforce that
// equivocation_events / abort_events are the committee-wide union. Authenticated:
// root[i] == compute_view_root(list[i]) and root[i] is bound into creator i's
// signed Phase-1 commit. Empty for pre-F2 / non-evidence blocks.
std::vector<std::vector<Hash>>    creator_view_eq_lists;
std::vector<std::vector<Hash>>    creator_view_abort_lists;
```

### Step 2 — JSON serialize/restore the new lists

**File:** `src/chain/block.cpp` · **`to_json`** inside the existing
`if (any_view_root)` block (≈407-425, after `creator_view_inbound_lists`),
and **`from_json`** after line 538.

`to_json` — mirror the inbound-lists emission (block.cpp:418-424):

```cpp
json jvel = json::array();
for (auto& list : creator_view_eq_lists) {
    json one = json::array();
    for (auto& h : list) one.push_back(to_hex(h));
    jvel.push_back(one);
}
j["creator_view_eq_lists"] = jvel;
// identical block for creator_view_abort_lists -> j["creator_view_abort_lists"]
```

`from_json` — mirror block.cpp:533-539 with two new conditional reads keyed on
`creator_view_eq_lists` / `creator_view_abort_lists`. Backward-compat is automatic:
the keys are emitted only inside `if (any_view_root)`, and a non-zero eq/abort root
forces `any_view_root` true via the existing scan at block.cpp:404-406.

### Step 3 — reconcile eq/abort in `build_body`

**File:** `src/node/producer.cpp` · **Symbol:** `build_body` (694-907).

(a) In the per-creator loop (717-728), carry the two new lists alongside
`creator_view_inbound_lists` (line 727):

```cpp
b.creator_view_eq_lists.push_back(c.view_eq_list);
b.creator_view_abort_lists.push_back(c.view_abort_list);
```

(b) Replace the direct assignments at lines 712-713 with f2-gated reconciliation.
Keep the pre-F2 path byte-identical (assembler's local pool as today):

```cpp
bool f2_active = (b.index >= chain.f2_active_from_height());
if (f2_active) {
    // canonical union of the K committed Phase-1 eq/abort views.
    std::set<Hash> eq_union, abort_union;
    { auto u = reconcile_union(b.creator_view_eq_lists);    eq_union.insert(u.begin(), u.end()); }
    { auto u = reconcile_union(b.creator_view_abort_lists); abort_union.insert(u.begin(), u.end()); }
    // materialize hashes -> structs from the local pools, in canonical hash order.
    b.equivocation_events.clear();
    for (auto& e : equivocation_events)
        if (eq_union.count(hash_equivocation_event(e))) b.equivocation_events.push_back(e);
    b.abort_events.clear();
    for (auto& a : aborts)
        if (abort_union.count(hash_abort_event(a))) b.abort_events.push_back(a);
} else {
    b.abort_events        = aborts;             // v1 path, unchanged
    b.equivocation_events = equivocation_events;
}
```

Note this is the inbound pattern in reverse direction (filter-down rather than
filter-in), and it must be ordered **after** the per-creator loop populates
`b.creator_view_eq_lists` / `b.creator_view_abort_lists`. Move the eq/abort
assignment out of lines 712-713 to here.

**Materialization caveat (the one real risk — see §3.3).** The union may contain a
hash for an event the assembler's local pool lacks. Such a hash is dropped by the
filter above. This is acceptable *only if* the gossip/validity layer guarantees
that any event in a committed Phase-1 view is also present in the assembler's pool
(it must be — the event had to pass V10/V11 and gossip to be committed by any
member). The producer must not invent a struct from a bare hash. See §3.3 for the
verdict's Risk-2 resolution and the validator-side consequence.

### Step 4 — leave `make_contrib` and `derive_canonical_view_lists` unchanged

No change. `make_contrib` already roots+binds eq/abort
(`producer.cpp:659-664, 668-670`); `derive_canonical_view_lists` already unions
eq/abort (`producer.cpp:452-453`).

### Step 5 — bind the reconciled eq/abort sets into `compute_block_digest`

**File:** `src/node/producer.cpp` · **Symbol:** `compute_block_digest` (577-606),
immediately after the inbound binding (598-604):

```cpp
// v2.7 F2 / S-030-D2: bind the reconciled equivocation/abort UNION into the
// digest so the K-of-K block sig attests to the exact set, closing the removal
// gap (a relayer cannot STRIP an event after signing — the two versions would
// otherwise share a digest). Skipped (no append) when empty, so v1 / non-evidence
// blocks keep a byte-identical digest. Order: inbound, then eq, then abort.
if (!b.equivocation_events.empty()) {
    std::vector<Hash> ekeys;
    ekeys.reserve(b.equivocation_events.size());
    for (auto& e : b.equivocation_events) ekeys.push_back(hash_equivocation_event(e));
    h.append(compute_view_root(ekeys));
}
if (!b.abort_events.empty()) {
    std::vector<Hash> akeys;
    akeys.reserve(b.abort_events.size());
    for (auto& a : b.abort_events) akeys.push_back(hash_abort_event(a));
    h.append(compute_view_root(akeys));
}
```

`compute_view_root` sorts internally (`producer.cpp:335-340`), so append order of
events within a field is irrelevant; the fixed field order (inbound, eq, abort) is
what must be stable across producer and validator. The empty-skip preserves the v1
digest exactly.

### Step 6 — validator enforcement

**File:** `src/node/validator.cpp` · new `check_eqabort_reconciliation(b, chain)`,
modeled on `check_inbound_receipts` (1132-1187), called from the block-validate
pipeline next to the inbound check, gated on `b.index >=
chain.f2_active_from_height()`.

```cpp
if (b.index >= chain.f2_active_from_height()) {
    // shape: lists sized to committee when present.
    if (!b.creator_view_eq_lists.empty()    && b.creator_view_eq_lists.size()    != b.creators.size())
        return {false, "F2: creator_view_eq_lists size != creators size"};
    if (!b.creator_view_abort_lists.empty() && b.creator_view_abort_lists.size() != b.creators.size())
        return {false, "F2: creator_view_abort_lists size != creators size"};
    // authenticate each list against its committed root (compute_view_root).
    for (size_t i = 0; i < b.creator_view_eq_lists.size(); ++i) {
        Hash root = (i < b.creator_view_eq_roots.size()) ? b.creator_view_eq_roots[i] : Hash{};
        if (compute_view_root(b.creator_view_eq_lists[i]) != root)
            return {false, "F2: creator_view_eq_lists[" + std::to_string(i) + "] != committed root"};
    }
    // identical loop for abort lists vs creator_view_abort_roots.
    // re-derive the canonical UNION and require block fields to equal it exactly.
    std::vector<Hash> eq_canon    = reconcile_union(b.creator_view_eq_lists);
    std::vector<Hash> abort_canon = reconcile_union(b.creator_view_abort_lists);
    std::set<Hash> eq_set(eq_canon.begin(), eq_canon.end());
    std::set<Hash> abort_set(abort_canon.begin(), abort_canon.end());
    if (b.equivocation_events.size() != eq_set.size())
        return {false, "F2: equivocation_events count != reconcile_union"};
    for (auto& e : b.equivocation_events)
        if (!eq_set.count(hash_equivocation_event(e)))
            return {false, "F2: equivocation_events contains event outside committee union"};
    if (b.abort_events.size() != abort_set.size())
        return {false, "F2: abort_events count != reconcile_union"};
    for (auto& a : b.abort_events)
        if (!abort_set.count(hash_abort_event(a)))
            return {false, "F2: abort_events contains event outside committee union"};
}
```

The exact-cardinality + exact-membership test (vs the inbound *subset* test) is the
point: under UNION the block must carry **every** event in the committee union, not
a subset. Combined with the digest binding (step 5) this is what prevents a signed
removal. Per-creator roots are already authenticated by `creator_ed_sigs` in
`check_creator_tx_commitments` (validator.cpp:166-170), so no separate root sig
check is needed — the `compute_view_root` equality above ties each *list* to its
already-sig-bound root.

Optionally route through the existing `validate_view_reconciliation`
(producer.cpp:458-496) instead of open-coding, passing
`b.equivocation_events`-derived hashes etc.; it already implements V25/V26. The
open-coded form above is preferred for symmetry with `check_inbound_receipts` and
to avoid re-hashing through the F2CanonicalViews struct.

---

## 3. Gossip-async safety argument (the gate)

**Verdict: SAFE.** UNION may be bound into the digest. The gossip-async failure
mode that killed the *naive* digest extension (S030-D2-Analysis §2) does **not**
apply here, for the same structural reason the shipped inbound binding is safe.

### 3.1 Why the naive extension was fatal

S030-D2-Analysis §2 (lines 57-77): the naive patch hashed each member's *local
tentative pool view* into the digest. Pools are gossip-fed, so members A and B hold
different `equivocation_events` at their commit instants, compute different
digests, and K signatures never gather. The round aborts; under recurring gossip
drift the chain stalls. The equivocation-slashing regression reproduced this.

### 3.2 Why this design is safe

The digest does **not** bind any member's local pool view. It binds
`reconcile_union(b.creator_view_eq_lists)` / `reconcile_union(b.creator_view_abort_lists)`
— a pure function of the **K signed Phase-1 commits**, computed at the Phase-1→2
boundary, *before* digesting. The argument is a four-step chain, each link verified:

1. **Members commit views, not the digest, in Phase-1.** Each creator binds its own
   `view_eq_root`/`view_abort_root` into its signed `make_contrib_commitment`
   (producer.cpp:668-670). Gossip-async divergence is fully expressed *here* and is
   harmless: divergent views produce divergent roots, but each member only signs its
   *own* root. No agreement on views is required at Phase-1.
2. **Reconciliation is a deterministic pure function of the committed set.**
   `reconcile_union` (producer.cpp:345-351) is `std::set`-based: commutative,
   associative, idempotent, order-independent (F2ViewReconciliationAnalysis.md
   T-1/T-3/T-4). Two honest assemblers with the *same K signed ContribMsgs* compute
   the *identical* canonical union — byte-for-byte, regardless of arrival order or
   local pool state.
3. **The K signed commits are identical across honest members at Phase-2.** By the
   time the digest is computed, every honest member has gathered the same K Phase-1
   commits (this is already required to compute `tx_root`/`creator_tx_lists`, which
   the v1 digest binds — producer.cpp:581 (`tx_root`) + 586-587 (`creator_tx_lists`)).
   The eq/abort lists ride in those same
   commits. So the *input* to `reconcile_union` is identical across honest members ⇒
   the *output* (and thus the digest) is identical ⇒ K signatures gather.
4. **Phase-2 signs the reconciled list, not a member's view (F2-SPEC §Q5).** A member
   may sign a union containing an event it did not personally observe; this is sound
   because (a) the event is individually verifiable via V10/V11 from event data alone,
   and (b) some member is bound to it via that member's committed root. The signer
   attests "the union of the K committed views includes this event and it passes
   V10/V11," not "I observed it." This is exactly the inbound Phase-2 semantics,
   transposed from intersection to union.

The decisive difference from the naive fix: **reconciliation moved the
divergence-absorbing boundary to Phase-1 (per-member, harmless) and made the
digest a function of the post-reconciliation canonical set (committee-agreed).**
The naive fix digested the pre-reconciliation per-member set.

### 3.3 The one residual risk and its resolution (verdict Risk-2)

The producer materializes structs from the union of hashes (step 3, build_body). If
a hash is in the union but the assembler's local pool lacks the struct, the
assembler cannot emit the event. Resolution:

- The assembler **drops** unknown-hash events (the filter in step 3), never
  fabricates a struct from a bare hash.
- This is safe because the union is built from `b.creator_view_eq_lists` — the K
  *committed* views. An event reached a committed view only by passing V10/V11 and
  gossiping to that member; under the protocol's gossip assumptions the assembler
  (itself a committee member) will hold the struct by Phase-2. If, under pathological
  partition, it does not, the assembler's produced block fails its *own* step-6
  cardinality check (it carries fewer events than the union) and is simply not
  produced — the round re-runs, no stall, no invalid block. This is a **liveness**
  degradation under partition, never a safety violation.
- F2-SPEC chose hashes (not full serialized events) in ContribMsg for bandwidth
  (§Q3). This design preserves that choice and pushes the struct-availability
  requirement onto the gossip layer, identical to the inbound treatment. If a future
  measurement shows the partition liveness cost is real, the fallback is to carry
  serialized events in ContribMsg for the eq/abort fields only (bandwidth hit,
  removes the materialization dependency) — but that is **not** required for safety
  and is out of scope here.

### 3.4 Forensic-field provenance (verdict Risk-5, eq only)

`hash_equivocation_event` includes `shard_id` and `beacon_anchor_height`
(producer.cpp:292-293). The same equivocation observed at two provenance points
hashes differently and both copies land in the union. This is **acceptable and
intended**: they are independent witnesses to the same misbehavior, and the apply
path (FA-Apply-10) slashes the equivocator once regardless (the apply keys on the
equivocator identity, not the event hash). Do **not** zero-normalize the forensic
fields — that would erase the audit trail and is unnecessary, because union
inclusion of redundant witnesses is harmless and bounded by `F2_VIEW_LIST_CAP`.
(This differs from the design-lens recommendation to zero-norm; the apply-layer
idempotence makes normalization unnecessary, and the audit trail is worth keeping.)

### 3.5 Conditional summary

| Condition | Safe to bind UNION into digest? |
|---|---|
| Reconciliation from K signed Phase-1 commits, then digest (this design) | **Yes** |
| Digest extended over assembler's local pre-reconciliation pool (naive) | No — stalls under gossip drift |
| Per-creator eq/abort lists NOT carried in Block (validator can't re-derive) | No — validator cannot enforce; binding is unauthenticated |
| Phase-1 eq/abort views never populated (step 0 skipped) | Degenerate-safe but useless — roots stay zero, union empty, digest unchanged; closes nothing |

The design is in row 1 only if **all** of steps 0, 1, 3, 5, 6 land together.

---

## 4. Test plan + build/verify gate

### 4.1 New regression: `tools/test_f2_eqabort_reconciliation.sh`

3-node cluster, F2 active (`v2_7_f2_active_from_height` pinned low in the test
genesis). Mirrors the inbound reconciliation test and the existing
`tools/test_equivocation_slashing.sh` cluster harness.

1. **Divergent-view convergence (union).** Inject equivocation evidence so node-1
   observes `{e1}`, node-2 observes `{e1,e2}`, node-3 observes `{e2}`. Assert the
   produced block's `equivocation_events == {e1,e2}` (union), the digest binds both,
   K-of-K signatures gather (no stall), FA-Apply-10 slashes both equivocators, and the
   A1 supply invariant closes (`chain.cpp:1395-1399`).
2. **Abort union.** Same pattern with Phase-1 `AbortEvent`s; assert union inclusion,
   FA-Apply-11 proportional slash for round-1 aborts, and that round-2 aborts present
   in the union are carried but **not** slashed (T-A2, `chain.cpp:1314` gate).
3. **Silent-node tolerance.** Drop node-3; assert the union of node-1+node-2 views is
   still bound and the block finalizes (one honest observer suffices — censorship
   resistance).
4. **Digest-removal attack.** Post-sign, strip an event from a block instance and
   re-gossip; assert validator `check_eqabort_reconciliation` rejects (cardinality
   mismatch) AND the digest no longer matches the K-of-K signatures.
5. **State-root consistency.** Assert all three nodes compute identical post-apply
   `state_root` (S-033) for the canonical block.

### 4.2 Backward-compat regression

- **Pre-F2 byte-identity.** A block produced below `f2_active_from_height` must have
  a byte-identical digest and JSON to the pre-change build. Verify
  `test_state_root_determinism.sh`, `test_snapshot_full_determinism.sh`, and the
  existing equivocation/abort apply tests stay green:
  `tools/test_equivocation_apply.sh`, `tools/test_abort_event_apply.sh`,
  `tools/test_equivocation_slashing.sh`, `tools/test_equivocation_evidence.sh`,
  `tools/test_equivocation_multi.sh`, `tools/test_abort_reselection.sh`.
- **Empty-field skip.** A block at/after F2 with no eq/abort events must skip the
  digest append (empty-guard) and keep the v1 digest — assert against an F2-active
  block with empty evidence.

### 4.3 Pre-flag-day dry-run (de-risk the digest change)

Per S030-D2-Analysis-style caution: ship the validator's
`check_eqabort_reconciliation` in **log-only** mode first (compute the canonical
union and log any mismatch without rejecting) for a soak window, then flip to
hard-reject at the genesis-pinned activation height. This catches any
producer/validator hashing or ordering skew before it can stall the chain.

### 4.4 Build/verify gate

- WSL2 Ubuntu: clean build (`determ`, `determ-wallet`, `determ-light`).
- `bash -n tools/test_f2_eqabort_reconciliation.sh`; add it to `run_all.sh` and the
  `FAST=1` regex; add the help-text line.
- Run the new test + the §4.2 backward-compat set as a cluster pass.
- Bump the shell-test count across the doc surfaces and add the test name to
  UNIT-TESTS / SECURITY / CLI-REFERENCE per the standard threading rule.

---

## 5. GO / NO-GO recommendation

**GO — bind the reconciled UNION into the digest.**

The gossip-async safety gate is passed: reconciliation is a pure deterministic
function of the K signed Phase-1 commits, computed before digesting, so honest
members converge on one digest exactly as they do for `tx_root` and for the shipped
inbound dimension (S030-D2-Analysis §4 item 7 affirms the inbound fix is sound and
shipped; this design round's adversarial gossip-async verification confirmed the
same property holds for the UNION rule). This is *not* the naive digest extension
that was reverted —
that hashed pre-reconciliation per-member pools; this hashes the post-reconciliation
committee-agreed set.

The change is well-scoped and low-risk because most of the machinery is already
shipped for inbound: the only genuinely new logic is (a) populating the eq/abort
Phase-1 view (step 0, ~15 LOC), (b) two Block list fields + their JSON (steps 1-2),
(c) the union reconciliation in build_body (step 3, ~20 LOC), (d) the digest append
(step 5, ~12 LOC), and (e) the validator enforcement (step 6, ~35 LOC). All reuse
existing, tested primitives (`reconcile_union`, `compute_view_root`,
`hash_equivocation_event`, `hash_abort_event`).

Conditions on GO (all mandatory):

1. Land steps 0,1,3,5,6 **atomically** behind the `f2_active_from_height` flag-day
   gate. Partial deployment (e.g. digest binding without the Phase-1 view, or
   validator enforcement without producer reconciliation) can stall the chain.
2. Keep the `on_contrib` equivocation *detection* on the v1 CORE commit
   (node.cpp:2171-2176) — do not bind detection to the view-bound commit.
3. Use **exact-cardinality + exact-membership** validation for the union (§2 step 6),
   not the inbound subset test — under UNION the block must carry the whole committee
   union.
4. Ship the validator check log-only first (§4.3), then flip to hard-reject.
5. Do **not** zero-normalize equivocation forensic fields (§3.4).

**Fallback if any condition cannot be met (NO-GO on digest binding):** if the
flag-day atomicity or the struct-materialization availability (§3.3) cannot be
guaranteed for a given deployment, do **not** bind eq/abort into the digest. Fall
back to the **apply-layer-only** closure that already ships: S-033 state_root
binding (S030-D2-Analysis §3.5) makes two divergent eq/abort sets fail apply on
honest nodes (state divergence narrows to zero blocks, detected at apply-time
loud-fail). For permissioned/consortium threat models that exclude two-instance
fully-Byzantine committees, S-033 is functionally equivalent and this consensus-layer
extension is optional. The consensus-layer UNION binding is the structural fix
needed only for permissionless deployments wanting the literal "no two K-of-K-signed
bodies per height" property.
