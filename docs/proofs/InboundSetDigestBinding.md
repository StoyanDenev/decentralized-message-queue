# Inbound-set digest binding — S-030 D2 removal-gap closure (inbound dimension)

This document formalizes the inbound-set digest binding shipped in commit `a727cb2`: the extension of `compute_block_digest` (`src/node/producer.cpp:577-606`) that appends a single Merkle root over the sorted `hash_cross_shard_receipt` keys of `inbound_receipts` into the K-of-K block-signature target — closing the S-030 D2 *removal gap* for the inbound dimension. Pre-`a727cb2`, the inbound-receipt set was bound only structurally (via `check_inbound_receipts`' subset-only intersection test) and via `signing_bytes`/`state_root`, but **not** by the digest the K committee signers actually sign; a relayer could therefore strip an admitted inbound receipt after the K-of-K signatures gathered, and the two block instances would share an identical `block_digest` (and so an identical valid K-of-K signature bundle). This proof shows the one-line digest append closes that gap at the strongest (signature) layer.

The four theorems below pin the contract:

1. **(T-1) Order-independent binding.** The appended root is a function of the *set* of admitted-receipt keys, not their order in `b.inbound_receipts`, because `compute_view_root` set-coerces (sort + dedup) before hashing.
2. **(T-2) Empty-set short-circuit preserves the v1 digest.** When `b.inbound_receipts` is empty (every non-cross-shard block, and every SINGLE/BEACON chain), no bytes are appended and the digest is byte-identical to the pre-`a727cb2` (v1) digest. The change is a pure no-op on non-cross-shard blocks.
3. **(T-3) Producer / validator digest agreement ⇒ post-signing strip is detectable.** Producer and validator compute the digest through the *same* `compute_block_digest` symbol over the same `Block`. A relayer who strips (or substitutes, or reorders into a different set) an admitted receipt after K-of-K signing changes the appended root, hence the digest, hence breaks Ed25519 verification of every gathered signature — the validator rejects.
4. **(T-4) Composition with the inbound intersection (sites 1+3) ⇒ the bound set is the deterministic committee-wide intersection.** The set whose root is digested is exactly the `reconcile_intersection` of the committee's committed Phase-1 inbound views — not the producer's local timing-dependent choice — so the K-of-K signature attests to a value the rule (not the proposer) determines.

The proof is short and structural: the digest extension is gated on a single `!b.inbound_receipts.empty()` short-circuit, and the appended content is one 32-byte root produced by an order-independent pure function. The cryptographic content (a relayer cannot find a different set with the same root, nor forge a fresh K-of-K bundle over the new digest) reduces to A1 (Ed25519 EUF-CMA) + A2 (SHA-256 collision / 2nd-preimage resistance). The proof exists so an external reviewer can confirm — without re-running the cross-shard suite — that the inbound dimension of the S-030 D2 removal gap is closed at the signature layer, byte-for-byte against the shipped code.

**Companion documents:** `Preliminaries.md` (F0) for notation and the cryptographic assumptions A1 (Ed25519 EUF-CMA) and A2 / §2.1 (SHA-256 collision + 2nd-preimage resistance); `S030-D2-Analysis.md` §2 for why a *naive* multi-field digest extension is fatal (gossip-async tentative-body divergence stalls the round) and §3.5 for the per-field closure map; `F2ViewReconciliationAnalysis.md` (the reconciliation primitives this composes with, esp. T-6 IntersectionConservative); `MakeContribCommitmentBackwardCompat.md` (the paired Phase-1 commit-binding step that binds each member's *view* root); `F2-SPEC.md` §Q1 (the union-for-evidence / intersection-for-receipts asymmetry that scopes this proof to the inbound dimension); `EqAbortViewDigestExtension.md` (the union-rule sibling). The equivocation/abort dimensions are not closed by *this* binding but are closed by their sibling (commit `48c4b45`) via the same structural pattern; see §5.

---

## 1. Theorem statements

**Setup.** Let `Block b` be a candidate block as defined in `include/determ/chain/block.hpp`. Let `R := b.inbound_receipts` be its inbound-receipt vector (each element a `chain::CrossShardReceipt`). Let `key(r) := hash_cross_shard_receipt(r)` (`src/node/producer.cpp:312-326`) — the domain-separated SHA-256 over the receipt's `"DTM-F2-RCPT-v1"` tag ‖ `src_shard` ‖ `dst_shard` ‖ `src_block_index` ‖ `src_block_hash` ‖ `tx_hash` ‖ `from` ‖ `to` ‖ `amount` ‖ `fee` ‖ `nonce`. Let `keys(R) := [ key(R[0]), …, key(R[n-1]) ]` and `set(keys(R)) := { key(r) : r ∈ R }` (duplicates collapse).

Let `vr(R) := compute_view_root(keys(R))` (`src/node/producer.cpp:335-340`) — the canonical Merkle root over the sorted-deduped key set.

Let `digest_v1(b)` denote the pre-`a727cb2` block digest: an `SHA256Builder` fed, in order, with
`b.index ‖ b.prev_hash ‖ b.tx_root ‖ b.delay_seed ‖ uint8(b.consensus_mode) ‖ b.bft_proposer ‖ (b.creators[i])_i ‖ (b.creator_tx_lists[i][j])_{i,j} ‖ (b.creator_ed_sigs[i])_i ‖ (b.creator_dh_inputs[i])_i`,
then `finalize()` (`src/node/producer.cpp:578-589,605`). Let `digest_v2(b)` denote the shipped `compute_block_digest(b)` at `:577-606`, which is `digest_v1`'s byte stream followed, **iff** `R` is non-empty, by one extra `h.append(vr(R))` (`:598-604`).

**Theorem T-1 (Order-independent binding).** For every `Block b` and every permutation `σ` of `b.inbound_receipts` into `b'` (`b'` equal to `b` in all fields except `b'.inbound_receipts = σ(b.inbound_receipts)`, with `set(keys(b'.inbound_receipts)) = set(keys(b.inbound_receipts))`):

$$
\mathrm{compute\_block\_digest}(b) \;=\; \mathrm{compute\_block\_digest}(b').
$$

The appended root is a function of the admitted-key *set*, not its vector order.

**Theorem T-2 (Empty-set short-circuit preserves the v1 digest).** For every `Block b` with `b.inbound_receipts.empty()`:

$$
\mathrm{compute\_block\_digest}(b) \;=\; \mathrm{digest\_v1}(b).
$$

Every non-cross-shard block — including all blocks on a SINGLE/BEACON chain (`chain.shard_count() <= 1`, where `inbound_receipts` is required empty by `check_inbound_receipts`, `src/node/validator.cpp:1136-1140`) — keeps a byte-identical pre-`a727cb2` digest. The change is a strict no-op on the v1 surface.

**Theorem T-3 (Producer / validator digest agreement ⇒ post-signing strip is detectable).** Let `b` be a block with non-empty `inbound_receipts` whose K-of-K signature bundle `(σ_i)` verified at production time, i.e. for every signing creator `i`, `verify(pk_i, digest_v2(b), σ_i) = true` (`src/node/validator.cpp:442-456`). Let a relayer transform `b` into `b*` by stripping, adding, substituting, or otherwise altering `inbound_receipts` such that `set(keys(b*.inbound_receipts)) ≠ set(keys(b.inbound_receipts))` (with all other digested fields unchanged). Then under A2,

$$
\Pr\!\bigl[\mathrm{compute\_block\_digest}(b^*) = \mathrm{compute\_block\_digest}(b)\bigr] \;\leq\; 2^{-128} + \mathrm{negl}(\lambda),
$$

and consequently, except with that negligible probability, every gathered `σ_i` fails `verify(pk_i, digest_v2(b*), σ_i)`. The relayer cannot produce a fresh valid bundle over `digest_v2(b*)` without forging at least K − (sentinel slack) Ed25519 signatures, which is infeasible under A1.

**Theorem T-4 (Composition: the bound set is the deterministic committee-wide intersection).** When F2 is active (`b.index >= chain.f2_active_from_height()`) and `b` is accepted by `check_inbound_receipts` (`src/node/validator.cpp:1168-1185`), the set `set(keys(b.inbound_receipts))` whose root `vr` is bound into `digest_v2` satisfies

$$
\mathrm{set}(\mathrm{keys}(b.\mathrm{inbound\_receipts})) \;\subseteq\; \mathrm{set}\bigl(\mathrm{reconcile\_intersection}(b.\mathrm{creator\_view\_inbound\_lists})\bigr),
$$

where `creator_view_inbound_lists` are the committee's Phase-1-committed inbound views (each authenticated against its signed `creator_view_inbound_roots[i]`). Therefore the digest binds a set determined by the committee-wide intersection rule (sites 1+3), not by the producer's local first-seen timing. The digest binding (this proof) and the intersection rule (sites 1+3) together make the inbound set both *rule-determined* and *signature-attested*.

---

## 2. Background

### 2.1 S-030 D2 — the block-digest field-coverage gap (inbound slice)

S-030 D2 (per `S030-D2-Analysis.md` §1) is the gap that the K-of-K committee signature target — `compute_block_digest` — historically excluded the pool-fed evidence and receipt lists (`equivocation_events`, `abort_events`, `inbound_receipts`), even though `Block::signing_bytes` covers them. The exclusion left a one-block window in which two valid K-of-K-signed block instances could differ in those fields behind the same digest. The original source comment at `:565-576` records this and warns that a *naive* digest extension does not work because gossip-async view drift makes members' tentative bodies diverge, so the K signatures never gather and the round stalls.

`S030-D2-Analysis.md` §2 makes the failure mode precise: if `compute_block_digest` simply appended each member's *locally observed* evidence/receipt pool, two honest members with momentarily different gossip views would compute different digests, sign different targets, and the K-of-K gather would fail. The naive extension trades a safety gap for a liveness failure.

The inbound dimension escapes the §2 trap because of a structural precondition that the evidence dimensions now share too: **the admitted inbound set is the deterministic committee-wide reconciliation computed *before* digesting**, not each member's raw local view. Sites 1+3 of the v2.7 F2 wiring (commits `850d2c3` + `c16d6c3`) ensure that the value fed into the digest is `reconcile_intersection` over the committee's *committed* Phase-1 views — a function of the K signed contribs, identical on every honest re-derivation by `F2ViewReconciliationAnalysis.md` T-3 (OrderIndependent) + T-6 (IntersectionConservative). Because every honest member computes the same admitted set, they all compute the same `vr`, the same digest, and the K-of-K gather succeeds. The `a727cb2` digest append is therefore safe *only in composition with* sites 1+3 — T-4 makes that dependency explicit.

This asymmetry is load-bearing and is exactly why `F2-SPEC.md` §Q1 assigns **intersection** to inbound receipts (unanimous observation) and **union** to equivocation/abort evidence (one honest observer suffices). The intersection rule yields a committee-wide-agreed set that is safe to digest. The **union** rule now has the analogous pre-digest canonicalization wired in as well (commit `48c4b45` — `reconcile_union` over the committee's committed eq/abort views, computed before digesting, with subset-membership validation + zero-root v1-sentinel handling; see `EqAbortViewDigestExtension.md`). This proof scopes to the inbound dimension for clarity, but all three pool-fed dimensions are now consensus-layer-bound by the same structural argument (a pure reconciliation function of the K signed Phase-1 commits, digested downstream).

### 2.2 The subset-only residual the digest closes

Even after sites 1+3, `check_inbound_receipts` (`src/node/validator.cpp:1168-1185`) enforces only a **subset** relationship: every admitted receipt's key must lie *inside* `reconcile_intersection`. It does **not** enforce that the admitted set equals the intersection, nor that the producer included every eligible receipt. This is by design — a producer may legitimately admit fewer receipts than the intersection allows (e.g. ones already credited in an earlier block are filtered at `:899` / `:1156-1158`). But the subset-only test has a corollary attack surface: a relayer can *remove* an admitted receipt from `b.inbound_receipts` after the K-of-K signatures gather and the shrunk set still passes the subset test (a subset of a subset is a subset). Pre-`a727cb2`, that stripped block carried the *same* `compute_block_digest` value as the original — so the same K-of-K signatures verified against it. The receiving shard would then never credit the stripped receipt, silently dropping a cross-shard transfer that the committee had attested. The `:590-597` source comment names this precisely: *"check_inbound_receipts' intersection test is subset-only — so without this a relayer could STRIP an inbound receipt after signing and the two versions would share a digest (the S-030-D2 removal gap)."* T-3 is the formal statement that the digest append closes it.

---

## 3. Implementation

### 3.1 `hash_cross_shard_receipt` — the per-receipt key

```cpp
// src/node/producer.cpp:312-326
Hash hash_cross_shard_receipt(const chain::CrossShardReceipt& r) {
    SHA256Builder b;
    b.append(std::string("DTM-F2-RCPT-v1"));
    b.append(static_cast<uint64_t>(r.src_shard));
    b.append(static_cast<uint64_t>(r.dst_shard));
    b.append(r.src_block_index);
    b.append(r.src_block_hash);
    b.append(r.tx_hash);
    b.append(r.from);
    b.append(r.to);
    b.append(r.amount);
    b.append(r.fee);
    b.append(r.nonce);
    return b.finalize();
}
```

**Contract.** `key(r)` is a domain-separated (`"DTM-F2-RCPT-v1"`) SHA-256 commitment to every economically-meaningful field of the receipt. Two receipts differing in any field produce different keys (modulo A2). The same `key` function is called at the producer's intersection filter (`:901`), the producer's digest append (`:602`), and the validator's intersection check (`:1181`) — one symbol, no re-implementation.

### 3.2 `compute_view_root` — the order-independent set root

```cpp
// src/node/producer.cpp:335-340
Hash compute_view_root(const std::vector<Hash>& items) {
    std::set<Hash> u(items.begin(), items.end());
    SHA256Builder b;
    for (auto& h : u) b.append(h);
    return b.finalize();
}
```

Line `336` set-coerces (dedup + canonical lexicographic sort via `std::set<Hash>`'s strict-weak-ordering on the inherited `operator<` of `std::array<uint8_t,32>`, per `[array.syn]` / `[lex.compare]`). The range-for at `:338` iterates `u` in non-descending key order (`[associative.reqmts]`) and feeds each 32-byte hash deterministically into `SHA256Builder::append`. The output is a function of `set(items)` alone — see `F2ViewReconciliationAnalysis.md` §3.1 for the full determinism argument and T-3 for the order-independence statement this proof reuses.

### 3.3 The digest extension (the object of this proof)

```cpp
// src/node/producer.cpp:577-606
Hash compute_block_digest(const Block& b) {
    SHA256Builder h;
    h.append(b.index);
    h.append(b.prev_hash);
    h.append(b.tx_root);
    h.append(b.delay_seed);
    h.append(static_cast<uint8_t>(b.consensus_mode));
    h.append(b.bft_proposer);
    for (auto& c : b.creators) h.append(c);
    for (auto& list : b.creator_tx_lists)
        for (auto& tx : list) h.append(tx);
    for (auto& s : b.creator_ed_sigs) h.append(s.data(), s.size());
    for (auto& d : b.creator_dh_inputs) h.append(d);
    // v2.7 F2 / S-016: bind the admitted inbound-receipt set into the digest …
    if (!b.inbound_receipts.empty()) {
        std::vector<Hash> ikeys;
        ikeys.reserve(b.inbound_receipts.size());
        for (auto& r : b.inbound_receipts)
            ikeys.push_back(hash_cross_shard_receipt(r));
        h.append(compute_view_root(ikeys));
    }
    return h.finalize();
}
```

**Mechanism.** The first ten `append` calls (`:579-589`) are exactly the pre-`a727cb2` (v1) byte stream — unchanged. The conditional at `:598` gates the new behavior on `!b.inbound_receipts.empty()`. When the gate fires, `:599-602` build `ikeys = [ key(R[0]), …, key(R[n-1]) ]` in receipt-vector order, and `:603` appends a single 32-byte `compute_view_root(ikeys)` = `vr(R)` to the same builder. When the gate does not fire, the builder reaches `finalize()` at `:605` having consumed only the v1 stream. The append is a single fixed-width 32-byte field, unambiguously positioned as the final segment of the pre-image whenever present.

### 3.4 Producer- and validator-side intersection enforcement (sites 1+3 context for T-4)

```cpp
// src/node/producer.cpp:891-904  (producer build_body, site 3 admit-filter)
bool f2_active = (b.index >= chain.f2_active_from_height());
std::set<Hash> f2_inbound_intersection;
if (f2_active) {
    auto isect = reconcile_intersection(b.creator_view_inbound_lists);
    f2_inbound_intersection.insert(isect.begin(), isect.end());
}
for (auto& r : inbound_receipts) {
    if (r.dst_shard != chain.my_shard_id()) continue;
    if (chain.inbound_receipt_applied(r.src_shard, r.tx_hash)) continue;
    if (f2_active
        && !f2_inbound_intersection.count(hash_cross_shard_receipt(r)))
        continue;
    b.inbound_receipts.push_back(r);
}
```

```cpp
// src/node/validator.cpp:1168-1185  (check_inbound_receipts, site 3 enforce)
if (b.index >= chain.f2_active_from_height() && !b.inbound_receipts.empty()) {
    if (b.creator_view_inbound_lists.size() != b.creators.size())
        return {false, "F2: creator_view_inbound_lists size != creators size"};
    for (size_t i = 0; i < b.creator_view_inbound_lists.size(); ++i) {
        Hash root = (i < b.creator_view_inbound_roots.size())
                  ? b.creator_view_inbound_roots[i] : Hash{};
        if (compute_view_root(b.creator_view_inbound_lists[i]) != root)
            return {false, "F2: … does not match committed root"};
    }
    std::vector<Hash> isect = reconcile_intersection(b.creator_view_inbound_lists);
    std::set<Hash> iset(isect.begin(), isect.end());
    for (size_t i = 0; i < b.inbound_receipts.size(); ++i) {
        if (!iset.count(hash_cross_shard_receipt(b.inbound_receipts[i])))
            return {false, "F2: inbound_receipts[" + std::to_string(i)
                         + "] not in committee-view intersection"};
    }
}
```

The producer admits only receipts whose key is in the intersection (`:900-902`); the validator (a) authenticates each per-creator view list against its committed root via `compute_view_root` (`:1171-1177`), then (b) rejects any admitted receipt whose key is outside `reconcile_intersection` of those authenticated lists (`:1178-1184`). Each `creator_view_inbound_roots[i]` is bound into creator i's Phase-1 Ed25519 commit (verified in `check_creator_*`, per `MakeContribCommitmentBackwardCompat.md`), so the intersection is computed over a *committed* set the producer cannot forge. This is the substrate T-4 composes onto.

---

## 4. Proofs of T-1..T-4

### 4.1 Proof of T-1 (Order-independent binding)

Fix `b` and a permutation `b'` of its `inbound_receipts` with `set(keys(b'.inbound_receipts)) = set(keys(b.inbound_receipts))`. All digested fields except `inbound_receipts` are identical between `b` and `b'`, so the `:579-589` byte stream is identical. For the conditional segment:

- If `b.inbound_receipts` is empty, then `b'.inbound_receipts` is too (a permutation preserves length), and neither appends — digests equal by the empty branch (this reduces to T-2).
- If non-empty, both append `compute_view_root(ikeys)`. By `compute_view_root`'s §3.2 mechanism, the output is a function of `set(ikeys) = set(keys(·))` alone (the `std::set<Hash>` coercion at `:336` erases the vector order before hashing). Since `set(keys(b'.inbound_receipts)) = set(keys(b.inbound_receipts))` by hypothesis, the two appended roots are byte-equal. (Formally this is `F2ViewReconciliationAnalysis.md` T-3 specialized to the within-list, K=1 case.)

In both cases the full pre-image fed to `finalize()` is identical, so the digests are equal.    ∎

**Implementation citation.** `src/node/producer.cpp:336` (set-coerce) + `:599-603` (build keys in receipt order, then root). The reorder cannot reach the digest because the order is destroyed at `:336` before any byte is hashed.

### 4.2 Proof of T-2 (Empty-set short-circuit preserves the v1 digest)

Fix `b` with `b.inbound_receipts.empty()`. The condition at `:598` (`!b.inbound_receipts.empty()`) evaluates false, so the body at `:599-603` is skipped and no byte is appended after the `:589` stream. The builder therefore consumes exactly the `:579-589` byte sequence — which is, by construction, `digest_v1(b)`'s pre-image — before `finalize()` at `:605`. SHA-256 is a deterministic function of its input byte stream (`src/crypto/sha256.cpp`), so `compute_block_digest(b) = digest_v1(b)`.    ∎

**Corollary T-2.1 (no v1-block regression).** Every block produced on a SINGLE/BEACON chain, and every cross-shard-chain block that happens to admit no inbound receipts, hashes byte-identically before and after `a727cb2`. No pre-`a727cb2` block, signature, or stored chain head re-hashes to a different digest. The change is non-breaking on the entire v1 surface; an external client computing block digests by the pre-`a727cb2` field list still matches on every non-cross-shard block.

**Implementation citation.** `src/node/producer.cpp:598` (the gate) + `:1136-1140` of `validator.cpp` (SINGLE/BEACON chains require `inbound_receipts` empty, so the gate provably never fires there).

### 4.3 Proof of T-3 (post-signing strip is detectable)

Let `b` have non-empty `inbound_receipts` and a K-of-K bundle `(σ_i)` that verified at production time against `digest_v2(b)` (`validator.cpp:442-456` loops every non-sentinel creator and requires `verify(pk_i, digest, σ_i)`). Let a relayer produce `b*` with `set(keys(b*.inbound_receipts)) ≠ set(keys(b.inbound_receipts))`, all other digested fields unchanged.

**Step 1 — the appended root changes.** Since `b*` still has non-empty `inbound_receipts` (a strip that emptied it would instead flip to the T-2 branch, changing the digest by *removing* the 32-byte segment — also a change; handled below), the digest append fires for both. By `compute_view_root`'s contract (§3.2; `F2ViewReconciliationAnalysis.md` §3.1 algebraic claim), `vr(b*.inbound_receipts) = vr(b.inbound_receipts)` would require `set(keys(b*.inbound_receipts)) = set(keys(b.inbound_receipts))` *unless* an SHA-256 collision occurred. By hypothesis the sets differ, so equality of roots implies a collision, which under A2 happens with probability ≤ `2^{-128}` per attempt. If instead the strip empties `inbound_receipts`, `digest_v2(b*) = digest_v1(b*)` (T-2), which omits the 32-byte root that `digest_v2(b)` included; the two pre-images then differ in length-and-content, again colliding only with probability ≤ `2^{-128} + negl` under A2 (the 2nd-preimage bound on the differing tail).

**Step 2 — digest inequality breaks every gathered signature.** Whenever `digest_v2(b*) ≠ digest_v2(b)` (the overwhelming-probability event from Step 1), each gathered `σ_i = Sign(sk_i, digest_v2(b))` is a signature over a message *different* from `digest_v2(b*)`. Ed25519 verification (`validator.cpp:455`) of `σ_i` against `digest_v2(b*)` therefore fails — a valid Ed25519 signature on message `m` does not verify on `m' ≠ m` except with the EUF-CMA-negligible probability subsumed in A1.

**Step 3 — the relayer cannot re-sign.** To make `b*` accepted, the relayer must furnish a fresh bundle valid over `digest_v2(b*)`: at least Q = required signing creators (K in MD mode; `K − ⌈2K/3⌉` sentinel slack permitted only in BFT mode per `validator.cpp:447-451`) valid Ed25519 signatures under the committee members' registered pubkeys. The relayer holds none of those secret keys; producing even one such signature contradicts A1 (Ed25519 EUF-CMA). Hence the strip is rejected except with negligible probability.

Combining Steps 1–3: the probability that a post-signing inbound-set alteration goes undetected is bounded by the A2 collision term `2^{-128}` plus the A1 forgery term, i.e. `2^{-128} + negl(λ)`.    ∎

**Implementation citation.** `src/node/producer.cpp:598-604` (digest binds `vr`) + `src/node/validator.cpp:442-456` (single `compute_block_digest` recomputation; per-creator Ed25519 `verify` against it). Producer and validator invoke the identical `compute_block_digest` symbol (the same translation unit, `:577`), so there is no producer/validator digest skew for an honest input — the only way to change the validator's recomputed digest is to change a digested field, and `inbound_receipts`' admitted-key set is now one.

### 4.4 Proof of T-4 (the bound set is the deterministic committee-wide intersection)

Assume F2 active (`b.index >= chain.f2_active_from_height()`) and `b` accepted by `check_inbound_receipts`. The validator's site-3 block at `validator.cpp:1168-1184` runs:

1. **Per-creator list authentication** (`:1171-1177`): for each `i`, `compute_view_root(b.creator_view_inbound_lists[i]) == b.creator_view_inbound_roots[i]`. Since `creator_view_inbound_roots[i]` is bound into creator i's Phase-1 commit signature (verified in `check_creator_*`; `MakeContribCommitmentBackwardCompat.md` T-2 rules out cross-shape replay), under A1+A2 the list `b.creator_view_inbound_lists[i]` is exactly the set creator i committed to at Phase-1 sign-time — the producer cannot substitute a different list without breaking either this root check (A2) or creator i's Phase-1 signature (A1).

2. **Intersection membership** (`:1178-1184`): let `I := reconcile_intersection(b.creator_view_inbound_lists)`. The loop rejects `b` unless every `r ∈ b.inbound_receipts` satisfies `key(r) ∈ set(I)`. Therefore acceptance implies `set(keys(b.inbound_receipts)) ⊆ set(I)`.

By `F2ViewReconciliationAnalysis.md` T-3 (OrderIndependent) and the determinism of `reconcile_intersection` (§3.3 there), `I` is a function of the *set-of-committed-sets* `{ set(b.creator_view_inbound_lists[i]) }` — identical on every honest validator's re-derivation, independent of producer-chosen creator ordering. By T-6 (IntersectionConservative), `key(r) ∈ set(I)` iff every committee member's committed view contains `key(r)` — i.e. the admitted set is gated by unanimous committee observation, not by the producer's local first-seen timing.

Now compose with T-3 of *this* document. The set whose root `vr` is digested is precisely `set(keys(b.inbound_receipts))` (§3.3). By the above, that set is a subset of the rule-determined `set(I)` and each of its elements is unanimously committed. T-3 then guarantees the K-of-K signature attests to *this exact set* — a relayer cannot shrink it (post-signing strip ⇒ digest change ⇒ T-3) and the producer cannot inflate it beyond `set(I)` (pre-signing ⇒ validator site-3 reject). Hence the digested, signature-attested inbound set is the deterministic committee-wide intersection (capped by the producer's legitimate already-credited filter at `:899` / `:1156-1158`).    ∎

**Why this escapes the `S030-D2-Analysis.md` §2 trap.** The §2 fatality applies to digesting each member's *raw local* view, which diverges under gossip-async. Here the digested value is `vr` over the *post-reconciliation* admitted set, which by T-4 is a deterministic function of the K *committed* views — every honest member computes the same admitted set (sites 1+3) hence the same `vr`, so the K-of-K gather converges. The digest append is safe *because* it sits downstream of the intersection reconciliation, not upstream of it. The equivocation/abort dimensions now satisfy the same structural precondition via the **union** analog (commit `48c4b45`): per-creator `creator_view_eq_lists` / `creator_view_abort_lists` are carried, `build_body` reconciles `reconcile_union` over them, and `compute_block_digest` appends a root over the reconciled set — so all three pool-fed dimensions are downstream of their reconciliation. This proof remains scoped to inbound for clarity; see `EqAbortViewDigestExtension.md` for the union dimension.

---

## 5. Composition with the evidence dimensions (now also closed)

This proof closes the S-030 D2 removal gap for the **inbound** dimension. The equivocation and abort dimensions are now closed by the same structural argument (commit `48c4b45`), with the **union** rule instead of intersection — see `EqAbortViewDigestExtension.md` for the full treatment. In summary:

- `Block` now carries `creator_view_eq_lists` / `creator_view_abort_lists` (the union analog of `creator_view_inbound_lists`), `build_body` reconciles `equivocation_events` / `abort_events` to `reconcile_union` over the committee's committed views (the subset the assembler can materialize), and `compute_block_digest` appends a root over the reconciled eq/abort sets (gated on a non-zero per-creator view root). So the §2 precondition (a deterministic committee-wide reconciled set computed before digesting) is now met for evidence too.
- Two refinements distinguish the union case from inbound: validator membership is **SUBSET**, not exact-cardinality (the event hashes carry observer-dependent forensic fields, so exact cardinality would stall), and the validator treats a **zero** per-creator root as the v1 short-circuit sentinel (an empty list contributing nothing) rather than recomputing `compute_view_root({})` (the non-zero empty-SHA-256). The intersection-only inbound check never needs the latter because an admitted receipt forces every root non-zero.
- The evidence dimensions remain additionally backstopped at the **apply layer** (S-033 `state_root` + S-038 producer wiring; `EquivocationSlashingApply.md` / `AbortEventApply.md`); the consensus-layer digest binding (`48c4b45`) is the strictly stronger *signature-layer* guarantee, now delivered for all three pool-fed dimensions.

This is consistent with `F2-SPEC.md` §Q1: intersection-reconciled inbound receipts (`a727cb2`) and union-reconciled evidence (`48c4b45`) each admit a safe pre-digest canonicalization, so all three pool-fed fields are signature-bound.

---

## 6. Test-suite citation

The inbound digest binding is exercised end-to-end by the cross-shard regression suite, which credits a cross-shard transfer at the destination shard only if the inbound receipt survives admission + K-of-K signing + the receiving shard's `check_inbound_receipts`:

- `tools/test_cross_shard_transfer.sh` — full source→destination credit path; a stripped inbound receipt would fail destination credit (the T-3 attack manifests as a dropped credit), and a digest that did not bind the set would let the strip through silently.
- The `compute_view_root` order-independence + dedup + content-sensitivity properties underpinning T-1 are unit-tested in `determ test-view-root` (`tools/test_view_root.sh`), scenarios 1–8 (see `F2ViewReconciliationAnalysis.md` §6).
- `hash_cross_shard_receipt`'s field coverage (the T-3 Step-1 distinguishing argument) and `reconcile_intersection` (T-4) are exercised across the cross-shard suite's receipt round-trip assertions.

A targeted regression that constructs a K-of-K-signed cross-shard block, strips one admitted inbound receipt, and asserts the stored K-of-K signatures FAIL re-verification against the recomputed digest would directly witness T-3; it is recommended as a follow-up (the property is currently covered transitively via the credit-path suite, not by a dedicated strip-after-sign test).

---

## 7. Status

**Shipped (commit `a727cb2`).** `compute_block_digest` (`src/node/producer.cpp:577-606`) appends `compute_view_root` over the sorted `hash_cross_shard_receipt` keys of `inbound_receipts` when non-empty, skipped when empty. Verified against the current tree: the conditional gate at `:598`, the key-build loop at `:599-602`, and the single root append at `:603` match this proof byte-for-byte; the v1 byte stream at `:579-589` is unchanged. The full cross-shard suite passes.

This proof does not change any code; it consolidates the argument that the inbound dimension of the S-030 D2 removal gap is closed at the signature layer — a relayer can no longer strip an admitted inbound receipt after K-of-K signing without breaking K-of-K verification (T-3), the change is byte-identical on all non-cross-shard blocks (T-2), the binding is order-independent (T-1), and the bound set is the deterministic committee-wide intersection rather than the producer's local timing (T-4). The equivocation/abort dimensions are now closed at the digest layer too (§5; commit `48c4b45`, the union analog of the carry+reconcile+digest pattern) and retain the apply-layer backstop.

---

## 8. References

- `src/node/producer.cpp:577-606` — `compute_block_digest`, the primary object of this proof (the `a727cb2` inbound append at `:590-604`).
- `src/node/producer.cpp:312-326` — `hash_cross_shard_receipt` (per-receipt key; the `"DTM-F2-RCPT-v1"` domain-separated SHA-256).
- `src/node/producer.cpp:335-340` — `compute_view_root` (order-independent set root; T-1).
- `src/node/producer.cpp:357-372` — `reconcile_intersection` (the rule whose output is digested under composition; T-4).
- `src/node/producer.cpp:891-904` — `build_body` site-3 admit-filter (producer side of T-4).
- `src/node/validator.cpp:442-456` — single `compute_block_digest` recomputation + per-creator Ed25519 `verify` (T-3).
- `src/node/validator.cpp:1132-1187` — `check_inbound_receipts` (SINGLE/BEACON empty requirement for T-2.1; site-3 intersection enforcement for T-4).
- `include/determ/chain/block.hpp` — `Block` field set incl. `inbound_receipts`, `creator_view_inbound_lists`, `creator_view_inbound_roots`.
- `docs/proofs/Preliminaries.md` §1.3 (hash conventions), §2.1 (SHA-256 collision + 2nd-preimage — A2), §2.2 (Ed25519 EUF-CMA — A1).
- `docs/proofs/S030-D2-Analysis.md` §1 (gap statement), §2 (why naive digest extension is fatal under gossip-async), §3.5 (per-field closure map).
- `docs/proofs/F2ViewReconciliationAnalysis.md` — T-3 (OrderIndependent, reused in T-1/T-4), T-6 (IntersectionConservative, reused in T-4), §3.1 (`compute_view_root` determinism).
- `docs/proofs/MakeContribCommitmentBackwardCompat.md` — Phase-1 commit-binding of the per-creator view roots (T-4 authenticity premise).
- `docs/proofs/EquivocationSlashingApply.md` (FA-Apply-10) + `docs/proofs/AbortEventApply.md` (FA-Apply-11) — the apply-layer backstop for the evidence dimensions (now also consensus-layer-closed per §5).
- `docs/proofs/EqAbortViewDigestExtension.md` — the union-rule sibling closing the equivocation/abort dimensions at the digest layer (commit `48c4b45`).
- `docs/proofs/F2-SPEC.md` §Q1 — union-for-evidence / intersection-for-receipts asymmetry; this proof treats the inbound (intersection) dimension, its sibling treats the evidence (union) dimensions.
- `tools/test_cross_shard_transfer.sh`, `tools/test_view_root.sh` — regression coverage (§6).
- ISO/IEC 14882:2020 [C++20]: `[array.syn]` (lexicographic compare on `std::array`), `[associative.reqmts]` (sorted iteration on `std::set`), `[set.modifiers]` (insertion is no-op on duplicates).
- NIST FIPS 180-4 — SHA-256 reference for `compute_view_root` + `hash_cross_shard_receipt`.
