# StateProofRaceWindowSoundness — temporal-consistency soundness of the `proof_height < / == / > vc.height` race-window dispatch for every `state_proof`-backed trustless read (PRW-1..PRW-5)

This document formalizes the soundness of the **temporal anchoring** step shared by *every* trustless `state_proof` read the light client performs — the three-branch race-window dispatch at `light/trustless_read.cpp:226-307` that binds a head-only state-proof's claimed `state_root` to a committee-signed header that **provably extends the operator's verified chain prefix**, even when the chain advanced between the head walk (step 2) and the proof fetch (step 3). Where `StateProofCompositeKeySoundness.md` proves the daemon rebuilds the *spatial* (key) coordinate of a composite leaf byte-for-byte, and `ReceiptInclusionProofSoundness.md` / `CompositeStateReadSoundness.md` prove the verifier reads back a leaf's *value* soundly, *this* proof covers the orthogonal **temporal** coordinate: that the `state_root` the proof is verified against is itself anchored to a committee-attested point on the pinned chain, not to a forked or future height the daemon invented during the RPC round-trip. The dispatch is namespace-agnostic — it runs identically for the simple namespaces `a|s|r|d|b|k|c` and the composite namespaces `i|m|p` — so the temporal guarantee proven here composes underneath *all* of `read_account_trustless`, `verify-receipt-inclusion`, the `m:`/`p:` reads, `stake-trustless`, and `supply-trustless`.

The proof exists because the race window is a **structurally distinct attack surface** from leaf reconstruction and value-hash decode, with three properties that matter for soundness and that the per-namespace proofs explicitly defer to this dispatch:

1. **The proof root is *not* the head root the operator just verified.** `verify_chain_to_head` (`light/trustless_read.cpp:81-186`) anchors a committee-signed `vc.head_state_root` at height `vc.height`. The subsequent `state_proof` RPC returns a proof against `compute_state_root()` + `height()` at the daemon's *current* head (`node.cpp:3375-3376`), which is generally `proof_height ≥ vc.height` because the chain advanced. Naively comparing `proof_root == vc.head_state_root` fails in the common case; naively trusting the proof's self-claimed `state_root` (verifying only that the Merkle siblings roll up to *it*, `verify_state_proof(proof, {})` at `:221`) defeats the entire trust model — a Byzantine daemon could fabricate a self-consistent proof against a forged root for a forked future height. The dispatch is the bridge that re-anchors the *future* root to the *verified* prefix.

2. **The anchor index is off by one from the proof height, and the off-by-one is load-bearing.** `proof.height` is the *count of applied blocks*; the last applied block lives at index `proof_height - 1` and its `block.state_root` is the **post-apply** commitment (S-038 producer wiring populates `body.state_root` with "the state after applying THIS block"). So the dispatch anchors the proof root to `header[proof_height - 1].state_root`, not `header[proof_height]` (which may not exist) nor `header[proof_height].state_root`. A drift in this index would either fail to anchor a valid proof (best case) or, paired with a daemon lie, anchor to the wrong header. PRW-2 pins the off-by-one against the S-038 "post-apply state" semantics.

3. **A committee signature on a header proves *nothing* about which chain that header belongs to.** The dispatch's `verify_block_sigs` sub-check (`:277-285`) confirms a *known committee signed* the anchor header, but a Byzantine daemon could replay a genuinely-committee-signed header from a *fork* that branched before `vc.height`. The defense is the prev_hash **extension walk** (`:289-298`) from `vc.height - 1` to the anchor index, which forces the new tip to descend from the already-verified head rather than float free. PRW-3 formalizes that the walk yields a *monotone prefix extension*, not merely a "chains via prev_hash" property.

No new cryptographic primitive is introduced. The claim is that an honest light client never **acts on** a state-proof whose root is not bound to a committee-attested header that extends the operator's genesis-pinned, header-walk-verified prefix — for any namespace. The proof deepens `LightClientThreatModel.md` Lemma **L-5** (the four-step sketch) and §4.4.1 (the race-window narrative inside T-L4) into five standalone theorems with an explicit adversary game, the off-by-one correctness argument, the monotone-prefix-extension lemma, a forked-future-root attack, the idempotent re-anchor invariant the downstream cleartext/value cross-check relies on, and the namespace-agnosticism that lifts the result from the `a:` flow it is coded in to every composite read shipped this round.

**Companion documents.** `Preliminaries.md` (F0) §2.0 (canonical assumption labels — **A1** = Ed25519 EUF-CMA §2.2, **A2** = SHA-256 collision / second-preimage §2.1, **A3** = SHA-256 preimage §2.1) — this proof reduces to **A1** (committee-signature unforgeability on the anchor header) and **A2** (prev_hash-link collision resistance on the extension walk) only; the off-by-one correctness (PRW-2) and the dispatch's total-case-split (PRW-1) are *unconditional*; `StateRootAnchorSoundness.md` (F6 — its **SR-1** per-height committee-anchored-root sub-lemma is the binding this dispatch *constructs at run time* for the floating proof root, its **SR-2** genesis-binding / no-floating-header lemma is the per-height analog of PRW-3's extension-walk argument and explicitly cites `trustless_read.cpp:286-298` as "the race-window prev_hash walk", and its **SR-3** height-binding is what PRW-2's index argument leans on — `index` is inside the signed digest so the anchor header's height is committee-attested); `LightClientThreatModel.md` (the malicious-daemon adversary `A_daemon` §2.1, the **T-L4** composite read whose §4.4.1 race-window mitigation and **Lemma L-5** this proof is the rigorous standalone form of, **T-L2** committee-sig head trust which PRW-3 invokes per anchor header, **L-6** fail-closed exit which PRW-5 inherits); `MerkleTreeSoundness.md` (the sorted-leaves balanced binary Merkle primitive — its **MT-4** inclusion-proof soundness is what makes a proof *against a given root* meaningful; this dispatch's job is to certify *which* root, upstream of MT-4); `ReceiptInclusionProofSoundness.md` + `CompositeStateReadSoundness.md` + `StateProofCompositeKeySoundness.md` (the composite-key reads that invoke this dispatch unchanged — their RI-1 / CR-1 "race-window anchor of the proof root to a committee-signed header" step is *exactly* this dispatch, deferred to here; this proof discharges the obligation they cite); `StakeProofSoundness.md` + `TxInclusionProofSoundness.md` + `SupplyProofSoundness.md` (the simple-key `s:`/membership/supply reads that run the identical dispatch — PRW-4 namespace-agnosticism is what lets all of them share this single temporal proof); `LightClientArchiveSoundness.md` (its **AR-3(ii)** "floating slice" defense is the archival-read analog of PRW-3's extension-walk — both reject a committee-signed-but-detached header); `LightClientCompositionMap.md` (the dependency map placing this dispatch between the head walk and the leaf cross-check); `S033StateRootNamespaceCoverage.md` (its **§2.3** "once-emitted, always-emitted" `state_root` determinism is what guarantees `header[proof_height-1].state_root` is non-zero in the S-033-active regime PRW-2 assumes); `docs/SECURITY.md` §S-033 + §S-038 for the producer-side `state_root` population this proof's off-by-one rests on; `docs/PROTOCOL.md` §4.1.1 for the "state after applying THIS block" semantics + §10.2 for the `state_proof` / `headers` RPC contracts.

---

## 1. Scope

### 1.1 In scope

The three-branch race-window dispatch at `light/trustless_read.cpp:226-307`, run once per trustless `state_proof` read after the proof has been self-verified (`verify_state_proof(proof, {})`, `:221`) and before any cleartext / value-hash cross-check:

> Given a committee-anchored `(vc.head_state_root, vc.height)` from the header walk (step 2) and a self-consistent proof claiming `(proof_root, proof_height)` from the `state_proof` RPC (step 3), the dispatch accepts the proof's root as authoritative **iff** it can bind `proof_root` to a committee-signed header at index `proof_height - 1` that extends the verified prefix `0 … vc.height - 1` — otherwise it throws.

The five theorems:

| Theorem | Property |
|---|---|
| **PRW-1** (Total, monotone case split) | The dispatch is a total function of `sign(proof_height − vc.height)`: `<` rejects (stale), `==` requires byte-equal root, `>` runs the four-step re-anchor. No `proof_height` falls through unhandled; no accepted proof has `proof_height < vc.height`. |
| **PRW-2** (Off-by-one anchor correctness) | `anchor_index = proof_height − 1` is the unique index whose `block.state_root` equals the post-apply state commitment for `proof_height` applied blocks, under the S-038 "state after applying THIS block" semantics; anchoring to `proof_height` or `proof_height − 2` is provably wrong. |
| **PRW-3** (Monotone verified-prefix extension) | In the `>` branch, the accepted anchor header is bound by `verify_block_sigs` (A1) **and** by the prev_hash extension walk `vc.height−1 … anchor_index` (A2) to descend from the already-verified head — so the new `(state_root, height)` extends the verified prefix rather than floating on a fork. |
| **PRW-4** (Namespace-agnostic reuse) | The dispatch consumes only `(proof_height, proof_root)` and the committee seed — never the namespace or key — so the temporal guarantee holds identically for every simple (`a|s|r|d|b|k|c`) and composite (`i|m|p`) read; the per-namespace proofs' "race-window anchor" step is discharged here once. |
| **PRW-5** (Idempotent re-anchor preserves the downstream invariant) | After a `>`-branch accept, the dispatch reassigns `(vc.head_state_root, vc.height, vc.head_block_hash)` to the proof's now-verified values (`:299-301`); the post-dispatch `vc` is itself a committee-anchored, genesis-rooted head at `proof_height`, so the subsequent cleartext / value-hash cross-check (L-4 / RI-2 / CR-2) operates against a sound anchor regardless of which branch ran. |

### 1.2 The dispatch (read off source)

From `light/trustless_read.cpp:235-307`, with `proof_height = proof.value("height", 0)` and `proof_root = proof.value("state_root", "")`:

```cpp
if (proof_height < vc.height) {
    throw ... "is BEFORE verified-chain head ... — daemon is serving stale state";   // PRW-1 stale branch
}
if (proof_height > vc.height) {
    // build committee_json from committee_seed                                        // PRW-3 sig binding
    uint64_t anchor_index = proof_height - 1;                                          // PRW-2 off-by-one
    auto pg = rpc.call("headers", {{"from", anchor_index}, {"count", 1}});
    ... // fetch header[anchor_index]
    if (hdr_root != proof_root) throw ...;                                             // (a) root match
    auto vbs = verify_block_sigs(h, committee_json, /*bft=*/false);
    if (!vbs.ok) vbs = verify_block_sigs(h, committee_json, /*bft=*/true);
    if (!vbs.ok) throw ...;                                                            // (b) committee signed
    if (anchor_index >= vc.height) {
        auto walk = rpc.call("headers",
            {{"from", vc.height - 1}, {"count", proof_height - vc.height + 2}});
        auto vh = verify_headers(walk, "", "");
        if (!vh.ok) throw ...;                                                         // (c) prev_hash extension
    }
    vc.head_state_root = proof_root;                                                   // PRW-5 re-anchor
    vc.height          = proof_height;
    vc.head_block_hash = h.value("block_hash", std::string{});
} else if (proof_root != vc.head_state_root) {
    throw ... "does not match verified head state_root";                              // PRW-1 == branch
}
```

### 1.3 Out of scope (intentional)

- **The cryptographic membership soundness of the proof against the anchored root.** That `merkle_verify` against the now-certified root proves membership is `MerkleTreeSoundness.md` MT-4; this proof certifies *which root*, upstream of MT-4. The self-consistency pre-check `verify_state_proof(proof, {})` (`:221`) only confirms the proof's siblings roll up to *its own* claimed root — it is a sanity gate, not the anchor; the anchor is this dispatch.
- **The leaf-key reconstruction and value-hash decode.** Spatial (key) reconstruction is `StateProofCompositeKeySoundness.md` SP-CK-1; value-hash read-back is `ReceiptInclusionProofSoundness.md` RI-2 / `CompositeStateReadSoundness.md` CR-2 / `StakeProofSoundness.md` SP-2 / Lemma L-4. This proof is the temporal complement, orthogonal to both.
- **The header-walk that produces `(vc.head_state_root, vc.height)`.** `verify_chain_to_head` correctness is `StateRootAnchorSoundness.md` SR-2 + `LightClientThreatModel.md` T-L2; this dispatch consumes its output as a trusted anchor.
- **Cross-invocation correlation.** Two separate trustless reads at different wall-clock times can each anchor to a different height; each invocation is sound in isolation (PRW-1..PRW-5), but the dispatch does not bind one invocation's height to another's. This is the `LightClientThreatModel.md` §5.x cross-invocation caveat, unchanged.
- **The S-033-inactive regime.** `read_account_trustless` throws `chain has not activated state_root (S-033)` (`:202-208`) before the dispatch ever runs if the head carries an empty `state_root`; PRW-2 assumes the S-033-active regime where every header's `state_root` is non-zero (`S033StateRootNamespaceCoverage.md` §2.3).

---

## 2. Threat model

The adversary is `A_daemon`, the **malicious daemon** of `LightClientThreatModel.md` §2.1: it controls the RPC endpoint, may return arbitrary JSON for `state_proof`, `headers`, and `account`, and knows the operator's genesis and committee seed (both public). `A_daemon` does **not** possess any committee member's Ed25519 secret key (A1) and cannot exhibit a SHA-256 collision (A2).

`A_daemon`'s race-window-specific goals, all of which the dispatch must defeat:

- **(G1) Stale-root serve.** Return a proof at `proof_height < vc.height` carrying an old `state_root` from before the head the client just verified — making the client act on superseded state.
- **(G2) Forged-future-root serve.** Return a self-consistent proof at some `proof_height > vc.height` against a fabricated `state_root` `R_A` for a state the chain never reached, hoping the client trusts the proof's self-claimed root because the chain "advanced".
- **(G3) Forked-detached-header anchor.** When the client demands a committee-signed header at `anchor_index`, serve a header that *is* genuinely committee-signed but belongs to a **fork** that branched before `vc.height` (e.g., a stale header the committee signed on an abandoned branch), so its `state_root` is committee-attested yet not on the operator's pinned chain.
- **(G4) Off-by-one confusion.** Serve a proof whose `state_root` matches `header[proof_height].state_root` (or `header[proof_height-2]`) rather than the canonical `header[proof_height-1].state_root`, exploiting an index drift to anchor the proof to the wrong block's commitment.

**Security goal.** An honest client accepts the proof's `(proof_root, proof_height)` as authoritative **iff** `proof_root` is the genuine post-apply state commitment of the operator's pinned chain at `proof_height` applied blocks, bound to a committee-signed header at `proof_height - 1` that extends the verified prefix — defeating G1 (PRW-1 stale branch), G2/G3 (PRW-3 sig + extension walk), and G4 (PRW-2 off-by-one).

---

## 3. Primitives reused

The dispatch reuses, unchanged:

1. **`verify_block_sigs(header, committee_json, bft)`** (`light/verify.cpp:190-283`) — the K-of-K committee-signature verifier (`LightClientThreatModel.md` L-2 digest binding + T-L2). The dispatch calls it `false`-then-`true` (`:277-280`) to accept either a non-BFT or BFT finalized anchor header. Returns `ok=true` only if a known committee actually signed the header's digest under their Ed25519 keys; forging this costs an A1 break.
2. **`verify_headers(headers_json, "", "")`** (`light/verify.cpp:104-188`) — the prev_hash continuity walker. Over a contiguous header slice it requires `headers[i].prev_hash == headers[i-1].block_hash` for every adjacent pair (`:167-178`). A break at any link returns `ok=false`. The dispatch passes empty genesis/prev anchors because the slice is interior (it starts at `vc.height - 1`, not genesis); the *first* element being the already-verified head supplies the binding to the pinned prefix (PRW-3).
3. **`rpc.call("headers", {from, count})`** (`light/rpc_client.cpp`) — fetches a contiguous header page. The dispatch uses two calls: one for the single anchor header at `anchor_index`, one for the extension slice `vc.height-1 … proof_height`.
4. **`block.state_root` semantics** — per S-038 producer wiring (`docs/SECURITY.md` §S-038), the producer populates `body.state_root` via a tentative-chain dry-run *after* assembling the block body, so `header[k].state_root` is the state commitment **after applying block `k`**. This is the "state after applying THIS block" invariant PRW-2 pins.

---

## 4. Security theorems

Throughout, fix the verified anchor `(R_v, h_v) := (vc.head_state_root, vc.height)` from the header walk (a committee-signed head at index `h_v - 1`, by `StateRootAnchorSoundness.md` SR-2), and the proof's claim `(R_p, h_p) := (proof_root, proof_height)`. Write `S(k)` for the genuine post-apply state commitment of the operator's pinned chain after `k` applied blocks, so the genuine `header[k-1].state_root = S(k)` and `R_v = S(h_v)`.

### 4.1 Theorem PRW-1 (total, monotone case split)

**Statement.** The dispatch is a total function of `sign(h_p − h_v)`: (i) every `h_p` lands in exactly one of the three branches `<`, `==`, `>`; (ii) the `<` branch throws unconditionally, so no accepted proof has `h_p < h_v`; (iii) the `==` branch accepts iff `R_p = R_v` byte-for-byte; (iv) the `>` branch accepts iff the four sub-checks (a)(b)(c) pass. There is no `h_p` for which the dispatch neither accepts nor throws.

**Proof.** The control flow at `:237-307` is the literal disjunction `if (h_p < h_v) {throw} if (h_p > h_v) {…} else if (R_p ≠ R_v) {throw}`. Since `h_p` and `h_v` are `uint64_t`, exactly one of `h_p < h_v`, `h_p > h_v`, `h_p == h_v` holds (trichotomy on a total order), so the case split is total and disjoint.

- **(ii) `<` branch.** The first `if` returns (throws) for every `h_p < h_v` with the `is BEFORE verified-chain head … serving stale state` diagnostic (`:238-241`); control never reaches the rest. Hence no accepted proof has `h_p < h_v` — **G1 is defeated unconditionally**, with no cryptographic assumption: a stale proof is rejected purely by the height comparison, regardless of whether its root is genuine or forged. (A daemon that wants the client to read superseded state cannot, because the client has already committee-verified a *later* head and refuses to regress.)
- **(iii) `==` branch.** Reached only when `h_p == h_v` (the second `if` is false). The `else if (R_p ≠ R_v)` throws on any byte-difference (`:302-306`); otherwise the dispatch falls through with `vc` unchanged and `R_p = R_v` accepted. Since `R_v = S(h_v)` is committee-anchored (SR-2) and `h_p == h_v`, an accepted `R_p` equals the genuine `S(h_v)` — **G2 at equal height is defeated** because any forged `R_A ≠ R_v` is caught by the byte-equality check.
- **(iv) `>` branch.** Reached only when `h_p > h_v`; analyzed in PRW-2 (index) and PRW-3 (binding). The branch always either throws (any sub-check fails) or reassigns `vc` (all pass) — it never falls through silently.

All three branches terminate in either a throw or an accept; the function is total.   ∎

**Remark (monotonicity).** The accepted height is monotone non-decreasing across the dispatch: the `<` branch is rejected, so a post-dispatch `vc.height ≥ pre-dispatch vc.height` always. This monotonicity is what PRW-5 relies on to argue the re-anchored `vc` still extends the genesis-pinned prefix.

### 4.2 Theorem PRW-2 (off-by-one anchor correctness)

**Statement.** In the `>` branch, `anchor_index = proof_height − 1` (`:258`) is the **unique** chain index `k` such that the genuine `header[k].state_root` equals the post-apply state commitment for `h_p` applied blocks, i.e. `header[anchor_index].state_root = S(h_p) = R_p` when the daemon is honest. Anchoring to `proof_height` (an index that need not exist) or `proof_height − 2` (the prior block's commitment) is provably wrong and would either fail to anchor an honest proof or, under G4, anchor to the wrong commitment.

**Proof.** `proof.height` is, by the `state_proof` RPC contract (`node.cpp:3375-3376`), the *count of applied blocks* on the daemon's chain at the moment the proof was built — equivalently `chain.height()`, the number of blocks `0 … h_p - 1`. The state commitment the proof is *against* is `compute_state_root()` evaluated *after* applying all `h_p` blocks, i.e. `S(h_p)`.

By the S-038 producer semantics (§3 primitive 4), each `header[k].state_root` is the commitment **after applying block `k`** — "the state after applying THIS block". The block at index `k` is the `(k+1)`-th applied block, so `header[k].state_root = S(k+1)`. Setting `k + 1 = h_p` gives the unique `k = h_p - 1`. Therefore:

$$\texttt{header}[h_p - 1].\texttt{state\_root} = S(h_p) = R_p \quad\text{(honest daemon)}.$$

- **`proof_height` is wrong.** `header[h_p].state_root = S(h_p + 1)`, the commitment *after the next block*; and on a chain with exactly `h_p` blocks, index `h_p` does not exist (the `headers` RPC would return an empty/short slice, which the dispatch's `pg["headers"].empty()` guard at `:261-267` already rejects). So `proof_height` neither exists nor commits to `S(h_p)`.
- **`proof_height − 2` is wrong.** `header[h_p - 2].state_root = S(h_p - 1)`, the commitment of the *prior* applied block. A proof against `S(h_p)` would fail the root-match `hdr_root == proof_root` (`:270`) against `S(h_p - 1) ≠ S(h_p)` (distinct unless the block was a no-op, and even then the commitment is re-pinned by the height field inside the digest, SR-3).

So `h_p - 1` is the unique correct index. The off-by-one is **unconditional** (a counting identity over the S-038 semantics), not a cryptographic claim. **G4 is defeated**: a daemon that serves a proof root matching `header[h_p].state_root` or `header[h_p-2].state_root` instead of `header[h_p-1].state_root` fails the `hdr_root == proof_root` byte-match at `:270`, because the honest `header[anchor_index]` the client fetches commits to `S(h_p)` and the daemon's mismatched root does not equal it. (If the daemon *also* lies about `header[anchor_index].state_root` to make it match its forged proof root, that lie is caught by PRW-3's committee-sig check — the daemon cannot re-sign the anchor header.)   ∎

**Remark (why the comment block matters).** The `:253-257` source comment ("`proof.height` is the count of applied blocks; the LAST applied block lives at index `proof.height - 1` …") is the natural-language statement of this counting identity. PRW-2 is its formalization and the regression specification any future edit to the index arithmetic must preserve.

### 4.3 Theorem PRW-3 (monotone verified-prefix extension)

**Statement.** In the `>` branch, an accepted anchor header `H_a := header[anchor_index]` is bound, under A1 + A2, to (i) a genuine committee signature on its digest-covered fields (including `index = anchor_index` and `state_root = R_p`), **and** (ii) a prev_hash chain from the already-verified head `header[h_v - 1]` up to `H_a`. Consequently `H_a` **descends from** the verified prefix `0 … h_v - 1` — it is a forward extension on the operator's pinned chain, not a detached or forked header. **G2 and G3 are defeated.**

**Proof.** The branch runs three sub-checks after fetching `H_a` (treated as untrusted until all three pass):

- **(a) Root match** (`:270`). `H_a.state_root == R_p` byte-for-byte, else throw. This binds the daemon's *claim about `H_a`'s `state_root`* to the proof's `R_p`. (Alone, insufficient — the daemon controls `H_a` until (b).)
- **(b) Committee signature** (`:277-285`). `verify_block_sigs(H_a, committee_json, false-then-true)` must return `ok`. By L-2 (digest binding) the verified digest covers `index`, `prev_hash`, `tx_root`, …, and (transitively forward, SR-1) `state_root`. By T-L2 / A1, a daemon without committee secret keys cannot produce a header with a valid K-of-K signature except with probability `≤ K · 2⁻¹²⁸`. So after (b), `H_a` is a *genuine committee-attested header* at index `anchor_index` with `state_root = R_p`. This already defeats **G2** (a fabricated `R_A` cannot ride inside a committee-signed header without an A1 forgery).

  But (b) alone does **not** defeat **G3**: `A_daemon` could replay a header the committee *genuinely signed on a fork* that branched before `h_v`. Such a header is committee-attested yet off the operator's pinned chain. The defense is (c).

- **(c) prev_hash extension walk** (`:289-298`). Guarded by `anchor_index >= vc.height` (`:289`; when `anchor_index == h_v - 1 < h_v` the anchor *is* the already-verified head and no walk is needed — see Remark), the dispatch fetches the contiguous slice `[h_v - 1 … h_p]` (count `h_p - h_v + 2`) and runs `verify_headers(walk, "", "")`. By §3 primitive 2, this requires `walk[i].prev_hash == walk[i-1].block_hash` for every adjacent pair. The slice's **first element is `header[h_v - 1]`** — the head the operator *already committee-verified* in step 2 (its `block_hash` is the genuine `prev_hash(h_v)` of the pinned chain). Thus the walk establishes a hash-link chain

  $$\texttt{header}[h_v-1] \to \texttt{header}[h_v] \to \cdots \to \texttt{header}[h_p-1] = H_a,$$

  where each `→` is a verified `prev_hash == prior block_hash` equality. By A2 (collision resistance on each link), `A_daemon` cannot substitute a forked `header[k]` for the genuine one without exhibiting a SHA-256 collision on the `block_hash`/`prev_hash` link (probability `≤ 2⁻¹²⁸` per link, `≤ (h_p - h_v + 1) · 2⁻¹²⁸` over the slice). Therefore `H_a` is hash-chained back to the verified head, so it **descends from the verified prefix** — defeating **G3**: a fork that branched before `h_v` cannot present a prev_hash chain from `header[h_v - 1]` (the fork's `header[h_v - 1]` either *is* the genuine one, in which case it is not a fork at this point, or differs, in which case the first link `walk[1].prev_hash == walk[0].block_hash` fails because `walk[0]` is pinned to the genuine head).

Combining (a)+(b)+(c): an accepted `H_a` is a genuine committee-attested header carrying `state_root = R_p`, hash-chained forward from the operator's verified head. So `R_p = S(h_p)` is the genuine post-apply commitment of the pinned chain at `h_p` (the "monotone prefix extension"). The aggregate failure probability is `≤ K · 2⁻¹²⁸ + (h_p - h_v + 1) · 2⁻¹²⁸`.   ∎

**Remark (the `anchor_index >= vc.height` guard).** When `h_p > h_v` but `anchor_index = h_p - 1 == h_v - 1` (i.e. `h_p == h_v`, impossible in this branch) the walk is skipped; the only way the guard is false in the `>` branch is the degenerate `h_p == h_v` which routes to the `==` branch instead. For `h_p ≥ h_v + 1`, `anchor_index = h_p - 1 ≥ h_v > h_v - 1`, so the guard holds and the walk runs. The guard is therefore a correctness optimization (skip the walk only when the anchor *is* the verified head), not a soundness gap.

### 4.4 Theorem PRW-4 (namespace-agnostic reuse)

**Statement.** The dispatch reads only `proof.height`, `proof.state_root`, the `headers` RPC, and the committee seed — it never inspects the proof's `namespace`, `key`, `key_bytes`, `value_hash`, `target_index`, `leaf_count`, or Merkle `proof` array. Therefore the temporal guarantee PRW-1..PRW-3 is **identical** for every namespace: the simple-key reads (`a|s|r|d|b|k|c`) and the composite-key reads (`i|m|p`) share one race-window proof, and the per-namespace soundness proofs' "race-window anchor of the proof root to a committee-signed header" obligation is discharged here once for all of them.

**Proof.** By inspection of `:235-307`: the only proof fields consumed are `proof.value("height", …)` (`:235`) and `proof.value("state_root", …)` (`:236`). The leaf-identifying fields (`namespace`, `key`, `key_bytes`, `value_hash`, `target_index`, `leaf_count`, `proof`) are consumed *only* by the upstream self-consistency check `verify_state_proof(proof, {})` (`:221`) and the downstream leaf cross-check (`:309-343` for `a:`; the analogous value-hash / presence-marker check for `i|m|p`). The dispatch operates on the `(height, state_root)` pair, which every `state_proof` reply carries regardless of namespace (`node.cpp:3367-3377` appends `state_root` + `height` to every branch's reply, simple and composite alike).

Hence substituting `namespace=i` (or `m`, `p`, `s`, `r`, `d`, `b`, `k`, `c`) for `namespace=a` changes neither the inputs nor the behavior of `:226-307`. The composite reads invoke `read_account_trustless`'s race-window step verbatim (their pipelines mirror it — `ReceiptInclusionProofSoundness.md` §1.4 step 5, `CompositeStateReadSoundness.md` §1.1 step 5, both citing `trustless_read.cpp:226-307`). Therefore PRW-1..PRW-3 transfer unchanged, and those proofs' RI-1 / CR-1 obligations are satisfied by this single theorem family rather than re-proved per namespace.   ∎

**Consequence.** The temporal coordinate of *every* trustless `state_proof` read in the codebase is covered by one proof. A future namespace added to `rpc_state_proof` inherits PRW-1..PRW-5 automatically, provided its reply also carries `(height, state_root)` (which the shared reply-builder tail guarantees) — the only per-namespace work left is the spatial reconstruction (SP-CK-1-style) and the value-hash decode (RI-2 / CR-2-style).

### 4.5 Theorem PRW-5 (idempotent re-anchor preserves the downstream invariant)

**Statement.** After a `>`-branch accept, the dispatch reassigns `vc.head_state_root := R_p`, `vc.height := h_p`, `vc.head_block_hash := H_a.block_hash` (`:299-301`). The post-dispatch `vc` is itself a committee-anchored, genesis-rooted head at `h_p` — equivalent to what `verify_chain_to_head` would have produced had it walked all the way to `h_p` — so the subsequent cleartext / value-hash cross-check (Lemma L-4 / RI-2 / CR-2) operates against a sound anchor regardless of which branch ran. The reassignment is **idempotent**: re-running the dispatch on the same proof with the updated `vc` lands in the `==` branch and accepts without state change.

**Proof.** By PRW-3, an accepted `H_a` is a genuine committee-attested header at index `h_p - 1`, hash-chained forward from the verified prefix; by PRW-2, its `state_root = R_p = S(h_p)`. So the triple `(R_p, h_p, H_a.block_hash)` is exactly the `(head_state_root, height, head_block_hash)` that `verify_chain_to_head` would have computed had the daemon's head been at `h_p` during step 2 — the dispatch has *extended the verified walk by `h_p − h_v` blocks at proof-fetch time*, with the same committee-sig + prev_hash guarantees the walk itself provides. Therefore the post-dispatch `vc` satisfies the same invariant the head walk establishes: a committee-signed, genesis-rooted head.

The downstream cross-check (`:309-343`) recomputes the leaf value-hash and compares it to `proof.value_hash`, having already established (via `verify_state_proof` + this dispatch) that the proof rolls up to `vc.head_state_root = R_p`. Since `R_p` is now a sound anchor, the cross-check's conclusion — "the daemon's cleartext is consistent with the committee-attested state at `h_p`" — is sound. The `==` and `>` branches converge to the same post-condition (a sound `vc` at the accepted height), so the cross-check is branch-independent.

**Idempotence.** Suppose the dispatch is re-entered (hypothetically) with the post-update `vc = (R_p, h_p, …)` and the same proof `(R_p, h_p)`. Now `h_p == vc.height`, routing to the `==` branch, which checks `R_p == vc.head_state_root = R_p` — true — and accepts with no further state change. So the re-anchor is a fixpoint: applying the dispatch twice equals applying it once. This matters because it guarantees the dispatch does not *over-advance* `vc` (e.g. it never sets `vc.height` past `h_p`), preserving the monotone-prefix invariant PRW-1's remark records.   ∎

---

## 5. Composition with the light-client proof family

The race-window dispatch sits between the head walk and the leaf cross-check, certifying the temporal coordinate that the membership and value proofs assume:

```
                    A1 (Ed25519 EUF-CMA)            A2 (SHA-256 collision)
                           │                               │
   verify_chain_to_head (head walk) ── (R_v, h_v) committee-anchored head (SR-2)
                           │
        ┌──────────────────┴───────────────────┐
        │   RACE-WINDOW DISPATCH (THIS DOC)     │   proof claims (R_p, h_p), h_p ≥ h_v
        │   PRW-1 total case split (defeats G1) │
        │   PRW-2 off-by-one anchor (defeats G4)│
        │   PRW-3 prefix extension (defeats G2/G3)
        │   PRW-4 namespace-agnostic            │
        │   PRW-5 idempotent re-anchor          │
        └──────────────────┬───────────────────┘
                           │  certifies R_p = S(h_p) on the pinned chain
                           ▼
              MerkleTreeSoundness MT-4 (proof against R_p ⇒ leaf membership)
                           │
        ┌──────────────────┴───────────────────┐
   simple-key value decode            composite-key reconstruction + decode
   StakeProofSoundness SP-2 / L-4     SP-CK-1 (key) + RI-2 / CR-2 (value)
```

- **PRW-1 and PRW-2 are unconditional** (total trichotomy case split + a counting identity over S-038 semantics); they assume no cryptographic hardness.
- **PRW-3 reduces to A1 (committee-sig forge) + A2 (prev_hash-link collision)** — the same two assumptions the head walk (SR-2 / T-L2) uses, applied to the *forward extension* slice rather than the genesis prefix.
- **PRW-4 and PRW-5 are structural** (an input-dependence argument + a fixpoint argument), assuming no hardness beyond what PRW-1..PRW-3 already established.

The end-to-end temporal soundness: SR-2 certifies the verified head `(R_v, h_v)` → this dispatch extends the certification to the proof's `(R_p, h_p)` over the race window (A1 + A2) → MT-4 makes a passing proof against `R_p` prove leaf membership (A2) → the per-namespace value/key proofs interpret the membership soundly. Aggregating with the `LightClientThreatModel.md` T-L4 bound, `Pr[A_daemon defeats the race-window anchor] ≤ K · 2⁻¹²⁸ + (h_p − h_v + 1) · 2⁻¹²⁸`, which is `≤ 2⁻⁹²` for practical chains (`K ≤ 16`, `h_p − h_v ≤ 2³²`) — matching the §4.4.1 concrete bound, now derived from standalone theorems.

---

## 6. Known limitations and findings

- **F-1 (per-invocation, not cross-invocation).** PRW-1..PRW-5 secure a *single* read's temporal anchor. Two reads at different wall-clock times can anchor to different heights; the dispatch does not bind invocation `n`'s height to invocation `n+1`'s. A daemon that consistently serves an *old-but-self-consistent* committee-signed head across all of an operator's queries cannot make any individual query unsound, but can hold the operator at a stale (yet genuine, committee-attested, prefix-extending) height — a liveness/freshness limitation, not a safety one. This is the `LightClientThreatModel.md` §5 cross-invocation caveat; orthogonal to this proof, which is per-invocation safety.
- **F-2 (extension-walk cost grows with the race window).** The `>` branch fetches `h_p − h_v + 2` headers to run the prev_hash walk. A daemon that stalls the proof fetch arbitrarily long (so the chain advances far past `vc.height`) inflates the walk slice. The cost is linear in the gap and bounded by the daemon's own honest head; the `headers` RPC pages at `HEADERS_PAGE_MAX = 256` so a very large gap requires multiple pages (the dispatch's single `rpc.call("headers", …)` with `count = h_p - h_v + 2` relies on the daemon honoring the page; an under-served page is caught by `verify_headers` continuity failing, fail-closed). Not a soundness gap; a DoS/latency consideration.
- **F-3 (off-by-one is implementation-pinned to S-038 semantics).** PRW-2's `anchor_index = h_p − 1` is correct *because* `block.state_root` is the post-apply commitment (S-038). If a future change made `state_root` the *pre-apply* commitment (the state before applying the block), the anchor index would shift to `h_p` and PRW-2 would break silently. The S-038 "state after applying THIS block" invariant must remain stable; it is cross-referenced in `docs/SECURITY.md` §S-038 and `S033StateRootNamespaceCoverage.md` §2.3, and exercised end-to-end by `tools/test_light_verify_receipt_inclusion.sh` (a real 2-shard INCLUDED whose proof anchors through this dispatch).
- **F-4 (fail-closed inherited).** Every failure path in the dispatch throws (`:238`, `:263`, `:271`, `:282`, `:294`, `:303`), propagating to the CLI dispatcher as a non-zero exit with a structured diagnostic — no silent downgrade to "trust the daemon's claimed root" (`LightClientThreatModel.md` L-6). This proof adds six throw sites to the L-6 enumeration of fail-closed exits.

---

## 7. Summary

Every trustless `state_proof` read verifies a proof against a `state_root` the daemon claims for a height that — because the chain advanced during the RPC round-trip — is generally *ahead* of the committee-verified head the client walked to. This document proves the soundness of the race-window dispatch that re-anchors that future root to the verified prefix: **PRW-1** — the three-branch `< / == / >` split is total and monotone, rejecting stale roots (`h_p < h_v`) unconditionally and requiring byte-equality at equal height; **PRW-2** — the anchor index `proof_height − 1` is the unique index whose `block.state_root` is the post-apply commitment for `h_p` applied blocks under the S-038 semantics, defeating off-by-one confusion; **PRW-3** — in the advanced-height branch, the anchor header is bound by a committee signature (A1) *and* a prev_hash extension walk from the verified head (A2), so it provably descends from the genesis-pinned prefix rather than floating on a fork; **PRW-4** — the dispatch consumes only `(height, state_root)`, so the temporal guarantee is namespace-agnostic and discharges the "race-window anchor" obligation cited by every simple-key and composite-key read once; **PRW-5** — the re-anchor reassigns `vc` to a sound committee-attested head at `h_p`, idempotently, so the downstream cleartext/value cross-check operates against a sound anchor regardless of which branch ran. PRW-1/PRW-2 are unconditional; PRW-3 reduces to A1 + A2 exactly as the head walk does; PRW-4/PRW-5 are structural. The result is the rigorous standalone form of `LightClientThreatModel.md` Lemma L-5 / §4.4.1, composing underneath `MerkleTreeSoundness.md` MT-4 and feeding the per-namespace value/key proofs the *temporal* coordinate they assume.
