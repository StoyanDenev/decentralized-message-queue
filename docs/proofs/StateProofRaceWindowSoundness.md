# StateProofRaceWindowSoundness — temporal-consistency soundness of the S-042 committee-bound `state_root` anchoring for every `state_proof`-backed trustless read (PRW-1..PRW-5)

This document formalizes the soundness of the **temporal anchoring** step shared by *every* trustless `state_proof` read the light client performs — the binding that ties a head-only state-proof's claimed `state_root` to a committee-signed point on the operator's pinned chain, even though the chain generally advanced between the header walk (step 2) and the proof fetch (step 3). That gap is the **race window**: the daemon's `state_proof` always answers about its *current* head (`rpc_state_proof` returns `chain_.height()`, `src/node/node.cpp:3443-3453`), which is usually *ahead* of the committee-verified head the client walked to. Where `StateProofCompositeKeySoundness.md` proves the daemon rebuilds the *spatial* (key) coordinate of a composite leaf byte-for-byte, and `ReceiptInclusionProofSoundness.md` / `CompositeStateReadSoundness.md` prove the verifier reads back a leaf's *value* soundly, *this* proof covers the orthogonal **temporal** coordinate: that the `state_root` the proof is verified against is itself bound to a committee-attested point on the pinned chain, not to a forked or future height the daemon invented during the RPC round-trip.

**Mechanism note (S-042 — read carefully).** An earlier revision of this proof described the race window as being handled by a three-branch `proof_height < / == / > vc.height` *dispatch* that verified the committee signatures **on the anchor header itself** and matched `anchor.state_root == proof_root`. That mechanism rested on a **false premise**: that a committee signature on a header binds that header's `state_root`. It does **not** — `state_root` is **excluded** from `compute_block_digest` (the byte string the K-of-K committee Ed25519-signs); it is bound only into `Block::signing_bytes` → `block_hash` (`StateRootAnchorSoundness.md` §3.1-§3.2). A daemon can therefore overwrite the `state_root` field of a genuinely committee-signed header *after* signing and the header's own signatures still verify. The shipped mechanism (S-042, `docs/SECURITY.md §S-042`) replaces the dispatch with a **stale-height gate** plus `committee_bound_state_root` (`light/trustless_read.cpp:335-437`), which binds the anchor's `state_root` **transitively forward**: it recomputes the anchor block's full `block_hash` (which *does* cover `state_root` via `signing_bytes`) and requires the committee-signed **successor** header's `prev_hash` to equal it. The phenomenon (the temporal race) is unchanged; the binding that defeats it changed. The `==`/`>` branch distinction is gone — both route to the same successor-binding call. This document is the standalone temporal-soundness form of that shipped mechanism; it is the temporal companion of `StateRootAnchorSoundness.md` SR-1 (which proves the same `committee_bound_state_root` binding as a per-height anchor primitive). PRW-3 below is SR-1 evaluated at `anchor_index = proof_height − 1`.

The proof exists because the race window is a **structurally distinct attack surface** from leaf reconstruction and value-hash decode, with three properties that matter for soundness and that the per-namespace proofs explicitly defer to this binding:

1. **The proof root is *not* the head root the operator just verified.** `verify_chain_to_head` (`light/trustless_read.cpp:234-248`, over the shared `verify_chain_walk` core at `:105-230`) anchors a committee-signed head at height `vc.height`. The subsequent `state_proof` RPC returns a proof against `compute_state_root()` + `height()` at the daemon's *current* head (`node.cpp:3451-3452`), generally `proof_height ≥ vc.height` because the chain advanced. Naively trusting the proof's self-claimed `state_root` (verifying only that the Merkle siblings roll up to *it*, `verify_state_proof(proof, {})` at `:505`) defeats the entire trust model — a Byzantine daemon could fabricate a self-consistent proof against a forged root for a forged future height. The binding is the bridge that re-anchors the *future* root to the committee.

2. **The anchor index is off by one from the proof height, and the off-by-one is load-bearing.** `proof.height` is the *count of applied blocks*; the last applied block lives at index `proof_height − 1` and its `block.state_root` is the **post-apply** commitment (S-038 producer wiring populates `body.state_root` with "the state after applying THIS block"). So `read_account_trustless` sets `anchor_index = proof_height − 1` (`:545`) and binds against `header[proof_height − 1].state_root`, not `header[proof_height]` (which may not exist) nor `header[proof_height].state_root`. PRW-2 pins the off-by-one against the S-038 "post-apply state" semantics.

3. **A committee signature on a header does *not* directly attest that header's `state_root`.** Because `state_root ∉ compute_block_digest`, verifying the anchor header's *own* committee signatures certifies its digest-covered fields but says **nothing** about its `state_root`. The defense is the **forward link**: `committee_bound_state_root` recomputes the anchor's `block_hash` over the full body (`state_root ∈ signing_bytes ⊆ block_hash`, `:343-364`) and requires the committee-signed *successor* header's `prev_hash` to equal it (`:424-432`), because `prev_hash` **is** in `compute_block_digest`. PRW-3 formalizes that this successor binding — not a prev_hash extension walk on the anchor header — is what makes the anchor's `state_root` committee-attested.

No new cryptographic primitive is introduced. The claim is that an honest light client never **acts on** a state-proof whose root is not bound to a committee-attested header on the operator's genesis-pinned chain — for any namespace, and never on the chain head (whose `state_root` has no signed successor yet and so fails closed). The proof deepens `LightClientThreatModel.md` Lemma **L-5** and §4.4.1 (the race-window narrative inside T-L4) into five standalone theorems with an explicit adversary game, the off-by-one correctness argument, the successor-binding lemma, a forged-future-root attack, the head-fail-closed disposition, the idempotent re-anchor invariant the downstream cleartext/value cross-check relies on, and the namespace-agnosticism that lifts the result from the `a:` flow it is coded in to every composite read.

**Companion documents.** `Preliminaries.md` (F0) §2.0 (canonical assumption labels — **A1** = Ed25519 EUF-CMA §2.2, **A2** = SHA-256 collision / second-preimage §2.1, **A3** = SHA-256 preimage §2.1) — this proof reduces to **A1** (committee-signature unforgeability on the *successor* header) and **A2** (`block_hash` / `signing_bytes` collision resistance) only; the off-by-one correctness (PRW-2) and the total disposition (PRW-1) are *unconditional*; `StateRootAnchorSoundness.md` (F6 — its **SR-1** per-height committee-anchored-root statement is *exactly* the `committee_bound_state_root` binding this proof invokes at `anchor_index = proof_height − 1`, its **SR-2** genesis-binding / no-floating-header lemma is the chain-identity this proof's verified head rests on, its **SR-3** height-binding is what PRW-2's index argument leans on — `index` is inside the signed digest so the anchor header's height is committee-attested, and its **§6.3** head-regime fail-closed boundary is the per-height form of PRW-5's head-serve defense); `WaitHoldAndWaitSoundness.md` (FB64 — the soundness-neutrality of the `--wait` hold-and-wait that lets `committee_bound_state_root` poll for the head's successor rather than fail closed; PRW-5 inherits its "bind the ALREADY-HELD proof, never re-fetch" invariant); `LightClientThreatModel.md` (the malicious-daemon adversary `A_daemon` §2.1, the **T-L4** composite read whose §4.4.1 race-window mitigation and **Lemma L-5** this proof is the rigorous standalone form of, **T-L2** committee-sig head trust which PRW-3 invokes per successor header, **L-6** fail-closed exit which PRW-5 inherits); `MerkleTreeSoundness.md` (the sorted-leaves balanced binary Merkle primitive — its **MT-4** inclusion-proof soundness is what makes a proof *against a given root* meaningful; this binding's job is to certify *which* root, upstream of MT-4); `ReceiptInclusionProofSoundness.md` + `CompositeStateReadSoundness.md` + `StateProofCompositeKeySoundness.md` (the composite-key reads that invoke this binding unchanged — their RI-1 / CR-1 "committee-anchor of the proof root" step is *exactly* this binding, deferred to here; this proof discharges the obligation they cite); `StakeProofSoundness.md` + `TxInclusionProofSoundness.md` + `SupplyProofSoundness.md` (the simple-key `s:`/membership/supply reads that run the identical binding — PRW-4 namespace-agnosticism is what lets all of them share this single temporal proof); `LightClientArchiveSoundness.md` (its **AR-3(ii)** "floating slice" defense is the archival-read analog of SR-2's genesis-binding); `LightClientCompositionMap.md` (the dependency map placing this binding between the head walk and the leaf cross-check); `S033StateRootNamespaceCoverage.md` (its **§2.3** "once-emitted, always-emitted" `state_root` determinism is what guarantees `header[proof_height-1].state_root` is non-zero in the S-033-active regime PRW-2 assumes); `docs/SECURITY.md` §S-033 + §S-038 + §S-042 for the producer-side `state_root` population and the light-client binding this proof's off-by-one and forward-link rest on; `docs/PROTOCOL.md` §4.1.1 for the "state after applying THIS block" semantics + §10.2 for the `state_proof` / `headers` / `block` RPC contracts.

---

## 1. Scope

### 1.1 In scope

The temporal-anchoring step run once per trustless `state_proof` read, after the proof has been self-verified (`verify_state_proof(proof, {})`, `light/trustless_read.cpp:505`) and key-bound (the F-6 step `:488-501`) and before any cleartext / value-hash cross-check — the **stale-height gate** (`:528-533`) plus the `committee_bound_state_root` (`:335-437`) call (`:546-548`) with the post-binding `attested == proof_root` check (`:549-555`):

> Given a committee-anchored verified head `(vc.head_state_root, vc.height)` from the header walk (step 2) and a self-consistent proof claiming `(proof_root, proof_height)` from the `state_proof` RPC (step 3), the reader accepts the proof's root as authoritative **iff** it can bind `proof_root` to the `state_root` of a block at index `proof_height − 1` whose full `block_hash` is committed by a committee-signed **successor** header's `prev_hash` — otherwise it throws. A `proof_height` before the verified head is rejected outright; a `proof_height − 1` that is the current head (no signed successor yet) fails closed unless `--wait` is supplied.

The five theorems:

| Theorem | Property |
|---|---|
| **PRW-1** (Total, monotone disposition) | The reader's temporal disposition is total: `proof_height < vc.height` throws (stale, `:528-533`); `proof_height ≥ vc.height` routes to `committee_bound_state_root(proof_height − 1)`, which either binds-and-matches (accept + re-anchor), binds-and-mismatches (`attested ≠ proof_root` throws, `:549-555`), or finds no signed successor and fails closed (`:388-401`). No `proof_height` falls through unhandled; no accepted proof has `proof_height < vc.height`; no accepted proof has an unbound root. |
| **PRW-2** (Off-by-one anchor correctness) | `anchor_index = proof_height − 1` (`:545`) is the unique index whose `block.state_root` equals the post-apply state commitment for `proof_height` applied blocks, under the S-038 "state after applying THIS block" semantics; anchoring to `proof_height` or `proof_height − 2` is provably wrong. |
| **PRW-3** (Committee binding via successor `prev_hash`) | `committee_bound_state_root` binds the anchor's `state_root` under A1 + A2: it recomputes the full anchor block's `block_hash` (binding `state_root` through `signing_bytes`, `:343-364`) and requires the committee-signed successor's `prev_hash` to equal it (`:424-432`). Because `state_root ∉ compute_block_digest`, the anchor header's *own* signatures do not suffice; the **successor**'s signature (whose digest covers `prev_hash`) is what certifies the anchor's `state_root`. |
| **PRW-4** (Namespace-agnostic reuse) | The binding consumes only `proof_height` (→ `anchor_index`), the committee seed, and the `block`/`headers` RPCs — never the namespace or key — so the temporal guarantee holds identically for every simple (`a\|s\|r\|d\|b\|k\|c`) and composite (`i\|m\|p`) read; the per-namespace proofs' "committee-anchor" step is discharged here once. |
| **PRW-5** (Idempotent re-anchor + head fail-closed) | After a binding accept, the reader reassigns `(vc.head_state_root, vc.height) := (proof_root, proof_height)` (`:556-557`); the post-binding `vc` is a committee-attested head at `proof_height`, so the downstream cleartext / value-hash cross-check operates against a sound anchor. The current head's `state_root` has no signed successor, so the binding **fails closed** (`:388-401`) unless `--wait` polls for the next block and binds the ALREADY-HELD proof (FB64). The accept is idempotent. |

### 1.2 The binding (read off source)

`read_account_trustless` (`light/trustless_read.cpp:439-599`), after the self-consistency check at `:505`, computes (`proof_height = proof.value("height", 0)`, `proof_root = proof.value("state_root", "")`):

```cpp
if (proof_height < vc.height) {
    throw ... "is BEFORE verified-chain head ... — daemon is serving stale state";  // PRW-1 stale gate, :528-533
}
// build committee_json from committee_seed                                          // :536-543
uint64_t anchor_index = proof_height - 1;                                            // PRW-2 off-by-one, :545
std::string attested =
    committee_bound_state_root(rpc, committee_json, anchor_index, max_wait_seconds); // PRW-3 successor binding, :546-548
if (attested != proof_root) {
    throw ... "committee-attested state_root ... does NOT match proof.state_root";   // PRW-1 mismatch, :549-555
}
vc.head_state_root = attested;                                                       // PRW-5 re-anchor, :556-557
vc.height          = proof_height;
```

and `committee_bound_state_root` (`:335-437`):

```cpp
json full = rpc.call("block", {{"index", anchor_index}});                            // fetch FULL block, :343
Block b = Block::from_json(full);
Hash recomputed = b.compute_hash();                                                  // recompute block_hash, :364
uint64_t succ = anchor_index + 1;
auto pg = rpc.call("headers", {{"from", succ}, {"count", 1}});                       // successor header, :374
for (waited = 0; waited < max_wait_seconds && !succ_present(pg); ++waited) {         // HOLD-AND-WAIT, :383-387
    sleep(1s); pg = rpc.call("headers", {{"from", succ}, {"count", 1}});
}
if (!succ_present(pg)) throw ... "NO committee-signed successor yet (it is the chain head)";  // head fail-closed, :388-401
auto vbs = verify_block_sigs(succ_hdr, committee_json, /*bft=*/false);               // successor sigs, :409-415
if (!vbs.ok) vbs = verify_block_sigs(succ_hdr, committee_json, /*bft=*/true);
if (!vbs.ok) throw ...;
if (succ_prev != recomputed_hex) throw ... "SECURITY — successor.prev_hash != recomputed block_hash";  // THE binding, :424-432
return (b.state_root != zero) ? to_hex(b.state_root) : std::string{};                // report anchor state_root, :434-436
```

### 1.3 Out of scope (intentional)

- **The cryptographic membership soundness of the proof against the anchored root.** That `merkle_verify` against the now-certified root proves membership is `MerkleTreeSoundness.md` MT-4; this proof certifies *which root*, upstream of MT-4. The self-consistency pre-check `verify_state_proof(proof, {})` (`:505`) only confirms the proof's siblings roll up to *its own* claimed root — a sanity gate, not the anchor.
- **The key-bind (F-6).** That `proof.key_bytes` equals the canonical `"<ns>:"+key` (the F-6 forge-class defense, `:488-501`, `NegativeVerdictSoundness.md` F-6) is the *spatial* attribution check; this proof is the *temporal* complement, orthogonal to it.
- **The leaf value-hash decode.** Value-hash read-back is `ReceiptInclusionProofSoundness.md` RI-2 / `CompositeStateReadSoundness.md` CR-2 / `StakeProofSoundness.md` SP-2 / Lemma L-4.
- **The header-walk that produces `(vc.head_state_root, vc.height)`.** `verify_chain_to_head` / `verify_chain_walk` correctness is `StateRootAnchorSoundness.md` SR-2 + `LightClientThreatModel.md` T-L2; this binding consumes its output as the committee-attested verified head (and uses `vc.height` only as the stale-gate floor — the trusted root is re-derived by `committee_bound_state_root`, not taken from the walk's reported head `state_root` field).
- **Cross-invocation correlation.** Two separate trustless reads at different wall-clock times can each anchor to a different height; each invocation is sound in isolation (PRW-1..PRW-5), but the binding does not tie one invocation's height to another's. This is the `LightClientThreatModel.md` §5 cross-invocation caveat, unchanged.
- **The S-033-inactive regime.** `read_account_trustless` throws `chain has not activated state_root (S-033)` (`:458-464`) before the binding ever runs if the verified head carries an empty `state_root`; PRW-2 assumes the S-033-active regime where every header's `state_root` is non-zero (`S033StateRootNamespaceCoverage.md` §2.3).

---

## 2. Threat model

The adversary is `A_daemon`, the **malicious daemon** of `LightClientThreatModel.md` §2.1: it controls the RPC endpoint, may return arbitrary JSON for `state_proof`, `headers`, `block`, and `account`, and knows the operator's genesis and committee seed (both public). `A_daemon` does **not** possess any committee member's Ed25519 secret key (A1) and cannot exhibit a SHA-256 collision (A2).

`A_daemon`'s race-window-specific goals, all of which the binding must defeat:

- **(G1) Stale-root serve.** Return a proof at `proof_height < vc.height` carrying an old `state_root` from before the head the client just verified — making the client act on superseded state.
- **(G2) Forged-future-root serve.** Return a self-consistent proof at some `proof_height ≥ vc.height` against a fabricated `state_root` `R_A` for a state the chain never reached, hoping the client trusts the proof's self-claimed root because the chain "advanced".
- **(G3) Forked / detached anchor.** When the client binds at `anchor_index`, serve a full block + successor header from a **fork** that branched on the pinned chain, so its `state_root` appears committee-attested yet is not the operator's canonical state.
- **(G4) Off-by-one confusion.** Serve a proof whose `state_root` matches `header[proof_height].state_root` (or `header[proof_height-2]`) rather than the canonical `header[proof_height-1].state_root`, exploiting an index drift to bind the proof to the wrong block's commitment.
- **(G5) Head-root serve.** Serve a proof for the *current head* (`anchor_index = proof_height − 1` is the chain head), whose `state_root` field is **not** committee-attested (no signed successor exists, and the header's own digest excludes `state_root`), hoping the client reports the daemon-asserted head root as committee-verified.

**Security goal.** An honest client accepts the proof's `(proof_root, proof_height)` as authoritative **iff** `proof_root` is the genuine post-apply `state_root` of the operator's pinned chain at `proof_height` applied blocks, bound to a committee-signed successor at `proof_height` — defeating G1 (PRW-1 stale gate), G2/G3 (PRW-3 successor binding), G4 (PRW-2 off-by-one), and G5 (PRW-5 head fail-closed).

---

## 3. Primitives reused

The binding reuses, unchanged:

1. **`committee_bound_state_root(rpc, committee_json, anchor_index, max_wait_seconds)`** (`light/trustless_read.cpp:335-437`) — the S-042 forward-link binder; the run-time construction of `StateRootAnchorSoundness.md` SR-1. Fetches the FULL block via the `"block"` RPC (`Node::rpc_block`, `src/node/node.cpp:2623`), recomputes `block_hash`, fetches + committee-verifies the SUCCESSOR header, and requires `successor.prev_hash == recomputed block_hash`. Returns the anchor's `state_root` (empty if zero) only after that match. The `"block"` RPC returns the unstripped body, so `signing_bytes`/`compute_hash` are recomputable — the stripped `"headers"` RPC cannot give this.
2. **`verify_block_sigs(header, committee_json, bft)`** (`light/verify.cpp:235-328`) — the K-of-K committee-signature verifier (`LightClientThreatModel.md` L-2 digest binding + T-L2). `committee_bound_state_root` calls it `false`-then-`true` (`:409-415`) to accept either a non-BFT or BFT finalized **successor** header. By L-2 (digest binding, `light_compute_block_digest`, `light/verify.cpp:57-92`) the verified digest covers `index`, `prev_hash`, `tx_root`, …; forging a valid K-of-K signature over a different digest costs an A1 break.
3. **`verify_chain_walk` / `verify_chain_to_head`** (`light/trustless_read.cpp:105-230`, `:234-248`) — the prev_hash continuity + per-block committee-sig walk from genesis (or a resume anchor) to the daemon's head at walk time, producing the committee-attested verified head `(vc.head_state_root, vc.height)` PRW-1 uses as the stale-gate floor (`StateRootAnchorSoundness.md` SR-2 / `LightClientThreatModel.md` T-L2).
4. **`block.state_root` semantics** — per S-038 producer wiring (`docs/SECURITY.md §S-038`), the producer populates `body.state_root` via a tentative-chain dry-run *after* assembling the block body, so `header[k].state_root` is the state commitment **after applying block `k`**. This is the "state after applying THIS block" invariant PRW-2 pins. Because `state_root ∉ compute_block_digest` (`src/node/producer.cpp:608-693`), the post-signature population does not invalidate the committee's digest signatures; the field is bound only through `signing_bytes`/`block_hash` (`StateRootAnchorSoundness.md` §3.1-§3.2).

---

## 4. Security theorems

Throughout, fix the verified head `(R_v, h_v) := (vc.head_state_root, vc.height)` from the header walk (a committee-attested head, by `StateRootAnchorSoundness.md` SR-2), and the proof's claim `(R_p, h_p) := (proof_root, proof_height)`. Write `S(k)` for the genuine post-apply state commitment of the operator's pinned chain after `k` applied blocks, so the genuine `header[k-1].state_root = S(k)`.

### 4.1 Theorem PRW-1 (total, monotone disposition)

**Statement.** The reader's temporal disposition is total: (i) `h_p < h_v` throws unconditionally (`:528-533`), so no accepted proof has `h_p < h_v`; (ii) `h_p ≥ h_v` routes to `committee_bound_state_root(h_p − 1)`, whose every path is one of {accept-and-re-anchor (binding holds ∧ `attested = R_p`), throw (`attested ≠ R_p`, `:549-555`; or any binding sub-check fails, `:388-401`/`:404`/`:411-415`/`:424-432`), fail-closed (no signed successor, `:388-401`)}. There is no `h_p` for which the reader neither accepts nor throws, and no accepted proof carries an unbound root.

**Proof.** The control flow is `if (h_p < h_v) {throw}` (`:528-533`) followed unconditionally by `attested = committee_bound_state_root(h_p − 1)` (`:546-548`) and `if (attested ≠ R_p) {throw}` (`:549-555`). Since `h_p` and `h_v` are `uint64_t`, exactly one of `h_p < h_v`, `h_p ≥ h_v` holds.

- **(i) Stale gate.** The first `if` throws for every `h_p < h_v` with the `is BEFORE verified-chain head … serving stale state` diagnostic (`:529-532`); control never reaches the binding. Hence no accepted proof has `h_p < h_v` — **G1 is defeated unconditionally**, with no cryptographic assumption: a stale proof is rejected purely by the height comparison, regardless of whether its root is genuine or forged. (A daemon that wants the client to read superseded state cannot, because the client has already committee-verified a *later* head and refuses to regress.)
- **(ii) Binding.** For `h_p ≥ h_v`, `committee_bound_state_root(h_p − 1)` is invoked. By inspection of `:335-437` every path either returns a value `attested` (only after the successor `prev_hash` match at `:424-432` passes) or throws (`:344-353` full-block out of range / RPC error; `:388-401` no signed successor; `:404` wrong successor index; `:411-415` successor sig failure; `:424-432` `prev_hash` mismatch). If it returns, the caller's `attested ≠ R_p` check (`:549-555`) either throws or accepts with `attested = R_p`. So the binding never falls through silently, and an accepted `R_p` equals a value that survived the successor binding — never a daemon-asserted root taken on trust.

All paths terminate in an accept (with a bound, matched root) or a throw; the disposition is total.   ∎

**Remark (monotonicity).** The accepted height is monotone non-decreasing across the read: the stale gate rejects `h_p < h_v`, so a post-read `vc.height ≥ pre-read vc.height` always. This monotonicity is what PRW-5 relies on to argue the re-anchored `vc` still extends the genesis-pinned prefix.

### 4.2 Theorem PRW-2 (off-by-one anchor correctness)

**Statement.** `anchor_index = proof_height − 1` (`:545`) is the **unique** chain index `k` such that the genuine `header[k].state_root` equals the post-apply state commitment for `h_p` applied blocks, i.e. `header[anchor_index].state_root = S(h_p) = R_p` when the daemon is honest. Anchoring to `proof_height` (an index that need not exist) or `proof_height − 2` (the prior block's commitment) is provably wrong and would either fail to bind an honest proof or, under G4, bind to the wrong commitment.

**Proof.** `proof.height` is, by the `state_proof` RPC contract (`node.cpp:3452`, `chain_.height()`), the *count of applied blocks* on the daemon's chain at the moment the proof was built — the number of blocks `0 … h_p - 1`. The state commitment the proof is *against* is `compute_state_root()` evaluated *after* applying all `h_p` blocks, i.e. `S(h_p)` (`node.cpp:3451`).

By the S-038 producer semantics (§3 primitive 4), each `header[k].state_root` is the commitment **after applying block `k`** — "the state after applying THIS block". The block at index `k` is the `(k+1)`-th applied block, so `header[k].state_root = S(k+1)`. Setting `k + 1 = h_p` gives the unique `k = h_p - 1`. Therefore:

$$\texttt{header}[h_p - 1].\texttt{state\_root} = S(h_p) = R_p \quad\text{(honest daemon)}.$$

- **`proof_height` is wrong.** `header[h_p].state_root = S(h_p + 1)`, the commitment *after the next block*; and on a chain with exactly `h_p` blocks, index `h_p` does not exist as an *anchor* (it is the successor the binding fetches). Binding at `h_p` would attempt to use the successor's own successor and mis-attribute `S(h_p+1)` to the proof.
- **`proof_height − 2` is wrong.** `header[h_p - 2].state_root = S(h_p - 1)`, the commitment of the *prior* applied block. The binding's `attested = header[h_p-2].state_root = S(h_p-1)` would fail the caller's `attested ≠ R_p` check against `R_p = S(h_p)` (distinct unless the block was a no-op, and even then the commitment is re-pinned by the height field inside the digest, SR-3).

So `h_p - 1` is the unique correct index. The off-by-one is **unconditional** (a counting identity over the S-038 semantics), not a cryptographic claim. **G4 is defeated**: a daemon that serves a proof root matching `header[h_p].state_root` or `header[h_p-2].state_root` instead of `header[h_p-1].state_root` fails the `attested ≠ R_p` check at `:549-555`, because the honestly-bound `header[anchor_index].state_root` the client derives is `S(h_p)` and the daemon's mismatched root does not equal it. (If the daemon *also* forges the anchor block's body to make its `state_root` match the proof root, that lie is caught by PRW-3's successor binding — the daemon cannot make a forged body's `block_hash` equal the committee-signed successor's `prev_hash`.)   ∎

**Remark (why the comment block matters).** The `:522-525` source comment ("`proof.height` is the count of applied blocks; the LAST applied block lives at index `proof.height - 1` and its `state_root` is the post-apply commitment …") is the natural-language statement of this counting identity. PRW-2 is its formalization and the regression specification any future edit to the index arithmetic must preserve.

### 4.3 Theorem PRW-3 (committee binding via successor `prev_hash`)

**Statement.** `committee_bound_state_root(anchor_index)` accepts the anchor's `state_root` as committee-attested **iff**, under A1 + A2, (i) the full anchor block recomputes locally to a `block_hash` whose `signing_bytes` contains that `state_root` (`:343-364`), **and** (ii) a committee-signed successor header at `anchor_index + 1` carries `prev_hash == recomputed block_hash` (`:409-432`). Consequently the reported `state_root` is the one the committee committed via the successor's signed `prev_hash` — defeating **G2 and G3**. The anchor header's *own* signatures are neither used nor sufficient, because `state_root ∉ compute_block_digest`.

**Proof.** The binder runs, treating the daemon's `block`/`headers` replies as untrusted until all checks pass:

- **(a) Full-block recompute** (`:343-364`). Fetch the FULL block at `anchor_index` via the `"block"` RPC and recompute `recomputed = b.compute_hash() = SHA256(signing_bytes(b) ‖ creator_block_sigs)`. By `StateRootAnchorSoundness.md` §3.2 (`Block::signing_bytes` appends `state_root` when non-zero), the served `state_root` is *inside* `recomputed`. This step binds the daemon's *claimed anchor `state_root`* into a locally-computed hash — the daemon cannot change `b.state_root` without changing `recomputed`.
- **(b) Successor committee signature** (`:409-415`). Fetch the successor header at `anchor_index + 1` and require `verify_block_sigs(succ_hdr, committee_json, false-then-true)` to return `ok`. By L-2 (digest binding) the verified digest covers `succ_hdr.index`, `succ_hdr.prev_hash`, `succ_hdr.tx_root`, …. By T-L2 / A1, a daemon without committee secret keys cannot produce a successor header with a valid K-of-K signature except with probability `≤ K · 2⁻¹²⁸`. So after (b), the successor is a *genuine committee-attested header* whose signed digest fixes its `prev_hash`.
- **(c) Forward-link match** (`:424-432`). Require `succ_hdr.prev_hash == recomputed` (hex). The genuine successor on the pinned chain has `prev_hash(anchor_index+1) = block_hash(anchor_index)` (the chain-continuity invariant), and `block_hash(anchor_index)` is computed over `signing_bytes` containing the genuine `S(h_p)`. Two cases for a daemon serving a forged anchor `state_root R_A ≠ S(h_p)`:
  - The recompute over the `R_A` body yields a `block_hash` **different** from the genuine `block_hash(anchor_index)`. Then it cannot equal the committee-signed `prev_hash` (which equals the genuine `block_hash`), so (c) throws.
  - The recompute over the `R_A` body **collides** with the genuine `block_hash(anchor_index)` despite `R_A ≠ S(h_p)` — a SHA-256 `signing_bytes` collision, probability `≤ 2⁻¹²⁸` (A2).
  Alternatively the daemon forges the successor's signed `prev_hash` to equal the `R_A`-body hash — an A1 forgery over a different `digest(anchor_index+1)`, `≤ K · 2⁻¹²⁸`.

Combining (a)+(b)+(c): an accepted anchor `state_root` is the value committed inside a `block_hash` that a committee-signed successor's `prev_hash` certifies. This defeats **G2** (a fabricated `R_A` cannot ride inside a body whose hash matches the committee-signed successor `prev_hash` without an A2 collision or A1 forgery) and **G3** (a forked anchor would need a committee-signed successor whose `prev_hash` commits the fork's anchor `block_hash`; under the static genesis committee `K_0` and honest-supermajority, the committee signs only the canonical successor — the same chain-membership trust T-L2 / SR-1 already assume; a fork's successor either is not committee-signed (fails (b)) or, if the committee equivocated, is the FA6-slashable case outside this proof's A1 honest-committee premise). The aggregate failure probability is `≤ K · 2⁻¹²⁸ + 2⁻¹²⁸`, matching `StateRootAnchorSoundness.md` SR-1.   ∎

**Remark (why this is *successor*-bound, not anchor-header-bound).** The discarded pre-S-042 mechanism verified the *anchor header's own* committee signatures and matched `anchor.state_root == proof_root`. Because `state_root ∉ compute_block_digest`, those signatures certify nothing about the anchor's `state_root`: a daemon overwrites the field post-signing and the anchor header still verifies. PRW-3's binding is sound precisely because it leans on the **successor**'s signature, whose digest *does* cover the `prev_hash` that equals the anchor's full `block_hash` (which *does* cover `state_root`). This is the substance of S-042 (`docs/SECURITY.md §S-042`).

### 4.4 Theorem PRW-4 (namespace-agnostic reuse)

**Statement.** The binding reads only `proof.height` (→ `anchor_index`), `proof.state_root`, the committee seed, and the `block`/`headers` RPCs — it never inspects the proof's `namespace`, `key`, `key_bytes`, `value_hash`, `target_index`, `leaf_count`, or Merkle `proof` array. Therefore the temporal guarantee PRW-1..PRW-3 is **identical** for every namespace: the simple-key reads (`a|s|r|d|b|k|c`) and the composite-key reads (`i|m|p`) share one race-window proof, and the per-namespace soundness proofs' "committee-anchor of the proof root to a committee-signed header" obligation is discharged here once for all of them.

**Proof.** By inspection of `:526-557` + `:335-437`: the only proof fields consumed are `proof.value("height", …)` (`:526`) and `proof.value("state_root", …)` (`:527`). The leaf-identifying fields (`namespace`, `key`, `key_bytes`, `value_hash`, `target_index`, `leaf_count`, `proof`) are consumed *only* by the upstream key-bind (`:488-501`) and self-consistency check (`:505`) and the downstream leaf cross-check (`:573-593` for `a:`; the analogous value-hash / presence-marker check for `i|m|p`). `committee_bound_state_root` itself takes only `(rpc, committee_json, anchor_index, max_wait_seconds)` — no namespace at all. The `(height, state_root)` pair is carried by every `state_proof` reply regardless of namespace (`node.cpp:3443-3453` appends `state_root` + `height` to every branch's reply, simple and composite alike).

Hence substituting `namespace=i` (or `m`, `p`, `s`, `r`, `d`, `b`, `k`, `c`) for `namespace=a` changes neither the inputs nor the behavior of the binding. The composite reads invoke the same `committee_bound_state_root` step verbatim (their pipelines mirror it — `ReceiptInclusionProofSoundness.md` §1.4 step 5, `CompositeStateReadSoundness.md` §1.1 step 5). Therefore PRW-1..PRW-3 transfer unchanged, and those proofs' RI-1 / CR-1 obligations are satisfied by this single theorem family rather than re-proved per namespace.   ∎

**Consequence.** The temporal coordinate of *every* trustless `state_proof` read in the codebase is covered by one proof. A future namespace added to `rpc_state_proof` inherits PRW-1..PRW-5 automatically, provided its reply also carries `(height, state_root)` (which the shared reply-builder tail guarantees) — the only per-namespace work left is the spatial reconstruction (SP-CK-1-style) and the value-hash decode (RI-2 / CR-2-style).

### 4.5 Theorem PRW-5 (idempotent re-anchor + head fail-closed)

**Statement.** After a binding accept, the reader reassigns `vc.head_state_root := R_p`, `vc.height := h_p` (`:556-557`). The post-read `vc` is a committee-attested head at `h_p` — equivalent to what `verify_chain_to_head` would have produced had it walked to `h_p` — so the subsequent cleartext / value-hash cross-check (Lemma L-4 / RI-2 / CR-2) operates against a sound anchor. **The current head's `state_root` is unbindable** (no signed successor exists, and the head's own digest excludes `state_root`), so `committee_bound_state_root` **fails closed** (`:388-401`) — defeating **G5** — unless `--wait <seconds>` polls for the successor block and binds the ALREADY-HELD proof (FB64). The accept is **idempotent**: re-running the read on the same proof with the updated `vc` lands in the same binding and accepts without further state change.

**Proof.** By PRW-3, an accepted anchor `state_root = R_p = S(h_p)` is committee-attested via the successor's signed `prev_hash`; by PRW-2, the anchor is at `h_p − 1`. So the pair `(R_p, h_p)` is exactly the `(head_state_root, height)` `verify_chain_to_head` would have computed had the daemon's head been at `h_p` during step 2 — the read has *extended the verified anchor by `h_p − h_v` blocks at proof-fetch time*, with the same committee-sig guarantee the walk provides. Therefore the post-read `vc` satisfies the head-walk invariant: a committee-attested head.

The downstream cross-check (`:573-593`) recomputes the leaf value-hash and compares it to `proof.value_hash`, having already established (via `verify_state_proof` + this binding) that the proof rolls up to `vc.head_state_root = R_p`. Since `R_p` is now a sound anchor, the cross-check's conclusion — "the daemon's cleartext is consistent with the committee-attested state at `h_p`" — is sound.

**Head fail-closed (G5).** When `anchor_index = h_p − 1` is the chain head, no block `h_p` exists, so the successor fetch (`:374`) returns an empty page and `succ_present(pg)` is false. With `max_wait_seconds == 0` the poll loop (`:383-387`) does not run and the binder throws *"state_root at index … has NO committee-signed successor yet (it is the chain head) — refusing to report an unbound head state_root"* (`:388-401`). Because the daemon's `state_proof` always answers about its *current* head, a live current-state read hits this case; the client never reports the daemon-asserted head `state_root` as committee-verified — **G5 defeated**. The opt-in `--wait <seconds>` makes the binder block up to N seconds polling for the successor, then bind the **already-held** proof against the now-existing successor (`:383-387`); the proof is never re-fetched (which would race a state change), so the reported value is the committee-attested state as of the anchor (`WaitHoldAndWaitSoundness.md` FB64 — soundness-neutrality). `max_wait_seconds == 0` is byte-identical to the fail-closed disposition.

**Idempotence.** Re-running the read on the same accepted proof with the post-update `vc = (R_p, h_p)` hits `h_p == vc.height ≥ vc.height` (not stale), binds at the same `h_p − 1`, derives the same `attested = R_p`, and accepts with no further state change — a fixpoint. This guarantees the read does not *over-advance* `vc` past `h_p`, preserving the monotone-prefix invariant PRW-1's remark records.   ∎

---

## 5. Composition with the light-client proof family

The committee-binding sits between the head walk and the leaf cross-check, certifying the temporal coordinate that the membership and value proofs assume:

```
                    A1 (Ed25519 EUF-CMA)            A2 (SHA-256 collision)
                           │                               │
   verify_chain_to_head (head walk) ── (R_v, h_v) committee-attested head (SR-2)
                           │
        ┌──────────────────┴───────────────────┐
        │   S-042 COMMITTEE BINDING (THIS DOC)  │   proof claims (R_p, h_p), h_p ≥ h_v
        │   PRW-1 total disposition (defeats G1)│
        │   PRW-2 off-by-one anchor (defeats G4)│
        │   PRW-3 successor binding (defeats G2/G3)
        │   PRW-4 namespace-agnostic            │
        │   PRW-5 re-anchor + head fail (defeats G5)
        └──────────────────┬───────────────────┘
                           │  certifies R_p = S(h_p) on the pinned chain
                           ▼
              MerkleTreeSoundness MT-4 (proof against R_p ⇒ leaf membership)
                           │
        ┌──────────────────┴───────────────────┐
   simple-key value decode            composite-key reconstruction + decode
   StakeProofSoundness SP-2 / L-4     SP-CK-1 (key) + RI-2 / CR-2 (value)
```

- **PRW-1 and PRW-2 are unconditional** (total disposition + a counting identity over S-038 semantics); they assume no cryptographic hardness.
- **PRW-3 reduces to A1 (successor-sig forge) + A2 (`signing_bytes`/`block_hash` collision)** — exactly the `StateRootAnchorSoundness.md` SR-1 bound, applied at `anchor_index = h_p − 1`.
- **PRW-4 and PRW-5 are structural** (an input-dependence argument + a head-existence/fixpoint argument), assuming no hardness beyond what PRW-1..PRW-3 already established (the `--wait` leg is soundness-neutral by FB64).

The end-to-end temporal soundness: SR-2 certifies the verified head `(R_v, h_v)` → this binding extends the certification to the proof's `(R_p, h_p)` over the race window (A1 + A2) → MT-4 makes a passing proof against `R_p` prove leaf membership (A2) → the per-namespace value/key proofs interpret the membership soundly. Aggregating with the `LightClientThreatModel.md` T-L4 bound, `Pr[A_daemon defeats the race-window binding] ≤ K · 2⁻¹²⁸ + 2⁻¹²⁸`, which is `≤ 2⁻⁹²` for practical chains (`K ≤ 16`) — matching the §4.4.1 / SR-1 concrete bound, now derived from standalone theorems.

---

## 6. Known limitations and findings

- **F-1 (per-invocation, not cross-invocation).** PRW-1..PRW-5 secure a *single* read's temporal anchor. Two reads at different wall-clock times can anchor to different heights; the binding does not tie invocation `n`'s height to invocation `n+1`'s. A daemon that consistently serves an *old-but-committee-attested* head across all of an operator's queries cannot make any individual query unsound, but can hold the operator at a stale (yet genuine, committee-attested, prefix-extending) height — a liveness/freshness limitation, not a safety one. This is the `LightClientThreatModel.md` §5 cross-invocation caveat; orthogonal to this proof, which is per-invocation safety.
- **F-2 (head reads require the chain to advance one block).** Because `committee_bound_state_root` binds the anchor through its *successor*, the current head's `state_root` is unbindable until block `h_p` is produced. A live current-state read therefore either fails closed (default `--wait 0`) or blocks up to `--wait <seconds>` for the next block (FB64). Not a soundness gap — it is the *reason* the head is sound (an unbound head root is refused) — but it is a usability/latency consideration the `--wait` flag addresses without weakening soundness.
- **F-3 (off-by-one is implementation-pinned to S-038 semantics).** PRW-2's `anchor_index = h_p − 1` is correct *because* `block.state_root` is the post-apply commitment (S-038). If a future change made `state_root` the *pre-apply* commitment (the state before applying the block), the anchor index would shift to `h_p` and PRW-2 would break silently. The S-038 "state after applying THIS block" invariant must remain stable; it is cross-referenced in `docs/SECURITY.md §S-038` and `S033StateRootNamespaceCoverage.md §2.3`, and exercised end-to-end by `tools/test_light_verify_receipt_inclusion.sh` (a real 2-shard INCLUDED whose proof binds through this step).
- **F-4 (committee binding assumes the static genesis committee `K_0`).** `committee_bound_state_root` verifies the successor header's signatures against the seed map built from `genesis.json`'s `initial_creators` (`build_genesis_committee`, `light/trustless_read.cpp:46-53`) — the same `K_0`-only assumption every light-client verifier makes (`LightClientThreatModel.md §6.5 + F-1`, `StateRootAnchorSoundness.md §6.2`). On a chain whose committee rotated via mid-chain REGISTER/DEREGISTER, the successor sig check fails closed at the first non-`K_0` signer — a positive safety property, but it means cross-rotation heights are not bindable without an operator-supplied extended committee map. Inherited, not introduced here.
- **F-5 (fail-closed inherited).** Every failure path in the binding throws (`:529`, `:344`, `:350`, `:388`, `:404`, `:411`, `:424`, `:550`), propagating to the CLI dispatcher as a non-zero exit with a structured diagnostic — no silent downgrade to "trust the daemon's claimed root" (`LightClientThreatModel.md` L-6). This proof adds these throw sites to the L-6 enumeration of fail-closed exits.

---

## 7. Summary

Every trustless `state_proof` read verifies a proof against a `state_root` the daemon claims for a height that — because the chain advanced during the RPC round-trip — is generally *ahead* of the committee-verified head the client walked to. This document proves the soundness of the S-042 binding that re-anchors that future root to the committee: **PRW-1** — the disposition is total and monotone, rejecting stale roots (`h_p < h_v`) unconditionally and routing every `h_p ≥ h_v` through `committee_bound_state_root`, which never accepts an unbound root; **PRW-2** — the anchor index `proof_height − 1` is the unique index whose `block.state_root` is the post-apply commitment for `h_p` applied blocks under the S-038 semantics, defeating off-by-one confusion; **PRW-3** — the anchor's `state_root` is bound *transitively forward*: its full `block_hash` (which covers `state_root` via `signing_bytes`) must equal a committee-signed **successor**'s `prev_hash`, because the anchor header's own digest excludes `state_root` (A1 + A2); **PRW-4** — the binding consumes only `(height, state_root)` and the committee seed, so the temporal guarantee is namespace-agnostic and discharges the "committee-anchor" obligation cited by every simple-key and composite-key read once; **PRW-5** — the re-anchor reassigns `vc` to a sound committee-attested head at `h_p`, idempotently, and the current head fails closed (no signed successor) unless `--wait` polls for the next block and binds the already-held proof. PRW-1/PRW-2 are unconditional; PRW-3 reduces to A1 + A2 exactly as `StateRootAnchorSoundness.md` SR-1 does; PRW-4/PRW-5 are structural. The result is the rigorous standalone temporal form of `LightClientThreatModel.md` Lemma L-5 / §4.4.1, composing underneath `MerkleTreeSoundness.md` MT-4 and feeding the per-namespace value/key proofs the *temporal* coordinate they assume.
