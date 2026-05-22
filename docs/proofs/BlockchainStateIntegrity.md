# BlockchainStateIntegrity — composition theorem (S-021 + S-033 + S-038 + apply-time gate)

This document formalizes the composition theorem showing that four independently-shipped state-integrity invariants — S-021 (chain.json wrap + load-time head_hash recompute), S-033 (state_root Merkle commitment in `Block::signing_bytes`), S-038 (producer-side population of `body.state_root`), and the apply-time recompute-and-throw gate inside `Chain::apply_transactions` — together provide **complete** state-integrity coverage across the three operational surfaces (at rest, at produce, at receive). Any state divergence between two honest nodes is detected at apply time, surfaced as a loud `runtime_error` with byte-precision diagnostic, and never silently propagated.

The proof is structural rather than cryptographic: each of the four mechanisms operates on a disjoint surface, and the four surfaces together exhaust the state-mutation lifecycle. The argument exists to make explicit, in one place, why the composition is total — an external auditor reviewing only `SECURITY.md` would see three separate mitigations stacked but might miss that they collectively cover every path by which a state divergence could be introduced and propagated.

**Companion documents.** `Preliminaries.md` (F0) §1.3 + §2.1 for hash conventions and SHA-256 collision resistance (A2); `SECURITY.md` §S-021 + §S-033 + §S-038 for the per-mechanism closure narratives this proof composes; `AccountStateInvariants.md` (FA-Apply-1) for the apply-determinism invariant that T-3 + T-4 invoke; `S030-D2-Analysis.md` §3.5 for the D1/D2 closure context (the broader consensus-safety argument that consumes T-2 + T-4 as inputs); `SnapshotEquivalence.md` (FA-Apply-2) for the parallel snapshot-side composition (S-021 has a sibling head_hash check at `restore_from_snapshot`); `WireFormatBackwardCompat.md` for the zero-skip backward-compat layer that lets S-038's wiring ship without forking pre-S-033 chains; `RpcAuthHmacSoundness.md` for the citation style and the surface-decomposition argument-pattern.

---

## 1. Theorem statements

**Setup.** Let `C` denote a Determ chain — a sequence of blocks `B_0, B_1, …, B_{h-1}` together with the post-apply state derived by `Chain::apply_transactions` over the sequence. Let `state(C)` denote the canonical state map (the union of `accounts_ ⊎ stakes_ ⊎ registrants_ ⊎ applied_inbound_receipts_ ⊎ abort_records_ ⊎ merge_state_ ⊎ pending_param_changes_ ⊎ dapp_registry_ ⊎ genesis-pinned-constants ⊎ A1-supply-counters`, the ten-namespace canonical state set documented in `PROTOCOL.md §4.1.1`). Let `MR(state(C))` denote `Chain::compute_state_root()` over that state (sorted-leaves balanced binary Merkle tree per `include/determ/chain/chain.hpp:262-270`).

Let `head_hash(C)` denote `compute_hash(B_{h-1})`, the chain anchor that `Chain::head_hash()` returns (`src/chain/chain.cpp:71-73`).

Two honest nodes `N_a` and `N_b` are **state-divergent at height `h`** iff they both have a chain prefix of length `h+1` but their `Chain::compute_state_root()` outputs differ.

**Theorem T-1 (Chain Integrity at Load Time, S-021).** Let `path` be the operator-supplied chain file path. Loading `chain.json` via `Chain::load(path, ...)` with a tampered block-body in `j["blocks"][i]` for any `i ∈ [0, h)` but a matching `j["head_hash"]` field (the head's `compute_hash` over the *tampered* sequence is fed into `head_hash`, i.e., the attacker recomputes the head hash to "patch" the wrap) is detected by the chain's `prev_hash` chain consistency check during replay. Tampering block `i` requires regenerating `B_i.compute_hash()`; this propagates to `B_{i+1}.prev_hash`, which now doesn't match what the on-disk `B_{i+1}` actually carries (assuming the attacker tampered only block `i`). The chain rejects mid-load with the block's own `prev_hash` mismatch from `Chain::append` at `src/chain/chain.cpp:54-58`. If the attacker tampers ALL blocks from `i` onward to fix up the chain, then they have effectively forged a divergent committee-signed history — which requires breaking Ed25519 EUF-CMA (A1 / `Preliminaries.md` §2.2) for the committee members at each affected block.

The wrapping `head_hash` field is the **single-byte O(1)** entry check: load-time recompute compares the head's recomputed `compute_hash()` against `j["head_hash"]`. Mismatch → throw `"chain file: head_hash mismatch (tampering or corruption?)"` before replay completes (`src/chain/chain.cpp:2037-2051`).

**Theorem T-2 (Apply-Time State Divergence Detection, S-033 + S-038).** Let `N_a` be an honest node receiving block `B_h` from gossip, with chain prefix `B_0, …, B_{h-1}` and state `state(C_{h-1})`. Let `B_h.state_root = r` (non-zero by S-038's wiring on every post-S-038-shipped block). `Chain::apply_transactions` runs the apply-effects update on `state(C_{h-1}) → state(C_h)`, then re-derives `r' := Chain::compute_state_root()` over the resulting state, then compares `r' == r`. For any divergence between `N_a`'s post-apply state and the producer's post-apply state (different account balance, different stake bucket, different applied-receipt set, different abort-records, different counters, etc., across any of the ten S-033 namespaces), `r' ≠ r` by `MR`'s pre-image-uniqueness (SHA-256 collision resistance, A2), and `apply_transactions` throws `"state_root mismatch at block <h>: block declares <hex> but computed <hex> (S-033)"` (`src/chain/chain.cpp:1432-1444`). The receiver does NOT advance its chain; the divergent block is rejected.

**Theorem T-3 (Producer Self-Apply Consistency, S-038).** Let `N_p` be the round's proposer. At `try_finalize_round` (`src/node/node.cpp:1024-1117`), the producer:

1. Builds `body := build_body(...)` (no `state_root` set).
2. Constructs `tentative_chain := chain_` (deep copy of the producer's chain).
3. Runs `tentative_chain.append(body)` (which runs `apply_transactions` internally on the body with zero state_root; the apply-time gate at chain.cpp:1432 short-circuits the comparison because `body.state_root == 0` per the zero-skip backward-compat shim).
4. Reads `body.state_root := tentative_chain.compute_state_root()` (the canonical post-apply Merkle root).
5. Calls `apply_block_locked(body)` on the live chain (which calls `chain_.append(body)`; the apply-time gate now sees `body.state_root ≠ 0` and compares against `chain_.compute_state_root()`).

By **FA-Apply-1** (apply determinism — `AccountStateInvariants.md` I-1..I-6 + the determinism of `std::map` iteration over UTF-8-sorted keys), running `apply_transactions(body)` on `chain_` (which is byte-identical to `tentative_chain` before append) produces a byte-identical post-apply state. Therefore `chain_.compute_state_root() == tentative_chain.compute_state_root() == body.state_root`, and the apply-time gate at chain.cpp:1432 passes by equality. Self-apply NEVER triggers the S-033 gate's loud-fail path.

**Theorem T-4 (Cross-Node Apply Consistency).** Let `N_a` and `N_b` be two honest nodes both holding chain prefix `B_0, …, B_{h-1}` with byte-identical `state(C_{h-1})` at every key. When both receive the same block `B_h` (transitively via gossip), both compute `state(C_h)` by `apply_transactions(B_h)`. By **FA-Apply-1**:

$$
\mathrm{state}(C_h)^{N_a} \;=\; \mathrm{state}(C_h)^{N_b}.
$$

By T-2 (apply-time gate), if either node had silently produced a divergent state (e.g., apply ordering reversed, integer overflow, wrong tx canonicalization, missing receipt admission), that node would have rejected `B_h` with the S-033 loud-fail. So either:

- Both apply successfully and the post-apply states are byte-identical (the FA-Apply-1 case), OR
- One or both apply-rejects loudly and refuses to advance (the T-2 case).

In neither case do honest nodes silently diverge.

**Theorem T-5 (Composition Theorem).** S-021 + S-033 + S-038 + the apply-time gate at `src/chain/chain.cpp:1432-1444` together provide:

- **At rest (load time):** A chain.json that's been tampered with on disk is detected by the wrapping `head_hash` check before replay completes (T-1). Tampering propagates through `prev_hash` chain consistency, requiring breaking Ed25519 EUF-CMA to forge the full re-signed chain — outside any operationally-feasible attack.
- **At produce time (self-apply):** The producer's own `body.state_root` is consistent with the producer's own post-apply state by construction (T-3 + FA-Apply-1). Self-apply is structurally safe — the producer cannot trigger the S-033 gate against itself.
- **At apply time (receive):** Any state divergence between the producer's declared state and the receiver's computed state is detected loud-fail at apply (T-2). The receiver does not advance its chain on divergent blocks; the operator sees a byte-precision `state_root mismatch at block <h>` diagnostic.
- **Steady-state (cross-node convergence):** Honest nodes starting from the same state and applying the same block sequence reach byte-identical state at every height (T-4). State divergence is impossible without one party rejecting a block.

The composition is **structural by surface decomposition**: each invariant operates on a disjoint operational phase (at rest / produce / receive). The four phases together exhaust the state-mutation lifecycle, so the composition is total over the state-integrity surface.

---

## 2. Background

### 2.1 S-021 — Chain.json wrap

`Chain::save` (chain.cpp:1944-1985) writes the chain.json file as a wrapping JSON object `{head_hash: hex(compute_hash(B_{h-1})), blocks: [B_0, …, B_{h-1}]}`. Pre-S-021, the file was a top-level array of blocks with no anchor. `Chain::load` (chain.cpp:1987-2054) accepts both formats: legacy array form is a no-op fallback that the next save() upgrades; wrapped form runs the recompute-and-compare at chain.cpp:2046-2050. Mismatch throws `"chain file: head_hash mismatch (tampering or corruption?); …"`. The `prev_hash` chain consistency check inside `Chain::append` (lines 54-58) catches mid-load tampering of any non-head block — each block's `prev_hash` must equal `head_hash()` of the prior prefix.

### 2.2 S-033 — State commitment in signing_bytes

`Block.state_root` (block.hpp:460-484) is a 32-byte SHA-256 hash. Non-zero values commit to `Chain::compute_state_root()` over the post-apply state. The closure added the field, wired it into `Block::signing_bytes()` under the zero-skip backward-compat shim (`WireFormatBackwardCompat.md` T-1), and added the apply-time gate at `Chain::apply_transactions` (chain.cpp:1432-1444).

The Merkle commitment is built over a ten-namespace canonical leaf set (`chain.hpp:236-269` + `PROTOCOL.md §4.1.1`):

| Namespace | Source | Namespace | Source |
|---|---|---|---|
| `a:` | accounts_ (balance + next_nonce) | `m:` | merge_state_ (per shard) |
| `s:` | stakes_ (locked + unlock_height) | `p:` | pending_param_changes_ (A5 staging) |
| `r:` | registrants_ (ed_pub + lifecycle) | `d:` | dapp_registry_ (S-037 closure) |
| `i:` | applied_inbound_receipts_ | `k:` | genesis-pinned constants |
| `b:` | abort_records_ | `c:` | A1 supply counters |

Every state mutation that `apply_transactions` performs maps into one or more of these namespaces; any divergence produces a different Merkle root by SHA-256 pre-image-uniqueness (A2).

### 2.3 S-038 — Producer wiring (historical gap)

Pre-S-038, `Node::try_finalize_round` did NOT populate `body.state_root` before broadcast. Every gossiped block carried `state_root = 0`; the S-033 gate's zero-skip backward-compat shim (`if (b.state_root != zero) verify`) short-circuited on every block. **The S-033 mitigation existed as data-layer infrastructure but was dormant in production.** This was discovered while writing the S-037 regression test — the snapshot tail-head's `state_root` field was observed empty in JSON. The S-038 closure (`SECURITY.md` §S-038) fixes the producer to populate `body.state_root` via a tentative-chain dry-run between `build_body` and `apply_block_locked`. Post-S-038, every produced block has `state_root = compute_state_root()`.

Critical: `compute_block_digest` (K-of-K signature target) **excludes** `state_root` (per `PROTOCOL.md §4.3` + `determ test-domain-separation`), so populating `state_root` AFTER signatures gather does NOT invalidate the gathered signatures. Only `compute_hash` (block_hash, via `signing_bytes`) **includes** `state_root` when non-zero, so the block_hash binds the commitment transitively forward via the next block's `prev_hash`.

### 2.4 The apply-time gate at chain.cpp:1432

```cpp
Hash zero{};
if (b.state_root != zero) {
    Hash computed = compute_state_root();
    if (computed != b.state_root) {
        throw std::runtime_error(
            "state_root mismatch at block <h>: block declares <hex> but computed <hex> (S-033)");
    }
}
```

The gate runs **after** all in-block mutations are committed to the chain's state maps. If it throws, the exception propagates out of `Chain::append`; the caller (`apply_block_locked`) rolls back via the A9 atomic-apply mechanism (`SECURITY.md` §S-002). The chain does not advance on a divergent block.

---

## 3. Implementation citations

The four load-bearing call sites:

| Site | File / lines | Role |
|---|---|---|
| `Chain::append` prev_hash check | `src/chain/chain.cpp:54-58` | T-1 mid-chain tampering detection (throws `"Block prev_hash mismatch"` if the loaded block's `prev_hash` doesn't equal `head_hash()` of the prior prefix). |
| `Chain::apply_transactions` S-033 gate | `src/chain/chain.cpp:1421-1446` | T-2's central mechanism. Compares `b.state_root` against locally-recomputed `compute_state_root()`; throws `"state_root mismatch at block <h>: …"` on divergence. Sketched in §2.4 above. |
| `Chain::save` wrap | `src/chain/chain.cpp:1944-1985` | Writes wrapping JSON `{head_hash, blocks}`. `head_hash` is `to_hex(blocks_.back().compute_hash())`. |
| `Chain::load` wrap check | `src/chain/chain.cpp:1987-2054` | T-1's primary mechanism. Loads wrapped form, replays each block (with `prev_hash` continuity check inside each `apply_transactions`), and compares head's recomputed `compute_hash` against `j["head_hash"]` at lines 2037-2051. Accepts legacy array form as no-op fallback. |
| `Node::try_finalize_round` state_root population | `src/node/node.cpp:1024-1117` (S-038 wiring at 1093-1117) | T-3's mechanism. Builds `body`, runs `tentative_chain = chain_; tentative_chain.append(body); body.state_root = tentative_chain.compute_state_root();` before `apply_block_locked(body)` and `gossip_.broadcast`. The pattern mirrors the digest dry-run in `start_block_sig_phase` (node.cpp:993-1002). |

Two layered checks at load time provide redundant detection: the `prev_hash` continuity inside each `apply_transactions(b)` call catches mid-chain tampering during replay, and the wrapping `head_hash` field provides O(1) entry detection at the file boundary. Even if an attacker patches `head_hash` to match a tampered head's recomputed hash, the chain's `prev_hash` continuity catches the divergence at the next block boundary (where the attacker would need to re-sign the affected committee signatures — A1).

`compute_block_digest` (the K-of-K signature target) **excludes** `state_root` (per `PROTOCOL.md §4.3` and the test-suite verification in `determ test-domain-separation`), so populating `state_root` AFTER signatures gather in T-3's flow does NOT invalidate the gathered committee signatures. Only `compute_hash` (block_hash, via `signing_bytes`) **includes** `state_root` when non-zero, so the block_hash binds the state commitment transitively forward via the next block's `prev_hash`.

---

## 4. Proofs

### 4.1 Proof of T-1 (Chain Integrity at Load Time, S-021)

Fix any chain.json file `path` written by an honest node via `Chain::save` (so it has the wrapped form). Let an adversary tamper any byte of any block `B_i` in `j["blocks"][i]` for `i ∈ [0, h)`. We analyze each tampering case:

**Case (a): adversary tampers only `B_i` (`i < h-1`), leaves `j["head_hash"]` untouched.** Loading runs `apply_transactions(B_i)` followed by `apply_transactions(B_{i+1})`. `B_{i+1}.prev_hash` on disk is whatever the honest save produced, equal to `compute_hash(B_i_pre_tampering)`. But `head_hash()` after the tampered `B_i` is replayed equals `compute_hash(B_i_post_tampering)`. By SHA-256 collision resistance (A2 / `Preliminaries.md` §2.1), `compute_hash(B_i_pre_tampering) ≠ compute_hash(B_i_post_tampering)` except with probability `≤ 2⁻¹²⁸`. So `B_{i+1}.prev_hash ≠ head_hash()`, and `Chain::append` at line 55 throws `"Block prev_hash mismatch"`. Load fails mid-replay.

**Case (b): adversary tampers only `B_{h-1}` (the head), leaves `j["head_hash"]` untouched.** Replay completes (no `prev_hash` mismatch at any intermediate boundary since only the head changed). The wrapping check at line 2046 then computes `to_hex(c.blocks_.back().compute_hash())` — the head's post-tampering hash — and compares against `j["head_hash"]` (the pre-tampering hash). By A2, these differ with probability `1 - 2⁻¹²⁸ ≈ 1`. Throw `"chain file: head_hash mismatch (tampering or corruption?)"`. Load fails at the wrap check.

**Case (c): adversary tampers `B_i` AND patches `j["head_hash"]` to a recomputed-head value that's consistent with the tampered chain.** This requires the adversary to recompute every `compute_hash(B_j)` for `j ∈ [i, h-1]` to satisfy each block's `prev_hash` continuity. But every block's compute_hash is over `signing_bytes`, which includes the committee signatures `creator_block_sigs` (signed under Ed25519). To produce a different `B_j` (for `j > i`) whose new `prev_hash` aligns with the tampered prior, the adversary must produce new `signing_bytes` and therefore new committee signatures over the new digest. This requires forging Ed25519 signatures under the committee members' keys for every affected block — breaking A1 (Ed25519 EUF-CMA per `Preliminaries.md` §2.2) for every committee member at every affected height.

In all three cases, the load-time integrity check rejects the tampered file. Case (c) reduces to A1; cases (a) and (b) reduce to A2. The composition gives: `Pr[undetected tampering] ≤ q_A1 · ε_A1 + q_A2 · ε_A2`, where `q_A1`, `q_A2` are the number of cryptographic queries the adversary makes and `ε_A1`, `ε_A2` are the operational signature-forgery and collision-finding bounds. Both terms are negligible.

The wrapping `head_hash` field is the **fast-path entry check** — O(1) hash-compare vs. O(h) replay — which provides operational benefit (fail-fast on corrupted files without replaying the entire chain) while the underlying `prev_hash` chain provides the cryptographic depth.   ∎

### 4.2 Proof of T-2 (Apply-Time State Divergence Detection, S-033 + S-038)

Fix an honest receiver `N_a` holding `state(C_{h-1})`. Let `B_h` be a block received from gossip with `B_h.state_root = r ≠ 0`. `Chain::apply_transactions` runs the in-block mutations in canonical order (the per-tx apply loop, abort_events apply, equivocation_events slashing apply, cross_shard_receipt admission, A1 counter updates, etc.). Let `state(C_h)^{N_a}` denote `N_a`'s post-apply state.

The gate at chain.cpp:1432 then runs:

1. `Hash zero{}` — initialize 32-byte zero sentinel.
2. `if (b.state_root != zero)` — since `r ≠ 0`, branch taken.
3. `Hash computed = compute_state_root()` — `N_a` runs `Chain::compute_state_root()` over `state(C_h)^{N_a}`. By the determinism of `std::map` iteration + `merkle_root` over the ten-namespace canonical leaves, `computed = MR(state(C_h)^{N_a})`.
4. `if (computed != b.state_root)` — compare the locally-derived Merkle root against the declared `r`.

If `MR(state(C_h)^{N_a}) ≠ r`, the throw at line 1443 fires. The receiver does NOT push `B_h` onto `blocks_` (the throw propagates out of `apply_transactions`, then out of `Chain::append` at the call site, before `blocks_.push_back(std::move(b))` runs).

For the gate to be sound, we need: **divergence in `state(C_h)^{N_a}` (vs the producer's `state(C_h)^{N_p}`) implies `MR(state(C_h)^{N_a}) ≠ r`**. This reduces to two claims:

**Claim (i): `MR` is a function** — same canonical state set ⇒ same root. This holds because `compute_state_root` iterates `std::map` in sorted-key order, produces a deterministic sorted-leaves vector, and feeds into `merkle_root` which is a deterministic SHA-256 tree. The full argument is in `AccountStateInvariants.md` §3 + `SnapshotEquivalence.md` T-S6.

**Claim (ii): `MR` is injective up to A2** — different canonical state sets ⇒ different roots except with cryptographically-negligible probability. This holds because every state difference maps into a different leaf (different value-hash in the same namespace, or a different key entirely in some namespace), and the Merkle tree's pre-image-collision probability under SHA-256 is `≤ 2⁻¹²⁸` per A2.

Together: if `state(C_h)^{N_a} ≠ state(C_h)^{N_p}` then `MR(state(C_h)^{N_a}) ≠ r = MR(state(C_h)^{N_p})` with probability `≥ 1 - 2⁻¹²⁸`, and the gate fires.

The diagnostic format (chain.cpp:1436-1442) includes the first 4 bytes of both expected and computed `state_root` — sufficient byte-precision for operator forensics. The S-033 tag in the error string makes the failure traceable to this proof's mechanism.   ∎

### 4.3 Proof of T-3 (Producer Self-Apply Consistency, S-038)

Fix the producer `N_p` at `try_finalize_round`. The producer has chain `C_p` with state `state(C_p)`. The producer builds `body` (no `state_root` yet) and runs:

1. `chain::Chain tentative_chain = chain_;` — deep copy of `C_p`. `tentative_chain` and `chain_` now have byte-identical `blocks_`, byte-identical state maps, byte-identical genesis-pinned constants and A1 counters.
2. `tentative_chain.append(body);` — runs `apply_transactions(body)` on `tentative_chain`. Since `body.state_root == 0`, the S-033 gate at chain.cpp:1432 short-circuits (the `if (b.state_root != zero)` predicate is false). The apply proceeds normally and produces `tentative_chain`'s post-apply state `state(tentative)`.
3. `body.state_root = tentative_chain.compute_state_root();` — assigns `r := MR(state(tentative))` to the body.
4. `apply_block_locked(body);` → `chain_.append(body);` → `apply_transactions(body)` on `chain_`. The gate at chain.cpp:1432 now sees `body.state_root = r ≠ 0` and enters the comparison.

The comparison computes `chain_.compute_state_root()` and compares against `r`. We need: `chain_.compute_state_root() == r`. This is where FA-Apply-1 (apply determinism) does the work.

By FA-Apply-1 (`AccountStateInvariants.md` §3, in particular Theorem T-A1 — full apply-path determinism): for any two chains `C_a` and `C_b` with `state(C_a) = state(C_b)` byte-for-byte, applying the same block `body` to both yields `state(C_a')` and `state(C_b')` byte-for-byte equal. Since `tentative_chain` and `chain_` had byte-identical state at step 1, and both ran `apply_transactions(body)` at steps 2 and 4 respectively, their post-apply states `state(tentative)` and `state(chain_after)` are byte-identical.

Therefore `chain_.compute_state_root() = MR(state(chain_after)) = MR(state(tentative)) = r`, and the gate's comparison passes by equality. Self-apply NEVER triggers the gate's loud-fail path.

A subtle point: the gate's comparison uses `compute_state_root()` over `chain_`'s state at the moment of the call — AFTER the in-block apply mutations have already mutated `chain_.accounts_` etc. So the comparison is "what the producer says the state should be" vs "what the producer's apply actually produced." By determinism (FA-Apply-1) + the byte-identical starting state (step 1's deep copy), these match.   ∎

### 4.4 Proof of T-4 (Cross-Node Apply Consistency)

Fix two honest nodes `N_a` and `N_b`. Both have processed the same block sequence `B_0, …, B_{h-1}` from a common starting state (e.g., the genesis block `B_0` whose state is pinned by the operator config). We claim: at every height `h ≥ 0`, `state(C_{h})^{N_a} = state(C_{h})^{N_b}` byte-for-byte.

**Base case (`h = 0`).** Both nodes initialize from the same genesis. Genesis is loaded by `Chain::load` or constructed from `GenesisConfig`; both paths produce a deterministic genesis state (the operator's pinned `genesis_hash` ensures both nodes agree on the genesis block, and `apply_transactions(B_0)` produces a deterministic initial state by FA-Apply-1).

**Inductive step (`h → h+1`).** Assume `state(C_h)^{N_a} = state(C_h)^{N_b}` (induction hypothesis). Both nodes receive the same block `B_{h+1}` via gossip (a gossiped block is byte-identical across honest peers because the producer broadcasts a single body — and the wire format is byte-deterministic per the JSON / binary-codec encoders). Both nodes run `apply_transactions(B_{h+1})`.

By FA-Apply-1, applying the same block to byte-identical starting states yields byte-identical post-apply states. So `state(C_{h+1})^{N_a} = state(C_{h+1})^{N_b}`.

What if a node fails apply (the gate fires)? By T-2, this only happens if the node's local apply diverges from the producer's declared `state_root`. Under the inductive hypothesis (both nodes had byte-identical state at `h`), both nodes' apply produces the same post-apply state, and both either pass the gate or fail it identically. By T-3 (producer self-apply consistency), an honestly-produced block has `state_root = MR(state(C_{h+1})^{producer})`. If `N_a`'s and `N_b`'s post-apply states match the producer's (which holds by the inductive hypothesis + FA-Apply-1), both nodes' computed `state_root` equals the declared value and both apply succeeds.

So the only way honest nodes can diverge in apply outcomes is if their starting states are already different — which contradicts the inductive hypothesis. Therefore by induction, honest nodes converge byte-for-byte at every height.

A note on what this proof does NOT require: it does NOT assume the producer is honest. The argument is symmetric between producer-honesty and producer-Byzantine cases — if the producer is Byzantine and signs a block with mismatched `state_root` (e.g., manipulated body bytes vs declared root), the apply-time gate at T-2 fires on every honest receiver and the chain doesn't advance. Honest nodes still converge: they all reject the Byzantine block at the same boundary.   ∎

### 4.5 Proof of T-5 (Composition Theorem)

The four invariants form a surface-disjoint composition. Let `Surface_load`, `Surface_produce`, `Surface_receive`, and `Surface_steady` denote the four operational surfaces:

- `Surface_load`: chain.json on disk being read into memory. Boundary: process start, snapshot restore, manual reload.
- `Surface_produce`: a node assembling and broadcasting a block. Boundary: `try_finalize_round` → `gossip_.broadcast`.
- `Surface_receive`: a node receiving a block from gossip and attempting to apply it. Boundary: `on_block` → `apply_block_locked` → `chain_.append`.
- `Surface_steady`: the invariant maintained between honest nodes over time, conditional on the above three.

Each invariant covers exactly one surface:

| Surface | Invariant | Mechanism | Theorem |
|---|---|---|---|
| `Surface_load` | S-021 | wrap + `prev_hash` chain | T-1 |
| `Surface_produce` | S-038 + FA-Apply-1 | tentative-chain dry-run | T-3 |
| `Surface_receive` | S-033 apply-gate | `compute_state_root()` recompute + throw | T-2 |
| `Surface_steady` | FA-Apply-1 (induction over T-2 + T-3) | apply determinism | T-4 |

The four surfaces are mutually disjoint by definition (each is a different program code path), and their union covers every operational path by which state can be introduced or mutated in a Determ node:

- A chain enters memory only via `Surface_load` (T-1 protects).
- A block becomes part of the chain only via either `Surface_produce` (the local node produces; T-3 protects) or `Surface_receive` (a remote node produced; T-2 protects).
- After `Surface_load` / `Surface_produce` / `Surface_receive` operations have been applied, the chain's steady state evolves according to FA-Apply-1 under T-4.

Therefore the composition is **total over the state-integrity surface**: any state divergence introduced by any of the four operational paths is detected by the corresponding invariant. There is no fifth path where state could be introduced or mutated outside of these four (the chain has no admin interface, no per-transaction state-override path, no out-of-band consensus pathway).

The composition is **independent**: the four invariants do not assume each other. T-1 (S-021) does not depend on S-033 or S-038 — the load-time wrap check is a self-contained mechanism. T-2 (S-033 gate) depends on S-038 only for the apply-gate to actually fire on production blocks (pre-S-038 the gate was dormant; post-S-038 the gate is active for every block); but the gate's logic stands alone. T-3 (S-038 self-apply) depends on FA-Apply-1 (apply determinism), not on T-1 or T-2 directly. T-4 (cross-node consistency) is a composition lemma of T-2 + T-3 + FA-Apply-1.

The independence means a failure of any one of the four mechanisms (say, a bug in S-021's wrap check) would degrade the corresponding surface but not invalidate the others — defense in depth is preserved. In particular, even if T-1 failed and a tampered chain were loaded, the next block applied to it (by T-2) would either accept it (if the tampering preserved canonical state somehow — degenerate case) or reject it loudly. Conversely, if T-2 were bypassed (e.g., the gate's zero-skip shim accidentally accepted zero-state-root production blocks), T-1's wrap check would still catch on-disk tampering of the chain file.   ∎

---

## 5. Adversary model

**(a) No-key adversary.** Cannot produce a block any honest peer will accept. (i) Tampering chain.json requires re-signing committee signatures over the new digest — reduces to A1 (Ed25519 EUF-CMA). (ii) Injecting via gossip requires the same key forgery (`BlockValidator::validate` V8). (iii) Even if an unauthenticated block somehow reached `apply_transactions`, T-2 fires unless the attacker's declared `state_root` exactly equals every honest peer's locally-recomputed root — finding such a value reduces to A2 per peer.

**(b) Single committee-key adversary.** Can sign and gossip a `BlockSigMsg` but cannot assemble a full block alone (K-of-K in MD mode, `⌈2k_bft/3⌉` in BFT mode require honest co-signers). Can equivocate, but FA6 (`EquivocationSlashing.md`) detects and slashes the stake. If the adversary somehow forms a block (collusion, degenerate K), **T-2 fires on every honest peer**: the declared `state_root` must match the canonical post-apply state, which by FA-Apply-1 is determined entirely by the (starting state, apply-affecting bytes) pair. Tampering any apply-affecting field changes the canonical root, so the declared and computed values diverge. **Net: the apply-time gate is the structural-equivalent of a per-block consensus equality check** — there is exactly one valid `state_root` per (starting state, body) pair, and the adversary can spend stake on equivocation evidence but cannot produce a divergent block that survives apply.

**(c) Network-level adversary** (MITM, gossip-link attacker). Drops cause liveness loss only (FA2). Malformed messages caught by wire-format + signature checks before `apply_transactions`. Replay of valid blocks is no-op'd by the duplicate-skip at `apply_block_locked` (node.cpp:1710); tx replay blocked by nonce monotonicity (FA-Apply-3).

**(d) Disk-level adversary** (write access to `chain.json`). Cannot bypass T-1: patching `head_hash` to a value consistent with the tampered chain requires forging committee signatures per case (c) of the T-1 proof (A1).

---

## 6. Identified gaps and known limitations

### 6.1 Pre-S-038 historical blocks bypass T-2

Pre-S-033 blocks (where the field didn't exist) and pre-S-038 blocks (where the producer didn't populate it) both have `state_root = 0` in JSON. The apply-time gate at chain.cpp:1432 short-circuits on `state_root == 0` per the zero-skip backward-compat shim (`WireFormatBackwardCompat.md` T-1). **T-2 does NOT cover these blocks** — their post-apply state isn't verified at apply.

This is **intentional**: forcing strict checking on legacy chains would break chains that exist today. A node loading a pre-S-038 chain falls back on `prev_hash` continuity + the head's `head_hash` anchor (T-1) for integrity. Once a post-S-038 block is appended, the gate is active from that point forward — every new block's `state_root` is checked, and `prev_hash` continuity transitively authenticates every prior block's contribution to the next block's compute_hash.

A flag-day migration that refuses to start on a head with `state_root == 0` would harden T-2 retroactively, but the coordination cost is not justified by the marginal security gain (the dormant blocks are still protected by `prev_hash` continuity + load-time head_hash anchor).

### 6.2 Out-of-namespace state divergence

T-2 covers exactly the ten namespaces enumerated by `build_state_leaves()` in §2.2. Any future state field NOT threaded into `build_state_leaves()` (AND into `Chain::serialize_state` / `restore_from_snapshot` simultaneously, per S-037's prior gap) would land outside the commitment. The lock-in regression `determ test-state-root-namespaces` (12 assertions) catches any field added without coverage.

### 6.3 Consensus-layer divergence prevention out of scope

This proof covers **detection at apply time**. It does NOT cover **prevention at signature-gathering time**. Two divergent block bodies can both be K-of-K-signed and both circulate on gossip; T-2 ensures only one applies on any honest peer (the one whose `state_root` matches the receiver's computed root — exactly one by FA-Apply-1). v2.7 F2 view reconciliation (`F2-SPEC.md`) is the long-term consensus-layer fix for S-030 D2 full closure.

### 6.4 Snapshot path covered by FA-Apply-2

The snapshot path (`Chain::serialize_state` / `restore_from_snapshot`) has a parallel S-033 gate that checks the tail-head's stored `state_root` against the freshly-restored `compute_state_root()` (the snapshot-side analogue of T-2). Coverage of that surface is in `SnapshotEquivalence.md` (FA-Apply-2), not this proof. The two compose to cover both pathways by which a block can become part of a node's chain.

### 6.5 Non-Byzantine bugs in compute_state_root

T-2 assumes `compute_state_root()` correctly hashes the actual `Chain` state. A bug that omits a state field from `build_state_leaves` would leave that field out of the commitment; T-2 would fail to detect divergence in it. The namespace-coverage regressions in §6.2 are the mitigation.

---

## 7. Test-suite citation

| Test | Theorem coverage |
|---|---|
| `tools/test_chain_integrity.sh` (4/4 PASS) | T-1 primary: S-021 wrap + load-time tampering rejection (tampered head detected; tampered mid-chain detected via prev_hash; legacy array-form accepted; round-trip preserves state). |
| `tools/test_chain_save_load.sh` | T-1 cross-check + `Chain::save`/`load` round-trip identity. |
| `tools/test_state_root.sh` (13 assertions) | T-2 supporting: `compute_state_root()` commitment algebra (determinism, purity, per-namespace sensitivity, order independence, invertibility). |
| `tools/test_state_root_namespaces.sh` (12 assertions) | T-2 supporting: exhaustive 10-namespace coverage (a:/s:/r:/d:/i:/b:/m:/p:/k:/c:). The lock-in regression for §6.2's out-of-namespace gap mitigation. |
| `tools/test_state_root_unit.sh` | T-2 supporting: domain-separation between namespaces, sorted-order determinism, Merkle tree branch-coverage. |
| `tools/test_snapshot_bootstrap.sh` | FA-Apply-2 + T-2 sibling: snapshot tail-head's `state_root` matches receiver's freshly-restored `compute_state_root()` end-to-end. |
| `tools/test_dapp_snapshot.sh` (12/12 PASS) | T-2 + T-3 + FA-Apply-2 composition. Strict assertion that the snapshot tail-head's stored `state_root` is non-empty in JSON AND matches the receiver's `compute_state_root()` after restore. **Pre-S-038, this assertion would have failed** — proving S-038 closed the producer-side gap end-to-end. |
| `tools/test_snapshot_roundtrip.sh` (15 assertions) | T-3 + FA-Apply-2: round-trip serialize → restore preserves `compute_state_root` byte-for-byte. |
| `tools/test_snapshot_then_apply.sh` (21 assertions) | T-3 + T-4 composition: post-restore replay matches control-chain state_root + balances + nonces at every height. The explicit cross-chain convergence (T-4) assertion across snapshot bootstrap. |
| `tools/test_chain_apply_block.sh` | T-2 positive coverage (matching state_root → apply succeeds). |
| `determ test-domain-separation` (20 assertions) | T-2 + T-3 supporting: S-033/S-038 exclusion-fence proofs — `state_root` mutation leaves `block_digest` unchanged AND changes `Block::compute_hash`. Confirms S-038's wiring doesn't break K-of-K signatures. |
| `determ test-block-hash` (16 assertions) | T-1 + T-3 supporting: `signing_bytes` + `compute_hash` full field coverage including zero-skip for `state_root` — proves the load-time `head_hash` anchor commits to `state_root` when non-zero. |

CI gates on these tests passing.

---

## 8. Status

**Shipped (analytic composition).** S-021, S-033, S-038, and the apply-time gate all live in the current `main` branch:

- **S-021** wrap + load-time check: `src/chain/chain.cpp::save` (lines 1944-1985) + `::load` (lines 1987-2054).
- **S-033** state_root field + Merkle commitment: `include/determ/chain/block.hpp:460-484` (field) + `src/chain/chain.cpp::compute_state_root` (line 413) + `::build_state_leaves` (lines 267+) + apply-time gate at lines 1421-1446.
- **S-038** producer wiring: `src/node/node.cpp::try_finalize_round` (lines 1093-1117), with the parallel dry-run pattern in `start_block_sig_phase` (lines 975-1002).
- **Apply-time gate** at `src/chain/chain.cpp:1432-1444` — the central T-2 mechanism.

Regression coverage as described in §7.

**The composition theorem is analytic.** This proof does not change any code; it consolidates the four mechanisms' coverage argument so an external auditor can confirm without re-reading the implementation that the four together exhaustively cover the state-integrity surface.

**Known limitations** as registered in §6:
- Pre-S-038 historical blocks bypass T-2 (intentional backward-compat).
- New state fields must be threaded into `build_state_leaves()` (locked in by `test_state_root_namespaces.sh`).
- Consensus-layer divergence prevention (S-030 D2 full closure) is v2.7 F2's job, not T-2's.

**Future composition.** This proof is the foundational state-integrity analytic; FA-Apply-2 (`SnapshotEquivalence.md`) extends it to the snapshot pathway. A future composition could extend T-2's coverage to RPC `submit_tx` paths (which today rely on `BlockValidator::validate` for soundness — a different but parallel surface).

---

## 9. References

### SECURITY.md sections

- `docs/SECURITY.md` §S-021 — chain.json wrap + load-time recompute closure.
- `docs/SECURITY.md` §S-033 — state_root Merkle commitment + apply-time gate (data-layer half).
- `docs/SECURITY.md` §S-038 — producer-side state_root population (makes S-033 functional end-to-end).
- `docs/SECURITY.md` §S-030 D1 + D2 — broader consensus-safety closure narrative that consumes T-2 + T-4.
- `docs/SECURITY.md` §S-012, §S-037 — snapshot-side sibling surface + the discovery vector for S-038.

### Implementation sites

- `src/chain/chain.cpp:54-58` — `Chain::append` with `prev_hash` continuity (T-1 mid-chain).
- `src/chain/chain.cpp:71-73` — `Chain::head_hash`.
- `src/chain/chain.cpp:267+` — `Chain::build_state_leaves` (ten-namespace leaf generator).
- `src/chain/chain.cpp:413-415` — `Chain::compute_state_root` (central S-033 primitive).
- `src/chain/chain.cpp:1421-1446` — the S-033 apply-time gate (T-2 mechanism).
- `src/chain/chain.cpp:1944-1985` — `Chain::save` (wraps chain.json).
- `src/chain/chain.cpp:1987-2054` — `Chain::load` (T-1's head_hash check at 2037-2051).
- `src/node/node.cpp:1024-1117` — `Node::try_finalize_round` (T-3's producer path; S-038 wiring at 1093-1117).
- `src/node/node.cpp:975-1002` — `Node::start_block_sig_phase` (parallel digest-dry-run).
- `src/node/node.cpp:1704-1810` — `Node::apply_block_locked` (receiver's apply path consuming T-2).
- `include/determ/chain/block.hpp:460-484` — `Block.state_root` declaration.
- `include/determ/chain/chain.hpp:236-270` — `Chain::compute_state_root` declaration + namespace key-encoding table.

### Companion proofs

- `docs/proofs/Preliminaries.md` (F0) — §2.1 SHA-256 collision resistance (A2), §2.2 Ed25519 EUF-CMA (A1).
- `docs/proofs/AccountStateInvariants.md` (FA-Apply-1) — apply determinism (T-3 + T-4 invocation).
- `docs/proofs/SnapshotEquivalence.md` (FA-Apply-2) — snapshot-pathway sibling.
- `docs/proofs/NonceMonotonicity.md` (FA-Apply-3) — tx-replay surface cited in §5.
- `docs/proofs/S030-D2-Analysis.md` §3.5 — D1/D2 closure context.
- `docs/proofs/F2-SPEC.md` — v2.7 F2 consensus-layer counterpart for S-030 D2 full closure.
- `docs/proofs/WireFormatBackwardCompat.md` — zero-skip backward-compat layer.
- `docs/proofs/MakeContribCommitmentBackwardCompat.md` + `docs/proofs/RpcAuthHmacSoundness.md` — citation-style templates.
- `docs/proofs/Safety.md` (FA1), `docs/proofs/EquivocationSlashing.md` (FA6), `docs/proofs/Censorship.md` (FA2) — cited in §5.

### Tests

- `tools/test_chain_integrity.sh` + `tools/test_chain_save_load.sh` — T-1 lock-in.
- `tools/test_state_root*.sh` (test_state_root.sh, test_state_root_namespaces.sh, test_state_root_unit.sh) — T-2 commitment algebra + 10-namespace coverage.
- `tools/test_snapshot_bootstrap.sh` + `tools/test_snapshot_roundtrip.sh` + `tools/test_snapshot_then_apply.sh` + `tools/test_dapp_snapshot.sh` — T-3 + T-4 + FA-Apply-2 composition.
- `determ test-domain-separation` + `determ test-block-hash` — T-2 + T-3 exclusion-fence + signing_bytes coverage.

### Specifications

- `docs/PROTOCOL.md` §4.1.1 — full state_root namespace table.
- `docs/PROTOCOL.md` §4.3 — `compute_block_digest` exclusion list.
- `docs/PROTOCOL.md` §10.2 — `state_proof` RPC.
- `docs/PROTOCOL.md` §11 — snapshot serialization format.
- NIST FIPS 180-4 — SHA-256 (referenced by A2).
- RFC 8032 — Ed25519 (referenced by A1).
