> **TIER: PROCESS / ARCHIVE.** Deliberation/meta; retained for rationale but NOT coherence-maintained as part of the 1.0 set. Roadmap index: docs/ROADMAP.md

# LightClientCompositionMap — capstone composition lattice for the light-client proof family

This is a **reading guide and integration map**, not a new proof. Over R39 + R40 the `determ-light.exe` light-client grew a family of independently-written soundness proofs. Each was authored against its own subcommand and threat sub-model; each cites `Preliminaries.md` for the base cryptographic assumptions and `LightClientThreatModel.md` for the per-invocation pipeline. What no single document supplies is the **global picture**: which theorem rests on which, which base assumption (A1 / A2 / A3 / A4) bottoms out each chain, and which `determ-light` subcommand each guarantee actually backs. This capstone assembles that picture as a composition lattice so a reviewer does not have to reconstruct it from six documents.

No new theorems are introduced. Every theorem label used here (`T-L*`, `MT-*`, `AR-*`, `AH-*`, `TI-*`, `SR-*`) is defined and proved in one of the family documents; this document only draws the edges between them and pins each edge to its base assumption.

**The three binaries.** Determ ships three executables (`LightClientThreatModel.md` §intro):

- **`determ.exe`** — the full daemon: produces blocks, gossips, serves RPC, holds the full chain + state. Trusted by its operator.
- **`determ-wallet.exe`** — offline key operations (keyfile create/decrypt, Shamir, OPAQUE). The libsodium-heavy binary; not network-facing.
- **`determ-light.exe`** — the **trust-minimized client**. A ~3–5 MB stripped binary that talks to ONE operator-controlled daemon for data but verifies every byte locally against a pinned genesis anchor + Ed25519 committee signatures + Merkle state-proofs. A malicious daemon cannot trick an honest light-client into acting on data inconsistent with the genesis-pinned chain. The light-client proof family is the formal account of *that* claim, per subcommand.

**The family documents this map indexes.**

| Doc | Theorems | Subject |
|---|---|---|
| [LightClientThreatModel.md](LightClientThreatModel.md) | T-L1..T-L5 | The online per-invocation pipeline (anchor → walk → sig-verify → state-proof → sign+submit) under a malicious daemon `A_daemon`. The family's **root**. |
| [MerkleTreeSoundness.md](MerkleTreeSoundness.md) | MT-1..MT-5 | The sorted-leaves balanced binary Merkle primitive (`src/crypto/merkle.cpp`) that state-proofs rest on. The family's **cryptographic substrate** for inclusion. |
| [StateRootAnchorSoundness.md](StateRootAnchorSoundness.md) | SR-1..SR-5 | Per-height committee-verified `state_root` anchoring (`verify-state-root`). **(F6 R40 — sibling.)** |
| [TxInclusionProofSoundness.md](TxInclusionProofSoundness.md) | TI-1..TI-4 | Per-transaction inclusion within one block's body via the committee-signed `tx_root` (`verify-tx-inclusion`). |
| [AccountHistorySoundness.md](AccountHistorySoundness.md) | AH-1..AH-4 | A verified `(height, balance, nonce)` trajectory across a height range (`account-history`). |
| [LightClientArchiveSoundness.md](LightClientArchiveSoundness.md) | AR-1..AR-4 | Offline-reverifiable header-archive soundness (`export-headers` → `verify-archive`). |

> **Note on `StateRootAnchorSoundness.md` (F6 R40).** This sibling document lands in parallel with this capstone. Its SR-* theorems are cited here at the **spec level** per its task description: SR-1 (committee-anchored per-height `state_root`), SR-2 (genesis-binding of the root chain), and the SR-3..SR-5 supporting results (root-equality, fail-closed, head-vs-historical anchoring). Where a precise SR label is load-bearing below it is tagged **(F6 R40)** so a reviewer knows to confirm the exact statement against F6's document once threaded. The lattice edges into SR-1 (from T-L2 + the digest binding) hold structurally regardless of F6's internal numbering, because SR-1 *is* the committee-signed-`state_root` fact that T-L4 / AH-1 already consume under the T-L2 + S-033 composition.

**Status of the family.** All six documents are shipped (R39 + R40). Every referenced theorem is proved in its home document. This capstone adds zero theorems; it is a coherence artifact.

---

## 1. Purpose and scope

### 1.1 What this document is

A **composition map** for the light-client proof family — a single place that answers, for a reviewer or an operator:

1. *What does each `determ-light` subcommand actually guarantee, and which theorem backs it?* (§5)
2. *Which theorem rests on which?* (the lattice, §4)
3. *Which base cryptographic assumption bottoms out each chain?* (the spine, §2 + §4)
4. *Which honest limitations recur across the whole family?* (§6)

### 1.2 What this document is NOT

It is **not** a proof. It introduces no theorem, proves no new bound, and modifies none of the six family documents. Where this map states a reduction (e.g. "T-L3 reduces to A2"), the reduction is *proved* in the cited home document; this map only records the edge. A reviewer who wants the proof of any node follows the `→` to its home document.

It is also **not** a substitute for `Preliminaries.md` (the assumption legend) or `LightClientThreatModel.md` (the threat model). It assumes both and threads them.

### 1.3 The shared trust model (one paragraph, since all six share it)

Every document in the family proves soundness under the **same** adversary `A_daemon` (`LightClientThreatModel.md` §2.1): the single RPC endpoint the light-client talks to is fully adversarial — it may return arbitrary JSON, drop/stall requests, mutate responses within an invocation, and coordinate lies across invocations. Every document is **fail-closed**: any detected inconsistency throws and propagates to a non-zero exit, never a silent downgrade (`LightClientThreatModel.md` L-6, inherited as AR-L1 / AH-L5 / TL-3). Every document declares the **same** out-of-scope adversaries: `A_crypto` (breaks a primitive), `A_local` (compromises the operator's machine or binary), `A_net` (transport MITM — observationally equivalent to `A_daemon` for soundness), `A_genesis` (tampers the pinned genesis). The family's soundness is therefore *structural* — a composition of base-primitive guarantees — not a new cryptographic construction.

---

## 2. The base layer (where every chain bottoms out)

Every light-client guarantee reduces, ultimately, to a small set of base cryptographic assumptions (`Preliminaries.md` §2.0) plus a set of chain-level preconditions the light-client **inherits** (it does not re-prove them; it depends on them holding for the chain whose data it verifies).

### 2.1 Base cryptographic assumptions (`Preliminaries.md` §2.0)

**A1 — Ed25519 EUF-CMA (`Preliminaries.md` §2.2).** No PPT adversary can forge a valid signature on an unqueried message without the secret key, except with probability `≤ ~2⁻¹²⁸`. In the family, A1 is the assumption behind **committee signatures**: every "the committee signed this header / digest / `state_root` / `tx_root`" claim reduces to A1. It is the load-bearing wall of T-L2, and transitively of T-L3 / T-L4 / T-L5 / SR-1 / TI-1..TI-3 / AR-1(c) / AH-1.

**A2 — SHA-256 collision resistance (`Preliminaries.md` §2.1).** No PPT adversary can find `x ≠ y` with `H(x) = H(y)` better than the `≤ 2⁻¹²⁸` birthday bound. In the family, A2 is the assumption behind every **hash-as-commitment**: Merkle leaf/inner hashes (MT-1..MT-4), block digests, the genesis hash (T-L1), `tx_root` (TI-1..TI-3), and the `a:`-namespace value-hash cross-check (L-4 / AH-L4). It is the most heavily used base assumption in the family.

**A3 — SHA-256 preimage / second-preimage resistance (`Preliminaries.md` §2.1).** No PPT adversary can invert `H` or find a second preimage better than `≤ 2⁻²⁵⁶` (`2⁻¹²⁸` under Grover). In the family, A3 appears in two places: T-L1 Case 2 (a daemon synthesizing a block-0 hash equal to a fixed `expected` would need a preimage) and the transaction **content-binding** note (TI-1 / Scenario Z — a tampered tx body hashing to a genuine committed `H` would be a second preimage of `H` under `Transaction::signing_bytes`).

**A4 — CSPRNG uniform secret sampling (`Preliminaries.md` §2.3).** Phase-1 secrets are drawn from a CSPRNG indistinguishable from uniform. **A4 is largely not light-client-relevant.** The light-client never samples Phase-1 secrets; it only *verifies* signatures and Merkle paths over already-produced blocks. A4 underwrites the chain-side randomness (FA3 selective-abort), which the light-client inherits *transitively* via the committee-signed digest (`LightClientThreatModel.md` §5.3) but never exercises directly. No light-client theorem reduces to A4. It is listed here for completeness of the base layer, and so a reviewer is not surprised by its absence from every per-command reduction.

### 2.2 Chain-level preconditions the light-client INHERITS

The light-client does not re-establish the chain's own consensus and state-integrity invariants. It *depends* on them holding for the chain whose data the daemon serves. These are the lower boundary of the lattice on the "chain" side (as opposed to the "primitive" side, which is A1/A2/A3).

**FA1 (Safety) — the committee model.** `Safety.md` (FA1) establishes the K-of-K mutual-distrust per-height safety property (≤ 1 finalized digest per height) under committee Ed25519 signatures. The light-client uses the **per-block** signature-set primitive FA1 leverages — for each header it ingests, it confirms K (or `⌈2K/3⌉` in BFT) signatures over the computed digest (T-L2 = "FA1 per-block primitive at the light-client side"). `Safety.md` §7 (R39+2 B6) records the light-client composition explicitly (Theorem T-1.2: `determ-light` never acts on data inconsistent with the pinned genesis under `A_daemon`). The light-client adds **no new chain-level invariant**; it composes the existing FA1 result.

**S-033 + S-038 — the `state_root` binding.** `S033StateRootNamespaceCoverage.md` (S-033) proves `Block.state_root` is a Merkle root committing the full 10-namespace state surface; `BlockchainStateIntegrity.md` / SECURITY.md §S-038 prove the producer actually **populates** `body.state_root` on every block produced post-S-038 (pre-S-038 the apply-time gate was dormant). The light-client's state-proof anchor (T-L3 / T-L4 / SR-1 / AH-1) is exactly this `state_root` field. Consequence: balance/nonce reads require S-033 + S-038 **active** on the chain, and `read_account_trustless` throws `chain has not activated state_root (S-033)` on a pre-S-033 chain (`LightClientThreatModel.md` §5.5). This is a chain-level deployment prerequisite, not a light-client design choice. (Tx-inclusion is the exception — TI uses `tx_root`, not `state_root`, so it has no S-033 prerequisite; see §4 + §5.)

**S-021 — chain integrity.** `BlockchainStateIntegrity.md` (S-021) wraps `chain.json` in a `{head_hash, blocks}` envelope with head-hash recomputation at load. The daemon serving light-client data has passed S-021 load validation; the light-client benefits transitively (a daemon that loaded a tampered chain would have failed its own S-021 gate). The light-client does not itself perform S-021 validation — it never sees `chain.json` — but the chain identity it anchors to (T-L1) is the same one S-021 protects at rest on the daemon.

**Summary of the base layer.** Every light-client guarantee rests on **{A1, A2}** at the cryptographic floor (A3 in two specific corners, A4 not at all), and inherits **{FA1, S-033 + S-038, S-021}** as chain-level preconditions it does not re-prove. The lattice in §4 makes the cryptographic reductions precise; the chain-level inheritances are the standing assumptions under which every edge holds.

---

## 3. The primitive theorems (per-doc digest)

This section is the lattice's **node list**: each family theorem, a one-line statement, and the base assumption(s) it reduces to (proved in its home document). The reductions are summarized here and drawn as edges in §4.

### 3.1 LightClientThreatModel.md — T-L1..T-L5 (the root)

| Theorem | One-line | Reduces to |
|---|---|---|
| **T-L1** | Genesis-anchored chain identity: a daemon serving a chain whose genesis ≠ the pinned `genesis.json` cannot pass `anchor_genesis`. Bound `≤ 2⁻¹²⁸`. | A2 (+ A3, Case 2) |
| **T-L2** | Head trust via committee sigs: a daemon cannot present a forged header that `verify_block_sigs` accepts as committee-signed. Bound `≤ K·2⁻¹²⁸`. | A1 (+ FA1 per-block primitive) |
| **T-L3** | State-proof correctness: against a committee-signed `state_root`, a daemon cannot present a forged Merkle path for a non-committed value. Bound `≤ log₂(leaf_count)·2⁻¹²⁸`. | A2 (= MT-4) |
| **T-L4** | Balance/nonce trust via composition: `read_account_trustless` binds `(balance, next_nonce)` end-to-end to a committee-signed `state_root` anchored to the pinned genesis (incl. the race-window mitigation). Bound `≤ 2⁻⁹²`. | T-L1 + T-L2 + T-L3 + L-4 |
| **T-L5** | Sign-and-submit correctness: a tx signed by the light-client and submitted via `verify-and-submit` cannot be mutated by the daemon without breaking the signature; nonce comes from a T-L4-verified read. | T-L4 + A1 |

Supporting lemmas: **L-1** (genesis-encoding determinism), **L-2** (`light_compute_block_digest` ≡ producer digest, byte-for-byte), **L-3** (Merkle inclusion soundness — the seed of MT-4), **L-4** (cleartext-vs-`value_hash` cross-check binds the daemon's `account` reply), **L-5** (race-window mitigation soundness), **L-6** (fail-closed exit).

### 3.2 MerkleTreeSoundness.md — MT-1..MT-5 (the inclusion substrate)

| Theorem | One-line | Reduces to |
|---|---|---|
| **MT-1** | Determinism / permutation-invariance: `MR` is a pure function of the leaf *set* (internal key-sort). | (structural; pure SHA-256) |
| **MT-2** | Domain separation: `0x00` leaf prefix vs `0x01` inner prefix make leaf/inner preimage languages disjoint (RFC 6962-style). | A2 (for the collision corner) |
| **MT-3** | Collision-resistance inheritance: distinct leaf sets colliding on a root yield a SHA-256 collision via an O(log n) top-down extractor. | A2 |
| **MT-4** | Inclusion-proof soundness: a passing `merkle_verify` against a committee-signed root proves membership except `≤ 2⁻¹²⁸`. **The load-bearing light-client theorem.** | A2 (rests on MT-1/MT-2/MT-3) |
| **MT-5** | Non-membership capability boundary: positive membership only; NOT an SMT; no native absence proofs (honest non-overclaim). | (capability statement) |

MT-4 is the cryptographic core that T-L3 *is*, and that SR-1 / AH-1 Gate-3 invoke per height. **S-040 CLOSED** — `leaf_count` is bound into the committed root via the root-wrapper hash `root = SHA256(0x02 ‖ u32_be(leaf_count) ‖ inner_root)` (`src/crypto/merkle.cpp::merkle_root_wrap`), so a forged count yields a different wrapper hash and is rejected; the former single-envelope-sourcing obligation is now enforced by the hash, not just a caller guideline. The light client inherits this via its direct `crypto::merkle_verify` call (`light/verify.cpp`).

### 3.3 StateRootAnchorSoundness.md — SR-1..SR-5 (F6 R40)

| Theorem | One-line | Reduces to |
|---|---|---|
| **SR-1** | Committee-anchored per-height `state_root`: a daemon cannot present a `state_root` at height `h` that the committee did not sign. `state_root` is **NOT** in `compute_block_digest` (what the committee directly signs); it is committee-certified **transitively forward** — `state_root(h) ∈ signing_bytes(h) ∈ block_hash(h) = prev_hash(h+1) ∈ digest(h+1)` — so the *successor* block `h+1`'s signature pins it. | T-L2 (on block `h+1`) + the forward digest link (A1 + A2) |
| **SR-2** | Genesis-binding: the per-height root chain is anchored to the pinned genesis (the root at `h` belongs to the operator's chain, not a fork). | T-L1 + continuity (A2/A3) |
| **SR-3..SR-5** | Supporting: height-binding / fail-closed on mismatch / pre-S-033 vacuity honesty (the per-height analog of L-5 + L-6). | A2 + (fail-closed) |

> The lattice edge **SR-1 ← T-L2 + (A1+A2)** is the structural fact the other light-client reads (T-L4, AH-1) already depend on: a committee-signed *successor* header pins a *specific* `state_root` at its predecessor's height via the transitive-forward `block_hash(h)=prev_hash(h+1)∈digest(h+1)` link (the head's root has no successor yet — full nodes enforce it via the apply-layer S-033 gate; `StateRootAnchorSoundness.md` §3.4 + §6.3).

### 3.4 TxInclusionProofSoundness.md — TI-1..TI-4 (tx membership)

| Theorem | One-line | Reduces to |
|---|---|---|
| **TI-1** | Sound positive inclusion: `INCLUDED` ⇒ tx `H` genuinely in committee-signed block `B`. Bound `≤ (K+1)·2⁻¹²⁸`. | A1 + A2 (committee `tx_root` + recompute) |
| **TI-2** | Sound non-inclusion: `NOT-INCLUDED` ⇒ `H` genuinely absent from block `B`; an omitting daemon changes the recomputed root and is caught (→ `UNVERIFIABLE`, never a false negative). Bound `≤ (K+1)·2⁻¹²⁸`. | A1 + A2 |
| **TI-3** | Tampered-body detection: the recompute-`tx_root`-from-body-and-match gate fires before the membership scan; any body whose recomputed root ≠ committee-signed root → `UNVERIFIABLE`. **The gate that makes TI-1/TI-2 sound.** | A2 |
| **TI-4** | Degradation honesty: the counterfactual regime where `tx_root` is NOT in the digest would degrade to daemon-trust; documented as a regression tripwire — explicitly NOT Determ's case (Determ is **STRONG**). | (honesty boundary) |

Key structural facts: `tx_root` IS in the committee-signed digest (`producer.cpp:581`, mirrored `light/verify.cpp:51`), so TI is in the **strong regime**; `tx_root` is a **flat SHA-256 over the sorted union of tx hashes**, NOT a Merkle tree — so MT-4 does not apply verbatim (§4.5 of TI), and TI uses a direct `tx_root`-recompute collision argument. TI needs **no** S-033 prerequisite (`tx_root` ⊥ `state_root`, independent block fields).

### 3.5 AccountHistorySoundness.md — AH-1..AH-4 (the trajectory)

| Theorem | One-line | Reduces to |
|---|---|---|
| **AH-1** | Per-point soundness: if a `(h, balance, nonce)` row is emitted, its value is `D`'s genuine on-chain state at `h`. Bound `≤ K·2⁻¹²⁸ + log₂(leaf_count)·2⁻¹²⁸ + 2⁻¹²⁸` per height. **= T-L4 at a fixed historical height.** | T-L2 + T-L3/MT-4 + T-L1 (+ L-4) |
| **AH-2** | Trajectory consistency: each row binds the `state_root` from ITS OWN committee-verified `header[h]`; no shared root across rows, so `h_i`'s proof cannot validate against `h_j`'s root (cross-height confusion = A2 collision). | A1 + A2 |
| **AH-3** | Nonce monotonicity is **necessary-not-sufficient**: a forged-but-coherent history could preserve monotonicity, so it is a *cross-check*, not a soundness source. The real guarantee is AH-1's per-point anchoring. | (honesty theorem; rests on AH-1 + FA-Apply-3) |
| **AH-4** | Sampling-gap honesty: the trajectory proves values AT the sampled heights only; balance can move up-and-back within a `--step` gap unobserved. A verified *sample*, not a continuous audit. | (scope statement) |

AH-1 is structurally T-L4 specialized to a fixed `h`; AH-2 is its multi-point extension (independent per-row anchoring under one genesis anchor). AH-3 / AH-4 are honesty theorems (the temporal-sampling analog of AR-3's range honesty).

### 3.6 LightClientArchiveSoundness.md — AR-1..AR-4 (the offline archive)

| Theorem | One-line | Reduces to |
|---|---|---|
| **AR-1** | Archive integrity = header-sequence attestation: a passing `verify-archive` attests prev_hash continuity (a) + genesis equality for `from==0` (b) + per-header committee-signed validity (c). Bound `≤ count·K·2⁻¹²⁸ + 2⁻¹²⁸`. **= T-L1 + T-L2 applied to archive bytes.** | A1 + A2/A3 |
| **AR-2** | Offline temporal soundness: `verify-archive` is a *pure function* of (archive bytes, genesis bytes) — no clock, no network — so the verdict is time-invariant. **New (no online analog).** | (purity → time-invariance) |
| **AR-3** | Range-completeness caveat (`A_stale`): `exported_at_height` is an unverified exporter claim; truncated-but-consistent sub-ranges still verify; `from>0` slices "float". Completeness is an auditor-side obligation. **The dominant residual.** | (scope limitation; not a crypto break) |
| **AR-4** | Committee-continuity: export + verify use the **static** genesis-seeded `K_0`; export fails closed on a non-`K_0` creator. Sound for committee-stable ranges out of the box; cross-rotation needs an operator-supplied extended committee. | (= T-L2 committee caveat) |

AR-1 is structurally T-L1 + T-L2 applied to frozen archive bytes; AR-2 is genuinely new (it has no online analog because online there is always a live daemon to re-query). AR-3 is the temporal sharpening of `LightClientThreatModel.md` F-4 (no defense against truncated chain claims).

---

## 4. The composition lattice (the core)

This is the dependency graph: the **rests-on** edges between the family theorems, terminating at the base assumptions {A1, A2, A3} and the inherited chain preconditions {FA1, S-033+S-038, S-021}. Read `X ← Y` as "X rests on Y" (X is proved using Y). Edges are cited to the home-document theorem that establishes them.

### 4.1 The lattice graph (ASCII)

```
                    determ-light SUBCOMMANDS  (§5 maps each to the theorem(s) below)
                                        │
   ┌──────────────────┬─────────────────┼──────────────────┬───────────────────┐
   ▼                  ▼                 ▼                  ▼                   ▼
 T-L5 ───────────►  T-L4 ──────────►  AH-1/AH-2 ───►  TI-1/TI-2 ────►   AR-1 / AR-2 / AR-3 / AR-4
(sign+submit)     (balance/nonce)   (trajectory)    (tx-inclusion)        (offline archive)
   │                  │                 │                  │                   │
   │  (nonce from)    │                 │ (= T-L4 @ fixed  │ (parallel to      │ (= T-L1+T-L2 on
   │                  │                 │   historical h)  │  state_root via   │   archive bytes;
   ▼                  ▼                 ▼                  │  tx_root sibling) │   AR-2 has NO
   └──────────────►  composed of:  ────┘                  │                   │   online analog)
                    ┌────────────────────────────┐        │                   │
                    │                             │        │                   │
                    ▼                             ▼        ▼                   ▼
                  SR-1 ◄───────────────────────  T-L3  = MT-4               TI-3
          (committee-anchored                  (state-proof              (tx_root recompute
           state_root, F6 R40)                  correctness)              gate; flat-SHA, A2)
                    │                             │
        ┌───────────┘                             ▼
        ▼                                        MT-4 ◄── MT-1, MT-2, MT-3   (Merkle primitive)
      T-L2  ◄──────────────────────────────────────┐       │   │    │
   (committee-sig head trust)                       │       │   │    │
        │   ▲                                        │       ▼   ▼    ▼
        │   │ (FA1 per-block primitive)              │      A2  A2   A2
        │   └──── FA1 (Safety.md §7)                 │
        ▼                                            ▼
       A1                                           T-L1  ◄── L-1 (genesis determinism)
   (Ed25519 EUF-CMA)                          (genesis anchor)
        ▲                                            │
        │                                            ▼
        │                                          A2  (+ A3 for Case-2 preimage)
        │
   ════╪═════════════════════ THE SHARED SPINE ═════════════════════════════
       └──────────────────────────────►  { A1 , A2 }  ◄────────────────────────
          everything funnels here    (A3 in two corners: T-L1 Case 2, TI content-binding;
                                       A4 NOT used by any light-client theorem)

   INHERITED CHAIN PRECONDITIONS (standing assumptions under which every edge holds):
      FA1 (committee model)  ·  S-033 + S-038 (state_root binding)  ·  S-021 (chain integrity)
```

### 4.2 The edges, stated precisely

Each edge below is a "rests-on" relation proved in the cited home document. The numbered list is the authoritative edge set; the ASCII graph above is its picture.

- **T-L1 (genesis anchor) ← `compute_genesis_hash` + A2** (and A3 in Case 2). The local recomputation `compute_genesis_hash(genesis_O)` is deterministic (L-1); equality against the daemon's block-0 hash reduces a wrong-chain pass to a SHA-256 collision (A2), or a synthesized-hash pass to a preimage (A3). *(`LightClientThreatModel.md` T-L1.)*

- **T-L2 (committee-sig head trust) ← A1 + committee composition.** `verify_block_sigs` requires `≥ required` Ed25519 verifications over `light_compute_block_digest` under the genesis-seeded committee map; forging without the members' keys is `≤ K·2⁻¹²⁸` (A1). T-L2 is the FA1 per-block primitive at the light-client side. *(`LightClientThreatModel.md` T-L2; `Safety.md` §7.)*

- **T-L3 (state-proof correctness) ← MT-4 ← MT-1 / MT-2 / MT-3 ← A2.** `verify_state_proof` delegates to `merkle_verify`; MT-4 (inclusion-proof soundness) is the exact theorem licensing "a passing verification implies membership under A2." MT-4 rests on MT-1 (determinism), MT-2 (domain separation), MT-3 (collision-resistance inheritance), all reducing to A2. T-L3's L-3 lemma *is* the seed of MT-4. *(`LightClientThreatModel.md` T-L3 + L-3; `MerkleTreeSoundness.md` MT-4.)*

- **SR-1 (committee-anchored `state_root`, F6 R40) ← T-L2 (on block `h+1`) + the forward digest link (A1 + A2).** A committee-signed *successor* `header[h+1]` pins a *specific* `state_root` value at height `h`: `state_root` is **NOT** in `compute_block_digest` directly, but `state_root(h) ∈ signing_bytes(h) ∈ block_hash(h) = prev_hash(h+1) ∈ digest(h+1)`, and the committee signs `digest(h+1)`. (Head boundary: the head's root has no signed successor; full nodes enforce it via the apply-layer S-033 gate.) This is the structural fact `S033StateRootNamespaceCoverage.md` + `LightClientThreatModel.md` §5.2 / T-L3 mechanism note record and that T-L4 / AH-1 already consume. *(F6 SR-1; structurally = T-L2 on `h+1` + S-033 binding via the prev_hash chain.)*

- **T-L4 (balance/nonce) ← SR-1 + T-L3 (+ T-L1 + L-4).** The composite read anchors a state-proof against a committee-signed `state_root` (SR-1, via the race-window mitigation L-5), verifies the Merkle path against it (T-L3 = MT-4), and binds the cleartext `(balance, nonce)` via the value-hash cross-check (L-4). All three sub-bounds are independent; the composition is sound by union bound. *(`LightClientThreatModel.md` T-L4 §4.4 + §4.4.1.)*

- **AH-1 (per-height account point) ← T-L4 applied per height + SR-1.** AH-1 is structurally T-L4 specialized to a fixed historical `h`: T-L2 (committee-signed `header[h]`, SR-1's anchor) + T-L3/MT-4 (state-proof against `header[h].state_root`) + T-L1 (genesis anchor, once). Gate-independence (AH-L0) makes the three forge events disjoint hardness instances. *(`AccountHistorySoundness.md` AH-1; = T-L4 at fixed `h`.)*

- **AH-2 (trajectory) ← AH-1 + genesis-linkage (the `IncrementalChainWalker` single pass).** Each row binds the root from its *own* committee-verified `header[h]`; the only inter-row coupling is the one-time genesis anchor + the per-height prev_hash linkage to the genesis-rooted chain (a single monotonic pass via `IncrementalChainWalker::advance_to`). No shared root couples row values; cross-height confusion = A2 collision. *(`AccountHistorySoundness.md` AH-2 + AH-L2/AH-L3.)*

- **TI-1 (tx-inclusion) ← T-L2 + tx_root-in-digest (A1 + A2), parallel to SR-1 (state_root sibling).** `verify-tx-inclusion` reuses T-L1 + T-L2 to obtain a committee-signed `tx_root` (the digest binds `tx_root` at `producer.cpp:581`), then recomputes `tx_root` from the served body and gates on the match (TI-3, A2). `tx_root` is the **sibling commitment** to `state_root`: both are fields the committee signs, but `tx_root` is a flat SHA-256 over the tx-hash set (not a Merkle tree), so MT-4 does NOT apply verbatim — TI uses a direct recompute collision argument. *(`TxInclusionProofSoundness.md` TI-1/TI-3 §3-§4; `tx_root` ⊥ `state_root` per §3.2.)*

- **AR-1 (archive) ← T-L1 + T-L2 offline.** AR-1 is T-L1 (genesis equality, AR-1 clause b) + T-L2 (per-header committee-sig, AR-1 clause c) + continuity (AR-1 clause a) applied to **frozen archive bytes** instead of live RPC. **AR-2 (temporal) ← purity:** `verify-archive` is a pure function of (archive bytes, genesis bytes), so the verdict is time-invariant — genuinely new, no online analog. **AR-3 (range-completeness caveat):** acceptance proves validity of *contained* headers, not completeness (`exported_at_height` is an unverified claim; `from>0` slices float) — a scope limitation, not a crypto break. **AR-4 = T-L2's committee caveat** (static `K_0`, fail-closed on rotation). *(`LightClientArchiveSoundness.md` AR-1..AR-4 + §5.1.)*

- **T-L5 (sign+submit) ← T-L4 + A1.** The signed tx's nonce comes from a T-L4-verified read; the daemon cannot mutate the envelope without breaking the Ed25519 signature (A1). *(`LightClientThreatModel.md` T-L5.)*

### 4.3 The shared spine

The lattice's defining feature: **every chain funnels to {A1, A2} at the bottom.**

- The **committee-signature** spine (T-L2 ← A1) carries: T-L2 → SR-1 → T-L4 → AH-1, T-L4 → T-L5, T-L2 → TI-1, T-L2 → AR-1.
- The **hash-commitment** spine (T-L1, MT-4, `tx_root`, value-hash ← A2) carries: T-L1 → T-L4/AR-1/AH-1; MT-1/2/3 → MT-4 → T-L3 → T-L4 → AH-1; `tx_root` recompute → TI-1/2/3; L-4 cross-check → T-L4/AH-1.
- **A3** appears at exactly two leaves: T-L1 Case 2 (synthesized block-0 hash = preimage) and the TI content-binding note (tampered tx body = second preimage of a committed `H`).
- **A4** appears at **zero** light-client leaves (it underwrites chain-side randomness, inherited transitively via the digest, never exercised by the client — §2.1).

Above the spine sit the **inherited chain preconditions** {FA1, S-033 + S-038, S-021}: standing assumptions, not edges into A1/A2 from the light-client's own reductions, but the conditions under which the committee model, the `state_root` binding, and the chain identity the client anchors to are meaningful. A reviewer auditing soundness checks the {A1, A2} spine for the light-client's own logic and confirms {FA1, S-033+S-038, S-021} hold for the chain whose data is verified.

---

## 5. Command → guarantee map (operator-facing)

This is the operator-facing reference: each `determ-light` subcommand, the theorem(s) backing its soundness, and the **residual trust / limitation** an operator must understand. Subcommands are dispatched from `light/main.cpp` (lines 933–948); the pure-verifier commands take operator-controlled file input and are not adversary-exposed.

| Subcommand | Class | Backing theorem(s) | Residual trust / limitation |
|---|---|---|---|
| `verify-headers` | pure verifier (offline file in) | T-L1 (genesis branch, index 0) + prev_hash continuity (`LightClientThreatModel.md` §3.3) | Continuity only proves *internal* linkage of the supplied page; authenticity weight is on `verify-block-sigs`. Genesis anchor fires only when the page starts at block 0. |
| `verify-block-sigs` | pure verifier (offline file in) | **T-L2** (A1; FA1 per-block primitive) | Committee map seeded from genesis `initial_creators` only — a creator outside `K_0` fails closed (the static-`K_0` caveat, §6.2). MD vs BFT threshold per `bft_mode`. |
| `verify-state-proof` | pure verifier (offline file in) | **T-L3 = MT-4** (A2) | Self-anchoring against the supplied root unless `--state-root` pins an independently-trusted root. **S-040 CLOSED** — `leaf_count` is bound into the committed root (root-wrapper); a forged count is rejected by `merkle_verify`, so no caller-side sourcing obligation remains. |
| `verify-chain` | composite | T-L1 + T-L2 + continuity, end-to-end from block 0 to tip (`--resume`: T-L2 over the suffix + **LSP-1/LSP-2/LSP-6** for the skipped prefix) | Single-daemon: a truncated-tip lie (daemon under-reports head) is an *availability* lie, not caught (`LightClientThreatModel.md` F-4). `--persist` caches the verified anchor (**LSP-1**); `--resume` skips the prefix re-walk by verifying only the suffix above the cached anchor (**LSP-6**, `LightStatePersistenceSoundness.md`) — falls back to a full verify when the anchor is unusable, fork-below-anchor is a hard error. |
| `state` | offline cache manager (no daemon) | **LSP-1..LSP-5** (`LightStatePersistenceSoundness.md`) | Manages the `verify-chain --persist` anchor: `--show` (load+validate+print), `--clear` (delete), `--selftest` (in-binary round-trip + reject-path checks), `--verify-anchor --genesis <file>` (the **LSP-2 offline genesis re-pin gate** — local `compute_genesis_hash` recompute → PASS / MISMATCH exit 2; the security-critical half of the LSP-6 resume, landed + tested offline ahead of it). Trusted-local file (LSP-5; a local-tamper is out of scope, §6.6); genesis-pinned (LSP-2) + schema-versioned (LSP-3) + fail-closed on corrupt (LSP-4). |
| `balance-trustless` | composite | **T-L4** (= T-L1 + T-L2 + T-L3 + L-4 + race-window L-5) | Requires **S-033 + S-038** active (else throws `chain has not activated state_root`); head-only state-proof RPC — balance Merkle-verified at the verified head. `--resume` reuses a cached committee-verified anchor via the shared `anchored_head` helper (LSP-6; the same resume path as `verify-chain`, so the head-anchoring inherits the resume soundness — `LightStatePersistenceSoundness.md` LSP-6 / `VerifyChainWalkSoundness.md`). |
| `nonce-trustless` | composite | **T-L4** (same as balance-trustless, extracts `next_nonce`) | Same as balance-trustless (incl. `--resume` via `anchored_head`). The nonce feeds `verify-and-submit`. |
| `account-history` | composite (trajectory) | **AH-1** (per row = T-L4 @ fixed h) + **AH-2** (independent anchoring) + **SR-1** (per-height committee `state_root`, F6 R40) | **Sampling gaps (AH-4)** — values at sampled heights only; balance can move within a `--step` gap unseen. **Head-only Merkle** — `state_root` committee-verified per height, but balance/nonce Merkle-verified at HEAD only (rows annotated `balance_merkle_verified`); per-height Merkle auto-upgrades if the RPC gains a height param. Static `K_0` (§6.2). Nonce monotonicity is a *cross-check* not a guarantee (AH-3). |
| `export-headers` | network fetch + online verify, writes archive | T-L1 + T-L2 + continuity (the online half of **AR-1**); fail-closed before write (**AR-L1**) | Default archive **strips** `creator_block_sigs` — offline re-verification of sigs needs `--include-committee-sigs` (AR-1 stripped-archive caveat, §6.4 of AR). `exported_at_height` is an unverified claim (AR-3). |
| `verify-archive` | offline verifier (no daemon) | **AR-1** (offline) + **AR-2** (temporal — pure function of bytes) | **Range-completeness (AR-3)** — proves validity of contained headers, not completeness; `from>0` slices float; stripped archives prove continuity+genesis only, not committee sigs (§6.4 of AR). Static `K_0` fed identically to export + verify (AR-4). |
| `verify-tx-inclusion` | composite (membership) | **TI-1** (INCLUDED) / **TI-2** (NOT-INCLUDED) / **TI-3** (tampered-body gate) — A1 + A2 | **No S-033 prerequisite** (uses `tx_root` ⊥ `state_root`); full-body recompute O(block size), not a compact proof; membership at a *named* height `B`, not chain-wide; omission → `UNVERIFIABLE` (never a false `NOT-INCLUDED`). Static `K_0` (§6.4 of TI). |
| `verify-state-root` | per-height verifier **(F6 R40)** | **SR-1** (committee-anchored per-height `state_root`) + **SR-2** (genesis-binding) | Per-height committee-verified root (transitive-forward via the successor's signed digest). Height-binding + fail-closed + pre-S-033 vacuity are SR-3..SR-5. Static `K_0`; requires S-033 + S-038 for a non-zero root (else vacuous — pre-S-033). |
| `watch-head` | periodic monitor (in-memory session) | T-L1 (once at startup) + **T-L2** per tick (`light/watch.hpp`) | Per-tick committee-sig verify against the genesis-seeded committee; on `sigs_valid=no` prints WARN + continues (visibility, not silence). No persistence across restarts; single-daemon (no cross-check). Static `K_0`. |
| `sign-tx` | offline sign (no network) | (part of **T-L5**) — `compute_signing_bytes` byte-identical to chain `Transaction::signing_bytes` | Not adversary-exposed (operator keyfile + envelope in); **no keyfile encryption** (plaintext keyfile shape — libsodium-free footprint; encryption lives in `determ-wallet`). |
| `submit-tx` | network submit (operator pre-signed) | (part of **T-L5**) — daemon cannot mutate without breaking the signature (A1) | Submits an operator-pre-signed envelope; the daemon may *drop* it (availability), but cannot mutate it (soundness). No on-submit verification of the nonce's freshness unless paired with a trustless read. |
| `verify-and-submit` | composite (read → sign → submit) | **T-L5** (= **T-L4** verified nonce + sign + submit under A1) | Composes `nonce-trustless` (T-L4) + `sign-tx` + `submit-tx`; requires S-033 + S-038 (via the nonce read). `--resume` reuses a cached anchor for the embedded nonce read (via `anchored_head`, same as the standalone reads). End-to-end bound `≈ 2⁻⁹²`. Static `K_0`. |

**Reading the residual column.** Four limitations recur across nearly every row — single-daemon per command (no multi-peer cross-check — **now addressable** via the `cross-check` subcommand, which independently committee-verifies ≥2 daemons and flags a committee-signed fork at a shared height as DIVERGENCE; soundness in `MultiPeerCrossCheckSoundness.md` MPC-1..MPC-5; both localhost `--rpc-port` and cross-host `--peer <host:port>` peers supported, commit `9fed9ad`), static genesis committee `K_0` (cross-rotation fails closed), head-only state-proof RPC (balance/nonce Merkle-verified at head; `state_root` committee-verified per height), and pre-S-033 vacuity (the state-anchored reads throw on a chain without S-033+S-038). §6 consolidates these so they are stated once rather than re-derived per command.

---

## 6. The shared limitations (consolidated)

These honest limitations recur across the family. Each is stated once here, with a pointer to where it is treated in depth. None undermines the per-invocation soundness claim; all are operator-mitigable or scope statements.

### 6.1 Single-daemon (no multi-peer cross-check)

The light-client talks to **one** daemon per invocation. A maliciously-stalling, truncating, or withholding daemon is detected only as a fail-closed exit (`verify-archive` → `UNVERIFIABLE`-style refusal, `account-history` → per-height throw) — the client cannot say "this daemon is wrong; daemon-B is right." Truncated-tip and stale-slice lies are *availability* failures, not *soundness* breaks (the client never acts on inconsistent data; it just may not see all data). **Treated in depth:** `LightClientThreatModel.md` §6.2 + F-4; `LightClientArchiveSoundness.md` §6.5 (`A_stale`); `AccountHistorySoundness.md` §6.5; `TxInclusionProofSoundness.md` §6.2. **Mitigation path:** the future "stateful sync client" tier (multi-peer cross-check), out of scope for the current binary; operators today run a second invocation against a different port and diff.

### 6.2 Static genesis committee `K_0` (the AR-4 / AH §6.2 / TI §6.4 common caveat)

The committee map is seeded **only** from genesis `initial_creators` via `build_genesis_committee` (`light/trustless_read.cpp:43-50`) and is never mutated across a walk. Mid-chain `REGISTER` / `DEREGISTER` shifts the active committee; a header signed by a post-genesis-registered creator not in `K_0` makes `verify_block_sigs` **fail closed** (`"creator '<domain>' is not in the supplied committee"`). This is a *safe* failure (no under-verified data is ever accepted) but means the family is sound **out of the box only for committee-stable ranges**. Cross-rotation ranges need an operator-supplied extended committee that is a superset of every creator encountered, fed identically to every step. **Treated in depth:** `LightClientThreatModel.md` §6.5 + F-1; `LightClientArchiveSoundness.md` AR-4 + §6.2; `AccountHistorySoundness.md` §6.2; `TxInclusionProofSoundness.md` §6.4; **(F6 R40)** the SR-* equivalent. **Mitigation path:** a future stateful-sync extension tracking committee evolution chain-side (or a `--committee` override; confirm per-binary support).

### 6.3 Head-only state-proof RPC (balance/nonce Merkle-verified at head; `state_root` committee-verified per height)

The chain's `Chain::state_proof` (`src/chain/chain.cpp:435-462`) builds a proof from the **current** live state — no height parameter. So balance/nonce are Merkle-verified (MT-4 / T-L3) against the head's `state_root`, while a *per-height* committee-signed `state_root` is verified via header verification (SR-1 / T-L2). For `account-history`, each sampled row carries `balance_proven_at_height` + `balance_merkle_verified` (the latter true only when the sample is the head); a historical Merkle read depends on the daemon being able to serve a height-bound proof (an archival capability) — a daemon that cannot fails closed. **Treated in depth:** `AccountHistorySoundness.md` §1 honesty note + §6.4; `MerkleTreeSoundness.md` §6.2 (S-040 CLOSED — `leaf_count` is bound into the committed root via the root-wrapper, so the former `leaf_count`-sourcing obligation that paired with this head-only constraint is now enforced by the hash). **Mitigation path:** the height-generic code auto-upgrades to per-height Merkle verification if the `state_proof` RPC gains a height parameter.

### 6.4 Pre-S-033 vacuity (state-anchored reads on a chain without S-033 + S-038)

The state-anchored reads (`balance-trustless`, `nonce-trustless`, `account-history`, `verify-and-submit`, `verify-state-root`) require **S-033 + S-038 active** on the chain. Pre-S-038, the producer never populated `body.state_root`, so the field is empty and `read_account_trustless` throws `chain has not activated state_root (S-033)` rather than silently proceeding. This is a chain-level deployment prerequisite, not a client design choice. **The exception is `verify-tx-inclusion`:** it anchors on `tx_root` (in the digest since v1, independent of `state_root`), so it works on pre-S-033 blocks where the balance/nonce reads would throw. **Treated in depth:** `LightClientThreatModel.md` §5.5; `TxInclusionProofSoundness.md` §3.2 + §6.5 (the recorded non-limitation); §2.2 of this map (the inherited S-033 + S-038 precondition).

### 6.5 Sampling gaps (account-history) and range-completeness (archive)

Two faces of the same honesty discipline — "the verification proves what it covers, not what it doesn't":

- **`account-history` sampling gaps (AH-4):** the trajectory proves values AT the sampled heights `{H1, H1+S, …}` only; a transaction could move balance up and back within a `--step` gap and the sample would not reveal it. A verified *sample at stride S*, not a continuous audit. Even `S=1` reports post-block states (no intra-block ordering). **Treated in depth:** `AccountHistorySoundness.md` AH-4 + §6.1.
- **`verify-archive` range-completeness (AR-3):** an accepted archive proves validity of the headers it *contains*, not that it contains *all* headers of a range; `exported_at_height` is an unverified exporter claim, and `from>0` slices float (not anchored to block `from−1`). Completeness is an auditor-side obligation (C-from-genesis or C-cross-check). **Treated in depth:** `LightClientArchiveSoundness.md` AR-3 + §6.1.

These are **scope statements, not soundness failures** — every emitted row / contained header is individually sound. They recur because the family deliberately refuses to over-claim coverage.

### 6.6 Operator-environment limitations (no persistence / no keyfile encryption / no RPC auth / no transport encryption)

Inherited uniformly from `LightClientThreatModel.md` §6: **no persistence** (every invocation re-anchors from genesis and re-walks — O(height) cost; mitigated for `account-history` by the in-memory single-walk-to-`H2` optimization) — **substrate now shipped**: `verify-chain --persist` writes a validated, genesis-pinned, schema-versioned, fail-closed anchor (`{schema_version, genesis_hash, head_height, head_block_hash, head_state_root}`) to `~/.determ-light/state.json` (or `$DETERM_LIGHT_STATE`), managed offline via the `state --show/--clear/--selftest` subcommand (`light/persist.{hpp,cpp}`; soundness `LightStatePersistenceSoundness.md` LSP-1..LSP-6); the anchor is written ONLY after a full committee-verify (LSP-1), so it can never hold an unverified head; the fast-resume *consumer* `verify-chain --resume` (`verify_chain_from_anchor`) is **now shipped** (LSP-6) — it verifies only the suffix above the cached anchor and skips the `0..anchor_height` re-walk, falling back to a full verify when the anchor is unusable; so the O(height) per-invocation cost is paid only on the first verify or a cache miss, not every run; **no keyfile encryption** (plaintext keyfile shape only — the libsodium-free footprint keeps the binary ~3–5 MB; encryption lives in `determ-wallet`); **no RPC auth client** (operator supplies HMAC out-of-band if the daemon requires it); **no transport encryption** (operator wraps RPC in TLS/tunnel; an active MITM is observationally `A_daemon` and thus *covered* for soundness — every byte is verified). None affects the per-invocation soundness claim. **Treated in depth:** `LightClientThreatModel.md` §6.1, §6.4, §6.6, §6.7.

---

## 7. Cross-references

### The six family proof documents (the lattice nodes)

| Document | Theorems | Role in the lattice |
|---|---|---|
| [LightClientThreatModel.md](LightClientThreatModel.md) | T-L1..T-L5, L-1..L-6 | **Root.** The online per-invocation pipeline; T-L1/T-L2 are reused by every sibling. |
| [MerkleTreeSoundness.md](MerkleTreeSoundness.md) | MT-1..MT-5 | **Inclusion substrate.** MT-4 = T-L3's core; consumed by SR-1 / AH-1 Gate-3. |
| [StateRootAnchorSoundness.md](StateRootAnchorSoundness.md) | SR-1..SR-5 | **(F6 R40.)** Per-height committee-anchored `state_root`; the anchor T-L4 / AH-1 consume. |
| [TxInclusionProofSoundness.md](TxInclusionProofSoundness.md) | TI-1..TI-4 | Tx membership via `tx_root` (the `state_root` sibling commitment; flat-SHA, not Merkle). |
| [AccountHistorySoundness.md](AccountHistorySoundness.md) | AH-1..AH-4 | The multi-height trajectory; AH-1 = T-L4 at a fixed historical height. |
| [LightClientArchiveSoundness.md](LightClientArchiveSoundness.md) | AR-1..AR-4 | Offline header-archive; AR-1 = T-L1+T-L2 on frozen bytes; AR-2 is genuinely new. |

### Preliminaries (the base layer)

- [Preliminaries.md](Preliminaries.md) §2.0 — canonical assumption labels (**A1** Ed25519 EUF-CMA, **A2** SHA-256 collision, **A3** preimage/2nd-preimage, **A4** CSPRNG). §2.1 (SHA-256), §2.2 (Ed25519), §2.3 (CSPRNG). §1.3 (hash/digest notation).
- [Safety.md](Safety.md) §7 — FA1 light-client safety composition (T-1.2 / T-1.2.1); the committee-model precondition T-L2 inherits.
- [S033StateRootNamespaceCoverage.md](S033StateRootNamespaceCoverage.md) + [BlockchainStateIntegrity.md](BlockchainStateIntegrity.md) — S-033 (10-namespace `state_root`) + S-038 (producer-side population) + S-021 (chain.json wrap); the inherited chain preconditions (§2.2).
- [NonceMonotonicity.md](NonceMonotonicity.md) (FA-Apply-3) — the chain-side nonce-monotonicity invariant AH-3 cross-checks against.

### Light-client implementation files (`light/`)

| File | Surface |
|---|---|
| `light/main.cpp` (dispatch lines 933–948) | The subcommand dispatcher (§5). |
| `light/trustless_read.cpp` / `.hpp` | `anchor_genesis` (T-L1), `verify_chain_to_head`, `read_account_trustless` (T-L4 + race-window), `build_genesis_committee` (the `K_0` seed, §6.2). |
| `light/verify.cpp` / `.hpp` | `verify_headers` (continuity), `verify_block_sigs` (T-L2), `light_compute_block_digest` (L-2; binds `tx_root` at `:51`), `verify_state_proof` → `merkle_verify` (T-L3/MT-4). |
| `light/account_history.cpp` / `.hpp` | `run_account_history` (AH-1/AH-2), `verify_header_state_root_at` (SR-1 per height), `IncrementalChainWalker::advance_to` (genesis-linkage single pass). |
| `light/verify_tx_inclusion.cpp` / `.hpp` | `verify-tx-inclusion` (TI-1/TI-2/TI-3). |
| `light/verify_archive.cpp` / `.hpp` | `verify-archive` (AR-1 offline / AR-2). |
| `light/export.cpp` / `.hpp` | `export-headers` (AR-1 online half / AR-L1 fail-closed). |
| `light/watch.cpp` / `.hpp` | `watch-head` (T-L1 once + T-L2 per tick). |
| `light/sign_tx.cpp` / `.hpp` | `sign-tx` (`compute_signing_bytes` ≡ `Transaction::signing_bytes`; T-L5). |
| `light/rpc_client.cpp` / `.hpp` | `RpcClient::call` (the JSON-RPC transport every fetch rides on). |
| `light/keyfile.cpp` / `.hpp` | `load_light_keyfile` (plaintext keyfile shape; §6.6). |
| `src/crypto/merkle.cpp` + `include/determ/crypto/merkle.hpp` | `merkle_leaf_hash` / `merkle_inner_hash` / `merkle_root` / `merkle_proof` / `merkle_verify` (MT-1..MT-5). |
| `src/node/producer.cpp` | `compute_block_digest` (`:577-591`, binds `tx_root` at `:581`), `compute_tx_root` (`:262-270`), `make_block_sig`. |

### determ-light test scripts (`tools/`)

| Test script | Theorem coverage |
|---|---|
| `tools/test_light_genesis_anchor.sh` | T-L1 (wrong `--genesis` → refuse). |
| `tools/test_light_verify_headers.sh` | T-L1 + continuity. |
| `tools/test_light_verify_block_sigs.sh` | T-L2 (+ L-2 digest tripwire for TI-4). |
| `tools/test_light_verify_state_proof.sh` | T-L3 / MT-4 (end-to-end). |
| `tools/test_light_verify_chain.sh` | T-L2 composite (genesis → tip). |
| `tools/test_light_balance_trustless.sh` / `tools/test_light_nonce_trustless.sh` | T-L4. |
| `tools/test_light_account_history.sh` | AH-1 / AH-2 / AH-3 / AH-4. |
| `tools/test_light_export_headers.sh` | AR-1 (export side) / AR-2 (offline round-trip) / AR-3 (wrong-range reject). |
| `tools/test_light_verify_archive.sh` | AR-1 (offline) / AR-2 / AR-3 negatives. |
| `tools/test_light_verify_tx_inclusion.sh` | TI-1 / TI-2 / TI-3 (+ the `K_0` caveat). |
| `tools/test_light_watch_head.sh` | T-L1 + per-tick T-L2 (watch-head). |
| `tools/test_light_sign_tx.sh` | T-L5 (offline sign; cross-binary verify). |
| `tools/test_light_verify_and_submit.sh` | T-L4 + T-L5 (end-to-end). |
| `tools/test_merkle.sh` + `tools/test_merkle_proof_tampering.sh` + `tools/test_verify_state_proof.sh` | MT-1..MT-5 primitive surface. |

---

## 8. Status

- **Capstone index — composition map only.** This document introduces **no new theorems**. It is an integration lattice over the light-client proof family: the node list (§3), the rests-on edges (§4), the command→guarantee map (§5), and the consolidated shared limitations (§6).
- **All referenced proofs shipped (R39 + R40).** `LightClientThreatModel.md` (T-L1..T-L5), `MerkleTreeSoundness.md` (MT-1..MT-5), `TxInclusionProofSoundness.md` (TI-1..TI-4), `AccountHistorySoundness.md` (AH-1..AH-4), `LightClientArchiveSoundness.md` (AR-1..AR-4), and `StateRootAnchorSoundness.md` (SR-1..SR-5, the F6 R40 sibling) are all in the tree and threaded. SR-1's binding is transitive-forward (`state_root(h)` is NOT in `compute_block_digest`; certified via the successor block's signed `digest(h+1)` over `prev_hash(h+1)=block_hash(h)`).
- **The shared spine.** Every light-client guarantee funnels to **{A1, A2}** at the cryptographic floor — A1 (Ed25519 EUF-CMA) for committee signatures, A2 (SHA-256 collision) for hash commitments (Merkle roots, genesis hash, `tx_root`, value-hash cross-checks). A3 (preimage) appears at two leaves (T-L1 Case 2, TI content-binding); **A4 (CSPRNG) is used by no light-client theorem** (it underwrites chain-side randomness inherited transitively via the digest). Above the spine, the family inherits {FA1, S-033 + S-038, S-021} as chain-level preconditions it does not re-prove.
- **Theorem labels grounded.** Every `T-L*` / `MT-*` / `AR-*` / `AH-*` / `TI-*` / `SR-*` label in this map is the real label defined in its home document (verified by reading the six documents' theorem statements). No labels are invented; assumption labels follow `Preliminaries.md` §2.0 exactly (no FA3-for-SHA-256).
- **Audience.** A reviewer uses §3 + §4 to confirm the global proof structure; an operator uses §5 + §6 to know what each subcommand actually guarantees and what residual trust remains.

---
