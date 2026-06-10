# AccountHistorySoundness — trustless verified balance/nonce trajectory soundness (`determ-light account-history`)

This document formalizes the soundness of the **`account-history` subcommand** of the `determ-light.exe` light-client binary. The subcommand produces a *trajectory* — a verified sequence of `(height, balance, nonce)` rows for one account `D` sampled across a height range `[H1, H2]` at stride `S` — where **every row is independently anchored** to the operator's pinned genesis-chain by the same per-invocation trust-minimization machinery `LightClientThreatModel.md` proves for a single point.

- **`account-history`** (sibling D3, shipped R40) — for each sampled height `h ∈ {H1, H1+S, H1+2S, …} ∩ [H1, H2]`, performs a trustless account read AT height `h`: fetch `header[h]`, verify the committee Ed25519 signatures + the `prev_hash` linkage back to the genesis-anchored chain, fetch the state-proof for `D`'s account leaf at `h`, verify the Merkle path against `header[h]`'s committee-signed `state_root`, extract `(balance, nonce)`. It composes the existing single-point `balance-trustless` / `nonce-trustless` logic (`light/trustless_read.cpp::read_account_trustless` + its race-window handling) across a height range. Implementation shipped at `light/account_history.cpp` (D3 R40) — entry `run_account_history`, per-height committee-signed-`state_root` verify `verify_header_state_root_at`, genesis-linkage walk `IncrementalChainWalker::advance_to` (a single monotonic `prev_hash` pass from genesis across the whole sampled range — each header is fetched at most once for the chain check, since sampled heights increase monotonically). **Shipped constraint (concretized in §6.4):** the daemon's `state_proof` / `account` RPCs serve the CURRENT head only, so each sampled height's committee-signed `state_root` is verified via header verification (`verify_header_state_root_at`), but balance/nonce are Merkle-verified against a `state_proof` only at the head (one `read_account_trustless` Merkle-read); each row carries `balance_proven_at_height` + `balance_merkle_verified` (true only when the sampled height is the head). The code is height-generic and auto-upgrades to per-height Merkle verification if the daemon's `state_proof` RPC gains a height parameter. AH-1 below is robust to this because it conditions soundness on row *emission* (and binds the committee-verified `state_root` per height regardless of where the balance Merkle-read lands).

The security claim worth proving — and the reason this proof exists as a distinct document from `LightClientThreatModel.md` — is the **multi-height** one:

> A trajectory emitted by `account-history` is a sequence of independently-sound `(height, balance, nonce)` points; each point is proven to be the on-chain account state of `D` at its own sampled height, anchored to the operator's pinned genesis, under the same A1 (Ed25519 EUF-CMA) + A2 (SHA-256 collision) assumptions as the single-point read. A malicious daemon cannot inject a wrong value at any sampled height, nor make one height's proof validate against another height's `state_root`.

`LightClientThreatModel.md` proves the *per-invocation* trustless read (T-L4 balance/nonce-via-state-proof) is sound at a single point. This document adds the **multi-height dimension**: a verified trajectory, each point independently committee-anchored, with no shared trust between points beyond the one-time genesis anchor. No new cryptographic primitive is introduced — the soundness is the *temporal composition* of T-L2 (committee-sig) + T-L3 / MT-4 (state-proof correctness) + T-L1 (genesis anchor), re-applied per sampled height.

This proof is deliberately honest about two limitations a rigorous treatment must not overclaim: **AH-3 (nonce monotonicity is a consistency cross-check, NOT a soundness source)** — a daemon serving an internally-consistent forged history could preserve monotonicity, so monotonicity is necessary-not-sufficient and the *real* guarantee is AH-1's per-point committee-sig anchoring; and **AH-4 (sampling-gap honesty)** — the trajectory proves the values AT the sampled heights only and says nothing about balance between samples (a transaction could move balance up and back within a `--step` gap). Both are analyzed precisely in §4 and recorded in §6.

**Companion documents.** `LightClientThreatModel.md` (T-L1..T-L5, the online per-invocation pipeline this subcommand reuses per sampled height); `LightClientArchiveSoundness.md` (the archive sibling — `account-history` is the *live-query* analog of the `export-headers` / `verify-archive` flow, sharing AR-4's committee-rotation honesty and AR-3's range-honesty discipline); `MerkleTreeSoundness.md` (MT-4 inclusion-proof soundness, the offline Merkle primitive the per-height state-proof step rests on); `Preliminaries.md` (F0) §2.1 (SHA-256 collision resistance, A2) + §2.2 (Ed25519 EUF-CMA, A1) + §2.0 (canonical assumption-label table); `Safety.md` (FA1) for the K-of-K signature-set safety property each per-height read inherits; `NonceMonotonicity.md` (FA-Apply-3) for the chain-side nonce-monotonicity invariant AH-3 cross-checks against; `S033StateRootNamespaceCoverage.md` for the `state_root` commitment surface each per-height read anchors against; `BlockchainStateIntegrity.md` for the chain-level integrity the daemon's served data has already passed; `RpcAuthHmacSoundness.md` + `S001RpcAuthSoundness.md` for the multi-theorem-under-named-adversary citation style.

---

## 1. Scope

The object of study is the **`account-history` subcommand** as a *temporal composition* of `LightClientThreatModel.md`'s per-invocation trustless read. The single-point read (`read_account_trustless`, T-L4) yields one verified `(balance, nonce, state_root, height)` tuple anchored to the operator's pinned genesis. `account-history` invokes the same verification machinery once per sampled height and assembles the results into a trajectory:

```
   operator's --genesis <file>     --domain D     --from H1     --to H2     --step S
                                          │
                                          ▼
                       ┌──────────────────────────────────────┐
                       │  account-history (D3 R40)             │
                       │  anchor_genesis  (ONCE, at startup)   │  T-L1
                       │  for each h in {H1, H1+S, …} ∩ [H1,H2]:│
                       │    ┌─────────────────────────────┐    │
                       │    │ read account AT height h:    │    │
                       │    │   fetch header[h]            │    │
                       │    │   verify committee sigs      │    │  T-L2  (per h)
                       │    │   verify prev_hash linkage   │    │  continuity (per h)
                       │    │   fetch state-proof @ h      │    │
                       │    │   verify Merkle path vs      │    │  MT-4 / T-L3 (per h)
                       │    │     header[h].state_root     │    │
                       │    │   extract (balance, nonce)   │    │  AH-1  (per h)
                       │    └─────────────────────────────┘    │
                       │    emit row (h, balance, nonce)       │
                       └──────────────────────────────────────┘
                                          │
                                          ▼
                          trajectory: [(h_0, b_0, n_0), (h_1, b_1, n_1), …]
                                       each row independently anchored (AH-2)
```

The trajectory adds the **multi-height dimension** that `LightClientThreatModel.md` does not address: that document's claims are per-invocation against a live daemon for a *single* account state (the current head, or one anchored height). Here, `account-history` samples *many* heights in one run and the central question is whether (a) each sampled point is individually sound (AH-1), (b) the points are mutually consistent under one genesis anchor (AH-2), (c) the cross-row nonce-monotonicity property is a soundness source or merely a consistency cross-check (AH-3 — it is the latter), and (d) what the trajectory does and does not establish *between* samples (AH-4).

**Relationship to `read_account_trustless` (the per-height primitive).** The shipped single-point read at `light/trustless_read.cpp:439-599` reads the account state at the daemon's *current verified head* (`verify_chain_to_head` walks to the daemon's tip, then the S-042 committee-binding in §4.4.1 of `LightClientThreatModel.md` anchors the proof root to a committee-signed successor header via `committee_bound_state_root`). For a *historical* read at a fixed sampled height `h < head`, `account-history` (D3 R40) must request the state-proof bound to height `h` specifically and anchor it to `header[h]`'s committee-signed `state_root`, rather than to the head. This is an extension of the single-point flow's structure, not a change to its trust model:

- The genesis anchor (T-L1) is unchanged and runs **once** at startup.
- The committee-sig verification (T-L2) is applied to `header[h]` per sampled height instead of to the head once.
- The state-proof verification (MT-4 / T-L3) anchors against `header[h].state_root` instead of the head's `state_root`.
- The cleartext cross-check (L-4 of `LightClientThreatModel.md`) — if `account-history` performs it — binds `SHA256(balance_be ‖ nonce_be)` to the proof's verified `value_hash` at height `h`.

**Honesty note on per-height state-proof availability (§6.4, flag for D3).** The chain's `Chain::state_proof` producer at `src/chain/chain.cpp:435-462` builds a proof from `build_state_leaves()` over the chain's *live* state — it proves the *current* head's state, with no height parameter. A trustless historical read at `h < head` therefore depends on the daemon being able to serve a state-proof bound to height `h` (e.g., a daemon that retains historical state, or an archival daemon, or one that reconstructs the leaf set at `h`). Whether D3's `account-history` (i) requires such a daemon capability, (ii) restricts the trajectory to heights the daemon can prove, or (iii) reads only at heights where the daemon's current-state proof is the correct historical answer, is an **implementation decision D3 owns**. The soundness theorems below hold for *whatever* `(header[h], state-proof@h)` pair the daemon serves: AH-1 proves that **if** a row is emitted, its value is committee-anchored at `h`; it does **not** assume the daemon *can* serve every requested `h`. A daemon that cannot prove a requested height fails closed (no row, non-zero diagnostic) — exactly the `LightClientThreatModel.md` L-6 fail-closed discipline, here per sampled height. This mirrors `LightClientArchiveSoundness.md` AR-3's "the archive proves what it contains, the daemon's *ability* to serve a range is a separate availability question."

**Out of scope (inherited from `LightClientThreatModel.md` §2.2, plus trajectory-specific exclusions).**

- **Cryptographic breaks** (`A_crypto`): SHA-256 collision/preimage finder (A2 / A3), Ed25519 forger (A1). The trajectory's soundness rests on these being infeasible.
- **The operator's own machine compromise** (`A_local`): key extraction, ptrace, tampering with the `account-history` binary, or rewriting the emitted trajectory after the run. Operator mitigates via OS-level integrity.
- **Tampered pinned genesis** (`A_genesis`): if the operator pins a tampered `genesis.json`, every row anchors to the wrong chain identity. The "trust anchor itself is compromised" case; out of scope exactly as in `LightClientThreatModel.md` §2.2.
- **Inter-sample completeness.** The trajectory is a *sample at stride `S`*; it makes no claim about balance/nonce at heights *between* samples (AH-4). This is not a limitation to be fixed — it is the definition of a sampled trajectory — but it is recorded in §4.4 and §6.1 because an auditor must not read a continuous audit into a sampled trajectory.
- **Multi-peer cross-check.** `account-history` talks to ONE daemon (`LightClientThreatModel.md` §6.2). It does not cross-check the trajectory against a second daemon. A daemon that *withholds* a height (refuses the header or state-proof) is detected only as a per-height fail-closed exit, not by comparison against an independent source.

---

## 2. Threat model

We retain the `LightClientThreatModel.md` adversary `A_daemon` (the single daemon the light-client talks to is fully under adversary control) and specialize its three trajectory-relevant strategies into a named adversary `A_history`.

### 2.1 `A_history` — malicious-daemon-serving-a-forged-trajectory adversary

`A_history` is `A_daemon` (`LightClientThreatModel.md` §2.1) restricted to the `account-history` query pattern: the daemon serving the headers + state-proofs + cleartext account replies for the sampled heights is fully adversarial. Concretely, `A_history` tries to make `account-history` emit a row whose value is *not* the on-chain account state of `D` at the row's height, via one of three strategies:

- **(a) Forged value at a sampled height.** For some sampled `h`, return a state-proof / cleartext reply whose `(balance_A, nonce_A)` differs from `D`'s genuine on-chain state at `h`.
- **(b) Stale / forked state-proof for one height.** For some sampled `h`, return a *genuine-but-wrong-height* proof (a proof from a different height `h' ≠ h`, or from a fork) presented as the answer for `h` — i.e., a proof that verifies against *some* root but not against `header[h]`'s committee-signed `state_root`.
- **(c) Header whose committee sigs don't cover the claimed `state_root`.** For some sampled `h`, return a `header[h]` carrying a `state_root` value the committee did not actually sign — e.g., a header with a swapped-in `state_root` whose `creator_block_sigs` are stale, forged, or signed over a different digest.

`A_history` wins if `account-history` emits **any** row `(h, balance, nonce)` whose value is not `D`'s genuine on-chain state at `h` on the operator's pinned chain. AH-1 (per-point soundness) defeats strategies (a)–(c) cryptographically; AH-2 (trajectory consistency) additionally rules out the cross-height confusion attack (making `h_i`'s proof validate against `h_j`'s root).

### 2.2 Adversary capability EXPLICITLY OUT of scope

As `LightClientThreatModel.md` §2.2:

- **`A_crypto`: cryptographic adversary.** SHA-256 collision finder, Ed25519 forger. Covered by Preliminaries §2.1 (A2 / A3) + §2.2 (A1). Out of scope; the trajectory's defenses rest on `A_crypto` being infeasible.
- **`A_local`: operator's machine compromise.** Key extraction, ptrace, side-channel on the `account-history` process, or rewriting the emitted trajectory. Operator mitigates via OS-level controls.
- **`A_net`: network MITM.** Eavesdropper / active man-in-the-middle on the operator-to-daemon transport. Operator wraps the RPC in TLS / tunnel; the light-client makes no transport-layer claims. An active MITM is observationally equivalent to a malicious daemon and is therefore *covered* by `A_history` for soundness purposes (every byte is verified).
- **`A_genesis`: tampered `--genesis <file>`.** The trust anchor itself is compromised. Out of scope.

### 2.3 Security goal

An **honest light-client** running `account-history` is one that loads a genuine operator-trusted `genesis.json`, runs the released binary unmodified, and does not bypass its own verification. The security claim is: under `A_history`, an honest `account-history` invocation never **emits** a trajectory row whose `(balance, nonce)` is inconsistent with `D`'s genuine on-chain account state at that row's height on the operator's pinned chain.

The negation form (fail-closed): any inconsistency `account-history` detects at any sampled height causes a `throw std::runtime_error(...)` that propagates to a non-zero process exit with a structured stderr diagnostic — the same discipline `LightClientThreatModel.md` L-6 establishes for the single-point read, here applied per sampled height. A partially-emitted trajectory (rows for heights verified before the failing height) followed by a hard error is acceptable; what is **not** acceptable is a silently-wrong row.

### 2.4 Adversary-to-theorem matrix

| Adversary / strategy | Capability | Wins if | Defeated / bounded by | Outcome |
|---|---|---|---|---|
| `A_history` (a) forged value | Returns a state-proof/cleartext with a wrong `(balance, nonce)` at some sampled `h` | A row is emitted whose value ≠ `D`'s on-chain state at `h` | AH-1 via MT-4 / T-L3 (leaf forge ≤ `log₂(leaf_count)·2⁻¹²⁸`) + L-4 cleartext cross-check (`2⁻¹²⁸`) | **Defeated** (cryptographically, A2) |
| `A_history` (b) stale/forked proof | Returns a genuine-but-wrong-height/forked proof for some sampled `h` | The wrong-height proof is accepted as the answer for `h` | AH-1: proof must verify against `header[h].state_root` (committee-signed, T-L2) anchored at `h` via prev_hash linkage to genesis (T-L1) | **Defeated** (A1 + A2) |
| `A_history` (c) unsigned `state_root` | Returns `header[h]` with a `state_root` the committee did not sign | A row anchors to a forged `state_root` | AH-1 via T-L2: `state_root` is bound into the committee-signed `block_hash` chain; a swapped `state_root` desynchronizes the prev_hash linkage or fails the sig check | **Defeated** (A1 + A2) |
| `A_history` cross-height confusion | Serves `h_i`'s proof against `h_j`'s root | A point validates against the wrong height's commitment | AH-2: each row binds the `state_root` from ITS OWN committee-verified `header[h]` (no shared root across rows) | **Defeated** (A1 + A2) |
| (no-op) monotonicity-preserving forgery | Serves an internally-consistent forged history that preserves nonce-monotonicity | The auditor concludes soundness *from monotonicity alone* | AH-3: monotonicity is necessary-not-sufficient; AH-1's per-point committee-sig anchoring is the real guarantee — monotonicity is a *cross-check*, not a soundness source | **Bounded by AH-1, not by monotonicity** (the AH-3 honesty point) |
| Inter-sample tampering | A tx moves balance up and back within a `--step` gap | The auditor reads a continuous audit into the sampled trajectory | AH-4 — *not a soundness failure*; the trajectory is a verified *sample*, not a continuous audit; an auditor-side scope obligation | **Scope limitation** (documented, not defeated) |
| `A_crypto` / `A_local` / `A_genesis` (§2.2) | Break a primitive / compromise the machine / tamper the genesis | (various) | Out of scope | **Out of scope** (explicit) |

The matrix encodes the proof's central honesty points: strategies (a)–(c) and the cross-height confusion attack are *defeated cryptographically* (AH-1 + AH-2); the monotonicity-preserving forgery is **not** defeated by monotonicity (a daemon could preserve it) but **is** defeated by AH-1's per-point anchoring (AH-3); and inter-sample tampering is a *scope* limitation discharged by reading the trajectory as a sample, not a defect (AH-4).

---

## 3. Per-height primitive recap

`account-history` reuses, verbatim per sampled height, the verification primitives `LightClientThreatModel.md` §3 defines and `MerkleTreeSoundness.md` proves. They are recapped here only to fix notation; the authoritative descriptions are in those documents.

| Primitive | Function | Reference | Used at (per sampled `h`) |
|---|---|---|---|
| Genesis anchor | `anchor_genesis` | `LightClientThreatModel.md` §3.1 / T-L1 | once at startup (shared by all rows) |
| Committee-signature verify | `verify_block_sigs` | `LightClientThreatModel.md` §3.2 / T-L2 | per `header[h]` |
| Header-chain continuity | `verify_headers` | `LightClientThreatModel.md` §3.3 | per `header[h]` (prev_hash linkage to the genesis-anchored chain) |
| Merkle state-proof verify | `verify_state_proof` → `merkle_verify` | `LightClientThreatModel.md` §3.4 / T-L3; `MerkleTreeSoundness.md` MT-4 | per state-proof@`h` |
| Composite trustless read | `read_account_trustless` | `LightClientThreatModel.md` §4.4 / T-L4 | per sampled `h` (the structural template `account-history` lifts to a range) |

The four load-bearing facts for this document:

- **T-L1 (genesis-anchored chain identity).** `anchor_genesis` recomputes `compute_genesis_hash(genesis_O)` locally and cross-checks the daemon's block-0 hash byte-for-byte (`light/trustless_read.cpp:55-82`). Under A2, a daemon serving a chain whose genesis ≠ the operator's pinned `genesis.json` cannot pass this gate (`LightClientThreatModel.md` T-L1). In `account-history` this gate runs **once** at startup; every per-height read inherits the anchored chain identity.

- **T-L2 (head trust via committee signatures).** `verify_block_sigs` (`light/verify.cpp:235-328`) requires every entry of `header[h].creators` to be in the committee map and `valid ≥ required` Ed25519 verifications over `light_compute_block_digest(header[h])` at the K-of-K (MD) or `⌈2k/3⌉` (BFT) threshold. Under A1, a daemon cannot present a `header[h]` the committee did not sign (`LightClientThreatModel.md` T-L2). Crucially, `state_root` is part of `header[h]`'s content bound into its `block_hash` chain (`S033StateRootNamespaceCoverage.md`; `LightClientThreatModel.md` §5.2 note), so a committee-signed `header[h]` pins a *specific* `state_root` value at `h`.

- **T-L3 / MT-4 (state-proof correctness).** `verify_state_proof` (`light/verify.cpp:330-396`) delegates to `crypto::merkle_verify` (`src/crypto/merkle.cpp:113-141`). `MerkleTreeSoundness.md` **MT-4 (inclusion-proof soundness, §4)** proves: fix a leaf set `Λ` with root `r = MR(Λ)` and `n = |Λ|`; for any `(key⋆, value⋆, target_index⋆, proof⋆)` with `target_index⋆ < n`, a passing `merkle_verify` against `r` implies genuine membership with probability `≥ 1 − 2⁻¹²⁸` under A2. Applied to `account-history`: a state-proof for `D`'s `a:`-namespace leaf that verifies against `header[h].state_root` proves `D`'s leaf value is genuinely committed under that root — i.e., is `D`'s on-chain account state at `h`. (**S-040 CLOSED** — `leaf_count` is bound into the committed root via the root-wrapper hash `SHA256(0x02 ‖ be_u32(leaf_count) ‖ inner_root)`; `merkle_verify` re-applies the wrapper with the caller-supplied `leaf_count`, so a forged count yields a different wrapper hash and is rejected by the hash itself. The former obligation to source `leaf_count` from the same anchor as `state_root` is now enforced cryptographically rather than as a caller guideline — see `MerkleTreeSoundness.md` §6.2 / S-040.)

- **T-L4 + race-window (balance/nonce composition).** `read_account_trustless` (`LightClientThreatModel.md` §4.4 / T-L4) chains genesis-anchor → header-walk + per-block sig verify → state-proof fetch → self-anchored proof verify → S-042 committee-binding (bind the proof's `state_root` to a committee-signed successor header) → cleartext cross-check (`SHA256(balance_be ‖ nonce_be) == proof.value_hash`, Lemma L-4). The **race-window mitigation (S-042)** (`LightClientThreatModel.md` §4.4.1) handles the case where the chain advanced during the round-trip: after a stale-height gate rejects a proof before the verified head, `committee_bound_state_root` sets `anchor_index = proof_height − 1`, recomputes that block's `block_hash` from the full body (`state_root` is *inside* `block_hash`), and requires the committee-signed **successor** header's `prev_hash` to equal it — the anchor's `state_root` is thus bound transitively forward via the successor's signature (the anchor header's own digest *excludes* `state_root`, so signing it does not bind it). For `account-history`'s historical read at a *fixed* `h`, the analogous binding anchors `header[h]` via the same successor-`prev_hash` rule (the sampled height is the target, not a moving head); the structural binding — proof's root ⇔ committee-signed successor's `prev_hash` ⇔ prev_hash linkage to genesis — is identical.

---

## 4. Soundness theorems

Notation: `D` is the queried account domain; `[H1, H2]` the height range; `S` the stride; `Σ := {H1, H1+S, H1+2S, …} ∩ [H1, H2]` the sampled-height set; `header[h]` the daemon's header reply for height `h`; `R_h := header[h].state_root` the per-height committee-signed root; `K_0 := build_genesis_committee(genesis_O)` the genesis-seeded committee map; `(b_h, n_h)` the daemon's served balance/nonce at `h`; `(b_h^T, n_h^T)` the *true* on-chain values. `A1` = Ed25519 EUF-CMA (Preliminaries §2.2), `A2` = SHA-256 collision resistance (§2.1), `A3` = SHA-256 preimage resistance (§2.1), per `Preliminaries.md §2.0`.

### 4.0 Formalism: the trajectory function and the soundness predicate

To make the AH-1..AH-4 statements precise, we fix the object `account-history` computes and the property we prove of it.

**The sampled-height set.** Given `--from H1 --to H2 --step S` with `S ≥ 1` and `H1 ≤ H2`, the sampled-height set is `Σ := { H1 + i·S : i ∈ ℕ₀, H1 + i·S ≤ H2 }`. It is finite (`|Σ| = ⌊(H2 − H1)/S⌋ + 1`) and strictly increasing. Write its elements in order as `h_0 < h_1 < … < h_{m−1}` with `m = |Σ|`.

**The per-height read.** Let `ρ : (daemon, h) → ({(b, n), state_root, ⊥})` be the per-sampled-height trustless read `account-history` performs (AH-L1: a restriction of `read_account_trustless` to a fixed historical `h`). `ρ` either returns a verified `((b_h, n_h), R_h)` pair or signals failure (`⊥`, which triggers the fail-closed throw of AH-L5). `ρ` is defined as the composition of the three gates of §4.1: `ρ(daemon, h) = G3 ∘ G2 ∘ G1` where `G1` accepts a committee-signed `header[h]` (pinning `R_h`), `G2` accepts the genesis-linkage of `header[h]`, and `G3` accepts a state-proof for `D` verifying against `R_h` (yielding `(b_h, n_h)`).

**The trajectory function.** `account-history` computes
```
   AcctHist(daemon, genesis_O, D, H1, H2, S)
     = let _ = anchor_genesis(daemon, genesis_O)         // T-L1, once (AH-L3)
       in [ (h, ρ(daemon, h).b, ρ(daemon, h).n) : h ∈ Σ, in increasing order ]
```
with the convention that the first `h` for which `ρ` returns `⊥` aborts the whole computation (no further rows; non-zero exit). The output is a list of rows `T = [(h_0, b_{h_0}, n_{h_0}), …]`, possibly truncated by an abort.

**The soundness predicate.** A row `(h, b, n)` is *sound* iff `(b, n) = (b_h^T, n_h^T)` — the daemon-served value equals `D`'s genuine on-chain account state at `h` on the operator's pinned chain. A trajectory `T` is *row-wise sound* iff every emitted row is sound. The §2.3 security goal is exactly: under `A_history`, `AcctHist` is row-wise sound (no silently-wrong row), with the negation form being fail-closed abort (AH-L5).

**Lemma AH-L0 (gate independence).** The three success events `G1`, `G2`, `G3` of `ρ` reduce to *disjoint* cryptographic hardness instances, so their adversarial-success probabilities add (rather than requiring a joint analysis). Proof: `G1`'s forge target is an Ed25519 signature over `light_compute_block_digest(header[h])` (A1 instance, keyed by a committee member's `sk`); `G2`'s forge target is a `prev_hash` collision linking a fabricated header into the genesis-rooted chain (A2 instance over the SHA-256 `block_hash` preimage); `G3`'s forge target is a Merkle sibling-path collision making a non-member leaf roll up to `R_h` (A2 instance over the SHA-256 tree, MT-4). The A1 instance (a Schnorr-type signature forgery) and the two A2 instances (SHA-256 collisions on disjoint preimage languages — `block_hash` inputs vs Merkle leaf/inner inputs, kept disjoint by the `0x00`/`0x01` domain separation of `MerkleTreeSoundness.md` MT-2) share no key material and no preimage structure. Hence a single adversarial query cannot amortize work across the three; the union bound `Pr[¬G1 ∨ ¬G2 ∨ ¬G3 broken] ≤ Pr[G1 broken] + Pr[G2 broken] + Pr[G3 broken]` is the correct (and tight) composition. □

This formalism is used as follows: AH-1 proves each *individual* row is sound (a property of `ρ` at one `h`, via AH-L0); AH-2 proves the rows are *mutually independent* (a property of the list — no cross-row coupling beyond the shared genesis anchor and per-row genesis linkage); AH-3 proves a property of the *nonce projection* `[n_{h_0}, …, n_{h_{m−1}}]` (monotonicity) is a cross-check on `T`, not a soundness source; AH-4 bounds what `T` says about heights `h ∉ Σ` (nothing).

### 4.1 Theorem AH-1 (per-point soundness)

**Statement.** Under A1 + A2, for every sampled height `h ∈ Σ`, if `account-history` **emits** a row `(h, b_h, n_h)`, then `(b_h, n_h)` is `D`'s genuine on-chain account state at height `h` on the operator's pinned chain — i.e., `(b_h, n_h) = (b_h^T, n_h^T)`. No adversary `A_history` (strategies (a)–(c) of §2.1) can cause `account-history` to emit a row with `(b_h, n_h) ≠ (b_h^T, n_h^T)` except with probability `≤ K · 2⁻¹²⁸ + log₂(leaf_count) · 2⁻¹²⁸ + 2⁻¹²⁸` per sampled height.

**Adversary game.**

1. Setup. Operator pins `genesis_O`; `K_0` and `gh_O := compute_genesis_hash(genesis_O)` are computed locally inside `account-history`. The genesis anchor (T-L1) has passed once at startup.
2. For a sampled height `h`, `A_history` returns `(header[h], state-proof@h, cleartext_account@h)` of its choosing.
3. Adversary wins if `account-history` emits `(h, b_h, n_h)` with `(b_h, n_h) ≠ (b_h^T, n_h^T)`.

**Proof.** A row `(h, b_h, n_h)` is emitted only after the per-height read passes the composition of three independent gates, each a restriction of a proven primitive:

*Gate 1 — committee-signed header at `h` (T-L2).* `account-history` runs `verify_block_sigs(header[h], committee_json, MD-then-BFT)`. By T-L2 (`LightClientThreatModel.md` §4.2), acceptance requires `valid ≥ required` Ed25519 signatures over `light_compute_block_digest(header[h])` under `K_0` keys. Because `prev_hash`, `tx_root`, `delay_seed`, `index`, `consensus_mode`, `bft_proposer`, `creators`, `creator_tx_lists`, `creator_ed_sigs`, and `creator_dh_inputs` are all inputs to the digest (`LightClientThreatModel.md` L-2), and because `header[h].state_root` is bound into `header[h].block_hash` via the broader `signing_bytes`/`block_hash` chain (`S033StateRootNamespaceCoverage.md`; `LightClientThreatModel.md` §5.2 note), a daemon serving a `header[h]` whose `state_root` value differs from what the committee signed (`A_history` strategy (c)) must either (i) forge `required` committee signatures over a new digest — `≤ K · 2⁻¹²⁸` under A1 — or (ii) present a `state_root`/`block_hash` pair that does not cohere, which desynchronizes Gate 2's prev_hash linkage. Hence Gate 1 pins a *specific*, committee-attested `R_h := header[h].state_root` for height `h`.

*Gate 2 — `header[h]` linked to the genesis-anchored chain (T-L1 + continuity).* `account-history` confirms `header[h]` chains, via `prev_hash`, to the genesis-anchored prefix (the §4.2 linkage discussion below). By T-L1, the chain's identity is pinned to `genesis_O` (A2 collision + A3 preimage on the genesis hash; `LightClientThreatModel.md` T-L1 Cases 1–2). By `verify_headers` continuity (`LightClientThreatModel.md` §3.3), each `prev_hash` link is an A2-collision-resistant binding to the prior block's `block_hash`. Therefore `header[h]` is not a free-floating forged header but one attested as block `h` of the operator's pinned chain — defeating `A_history` strategy (b)'s *forked-header* variant.

*Gate 3 — `D`'s leaf committed under `R_h` (MT-4 / T-L3), plus cleartext binding (L-4).* `account-history` runs `verify_state_proof(state-proof@h, R_h)` — i.e., anchored against the *committee-signed* root `R_h` from Gate 1, not the proof's self-claimed root. By `MerkleTreeSoundness.md` MT-4, acceptance implies `D`'s `a:`-namespace leaf value `value_hash_h` is genuinely committed under `R_h` with probability `≥ 1 − log₂(leaf_count) · 2⁻¹²⁸` under A2. A daemon serving a stale/wrong-height proof (`A_history` strategy (b)) returns a proof that rolls up to some root `r' ≠ R_h`; the anchored check `merkle_verify(R_h, …)` rejects it (the wrong-height proof does not verify against `header[h]`'s root) unless the daemon finds a second leaf set colliding to `R_h` — an A2 violation. Finally, if `account-history` performs the cleartext cross-check (Lemma L-4 of `LightClientThreatModel.md`), it recomputes `SHA256(b_h‖n_h) ` and requires equality with the verified `value_hash_h`; a daemon serving `(b_h, n_h) ≠ (b_h^T, n_h^T)` (strategy (a)) while the proof commits the true leaf must force `SHA256(b_h‖n_h) = SHA256(b_h^T‖n_h^T)` for distinct pairs — a SHA-256 collision, `≤ 2⁻¹²⁸`. If `account-history` instead reads `(b_h, n_h)` *directly from the verified leaf encoding* (decoding `value_hash`'s preimage from the proof), the value is the committed one by MT-4 and no separate cross-check is needed. Either construction binds `(b_h, n_h)` to `R_h`.

Combining the three gates: by Lemma AH-L0 the three forge events reduce to disjoint hardness instances (one A1, two A2 over domain-separated preimage languages), so their success probabilities add under the union bound: `Pr[A_history wins AH-1 at h] ≤ K · 2⁻¹²⁸ + log₂(leaf_count) · 2⁻¹²⁸ + 2⁻¹²⁸` (the `K·2⁻¹²⁸` Gate-1 term, the `log₂(leaf_count)·2⁻¹²⁸` Gate-3 MT-4 term, and the `2⁻¹²⁸` cleartext-collision term; the Gate-2 genesis-linkage term is dominated by the per-height prev_hash walk and folded into the trajectory-level bound of §8). For `K ≤ 16` and `leaf_count ≤ 2⁶⁴`: `≤ 16·2⁻¹²⁸ + 64·2⁻¹²⁸ + 2⁻¹²⁸ ≤ 2⁻¹²¹`, negligible. ∎

**Composition statement.** AH-1 is, structurally, **T-L4 (`LightClientThreatModel.md`) applied at a fixed historical height `h`**: T-L2 (committee-signed `header[h]`) + MT-4 / T-L3 (state-proof verifies against `header[h].state_root`) + T-L1 (genesis anchor, once). The single-point read's S-042 committee-binding (`LightClientThreatModel.md` §4.4.1) is specialized: instead of binding a moving head's proof to its committee-signed successor, `account-history` binds the sampled `header[h]` to its successor's committee-signed `prev_hash` directly. No new cryptographic claim beyond T-L4 is asserted per point.

### 4.2 Theorem AH-2 (trajectory consistency)

**Statement.** Under A1 + A2, across the sampled sequence `Σ`, each emitted row `(h, b_h, n_h)` is **independently anchored** to the *same* genesis-pinned chain: the genesis anchor (T-L1) runs once at startup, and each row's value binds the `state_root` from **its own** committee-verified `header[h]` (`R_h`) via that header's `prev_hash` linkage to the genesis-anchored prefix. Consequently, `A_history` cannot make height `h_i`'s state-proof validate against height `h_j`'s `state_root` (`i ≠ j`): the trajectory is a sequence of independently-sound points, not a chain of inter-dependent ones.

**Adversary game.**

1. Setup as AH-1. Genesis anchor passed once.
2. `A_history` serves the per-height tuples for all `h ∈ Σ`, attempting a *cross-height confusion*: present `h_i`'s proof (or leaf) as the answer for `h_j`, so that a value true at `h_i` is emitted for `h_j` (`b_{h_j} := b_{h_i}^T` with `b_{h_i}^T ≠ b_{h_j}^T`).
3. Adversary wins if `account-history` emits a row for `h_j` whose value is `D`'s state at some *other* height `h_i ≠ h_j`.

**Proof.** Each row `h_j` is anchored, by AH-1 Gate 3, against `R_{h_j} := header[h_j].state_root` — the root from `h_j`'s *own* committee-verified header, not from `h_i`'s. The state-proof presented for `h_j` must satisfy `merkle_verify(R_{h_j}, key_bytes_D, value_hash, target_index, leaf_count, sibs) = true`. A proof that commits `D`'s state at `h_i` rolls up to `R_{h_i}`; for it to also verify against `R_{h_j}` requires either `R_{h_i} = R_{h_j}` (which, for distinct on-chain account states at `h_i` vs `h_j`, would require two distinct leaf sets producing the same Merkle root — an A2 collision, `≤ 2⁻¹²⁸`) or a forged sibling path making the `h_i`-leaf roll up to `R_{h_j}` (an A2 collision cascade up the tree, `≤ log₂(leaf_count) · 2⁻¹²⁸`, by MT-4). Both are infeasible under A2.

The **independence** is the structural crux: there is *no shared root* across rows that the adversary can exploit. Unlike a header-*chain* verification (where block `h+1` depends on block `h`'s `block_hash` via `prev_hash`), the *account-value* rows are each independently anchored to their own header's `state_root`. The only shared trust is (i) the one-time genesis anchor and (ii) the per-height `prev_hash` linkage that pins each `header[h]` to the same genesis-rooted chain. Both are *necessary* (they establish that each `R_h` belongs to the operator's chain) but neither couples row `h_i`'s *value* to row `h_j`'s *value*. Therefore corrupting one row's value (an A2/A1 break at that row, ruled out by AH-1) does not corrupt another, and confusing two rows (this theorem) is an A2 break. ∎

**Note on the `prev_hash` linkage (how each `header[h]` is anchored to genesis).** `account-history` must establish that each `header[h]` it verifies is genuinely block `h` of the operator's pinned chain — not a free-floating committee-subset-signed header. Two sound constructions, both reusing existing primitives:

- **Full-walk construction.** Walk the header chain from block 0 (genesis-anchored) to each sampled `h` via `verify_headers` page loop (`verify_chain_walk`, `light/trustless_read.cpp:105-230`, entered via `verify_chain_to_head` at `:234-248`), confirming `prev_hash` continuity throughout. This is the strongest binding (every link from genesis to `h` is checked) but costs `O(h)` Ed25519 verifications per sampled height — the same per-invocation cost the single-point read pays (`LightClientThreatModel.md` §6.1), now potentially repeated per sample. D3 may amortize by walking once to `H2` and caching the verified header chain in memory for the duration of the run (an in-memory optimization that does not change the trust model — the cache is the light-client's own verified data, not the daemon's claim).
- **Anchored-segment construction.** For sampled `h_{k}` after a previously-verified `h_{k-1}`, walk only the segment `[h_{k-1}, h_k]` and confirm `header[h_{k-1}].block_hash` matches the previously-verified value (the race-window §4.4.1 pattern, generalized to forward sampling). This binds each new `header[h_k]` to the already-verified prefix.

Whichever D3 chooses, the soundness requirement AH-2 imposes is: **each `header[h]`'s `prev_hash` must be transitively linked to the genesis-anchored block 0**, so that `R_h` is provably a root of the operator's pinned chain. A `from > 0` *unanchored* read — verifying `header[h]`'s sigs in isolation without linking it to genesis — would suffer exactly the `LightClientArchiveSoundness.md` AR-3(ii) "floating slice" defect (a committee-subset could sign a forked/alternative header at the same index). The proof's AH-2 holds **conditional on the linkage being established** (full-walk or anchored-segment); a hypothetical implementation that skipped the linkage would reduce AH-2 to "each row is committee-signed by *some* `K_0` subset" — internally consistent but not genesis-anchored. This conditional is flagged for D3 in §6.3 and mirrors the AR-3(ii) honesty point.

### 4.3 Theorem AH-3 (nonce monotonicity is a consistency check, NOT a soundness source)

This is a key honesty theorem. We state precisely the role of cross-row nonce-monotonicity and warn against the over-claim that monotonicity *establishes* soundness.

**Statement.** For a *live* account `D` (one that originates transactions), the nonce `n_h` is **non-decreasing** in `h`: for sampled heights `h_i < h_j`, the genuine on-chain values satisfy `n_{h_i}^T ≤ n_{h_j}^T` (the chain's nonce-monotonicity invariant, `NonceMonotonicity.md` FA-Apply-3 T-N5, lifted across blocks). `account-history` MAY surface a *violation* — an emitted trajectory in which `n_{h_i} > n_{h_j}` for `h_i < h_j` — as evidence of **daemon inconsistency**. However:

(i) Monotonicity is **necessary, not sufficient**, for trajectory soundness. A monotonic trajectory is *not* thereby proven sound: a daemon serving an internally-consistent forged history (e.g., a coherent but fabricated nonce ladder `0, 1, 2, …` across the sampled heights) preserves monotonicity while being entirely fake.

(ii) The **real soundness guarantee is AH-1's per-point committee-sig anchoring**, not monotonicity. Each `(h, b_h, n_h)` is sound because it is bound to `header[h]`'s committee-signed `state_root` (AH-1), independently of whether the *sequence* of nonces happens to be monotonic.

(iii) Therefore monotonicity is a **cross-check** (a cheap, useful sanity assertion that catches *some* daemon misbehavior — specifically a daemon that serves *genuine* proofs but in a *scrambled order*, or a daemon whose forgery is sloppy enough to break the ladder), **not** a soundness source. A trajectory that passes AH-1 at every point but exhibits a monotonicity violation indicates a *genuine on-chain anomaly* (which, given AH-1, cannot happen for a correctly-functioning chain — see the proof) or a *bug*, and `account-history` should surface it; a trajectory that passes AH-1 at every point *and* is monotonic is sound **because of AH-1**, with monotonicity adding confirmatory (not foundational) evidence.

**Proof.**

*Monotonicity holds on a genuine chain.* By `NonceMonotonicity.md` FA-Apply-3, an account's `next_nonce` advances by exactly 1 per successfully-applied transaction it originates and never decreases (T-N1 stale-nonce rejection, T-N4 replay-defense via monotonic advance, T-N5 monotonic accumulation across blocks). Block application is append-only over the chain; for `h_i < h_j`, the state at `h_j` is the result of applying blocks `(h_i, h_j]` on top of the state at `h_i`, none of which can decrease `D`'s nonce. Hence `n_{h_i}^T ≤ n_{h_j}^T`. ∎ (for the necessary direction).

*Monotonicity is not sufficient.* Consider a daemon that does not serve the genuine chain at all but fabricates, for each sampled `h`, a *self-consistent* forged `(header[h], state-proof@h)` with a fabricated `state_root` and a fabricated nonce ladder `n_{h_0} = 0, n_{h_1} = 1, …`. **If** such a daemon could pass AH-1 (it cannot — that is the point), the trajectory would be monotonic yet fake. Monotonicity alone cannot distinguish this fabricated ladder from the genuine one: both are non-decreasing. The distinguishing power comes *entirely* from AH-1 — the forged `header[h]` fails the committee-sig gate (Gate 1, A1) or the forged proof fails the MT-4 gate against the committee-signed root (Gate 3, A2). Thus the daemon's fabrication is caught by AH-1's cryptographic anchoring, **regardless of whether it preserved monotonicity**. A monotonicity check *in isolation* would have accepted the fabricated ladder. Therefore monotonicity is not a soundness source. ∎ (for the insufficiency direction).

**Why monotonicity is still worth surfacing (the cross-check value).** Given AH-1, every emitted row is individually committee-anchored, so a *correctly-functioning chain* cannot produce a genuine monotonicity violation (the necessary direction proves `n_{h_i}^T ≤ n_{h_j}^T`). Hence if `account-history` emits an AH-1-sound trajectory that *also* violates monotonicity, exactly one of the following holds: (a) a chain-level bug or invariant breach in the daemon's chain (an FA-Apply-3 violation that should never occur), (b) a sampling/ordering bug in `account-history` itself, or (c) — ruled out under A1+A2 — a forgery that somehow passed AH-1. The monotonicity cross-check is therefore a cheap **defense-in-depth tripwire**: it cannot *replace* AH-1, but it can catch implementation bugs and would loudly signal the (cryptographically-precluded) event that AH-1 was somehow bypassed. `account-history` SHOULD report a monotonicity violation as a hard error or prominent warning, framed as "daemon/chain inconsistency detected," precisely because under sound operation it must never fire.

**The over-claim to avoid (stated explicitly).** It is tempting to present a monotonic balance/nonce trajectory as "self-evidently consistent therefore trustworthy." This proof rejects that framing. *Monotonicity is a property a forged-but-coherent history can also satisfy.* The trajectory's trustworthiness rests on AH-1 (per-point committee anchoring) and AH-2 (independent anchoring), **not** on the shape of the nonce sequence. An auditor MUST NOT downgrade from per-point verification to "the numbers look monotonic" — that is exactly the trust the light-client exists to eliminate.

**Remark (balance is not monotonic).** Unlike nonce, *balance* `b_h` has no monotonicity property — it rises on credit and falls on debit. There is no cross-row balance sanity check analogous to the nonce ladder; each balance row's soundness rests entirely on AH-1. This reinforces AH-3's thesis: the per-point anchoring is the universal guarantee; sequence-shape heuristics (available only for nonce, and only as a tripwire) are confirmatory at best.

### 4.4 Theorem AH-4 (sampling-gap honesty)

This is the second honesty theorem, the trajectory analog of `LightClientArchiveSoundness.md` AR-3 (range-completeness honesty).

**Statement.** `account-history` proves the values `(b_h, n_h)` **AT the sampled heights `h ∈ Σ` only**. It says **nothing** about `D`'s balance or nonce at heights *between* consecutive samples. Specifically, for consecutive samples `h_k, h_{k+1} = h_k + S` (`S > 1`), the trajectory establishes `(b_{h_k}, n_{h_k})` and `(b_{h_{k+1}}, n_{h_{k+1}})` but does **not** establish any value at `h_k < h' < h_{k+1}`. A transaction (or several) could move `D`'s balance arbitrarily within the gap — up then back down, or to an extreme and back — and the sampled trajectory would not reveal it.

**Proof.** The set of facts `account-history` establishes is exactly `{AH-1 at h : h ∈ Σ}` — one committee-anchored value per sampled height. No fact is established for `h' ∉ Σ`: `account-history` fetches no `header[h']`, no state-proof at `h'`, and runs no verification for `h'`. The chain's apply layer (`NonceMonotonicity.md` FA-Apply-3, `AccountStateInvariants.md` FA-Apply-1) processes *every* block, so `D`'s state at `h'` is well-defined on-chain — but the trajectory simply does not sample it. Concretely:

- *Balance round-trip in a gap.* Suppose at `h_k`, `b_{h_k} = 100`; at `h_k + 1`, a transaction credits 1000 (`b = 1100`); at `h_k + 2`, a transaction debits 1000 (`b = 100`); and `h_{k+1} = h_k + S` with `S ≥ 3` reports `b_{h_{k+1}} = 100`. The trajectory shows `100 → 100` across the gap and gives no hint of the intervening `1100`. This is **not** a daemon lie — both sampled rows are AH-1-sound — it is the inherent limitation of sampling at stride `S`. **Not revealed by the trajectory.**
- *Nonce activity in a gap.* Multiple transactions in the gap advance the nonce; the trajectory shows the endpoints (`n_{h_k}, n_{h_{k+1}}`) with `n_{h_{k+1}} ≥ n_{h_k}` but does not enumerate the intervening advances. The *count* of intervening transactions is `n_{h_{k+1}} − n_{h_k}` (a derivable lower-bound observation for a single-origin account, since each origin-tx advances the nonce by 1), but their *effects on balance* are not sampled. **Not revealed.**

Hence the trajectory is a **verified sample, not a continuous audit.** ∎

**What AH-4 does and does not say.** AH-4 is **not** a soundness failure — every emitted row is sound (AH-1). It is a *scope* statement: the trajectory's resolution is `S`, and inter-sample behavior is below that resolution. An auditor MUST read the trajectory as "these are the verified values at these specific heights," **not** "this is `D`'s complete balance history." To obtain finer resolution, the auditor reduces `S` (more samples, more verification cost — the `O(height)` per-read cost of `LightClientThreatModel.md` §6.1 multiplied by the sample count); to obtain a *continuous* audit, the auditor would need to sample *every* height (`S = 1`), which verifies `D`'s state at every block but is the most expensive mode and still says nothing about *intra-block* ordering (multiple txs in one block are applied atomically and the trajectory sees only the post-block state).

**Auditor obligations (honest documentation).** To use `account-history` as a *complete* balance audit over `[H1, H2]`, an auditor must either:

1. Set `S = 1` (sample every block), accepting the full per-block verification cost, *and* understand that even then the trajectory reports post-block states (intra-block tx ordering is not surfaced — it is an apply-layer property, `MultiEventComposition.md` FA-Apply-15). The nonce deltas (`n_{h+1} − n_h`) bound the per-block origin-tx count.
2. Accept the sampled trajectory as a *spot-check at stride `S`* and not infer inter-sample behavior. This is the intended use: cheap periodic verification (e.g., "verify my balance every 1000 blocks") that detects *sustained* divergence without auditing every transaction.

This mirrors `LightClientArchiveSoundness.md` AR-3's verdict ("the archive proves the validity of the headers it *contains*, not their *completeness* over any range") — here transposed to the temporal-sampling axis: **the trajectory proves the values at the heights it *samples*, not the values *between* samples.**

### 4.5 Supporting lemmas

These lemmas isolate the load-bearing steps so a reviewer can match each to a code location. Several restate `LightClientThreatModel.md` / `MerkleTreeSoundness.md` lemmas applied per sampled height; they are reproduced here so this proof is self-contained.

**Lemma AH-L1 (per-height read is the single-point read at a fixed `h`).** The per-sampled-height verification `account-history` runs is a restriction of `read_account_trustless` (`LightClientThreatModel.md` T-L4) with the target height fixed to `h` rather than the daemon's moving head. Proof: both chain (genesis-anchor once) → (committee-signed header carrying `state_root`) → (state-proof verified against that header's `state_root`) → (balance/nonce bound to the verified leaf). The only structural difference is the *target selection*: the single-point read targets the head (and handles chain-advancement via the §4.4.1 race-window dispatch), whereas the per-height read targets a fixed `h` (and anchors to `header[h]` directly). The cryptographic gates (T-L2, MT-4/T-L3, T-L1) are identical. □

**Lemma AH-L2 (per-row independence — no shared root across rows).** For sampled heights `h_i ≠ h_j`, row `h_i`'s value is anchored to `R_{h_i}` and row `h_j`'s to `R_{h_j}`, and these anchors are not coupled: corrupting `R_{h_i}` (infeasible under AH-1) does not affect `R_{h_j}`. Proof: each `R_h := header[h].state_root` is a field of an independently-fetched, independently-committee-verified header. The only inter-row coupling is the prev_hash linkage that pins *both* headers to the same genesis-rooted chain (a *consistency* coupling: both belong to the operator's chain) — it does not make `header[h_i]`'s `state_root` a function of `header[h_j]`'s. Hence the rows are independently sound (the AH-2 crux). □

**Lemma AH-L3 (genesis anchor amortizes across rows).** The genesis anchor (T-L1) is a per-*invocation* check, not per-row: `anchor_genesis` runs once at `account-history` startup, establishing the chain identity for the whole run. Proof: T-L1's local operand `gh_O := compute_genesis_hash(genesis_O)` is a deterministic function of the pinned genesis (`LightClientThreatModel.md` L-1), independent of which heights are sampled; the daemon's block-0 reply is checked once. Every subsequent per-height `prev_hash` linkage (AH-L2) ties back to this single anchor. □

**Lemma AH-L4 (cleartext cross-check binds the daemon's `account` reply per height, if performed).** If `account-history` performs the cleartext cross-check at each sampled `h` (fetching `rpc_account` for `D` at `h`, recomputing `SHA256(balance_be ‖ nonce_be)`, comparing to the proof's verified `value_hash`), then a daemon lying about `(b_h, n_h)` while serving an honest proof must force a SHA-256 collision on the value-hash encoding, `≤ 2⁻¹²⁸`. Proof: identical to `LightClientThreatModel.md` Lemma L-4, applied at height `h`; the `a:`-namespace leaf encoding is `value_hash = SHA256(balance_u64 ‖ next_nonce_u64)` (`S033StateRootNamespaceCoverage.md` §2.1; the same encoding `read_account_trustless` cross-checks at `light/trustless_read.cpp:573-593`). If `account-history` instead decodes `(b_h, n_h)` directly from the verified leaf preimage, this lemma is vacuous (no separate cleartext reply to cross-check) and AH-1 Gate 3 binds the value via MT-4 alone. □

**Lemma AH-L5 (fail-closed exit per sampled height).** Any inconsistency `account-history` detects at any sampled height causes a `throw` propagating to a non-zero exit; no silently-wrong row is emitted. Proof: `account-history` (D3 R40) composes the verify primitives (`verify_block_sigs`, `verify_headers`, `verify_state_proof`) whose failure branches set `ok=false`/throw (`LightClientThreatModel.md` L-6), and the per-height read template (`read_account_trustless`) throws on every inconsistency it detects (`light/trustless_read.cpp` throw sites). A row is emitted only on the success path past all gates. Thus a failing height aborts with a diagnostic rather than emitting a wrong row — the §2.3 negation-form goal, per sampled height. (The throw sites are in `light/account_history.cpp`: `verify_header_state_root_at` throws a height-bearing `runtime_error` on committee-sig failure or a missing header, and `IncrementalChainWalker::advance_to` throws on a prev_hash linkage break (or a zero-progress header page); both propagate to a non-zero exit from `run_account_history`.) □

---

## 5. Composition

### 5.1 AH-1 ⊂ T-L4 ⊂ A1 + A2

AH-1 (per-point soundness) is, structurally, **T-L4 (`LightClientThreatModel.md` §4.4) applied at a fixed historical height**, which in turn reduces to A1 (Ed25519 EUF-CMA, for the committee-sig gate T-L2) + A2 (SHA-256 collision resistance, for the genesis anchor T-L1 and the Merkle inclusion gate MT-4 / T-L3):

```
   AH-1 (per-point soundness, this doc §4.1)
     ⊂ T-L4 (balance/nonce via state-proof, LightClientThreatModel.md §4.4)
         = T-L1 (genesis anchor)        ⊂ A2 + A3
         + T-L2 (committee sigs)        ⊂ A1
         + T-L3 (state-proof correctness) = MT-4 (MerkleTreeSoundness.md §4) ⊂ A2
         + L-4 (cleartext cross-check)  ⊂ A2
```

No new cryptographic assumption is introduced. `account-history`'s contribution over `LightClientThreatModel.md` is **temporal-multi-point** (AH-2: independent per-row anchoring) and **honesty-scope** (AH-3: monotonicity ≠ soundness; AH-4: sampling gaps), not cryptographic — the same "adds no new chain-level invariant; composes existing results" posture that `Safety.md` §7 records for the light-client's relationship to FA1 and that `LightClientArchiveSoundness.md` §5.1 records for the archive flow.

### 5.2 Cross-reference: MT-4 (MerkleTreeSoundness.md) underpins the per-height state-proof step

Each per-height AH-1 Gate 3 invokes `merkle_verify(R_h, key_bytes_D, value_hash, target_index, leaf_count, sibs)` anchored against the committee-signed `R_h`. `MerkleTreeSoundness.md` **MT-4 (§4, inclusion-proof soundness)** is the exact theorem that licenses "a passing verification implies genuine membership under A2." **S-040 is CLOSED** — `leaf_count` is bound into the committed root via the root-wrapper hash `R_h := SHA256(0x02 ‖ be_u32(leaf_count) ‖ inner_root)` (`src/crypto/merkle.cpp::merkle_root_wrap`, `0x02` domain-separated from the `0x00` leaf / `0x01` inner prefixes); `merkle_verify` re-derives the inner root from the proof, re-applies the wrapper with the caller-supplied `leaf_count`, and compares to the committee-signed `R_h`, so a forged `leaf_count` (M ≠ N) yields a different wrapper hash and is rejected by the hash itself. The former MT-4 obligation to source `leaf_count` from the same anchor as `state_root` (`MerkleTreeSoundness.md` §6.2 / S-040) is thus enforced cryptographically here, not merely by anchoring both `R_h` and the proof's `leaf_count` to the same committee-signed `header[h]`. AH-1 inherits MT-4's `log₂(leaf_count) · 2⁻¹²⁸` per-attempt bound for the inclusion gate.

### 5.3 Cross-reference: LightClientThreatModel.md (T-L1..T-L4)

`account-history` is a *direct consumer* of the online per-invocation pipeline:

| `LightClientThreatModel.md` | `account-history` (this doc) | Relationship |
|---|---|---|
| T-L1 (genesis-anchored chain identity) | once at startup (AH-L3) | Identical `anchor_genesis`; amortized across all rows |
| T-L2 (head trust via committee sigs) | AH-1 Gate 1, per `header[h]` | Same `verify_block_sigs` primitive; applied per sampled height instead of to the head once; AH-4/AR-4 committee caveat applies (§6.2) |
| T-L3 (state-proof correctness) = MT-4 | AH-1 Gate 3, per state-proof@`h` | Same `verify_state_proof`/`merkle_verify`; anchored to `header[h].state_root` |
| §4.4.1 (race-window mitigation) | per-height anchoring to `header[h]` (§4.2 note) | Specialized: fixed-`h` target instead of moving-head |
| T-L4 (balance/nonce composition) | **AH-1** (per point) | AH-1 = T-L4 at a fixed historical height |
| L-4 (cleartext cross-check) | AH-L4 (per height, if performed) | Same value-hash binding |
| L-6 (fail-closed exit) | AH-L5 (per sampled height) | Same throw-on-inconsistency discipline, per height |
| (no online analog — single point) | **AH-2 (trajectory consistency)** | **New**: independent per-row anchoring under one genesis anchor |
| (no online analog) | **AH-3 (monotonicity ≠ soundness)** | **New**: the multi-point honesty theorem |
| (no online analog) | **AH-4 (sampling-gap honesty)** | **New**: temporal-sampling form of range honesty |

### 5.4 Cross-reference: LightClientArchiveSoundness.md (the live-query analog)

`account-history` is the **live-query analog** of the `export-headers` / `verify-archive` flow. The archive flow captures a header *range* at time `t1` and re-verifies it offline at `t2`; `account-history` queries an account-value *trajectory* live and verifies each point against the daemon at query time. The correspondence:

| `LightClientArchiveSoundness.md` (archive) | `account-history` (this doc) | Shared discipline |
|---|---|---|
| AR-1 (archive integrity = header-sequence attestation) | AH-1 (per-point soundness) | Both restrict T-L1 + T-L2 (+ MT-4 for AH-1) to a finite scope; AR-1 over a header range, AH-1 over a per-height account read |
| AR-3 (range-completeness honesty / `A_stale`) | **AH-4 (sampling-gap honesty)** | Both refuse to over-claim coverage: AR-3 "validity of contained headers, not range-completeness"; AH-4 "values at sampled heights, not between samples" |
| AR-4 (committee-rotation: static genesis seed `K_0`; fail-closed on cross-rotation) | **§6.2** (same `K_0` limitation, inherited) | Both seed the committee from genesis `initial_creators` only; cross-rotation ranges/heights need an operator-supplied extended committee |
| AR-2 (offline temporal soundness — pure function of bytes) | — (no analog; `account-history` is *live*, not offline) | `account-history` queries a live daemon per run; it does not freeze bytes for offline re-verification (a future `export-account-history` archive mode would, composing AH-1 with AR-2 the way §5.2 of the archive doc composes AR-1 + MT-4) |

The archive flow and `account-history` are siblings under the same trust model (single daemon, genesis-pinned, committee-signed, fail-closed); they differ on the *axis* of composition (archive = header range frozen for offline re-verification; `account-history` = account-value trajectory verified live). AH-4 is to the temporal-sampling axis what AR-3 is to the range axis.

---

## 6. Limitations

### 6.1 Sampling gaps (AH-4) — the trajectory is a sample, not a continuous audit (the big one)

Per AH-4: `account-history` proves the values AT the sampled heights `Σ = {H1, H1+S, …} ∩ [H1, H2]` only. Between consecutive samples (`S > 1`), balance can move arbitrarily (up and back) and the trajectory will not reveal it; nonce activity is bounded by the endpoint deltas but its balance effects are not sampled. This is **not** a soundness failure (every row is AH-1-sound) — it is the inherent resolution limit of sampling at stride `S`. An auditor must read the trajectory as "verified values at these specific heights," not "complete balance history." Finer resolution costs more verification (`S = 1` samples every block, at the full per-read `O(height)` cost ×sample-count); even `S = 1` reports post-block states and does not surface intra-block tx ordering (an apply-layer property, `MultiEventComposition.md` FA-Apply-15). This is the dominant residual and the temporal-sampling analog of `LightClientArchiveSoundness.md` AR-3.

### 6.2 Committee-rotation within `[H1, H2]` (inherited AR-4 / `LightClientThreatModel.md` §6.5)

The per-height committee-sig verification (AH-1 Gate 1) uses the committee map seeded from genesis `initial_creators` via `build_genesis_committee` (`light/trustless_read.cpp:46-53`) — the **static** `K_0`. If the active committee **rotates** within `[H1, H2]` via on-chain `REGISTER` / `DEREGISTER`, per-height verification must use the committee valid AT that height. The honest status:

- **`read_account_trustless` (and hence `account-history` built on it) tracks only `K_0`.** `verify_chain_walk` builds `committee_json` once from the genesis seed and never mutates it across the walk (`light/trustless_read.cpp:115-120`, invoked once; the per-block `verify_block_sigs` call uses the same object every iteration). `verify_block_sigs` demands every entry of a header's `creators` be in `K_0` (`light/verify.cpp:268-273`: `"creator '<domain>' is not in the supplied committee"`).
- **Consequence (mirrors AR-4 exactly).** For a sampled `header[h]` produced by a committee containing a *post-genesis-registered* creator not in `K_0`, AH-1 Gate 1 **fails closed** — `verify_block_sigs` rejects, the per-height read throws (AH-L5), and `account-history` exits non-zero with the membership diagnostic. No under-verified row is emitted (a *safe* failure mode), but the trajectory cannot span a cross-rotation height under the default seed.
- **Honest flag.** `account-history` is therefore **sound out-of-the-box only for committee-stable ranges** (every sampled `header[h]` produced by a `creators ⊆ K_0` committee — the common case for short audit windows and permissioned chains with a fixed genesis committee). For **cross-rotation ranges**, the operator must supply an **extended committee** that is a superset of every creator encountered across `Σ`, fed to `account-history` the same way the online pipeline / archive flow require (`LightClientThreatModel.md` §6.5 + F-1; `LightClientArchiveSoundness.md` AR-4). **Confirmed against the shipped binary:** `account-history` (D3 R40) builds the committee from the genesis seed only (`build_genesis_committee(genesis)` at `light/account_history.cpp`) and does **not** expose a `--committee <file>` override — so a cross-rotation range fails closed today. AH-1's Gate 1 holds for whatever committee the run is given, provided it is a superset of every creator encountered; a future stateful-sync extension tracking `REGISTER` / `DEREGISTER` from the chain (or a `--committee` override) would close it.

### 6.3 Per-height anchoring to genesis must be established (AH-2 conditional)

Per AH-2's note: each `header[h]` must be transitively `prev_hash`-linked to the genesis-anchored block 0 (full-walk or anchored-segment construction), so that `R_h` is provably a root of the operator's pinned chain. An implementation that verified `header[h]`'s committee sigs *in isolation* — without linking it to genesis — would suffer the `LightClientArchiveSoundness.md` AR-3(ii) "floating slice" defect: a committee-subset could sign a forked/alternative header at index `h`, and the row would be "committee-signed by *some* `K_0` subset" but not genesis-anchored. AH-2 holds **conditional on the linkage**. **Confirmed against the shipped binary:** `account-history` (D3 R40) establishes the linkage via `IncrementalChainWalker::advance_to` (`light/account_history.cpp`), which advances a single monotonic `prev_hash` frontier through `verify_headers` from the genesis-anchored block 0, threading each page's last verified `block_hash` as the next page's anchor. Because sampled heights increase monotonically the chain from genesis is walked once across the whole range (each header fetched at most once for the chain check, rather than re-walked from index 0 per sample); by the time height `h` is sampled the verified frontier already covers `[0, h]`, so each `header[h]` is anchored to the pinned genesis — not an isolated committee-signed header. The AH-2 conditional is therefore discharged in the shipped code; it is stated explicit here rather than assumed.

### 6.4 Per-height state-proof availability is a daemon capability (flag for D3)

Per §1's honesty note: the chain's `Chain::state_proof` (`src/chain/chain.cpp:435-462`) builds a proof from the *current* live state, with no height parameter. A trustless historical read at `h < head` depends on the daemon being able to serve a state-proof bound to height `h` (an archival/historical-state daemon capability). AH-1 holds for *whatever* `(header[h], state-proof@h)` pair the daemon serves — it proves an *emitted* row is anchored at `h`; it does **not** assume the daemon *can* serve every requested `h`. A daemon unable to prove a requested height fails closed (no row, diagnostic) per AH-L5. Whether D3's `account-history` requires an archival daemon, restricts `Σ` to provable heights, or reads only where the current-state proof is the correct historical answer is D3's implementation decision; the soundness claim is robust to all three (it conditions on emission). This mirrors the availability-vs-soundness split of `LightClientThreatModel.md` F-4 + `LightClientArchiveSoundness.md` AR-3.

### 6.5 Single-daemon — no multi-peer cross-check

`account-history` talks to ONE daemon (`LightClientThreatModel.md` §6.2). It does not cross-check the trajectory against a second daemon. A daemon that *withholds* a sampled height (refuses the header or state-proof) is detected only as a per-height fail-closed exit (AH-L5), not by comparison against an independent source; a daemon that serves a *consistent stale slice* (genuine data from an old chain prefix) is detected only if a monotonicity violation surfaces (AH-3 tripwire) or if the operator independently knows the expected head. Completeness/freshness against a withholding or stale daemon is the operator's cross-check obligation (run a second invocation against a different port and diff, per `LightClientThreatModel.md` §6.2), not an automatic check. Ties to AH-4's auditor-obligation framing.

### 6.6 No persistence, transport, or auth claims

Inherited from `LightClientThreatModel.md` §6.1 (no persistence — each run re-anchors from genesis and re-walks; an `account-history` run over many samples pays the walk cost, mitigated by D3's in-memory single-walk-to-`H2` optimization per §6.3), §6.6 (no RPC auth — operator supplies HMAC out-of-band if the daemon requires it), §6.7 (plaintext transport — operator wraps in TLS/tunnel; an active MITM is covered by `A_history` for soundness). None affect the per-point soundness claim (every byte is verified per sampled height).

---

## 7. Cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem / artifact | Function / location | Role |
|---|---|---|
| AH-1 / AH-2 (composition) | `run_account_history` | `light/account_history.cpp` (D3 R40) | Trajectory assembly: anchors genesis once, head Merkle-read via `read_account_trustless`, then per sampled height `verify_header_state_root_at` (committee-signed `state_root`) + `IncrementalChainWalker::advance_to` (incremental genesis linkage — single monotonic pass across the range). Fail-closed per height (AH-L5). |
| AH-1 (per-height read template) | `read_account_trustless` | `light/trustless_read.cpp:439-599` | The single-point read AH-1 specializes to a fixed historical `h` (AH-L1). |
| AH-1 Gate 1 / §6.2 (T-L2) | `verify_block_sigs` | `light/verify.cpp:235-328` | `creators ⊆ K_0` membership + Ed25519 threshold verify over `light_compute_block_digest`; per `header[h]`. |
| AH-1 Gate 1 (digest binding) | `light_compute_block_digest` | `light/verify.cpp:57-92` | Byte-for-byte copy of `producer.cpp::compute_block_digest`; binds `header[h]` content (incl. fields chaining to `state_root`) to the signed digest. |
| AH-1 Gate 2 / AH-2 (continuity) | `verify_headers` | `light/verify.cpp:135-233` | prev_hash linkage of `header[h]` to the genesis-anchored prefix. |
| AH-1 Gate 2 / AH-L3 (genesis anchor) | `anchor_genesis` | `light/trustless_read.cpp:55-82` | Once at startup; `compute_genesis_hash(genesis_O)` vs daemon block 0. |
| AH-1 Gate 3 (MT-4 / T-L3) | `verify_state_proof` → `merkle_verify` | `light/verify.cpp:330-396` → `src/crypto/merkle.cpp:113-141` | State-proof verified against committee-signed `R_h := header[h].state_root`. |
| AH-1 (S-042 committee-binding) | `committee_bound_state_root` | `light/trustless_read.cpp:335-437` | Binds the proof root to a committee-signed successor header (`successor.prev_hash == recomputed anchor block_hash`, `:424-432`); the head fails closed unless `--wait`. |
| AH-L4 (cleartext cross-check) | value-hash recompute | `light/trustless_read.cpp:573-593` | `SHA256(balance_be ‖ nonce_be) == proof.value_hash`, per height (if performed). |
| §6.2 (committee seed) | `build_genesis_committee` | `light/trustless_read.cpp:46-53` | Seeds `K_0` from genesis `initial_creators` only — the static-committee fact §6.2 turns on. |
| §6.4 (state-proof producer) | `Chain::state_proof` | `src/chain/chain.cpp:435-462` | Builds proof from *current* live state (no height param); the daemon-capability honesty note. |
| AH-3 (nonce monotonicity) | nonce-gate invariant | `NonceMonotonicity.md` FA-Apply-3 (T-N1, T-N4, T-N5) | The chain-side monotonicity AH-3 cross-checks against; the necessary-not-sufficient argument. |

Companion proofs:

| Document | Relationship |
|---|---|
| [LightClientThreatModel.md](LightClientThreatModel.md) | Base: T-L1 (genesis anchor) + T-L2 (committee-sig) + T-L3 (state-proof) + T-L4 (balance/nonce composition) + L-4 (cleartext cross-check) + L-6 (fail-closed). AH-1 = T-L4 at a fixed historical height; §6.2 = T-L2's committee-evolution caveat; AH-4 = temporal-sampling form of F-4. |
| [MerkleTreeSoundness.md](MerkleTreeSoundness.md) | MT-4 (§4, inclusion-proof soundness) is the cryptographic core of AH-1 Gate 3 (the per-height state-proof step). **S-040 CLOSED** — `leaf_count` is bound into the committed root via the root-wrapper hash `R_h := SHA256(0x02 ‖ be_u32(leaf_count) ‖ inner_root)` (`src/crypto/merkle.cpp::merkle_root_wrap`); `merkle_verify` re-applies the wrapper with the caller-supplied `leaf_count` and compares to `R_h`, so a forged count yields a different wrapper hash and is rejected by the hash. The former §6.2 single-envelope-sourcing obligation (anchor both `R_h` and `leaf_count` to the same committee-signed `header[h]`) is now enforced cryptographically, not just as a caller guideline. |
| [LightClientArchiveSoundness.md](LightClientArchiveSoundness.md) | The archive sibling — `account-history` is the *live-query* analog of `export-headers` / `verify-archive`. AH-1 ↔ AR-1 (finite-scope restriction of T-L1 + T-L2); AH-4 ↔ AR-3 (coverage honesty); §6.2 ↔ AR-4 (static `K_0` committee, fail-closed on cross-rotation). |
| [NonceMonotonicity.md](NonceMonotonicity.md) (FA-Apply-3) | The chain-side nonce-monotonicity invariant AH-3 cross-checks against (T-N5 monotonic accumulation across blocks). AH-3's necessary direction rests on it. |
| [Safety.md](Safety.md) §7 | FA1 per-block sig primitive each per-height read inherits; "adds no new chain-level invariant" composition posture. |
| [S033StateRootNamespaceCoverage.md](S033StateRootNamespaceCoverage.md) | The `state_root` binding (`a:`-namespace leaf encoding `SHA256(balance_u64 ‖ next_nonce_u64)`) each per-height read anchors against. |

Integration tests:

| Test script | Coverage |
|---|---|
| `tools/test_light_account_history.sh` (D3 R40) | AH-1 (each sampled row verifies; daemon lies about balance/nonce at one height → that row fails, exit non-zero + diagnostic pointing at the height), AH-2 (rows independently anchored; a proof served for the wrong height → reject), AH-3 (monotonicity-violation surfaced as daemon-inconsistency error; AND a monotonic-but-forged history still rejected by AH-1's per-point gate, demonstrating monotonicity is not the guarantee), AH-4 (sampling-gap documented: a balance round-trip within a `--step` gap is not surfaced — asserted as expected behavior, not a bug), and the committee-stable-vs-cross-rotation distinction of §6.2. Authored by sibling D3, R40 (landing in parallel with this proof). |

---

## 8. Status

- **Spec.** Complete (this document).
- **Implementation.** Shipped (sibling D3, R40). `light/account_history.cpp` — `run_account_history` (entry / trajectory assembly), `verify_header_state_root_at` (per-height committee-signed `state_root`), `IncrementalChainWalker::advance_to` (incremental genesis linkage — single monotonic prev_hash pass across the sampled range); test `tools/test_light_account_history.sh`. The shipped flow Merkle-verifies balance/nonce at the head only and committee-verifies the `state_root` per sampled height (the daemon's `state_proof`/`account` RPCs are head-only; rows carry `balance_proven_at_height` + `balance_merkle_verified`); the code is height-generic and auto-upgrades if the RPC gains a height parameter. AH-1 conditions soundness on row *emission*, so it holds unchanged for this head-only-Merkle / per-height-`state_root` shape (see §6.4).
- **Proof.** Complete: AH-1 (per-point soundness), AH-2 (trajectory consistency — independent per-row anchoring), AH-3 (nonce monotonicity is a consistency cross-check, NOT a soundness source — the multi-point honesty theorem), AH-4 (sampling-gap honesty — the trajectory is a verified sample, not a continuous audit).
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA, §2.2), A2 (SHA-256 collision resistance, §2.1), A3 (SHA-256 preimage resistance, §2.1, in T-L1's genesis-anchor Case 2 inherited via AH-1 Gate 2). Per `Preliminaries.md §2.0`. No new primitive.
- **Adversary model.** `A_history` (malicious daemon serving a forged trajectory: forged value (a), stale/forked proof (b), unsigned `state_root` (c), and the cross-height confusion attack — all defeated by AH-1 + AH-2). Out of scope: `A_crypto`, `A_local`, `A_net` (covered by `A_history` for soundness), `A_genesis`.
- **Composes with.** `LightClientThreatModel.md` (T-L1 + T-L2 + T-L3 + T-L4 + L-4 + L-6 — AH-1 is T-L4 at a fixed historical height); `MerkleTreeSoundness.md` MT-4 (the per-height state-proof inclusion gate); `LightClientArchiveSoundness.md` (the live-query analog of the archive flow — AH-1 ↔ AR-1, AH-4 ↔ AR-3, §6.2 ↔ AR-4); `NonceMonotonicity.md` FA-Apply-3 (the monotonicity invariant AH-3 cross-checks against); `Safety.md` §7 (FA1 per-block primitive); `S033StateRootNamespaceCoverage.md` (the `state_root` binding).
- **AH-3 monotonicity finding (headline honesty point).** Nonce monotonicity across increasing heights is **necessary but not sufficient** for trajectory soundness. A daemon serving an internally-consistent forged history could preserve monotonicity (a coherent fake nonce ladder), so monotonicity cannot *establish* soundness — it is a **cross-check** (a defense-in-depth tripwire that, under sound A1+A2 operation, must never fire, since AH-1 already guarantees the necessary direction holds on a genuine chain). The **real guarantee is AH-1's per-point committee-sig anchoring**: each row is bound to its own `header[h]`'s committee-signed `state_root`, independent of the nonce sequence's shape. Balance has no monotonicity property at all, reinforcing that per-point anchoring — not sequence-shape heuristics — is the universal guarantee. An auditor MUST NOT downgrade from per-point verification to "the numbers look monotonic."
- **AH-4 / committee-rotation honesty note.** (i) **Sampling gaps (AH-4):** the trajectory proves the values AT the sampled heights only; balance can move up-and-back within a `--step` gap unobserved. The trajectory is a verified *sample at stride `S`*, not a continuous audit — the temporal-sampling analog of `LightClientArchiveSoundness.md` AR-3's range honesty. Finer resolution costs proportionally more verification; even `S = 1` reports post-block states (no intra-block ordering). (ii) **Committee rotation (§6.2):** `read_account_trustless` — and hence `account-history` built on it — tracks only the **static genesis committee `K_0`** (`build_genesis_committee` seeds from `initial_creators` only; the committee map is built once and never mutated across the walk). Per-height verification of a `header[h]` produced by a post-genesis-registered committee **fails closed** (membership rejection → throw → non-zero exit; no under-verified row), so `account-history` is **sound out-of-the-box only for committee-stable ranges**; cross-rotation ranges require an operator-supplied extended committee (superset of every creator across `Σ`). Inherited from `LightClientThreatModel.md` §6.5 + F-1 and `LightClientArchiveSoundness.md` AR-4; closed by a future stateful-sync / committee-rotation-tracking extension. Flagged honestly rather than assumed away.
- **Concrete-security bound.** AH-1 per sampled height: `Pr[A_history wins AH-1 at h] ≤ K · 2⁻¹²⁸ + log₂(leaf_count) · 2⁻¹²⁸ + 2⁻¹²⁸`; for `K ≤ 16`, `leaf_count ≤ 2⁶⁴`, `≤ 2⁻¹²¹`. Union over `|Σ|` sampled heights (plus the one-time T-L1 anchor and the per-height prev_hash linkage cost): `≤ |Σ| · (vc.height + 2) · K · 2⁻¹²⁸ + 2⁻¹²⁸`; for practical chains (`|Σ| ≤ 2²⁰`, `vc.height ≤ 2³²`, `K ≤ 16`), `≤ 2⁻⁶⁰`, operationally negligible. AH-2 is structural (independent per-row anchoring; the cross-height confusion attack reduces to an A2 collision, `≤ log₂(leaf_count) · 2⁻¹²⁸`). AH-3 / AH-4 are honesty/scope theorems, not cryptographic breaks — the "bound" against a monotonicity-preserving forgery is AH-1's per-point gate (the forgery is caught cryptographically regardless of monotonicity), and the "bound" against inter-sample tampering is "1" (it is invisible to the sample by definition — a scope limitation, not a soundness failure). Under Grover (PQ), AH-1's `2⁻¹²⁸` terms degrade to `2⁻⁶⁴` (operationally secure; PQ-signature migration is the long-term path per `LightClientThreatModel.md` §9).

---
