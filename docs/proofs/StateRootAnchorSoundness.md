# StateRootAnchorSoundness — per-height committee-verified `state_root` anchor (`determ-light verify-state-root`)

This document proves the soundness of the `determ-light verify-state-root --height H` subcommand (sibling F3, landing this round): the per-height primitive that establishes the **committee-verified `state_root` at a single height `H`**, bound to the operator's genesis-pinned chain. It is the sub-result that `balance-trustless` / `account-history` / `verify-state-proof`'s root-anchor all consume internally (the existing in-tree composite `read_account_trustless` at `light/trustless_read.cpp:439-599` performs the same anchoring inline; F3 factors it out as a standalone command, mirroring `verify_header_state_root_at` + the `IncrementalChainWalker` pattern).

The proof exists because the per-height anchor is the **single load-bearing trust hinge** for every trust-minimized account read: a light client that holds a wrong `state_root` for `H` will faithfully verify a Merkle inclusion proof (MT-4) against the wrong root and report a wrong-but-internally-consistent balance. `verify-state-root` is therefore the primitive whose soundness everything downstream rests on, and it deserves a standalone treatment rather than being buried inside `T-L4`'s composite flow.

**A correction to the brief's stated binding (load-bearing — read carefully).** The F6 task brief asserts that `state_root` "is appended to the digest the K-of-K committee signs" via `compute_block_digest`. **This is not what the source does**, and the proof below uses the *actual* mechanism. `state_root` is bound into `Block::signing_bytes()` (and hence the `block_hash`), **not** into `compute_block_digest()` (what the committee Ed25519-signs). The two are different functions:

- `src/node/producer.cpp::compute_block_digest` (lines 608-693; common-case prefix 610-620) appends `index, prev_hash, tx_root, delay_seed, consensus_mode, bft_proposer, creators, creator_tx_lists, creator_ed_sigs, creator_dh_inputs`. **`state_root` is absent.** The mirror `light/verify.cpp::light_compute_block_digest` (lines 57-92) carries an explicit comment: *"producer.cpp's compute_block_digest does NOT include … or state_root."*
- `src/chain/block.cpp::Block::signing_bytes` (lines 336-350) appends `state_root` **when non-zero** (the S-033 zero-skip backward-compat shim). `block_hash = compute_hash() = SHA256(signing_bytes ‖ creator_block_sigs)` (block.cpp:356-364).

The committee signature therefore binds `state_root` **transitively forward**, not directly: `state_root(H) ∈ signing_bytes(H) ∈ block_hash(H)`, and `block_hash(H)` is the `prev_hash` of block `H+1`, and `prev_hash` **is** in `compute_block_digest(H+1)`. So a committee signature on block `H+1` certifies `H`'s `state_root`. This is the exact mechanism block.cpp:341-344 documents (*"The prev_hash chain then forward-binds the commitment so any future block's verification transitively authenticates all prior state roots"*) and that `MerkleTreeSoundness.md §5.4` summarizes as the chain of trust *"committee signatures (A1) → block_hash → state_root (when non-zero) → [MT-4] → leaf membership."* §3 and §4 below state this precisely, and §3.4 documents the residual per-height subtlety honestly: verifying block `H`'s own committee signatures alone does **not** certify `H`'s `state_root` — only a signed successor (or the operator's `--height H` being the head whose root the operator anchors with the forward link) closes the binding.

**Canonical assumption labels.** Per `Preliminaries.md §2.0`: **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision resistance (§2.1), **A3** = SHA-256 preimage / second-preimage (§2.1), **A4** = CSPRNG uniform sampling (§2.3). FA3 denotes `SelectiveAbort.md` and is **not** used here for SHA-256.

**Companion documents.** `LightClientThreatModel.md` (T-L1 genesis anchor, T-L2 committee-sig trust, T-L3 state-proof correctness, T-L4 balance/nonce composition — this document factors out the "committee-verified `state_root` at `H`" sub-result those theorems use); `MerkleTreeSoundness.md` (MT-4 inclusion-proof soundness — the consumer of the root this primitive anchors); `S033StateRootNamespaceCoverage.md` (T-1..T-5 — the 10-namespace coverage completeness of the root being anchored, and T-4's producer/receiver symmetry); `BlockchainStateIntegrity.md` (the S-021 + S-033 + S-038 four-surface composition; §2.3 the `block_hash`-binds-`state_root` mechanism); `Preliminaries.md` (F0) §2.0 (assumption labels), §2.1 (A2/A3), §2.2 (A1); `Safety.md` (FA1) §7 (the light-client safety composition T-1.2); `LightClientArchiveSoundness.md` (AR-1..AR-4 — the offline sibling sharing the same genesis-anchor + committee-sig walls); `AccountHistorySoundness.md` (sibling, parallel this round — AH-1 per-point root consumes SR-1); `TxInclusionProofSoundness.md` (sibling, parallel — the `tx_root` analog of this `state_root` anchor; `tx_root` IS in the digest directly, `state_root` is the transitively-forward-bound sibling field); `docs/SECURITY.md §S-033` + §S-038 (the closures that make the anchored root real); `docs/PROTOCOL.md §4.1` (`signing_bytes` field list) + §4.3 (`block_digest` exclusion list) + §4.1.1 (namespace table).

> **Source-availability note (concretized — F3 landed R40; binding mechanized post-R40).** F3's `light/verify_state_root.cpp` (the `verify_state_root_at` verifier at `:101`) + `light/main.cpp::cmd_verify_state_root` (`:569`, dispatched at `:1039`) + `tools/test_light_verify_state_root.sh` (7 PASS) are now in-tree. The *binding* this proof rests on (§3) is grounded in code that IS present: `producer.cpp::compute_block_digest`, `block.cpp::signing_bytes` / `compute_hash`, `light/verify.cpp::light_compute_block_digest` / `verify_block_sigs` / `verify_headers`. **Crucially, the recompute-and-successor binding §3.3 specifies is now IMPLEMENTED** — `light/trustless_read.cpp::committee_bound_state_root` (`:335-437`) fetches the full block via the `"block"` RPC, recomputes `block_hash`, and binds `state_root` to the committee-signed successor's `prev_hash`; ALL trust-minimized state readers (`read_account_trustless`, `verify_state_root_at`, and the stake / supply / account-history / receipt-inclusion / merge-state / param-change / registrant / dapp-registration / account verifiers in `light/main.cpp`) route their reported `state_root` through it. Earlier revisions of this proof noted this recompute was ABSENT (a residual / honest-daemon caveat); it is now PRESENT and fails closed at the head (no signed successor). The fix is entirely light-client-side; the consensus digest / `signing_bytes` are UNCHANGED. See `docs/SECURITY.md §S-042`.

---

## 1. Scope

`determ-light verify-state-root --height H` is a per-invocation composite verifier whose single output is the **committee-verified `state_root` at height `H`** (a 64-hex string), or a fail-closed non-zero exit. It composes, in order:

1. **Genesis anchor.** Recompute `compute_genesis_hash(genesis_O)` locally from the operator's `--genesis <file>`; fetch the daemon's block 0 via `rpc_headers from=0 count=1`; require byte-equality (`anchor_genesis`, `light/trustless_read.cpp:55-82`). This is `T-L1`.
2. **Fetch header[H].** Retrieve the header at index `H` from the daemon (`rpc_headers from=H count=1`).
3. **Verify the prev_hash chain genesis → H.** Walk headers `0 … H` (in pages of 256 per the daemon's `HEADERS_PAGE_MAX`), requiring `headers[i].prev_hash == headers[i-1].block_hash` (`verify_headers`, `light/verify.cpp:135-233`), so `H` is bound to the genesis-pinned block 0 rather than being an isolated header. This is the genesis-binding that §4's `SR-2` rests on.
4. **Verify header[H]'s committee signatures.** Recompute `light_compute_block_digest(header[H])` and Ed25519-verify the `K`-of-`K` (MD mode) or `ceil(2K/3)`-of-`k_bft` (BFT mode) `creator_block_sigs` against the genesis-seeded committee `K_0` (`verify_block_sigs`, `light/verify.cpp:235-328`).
5. **Report the committee-verified `state_root`.** Emit `header[H].state_root` (the `state_root_hex` field of the `VerifyResult`, set only when non-zero per `verify.cpp:323-326`), bound to `H` by §4's theorems.

The command is a *read-only verifier*: it signs nothing, submits nothing, and (unlike `verify-and-submit`) has no keyfile surface. Its entire output is "here is the `state_root` committed at `H`, and here is why you can trust it without trusting the daemon."

**Relationship to the existing in-tree code.** The in-tree composite `read_account_trustless` (`light/trustless_read.cpp:439-599`) already performs steps 1-4 inline as part of its balance/nonce read, anchoring the proof's claimed root to a committee-signed header via the S-042 committee-binding (`committee_bound_state_root`, `light/trustless_read.cpp:335-437`). F3's `verify-state-root` factors steps 1-5 out as a standalone command so that (a) `account-history` can call it per sampled height (the `verify_header_state_root_at` helper), and (b) operators can obtain a trust-anchored root to feed `verify-state-proof --state-root <R>` directly. The soundness argument below is the standalone form of the sub-lemma `T-L4` uses without separately naming.

**Out of scope (inherited from `LightClientThreatModel.md §2.2 / §6`).**

- `A_crypto` (SHA-256 collision finder / Ed25519 forger). The primitive's defenses rest on A1 + A2 being infeasible.
- `A_local` (operator's machine compromise) and `A_genesis` (tampered `--genesis` on disk). The genesis anchor is *the* trust root; a compromised anchor is out of scope.
- `A_net` (transport MITM). The operator wraps the RPC in TLS / tunnel if exposed.
- Multi-peer redundancy, persistence across invocations, the committee-rotation tracking gap (§6.2 here; §6.5 + F-1 in `LightClientThreatModel.md`).

---

## 2. Threat model

### 2.1 Adversary `A_root`

`A_root` is the standard malicious-daemon `A_daemon` of `LightClientThreatModel.md §2.1`, specialized to the per-height anchor: a daemon under full adversary control that responds to `verify-state-root`'s `rpc_headers` requests with arbitrary JSON. Its goal is to make `verify-state-root --height H` report a `state_root` value `R_A` that is **not** the genuine committee-committed `state_root` of the operator's pinned chain at height `H`, without the command throwing. Three concrete attack shapes:

- **(a) Fabricated root at `H`.** Serve header[H] with a `state_root` field `R_A ≠ R_T` (the true root at `H`), keeping all other fields genuine, so the daemon hopes the committee-sig check still passes (it would, naively, since the digest excludes `state_root` — see §3.4).
- **(b) Real root from a different / forked height.** Serve a genuine committee-signed header from height `H' ≠ H` (or from a fork) whose `state_root` is `R_{H'}`, and pass it off as `H`'s root.
- **(c) Isolated committee-signed forked header.** Serve a header at index `H` that is genuinely signed by some subset of `K_0` but is **not** part of the operator's pinned chain — a "floating slice" the daemon forked off, with a `state_root` reflecting an alternative state.

### 2.2 Honest auditor

An honest invocation: loads a genuine operator-trusted `genesis.json`; runs the released `determ-light.exe` (F3) unmodified; does not bypass verification by reading `rpc_account` / a raw header field directly. The security claim (§4) is that under `A_root`, such an invocation either reports the genuine committee-committed `state_root` at `H` or fail-closed exits — never a daemon-asserted root masquerading as committee-verified.

### 2.3 Out of scope

As §1: `A_crypto`, `A_local`, `A_net`, `A_genesis`, and the orthogonal availability attacks (daemon stalls / truncates — `LightClientThreatModel.md` F-4). These are availability, not soundness, and surface as fail-closed exit.

---

## 3. The binding (load-bearing)

This section states precisely, from the source, *what binds `state_root` to the committee* and *what does not*. It is the foundation for every theorem in §4. Get this wrong and the whole proof is wrong; the brief got it wrong, so it is stated here in full.

### 3.1 What the committee signs: `compute_block_digest` (excludes `state_root`)

Each committee member's Phase-2 Ed25519 signature in `creator_block_sigs[i]` is over `compute_block_digest(B)` (`src/node/producer.cpp:608-693`; common-case prefix 610-620):

```
digest(B) = SHA256(
    B.index ‖ B.prev_hash ‖ B.tx_root ‖ B.delay_seed
  ‖ u8(B.consensus_mode) ‖ B.bft_proposer
  ‖ (B.creators[i])_i
  ‖ (B.creator_tx_lists[i][j])_{i,j}
  ‖ (B.creator_ed_sigs[i])_i
  ‖ (B.creator_dh_inputs[i])_i )
```

`B.state_root` does **not** appear. The light client recomputes the digest byte-for-byte in `light/verify.cpp::light_compute_block_digest`, which carries the explicit invariant comment:

> *"producer.cpp's compute_block_digest does NOT include transactions, cross_shard_receipts, initial_state, or state_root. It binds the v1 core (per-creator Phase-1 commits + index/prev_hash/tx_root/delay_seed + consensus_mode/bft_proposer), the conditional F2 view-root appendages (inbound/eq/abort — which the light client omits and fail-closes on, since they need the rpc_headers-stripped collections), and partner_subset_hash when non-zero (S-030-D2; survives the header strip, so the light client binds it too)."*

For this proof the load-bearing fact is unchanged: `state_root` is excluded from the digest (so the producer can populate it post-signature — §3.1 below). The partner_subset_hash binding (commit `8585a50`) is orthogonal and does not touch the state_root argument.

The exclusion is deliberate and load-bearing for S-038: because the digest excludes `state_root`, the producer can populate `body.state_root` (via the tentative-chain dry-run, `S033StateRootNamespaceCoverage.md §2.3`) *after* the committee has gathered its signatures over the digest, without invalidating those signatures. The regression `determ test-domain-separation` (per `S033StateRootNamespaceCoverage.md §8`, assertion family) pins exactly this: *"state_root mutation leaves block_digest unchanged AND changes Block::compute_hash."*

### 3.2 What `state_root` IS bound into: `signing_bytes` / `block_hash` (when non-zero)

`Block::signing_bytes()` (`src/chain/block.cpp:235-354`) appends `state_root` **only when non-zero** (the S-033 zero-skip shim, lines 336-350):

```cpp
// S-033 / v2.1: bind state_root into the block hash chain ONLY when non-zero.
{
    Hash zero{};
    if (state_root != zero) {
        b.append(state_root);
    }
}
```

and `block_hash := Block::compute_hash()` is `SHA256(signing_bytes ‖ creator_block_sigs[0..k))` (block.cpp:356-364). So `state_root(B) ∈ signing_bytes(B) ∈ block_hash(B)` whenever `state_root(B) ≠ 0`. The same `non-zero` guard governs `partner_subset_hash` (block.cpp:329-334) and is the WireFormatBackwardCompat C-2 pattern: a pre-S-033 block with `state_root == 0` contributes nothing to `signing_bytes`, preserving byte-identical hashes with legacy chains.

### 3.3 The transitive-forward link: `block_hash(H) = prev_hash(H+1) ∈ digest(H+1)`

`prev_hash` **is** in `compute_block_digest` (§3.1, the second field). And by the chain-continuity invariant (`verify_headers`, `light/verify.cpp:211-223`), `prev_hash(H+1) == block_hash(H)` on the genesis-pinned chain. Composing §3.2 + §3.1:

```
state_root(H)  ∈  signing_bytes(H)  ∈  block_hash(H)  =  prev_hash(H+1)  ∈  digest(H+1)
                                                                            └── committee-signed (A1)
```

Therefore **a `K`-of-`K` committee signature on block `H+1` certifies `H`'s `state_root`** (when `state_root(H) ≠ 0`): forging an alternative `state_root'(H) ≠ state_root(H)` while keeping `H+1`'s signed `prev_hash` requires either a `signing_bytes` collision at `H` (so `block_hash(H)` is unchanged despite the changed `state_root` — A2) or forging `H+1`'s committee signatures over a different `prev_hash` (A1). This is exactly block.cpp:341-344's *"the prev_hash chain then forward-binds the commitment so any future block's verification transitively authenticates all prior state roots — turning the chain into a verifiable state log,"* and `MerkleTreeSoundness.md §5.4`'s chain of trust.

### 3.4 The per-height subtlety (honest statement)

A direct corollary of §3.1: **verifying block `H`'s OWN committee signatures does not, by itself, certify `H`'s `state_root`.** Because `digest(H)` excludes `state_root(H)`, a daemon can take a genuine header[H], overwrite its `state_root` field with `R_A`, leave every digest-covered field intact, replay the genuine `creator_block_sigs`, and `verify_block_sigs(header[H], K_0)` will return `ok=true` with `state_root_hex = R_A` — the attack shape §2.1(a).

What closes the gap is **the forward link of §3.3 plus the prev_hash walk of §1 step 3**, evaluated as follows. Two regimes, mirroring the in-tree `read_account_trustless` logic at the S-042 committee-binding (`committee_bound_state_root`, `trustless_read.cpp:335-437`):

- **`H` is interior (a signed successor exists).** The operator's pinned chain has a committee-signed block at `H+1` whose `prev_hash` the walk (§1 step 3) ties to `block_hash(H)`. The tampered `state_root'(H) = R_A` changes the *true* `block_hash(H)` (§3.2), which must then either (i) mismatch `prev_hash(H+1)` — caught by the chain-continuity check at the `H → H+1` link — or (ii) match it only via a `signing_bytes` collision (A2). The daemon cannot have it both ways: a forged `R_A` that keeps `block_hash(H)` fixed is an A2 break; a forged `R_A` that changes `block_hash(H)` breaks the `H+1` prev_hash link (which is committee-signed by A1). See §4.1's reduction.

  **Mechanized binding — recompute + successor (IMPLEMENTED).** The shipped light client no longer trusts the daemon-*reported* `block_hash` field for the `state_root` binding. The helper `light/trustless_read.cpp::committee_bound_state_root` (`:335-437`) closes the gap concretely: it (1) fetches the **FULL** block at `H` via the `"block"` RPC (`Node::rpc_block`, `node.cpp:2623-2627`, which returns the complete unstripped body so `signing_bytes`/`compute_hash` are recomputable — the stripped `"headers"` RPC cannot give this), (2) recomputes `b.compute_hash()` locally (binding `state_root`, since it is inside `signing_bytes` per §3.2), (3) fetches the committee-signed SUCCESSOR header at `H+1` and verifies its committee sigs (`verify_block_sigs`, MD then BFT), (4) requires `successor.prev_hash == recomputed block_hash(H)` byte-for-byte, and (5) returns the anchor's `state_root` (empty if zero) ONLY after that match. A daemon that swapped `state_root(H) = R_A` produces a recomputed `block_hash(H)` that no longer matches the `prev_hash` the committee signed in `digest(H+1)` — so step (4) throws (`trustless_read.cpp:424-432`). This makes the §3.3 forward-link binding *mechanical*, not merely *latent*: pre-helper, soundness held under A1 because the next block's signed digest pinned the prior `block_hash` regardless of the reported value, but the recompute step now also catches a self-inconsistent `(state_root, block_hash)` header at `H` directly rather than relying solely on the reported field surviving the `H → H+1` link.

- **`H` is the head (no signed successor yet).** There is no block `H+1` to forward-bind `H`'s `state_root`, so `committee_bound_state_root` **fails closed**: the successor fetch at `H+1` returns no header and the helper throws *"state_root at index H has NO committee-signed successor yet (it is the chain head) — refusing to report an unbound head state_root; retry once the chain advances one block"* (`trustless_read.cpp:388-401`). The light client therefore never reports the head's `state_root` as committee-verified until a successor exists. `verify_state_root_at` (`light/verify_state_root.cpp:181-205`) routes a non-genesis `H` through the helper and, on a head-height query, returns `ok=false` + the diagnostic rather than surfacing an unbound root. §4.1 states `SR-1` for the interior regime (the strong, signed-successor case) and §6.3 documents the head-regime fail-closed boundary.

### 3.5 S-033-active vs pre-S-033 regimes

- **S-033-active.** Some block has emitted a non-zero `state_root` (post-S-038 producer, per `S033StateRootNamespaceCoverage.md §2.3`). By the "once-emitted, always-emitted" determinism (`block.hpp:466-468`), every subsequent block carries a non-zero `state_root`. In this regime §3.2-§3.3's binding is live and `SR-1`/`SR-2`/`SR-3` give a *strong* committee-anchored root.
- **Pre-S-033 (or feature-inactive).** Every header carries `state_root == 0` (empty/absent in JSON). Then §3.2's `non-zero` guard means `state_root` contributes *nothing* to `signing_bytes`, so there is no committed state to anchor: the binding is **vacuous**. `verify_block_sigs` still committee-verifies the header (digest-covered fields) but leaves `state_root_hex` empty (verify.cpp:323-326). `SR-5` documents what the command reports here, mirroring `read_account_trustless`'s explicit throw `"chain has not activated state_root (S-033)"` (trustless_read.cpp:458-464).

### 3.6 Field-membership table (digest vs signing_bytes) and a worked attack

The entire binding rests on which fields are in `compute_block_digest` (committee-signed directly) versus `signing_bytes` (committee-signed indirectly, via the forward `block_hash`→`prev_hash` link). This table is read off `producer.cpp:608-693` (digest) and `block.cpp:235-354` (signing_bytes); the rightmost column is the consequence for an auditor who recomputes from a header.

| Field | In `compute_block_digest`? | In `signing_bytes` (`block_hash`)? | Binding to committee at this height |
|---|---|---|---|
| `index` | **yes** (1st field) | yes | **direct** — `SR-3` height-binding |
| `prev_hash` | **yes** | yes | **direct** — links to prior `block_hash` (`SR-2`) |
| `tx_root` | **yes** | yes | **direct** — the `TxInclusionProofSoundness` analog |
| `delay_seed` | yes | yes | direct |
| `consensus_mode`, `bft_proposer` | yes | yes | direct |
| `creators`, `creator_tx_lists`, `creator_ed_sigs`, `creator_dh_inputs` | yes | yes (+ `creator_dh_secrets`) | direct (Phase-1 commits) |
| **`state_root`** | **NO** | **yes, when non-zero** (S-033 shim) | **transitive forward** — `block_hash(H)=prev_hash(H+1)∈digest(H+1)` (§3.3, `SR-1`) |
| `partner_subset_hash` | no | yes, when non-zero | transitive forward (same shim, block.cpp:329-334) |
| `timestamp`, `delay_output`, `cumulative_rand`, `abort_events`, `equivocation_events`, `cross_shard_receipts`, `inbound_receipts`, `initial_state` | no | yes | transitive forward / block-identity only (S-030 D2 window for evidence — out of scope here) |

The asymmetry on the `state_root` row is the whole point. A naive verifier that checks only "header[H]'s committee sigs verify against `digest(H)`" would accept *any* `state_root` value the daemon attaches, because the digest does not constrain it. **Worked attack (§2.1(a), defeated):**

1. Daemon takes the genuine header[H] with `state_root = R_T`, genuine `creator_block_sigs`, genuine `block_hash_T(H)`.
2. Daemon overwrites the served header's `state_root` field with `R_A ≠ R_T`, leaving `creators`, `prev_hash`, `tx_root`, … and the `creator_block_sigs` untouched.
3. The auditor recomputes `light_compute_block_digest(served header) = digest(H)` — **identical** to the genuine digest, because `state_root` is not in it. The committee sigs verify. `verify_block_sigs` returns `ok=true, state_root_hex = R_A`.
4. **But** the auditor binds via `committee_bound_state_root` (`trustless_read.cpp:335-437`): it fetches the **FULL** block `H`, recomputes `block_hash(H)` over `signing_bytes` containing `R_A`, fetches block `H+1`, verifies its committee sigs, and requires `prev_hash(H+1) == recomputed block_hash(H)`. The genuine `prev_hash(H+1)` the committee signed equals `block_hash_T(H)` (computed over `signing_bytes` containing `R_T`). The daemon now faces the `SR-1` dilemma: either the recomputed `block_hash` over the `R_A` body differs from `block_hash_T(H)` (so step (4) throws — the served `R_A` is rejected), or it collides with `block_hash_T(H)` despite `R_A ≠ R_T` (an A2 `signing_bytes` collision), or the daemon also forges `prev_hash(H+1)` so the committee-signed `digest(H+1)` carries the fake value — an A1 forgery.

The attack succeeds only by an A1 forgery on `H+1` or an A2 collision at `H`. This is the substance of `SR-1`; §4.1 formalizes the case split.

---

## 4. Soundness theorems

Throughout, `R_T` denotes the genuine committee-committed `state_root` of the operator's pinned chain at height `H`; `K_0` the genesis-seeded committee (`build_genesis_committee`, `trustless_read.cpp:46-53`); `digest(·)` and `signing_bytes(·)` / `block_hash(·)` as in §3. Bounds are per the `Preliminaries.md §2.0` labels (A1, A2 ≈ `2⁻¹²⁸`; A3 ≈ `2⁻²⁵⁶`).

### 4.1 SR-1 (committee-anchored root)

**Statement.** In the **S-033-active interior regime** (§3.5, §3.4 — `state_root(H) ≠ 0` and a committee-signed block `H+1` exists on the pinned chain), the `state_root` reported by `verify-state-root --height H` equals `R_T`, except with probability `≤ K · 2⁻¹²⁸ + 2⁻¹²⁸`. Forging a different reported root requires either a committee-signature forgery (A1) on block `H+1` or a `signing_bytes` collision at `H` (A2).

**Adversary game.**

1. Operator pins `genesis_O`; `K_0` loaded into the seed map. Adversary controls the daemon; the genuine pinned chain has `state_root(H) = R_T ≠ 0` and a committee-signed `H+1`.
2. Auditor runs `verify-state-root --height H`. Internally: anchor genesis (`T-L1`), fetch + walk headers `0..H` (and `H+1` for the forward link, via the same paged walk), committee-verify, report `header[H].state_root`.
3. `A_root` wins if the command returns `R_A ≠ R_T` without throwing.

**Proof.** Suppose the command returns `R_A ≠ R_T`. The reported value is `header[H].state_root` as served by the daemon. Two cases:

**Case (i): the daemon kept `block_hash(H)` (the reported field, and the value `prev_hash(H+1)` links to) equal to the genuine `block_hash_T(H)`.** Then the genuine `block_hash_T(H) = SHA256(signing_bytes_T(H) ‖ sigs)` where `signing_bytes_T(H)` contains `R_T` (§3.2). But the served header has `state_root = R_A ≠ R_T`, so its `signing_bytes` differs from `signing_bytes_T(H)` (the `state_root` append at block.cpp:347-348 differs). For the served header to nonetheless hash to the same `block_hash_T(H)` — required so the `H → H+1` prev_hash link (which is committee-signed inside `digest(H+1)`) still closes — we need `SHA256(signing_bytes_{R_A}(H) ‖ sigs) = SHA256(signing_bytes_{R_T}(H) ‖ sigs)` with `signing_bytes_{R_A} ≠ signing_bytes_{R_T}`. That is a SHA-256 collision: probability `≤ 2⁻¹²⁸` (A2).

**Case (ii): the daemon changed `block_hash(H)` to match its tampered `R_A` (i.e. served `block_hash_A(H) = SHA256(signing_bytes_{R_A}(H) ‖ sigs)`, internally self-consistent).** Then for the chain walk to close, `prev_hash(H+1)` as served must equal `block_hash_A(H) ≠ block_hash_T(H)`. But `prev_hash(H+1) ∈ digest(H+1)` (§3.1, §3.3), and the auditor committee-verifies `H+1`'s signatures over `digest(H+1)` against `K_0`. The genuine committee signed `digest(H+1)` containing `prev_hash(H+1) = block_hash_T(H)`. For the auditor to accept `H+1` with `prev_hash(H+1) = block_hash_A(H)`, the daemon must present `required` valid signatures over a *different* digest `digest_A(H+1)` — an Ed25519 forgery for each of `required` distinct committee members. By A1, each forgery succeeds with probability `≤ 2⁻¹²⁸`; the union over `required ≤ K` members is `≤ K · 2⁻¹²⁸`. (This reuses `T-L2`'s reduction verbatim, applied to block `H+1`.)

The two cases are exhaustive: either the served `block_hash(H)` matches the genuine one (Case i) or it does not (Case ii). Summing, `Pr[A_root wins SR-1] ≤ K · 2⁻¹²⁸ + 2⁻¹²⁸`.   ∎

**Remark (why this is *committee-signed* and not *daemon-asserted*).** The reported root is not merely a header field the daemon hands over; it is pinned by the committee's signature on the *successor* block via the prev_hash chain. The brief's framing ("`state_root` ∈ the signed digest") names the wrong function; the *conclusion* (committee-signed, not daemon-asserted) is correct, achieved through the two-step §3.3 mechanism. `SR-1` is precisely the sub-lemma `T-L4` relies on at `trustless_read.cpp:409-415` when it verifies the committee-signed **successor** header's sigs inside `committee_bound_state_root`.

### 4.2 SR-2 (genesis-binding / no floating header)

**Statement.** The prev_hash-chain verification from the genesis-anchored block 0 up through `H` (§1 step 3) guarantees the reported root is the root of the **operator's pinned chain** at `H`, not a fork's. Specifically, `A_root` cannot make `verify-state-root --height H` accept an isolated committee-signed header at index `H` (attack §2.1(c)) that does not extend block 0, except by an A1 forgery or A2 collision on some link of the `0..H` chain.

**Adversary game.**

1. As `SR-1` setup. `A_root` constructs a forked header `H_A` at index `H`, genuinely signed by some subset of `K_0`, with `state_root = R_A` reflecting a fork state. `H_A` is *not* on the chain that descends from `genesis_O`'s block 0.
2. `A_root` wins if `verify-state-root --height H` reports `R_A`.

**Proof.** The command's step 3 walks `headers[0..H]` and requires, for each `i ∈ [1, H]`, `headers[i].prev_hash == headers[i-1].block_hash` (`verify_headers`, verify.cpp:211-223), with `headers[0]` pinned to `genesis_O` by the genesis anchor (`T-L1`: `headers[0].block_hash == compute_genesis_hash(genesis_O)`, verify.cpp:193-200). For `H_A` to be accepted at the tail, the daemon must present a contiguous prev_hash chain `block 0 (= genesis_O) → … → H_A`. Either:

- **The chain is genuine up to `H`** — then `headers[H] = H_T` is the real header at `H` on the pinned chain, and `H_A ≠ H_T` cannot be the tail (the daemon would have to substitute `H_A` for `H_T` at index `H`, but then `H_A.prev_hash` must equal `block_hash(H-1)` of the genuine chain *and* `H_A`'s `block_hash` must equal the genuine `prev_hash(H+1)` for `SR-1`'s forward link — driving us back into `SR-1`'s Case (i)/(ii) collision/forgery), **or**
- **The daemon fabricates an alternative chain** `0 → … → H_A` where some intermediate link is forged. Pinning `headers[0]` to the genuine genesis (A2 via `T-L1`) and requiring each `prev_hash` link to hold, an alternative chain that reaches `H_A` at index `H` must differ from the genuine chain at some first index `m ≤ H`; at `m`, `headers[m].prev_hash = block_hash(m-1)` of the genuine chain (since indices `< m` are genuine), but `headers[m] ≠` genuine `header[m]`, so `headers[m]`'s committee signatures (verified at the per-block check) must be a forgery over a different `digest(m)` — A1, `≤ K · 2⁻¹²⁸` per block, `≤ H · K · 2⁻¹²⁸` over the walk. (Equivalently, a collision making two distinct `header[m]` share a `block_hash` to splice the fork in undetected — A2.)

This is the per-height application of `LightClientArchiveSoundness.md` AR-3(ii)'s "floating slice" defense and `T-L4`'s race-window successor binding (the `successor.prev_hash == recomputed block_hash` check in `committee_bound_state_root`, `trustless_read.cpp:424-432`): a committee-signed header in isolation proves nothing about *which chain* it belongs to; only the genesis-rooted prev_hash chain does. `Pr[A_root wins SR-2] ≤ H · K · 2⁻¹²⁸ + 2⁻¹²⁸`.   ∎

### 4.3 SR-3 (height-binding)

**Statement.** The reported root is bound to height `H` *specifically*: `A_root` cannot serve a genuine committee-signed header from height `H' ≠ H` (attack §2.1(b)) and have `verify-state-root --height H` report it as `H`'s root, except by A1 forgery or A2 collision.

**Proof.** `B.index` is the **first** field of `compute_block_digest` (producer.cpp:610 / verify.cpp:59: `h.append(b.index)`), so the committee's signature over `digest(H')` binds the index `H'`. The command fetches the header at index `H` and the prev_hash walk requires the tail header's position in the `0..H` chain to be exactly `H` (the walk has `H` links from genesis; `verify_headers` indexes positionally). For `A_root` to substitute height `H'`'s header at chain-position `H`:

- The substituted header carries `index = H'` in its digest-covered bytes. If `H' ≠ H`, the committee signed `digest` with `index = H'`; to place it at position `H` in the walk the daemon would need it to chain (its `prev_hash` = `block_hash(H-1)` of the genuine chain, and its `block_hash` = `prev_hash(H+1)`). But the genuine block at chain-position `H` has `index = H`; a header with `index = H'` spliced there either (i) fails the prev_hash links unless the daemon forges the neighboring digests (A1), or (ii) the daemon rewrites the substituted header's `index` field to `H` — but that changes `digest` (index is in it), invalidating the committee sigs, forcing an A1 forgery over the rewritten digest.

Either way the substitution costs an A1 forgery (`≤ K · 2⁻¹²⁸`) or an A2 collision. Because `index` is *inside* the signed digest — unlike `state_root`, which is not (§3.1) — height-binding is *direct* for the digest, and propagates to `state_root` through the same header's `signing_bytes` + the forward link of `SR-1`. `Pr[A_root wins SR-3] ≤ K · 2⁻¹²⁸`.   ∎

### 4.4 SR-4 (fail-closed)

**Statement.** Any signature failure, chain break, genesis mismatch, malformed header, or absent successor (in the regimes where a successor is required) causes `verify-state-root` to exit non-zero with a structured diagnostic — never a bare daemon-reported root.

**Proof.** By inspection of the verification surfaces the command composes, all of which set `r.ok = false` (consumed by a caller that throws) or throw directly:

- **Genesis mismatch** → `anchor_genesis` throws `GENESIS HASH MISMATCH` (trustless_read.cpp:75-80). No downstream step runs.
- **Chain break** (any `prev_hash != prior block_hash`, or `headers[0]` non-zero `prev_hash`, or genesis `block_hash` mismatch) → `verify_headers` returns `ok=false` with a `FAIL: prev_hash chain break …` / `FAIL: genesis …` detail (verify.cpp:189-220); the composite caller throws.
- **Committee-sig failure** (creator not in `K_0`, sig count mismatch, sentinel-zero in MD mode, Ed25519 verify failure, or `valid < required`) → `verify_block_sigs` returns `ok=false` with a `FAIL: …` detail (verify.cpp:270-316); caller throws.
- **Malformed header** → `Block::from_json` throws, caught into a `malformed header:` detail (verify.cpp:255-257).
- **Empty/absent `state_root`** in the S-033-active regime where one is expected, or an absent successor for the interior binding → fail-closed per `SR-5` / §3.4 (the in-tree analog throws `"chain has not activated state_root (S-033)"`, trustless_read.cpp:458-464).

This is the per-command instance of `LightClientThreatModel.md` Lemma L-6 (fail-closed exit): no verification surface silently downgrades to "trust the daemon." F3's `verify_state_root_at` (`light/verify_state_root.cpp:101`) returns a `StateRootResult` whose `ok=false` / `detail` the `cmd_verify_state_root` dispatcher (`light/main.cpp:569`) propagates as a non-zero exit with stderr diagnostic, matching the discipline of every other `light/` verifier. The throw-discipline is structural.   ∎

### 4.5 SR-5 (pre-S-033 degradation honesty)

**Statement.** On a chain where S-033 is not active (every header's `state_root == 0`, §3.5), `verify-state-root --height H` can still committee-verify header[H] (its digest-covered fields), but the `state_root` binding is **vacuous** — there is no committed state to anchor — and the command reports this explicitly rather than emitting a meaningless zero/empty root as if it were authoritative.

**Analysis.** Two sub-facts, both grounded in present code:

1. **The binding is vacuous, not merely empty.** By the §3.2 zero-skip shim, `state_root == 0` contributes *nothing* to `signing_bytes(H)`. So even the transitive forward link of `SR-1` carries no information about state: `H+1`'s committee signature binds `H`'s `block_hash`, but `H`'s `block_hash` was computed with `state_root` absent. There is simply no state commitment in the chain to verify. This is not an attack surface — it is the honest absence of the S-033 feature.
2. **What the command reports.** `verify_block_sigs` sets `state_root_hex` only when `b.state_root != zero` (verify.cpp:323-326); on a pre-S-033 header it stays empty. The in-tree `read_account_trustless` treats an empty head `state_root` as a hard error, throwing `"trustless-read: chain has not activated state_root (S-033) — head header carries no state_root, so state-proofs can't be anchored. Use the daemon's `account` RPC directly for chains without S-033 active."` (trustless_read.cpp:458-464). F3's `verify-state-root` **should handle the same way** (confirmed as the intended behavior by mirroring the in-tree primitive it factors out): report committee-verification of the header succeeded, but fail-closed (non-zero exit) on the *state_root* deliverable with a diagnostic stating the chain has not activated S-033, rather than printing an all-zero root that a caller might mistake for a real anchor. This keeps `SR-5` aligned with `SR-4`'s fail-closed discipline: the command never hands back a root that isn't a genuine committed-state commitment.

**Boundary with `MerkleTreeSoundness.md §2.5.**` The empty-leaf-set root is the all-zero sentinel `Hash{}` ("no committed state"). A pre-S-033 chain's absence of a `state_root` field is distinct from a chain whose committed state is genuinely empty (operationally near-impossible — even a fresh chain has 13 `k:` constants + 5 `k:c:` counters per `S033StateRootNamespaceCoverage.md §4.3`). `verify-state-root` does not attempt to distinguish these cryptographically; it reports "no S-033 state_root present" for the empty-field case and lets the operator fall back to the daemon's `account` RPC (with the attendant trust cost) as the in-tree text instructs.   ∎

### 4.6 Supporting lemmas

**Lemma SR-L1 (`light_compute_block_digest` byte-equivalence + `state_root` exclusion).** For any header `H`, `light/verify.cpp::light_compute_block_digest(H)` equals `src/node/producer.cpp::compute_block_digest(H)` byte-for-byte, and neither includes `H.state_root`. *Proof:* the two functions are line-for-line identical (verify.cpp:57-92 mirrors producer.cpp:608-693, kept in sync per the verify.cpp:32-56 comment header); both append the eight field groups of §3.1 and stop. `state_root` appears in neither append sequence. Any future divergence would surface in the cross-binary `tools/test_light_verify_block_sigs.sh` (boots a real producer-generated block) and in `determ test-domain-separation` (asserts `state_root` mutation leaves `block_digest` unchanged). Therefore the digest the auditor recomputes for `H` is the exact byte string the committee signed, and it carries no `state_root` constraint.   □

**Lemma SR-L2 (`block_hash` binds `state_root` when non-zero).** For any header `H` with `state_root(H) ≠ 0`, two distinct `state_root` values produce distinct `block_hash` values except with probability `≤ 2⁻¹²⁸`. *Proof:* `block_hash(H) = SHA256(signing_bytes(H) ‖ creator_block_sigs)` (block.cpp:356-364), and `signing_bytes(H)` appends `state_root` at block.cpp:347-348 under the `state_root != zero` guard. Replacing `state_root` with a distinct non-zero value changes the `signing_bytes` byte string (the append differs; all other appends are unchanged), so `block_hash` changes unless the two distinct `signing_bytes` strings collide under SHA-256 — an A2 event, `≤ 2⁻¹²⁸`. (For the zero ↔ non-zero transition the guard itself changes the append set, so the strings differ by more than the 32 `state_root` bytes; the collision bound is unchanged.) This is the half of the binding that lives in `block.cpp`; the forward link (SR-L3) carries it to the committee.   □

**Lemma SR-L3 (forward link: `H+1`'s committee sig pins `H`'s `block_hash`).** If block `H+1` carries `required` valid committee signatures over `digest(H+1)` (verifiable against `K_0`), then `prev_hash(H+1)` — and hence `block_hash(H)`, since the pinned chain has `prev_hash(H+1) = block_hash(H)` — is fixed up to A1. *Proof:* `prev_hash` is the second field of `compute_block_digest` (§3.1, SR-L1), so it is inside the byte string each committee member signed. By A1 (Ed25519 EUF-CMA), producing `required` valid signatures over a `digest(H+1)` containing a *different* `prev_hash(H+1)` value requires forging each of `required` distinct members' signatures, `≤ K · 2⁻¹²⁸` by union bound (the `T-L2` reduction). Composing SR-L2 + SR-L3: `state_root(H)` is fixed up to A1 (forge `H+1`) ∨ A2 (collide `signing_bytes(H)`), which is exactly `SR-1`'s bound. □

---

## 5. Composition

`SR-1` is the per-height committee-anchored-root sub-lemma that three downstream results consume. The composition makes `verify-state-root` + `verify-state-proof` a complete trust-minimized account read.

### 5.1 Under `LightClientThreatModel.md` T-L4 (balance/nonce via state-proof)

`T-L4`'s race-window mitigation (the S-042 committee-binding, `committee_bound_state_root`, `trustless_read.cpp:335-437`) anchors the state-proof's claimed root to a committee-signed header before invoking `verify_state_proof`. That anchoring step *is* `SR-1`: it confirms the proof verifies against a root that is committee-committed at the proof's height (and chains to genesis, `SR-2`, at that height). `T-L4` then layers `MT-4` (the Merkle inclusion proof rolls up to that root) + the cleartext-vs-`value_hash` cross-check (`T-L4` Lemma L-4). Factoring `SR-1` out as `verify-state-root` lets `T-L4`'s narrative cite a named standalone lemma rather than re-deriving the anchor inline.

### 5.2 Under `AccountHistorySoundness.md` AH-1 (per-point root)

`account-history` (sibling, this round) samples the chain at multiple heights and, at each sampled height `h`, must establish the committee-verified `state_root(h)` before reading the account's state via a proof. `AH-1`'s per-point root is exactly `SR-1` applied at each sampled `h` (via `verify_header_state_root_at` / the `IncrementalChainWalker`, which reuses `verify_headers` + `verify_block_sigs`). The `account-history` soundness is then "`SR-1` at each sample" composed with `MT-4` at each sample + nonce-monotonicity across samples (FA-Apply-3). `(AccountHistorySoundness.md` may not be in this worktree base — cited at spec level; the threader links it.)

### 5.3 Under `MerkleTreeSoundness.md` MT-4 (inclusion against the root)

`MT-4` proves that a passing `merkle_verify` against a root `R` proves leaf membership under `R` (except `≤ 2⁻¹²⁸`). `MT-4` is stated *against a committee-signed root* but does not itself establish that the root is committee-signed — that is `SR-1`'s job. The composition `SR-1 → MT-4` is the full chain `MerkleTreeSoundness.md §5.4` writes as *committee signatures (A1) → block_hash → state_root → [MT-4] → leaf membership*: `SR-1` is the *"committee signatures → block_hash → state_root"* prefix; `MT-4` is the *"state_root → leaf membership"* suffix.

### 5.4 Full trust-minimized account read

```
  verify-state-root --height H               verify-state-proof --state-root R
  ──────────────────────────────             ─────────────────────────────────
  genesis anchor      (T-L1)                  merkle_verify(R, key, value_hash,
  prev_hash walk 0..H (SR-2)                    target_index, leaf_count, proof)
  committee-verify    (SR-1, SR-3)              ────────────────────────────────
  report R = state_root(H)  ───────────►  R     proves (key, value_hash) ∈ R   (MT-4)
                                                ────────────────────────────────
                                          recompute leaf from daemon cleartext,
                                          compare to value_hash      (T-L4 L-4)
```

The operator runs `verify-state-root --height H` to obtain a trust-anchored `R`, then feeds `R` to `verify-state-proof --state-root R` (the `--state-root` override path, `MerkleTreeSoundness.md §5.4` + verify.cpp:363-376). Composition: `Pr[full read compromised] ≤ Pr[SR-1] + Pr[MT-4] + Pr[cleartext collision] ≤ (H·K + K + 1)·2⁻¹²⁸ + log₂(leaf_count)·2⁻¹²⁸ + 2⁻¹²⁸`, which for practical `H ≤ 2³²`, `K ≤ 16`, `leaf_count ≤ 2⁶⁴` is `≤ 2⁻⁹²` — matching `T-L4`'s bound, as expected since `verify-state-root` is the factored-out anchor `T-L4` already performed.

---

## 6. Limitations

### 6.1 Single-daemon (no multi-peer)

`verify-state-root` talks to one daemon. A daemon that *stalls* or *truncates* (refuses to serve `H` or `H+1`) is detected only as fail-closed exit, not as "this daemon is wrong; daemon-B is right." This is the `LightClientThreatModel.md §6.2` availability boundary, inherited unchanged. The soundness claim (`SR-1`..`SR-5`) is unaffected — a stalling daemon cannot make the command report a wrong root, only fail.

### 6.2 Committee-rotation (genesis committee `K_0` only)

Like every other light-client verifier, `verify-state-root` seeds its committee map from `genesis.json`'s `initial_creators` (`build_genesis_committee`, `trustless_read.cpp:46-53`) and requires every creator encountered in the `0..H` walk to be in that map (`verify_block_sigs`, verify.cpp:268-273). On a chain with mid-chain REGISTER/DEREGISTER that rotated the committee, the walk **fails closed** at the first header signed by a non-`K_0` creator — a positive safety property (it never silently trusts an unknown signer), but it means cross-rotation heights are not verifiable without an operator-supplied extended committee map fed to the command. This is `LightClientThreatModel.md §6.5 + F-1` and `LightClientArchiveSoundness.md` AR-4, applied to the per-height anchor. (Confirmed at spec level against F3's expected use of the shared `build_genesis_committee` / `verify_block_sigs` helpers; the threader verifies once F3 lands.)

### 6.3 The head-regime binding boundary (§3.4) — now fails closed

`SR-1` is stated for the **interior** regime (a committee-signed successor `H+1` exists). When `H` is the chain head, there is no successor to forward-bind `H`'s `state_root` via §3.3, and `H`'s OWN committee sigs do NOT bind `state_root` (the digest excludes it, §3.1). The shipped binding helper `committee_bound_state_root` (§6.4) handles this by **failing closed**: it attempts to fetch the successor at `H+1`, finds none, and throws *"NO committee-signed successor yet … retry once the chain advances one block"* (`trustless_read.cpp:388-401`). So the light client never reports an unbound head `state_root` as committee-verified. Operators wanting a strongly committee-anchored head root query `H` once a successor `H+1` has been produced. This is no longer a soundness boundary the document merely flags — it is an enforced fail-closed disposition.

**Liveness note (`--wait` hold-and-wait).** Because the daemon's `state_proof` always serves the *current* head (`rpc_state_proof` returns `chain_.height()`), the anchor in a current-state read is essentially always the head — so without intervention the readers fail closed on every live current-state read. The opt-in `--wait <seconds>` flag (default `0` = the fail-closed disposition above, unchanged) makes `committee_bound_state_root` **block up to N seconds polling for the successor block, then bind the ALREADY-HELD proof** (`trustless_read.cpp` poll loop). This restores usability for current-head reads **without weakening soundness**: the caller's proof was captured for the anchor and is held verbatim; the wait only delays the successor fetch, after which the identical `successor.prev_hash == recomputed block_hash(anchor)` binding (§3.3) runs — the reader never re-fetches the proof (which would race a state change), so the reported value is the committee-attested state as of the anchor (one block "settled" by the time the successor lands). `max_wait_seconds == 0` runs no loop and is byte-identical to the prior behaviour. The live "succeeds once the next block lands" leg runs on CI; the offline flag contract (help, bad-value rejection, no-op default) is `tools/test_light_wait_flag.sh`.

### 6.4 Resolved: the `state_root` field is now bound via full-block recompute + successor (IMPLEMENTED)

**History.** Earlier revisions of this proof flagged a defense-in-depth gap: `verify_headers` (`light/verify.cpp:211-223`) links the chain using the daemon-*reported* `block_hash` field and never recomputes `compute_hash(header)` from `signing_bytes`. As §3.4 shows, *interior*-regime soundness held anyway under A1+A2 (the next block's committee-signed `digest` pins the prior `block_hash` regardless of the reported value), but the *head* regime had no successor to forward-bind the head's `state_root`, and the readers reported the daemon's `state_root` field as committee-verified. **This was a confirmed HIGH-severity light-client gap**: because the committee digest excludes `state_root` (§3.1) and the stripped `"headers"` RPC cannot recompute `block_hash` (§3.2 needs the heavy fields), a malicious daemon could swap the `state_root` field *after* the committee signed and the trustless readers would report it as "committee-verified" — a forged balance/state.

**Resolution (SHIPPED).** The exact recompute this section previously recommended is now implemented as `light/trustless_read.cpp::committee_bound_state_root` (`:335-437`):

- It fetches the **FULL** block at the anchor index via the `"block"` RPC (`Node::rpc_block`, `node.cpp:2623-2627`) — the unstripped body, so `signing_bytes`/`compute_hash` are recomputable — recomputes `block_hash`, fetches the committee-signed SUCCESSOR header, verifies its sigs, and requires `successor.prev_hash == recomputed block_hash`. The recompute *does* cover `state_root` via `signing_bytes` (§3.2), so a swapped field is caught either by the recompute mismatch directly or by the successor `prev_hash` mismatch.
- **Head-regime closed by failing closed.** At the head there is no successor, so the helper throws rather than reporting an unbound root (`trustless_read.cpp:388-401`). This is stronger than the previously-recommended "certify `H`'s root from `H`'s own sigs at the head" — `H`'s own committee sigs do NOT bind `state_root` (the digest excludes it), so the only sound disposition at the head is to refuse until a successor exists, which is exactly what ships.

**Soundness impact.** The interior-regime `SR-1` statement is unchanged (it never needed the recompute). The fix removes the §6.3 head-regime caveat by failing closed and routes every trust-minimized reader (`read_account_trustless`, `verify_state_root_at`, and the stake / supply / account-history / receipt-inclusion / merge-state / param-change / registrant / dapp-registration / account verifiers) through the helper. The consensus digest / `signing_bytes` are UNCHANGED. Tracked as `docs/SECURITY.md §S-042`.

### 6.5 Pre-S-033 vacuous binding (`SR-5`)

On chains without S-033 active, the anchored root is vacuous (§3.5, §4.5). `verify-state-root` reports the absence rather than a meaningless zero root. Operators on such chains fall back to the daemon's `account` RPC with the attendant single-daemon trust cost. This is a chain-level deployment regime, not a command defect.

---

## 7. Cross-references

| Component | File / location | Role in this proof |
|---|---|---|
| `verify-state-root` CLI | `light/verify_state_root.cpp:101` (`verify_state_root_at`) + `light/main.cpp:569` (`cmd_verify_state_root`, dispatched `:1039`) | The standalone per-height anchor command; composes steps 1-5 of §1. |
| `verify_header_state_root_at` / `IncrementalChainWalker` | `light/account_history.cpp` (D3 / sibling R40) | The per-point anchor helper `account-history` reuses; the standalone form of §1 steps 1-4. |
| `read_account_trustless` (anchor inline) | `light/trustless_read.cpp:439-599` (S-042 committee-binding via `committee_bound_state_root` at `:546-548`) | The in-tree composite F3 factors out; the committee-signed successor sig-verify at `:409-415` *is* `SR-1`; the pre-S-033 throw at `:458-464` *is* `SR-5`. |
| `anchor_genesis` | `light/trustless_read.cpp:55-82` | `T-L1` genesis anchor (§1 step 1, `SR-2` base). |
| `verify_headers` | `light/verify.cpp:135-233` | prev_hash walk genesis → H (§1 step 3, `SR-2`). |
| `committee_bound_state_root` | `light/trustless_read.cpp:335-437` (decl `trustless_read.hpp:174-205`) | **The implemented §3.3/§6.4 binding:** full-block recompute via the `"block"` RPC + committee-signed successor `prev_hash` match; head fails closed (`:388-401`). All trust-minimized readers route their reported `state_root` through it. |
| `Node::rpc_block` (full block) | `src/node/node.cpp:2623-2627` | the `"block"` RPC returning the UNSTRIPPED body, so the light client can recompute `compute_hash` (the stripped `"headers"` RPC cannot — `node.cpp:2658-2661`). |
| `verify_block_sigs` | `light/verify.cpp:235-328` | committee-sig verify (§1 step 4, `SR-1`/`SR-3`); reports `state_root_hex` only when non-zero (`:323-326`, `SR-5`). |
| `light_compute_block_digest` | `light/verify.cpp:57-92` | the committee-signed digest — **excludes `state_root`** (§3.1, the load-bearing fact). |
| `compute_block_digest` | `src/node/producer.cpp:608-693` | upstream digest the light copy mirrors; `index` first (`SR-3`), no `state_root` (§3.1). |
| `Block::signing_bytes` | `src/chain/block.cpp:235-354` (`:336-350`) | binds `state_root` into `block_hash` **when non-zero** (§3.2). |
| `Block::compute_hash` | `src/chain/block.cpp:356-364` | `SHA256(signing_bytes ‖ creator_block_sigs)` = `block_hash` (§3.2). |
| apply-time + snapshot `state_root` gates | `src/chain/chain.cpp:1421-1446`, `:1880-1911` | full-node-side enforcement that the root is the genuine post-apply state (`S033` T-4/T-5) — the property the light client anchors to. |
| `tools/test_light_verify_state_root.sh` | (F3 R40; 7 PASS) | end-to-end: wrong `--genesis` → fail; tampered `state_root` at `H` with valid digest sigs → fail via the `H+1` link / recompute; pre-S-033 chain → reports "S-033 not active". |
| `tools/test_light_state_root_binding.sh` | (offline; S-042 witness) | offline mechanized witness for `committee_bound_state_root`: full-block recompute + successor `prev_hash` binding; a swapped `state_root` field is REJECTED; the head (no successor) fails closed. The live forgery-catch (daemon swaps `state_root` post-signing → reader throws) runs on CI. |
| `LightClientThreatModel.md` | T-L1/T-L2/T-L3/T-L4, L-6 | parent online pipeline; `SR-1` is `T-L4`'s factored anchor; `SR-4` is L-6 per-command. |
| `MerkleTreeSoundness.md` | MT-4, §5.4 | the inclusion-proof consumer of the anchored root; §5.4's chain-of-trust prefix is `SR-1`. |
| `S033StateRootNamespaceCoverage.md` | T-1..T-5, §2.3, §4.3 | what the anchored root commits to (10 namespaces); the producer wiring; the empty-tree boundary. |
| `BlockchainStateIntegrity.md` | §2.3 | the `block_hash`-binds-`state_root`-forward mechanism this proof's §3.3 formalizes for the light client. |
| `AccountHistorySoundness.md` | AH-1 (sibling R40) | per-point root = `SR-1` per sampled height. (Spec-level cite.) |
| `TxInclusionProofSoundness.md` | (sibling R40) | the `tx_root` analog — `tx_root` IS in `compute_block_digest` directly; `state_root` is the transitively-forward-bound sibling field (§3.1 contrast). (Spec-level cite.) |
| `LightClientArchiveSoundness.md` | AR-3(ii), AR-4 | the "floating slice" defense (`SR-2`) + the `K_0`-only committee limitation (§6.2). |

---

## 8. Status

- **Implementation.** `verify-state-root` shipped in F3 (this round, R40): `light/verify_state_root.cpp:101` (`verify_state_root_at`) + `light/main.cpp:569` (`cmd_verify_state_root`, dispatched `:1039`) + `tools/test_light_verify_state_root.sh` (7 PASS). The anchor logic it factors out is already in-tree and exercised (`read_account_trustless`, `light/trustless_read.cpp`); F3 exposes it standalone.
- **Proof.** Complete (this document). `SR-1`..`SR-5` cover the committee-anchored root, genesis-binding, height-binding, fail-closed discipline, and the pre-S-033 vacuous-binding honesty.
- **Regime labeling.** **S-033-active (interior):** strong — the reported root is committee-committed at `H` by the transitively-forward prev_hash binding (`SR-1`), bound to genesis (`SR-2`) and to height `H` (`SR-3`), and **mechanically enforced** by `committee_bound_state_root` (full-block recompute + successor `prev_hash` match). **S-033-active (head):** the helper **fails closed** (no committee-signed successor yet — `trustless_read.cpp:388-401`); the light client never reports an unbound head root (§6.3). **Pre-S-033:** vacuous — no committed state to anchor; the command reports the absence and fail-closes on the root deliverable (`SR-5`), mirroring the in-tree `"chain has not activated state_root (S-033)"` throw.
- **The binding finding (load-bearing) — now mechanized.** `state_root` is **NOT** in `compute_block_digest` (what the committee directly Ed25519-signs). It **IS** in `Block::signing_bytes` / `block_hash` (when non-zero, S-033 zero-skip shim), and is committee-bound **transitively forward** via `block_hash(H) = prev_hash(H+1) ∈ digest(H+1)`. The §3.3 mechanism is now IMPLEMENTED in `light/trustless_read.cpp::committee_bound_state_root` (`:335-437`): full-block recompute via the `"block"` RPC binds the served `state_root` into a locally-recomputed `block_hash`, then the committee-signed successor's `prev_hash` certifies it. Earlier this proof noted the recompute was ABSENT (the readers trusted the daemon's reported `block_hash`/`state_root` field — a confirmed HIGH-severity gap; see `docs/SECURITY.md §S-042`). It is now PRESENT and routed through by every trust-minimized reader. This matches `MerkleTreeSoundness.md §5.4`'s chain of trust and block.cpp:341-344's source comment, and is pinned by the `determ test-domain-separation` assertion that `state_root` mutation leaves `block_digest` unchanged but changes `Block::compute_hash`.
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA), A2 (SHA-256 collision resistance), and transitively A3 (preimage, in `T-L1`'s genesis-anchor case 2). Per `Preliminaries.md §2.0`. FA3 (`SelectiveAbort.md`) is **not** used for SHA-256.
- **Concrete-security bound.** `SR-1`: `≤ (K+1)·2⁻¹²⁸`; `SR-2`: `≤ (H·K+1)·2⁻¹²⁸`; `SR-3`: `≤ K·2⁻¹²⁸`. Full account read (`SR-1 → MT-4 → cleartext`): `≤ 2⁻⁹²` for `H ≤ 2³²`, `K ≤ 16`, `leaf_count ≤ 2⁶⁴` — matching `T-L4`.
- **Resolved hardening (§6.4).** The recompute-and-bind step earlier recommended here is now SHIPPED as `committee_bound_state_root` (`trustless_read.cpp:335-437`): full-block recompute via the `"block"` RPC + committee-signed successor `prev_hash` match, head fails closed. The former honest-daemon caveat (readers trusting the daemon's `state_root` field) is closed; tracked as `docs/SECURITY.md §S-042`. The consensus digest / `signing_bytes` are unchanged.
