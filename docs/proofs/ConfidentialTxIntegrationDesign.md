> **TIER: FUTURE — post-1.0, non-authoritative.** Design-stage; does NOT describe shipped code and is NOT coherence-maintained against src/. Roadmap index: docs/ROADMAP.md

# ConfidentialTxIntegrationDesign — a DESIGN + THREAT-MODEL proposal for wiring Determ's Bulletproofs range proofs into the ledger as confidential (hidden-amount) transactions

**This is a PROPOSAL for owner review, not a specification of anything shipped.** It describes a *possible* confidential-transaction (CT) construction over the range-proof / Pedersen library that IS shipped (`src/crypto/pedersen/`, CRYPTO-C99-SPEC.md §3.19, increments 1-5), and reasons about where hiding amounts would collide with the current plaintext-amount ledger. **No chain, consensus, ledger, wallet, or crypto file is modified by this document.** Nothing here claims any shipped chain functionality: the range-proof *library* is shipped and proven (bounded — see §7); the *integration* sketched here is entirely design-stage, unbuilt, unproven, and consensus-critical.

**Governance status (read this first).** Confidential transactions are a **Claude-drafted design proposal**. Determ's FROST-deviation discipline (`FROST_DEVIATION_NOTICE.md`; MEMORY: *frost-deviation-discipline*) requires that any AI-suggested primitive or consensus change be explicitly signed off by the owner (Stoyan Denev) **before** it enters immutable docs or consensus code. This document therefore surfaces decisions and trade-offs; it **decides nothing** and recommends nothing as final. It exists so the owner can accept, reject, or redirect the whole track. The single largest such decision — the curve (§2) — is deliberately left open with both branches laid out.

---

## 0. What is shipped vs. what this proposes

| Layer | Status | Source of truth |
|---|---|---|
| Pedersen commitment `C = v·G + r·H` over P-256, additive homomorphism | **SHIPPED (library, additive, no chain caller)** | `src/crypto/pedersen/pedersen.c`; `PedersenCommitmentSoundness.md` (PC-1..PC-11) |
| Bulletproofs inner-product argument (IPA) | **SHIPPED (library)** | `src/crypto/pedersen/ipa.c`; `BulletproofsIPASoundness.md` (IPA-1..IPA-6) |
| Bulletproofs single-value range proof `v ∈ [0, 2^n)` | **SHIPPED (library)** | `src/crypto/pedersen/rangeproof.c` + `.h`; `BulletproofsRangeProofSoundness.md` (RP-1..RP-6) |
| Plaintext-amount ledger, supply invariant, state root, light client | **SHIPPED** | `src/chain/chain.cpp`, `include/determ/chain/{block,chain}.hpp`, `light/` |
| **Confidential-transaction chain integration (this document)** | **PROPOSAL — nothing built** | — |

Every shipped library artifact above carries the honest non-claim that it is **not a consensus or wallet primitive** and has **no in-tree consumer** (`rangeproof.h:13` "LIBRARY PRIMITIVE — no chain call site"; RP-NC-3 / IPA-NC-3 / PC-NC-3). This proposal is the design for the consumer those documents defer.

**Authoritative external construction.** Confidential Transactions as deployed by Elements/Liquid and Grin/Mimblewimble; the range proof is Bünz–Bootle–Boneh–Poelstra–Wuille–Maxwell, *"Bulletproofs: Short Proofs for Confidential Transactions and More"* (IEEE S&P 2018) §4. The balance-in-commitment-space technique is Maxwell's original CT write-up. This document maps that construction onto Determ's specific ledger, which differs from a UTXO chain in ways that matter (§3).

---

## 1. The confidential-transaction construction

### 1.1 What changes at the value layer

Today a transfer moves a **plaintext** `uint64_t amount` between two accounts (`include/determ/chain/block.hpp:205-221`: `struct Transaction { … uint64_t amount; uint64_t fee; … }`), and each account's balance is a **plaintext** `uint64_t` (`AccountState::balance`) hashed directly into the state commitment (`src/chain/chain.cpp:278-283`: the `"a:"+domain` leaf is `SHA256(balance ‖ next_nonce)`).

The confidential construction replaces the **amount** (and, in the account-model variant, the **balance**) with a Pedersen **value commitment**:

```
V = v·g + gamma·h        (the shipped inc.1 shape: rangeproof.c uses V = v*g + gamma*h)
```

where `g` is the P-256 base point, `h` is the nothing-up-my-sleeve second generator (unknown `log_g(h)`), `v` is the hidden amount, and `gamma` is a per-commitment **blinding factor** drawn from a CSPRNG. `V` is a 33-byte SEC1-compressed point. Given only `V`, an observer learns nothing about `v` (hiding, PC-3), while the committer is bound to a single `v` (computational binding under ECDLP, PC-2).

Two guarantees that plaintext amounts gave for free must now be re-established cryptographically:

1. **Non-negativity + no-overflow.** A plaintext `uint64_t` is trivially in `[0, 2^64)`. A commitment `V` hides *any* scalar `v < n_order` (the P-256 group order ≈ 2^256), so a malicious committer could "hide" a value that, in modular arithmetic, behaves like a **negative** number (e.g. `v = n_order − 1 ≡ −1`) and mint money via a balance equation that wraps mod `n`. This is defeated by attaching a **range proof** to every output commitment: `determ_rangeproof_verify(V, proof, n)` proves `v ∈ [0, 2^n)` for a chosen `n` (`n ≤ 64` per `DETERM_RANGEPROOF_MAX_BITS`, `rangeproof.h:28`) **without revealing `v`** (RP-2). Choosing `n = 64` matches the existing `uint64_t` value domain exactly.

2. **Supply conservation.** Today the ledger sums plaintext balances and checks them against running counters (§3a). With hidden amounts, conservation is enforced in **commitment space** via the additive homomorphism (PC-4).

### 1.2 The balance proof (input = output + fee, in commitment space)

The homomorphism `commit(v1,r1) (+) commit(v2,r2) == commit(v1+v2, r1+r2)` (PC-4, machine-gated including the mod-`n` wraparound vector) lets a validator check value conservation **without seeing any amount**. For a transaction spending input commitments `{V_in}` to output commitments `{V_out}` with a **plaintext** fee `f`:

```
Σ V_in  −  Σ V_out  −  f·g   should be a commitment to 0
```

Write each `V = v·g + gamma·h`. If the amounts balance (`Σ v_in = Σ v_out + f`), the `g`-components cancel and the left-hand side collapses to a pure `h`-multiple:

```
Σ V_in − Σ V_out − f·g  =  (Σ v_in − Σ v_out − f)·g  +  (Σ gamma_in − Σ gamma_out)·h
                        =  0·g  +  r·h                    where  r = Σ gamma_in − Σ gamma_out
```

So conservation reduces to: **the residual point is `r·h` for some blinding `r` the prover knows** — i.e. it is a commitment to the value 0. The prover proves this by demonstrating knowledge of `r` such that `residual = r·h`. Two standard ways to discharge it, either acceptable, to be chosen at build time:

- **(a) Reveal `r` (the "excess" / kernel value).** The transaction carries `r` in the clear; the validator recomputes `r·h` and checks equality with the residual. Simple; leaks nothing about amounts (only the blinding *difference*). This is Mimblewimble's kernel-excess style.
- **(b) A Schnorr signature over `h`.** The prover signs with `r` as the secret key against public key `residual = r·h`, proving knowledge of `r` without revealing it, and simultaneously binds the whole transaction (anti-malleability, §4). This is the Elements/Liquid style and is preferred because it binds signer authorization to the balance proof. **NOTE: Determ has no shipped Schnorr-over-P-256 signing primitive** — this would be new crypto (TBD — a Schnorr/DLEQ proof over the P-256 stack, or reuse of the OPRF track's DLEQ machinery; verify what exists against `src/crypto/oprf/` and `CRYPTO-C99-SPEC.md §3.9`).

Every output commitment additionally carries a range proof (§1.1). **Inputs need no range proof** — they were range-proven when created as prior outputs (an inductive invariant: every commitment on the ledger was range-proven at birth). This halves the proof count vs. proving both sides.

### 1.3 Where the blinding factors come from

The balance proof only works if the prover controls the blinding factors so that `Σ gamma_in − Σ gamma_out` is a value it knows. In practice the wallet chooses `gamma_out` for each output freely (CSPRNG) except it may fix the **last** output's blinding to make the sums balance to a chosen `r` (or, in style (a), simply publishes `r = Σ gamma_in − Σ gamma_out`). The receiver must learn its output's `(v, gamma)` to spend later — delivered via an encrypted memo / DH-derived shared secret (the v2.22 "amount DH handshake" over X25519 that the spec already anticipates, CRYPTO-C99-SPEC.md §2.Q1/Q2, line 47/73). **This receiver-side amount-communication channel is out of scope for this document but is a hard prerequisite** (TBD — design against the v2.22 X25519 amount handshake).

### 1.4 Account model vs. UTXO model — a structural fork in the road

Determ is an **account/balance** ledger (`accounts_[domain].balance`), not a UTXO set. Confidential Transactions as classically deployed (Elements, Grin) are **UTXO**: a "balance" is just the set of unspent output commitments you can open. Two integration shapes, each with deep consequences:

- **UTXO-style confidential outputs alongside the account ledger.** Introduce a parallel commitment set: a confidential transfer consumes input commitments and creates output commitments, tracked in a new state namespace (e.g. `"v:"` for value-commitments / a nullifier set for spent ones). The account balance model is untouched for transparent txs; confidential value lives in its own UTXO-like pool. This is the **cleaner cryptographic fit** (the balance proof is naturally per-transaction) but adds a whole second accounting model to a chain that is currently single-model.
- **Confidential account balances.** Replace `AccountState::balance` (a `uint64_t`) with a commitment `C_balance = balance·g + gamma·h`. A transfer homomorphically debits `C_from` and credits `C_to`. This preserves the account model but is **substantially harder**: every balance mutation must re-blind, the "sufficient balance" check (`acct.balance < fee`, `chain.cpp:729`) becomes a range proof that the *post-debit* balance is still `≥ 0`, and concurrent debits to one account under one blinding factor create witness-management hazards. **This variant is not recommended as a first step**; the UTXO-style pool is the lower-risk path. (TBD — the exact state-model choice is Decision D3, §8.)

For the remainder of this document the **UTXO-style confidential-output pool** is assumed as the reference shape, because it localizes the balance proof to one transaction and leaves the transparent account ledger and its supply invariant intact (§3a shows why that matters).

---

## 2. THE CURVE DECISION (surfaced, deliberately not decided)

This is the single most consequential open decision and it is **the owner's call**. The facts:

- **The shipped range-proof / Pedersen / IPA library is over NIST P-256** (`rangeproof.c`, `pedersen.c`, `ipa.c`; all use the §3.8c P-256 field/point ops). It is proven (bounded) and dual-oracle-gated *today*.
- **The chain-level Bulletproofs plan of record is secp256k1**, not P-256. CRYPTO-C99-SPEC.md is explicit and repeated on this:
  - §2.Q1 (line 48): *"secp256k1 — Bulletproofs (v2.22) … libsecp256k1 + libsecp256k1-zkp deliver production-tested C99 Bulletproofs (Liquid, Grin since 2019)."*
  - §2.Q2 (line 74): *"v2.22 Bulletproofs → secp256k1 via libsecp256k1-zkp (not ristretto255)."*
  - The companion `v2.22-PRIVACY-SPEC.md` is described (line 11) as: *"confidential transactions spec (consumer; Bulletproofs primitive switches to secp256k1 per this spec)."*
  - The from-scratch **P-256** range-proof stack is explicitly labelled *"the library-primitive-first exploration"* — **not** the intended chain path (RP-NC-3, IPA-NC-3: *"CRYPTO-C99-SPEC §3.1/§48 record that the eventual v2.22 chain-level Bulletproofs is planned over secp256k1 … this from-scratch P-256 stack is the library-primitive-first exploration"*).

So the two branches are:

### Option A — reuse the shipped P-256 range-proof library now

**For:**
- **Fastest to a working prototype.** The prover/verifier, KAT corpus, dual-oracle gate, and soundness accounting already exist and are green. No new multi-week from-scratch crypto library.
- **Fully in-tree, libsodium-free, no new vendored dependency.** No libsecp256k1-zkp build-configuration complexity (which the spec itself flags as a risk, §Q-risks line 1337).
- **FIPS-profile compatible.** P-256 is FIPS 186-5 validated; secp256k1 is not on NIST's list. Under the current profile design, confidential transactions are **only** deployable in FIPS profiles if they are over P-256 — and the spec currently records CT as **UNAVAILABLE in FIPS profiles** precisely because it assumed secp256k1 (CRYPTO-C99-SPEC.md line 484: *"Confidential transactions (v2.22 Bulletproofs): ✅ Available [MODERN] / ❌ UNAVAILABLE — no FIPS-validated range proofs exist [FIPS]"*). Option A could *change* that answer.

**Against:**
- **P-256 is a NIST curve that parts of the confidential-transaction ecosystem distrust** (the Dual_EC_DRBG history; the unexplained curve seeds). secp256k1 / ristretto255 are the culturally-expected curves for privacy tech. This is a reputational/ecosystem concern, not a known mathematical weakness in P-256.
- **It is not the §2.Q1 plan of record.** Adopting P-256 for the chain path means amending the spec's curve decision and the v2.22-PRIVACY-SPEC — itself an owner-gated governance change (a Claude-introduced deviation from Stoyan's documented secp256k1 choice, exactly the class the FROST discipline guards).
- **Constant-time gap is on the critical path** (§4, NC-4/L-4): the shipped P-256 range prover is explicitly **not constant-time**. This is true of *any* from-scratch impl until hardened, but it means Option A ships the CT-hardening obligation with it.

### Option B — build a secp256k1 range-proof library (via libsecp256k1-zkp) to match the plan

**For:**
- **Matches the documented plan** (§2.Q1/Q2, v2.22-PRIVACY-SPEC) and the wider CT ecosystem's curve.
- **libsecp256k1-zkp is the most production-tested Bulletproofs code in existence** (Liquid, Grin, since 2019), with batch verification, aggregation, and a hardened constant-time prover already in it — capabilities the shipped P-256 lib does **not** have (single-value only, non-batched, non-CT: RP-NC-1/NC-2/NC-4).

**Against:**
- **A second, multi-week, from-scratch-or-vendored library effort** before any chain integration begins. The spec budgets secp256k1 + libsecp256k1-zkp at ~10 days and flags its **build-configuration complexity** as a named risk (line 1294, 1337).
- **Adds a second curve family + a vendored MIT dependency** (~3K LOC libsecp256k1-zkp + ~6K libsecp256k1), reversing part of the "own every primitive, no external crypto lib" posture (contrast the from-scratch P-256 stack).
- **Unavailable in FIPS profiles** — CT would remain a MODERN-profile-only feature (the current documented state).

### The recommendation this document makes: none (by design)

Both are defensible. A pragmatic *sequencing* observation — offered as input, not a decision — is that the chain-integration design work in §3-§4 (the balance proof, the state-commitment binding, the DoS budget, the light-client story, migration) is **largely curve-agnostic**: it is the same protocol whether the underlying group is P-256 or secp256k1. So the owner *could* approve the integration **design** independent of the curve, and bind the curve later. That is itself Decision D1 (§8).

---

## 3. Consensus-critical concerns

Each subsection is a place where hidden amounts collide with a shipped, load-bearing assumption. These are the concerns that make CT integration **consensus-critical** and separate it from the additive library work.

### 3a. Supply invariant — how the homomorphic balance check preserves conservation, and what breaks if a range proof is forged

**Today's guarantee (shipped, exact).** At the end of every non-genesis block apply, `chain.cpp:1398-1420` asserts:

```
live_total_supply()  ==  expected_total()
```

where (`chain.cpp:549-554`, `chain.hpp:450-456`):

```
live_total_supply()  =  Σ accounts_[·].balance  +  Σ stakes_[·].locked
expected_total()     =  genesis_total_ + accumulated_subsidy_ + accumulated_inbound_
                        − accumulated_slashed_ − accumulated_outbound_
```

A violation **throws** (`throw std::runtime_error`), which the apply-path caller surfaces loudly — a mismatch is treated as a consensus break, not a warning. This is a **plaintext sum**: it works precisely because every balance and stake is a visible `uint64_t`.

**The collision.** If a transfer's amount is a commitment `V`, its `v` is **not summable in the clear**. The plaintext invariant above cannot see confidential value at all. Two consistent ways to keep supply sound:

1. **Keep confidential value out of the transparent counters entirely** (the UTXO-pool shape, §1.4). Transparent balances/stakes still satisfy the shipped invariant verbatim. The confidential pool's conservation is enforced **per-transaction** by the balance proof (§1.2): each confidential tx proves `Σ V_in − Σ V_out − f·g = r·h`, so it neither creates nor destroys hidden value (only the plaintext fee `f` crosses from confidential to transparent — see §3e). The pool's total hidden supply is therefore invariant under confidential txs by construction, and the **boundary** operations (shielding a plaintext amount into a commitment; unshielding back) are the only places value moves between the transparent and confidential domains — and those operations expose a plaintext amount at the boundary, so the transparent invariant still balances. **This is the recommended design: the shipped supply invariant is left byte-for-byte intact.**
2. Replace the plaintext invariant with a homomorphic one (sum all commitments, check against a committed total). Far more invasive; not recommended.

**What breaks if a range proof is forged.** This is the **highest-severity failure in the whole design.** The balance proof `Σ V_in − Σ V_out − f·g = r·h` guarantees conservation **only in the group mod `n_order`**. Without a range proof, a committer can set an output `v_out ≡ −k (mod n_order)` for large `k`; the balance equation still holds mod `n`, but that output is spendable later as an enormous positive value — **silent inflation**. The range proof on every output is the *only* thing forcing `v_out ∈ [0, 2^n)` so that the mod-`n` balance is also an **integer** balance. Therefore:

> **A range-proof soundness break ⇒ a committer can create hidden negative outputs ⇒ undetectable inflation of the confidential supply, invisible to the plaintext supply invariant.** This ties directly to `BulletproofsRangeProofSoundness.md` **RP-2** (soundness is a *reduction* to Bulletproofs §4 under ECDLP + ROM, backed by reject-witnesses, **not** a machine-checked extractor) and **L-1** (soundness assumed under ECDLP + generator independence; a P-256 discrete-log break breaks binding regardless of any byte-exactness). The confidential supply's integrity rests entirely on RP-2/L-1 holding. There is **no cheap runtime cross-check** for a forged range proof the way the plaintext invariant catches a plaintext imbalance — a forged-but-verifying proof is, by definition, accepted. This asymmetry (plaintext imbalance is caught by an O(N) sum; confidential inflation is caught by nothing weaker than range-proof soundness) is the core risk of the entire track and must be stated plainly to the owner.

### 3b. Transaction validity + DoS — verification cost, block-time budget, mitigations

**Cost.** Range-proof verification is the expensive new per-transaction cost. The shipped verifier is **explicitly the non-optimized form**: it reconstructs `P` and folds the IPA generators explicitly rather than collapsing into one `O(n)` multi-exponentiation (RP-NC-2, IPA-NC-2). For `n = 64` that is `2·log2(64) = 12` IPA rounds of point operations plus the `t_hat` identity check — on the order of a few hundred P-256 scalar-mults per proof. A block full of confidential txs multiplies this by the tx count. Determ produces a block roughly every cycle, so **per-block verification time is a hard, consensus-relevant budget**: if verifying a block's proofs cannot finish inside the round, honest validators fall behind and liveness degrades.

**Mitigations (all require the *optimized/batched* verifier the shipped lib does not yet have — RP-NC-2):**
- **Batch verification.** Bulletproofs batch-verify many range proofs in roughly one multi-exp of size proportional to the largest, amortizing the fixed cost. libsecp256k1-zkp (Option B) has this; the shipped P-256 lib (Option A) does **not** — it would need the single-multi-exp verify optimization built first (listed as a candidate follow-on in §3.19: *"the single-multi-exp verify optimization"*).
- **Proof-size / count limits.** Cap confidential outputs per tx and confidential txs per block (a consensus parameter), bounding worst-case verification time. This is a genesis/param knob, analogous to `MAX_COMPOSABLE_INNER` (`chain.cpp:977`).
- **Fee pricing.** Price a confidential output's verification cost into its minimum fee so a DoS flood is economically bounded (the fee is plaintext, §3e, so it *can* be priced).
- **Fixed `n`.** Mandate a single bit-width (`n = 64`) chain-wide so proof size and verify cost are uniform and predictable (no adversary picking pathological `n`).

**Validate-vs-apply divergence hazard.** Determ already treats validate/apply divergence as a consensus bug class (S-030 D1). Range-proof verification must run at the **same** point in validate and apply, over the **same** bytes, or two nodes could disagree on a tx's validity. This is a strict requirement, not an optimization.

### 3c. State-commitment implications — committing V's + proofs, and the determinism / on-chain-CSPRNG divergence

**Where commitments enter the state root.** The state root is a sorted-leaves binary Merkle root over namespaced `(key, value_hash)` leaves (`chain.cpp:build_state_leaves`, `:262-411`); e.g. the account leaf is `SHA256(balance ‖ next_nonce)` under `"a:"+domain` (`:278-283`). A confidential-output pool adds a new namespace — say `"v:"+commitment_id` whose leaf commits the 33-byte `V` (and a spent/nullifier marker in another namespace) — exactly the way `"d:"` (DApp registry) and `"i:"` (inbound receipts) were added. The commitment `V` is a fixed 33-byte string, so hashing it into a leaf is deterministic and needs no special handling.

**Do the range proofs go into the state root?** They need **not** be committed to the *state* root (they are transaction-witness data, not persistent state), but they **must** be committed to the **block** (via `tx_root` / the transaction serialization that feeds `compute_block_digest`) so that (i) the committee signatures authenticate them and (ii) a light client can obtain them (§3d). Keeping proofs out of the *state* leaves keeps the state root small; the shipped design already separates transaction data (block digest) from state (state root). (TBD — confirm the exact `tx_root` construction and that proof bytes are inside the signed transaction envelope: verify against `include/determ/chain/block.hpp` `tx_root` + `signing_bytes()`.)

**The determinism / CSPRNG divergence — call this out.** The shipped range prover takes its randomness **from the caller** (`alpha, rho, tau1, tau2, sL, sR`, `rangeproof.h:39-42`) purely so the KAT is reproducible (RP-3 caveat, RP-4). A real on-chain prover **must** draw these from a CSPRNG (RP-3 caveat: *"the security of a real deployment depends on that randomness being unpredictable"*; L-2). This is a genuine divergence from the shipped test posture and has two consequences:
- **The prover is non-deterministic across runs** (different randomness → different proof bytes), which is *fine and expected* — the *verifier* is deterministic given the proof bytes, and it is the verifier that runs in consensus. Nodes verify the proof the producer put in the block; they never re-prove. So consensus determinism is preserved as long as **verification** is deterministic (it is: pure function of `(V, proof, n)`), **not** proving.
- **But the prover's randomness quality is now security-critical, not test-cosmetic.** A weak/predictable `gamma` or `sL/sR` leaks the amount or the blinding (breaking hiding). The wallet's CSPRNG becomes part of the confidentiality TCB. This is the same class as the Pedersen `r` caveat (PC-3, L-3: *"Production callers must draw r from the CSPRNG"*). (TBD — the on-chain/wallet CSPRNG source: verify against `src/crypto/random.cpp` / `src/crypto/rng/`.)

### 3d. Light-client verification — can a trustless light client verify a confidential tx without the amounts?

**Today's light-client trust model (shipped, from `light/trustless_read.cpp` + `src/node/node.cpp:3760-3860`).** A determ-light client: (1) anchors the genesis hash; (2) walks the header chain verifying every block's committee signatures (K-of-K / BFT Ed25519 over the block digest); (3) fetches a `state_proof` (a Merkle inclusion proof of a `(key, value_hash)` pair) and verifies it against the committee-signed `state_root` via `merkle_verify` (`include/determ/crypto/merkle.hpp:84`). Crucially, **the light client does NOT re-execute transactions and does NOT independently verify amounts** — it *trusts the committee-signed `state_root`* and checks inclusion. For a balance read it cross-checks the daemon's cleartext balance RPC against the `value_hash = SHA256(balance ‖ next_nonce)` in the proof (MEMORY: *light-stake-read-keybind-gap*, *determ-f7-light-f2-verification* — single-leaf readers need both a key-bind and a value-hash-bind).

**Under confidential txs.** Two distinct questions:

1. **Can a light client verify a confidential tx's *validity* (range proof + balance) without the amounts?** *Yes, cryptographically* — range-proof verification and the balance check are **public-coin operations that need only `V`, the proof bytes, and the plaintext fee** (`determ_rangeproof_verify` takes `(V33, proof, n)`, no witness). A light client *could* download the confidential txs of a block + their proofs and verify them directly, gaining a *stronger* guarantee than today (it would be checking validity itself, not just trusting the committee). What it must download: the block's confidential transactions including all `V`'s and range proofs and the balance-proof data (the residual/excess or Schnorr sig). This is **more** data than a header + one state proof (proofs are ~600+ bytes each), so it is a bandwidth trade, not a free upgrade.
2. **Can a light client learn *its own* confidential balance trustlessly?** Only if it holds the opening `(v, gamma)` for its output commitments (delivered via the encrypted-memo channel, §1.3). It then verifies the commitment is included in the state root (`"v:"` leaf inclusion, same `merkle_verify` path) and opens it locally with its `(v, gamma)`. It **cannot** read another party's amount — which is the whole point.

**The honest limit:** the current light client *trusts the committee for validity* and only checks inclusion. A confidential-aware light client should *at minimum* preserve that (verify `V` inclusion in `state_root`), and *may optionally* verify range/balance proofs itself. The committee-signature trust root is unchanged; confidentiality does not weaken it, but it does mean the daemon's *cleartext-balance cross-check* (the shipped `light/` design's final step) **no longer applies to confidential value** — there is no cleartext balance to cross-check. (TBD — exact confidential light-read RPC surface: to be designed against `light/trustless_read.cpp`'s state-proof path.)

### 3e. Fee handling — fees MUST stay visible

Fees **cannot** be confidential. Validators need the fee value in the clear because:
- The **balance proof** has a plaintext fee term: `Σ V_in − Σ V_out − f·g = r·h` (§1.2) requires `f` as a scalar to form `f·g`. A hidden fee would make the balance equation unverifiable.
- **Fee distribution is plaintext accounting.** The shipped path sums `total_fees` and mints `total_fees + subsidy_this_block` to block creators, split evenly with dust to `creators[0]` (`chain.cpp:721-732`, `:1235-1307`). Creators must receive a **known** amount; a confidential fee would break creator payout and the supply invariant (the fee is the value that crosses from the confidential domain into transparent creator balances).
- **DoS pricing** (§3b) needs the fee visible to price verification cost.

So the confidential `Transaction` keeps its **plaintext `uint64_t fee`** (the shipped field, `block.hpp:210`) and only the `amount`/outputs become commitments. The fee is the designed, minimal leakage — and it is *desirable* leakage (it funds and prices the system). This also means the balance proof's plaintext `f·g` term is the bridge that keeps the transparent supply invariant (§3a) balanced across the confidential/transparent boundary.

### 3f. Migration — coexistence of transparent and confidential txs, and the transition

- **Coexistence.** The cleanest path adds a **new `TxType`** (e.g. `CONFIDENTIAL_TRANSFER = 11`, the next free slot after `DAPP_CALL = 10`, `block.hpp:23-181`) rather than mutating `TRANSFER`. Transparent transfers are byte-for-byte unchanged; confidential txs are a parallel, opt-in path. This preserves all existing wire formats, KATs, and the plaintext supply invariant (§3a). The reserved-slot discipline already exists (`REGION_CHANGE = 5` was reserved this way).
- **Shield / unshield boundary.** Value enters the confidential pool via a **shield** operation (plaintext `amount` debited from an account balance → an output commitment `V = amount·g + gamma·h`, `amount` visible at the boundary so the transparent invariant balances) and leaves via **unshield** (open a commitment, prove it, credit a plaintext account). These two operations are the *only* transparent↔confidential value crossings and each exposes a plaintext amount, which is exactly what keeps §3a's invariant sound.
- **Transition.** Because it is opt-in and additive, there is no flag-day. A genesis/param gate (`confidential_enabled`) can turn the feature on for a deployment; FIPS-profile deployments would gate it off if the curve is secp256k1 (§2, Option A vs B changes this answer).
- **No consensus-format break** for existing nodes that don't understand confidential txs **only if** confidential txs are gated behind a version/feature flag those nodes reject cleanly — otherwise a confidential tx is an unparseable/invalid tx to an old node and forks the chain. This is the standard soft-fork-vs-hard-fork question and must be decided explicitly (part of Decision D4, §8).

---

## 4. Threat model

### 4.1 What confidential transactions DO and DO NOT protect

**DO protect:**
- **Output amounts.** The value `v` in each `V = v·g + gamma·h` is hidden (information-theoretic hiding for a uniform `gamma`, PC-3). An observer with unbounded computing power still cannot recover `v` from `V` alone.

**Do NOT protect (explicit non-goals):**
- **Sender / receiver identity.** The `from`/`to` domains are plaintext in the `Transaction` struct (`block.hpp:207-208`). Hiding *who* transacts is the **separate anon-address track** (`AnonAddressDerivationMigration.md`), which is REOPENED and independent. CT hides *how much*, not *who*.
- **The transaction graph / linkage.** Which commitments are consumed by which tx is visible (the UTXO spend graph). Timing, amounts-correlation, and graph analysis can still deanonymize flows. CT is not a mixnet.
- **The fact that a transaction IS confidential.** A `CONFIDENTIAL_TRANSFER` is a distinct, visible tx type (§3f). Observers see *that* a confidential transfer happened (and its fee), just not the amount.
- **Fees.** Plaintext by design (§3e).

### 4.2 Assumptions and their failure modes

| Assumption | Guarantees | Failure mode | Severity |
|---|---|---|---|
| **ECDLP hard on the chosen curve** (P-256 or secp256k1) | Pedersen **binding** (PC-2/L-1), range-proof **soundness** (RP-2/L-1), IPA binding (IPA-2/L-1) | A discrete-log break lets an attacker equivocate a commitment (two openings) → forge balance/range proofs → **silent inflation** | **Catastrophic** |
| **`h`'s discrete log to `g` is unknown** (nothing-up-my-sleeve RFC 9380 gen) | Binding of every commitment | If `log_g(h)` were known, any commitment opens to any value → inflation | Catastrophic (mitigated by nothing-up-my-sleeve derivation, PC-1) |
| **Fiat-Shamir sound in the ROM** (challenges = `hash_to_scalar(transcript)`) | Non-interactive soundness of range proof + IPA (RP-2/L-3, IPA-2/L-3) | A ROM-uninstantiability attack on the concrete hash could forge a proof | High (assumed, not proved — L-3) |
| **Prover randomness is a real CSPRNG** (`gamma`, `sL/sR`, etc.) | **Hiding** of amounts (PC-3/L-3, RP-3 caveat) | Weak/reused blinding leaks the amount; predictable `sL/sR` can leak `v` | High (wallet TCB, §3c) |
| **Range proof attached to every output** | Non-negativity / no mod-`n` wraparound | A missing or forged range proof ⇒ hidden negative value ⇒ inflation (§3a) | **Catastrophic** — the single highest risk |

### 4.3 The highest-severity risk, stated once more, plainly

A **range-proof forgery ⇒ hidden negative output ⇒ silent inflation of the confidential supply, invisible to the plaintext supply invariant** (§3a). This is worse than a transparent inflation bug because the plaintext invariant (`chain.cpp:1398`) — Determ's strongest, always-on supply check — **cannot see it**. The confidential supply's integrity reduces entirely to range-proof soundness, which is **RP-2 (a literature reduction under ECDLP + ROM, backed by reject-witnesses, not a machine-checked extractor) + L-1**. The owner should weigh that the confidential-value guarantee is *strictly weaker in verifiability* than the transparent-value guarantee: transparent conservation is a cheap runtime assertion; confidential conservation is an unfalsifiable-at-runtime cryptographic assumption.

### 4.4 Replay, malleability, and the timing side channel (NC-4/L-4 becomes a REQUIREMENT)

- **Replay.** The existing nonce/`next_nonce` mechanism (`block.hpp:211`, per-account) prevents replay of transparent txs. Confidential txs need an equivalent: a **spent-commitment / nullifier set** (a new state namespace) so an output commitment cannot be double-spent. Without it, a confidential input could be consumed twice. This is new consensus state and new apply logic (part of the integration, not the library).
- **Malleability.** A confidential tx's proofs and commitments must be bound to the authorizing signature so a relayer cannot alter outputs. The **Schnorr-over-`h` balance-proof style (§1.2b) binds the transaction and is preferred for this reason.** If the reveal-`r` style (§1.2a) is used instead, a *separate* signature must cover all `V`'s + proofs + fee. Determ's transactions are already signed (`Transaction::sig`, `signing_bytes()`); the confidential fields must be inside `signing_bytes()`.
- **Timing side channel — the CT-hardening prerequisite.** The shipped range **prover** is **explicitly not constant-time**: `sc_add`/`sc_sub`'s conditional subtraction and the `pedersen_msm` zero-scalar skip branch on the **secret witness** (`v`'s bits, `sL/sR`) — `rangeproof.c:36-37` ("*Data-dependent subtract branch — owner-gated CT-hardening step*"), RP-NC-4 / L-4, IPA-NC-4, PC-NC-2. For a **library primitive with no on-chain prover** this is a deferred, owner-gated nicety. **For an on-chain confidential-transaction prover it is not optional.** A wallet that proves a transfer while an attacker measures timing can leak the hidden amount `v` (its bit pattern drives the branch) — defeating the entire point. Therefore:

> **The owner-gated constant-time hardening of the range prover (and the underlying `pedersen_msm` / `sc_add` / `sc_sub`) is a HARD PREREQUISITE for confidential-transaction deployment, not a follow-on.** It is promoted from NC-4/L-4 ("optional, owner-gated") to REQUIRED by this use. If Option B (secp256k1 / libsecp256k1-zkp) is chosen, that library's prover is already constant-time-hardened, which discharges this prerequisite — a further point in Option B's favor.

### 4.5 The one genuine free advantage: no trusted setup

Bulletproofs require **no trusted setup** — the generators are nothing-up-my-sleeve RFC 9380 hash-to-curve images (`pedersen.c`, PC-1/PC-9), with no toxic-waste ceremony and no per-circuit setup (unlike zk-SNARKs). This is a real, unqualified advantage of the Bulletproofs approach and should be stated as such: there is no ceremony to run, no ceremony-compromise risk, and no setup parameters to distribute or trust. It is one of the two reasons Bulletproofs (vs. Groth16 etc.) is the right primitive for a CT chain (the other being short, aggregatable proofs).

---

## 5. Non-goals and out-of-scope (so the owner knows what this does NOT design)

- **Sender/receiver privacy** (anon addresses) — separate track, `AnonAddressDerivationMigration.md`.
- **The receiver amount-communication channel** (encrypted memo / X25519 DH) — a hard prerequisite (§1.3), not designed here.
- **A Schnorr-over-P-256 signing primitive** — needed for §1.2b balance-proof style; not shipped, not designed here.
- **Proof aggregation** (multiple values / one argument) and the **single-multi-exp batched verifier** — needed for §3b DoS mitigation on the P-256 path; the shipped lib is single-value, non-batched, non-optimized (RP-NC-1/NC-2). libsecp256k1-zkp (Option B) has these.
- **The confidential account-balance variant** (§1.4) — reasoned about but explicitly not recommended as the first step.
- **Formal verification of the integration** — none exists; §7.

---

## 6. Estimated shape of the work (for owner sizing only — not a commitment)

This is offered so the owner can gauge magnitude, **not** as a plan. Roughly, in dependency order:
1. Curve decision (D1) — gates everything downstream.
2. **CT-hardening of the prover** (REQUIRED prerequisite, §4.4) — or discharged by choosing Option B.
3. Receiver amount channel + (if §1.2b) a Schnorr/DLEQ signing primitive.
4. Batched/aggregated verifier for DoS budget (§3b) — or Option B.
5. The consensus integration itself: new `TxType`, confidential-output + nullifier state namespaces, shield/unshield boundary, balance-proof verification in validate **and** apply (same bytes, same point — S-030 D1 discipline), block-digest binding of proofs, DoS param limits, fee pricing.
6. Light-client confidential read path (§3d).
7. A supply-conservation argument for the confidential pool + boundary, and a TLA/proof accounting analogous to the shipped soundness docs.

Each of 2-7 is a separately-reviewed, consensus-critical increment. This is a **multi-month** track, not an increment.

---

## 7. What's proven vs. designed-in-prose, and the honest bottom line

**Proven (bounded — the LIBRARY):**
- Pedersen commitment: binding (computational, ECDLP — PC-2/L-1), hiding (information-theoretic for uniform `r` — PC-3), additive homomorphism (PC-4, incl. mod-`n` wraparound), all dual-oracle byte-gated over a frozen corpus. `PedersenCommitmentSoundness.md`.
- IPA: completeness (IPA-1), special-soundness/binding (reduction, ECDLP+ROM — IPA-2/L-1/L-3), determinism (IPA-3), byte-conformance (IPA-4). `BulletproofsIPASoundness.md`.
- Range proof: completeness (RP-1), soundness (reduction to Bulletproofs §4, ECDLP+ROM, reject-witnesses **not** an extractor — RP-2/L-1/L-3), determinism (RP-3), byte-conformance (RP-4), proof-length contract (RP-5). `BulletproofsRangeProofSoundness.md`.
- **Limits that carry into this design:** soundness/binding are *reductions under ECDLP + ROM*, not machine-checked extractors (RP-2/IPA-2/PC-2 caveats, L-1/L-3); conformance is over a handful of frozen vectors + bounded `n` (L-2); the prover is **not constant-time** (NC-4/L-4); single-value, non-batched, non-aggregated (RP-NC-1/NC-2).

**Designed-in-prose only (UNPROVEN — this document):**
- **Everything in §1-§4.** The confidential-tx construction, the balance proof, the supply-conservation argument for the confidential pool, the state-commitment binding, the DoS budget, the light-client story, the migration, and the threat model are **design-stage prose**. There is no code, no test, no proof, and no TLA model for any of it. It is consensus-critical and would need the full soundness-accounting treatment the shipped library received *before* any of it could be trusted.

**The honest bottom line for the owner:** the *cryptographic building block* is in good shape (proven within stated limits). The *integration* is the hard, dangerous, unbuilt part — because it is where hidden amounts meet a live supply invariant, a live state commitment, a live consensus round budget, and a live light-client trust model. The single largest risk is that confidential-supply integrity has **no runtime check** and rests entirely on range-proof soundness (RP-2/L-1) — a strictly weaker verifiability posture than the transparent ledger's cheap always-on invariant. Nothing in this proposal should be built until the owner has decided the curve (D1), authorized the deviation from the documented secp256k1 plan if Option A is chosen, and committed to the CT-hardening prerequisite.

---

## 8. Decisions the owner must make (numbered)

1. **D1 — Curve.** Reuse the shipped **P-256** range-proof library (Option A: fast, in-tree, FIPS-capable, but a NIST curve and a deviation from the §2.Q1/v2.22 secp256k1 plan of record) **or** build a **secp256k1** range-proof lib via libsecp256k1-zkp (Option B: matches the plan + ecosystem + gets batching/aggregation/CT-hardening for free, but a multi-week second library + a vendored dependency + MODERN-profile-only). §2. *This proposal recommends neither; it is the owner's call. Note the §3-§4 integration design is largely curve-agnostic and could be approved independently of D1.*
2. **D2 — Adopt or not.** Approve the confidential-transaction track at all? This is a multi-month, consensus-critical, AI-drafted deviation that the FROST discipline requires the owner to explicitly authorize before any consensus code is written. Rejecting is a legitimate outcome.
3. **D3 — State model.** UTXO-style confidential-output pool (recommended — localizes the balance proof, leaves the transparent supply invariant §3a intact) **vs.** confidential account balances (not recommended — far harder). §1.4.
4. **D4 — Rollout / fork discipline.** Opt-in new `TxType` behind a feature/version gate (soft-fork-shaped) with an explicit answer to how old nodes treat confidential txs (reject-cleanly vs. fork). Genesis/param gate `confidential_enabled`; FIPS-profile availability follows from D1. §3f.
5. **D5 — Confidential-by-default or opt-in.** Are amounts confidential by default (stronger privacy, larger blocks, higher verify cost, no plaintext-amount analytics) **or** opt-in per transaction (weaker default privacy, but backward-compatible and cheaper)? §3f/§4.1.
6. **D6 — The CT-hardening prerequisite.** Commit to constant-time-hardening the range prover (and `pedersen_msm`/`sc_add`/`sc_sub`) **before** any on-chain proving — promoted here from optional (NC-4/L-4) to REQUIRED (§4.4). Choosing Option B (D1) discharges this via libsecp256k1-zkp's already-hardened prover. This is a gating prerequisite, not a follow-on.

---

## 9. Cross-references

| Reference | Role |
|---|---|
| `src/crypto/pedersen/rangeproof.c` + `include/determ/crypto/pedersen/rangeproof.h` | The shipped range-proof library this proposal would consume (`V = v·g + gamma·h`; `_prove`/`_verify`/`_proof_len`; caller-supplied randomness; `n ≤ 64`; not constant-time). |
| `docs/proofs/BulletproofsRangeProofSoundness.md` (RP-1..RP-6, NC-1..NC-4, L-1..L-4) | What is proven about the range proof + its limits (soundness = reduction under ECDLP+ROM; not CT; single-value). The §3a inflation risk ties to RP-2/L-1; the §4.4 CT prerequisite to NC-4/L-4. |
| `docs/proofs/BulletproofsIPASoundness.md` / `PedersenCommitmentSoundness.md` | The IPA + Pedersen commitment claims + limits the construction builds on (homomorphism PC-4; binding PC-2/L-1; hiding PC-3/L-3). |
| `docs/proofs/CRYPTO-C99-SPEC.md` §2.Q1/Q2 (lines 40-79), §3.7 (line 616), the profile table (lines 481-487), §3.19 (lines 1157-1279) | The curve decision of record (**secp256k1** for chain Bulletproofs), the FIPS-profile CT-unavailability note, and the shipped-library design entry. §2. |
| `src/chain/chain.cpp:1398-1420` + `include/determ/chain/chain.hpp:450-456` | The shipped supply-conservation invariant (`live_total_supply() == expected_total()`) that confidential value must not break. §3a. |
| `src/chain/chain.cpp:262-411` (`build_state_leaves`) | The state-commitment leaf structure (`"a:"` account leaf = `SHA256(balance ‖ next_nonce)`) a confidential-output namespace would extend. §3c. |
| `include/determ/chain/block.hpp:23-181` (`TxType`), `:205-221` (`Transaction`) | The plaintext-`amount`/`fee` transaction the confidential path forks from; the free `TxType` slot for `CONFIDENTIAL_TRANSFER`. §3e/§3f. |
| `light/trustless_read.cpp`, `src/node/node.cpp:3760-3860`, `include/determ/crypto/merkle.hpp:84` | The light-client trust model (committee-signed `state_root` + Merkle inclusion; does not re-execute or verify amounts) confidential reads must fit into. §3d. |
| `FROST_DEVIATION_NOTICE.md`; MEMORY *frost-deviation-discipline* | The governance discipline that makes this an owner-sign-off-required, AI-drafted proposal. §0. |
| `AnonAddressDerivationMigration.md` | The **separate** sender/receiver-privacy track CT does not address. §4.1. |
| Bünz et al., *Bulletproofs* (IEEE S&P 2018) §4; Maxwell, *Confidential Transactions*; Elements/Liquid + Grin/Mimblewimble | The external CT construction this maps onto Determ's ledger. |

---

## 10. Status

- **This document.** A design + threat-model **proposal** for owner review. Not a specification of shipped code. Nothing here is built, wired, tested, or proven.
- **The library it would consume.** Shipped and proven within stated limits (§7): `src/crypto/pedersen/` inc.1-5, additive, **no in-tree consumer** — this proposal is the design for that deferred consumer.
- **Gating.** Blocked on owner Decisions D1-D6 (§8). Per the FROST-deviation discipline, no consensus code may be written for this track until the owner explicitly authorizes it (D2) and resolves the curve (D1) and the CT-hardening prerequisite (D6).
- **Highest-severity risk to weigh (§3a/§4.3).** Confidential-supply integrity has no runtime cross-check and rests entirely on range-proof soundness (RP-2/L-1); a forged range proof ⇒ silent inflation invisible to the shipped supply invariant.
