# ShardRoutingSoundness — deterministic address-to-shard routing primitive soundness

This document formalizes the structural and security properties of Determ's **address-to-shard routing function** — the `crypto::shard_id_for_address` primitive implemented in `src/crypto/random.cpp:177-191`. It is the foundational map of the entire sharding subsystem: every cross-shard transfer's destination shard, every shard's "do I own this address?" decision, and every wallet's "which shard do I query?" decision routes through this single function.

Two adjacent proofs treat the *consumers* of this map — `CrossShardReceipts.md` (FA7, cross-shard atomicity / no double-credit) and `RegionalSharding.md` (FA8, regional pinning preserves FA1/FA4/FA6/FA7) — but **neither proves the routing function itself**. Both invoke, without proof, the routing equality `r.dst_shard == shard_id_for_address(tx.to, ...)` as a premise: FA7's central exactly-one-receipt theorem (`CrossShardReceipts.md` §61) asserts `r.dst_shard == shard_id_for_address(tx.to, …)` as a *given* about the emitted receipt, and FA8's receipt-verification argument (`RegionalSharding.md` §3.4) assumes the receiver and the producer compute the *same* destination shard. This document discharges the obligations both proofs lean on: that the map is a **deterministic total function** (same inputs ⇒ same shard, on every node and wallet for the chain's lifetime), that it **partitions** the address space (every address routes to exactly one in-range shard), that it is **near-uniform** (no shard is starved or overloaded beyond a negligible modulo bias), and that it is **salt-bound** (chain-lifetime salt fixity prevents cross-shard and cross-chain routing confusion).

The proof is partly structural (totality, range, determinism) and partly cryptographic (a near-uniformity argument under SHA-256 modeled as a random oracle, and a salt-binding argument under A2 collision resistance + the S-039 genesis-hash binding). Where a reduction is to a base assumption it is to **A2 (SHA-256 collision / second-preimage resistance)** or **A3 (preimage resistance)** as stated in `Preliminaries.md` §2.1, with one near-uniformity statement made in the **random-oracle idealization (A3-ROM)** and explicitly flagged as such.

**Companion documents.** `Preliminaries.md` (F0) §1.3 for hash notation (`H`, `‖`, big-endian integer encoding) and §2.1/§2.3 for SHA-256 collision/preimage resistance (A2/A3) + CSPRNG uniform sampling (A4); `CrossShardReceipts.md` (FA7) — the cross-shard atomicity proof whose receipt-routing premise this document discharges; `RegionalSharding.md` (FA8) — the regional-pinning corollary whose producer/receiver routing-agreement premise this document discharges; `CrossShardOutboundApply.md` (FA-Apply-13) §T-O4 — the source-side apply-path step that emits `dest_shard = shard_id_for_address(to, …)`, conditional on the totality + determinism proven here; `CrossShardSupplyConservation.md` (FA-Apply-17) — the K-shard aggregate identity that rests on each address belonging to exactly one shard; `MerkleTreeSoundness.md` — the sibling crypto-primitive proof in the same structural-plus-reduction style; `docs/SECURITY.md` §S-039 for the genesis-hash binding that pins the salt; `docs/PROTOCOL.md` for the cross-shard receipt flow. The empirical pinning is `determ test-shard-routing-determinism` (`tools/test_shard_routing_determinism.sh`, ~20 assertions / 8 scenarios) plus the `determ test-shard-routing` baseline (7 assertions) and the Chain-layer `tools/test_anon_routing.sh` / `tools/test_chain_shard_routing_config.sh`.

This proof covers a surface no existing FA-track document states as a theorem: the FA7 / FA8 / FA-Apply-13 / FA-Apply-17 line all *assume* the routing map is a deterministic, total, chain-consistent partition; this document proves it.

---

## 1. Scope

### 1.1 In scope

The single function in `src/crypto/random.cpp` and its header contract in `include/determ/crypto/random.hpp:48-58`:

| Function | Signature | Role |
|---|---|---|
| `shard_id_for_address` | `(addr : string, shard_count : u32, shard_address_salt : Hash) → ShardId` | Maps any address byte-string to one of `shard_count` shards via a salted hash + modulo fold. |

`ShardId` is `uint32_t` (`include/determ/types.hpp:19`). The function body, read directly off `random.cpp:177-191`:

```
ShardId shard_id_for_address(const std::string& addr,
                             uint32_t shard_count,
                             const Hash& shard_address_salt) {
    if (shard_count <= 1) return 0;                         // (L1) single-shard short-circuit
    Hash h = SHA256Builder{}
        .append(shard_address_salt)                         // (L2) salt prefix
        .append(std::string("shard-route"))                 // (L3) domain tag
        .append(addr)                                       // (L4) address bytes
        .finalize();
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | h[i];        // (L5) big-endian fold of first 8 bytes
    return static_cast<ShardId>(v % shard_count);           // (L6) modulo reduction
}
```

The chain-level consumer `Chain::is_cross_shard` (`src/chain/chain.cpp:198-201`) wraps it:

```
bool Chain::is_cross_shard(const std::string& to) const {
    if (shard_count_ <= 1) return false;
    return crypto::shard_id_for_address(to, shard_count_, shard_salt_) != my_shard_id_;
}
```

### 1.2 Out of scope

- **Region tagging / committee filtering** (`eligible_in_region`) — covered by `RegionalSharding.md` (FA8). Routing decides *which shard owns an address*; region filtering decides *which validators staff a shard's committee*. They are orthogonal.
- **Receipt admission / dedup mechanics** — covered by `CrossShardReceipts.md` (FA7), `CrossShardReceiptDedup.md` (FA-Apply-9), `AppliedReceiptRestore.md` (FA-Apply-12). This document proves only that producer and receiver agree on `dst_shard`; it does not re-prove no-double-credit.
- **Address derivation / normalization** — the anon-address byte form and its S-028 lowercase canonicalization are covered by `AnonAddressDerivationMigration.md` and `S028AnonAddressNormalization.md`. This document treats `addr` as an opaque byte-string and proves routing on whatever bytes it receives; §6.3 documents the S-028 composition only as a corollary.
- **The genesis-hash binding mechanism itself** — that `shard_address_salt` is one of the consensus-critical parameters folded into `compute_genesis_hash` (`src/chain/genesis.cpp:452`) is the subject of S-039; this document consumes that result as Lemma SR-0.

### 1.3 Threat model

The adversary `A_route` is the standard Byzantine adversary of `Preliminaries.md` §3.2, specialized to the routing surface. `A_route` may:

- Choose addresses adaptively, including addresses crafted to try to land on a target shard (a *routing-grind* attack) or to collide two distinct addresses onto whatever the attacker prefers.
- Propose blocks claiming a `dst_shard` that disagrees with the canonical routing of `tx.to` (a *misroute* attack).
- Attempt to replay a receipt routed under chain `X`'s salt into chain `Y` (a *cross-chain confusion* attack).

`A_route` may **not** break A1/A2/A3/A4 (`Preliminaries.md` §3.2) and may **not** alter the genesis-pinned `shard_count` / `shard_address_salt` without changing the genesis hash that honest nodes pin (S-039, Lemma SR-0).

---

## 2. Definitions and the genesis-binding lemma

**Definition (canonical routing map).** Fix a chain with genesis-pinned `S := shard_count ≥ 1` and `salt := shard_address_salt ∈ {0,1}²⁵⁶`. Define

$$\rho_{S,\,salt}(a) \;:=\; \texttt{shard\_id\_for\_address}(a, S, salt) \;\in\; \{0, 1, \dots, S-1\}.$$

For `S = 1`, `ρ ≡ 0` by line (L1). For `S ≥ 2`, write `D(a) := H(salt ‖ "shard-route" ‖ a)` for the 256-bit digest of line (L2)–(L4), and `fold(D) := Σ_{i=0}^{7} D[i] · 2^{8(7-i)} ∈ {0, …, 2⁶⁴−1}` for the big-endian 8-byte fold of line (L5). Then `ρ_{S,salt}(a) = fold(D(a)) mod S` (line L6).

**Lemma SR-0 (salt + count are chain-lifetime constants, pinned by the genesis hash).** On any chain, `S` and `salt` are immutable for the chain's lifetime and are bound into `compute_genesis_hash`.

*Proof.* `shard_count_` and `shard_salt_` are set once at chain construction (`chain.cpp:193,195` set them from the genesis config; `chain.cpp:1735-1736` restore them verbatim from a snapshot) and are never mutated by any apply branch — no `apply_transactions` branch writes either field (confirmed: the only writes are the constructor, the snapshot-restore path, and the explicit `set_sharding(...)` setter used at construction). `compute_genesis_hash` appends `cfg.shard_address_salt` (`genesis.cpp:452`) into the genesis-binding buffer per the S-039 closure, so two chains with different `salt` (or different `shard_count`) have different genesis hashes and are rejected by any honest node pinning the other's genesis. ∎

Lemma SR-0 is the hinge for every "all nodes agree" claim below: because `(S, salt)` is a single chain-wide constant, `ρ_{S,salt}` is a single chain-wide function — not a per-node or per-epoch quantity.

---

## 3. Theorem statements

**Theorem SR-1 (Determinism / chain-consistency).** For a fixed chain (fixed `(S, salt)` per Lemma SR-0) and any address `a`, every evaluation of `ρ_{S,salt}(a)` — on any node (beacon, any shard daemon), any wallet (`determ-wallet`), any light client (`determ-light`), at any height, in any process, on any platform — yields the **same** `ShardId`. Routing is a pure deterministic function of its three arguments.

**Theorem SR-2 (Totality + partition).** For every `S ≥ 1`, `ρ_{S,salt}` is a **total function** from the address byte-space `{0,1}*` into `{0, …, S−1}`: it is defined on every input (including the empty string), never throws, and returns exactly one in-range shard. Consequently the preimages `{ρ_{S,salt}^{-1}(j)}_{j=0}^{S-1}` form a **partition** of the address space — every address belongs to exactly one shard.

**Theorem SR-3 (Near-uniform load, A3-ROM).** Model `H` as a random oracle (A3-ROM, `Preliminaries.md` §2.1). For `S ≥ 2`, the routing distribution over a uniformly random address has, for each shard `j`,

$$\left| \Pr[\rho_{S,salt}(a) = j] - \tfrac{1}{S} \right| \;\le\; \frac{S}{2^{64}},$$

i.e. the modulo-fold bias is bounded by `S · 2⁻⁶⁴`. For any practical `S` (e.g. `S ≤ 2³²−1`, the `uint32_t` ceiling) the bias is `≤ 2⁻³²`, negligible.

**Theorem SR-4 (Salt-binding / no cross-chain confusion).** Under A2 (SHA-256 collision resistance) and Lemma SR-0, an adversary cannot make a receipt routed for shard `j` on a chain with salt `salt_X` route to shard `j` on a *different* chain with `salt_Y ≠ salt_X` other than with the probability that two random salts induce the same routing on a chosen address — i.e. `2⁻⁶⁴` per address per shard for the fold collision, and the cross-chain replay is independently barred because the two chains have distinct genesis hashes (SR-0).

**Theorem SR-5 (Misroute detection / producer-receiver agreement).** A block claiming a cross-shard receipt with `r.dst_shard ≠ ρ_{S,salt}(r.to)` is rejected by any honest validator's cross-shard receipt check, and conversely an honestly emitted receipt always carries `r.dst_shard = ρ_{S,salt}(r.to)`. Hence the producer and every receiver compute the **same** destination shard — the premise FA7 (§61) and FA8 (§3.4) assume.

**Corollary SR-5.1 (Routing-grind buys nothing safety-relevant).** An adversary who grinds addresses to land transactions on a chosen shard gains only the ability to *choose where its own funds live* — it cannot misroute another party's funds, double-route a single transfer, or break the partition (SR-2 + SR-5). Routing-grind is therefore a non-attack against safety; it is at most a load-distribution nuisance bounded by SR-3.

---

## 4. Proofs

### 4.1 Theorem SR-1 (Determinism)

`ρ_{S,salt}` is the composition of three deterministic stages:

1. **Hash stage (L2–L4).** `SHA256Builder.append` appends bytes in a fixed order. Note `shard_count` is *not* hashed — only `salt`, the literal domain tag `"shard-route"`, and the raw `addr` bytes enter the digest. SHA-256 is a deterministic function of its byte input (`Preliminaries.md` §1.3). The three appends are sequenced in fixed program order, so `D(a)` is a deterministic function of `(salt, a)`.
2. **Fold stage (L5).** The loop reads the first 8 bytes of `D(a)` in fixed index order `0..7` with a fixed big-endian shift schedule; `fold` is a pure integer function of `D(a)`. No floating point, no platform-dependent integer width is exposed (the accumulator is `uint64_t`, well-defined on every conforming target).
3. **Reduce stage (L6).** `v % shard_count` is well-defined integer modulo (`shard_count ≥ 2` on this branch, so no division by zero); the `static_cast<ShardId>` is a narrowing to `uint32_t` of a value already `< shard_count ≤ 2³²−1`, hence lossless.

No stage reads global mutable state, a clock, a PRNG, or any per-node configuration other than the three explicit arguments. By Lemma SR-0 the two non-address arguments `(S, salt)` are chain-wide constants. Therefore for a fixed chain, `ρ_{S,salt}` depends only on `a`, and every evaluation on every participant yields the identical `ShardId`. ∎

This is the result that makes a single chain-wide routing partition meaningful: a determinism break here would silently fork the chain at the routing layer (different nodes disagree on which shard owns an address), exactly the failure mode `tools/test_shard_routing_determinism.sh` scenario (1) pins by replay + cross-instance salt-rebuild assertions.

### 4.2 Theorem SR-2 (Totality + partition)

**Totality.** For `S ≤ 1` line (L1) returns `0` unconditionally — defined for every `a`, including `a = ""`. For `S ≥ 2`: `SHA256Builder` accepts an arbitrary-length byte string (the empty string included — the builder appends zero bytes and finalizes a well-defined digest of the salt + tag alone), the fold reads exactly the first 8 of the 32 output bytes (always present), and the modulo is defined because `S ≥ 2 > 0`. No branch throws, allocates unboundedly, or returns out of `{0,…,S−1}` (a modulo-`S` result is in `[0, S−1]` by definition). Hence `ρ` is total. (Scenario (7) of the determinism test pins the empty-address case; scenario (6) pins the `S=0`/`S=1`/`S=65536` boundary cases.)

**Range + partition.** The return value is `fold(D(a)) mod S ∈ {0,…,S−1}`, so `ρ: {0,1}* → {0,…,S−1}` is a well-defined function into the shard index set. Because `ρ` is a function (single-valued — SR-1), the family of preimages `P_j := {a : ρ(a) = j}` satisfies (i) `⋃_j P_j = {0,1}*` (totality) and (ii) `P_j ∩ P_{j'} = ∅` for `j ≠ j'` (single-valuedness). That is the definition of a partition: **every address belongs to exactly one shard.** ∎

The partition property is the unstated premise of FA-Apply-17 (`CrossShardSupplyConservation.md`): the K-shard aggregate identity `Σ_shards (Σ balances + …) = Σ genesis_total` requires that each address contributes its balance to exactly one shard's local sum, with no address double-counted across shards and none orphaned. SR-2 supplies precisely that.

### 4.3 Theorem SR-3 (Near-uniform load, A3-ROM)

Model `H` as a random oracle, so `D(a)` is uniform on `{0,1}²⁵⁶` for a fresh `a` (A3-ROM). Then `fold(D(a))` is uniform on `U := {0,…,2⁶⁴−1}` (it reads 64 independent uniform bits). The routing distributes `U` into `S` residue classes mod `S`. Write `2⁶⁴ = qS + r` with `0 ≤ r < S`; then `r` classes contain `q+1` of the `2⁶⁴` fold-values and `S−r` classes contain `q`. For shard `j`:

$$\Pr[\rho(a)=j] \in \left\{ \frac{q}{2^{64}},\; \frac{q+1}{2^{64}} \right\}, \qquad \left|\Pr[\rho(a)=j] - \tfrac1S\right| \le \frac{S}{2^{64}}.$$

Concretely: `1/S − q/2⁶⁴ ≤ (S − r)/(S · 2⁶⁴) ≤ S/2⁶⁴` and `(q+1)/2⁶⁴ − 1/S ≤ r/(S·2⁶⁴) ≤ 1/2⁶⁴`, so the two-sided deviation is bounded by `S/2⁶⁴`. For `S ≤ 2³²−1` this is `< 2⁻³²`. ∎

The bound matches the source comment ("Bias is negligible at S << 2^64", `random.cpp:186-187`) and is empirically pinned by scenario (4) of `tools/test_shard_routing_determinism.sh`: 1000 anon addresses over `S=8` shards yield an empirical per-shard standard deviation near the binomial(1000, 1/8) ideal (≈10.5), catching any modulo-bias or salt-truncation regression that would skew the load. The near-uniformity is a *liveness/load* property (no shard is starved), not a safety property — safety holds regardless of how addresses distribute.

### 4.4 Theorem SR-4 (Salt-binding)

Two attacks are barred separately.

**(a) Cross-chain replay.** A receipt produced on chain `X` (salt `salt_X`) replayed onto chain `Y` (salt `salt_Y ≠ salt_X`) is rejected before routing is even consulted: by Lemma SR-0 the two chains have distinct genesis hashes, so chain `Y`'s nodes pin a genesis that chain `X`'s blocks do not extend, and the receipt's carrying block fails V1 (prev-hash chain to `Y`'s genesis). The salt-binding here is *structural*, inherited from S-039.

**(b) Salt-collision routing-confusion.** Suppose `A_route` wants an address `a` to route identically under two different salts, `ρ_{S,salt_X}(a) = ρ_{S,salt_Y}(a)`, to make a precomputed misroute table portable. This requires `fold(H(salt_X ‖ tag ‖ a)) ≡ fold(H(salt_Y ‖ tag ‖ a)) (mod S)`. Under A3-ROM the two digests are independent uniform 256-bit strings, so their folds collide mod `S` with probability `≤ 1/S + S/2⁶⁴` (a single residue match plus the SR-3 bias); for a *specific* target shard the bare fold-equality probability is `2⁻⁶⁴`. Finding a salt pair + address that *systematically* preserves routing across many addresses would require a second-preimage / structural break of SHA-256, contradicting A2/A3. ∎

Because (a) already bars any cross-chain replay structurally, (b) is a defense-in-depth statement: even absent the genesis-hash gate, the salt prefix makes routing tables non-portable across chains. Scenario (5) of the determinism test pins the salt-sensitivity empirically (a fixed address routes to different shards across 1000 distinct salts, hitting every shard `0..7`), and scenario (2) pins single-byte salt avalanche.

### 4.5 Theorem SR-5 (Misroute detection / producer-receiver agreement)

**Honest emission.** The source-side apply path computes `dest_shard = shard_id_for_address(to, shard_count_, shard_salt_)` when emitting an outbound receipt (`CrossShardOutboundApply.md` T-O4; the cross-shard branch at `chain.cpp:1205`). By SR-1 this equals `ρ_{S,salt}(r.to)` deterministically.

**Receiver check.** A receiving validator independently recomputes `ρ_{S,salt}(r.to)` from the same chain-wide `(S, salt)` (Lemma SR-0) and compares against `my_shard_id_` and against the claimed `r.dst_shard`. The chain's own `is_cross_shard` guard (`chain.cpp:198-201, 998, 1020-1021`) rejects a receipt whose routed destination does not match the admitting shard. A block claiming `r.dst_shard ≠ ρ_{S,salt}(r.to)` is therefore rejected: either the destination shard sees `ρ_{S,salt}(r.to) ≠ my_shard_id_` (the receipt was misaddressed to it) and drops it, or no shard's `my_shard_id_` equals the forged `r.dst_shard` consistent with `ρ`, so the receipt is never admitted anywhere — the value cannot be double-spent into a shard that does not legitimately own `r.to`.

By SR-1 the producer's `ρ_{S,salt}(r.to)` and every receiver's `ρ_{S,salt}(r.to)` are the *same* value. This is exactly the producer-receiver routing-agreement premise that FA7's exactly-one-receipt theorem (`CrossShardReceipts.md` §61, the `r.dst_shard == shard_id_for_address(tx.to, …)` clause) and FA8's receipt-verification argument (`RegionalSharding.md` §3.4) take as given. SR-5 discharges it. ∎

**Executed gate.** SR-5's misroute reject is gated by `determ test-sr5-misroute-receipt` (`tools/test_sr5_misroute_receipt.sh`, FAST, both platforms): a receipt with `dst_shard ≠ ρ(to)` (and a second leg claiming the producer's own shard) is rejected by `check_cross_shard_receipts` with a `"dst_shard mismatch"` — driven via the `check_cross_shard_receipts_for_test` seam — while a correctly-routed control is accepted; the falsify (deleting the reject) lets the misrouted receipt through (`A_misroute` succeeds). See `ProofClaimGateTraceability.md` §3g.

**Corollary SR-5.1.** A routing-grind adversary choosing `a` to land on a target shard `j` exercises only the public function `ρ` on its *own* addresses; by SR-2 the result is a single in-range shard, by SR-5 every node agrees on it, and by SR-1 the choice is fixed once `a` is fixed. The adversary cannot (i) make a single transfer route to two shards (SR-2 single-valuedness), (ii) misroute another party's `to` address (SR-1 — routing depends only on `a`, not on who submits the tx), or (iii) cause a receiver to admit a receipt for an address it does not own (SR-5). The only "gain" is choosing the home shard of the adversary's own funds — a load-placement choice bounded in aggregate effect by SR-3. ∎

---

## 5. Adversary table

| Adversary | Goal | Defeated by | Residual bound |
|---|---|---|---|
| `A_nondeterm` | Make two honest nodes route the same address to different shards (silent fork at routing layer) | SR-1 (pure function of 3 args) + SR-0 (chain-wide `(S,salt)`) | 0 (structural) |
| `A_orphan` | Craft an address that routes to *no* shard or *two* shards | SR-2 (totality + partition) | 0 (structural) |
| `A_starve` | Skew load so one shard holds a disproportionate share via address choice | SR-3 (near-uniform, A3-ROM) | per-shard bias `≤ S·2⁻⁶⁴` |
| `A_grind` | Choose where the adversary's own funds live | not an attack (SR-5.1) — only self-placement, no safety impact | n/a (nuisance only) |
| `A_misroute` | Propose a block claiming `r.dst_shard ≠ ρ(r.to)` to redirect funds | SR-5 (receiver recomputes `ρ` + `is_cross_shard` guard) | 0 (structural reject) |
| `A_crosschain` | Replay a chain-`X` receipt onto chain `Y` (salt mismatch) | SR-4(a) (distinct genesis hash, S-039) + V1 prev-hash chain | 0 (structural) |
| `A_saltport` | Build a routing table portable across two salts | SR-4(b) (salt prefix → independent digests under A3-ROM) | `2⁻⁶⁴` per (address, target shard) |

Every safety-relevant row reduces to `0` (structural) or to a cryptographic A2/A3-ROM bound of `≤ 2⁻⁶⁴`. The single non-zero "soft" row (`A_starve`) is a *load* concern, not a safety one, and is bounded negligibly.

---

## 6. Discussion

### 6.1 Why the fold reads 8 bytes, not 4

`ShardId` is `uint32_t`, so a 4-byte fold would already exceed any realistic `shard_count`. Reading 8 bytes (a `uint64_t` accumulator) makes the modulo bias `S/2⁶⁴` rather than `S/2³²` — a free upgrade that keeps the bias negligible even at the `uint32_t` ceiling on `shard_count`. SR-3's bound depends on this width; a regression that truncated the fold to 4 bytes would loosen the bias to `S/2³²` (`≈ 1` at the `uint32_t` ceiling) and is caught by the uniformity assertion in scenario (4) of the test.

### 6.2 Routing operates on the byte form, not the logical owner

`ρ` hashes the raw `addr` byte-string. The same logical owner expressed as a registered domain string vs. an anonymous bearer-wallet address are *different byte-strings* and therefore generally route to *different* shards (test scenario (3)). This is by design: routing is a property of the address bytes, and the cross-shard machinery (FA7) handles transfers between any two shards regardless of which logical entity owns the endpoints. No theorem here depends on domain/anon equivalence.

### 6.3 Composition with S-028 anon-address normalization

For anonymous addresses the ingress layer applies S-028 lowercase canonicalization (`normalize_anon_address`) *before* routing, so two case-variant spellings of one bearer wallet collapse to one canonical byte-string and therefore one shard (test scenario (8)). This is a composition with the upstream S-028 result (`S028AnonAddressNormalization.md`), not a property of `ρ` itself: `ρ` is deterministic on whatever bytes it receives (SR-1); S-028 guarantees the bytes are canonical. The two results compose cleanly — SR-1 needs no modification.

### 6.4 What this proof does NOT cover

- **Optimal shard count selection.** How an operator should choose `shard_count` for a target throughput/latency profile is a deployment question, not a theorem. SR-3 only bounds the per-shard load *bias* for any fixed `S`.
- **Dynamic resharding.** The current protocol fixes `(S, salt)` at genesis (SR-0). Re-sharding a live chain (changing `S`) would change every address's home shard and is a v2+ migration design item, not covered here.
- **Address-space adversarial clustering across an honest-but-correlated population.** SR-3 assumes addresses are effectively random under A3-ROM; a real population whose addresses are adversarially correlated could in principle cluster, but doing so requires grinding SHA-256 preimages (A3) to a chosen residue, which is itself bounded by SR-4(b) per target.

---

## 7. Implementation cross-reference

| Component | Source |
|---|---|
| Routing primitive | `src/crypto/random.cpp:177-191` (`shard_id_for_address`) |
| Header contract | `include/determ/crypto/random.hpp:48-58` |
| `ShardId` type | `include/determ/types.hpp:19` (`uint32_t`) |
| Chain-level `is_cross_shard` wrapper | `src/chain/chain.cpp:198-201` |
| Cross-shard branch consuming `ρ` (source debit + outbound emit) | `src/chain/chain.cpp:1205` (and the `is_cross_shard` guards at `752`, `998`, `1020-1021`) |
| Salt + count set at construction | `src/chain/chain.cpp:193-195` (set), `1735-1736` (snapshot restore) |
| Salt folded into genesis hash (S-039) | `src/chain/genesis.cpp:452` (`compute_genesis_hash`) |
| Genesis-config salt field | `include/determ/chain/genesis.hpp:191` (`shard_address_salt`, CSPRNG-generated at build) |
| Empirical pin (determinism + uniformity + salt-sensitivity) | `determ test-shard-routing-determinism` → `tools/test_shard_routing_determinism.sh` (~20 assertions / 8 scenarios) |
| Empirical pin (baseline) | `determ test-shard-routing` (7 assertions) |
| Chain-layer integration pins | `tools/test_anon_routing.sh`, `tools/test_chain_shard_routing_config.sh` |

A reviewer can confirm routing soundness by:

1. Reading `shard_id_for_address`: it is a pure deterministic projection of `(addr, shard_count, salt)`, no randomness, no global state (SR-1).
2. Confirming `shard_count_` / `shard_salt_` are written only at construction + snapshot restore, never in any apply branch (SR-0), and that `shard_address_salt` is appended into `compute_genesis_hash` (S-039).
3. Confirming the receiver-side `is_cross_shard` guard recomputes `ρ` rather than trusting a claimed `dst_shard` (SR-5).

---

## 8. Conclusion

SR-1 through SR-5 establish that the address-to-shard routing primitive is a **deterministic, total, chain-consistent partition** of the address space, near-uniform under A3-ROM and salt-bound under A2 + S-039. These are precisely the premises that FA7 (`CrossShardReceipts.md`, the `dst_shard == shard_id_for_address(...)` clause), FA8 (`RegionalSharding.md` §3.4, producer/receiver routing agreement), FA-Apply-13 (`CrossShardOutboundApply.md` T-O4, source-side emission), and FA-Apply-17 (`CrossShardSupplyConservation.md`, every address belongs to exactly one shard) invoke without proof. This document closes that obligation: the cross-shard atomicity and aggregate-supply theorems rest on a routing map that is now proved to be a single, deterministic, total, chain-wide partition — not assumed to be one.

The remaining gaps (optimal shard-count selection, dynamic resharding) are deployment/roadmap concerns; they do not undermine the per-property routing soundness proved here.

## C99 local routing query (2026-09-22)

This section alone specifies the new C99 consumer. It does not inherit the C++
receipt-validation, genesis-authentication or load-security claims above.

`shard_routing_for_pubkey` accepts exactly 32 account-key bytes and a configuration
with `1 <= shard_count <= UINT32_MAX`. It encodes the account as the existing
66-byte lowercase `0x` plus hexadecimal key address and computes
`BE64(SHA256(salt32 || "shard-route" || address66)[0:8]) % shard_count`.
For one shard the result is zero. The folding shifts an unsigned 64-bit value at
most eight times and the modulus is nonzero; the result is uniquely defined and
less than the count. Identical key, salt and count produce identical results. No
curve validity, account registration, randomness or population balance follows
from accepting arbitrary 32 bytes as a routing input.

All storage is bounded independently of the count; there is no per-shard arena or
new heap allocation. Invalid pointers, key length or zero count return an error
without writing the result. Initialization copies the full salt and rejects an
invalid configuration without modifying its destination.

`determ-node` parses `--routing-shards` as a nonzero u32 decimal and
`--routing-salt` as exactly 64 hexadecimal digits once, before starting services.
Defaults are one shard and 32 zero bytes. These settings are **local inputs** to the query and optional inbox below,
not an authenticated genesis or a new consensus configuration mechanism. RPC cannot
change them. `get_shard_for_pubkey` takes exactly `params:{"pubkey":"<64 hex>"}`
and returns the normalized address, shard ID, count, salt, `scope:"routing-query"`,
`config_source:"local"` and `consensus_enforced:false`. Uppercase input normalizes
before hashing. Absence of configuration returns unavailable.

This method validates its complete request envelope with a 512-byte bound. It
rejects unknown/duplicate fields, malformed separators, trailing data and escaped
strings. Its optional ID is null, an integer of at most 20 characters, or an
unescaped printable ASCII string of at most 32 characters. Invalid params retain
a valid request ID. Responses must fit the supplied output buffer. These narrow
endpoint rules do not establish strict JSON handling by unrelated legacy methods.

`test-shard-routing` pins 25 independently computed vectors over five salt/key
combinations and counts 1, 3, 7, 65536 and UINT32_MAX, plus failure-output invariants.
`test-rpc-shard-routing` tests dispatch, context isolation, malformed inputs, bounds
and ID correlation. The `determ-node` CI smoke starts actual local HTTP servers
with default and configured inputs and checks their replies and immutable settings.
Isolated mutations target the domain, salt, folding width, zero count, key length,
request bounds/duplicates, error correlation and the node's routing-context wiring.
This is a useful routing consumer. The signed pending inbox below is a separate
receiver; ownership at apply, election and cross-shard execution remain unimplemented.


## C99 signed pending inbox (2026-09-22)

**Scope.** `pending_transfer_submit` and the node's opt-in
`submit_pending_transfer` RPC retain signature- and routing-checked messages for
local inspection. They do not check balances, nonce readiness, aggregate spending,
fees, block eligibility or inclusion. The inbox has no persistence, gossip,
expiration or drain-to-execution path. It is not a production mempool or a ledger
acceptance rule. The event loop serializes access; separate buckets establish a
storage boundary, not parallel execution or freedom from cross-shard locks.

**Format and verification.** The supported subset is exactly the existing
397-byte anonymous, payload-empty, PQ-empty TRANSFER frame. Both addresses are
66-byte `0x` plus lowercase hex. The first and third 32-byte core slots hold ASCII
address prefixes, as in C++ `Transaction::encode_frame`, despite the C99 codec's
`sender_pubkey` / `recipient_pubkey` field names. Full decode/reencode equality
rejects alternate padding/reserved bytes; exact length rejects optional trailers.
Raw account keys are derived from the addresses. The verified 195-byte preimage is
`type_u8 || genesis32 || shard_BE32 || from66 || 0 || to66 || 0 || amount_BE64 ||
fee_BE64 || nonce_BE64`, matching C++ `Transaction::signing_bytes`. Its SHA-256 must
equal the supplied hash exactly, including when that supplied hash is zero.
Ed25519 verification and a separate sender small-order rejection are mandatory.

The pool copies a nonzero u32 shard count, full salt and exact genesis identity at
initialization. The sender's computed route must equal the transaction's signed
shard ID; the destination route must be the same. Cross-shard transactions return
unsupported here rather than inventing a settlement rule. Zero genesis is a literal
identity, never a wildcard. These are local pinned inputs; no authenticated genesis
loader or membership proof is inferred. Signatures cover chain and shard; the
standalone ledger's different 88-byte preimage is not substituted for them.

**State invariant and proof.** Initialization creates empty caller-owned buckets.
Every insertion/replacement first validates the complete frame, hash, signature,
sender key and context/routing against the copied configuration. Thus, by induction,
every retained entry passed those checks under that same configuration. Authentication
also precedes duplicate lookup, so a forged known hash cannot acknowledge or displace
an incumbent. Entries own their complete frame; caller buffer reuse cannot change it.
The caller keeps pool/configuration/buckets unmodified, supplies disjoint buffers
and serializes access, as stated by the API contract.

For a resident `(sender, nonce)`, a valid lower data hash replaces the entry; an
equal hash leaves its existing signature bytes, and a greater hash refuses. This
applies only to pending alternatives and does not rank blocks. The hash omits the
signature; no signature uniqueness or identical-frame convergence is claimed.
A lower-hash signed alternative can be stale or unaffordable and still displace an
incumbent here. This inbox therefore does not yet implement the assembly/requeue
rule among state-valid alternatives; any future execution consumer must revalidate
and define recovery of discarded alternatives.
The bucket is sorted by raw sender bytes and unsigned nonce. Different nonce slots
are not asserted to be jointly executable. At most four entries occupy a bucket,
and at most eight caller-supplied buckets exist, independently of configured S.
Capacity rejects a new slot or shard before mutation; lower-hash replacement of a
resident slot remains possible when full. Every negative return leaves the pool,
buckets and result/snapshot output unchanged. This is bounded memory, not fair
admission: unfunded signing keys can fill it. With a finite capacity, arrival order
can determine which distinct slots/shards are retained.

**Consumer.** `--pending-genesis <64 hex>` explicitly enables the inbox and requires
an RPC port. Count/salt come from the existing startup routing flags. Without the
flag both pending methods return disabled. Submit takes only
`params:{"frame":"<794 hex>"}`; list takes only `params:{"shard_id":<u32>}` and
returns up to four complete frame hex strings. Hex is a human-readable RPC view;
owned transaction bytes and checked-in signed fixtures are canonical binary.
Both methods use a closed 1024-byte envelope, with the routing query's bounded ID
forms and duplicate/unknown-key rejection. Successful replies identify
`scope:"pending-signature-and-routing"`, `config_source:"local"`,
`state_validated:false` and the copied chain/routing configuration. Submit requires
a 512-byte response capacity before calling the mutating function. The largest
successful reply is 481 bytes plus NUL (32-character string ID, two maximum u32s,
three 64-character hex strings, nine-character status); errors are shorter. Thus an
insufficient output buffer cannot admit a transaction and then lose its response.
List is read-only and refuses truncated output.

The core adds no dynamic allocation. Ed25519 verification of this fixed 195-byte
preimage uses the bounded automatic buffer documented in
[K2_VDF_Soundness.md](K2_VDF_Soundness.md); generic longer-message crypto callers
retain their existing allocation fallback. This does not claim an allocation-free
runtime for arbitrary unrelated node features or C library internals.

**Verification contract.** `test-pending-transfer` exercises the receiving library
with independently signed binary fixtures, strict encoding/signing/context checks,
small-order forgery, authenticated duplicate/conflict decisions, full-capacity
replacement, sparse large shard counts, owned input lifetime and rejection neutrality.
`test-rpc-pending-transfer` checks the actual dispatch grammar, configuration
isolation, signature checks on duplicate submissions and output preflight. The node
smoke submits and retrieves exact signed frames over HTTP with default/non-default
configuration and verifies disabled-by-default behavior. Independent review and the
fresh-build mutation results are recorded in the decision log; tests establish the
stated code obligations, not missing ledger or consensus properties.


### HTTP framing boundary

The C99 HTTP transport locates framing fields only in complete CRLF-delimited
header lines. POST requires exactly one case-insensitive `Content-Length` field
with a positive decimal value and optional surrounding SP/HTAB; duplicate length
fields, trailing junk and `Transfer-Encoding` are refused before RPC dispatch.
A similarly named header or text in a header value/body is not a framing field.
This replaces the nonportable GNU `strcasestr` call, whose declaration is absent
under the Linux build's POSIX feature macros.

The receive buffer reserves one byte for its terminating NUL. After locating the
header terminator, the remaining body capacity is
`HTTP_RPC_BUF_SIZE - 1 - header_length`. Each decimal step is checked against that
capacity before multiplication/addition. A complete body therefore has a
representable total length within the actual receive capacity. Dispatch waits
until all declared bytes have arrived. Invalid/oversized framing returns an HTTP
error without reaching pending-inbox mutation. This bounds this POST framing
path; it is not a claim of complete HTTP conformance or production RPC hardening.
Actual socket tests exercise case variation, fragmented delivery, malformed
framing with pending-state snapshots and the reserved-byte boundary.
