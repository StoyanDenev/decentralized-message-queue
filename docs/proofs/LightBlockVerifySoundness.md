# LightBlockVerifySoundness — self-contained OFFLINE single-block verifier (`determ-light block-verify`)

This document proves the soundness of the `determ-light block-verify` subcommand: a **composite, one-shot, fully OFFLINE single-block verifier** that an operator runs against one block JSON + one committee JSON to obtain, in a single invocation, a PASS/FAIL verdict over three independently-characterizable checks — STRUCTURE (`Block`-shape well-formedness), TX-ROOT (the daemon's `tx_root` accept gate, recomputed locally), and SIGS (K-of-K, or `⌈2K/3⌉` under `--bft`, Ed25519 committee-signature verification over a digest the light client **recomputes itself**). It conjoins the three into one verdict with a monitor-friendly exit code (`0` all pass, `2` a check failed, `1` args/parse error).

```
determ-light block-verify --block <file> --committee <file> [--bft] [--json]
```

**The load-bearing distinction — and the whole point of this proof.** `block-verify` is the **light-client analogue** of `determ-wallet block-verify` (proved in `OfflineBlockVerifySoundness.md`, BV-1/BV-2/BV-3), but it is **strictly stronger**. The wallet does **not** link the chain library (a deliberate lean-TCB choice), so it cannot compute `compute_block_digest(b)`; its SIGS check verifies committee signatures over an **operator-supplied** `--block-digest`, and its soundness (BV-2 / `OfflineBlockVerifySoundness.md` §5 F-BV2) is therefore *conditional* on that supplied digest being the block's true digest. `determ-light` **does** link the block/digest code: its `verify_block_sigs` calls `light_compute_block_digest(b)` — a byte-for-byte copy of `src/node/producer.cpp::compute_block_digest` (per the `light/verify.cpp:32-56` KEEP-IN-SYNC comment) — and so **recomputes the digest from THIS block's own fields**. Consequently the light client's SIGS check is **UNCONDITIONAL**: it verifies that the supplied committee actually signed *this block's true digest*, with **no operator-supplied-digest trust boundary**. This is `block-verify`'s strict improvement over the wallet sibling, and it is the content of theorem **LBV-2** below.

**A note on what "composite" means here.** Like the wallet sibling, `block-verify` composes *checks*, not bare cryptographic primitives, over a *single local block JSON* with **no network, no RPC, no daemon, no genesis anchor, and no chain-continuity context**. It is a single-block predicate, not a chain-walk (contrast `LightClientThreatModel.md`'s `verify-chain` composite, T-L1+T-L2). This narrows what a PASS can assert (§5) and is the source of every honest limitation in §findings — chief among them the **committee-provenance boundary** (§5 F-LBV3): the light client proves the block is signed by the *supplied* committee, not that the supplied committee is the genuine height-correct one.

**Canonical assumption labels.** Per `Preliminaries.md §2.0`: **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision resistance (§2.1). `block-verify` reduces to **A1** (SIGS) + **A2** (TX-ROOT) only; A3 and A4 are not used.

**Companion documents.**
- `OfflineBlockVerifySoundness.md` (BV-1/BV-2/BV-3/F-BV2) — the **wallet sibling this contrasts with**. BV-1 (the wallet's TX-ROOT byte-equivalence) is mirrored here as LBV-1; BV-2 (the wallet's SIGS, **conditional** on a correct operator-supplied digest) is the result LBV-2 strictly improves upon — LBV-2 is BV-2 with the digest conditional **discharged** by self-recomputation.
- `LightClientThreatModel.md` (T-L1, T-L2, the `A_daemon` adversary model, Lemma L-2 `light_compute_block_digest` byte-equivalence) — `block-verify` reuses `verify_block_sigs` (the T-L2 primitive) but in an **OFFLINE single-block** context with **no genesis anchor** (no T-L1) and **no chain-continuity walk**. The committee-provenance caveat is exactly `LightClientThreatModel.md` §6.5 / F-1 (genesis-only committee map), here surfaced as the residual honest boundary.
- `BatchSigningSoundness.md` (BS-3, the per-signer loop) — SIGS's per-creator verification loop is a faithful `N`-fold replication of the single-sig verify primitive with no cross-signer state; LBV-2's no-cross-signer-channel argument instantiates BS-3 for the committee-sig loop.
- `Safety.md` (FA1) — the K-of-K (or `Q = ⌈2|K_h|/3⌉` BFT) per-block signature-set safety primitive the light client consumes per block.
- `Preliminaries.md` (F0) §2.0 (assumption labels), §2.1 (A2), §2.2 (A1).
- `MerkleTreeSoundness.md` — cited **to disclaim**: `tx_root` is a flat sorted-dedup-union SHA-256 commitment, **NOT** a Merkle tree; MT-1..MT-5 do not apply (§2.1).

---

## 0. Implementation status

**`int cmd_block_verify(int, char**)` is IMPLEMENTED and SHIPPED in `light/main.cpp:652-805`** (dispatched on `block-verify` at `:5850`; help text at `:110-114`). It is exercised offline by `tools/test_light_block_verify.sh` (boots a 3-node cluster, fetches block 1 as a FULL `Block` via `determ block-info 1 --json` plus the committee via `determ validators --json`, then runs `block-verify` locally: happy-path PASS + four fail-closed negatives — tampered `tx_root`, tampered `creator_block_sig`, wrong committee pubkey, missing field).

The composed verification cores are read directly off source:
- **TX-ROOT** — recomputed inline in `cmd_block_verify` (`light/main.cpp:728-761`): a `std::vector<Hash>` filled from `creator_tx_lists`, then `std::sort` + `std::unique`, then `SHA256(concat)`, compared against the stored `tx_root` (case-normalized). This mirrors `src/node/producer.cpp::compute_tx_root` (`:262-270`) and the light client's own `light_compute_tx_root` in `light/verify_tx_inclusion.cpp:35-43`.
- **SIGS** — delegated to `determ::light::verify_block_sigs` (`light/verify.cpp:190-283`), which calls `light_compute_block_digest` (`light/verify.cpp:57-92`) to recompute the digest **internally**, then per-creator Ed25519-verifies (`determ::crypto::verify`) against it, enforcing `required = bft ? (2K+2)/3 : K`.
- **STRUCTURE** — a pure well-formedness predicate over the parsed JSON (`light/main.cpp:692-726`): seven required fields present and correctly typed (`index`, `prev_hash`, `timestamp`, `creators[]`, `creator_tx_lists[]`, `tx_root`, `creator_block_sigs[]`), `creators[]` non-empty.

---

## 1. Scope

### 1.1 In scope

The `determ-light block-verify` composite. Its control flow, read off `light/main.cpp:652-805`:

1. **Argument parse + validation.** `--block` and `--committee` are required; `--bft`, `--json` are optional. An unknown arg (`:661-664`), a missing `--block`/`--committee` (`:666-669`), an unreadable / non-JSON file (`:672-678`), or a non-object block (`:683-686`) → `return 1` (args/parse error) before any check verdict is recorded. A `{block:{...}}` envelope **is** transparently unwrapped *only* when it lacks a top-level `creator_tx_lists` (`:679-682`), so both the `block-info --json` envelope shape and the raw `Block` shape are accepted.

2. **STRUCTURE check (`:692-726`).** A pure well-formedness predicate: the seven required fields are present and of the right JSON type (string / number / array), and `creators[]` is non-empty. STRUCTURE PASS ⟺ the JSON is a syntactically well-formed `Block` envelope.

3. **TX-ROOT check (`:728-761`), gated on STRUCTURE PASS.** Build the union `uni` of every 32-byte hash across `creator_tx_lists` (each entry hex-decoded to `Hash` via `from_hex_arr<32>`), `std::sort` + `std::unique` it, compute `SHA256(‖_{h∈uni} h)`, and byte-compare against the case-normalized stored `tx_root`. TX-ROOT PASS ⟺ `computed == stored`. If STRUCTURE FAILed, TX-ROOT is recorded as **SKIP** (`:760`).

4. **SIGS check (`:763-780`), gated on STRUCTURE PASS.** Call `verify_block_sigs(block_json, committee_json, bft)`; SIGS PASS ⟺ `r.ok`. The verifier **recomputes the digest internally** (`light_compute_block_digest`), confirms every `creators[i]` is in the supplied committee, requires `creator_block_sigs.size() == creators.size()`, Ed25519-verifies each non-sentinel signature against the recomputed digest, and enforces `valid ≥ required`. If STRUCTURE FAILed, SIGS is recorded as **SKIP** (`:779`).

5. **Aggregate verdict + exit (`:782-804`).** `overall = (failed == 0)`. Exit `0` iff `overall`; exit `2` iff any check FAILed; exit `1` on the args/parse faults of step 1. `--json` emits an aggregate object (`audit`, `passed`, `failed`, `checks[]`); human mode emits a per-check summary. Output is read-only over the verdicts.

### 1.2 The three components

| Component | Implementation basis | What it establishes | Backing |
|---|---|---|---|
| **STRUCTURE** | `light/main.cpp:692-726` (new predicate) | The block JSON is a syntactically well-formed `Block` envelope (seven fields present, correct types, `creators[]` non-empty) | Structural; no cryptographic assumption (LBV-3 §3.3) |
| **TX-ROOT** | `light/main.cpp:728-761` | The block's stored `tx_root` equals the canonical commitment over its `creator_tx_lists` — **byte-identical to the daemon's accept gate** | A2 (LBV-1 §3.1) |
| **SIGS** | `verify_block_sigs` (`light/verify.cpp:190-283`) | A quorum of valid Ed25519 committee signatures exist over **`light_compute_block_digest(b)` — recomputed from THIS block** | A1, **UNCONDITIONAL** (LBV-2 §3.2) |

### 1.3 Out of scope (intentional — the verifier's coverage boundary)

- **Committee provenance.** SIGS verifies signatures against the **operator-supplied** `--committee` map. `block-verify` proves the block is signed by *that supplied committee*; it does **not** prove the supplied committee is the genuine, height-correct committee. For full trust-minimization the committee must be the genesis/chain-derived set — derived trustlessly by the sibling commands `determ-light verify-chain` (`light/main.cpp:930`, anchor + walk + per-block sig verify) and `committee-at-height` (`light/main.cpp:204`, report committee-verified creators at block H). §5 F-LBV3.
- **Semantic / consensus validity.** STRUCTURE is *well-formedness*, not semantic validity. A PASS does not assert `index` follows its predecessor, that `prev_hash` links to a real prior block, that `timestamp` is in-window, that `creators[]` is the protocol-selected committee for that height, or that any transaction in `creator_tx_lists` is itself valid (signed, nonce-ordered, balance-covered). Those are chain-state / apply-layer properties (`Safety.md`, the FA-Apply track). §5 F-LBV1.
- **Genesis / continuity / chain context.** `block-verify` is a *single-block* predicate. There is no genesis anchor (contrast `LightClientThreatModel.md` T-L1), no prev_hash continuity walk (contrast `verify_chain_to_head`), no head pinning. A PASS asserts properties *of this one JSON object in isolation*. §5 F-LBV2.
- **`tx_root` set-membership semantics.** TX-ROOT verifies the stored root equals the commitment over the *supplied* `creator_tx_lists`. It does not assert those lists are the transactions the block *should* contain (censorship / inclusion — `Censorship.md`, the per-tx-inclusion proofs); it asserts only that the stored root is a faithful commitment over whatever lists are present. §5 F-LBV4.
- **Cross-shard / F2-reconciled digest extensions.** `light_compute_block_digest` is byte-identical to `producer.cpp::compute_block_digest` **for the common case** (non-cross-shard, non-F2-reconciled blocks). For blocks carrying inbound receipts or non-zero F2 view-roots, the producer binds extra roots that the light copy omits; SIGS is sound for such blocks only modulo that scope. See §3.2 (the byte-equivalence domain) and §5 F-LBV5.

---

## 2. Construction specification

Read directly off the three components.

### 2.1 TX-ROOT — the canonical commitment (NOT a Merkle tree)

The daemon's `src/node/producer.cpp::compute_tx_root` (`:262-270`):

```cpp
Hash compute_tx_root(const std::vector<std::vector<Hash>>& creator_tx_lists) {
    std::set<Hash> u;
    for (auto& list : creator_tx_lists)
        for (auto& h : list) u.insert(h);
    SHA256Builder b;
    for (auto& h : u) b.append(h);
    return b.finalize();
}
```

where `Hash = std::array<uint8_t,32>` (`include/determ/types.hpp:15`) and `std::set<Hash>` orders by `std::array`'s lexicographic raw-byte comparison. The commitment is

$$
\mathrm{tx\_root} \;=\; H\Big(\;\big\Vert_{h \in \mathrm{sort}(u)}\, h\;\Big), \qquad u = \bigcup_{i}\bigcup_{j} \{\,\mathrm{creator\_tx\_lists}[i][j]\,\},
$$

with the empty-union case `u = ∅` yielding `H(\varepsilon) = \mathrm{SHA\text{-}256("")}`.

**This is a flat sorted-dedup-union commitment, NOT a Merkle tree.** It does not use `src/crypto/merkle.cpp`; `MerkleTreeSoundness.md` MT-1..MT-5 do **not** apply (no leaf/inner domain separation, no `leaf_count` binding, no inclusion-proof structure). TX-ROOT's only cryptographic dependency is A2 collision resistance of the single outer SHA-256 (§3.1). This cross-reference exists solely to disclaim the richer Merkle import.

The light client's inline reimplementation in `cmd_block_verify` (`light/main.cpp:733-748`):

```cpp
std::vector<Hash> uni;
for (auto& list : block_json["creator_tx_lists"]) {
    // (rejects non-array list, non-string entry)
    for (auto& hj : list)
        uni.push_back(from_hex_arr<32>(hj.get<std::string>()));
}
std::sort(uni.begin(), uni.end());
uni.erase(std::unique(uni.begin(), uni.end()), uni.end());
determ::crypto::SHA256Builder b;
for (auto& h : uni) b.append(h);
std::string computed = to_hex(b.finalize());
```

(The light client's other copy — `light_compute_tx_root` in `light/verify_tx_inclusion.cpp:35-43` — uses `std::set<Hash>` literally, matching the daemon; the `cmd_block_verify` copy uses `vector` + `sort` + `unique`, which §3.1 proves byte-equivalent.)

### 2.2 SIGS — the per-signer Ed25519 quorum gate over a SELF-RECOMPUTED digest

The daemon's `compute_block_digest` (`src/node/producer.cpp:610-620`, common-case prefix):

```cpp
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
    // ... (cross-shard / F2 extensions follow; see §3.2) ...
}
```

The light client's `light_compute_block_digest` (`light/verify.cpp:57-92`) reproduces this prefix **byte-for-byte** (same field set, same order, same encoders). Critically, the light client's `verify_block_sigs` (`light/verify.cpp:283-307`) computes the digest **from the block itself** and verifies each signature against it:

```cpp
Hash digest = light_compute_block_digest(b);          // ← LIGHT recomputes, from THIS block
Signature zero_sig{};
size_t valid = 0;
for (size_t i = 0; i < b.creators.size(); ++i) {
    const auto& sig = b.creator_block_sigs[i];
    if (sig == zero_sig) {                              // sentinel = abstention
        if (!bft_mode) { /* FAIL: sentinel in MD mode */ }
        continue;
    }
    const auto& pk = pubkey_of.at(b.creators[i]);
    if (determ::crypto::verify(pk, digest.data(), digest.size(), sig)) valid++;
    else { /* FAIL: sig does not verify */ }
}
size_t required = bft_mode ? (2 * b.creators.size() + 2) / 3 : b.creators.size();
// PASS iff valid >= required
```

This is the **load-bearing contrast** with the wallet sibling: the wallet's `cmd_committee_signature_verify` verifies over an `--block-digest` the operator supplies (`OfflineBlockVerifySoundness.md` §2.2 — `digest_bytes` is operator-supplied, *never recomputed*, because the wallet does not link the chain library). The light client substitutes a **self-recomputation** for that operator input.

### 2.3 STRUCTURE — the well-formedness predicate

A pure structural predicate (no crypto, `light/main.cpp:696-719`): the parsed JSON `contains` each of the seven required keys with the correct JSON type (`{"index",num}`, `{"prev_hash",str}`, `{"timestamp",num}`, `{"creators",arr}`, `{"creator_tx_lists",arr}`, `{"tx_root",str}`, `{"creator_block_sigs",arr}`), and `creators[]` is non-empty. The hex-width / byte-decoding of individual fields is enforced downstream by TX-ROOT (`from_hex_arr<32>` throws on bad width) and SIGS (`Block::from_json` + `parse_committee`); STRUCTURE supplies the presence + type + non-emptiness conjunction those two consume.

---

## 3. Soundness theorems

Throughout, let `STRUCT ∈ {PASS, FAIL}`, `TXR ∈ {PASS, FAIL, SKIP}`, `SIGS ∈ {PASS, FAIL, SKIP}` be the three component verdicts, and `BV ∈ {PASS, FAIL}` the aggregate (exit `0` / non-zero). Bounds follow `Preliminaries.md §2.0` (A1, A2 ≈ `2⁻¹²⁸`).

### 3.1 LBV-1 (TX-ROOT byte-equivalence + soundness)

**Statement.** Under A2, the light client's inline `tx_root` recompute in `cmd_block_verify` is **byte-identical** to the daemon's `src/node/producer.cpp::compute_tx_root` on every input, so a TX-ROOT PASS is *exactly* the daemon's `tx_root` accept gate. Consequently a daemon or block forger cannot produce a block whose stored `tx_root` passes TX-ROOT while committing to a different transaction set than the one in `creator_tx_lists`, except by exhibiting a SHA-256 collision (an A2 break, `≤ 2⁻¹²⁸`-class).

**Proof of byte-equivalence.** Both routines compute `H(‖_{h∈sort(u)} h)` over the same sorted-dedup union `u`. Match the operations:

1. **Union + dedup + ordering.** The daemon inserts every 32-byte `tx_hash` into a `std::set<Hash>`, whose iteration order is ascending lexicographic raw-byte order, with insertion deduping identical hashes. The light client `push_back`s every `from_hex_arr<32>`-decoded hash into a `std::vector<Hash>`, then `std::sort` (default `operator<` on `std::array<uint8_t,32>` = the same lexicographic raw-byte comparison `std::set` uses) followed by `std::unique` (which, on a *sorted* range, removes exactly the adjacent duplicates — i.e. all duplicates). The resulting ordered sequence is identical: `std::set<Hash>` and `sort(vector)+unique` produce the same sorted, deduplicated sequence under the same comparator. The nested loop order (outer over creator lists, inner over hashes) is identical and, the result being order-invariant, irrelevant. ⇒ Both produce the **same ordered byte sequence** `‖_{h∈sort(u)} h`.

2. **Hashing.** Both append each set/range member to a `determ::crypto::SHA256Builder` and `finalize()` — the *identical* builder type and call sequence in both (the daemon at `producer.cpp:267-269`, the light client at `main.cpp:745-747`). `SHA256Builder::append(Hash)` appends exactly the 32 raw bytes with no per-append framing; appending the same byte sequence then finalizing yields the same digest. ⇒ Same digest.

3. **Empty union.** Both reduce to `SHA-256("")` when `u = ∅` (the builder finalizes over zero appended bytes in both). ⇒ Same digest on the empty case.

4. **Input domain.** Both accept the same 32-byte-hash domain; the light client additionally *rejects* (records a TX-ROOT FAIL via the caught `from_hex_arr<32>` exception — never a silent PASS) any list entry that is not a 64-hex 32-byte string (`main.cpp:737-740, 753`). So on every input the daemon would accept, the light client computes the identical root; on inputs the daemon's struct could never hold, the light client fails closed. ⇒ No input on which the two diverge into a *PASS*.

Hence the light client's recomputed root equals `compute_tx_root(creator_tx_lists)` bit-for-bit. The daemon's accept gate is `expected = compute_tx_root(...); reject if expected != b.tx_root`; the light client's TX-ROOT PASS is `computed == stored tx_root` (case-normalized, `main.cpp:748-750`). Since `computed == expected`, **TX-ROOT PASS ⟺ the daemon's `tx_root` gate accepts** on the same block. ∎ (byte-equivalence)

**Proof of soundness.** Suppose a malicious producer / serving daemon presents a block with stored field `tx_root = r` and lists `L = creator_tx_lists`, and wants TX-ROOT to PASS while the *true* committed transaction set differs from `union(L)`. TX-ROOT PASS requires `r == H(‖_{h∈sort(union(L))} h)`. For the verdict to be *misleading*, there must exist a second list-set `L'` with `union(L') ≠ union(L)` yet `H(‖ sort(union(L'))) = r = H(‖ sort(union(L)))` with `sort(union(L')) ≠ sort(union(L))` — a SHA-256 collision on the outer hash. By A2 (collision resistance, `Preliminaries.md §2.1`), `Pr[\text{such collision}] ≤ 2⁻¹²⁸`-class. Absent such a collision, TX-ROOT PASS pins the stored root to the *unique* tx-set `union(L)` present in the block JSON, exactly the set the daemon would bind. A tampered tx-set cannot pass except via an A2 break. ∎

**Bound.** `Pr[\text{TX-ROOT PASS} ∧ \text{committed set} ≠ union(L)] ≤ \varepsilon_{A2} ≤ 2⁻¹²⁸`-class (one outer-hash collision).

### 3.2 LBV-2 (SIGS soundness — UNCONDITIONAL — the key result)

**Statement.** Under A1, a SIGS PASS implies there exist at least `required` valid Ed25519 signatures, by distinct committee members whose public keys are in the supplied `--committee`, **over `digest = light_compute_block_digest(b)`** — the digest the light client recomputes from *this very block's fields*, where `required = K` (full K-of-K, MD mode) or `required = ⌈2K/3⌉ = (2K+2)/3` (`--bft`). **This soundness is UNCONDITIONAL** — there is **no operator-supplied-digest precondition**, because the light client links the block/digest code and recomputes the digest itself rather than trusting an external one.

**Proof (the verification is sound, and the digest it verifies against is the block's own true digest).**

*Part 1 — the digest is the block's true digest.* `verify_block_sigs` computes `digest := light_compute_block_digest(b)` at `light/verify.cpp:283`, where `b` is the parsed block under test. By Lemma L-2 of `LightClientThreatModel.md` (and §2.2 above), `light_compute_block_digest` is a byte-for-byte copy of `src/node/producer.cpp::compute_block_digest` over the common-case field prefix — `index, prev_hash, tx_root, delay_seed, consensus_mode, bft_proposer`, then per-creator `(domain ‖ tx_list ‖ ed_sig ‖ dh_input)` (`producer.cpp:610-620` ≡ `verify.cpp:57-92`). Therefore, for any block the producer signed in the common case, `light_compute_block_digest(b)` equals the *exact* digest the committee signed when it produced `b`. There is **no operator input** in this step: the digest is a pure function of `b`'s own fields. (The byte-equivalence domain is the common case; cross-shard / F2-reconciled blocks are out of this part's scope — §5 F-LBV5.)

*Part 2 — the per-signer verification is sound for that digest.* For each creator `i` with a non-sentinel signature `σ_i` and committee pubkey `pk_i = pubkey_of.at(b.creators[i])`, SIGS counts `i` as valid iff `determ::crypto::verify(pk_i, digest, σ_i)` succeeds (`verify.cpp:254`). By A1 (Ed25519 EUF-CMA, `Preliminaries.md §2.2`), an adversary not holding `sk_i` cannot produce a `σ_i` with `Verify(pk_i, digest, σ_i) = 1` for a `digest` member `i` never signed, except with probability `≤ 2⁻¹²⁸`. SIGS PASS requires `valid ≥ required` such signers, each a distinct committee domain: the loop iterates `creators[i]` once each; every creator is checked for membership in the supplied committee before verification (`verify.cpp:223-229`, FAIL if any creator is absent), and `creator_block_sigs.size() == creators.size()` is enforced (`verify.cpp:230-236`). The per-signer loop is a faithful `N`-fold replication of the single-sig verify primitive with no cross-signer state — the only shared state is the immutable `pubkey_of` map and the immutable `digest` — instantiating `BatchSigningSoundness.md` BS-3's "loop adds no attack surface" structural-isolation property for the committee-sig loop.

*Conclusion.* Combining Parts 1 and 2: a SIGS PASS implies `required` distinct committee members produced valid Ed25519 signatures over `light_compute_block_digest(b)`, which **is** this block's true digest — under A1, up to `≤ K·2⁻¹²⁸`, **with no precondition on any operator-supplied digest**. ∎

**Contrast with the wallet sibling (the strict improvement).** `OfflineBlockVerifySoundness.md` BV-2 / §5 F-BV2 states the wallet's SIGS soundness *conditionally*: the wallet verifies over an **operator-supplied** `--block-digest` (`OfflineBlockVerifySoundness.md` §2.2; the wallet cannot recompute the digest because `determ-wallet` deliberately does not link the chain library), so a SIGS PASS is meaningful for *this* block **iff the supplied digest is the block's true digest** — a wrong digest yields a *vacuous* verdict. LBV-2 **discharges** that conditional: because `determ-light` *does* link the digest code and recomputes the digest from the block itself, the precondition "the digest is correct" is no longer an operator obligation but a *theorem* (Part 1). Thus:

> **Wallet `block-verify`** needs **digest + committee** as operator inputs (SIGS conditional, BV-2). **Light `block-verify`** needs **only committee** (SIGS unconditional, LBV-2). Light's SIGS is strictly stronger: it proves the committee signed *this block's true digest*, not merely "these sigs are valid over whatever digest you handed me."

**Bound.** `Pr[\text{SIGS PASS} ∧ ¬(required \text{ valid committee sigs over } b\text{'s true digest})] ≤ K·2⁻¹²⁸` (A1, per signer). Unlike BV-2, there is **no digest-correctness conditional outside this bound** — the digest correctness is internal (Part 1), not an operator precondition. For practical committees (`K ≤ 16`) the bound is `≤ 2⁻¹²⁴`-class.

### 3.3 LBV-3 (composite soundness + fail-closed + the honest boundary)

**Statement.** Under A1 + A2, `BV = PASS` (exit 0) implies the conjunction

> **STRUCTURE** (the block JSON is a well-formed `Block` envelope — seven fields present, types correct, `creators[]` non-empty)
> **∧ TX-ROOT** (the stored `tx_root` is the canonical commitment over `creator_tx_lists`, LBV-1, under A2)
> **∧ SIGS** (`required` valid committee signatures over `b`'s self-recomputed true digest, LBV-2, under A1, **unconditional**).

Moreover, any check FAIL or any args/parse error yields a **non-zero exit, never a false PASS**. The one remaining honest boundary is **committee provenance**: `block-verify` proves the block is signed by the *supplied* committee, not that the supplied committee is the genuine height-correct one.

**Proof of composite soundness.** `BV = PASS` ⟺ `failed == 0` ⟺ `STRUCT = PASS ∧ TXR = PASS ∧ SIGS = PASS` (§1.1 step 5; TX-ROOT and SIGS are recorded as SKIP only when STRUCTURE FAILed, in which case `failed ≥ 1` already, so a true `BV = PASS` requires all three at PASS). Each conjunct reduces to its component:

- `STRUCT = PASS` ⟹ the seven required fields are present, correctly typed, `creators[]` non-empty (deterministic predicate, no assumption). This is *well-formedness*, the precondition the other two checks rely on (a malformed JSON could not be parsed into the lists/sigs they consume).
- `TXR = PASS` ⟹ (LBV-1) the stored `tx_root` equals the canonical union-commitment over `creator_tx_lists`, under A2, byte-identical to the daemon's gate.
- `SIGS = PASS` ⟹ (LBV-2) `required` distinct supplied-committee members signed `b`'s self-recomputed true digest under A1, **unconditionally**.

The composite adds no verification logic beyond the conjunction; its soundness is exactly the conjunction of the three. `Pr[BV = PASS ∧ ¬(\text{STRUCT} ∧ \text{TXR-sound} ∧ \text{SIGS-sound})] ≤ \varepsilon_{A2} + \varepsilon_{A1}` (§3.4). ∎

**Proof of fail-closed.** Enumerate every non-PASS pathway; each yields a non-zero exit with no false PASS:

- **Args/parse fault.** Unknown arg (`:661-664`), missing `--block`/`--committee` (`:666-669`), unreadable / non-JSON file (`:672-678`), non-object block (`:683-686`) → `return 1` *before any verdict is recorded*. Exit 1, never PASS.
- **STRUCTURE FAIL.** A missing/mistyped required field or empty `creators[]` → `struct_ok = false` → `++failed` → `overall = false` → exit 2 (`:720-725, 782, 804`). TX-ROOT and SIGS are then recorded SKIP (`:760, :779`), which cannot rescue the verdict — `failed ≥ 1` already.
- **TX-ROOT FAIL.** `computed != stored`, or a bad-hex / non-array `creator_tx_lists` entry that throws inside the `try` (`:732-753`) → `ok = false` → `++failed` → exit 2.
- **SIGS FAIL.** `verify_block_sigs` returns `!r.ok` — a creator absent from the committee, a size mismatch, a sentinel-zero sig in MD mode, a signature that does not verify against the recomputed digest, or `valid < required` (`verify.cpp:223-273`) — or the call throws (`:773`) → `ok = false` → `++failed` → exit 2. A *stricter* quorum (MD when the block was BFT-escalated) can only push more blocks into FAIL — a possible false FAIL, never a false PASS.

In every non-PASS pathway the exit is non-zero (1 for args/parse, 2 for a check FAIL) and no `BLOCK-VERIFY: PASS` is emitted. `overall = (failed == 0)` is a faithful function of the component verdicts; no code path sets it true while a check FAILed. ∎

**The remaining honest boundary (committee provenance).** SIGS verifies against the operator-supplied `--committee`. LBV-2 proves the block is signed by **that supplied committee** over the block's true digest — it does **not** prove the supplied committee is the *genuine, height-correct* committee for the block. An operator who supplies a *fabricated* committee (one whose keys signed a forged block) gets a SIGS PASS that is *sound for that committee but meaningless for the real chain*. This is **strictly smaller** than the wallet sibling's boundary: the wallet has **two** operator inputs to trust — the committee **and** the digest (BV-2 conditional + the same committee-provenance gap); the light client has **only one** — the committee. For full trust-minimization the committee must be the genesis/chain-derived set, which `determ-light verify-chain` (`light/main.cpp:930`) and `committee-at-height` (`light/main.cpp:204`) derive trustlessly (anchor genesis per `LightClientThreatModel.md` T-L1, then walk + per-block sig-verify per T-L2). `block-verify` is the **offline, single-block, committee-as-input** member of that family; pair it with the chain-derived committee for an end-to-end trustless verdict.

### 3.4 LBV-E (composition error bound)

**Statement.** The composite's soundness error is the sum of its two cryptographic components' bounds; STRUCTURE and the conjunction logic are deterministic and contribute no term:

$$
\Pr[\text{BV} = \text{PASS} \ \wedge\ \neg(\text{STRUCT} \wedge \text{TXR-sound} \wedge \text{SIGS-sound})]
\;\le\; \varepsilon_{\text{TXR}} + \varepsilon_{\text{SIGS}}
\;\le\; \underbrace{2^{-128}\text{-class}}_{\text{A2, one outer hash}} \;+\; \underbrace{K \cdot 2^{-128}}_{\text{A1, } K \text{ signers}}.
$$

**Derivation.** `BV = PASS` requires `STRUCT = PASS ∧ TXR = PASS ∧ SIGS = PASS` (LBV-3). The event "BV passes yet a cryptographic component is unsound" is contained in "(TXR passes yet TXR unsound) ∨ (SIGS passes yet SIGS unsound)"; by the union bound it is `≤ Pr[TXR unsound] + Pr[SIGS unsound]`. From LBV-1, `Pr[TXR unsound] ≤ \varepsilon_{A2} ≤ 2⁻¹²⁸`-class (one outer-SHA-256 collision). From LBV-2, `Pr[SIGS unsound] ≤ K·2⁻¹²⁸` (an Ed25519 forgery for one of `≤ K` signers). STRUCTURE is a deterministic predicate; the conjunction / exit-code mapping are deterministic boolean operations — none adds a cryptographic term. For practical committees (`K ≤ 16`) the bound is `≤ 2⁻¹²³`-class, dominated by the K-fold A1 term. ∎

**No digest conditional in the bound — and none outside it.** Unlike `OfflineBlockVerifySoundness.md` BV-E (whose bound is *conditional* on a correct operator-supplied digest, a precondition held outside the probability term), LBV-E has **no digest-correctness conditional at all** — the digest is self-recomputed (LBV-2 Part 1), so its correctness is a theorem internal to the bound, not an external operator obligation. The only honest precondition that remains is committee provenance (LBV-3), which — like BV-2's committee-provenance gap — is an operator-input statement, not a cryptographic event, and so is not a probability term either.

---

## 4. Composition with companion proofs

### 4.1 `OfflineBlockVerifySoundness.md` — the wallet sibling this strictly improves on

`block-verify` (light) is the chain-linked, OFFLINE, single-block analogue of `block-verify` (wallet). Both carry the BV-3 / LBV-3 posture (the shell adds no trust surface; the exit code is a faithful function of component verdicts; fail-closed on every error). The differences:

| | wallet `block-verify` (BV-*) | light `block-verify` (LBV-*) |
|---|---|---|
| TX-ROOT | reimplemented inline; byte-identical to daemon (BV-1) | reimplemented inline; byte-identical to daemon (LBV-1) — same result |
| Digest | **operator-supplied** `--block-digest` (no chain-lib link) | **self-recomputed** `light_compute_block_digest` (links block code) |
| SIGS soundness | **conditional** on a correct supplied digest (BV-2, F-BV2) | **unconditional** (LBV-2) — the conditional is discharged |
| Operator inputs to trust | digest **and** committee | **only** committee |
| Trust boundary | digest-provenance + committee-provenance | committee-provenance **only** (strictly smaller) |

LBV-2 is precisely BV-2 with the digest conditional removed; LBV-1 and the fail-closed argument of LBV-3 mirror BV-1 / BV-3 unchanged.

### 4.2 `LightClientThreatModel.md` — the chain-walk family `block-verify` plugs into

`block-verify` reuses the T-L2 primitive `verify_block_sigs` (and its Lemma L-2 `light_compute_block_digest` byte-equivalence) but in an **OFFLINE single-block** setting with **no T-L1 genesis anchor** and **no chain-continuity walk**. The committee-provenance residual of LBV-3 is exactly `LightClientThreatModel.md` §6.5 / F-1 (genesis-only committee map): the secure source of the committee is the chain-derived set that `verify-chain` / `committee-at-height` produce. `block-verify` is the standalone, single-block, committee-as-input verifier; the composite `verify-chain` family supplies the trustless committee and the genesis anchor `block-verify` deliberately omits.

### 4.3 `BatchSigningSoundness.md` — the per-signer loop is a faithful N-fold replication

SIGS's per-creator verification loop (`verify.cpp:287-307`) is a composition of the single-sig verify primitive, exactly as BS-3 composes the single-tx verify. LBV-2 Part 2's "no cross-signer state, sole shared state is the immutable committee map + immutable digest" argument *is* BS-3's structural-isolation argument specialized to the committee-sig loop: signer `i`'s verdict depends only on `(σ_i, digest, pk_i)`, never on signer `j ≠ i`.

### 4.4 `Safety.md` (FA1) + `Preliminaries.md` — the assumption base

SIGS consumes FA1's per-block K-of-K (or `Q = ⌈2|K_h|/3⌉` BFT) signature-set primitive (`Safety.md` L-1.3) applied to a single block. LBV-1 reduces to A2 (§2.1); LBV-2 reduces to A1 (§2.2). A3 and A4 are not used. The composite's bound (LBV-E) is the union of A1 + A2, with no independent term — the deterministic-orchestration posture.

---

## 5. Findings (honest limitations)

Stated so an operator knows exactly what a `block-verify: PASS` does and does not assert. None undermines the per-invocation soundness of LBV-3; all are coverage/scope statements or the one committee-provenance boundary.

### F-LBV1 STRUCTURE is well-formedness, not semantic validity

A STRUCTURE PASS asserts the JSON is a *syntactically well-formed `Block` envelope* (seven required fields present, correct types, `creators[]` non-empty). It does **not** assert the block is *semantically* valid: that `index` succeeds a real predecessor, that `prev_hash` links to an actual prior block, that `timestamp` is in-window, that `creators[]` is the protocol-selected committee for that height, or that the transactions in `creator_tx_lists` are themselves signed/nonce-ordered/balance-covered. Those are chain-state and apply-layer properties (`Safety.md`, the FA-Apply track) requiring full chain context the offline verifier does not have.

### F-LBV2 No genesis, no continuity, no chain context — single block only

`block-verify` is a *single-block* predicate. There is no genesis anchor (contrast `LightClientThreatModel.md` T-L1), no prev_hash-continuity walk, no head pinning. A PASS asserts properties of *this one JSON object in isolation*. It cannot and does not assert the block belongs to any particular chain, follows any particular predecessor, or is the canonical block at its height. An operator needing chain-anchored assurance runs the `determ-light verify-chain` / `audit` family (which link the verification path and walk from a pinned genesis).

### F-LBV3 The committee is operator-supplied — provenance is the remaining honest boundary (the one load-bearing limitation)

SIGS verifies against the operator-supplied `--committee`. LBV-2 proves the block is signed by **that supplied committee** over the block's true self-recomputed digest — **unconditionally** in the digest, but **conditional on the committee being the genuine height-correct set**. An operator who supplies a fabricated committee (whose keys signed a forged block) gets a SIGS PASS that is sound *for that committee* but meaningless for the real chain. For full trust-minimization the committee MUST be the genesis/chain-derived set: `determ-light verify-chain` (`light/main.cpp:930`) anchors genesis (T-L1) and walks + sig-verifies every block (T-L2) to establish the height-correct committee trustlessly; `committee-at-height` (`light/main.cpp:204`) reports the committee-verified creators at a given height. **This is the strictly smaller trust boundary** vs. the wallet sibling, which carries BOTH a digest-provenance conditional (BV-2) AND the same committee-provenance gap. Pair `block-verify` with a chain-derived committee for an end-to-end trustless verdict.

### F-LBV4 TX-ROOT verifies the commitment over the SUPPLIED lists, not their correctness as a tx-set

TX-ROOT PASS means the stored `tx_root` is a faithful commitment over whatever `creator_tx_lists` the JSON carries (LBV-1). It does **not** assert those lists are the transactions the block *should* contain — censorship (a creator omitting a tx) and inclusion (a specific tx being present) are out of scope (`Censorship.md`, the per-tx-inclusion proofs). A block that commits faithfully to a *censored* tx-set passes TX-ROOT; TX-ROOT detects only a stored-root that disagrees with the present lists, i.e. a tampered/forged root.

### F-LBV5 The self-recomputed digest is byte-identical to the producer only in the common case

`light_compute_block_digest` (`light/verify.cpp:57-92`) reproduces `producer.cpp::compute_block_digest`'s field prefix (`producer.cpp:610-620`) byte-for-byte. But the producer appends **further** roots for blocks that carry cross-shard inbound receipts (a `compute_view_root` over `inbound_receipts`, `producer.cpp:629-635`) or that went through F2 reconciliation (non-zero per-creator eq/abort view-roots ⇒ extra `compute_view_root` appends, `producer.cpp:650-661`). The light copy **omits** these extensions. For the common case — non-cross-shard, non-F2-reconciled blocks (empty `inbound_receipts` AND all-zero view roots), which keep a byte-identical v1 digest by the producer's own design (`producer.cpp:610-620, 627-628`) — LBV-2 holds exactly. For a cross-shard / F2-reconciled block, the light client's recomputed digest would differ from the producer's, so the genuine committee signatures would **not** verify and SIGS would FAIL (a fail-closed false-negative, never a false PASS). `block-verify` is therefore sound-and-meaningful for common-case blocks and **fail-closed (conservative)** on the cross-shard / F2 extensions. This is an honest scope boundary on which blocks SIGS can PASS, not a soundness gap (LBV-3 fail-closed covers it: a stricter-than-true digest can only cause a false FAIL). The KEEP-IN-SYNC comment at `light/verify.cpp:40-56` documents the omitted field set.

### F-LBV6 Sentinel / quorum semantics inherited from `verify_block_sigs`

SIGS inherits `verify_block_sigs`'s exact handling: a 64-byte all-zero signature is a *sentinel abstention* — permitted (and uncounted) only under `--bft`, a hard FAIL in MD mode (`verify.cpp:244-252`); a creator absent from the committee map is a hard FAIL (`verify.cpp:223-229`); `creator_block_sigs.size() != creators.size()` is a hard FAIL (`verify.cpp:230-236`). The MD quorum is full K; the `--bft` quorum is `⌈2K/3⌉ = (2*creators.size()+2)/3` (`verify.cpp:264-266`). An operator running MD (`--bft` omitted) against a BFT-escalated block (which carries sentinel-zero slots) gets a clean FAIL, not a false PASS — they must pass `--bft` to verify such blocks. These are not new surfaces; they are `verify_block_sigs`'s behavior, carried verbatim.

---

## 6. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem | Surface | File:lines | Role |
|---|---|---|---|
| — | `cmd_block_verify` (composite) | `light/main.cpp:652-805` | Arg parse, `{block:{...}}` unwrap, three checks, conjunction, exit 0/1/2. |
| LBV-1 | TX-ROOT inline recompute | `light/main.cpp:728-761` | `vector<Hash>` + `sort` + `unique` + `SHA256(concat)`; case-normalized compare vs stored `tx_root`. |
| LBV-1 | `light_compute_tx_root` (set form) | `light/verify_tx_inclusion.cpp:35-43` | `std::set<Hash>` union — the literal daemon mirror the inline form is proved byte-equal to. |
| LBV-1 | daemon original | `src/node/producer.cpp:262-270` | `compute_tx_root` — the byte-identical reference. |
| LBV-2 | `verify_block_sigs` | `light/verify.cpp:190-283` | Per-creator Ed25519 verify over the **self-recomputed** digest; quorum `K` / `⌈2K/3⌉`. |
| LBV-2 | `light_compute_block_digest` | `light/verify.cpp:57-92` | Byte-for-byte copy of `producer.cpp::compute_block_digest` (common-case prefix). |
| LBV-2 | digest recomputed (not supplied) | `light/verify.cpp:283` | `Hash digest = light_compute_block_digest(b);` — the UNCONDITIONAL improvement over wallet BV-2. |
| LBV-2 | daemon original | `src/node/producer.cpp:610-620` (+ `:629-690` extensions) | `compute_block_digest`; F-LBV5 covers the cross-shard / F2 tail the light copy omits. |
| LBV-2 | per-signer loop isolation | `light/verify.cpp:287-307` | No cross-signer state; instantiates `BatchSigningSoundness.md` BS-3. |
| LBV-3 | STRUCTURE predicate | `light/main.cpp:692-726` | Seven-field presence + type + non-empty `creators[]`. |
| LBV-3 | conjunction + exit | `light/main.cpp:782-804` | `overall = (failed == 0)`; exit 0/1/2. |
| LBV-3 | committee-provenance escape hatch | `light/main.cpp:930` (`verify-chain`), `:204` (`committee-at-height`) | Trustless committee derivation (anchor + walk per T-L1/T-L2). |
| LBV-E | (no new term) | — | Bound = `\varepsilon_{A2} + K·\varepsilon_{A1} ≤ 2⁻¹²³`-class; STRUCTURE + conjunction deterministic; **no digest conditional**. |

**Tests.**

| Test | Coverage |
|---|---|
| `tools/test_light_block_verify.sh` | LBV-3 end-to-end (boots a 3-node cluster; block 1 via `block-info --json` + committee via `validators --json`): happy-path PASS (all three checks, exit 0); `--json` `audit=PASS`, `passed==3`; tampered `tx_root` → TX-ROOT FAIL, exit 2; tampered `creator_block_sig` → SIGS FAIL, exit 2; wrong committee pubkey → SIGS FAIL, exit 2; missing field → STRUCTURE FAIL, exit 2. |
| `tools/test_light_verify_block_sigs.sh` | LBV-2 component (T-L2): happy path + tampered sig → FAIL + wrong committee → FAIL. |

---

## 7. Status

- **Implementation.** **SHIPPED.** `int cmd_block_verify` is in `light/main.cpp:652-805` (dispatched on `block-verify` at `:5850`), exercised by `tools/test_light_block_verify.sh` (cluster-boot fixture + happy-path PASS + four fail-closed negatives). Composes STRUCTURE (`:692-726`), TX-ROOT (`:728-761`), and SIGS via `verify_block_sigs` (`light/verify.cpp:190-283`).
- **Proof.** Complete (this document). LBV-1 (TX-ROOT byte-equivalence to `producer.cpp::compute_tx_root` + A2 soundness — a tampered tx-set cannot pass except via a SHA-256 collision); **LBV-2 (SIGS soundness UNCONDITIONAL under A1 — the light client recomputes `compute_block_digest` itself via `light_compute_block_digest`, so a SIGS PASS proves the supplied committee signed THIS block's true digest, with NO operator-supplied-digest precondition — the strict improvement over wallet BV-2's conditional)**; LBV-3 (composite soundness = STRUCTURE ∧ TX-ROOT ∧ SIGS, fail-closed — every FAIL/parse-error → non-zero exit, never a false PASS; remaining honest boundary = committee provenance). Composition bound LBV-E (`≤ \varepsilon_{A2} + K·\varepsilon_{A1} ≤ 2⁻¹²³`-class; no new cryptographic term; **no digest conditional**).
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA, SIGS), A2 (SHA-256 collision resistance, TX-ROOT). A3, A4 not used. Per `Preliminaries.md §2.0`.
- **Composes with.** `OfflineBlockVerifySoundness.md` (the wallet sibling — LBV-2 is BV-2 with the digest conditional discharged), `LightClientThreatModel.md` (T-L1/T-L2 chain-walk family + Lemma L-2 digest byte-equivalence + the committee-provenance escape hatch), `BatchSigningSoundness.md` (BS-3 per-signer-loop isolation), `Safety.md` (FA1 per-block K-of-K primitive), `Preliminaries.md` (A1 + A2 base), `MerkleTreeSoundness.md` (cited to *disclaim* — `tx_root` is NOT a Merkle tree).
- **Known limitations (§findings).** F-LBV1 (STRUCTURE is well-formedness, not semantic validity); F-LBV2 (single block only — no genesis/continuity/chain context); **F-LBV3 (the load-bearing one: the committee is operator-supplied — `block-verify` proves the block is signed by the SUPPLIED committee, not the genuine height-correct one; pair with `verify-chain` / `committee-at-height` for trustless committee provenance)**; F-LBV4 (TX-ROOT commits over the supplied lists, not their correctness as a tx-set); F-LBV5 (the self-recomputed digest is byte-identical only in the common case — cross-shard / F2-reconciled blocks fail-closed); F-LBV6 (sentinel / quorum semantics inherited verbatim from `verify_block_sigs`). None undermines the per-invocation soundness of LBV-3.
- **The strongest of the three offline block verifiers (load-bearing).** Among Determ's offline block verifiers, `determ-light block-verify` is the **strongest**: **wallet `block-verify` needs digest + committee** (SIGS conditional on a correct operator-supplied digest, BV-2); **light `block-verify` needs only committee** (SIGS unconditional, LBV-2 — the digest is self-recomputed from the block). The light client links the block/digest code; the wallet deliberately does not. The remaining trust boundary is therefore strictly smaller — committee provenance alone — and is itself dischargeable via the chain-derived committee from `verify-chain` / `committee-at-height`.

---
