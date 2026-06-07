# OfflineBlockVerifySoundness — composite one-shot OFFLINE single-block verifier (`determ-wallet block-verify`)

This document proves the soundness of the `determ-wallet block-verify` subcommand: a **composite, one-shot, fully OFFLINE single-block verifier** that an operator runs against one block JSON to obtain, in a single invocation, a PASS/FAIL verdict over three independently-characterizable checks — STRUCTURE (well-formedness), TX-ROOT (the daemon's `tx_root` accept gate, recomputed locally), and SIGS (K-of-K / BFT-quorum Ed25519 committee-signature verification over an operator-supplied block digest). It conjoins the three into one verdict with a monitor-friendly exit code (`0` all pass, `1` args/parse error, `2` a check failed).

The proof's posture mirrors `LightClientAuditComposition.md` (the `determ-light audit` composite): `block-verify` is **pure orchestration over reimplemented primitives**. It introduces no new cryptographic logic — it composes two already-grounded wallet primitives (`cmd_block_tx_root`'s `tx_root` recompute and `cmd_committee_signature_verify`'s Ed25519 gate) plus one new well-formedness predicate (STRUCTURE), conjoins their verdicts, and maps the conjunction to a process exit code. Its soundness is therefore *exactly* the conjunction of its components' soundness — with one **honest asymmetry** that distinguishes it from the `determ-light` family: the SIGS component verifies signatures over a digest the operator supplies rather than one the wallet recomputes, because **`determ-wallet` deliberately does NOT link the chain library** (TCB separation). The SIGS verdict is therefore *conditional* on a correct operator-supplied `--block-digest`; this document states that trust boundary precisely rather than papering over it (BV-2, §5 F-BV2).

**A note on what "composite" means here.** Like `audit`, `block-verify` composes *checks*, not bare cryptographic primitives. But unlike `audit` — whose two components are themselves fully-proved composites over RPC reads — `block-verify` operates on a *single local block JSON* with **no network, no RPC, no daemon, no genesis, and no chain context**. It is a single-block predicate, not a chain-walk. This narrows what a PASS can assert (§5: STRUCTURE is well-formedness not semantic validity; there is no genesis/continuity anchoring; the SIGS digest is operator-trusted) and is the source of every honest limitation in §5.

**The load-bearing design fact (TCB separation).** `determ-wallet` does not link `libdeterm_chain`. Consequently the canonical `compute_tx_root` (the union/dedup/SHA-256 commitment) and the Ed25519 committee-signature gate are **reimplemented inline** in `wallet/main.cpp` over `std::set<std::array<uint8_t,32>>` + OpenSSL `SHA256` + libsodium `crypto_sign_verify_detached`, rather than called from the chain library. BV-1 proves the TX-ROOT reimplementation is **byte-identical** to the daemon's `src/node/producer.cpp::compute_tx_root`, so a TX-ROOT PASS is exactly the daemon's accept gate. BV-2 proves the SIGS reimplementation faithfully verifies Ed25519 sigs under A1, but cannot recompute the digest the daemon binds (`compute_block_digest`) — hence the conditional. This is the *cost* of the wallet's lean TCB, paid as a stated trust boundary, not a hidden assumption.

**Canonical assumption labels.** Per `Preliminaries.md §2.0`: **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision resistance (§2.1), **A3** = SHA-256 preimage / second-preimage resistance (§2.1), **A4** = CSPRNG uniform sampling (§2.3). `block-verify` reduces to **A1** (SIGS) + **A2** (TX-ROOT) only; A3 and A4 are not used. (The "A1 unitary-supply invariant" of the apply-layer proofs is an accounting identity unrelated to assumption A1; this document uses "A1" exclusively for Ed25519 EUF-CMA, since no supply identity appears here.)

**Companion documents.** `Preliminaries.md` (F0) §1.3 (hash notation `H`, `‖`, big-endian integer encoding), §2.0 (assumption labels), §2.1 (A2), §2.2 (A1) — `block-verify` reduces to A1 + A2; `LightClientAuditComposition.md` (the composite-orchestration sibling whose AC-1/AC-2/AC-3/AC-4 posture this document mirrors for an OFFLINE single-block subject) — `block-verify` is the wallet-TCB, single-block analogue of `audit`; `MerkleTreeSoundness.md` (the state-commitment Merkle primitive — cited for the *contrast*: `tx_root` is **NOT** a Merkle tree but a flat sorted-dedup-union SHA-256 commitment, §2.1 here makes this explicit so a reader does not import MT-1..MT-5 by mistake); `BatchSigningSoundness.md` (the wallet-tooling-soundness companion whose "wrap a primitive in a loop, prove no new attack surface" thesis BV-2 instantiates for the per-signer verification loop); `docs/PROTOCOL.md §4.3` (`block_digest` field-exclusion list — why the wallet cannot recompute the digest) and `docs/SECURITY.md` for the TCB-separation narrative.

---

## 0. Implementation status and proof-to-spec divergence

**`int cmd_block_verify(...)` is IMPLEMENTED in `wallet/main.cpp`** (dispatched on `block-verify`, exercised offline by `tools/test_wallet_block_verify.sh`). This document was first drafted against the **SPEC** below; the two implementation divergences it flagged (D1, D2) were both **RESOLVED** in the shipped code during implementation — the adversarial proof-grounding pass that produced this document caught a real field-name bug (D1) before it shipped. The updated D-entries and §7 reflect the shipped reality. The two *components* it composes are read directly off source:

- `cmd_block_tx_root` (`wallet/main.cpp:14019`) — the TX-ROOT recompute, including the `std::set<std::array<uint8_t,32>>` union, the `SHA256(concatenation)` finalize, and the `--check` byte-compare against the stored `tx_root` (lines 14118-14219).
- `cmd_committee_signature_verify` (`wallet/main.cpp:8623`) — the SIGS gate: per-signer `crypto_sign_verify_detached` over `digest_bytes`, sentinel-zero abstention handling, and the `required = (2*present_count+2)/3` quorum (lines 8817-8918).

**SPEC of `block-verify` (the object proved):**

```
determ-wallet block-verify --block-json <file|-> [--committee <file>]
                           [--block-digest <hex64>] [--bft] [--json]
```

A one-shot OFFLINE single-block verifier composing three checks into one PASS/FAIL with a monitor-friendly exit code (`0` all pass, `1` args/parse error, `2` a check failed):

1. **STRUCTURE** — the block JSON is well-formed: required fields present (`index`, `prev_hash`, `creators[]`, `creator_tx_lists[]`, `tx_root`, `timestamp`, `creator_block_sigs[]`), `creators[]` non-empty, field shapes valid; a `{block:{...}}` envelope is rejected (block-verify requires an unwrapped Block, the `block-info --json` shape). *(New well-formedness logic.)*
2. **TX-ROOT** — recompute `compute_tx_root(creator_tx_lists)` (the sorted-dedup UNION of every 32-byte `tx_hash`, `std::set<Hash>` ordered by raw bytes, SHA-256 over the concatenation; empty union ⇒ `SHA-256("")`) and compare to the block's stored `tx_root`. *(Reuses the `cmd_block_tx_root` logic, which mirrors `src/node/producer.cpp::compute_tx_root` byte-for-byte.)*
3. **SIGS** — attempted **only if BOTH `--committee` AND `--block-digest` are supplied, else SKIP**: BFT-style `⌈2·present/3⌉`-quorum Ed25519 committee-signature verification over the **OPERATOR-SUPPLIED** `block_digest` via libsodium. *(Reuses `cmd_committee_signature_verify` verbatim — there is no `--bft` switch; the quorum is the component's unconditional `⌈2P/3⌉`.)*

**Divergences flagged during drafting — both RESOLVED in the shipped code.** The composite faithfully reuses the two shipped components' verification cores unchanged and adds (a) the STRUCTURE predicate, (b) the three-way conjunction, and (c) the SKIP gating. Two implementation choices the early spec left open were pinned in the final `cmd_block_verify`:

- **(D1) Field-name reconciliation — RESOLVED.** An early STRUCTURE draft named `block_sigs[]`, but the shipped `cmd_committee_signature_verify` reads `creator_block_sigs[]` (and `cmd_block_tx_root` reads `creator_tx_lists` + `tx_root`). The proof-grounding pass caught the mismatch as a **real bug** before ship: had STRUCTURE required `block_sigs`, it would have wrongly rejected every real block (which carries `creator_block_sigs`). The shipped `cmd_block_verify` STRUCTURE presence-checks `creator_block_sigs[]`, `creator_tx_lists[]`, and `tx_root` — the exact fields the TX-ROOT and SIGS components consume; STRUCTURE and SIGS now agree on the signature array. (A `{block:{...}}` envelope is rejected rather than silently unwrapped, so STRUCTURE also agrees with `cmd_block_tx_root`, which requires the top-level Block shape.)
- **(D2) The quorum — RESOLVED.** The shipped `cmd_block_verify` reuses `cmd_committee_signature_verify` verbatim and therefore inherits its **unconditional `required = ⌈2·present/3⌉`** quorum (BFT-style over present signatures). There is no `--bft` switch and no full-K-of-K MUTUAL_DISTRUST branch (`--bft` was dropped from `block-verify`). BV-2 / BV-3 below are stated over exactly this `⌈2P/3⌉` quorum.

Neither D1 nor D2 affects the *cryptographic* soundness of the underlying checks (BV-1, BV-2); they fixed which field STRUCTURE reads (D1) and pinned which quorum SIGS enforces (D2). §3.3's fail-closed argument holds uniformly: a stricter-than-needed threshold can only cause a false FAIL, never a false PASS.

---

## 1. Scope

### 1.1 In scope

The `determ-wallet block-verify` composite per the §0 SPEC. Its control flow, as specified (to be reconciled with the final `cmd_block_verify` per §0):

1. **Argument parse + validation.** `--block-json` is required (`<file>` path or `-` for stdin); `--committee`, `--block-digest`, `--bft`, `--json` are optional. A missing `--block-json`, an unknown arg, an unreadable file, or non-JSON / non-object input → `return 1` (args/parse error) before any check verdict is recorded. This matches both components' parse-fault posture (`cmd_block_tx_root:14074-14103`, `cmd_committee_signature_verify:8641-8694`).

2. **STRUCTURE check (new logic).** A pure well-formedness predicate over the parsed JSON object: the seven required fields are present and of the right JSON type; `creators[]` is a non-empty array; the hex-typed fields (`prev_hash`, `tx_root`, each `creator_tx_lists[i][j]`, each `creator_block_sigs[i]`) decode to their fixed byte widths (32 for hashes, 64 for sigs, or the all-zero sentinel). STRUCTURE PASS ⟺ the JSON is a syntactically well-formed block envelope; STRUCTURE FAIL ⟺ a required field is missing/mistyped or a hex width is wrong.

3. **TX-ROOT check (reuses `cmd_block_tx_root` core).** Build the sorted-dedup union `u = ⋃_i ⋃_j {creator_tx_lists[i][j]}` as a `std::set<std::array<uint8_t,32>>`, compute `root = SHA256(‖_{h∈u} h)`, and byte-compare `root` against the decoded stored `tx_root`. TX-ROOT PASS ⟺ `root == tx_root`.

4. **SIGS check (reuses `cmd_committee_signature_verify` core), conditional.** Attempted **iff both `--committee` and `--block-digest` are supplied**. When attempted: load the committee (`domain → ed_pub` map), decode the operator-supplied digest to 32 bytes, and for each creator verify `crypto_sign_verify_detached(sig_i, digest, pk_i)`; sentinel-zero / empty sigs count as abstentions; SIGS PASS ⟺ `valid_count ≥ required` for the applicable quorum (per §0 D2). When **either** `--committee` or `--block-digest` is absent → SIGS = **SKIP** (reported, not counted as PASS, not counted as FAIL).

5. **Aggregate verdict + exit.** `overall = STRUCTURE-PASS ∧ TX-ROOT-PASS ∧ (SIGS-PASS ∨ SIGS-SKIP)`. Exit `0` iff `overall`; exit `2` iff any check FAILed; exit `1` on the args/parse faults of step 1. The `--json` mode emits an aggregate object; the human mode emits a per-check summary. Output is read-only over the verdicts.

### 1.2 The three components

| Component | Implementation basis | What it establishes | Backing |
|---|---|---|---|
| **STRUCTURE** | New well-formedness predicate (§0) | The block JSON is a syntactically well-formed block envelope (required fields present, correct types, hex widths valid, `creators[]` non-empty) | Structural; no cryptographic assumption (BV-3 §3.3) |
| **TX-ROOT** | `cmd_block_tx_root` core (`wallet/main.cpp:14118-14219`) | The block's stored `tx_root` equals the canonical commitment over its `creator_tx_lists` — **byte-identical to the daemon's accept gate** | A2 (BV-1 §3.1) |
| **SIGS** | `cmd_committee_signature_verify` core (`wallet/main.cpp:8817-8918`) | A quorum of valid Ed25519 committee signatures exist over the **operator-supplied** digest | A1, **conditional on a correct digest** (BV-2 §3.2) |

### 1.3 Out of scope (intentional — the verifier's coverage boundary)

- **Digest recomputation.** The wallet does not link the chain library and so cannot compute `compute_block_digest(b)` (`src/node/validator.cpp:443`), which excludes ~11 block fields and depends on consensus-layer encoders. SIGS verifies sigs over an *operator-supplied* digest. Recomputing the true digest is the daemon's job (`determ verify-block-sigs`); the wallet trusts the supplied one. This is the BV-2 trust boundary, stated honestly (§5 F-BV2). **Out of scope: any guarantee that the supplied digest is the block's real digest.**
- **Semantic / consensus validity.** STRUCTURE is *well-formedness*, not semantic validity. A PASS does not assert the block's `index` follows its predecessor, that `prev_hash` links to a real prior block, that `timestamp` is in-window, that `creators[]` is the protocol-selected committee for that height, that the abort/BFT-proposer fields are consistent, or that any transaction in `creator_tx_lists` is itself valid (signed, nonce-ordered, balance-covered). Those are chain-state / apply-layer properties (`Safety.md`, `AccountStateInvariants.md`, the apply-track proofs) requiring full chain context the wallet does not have. §5 F-BV3 states this.
- **Genesis / continuity / chain context.** `block-verify` is a *single-block* predicate. There is no genesis anchor (contrast `LightClientThreatModel.md` T-L1), no prev_hash continuity walk (contrast `verify_chain_to_head`), no committee-rotation threading. A PASS asserts properties *of this one JSON object in isolation*. §5 F-BV4.
- **The `tx_root` set membership semantics.** TX-ROOT verifies the stored root equals the commitment over the *supplied* `creator_tx_lists`. It does not assert those lists are the transactions the block *should* contain (that is the censorship / inclusion question of `Censorship.md` and the per-tx-inclusion proofs); it asserts only that the stored root is a faithful commitment over whatever lists are present.
- **Committee rotation / source of the committee file.** SIGS verifies sigs against the operator-supplied `--committee` map. Whether that committee is the correct one for the block's height is out of scope (the operator supplies it from a trusted source, e.g. `determ validators --json`), exactly as `cmd_committee_signature_verify` already assumes.

---

## 2. Construction specification

Read directly off the two shipped components plus the SPEC for STRUCTURE.

### 2.1 TX-ROOT — the canonical commitment (NOT a Merkle tree)

The daemon's `src/node/producer.cpp::compute_tx_root` (lines 262-270):

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

where `Hash = std::array<uint8_t,32>` and `std::set<Hash>` orders by the array's lexicographic raw-byte comparison. The commitment is:

$$
\mathrm{tx\_root} \;=\; H\Big(\;\big\Vert_{h \in \mathrm{sort}(u)}\, h\;\Big), \qquad u = \bigcup_{i}\bigcup_{j} \{\,\mathrm{creator\_tx\_lists}[i][j]\,\},
$$

with the empty-union case `u = ∅` yielding `H(\varepsilon) = \mathrm{SHA\text{-}256("")}` (the builder finalizes over zero appended bytes).

**This is a flat sorted-dedup-union commitment, NOT a Merkle tree.** It does *not* use `src/crypto/merkle.cpp` and therefore `MerkleTreeSoundness.md` MT-1..MT-5 do **not** apply. There is no leaf/inner domain separation, no `leaf_count` binding, no inclusion-proof structure. The only security property TX-ROOT rests on is A2 collision resistance of the single outer SHA-256 (§3.1). This document cites `MerkleTreeSoundness.md` solely to *disclaim* that import — a reader must not assume the richer Merkle properties hold here.

The wallet's reimplementation in `cmd_block_tx_root` (lines 14118-14164):

```cpp
std::set<std::array<uint8_t, 32>> u;
for (auto& list : j["creator_tx_lists"]) {           // outer loop over creators
    for (auto& hj : list) {                           // inner loop over tx_hashes
        std::vector<uint8_t> hb = from_hex(hj.get<std::string>());
        // (rejects non-string, non-hex, and size != 32)
        std::array<uint8_t, 32> h{};
        std::copy(hb.begin(), hb.end(), h.begin());
        u.insert(h);
    }
}
std::vector<uint8_t> buf;
for (auto& h : u) buf.insert(buf.end(), h.begin(), h.end());
std::array<uint8_t, 32> root{};
SHA256(buf.data(), buf.size(), root.data());          // OpenSSL one-shot
```

### 2.2 SIGS — the per-signer Ed25519 quorum gate

The daemon's accept gate (`src/node/validator.cpp:443-465`) computes the digest *itself* and verifies each non-sentinel sig against it:

```cpp
Hash digest = compute_block_digest(b);                 // ← daemon recomputes
for (size_t i = 0; i < b.creators.size(); ++i) {
    if (b.creator_block_sigs[i] == zero_sig) continue;  // sentinel = abstention
    auto e = registry.find(b.creators[i]);
    if (!verify(e->pubkey, digest.data(), digest.size(), b.creator_block_sigs[i]))
        return {false, "block sig invalid"};
    ++signed_count;
}
if (signed_count < required) return {false, "..."};     // required = required_block_sigs(mode, K)
```

The wallet's `cmd_committee_signature_verify` (lines 8832-8883) is structurally the same loop, with the **one critical substitution**: `digest_bytes` comes from the operator-supplied `--block-digest`, not from `compute_block_digest(b)`:

```cpp
int rc = crypto_sign_verify_detached(
    sig_bytes.data(),
    digest_bytes.data(), digest_bytes.size(),          // ← operator-supplied
    pk.data());
sig_valid = (rc == 0);
...
size_t required = (2 * present_count + 2) / 3;          // ceil(2P/3)
bool pass = (present_count > 0) && (valid_count >= required);
```

### 2.3 STRUCTURE — the well-formedness predicate

A pure structural predicate (no crypto): the parsed JSON is an object; it `contains` each of the seven required keys with the correct JSON type; `creators[]` is a non-empty array; every hex-typed field `from_hex`-decodes to its exact expected width (32 bytes for `prev_hash`/`tx_root`/each `tx_hash`; 64 bytes or the 128-zero sentinel for each signature). The component parse-checks already in `cmd_block_tx_root` (`:14104-14146`) and `cmd_committee_signature_verify` (`:8696-8735`, `:8779-8805`) supply the per-field width validators STRUCTURE composes; the new logic is the *presence + non-emptiness* conjunction over the full seven-field set.

---

## 3. Soundness theorems

Throughout, let `STRUCT ∈ {PASS, FAIL}`, `TXR ∈ {PASS, FAIL}`, `SIGS ∈ {PASS, FAIL, SKIP}` be the three component verdicts, and `BV ∈ {PASS, FAIL}` the aggregate (exit `0` / non-zero). Bounds follow `Preliminaries.md §2.0` (A1, A2 ≈ `2⁻¹²⁸`).

### 3.1 BV-1 (TX-ROOT byte-equivalence + soundness)

**Statement.** Under A2, the wallet's reimplemented `tx_root` recompute is **byte-identical** to the daemon's `src/node/producer.cpp::compute_tx_root` on every input, so a TX-ROOT PASS is *exactly* the daemon's `tx_root` accept gate. Consequently a daemon or block forger cannot produce a block whose stored `tx_root` passes TX-ROOT while committing to a different transaction set than the one in `creator_tx_lists`, except by exhibiting a SHA-256 collision (an A2 break, `≤ 2⁻¹²⁸`-class).

**Proof of byte-equivalence.** Both routines compute `H(‖_{h∈sort(u)} h)` over the same sorted-dedup union `u`. Match the four operations:

1. **Union + dedup + ordering.** Both insert every 32-byte `tx_hash` into a `std::set<std::array<uint8_t,32>>` (daemon: `std::set<Hash>` with `Hash = std::array<uint8_t,32>`; wallet: literally `std::set<std::array<uint8_t,32>>`). `std::set`'s default comparator is `std::less<std::array<uint8_t,32>>`, which is element-wise lexicographic over the raw bytes — identical in both. Insertion dedups identical hashes identically. The iteration order over the set is the sorted order in both. The nested loop order (outer over creator lists, inner over hashes) is identical and, because the result is a *set*, order-invariant regardless. ⇒ Both produce the **same ordered byte sequence** `‖_{h∈sort(u)} h`.

2. **Hashing.** The daemon appends each member to a `SHA256Builder` and finalizes; the wallet concatenates members into `buf` and calls OpenSSL `SHA256(buf, ...)` once. A streaming SHA-256 that appends the same byte sequence then finalizes is, by the Merkle–Damgård construction, **byte-identical** to a one-shot hash of the concatenation (SHA-256 is not keyed and has no per-append framing — `SHA256Builder::append(Hash)` appends exactly the 32 raw bytes, the wallet `buf` holds exactly those same bytes in the same order). The `cmd_block_tx_root` source comment at `:14155-14158` asserts precisely this equivalence. ⇒ Same digest.

3. **Empty union.** Both reduce to `SHA-256("")` when `u = ∅` (daemon: finalize over zero appends; wallet: `SHA256(buf=∅, 0, root)`). The §0 SPEC and the `cmd_block_tx_root` help text (`:14047-14048`) both pin this to match the daemon's empty-block emission. ⇒ Same digest on the empty case.

4. **Input domain.** Both accept the same 32-byte-hash domain; the wallet additionally *rejects* (returns 1, an args/parse fault — never a silent PASS) any list entry that is not a 64-hex 32-byte string (`:14128-14146`). So on every input the daemon would accept, the wallet computes the identical root; on inputs the daemon's struct could never hold (non-32-byte), the wallet fails closed at parse. ⇒ No input on which the two diverge into a *PASS*.

Hence the wallet's recomputed root equals the daemon's `compute_tx_root(creator_tx_lists)` bit-for-bit. The daemon's accept gate is `expected = compute_tx_root(...); reject if expected != b.tx_root`; the wallet's TX-ROOT PASS is `root == stored tx_root`. Since `root == expected`, **TX-ROOT PASS ⟺ the daemon's `tx_root` gate accepts** on the same block. ∎ (byte-equivalence)

**Proof of soundness.** Suppose an adversary `A_fork` (a malicious block producer / serving daemon) presents a block with stored field `tx_root = r` and lists `L = creator_tx_lists`, and wants TX-ROOT to PASS while the *true* committed transaction set differs from `union(L)`. TX-ROOT PASS requires `r == H(‖_{h∈sort(union(L))} h)`. For the verdict to be *misleading*, there must exist a second list-set `L' ≠ L` (a different tx-set) with `union(L') ≠ union(L)` yet the producer claimed `r` was the commitment to `L'` — i.e. `H(‖ sort(union(L'))) = r = H(‖ sort(union(L)))` with `sort(union(L')) ≠ sort(union(L))`. That is a SHA-256 collision on the outer hash. By A2 (collision resistance, `Preliminaries.md §2.1`), `Pr[\text{such collision}] ≤ 2⁻¹²⁸`-class. Absent such a collision, TX-ROOT PASS pins the stored root to the *unique* tx-set `union(L)` actually present in the block JSON, and (by byte-equivalence) this is exactly the set the daemon would bind. A forger cannot make a tampered tx-set pass except via an A2 break. ∎

**Bound.** `Pr[\text{TX-ROOT PASS} ∧ \text{committed set} ≠ union(L)] ≤ \varepsilon_{A2} ≤ 2⁻¹²⁸`-class (one outer-hash collision).

### 3.2 BV-2 (SIGS soundness, CONDITIONAL on a correct digest)

**Statement.** Under A1, a SIGS PASS implies there exist at least `required` valid Ed25519 signatures, by distinct committee members whose public keys are in the supplied `--committee`, **over the operator-supplied digest `d`** — where `required` is the quorum the final code computes (full K-of-K, or `⌈2K/3⌉` under `--bft`, or the component's unconditional `⌈2·present/3⌉`; see §0 D2). **This soundness is conditional on `d` being the block's true digest.** The wallet cannot recompute the true digest (no chain-library link ⇒ no `compute_block_digest`), so if the operator supplies a wrong `d`, SIGS verifies signatures over the wrong message and the verdict is **vacuous** — it neither implies nor denies that the block carries valid signatures over its *real* digest.

**Proof (the verification is sound for the digest it is given).** Fix the supplied digest `d` (32 bytes, validated to width at `:8656-8673`). For each creator `i` with a non-sentinel signature `σ_i` and committee pubkey `pk_i`, SIGS counts `i` as valid iff `crypto_sign_verify_detached(σ_i, d, pk_i) == 0`. By A1 (Ed25519 EUF-CMA, `Preliminaries.md §2.2`), an adversary not holding `sk_i` cannot produce a `σ_i` with `Verify(pk_i, d, σ_i) = 1` for a `d` member `i` never signed, except with probability `≤ 2⁻¹²⁸`. Therefore each counted-valid signer either (a) genuinely signed `d` under `sk_i`, or (b) the adversary broke A1 (`≤ 2⁻¹²⁸` per signer). SIGS PASS requires `valid_count ≥ required` such signers, each a distinct committee domain (the loop iterates `creators[i]` once each; `cmd_committee_signature_verify:8807-8815` fails closed if any creator is absent from the committee map, so every counted signer has a committee-bound key). The per-signer verification is a faithful `N`-fold replication of the single-sig verify primitive with no cross-signer state (the only shared state is the immutable `pubkey_of` map and the immutable `digest_bytes`) — this is the `BatchSigningSoundness.md` BS-3 "loop adds no attack surface" property instantiated for the committee-sig loop. Hence **SIGS PASS ⟹ `required` distinct committee members produced valid Ed25519 sigs over `d`**, under A1, up to `≤ K·2⁻¹²⁸`. ∎ (soundness *for `d`*)

**The conditional (the TCB-separation cost, stated honestly).** The above is sound *for whatever message `d` was supplied*. The daemon's accept gate verifies over `digest = compute_block_digest(b)` — a value it derives from the block's own fields, **excluding** `delay_output`, `creator_dh_secrets`, and ~9 other fields (`docs/PROTOCOL.md §4.3`; `src/node/validator.cpp:443`). The wallet **cannot** compute this: `compute_block_digest` lives in the chain library, which `determ-wallet` deliberately does not link (TCB separation). Three consequences, all honestly disclosed:

1. **A correct `d` ⇒ meaningful verdict.** If the operator supplies the block's *true* digest (e.g. copied from `determ verify-block-sigs`'s emitted `digest:` line, which *does* run `compute_block_digest`), then SIGS PASS is exactly the daemon's committee-sig accept gate over that digest, and BV-2's soundness statement is the real "K-of-K (or BFT-quorum) valid committee signatures over the block" property.
2. **A wrong `d` ⇒ vacuous verdict.** If the operator supplies a digest that is *not* the block's true digest, then: SIGS may FAIL (the real sigs don't verify over the wrong `d`) — a *false FAIL*, not a soundness break; or, only by an A1 break (`≤ 2⁻¹²⁸`) or by the operator supplying a digest the committee *did* coincidentally sign for some *other* block, could SIGS PASS over a wrong-for-this-block `d`. In no case does a wrong `d` cause `block-verify` to assert a *true* property about *this* block's signatures. The verdict is vacuous, not unsound-in-the-A1-sense: it correctly reports "these sigs are/aren't valid over `d`," it just may be the wrong `d`.
3. **The digest must come from a trusted source.** Because the wallet cannot self-check `d`, the security of the SIGS verdict reduces to the trustworthiness of the digest source. The canonical trusted source is `determ verify-block-sigs` (a chain-linked daemon tool that computes `compute_block_digest` itself). This is the **wallet-TCB-separation cost**: the wallet trades the ability to recompute the digest for a lean, chain-library-free TCB, and pays it as a stated operator obligation.

**Bound.** `Pr[\text{SIGS PASS} ∧ ¬(required \text{ valid committee sigs over } d)] ≤ K·2⁻¹²⁸` (A1, per signer). The *conditional* — that `d` is the block's true digest — is **not** a probabilistic term; it is an operator-supplied precondition (§5 F-BV2). The honest statement of BV-2 is: *sound under A1 for the supplied digest; meaningful for this block iff the digest is correct.*

### 3.3 BV-3 (composite soundness + fail-closed)

**Statement.** Under A1 + A2, `BV = PASS` (exit 0) implies the conjunction

> **STRUCTURE** (the block JSON is well-formed — required fields present, types correct, hex widths valid, `creators[]` non-empty)
> **∧ TX-ROOT** (the stored `tx_root` is the canonical commitment over `creator_tx_lists`, BV-1, under A2)
> **∧ (SIGS-PASS ∨ SIGS-SKIP)** (either `required` valid committee sigs over the supplied digest, BV-2 conditional, under A1; or SIGS was not attempted because `--committee`/`--block-digest` was absent).

Moreover, any check FAIL or any args/parse error yields a **non-zero exit, never a false PASS**, and SIGS-SKIP is **reported, not PASS-masking**.

**Proof of composite soundness.** `BV = PASS` ⟺ `overall` true ⟺ `STRUCT = PASS ∧ TXR = PASS ∧ SIGS ∈ {PASS, SKIP}` (§1.1 step 5). Each conjunct reduces to its component:

- `STRUCT = PASS` ⟹ the seven required fields are present, correctly typed, hex widths valid, `creators[]` non-empty (BV-3's structural predicate; deterministic, no assumption). This is *well-formedness*, the precondition the other two checks rely on (a malformed JSON could not even be parsed into the lists/sigs the other checks consume).
- `TXR = PASS` ⟹ (BV-1) the stored `tx_root` equals the canonical union-commitment over `creator_tx_lists`, under A2, byte-identical to the daemon's gate.
- `SIGS = PASS` ⟹ (BV-2) `required` distinct committee members signed the supplied digest under A1 (conditional on a correct digest); **or** `SIGS = SKIP` ⟹ SIGS was not attempted (no committee/digest), which the conjunction admits *explicitly* (the spec's `SIGS-PASS ∨ SIGS-SKIP`), and which the aggregate reports as SKIP (§ fail-closed below).

The composite adds no verification logic beyond the conjunction; its soundness is exactly the conjunction of the three. `Pr[BV = PASS ∧ ¬(\text{STRUCT} ∧ \text{TXR-sound} ∧ \text{SIGS-or-skip})] ≤ \varepsilon_{A2} + \varepsilon_{A1}` (§3.4). ∎

**Proof of fail-closed.** Enumerate every non-PASS pathway and confirm each yields a non-zero exit with no false PASS:

- **Args/parse fault.** Missing `--block-json`, unknown arg, unreadable file, non-JSON, non-object → `return 1` *before any verdict is recorded* (§1.1 step 1; both components do exactly this). Exit 1, never PASS.
- **STRUCTURE FAIL.** A missing/mistyped required field, a wrong hex width, or empty `creators[]` → `STRUCT = FAIL` → `overall = false` → exit 2. (The width-decode faults are the same `from_hex`/size checks the components already return 1 on; under the composite they become a recorded FAIL verdict rather than a bare parse return, but either way the exit is non-zero — §0 D1 reconciliation does not change this.)
- **TX-ROOT FAIL.** `root != stored tx_root` → `TXR = FAIL` → exit 2. (Mirrors `cmd_block_tx_root --check` returning 2 at `:14219`.)
- **SIGS FAIL.** `valid_count < required` (or `present_count == 0`) → `SIGS = FAIL` → exit 2. (Mirrors `cmd_committee_signature_verify` returning 2 at `:8918`.) A *stricter* quorum than the spec intends (the §0 D2 ambiguity) can only push more blocks into FAIL — a possible false FAIL, never a false PASS. This is why D2 does not threaten soundness.
- **SIGS SKIP.** Neither `--committee` nor `--block-digest` (or only one) supplied → `SIGS = SKIP`. The conjunction admits `SIGS-SKIP` as non-blocking, so `overall` can still be PASS *iff STRUCTURE and TX-ROOT both passed*. Crucially, SKIP is **not PASS-masking**: (i) it does not assert any signature property — the aggregate output records the literal `SIGS SKIP (no committee/digest supplied)` row in both `--json` and human modes, so the operator sees that sigs were *not checked*; (ii) it does not turn a STRUCTURE/TX-ROOT FAIL into a PASS — those failures independently force exit 2; (iii) a PASS-with-SKIP is *honestly weaker* than a PASS-with-SIGS-PASS, and the verdict surface says so. A monitor that requires signature assurance MUST supply both flags; a monitor that only needs structural + tx-root assurance MAY omit them and reads the SKIP as an explicit "sigs unverified" disclosure.

In every non-PASS pathway the exit is non-zero (1 for args/parse, 2 for a check FAIL) and no `BV: PASS` is emitted. `overall` is the three-way conjunction; no code path sets it true while a check FAILed. BV-3 holds. ∎

### 3.4 BV-E (composition error bound)

**Statement.** The composite's soundness error is the sum of its two cryptographic components' bounds; STRUCTURE and the SKIP/conjunction logic are deterministic and contribute no term:

$$
\Pr[\text{BV} = \text{PASS} \ \wedge\ \neg(\text{STRUCT} \wedge \text{TXR-sound} \wedge \text{SIGS-or-skip})]
\;\le\; \varepsilon_{\text{TXR}} + \varepsilon_{\text{SIGS}}
\;\le\; \underbrace{2^{-128}\text{-class}}_{\text{A2, one outer hash}} \;+\; \underbrace{K \cdot 2^{-128}}_{\text{A1, } K \text{ signers}}.
$$

**Derivation.** `BV = PASS` requires `STRUCT = PASS ∧ TXR = PASS ∧ SIGS ∈ {PASS, SKIP}` (BV-3). The event "BV passes yet a *cryptographic* component is unsound" is contained in "(TXR passes yet TXR unsound) ∨ (SIGS passes yet SIGS unsound-for-d)"; by the union bound it is `≤ Pr[TXR unsound] + Pr[SIGS unsound]`. From BV-1, `Pr[TXR unsound] ≤ \varepsilon_{A2} ≤ 2⁻¹²⁸`-class (a single outer-SHA-256 collision). From BV-2, `Pr[SIGS unsound for d] ≤ K·2⁻¹²⁸` (an Ed25519 forgery for one of ≤ K signers). STRUCTURE is a deterministic predicate (probability-1 correct on its own definition) and the conjunction / SKIP-gating / exit-code mapping are deterministic boolean operations — none adds a cryptographic term, exactly as `LightClientAuditComposition.md` AC-E argues for its orchestration. For practical committees (`K ≤ 16`) the bound is `≤ 2⁻¹²³`-class, dominated by the K-fold A1 term. ∎

**The conditional is NOT in the bound.** BV-E bounds the probability that BV PASSes while a check is *cryptographically* unsound. It does **not** bound the BV-2 conditional — that the operator-supplied digest is correct. A wrong digest is an operator-input error, not a cryptographic event; it is handled as a stated precondition (§5 F-BV2), not a probability term. This is the formal counterpart of "the wallet trusts the digest source": the bound is conditional on a correct `d`, and that conditioning is made explicit rather than absorbed into `\varepsilon`.

---

## 4. Composition with companion proofs

### 4.1 `LightClientAuditComposition.md` — the orchestration-only sibling

`block-verify` is the wallet-TCB, OFFLINE, single-block analogue of `audit`. Both are "pure orchestration over already-grounded checks, conjoined to one exit code," and both carry the AC-2/BV-3 posture (the shell adds no trust surface; the exit code is a faithful function of component verdicts; fail-closed on every error). The differences are: (a) `audit` composes two RPC-backed chain-walk composites, `block-verify` composes two local single-block primitives + a structural predicate; (b) `audit`'s components are each *separately sound standalone*, `block-verify`'s SIGS component carries the digest *conditional* (the load-bearing asymmetry, BV-2); (c) `audit` has a CHAIN→SUPPLY short-circuit SKIP, `block-verify` has a SIGS SKIP gated on flag presence rather than a prior check's verdict. Both SKIPs are *reported, not PASS-masking* (AC-4 / BV-3).

### 4.2 `MerkleTreeSoundness.md` — cited to DISCLAIM, not import

TX-ROOT is **not** the Merkle primitive. `compute_tx_root` is a flat sorted-dedup-union SHA-256 commitment with no leaf/inner domain separation, no `leaf_count` binding, and no inclusion-proof structure; it does not touch `src/crypto/merkle.cpp`. MT-1 (determinism) has an analogue here — same tx-set ⇒ same root, by the same set-ordering argument (BV-1 step 1) — but MT-2..MT-5 (second-preimage via domain-separated leaves, inclusion-proof soundness, `leaf_count` binding, non-membership) do **not** apply. TX-ROOT's only cryptographic dependency is A2 on the single outer hash (BV-1). This cross-reference exists to prevent a reader from importing the richer Merkle guarantees.

### 4.3 `BatchSigningSoundness.md` — the per-signer loop is a faithful N-fold replication

SIGS's per-creator verification loop is a composition of the single-sig verify primitive, exactly as `verify-batch` (BS-3) composes the single-tx verify. BV-2's "no cross-signer state, sole shared state is the immutable committee map + immutable digest" argument *is* BS-1/BS-3's structural-isolation argument specialized to the committee-sig loop: signer `i`'s verdict depends only on `(σ_i, d, pk_i)`, never on signer `j ≠ i`. The composite inherits BS-3's per-record soundness with no new attack surface from the loop.

### 4.4 `Preliminaries.md` — the assumption base

BV-1 reduces to A2 (§2.1); BV-2 reduces to A1 (§2.2). A3 and A4 are not used (there is no preimage argument and no sampling). The composite's bound (BV-E) is the union of these two, with no independent term — consistent with the deterministic-orchestration posture.

---

## 5. Findings (honest limitations)

Stated so an operator knows exactly what a `block-verify: PASS` does and does not assert. None undermines the per-invocation soundness of BV-3; all are coverage/scope statements or the one TCB-separation conditional.

### F-BV1 STRUCTURE is well-formedness, not semantic validity

A STRUCTURE PASS asserts the JSON is a *syntactically well-formed block envelope* (required fields present, correct types, hex widths valid, `creators[]` non-empty). It does **not** assert the block is *semantically* valid: that `index` succeeds a real predecessor, that `prev_hash` links to an actual prior block, that `timestamp` is in-window, that `creators[]` is the protocol-selected committee for that height, that abort/BFT-proposer fields are internally consistent, or that the transactions in `creator_tx_lists` are themselves signed/nonce-ordered/balance-covered. Those are chain-state and apply-layer properties (`Safety.md`, `AccountStateInvariants.md`, the apply-track proofs) requiring full chain context the wallet does not have. `block-verify` is a *well-formedness + commitment + signature-quorum* check on one isolated object, not a consensus-validity oracle.

### F-BV2 SIGS soundness is CONDITIONAL on a correct operator-supplied digest (the TCB-separation cost)

This is the load-bearing honesty of the proof. `determ-wallet` does **not** link the chain library, so it **cannot** recompute `compute_block_digest(b)` — the value the daemon actually verifies committee signatures against (`src/node/validator.cpp:443`; the digest excludes `delay_output`, `creator_dh_secrets`, and ~9 other fields per `docs/PROTOCOL.md §4.3`). SIGS therefore verifies signatures over an **operator-supplied** `--block-digest`. A SIGS PASS is sound (under A1) *for that supplied digest*; it is a *meaningful* statement about *this block* **iff the supplied digest is the block's true digest**. A wrong digest yields a *vacuous* verdict (typically a false FAIL; a false PASS would require an A1 break or a cross-block coincidence). The digest must come from a trusted, chain-linked source — canonically `determ verify-block-sigs`, which computes `compute_block_digest` itself. This is the deliberate cost of the wallet's lean TCB: it trades digest self-recomputation for a chain-library-free trusted base, and pays it as a stated operator obligation, not a hidden assumption. An operator who supplies a digest of unknown provenance gets a SIGS verdict of unknown meaning.

### F-BV3 No genesis, no continuity, no chain context — single block only

`block-verify` is a *single-block* predicate. There is no genesis anchor (contrast `LightClientThreatModel.md` T-L1 / `audit`'s CHAIN conjunct), no prev_hash-continuity walk, no committee-rotation threading, no head pinning. A PASS asserts properties of *this one JSON object in isolation*. It cannot and does not assert the block belongs to any particular chain, follows any particular predecessor, or is the canonical block at its height. An operator needing chain-anchored assurance runs the `determ-light verify-chain` / `audit` family (which *do* link the verification path and walk from a pinned genesis).

### F-BV4 TX-ROOT verifies the commitment over the SUPPLIED lists, not their correctness as a tx-set

TX-ROOT PASS means the stored `tx_root` is a faithful commitment over whatever `creator_tx_lists` the JSON carries (BV-1). It does **not** assert those lists are the transactions the block *should* contain — censorship (a creator omitting a tx) and inclusion (a specific tx being present) are out of scope (`Censorship.md`, the per-tx-inclusion proofs). A block that commits faithfully to a *censored* tx-set passes TX-ROOT; TX-ROOT detects only a stored-root that disagrees with the present lists, i.e. a tampered/forged root.

### F-BV5 The `--bft` quorum semantics depend on the final implementation (§0 D2)

The reused `cmd_committee_signature_verify` computes `required = ⌈2·present_count/3⌉` *unconditionally* — it has no full-K-of-K MUTUAL_DISTRUST branch and no `--bft` switch. The §0 SPEC, by contrast, asks for full K-of-K *without* `--bft` and `⌈2K/3⌉` *with* it. Until `cmd_block_verify` lands, it is unresolved whether the composite (a) adds the two-mode `required_block_sigs` branch (matching `src/node/validator.cpp`'s daemon behavior) or (b) inherits the component's unconditional `⌈2P/3⌉`. BV-2/BV-3 are proved over *whatever quorum the final code computes*; a quorum stricter than intended can only cause a false FAIL, never a false PASS (BV-3 fail-closed), so this does not threaten soundness — but it does affect *which* blocks PASS, and an operator must know which threshold their build enforces. **Reconcile when the command lands.**

### F-BV6 Off-curve / malformed committee keys and sentinel semantics inherited from the component

SIGS inherits `cmd_committee_signature_verify`'s exact handling: a committee member with a non-64-hex / non-32-byte pubkey is a hard parse fault (exit 1, fail-closed, `:8779-8805`); a creator absent from the committee map is a hard fault (`:8807-8815`); an all-128-zero or empty signature is a *sentinel abstention* counted toward `missing_count`, not a failure (`:8838-8840`) — matching the daemon's `zero_sig` sentinel (`src/node/validator.cpp:452`). These are not new surfaces; they are the component's behavior, carried verbatim. The all-zero-sentinel false-positive rate (a real Ed25519 sig that is all zeros) is `~2⁻⁵¹²`, negligible (`validator.cpp:448-451`).

---

## 6. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code. **Note:** `cmd_block_verify` itself is not yet in tree (§0); the rows below cite the *components* it composes plus the daemon originals BV-1/BV-2 reduce to. Re-anchor the `cmd_block_verify` rows when the command lands.

| Theorem | Component | File:lines | Role |
|---|---|---|---|
| BV-1 | wallet `tx_root` recompute | `wallet/main.cpp:14118-14164` | `std::set<array<uint8_t,32>>` union + `SHA256(concat)` — the reimplementation. |
| BV-1 | wallet `--check` byte-compare | `wallet/main.cpp:14171-14219` | Decode stored `tx_root`, `std::equal` against recomputed; exit 2 on mismatch. |
| BV-1 | daemon original | `src/node/producer.cpp:262-270` | `compute_tx_root` — the byte-identical reference. |
| BV-1 | daemon accept gate | `src/node/producer.cpp:803` | `b.tx_root = compute_tx_root(b.creator_tx_lists)` (producer); validator re-derives + compares. |
| BV-2 | wallet per-signer verify | `wallet/main.cpp:8832-8870` | `crypto_sign_verify_detached(σ_i, digest_bytes, pk_i)` over the **operator-supplied** digest. |
| BV-2 | wallet quorum | `wallet/main.cpp:8882-8883` | `required = (2*present+2)/3`; `pass = present>0 && valid≥required`. |
| BV-2 | digest is operator-supplied | `wallet/main.cpp:8656-8673` | `--block-digest` parsed to 32 bytes; **never recomputed** (no chain-lib link). |
| BV-2 | daemon original (digest recomputed) | `src/node/validator.cpp:443-465` | `digest = compute_block_digest(b)` then per-sig `verify`; `signed_count < required` → reject. |
| BV-2 | digest field exclusions | `docs/PROTOCOL.md §4.3` | Why the wallet cannot recompute the digest. |
| BV-3 | composite conjunction + exit | `cmd_block_verify` (TBD, §0) | `overall = STRUCT ∧ TXR ∧ (SIGS-PASS ∨ SIGS-SKIP)`; exit 0/1/2. |
| BV-3 | STRUCTURE width validators (reused) | `wallet/main.cpp:14104-14146`, `:8696-8735` | Per-field presence/type/width checks the predicate composes. |
| BV-3 | TX-ROOT FAIL exit | `wallet/main.cpp:14219` | `if (do_check && !match) return 2;` (component's exit-2 posture). |
| BV-3 | SIGS FAIL exit | `wallet/main.cpp:8918` | `return pass ? 0 : 2;` (component's exit-2 posture). |
| BV-E | (no new term) | — | Bound = `\varepsilon_{A2} + K·\varepsilon_{A1} ≤ 2⁻¹²³`-class; STRUCTURE + conjunction deterministic. |

**Tests** (to be added with the command; the components are already exercised):

| Test | Coverage |
|---|---|
| `tools/test_block_tx_root.sh` (existing) | TX-ROOT core (BV-1): recompute + `--check` match/mismatch, empty union ⇒ `SHA-256("")`. |
| `tools/test_committee_signature_verify.sh` (existing) | SIGS core (BV-2): valid quorum PASS, sub-quorum FAIL, sentinel abstention, wrong-digest FAIL. |
| `tools/test_block_verify.sh` (TBD) | BV-3 end-to-end — happy-path PASS (all three), STRUCTURE-fail → exit 2, TX-ROOT tamper → exit 2, SIGS sub-quorum → exit 2, SIGS SKIP (no committee/digest) reported + still-PASS-if-others-pass, `--json` aggregate shape, wrong-digest → SIGS FAIL (the F-BV2 false-FAIL path). |

---

## 7. Status

- **Implementation.** **SHIPPED.** `int cmd_block_verify` is in `wallet/main.cpp` (dispatched on `block-verify`), exercised by `tools/test_wallet_block_verify.sh` (24/24 offline assertions: STRUCTURE + TX-ROOT both branches, SKIP, fail-closed negatives, `{block:{...}}`-envelope rejection, and the SIGS-attempted-then-FAIL delegation branch). The two composed components: `cmd_block_tx_root` (`:14019`) and `cmd_committee_signature_verify` (`:8623`).
- **Proof.** Complete (this document). BV-1 (TX-ROOT byte-equivalence to `producer.cpp::compute_tx_root` + A2 soundness — a tampered tx-set cannot pass except via a SHA-256 collision); BV-2 (SIGS soundness under A1, **CONDITIONAL** on a correct operator-supplied digest — the wallet cannot recompute `compute_block_digest`, the TCB-separation cost, stated as a precondition not a probability term); BV-3 (composite soundness = conjunction of STRUCTURE ∧ TX-ROOT ∧ (SIGS ∨ SIGS-skip), fail-closed — every FAIL/parse-error → non-zero exit, never a false PASS; SIGS SKIP reported, not PASS-masking). Composition bound BV-E (`≤ \varepsilon_{A2} + K·\varepsilon_{A1} ≤ 2⁻¹²³`-class; no new cryptographic term; the digest conditional is NOT in the bound).
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA, SIGS), A2 (SHA-256 collision resistance, TX-ROOT). A3, A4 not used. Per `Preliminaries.md §2.0`.
- **Obligations — RESOLVED.** (§0 D1) STRUCTURE presence-checks `creator_block_sigs` (matching the components, not the early-draft `block_sigs`) plus `creator_tx_lists` + `tx_root` — the field-name mismatch was caught + fixed during implementation, before it could wrongly reject real blocks. (§0 D2 / F-BV5) the composite inherits `cmd_committee_signature_verify`'s unconditional `⌈2P/3⌉` quorum (no `--bft`, no full-K branch). Neither affected cryptographic soundness.
- **Composes with.** `LightClientAuditComposition.md` (the orchestration-only sibling — AC-2/AC-3/AC-4 posture mirrored), `MerkleTreeSoundness.md` (cited to *disclaim* — `tx_root` is NOT a Merkle tree), `BatchSigningSoundness.md` (BS-3 per-signer-loop isolation), `Preliminaries.md` (A1 + A2 base).
- **Known limitations (§findings).** F-BV1 (STRUCTURE is well-formedness, not semantic validity); **F-BV2 (the load-bearing one: SIGS is conditional on a correct operator-supplied digest — the wallet-TCB-separation cost; a wrong digest yields a vacuous verdict)**; F-BV3 (single block only — no genesis/continuity/chain context); F-BV4 (TX-ROOT commits over the supplied lists, not their correctness as a tx-set); F-BV5 (the `--bft` quorum semantics depend on the final implementation); F-BV6 (off-curve key / sentinel handling inherited verbatim from the component). None undermines the per-invocation soundness of BV-3.
- **The TCB-separation posture (load-bearing).** `determ-wallet` deliberately does not link the chain library. TX-ROOT and the Ed25519 gate are reimplemented inline; BV-1 proves the TX-ROOT reimplementation is byte-identical to the daemon's, so its PASS is exactly the daemon's gate (sound, unconditional under A2). SIGS is sound under A1 but cannot recompute the digest, so its meaningfulness for *this* block is conditional on a correct supplied digest (BV-2). This is the precise boundary between what `block-verify` proves unconditionally (well-formedness + the tx-root commitment) and what it proves conditionally (the committee signatures, given a trusted digest).

---
