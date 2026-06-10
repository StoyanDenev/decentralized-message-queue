# LightVerifyChainFileSoundness — self-contained OFFLINE whole-chain file verifier (`determ-light verify-chain-file`)

This document proves the soundness of the `determ-light verify-chain-file` subcommand: a **composite, one-shot, fully OFFLINE whole-chain verifier** — the *file-based dual* of the online `verify-chain` — that an operator runs against an exported headers file plus committee material, with **NO daemon, NO RPC, NO network**, to obtain a single PASS/FAIL verdict over two checks:

- **CONTINUITY** — `verify_headers(doc, genesis_hash_hex, prev_hash_hex)` (`light/verify.cpp:135-233`): walks the stored `prev_hash` chain (`header[i].prev_hash == header[i-1].block_hash`) over the file's own `block_hash` fields, optionally anchoring block 0 via `--genesis-hash` or a mid-chain start via `--prev-hash`.
- **SIGS** — for every header with `index != 0`, `verify_block_sigs(header, committee, bft)` (`light/verify.cpp:235-328`), which **recomputes** the block digest via `light_compute_block_digest` and Ed25519-verifies the committee signatures over that recomputed digest. **Only `index == 0` (the genesis) is skipped.**

It conjoins the two into one verdict with a monitor-friendly exit code (`0` both pass, `2` a check failed, `1` args/parse error).

```
determ-light verify-chain-file --in <file>
    (--committee <file> | --committee-manifest <file>)
    [--genesis-hash <hex64>] [--prev-hash <hex64>] [--bft] [--json]
```

**The load-bearing distinction — and a real bug this proof records.** `verify-chain-file` is the **offline, file-based analogue** of the online `verify-chain` chain-walk (`LightClientThreatModel.md` T-L1/T-L2 over RPC pages). It reuses the *exact same two primitives* — `verify_headers` and `verify_block_sigs` — but consumes a **local exported headers file** rather than paging from a live daemon. This shifts the threat model: the adversary is no longer (only) a lying daemon over the wire, but an attacker who can **edit the file on disk** before the operator runs the verifier. The single most important design decision under that threat model is **where the genesis-skip is keyed**: on `index == 0`, **NOT** on an empty `creator_block_sigs` array. **A mid-development bug keyed the skip on emptiness; this proof records its fix as Lemma VCF-S (the strip-hole lemma)** and proves the index-based skip closes the hole.

**A note on what "composite" means here.** Like the single-block `block-verify` sibling (`LightBlockVerifySoundness.md`, LBV-1/LBV-2/LBV-3), `verify-chain-file` composes *checks*, not bare cryptographic primitives. Unlike `block-verify` (a single-block predicate), `verify-chain-file` is a **whole-chain** predicate: it conjoins a *linkage* check (CONTINUITY, over the stored `block_hash` walk) with a *per-block attestation* check (SIGS, over every non-genesis header). The composite covers two distinct attacks — reordering / linkage-break (CONTINUITY) and content-tamper / forgery (SIGS) — that neither check covers alone (§3.3). Its honest residual is exactly the one its online and single-block siblings carry: **committee provenance** (`LightBlockVerifySoundness.md` F-LBV3 / `LightClientThreatModel.md` T-L2 caveat).

**Canonical assumption labels.** Per `Preliminaries.md §2.0`: **A1** = Ed25519 EUF-CMA (`Preliminaries.md §2.2`), **A2** = SHA-256 collision resistance (`Preliminaries.md §2.1`). `verify-chain-file` reduces to **A1** (SIGS) + **A2** (CONTINUITY genesis anchor) only; A3 and A4 are not used by this path.

**Companion documents.**
- `LightBlockVerifySoundness.md` (LBV-1/LBV-2/LBV-3, **F-LBV5**) — the **single-block sibling**. `verify-chain-file`'s SIGS check is `verify_block_sigs` applied once per non-genesis header; LBV-2 (the **UNCONDITIONAL** per-block SIGS soundness, digest self-recomputed) is inherited verbatim per header, and **F-LBV5** (cross-shard / F2 fail-close) is inherited directly here as **F-VCF6**.
- `LightClientThreatModel.md` (**T-L1** genesis-anchored chain identity §4.1, **T-L2** head trust via committee signatures §4.2, **Lemma L-2** `light_compute_block_digest` byte-equivalence §4.6) — `verify-chain-file` is the OFFLINE-file dual of the online `verify-chain` chain-walk these theorems cover. CONTINUITY's genesis anchor instantiates the T-L1 byte-equality check from a `--genesis-hash` flag instead of a recomputed `compute_genesis_hash`; SIGS instantiates T-L2 per header.
- `OfflineBlockVerifySoundness.md` (BV-1/BV-2/**F-BV2**) — the wallet sibling whose **conditional** SIGS posture (operator-supplied digest) `verify-chain-file` improves on by self-recomputing the digest (it links the chain library, like `determ-light`).
- `Safety.md` (**FA1**) — the per-block K-of-K (or `Q = ⌈2|K_h|/3⌉` BFT) signature-set safety primitive (`Safety.md` Lemma L-1.3) that SIGS consumes per header.
- `BatchSigningSoundness.md` (**BS-3**, the per-signer loop) — SIGS's per-creator verification loop instantiates BS-3's structural-isolation (no cross-signer channel); here it is replicated once per non-genesis header with no cross-header channel either.
- `Preliminaries.md` (F0) §2.0 (assumption labels), §2.1 (A2), §2.2 (A1).

---

## 0. Implementation status

**`int cmd_verify_chain_file(int, char**)` is IMPLEMENTED and SHIPPED in `light/main.cpp:850-1011`** (dispatched on `verify-chain-file` at `light/main.cpp:6057`). It is the offline file dual of the online `cmd_verify_chain` (`light/main.cpp:1136`). The two composed verification cores are read directly off source and are the same primitives the online `verify-chain` family uses:

- **CONTINUITY** — `determ::light::verify_headers` (`light/verify.cpp:135-233`): leading-header anchor (`index == 0` ⇒ zero `prev_hash`, optional `--genesis-hash` byte-equality against `headers[0].block_hash`; `index > 0` ⇒ optional `--prev-hash` match), then the consecutive-pair walk `headers[i].prev_hash == headers[i-1].block_hash` over the **stored** `block_hash` fields (`light/verify.cpp:211-223`).
- **SIGS** — for each header in `doc` with `index != 0`, `determ::light::verify_block_sigs` (`light/verify.cpp:235-328`), which calls `light_compute_block_digest` (`light/verify.cpp:57-92`) to **recompute** the digest internally, then per-creator Ed25519-verifies (`determ::crypto::verify`) against it, enforcing `required = bft ? (2K+2)/3 : K`. The genesis skip is keyed on `idx == 0` at `light/main.cpp:962`.

The single-committee vs. `--committee-manifest` resolver is the `committee_for` lambda at `light/main.cpp:892-912`: single-committee mode returns the same committee for every index; manifest mode picks the inclusive `[from, to]` range covering `idx` and lazily loads + caches its committee file, returning `false` (⇒ SIGS FAIL, never skip) when **no** range covers `idx` (`light/main.cpp:910-911`).

---

## 1. Scope

### 1.1 In scope

The `determ-light verify-chain-file` composite. Its control flow, read off `light/main.cpp:850-1011`:

1. **Argument parse + validation (`:851-885`).** `--in` is required (`:867-870`). **Exactly one** of `--committee` / `--committee-manifest` is required — the XOR is enforced by `committee_path.empty() == manifest_path.empty()` ⇒ error (`:871-875`), so supplying both or neither is a hard `return 1`. `--genesis-hash`, `--prev-hash`, `--bft`, `--json` are optional. An unknown arg (`:862-865`) or an unreadable / non-JSON file (`:882-884`) → `return 1` (args/parse error) **before any check verdict is recorded**.

2. **CONTINUITY check (`:918-937`).** Call `verify_headers(doc, genesis_hash_hex, prev_hash_hex)`. CONTINUITY PASS ⟺ `r.ok`. The verdict and an anchor annotation (`genesis-anchored` / `prev-anchored` / unanchored) are recorded.

3. **SIGS check (`:939-986`), gated on CONTINUITY PASS.** **Only if CONTINUITY passed** (`:940`), iterate every header in `doc`. For each header: read `idx`; if `idx == 0`, increment `skipped` and `continue` (`:962`, genesis); otherwise resolve the committee via `committee_for(idx, …)` (FAIL via thrown `runtime_error` if no range covers it, `:965-966`) and call `verify_block_sigs(h, committee, bft)` — any `!vbs.ok` throws (`:968-969`). If `verified == 0 && skipped > 0` (only the genesis present), throw "no committee-signed block to verify" (`:972-973`). SIGS PASS ⟺ the loop completes with `ok = true`. If CONTINUITY FAILed, SIGS is recorded as **SKIP** (`:984-985`).

4. **Aggregate verdict + exit (`:988-1010`).** `overall = (failed == 0)`. Exit `0` iff `overall`; exit `2` iff any check FAILed; exit `1` on the args/parse faults of step 1. `--json` emits an aggregate object (`audit`, `passed`, `failed`, `checks[]`); human mode emits a per-check summary. Output is read-only over the verdicts.

### 1.2 The two components

| Component | Implementation basis | What it establishes | Backing |
|---|---|---|---|
| **CONTINUITY** | `verify_headers` (`light/verify.cpp:135-233`) | The file's headers form an unbroken stored-`block_hash` linkage (`prev_hash[i] == block_hash[i-1]`), optionally anchored at block 0 (`--genesis-hash`) or mid-chain (`--prev-hash`) | A2 at the anchor (VCF-1 §3.1); structural for the walk |
| **SIGS** | per non-genesis header `verify_block_sigs` (`light/verify.cpp:235-328`) | Every header with `index != 0` carries a committee-signature quorum over **`light_compute_block_digest(b)` — recomputed from THAT header** | A1, **UNCONDITIONAL** per header (VCF-2 §3.2, inheriting LBV-2) |

### 1.3 Out of scope (intentional — the verifier's coverage boundary)

- **Committee provenance.** SIGS verifies against the operator-supplied `--committee` / `--committee-manifest`. `verify-chain-file` proves each block is signed by *that supplied committee*; it does **not** prove the supplied committee(s) are the genuine, height-correct committees. This is the one load-bearing residual — `LightBlockVerifySoundness.md` F-LBV3, `LightClientThreatModel.md` T-L2 caveat — surfaced here as §3.4 / F-VCF3.
- **Genesis trust without `--genesis-hash`.** Genesis (index 0) carries no committee sigs by construction; its trust comes **only** from the `--genesis-hash` anchor in CONTINUITY (byte-matched against the file's own `headers[0].block_hash`). **Without `--genesis-hash`, genesis is unanchored** — the file's claimed block-0 hash is taken as given, and the whole chain is verified relative to *whatever* block 0 the file asserts (§3.4 / F-VCF4). This is a documented limitation, the offline-file counterpart of the online T-L1 anchor.
- **Block-hash recomputation.** CONTINUITY walks the **stored** `block_hash` fields; it does **not** recompute `Block::compute_hash` per header. The linkage it checks is "the file is internally consistent as a prev_hash chain," not "each stored `block_hash` is the true hash of its block body." The per-block content attestation is SIGS's job, not CONTINUITY's (§3.1 records exactly what CONTINUITY does and does not assert; §3.3 proves SIGS closes the content-tamper gap CONTINUITY leaves open).
- **Cross-shard / F2-reconciled digest extensions.** `light_compute_block_digest` omits the `compute_view_root` terms the full producer binds for cross-shard / F2 blocks; SIGS **fail-closes** (false-negative, never a false PASS) on such blocks. Inherited from `LightBlockVerifySoundness.md` F-LBV5; surfaced here as F-VCF6.
- **Semantic / consensus validity.** A PASS does not assert any block's transactions are individually valid (signed / nonce-ordered / balance-covered), that timestamps are in-window, or that `creators[]` is the protocol-selected committee for the height. Those are apply-layer / chain-state properties (`Safety.md`, the FA-Apply track). §F-VCF5.

---

## 2. Construction specification

Read directly off the two components.

### 2.1 CONTINUITY — the stored-`block_hash` linkage walk (NOT a hash recompute)

`verify_headers` (`light/verify.cpp:135-233`), two phases:

**Anchor phase (`:137-164`).** Let `headers[0]` have index `i0` and `prev_hash` field `p0`.
- If `i0 == 0`: require `p0 == "0"*64` (genesis has zero prev_hash, `:187-192`). If `--genesis-hash` (`genesis_hash_hex`) is non-empty, require `headers[0].block_hash == genesis_hash_hex` byte-for-byte (`:193-200`). **This is the only genesis trust anchor.**
- Else (`i0 > 0`) and `--prev-hash` (`prev_hash_hex`) non-empty: require `p0 == prev_hash_hex` (`:157-164`), anchoring a mid-chain start to a caller-supplied prior block hash.

**Walk phase (`:166-178`).** For `i` from `1` to `headers.size()-1`:
```cpp
std::string prev       = headers[i].prev_hash;       // 64-hex, validated width
std::string prior_hash = headers[i-1].block_hash;    // 64-hex, validated width
if (prev != prior_hash) return FAIL(chain break at i);
```
i.e. CONTINUITY checks `headers[i].prev_hash == headers[i-1].block_hash` over the **stored** fields. It does **not** call `Block::compute_hash` on any header. On success it returns `ok=true`, `count = headers.size()`, and `block_hash_hex = headers.back().block_hash` (the tail, suitable as a next-page anchor in the online walk).

The commitment CONTINUITY establishes is therefore *internal linkage consistency* plus, at the head, the `--genesis-hash` (or `--prev-hash`) byte-equality. It does **not** by itself bind any header's content. §3.1 states this precisely; §3.3 shows SIGS supplies the content binding.

### 2.2 SIGS — per-non-genesis-header committee-quorum over a SELF-RECOMPUTED digest

For each header `h` with `idx != 0`, the composite calls `verify_block_sigs(h, committee, bft)` (`light/verify.cpp:235-328`). The core (§2.2 of `LightBlockVerifySoundness.md`, reproduced for the per-header instance):

```cpp
Hash digest = light_compute_block_digest(b);          // ← LIGHT recomputes from THIS header
for (size_t i = 0; i < b.creators.size(); ++i) {
    const auto& sig = b.creator_block_sigs[i];
    if (sig == zero_sig) { if (!bft_mode) FAIL; else continue; }   // sentinel = abstention
    const auto& pk = pubkey_of.at(b.creators[i]);
    if (!verify(pk, digest.data(), digest.size(), sig)) FAIL;
    valid++;
}
size_t required = bft_mode ? (2 * b.creators.size() + 2) / 3 : b.creators.size();
// PASS iff valid >= required
```

with the pre-checks: every `creators[i]` must be in the supplied committee (`light/verify.cpp:268-273`, FAIL otherwise) and `creator_block_sigs.size() == creators.size()` (`light/verify.cpp:275-281`, FAIL otherwise). The digest is byte-for-byte the producer's `compute_block_digest` over the common-case field prefix (`light_compute_block_digest`, `light/verify.cpp:57-92` ≡ `src/node/producer.cpp:608-693`), per `LightClientThreatModel.md` Lemma L-2.

**The digest binds `prev_hash`.** Critically for the composite (§3.3), `light_compute_block_digest` appends `b.prev_hash` as its second field (`light/verify.cpp:60`): `h.append(b.prev_hash);`. So a tampered `prev_hash` changes the recomputed digest and breaks the committee signatures — SIGS FAILs. This is the bridge by which SIGS, an independent per-block check, also re-validates the linkage CONTINUITY walks over.

### 2.3 The committee resolver (`committee_for`, `light/main.cpp:892-912`)

```cpp
auto committee_for = [&](uint64_t idx, json& out, std::string& why) -> bool {
    if (!committee_path.empty()) { out = committee_json; return true; }   // single-committee
    if (!manifest_json.is_array()) { why = "manifest is not a JSON array"; return false; }
    for (auto& e : manifest_json) {
        // skip entries missing from/to/committee
        uint64_t lo = e["from"], hi = e["to"];
        if (idx < lo || idx > hi) continue;                   // not this range
        // lazily read+cache the committee file for this range
        out = committee_cache[e["committee"]]; return true;
    }
    why = "no manifest range covers block " + idx;            // ⇒ SIGS FAIL (never skip)
    return false;
};
```

Single-committee mode (`--committee`) returns the same committee for every index. Manifest mode (`--committee-manifest`) selects the **first** inclusive `[from, to]` range covering `idx` and returns its committee, caching the parsed file. A block that **no** range covers makes `committee_for` return `false`, which the SIGS loop turns into a thrown `runtime_error` ⇒ SIGS FAIL (`light/main.cpp:965-966`) — never a skip (§3.4 / VCF-4).

### 2.4 The genesis skip — keyed on `index`, NOT on emptiness (the load-bearing choice)

The SIGS loop (`light/main.cpp:950-971`):
```cpp
for (auto& h : headers) {
    uint64_t idx = (h.contains("index") && h["index"].is_number())
        ? h["index"].get<uint64_t>() : UINT64_MAX;
    if (idx == 0) { ++skipped; continue; }       // genesis: no committee sigs
    // ... committee_for + verify_block_sigs (FAIL throws) ...
}
```

The skip predicate is `idx == 0`, **not** `creator_block_sigs.empty()`. A header that is absent its `index` field gets `idx = UINT64_MAX` (`light/main.cpp:960-961`) — **not** `0` — so it is **not** skipped; it flows into `verify_block_sigs`, which fails-closed (no `index` ⇒ malformed `Block::from_json` or a digest the committee never signed). §3.2.1 (Lemma VCF-S) proves why this choice is load-bearing.

---

## 3. Soundness theorems

Throughout, let `CONT ∈ {PASS, FAIL}`, `SIGS ∈ {PASS, FAIL, SKIP}` be the two component verdicts, and `VCF ∈ {PASS, FAIL}` the aggregate (exit `0` / non-zero). Bounds follow `Preliminaries.md §2.0` (A1, A2 ≈ `2⁻¹²⁸`). Let the file present headers `H_0, H_1, …, H_{n-1}` with stored fields `block_hash[j]`, `prev_hash[j]`, `index[j]`.

### 3.1 VCF-1 (CONTINUITY soundness — internal linkage + the anchor)

**Statement.** A CONTINUITY PASS implies (i) the file's headers form an **unbroken stored-`block_hash` linkage** — `prev_hash[j] == block_hash[j-1]` for all `1 ≤ j ≤ n-1` (`light/verify.cpp:211-223`) — and (ii) **if `--genesis-hash` is supplied and `index[0] == 0`**, the file's `block_hash[0]` equals the supplied genesis hash byte-for-byte, under A2 the unique commitment to the operator's pinned genesis (`light/verify.cpp:193-200`). CONTINUITY does **not** assert any stored `block_hash[j]` is the true `Block::compute_hash` of its body; it asserts the *linkage among the stored fields* (plus the optional head anchor).

**Proof.**

*Part 1 — the walk.* CONTINUITY PASS requires the loop at `light/verify.cpp:211-223` to complete without a `prev != prior_hash` mismatch, i.e. `prev_hash[j] == block_hash[j-1]` for every consecutive pair. This is a deterministic string comparison over the file's own fields (each width-validated to 64 hex chars at `:120-135`); the conjunction is exactly the unbroken-linkage predicate. Any single break (a reordered, inserted, or deleted header that desynchronizes a `prev_hash`/`block_hash` pair) makes some `prev_hash[j] != block_hash[j-1]` and forces FAIL (`:170-176`). No assumption is needed for the walk itself — it is a structural string-equality conjunction.

*Part 2 — the genesis anchor (A2).* If `index[0] == 0` and `--genesis-hash = g`, CONTINUITY additionally requires `block_hash[0] == g` (`:193-200`) and `prev_hash[0] == "0"*64` (`:187-192`). The operator obtains `g` from a trusted out-of-band source (e.g. a pinned `genesis.json` run through `determ-light` genesis derivation, or a published constant). For the file to present a `block_hash[0]` equal to `g` while committing to a genesis *different* from the operator's pinned one, the file's genesis encoding must SHA-256-collide with the pinned genesis's encoding — an A2 break (`Preliminaries.md §2.1`), `≤ 2⁻¹²⁸`-class. This is the **offline-file instance of `LightClientThreatModel.md` T-L1**: T-L1 byte-compares the daemon's reported block-0 hash against a *locally recomputed* `compute_genesis_hash`; `verify-chain-file` byte-compares the file's `block_hash[0]` against an *operator-supplied* `--genesis-hash`. The anchor mechanism (byte-equality of a 32-byte hash) and its A2 bound are identical; the only difference is the provenance of the expected value (recomputed in T-L1 vs. flag-supplied here). **Note:** this path never calls `compute_genesis_hash`, so it is unaffected by the known `determ-light` cross-platform genesis-hash determinism gap — the operator supplies the hash directly.

*What Part 1+2 do NOT give.* CONTINUITY says nothing about whether any `block_hash[j]` (for `j ≥ 1`, or `j == 0` without `--genesis-hash`) is the *true* `Block::compute_hash` of its body — it walks the stored fields without recomputing them. An attacker who rewrites a block's body **and** updates its stored `block_hash[j]` **and** the next header's `prev_hash[j+1]` to match keeps the linkage intact and passes CONTINUITY. CONTINUITY catches reordering / linkage breaks; it does **not** catch content tampering. The content binding is SIGS's job (VCF-3 §3.3 proves the composite closes this). ∎

**Bound.** With `--genesis-hash`: `Pr[CONT PASS ∧ committed genesis ≠ pinned] ≤ ε_{A2} ≤ 2⁻¹²⁸`-class (one genesis-hash collision). The walk itself is deterministic (no cryptographic term).

### 3.2 VCF-2 (SIGS soundness — per non-genesis header, UNCONDITIONAL — inheriting LBV-2)

**Statement.** Under A1, a SIGS PASS implies that **every** header `H_j` with `index[j] != 0` carries at least `required` valid Ed25519 signatures, by distinct committee members whose public keys are in the committee resolved for `index[j]` (single or manifest), **over `digest_j = light_compute_block_digest(H_j)`** — the digest the light client recomputes from *that very header's fields*, where `required = K_j` (MD) or `⌈2K_j/3⌉` (`--bft`). **This soundness is UNCONDITIONAL** in the digest — there is **no operator-supplied-digest precondition** — because the light client links the digest code and recomputes per header (it does not trust an external digest).

**Proof.** SIGS PASS requires the loop at `light/main.cpp:950-971` to complete with `verified ≥ 1` and no thrown FAIL. For each non-genesis header `H_j` it reaches, `verify_block_sigs(H_j, committee_j, bft)` returned `ok=true`. Apply **`LightBlockVerifySoundness.md` LBV-2** to `H_j`:

- *Part 1 (digest is the header's true digest).* `verify_block_sigs` computes `digest_j := light_compute_block_digest(b_j)` at `light/verify.cpp:283`, where `b_j` is the parsed header. By `LightClientThreatModel.md` Lemma L-2, `light_compute_block_digest` is byte-for-byte `producer.cpp::compute_block_digest` over the common-case field prefix — so `digest_j` equals the exact digest the committee signed when it produced `H_j`. No operator input enters; the digest is a pure function of `H_j`'s own fields. (Cross-shard / F2 headers are out of this part's scope — F-VCF6, inheriting F-LBV5.)
- *Part 2 (per-signer verification is sound for that digest).* Each counted-valid creator `i` satisfies `verify(pk_i, digest_j, σ_i) = 1` with `pk_i` drawn from the resolved committee (`light/verify.cpp:299`); every creator is pre-checked for committee membership (`:268-273`) and `creator_block_sigs.size() == creators.size()` is enforced (`:275-281`). By A1 (Ed25519 EUF-CMA, `Preliminaries.md §2.2`), an adversary without `sk_i` produces such a `σ_i` for a never-signed `digest_j` with probability `≤ 2⁻¹²⁸`. The per-signer loop is a faithful `K_j`-fold replication of the single-sig verify primitive with no cross-signer state — instantiating `BatchSigningSoundness.md` BS-3's structural-isolation property for the committee-sig loop.

Combining, a SIGS PASS implies for *every* non-genesis header `H_j` that `required` distinct resolved-committee members signed `H_j`'s true digest under A1. There is additionally **no cross-header channel**: header `H_j`'s verdict depends only on `(H_j, committee_j, bft)` — `verify_block_sigs` reads no other header and carries no state between iterations (the loop's only mutable state is the `verified`/`skipped` counters and the committee cache, both monotone and verdict-independent of order). So the per-header BS-3 isolation lifts to a per-chain isolation: the conjunction over `j` is sound iff each conjunct is. ∎

**Bound.** `Pr[SIGS PASS ∧ ∃ non-genesis H_j without required valid committee sigs over its true digest] ≤ Σ_j K_j · 2⁻¹²⁸ ≤ n·K_max·2⁻¹²⁸` (A1, union bound over headers × signers). For practical chains this is `≤ 2⁻¹⁰⁰`-class.

#### 3.2.1 Lemma VCF-S (the strip-hole lemma — index-based skip, NOT emptiness-based)

**Statement.** Keying the genesis skip on `index == 0` (`light/main.cpp:962`), rather than on an empty / absent `creator_block_sigs`, is **necessary for soundness**: an emptiness-based skip would let an on-disk attacker **strip a real non-genesis block's committee signatures** and have the stripped block **silently skipped** (a false PASS); the index-based skip forces every stripped non-genesis header into `verify_block_sigs`, which FAILs on zero present signatures.

**Why an emptiness-based skip is unsound (the bug, recorded).** Consider a hypothetical skip predicate `creator_block_sigs.empty() ⇒ skip` (a mid-development implementation; **fixed**). The attacker takes a genuine chain file and, for some non-genesis header `H_k` (`index[k] ≥ 1`), deletes its `creator_block_sigs` array (or sets it empty). Critically:

1. **CONTINUITY does not catch it.** `verify_headers` walks the **stored** `block_hash`/`prev_hash` linkage (VCF-1) and **does not recompute** `Block::compute_hash`. The real `creator_block_sigs` are bound into `block_hash` by the producer — `Block::compute_hash` appends every `creator_block_sigs[i]` after `signing_bytes` (`src/chain/block.cpp:356-365`):
   ```cpp
   Hash Block::compute_hash() const {
       auto sb = signing_bytes();
       SHA256Builder b; b.append(sb.data(), sb.size());
       for (auto& s : creator_block_sigs) b.append(s.data(), s.size());  // sigs bound in
       return b.finalize();
   }
   ```
   But because CONTINUITY never recomputes `compute_hash`, stripping the sigs from `H_k` while leaving the **stored** `block_hash[k]` field unchanged keeps the linkage `prev_hash[k+1] == block_hash[k]` intact. CONTINUITY passes.
2. **An emptiness-based skip would then skip `H_k`.** With the sigs stripped, `creator_block_sigs.empty()` is true ⇒ the hypothetical predicate skips `H_k` entirely ⇒ **no committee-signature check ever runs on the stripped block.** The attacker has removed a real block's only per-block attestation and dodged verification — a false PASS over a chain whose block `k` is unattested.

**Why the index-based skip closes it.** The shipped predicate skips **only** `index == 0`. For a non-genesis header `H_k` (`index[k] ≥ 1`) with stripped sigs, `idx = index[k] != 0`, so `H_k` is **not** skipped — it flows into `verify_block_sigs` (`light/main.cpp:965-967`). There, one of two fail-closed paths fires:
- If `creator_block_sigs` is absent/empty while `creators` is non-empty, the size check `creator_block_sigs.size() != creators.size()` FAILs (`light/verify.cpp:275-281`).
- If the attacker also empties `creators` to match (size 0 == 0), then `valid = 0` and `required = K = 0` would naively pass the `valid >= required` gate — **but** `creators` empty means no signer attests the block at all, and such a header cannot be the genuine block at `index[k]` (the genuine block has a non-empty committee); the digest `light_compute_block_digest` over the mangled fields will not match what any successor header's `prev_hash` linkage *and* the committee at that height attest. In practice the genuine chain's `H_k` has `K ≥ 1` creators, so a stripped `H_k` presenting `creators=[]` mismatches the real block's content; and any header the attacker substitutes wholesale (non-empty creators with forged sigs) reduces to the A1 forgery bound of VCF-2. Either way there is **no skip** — the non-genesis header is verified, not bypassed.

Thus the index keying forces the stripped block into the verifier and fail-closes; the emptiness keying would have bypassed it. **VCF-S is the formal record of a real bug found and fixed mid-development.** ∎

**Residual note (honest).** The strip-hole closure relies on the SIGS gate's size/membership/quorum checks; it is *not* defeated by the CONTINUITY-only weakness because the composite **requires both checks to pass** (VCF-3). An operator who runs CONTINUITY alone (not exposed as a separate mode here — the composite always runs SIGS when CONTINUITY passes) would inherit the strip weakness; the composite does not, because SIGS is unconditional on every non-genesis header.

### 3.3 VCF-3 (composite soundness — CONTINUITY ∧ SIGS covers BOTH reordering AND content-tamper)

**Statement.** Under A1 + A2, `VCF = PASS` (exit 0) implies the conjunction

> **CONTINUITY** (unbroken stored-`block_hash` linkage + optional A2 genesis/prev anchor, VCF-1)
> **∧ SIGS** (every non-genesis header carries `required` valid committee sigs over its self-recomputed true digest, VCF-2 / LBV-2, **unconditional**, with the genesis skip keyed on `index` per VCF-S).

Moreover the composite covers **two distinct attacks that neither check covers alone**: CONTINUITY catches **reordering / linkage breaks** (VCF-1), SIGS catches **content tampering + forgery** (VCF-2), and the linkage-vs-content split is bridged because **the digest SIGS verifies binds `prev_hash`** (`light/verify.cpp:60`).

**Proof of composite soundness.** `VCF = PASS` ⟺ `failed == 0` ⟺ `CONT = PASS ∧ SIGS = PASS` (`light/main.cpp:988`; SIGS is recorded SKIP only when CONTINUITY FAILed, in which case `failed ≥ 1` already, so a true PASS requires both at PASS). `CONT = PASS` ⟹ VCF-1; `SIGS = PASS` ⟹ VCF-2 over every non-genesis header. The composite adds no verification logic beyond the conjunction and the per-index committee selection (VCF-4); its soundness is the conjunction of the two.

**Proof that the composite covers both attack classes (the load-bearing coverage argument).**

- *Content tampering is caught by SIGS regardless of CONTINUITY's weaker walk.* CONTINUITY (VCF-1) walks stored `block_hash` fields without recomputing them, so it cannot detect a block whose *body* was altered while its stored `block_hash` and the neighboring `prev_hash` were kept consistent. **SIGS catches exactly this.** Any change to a digest-bound field of a non-genesis header `H_j` — `index`, `prev_hash`, `tx_root`, `delay_seed`, `consensus_mode`, `bft_proposer`, `creators`, `creator_tx_lists`, `creator_ed_sigs`, `creator_dh_inputs` (`light/verify.cpp:59-69`) — changes `digest_j = light_compute_block_digest(H_j)`. The genuine committee signatures were produced over the *original* digest; over the tampered digest they no longer verify (A1), so `verify_block_sigs` FAILs and the loop throws (`light/main.cpp:968-969`) ⇒ SIGS FAIL ⇒ `VCF = FAIL`. To make a tampered non-genesis block pass, the attacker must forge `required` committee signatures over the new digest — the VCF-2 A1 bound (`≤ K·2⁻¹²⁸` per block).
- *Reordering / linkage breaks are caught by CONTINUITY.* If the attacker reorders, inserts, or deletes headers without re-deriving the prev_hash chain, some `prev_hash[j] != block_hash[j-1]` and CONTINUITY FAILs (VCF-1 Part 1) ⇒ `VCF = FAIL`. If the attacker *does* re-derive a consistent linkage around a substituted block, then that substituted block's content differs from a genuine block and falls to the SIGS argument above (its `prev_hash` is digest-bound, so a re-linked substitute presents a `prev_hash` the genuine committee never signed over ⇒ SIGS FAIL).
- *The bridge: `prev_hash` is in the digest.* The two checks are not independent silos — they overlap precisely on `prev_hash`. CONTINUITY constrains `prev_hash[j]` to equal the stored `block_hash[j-1]` (linkage); SIGS constrains `prev_hash[j]` to be the value the committee signed (content). An attacker who edits `prev_hash[j]` to forge a re-linking must satisfy *both*: match the stored predecessor hash (CONTINUITY) **and** match a committee-signed digest (SIGS). The genuine committee signed only the genuine `prev_hash[j]`; any other value breaks SIGS under A1. So the composite admits exactly the genuine prev_hash at each link — no alternate linkage survives both checks except via an A1 forgery. ∎

**Proof of fail-closed.** Every non-PASS pathway yields a non-zero exit with no false PASS:
- **Args/parse fault.** Missing `--in`, the `--committee`/`--committee-manifest` XOR violation, unknown arg, or unreadable/non-JSON file → `return 1` *before any verdict is recorded* (`light/main.cpp:862-885`). Exit 1, never PASS.
- **CONTINUITY FAIL.** A linkage break, a bad genesis prev_hash, a `--genesis-hash`/`--prev-hash` mismatch, a malformed header field, or a thrown exception inside `verify_headers` → `cont_ok = false` → `++failed` → exit 2 (`light/main.cpp:923-936, 988, 1010`). SIGS is then recorded SKIP (`:984-985`) — it cannot rescue the verdict (`failed ≥ 1`).
- **SIGS FAIL.** Any non-genesis header whose `verify_block_sigs` returns `!ok` (creator absent from committee, size mismatch, sentinel-zero in MD mode, signature mismatch, sub-quorum), an **uncovered** block in manifest mode (`committee_for` returns false, `:965-966`), a committee-file read error inside the resolver (`:904-906`), or "only the genesis present" (`:972-973`) → the loop throws → `ok = false` → `++failed` → exit 2. A *stricter* quorum (MD against a BFT-escalated chain) can only push more blocks into FAIL — a possible false FAIL, never a false PASS.

In every non-PASS pathway the exit is non-zero and no `VERIFY-CHAIN-FILE: PASS` is emitted. `overall = (failed == 0)` is a faithful function of the component verdicts. ∎

### 3.4 VCF-4 (manifest per-range soundness + uncovered-block-fails)

**Statement.** In `--committee-manifest` mode, each non-genesis header `H_j` is verified against the committee whose inclusive `[from, to]` range covers `index[j]`; per-range selection is sound (each block is checked against its mapped committee, not some other range's), and a block that **no** range covers is a SIGS **FAIL** (uncovered block), never a skip — so a gap in the manifest cannot silently drop verification of any non-genesis block.

**Proof.**

*Per-range selection soundness.* `committee_for(idx, …)` (`light/main.cpp:892-912`) iterates the manifest array and returns the **first** entry with `lo ≤ idx ≤ hi` (`:898-899`, inclusive both ends). The committee it returns is that entry's `committee` file (lazily read + cached, `:900-908`). `verify_block_sigs` then verifies `H_j`'s signatures against **that** committee's pubkeys (VCF-2). So each block is checked against the committee its covering range designates; there is no cross-range leakage (the resolver returns exactly one committee per call, deterministically the first covering range). If ranges overlap, the *first* covering range in array order wins — deterministic, and an operator-authored manifest controls the order; a block in an overlap is still verified against a real committee, never skipped.

*Uncovered-block-fails (the gap-closure).* If **no** manifest entry covers `index[j]` (a gap between ranges, or `index[j]` beyond all ranges), the loop in `committee_for` exhausts without returning, sets `why = "no manifest range covers block <idx>"`, and returns `false` (`:910-911`). The SIGS loop turns this into `throw std::runtime_error("block <idx>: " + why)` (`light/main.cpp:965-966`), which is caught at `:979` and recorded as SIGS **FAIL** ⇒ exit 2. So a manifest gap does **not** silently skip the uncovered block — it **fails the whole audit**, forcing the operator to supply a complete manifest. This is the manifest-mode analogue of VCF-S's "no silent skip" guarantee: just as a stripped non-genesis header fails rather than skips, an uncovered non-genesis header fails rather than skips. The only skip remains `index == 0` (§2.4). ∎

**The remaining honest boundary (committee provenance).** VCF-2 / VCF-4 prove each block is signed by **the supplied committee** (single or per-range) over its true digest — they do **not** prove the supplied committee is the *genuine, height-correct* one. This is identical to `LightBlockVerifySoundness.md` **F-LBV3** and `LightClientThreatModel.md` **T-L2**'s caveat: an operator who supplies a fabricated committee (or a manifest mapping ranges to attacker-chosen committees) gets a PASS that is sound *for those committees* but meaningless for the real chain. For full trust-minimization the committee(s) must be the genesis/chain-derived set — derived trustlessly by the online `verify-chain` family (anchor genesis per T-L1, then walk + per-block sig-verify per T-L2). `verify-chain-file` is the **offline, file-based, committee-as-input** member of that family; pair it with chain-derived committee material for an end-to-end trustless verdict. **This is the sole remaining trust boundary** (the genesis anchor when `--genesis-hash` is supplied is discharged under A2 by VCF-1; without it, genesis is unanchored — F-VCF4).

### 3.5 VCF-E (composition error bound)

**Statement.** The composite's soundness error is the sum of its two cryptographic components' bounds; the linkage walk, the manifest selection, and the conjunction logic are deterministic and contribute no term:

$$
\Pr[\text{VCF} = \text{PASS} \ \wedge\ \neg(\text{CONT-sound} \wedge \text{SIGS-sound})]
\;\le\; \varepsilon_{\text{CONT}} + \varepsilon_{\text{SIGS}}
\;\le\; \underbrace{2^{-128}\text{-class}}_{\text{A2, genesis anchor}} \;+\; \underbrace{n \cdot K_{\max} \cdot 2^{-128}}_{\text{A1, } n \text{ headers} \times K \text{ signers}}.
$$

**Derivation.** `VCF = PASS` requires `CONT = PASS ∧ SIGS = PASS` (VCF-3). The event "VCF passes yet a cryptographic component is unsound" ⊆ "(CONT passes yet its genesis anchor unsound) ∨ (SIGS passes yet some header's sigs unsound)"; by the union bound it is `≤ Pr[CONT genesis-anchor collision] + Pr[SIGS unsound]`. From VCF-1, `Pr[CONT genesis-anchor collision] ≤ ε_{A2} ≤ 2⁻¹²⁸`-class (one genesis-hash collision; **zero** if `--genesis-hash` is omitted — but then genesis is unanchored, a coverage limitation F-VCF4, not a probability term). From VCF-2, `Pr[SIGS unsound] ≤ n·K_max·2⁻¹²⁸` (an Ed25519 forgery for one signer of one of `n` headers). The linkage walk is a deterministic string conjunction; manifest selection and the aggregate exit-code mapping are deterministic — none adds a cryptographic term. ∎

**No digest conditional in the bound — and none outside it.** Like `LightBlockVerifySoundness.md` LBV-E (and unlike the wallet `OfflineBlockVerifySoundness.md` BV-E), VCF-E has **no digest-correctness conditional** — the digest is self-recomputed per header (VCF-2 Part 1), so its correctness is a theorem internal to the bound, not an operator obligation. The only honest precondition that remains is committee provenance (VCF-4 / §3.4), an operator-input statement, not a probability term.

---

## 4. Composition with companion proofs

### 4.1 `LightBlockVerifySoundness.md` — the single-block sibling SIGS is `n`-fold replicated from

`verify-chain-file`'s SIGS check **is** `LightBlockVerifySoundness.md`'s SIGS applied once per non-genesis header. **LBV-2** (UNCONDITIONAL per-block SIGS soundness via self-recomputed `light_compute_block_digest`) is inherited verbatim per header (VCF-2 Part 1+2); **LBV-3**'s fail-closed posture is inherited per header and lifted to the chain (VCF-3); **F-LBV5** (cross-shard / F2 fail-close) is inherited directly as **F-VCF6**; **F-LBV3** (committee-provenance residual) is the same boundary as VCF-4 / §3.4. The difference is scope: `block-verify` is a single-block predicate (no continuity), `verify-chain-file` adds the CONTINUITY linkage walk and the per-header replication of SIGS over the whole exported file.

### 4.2 `LightClientThreatModel.md` — the OFFLINE-file dual of the online `verify-chain`

`verify-chain-file` is the file-based dual of the online `verify-chain` chain-walk (`light/trustless_read.cpp`, T-L1+T-L2 over RPC pages). It reuses the *exact same primitives* — `verify_headers` and `verify_block_sigs` — but consumes a local file instead of paging from a daemon. CONTINUITY's `--genesis-hash` anchor is the offline instance of **T-L1** (byte-equality of block-0 hash; here the expected value is flag-supplied rather than recomputed via `compute_genesis_hash`, sidestepping the cross-platform genesis-determinism gap). SIGS is **T-L2** per header, leaning on **Lemma L-2** (`light_compute_block_digest` byte-equivalence with the producer). The committee-evolution caveat of T-L2 (the seed map must be a superset of every creator on the chain) is exactly what manifest mode (VCF-4) generalizes: per-range committees handle mid-chain registry changes the single committee cannot.

### 4.3 `OfflineBlockVerifySoundness.md` — the conditional wallet sibling improved upon

The wallet `block-verify` (BV-2 / **F-BV2**) verifies committee sigs over an **operator-supplied** digest (the wallet does not link the chain library), so its SIGS is *conditional* on a correct supplied digest. `verify-chain-file`, like all of `determ-light`, links the digest code and self-recomputes per header — discharging that conditional (VCF-2 is unconditional in the digest, exactly as LBV-2 discharges BV-2). The remaining trust boundary is therefore strictly smaller: committee provenance only, no digest provenance.

### 4.4 `Safety.md` (FA1) + `BatchSigningSoundness.md` (BS-3) + `Preliminaries.md` — the assumption base

SIGS consumes **FA1**'s per-block K-of-K (or `Q = ⌈2|K_h|/3⌉` BFT) signature-set primitive (`Safety.md` Lemma L-1.3) applied to each header. The per-signer loop instantiates **BS-3**'s structural isolation (no cross-signer channel); VCF-2 lifts it to a per-header isolation (no cross-header channel). CONTINUITY's genesis anchor reduces to **A2** (`Preliminaries.md §2.1`); SIGS reduces to **A1** (`Preliminaries.md §2.2`). A3 and A4 are not used. The composite bound (VCF-E) is the union of A1 + A2 with no independent term.

---

## 5. Findings (honest limitations)

Stated so an operator knows exactly what a `verify-chain-file: PASS` does and does not assert. None undermines the per-invocation soundness of VCF-3; all are coverage/scope statements or the one committee-provenance boundary.

### F-VCF1 CONTINUITY walks stored `block_hash` fields — it does not recompute block hashes

CONTINUITY (VCF-1) checks `prev_hash[j] == block_hash[j-1]` over the file's **stored** fields; it does **not** call `Block::compute_hash` per header. A PASS asserts *internal linkage consistency* (plus the optional head anchor), not that any stored `block_hash[j]` is the true hash of its body. The per-block content attestation is SIGS's job (VCF-2), and the composite **requires both** (VCF-3), so a content-tampered block that keeps a consistent stored linkage still fails SIGS. CONTINUITY *alone* would not catch content tampering — which is exactly why the strip-hole lemma (VCF-S) keys the genesis skip on `index`, not emptiness: the composite must force every non-genesis block into the content-checking SIGS path.

### F-VCF2 Genesis is anchored ONLY by `--genesis-hash`; without it, genesis is unanchored

Genesis (index 0) carries no committee sigs by construction, so SIGS skips it (§2.4). Its trust comes **solely** from the `--genesis-hash` byte-equality in CONTINUITY (VCF-1 Part 2). **Without `--genesis-hash`, the file's claimed `block_hash[0]` is taken as given** — the entire chain is then verified *relative to whatever block 0 the file asserts*, with no external pin. This is the offline-file counterpart of the online T-L1 anchor and is a documented limitation. An operator wanting genesis-anchored assurance MUST supply `--genesis-hash` from a trusted source. (This path never calls `compute_genesis_hash`, so it is unaffected by the known `determ-light` cross-platform genesis-hash determinism gap — the operator supplies the hash directly.)

### F-VCF3 The committee is operator-supplied — provenance is the remaining honest boundary (the one load-bearing limitation)

SIGS verifies against the operator-supplied `--committee` / `--committee-manifest`. VCF-2/VCF-4 prove each block is signed by **that supplied committee** over its true self-recomputed digest — **unconditional in the digest**, but **conditional on the committee(s) being the genuine height-correct sets**. An operator who supplies a fabricated committee (or a manifest mapping ranges to attacker-chosen committees whose keys signed forged blocks) gets a PASS sound *for those committees* but meaningless for the real chain. This is the **same boundary** as `LightBlockVerifySoundness.md` F-LBV3 / `LightClientThreatModel.md` T-L2. For full trust-minimization the committee material MUST be the genesis/chain-derived set; pair `verify-chain-file` with the chain-derived committee the online `verify-chain` family produces (anchor genesis T-L1, then walk + sig-verify T-L2).

### F-VCF4 Uncovered manifest blocks FAIL, but manifest correctness is operator-supplied

VCF-4 proves a non-genesis block that no manifest range covers is a SIGS FAIL (no silent skip). It does **not** prove the manifest's range→committee mapping is the *correct* per-height committee assignment — that is the F-VCF3 provenance boundary applied per range. An operator who authors a manifest that maps the right index ranges to the wrong committees gets PASSes that are sound for those committees but wrong for the chain. The manifest closes the *coverage* gap (every block is checked, none skipped) but inherits the *provenance* boundary (the committees themselves must be genuine).

### F-VCF5 No semantic / consensus validity, no apply-layer check

A PASS asserts linkage + per-block committee attestation. It does **not** assert any block's transactions are individually valid (signed / nonce-ordered / balance-covered), that timestamps are in-window, that `creators[]` is the protocol-selected committee for the height, or that the chain's state transitions are apply-correct. Those are chain-state / apply-layer properties (`Safety.md`, the FA-Apply track) requiring full execution the offline file verifier does not perform.

### F-VCF6 The self-recomputed digest is byte-identical to the producer only in the common case (inherited F-LBV5)

`light_compute_block_digest` (`light/verify.cpp:57-92`) reproduces `producer.cpp::compute_block_digest`'s common-case field prefix byte-for-byte, but **omits** the `compute_view_root` extensions the producer binds for blocks carrying cross-shard inbound receipts (`producer.cpp:629-635`) or non-zero F2 view-roots (`producer.cpp:650-661`). For common-case blocks (non-cross-shard, non-F2-reconciled), VCF-2 holds exactly. For a cross-shard / F2-reconciled block, the light digest differs from the producer's, so the genuine committee sigs do **not** verify and SIGS **FAILs** — a fail-closed false-negative, never a false PASS. `verify-chain-file` is therefore sound-and-meaningful for common-case chains and **fail-closed (conservative)** on cross-shard / F2 blocks. This is `LightBlockVerifySoundness.md` **F-LBV5** inherited verbatim; the KEEP-IN-SYNC comment at `light/verify.cpp:40-56` documents the omitted field set.

### F-VCF7 Sentinel / quorum semantics inherited from `verify_block_sigs`

SIGS inherits `verify_block_sigs`'s exact handling: a 64-byte all-zero signature is a *sentinel abstention* — permitted (uncounted) only under `--bft`, a hard FAIL in MD mode (`light/verify.cpp:289-297`); a creator absent from the resolved committee is a hard FAIL (`:268-273`); `creator_block_sigs.size() != creators.size()` is a hard FAIL (`:275-281`). The MD quorum is full `K`; the `--bft` quorum is `⌈2K/3⌉ = (2K+2)/3` (`:309-311`). An operator running MD against a BFT-escalated chain gets a clean FAIL, not a false PASS — they must pass `--bft`. These are `verify_block_sigs`'s behavior, carried verbatim (the same as `LightBlockVerifySoundness.md` F-LBV6).

---

## 6. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem | Surface | File:lines | Role |
|---|---|---|---|
| — | `cmd_verify_chain_file` (composite) | `light/main.cpp:850-1011` | Arg parse + XOR gate, CONTINUITY, SIGS loop, conjunction, exit 0/1/2. |
| VCF-1 | `verify_headers` | `light/verify.cpp:135-233` | Genesis/prev anchor + stored-`block_hash` linkage walk. |
| VCF-1 | genesis-hash anchor | `light/verify.cpp:193-200` | `headers[0].block_hash == --genesis-hash` byte-equality (offline T-L1). |
| VCF-1 | linkage walk | `light/verify.cpp:211-223` | `headers[i].prev_hash == headers[i-1].block_hash`. |
| VCF-2 | per-header `verify_block_sigs` | `light/verify.cpp:235-328` | Per-creator Ed25519 verify over the **self-recomputed** digest; quorum `K` / `⌈2K/3⌉`. |
| VCF-2 | `light_compute_block_digest` | `light/verify.cpp:57-92` | Byte-for-byte copy of `producer.cpp::compute_block_digest` (common-case prefix); binds `prev_hash` (`:60`). |
| VCF-2 | digest recomputed (not supplied) | `light/verify.cpp:283` | `Hash digest = light_compute_block_digest(b);` — the UNCONDITIONAL improvement over wallet BV-2. |
| VCF-2 | daemon original | `src/node/producer.cpp:608-693` (+`:629-690` extensions) | `compute_block_digest`; F-VCF6 covers the cross-shard / F2 tail the light copy omits. |
| VCF-S | genesis skip keyed on `index` | `light/main.cpp:960-962` | `idx == 0 ⇒ skip`, NOT emptiness — closes the sig-strip hole. |
| VCF-S | sigs bound into `block_hash` | `src/chain/block.cpp:356-365` | `Block::compute_hash` appends `creator_block_sigs` after `signing_bytes` — why CONTINUITY's stored-hash walk cannot catch a strip. |
| VCF-S | size-mismatch FAIL | `light/verify.cpp:275-281` | `creator_block_sigs.size() != creators.size() ⇒ FAIL` — the fail-close a stripped header hits. |
| VCF-3 | CONTINUITY-gates-SIGS + conjunction | `light/main.cpp:940, 988` | SIGS runs only if CONTINUITY passed; `overall = (failed == 0)`. |
| VCF-3 | exit code | `light/main.cpp:1010` | `return overall ? 0 : 2;` (args/parse → 1 earlier). |
| VCF-4 | `committee_for` resolver | `light/main.cpp:892-912` | Single-committee passthrough; manifest first-covering-range select; uncovered ⇒ false. |
| VCF-4 | uncovered-block FAIL | `light/main.cpp:910-911, 965-966` | `no manifest range covers block <idx>` ⇒ thrown ⇒ SIGS FAIL (never skip). |
| VCF-E | (no new term) | — | Bound = `ε_{A2} + n·K·ε_{A1}`; linkage walk + manifest select + conjunction deterministic; **no digest conditional**. |

**Tests.**

| Test | Coverage |
|---|---|
| `tools/test_light_verify_chain_file.sh` | VCF-3 end-to-end (export a real chain headers file + committee, run offline): happy-path PASS; tampered `prev_hash` → CONTINUITY FAIL; tampered digest-bound field → SIGS FAIL; stripped non-genesis sigs → SIGS FAIL (VCF-S); manifest happy path + uncovered-block FAIL (VCF-4); `--genesis-hash` mismatch → CONTINUITY FAIL. |
| `tools/test_light_verify_headers.sh` | CONTINUITY component (T-L1 + continuity): happy path + tampered `prev_hash` → FAIL + genesis-hash anchor mismatch → FAIL. |
| `tools/test_light_verify_block_sigs.sh` | SIGS component (T-L2 / LBV-2): happy path + tampered sig → FAIL + wrong committee → FAIL. |

---

## 7. Status

- **Implementation.** **SHIPPED.** `int cmd_verify_chain_file` is in `light/main.cpp:850-1011` (dispatched on `verify-chain-file` at `:6057`), the offline file dual of online `cmd_verify_chain` (`:1136`). Composes CONTINUITY via `verify_headers` (`light/verify.cpp:135-233`) and SIGS via per-non-genesis-header `verify_block_sigs` (`light/verify.cpp:235-328`), with the `committee_for` single/manifest resolver (`light/main.cpp:892-912`).
- **Proof.** Complete (this document). VCF-1 (CONTINUITY soundness — stored-`block_hash` linkage + A2 genesis anchor; honest about NOT recomputing block hashes); **VCF-2 (SIGS soundness UNCONDITIONAL per non-genesis header under A1 — self-recomputed digest, inheriting LBV-2)**; **Lemma VCF-S (the strip-hole lemma — the genesis skip MUST key on `index`, not emptiness; records a real mid-development bug + its fix)**; VCF-3 (composite soundness = CONTINUITY ∧ SIGS, covering BOTH reordering AND content-tamper via the `prev_hash`-in-digest bridge, fail-closed); VCF-4 (manifest per-range soundness + uncovered-block-FAILs-never-skips). Composition bound VCF-E (`≤ ε_{A2} + n·K·ε_{A1}`; no new cryptographic term; **no digest conditional**).
- **Soundness gap hunt — result.** **No genuine soundness gap found.** The one design point that *would* have been a real gap — an emptiness-based genesis skip permitting a silent sig-strip — is **closed** by the index-based skip (VCF-S), which this proof records as a real fixed bug. The manifest gap-in-coverage that *would* silently drop verification is **closed** by the uncovered-block-FAIL rule (VCF-4). The residuals (F-VCF1..F-VCF7) are all **coverage/scope statements or the committee-provenance boundary**, none of which is a false-PASS path: every honest limitation either fail-closes (F-VCF6 cross-shard/F2) or is an explicit "this is not asserted" coverage note (genesis-unanchored without `--genesis-hash`, committee provenance, semantic validity). The sole remaining trust boundary is **committee provenance** — identical to `LightBlockVerifySoundness.md` LBV-3 / F-LBV3 and `LightClientThreatModel.md` T-L2.
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA, SIGS), A2 (SHA-256 collision resistance, CONTINUITY genesis anchor). A3, A4 not used. Per `Preliminaries.md §2.0`.
- **Composes with.** `LightBlockVerifySoundness.md` (LBV-2 per-header SIGS / LBV-3 fail-closed / F-LBV5 ≡ F-VCF6 / F-LBV3 ≡ committee-provenance), `LightClientThreatModel.md` (T-L1 genesis anchor offline-dual / T-L2 per-header sigs / Lemma L-2 digest byte-equivalence), `OfflineBlockVerifySoundness.md` (BV-2 / F-BV2 — the conditional wallet sibling improved upon), `Safety.md` (FA1 per-block K-of-K primitive), `BatchSigningSoundness.md` (BS-3 per-signer-loop isolation), `Preliminaries.md` (A1 + A2 base).
- **Known limitations (§findings).** F-VCF1 (CONTINUITY walks stored hashes, no recompute — content binding is SIGS's job); F-VCF2 (genesis anchored only by `--genesis-hash`; unanchored without it); **F-VCF3 (the load-bearing one: committee is operator-supplied — proves the block is signed by the SUPPLIED committee, not the genuine height-correct one; pair with the online `verify-chain` family for trustless provenance)**; F-VCF4 (uncovered manifest blocks FAIL, but manifest range→committee correctness is operator-supplied); F-VCF5 (no semantic/consensus/apply-layer validity); F-VCF6 (cross-shard / F2 digest extensions ⇒ fail-closed, inherited F-LBV5); F-VCF7 (sentinel / quorum semantics inherited verbatim from `verify_block_sigs`). None undermines the per-invocation soundness of VCF-3.
- **The offline whole-chain file verifier (load-bearing).** `verify-chain-file` is the OFFLINE, file-based dual of the online `verify-chain`: same two primitives (`verify_headers` + `verify_block_sigs`), consumed from a local exported file with no daemon. CONTINUITY catches reordering / linkage breaks; SIGS catches content tampering + forgery (re-validating linkage too, since `prev_hash` is digest-bound); the index-based genesis skip prevents a silent sig-strip (VCF-S); the uncovered-block-FAILs rule prevents a manifest gap from dropping verification (VCF-4). The remaining trust boundary is committee provenance alone, dischargeable via the chain-derived committee material the online `verify-chain` family produces.

---
