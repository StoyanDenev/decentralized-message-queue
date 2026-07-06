> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# ConfidentialTxBundleSoundness — the DCT1 confidential-transfer BUNDLE: wire format / what `verify` checks / composition-is-structural / fail-closed parsing + conformance accounting

This document is the "what is proven vs. what is assumed-in-prose" honest accounting for the **DCT1 confidential-transfer bundle** — the serialized, single-`verify` composition of the already-shipped **§3.19 P-256** confidential-transaction primitives into one attacker-controlled byte string that a verifier accepts **iff** the transfer is well-formed (every output in range **AND** value conserved).

- **Module** — `src/crypto/pedersen/ctxbundle.c` + `include/determ/crypto/pedersen/ctxbundle.h` (`determ_ctx_bundle_len` / `_serialize` / `_verify`), CRYPTO-C99-SPEC.md **§3.22**.
- **Structural gate** — `test-p256-ctx-bundle` (the `main.cpp` subcommand) via `tools/test_p256_ctx_bundle.sh`: it pins the **serialization layout** + accept / per-region tamper / malformed rejection.
- **Crypto gate (inherited)** — the underlying balance + range + composition math is pinned by `test-p256-confidential-tx-c99` (§3.19 increment 8) and the four §3.19 sibling documents; the bundle adds **no new hardness assumption**.

The bundle is a thin, purely-structural layer over the primitives whose soundness is established in [`ConfidentialTxBalanceSoundness.md`](ConfidentialTxBalanceSoundness.md) (claims **CTB-1..CTB-8**). It **inherits** those claims and **cites** them; it does **not** re-derive the discrete-log / ROM reductions. Specifically it inherits:

- **CTB-3** — a verifying balance proof binds value conservation `Σ v_in = Σ v_out + fee` (under DL + ROM).
- **CTB-5** — range ∧ balance over the SAME output commitment (`V_j == C_out[j]`) is a sound confidential transfer (no inflation-by-overflow, no mint/burn).
- and, as the primitive substrate, **CTB-1** (balance completeness), **CTB-2** (Schnorr PoK of discrete log), **CTB-8** (fail-closed + trust inheritance).

The range-proof half is discharged by [`BulletproofsRangeProofSoundness.md`](BulletproofsRangeProofSoundness.md) / [`BulletproofsIPASoundness.md`](BulletproofsIPASoundness.md) / [`PedersenCommitmentSoundness.md`](PedersenCommitmentSoundness.md) (the §3.19 inc.1-6 stack, RP-2 = each output `v_j ∈ [0, 2^n)`).

This is **library-primitive-first, ZERO consensus touch** — `ctxbundle.h` carries "This is a LIBRARY primitive"; no Determ chain / ledger / wallet path constructs, proves, or verifies a DCT1 bundle. The bundle proves a *transfer is well-formed*; it does **not** by itself constitute a confidential-transaction consensus feature (see the prominent **§4 non-claims**).

**Authoritative external sources.** Same as the balance doc — Maxwell, *"Confidential Transactions"* (2015); Bünz et al., *"Bulletproofs"* (IEEE S&P 2018); Schnorr (J. Cryptology 1991); Pedersen (CRYPTO '91). Nothing new is assumed here beyond what those sources + the §3.19 stack already assume.

---

## 1. The DCT1 wire format + what `verify` checks

### 1.1 Wire layout (from `ctxbundle.h` / `ctxbundle.c`)

A DCT1 bundle is one contiguous byte string. `DCT_HDR = 15` (`= MAGIC(4) + n_in(1) + m(1) + n(1) + fee(8)`):

```
offset  field
------  ------------------------------------------------------------
0       MAGIC(4) = "DCT1"                       (0x44 0x43 0x54 0x31)
4       n_in (1)   number of input commitments  (1..255)
5       m    (1)   number of output commitments (1..255)
6       n    (1)   range bit-width per output   (power of two, <= 64)
7       fee  (8)   big-endian u64               (PUBLIC)
15      C_in [n_in * 33]   input value commitments  (SEC1 compressed, 33 B each)
        C_out[m    * 33]   output value commitments (SEC1 compressed, 33 B each)
        agg_rangeproof[L]  ONE aggregated Bulletproofs range proof over the m outputs
                           L = determ_agg_rangeproof_proof_len(m, n)
        balance_proof[65]  the Schnorr balance/excess proof  (compress(T) 33 + s 32)
```

`determ_ctx_bundle_len(n_in, m, n)` returns the exact total (`DCT_HDR + n_in*33 + m*33 + L + 65`) or `0` when any parameter is out of range, and it is the **single** parameter validator: `n_in`/`m ∈ [1,255]`, `n` a power of two `<= 64` (`n_pow2_le64`), `m*n <= 256` (the IPA dimension bound), and `L != 0`. `verify` calls it and enforces `len == need` **exactly** — no trailing slack, no truncation.

### 1.2 What `determ_ctx_bundle_verify` checks — range AND balance

`verify` takes `len` **fully attacker-controlled** bytes and returns `0` iff the transfer is valid, `-1` otherwise. The check sequence (source `ctxbundle.c:41-66`):

1. **Length / magic / params** — `len >= DCT_HDR`; `MAGIC == "DCT1"`; parse `n_in, m, n`; `need = determ_ctx_bundle_len(...)` (validates all params, `0` ⟹ reject); `len == need` **exactly**.
2. **Recompute the excess** `E = Σ C_in − Σ C_out − fee·G` from the bundle's own `C_in`/`C_out`/`fee` via `determ_p256_balance_excess`. **`E` is never carried in the wire** — the verifier derives it, so it cannot be spoofed. A non-zero return (malformed commitment or the **degenerate identity excess** `E = O`) is a reject.
3. **Balance** — `determ_p256_balance_verify(E, balance_proof)`; a reject means value is not conserved (the excess has a non-zero `G`-component; CTB-3).
4. **Range** — `determ_agg_rangeproof_verify(C_out, agg_rangeproof, m, n)`; `C_out` is passed **directly** as the aggregated range proof's value-commitment array `V`, so each output is proven `∈ [0, 2^n)` (RP-2).

All four must pass. Any failure ⟹ `-1`. There is no accept path that skips either the balance or the range check.

### 1.3 `C_out` is used directly as the range proof's `V` — the composition identity is STRUCTURAL

The load-bearing composition fact (inherited **CTB-5**) is that the SAME commitment serves both proofs. In the bundle this is not *checked* — it is *structural*: `verify` passes the wire `C_out` array as the `V` argument to `determ_agg_rangeproof_verify`. There is exactly one `C_out` in the bundle; the range proof and the "output side" of the balance excess read the **identical bytes**. So `V_j == C_out[j]` holds **by construction of the wire format**, not by a `memcmp` the verifier could get wrong or an adversary could desynchronize. A malicious serializer that supplied a range proof over a *different* `V` simply produces a range proof that fails to verify against the bundle's `C_out` — there is no second `V` field to disagree with.

The serializer's contract (`ctxbundle.h`) makes this explicit: the caller **must** have produced the aggregated range proof with `gamma_j = r_out_j` so that its internal `V_j = v_j·G + r_j·H` equals the tx commitment `C_out[j]`. The `test-p256-ctx-bundle` builder does exactly this (`gammas = r_out`) and asserts `memcmp(V, C_out, m*33) == 0` at *construction* time — but `verify` needs no such assertion because it feeds `C_out` in as `V`.

---

## 2. Claims (CTBN-1 .. CTBN-5)

**PROVEN-in-code** = enforced by shipped source + witnessed by a green assertion in `test-p256-ctx-bundle` (or inherited from a green §3.19 test). **argued-in-prose** = a reduction to a cited theorem or to an inherited CTB-* claim (assumed, not machine-checked here).

- **CTBN-1 (bundle soundness — verifies iff range ∧ balance both hold).** `determ_ctx_bundle_verify` returns `0` **iff** (a) the aggregated range proof verifies against `C_out` (every output `v_j ∈ [0, 2^n)`) **and** (b) the balance proof verifies against the recomputed excess `E` (`Σ v_in = Σ v_out + fee`). Therefore a bundle that verifies is a **sound confidential transfer**: no inflation-by-overflow / negative output (range half, RP-2), and value is conserved with no mint/burn (balance half). This is the bundle-level statement of inherited **CTB-5**; the "no accept without BOTH" direction is **proven-in-code** (the two `!= 0 return -1` guards at `ctxbundle.c:63-64` are unconditional and sequential), while the "each half binds its property" direction is **inherited-in-prose** from CTB-3 (balance ⟹ conservation, under DL + ROM) + RP-2 (range ⟹ bounded value). **Evidence:** `test-p256-ctx-bundle` — the honest bundle **accepts** (`"verify ACCEPTS an honest confidential transfer"`); tampering the aggregated-range-proof region **rejects** (range half fires); tampering the balance-proof region **rejects** (balance half fires); tampering a `C_out` byte **rejects** (it breaks *both* halves at once — `E` shifts and `V` shifts). **Caveat:** the accept witness is a single fixed 2-in/2-out, `n=4` transfer; general soundness is the conjunction of the §3.19 results, not an exhaustive sweep (L-2).

- **CTBN-2 (memory-safe, fail-closed parser).** `verify` treats every input byte as adversarial and rejects — never reads out of bounds, never accepts a malformed bundle. Concretely: (i) `len < DCT_HDR` ⟹ reject before any header read; (ii) bad `MAGIC` ⟹ reject; (iii) `determ_ctx_bundle_len` re-validates `n_in`/`m`/`n`/`m*n` and returns `0` on any violation ⟹ reject; (iv) `len != need` ⟹ reject — this catches **both** truncation (short buffer) **and** a trailing byte (over-long buffer), so all interior pointers (`C_in`, `C_out`, `agg_rp`, `bal`) are provably in-bounds before they are dereferenced; (v) the **identity excess** (`determ_p256_balance_excess != 0`, e.g. `E = O` which has no SEC1-compressed encoding, or a malformed commitment) ⟹ reject. This is **proven-in-code**: the bounds arithmetic is derived from the validated `(n_in, m, n)` and `len == need` gates them all. **Evidence:** the `test-p256-ctx-bundle` malformed suite — `bad magic`, `truncated` (buffer sliced to `blen/2`), `n not a power of two` (`bundle[6]=3`), and `trailing byte` (`push_back(0)`) each **reject**. **Caveat:** "memory-safe" here means every offset is bounded by the validated params and `len`; it is an argued property of the arithmetic, not a machine-checked ASan/fuzz proof (though the §3.19 stack runs under the `DETERM_UBSAN`/ASan gate; L-4).

- **CTBN-3 (the excess `E` is unspoofable — the verifier derives it, never trusts a carried value).** The balance excess `E` is **not** part of the wire format. `verify` recomputes `E = Σ C_in − Σ C_out − fee·G` from the bundle's own committed `C_in`, `C_out`, and public `fee`, then verifies the balance proof against *that* `E`. An attacker therefore cannot present a balance proof for a favorable `E'` while shipping different commitments: the `E` the proof is checked against is a deterministic function of the very bytes the range proof also constrains. **Proven-in-code:** `E` is a local `uint8_t E[33]` populated only by `determ_p256_balance_excess(E, C_in, n_in, C_out, m, fee)` — there is no code path that reads `E` from `bundle`. **Argued-in-prose (inherited):** that a verifying balance proof over the derived `E` binds conservation is CTB-2/CTB-3. **Evidence:** tampering `fee` (offset 7) or any `C_in`/`C_out` byte **rejects** in `test-p256-ctx-bundle`, because it changes the recomputed `E` out from under the balance proof.

- **CTBN-4 (the composition identity is STRUCTURAL, not checked).** `V_j == C_out[j]` — the "same commitment serves both the range proof and the balance side" fact that CTB-5's soundness rests on — holds **by construction of the DCT1 wire format**: there is a single `C_out` array, and `verify` passes it as the range proof's `V`. Unlike the standalone composition test (`test-p256-confidential-tx-c99`, which builds `V` and `C_out` on two code paths and asserts `memcmp`), the bundle has no second `V` to desynchronize. **Proven-in-code:** the single call `determ_agg_rangeproof_verify(C_out, agg_rp, m, n)` at `ctxbundle.c:64` is the whole mechanism — `C_out` *is* `V`. **Consequence:** the classic "range proof over one commitment, balance over another" splicing attack is structurally impossible in DCT1; the only way to satisfy the range check is to range-prove the exact `C_out` the balance excess consumed. **Evidence:** the construction-time `memcmp(V, C_out, ...)==0` assertion in `test-p256-ctx-bundle` documents the serializer contract; the `C_out`-tamper reject shows a desynchronized `C_out` fails.

- **CTBN-5 (determinism → reproducible bytes; dual-oracle byte-freeze is the CTX-2 follow-up).** `determ_ctx_bundle_serialize` is a pure byte layout (magic ‖ params ‖ big-endian fee ‖ `memcpy`'d components) over deterministic §3.19 primitives, so for fixed component inputs the bundle bytes are **bit-exactly reproducible** and `verify` is a deterministic accept/reject. This is **proven-in-code** to the extent the structural gate exercises it: `test-p256-ctx-bundle` builds the bundle from fixed scalars and both the length (`blen`) and every accept/reject verdict are deterministic across runs and platforms (the §3.19 primitives underneath are byte-invariant MSVC+GCC, gated by `test-c99-vectors` / `ci_local.sh`). **STATUS — the whole-bundle dual-oracle byte-freeze is SHIPPED.** The shipped C `test-p256-ctx-bundle` pins the 702-byte bundle's **SHA-256**, and an INDEPENDENT from-scratch python oracle `tools/verify_ctx_bundle.py` (composing `verify_pedersen` + `verify_bp_agg_rangeproof` + `verify_p256_balance`) reproduces the SAME bundle **byte-for-byte** into the frozen corpus `tools/vectors/p256_ctx_bundle.json`; `tools/test_p256_ctx_bundle.sh` runs both sides. Two independent implementations agreeing on one frozen bundle means a divergence with both green is *our* bug, not the vectors'. The component bytes are additionally §3.13 dual-oracle-frozen (`p256_balance.json` + the range-proof corpora, which already pin the crypto the bundle `memcpy`s) and byte-invariant MSVC+GCC (`ci_local.sh`).

---

## 3. Validation map

| Claim | Enforced in source | Structural gate (`test-p256-ctx-bundle`) | Inherited from | Status |
|---|---|---|---|---|
| **CTBN-1** verifies iff range ∧ balance | `ctxbundle.c:60-64` (excess → balance → range, all must pass) | honest accept; range-region tamper reject; balance-region tamper reject; `C_out` tamper reject | CTB-5 / CTB-3 / RP-2 | proven-in-code (both-halves-required) + inherited-in-prose (each binds) |
| **CTBN-2** fail-closed parser | `ctxbundle.c:42-47,60` (`len>=HDR`, magic, `len!=need`, identity-excess) | bad magic / truncated / bad `n` / trailing byte all reject | CTB-8 (fail-closed) | proven-in-code (bounds from validated params) |
| **CTBN-3** `E` recomputed, unspoofable | `ctxbundle.c:59-60` (`E` local, derived, never read from wire) | `fee` tamper reject; `C_in`/`C_out` tamper reject | CTB-2 / CTB-3 | proven-in-code (no carried-`E` path) |
| **CTBN-4** composition identity structural | `ctxbundle.c:64` (`C_out` passed as `V`; single array) | serializer `memcmp(V,C_out)==0` contract; `C_out` tamper reject | CTB-5 (`V_j==C_out[j]`) | proven-in-code (structural) |
| **CTBN-5** determinism / dual-oracle byte-freeze | `ctxbundle.c:30-38` (pure layout over deterministic prims) | deterministic `blen` + bundle **SHA-256 pinned == python oracle** | §3.13 component dual-oracle + `verify_ctx_bundle.py` / `p256_ctx_bundle.json` (whole-bundle) | **proven-in-code** (layout + whole-bundle dual-oracle byte-freeze SHIPPED) |

The bundle gate is the **serialization + fail-closed-parse + division-of-labour** witness that the accept-only crypto vectors cannot provide; the underlying crypto conformance is the already-green §3.19 stack (`test-p256-confidential-tx-c99` + the §3.13 dual-oracle over the balance/range corpora). Their conjunction — bounded by L-1..L-4 — is what "the DCT1 bundle is a deterministic, fail-closed, structurally-composed wrapper that accepts iff the transfer is range-valid AND balance-valid, under the inherited DL + ROM assumptions" means for this §3.22 library primitive.

---

## 4. Non-claims — THIS IS A LIBRARY BUNDLE, NOT A CHAIN INTEGRATION

**Read this section before treating DCT1 as a confidential-transaction feature.** The bundle proves a *single transfer is well-formed*. A confidential-transaction **consensus integration** needs strictly more, none of which lives in this module:

- **NC-1 — No shielded-pool STATE MODEL.** A real confidential-tx chain feature requires a **commitment set** (the notes/outputs that exist) and a **nullifier set** (spent-note markers) maintained in consensus state, plus **deposit / withdraw** (shielding / unshielding) rules bridging the transparent and confidential value pools so the shielded supply is conserved end-to-end. DCT1 has **none** of this. It is a self-contained proof object with no notion of a ledger, a UTXO/note set, or a pool balance.

- **NC-2 — DOES NOT prevent replay / double-spend.** The bundle carries **no nullifier** and consults no spent-set. The *same* valid bundle can be submitted twice and will verify twice — verifying a bundle says nothing about whether its inputs were already spent. Double-spend prevention is exactly the job of the **nullifier set** in the (owner-gated, not-yet-designed) integration, not of this primitive.

- **NC-3 — Amount privacy ONLY; NOT sender / receiver / graph privacy.** DCT1 hides *amounts* (each `C_out` is a hiding Pedersen commitment; the range + balance proofs reveal nothing about values beyond "in range" and "balanced"). It does **NOT** hide the sender or receiver, the transaction graph, the fact a transfer exists, or the **fee** (public by construction — it is an 8-byte plaintext field and appears as the `fee·G` term). This is inherited **NC-1** of the balance doc, restated for the bundle.

- **NC-4 — No consensus / wallet consumer; owner-gated PROFILE choice pending.** No Determ chain / ledger / wallet path builds or verifies a DCT1 bundle (inherited **CTB / NC-2**). Chain integration is a separate, consensus-critical, **owner-gated** step that also requires the **profile decision**: **P-256 (FIPS)** — what this module implements — **vs. `Z_p*` (MODERN)**. A `Z_p*` mirror bundle over the §3.20 finite-field stack is a follow-up and does **not** exist yet (L-3). See [`ConfidentialTxIntegrationDesign.md`](ConfidentialTxIntegrationDesign.md) (a FUTURE-tier proposal, decides nothing).

- **NC-5 — Not post-quantum.** Soundness rests on P-256 discrete log (ECDLP), broken by Shor's algorithm. Classical-adversary construction (inherited **NC-4**).

---

## 5. Limits (L-1 .. L-4)

- **L-1 — Soundness is a REDUCTION, inherited, not a machine-checked extractor.** CTBN-1's "each half binds its property" rests on CTB-3 (balance = conservation, reduced to Schnorr 1991 + commitment binding under DL + the Fiat-Shamir ROM) and RP-2 (range = bounded value, the Bulletproofs soundness reduction). This document adds **no** new extractor and re-proves **nothing**; a break of P-256 DL or the ROM assumption breaks the bundle regardless of any structural gating here. The `test-p256-ctx-bundle` tamper witnesses show the deployed reject paths fire — they are **not** a soundness proof.

- **L-2 — Conformance is over a FIXED witness, not the input space.** The structural gate exercises exactly one honest transfer (2-in / 2-out, `n=4`, fixed scalars) plus its per-region tamper and malformed variants. Completeness / soundness for arbitrary `(n_in, m, n)` shapes follows from the layout arithmetic + the inherited §3.19 results, not exhaustive coverage. (The whole-bundle dual-oracle byte-freeze IS shipped — CTBN-5 — but over the same fixed 2-in/2-out witness.)

- **L-3 — P-256 profile ONLY (so far).** DCT1 as implemented is FIPS/P-256. The `Z_p*` MODERN-profile mirror (over the §3.20 finite-field balance + range stack) is a follow-up; the owner-gated profile choice (NC-4) is undecided.

- **L-4 — Not a constant-time claim beyond §3.19's CT-hardening.** `verify` runs on public, attacker-supplied bytes, so timing is not secret-dependent at the bundle layer; the *provers* underneath were CT-hardened 2026-07-06 (balance-doc NC-3, `ConstantTimeInventory.md`). This document asserts only functional soundness — completeness / soundness / fail-closed — not a machine-checked timing proof.

---

## 6. Status

- **Spec.** Complete (this document); design entry CRYPTO-C99-SPEC.md §3.22.
- **Module + structural gate shipped and green.** `src/crypto/pedersen/ctxbundle.c` (`determ_ctx_bundle_len` / `_serialize` / `_verify`); `test-p256-ctx-bundle` via `tools/test_p256_ctx_bundle.sh` — honest accept + per-region tamper reject (fee / `C_in` / `C_out` / agg-rangeproof / balance-proof) + malformed reject (bad magic / truncated / non-power-of-two `n` / trailing byte). Underlying crypto pinned by `test-p256-confidential-tx-c99` (§3.19 inc.8) + the §3.13 balance/range dual-oracle corpora.
- **Claims.** CTBN-1 (verifies iff range ∧ balance — inherits CTB-5/CTB-3/RP-2), CTBN-2 (memory-safe fail-closed parser), CTBN-3 (excess `E` recomputed, unspoofable), CTBN-4 (composition identity `V_j==C_out[j]` is structural), CTBN-5 (deterministic layout + whole-bundle dual-oracle byte-freeze SHIPPED: `verify_ctx_bundle.py` + `p256_ctx_bundle.json` + the C SHA-256 KAT) — all at the proven-in-code / inherited-in-prose split recorded in §3.
- **Non-claims (NC-1..NC-5).** No shielded-pool state model (commitment + nullifier sets, deposit/withdraw); does NOT prevent replay/double-spend (that is the nullifier set); amount privacy only (not sender/receiver/graph/fee/existence); no consensus/wallet consumer + owner-gated P-256-vs-`Z_p*` profile choice; not post-quantum.
- **Limits (L-1..L-4).** Soundness is an inherited reduction (not an extractor); conformance is over a fixed witness (the whole-bundle dual-oracle byte-freeze is shipped); P-256 profile only; not a timing proof beyond §3.19's CT-hardening.

Cross-references: [`ConfidentialTxBalanceSoundness.md`](ConfidentialTxBalanceSoundness.md) (CTB-1..CTB-8 — the inherited balance + composition soundness); [`BulletproofsRangeProofSoundness.md`](BulletproofsRangeProofSoundness.md) / [`BulletproofsIPASoundness.md`](BulletproofsIPASoundness.md) / [`PedersenCommitmentSoundness.md`](PedersenCommitmentSoundness.md) (the §3.19 range-proof half, RP-2); [`ConfidentialTxIntegrationDesign.md`](ConfidentialTxIntegrationDesign.md) (the FUTURE-tier, owner-gated chain-integration proposal); CRYPTO-C99-SPEC.md §3.22 (the DCT1 bundle design entry), §3.19 (the P-256 confidential-tx primitives), §3.13 (the dual-oracle vector gate); `src/crypto/pedersen/README.md` (module provenance).
