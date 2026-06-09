# BlockDigestCrossBinaryParity — byte-identity of the light client's block-digest recompute vs the producer's, on every non-F2 block (FB62)

This document formalizes the **cross-binary block-digest parity invariant**: that `determ-light`'s independent recompute of the K-of-K committee's Phase-2 signature target (`light_compute_block_digest`) is **byte-for-byte identical** to the daemon's authoritative definition (`compute_block_digest`) on every block the light client does *not* fail-close on — i.e. every block with empty `inbound_receipts` and all-zero `creator_view_eq_roots` / `creator_view_abort_roots` (every **non-F2** block, which includes merged blocks with a non-zero `partner_subset_hash` and timestamp-reconciled blocks). On that domain the two digests coincide exactly, so the light client's Ed25519 verification of each committee signature is sound: a signature the committee produced over the daemon's digest verifies under the light client's recomputed digest, and a tampered header fails.

It is the digest-layer analog of `CanonicalSigningBytesParity.md` (FB61), which discharges the same kind of obligation for the Transaction `signing_bytes` pre-image. Where FB61 keeps "the transaction" a single binary-independent object, this proof keeps "the digest the committee signed" a single binary-independent object on the light client's verification domain — and, equally important, pins the *boundary* of that domain: on an F2 / cross-shard block the light client deliberately omits roots the producer bound, so its recompute diverges and **every** committee signature fails its check — a false NEGATIVE (UNVERIFIABLE), never a false positive.

**Companion documents.** `Preliminaries.md` (F0) §2.0 canonical assumption labels — **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision/preimage resistance (§2.1). `S030-D2-Analysis.md` (the digest field model: which block fields are bound into `compute_block_digest`, the F2 view-reconciliation that gates the three pool-fed roots, and the `partner_subset_hash` / `timestamp` deterministic-and-median tail). `CanonicalSigningBytesParity.md` (FB61 — the sibling byte-identity proof for the tx pre-image; same proof shape, same `tools/`-guard discipline). `CrossBinaryCanonicalFormat.md` (CBF — CBF-2 names `light/verify.cpp::light_compute_block_digest` as a re-implementation surface that "must stay byte-identical to the daemon"; this proof is the byte-identity discharge of that obligation on the non-F2 domain). `Safety.md` (FA1 — the K-of-K committee signature is the FA1 finalization target this digest IS). `LightClientThreatModel.md` / `LightClientCompositionMap.md` (the T-L block-sig-verification leg whose soundness reduces to this parity).

---

## 1. The invariant

### 1.1 The digest field model

A `Block b` is signed by its K-of-K committee in Phase 2 over `compute_block_digest(b)` — a single SHA-256 over an ordered token stream (`src/node/producer.cpp:608-693`). The token stream is a fixed **core** of 10 field-groups followed by up to five **conditional appendages**, each gated on an intrinsic, JSON-stable signal in the block:

| Group | Fields | Gate | producer.cpp |
|---|---|---|---|
| core (10) | `index`, `prev_hash`, `tx_root`, `delay_seed`, `consensus_mode`, `bft_proposer`, `creators`, `creator_tx_lists`, `creator_ed_sigs`, `creator_dh_inputs` | always | `:610-620` |
| F2 inbound | root over sorted `hash_cross_shard_receipt(inbound_receipts)` | `!inbound_receipts.empty()` | `:629-635` |
| F2 eq | root over `hash_equivocation_event(equivocation_events)` | `any_nonzero(creator_view_eq_roots)` | `:650-655` |
| F2 abort | root over `hash_abort_event(abort_events)` | `any_nonzero(creator_view_abort_roots)` | `:656-661` |
| partner | `partner_subset_hash` | `!is_zero_hash_(partner_subset_hash)` | `:674-676` |
| timestamp | `b.timestamp` | `!creator_proposer_times.empty()` | `:689-691` |

The three **F2** appendages (inbound / eq / abort) are the v2.7 F2 / S-030-D2 view-reconciliation bindings — they bind a *reconciled* set computed from the K signed Phase-1 commits (`S030-D2-Analysis.md` §3.2, §4 items 7+8). The **partner** and **timestamp** appendages are NOT pool-fed views: `partner_subset_hash` is deterministic (every committee member at a merged height computes the identical value from the merge state — `S030-D2-Analysis.md` §3.2, item 9) and `timestamp` is the deterministic lower-median of the K committed `proposer_time`s (`S030-D2-Analysis.md` §5, item 10). Field order is fixed: **core, inbound, eq, abort, partner_subset_hash, timestamp** (`producer.cpp:645/673/688` order comments).

### 1.2 The non-F2 domain

Call `b` a **non-F2 block** iff

```
inbound_receipts == ∅   ∧   any_nonzero(creator_view_eq_roots) == false   ∧   any_nonzero(creator_view_abort_roots) == false
```

On a non-F2 block all three F2 gates are FALSE, so `compute_block_digest(b)` emits **core + (partner if non-zero) + (timestamp if reconciled)** and nothing else. This domain is broad: it includes every ordinary single-shard block, every **merged** block (non-zero `partner_subset_hash`), and every **timestamp-reconciled** block (non-empty `creator_proposer_times`). It excludes only blocks that actually carry cross-shard inbound receipts or reconciled equivocation/abort evidence — the cross-shard / F2 blocks the light client cannot reconstruct from a stripped header (§4).

### 1.3 Statement

> **BDP (block-digest parity).** For every **non-F2** block `b` (per §1.2),
> `light_compute_block_digest(b) == compute_block_digest(b)` (byte-for-byte),
>
> hence for each committee member `i`, `crypto::verify(pk_i, light_digest, sig_i)` returns the same boolean as `crypto::verify(pk_i, producer_digest, sig_i)`. Since the committee produced `sig_i` over `producer_digest`, the light client's K-of-K verification (`light/verify.cpp::verify_block_sigs`, digest at `:283`, Ed25519 verify at `:299`) accepts exactly the genuinely-signed non-F2 headers and rejects any post-signing tamper (A1).

BDP is an **unconditional byte equality** on the non-F2 domain — both functions are pure straight-line SHA-256 builders over the same `Block` fields in the same order; A1 enters only to lift digest equality to signature-verification equivalence, A2 only for §6's divergence-detection direction.

---

## 2. Preliminaries

We rely only on:

- **(P-det) Determinism of each builder.** `compute_block_digest` and `light_compute_block_digest` are pure functions of the `Block` argument — a fresh `SHA256Builder`, a straight-line sequence of `h.append(...)` calls, no clock, no RNG, no global mutable state, no iteration over an unordered container whose order is not already fixed in the block (`creators` / `creator_tx_lists` / `creator_dh_inputs` are committee-selection-ordered vectors, identical in both). A pure straight-line builder returns the same 32 bytes on the same `Block` on every host. (This is the digest specialization of `CrossBinaryCanonicalFormat.md` §4.3's determinism premise; the in-process `determ` leg is pinned by `tools/test_block_digest.sh`.)
- **(P-app) `SHA256Builder::append` is type-stable across the two binaries.** Both functions call the *same* `determ::crypto::SHA256Builder` (`#include <determ/crypto/sha256.hpp>`; `light/verify.cpp:19`), and both feed it the same C++ types from the same `determ::chain::Block` struct (`light/verify.cpp:22` includes `<determ/chain/block.hpp>` — the light client links the canonical `Block`, it does not re-declare it). So `append(b.index)` etc. serialize identically by construction; there is no second `Block` layout to drift against. (This is strictly stronger than FB61's tx-pre-image case, where the wallet re-declares the byte layout inline — here only the *call sequence* can drift, not the per-field encoding.)
- **A1** (Ed25519 EUF-CMA) lifts digest byte-equality to signature-verification equivalence in §3.2/§4 (a verifier recomputing the identical message bytes decides each signature the same way the signer intended).
- **A2** (SHA-256 collision/preimage resistance) enters only in §5/§6 for the divergence-*detection* direction (a drifted token sequence overwhelmingly yields a different digest, so a guard reliably flags it); the parity equality itself is exact.

The two functions are deliberately decoupled: `light/verify.cpp:32` marks `light_compute_block_digest` "COPY OF producer.cpp ... — keep in sync," and `:56` repeats "If the upstream byte-order or field set ever changes, mirror it here." The copy exists because the light client is a separate binary that the daemon's `compute_block_digest` does not link; the parity is therefore a maintained mirror, not a shared call — exactly the re-implementation regime CBF-2 flags and §5's source guard polices.

---

## 3. The producer's digest is the spec

### 3.1 Theorem T-1 (producer defines the spec)

**Statement.** `compute_block_digest(b)` (`producer.cpp:608-693`) is the digest the K-of-K committee actually signs in Phase 2; it *defines* the reference token sequence against which the light recompute is measured.

**Proof.** The committee's Phase-2 `BlockSigMsg` carries an Ed25519 signature over `compute_block_digest(b)` (the Phase-2 sign target; `producer.cpp` digest at `:608`, consumed at the round-finalize site). Validators recompute it (`src/node/validator.cpp` `check_block_sigs`) and the light client recomputes it (`verify.cpp:283`). There is exactly one such function in `src/`; `determ` links it directly. Whatever bytes it emits ARE the message the signatures attest to — there is no obligation beyond exhibiting the token stream, which §1.1's table maps field-by-field to `producer.cpp:610-691`. T-1 is the definitional anchor; T-2/T-3 are proved relative to it. ∎

### 3.2 The field-order table (both functions side by side)

Token-stream positions in emission order. `producer` = `compute_block_digest` (`src/node/producer.cpp`); `light` = `light_compute_block_digest` (`light/verify.cpp`). "≡" means the same `h.append` over the same `Block` field; the three F2 roots are present in `producer` only.

| Pos | Token (role) | producer | light | Identical? |
|---|---|---|---|---|
| 1 | `index` | `:610` | `:59` | ≡ |
| 2 | `prev_hash` | `:611` | `:60` | ≡ |
| 3 | `tx_root` | `:612` | `:61` | ≡ |
| 4 | `delay_seed` | `:613` | `:62` | ≡ |
| 5 | `consensus_mode` (`u8`) | `:614` | `:63` | ≡ |
| 6 | `bft_proposer` | `:615` | `:64` | ≡ |
| 7 | `creators[]` | `:616` | `:65` | ≡ |
| 8 | `creator_tx_lists[][]` | `:617-618` | `:66-67` | ≡ |
| 9 | `creator_ed_sigs[]` | `:619` | `:68` | ≡ |
| 10 | `creator_dh_inputs[]` | `:620` | `:69` | ≡ |
| F2-a | inbound-receipt view root | `:629-635` (gate `!inbound_receipts.empty()`) | — (absent) | producer-only |
| F2-b | equivocation view root | `:650-655` (gate `any_nonzero(creator_view_eq_roots)`) | — (absent) | producer-only |
| F2-c | abort view root | `:656-661` (gate `any_nonzero(creator_view_abort_roots)`) | — (absent) | producer-only |
| 11 | `partner_subset_hash` | `:674-676` (gate `!is_zero_hash_(...)`) | `:76-78` (gate `partner_subset_hash != zero`) | ≡ (same order, same trigger) |
| 12 | `timestamp` | `:689-691` (gate `!creator_proposer_times.empty()`) | `:88-90` (gate `!creator_proposer_times.empty()`) | ≡ (same order, same trigger) |

The **core 10** (positions 1-10) are emitted unconditionally and identically. The **three F2 roots** (F2-a/F2-b/F2-c) appear in `producer` only — the light client cannot reconstruct them from a header (the `inbound_receipts` / `equivocation_events` / `abort_events` collections are stripped by `rpc_headers`, and the F2 roots are over the reconciled sets; `verify.cpp:44-48`), so it omits them. The **partner** and **timestamp** tail (positions 11-12) appear in BOTH, in the **same order** and under the **same trigger**: `partner_subset_hash` survives the `rpc_headers` strip (kept alongside `state_root` — `verify.cpp:49-53`, `S030-D2-Analysis.md` item 9) so the light client has the exact value to bind; `creator_proposer_times` likewise survives the strip (`verify.cpp:79-87`), so the light client binds the same `b.timestamp` the committee signed.

Crucially, the partner/timestamp gates are *intrinsic to the block value*, not to whether the block is F2: a non-F2 merged block (non-zero `partner_subset_hash`, all F2 gates false) emits position 11 in BOTH functions, and the byte streams stay identical. This is why BDP holds on the *merged* and *timestamp-reconciled* sub-domains, not only on plain single-shard blocks.

---

## 4. Theorems

### 4.1 Theorem T-2 (light == spec on the non-F2 domain)

**Statement.** For every **non-F2** block `b` (§1.2), `light_compute_block_digest(b) == compute_block_digest(b)` byte-for-byte; hence each committee signature decides identically under both digests, and `verify_block_sigs` is sound (accepts the genuinely-signed non-F2 header, rejects tamper).

**Proof obligation.** Two parts: (i) the producer's *emitted* token sequence on a non-F2 block equals the light client's emitted sequence (the source-guard equality), and (ii) the conditional triggers for the two shared tail appendages coincide on every block (the conditional-trigger equality).

**Proof.**

*(i) Source token-sequence equality (= the source guard).* On a non-F2 block, all three F2 gates in `compute_block_digest` are FALSE:
- `!b.inbound_receipts.empty()` is FALSE (the non-F2 premise: `inbound_receipts == ∅`), so `:629-635` emits nothing.
- `any_nonzero(b.creator_view_eq_roots)` is FALSE (premise), so `:650-655` emits nothing.
- `any_nonzero(b.creator_view_abort_roots)` is FALSE (premise), so `:656-661` emits nothing.

So the producer's emitted stream is exactly **core (positions 1-10) + partner (cond.) + timestamp (cond.)**. The light client `light_compute_block_digest` has NO F2 appendages at all (the §3.2 table: F2-a/F2-b/F2-c rows are absent from `verify.cpp`), so its stream is **core + partner (cond.) + timestamp (cond.)** *unconditionally* — its sequence is the producer's sequence with the three (now-empty) F2 slots already removed. The remaining sequences are token-for-token equal: positions 1-10 map `producer:610-620 ≡ light:59-69` (same `h.append` over the same `Block` field, in the same order, via the same `SHA256Builder` under (P-app)). Therefore the producer's *emitted* tokens on a non-F2 block coincide with the light client's *always-emitted* tokens, before considering the tail gates.

*(ii) Conditional-trigger equality.* The two shared tail appendages must fire on the same blocks:
- **partner** (position 11): producer gate `!is_zero_hash_(b.partner_subset_hash)` (`:674`) vs light gate `b.partner_subset_hash != zero` (`:76`). Both test "is `partner_subset_hash` non-zero," over the identical `Block` field; `is_zero_hash_` is the all-zero-bytes predicate and `!= zero` is its De-Morgan complement, so they fire on exactly the same blocks, and when they fire both append the identical 32-byte `b.partner_subset_hash` (`:675 ≡ :77`).
- **timestamp** (position 12): producer gate `!b.creator_proposer_times.empty()` (`:689`) vs light gate `!b.creator_proposer_times.empty()` (`:88`) — *syntactically identical* predicate over the identical `Block` field; when fired both append `b.timestamp` (`:690 ≡ :89`). Because `creator_proposer_times` survives the `rpc_headers` strip and `from_json` repopulates it (`src/chain/block.cpp:586-588`), the light client's `b.creator_proposer_times` is the same vector the producer digested, so the gate evaluates identically.

Combining (i) and (ii): on a non-F2 block the two functions emit the identical ordered token stream — core, then (iff non-zero) partner, then (iff reconciled) timestamp — and feed it to the same `SHA256Builder`. By (P-det)+(P-app) the finalized 32-byte digests are byte-equal:

```
non-F2 ⇒ light_compute_block_digest(b) == compute_block_digest(b).
```

*Soundness of `verify_block_sigs`.* `verify.cpp:283` computes `digest = light_compute_block_digest(b)` and `:299` runs `crypto::verify(pk_i, digest, sig_i)` for each creator. The committee produced `sig_i` over `compute_block_digest(b)`. On a non-F2 block these two digest byte strings are equal, so under A1 each `verify` returns TRUE for a genuine signature and FALSE for any post-signing tamper (a flipped `tx_root`, a swapped `creators` entry, a stripped/altered `partner_subset_hash`, a tampered reconciled `timestamp`) — the verifier's message argument matches the signed bytes iff the header is intact. Therefore `verify_block_sigs` accepts exactly the genuinely-signed non-F2 headers and rejects tamper. ∎

**Mechanical discharge.** `tools/test_block_digest_xbinary_parity.sh` (§5) reduces both source sites to ordered token lists and asserts the light list equals the producer list with the three F2 appendages removed AND the partner/timestamp tail in the same order under the same gates — turning any tail drift RED at the source level pre-build. The runtime end-to-end leg is `tools/test_light_verify_block_sigs.sh` (a cluster mints a real block 1, the light client verifies its K-of-K sigs against its own recompute).

### 4.2 Theorem T-3 (fail-closed soundness on F2 / cross-shard blocks)

**Statement.** On an **F2 / cross-shard** block (non-empty `inbound_receipts`, or non-zero `creator_view_eq_roots`, or non-zero `creator_view_abort_roots`), the light client omits one or more roots the producer bound, so `light_compute_block_digest(b) != compute_block_digest(b)` (overwhelmingly, A2), so **every** committee signature fails the light client's `crypto::verify` check (A1). The result is `verify_block_sigs` returning FAIL/UNVERIFIABLE — a false **NEGATIVE**, never a false positive. The light client documents that such blocks must be verified against a full node.

**Proof.** Let `b` be F2: at least one of the three F2 gates in `compute_block_digest` is TRUE, so the producer's digest stream contains at least one F2 root token (one of `:634` / `:654` / `:660`) that the light client's stream — which has no F2 appendages — does not contain. The two token streams therefore differ in length and content at the first F2 slot, so under A2 (the two distinct pre-images collide with probability `≤ 2⁻¹²⁸`) `light_compute_block_digest(b) != compute_block_digest(b)`. The committee signed `compute_block_digest(b)`; at `verify.cpp:299` the light client checks each `sig_i` against its *different* `light` digest, so under A1 every `crypto::verify` returns FALSE, `valid` stays below `required` (`:313`), and `verify_block_sigs` returns FAIL with detail "signature does NOT verify against block_digest" (`:302`). This is a refusal to attest, not a false acceptance: there is no input on which the light client accepts a *forged* F2 header, because it never produces the producer's digest for any F2 block — so it can never assemble K passing signatures over a digest it would also accept from an attacker. The direction of the error is strictly safe (availability loss, not soundness loss).

The fail-close is documented and intentional. `verify.cpp:40-56` (the function-header IMPORTANT block) states that `compute_block_digest` binds "the F2 view roots over the rpc_headers-STRIPPED collections (inbound_receipts / equivocation_events / abort_events)," that "the light client cannot reconstruct these from a stripped header, so it does NOT bind them and FAIL-CLOSES on F2 / cross-shard blocks (false-negative, never false-PASS — verify those against a full node)." The light client thus advertises its domain (non-F2 headers) and defers F2 / cross-shard blocks to a full node, which has the unstripped collections and the F2 reconciliation inputs. ∎

**Note (why the omission cannot flip to a false positive).** The light client's digest is *missing* tokens the producer included; it is never a *superset*. A false positive would require the light client to compute the producer's exact digest for a block it should reject — impossible here, because on an F2 block the light client structurally cannot emit the F2 root tokens (it has no code path for them). The only reachable error is "rejects a genuine F2 header it lacks the data to check," which §6 prices as an availability concern bounded to F2 / cross-shard headers.

---

## 5. Mechanized witnesses

Defense-in-depth, mirroring FB61's layering: a **source-level guard** catches a maintainer's drift in either digest function *before* a build (critical on hosts that cannot build all binaries), a **producer-side in-process field fence** pins the daemon's digest shape, and a **cluster end-to-end** test confirms a real light binary verifies a real minted block's K-of-K signatures against its own recompute.

| Layer | Script | What it pins | Live-check (negative control) |
|---|---|---|---|
| Source (pre-build), NEW | `tools/test_block_digest_xbinary_parity.sh` | Parses BOTH C++ sites (`src/node/producer.cpp::compute_block_digest` and `light/verify.cpp::light_compute_block_digest`), reduces each to an ordered `append`-token list, and asserts: (a) the **core 10** tokens are identical and in identical order; (b) the light list is the producer list with exactly the three F2 appendages (inbound / eq / abort roots) removed; (c) the **partner** + **timestamp** tail appears in BOTH, in the same order, under matching gates (`is_zero_hash_`/`!= zero` for partner; the identical `!creator_proposer_times.empty()` for timestamp). Pure `awk`/`grep` over `.cpp`; no binary; never SKIPs; offline; deterministic. The F2-appendage removal is asserted as an *exact remainder* (the light list ∪ {3 F2 roots} == producer list), so a *fourth* producer-only append, or a reordered tail, or a partner/timestamp token dropped from light, all break the check. | `SELFTEST=1 bash …` runs a liveness self-check: it feeds synthetic snippets through the same `extract_tokens()` — (1) canonical sanity, (2) a reordered tail (timestamp before partner), (3) a dropped light-side partner append, (4) an F2 root spuriously present in the light list, (5) a core field reordered — and asserts each drift reduces to a token sequence the production assertion would flag RED. Exits non-zero if any drift is missed. |
| Producer (in-process) | `tools/test_block_digest.sh` | Drives the daemon's `compute_block_digest` directly: asserts the core fields are bound, the conditional appendages fire only on their trigger (a non-F2 block keeps the byte-identical v1 digest; a merged block binds `partner_subset_hash`; a reconciled block binds `timestamp`), and that mutating any bound field changes the digest. The producer-side field fence behind T-1. | The bound-field-mutation assertions are themselves the negative controls: flipping a bound field must change the digest; toggling a gate off must drop its token. |
| Cluster (end-to-end) | `tools/test_light_verify_block_sigs.sh` | Boots a cluster, mints a real **block 1** (the common non-merged, non-F2 case), serves its header via `rpc_headers`, and runs `determ-light verify-block-sigs` — asserting the light binary's `light_compute_block_digest` recompute (B) reproduces the daemon's `compute_block_digest` (A) closely enough that all K committee Ed25519 sigs verify (the `(B)==(A)` end-to-end equality for the non-merged common case). | A tamper variant mutates a header field after signing; the light client's recomputed digest must then DIFFER and the sig check must FAIL — proving the verification is a live check, not a green-by-default pass. |

**Coverage split (why all three).** The cluster test (`test_light_verify_block_sigs.sh`) pins the **common case at runtime** — but the block-1 it mints is plain: non-merged (`partner_subset_hash == 0`) and non-reconciled in the minimal harness, so its digest exercises only the **core 10** and *never triggers* the partner or timestamp tail appendages. The conditional **merged-block / reconciled-block tail** — positions 11-12, the sub-domain where BDP is least obvious because the two functions each run a *conditional* append — is exactly what the NEW source guard (`test_block_digest_xbinary_parity.sh`) pins: it asserts the tail's order and matching gates *statically*, on every host, without needing a cluster to mint a merged block. The producer fence (`test_block_digest.sh`) closes the third side: it confirms the daemon's `compute_block_digest` actually fires the tail on a merged/reconciled block (so the source guard is asserting parity against a *live* feature, not dead code). Source guard ⇒ the mirror is faithful pre-build (incl. the tail the cluster never reaches); producer fence ⇒ the daemon side of the mirror is real; cluster ⇒ a built light binary verifies a built daemon's signatures end-to-end. The negative controls make each layer a *live* equality/verification check rather than a tautology.

> **Status note.** `tools/test_block_digest.sh` and `tools/test_light_verify_block_sigs.sh` are shipped and auto-discovered by `run_all.sh` (the `tools/test_*.sh` glob). `tools/test_block_digest_xbinary_parity.sh` is the NEW source guard introduced alongside this proof (static, pre-build, with a `SELFTEST=1` liveness mode), matching the FB61 `test_signing_bytes_source_parity.sh` pattern.

---

## 6. Threat / why it matters

The block digest is the **FA1 committee-signature target**: the K-of-K Phase-2 signatures attest to `compute_block_digest(b)`, and that attestation is what a light client trusts in place of replaying the chain. A drift between the two digest functions is therefore a consensus-adjacent fault, not a cosmetic one, and it bites in *both* directions.

**Direction 1 — light rejects valid merged-block sigs (liveness / availability loss for light clients).** Suppose a maintainer edits `compute_block_digest`'s tail — say reorders `partner_subset_hash` and `timestamp`, or changes the partner gate — but forgets to mirror it in `light_compute_block_digest` (the `verify.cpp:32/56` "keep in sync" comments exist precisely because this is a separate binary the daemon does not link). Then on every **merged** block (non-zero `partner_subset_hash`) the light client recomputes a digest that no longer matches the committee's signed digest, and `verify_block_sigs` rejects a perfectly valid block as UNVERIFIABLE (`:302`). Light clients on a region that merges would silently lose the ability to verify any merged header — a targeted availability outage that a single-shard test harness (which never mints a merged block) would not surface. The NEW source guard turns this RED at review time, on any host, before a build.

**Direction 2 — producer-side tail bug lets two distinct merged blocks share a digest (FA1 equivocation-binding loss).** Symmetrically, a bug on the *producer* side — e.g. failing to bind `partner_subset_hash` when it should — would let two distinct blocks at a merged height carry the *same* digest while differing in the partner commitment. Both would collect the same K-of-K signatures; FA1's "≤ 1 finalized digest per height" would hold *vacuously* while two distinct merged bodies circulated behind it — exactly the S-030-D2 removal gap that the `partner_subset_hash` digest binding (commit `8585a50`, `S030-D2-Analysis.md` item 9) was added to close. The producer fence (`test_block_digest.sh`) pins that the daemon binds the field; this proof pins that the light client mirrors the binding, so the *verifier* side of the FA1 guarantee is also drift-protected. (The full S-030-D2 analysis — which fields the digest must bind and why the F2 roots use reconciliation while partner/timestamp do not — lives in `S030-D2-Analysis.md`; this proof is the cross-binary-parity complement: given that the producer binds the right fields, the light client recomputes the same digest on its domain and fail-closes off it.)

**Why fail-closed is the right boundary.** The F2 / cross-shard blocks the light client *cannot* check (it lacks the stripped collections and the reconciliation inputs) are handled by structural omission, not by a weaker check: the light digest diverges, every sig fails, the block is UNVERIFIABLE, and the documented contract (`verify.cpp:40-56`) routes the operator to a full node. Under A2 this is reliable — a genuine F2 header never accidentally matches the light digest — so the only cost is availability on F2 headers, never a false acceptance. BDP is the invariant that keeps "the digest the committee signed" a single binary-independent object on the light client's verification domain, and the three mechanized witnesses keep BDP from rotting.

---

## 7. Implementation cross-references

| Theorem / claim | Function | File:lines | Role |
|---|---|---|---|
| T-1 producer spec | `compute_block_digest` | `src/node/producer.cpp:608-693` | The digest the K-of-K committee signs; core `:610-620`, F2 inbound `:629-635`, F2 eq `:650-655`, F2 abort `:656-661`, partner `:674-676`, timestamp `:689-691`. |
| T-2 light recompute | `light_compute_block_digest` | `light/verify.cpp:57-92` | Mirror; core `:59-69`, partner `:76-78`, timestamp `:88-90`; NO F2 appendages. |
| T-2 sig-verify path | `verify_block_sigs` | `light/verify.cpp:235-328` (digest `:283`, Ed25519 verify `:299`) | Consumes the recomputed digest to check each committee sig. |
| T-3 fail-close contract | header comment | `light/verify.cpp:40-56` | Documents that F2 / cross-shard blocks fail-close (false-negative, never false-PASS — verify against a full node). |
| partner survives strip | `from_json` / `to_json` | `src/chain/block.cpp:323-332` (signing_bytes bind), `:499-500` (serialize) | `partner_subset_hash` bound into block hash + kept in stripped header. |
| timestamp survives strip | `from_json` | `src/chain/block.cpp:446-449` (serialize), `:586-588` (parse) | `creator_proposer_times` repopulated on the light side ⇒ identical gate. |
| field model | — | `docs/proofs/S030-D2-Analysis.md` §1, §3.2, §5, items 7-10 | Which fields the digest binds and the F2 reconciliation vs deterministic/median tail. |

Tests:

| Script | Theorem coverage |
|---|---|
| `tools/test_block_digest_xbinary_parity.sh` (NEW) | T-2 source-level token-parity (core identical, light = producer minus 3 F2 roots, partner/timestamp tail same order + matching gates) + `SELFTEST=1` liveness self-check (reorder / drop / spurious-F2 / core-reorder drift classes). |
| `tools/test_block_digest.sh` | T-1 producer-side field fence (core bound; conditional appendages fire only on trigger; bound-field mutation changes the digest). |
| `tools/test_light_verify_block_sigs.sh` | T-2 runtime end-to-end `(B)==(A)` for the non-merged common case (real cluster block 1, all K sigs verify against the light recompute) + tamper negative control. |

---

## 8. Status

- **Spec.** Complete (this document, FB62).
- **Invariant.** BDP holds **unconditionally** (exact byte equality) on the non-F2 domain — T-2: `light_compute_block_digest(b) == compute_block_digest(b)` for every block with empty `inbound_receipts` and all-zero eq/abort view roots, which includes merged (non-zero `partner_subset_hash`) and timestamp-reconciled blocks. The light client's K-of-K Ed25519 verification is sound there (accepts genuine, rejects tamper).
- **Boundary.** T-3: on F2 / cross-shard blocks the light client omits roots the producer bound, so its digest diverges and every committee sig fails its check — a false NEGATIVE (UNVERIFIABLE), never a false positive. Documented contract: verify F2 / cross-shard blocks against a full node (`verify.cpp:40-56`).
- **Assumptions.** None for the byte-identity equality (pure straight-line builders over the same `Block` via the same `SHA256Builder`; (P-det)+(P-app)). A1 (Ed25519 EUF-CMA) lifts digest equality to sig-verify equivalence; A2 (SHA-256) only for the divergence-detection direction in §5/§6.
- **Relationship.** Digest-layer sibling of `CanonicalSigningBytesParity.md` (FB61, tx-pre-image parity); the byte-identity discharge of `CrossBinaryCanonicalFormat.md` CBF-2's `light_compute_block_digest` re-implementation surface; consumes the field model of `S030-D2-Analysis.md`.
- **Mechanized witnesses.** NEW source guard `tools/test_block_digest_xbinary_parity.sh` (static, pre-build, `SELFTEST=1` liveness) + producer fence `tools/test_block_digest.sh` (shipped) + cluster end-to-end `tools/test_light_verify_block_sigs.sh` (shipped). Coverage split: cluster pins the common case at runtime; source guard pins the conditional merged/reconciled tail the cluster's block 1 never triggers.
- **Threat.** A tail drift would make the light client reject valid merged-block sigs (light-client availability loss) or, dually, a producer-side tail bug would let two distinct merged blocks share a digest (FA1 equivocation-binding loss); the source guard turns either RED pre-build. Cross-ref `S030-D2-Analysis.md`.

---
