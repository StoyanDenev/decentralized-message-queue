# NegativeVerdictSoundness — soundness asymmetry of the `NOT-INCLUDED` / absence verdict across the `determ-light` verifier family

This document formalizes a property that the existing light-client proofs each *assert in passing* but none take as their subject: the **soundness of the negative verdict**. Every trust-minimized `determ-light` verifier returns one of three answers — a positive (`INCLUDED` / `APPLIED`), a negative (`NOT-INCLUDED`), or the fail-closed `UNVERIFIABLE`. The positive verdicts are exhaustively analyzed elsewhere (`TxInclusionProofSoundness.md` TI-1, `ReceiptInclusionProofSoundness.md` RI-2, `LightClientThreatModel.md` T-L3). This proof asks the *dual* question, across the whole family at once:

> When a `determ-light` verifier reports `NOT-INCLUDED` (tx `H` absent from block `B`; receipt absent; shard not merged), is that a **cryptographically sound** statement, or is it a **daemon-trusted assertion** that a Byzantine daemon could forge?

The answer is **not uniform**, and the non-uniformity is load-bearing for any caller who would act on absence. The verifier family splits into two regimes with *different* trust footings for their negatives:

1. **The block-body-reconstruction regime** (`verify-tx-inclusion`). The committed object — the block's transaction set — is **fully enumerable** from the committee-signed block: `tx_root` is a flat SHA-256 over the *complete* sorted union of tx hashes (`producer.cpp:262-270`), and the verifier recomputes it from the entire body and gates on byte-equality before scanning for `H`. Absence of `H` from a body whose recomputed root matches the committee-signed root is therefore a **sound exclusion**: a daemon that drops the one tx the caller is asking about changes the recomputed root and is caught (→ `UNVERIFIABLE`, never a false `NOT-INCLUDED`). This regime delivers a genuine *verified negative*.

2. **The state-proof regime** (`verify-receipt-inclusion` on `i:`, `verify-merge-state` on `m:`, `verify-param-change` on `p:`). The committed object is a **single leaf** inside a sorted-leaves balanced Merkle tree, and the sorted-leaves primitive supports **positive membership proofs only** — it is *not* a sparse Merkle tree and has **no native non-membership (absence) proof** (`MerkleTreeSoundness.md` MT-5). The verifier cannot enumerate the full leaf set, so it cannot reconstruct-and-check the way the tx regime does. When the daemon replies `not_found` for the canonical key, the verifier reports `NOT-INCLUDED` — but that negative is **not cryptographically backed**: a Byzantine daemon withholding a genuinely-present leaf is observationally **indistinguishable** from a genuinely-absent leaf (`ReceiptInclusionProofSoundness.md` §4.3). The "verified negative" in the `i:`/`m:` source comments is, precisely, *trusted-daemon* for the negative answer.

The proof's purpose is to (a) prove the block-body negative is sound (NV-1), (b) prove the state-proof negative is **not** sound and characterize exactly what trust it rests on (NV-2, NV-3), (c) prove the one indispensable safety property that holds in **both** regimes and makes the asymmetry tolerable — **no Byzantine daemon can convert a forged negative into a false positive**, so the A1-relevant decision (releasing off-chain value on belief that something settled) is *never* driven by a forgeable verdict (NV-4), (d) prove the contract is fail-closed on every non-`not_found` refusal (NV-5), and (e) fix the **caller contract** that downstream code must honor so the unsound negative is never weaponized (NV-6). The result is a precise, citable boundary: `INCLUDED`/`APPLIED` is trustless in both regimes; `NOT-INCLUDED` is trustless *only* in the block-body regime and is a daemon assertion in the state-proof regime.

No new cryptographic primitive is introduced. The block-body negative reduces to **A2** (SHA-256 collision resistance) via the `tx_root` recompute gate; the state-proof negative reduces to **no assumption at all** (it is unconditionally forgeable by `A_daemon` and the proof says so).

**Companion documents.** `Preliminaries.md` (F0) §2.0 canonical assumption labels — **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision resistance (§2.1), **A3** = SHA-256 preimage resistance (§2.1); `MerkleTreeSoundness.md` (**MT-5** is the load-bearing input — "positive membership proofs only; no native non-membership"; §6.3 "not a sparse Merkle tree" + the migration note); `TxInclusionProofSoundness.md` (**TI-2** proves the *positive* form of NV-1 — sound non-inclusion in the block-body regime — and §3.3 pins `tx_root` as the flat-SHA full-set commitment that makes enumeration possible; this proof lifts TI-2 into the cross-family asymmetry statement and contrasts it against the state-proof regime TI-2 does *not* cover); `ReceiptInclusionProofSoundness.md` (**RI-3** non-application "is *not* a cryptographically provable statement under the sorted-leaves primitive"; its §4.3 daemon-withholding-vs-genuine-absence indistinguishability is exactly NV-2's argument; its §1.3 "no positive NOT-APPLIED verdict" is the property NV-6 turns into a caller contract); `StateProofCompositeKeySoundness.md` (**SP-CK-3** sourcing-independent soundness — the *positive* read; this proof is the negative-read complement); `LightClientThreatModel.md` (the malicious-daemon adversary `A_daemon`; **L-6** fail-closed exit that NV-5 specializes; T-L3 state-proof correctness whose negative this proof bounds); `LightClientCompositionMap.md` (§5 command→guarantee map + §6 consolidated limitations — this proof supplies the missing per-command *negative-verdict* column); `CrossShardReceiptDedup.md` (**T-R7** entry-exists-iff-applied — the chain-state predicate that makes the `i:` *positive* meaningful and bounds what an honest `not_found` would mean); `S036UnderQuorumMerge.md` (FA9/`UnderQuorumMerge.md` — the `m:` merge-state semantics whose absence `verify-merge-state` reports); `docs/SECURITY.md` §S-033 (committee-anchored state_root) + §S-040 (`leaf_count` caller-trust narrative); `docs/PROTOCOL.md` §10.2 (`state_proof` RPC contract — `not_found` for an absent key).

---

## 1. Scope

### 1.1 In scope

The **negative verdict** (`NOT-INCLUDED`, and its `i:`-namespace label `NOT-APPLIED`-shaped variant) of four `determ-light` subcommands — one block-body verifier and three state-proof verifiers — as dispatched in `light/main.cpp`:

| Subcommand | Committed object | Negative source | Regime |
|---|---|---|---|
| `verify-tx-inclusion` | block `B`'s tx set (committed by `tx_root`) | full-body `tx_root` recompute + bijection + scan (`light/verify_tx_inclusion.cpp:184-255`) | block-body |
| `verify-receipt-inclusion` | `i:` leaf `(key_i(S,H), SHA256(0x01))` | daemon `state_proof` reply `not_found` (`light/main.cpp:1458-1464`) | state-proof |
| `verify-merge-state` | `m:` leaf `(key_m(D), value_hash)` | daemon `state_proof` reply `not_found` (`light/main.cpp:1790-1800`) | state-proof |
| `verify-param-change` | `p:` leaf `(key_p(E,j), value_hash)` | daemon `state_proof` reply `not_found` (`light/main.cpp:2146-2153`) | state-proof |

The six theorems and one lemma:

| # | Property |
|---|---|
| **NV-1** (Block-body negative is sound) | In the block-body regime, `NOT-INCLUDED` ⇒ `H` is genuinely absent from the committee-signed block `B`; a daemon cannot forge a false `NOT-INCLUDED`. Reduces to **A2** via the `tx_root` recompute gate (lifts TI-2). |
| **NV-2** (State-proof negative is NOT sound) | In the state-proof regime (`i:`/`m:`/`p:`), `NOT-INCLUDED` does **not** imply genuine absence: a Byzantine daemon can return `not_found` for a key whose leaf is genuinely committed, and the verifier cannot distinguish this from real absence. The forgery requires **no** broken assumption — it is unconditional for `A_daemon`. |
| **NV-3** (Exact trust footing of the state-proof negative) | The state-proof `NOT-INCLUDED` rests on a *liveness/honesty* assumption about the daemon ("the daemon answers `not_found` only for keys genuinely absent"), which is **outside** the {A1, A2, A3} cryptographic base and is **not** discharged by the genesis anchor or the committee-sig trust. We name this non-cryptographic precondition explicitly. |
| **NV-4** (No negative→positive weaponization) | In **both** regimes, a daemon that forges a negative cannot thereby cause the verifier to emit a *positive* (`INCLUDED`/`APPLIED`) for an uncommitted object. The two verdict surfaces are independent; the unsound negative cannot manufacture a false settlement claim. |
| **NV-5** (Fail-closed on non-`not_found` refusal) | Any daemon reply other than a clean inclusion proof or the literal `not_found` for the **canonical** key yields `UNVERIFIABLE` (fail-closed), never a `NOT-INCLUDED` and never an `INCLUDED`. The `not_found` branch is reachable only for the exact canonical key the verifier computed. |
| **NV-6** (Caller contract) | A downstream consumer MUST treat a state-proof `NOT-INCLUDED` as *"no membership proof obtained"* (≈ `UNVERIFIABLE` for value-releasing decisions), and MUST NOT treat it as authoritative absence. The block-body `NOT-INCLUDED` MAY be treated as authoritative absence. The A1-relevant value-release decision keys off the *positive* verdict only. |

| Lemma | Property |
|---|---|
| **NV-T** (Enumerability dichotomy) | The block-body regime's negative is sound *because* the committed tx set is fully enumerable from one committee-signed object; the state-proof regime's negative is unsound *because* the committed leaf set is **not** enumerable from the head-only `state_proof` RPC and the sorted-leaves primitive has no exclusion proof (MT-5). Enumerability is the structural discriminator. |

### 1.2 Out of scope

- **Positive-verdict soundness.** `INCLUDED`/`APPLIED` is proven sound by TI-1 / RI-2 / SP-CK-3 / T-L3; this proof cites those and does not re-derive them.
- **Multi-peer cross-checking.** Querying `k` independent daemons and trusting absence only on unanimous `not_found` would *raise* the state-proof negative's footing to "at least one honest peer" — but `determ-light` is single-daemon (`LightClientThreatModel.md` §6). The single-daemon negative is what NV-2/NV-3 bound. Multi-peer is noted as the upgrade path (§6) but not analyzed.
- **Liveness / availability.** A daemon that simply refuses to answer is an availability failure, caught by NV-5 (`UNVERIFIABLE`), not a soundness failure.
- **A future sparse-Merkle migration** that would make the state-proof negative sound (MT-5 §6.3 / `merkle.hpp:18-21`). Today no shipped feature relies on a sound state-proof absence, so this is the documented boundary, not a gap.

### 1.3 Adversary

`A_daemon` (`LightClientThreatModel.md` §2): a fully-Byzantine single daemon serving all RPC data — headers, bodies, `state_proof` replies. `A_daemon` may withhold, fabricate, reorder, or mis-label any reply. It does **not** hold any committee secret key (else A1 is broken, out of scope) and cannot find a SHA-256 collision (A2). The genesis file is operator-pinned (`A_genesis` out of scope). The question NV-1..NV-6 answer is exactly: *which negative verdicts can `A_daemon` forge?*

---

## 2. Preliminaries specialized to the negative verdict

### 2.1 The block-body commitment is a full-set commitment

From `TxInclusionProofSoundness.md` §3.3, grounded in `src/node/producer.cpp:262-270` (`compute_tx_root`):

$$
\texttt{tx\_root}(B) \;=\; \mathrm{SHA256}\!\big(\,\mathrm{sort}\{\,h_1, h_2, \ldots, h_n\,\}\,\big),
$$

where `{h_1, …, h_n}` is the **complete** set of transaction hashes committed at block `B`. The commitment is over the *entire* set at once, not a per-element accumulator. `tx_root` is bound into the committee-signed block digest (`producer.cpp:581` `h.append(b.tx_root)`; mirrored light-side at `light/verify.cpp:51`), so after `verify-tx-inclusion`'s steps 1-3 (genesis anchor + committee-sig head trust, TI §1.1) the verifier holds a **trusted** `tx_root` and a daemon-supplied body. The membership decision is:

```
recompute r' := light_compute_tx_root(body.creator_tx_lists)   // light/verify_tx_inclusion.cpp:184
if r' != committee-signed tx_root: UNVERIFIABLE                 // :185-191 (root gate)
// bijection gate: every body tx ∈ committed set, no dups, |body| == |committed|
if body is not a bijection onto the committed set: UNVERIFIABLE // :214-240
else: INCLUDED iff H ∈ {hash(tx) : tx ∈ body} else NOT_INCLUDED // :242-255
```

**Key structural fact (enumerability).** Because `tx_root` commits the *whole* set and the gate forces the daemon's body to hash to that exact root, after the gate the verifier possesses the genuine, complete committed tx set. The verifier additionally enforces a **bijection** between the served body and the committee-signed hash set — rejecting any body tx not in the committed set, any duplicate, and any body whose cardinality differs from the committed set (`:214-240`) — so omission *and* padding are both caught before the scan. Membership *and non-membership* of `H` are then decidable by inspection over the genuine complete set.

### 2.2 The state-proof commitment is a per-leaf commitment with no exclusion proof

From `MerkleTreeSoundness.md` MT-5 and `chain.cpp::build_state_leaves` / `Chain::state_proof` (`chain.cpp:435-462`): the state tree is a **sorted-leaves balanced binary Merkle tree** over the ten namespaces. Leaf order is sort-order over the canonical key bytes, **not** a key-indexed path. The `state_proof` RPC (`node.cpp` `rpc_state_proof`, lines 3287-3378) returns a **positive** inclusion proof for a present key, or the structured error `not_found` for an absent key (`chain.cpp:449` — `state_proof` returns `nullopt`; surfaced as `{"error":"not_found"}`). There is **no** path that returns a *proof of absence*.

**Key structural fact (non-enumerability).** The head-only `state_proof` RPC exposes one leaf per call and never the full sorted leaf vector; the verifier cannot reconstruct the leaf set, so it cannot decide non-membership the way §2.1 decides it for the tx set. The only signal of absence is the daemon's *unverifiable* `not_found`.

### 2.3 The committee-signed root binds present leaves only

The S-033 state_root is committee-anchored (`StateRootAnchorSoundness.md` SR-1; `S033StateRootNamespaceCoverage.md`). A signed root `R` proves, for any leaf `ℓ` the verifier holds a passing `merkle_verify(ℓ, path, R)` for, that `ℓ ∈ leaves(R)` (MT-4, A2). It says **nothing verifiable** about a leaf the verifier does *not* hold a path for: absence is not a statement `R` can be made to attest under the sorted-leaves primitive. This is the cryptographic content of MT-5, restated for the root layer.

---

## 3. Lemma NV-T (enumerability dichotomy)

**Statement.** A trust-minimized non-membership decision is sound iff the verifier can reconstruct the *complete* committed set from committee-signed data. The block-body regime satisfies this (§2.1); the state-proof regime does not (§2.2). Enumerability is therefore the structural discriminator between a sound and an unsound negative.

**Proof.**

(⇐, block-body) After the §2.1 gate fires (recomputed `r'` equals the committee-signed `tx_root`), the verifier holds set `T := {hash(tx) : tx ∈ body}` with `SHA256(sort T) = tx_root`. Suppose the genuine committed set were `T* ≠ T`. Then `sort T ≠ sort T*` (sets differ ⇒ sorted sequences differ), so `SHA256(sort T) = SHA256(sort T*)` is a SHA-256 collision, contradicting **A2**. Hence `T = T*` except with probability ≤ `2⁻¹²⁸`. The verifier's membership/non-membership decision over `T` is therefore a decision over the genuine `T*`. Non-membership is decidable and sound. ∎(⇐)

(⇏, state-proof) The verifier never obtains the full leaf set (§2.2): each `state_proof` call yields at most one leaf, and the RPC has no "dump all leaves" mode that is itself committee-verifiable leaf-by-leaf into a *complete* set. With only a per-key positive-membership oracle and an unverifiable `not_found`, the verifier cannot exhibit the analog of `T` above. There is no reconstruction step, hence no collision argument to make the negative sound. ∎(⇏)

The dichotomy is exactly the SMT-vs-sorted-leaves boundary of MT-5: an SMT's key-path *is* a per-key non-membership witness (an empty slot at the key's path is committee-verifiable); the sorted-leaves tree has no such witness. ∎

---

## 4. Theorem NV-1 (block-body negative is sound)

**Statement.** For `verify-tx-inclusion`: if the verifier emits `NOT-INCLUDED` for `(H, B)`, then `H` is the hash of no transaction in the genuine committee-signed block `B`, except with probability ≤ `(K+1)·2⁻¹²⁸`. Equivalently, `A_daemon` cannot forge a false `NOT-INCLUDED`.

**Proof.** `NOT-INCLUDED` is emitted only on the path: steps 1-3 pass (genesis anchor T-L1 + committee-sig head trust T-L2, giving a trusted `tx_root`), the §2.1 gate passes (recomputed `r'` equals the committee-signed `tx_root`), and `H ∉ T`. By NV-T (⇐), `T` equals the genuine committed set `T*` except with probability ≤ `2⁻¹²⁸` (A2). The trusted `tx_root` itself is genuine except with probability ≤ `K·2⁻¹²⁸` (A1 committee-sig forgery over the digest, T-L2; `K` committee members). Conditioned on both, `H ∉ T = T*` is exactly "`H` genuinely absent." Union bound gives `(K+1)·2⁻¹²⁸`.

The false-`NOT-INCLUDED` attack — daemon serves a body that *omits* the genuine tx with hash `H` — is defeated by the gate: omitting any committed tx changes `r'`, so `r' ≠ tx_root` and the verifier exits `UNVERIFIABLE`, **not** `NOT-INCLUDED` (TI-2; TI-3 tampered-body detection). This is the positive-form result of `TxInclusionProofSoundness.md` TI-2, here lifted to the family-level statement that the block-body negative is the *sound* member of the dichotomy. ∎

---

## 5. Theorem NV-2 (state-proof negative is NOT sound)

**Statement.** For `verify-receipt-inclusion` (`i:`), `verify-merge-state` (`m:`), and `verify-param-change` (`p:`): the verifier may emit `NOT-INCLUDED` for a key whose leaf is genuinely committed under the committee-signed root. `A_daemon` can force this with **no** broken cryptographic assumption.

**Proof (constructive attack).** Let key `k` (the canonical `i:` receipt key `key_i(S,H)`, the canonical `m:` merge key `key_m(D)`, or the canonical `p:` param-change key `key_p(E,j)`) have a genuinely-committed leaf `ℓ = (k, v)` under the current committee-signed state_root `R` (e.g. the receipt *was* applied, T-R7; the shard *is* merged; or the change *is* staged). The honest daemon would answer the verifier's `state_proof{namespace, key=hex(body)}` with a valid Merkle path proving `ℓ ∈ leaves(R)`.

`A_daemon` instead replies `{"error":"not_found"}`. The verifier's code (`light/main.cpp:1458` for `i:`, `:1790` for `m:`, `:2146` for `p:`) reaches the branch `if (err == "not_found")` and sets `verdict = NOT_INCLUDED`. No genesis-anchor, header-sig, prev_hash, `key_bytes`, or `value_hash` check has any purchase here: those checks gate the *positive* path (binding a served proof to the intended leaf) and are simply not exercised when the daemon serves no proof at all.

The verifier has **no** counter-evidence: by NV-T (⇏) it cannot reconstruct the leaf set to observe that `ℓ` is present, and by §2.3 the committee-signed root `R` cannot be made to attest `ℓ`'s presence without a path the daemon declines to supply. The withheld-present case and the genuinely-absent case produce **byte-identical** observable transcripts (`ReceiptInclusionProofSoundness.md` §4.3 — "indistinguishable"). The attack uses only the daemon's freedom to choose its reply; it breaks neither A1, A2, nor A3. Hence the forgery probability is `1`, not a cryptographic bound. ∎

**Remark (source-comment vs. proof).** The `i:`/`m:`/`p:` source comments label the `not_found`→`NOT-INCLUDED` outcome "a sound verified negative" (`light/main.cpp:1333-1334`, `:1645-1646`, `:2022-2023`). NV-2 sharpens this: it is *sound relative to an honest-daemon assumption*, and **unsound** against `A_daemon`. The verdict is correct *information* when the daemon is honest, but it is not a *proof*. The block-body `NOT-INCLUDED` (NV-1) is the only negative that is a proof. §6 records this as finding F-1, with the recommended doc/comment refinement.

---

## 6. Theorem NV-3 (exact trust footing of the state-proof negative)

**Statement.** The state-proof `NOT-INCLUDED` is sound **iff** the following non-cryptographic precondition holds, which lies outside the {A1, A2, A3} base and is discharged by neither the genesis anchor nor the committee-sig trust:

> **(H-neg) Negative-honesty.** The daemon returns `not_found` for the canonical key `k` *only if* no leaf for `k` is committed under the current committee-signed root.

**Proof.** (Sufficiency) If (H-neg) holds, then a `not_found` reply for `k` implies `k`'s leaf is genuinely absent, so `NOT-INCLUDED` is sound. (Necessity) If (H-neg) fails, the constructive attack of NV-2 produces a false `NOT-INCLUDED`. Hence (H-neg) is exactly the missing premise.

**(H-neg) is not cryptographic.** It constrains the daemon's *behavior on the negative path*, where no signed object is produced to check against. The genesis anchor (T-L1) binds chain *identity*; the committee-sig trust (T-L2) binds the *head and its roots*; the Merkle gate (T-L3, MT-4) binds *served positive proofs* to present leaves. None of the three constrains what the daemon does when it chooses to serve *no* proof. (H-neg) therefore sits beside, not within, the cryptographic base — it is a trust/honesty assumption on the single daemon, exactly the assumption `LightClientThreatModel.md` §6 lists as a residual single-daemon limitation, here pinned to the negative path specifically.

**Footing comparison.** The positive verdict's footing is `{A1, A2}` (+ A3 for content binding) — purely cryptographic, holding against a fully-Byzantine daemon. The block-body negative's footing is `{A1, A2}` (NV-1) — also purely cryptographic. The state-proof negative's footing is `{A1, A2}` **plus (H-neg)** — the one verdict in the family whose soundness requires trusting `A_daemon` not to lie by omission. ∎

---

## 7. Theorem NV-4 (no negative→positive weaponization)

**Statement.** In both regimes, `A_daemon` forging a negative cannot cause the verifier to emit a *positive* (`INCLUDED`/`APPLIED`) for an object not committed under the committee-signed data. The negative surface and the positive surface are independent; an unsound negative cannot manufacture a false settlement.

**Proof.** The positive verdict is emitted **only** on a disjoint code path that requires a daemon-served object passing all binding checks:

- Block-body (`verify-tx-inclusion`): `INCLUDED` requires the §2.1 gate to pass **and** `H ∈ T`. Both are checks against committee-signed data; NV-1's analysis shows a positive is sound (TI-1). A `not_found`-style refusal yields no body and cannot reach the `INCLUDED` branch.
- State-proof (`i:`/`m:`/`p:`): `APPLIED`/`INCLUDED` requires a served Merkle proof with `key_bytes == local canonical key` **and** `value_hash == expected marker` **and** `merkle_verify(...) == R` (`light/main.cpp:1465-...` for `i:`, `:1801-...` for `m:`, `:2157-...` for `p:`). The `not_found` branch (`:1458`, `:1790`, `:2146`) is *mutually exclusive* with this branch (the outer `if (proof.contains("error"))` short-circuits). A daemon that returns `not_found` has, by construction, **not** supplied a proof, so it cannot reach the positive branch in the same call.

Thus a forged negative is confined to the negative surface. To produce a false positive `A_daemon` must forge a *positive* proof, which reduces to A1/A2 (RI-2 / TI-1 / SP-CK-3) and is infeasible. The two surfaces do not compose into a false-positive escalation. ∎

**Why NV-4 makes the NV-2 asymmetry tolerable.** The only A1-relevant (supply-affecting / value-releasing) decision a caller makes is to *release off-chain value on belief that an on-chain event settled* — and that decision keys off a **positive** verdict (`ReceiptInclusionProofSoundness.md` §1.2 "acts on" = displays as authoritative / feeds a settlement). A forged *negative* cannot trigger such a release; at worst it causes the caller to *withhold* an action it could safely have taken (a liveness/availability harm, not a soundness harm). The unsound negative is thus confined to the fail-safe direction. NV-6 turns this into the caller contract.

---

## 8. Theorem NV-5 (fail-closed on non-`not_found` refusal) and Lemma NV-5a (canonical-key reachability)

**NV-5 statement.** For the state-proof regime, any daemon reply that is neither a clean inclusion proof nor the literal string `not_found` yields `UNVERIFIABLE`, never `NOT-INCLUDED` and never `INCLUDED`.

**Proof.** The error branch (`light/main.cpp:1458-1464` for `i:`, `:1790-1800` for `m:`, `:2146-2153` for `p:`) tests `err == "not_found"` exactly; the `else` arm sets `verdict = UNVERIFIABLE` with detail "daemon refused the … state-proof: <err> (cannot prove membership trustlessly)". So any other error label — `"invalid hex key for composite namespace"`, a width-check rejection, an RPC/transport error, a malformed JSON reply — falls through to `UNVERIFIABLE`. This specializes `LightClientThreatModel.md` L-6 (fail-closed exit) to the negative path: the verifier never upgrades an *ambiguous* refusal to a verdict; only the one explicit `not_found` label produces `NOT-INCLUDED`, and even that is the NV-3-footed verdict, not a proof. ∎

**NV-5a statement (canonical-key reachability).** The `not_found`→`NOT-INCLUDED` branch is reachable only for a `state_proof` query whose `key` is `hex(body)` for the **exact canonical** body the verifier computed locally (`i:` = `u64_be(src_shard) ‖ tx_hash`, `light/main.cpp:1440-1444`; `m:` = `u32_be(shard_id)`, `:1770-1777`; `p:` = `u64_be(eff_height) ‖ u32_be(idx)`, `:2125-2133`). A daemon cannot trick the verifier into asking about, then reporting absence of, a *different* key.

**Proof.** The query body is built **locally** from the verifier's own arguments (`i:` ← `--src-shard`/`--tx-hash`; `m:` ← `--shard-id`; `p:` ← `--effective-height`/`--idx`) before the RPC call; the daemon has no input into which key is queried. The `not_found` reply is therefore necessarily about the canonical key. Combined with NV-2/NV-3 this means: the *only* thing the daemon can lie about on the negative path is *whether the canonical leaf is present* — it cannot also lie about *which* leaf the negative concerns. The unsound negative is thus tightly scoped to a single, verifier-chosen key. ∎

---

## 9. Theorem NV-6 (caller contract)

**Statement.** Let a downstream consumer `C` (an exchange, a bridge relayer, a UI) act on a `determ-light` verdict. Soundness of `C`'s value-affecting decisions is preserved **iff** `C` honors:

1. **Positive (both regimes):** `INCLUDED`/`APPLIED` MAY be treated as authoritative membership/settlement (sound by TI-1 / RI-2 / SP-CK-3 / T-L3).
2. **Block-body negative:** a `verify-tx-inclusion` `NOT-INCLUDED` MAY be treated as authoritative absence (sound by NV-1).
3. **State-proof negative:** a `verify-receipt-inclusion` / `verify-merge-state` `NOT-INCLUDED` MUST be treated as *"no membership proof obtained"* — operationally equivalent to `UNVERIFIABLE` for any value-releasing or value-withholding-with-finality decision — and MUST NOT be treated as authoritative absence.
4. **`UNVERIFIABLE` (all):** never a basis for a value-affecting decision; retry / switch daemon / escalate.

**Proof.** (1) and (2) are restatements of the cited soundness theorems. (4) is the fail-closed contract (NV-5 / L-6). The crux is (3). By NV-2/NV-3 the state-proof `NOT-INCLUDED` is sound only under the un-discharged premise (H-neg); a consumer that treats it as authoritative absence inherits (H-neg) as a *silent trust assumption on a single Byzantine-capable daemon*. The failure mode this admits: `C` concludes "the cross-shard credit did **not** settle" (or "shard `S` is **not** merged") on a daemon `not_found`, and on that basis takes an irreversible action — e.g. re-issues / refunds value it believes never arrived, or routes around a merge it believes absent — while the leaf is in fact committed. This is a soundness violation of `C`, manufactured entirely by `A_daemon` at zero cryptographic cost.

By NV-4 the safe direction is available: the *positive* verdict is sound in both regimes, so `C` can always make its value-releasing decision conditional on a positive proof and *default to inaction* on a negative it cannot cryptographically trust. Honoring (3) — treating the state-proof negative as non-authoritative — confines `A_daemon`'s influence to the fail-safe (withhold/retry) direction, where NV-4 guarantees no false settlement is producible. Conversely, violating (3) reintroduces the NV-2 attack as a `C`-level soundness break. Hence (3) is both necessary and sufficient for `C`'s soundness on the state-proof negative. ∎

**Corollary NV-6.1 (the `i:` append-only sharpening does not rescue the negative).** The `i:` receipt leaf is append-only (`applied_inbound_receipts_` is never erased except by atomic rollback on a failed apply; `light/main.cpp:1323-1328`), so a *positive* `APPLIED` at any height stays valid at every later height. This strengthens the **positive** verdict's temporal stability but does **not** make the `i:` *negative* sound: append-only says nothing about a daemon's freedom to withhold a present leaf. NV-2 stands for `i:` exactly as for the mutable `m:` case. (The `m:` leaf is additionally mutable — a `MERGE_END` erases it — so its *positive* is head-anchored, `light/main.cpp:1635-1640`; but the negative's unsoundness is the same MT-5 fact in both.)

---

## 10. Concrete-security summary

| Verdict | Subcommand(s) | Footing | Adversary bound vs. `A_daemon` |
|---|---|---|---|
| `INCLUDED` / `APPLIED` | all three | A1 + A2 (+A3 content-binding) | ≤ `(K+1)·2⁻¹²⁸` (forging a positive) |
| `NOT-INCLUDED` (block-body) | `verify-tx-inclusion` | A1 + A2 (NV-1) | ≤ `(K+1)·2⁻¹²⁸` (forging the negative) |
| `NOT-INCLUDED` (state-proof) | `verify-receipt-inclusion`, `verify-merge-state` | A1 + A2 **+ (H-neg)** (NV-2/NV-3) | **1** — unconditionally forgeable; sound only under (H-neg) |
| `UNVERIFIABLE` | all three | fail-closed (NV-5 / L-6) | n/a (never a value-decision basis) |

The single row that is **not** purely cryptographic is the state-proof negative; NV-4 confines its forgery to the fail-safe direction and NV-6 fixes the caller contract that keeps that confinement intact.

---

## 11. Findings

- **F-1 (doc/comment refinement — Low/Op).** The `i:`/`m:`/`p:` source comments call the `not_found`→`NOT-INCLUDED` outcome "a sound verified negative" (`light/main.cpp:1333-1334`, `:1645-1646`, `:2022-2023`). Per NV-2/NV-3 this is sound only under the non-cryptographic premise (H-neg). Recommended refinement: amend the comments to "a daemon-asserted negative — sound under the single-daemon negative-honesty assumption (H-neg); NOT a cryptographic absence proof (no non-membership witness under the sorted-leaves primitive, `MerkleTreeSoundness.md` MT-5)." This is a comment-only change; no behavior changes. The verdict itself is already correctly *distinguished* from a positive (which is the load-bearing safety property, NV-4), so this is a clarity fix, not a defect.
- **F-2 (caller-facing surfacing — Low/Op).** The four subcommands' `--json` output emits the verdict string but does not carry a `soundness` field distinguishing a *cryptographic* `NOT-INCLUDED` (block-body) from a *daemon-asserted* one (state-proof). A downstream `C` that machine-parses the verdict cannot today tell which NV-6 clause applies. Recommended (forward-dev, additive): add `"negative_footing": "cryptographic" | "daemon_asserted"` to the JSON for `NOT-INCLUDED` verdicts so NV-6 clause (2) vs (3) is machine-discriminable. Tracked as a CLI enhancement, not a security gap (NV-4 already confines the harm).
- **F-3 (upgrade path — design item).** The state-proof negative becomes **sound** under either (a) a sparse-Merkle migration giving native non-membership proofs (MT-5 §6.3; root stays a 32-byte `Hash`, `merkle.hpp:18-21`, so wire-compatible at the root), or (b) multi-peer cross-checking where `NOT-INCLUDED` is asserted only on unanimous `not_found` across `k` daemons (footing rises to "≥1 honest peer"). Both are out-of-scope today (no shipped feature relies on a sound state-proof absence); recorded so the boundary is a *decision*, not an oversight.
- **F-4 (composition guard).** NV-1's soundness depends on `tx_root` being the *full-set* commitment (§2.1) and being inside the committee-signed digest. If a future change moved any tx outside `tx_root`'s preimage, or removed `tx_root` from the digest (the `TxInclusionProofSoundness.md` TI-4 counterfactual), the block-body negative would degrade to the daemon-trusted regime and join the state-proof negative under (H-neg). The `validator.cpp:161-167` chain-side gate (`tx_root == compute_tx_root(creator_tx_lists)`) + `producer.cpp:581` digest-append are the maintenance contract for NV-1; a regression there is a regression of NV-1, and the `tools/test_light_verify_tx_inclusion.sh` NOT-INCLUDED scenario is its tripwire.

---

## 12. Implementation cross-reference

| Claim | Source location | Note |
|---|---|---|
| NV-1 (block-body negative sound) | `light/verify_tx_inclusion.cpp:184-191` (root gate), `:214-240` (bijection gate — rejects omission/padding), `:242-255` (membership scan / `NOT_INCLUDED`) | The root + bijection gates make the negative sound; lifts TI-2. |
| §2.1 full-set `tx_root` | `src/node/producer.cpp:262-270` (`compute_tx_root`), `:581` (digest append); `light/verify.cpp:51` (light recompute) | Flat SHA-256 over the *complete* sorted hash set. |
| NV-2 (`i:` forgeable negative) | `light/main.cpp:1458-1464` (`not_found`→`NOT_INCLUDED` branch); `:1465-...` (disjoint positive branch) | `not_found` reachable without any binding check. |
| NV-2 (`m:` forgeable negative) | `light/main.cpp:1790-1800` (`not_found`→`NOT_INCLUDED`); `:1801-...` (disjoint positive branch) | Same shape; `m:` additionally mutable. |
| NV-2 (`p:` forgeable negative) | `light/main.cpp:2146-2153` (`not_found`→`NOT_INCLUDED`); `:2157-...` (disjoint positive branch) | Same shape; `p:` param-change staging. |
| §2.2 / NV-T (⇏) no exclusion proof | `MerkleTreeSoundness.md` MT-5; `src/chain/chain.cpp:435-462` (`state_proof`, `nullopt` at `:449`); `src/node/node.cpp:3287-3378` (`rpc_state_proof`) | Sorted-leaves tree; positive membership only. |
| NV-4 (no negative→positive) | `light/main.cpp:1458` / `:1790` / `:2146` outer `if (error)` short-circuit; `light/verify_tx_inclusion.cpp` `INCLUDED` only after gate | Positive and negative branches mutually exclusive. |
| NV-5 (fail-closed on other errors) | `light/main.cpp:1463-1464` / `:1797-1800` / `:2153` (`else` → `UNVERIFIABLE`) | Only literal `not_found` yields the negative. |
| NV-5a (canonical-key reachability) | `light/main.cpp:1440-1444` (`i:` body), `:1770-1777` (`m:` body), `:2125-2133` (`p:` body) | Query key built locally; daemon has no say. |
| Corollary NV-6.1 (`i:` append-only) | `light/main.cpp:1323-1328` (append-only note); `m:` mutability `:1635-1640` | Append-only rescues the *positive*, not the negative. |

---

## 13. Relationship to the light-client proof family

This proof is the **negative-verdict complement** to the family's positive-verdict proofs and fills the one column `LightClientCompositionMap.md` §5 leaves implicit (each command's *negative* footing):

- `TxInclusionProofSoundness.md` proves the *positive* (TI-1) and the *block-body negative* (TI-2); NV-1 re-states TI-2 as the sound pole of the family-wide dichotomy.
- `ReceiptInclusionProofSoundness.md` proves the `i:` *positive* (RI-2) and notes the negative is `UNVERIFIABLE`-only (RI-3); NV-2/NV-3 give the constructive forgery + the exact (H-neg) footing, and NV-6 promotes RI-3's observation into a caller contract.
- `StateProofCompositeKeySoundness.md` proves the daemon-side *positive* reconstruction is byte-faithful (SP-CK-1..3); NV-2 shows the daemon's *negative* path bypasses that reconstruction entirely (no leaf is served to reconstruct).
- `MerkleTreeSoundness.md` MT-5 is the single load-bearing input; this proof is, in effect, the *applied consequence* of MT-5 at the verifier-and-caller layer.
- `LightClientThreatModel.md` §6 lists single-daemon trust as a residual limitation; NV-3 names the *exact* place that limitation bites (the state-proof negative path) and NV-4 bounds its blast radius (fail-safe direction only).

Adds the negative-verdict soundness boundary that no existing proof states as its subject; reduces only to **A2** for the sound (block-body) negative and to the explicitly-named non-cryptographic premise **(H-neg)** for the unsound (state-proof) negative.
