# OfflineEquivocationEvidenceSoundness — offline `determ-light` equivocation-evidence verifier

This document formalizes the soundness of an **offline** equivocation-evidence verifier for the `determ-light.exe` light-client binary: a pure-verifier surface that, given two signed messages claimed to originate from the same registered signer at the same `(height, generation)`, and the signer's registered Ed25519 public key, decides **with no network connection and no chain state** whether the pair constitutes a valid `EquivocationEvent` under the V11 predicate. The verifier is the offline forensic dual of the daemon-side detection paths: where `S006ContribMsgEquivocation.md` (Phase-1) and the rev.8 BlockSigMsg path (Phase-2) *detect* equivocation live on the receive path, this verifier *adjudicates* an already-assembled evidence pair offline, so an auditor, a slashed operator, or a governance reviewer can independently confirm an on-chain slash was justified — or refute a fabricated accusation — without trusting any daemon.

The proof exists because the adjudication trust posture is structural, not cryptographic: it composes the V11 predicate (`Preliminaries.md` §5), Ed25519 EUF-CMA (A1), SHA-256 collision resistance (A2), and the digest-agnosticism argument of FA6 / S-006 into a four-step offline pipeline (`parse` → `recompute-pubkey-bind` → `verify-both-sigs` → `distinctness-gate`) under a **fabricating-accuser** adversary model. No new cryptographic primitive is introduced. The two security claims are (i) **soundness** — the verifier accepts an evidence pair only if it would slash the named signer under the same rules the chain applies (no over-acceptance of fabricated evidence against an honest signer), and (ii) **completeness relative to V11** — the verifier accepts exactly the pairs V11 would accept, so an offline ACCEPT is a faithful, daemon-independent predictor of the on-chain slash. The verifier never *acts* (it neither signs nor submits); its sole output is an ACCEPT/REJECT verdict with a structured diagnostic, mirroring the fail-closed posture of `LightClientThreatModel.md` §2.3.

**Companion documents.** `Preliminaries.md` (F0) §2.1 (SHA-256 collision resistance = A2) + §2.2 (Ed25519 EUF-CMA = A1) + §4 (H1/H2 honest/Byzantine signer hypotheses) + §5 (validator predicate V11); `EquivocationSlashing.md` (FA6) for the on-chain slashing-soundness theorem T-6 this verifier mirrors offline (the "honest never slashed" property the ACCEPT verdict must not violate); `S006ContribMsgEquivocation.md` for the digest-agnosticism argument (V11 checks "two distinct hashes both signed by the same registered key," indifferent to whether the hashes are `compute_block_digest`s or `make_contrib_commitment`s) the verifier inherits to handle both Phase-1 and Phase-2 evidence pairs uniformly; `EquivocationSlashingApply.md` (FA-Apply-10) for the apply-side mechanics an offline ACCEPT predicts (full forfeit + registry deactivation); `LightClientThreatModel.md` for the `determ-light` trust posture, the fail-closed-exit convention, and the citation style (multiple-theorem closure under a named adversary model); `MakeContribCommitmentBackwardCompat.md` for the v1/F2 commit-primitive determinism the Phase-1 branch's recompute step relies on.

---

## 1. Scope

The offline verifier is a **per-invocation, pure** surface: each invocation

1. reads an evidence file (the JSON serialization of an `EquivocationEvent`, or its constituent parts) and a committee/pubkey file from operator-controlled disk,
2. decides ACCEPT/REJECT against the V11 predicate using only local computation,
3. exits with a structured verdict; a zero exit code denotes ACCEPT, a non-zero exit code denotes REJECT-with-reason.

There is no network I/O, no daemon connection, no chain walk, no genesis anchor. The verifier never reads `--rpc-port`. Its only inputs are bytes on the operator's disk: the evidence pair and the registered Ed25519 public key of the named signer (supplied via a committee JSON of the form `{members: [{domain, ed_pub}, ...]}`, the same shape `light/verify.cpp::parse_committee` already consumes per `LightClientThreatModel.md` §3.2).

This sits in the `LightClientThreatModel.md` §1 taxonomy as a **pure verifier (offline file in)** subcommand — the same class as `verify-headers`, `verify-block-sigs`, `verify-state-proof`. It is *not* a composite command: it does no `anchor_genesis`, no `verify_chain_to_head`, no state-proof read. Consequently it is **not adversary-exposed at the transport layer** — there is no `A_daemon`. The relevant adversary is the *author of the evidence file* (§2).

The verifier handles **two evidence classes** under one predicate, distinguished by a `class` tag on the evidence (or inferred from which digest-recompute the operator requests):

| Evidence class | The two hashes are over | Live detection counterpart |
|---|---|---|
| Phase-2 (block-digest) | `compute_block_digest` (the rev.8 BlockSigMsg surface) | `node.cpp::apply_block_locked` cross-block check |
| Phase-1 (contrib-commit) | `make_contrib_commitment` (the S-006 surface) | `node.cpp::on_contrib` recompute-then-compare |

Per the digest-agnosticism of V11 (`S006ContribMsgEquivocation.md` §2.2), the adjudication arithmetic is **identical** across both classes — the class tag affects only *which* recompute primitive binds the pre-image (relevant when the verifier is asked to recompute a digest from raw fields rather than trust a supplied 32-byte hash; see §3.2 mode (b)).

**Out of scope (intentional).**

- **Detection.** The verifier does not *find* equivocation in a stream of messages; it adjudicates an already-assembled pair. Detection is the daemon's job (S-006 + rev.8).
- **Completeness of the chain's slashing pipeline.** Whether *every* actual equivocation eventually surfaces as a finalized event is FA4-adjacent liveness, out of scope here and in FA6 alike.
- **Committee-evolution tracking.** As in `LightClientThreatModel.md` §6.5, the verifier trusts the operator-supplied pubkey for the named signer. Whether that pubkey is the *currently-registered* key for the signer at the claimed height is the operator's responsibility (or a future stateful-sync extension). The verifier's claim is conditional on "the supplied pubkey is the signer's registered key at `block_index`" — see §2.2 `A_keymap`.
- **Cross-shard routing.** The `shard_id` / `beacon_anchor_height` forensic fields are parsed and surfaced but, per `block.hpp:264-275`, are *not consumed by validator correctness checks* — the two-sig proof is independently verifiable against the registered key regardless of where it was first observed. The verifier mirrors this: it adjudicates the cryptographic core and reports the forensic fields without gating on them (§4.5).

---

## 2. Threat model

### 2.1 Adversary capability

The adversary `A_accuser` is a **fabricating accuser** — the author of the evidence file the verifier consumes. `A_accuser` may:

- **Author arbitrary evidence JSON.** Forge `equivocator`, `block_index`, `digest_a`, `digest_b`, `sig_a`, `sig_b`, `shard_id`, `beacon_anchor_height` to any values.
- **Choose the named signer freely**, including naming an honest validator the adversary wishes to see falsely slashed.
- **Replay genuine signatures.** Harvest a real signature by an honest signer (e.g., a legitimately-broadcast `BlockSigMsg` or `ContribMsg`) and attempt to pair it with a fabricated second signature, or with a genuine-but-different-round signature.
- **Submit the same evidence repeatedly** across invocations (the verifier is stateless, so cross-invocation correlation is the operator's concern, not a soundness surface).

The adversary's **goal** is an over-acceptance: cause the verifier to emit ACCEPT for an evidence pair that names an honest signer `d` who did **not** equivocate, so that a downstream actor (operator, governance) is misled into believing `d` deserves slashing. The symmetric goal — causing a REJECT for a genuine equivocation (a false exoneration) — is the completeness concern (T-OE3).

### 2.2 Adversary capability EXPLICITLY OUT of scope

- **`A_crypto`: cryptographic adversary.** SHA-256 collision finder, Ed25519 forger. Covered by A2 (`Preliminaries.md` §2.1) + A1 (§2.2). The verifier's soundness rests on `A_crypto` being infeasible.
- **`A_keymap`: tampered committee/pubkey file.** If the adversary substitutes a pubkey they control for the named signer's *genuine* registered key, then "verify both sigs against the supplied key" becomes vacuous (the adversary signs both halves themselves). This is the offline analogue of `A_genesis` in `LightClientThreatModel.md` §2.2 — the trust anchor itself is compromised. Operator mitigates by sourcing the pubkey from a trusted committee snapshot (the same `genesis.json` / `creators` RPC path the trustless reads use). The verifier's claim is conditional on the supplied key being the signer's genuine registered key at `block_index`. See §4.2 and Finding F-1.
- **`A_local`: operator-machine compromise**, and **`A_net`: transport MITM**: identical to `LightClientThreatModel.md` §2.2 — the offline verifier has no transport at all, so `A_net` is moot, and `A_local` is OS-level operator responsibility.

### 2.3 Security goal

An **honest verifier** is one that runs the released binary unmodified, sources the named signer's genuine registered Ed25519 key into the committee/pubkey file, and does not bypass its own checks. The two claims:

- **Soundness (T-OE1).** Under A1, an honest verifier emits ACCEPT only for evidence pairs that constitute a genuine equivocation by the named signer. Equivalently: an honest signer (per H1, who signs at most one message per `(height, generation)`) is never the subject of an ACCEPT verdict, except with probability `≤ 2⁻¹²⁸` per fabrication attempt. This is the offline mirror of FA6 T-6.
- **Completeness relative to V11 (T-OE3).** The verifier emits ACCEPT for exactly the evidence pairs the chain's V11 predicate would accept (and hence would slash on apply). An offline ACCEPT is therefore a daemon-independent, faithful predictor of the on-chain slash; an offline REJECT guarantees the chain would not slash on this evidence.

The negation form (fail-closed): any input the verifier cannot positively adjudicate as a valid equivocation causes a REJECT with a structured diagnostic and a non-zero exit code. There is no "trust the evidence file" downgrade path.

---

## 3. The verifier pipeline

The verifier composes four steps over the operator's evidence + pubkey inputs. The steps mirror the V11 predicate (`Preliminaries.md` §5; implemented at `src/node/validator.cpp::check_equivocation_events`) restricted to a single event, evaluated offline.

### 3.1 Step 1 — parse + structural gate

Parse the evidence JSON into a typed `EquivocationEvent` via the same `EquivocationEvent::from_json` the chain uses (`include/determ/chain/block.hpp:278`), using the `json_require<T>` S-018 validators for type-strictness. Reject on:

- Missing or mistyped required fields (`equivocator`, `block_index`, `digest_a`, `digest_b`, `sig_a`, `sig_b`).
- Either digest not exactly 32 bytes (64 hex) or either signature not exactly 64 bytes (128 hex).
- `equivocator` not present in the supplied committee/pubkey map (no key to verify against ⇒ unadjudicable ⇒ REJECT, mirroring `verify_block_sigs`'s "creator not in supplied committee" fail-closed branch at `light/verify.cpp:268-273`).

### 3.2 Step 2 — pubkey binding (two modes)

Look up `pk := pubkey_of[ev.equivocator]` from the committee/pubkey map. The verifier supports two operating modes that differ only in how the two hashes-to-be-verified are obtained:

- **(a) Hash-trusting mode** (default; matches the on-chain `EquivocationEvent` payload exactly). The two 32-byte hashes `ev.digest_a`, `ev.digest_b` are taken verbatim from the evidence. This is the mode that adjudicates an *already-baked* on-chain event byte-for-byte — the chain itself stores only the hashes, not the pre-images (`block.hpp:256-262`), so an auditor re-checking a finalized slash uses this mode.
- **(b) Pre-image-recomputing mode** (forensic; for raw-message evidence). The evidence carries the *full* Phase-1 `ContribMsg` fields or Phase-2 `Block` header fields, and the verifier recomputes each digest locally — `make_contrib_commitment(block_index, prev_hash, tx_hashes, dh_input, view_eq_root, view_abort_root, view_inbound_root)` for the Phase-1 class, or `light_compute_block_digest(b)` (the byte-for-byte producer copy at `light/verify.cpp:57-92`) for the Phase-2 class. This mode lets an operator who holds two *raw* conflicting messages (rather than a pre-assembled event) verify them, and is the offline analogue of the `on_contrib` recompute step (`S006ContribMsgEquivocation.md` §3.1). The recompute primitives are deterministic (`MakeContribCommitmentBackwardCompat.md` L-2; `LightClientThreatModel.md` L-2 for the block-digest copy), so mode (b) on a genuine pair yields the same two hashes the signer signed.

Both modes converge on the same downstream adjudication: two 32-byte hashes `h_a`, `h_b` and two 64-byte signatures `σ_a`, `σ_b`, all to be checked against the single key `pk`.

### 3.3 Step 3 — dual signature verification

Verify both signatures against the named signer's key under the same Ed25519 primitive the chain uses (`crypto::verify`, OpenSSL `EVP_DigestVerify` over the raw 32-byte hash, matching `validator.cpp::check_equivocation_events`):

```
Verify(pk, h_a, σ_a) == 1   AND   Verify(pk, h_b, σ_b) == 1
```

Either verify failing ⇒ REJECT (`signature does not verify under the named signer's key`). This is the load-bearing cryptographic step: it binds *both* halves of the evidence to `pk` under A1.

### 3.4 Step 4 — distinctness + same-target gate

Apply the V11 non-triviality gates:

- **Digest distinctness:** `h_a ≠ h_b`. Equal digests are not equivocation (the signer signed one thing, possibly replayed). REJECT on equality (`identical digests — not equivocation`). This is the V11 `digest_a != digest_b` clause.
- **Signature distinctness:** `σ_a ≠ σ_b`. Under RFC 8032, distinct messages yield distinct deterministic signatures; equal signatures over claimed-distinct digests is a malformed pair. REJECT on equality (`identical signatures`). This is the V11 `sig_a != sig_b` clause.
- **Same-target binding:** the two hashes pertain to the same `block_index` (and, in mode (b) Phase-1, the same `(prev_hash, aborts_gen)` generation). In hash-trusting mode (a) this is implicit — a single `EquivocationEvent` carries one `block_index` for both halves (`block.hpp:258`). In recompute mode (b) the verifier checks that both raw messages declare the same `(block_index)` [and `(prev_hash, aborts_gen)` for Phase-1] before recomputing, REJECT-ing a cross-target pair (`messages target different (height,generation) — legitimate distinct signing, not equivocation`). This is the gate that prevents a genuine cross-round signature pair from being mis-adjudicated as equivocation (the Subcase b.2 / T-2 concern of FA6 / S-006, handled offline).

On passing all four steps the verifier emits **ACCEPT** with a verdict record: `{equivocator, block_index, class, digest_a, digest_b, would_slash: true}`.

### 3.5 Pipeline composition diagram

```
operator's --evidence <file>          operator's --committee <file>
            │                                     │
            ▼                                     ▼
  ┌─────────────────────────┐           ┌────────────────────────┐
  │ EquivocationEvent       │           │ parse_committee         │
  │ ::from_json (S-018)     │           │ domain → PubKey map     │
  └────────────┬────────────┘           └───────────┬────────────┘
               │ structural gate (Step 1)           │
               └───────────────┬────────────────────┘
                               ▼
                   ┌─────────────────────────┐
                   │  pubkey binding         │  Step 2 / T-OE0
                   │  pk = pubkey_of[equiv]  │  (mode a: trust hashes;
                   │  + optional recompute   │   mode b: recompute digest)
                   └────────────┬────────────┘
                                │ key found → continue; absent → REJECT
                                ▼
                   ┌─────────────────────────┐
                   │  dual sig verify        │  Step 3 / T-OE1 core
                   │  Verify(pk,h_a,σ_a)=1   │  (A1 binding, both halves)
                   │  Verify(pk,h_b,σ_b)=1   │
                   └────────────┬────────────┘
                                │ both ok → continue; either fails → REJECT
                                ▼
                   ┌─────────────────────────┐
                   │  distinctness + target  │  Step 4 / T-OE2
                   │  h_a ≠ h_b, σ_a ≠ σ_b   │  (V11 non-triviality)
                   │  same (height,gen)      │
                   └────────────┬────────────┘
                                │ all gates pass → ACCEPT; any fails → REJECT
                                ▼
                         ┌──────────────┐
                         │  verdict      │  ACCEPT ⇒ exit 0
                         │  {would_slash}│  REJECT ⇒ exit ≠0 + diagnostic
                         └──────────────┘
```

Each step depends on every upstream step having passed. The pipeline is a total function from `(evidence, pubkey-map)` to a verdict; there is no input on which it loops, blocks, or trusts unverified data.

---

## 4. Security theorems

Throughout, fix a named signer `d := ev.equivocator`, its supplied key `pk := pubkey_of[d]`, the two hashes `h_a, h_b`, and the two signatures `σ_a, σ_b`. Let `V11(d, h_a, σ_a, h_b, σ_b, pk)` denote the chain's per-event validator predicate (`Preliminaries.md` §5):

```
V11 ≡  Verify(pk, h_a, σ_a) ∧ Verify(pk, h_b, σ_b) ∧ (h_a ≠ h_b) ∧ (σ_a ≠ σ_b) ∧ registered(d)
```

### 4.1 Theorem T-OE0 (parse determinism + total adjudicability)

**Statement.** For every byte-string evidence input `E` and every committee/pubkey file `C`, the verifier reaches exactly one of {ACCEPT, REJECT-with-reason} in finite time, with no third "indeterminate" outcome and no unbounded loop. The outcome is a deterministic function of `(E, C)`.

**Proof.** Step 1 either parses `E` into a well-typed `EquivocationEvent` (via `from_json` + S-018 `json_require<T>`, which throw on type mismatch and are caught by the dispatcher into a REJECT) or REJECTs. Given a parse, Step 2's map lookup is total: either `d ∈ pubkey_of` (continue) or not (REJECT). Step 3 invokes `crypto::verify` twice — each call is a finite Ed25519 verification returning a boolean. Step 4 is three constant-time comparisons (two 32-byte/64-byte `memcmp`, one integer compare on `block_index`). No step reads external state or loops over unbounded input (the evidence carries exactly two digests and two signatures; in recompute mode (b) the per-message field set is bounded by the S-022 per-MsgType body cap, `S022WireFormatCaps.md` T-1). The composition is a finite deterministic decision procedure. ∎

This is the offline analogue of `LightClientThreatModel.md` L-6 (fail-closed exit): there is no silent-accept path and no indeterminate state.

### 4.2 Theorem T-OE1 (soundness — no false ACCEPT against an honest signer)

**Statement.** Under (A1) Ed25519 EUF-CMA, and conditional on the supplied `pk` being `d`'s genuine registered key (i.e., `¬A_keymap`), if `d` is honest (H1 — `d` signs at most one message per `(block_index, generation)` tuple), then the verifier emits ACCEPT on `A_accuser`'s evidence with probability `≤ 2⁻¹²⁸` per fabrication attempt.

**Adversary game.**

1. Setup. Honest signer `d` has registered key `pk` with secret `sk` known only to `d`. The verifier is given `pk` for `d` (¬A_keymap).
2. `A_accuser` authors an evidence pair `(h_a, σ_a, h_b, σ_b)` naming `d`, with `h_a ≠ h_b`, attempting to make both sigs verify under `pk`.
3. `A_accuser` wins if the verifier emits ACCEPT.

**Proof.** ACCEPT requires (Step 3) both `Verify(pk, h_a, σ_a) = 1` and `Verify(pk, h_b, σ_b) = 1`, and (Step 4) `h_a ≠ h_b`. Since `d` is honest under H1, `d` signed at most one message at `(block_index, generation)`. So at least one of `h_a, h_b` is a hash `d` did **not** sign (because `h_a ≠ h_b` forces the two to be distinct, and an honest `d` produced at most one signature here). For the unsigned hash `h_x ∈ {h_a, h_b}`, the corresponding `σ_x` with `Verify(pk, h_x, σ_x) = 1` is a valid Ed25519 signature by `pk` over a message `d` never signed — an existential forgery. By A1 (EUF-CMA, `Preliminaries.md` §2.2), `A_accuser` produces such a `σ_x` with probability `≤ 2⁻¹²⁸` per attempt.

The only way to ACCEPT *without* a forgery is for both `σ_a, σ_b` to be genuine signatures by `d`. But under H1 a genuine same-`(height,generation)` pair would require `d` to have signed two distinct messages there — contradicting H1's honesty. So a genuine-pair ACCEPT against an honest `d` is impossible by hypothesis; the residual ACCEPT probability is exactly the forgery probability `≤ 2⁻¹²⁸`. ∎

**Concrete-security bound.** `Pr[A_accuser wins T-OE1] ≤ 2⁻¹²⁸` per attempt; over `Q` attempts, `≤ Q · 2⁻¹²⁸`. For `Q = 2⁶⁰`, cumulative `≤ 2⁻⁶⁸`, strongly negligible — identical to FA6 T-6's bound, as it must be, since the verifier evaluates the same predicate.

**Relationship to FA6 T-6.** FA6 proves that an honest validator is never named in a *finalized* `EquivocationEvent`. T-OE1 proves the offline verifier inherits exactly that property: an honest signer is never the subject of an offline ACCEPT. The two are the same statement evaluated at two sites — the chain's apply gate (FA6) and the operator's offline forensic check (T-OE1). An auditor who runs the offline verifier on a finalized event and gets ACCEPT learns nothing FA6 didn't already guarantee; the value is that they learn it *without trusting the chain that applied it*.

### 4.3 Theorem T-OE2 (non-triviality — replays and self-pairs rejected)

**Statement.** The verifier REJECTs every evidence pair that is not a genuine equivocation by construction, independent of any cryptographic assumption, in the following degenerate cases: (i) `h_a == h_b` (digest replay); (ii) `σ_a == σ_b` (signature replay); (iii) the two messages target different `(height, generation)` in recompute mode (b).

**Proof.** Direct from Step 4. Case (i): the `h_a ≠ h_b` gate fails ⇒ REJECT (`identical digests — not equivocation`). This is the V11 `digest_a != digest_b` clause, and it is what makes an honest signer's *legitimate retry* of the same message (RFC 8032 deterministic signatures yield a bit-identical `(h, σ)` on retry) a non-event: a byte-identical retry has `h_a == h_b` and is rejected. Case (ii): the `σ_a ≠ σ_b` gate fails ⇒ REJECT. Note that under RFC 8032 a genuine pair with `h_a ≠ h_b` *necessarily* has `σ_a ≠ σ_b` (distinct messages ⇒ distinct deterministic nonces ⇒ distinct signatures with overwhelming probability), so `σ_a == σ_b` together with `h_a ≠ h_b` is itself a malformed pair the gate catches. Case (iii): the same-target check in mode (b) fails ⇒ REJECT. A signer who legitimately aborts at generation `g` and re-signs at generation `g+1` produces two genuine messages at *different* targets; these are not equivocation (FA6 Subcase b.2, S-006 T-2), and the cross-target REJECT prevents adjudicating them as such. ∎

T-OE2 is the offline guard against the two ways a *genuine* honest action could be mistaken for equivocation: byte-identical retry (caught by (i)) and cross-generation retry (caught by (iii)). It complements T-OE1: T-OE1 closes the *forgery* path (fabricated second signature), T-OE2 closes the *harvest* path (genuine-but-non-conflicting signatures repurposed as a fake pair).

### 4.4 Theorem T-OE3 (completeness relative to V11 — faithful slash predictor)

**Statement.** In hash-trusting mode (a), the verifier emits ACCEPT if and only if `V11(d, h_a, σ_a, h_b, σ_b, pk)` holds. Consequently, an offline ACCEPT predicts that the chain *would* slash `d` on this evidence (FA-Apply-10 T-E1: full forfeit + registry deactivation), and an offline REJECT guarantees the chain *would not* slash on this evidence.

**Proof.** The verifier's ACCEPT condition is the conjunction of Step 3 (`Verify(pk,h_a,σ_a) ∧ Verify(pk,h_b,σ_b)`) and Step 4 (`h_a ≠ h_b ∧ σ_a ≠ σ_b`), with Step 1 establishing `registered(d)` (the `d ∈ pubkey_of` gate is the offline stand-in for the chain's registry lookup; conditional on ¬A_keymap the supplied map reflects the registry). This conjunction is exactly the V11 predicate restated above. So `ACCEPT ⟺ V11`.

By FA6 / S-006, the chain bakes an `EquivocationEvent` only when V11 holds (`validator.cpp::check_equivocation_events` gates the block), and by FA-Apply-10 T-E1 the apply path slashes `d` on every V11-passing baked event. Therefore `ACCEPT ⟹ (chain would slash d)`. Conversely `REJECT ⟹ ¬V11 ⟹ (chain would reject the event at validate-time) ⟹ (no slash)`. The verifier is a faithful, daemon-independent oracle for the on-chain slash decision. ∎

**Caveat (mode (b) vs mode (a)).** Completeness is stated for hash-trusting mode (a), which adjudicates the exact bytes the chain stores. In recompute mode (b), the verifier additionally re-derives the digests from raw fields; if the operator's raw-field encoding diverges from the producer's (e.g., a stale `make_contrib_commitment` ordering), mode (b) could recompute a digest that does not match what the signer actually signed, yielding a *false REJECT* (never a false ACCEPT — a wrong recompute only makes a genuine signature fail to verify, never makes a forgery succeed). So mode (b) is sound (T-OE1 holds) but its completeness is conditional on the recompute primitive being byte-faithful to the producer (the `MakeContribCommitmentBackwardCompat.md` L-2 / `LightClientThreatModel.md` L-2 "keep in sync" invariant). Mode (a) is the canonical completeness mode; mode (b) is the forensic convenience whose completeness rests on the same digest-copy discipline the rest of `determ-light` relies on.

### 4.5 Theorem T-OE4 (forensic-field independence)

**Statement.** The verdict (ACCEPT/REJECT) is invariant under any value of the forensic fields `shard_id` and `beacon_anchor_height`. Two evidence inputs that agree on `(equivocator, block_index, digest_a, sig_a, digest_b, sig_b)` but differ arbitrarily on `(shard_id, beacon_anchor_height)` receive the same verdict.

**Proof.** Steps 1–4 read `shard_id` and `beacon_anchor_height` only for inclusion in the surfaced verdict record; no gate branches on their values. This mirrors the on-chain `block.hpp:264-275` design note: the cross-chain provenance fields are forensic and "not consumed by validator correctness checks (the two-sig proof is independently verifiable against the equivocator's beacon-registered Ed25519 key, regardless of where it was first observed)." The verifier therefore adjudicates the cryptographic core identically for single-chain and shard-detected evidence, and reports the provenance without trusting it. ∎

T-OE4 is what makes the offline verifier usable for *cross-shard* slashing forensics (FA6 Corollary T-6.1): an auditor on shard `S_Y` can adjudicate evidence first observed on shard `S_X` using only `S_X`'s signer key, with no beacon round-trip — the `shard_id`/`beacon_anchor_height` fields document where it came from but do not gate the verdict.

---

## 5. Composition with FA-series theorems

### 5.1 FA6 (EquivocationSlashing) — same predicate, two sites

T-OE1 + T-OE3 are FA6's soundness (T-6) and the V11 predicate evaluated **offline** instead of at the chain's apply gate. The verifier introduces no new cryptographic claim: it is FA6's two-sig check, lifted out of the daemon, with the registry lookup replaced by an operator-supplied committee map (conditional on ¬A_keymap). The offline ACCEPT is sound *because* FA6's underlying EUF-CMA reduction is sound; the offline verifier is a re-hosting of that reduction at the auditor's machine.

**Composition statement.** `OfflineEquivocationEvidence ⊑ FA6` — the offline verifier's soundness is a restriction of FA6 T-6 to a single event under an operator-supplied key.

### 5.2 S-006 (ContribMsgEquivocation) — digest-agnosticism makes one verifier handle both classes

The verifier handles Phase-1 (contrib-commit) and Phase-2 (block-digest) evidence under one predicate precisely because V11 is digest-agnostic (`S006ContribMsgEquivocation.md` §2.2): it checks "two distinct hashes both signed by the same registered key," indifferent to what the hashes are over. The class tag (§1) selects the recompute primitive in mode (b) but does not change the adjudication arithmetic. S-006's T-2 (cross-generation no-false-positive) is mirrored offline by T-OE2 case (iii).

**Composition statement.** The offline verifier inherits S-006's two-surface coverage: a single offline tool adjudicates evidence from either detection path.

### 5.3 FA-Apply-10 (EquivocationSlashingApply) — what an ACCEPT predicts

T-OE3 ties the offline ACCEPT to FA-Apply-10 T-E1 (full forfeit) + T-E2 (registry deactivation): an offline ACCEPT predicts exactly those apply-side deltas. The verifier does not *perform* the slash (it never touches chain state); it predicts it. The prediction is faithful because ACCEPT ⟺ V11 and the chain slashes on every V11-passing event.

**Composition statement.** T-OE3 + FA-Apply-10 give the operator a pre-image of the slash: "if this evidence reaches a producer, `d` loses its entire locked stake and is deactivated next block."

### 5.4 LightClientThreatModel — same fail-closed posture, no daemon adversary

The offline verifier is a new **pure verifier (offline file in)** subcommand in the `LightClientThreatModel.md` §1 taxonomy. It inherits the fail-closed-exit convention (L-6) — every non-adjudicable input REJECTs with a structured diagnostic. It differs from the composite trustless reads in that it has **no `A_daemon`** (no network), so the relevant adversary is `A_accuser` (the evidence author), not a malicious daemon. T-OE0's total-adjudicability is the offline analogue of L-6.

**Composition statement.** The offline verifier extends `determ-light`'s pure-verifier surface to equivocation forensics without weakening any LightClientThreatModel claim and without adding a network adversary surface.

---

## 6. Known limitations

### 6.1 Operator-supplied key is the trust anchor (A_keymap)

T-OE1 + T-OE3 are conditional on the supplied `pk` being `d`'s genuine registered key. If the operator sources a wrong key, soundness degrades to vacuity (the verifier checks sigs against the wrong key — a forged pair under the wrong key would ACCEPT, but slashing the chain would not honor it because the chain uses the *real* registry key). The operator mitigates by sourcing the committee map from the same trusted path the trustless reads use (`genesis.json` `initial_creators` or a committee snapshot anchored via `LightClientThreatModel.md` T-L2). This is the exact analogue of `A_genesis` in the trustless-read model. See Finding F-1.

### 6.2 No registry-height awareness

The verifier checks `d ∈ pubkey_of`; it does not verify that `d` was *registered and active* at `block_index` (the chain's V11 does this against its live registry). A signer who DEREGISTERed before `block_index`, or registered after, would be adjudicated against whatever key the operator supplied. For the canonical use (auditing a finalized on-chain event whose `block_index` the chain already validated), this gap is closed by the chain having already gated the event; for *novel* offline evidence the operator must ensure the key matches the signer's registration at the claimed height. A future stateful-sync extension (tracking REGISTER/DEREGISTER) would close this, matching the `LightClientThreatModel.md` §6.5 committee-evolution limitation.

### 6.3 No detection, only adjudication

The verifier does not scan a message stream for equivocation; it adjudicates a pre-assembled pair. An operator wanting to *find* equivocation in raw gossip captures must first pair conflicting messages by `(signer, height, generation)` themselves, then feed each candidate pair to the verifier. Detection remains the daemon's S-006 + rev.8 job.

### 6.4 Mode (b) completeness rests on digest-copy fidelity

As in T-OE3's caveat, recompute mode (b)'s completeness depends on the local `make_contrib_commitment` / `light_compute_block_digest` copies being byte-faithful to the producer. A divergence yields false REJECTs (never false ACCEPTs). Mode (a) is the canonical mode and is unconditionally complete relative to V11.

---

## 7. Findings register

### F-1 Committee/pubkey map is the sole trust anchor

**Surface.** Step 2 (§3.2) trusts the operator-supplied `pubkey_of[d]`. A tampered map (`A_keymap`) makes both-sig-verify vacuous.

**Soundness impact.** T-OE1 + T-OE3 hold conditional on ¬A_keymap. With a tampered map, the offline verdict no longer predicts the on-chain slash (the chain uses the real registry key).

**Mitigation.** Source the committee map from a trusted committee snapshot (the same path `build_genesis_committee` / a `creators` RPC uses). Operator-visible; clean fail-closed exit if `d` is absent from the map.

### F-2 Hash-trusting mode (a) cannot detect a pre-image lie

**Surface.** In mode (a), the verifier trusts that `digest_a`/`digest_b` are over genuine protocol messages (it checks sigs over the hashes, not what the hashes are *over*).

**Soundness impact.** None for the slash-prediction claim — the chain also stores only the hashes and slashes on the two-sig proof over them (`block.hpp:256-262`). If a signer genuinely signed two distinct 32-byte values at the same target, that *is* equivocation by the protocol's definition, regardless of what the values pre-image to. The "what the hash is over" question is a mode-(b) forensic enrichment, not a soundness gap.

**Mitigation.** None needed; mode (a) faithfully mirrors the chain. Mode (b) is available when pre-image inspection is desired.

### F-3 Cross-invocation correlation is operator's responsibility

**Surface.** The verifier is stateless; it adjudicates one pair per invocation.

**Soundness impact.** None per-invocation. An operator re-adjudicating the same genuine evidence repeatedly always gets the same ACCEPT (T-OE0 determinism).

**Mitigation.** Operator-level; not a soundness concern.

---

## 8. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to the surfaces the verifier mirrors.

| Theorem | Mirrors / depends on | File:lines | Role |
|---|---|---|---|
| T-OE0 | `EquivocationEvent::from_json` + S-018 `json_require<T>` | `include/determ/chain/block.hpp:277-278` | Parse + structural gate (total, deterministic). |
| T-OE0 | `parse_committee` | `light/verify.cpp:102-133` | domain → PubKey map; absent-signer REJECT. |
| T-OE1 | `crypto::verify` (Ed25519) | `src/node/validator.cpp::check_equivocation_events` | Dual signature verify under the named key (the A1-binding core). |
| T-OE1 | V11 predicate | `Preliminaries.md` §5 | The predicate the verifier evaluates offline. |
| T-OE2 | digest/sig distinctness | `validator.cpp::check_equivocation_events` (`digest_a != digest_b`, `sig_a != sig_b`) | Non-triviality gate (replay + self-pair REJECT). |
| T-OE2 | cross-generation REJECT | `S006ContribMsgEquivocation.md` T-2 | Cross-target pair is not equivocation. |
| T-OE3 | V11 ⟺ ACCEPT; slash prediction | `EquivocationSlashingApply.md` T-E1/T-E2 | What an ACCEPT predicts (full forfeit + deactivation). |
| T-OE3 (mode b) | recompute primitives | `light/verify.cpp:57-92` (`light_compute_block_digest`); `src/node/producer.cpp::make_contrib_commitment` | Byte-faithful digest recompute. |
| T-OE4 | forensic-field independence | `include/determ/chain/block.hpp:264-275` | `shard_id`/`beacon_anchor_height` not consumed by correctness checks. |

The verifier reuses, without modification, the `EquivocationEvent` struct, the `parse_committee` pubkey-map loader, the `crypto::verify` primitive, and (in mode b) the `light_compute_block_digest` / `make_contrib_commitment` recompute copies — no new wire format, no new cryptographic primitive. The offline verifier is the V11 predicate re-hosted at the auditor's machine.

Suggested integration tests (one per theorem family), should the Lane-C verifier subcommand land:

| Test script | Theorem coverage |
|---|---|
| `tools/test_light_verify_equivocation.sh` | T-OE1 — genuine two-sig pair → ACCEPT; fabricated second sig under honest key → REJECT. |
| (same) | T-OE2 — identical digests → REJECT; cross-generation pair → REJECT. |
| (same) | T-OE3 — ACCEPT verdict matches `determ test-equivocation-apply`'s would-slash outcome on the same pair. |
| (same) | T-OE4 — verdict invariant under `shard_id`/`beacon_anchor_height` perturbation. |

These are *suggested* surfaces for the Lane-C verifier owner; this proof's correctness rests on §3's pipeline + §4's theorems and does not depend on a test existing.

---

## 9. Status

- **Spec.** Complete (this document).
- **Implementation.** The offline verifier subcommand is a Lane-C `determ-light` surface (owned separately); this document is the soundness proof that surface must satisfy. The verifier reuses existing primitives (`EquivocationEvent::from_json`, `parse_committee`, `crypto::verify`, the digest-recompute copies) — no new cryptographic primitive.
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA) for T-OE1; A2 (SHA-256 collision resistance) transitively for the digest-distinctness ⇒ message-distinctness step and for mode-(b) recompute determinism; H1 (honest-signer single-message) for the soundness reduction. A3/A4 are not invoked.
- **Adversary model.** `A_accuser` (fabricating evidence author). Explicitly out of scope: `A_crypto`, `A_keymap`, `A_local`, `A_net` (no transport at all — pure offline).
- **Composes with.** FA6 (same predicate, offline site), S-006 (digest-agnostic two-class coverage), FA-Apply-10 (slash prediction), LightClientThreatModel (pure-verifier fail-closed posture). Introduces no new chain-level invariant.
- **Theorems.** T-OE0 (total adjudicability), T-OE1 (soundness — no false ACCEPT against honest, `≤ 2⁻¹²⁸`/attempt), T-OE2 (non-triviality — replays/self-pairs/cross-target REJECT), T-OE3 (completeness relative to V11 — faithful slash predictor), T-OE4 (forensic-field independence). All closed against the cited surfaces.
- **Concrete-security bound.** `Pr[false ACCEPT against honest d] ≤ 2⁻¹²⁸` per attempt; `≤ Q · 2⁻¹²⁸` over `Q` attempts — identical to FA6 T-6, as the verifier evaluates the same predicate. Under Grover (PQ), the bound degrades to `≤ Q · 2⁻⁶⁴` for Ed25519, still negligible for any operational `Q`; PQ-signature migration is the long-term path (`Preliminaries.md` §2.2 note).

---
