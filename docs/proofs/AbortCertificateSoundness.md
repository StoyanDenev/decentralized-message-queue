# FA-Cert — Abort-certificate quorum-verification soundness (V10)

This document proves that Determ's **abort-certificate verification gate** — `BlockValidator::check_abort_certs` at `src/node/validator.cpp:172–298`, the implementation of validity predicate V10 (Preliminaries §5) — produces no false suspension-slash accusations: a finalized `AbortEvent` can name `aborting_node = d` only when (a) `d` was genuinely selected into the at-event committee under the same deterministic committee re-derivation the producer used, and (b) `M−1` **distinct, registered** committee peers each signed an Ed25519 `AbortClaimMsg` over the canonical `(block_index, round, prev_hash, missing_creator = d)` tuple. Under EUF-CMA, a producer cannot fabricate that quorum against an honest validator without forging at least one honest peer's signature.

This is the verification-side counterpart to FA6 (`EquivocationSlashing.md`), which proves cryptographic soundness of the **equivocation** accusation channel. FA-Cert proves the parallel property for the **abort** accusation channel, closing the dependency that `AbortEventApply.md` (FA-Apply-11 §4, "What this doesn't prove") explicitly defers: FA-Apply-11 T-A1 presumes the `AbortEvent` was already admitted by V10; FA-Cert is the proof that V10's admission is sound. The two together — V10 soundness (FA-Cert) + apply-side proportional slash mechanics (FA-Apply-11) — close the abort-channel slashing loop the same way FA6 + FA-Apply-10 close the equivocation-channel loop.

The argument has two halves, mirroring the two on-chain bindings the certificate carries:

1. **Committee-membership binding.** The validator re-derives the at-event committee from the same epoch-relative seed, region filter, exclusion set, and `event_hash` fold the producer used (`select_m_creators` over `rand = SHA256(rand ‖ ae.event_hash)`), and rejects any `AbortEvent` whose `aborting_node` is not in the re-derived set. An honest `d` who was never selected cannot be slashed because no producer can name them.
2. **Quorum-signature binding.** Each of the `M−1` `AbortClaimMsg`s must carry a distinct registered claimer, must match the event's `(block_index, round, prev_hash, missing_creator)` exactly, and must verify under the claimer's registered Ed25519 key. Forging this quorum against honest `d` requires forging an honest claimer's signature (EUF-CMA, `≤ 2⁻¹²⁸` per attempt).

**Companion documents:** `Preliminaries.md` (F0) for notation, the V10 abort-certificate predicate, V3 creator-selection, and the assumptions (A1 EUF-CMA, A2 SHA-256 collision-resistance, A3 CSPRNG uniformity, H1–H4 honest behavior); `EquivocationSlashing.md` (FA6) for the analogous **equivocation**-channel soundness theorem (the structural template this proof mirrors); `AbortEventApply.md` (FA-Apply-11) for the apply-side proportional-slash mechanics (T-A1..T-A8) that fire conditional on FA-Cert's admission soundness — FA-Apply-11 §4 names V10 soundness as out of its scope, and FA-Cert closes exactly that; `SelectiveAbort.md` (FA5) for the abort-defense randomness story and the BFT escalation gate that sets the per-event committee size; `S020CommitteeSelection.md` (S-020) for the `select_m_creators` hybrid Fisher-Yates / rejection-sampling soundness this proof reuses unchanged in the at-event re-derivation; `StakeForfeitureCascade.md` (FA-Apply-16) for the cascade interaction between abort-slash and equivocation-slash on the same offender; `docs/SECURITY.md` §S-013 for the per-signer cap that bounds the evidence pool the abort/equivocation certificates draw from.

---

## 1. Setup

### 1.1 The `AbortEvent` and `AbortClaimMsg` structs

Per `include/determ/chain/block.hpp:228–237`:

```cpp
struct AbortEvent {
    uint8_t     round{0};            // 1 (Phase-1, commit) or 2 (Phase-2, reveal)
    std::string aborting_node;       // the missing_creator the M-1 claims agree on
    int64_t     timestamp{0};        // first quorum claim's timestamp
    Hash        event_hash{};        // SHA256(round ‖ aborting_node ‖ timestamp ‖ random_state)
    nlohmann::json claims_json;      // inline array of M-1 signed AbortClaimMsg JSON objects
};
```

Per `include/determ/node/producer.hpp:67–82`:

```cpp
struct AbortClaimMsg {
    uint64_t    block_index{0};
    uint8_t     round{0};            // 1 = CONTRIB phase, 2 = BLOCK_SIG phase
    Hash        prev_hash{};
    std::string missing_creator;
    std::string claimer;
    Signature   ed_sig{};            // Ed25519 over the abort_claim_message digest
};

Hash make_abort_claim_message(uint64_t block_index, uint8_t round,
                               const Hash& prev_hash,
                               const std::string& missing_creator);
```

The `event_hash` is the chain's deterministic fingerprint of the abort; it feeds the committee re-derivation fold (§1.3) so the post-abort committee is bound to the same evidence the validator independently recomputes. The `claims_json` array is the **certificate** — the `M−1` peer attestations that authorize the slash named by `aborting_node`.

Let `claim_digest(m) := make_abort_claim_message(m.block_index, m.round, m.prev_hash, m.missing_creator)` denote the canonical domain-separated digest each `AbortClaimMsg`'s `ed_sig` covers. Note `claim_digest` is a pure function of `(block_index, round, prev_hash, missing_creator)` — it does **not** include `claimer`, so a single claimer cannot reuse another claimer's signature unless their registered keys coincide (impossible: registry domains are unique).

### 1.2 The V10 verification gate

Per `src/node/validator.cpp:172–298`, `check_abort_certs(b, chain, registry)` performs, for each `ae ∈ b.abort_events` in iteration order:

1. **At-event committee re-derivation** (lines 224–249). Build the available pool `avail` = `registry.eligible_in_region(committee_region_)` (plus R4 refugee extension) minus the domains excluded by **preceding** aborts in the same block. Compute the per-event committee size `m_at_event` under the same BFT-escalation rule as `node.cpp::check_if_selected` (`k_full` normally; `k_bft = ⌈2·k_full/3⌉` when `avail < k_full ∧ bft_enabled ∧ i ≥ bft_escalation_threshold ∧ avail ≥ k_bft`). Draw `select_m_creators(rand, avail.size(), m_at_event)` and map indices to domains.
2. **Membership check** (lines 251–255). Reject unless `ae.aborting_node ∈ domains_at_event`.
3. **Quorum-count check** (lines 257–264). Reject unless `claims_json` is an array of exactly `M−1 = domains_at_event.size() − 1` entries.
4. **Per-claim binding + signature check** (lines 266–290). For each claim `m`: reject on any of `block_index ≠ b.index`, `round ≠ ae.round`, `prev_hash ≠ chain.head_hash()`, `missing_creator ≠ ae.aborting_node`, `claimer == missing_creator`, `claimer ∉ domains_at_event`, duplicate `claimer` (a `std::set seen_claimers` enforces distinctness), `claimer ∉ registry`, or `Verify(registry.find(claimer).pubkey, claim_digest(m), m.ed_sig) = 0`.
5. **Advance fold** (lines 292–294). `excluded.insert(ae.aborting_node)` and `rand := SHA256(rand ‖ ae.event_hash)`, so the next event's committee re-derivation sees the same exclusion + remix the producer used.

The function returns `{true, ""}` only if every event clears all five steps; the first failure returns `{false, diagnostic}` and the block is rejected.

### 1.3 The committee-re-derivation seed chain

Per `validator.cpp:186–223`, the seed the validator feeds to `select_m_creators` is derived identically to `check_creator_selection` (V3):

```
epoch_index = epoch_blocks_ ? (b.index / epoch_blocks_) : 0
epoch_start = epoch_index * max(epoch_blocks_, 1)
epoch_rand  = resolve_epoch_rand(epoch_start, chain)
prev_rand   = epoch_committee_seed(epoch_rand, shard_id_)
rand        = prev_rand   // then folded once per preceding abort:
                          //   rand := SHA256(rand ‖ ae[j].event_hash) for j < i
```

This is the same seed pipeline V3 uses for the canonical committee, so the at-event re-derivation in V10 is **forced to agree** with the V3 committee the block already committed to. Any divergence between the validator's `prev_rand` and the producer's would surface first as a V3 `creator[i] mismatch` rejection before V10 is reached; V10's re-derivation is therefore consistent-by-construction with V3 (this is the load-bearing observation for T-C2 below).

---

## 2. Theorems

Throughout, fix a block `B` at height `h = b.index` with `prev_hash = chain.head_hash()`, and let `d ∈ V \ F` denote an **honest** validator (one that obeys H1–H4: in particular, an honest claimer signs at most one `AbortClaimMsg` per `(block_index, round, missing_creator)` tuple, and only when it genuinely observed `missing_creator` fail to contribute at that round).

### T-C1 — Membership soundness (honest non-member is never named)

**Statement.** If `d` was **not** in the at-event committee `domains_at_event` that the deterministic re-derivation produces for some `ae ∈ B.abort_events` (i.e., `d ∉ select_m_creators(rand, avail, m_at_event)` mapped to domains), then no block naming `ae.aborting_node = d` passes V10. Consequently `d` cannot be suspension-slashed by FA-Apply-11 T-A1 for that event.

*Proof.* By the membership check at `validator.cpp:251–255`: the validator computes `domains_at_event` from the deterministic draw and rejects with `aborting_node not in selected set` unless `ae.aborting_node ∈ domains_at_event`. The draw is a pure deterministic function of `(rand, avail, m_at_event)` (S-020 `select_m_creators` soundness, `S020CommitteeSelection.md`), and `rand` is fixed by §1.3's seed chain, which V3 already pinned. So if the honest re-derivation excludes `d`, every honest validator's re-derivation excludes `d` (determinism), and every honest validator rejects the block. A producer cannot make `d ∈ domains_at_event` by manipulation: the only inputs to the draw are `epoch_rand` (committed by prior blocks / the beacon, unforgeable under A3 + the commit-reveal of V5/V6), the region filter, and the preceding aborts' `event_hash` fold — none of which a single producer controls without already diverging from V3 and being rejected upstream. ∎

**Code witness.** `src/node/validator.cpp:228–255` (pool build + `select_m_creators` draw + membership reject); `src/node/validator.cpp:186–192` (seed chain shared with V3); `src/crypto/random.cpp:122` (`select_after_abort_m`) and `select_m_creators` (the S-020 deterministic draw).

**Test witness.** `tools/test_abort_reselection.sh` (`determ`'s abort-reselection in-process scenarios) exercises the post-abort committee re-derivation determinism — the same `select_m_creators(rand ‖ event_hash)` fold the validator recomputes; `src/main.cpp:6783–6826` ("a run of aborts folded through chain_abort_hash drives a chained fallback") pins the fold determinism that T-C1's membership draw rests on.

### T-C2 — Producer/validator committee-re-derivation agreement

**Statement.** For any block `B` that passes V3 (creator selection), the at-event committee `domains_at_event` the validator computes in V10 for each `ae ∈ B.abort_events` equals the committee the **producer** used when it gathered the `M−1` claims, provided both run the same genesis params (`k_block_sigs_`, `bft_escalation_threshold_`, `epoch_blocks_`, `committee_region_`, `shard_id_`). No honest validator and honest producer ever disagree on who was a member at abort-event `i`.

*Proof.* The validator's seed chain (§1.3) is byte-identical to `check_creator_selection`'s (V3) — same `resolve_epoch_rand`, `epoch_committee_seed`, region filter, and refugee extension (`validator.cpp:196–209` mirrors the V3 block). The per-event size rule at `validator.cpp:238–244` mirrors `node.cpp::check_if_selected`'s escalation gate verbatim (`avail < k_full ∧ bft_enabled ∧ i ≥ bft_escalation_threshold ∧ avail ≥ k_bft ⇒ m = k_bft`). The exclusion set is rebuilt by replaying preceding aborts in the same iteration order (`excluded.insert(ae.aborting_node)` at line 293), and the `rand` fold at line 294 (`SHA256(rand ‖ ae.event_hash)`) matches the producer's. Because every input to `select_m_creators` is reproduced identically and the draw is deterministic (S-020), the output committee is identical. Any param mismatch would surface as a V3 rejection before V10 runs; conditional on V3 passing, V10's committee is forced to agree. ∎

**Code witness.** `src/node/validator.cpp:186–209` (seed chain + region/refugee mirror of V3); `src/node/validator.cpp:217–249` (size rule + draw mirroring `node.cpp::check_if_selected`); `src/node/validator.cpp:293–294` (exclusion + fold advance).

**Test witness.** `tools/test_abort_reselection.sh` (producer/validator re-derivation parity across abort cascades); the V3 parity is independently pinned by `tools/test_required_block_sigs.sh` + `determ test-block-validator-extensive` (committee-selection re-derivation consistency).

### T-C3 — Quorum-signature soundness (no fabricated certificate against honest `d`)

**Statement.** Under A1 (Ed25519 EUF-CMA) and H4 (honest claimers sign truthfully), a producer cannot assemble a V10-passing `AbortEvent` naming honest `d` as `aborting_node` unless honest `d` genuinely failed to contribute at `(h, ae.round)` — i.e., unless at least one honest claimer truthfully attested it. Equivalently: the probability that a finalized `AbortEvent` falsely slashes honest `d` is `≤ q · 2⁻¹²⁸` for an adversary making `q` forgery attempts.

*Proof.* Suppose a finalized block names honest `d` as `aborting_node` for event `ae` though `d` did contribute on time. By T-C1, `d ∈ domains_at_event`, so `M = domains_at_event.size() ≥ 2` and the certificate must carry `M−1 ≥ 1` claims (count check, lines 261–264). By the per-claim checks (lines 266–290), each claim `m` satisfies: `m.missing_creator = d`, `m.claimer ≠ d` (line 276), `m.claimer ∈ domains_at_event` (lines 277–279), `m.claimer` distinct across claims (line 280), `m.claimer ∈ registry` (lines 283–284), and `Verify(registry.find(m.claimer).pubkey, claim_digest(m), m.ed_sig) = 1` (lines 286–289) where `claim_digest(m)` binds `(h, ae.round, prev_hash, d)`.

Partition the `M−1` claimers into honest `H` and Byzantine `F'`. Each honest claimer `c ∈ H` produced a valid signature over `claim_digest = make_abort_claim_message(h, ae.round, prev_hash, d)`. By H4, an honest `c` signs such a message only if it observed `d` fail to contribute at `(h, ae.round)`. By hypothesis `d` contributed on time, so no honest `c` signed it; any signature in the certificate attributed to an honest claimer's key is therefore a forgery. A V10-passing certificate must contain `M−1` valid signatures by **distinct** registered claimers; for the certificate to exist with honest claimers' keys, the adversary must forge at least one (each forgery succeeds with probability `≤ 2⁻¹²⁸` under A1). If instead **all** `M−1` claimers are Byzantine (`H = ∅`), then `|F'| = M−1`, i.e., the Byzantine fraction among the at-event committee is `(M−1)/M`, which violates the honest-majority committee assumption that the abort-defense relies on (FA5 / FA1: at least one honest member per committee under H1–H3) — outside the adversary model. Therefore, within the model, fabricating the certificate requires forging an honest signature, bounding the false-slash probability by `q · 2⁻¹²⁸`. ∎

**Code witness.** `src/node/validator.cpp:257–290` (count check + per-claim binding + distinct-claimer set + EUF-CMA `verify`); `include/determ/node/producer.hpp:80–82` (the domain-separated `make_abort_claim_message` digest each `ed_sig` covers).

**Test witness.** `tools/test_abort_event_apply.sh` exercises the apply side that fires only after V10 admits the event; the V10 signature-binding path is structurally pinned by the shared `verify` primitive covered in `S006ContribMsgEquivocation.md` T-4 and `EquivocationSlashing.md` T-6 (both reduce false accusation to A1 over a domain-separated digest).

### T-C4 — Domain separation (abort claims are not replayable as other signatures)

**Statement.** A valid `AbortClaimMsg` signature for `(h, r, prev_hash, d)` cannot be repurposed as a signature for any other consensus message (a `ContribMsg` commit, a `BlockSigMsg` digest, an `EquivocationEvent` half, a different round, a different missing creator, or a different height), nor vice-versa. The abort-certificate signing space is disjoint from every other Ed25519-signed message space in the protocol.

*Proof.* `claim_digest = make_abort_claim_message(block_index, round, prev_hash, missing_creator)` is computed by a `SHA256Builder` over a fixed-arity, fixed-order field tuple distinct from every other signed digest in the protocol: `make_contrib_commitment` (Phase-1, mixes `tx_hashes` + `dh_input`), `compute_block_digest` (Phase-2 block hash), and the raw `(digest_a, digest_b)` an `EquivocationEvent` carries all hash structurally different pre-images. Under A2 (SHA-256 collision-resistance), the probability that an abort-claim digest collides with any other message digest is `≤ 2⁻¹²⁸`. The per-field binding (`block_index`, `round`, `prev_hash`, `missing_creator`) further prevents intra-channel replay: a claim signed for round 1 cannot be reused at round 2 (the validator's `round ≠ ae.round` reject at line 271), a claim signed against missing creator `x` cannot be reused against `d ≠ x` (the `missing_creator ≠ ae.aborting_node` reject at line 273), and a claim signed at height `h` cannot be reused at `h' ≠ h` (the `block_index ≠ b.index` reject at line 270). The `prev_hash` binding additionally pins the claim to a specific chain tip, preventing cross-fork replay. ∎

**Code witness.** `src/node/validator.cpp:270–273` (the four per-field rejects that enforce intra-channel binding); `include/determ/node/producer.hpp:79–82` ("Domain-separated commitment that each AbortClaim's Ed25519 sig covers").

**Test witness.** The domain-separation discipline is the same one verified across the protocol's signed-message surfaces in `WireFormatBackwardCompat.md` T-2 (domain-separator replay defense) and `MakeContribCommitmentBackwardCompat.md`; the abort-claim digest's field sensitivity is exercised by the abort-flow integration scripts (`tools/test_abort_reselection.sh`, `tools/test_abort_event_apply.sh`).

### T-C5 — Quorum-count exactness and distinct-claimer enforcement

**Statement.** A V10-passing `AbortEvent` carries **exactly** `M−1` claims, all from **distinct** registered claimers none of whom is the accused `d`. A producer can neither pad the certificate with duplicate signatures from a single colluding peer to reach the count, nor include the accused's own (coerced) signature toward the quorum.

*Proof.* The count check at `validator.cpp:261–264` rejects unless `claims_json.size() == domains_at_event.size() − 1` — both under- and over-sized certificates fail (`!=`, not `>=`). The `std::set<std::string> seen_claimers` at lines 266–281 rejects the second occurrence of any `claimer` (`if (!seen_claimers.insert(m_.claimer).second) return {false, "duplicate claimer in cert"}`), so the `M−1` claims are from `M−1` *distinct* domains. The `claimer == missing_creator` reject at line 276 excludes the accused from contributing toward its own slash. Combined with the `claimer ∈ domains_at_event` membership check (lines 277–279), the `M−1` distinct claimers are exactly the non-accused members of the `M`-sized at-event committee. Thus the certificate is a *full* quorum of the at-event committee minus the accused — the maximal honest-attainable evidence set — and cannot be forged by quorum-padding. ∎

**Code witness.** `src/node/validator.cpp:261–264` (exact-count `!=` reject); `src/node/validator.cpp:266–281` (distinct-claimer `std::set` + accused-exclusion + membership).

**Test witness — ⚠ NONE (corrected 2026-07-20).** An earlier revision of this line
claimed the exact-count and distinct-claimer invariants were "pinned by `determ
test-block-validator-extensive` (block-validator negative cases) and the abort-cert
assembly path in `tools/test_abort_event_apply.sh`". **Both citations were false and
have been withdrawn.** Measured:
`determ test-block-validator-extensive` contains **zero** occurrences of the
substring "abort" (its advertised "V1..V20 gate-by-gate" coverage stops short of
V10), and `test_abort_event_apply.sh` exercises the **apply** path
(`Chain::apply_transactions`), never `BlockValidator::check_abort_certs`.
Repo-wide: of 31 `abort_events.push_back` sites in `src/main.cpp`, none has a
`validate()` call within ±40 lines; of 68 `BlockValidator` sites, none touches
`abort_events`.

**T-C5 therefore has NO enforcing gate**, as do T-C1/T-C3/T-C4 — see
[ProofClaimGateTraceability.md](ProofClaimGateTraceability.md) §3, where this
cluster is the top-ranked open gap. The proof argument above stands on code
inspection; what is missing is the mechanism that would fail if the code changed.
The scoped remediation is an FA-capture negative test (drive the deterministic FA
harness to produce a genuine abort-carrying block, then mutate its certificate and
re-validate), because `check_abort_certs` is private and reaching it requires
passing the five earlier gates including the post-abort creator re-selection.

Per-signer evidence-pool bounds do genuinely compose with `S013PerSignerCap.md`
(S-013, 2-entry cap on the buffered evidence the certificate draws from).

### T-C6 — Phase discrimination preserved through verification

**Statement.** V10 verifies the certificate for `round ∈ {1, 2}` identically (both Phase-1 commit aborts and Phase-2 reveal aborts carry an `M−1` quorum and are validity-checked the same way), but the **apply** consequence is phase-discriminated: only `round == 1` triggers the suspension slash (FA-Apply-11 T-A1), while `round == 2` is verified-but-not-slashed (FA-Apply-11 T-A2). FA-Cert's soundness therefore covers both phases' admission, and the economic asymmetry lives entirely in the apply layer, not the verification gate.

*Proof.* The V10 loop body at `validator.cpp:224–295` does not branch on `ae.round` for any of its five steps — the committee re-derivation, membership, count, per-claim binding (which checks `round ≠ ae.round`, i.e., the claim's round must *match* the event's, whatever it is), and fold all run identically for round 1 and round 2. The only round-gated logic is the apply-side `if (ae.round != 1) continue;` at `chain.cpp:1314` (FA-Apply-11 T-A2). Hence V10 soundly admits a correctly-quorumed abort of either phase, and the "Phase-1 slashes / Phase-2 informational" asymmetry that FA-Apply-11 §3 tabulates is enforced downstream of FA-Cert, not within it. This separation of concerns is what lets FA-Cert state a single soundness theorem covering both phases. ∎

**Code witness.** `src/node/validator.cpp:271` (the claim's `round` must equal the event's `round`, phase-agnostic); `src/chain/chain.cpp:1314` (the apply-side phase gate, FA-Apply-11 territory, *not* in V10).

**Test witness.** `tools/test_abort_event_apply.sh` Phase-1 vs Phase-2 assertions (`src/main.cpp:15564–15593`) exercise the apply-side discrimination; the verification side admits both phases identically (structural, by the absence of a round branch in `check_abort_certs`).

### T-C7 — Determinism and snapshot-stability of the verification verdict

**Statement.** For a fixed chain state and fixed block `B`, two independent invocations of `check_abort_certs(B, chain, registry)` return identical verdicts (`ok` flag + diagnostic), and the verdict is stable across a `serialize_state` / `restore_from_snapshot` round-trip of the chain state the validator runs against. No abort certificate that verified before a snapshot restore fails after it, and none that failed verifies.

*Proof.* `check_abort_certs` is a pure function of `(B, chain.head_hash(), registry, genesis params)`: it performs no I/O, no clock reads, no randomness, and no map iteration whose order affects the result (the `select_m_creators` draw is deterministic per S-020; the `std::set seen_claimers` membership is order-independent; the per-claim loop iterates `claims_json` in its serialized array order, which is fixed by the block bytes). The only chain-state inputs are `head_hash()` (the V1-pinned prev_hash), `eligible_in_region` (the registry-derived pool), `shards_absorbed_by` (the R4 refugee set), and `resolve_epoch_rand` (the epoch seed) — all of which are reconstructed byte-identically by snapshot restore (the registry + epoch rand + merge state are covered by the S-033 state-root namespaces, `S033StateRootNamespaceCoverage.md`; abort_records under `b:` per FA-Apply-11 T-A8). Hence the seed chain, pool, and exclusion set are identical pre- and post-restore, the `select_m_creators` draws are identical, and the verdict is byte-stable. ∎

**Code witness.** `src/node/validator.cpp:172–298` (the pure verification function); `include/determ/chain/chain.hpp` (`resolve_epoch_rand`, `eligible_in_region`, `shards_absorbed_by` — all deterministic over restored state).

**Test witness.** Determinism composes through `tools/test_chain_save_load.sh` (snapshot round-trip preserves the registry + epoch rand the re-derivation reads) and `determ test-block-validator-extensive` (repeated validation of the same block yields identical verdicts); the S-033 state-root gate is the runtime mechanism that would surface any non-determinism in the inputs the verdict depends on.

---

## 3. Abort certificate vs equivocation evidence — the two accusation channels

Determ has two on-chain validator-side accusation gates with deliberately different evidence shapes. Pinning the symmetry (and the one structural asymmetry) makes the soundness story explicit:

| Dimension | Abort certificate (V10, this proof) | Equivocation event (V11, FA6) |
|---|---|---|
| Evidence shape | `M−1` distinct peers' Ed25519 claims over `(h, round, prev_hash, d)` | Two distinct sigs by `d`'s own key over two distinct digests at `h` |
| Who signs | The accused's **peers** (third-party attestation) | The accused **themselves** (self-incriminating) |
| Soundness root | EUF-CMA over honest claimers' keys + honest-majority committee (FA5/FA1) | EUF-CMA over the accused's own key (FA6 T-6) |
| Committee binding | Yes — V10 re-derives `domains_at_event` and checks membership (T-C1/T-C2) | No — V11 is committee-agnostic (any registered key suffices) |
| False-positive risk | `≤ q · 2⁻¹²⁸` (T-C3) — needs forging an honest peer's sig | `≤ q · 2⁻¹²⁸` (FA6 T-6) — needs forging the accused's own sig |
| Apply consequence | Phase-1: proportional `SUSPENSION_SLASH` (FA-Apply-11 T-A1); Phase-2: none (T-A2) | Full forfeit + immediate deregister (FA-Apply-10 T-E1/T-E2) |
| Phase discrimination | In apply layer only (T-C6); V10 admits both phases | N/A (equivocation is single-shaped) |
| Validator function | `check_abort_certs` (`validator.cpp:172–298`) | `check_equivocation_events` (`validator.cpp:307–332`) |

**The structural asymmetry that matters.** Equivocation evidence is *self-incriminating*: the accused's own key signed two conflicting things, so V11 needs no committee context — any party who observes both signatures can prove guilt, and FA6's soundness reduces to "honest `d` never signs two conflicting digests" (H2). Abort evidence is *third-party attestation*: the accused did **nothing** signable (they were silent), so the proof of their silence is `M−1` peers each swearing they were present and `d` was not. This is why V10 must bind the committee membership (T-C1/T-C2) — without it, a producer could collect `M−1` signatures from *any* `M−1` registered domains and slash an arbitrary `d` who was never even selected. The committee-membership binding is the abort channel's analog of the equivocation channel's "the sig is over the accused's *own* digest" self-incrimination property. Both channels reduce false-accusation to a single EUF-CMA forgery, but they get there through structurally different bindings.

**Why honest-majority is needed for abort soundness but not equivocation soundness.** FA6 T-6 is *unconditional* in the committee composition — even a fully-Byzantine committee cannot forge an honest `d`'s self-signature. FA-Cert T-C3, by contrast, needs the honest-majority committee assumption (at least one honest member per committee, FA5/FA1) to rule out the `H = ∅` corner where all `M−1` claimers are Byzantine and collude to slash honest `d`. This is intrinsic to third-party attestation: if *every* witness lies, no signature check can save the accused. The protocol's defense in that corner is the same one FA5/FA1 rely on — the committee-selection randomness (A3 + V6 commit-reveal) makes a fully-Byzantine committee at a given height require either `f ≥ N/3` global Byzantine stake (defeated by FA1's safety bound) or a committee-selection grind (defeated by S-020 + the equivocation slash on any grinding attempt). FA-Cert inherits that boundary rather than re-proving it.

---

## 4. Adversary model

| Adversary | Capability | Defense | Theorem |
|---|---|---|---|
| `A_nonmember` | Producer names honest `d` who was never selected at the at-event committee | V10 membership reject (`aborting_node not in selected set`) | T-C1 |
| `A_seed_grind` | Producer manipulates the committee seed so `d` appears selected | Seed chain forced to agree with V3; divergence rejected upstream; A3 + commit-reveal unpredictability | T-C1, T-C2 |
| `A_forge_claim` | Producer fabricates `M−1` claims with honest claimers' keys | EUF-CMA per-claim `verify` reject; forgery `≤ 2⁻¹²⁸` | T-C3 |
| `A_replay` | Producer reuses an honest claim from another round / height / missing-creator / fork | Per-field binding rejects (`round`, `block_index`, `missing_creator`, `prev_hash`); A2 domain separation | T-C4 |
| `A_pad` | Producer pads the certificate with duplicate sigs from one colluding peer to reach `M−1` | Exact-count `!=` reject + `seen_claimers` distinct-claimer set | T-C5 |
| `A_self_claim` | Producer includes the accused's coerced self-signature toward the quorum | `claimer == missing_creator` reject | T-C5 |
| `A_phase_smuggle` | Producer mislabels a Phase-2 (no-slash) abort as Phase-1 to slash | Claim `round` must match event `round` (T-C4); committee re-derivation uses the event's actual round-state via the fold; apply gate is the only round-discriminator and is sound (FA-Apply-11) | T-C4, T-C6 |
| `A_full_byzantine_committee` | All `M−1` claimers Byzantine, collude to slash honest `d` | Outside model (needs `f ≥ N/3` or committee grind); inherited from FA5/FA1 + S-020 + FA6 grind-slash | §3 discussion |

Every in-model adversary that could falsely suspension-slash honest `d` reduces to either (a) a committee-selection grind (defeated by the V3-agreement T-C2 + A3 + S-020) or (b) a single EUF-CMA forgery (T-C3, `≤ 2⁻¹²⁸`). The out-of-model `A_full_byzantine_committee` is the abort channel's irreducible trust assumption, identical in strength to the honest-member assumption FA5 already requires for the protocol to be safe at all.

---

## 5. What this proof does NOT cover

- **Completeness (every genuine aborter gets a certificate).** FA-Cert is *one-sided*: it proves V10 admits no false accusation against honest `d`. It does **not** prove that every validator who genuinely aborted is eventually certified and slashed — that is a liveness property of the producer's abort-detection + the gossip propagation of `AbortClaimMsg`s (FA4 territory), out of scope here, exactly as FA6 §4.3 scopes out equivocation-slash completeness.
- **Producer abort-detection correctness.** Whether the producer correctly identifies the *true* missing creator at a round is `src/node/producer.cpp`'s scope. FA-Cert proves the validator soundly verifies *whatever certificate the producer assembled*; if `M−1` honest peers genuinely (and correctly) attest `d`'s silence, the slash is correct — the upstream "is `d` actually the one who went silent" question is the producer's, and is bounded by the same honest-majority assumption (a majority of honest peers will not all attest a present node's absence).
- **The `event_hash` pre-image correctness.** V10 folds `ae.event_hash` into the committee re-derivation (line 294) but does not independently recompute `event_hash = SHA256(round ‖ aborting_node ‖ timestamp ‖ random_state)` from its parts. A malformed `event_hash` changes the *next* event's committee draw, which would cascade into a V3 or V10 mismatch on the subsequent event — the binding is enforced transitively through the seed chain rather than by a direct per-event recompute. The first-event committee (folded zero times) is pinned directly by V3, which is the load-bearing anchor.
- **Apply-side mechanics.** The proportional `SUSPENSION_SLASH` deduction, the S-032 `abort_records_` cache update, the floor-at-zero arithmetic, the A1 supply contribution, and the no-registry-deactivation property are all FA-Apply-11's scope (T-A1..T-A8). FA-Cert's verdict is the *gate* those mechanics fire behind.
- **Cross-shard abort propagation.** A validator who aborts on shard `S_X` is certified and slashed on `S_X` by the local V10 + apply. Whether that propagates to `S_Y` is FA8 (`RegionalSharding.md`) + the cross-shard receipt path; FA-Cert assumes local-shard context (the `committee_region_` / `shard_id_` filters in the re-derivation are the shard-local pool).
- **The S-013 evidence-pool bound itself.** FA-Cert assumes the `M−1` claims arrive at the producer; the bound on how many such buffered claims a node retains per signer (the per-signer cap that prevents memory exhaustion) is `S013PerSignerCap.md`. FA-Cert composes with S-013 (the cap does not change which certificates verify, only how many are buffered) but does not re-prove it.

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | Notation; V10 abort-certificate predicate (§5); V3 creator selection (§6); A1/A2/A3 + H1–H4 assumptions |
| `EquivocationSlashing.md` (FA6) | The analogous **equivocation**-channel soundness theorem this proof structurally mirrors; §3 contrasts the self-incriminating vs third-party-attestation evidence shapes |
| `AbortEventApply.md` (FA-Apply-11) | Apply-side proportional-slash mechanics (T-A1..T-A8); §4 explicitly defers V10 soundness — FA-Cert closes exactly that dependency |
| `SelectiveAbort.md` (FA5) | Abort-defense randomness + the BFT escalation gate setting the per-event committee size; supplies the honest-majority-committee assumption T-C3 leans on |
| `S020CommitteeSelection.md` (S-020) | `select_m_creators` hybrid Fisher-Yates / rejection-sampling soundness reused unchanged in the at-event re-derivation (T-C1/T-C2) |
| `S033StateRootNamespaceCoverage.md` (S-033) | State-root coverage of the registry + epoch rand + merge state that the verdict's determinism (T-C7) depends on |
| `StakeForfeitureCascade.md` (FA-Apply-16) | The cascade interaction when the same offender is both abort-slashed (this channel) and equivocation-slashed |
| `S013PerSignerCap.md` (S-013) | The per-signer cap on the buffered evidence pool the certificate draws from |
| `WireFormatBackwardCompat.md` / `MakeContribCommitmentBackwardCompat.md` | Domain-separation discipline underpinning T-C4 |
| `docs/SECURITY.md` §S-013 / abort-handling rows | Audit-side record for the abort/equivocation evidence-handling surfaces |

A reviewer can confirm V10 soundness by:

- Reading `check_abort_certs` (`validator.cpp:172–298`) to confirm all five steps (re-derivation, membership, exact-count, per-claim binding + sig verify, fold) fire before `{true, ""}` is returned.
- Confirming the seed chain (lines 186–209) is byte-identical to `check_creator_selection` (V3) so the committee re-derivation cannot diverge from the block's committed committee (T-C2).
- Confirming the per-claim loop (lines 266–290) enforces distinct registered claimers, accused-exclusion, the four per-field bindings, and the EUF-CMA `verify` — the conjunction that reduces false accusation to a single forgery (T-C3).

---

## 7. Conclusion

T-C1 through T-C7 establish that V10 (`check_abort_certs`) is a **sound** suspension-slash accusation gate: an honest validator is never named as the aborting node in a finalized block except with probability `≤ q · 2⁻¹²⁸` (one EUF-CMA forgery), under the same honest-majority-committee assumption the protocol already needs to be safe. The soundness rests on two bindings the certificate carries — committee membership (re-derived deterministically and forced to agree with V3) and an `M−1` distinct-registered-claimer Ed25519 quorum over a domain-separated digest — neither of which a single producer (or any sub-honest-majority coalition) can forge.

FA-Cert is the verification-side bookend the abort channel needed: FA-Apply-11 proves the slash *applies* correctly once admitted, and FA-Cert proves the admission *is sound*. Together they give the abort channel the same end-to-end soundness story FA6 + FA-Apply-10 give the equivocation channel — with the one principled difference, made explicit in §3, that third-party attestation (abort) requires an honest-majority committee where self-incrimination (equivocation) does not.
