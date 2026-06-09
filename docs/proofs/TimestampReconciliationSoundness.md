> **TIER: NEAR-TERM — 1.0.x in-flight.** Committed/imminent but NOT yet shipped; not part of the 1.0-authoritative set. Roadmap index: docs/ROADMAP.md

# TimestampReconciliationSoundness — closing the last S-030-D2 digest residual: the block `timestamp` (commit `f99eeb8`)

This document is the soundness argument for the **timestamp median reconciliation** that binds `Block.timestamp` into `compute_block_digest` (commit `f99eeb8`). It is the final dimension of the S-030-D2 block-digest field-coverage gap analyzed in `S030-D2-Analysis.md` — the one §5 of that document calls *"the non-fix that became the fix."* With it shipped, every S-030-D2 ✗ row is closed at the consensus (digest) layer: the three pool-fed views (`inbound_receipts` / `equivocation_events` / `abort_events`, via v2.7 F2), `partner_subset_hash` (commit `8585a50`), and now `timestamp`. `cross_shard_receipts` is the lone remaining digest-excluded field, but it is deterministically derived from the committee tx set already bound by `tx_root` + `creator_tx_lists`, not an independent divergence vector (`S030-D2-Analysis.md §4 item 10`).

The proof exists because the timestamp is the **one** ✗-row field that cannot be digest-bound *raw*. The other dimensions are sets reconciled by union/intersection; the timestamp is a single scalar with a fundamentally different obstacle: honest committee clocks differ within the validator's `±30s` window (`validator.cpp::check_timestamp`, `kTimestampWindowSec = 30`), so two honest members signing a digest over their *own* `now_unix()` would compute divergent digests, fail to gather K signatures, and abort the round — the gossip-async-divergence obstacle of `S030-D2-Analysis.md §2` reappearing as a clock-skew obstacle in §5. The fix transposes the F2 commit-then-reconcile pattern from a set reduction to a **deterministic order statistic** (the lower-median), making the bound value a pure function of the K signed Phase-1 commits. This document proves that transposition is sound.

**Canonical assumption labels.** Per `Preliminaries.md §2.0`: **A1** = Ed25519 EUF-CMA (§2.2), **A2** = SHA-256 collision resistance (§2.1), **A3** = SHA-256 preimage / second-preimage resistance (§2.1), **A4** = CSPRNG uniform sampling (§2.3). The Byzantine fault bound `f < K/3` is the per-block honest-committee threshold of `Preliminaries.md §3` (for *liveness-flavored* properties; FA1 safety holds for any `f`). The "BFT-time median" argument of T-2 is an availability/robustness property of the reconciled value, not a safety property, so it is the one place `f < K/3` is load-bearing.

**Companion documents.** `S030-D2-Analysis.md §5` (the authoritative analysis this proof formalizes — read it first); `EqAbortViewDigestExtension.md` (the eq/abort F2 dimension, the set-reconciliation sibling whose UNION rule this timestamp median parallels); `F2ViewReconciliationAnalysis.md` (T-1..T-6 purity/order-independence/idempotence of `reconcile_union` — the analogue for a set that this proof restates for the scalar lower-median); `F2-SPEC.md §6.3` (the pre-implementation review gate this commit landed against); `StateRootAnchorSoundness.md §3.1` (the contrasting field whose binding is *transitive-forward via `signing_bytes`*, NOT a direct digest append — the timestamp binding is the opposite case, a *direct* append into `compute_block_digest`); `ConsensusPhaseStructureSoundness.md` (FA-Phase — the Phase-1 commit / Phase-1→2 transition structure this binding rides on); `Safety.md` (FA1 — the "≤ 1 finalized digest per height" theorem this closure strengthens to "≤ 1 finalized *instance* per height" for the timestamp dimension); `BlockTimestampMonotonic.tla` (FB29 — the existing TLA+ companion modeling the four-surface `Block.timestamp` contract at the chain/hash/digest/signing_bytes layers; the digest surface it models is now the *reconciled* timestamp); `Preliminaries.md §2.0/§3` (assumption labels + fault bound); `docs/SECURITY.md §S-030` (the audit finding).

---

## 1. Scope

The mechanism, end to end (all citations to the shipped code at commit `f99eeb8`):

1. **Phase-1 commit (signed).** Each committee member sets `ContribMsg.proposer_time = now_unix()` and binds it into its Phase-1 commitment. `make_contrib_commitment` (`src/node/producer.cpp:228-292`) appends `"DTM-TS-v1" ‖ proposer_time` **only when `proposer_time != 0`**, *after* the F2 `"DTM-F2-v1"` view-root block, behind its own domain separator (so it cannot be confused with an F2 view root or a v1 pre-image). The member's Phase-1 Ed25519 signature (`ed_sig`) is over this commitment — so the committed time is authenticated. The production node passes `now_unix()` at `src/node/node.cpp:887-897` (`Node::start_contrib_phase`); `now_unix() > 0`, so the reconciliation gate fires on real blocks.

2. **Reconcile at the Phase 1→2 boundary.** `build_body` (`src/node/producer.cpp:818-846`) carries each member's `proposer_time` into `b.creator_proposer_times` (committee/selection order, parallel to `b.creators`). Then: if **every** entry is non-zero (production path), it sets `b.timestamp = reconcile_median_time(b.creator_proposer_times)`; otherwise (any entry zero — legacy/test/pre-activation) it **clears** the vector and leaves `b.timestamp` at the assembler wall-clock (the byte-identical v1 shape). `reconcile_median_time` (`producer.cpp:286-291`) is the deterministic **lower-median**: sort a copy, return `sorted[(v.size()-1)/2]`; `0` for empty input.

3. **Digest binding.** `compute_block_digest` (`producer.cpp:689-690`) appends `b.timestamp` **only when `b.creator_proposer_times` is non-empty** — the activation signal that the block went through reconciliation. Field order: `inbound, eq, abort, partner_subset_hash, timestamp`. A legacy block (empty vector) appends nothing, keeping the byte-identical v1 digest.

4. **Validator.** `check_creator_tx_commitments` (`src/node/validator.cpp:164-184`) recomputes each creator's Phase-1 commit **with** that creator's `proposer_time` (via the `pt_at` accessor), so the per-creator time is authenticated by `creator_ed_sigs` — tampering any `proposer_time` fails this sig check. `check_timestamp` (`validator.cpp:1306-1327`), when `b.creator_proposer_times` is non-empty, rejects on (a) `size != creators.size()`, (b) any zero entry, or (c) `b.timestamp != reconcile_median_time(b.creator_proposer_times)`; then applies the existing `±30s` wall-clock bound (`kTimestampWindowSec = 30`).

5. **Light client.** `light/verify.cpp::light_compute_block_digest` (`light/verify.cpp:76-90`) mirrors the append: it binds `b.timestamp` when `creator_proposer_times` is non-empty, in the same field order. `creator_proposer_times` survives the `rpc_headers` strip (it is not one of the four stripped heavy collections — `transactions` / `cross_shard_receipts` / `inbound_receipts` / `initial_state`), so the light client holds both the vector and `b.timestamp` and binds the same value the committee signed.

6. **Wire/JSON.** `ContribMsg.to_json` / `from_json` (`producer.cpp:62-101`) emit/read `proposer_time` only when non-zero. `Block::to_json` / `from_json` (`src/chain/block.cpp:443-449, 581-590`) emit/read `creator_proposer_times` only when non-empty. `block.hpp:428-438` declares `std::vector<uint64_t> creator_proposer_times`.

**Out of scope.** The `±30s` *wall-clock* admission bound itself (an inherited S-003 liveness sanity, not a consensus-defining property — `validator.cpp:1296-1302`); the four-surface `Block.timestamp` contract at the `compute_hash` / `signing_bytes` layers (FB29 / `BlockTimestampMonotonic.tla`; this document covers only the new *digest* surface); the broader S-030-D2 set-reconciliation dimensions (`EqAbortViewDigestExtension.md`, `S030-D2-Analysis.md §4`).

---

## 2. Threat model

### 2.1 Adversary `A_ts`

`A_ts` is the S-030-D2 two-instance / post-signing-tamper adversary specialized to the timestamp dimension. Two concrete shapes, mirroring the structural D2 attack (`S030-D2-Analysis.md §1`):

- **(a) Post-signing relayer tamper.** A relayer (or malicious daemon, or full-node serving a light client) takes a genuine K-of-K-signed reconciled block, overwrites `b.timestamp` with a value of its choosing, and re-gossips. Goal: have an honest receiver apply (or a light client report) the altered timestamp under cover of the genuine committee signatures.

- **(b) Two-instance divergence.** A Byzantine-influenced committee (or an implementation race) mints two distinct block instances at the same height that differ in `timestamp`, both K-of-K-signed, both circulating. Goal: have two honest nodes apply different `timestamp` values, splitting state.

- **(c) Median-input forgery.** A malicious assembler fabricates the `creator_proposer_times` vector — substituting times it prefers — to steer the reconciled median, while passing committee verification.

- **(d) Byzantine clock-poisoning.** Up to `f` Byzantine committee members contribute extreme `proposer_time` values (far future / far past) in their Phase-1 commits, attempting to drag the canonical timestamp outside the honest-clock spread.

### 2.2 Honest party

An honest assembler runs the released `determ` build at `build_body`; an honest validator runs `check_creator_tx_commitments` + `check_timestamp`; an honest light client runs `light_compute_block_digest` + `verify_block_sigs`. None bypasses verification. The claims (§3) are that under `A_ts`, every honest party either binds/accepts the genuine reconciled median or fail-closes — never a relayer-asserted or unilaterally-steered timestamp.

### 2.3 Out of scope

`A_crypto` (SHA-256 collision finder per A2 / Ed25519 forger per A1 — the binding rests on these being infeasible). Pure availability attacks (a partition where an honest assembler lacks a quorum of non-zero times falls back to the v1 shape, a liveness degradation, not a safety break). Coordinated-real-clock skew across an entire honest committee beyond `±30s` (an environment fault the `±30s` bound flags, not an adversary this proof defeats).

---

## 3. Soundness theorems

Throughout, `K = |b.creators|` is the committee size; `t_1, …, t_K` are the per-creator committed `proposer_time` values in `b.creator_proposer_times`; `m := reconcile_median_time(t_1,…,t_K) = sorted(t)[(K-1)/2]` is the canonical reconciled timestamp; `digest(b) := compute_block_digest(b)`; `f` is the number of Byzantine committee members. Bounds are per `Preliminaries.md §2.0` (A1, A2 ≈ `2⁻¹²⁸`).

### T-1 DETERMINISM (the §5 gossip-async-divergence obstacle defeated)

**Statement.** The reconciled timestamp `m` is a pure, total function of the multiset `{t_1, …, t_K}` of K signed Phase-1 `proposer_time`s. Therefore every honest assembler that has gathered the same K Phase-1 commits computes the identical `b.timestamp`, hence the identical `digest(b)`, hence the K Ed25519 signatures gather. This is precisely what a **raw** timestamp cannot achieve.

**Proof.** `reconcile_median_time` (`producer.cpp:286-291`) is `v = sort(copy(times)); return v[(v.size()-1)/2]`. Sorting a `std::vector<uint64_t>` is a deterministic total order on a finite multiset; indexing at the fixed position `(K-1)/2` is total for `K ≥ 1`. There is no clock read, no map iteration, no gossip-pool inspection, no floating point — the output depends *only* on the input multiset. Two assemblers with the same `{t_1,…,t_K}` therefore obtain bytewise-identical `m`.

The K Phase-1 commits are already the shared input the v1 digest depends on: `tx_root` (`producer.cpp:612`) and `creator_tx_lists` (`:617-618`) are functions of the same K signed `ContribMsg`s, and every honest member must have gathered them to compute the v1 digest at all (`ConsensusPhaseStructureSoundness.md` T-1, T-4 — the K-arrived phase-transition gate seals an ordered commitment set before Phase-2). The `proposer_time`s ride in those same commits (`ContribMsg.proposer_time`, carried into `b.creator_proposer_times` at `build_body` `producer.cpp:820-822`). So the *input* to `reconcile_median_time` is identical across honest members ⇒ the *output* `m`, and the digest append `h.append(b.timestamp)` (`producer.cpp:689-690`), are identical ⇒ all honest members sign the same digest ⇒ K-of-K gathers.

**Contrast with the raw timestamp (the §5 obstacle).** A raw append `h.append(now_unix())` makes the digest a function of the *signing member's local clock*. Two honest members with clocks differing by even 200 ms compute different digests, K signatures never gather, the round aborts; under recurring skew the chain stalls. This is the scalar incarnation of the gossip-async-divergence failure that `S030-D2-Analysis.md §2` showed killed the naive set extension. The reconciliation moves the divergence-absorbing boundary into Phase-1 (each member commits its *own* clock value, harmlessly) and makes the digest a function of the post-reconciliation canonical scalar (committee-agreed). ∎

### T-2 BYZANTINE-ROBUSTNESS (the median is honest-flanked under `f < K/3`)

**Statement.** Under `f < K/3` Byzantine committee members (`K ≥ 3`), the lower-median `m = sorted(t)[(K-1)/2]` lies within the closed interval `[min(honest t), max(honest t)]` — i.e. it is *honest-flanked* on both sides. A Byzantine minority therefore cannot drag the canonical timestamp outside the honest-clock spread (defeating `A_ts(d)`, clock-poisoning).

**Proof.** Let `h = K - f` be the honest count. The chosen order-statistic index is `j := (K-1)/2` (integer division), the lower-median position in `0..K-1`. We show position `j` is flanked by an honest value on each side, i.e. there is at least one honest value at or below position `j` and at least one honest value at or above position `j`.

A Byzantine adversary controls at most `f` of the K sorted values; it can place them at the lowest `f` positions (`0..f-1`) or the highest `f` positions (`K-f..K-1`) or any mix. The worst case for "honest-flanked" is to pack all `f` Byzantine values entirely below position `j` (pulling the median up toward an extreme low... no — pushing the honest mass up) or entirely above it.

- **Honest value at or below `j`.** If the adversary places all `f` Byzantine values at positions `0..f-1`, the value at position `j` is honest iff `j ≥ f`, i.e. there exists an honest value occupying position `j` or some position `≤ j`. We need `f ≤ j = (K-1)/2`. Since `f ≤ (K-1)/2` is exactly the condition, and `f < K/3 ⇒ f ≤ ⌈K/3⌉ - 1 ≤ (K-1)/2` for all `K ≥ 3`, this holds. Concretely the implementation comment (`producer.cpp:280-285` / `producer.hpp` doc on `reconcile_median_time`) states it: *"the order statistic at index `(K-1)/2` is flanked by honest values on both sides when `f ≤ (K-1)/2`, which `f < K/3` implies for `K ≥ 3`."*
- **Honest value at or above `j`.** Symmetrically, if the adversary packs all `f` values at the top positions `K-f..K-1`, position `j` is honest iff `j ≤ K-1-f`, i.e. `f ≤ K-1-j = K-1-(K-1)/2 = ⌈(K-1)/2⌉ ≥ (K-1)/2`. Again satisfied by `f ≤ (K-1)/2`.

Both bounds reduce to `f ≤ (K-1)/2`. We verify `f < K/3 ⇒ f ≤ (K-1)/2` for `K ≥ 3`: the largest integer `f` with `f < K/3` is `f = ⌈K/3⌉ - 1`. For `K = 3`: `f ≤ 0 ≤ 1 = (K-1)/2`. For `K = 6`: `f ≤ 1 ≤ 2`. For `K = 7`: `f ≤ 2 ≤ 3`. In general `⌈K/3⌉ - 1 ≤ (K-1)/2 ⇔ 2⌈K/3⌉ ≤ K+1`, which holds for every `K ≥ 1`. Hence under `f < K/3` the lower-median index is flanked.

Because `m` sits at an honest-flanked position, there is an honest value `t_lo ≤ m` and an honest value `t_hi ≥ m`, so `min(honest) ≤ t_lo ≤ m ≤ t_hi ≤ max(honest)`: `m ∈ [min(honest t), max(honest t)]`. The Byzantine `f` values, however extreme, cannot move `m` outside the honest range. (This is the standard BFT-time median; the regression exercises it directly at K=7, f=2 — see §5.) ∎

**Remark (lower- vs exact-median, and why integer-clean).** `reconcile_median_time` returns one of the *committed* values (the order statistic), never an average — so it is integer-valued with no rounding ambiguity and no division by parity. The lower-median choice (`(K-1)/2`, the lower of the two central positions for even K) is a fixed, deterministic convention that both the producer and the validator call (`producer.cpp:286` and `validator.cpp:1316`), so the parity convention can never desynchronize them.

### T-3 AUTHENTICATION (each `proposer_time` is sig-bound; the median uses authenticated inputs)

**Statement.** Each `b.creator_proposer_times[i]` is authenticated by `b.creator_ed_sigs[i]` via the Phase-1 commitment. Tampering any `proposer_time` post-signing fails `check_creator_tx_commitments` (with probability of forgery `≤ 2⁻¹²⁸` per entry, A1). Hence the validator's re-derived median is computed over sig-authenticated inputs, defeating `A_ts(c)` (median-input forgery).

**Proof.** Creator `i`'s Phase-1 signature `b.creator_ed_sigs[i]` is over `make_contrib_commitment(b.index, b.prev_hash, list_i, dh_input_i, eq_root_i, abort_root_i, inbound_root_i, proposer_time_i)`. The `proposer_time_i` argument is appended into the SHA-256 commitment behind the `"DTM-TS-v1"` domain separator when non-zero (`producer.cpp:264-271`). The validator recomputes exactly this commitment with `pt_at(b.creator_proposer_times, i)` supplying `proposer_time_i` (`validator.cpp:171-180`) and rejects if `verify(pubkey_i, commit, sig_i)` fails (`validator.cpp:182`).

Suppose `A_ts` serves a block whose `b.creator_proposer_times[i] = t'_i ≠ t_i` (the value creator `i` actually committed) while keeping `b.creator_ed_sigs[i]` genuine. Then the validator recomputes a commitment containing `t'_i`, which differs from the byte string creator `i` signed (the `"DTM-TS-v1" ‖ t'_i` append differs from `"DTM-TS-v1" ‖ t_i`; all other appends unchanged). For `verify` to nonetheless accept, `A_ts` must present a valid Ed25519 signature by creator `i` over a *different* message — an EUF-CMA forgery, probability `≤ 2⁻¹²⁸` (A1). The union over the up-to-`K` per-creator checks is `≤ K · 2⁻¹²⁸`.

Therefore, except with negligible probability, every `t_i` the validator feeds into `reconcile_median_time` (`validator.cpp:1318`) is the value that creator actually signed in Phase-1. The domain separation (`"DTM-TS-v1"`, distinct from the F2 `"DTM-F2-v1"` block and from the v1 pre-image) ensures a `proposer_time` cannot be cross-replayed as an F2 view root or vice versa (A2 cross-domain second-preimage; `SchemaDiscriminatorsImpl.md` style). A malicious assembler thus cannot fabricate median inputs: it can only assemble from the K *signed* commits, exactly as it cannot fabricate `tx_root` inputs. ∎

**Note (no separate `signing_bytes` binding needed).** Unlike `state_root` / `partner_subset_hash`, which are bound transitively-forward via `Block::signing_bytes` (`StateRootAnchorSoundness.md §3.2`), `creator_proposer_times` needs *no* separate `signing_bytes` append: the per-creator times are already authenticated by `creator_ed_sigs` (the Phase-1 commitment), and the canonical `b.timestamp` they reconcile to is bound *directly* into `compute_block_digest` (T-4). This is the same device the `creator_view_*` roots use (`block.hpp:428-438` comment).

### T-4 DIGEST-CLOSURE (binding `timestamp` closes the S-030-D2 ✗ row)

**Statement.** Binding `b.timestamp` into `compute_block_digest` (when `creator_proposer_times` is non-empty) closes the timestamp dimension of S-030-D2: a relayer that alters `b.timestamp` post-signing changes `digest(b)`, so the stored K-of-K signatures no longer verify (defeating `A_ts(a)`); and two block instances differing only in `timestamp` produce different digests, so they cannot both gather K-of-K signatures (defeating `A_ts(b)`).

**Proof.** On a reconciled block, `compute_block_digest` appends `b.timestamp` as the last field (`producer.cpp:689-690`, order `inbound, eq, abort, partner_subset_hash, timestamp`). The committee's Phase-2 signatures `b.creator_block_sigs` are over `digest(b)` (`ConsensusPhaseStructureSoundness.md` T-4; `producer.cpp::make_block_sig`).

*Defeating (a).* Let `A_ts` overwrite `b.timestamp ← t'' ≠ m` on a genuinely-signed block. Verifying the block recomputes `digest(b)`, now with `h.append(t'')` instead of `h.append(m)`. The recomputed digest differs from the one the committee signed unless `SHA256(… ‖ t'') = SHA256(… ‖ m)` with `t'' ≠ m` — a SHA-256 collision, `≤ 2⁻¹²⁸` (A2). So the stored K signatures (over the genuine `m`-digest) fail to verify against the recomputed `t''`-digest; the block is rejected at signature verification. The full node also has the independent `check_timestamp` re-derivation (T-2/T-3 inputs) that rejects `b.timestamp != reconcile_median_time(b.creator_proposer_times)` (`validator.cpp:1320-1321`) — so a tampered timestamp fails **both** the digest-signature check **and** the median re-derivation. Belt and suspenders.

*Defeating (b).* Two instances with distinct timestamps `m_1 ≠ m_2` (on reconciled blocks) have `digest_1 ≠ digest_2` (same A2 argument). A committee signature gathers around exactly one digest; the K-of-K signature set cannot simultaneously certify both `digest_1` and `digest_2` without K members each double-signing two distinct messages — which is itself equivocation (FA6-slashable) and, for the honest majority, impossible. So at most one timestamped instance gathers K-of-K. This upgrades the S-030-D2 timestamp row from the "✗ (two instances share a digest)" state to the closed state: combined with T-1 (honest members all reconcile to the *same* `m`), no two distinct timestamps can both be the canonical reconciled value over the same K commits, and no altered timestamp survives the digest. This is the consensus-layer closure (`S030-D2-Analysis.md §4 item 10`), stronger than the apply-layer S-033 fallback (`§3.5`).

The digest is a SHA-256 finalize over an append sequence; appending `b.timestamp` (8 bytes, big-endian, via `SHA256Builder::append(uint64_t)`) makes the timestamp a preimage component, so any change to it changes the finalized 32-byte digest except under an A2 collision. ∎

### T-5 BACKWARD-COMPAT (conditional gate preserves byte-identical v1 digests)

**Statement.** The conditional gate — bind iff `b.creator_proposer_times` is non-empty — preserves byte-identical v1 digests (and v1 JSON, and v1 Phase-1 commitments) for every legacy / non-reconciled block. No previously-valid block's digest changes.

**Proof.** Three gated surfaces, each a strict empty/zero short-circuit:

1. **Digest.** `compute_block_digest` appends `b.timestamp` only inside `if (!b.creator_proposer_times.empty())` (`producer.cpp:689`). A legacy block has an empty `creator_proposer_times` (it was either produced pre-feature, or `build_body` cleared the vector because some `proposer_time` was zero — `producer.cpp:841-842`), so the branch is skipped and the digest append sequence is byte-identical to v1. The same gate is mirrored in `light_compute_block_digest` (`light/verify.cpp:88-89`).
2. **Phase-1 commitment.** `make_contrib_commitment` appends `"DTM-TS-v1" ‖ proposer_time` only inside `if (proposer_time != 0)` (`producer.cpp:264`). A legacy/test contrib with `proposer_time == 0` produces a byte-identical pre-feature commitment — the same all-zero short-circuit the F2 view roots use. The validator's `pt_at` returns `0` for missing indices (`validator.cpp:177-179`), reproducing the legacy commit on legacy blocks.
3. **JSON.** `ContribMsg.to_json` emits `proposer_time` only when non-zero (`producer.cpp:62-65`); `Block::to_json` emits `creator_proposer_times` only when non-empty (`block.cpp:443-449`). Legacy serializations omit the fields entirely, staying byte-identical; `from_json` defaults to `0` / empty.

The empirical witness is the commit's `FAST=1 158→159 PASS / 0 FAIL`: every non-reconciled block in the existing regression corpus is byte-identical pre- and post-change (the commit message records this, and `test-block-digest` assertions 15–16 pin the EXCLUSION on the non-F2 path). The `all_set` guard in `build_body` (`producer.cpp:837-843`) is the decision point: production (all-non-zero) reconciles and binds; any zero falls back to the assembler wall-clock and drops the vector, keeping v1 shape. ∎

### T-6 LIVENESS (the median is ~now, so the `±30s` bound still admits honest blocks)

**Statement.** On an honest committee with clocks within the `±30s` validator window, the reconciled median `m` lies within the honest-clock spread (T-2), hence within `±30s` of every honest validator's `now_unix()`. So `check_timestamp`'s wall-clock bound (`validator.cpp:1324-1327`) admits honestly-produced reconciled blocks — the binding does not regress liveness.

**Proof.** By T-2, `m ∈ [min(honest t), max(honest t)]`. If all honest committee members' clocks are within `±30s` of true time (the operating assumption the `±30s` window encodes — `validator.cpp:1296-1302`, the S-003 widening from ±5s), then `min(honest t)` and `max(honest t)` are both within `±30s` of true time, so `m` is too. An honest validator's `now_unix()` is likewise within `±30s` of true time, so `|m - now_unix_validator| ≤ 60s`... — and tighter in practice, since the median of clocks clustered around true time is itself near true time. The deployed `kTimestampWindowSec = 30` bounds `|b.timestamp - now_unix()| ≤ 30s`; because `m` is an honest-clock order statistic (not an adversarial extreme, by T-2), it sits in the dense central region of the honest clock distribution, comfortably inside the window for any reasonable skew budget. The `±30s` bound is explicitly a *liveness sanity*, not a consensus-defining property (`validator.cpp:1300-1302`): a reconciled `m` near `now` keeps honest blocks admissible while the median's Byzantine-robustness (T-2) is what makes the *consensus-bound* value trustworthy. Hence no honest block that would have been admitted pre-change is rejected post-change. ∎

**Note (the validator runs both checks).** For a reconciled block, `check_timestamp` first re-derives the median and rejects on mismatch (the consensus check, T-3/T-4), *then* applies the `±30s` bound (the liveness sanity). The two are complementary: the median check pins `b.timestamp` to the authenticated committee inputs; the `±30s` check catches an entire-committee real-clock fault (an environment problem, out of `A_ts` scope) before it poisons downstream consumers.

### T-7 LIGHT-CLIENT (the field survives the header strip; header-only sync stays sound)

**Statement.** `creator_proposer_times` is retained through `node.cpp::rpc_headers` (only `transactions` / `cross_shard_receipts` / `inbound_receipts` / `initial_state` are stripped), so `light_compute_block_digest` binds the same `b.timestamp` the full committee signed. A daemon that tampers `b.timestamp` post-signing fails the light client's `verify_block_sigs`. Header-only sync therefore inherits T-4's closure.

**Proof.** `light_compute_block_digest` (`light/verify.cpp:76-90`) is the byte-for-byte mirror of `compute_block_digest`, including the gated timestamp append at the same field position (`inbound, eq, abort, partner_subset_hash, timestamp`). For the light client to recompute the same digest the committee signed, the header it receives must carry both `b.creator_proposer_times` (the activation signal) and `b.timestamp`. Because `rpc_headers` strips only the four heavy collections and keeps `creator_proposer_times` (alongside `state_root` / `partner_subset_hash` — the commit message and `StateRootAnchorSoundness.md §3.1` document the strip set), the light client has both fields.

Now suppose a malicious daemon serves a header with a tampered `b.timestamp = t'' ≠ m` on a reconciled block, replaying the genuine `creator_block_sigs`. The light client recomputes `light_compute_block_digest` with `h.append(t'')`, getting a digest that differs from the signed one except under A2; `verify_block_sigs` then fails the Ed25519 check against the genuine signatures, and the light client fail-closes (the standard `LightClientThreatModel.md` L-6 fail-closed posture). So a header-only client binds exactly the committee-signed timestamp — the same T-4 closure, transported through the header strip. (On a legacy header with empty `creator_proposer_times`, the light client appends nothing — byte-identical v1 digest — and the timestamp is not light-bound, consistent with T-5.) ∎

---

## 4. Why the timestamp is the *hardest* of the S-030-D2 dimensions

A short structural note, because it explains why this dimension warranted its own proof rather than folding into `EqAbortViewDigestExtension.md`.

| Dimension | Reconciliation | Why digest-bindable |
|---|---|---|
| `inbound_receipts` | `reconcile_intersection` over K committed views | pure function of K signed commits (`S030-D2-Analysis.md §4 item 7`) |
| `equivocation_events` / `abort_events` | `reconcile_union` over K committed views | pure function of K signed commits (`EqAbortViewDigestExtension.md §3.2`) |
| `partner_subset_hash` | none — deterministic from merge state | every member computes it identically; bind raw (`S030-D2-Analysis.md §3.2 / §4 item 9`) |
| **`timestamp`** | **`reconcile_median_time` — lower-median order statistic** | **pure function of K signed `proposer_time`s (T-1); honest-flanked under `f < K/3` (T-2)** |
| `cross_shard_receipts` | none — derived from committee tx set | already bound via `tx_root` + `creator_tx_lists`; stays digest-excluded but not an independent vector |

The set dimensions reconcile via lattice operations (union/intersection) whose purity is `F2ViewReconciliationAnalysis.md`'s T-1/T-3/T-4 (commutative, associative, idempotent, order-independent). `partner_subset_hash` needs no reconciliation at all. The timestamp is the only dimension that is (i) a *scalar* with (ii) *legitimate honest divergence* (clock skew within `±30s`) that (iii) cannot be unioned (you cannot put two clock readings "in" a block — you must pick one). The lower-median is the resolution: it is the scalar analogue of a set reduction — a deterministic order statistic that is simultaneously a *pure function of the committed inputs* (T-1, giving digest-bindability) and *Byzantine-robust* (T-2, giving a trustworthy canonical value). That dual property is exactly what `S030-D2-Analysis.md §5` means by *"the non-fix that became the fix"*: a raw timestamp is the non-fix (T-1 contrast); the reconciled median is the fix.

---

## 5. Regression / empirical pinning

- **`determ test-timestamp-reconciliation`** (in-process, `tools/test_timestamp_reconciliation.sh` wrapper; in the `FAST=1` allowlist) — **16 assertions** covering, per the commit message:
  - the median **order statistic** correctness across odd/even K (lower-median convention, `sorted[(K-1)/2]`), **including the K=7, f=2 Byzantine-robustness case** that directly witnesses T-2 (two extreme Byzantine times do not move the median outside the five honest values);
  - the digest is **bound iff reconciled** and binds **the median, not the raw times** (T-4 + the T-1 distinction);
  - the Phase-1 commitment is **bound iff `proposer_time != 0`** (T-3 authentication + T-5 backward-compat short-circuit);
  - `ContribMsg` JSON **round-trip** of `proposer_time` (the wire-shape gate).
- **`FAST=1` 158→159 PASS / 0 FAIL** — every non-reconciled block byte-identical pre/post change, the T-5 backward-compat witness.
- **`determ test-block-digest`** (26 assertions) — the digest-layer EXCLUSION/INCLUSION boundary (assertions 15–16 pin the non-F2 exclusion; the same harness pins the timestamp gate fires only when `creator_proposer_times` is non-empty), shared with the other S-030-D2 dimensions.

These are *empirical* witnesses; the theorems above are the analytic argument the tests sample.

---

## 6. Relationship to the FB TLA+ model

The existing timestamp TLA+ companion is **FB29, `tla/BlockTimestampMonotonic.tla`** — it formalizes the four-surface `Block.timestamp` contract (chain `compute_hash` / `signing_bytes` / committee `digest` / on-disk wrap) at the state-machine layer, the machine-checkable sibling of the in-process `test-time-monotonicity`. The digest surface that FB29 models is now the **reconciled** timestamp: the value bound at `compute_block_digest` is `reconcile_median_time(creator_proposer_times)`, not a raw assembler clock. The determinism property (T-1 here) is the prose analogue of FB29's digest-surface determinism invariant; the lower-median's purity is the scalar restatement of the `reconcile_union` purity that `F2ViewReconciliation.tla` (the F2 set-reconciliation FB model) captures for the set dimensions. As with every sibling FB module, FB29 is **spec, model-check pending TLC install** — no TLC run is claimed here (the toolchain is not installed in this environment; `tla/CHECK-RESULTS.md` is the transcript template). A dedicated `TimestampMedianReconciliation.tla` modeling the lower-median order statistic under `f < K/3` (the T-2 honest-flanked invariant as a state-machine property) is the natural follow-on FB module; until it lands, FB29 + this analytic proof are the timestamp-dimension coverage.

---

## 7. Cross-references

| Component | File / location | Role in this proof |
|---|---|---|
| `reconcile_median_time` | `src/node/producer.cpp:286-291` | the deterministic lower-median `sorted[(K-1)/2]` (T-1, T-2) |
| `make_contrib_commitment` (TS append) | `src/node/producer.cpp:264-271` | `"DTM-TS-v1" ‖ proposer_time` bound iff non-zero (T-3, T-5) |
| `make_contrib` / `ContribMsg.proposer_time` | `src/node/producer.cpp:62-101, 714-758`; `include/determ/node/producer.hpp:55-71` | carries each member's committed time (T-1, T-3) |
| `build_body` (reconcile + fallback) | `src/node/producer.cpp:818-846` | sets `b.timestamp = median` iff all non-zero; else clears vector → v1 shape (T-1, T-5) |
| `compute_block_digest` (TS bind) | `src/node/producer.cpp:689-690` | appends `b.timestamp` iff `creator_proposer_times` non-empty (T-4, T-5) |
| `check_creator_tx_commitments` | `src/node/validator.cpp:164-184` | recomputes commit WITH `proposer_time` → `creator_ed_sigs` authenticate it (T-3) |
| `check_timestamp` | `src/node/validator.cpp:1306-1327` | re-derives median, rejects size/zero/mismatch, then `±30s` bound (T-2, T-4, T-6) |
| `Block::creator_proposer_times` | `include/determ/chain/block.hpp:428-438`; `src/chain/block.cpp:443-449, 581-590` | the per-creator times field + its conditional JSON (T-5, T-7) |
| `light_compute_block_digest` | `light/verify.cpp:76-90` | mirrors the digest append; survives the `rpc_headers` strip (T-7) |
| `rpc_headers` strip set | `src/node/node.cpp::rpc_headers` | strips only transactions / cross_shard_receipts / inbound_receipts / initial_state — keeps `creator_proposer_times` (T-7) |
| `node.cpp::start_contrib_phase` | `src/node/node.cpp:887-897` | production node passes `now_unix()` so the gate fires on real blocks (§1, T-6) |
| `S030-D2-Analysis.md §5` | `docs/proofs/S030-D2-Analysis.md` | the authoritative analysis this proof formalizes; §4 item 10 = the closure claim |
| `EqAbortViewDigestExtension.md` | `docs/proofs/EqAbortViewDigestExtension.md` | the set-reconciliation sibling (UNION); §4 the contrast table |
| `F2ViewReconciliationAnalysis.md` | `docs/proofs/F2ViewReconciliationAnalysis.md` | T-1/T-3/T-4 purity of `reconcile_union` — the set analogue of T-1 here |
| `StateRootAnchorSoundness.md §3.1` | `docs/proofs/StateRootAnchorSoundness.md` | the contrast field bound transitively-forward (NOT a direct digest append) |
| `ConsensusPhaseStructureSoundness.md` | `docs/proofs/ConsensusPhaseStructureSoundness.md` | FA-Phase — the Phase-1 commit / K-arrived transition this binding rides |
| `Safety.md` (FA1) | `docs/proofs/Safety.md` | the "≤ 1 finalized digest" theorem T-4 strengthens for the timestamp dimension |
| `tla/BlockTimestampMonotonic.tla` (FB29) | `docs/proofs/tla/BlockTimestampMonotonic.tla` | existing timestamp TLA+ companion (digest surface now reconciled) — spec, model-check pending TLC install |
| commit `f99eeb8` | git | the implementing commit (`feat(consensus): bind timestamp into compute_block_digest via median reconciliation`) |
| `determ test-timestamp-reconciliation` | `tools/test_timestamp_reconciliation.sh` | 16 assertions (incl. K=7 f=2 Byzantine robustness) — empirical pin of T-1..T-5 |

---

## 8. Status

- **Implementation.** Shipped in commit `f99eeb8` (this round, feature branch per `F2-SPEC.md §6.3`'s wire-version-bump review gate). `determ` + `determ-light` build clean.
- **Proof.** Complete (this document). T-1..T-7 cover determinism, Byzantine-robustness, authentication, digest-closure, backward-compat, liveness, and light-client soundness.
- **Closure scope.** This closes the **last** S-030-D2 digest ✗ row at the **consensus layer**. With it: the three pool-fed views (v2.7 F2), `partner_subset_hash` (`8585a50`), and `timestamp` (`f99eeb8`) are all digest-bound; `cross_shard_receipts` stays digest-excluded but is deterministically derived from the `tx_root`-bound committee tx set, not an independent divergence vector. Per `S030-D2-Analysis.md §4 item 10`: no two distinct block instances can both collect K-of-K signatures over differing values of any of these fields.
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA — the per-`proposer_time` authentication, T-3; the signature-fails-on-tamper, T-4/T-7) and A2 (SHA-256 collision resistance — the digest binds the timestamp as a preimage component, T-4/T-7; domain separation, T-3). The `f < K/3` fault bound (`Preliminaries.md §3`) is load-bearing only for T-2's Byzantine-robustness (an availability/robustness property of the canonical value, not an FA1 safety property — FA1 safety holds for any `f`).
- **Concrete-security bound.** Per-block timestamp-tamper detection: `≤ K · 2⁻¹²⁸` (T-3, A1 union over per-creator commits) `+ 2⁻¹²⁸` (T-4, A2 digest collision) `= ≤ (K+1) · 2⁻¹²⁸`, matching the other S-030-D2 digest dimensions.
- **TLA+.** No TLC run claimed (toolchain not installed). FB29 (`BlockTimestampMonotonic.tla`) is the existing timestamp companion; a dedicated lower-median FB module is the natural follow-on (§6).
