# v2.10 Phase D — wiring FROST into the block-randomness path (expansion)

**Scope of this doc.** This is the detailed expansion of the single remaining v2.10
*consensus-integration* step: replacing the v1 commit-reveal block randomness with a
FROST threshold-signature aggregate, behind `GenesisConfig::v2_10_active_from_height`.
It is the "what would it actually take" companion to the sequencing in
`F2-V210-IMPLEMENTATION-PLAN.md` (the authoritative owner-doc for the consensus
schedule) and `V210ImplementationRoadmap.md` Phase B–F. The cryptographic
prerequisites (the libsodium-free C99 FROST keygen / DKG / distributed-sign /
aggregate) are **all shipped + adversarially audited** (`C99CryptoStackAudit.md`
§7/§8/§8b, `FrostThresholdSoundness.md` T-1…T-7); what remains is purely
consensus-layer plumbing. **This doc changes no code — it is the plan.**

---

## 1. What it replaces, and why

### The current v1 commit-reveal randomness (code as it stands)

Per-block randomness today is a hash-commit-reveal beacon among the K committee
members:

- **Phase 1 (commit).** Each selected creator picks a 32-byte secret
  `dh_secret = RAND_bytes(32)` (`src/node/node.cpp:838`) and publishes only its
  commitment `dh_input = SHA256(dh_secret)` inside its `ContribMsg`
  (`producer.cpp::make_contrib`).
- **Phase 2 (reveal).** Each creator reveals `dh_secret` in its `BlockSigMsg`; the
  producer verifies it against the Phase-1 commit (`node.cpp:2313–2332`,
  `pending_secrets_[signer] = dh_secret`).
- **Aggregate.** The producer computes
  `delay_seed = compute_delay_seed(index, prev_hash, tx_root, creator_dh_inputs)`
  (`producer.cpp:509`) and
  `delay_output = compute_block_rand(delay_seed, ordered_secrets)` =
  `SHA256(delay_seed ‖ s₁ ‖ … ‖ s_K)` (`producer.cpp:637–643`, called at `:808`),
  then folds it forward:
  `cumulative_rand = SHA256(prev_rand ‖ delay_output ‖ …)` (`producer.cpp:818`).
- **Consumers** of `cumulative_rand`: committee selection, the REGISTER/DEREGISTER
  activation jitter `derive_delay` (`chain.cpp:42`, `:801`, `:844`), and the
  subsidy lottery (`chain.cpp:1252`).

### The residual attack (FA3 / S-006 selective-abort)

`compute_block_rand` is `SHA256(delay_seed ‖ s₁ ‖ … ‖ s_K)`. The **last revealer**
sees the other K−1 secrets before committing its own reveal, so it can *grind* — try
candidate behaviours, or simply **abort (withhold)** — to bias the final hash
(last-revealer advantage). The commit-reveal binds each `s_i` to a Phase-1 commit, so
a revealed secret can't be *changed*, but a Phase-2 participant can still **selectively
withhold** to veto an unfavourable outcome and force a re-roll. This is the residual
bias documented as FA3 / S-006.

### What FROST changes — and the discipline it requires

The win FROST gives *for free* is **liveness**, not automatic bias-resistance — and
even that liveness is weaker than "t-of-n just works." Plain FROST is **not
drop-tolerant within a fixed signing set**: aggregation needs a partial from *every*
member of the chosen set `S` (a missing signer's private nonces `d_i, e_i` can't be
interpolated from the public commitments), so a member that commits in round 1 but
withholds its round-2 partial *stalls that attempt*. The protocol must then re-select a
different set `S'` and re-run round 1 — which, because `R = Σ_{i∈S'}(Dᵢ+[ρᵢ]Eᵢ)`
rebinds to `S'`'s commitments and fresh nonces, produces a **different `R`**. So FROST
tolerates a withholding minority `< K−t` only in the sense that the survivors can still
produce *a* valid signature (a re-rolled one with a different `R`) — removing the v1
**halt/veto** lever — **not** in the sense that any `t` reconstruct the *same* value.
(Threshold **BLS** is the scheme that genuinely absorbs up to `n−t` withholders: its
partials `σᵢ = [sᵢ]H(m)` Lagrange-interpolate to the *same unique* `σ` from any
`t`-subset; see below.) What `FrostThresholdSoundness.md` T-1.1 actually guarantees is
narrower still: once a session's round-1 commitment set is *fixed*, a member that has
already committed cannot *change* that session's `(R, z)` by withholding its round-2
partial. (Robustness wrappers like **ROAST** add liveness by multiplexing overlapping
signing sessions, but each completing session still yields its own `R` — they fix
liveness, not output-determinism.)

**But raw `R` is not an unbiasable beacon, and FROST is not BLS.** A FROST/Schnorr
signature is *randomized and non-unique*: `R = Σ_{i∈S}(Dᵢ + [ρᵢ]Eᵢ)` with
`ρᵢ = H₁(i, m, {(j,D_j,E_j)}_{j∈S})` depends on *which* subset `S` signs and on its
freshly sampled per-session nonces — so a different subset, or a re-run with fresh
nonces, yields a different valid `R`. (Threshold **BLS** — drand / DFINITY — *is* a
unique signature `σ = [s]·H(m)` and is the textbook unbiasable-beacon primitive;
Determ chose FROST to reuse the Ed25519 stack and avoid pairings — see
`v2.10-DKG-SPEC.md` Q5.) Consequently an adversary that can **steer subset selection**
(when `K > t`, influence which `t` aggregate) or **grind its own nonce** (abort after
seeing the candidate `R` and re-run) retains a last-actor bias unless the protocol
removes those degrees of freedom.

**The discipline that makes FROST-as-beacon unbiasable** (mandatory, not optional):
(1) fix a **canonical signer set** before any round-1 commitment is revealed — no
post-hoc choice among `> t` qualifying subsets (e.g. require the full committee, or a
height-deterministic subset); and (2) **bind the nonces** — keep FROST's
commit-then-reveal round-1 structure *and* forbid same-`(seed‖height)` re-signing /
enforce verifiable nonce derivation — so no member can grind `R`. Under that discipline
the per-block output is determined once the frozen commitment set is published, and the
residual reduces to the same **abort ⇒ deterministic re-roll** posture the v1 scheme
already has (handled economically by suspension slashing). Net: FROST's concrete gain
over today's commit-reveal beacon is **availability** (a withholding minority can't
stall the round); matching or beating its *bias* guarantee is a design obligation, not
a free consequence of using a threshold signature.

### Why FROST rather than a *disciplined* MPDH / PVSS / VDF beacon?

The bias-closing discipline is **largely primitive-agnostic** — most of it is *not*
FROST-specific, and the v1 commit-reveal beacon already has the core of it:

- **Anti-grinding (hiding commit)** — Determ's v1 already does this: a hiding
  `dh_input = SHA256(s_i ‖ pk_i)` revealed only in Phase 2 makes every other secret
  look uniform at decision time (FA3 / `SelectiveAbort.md` T-3, information-theoretic
  under SHA-256 preimage resistance). This is the *same* role FROST's round-1 nonce
  commitment plays. No FROST advantage.
- **Canonical contributor set** — trivially applies to any committee beacon (the
  height-deterministic committee is already fixed). No FROST advantage.
- **VDF / delay hardening** (RANDAO+VDF, Unicorn) — makes the output un-evaluable
  before the abort deadline so the last revealer can't condition on it. **Primitive-
  agnostic** — bolts onto an MPDH/commit-reveal seed exactly as onto a FROST aggregate.
  Determ *deliberately abandoned* the delay-function route (S-009: an iterated-SHA-256
  "VDF" is only as strong as the honest/ASIC hardware asymmetry, ~10¹⁰×, which collapses
  the margin) in favour of the hiding-commit structural argument.
- **PVSS reconstruction** (SCRAPE, HydRand, RandShare) — secret-share each contribution
  so a withholder's value is *reconstructed* by any `t` honest members → withholding
  gains nothing. **Applies to MPDH** — but adding it *turns the contributory beacon into
  a per-round threshold scheme*, paying a DKG-class `O(n²)` dealing+verification cost
  **every round**, versus FROST amortising one DKG (+ PSS refresh, T-6/T-7) across a
  whole epoch.

So FROST's genuine, **non-replicable** edge over a disciplined MPDH beacon is **not**
bias-resistance — it is (1) **amortisation** (one epoch-DKG + cheap 2-round signing
per block, vs per-round PVSS dealing) and (2) a **succinct, O(1)-verifiable** single
Ed25519 signature under a fixed `PK` (vs an `O(n)` re-check of all contributions). The
*one* bias property exclusive to a keyed scheme is **signature uniqueness** — a
deterministic output from public inputs + a pinned key — which makes the beacon
unbiasable *by construction*. **BLS** (drand/DFINITY) has it; **FROST/Schnorr does not**
(randomized nonces); and a **contributory MPDH beacon can *never* have it** — its output
is by definition a function of fresh per-round entropy, not of public inputs alone. That
impossibility is exactly why both FROST-as-beacon and commit-reveal need the §1
discipline, and why a true *unbiasable-by-construction* beacon means moving to a unique
threshold-VRF/BLS construction.

---

## 2. The FROST replacement (per-block protocol)

Precondition: the committee shares a FROST group key `PK` with per-member shares
`s_i`, established by an epoch-boundary DKG (Phase B/C below).

- **Phase 1 (round-1 commitments).** Each member broadcasts its FROST round-1 nonce
  commitments `(D_i, E_i)` — replaces the `dh_input` commit. (C99:
  pick `d_i, e_i`; `D_i = [d_i]B`, `E_i = [e_i]B` via `determ_ed25519_point_basemul`.)
- **Phase 2 (partial signatures).** Each member broadcasts its partial `z_i =
  determ_frost_sign_partial(xs, t, pos, s_i, d_i, e_i, D[], E[], msg, PK)` over
  `msg = beacon_seed ‖ LE64(height)` (where `beacon_seed = delay_seed`) — replaces the
  `dh_secret` reveal.
- **Aggregate.** Over the **canonical, pre-frozen signer set** (§1 — fixed before any
  round-1 reveal so it can't be chosen post-hoc), the producer runs
  `sig = determ_frost_aggregate(xs, t, D[], E[], partials[], msg, PK)` → `(R, z)`; set
  `delay_output := SHA256(R ‖ z)` (32-byte field) and fold into `cumulative_rand`
  exactly as today. Once that commitment set is published, every aggregator derives the
  identical `(R, z)`, so a member can't alter the output by withholding its round-2
  partial (T-1.1).
- **Verify.** The validator checks `determ_frost_verify(sig, PK, msg)` — a **standard
  Ed25519 verification** under the epoch `PK` (`FrostThresholdSoundness.md` T-1) — *and*
  that the signer set is the height-canonical one (so no subset substitution). Honest
  validators recomputing over the same published commitment set agree on the one
  `(R, z)`.

This converts the v1 **halt/veto** exposure into a robust round (a withholding minority
`< K−t` can't stall it). The residual *bias* (subset/nonce grinding) is closed only by
the §1 discipline — a canonical frozen signer set + bound nonces — **not** by threshold
aggregation alone. The aggregate is also a single Ed25519 sig under a fixed `PK` (vs the
v1 K-way hash), which a full node verifies in O(1) instead of re-hashing K secrets;
note this is the beacon-output step only — a light client still performs the O(K)
committee-signature checks per header either way (`FrostThresholdSoundness.md` T-1/T-7).

---

## 3. Exact code touch points (file-by-file)

| File | Change |
|---|---|
| `src/node/producer.cpp` | `compute_block_rand` (and the `build_body` `delay_output` population at `:808`) branch on `index >= v2_10_active_from_height`: below = v1 `SHA256(delay_seed ‖ secrets)`; at/above = `determ_frost_aggregate(...)`. `compute_delay_seed` stays (it is the beacon-seed input to `msg`). |
| `src/node/node.cpp` | Phase-1 `dh_secret`/commit (`:838`) → FROST round-1 `(D_i,E_i)`; Phase-2 reveal/verify (`:2313`) → collect+verify partial `z_i`; `pending_secrets_` → `pending_partials_`. The K-arrived gating in `try_finalize_round` is reused. |
| `src/node/validator.cpp` | the `delay_output` recompute/equality check → `determ_frost_verify` of the aggregate under the epoch `PK`. |
| `src/chain/block.cpp` | `ContribMsg`/`BlockSigMsg` fields: `dh_input` → round-1 commitments, `dh_secret` → partial; OR new optional fields kept zero below activation. `signing_bytes` + `compute_block_digest` binding (the digest already excludes `delay_output` per S-009; the partials/commitments need the same Phase-2-aware treatment). |
| `src/crypto/frost.cpp` | the C++ `frost_*` stubs (currently `throw "Phase A not yet implemented"`) bridge to the shipped C99 `determ_frost_*`. Impedance match: the `frost.hpp` API (`KeygenRound1Output`, `SignRound1Output`, `CommitmentMap`, …) over the C99 raw-buffer API. `frost_verify` is already real. |
| `include/determ/chain/genesis.hpp` + `genesis.cpp` | `epoch_blocks`, `dkg_round_blocks`, `v2_10_active_from_height` constants + parsing (field already declared at `genesis.hpp:216`, currently no-op). |
| `src/net/messages.hpp` + `binary_codec.cpp` + `gossip.cpp` | wire-format for the DKG ceremony messages (Phase B) + the round-1/round-2 randomness fields; a wire-version bump. |
| `new src/node/dkg.cpp` | the DKG ceremony state machine (Phase B) + epoch orchestration (Phase C). |

---

## 4. The crypto is done — the gap is the consensus layer

| Layer | Status |
|---|---|
| C99 FROST keygen / DKG / `sign_partial` / `aggregate` / `verify` | **SHIPPED + audited** (`src/crypto/frost/`, `test-frost-c99` 47 assertions, `C99CryptoStackAudit.md` §7/§8/§8b) |
| FROST construction soundness (incl. selective-abort closure) | **PROVEN** (`FrostThresholdSoundness.md` T-1…T-7) |
| Phase B — DKG ceremony wire + state machine | **NOT done** (gossip msgs, `dkg.cpp`) |
| Phase C — epoch-boundary orchestration (`epoch_public_key`) | **NOT done** |
| Phase D — the randomness-path swap above | **NOT done** (this doc) |
| Phase E — fallback (insufficient partials → v1; DKG timeout → prev-epoch keys) | **NOT done** |

So the order is **B → C → D → E**: you cannot FROST-sign a beacon without a DKG'd
group key + per-member shares first. The hard cryptographic part (the part that needed
careful from-scratch implementation + validation) is finished; what remains is
consensus-protocol plumbing + multi-node cluster testing.

---

## 5. Activation gating — the backward-compat invariant

Below `v2_10_active_from_height`, blocks MUST be **byte-identical** to v1 (no FROST
fields populated, v1 commit-reveal beacon, identical `signing_bytes`/`block_digest`).
At/above, the producer + validator switch to the FROST path. This mirrors the
already-shipped `v2_7_f2_active_from_height` gate (`genesis.hpp:208`). The new
wire fields stay zero/absent below activation so a pre-activation block's hash is
unchanged — an external client computing hashes from the v1 rules stays correct up to
the flag-day height.

---

## 6. Merge-cost reality — why this is NOT a zero-merge-cost task

Phase D touches `producer.cpp`, `node.cpp`, `validator.cpp`, `block.cpp`,
`chain.cpp`, `genesis.{hpp,cpp}`, `net/messages.hpp`, `net/binary_codec.cpp`,
`net/gossip.cpp` — **exactly the files the concurrent session is actively editing**
for its v2.7 F2 / S-030 consensus work (those files have commits within the last
day). Doing Phase D *concurrently* with that work would produce continuous merge
conflicts in the hottest files in the tree. This is the precise reason it has been
deferred throughout this session: it is the OPPOSITE of the "zero merge cost"
constraint — it is inherently in the contested consensus lane.

It is therefore best done **either** by the concurrent session (it is their lane and
they hold the live context on those files) **or** by me in a window when their
consensus work has settled (so the diffs don't collide), and it must be a single
coordinated effort (B→C→D→E) rather than interleaved.

---

## 7. Test plan

- New cluster tests (`tools/test_*.sh`, not FAST — they boot a multi-node cluster):
  R-block DKG ceremony; a silent member (partial withheld) → same `R` from the
  remaining quorum (the selective-abort regression); same-`R`-from-different-subset;
  DKG complaint/exclusion; PSS refresh across an epoch; the v1→FROST flag-day
  transition (blocks straddling `v2_10_active_from_height` validate under the right
  rule).
- Determinism: every node computes the identical `delay_output`/`cumulative_rand`
  from the same partials (the aggregate is deterministic given the commitment set).
- Migration: wire-version bump; a flag-day genesis; the existing in-process
  `determ test-*` suite still green below activation.

---

## 8. Effort + recommendation

Per `V210ImplementationRoadmap.md`: Phase B ~1–1.5 wk, Phase C ~3–5 d, Phase D ~3–5 d,
Phase E ~3–5 d, Phase F (tests/migration/docs) ~1 wk → **~3–4 weeks** of consensus
integration. The crypto (the genuinely hard, validation-heavy part) is **0 of that**
— it is done. The remaining cost is protocol plumbing + cluster testing + the
flag-day discipline.

**Recommendation:** treat B→C→D→E as one coordinated consensus effort, owned by
whoever holds the consensus lane, in a window free of competing F2/S-030 edits to the
shared files in §6. The FROST primitives + soundness proofs + the libsodium-equivalence
evidence are all in place, so most of the work is integration plumbing. The one genuine
**design** obligation (not just wiring) is the beacon-unbiasability discipline of §1 —
the canonical, pre-frozen signer set + nonce binding that a Schnorr/FROST aggregate
needs to be a sound beacon (BLS would get this for free; FROST does not). That piece
must be specified and audited, not merely coded; everything else is mechanical.

---

## 9. The simplicity tradeoff — keep MPDH, go FROST, or go BLS?

A fair reading of §1 is that **the v2.10 FROST swap is not a bias-resistance upgrade.**
The v1 MPDH commit-reveal already closes *grinding* (FA3 / `SelectiveAbort.md` T-3,
information-theoretic under SHA-256 preimage resistance) and handles *abort* via
re-roll + suspension slashing. So the honest question is whether FROST's *narrow* gains
justify its *large* added complexity.

**What staying on MPDH avoids (the simplicity case):**

- No **DKG ceremony** (Phase B): gossip messages, state machine, Feldman VSS, PoP,
  complaint/exclusion handling.
- No **epoch orchestration** (Phase C) or **PSS refresh**: no key rotation, no share
  handover on membership change.
- No **threshold-signing wire** (round-1 commitments / round-2 partials), no new
  message types, no wire-version bump.
- No **long-lived secret-share** key material — hence none of its failure modes
  (ceremony failure → stale-key reuse, below-threshold halt, PSS bugs leaving members
  shareless). The v1 beacon is *stateless*: a fresh secret per block, nothing carried
  between rounds, nothing to leak.
- No new EC/threshold assumptions — the bias defense rests only on SHA-256 preimage
  resistance.
- ~3–4 weeks of consensus integration in the hot files (§6) + multi-node cluster
  testing, avoided.

**What FROST actually buys over *disciplined* MPDH — and the honest size of each:**

- **Availability**: `t`-of-`K` liveness (with a ROAST-style wrapper) vs `K`-of-`K`, so a
  withholding minority can't stall the round. *Real*, but partly already covered by the
  v1 abort→re-roll + slashing + BFT escalation — and FROST does **not** make abort
  *bias* vanish (each re-roll is a different `R`; only BLS folds withholders into the
  *same* output).
- **Succinct verifiability**: an O(1) single Ed25519 beacon vs O(n) re-check of all
  contributions. *Real but marginal for Determ* — the light client does not re-verify
  the beacon today (it is excluded from the signed digest) and still does O(`K`)
  committee-signature checks per header regardless.

**Decision guide:**

| Goal | Choice | Cost |
|---|---|---|
| Bias defense is enough; keep it simple | **Keep MPDH** (skip v2.10) | lowest — FA3 already holds; stateless; no ceremony |
| Need withholding-minority liveness + a publicly-verifiable single-sig beacon | **FROST** (Phases B–E + §1 discipline) | ~3–4 wks + long-lived-secret failure surface |
| Need unbiasable-*by-construction* (no abort re-roll bias at all) | **Threshold BLS** | highest — pairings + DKG; the only option that delivers it |

For Determ's fork-free, permissioned/consortium-leaning posture, the simplicity case for
MPDH is strong: the current FA3 guarantee already neutralises grinding bias, and FROST
is justified mainly if `t`-of-`K` availability under committee churn becomes a hard
requirement. **FROST is a middle option that costs nearly as much as BLS but does not
deliver BLS's defining property** — so the genuine forks are *keep MPDH* (simplest) or
*go BLS* (if unbiasable-by-construction is actually required).
