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

### Why FROST closes it

A FROST aggregate `R` over a fixed message is **recomputable from ANY t-of-K
partials** (`FrostThresholdSoundness.md` T-1.1 — every t-subset that reaches
aggregation derives the *same* `R`). So a withholding minority `< K−t` cannot bias or
veto the output: the remaining `≥ t` honest members produce the identical `R`. The
last-revealer advantage disappears — there is nothing to grind, and aborting changes
nothing as long as a `t`-quorum proceeds.

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
- **Aggregate.** The producer runs
  `sig = determ_frost_aggregate(xs, t, D[], E[], partials[], msg, PK)` → `(R, z)`;
  set `delay_output := R` (or `SHA256(R ‖ z)` to keep a 32-byte field), and fold into
  `cumulative_rand` exactly as today.
- **Verify.** The validator checks `determ_frost_verify(sig, PK, msg)` — which is a
  **standard Ed25519 verification** under the epoch `PK` (`FrostThresholdSoundness.md`
  T-1). Any t-of-K quorum yields the same `R`, so all honest validators agree.

The selective-abort attack is closed; the beacon also becomes *publicly verifiable*
(a single Ed25519 sig under `PK`) rather than a K-way hash, which helps light clients
(`FrostThresholdSoundness.md` T-7).

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
evidence are all in place to make it a mechanical (if careful) integration rather than
a research task.
