# FA-Apply-19 — Randomized registration-delay unbiasability (`derive_delay` anti-grinding)

This document formalizes a security property of the staking lifecycle that the apply-layer state-machine proof (`StakeLifecycle.md`, FA-Apply-4) names but does not prove: an operator who submits a REGISTER or DEREGISTER transaction has **no exploitable control** over the resulting `active_from` (committee-eligibility onset), `inactive_from` (committee-eligibility offset), or `unlock_height` (stake-release onset). All three lifecycle anchors are computed as `height + derive_delay(b.cumulative_rand, tx.hash)`, and `derive_delay` mixes the block's `cumulative_rand` — a commit-reveal beacon value that is unpredictable at the moment the operator forms the transaction — so the operator can neither pin a chosen delay nor profitably grind the transaction over many candidate forms to bias the delay distribution away from uniform-over-`[1, REGISTRATION_DELAY_WINDOW]`.

The proof matters because the three anchors are not cosmetic. `active_from` gates when a freshly-registered validator first becomes eligible for committee selection (`registry.cpp:61`: `if (r.active_from > at_index) continue;`); `inactive_from` gates when a deregistering validator stops being eligible (`registry.cpp:62`: `if (at_index >= r.inactive_from) continue;`); and `unlock_height = inactive_from + unstake_delay_` gates when the operator's locked stake becomes withdrawable (`StakeLifecycle.md` T-K3 / T-K5). An operator who could **choose** their `active_from` could time their committee entry to coincide with a target block (selection-timing grinding); one who could **choose** their `inactive_from` could shorten the slashing-evidence window (`StakeForfeitureCascade.md` §1.1) or pull their `unlock_height` forward to escape an in-flight equivocation accusation. This proof closes the gap by reducing the no-control claim to the FA3 randomness-beacon unbiasability theorem (`SelectiveAbort.md`) plus the A3/A2 properties of SHA-256.

The proof is structural, not cryptographically novel: it composes (1) the commit-reveal beacon's no-predictive-bias property from FA3, (2) the chaining identity `cumulative_rand_h = SHA256(cumulative_rand_{h-1} ‖ delay_output_h)` from F0 V9, and (3) the SHA-256 preimage / near-uniformity assumptions from F0 §2.1 / §2.3, into an end-to-end "operator cannot grind their own lifecycle anchor" statement. No new primitive is introduced.

**Companion documents:** `Preliminaries.md` (F0) for the canonical assumption labels (A2 = SHA-256 collision / second-preimage §2.1, A3 = SHA-256 preimage §2.1, A4 = CSPRNG / near-uniformity §2.3), the validator predicate V3 (creator selection) + V9 (cumulative_rand chaining), and the commit-reveal beacon notation `R(B) = delay_output(B)`; `SelectiveAbort.md` (FA3) for T-3 — no committee member can predictively bias `R` by selective abort or non-uniform secret choice, the load-bearing input to RD-2; `StakeLifecycle.md` (FA-Apply-4) for T-K3 (DEREGISTER deferred-unlock arithmetic `unlock_height = inactive_from + unstake_delay_`) and the `derive_delay`-into-`inactive_from` write this proof analyzes; `NefPoolDrain.md` (FA-Apply-14) for the REGISTER apply branch that writes `active_from = height + derive_delay(...)` at `chain.cpp:801`; `S017UnstakeApplyConsistency.md` (the three-layer unlock-height enforcement) §6.2 for the PARAM_CHANGE-of-`UNSTAKE_DELAY` interaction that RD-5 composes against; `S020CommitteeSelection.md` (S-020) for the committee-selection seed-grinding adversary `A_seed_grind` whose registration-side analogue this proof rules out; `StakeForfeitureCascade.md` (FA-Apply-16) §1.1 for the deferred-unlock window as the slashing-evidence window that RD-4 protects; `docs/SECURITY.md` §S-009 (delay-hash removal) for the historical provenance of the `cumulative_rand` beacon; `docs/PROTOCOL.md` §3.3 for the apply rules and §6 for the committee-selection derivation.

---

## 1. Setup

### 1.1 The `derive_delay` helper

Per `src/chain/chain.cpp:42–47`:

```cpp
// Compute the randomized 1..REGISTRATION_DELAY_WINDOW delay, deterministically
// derived from the block's cumulative_rand and the tx hash so all nodes agree
// and the operator can't pick their own activation height.
static uint64_t derive_delay(const Hash& cumulative_rand, const Hash& tx_hash) {
    Hash seed = sha256(tx_hash, cumulative_rand);
    uint64_t v = 0;
    for (int b = 0; b < 8; ++b) v = (v << 8) | seed[b];
    return 1 + (v % REGISTRATION_DELAY_WINDOW);
}
```

with `REGISTRATION_DELAY_WINDOW = 10` (`include/determ/node/registry.hpp:15`, duplicated as a `static constexpr` at `chain.cpp:26` so the apply path needs no registry-header dependency). Writing `W := REGISTRATION_DELAY_WINDOW = 10`, `H := SHA-256`, and `lead8(x)` for the big-endian decode of the leading 8 bytes of a 32-byte digest, the helper computes

$$
\texttt{derive\_delay}(\rho, \tau) \;=\; 1 + \big(\,\texttt{lead8}\big(H(\tau \,\|\, \rho)\big) \bmod W\,\big) \;\in\; \{1, 2, \ldots, W\},
$$

where `ρ = b.cumulative_rand` is the enclosing block's cumulative randomness and `τ = tx.hash` is the registering / deregistering transaction's hash. The output range is exactly `[1, W]` — never `0`, so every anchor is strictly in the future of the block in which the transaction applies (this is the `1 +` term; see RD-1).

### 1.2 The two consumption sites

`derive_delay` is consumed at exactly two apply-branch sites, both keyed on the same `(b.cumulative_rand, tx.hash)` pair:

1. **REGISTER** (`chain.cpp:801`, inside the `NefPoolDrain.md` FA-Apply-14 branch):
   ```cpp
   e.active_from   = height + derive_delay(b.cumulative_rand, tx.hash);
   e.inactive_from = UINT64_MAX;
   ```
   The freshly-built `RegistryEntry` gets `active_from` set `1..W` blocks past the REGISTER's own block height. Until that height the registrant is filtered out of every committee by `registry.cpp:61`.

2. **DEREGISTER** (`chain.cpp:844–851`, inside the `StakeLifecycle.md` FA-Apply-4 T-K3 branch):
   ```cpp
   uint64_t inactive_from = height + derive_delay(b.cumulative_rand, tx.hash);
   rit->second.inactive_from = inactive_from;
   // ...
   sit->second.unlock_height = inactive_from + unstake_delay_;
   ```
   The deregistering validator's `inactive_from` is set `1..W` blocks past the DEREGISTER's block height, and the stake's `unlock_height` chains off that value plus the genesis-pinned `unstake_delay_`.

No other call site exists (`Grep "derive_delay" src/` returns the definition plus these two writes — the only third occurrence at `chain.cpp:1246` is a textual comment in the unrelated LOTTERY subsidy branch, not a call). The proof's scope is therefore exactly these two writes and the helper they share.

### 1.3 The randomness source: `cumulative_rand`

`b.cumulative_rand` is **not** an operator-supplied field. Per F0 V9 (`Preliminaries.md` §V9), it chains forward across blocks:

$$
\texttt{cumulative\_rand}_h \;=\; H\big(\texttt{cumulative\_rand}_{h-1} \,\|\, \texttt{delay\_output}_h\big),
$$

and `delay_output_h = R(B_h)` is the commit-reveal beacon of block `h`:

$$
R(B_h) \;=\; H\big(\texttt{delay\_seed}(B_h) \,\|\, s_{\sigma(1)} \,\|\, \cdots \,\|\, s_{\sigma(K)}\big),
$$

where the `s_{σ(i)}` are the K committee members' Phase-2 secret reveals in committee-selection order (`Preliminaries.md` §"R(B)"). The beacon is the subject of FA3 (`SelectiveAbort.md`): **no single committee member can predictively bias `R`** (FA3 T-3), because at least one honest member's unrevealed secret is uniform and entropic at Phase-1 commit time, and the commit-reveal binding (V5) prevents any member from choosing their reveal as a function of the others'.

The operator who submits a REGISTER/DEREGISTER transaction is, in the general case, **not** a member of the committee that produces the block in which their transaction lands — and even if they are, FA3 T-3 denies them predictive control over `R`. This is the structural fact RD-2 turns into the no-grinding claim.

### 1.4 The adversary

`A_op` is a **registration-grinding operator**: a single domain (or a small Sybil cluster bounded by the S-010/S-011 economics) that wants to influence the `active_from` / `inactive_from` / `unlock_height` of its own registry entry. `A_op` may:

- choose the transaction's mutable fields freely (nonce within the strict-equality gate, fee, the 32-byte ed_pub payload for REGISTER, the region string) — every such choice changes `tx.hash = τ` and therefore the `derive_delay` input;
- submit, withhold, or re-submit the transaction across many candidate heights;
- observe the full public chain, including all committed `cumulative_rand` values up to the current head;
- collude with up to `f < K/3` committee members (the BFT-mode honest-majority bound of FA5/`BFTSafety.md`) or, in mutual-distrust mode, up to `K-1` of the K members (FA1/`Safety.md`).

`A_op` may NOT: break SHA-256 preimage resistance (A3) or collision resistance (A2); predict an honest committee member's Phase-1 secret before its Phase-2 reveal (the FA3 commitment-hiding property); or forge the committee selection (V3 is deterministic and re-derived by every validator). Out of scope identically to FA3: `A_crypto` (the proof rests on A2/A3/A4 holding) and `A_genesis` (a tampered genesis that sets `W = 1` is an operator-trust question, not a grinding attack — see §5).

---

## 2. Theorems

### RD-1 — Anchors are strictly future-dated and range-bounded

**Statement.** For every REGISTER transaction applied at block height `h`, the resulting `active_from ∈ [h+1, h+W]`. For every DEREGISTER transaction applied at block height `h` against a registered domain, the resulting `inactive_from ∈ [h+1, h+W]` and `unlock_height = inactive_from + unstake_delay_ ∈ [h+1+unstake_delay_, h+W+unstake_delay_]`. In particular every anchor is strictly greater than the block height that produced it (no same-block activation, no same-block deactivation, no zero-delay unlock).

*Proof.* `derive_delay` returns `1 + (v mod W)` with `v ≥ 0` and `W = 10 > 0`, so its output lies in `{1, …, W}` for every input — the `1 +` guarantees the minimum is `1`, the `mod W` guarantees the maximum is `W`. Adding `height = h` gives `active_from`/`inactive_from ∈ [h+1, h+W]`. The `unlock_height` range follows by adding the non-negative `unstake_delay_` to both endpoints. Since `W ≥ 1`, the minimum anchor `h+1 > h`. ∎

**Code witness.** `src/chain/chain.cpp:46` (the `1 + (v % W)` form); `chain.cpp:801` (REGISTER `active_from`); `chain.cpp:844–851` (DEREGISTER `inactive_from` + `unlock_height`).

**Significance.** RD-1 is the structural reason an operator cannot register and immediately self-select into the *current* block's committee: V3 committee selection at height `h` draws from `eligible_in_region(h)`, which by `registry.cpp:61` excludes any registrant with `active_from > h`. A registrant minted at `h` has `active_from ≥ h+1 > h`, so it is never eligible for its own registration block. Symmetrically a DEREGISTER at `h` cannot drop the validator out of block `h`'s already-fixed committee.

### RD-2 — Operator cannot predict the realized delay

**Statement.** Let `A_op` choose a candidate transaction form `τ` (any combination of nonce/fee/payload/region consistent with admission) **before** the block `B_h` carrying it is finalized — equivalently, before `cumulative_rand_h` is determined. Then `A_op`'s probability of correctly predicting `derive_delay(cumulative_rand_h, τ)` is at most `1/W + negl(λ)`, i.e. no better than guessing uniformly over the `W` outcomes, under A3 (SHA-256 preimage / RO behavior) and FA3 T-3 (beacon unbiasability).

*Proof.* The realized delay is `1 + (lead8(H(τ ‖ ρ)) mod W)` with `ρ = cumulative_rand_h`. Fix `τ` (the operator's chosen form). The delay is a deterministic function of `ρ`. Two cases:

- **`A_op` is not a member of the height-`h` committee** (or is but does not control all reveals). By V9, `ρ = H(cumulative_rand_{h-1} ‖ delay_output_h)`, and `delay_output_h = R(B_h)` is the FA3 beacon. By FA3 T-3, the distribution of `R(B_h)` conditioned on everything `A_op` knows at transaction-formation time is computationally indistinguishable from uniform over the digest space (the honest member's unrevealed secret supplies fresh entropy that `A_op` cannot predict before Phase-2). Hashing a near-uniform `ρ` (after the further `H(cumulative_rand_{h-1} ‖ ·)` chaining, which is preimage-binding under A3) with the fixed `τ` yields `H(τ ‖ ρ)` indistinguishable from a uniform 32-byte string by the random-oracle modeling of A3. Then `lead8(·) mod W` is within statistical distance `≤ W / 2^{64} < 2^{-60}` of uniform over `{0, …, W-1}` (A4 near-uniformity of a modular reduction of a 64-bit uniform value; the modulus `W = 10` does not divide `2^{64}` but the bias is bounded by `W·2^{-64}`). So the realized delay is `negl`-close to uniform over `{1, …, W}`, and any predictor wins with probability `≤ 1/W + negl(λ)`.

- **`A_op` controls the entire height-`h` committee** (the all-Byzantine-committee case). Then `A_op` *can* compute `R(B_h)` once all K reveals are fixed — but only at Phase-2, which is *after* `A_op` had to commit the transaction's `τ` (the transaction must already be in the mempool / Phase-1 block body to be included). More importantly, this case is the consensus-safety question, not a grinding question: an all-Byzantine committee at a single height can already do far worse (forge the whole block), and is ruled out by the honest-fraction assumptions of FA1 (K-of-K mutual-distrust: any one honest member suffices) and FA5 (`f < K/3`). Under the standing honest-fraction assumption this case does not arise; we flag it for completeness and defer to FA1/FA5 for the safety bound.

In the in-scope (honest-fraction) case, prediction is no better than uniform guessing. ∎

**Code witness.** `src/chain/chain.cpp:43` (`H(τ ‖ ρ)`); the beacon construction is cited from `Preliminaries.md` §"R(B)" + V9; the unbiasability is `SelectiveAbort.md` T-3.

### RD-3 — Grinding the transaction form yields no profitable bias

**Statement.** Suppose `A_op` is willing to try `t` distinct candidate transaction forms `τ_1, …, τ_t` (varying nonce/fee/payload/region) and pick whichever yields a most-favorable delay. If the candidates are committed *before* `cumulative_rand_h` is fixed (the realistic case, since all candidates compete for inclusion at the same height with the same `ρ`), `A_op` gains at most a negligible advantage over a single submission. If `A_op` instead spreads candidates across `t` distinct future heights `h_1 < … < h_t` (each with its own independent `ρ_j`), the best-of-`t` delay is the minimum (or maximum, per the attack goal) of `t` near-uniform `[1,W]` draws, but **each retry costs a full transaction fee and a block of latency**, and the resulting distribution still has full support on `[1,W]` — so no specific target delay is reachable with certainty.

*Proof.* Two grinding modes:

- **Same-height grinding.** All candidates `τ_j` for inclusion at height `h` are hashed against the *same* `ρ = cumulative_rand_h`. By RD-2, each `derive_delay(ρ, τ_j)` is near-uniform over `[1,W]`, and (modeling `H` as a random oracle per A3) the `t` outputs are independent across distinct `τ_j` (distinct first-arguments to `H` give independent oracle outputs). So `A_op` does get `t` independent draws — but only **one** transaction can actually be included for a given `(from, nonce)` (the strict-equality nonce gate, FA-Apply-3 / `NonceMonotonicity.md`, admits exactly one transaction per nonce slot per applied block). `A_op` must therefore decide *which* `τ_j` to broadcast before knowing `ρ` (the producer fixes `ρ` only at finalize). Conditioned on the pre-`ρ` choice, the realized delay is a single near-uniform draw (RD-2). The other `t-1` candidates are never applied. Advantage over a single submission: `negl(λ)`.

- **Cross-height grinding.** `A_op` submits, observes the realized delay, and if unfavorable submits again at a later height with a fresh `ρ_{h_{j+1}}`. This *does* let `A_op` resample, at a cost of one fee + one block per retry. The number of retries to hit a *specific* target delay `d*` is geometric with success probability `≈ 1/W`, so expected `W = 10` retries (10 fees, 10 blocks of latency) per targeted REGISTER, and the operator still cannot *guarantee* `d*` in bounded tries. For DEREGISTER the resampling is strictly self-defeating against the slashing-window goal: see RD-4. The economic cost (a fee per retry, S-010/S-011 stake pricing per Sybil identity) plus the unbounded-in-the-worst-case latency makes targeted grinding non-profitable for any realistic objective; the chain does not promise *zero* resampling, it promises *no free, deterministic* control. ∎

**Code witness.** `src/chain/chain.cpp:43` (per-`τ` independence via the `H(τ ‖ ρ)` first-argument); `src/chain/chain.cpp:739` (the strict-equality nonce gate that admits one tx per nonce slot, shared with `NonceMonotonicity.md`).

**Significance.** RD-3 is the registration-side analogue of the `A_seed_grind` adversary that `S020CommitteeSelection.md` (S-020) rules out for committee *selection*: there, an operator cannot grind the committee seed to self-select; here, an operator cannot grind their *registration delay* to time their selection-eligibility onset. The two together close the "operator-controlled selection timing" surface end-to-end.

### RD-4 — DEREGISTER cannot shorten the slashing-evidence window

**Statement.** A deregistering operator cannot use `derive_delay`'s randomness to *minimize* the time their stake remains slashable. The slashing-evidence window is `[registered_at, unlock_height)` with `unlock_height = inactive_from + unstake_delay_` and `inactive_from = h_d + derive_delay(...)` for DEREGISTER at height `h_d`. Since `derive_delay ≥ 1`, the minimum achievable `unlock_height` over all transaction forms is `h_d + 1 + unstake_delay_`, and the operator cannot drive it below that floor — in particular cannot make the stake unlockable in the same block as the DEREGISTER, nor skip the `unstake_delay_` cooldown.

*Proof.* By RD-1, `inactive_from ≥ h_d + 1` for every transaction form (the `1 +` floor in `derive_delay`). The `unstake_delay_` term is added unconditionally (`chain.cpp:851`) and is genesis-pinned (not operator-controlled), so `unlock_height ≥ h_d + 1 + unstake_delay_`. The randomness can only *lengthen* the window (up to `h_d + W + unstake_delay_`), never shorten it below the `+1+unstake_delay_` floor. By RD-2/RD-3 the operator cannot even reliably *hit* the `+1` minimum — the realized `inactive_from` is near-uniform on `[h_d+1, h_d+W]`. The slashing branches (`StakeForfeitureCascade.md` FA-Apply-16, `EquivocationSlashingApply.md` FA-Apply-10) consume `stakes_[d].locked` for any evidence height `< unlock_height` and do **not** consult `inactive_from`'s exact value, so an operator who races a DEREGISTER ahead of an in-flight equivocation accusation still leaves their stake forfeitable for the full `[h_d+1+unstake_delay_]`-floored window. ∎

**Code witness.** `src/chain/chain.cpp:851` (`unlock_height = inactive_from + unstake_delay_`); `chain.cpp:46` (the `1 +` floor); the slashing-window semantics are `StakeForfeitureCascade.md` §1.1 + `StakeLifecycle.md` §4.

**Significance.** This is the security-relevant payload of the whole proof. If the operator could pick `derive_delay = 0` (or grind it toward `0`), an equivocator could DEREGISTER the instant they sense an accusation forming and pull `unlock_height` forward to escape the slash. RD-1's `1 +` floor plus RD-2's unpredictability plus the unconditional `unstake_delay_` add jointly forbid this: the window has a hard floor and a randomized (never operator-shortened) length.

### RD-5 — PARAM_CHANGE of the window does not retro-bias committed anchors

**Statement.** `REGISTRATION_DELAY_WINDOW` is a compile-time constant (`registry.hpp:15` / `chain.cpp:26`), not an A5 PARAM_CHANGE-whitelisted parameter, so it cannot be mutated at runtime at all. `unstake_delay_` *is* A5-mutable (`Governance.md` FA10), but a PARAM_CHANGE to `unstake_delay_` after a DEREGISTER has committed does **not** retroactively alter the already-written `stakes_[d].unlock_height`. Therefore neither the window bound nor the cooldown can be grinding-exploited via governance to retro-shift a committed lifecycle anchor.

*Proof.* `W` is `static constexpr`; the apply path reads it as a literal with no chain-state indirection (`chain.cpp:46`), so no transaction, no PARAM_CHANGE, and no operator action can change `W` for a running chain — it is fixed at build time and bound into the genesis hash via the binary's identity (S-039 genesis-param binding). For `unstake_delay_`: `chain.cpp:851` writes `unlock_height = inactive_from + unstake_delay_` **at DEREGISTER apply time**, capturing the then-current `unstake_delay_` into the per-domain `StakeEntry`. The three-layer enforcement gate (`S017UnstakeApplyConsistency.md` T-1/T-2/T-3) reads the *stored* `stakes_[d].unlock_height`, not the live `unstake_delay_` parameter, so a subsequent PARAM_CHANGE to `unstake_delay_` (which requires N-of-N keyholder threshold, FA10) affects only *future* DEREGISTERs and leaves committed anchors immutable. This is exactly the §6.2 robustness property of `S017UnstakeApplyConsistency.md`, here re-stated as the anti-grinding corollary: the operator cannot collude with governance to retro-shorten an in-window stake's `unlock_height`. ∎

**Code witness.** `include/determ/node/registry.hpp:15` + `src/chain/chain.cpp:26` (`W` as `static constexpr`); `src/chain/chain.cpp:851` (capture-at-DEREGISTER of `unstake_delay_`); the gate-reads-stored-value property is `S017UnstakeApplyConsistency.md` §6.2.

### RD-6 — Determinism: every honest node agrees on the realized anchor

**Statement.** For a fixed applied block sequence, every honest node computes byte-identical `active_from` / `inactive_from` / `unlock_height` for every domain. The randomized delay is *deterministic given the block* — it is randomized only with respect to the operator's *ex-ante* knowledge, not with respect to *ex-post* replay.

*Proof.* `derive_delay(ρ, τ)` is a pure function of `(ρ, τ)`. `ρ = b.cumulative_rand` is a committed block field that every node that has applied `B_{h-1}` and validated `B_h` agrees on (V9 chaining is deterministic; the beacon `R(B_h)` is fixed once the K reveals are in the block body). `τ = tx.hash` is the transaction's content hash, identical across nodes. SHA-256 is deterministic. Hence the helper's output, and the anchors derived from it, are byte-identical across honest nodes and across snapshot-restore replays (`SnapshotEquivalence.md` FA-Apply-2 carries `active_from` / `inactive_from` / `unlock_height` via the `r:` and `s:` state-root namespaces; `S033StateRootNamespaceCoverage.md` §2.1). The randomness is "unpredictable to the operator at submission" but "fully determined and agreed-upon after finalization" — the standard commit-reveal posture. ∎

**Code witness.** `src/chain/chain.cpp:42–47` (pure function); `chain.cpp:303–304` (`active_from` / `inactive_from` committed into the `r:` state-root leaf via `build_state_leaves`); `chain.cpp:292–297` (`unlock_height` committed into the `s:` leaf).

---

## 3. Why this is not redundant with FA3 / S-020

FA3 (`SelectiveAbort.md`) proves the *beacon* is unbiasable. S-020 (`S020CommitteeSelection.md`) proves the *committee seed* cannot be ground to self-select. Neither addresses the *registration delay*: FA3 stops at "`R` is uniform," and S-020 assumes a fixed eligible pool and analyzes selection *within* it. The present proof bridges the two — it shows that the *onset* and *offset* of a validator's membership in the eligible pool are themselves randomized by the same beacon, so an operator cannot manufacture a favorable selection *timing* by controlling when their entry enters or leaves eligibility. Concretely:

- Without RD-2/RD-3, an operator could compute "if I register such that `active_from = h*`, I land in committee `h*`'s pool at the moment the seed favors me." RD-2 denies the operator control over `active_from`, so this composed grind collapses — the operator faces a fresh near-uniform `active_from` regardless of transaction form.
- Without RD-4, the slashing-window analysis of `StakeForfeitureCascade.md` would have a hole: it assumes the deferred-unlock window has a hard lower bound. RD-4 supplies that bound and proves the operator cannot erode it.

The proof is also distinct from `StakeLifecycle.md` (FA-Apply-4), which *states* the deferred-unlock arithmetic and notes parenthetically that "the operator cannot pre-pick" the height, but proves only the apply-time *state-machine* correctness (T-K1..T-K7), not the *unbiasability* of the randomness feeding it. RD-1..RD-6 are the unbiasability theorems FA-Apply-4 defers.

---

## 4. Adversary table

| Adversary | Goal | Defeated by | Residual |
|---|---|---|---|
| `A_op-predict` | Predict realized `active_from` / `inactive_from` to time committee entry | RD-2 (near-uniform over `[1,W]` under A3 + FA3 T-3) | `≤ 1/W + negl` guess probability |
| `A_op-same-height-grind` | Hash many `τ_j` against one `ρ`, include the best | RD-3 same-height case (one tx per nonce slot; choice fixed before `ρ`) | `negl` advantage |
| `A_op-cross-height-grind` | Resample across heights for a target delay | RD-3 cross-height case (one fee + one block per retry; full support, no certainty) | economic + latency cost; no deterministic target |
| `A_op-deregister-race` | DEREGISTER to pull `unlock_height` forward, escape an in-flight slash | RD-4 (`1 +` floor + unconditional `unstake_delay_`; slash ignores `inactive_from`) | none — window has hard floor |
| `A_op-zero-delay` | Activate / deactivate / unlock in the same block | RD-1 (`derive_delay ≥ 1`) | none |
| `A_op-governance` | PARAM_CHANGE the window/cooldown to retro-shift a committed anchor | RD-5 (`W` is `constexpr`; `unstake_delay_` captured-at-DEREGISTER) + FA10 N-of-N | none for committed anchors |
| `A_op-fork-disagree` | Get honest nodes to disagree on the realized anchor | RD-6 (pure function of committed block fields; determinism) | none |
| `A_full_byzantine_committee` | Control all K reveals at the target height to fix `R` | out of scope — FA1 (K-of-K) / FA5 (`f < K/3`) | consensus-safety question, not grinding |

The two honest residuals (`A_op-cross-height-grind`'s resampling cost, and the all-Byzantine-committee deferral) are the same residuals FA3 carries: the chain promises *no free deterministic control*, not *zero resampling*, and assumes an honest committee fraction.

---

## 5. What this doesn't prove

- **Genesis honesty.** A genesis that ships a binary with `W = 1` collapses the delay to a constant `1`, eliminating the randomization (every anchor becomes exactly `h+1`). This is not a grinding attack — it is an operator-trust question about which binary / genesis the node runs, covered by S-039 (genesis-param binding into the genesis hash) and the operator's out-of-band binary verification. The proof assumes the standard `W = 10`.
- **Beacon unbiasability itself.** RD-2 *consumes* FA3 T-3 as a black box. The proof that the commit-reveal beacon `R` is unbiasable is FA3's scope; a regression that weakened the commit-reveal binding (V5) or removed the honest-member entropy would invalidate RD-2's first case, and is caught by FA3's regressions, not this proof's.
- **Selection fairness within the eligible pool.** Once a validator's `active_from` has passed and it is in the eligible pool, *which* committees it is selected into is the stake-weighted Fisher-Yates selection of S-020. This proof covers the *timing* of pool membership, not the *selection probability* within it.
- **The apply-time state machine.** That REGISTER correctly writes `active_from` and DEREGISTER correctly writes `inactive_from` / `unlock_height` (as opposed to leaving them stale or mis-ordered) is `StakeLifecycle.md` T-K3 + `NefPoolDrain.md`. RD-1..RD-6 take the *write* as given and analyze the *value* written.
- **Sybil amplification.** An operator running `N` Sybil domains gets `N` independent near-uniform delays, one per domain. This does not help target a single domain's delay (each is independent), and the cost of `N` registrations is the S-010/S-011 stake-pricing floor. Cross-Sybil delay correlation is `negl` because each domain's `τ` differs.

---

## 6. Cross-references

| Reference | Role |
|---|---|
| `Preliminaries.md` (F0) | A2/A3/A4 assumption labels; V3 (creator selection); V9 (`cumulative_rand` chaining); `R(B) = delay_output` beacon notation. |
| `SelectiveAbort.md` (FA3) | T-3 — no committee member predictively biases `R`; the load-bearing input to RD-2. |
| `StakeLifecycle.md` (FA-Apply-4) | T-K3 DEREGISTER deferred-unlock arithmetic; the `derive_delay`-into-`inactive_from` write whose unbiasability RD-2..RD-4 prove (FA-Apply-4 states the "operator cannot pre-pick" claim; this proof discharges it). |
| `NefPoolDrain.md` (FA-Apply-14) | The REGISTER apply branch (`chain.cpp:801`) that writes `active_from = height + derive_delay(...)`. |
| `S017UnstakeApplyConsistency.md` | §6.2 PARAM_CHANGE-of-`unstake_delay_` robustness that RD-5 re-states as the anti-grinding corollary; the three-layer gate reads stored `unlock_height`. |
| `StakeForfeitureCascade.md` (FA-Apply-16) | §1.1 deferred-unlock window as the slashing-evidence window that RD-4 protects with a hard floor. |
| `EquivocationSlashingApply.md` (FA-Apply-10) | Slashing branch that consumes `stakes_[d].locked` for evidence `< unlock_height` and ignores `inactive_from`'s exact value (RD-4). |
| `S020CommitteeSelection.md` (S-020) | The `A_seed_grind` committee-selection adversary; RD-3 is its registration-side analogue. |
| `BFTSafety.md` (FA5) / `Safety.md` (FA1) | Honest-fraction bounds ruling out the all-Byzantine-committee case in RD-2 / the adversary table. |
| `SnapshotEquivalence.md` (FA-Apply-2) | Carries `active_from` / `inactive_from` / `unlock_height` across snapshot restore via the `r:` + `s:` namespaces (RD-6). |
| `S033StateRootNamespaceCoverage.md` (S-033) | §2.1 `r:` / `s:` leaf encodings binding the anchors to the committee-signed `state_root`. |
| `Governance.md` (FA10) | A5 PARAM_CHANGE N-of-N keyholder threshold for `unstake_delay_` (RD-5). |
| `docs/SECURITY.md` §S-009 | Delay-hash removal; provenance of the `cumulative_rand` beacon used by `derive_delay`. |
| `docs/PROTOCOL.md` §3.3 | Apply rules for REGISTER / DEREGISTER (randomized `active_from` / `inactive_from`). |
| `docs/PROTOCOL.md` §6 | Committee-selection derivation (V3) that `active_from` gates eligibility for. |
| `src/chain/chain.cpp:42–47` | `derive_delay` helper (RD-1, RD-2, RD-6). |
| `src/chain/chain.cpp:26` + `include/determ/node/registry.hpp:15` | `REGISTRATION_DELAY_WINDOW = 10` as `static constexpr` (RD-1, RD-5). |
| `src/chain/chain.cpp:801` | REGISTER `active_from` write. |
| `src/chain/chain.cpp:844–851` | DEREGISTER `inactive_from` + `unlock_height` writes. |
| `src/chain/chain.cpp:292–297` | `s:` leaf binding `unlock_height` (RD-6). |
| `src/chain/chain.cpp:303–304` | `r:` leaf binding `active_from` / `inactive_from` (RD-6). |
| `src/node/registry.cpp:61–62` | `eligible_in_region` filters on `active_from > at_index` and `at_index >= inactive_from` — the gates the anchors control. |
| `src/chain/chain.cpp:739` | Strict-equality nonce gate (one tx per nonce slot; RD-3 same-height case). |
| `tools/test_randomized_delay.sh` / `determ test-randomized-delay` | Exercises the `derive_delay` range + determinism (RD-1, RD-6); the in-process unit test pins `derive_delay ∈ [1,W]` and replay-identity. |
| `tools/test_unstake_deregister_apply.sh` | DEREGISTER scenario asserting `inactive_from > height` and `unlock_height = inactive_from + unstake_delay` (RD-1, RD-4). |

---

## 7. Status

All six theorems (RD-1 through RD-6) are closed in the current codebase:

- **RD-1** (future-dated, range-bounded anchors) closed via the `1 + (v % W)` form at `chain.cpp:46`.
- **RD-2** (unpredictability) closed by reduction to FA3 T-3 (`SelectiveAbort.md`) + A3 + V9 chaining, in the honest-committee-fraction case.
- **RD-3** (no profitable grinding) closed via the per-`τ` random-oracle independence + the one-tx-per-nonce-slot gate (same-height) + the per-retry economic/latency cost (cross-height).
- **RD-4** (slashing window not shortenable) closed via the `1 +` floor + the unconditional `unstake_delay_` add + the slash branch's insensitivity to `inactive_from`.
- **RD-5** (no governance retro-bias) closed via `W` being `static constexpr` + the capture-at-DEREGISTER of `unstake_delay_` into the stored anchor.
- **RD-6** (determinism) closed via `derive_delay` being a pure function of committed block fields + the `r:` / `s:` state-root binding.

No theorem is open or partial. The proof introduces no new code and no new cryptographic assumption: it composes FA3 (beacon unbiasability), the F0 V9 chaining identity, and the SHA-256 assumptions A2/A3/A4 into the registration-delay anti-grinding guarantee that `StakeLifecycle.md` (FA-Apply-4) and `StakeForfeitureCascade.md` (FA-Apply-16) both rely on but neither establishes. The single residual — cross-height resampling at a fee + latency cost per retry — is the same "no free deterministic control, but resampling is not forbidden" posture FA3 carries for the beacon itself, and is economically bounded by the S-010/S-011 stake-pricing floor on Sybil identities.
