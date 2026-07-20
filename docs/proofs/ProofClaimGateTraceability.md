# Proof-claim → gate traceability — the verified/aspirational boundary

**Status: AUDIT SHIPPED (register of gaps; remediation increments owner-gated).**
This document records a systematic answer to one question the SBOM round taught
us to ask of every claim in this repo:

> Which numbered claims in `docs/proofs/` are asserted but **not enforced by any
> executable gate** — i.e. which properties could silently regress with the whole
> suite staying green?

It is the KISS directive ("a small green VERIFIED surface beats a large
aspirational one") applied to the proof corpus itself, and the direct
generalization of the [MinixSBOM](MinixSBOM.md) lesson: *a recorded claim that no
ratchet checks is prose, and a check that cannot fail certifies nothing.*

## 1. Method

- **Scope.** The 92 security-property docs (`*Soundness*`, `*Safety*`,
  `*Integrity*`, `*Invariant*`, `*Parity*`, `*Conservation*`, `*Dedup*`,
  `*Isolation*`, `*Commitment*`, `*Determinism*`, `*Canonical*`) out of 209 proof
  docs — the set where an unenforced claim actually costs something.
- **Tracers.** 12 parallel agents, 8 docs each. For every numbered claim: decide
  whether it is *mechanically checkable*, then hunt for the gate that enforces it
  across the ~486 `tools/test_*.sh` wrappers, the `determ` / `determ-wallet` /
  `determ-light` test subcommands, the offline doc guards, and the
  `tools/vectors/` golden corpora. Explicit non-claims (`NC-*`), design
  rationale, and threat-model narrative were excluded by construction.
- **Adversarial verification.** Every candidate gap went to an independent
  verifier whose **default verdict was REFUTED** — instructed to assume the
  property IS enforced and to search harder and differently, and to credit
  *indirect* coverage (a golden byte-vector that pins a digest, a round-trip
  test that pins a codec, a live cluster that pins liveness) as genuine
  enforcement. A gap is CONFIRMED only when the verifier could name the exact
  mutation that would pass every existing gate.
- **Cost.** 87 agents, ~12.9M tokens.

## 2. Result

**64 confirmed unenforced claims: 14 HIGH, 39 MEDIUM, 11 LOW.** The corpus is
large and mostly well-gated; these are the residue that survived an
assume-it-is-enforced verifier.

The HIGH set — each with a verifier-supplied mutation that leaves every gate
green:

| Claim | Doc | Silently deletable check |
|---|---|---|
| **T-C1, T-C3, T-C4, T-C5** | AbortCertificateSoundness | the abort-certificate quorum in `validator.cpp::check_abort_certs` — per-claim Ed25519 verify, exact `max(2,K-1)` count, `aborting_node ∈ selected set`, and the round/block_index field binding |
| PE-4 | BFTProposerElectionSoundness | `b.bft_proposer != b.creators[expected_idx]` reject |
| T-1, T-2 | S025BFTEscalationSoundness | the `bft_enabled_` genesis guard and the escalation-threshold arm in `check_block_sigs` |
| AL-3 | AuditLayerSoundness | the `default:` unknown-tx-type reject in `check_transactions` |
| SR-5 | ShardRoutingSoundness | the receipt `dst_shard` mismatch reject |
| ~~GW-2~~ **CLOSED** | GovernanceWhitelistSoundness | the exact-width `value.size() != 8` decode guard — **gate shipped**, see §3a |
| CR-2, RP-3, SU-2 | CompositeStateRead / RegistrantProof / SupplyProof | the light client's **value-hash cleartext cross-check** (three separate call sites) |
| WH-2 | WaitHoldAndWaitSoundness | (verified by an *executed* mutant build, not inspection) |

## 3. The top gap, independently re-verified

The four-claim **abort-certificate cluster is the highest-value gap** and was
re-verified by hand rather than taken on the agents' word:

- `check_abort_certs` (`src/node/validator.cpp:232`) carries ~13 distinct reject
  paths and is the last line of defense against a **forged abort certificate**,
  whose consequence is consensus-level *false suspension-slashing of an honest
  validator*.
- It has **no negative test**. Measured, not asserted: of 31
  `abort_events.push_back` sites in `src/main.cpp`, **zero** have a `validate()`
  call within ±40 lines; of 68 `BlockValidator` sites, **zero** touch
  `abort_events` in the following 120 lines.
- The two witnesses the doc and `proofs/README.md` name —
  `test-block-validator-basic` and `test-block-validator-extensive` (whose help
  text advertises "V1..V20 gate-by-gate") — contain the substring "abort" once
  (a header comment) and zero times respectively.
- The genuinely indirect coverage is real but **directionally wrong**: the
  deterministic FA harnesses do drive real aborts through the production
  `validate()` path, so they would catch an *inversion* that false-rejects honest
  certs. But soundness regressions **widen** acceptance, and accept-widening is
  structurally invisible to liveness, byte-identity replay, and golden-vector
  gates alike — honest inputs never exercise the weakened branch.

**Why no gate ships in this increment.** `check_abort_certs` is `private`, so a
negative test must drive it through `validate()` — which means constructing a
block that passes ~10 earlier gates with a correctly reconstructed at-event
committee and real Ed25519 claim signatures. That is intricate, and a
half-correct version that passed vacuously would be *worse than none* — the exact
failure mode this audit exists to detect. It is scoped as the next increment
rather than rushed.

## 3a. First gap CLOSED — GW-2 (the exact-width decode guard)

`Chain::activate_pending_params`' `parse_u64` opens with
`if (value.size() != 8) return false;` in front of a **fixed 8-iteration loop**
`v |= value[i] << (8*i)`. The guard is load-bearing twice over: a SHORT value
would read **past the end** of the vector, and an over-long value would silently
decode its first 8 bytes as if the operator had authorized exactly that number.
The staged bytes originate in a `PARAM_CHANGE` payload, so this is the only thing
between a malformed governance value and a silently mis-applied consensus
parameter.

Closed by **7 assertions added to the existing `test-param-change-apply`** —
extended rather than given a new subcommand/wrapper/FAST entry (minimalism).
Each malformed width (0, 1, 4, 7, 9 bytes) must leave the parameter UNCHANGED;
the exact-8 case must still apply (non-vacuity); and the same guard is checked on
`SUSPENSION_SLASH` / `UNSTAKE_DELAY`.

*Falsify-on-mutant (executed).* Applying the audit's named mutation —
`value.size() != 8` → `< 8` — flips **exactly one** assertion RED: the 9-byte
over-long case. The four short-value cases still pass (they remain `< 8`, still
rejected) and non-vacuity holds. That is the precise, expected signature: the
over-long assertion is the one carrying the `!=`-versus-`<` semantics, and the
counter-delta (not merely the PASS line) confirms the gate is load-bearing.

## 4. How to use this register

Each entry names a concrete mutation. The remediation pattern is the one this
repo already uses: add the negative assertion, then **falsify on mutant** — apply
the named mutation, confirm the new gate turns RED, revert, confirm green. Two
cautions carried from [DetermJsonParitySoundness](DetermJsonParitySoundness.md)
§5: a falsify target must be *observable at the surface the gate measures* (a
redundant check masked by a downstream guard yields a green mutant run that
proves nothing — verify by counter-delta, not just the PASS line), and a
first-match `grep -q` style check certifies "at least one", never "every".

**Non-claim.** This audit establishes *absence of an enforcing gate*, NOT the
presence of a bug. Every property listed is believed to hold in the current code;
what is missing is the mechanism that would catch it if it stopped holding.

## 5. Gate

This document is a register, not a runtime property, so it has no ratchet of its
own — the honest scoping the register itself argues for. It is anchored by the
`docs/proofs/` corpus it audits and is refreshed by re-running the traceability
workflow. Cross-references [MinixSBOM.md](MinixSBOM.md) §4 (the ratchet-verified
manifest pattern) and [DetermJsonParitySoundness.md](DetermJsonParitySoundness.md)
§5 (falsify-on-mutant discipline).
