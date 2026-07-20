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

**Remediation status: 9 of the 14 HIGH claims are now closed** — GW-2 (§3a),
the abort-certificate cluster T-C1/T-C3/T-C4/T-C5 (§3b), the BFT-escalation arm
T-1/T-2/PE-4 (§3c), and CR-2 (§3d). Five HIGH remain: AL-3, SR-5, WH-2, and the
two light-client sites whose cleartext arrives over the wire, RP-3 and SU-2.
**55 claims open overall.**

The HIGH set — each with a verifier-supplied mutation that leaves every gate
green:

| Claim | Doc | Silently deletable check |
|---|---|---|
| ~~**T-C1, T-C3, T-C4, T-C5**~~ **CLOSED** | AbortCertificateSoundness | the abort-certificate quorum in `validator.cpp::check_abort_certs` — **gate shipped**, see §3b |
| ~~PE-4~~ **CLOSED** | BFTProposerElectionSoundness | `b.bft_proposer != b.creators[expected_idx]` reject — **gate shipped**, see §3c |
| ~~T-1, T-2~~ **CLOSED** | S025BFTEscalationSoundness | the `bft_enabled_` genesis guard and the escalation-threshold arm in `check_block_sigs` — **gate shipped**, see §3c |
| AL-3 | AuditLayerSoundness | the `default:` unknown-tx-type reject in `check_transactions` |
| SR-5 | ShardRoutingSoundness | the receipt `dst_shard` mismatch reject |
| ~~GW-2~~ **CLOSED** | GovernanceWhitelistSoundness | the exact-width `value.size() != 8` decode guard — **gate shipped**, see §3a |
| ~~CR-2~~ **CLOSED** / RP-3, SU-2 | CompositeStateRead / RegistrantProof / SupplyProof | the light client's **value-hash cleartext cross-check** — CR-2 **gate shipped**, see §3d; RP-3/SU-2 still open (they need a tampering proxy) |
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

## 3b. Top gap CLOSED — the abort-certificate cluster (T-C1/T-C3/T-C4/T-C5)

Closed by `determ test-abort-cert-validation`
(`tools/test_abort_cert_validation.sh`, FAST via `abort_cert_validation`).

`check_abort_certs` is `private`, so the gate drives it through the public
`validate()`: a 4-node genesis with REAL Ed25519 keypairs, the at-event committee
derived exactly as the validator derives it, and a self-consistent abort-carrying
block. A well-formed certificate CLEARS V10 (baseline); twelve mutants each assert
their SPECIFIC V10 reject — the four claim field-bindings (T-C4), accused-self-claim
/ duplicate-claimer / under- and over-sized quorum / non-array claims (T-C5),
non-member claimer and accusing a non-selected node (T-C1), and a forged Ed25519
claim signature (T-C3).

**The design constraint that made this non-trivial**, recorded because it is the
reusable lesson: `check_creator_selection` runs BEFORE V10 and *itself* reads
`b.abort_events` (it excludes `aborting_node` and folds `event_hash` into the
selection rand). A naive build-once-then-mutate test would therefore trip THAT
gate and never reach V10 — passing vacuously while appearing to test the
certificate. The builder instead RE-DERIVES `b.creators` and every per-creator
commitment from the abort inputs on each call, keeping each mutant self-consistent
up to the certificate itself. The baseline asserts only that NO abort-cert message
appears; later gates legitimately reject the hand-built block, and that is correct
— the property under test is *which gate fires*, not whether the block is valid.

*Falsify-on-mutant (executed).* Turning the per-claim signature reject
(`validator.cpp:353-354`) into a `continue` — the exact silent mutation the audit
named — flips **exactly one** assertion RED (T-C3) and nothing else. Before this
gate, that mutation passed all 257 tests.

*Honest residual.* Two of the fourteen reject strings remain uncovered:
`"insufficient eligible nodes at abort_event[i]"` needs a larger BFT-escalation
fixture, and `"claimer not found in registry"` is **defensive-only** — a claimer
that passed the at-event membership check is in the registry by construction, so
the branch is unreachable through `validate()`.

## 3c. Third cluster CLOSED — the BFT-escalation arm (T-1, T-2, PE-4)

Closed by **10 assertions added to the existing `test-abort-cert-validation`**
(24 total in that gate) rather than a new subcommand — minimalism, and the
fixture is the same one: a BFT
block is by construction an abort-ESCALATED block, so it must carry a certificate
that clears V10 before the 9th gate ever sees it.

The reachability fact that makes these testable at all: `check_creator_selection`
(3rd) enforces only the mode↔**size** pairing — `m == ceil(2K/3)` for BFT — and
never consults `bft_enabled_`. A BFT-mode block with an escalated committee
therefore reaches `check_block_sigs` even with the genesis flag off, which is
exactly the adversarial case T-1 describes. Two further prerequisites had to be
made well-formed for any of this to be reachable: `check_delay` (8th) sits
between the two clusters, so the builder now also computes the `delay_seed` /
`delay_output` commit-reveal pair. (The V10 assertions are unaffected — gate 6
fires before gate 8 either way, and all fourteen still pass.)

**PE-4 is asserted without re-deriving `proposer_idx()`**, which would only
mirror the code under test. Instead every committee member is driven as the
claimed proposer and **exactly one must survive**. That shape is what makes the
assertion two-sided: deleting the equality leaves *zero* rejected, inverting it
rejects *both*. A proposer outside the committee entirely is rejected as a
separate assertion, and the surviving proposer is then shown to fall to the
sentinel-signature check — proving the accepted branch is the one that continues.
A correctly-proposed, fully-signed BFT block clears the whole gate (non-vacuity).

*Falsify-on-mutant (executed, three separate mutations, each reverted).*

| Mutation | Assertions turned RED |
|---|---|
| neutralize the `!bft_enabled_` guard | T-1 only |
| neutralize the abort-threshold arm | T-2 only |
| neutralize `b.bft_proposer != b.creators[expected_idx]` | **both** PE-4 assertions |

*Method note worth keeping:* the first attempt at the T-2 mutant produced
malformed C++, the build failed, and the **stale binary from the previous mutant
round ran instead** — reporting the previous mutation's signature and nearly
manufacturing a false result. Every mutant round must confirm the build actually
succeeded before trusting what the binary prints; this is the compiled-language
twin of the redundant-check trap in §4.

*Note on PE-4's history:* `proposer_idx()` was already unit-tested for
determinism and in-range behaviour. The gap was never the function — it was the
validator's **use** of it. A well-tested helper called by an unenforced
comparison is a recurring shape in this register; the helper's own tests read as
coverage while the security-relevant equality goes unchecked.

## 3d. CR-2 CLOSED — the light client's value-hash cleartext cross-check

Registered as one three-site cluster (CR-2 / RP-3 / SU-2), the scouting for this
gate found the three sites are **not one testability class**, and saying so is
the useful result:

| Claim | Where the cleartext comes from | What it takes to gate |
|---|---|---|
| **CR-2** | the operator's own **argv** (`--name` / `--value-hex`, `--partner-id` / `--refugee-region`) | nothing — a wrong flag against an honest daemon |
| RP-3 | a second `account` RPC reply | a tampering proxy |
| SU-2 | the `value_hex` field of the same `state_proof` reply | a tampering proxy |

The threat model differs accordingly. For RP-3/SU-2 the adversary is a lying
daemon. For CR-2 the "adversary" is an operator asserting a `(name, value)` the
chain never committed — the check is what stops `verify-param-change` from
rubber-stamping an assertion the proof does not actually support. Both are real;
only the latter needs no interposition, because **neither `name` nor `value`
participates in the leaf key** (`'p:' || u64_be(effective_height) || u32_be(idx)`),
so a wrong value clears the `key_bytes` gate and lands exactly on the comparison.

Closed by **4 assertions added to `tools/test_light_verify_param_change.sh`** —
no new file, no new binary, no new dependency.

**The prerequisite was the harder half.** That test's INCLUDED headline had been
SKIPping *unconditionally*: a `p:` leaf only exists on a GOVERNED chain, and the
fixture's genesis was ungoverned, so the branch could never be taken. The gate
therefore also stages its own subject — genesis now carries a 1-of-1 param
keyholder (the node's own key) and the test submits one change at
`effective_height + 1e6`, far enough out that activation cannot consume the leaf
mid-run. That converts a permanently-skipped assertion into a real control, and
**the control is what makes the tamper legs non-vacuous**: without a leaf, the
`not_found` branch fires ~30 lines before the comparison and every tamper leg
would pass while testing nothing.

`exit == 3` is asserted **exactly**, never "non-zero" — a malformed `--value-hex`
throws out of `from_hex` and exits 1, so a non-zero assertion would pass on the
mutant. Each leg additionally asserts the detail is *not* a `key_bytes` message,
pinning that the key gate did not fire in the comparison's place.

*Falsify-on-mutant (executed, each reverted).*

| Mutation | Effect |
|---|---|
| `light/main.cpp:5467` `if (proof_value_hash != expected_value_hash)` → `if (false)` | **both** tamper legs flip to INCLUDED/exit 0 — the client certifies attacker-chosen cleartext as verified — control unaffected (9 pass → 7 pass / 2 fail) |
| `light/main.cpp:5397` delete `mb.append(name);` | the **control** flips red (8 pass / 1 fail); tamper legs stay green |

That asymmetry is worth keeping. Dropping a field from the preimage makes the
client **over**-reject, so it is the control that catches it, while deleting the
comparison makes it **under**-reject, which only the tamper legs catch. The
control pins accept-narrowing and the tamper legs pin accept-widening; neither
direction is gated by the other. This is the constructive answer to §2's warning
about asking which direction a gate constrains.

*Open residual.* RP-3 and SU-2 remain ungated. Their cleartext arrives on the
wire and no honest daemon can be coaxed into serving a mismatch (`node.cpp` emits
`value_hex` only when it already hashes correctly), so they need a tampering
proxy — tracked as the next increment, not as a claim this section closes.

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
