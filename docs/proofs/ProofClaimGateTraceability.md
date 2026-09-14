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

**Remediation status: ALL 14 HIGH claims are now closed** — GW-2 (§3a),
the abort-certificate cluster T-C1/T-C3/T-C4/T-C5 (§3b), the BFT-escalation arm
T-1/T-2/PE-4 (§3c), CR-2 (§3d), the two wire-sourced light-client sites
**RP-3 and SU-2 (§3e)**, **AL-3 (§3f)** — the unknown-tx-type fail-close —
**SR-5 (§3g)** — the cross-shard receipt misroute reject — and **WH-2 (§3h)** —
the light-client `--wait` no-re-fetch/no-race neutrality, by a moving-daemon
executed mutant. A **2026-07-21 reconstruction (§6)** re-enumerated the lower
tiers the original run recorded only as counts — 34 confirmed unenforced
MED/LOW gaps (4 more were re-examined and found already-gated) — and six MEDs
are now closed: **SP-2 (§3i)** the stake-info cleartext cross-check, **SB-3
(§3j)** the reward-path overflow guard, **AL-5 (§3k)** audit-map crash/rollback
atomicity, **STMC-5 (§3l)** the merge-window `u64`-overflow fail-close, **T-3
(§3m)** the commit-reveal delay-derivation check, **PCL-1 (§3n)** the
governance-whitelist source-coherence guard, **ADC-3 (§3o)** the F2 sub-hasher
source-parity guard (+ its 2 same-class siblings hash_equivocation_event /
hash_cross_shard_receipt), and **T-1 (§3p)** the RPC HMAC canonical-pre-image
source-parity guard (SB-3/AL-5/STMC-5/T-3/ADC-3 gated in FAST both platforms;
PCL-1 + T-1 offline ci_local guards), and **BinaryCodec-T-3 (§3q)** the short tx-frame
reject (an additive FAST negative leg in test-tx-binary-codec), and **MakeContribCommit-T-1
(§3r)** the v1 pre-image reference leg in test-view-root. **24 MED/LOW open; zero HIGH.**

The HIGH set — each with a verifier-supplied mutation that leaves every gate
green:

| Claim | Doc | Silently deletable check |
|---|---|---|
| ~~**T-C1, T-C3, T-C4, T-C5**~~ **CLOSED** | AbortCertificateSoundness | the abort-certificate quorum in `validator.cpp::check_abort_certs` — **gate shipped**, see §3b |
| ~~PE-4~~ **CLOSED** | BFTProposerElectionSoundness | `b.bft_proposer != b.creators[expected_idx]` reject — **gate shipped**, see §3c |
| ~~T-1, T-2~~ **CLOSED** | S025BFTEscalationSoundness | the `bft_enabled_` genesis guard and the escalation-threshold arm in `check_block_sigs` — **gate shipped**, see §3c |
| ~~AL-3~~ **CLOSED** | AuditLayerSoundness | the `default:` unknown-tx-type reject in `check_transactions` — **gate shipped**, see §3f |
| ~~SR-5~~ **CLOSED** | ShardRoutingSoundness | the receipt `dst_shard` mismatch reject — **gate shipped**, see §3g |
| ~~GW-2~~ **CLOSED** | GovernanceWhitelistSoundness | the exact-width `value.size() != 8` decode guard — **gate shipped**, see §3a |
| ~~CR-2 / RP-3 / SU-2~~ **CLOSED** | CompositeStateRead / RegistrantProof / SupplyProof | the light client's **value-hash cleartext cross-check** — CR-2 via argv (§3d); RP-3/SU-2 via a tampering proxy against a lying daemon (§3e) |
| ~~WH-2~~ **CLOSED** | WaitHoldAndWaitSoundness | (verified by an *executed* mutant build, not inspection) — **gate shipped**, see §3h |

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

## 3e. RP-3 and SU-2 CLOSED — the wire-sourced cross-checks vs a lying daemon

CR-2's argv attack cannot reach RP-3/SU-2: their cleartext arrives **on the
wire**, and no honest daemon serves a mismatch (`node.cpp` emits the registry
fields / `value_hex` only when they already hash to the committed `value_hash`).
The adversary here is a **lying daemon**, so the lie is injected by a transparent
man-in-the-middle: **`tools/rpc_tamper_proxy.py`** (stdlib-only, ~180 lines) sits
between `determ-light` (`--rpc-port` → proxy) and the honest node, relays every
newline-delimited JSON request/reply verbatim, and rewrites exactly ONE named
field of one reply. Nothing signs the RPC response (the optional HMAC auth covers
only the request), so the rewrite is invisible at the transport layer **by
design** — the client must catch it cryptographically.

| Claim | Gate | Tampered field | Result |
|---|---|---|---|
| **RP-3** | `tools/test_light_registrant_tamper.sh` (8 assert) | `account` reply `result.registry.registered_at` (then `.region`) | `verify-registrant` → `UNVERIFIABLE`, exit **3**, "does not match the recomputed hash of the account registry" |
| **SU-2** | `tools/test_light_supply_tamper.sh` (4 assert) | `state_proof` reply `result.value_hex` for `genesis_total` | `supply-trustless` → `UNVERIFIABLE`, exit **3**, "TAMPERED — daemon's atomic value_hex for counter 'genesis_total'" |

**Non-vacuity — the CR-2 lesson applied to a wire adversary.** Each gate runs the
SAME client through a **pass-through** instance of the SAME proxy first:
- RP-3's control reaches **INCLUDED / exit 0** — proving the proxy is transparent
  AND the value-hash compare (`light/main.cpp:6112`) is reached and passes on
  honest input. The tamper legs then flip it, asserting exit is **exactly 3**
  (an `ed_pub`-decode or inconsistent-daemon throw exits 1, so "non-zero" would
  pass on the wrong gate) and the detail is the account-registry mismatch, not a
  key-bind message. A second field (`region`) proves the `value_hash` binds the
  WHOLE registrant record, not one field.
- SU-2 targets `genesis_total` (`kCounters[0]`), whose compare at
  `light/main.cpp:8007` executes BEFORE the stale-height / committee-root / merkle
  steps. On a fast single-host cluster the honest verdict can itself be
  `UNVERIFIABLE` — **not a defect**: the chain advances between the per-counter
  `state_proof` calls, so a later counter anchors to a newer `state_root` and the
  client correctly fail-closes on a cross-snapshot read. Because the outer exit-3
  is therefore not discriminating there, the gate's non-vacuous core is a
  **detail differential**: the honest path never emits the genesis_total value_hex
  marker (proving `:8007` passes honestly), the tampered path always does.

*Falsify-on-mutant (executed, each reverted; determ-light rebuilt).*

| Mutation | Effect |
|---|---|
| `light/main.cpp:6112` `if (proof_value_hash != expected_value_hash)` → `if (false)` | RP-3 tamper legs flip: the client certifies the attacker's registry as **INCLUDED / exit 0** (it even prints the fabricated `region: TAMPERED_REGION` as verified); the pass-through control is unaffected (8 pass → 4 pass / 4 fail) |
| `light/main.cpp:8007` same neutralization | SU-2's genesis_total value_hex detail marker vanishes (the compare no longer fires); the discriminating detail assertion flips (4 pass → 3 pass / 1 fail). The bare exit-3 stays green on this host because the cross-snapshot read race independently yields exit 3 — which is exactly why the gate keys on the detail marker, not the exit code |

Same asymmetry as §3d: the pass-through control pins accept-narrowing (a broken
proxy or an over-rejecting client makes the honest leg go red), the tamper legs
pin accept-widening (a deleted comparison makes the client certify a lie). The
proxy is reusable for any future wire-sourced cross-check (`--method`, dotted
`--field`, `flip-hex`/`bump`/`set`). These are cluster-bound (need a bindable
local node), so — like the other `*-trustless` tests — they run standalone, not
in `ci_local`/FAST; both self-skip (exit 0) if the node cannot bootstrap.

## 3f. AL-3 CLOSED — the unknown-tx-type fail-close in check_transactions

`TxType` is an `enum class : uint8_t` with values 0..17, but
`Transaction::from_json` casts any int **straight into the enum with no range
check** (`src/chain/block.cpp`), so an out-of-range discriminator like `99`
decodes cleanly off the wire and reaches the type `switch` inside
`check_transactions` (gate 11 of `BlockValidator::validate`). The `default:`
case is the only thing between an unrecognized type and a silently
accepted-then-skipped transaction — and, as its own comment records, before this
reject existed an unknown type **passed validation and no-op'd at apply**,
diverging the validator's nonce simulation from apply (the W-1/S-039 hazard).

Closed by **`determ test-al3-unknown-tx-type`** (`tools/test_al3_unknown_tx_type.sh`,
FAST — in-process, no cluster). It drives `check_transactions` in isolation via
the public `check_transactions_for_test` seam (`validator.hpp`) — that check
reads only `b.transactions`, so no committee / block-sig / `tx_root` machinery is
assembled. A tx from a genesis creator ("alice", real Ed25519 key) clears every
pre-switch guard (registered non-zero sender, `amount`/`fee` small so no S-049
overflow, non-anon so a valid signature is required, correct nonce) and differs
between legs ONLY in the type byte:

- **Positive control** — a KNOWN type (`TRANSFER`) reaches the switch and does
  NOT yield the unknown-type message, proving the reject below is TYPE-triggered,
  not a generic pre-switch failure of the fixture.
- **AL-3 legs** — type `99` and type `255` are each rejected, and the reject's
  **specific** `"unknown tx type"` message proves the switch was actually reached
  (only `default:` emits it), i.e. the value decoded past `from_json` and every
  pre-switch guard passed.

*Falsify-on-mutant (executed, reverted via file backup; determ rebuilt).*

| Mutation | Effect |
|---|---|
| `src/node/validator.cpp:1352` `default:` `return {false, "unknown tx type …"}` → `break;` | the unknown-type tx drops through the switch and the function returns `{true,""}` (accept); all three AL-3 legs flip RED while the positive control stays GREEN (4 pass → 1 pass / 3 fail) |

The asymmetry is the usual one: the control pins that the fixture reaches and
passes the switch on a known type (accept-narrowing), the negative legs pin that
an unknown type is fail-closed (accept-widening). This gate runs in FAST on both
platforms (it needs no bindable node), unlike the §3e cluster gates.

## 3g. SR-5 CLOSED — the cross-shard receipt misroute reject

`ShardRoutingSoundness.md` Theorem SR-5 (misroute detection): a block claiming a
cross-shard receipt whose `dst_shard ≠ ρ_{S,salt}(to)` must be rejected — the
receiver **recomputes** the destination shard from `(to, shard_count, salt)`
rather than trusting the producer's claimed `dst_shard`. This is the
`A_misroute` defense (threat table §4.5): without it a block producer could
redirect another party's funds to a shard of its choosing. The enforcing check
is `BlockValidator::check_cross_shard_receipts` (gate 12,
`src/node/validator.cpp`), whose `dst_shard` comparison had no negative test.

Closed by **`determ test-sr5-misroute-receipt`**
(`tools/test_sr5_misroute_receipt.sh`, FAST — in-process, both platforms). Like
AL-3 it drives the check in isolation via a new public const-forwarder seam
`check_cross_shard_receipts_for_test` (`validator.hpp`, 2-arg — the check reads
only `b + chain`, no `NodeRegistry`). A shard-count-4 chain, a cross-shard
`TRANSFER` whose `to` routes off shard 0, and one receipt matching the tx in
every field; the legs differ ONLY in `dst_shard`:

- **Positive control** — `dst == ρ(to)` is ACCEPTED, proving the fixture reaches
  and passes the whole receipt check (size + `src_shard` + `src_block_index` +
  field-match) on a correctly-routed receipt.
- **SR-5 legs** — `dst = correct+1` and `dst = 0` (my own shard) are each
  REJECTED with the **specific** `"dst_shard mismatch"` message, which proves the
  `dst_shard`-recompute gate fired and not the earlier `src_shard`/size guards
  (identical between the legs).

*Falsify-on-mutant (executed, reverted via file backup; determ rebuilt).*

| Mutation | Effect |
|---|---|
| `src/node/validator.cpp` — delete the `if (r.dst_shard != ρ(tx.to,…)) return {false, "…dst_shard mismatch"}` reject | the misrouted receipt passes through to acceptance (`A_misroute` succeeds); all three SR-5 legs flip RED while the correctly-routed control stays GREEN |

The one delta from AL-3: SR-5 required **adding** a test seam (AL-3 reused an
existing one), kept a pure byte-neutral const forwarder. Same accept-widening
asymmetry: the control pins that a correct route is accepted, the negative legs
pin that an incorrect route is rejected.

## 3h. WH-2 CLOSED — the light-client `--wait` no-re-fetch neutrality (the last HIGH)

`WaitHoldAndWaitSoundness.md` §4.2 (WH-2): `read_account_trustless` captures the
`state_proof` for the anchor **exactly once**, before the `--wait` loop is
entered; the loop (inside `committee_bound_state_root`) re-polls ONLY the
successor `headers`, never the proof. So a daemon that advances its state DURING
the wait cannot swap the bound root — the proof was frozen before the loop. This
is a **soundness-neutrality** property: invisible on a static chain (a re-fetch
mutant only diverges when the proof CHANGES between fetches), which is why the
register demanded an **executed mutant**, not inspection.

Closed by **`tools/test_light_wh2_norefetch.sh`** with a MOVING DAEMON. The
reusable `tools/rpc_tamper_proxy.py` gained two modes: `--serve-first N` (pass
the first N `state_proof` replies verbatim, then flip `state_root`) and
`--withhold-successor K` (return an empty `headers` array for the successor poll
— `from>0, count==1` — K times, forcing the client's `--wait` loop to iterate);
it also logs every forwarded request. Against this daemon the CLEAN client is
**immune**, and the gate reads it straight off the proxy log — five assertions:
a pass-through control verifies; the moving-daemon run (a) stays `verified`/exit
0 despite the armed flip, (b) issues **exactly one** `state_proof` request
(fetch-once), (c) iterated the `--wait` loop (successor withheld ≥2× ⇒ it
re-polled only `headers`), and (d) fired **zero** tampers (no 2nd `state_proof`
to flip).

*Executed-mutant falsify (run out-of-band, reverted via file backup; determ-light
rebuilt).*

| Mutation | Effect |
|---|---|
| `light/trustless_read.cpp` — insert a caller-side `state_proof` re-fetch after the wait, before the held `if (attested != proof_root)` compare (overwriting `proof_root`) | the re-fetch is `state_proof` call #2 ⇒ the moving daemon flips it ⇒ `proof_root != attested` ⇒ the client throws `SECURITY … does NOT match proof.state_root` and exits 1. 4 of the 5 clean assertions flip (only the proxy-side loop-iterated stays) |

A sharper result fell out: the re-fetch mutant fails **even through a
pass-through (honest) proxy**, because the re-fetch binds an *advanced*
`state_root` (the chain moved during `--wait`) that no longer matches the
committee-bound anchor. So the fetch-once structure is load-bearing against an
ordinary moving chain, not only a malicious daemon — exactly the race WH-2 says
it avoids. (This gate is cluster-bound, standalone; the tamper proxy's extensions
are backward-compatible — RP-3 8/0, SU-2 4/0 unchanged.)

**With WH-2 closed, all 14 HIGH gate-gaps from the 2026-07-19 traceability audit
are gated + falsified.**

## 3i. First MED CLOSED — SP-2, the stake-info cleartext cross-check vs a lying daemon

`StakeProofSoundness.md` §4.2 (SP-2 cleartext cross-check): `read_stake_trustless`
recomputes `SHA256(u64_be(locked) ‖ u64_be(unlock_height))` from the daemon's
separately-served `stake_info` reply and rejects any mismatch against the
committee-proven `value_hash` (`light/main.cpp:2395`). It is the `s:`-namespace
sibling of the a:/r:/c: cross-checks gated by CR-2 / RP-3 / SU-2 — the **last of
the light-client value-hash cleartext cross-checks**, and the original F-6 site.
No stake-info tamper test existed and the proxy was never interposed on
`stake_info` (every stake test is an honest-daemon parity check), so the
accept-widening direction — a lying daemon serving an honest `s:` proof but a
FALSE `stake_info` cleartext — was unguarded. Consequence: `stake-trustless`
reports attacker-chosen (locked, unlock_height) as committee-verified, feeding
min_stake / unlock-maturity decisions off forged numbers.

Closed by **`tools/test_light_stake_tamper.sh`** (cluster-bound, standalone),
reusing `tools/rpc_tamper_proxy.py` — which gained a **JSON-coercing `set` mode**
so an integer field can be tampered (a bare word still falls back to a string, so
RP-3/SU-2 are unaffected). Eight assertions: a PART A offline proxy self-test
(pass-through relays `locked` as an int; `set` yields integer `12345`, not the
string `"12345"`) so the gate is non-vacuous even where the live cluster SKIPs; a
pass-through **control** (`verified=true`/exit 0 — the compare is reached and
honest-passes); and two **tamper legs** — `bump locked` and `set unlock_height` —
each asserting exit **1** with the SPECIFIC `TAMPERED — daemon's stake_info reply`
detail and NOT a SECURITY/key-bind message.

**The detail differential (the SU-2 lesson):** `cmd_stake_trustless` maps EVERY
throw to exit 1 (`light/main.cpp:2469`) — the key-bind reject (:2312), the
committee-attest SECURITY reject (:2361), an RPC failure — so "exit non-zero", or
even "exit 1", is not discriminating. The legs key on the value-hash-specific
`TAMPERED`/`stake_info` detail, pinning that :2395 fired and not an earlier gate.

*Falsify-on-mutant (executed, reverted; determ-light rebuilt).* Neutering the
compare at `:2395` **alone** (`→ if (false)`, leaving the `:2664`
verify-unstake-eligibility sibling intact) flips both tamper legs to a **false
`verified=true`/exit 0**: the client certifies the daemon's forged `locked=1001`
/ `unlock_height=12345` as committee-verified — the exact SP-2 break. 8/0 → 4/4;
PART A + control stay green (the mutant is invisible on honest input). The two
tamper legs prove **whole-leaf binding** — a lie about EITHER scalar is caught.
Backward-compatible: RP-3 8/0, SU-2 4/0, WH-2 5/0 unchanged.

## 3j. SB-3 CLOSED — the reward-path overflow guard (a FAST consensus gate)

`SubsidyAccountingSoundness.md` SB-3 corollary 3 (*no silent wrap*): every credit
on the block-reward path is guarded by `checked_add_u64` — the fees+subsidy join
(`chain.cpp:1749`), each per-creator credit (`:1761`), the dust remainder
(`:1769`) — so on overflow the apply throws an `S-007` diagnostic and the A9
envelope rolls back byte-identical, and no partial mint survives. The consequence
of a regression is direct **supply inflation at the reward hot path**: a raw
`bal += per_creator` silently wraps a committee creator whose balance is near
`UINT64_MAX`, minting `~2^64` from nothing. No existing test drove a *creator*
(as opposed to a tx recipient) near the ceiling — every subsidy/fee test uses
small balances — so the guard had no negative test.

Closed by **extending `determ test-overflow-paths`** (`tools/test_overflow_paths.sh`,
FAST both platforms — no new subcommand; the existing overflow suite already had
the near-`UINT64_MAX` fixture machinery). Six assertions on the sole-creator
`build_genesis_overflow` helper + `set_block_subsidy(100)`: the per-creator credit
overflows and throws `S-007 "per-creator"`; the A9 rollback leaves the creator
balance and `state_root` byte-identical (no partial mint); and a **boundary
control** — a subsidy bringing the creator to *exactly* `UINT64_MAX` is credited,
not rejected — pinning the strict-greater semantics (an over-reject `>=` mutant
would flip the control).

*Falsify-on-mutant (executed, reverted via `git checkout`; determ rebuilt).*
Replacing the guard at `:1761` with `bal += per_creator` (the register's named
mutation) makes the near-max creator wrap silently with no throw and no rollback:
the overflow assertion and both rollback assertions flip RED (6/6 → 3/6) while the
setup and boundary control stay green (the mutant is invisible at the exact-max
boundary — a raw add reaches `UINT64_MAX` without wrapping). The `:1749` and
`:1769` guards are the identical `checked_add_u64` idiom; the per-creator site is
the falsifiable representative. **This is the first MED gated in FAST on both
platforms** (SP-2 is cluster-bound/Windows-standalone).

## 3k. AL-5 CLOSED — audit-map crash/rollback atomicity (a FAST consensus gate)

`AuditLayerSoundness.md` AL-5 (crash/rollback atomicity): a throwing
`apply_transactions` restores BOTH audit maps (`audit_keys_`,
`audit_log_count_`) byte-identically, so a failed block leaves the `ak:`/`al:`
leaves exactly as before — no half-applied `ROTATE_AUDIT_KEY` / `LOG_AUDIT_ACCESS`
survives to fork the `state_root`. The doc's own coverage table flagged this row
as *proven-in-code, **not separately fault-injected*** — every earlier
`test-audit-keys` assertion exercised only the SUCCESS path. The regression is a
consensus fork: with the restore branches gone, a node that fails a block mid-apply
keeps the partial audit mutation while a node that never started it does not.

Closed by **extending `determ test-audit-keys`** (`tools/test_audit_keys.sh`,
FAST both platforms — no new subcommand; reused its `rotate_tx`/`log_tx`/
`append_block` helpers + the SB-3 near-`UINT64_MAX` overflow idiom). One block,
three txs — `[ROTATE_AUDIT_KEY(pk1), LOG_AUDIT_ACCESS, TRANSFER]` — where the
TRANSFER credits a genesis `bob` at `UINT64_MAX − 5` and throws `S-007` mid-apply,
*after* the ROTATE and LOG have already mutated both maps. Five assertions: the
append throws; `audit_key == nullopt` and `audit_log_count == 0` (both rolled
back); and `state_root` byte-identical to pre-apply. The two per-map assertions
independently pin each restore branch.

*Falsify-on-mutant (executed, reverted via `git checkout`; determ rebuilt).*
Neutering both restore branches at `chain.cpp:775-778` (the register's named
mutation) makes the mid-block ROTATE and LOG survive the throw: all three rollback
assertions flip RED (5/5 → 2/5) while the setup and the throw-detection stay green.
The lazy-snapshot capture (`__ensure_audit_keys` / `__ensure_audit_log_count`
before the first mutation) is what makes the pre-block map recoverable; this gate
is the executed witness that the capture *and* the restore are both load-bearing.

## 3l. STMC-5 CLOSED — the merge-window u64-overflow fail-close (a FAST consensus gate)

`ShardTipMergeClosureSoundness.md` STMC-5: a `MERGE_BEGIN` admission is
uniform-fail-closed on a `u64`-overflowing window terminus — the guard at
`validator.cpp:922-925` rejects an `evidence_window_start` where
`evidence_window_start + merge_threshold_blocks` wraps. `evidence_window_start`
is **attacker-controlled** (it rides the `MergeEvent` payload). Without the guard,
setting it to `UINT64_MAX` wraps the terminus so the witness loop
`for (h = start; h < start + T; ++h)` runs **zero** iterations — a silently EMPTY
window — and a merge admission that proves *nothing* (no committed sub-2K distress)
slips through. The consequence is an unjustified shard merge on a BEACON.

Closed by **extending `determ test-s036-merge-witness`** (`tools/test_s036_merge_witness.sh`,
FAST both platforms — no new subcommand; the subcommand's `run(...)` helper already
takes `window_start`). One scenario reusing scenario A's genuine sub-2K records
(ACCEPTED at `window_start = 0`, the built-in positive control) with only
`window_start` flipped to `UINT64_MAX`, asserting `!r.ok` **and** the reject detail
contains `"overflows u64"` — so the overflow guard is the sole cause of the flip,
not an incidental later gate.

*Falsify-on-mutant (executed, reverted via `git checkout`; determ rebuilt).*
Neutering the guard condition at `validator.cpp:923` (`&& false`) makes the
wrapped-empty window slip through: the STMC-5 assertion flips RED (the merge is no
longer rejected with `"overflows u64"`) while scenario A — the positive control at
`window_start = 0` — and every other scenario stay green.

## 3m. T-3 CLOSED — the commit-reveal delay derivation check (a FAST consensus gate)

`ConsensusPhaseStructureSoundness.md` T-3 (derivation determinism): `check_delay`
(the 8th of `validate()`'s gates) re-derives BOTH `delay_seed`
(= `SHA256(index‖prev_hash‖tx_root‖ordered dh_inputs)`) and `delay_output`
(= `SHA256(delay_seed‖ordered secrets)`) and rejects a block whose stored values
are not the canonical functions of the authenticated Phase-1/Phase-2 inputs. No
`test-*` drove `check_delay`: mutating either compare (`validator.cpp:446`
`delay_output` / `:433` `delay_seed`) to `if (false)` passed the whole suite — a
producer could then ship a non-canonical `delay_output` (the block randomness `R`)
and honest nodes would accept it.

Closed by **extending `determ test-abort-cert-validation`** (`tools/test_abort_cert_validation.sh`,
FAST both platforms — no new subcommand; its real-key fixture already builds a
block with a canonical commit-reveal pair). Added one public const seam
`BlockValidator::check_delay_for_test(const Block&)` (the fourth `*_for_test`
forwarder, byte-neutral to production). Three assertions: a positive control (the
honest pair clears `check_delay` — observable *only* via the seam, since the
hand-built block would fail the later block-sig/digest gates of full `validate()`,
the recurring "key the control on the gate, not the pipeline" lesson) and two
negative legs (a one-byte-tampered `delay_output` → `"delay_output mismatch"`; a
tampered `delay_seed` → `"delay_seed mismatch"`).

*Falsify-on-mutant (executed, BOTH compares independently, each reverted).*
`:446 → if(false)` flips ONLY the delay_output leg RED (control + seed leg green);
`:433 → if(false)` flips ONLY the delay_seed leg RED — the tampered seed falls
through to `:446`, which emits `"delay_output mismatch"` (not the seed-specific
string), so the substring-keyed leg goes red while the control and delay_output
leg stay green. Each compare is therefore independently gated. (This round used a
parallel design workflow to pre-verify the fixture's reachability and the
delay_seed fall-through before implementation.)

## 3n. PCL-1 CLOSED — the governance-whitelist source-coherence guard (offline)

`ParamChangeLintSoundness.md` PCL-1: the wallet's `kWhitelist` and
`kNumericScalars` are byte-for-byte the validator's whitelist
(`src/node/validator.cpp`) and the chain's `parse_u64` scalar dispatch
(`src/chain/chain.cpp`). **The load-bearing fact:** `determ-wallet` links no chain
library (TCB separation), so these are HAND-MAINTAINED mirrors in a *different
binary* — adding a name to one copy without the others (the register's mutation)
is invisible to every runtime test, and makes the wallet lint silently reject a
now-valid governance param or accept one the chain cannot apply. Only source
parity can catch it.

Closed by **a new offline guard `tools/test_param_change_whitelist_coherence.sh`**
(pure awk/grep, no node/build) wired into the ci_local offline doc-guard loop
(`tools/ci_local.sh`), so it gates on both platforms via CI and is auto-discovered
by a full `run_all.sh`; like the other doc guards it is intentionally NOT in the
FAST regex. It extracts all three `kWhitelist` literals + the wallet
`kNumericScalars` + the chain dispatch names and asserts: all three whitelists
set-identical; `kNumericScalars` == the chain dispatch; every scalar on the
whitelist. It pins `EXPECTED_WL_BLOCKS = 3` so a renamed/deleted copy (which would
make a parity check *vacuously* pass) turns it RED — the anti-vacuity control.

*Falsify (executed, reverted via `git checkout`; no build — a source guard).*
Adding `"NEW_SCALAR"` to the validator `kWhitelist` alone makes the guard FAIL
(`drift: kWhitelist sets differ`, validator 10 vs wallet 9); the coherent tree
passes 4/4. This is the first register gap closed as a pure source-coherence guard
(the CB-2/ADC-3 class), not a runtime negative test.

## 3o. ADC-3 CLOSED — the F2 sub-hasher source-parity guard (+ 2 siblings)

`AbortDigestCanonicalizationSoundness.md` ADC-3: `hash_abort_event` is
re-implemented in TWO binaries that deliberately do NOT share a code path —
`src/node/producer.cpp` (ground truth; feeds the `akeys` view root the block
digest binds) and `light/verify.cpp` (the mirror that recomputes that root to
verify each committee member's Ed25519 sig). **The load-bearing fact:** the block
digest binds the abort view root, so a field reorder / add / drop / recast in
EITHER `hash_abort_event` copy silently drifts the committee-signed digest for
cross-shard / reconciled blocks — yet no runtime test catches it (the only runtime
cross-check, `test_light_verify_block_sigs.sh`, exercises block 1, a non-F2 block,
so the F2 collections are never populated and the sub-hasher never runs on both
sides with the same input). The existing `test_block_digest_xbinary_parity.sh`
guard reduces the whole abort view root to ONE token (`ABORT_ROOT`) and so never
saw the sub-hasher's internal field order — exactly the surviving-mutant the
register named (swap `hash_abort_event`'s round/aborting_node appends in light —
`light/verify.cpp:94-95` — or drop the `timestamp` append at `light/verify.cpp:96`).

Closed by **extending `tools/test_block_digest_xbinary_parity.sh`** (the same
static cross-binary guard, already FAST both platforms) with an
`extract_subhasher_appends` extractor + a `check_subhasher` assertion: it isolates
each F2 sub-hasher body by its `^Hash <fn>(` anchor, reduces every `b.append(ARG)`
to `ARG` with the `determ::` / `chain::` / `std::` namespace qualifiers stripped
(the ONLY spelling difference between the two copies), and asserts the producer and
light append sequences are EQUAL, non-empty (anti-vacuity), and carry the expected
`DTM-F2-*` domain tag. The same mechanism trivially covers the two SIBLING F2
sub-hashers of the identical gap class, so all three are closed in one pass:
**`hash_abort_event` (ADC-3, `DTM-F2-ABORT-v2`) + `hash_equivocation_event`
(`DTM-F2-EQ-v1`) + `hash_cross_shard_receipt` (`DTM-F2-RCPT-v1`)**. A `SELFTEST=1`
leg proves the extractor flags a reordered field AND that the `chain::` vs
`determ::chain::` spelling normalizes equal (no false positive). No new file, no
new test (count unchanged), zero compiled change.

*Falsify (executed, reverted via `git checkout` — a source guard, no build).*
Swapping `b.append(e.round)` / `b.append(e.aborting_node)` in
`light/verify.cpp::hash_abort_event` makes the guard FAIL (`sub-hasher
hash_abort_event: producer != light`); the coherent tree passes. Verified on both
git-bash (MSVC side) and WSL Ubuntu (Linux gate) — main + selftest identical.

**D2-inc3 update (commit `c8a63d2`) — the gate legs moved with the formula, ADC-3
stays CLOSED.** `hash_abort_event` no longer SHA-256s `claims_json.dump()`: the
claim list is the typed `std::vector<chain::AbortClaim>` and its digest preimage
is the canonical fixed-layout binary encoding `chain::encode_abort_claims`
(`src/chain/block.cpp`), under the bumped domain `DTM-F2-ABORT-v2`. Both copies
of the sub-hasher moved lock-step (`src/node/producer.cpp:437`,
`light/verify.cpp:87`) and the three `hash_abort_event` heredocs in
`test_block_digest_xbinary_parity.sh` were re-derived, so the append-sequence
extractor still asserts producer == light on the v2 formula. The claims leg is
now *stronger* than a mirrored append: both binaries CALL the one shared codec,
so that portion cannot be hand-mirrored wrong at all. The
`AbortDigestCanonicalizationSoundness.md` companion gate
(`determ test-abort-claims-canonical`) was rewritten against the codec and now
pins (1) codec round-trip fidelity over all six fields + byte-determinism +
empty-list round-trip, (2) PER-FIELD digest binding for each of the six fields
plus claim ORDER and COUNT — falsify-on-mutant by deleting a field's append from
`encode_abort_claims` (e.g. `claimer`), which reddens exactly that leg while the
digest is otherwise unchanged, (3) fail-closed decode with four specific reject
strings (`truncated count header`, `truncated claim`, `truncated lp_str`,
`trailing bytes after last claim`), and (4) the F-10 STRUCTURAL closure — the
container "claims" value is one hex string at every depth, the abort-carrying
block is accepted at BOTH `BLOCK` and `CHAIN_RESPONSE` payload depths, it
round-trips as a byte fixed point with its digest intact, and the pre-D2
JSON-array shape is REJECTED at the parse boundary. The JSON canonicalization
helper the old legs exercised (`include/determ/chain/abort_canonical.hpp`,
`canonical_abort_claims{,_dump}`) is DELETED — the channel it policed is
structurally impossible on a typed claim, so there is no surviving mutant of that
class left to gate.

## 3p. T-1 CLOSED — the RPC HMAC canonical-pre-image source-parity guard (offline)

`RpcAuthHmacSoundness.md` T-1: the RPC auth tag is `HMAC-SHA-256(secret,
canonical_for_hmac(method, params))`, and `canonical_for_hmac` binds the METHOD
into the pre-image — `return method + "|" + params.dump();` (`src/rpc/rpc.cpp`).
Binding the method is what prevents CROSS-METHOD REPLAY: a captured auth tag for a
read like `balance` must not authenticate a `stop` / `submit` call. The register's
surviving mutation drops the prefix (`return params.dump();`), after which a valid
tag for ANY method authenticates EVERY method.

**The load-bearing fact:** nothing gated the method-binding at the PRODUCTION
source. `determ test-rpc-auth-hmac` (17 assertions, incl. #14 "wrong method →
different tag") tests a **local lambda copy** of `canonical_for_hmac`, not the
production function — the production one lives in an **anonymous namespace** in
`rpc.cpp` (internal linkage, uncallable from the test), so the two are hand-mirrored
in different translation units. The live-cluster test (`tools/test_rpc_hmac_auth.sh`)
drives the SAME production canonical on both client and server, so a dropped method
prefix still round-trips (correct / wrong / missing tag all still behave) — the
method-binding property is invisible to it. So a production drop survives EVERY
existing gate.

Closed by **a new offline guard `tools/test_rpc_hmac_canonical_parity.sh`** (pure
awk over `rpc.cpp` + `main.cpp`, no build/node) wired into the `ci_local.sh` offline
doc-guard loop, so it gates on both platforms via CI (like PCL-1). It extracts the
production `canonical_for_hmac` return expression + the test lambda's, and asserts
(a) production **binds `method`** (the security property — anti-cross-method-replay)
and (b) production **==** the lambda spec. The lambda is the SELF-TESTED spec
(assertion #14 turns RED if the lambda ever drops the method), so pinning
production == lambda transitively gates production's method-binding. Same class as
PCL-1 (governance whitelist) + ADC-3 (F2 sub-hashers): two hand-mirrored copies in
different binaries/TUs, pinned equal at the source. A `SELFTEST=1` leg drives a
dropped-prefix snippet through the extractor to prove the drift is flagged.

*Falsify (executed, reverted via `git checkout` — a source guard, no build).*
Applying the register's exact mutation (`rpc.cpp` → `return params.dump();`) makes
the guard FAIL (2 violations: "does NOT bind the method — CROSS-METHOD REPLAY" +
"DIFFERS from the self-tested lambda spec"); the coherent tree passes. Verified on
both git-bash (MSVC side) and WSL Ubuntu (Linux gate) — main + selftest identical.
**T-3-s001 (handle_session auth-before-dispatch) remains DEFERRED** — it touches the
live auth control flow, not a pure helper, so it needs a careful review rather than
an additive source guard.

## 3q. BinaryCodecRoundTripSoundness T-3 CLOSED — the short tx-frame reject (FAST unit)

`decode_tx_frame` (`src/net/binary_codec.cpp`) rejects a TRANSACTION frame whose body
is below the `128 + 1 + 2` minimum: `if (len < 128 + 1 + 2) throw "tx frame too
short"`. That guard sits in front of the fixed-slot reads (sender/amount/recipient/
payload at offsets 0..127, then the type + payload_len header). The register's
surviving mutant deletes it, after which a short/truncated frame off the P2P wire
reads past its buffer and/or decodes a garbage transaction — with NO red test (the
existing `test-tx-binary-codec` only round-trips WELL-FORMED frames).

Closed by **an additive negative leg in the existing `test-tx-binary-codec`** (FAST,
both platforms). `decode_tx_frame` is file-local, so the leg reaches it through the
PUBLIC `decode_binary` path: encode a real TRANSACTION message, keep its valid 4-byte
binary-envelope header, and truncate the body to `min - 1 = 130` bytes. `decode_binary`
extracts the body and calls `decode_tx_frame(body, 130)` → `130 < 131` → throws "tx
frame too short". A positive control (the full frame decodes) keeps the leg from
passing vacuously if `encode_binary` ever changes shape. 130 is chosen deliberately —
one below the threshold so the guard fires, yet ≥ the 128-byte fixed region so the
decode stays in bounds if the guard were removed (the mutant then just fails to throw
→ the leg goes RED, no reliance on out-of-bounds behavior on the shipped path).

*Falsify (executed, reverted via `git checkout`).* `binary_codec.cpp` `if (len < 128 +
1 + 2)` → `if (false)` makes the negative leg FAIL ('tx frame too short' no longer
thrown) while the positive control stays green; the coherent tree passes both.
Compiled change — MSVC FAST + WSL2 GCC ci_local both green; test count unchanged (leg
added to an existing subcommand).

## 3r. MakeContribCommitmentBackwardCompat T-1 CLOSED — v1 pre-image reference (FAST unit)

> **UPDATE 2026-08-12 — the pinned form changed; the gate is re-anchored, still CLOSED.**
> `make_contrib_commitment` became two-level: `SHA-256("DTM-CONTRIB-v3" ‖ block_index u64 BE ‖ gen u64 BE ‖
> body_root)` over `make_contrib_body_root` (`src/node/producer.cpp:332` / `:252`), which is the legacy
> preimage **minus** the leading `block_index` append. The 18b leg's old external reference — the
> one-level v1 4-append pre-image — was therefore legitimately broken by the shipped change (not by a
> regression), and was **re-anchored to an independent two-level re-derivation**: the leg rebuilds
> `body_root` with a fresh `SHA256Builder` and then re-applies the outer tag + BE index, so it remains
> an EXTERNAL byte pin (body + outer tag + endianness), and the positive control (an F2 non-zero-root
> commit must NOT equal the reference) is retained. The register's surviving mutant
> (`bool any_view = true`) still reddens it, because `any_view` still gates the `DTM-F2-v1` block inside
> the body. The `pre-F2 peer byte-compat` MOTIVE is obsolete pre-genesis — see
> `MakeContribCommitmentBackwardCompat.md` §0 — but the gate's VALUE is unchanged: it is the only
> external pin on this preimage's byte layout.


`make_contrib_commitment` (`src/node/producer.cpp:248`) has a **v1 backward-compat
short-circuit**: when all three F2 view roots are zero it falls through to the
pre-F2 commit shape — 4 appends `SHA256( u64(index) ‖ prev ‖ inner_root ‖ dh )`,
`inner_root = SHA256(concat sorted_tx_hashes)`, with NO `DTM-F2-v1` domain tag — so
a pre-F2 peer's ContribMsg signature verifies against the same bytes. The register's
surviving mutant forces `bool any_view = true` (producer.cpp:277-279), which makes
the zero-view commit take the F2 path (prepend the `DTM-F2-v1` tag + the 3 zero
roots), silently breaking the byte-identity with pre-F2 peers — with NO red test.

**The false coverage** (why the existing `test-view-root` assertions miss it): assn
18 compares two *zero-view* calls (both mutate identically → still equal → green),
and assn 19 compares two *non-zero-root* calls that differ by the root VALUE, not by
the tag's presence (also green under `any_view=true`). Neither pins the v1 BYTES
against an external reference.

Closed by **an additive leg (18b) in the existing `determ test-view-root`** (FAST,
both platforms via `tools/test_view_root.sh`; `make_contrib_commitment` is a public
free fn, called in-process — no live node). The leg independently rebuilds the v1
4-append pre-image with a fresh `SHA256Builder` and asserts the zero-view commit
equals it, plus a positive control that an F2 (non-zero eq_root) commit does NOT
equal the v1 reference (so the leg can't pass vacuously). This supplies exactly the
pre-F2 reference (Lemma L-1) the backward-compat proof rests on.

*Falsify (executed, reverted via `git checkout`).* producer.cpp:277-279
`bool any_view = !is_zero_hash(...) || …` → `bool any_view = true;` flips ONLY the
18b negative leg RED (the zero-view commit gains the `DTM-F2-v1` tag → ≠ the
independent v1 pre-image); the positive control + all prior view-root assertions
stay green. Compiled change — MSVC FAST + WSL2 GCC ci_local both green (run
SEQUENTIALLY); test count unchanged. *(Design pre-verified in the register-gate-triage
Workflow, run wf_b2e68071.)*

## 3s. T-OE4 CLOSED — offline equivocation clause-3 asymmetry (FAST unit)

`cmd_verify_equivocation` (`light/main.cpp`, the offline `determ-light
verify-equivocation` FA6 verifier) re-runs the daemon's V11 double-sign gate as a
FOUR-clause else-if chain: (1) digests distinct, (2) sigs distinct, (3) sig_a
verifies, (4) sig_b verifies — else the verdict stays **EQUIVOCATION-PROVEN**
(exit 0, a cryptographically-justified slash). Clause 3 (`else if (!sig_a_ok)`,
lines 7587-7589) has NO enforcing negative leg: deleting it lets an event with
**sig_a INVALID but sig_b VALID** (dd=T, sd=T, sig_a_ok=F, sig_b_ok=T) skip clause
4 (its `!sig_b_ok` is false) and fall through to PROVEN — a forged sig_a reported
as a proven double-sign, i.e. a false-slashing justification, with no red test.

**The false coverage** (why the existing wrapper's four NOT-EQUIVOCATION legs miss
it): assertion 4 (wrong `--pubkey`) invalidates BOTH sigs, so with clause 3 gone it
still reaches clause 4 → green; assertions 5/6 short-circuit on clauses 1/2;
assertion 7 tampers sig_b only, keeping sig_a valid → clause 4 → green. **No leg
builds the sig_a-bad / sig_b-good profile.** And the whole wrapper was outside the
FAST regex — it ran only in a full local suite, never in either platform gate.

Closed by **an additive leg (7b) in the existing `test_light_verify_equivocation.sh`**
(no new wrapper, no production edit) + **wiring `light_verify_equivocation` into the
run_all.sh FAST ONLY_PATTERN** so it now gates on BOTH platforms alongside its
`light_verify_ct`/`_notekey`/`_enote_inclusion` siblings. The leg tampers sig_a only
(`SIG_A_BAD="${SIG_A%?}b"`, sig_b left valid) → asserts exit 3 + reason
`"sig_a does not verify"`, and carries its own adjacent PROVEN control (the genuine
double-sign still reaches V11) so it can't pass vacuously if the fixture stops
reaching the gate. Pure offline, baked RFC-8032 Ed25519 vector — no daemon, no
runtime crypto backend.

*Falsify (executed, reverted via `git checkout`).* delete clause 3 (light/main.cpp
7587-7589) → determ-light rebuilt → the 7b negative leg flips RED (tampered_a now
yields PROVEN exit 0, rc=0≠3) as the SOLE failure (13 pass / 1 fail); the adjacent
control + assertions 4/7 stay green. No compiled `determ` change (the leg drives
`determ-light`), so MSVC FAST is 265/0 (was 264 — the newly-wired test) and WSL2 GCC
ci_local 265/0 + 6 doc guards. *(Design adversarially verified SOUND in the FAST_UNIT
batch-design Workflow, run wf_f1a08faf-653.)*

## 3t. SP-CK-2 CLOSED — composite-key exact-width guard (FAST unit, shared free fn)

`Node::rpc_state_proof` (`src/node/node.cpp`) exposes the composite-key namespaces
(i:/m:/p:/cc:/t:): the `key` argument is the HEX of a binary body that is decoded and
**exact-width-checked** before it builds the leaf key `ns:body`. The width guard
(originally `if (body.size() != want)` at node.cpp:4709) is load-bearing — a
wrong-width body (e.g. a 39- or 41-byte `i:` body when `want`=40) would silently
build a DIFFERENT leaf key and alias/forge a state-proof target. The register mutant
neutralizes the check (`if(false)`) with no red test.

**The reachability gap** (why no prior assertion drove it): the existing
`test-state-proof-composite-key` builds BINARY keys and calls `Chain::state_proof`
directly, entirely bypassing the hex-decode + width layer that only
`Node::rpc_state_proof` performs — and driving a real `Node` in-process needs a full
on-disk bootstrap (config/key/genesis/chain-load), far too heavy and not FAST-clean.

Closed by **extracting the decode+width logic into a byte-neutral free fn**
`determ::node::decode_composite_state_body(ns, hex) -> {hex_ok, ok, body, want}`
(DECL in node.hpp, DEFN in node.cpp) that `rpc_state_proof` now calls — rebuilding
its TWO error-json shapes VERBATIM (invalid-hex + wrong-length), so RPC output is
byte-identical (all state_proof unit/namespace/value-hash tests unchanged; the
mutant now lives on the real production path). Four legs added to the existing
`test-state-proof-composite-key` (FAST both platforms; no new wrapper, no regex
edit): a correct-width control (40B accepted), a 39-byte short + a 41-byte long
reject (both valid EVEN-length hex so `hex_ok` stays true — isolating the WIDTH
verdict), and a non-hex leg pinning the distinct `hex_ok=false` path.

*Falsify (executed).* `d.ok = (d.body.size() == d.want)` → `d.ok = true`
(equivalently the register's `if(false)`): determ rebuilt → ONLY the 39-byte + 41-byte
reject legs flip RED; the correct-width control + the non-hex leg stay green — clean
two-sided. Compiled change — MSVC FAST + WSL2 GCC ci_local both green (run
SEQUENTIALLY); test count unchanged (legs added to an existing subcommand).
*(Design adversarially verified SOUND in Workflow wf_f1a08faf-653; also fixed the stale
node.hpp "i/m/p … not yet exposed by RPC" comment.)*

**PROCESS TRAP HIT (recorded):** the falsify-revert used `git checkout -- node.cpp`
but node.cpp was UNCOMMITTED this round — so the checkout wiped BOTH the mutant AND
the legitimate free-fn definition, leaving node.hpp's decl + main.cpp's call as an
unresolved external (LNK2019). When the file under falsify is UNCOMMITTED, revert the
mutant with a TARGETED edit (restore just the mutated line), never `git checkout`.

## 3u. RL-2 CLOSED — S-014 gossip HELLO-exemption (FAST unit; LAST FAST_UNIT gap)

`GossipNet::handle_message` (`src/net/gossip.cpp:157`) gates every **non-HELLO**
message through the S-014 per-peer-IP token bucket and EXEMPTS HELLO, so a
freshly-attached peer can always finish the handshake even when its IP bucket is
empty (`if (msg.type != MsgType::HELLO) { … if (!rate_limiter_.consume(ip)) return; }`).
The register mutant `if (true)` makes HELLO also consume a token — a peer whose
bucket is drained (e.g. by an attacker sharing its NAT IP) can no longer complete
the handshake, a liveness/censorship break — with no red test.

**Why no existing gate observes it:** `test-rate-limiter` / `-bucket` exercise
`net::RateLimiter` in ISOLATION (never construct GossipNet, never call
handle_message); the live `test_gossip_rate_limit.sh` cluster (excluded from FAST)
measures only aggregate consensus throughput, which one extra token-per-connection
doesn't move; `test-node-reorg-s048` drives GossipNet over VirtualTransport but never
sets a rate limit nor drains a bucket. The mutant is invisible to all three.

Closed by a **new FAST subcommand `determ test-rl2-hello-exempt`** that drives the
REAL `GossipNet::handle_message` over the in-process **VirtualTransport wire** (no OS
socket, deterministic `run_ready` pump) — **no production seam** (the register's
assumed `handle_message_for_test` proved unnecessary). Receiver R: burst=1 bucket,
near-zero refill; sender S: **no `set_hello`** so `connect()` emits no auto-HELLO (an
auto-HELLO would pre-set the peer domain and green the leg even under the mutant).
Three legs + setup: (1) 1st `STATUS_REQUEST` consumes the one token → dispatched
(`on_status_request` counter); (2) 2nd `STATUS_REQUEST` dropped at the drained bucket
— proving it is **provably EMPTY** (the load-bearing non-vacuity control); (3) a
`make_hello("late")` on the EMPTY bucket is STILL dispatched (R's `peer_addresses()`
gains `"(late)"`) — the exemption. Observability is all public: `on_status_request`
(non-HELLO dispatch) + `peer_addresses()` (HELLO set the domain).

*Falsify (executed, reverted via `git checkout` — gossip.cpp was committed, only the
mutant added).* `:157` `if (msg.type != MsgType::HELLO)` → `if (true)`: the HELLO now
enters the consume block, finds the empty bucket, `return`s — never sets the domain →
leg 3 flips RED as the SOLE failure; setup + both STATUS_REQUEST controls stay green
(if the bucket had held a spare token the mutant HELLO would consume it and still
dispatch, so leg 2 being green is what makes leg 3 discriminating). Compiled change —
MSVC FAST + WSL2 GCC ci_local both green (run SEQUENTIALLY); +1 test. Wall-clock note:
`RateLimiter` refills off `steady_clock` (NOT the injected VirtualClock), neutralized
by rate=0.001/s (a sub-second test refills ≪1 token). *(Design adversarially verified
SOUND in Workflow wf_f1a08faf-653.)*

**MILESTONE: the FAST_UNIT tranche is now EXHAUSTED** — every register gap reachable
from an in-process `determ test-*` seam is closed. The remaining open rows are all
OFFLINE_SOURCE (build-free source guards) + 12 CLUSTER (live-node + rpc_tamper_proxy);
§6.1 carries the live count (2 open — all genuinely live-node CLUSTER, NOT source-countable
— after §3ae closed LSP-7 BEHAVIORALLY (live-node resume head-monotonicity G1 gate, mutant-
falsified via a rebuilt determ-light), §3ad closed SS-5 BEHAVIORALLY (live-node auth-ordering
gate), §3ac closed VCW-4 + TI-3 + SU-3 (count-gate invariants 8/9/10, adversarially
verified), §3ab closed OSB-5, and §3aa
reclassified + closed 4 comparison-shaped rows (DR-2/CP-2/AB-2 via a value-hash-bind
completeness invariant, RI-2 already covered by CP-1's invariant-4); §3z closed CP-1 +
PRW-1; on top of §3y's SR-1/LSP-6/RP-5/DR-6 and §3w/§3x's CB-4/WA-2).

## 3v. T-1kd CLOSED — S-014 rate-limiter keys on BARE IP (FAST unit; RECLASSIFIED)

`GossipNet::handle_message` (`gossip.cpp:160-162`) strips `":<port>"` from
`peer->address()` so the S-014 token bucket keys on the **bare IP** — else each
connection (a distinct ephemeral port) gets its OWN bucket and the per-IP rate limit
is trivially defeated by opening N connections. The register mutant deletes the strip
(`auto colon = ip.rfind(':'); if (colon!=npos) ip = ip.substr(0,colon);`), and no
existing gate observed it (`test-rate-limiter` exercises `RateLimiter` in isolation;
the live cluster test measures aggregate throughput).

**RECLASSIFIED OFFLINE_SOURCE → FAST_UNIT.** The gate-class triage (§6.3) had this as
OFFLINE_SOURCE (a grep-presence guard on the strip), but the just-shipped §3u RL-2
harness made a stronger **behavioral** gate cheap: the two adversarial-verify
workflows (wf_f1a08faf-653 for the class, wf_6a81aa3a-4d7 for this design) both
confirmed FAST_UNIT is correct and beats a grep guard. Closed by a 5th leg in the
existing `determ test-rl2-hello-exempt` (no new file): after S drains the bucket, a
SECOND sender S2 shares IP 127.0.0.1 — VirtualTransport hands each connection a
distinct pseudo-port (`virtual_transport.hpp` `next_pseudo_port_`), and its
`remote_endpoint()` header comment even documents that "virtual peers therefore share
the 127.0.0.1 rate-limit bucket." So under the strip S2's `STATUS_REQUEST` is dropped
(shared DRAINED bucket); a `R.peer_count()==2` control pins that S2 actually attached.

*Falsify (executed, reverted via `git checkout` — gossip.cpp was committed, only the
strip deleted).* delete the port strip → S2 keys on `127.0.0.1:<its pseudo-port>`, a
NEW key with a full burst=1 bucket → its `STATUS_REQUEST` is DISPATCHED → the T-1kd
leg flips RED as the SOLE failure; setup + all 4 RL-2 legs (which key on S's own
port-stripped/port-kept IP either way) stay green. Compiled change — MSVC FAST + WSL2
GCC ci_local both green (run SEQUENTIALLY); test count unchanged (leg added to the
existing subcommand). *(Design adversarially verified SOUND in Workflow wf_6a81aa3a-4d7.)*

## 3w. CB-4 CLOSED — node-keygen entropy check fails CLOSED (OFFLINE source guard)

`generate_node_key` (`src/crypto/keys.cpp:36-37`) draws a 32-byte seed from the OS
CSPRNG and derives the Ed25519 node identity from it. The security property is
FAIL-CLOSED entropy: `determ_rng_bytes` returns non-zero on a short/failed read, and
the `if (... != 0) throw` is the only thing between an entropy failure and an
all-zero (or partially-initialised) private seed being published as a validator key.
The register mutant keeps the draw but drops the fatal check —
`(void)determ_rng_bytes(key.priv_seed.data(), 32);` — so a failed OS CSPRNG draw
becomes a silently-forgeable node identity. No unit test can portably force the OS
CSPRNG to fail, so every happy-path keygen test still passes under the mutant (the
fail-closed-branch class — SB-3 §3j, AL-5 §3k).

Closed by NEW `tools/test_keygen_failclosed_guard.sh`, a build-free read-only awk
over `generate_node_key()`'s body wired into ci_local's offline doc-guard loop. It
pins four properties: exactly ONE `determ_rng_bytes` draw (non-vacuity anchor), the
draw sits inside an `if (... != 0)` guard, it is NOT a `(void)`-cast (return not
discarded), and a `throw` follows to abort identity creation. `SELFTEST=1` drives a
coherent and a `(void)`-cast snippet through the SAME extractor to prove it live.

*Falsify (executed, reverted via `git checkout` — keys.cpp was committed, only the
check mutated).* `(void)determ_rng_bytes(...)` → 3 of 4 assertions flip RED
(fail-closed, void-cast, throw), the non-vacuity anchor stays green — the precise
signature. Pure OFFLINE source guard (zero compiled change) → MSVC FAST trivially
unaffected; WSL2 GCC ci_local is the gate (green). *(Design adversarially verified
SOUND in Workflow wf_6a81aa3a-4d7.)*

## 3x. WA-2 CLOSED — wallet receiver-credit gate is exact (OFFLINE source guard)

The wallet tx tally credits a receiver's running balance in exactly one place
(`wallet/main.cpp:18681`): `if (to_hit && t == 0) { tit->second.credits += amt; }`.
The gate is a CORRECTNESS invariant — only a same-shard TRANSFER (tx type 0) to the
tracked account may add to `credits`; DAPP_CALL (10) moves and cross-shard receiver
credits the wallet cannot confirm must fold into `non_tx_delta` instead. The register
mutant widens the gate to `if (to_hit && (t == 0 || t == 10))`, double-counting
DApp-call amounts that already folded into `non_tx_delta` and breaking the
"provably-exact tally" property. Every existing wallet test uses plain TRANSFERs, so
the widened gate passes them all.

Closed by NEW `tools/test_wallet_accounting_credit_gate_source.sh`, a build-free
read-only awk wired into ci_local's offline loop. It pins TWO properties: exactly ONE
`credits +=` site (non-vacuity — a second credit path or a rename flips the count)
and the governing condition EXACTLY `to_hit&&t==0` (whitespace-normalised).
`SELFTEST=1` drives a coherent and a widened-gate snippet through the SAME extractor.

*Falsify (executed, reverted via `git checkout` — wallet/main.cpp was committed).*
widen to `(t == 0 || t == 10)` → the condition assertion flips RED as the SOLE
failure, the non-vacuity anchor stays green. Pure OFFLINE source guard (zero compiled
change) → MSVC FAST trivially unaffected; WSL2 GCC ci_local is the gate (green).
*(Design adversarially verified SOUND in Workflow wf_6a81aa3a-4d7.)*

## 3y. OFFLINE_SOURCE batch 2 — SR-1 + LSP-6 + RP-5 + DR-6 CLOSED (4 light-client source guards)

Four light-client (`light/`) source guards closed in one batch. Designs were
re-verified against CURRENT source and adversarially checked (each on anchor-
uniqueness, non-vacuity, and falsify-reach) in Workflow wf_a639e7da-b94 — all four
returned SOUND. Each falsify was executed against the real (committed) source and
reverted via `git checkout`; all four RED under their own mutant, GREEN post-revert;
one WSL2 GCC `ci_local` run is the gate (pure-offline, zero compiled change → MSVC
FAST trivially unaffected).

- **#2 SR-1 (StateRootAnchorSoundness)** — EXTEND `test_light_state_root_binding_guard.sh`.
  The pre-existing I3b used a bare `grep -q 'succ_prev != recomputed_hex'`, which
  STILL matches the register mutant `if (succ_prev != recomputed_hex && false)` — the
  exact vacuity the register warns of. Added **I3d** (`EXPECTED_BIND_IF=1`: the binding
  IF is the SINGLE-TERM `(succ_prev != recomputed_hex)`, so `&& false` drops the count
  1→0) + **I3e** (`EXPECTED_RECOMPUTE=1`: `recomputed = b.compute_hash()` is a LOCAL
  recompute, so re-sourcing from a daemon field drops it 1→0) + SELFTEST R5/R6.
  *Falsify:* `&& false` at `trustless_read.cpp:637` → I3d RED (I3b stays green — proving
  why I3d was needed), I3e green.
- **#17 LSP-6 (LightStatePersistenceSoundness)** — EXTEND `test_light_resume_monotonicity_guard.sh`.
  New **I7** (`EXPECTED_ANCHOR_BIND=2`): both `verify_chain_from_anchor(...)` call sites
  in `anchored_head` must bind BOTH `st.head_height` AND `st.head_block_hash` (the cached
  anchor as the resume's first verified link). An EXACT count of 2 — a bare `grep -q`
  stays green when only ONE site's binding is stripped (the other still holds
  `st.head_block_hash`). *Falsify:* drop `st.head_block_hash` from the :509 resume call →
  count 2→1 → I7 RED (I6 call-token count stays 2).
- **#23 RP-5 (RegistrantProofSoundness)** — NEW `test_registrant_lifecycle_classifier_coherence.sh`.
  Pins the deactivation classifier (`light/main.cpp:6193`, a two-physical-line statement):
  `EXPECTED_DEACT_ASSIGNS=1` (paren-independent anchor, stays green under `-> false`) +
  the accumulated RHS == `(inactive_from!=0&&inactive_from<=anchored_height)`.
  *Falsify:* `-> false` → content RED, anchor green; drop-conjunct → content RED.
- **#28 DR-6 (DAppRegistryReadSoundness)** — NEW `test_dapp_registry_active_boundary_coherence.sh`.
  Pins the dapp active boundary (`light/main.cpp:7021`): exactly 1 site, RHS ==
  `(anchored_height<inactive_from)`, operator STRICT `<`. *Falsify:* `<` → `<=` → expr
  + op RED, non-vacuity green; `-> true` → anchor count 1→0 RED.

**CI-wiring fix (CP-1-class trap, closed here for the two EXTEND guards).** The
register warned (CP-1) that a design's "the guard runs in ci_local" claim can be FALSE.
Both `test_light_state_root_binding_guard.sh` and `test_light_resume_monotonicity_guard.sh`
were in fact NOT run by `ci_local` at all (absent from the FAST `ONLY_PATTERN` and from
the offline doc-guard loop) — so their invariants were ungated on the local gate. This
round wires all four guards into `ci_local`'s offline doc-guard loop, closing that
pre-existing gap alongside the new invariants. *(Designs adversarially verified SOUND in
Workflow wf_a639e7da-b94.)*

## 3z. OFFLINE_SOURCE EXHAUSTED — CP-1 + PRW-1 CLOSED (last 2 light-client source guards)

The final two OFFLINE_SOURCE gaps, both `NEEDS_FIX` from the §6.3 triage, closed in
one guard extension. Both are properties of the light-client trustless-read path, so
both landed as new positive-count invariants in `tools/test_light_keybind_surface.sh`
(the existing F-6 key-bind completeness guard over the same `light/*.cpp` readers) —
document-convergent (one guard, one read-path) and minimal.

- **#16 CP-1 (ConstantProofSoundness)** — the pre-existing invariants 1-3 classify a
  state_proof consumer as "bound" on the key_bytes EXTRACTION (`b=1` fires on
  `proof.value("key_bytes")`), so the register mutant `if (proof_key_hex != local_key_hex)`
  → `if (false)` (cmd_verify_constant, `light/main.cpp:2851`) leaves the extraction in
  place and slips past 1-3 — a genuine vacuity confirmed this round. New **invariant-4**
  pins a POSITIVE count of the load-bearing comparison (`EXPECTED_KEYBIND_CMP=14`); the
  `if (false)` mutant drops it 14→13 → RED.
- **#26 PRW-1 (StateProofRaceWindowSoundness)** — every trustless reader rejects a proof
  anchored BELOW the verified-chain head with `if (proof_height < vc.height) throw ...`
  (a stale-state race window). The register mutant deletes one guard. New **invariant-5**
  pins `EXPECTED_STALEREAD_GUARD=14`; deleting one drops it 14→13 → RED. *(The banked
  design pointed PRW-1 at `test_light_resume_monotonicity_guard.sh` I7 — that was the
  NEEDS_FIX error; the guard belongs in the keybind-surface reader guard, not the
  anchored_head resume guard.)*

Both counts are 14 (one key-bind + one stale-read guard per trustless reader);
SELFTEST(4)/(5) drive a scratch mutation through the same `grep -hoE | wc -l` extractor.
*Falsify (executed, reverted via `git checkout` — light/main.cpp held ONLY the 2 mutants,
diff-verified before revert).* the two register mutants flip invariant-4 and invariant-5
RED (14→13 each), all other invariants green. **CI-WIRING FIX (the CP-1 NEEDS_FIX itself):**
`test_light_keybind_surface.sh` was NOT run by ci_local (absent from FAST `ONLY_PATTERN`
and the offline loop) — its named CI-wiring claim was FALSE, exactly as the triage warned.
Wired into ci_local's offline doc-guard loop this round (the §3y light-guard trap again).
Pure-offline, zero compiled change → MSVC FAST trivially unaffected; WSL2 GCC ci_local is
the gate (green). **OFFLINE_SOURCE tranche EXHAUSTED — 12 CLUSTER rows remain.**

## 3aa. 4 CLUSTER rows reclassified + closed by value-hash-bind completeness (DR-2 + CP-2 + AB-2 + RI-2)

The §3z-era statement that "all 12 remaining need a live node" was an over-
classification. Four of them are single-comparison verdict binds (`if (X) -> if
(false)` / `= (X) -> = true`) — the SAME shape CP-1 (§3z) closed with a positive-count
completeness invariant. That pattern reclassifies them from CLUSTER to OFFLINE_SOURCE
and closes them deterministically on both platforms, exactly as the RL-2 (§3v) and
CP-1 precedents established. Closed by extending `test_light_keybind_surface.sh` (the
F-6 reader completeness guard already gating the same `light/*.cpp` readers) with
**invariant-6** — three positive counts over the value-hash cleartext cross-checks:

- **#12 DR-2 (DAppRegistryReadSoundness)** — `proof_value_hash != expected_value_hash`
  (`light/main.cpp:6944`, dapp_info read), one of 9. Mutant `-> if (false)` → 9→8 RED.
- **#20 AB-2 (AbortRecordProofSoundness)** — `computed_value_hash != proof_value_hash`
  (`light/main.cpp:2664`, abort-record read), one of 3. Mutant `-> if (false)` → 3→2 RED.
- **#15 CP-2 (ConstantProofSoundness)** — `proof_value_hash == expected_value_hash`
  (`light/main.cpp:2898`, verify-constant), the sole `==` site. Mutant `= true` → 1→0 RED.
- **#19 RI-2 (ReceiptInclusionProofSoundness)** — its key-bind
  `if (proof_key_hex != local_key_hex)` (`light/main.cpp:4796`) is ALREADY one of the 14
  sites **invariant-4** (§3z, CP-1) counts, so the register's `-> if (false)` mutant
  there drops that count 14→13 → RED. No new assertion needed; recorded here.

**Honest scope.** These are SOURCE-COUNT completeness closures: they catch the
register's named `if(false)`/`= true` neuter (falsify-on-mutant, §4) and pin per-reader
completeness — no reader may silently ship without its value-hash cross-check. They do
NOT re-derive the behavioral rejection; that MECHANISM is separately proven by the
live-node MITM tamper tests (`test_light_{supply,stake,registrant}_tamper.sh` via
`tools/rpc_tamper_proxy.py`), which drive a LYING DAEMON and assert the client reports
UNVERIFIABLE. Completeness invariant + behavioral mechanism test = the full defense.
*Falsify (executed, reverted via `git checkout` — light/main.cpp held ONLY the 3
mutants, diff-verified).* the three mutants flip invariant-6 RED (9→8 / 3→2 / 1→0).
Pure-offline, zero compiled change; the guard is already in ci_local's offline loop
(§3z). **The genuinely live-node CLUSTER rows now number 8** (OSB-5, T-3, MPC-3, SS-5,
VCW-4, SU-3, LSP-7, TI-3 — auth control-flow, multi-peer, count-gates in other files,
offline bundle).

## 3ab. OSB-5 CLOSED — offline state-bundle value-hash completeness (invariant-7)

OSB-5 was classified CLUSTER, but the OFFLINE state-bundle verifier
(`light/verify_state_bundle.cpp`, subcommand `verify-state-bundle --in <bundle>
--genesis <file>`) contacts NO daemon — its OSB-5 leg is a value-hash cleartext
cross-check `if (computed_vh != proof_vh)` (line 470) recomputing the account_cleartext
hash and requiring it equal the committee-committed value_hash. That is the same value-
hash-bind shape §3aa closed; the abbreviated var names (`computed_vh`/`proof_vh`) make it
a separate count. Closed by **invariant-7** in `test_light_keybind_surface.sh`
(EXPECTED_BUNDLE_VH=1): a `-> if(false)` neuter drops 1→0 → RED. Same crypto MECHANISM
(a tampered cleartext fails SHA256==value_hash) proven behaviorally by
`test_light_supply_tamper.sh`; this pins the offline bundle reader's completeness.

*Why not the behavioral bundle-tamper leg?* `test_light_state_bundle.sh` already tampers
the bundle's `anchor_block.state_root` / `successor_header.prev_hash` (committee binding)
as cluster legs, but never `account_cleartext` (the OSB-5 leg). Adding that leg is sound,
but the account_cleartext leg sits BEHIND the committee-binding gate, so it needs a REAL
committee-signed bundle (a live-node export); the 3-node cluster does not come up
reliably on WSL2 /mnt/c (it hung past 300s), so a cluster leg cannot be verified here.
The completeness invariant is the deterministic both-platform closure; the behavioral
account_cleartext leg remains available as a CI/WSL2 cluster leg for a future live round.
*Falsify (executed, reverted via `git checkout`).* the `if(false)` mutant flips
invariant-7 1→0 RED. Pure-offline, guard already in ci_local's loop (§3z); WSL2 GCC
ci_local green. **7 remaining are genuinely live-node CLUSTER** (T-3, SS-5 auth control-
flow; MPC-3 multi-peer; VCW-4/TI-3 count-gates; SU-3 height-gated supply; LSP-7 resume).

## 3af. MPC-3 investigated — the banked live-fork design is IMPRACTICAL as a fixture (documented negative result)

Attempting the banked MPC-3 DIVERGENCE gate (the design in §3ae / Workflow wf_d9008c84-0ad)
surfaced a real infrastructural obstacle that INVALIDATES it as a live fixture. The design's
reachability premise was partly right, partly fatally wrong:
- **CONFIRMED:** two same-identity M=1/K=1 partitioned `determ` instances DO build divergent
  chains (per-round `dh_input` is fresh OS randomness + `proposer_time` is wall-clock, so
  `block_hash`, `timestamp`, `delay_seed`/`delay_output` all differ at every h≥1 — verified by
  diffing A/B `chain.json`). `state_root` at equal height MATCHES (no txs → same balances).
- **FATAL for the fixture:** (1) `verify_chain_to_head` walks `[0, head)`, so at a LOW equal
  height the compared head is still the SHARED GENESIS PREFIX → AGREE, not DIVERGENCE (the fork
  only shows once the walk includes block ≥1, i.e. head height ≥2). (2) the block timers
  (`tx_commit_ms`/`block_sig_ms`) do NOT throttle EMPTY-block production — a peerless M=1 node
  mints back-to-back at max speed (~10+ blocks/s), so nodes CANNOT be frozen or plateaued at a
  common height; two independent instances DRIFT continuously and are almost never at an equal
  height, making the DIVERGENCE leg a pure race. (3) the chains grow tall within seconds, so
  cross-check (which re-walks every header per peer) becomes slow and the whole test runs >120s
  — unsuitable for the suite.

Net: DIVERGENCE-at-a-common-height is not reliably samplable from two free-running nodes. A
sound live gate would need chain-file surgery — truncate two divergent chains to an identical
height H≥2 and recompute `head_hash`, then serve them frozen — which is too error-prone for a
shell fixture. The two register-named mutants (neutralize `if(false)` at :2122; over-compare —
flatten the by_height grouping 2115-2131) therefore stand UN-gated behaviorally. The
lag-benignity leg (different-height peers → INCONCLUSIVE) + the AGREE positive control ARE
reliably reachable, but they only cover the over-compare mutant; the load-bearing NEUTRALIZE
mutant needs the equal-height fork the free-running fixture cannot reliably produce.

**MPC-3 is RE-CLASSIFIED alongside T-3-s001 as a behavioral residual that needs a purpose-built
freeze-two-forks harness (or owner review) — NOT the banked free-running-nodes fixture. No test
was committed for this attempt** (a fixture that always SKIPs its load-bearing leg is not a gate).

## 3ae. LSP-7 CLOSED — behavioral (live-node) resume head-monotonicity gate, falsify-on-mutant via a rebuilt binary

The SECOND live-node CLUSTER residual closed BEHAVIORALLY (continuing the owner-directed live
round, 2026-07-23). `tools/test_light_resume_regression_live.sh` — the behavioral complement to
the STATIC source guard `test_light_resume_monotonicity_guard.sh` (which only asserts the throw
TOKEN is present in source; a functional fail-open that keeps the token but regresses the height
comparison is invisible to grep, caught here by a live exit-code differential) — pins the G1
resume head-monotonicity gate in `anchored_head` (light/trustless_read.cpp:443).

- **#25 LSP-7 (LightStatePersistenceSoundness)** — G1: `if (daemon_head < st.head_height) throw
  "...is BELOW the previously committee-verified anchor..."`. The cached anchor is written by
  `verify-chain --persist` ONLY after a full genesis-to-head verify (LSP-1); a fork-free chain
  never regresses, so a daemon below the anchor is serving stale/rollback state and MUST be
  refused. The discriminator is a pure HEIGHT comparison — no fork, no sampling race:
    * G1-NEGATIVE leg — a committee-verified cache at height H (53), then `verify-chain --resume`
      against a below-anchor daemon (a FRESH data-dir seeded with node1's `node_key.json` + the
      SAME genesis → rebuilds a short, committee-VALID chain from 0, the doc's "restored from an
      old snapshot"; head 1) → HONEST throws exit 1 with "is BELOW ... anchor".
    * POSITIVE CONTROL — `--resume` against a legitimately-AHEAD daemon (>H) → exit 0 "RESUMED"
      (proves the gate is not always-reject); stays green under both binaries.

Design + falsify plan were adversarially produced + judged in Workflow wf_d9008c84-0ad (a
2-design + judge panel; the judge picked LSP-7 over MPC-3 for reliability — LSP-7's discriminating
state is deterministic, while MPC-3's DIVERGENCE leg risks a spurious RED when a peer is
transiently unverifiable). The panel CORRECTED a critical design flaw: a BARE DELETE of the G1
throw does NOT discriminate (control falls to the `>anchor` resume branch :509, whose own head
fetch re-throws the G3 error at :526) — so the honest side asserts BOTH exit==1 AND the
G1-specific "is BELOW ... anchor" token, and the FAITHFUL mutant is the fall-back-to-full-verify-
and-accept (the pre-LSP-7 fail-open), not a delete.

*Falsify-on-mutant (executed via a REBUILT determ-light — determ.exe untouched, so the live nodes
keep working).* Replaced the G1 throw (trustless_read.cpp:443-454) with the pre-LSP-7 fall-back-
to-full-verify-accept, rebuilt determ-light, re-ran → the G1-negative leg flipped to exit 0
"daemon not ahead of cached anchor — full verify" (silent accept of the height-1-vs-anchor-53
regression), 3/0 → 2/1 RED; the positive control stayed GREEN (the discriminator is the
G1-negative leg specifically). Reverted via `git checkout light/trustless_read.cpp` (committed
clean this round), rebuilt, re-ran → 3/0 green.

Windows-standalone: auto-globbed into the FULL `run_all.sh`, EXCLUDED from FAST=1 (needs live
daemons), NOT in ci_local → zero compiled/gate delta for the commit. **2 remaining CLUSTER: T-3
(handle_session, owner-DEFERRED), MPC-3 (multi-peer cross-check LOOP — the banked free-running-
nodes design was ATTEMPTED and found IMPRACTICAL as a fixture, §3af: nodes mint unthrottled so
cannot be frozen/plateaued at a common height, making the equal-height DIVERGENCE sample a pure
race; re-classified as needing a freeze-two-forks harness or owner review).**

## 3ad. SS-5 CLOSED — behavioral (live-node) auth-ordering gate, falsify-on-mutant via a REBUILT binary

The FIRST live-node CLUSTER residual closed BEHAVIORALLY (owner-directed live round,
2026-07-23). `tools/test_rpc_dapp_subscribe_auth.sh` — a single-node (M=K=1),
auth-ENABLED daemon with the `determ` CLI as the wire client — pins the SS-5 ordering
property in `src/rpc/rpc.cpp::handle_session`: `verify_auth` (line 171) fires BEFORE
the `dapp_subscribe` socket-takeover branch (line 175), so an unauthenticated subscribe
is refused at the auth gate and never reaches the handler.

- **#14 SS-5 (StreamingSubscriptionSoundness)** — the discriminator is the SAME
  unknown-domain `dapp_subscribe` request with auth toggled:
    * UNauthenticated → `auth_required: missing 'auth' field` (auth precedes the domain
      inspection — the correct ordering).
    * AUTHENTICATED   → `invalid_arg: unknown DApp domain` (reaches the handler —
      the positive control proving the gate is live, not a reject-everything tautology).
  A control leg re-proves the gate is enabled (unauth `status` → auth error), so the
  SS-5 legs rest on a confirmed-ON gate. NO cluster, NO dapp registration needed.

*Falsify-on-mutant (executed via a REBUILT binary — the gold standard for a behavioral
gate).* The register's named SS-5 mutation (hoist the `dapp_subscribe` branch above the
auth check) was applied minimally to `rpc.cpp:172` (`!auth_err.empty()` →
`!auth_err.empty() && req.value("method","") != "dapp_subscribe"`, so an unauthenticated
subscribe skips the auth-error branch and falls through to the handler), `determ.exe`
rebuilt, and the test RE-RUN: the unauth leg flipped to `invalid_arg: unknown DApp` — the
handler ran WITHOUT auth — turning the gate RED (3/0 → 2/1). The `status` control leg
stayed GREEN under the mutant, which is exactly WHY the status-only `test_rpc_hmac_auth.sh`
cannot catch SS-5 (status is the final dispatch branch, auth-gated even under the hoist).
Mutant reverted via `git checkout src/rpc/rpc.cpp` (committed clean this round), rebuilt,
re-run → 3/0 green.

Windows-standalone (needs a live daemon): auto-globbed into the FULL `run_all.sh` run
(`for t in tools/test_*.sh`), correctly EXCLUDED from FAST=1 (its ONLY_PATTERN allowlist
omits it). NOT in ci_local — the WSL2 `/mnt/c` cluster infeasibility stands, but the
single-node daemon comes up fine natively on Windows (the WSL hang was `/mnt/c`-specific,
confirmed this round: a 3-node cluster reached height 12 under Git Bash). **3 remaining
CLUSTER: T-3 (handle_session, owner-DEFERRED — a subtle auth-before-dispatch mutant that
keeps dapp_subscribe auth-gated, needs review not a fixture), MPC-3 (multi-peer cross-check
LOOP), LSP-7 (resume persistence).**

## 3ac. VCW-4 + TI-3 + SU-3 CLOSED — 3 count-gate completeness invariants (adversarially verified)

The 3 count-gate-shaped CLUSTER rows closed by invariants 8/9/10 in
`test_light_keybind_surface.sh`, each a positive count of the load-bearing verdict
comparison (`-> if(false)` mutant drops it 1→0 → RED). Designs were adversarially
verified against current source in Workflow wf_52594f94-a57 BEFORE shipping — which
caught a real design error (see TI-3).

- **#18 VCW-4 (VerifyChainWalkSoundness)** — **invariant-8**: the header-walk truncation
  gate `headers_seen != head_height - start_from` (`trustless_read.cpp:342`), the sole
  catcher of a short FINAL page (a truncated last page passes contiguity + per-block
  sigs but leaves trailing headers unverified). On the UNCONDITIONAL post-loop verdict
  path — no runtime-skip caveat. Anchor is the FULL comparison (the bare
  `head_height - start_from` substring also appears in the adjacent error string, count 2).
- **#30 TI-3 (TxInclusionProofSoundness)** — **invariant-9**: the tx_root recompute-and-
  match gate `recomputed_root != b.tx_root` (`verify_tx_inclusion.cpp:185`, proof §4.3
  r_A==r*). **The verifier CORRECTED the naive design:** the register's cited sites
  (`committed.find(h)==end()` :217, `body_hashes.size()!=committed.size()` :231) are NOT
  load-bearing — they validate the body against an ALREADY committee-signed `committed`
  set and cannot forge a false INCLUDED/NOT-INCLUDED (the verdict at :253 reads
  `committed`, never the body). Pinning :217/:231 would have gated the wrong site; :185
  (the tx_root recompute) is the operative gate.
- **#24 SU-3 (SupplyProofSoundness)** — **invariant-10**: the A1 total-mismatch VIOLATED
  leg `have_claimed_total && claimed_total != expected_total` (`main.cpp:8157`).
  LIMITATION (recorded in the guard comment): this leg is R51-HEIGHT-GATED
  (`have_claimed_total` forced false at ~8132 when the fresh chain_summary height differs
  from the anchored height), so the compare is CONDITIONALLY load-bearing — the invariant
  pins its TEXT-PRESENCE (the canonical `else if(false)` neuter), not runtime firing, the
  same contract as invariants 4/6/7.

*Falsify (executed, reverted via `git checkout` — the 3 source files held ONLY the 3
mutants, diff-verified).* the three mutants flip invariant-8/9/10 RED (each 1→0). Pure-
offline, guard already in ci_local's loop (§3z); WSL2 GCC ci_local green. **4 remaining
are genuinely live-node CLUSTER, NOT source-countable: T-3 + SS-5 (rpc.cpp handle_session
auth BRANCH-ORDERING control-flow), MPC-3 (multi-peer cross-check LOOP), LSP-7 (resume
persistence).**

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

## 6. The reconstructed MED/LOW register (open items)

The original audit (§2) carried only the 14 HIGH into this document and
recorded the lower tiers as bare counts. A **2026-07-21 reconstruction**
re-ran the traceability workflow over the same 93 security-property docs
(16 finders -> per-claim adversarial verifier whose default verdict was
REFUTED; 54 agents, ~8.2M tokens) to **enumerate** them — the actionable
list this register previously lacked. It confirmed **34** unenforced gaps
(each with a concrete surviving mutation) and, usefully, found **4**
claims the first pass had flagged that ARE in fact gated (§6.2). Ranked
by the verifier's value_rank (1 = must-gate), then severity, then
gate-cost. **SP-2 (§3i), SB-3 (§3j), AL-5 (§3k), STMC-5 (§3l), T-3 (§3m), PCL-1 (§3n), ADC-3 (§3o), T-1 (§3p), BinaryCodec-T-3 (§3q), MakeContribCommit-T-1 (§3r), T-OE4 (§3s), SP-CK-2 (§3t), RL-2 (§3u), T-1kd (§3v), CB-4 (§3w), WA-2 (§3x), SR-1 + LSP-6 + RP-5 + DR-6 (§3y), CP-1 + PRW-1 (§3z), DR-2 + CP-2 + AB-2 + RI-2 (§3aa), OSB-5 (§3ab), VCW-4 + TI-3 + SU-3 (§3ac), SS-5 (§3ad), LSP-7 (§3ae) are now closed** — leaving 2. **The FAST_UNIT AND OFFLINE_SOURCE tranches are BOTH EXHAUSTED, plus the 8 comparison/value-hash/count-gate-shaped CLUSTER rows (§3aa + §3ab + §3ac); and the two live-node CLUSTER rows SS-5 (§3ad, single-node auth-ordering) + LSP-7 (§3ae, resume head-monotonicity G1) are now closed BEHAVIORALLY, each mutant-falsified via a rebuilt binary. The 2 remaining are live-node CLUSTER: T-3 (rpc.cpp handle_session, owner-DEFERRED — a subtle auth-before-dispatch mutant that keeps dapp_subscribe auth-gated, needs review not a fixture), MPC-3 (multi-peer cross-check loop — the banked free-running-nodes design was attempted and found IMPRACTICAL as a fixture, §3af; needs a freeze-two-forks harness or owner review).**

### 6.1 Confirmed unenforced MED/LOW claims (2 open — all live-node CLUSTER + SP-2, SB-3, AL-5, STMC-5, T-3, PCL-1, ADC-3, T-1, BinaryCodec-T-3, MakeContribCommit-T-1, T-OE4, SP-CK-2, RL-2, T-1kd, CB-4, WA-2, SR-1, LSP-6, RP-5, DR-6, CP-1, PRW-1, DR-2, CP-2, AB-2, RI-2, OSB-5, VCW-4, TI-3, SU-3, SS-5, LSP-7 CLOSED)

| # | Claim | Doc | Sev | Gate-cost | Status | Silently-deletable check (verifier's surviving mutation) |
|---|---|---|---|---|---|---|
| 1 | SP-2 | StakeProofSoundness | MED | trivial | **CLOSED §3i** | SURVIVING MUTATION: light/main.cpp:2395 `if (computed_value_hash != proof_value_hash)` -> `if (false)` (or a -Wunused-safe `if (computed_value_hash != |
| 2 | SR-1 | StateRootAnchorSoundness | MED | moderate | **CLOSED §3y** | Surviving mutation: light/trustless_read.cpp:637 `if (succ_prev != recomputed_hex && false) {` (equivalently, at :577 source `recomputed` from the dae |
| 3 | ADC-3 | AbortDigestCanonicalizationSoundness | MED | trivial | **CLOSED §3o** (legs re-derived on the D2-inc3 `DTM-F2-ABORT-v2` binary preimage) | Surviving mutant: in light/verify.cpp::hash_abort_event delete `b.append(static_cast<uint64_t>(e.timestamp));` (now line 96) OR swap the round/aborting_node appends (now lines 94/95) |
| 4 | T-1 | RpcAuthHmacSoundness | MED | trivial | **CLOSED §3p** | SURVIVING MUTATION: src/rpc/rpc.cpp:52 `canonical_for_hmac` -> `return params.dump();` (drop the `method + "\|"` prefix). It survives every existing g |
| 5 | OSB-5 | OfflineStateBundleSoundness | MED | trivial | **CLOSED §3ab** | Surviving mutation: delete verify_state_bundle.cpp:455-478 (or set the compare to `if(false)`). It survives EVERY existing gate. test_light_state_bund |
| 6 | SB-3 | SubsidyAccountingSoundness | MED | trivial | **CLOSED §3j** | SURVIVING MUTANT: chain.cpp:1761 replace `if (!checked_add_u64(bal, per_creator, &bal)) { throw }` with `bal += per_creator;`. It survives EVERY exist |
| 7 | AL-5 | AuditLayerSoundness | MED | trivial | **CLOSED §3k** | Surviving mutation: delete both audit-map restore branches at src/chain/chain.cpp:775-778 (`if (s.audit_keys) audit_keys_ = std::move(*s.audit_keys);` |
| 8 | T-3 | S001RpcAuthSoundness | MED | trivial | open | Surviving mutant in src/rpc/rpc.cpp::handle_session: keep the `dapp_subscribe` else-if branch exactly as-is (so it stays auth-gated and test_dapp_subs |
| 9 | T-3 | ConsensusPhaseStructureSoundness | MED | trivial | **CLOSED §3m** | Surviving mutation: validator.cpp:446 `if (expected_output != b.delay_output) return {false,"delay_output mismatch (commit-reveal)"}` -> `if (false) . |
| 10 | PCL-1 | ParamChangeLintSoundness | MED | trivial | **CLOSED §3n** | Surviving mutation: add "NEW_SCALAR" to the validator's kWhitelist literal at src/node/validator.cpp:784-789 (a trivially-compilable one-line std::set |
| 11 | STMC-5 | ShardTipMergeClosureSoundness | MED | trivial | **CLOSED §3l** | Surviving mutation: delete/neutralize the overflow guard at src/node/validator.cpp:922-926 (`if (ev->evidence_window_start + threshold < ev->evidence_ |
| 12 | DR-2 | DAppRegistryReadSoundness | MED | moderate | **CLOSED §3aa** | SURVIVING MUTATION: light/main.cpp:6944 `if (proof_value_hash != expected_value_hash){ verdict=UNVERIFIABLE; ... }` -> `if (false){ ... }` survives EV |
| 13 | MPC-3 | MultiPeerCrossCheckSoundness | MED | moderate | open | Surviving mutation: in light/main.cpp cmd_cross_check (lines 2103-2131) replace the by_height intra-group comparison with a loop that compares every p |
| 14 | SS-5 | StreamingSubscriptionSoundness | MED | moderate | **CLOSED §3ad** | SURVIVING MUTANT: in src/rpc/rpc.cpp handle_session (~line 171-204), hoist the `req.value("method","")=="dapp_subscribe"` takeover branch ABOVE the `v |
| 15 | CP-2 | ConstantProofSoundness | MED | moderate | **CLOSED §3aa** | Surviving mutant: light/main.cpp:2898 `bool confirmed = (proof_value_hash == expected_value_hash);` -> `bool confirmed = true;` (verify-constant repor |
| 16 | CP-1 | ConstantProofSoundness | MED | moderate | **CLOSED §3z** | SURVIVING MUTATION: in light/main.cpp cmd_verify_constant, change line 2851 `if (proof_key_hex != local_key_hex) {` to `if (false) {` (compile-clean v |
| 17 | LSP-6 | LightStatePersistenceSoundness | MED | moderate | **CLOSED §3y** | Surviving mutation: in anchored_head (light/trustless_read.cpp:509) change verify_chain_from_anchor(rpc, committee_seed, st.head_height, st.head_block |
| 18 | VCW-4 | VerifyChainWalkSoundness | MED | moderate | **CLOSED §3ac** | Surviving mutation: in light/trustless_read.cpp change the walked-count gate (lines 342-348) `if (headers_seen != head_height - start_from)` to `if (f |
| 19 | RI-2 | ReceiptInclusionProofSoundness | MED | moderate | **CLOSED §3aa** | Surviving mutant: in light/main.cpp cmd_verify_receipt_inclusion, change `if (proof_key_hex != local_key_hex)` (~line 4796) to `if (false)`. RI-2's ke |
| 20 | AB-2 | AbortRecordProofSoundness | MED | hard | **CLOSED §3aa** | Surviving mutation: light/main.cpp:2664 `if (computed_value_hash != proof_value_hash)` -> `if (false)` neutralizes the TAMPERED value-hash bind of the |
| 21 | T-3 | BinaryCodecRoundTripSoundness | LOW | trivial | **CLOSED §3q** | Surviving mutant: delete `if (len < 128 + 1 + 2) throw std::runtime_error("binary_codec: tx frame too short");` at src/net/binary_codec.cpp:256-257. E |
| 22 | T-1 | MakeContribCommitmentBackwardCompat | LOW | trivial | **CLOSED §3r** | Surviving mutation: `bool any_view = true;` at src/node/producer.cpp:277-279 (equivalently, make the local is_zero_hash lambda return false). make_con |
| 23 | RP-5 | RegistrantProofSoundness | LOW | moderate | **CLOSED §3y** | SURVIVING MUTATION: light/main.cpp:6193 `bool deactivated = (inactive_from != 0 && inactive_from <= anchored_height)` -> `bool deactivated = false;` ( |
| 24 | SU-3 | SupplyProofSoundness | LOW | moderate | **CLOSED §3ac** | Surviving mutation: in light/main.cpp cmd_supply_trustless, neutralize the total-mismatch VIOLATED leg at ~8157 `else if (have_claimed_total && claime |
| 25 | LSP-7 | LightStatePersistenceSoundness | MED | hard | **CLOSED §3ae** | No behavioral gate exists; the only LSP-7 gate (test_light_resume_monotonicity_guard.sh) is a static awk/grep over light/trustless_read.cpp asserting  |
| 26 | PRW-1 | StateProofRaceWindowSoundness | LOW | trivial | **CLOSED §3z** | Surviving mutation: delete the `if (proof_height < vc.height) { throw ... "is BEFORE verified-chain head ... serving stale state" }` block at light/tr |
| 27 | T-OE4 | OfflineEquivocationEvidenceSoundness | LOW | trivial | **CLOSED §3s** | Surviving mutation: delete V11 clause 3 (`else if (!sig_a_ok)`, light/main.cpp 7587-7589) — an event with sig_a INVALID + sig_b VALID skips clause 4 and reaches EQUIVOCATION-PROVEN. |
| 28 | DR-6 | DAppRegistryReadSoundness | LOW | moderate | **CLOSED §3y** | SURVIVING MUTANT: light/main.cpp:7021 `active = (anchored_height < inactive_from)` -> `active = true;` (equivalently `<` -> `<=`). It survives EVERY e |
| 29 | RL-2 | S014RateLimiterSoundness | LOW | moderate | **CLOSED §3u** | Surviving mutation: src/net/gossip.cpp:157 `if (msg.type != MsgType::HELLO) { ...consume(ip)... }` -> `if (true) { ... }` so HELLO also consumes a token (breaks the handshake-always-completes exemption). |
| 30 | TI-3 | TxInclusionProofSoundness | LOW | moderate | **CLOSED §3ac** | SURVIVING MUTATION: in light/verify_tx_inclusion.cpp step 5, change `if (committed.find(h) == committed.end())` (line ~217) and/or `if (body_hashes.si |
| 31 | WA-2 | WalletDomainAccountingSoundness | LOW | moderate | **CLOSED §3x** | Surviving mutant: in wallet/main.cpp cmd_account_accounting (line ~18681) widen the receiver gate to `if (to_hit && (t == 0 \|\| t == 10)) { tit->seco |
| 32 | CB-4 | CryptoBackendMigrationSoundness | LOW | moderate | **CLOSED §3w** | Surviving mutant (keys.cpp:36-37): drop the fatal check but keep the draw — `(void)determ_rng_bytes(key.priv_seed.data(), 32);` — so a failed/partial  |
| 33 | T-1 | RateLimiterKeyDerivationSoundness | LOW | moderate | **CLOSED §3v** | Surviving mutation: delete the port strip in src/net/gossip.cpp GossipNet::handle_message (`auto colon = ip.rfind(':'); if (colon!=npos) ip = ip.substr(0,colon);`) so each connection keys on ip:port, defeating per-IP limiting. RECLASSIFIED to FAST_UNIT (2nd-sender leg in test-rl2-hello-exempt). |
| 34 | SP-CK-2 | StateProofCompositeKeySoundness | LOW | moderate | **CLOSED §3t** | Surviving mutation: src/node/node.cpp:4709 `if (body.size() != want)` -> `if (false)` (now `decode_composite_state_body`'s `d.ok = true`). A wrong-width composite body (39/41-byte `i:`) aliases a different leaf. |

### 6.2 Re-examined and found GATED (4 — recorded so they are not re-audited)

| Claim | Doc | Enforcing gate the reconstruction located |
|---|---|---|
| T-5 | JsonValidationSoundness | test-consensus-msgs (src/main.cpp:13103; wrapper tools/test_consensus_msgs.sh; FAST both platforms). The tx_hashes defense-in-depth object at src/main |
| T-2 | BlockchainStateIntegrity | test-eligibility-floor (src/main.cpp ~26377-26426; wrapper tools/test_eligibility_floor.sh; FAST both platforms). Its "lost-K reload (K defaulted 0) i |
| SP-5 | ShieldedPoolSoundness | Catching gate: `determ test-ctx-enote` (wrapper tools/test_ctx_enote.sh; FAST regex token `ctx_enote` in run_all.sh:108, so gated on BOTH platforms vi |
| DC-1 | DAppRegistryCommitmentSoundness | Catching gate: `test-dapp-registry-trustless-read` (wrapper tools/test_dapp_registry_trustless_read.sh; wired in run_all.sh FAST pattern, both platfor |

**Method note.** Like the original, this is a register of *absent gates*, not
of bugs — every listed property is believed to hold today. The remediation
pattern is §4's: add the negative assertion, then falsify-on-mutant. Rows
are refreshed by re-running the workflow (§5).

### 6.3 Gate-class triage of the open backlog (Workflow wf_b2e68071)

A read-only reachability sweep (25 agents, one per open row) classified how each
remaining gap is *closeable*, so future rounds pick by cost rather than re-deriving
reachability each time. Three classes:

- **FAST_UNIT** — the mutated code is reachable from a `determ test-*` (or
  `determ-light`) subcommand seam, so an additive in-process negative leg closes it
  on **both** platforms with no live node. Cheapest. **TRANCHE EXHAUSTED** — all
  FAST_UNIT gaps are closed: #22 MakeContribCommit-T-1 §3r, #27 T-OE4 §3s, #34
  SP-CK-2 §3t, #29 RL-2 §3u. Kept here for the pattern record:
  - **#29 RL-2** (CLOSED §3u — S-014 gossip HELLO-exempt token consume,
    `gossip.cpp:157`; mutant `if (msg.type != HELLO)` → `if (true)`). **No new seam
    needed** — the register's assumed `handle_message_for_test` was UNNECESSARY: the
    existing VirtualTransport wire path (used by `test-node-reorg-s048`) already drives
    `handle_message` in-process, with `on_status_request` (dispatch counter) +
    `peer_addresses()` (proves a HELLO was dispatched) as public observability. New
    subcommand `test-rl2-hello-exempt`. TRAPS confirmed real: keep sender domain empty
    (connect() auto-HELLOs); rate ~0.001/s (avoid a refill between drain and the HELLO);
    the bucket-empty control is load-bearing (non-vacuity).
  - **#34 SP-CK-2** (CLOSED §3t — composite-key body-width guard `node.cpp:4709`
    `if (body.size()!=want)`; mutant `if(false)`). Needs ONE additive **byte-neutral**
    production seam — extract a pure free fn `decode_composite_state_body(ns,hex) ->
    {hex_ok, ok, body, want}` (DECL node.hpp / DEFN node.cpp, verbatim from
    node.cpp 4695-4718); `rpc_state_proof` calls it and rebuilds its TWO existing
    error-json shapes VERBATIM (verify byte-identity with `test_state_proof.sh`
    before/after). EXTEND the existing `test-state-proof-composite-key` subcommand
    (already in FAST regex) to assert on the struct — no new wrapper, no regex edit.
  *(#22 MakeContribCommit-T-1 was in this class — CLOSED §3r; #27 T-OE4 — CLOSED §3s.)*
- **OFFLINE_SOURCE (TRANCHE EXHAUSTED — 0 left)** — a source-parity / presence invariant
  closeable by a build-free awk/source guard wired into ci_local's offline loop (the
  PCL-1 / ADC-3 / T-1 pattern). **ALL closed:** #2 SR-1 + #17 LSP-6 + #23 RP-5 + #28 DR-6
  (§3y), #31 WA-2 (§3x), #32 CB-4 (§3w), and the final two #16 CP-1 + #26 PRW-1 (§3z).
  *(#33 T-1kd was here but RECLASSIFIED to FAST_UNIT and CLOSED §3v — a behavioral
  2nd-sender leg beat the grep guard.)* **Designs adversarially
  verified in Workflow wf_6a81aa3a-4d7 (each pins a POSITIVE anchor count so a
  rename/delete flips RED, never a bare substring grep):**
  - **#2 SR-1** (CLOSED §3y): EXTEND `test_light_state_root_binding_guard.sh` — added I3d
    (`if (succ_prev != recomputed_hex)` pinned to a single-term parenthesized form,
    EXPECTED_BIND_IF=1, so `&& false` breaks it) + I3e (`Hash recomputed = b.compute_hash();`
    EXPECTED_RECOMPUTE=1, so re-sourcing from a daemon field breaks it) + SELFTEST R5/R6.
    Falsified (`&& false` → I3d RED, I3b stays green — the vacuity that motivated I3d),
    ci_local green. Also wired into ci_local (was previously unrun there).
  - **#32 CB-4** (CLOSED §3w): NEW `tools/test_keygen_failclosed_guard.sh` (+ ci_local wire) —
    asserts `keys.cpp generate_node_key` fatal-throws on `determ_rng_bytes(...) != 0`, no
    `(void)`-cast of the RNG return. Falsified (void-cast → 3/4 RED), ci_local green.
  - **#17 LSP-6** (CLOSED §3y): EXTEND `test_light_resume_monotonicity_guard.sh` I7 — the
    `verify_chain_from_anchor` initial-prev-anchor binding, EXACT count of 2 call sites
    binding st.head_height + st.head_block_hash. Falsified (drop the :509 resume site's
    block_hash → count 2→1 RED), ci_local green. Also wired into ci_local (was unrun).
  - **#31 WA-2** (CLOSED §3x): NEW `tools/test_wallet_accounting_credit_gate_source.sh` — the
    `credits +=` receiver-gate must stay `to_hit && t == 0` (single-shard TRANSFER only).
    Falsified (widen to `t==0||t==10` → condition RED), ci_local green.
  - **#23 RP-5** (CLOSED §3y): NEW `tools/test_registrant_lifecycle_classifier_coherence.sh` —
    the deactivation clause == `(inactive_from!=0&&inactive_from<=anchored_height)` (multi-line
    accumulate). Falsified (`-> false` / drop-conjunct → content RED), ci_local green.
  - **#28 DR-6** (CLOSED §3y): NEW `tools/test_dapp_registry_active_boundary_coherence.sh` —
    the dapp active boundary `(anchored_height<inactive_from)`, STRICT `<`. Falsified
    (`<` → `<=` → expr+op RED; `-> true` → anchor 1→0 RED), ci_local green.
  - **#26 PRW-1** (CLOSED §3z): the banked "EXTEND test_light_resume_monotonicity_guard.sh
    I7" pointer was the NEEDS_FIX error — the `proof_height < vc.height` stale-read guard
    belongs in `test_light_keybind_surface.sh` (same reader path), NOT the anchored_head
    resume guard. Shipped as invariant-5 (EXPECTED_STALEREAD_GUARD=14). Falsified, ci_local green.
  - **#16 CP-1** (CLOSED §3z): EXTEND `test_light_keybind_surface.sh` invariant-4 pinning
    `proof_key_hex != local_key_hex` count (=14) — invariants 1-3 counted the EXTRACTION,
    so `if(false)` slipped past (confirmed vacuity). The design's named CI-wiring claim WAS
    FALSE (guard was absent from ci_local): re-verified + wired into the offline loop this
    round before shipping, exactly as the NEEDS_FIX warned. Falsified, ci_local green.
  Full designs: scratchpad/offline_designs.txt (session-local; re-extract from the
  wf_6a81aa3a-4d7 journal if needed).
- **CLUSTER (2 left — the genuinely behavioral residual)** — light-client verdict logic
  needing a live node + the `rpc_tamper_proxy.py` MITM; Windows-standalone, not in ci_local.
  **#8 T-3, #13 MPC-3** — auth branch-ordering control-flow (T-3 in rpc.cpp handle_session),
  multi-peer cross-check loop (MPC-3). These are NOT single-comparison count-gates (a
  source-count completeness invariant cannot catch a branch-hoist / loop-rewrite / ordering
  mutation), so they need a live-node behavioral test or careful review. *(#14 SS-5 CLOSED §3ad
  + #25 LSP-7 CLOSED §3ae — the two live-node CLUSTER rows closed BEHAVIORALLY:
  `test_rpc_dapp_subscribe_auth.sh` pins dapp_subscribe-behind-auth on a single auth-enabled
  node (3/0 → 2/1 under the hoist), and `test_light_resume_regression_live.sh` pins the G1
  resume head-monotonicity gate (cache@H vs a below-anchor daemon → exit 1 'is BELOW'; 3/0 →
  2/1 under the pre-LSP-7 fall-back-accept mutant), each mutant-falsified via a rebuilt binary.
  These prove the live-round approach: the 3-node cluster hangs on WSL2 /mnt/c but single/multi-
  node daemons come up fine natively on Windows Git Bash. #18 VCW-4, #24 SU-3, #30 TI-3 CLOSED
  §3ac via count-gate invariants 8/9/10 — TI-3's anchor was corrected from the non-load-bearing
  body checks to the tx_root recompute by the adversarial verifier. #12 DR-2, #15 CP-2, #19 RI-2,
  #20 AB-2 CLOSED §3aa; #5 OSB-5 CLOSED §3ab — all were CLUSTER-classified but were
  comparison/value-hash binds closed by the completeness invariants.)* **#8 T-3-s001 stays
  DEFERRED** (owner-flagged handle_session auth review). MPC-3 was the last non-deferred residual;
  its banked free-running-nodes design was ATTEMPTED and found IMPRACTICAL as a fixture (§3af —
  unthrottled minting prevents freezing two forks at a common height; the equal-height DIVERGENCE
  sample is a pure race, and the tall chains push the run >120s). Both remaining rows now need a
  purpose-built harness (MPC-3: freeze-two-forks; T-3: handle_session review), not an additive fixture.

**#8 T-3-s001 (handle_session auth-before-dispatch) stays DEFERRED** — LIVE auth
control flow, not an additive guard; needs careful review, not a fixture.

Recommended order: **BOTH the FAST_UNIT and OFFLINE_SOURCE tranches are EXHAUSTED** —
every gap closeable without a live node is closed (§3i-§3z). The remaining **12 are ALL
CLUSTER**: light-client verdict logic needing a live node + the `rpc_tamper_proxy.py`
MITM (Windows-standalone, not in ci_local). Next is a live-node CLUSTER round (or two) —
a different harness class from every gate shipped so far; **#8 T-3-s001 stays DEFERRED**
(live auth control flow, needs review not a fixture).
