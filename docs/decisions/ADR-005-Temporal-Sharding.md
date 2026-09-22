> **TIER: FUTURE — proposed design only.** Roadmap index: [ROADMAP.md](../ROADMAP.md).

# ADR 005: Temporal Sharding — Design Gate

**Date:** 2026-09-22
**Status:** PROPOSED; implementation blocked on the consensus and settlement design.
**Owner constraint (2026-09-22):** One elected pair per shard, with a separately
proved timeout and replacement rule. Competing pairs are not the selected path.

**Decision authority:** [Decision Log](../proofs/DECISION-LOG.md).

## 1. Result of the corrected prompt

The original prompt's premise is refuted: sequential work within one computation
alone does not preserve a shard's security independently of its participant set,
resource allocation or data availability. A fixed exclusive pair can halt by
withholding. A colluding pair can know both inputs before the timer starts and
precompute. Independent candidates and shards can be evaluated concurrently even
if each individual evaluation were proved sequential. A Merkle path proves inclusion
under a supplied root, not the validity, availability or eventual canonicality of
that root's chain.

Consequently this gate does not adopt temporal sharding, deprecate beacons, remove
EXTENDED topology, change wire bytes or claim a production shard count. It records
the prerequisites and the smallest implementation boundary once those prerequisites
are resolved. The existing C++ topology continues to have its current behavior and
open findings, including the separately tracked receipt-authentication problem.
Data-availability sampling is a data-availability technique; it is not made obsolete
by replacing BFT voting with a delay evaluator. No particular coordination topology
is mandated or ruled out by this proposal.

## 2. Repository baseline

| Requested component | Actual source and limitation |
|---|---|
| `include/determ/wire/block.h` | Does not exist. C99 `wire_block_header_t` in `include/determ/wire/parser.h` has a 212-byte codec. `consensus_block_header_t` in `include/determ/consensus/dda.h` has a separate 120-byte codec. Neither is production C99 block admission. They disagree on work width (u32 versus u64); choose one canonical format before extension. |
| `src/crypto/vrf.c`, `vrf_elect_nodes()` | Do not exist. No C99 authenticated validator registry, frozen eligibility snapshot, seed rule or verifiable election is integrated. Hashing public seed bytes is deterministic sampling, not by itself a VRF protocol. |
| `src/ledger/mempool.c` | Does not exist. C99 state is in `src/ledger/state.c`; the C++ mempool and chain are separate. Neither an arena allocation nor a transaction shard field establishes state isolation. |
| Transaction shard identity | Existing C99 binary transaction/container codecs already use u32 shard identifiers in `include/determ/wire/binary_codec.h`. The prototype parser has another transaction shape. Define the authoritative format and signing coverage; do not append a conflicting u16 field blindly. |
| PoSW fork choice | C99 `determ-node` performs a local pair computation only. Validated block ingestion, work accumulation, branch adoption and durable rollback are missing. Raw work-comparison helpers were removed because they did not implement these rules. |
| Existing sharding | C++ beacon, shard and receipt paths exist, as does canonical account-to-shard modulus routing in `src/crypto/random.cpp`. A text search cannot establish that their structs or discriminators are unused. No deletion is authorized by this proposal. |

The [C99 contract](../proofs/K2_VDF_Soundness.md) and
[ADR-004](ADR-004-Fault-Model.md) define the current limitations. Tests for isolated
arithmetic or a successful socket exchange cannot close these architectural gaps.

## 3. Required design decisions and proof obligations

### 3.1 Producer and fault model

Specify authenticated membership and admission cost; eligible stake/identity snapshot;
network synchrony assumptions; adversarial identities, hardware and concurrent work;
and the producer rule for each shard. The owner selected an **exclusive elected
pair**, with timeout/replacement proved separately. Specify authenticated replacement,
what prevents conflicting replacement authority, and the assumptions under which a
withholding pair is eventually replaced. A local timeout supplies none of these rules.
Multiple competing pairs are not authorized by this choice.

**Replacement gate — refutation of a local-counter implementation.** Let the
membership/seed select pair P0 for attempt 0 and P1 for attempt 1. An honest node A
receives nothing from P0 and locally times out; node B's clock/receipt schedule is
behind and it receives P0's result before its own timeout. If A treats P1 as the
exclusive authority while B still accepts P0, a counter alone has not established
common exclusive production rights. More directly, if verifiers trust a submitted
attempt number without replacement evidence, an adversary can skip to any attempt
whose derived pair it controls. If they require equality to their own local counter,
the same candidate's admission depends on delivery schedule. Neither rule proves a
canonical replacement sequence.

This trace does not assert that temporary forks are forbidden under ADR-004; it
shows that pair exclusivity, admissible work and recovery remain undefined even
before a probabilistic fork-choice proof can start. A replacement specification must
choose an objectively verifiable authority transition and state its assumptions:
for example, a precisely defined timeout certificate with its own participation and
fault threshold, or a clock/slot rule with bounded skew, validity and offline-verification
semantics, or a delay certificate whose freshness and hardness are actually proved.
These are alternatives for review, not implemented or accepted mechanisms. A claimed
VDF output from the current custom evaluator cannot stand in for that proof.

The local driver's failed attempt followed by caller-controlled retry is deliberately
outside this consensus rule: its explicit restart elects nobody and confers no signing rights.

For the selected exclusive-pair design, define challenge freshness and context binding to protocol version,
chain identity, shard, parent commitment, height, epoch/attempt and membership snapshot.
An unauthenticated header hash or a signature-malleable block hash is not an acceptable
randomness source. Specify the delay construction and its actual proof/hardware
assumptions. Treat producer-supplied timestamps as adversarial inputs. State precisely
what timestamp rules every verifier enforces and what difficulty adjustment proves.

### 3.2 Election and finite resource limits

Specify a verified VRF construction if private-key verifiable sortition is required;
otherwise name the mechanism deterministic sampling. Define seed provenance and
withholding/grinding behavior, domain separation, canonical input encoding, distinct
roles, tie handling, eligibility, retries and verification at the receiving node.

Decide whether participants may serve multiple shards. Disjoint pairs need at least
2S eligible participants for S shards, plus a spare/replacement policy. Overlapping
pairs need an explicit concurrency and resource bound. Two roles per shard do not
establish O(1) total network overhead: validation, dissemination, availability and
cross-shard traffic must also be counted.

If u16 IDs are selected, they represent values 0..65535; a shard **count** that can
reach 65536 requires u32 or a comparably explicit larger type. Count zero is invalid;
a reserved coordinator value reduces the usable ID set. The production limit must
be derived from bounded memory and membership, not field width. Use explicit BE
encoding/decoding with exact-length and overflow checks; native struct packing is
not a wire-format definition. Any pre-genesis format decision updates every decoder,
signer, hash, golden vector and persistence reader together. Post-genesis frozen
formats cannot be silently migrated.

### 3.3 State ownership and settlement

The owner clarifies that shard assignment uses modulus. Account routing already
has a canonical definition in [PROTOCOL §7.2](../PROTOCOL.md#72-address-to-shard-routing)
and `src/crypto/random.cpp::shard_id_for_address`:

```
shard_id(addr) = BE64(SHA256(salt || "shard-route" || addr)[0:8]) mod S
```

For a valid fixed topology, S >= 1; S = 1 routes every address to shard 0. The
existing definition pins salt and S at genesis. See
[ShardRoutingSoundness.md](../proofs/ShardRoutingSoundness.md) for the mapping's
contract and scope. This mapping is the account-routing baseline, not a new owner
decision still to be made. It does not itself select the two block co-creators.

The C99 path still needs to integrate that mapping with its canonical account
representation and enforce ownership at transaction admission and state application,
including account nonces and the effects of transactions involving other shards.
A client-requested target shard must match derived ownership. Splitting queues into
arenas alone does not enforce these checks.
Specify hard limits, admission/backpressure, per-shard arena ownership and reclamation,
execution scheduling and all shared-state access. Fixed capacity and no malloc do not
by themselves make the execution path lock-free or race-free.

For transactions affecting multiple shards, define and verify chain/shard identity,
canonical signed transaction bytes, inclusion, block validity, parent linkage and the
history-selection rule. The owner specifies transactions; no separate credit, receipt
approval or sender-voting mechanism is adopted here. A Merkle inclusion path alone
does not establish the validity or selected-history status of its containing block.

Prove conservation and replay protection across retries, crashes and local history
correction. If a transaction on shard B is valid only because of an earlier transaction
on shard A, learning and applying a correction of A's history must cause B to
revalidate the dependent transaction and any further dependencies. Specify how these
corrections are applied consistently and recovered after crashes; local acceptance
is recoverable under §3.4.

Specify how receiving validators obtain enough data to validate transitions and
reject unavailable histories. Header work alone is insufficient. Dynamic resharding,
state migration and topology removal are outside a first fixed-topology increment.

### 3.4 Owner clarification: temporary forks and local recovery

The following are intended design requirements from the continuing 2026-09-22
discussion, not shipped C99 consensus behavior or a completed convergence proof:

- Exactly two elected co-creators produce a block and supply the fresh ephemeral
  cryptographic contributions. Message senders submit signed transactions and verify
  blocks locally; they supply no MP-DH shares and perform no consensus commit/reveal.
  This supersedes the earlier proposal for interactive sender participation.
- The owner adopts a public-verification requirement for the DH-derived result.
  A block must carry cryptographic evidence sufficient for an ordinary receiving
  node to verify derivation from the two co-creators' committed ephemeral
  contributions, binding the canonical ordered-body hash, chain/shard identity,
  parent, height and round. The receiver must also verify that the VDF uses that
  verified input. Creator signatures authenticate endorsement; they do not alone
  prove this derivation. A body hash supplies binding, not independent secret entropy.
  The exact proof relation, commitment scheme, publication sequence, canonical
  encoding and verifier remain to be designed and reviewed. This requirement does
  not select an off-the-shelf proof suite, require disclosure of private keys or
  establish resistance to candidate grinding. No such verifier has shipped.
- Only messages received by both co-creators are eligible for inclusion. This is a
  shared-receipt condition; it does not silently require every eligible message to
  fit in a block or define the complete canonical selection/ordering algorithm.
- For competing blocks at the same height, the stated preference is more distinct
  valid included ledger messages, then the smaller header value. For conflicting
  messages, the preserved message has the smaller data hash. The owner also selects
  the smaller produced successor header to resolve conflicting successor candidates.
  Define precisely how these rules compose with ADR-004's intended validated-work
  ordering, transaction dependencies and comparison of complete histories before
  implementing the comparator. A header value is not interchangeable with its hash.
- The owner explicitly adopts the same-body case: among valid competing blocks at
  the same height with an identical message body, prefer the smaller header interpreted
  as a number. A node that received only the larger-header candidate may temporarily
  follow it; later receipt of the preferred candidate triggers local history correction
  and revalidation of affected descendants. This tie-break is decided. Its canonical
  header representation and the recovery transitions still need implementation and
  verification; no additional tie-break is required for this case.
- Senders attach their known-history hash to messages so differing views can be
  discovered and reconciled through gossip coordinated by co-creators. A difference
  may indicate lag as well as competing histories; retrieve and validate the relevant
  histories. Recovery must remain possible after the original faulty creators stop
  cooperating.
- Senders "finalize for themselves": they verify and accept locally. There is no
  requirement to collect approvals from all previous-block senders, no sender quorum,
  and no collective finalization/approval barrier waiting for those senders. Sender
  shares or reveals are not a block-production dependency. Incomplete cooperation
  by the co-creators still requires the separately specified attempt/recovery rules.
  No unanimity safety proof follows from local verification.
- Temporary forks and correction of divergent local histories are intentional.
  Local acceptance is not an irreversible network-wide finality certificate. The
  property to establish is convergence under explicit delivery/fault assumptions and
  correct state recovery. Identical malformed or conflicting behavior has the same
  treatment whether caused by hardware, network faults or intentional actions.
- Omitted transactions are resent to later co-creators and checked against the
  selected state. A stale/conflicting transaction does not gain validity by being
  resent or by having a smaller hash; an already consumed nonce or unavailable funds
  must still fail the applicable transaction checks. A late submission alone does
  not authorize rewriting an earlier accepted decision; correction follows the
  separately verified competing-history rule.
- The intended configurable block time B has a total attempt timeout of 3B, measured
  from the round start. This is the owner's 1:3 design choice, not a change to the
  shipped prototype's 1000/2000 ms local-attempt deadlines. The shared round-start
  and eligibility rules still need specification. The VDF's agreed election role
  delays knowledge of the next pair; early knowledge alone does not authorize that
  pair to produce early or supply an independent "replacement proof".

### 3.5 DSF convergence and recovery design gate

The owner selects deterministic simulation to test this recovery model. Extend the
existing DSF approach in a separate, explicitly scoped increment. Current capabilities
must not be confused with coverage of the proposed protocol:

- The standalone `determ-dsf` runner uses scripted model nodes under `sim/`.
- The [C++ deterministic scheduler](../proofs/DeterministicSchedulerDesign.md) drives
  the existing C++ Node with loss, duplication, partition/heal, delayed delivery and
  crash/rejoin. Its `FaStepMonitor` asserts immutability below the head and height
  monotonicity for that older engine. Preserve those existing checks; do not present
  them as verification of this different recovery model.
- The [C99 DSF seams](../proofs/DSF-SPEC.md#10-separate-c99-local-attempt-test-harness)
  and `tests/test_dsf_k2_duel.c` currently exercise bounded local attempts. They have
  no distributed block admission, branch selection or ledger recovery to drive.

**First increment: one-chain model.** Specify the candidate-admission, whole-history
comparison and recovery transitions before writing their scenario. Fix a finite set
of eligible candidate data for this first experiment and state the delivery and
availability assumptions. Include two conflicting candidates from the same elected
pair, different local receipt schedules, shared versus one-sided message receipt,
the stated message/header selection cases, and a transaction whose validity depends
on the initially selected history. Witness a temporary split and a local correction.
Include the adopted same-height, identical-body case with different header values:
deliver the larger-header candidate first to one node, then the preferred candidate,
and verify selection and correction of any affected descendants. Every candidate
and descendant used by the scenario must satisfy the model's admission and producer
eligibility rules; do not assume an isolated branch may advance without checking them.
Then heal the partition, deliver/retransmit the missing eligible data and drive
recovery to a specified quiescent observation point. The harness controls delivery;
it must not tell nodes which history wins or copy one node's state into another.

Check all of the following:

1. After healing and delivery/recovery under the scenario's stated assumptions,
   proper nodes select the same complete history **and** ledger state, including
   balances and nonces. Temporary differing local histories are allowed before that
   point. Disagreement at a recovery bound justified by the model falsifies that
   bound; reaching an arbitrary simulation step/time cap alone is inconclusive about
   eventual convergence.
2. At every externally visible state boundary, a node's state equals independent
   replay of its own selected, validated history from the common anchor. No mixed
   ancestry, effects from an abandoned history, duplicate application or invalid
   dependent transaction may survive correction. Recovery publishes a consistent
   state, including after a crash/restart during correction.
3. Omitted transactions are requeued without duplication and admitted only if valid
   against the selected state. Losing same-nonce transactions must not be counted as
   successful retries. Check conservation against that history's explicit monetary
   rules, without assuming a subsidy or receipt mechanism from another engine.
4. Record witnesses that the split, relevant injected faults, correction and healing
   actually occurred. Replaying the same scenario/seeds produces the same trace.
5. After a successful fresh build, mutants breaking selection, rollback/replay,
   dependency revalidation or duplicate rejection must fail the corresponding
   receiver/apply check. The state oracle must not simply call the same recovery
   routine being checked.

**Next increment: cross-shard dependencies.** Apply the reviewed one-chain recovery
model to a transaction dependency crossing two shards, then to a dependent onward
transaction. Check the same conservation, revalidation, replay and crash properties
against each node's coherent selected dependency history at its local publication
boundaries; compare proper nodes after the relevant histories and corrections have
been delivered and processed under the stated recovery assumptions. Incompatible
provisional views on opposite sides of a partition are not one globally selected
state to sum or compare. Full block propagation may supply recovery data; it does
not substitute for executing those state transitions.

Finite schedules and a frozen candidate set can falsify a design and reproduce a
defect. Passing them does not prove convergence under indefinitely produced competing
histories or establish a confirmation depth. Independent design/adversarial review
and stated fault/network assumptions remain required. Model results are labeled as
model results; production claims require driving the actual surviving verifier and
apply path. Run all gates through `tools/ci_local.sh`; no new recovery gate or
production behavior is claimed by this documentation increment.

## 4. Corrected execution instructions

1. Inspect the current source, decision log and test entry points. Refute inconsistent
   premises before changing consensus. Record missing rules as design blockers.
2. Complete and independently review the production single-shard accept/reorganization
   model before using it as the security premise of parallel execution.
3. Resolve the exclusive-pair replacement and settlement rules in §3 and write a model with
   explicit safety, liveness and resource claims, assumptions and counterexample traces.
   Review that model independently before implementation. If refuted, stop dependent
   code and preserve the result; do not mark the ADR accepted.
4. Once the gate passes, implement the smallest behavior-changing fixed-topology
   increment using actual source paths and explicit canonical codecs. No placeholder
   VRF, cosmetic shard field, blanket beacon deletion or automatic reserved-tag DROP.
5. Add negative and falsify-on-mutant gates where receivers admit blocks, election
   proofs, transactions and receipts. Cover withheld participants/data, forged work,
   context replay, invalid shard/count bounds, competing histories, double credit,
   crash recovery, queue capacity and canonical malformed-byte rejection. Positive
   controls must demonstrate the intended accepted behavior.
6. Build and test through `tools/ci_local.sh`, independently review the complete diff,
   converge existing authoritative docs, and append the decision log. Only then commit
   the explicit reviewed files; never stage all `include/ src/ docs/` indiscriminately.

## 5. Acceptance boundary

For this design gate, success is a source-grounded proposal or precise refutation,
not a fabricated implementation. The counterexamples in §1 and §3 block the original
acceptance criteria. Production sharding is accepted only after the dependencies and
receiver-side gates above are satisfied. A green C99 prototype gate cannot change
that disposition.
