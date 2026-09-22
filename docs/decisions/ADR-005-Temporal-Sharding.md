> **TIER: FUTURE — proposed design only.** Roadmap index: [ROADMAP.md](../ROADMAP.md).

# ADR 005: Temporal Sharding — Design Gate

**Date:** 2026-09-22
**Status:** PROPOSED; bounded model and routing-query increments implemented; production consensus and settlement incomplete.
**Owner constraint (2026-09-22):** One elected pair per shard, with a separately
proved timeout and replacement rule. Competing pairs are not the selected path.
Each shard is provisioned with a large eligible population; initial and subsequent
pairs are selected only from that shard's eligible participants.

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
pair**. Available prior state determines the next pair under the shard-local
eligibility rule. The VDF delays knowledge of that pair; it does not authorize
production or serve as an independent replacement proof. Define the production
state machine, shared round start, attempt timing and receiver checks that determine
when each state-derived pair may act, and the recovery transitions after incomplete
cooperation. Multiple concurrently authorized pairs are not the selected path.

**Local-counter limitation.** Let the prior state determine pair P0 for attempt 0
and P1 for attempt 1. Node A receives nothing from P0 and locally times out; node B
receives P0's result before its own timeout. Merely incrementing A's local counter
does not specify how both receivers validate late results, determine the relevant
prior state or reconcile their histories. Trusting an arbitrary submitted attempt
number also fails to establish that the named pair may act; requiring equality to
a receiver's local counter makes admission depend on its delivery schedule. This is
a missing state-transition and recovery specification, not a requirement to invent
a timeout certificate or give a VDF output production authority.

Temporary forks are permitted by §3.4. The task is to define which candidates remain
valid on their actual prior states and how local histories recover, under explicit
timing and delivery assumptions. Public DH/VDF verification, the production
state machine and its receiving checks remain to be implemented and reviewed. The
bounded fixture model in §3.5 does not discharge those requirements.

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

**Owner decision: large populations and shard-local eligibility.** Each shard is
provisioned with a large population of eligible participants. Exactly two distinct
co-creators are elected from that shard's own eligible pool, and subsequent attempts
use the same shard-local boundary. No network-wide producer fallback is adopted.
The existing K=2 requirement means an attempt cannot produce a valid block without
two eligible local participants completing their required cooperation.

"Large" is a qualitative requirement; a numerical minimum and reserve margin have
not been selected. Specify those provisioning limits and the availability/fault
assumptions before claiming progress. A global participant count does not establish
the population of each individual shard. This decision does not authorize automatic
resharding or define the outstanding timeout/replacement transitions. Two roles per
shard do not establish O(1) total network overhead: validation, dissemination,
availability and cross-shard traffic must also be counted.

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

The C99 mirror in `src/ledger/shard_routing.c` now maps an exact 32-byte public key
through the canonical anonymous address `"0x" + lowercase_hex(pubkey)` and the
existing modulus formula. The read-only `get_shard_for_pubkey` RPC uses local
`--routing-shards` / `--routing-salt` settings and labels its response
`config_source: "local"`, `consensus_enforced: false`. It does not authenticate a
genesis configuration, assign producers, admit transactions or execute a shard.

The C99 path still needs ownership enforcement at transaction admission and state
application, including account nonces and the effects of transactions involving
other shards.
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
  implementing the production history comparator. A header value is not interchangeable
  with its hash.
- The owner explicitly adopts the same-body case: among valid competing blocks at
  the same height with an identical message body, prefer the smaller header interpreted
  as a number. A node that received only the larger-header candidate may temporarily
  follow it; later receipt of the preferred candidate triggers local history correction
  and revalidation of affected descendants. This tie-break is decided. Its canonical
  production header representation and recovery transitions still need implementation
  and verification. The bounded model below exercises this case with a model-only
  header; no additional tie-break is required for this case.
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

The owner selects deterministic simulation to test recovery. The first bounded
one-chain increment is now implemented in `sim/k2_recovery_model.c` and
`tests/test_dsf_k2_recovery.c`; its exact contract and conditional finite-convergence
argument are in [DSF-SPEC §10.4](../proofs/DSF-SPEC.md#104-bounded-c99-fork-recovery-model).
This is a partial design gate, not a production implementation of this ADR.

The surfaces remain separate. The standalone `determ-dsf` runner uses scripted
model nodes. The [C++ deterministic scheduler](../proofs/DeterministicSchedulerDesign.md)
drives the existing C++ Node and retains its existing settled-history monitor.
The [C99 local-attempt seams](../proofs/DSF-SPEC.md#10-separate-c99-local-attempt-test-harness)
and `test-dsf-k2-duel` still exercise local attempts. The new recovery target drives
a bounded model receiver/replayer with the real C99 sender-signature and ledger-apply
functions; it does not drive `determ-node` block admission.

**Implemented domain.** One common anchor, at most eight candidate records, four
transactions per candidate and four selected blocks; immutable fixtures supply
pair authority and joint receipt facts. Each candidate is validated on its original
parent history. Valid root siblings rank by distinct included message count, then
fixed-width big-endian model-header value. Losing descendants retain their original
parents; replay never transplants them onto a preferred root. Each nonanchor parent
has at most one valid child in the supported domain.

Differing root transactions with the same sender and nonce, and competing valid
children of a nonanchor parent, return `UNSUPPORTED` without publishing partial
state. Opposite delivery orders may remain different outside that domain. This
restriction avoids deciding the still-open composition of conflicting-message,
header and complete-history preferences; it is not a new protocol rule. Frozen
pair/receipt fixtures do not prove production eligibility, public DH derivation,
VDF verification or that the modeled competing histories are reachable.

**Implemented checks.** Fixed scenarios witness a temporary split and later
correction, greater-message-count preference, identical-body lower-header preference,
original-parent descendant detachment, dependent-spend rejection, one-sided receipts,
invalid signatures/bodies, bounded capacity and atomic failure. The independent
arithmetic oracle checks selected-history ancestry, balances, nonces and conservation;
nodes never copy another node's state. Omitted transactions are deduplicated and
individually revalidated against selected state; smaller data hash resolves ready
same-sender/nonce alternatives. A ready queue is not a promise that all entries form
a valid batch. Eight seeded delivery permutations are each replayed twice to compare
traces. Canonical journal bytes test old/new in-memory crash cuts and independent
state reconstruction, not filesystem durability.

For a common finite candidate set within the supported bounds, eventual delivery of
all required ancestors gives every node the same original-parent validity results,
the same deterministically preferred root and the same unique descendant suffix.
Deterministic replay then produces the same selected ledger state. This conditional
argument does not extend to indefinitely growing histories, arbitrary faults,
production confirmation depth or unavailable data. Gates and mutants exercise the
model receiver/apply rules; their execution is recorded separately after a successful
fresh build through `tools/ci_local.sh` and independent review.

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
apply path. Run all gates through `tools/ci_local.sh`. The bounded recovery gate
above is implemented; production recovery and cross-shard behavior remain open.

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
