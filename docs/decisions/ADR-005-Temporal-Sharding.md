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
| Existing sharding | C++ beacon, shard and receipt paths exist. A text search cannot establish that their structs or discriminators are unused. No deletion is authorized by this proposal. |

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

Define canonical ownership for accounts, contracts, nonces and spent receipts.
A client-requested target shard must match derived ownership. Splitting queues into
arenas does not prevent two shards from concurrently spending the same account.
Specify hard limits, admission/backpressure, per-shard arena ownership and reclamation,
execution scheduling and all shared-state access. Fixed capacity and no malloc do not
by themselves make the execution path lock-free or race-free.

Before a cross-shard receipt credits anything, define and verify source-chain identity,
source/destination shard, canonical transaction/receipt bytes, inclusion, source block
validity, parent linkage, authenticated cumulative work, and the finality policy.
Persist replay protection and import state atomically. Prove conservation across
export/import, retries, crashes and source/destination reorganizations. For example:
source A exports funds; B credits a receipt; A reorganizes away the export; the funds
are spent again on A. A Merkle proof of the old export does not prevent this trace.
Choose an explicit rollback/finality/escrow design and prove its failure bounds.

Specify how receiving validators obtain enough data to validate transitions and
reject unavailable histories. Header work alone is insufficient. Dynamic resharding,
state migration and topology removal are outside a first fixed-topology increment.

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
