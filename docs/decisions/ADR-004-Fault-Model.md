> **TIER: FUTURE — accepted research direction, not implemented.** Nothing in this ADR is shipped consensus; the C++ K-of-K rules remain the implemented protocol. Roadmap index: [ROADMAP.md](../ROADMAP.md)

# ADR 004: Fault Model Correction (Proof of Sequential Work)
**Date:** 2026-09-22 (tier marker and design-note references added 2026-09-23)
**Status:** Research direction accepted by the owner; not implemented, production protocol and security proof incomplete. (The owner's separate goal, restated 2026-09-23, is the C99 migration — docs/C99-MINIX-PORT.md §0.)

## 1. Equivocation and finality

The K=2 experiment does not establish instant, fork-free finality. A participant
can produce conflicting candidates, and a deterministic computation for each
candidate does not make the candidates unique. PoSW with validated cumulative-work
fork choice is the intended research direction. The current C99 driver has no
production block admission, chain adoption or reorganization path. Unused helpers
that compared caller-supplied work totals have been removed; they were not an
implementation of secure fork choice.

## 2. Precomputation and grinding

Colluding participants know their payloads before the commit window and can
precompute candidates. The former economic argument assumed competing honest
pairs with sufficient chain growth without specifying who those pairs are or
bounding adversarial work. That conclusion is withdrawn. A sequential dependency
within one evaluation does not prevent parallel evaluation of independent
candidates, private histories or independent shards.

A production design needs a membership/Sybil model, eligible producer and recovery
rules, a canonical fresh challenge, a specified delay construction and hardness
assumption, timestamp validity, validated work accounting, data availability and
atomic reorganization semantics. Honest/adversarial growth bounds and a finality
policy must be derived from those rules. No confirmation depth is selected here.

## 3. Current implementation contract

C99 `determ-node` is a bounded local two-party experiment. Two commitments and two
matching reveals are required; a missing party fails the attempt. An explicit
retry is not an election or a guarantee of eventual success. Evaluation output is
not a finalized ledger block. See [K2_VDF_Soundness.md](../proofs/K2_VDF_Soundness.md)
for the exact contract, tests and limits.

## 4. Supersession and sharding

The previous C99 claims of fork-free finality, absolute liveness, 1-of-2 fallback,
zero bias and hardware-independent enforced blindness are withdrawn. This ADR
does not replace the existing C++ accept rules or validate their separate claims.
[ADR-005](ADR-005-Temporal-Sharding.md) records the proposed sharding design gate;
beacon deprecation and sharding security do not follow from choosing PoSW.

## 5. Design notes (not proofs)

[PoSW_Nakamoto_Safety.md](../proofs/PoSW_Nakamoto_Safety.md),
[PoSW_Economic_Soundness.md](../proofs/PoSW_Economic_Soundness.md),
[VRF_Sharding_Safety.md](../proofs/VRF_Sharding_Safety.md) and
[tla/PoSWForkChoiceDesign.tla](../proofs/tla/PoSWForkChoiceDesign.tla) sketch parts of this
direction. Each is a future-tier design note whose review-status section lists the
unproven steps and the mechanisms missing from the code; none discharges an obligation
of §2.

## 6. Preserved K=2 design for comparison (2026-09-24)

**Status: agreed requirements preserved; production design and proof incomplete.**
The owner requested a saved design so other agents can compare it with K-of-K.
The current evidence does not establish that K=2 has no holes. This section is the
comparison entry point for the owner's recorded requirements, not a new security
theorem or authorization to replace the shipped protocol. The detailed requirements
remain in [ADR-005 §3](ADR-005-Temporal-Sharding.md#3-required-design-decisions-and-proof-obligations);
the [2026-09-23 Decision Log entry](../proofs/DECISION-LOG.md) controls implementation
and proof status.

**Terminology.** K=2 names a participant count. Requiring both participants is
itself a 2-of-2 cooperation rule. The comparison here is between the existing C++
K-of-K committee protocol and the proposed pair-production/PoSW/recovery protocol;
changing K to 2 alone does not supply the latter's election or history rules.

### 6.1 Recorded owner requirements

| Subject | Preserved requirement |
|---|---|
| Co-creators | Exactly one elected Aggregator/Contributor pair per shard attempt, with two distinct eligible members from that shard's large local population. No competing normal pairs or global-pool fallback. Incomplete cooperation produces no completed valid candidate; no missing share is fabricated. |
| Membership | Decided 2026-09-24 (H1). Eligibility requires locked stake above a floor, and pair draws and witness quorums are weighted by stake, so f is a share of stake. The protocol assigns a new member to a shard using randomness revealed after its admission; a member cannot choose its shard. Every member of a shard's eligible population may sign failure statements, and H3's quorum is two thirds of the shard's stake. The network-wide faulty share is assumed below 1/3 by a stated margin, and each shard's minimum population is derived so that random assignment keeps every shard below 1/3 except with a stated probability (for equal stakes, a 1/4 network-wide share and about 1,000 members per shard give about 2⁻²⁹ per shard); unequal stakes shrink the effective population, so the derivation uses the stake distribution. Still to set: the eligibility snapshot rule and the stake floor (the margin and probability target lapsed with the revision that follows). Revised 2026-09-24 after review: each shard's faulty stake is assumed below 1/3 at all times, as an explicit assumption applied equally to K-of-K's pools; random assignment stays as defence in depth, and the derivation of a per-shard minimum from a network-wide margin is withdrawn, because adaptive corruption and exit-and-rejoin defeat it. |
| Subsequent pair | Derive it from the last agreed state and contributions already available there, without waiting for fresh shares from the stalled pair. The VDF delays knowledge of the pair; its output neither grants production rights nor serves as an independent replacement proof. Decided 2026-09-24 (H6): on the fastest admitted adversary hardware (speed-up α) the delay outlasts a pair's choosing window of 3B, so no pair can evaluate candidate contributions or bodies before its deadline; the pair for a height is derived from a VDF output over the DH result d > 3α heights earlier, recorded on chain with its proof before it is needed. The VDF is a class-group construction with short Wesolowski-style proofs and no trusted setup; its iteration count is fixed at genesis with a margin for hardware gains over the chain's life. Decided 2026-09-24 (H8): the delay also outlasts k stalled attempts at the next height, so that a withheld sibling cannot be released with its outcome known unless colluders stall k attempts in a row (revised 2026-09-24 after review: k covers the stalls that colluder-containing pairs and flooding, b per T, can jointly produce while the delay runs; clarified after the third review: k counts every colluder-containing or flooded attempt after the fork, whether it stalls or completes on both branches). Decided 2026-09-24 (H2): seed = hash(domain tag, chain, shard, height, attempt, VDF output); two distinct members are drawn by stake without replacement from the eligibility snapshot, the first as Aggregator and the second as Contributor; this is deterministic sampling, not a VRF. The VDF output over block h's DH result, which selects the pairs for height h+d, must be in block h+d−1 with its proof, and that block is invalid without them; anyone may compute and gossip them. Corrected 2026-09-24 (review): the eligibility snapshot that selects pairs for height h+d is fixed by state no later than height h−1, before block h's DH result is revealed, so admissions, exits and suspensions affect draws only through later snapshots. |
| Replacement | Decided 2026-09-24 (H3). After attempt a's deadline, a member of the shard's eligible population that has not received a completed attempt-a result signs a canonical failure statement for (chain, shard, height, a). Statements from at least two thirds of the population form a failure certificate, which authorizes attempt a+1's pair; a block of attempt a+1 carries the certificates for every earlier attempt at its height. The certificate authorizes and is not an input to the next pair's derivation. The owner authorizes this quorum, which the 2026-09-22 entry had not. H4 sets the deadline; H1 weights and sizes the quorum. Decided 2026-09-24 (H7): co-creators broadcast their commitments, reveals and signatures to the shard; each failure statement also names the member whose messages the witness did not receive by the deadline, and when two thirds of the shard's stake name the same member it is suspended for a window, with no stake deduction. A crashed member is treated the same way. Revised 2026-09-24 after review (H7): silence is not penalized beyond the lost reward (H20), and failure statements no longer name members, because a flooded honest member cannot be told apart from a withholder; only H13's equivocation evidence suspends a member. Decided 2026-09-24 (H13): two valid header signatures by one member over different header contents for the same (chain, shard, height, attempt, parent) are equivocation evidence; it goes on chain, capped and deduplicated per block, and every member whose two signatures it carries is suspended for a window, with no stake deduction. Members record the set of (height, attempt, parent) keys they have signed above the latest finalized checkpoint durably before signing (predicate corrected 2026-09-24 after review: failure statements and a legitimate re-signature on another parent are not equivocation). Decided 2026-09-24 (H12): failure statements also name the parent block, so a certificate cannot be reused on another branch. |
| Timing | Configurable block time B; total attempt timeout 3B from the round start. VDF parameters must account for their intended timing use. This is a design requirement, not proof of a hardware-independent duration or the prototype's 1000/2000 ms settings. Decided 2026-09-24 (H4): attempt 0 starts when a node has received and validated the parent (which carries the VDF output the attempt needs, H2), and attempt a+1 when it has received attempt a's failure certificate; each deadline is 3B later. A node's clock decides only when it signs a failure statement, never whether a block is valid. A block's timestamp must exceed its parent's, and nothing in consensus reads it: no deadline, difficulty or randomness depends on it. |
| Cryptographic contributions | The two co-creators supply ephemeral contributions, with registered identity keys and canonical body/context binding. Ordinary receivers must verify the DH-derived result and its use as the VDF input. An ordered-body hash binds transactions; signatures alone do not prove DH derivation. The concrete proof relation and publication sequence remain open. Decided 2026-09-24 (H5): each co-creator commits, before either reveals, to its ephemeral public share and to the hash of the transactions it received; each then reveals its ephemeral scalar, and any receiver recomputes the DH result from the two scalars and checks both commitments. The eligible body, the intersection of the two committed lists, is thereby fixed before either reveal. The canonical bytes, context binding, point and scalar checks and the body rule (H14) remain to be specified. |
| Senders and body eligibility | Senders submit signed transactions and verify locally; no sender MP-DH shares, commit/reveal, quorum or approval barrier. Only transactions received by both co-creators are eligible for inclusion. Canonical production assembly still needs specification. Decided 2026-09-24 (H14): the body is a function of the two committed received-lists and the parent state: transactions invalid on the parent are dropped, same-sender/nonce conflicts resolve by the smaller data hash, and the rest is ordered canonically and filled to the block cap. The censorship guarantee is the joint-receipt bound: a transaction that every faulty member omits is included by the first fully honest pair, about 1/(1 − f)² heights on average for an unbiased draw. |
| Candidate ranking | Validate each candidate on its original parent history. At the same height prefer more distinct valid included transactions, then the smaller full header interpreted numerically. This includes identical bodies and valid conflicting sender/nonce transactions. The smaller-successor-header requirement is also retained; complete-history/work composition remains open. Decided 2026-09-24 (H3): a candidate carrying failure certificates that cover another candidate's attempt outranks it; this criterion comes before the count. Decided 2026-09-24 (H8): the longer valid history wins, and the same-height rules (the certificate criterion, then count, then header) decide only between histories of equal length; with a fixed delay per block, the most validated work is the longest valid history. Decided 2026-09-24 (H9): a block's header, for ranking and for its child's parent commitment, is the content its pair signs; pair signatures and witness signature sets travel outside it, and a certificate is referenced by the height and attempt it certifies. The smaller full header is the smaller signed header content, read as a big-endian number. One new canonical big-endian fixed-width header replaces both prototype formats; it has no work field, since work equals height. Decided 2026-09-24 (H10): histories of equal length are compared at their first differing height by the same-height rules; a longer valid history wins however far back it diverges, and settlement is a confirmation depth (H12). Revised 2026-09-24 after review: correction never crosses the latest finalized checkpoint (H12). Revised 2026-09-24 after review (H3): where two histories diverge at height h, a block there carrying failure certificates, bound to their common parent, that cover the other block's attempt wins regardless of length; otherwise the longer valid history wins, and equal lengths are compared at the fork point by count and then header. Revised again 2026-09-24 after the second review, superseding certificate-first: above the fork-choice root (the highest justified checkpoint), the longer valid history wins, and at equal length the fork-point blocks are compared by the certificate criterion, then count, then header. |
| Settlement | Decided 2026-09-24 (H12). A block is settled once z blocks extend it. z is set so that a reversal anywhere in the chain's life has probability at most 2⁻⁴⁰ against an adversary that waits for a run of fully colluding pairs, which it can foresee because pairs are known d heights ahead: z = 20 as f approaches 1/3 and 15 at f = 1/4, for 10⁸ heights. d must be at least z + 2 (superseded below). Light clients apply the same z (superseded: H19). Revised 2026-09-24 after review (finality checkpoints): every E heights, members holding at least two thirds of the shard's stake vote a checkpoint final in the style of Casper FFG, with votes linking a finalized source checkpoint to a target, so that two conflicting finalized checkpoints imply that a third of the stake broke a voting rule and left evidence. A finalized checkpoint is never reverted, and fork choice (H8, H10) runs only above the latest one. Corrected 2026-09-24 after the second review, to match Casper FFG: a vote links a justified source checkpoint to a target; a link with two thirds of the stake justifies its target; a justified checkpoint with such a link to its direct child is finalized; double votes and surround votes are recorded as evidence; fork choice is rooted at the highest justified checkpoint the node has seen; each link's voter set is a named eligibility snapshot, and an exit takes effect only after unbonding. A payment is settled when a finalized checkpoint covers its block, which supersedes the depth-z rule above. A new node, or one offline longer than the unbonding period, starts from a recent finalized checkpoint obtained from a source it trusts (weak subjectivity). |
| Availability | Decided 2026-09-24 (H16). For a node, a block counts toward history length, and can be extended or witnessed, only once the node holds its full body; honest nodes relay every body they hold, but at most two per (height, attempt, parent), the second as equivocation evidence. Every node keeps full bodies for at least z + d heights (corrected after the second review: back to the latest finalized checkpoint plus d heights) and periodic state snapshots; archive nodes keep all history, and a deeper correction fetches history from them. |
| Transactions | Decided 2026-09-24 (H15). The K=2 design carries transfers, intra-shard and cross-shard (H18), and the membership transactions H1 needs (admission with stake, unstake, exit); the other K-of-K types are stated differences in the comparison. The signing preimage starts with a domain tag, the genesis hash and the shard id, and every variable-length field is length-prefixed, so the encoding is injective. |
| Verification | Decided 2026-09-24 (H19). Each epoch's header commits a stake-sum Merkle root of the eligibility snapshot, so a light client checks each pair's stake-weighted draw with O(log N) proofs, the pair signatures and the VDF proof per block, and certificates on stalls, and treats a block as settled at depth z; shards verify each other the same way (H18). Corrected 2026-09-24 after the second review: settled means finalized (H12), so a light client or destination shard also verifies checkpoint votes holding two thirds of the source shard's stake, and the changes of the voter set between checkpoints. Failure certificates are plain lists of Ed25519 signatures. |
| Incentives | Decided 2026-09-24 (H20). Each completed block pays a subsidy and its fees, split equally between the two co-creators; a stalled attempt earns nothing. Witnessing, carrying the VDF output and relaying bodies are duties of eligibility, paid only through each member's expected share of block rewards; failure statements are never paid. |
| Deployment | Decided 2026-09-24 (H21). No chain runs K=2 until its holes are closed; which deployments run it is decided from the comparison's result. A genesis consensus field names the protocol: K-of-K is the default and stays out of the genesis hash, so existing hashes are unchanged, and K=2 is a non-default value mixed into the hash, as `crypto_profile` is. |
| Transaction conflicts | Smaller transaction-data hash applies only during assembly/requeue among alternatives valid against the relevant state. It never overrides block ranking, replaces a transaction in the selected block, or revives an already consumed nonce. Omitted transactions are resent and revalidated. |
| Local correction | Temporary forks are permitted. Local acceptance is recoverable, not an irreversible network-wide certificate. Known-history hashes help discover lag or forks; nodes fetch and validate histories and correct descendants/dependencies. Recovery must work after faulty co-creators stop cooperating. Identical faults receive identical treatment regardless of intent. Revised 2026-09-24 (H12, after review): acceptance of blocks above the latest finalized checkpoint stays recoverable, while finalized checkpoints are irreversible network-wide certificates; this revises the earlier exclusion of such certificates. Decided 2026-09-24 (H17): a node switching histories loads the latest snapshot at or below the fork point, replays the winning branch through the normal apply path and requeues abandoned transactions for revalidation; it writes the new state fully and then moves its head in one durable step, so a crash leaves either the old head or the new one. |
| Shards and dependencies | Preserve the canonical fixed salt/count modulus routing and shard-local eligibility. Cross-shard effects are transactions; no extra sender-voting or receipt-approval mechanism is adopted. Dependent transactions must be revalidated after source-history correction. Neither beacon deprecation nor sharding security follows from these requirements. Decided 2026-09-24 (H18): shard B credits a transfer from shard A only once A's block is settled (z deep), proved by A's headers, pair signatures, certificates and a Merkle path (revised 2026-09-24 after review: settled means covered by a finalized checkpoint of A, and a second finalized transfer with a sequence number already credited is rejected and is evidence of a finality failure); each A→B transfer carries a sequence number for that shard pair, and B applies them in order, exactly once. The revalidation rule for dependents stays, for corrections deeper than z (after the revision above, only after a finality failure). |
| Common model | Both designs are judged under one model (H0, decided 2026-09-24). Partial synchrony: during synchrony periods every message reaches every honest node within a known Δ; safety must always hold, and progress is claimed only during synchrony. Clock drift is bounded by ρ and not adversarial. At any time fewer than a third of a shard's eligible population is malicious, crashed, offline or flooded (f < 1/3). Corruption is delayed-adaptive: the adversary chooses whom to corrupt as the protocol runs, and a corruption takes effect only after a delay τ; each design states how long its producers are known before they finish, and its claims need that to be shorter than τ. Members known in advance can be flooded, up to a stated number for a stated time (revised 2026-09-24 after review: at most b members per window T, and liveness and the H8 and H14 bounds are stated as functions of b and T). The adversary's speed-up on the delay function is at most α, set in H6. Completed 2026-09-24 after review: (1) f is measured by stake: each shard's faulty stake, whether malicious, crashed, offline or flooded, stays below 1/3 at all times, for both designs; (2) finalized checkpoints must be safe in any network condition, while fork choice above the last checkpoint, liveness and replacement are claimed only during synchrony; (3) a claim that relies on a pair or committee known in advance requires the time from its becoming known to its finishing to be shorter than τ, which holds only during synchrony with bounded stalls; (4) the adversary may acquire former members' keys, and finality with an unbonding period longer than the weak-subjectivity window bounds the damage; (5) during synchrony a message up to the block cap held by one honest node reaches every honest node within Δ; (6) α is measured against a named reference VDF evaluator on stated commodity hardware, and the genesis iteration count carries a margin for α's growth over the chain's life; (7) honest nodes keep durable storage, and a node that loses its signing record counts as faulty; (8) SHA-256 is collision- and preimage-resistant and serves as a random oracle for seeds, Ed25519 is EUF-CMA, the class-group VDF is sequential and sound, and commitments are hiding and binding; (9) the first d heights' pairs must not be computable before launch, by a mechanism still to be specified. Completed further 2026-09-24 after the second review: (10) at most b distinct members are flooded within any sliding window of length T, and liveness requires b·3B/T < (1 − f)², where here f is the malicious, crashed and offline share and the flooded members are counted by b; (11) every claim relying on τ or on the delay states the number of consecutive stalls it assumes and the probability of exceeding it given f, b and T; (12) the adversary has unlimited parallel computation, α bounding only its sequential VDF speed, and it is rushing; (13) every probabilistic claim fails with probability at most 2⁻⁴⁰ over the chain's life (10⁸ heights), per shard with a union bound over shards. |

These requirements retain the owner's choices. They do not resolve the outstanding
details by silently substituting a global election, competing-pair model, sender
unanimity, 1-of-2 fallback, irreversible finality or transaction-hash block ranking. (Finality checkpoints were later adopted explicitly, H12.)

### 6.2 Comparison with the existing K-of-K protocol

| Dimension | Existing C++ K-of-K protocol (MD mode) | Proposed K=2 PoSW direction |
|---|---|---|
| Production participation | K selected committee members contribute; all K signatures are required in MD mode. Optional BFT escalation has separate rules and assumptions. | One elected two-member pair must cooperate. Sender participation does not expand the pair. Decided 2026-09-24 (§7): pairs are drawn publicly by stake from a class-group VDF output d > 3α heights back, and a two-thirds witness quorum certifies a stall and admits the next pair (H2, H3, H6); proofs pending. |
| Transaction-set construction | Phase-1 creator transaction lists feed the union-based body reconciliation described in PROTOCOL §5. | Only jointly received transactions are eligible. Decided 2026-09-24: the body is a canonical function of the two committed received-lists and the parent state (H5, H14); proofs pending. This is a design difference, not a C99 parity port. |
| Safety/history objective | For the same committee and round, two different unanimous digest certificates require every member to sign both; one rule-following member that does not double-sign prevents that. Cross-round committee changes and the reorg-able head require separate analysis; committee intersection remains open (S-054 / D5a). | Permit temporary divergent histories and prove correct recovery/convergence under stated assumptions. Decided 2026-09-24: above the highest justified checkpoint the longer history wins, with certificate, count and header at equal length (H3, H8–H10); Casper-FFG checkpoints every E heights are intended to settle covered payments (H12), with proofs pending. E alone is not a settlement-latency bound, and K-of-K's local depth-1 reorg limit is not unconditional network finality. |
| Stalled cooperation | Existing abort-claim, suspension/reselection and optional escalation paths apply, with open liveness findings. | Missing cooperation fails an attempt. Decided 2026-09-24: a stall is certified by a two-thirds witness quorum after a 3B deadline counted from local receipt of the parent; a late original wins only if extended before the replacement arrives; silence costs only the reward (H3, H4, H7); proofs pending. |
| Randomness and work | Shipped commit/reveal randomness and deterministic committee selection; no PoSW security premise. Their recorded withholding/bias limits remain. | Publicly verified co-creator derivation plus an explicitly justified delay construction is required. Decided 2026-09-24: committed, then revealed, ephemeral DH scalars and a class-group VDF with short proofs that keeps grinding blind (H5, H6, H8). No sequential-hardness, no-grinding or chain-growth proof is established yet. |
| Evidence | C++ verifier/apply paths, analytic FA proofs and FB1 model, each with its own scope and the SECURITY ledger's residuals. | FB74/FB75 local-attempt evidence and a bounded recovery model. No production consensus or cross-shard settlement theorem; the proofs owed by the decided design are listed per hole in §7. |

Baseline references: [PROTOCOL §5](../PROTOCOL.md),
[Preliminaries §§3.3–4](../proofs/Preliminaries.md),
[ConsensusPhaseStructureSoundness](../proofs/ConsensusPhaseStructureSoundness.md),
[Safety](../proofs/Safety.md), [FB1](../proofs/tla/Consensus.tla) and
[SECURITY](../SECURITY.md). The comparison does not certify the C++ baseline as
hole-free. Its open findings and the reverted increments listed in the Decision
Log remain controlling. Same-round certificate safety does not require or prove
that all rule-following members received identical Phase-1 views before signing.
FB1 uses a shared abstract message view and bounded rounds; its model results
cannot be transferred to arbitrary per-node histories or permanent withholding.

### 6.3 Evidence boundary and remaining obligations

[FB74](../proofs/tla/K2LocalAttempt.tla) models a local attempt requiring two
matching reveals; it models neither membership/election nor ledger finality.
[FB75](../proofs/K2_VDF_Soundness.md) records the corresponding local contracts
and refuted broader claims. The [bounded recovery model](../proofs/DSF-SPEC.md#104-bounded-c99-fork-recovery-model)
establishes only a conditional finite-domain result: common anchor and finite
available candidates, trusted pair/receipt fixtures, bounded storage and unique
valid descendant suffixes. It does not prove those authority facts or convergence
for arbitrary, indefinitely growing histories.

Before calling the production design complete, an independent review must discharge
these obligations (§7 splits them into individually tracked holes):

1. **Membership and attempt validity:** authenticated admission and shard-local
   eligibility snapshots; numerical population/resource limits; prior-state pair
   derivation, shared round start, 3B transitions and treatment of late results.
2. **Public cryptographic verification:** the DH proof relation, commitments,
   canonical publication/context bytes, signature-independent parent commitment,
   delay construction and receiver verifier; justified hardware, freshness,
   withholding and parallel-candidate/grinding assumptions.
3. **Complete history selection:** canonical production headers and block/state
   admission, validated work accounting, and an unambiguous composition with the
   owner's count/header and successor rules over entire histories.
4. **Available state and recovery:** history retrieval, atomic replay/persistence
   through crashes, and cross-shard dependency correction with conservation and
   replay protection at each node's coherent publication boundaries.
5. **Derived guarantees:** convergence, progress/chain-growth bounds and any
   settlement policy under explicit fault, hardware and delivery assumptions.

An unimplemented rule and an unproved rule are different gaps; filling in code for
the local experiment closes neither automatically. Compare proposals against the
same stated adversary and observable properties, retain counterexamples, and add
falsify-on-mutant gates at the actual receiving/apply layer when behavior is
implemented. Green bounded tests or the future-tier notes in §5 cannot stand in
for these design proofs. The C99 parity migration remains separately governed by
[C99-MINIX-PORT §0](../C99-MINIX-PORT.md#0-status-on-2026-09-23--what-exists-and-the-retirement-rule).

## 7. Open design holes (2026-09-24)

**Status (2026-09-24): every hole has an owner decision. Three independent reviews
reopened and re-decided H0, H1, H3, H7, H8, H10, H12 and H18 (§7.1). H0 is CLOSED; H1–H21
are DECIDED, and each becomes CLOSED when its proof passes independent review.** Each hole is one question the K=2 design must
answer before its §6.2 row can be compared with K-of-K. §6.3's obligations are split
into holes (item 1 into H1–H4, item 2 into H5–H9, item 3 into H9–H11, item 4 into
H16–H18, item 5 into H12); H0 states the common model that §6.3 requires, and
H13–H15 and H19–H21 are added because the comparison needs them. ADR-005 §3 keeps the
detailed requirements. Every hole also states how K-of-K answers the same question,
with that protocol's open findings ([SECURITY](../SECURITY.md)), so the comparison is
between two designs with their gaps stated.

### 7.1 How a hole closes

1. The owner records the choice in a Decision Log entry. A choice that changes a
   requirement in §6.1 says so; §7.2 names the rows each hole may revise.
2. The rule is written into §6.1 or ADR-005 §3 precisely enough to implement.
3. The claim it supports is proved under the H0 model. A bounded model search can
   only refute: a counterexample reopens the hole, and a search that finds none does
   not close it.
4. An independent review accepts the proof, and the hole is CLOSED.

Statuses: OPEN → DECIDED (rule recorded, proof pending) → CLOSED. REFUTED means a
reviewed impossibility argument shows that no rule meets the requirements as
recorded; revising a requirement reopens the hole. The comparison is finished when
every hole is CLOSED or REFUTED.

### 7.2 Summary

| ID | Hole | §6.2 row | May revise (§6.1) | Status |
|---|---|---|---|---|
| H0 | Common adversary, network and hardware model | all | — | CLOSED |
| H1 | Membership, shard assignment, admission cost and population | Production participation | — | DECIDED |
| H2 | Next-pair derivation | Production participation | — | DECIDED |
| H3 | Replacement after a stalled attempt, and late results | Stalled cooperation | Co-creators, Subsequent pair, Candidate ranking or Cryptographic contributions, by mechanism | DECIDED |
| H4 | Round start and timestamps | Stalled cooperation | — | DECIDED |
| H5 | Contribution protocol and public derivation proof | Randomness and work | Cryptographic contributions | DECIDED |
| H6 | Delay function, calibration and verification cost | Randomness and work | Subsequent pair, Timing, Cryptographic contributions (option d) | DECIDED |
| H7 | Withholding by the second revealer | Randomness and work | — | DECIDED |
| H8 | Grinding by one member or a colluding pair | Randomness and work | Cryptographic contributions, Subsequent pair, Candidate ranking | DECIDED |
| H9 | Canonical header, compared bytes and parent commitment | Safety/history objective | Candidate ranking | DECIDED |
| H10 | Whole-history selection and work accounting | Safety/history objective | Candidate ranking | DECIDED |
| H11 | Ranking manipulation by padding and header grinding | Safety/history objective | Candidate ranking | DECIDED |
| H12 | Convergence, chain growth and settlement | Safety/history objective | — | DECIDED |
| H13 | Equivocation | Safety/history objective | — | DECIDED |
| H14 | Joint receipt and censorship | Transaction-set construction | Senders and body eligibility | DECIDED |
| H15 | Transaction scope, signed format and chain identity | Transaction-set construction | — | DECIDED |
| H16 | Data availability and history retrieval | Safety/history objective | — | DECIDED |
| H17 | Local recovery: replay, persistence, crash safety | Safety/history objective | — | DECIDED |
| H18 | Cross-shard dependencies under correction | Safety/history objective | Shards and dependencies | DECIDED |
| H19 | Verification cost, dissemination and light clients | (not in §6.2) | — | DECIDED |
| H20 | Incentives | (not in §6.2) | — | DECIDED |
| H21 | Deployment and genesis identity | (not in §6.2) | — | DECIDED |

**Suggested order.** H0 first: every other hole is judged under it. Then H3, which
decides whether the recorded design can have a replacement rule at all: every known
mechanism needs a revised §6.1 requirement or a new owner entry. Then H1, H4 and H6 as
H3's choice requires; then H5 and H14; then H7 and H8; then H2 (it closes once H7 and
H8 bound the influence); then H9–H12. The remaining holes may close in any order.

### 7.3 The holes

Options marked *candidate* are not recorded decisions; they show the known design
space. N is a shard's eligible population, f its malicious fraction, S the shard
count, B the block time and a the attempt index.

**H0 — Common adversary, network and hardware model**
- *Completed (2026-09-24, after two reviews):* thirteen terms added to §6.1 row "Common
  model".
  H0 proves no claim of its own; CLOSED 2026-09-24 after the third independent review
  confirmed it is precise enough for the other holes.
- *Reopened (2026-09-24, review):* not precise enough. Flooding has no rate, so flooding
  one member of each known pair stalls every attempt; suspended honest stake is not
  counted in f; the safety claims that hold during asynchrony are unstated; τ is a time
  while the lookahead is in heights; former members' keys, f by stake, and the relay and
  Δ assumptions are unstated.
- *Decided (2026-09-24):* §6.1, row "Common model". H0 proves no claim of its own;
  it closes once an independent review confirms it is precise enough for the other
  holes.
- *Question:* Which network, adversary and hardware model do both designs answer to?
- *Recorded:* §6.3 requires comparing the proposals against the same stated
  adversary. Nothing further is recorded for K=2.
- *Open because:* designs judged under different assumptions cannot be compared, and
  K=2 needs terms K-of-K does not use: the adversary's fraction of each shard's
  population, its hardware speed-up on the delay function (H6), and whether it can
  corrupt or flood a pair once the pair is known.
- *Closes with:* one model used by every hole: delivery (synchrony intervals and a
  bound Δ), a clock-drift bound, the per-shard f, static or adaptive corruption,
  targeted denial of service against known members, hardware advantage, and crash
  versus Byzantine faults.
- *K-of-K:* partial synchrony with a known Δ, bounded and non-adversarial clock drift,
  and a Byzantine set F whose corruption is not stated as static or adaptive
  ([Preliminaries §3](../proofs/Preliminaries.md#3-network-and-adversary-model)).
  Safety is conditional on committee intersection (S-054) and one honest member per
  committee; liveness needs an all-honest committee within bounded retries. Targeted
  flooding is outside the model: at most one silent member is tolerated, none at
  K = 2 (S-044), two halt the height at every K (S-076), and the epoch seed lets an
  attacker choose its victims for an epoch (Decision Log 2026-09-15).

**H1 — Membership, shard assignment, admission cost and population**
- *Revised (2026-09-24, after review):* per-shard f < 1/3 is an explicit assumption for
  both designs (§6.1 row "Membership"). Still to specify: the minimum population, now
  set by availability and cost rather than a sampling bound; the assignment randomness
  (proposed: the admitting shard's VDF output after admission); a membership message
  carried under finality; and an unbonding period longer than the weak-subjectivity
  window.
- *Reopened (2026-09-24, review):* under delayed-adaptive corruption the adversary can
  corrupt one shard's members after assignment, and exit and re-admission reach a chosen
  shard at the cost of time, so random assignment does not bound a shard's f; the 2⁻²⁹
  figure holds for one static sample, about 2⁻⁹ across 100 shards and 10⁴ snapshots.
- *Decided (2026-09-24):* stake weighting, random assignment after admission, the whole
  population as witnesses, and a minimum derived from a network-wide margin (§6.1 row
  "Membership"). Still to set and prove: the snapshot rule, margin, probability target
  and stake floor; the minimum for the actual stake distribution; that the assignment
  randomness cannot be steered (H2); and that re-admission costs enough to deter
  retrying for a chosen shard.
- *Question:* Who belongs to a shard's eligible population, how is a member assigned
  to a shard, what does admission cost, how is the eligibility snapshot fixed and
  authenticated, and what minimum population and reserve does a shard need?
- *Recorded:* a large eligible population per shard; co-creators and replacements
  come from the shard's own pool; no network-wide fallback (§6.1). "Large" has no
  number and no reserve margin is selected
  ([ADR-005 §3.2](ADR-005-Temporal-Sharding.md#32-election-and-finite-resource-limits)).
  Account routing is the canonical modulus, which "does not itself select the two
  block co-creators" (ADR-005 §3.3). The owner's words: "Sharding is based on modulus
  so every node knows its shard"; the entry recording them "does not infer a new
  validator-membership or election rule from the account-routing function" (Decision
  Log 2026-09-22).
- *Open because:* no admission rule, cost, snapshot or member-to-shard assignment
  exists. If a member's shard were the routing of its own key or address (one reading
  of the owner's words, which that entry declined to infer), a new key would land in a
  chosen shard after about S tries, so an adversary could concentrate its identities
  and a shard's f would not be bounded by the network-wide fraction. For a uniform,
  unbiased draw, a pair has at least one malicious member with probability
  ≈ 2f − f² and two with probability ≈ f² (drawing without replacement changes this
  by O(1/N)); bias from H2, H7 or H8 raises both. N does not enter these figures: it
  matters through the cost of reaching fraction f and through the reserve of live
  members that replacement (H3) needs.
- *Closes with:* an admission rule and cost; a snapshot rule every verifier can check;
  a member-to-shard assignment the adversary cannot steer, or a per-shard f with its
  admission-cost argument; and a minimum population and reserve derived from f and
  stated targets for halting (H3), censorship (H14) and collusion (H8).
- *K-of-K:* staked registered domains (STAKE_INCLUSION; DOMAIN_INCLUSION is still in
  the code, D21 decided, not landed), with no post-genesis join path (S-069; D6
  decided, not landed). On EXTENDED a shard's pool is the validators whose registered
  region matches the chain's `committee_region`, so members choose their shard
  ([PROTOCOL §5.2](../PROTOCOL.md#52-committee-selection)); the pool is frozen per
  epoch only on EXTENDED and read from the current registry elsewhere. Genesis checks
  only 2K > m_creators; the decided pool bound 2K > N(h), at most 5 members on the WEB
  preset (K = 3), is not landed (S-054, D5a). For an unbiased draw from a large pool a
  K-member committee is all-Byzantine with probability ≈ f^K and contains a Byzantine
  member with probability ≈ 1 − (1 − f)^K; small pools take the exact hypergeometric
  values, and under the decided bound an all-Byzantine committee needs a Byzantine
  majority of the pool.

**H2 — Next-pair derivation**
- *Decided (2026-09-24):* public stake-weighted sampling from a seed over the VDF output,
  with the output carried in block h+d−1 (§6.1 row "Subsequent pair"). Still to specify
  and prove: the domain tag and canonical encoding; the weighted-sampling algorithm with
  test vectors; that the draw is unbiased given H6's blindness and H8's release bound;
  and H1's shard-assignment randomness from the same outputs.
- *Question:* What exact function maps the last agreed state and the attempt index to
  the next pair, and how far can the current pair, a relayer or a coalition steer it?
- *Recorded:* the next pair is derived from the last agreed state and contributions
  already available there, without waiting for fresh shares from the stalled pair;
  the VDF delays knowledge of the pair and grants no production right (§6.1). An
  unauthenticated header hash or a signature-malleable block hash is not an
  acceptable source
  ([ADR-005 §3.1](ADR-005-Temporal-Sharding.md#31-producer-and-fault-model)); a
  mechanism is called a VRF only if it is a verified construction, otherwise
  deterministic sampling (ADR-005 §3.2).
- *Open because:* inputs, domain separation, attempt indexing and the sampling
  algorithm are unspecified, and the influence bound depends on H7 and H8.
- *Closes with:* a canonical derivation over committed inputs, with test vectors, and
  an influence bound composed from H7 and H8; H2 therefore closes after them.
- *K-of-K:* the committee is drawn from `cumulative_rand`, a commit-reveal whose
  inputs are digest-covered or commit-pinned; the last revealer can reject one sample
  per height (S-077). On EXTENDED, any K eligible domains can drive the beacon's rand
  chain (S-093), and an unconfirmed first header seeds an epoch (S-094).

**H3 — Replacement after a stalled attempt, and late results**
- *Decided again (2026-09-24, after the second review):* length first above the
  fork-choice root, with the certificate criterion only at equal length (§6.1 row
  "Candidate ranking"). The late-result guarantee is restated: a late original wins only
  if it is extended before the replacement arrives, a choice H8's delay keeps blind.
  Still to prove: that restated guarantee, and that certificates bound to the parent
  cannot be reused across branches.
- *Reopened (2026-09-24, second review):* certificate first lets a fully colluding attempt
  a+1 pair sign certified siblings, withhold them, and release the one whose VDF outcome
  it prefers before the next checkpoint finalizes, beating the whole honest branch.
- *Revised (2026-09-24, after review):* certificate first at the fork point, then length
  (§6.1 row "Candidate ranking"). Still to prove: a late original never beats a
  certified replacement at their fork point; certificates bound to the parent cannot be
  reused; above the last checkpoint no certificate forms without two thirds of current
  stake.
- *Reopened (2026-09-24, review):* under H8's length-first rule a late attempt-a block
  that is extended before attempt a+1's block wins despite the certificate,
  contradicting "a withheld result released later loses" and orphaning the certificate
  that carries H7's naming.
- *Decided (2026-09-24):* the witness quorum (mechanism 3), recorded in §6.1 rows
  "Replacement" and "Candidate ranking". Still to prove under H0: a result that
  reached every honest member before the deadline is never displaced; a stalled attempt
  is certified within Δ of its deadline during synchrony; a withheld result released
  later loses. H1 weights and sizes the quorum, and H4 sets the deadline.
- *Question:* When an elected pair does not complete, what transition, checkable by
  every receiver from data it holds, lets the next pair act, and what happens to the
  stalled pair's result if it arrives late?
- *Recorded:* the owner's constraint is "One elected pair, with a separately proved
  timeout and replacement rule" (Decision Log 2026-09-22, "C99 K=2 correction"). The
  same entry requires "an objectively verifiable replacement transition and its
  fault/timing assumptions", refutes a local timeout counter as replacement
  authorization, and "authorizes neither competing pairs nor an invented quorum,
  clock oracle or unproved delay certificate". §6.1: no competing normal pairs or
  global fallback; the next pair is derived without fresh shares from the stalled
  pair; the VDF output is not an independent replacement proof. ADR-005 §3.1 shows how
  a late result makes admission depend on each receiver's delivery order.
- *Open because:* without a timing assumption a stalled pair cannot be told apart
  from a slow one, and the only witness to one member's silence is its partner. A
  replacement triggered by one member's claim is the S-044 cascade: at K=2 a single
  claim excluded members under ordinary timing skew until the pool fell below K
  (reproduced live three times), which is why the K=2 abort quorum is now
  unsatisfiable (`chain::abort_claim_quorum`).
- *Candidate mechanisms* (they can be combined):
  1. *Time* — a delay proof with a short verifier, bound to the stalled attempt, shows
     that 3B of sequential work has passed since the round start. The 2026-09-22
     entry does not authorize an unproved certificate, and §6.1 denies this role only
     to the election VDF's output. It needs H6's hardware bound: a faster adversary
     obtains the certificate early and can replace an honest pair before its 3B window
     has elapsed.
  2. *Slot timing* — each receiver admits attempt a's pair once its own clock passes
     the round start plus a·3B, under a stated drift bound, with no certificate.
     K-of-K's time-bucket design was refuted because no bucket size was both agreed by
     all honest members before a round and short enough to rotate (Decision Log
     2026-08-12, "final+9"; S-076), and the 2026-09-16 entry lists the "time-bucket /
     round-marker / local-cadence family" among refuted designs not to be revived.
     Those findings concern the fork-free K-of-K chain, so an owner entry must say
     whether they apply here. The slot is 3B, so it needs 3B well above twice the
     drift bound plus Δ, and receivers still disagree near a boundary, which is
     admissible only if that disagreement converges (H10, H12).
  3. *Witnesses* — shard members sign that attempt a produced nothing by its deadline,
     and a threshold forms a certificate (the shape of K-of-K's R-15). The 2026-09-22
     entry does not authorize an invented quorum, so this needs an owner entry, and
     H1 to size it. Honest witnesses that received attempt a's result in time do not
     sign, so with a quorum larger than the malicious share a result delivered to
     every honest witness before the deadline cannot be replaced; under H0 that means
     a result completed at least Δ before the deadline, within a synchrony interval. A
     result completed later, or delivered selectively, can still meet a certificate
     (late results, below). Time alone gives no such protection.
  4. *Competition* — attempt a+1's pair may always produce, and the ranking rules
     settle it against a late attempt-a result. Revises "No competing normal pairs"
     (Co-creators); needs H10 and H11.
  5. *Degrade* — the remaining member completes alone after the timeout: the
     withdrawn 1-of-2 fallback (§4). Revises "Incomplete cooperation produces no
     completed valid candidate" (Co-creators).
  6. *Widen* — after the timeout, more pairs or members outside the shard may produce.
     Revises "no competing normal pairs or global-pool fallback" (Co-creators) or
     shard-local eligibility.
  7. *Reconstruct* — each co-creator deals its contribution to shard members in
     advance by publicly verifiable secret sharing, and a threshold completes a
     stalled attempt. The threshold is a quorum (owner entry), and it changes
     Cryptographic contributions.
  8. *Halt* — the shard stops until recovery outside the protocol. Contradicts the
     owner's "separately proved timeout and replacement rule" and the Subsequent pair
     row, which provides a next pair after a stall.
- *Time-based admission* (mechanisms 1 and 2) admits attempt a+1 on elapsed time
  alone, whether or not attempt a completed, and a node validating later must admit
  every attempt whose time has passed (Decision Log 2026-08-12 "final+9", "No replay
  seam"; 2026-09-22, "attempt jump"). §6.1's ranking has no attempt term, so a later
  pair that is entirely malicious (≈ f² per attempt) can outrank an honest result at
  that height by padding (H11), how far back depending on H10. Without an
  attempt-ordering rule, which revises Candidate ranking, this is competition.
- *Late results:* under every mechanism a completed attempt-a result can reach some
  receivers after others admitted attempt a+1. The rule must say whether it stays
  valid and, if it does, how it ranks against attempt a+1's result without becoming
  the competing pairs the owner excluded.
- *Closes with:* an owner entry choosing the mechanism and revising any requirement it
  conflicts with; a transition rule every receiver checks; the late-result rule; and
  a model showing progress under H0 and convergence of receivers that saw the
  transition at different times.
- *K-of-K:* abort claims with quorum max(2, K−1) exclude one silent member and
  re-draw the committee when the pool has a spare. At K=2 the quorum is unreachable,
  so one silent member halts the height
  ([V10](../proofs/Preliminaries.md#5-block-validity-predicate); S-044's fix chose a
  halt over the cascade); two silent members halt at every K (S-076); a pool
  shortfall that predates a height never arms BFT escalation (S-086). The certified
  re-draw is decided (R-15, D11) and has no design yet (gate G1).

**H4 — Round start and timestamps**
- *Decided (2026-09-24):* local receipt and informational timestamps (§6.1 row
  "Timing"). Still to prove under H0: during synchrony a pair that completes at least
  2Δ, plus drift, before its own deadline cannot be certified as failed. H6 must fix
  the delay parameter without timestamps.
- *Question:* When does a round start, so that 3B means the same thing at every
  receiver, and which producer timestamps does every verifier accept?
- *Recorded:* configurable block time B and a total attempt timeout of 3B from the
  round start; producer timestamps are adversarial inputs; the timestamp rules every
  verifier enforces, and what difficulty adjustment proves, must be stated (§6.1;
  ADR-005 §3.1).
- *Open because:* neither is specified. A start read from a local clock or from local
  receipt of the parent differs between receivers by delivery delay and drift; a
  start taken from the parent's timestamp is chosen by the parent's producers within
  whatever window verifiers allow; a start fixed by a delay proof depends on H6.
- *Closes with:* a round-start definition and a timestamp rule, with their
  assumptions stated in H0 and consistent with H3's mechanism.
- *K-of-K:* round timers are node-local, and a stall becomes consensus-visible only as
  an abort certificate (V10). The block timestamp is the lower median of the
  committed proposer times, bound into the digest, and every verifier also checks it
  against its own clock (±30 s, V14), so validity already depends on local clocks
  within that window.

**H5 — Contribution protocol and public derivation proof**
- *Decided (2026-09-24):* option (c), revealed DH scalars, with each commitment also
  fixing the co-creator's received-transaction list (§6.1 row "Cryptographic
  contributions"). Still to specify and prove: canonical commitment and reveal bytes
  bound to chain, shard, parent, height and attempt; point and scalar checks; binding
  and hiding of the commitments; and that the second revealer's only lever is to
  withhold (H7).
- *Question:* How do the two co-creators commit to and reveal their contributions,
  what does the published result derive from, and what lets any receiver check that
  derivation and its binding to body, chain, shard, parent, height and round?
- *Recorded:* ephemeral contributions under registered identity keys; ordinary
  receivers verify the DH-derived result and its use as the VDF input; signatures
  alone do not prove the derivation; senders supply no shares (§6.1). The requirement
  selects no proof suite and does not require disclosing private keys; the relation,
  commitment scheme, publication sequence and encoding are open
  ([ADR-005 §3.4](ADR-005-Temporal-Sharding.md#34-owner-clarification-temporary-forks-and-local-recovery)).
- *Open because:* none of these exists.
- *Candidate options:*
  (a) hash commit-reveal: each co-creator commits to H(rᵢ ‖ context) and reveals rᵢ;
  the result is H(r_A ‖ r_C ‖ context), and any receiver recomputes it. There is no
  DH, so this revises Cryptographic contributions. Only the second revealer learns the
  result before publication (H7).
  (b) DH with a Chaum–Pedersen (DLEQ) proof that the published value combines the two
  committed public shares. It meets the recorded DH requirement without revision. Both
  co-creators know the result once the shares are exchanged (in (a) only the second
  revealer does): a private head start (H7, H8).
  (c) DH with the ephemeral scalars revealed once both public shares are committed;
  receivers recompute the result. An ephemeral scalar is not an identity key, so no
  private key the requirement protects is disclosed. Same head start as (b).
- *Closes with:* the construction, its security argument (binding, and who learns the
  result when), canonical encoding and a verifier specification.
- *K-of-K:* option (a)'s shape: every member commits in Phase 1 and reveals in
  Phase 2. `cumulative_rand` is outside the digest, but every verifier recomputes it
  from the digest-covered commitments and the revealed secrets (`check_delay`,
  `check_cumulative_rand`); no derivation proof is needed.

**H6 — Delay function, calibration and verification cost**
- *Decided (2026-09-24):* blind trials with a class-group VDF and short proofs (§6.1 row
  "Subsequent pair"). Still to specify and prove: the group, proof and assumption; α and
  the lifetime margin; the genesis iteration count; d; who computes and publishes each
  output and proof, and what happens if nobody does; the per-block verification cost
  (H19). The lookahead is time, not heights: about T_vdf(1 − 1/α) plus 3B for each attempt,
  so each claim relying on τ must state the attempt bound it assumes (H0).
- *Question:* Which delay function, under which sequential-hardness assumption, with
  what bound on hardware advantage, calibrated and adjusted how, and verified at what
  cost by every full node?
- *Recorded:* the VDF delays knowledge of the next pair; its parameters must account
  for their timing use; no hardware-independent duration is claimed (§6.1). The delay
  construction and its proof and hardware assumptions must be specified, and what
  difficulty adjustment proves must be stated (ADR-005 §3.1).
- *Open because:* the in-tree evaluator is a custom AES/SHA-256 computation with no
  sequential-hardness, ASIC-resistance or minimum-duration argument, and `vdf_verify`
  repeats the evaluation ([K2_VDF_Soundness §1](../proofs/K2_VDF_Soundness.md)).
  Every full node therefore pays the full delay per block of each shard it follows
  (H19), and faster hardware gains an unbounded margin. The C99 difficulty helper
  adjusts from timestamps alone and is not production difficulty validation (Decision
  Log 2026-09-22); with adversarial timestamps (H4) such an adjustment can be steered.
  The project has removed a delay function before: S-009 deleted iterated SHA-256 as
  unenforceable under ASIC asymmetry, and
  [S009DelayHashRemoval F-2](../proofs/S009DelayHashRemoval.md) requires a
  reintroduction to name an attack it stops that commit-reveal does not (the
  last-revealer veto, S-077, is one) and to avoid five defects: an ASIC-amenable
  construction, an operator-set iteration count, a parameter outside the genesis, a
  verification cost that grows with the delay, and per-iteration allocation.
  Pietrzak's VDF was considered then and not adopted.
- *Candidate options:* (a) Wesolowski or Pietrzak: short proofs, over an RSA group
  (trusted setup) or a class group, with new from-scratch big-integer code under the
  crypto doctrine; (b) iterated hashing with a succinct proof: an expensive prover;
  (c) verification by recomputation, with its cost accepted (H19); (d) no delay, with
  H2's unpredictability obtained another way, as K-of-K did.
- *Closes with:* a named construction and assumption, a calibration and adjustment
  argument that survives adversarial timestamps, and the per-block verification cost;
  or (d) with H2 closed without a delay.
- *K-of-K:* no delay function and no work premise since S-009; unpredictability comes
  from commit-reveal, whose last-revealer residual is S-077.

**H7 — Withholding by the second revealer**
- *Revised (2026-09-24, after review):* reward loss only; failure statements name no one
  (§6.1 row "Replacement"). Stalls are now free for a colluder apart from the lost
  reward, which H8's stall margin must absorb. Still to prove: the liveness bound as a
  function of f, b and T.
- *Reopened (2026-09-24, review):* a flooded honest member is named like a withholder, so
  flooding lets the adversary suspend honest stake and raise the effective f; and a
  staller can time its last message so that no member is named by two thirds.
- *Decided (2026-09-24):* attested suspension (§6.1 row "Replacement"). Still to specify
  and prove: the suspension window; phase deadlines under which an honest member is never
  named for a message it could not yet send (for example, a reveal delayed by its
  partner's late commitment); that during synchrony an honest member that sent in time is
  never named by two thirds; and the remaining production shift (≈ f² per stall, since
  replacement pairs are known in advance), now paid for with the staller's seat.
- *Question:* What does a co-creator gain by withholding its reveal or signature after
  seeing its partner's, and how is that bounded?
- *Recorded:* incomplete cooperation produces no completed candidate; identical faults
  are treated identically regardless of intent (§6.1).
- *Open because:* the second revealer holds the VDF input before it decides. If it can
  evaluate the delay before its deadline (H6), it knows the next pair and can reject
  outcomes it dislikes; if not, it can still abort blindly. Once H3 exists,
  withholding changes who produces next: a bias on election and a lever for
  censorship. No third party can attribute the failure, because the only witness is
  the partner, whose claim cannot be checked; a cost for withholding therefore needs a
  witness mechanism (H3), and under identical treatment it also falls on crashed
  members.
- *Closes with:* a bias bound under H0, per attempt and cumulative, composed with H6's
  hardware bound, and the owner's choice of a cost (possibly none) with its
  attribution rule.
- *K-of-K:* the same residual: the last Phase-2 revealer can reject one sample per
  height, lifting its next-committee inclusion probability from K/N to at most
  K/N + (1 − K/N)·K/N per veto (S-077). The other K − 1 members witness its silence;
  suspending the withholder is decided (R-16, D12), not landed.

**H8 — Grinding by one member or a colluding pair**
- *Revised (2026-09-24, after review):* k covers colluder and flooding stalls (§6.1 row
  "Subsequent pair"). Still to prove: the release bound as a function of f, b, T and k.
- *Decided (2026-09-24):* longest history first, with a delay that outlasts k stalls at the
  next height (§6.1 rows "Candidate ranking" and "Subsequent pair"). Still to prove:
  one member and a colluding pair choose blindly; releasing a withheld sibling with its
  outcome known needs k consecutive colluder-containing pairs, about (2f − f²)^k per
  colluding-pair height; H7's suspensions bound repeated tries; the bias left over.
- *Question:* Which parties can try many candidates for one attempt (contributions,
  bodies or private histories) and keep the one that elects a favourable next pair or
  wins a later tie? How many trials fit in the window, and what bounds the gain?
- *Recorded:* challenge freshness and context binding are required (ADR-005 §3.1).
  Colluding participants can precompute candidates, a sequential dependency within one
  evaluation does not prevent parallel evaluation of independent candidates, and the
  economic no-grinding argument is withdrawn (§2).
- *Open because:* as recorded, the derived result binds the ordered-body hash and is
  the VDF input (Decision Log 2026-09-22, "Noninteractive senders"), so the body
  steers the next pair. If the body is fixed only after a member knows its partner's
  contribution (H5's publication sequence), one malicious member, present in
  ≈ 2f − f² of attempts (H1), chooses the body: it can deny receipt of any pending
  transaction (H14) and add transactions of its own sent to its partner, limited only
  by the delay evaluations it can run in the window; if contributions are not
  committed before either is revealed, it can grind its own as well. A colluding pair
  (≈ f²) knows both contributions before the timer and grinds contributions, bodies
  and private histories together (FB75 R1). Each trial costs one delay evaluation, and
  trials run in parallel (H6). No fresh-challenge rule or bound exists.
- *Candidate closures:* keep attacker-chosen values out of the next-pair input once
  either contribution is known, by fixing the body in each co-creator's commitment
  before either contribution is revealed (K-of-K's Phase-1 shape, which keeps the
  recorded binding) or by excluding the body from the VDF input (which revises
  Cryptographic contributions). With contributions committed before either is
  revealed, either choice stops one member's informed grinding, leaving the H7 veto,
  but not a colluding pair's. Alternatively, make every trial blind, with the delay on
  the adversary's hardware longer than the time it has to choose (up to 3B after the
  round start); the next pair must still be known by its own round start, which
  forces the pair to be derived several heights ahead. Or accept a stated bias bound.
- *Closes with:* a bound on the adversary's election advantage under H0, per attempt
  and cumulative, or a counterexample.
- *K-of-K:* selection reads `cumulative_rand`, whose inputs are digest-covered or
  commit-pinned: `delay_seed` covers `tx_root` (the union of the Phase-1-signed hash
  lists, not the delivered body) and `prev_hash`, all fixed before any secret is
  revealed. Choosing the outcome needs an all-Byzantine committee (≈ f^K per draw from
  a large pool, H1), and one member's lever is rejection sampling (S-077). The block
  hash is signer- and relayer-malleable (S-029, S-102), which is why nothing
  security-relevant is seeded from it; the parent's hash enters only through
  `prev_hash`, before the child committee's secrets exist (Decision Log 2026-08-12,
  "final+9").

**H9 — Canonical header, compared bytes and parent commitment**
- *Decided (2026-09-24):* content-only identity and a new canonical header (§6.1 row
  "Candidate ranking"). Still to specify and prove: the field list and encoding with
  test vectors; that only the pair can produce two valid encodings of different content
  for its attempt; and that the parent commitment covers content only.
- *Question:* What is the single canonical production header, which bytes are signed,
  which bytes does "the smaller full header" compare, and how does a child commit to
  its parent independently of signature bytes?
- *Recorded:* at one height more distinct valid transactions win, then the smaller
  full header read as a number; the smaller successor header wins among successors
  (§6.1); a header value is not interchangeable with its hash (ADR-005 §3.4); §6.3
  item 2 requires a signature-independent parent commitment.
- *Open because:* two incompatible C99 header formats exist (212 and 120 bytes, with
  32- and 64-bit work fields; ADR-005 §2). If the compared bytes or the parent
  commitment include signatures, or any field a signer or relayer can vary without
  changing content, whoever tries more variants wins ties, and a relayer can give one
  parent several identities for children to commit to: the malleability recorded for
  the C++ block hash (S-029, S-102).
- *Closes with:* one canonical encoding; an argument that no party can produce two
  valid headers for the same content that differ in the compared bytes, or that such
  bytes are excluded from the comparison; and a parent commitment over
  signature-independent content.
- *K-of-K:* the committee signs `compute_block_digest`, which excludes `transactions`
  (the body; Censorship §0), `state_root`, `initial_state`, `delay_output`,
  `creator_dh_secrets` and `cumulative_rand`. The
  block hash covers `Block::signing_bytes` plus the signatures, and `prev_hash`
  commits to it, so the parent commitment depends on signature bytes.
  `resolve_fork`'s last tie-break, the smallest block hash, is grindable by the
  trailing signer and by a relayer through `initial_state` (S-029; the accept rule
  that would close the relayer path is not written).

**H10 — Whole-history selection and work accounting**
- *Revised (2026-09-24, after review):* correction never crosses the latest finalized
  checkpoint (H12), which bounds the long-range attack for nodes that follow the chain.
- *Reopened (2026-09-24, review):* with unbounded correction depth, keys of former
  members holding two thirds of an old snapshot can build a private branch with its own
  certificates and outgrow the chain from any depth (a long-range attack); the first d
  pairs also derive from a seed known when the genesis is published.
- *Decided (2026-09-24, H8 and H10):* the longer valid history wins; equal lengths are
  compared at the fork point by the same-height rules; correction depth is unbounded
  (§6.1 row "Candidate ranking"). Still to prove: every honest node computes the same
  total order from the same candidates, and the bounded model covers competing
  descendants (`K2_MODEL_UNSUPPORTED_BRANCHING`).
- *Question:* How do the same-height rules and the successor rule compose into one
  order over complete histories, together with validated work, and how deep may a
  reorganization go?
- *Recorded:* each candidate is validated on its own parent; the ranking rules above;
  validated-work ordering is intended; complete-history and work composition remain
  open (§1, §6.1).
- *Open because:* the composition is unspecified, "work" is not yet validated work,
  and the bounded model stops at competing descendants
  (`K2_MODEL_UNSUPPORTED_BRANCHING`,
  [DSF-SPEC §10.4](../proofs/DSF-SPEC.md#104-bounded-c99-fork-recovery-model)).
- *Closes with:* a total order over histories that every honest node computes
  identically from the same candidates, a reorganization-depth statement, and a model
  that covers competing descendants.
- *K-of-K:* committee intersection plus one honest member makes history selection a
  one-height problem (FA1; 2K > N(h) is open, S-054); the abort/finalize race resolves
  by `resolve_fork` and a depth-1 reorganization (S-048).

**H11 — Ranking manipulation by padding and header grinding**
- *Decided (2026-09-24):* the count criterion stays, with its manipulation bound stated:
  after H8–H10, count and header decide only between equal-length histories whose
  fork-point blocks have the same certificate status, that is between a colluding pair's
  own siblings (bounded by H8) or between honest branches after a partition, where a
  sender can choose the surviving branch at a fee cost. Header grinding is left to the
  pair alone (H9). Still to prove: that these are the only cases.
- *Question:* Can a pair raise its candidate's rank without serving users better, by
  padding the body with its own transactions or by grinding the compared header
  bytes, and what does that cost?
- *Recorded:* more distinct valid included transactions win, then the smaller header;
  this applies to identical bodies and to conflicting sender/nonce transactions
  (§6.1).
- *Open because:* whenever candidates compete (H3's late results, H13, partitions),
  any party that can get extra valid transactions to one competing pair can out-count
  an honest candidate, at a fee cost H20 has not set: a colluding pair, one malicious
  member sending its own transfers to its partner (≈ 2f − f²), or any funded sender
  delivering to that pair only. Among equal counts, any variable header byte (H9) can
  be ground for a smaller value. Each win over a candidate that nodes already follow
  forces a correction on every one of them (H12, H17).
- *Closes with:* a bound on what padding and grinding buy an adversary, or a revised
  ranking rule.
- *K-of-K:* `resolve_fork` ranks by the heaviest signature set, then fewer abort
  events, then the smallest block hash. There is no count to pad; the block-hash step
  is grindable (S-029), and the harm is limited to liveness griefing because nothing
  security-relevant is seeded from the block hash.

**H12 — Convergence, chain growth and settlement**
- *Revised (2026-09-24, after review):* finality checkpoints (§6.1 rows "Settlement" and
  "Local correction"). Still to specify and prove: the voting rules and accountable
  safety under f < 1/3 in any network condition; finalization liveness during synchrony;
  the interval E, the unbonding period and the weak-subjectivity window; the voter set of
  each link fixed from finalized state, so conflicting branches share it; and adoption of
  a newly justified root only at defined points, against vote-withholding delays.
- *Reopened (2026-09-24, review):* settlement fails under asynchrony with no corrupt
  member (isolated attempt-0 pairs extend a block that the certified majority later
  replaces), and the lookahead in heights exceeds τ during long stalls; an equal-length
  branch wins by count, so the run is z+1 (z = 21 and 16), or z when flooding picks the
  fork-height pair.
- *Decided (2026-09-24):* settlement at depth z for 2⁻⁴⁰ over the chain's life (§6.1 row
  "Settlement"). Still to prove under H0: honest nodes converge once synchrony resumes;
  the honest chain's growth rate; the reversal bound (a private branch cannot use
  replacements and, for its first d heights, needs the public schedule's pairs to be
  fully colluding); and the chain-life assumption behind z.
- *Question:* Under H0, do honest nodes converge on one history, how fast does the
  honest history grow relative to an adversary's, and when may a payment be treated
  as settled?
- *Recorded:* temporary forks are allowed; local acceptance is recoverable, not an
  irreversible network-wide certificate; the property to establish is convergence
  under explicit delivery and fault assumptions (§6.1; ADR-005 §3.4).
- *Open because:* none of these is stated or proved (§6.3 item 5), §2 selects no
  confirmation depth, and the bounded model's finite result does not extend to
  growing histories.
- *Closes with:* theorems with explicit assumptions, and a confirmation rule that users
  and light clients can apply.
- *K-of-K:* no separate finality layer. Fork freedom rests on committee intersection
  (S-054, open) and one honest member in the deciding committee (FA1; an all-Byzantine
  committee can fork its height), and FA1's corollary holds per round instance. The
  head can still be reorganized to depth 1 (S-048), so H−1 is the de-facto finality
  floor ([BoundedReorgDesign](../proofs/BoundedReorgDesign.md)).

**H13 — Equivocation**
- *Decided (2026-09-24):* record and suspend (§6.1 row "Replacement"). Still to specify
  and prove: the evidence format, cap and window; that an honest member with a durable
  signing record never satisfies the predicate; and that results of different attempts
  are never taken for equivocation.
- *Question:* When co-creators sign two different candidates for one attempt, how is
  it detected, what evidence is recorded, and what follows?
- *Recorded:* identical faults are treated identically regardless of intent (§6.1).
- *Open because:* a valid candidate needs both signatures, so one malicious member
  cannot equivocate while its partner signs once; a colluding pair (≈ f²) can issue
  any number of valid candidates for one attempt, and the evidence names both. A
  member that restarts without its signing state produces the same evidence, so any
  consequence also falls on faulty honest members. Results of different attempts at
  one height (H3) are not equivocation. No evidence format or consequence exists.
- *Closes with:* a detection and evidence rule and an explicit consequence, which may
  be "none", consistent with H3's late-result rule.
- *K-of-K:* two signatures by one member over different digests at the same height
  and round generation (V11) are detected and kept as a capped, deduplicated evidence
  record with no L1 consequence (D4, O-1 step 3b); the
  consequence belongs to an L2 bond (D22), not designed; and no predicate over two
  signed openings separates a splitter from an honest node across rounds (R-1).

**H14 — Joint receipt and censorship**
- *Decided (2026-09-24):* a canonical body over the intersection, and the joint-receipt
  bound as the censorship guarantee (§6.1 row "Senders and body eligibility"). Still to
  specify and prove: the canonical order and cap, and the bound under bias from H2, H7
  and H8.
- *Question:* How do the co-creators establish that both received a transaction, and
  how long can a malicious member keep a transaction out?
- *Recorded:* only transactions received by both co-creators are eligible; omitted
  transactions are resent and revalidated; production assembly still needs
  specification (§6.1).
- *Open because:* non-receipt cannot be proved, so either member can keep any
  transaction out of its pair's blocks by claiming it never arrived. If every
  malicious member censors a transaction, it waits for an all-honest pair: at least
  1/(1 − f)² attempts in expectation for an unbiased draw (2.25 at f = 1/3), more when
  the draw is biased (H2, H7, H8) or attempts stall (H3).
- *Closes with:* the assembly protocol, and a censorship bound the owner accepts or a
  changed inclusion rule.
- *K-of-K:* a rule-following member's committed hash list enters the union, so one
  honest member suffices to commit a transaction. The body, however, is not
  committee-signed: an assembler or relayer can strip a committed transaction after
  signing, so FA2's censorship theorem is false for shipped code
  ([Censorship §0](../proofs/Censorship.md); S-030 partial).

**H15 — Transaction scope, signed format and chain identity**
- *Decided (2026-09-24):* transfers plus membership transactions, with a length-prefixed
  preimage carrying the chain identity (§6.1 row "Transactions"). Still to specify and
  prove: the field lists, the injectivity argument and test vectors; the list of K-of-K
  types recorded as stated differences.
- *Question:* Which transaction types and address forms does a K=2 chain carry, and
  exactly which bytes are signed?
- *Recorded:* modulus routing; cross-shard effects are transactions (§6.1).
- *Open because:* the C99 pending inbox accepts only anonymous intra-shard transfers
  between fixed 66-byte hex addresses. It verifies the decided D23 preimage (type,
  genesis hash, shard id, from, to, amount, fee, nonce); the C++ signing bytes omit
  the chain identity (D23's landing was reverted 2026-09-23), so a C++-signed
  transaction is not accepted there. A hex address cannot hold a NUL, so S-117 does
  not arise in that subset; a wider scope with variable-length fields must
  length-prefix them or reject NUL. The comparison needs the same scope on both sides
  or a stated difference.
- *Closes with:* a scope decision, a canonical signed layout with an injectivity
  argument, and test vectors.
- *K-of-K:* eighteen type discriminators, TRANSFER (0) to REGISTER_NOTE_KEY (17), of
  which REGION_CHANGE (5) is reserved and rejected. The signing bytes bind no chain
  identity (S-103; D23 decided, its landing reverted 2026-09-23) and are not injective
  with a NUL in `to` (S-117, open).

**H16 — Data availability and history retrieval**
- *Decided (2026-09-24):* full bodies with availability gating, and retention back to the
  latest finalized checkpoint plus d heights, plus archives (§6.1 row "Availability"). Still to specify and prove: the
  snapshot interval and format; that a withheld body never counts; that selective delivery
  resolves once the body spreads; and what a node does when no archive is reachable.
- *Question:* How does a receiver obtain the data it needs to validate a candidate
  history, and what does it do with a header whose body is withheld?
- *Recorded:* known-history hashes expose differing views, and nodes fetch and
  validate histories (§6.1); header work alone is insufficient (ADR-005 §3.3).
- *Open because:* no availability or retention rule exists, and a pair can publish a
  header while withholding its body, or give the body to some receivers only and
  split their views.
- *Closes with:* an availability rule (full replication, sampling or custody), a
  retention period covering H10's reorganization depth, and the treatment of
  unavailable candidates.
- *K-of-K:* each committee member holds the transactions whose hashes it committed,
  and blocks, chain ranges and snapshots are served over gossip. The body is outside
  the committee signatures (Censorship §0), so two bodies can circulate under one
  signature set.

**H17 — Local recovery: replay, persistence, crash safety**
- *Decided (2026-09-24):* snapshot plus replay with an atomic head switch (§6.1 row
  "Local correction"). Still to specify and prove: the snapshot format and interval;
  that the recovered state equals a fresh replay of the selected history over unbounded
  histories; crash safety at every step; and that requeueing preserves conservation.
- *Question:* What state machine detaches a losing branch, replays the winning one,
  requeues transactions and survives a crash at any point?
- *Recorded:* temporary forks and local correction are intended; recovery must work
  after faulty co-creators stop cooperating (§6.1); the bounded model covers one
  anchor and a finite candidate set
  ([ADR-005 §3.5](ADR-005-Temporal-Sharding.md#35-dsf-convergence-and-recovery-design-gate)).
- *Open because:* unbounded histories, persistence and the production receiver are
  unspecified; the model uses in-memory journals and trusted pair and receipt
  fixtures.
- *Closes with:* a specification over unbounded histories, a crash model, and evidence
  that recovery equals a fresh replay of the selected history.
- *K-of-K:* a depth-1 head reorganization, atomic over an apply failure (S-102); a
  snapshot-bootstrapped node cannot follow the chain (S-075, open).

**H18 — Cross-shard dependencies under correction**
- *Revised (2026-09-24, after review):* credit only under a finalized checkpoint of the
  source shard; a repeated sequence number is rejected as evidence of a finality failure.
- *Reopened (2026-09-24, review):* inherits H12's asynchrony problem; a credit proof
  needs only a z-deep branch to exist, adding log₂S bits; two settled transfers with the
  same sequence number need a rule.
- *Decided (2026-09-24):* credit after settlement, ordered per source (§6.1 row "Shards
  and dependencies"). Still to specify and prove: the proof format; global conservation
  with per-shard accounting (debit on A, credit on B); exactly-once crediting across
  retries, crashes and corrections; and handling of a correction deeper than z.
- *Question:* When shard A corrects its history, how are dependent transactions on
  shard B revalidated, with conservation and replay protection?
- *Recorded:* cross-shard effects are transactions; no receipt approval or sender
  voting; dependents are revalidated after correction (§6.1).
- *Open because:* no mechanism exists; it is the planned next simulation increment
  (ADR-005 §3.5).
- *Closes with:* a dependency and correction rule, and evidence of conservation and no
  double credit across correction, retries and crashes.
- *K-of-K:* receipts travel through shard tips and the beacon on EXTENDED. Bundles are
  unauthenticated (S-064), and the inbound credit mints on the destination shard, so
  per-shard supply is not conserved (S-096); both are open and EXTENDED only.

**H19 — Verification cost, dissemination and light clients**
- *Decided (2026-09-24):* a verified light client over stake-sum Merkle roots, and plain
  Ed25519 certificates (§6.1 row "Verification"). Still to specify and measure: the
  per-block verification cost, the dissemination cost per height and per stall, and the
  light client's trust assumptions and proof sizes.
- *Question:* What does a full node verify per block and at what cost, what does
  dissemination cost within and across shards, and what can a light client verify?
- *Recorded:* ordinary receivers verify the derivation and its use as the delay input
  (§6.1). Two roles per shard do not establish O(1) total overhead: validation,
  dissemination, availability and cross-shard traffic must be counted (ADR-005 §3.2).
- *Open because:* with verification by recomputation (H6) every full node pays the
  full delay per block of each shard it follows, and no light-client protocol exists
  for pair legitimacy, derivation proofs or work.
- *Closes with:* a verifier specification with its per-block cost, a dissemination
  cost model, and a light-client protocol with its trust assumptions.
- *K-of-K:* per height each committee member gossips a Phase-1 contribution and a
  Phase-2 signature carrying its reveal; every full node receives the block, checks
  the K signatures and replays apply. `determ-light` checks block signatures against
  the committee with a quorum floor and verifies transaction inclusion in those
  blocks (S-100).

**H20 — Incentives**
- *Decided (2026-09-24):* subsidy and fees to the pair, duties without separate pay (§6.1
  row "Incentives"). Still to specify and prove: the subsidy schedule; that cooperation
  pays under H0 given H13's suspensions and H7's reward loss; and the cost of steering a
  partition (H11). Since stalls cost only the reward, colluders can stall mixed pairs, so
  the share of heights produced by fully colluding pairs rises from f² to
  f²/(f² + (1 − f)²), about 1/5 as f approaches 1/3; a member that abstains from
  checkpoint votes counts as offline in f.
- *Question:* Why does a rational co-creator cooperate rather than withhold, grind,
  pad or censor, and who pays for availability and verification?
- *Recorded:* nothing for K=2.
- *Open because:* no fee, reward, stake or penalty rule exists for pairs.
- *Closes with:* a reward and cost model with an argument that cooperation pays under
  H0, or an owner decision that the design rests on no incentive argument.
- *K-of-K:* subsidy and fees are kept (O-4, D3), and L1 has no slashing (D4). S-011
  was narrowed on 2026-09-17: a cartel's per-round cost is the opportunity cost of
  recoverable capital plus bandwidth, so the "economic infeasibility" half is struck
  and the stake floor prices only entry. Suspending a Phase-2 withholder is decided
  (D12), not landed.

**H21 — Deployment and genesis identity**
- *Decided (2026-09-24):* deployment chosen after the proofs, and a genesis consensus
  field (§6.1 row "Deployment"). Still to specify: the field's encoding in DGC1 and its
  place in the genesis hash, with test vectors showing existing hashes unchanged.
- *Question:* Which deployments would run K=2, and how does a K=2 chain identify
  itself at genesis so it can never be taken for a K-of-K chain?
- *Recorded:* no migrations; consensus constants are fixed at genesis.
- *Open because:* no deployment split is decided and no genesis field names the
  consensus.
- *Closes with:* a deployment decision and a genesis field that leaves existing
  genesis hashes unchanged, as `crypto_profile` does by entering the hash only when
  non-default.
- *K-of-K:* the implemented protocol; the 2026-09-16 launch configuration (GLOBAL
  beacon 7/5, WEB shards 4/3, D2c) assumes it.

## 8. Compare mechanisms to produce one design (2026-09-24)

**Owner objective:** compare K-of-K and K=2 to combine their best mechanisms in one
design. The owner adopted the §8.1 recommendation as the development direction on
2026-09-24; §8.4 is its execution plan. Adoption selects the work to do, not a claim
that the composition is proved or implemented. The latest decisions in §6.1 remain
controlling; §7's proof obligations and H21's deployment gate remain. In particular,
two co-creators and joint-receipt eligibility are retained unless explicitly revised.

### 8.1 Initial synthesis

| Mechanism | Candidate contribution to the combined design | Integration condition |
|---|---|---|
| Producer endorsement | Retain K-of-K's requirement that every selected producer endorses the same content, with the currently selected two producers. This is already 2-of-2. | Bind the actual canonical body and context in receiver validation; one non-double-signing producer gives a guarantee only for the same parent, attempt and producer set in one chain/shard/height context, not checkpoint finality. |
| Commit/reveal and assembly | Retain authenticated, fixed contributions and received lists before revelation; derive a deterministic body from the decided intersection. | The precise commitment, ordering, capacity, validation and availability rules must compose (H5, H9, H14). Do not inherit the C++ post-signature body-omission defect. |
| Election and delayed randomness | Use the decided stake-weighted pair draw, fixed eligibility snapshot and VDF pipeline; retain the rule against deriving security randomness from signature-malleable block identities. | Establish the full input dependency and release-time argument under H0, including withholding, parallel trials and flooding (H2, H6–H8). A primitive's sequentiality does not prove the whole election unbiased. |
| Recovery from silence | Use K=2's selected witnesses outside the producer pair, parent-bound failure certificates and local 3B deadlines. | Prove receiver agreement on attempt authority and progress; importing K-of-K's producer-only abort quorum would halt with one silent member at K=2 (two at larger K; H3, H4). |
| History and finality | Use the latest decided longest-history/tie rules above the justified root and stake-quorum checkpoints for settlement. | Prove fork choice, voting, membership changes and replacement together (H10, H12). Neither unanimous production nor a local rollback limit substitutes for that proof. |
| Execution and persistence | Reuse the existing discipline of one receiver/apply rule set, with producers checking that same rule set; replay validated transactions and switch persisted state atomically. | Reuse reviewed semantics and primitives, not every existing implementation detail. The general recovery and crash obligations remain H17; C99 port-then-retire is unchanged. |
| Shard boundaries | Use source-checkpoint verification and ordered, exactly-once application of cross-shard transactions as decided. | Prove authentication, conservation and retry/crash behavior; local correctness alone does not establish cross-shard correctness (H18). |

This is a candidate integration of already selected rules and useful existing
principles. It does not select a configurable-K product, extra protocol modes, a new
transaction scope, a different finality system or a replacement for the chosen VDF.

### 8.2 Fair comparison and selection

1. **Fix the required properties.** No conflicting finalized histories; valid
   transactions and conserved state across shards; authorized replacement and progress
   under the stated delivery/fault assumptions; recoverable pre-finality histories;
   bounded resource use. Specify the inclusion guarantee separately from consensus
   safety, including delivery, capacity and ordering conditions.
2. **Use the same concrete environment.** Compare identical transaction scope and
   load, network and hardware, with explicit identity counts, stakes and faulty
   members. Keep faulty stake and faulty identity fractions separate: the C++ sampler
   selects identities, while H1/H2 use stake. H0 is the starting model; the mapping
   to each mechanism must be derived, not assumed.
3. **Compare one mechanism at a time, then its dependencies.** Record what property
   it supplies, its assumptions, a failure trace, its costs, and what other rules it
   depends on. First reject variants that fail a required property. Among survivors,
   compare safety assumptions, settled-transaction throughput, tail settlement and
   recovery latency, CPU, bytes, storage and worst-case certificate/replay costs.
   Count quorum and VDF work, not just the number of normal block producers.
4. **Review the composition.** Use the same withholding, partition/heal, conflicting
   candidate, unavailable-body, unequal-stake and crash/restart cases. Prove the
   unbounded claims and independently review them; finite DSF/model counterexamples
   can refute a proposal but passing runs do not prove it. Only then implement the
   smallest increment and gate it at receiver/apply through `tools/ci_local.sh`.

The clearest incompatible choice is transaction eligibility. K-of-K's union aims to
let one proper producer force a transaction's consideration; the decided K=2
intersection allows either producer to omit it from eligibility. They cannot both be
the body rule for the same attempt. Evaluate any change together with availability,
commitment timing and capacity, and record it as a proposed revision of H14 rather
than silently merging the rules. Similarly, changing producer count is an analytical
variant until authorized; changing the count alone proves no election, recovery or
finality property. New votes or thresholds are not inferred from the synthesis goal.

Two corrections apply to the earlier comparison shorthand: C++'s depth-1 reorg limit
is a local acceptance rule, not an unconditional one-block network-finality theorem;
and a bound on faulty stake does not establish a bound on faulty identity count.
See the Decision Log entry "Comparison objective: combine the best mechanisms".

### 8.3 Comparison against the controlling goals (2026-09-24)

**Scope.** The owner's latest instruction is to compare the two designs against
the goals. The implementation target is now the [freestanding C99
plan](../C99-MINIX-PORT.md): no libc, external target libraries or heap allocation;
bounded memory with explicit ownership; secret-independent cryptographic processing
under reviewed compiler/target profiles; and proof-backed protocol claims. Existing
hosted code is evidence and a reference, not a deployment candidate that already
meets that target. This assessment extends §8.1; it changes no selected protocol
rule and closes no H item.

Safety, memory/dependency conformance and the required side-channel contract are
**admission requirements**, not scores that faster performance can offset. Compare
performance and implementation complexity only within the stated security and
functional scope. In particular, use the same transfer/membership workload for both
designs; the larger C++ transaction feature set is not a fair throughput handicap
to attribute to K-of-K consensus itself.

| Goal | K-of-K reference design | Decided K=2 design | Assessment for the combined design |
|---|---|---|---|
| Proof-backed safety | Existing receiver/apply code, FA proofs and FB1 provide more implementation evidence. Same-context unanimous digest endorsement has a narrow argument; cross-round committee intersection and actual body binding remain open (S-054, Censorship §0). | Two endorsements alone do not establish network finality. H12 adds stake-quorum checkpoints; membership, voting, fork choice, replacement and VDF composition still require proofs. | Neither is qualified as a complete secure target. Reuse the scoped unanimous-endorsement argument, bind the actual canonical body/context at the receiver, and prove the complete history rules separately. |
| Strict C99, no libc or external target libraries | Current C++/hosted implementation fails this deployment requirement; the consensus rules do not inherently require C++ or POSIX. A verified port remains possible. | The C99 local experiment is already strict C99 in its configured targets, but uses hosted transport/runtime and implements a different evaluator from the selected class-group VDF. It is not the production design. | Neither current executable qualifies. Reuse independently qualified C99 primitives and canonical codec semantics; the target needs its own complete link, platform and dependency evidence. |
| No heap; bounded memory and work | K fixes the normal committee size, but current containers, mempools, registry, evidence, chain state and I/O still need bounded replacements and a persistent-state design. | Two normal producers reduce that part of the state. Witness/vote sets, previous-attempt certificates, received lists, VDF scratch, concurrent candidates and recovery history remain additional resource obligations. | Fixed pair size is not a whole-node memory bound. Both need a receiver resource contract; K=2 has more new classes of cryptographic and recovery state to bound. |
| Secret-independent crypto and small cryptographic implementation | Commit/reveal, signatures and existing primitives avoid a VDF-specific arithmetic/proof engine. This is a relative implementation-scope advantage, not whole-stack side-channel qualification. | Adds ephemeral-DH derivation and class-group VDF/proof machinery to qualify; signing and pre-reveal secret handling still need their own contracts. Public proof verification also needs bounded malformed-input cost. | K-of-K has less new cryptographic machinery. Keep the selected VDF only with its explicit H6/H8 security argument and target evidence; this comparison does not remove or replace it. Current Argon2id/libc-backed helpers qualify neither target (§9 of the crypto specification). |
| Recovery from incomplete cooperation | Producer-only abort quorum `max(2, K−1)` cannot recover at K=2 with one silent member, and has the recorded two-silent-member problem at larger K (H3, S-076). | Failure witnesses outside the pair can authorize a new pair under the selected two-thirds-stake rule and 3B local deadline; completion of its safety/liveness argument is pending. | Retain the decided external witness recovery mechanism for the pair. Importing the old abort threshold unchanged would defeat the selected recovery goal. |
| Transaction eligibility and inclusion | The union aims to preserve consideration of a transaction contributed by one proper member. The shipped post-signature body-omission gap prevents claiming that inclusion guarantee today. | The decided intersection admits only jointly received transactions; either member can omit one. Delay/censorship bounds need actual sampling, delivery, validity, capacity and stall assumptions (H14). | Preserve the selected joint-receipt rule. The union's one-member inclusion property is not inherited; it remains the explicit tradeoff identified in §8.2. |
| Normal production cost and settlement cost | Normal producer exchanges and signatures scale with K; no selected VDF or separate checkpoint voting layer. The local depth-1 reorg limit is not unconditional network finality. | Two normal producers, plus DH/VDF verification, certificates on stalls and shard-wide checkpoint votes. Settlement waits for covering finality, whose latency remains to be derived under H12. | K=2 reduces normal producer participation when K > 2. No measured advantage in settled throughput, tail latency, total bytes, energy or verifier cost follows. Include all auxiliary work and recovery. |
| Sharding and crash recovery | Existing beacon/EXTENDED and atomic local reorg work offer reference code, with S-064/S-096 and snapshot/recovery residuals. | Source-finalized cross-shard transactions, sequence ordering, snapshot/replay and durable head switching are selected directions (H16–H18), not implemented end-to-end guarantees. | Reuse validated receiver/apply semantics and atomic publication discipline; prove the new cross-shard and persistence composition. Two producers and a VDF do not justify deleting topology or availability checks. |
| Minimalism and reusable evidence | More existing functionality and evidence; fewer new cryptographic constructions, but substantial hosted code and protocol defects remain. | Smaller normal producer set and narrower transaction scope, with more newly specified election, timing, quorum, finality and recovery mechanisms. | Reuse sound mechanisms at their actual scope. Fewer producers is not sufficient evidence of a simpler whole protocol; fewer implemented prototype features is not a security advantage. |

**Resource accounting before benchmarks.** Let K be the baseline's selected
producer count; N the K=2 shard's eligible identity count; A the number of earlier
attempts certified by an accepted block; q_a the distinct signers in the certificate
for earlier attempt a; q_F the signers in a checkpoint link; and E the checkpoint
interval. These are accounting variables, not newly selected protocol limits.

- The baseline's normal block includes K producer endorsements plus its Phase-1
  authentication, transaction verification and apply work. The pair design includes
  two producer endorsements plus contribution authentication, DH derivation, VDF
  proof verification, transaction verification and apply work. Counting only K
  versus 2 omits required work in both cases.
- H3/H19 carry plain Ed25519 failure-certificate lists for all earlier attempts.
  Their signature count is `sum(q_a, a = 0 .. A−1)`; if a certificate needs up to N
  distinct signers, this contribution can grow as A·N. Two-thirds **stake** does not
  imply a certificate of two-thirds the number of identities. Canonical membership,
  duplicate rejection, encoded-size limits and verifier work must be specified.
- With a plain-signature representation, checkpoint voting contributes q_F
  signatures per successful link; its concrete proof encoding remains H12/H19 work.
  Roughly q_F/E per height is an amortized
  accounting term only with the assumed successful link cadence; it omits extra
  links, retries, dissemination and stalled-finality behavior. It is not a peak
  memory/CPU bound or a finality-latency theorem.
- H16/H17 require bodies and durable signing/recovery records relative to the last
  finalized checkpoint. E alone does not bound the unfinalized suffix when finality
  stalls. Define bounded-RAM access to persistent state, snapshots and replay,
  candidate retention, resource exhaustion and crash points. Silently rejecting an
  otherwise valid history to fit a local arena is not a proof of protocol liveness.
- The selected class-group construction needs concrete parameter sizes, evaluation
  and proof-generation scratch, verification work and pipeline/concurrency budgets.
  The existing AES/SHA repeated-work timing is not a benchmark of that construction.
  No network-wide O(1) or throughput multiplier is inferred from these counts.

**Sampling and fault-model fairness.** Hold the actual identities, stake vector,
faulty identities and network schedule fixed when comparing selection. C++ selects
identities; H2 selects two distinct identities by stake. A stake fraction alone does
not give the former's faulty-committee probability. Nor is `(1−f)^2` an exact
proper-pair probability for unequal stakes sampled without replacement. For the
idealized sequential proportional draw with at least two positive-weight eligible
members, if W is total stake, P is the proper set,
W_P its total stake and w_i one member's stake, the probability is
`sum((w_i/W) * ((W_P−w_i)/(W−w_i)), i in P)`: condition on the first draw and then
remove that identity's stake for the second. This is a one-draw accounting identity,
not a proof of H2's real sampler or an independent-retry/inclusion guarantee.
The earlier H14 `1/(1−f)^2` illustration must not be used as a demonstrated latency
or as an exact general bound. Capacity, resubmission, adversarial bias, flooding and
correlated retries require their own argument. No stake cap or different sampler
is selected by this clarification.

**Result for synthesis.** The currently justified direction is the §8.1 composition:
two co-creators endorsing the same receiver-validated canonical body/context;
commit-before-reveal and the selected joint receipt; signature-independent election
inputs; the decided external recovery witnesses and checkpoint settlement; and
reused validation/apply, canonical serialization and durable-publication principles.
Qualified primitives and bounded C99 ingestion/storage facilities are common to
either consensus design. Existing implementation defects, producer-only K=2 aborts,
the union's incompatible inclusion claim and unqualified runtime/crypto code are
not inherited into that target.

There is no proved or benchmarked whole-design winner. K-of-K currently offers
more reusable implementation evidence and a smaller cryptographic scope; K=2
offers fewer normal producers and explicitly selected recovery/finality mechanisms,
at the cost of additional protocol, arithmetic and state-management obligations.
The next discriminating design artifact is a receiver/resource specification
covering normal blocks, stalls, checkpoint delays and crash recovery, paired with
the H2/H6/H8/H12 proofs. Only after that gate is meaningful should equivalent
implementations be benchmarked for settled throughput, p95/p99 settlement and
recovery latency, peak RAM/stack, persistent I/O, CPU/energy and bytes under matched
loads and adversarial schedules. This assessment initially changed no work order;
the subsequent owner instruction adopts the development sequence in §8.4. Neither
the comparison nor that adoption authorizes deployment.

### 8.4 Adopted development plan (2026-09-24)

**Selected direction:** two co-creators unanimously endorse one canonical,
receiver-validated body and context. Reuse sound K-of-K validation, canonical
encoding and persistence principles; use the already decided K=2 joint receipt,
stake-weighted election/VDF pipeline, external failure witnesses, local 3B timeout
and checkpoint settlement. The joint-receipt rule does not acquire the union's
one-proper-producer inclusion guarantee. Every reused mechanism still needs review
against its known defects, the composed protocol and the freestanding target.

The implementation target is strict freestanding C99 with no libc, external target
runtime libraries or heap; bounded storage, explicit ownership and qualified
secret-independent cryptographic processing are mandatory. Existing hosted C++ and
C99 executables remain references or experiments. Neither is a qualified target.
No new producer count, quorum, VDF, KDF, transaction scope or checkpoint encoding is
selected by this plan. H0 remains CLOSED as a stated model; H1–H21 remain DECIDED
with their proofs owed. Performance does not compensate for a failed security or
resource requirement.

| Order | Deliverable | Required evidence before advancing |
|---|---|---|
| 0. Preserve and commit the reviewed starting point | Inventory the existing staged restoration, unstaged documentation/foundation work and untracked files; make coherent, explicitly scoped local commits. | Review the exact contents of each commit, independently review consensus/apply/wire/model changes, and pass the applicable `ci_local.sh` checks for that snapshot. Preserve unrelated work. The Claude instructions are in C99-MINIX-PORT §12. |
| 1. Specify one-shard receiver and resource contracts | Extend this ADR and the existing C99 plan with the first deliverable below. | Explicit predicates, ownership and failure transitions; byte/work/storage accounting; proofs or precise counterexamples; independent adversarial review and a dependency map to §7. No production acceptance rule depending on an unresolved contract is implemented. |
| 2. Build the smallest proved surviving component | Choose a real receiver/apply/codec or qualified primitive boundary from the reviewed contract, with a concrete caller and a falsifiable property. | Design proof and independent review, then implementation and receiver/apply-level positive, negative and mutant gates through `ci_local.sh`; fresh successful builds precede mutant results. Parity covers unchanged reference behavior; an authorized changed rule uses its reviewed specification and vectors. Do not port obsolete consensus solely to delete it. Repeat this step in separate increments. |
| 3. Establish composed single-shard behavior | Integrate election, signed body/context, replacement, fork choice, checkpoint voting/membership and durable recovery. | Close each applicable H obligation with reviewed arguments and implementation evidence. Exercise withholding, selective release, partitions/healing, competing candidates, unequal stakes, unavailable bodies, exhaustion and crashes. Finite DSF/TLC checks supplement, not replace, the unbounded arguments. |
| 4. Add sharding after its premises hold | Follow ADR-005 for fixed topology, shard-local eligibility, source-checkpoint authentication and ordered exactly-once cross-shard application. | H18 and the applicable membership/availability/resource obligations, plus receiver/apply/crash evidence. Single-shard safety alone does not establish cross-shard conservation or settlement. Production sharding and beacon retirement are not approved by this plan. |
| 5. Qualify the target and compare measured costs | Assemble the real MicroVM image; qualify each compiler/ISA/platform profile and benchmark equivalent workloads with complete protocol costs. | Final link/dependency and memory/ownership evidence, crypto artifact and leakage evidence within explicit assumptions, persistence/boot tests, settled throughput and tail settlement/recovery costs. H21 remains a separate deployment decision. Platform and primitive evidence may be developed earlier where independently useful. |

**First development deliverable — receiver/state/resource contract.** Keep it in
this ADR and C99-MINIX-PORT, with formal arguments linked from the existing proof
record as needed. Describe the following before choosing a production wire layout:

1. The canonical body and full chain/shard/height/parent/attempt/producer context
   that both endorsements bind; commitment/reveal dependencies, joint receipt,
   ordering and availability; and the exact receiver predicates. Document which
   acceptance and inclusion properties each predicate supplies (H5, H9, H14, H19).
2. Verification and state transitions for eligibility, public DH/VDF evidence,
   prior-attempt failure certificates, checkpoint votes and membership snapshots.
   Map every input to its authentication, replay scope and persistence lifetime;
   distinguish tentative validation from authoritative state publication
   (H1–H8, H10–H13, H15–H17, H19–H20).
3. For each received/retained object, account for encoded bytes, counts, worst-case
   verification work, RAM/stack scratch, durable storage, ownership and lifetime.
   Include concurrent candidates, retransmissions, invalid input and crash replay.
   Distinguish consensus validity limits from local queue/storage exhaustion;
   dropping work safely does not establish eventual progress.
4. Resolve the resource composition first: H3/H19 require certificates for every
   earlier attempt, so the signature count grows as `sum(q_a)` over those attempts.
   Checkpoint spacing E does not bound the unfinalized suffix when finality stalls.
   Demonstrate how bounded RAM and persistent/streaming processing compose with
   canonical framing, verification work, storage exhaustion and the required
   safety/liveness properties. Streaming alone does not bound total bytes, work
   or disk use. If the selected rules cannot satisfy the required budgets, record
   the precise incompatibility and alternatives requiring an owner decision. Do
   not silently cap attempts, discard required certificates or claim progress
   after local exhaustion.
5. State assumptions and required proofs for each transition, an adversarial trace
   that would falsify it, and the receiver/apply/model gate that exercises it.
   Record proved, refuted and pending items separately. A counterexample is a valid
   design result; a green finite model is not completion of a general proof.

**Work selection and retirement.** This combined-design specification/proof track
is the next development task, superseding the older work order only for this track.
The reference safety backlog remains valid and open; its unfixed behavior is not
inherited as a proved property. Retain the hosted K-of-K reference while replacements
are qualified under C99-MINIX-PORT §0. Retirement remains a separate reviewed commit.
Do not promote the teaching QF frame, bounded recovery model or repeated-work
evaluator into production consensus by renaming it. Sharding, integration and
deployment remain conditional on their own proofs and acceptance decisions.
