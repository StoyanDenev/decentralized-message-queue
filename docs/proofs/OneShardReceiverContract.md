> **TIER: FUTURE — design specification for the adopted combined design; nothing here is shipped consensus.** Roadmap index: [ROADMAP.md](../ROADMAP.md)

# OneShardReceiverContract — resource composition of the adopted combined design

**Status:** FB76. Hand proofs and counterexamples for the first deliverable of
[ADR-004 §8.4](../decisions/ADR-004-Fault-Model.md#84-adopted-development-plan-2026-09-24),
item 4 first: whether bounded memory, streaming and persistence compose with the recorded
rules for failure certificates and checkpoint finality. The contract is
[ADR-004 §9](../decisions/ADR-004-Fault-Model.md#9-one-shard-receiver-state-and-resource-contract-2026-09-24).
Proved here: Lemma Q (streaming stake-quorum verification), Lemma P (a predecessor
certificate implies all earlier ones, under stated premises) and the counterexamples U1–U3
with Corollary U4. These are proofs about the proposed design, not about shipped behavior.
None of it changes a recorded decision; §6 lists alternatives that need an owner decision,
and §8 separates proved, sketched and open items. Two rounds of independent design review
on 2026-09-24 found blocking errors in the earlier drafts; this text addresses them. Each
item is accepted only after independent review (ADR-004 §7.1), and a bounded model check
could only refute it.

## 1. Model and notation

One shard, under H0 (ADR-004 §6.1, "Common model"). Recorded rules used: H1 (stake-weighted
quorums), H2 (pairs drawn from an eligibility snapshot fixed by state no later than
h − d − 1), H3 as last decided (failure statements, a certificate of at least two thirds of
the stake, parent binding, carried certificates, and the certificate criterion that fork
choice applies at equal length), H4 (attempt start rule), H12 (checkpoints), H13 (signing
records), H16 (availability and retention), H17 (snapshot and replay) and H19 (plain
Ed25519 failure certificates).

- G is the chain identity (genesis hash); h ≥ 1 a height; a ≥ 0 an attempt; P the parent,
  the block at height h − 1 on the branch considered.
- S = (m_0, …, m_{N−1}) is the eligibility snapshot that weights certificates at (h, P).
  Member i has public key k_i and stake w_i ≥ 1, and W = Σ w_i. The proofs assume
  1 ≤ W ≤ 2^64 − 1. That precondition must be discharged by the amount encoding and a
  supply bound (H15, H20, both open); if they do not discharge it, a bound on W is a limit
  for the owner to decide, not something a receiver may impose. Which snapshot this is,
  and the order of its members, are open (§6, D6).
- A set X of members is a **quorum** of S when 3·w(X) ≥ 2·W. This reads "at least two
  thirds of the stake" (H1, H3, H12) as a non-strict inequality. Over the integers it is
  w(X) ≥ τ(W) with τ(W) = W − ⌊W/3⌋: writing W = 3k + r with r ∈ {0, 1, 2},
  ⌈2W/3⌉ = 2k + r = W − ⌊W/3⌋. τ is computed without overflow.
- Two quorums X and Y of S satisfy w(X ∩ Y) ≥ 2τ(W) − W = W − 2⌊W/3⌋ ≥ W/3. If the
  faulty stake of S is below W/3, X ∩ Y contains an honest member.
- M(h, a, P) is the byte string a member signs to state that attempt a at (h, P) failed.
  Its canonical encoding is open (§6, D5). The proofs need only that it is injective in
  (G, shard, h, a, P) and domain-separated from every other message a member signs
  (headers, votes, transactions), so that no signature has two meanings.
- Verify(k, M, σ) is one fixed, deterministic Ed25519 verification predicate shared by
  every receiver. Ed25519 variants disagree on some adversarial inputs (cofactored versus
  cofactorless checks, non-canonical encodings), so consensus must name one. The C99
  library's strict check (canonical S and canonical public-key encoding, per its header)
  is the candidate. Its group equation and the other encodings it rejects must be written
  down (H19, open). EUF-CMA says nothing about small-order public keys, so admission must
  keep such keys out of every snapshot (the analogue of S-068; H1 and H15, open).
- A **certificate entry list** is E = ((i_1, σ_1), …, (i_q, σ_q)).

E is **canonical** for (S, M) when:

- (C1) 0 ≤ i_1 < i_2 < … < i_q ≤ N − 1;
- (C2) Verify(k_{i_j}, M, σ_j) = 1 for every j;
- (C3) Σ_j w_{i_j} ≥ τ(W).

(C1) is a proposed canonical order (§6, D5), not a new limit. It fixes one entry order
per signer set, so duplicate signers cannot occur. Any wire encoding that presents the
entries in snapshot-index order satisfies it, for example a sorted list or a signer bitmap
followed by the signatures in bit order. An encoding that allows arbitrary order would
need O(N) duplicate state and a different verifier. Encoding indices in 32 bits requires
N ≤ 2^32 − 1, a population limit that D7 must accept.

## 2. Lemma Q — streaming stake-quorum verification

The verifier keeps (next, sum, state), starting from (0, 0, OPEN), and processes one entry
at a time:

- absorb(i, σ): if state ≠ OPEN, refuse. If i < next or i ≥ N, set state = REJECTED
  (order or range). Otherwise, if Verify(k_i, M, σ) = 0, set state = REJECTED
  (signature). Otherwise sum ← sum + w_i and next ← i + 1.
- finish(): ACCEPT exactly when state = OPEN and sum ≥ τ(W); otherwise REJECT. After
  finish the state is terminal.

**Q1 (exactness).** finish() returns ACCEPT after absorbing E if and only if E is
canonical for (S, M).

*Proof.* (⇒) Each absorb that succeeded had i_j ≥ next = i_{j−1} + 1 (next = 0 for j = 1)
and i_j ≤ N − 1, which is (C1). Its signature check passed, which is (C2). No absorb
rejected, so sum = Σ_j w_{i_j} ≥ τ(W), which is (C3). (⇐) For canonical E, by induction
on j every absorb sees state = OPEN and next = i_{j−1} + 1 ≤ i_j ≤ N − 1 by (C1), and
passes the signature check by (C2); afterwards sum = Σ_j w_{i_j}, and (C3) gives ACCEPT. ∎

**Q2 (distinct signers).** In an accepted E the map j ↦ i_j is injective (C1), so the
signer set has exactly q members and stake sum.

**Q3 (no overflow).** Before absorbing (i, σ) with i ≥ next, sum is the stake of distinct
members with indices below i, so sum + w_i ≤ W ≤ 2^64 − 1. With 32-bit indices,
next = i + 1 ≤ N ≤ 2^32 − 1 does not overflow either.

**Q4 (resources).** The state is three words, independent of q and N. Each absorb costs at
most one Verify, one snapshot lookup by index and O(1) arithmetic. E is never buffered. A
rejected E costs at most one Verify per entry up to and including the rejected one; an
order or range violation is rejected before its signature is checked.

**Q5 (chunk invariance).** The verdict depends only on the sequence of absorbed entries,
since the state carries everything between calls. Any split of E across calls gives the
same verdict.

**Q6 (terminal states).** After a rejection, every further absorb is refused and finish
repeats the stored verdict, so a rejected certificate cannot be resumed. The
implementation also treats an absorb after an accepting finish as a rejection. A caller
that finished before the last entry of the framing is therefore told so if it offers
another entry, but not if it stops reading, which is why finish must follow the last
entry.

Q1 is a statement about whole lists and one unchanged snapshot. The implementation
compares 3·sum with 2·W exactly, as 128-bit values built from shifts and additions, and
copies the snapshot's fields at begin. The key and stake arrays must not change between
the snapshot's validation and the last finish that uses them. A caller must call finish
only after the last entry of the certificate's framing. A receiver that stopped once the
quorum was met would accept a valid prefix followed by a bad entry that another receiver
rejects, and receivers would diverge.

Q1–Q6 are the contract of the C99 component of ADR-004 §9.7 (C99-MINIX-PORT §13). They
say nothing about which statement bytes or snapshot a receiver must use; those are the
caller's obligations (D5, D6).

## 3. Lemma P — a predecessor certificate implies all earlier certificates

Fix (G, shard, h, P) and the snapshot S used at (h, P). Assume:

- **(P-a)** Honest members follow H3 and H4 as recorded. An honest member signs M(h, a, P)
  only after its local deadline for attempt a at (h, P) has passed, and its attempt a ≥ 1
  at (h, P) starts only after it has received a canonical certificate for (h, a − 1, P)
  under S. This must hold across restarts (§7, K4).
- **(P-b)** F < τ(W), where F is the stake of the members of S whose signing keys the
  adversary controls. This follows from H0(1) only if H0(1) is read against the snapshot
  in use. Read against the current population, it does not. For example, let S have
  W = 100. After S is fixed, 110 honest stake joins; during a stall the adversary corrupts
  69 of S's stake. That is below a third of the current 210, so H0(1) holds, but it is at
  least τ(100) = 67, so the adversary can certify any attempt at (h, P) under either
  carriage rule. Exits are a second route: H0(4) lets the adversary acquire former
  members' keys and bounds that damage through finality and unbonding, not through f. So
  (P-b) is an added premise whenever stake or membership has changed since S was fixed.
  D6 must name a snapshot that H0(1) covers, or the owner must clarify H0(1). The same
  premise underlies every snapshot-weighted quorum, including H12's links, whether or not
  D1 is adopted.
- **(P-c)** Verify is EUF-CMA secure for every key in S (H0(8), with small-order keys
  excluded as in §1).
- **(P-d)** Every honest member judges certificates at (h, P) under the same S, one
  determined by P's branch (D6).

**Lemma P.** If a canonical certificate C_a for (h, a, P) under S exists with a ≥ 1, then
for every a' < a a canonical certificate for (h, a', P) under S existed and had been
received by an honest member before that member started attempt a' + 1.

*Proof.* The signers of C_a hold w(C_a) ≥ τ(W) > F, so at least one signer j is honest. By
(P-c), j itself signed M(h, a, P), except with negligible probability. By (P-a), j's
attempt a at (h, P) had started, so j had received a canonical certificate C_{a−1} for
(h, a − 1, P) under S, and by (P-d) that is the certificate every honest member would
accept. If a − 1 ≥ 1, apply the same argument to C_{a−1}. Induction on a reaches a' = 0. ∎

The proof uses no timing assumption, and parent binding keeps certificates for another
parent out. Lemma P does not claim that any particular node holds or can fetch the earlier
certificates, only that they existed.

**Corollary P1 (authorization).** Under (P-a)–(P-d), presenting a canonical certificate for
(h, a − 1, P) implies that canonical certificates for every (h, a', P) with a' < a exist.
H3's requirement that attempt a be authorized by certificates for every earlier attempt is
then implied by the predecessor certificate alone. The authorization rests on honest
members' attempt state rather than on carried signatures, which is why K4 is needed.

**Corollary P2 (fork choice).** Take the proposed receiver predicate **(X1)**: a block of
attempt a carries exactly the certificates for attempts 0, …, a − 1, bound to its parent
(under D1: exactly the certificate for attempt a − 1). Let X and Y be valid blocks at a fork
point, with the same height h and parent P and attempts a_X ≠ a_Y.

- Under the recorded all-certificates rule with (X1), the certificate criterion ("carrying
  failure certificates, bound to their common parent, that cover the other block's
  attempt") holds for X exactly when a_X > a_Y.
- Without (X1) the only-if direction fails. The record says only that a block carries the
  certificates for every earlier attempt. A colluding attempt-a_X pair with a_X < a_Y can
  withhold X until C_{a_Y} forms and then carry it, so X and Y cover each other and the
  criterion decides nothing.
- Under D1 the recorded criterion wording no longer applies, because X at attempt 2
  carries only C_1, which does not cover Y at attempt 0. D1 must therefore restate the
  criterion as "the fork-point block with the higher attempt index wins". By P1 this picks
  the same block as the recorded rule with (X1) whenever (P-a)–(P-d) hold. ∎

When a_X = a_Y the criterion does not apply, and count and then header decide, as
recorded.

## 4. Theorems U1–U3 and Corollary U4 — what the recorded rules do not bound

**U1 (carried certificate evidence).** Under H0 and the recorded H3, H4 and H19, for every
bound X there is an H0-admissible execution in which a valid block carries more than X
certificate entries.

*Construction.* Let every member be honest (F = 0 is admissible). At (h, P) the network
scheduler holds every message of the pair of each attempt a < A until after every node's
attempt-a deadline, and delivers failure statements promptly. H0(2) claims progress and
replacement only during synchrony and bounds no asynchronous period. Each node's attempt-a
deadline passes without a completed result, every member signs M(h, a, P), a canonical
certificate C_a with q_a ≥ 1 entries forms, and nodes start attempt a + 1 (H4). At attempt
A the scheduler delivers the pair's messages. Under the recorded rule the attempt-A block
is valid only if it carries C_0, …, C_{A−1}: Σ q_a ≥ A entries and at least 64·A signature
bytes. Take A = X + 1. The asynchronous period lasts about A·3B plus delivery times. ∎

Under D1 the same execution yields one carried certificate. Even within synchrony, stalls
come from pairs that contain a faulty or flooded member; U3 shows that the recorded
assumptions give no bound on how many there are in a row.

**U2 (unfinalized suffix).** Under H0, H12, H13 and H16, for every L there is an admissible
execution in which the latest finalized checkpoint lags the tip by more than L heights.
Meanwhile every node must retain full bodies back to d heights below that checkpoint
(H16), its signing records above it (H13), and what H17 needs to replay from a snapshot at
or below any fork point above it.

*Construction.* During asynchrony the scheduler delivers each pair's messages before its
deadline, so blocks complete at attempt 0, and holds every checkpoint vote. No link gathers
two thirds of the stake at any node, so neither justification nor finality advances, while
the chain grows by one height per completed block. No recorded rule stops production when
finality lags. ∎ The same growth occurs outside H0 whenever members holding more than
W − τ(W) of the stake stop voting.

**U3 (no a-priori stall bound).** Under H0, H1 and H2 as recorded, the probability p that a
drawn pair has no faulty or flooded member can be arbitrarily close to 0, and is 0 when one
identity holds all proper stake. H0 bounds the faulty stake, not how proper stake is spread
across identities, and H2 draws two distinct identities.

*Example.* Let faulty stake be 0.3W, one proper identity hold 0.7W − ε and another hold ε.
By ADR-004 §8.3's one-draw identity, in units of W,
p = (0.7 − ε)·ε/(0.3 + ε) + ε·(0.7 − ε)/(1 − ε), which tends to 0 with ε (p ≈ 0.029 at
ε = 0.01). So during synchrony no attempt bound follows from the recorded assumptions, not
even one at H0(13)'s 2⁻⁴⁰ target. H0(10)'s liveness condition uses (1 − f)², which §8.3
already notes is not this probability for unequal stakes. ∎

**Corollary U4 (fixed local budgets).** Let a node have fixed budgets for message size,
durable bytes and verification work per block. By U1 and U2 there are admissible
executions in which a valid block, or the unfinalized history the node must retain,
exceeds every such budget. So no node with fixed budgets can both accept every valid
history of the recorded design and stay within them. ∎

What such a node should do is a design choice. ADR-004 §9.1 proposes local capacity
refusal: the node does not hold the object (H16), so the block does not count toward its
history, and it does not extend, endorse or vote above the block or record it as invalid.

The consequences depend on how much stake refuses. Let an oversized completed block X at
(h, a) on parent P be refused by honest members holding stake R. Refusers never hold X,
so they start no attempts above it and sign nothing there. Two conditions matter, and the
adversary controls them independently through two faulty stakes: F', which withholds
above X, and F_s, which signs M(h, a, P).

- **(i) Above X.** A quorum there needs τ(W) of the stake among nodes that hold X. If
  R + F' > W − τ(W), X's branch can neither certify a stall nor finalize without the
  refusers, so it halts at its first stall above X.
- **(ii) At (h, a).** If the refusers sign M(h, a, P) and R + F_s ≥ τ(W), X can be
  certified as failed and replaced by a later attempt X'. When carried certificates caused
  the refusal, X' is larger still (U1); when the body caused it, X' may fit.

When neither condition holds, the chain continues on X and the refusers are effectively
offline for it. When (ii) holds, the refusers cannot adopt X's branch. Nodes holding X
switch only once the replacement branch is at least as long, since at equal length the
higher attempt wins (P2 with (X1)). Otherwise the split persists until one side finalizes,
which needs τ(W) of the stake on that side.

R, F', F_s and W are read in the weighting snapshot of each quorum, which D6 leaves open
and which can differ above X. The analysis assumes X reached every honest node. With
partial delivery, honest nodes that did not receive X also sign, which is H3's ordinary
late-result case, not a refusal effect.

Whether a refusing node signs H3's failure statement is open. H3 lets a member sign when
it "has not received a completed attempt-a result", and H16 speaks of blocks a node
cannot obtain in full. Whether H0's f counts a refusing node as offline would be a
clarification of the closed H0. Because U1 and U2 affect every node alike, the scheduler
can push every honest node into refusal. Refusal does not weaken H12's pending safety
argument, but no liveness is claimed once condition (i) or (ii) holds.

## 5. What bounded working memory can achieve

- **R1 (proved, Lemma Q).** Certificate verification needs O(1) state per certificate,
  whatever q and A are. The snapshot is read through an index lookup that can be backed by
  persistent storage. Checkpoint links can use the same verifier if H12's encoding is a
  plain-signature list in snapshot-index order (open).
- **R2 (design claim, not proved).** A block can be ingested as a stream into durable
  staging and verified in one pass. Working memory is then bounded by the largest
  indivisible item (a transaction, a certificate entry, a VDF group element) plus hash and
  accumulator states. This needs an encoding whose checks use only data already seen or
  committed earlier:
  - certificates bound to (h, a, P) can be checked before the body;
  - H14's body rule needs the parent state, on disk, and both committed received-lists;
    with both lists ordered canonically, for example by transaction data hash, the
    intersection is a linear merge in O(1) memory (proposed; H14's order is open);
  - Ed25519 over a long message must hash it as a stream. The hosted C99 verifier
    allocates for messages over 448 bytes, which the freestanding target cannot do.
- **R3 (design claim, not proved).** H17's replay can run block by block from a snapshot,
  with the state on disk and one block's streaming state in memory.
- **Open:** fork-choice computation over held candidates, aggregation of failure
  statements and votes, and surround-vote detection. Each needs its own memory argument.

So working memory can plausibly be bounded independently of A and of the suffix length L.
Durable bytes, total verification work and bandwidth cannot, because of U1 and U2.

## 6. Alternatives that need an owner decision

- **D1 — carry only the predecessor certificate** (resolves U1).
  - Rule change: replace H3's "carries the certificates for every earlier attempt at its
    height" with "carries exactly the certificate for the immediately preceding attempt"
    ((X1) under D1).
  - Criterion change: restate §6.1's certificate criterion as "the fork-point block with
    the higher attempt index wins" (P2).
  - Effect: authorization and fork choice are unchanged under (P-a)–(P-d), K4 and (X1). A
    block's certificate evidence is at most one canonical certificate, of at most N
    entries.
  - Also changed: H19's light-client check becomes one certificate per stalled height.
  - Unchanged: H8's margin k, H13's predicate and H18's proofs, beyond certificate count,
    because a certificate is not an input to the draw (H3). Nodes still receive and verify
    one certificate per failed attempt, at a rate limited by the 3B deadlines, and keep
    only the latest one per (h, P).
- **D2 — a stake-distribution assumption or a sampler change** (resolves U3).
  - Proposal: add an explicit H0 term giving a lower bound p_min on the probability that a
    drawn pair contains no faulty member, for example from a cap on any one identity's
    share of the stake.
  - Sketch, not a bound: if stalls came only from faulty members, the draws were
    independent (H0(8)'s random-oracle seed), and every fully proper pair completed within
    its 3B deadline during synchrony (an open H4 obligation), then
    P(at least a stalls at a height) ≤ (1 − p_min)^a. H0(13)'s target would then give
    A_max = ⌈(40 + log₂ 10⁸) / (−log₂(1 − p_min))⌉ (for example 69 at p_min = 0.49).
  - Why it is only a sketch:
    - Flooding is not independent: pairs are known in advance, so the adversary can
      flood exactly the proper ones (b per T).
    - H0(3) needs a pair's known-to-finished time below τ, which itself presupposes an
      attempt bound.
    - Draw bias is open (H2, H8).
    - H0(11) asks for the bound as a function of f, b and T.
  - Liveness needs some such assumption or sampler change either way. Per-block bounds
    under D1 do not.
- **D3 — growth of the unfinalized suffix** (resolves U2). One of:
  - (a) an H0 provisioning assumption that finality lags the tip by at most L_max heights;
  - (b) finality-gated production: a block at height h is valid only if h ≤ F + L_max,
    for the latest checkpoint F finalized by votes carried on its own branch. This needs
    on-chain votes (the H12/H19 encoding). It also meets a deadlock under U2's own
    schedule. Once a branch reaches F + L_max with no votes carried, no further block is
    valid, so no block can carry the missing votes, even after synchrony returns. So (b)
    needs vote-only extension or a proof that the deadlock cannot occur. Because Casper
    finalization needs the child checkpoint's link, L_max must be at least 2E plus the
    vote-inclusion delay;
  - (c) accepting the growth, with monitoring and U4's refusal, and no liveness claim
    after long asynchrony.

  State synchronization from a finalized checkpoint bounds catch-up work for lagging nodes
  but not the storage voters need.
- **D4 — the K=2 block cap and the received lists.** H0(5) and H14 refer to "the block
  cap", which has no value in the K=2 record. D9, the K-of-K block-byte cap, is a separate
  decision (decided 2026-09-16, not landed). Each committed received-list (H5, H14) is
  unbounded unless capped or given a streamable proof structure. Any per-block byte or work
  bound needs both.
- **D5 — canonical statement and certificate encoding** (needed under every alternative).
  Proposed: M(h, a, P) = domain tag ‖ G ‖ shard ‖ h ‖ a ‖ P in fixed-width big-endian,
  certificate entries in snapshot-index order (C1), and 32-bit snapshot indices. Lemma Q,
  and the component that implements it, apply to every encoding that presents entries in
  that order.
- **D6 — the snapshot that weights a failure certificate.** The record says "two thirds of
  the population" (§6.1 Replacement row) and "two thirds of the shard's stake" (Membership
  row); the superseded H3 text said "two thirds of current stake". It names no snapshot.
  Proposed: the snapshot that H2 uses to draw height h's pairs on the branch through P, so
  that (P-d) holds. Under the current-population reading of H0(1), that snapshot is
  covered only if stake and membership have not changed since it was fixed (P-b). D6
  must name a covered snapshot, or the owner must clarify H0(1).
- **D7 — the population bound.** Nothing bounds N. H1 sets only an open minimum, and
  ADR-005 §3.2 records that "'Large' is a qualitative requirement; a numerical minimum and
  reserve margin have not been selected". Under D1 a block still carries up to N entries;
  snapshots, draw verification and state are O(N). Either N_max follows from the stake
  floor and the supply (both open), or every budget is written as a function of N. By
  analogy with ADR-005 §3.2's rule that production limits derive from bounded memory and
  membership, not field width, D7 also covers the 2^32 − 1 index width that D5 proposes.
- **D8 — branching, retention and parent tracking.** The record does not say which
  parents an honest member runs attempts for, or how many candidates above the latest
  finalized checkpoint a node keeps. Any retention policy needs a proof that it never
  drops the fork-choice winner.

## 7. Crash-consistency obligations

- **K1** A member records (h, a, P), or a vote's (source, target), durably before
  releasing the header signature or vote (H12, H13). A crash between the record and the
  release is safe.
- **K2** A received object becomes held (H16) only after it has been verified and durably
  published. Staging is discarded on restart.
- **K3** H17's head switch writes and syncs the new state before the head moves in one
  durable step. The target's storage contract must provide such a step.
- **K4** After a restart a member's attempt at (h, P) is 0 unless it holds a canonical
  certificate for (h, a − 1, P). It never signs M(h, a, P) for an attempt it has not
  started. This is Lemma P's premise (P-a).
- **K5** Pruning after a durable new finalized checkpoint removes only data older than d
  heights below it (H16). It keeps the state snapshot that H17 needs, every eligibility
  snapshot and VDF output needed to validate blocks above it, and the voter-set snapshots
  of unfinalized links. Pruning is idempotent.
- **K6** A member that received a completed attempt-a result before its deadline must not
  sign M(h, a, P) after a restart that lost it. Otherwise H3's timely-result guarantee
  weakens. Either received results are held durably before the deadline, or a restarted
  member abstains for attempts whose deadline passed while it was down. Which one is open.

These are specification obligations. Only K2's pattern has an implementation to date: the
hosted C99 block store's fsync-then-rename manifest.

## 8. Status

- **Proved here, pending independent review:**
  - Q1–Q6. The code review of the implementation also checked Lemma Q in both
    directions.
  - Lemma P and P1, under (P-a)–(P-d).
  - P2, under (X1).
  - U1, U2 and U3 (counterexamples), and U4.
- **Sketched, not proved:** R2, R3 and D2's attempt bound.
- **Implemented as a qualified primitive:** Lemma Q, as the freestanding C99 component
  `stake_quorum` (ADR-004 §9.7, C99-MINIX-PORT §13). It has no production caller until D5
  and D6 (and H12's encoding, for links) are decided.
- **Open:**
  - D1–D8 await owner decisions, and so do the refusal choices in §4.
  - (X1) and the (P-b) discharge.
  - K1–K6 have no combined-design implementation or tests.
  - The Ed25519 variant and admission of small-order keys.
  - The H proofs in ADR-004 §7.3, including H12's accountable safety.
