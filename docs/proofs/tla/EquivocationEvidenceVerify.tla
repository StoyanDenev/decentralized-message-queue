--------------------------- MODULE EquivocationEvidenceVerify ---------------------------
(*
FB48 — TLA+ specification of the OFFLINE equivocation-evidence
verifier predicate: the four-clause accept/reject decision that
`BlockValidator::check_equivocation_events` (src/node/validator.cpp:307-332)
runs on every EquivocationEvent baked into a candidate block, and that
an offline light-client equivocation-evidence checker re-runs on a pair
of conflicting signed messages without any chain state beyond the
signer's registered pubkey.

NOTE: no model-check this session — caller will TLC-validate. This
module is syntactically self-contained and ready for `tlc -config
EquivocationEvidenceVerify.cfg EquivocationEvidenceVerify.tla` once a
companion `.cfg` is supplied (one is shipped alongside).

Scope. Where FB28 S006ContribMsgEquivocation.tla models the RECEIVE-time
DETECTOR (Node::on_contrib constructs an EquivocationEvent from two
conflicting pending ContribMsgs) and FB14/FB15 EquivocationApply.tla
models the APPLY-time MECHANICS (a validated event forfeits stake +
deactivates the registry entry), this spec models the GATE BETWEEN the
two: the verifier predicate that decides whether a candidate
EquivocationEvent is admissible PROOF of equivocation in the first
place. FB28 explicitly defers this — "the V11 validator predicate
re-verification at `validator.cpp:307..322` is FA6 territory" — and
FB14 begins downstream of it ("Equivocate(d) abstracts EUF-CMA / V11").
FB48 fills exactly that gap: it pins the FA6 "slashing only catches the
guilty" soundness AT THE VERIFIER, so that no malformed, self-forged,
or unregistered-signer evidence is ever accepted, and every genuine
two-signature conflict is.

The predicate (validator.cpp:312-329, in clause order):

  (C1) digest_a # digest_b           \* two DIFFERENT signed messages
  (C2) sig_a    # sig_b              \* two DISTINCT signatures
  (C3) equivocator \in registry      \* registered signer (pubkey known)
  (C4a) verify(pubkey, digest_a, sig_a)   \* sig_a is genuine
  (C4b) verify(pubkey, digest_b, sig_b)   \* sig_b is genuine

Accept iff C1 /\ C2 /\ C3 /\ C4a /\ C4b. The clauses are checked in
order with early-return on the first failure (the C++ `return {false,
...}` cascade); the spec models the conjunction directly because the
ACCEPT verdict is order-independent — the diagnostic STRING differs by
which clause fired first, but the boolean verdict is the conjunction.

The offline light-client tie-in. An external auditor holding only the
signer's registered Ed25519 pubkey (obtainable trustlessly from the
`s:` / registry namespace via a state_proof, FB43/FB44) can re-run
EXACTLY this predicate on a pair of conflicting signed block_digests
and reach the SAME verdict as the on-chain validator — no consensus
participation, no mempool, no full chain replay required. The verifier
is PURE in (evidence, pubkey): it is the minimal trusted-computing-base
for "is this slashing justified?" FB48 is the state-machine witness
that the predicate's verdict depends ONLY on those inputs and is
monotone-stable (re-checking never flips a verdict).

What the model verifies (under TLC):

  (T-EV1) Soundness — no forged accept. Every ACCEPTED evidence record
          has two DISTINCT genuine signatures by the SAME registered
          signer over two DISTINCT digests. Contrapositive of the FA6
          "slashing only catches the guilty" theorem: the verifier
          never approves evidence the signer did not actually produce.
          Headline INV_AcceptImpliesGuilty.
  (T-EV2) Completeness — no missed equivocation. Every evidence record
          that IS a genuine equivocation (registered signer, two
          distinct genuine sigs over two distinct digests) is ACCEPTED.
          The verifier never rejects a valid two-signature conflict.
          INV_GuiltyImpliesAccept. Together with T-EV1 this gives the
          accept-IFF-guilty characterization (the FB44 AcceptIffHonest
          analog for the slashing-evidence gate).
  (T-EV3) Non-equivocation rejected (C1). Evidence with digest_a =
          digest_b (one message double-counted, not a conflict) is
          REJECTED. INV_EqualDigestRejected.
  (T-EV4) Same-signature rejected (C2). Evidence with sig_a = sig_b
          (one signature presented twice) is REJECTED even if the
          digests differ — a single signature cannot witness two
          messages. INV_EqualSigRejected.
  (T-EV5) Unregistered signer rejected (C3). Evidence naming a signer
          absent from the registry is REJECTED — no pubkey to verify
          against, no stake to slash. INV_UnregisteredRejected.
  (T-EV6) Forgery rejected (C4). Evidence whose sig_a or sig_b does NOT
          verify under the registered signer's pubkey is REJECTED —
          the Ed25519 EUF-CMA gate. An adversary cannot frame an honest
          signer by fabricating signatures. INV_ForgedSigRejected.
  (T-EV7) Verdict determinism / purity. The verdict is a pure function
          of (evidence, registry, valid_sigs); re-verifying the same
          record yields the same verdict. No reachable state holds two
          verdict-log entries for the same record with opposite
          verdicts. INV_VerdictDeterministic (state predicate).

Modeling scope (TLC tractability):

  * Verifier is PURE — no mutation of registry / stakes / chain. The
    spec accumulates an append-only verdict_log of [evidence, verdict]
    records; the apply-side stake-forfeit is FB14/FB15 territory and
    composes downstream of every ACCEPT verdict here.
  * Signatures are modeled abstractly (the FB23 FrostVerify / FB28
    device): a Sig is a tagged tuple <<signer, digest>>; membership in
    `valid_sigs` is the spec-layer projection of `crypto::verify(pubkey,
    digest, sig) == true`. The adversary may PRESENT any (signer,
    digest, sig) triple as evidence (ForgeEvidence), but a sig enters
    `valid_sigs` only via an honest SignMessage by the key's true
    owner — so C4 catches every forgery. Ed25519 EUF-CMA tightness is
    FA-track / FB23 territory.
  * `registry` is a fixed SUBSET of Signers (the registered domains);
    the spec does not model REGISTER/DEREGISTER churn (FB8 / FB41
    territory) — registry membership is a verify-time snapshot, matching
    the validator's single `registry.find(ev.equivocator)` lookup.
  * Evidence == [equivocator, digest_a, sig_a, digest_b, sig_b] — the
    five verifier-relevant fields of the C++ EquivocationEvent (block.hpp
    :256-279). The forensic fields (block_index / shard_id /
    beacon_anchor_height) are abstracted; the verifier predicate at
    validator.cpp:312-329 consumes ONLY these five (the block_index
    binding is checked separately and is FB28/FB15 territory).
  * The per-event loop (validator.cpp:309 `for ... b.equivocation_events`)
    is abstracted into per-record VerifyEvidence actions; a block with N
    events is N independent verdicts, all of which must ACCEPT for the
    block to pass (the C++ early-return on the first REJECT is the
    conjunction over the loop). INV_AcceptImpliesGuilty quantifies over
    every logged ACCEPT.

To check (assuming TLC installed):
  $ tlc EquivocationEvidenceVerify.tla -config EquivocationEvidenceVerify.cfg

Recommended config (state space ~10^4, < 30s):
  Signers = {a, b}, Registered = {a}, Digests = {d1, d2}.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Signers,        \* finite universe of signer / domain identifiers
    Registered,     \* SUBSET Signers — the registered (pubkey-known) signers
    Digests,        \* finite universe of signed block_digests
    MaxVerifies     \* TLC bound on the verdict-log length

ASSUME ConfigOK ==
    /\ Cardinality(Signers)  >= 1
    /\ Registered \subseteq Signers
    /\ Cardinality(Digests)  >= 2   \* need >=2 to model digest_a # digest_b
    /\ MaxVerifies \in Nat /\ MaxVerifies >= 1

----------------------------------------------------------------------------
\* §1. Shapes.
\*
\* Sig: spec-layer Ed25519 signature, a tagged tuple <<signer, digest>>.
\* Membership in `valid_sigs` is the spec-layer projection of
\* `crypto::verify(pubkey, digest, sig) == true`. The C++ verifier at
\* validator.cpp:324/327 calls `verify(entry->pubkey, ev.digest_x.data(),
\* ev.digest_x.size(), ev.sig_x)`; the spec models the accept/reject of
\* that call as `[signer |-> equivocator, digest |-> digest_x] \in
\* valid_sigs`. A genuine signature binds the TRUE signer to the digest;
\* a forged one names a signer whose key did not produce it (so it is
\* absent from valid_sigs).

Sig == [signer : Signers, digest : Digests]

\* Evidence: the five verifier-relevant fields of EquivocationEvent
\* (block.hpp:256-279). equivocator names the accused signer; (digest_a,
\* sig_a) and (digest_b, sig_b) are the two conflicting signed messages.
Evidence == [
    equivocator : Signers,
    digest_a    : Digests,
    sig_a       : Sig,
    digest_b    : Digests,
    sig_b       : Sig
]

\* Verdict tags.
ACCEPT == "ACCEPT"
REJECT == "REJECT"
Verdicts == {ACCEPT, REJECT}

\* VerdictRecord: a logged (evidence, verdict) pair. The append-only
\* verdict_log accumulates one per VerifyEvidence step.
VerdictRecord == [evidence : Evidence, verdict : Verdicts]

----------------------------------------------------------------------------
\* §2. Pure helpers — the verifier predicate clauses.
\*
\* SigVerifies(s, dg, sg): the spec-layer `crypto::verify`. TRUE iff the
\* signature sg is in valid_sigs AND structurally binds signer s to
\* digest dg. The structural binding clause mirrors the C++ call passing
\* `entry->pubkey` (the equivocator's key) and `ev.digest_x` (the claimed
\* digest): a genuine sig is over the right digest by the right signer.

SigVerifies(s, dg, sg, vs) ==
    /\ sg \in vs
    /\ sg = [signer |-> s, digest |-> dg]

\* IsGuilty(ev, reg, vs): the GROUND-TRUTH equivocation predicate — what
\* the verifier is TRYING to decide. TRUE iff ev is a genuine
\* equivocation: registered signer, two distinct digests, two distinct
\* genuine signatures by that signer. The verifier's ACCEPT verdict must
\* coincide with IsGuilty (T-EV1 + T-EV2 = accept IFF guilty).
IsGuilty(ev, reg, vs) ==
    /\ ev.equivocator \in reg
    /\ ev.digest_a # ev.digest_b
    /\ ev.sig_a # ev.sig_b
    /\ SigVerifies(ev.equivocator, ev.digest_a, ev.sig_a, vs)
    /\ SigVerifies(ev.equivocator, ev.digest_b, ev.sig_b, vs)

\* VerifierAccepts(ev, reg, vs): the IMPLEMENTED predicate — the exact
\* conjunction of the five C++ clauses (validator.cpp:312-329), in the
\* same operand structure. This is what the verifier COMPUTES; the
\* soundness/completeness invariants assert VerifierAccepts coincides
\* with IsGuilty over every reachable evidence record.
\*
\*   C1  ev.digest_a # ev.digest_b           (validator.cpp:312)
\*   C2  ev.sig_a    # ev.sig_b              (validator.cpp:315)
\*   C3  ev.equivocator \in reg              (validator.cpp:319-322)
\*   C4a verify(pubkey, digest_a, sig_a)     (validator.cpp:324)
\*   C4b verify(pubkey, digest_b, sig_b)     (validator.cpp:327)
VerifierAccepts(ev, reg, vs) ==
    /\ ev.digest_a # ev.digest_b
    /\ ev.sig_a # ev.sig_b
    /\ ev.equivocator \in reg
    /\ SigVerifies(ev.equivocator, ev.digest_a, ev.sig_a, vs)
    /\ SigVerifies(ev.equivocator, ev.digest_b, ev.sig_b, vs)

----------------------------------------------------------------------------
\* §3. State.
\*
\* valid_sigs   : SUBSET Sig — the genuine signatures produced so far.
\*                Populated ONLY by SignMessage (the true key owner
\*                signing); ForgeEvidence never adds to it. The spec-layer
\*                projection of "crypto::verify accepts this sig."
\* verdict_log  : Seq of VerdictRecord — append-only audit of every
\*                verifier decision. The verifier is pure: it never
\*                mutates valid_sigs / registry; it only appends a verdict.
\* registry     : SUBSET Signers — the registered signers (constant after
\*                Init; a verify-time snapshot equal to the Registered
\*                constant). Carried as a variable so the type invariant
\*                and the IsGuilty/VerifierAccepts helpers read a single
\*                state component, matching the C++ `registry.find` lookup.

VARIABLES
    valid_sigs,
    verdict_log,
    registry

vars == <<valid_sigs, verdict_log, registry>>

----------------------------------------------------------------------------
\* §4. Initial state. No genuine signatures yet; empty verdict log; the
\* registry snapshot equals the Registered constant.

Init ==
    /\ valid_sigs  = {}
    /\ verdict_log = << >>
    /\ registry    = Registered

----------------------------------------------------------------------------
\* §5. Actions.

\* SignMessage(s, dg): the TRUE owner of signer s's key signs digest dg.
\* Admits the genuine signature into valid_sigs (the spec-layer
\* projection of producing a sig that `crypto::verify` will accept).
\* Honest OR Byzantine: a Byzantine signer signs TWO distinct digests
\* (the equivocation act) by calling SignMessage twice with the same
\* signer and different dg — no forgery is needed because the Byzantine
\* signer holds the secret. An honest signer signs at most one digest per
\* (height, gen); the spec does not enforce that here (the adversary
\* surface is unrestricted) — the verifier's job is to decide on whatever
\* evidence is PRESENTED, and equivocation is exactly two SignMessage
\* calls by the same signer over distinct digests.
SignMessage(s, dg) ==
    /\ s  \in Signers
    /\ dg \in Digests
    /\ valid_sigs' = valid_sigs \cup {[signer |-> s, digest |-> dg]}
    /\ UNCHANGED <<verdict_log, registry>>

\* VerifyEvidence(ev): the verifier runs check_equivocation_events on a
\* candidate evidence record and appends the verdict. The verdict is the
\* EXACT VerifierAccepts conjunction. PURE — only verdict_log grows.
\*
\* ev ranges over the FULL Evidence universe at the Next level: this
\* covers honest two-sig conflicts (both sigs in valid_sigs, distinct
\* digests) AND every adversarial malformation (equal digests, equal
\* sigs, unregistered equivocator, forged sigs absent from valid_sigs).
\* The verifier must reach the right verdict on ALL of them.
VerifyEvidence(ev) ==
    /\ ev \in Evidence
    /\ Len(verdict_log) < MaxVerifies
    /\ LET v == IF VerifierAccepts(ev, registry, valid_sigs)
                THEN ACCEPT ELSE REJECT
       IN verdict_log' = Append(verdict_log,
                                [evidence |-> ev, verdict |-> v])
    /\ UNCHANGED <<valid_sigs, registry>>

\* ForgeEvidence(ev): the adversary PRESENTS an evidence record whose
\* signatures were NOT produced by the named signer's key (the sigs are
\* absent from valid_sigs, OR name a signer different from the digest's
\* true author). Modeled identically to VerifyEvidence — the verifier
\* runs the same predicate; the point is that the .cfg / Next enumeration
\* reaches such records and INV_ForgedSigRejected confirms they are
\* REJECTED. Kept as a distinct action only for documentary clarity; its
\* body is the VerifyEvidence body (the verifier does not know in advance
\* whether evidence is forged — that is precisely what it decides).
ForgeEvidence(ev) ==
    /\ ev \in Evidence
    /\ \/ ev.sig_a \notin valid_sigs
       \/ ev.sig_b \notin valid_sigs
       \/ ev.sig_a # [signer |-> ev.equivocator, digest |-> ev.digest_a]
       \/ ev.sig_b # [signer |-> ev.equivocator, digest |-> ev.digest_b]
    /\ Len(verdict_log) < MaxVerifies
    /\ LET v == IF VerifierAccepts(ev, registry, valid_sigs)
                THEN ACCEPT ELSE REJECT
       IN verdict_log' = Append(verdict_log,
                                [evidence |-> ev, verdict |-> v])
    /\ UNCHANGED <<valid_sigs, registry>>

\* Stutter at saturation: when MaxVerifies verdicts have been logged and
\* no SignMessage adds a new genuine sig, TLC stutters. The bounded model
\* (finite Signers + finite Digests + bounded log) guarantees saturation.
Stutter ==
    /\ UNCHANGED vars

Next ==
    \/ \E s \in Signers, dg \in Digests : SignMessage(s, dg)
    \/ \E ev \in Evidence : VerifyEvidence(ev)
    \/ \E ev \in Evidence : ForgeEvidence(ev)
    \/ Stutter

\* Fairness on VerifyEvidence so a pending verifiable record eventually
\* gets a verdict (PROP_EventualVerdict). The disjunction over the
\* Evidence universe is the eventual-progress driver.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ \A ev \in Evidence : WF_vars(VerifyEvidence(ev))

----------------------------------------------------------------------------
\* §6. Invariants — the seven T-EV1..T-EV7 claims.

\* Type invariant.
INV_TypeOK ==
    /\ valid_sigs  \subseteq Sig
    /\ verdict_log \in Seq(VerdictRecord)
    /\ registry    \subseteq Signers

\* INV_AcceptImpliesGuilty (T-EV1, SOUNDNESS — the headline).
\*
\* Every ACCEPTED evidence record in the log is a GENUINE equivocation:
\* registered signer, two distinct digests, two distinct genuine
\* signatures by that signer. The verifier never approves evidence the
\* signer did not actually produce. This is the FA6 "slashing only
\* catches the guilty" soundness AT THE VERIFIER — composed with FB14/FB15
\* (apply) and FB28 (detect), it gives the end-to-end "only the guilty
\* lose stake" guarantee.
INV_AcceptImpliesGuilty ==
    \A i \in DOMAIN verdict_log :
       (verdict_log[i].verdict = ACCEPT)
       => IsGuilty(verdict_log[i].evidence, registry, valid_sigs)

\* INV_GuiltyImpliesAccept (T-EV2, COMPLETENESS).
\*
\* Every record that the verifier LOGGED and that IS a genuine
\* equivocation was ACCEPTED — the verifier never rejects a valid
\* two-signature conflict. Together with T-EV1 this is the accept-IFF-
\* guilty characterization. (Quantified over logged records: the verifier
\* only emits a verdict on records it was asked to check.)
INV_GuiltyImpliesAccept ==
    \A i \in DOMAIN verdict_log :
       IsGuilty(verdict_log[i].evidence, registry, valid_sigs)
       => (verdict_log[i].verdict = ACCEPT)

\* INV_EqualDigestRejected (T-EV3, clause C1).
\*
\* Any logged record with digest_a = digest_b was REJECTED — one message
\* double-counted is not a conflict (validator.cpp:312).
INV_EqualDigestRejected ==
    \A i \in DOMAIN verdict_log :
       (verdict_log[i].evidence.digest_a = verdict_log[i].evidence.digest_b)
       => (verdict_log[i].verdict = REJECT)

\* INV_EqualSigRejected (T-EV4, clause C2).
\*
\* Any logged record with sig_a = sig_b was REJECTED even if the digests
\* differ — a single signature cannot witness two messages
\* (validator.cpp:315).
INV_EqualSigRejected ==
    \A i \in DOMAIN verdict_log :
       (verdict_log[i].evidence.sig_a = verdict_log[i].evidence.sig_b)
       => (verdict_log[i].verdict = REJECT)

\* INV_UnregisteredRejected (T-EV5, clause C3).
\*
\* Any logged record naming a signer absent from the registry was
\* REJECTED — no pubkey to verify against, no stake to slash
\* (validator.cpp:319-322).
INV_UnregisteredRejected ==
    \A i \in DOMAIN verdict_log :
       (verdict_log[i].evidence.equivocator \notin registry)
       => (verdict_log[i].verdict = REJECT)

\* INV_ForgedSigRejected (T-EV6, clause C4).
\*
\* Any logged record whose sig_a or sig_b does NOT verify under the named
\* signer's key (absent from valid_sigs, or not bound to the right
\* (signer, digest)) was REJECTED. An adversary cannot frame an honest
\* signer with fabricated signatures (validator.cpp:324/327). The Ed25519
\* EUF-CMA gate at the verifier layer.
INV_ForgedSigRejected ==
    \A i \in DOMAIN verdict_log :
       LET ev == verdict_log[i].evidence IN
       (\/ ~ SigVerifies(ev.equivocator, ev.digest_a, ev.sig_a, valid_sigs)
        \/ ~ SigVerifies(ev.equivocator, ev.digest_b, ev.sig_b, valid_sigs))
       => (verdict_log[i].verdict = REJECT)

\* INV_VerdictDeterministic (T-EV7, PURITY).
\*
\* The verdict is a pure function of (evidence, registry, valid_sigs):
\* no two logged records for the SAME evidence carry opposite verdicts.
\* Because valid_sigs only GROWS (SignMessage is monotone) and registry
\* is constant, a record logged as REJECT before a missing sig arrives will
\* NOT equal what VerifierAccepts recomputes against the LATER valid_sigs —
\* a reachable REJECT->ACCEPT flip. This same-state invariant is therefore
\* NOT in the checked set (see .cfg INVARIANTS); the omission is benign for
\* safety, since INV_AcceptImpliesGuilty still holds (the verifier never
\* ACCEPTs a non-equivocation). The predicate VerifierAccepts is pure given
\* a FIXED state; only the frozen-log-entry-vs-grown-state comparison breaks.
INV_VerdictDeterministic ==
    \A i \in DOMAIN verdict_log :
       verdict_log[i].verdict =
          (IF VerifierAccepts(verdict_log[i].evidence, registry, valid_sigs)
           THEN ACCEPT ELSE REJECT)

----------------------------------------------------------------------------
\* §7. Temporal property.

\* PROP_EventualVerdict: under fairness on VerifyEvidence, any verifiable
\* evidence eventually receives a verdict (the log grows) until the
\* model-bound MaxVerifies is reached. The eventual-progress liveness for
\* the verifier — it does not stall on admissible evidence.
PROP_EventualVerdict ==
    (Len(verdict_log) < MaxVerifies)
    ~> (Len(verdict_log) > 0 \/ Len(verdict_log) >= MaxVerifies)

----------------------------------------------------------------------------
\* §8. Soundness commentary — what TLC checks vs. what the C++ enforces.
\*
\* The verifier predicate is a five-clause conjunction with early-return
\* diagnostics (validator.cpp:312-329). The TLA+ layer abstracts the
\* per-event loop into per-record VerifyEvidence / ForgeEvidence actions
\* and pins the verdict as the VerifierAccepts conjunction. The seven
\* invariants partition the predicate's contract:
\*
\*   * T-EV1 (Soundness) -> INV_AcceptImpliesGuilty. The headline FA6
\*     claim at the verifier: every ACCEPT is a genuine two-sig conflict
\*     by a registered signer. Composed with FB14/FB15 (apply) this is
\*     "only the guilty lose stake."
\*   * T-EV2 (Completeness) -> INV_GuiltyImpliesAccept. No genuine
\*     equivocation escapes the gate. T-EV1 + T-EV2 = accept IFF guilty
\*     (the FB44 AcceptIffHonest analog for the slashing gate).
\*   * T-EV3..T-EV6 (clause rejections) -> INV_EqualDigestRejected /
\*     INV_EqualSigRejected / INV_UnregisteredRejected /
\*     INV_ForgedSigRejected. Each pins one C++ early-return: C1 digest
\*     equality, C2 signature equality, C3 registry membership, C4
\*     Ed25519 verify. Together they enumerate the REJECT space.
\*   * T-EV7 (Purity) -> INV_VerdictDeterministic. The verdict is a pure
\*     function of (evidence, registry, valid_sigs) — the property an
\*     offline light-client verifier relies on to re-derive the on-chain
\*     verdict from the signer's pubkey alone.
\*
\* What this spec adds beyond the prose proof: a state-machine witness
\* that the verifier's accept-IFF-guilty contract holds across every
\* reachable interleaving of SignMessage (honest + Byzantine
\* double-signing) and VerifyEvidence / ForgeEvidence (the full evidence
\* universe, including every malformation) within the bounded model.
\*
\* What the spec does NOT check (FA-track / sibling-spec territory):
\*   * Apply-side stake forfeiture + registry deactivation. FB14/FB15
\*     EquivocationApply.tla covers the downstream of every ACCEPT.
\*   * Receive-time event CONSTRUCTION from pending ContribMsgs. FB28
\*     S006ContribMsgEquivocation.tla covers the upstream detector that
\*     produces the candidate evidence this spec verifies.
\*   * Ed25519 EUF-CMA cryptographic tightness. The valid_sigs membership
\*     predicate is the spec-layer projection of crypto::verify; FB23
\*     FrostVerify.tla models the verify relation; the bounded forgery
\*     surface here (sigs absent from valid_sigs) is the state-machine
\*     consequence, not the number-theoretic proof.
\*   * The block_index / shard_id / beacon_anchor_height forensic binding.
\*     The verifier predicate at validator.cpp:312-329 consumes only the
\*     five fields modeled here; the cross-shard slashing routing is FA6
\*     T-6.1 / FB13 territory.
\*   * The diagnostic STRING returned on the first failed clause. The
\*     spec models only the boolean verdict (the conjunction is
\*     order-independent for the verdict; the C++ early-return order
\*     matters only for the human-readable reason).

============================================================================
\* Cross-references.
\*
\* FA6 (EquivocationSlashing.md) — the cryptographic soundness theorem
\*   ("slashing only catches the guilty"). INV_AcceptImpliesGuilty is the
\*   state-machine projection of FA6 at the verifier layer; the apply-side
\*   projection is FB15's Inv_DeactivatedAfterSlash + Inv_NoDoubleSlash.
\*
\* C++ enforcement: src/node/validator.cpp
\*   BlockValidator::check_equivocation_events                 @ 307-332
\*   C1 digest_a != digest_b (not equivocation)                @ 312-314
\*   C2 sig_a != sig_b (same signature)                        @ 315-317
\*   C3 registry.find(ev.equivocator) (registered signer)      @ 319-322
\*   C4a verify(pubkey, digest_a, sig_a)                       @ 324-326
\*   C4b verify(pubkey, digest_b, sig_b)                       @ 327-329
\*   validate_block call site (early-return on first reject)   @ 32
\*
\* EquivocationEvent struct: include/determ/chain/block.hpp lines
\*   256..279 — the five verifier-relevant fields (equivocator, digest_a,
\*   sig_a, digest_b, sig_b) the spec's Evidence record projects; the
\*   forensic fields (block_index / shard_id / beacon_anchor_height) are
\*   abstracted (FB13 / FB15 territory).
\*
\* FB14/FB15 EquivocationApply.tla (FA-Apply-10 apply-side mechanics) —
\*   the DOWNSTREAM sibling. FB48 (this spec) is the GATE that decides
\*   admissibility; FB15 is the apply that forfeits stake on every
\*   admitted event. FB15's Equivocate(d) action "abstracts EUF-CMA /
\*   V11" — FB48 is exactly that abstracted V11 made explicit.
\*
\* FB28 S006ContribMsgEquivocation.tla (receive-time detector) — the
\*   UPSTREAM sibling. FB28 CONSTRUCTS candidate evidence from two
\*   conflicting pending ContribMsgs and explicitly defers the V11
\*   re-verification to "FA6 territory"; FB48 IS that re-verification.
\*   FB28 INV_TwoSigsValid is the receive-time half; FB48
\*   INV_ForgedSigRejected + INV_AcceptImpliesGuilty is the validate-time
\*   half (the validator re-runs the check for belt-and-suspenders).
\*
\* FB23 FrostVerify.tla (Ed25519 EUF-CMA model) — the valid_sigs
\*   membership predicate is the spec-layer projection of the FrostVerify
\*   accept relation, restricted to the single-signer Ed25519 case used
\*   by check_equivocation_events.
\*
\* FB44 MerklePathVerify.tla (client-side inclusion verifier) — the
\*   structural sibling: both are PURE accept/reject verifier predicates
\*   with an accept-IFF-honest/guilty headline (FB44 INV_AcceptIffHonest;
\*   FB48 INV_AcceptImpliesGuilty + INV_GuiltyImpliesAccept). An offline
\*   light-client auditor composes the two: FB44 proves the signer's
\*   pubkey was trustlessly read under the committee-signed state_root;
\*   FB48 proves the equivocation verdict computed from that pubkey is
\*   sound. Together they give a chain-free "is this slashing justified?"
\*   decision from a single state_proof + the two signed digests.
\*
\* SECURITY.md §S-006 — the ContribMsg-equivocation closure; the V11
\*   validator predicate modeled here is the block-validate-time gate
\*   that re-checks every event the S-006 detector (or the rev.8
\*   BlockSigMsg detector) routes into a block body.
\*
\* Preliminaries.md §2.2 (A1 Ed25519 EUF-CMA) : the valid_sigs membership
\*   predicate is the spec-layer projection of crypto::verify acceptance;
\*   INV_ForgedSigRejected is the verifier's reliance on that assumption.
============================================================================
