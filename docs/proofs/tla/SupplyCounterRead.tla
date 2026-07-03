-------------------------- MODULE SupplyCounterRead --------------------------
(*
FB70 — TLA+ specification of the ATOMIC FIVE-COUNTER SUPPLY READ: the
`determ-light supply-trustless` composition (light/main.cpp::
cmd_supply_trustless, main.cpp:6175-6578, R51 posture) that reads the five
A1 supply counters from the committee-verified `c:` namespace of a possibly
Byzantine daemon and recomputes the closed-form A1 unitary-supply identity

    expected_total = genesis_total + accumulated_subsidy
                   + accumulated_inbound - accumulated_slashed
                   - accumulated_outbound          (chain.hpp:443-449)

entirely from committee-committed values. The single-leaf trust reductions
(genesis anchor, committee-signed head, Merkle path, value-hash bind) are
the a:/s:/d:/r: sibling readers' territory (FB50 / FB53 / FB60, FB44,
FB23); what is NEW here — and what this module pins — is the COMPOSITION
obligation: the five values are meaningful as an identity only if ALL FIVE
anchor to ONE committee-attested state_root, i.e. one consistent snapshot.
A daemon that serves five individually-valid proofs against two different
roots (the SPLIT-ROOT attack) could present counters that are each
leaf-committed yet mutually inconsistent; supply-trustless closes this by
resolving a single anchor root from the first counter's proof (after the
stale-height gate + the S-042 committee binding) and requiring every later
counter to match it exactly (main.cpp:6371-6438).

Prose companion: docs/proofs/SupplyProofSoundness.md — SU-1 (committee-
signed state_root binds the c: leaf), SU-2 (Merkle proof + value-hash bind
soundness), SU-3 (the five verified counters let the client re-check the
A1 identity itself), SU-4 (leaf_count binding). This module machine-checks
the SU-3 composition layer over abstracted SU-1/SU-2 gates.

The daemon serves, per counter, a proof carrying (root, height, value) —
R51's atomic value_hex is served from the same locked snapshot as the
proof, so value and proof are ONE message (main.cpp:6288-6308). The
Byzantine actions modeled, per the three attack classes:

  HONEST — the genuine proof at the head snapshot: root = the committee-
           attested head root, height = head, value = the committed leaf
           value. Passes every gate.
  LIE    — the genuine proof but a LIED value (value /= committed leaf).
           The recomputed SHA256(u64_be(value)) does not equal the proof's
           Merkle-verified value_hash, so the bind gate rejects
           (main.cpp:6350-6369; injective-Encode abstraction, A2).
  STALE  — a genuinely-committed proof from an OLDER height (root is
           attested, but at a height before the verified head). On the
           FIRST counter the stale-height gate rejects it
           (proof.height < vc.height throw, main.cpp:6380-6385); on a
           LATER counter it is a root mismatch against the resolved anchor
           — the split-root guard rejects it (main.cpp:6424-6438).
  FORGED — a fabricated proof against a root the committee never attested
           (internally consistent: the daemon controls the fake proof, so
           its value_hash matches its served value — the bind gate passes;
           what fails is the ROOT). On the FIRST counter the S-042
           committee binding rejects it (committee_bound_state_root
           mismatch throw, main.cpp:6396-6423); on a LATER counter the
           split-root guard rejects it.

Any rejection fails the WHOLE read closed (the C++ loop breaks; verdict
UNVERIFIABLE exit 3, or the stale/committee-binding throw exit 1 — both
non-accept, folded to one UNVERIFIABLE here). Only when all five counters
are accepted against the single anchor does the client recompute the A1
closed form: CONSERVED (exit 0) when non-negative and consistent, VIOLATED
(exit 2) when the committee-committed counters themselves underflow the
identity (slashed+outbound > genesis+subsidy+inbound — the defense-in-
depth branch, main.cpp:6486-6519; unreachable on a chain whose apply path
enforces I-6, but the reader does not assume it).

Safety theorems (the brief's S1-S3):

  (S1) Single-height truth. If the client reports CONSERVED (or VIOLATED —
       both are sound verified verdicts), all five accepted values equal
       the chain's committed counter values at ONE height: the committee-
       attested head. No mixed-height acceptance: a run can never combine
       a height-h value with a height-h' value. INV_S1_SingleHeightTruth.
  (S2) No split-root accept. A counter served against a root different
       from the single resolved anchor (or an unattested root, or a stale
       root on the first counter) is never accepted; every accepted
       counter's root equals the committee-attested head root.
       INV_S2_NoSplitRootAccept.  (SU-1's single-root precondition.)
  (S3) No lied-value accept. A served value inconsistent with the
       committed leaf (value_hash bind failure) is never accepted; every
       accepted value equals the committed leaf value. Under A2 a daemon
       lying about a counter while serving an honest proof must find a
       SHA-256 second-preimage on a single u64 field.
       INV_S3_NoLiedValueAccept.  (SU-2's bind.)

  Plus: INV_FailClosed (a rejected serve <=> the whole read is
  UNVERIFIABLE — no partial acceptance is ever reported), and
  INV_VerdictFaithful (CONSERVED iff the committed head counters satisfy
  the A1 closed form; VIOLATED iff they underflow it — the verdict is a
  recompute over committee-committed values, never a daemon claim).

Temporal pair + non-vacuity witnesses:

  PROP_EventualVerdict    — the pipeline always terminates with a verdict.
  PROP_HonestConserved    — an all-HONEST daemon over a conserving head
                            snapshot ALWAYS reaches CONSERVED: the honest
                            path is admitted, the gates do not vacuously
                            reject everything. (Leads-to, checked green.)
  PROP_HonestViolated     — an all-HONEST daemon over an underflowing
                            snapshot reaches VIOLATED (the defense-in-
                            depth branch is live, not dead code).

NON-VACUITY PROBES (falsify-on-mutant; run 2026-07-03, tla2tools v1.8.0,
all four falsified as expected — none of these ships in the green .cfg):

  M0 (reachability): checking the in-module probe invariant
     Probe_ConservedUnreachable (== verdict /= "CONSERVED") is EXPECTED
     FALSIFIED — TLC produces the all-honest trace ending CONSERVED,
     machine-confirming the honest path reaches CONSERVED. VERIFIED:
     falsified at depth 7 (5 accepts + Finalize from an all-HONEST init).
  M1 (split-root guard removed): mutate RejectReason's anchored branch to
     accept any root once anchored -> INV_S2_NoSplitRootAccept EXPECTED
     FALSIFIED (a STALE/FORGED later counter is accepted). VERIFIED.
  M2 (bind gate removed): mutate BindOk to TRUE -> INV_S3_NoLiedValueAccept
     EXPECTED FALSIFIED (a LIE serve is accepted with value /= committed).
     VERIFIED.
  M3 (stale-height gate removed): drop the first-counter height check ->
     a STALE first counter anchors at the OLD attested root:
     INV_S2_NoSplitRootAccept EXPECTED FALSIFIED at depth 2 (the accept
     right after Init anchors R1 /= head root), and — checked alone —
     INV_S1_SingleHeightTruth EXPECTED FALSIFIED (an all-STALE run
     reports CONSERVED over stale values, accepted values /= committed
     head values). BOTH VERIFIED.

Modeling scope (kept tractable for TLC; abstraction boundary matches the
sibling read specs):

  * The genesis anchor + committee-verified header walk (anchor_genesis /
    verify_chain_to_head / anchored_head, main.cpp:6217-6237) are NOT
    modeled: this module starts from a client that already holds the
    committee-attested head height. A daemon failing those upstream gates
    never reaches the counter loop (FB23 + T-L1/T-L2 territory).
  * SHA-256 / u64_be leaf encoding is the standard injective-term
    abstraction (FB23/FB26/FB44/FB50/FB53/FB60 device): the bind gate
    passes iff the served value equals the value the served proof
    commits. A LIE against a genuine proof therefore always fails the
    bind; a FORGED proof is internally consistent (bind passes) and is
    caught by the root gates instead.
  * The Merkle path bytes are FB44 (MerklePathVerify) territory: an
    accepted counter's path is the genuine one (a path to the anchored
    root for a wrong value is a second-preimage). The canonical key bind
    ("k:c:"+name, main.cpp:6334-6349) is FB43 territory and is folded
    into the same bind abstraction — a wrong-key serve rejects exactly
    like a lied value (fail-closed, same code path).
  * Two snapshot heights: the verified head (height 2) and one stale
    height (1). The stale snapshot's concrete values are fixed all-zero
    (StaleSnapshot): they are never accepted in the un-mutated model, so
    their enumeration would only inflate the state space; the M3 mutant
    remains falsifiable because a stale all-zero CONSERVED still
    contradicts a non-zero committed head. The forward race window
    (proof.height > vc.height, chain advanced mid-read) is collapsed:
    its resolution is the SAME single-anchor-then-match discipline
    (main.cpp:6379-6423), pinned by StateProofRaceWindowSoundness.md.
  * The daemon's per-counter strategy is fixed at Init (a static
    adversary). Adaptivity gains nothing: the client reveals nothing
    mid-read that the daemon does not already know, and the loop's
    fail-closed break makes any post-rejection choice unreachable.
  * The optional daemon total_supply cross-check (height-gated in R51,
    main.cpp:6454-6479) and the not_found refusal arm (main.cpp:
    6319-6332, trivially fail-closed) are out of scope; the A1 identity
    recompute over the five committed values is the modeled verdict.

Counter index convention (kCounters order, main.cpp:6205-6208):
  1 = genesis_total          (+)     4 = accumulated_slashed    (-)
  2 = accumulated_subsidy    (+)     5 = accumulated_outbound   (-)
  3 = accumulated_inbound    (+)

To check (assuming TLC installed):
  $ tlc SupplyCounterRead.tla -config SupplyCounterRead.cfg
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Values,   \* finite counter-value universe (Nat), |Values| >= 2, 0 in it
    NoVal     \* sentinel for "no accepted value" — outside Values (typed
              \* sentinel: INV_TypeOK pins acc's range so a sentinel can
              \* never masquerade as an accepted counter value)

ASSUME ConfigOK ==
    /\ Values \subseteq Nat
    /\ Cardinality(Values) >= 2   \* a lied value /= committed must exist
    /\ 0 \in Values               \* the conserving all-zero snapshot exists
    /\ NoVal \in Nat /\ NoVal \notin Values

\* -----------------------------------------------------------------
\* §1. Fixed universe: counters, heights, roots, serve modes.
\* -----------------------------------------------------------------

Counters == 1..5          \* kCounters order (see index convention above)

StaleHeight == 1          \* one committed-but-old snapshot height
HeadHeight  == 2          \* the committee-attested verified head

\* Abstract roots: "R2" is the state_root the committee attested at the
\* head, "R1" the genuinely-committed root at the stale height, "RF" a
\* fabricated root no committee member ever attested. Root identity is the
\* injective stand-in for the 32-byte state_root (A2: two roots are equal
\* iff the committed states are).
Roots == {"R1", "R2", "RF"}

\* The committee-attested root at a height — what the S-042 binding
\* (committee_bound_state_root, main.cpp:6396-6423) recomputes and what
\* any served root is checked against when the anchor is resolved.
AttestedRootAt(h) == IF h = StaleHeight THEN "R1" ELSE "R2"

Modes == {"HONEST", "LIE", "STALE", "FORGED"}

\* The stale snapshot's committed counter values (see scope note: fixed,
\* not enumerated — stale serves are rejected before value acceptance).
StaleSnapshot == [c \in Counters |-> 0]

\* -----------------------------------------------------------------
\* §2. Variables.
\* -----------------------------------------------------------------

VARIABLES
    chain_head, \* [Counters -> Values]: committed c: leaf values at head
    strategy,   \* [Counters -> Modes]: the daemon's per-counter serve mode
    idx,        \* 1..6: next counter to process (6 = all five done)
    anchor,     \* "NONE" | Roots: the single resolved anchor root
    status,     \* [Counters -> {"PENDING","ACCEPTED","REJECTED"}]
    acc,        \* [Counters -> Values \cup {NoVal}]: accepted values
    reason,     \* [Counters -> reject reasons]: which gate fired
    verdict     \* "NONE" | "CONSERVED" | "VIOLATED" | "UNVERIFIABLE"

vars == <<chain_head, strategy, idx, anchor, status, acc, reason, verdict>>

Reasons == {"NONE", "BIND", "STALE_HEIGHT", "UNATTESTED", "SPLIT_ROOT"}

\* -----------------------------------------------------------------
\* §3. The served proof per mode + the gate pipeline.
\* -----------------------------------------------------------------

\* What the daemon serves for counter c under mode m — one atomic
\* (root, height, value) message (R51 value_hex posture, main.cpp:
\* 6288-6308).
ServedRoot(m) ==
    CASE m = "HONEST" -> "R2"
      [] m = "LIE"    -> "R2"   \* genuine proof, lied value
      [] m = "STALE"  -> "R1"
      [] m = "FORGED" -> "RF"

ServedHeight(m) == IF m = "STALE" THEN StaleHeight ELSE HeadHeight

\* LieValue: any committed-leaf mismatch; which wrong value is irrelevant
\* under the injective-Encode abstraction (deterministic CHOOSE keeps the
\* pipeline a pure function of Init).
LieValue(v) == CHOOSE w \in Values : w /= v

ServedValue(c, m) ==
    CASE m = "HONEST" -> chain_head[c]
      [] m = "LIE"    -> LieValue(chain_head[c])
      [] m = "STALE"  -> StaleSnapshot[c]
      [] m = "FORGED" -> chain_head[c]  \* even the TRUE value under a
                                        \* forged root must be rejected

\* BindOk — the key+value hash bind (main.cpp:6334-6369): recomputed
\* SHA256(u64_be(served value)) vs the served proof's value_hash. A LIE
\* pairs a lied value with the GENUINE proof, so the bind fails; HONEST /
\* STALE / FORGED serves are internally consistent (a forger controls its
\* fake proof's value_hash), so the bind passes and the root gates decide.
BindOk(m) == m /= "LIE"

\* RejectReason — the gate pipeline for the counter at hand, in C++ order:
\* bind (6334-6369), then anchor resolution on the first counter [stale-
\* height gate 6380-6385 -> S-042 committee binding 6396-6423] or the
\* split-root guard on later counters (6424-6438). Merkle verification
\* (6440-6448) is abstracted: a bind-consistent serve against the genuine
\* anchored root recomputes (FB44); every forged-root case is already
\* rejected here. Returns "NONE" iff the serve is accepted.
RejectReason(m) ==
    IF ~BindOk(m) THEN "BIND"
    ELSE IF anchor = "NONE"
         THEN IF ServedHeight(m) < HeadHeight
              THEN "STALE_HEIGHT"     \* proof before verified head
              ELSE IF AttestedRootAt(ServedHeight(m)) /= ServedRoot(m)
                   THEN "UNATTESTED"  \* committee never signed this root
                   ELSE "NONE"        \* resolves the anchor
         ELSE IF ServedRoot(m) /= anchor
              THEN "SPLIT_ROOT"       \* the split-root attack
              ELSE "NONE"

\* -----------------------------------------------------------------
\* §4. Initial state.
\* -----------------------------------------------------------------
\*
\* The committed head snapshot and the daemon strategy are fixed at Init;
\* TLC enumerates every (chain_head, strategy) pair, so every single-
\* counter attack position (first vs later) x mode combination is
\* explored, including the all-HONEST witness inits and head snapshots
\* both satisfying and underflowing the A1 identity.
Init ==
    /\ chain_head \in [Counters -> Values]
    /\ strategy   \in [Counters -> Modes]
    /\ idx     = 1
    /\ anchor  = "NONE"
    /\ status  = [c \in Counters |-> "PENDING"]
    /\ acc     = [c \in Counters |-> NoVal]
    /\ reason  = [c \in Counters |-> "NONE"]
    /\ verdict = "NONE"

\* -----------------------------------------------------------------
\* §5. Actions.
\* -----------------------------------------------------------------

\* ProcessOne — run counter idx through the gate pipeline. Accept: record
\* the served value, resolve the anchor on the first accept, advance.
\* Reject: fail the WHOLE read closed (the C++ `all_ok = false; break`) —
\* verdict UNVERIFIABLE, later counters stay PENDING (never processed).
ProcessOne ==
    /\ verdict = "NONE"
    /\ idx \in Counters
    /\ LET m  == strategy[idx]
           rr == RejectReason(m)
       IN IF rr = "NONE"
          THEN /\ status' = [status EXCEPT ![idx] = "ACCEPTED"]
               /\ acc'    = [acc    EXCEPT ![idx] = ServedValue(idx, m)]
               /\ anchor' = IF anchor = "NONE" THEN ServedRoot(m)
                                               ELSE anchor
               /\ idx'    = idx + 1
               /\ UNCHANGED <<chain_head, strategy, reason, verdict>>
          ELSE /\ status'  = [status EXCEPT ![idx] = "REJECTED"]
               /\ reason'  = [reason EXCEPT ![idx] = rr]
               /\ verdict' = "UNVERIFIABLE"
               /\ UNCHANGED <<chain_head, strategy, idx, anchor, acc>>

\* Finalize — all five accepted against the single anchor: recompute the
\* A1 closed form from the ACCEPTED (committee-committed) values.
\* Underflow-guarded exactly like the C++ (pos vs neg before subtracting,
\* main.cpp:6486-6501): underflow -> VIOLATED, else CONSERVED.
Finalize ==
    /\ verdict = "NONE"
    /\ idx = 6
    /\ LET pos == acc[1] + acc[2] + acc[3]
           neg == acc[4] + acc[5]
       IN verdict' = IF neg > pos THEN "VIOLATED" ELSE "CONSERVED"
    /\ UNCHANGED <<chain_head, strategy, idx, anchor, status, acc, reason>>

\* Done — stutter once the verdict is set (terminating exhibit).
Done ==
    /\ verdict /= "NONE"
    /\ UNCHANGED vars

Next == ProcessOne \/ Finalize \/ Done

\* WF on the two progress actions: the pipeline runs to completion in
\* every behavior (PROP_EventualVerdict) — the read never wedges.
Spec == Init /\ [][Next]_vars /\ WF_vars(ProcessOne \/ Finalize)

\* -----------------------------------------------------------------
\* §6. Type invariant.
\* -----------------------------------------------------------------

INV_TypeOK ==
    /\ chain_head \in [Counters -> Values]
    /\ strategy   \in [Counters -> Modes]
    /\ idx        \in 1..6
    /\ anchor     \in {"NONE"} \cup Roots
    /\ status     \in [Counters -> {"PENDING", "ACCEPTED", "REJECTED"}]
    /\ acc        \in [Counters -> Values \cup {NoVal}]
    /\ reason     \in [Counters -> Reasons]
    /\ verdict    \in {"NONE", "CONSERVED", "VIOLATED", "UNVERIFIABLE"}

\* -----------------------------------------------------------------
\* §7. Safety invariants — S1, S2, S3 + fail-closed + faithfulness.
\* -----------------------------------------------------------------

\* The A1 closed form over the COMMITTED head snapshot.
HeadConserving ==
    chain_head[1] + chain_head[2] + chain_head[3]
        >= chain_head[4] + chain_head[5]

\* INV_S1_SingleHeightTruth (S1) — a sound verified verdict (CONSERVED or
\* VIOLATED) implies ALL FIVE counters were accepted, the anchor is the
\* committee-attested HEAD root, and every accepted value equals the
\* chain's committed value at that ONE height. No mixed-height acceptance:
\* no run combines values from two snapshots. (SU-3's precondition + the
\* single-root discipline of SupplyProofSoundness §3.)
INV_S1_SingleHeightTruth ==
    (verdict \in {"CONSERVED", "VIOLATED"}) =>
        /\ anchor = AttestedRootAt(HeadHeight)
        /\ \A c \in Counters :
              /\ status[c] = "ACCEPTED"
              /\ acc[c] = chain_head[c]

\* INV_S2_NoSplitRootAccept (S2) — no accepted counter was served against
\* a root other than the single committee-attested head root: the split-
\* root serve (root /= anchor), the stale-root serve, and the unattested-
\* root serve are never accepted. (SU-1's single-root binding; the
\* main.cpp:6424-6438 guard + the 6380-6423 anchor gates.)
INV_S2_NoSplitRootAccept ==
    \A c \in Counters :
        (status[c] = "ACCEPTED") =>
            /\ anchor /= "NONE"
            /\ ServedRoot(strategy[c]) = anchor
            /\ anchor = AttestedRootAt(HeadHeight)

\* INV_S3_NoLiedValueAccept (S3) — no accepted value is inconsistent with
\* the committed leaf under the anchored root: every accepted value equals
\* the committed head value, and a LIE serve is never accepted. (SU-2's
\* value-hash bind, main.cpp:6350-6369; under A2 a lying daemon needs a
\* SHA-256 second-preimage on a single u64.)
INV_S3_NoLiedValueAccept ==
    \A c \in Counters :
        (status[c] = "ACCEPTED") =>
            /\ strategy[c] /= "LIE"
            /\ acc[c] = chain_head[c]

\* INV_FailClosed — one rejected serve <=> the whole read reports
\* UNVERIFIABLE. No partial acceptance is ever surfaced as a verdict, and
\* UNVERIFIABLE is never reported without a concrete rejected serve.
INV_FailClosed ==
    (verdict = "UNVERIFIABLE")
        <=> (\E c \in Counters : status[c] = "REJECTED")

\* INV_VerdictFaithful — the verdict is the A1 recompute over the
\* COMMITTED head values, never a daemon claim: CONSERVED iff the
\* committed snapshot satisfies the closed form, VIOLATED iff it
\* underflows it. (With S1, accepted values = committed values, so the
\* client's arithmetic over accepted values equals this.)
INV_VerdictFaithful ==
    /\ (verdict = "CONSERVED") => HeadConserving
    /\ (verdict = "VIOLATED")  => ~HeadConserving

\* -----------------------------------------------------------------
\* §8. Temporal properties + non-vacuity witnesses.
\* -----------------------------------------------------------------

\* PROP_EventualVerdict — under WF on the progress actions, every read
\* terminates with one of the three verdicts; the pipeline never wedges.
PROP_EventualVerdict == <>(verdict /= "NONE")

AllHonest == \A c \in Counters : strategy[c] = "HONEST"

\* PROP_HonestConserved — THE NON-VACUITY WITNESS: an all-HONEST daemon
\* over a conserving committed snapshot always reaches CONSERVED. The
\* gates admit the honest path; they do not vacuously reject everything.
\* Antecedent inits exist in the enumerated universe (e.g. the all-zero
\* snapshot + all-HONEST strategy), and probe M0 (header) independently
\* machine-confirms CONSERVED's reachability by falsification.
PROP_HonestConserved ==
    (AllHonest /\ HeadConserving) ~> (verdict = "CONSERVED")

\* PROP_HonestViolated — the defense-in-depth branch is live: an all-
\* HONEST daemon over an underflowing snapshot reaches VIOLATED (the
\* committed counters themselves break the identity — main.cpp:6496-6501).
PROP_HonestViolated ==
    (AllHonest /\ ~HeadConserving) ~> (verdict = "VIOLATED")

\* -----------------------------------------------------------------
\* §9. Non-vacuity probe M0 (NOT in the shipped .cfg — EXPECTED
\* FALSIFIED when checked; see the header probe table).
\* -----------------------------------------------------------------
\*
\* Checking this as an INVARIANT makes TLC exhibit a trace reaching
\* CONSERVED (the all-honest run), machine-confirming the honest path is
\* reachable — the falsify-on-mutant discipline. Run manually:
\*   add "Probe_ConservedUnreachable" to a scratch copy's INVARIANTS.
Probe_ConservedUnreachable == verdict /= "CONSERVED"

=============================================================================
\* Cross-references.
\*
\* SupplyProofSoundness.md (FB70 prose companion) ->
\*   SU-1 (committee-signed state_root binds the c: leaf — the S2 root
\*   gates), SU-2 (Merkle + value-hash bind — the S3 bind gate), SU-3
\*   (the five-counter A1 identity recompute — S1 + INV_VerdictFaithful),
\*   SU-4 (leaf_count root-wrapper binding — inside the FB44 abstraction).
\*   Its §3 single-root precondition is exactly the anchor discipline
\*   this module pins.
\*
\* C++ enforcement (light/main.cpp::cmd_supply_trustless, :6175-6578):
\*   kCounters order (:6205-6208), R51 atomic value_hex (:6288-6308),
\*   canonical-key + value-hash bind (:6334-6369 / BindOk), stale-height
\*   gate (:6380-6385), S-042 committee binding of the first counter's
\*   root (:6396-6423 / AttestedRootAt), split-root guard (:6424-6438 /
\*   RejectReason SPLIT_ROOT), merkle verify (:6440-6448, FB44
\*   abstraction), underflow guard + A1 recompute + verdict (:6486-6519 /
\*   Finalize), exit codes 0/2/3 (:6567-6573).
\*   src/chain/chain.cpp const_leaf (:380-384) + the five c: counters
\*   (:403-408) — the committed leaf encoding SHA256(u64_be(value));
\*   include/determ/chain/chain.hpp:443-449 expected_total (the A1 closed
\*   form Finalize recomputes); src/node/node.cpp rpc_state_proof "c"
\*   branch (:3305-3311) — the served proof envelope.
\*
\* Sibling specs (style template + abstraction sources):
\*   DAppRegistrationRead.tla (FB50) / UnstakeEligibilityRead.tla (FB53) /
\*       RegistrantRead.tla (FB60) — the single-leaf four-gate trustless
\*       readers; FB70 composes FIVE such reads under ONE anchor root.
\*   MerklePathVerify.tla (FB44) — the path-recompute soundness the
\*       accept abstraction rests on.
\*   FrostVerify.tla (FB23) — the committee-signature soundness behind
\*       AttestedRootAt.
\*   UnitarySupplyLedger.tla (FB-series ledger spec) — the apply-side A1
\*       identity maintenance; FB70 is its trustless READ dual.
\*
\* Runtime regression:
\*   tools/test_light_supply_trustless.sh — exercises the live
\*       supply-trustless pipeline (CONSERVED verdict + tamper arms) this
\*       module models.
=============================================================================
