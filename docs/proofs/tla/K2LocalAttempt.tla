--------------------------- MODULE K2LocalAttempt ---------------------------
(*
FB74 — TLA+ model of the experimental C99 two-participant commit/reveal
attempt: src/consensus/duel_state.c (state machine) and the completion step
in src/net/k2_net.c (VDF_EVALUATION -> COMPLETED after local evaluation).
Contract prose: docs/proofs/K2_VDF_Soundness.md. Added 2026-09-23 to replace
the withdrawn K=2 "1-of-2 fallback" rewrite of FB1 (Consensus.tla).

This is a LOCAL attempt, not a consensus protocol. The model states what the
code does and nothing more:

  * Both commitments must arrive before CommitDeadline (code: T+1000 ms);
    a missing commitment at the deadline aborts the attempt (SILENCE).
  * The reveal window opens only with BOTH commitments present; opening at or
    after RevealDeadline (code: T+2000 ms) aborts (INCOMPLETE).
  * A reveal that does not match its commitment aborts the attempt (INVALID).
    At the duel_state.c API a reveal at or after RevealDeadline is DROPPED and
    a duplicate commitment or reveal is refused (no state change).
  * The network driver (k2_net.c, fail_attempt) turns every non-success status
    from that API — including those drops and refusals — and every malformed
    frame, EOF, socket error, VDF failure or send failure into an abort of the
    open attempt, from COMMIT, AWAIT_REVEALS or VDF_EVAL (DriverAbort, cause
    DRIVER).
  * Evaluation starts only with BOTH matching reveals; at the deadline with a
    reveal missing, the attempt aborts (INCOMPLETE). There is no 1-of-2
    fallback and no replacement participant.
  * COMPLETED is a local computation result: nothing here finalizes a block,
    elects a participant, or authenticates a peer (no such variable exists).
  * Restart after ABORTED/COMPLETED is an explicit caller action (Start); the
    model bounds it with MaxAttempts.

Payload identity abstracts SHA-256 commitment binding: a participant reveals
either the payload it committed to or a different one. Time is a discrete
tick counter; the model is exact about which side of each deadline an action
happens on, which is what the code's `elapsed >= deadline` tests decide.

Invariants checked by TLC (tools/test_tla_model_check.sh):
  Inv_EvalNeedsBothMatching  evaluation/completion implies both commitments
                             and both matching reveals exist (no fallback).
  Inv_RevealNeedsBothCommits a stored reveal implies both commitments exist.
  Inv_AbortHasCause          ABORTED iff a terminal cause is recorded.
  Inv_CommitsBeforeDeadline  past the commit phase, every commitment arrived
                             strictly before CommitDeadline.
Liveness is deliberately NOT claimed: one silent participant prevents
completion of every attempt (K2_VDF_Soundness.md R1/R2).
*)
EXTENDS Naturals

CONSTANTS
    CommitDeadline,   \* ticks from attempt start (code: DUEL_COMMIT_TIMEOUT_MS)
    RevealDeadline,   \* ticks from attempt start (code: DUEL_REVEAL_WINDOW_MS)
    MaxAttempts       \* bound on explicit restarts, for model checking

ASSUME ConstantsOK ==
    /\ CommitDeadline \in Nat /\ CommitDeadline >= 1
    /\ RevealDeadline \in Nat /\ RevealDeadline > CommitDeadline
    /\ MaxAttempts \in Nat /\ MaxAttempts >= 1

Roles    == {"agg", "cont"}
Payloads == {"p1", "p2"}
NONE     == "none"

VARIABLES
    state,      \* "IDLE" | "COMMIT" | "AWAIT_REVEALS" | "VDF_EVAL" | "COMPLETED" | "ABORTED"
    t,          \* ticks since the current attempt started
    commit,     \* [Roles -> Payloads \cup {NONE}]
    commitAt,   \* [Roles -> tick of arrival, or RevealDeadline + 1 if none]
    reveal,     \* [Roles -> Payloads \cup {NONE}]
    cause,      \* NONE | "SILENCE" | "INCOMPLETE" | "INVALID" | "DRIVER"
    attempts

vars == <<state, t, commit, commitAt, reveal, cause, attempts>>

States == {"IDLE", "COMMIT", "AWAIT_REVEALS", "VDF_EVAL", "COMPLETED", "ABORTED"}
NoTick == RevealDeadline + 1

TypeOK ==
    /\ state \in States
    /\ t \in 0..RevealDeadline
    /\ commit \in [Roles -> Payloads \cup {NONE}]
    /\ commitAt \in [Roles -> 0..NoTick]
    /\ reveal \in [Roles -> Payloads \cup {NONE}]
    /\ cause \in {NONE, "SILENCE", "INCOMPLETE", "INVALID", "DRIVER"}
    /\ attempts \in 0..MaxAttempts

Init ==
    /\ state = "IDLE"
    /\ t = 0
    /\ commit = [r \in Roles |-> NONE]
    /\ commitAt = [r \in Roles |-> NoTick]
    /\ reveal = [r \in Roles |-> NONE]
    /\ cause = NONE
    /\ attempts = 0

Abort(c) == /\ state' = "ABORTED" /\ cause' = c

\* duel_state_start_commitment_phase: allowed from IDLE, COMPLETED, ABORTED; resets.
Start ==
    /\ state \in {"IDLE", "COMPLETED", "ABORTED"}
    /\ attempts < MaxAttempts
    /\ state' = "COMMIT"
    /\ t' = 0
    /\ commit' = [r \in Roles |-> NONE]
    /\ commitAt' = [r \in Roles |-> NoTick]
    /\ reveal' = [r \in Roles |-> NONE]
    /\ cause' = NONE
    /\ attempts' = attempts + 1

\* The monotonic clock advances while an attempt is open.
Tick ==
    /\ state \in {"COMMIT", "AWAIT_REVEALS"}
    /\ t < RevealDeadline
    /\ t' = t + 1
    /\ UNCHANGED <<state, commit, commitAt, reveal, cause, attempts>>

\* submit_commit: at/after the deadline it aborts; a duplicate is refused.
SubmitCommit(r, p) ==
    /\ state = "COMMIT"
    /\ IF t >= CommitDeadline
          THEN /\ Abort("SILENCE")
               /\ UNCHANGED <<t, commit, commitAt, reveal, attempts>>
          ELSE /\ commit[r] = NONE
               /\ commit' = [commit EXCEPT ![r] = p]
               /\ commitAt' = [commitAt EXCEPT ![r] = t]
               /\ UNCHANGED <<state, t, reveal, cause, attempts>>

\* duel_state_poll_commit_timeout
PollCommitTimeout ==
    /\ state = "COMMIT"
    /\ \E r \in Roles : commit[r] = NONE
    /\ t >= CommitDeadline
    /\ Abort("SILENCE")
    /\ UNCHANGED <<t, commit, commitAt, reveal, attempts>>

\* duel_state_start_reveal_window: needs both commitments.
StartRevealWindow ==
    /\ state = "COMMIT"
    /\ \A r \in Roles : commit[r] /= NONE
    /\ IF t >= RevealDeadline
          THEN /\ Abort("INCOMPLETE")
               /\ UNCHANGED <<t, commit, commitAt, reveal, attempts>>
          ELSE /\ state' = "AWAIT_REVEALS"
               /\ UNCHANGED <<t, commit, commitAt, reveal, cause, attempts>>

\* submit_reveal: at the state-machine API late reveals are dropped (no state
\* change, not modeled as a step) and a duplicate is refused; a mismatching
\* reveal aborts. The driver's reaction to drops and refusals is DriverAbort.
SubmitReveal(r, p) ==
    /\ state = "AWAIT_REVEALS"
    /\ t < RevealDeadline
    /\ reveal[r] = NONE
    /\ IF p = commit[r]
          THEN /\ reveal' = [reveal EXCEPT ![r] = p]
               /\ UNCHANGED <<state, t, commit, commitAt, cause, attempts>>
          ELSE /\ Abort("INVALID")
               /\ UNCHANGED <<t, commit, commitAt, reveal, attempts>>

\* duel_state_poll_buzzer
PollBuzzer ==
    /\ state = "AWAIT_REVEALS"
    /\ IF \A r \in Roles : reveal[r] /= NONE
          THEN /\ state' = "VDF_EVAL"
               /\ UNCHANGED <<t, commit, commitAt, reveal, cause, attempts>>
          ELSE /\ t >= RevealDeadline
               /\ Abort("INCOMPLETE")
               /\ UNCHANGED <<t, commit, commitAt, reveal, attempts>>

\* k2_net.c: local evaluation finished; no finality is attached.
FinishEvaluation ==
    /\ state = "VDF_EVAL"
    /\ state' = "COMPLETED"
    /\ UNCHANGED <<t, commit, commitAt, reveal, cause, attempts>>

\* k2_net.c fail_attempt: a non-success status, malformed frame, EOF, socket,
\* VDF or send failure aborts the open attempt.
DriverAbort ==
    /\ state \in {"COMMIT", "AWAIT_REVEALS", "VDF_EVAL"}
    /\ Abort("DRIVER")
    /\ UNCHANGED <<t, commit, commitAt, reveal, attempts>>

Next ==
    \/ Start
    \/ Tick
    \/ \E r \in Roles, p \in Payloads : SubmitCommit(r, p) \/ SubmitReveal(r, p)
    \/ PollCommitTimeout
    \/ StartRevealWindow
    \/ PollBuzzer
    \/ FinishEvaluation
    \/ DriverAbort

Spec == Init /\ [][Next]_vars

----------------------------------------------------------------------------
Inv_EvalNeedsBothMatching ==
    state \in {"VDF_EVAL", "COMPLETED"} =>
        \A r \in Roles : commit[r] /= NONE /\ reveal[r] = commit[r]

Inv_RevealNeedsBothCommits ==
    \A r \in Roles : reveal[r] /= NONE => \A q \in Roles : commit[q] /= NONE

Inv_AbortHasCause == (state = "ABORTED") <=> (cause /= NONE)

Inv_CommitsBeforeDeadline ==
    state \in {"AWAIT_REVEALS", "VDF_EVAL", "COMPLETED"} =>
        \A r \in Roles : commitAt[r] < CommitDeadline
=============================================================================
