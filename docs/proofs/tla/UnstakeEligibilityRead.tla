--------------------------- MODULE UnstakeEligibilityRead ---------------------------
(*
FB53 — TLA+ specification of the TRUSTLESS s:-NAMESPACE UNSTAKE-ELIGIBILITY
READER: the end-to-end `determ-light verify-unstake-eligibility <domain>`
pipeline that decides — WITHOUT trusting the serving daemon — whether an
account's locked stake would be unstakeable at the committee-verified head
height. Where FB50 (DAppRegistrationRead) reads a STATIC d:-namespace
registry value and binds it to a claimed entry, FB53 reads the s:-namespace
stake leaf AND then computes a HEIGHT-RELATIVE verdict: the same
`b.index >= unlock_height` predicate the validator enforces in
BlockValidator::check_tx, evaluated over the COMMITTEE-ANCHORED head height
H and the COMMITTEE-ANCHORED unlock_height — never the daemon's raw claim.

This is the read-side dual of the apply-side stake-unlock specs (FB8
StakeLifecycle, FB21 StakeForfeitureCascade, FB41 StakeRefundFlow): those
pin that the PRODUCER/VALIDATOR never refunds locked stake before
`height >= unlock_height` (the S-017 producer/chain-divergence closure);
FB53 pins that a LIGHT CLIENT can trustlessly PREDICT that same verdict
from a committee-signed state_root, and that no lying daemon can ever talk
the client into a false ELIGIBLE.

NOTE: no model-check this session — caller will TLC-validate. This module
is syntactically self-contained and ready for `tlc -config
UnstakeEligibilityRead.cfg UnstakeEligibilityRead.tla` once a companion
`.cfg` is supplied (one is shipped alongside).

Scope. A `verify-unstake-eligibility <domain>` read composes four trust
reductions, then evaluates ONE height-relative verdict over the two
committee-anchored facts the reductions expose:

  (1) ANCHOR  — the client recomputes the genesis hash locally and rejects
      any daemon whose block-0 hash differs (light/trustless_read.cpp::
      anchor_genesis). A daemon serving a DIFFERENT chain is refused before
      any stake datum is read.
  (2) HEAD    — the client verifies the committee-signed header chain to
      the tip and extracts BOTH (a) the tip's committed state_root and (b)
      the committee-attested head height H (light/main.cpp::cmd_verify_
      unstake_eligibility composes stake-trustless's verify_chain_to_head).
      The head height H is itself committee-anchored — the verdict's
      "current height" input is NOT the daemon's bare claim.
  (3) PATH    — the client fetches the `s:<domain>` state-proof and runs
      merkle_verify: the (key_bytes, value_hash) leaf at target_index in a
      leaf_count-leaf tree must recompute (with the proof siblings + the
      S-040 root-wrapper) to the trusted state_root. FB44 (MerklePathVerify)
      territory — abstracted here to a single PathOk predicate.
  (4) BIND    — the served leaf's `value_hash` must equal SHA256 of the
      CANONICAL StakeEntry field-encoding for the (locked, unlock_height)
      pair the daemon's `stake_info` cleartext claims:
        value_hash = SHA256( u64_be(locked) || u64_be(unlock_height) )
      (src/chain/chain.cpp:292-296, the stakes_ branch of
      build_state_leaves). WITHOUT the bind a daemon could serve a valid
      Merkle path for the RIGHT key + state_root but hand the client a
      (locked, unlock_height) pair that does NOT correspond to the committed
      leaf — e.g. claiming a matured unlock_height to manufacture a false
      ELIGIBLE. The bind closes this: the client recomputes
      SHA256(canonical_encoding(claimed)) and compares it to the served
      value_hash; a mismatch is UNVERIFIABLE.

  (5) VERDICT — THE NOVEL CRUX OF FB53. Once the four reductions expose the
      committee-anchored facts (locked, unlock_height, H), the client
      evaluates the SAME predicate the validator enforces — an UNSTAKE tx
      mined into the NEXT block (index H+1) succeeds iff
      `H + 1 >= unlock_height` (BlockValidator::check_tx; the S-017 gate).
      The verdict is a DERIVED FACT over the two anchored inputs, not a
      daemon assertion:
        NO-STAKE  : locked = 0 (or no s: leaf) — nothing to unstake.
        BONDED    : locked > 0 AND unlock_height = NONE (UINT64_MAX) — no
                    unlock scheduled; DEREGISTER must arm one first.
        ELIGIBLE  : locked > 0 AND unlock_height /= NONE AND H+1 >= unlock_height.
        LOCKED    : locked > 0 AND unlock_height /= NONE AND H+1 < unlock_height.

The load-bearing safety property (THE HEADLINE): a read EVER reports
ELIGIBLE only when ALL FOUR reductions passed (the daemon ran our chain,
served a committee-signed head, the s:<domain> Merkle path recomputes to
the trusted state_root, AND the served value_hash binds to the claimed
(locked, unlock_height)) AND the height-relative predicate H+1 >=
unlock_height genuinely holds over the COMMITTED stake leaf at the
COMMITTEE-ATTESTED head. No reachable read reports ELIGIBLE for a domain
whose committed unlock_height has NOT matured at H+1, and no subverted gate
ever yields ELIGIBLE — a failed gate is UNVERIFIABLE, never a verdict. This
is the no-false-ELIGIBLE contract: the trustless dual of the S-017 apply-
side no-early-unstake invariant (FB8 Inv_NoEarlyUnstake).

Eight theorems are pinned:

  (T-UE1) Four-Gate Soundness. Every read with a non-UNVERIFIABLE verdict
          passed all four gates (anchor /\ head /\ path /\ bind). No
          reachable verdict skips a gate. The headline no-trust-leak
          contract.
  (T-UE2) Anchor Gate. A read against a daemon whose block-0 hash differs
          from the locally-recomputed genesis hash is UNVERIFIABLE before
          any stake datum is consumed (anchor_genesis throw). No verdict
          ever has anchor = FALSE.
  (T-UE3) Head Gate. A read whose header chain to the tip is NOT committee-
          verified (a forged or unsigned head) is UNVERIFIABLE; neither the
          state_root NOR the head height H such a read would trust is used.
          No verdict ever has head_verified = FALSE.
  (T-UE4) Path Gate. A read whose s:<domain> Merkle path does NOT recompute
          to the trusted state_root is UNVERIFIABLE (the FB44 merkle_verify
          gate). No verdict ever has path_ok = FALSE.
  (T-UE5) Value-Hash Binding. A read whose claimed (locked, unlock_height)
          canonical encoding does NOT hash to the served value_hash is
          UNVERIFIABLE. Under collision resistance a match implies claimed =
          committed. No verdict ever has bind_ok = FALSE. This is the
          s:-namespace anti-substitution gate — a daemon cannot swap a
          matured unlock_height for the committed one.
  (T-UE6) No-False-ELIGIBLE (THE NOVEL CRUX). A read reports ELIGIBLE iff
          ALL FOUR gates pass AND the committed stake leaf has locked > 0,
          a non-NONE unlock_height, AND H+1 >= that unlock_height at the
          committee-attested head H. No reachable read reports ELIGIBLE for
          a domain whose COMMITTED unlock_height has not matured at H+1, and
          no subverted-gate read ever reports ELIGIBLE. The trustless dual
          of the S-017 / FB8 apply-side no-early-unstake invariant.
  (T-UE7) Verdict Faithfulness. Every non-UNVERIFIABLE verdict equals the
          verdict computed from the COMMITTED stake leaf (locked,
          unlock_height) against the committee-attested head H — never the
          daemon's raw claim. Derived from the bind gate (claimed =
          committed) + head gate (H is anchored): the four verdicts
          partition the committed-state x head-height space, so the reported
          verdict is a pure function of committed facts.
  (T-UE8) Determinism. Two identical reads (same domain, same daemon state,
          same head) produce the identical verdict. The four gate predicates
          + the height-relative classifier are pure functions of the read
          inputs against the fixed committed state.

The state machine. A single committed stake table (the chain's s: namespace
leaf domain at a fixed state-root) and a fixed committee-attested head
height H are set at Init. A non-deterministic Read action admits one
(domain, claimed (locked, unlock_height), daemon-honest flags) request per
step, runs it through the four-gate pipeline + the verdict classifier via
MakeRecord, appends a ReadRecord to a read log, increments read_count. The
invariants read this log to verify every non-UNVERIFIABLE verdict passed all
four gates (T-UE1) and equals the committed-state verdict (T-UE6 / T-UE7).

The four gates as pure-function predicates:

  AnchorOk(daemon)       : the daemon's block-0 hash matches the locally-
                           recomputed genesis hash. Per-daemon BOOLEAN flag
                           (the byte-level recompute is trustless_read.cpp's
                           job — anchor_genesis).
  HeadOk(daemon)         : the daemon's header chain to the tip is committee-
                           signed (FB23 + verify_chain_to_head). Per-daemon
                           BOOLEAN flag. When TRUE, the head height H AND the
                           state_root the path gate trusts are both genuine.
  PathOk(domain, daemon) : the daemon's s:<domain> state_proof answer is
                           honest — a Merkle path that recomputes to the
                           trusted state_root when a committed leaf exists
                           (FB44 merkle_verify), an honest not_found when
                           none does. A forged answer fails the gate.
  BindOk(domain, daemon) : SHA256(canonical_encoding(claimed)) =
                           committed_value_hash. Via the injective Encode
                           abstraction, BindOk holds iff the claimed
                           (locked, unlock_height) equals the committed pair;
                           vacuously TRUE for an absent domain (no leaf, so
                           the code never runs the bind on the not_found arm).

Variables:

  * `committed` — function Domains -> StakeEntry \cup {ABSENT}. The chain's
    s: namespace leaf domain at the fixed state-root: which domains have a
    stake leaf and (for each) the committed (locked, unlock_height) pair.
    Set once at Init; the pipeline checks claimed pairs against it. Models
    the build_state_leaves stakes_-branch output (chain.cpp:292-296).
  * `head` — Nat. The committee-attested head height H. Set once at Init;
    the verdict's "current height" input. The S-017 gate uses the NEXT-block
    index H+1 (an UNSTAKE tx mined at the verified head lands in block H+1),
    so the verdict predicate is H+1 >= unlock_height.
  * `read_log` — a Seq of ReadRecord. Each record tags the request (domain,
    claimed pair, the daemon's honest/forged flags), the four per-gate
    Booleans, and the resulting verdict. The invariants read this log.
  * `read_count` — Nat. Bounds read_log length for TLC tractability (one
    Read per step until MaxReads).

Modeling scope (kept tractable for TLC):

  * SHA-256 / the canonical StakeEntry encoding is modeled as an injective
    abstract constructor: Encode(entry) is a structured TERM, and two terms
    are equal IFF the entries are structurally identical. This is the
    standard collision-resistance abstraction (FB23 FrostVerify, FB26
    BlockchainStateIntegrity, FB44 MerklePathVerify, FB50 DAppRegistration
    Read use the same device). Under collision resistance, value_hash
    equality reduces to entry equality, so the bind gate (T-UE5) is EXACTLY
    claimed = committed.
  * A StakeEntry is a record [locked, unlock_height]. unlock_height = NONE
    models the UINT64_MAX "no unlock scheduled" sentinel (chain.cpp:707/811;
    a stake_table entry can exist with 0 locked + UINT64_MAX unlock_height).
    NONE is a single concrete value strictly greater than every reachable
    head + 1 (ConfigOK), so an unlock_height = NONE never matures — the
    BONDED verdict — exactly the apply-side "DEREGISTER must arm an unlock
    first" rule.
  * The anchor + head gates are per-daemon BOOLEAN flags. The byte-level
    genesis recompute is anchor_genesis (trustless_read.cpp); the committee-
    signature soundness is FB23 (FrostVerify.tla). When head_honest = TRUE,
    BOTH the state_root AND the head height H are genuine — FB53 reads the
    single anchored head `head` for the verdict's height input. A forged
    head is rejected (UNVERIFIABLE) before the verdict is computed, so a
    lying daemon cannot manufacture a false ELIGIBLE by inflating H.
  * The path gate is TRUE iff the daemon answers the s:<domain> state_proof
    honestly: a path that recomputes to the state_root when a committed leaf
    exists, an honest not_found when none does; a forged answer is path_ok =
    FALSE. The cryptographic path soundness is FB44 (MerklePathVerify.tla).
    A domain with no committed s: leaf has no value_hash to prove or bind
    (the bind gate is vacuous there), so the pipeline reports NO-STAKE (the
    documented "sound state_proof not_found at the verified head" ->
    NO-STAKE branch, light/main.cpp — the daemon-asserted arm of the
    two-arm NO-STAKE split), NOT a forged membership — the
    no-fabricated-stake analog of FB43's INV_AbsenceSound.

The verdict classifier (the novel fifth step):

  Verdict(committed_entry, H) ==
    IF four gates fail            -> "UNVERIFIABLE"   (exit 3)
    ELSE IF committed = ABSENT
         \/ committed.locked = 0  -> "NO-STAKE"
    ELSE IF committed.unlock_height = NONE
                                  -> "BONDED"
    ELSE IF H + 1 >= committed.unlock_height
                                  -> "ELIGIBLE"       (S-017 gate matured)
    ELSE                          -> "LOCKED"         (H+1 < unlock_height)

The "+ 1" is the load-bearing detail: an UNSTAKE tx submitted against the
verified head H is mined into block H+1, and BlockValidator::check_tx gates
on `b.index >= unlock_height` where b.index = H+1. FB53 re-runs that exact
arithmetic over the COMMITTED unlock_height so the ELIGIBLE verdict matches
what the validator would actually accept — never an off-by-one optimistic
read.

TLC verifies the eight invariants at every reachable state across every
reachable interleaving of Read actions over the bounded domain x
claimed-entry x daemon-flag universe against the fixed committed stake table
and head height.

To check (assuming TLC installed):
  $ tlc UnstakeEligibilityRead.tla -config UnstakeEligibilityRead.cfg

Recommended config (state space ~3x10^5, minutes — the order-recording
read_log grows as (|Domains| x |DaemonFlags|)^MaxReads, so MaxReads and the
StakeEntry universe stay small):
  Domains = {d1, d2}, Lockeds = {0, 1}, Unlocks = {2} (with NONE a separate
  sentinel > MaxHead + 1), MaxHead = 2 (so H+1 lands below, exactly at, and
  above the unlock height — all three relations of the S-017 boundary),
  MaxReads = 2 (every outcome class is reachable at depth 1; depth 2 gives
  PROP_Determinism its repeated-read pairs), committed quantified over all
  mappings (so an absent-domain NO-STAKE read is reachable), and a
  daemon-flag universe spanning honest + each single-gate-forged variant
  (anchor-forged, head-forged, path-forged, bind-forged).

Cross-references:
  - docs/proofs/tla/DAppRegistrationRead.tla (FB50) — the d:-namespace
    trustless reader FB53 mirrors. FB50 binds a STATIC registry value; FB53
    binds the s:-leaf (locked, unlock_height) AND adds the height-relative
    verdict classifier (the novel fifth step FB50 lacks). The four-gate
    pipeline + injective-Encode abstraction + INV-* style are shared.
  - docs/proofs/tla/StakeLifecycle.tla (FB8) — the APPLY-side no-early-
    unstake invariant (Inv_NoEarlyUnstake: no UNSTAKE refunds locked stake
    while height < unlock_height). FB53 is the READ-side dual: a light client
    PREDICTS that same gate from a committed leaf. The unlock_height FB53
    reads is the one FB8's Deregister action armed.
  - docs/proofs/tla/StakeRefundFlow.tla (FB41) / StakeForfeitureCascade.tla
    (FB21) — sibling apply-side stake-unlock specs (refund timing / cascade
    ordering). FB53 consumes the committed unlock_height those specs produce
    and re-derives the unstake-eligibility verdict trustlessly.
  - docs/proofs/tla/CompositeKeyStateProof.tla (FB43) — the SERVER-side key
    reconstruction over all ten namespaces (right key); FB53 reads the s:
    namespace leaf whose key FB43 pins canonical.
  - docs/proofs/tla/MerklePathVerify.tla (FB44) — the CLIENT-side path
    verification (right path); FB53's PathOk predicate abstracts FB44's
    accept/reject decision. Composition: FB43 (right key) + FB44 (right
    path) + FB53 (right value + right verdict) = a fully trustless
    s:-namespace unstake-eligibility read.
  - docs/proofs/tla/FrostVerify.tla (FB23) — the committee-signature verify
    over the state_root + head; FB53's HeadOk predicate abstracts FB23's
    accept/reject decision. The head height H AND the state_root FB53's path
    gate verifies against are the ones FB23 confirms committee-signed.
  - light/main.cpp::cmd_verify_unstake_eligibility — the C++ reader (the
    ELIGIBLE / LOCKED / BONDED / NO-STAKE / UNVERIFIABLE verdict pipeline,
    re-running the validator's `b.index >= unlock_height` predicate over the
    committee-attested unlock_height).
  - light/trustless_read.cpp::anchor_genesis (AnchorOk) / verify_chain_to_
    head (HeadOk — extracts BOTH state_root and head height H).
  - src/chain/chain.cpp:292-296 — build_state_leaves stakes_ branch; the
    canonical (locked, unlock_height) field-encoding the value_hash commits.
    Encode is the spec-layer projection of this hash builder.
  - src/chain/block.cpp BlockValidator::check_tx — the apply-side S-017 gate
    (`b.index >= unlock_height`) FB53's verdict classifier mirrors.
  - tools/test_light_verify_unstake_eligibility.sh / tools/test_light_stake_
    trustless.sh — the runtime surface exercising the s: namespace read.
*)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Domains,    \* set of account / operator domain identifiers
    Lockeds,    \* finite set of locked-stake amounts (e.g. {0, 1})
    Unlocks,    \* finite set of concrete (non-NONE) unlock_height values
    NONE,       \* "no unlock scheduled" sentinel (UINT64_MAX); > MaxHead + 1
    MaxHead,    \* upper bound on the committee-attested head height H
    MaxReads    \* bound on read_log length (TLC tractability)

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ Cardinality(Lockeds) >= 1
    /\ Cardinality(Unlocks) >= 1
    /\ Lockeds \subseteq Nat
    /\ Unlocks \subseteq Nat
    /\ MaxHead  \in Nat /\ MaxHead  >= 0
    \* NONE must be strictly larger than every reachable head+1 so that an
    \* unlock_height = NONE NEVER matures (the BONDED verdict). It must also
    \* sit outside the concrete Unlocks set so the classifier's
    \* `unlock_height = NONE` test is unambiguous.
    /\ NONE \in Nat /\ NONE > MaxHead + 1
    /\ NONE \notin Unlocks
    /\ MaxReads \in Nat /\ MaxReads >= 1

\* -----------------------------------------------------------------
\* §1. StakeEntry shape + the ABSENT sentinel + verdict tags.
\* -----------------------------------------------------------------
\*
\* A StakeEntry is the committed s:-namespace leaf FB53 reads. The model
\* carries exactly the two value-hashed fields:
\*   locked        — locked-stake amount (chain.cpp:294, b.append(st.locked)).
\*   unlock_height — armed unlock height, or NONE (UINT64_MAX) if no UNSTAKE
\*                   window is scheduled (chain.cpp:295,
\*                   b.append(st.unlock_height)).
StakeEntry == [locked:        Lockeds,
               unlock_height: Unlocks \cup {NONE}]

\* ABSENT marks "no s:<domain> leaf was committed for this domain." A read
\* against an absent domain has no value_hash to prove or bind, so the
\* pipeline reports NO-STAKE (the sound state_proof not_found branch), NOT a
\* forged membership.
ABSENT == [absent |-> TRUE]

CommittedShape == StakeEntry \cup {ABSENT}

\* The five sound verdicts. UNVERIFIABLE is the fail-closed outcome for any
\* subverted gate (exit 3); the other four partition the committed-state x
\* head-height space.
Verdicts == {"ELIGIBLE", "LOCKED", "BONDED", "NO-STAKE", "UNVERIFIABLE"}

\* -----------------------------------------------------------------
\* §2. Encode — the injective canonical StakeEntry encoding (abstract).
\* -----------------------------------------------------------------
\*
\* value_hash = SHA256( u64_be(locked) || u64_be(unlock_height) )
\* (src/chain/chain.cpp:292-296). Under SHA-256 collision/second-preimage
\* resistance, two value_hashes are equal IFF the encoded (locked,
\* unlock_height) pairs are identical. We model Encode as a structured TERM
\* (the entry record itself, tagged): TLA+ record equality is structural, so
\* Encode(e1) = Encode(e2) <=> e1 = e2 — exactly the injective-encoding
\* abstraction (FB23 / FB26 / FB44 / FB50 use the same device).
Encode(e) == <<"stake_leaf", e>>

\* -----------------------------------------------------------------
\* §3. Variables.
\* -----------------------------------------------------------------
\*
\* Declared BEFORE the gate predicates (§4): PathOk / BindOk / Classify
\* read the `committed` state variable, and TLA+ requires declaration
\* before use.

VARIABLES
    committed,    \* function Domains -> CommittedShape (the s: leaf domain)
    head,         \* Nat: the committee-attested head height H
    read_log,     \* Seq(ReadRecord)
    read_count    \* Nat (bounds read_log for TLC)

vars == <<committed, head, read_log, read_count>>

\* -----------------------------------------------------------------
\* §4. The four trust-reduction gates as pure-function predicates.
\* -----------------------------------------------------------------
\*
\* A daemon is modeled by three honest/forged Booleans plus the claimed
\* (locked, unlock_height) pair it serves. The gates read these flags + the
\* fixed committed stake table. A read produces a sound verdict iff ALL FOUR
\* gates pass; otherwise UNVERIFIABLE.
\*
\* DaemonFlags shape:
\*   anchor_honest : the daemon's block-0 hash matches our genesis hash.
\*   head_honest   : the daemon's header chain to the tip is committee-signed
\*                   (FB23 / verify_chain_to_head); BOTH the state_root AND
\*                   the head height H are genuine when TRUE.
\*   path_honest   : the daemon answers the s:<domain> state_proof honestly —
\*                   a Merkle path that recomputes to the committed state_root
\*                   when a leaf exists (FB44), an honest not_found when none
\*                   does.
\*   claimed       : the StakeEntry the daemon claims is the committed leaf
\*                   (the (locked, unlock_height) the client BIND-checks
\*                   against the served value_hash). A forged claim differs
\*                   from the committed entry.
DaemonFlags == [anchor_honest : BOOLEAN,
                head_honest   : BOOLEAN,
                path_honest   : BOOLEAN,
                claimed       : StakeEntry]

\* AnchorOk(daemon) — the daemon ran our chain (block-0 hash matches the
\* locally-recomputed genesis hash). trustless_read.cpp::anchor_genesis.
AnchorOk(daemon) == daemon.anchor_honest = TRUE

\* HeadOk(daemon) — the daemon's header chain to the tip is committee-signed;
\* the state_root AND the head height H the verdict trusts are genuine. FB23
\* + verify_chain_to_head (trustless_read.cpp).
HeadOk(daemon) == daemon.head_honest = TRUE

\* PathOk(domain, daemon) — the daemon's s:<domain> state_proof answer is
\* honest: a Merkle path that recomputes to the trusted state_root when the
\* domain HAS a committed leaf (FB44 merkle_verify), or an honest not_found
\* when it has NONE. A forged answer (a path that does not recompute, or any
\* non-not_found refusal) is PathOk FALSE -> UNVERIFIABLE
\* (read_stake_trustless rethrows every non-not_found failure). The honest
\* not_found routes the absent domain to NO-STAKE in the classifier — the
\* daemon-asserted arm of the code's two-arm NO-STAKE split
\* (light/main.cpp have_stake = false; NegativeVerdictSoundness.md
\* NV-2/NV-3), not a forged-membership accept.
PathOk(domain, daemon) == daemon.path_honest = TRUE

\* BindOk(domain, daemon) — the s:-NAMESPACE anti-substitution gate. The
\* served value_hash equals SHA256(canonical_encoding(claimed)). Under the
\* injective-Encode abstraction, this holds iff the claimed (locked,
\* unlock_height) equals the committed pair: a daemon that serves a forged
\* claim (e.g. a matured unlock_height to fake ELIGIBLE) produces a
\* recomputed hash Encode(claimed) /= Encode(committed) = committed
\* value_hash, so the bind fails. An absent domain has no leaf, value_hash,
\* or stake_info cleartext — the code never runs the bind on the not_found
\* arm — so BindOk is vacuously TRUE there (the path gate already decided
\* honest-not_found vs forged).
\*
\* src/chain/chain.cpp:292-296 commits value_hash = Encode(committed); the
\* client recomputes Encode(claimed) and compares. THE crux of T-UE5 closing
\* the unlock_height-substitution attack.
BindOk(domain, daemon) ==
    \/ committed[domain] = ABSENT
    \/ Encode(daemon.claimed) = Encode(committed[domain])

\* AllGatesOk(domain, daemon) — the conjunction of the four trust
\* reductions. A read produces a sound (non-UNVERIFIABLE) verdict iff this
\* holds; otherwise the read fails closed to UNVERIFIABLE.
AllGatesOk(domain, daemon) ==
    /\ AnchorOk(daemon)
    /\ HeadOk(daemon)
    /\ PathOk(domain, daemon)
    /\ BindOk(domain, daemon)

\* -----------------------------------------------------------------
\* §5. The verdict classifier — the NOVEL fifth step.
\* -----------------------------------------------------------------
\*
\* Once the four reductions expose the committed (locked, unlock_height) and
\* the committee-attested head H, the verdict re-runs the SAME predicate the
\* validator enforces in BlockValidator::check_tx: an UNSTAKE tx mined into
\* the NEXT block (index H+1) succeeds iff `H + 1 >= unlock_height` (the
\* S-017 gate). Because the gates passed, `committed[domain]` is the genuine
\* committed leaf and H is the genuine committee-attested head — the verdict
\* is a pure function of committed facts, never the daemon's raw claim.
\*
\* When the gates do NOT all pass, the read fails closed to UNVERIFIABLE —
\* NEVER an optimistic verdict. The NO-STAKE branch is the code's TWO-ARM
\* split (light/main.cpp): leaf-absent (an honest not_found — the
\* daemon-asserted arm) and leaf-present-with-locked = 0 (the committee-
\* anchored cryptographic arm) both route to NO-STAKE; an unscheduled unlock
\* (NONE) routes to BONDED.
Classify(domain, daemon, H) ==
    IF ~AllGatesOk(domain, daemon)
        THEN "UNVERIFIABLE"
    ELSE IF committed[domain] = ABSENT \/ committed[domain].locked = 0
        THEN "NO-STAKE"
    ELSE IF committed[domain].unlock_height = NONE
        THEN "BONDED"
    ELSE IF H + 1 >= committed[domain].unlock_height
        THEN "ELIGIBLE"
    ELSE "LOCKED"

\* -----------------------------------------------------------------
\* §6. ReadRecord shape + the MakeRecord pipeline.
\* -----------------------------------------------------------------
\*
\* Each Read appends one ReadRecord: the request (domain + daemon flags +
\* claimed entry), the four per-gate Booleans, and the resulting verdict.
\* The invariants read this log.

ReadRecord == [
    domain  : Domains,
    daemon  : DaemonFlags,
    anchor  : BOOLEAN,
    head    : BOOLEAN,
    path    : BOOLEAN,
    bind    : BOOLEAN,
    verdict : Verdicts
]

\* MakeRecord(domain, daemon, H): run the four-gate pipeline + the verdict
\* classifier. The verdict is UNVERIFIABLE unless ALL FOUR gates pass — the
\* trustless-read fail-closed contract: a sound verdict is reported iff the
\* daemon ran our chain (anchor) AND served a committee-signed head (head)
\* AND answered the s:<domain> state_proof honestly (path — a recomputing
\* Merkle path for a present leaf, an honest not_found for an absent one)
\* AND the served value_hash binds to the claimed pair's canonical encoding
\* (bind — vacuous on the absent/not_found arm). The ELIGIBLE / LOCKED /
\* BONDED / NO-STAKE split is then the height-relative classifier over the
\* committed leaf.
MakeRecord(domain, daemon, H) ==
    LET a == AnchorOk(daemon)
        h == HeadOk(daemon)
        p == PathOk(domain, daemon)
        b == BindOk(domain, daemon)
    IN [ domain  |-> domain,
         daemon  |-> daemon,
         anchor  |-> a,
         head    |-> h,
         path    |-> p,
         bind    |-> b,
         verdict |-> Classify(domain, daemon, H) ]

\* -----------------------------------------------------------------
\* §7. Initial state.
\* -----------------------------------------------------------------
\*
\* The committed stake table is fixed at Init: each domain either maps to a
\* committed StakeEntry or to ABSENT. The committee-attested head height H is
\* fixed in 0..MaxHead. The model leaves both to the .cfg (Init quantifies
\* over the legal shapes) so TLC explores reads against committed + absent
\* domains and across the full head-height range — including heads below,
\* at, and above each unlock_height (so all four sound verdicts are
\* reachable). read_log starts empty; read_count starts at 0.
Init ==
    /\ committed \in [Domains -> CommittedShape]
    /\ head \in 0..MaxHead
    /\ read_log   = <<>>
    /\ read_count = 0

\* -----------------------------------------------------------------
\* §8. Actions.
\* -----------------------------------------------------------------

\* Read(domain, daemon): the headline action — admit one (domain,
\* daemon-flags + claimed-entry) request, run the four-gate pipeline + the
\* verdict classifier via MakeRecord against the fixed committee-attested
\* head, append one ReadRecord to read_log, increment read_count. Models one
\* `determ-light verify-unstake-eligibility <domain>` invocation against a
\* (possibly adversarial) daemon. The committed stake table + head are
\* read-only (the chain state is fixed at this state-root + head).
Read(domain, daemon) ==
    /\ domain \in Domains
    /\ daemon \in DaemonFlags
    /\ read_count < MaxReads
    /\ read_log'   = Append(read_log, MakeRecord(domain, daemon, head))
    /\ read_count' = read_count + 1
    /\ UNCHANGED <<committed, head>>

\* Saturate: stutter once read_count reaches MaxReads. TLC bounds the state
\* space; the invariants are evaluated at every reachable state along the
\* way.
Saturate ==
    /\ read_count >= MaxReads
    /\ UNCHANGED vars

Next ==
    \/ \E domain \in Domains, daemon \in DaemonFlags : Read(domain, daemon)
    \/ Saturate

Spec == Init /\ [][Next]_vars
             /\ WF_vars(\E domain \in Domains, daemon \in DaemonFlags :
                            Read(domain, daemon))

\* -----------------------------------------------------------------
\* §9. Type invariant.
\* -----------------------------------------------------------------

INV_TypeOK ==
    /\ committed  \in [Domains -> CommittedShape]
    /\ head       \in 0..MaxHead
    /\ read_log   \in Seq(ReadRecord)
    /\ read_count \in Nat
    /\ read_count <= MaxReads
    /\ Len(read_log) = read_count

\* -----------------------------------------------------------------
\* §10. Invariants — the eight T-UE1..T-UE8 claims.
\* -----------------------------------------------------------------

\* INV_FourGateSound (T-UE1) — the headline no-trust-leak contract. Every
\* read with a non-UNVERIFIABLE verdict passed ALL FOUR gates. No reachable
\* sound verdict skips a gate.
\*
\* Structural witness: MakeRecord sets verdict = UNVERIFIABLE unless
\* AllGatesOk (anchor /\ head /\ path /\ bind). So verdict /= UNVERIFIABLE
\* implies all four per-gate Booleans are TRUE.
INV_FourGateSound ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       (e.verdict /= "UNVERIFIABLE")
       => (e.anchor /\ e.head /\ e.path /\ e.bind)

\* INV_AnchorGate (T-UE2) — a read against a daemon that does NOT run our
\* chain fails closed. No sound verdict has anchor = FALSE.
\*
\* Structural witness: AnchorOk(daemon) = daemon.anchor_honest; a forged
\* anchor makes anchor = FALSE, so Classify returns UNVERIFIABLE.
\* trustless_read.cpp::anchor_genesis (the GENESIS HASH MISMATCH throw).
INV_AnchorGate ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       (e.verdict /= "UNVERIFIABLE") => e.anchor

\* INV_HeadGate (T-UE3) — a read whose header chain is not committee-verified
\* fails closed; neither the state_root NOR the head height H such a read
\* would trust is used. No sound verdict has head = FALSE.
\*
\* Structural witness: HeadOk(daemon) = daemon.head_honest; a forged head
\* makes head = FALSE, so Classify returns UNVERIFIABLE. FB23 (FrostVerify) +
\* verify_chain_to_head. This is what stops a lying daemon from inflating H
\* to manufacture a false ELIGIBLE.
INV_HeadGate ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       (e.verdict /= "UNVERIFIABLE") => e.head

\* INV_PathGate (T-UE4) — a read whose s:<domain> Merkle path does not
\* recompute to the trusted state_root fails closed. No sound verdict has
\* path = FALSE.
\*
\* Structural witness: PathOk is the honest state_proof answer (a recomputing
\* path for a present leaf, an honest not_found for an absent one); a forged
\* answer makes path = FALSE -> UNVERIFIABLE. FB44 merkle_verify.
INV_PathGate ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       (e.verdict /= "UNVERIFIABLE") => e.path

\* INV_BindGate (T-UE5) — THE s:-NAMESPACE anti-substitution invariant. A
\* read whose claimed (locked, unlock_height) canonical encoding does NOT
\* hash to the served value_hash fails closed. No sound verdict has bind =
\* FALSE.
\*
\* Structural witness: for a present leaf, BindOk requires Encode(claimed) =
\* Encode(committed[domain]); a forged claim (e.g. a matured unlock_height to
\* fake ELIGIBLE) makes bind = FALSE -> UNVERIFIABLE. For an absent domain
\* the bind is vacuous (no value_hash exists; the code never runs it).
\* src/chain/chain.cpp:292-296 (the canonical encoding the value_hash
\* commits).
INV_BindGate ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       (e.verdict /= "UNVERIFIABLE") => e.bind

\* INV_NoFalseEligible (T-UE6) — THE NOVEL CRUX. A read reports ELIGIBLE iff
\* ALL FOUR gates pass AND the committed stake leaf has locked > 0, a
\* non-NONE unlock_height, AND H+1 >= that unlock_height at the committee-
\* attested head. No reachable read reports ELIGIBLE for a domain whose
\* COMMITTED unlock_height has not matured at H+1, and no subverted-gate read
\* ever reports ELIGIBLE.
\*
\* This is the trustless dual of the S-017 / FB8 apply-side no-early-unstake
\* invariant: just as the validator never refunds locked stake before
\* height >= unlock_height, the light client never PREDICTS unstakeability
\* before H+1 >= unlock_height over the COMMITTED leaf.
\*
\* Structural witness: Classify returns ELIGIBLE only in the innermost
\* branch, which requires AllGatesOk (so all four gate Booleans TRUE),
\* committed[domain] /= ABSENT, locked /= 0, unlock_height /= NONE, AND
\* H+1 >= unlock_height. The bind gate forces committed[domain] = claimed,
\* so the unlock_height the predicate uses is the COMMITTED one.
INV_NoFalseEligible ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       (e.verdict = "ELIGIBLE")
       => /\ e.anchor /\ e.head /\ e.path /\ e.bind
          /\ committed[e.domain] /= ABSENT
          /\ committed[e.domain].locked > 0
          /\ committed[e.domain].unlock_height /= NONE
          /\ head + 1 >= committed[e.domain].unlock_height

\* INV_VerdictFaithful (T-UE7) — every non-UNVERIFIABLE verdict equals the
\* verdict computed from the COMMITTED stake leaf against the committee-
\* attested head H — never the daemon's raw claim.
\*
\* Derivation: a sound verdict has all four gates TRUE (INV_FourGateSound),
\* so for a present leaf BindOk holds -> daemon.claimed = committed[domain]
\* (injective Encode), and the absent arm's NO-STAKE reads no claim at all.
\* Classify reads committed[domain] (NOT daemon.claimed) for the locked /
\* unlock_height tests, so the reported verdict is exactly the committed-
\* state verdict. We assert the standing equality: the recorded verdict
\* equals Classify recomputed from committed + head. Because committed + head
\* are fixed and Classify is a pure function, this is a state predicate TLC
\* checks at every reachable state.
INV_VerdictFaithful ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       e.verdict = Classify(e.domain, e.daemon, head)

\* INV_NoEligibleOnAbsent (T-UE4 + T-UE6, absence corollary) — a read for an
\* absent domain (no committed s:<domain> leaf) is never ELIGIBLE (nor any
\* stake-bearing verdict). An honest not_found routes the absent domain to
\* the classifier's NO-STAKE branch (the daemon-asserted arm of the two-arm
\* split); a forged state_proof answer fails the path gate -> UNVERIFIABLE.
\* Neither is ever ELIGIBLE. The no-fabricated-stake invariant at the
\* application layer (the analog of FB43 INV_AbsenceSound / FB50
\* INV_NoAbsentAccept).
INV_NoEligibleOnAbsent ==
    \A i \in 1..Len(read_log) :
       LET e == read_log[i] IN
       (e.verdict = "ELIGIBLE") => (committed[e.domain] /= ABSENT)

\* -----------------------------------------------------------------
\* §11. Temporal properties.
\* -----------------------------------------------------------------

\* PROP_EventualAnswer — under fairness on Read, the read_log always
\* eventually grows until saturation. The pipeline always terminates with a
\* verdict (one of the five) — it never hangs on a read. The no-stuck-read
\* liveness contract.
PROP_EventualAnswer ==
    (read_count < MaxReads)
    ~> (read_count > 0 /\ Len(read_log) = read_count)

\* PROP_Determinism (T-UE8) — the four-gate pipeline + the height-relative
\* classifier is a pure function of (domain, daemon, head) against the fixed
\* committed stake table. Stated as a standing invariant over the log: any
\* two records with the same (domain, daemon) have the identical four per-
\* gate Booleans AND the identical verdict. Since committed + head are fixed
\* at Init and MakeRecord is deterministic, identical reads always produce
\* identical records.
PROP_Determinism ==
    \A i, j \in 1..Len(read_log) :
       (/\ read_log[i].domain = read_log[j].domain
        /\ read_log[i].daemon = read_log[j].daemon)
       => (/\ read_log[i].anchor  = read_log[j].anchor
           /\ read_log[i].head    = read_log[j].head
           /\ read_log[i].path    = read_log[j].path
           /\ read_log[i].bind    = read_log[j].bind
           /\ read_log[i].verdict = read_log[j].verdict)

\* -----------------------------------------------------------------
\* §12. Soundness commentary — what TLC checks vs. the C++ reader.
\* -----------------------------------------------------------------
\*
\* The trustless unstake-eligibility read composes four trust reductions,
\* each of which a malicious daemon could subvert independently, then
\* evaluates ONE height-relative verdict over the two committee-anchored
\* facts (committed unlock_height + attested head H). FB53 pins the
\* COMPOSITION + VERDICT obligation: a sound verdict requires ALL FOUR gates,
\* so subverting any one fails closed to UNVERIFIABLE — never an optimistic
\* ELIGIBLE. TLC enumerates every reachable interleaving of reads over the
\* bounded domain x daemon-flag x head universe — including the four single-
\* gate-forged daemon variants AND heads below/at/above each unlock_height —
\* and confirms the eight invariants hold against the fixed committed table.
\*
\* The crux is INV_NoFalseEligible (T-UE6): the s:-namespace no-false-
\* ELIGIBLE guarantee. FB43 (CompositeKeyStateProof) pins that the served KEY
\* is canonical; FB44 (MerklePathVerify) pins that the served PATH recomputes
\* to the state_root; FB53's BindOk (T-UE5) pins that the served VALUE binds
\* to the claimed (locked, unlock_height). But a daemon that serves the RIGHT
\* key + a VALID path + an HONESTLY-bound leaf could STILL try to mislead the
\* client about unstakeability by lying about the CURRENT HEIGHT — claiming a
\* head H' > the real head so that H'+1 >= unlock_height appears to hold. The
\* head gate (T-UE3) closes this: the verdict's "current height" input is the
\* COMMITTEE-ATTESTED head H, not the daemon's bare claim, so a forged head
\* is UNVERIFIABLE before the verdict is computed. Both inputs to the S-017
\* predicate (unlock_height via bind, H via head) are committee-anchored,
\* hence the verdict cannot be faked:
\*
\*   FB43 (right key) + FB44 (right path) + FB53 (right value + right height
\*       + right verdict) = a fully trustless s:-namespace unstake-
\*       eligibility read.
\*
\* What this spec adds beyond the apply-side FB8 / FB21 / FB41: those pin
\* that the PRODUCER/VALIDATOR never refunds locked stake before
\* height >= unlock_height (the S-017 no-early-unstake gate). FB53 pins that
\* a LIGHT CLIENT can trustlessly PREDICT that same gate's verdict from a
\* committee-signed state_root — the read-side dual. The committed
\* unlock_height FB53 reads is exactly the one FB8's Deregister action armed;
\* FB53's ELIGIBLE verdict fires iff the validator would actually accept the
\* UNSTAKE at block H+1.
\*
\* What this spec adds beyond the sibling read FB50 (DAppRegistrationRead):
\* FB50 binds a STATIC registry value and accepts/rejects. FB53 binds the
\* s:-leaf AND adds the HEIGHT-RELATIVE verdict classifier (NO-STAKE / BONDED
\* / ELIGIBLE / LOCKED), re-running the validator's `b.index >= unlock_height`
\* arithmetic with the +1 next-block offset over the committee-attested head.
\* The "+1" is load-bearing: an off-by-one optimistic read would report
\* ELIGIBLE one block early, which the validator would then reject — FB53's
\* classifier mirrors the apply-side arithmetic exactly so the prediction is
\* sound.
\*
\* What the spec does NOT check (consistent with the sibling specs' scope
\* notes + the collision-resistance abstraction):
\*   * The byte-level SHA-256 / canonical encoding. Modeled as an injective
\*     term constructor (FB23 / FB26 / FB44 / FB50 use the same device). The
\*     concrete encoding is exercised by tools/test_light_stake_trustless.sh
\*     + tools/test_light_verify_unstake_eligibility.sh.
\*   * The Merkle-path bytes. PathOk abstracts FB44 (MerklePathVerify)'s
\*     accept/reject decision; the byte-level walk soundness is FB44.
\*   * The committee-signature bytes + the header-chain walk to the head.
\*     HeadOk abstracts FB23 (FrostVerify)'s accept/reject decision over the
\*     state_root AND the head height; the Ed25519/FROST verify soundness is
\*     FB23, the prev_hash walk is verify_chain_to_head.
\*   * Non-membership. An absent domain returns NO-STAKE (or UNVERIFIABLE if
\*     the daemon forges a path it cannot bind). The not_found arm is modeled
\*     HONEST (path_honest = TRUE) — a lying not_found for a COMMITTED domain
\*     (a false NO-STAKE) is the documented daemon-asserted-negative gap
\*     ((H-neg), NegativeVerdictSoundness.md NV-2/NV-3) and is NOT modeled;
\*     trustless non-membership requires the documented SMT migration and is
\*     out of scope (same boundary as FB43 T-CK5 / FB50 INV_NoAbsentAccept).
\*   * The apply-side stake mutation. How committed[domain] came to hold its
\*     (locked, unlock_height) is FB8 / FB21 / FB41 territory; FB53 reads a
\*     fixed committed table at a single state-root + head.

============================================================================
\* Cross-references.
\*
\* DAppRegistrationRead.tla (FB50) ->
\*   The d:-namespace trustless reader FB53 mirrors. FB50 binds a STATIC
\*       registry value (accept/reject); FB53 binds the s:-leaf (locked,
\*       unlock_height) AND adds the height-relative verdict classifier (the
\*       novel fifth step). Shared: four-gate pipeline, injective-Encode
\*       abstraction, INV-* state-machine style.
\*
\* StakeLifecycle.tla (FB8) ->
\*   The APPLY-side Inv_NoEarlyUnstake (no UNSTAKE refunds locked stake while
\*       height < unlock_height — the S-017 gate). FB53 is the READ-side dual:
\*       INV_NoFalseEligible predicts that same gate trustlessly. The
\*       unlock_height FB53 reads is the one FB8's Deregister armed.
\*
\* StakeRefundFlow.tla (FB41) / StakeForfeitureCascade.tla (FB21) ->
\*   Sibling apply-side stake-unlock specs (refund timing / cascade order).
\*       FB53 consumes the committed unlock_height they produce and re-derives
\*       the unstake-eligibility verdict trustlessly.
\*
\* CompositeKeyStateProof.tla (FB43) ->
\*   FB43 (right key over all ten namespaces); FB53 reads the s: leaf whose
\*       key FB43 pins canonical. Composition FB43 + FB44 + FB53.
\*
\* MerklePathVerify.tla (FB44) ->
\*   FB44 (right path); FB53's PathOk predicate abstracts FB44's accept/reject
\*       decision.
\*
\* FrostVerify.tla (FB23) ->
\*   FB23 (committee-signed head); FB53's HeadOk predicate abstracts FB23's
\*       accept/reject decision over BOTH the state_root AND the head height H
\*       (the verdict's two committee-anchored inputs).
\*
\* C++ enforcement:
\*   light/main.cpp::cmd_verify_unstake_eligibility : the ELIGIBLE / LOCKED /
\*       BONDED / NO-STAKE / UNVERIFIABLE verdict pipeline, re-running the
\*       validator's `b.index >= unlock_height` predicate over the committee-
\*       attested unlock_height at head H. The Classify operator is the
\*       spec-layer projection. INV_NoFalseEligible (T-UE6).
\*   light/trustless_read.cpp::anchor_genesis : AnchorOk (INV_AnchorGate).
\*   light/trustless_read.cpp::verify_chain_to_head : HeadOk — extracts BOTH
\*       state_root and head height H (INV_HeadGate).
\*   src/chain/chain.cpp:292-296 : build_state_leaves stakes_ branch — the
\*       canonical (locked, unlock_height) encoding the value_hash commits.
\*       Encode is the spec-layer projection. INV_BindGate (T-UE5).
\*   src/chain/block.cpp BlockValidator::check_tx : the apply-side S-017 gate
\*       (`b.index >= unlock_height`) the Classify ELIGIBLE branch mirrors.
\*
\* Sibling specs (style template):
\*   FB50 DAppRegistrationRead.tla — the four-gate trustless-read pipeline +
\*       injective-Encode + INV-* style this module reuses; FB53 is its
\*       s:-namespace verdict-bearing companion.
\*   FB44 MerklePathVerify.tla — the injective-hash-term abstraction.
\*   FB23 FrostVerify.tla — the committee-signature verify abstraction
\*       FB53's HeadOk consumes.
\*
\* Runtime regressions:
\*   tools/test_light_verify_unstake_eligibility.sh — exercises the ELIGIBLE
\*       / LOCKED / BONDED / NO-STAKE / UNVERIFIABLE verdict pipeline FB53
\*       models.
\*   tools/test_light_stake_trustless.sh — the (locked, unlock_height) read
\*       FB53's bind gate recomputes against; FB53 adds the verdict step on
\*       top of that raw pair.
============================================================================
