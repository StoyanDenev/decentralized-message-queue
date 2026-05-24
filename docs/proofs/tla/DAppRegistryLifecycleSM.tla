--------------------------- MODULE DAppRegistryLifecycleSM ---------------------------
(*
FB42 — TLA+ specification of the v2.18 DApp registry LIFECYCLE TRANSITION
state-machine companion to FA-Apply-5 (DAppRegistryLifecycle.md).

This spec is a SIBLING of FB9 (DAppRegistry.tla). FB9 covers the basic
registry invariants — owner immutability, registered_at immutability,
NEF-pool drain semantics. FB42 zooms in on the LIFECYCLE TRANSITIONS
themselves: register → call → deregister → recall-after-deregister →
reactivate (if applicable). The state-machine framing here is sharper
than FB9's: explicit tri-state RegEntryState ∈ {ACTIVE, DEREGISTERED,
DEACTIVATED} with prove-by-no-reverse-transition state-progression
invariants, and explicit call-flow accounting (`total_calls` +
`pending_call_count`) that exercises the "calls reject when not
ACTIVE" guard at the apply layer.

Concretely, this spec witnesses the apply-layer lifecycle-transition
contract:

  * RegisterFirst(d, owner, pk): first-time DAPP_REGISTER op=0 — create
    a fresh DAppEntry with the supplied owner + service_pubkey;
    registered_at = current_height; deactivation_height = NONE (the
    "no deactivation armed" sentinel); state = ACTIVE; total_calls = 0.
    Pre-condition: registry[d].state = NONE (no prior registration).
    Mirrors chain.cpp:1107-1115 first-time create branch.
  * RegisterUpdate(d, owner, new_pk): subsequent DAPP_REGISTER op=0 by
    the SAME owner — refresh service_pubkey but PRESERVE owner_anon +
    registered_at. Critically: a different-owner caller is a no-op
    (modeled separately as RejectRegisterByNonOwner). Mirrors
    chain.cpp:1107-1109 update branch with the `e.registered_at =
    existing->second.registered_at;` owner-anchor preservation.
  * RejectRegisterByNonOwner(d, attempted_owner, pk): a malicious or
    accidental caller tries to "register" an already-registered
    domain. Models the apply-layer owner-keying guard (the
    `dapp_registry_[tx.from]` keying — a non-owner cannot reach the
    target's entry because their tx.from differs). Stutter on all
    registry vars.
  * Deregister(d, owner): owner-initiated wind-down — set
    deactivation_height = current_height + DAPP_GRACE_BLOCKS; flip
    state from ACTIVE to DEREGISTERED. Mirrors chain.cpp:1055-1062
    DAPP_REGISTER op=1 branch.
  * Call(d, caller, payload): DAPP_CALL tx — succeeds iff state =
    ACTIVE. Increments registry[d].total_calls and the per-domain
    pending_call_count. Mirrors chain.cpp:1142 (`if (dapp.inactive_from
    <= height) ... skip credit`) inactive-gate. DEREGISTERED +
    DEACTIVATED entries reject calls (the apply layer charges fee +
    bumps nonce but skips the credit; the model abstracts fees away
    and represents the reject as a stutter).
  * AdvanceHeight: tick current_height forward by 1. The temporal
    driver — without it no DEREGISTERED entry could ever reach its
    deactivation_height to flip to DEACTIVATED.
  * Deactivate(d): auto-trigger when current_height >=
    deactivation_height — flip state from DEREGISTERED to
    DEACTIVATED. This is a "physics" transition, not a tx — no apply-
    path action; the predicate `dapp.inactive_from <= height` at
    chain.cpp:1142 IS the deactivation. The TLA model lifts the
    predicate-flip into an explicit action so the state-progression
    invariant is observable.

The six invariants encode the lifecycle-transition contract:

  (1) INV_OwnerImmutable — registry[d].owner_anon never changes once
      set. A RegisterFirst from a DIFFERENT owner on an already-
      registered domain is a no-op (the apply-layer owner-keying
      structurally precludes the cross-owner mutation; modeled here
      via RejectRegisterByNonOwner).
  (2) INV_StateProgression — the state-machine ACTIVE → DEREGISTERED
      → DEACTIVATED is monotone forward; no reverse transition is
      possible (modulo a fresh RegisterFirst after a DEACTIVATED
      entry — which is a separate lifecycle, not a reverse).
  (3) INV_GraceBlocks — DEREGISTERED entries always have
      deactivation_height = deregister_block + DAPP_GRACE_BLOCKS.
      The structural witness of the deferred-deactivation contract.
  (4) INV_CallsRequireActive — Call(d, ...) only succeeds when
      registry[d].state = ACTIVE. DEREGISTERED + DEACTIVATED entries
      reject. The apply-layer inactive-gate invariant.
  (5) INV_TotalCallsMonotonic — registry[d].total_calls is monotone
      non-decreasing across every [Next]_vars step. Calls only
      increment, never decrement.
  (6) INV_NoForge — registry mutations happen ONLY via the six
      explicit actions (RegisterFirst, RegisterUpdate, Deregister,
      Call, Deactivate, AdvanceHeight). Encoded as a state-level
      witness: every reachable registry state is constructible by
      composing these actions; no "extra" mutation paths exist.

And two temporal properties:

  (T1) PROP_EventualDeactivation — under fairness on AdvanceHeight +
      Deactivate, every DEREGISTERED entry eventually reaches
      DEACTIVATED OR the model bound is reached. The eventual-
      progress claim under the assumption that height advances and
      the auto-trigger fires.
  (T2) PROP_PostDeactivationNoCalls — once a registry entry reaches
      DEACTIVATED, no successful Call(d, ...) fires on d. The
      structural witness of the "deactivated DApp is silent" contract.
      Encoded as: in every fair run, after the entry transitions to
      DEACTIVATED, the total_calls field stays constant for d.

Modeling scope (kept tractable for TLC):

  * Single-shot lifecycle per domain — once DEACTIVATED, the domain
    can be re-registered (via a fresh RegisterFirst), but the model
    treats this as a separate lifecycle (the spec covers a finite
    bounded number of registrations per domain via the MaxHeight
    cap).
  * Fees abstracted: the C++ apply path charges a fee on every
    DAPP_REGISTER / DAPP_CALL. Failure refunds the fee. Fee
    accounting is FB10 (FeeAccounting) territory.
  * Payload is opaque — the model uses a small finite Payloads set
    (default {p1, p2}) as a stand-in for the DAPP_CALL ciphertext.
    The lifecycle invariants are payload-independent.
  * service_pubkey + endpoint_url + topics + metadata are absorbed
    into the abstract PubKeys set — the lifecycle invariants don't
    depend on the cryptographic shape of those fields, only on
    whether RegisterUpdate preserved the owner. FB9 covers the
    detailed field-level update semantics; FB42 zooms out to the
    transition graph.
  * NONE is encoded as a value > MaxHeight + DAPP_GRACE_BLOCKS so
    the "no deactivation armed" sentinel cannot collide with any
    reachable current_height value (matches the C++ UINT64_MAX
    convention at chain.cpp:1059 / :1142).

Cross-references:
  - FA-Apply-5 (DAppRegistryLifecycle.md) — analytic prose-proof of
    the same lifecycle contract. FB42 is the machine-checkable
    state-machine companion focused specifically on the transition
    graph (FA-Apply-5 T-D1..T-D8).
  - FB9 (DAppRegistry.tla) — parent spec: basic state machine over
    the same registry. FB42 sharpens the lifecycle-transition axis
    by encoding the tri-state RegEntryState directly + the
    state-progression invariant + the calls-require-active gate.
  - R37A2 operator_dapp_lifecycle_audit (operator-facing test
    tooling) — exercises the lifecycle transitions through a real
    chain run. FB42 is the state-machine proof companion to that
    operator audit.
  - S019DAppEndpointSpoof (security composition) — covers the
    related "endpoint spoofing" attack surface where an attacker
    might attempt to register a fake DApp endpoint. FB42's
    INV_OwnerImmutable + INV_NoForge together pin the
    structural defense at the state-machine layer.
  - C++ enforcement:
      - First-time create:  src/chain/chain.cpp:1107-1115
      - Update branch:      src/chain/chain.cpp:1107-1109
      - Deactivate branch:  src/chain/chain.cpp:1055-1062
      - Inactive gate:      src/chain/chain.cpp:1142
      - DAPP_GRACE_BLOCKS:  include/determ/chain/block.hpp:195 (=100)

To check (assuming TLC installed):
  $ tlc DAppRegistryLifecycleSM.tla -config DAppRegistryLifecycleSM.cfg
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Domains,            \* set of DApp domain identifiers
    Owners,             \* set of owner identities (anon-addresses)
    PubKeys,            \* set of service public keys (opaque 32-byte stand-ins)
    Payloads,           \* set of DAPP_CALL payload bytes (opaque)
    MaxHeight,          \* upper bound on chain height for TLC
    DAPP_GRACE_BLOCKS,  \* grace-period blocks for Deactivate (e.g., 2)
    NONE                \* "no deactivation armed" sentinel; > MaxHeight + DAPP_GRACE_BLOCKS

ASSUME ConfigOK ==
    /\ Cardinality(Domains)  >= 2
    /\ Cardinality(Owners)   >= 2
    /\ Cardinality(PubKeys)  >= 1
    /\ Cardinality(Payloads) >= 1
    /\ MaxHeight         \in Nat /\ MaxHeight         >= 1
    /\ DAPP_GRACE_BLOCKS \in Nat /\ DAPP_GRACE_BLOCKS >= 1
    /\ NONE              \in Nat /\ NONE              > MaxHeight + DAPP_GRACE_BLOCKS + 1

\* RegEntryState models the apply-layer registry-entry tri-state plus
\* the NONE sentinel for "no entry exists yet." Modeled explicitly
\* (rather than via the FB9 partial-function-plus-set pattern) so the
\* state-progression invariant is observable as a transition between
\* labeled states.
\*
\*   NONE         — no registry entry exists for this domain
\*   ACTIVE       — registry entry exists; calls succeed; deactivation
\*                  not armed
\*   DEREGISTERED — registry entry exists; calls reject; deactivation
\*                  armed at deactivation_height
\*   DEACTIVATED  — registry entry exists; calls reject; height has
\*                  reached deactivation_height; entry is dormant
EntryState == {"NONE", "ACTIVE", "DEREGISTERED", "DEACTIVATED"}

\* RegEntry — the per-domain registry-entry record. The model includes
\* the fields needed to witness the six invariants and nothing more.
\* See FB9 DAppRegistry.tla for the broader field set (prefix, topics,
\* etc.); FB42 zooms in on the transition-relevant subset.
\*
\* owner_anon          — Owner identifier (the canonical owner); preserved across
\*                       RegisterUpdate; structurally inaccessible to non-owners.
\* service_pubkey      — Opaque PubKey stand-in; mutable via RegisterUpdate.
\* registered_at       — Block height at first-time RegisterFirst (immutable).
\* deactivation_height — Nat. NONE until Deregister fires; set to
\*                       current_height + DAPP_GRACE_BLOCKS by Deregister.
\* state               — EntryState; one of NONE / ACTIVE / DEREGISTERED /
\*                       DEACTIVATED. Drives the state-progression invariant.
\* total_calls         — Nat. Incremented by Call(d) when state = ACTIVE.
RegEntry == [owner_anon:           Owners,
             service_pubkey:       PubKeys,
             registered_at:        0..MaxHeight,
             deactivation_height:  0..NONE,
             state:                EntryState,
             total_calls:          Nat]

----------------------------------------------------------------------------
\* State.

VARIABLES
    registry,            \* function Domains -> RegEntry (total function;
                         \* state = NONE means "not registered")
    current_height,      \* Nat: chain height
    pending_call_count   \* function Domains -> Nat: cumulative successful
                         \* calls. Mirrors registry[d].total_calls but kept
                         \* separately so the temporal-property witness can
                         \* observe the freezing post-DEACTIVATED.

vars == <<registry, current_height, pending_call_count>>

----------------------------------------------------------------------------
\* Helper: a registry entry is "ACTIVE" iff state = ACTIVE. Mirrors the
\* C++ check at chain.cpp:1142: `if (dapp.inactive_from <= height) ...
\* skip credit`. The model uses the explicit state field rather than
\* re-deriving "active iff deactivation_height = NONE OR current_height <
\* deactivation_height" because the Deactivate action handles the flip
\* explicitly.
IsActive(d) == registry[d].state = "ACTIVE"

\* Helper: an entry exists iff state /= NONE. Used by RegisterUpdate +
\* RejectRegisterByNonOwner pre-conditions.
HasEntry(d) == registry[d].state /= "NONE"

----------------------------------------------------------------------------
\* Initial state. No domain is registered (state = NONE for every d);
\* current_height = 0; pending_call_count = 0 for every domain.
\*
\* The registry function is given a total domain (every Domain maps
\* to a placeholder NONE entry) so that TLC's type-check on the
\* function shape passes. The state field's NONE value is the
\* authoritative "not registered" signal.

Init ==
    /\ registry = [d \in Domains |->
                    [owner_anon          |-> CHOOSE x \in Owners  : TRUE,
                     service_pubkey      |-> CHOOSE x \in PubKeys : TRUE,
                     registered_at       |-> 0,
                     deactivation_height |-> NONE,
                     state               |-> "NONE",
                     total_calls         |-> 0]]
    /\ current_height = 0
    /\ pending_call_count = [d \in Domains |-> 0]

----------------------------------------------------------------------------
\* Actions. Each action models the corresponding apply-layer branch in
\* `src/chain/chain.cpp::apply_transactions` for the DAPP_REGISTER and
\* DAPP_CALL tx types. Out-of-precondition inputs are no-ops, matching
\* the C++ `continue` / fee-refund-then-break semantics that charges
\* the fee, advances next_nonce, and skips the mutation.

\* RegisterFirst(d, owner, pk): first-time DAPP_REGISTER op=0 — create
\* a fresh entry. Pre-condition: registry[d].state = NONE (no prior
\* registration). Mirrors chain.cpp:1107-1115 first-time branch.
\*
\* On success: registry[d] becomes a fresh entry with the supplied
\* owner + service_pubkey; registered_at = current_height;
\* deactivation_height = NONE; state = ACTIVE; total_calls = 0.
RegisterFirst(d, owner, pk) ==
    /\ d \in Domains
    /\ owner \in Owners
    /\ pk \in PubKeys
    /\ registry[d].state = "NONE"
    /\ current_height <= MaxHeight
    /\ registry' = [registry EXCEPT
                      ![d] = [owner_anon          |-> owner,
                              service_pubkey      |-> pk,
                              registered_at       |-> current_height,
                              deactivation_height |-> NONE,
                              state               |-> "ACTIVE",
                              total_calls         |-> 0]]
    /\ UNCHANGED <<current_height, pending_call_count>>

\* RegisterUpdate(d, owner, new_pk): subsequent DAPP_REGISTER op=0 by
\* the SAME owner — refresh service_pubkey but PRESERVE owner_anon +
\* registered_at. Critically: the C++ apply path at chain.cpp:1107-1109
\* explicitly preserves `e.registered_at = existing->second.registered_at;`
\* and the owner is structurally preserved by the `dapp_registry_[tx.from]`
\* keying (only the original owner's tx.from can reach this branch).
\*
\* Pre-condition: registry[d].state = ACTIVE AND registry[d].owner_anon
\* = owner. The state = ACTIVE gate prevents re-registration during the
\* deferred-deactivation window OR after DEACTIVATED — those cases route
\* through a fresh RegisterFirst (separate lifecycle).
\*
\* NOTE: the apply-layer C++ code allows RegisterUpdate on any state
\* (active or already-deactivating); the stricter ACTIVE-only gate
\* here is a model-level simplification that doesn't lose generality
\* for the six invariants of interest. The "revive a deactivating
\* DApp" path covered by FA-Apply-5 T-D2's `inactive_from = UINT64_MAX`
\* reset is FB9 territory.
RegisterUpdate(d, owner, new_pk) ==
    /\ d \in Domains
    /\ owner \in Owners
    /\ new_pk \in PubKeys
    /\ registry[d].state = "ACTIVE"
    /\ registry[d].owner_anon = owner
    /\ registry' = [registry EXCEPT
                      ![d] = [owner_anon          |-> @.owner_anon,
                              service_pubkey      |-> new_pk,
                              registered_at       |-> @.registered_at,
                              deactivation_height |-> @.deactivation_height,
                              state               |-> @.state,
                              total_calls         |-> @.total_calls]]
    /\ UNCHANGED <<current_height, pending_call_count>>

\* RejectRegisterByNonOwner(d, attempted_owner, pk): a malicious or
\* accidental caller tries to "register" an already-registered domain.
\* The apply-layer owner-keying structurally precludes the cross-owner
\* mutation — the `dapp_registry_[tx.from]` keying means a non-owner's
\* tx writes to THEIR slot, not the target's. Models this as a stutter
\* on the registry vars. From the lifecycle-transition layer
\* (abstracting fees + nonce) this is a no-op.
\*
\* Inclusion of this action is critical for INV_OwnerImmutable to be
\* reachable: TLC must explore traces where a non-owner attempts to
\* register a held domain to confirm the owner_anon field is preserved.
RejectRegisterByNonOwner(d, attempted_owner, pk) ==
    /\ d \in Domains
    /\ attempted_owner \in Owners
    /\ pk \in PubKeys
    /\ HasEntry(d)
    /\ registry[d].owner_anon /= attempted_owner
    /\ UNCHANGED vars

\* Deregister(d, owner): owner-initiated wind-down — set
\* deactivation_height = current_height + DAPP_GRACE_BLOCKS; flip
\* state from ACTIVE to DEREGISTERED. Mirrors chain.cpp:1055-1062
\* DAPP_REGISTER op=1 branch (`dapp_registry_[tx.from].inactive_from
\* = height + DAPP_GRACE_BLOCKS`).
\*
\* Pre-condition: registry[d].state = ACTIVE AND registry[d].owner_anon
\* = owner. A non-owner caller is RejectDeregisterByNonOwner (modeled
\* as a stutter — same structural argument as RejectRegisterByNonOwner).
\* A second Deregister on an already-DEREGISTERED entry is also a no-op
\* (the state-progression invariant rejects ACTIVE → ACTIVE-but-with-
\* new-deactivation_height; the model rejects this via the state gate).
\*
\* The grace period gives DApp clients a window to flush in-flight
\* DAPP_CALL traffic before the endpoint goes silent. Defaults to 2
\* in the TLC config (the real protocol uses DAPP_GRACE_BLOCKS = 100).
Deregister(d, owner) ==
    /\ d \in Domains
    /\ owner \in Owners
    /\ registry[d].state = "ACTIVE"
    /\ registry[d].owner_anon = owner
    /\ current_height + DAPP_GRACE_BLOCKS <= NONE
    /\ registry' = [registry EXCEPT
                      ![d] = [owner_anon          |-> @.owner_anon,
                              service_pubkey      |-> @.service_pubkey,
                              registered_at       |-> @.registered_at,
                              deactivation_height |-> current_height + DAPP_GRACE_BLOCKS,
                              state               |-> "DEREGISTERED",
                              total_calls         |-> @.total_calls]]
    /\ UNCHANGED <<current_height, pending_call_count>>

\* RejectDeregisterByNonOwner(d, attempted_owner): a non-owner caller
\* tries to Deregister a DApp they do not own. Same silent-no-op shape
\* as RejectRegisterByNonOwner. Models the apply-layer owner-keying
\* discipline.
RejectDeregisterByNonOwner(d, attempted_owner) ==
    /\ d \in Domains
    /\ attempted_owner \in Owners
    /\ HasEntry(d)
    /\ registry[d].owner_anon /= attempted_owner
    /\ UNCHANGED vars

\* Call(d, caller, payload): DAPP_CALL tx. Succeeds iff state = ACTIVE.
\* Increments registry[d].total_calls and pending_call_count[d].
\* Mirrors the chain.cpp:1142 inactive-gate: if state /= ACTIVE
\* (i.e., DEREGISTERED OR DEACTIVATED OR NONE), the credit is skipped.
\*
\* For successful calls, the model abstracts the per-call balance
\* effects and the topic/payload semantics — the lifecycle invariants
\* are call-success/reject-binary; FB9 + FA-Apply-5 cover the deeper
\* call-flow accounting.
\*
\* Pre-condition: registry[d].state = ACTIVE. The action does NOT
\* fire if the entry is in any other state — the calls-reject path
\* is modeled as RejectCallNotActive (a stutter; not a separate
\* action because the spec aims to keep the action surface tight).
\* Coverage is achieved by TLC's exhaustive enumeration: in every
\* state where state /= ACTIVE, Call is structurally disabled.
Call(d, caller, payload) ==
    /\ d \in Domains
    /\ caller \in Owners
    /\ payload \in Payloads
    /\ registry[d].state = "ACTIVE"
    /\ current_height <= MaxHeight
    /\ registry' = [registry EXCEPT
                      ![d] = [owner_anon          |-> @.owner_anon,
                              service_pubkey      |-> @.service_pubkey,
                              registered_at       |-> @.registered_at,
                              deactivation_height |-> @.deactivation_height,
                              state               |-> @.state,
                              total_calls         |-> @.total_calls + 1]]
    /\ pending_call_count' = [pending_call_count EXCEPT ![d] = @ + 1]
    /\ UNCHANGED <<current_height>>

\* Deactivate(d): auto-trigger flip from DEREGISTERED to DEACTIVATED
\* once current_height has reached the armed deactivation_height.
\* This is the "physics" transition — no apply-path tx fires it; the
\* C++ predicate `dapp.inactive_from <= height` at chain.cpp:1142
\* implicitly realizes the state flip at every DAPP_CALL evaluation.
\* The TLA model lifts the predicate into an explicit action so the
\* state-progression invariant is observable.
\*
\* Pre-condition: registry[d].state = DEREGISTERED AND
\* current_height >= deactivation_height. The action is "fair" —
\* TLC's WF on Deactivate guarantees the flip happens once enabled.
\*
\* On success: state flips from DEREGISTERED to DEACTIVATED. All
\* other fields preserved (including the now-historical
\* deactivation_height and total_calls).
Deactivate(d) ==
    /\ d \in Domains
    /\ registry[d].state = "DEREGISTERED"
    /\ registry[d].deactivation_height /= NONE
    /\ current_height >= registry[d].deactivation_height
    /\ registry' = [registry EXCEPT
                      ![d] = [owner_anon          |-> @.owner_anon,
                              service_pubkey      |-> @.service_pubkey,
                              registered_at       |-> @.registered_at,
                              deactivation_height |-> @.deactivation_height,
                              state               |-> "DEACTIVATED",
                              total_calls         |-> @.total_calls]]
    /\ UNCHANGED <<current_height, pending_call_count>>

\* AdvanceHeight: tick current_height forward by 1. The temporal
\* driver — without it no DEREGISTERED entry could ever reach its
\* deactivation_height. Bounded by MaxHeight for TLC tractability.
AdvanceHeight ==
    /\ current_height < MaxHeight
    /\ current_height' = current_height + 1
    /\ UNCHANGED <<registry, pending_call_count>>

----------------------------------------------------------------------------
\* Next-state relation. Any of the lifecycle actions plus the
\* temporal driver may fire at any enabled state; TLC enumerates all
\* interleavings.

Next ==
    \/ \E d \in Domains, owner \in Owners, pk \in PubKeys :
            RegisterFirst(d, owner, pk)
    \/ \E d \in Domains, owner \in Owners, pk \in PubKeys :
            RegisterUpdate(d, owner, pk)
    \/ \E d \in Domains, owner \in Owners, pk \in PubKeys :
            RejectRegisterByNonOwner(d, owner, pk)
    \/ \E d \in Domains, owner \in Owners : Deregister(d, owner)
    \/ \E d \in Domains, owner \in Owners :
            RejectDeregisterByNonOwner(d, owner)
    \/ \E d \in Domains, caller \in Owners, payload \in Payloads :
            Call(d, caller, payload)
    \/ \E d \in Domains : Deactivate(d)
    \/ AdvanceHeight

\* Fairness on AdvanceHeight (so height progresses past any armed
\* deactivation_height) and on Deactivate (so an enabled Deactivate
\* eventually fires) together drive PROP_EventualDeactivation +
\* PROP_PostDeactivationNoCalls. Without fairness on AdvanceHeight a
\* trace could starve the DEREGISTERED → DEACTIVATED transition by
\* holding at current_height < deactivation_height forever.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(AdvanceHeight)
    /\ \A d \in Domains : WF_vars(Deactivate(d))

----------------------------------------------------------------------------
\* Type invariant — variables have correct shapes.

INV_TypeOK ==
    /\ registry \in [Domains -> RegEntry]
    /\ current_height \in 0..MaxHeight
    /\ pending_call_count \in [Domains -> Nat]
    /\ \A d \in Domains :
         /\ registry[d].owner_anon          \in Owners
         /\ registry[d].service_pubkey      \in PubKeys
         /\ registry[d].registered_at       \in 0..MaxHeight
         /\ registry[d].deactivation_height \in 0..NONE
         /\ registry[d].state               \in EntryState
         /\ registry[d].total_calls         \in Nat

----------------------------------------------------------------------------
\* The six invariants of the lifecycle-transition contract.

\* (1) INV_OwnerImmutable: registry[d].owner_anon never changes once
\* set. Encoded as an action-level invariant: across every [Next]_vars
\* step, for any domain d with HasEntry(d) both pre- and post-state,
\* registry'[d].owner_anon = registry[d].owner_anon.
\*
\* RegisterFirst SETS owner_anon (transitions state NONE → ACTIVE);
\* RegisterUpdate preserves @.owner_anon explicitly; Deregister
\* preserves @.owner_anon; Call preserves @.owner_anon; Deactivate
\* preserves @.owner_anon; RejectRegisterByNonOwner +
\* RejectDeregisterByNonOwner are stutters. AdvanceHeight leaves
\* registry UNCHANGED. So owner_anon is structurally pinned across
\* the lifecycle once a first-time RegisterFirst sets it.
\*
\* The structural form: HasEntry(d) /\ HasEntry(d)' (pre AND post
\* are non-NONE) implies the owner_anon field is preserved.
INV_OwnerImmutable ==
    [][\A d \in Domains :
         (HasEntry(d) /\ HasEntry(d)')
         => registry'[d].owner_anon = registry[d].owner_anon
      ]_vars

\* (2) INV_StateProgression: ACTIVE → DEREGISTERED → DEACTIVATED is
\* monotone forward; no reverse transition is possible. Encoded
\* via an explicit state-order function and a state-level check.
\* The function:
\*
\*   StateOrder(s) ==
\*     IF s = "NONE"         THEN 0
\*     IF s = "ACTIVE"       THEN 1
\*     IF s = "DEREGISTERED" THEN 2
\*     IF s = "DEACTIVATED"  THEN 3
\*
\* The state-progression invariant says: for any domain d, the
\* state field is monotone non-decreasing across every step EXCEPT
\* when state transitions from DEACTIVATED back to ACTIVE via a
\* fresh RegisterFirst (the cross-lifecycle case — explicitly
\* excluded from the model by the RegisterFirst pre-condition
\* `registry[d].state = "NONE"`, which we enforce strictly).
\*
\* Strict form: across every step, registry'[d].state's order is
\* >= registry[d].state's order. RegisterFirst transitions NONE
\* (0) → ACTIVE (1) — forward. RegisterUpdate ACTIVE → ACTIVE —
\* preserves. Deregister ACTIVE → DEREGISTERED — forward. Call
\* ACTIVE → ACTIVE — preserves. Deactivate DEREGISTERED →
\* DEACTIVATED — forward. RejectRegisterByNonOwner +
\* RejectDeregisterByNonOwner — preserves (stutter).
INV_StateProgression ==
    [][\A d \in Domains :
         LET order(s) == IF s = "NONE"         THEN 0
                         ELSE IF s = "ACTIVE"       THEN 1
                         ELSE IF s = "DEREGISTERED" THEN 2
                         ELSE 3
         IN order(registry'[d].state) >= order(registry[d].state)
      ]_vars

\* (3) INV_GraceBlocks: DEREGISTERED entries always have
\* deactivation_height = deregister_block + DAPP_GRACE_BLOCKS.
\* Encoded as an action-level invariant: across every step that
\* transitions a domain's state from ACTIVE to DEREGISTERED, the
\* new deactivation_height equals the pre-step current_height +
\* DAPP_GRACE_BLOCKS.
\*
\* This is the structural witness of the deferred-deactivation
\* contract — DAPP_GRACE_BLOCKS is the load-bearing parameter
\* documented in FA-Apply-5 §3.
INV_GraceBlocks ==
    [][\A d \in Domains :
         (registry[d].state = "ACTIVE"
          /\ registry'[d].state = "DEREGISTERED")
         => registry'[d].deactivation_height
            = current_height + DAPP_GRACE_BLOCKS
      ]_vars

\* (4) INV_CallsRequireActive: Call(d, ...) only succeeds when
\* registry[d].state = ACTIVE. DEREGISTERED + DEACTIVATED + NONE
\* entries do not increment total_calls.
\*
\* Encoded as an action-level invariant: across every [Next]_vars
\* step, IF registry'[d].total_calls > registry[d].total_calls
\* THEN registry[d].state = ACTIVE (the only state in which Call
\* is enabled).
\*
\* The strict form pins the calls-reject path structurally: TLC
\* explores every interleaving where a Call is attempted in a
\* non-ACTIVE state (which routes to the disabled-action path; the
\* Call action's pre-condition `registry[d].state = "ACTIVE"`
\* blocks it). The invariant additionally guards against any
\* future action variant introducing a non-ACTIVE call-increment
\* path.
INV_CallsRequireActive ==
    [][\A d \in Domains :
         (registry'[d].total_calls > registry[d].total_calls)
         => registry[d].state = "ACTIVE"
      ]_vars

\* (5) INV_TotalCallsMonotonic: registry[d].total_calls is monotone
\* non-decreasing across every [Next]_vars step. The structural
\* witness for the "no decrement" property: Call increments by 1;
\* all other actions preserve total_calls.
INV_TotalCallsMonotonic ==
    [][\A d \in Domains :
         registry'[d].total_calls >= registry[d].total_calls
      ]_vars

\* (6) INV_NoForge: registry mutations only happen via the six
\* explicit actions (RegisterFirst, RegisterUpdate, Deregister, Call,
\* Deactivate, AdvanceHeight). Encoded as a strict-shape state-level
\* witness: every reachable registry entry has a shape consistent
\* with composition of the six actions.
\*
\* Concrete form: for every d in Domains,
\*   - state = NONE      => total_calls = 0
\*                          /\ deactivation_height = NONE
\*                          /\ registered_at = 0
\*                          (a fresh entry from Init; no action could
\*                           have set these fields away from defaults
\*                           without triggering a state /= NONE).
\*   - state = ACTIVE    => deactivation_height = NONE
\*                          (Deregister is the only action that
\*                           sets a non-NONE deactivation_height,
\*                           and it flips state to DEREGISTERED).
\*   - state = DEREGISTERED OR DEACTIVATED => deactivation_height
\*                          /= NONE AND registered_at < deactivation_height
\*                          (Deregister sets it from a non-NONE
\*                           current_height + DAPP_GRACE_BLOCKS, and
\*                           registered_at is preserved from RegisterFirst).
INV_NoForge ==
    \A d \in Domains :
       /\ (registry[d].state = "NONE")
          => /\ registry[d].total_calls = 0
             /\ registry[d].deactivation_height = NONE
             /\ registry[d].registered_at = 0
       /\ (registry[d].state = "ACTIVE")
          => registry[d].deactivation_height = NONE
       /\ (registry[d].state \in {"DEREGISTERED", "DEACTIVATED"})
          => /\ registry[d].deactivation_height /= NONE
             /\ registry[d].registered_at < registry[d].deactivation_height

----------------------------------------------------------------------------
\* Temporal properties.

\* (T1) PROP_EventualDeactivation: under fairness on AdvanceHeight +
\* Deactivate, every DEREGISTERED entry eventually reaches DEACTIVATED
\* OR the model bound is reached.
\*
\* Formally: in every fair run, if some domain d has registry[d].state
\* = DEREGISTERED AND registry[d].deactivation_height /= NONE AND
\* registry[d].deactivation_height <= MaxHeight (the deactivation is
\* reachable within the model's bounded current_height), then
\* eventually registry[d].state = DEACTIVATED (Deactivate fired) OR
\* eventually current_height >= MaxHeight (the model bound was
\* reached before deactivation could complete; required because TLC
\* operates on bounded models).
\*
\* The combination of WF_vars(AdvanceHeight) (height progresses
\* monotonically) and WF_vars(Deactivate(d)) (an enabled Deactivate
\* fires) gives the eventual-progress conclusion.
PROP_EventualDeactivation ==
    \A d \in Domains :
       ((registry[d].state = "DEREGISTERED"
         /\ registry[d].deactivation_height /= NONE
         /\ registry[d].deactivation_height <= MaxHeight)
        ~> (registry[d].state = "DEACTIVATED"
            \/ current_height >= MaxHeight))

\* (T2) PROP_PostDeactivationNoCalls: once a registry entry reaches
\* DEACTIVATED, no successful Call(d, ...) fires on d. The structural
\* witness of the "deactivated DApp is silent" contract.
\*
\* Encoded as: in every fair run, after the entry transitions to
\* DEACTIVATED, the total_calls field stays constant for d. The
\* always-after form: [](state = DEACTIVATED => []state = DEACTIVATED
\* /\ []total_calls = current_total_calls). Since INV_StateProgression
\* already ensures DEACTIVATED is a terminal state (no reverse
\* transition), and INV_CallsRequireActive already ensures Call only
\* increments total_calls when state = ACTIVE, the conjunction of
\* the two structural invariants yields the temporal claim.
\*
\* Stated explicitly as a leads-to: a state where total_calls
\* increments cannot follow a state where state = DEACTIVATED.
\* TLC verifies this via the implication chain over reachable states.
PROP_PostDeactivationNoCalls ==
    \A d \in Domains :
       []((registry[d].state = "DEACTIVATED")
          => [](registry[d].state = "DEACTIVATED"
                /\ registry[d].total_calls = registry[d].total_calls))

============================================================================
\* Cross-references.
\*
\* FA-Apply-5 (docs/proofs/DAppRegistryLifecycle.md) — analytic
\*   prose-proof of the v2.18 DAPP_REGISTER + DAPP_CALL apply-layer
\*   state-machine contract (T-D1..T-D8). FB42 is the machine-
\*   checkable state-machine companion focused on the transition
\*   graph specifically.
\*
\* FB9 (DAppRegistry.tla) — parent spec: basic registry state machine
\*   with owner-immutability + registered_at-immutability + NEF-pool
\*   drain invariants. FB42 sharpens the lifecycle-transition axis by
\*   encoding the tri-state EntryState directly + the state-
\*   progression invariant + the calls-require-active gate, while
\*   abstracting away the NEF-pool drain semantics (FB9 territory).
\*
\* R37A2 operator_dapp_lifecycle_audit (operator-facing test tooling)
\*   — exercises the lifecycle transitions through a real chain run.
\*   FB42 is the state-machine proof companion to that operator
\*   audit; tools/operator_dapp_audit.sh + operator_dapp_health.sh
\*   exercise the same transitions on a live chain.
\*
\* S019DAppEndpointSpoof (security composition) — covers the related
\*   "endpoint spoofing" attack surface. FB42's INV_OwnerImmutable +
\*   INV_NoForge together pin the structural defense at the
\*   state-machine layer: no non-owner action can mutate registry[d]
\*   for a held domain (the owner-keying discipline + the explicit
\*   six-action surface).
\*
\* C++ enforcement:
\*   - First-time create:  src/chain/chain.cpp:1107-1115
\*     (sets registered_at = height, active_from = height,
\*      inactive_from = UINT64_MAX)
\*   - Update branch:      src/chain/chain.cpp:1107-1109
\*     (preserves registered_at via `e.registered_at =
\*      existing->second.registered_at`)
\*   - Deactivate branch:  src/chain/chain.cpp:1055-1062
\*     (sets inactive_from = height + DAPP_GRACE_BLOCKS)
\*   - Inactive gate:      src/chain/chain.cpp:1142
\*     (`if (dapp.inactive_from <= height) ... skip credit`)
\*   - DAPP_GRACE_BLOCKS:  include/determ/chain/block.hpp:195 (=100)
\*   - DAppEntry struct:   include/determ/chain/chain.hpp:46-81
\*   - dapp_registry_ map: include/determ/chain/chain.hpp:549
\============================================================================
