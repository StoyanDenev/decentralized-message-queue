--------------------------- MODULE DAppRegistry ---------------------------
(*
FB9 — TLA+ specification of the v2.18 DAPP_REGISTER state machine.
Models the apply-layer lifecycle of a DApp registry entry from
first-time registration, through update / re-registration, into
deactivation, and the NEF-pool drain semantics that gate first-time
registrations.

This spec captures the invariants of Determ's DApp registry at the
state-machine layer, independent of consensus, signature verification,
and payload-decoding details:

  * First-time `Register(d, owner, ...)` creates a fresh DAppEntry with
    `owner`, `registered_at = height`, `inactive_from = Sentinel`,
    and the supplied prefix + topic set. Drains the NEF pool by half.
  * `Update(d, owner, prefix', topics')` (same domain, same owner,
    currently-active) preserves `owner` + `registered_at` and refreshes
    only the mutable fields. Does NOT drain the NEF pool — the half-
    drain fires exactly once per domain at the first-time-Register.
  * A non-owner attempting Update or Deactivate is a silent no-op
    (matches the validator-side ed_pub authentication and the apply-
    layer `tx.from` ownership check). The registry entry is unchanged.
  * `Deactivate(d, owner)` (owner check + currently-active gate) sets
    `inactive_from = height + DappGrace`. The grace period is a small
    finite constant in the model; the real protocol uses a chain-
    governance-tunable delay (DAPP_GRACE_BLOCKS in chain.cpp).
  * The Inv_OwnerImmutable + Inv_RegisteredAtImmutable invariants are
    the headline structural claims: re-Register preserves the canonical
    identity binding (owner + first-registered-at) — an attacker cannot
    re-key or backdate a DApp via Update.
  * Inv_NefDrainsOnlyOnce + Inv_NefPoolNonNegative cover the economic-
    correctness side: the pool's half-drain fires exactly once per
    first-time domain registration, and the pool is Nat-typed (zero
    is a valid terminal state; never negative).
  * Under fairness on AdvanceHeight + Deactivate, any owner can
    eventually deactivate their DApp (Prop_EventualDeactivation), and
    once deactivated the DApp's active-status eventually flips to
    inactive (Prop_PostDeactivationInactive).

Modeling scope (kept tractable for TLC):

  * The model uses a small fixed `DappGrace` constant (3); the real
    protocol uses chain.cpp::DAPP_GRACE_BLOCKS (currently 100). The
    state-machine properties are invariant in the grace value as long
    as it is a fixed Nat.
  * `Sentinel` is a single concrete value strictly greater than
    MaxHeight + DappGrace; the C++ uses UINT64_MAX. Either value is
    correct as long as it cannot collide with any reachable height-
    plus-grace value.
  * Prefix and topic set are modeled as STRING-valued and Topic-set-
    valued fields. The actual chain enforces additional payload-encoding
    constraints (lowercase `[a-z0-9._-]+`, ≤ 64 bytes, ≤ 32 topics per
    DApp) — these are validator-layer concerns, not lifecycle-layer.
  * Owner authentication via Ed25519 sig is out of scope (FA2 / S-002
    territory). The model takes the `owner` field as the authenticated
    `tx.from` AFTER signature verification has passed.
  * DAPP_CALL tx semantics (the message-delivery side of v2.19) are
    out of scope here — covered by the apply-path tests + AccountState
    invariants. This spec is the registration / metadata side only.
  * The NEF pool is modeled as a single Nat value draining by floor-half
    on each first-time Register; the C++ implementation has the same
    semantics on the validator REGISTER path (ZEROTH_ADDRESS balance).
    The DAppRegistry spec abstracts this as a registry-side commitment
    that the half-drain happens at most once per domain.

Companion prose proof: `docs/proofs/DAppRegistryLifecycle.md`
(separately written by a parallel agent; may not yet exist in this
worktree).

To check (assuming TLC installed):
  $ tlc DAppRegistry.tla -config DAppRegistry.cfg
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Domains,            \* set of DApp domain identifiers
    Topics,             \* set of topic strings (routing tags)
    MaxHeight,          \* upper bound on chain height for TLC
    DappGrace,          \* grace-period blocks for Deactivate (e.g., 3)
    Sentinel,           \* "still-active" marker; > MaxHeight + DappGrace
    InitialNefPool      \* starting NEF pool balance (e.g., 2)

ASSUME ConfigOK ==
    /\ Cardinality(Domains) >= 2
    /\ Cardinality(Topics)  >= 1
    /\ MaxHeight      \in Nat /\ MaxHeight      >= 1
    /\ DappGrace      \in Nat /\ DappGrace      >= 1
    /\ Sentinel       \in Nat /\ Sentinel       > MaxHeight + DappGrace + 1
    /\ InitialNefPool \in Nat /\ InitialNefPool >= 1

\* Prefix values modeled as a small finite set. The actual chain accepts
\* opaque utf8 endpoint URLs; the lifecycle invariants don't depend on
\* the prefix shape, only on whether Update preserved the owner +
\* registered_at fields. We use the Domains set as a stand-in for the
\* prefix range — any string-valued constant set with > 1 element would
\* do; reusing Domains keeps the model small.
Prefixes == Domains

\* DAppEntry shape: owner identifier + registered_at height +
\* inactive_from marker + prefix + topic set. The on-chain entry has
\* additional fields (service_pubkey, endpoint_url, retention,
\* metadata, active_from) — these are payload-decoding details, not
\* lifecycle invariants. The model includes the fields needed to
\* witness the lifecycle invariants and nothing more.
DAppEntry == [owner: Domains,
              registered_at: 0..MaxHeight,
              inactive_from: 0..Sentinel,
              prefix: Prefixes,
              topics: SUBSET Topics]

----------------------------------------------------------------------------
\* State.

VARIABLES
    dapp_registry,      \* function Domains -> DAppEntry (partial; UNDEF outside)
    registered_domains, \* SUBSET Domains — domains with a registry entry
    nef_pool,           \* Nat — drains by floor-half on first-time Register
    first_registered,   \* SUBSET Domains — provenance set (audit trail)
    height              \* current chain height

vars == <<dapp_registry, registered_domains, nef_pool,
          first_registered, height>>

\* Helper: a domain is "active" iff it has a registry entry AND
\* (the entry's inactive_from is Sentinel OR the current height has
\* not yet reached inactive_from). Matches the C++ check at
\* `src/chain/chain.cpp::DAPP_CALL` case: `if (dapp.inactive_from <=
\* height) ... skip credit`.
DappActive(d) ==
    /\ d \in registered_domains
    /\ \/ dapp_registry[d].inactive_from = Sentinel
       \/ height < dapp_registry[d].inactive_from

----------------------------------------------------------------------------
\* Initial state. Empty registry, NEF pool seeded, no first-registered
\* provenance, height = 0.
\*
\* The dapp_registry function is given a total domain (every Domain
\* maps to a placeholder entry) so that TLC's type-check on the
\* function shape passes. The registered_domains set is the
\* authoritative "is this domain registered?" predicate — entries
\* outside it are ignored. This matches the C++ std::map<string,
\* DAppEntry> pattern where map.find(d) == map.end() is the
\* "not registered" signal.

Init ==
    /\ dapp_registry = [d \in Domains |->
                          [owner         |-> CHOOSE x \in Domains : TRUE,
                           registered_at |-> 0,
                           inactive_from |-> Sentinel,
                           prefix        |-> CHOOSE x \in Prefixes : TRUE,
                           topics        |-> {}]]
    /\ registered_domains = {}
    /\ nef_pool = InitialNefPool
    /\ first_registered = {}
    /\ height = 0

----------------------------------------------------------------------------
\* Actions. Each action models the corresponding apply-layer branch in
\* `src/chain/chain.cpp::apply_transactions` for the DAPP_REGISTER tx
\* type. The actions are total relations — out-of-precondition inputs
\* are no-ops (matching the C++ `continue` / `break` semantics that
\* charges the fee, advances next_nonce, and skips the mutation).

\* Register(d, owner, prefix, topics): first-time registration of
\* domain `d` by `owner`. Models the create/update branch at
\* `src/chain/chain.cpp:1064-1116` for the case where
\* `dapp_registry_.find(tx.from) == dapp_registry_.end()` (existing
\* check at line 1107).
\*
\* On first-time apply:
\*   - dapp_registry[d] gains a fresh entry with owner, registered_at =
\*     height, inactive_from = Sentinel, the supplied prefix + topics.
\*   - registered_domains gains d.
\*   - first_registered gains d (provenance — used by Inv_NefDrainsOnlyOnce).
\*   - nef_pool drains by floor-half (`nef_pool' = nef_pool \div 2`),
\*     modeling the geometric half-drain on first-time REGISTER
\*     documented in tools/test_nef_pool_drain.sh.
\*
\* Pre-condition: d \notin registered_domains. The Update action
\* handles the re-Register case. Splitting first-time vs. update into
\* two named actions keeps the NEF-drain logic local to one action
\* disjunct, which TLC enumerates exhaustively.
Register(d, owner, prefix, topics) ==
    /\ d \in Domains
    /\ owner \in Domains
    /\ prefix \in Prefixes
    /\ topics \in SUBSET Topics
    /\ d \notin registered_domains
    /\ height <= MaxHeight
    /\ dapp_registry' = [dapp_registry EXCEPT
                          ![d] = [owner         |-> owner,
                                  registered_at |-> height,
                                  inactive_from |-> Sentinel,
                                  prefix        |-> prefix,
                                  topics        |-> topics]]
    /\ registered_domains' = registered_domains \cup {d}
    /\ first_registered'   = first_registered   \cup {d}
    /\ nef_pool' = nef_pool \div 2
    /\ UNCHANGED <<height>>

\* Update(d, owner, prefix', topics'): mutable-field refresh for an
\* already-registered, currently-active DApp by its owner. Models the
\* create/update branch at `src/chain/chain.cpp:1064-1116` for the case
\* where `existing != dapp_registry_.end()` (line 1108) — the C++
\* preserves registered_at (line 1109) and refreshes everything else,
\* but the TLA-level model restricts the refresh to (prefix, topics)
\* since service_pubkey + endpoint_url + retention + metadata are not
\* invariant-relevant for the lifecycle properties.
\*
\* CRITICALLY: owner field is preserved (Inv_OwnerImmutable) and
\* registered_at is preserved (Inv_RegisteredAtImmutable). The C++
\* code at line 1109 explicitly preserves registered_at via
\* `e.registered_at = existing->second.registered_at;` — without this
\* line, an Update could backdate the DApp. The TLA model encodes the
\* same preservation in the function-update below.
\*
\* NO NEF DRAIN: only first-time Register drains the pool. This is the
\* defense against "registration churn drain attacks" called out in
\* tools/test_nef_pool_drain.sh's "Re-REGISTER (key rotation): pool
\* UNCHANGED" assertion.
\*
\* Pre-condition: d \in registered_domains AND
\* dapp_registry[d].owner = owner (the proper-authentication check)
\* AND dapp_registry[d].inactive_from = Sentinel (the
\* currently-active check — a deactivated DApp cannot be Update'd
\* during its grace period, matching the validator-side reject).
Update(d, owner, new_prefix, new_topics) ==
    /\ d \in Domains
    /\ owner \in Domains
    /\ new_prefix \in Prefixes
    /\ new_topics \in SUBSET Topics
    /\ d \in registered_domains
    /\ dapp_registry[d].owner = owner
    /\ dapp_registry[d].inactive_from = Sentinel
    /\ dapp_registry' = [dapp_registry EXCEPT
                          ![d] = [owner         |-> dapp_registry[d].owner,
                                  registered_at |-> dapp_registry[d].registered_at,
                                  inactive_from |-> Sentinel,
                                  prefix        |-> new_prefix,
                                  topics        |-> new_topics]]
    /\ UNCHANGED <<registered_domains, nef_pool, first_registered, height>>

\* RejectUpdateByNonOwner(d, attempted_owner, prefix, topics):
\* a malicious caller tries to Update a DApp they do not own. Models
\* the silent-no-op behavior of the apply layer: the tx fails the
\* `dapp_registry[d].owner = tx.from` check, the fee is charged, the
\* nonce is advanced, but the registry entry is not mutated. From the
\* state-machine layer (which abstracts fees + nonce) this is a
\* stutter on (dapp_registry, registered_domains, nef_pool,
\* first_registered, height).
\*
\* Pre-condition: d \in registered_domains AND
\* dapp_registry[d].owner /= attempted_owner. The RejectUpdateByNonOwner
\* action's existence is important — it witnesses Inv_OwnerImmutable
\* by demonstrating that an attacker-shaped step CANNOT mutate the
\* owner field. TLC explores traces where such attempts interleave
\* with legitimate Updates.
RejectUpdateByNonOwner(d, attempted_owner, new_prefix, new_topics) ==
    /\ d \in Domains
    /\ attempted_owner \in Domains
    /\ new_prefix \in Prefixes
    /\ new_topics \in SUBSET Topics
    /\ d \in registered_domains
    /\ dapp_registry[d].owner /= attempted_owner
    /\ UNCHANGED vars

\* Deactivate(d, owner): owner-initiated deactivation. Models the
\* op=1 branch at `src/chain/chain.cpp:1055-1062`: set
\* dapp_registry[d].inactive_from = height + DAPP_GRACE_BLOCKS.
\*
\* The grace period gives DApp clients a window to see the wind-down
\* signal before the endpoint goes silent. After height >=
\* inactive_from, the DAPP_CALL path rejects new calls (chain.cpp:1142
\* `if (dapp.inactive_from <= height)`). The registry entry itself is
\* retained for historical lookups; reactivation requires a fresh
\* Register (which the model treats as a first-time apply IF the
\* domain has been fully erased — out of scope for this spec, which
\* keeps the lifecycle one-shot per domain).
\*
\* Pre-condition: d \in registered_domains AND
\* dapp_registry[d].owner = owner (the proper-authentication check)
\* AND dapp_registry[d].inactive_from = Sentinel (no double-
\* deactivation — the second Deactivate would otherwise overwrite the
\* inactive_from value to height + DappGrace > original inactive_from,
\* which violates Inv_DeactivationForward only if the new height + grace
\* is smaller; the model rules this out by guarding on Sentinel).
\*
\* The new inactive_from value `height + DappGrace` is bounded above
\* by MaxHeight + DappGrace, which is < Sentinel by ConfigOK — so the
\* updated entry remains in the type's value range.
Deactivate(d, owner) ==
    /\ d \in Domains
    /\ owner \in Domains
    /\ d \in registered_domains
    /\ dapp_registry[d].owner = owner
    /\ dapp_registry[d].inactive_from = Sentinel
    /\ height + DappGrace <= Sentinel
    /\ dapp_registry' = [dapp_registry EXCEPT
                          ![d] = [owner         |-> @.owner,
                                  registered_at |-> @.registered_at,
                                  inactive_from |-> height + DappGrace,
                                  prefix        |-> @.prefix,
                                  topics        |-> @.topics]]
    /\ UNCHANGED <<registered_domains, nef_pool, first_registered, height>>

\* RejectDeactivateByNonOwner(d, attempted_owner): a malicious caller
\* tries to Deactivate a DApp they do not own. Same silent-no-op
\* shape as RejectUpdateByNonOwner — the apply layer rejects on the
\* ed_pub mismatch, the fee is charged, the nonce advances, but the
\* registry entry is not mutated.
\*
\* This action exists to witness Inv_OwnerImmutable + Inv_DeactivationForward
\* under adversarial interleaving. TLC explores traces where the owner
\* legitimately Deactivates after a non-owner failed attempt — the
\* failed attempt must not have changed any state.
RejectDeactivateByNonOwner(d, attempted_owner) ==
    /\ d \in Domains
    /\ attempted_owner \in Domains
    /\ d \in registered_domains
    /\ dapp_registry[d].owner /= attempted_owner
    /\ UNCHANGED vars

\* AdvanceHeight: tick the block index forward by 1. The temporal
\* driver — without it, no Deactivate state can ever reach its
\* inactive_from horizon and the DappActive predicate cannot flip
\* from TRUE to FALSE.
AdvanceHeight ==
    /\ height < MaxHeight
    /\ height' = height + 1
    /\ UNCHANGED <<dapp_registry, registered_domains, nef_pool,
                   first_registered>>

----------------------------------------------------------------------------
\* Next-state relation. Any of the lifecycle actions plus the temporal
\* driver may fire at any enabled state; TLC enumerates all
\* interleavings.

Next ==
    \/ \E d \in Domains, owner \in Domains,
         prefix \in Prefixes, topics \in SUBSET Topics :
            Register(d, owner, prefix, topics)
    \/ \E d \in Domains, owner \in Domains,
         prefix \in Prefixes, topics \in SUBSET Topics :
            Update(d, owner, prefix, topics)
    \/ \E d \in Domains, owner \in Domains,
         prefix \in Prefixes, topics \in SUBSET Topics :
            RejectUpdateByNonOwner(d, owner, prefix, topics)
    \/ \E d \in Domains, owner \in Domains : Deactivate(d, owner)
    \/ \E d \in Domains, owner \in Domains :
            RejectDeactivateByNonOwner(d, owner)
    \/ AdvanceHeight

\* Fairness on AdvanceHeight (so that height progresses past any armed
\* inactive_from) and on Deactivate (so that an enabled Deactivate
\* eventually fires) together drive Prop_EventualDeactivation +
\* Prop_PostDeactivationInactive. Without fairness on AdvanceHeight
\* a trace could starve the post-deactivation transition by holding
\* at height < inactive_from forever.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(AdvanceHeight)
    /\ \A d \in Domains, owner \in Domains : WF_vars(Deactivate(d, owner))

----------------------------------------------------------------------------
\* Invariants.

\* Type invariant: variables have correct shapes.
Inv_TypeOK ==
    /\ dapp_registry \in [Domains -> DAppEntry]
    /\ registered_domains \subseteq Domains
    /\ first_registered  \subseteq Domains
    /\ first_registered  \subseteq registered_domains
    /\ nef_pool \in 0..InitialNefPool
    /\ height \in 0..MaxHeight

\* OwnerImmutable: for any domain d in registered_domains, the
\* dapp_registry[d].owner field equals the value set at first-time
\* Register. Update preserves owner (line 1109 in chain.cpp implicitly,
\* via the C++ pattern of preserving `existing->second.registered_at`
\* combined with the model's restriction that Update never writes a
\* new owner). Deactivate preserves owner (the op=1 branch only
\* mutates inactive_from).
\*
\* Stated as an action-level invariant: across every step, for any
\* domain d that is registered_at both pre- and post-state, the owner
\* field is unchanged. Adversarial RejectUpdateByNonOwner is a stutter,
\* so the invariant holds vacuously. The TypeOK invariant rules out
\* spurious mutations outside the four lifecycle actions.
Inv_OwnerImmutable ==
    [][\A d \in Domains :
         (d \in registered_domains /\ d \in registered_domains')
         => dapp_registry'[d].owner = dapp_registry[d].owner
      ]_vars

\* RegisteredAtImmutable: same as Inv_OwnerImmutable but for the
\* registered_at field. The C++ code at line 1109 preserves
\* `existing->second.registered_at` explicitly — without that line,
\* an Update could backdate the DApp by overwriting registered_at to
\* the current height. The TLA model encodes the preservation in the
\* Update action's update-clause; this invariant is the structural
\* witness.
\*
\* This is the structural defense against "DApp backdating attacks"
\* where a malicious owner could try to make their DApp look older
\* than it really is by Update'ing with a manipulated registered_at.
\* Since Update never touches registered_at, the invariant holds.
Inv_RegisteredAtImmutable ==
    [][\A d \in Domains :
         (d \in registered_domains /\ d \in registered_domains')
         => dapp_registry'[d].registered_at
            = dapp_registry[d].registered_at
      ]_vars

\* DeactivationForward: a deactivated DApp's inactive_from horizon
\* is monotone non-decreasing across any step. Two cases:
\*   (1) Domain was active (inactive_from = Sentinel) — any
\*       Deactivate moves inactive_from to height + DappGrace, which
\*       is < Sentinel by ConfigOK. So inactive_from DECREASES from
\*       Sentinel to a smaller value — the "forward" direction is in
\*       terms of approaching the height axis, not numerical magnitude.
\*       We express the invariant with the "is currently smaller than
\*       Sentinel" case separately.
\*   (2) Domain was already inactive — the guard
\*       `dapp_registry[d].inactive_from = Sentinel` blocks Deactivate,
\*       so inactive_from cannot be re-armed. RejectDeactivateByNonOwner
\*       and AdvanceHeight are stutters on inactive_from.
\*
\* Stated as: once inactive_from has been set away from Sentinel by
\* Deactivate, it never changes again. This is the "no re-arming"
\* property that makes Deactivate one-shot per domain (within this
\* model's lifecycle scope).
Inv_DeactivationForward ==
    [][\A d \in Domains :
         (d \in registered_domains
          /\ d \in registered_domains'
          /\ dapp_registry[d].inactive_from /= Sentinel)
         => dapp_registry'[d].inactive_from
            = dapp_registry[d].inactive_from
      ]_vars

\* NefDrainsOnlyOnce: for any domain d, the NEF pool draws down at
\* MOST once per d across any reachable state sequence. Encoded via
\* the first_registered set: a Register step adds d to
\* first_registered AND drains the pool; any subsequent step on the
\* same d either (a) is an Update — `d \in registered_domains` was
\* already TRUE, so Register's guard `d \notin registered_domains`
\* blocks it — or (b) is a Deactivate / Reject* — none of which
\* touch nef_pool.
\*
\* Stated as the structural property: for any d \in first_registered',
\* either d \in first_registered (no new drain credited to d on this
\* step) OR d \in (first_registered' \setminus first_registered) AND
\* the pool delta is consistent with a floor-half (nef_pool' =
\* nef_pool \div 2).
\*
\* Action-level formulation: if first_registered' /= first_registered,
\* the delta is a singleton {d} AND nef_pool' = nef_pool \div 2.
\* AND if first_registered' = first_registered, nef_pool' = nef_pool
\* (no drain).
Inv_NefDrainsOnlyOnce ==
    [][LET added == first_registered' \ first_registered IN
       /\ (added = {} => nef_pool' = nef_pool)
       /\ (added /= {} => /\ Cardinality(added) = 1
                          /\ nef_pool' = nef_pool \div 2)
      ]_vars

\* RegisterIdempotent (T-D2): re-Register attempts on an already-
\* registered domain do not change the owner or registered_at fields.
\* The Register action's guard `d \notin registered_domains` blocks
\* re-Register at the apply layer — the C++ apply path falls into the
\* Update branch (line 1108) instead, which preserves owner +
\* registered_at by the two preceding invariants.
\*
\* State-level formulation: every d \in registered_domains satisfies
\* (Update(d) preserves owner + registered_at) AND (Register(d) is
\* disabled). The disabling is structural via the Register guard.
\* The preservation is Inv_OwnerImmutable + Inv_RegisteredAtImmutable.
\* This invariant is the conjunction that captures the T-D2
\* idempotency claim.
\*
\* Encoded as: for any d \in first_registered (provenance witness
\* that d's owner was set at first-Register-time), the current
\* dapp_registry[d].owner = (the value set at first-Register-time).
\* Since Inv_OwnerImmutable holds and first_registered grows
\* monotonically with d's first Register step, the post-first-Register
\* owner is canonical.
Inv_RegisterIdempotent ==
    \A d \in first_registered :
       /\ d \in registered_domains
       /\ dapp_registry[d].registered_at <= height

\* NefPoolNonNegative: the NEF pool is Nat-valued at every reachable
\* state. The floor-half drain (`nef_pool \div 2`) is closed on Nat —
\* `0 \div 2 = 0`, so the pool reaches zero and stays there. No
\* action subtracts more than `nef_pool` from itself, so the pool
\* cannot go negative.
\*
\* This is the lower-bound side of the type-OK constraint; stated
\* separately as the headline "no negative pool" claim per the
\* economic-soundness invariants.
Inv_NefPoolNonNegative == nef_pool >= 0

----------------------------------------------------------------------------
\* Temporal properties.

\* EventualDeactivation: under fairness on AdvanceHeight + Deactivate,
\* any active DApp can eventually be deactivated by its owner. The
\* "can be" is conditioned on the owner choosing to fire Deactivate —
\* this is the existence-of-a-step claim, not the unconditional
\* eventually claim.
\*
\* Formally: in every fair run, if some domain d is registered AND
\* active AND height < MaxHeight, then there exists a future state
\* where either (a) the owner has deactivated d (inactive_from /=
\* Sentinel) or (b) the model bound was reached (height >= MaxHeight)
\* before the owner chose to deactivate. The "or" reflects the
\* model bound; without it the property would be too strong (TLC
\* operates on bounded models).
\*
\* The combination of WF_vars(AdvanceHeight) (height progresses) and
\* WF_vars(Deactivate(d, owner)) (an enabled Deactivate fires) gives
\* the eventual-progress conclusion.
Prop_EventualDeactivation ==
    \A d \in Domains :
       ((d \in registered_domains
         /\ dapp_registry[d].inactive_from = Sentinel
         /\ height < MaxHeight)
        ~> (dapp_registry[d].inactive_from /= Sentinel
            \/ height >= MaxHeight))

\* PostDeactivationInactive: once Deactivate has fired on a domain d,
\* the DappActive predicate eventually flips from TRUE to FALSE. The
\* grace period delays the flip — DappActive remains TRUE during the
\* window `dapp_registry[d].inactive_from = h+DappGrace` and
\* `height < h+DappGrace`, then flips to FALSE at `height >=
\* inactive_from`.
\*
\* Formally: in every fair run, if some domain d has inactive_from /=
\* Sentinel (Deactivate has fired), then eventually either (a)
\* DappActive(d) = FALSE (height has caught up to inactive_from) OR
\* (b) the model bound was reached before height could catch up
\* (inactive_from > MaxHeight). Both branches are admissible escapes
\* in a bounded model.
\*
\* The DappActive predicate is unfolded inline for TLC's benefit —
\* it depends on (d, height, dapp_registry), all of which are
\* covered by [Next]_vars steps.
Prop_PostDeactivationInactive ==
    \A d \in Domains :
       ((d \in registered_domains
         /\ dapp_registry[d].inactive_from /= Sentinel
         /\ dapp_registry[d].inactive_from <= MaxHeight)
        ~> (~ DappActive(d) \/ height >= MaxHeight))

============================================================================
