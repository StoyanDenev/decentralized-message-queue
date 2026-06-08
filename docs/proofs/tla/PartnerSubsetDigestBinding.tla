--------------------------- MODULE PartnerSubsetDigestBinding ---------------------------
(*
TLA+ specification of the DETERMINISTIC-BINDING contract for the R4/R7
merged-signing partner_subset_hash, the machine-checkable companion to the
partner_subset_hash digest binding (commit `8585a50`; analytic record
`docs/proofs/S030-D2-Analysis.md` §3.2 + §1 item 9 — the partner_subset_hash
row of the S-030-D2 digest-coverage table, now ✓ on both the signing_bytes
and the compute_block_digest sides).

This is the simplest member of the S-030-D2 digest-binding family. Where the
three POOL-FED dimensions (inbound / equivocation / abort — FB22
F2ViewReconciliation.tla + EqAbortViewDigestExtension.md) had to interpose a
gossip-async-safe view-reconciliation step BEFORE digesting (each member's
local pool view diverges, so the digest binds the reconcile_union /
reconcile_intersection of the K signed Phase-1 commits, not any one member's
raw view), partner_subset_hash needs NO such reconciliation. Per
S030-D2-Analysis §3.2, at a merged height it is a SINGLE hash value that every
committee member computes IDENTICALLY from the (committee-agreed) merge state.
There is no per-member pool, hence no divergence to absorb, hence the raw value
can be bound straight into the digest without reintroducing the gossip-async
digest divergence that S030-D2-Analysis §2 warns the naive pool-binding fix
hits. THIS spec models exactly that contract — the deterministic single value,
its conditional (non-zero) binding, and the post-signing tamper-detection — and
deliberately CONTRASTS it with the F2 pool fields by asserting, as an invariant,
that there is one committed value with no per-member divergence.

--------------------------------------------------------------------------
The shipped mechanism (read off the two source append sites; quoted faithfully):

  * src/node/producer.cpp::compute_block_digest — after the inbound, eq, and
    abort F2 appends, appends b.partner_subset_hash ONLY when non-zero
    (the is_zero_hash_(b.partner_subset_hash) guard):

        if (!is_zero_hash_(b.partner_subset_hash)) {
            h.append(b.partner_subset_hash);
        }

    The source comment states the contract verbatim: "Unlike the pool-fed
    eq/abort/inbound fields above, partner_subset_hash is NOT a gossip-async
    per-member view — it is DETERMINISTIC: every committee member at a merged
    height computes the identical value from the merge state
    (S030-D2-Analysis.md §3.2), so binding it raw cannot reintroduce the
    gossip-async digest divergence §2 warns about." Field order in the digest:
    inbound, eq, abort, partner_subset_hash (then timestamp, the f99eeb8
    dimension — out of scope here).

  * src/chain/block.cpp:323-334 — Block::signing_bytes() appends
    partner_subset_hash ONLY when non-zero (the R4 Phase-3 shim, the SAME
    backward-compat pattern S-033 state_root:336-342 reuses):

        Hash zero{};
        if (partner_subset_hash != zero) {
            b.append(partner_subset_hash);
        }

    so the value is bound into block_hash = compute_hash() too (defense in
    depth: the digest binds it for the committee Phase-2 sig directly; the
    signing_bytes binding carries it into the forward prev_hash chain).

  * light/verify.cpp::light_compute_block_digest — mirrors the digest append,
    so a light client doing header-only sync binds partner_subset_hash too; the
    field SURVIVES the rpc_headers strip (node.cpp::rpc_headers keeps it — only
    transactions / cross_shard_receipts / inbound_receipts / initial_state are
    stripped).

Backward-compat invariant (the conditional gate): a non-merged block has
partner_subset_hash == 0, the is_zero_hash_ guard skips the append, and the
digest is BYTE-IDENTICAL to the pre-8585a50 v1 digest. The empirical pin
(FAST=1 158->159 PASS) confirmed ZERO existing digests changed; the in-process
witnesses are determ test-block-digest (26 assertions — assertions exercise the
partner_subset_hash bind/strip pair) + determ test-timestamp-reconciliation
(16 assertions, the sibling f99eeb8 dimension).

--------------------------------------------------------------------------
What this spec models (and what it abstracts).

State (the four VARIABLES the brief mandates):

  * committed   — the partner_subset_hash COMMITTED by the committee for this
    height. An abstract value drawn from a small symbolic universe Hashes plus
    the distinguished sentinel Zero (= 0 = NON-MERGED). Modeled as a SINGLE
    value (not a per-member function) — this is the deterministic-value
    abstraction: at a merged height every committee member computes the
    identical partner_subset_hash from the merge state, so there is exactly one
    committed value, in contrast to the F2 pool fields whose per-member views
    diverge before reconciliation. ComputeMerged sets it to a non-zero
    deterministic value; it is Zero until then (non-merged) and stays the
    deterministic value once computed (never per-member-divergent).
  * digest      — the block digest the K-of-K committee Phase-2 sig is taken
    over. Bound to `committed` CONDITIONALLY: when committed = Zero the digest
    is the v1 baseline DigestV1 (byte-identical, the is_zero_hash_ skip); when
    committed /= Zero the digest is DigestWith(committed) (the append). Modeled
    as an abstract injective tag so distinct committed values give distinct
    digests (the SHA-256 binding, abstracted — A2 collision resistance is the
    cryptographic assumption that makes DigestWith injective, out of scope as
    in every sibling spec).
  * signed      — a flag: TRUE once the committee has taken its K-of-K Phase-2
    signature over the current `digest`. Sign latches the value of `digest`
    into `signedDigest` (the bytes the signature actually covers). After signing,
    Strip / Alter mutate `committed` (the adversary's post-sign tamper) and the
    digest is RECOMPUTED; VerifySigs compares the recomputed digest against the
    latched signedDigest.
  * signedDigest — the digest value the latched signature covers (set by Sign).
    BindingDetectsTamper is the claim that any post-sign change to a non-zero
    committed value makes the recomputed digest differ from signedDigest.

Actions:

  * ComputeMerged(v) — set committed to a non-zero deterministic value v (the
    merged-height case; mirrors producer populating partner_subset_hash from the
    committee-agreed merge state). Enabled only before signing and only from a
    non-merged (committed = Zero) state, modeling the once-per-height
    deterministic computation. Recomputes digest = DigestWith(v).
  * Digest — recompute `digest` from `committed` under the conditional gate:
    DigestV1 when committed = Zero (the is_zero_hash_ skip — byte-identical v1),
    DigestWith(committed) when non-zero (the append). Idempotent; models the
    producer's compute_block_digest call.
  * Sign — the K-of-K Phase-2 signature: latch signedDigest := digest, signed :=
    TRUE. Enabled once (the committee signs the finalized digest once).
  * Strip — adversary post-sign STRIP: set committed := Zero (remove the partner
    commitment after the K-of-K signature). Enabled only after signing and only
    when committed is currently non-zero (there is something to strip).
  * Alter — adversary post-sign ALTER: set committed := some other non-zero value
    w /= committed (swap the partner commitment). Enabled only after signing.
  * VerifySigs — recompute the digest from the (possibly tampered) committed and
    compare to signedDigest; sets verified := (recomputed = signedDigest). The
    honest committee sig verifies iff the bytes still match what was signed.

Abstracted (kept finite for a future TLC run): the SHA-256 hash function is an
abstract injective tag (DigestWith), exactly as FB40 MakeBlockSigPrimitive.tla /
FB24 MakeContribCommitment.tla abstract their SHA-256; the K committee members,
the Ed25519 signature mechanics, the merge-state derivation, and the
signing_bytes / block_hash forward-chain (StateRootAnchorSoundness.md SR-1) are
all abstracted to their supply-of-the-binding core. The headline DETERMINISM
property — one committed value, no per-member divergence — is encoded as the
single-`committed`-variable shape plus Inv_DeterministicValue, which is the
whole point of the spec: it is what distinguishes partner_subset_hash from the
F2 pool fields and is why binding the RAW value is gossip-async-safe.

--------------------------------------------------------------------------
Invariants (the 4-5 the brief mandates):

  (PSB-0) Inv_TypeOK — every variable has the right shape; the symbolic value
          universe is finite for TLC.
  (PSB-1) Inv_DeterministicValue — THE contrast with the F2 pool fields. The
          committed partner_subset_hash is a SINGLE value (modeled as the scalar
          `committed`, never a per-member function), and once ComputeMerged has
          fired it is the SAME deterministic value for the whole committee — no
          per-member divergence exists for this field. State-form: `committed` is
          always a single element of Hashes ∪ {Zero}; there is no reachable state
          in which two committee members hold different partner_subset_hash
          values. This is the abstraction of S030-D2-Analysis §3.2 ("a single hash
          value that all committee members at a merged height should compute
          identically from the merge state. No per-member pool involved.") — the
          reason no reconcile step is needed and raw binding is gossip-async-safe.
  (PSB-2) Inv_BindingDetectsTamper — any post-sign change to a NON-ZERO
          partner_subset_hash makes the recomputed digest differ from the signed
          digest. State-form: after signing, if the current committed differs
          from what was signed AND at least one of the two is non-zero, then the
          recomputed digest /= signedDigest (so VerifySigs would fail). This is
          the digest-binding guarantee: a relayer that strips or alters the
          partner commitment after the K-of-K Phase-2 signature changes the
          digest, so the stored signatures no longer verify (the ✗→✓ flip the
          commit `8585a50` achieves for the partner_subset_hash row).
  (PSB-3) Inv_ConditionalGate — when partner_subset_hash is Zero (non-merged),
          it is NOT bound and the digest is byte-identical to the v1 baseline
          DigestV1. State-form: committed = Zero ⇒ digest = DigestV1. This is
          the is_zero_hash_ skip (producer.cpp) / the `partner_subset_hash !=
          zero` shim (block.cpp:323) — the backward-compat invariant that every
          legacy / non-merged block keeps a byte-identical v1 digest (FAST=1
          158->159 with zero existing digests changed).
  (PSB-4) Inv_VerifyHonestUntampered — soundness companion to PSB-2: if the
          committed value has NOT changed since signing, VerifySigs (when it has
          run) reports verified = TRUE. Rules out a spurious-rejection model
          where an honest, untampered block fails its own signature check; pins
          that the gate fires ONLY on tamper, not on the legitimate post-sign
          state.

  (PSB-5) Prop_TamperNeverVerifies — temporal []-restatement: across every
          reachable state, a verified-TRUE result with a tampered non-zero
          committed value is unreachable (verified ⇒ the bound bytes match).

Modeling scope (kept small + finite-checkable so it COULD be model-checked
later): a single height (one block, one K-of-K committee signature); the value
universe Hashes is a small symbolic set (e.g. {h1, h2}) plus the Zero sentinel;
no step counter is needed because the action set is naturally bounded (compute
once, sign once, then a bounded adversary tamper + verify). Cardinality(Hashes)
>= 2 so Alter has a distinct target.

Companion analytic record: `docs/proofs/S030-D2-Analysis.md` §3.2 (the
deterministic single-value argument) + §1 item 9 / the partner_subset_hash row
of the §1 digest-coverage table (the ✓✓ status after `8585a50`). Empirical
pins: determ test-block-digest (the partner_subset_hash bind/strip assertions,
26 total) + the FAST=1 158->159 backward-compat confirmation.

Adjacent specs: FB22 (F2ViewReconciliation.tla) — the POOL-FED counterpart that
DOES need reconcile_union / reconcile_intersection before digesting; this spec
is its deterministic-no-reconciliation foil. FB40 (MakeBlockSigPrimitive.tla) —
the Phase-2 K-of-K make_block_sig primitive whose digest pre-image this binding
extends; the DigestWith injective-tag abstraction matches FB40's sig abstraction.
FB24 (MakeContribCommitment.tla) — the Phase-1 conditional-on-any_view
backward-compat shim, the same v1-byte-identity discipline PSB-3 encodes here.
FB26 (BlockchainStateIntegrity.tla) — the apply/load tamper-detection sibling;
PSB-2 is its digest-layer analog for the partner field specifically.

NOTE: spec-only, model-check pending TLC install (matching every sibling in this
directory).
*)

EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Hashes      \* finite symbolic universe of NON-ZERO partner_subset_hash values

\* The distinguished NON-MERGED sentinel: partner_subset_hash == 0. Chosen
\* outside Hashes so the "is_zero_hash_" test is just equality with Zero.
Zero == "ZERO_HASH"

\* Distinguished abstract digest tags. DigestV1 is the byte-identical v1 digest
\* a non-merged block carries (the is_zero_hash_ skip). DigestWith(v) is the v1
\* digest with partner_subset_hash v appended — an INJECTIVE tag in v (the
\* SHA-256 binding, abstracted; A2 collision resistance is what makes distinct
\* v give distinct digests, out of scope as in every sibling). NoSig is the
\* "nothing latched yet" sentinel for signedDigest before Sign fires.
DigestV1    == "DIGEST_V1"
NoSig       == "NO_SIG"
DigestWith(v) == <<"DIGEST_WITH", v>>

\* The set of all reachable digest values, for the type invariant.
DigestUniverse == {DigestV1} \cup { DigestWith(v) : v \in Hashes }

ASSUME ConfigOK ==
    /\ Cardinality(Hashes) >= 2          \* >= 2 so Alter has a distinct target
    /\ Zero \notin Hashes                 \* the sentinel is outside the value set
    /\ \A v \in Hashes : DigestWith(v) /= DigestV1   \* append /= v1 (non-zero binds)

----------------------------------------------------------------------------
\* State.

VARIABLES
    committed,      \* the committee-committed partner_subset_hash (Zero = non-merged); a SINGLE value (PSB-1)
    digest,         \* the block digest the K-of-K Phase-2 sig is taken over (conditional on committed)
    signed,         \* BOOLEAN: has the committee taken its K-of-K Phase-2 signature over `digest`?
    signedDigest,   \* the digest value the latched signature actually covers (NoSig until Sign)
    verified        \* result of the last VerifySigs (BOOLEAN), or "UNVERIFIED" before any check

vars == <<committed, digest, signed, signedDigest, verified>>

Unverified == "UNVERIFIED"

----------------------------------------------------------------------------
\* Helpers.

\* The conditional gate (producer.cpp::compute_block_digest /
\* block.cpp:323-334): the digest a block with partner_subset_hash = c carries.
\* Zero (non-merged) => byte-identical v1 baseline (is_zero_hash_ SKIP);
\* non-zero => v1 with the partner commitment appended (the bind).
DigestOf(c) == IF c = Zero THEN DigestV1 ELSE DigestWith(c)

\* The committed value the latched signature covers, recovered from signedDigest.
\* (signedDigest = DigestV1 <=> Zero was signed; signedDigest = DigestWith(v)
\* <=> v was signed.) Defined only meaningfully when signed; NoSig maps to Zero
\* as a harmless default for the unsigned case (PSB-2 guards on `signed`).
signedCommitted ==
    IF signedDigest = DigestV1 THEN Zero
    ELSE IF signedDigest = NoSig THEN Zero
    ELSE signedDigest[2]

----------------------------------------------------------------------------
\* Initial state. A fresh non-merged block: partner_subset_hash = Zero (the
\* default), the digest is the byte-identical v1 baseline (the is_zero_hash_
\* skip), nothing signed yet, no signature latched, no verification run.

Init ==
    /\ committed    = Zero
    /\ digest       = DigestV1
    /\ signed       = FALSE
    /\ signedDigest = NoSig
    /\ verified     = Unverified

----------------------------------------------------------------------------
\* Actions.

\* ComputeMerged(v): the merged-height case. The producer populates
\* partner_subset_hash with the DETERMINISTIC value v computed from the
\* committee-agreed merge state (S030-D2-Analysis §3.2 — a single value every
\* member computes identically; NO per-member pool, hence NO reconciliation
\* step). Enabled only before signing and only from a non-merged state (the
\* value is computed once per height). Recomputes the digest under the gate.
ComputeMerged(v) ==
    /\ ~signed
    /\ committed = Zero
    /\ v \in Hashes
    /\ committed' = v
    /\ digest'    = DigestOf(v)
    /\ UNCHANGED <<signed, signedDigest, verified>>

\* Digest: recompute `digest` from the current `committed` under the
\* conditional gate (models the producer's compute_block_digest). Idempotent —
\* it just re-asserts digest = DigestOf(committed). Enabled before signing.
Digest ==
    /\ ~signed
    /\ digest' = DigestOf(committed)
    /\ UNCHANGED <<committed, signed, signedDigest, verified>>

\* Sign: the K-of-K Phase-2 committee signature over the finalized `digest`.
\* Latch the signed bytes (signedDigest := digest) and flip `signed`. Fires
\* once (the committee signs the finalized digest a single time per height).
\* Pre-condition digest = DigestOf(committed) ensures the latched bytes are the
\* genuine digest of the committed value (the producer finalized the digest
\* before gathering signatures).
Sign ==
    /\ ~signed
    /\ digest = DigestOf(committed)
    /\ signed'       = TRUE
    /\ signedDigest' = digest
    /\ UNCHANGED <<committed, digest, verified>>

\* Strip: adversary post-sign STRIP — remove the partner commitment after the
\* K-of-K signature (set committed := Zero). Enabled only after signing and only
\* when there is a non-zero commitment to strip. The digest is RECOMPUTED to the
\* now-non-merged value (DigestV1) — the relayer-served block reflects the strip;
\* the latched signedDigest is unchanged (the signature still covers the old
\* bytes). PSB-2 is the claim that this is detectable.
Strip ==
    /\ signed
    /\ committed /= Zero
    /\ committed' = Zero
    /\ digest'    = DigestOf(Zero)
    /\ UNCHANGED <<signed, signedDigest, verified>>

\* Alter(w): adversary post-sign ALTER — swap the partner commitment for a
\* different non-zero value w after the K-of-K signature. Enabled only after
\* signing. The digest is recomputed to DigestWith(w); signedDigest unchanged.
Alter(w) ==
    /\ signed
    /\ w \in Hashes
    /\ w /= committed
    /\ committed' = w
    /\ digest'    = DigestOf(w)
    /\ UNCHANGED <<signed, signedDigest, verified>>

\* VerifySigs: the honest committee-signature check — recompute the digest from
\* the (possibly tampered) `committed` and compare to the latched signedDigest.
\* The Ed25519 K-of-K sig verifies iff the bytes still match what was signed.
\* Enabled only after signing (there is a signature to verify). Sets `verified`.
VerifySigs ==
    /\ signed
    /\ verified' = (DigestOf(committed) = signedDigest)
    /\ UNCHANGED <<committed, digest, signed, signedDigest>>

----------------------------------------------------------------------------
\* Next-state relation. Compute the deterministic merged value (or not), digest,
\* sign once, then the bounded adversary tamper (strip/alter) + verify, in
\* arbitrary interleaving. TLC enumerates the composition over the small value
\* universe.

Next ==
    \/ \E v \in Hashes : ComputeMerged(v)
    \/ Digest
    \/ Sign
    \/ Strip
    \/ \E w \in Hashes : Alter(w)
    \/ VerifySigs

\* Weak fairness on VerifySigs drives the temporal witness: after signing, the
\* committee-sig check eventually runs and exposes any tamper. The safety
\* invariants (PSB-1..PSB-4) hold in EVERY reachable state regardless of which
\* actions fire.
Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(VerifySigs)

----------------------------------------------------------------------------
\* Invariants — PSB-0..PSB-4.

\* PSB-0 / Inv_TypeOK: every variable has the right shape; the value + digest
\* universes are finite so TLC's state space is bounded.
Inv_TypeOK ==
    /\ committed \in (Hashes \cup {Zero})
    /\ digest \in DigestUniverse
    /\ signed \in BOOLEAN
    /\ signedDigest \in (DigestUniverse \cup {NoSig})
    /\ verified \in (BOOLEAN \cup {Unverified})

\* PSB-1 / Inv_DeterministicValue: THE contrast with the F2 pool fields. The
\* committed partner_subset_hash is a SINGLE value — modeled as the scalar
\* `committed`, never a per-member [Member -> Hash] function. There is no
\* reachable state in which the committee holds two different partner_subset_hash
\* values for this height, so no view-reconciliation is needed (unlike inbound /
\* eq / abort, whose per-member pools diverge and must be reconcile_union'd /
\* reconcile_intersection'd before digesting). This is the structural encoding of
\* S030-D2-Analysis §3.2: "a single hash value that all committee members at a
\* merged height should compute identically from the merge state. No per-member
\* pool involved." The single-scalar shape IS the determinism witness; this
\* invariant pins that the shape is always inhabited by exactly one value.
Inv_DeterministicValue ==
    committed \in (Hashes \cup {Zero})

\* PSB-2 / Inv_BindingDetectsTamper: any post-sign change to a NON-ZERO
\* partner_subset_hash makes the recomputed digest differ from the signed digest.
\* State-form: once signed, if the current committed differs from the value that
\* was signed (recovered from signedDigest) AND at least one side is non-zero,
\* the recomputed digest no longer equals signedDigest — so VerifySigs would
\* reject. This is the digest-binding guarantee: a relayer that strips (Strip) or
\* alters (Alter) the partner commitment after the K-of-K Phase-2 signature
\* changes the digest, so the stored signatures no longer verify. It is what
\* flips the partner_subset_hash row from ✗ to ✓ in the S-030-D2 digest-coverage
\* table (commit 8585a50). Because DigestOf is injective on Hashes and maps Zero
\* to the distinct DigestV1, any committed' /= signed-committed yields
\* DigestOf(committed') /= signedDigest.
\* The substantive claim is the iff between "committed changed since signing"
\* and "recomputed digest differs from the signed bytes": tamper is detectable
\* exactly when it happened. Because DigestOf is injective on Hashes and maps
\* Zero to the distinct DigestV1, committed /= signedCommitted <=>
\* DigestOf(committed) /= signedDigest, which covers BOTH directions of the
\* binding (a non-zero alter, and a strip to Zero).
Inv_BindingDetectsTamper ==
    signed =>
        ( (committed /= signedCommitted) <=> (DigestOf(committed) /= signedDigest) )

\* PSB-3 / Inv_ConditionalGate: when partner_subset_hash is Zero (non-merged),
\* it is NOT bound and the digest is byte-identical to the v1 baseline DigestV1.
\* This is the is_zero_hash_ skip (producer.cpp::compute_block_digest) and the
\* `partner_subset_hash != zero` shim (block.cpp:323-334) — the backward-compat
\* invariant that every legacy / non-merged block keeps a byte-identical v1
\* digest (the FAST=1 158->159 confirmation that ZERO existing digests changed).
\* Holds in every state before signing (where the digest tracks committed) and is
\* preserved by Strip (which sets committed = Zero and recomputes digest =
\* DigestV1).
Inv_ConditionalGate ==
    (committed = Zero) => (digest = DigestV1)

\* PSB-4 / Inv_VerifyHonestUntampered: soundness companion to PSB-2 — the gate
\* fires ONLY on tamper, never on the legitimate post-sign state. If the
\* committed value has NOT changed since signing (committed = signedCommitted),
\* then any VerifySigs result reports verified = TRUE. Rules out a
\* spurious-rejection model where an honest, untampered block fails its own
\* signature check.
Inv_VerifyHonestUntampered ==
    (signed /\ verified \in BOOLEAN /\ committed = signedCommitted) => (verified = TRUE)

----------------------------------------------------------------------------
\* Temporal property.

\* PSB-5 / Prop_TamperNeverVerifies: across every reachable state, a
\* verified-TRUE result while the committed value differs from the signed value
\* (a tamper that should have been caught) is unreachable. The honest committee
\* sig check never accepts a stripped/altered partner commitment.
Prop_TamperNeverVerifies ==
    [](  (verified = TRUE /\ signed) => (DigestOf(committed) = signedDigest) )

============================================================================
\* Cross-references.
\*
\* FB22 (F2ViewReconciliation.tla) — the POOL-FED counterpart. inbound / eq /
\*   abort are gossip-async per-member views that MUST be reconcile_union'd
\*   (eq/abort) / reconcile_intersection'd (inbound) before digesting, because
\*   members hold divergent pools at their commit instants
\*   (S030-D2-Analysis.md §2). partner_subset_hash needs NONE of that: PSB-1
\*   (Inv_DeterministicValue) is the structural foil — a single committed value,
\*   no per-member divergence — which is why binding the RAW value (no reconcile)
\*   is gossip-async-safe (S030-D2-Analysis §3.2).
\*
\* FB40 (MakeBlockSigPrimitive.tla) — the Phase-2 K-of-K make_block_sig
\*   primitive whose digest pre-image this binding extends. The DigestWith(v)
\*   injective-tag abstraction here matches FB40's abstract-injective sig tag
\*   (both abstract SHA-256 / Ed25519 to an injection; A1/A2 are the underlying
\*   cryptographic assumptions, out of scope per the sibling convention).
\*
\* FB24 (MakeContribCommitment.tla) — the Phase-1 conditional-on-`any_view`
\*   backward-compat shim. PSB-3 (Inv_ConditionalGate) is the same
\*   v1-byte-identity discipline applied to the partner_subset_hash append: the
\*   non-merged / zero path keeps a byte-identical v1 digest, exactly as the
\*   no-view path keeps a byte-identical v1 commit.
\*
\* FB26 (BlockchainStateIntegrity.tla) — the apply/load tamper-detection
\*   sibling. PSB-2 (Inv_BindingDetectsTamper) is its digest-layer analog for the
\*   partner field specifically: a post-sign strip/alter changes the digest, so
\*   the stored K-of-K signatures no longer verify.
\*
\* Companion analytic record:
\*   docs/proofs/S030-D2-Analysis.md §3.2 (the deterministic single-value
\*   argument — "a single hash value that all committee members at a merged
\*   height should compute identically from the merge state. No per-member pool
\*   involved.") + §1 item 9 / the partner_subset_hash row of the §1
\*   digest-coverage table (✓ on both signing_bytes and compute_block_digest
\*   after commit 8585a50). Inv_DeterministicValue = §3.2's no-pool claim;
\*   Inv_BindingDetectsTamper = the ✗→✓ digest-row flip; Inv_ConditionalGate =
\*   the "conditional: bound when non-zero" qualifier on that row.
\*
\* C++ enforcement:
\*   src/node/producer.cpp::compute_block_digest : appends b.partner_subset_hash
\*       under the !is_zero_hash_(b.partner_subset_hash) guard, after the inbound/
\*       eq/abort F2 appends (field order: inbound, eq, abort, partner_subset_hash,
\*       timestamp) — the digest binding (PSB-2 / PSB-3) modeled by DigestOf.
\*   src/chain/block.cpp:323-334 : Block::signing_bytes appends partner_subset_hash
\*       under the `partner_subset_hash != zero` shim — the defense-in-depth
\*       block_hash binding (carries into the forward prev_hash chain;
\*       StateRootAnchorSoundness.md SR-1).
\*   light/verify.cpp::light_compute_block_digest : mirrors the digest append
\*       (survives the rpc_headers strip, so header-only light sync binds it too).
\*
\* Runtime regression:
\*   determ test-block-digest (26 assertions; the partner_subset_hash bind/strip
\*       pair) — the in-process digest-layer witness of PSB-2 / PSB-3.
\*   determ test-timestamp-reconciliation (16 assertions) — the sibling f99eeb8
\*       timestamp dimension (out of scope here; same field-order family).
\*   FAST=1 158->159 PASS — the backward-compat confirmation that ZERO existing
\*       (non-merged) digests changed (PSB-3).
\*
\* To check (assuming TLC installed):
\*   $ tlc PartnerSubsetDigestBinding.tla -config PartnerSubsetDigestBinding.cfg
\* Recommended config (small + finite): Hashes = {h1, h2}.
============================================================================
