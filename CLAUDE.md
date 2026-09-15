This is working folder for DLT
Tone: direct and professional, not chatty

## PROJECT DOCTRINE — non-negotiable, applies to ALL work
Read this before writing code or docs. On any decision conflict, docs/proofs/DECISION-LOG.md wins.

- Provable security (B3): every claim is proof-backed, nothing aspirational.
  New behavior ships with a falsify-on-mutant gate. Do not add unproven or
  speculative surface.
- Green is not proof (B3 corollary; measured 2026-08-12/13, DECISION-LOG). A
  falsify-on-mutant gate proves the code enforces what the gate ASSERTS. It
  cannot prove the assertion is the property you NEED. Nine consensus designs in
  one session were wrong; six of them were carried to a green tree — Option D's
  gate was 34/34 with six mutants confirmed RED and FAST 303/0 — and three were
  refuted on paper (DECISION-LOG 2026-08-13, doctrine entry). For consensus work a
  green gate is NECESSARY AND NOT SUFFICIENT. Standing rules:
    * ADVERSARIAL REVIEW OF THE DIFF, BEFORE COMMIT, INDEPENDENT OF GATE COLOUR,
      on any change to consensus accept-rules, the apply path, wire formats,
      committee derivation, or the slashing/evidence path. Across those nine,
      review returned 124 confirmed defects against 11 false alarms; the
      mutant-verified gates shipped with the changes found none of them. A
      purpose-built ratchet is not a substitute — round_seq shipped one and a
      reviewer defeated it with a ONE-LINE edit while it stayed green.
    * ASSERT AT THE LAYER WHERE THE RULE LIVES. A gate built on a producer-side
      proxy goes green while the bug is live; that is exactly how Option C was
      refuted. The slashing predicate is body_root_a != body_root_b in the
      VERIFIER (validator.cpp V11 + the node.cpp adoption gate); the core
      comparison in the in-tree assembler is a courtesy, not the rule.
    * DESIGN-AND-PROVE BEFORE IMPLEMENTING when the design is uncertain. The
      time-bucket and lock-rule designs were REFUTED at design stage for a
      fraction of the cost of the ones implemented first.
    * SMALLEST INCREMENT THAT KEEPS THE TREE GREEN AND TRUTHFUL. All three slashing
      attempts failed and were reverted; the first two by BUNDLING: the ~10-line core removal was verified sound
      BOTH times and was sunk by a per-block cap, an exit-code change and doc
      convergence that each failed independently. Land the verified core alone;
      every rider is its own increment with its own review.
    * VERIFY WITH tools/ci_local.sh — never a bare tools/run_all.sh or bare
      tools/test_*.sh. Only ci_local exports DETERM_BIN / DETERM_WALLET_BIN /
      DETERM_LIGHT_BIN / DETERM_DSF_BIN; a bare run resolves the binary by
      tools/common.sh search order (three "faked" mutant results this session
      were a stale tree shadowing build-linux — that tree is deleted, the
      discipline stands) and SKIPs every DSF gate when DETERM_DSF_BIN is unset.
      CONFIRM THE BUILD SUCCEEDED before trusting any mutant result: a failed
      build leaves the previous binary in place, so the mutant "dies" against
      unmutated code.
- Never seed anything security-relevant from a block hash. Block::compute_hash
  (src/chain/block.cpp) hashes signing_bytes() and then APPENDS
  creator_block_sigs, and Ed25519 verification checks only pk-y canonicality,
  S < L and the group equation — RFC 8032's deterministic nonce is a signer-side
  convention NO verifier can check. So a member broadcasting its BlockSigMsg
  last can enumerate unboundedly many VALID signatures over the SAME
  compute_block_digest, each yielding a different block hash, and publish the
  one that seats the committee it wants: the hash is MALLEABLE under a fixed
  digest, at ~one Ed25519 sign per trial. This is harmless today ONLY because
  committee selection and the subsidy lottery route through cumulative_rand's
  commit-reveal, every input of which is digest-covered or commit-pinned. Keep
  it that way (DECISION-LOG 2026-08-12 "final+9").
- No migrations, ever (owner constraint). Pre-genesis changes are free;
  post-genesis consensus + state format is frozen. Upgrades are additive only.
- From-scratch C99 crypto, zero heavy deps: no libsodium / OpenSSL in the
  consensus path; every primitive vendored in src/crypto/** (CRYPTO-C99-SPEC.md).
- C99 / Minix-portable discipline throughout: no heavy deps, portable C99 so the
  eventual Minix reference build stays possible (docs/C99-MINIX-PORT.md).
- Minimalism / smallest green surface: do not build speculative or aspirational
  surface; delete dead abstraction. A feature that changes zero behavior is not
  built.
- Canonical binary only in storage / wire / keyfiles / test vectors — no JSON on
  those paths (DECISION-LOG D2). Human-readable text is a non-authoritative view.
- Security model is K-of-K mutual distrust + fork-free consensus. FROST is out;
  reintroduction needs owner sign-off (FROST_DEVIATION_NOTICE).
- Sequence-before-harden: do NOT spend B3 falsify-on-mutant effort on code
  scheduled for replacement (e.g. JSON serialization paths pending the D2
  binary migration). Do the replacement first, then gate the survivor —
  hardening doomed code is wasted proof-work. Consensus accept-rule/logic
  fixes that survive a container swap are exempt (they are not 'replaced').
- Convergence: keep the canonical doc set coherent; extend an existing doc, do
  not spawn parallel ones. Rule: a doc with NO tier marker is an authoritative
  convergence point and must track shipped code; a doc marked TIER: FUTURE /
  NEAR-TERM / PROCESS-ARCHIVE is not. Core convergence points:
    * README.md ................. public overview / entry point
    * docs/WHITEPAPER-v1.x.md + docs/PROTOCOL.md ... the v1 specification
    * docs/proofs/*.md .......... per-claim formal proofs (the B3 record)
    * docs/SECURITY.md .......... the S-item security ledger
    * LICENSING.md .............. licensing authority
  docs/proofs/DECISION-LOG.md is the decisions + rationale authority (wins on any
  decision conflict; append-only). Any unavoidable new doc carries its TIER on line 1.
- No systemic backdoor (owner HARD CONSTRAINT, DECISION-LOG 2026-08-18 6265d34):
  "No key escrow, no protocol-level disclosure compulsion, no third-party master
  key — ever." Selective disclosure exists only as the holder's voluntary,
  per-view-key act in the designed v2.22/v2.24 mechanism. Any doc asserting
  unqualified PFS alongside view-key disclosure is wrong (same entry).

## CURRENT FRONT — read before selecting any work (owner directive 2026-07-28)
ACTIVE FRONT = execute the D2 JSON->binary migration NOW (DECISION-LOG 2026-07-28).
Rationale: D.5 reference RP + RP SDK are built (inc.6b + sdk/rp), G5/G6 shipped —
and the pool has been hardening JSON-envelope code that D2 deletes (e.g. round-12
net perf on the JSON envelope). Per sequence-before-harden, migrate first.
  1. Strip JSON from the p2p wire envelope (src/net/gossip.cpp, messages.cpp,
     binary_codec.cpp) + storage/genesis (src/chain/block.cpp, chain.cpp,
     genesis.cpp) + wallet keyfiles. Wire portion is GENESIS-DEADLINE (no-migrations).
     PROGRESS 2026-07-31: the ENVELOPE strip is DONE (b29d422 pq_auth tx-frame
     gap + ce31c6f binary-only envelope/HELLO, negotiation deleted, mirrors +
     gates rewritten, mutant-verified, FAST green). PER-TYPE PAYLOAD frames:
     7bcd32d COMPOSABLE_BATCH, c8a63d2+40d61cd abort claims typed,
     ad595bb inc6a (5 request/status), e845b44 inc6b (4 consensus-chatter),
     2803a13 the both-directions exact-length gate. 11 of the 19 types are now
     fixed binary frames; 8 still carry length-prefixed JSON PAYLOADS inside
     the binary envelope (BLOCK, CONTRIB, CHAIN_RESPONSE, BEACON_HEADER,
     SHARD_TIP, CROSS_SHARD_RECEIPT_BUNDLE, SNAPSHOT_RESPONSE,
     HEADERS_RESPONSE) — WIRE-2 stays until those binarize per-type. Next is
     inc5 (Block frame), the keystone: BLOCK/BEACON_HEADER/SHARD_TIP/
     CROSS_SHARD_RECEIPT_BUNDLE/CHAIN_RESPONSE all carry a Block, and chain
     storage (inc8) has a TOTAL hard dependency on it.
     PROGRESS 2026-08-12 (d34c632): inc5 (the canonical binary Block container)
     LANDED at d33d410+76d7ea4. WALLET/LIGHT KEYFILES ARE DONE — D2 step 3
     shipped seven at-rest containers (DWE bytes, DAK1, DAB1, DNK1, DSS1, DBE1,
     DRS1) + DLS1 for the light anchor cache; the dot-hex envelope, the
     JSON-interior node keyfile and the JSON light state are deleted; DAK1/DNK1
     derive-equality replaces the S-028 address cross-check; ZERO src/ edits.
     REMAINDER (explicit, still open): node_key.json (src/crypto/keys.cpp) and
     DETERM-ACCOUNT-V1 stay src-owned JSON/text until the src-side increment
     (marked D2-DEFERRED(src) in code); the light export-headers archive waits
     on the binary header frame.
     PROGRESS 2026-08-12 (8a106aa): inc7a/7b + inc8 LANDED. Six of the eight
     lp-JSON wire payloads are true binary frames now (BLOCK, CONTRIB,
     CHAIN_RESPONSE, BEACON_HEADER, SHARD_TIP, CROSS_SHARD_RECEIPT_BUNDLE), all
     delegating to chain::Block::encode_frame; SHARD_TIP decodes with
     allow_witnesses=false (fail-closes POISON-WITNESS pre-auth). CHAIN STORAGE +
     GENESIS + SNAPSHOT are binary-only: <path>.blocks/<i>.blk DBK1 frames + a
     fixed 44-byte DMF1 manifest written atomically last; Chain::save and the
     whole legacy chain.json read path DELETED (a chain.json with no manifest
     loads as an EMPTY chain — gate CS-8); GenesisConfig gains DGC1 (hash-neutral,
     GB-3); snapshots gain DSN1 via Chain::encode_state/decode_state.
     REMAINDER, still open: inc7c — SNAPSHOT_RESPONSE + HEADERS_RESPONSE are the
     last two lp-JSON payloads, so WIRE-2 + the fallback stay until they binarize;
     node_key.json (src/crypto/keys.cpp) and DETERM-ACCOUNT-V1 stay src-owned
     JSON/text (marked D2-DEFERRED(src) in code); the light export-headers archive
     waits on the binary header frame.
  1b. ENDGAME, before step 2 — Improvements.md §12.1: extract the 237 test/selftest
     subcommands out of src/main.cpp into a determ-selftest binary. Measured at
     53a849d: 237 of 292 `cmd ==` handlers are test-*/selftest-*, spanning lines
     6,955-64,364 of 64,683, and 1,151 of the file's 1,513 json-bearing lines (76%)
     sit inside that region. Doing this AFTER D2 stops touching src/main.cpp and
     BEFORE step 2 means the parser deletion faces a main.cpp with ~76% less JSON.
     Sequencing fixed by DECISION-LOG 2026-08-13, correction (i).
  2. Delete third_party/nlohmann/json.hpp AND include/determ/json/json.hpp;
     regenerate test vectors as binary. RPC/CLI/config may keep optional text.
     (= step 4 of the five-step D2 authorization, DECISION-LOG 2026-07-28.)
  3. Gate the BINARY replacements falsify-on-mutant — not the deleted JSON paths.

LIVE CRITICALS ON THE RECORD (audit 2026-09-14; DECISION-LOG 2026-08-13..16 and
2026-09-14; ledger rows docs/SECURITY.md S-055..S-067). Recorded in the log after this
section was last written and carried in the ledger. STILL OPEN: S-055 C0 F2
equivocation-view digest halt; S-057 unsigned unbounded pq_auth -> unrelayable blocks;
S-063 DAPP_CALL frames report payments never made; S-064 cross-shard bundles
unauthenticated (multi-shard only); S-065 CT proof verification (~2.2 s per bundle)
under the consensus lock; S-067 UNSTAKE is unincludable (stake unrecoverable through
consensus).
CLOSED 2026-09-15 (owner-authorized accept-rule change, DECISION-LOG 2026-09-15): S-060
REGISTER identity takeover — REGISTER is CREATE-ONLY (V-REG-1: rejected for any domain in
the raw registrants map, and unless nonce == 0); with it the reopened leg of S-052 and
the companion S-068 (a small-order REGISTER key is rejected, after the signature).
Decided consequences: a domain name is single-use, a lost key is terminal, key rotation
is a separate incumbent-signed transaction (R-6, open).
CLOSED 2026-09-14 (node-local, no consensus change): S-056/S-059/S-061/S-062 — the
producer now asks the verifier (BlockValidator::check_transaction is the ONE per-tx
rule set; build_body admits only what it accepts; a resident rejected tx is evicted
on the first build at each head) — S-058 (the Phase-2 trigger is committee
completeness, not map size; the Phase-1 timer is released only once complete) and
S-066 (gossip trusted the unsigned wire hash). Their ORDER against the D2 front is
owner decision O-3 below — until it is taken ACTIVE FRONT stays D2 as written, but
no thread may treat the ledger as clean. S-055/S-057/S-065/S-067 need owner
decisions (DECISION CLOCK R-7, R-8, R-10, R-11).

FOLDED IN (DECISION-LOG 2026-08-13, directive 1): pre-launch item B1 is closed as a
standalone item. Its (a) half — per-block append-only files replacing monolithic
chain.json — was ABSORBED by inc8 above. Its (b) half — an incrementally-persisted
state so Chain::load (src/chain/chain.cpp:3483) stops replaying apply_transactions
over every block — folds into the NEXT src/chain/chain.cpp storage pass, scheduled
with that pass and not ahead of it. It is cheaper than when scoped: inc8 already
built the container it needs (Chain::encode_state/decode_state, the DSN1 record at
src/chain/chain.cpp:2859 / :3018). Do NOT open B1 as separate work — a thread that
did would rewrite the storage inc8 just rewrote.

FROZEN for new hardening until D2 lands: do NOT open perf/robustness/gate work on
the JSON-path files listed above — they are being deleted; hardening them is wasted.
Harden the binary survivors after the swap.

WHERE THE PRIORITY LIVES (DECISION-LOG 2026-08-13, directive 2). This CURRENT FRONT
section is the operational source for WHAT TO WORK ON NEXT. PRE-LAUNCH-DECISIONS.md's
9-build + 3-verification execution plan, docs/proofs/IMPLEMENTATION-SEQUENCING.md and
docs/proofs/V1.1-PLAN.md are SUPERSEDED-FOR-SEQUENCING: their ORDERING predates the D2
authorization and must not be used to select work. Their per-item DECISIONS remain the
standing record and are unaffected. DECISION-LOG.md wins over all of them.

PRE-GENESIS BACKLOG (must land before mainnet) — DApp substrate Q2/Q3/Q4 code
(DECISION-LOG 2026-07-28): governed payload cap; enforce topic routing; accept_anon.
Also: decide the final CryptoProfile enum value set (currently {MODERN=0, FIPS=1},
include/determ/chain/params.hpp:122-125). It is GENESIS-FROZEN and invisible to work
selection until now: crypto_profile is mixed into the genesis hash when non-default
(src/chain/genesis.cpp:872-875, reaching compute_genesis_hash at :926), written as
a u8 by the DGC1 encoder (:532), and FAIL-CLOSED on decode — an unknown value is
rejected outright (:606-609). Cross-ref Improvements.md §12.5 (whose named subjects
tactical_civilian / cluster_civilian are TIMING presets that were never implemented —
zero occurrences in src/ include/ light/ wallet/; see DECISION-LOG 2026-08-13
directive 4 for the correction).
Also: B4 reserved-discriminator audit (docs/proofs/ReservedDiscriminatorAudit.md, 14 KEEP
/ 8 DROP; drop 1 of 8 executed 2026-07-09, drops 2-8 unexecuted) — the audit stands, but
EXECUTION of drops 2-8 is deferred to the LAST pre-genesis act (DECISION-LOG 2026-08-13,
directive 3): every slot KEPT preserves a post-genesis additive path (that is exactly how v2.15
Option-B on-chain multisig stays shippable later), every slot DROPPED forecloses one
PERMANENTLY under no-migrations. Do not execute DROPs early. KEEP verdicts need no
execution.
Also: C2 adversarial FA/DSF sweep is UNBLOCKED NOW. Its recorded prerequisite (the
"remaining deterministic-scheduler increments 2-5") is DISCHARGED —
docs/proofs/DeterministicSchedulerDesign.md reads "increments 1-11 SHIPPED", and
increment 5 IS the adversarial-schedule harness (test-fa-adversarial-deterministic).
What remains is RUNNING the full sweep (seed/scenario breadth), not building anything.
Also: macOS/Darwin support — LANDED (DECISION-LOG 2026-08-11, both entries): RNG
__APPLE__ getentropy branch, kqueue reactor backend, script portability; first
native Darwin/arm64 build green, byte-freeze pins matched, no goldens regenerated
(FAST was 294/0 at that commit; 299/0 as of d34c632). Tail: full run_all on Darwin
(pip3 pynacl — three EQV cluster scripts now carry a pynacl fallback and run here),
macOS CI runner, APFS.

BOTH RANK-1 CONSENSUS HOLES ARE CLOSED (authorized owner 2026-07-31; LANDED d34c632,
DECISION-LOG 2026-08-12). Hole 1's closure (S-052) was REOPENED on a different leg on
2026-08-14 — S-060, the REGISTER identity takeover (any key could replace the accused
key in the registry the verifier resolves against, validator.cpp:471) — and RE-CLOSED
2026-09-15 by the owner-authorized V-REG-1: REGISTER is create-only (raw registrants
map, nonce 0), so no key can be rebound (DECISION-LOG 2026-09-15). Hole 2 (S-053)
stands. Do not re-open the closed legs; harden forward from here.
  - Hole 1 forged-slash -> docs/SECURITY.md S-052. Closed by HEIGHT BINDING, not by
    carrying headers (rejected on analysis: unbounded size + Block>EquivocationEvent>Block
    recursion). Both digest families are now two-level and openable:
      block_digest   = SHA256("DTM-BLKDIG-v3"  || index       || gen || body_root)
      contrib_commit = SHA256("DTM-CONTRIB-v3" || block_index || gen || body_root)
    (as SHIPPED: src/node/producer.cpp compose_block_digest / compose_contrib_commitment;
    the v2 tags without gen that this block and several docs carried were never the
    shipped bytes — corrected 2026-09-14). EquivocationEvent carries kind + per-side
    {index, gen, body_root, sig}; digest_a/digest_b DELETED; verifier rejects kind>1,
    asserts index_a==index_b==block_index AND gen_a==gen_b (validator.cpp:441-460),
    verifies against DERIVED digests. Wire (GENESIS-DEADLINE): EQUIV_REC +
    EQUIVOCATION_EVIDENCE fixed 245 B after the lp_str (binary_codec.cpp:547), decode
    fail-closes on kind>1.
    Gate: the 8-arm EQV block of test-abort-cert-validation.
    RESIDUAL, OPEN, NOT authorized: same-height cross-round honest double-signing.
    The gen binding IS SHIPPED (v3 digests above; the gen_a==gen_b assert), so a
    cross-round pair is no longer a recognized double-sign — but the binding is
    EVADABLE: gen is signer-chosen off-chain, so a splitter signs side B at gen+1 and
    is acquitted, while an honest node's openings are bit-identical to a splitter's
    (DECISION-LOG 2026-08-13 b5838fb; the six 2026-08-12 designs "final".."final+9").
    Recorded in EquivocationSlashing.md §2 Case (c) + PROTOCOL.md §6.1 — do NOT treat
    it as closed and do NOT re-propose a predicate over two signed openings. The
    residual's HARM will be gone once the L2 relocation lands; AT HEAD THE FORFEITURE
    IS LIVE (chain.cpp:1819-1825) — the relocation FAILED review and was REVERTED (see
    NOT LANDED below). What remains open is the sound successor. Tracked as R-1.
  - Hole 2 empty-committee beacon -> docs/SECURITY.md S-053. Closed by extracting
    verify_committee_sigs as the ONE committee-signature core (non-empty + size match +
    membership + verify + signed_count >= required_k); both verify_shard_tip_committee_
    sig_root and on_beacon_header route through it. Gate: test-beacon-header-committee.
    SCOPE, stated honestly: this does NOT authenticate cumulative_rand (outside
    compute_block_digest; check_cumulative_rand is apply-path only) — PRE-EXISTING, still
    NOT authorized, adjacent to the also-unauthorized HELLO beacon-role authentication.

ALSO LANDED d34c632: S-050 straggler recovery (owner-authorized in-session 2026-08-12).
An idle non-committee follower arms no round timer, so the S-050 stall valve never fired
for it and one missed block stranded it permanently. apply_block_locked now treats
b.index > height() as proof a peer minted past our head and arms the existing tolerance-0
catch-up, GUARDED to fire once per stall episode. Gate: test-straggler-resync.
FAST was 299/0 at d34c632 (294 baseline + 5 new gates: test-beacon-header-committee,
test-straggler-resync, selftest-envelope-bytes, selftest-keyfile-binary,
selftest-backup-binary); 302/0 as of 8a106aa (+wire_payload_frames,
genesis_binary_codec, snapshot_binary_codec).
NOT authorized (separate future item): authenticate the self-declared BEACON role in HELLO.

SLASHING AT THE PRE-FINALIZATION LAYER NOW CARRIES NO CONSEQUENCE (owner decision
2026-08-13; DECISION-LOG 2026-08-13). A same-height duplicate signature detected before
finalization is logged and gossiped for operator attention and takes NO consensus action
— no stake forfeiture, no exclusion. Six designs failed (DECISION-LOG 2026-08-12 entries
"final", "final+1", "final+3", "final+5", "final+7", "final+9") and together
proved the predicate unsound and unfixable: no predicate over two signed openings is both
sound and complete under asynchrony (a splitter's openings are bit-identical to an honest
node's — only DELIVERY differs), and at |eligible pool| == K no exclusion is safe
either (K-of-K selection is the identity on the SET, so rotation evicts no one, and a
non-liftable exclusion is a self-sustaining permanent halt). Stated over the POOL, not
m_creators: no accept rule reads M (DECISION-LOG 2026-08-14 ddfe877).
  THE CHANGE IS A RELOCATION, NOT A REMOVAL (owner correction 2026-08-13). SUPERSESSION
  UNRESOLVED (audit 2026-09-14): the owner entry that FOLLOWED this correction the same
  day (DECISION-LOG 5082737) moved slashing back INTO L1 with a lock rule + an M > K
  genesis invariant; that design was REFUTED at design stage hours later (b5838fb:
  "the sound options remaining are an L2/economic layer ... or no consequence at all")
  and no owner entry since restates the position. This block is therefore the last
  UNREFUTED owner position, not a settled decision — owner item O-1 below. Slashing moves
  OUT OF L1 INTO L2. L1 keeps DETECTION and the on-chain EVIDENCE RECORD but attaches no
  consensus consequence; the economic consequence is applied at the DApp/L2 layer, which
  may use inputs L1 provably cannot (off-chain corroboration, elapsed time, arbitration,
  dispute/appeal) and whose verdict is therefore not required to be sound-and-complete as
  a consensus rule. This is why the impossibility results above are not fatal: they bound
  what a CONSENSUS predicate can decide, not what an L2 policy can.
  CONSEQUENCE FOR THE EVIDENCE RECORD: it is NOT merely diagnostic — it is the INPUT to
  L2. It must therefore be reliable, capped and queryable, which makes the per-block cap +
  in-block duplicate rejection (see below) a correctness requirement of the L2 design, not
  just a DoS fix.
  OPEN ARCHITECTURAL QUESTION (owner): what does L2 slash? Either (a) L1 exposes a
  DApp-callable stake primitive — but then the L2 verdict re-enters consensus and the
  soundness problem returns; or (b) validators post a SEPARATE L2 bond and L1 stake is
  never slashable — fully clean, opt-in, and consistent with K-of-K mutual distrust; or
  (c) L2 consequence is exclusion/reputation at the service layer only. NOT DECIDED.
  NOT LANDED — the code change was written, FAILED adversarial review (22 findings
  confirmed, 1 false alarm) and was REVERTED. The core removal is sound (A1 neutral,
  snapshot round-trips, no state_root leaf changes shape), but landing it additionally
  requires: a per-block CAP + in-block duplicate rejection on equivocation_events (2
  Ed25519 verifies each and deregistration was the only limiter, so the same event becomes
  re-includable forever — a NEW DoS vector the removal creates); S-006's status re-derived
  (its entire closure was "route detection into the slashing apply path", so it is
  silently reopened); an HONEST S-011 residual (the drafted one was wrong in three places
  — BFT escalation can seat a zero-honest committee at |pool| == K, abort-driven stake drain
  below min_stake IS permanent and S-051 does not lift it, and DOMAIN_INCLUSION zeroes
  BOTH legs); and ~16 authoritative no-TIER proof docs still asserting the deleted
  forfeiture as shipped. Full finding list: DECISION-LOG 2026-08-13.
  THIS REOPENS S-011 WHEN IT LANDS. docs/SECURITY.md states S-011's mitigation as the
  S-010 stake floor PLUS the FA6 equivocation-slashing economic bound; once the
  pre-finalization consequence is removed, the slashing half no longer holds as written.
  Same flag stands against BFTSafety.md B2 / T-5.1 (DECISION-LOG 2026-08-12 "final+6")
  and, newly, against S-029's Level-3 block_hash-grinding closure and S-013's economic
  leg. Until the re-derivation lands, do NOT cite the old bound.

DECISION CLOCK — UNAUTHORIZED consensus/wire residuals (DECISION-LOG 2026-08-13,
directive 5; rows R-4..R-9 added 2026-09-14 from the log entries that asked for them). All three are pre-genesis or never. They are correctly marked NOT
authorized, but an unauthorized item does not self-surface and THE DECISION HAS A
DEADLINE even when the work does not. A thread reaching one of these milestones must
surface the row to the owner before calling the milestone complete.
  R-1  Hole-1 residual: same-height CROSS-ROUND double-signing satisfies V11
       (EquivocationSlashing.md §2 Case (c) + PROTOCOL.md §6.1).
       DECIDE BY: the owner's restatement of the slashing position (O-1 below; the
       "finalization-layer design gate" this row named was itself a mis-recording per
       DECISION-LOG f310086), due before B4's DROP execution (the last pre-genesis act).
  R-2  cumulative_rand is NOT authenticated on the beacon-header path (outside
       compute_block_digest; check_cumulative_rand is apply-path only).
       DECIDE BY: D3 / S-036 closure (on-chain SHARD_TIP, v2.11) — same code path, and
       the launch posture is EXTENDED.
  R-3  The self-declared BEACON role in HELLO is unauthenticated.
       DECIDE BY: D2 completion, the parser-deletion step — HELLO is wire surface and D2
       is its last wholesale rewrite.
  R-4  The committee-derivation safety bound 2K > N(h) over the ELIGIBLE POOL (S-054 is
       partial: the shipped band guards m_creators, which no accept rule reads; with
       N >= 2K two racing same-height committees finalize conflicting blocks with no
       double-signer — DECISION-LOG 2026-08-14 ddfe877). Two shapes: a genesis-pinned
       pool cap, or the verifier refusing a committee drawn from a pool larger than
       2K-1 (halt, not fork). Design together with F-c (AbortCascadeLiveness.md §4.3),
       whose soundness turns on whether the pool can be adversarially shrunk.
       DECIDE BY: before genesis; frozen accept rule.
  R-5  DECIDED + LANDED 2026-09-15 (owner): create-only REGISTER (V-REG-1) closes S-060;
       key loss is terminal for the domain; DEREGISTER is terminal too (no re-entry under
       the same name — balance, stake and DApp ownership stay with the domain, S-067).
       The small-order-key companion S-068 landed the same day (a REGISTER payload key
       must decode to a large-order point). Gates: test-register-create-only,
       test-register-small-order-key. Kept here as the record.
  R-6  ROTATE_IDENTITY_KEY / revocability: a new TxType is free at the wire and state
       layer (1c0a61d), but old validators fail closed on unknown types, so first use
       needs every validator upgraded — a coordination requirement, not a migration.
       The open question is whether it ships BEFORE genesis. DECIDE BY: before genesis if
       validators must be able to rotate before an upgrade window exists.
  R-7  S-057: a rule that non-PQ transaction types carry empty pq_auth, and/or a
       consensus block-byte cap matching the 4 MB wire cap (a valid block must never be
       unrelayable). New accept rules. DECIDE BY: before genesis.
  R-8  S-055 C0: evidence-payload demotion (design AUTHORIZED, DECISION-LOG 5b2d7fe) is
       sound only once the evidence carries no L1 consequence (7570989) — gated on O-1;
       lands with the per-block cap + in-block duplicate rejection as their own
       increments. DECIDE BY: O-1.
  R-9  B4 interaction: MsgTypes 12/13/14 KEEP-or-DROP flips the audit's 14/8 to 12/10
       under the P1 sharding posture (DECISION-LOG e7c6fc2). DECIDE BY: B4 DROP execution.
  R-10 S-065: CT proof verification (~2.2 s per aggregated range proof, measured
       2026-09-14) runs under the exclusive consensus lock at validation and at the
       first build of each head; and anonymous CT ingress is blocked only by the S-002
       mirror's anon->TRANSFER-only rule, which is NOT the verifier's rule (the
       documented light-client shield flow from an anonymous key is rejected at
       ingress). Design: verification off the lock (or a CT budget) + settle the anon
       CT ingress rule. DECIDE BY: before any CT deployment; node-local except the
       ingress rule's consistency with the verifier.
  R-11 S-067: no UNSTAKE is includable (unlock only after DEREGISTER, by which time the
       domain is ineligible and the verifier rejects its every tx) — staked funds are
       unrecoverable through consensus. Accept-rule change (an inactive registrant may
       UNSTAKE). DECIDE BY: before genesis; frozen accept rule.
  R-12 S-069: under STAKE_INCLUSION (the default) no domain can JOIN after genesis — a
       fresh registrant holds 0 stake, is therefore absent from the eligible registry,
       and the verifier rejects its STAKE ("tx sender not in registry") before the stake
       can be established (DECISION-LOG 0fe6eda REVERSED 1 states it as a fact; README
       §"joins the eligible pool" claims the opposite). Either the validator set is
       closed at genesis BY DESIGN (then say so and the REGISTER/STAKE tooling is
       misleading) or STAKE from a registered-but-unstaked domain must be accepted (an
       accept-rule change). With V-REG-1 + terminal DEREGISTER the set can only shrink.
       DECIDE BY: before genesis; frozen accept rule.
  IF UNDECIDED AT GENESIS the default becomes "never", PERMANENTLY, under no-migrations.
  No decision is not a neutral state.

OWNER DECISIONS PENDING, non-consensus (audit 2026-09-14) — none of these is a code
change; each is one log entry:
  O-1  The standing slashing position after b5838fb: L2 relocation (option (b), a
       separate L2 bond with L1 stake never slashable, is the only one of (a)/(b)/(c)
       that does not re-enter consensus), or no consequence at all. Gates R-1, R-8 and
       the S-011/S-013/S-029/BFTSafety T-5.1 re-derivations.
  O-2  Ratify or narrow the 2026-08-13 "green is not proof" doctrine (352fc52 was
       recorded "at the direction of the session orchestrator ... flagged for owner
       review"; it is applied as binding above).
  O-3  Order the LIVE CRITICALS (S-055..S-063, SECURITY.md) against the D2 front. The log
       recommends the halts first (84c1447, 3dbe5f2, ddf93eb); ACTIVE FRONT still says D2.
  O-4  The no-cryptocurrency scope reduction (evaluated 0fe6eda, superseding 8b86d39) and
       its DIRECT CONFLICT with the no-backdoor constraint (6265d34 hazard 2): adopt,
       reject, or scope.
