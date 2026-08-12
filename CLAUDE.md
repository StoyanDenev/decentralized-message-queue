This is working folder for DLT
Tone: direct and professional, not chatty

## PROJECT DOCTRINE — non-negotiable, applies to ALL work
Read this before writing code or docs. On any decision conflict, docs/proofs/DECISION-LOG.md wins.

- Provable security (B3): every claim is proof-backed, nothing aspirational.
  New behavior ships with a falsify-on-mutant gate. Do not add unproven or
  speculative surface.
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
     on the binary header frame. IN FLIGHT THIS SESSION: inc7a/7b (the per-type
     wire payload frames for the 8 remaining JSON-payload types) and inc8
     (chain storage/genesis). Storage/genesis were not started before this
     session.
  2. Delete third_party/nlohmann/json.hpp AND include/determ/json/json.hpp;
     regenerate test vectors as binary. RPC/CLI/config may keep optional text.
  3. Gate the BINARY replacements falsify-on-mutant — not the deleted JSON paths.

FROZEN for new hardening until D2 lands: do NOT open perf/robustness/gate work on
the JSON-path files listed above — they are being deleted; hardening them is wasted.
Harden the binary survivors after the swap.

PRE-GENESIS BACKLOG (must land before mainnet) — DApp substrate Q2/Q3/Q4 code
(DECISION-LOG 2026-07-28): governed payload cap; enforce topic routing; accept_anon.
Also: macOS/Darwin support — LANDED (DECISION-LOG 2026-08-11, both entries): RNG
__APPLE__ getentropy branch, kqueue reactor backend, script portability; first
native Darwin/arm64 build green, byte-freeze pins matched, no goldens regenerated
(FAST was 294/0 at that commit; 299/0 as of d34c632). Tail: full run_all on Darwin
(pip3 pynacl — three EQV cluster scripts now carry a pynacl fallback and run here),
macOS CI runner, APFS.

BOTH RANK-1 CONSENSUS HOLES ARE CLOSED (authorized owner 2026-07-31; LANDED d34c632,
DECISION-LOG 2026-08-12). Do not re-open them; harden forward from here.
  - Hole 1 forged-slash -> docs/SECURITY.md S-052. Closed by HEIGHT BINDING, not by
    carrying headers (rejected on analysis: unbounded size + Block>EquivocationEvent>Block
    recursion). Both digest families are now two-level and openable:
      block_digest   = SHA256("DTM-BLKDIG-v2"  || index       u64BE || body_root)
      contrib_commit = SHA256("DTM-CONTRIB-v2" || block_index u64BE || body_root)
    EquivocationEvent carries kind + per-side {index, body_root, sig}; digest_a/digest_b
    DELETED; verifier rejects kind>1, asserts index_a==index_b==block_index, verifies
    against DERIVED digests. Wire (GENESIS-DEADLINE): EQUIV_REC + EQUIVOCATION_EVIDENCE
    fixed 229 B after the lp_str, kMinEquivEvent 230, decode fail-closes on kind>1.
    Gate: the 8-arm EQV block of test-abort-cert-validation.
    RESIDUAL, OPEN, NOT authorized: same-height cross-round honest double-signing still
    satisfies V11 (an abort re-round changes the body at one height). Closing it needs
    the round/aborts_gen bound into the openings. Recorded in EquivocationSlashing.md
    §2 Case (c) + PROTOCOL.md §6.1 — do NOT treat it as closed.
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
FAST is now 299/0 on Darwin/arm64 (294 baseline + 5 new gates: test-beacon-header-
committee, test-straggler-resync, selftest-envelope-bytes, selftest-keyfile-binary,
selftest-backup-binary).
NOT authorized (separate future item): authenticate the self-declared BEACON role in HELLO.
