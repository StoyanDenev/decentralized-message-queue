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
     storage (inc8) has a TOTAL hard dependency on it. Storage/genesis/keyfiles
     not started.
  2. Delete third_party/nlohmann/json.hpp AND include/determ/json/json.hpp;
     regenerate test vectors as binary. RPC/CLI/config may keep optional text.
  3. Gate the BINARY replacements falsify-on-mutant — not the deleted JSON paths.

FROZEN for new hardening until D2 lands: do NOT open perf/robustness/gate work on
the JSON-path files listed above — they are being deleted; hardening them is wasted.
Harden the binary survivors after the swap.

PRE-GENESIS BACKLOG (must land before mainnet) — DApp substrate Q2/Q3/Q4 code
(DECISION-LOG 2026-07-28): governed payload cap; enforce topic routing; accept_anon.

STILL OWNER-GATED, do not start: the two rank-1 consensus fixes
(RpcIngressGateAudit.md section 2). These SURVIVE D2 (accept-rule logic, not
serialization) so they are EXEMPT from the freeze — they are the real security
priority; await explicit owner sign-off.
