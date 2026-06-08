# Multi-Peer Cross-Check Soundness (`determ-light cross-check`)

**Status: implementation + soundness analysis.** Closes the single-daemon
limitation flagged as the shared residual across the light-client proof family
(`LightClientCompositionMap.md` §6: "single-daemon (no multi-peer cross-check)";
`LightClientThreatModel.md` §6). The `determ-light cross-check` subcommand
(`light/main.cpp::cmd_cross_check`, commit `36e7053`) verifies N independent
daemons against the same pinned genesis and detects a committee-signed
fork / equivocation served by a divergent daemon.

## 1. Mechanism

Given a pinned `--genesis` file and ≥2 daemon endpoints (`--rpc-port <N>` for
localhost and/or `--peer <host:port>` for remote/cross-host — see §4), for each
peer independently:

1. `anchor_genesis` — recompute the genesis hash locally and reject the peer if
   its block 0 doesn't match (the `LightClientThreatModel.md` T-L1 anchor).
2. `verify_chain_to_head` — committee-verify every header from genesis to the
   peer's head (prev_hash continuity + K-of-K Ed25519 over `compute_block_digest`,
   the T-L2 head-trust primitive), recording `(height, head_block_hash,
   head_state_root)`.

Then group peers by reported height and, for each height shared by ≥2 peers,
require all peers in that group to agree on `(block_hash, state_root)`.

Verdicts (exit codes): **AGREE** (0) — every shared-height group is consistent;
**DIVERGENCE** (2) — some shared height has disagreeing `block_hash`/`state_root`;
**INCONCLUSIVE** (3) — no two peers share a height this round; **UNVERIFIABLE**
(1) — a peer failed its own anchor/committee verification (fail-closed).

## 2. Assumptions & threat model

- **A1** (Ed25519 EUF-CMA), **A2** (SHA-256 collision resistance) — per
  `Preliminaries.md` §2.0/§2.1/§2.2; the same base the per-peer `verify-chain`
  consumes. The cross-check introduces **no new assumption**.
- Adversary **A_eclipse**: controls a *subset* of the queried daemons (can serve
  a forked/stale/lying chain) but not all of them; the operator queries ≥1
  independent honest peer. Adversary **A_byz_committee**: ≥ f+1 committee members
  at some height equivocate (sign two distinct blocks).

## 3. Theorems

**MPC-1 (Divergence-soundness — no false positive).** If two honest daemons both
serve the canonical chain, then at every height each has verified, their
`block_hash`/`state_root` are byte-identical (the canonical chain has exactly one
block per height, and both passed the same committee-sig + prev_hash gates under
A1+A2). Therefore a **DIVERGENCE** verdict implies two *committee-verified* blocks
differ at one height — which is only possible if either (a) ≥ f+1 committee
members equivocated at that height (**A_byz_committee** — a genuine consensus
fault), or (b) at least one daemon served a forged chain that nonetheless passed
K-of-K verification (an A1 forgery / A2 collision, probability ≤ `(H·K+1)·2⁻¹²⁸`).
Under A1+A2 with an honest committee, neither occurs for honest daemons, so
DIVERGENCE is never raised against a set of honest daemons on one chain — it is a
sound alarm, not noise.

**MPC-2 (Divergence is a true anomaly).** Conversely, a DIVERGENCE verdict is
*evidence* (not proof of which party is at fault): the two committee-verified
blocks at the shared height constitute a transferable equivocation witness when
they share ≥ Q overlapping committee signatures (the `EquivocationSlashing.md` /
FA6 surface) — i.e. the cross-check surfaces exactly the two-instance condition
FA1 §5.3 / `S030-D2-Analysis.md` discuss, now observable across peers rather than
only at a single node's apply gate.

**MPC-3 (Lag-benignity).** A peer at height `h' < max` is **not** compared
against peers at higher heights. Network asynchrony makes a lagging head normal;
comparing a peer's head against a different height would manufacture false
DIVERGENCE. Soundness: the canonical chain is a single sequence, so a peer's
verified head at `h'` is a verified *prefix position* — disagreement is only
meaningful at a height both peers have verified, which is exactly what the
height-grouping compares. (A peer that has *also* forked at a low height is caught
once a second peer reaches that height; the cross-check is a per-round detector,
not a one-shot proof of global agreement — stated honestly in §6.)

**MPC-4 (Fail-closed).** Any peer that fails `anchor_genesis` (wrong genesis →
eclipse onto a different chain) or `verify_chain_to_head` (bad sig / broken
prev_hash) yields **UNVERIFIABLE** and a non-zero exit *before* any comparison —
never a false AGREE. You cannot cross-check against a peer you cannot verify.

**MPC-5 (Per-peer guarantee preserved).** Each peer is independently fully
verified (the complete `verify-chain` pipeline) before its head enters the
comparison. The cross-check is a pure post-hoc comparison of already-verified
results; it adds cross-peer DETECTION and weakens no single-peer soundness
property (T-L1..T-L4, SR-1, TI-1, etc.).

## 4. What it does NOT close (honest limitations)

- **All-peers-collude.** If every queried daemon is the same malicious operator
  (or colluding set) serving one consistent forged-but-K-of-K-signed chain, they
  AGREE and the cross-check is silent. Multi-peer detection requires ≥1
  *independent honest* peer in the query set — the operator's responsibility.
  (This reduces to A_byz_committee: a forged chain still needs K-of-K sigs.)
- **Cross-host peers (now supported, commit `9fed9ad`).** `--rpc-port <N>` targets
  `127.0.0.1:<N>` (the local-cluster pattern); `--peer <host:port>` targets a
  remote daemon, resolved via `RpcClient`'s getaddrinfo host path — so true
  cross-HOST redundancy (independent operators / machines), the strongest form of
  this eclipse defense, is available. The loopback fast path is preserved
  byte-for-byte (the host branch fires only for a non-loopback host), so the
  agreement logic and every other determ-light command are unchanged. Residual:
  the eclipse defense is only as strong as the *independence* of the chosen hosts
  (querying N endpoints behind one malicious operator is still a collude set — see
  the bullet above).
- **Not a non-membership / liveness proof.** AGREE attests consistency among the
  queried peers at shared heights at one instant; it does not prove the chain is
  live, that a specific tx is included, or that no peer is withholding (the
  `NegativeVerdictSoundness.md` boundary).

## 5. Test surface

`tools/test_light_cross_check.sh`: (A) deterministic offline CLI/dispatch/
exit-code contract (≥2 `--rpc-port` required, missing `--genesis`, unknown arg,
help-listed); (B) best-effort live 2-daemon AGREE (cluster-bound; SKIPs where the
local cluster cannot mint blocks). The DIVERGENCE path requires a forked/Byzantine
daemon (test-only) and is exercised on WSL2/CI.

## 6. Cross-references

`LightClientThreatModel.md` (T-L1 anchor / T-L2 head-trust reused), `Safety.md`
(FA1 §5.3 two-instance discussion), `S030-D2-Analysis.md` (the digest-coverage
boundary the divergence witness rides on), `EquivocationSlashing.md` (FA6 — the
slashing pipeline a DIVERGENCE witness feeds), `LightClientCompositionMap.md` §6
(the single-daemon limitation this closes), `NegativeVerdictSoundness.md` (the
absence/withholding boundary), `Preliminaries.md` §2.0–§2.2.
