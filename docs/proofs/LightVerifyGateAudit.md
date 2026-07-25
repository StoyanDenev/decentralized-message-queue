# Light-Client Verifier Gate-Gap Audit

**Status:** open (2026-07-26); **1 autonomous gate CLOSED, 9 confirmed autonomous-safe in backlog, 0
owner-gated.** SIXTH code-surface register in the falsify-on-mutant series, after
[ProofClaimGateTraceability](ProofClaimGateTraceability.md),
[ConsensusValidatorGateAudit](ConsensusValidatorGateAudit.md) (19/19),
[RpcIngressGateAudit](RpcIngressGateAudit.md), [SnapshotRestoreGateAudit](SnapshotRestoreGateAudit.md),
and [BlockIngressGateAudit](BlockIngressGateAudit.md).

## 0. Surface & method

The **`determ-light` trustless-read verifier** — the CLIENT-SIDE trust boundary. The light client
consumes RPC/archive responses from an **untrusted or MITM server**; its only trust anchors are the
genesis-pinned committee/config and committee-signed `state_root`s. A **soundness gap = the verifier
ACCEPTS a forged proof/value it should reject** → the user is deceived about their balance / a tx's
inclusion / history / a receipt. Tightening the light client's own verification is client-side and
**autonomous-safe** (it is not consensus).

Discovery workflow `wf_4df8efc1-41a` — 5 finders (state-root anchor / inclusion proofs / trustless-read
core / history composites / archive-CT-RPC-decode) → adversarial REFUTE-by-default verifiers that
traced the full CLI flow. **11 findings → 10 CONFIRMED autonomous-safe, 1 REFUTED, 0 owner-gated.**
The surface is genuinely leaky (3 rank-1 anchor-forgery gaps).

## 1. CLOSED — empty-committee anchor forgery (`test-light-verify-empty-committee`, LVS-1)

`verify_block_sigs` (light/verify.cpp) — the **sole committee-signature gate** under
`committee_bound_state_root` (and thus the anchor for every balance/inclusion/history read) — derived
its quorum threshold from the block's **own attacker-controlled** `creators.size()`:
`required = bft ? (2*K+2)/3 : K`. With an empty `creators:[]`/`creator_block_sigs:[]` header, the
membership loop and the signature loop run zero iterations (`valid=0`), the size check is `0==0`, and
`required=0` in **both** MD and BFT modes, so `valid(0) < required(0)` is false and it returned
`ok=true` with **ZERO signatures verified**. `Block::from_json` accepts an empty `creators` array, so
the header is fully attacker-suppliable. A malicious/MITM daemon serves an empty-committee successor
header and forges the committee-attested `state_root` (`committee_verified=true`) with zero sigs —
deceiving the user. A forged **non-empty** block would need real committee keys, so the empty set is
the **unique keys-free forgery**; the empty-committee guard is the load-bearing soundness fix.
Confirmed independently by two finders (state-root-anchor + inclusion-proofs); it is the client-side
sibling of the node-side `beacon-header-empty-committee` rank-1 vuln (owner-gated in RpcIngress).

**Fix (client-side soundness, no node/consensus/wire change):** reject an empty creator set —
`if (b.creators.empty()) { r.detail = "…no creators (empty committee)…"; return r; }`. Every
legitimate committee-signed block carries `K>=1` creators, and genesis (index 0) is routed around this
function by both sinks (`verify_state_root_at` height==0 branch; `verify_chain_walk` skips idx0), so
no honest header regresses.

**Gate** = `test_light_verify_empty_committee.sh` — a FAST, fully-offline harness (hand-built JSON
fixtures; the empty case needs no real crypto, which is the point): NEG-1 empty committee (MD) →
FAIL + exit 1; NEG-2 empty committee (`--bft`) → FAIL + exit 1; CTRL a non-member creator reaches +
fails the membership check (non-vacuity — proves the CLI reaches the real quorum path). **Falsify-on-
mutant** (`if (false && b.creators.empty())`): the mutant prints `OK … verified: 0 sig(s) …
state_root: <forged>` (exit 0) — literally accepting a forged state_root with zero signatures — while
CTRL stays FAIL; a clean directional split on both platforms.

## 2. Backlog — confirmed autonomous-safe (ordered; each is a future gate)

| id | rank | file | gap |
|---|---|---|---|
| LV-1 | 1 | verify.cpp | `verify_block_sigs` threshold keyed to `creators.size()`, not genesis `k_block_sigs` — the fuller `creators.size()==expected_K` binding (defense-in-depth beyond §1's empty-set fix; §1 closed the only keys-free forgery). Threads genesis K through the chain-trust callers. |
| EXP-1 | 1 | export.cpp | `export-headers --from > 0` anchors the first page to NOTHING (no genesis in a `from>0` range), letting a MITM inject a fabricated/wrong-range archive marked `verified_committee_sigs=true`. Fix mirrors `verify_chain_walk`: require `headers[0].index == from`, reject any `index==0` when `from>0`. |
| LTX-HEIGHT-NOT-BOUND | 2 | verify_tx_inclusion.cpp | never binds the returned block's `index` to the requested `height` — a real committee-signed block at a DIFFERENT height forges an "included at height B" proof. Fix: `if (b.index != height) UNVERIFIABLE`. |
| LV-2 | 2 | trustless_read.cpp | unconditional MD→BFT quorum fallback accepts reduced-quorum (`ceil(2K/3)`) blocks with no BFT-eligibility gate. Fix: gate the `bft=true` retry on `consensus_mode==BFT && genesis.bft_enabled`. |
| WATCH-1 | 2 | watch.cpp | `watch-head` prints `state_root`/`head_hash` with `sigs_valid=yes` although the committee sig covers neither (the head has no signed successor). Fix: report a committee-bound `state_root` for `head-1`, label the head's own as unverified. |
| LRPC-1 | 2 | rpc_client.cpp | `RpcClient::read_line` grows its buffer unbounded → a MITM daemon OOM-crashes the reader. Fix: a light-local 16 MiB `kLightRpcMaxLineBytes` cap (the client-side sibling of the RpcIngress readline cap). |
| LSB-ANCHOR-INDEX-NOT-BOUND | 3 | verify_state_bundle.cpp | displays `bundle['anchor_index']` without binding it to the committee-anchored `anchor.index` — a real (key,value) proof can be relabeled to a false height. |
| AH-1 | 3 | account_history.cpp | the genesis row (h=0) reports the served `state_root` FIELD, which `anchor_genesis` never binds (block 0 hash is only string-compared, never recomputed). Fix: route idx==0 through `committee_bound_state_root` or derive the genesis `state_root` locally. |

## 3. REFUTED

**LARCH-1** (`verify-archive` accepts a committee-sig-stripped archive): refuted on verification — a
later bind/verify in the flow already catches the stripped-sig case.

## 4. Non-claim

Each finding establishes that the light verifier ACCEPTS an input it should reject (or is
DoS-crashable), not that a specific chain has been exploited. Every fix is client-side; none changes
the node, consensus, wire format, or what the chain accepts. Cross-references
`RpcIngressGateAudit.md` (the node-side `beacon-header-empty-committee` sibling of §1) and the F-6/F-7
light lessons in `ProofClaimGateTraceability.md`.
