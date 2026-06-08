# Shared Page-Walk Core Soundness (`verify_chain_walk`)

**Status: implementation + soundness analysis.** This is the analytic companion
to the resume-soundness fix recorded in `LightStatePersistenceSoundness.md`
(LSP-6). It proves the *shared* page-walk core
`light/trustless_read.cpp::verify_chain_walk` (lines `102–227`) is sound for
**both** of its callers — `verify_chain_to_head` (from-genesis, `start_from=0`,
`light/trustless_read.cpp:231–245`) and `verify_chain_from_anchor` (resume,
`start_from=anchor_height`, `light/trustless_read.cpp:247–273`). The two callers
differ *only* in the start anchor passed in; the per-block and per-page logic is
one body, so the resume path inherits the exact T-L2 head-trust guarantee of the
from-genesis walk rather than re-deriving a weaker variant of it.

The refactor that hoisted the common walk into `verify_chain_walk` was paired
with a three-part defense against a resume-suffix diversion attack a pre-merge
adversarial verifier found: a malicious daemon serving a resume-suffix header
that *claims* `index 0` diverted `verify_headers` into its binding-free genesis
branch (which ignores the caller's `prev_hash` anchor when `genesis_hash_hex` is
empty) while the per-block sig loop skipped the committee-sig check for index 0 —
yielding a false `RESUMED OK` on an unsigned, daemon-chosen head. The fix is the
subject of VCW-2, VCW-3, and the `from==0` gating in VCW-5.

## 1. Mechanism

`verify_chain_walk(rpc, committee_seed, genesis_hash_hex, start_from,
initial_prev_anchor, head_height)` walks headers in pages of `PAGE=256`
(`trustless_read.cpp:120`) over the half-open range `[start_from, head_height)`
(`for (uint64_t from = start_from; from < head_height; from += PAGE)`,
`:127`). For each page:

1. **Index-contiguity gate** (`:146–155`). Every header in the page must report
   `index == from + i` for its position `i`; a single mismatch throws
   `non-contiguous header index in page`. This is the headline resume-soundness
   defense (VCW-2).
2. **Anchor / continuity gate** (`:161–163`). The first page of a from-genesis
   walk (`from == 0`) calls `verify_headers(page, genesis_hash_hex, "")` — the
   genesis-anchored branch; every other page (including the *first* page of a
   resume suffix, where `from == start_from == anchor_height > 0`) calls
   `verify_headers(page, "", prev_anchor)` — the prev_hash-anchored branch, with
   `prev_anchor` seeded from `initial_prev_anchor` and re-pointed to each page's
   verified tail (`:170`). `verify_headers` itself walks intra-page prev_hash
   continuity (`verify.cpp:212–223`).
3. **Per-block committee-sig gate** (`:174–205`). Each header is committee-verified
   via `verify_block_sigs(h, committee_json, /*bft=*/false)` with a one-shot BFT
   retry (`:188–193`). The genesis block's sig check is skipped **only** under
   `idx == 0 && from == 0` (`:187`).

After the loop, the **walked-count gate** (`:213–219`) requires
`headers_seen == head_height - start_from`, rejecting a daemon that silently
truncated the range with a short final page (VCW-4).

`verify_chain_to_head` is the thin `start_from=0` wrapper (it short-circuits the
empty chain at `head_height==0`, `:237–241`); `verify_chain_from_anchor` is the
resume entry (it fetches the head, falls back when `head_height <= anchor_height`
rather than silently claiming a resume, `:255–262`, then calls the walk with
`start_from=anchor_height` and `initial_prev_anchor=anchor_block_hash`,
`:267–270`). Both obtain `head_height` from `fetch_head_height` (`:85–92`).

## 2. Assumptions & threat model

- **A1** (Ed25519 EUF-CMA), **A2** (SHA-256 collision resistance) — per
  `Preliminaries.md` §2.0/§2.1/§2.2; the same base every `determ-light`
  verification consumes. `verify_chain_walk` introduces **no new assumption**: the
  refactor + the three resume gates are structural (index arithmetic, branch
  selection, a counter equality) and rest entirely on A1+A2 for their
  cryptographic content.
- Adversary **A_daemon** (`LightClientThreatModel.md` §6): the daemon answering
  the `headers` RPC is fully Byzantine — it may serve arbitrary, reordered,
  truncated, forged, or selectively-honest header pages. It does **not** hold the
  committee's Ed25519 signing keys (defeating that is A1) and cannot find SHA-256
  collisions (A2). The genesis config and committee seed are operator-supplied
  (the T-L1 / persisted-anchor root of trust), not daemon-controlled.

## 3. Theorems

**VCW-1 (Refactor invariance).** For an honest daemon serving the canonical
chain, `verify_chain_to_head`'s per-block and continuity behavior is
byte-identical to the pre-refactor monolith. The hoisted body
(`verify_chain_walk`) is invoked by the from-genesis wrapper with
`start_from=0`, `initial_prev_anchor=""`, `genesis_hash_hex` = the locally
recomputed genesis hash (`:242–244`). Under those arguments: the page loop ranges
`[0, head_height)` exactly as before; the index-contiguity gate reduces to the
natural `0,1,2,…` invariant a genesis walk already satisfied; the first-page
branch selects `from==0 ⇒ verify_headers(page, genesis_hash_hex, "")` — the same
genesis-anchored call the monolith made; the sig-skip predicate `idx==0 &&
from==0` fires on exactly the genuine genesis block (block 0 on the first page)
and on nothing else, identical to the monolith's "skip the genesis block"
behavior; and the walked-count gate `headers_seen == head_height - 0` is a *new*
post-condition that an honest full walk *always* satisfies (it verifies every
block in range), so it never changes the verdict for an honest daemon. Hence the
refactor preserves the from-genesis T-L2 guarantee bit-for-bit and adds only
fail-closed strictness; the resume caller invokes the *same* body, so it inherits
that guarantee on its suffix range (VCW-5). ∎

**VCW-2 (Index-contiguity — the headline fix).** The gate at `:146–155` asserts
that the page returned for `from` carries exactly the indices `[from, from+count)`
in order: for header position `i`, `got = page["headers"][i].value("index", ~0)`
must equal `exp = from + i`, else it throws. This rejects:

- **An `index 0` header injected into a resume suffix.** On the first suffix page
  `from == anchor_height > 0`, so the expected first index is `anchor_height`, not
  `0`. A daemon that sets the first suffix header's `index` to `0` (to divert
  `verify_headers` into its genesis branch — see VCW-3) is caught here *before*
  `verify_headers` is even called, because `got=0 ≠ exp=anchor_height`. This is the
  paired defense to the `verify.cpp` index-0-with-anchor reject; either alone
  suffices, and both are present (defense in depth).
- **Index gaps / reordering / duplication.** Any page whose indices skip, repeat,
  or permute the contiguous run fails `got != exp` at the first offending
  position — a daemon cannot splice a header from one height into another height's
  slot to satisfy a downstream check.

Crucially, the gate **does not** reject `index 0` on the from-genesis walk: there
`from == 0 ⇒ exp == 0` at position `i=0`, so the genuine genesis block passes.
The gate thus distinguishes "index 0 is the real genesis (`from==0`)" from "index
0 is a daemon's diversion attempt (`from>0`)" purely by arithmetic, with no
heuristic. Combined with the loop's `from += PAGE` stride, it establishes the
invariant that the header at the head of page `from` *is* the block the chain
calls index `from`. ∎

**VCW-3 (Anchor binding).** The first page's first header is bound to the start
anchor on both paths:

- **From-genesis (`start_from=0`).** `verify_headers(page, genesis_hash_hex, "")`
  enters the genesis branch (`verify.cpp:172–201`): it requires
  `first_index==0`, `first_prev == 0…0` (`:188–192`), and — since
  `genesis_hash_hex` is non-empty — `block_hash == genesis_hash_hex` (`:193–201`).
  So block 0's hash is pinned to the operator's locally recomputed genesis hash
  (the T-L1 anchor).
- **Resume (`start_from=anchor_height`).** `verify_headers(page, "", prev_anchor)`
  enters the prev_hash branch (`verify.cpp:202–209`) because the
  index-contiguity gate (VCW-2) already forced `first_index == anchor_height ≠ 0`:
  it requires `first_prev == prev_hash_hex`, i.e. the first suffix header's
  `prev_hash` must equal the cached, previously-verified anchor `block_hash`
  (`initial_prev_anchor`). A suffix that forks/rolls back *below* the anchor fails
  here and throws — surfacing as a hard error, never a silent re-verification from
  genesis that would mask the fork.

The **paired `verify.cpp` defense** is the index-0-with-anchor reject at
`verify.cpp:172–186`: if a header *claims* `index 0` while a non-empty
`prev_hash_hex` anchor was supplied, `verify_headers` returns
`FAIL: header claims genesis (index 0) but a mid-chain prev_hash anchor was
supplied`. This independently blocks the diversion even if a future caller passed
an `index 0` page into the prev_hash branch without the contiguity gate in front
of it. The two defenses are deliberately redundant: VCW-2 stops the page before
`verify_headers`; this guard stops it inside `verify_headers`. ∎

**VCW-4 (Walked-count).** After the page loop, `:213–219` requires
`headers_seen == head_height - start_from`, where `headers_seen` accumulates
`vh.count` (the verified header count) per page (`:169`). A daemon that reports
`head_height = H` via `fetch_head_height` but then serves a short FINAL page —
returning fewer headers than the loop's `want = min(PAGE, head_height - from)`
requested for the last iteration — drives `headers_seen < H - start_from`, so the
gate throws `walked N headers but expected M … daemon served a short page`. This
closes the "reported-height-exceeds-walked" discrepancy: the verified tip can only
be claimed as `head_height` if *every* block in `[start_from, head_height)` was
actually walked and verified. Non-final short pages are *already* caught upstream
(the next page's first `prev_hash` would not chain, VCW-3 / `verify.cpp:212–223`);
this gate adds the final-page case. It **hardens both callers**: for
`verify_chain_from_anchor` it bounds the suffix; for `verify_chain_to_head`
(`start_from=0`) it bounds the full from-genesis walk — a daemon cannot report a
tall chain and then under-serve its tail. ∎

**VCW-5 (Prefix-skip soundness for resume).** The resume walk verifies only the
suffix `[anchor_height, head_height)` and skips re-verifying the committee-signed
prefix `[0, anchor_height)`. This is sound under A1+A2. The per-block sig check
binds each suffix block to a committee-attested digest: `verify_block_sigs`
recomputes `light_compute_block_digest(b)` (`verify.cpp:283`) and checks every
committee member's Ed25519 signature against it (`:287–307`). That digest binds
both `b.index` (`verify.cpp:59`) and `b.prev_hash` (`verify.cpp:60`) — so a valid
K-of-K signature on a suffix block forces its `prev_hash` to a value the committee
actually attested, not one the daemon chose. Inductively, from the cached anchor:
the first suffix block's `prev_hash` is pinned to `anchor_block_hash` (VCW-3) and
its index to `anchor_height` (VCW-2); each subsequent block's `prev_hash` is
pinned to the prior block's `block_hash` by intra-page continuity
(`verify.cpp:212–223`). A `block_hash` equal to the cached anchor therefore *is*
the previously-verified block — its hash transitively commits the entire prefix
under A2 — so re-verifying `[0, anchor_height)` is redundant. Critically, the
genesis sig-skip is gated on `from==0` (`:187`), **not** on `idx==0` alone: on the
resume walk `from == anchor_height > 0`, so the skip never fires and *no* suffix
block escapes its committee-sig check — even one a daemon mislabeled `index 0`
(which VCW-2 already rejects upstream). This is the local statement of
`LightStatePersistenceSoundness.md` LSP-6's prefix-skip argument, now anchored to
the shared-core line numbers. ∎

## 4. What it does NOT do (honest limitations)

- **No defense against an all-honest-looking forged chain.** If A_daemon could
  produce K-of-K committee Ed25519 signatures over a forged digest, the walk would
  accept it — but that is exactly an A1 break (probability `≤ H·K·2⁻¹²⁸` cumulative
  over a chain of `H` blocks per `LightClientThreatModel.md` T-L2). The walk is no
  stronger than A1+A2 and claims nothing more.
- **F2 / cross-shard blocks fail-closed, not bypassed.** `light_compute_block_digest`
  cannot reconstruct the F2 view roots stripped from the header
  (`verify.cpp:42–55`), so on such blocks the sig check FAILS (false-negative,
  never false-PASS). `verify_chain_walk` surfaces that as a hard error; verify
  those chains against a full node. This is a property of the digest, inherited by
  the walk, not introduced by it.
- **Single-daemon.** The walk verifies *one* daemon's served chain end to end; it
  does not detect a daemon that withholds (serves a shorter honest chain) or an
  eclipse onto a parallel committee-signed fork. Cross-daemon detection is
  `MultiPeerCrossCheckSoundness.md`'s job; liveness/withholding is the
  `NegativeVerdictSoundness.md` boundary.
- **Anchor trust is assumed, not established here.** The resume path trusts that
  `initial_prev_anchor` came from a prior committee-verified head. That the cached
  anchor is itself sound is `LightStatePersistenceSoundness.md` LSP-1..LSP-5's
  job (no-unverified-write, genesis-pin, fail-closed load); `verify_chain_walk`
  only guarantees the suffix correctly extends *whatever* anchor it is handed.

## 5. Test surface

- **Offline, every host:** `tools/test_light_verify_headers_edge.sh` exercises
  `verify_headers` directly with hand-crafted `headers` replies — no daemon, no
  genesis build. Case 4 (genesis header with non-zero `prev_hash` → FAIL exit 1)
  and cases 8–9 (`--prev-hash` / `--genesis-hash` anchor mismatch → FAIL exit 1)
  pin the anchor-branch gates of VCW-3 and the index-0-with-anchor reject path
  (`verify.cpp:172–192`) that VCW-2 pairs with. These run deterministically on
  every host because `verify_headers` is daemon-free.
- **Cluster:** `tools/test_light_verify_chain_file.sh` drives the full
  continuity + per-block-sig walk over a minted chain file (the same logic
  `verify_chain_walk` runs against a live daemon). Its negatives pin the gates:
  tampered `prev_hash` → CONTINUITY FAIL exit 2 (case 8, VCW-3/VCW-5 continuity);
  tampered committee sig → SIGS FAIL exit 2 (case 9, VCW-5 digest binding);
  STRIPPED sigs on a non-genesis block → SIGS FAIL exit 2 (case 10 — the
  emptiness-skip hole, confirming the skip keys on the genuine genesis only,
  VCW-5's `from==0` gating). The live resume suffix-verify + the index-contiguity
  / walked-count rejections against a real daemon are exercised on WSL2/CI, like
  every other `determ-light` composite.

## 6. Cross-references

`LightStatePersistenceSoundness.md` (LSP-6 — the resume-soundness fix this is the
analytic companion to; LSP-1..LSP-5 — the cached-anchor soundness VCW-5 depends
on), `LightClientThreatModel.md` (T-L1 genesis anchor reused by VCW-3; T-L2
head-trust the shared walk delivers on both ranges; A_daemon), `verify.cpp`
(`verify_headers` genesis/anchor branches + index-0 reject; `verify_block_sigs`;
`light_compute_block_digest` index+prev_hash binding),
`MultiPeerCrossCheckSoundness.md` (the single-daemon limitation §4 records, closed
cross-peer there), `Preliminaries.md` §2.0–§2.2 (A1 Ed25519 EUF-CMA / A2 SHA-256
collision resistance).
