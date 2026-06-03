# LightClientArchiveSoundness — offline-reverifiable header-archive soundness (`determ-light export-headers` / `verify-archive`)

This document formalizes the soundness of the **header-archive export/verify flow** shipped for the `determ-light.exe` light-client binary. The flow comprises two subcommands:

- **`export-headers`** (sibling B3, commit `1f42592`) — connects to ONE operator-controlled daemon, fetches headers `[from, from+count)`, verifies committee signatures + prev_hash continuity **online** (at export time) against a genesis-pinned committee, and writes a self-contained JSON archive to disk. Implementation at `light/export.cpp` + `light/export.hpp`.
- **`verify-archive`** (sibling C3, round 3, landing in parallel with this proof) — re-verifies that archive **offline** (no daemon contact) against a pinned genesis: genesis-hash anchor + prev_hash continuity + committee-signature re-verification. Implementation at `light/verify_archive.cpp` (C3 round 3); at the time of writing, this proof cites the verification steps at the *spec* level per the round-3 design and tags any unlanded specifics accordingly.

The security claim worth proving — and the reason this proof exists as a distinct document from `LightClientThreatModel.md` — is the **temporal** one:

> An archive that passes `verify-archive` is a cryptographically sound attestation of the chain's header sequence over `[from, from+count)`, re-checkable indefinitely without trusting any live daemon, under the same FA1 / FA3 + `LightClientThreatModel.md` assumptions.

`LightClientThreatModel.md` proves the *online* per-invocation pipeline is sound (an honest light-client never acts on data inconsistent with the operator's pinned genesis under a malicious daemon `A_daemon`). This document adds the time dimension: the export step captures a chain prefix at time `t1`; the archive is a self-contained byte string; `verify-archive` at any later time `t2 > t1` recomputes the same verdict from `(archive bytes, genesis bytes)` alone. No new cryptographic primitive is introduced — the soundness is the *composition* of T-L1 (genesis anchor) + T-L2 (committee-sig trust) + prev_hash continuity, re-applied to the archive's stored headers off-line.

This proof is deliberately honest about two limitations that a rigorous treatment must not overclaim: **AR-3 (range-completeness)** — the archive proves the headers it *contains* are valid but does not, in general, prove it contains *all* headers in a range; and **AR-4 (committee-rotation tracking)** — the export/verify committee is seeded from genesis and not extended for mid-range `REGISTER` / `DEREGISTER`, so the archive is sound for committee-stable ranges and needs the full registry history for cross-rotation ranges. Both are analyzed precisely in §4 and recorded in §6.

**Companion documents.** `LightClientThreatModel.md` (T-L1..T-L5, the online per-invocation pipeline this archive flow reuses); `Preliminaries.md` (F0) §2.1 (SHA-256 collision resistance, A3 in this proof's terms) + §2.2 (Ed25519 EUF-CMA, A1 in this proof's terms); `Safety.md` (FA1) for the K-of-K signature-set safety property the archive inherits via per-header sig re-verification; `S033StateRootNamespaceCoverage.md` for the state_root surface a future archive→state-proof composition would anchor against (§5.2); `MerkleTreeSoundness.md` (sibling C5, round 3 — landing in parallel) for the offline Merkle-inclusion primitive (MT-4) that §5.2 composes with; `BlockchainStateIntegrity.md` for the chain-level integrity the daemon's served data has already passed; `RpcAuthHmacSoundness.md` + `S001RpcAuthSoundness.md` for the multi-theorem-under-named-adversary citation style.

---

## 1. Scope

The object of study is the **export → archive → verify-archive** flow, a three-stage pipeline split across time and trust boundaries:

```
   time t1 (export)                  disk / transport                time t2 ≥ t1 (audit)
 ┌──────────────────────┐         ┌──────────────────┐         ┌──────────────────────────┐
 │ determ-light          │         │  archive.json    │         │ determ-light             │
 │   export-headers      │  write  │  {exported_at_   │  read   │   verify-archive         │
 │ ── ONE daemon ──►      │ ──────► │   height, from,  │ ──────► │ ── NO daemon ──►          │
 │ anchor_genesis        │         │   count,         │         │ genesis-hash anchor      │
 │ verify_headers        │         │   genesis_hash,  │         │ prev_hash continuity     │
 │ verify_block_sigs     │         │   headers:[...]} │         │ committee-sig re-verify  │
 │ (ONLINE verification) │         │                  │         │ (OFFLINE verification)   │
 └──────────────────────┘         └──────────────────┘         └──────────────────────────┘
        T-L1 + T-L2                  self-contained                 AR-1 + AR-2 (this doc)
```

The flow **builds on** `LightClientThreatModel.md`:

- The export step *is* a restriction of the online pipeline (T-L1 genesis anchor + T-L2 committee-sig verify + the §3.3 prev_hash continuity walk) to the finite range `[from, from+count)`, followed by a write to disk. It performs no state-proof read and no sign/submit (T-L3 / T-L4 / T-L5 are out of the archive flow's scope).
- The `verify-archive` step reuses the same verification primitives (`verify_headers`, `verify_block_sigs`) but sources its inputs from the archive bytes + the pinned genesis file rather than from a live daemon. It is therefore a *pure offline re-execution* of the export step's verification, minus the network fetch.

This document adds the **temporal dimension** that `LightClientThreatModel.md` does not address: that document's claims are all per-invocation against a live daemon at a single point in time. Here, the archive captured at `t1` is verified at `t2 > t1`, and the central question is whether the `t2` verdict is sound and time-invariant. AR-2 answers yes; AR-3 bounds exactly what the `t2` verdict does and does not establish.

**Archive schema** (from `light/export.cpp::run_export_headers`, the `archive` object built immediately before the write):

```json
{
  "exported_at_height": <head-height-at-export-time>,
  "from":               <H1>,
  "count":              <M>,
  "genesis_hash":       "<64-hex>",
  "headers": [
    {
      "index":                   <H1>,
      "header_json":             { ...header... },
      "verified_committee_sigs": true
    },
    ...
  ]
}
```

`header_json` is the daemon's `rpc_headers` per-block object. By default `creator_block_sigs` is stripped from each `header_json` after export-time verification (`hdr_copy.erase("creator_block_sigs")` in `light/export.cpp`); with `--include-committee-sigs` it is preserved. This distinction is load-bearing for offline committee-sig *re*-verification and is analyzed in AR-1, AR-2, and §6.4.

**Out of scope (inherited from `LightClientThreatModel.md` §2.2, plus archive-specific exclusions).**

- **Cryptographic breaks** (`A_crypto`): SHA-256 collision/preimage finder (A3 / A4), Ed25519 forger (A1). The archive flow's soundness rests on these being infeasible.
- **The auditor's own machine compromise** (`A_local`): key extraction, ptrace, tampering with the `verify-archive` binary itself, or rewriting the archive *after* a verification pass. Operator/auditor mitigates via OS-level integrity.
- **Tampered pinned genesis** (`A_genesis`): if the auditor pins a tampered `genesis.json`, the archive is verified against the wrong chain identity. This is the "trust anchor itself is compromised" case; out of scope exactly as in `LightClientThreatModel.md` §2.2.
- **State-proof / DApp / cross-shard archive content.** The archive carries only headers (the `a:`/`d:`/`i:` namespace state surfaces are not archived). A future archive→state-proof composition is noted in §5.2 but is not implemented; the archive itself attests headers only.
- **Freshness.** The archive is a *snapshot*; it makes no claim about chain state after `exported_at_height`. This is not a limitation to be fixed — it is the definition of a snapshot — but it is recorded in §6.3 because an auditor must not read more into an archive than its temporal scope supports.

---

## 2. Threat model

We retain the `LightClientThreatModel.md` adversary `A_daemon` (the single daemon the light-client talks to is fully under adversary control) for the *export* stage, and add three archive-flow-specific adversaries that target the auditor consuming the archive.

### 2.1 `A_archive_forge` — forged-archive adversary

The adversary hands the auditor a **forged archive** and tries to make `verify-archive` accept it. The forged archive may contain:

- **Fabricated headers** for a chain that never existed (arbitrary `index`, `prev_hash`, `block_hash`, `tx_root`, `delay_seed`, `creators`, `creator_block_sigs`, `state_root`).
- **Forged committee signatures** — `creator_block_sigs` entries the adversary computed without the committee members' Ed25519 secret keys.
- **A wrong-chain archive** — genuine headers from a *different* chain (different genesis) presented as if they were the auditor's chain.
- **A mixed archive** — a genuine prefix splice-jointed to fabricated suffix headers, or vice versa.

`A_archive_forge` wins if `verify-archive` returns success (exit 0) on an archive whose headers are not a genuine, committee-signed, genesis-anchored prefix of the auditor's pinned chain. AR-1 defeats this adversary.

### 2.2 `A_stale` — stale/truncated-archive adversary

The adversary serves a **real but incomplete or old** archive — every header in it is genuine and committee-signed, but the range is truncated or stale so as to hide later events:

- **Truncation**: the archive covers `[from, from+count)` but omits later genuine blocks that contain events the adversary wants hidden (a payment, a `DEREGISTER`, a slashing event recorded in a later block).
- **Stale `exported_at_height`**: the archive claims `exported_at_height = h_claim` but the chain's true head at export time was `h_true > h_claim`; the adversary under-reports the head to make the archive look complete-to-tip when it is not.
- **Genuine sub-range with a misleading boundary**: the archive is a valid `[from, from+count)` slice but the auditor is led to believe it is the *whole* chain or the whole period of interest.

`A_stale` is the subtle adversary: every cryptographic check passes because the headers *are* genuine. AR-3 analyzes precisely what the archive does and does not prove against `A_stale`, and what an auditor must do to obtain completeness.

### 2.3 `A_daemon_at_export` — malicious-daemon-at-export-time adversary

The daemon was malicious **at export time** and served bad data that the export step's *online* verification should have caught:

- Forged headers, forged sigs, wrong-chain block 0, broken prev_hash continuity, or a header signed by a creator outside the genesis-seeded committee.

`A_daemon_at_export` wins if `export-headers` produces a *non-failing* archive (exit 0, archive written) that nonetheless contains data inconsistent with the auditor's pinned genesis chain. AR-1's export-side half (and the fail-closed contract inherited from `LightClientThreatModel.md` L-6) defeats this adversary: any inconsistency the export-time verification detects causes a non-zero exit and *no* archive is written, so a written archive is one whose contents passed online verification.

### 2.4 Out of scope

As §1: `A_crypto`, `A_local` (including post-verification archive tampering on the auditor's disk and tampering with the `verify-archive` binary), `A_genesis`. We also exclude transport-layer confidentiality at export time (`A_net` from `LightClientThreatModel.md` §2.2) — it is an availability/privacy concern, not a soundness concern, because every byte the daemon returns is verified.

### 2.5 Security goal

Under the adversaries of §2.1–§2.3, the archive flow satisfies:

1. **Soundness of acceptance** (AR-1): `verify-archive` accepts only archives whose contained headers form a genesis-anchored, prev_hash-linked, committee-signed sequence over `[from, from+count)`.
2. **Temporal soundness** (AR-2): the acceptance verdict is a deterministic function of `(archive bytes, genesis bytes)` and is therefore invariant across verification time.
3. **Honest scope disclosure** (AR-3): acceptance establishes validity of the *contained* headers but not range-completeness, except in the from-genesis-to-known-head special case.

The negation form (fail-closed): any inconsistency `verify-archive` detects causes a `throw` propagating to a non-zero exit with a structured diagnostic — the same discipline `LightClientThreatModel.md` L-6 establishes for the online pipeline, re-used by the offline verifier.

### 2.6 Adversary-to-theorem matrix

| Adversary | Capability | Wins if | Defeated / bounded by | Outcome |
|---|---|---|---|---|
| `A_archive_forge` (§2.1) | Hands the auditor an arbitrary archive (fabricated headers, forged sigs, wrong-chain, spliced) | `verify-archive` accepts an archive whose headers are not a genuine genesis-anchored committee-signed prefix | AR-1 (A1 + A3/A4); bound `count · K · 2⁻¹²⁸ + 2⁻¹²⁸` | **Defeated** (cryptographically) — for `--include-committee-sigs` archives; stripped archives inherit clause (c) as an exporter claim (§4.1, §6.4) |
| `A_stale` (§2.2) | Serves a real-but-truncated/stale archive (genuine headers, incomplete/old range, under-reported `eah`) | Auditor concludes completeness/freshness the archive does not support | AR-3 — *bounded, not defeated*; AR-L5 (`eah` is a claim) + AR-L4 (slice floats) | **Scope limitation** — completeness is the auditor's C-from-genesis / C-cross-check obligation (§4.6, §6.1) |
| `A_daemon_at_export` (§2.3) | Malicious daemon at export time (forged/broken data the online verification should catch) | A *written* archive contains data inconsistent with `genesis_O` | AR-L1 (export fail-closed: no archive on any verification failure) + `LightClientThreatModel.md` T-L1/T-L2 online | **Defeated** — a written archive provably passed online verification |
| `A_crypto` / `A_local` / `A_genesis` (§2.4) | Break a primitive / compromise the auditor's machine or binary / tamper the pinned genesis | (various) | Out of scope — soundness rests on these not occurring | **Out of scope** (explicit) |

The matrix encodes the proof's central honesty point: `A_archive_forge` and `A_daemon_at_export` are *defeated cryptographically*, but `A_stale` is only *bounded* — it is a scope limitation discharged by auditor-side obligations, not a cryptographic guarantee. A reviewer should read AR-3 (§4.3) + the decision matrix (§4.6) as the precise statement of what `A_stale` can and cannot achieve.

---

## 3. Verification primitives recap

The archive flow reuses, verbatim, the verification primitives `LightClientThreatModel.md` §3 defines. They are recapped here only to fix notation; the authoritative descriptions are in that document.

| Primitive | Function | `LightClientThreatModel.md` ref | Used at |
|---|---|---|---|
| Genesis anchor | `anchor_genesis` (online) / genesis-hash equality (offline) | §3.1 / T-L1 | export (online), verify-archive (offline) |
| Committee-signature verify | `verify_block_sigs` | §3.2 / T-L2 | export (per header), verify-archive (per header, when sigs present) |
| Header-chain continuity | `verify_headers` | §3.3 | export (per page), verify-archive (over stored headers) |
| Merkle state-proof verify | `verify_state_proof` | §3.4 / T-L3 | *not* in the archive flow (headers only); §5.2 composition only |

The two load-bearing facts for this document:

- **Genesis anchor (offline form).** Online, `anchor_genesis` recomputes `compute_genesis_hash(genesis_O)` locally and cross-checks the daemon's block-0 hash. Offline, `verify-archive` recomputes `compute_genesis_hash(genesis_O)` from the pinned genesis file and checks byte-equality against the archive's `genesis_hash` field (and, when the archive contains block 0, against `headers[0].block_hash` via `verify_headers`' genesis branch). The local recomputation is the same deterministic SHA-256 reduction in both cases (`LightClientThreatModel.md` L-1); the only difference is whether the *other* operand comes from the network or from the archive bytes.

- **Committee-signature verify reuses the genesis-seeded committee.** Both `export.cpp::verify_header_sigs` and `trustless_read.cpp::verify_chain_to_head` build a single `committee_json` from `build_genesis_committee(genesis)` (the genesis `initial_creators`) and pass it unchanged to every per-header `verify_block_sigs` call. `verify_block_sigs` demands every entry of the header's `creators` list be present in that committee (`light/verify.cpp`: "creator '<domain>' is not in the supplied committee") before checking the Ed25519 signatures over `light_compute_block_digest`. This static-committee fact is exactly what AR-4 turns on.

`verify_headers` continuity has one subtlety the archive flow inherits and that AR-3 depends on: it anchors to the genesis hash **only when the leading header has `index == 0`**. For a sub-range starting at `from > 0`, the export step's page loop branches on `cursor == 0` (the absolute block index of the page, not the page ordinal): the genesis-anchored call `verify_headers(page, genesis_hash_hex, "")` fires only when `cursor == 0`, and otherwise the call is `verify_headers(page, "", prev_anchor)`. Since a `from > 0` export starts with `cursor == from > 0`, its first page takes the `else` branch with `prev_anchor` still at its empty initialization (`light/export.cpp`: `std::string prev_anchor;` initialized empty; assigned `vh.block_hash_hex` only *after* the first page verifies). Consequently the *first* header of a `from > 0` archive is **not** linked by hash to anything below it — `verify_headers` checks only that the headers within the slice chain to each other, not that the slice's first `prev_hash` connects to the genuine block `from − 1`. The slice is internally consistent and committee-signed, but its attachment to genesis is *unproven* for `from > 0`. This is the cryptographic root of the AR-3 caveat.

### 3.1 Archive ↔ `rpc_headers`-envelope reconstruction (the inverse-of-strip step)

`verify_headers` and `verify_block_sigs` consume an `rpc_headers`-shaped input (`{headers: [...], from, count, height}`) or a single header object — the shapes the daemon returns online. The archive stores the same headers but wrapped in the §1 record schema (`{index, header_json, verified_committee_sigs}` per record). `verify-archive` therefore reconstructs the envelope from the archive before re-running the primitives offline:

```
envelope := { headers: [ A.headers[j].header_json : 0 ≤ j < A.count ],
              from:    A.from,
              count:   A.count,
              height:  A.exported_at_height }
```

This is exactly the unwrap `tools/test_light_export_headers.sh` assertion 5 performs (it builds the envelope from `[rec['header_json'] for rec in a['headers']]` and pipes it to `verify-headers --in`), demonstrating the round-trip on the shipped B3 export. The reconstruction is a pure structural rearrangement — it copies `header_json` values without inspecting or mutating them — so it preserves byte-for-byte every field `verify_headers` / `verify_block_sigs` reads. Two consequences the theorems rely on:

- **For AR-1**, the offline primitives see exactly the fields the export-side primitives saw (modulo the stripped `creator_block_sigs` on default archives), so the offline verdict on those fields is the same computation as the online one.
- **For AR-2**, the reconstruction is itself a deterministic pure function of `A` (no clock, no network), so it does not break the purity argument: `verify-archive` is reconstruction ∘ primitives, a composition of pure functions.

`verify-archive` MAY perform the reconstruction internally (consuming the archive schema directly) rather than literally materializing an `rpc_headers` envelope; either way the *values* fed to the primitives are the archived `header_json` objects. Confirm the concrete shape at `light/verify_archive.cpp` (C3 round 3).

---

## 4. Soundness theorems

Notation: `H := headers` (the archive's `headers` array), `H[j].hj := H[j].header_json`, `from`, `count`, `gh := genesis_hash`, `eah := exported_at_height`. `genesis_O` is the auditor's pinned genesis; `K_0 := build_genesis_committee(genesis_O)` the genesis-seeded committee map. `A3` is SHA-256 collision resistance, `A4` SHA-256 preimage resistance, `A1` Ed25519 EUF-CMA (Preliminaries §2.1 + §2.2).

### 4.1 Theorem AR-1 (archive integrity = header-sequence attestation)

**Statement.** Under A1 + A3, an archive that passes `verify-archive` against pinned genesis `genesis_O` attests that its stored headers `H[0..count)` form a sequence such that:

(a) `H[j].hj.prev_hash == H[j−1].hj.block_hash` for every `1 ≤ j < count` (prev_hash continuity within the slice);
(b) if `from == 0`, then `H[0].hj.block_hash == compute_genesis_hash(genesis_O)` and `H[0].hj.prev_hash` is all-zero (genesis anchor);
(c) every non-genesis header `H[j].hj` carries `creators ⊆ K_0` and a committee-signature set valid under `K_0` over `light_compute_block_digest(H[j].hj)`, at the K-of-K (MD) or `⌈2k/3⌉` (BFT) threshold — **provided the archive carries `creator_block_sigs`** (the `--include-committee-sigs` archive; see the stripped-archive note below).

No adversary `A_archive_forge` can produce an archive violating (a)–(c) that `verify-archive` accepts, except with probability `≤ count · K · 2⁻¹²⁸`.

**Adversary game.**

1. Setup. Auditor pins `genesis_O`, computing `K_0` and `gh_O := compute_genesis_hash(genesis_O)` locally inside `verify-archive`.
2. `A_archive_forge` produces an archive `A` (arbitrary bytes parsing as the §1 schema).
3. Adversary wins if `verify-archive(A, genesis_O)` returns success while `A`'s headers violate (a), (b), or (c).

**Proof.** `verify-archive` reconstructs an `rpc_headers`-shaped envelope from `A`'s `header_json` records (the inverse of the export-side strip — see the round-trip in `tools/test_light_export_headers.sh` assertion 5, which performs exactly this unwrap) and runs the same `verify_headers` + `verify_block_sigs` primitives offline. We bound each clause:

*Clause (b), genesis anchor (from == 0 archives).* The verifier computes `gh_O` locally and checks `A.genesis_hash == gh_O` and, via `verify_headers`' index-0 branch, `H[0].hj.block_hash == gh_O`. For the adversary to pass with a different chain, it needs `compute_genesis_hash(genesis_A) = gh_O` for some `genesis_A ≠ genesis_O`, a SHA-256 collision, or it must fabricate a block-0 `header_json` whose `block_hash` field literally equals `gh_O` while the header's own content does not hash to `gh_O`. The latter is caught because `verify_block_sigs`/`verify_headers` operate on the stored fields; but note the archive's stored `block_hash` is a *claimed* field, not recomputed by `verify_headers`. This is the same observation as `LightClientThreatModel.md` T-L1 Case 2: the load-bearing anchor is the *equality* of the genesis hash; downstream prev_hash continuity (clause a) forces every subsequent header's `prev_hash` to equal the prior header's *claimed* `block_hash`, so a forged block-0 `block_hash` that does not match the header's true content desynchronizes the chain unless the adversary also forges every subsequent header consistently — which collapses to forging the committee signatures (clause c). Probability bounded by A3 collision + A4 preimage: `≤ 2⁻¹²⁸`.

*Clause (a), prev_hash continuity.* `verify_headers` walks consecutive pairs and requires `H[j].hj.prev_hash == H[j−1].hj.block_hash`. Any break throws. For the adversary to present a continuous-but-fake chain it must choose `block_hash` values that link; this is free (the adversary controls all fields), so continuity *alone* does not establish authenticity — it only establishes *internal* consistency of the slice. Authenticity comes from clause (c) binding each header's content (including `prev_hash`, which is an input to `light_compute_block_digest`) to a committee signature. Thus (a) is necessary but the security weight is carried by (c).

*Clause (c), committee signatures.* For every non-genesis `H[j].hj`, `verify_block_sigs` requires `creators ⊆ K_0` and `valid ≥ required` Ed25519 verifications of `creator_block_sigs[i]` against `digest_j := light_compute_block_digest(H[j].hj)` under `K_0[creators[i]]`. Because `prev_hash`, `tx_root`, `delay_seed`, `index`, `consensus_mode`, `bft_proposer`, `creators`, `creator_tx_lists`, `creator_ed_sigs`, and `creator_dh_inputs` are *all* inputs to `light_compute_block_digest` (`LightClientThreatModel.md` L-2, byte-for-byte copy of `producer.cpp::compute_block_digest`), any fabrication of those fields changes `digest_j`, so the adversary's stored `creator_block_sigs` would have to be valid Ed25519 signatures over the *new* digest under genesis-committee keys it does not hold. By A1, each such forge succeeds with probability `≤ 2⁻¹²⁸`; the threshold demands `required` distinct-member forges; union over `count` headers and `≤ K` members per header gives `≤ count · K · 2⁻¹²⁸`.

Combining: `Pr[A_archive_forge wins] ≤ 2⁻¹²⁸ + count · K · 2⁻¹²⁸ ≤ count · K · 2⁻¹²⁸ + 2⁻¹²⁸`. For `count ≤ 2⁴⁰` and `K ≤ 16`, this is `≤ 2⁻⁸⁴`, negligible. ∎

**Defeats `A_archive_forge`.** Forging an accepted archive requires either a genesis-hash collision/preimage (A3 / A4) or committee-signature forgery (A1) — exactly the two cryptographic walls T-L1 and T-L2 establish, now applied to archive bytes rather than live RPC replies.

**Stripped-archive caveat (load-bearing).** The *default* archive strips `creator_block_sigs` from each `header_json`. For a stripped archive, clause (c) **cannot be re-verified offline** — the signatures are simply not present in the bytes. `verify-archive` on a stripped archive can therefore re-establish only clauses (a) and (b) (prev_hash continuity + genesis anchor); it inherits clause (c) **transitively** from the export step's `verified_committee_sigs: true` assertion, which is a *claim recorded by the (possibly malicious) exporter*, not an offline-recheckable proof. The same byte-stripping is why `tools/test_light_export_headers.sh` assertion 5 round-trips the stripped archive through `verify-headers` (prev_hash) successfully even without sigs. **Consequence:** for an archive to be a fully *self-verifying* attestation under `A_archive_forge` — i.e., for clause (c) to be re-checkable by an auditor who does not trust the exporter — it MUST be exported with `--include-committee-sigs`. A stripped archive verified offline proves only that *some* prev_hash-linked, genesis-anchored header sequence with these claimed block hashes existed; it does not, offline, prove the committee signed them. This is recorded as a first-class limitation in §6.4, and `verify-archive`'s reporting SHOULD distinguish "continuity-only re-verification (stripped archive)" from "full committee-sig re-verification (`--include-committee-sigs` archive)". See `light/verify_archive.cpp` (C3 round 3) for whether it surfaces this distinction in its exit diagnostics.

### 4.2 Theorem AR-2 (offline re-verifiability / temporal soundness)

**Statement.** The `verify-archive` verdict is a **pure deterministic function** `V(archive_bytes, genesis_bytes) → {accept, reject}`. It depends on no live daemon, no network, and no wall-clock. Therefore for any two verification times `t2, t2′ ≥ t1` (the export time), `V` evaluated on the same `(archive_bytes, genesis_bytes)` yields the same verdict. An archive accepted at `t2` is accepted at every later `t2′`, and the attestation of AR-1 holds indefinitely.

**Proof.** We show every input to `verify-archive` is contained in `(archive_bytes, genesis_bytes)` and every step is a deterministic pure computation.

*Inputs.* `verify-archive` reads (i) the archive file bytes and (ii) the pinned genesis file bytes. It opens **no socket** — this is the defining difference from the online composite commands, whose pipeline diagram (`LightClientThreatModel.md` §3.5) has a live `RpcClient::call()` arm. The offline verifier's only I/O is two file reads.

*Genesis anchor.* `gh_O := compute_genesis_hash(GenesisConfig::from_json(genesis_bytes))`. By `LightClientThreatModel.md` L-1, `compute_genesis_hash` is a deterministic, platform-independent SHA-256 reduction over the canonical genesis encoding; it has no clock or network input. The equality check `A.genesis_hash == gh_O` (and the index-0 `block_hash` check) is byte comparison.

*Continuity.* `verify_headers` over the reconstructed envelope is a finite walk over `count` headers comparing fixed-width hex strings (`light/verify.cpp`). No clock, no network. Deterministic.

*Committee signatures.* `verify_block_sigs` parses `K_0` from `genesis_bytes`, computes `light_compute_block_digest` (pure SHA-256 reduction), and runs Ed25519 `verify` (deterministic given key, message, signature — RFC 8032 verification is a deterministic predicate). No clock, no network. (Applies to `--include-committee-sigs` archives; for stripped archives this step is absent per §4.1, which does not affect purity.)

*Composition.* `verify-archive` is the sequential composition of these pure steps with early-exit on the first failure. A finite composition of deterministic pure functions over a fixed input is itself a deterministic pure function. Hence `V(archive_bytes, genesis_bytes)` is well-defined and time-invariant. ∎

**Per-step input-dependency table** (the purity audit, step by step):

| `verify-archive` step | Reads from | Network? | Clock? | Determinism witness |
|---|---|---|---|---|
| Parse genesis | `genesis_bytes` | no | no | `GenesisConfig::from_json` is a pure parse |
| `gh_O := compute_genesis_hash` | parsed genesis | no | no | `LightClientThreatModel.md` L-1 (platform-independent SHA-256) |
| Genesis-hash equality | `gh_O`, `A.genesis_hash`, `A.headers[0].block_hash` | no | no | byte comparison |
| Reconstruct envelope (§3.1) | `A` | no | no | structural copy of `header_json` values |
| `verify_headers` continuity | reconstructed envelope | no | no | finite hex-string-equality walk (`light/verify.cpp`) |
| Parse committee `K_0` | `genesis_bytes` | no | no | `parse_committee` is a pure parse |
| `light_compute_block_digest` | each `header_json` | no | no | AR-L3 (digest binding); pure SHA-256 reduction |
| Ed25519 `verify` (sigs present) | digest, `K_0` pubkey, `creator_block_sigs[i]` | no | no | RFC 8032 verify is a deterministic predicate |

Every cell in the "Network?" and "Clock?" columns is "no". The only inputs are `genesis_bytes` and the archive `A`; the only outputs are accept/reject + a structured diagnostic. This is the mechanical content of "`V` is a pure function of `(archive bytes, genesis bytes)`" — and hence of time-invariance. Note in particular that `exported_at_height` does not appear in any row (AR-L5): the verdict does not depend on it, which is why an honest-looking but under-reported `eah` cannot change an *acceptance* verdict (it can only mislead the auditor about scope — AR-3).

**Contrast with the online pipeline.** `LightClientThreatModel.md`'s T-L1..T-L5 are per-invocation against a daemon whose responses may vary across invocations (`A_daemon` may "serve honest data once, lie next time", §2.1). The archive freezes the daemon's *export-time* responses into immutable bytes, removing the cross-invocation variability from the verification entirely: there is no daemon at `t2` to vary anything. This is precisely the value of an archive — it converts a *trust-the-daemon-now* check into a *trust-the-math-forever* artifact.

**Remark (what time-invariance does NOT give).** AR-2 says the *verdict on the archived bytes* is invariant. It does not say the *chain* is unchanged after `t1` — the chain advances; the archive simply stops describing it past `eah`. That gap is AR-3 (range) and §6.3 (freshness), not a defect in AR-2.

### 4.3 Theorem AR-3 (range-completeness caveat / `A_stale` analysis)

This is the key residual. We state precisely what an accepted archive proves about *range* and what it does not.

**Statement.** An archive that passes `verify-archive` proves that the headers it **contains** are valid (AR-1). It does **not**, in general, prove that it contains **all** headers of the chain over any interval, nor that `exported_at_height` is the chain's true head at export time. Specifically:

(i) The `exported_at_height` field is an **unverified claim** by the (possibly malicious) exporter/daemon. `verify-archive` has no offline means to check it against ground truth — there is no live chain to ask.
(ii) For `from > 0`, the archive does **not** prove its first header attaches to the genuine block `from − 1` (the §3 continuity subtlety: the leading `prev_hash` of a `from > 0` slice is checked against an empty anchor, so the slice "floats" — it is internally linked and committee-signed but not anchored to genesis).
(iii) Therefore `A_stale` (a real-but-truncated-or-stale archive) is **not** defeated by AR-1 + AR-2 alone.

Completeness is recoverable only under one of two auditor-side conditions:

- **(C-from-genesis)** `from == 0` **and** `count` reaches a head `H_known` the auditor independently knows to be the chain's true tip (or a known checkpoint). Then the genesis anchor (AR-1 clause b) pins the bottom, prev_hash continuity (AR-1 clause a) pins every link, and the independently-known head pins the top — the archive is a complete, gap-free, genesis-to-known-head attestation.
- **(C-cross-check)** The auditor cross-checks `exported_at_height` (and, for `from > 0`, the first header's attachment) against an **independent source** — a second daemon, an independently-pinned checkpoint, a previously-verified archive whose tip equals this archive's `from − 1` block hash, or an out-of-band published head.

**Proof of (i).** `export.cpp::run_export_headers` obtains `head_height` from `probe["height"]` where `probe = rpc.call("headers", {from:0, count:1})` — i.e., the daemon's *self-reported* tip. It is written verbatim into the archive as `exported_at_height`. The export step's *only* use of it is range validation (`from < head_height`, `from + count ≤ head_height`); it is never cryptographically bound to anything. An honest-looking daemon that under-reports its head (`A_stale`'s stale-`eah` variant) passes every export-time check — the headers it serves for the (smaller) range are genuine and committee-signed, so `verify_headers` + `verify_block_sigs` accept them, and the archive records the under-reported `eah`. Offline at `t2`, `verify-archive` likewise has nothing to compare `eah` against. Hence (i): `eah` is a claim, not a proof. ∎

**Proof of (ii).** For `from > 0`, the export step's first-page continuity call is `verify_headers(page, "", prev_anchor)` with `prev_anchor == ""` (empty) on the first iteration (`light/export.cpp` page loop: `prev_anchor` initialized empty; the `cursor == 0 ? genesis : prev_anchor` branch selects the empty `prev_anchor` for the leading page of a `from > 0` export). `verify_headers`' index-`>0` branch checks the leading `prev_hash` against `prev_hash_hex` **only if `prev_hash_hex` is non-empty** (`light/verify.cpp`: `else if (!prev_hash_hex.empty())`). With an empty anchor, that check is skipped, so the leading header's `prev_hash` is unconstrained relative to the genuine block `from − 1`. The same holds offline in `verify-archive`. Therefore a `from > 0` archive proves only "these `count` headers chain to each other and are committee-signed"; it does **not** prove "these headers are the genuine blocks at indices `[from, from+count)` of the auditor's chain" — a malicious exporter could serve a *different* committee-signed sub-chain that happens to be internally consistent (e.g., a sub-chain from a fork, or simply a different contiguous window whose committee membership is a subset of `K_0`). Anchoring a `from > 0` slice to the real chain requires the auditor to supply the genuine `block_hash` of block `from − 1` as the prev-anchor (condition C-cross-check). ∎

**Proof of (iii) / `A_stale` verdict.** Combine (i) and (ii): `A_stale` serves genuine headers, so AR-1 (validity of contained headers) holds and AR-2 (time-invariance) holds, yet the auditor learns nothing about completeness. Concretely:

- *Truncation attack*: the adversary exports `[0, h_hide)` honestly, omitting blocks `[h_hide, h_true)` that contain the event to hide. `verify-archive` accepts (all headers genuine). The auditor sees `exported_at_height = h_hide` and, absent C-cross-check, has no offline signal that the chain continued to `h_true`. **Not detected by the archive flow.**
- *Floating-slice attack* (`from > 0`): the adversary exports a genuine sub-chain that is not the prefix the auditor believes. `verify-archive` accepts. **Not detected** absent C-cross-check.

**Auditor obligations (honest documentation).** To use an archive as a *complete* attestation over a period, an auditor MUST do one of:

1. Export with `from == 0` and confirm the archive's tip block hash equals a head/checkpoint the auditor independently trusts (C-from-genesis). The `count` then provably spans genesis-to-known-head with no gaps.
2. Cross-check `exported_at_height` against an independent source, and for `from > 0`, additionally verify the archive's first header's `prev_hash` equals the genuine `block_hash` of block `from − 1` (C-cross-check). This re-anchors the floating slice.

**Verdict (the AR-3 headline).** *The archive proves the validity of the headers it contains, not their completeness over any range.* `exported_at_height` is a claim by a possibly-malicious exporter, not a proof. Range-completeness is an **auditor-side obligation** (C-from-genesis or C-cross-check), not a property the archive flow establishes on its own. This is the dominant residual limitation of the archive flow and is recorded as the first item of §6. It mirrors `LightClientThreatModel.md` F-4 (no defense against truncated chain claims by the daemon), now made temporal: the truncation/staleness is frozen into the archive and cannot be re-litigated offline.

### 4.4 Theorem AR-4 (committee-continuity within the archive)

**Statement.** The export and `verify-archive` committee is the **static** genesis-seeded committee `K_0`. If the active committee rotates within `[from, from+count)` via on-chain `REGISTER` / `DEREGISTER`, the archive flow's behavior is:

(a) **At export time**, any header whose `creators` list contains a domain **not in `K_0`** causes `verify_block_sigs` to fail (`"creator '<domain>' is not in the supplied committee"`), which causes `export-headers` to exit non-zero and write **no** archive. Hence **a successfully written archive cannot contain a header signed by a non-`K_0` creator** — the export step is fail-closed on committee drift (a positive safety property), at the cost of being unable to archive cross-rotation ranges at all under the default genesis-only seed.

(b) The archive's `header_json` records carry each block's `creators` list (it is part of the digest pre-image and is not stripped), but they do **not** carry the *public keys* of those creators — the pubkeys are sourced only from the genesis `initial_creators` via `build_genesis_committee`. Therefore an archive does **not** carry committee-evolution information sufficient to verify, offline, a header signed by a post-genesis-registered creator. `verify-archive` derives its committee solely from the pinned genesis file, identically to export.

(c) **Consequence.** The archive flow is **sound for committee-stable ranges** (every block in `[from, from+count)` produced by a `creators ⊆ K_0` committee — the common case for short-lived audit windows and for permissioned chains with a fixed genesis committee). For **cross-rotation ranges**, the archive flow under the default seed cannot produce an archive (it fails closed per (a)); to archive such a range, the operator must supply an **extended committee** that is a superset of every creator encountered — and crucially, *both* the export step *and* the `verify-archive` step must be given that same extended committee, since neither derives rotation from the chain.

**Proof.** Cross-reference to `verify_chain_to_head` (which `LightClientThreatModel.md` §3.3 + T-L2's "committee evolution" caveat documents) and direct reading of the export path:

- `light/trustless_read.hpp` states the contract explicitly: "The light client maintains an in-memory committee map (domain → pubkey) seeded from the genesis JSON's `initial_creators`, then extended as `REGISTER` txs would in a full node. v1.x light-client scope per the plan defers full `REGISTER` tracking — the verify pass extracts each block's `creators` list from the header and demands every member be in the locally-known committee (seeded from genesis ...). This covers genesis-pinned chains; chains with mid-chain `REGISTER`s need the daemon's `creators` RPC or a future stateful sync extension."
- `verify_chain_to_head` builds `committee_json` once from `committee_seed` and **never mutates it** across the page walk (`light/trustless_read.cpp`: the lambda `build_committee_json` is invoked once; the loop calls `verify_block_sigs(h, committee_json, …)` with the same object every iteration).
- `export.cpp::run_export_headers` does the same: `committee_json = build_committee_json(build_genesis_committee(genesis))` once, then `verify_header_sigs(h, committee_json)` per header. `verify_header_sigs` calls `verify_block_sigs` which rejects any `creators ⊄ committee`.

Thus the static-committee behavior is identical across the online composite read (`verify_chain_to_head`), the export step, and (by the §3 recap + C3's design reusing the same primitives) the offline `verify-archive` step. Clause (a) follows from `verify_block_sigs`' membership check + the export step's fail-closed exit (no archive on non-zero exit — `light/export.cpp` returns before the write on any per-header sig failure). Clause (b) follows from the archive schema carrying `header_json` (hence `creators`) but the pubkeys being a function of the genesis file only. Clause (c) is the composition of (a) and (b). ∎

**Finding (AR-4 headline).** *The archive carries enough to identify which domains signed each block (`creators`) but not enough to verify post-genesis-registered signers offline (no pubkeys for them).* Under the default genesis-only committee, the export step **fails closed** on any cross-rotation range — it will not silently produce an under-verified archive; it simply refuses. This is the safe failure mode, but it means: **the archive flow is sound for committee-stable ranges out of the box, and cross-rotation ranges require an operator-supplied extended committee fed identically to both `export-headers` and `verify-archive`.** This is the same limitation `LightClientThreatModel.md` §6.5 + F-1 record for the online pipeline, here inherited by the archive flow. A future stateful-sync extension that tracks `REGISTER` / `DEREGISTER` from the chain (or embeds a committee-rotation log into the archive) would close it; not implemented in the current binary. Whether `verify-archive` (C3 round 3) exposes a `--committee <file>` override for the extended-committee case is an implementation detail to confirm at `light/verify_archive.cpp`; the proof's clause (c) holds for whatever committee both steps are given, provided it is a superset of every creator encountered.

### 4.5 Supporting lemmas

These lemmas isolate the load-bearing steps so a reviewer can match each to a code location. Several are restatements of `LightClientThreatModel.md` lemmas applied to archive bytes; they are reproduced here so this proof is self-contained.

**Lemma AR-L1 (export-side fail-closed ⇒ written archive passed online verification).** If `export-headers` returns exit 0 and writes an archive `A`, then every record in `A` passed the export-time `verify_headers` (continuity) and `verify_block_sigs` (committee-sig) checks against `genesis_O`'s committee. Proof: `run_export_headers` returns a non-zero exit *before* the `std::ofstream` write on every verification-failure branch — the per-page `verify_headers` failure (`vh.ok == false`), the per-header `verify_block_sigs` failure (`sigs_ok == false`), the range-validation failures, and the assembled-count sanity check all `return 1` prior to the `f << archive.dump()` line. The write is reached only after the page loop completes with no early return. Therefore "archive written" ⇒ "all records passed online verification." This is the export-side instance of `LightClientThreatModel.md` L-6 (fail-closed exit) and is what defeats `A_daemon_at_export`. □

**Lemma AR-L2 (genesis-hash recomputation is identical online and offline).** The value `gh_O := compute_genesis_hash(GenesisConfig::from_json(genesis_bytes))` computed by `verify-archive` offline equals the value `anchor_genesis` computes online from the same `genesis_bytes`. Proof: both call the same `compute_genesis_hash` over the same parsed `GenesisConfig`; by `LightClientThreatModel.md` L-1 this is a deterministic, platform-independent SHA-256 reduction with no network or clock input. Hence the genesis anchor's *local operand* is identical in both settings; only the *other* operand differs (daemon block-0 reply online vs `archive.genesis_hash` / `headers[0].block_hash` offline). □

**Lemma AR-L3 (digest binding survives the strip-and-restore round-trip).** For an `--include-committee-sigs` archive, `light_compute_block_digest(H[j].hj)` computed by `verify-archive` equals the digest the producer signed when it produced the block. Proof: the export step stores `header_json` containing every field that is an input to `light_compute_block_digest` (index, prev_hash, tx_root, delay_seed, consensus_mode, bft_proposer, creators, creator_tx_lists, creator_ed_sigs, creator_dh_inputs) — none of these is the stripped field (`creator_block_sigs` is the *signature* over the digest, not an input to it). The heavy fields `pad_stripped_header` injects as empty (transactions, cross_shard_receipts, inbound_receipts, initial_state) are not digest inputs either (`LightClientThreatModel.md` L-2). Therefore the digest recomputed from the archived `header_json` equals the producer's digest byte-for-byte, and the archived `creator_block_sigs` verify against it under `K_0` exactly as they did at production. □

**Lemma AR-L4 (continuity within a slice is necessary but not sufficient for chain-attachment).** `verify_headers` over a slice establishes `H[j].prev_hash == H[j−1].block_hash` for all `1 ≤ j < count`, but for `from > 0` it does **not** establish `H[0].prev_hash == block_hash(block_{from−1})` of the genuine chain. Proof: the leading-header anchor check in `verify_headers`' index-`>0` branch is gated on `!prev_hash_hex.empty()`, and the export/verify path supplies an empty `prev_hash_hex` for the leading page of a `from > 0` slice (§3, §4.3(ii)). With the check skipped, `H[0].prev_hash` is unconstrained relative to the genuine chain; the slice is internally linked but unanchored below `from`. This is the cryptographic content of AR-3(ii). □

**Lemma AR-L5 (`exported_at_height` is causally downstream of the daemon, not the cryptography).** No verification step — online or offline — consumes `exported_at_height` as a security input. Proof: at export, `head_height` (written as `exported_at_height`) is used solely in the three range-validation comparisons; it is never fed to `verify_headers`, `verify_block_sigs`, `compute_genesis_hash`, or `light_compute_block_digest`. Offline, `verify-archive` likewise has no oracle to check it against. Hence `exported_at_height` is an unbound metadata claim — the content of AR-3(i). □

### 4.6 AR-3 auditor-obligation decision matrix

AR-3's honesty requirement is operational: an auditor must know, for a given archive, exactly what an accepted `verify-archive` verdict licenses them to conclude. The matrix below makes that explicit. "Validity" means AR-1 (contained headers are genuine, committee-signed, internally linked); "completeness" means "contains every block of the chain over the stated interval with no omission."

| Archive shape | `verify-archive` accepts ⇒ proves | Does NOT prove | Auditor action to upgrade to completeness |
|---|---|---|---|
| `from == 0`, tip = independently-known head `H_known` | Validity **and completeness** of `[0, H_known)` (genesis pins bottom via AR-1(b); continuity pins every link via AR-1(a); known head pins top) | — (complete under C-from-genesis) | None — this is the gold-standard complete attestation |
| `from == 0`, tip = exporter-claimed `eah` only | Validity of `[0, eah)`; bottom anchored to genesis | Completeness — `eah` is an exporter claim (AR-L5); chain may extend past `eah` (truncation, `A_stale`) | Confirm `eah`/tip against an independent head or checkpoint (C-cross-check) |
| `from > 0`, any tip | Validity of the *slice* (internally linked + committee-signed under `K_0`) | Attachment to the genuine block `from−1` (slice floats, AR-L4); completeness | Supply the genuine `block_hash(block_{from−1})` as a prev-anchor AND confirm tip (C-cross-check) |
| Stripped (default), any `from` | (offline) prev_hash continuity + genesis anchor only; committee-sig is the exporter's recorded claim | Offline committee-sig validity (sigs absent, §4.1 caveat); plus all range caveats above | Re-export with `--include-committee-sigs` for offline-recheckable sigs; then apply the range row above |

The matrix's top row is the only configuration in which an accepted archive is, by itself, a complete and self-verifying attestation — and only when the archive is also `--include-committee-sigs` (else the bottom row's sig caveat applies). Every other configuration leaves a documented, auditor-actionable gap. A rigorous audit procedure therefore pairs `verify-archive` acceptance with the corresponding right-column action; the proof does not claim the archive flow discharges those actions on its own.

---

## 5. Composition with `LightClientThreatModel.md` + `MerkleTreeSoundness.md`

### 5.1 AR-1 composes with T-L2 (committee-sig trust) and T-L1 (genesis anchor)

AR-1 is, structurally, **T-L1 + T-L2 applied to archive bytes instead of live RPC replies**, restricted to the finite range `[from, from+count)`:

- AR-1 clause (b) (genesis anchor) is T-L1's genesis-hash equality, evaluated against `archive.genesis_hash` / `headers[0].block_hash` rather than the daemon's block-0 reply. The reduction to A3/A4 is identical (`LightClientThreatModel.md` T-L1 Cases 1–2).
- AR-1 clause (c) (committee signatures) is T-L2's per-block `verify_block_sigs` primitive, evaluated against each `header_json` rather than each fetched header. The reduction to A1 (and the `K · 2⁻¹²⁸` per-header bound) is identical (`LightClientThreatModel.md` T-L2), and the committee-evolution caveat of T-L2 is exactly AR-4.
- AR-1 clause (a) (prev_hash continuity) is the §3.3 `verify_headers` walk, identical online and offline.

No new cryptographic assumption is introduced. The archive flow's contribution over `LightClientThreatModel.md` is **temporal** (AR-2) and **range-honesty** (AR-3), not cryptographic. This is the same "adds no new chain-level invariant; composes existing results" posture that `Safety.md` §7 (sibling B6, R39+2) records for the light-client's relationship to FA1.

### 5.2 Composition opportunity: AR-1 + MT-4 → offline state-membership proofs (future extension)

The current archive carries **headers only** — it does not archive state-proofs. A natural future extension would let an archive anchor *state-membership* proofs offline:

- AR-1 establishes that `header_json[j].state_root` is a committee-signed value (it is part of the header the committee signed via `light_compute_block_digest`'s coverage — though note `state_root` itself is bound through the header's broader `signing_bytes`/`block_hash` chain rather than the digest pre-image; see `LightClientThreatModel.md` T-L3 + `S033StateRootNamespaceCoverage.md` for the exact binding).
- `MerkleTreeSoundness.md` (sibling C5, round 3 — landing in parallel; see that document for the offline Merkle-inclusion theorem, referenced here as **MT-4**) establishes that `merkle_verify(R, key_bytes, value_hash, target_index, leaf_count, sibs)` accepts iff the leaf is genuinely committed under root `R`, offline, under A3.
- **Composition (if a future archive bundles state-proofs):** AR-1 (the archived header's `state_root` is committee-signed and genesis-anchored) + MT-4 (the leaf is committed under that `state_root`) would yield an **offline, indefinitely-recheckable state-membership attestation** — e.g., "account `domain` had balance `b` and nonce `n` at archived height `h`, provable from the archive bytes alone, no daemon." This is the archive analogue of the online T-L4 composite read.

This is noted as a **composition opportunity, not an implemented feature.** The current archive's `verify-archive` does not consume state-proofs; AR-1–AR-4 are about the header sequence. If/when a `--include-state-proofs` archive mode ships, this proof's AR-1 + `MerkleTreeSoundness.md` MT-4 are the two halves to compose, and the resulting theorem would mirror `LightClientThreatModel.md` T-L4's structure (committee-signed root + Merkle path + cleartext cross-check) with the daemon replaced by archive bytes.

### 5.3 What the archive flow does NOT extend

As `LightClientThreatModel.md` §5.2 (FA2): the archive flow does **not** extend censorship resistance. A daemon that censors specific headers at export time (refuses to serve them, or under-reports its head) produces a *valid-but-incomplete* archive — exactly the `A_stale` truncation analyzed in AR-3. The archive flow's defense is the auditor's C-from-genesis / C-cross-check obligation, not a cross-source consistency check (the light-client is single-daemon by design, `LightClientThreatModel.md` §6.2). This ties §5.3 directly to AR-3 and §6.1.

### 5.4 Online (T-Lx) ↔ archive (AR-x) cross-walk

For a reviewer holding both documents, the correspondence between the online per-invocation theorems and the archive theorems:

| Online (`LightClientThreatModel.md`) | Archive (this doc) | Relationship |
|---|---|---|
| T-L1 (genesis-anchored chain identity) | AR-1 clause (b) | Same A3/A4 reduction; operand is `archive.genesis_hash` instead of daemon block-0 reply (AR-L2) |
| T-L2 (head trust via committee sigs) | AR-1 clause (c) + AR-4 | Same A1 per-header `verify_block_sigs`; AR-4 = T-L2's committee-evolution caveat made concrete for the archive |
| §3.3 (header-chain continuity) | AR-1 clause (a) + AR-L4 | Identical `verify_headers` walk; AR-L4 isolates the `from > 0` floating-slice subtlety |
| L-6 (fail-closed exit) | AR-L1 (export) + §2.5 negation form (verify) | Export fail-closes before writing; verify-archive fail-closes on the first inconsistency |
| T-L3 (state-proof correctness) | — (not in archive flow) | §5.2 future composition only (AR-1 + MT-4); headers-only archive does not carry proofs |
| T-L4 / T-L5 (balance/nonce read; sign-and-submit) | — (not in archive flow) | The archive flow does not read state or sign; out of scope (§1) |
| (no online analogue — daemon is live) | **AR-2 (temporal soundness)** | **New**: the archive freezes the daemon's export-time replies, removing cross-invocation variability |
| F-4 (no defense against truncated chain claims) | **AR-3 (range-completeness / `A_stale`)** | Temporal form of F-4; the dominant residual, made precise + paired with auditor obligations |

The table makes the document's scope explicit: AR-1 and AR-4 are the archive-bytes restriction of T-L1 + T-L2 + continuity; AR-2 is genuinely new (it has no online analogue because online there is always a live daemon to re-query); AR-3 is the temporal sharpening of the online F-4 truncation finding. T-L3/T-L4/T-L5 have no archive analogue today because the archive carries headers only.

---

## 6. Known limitations

### 6.1 Range-completeness — `exported_at_height` is a claim (the big one)

Per AR-3: an accepted archive proves the validity of the headers it contains, **not** their completeness over any range. `exported_at_height` is the daemon's self-reported tip at export time, never cryptographically bound. For `from > 0`, the archive's first header is not anchored to the genuine block `from − 1` (it floats). Completeness is an **auditor-side obligation**:

- **C-from-genesis**: export `from == 0` and confirm the tip equals an independently-known head/checkpoint.
- **C-cross-check**: cross-check `exported_at_height` (and, for `from > 0`, the first header's attachment to block `from − 1`) against an independent source.

This is the dominant residual. It is the temporal form of `LightClientThreatModel.md` F-4. An archive must be read as "these specific headers are genuine," not "this is the complete chain over period X," unless an auditor-side completeness condition is met.

### 6.2 Committee-rotation tracking

Per AR-4: the export/verify committee is the static genesis seed `K_0`. Cross-rotation ranges (mid-range `REGISTER` / `DEREGISTER`) cause the export step to **fail closed** (no archive) under the default seed — a safe failure, but it means the archive flow is sound out-of-the-box only for **committee-stable ranges**. Cross-rotation ranges need an operator-supplied extended committee fed identically to `export-headers` and `verify-archive`. Inherited from `LightClientThreatModel.md` §6.5 + F-1. Mitigation path: a future stateful-sync extension tracking committee evolution from the chain, or embedding a committee-rotation log into the archive.

### 6.3 No freshness guarantee

An archive is a **snapshot**. It attests the header sequence up to `exported_at_height` and says **nothing** about chain state after that height. AR-2 guarantees the verdict on the archived bytes is time-invariant, but the *chain* advances past `eah`. An auditor must not infer current chain state from an old archive. (This is the definition of a snapshot, not a defect — but it is recorded so the temporal scope is never over-read.)

### 6.4 Stripped archives are not offline-self-verifying for committee sigs

Per the AR-1 stripped-archive caveat: the **default** archive strips `creator_block_sigs`. Offline, `verify-archive` on a stripped archive can re-establish prev_hash continuity + genesis anchor (AR-1 clauses a, b) but **cannot** re-verify committee signatures (clause c) — the signatures are not in the bytes; clause (c) is inherited as the exporter's `verified_committee_sigs: true` *claim*. For an archive to be a fully self-verifying attestation under `A_archive_forge` (clause c re-checkable by an auditor who does not trust the exporter), it MUST be exported with `--include-committee-sigs`. `verify-archive` SHOULD report which mode it ran in (continuity-only vs full committee-sig re-verification); confirm at `light/verify_archive.cpp` (C3 round 3).

### 6.5 Single-source

The archive came from **one** daemon. The export-time online verification (AR-1's export side; `A_daemon_at_export`) caught signature/continuity fraud — a written archive is one whose contents passed online verification, so fabricated-sig and broken-continuity archives are never produced by an honest export step. But a daemon that *withholds* (censors) specific headers at export time, or under-reports its head, produces a **valid-but-incomplete** archive (this is exactly AR-3's `A_stale`). The light-client is single-daemon by design (`LightClientThreatModel.md` §6.2), so the archive flow inherits the no-multi-peer-redundancy limitation: completeness/freshness against a withholding daemon is the auditor's C-cross-check obligation, not an automatic check. Ties to §6.1.

### 6.6 No transport / auth claims at export time

Export-time RPC is plaintext and unauthenticated by the light-client (`LightClientThreatModel.md` §6.6 + §6.7). This does not affect archive *soundness* (every byte is verified at export), only export-time confidentiality/availability. Operator wraps the export RPC in TLS/tunnel and supplies HMAC out-of-band if the daemon requires it.

---

## 7. Implementation cross-references

Per-theorem citation table for an auditor walking from theorem to code.

| Theorem | Function / artifact | File:location | Role |
|---|---|---|---|
| AR-1 (export side) | `run_export_headers` | `light/export.cpp` | Anchor genesis, page-walk `verify_headers`, per-header `verify_block_sigs`, write archive. Fail-closed: no archive on any verification failure. |
| AR-1 (export side) | `verify_header_sigs` | `light/export.cpp` (anon namespace) | Per-header committee-sig check vs genesis committee; genesis (index 0) skipped (anchored by genesis-hash). |
| AR-1 (offline side) | `verify-archive` flow | `light/verify_archive.cpp` (C3 round 3) | Re-run `verify_headers` + `verify_block_sigs` offline over the archive's `header_json` records against pinned genesis. Spec-level here; cite C3's function names once landed. |
| AR-1 / AR-2 | `verify_headers` | `light/verify.cpp` | prev_hash continuity walk; genesis-hash branch (index 0) / prev-anchor branch (index > 0); empty-anchor skip is the AR-3(ii) root. |
| AR-1 / AR-4 | `verify_block_sigs` | `light/verify.cpp` | `creators ⊆ committee` membership check + Ed25519 threshold verify over `light_compute_block_digest`. |
| AR-1 / AR-2 | `light_compute_block_digest` | `light/verify.cpp` | Byte-for-byte copy of `producer.cpp::compute_block_digest`; binds header content to the signed digest. |
| AR-1 (genesis anchor) | `compute_genesis_hash` | `src/chain/genesis.cpp` | Deterministic canonical genesis-block hash; recomputed locally by both export and verify-archive. |
| AR-4 | `build_genesis_committee` | `light/trustless_read.cpp` | Seeds committee from genesis `initial_creators` only — the static-committee fact AR-4 turns on. |
| AR-4 | `verify_chain_to_head` (committee handling) | `light/trustless_read.cpp` + `light/trustless_read.hpp` (scope note) | Documents the genesis-only committee map + the cross-rotation limitation inherited by the archive flow. |
| AR-3 (`eah` is a claim) | `run_export_headers` head probe | `light/export.cpp` (`probe["height"]` → `exported_at_height`) | Daemon's self-reported tip written verbatim; never cryptographically bound. |
| §5.2 (future composition) | `verify_state_proof` / `merkle_verify` | `light/verify.cpp` / `src/crypto/merkle.cpp` | Not in the current archive flow; the MT-4 half of the future offline state-membership composition. |

Companion proofs:

| Document | Relationship |
|---|---|
| [LightClientThreatModel.md](LightClientThreatModel.md) | Base: T-L1 (genesis anchor) + T-L2 (committee-sig) + §3.3 (continuity) + L-6 (fail-closed). AR-1 = T-L1 + T-L2 applied to archive bytes; AR-4 = T-L2's committee-evolution caveat; §6.1 = temporal form of F-4. |
| [MerkleTreeSoundness.md](MerkleTreeSoundness.md) (C5, round 3) | §5.2 composition opportunity: AR-1 + MT-4 → offline state-membership proofs (if a future `--include-state-proofs` archive ships). Landing in parallel; cite MT-4 once landed. |
| [Safety.md](Safety.md) §7 (B6, R39+2) | FA1 per-block primitive the archive's committee-sig re-verification inherits; "adds no new chain-level invariant" posture. |
| [S033StateRootNamespaceCoverage.md](S033StateRootNamespaceCoverage.md) | The `state_root` binding the §5.2 future composition would anchor against. |

Integration tests:

| Test script | Coverage |
|---|---|
| `tools/test_light_export_headers.sh` | Export side of AR-1 (archive shape, genesis anchor, per-record `verified_committee_sigs`), AR-2 (offline `verify-headers` round-trip on the exported archive — exit 0 with no daemon), AR-3 (wrong-range `--from > head` rejected, exit non-zero + diagnostic), and the stripped-vs-`--include-committee-sigs` size/content distinction of §6.4. Shipped with B3 (commit `1f42592`). |
| `tools/test_light_verify_archive.sh` | Offline side of AR-1 + AR-2 + the AR-3 negative cases (forged-sig archive → reject; tampered prev_hash → reject; wrong-genesis → reject; stale/truncated archive accepted-but-flagged-incomplete). Authored by sibling C3, round 3 (landing in parallel with this proof). |

---

## 8. Status

- **Spec.** Complete (this document).
- **Implementation — export-headers.** Shipped (sibling B3, commit `1f42592`). `light/export.cpp` + `light/export.hpp`; test `tools/test_light_export_headers.sh`.
- **Implementation — verify-archive.** Shipping this round (sibling C3, round 3), in parallel with this proof. `light/verify_archive.cpp`; test `tools/test_light_verify_archive.sh`. The proof cites verify-archive at the spec level (genesis anchor + prev_hash continuity + committee-sig re-verify, reusing the §3 primitives offline); function-name citations to be tightened once C3's code lands and is threaded.
- **Proof.** Complete: AR-1 (archive integrity = header-sequence attestation), AR-2 (offline re-verifiability / temporal soundness), AR-3 (range-completeness caveat / `A_stale` — the dominant residual), AR-4 (committee-continuity / static genesis committee).
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA), A3 (SHA-256 collision resistance), A4 (SHA-256 preimage resistance, in AR-1 clause-b Case 2). No new primitive.
- **Adversary model.** `A_archive_forge` (forged archive — defeated by AR-1), `A_stale` (stale/truncated archive — *bounded* by AR-3, not defeated; auditor-side completeness obligation), `A_daemon_at_export` (malicious daemon at export — defeated by AR-1's export side + fail-closed exit). Out of scope: `A_crypto`, `A_local` (incl. post-verification tampering), `A_genesis`.
- **Composes with.** `LightClientThreatModel.md` (T-L1 + T-L2 + §3.3 + L-6 — AR-1 is their archive-bytes restriction; AR-4 = T-L2's committee caveat); `Safety.md` §7 (FA1 per-block primitive); `MerkleTreeSoundness.md` MT-4 (§5.2 future composition opportunity only — not implemented); `S033StateRootNamespaceCoverage.md` (state_root binding for the future composition).
- **AR-3 range-completeness verdict.** The archive proves the **validity of the headers it contains, not their completeness** over any range. `exported_at_height` is an unverified claim by the (possibly malicious) exporter. For `from > 0`, the slice floats (its first `prev_hash` is checked against an empty anchor, so it is not anchored to the genuine block `from − 1`). Completeness is recoverable only via **C-from-genesis** (`from == 0` + independently-known head) or **C-cross-check** (independent verification of `exported_at_height` and, for `from > 0`, the first header's attachment). This is the dominant residual and is documented honestly rather than overclaimed.
- **AR-4 committee-rotation finding.** The export/verify committee is the **static genesis seed** `K_0`; the archive carries each block's `creators` but **not** the pubkeys of post-genesis-registered signers. Under the default seed, the export step **fails closed** on any cross-rotation range (no under-verified archive is ever produced — a safe failure mode). The archive flow is therefore **sound out-of-the-box for committee-stable ranges**; cross-rotation ranges require an operator-supplied extended committee fed identically to both `export-headers` and `verify-archive`. Inherited from `LightClientThreatModel.md` §6.5 + F-1; closed by a future stateful-sync / committee-rotation-log extension.
- **Concrete-security bound.** AR-1: `Pr[A_archive_forge wins] ≤ count · K · 2⁻¹²⁸ + 2⁻¹²⁸`; for `count ≤ 2⁴⁰`, `K ≤ 16`, `≤ 2⁻⁸⁴`. AR-2 is information-theoretic (purity → time-invariance), no probabilistic bound. AR-3 / `A_stale` is not a cryptographic break — the bound is "1" against a withholding/under-reporting daemon absent the auditor's completeness obligation; this is a *scope* limitation, not a soundness failure. Under Grover (PQ), AR-1's `2⁻¹²⁸` terms degrade to `2⁻⁶⁴` (operationally secure; PQ-signature migration is the long-term path per `LightClientThreatModel.md` §9).
