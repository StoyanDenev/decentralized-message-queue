# OfflineStateBundleSoundness — self-contained OFFLINE state-proof bundle (`determ-light export-state-bundle` / `verify-state-bundle`)

This document proves the soundness of the `determ-light` **state-proof bundle**: a producer/verifier pair (`light/verify_state_bundle.{hpp,cpp}`; subcommands at `light/main.cpp:2681` / `:2708`, dispatched `:6855-6856`) that lets a holder prove

> *"key `K` in namespace `NS` had value `V` at anchor height `H`"*

to a third party who re-verifies it with **NO daemon, NO RPC, NO network**, against the operator's own pinned `--genesis`. It is the **state-side analog of `verify-archive`** (`LightClientArchiveSoundness.md` AR-1..AR-4 — which covers HEADERS) and the **offline, file-based dual of `verify-state-root`** (`StateRootAnchorSoundness.md` SR-1..SR-5 — which establishes a committee-verified `state_root` over a live daemon). Where `verify-state-root` reads from RPC, the bundle carries the same bytes in a file and the verifier reads them offline.

- **`export-state-bundle`** (`light/verify_state_bundle.cpp:80`) is the **ONLINE producer** (needs a daemon). It fetches the `state_proof` for `(NS, K)`, the FULL anchor block at `proof_height-1` (the `"block"` RPC, so `block_hash` is recomputable offline), and the committee-signed SUCCESSOR header at `proof_height`; it then **re-verifies the binding via the existing `committee_bound_state_root` helper BEFORE writing** (`:146-154`), so an unbindable / chain-head bundle is never produced. For `ns=="a"` it also stores the account cleartext (`:170-181`). It writes a bundle JSON of schema `determ-light-state-bundle/1`.
- **`verify-state-bundle`** (`light/verify_state_bundle.cpp:227`) is the **OFFLINE verifier** (no `RpcClient`). It reproduces `committee_bound_state_root`'s logic reading from the bundle bytes instead of live RPC, plus a leading **key-binding** gate. Exit codes: **VERIFIED → 0**, **UNVERIFIABLE → 3**, **args/IO error → 1** (`light/verify_state_bundle.hpp:90-94`).

**The load-bearing binding (S-042), stated precisely.** `state_root` is **NOT** part of the committee-signed `compute_block_digest` (what each member Ed25519-signs); it lives in `Block::signing_bytes()` → `block_hash = compute_hash()` (when non-zero, the S-033 zero-skip shim, `src/chain/block.cpp:336-350`). The committee signs the **successor** block, whose digest binds its `prev_hash = block_hash(anchor)`. So a bundle carrying the FULL anchor block + the committee-signed successor header lets the verifier recompute `compute_hash(anchor)` and require it `== successor.prev_hash`, transitively binding the anchor's `state_root`. This is exactly `StateRootAnchorSoundness.md` §3.3's transitive-forward link and `trustless_read.cpp::committee_bound_state_root` (`:335-437`) — but evaluated over bundle bytes. The state-root assurance is the SR-1 interior-regime fact, not a new construction.

**Canonical assumption labels.** Per `Preliminaries.md §2.0`: **A1** = Ed25519 EUF-CMA (`§2.2`), **A2** = SHA-256 collision resistance (`§2.1`). `verify-state-bundle` reduces to **A1** (successor committee sigs) + **A2** (the anchor `block_hash` recompute, the genesis pin, the Merkle inclusion verify, the key-binding equality, and the `ns=="a"` value_hash recompute) only; A3 and A4 are not used by this path.

**Companion documents.**
- `StateRootAnchorSoundness.md` (SR-1..SR-5; the §3.3 transitive-forward binding; `committee_bound_state_root` at `trustless_read.cpp:335-437`) — the **online sibling**. The bundle's anchor binding (OSB-3) is SR-1's interior-regime statement evaluated over bundle bytes; the bundle's "head not bundleable" disposition is SR-1's head-regime fail-closed boundary (`StateRootAnchorSoundness.md §6.3`) moved to **export time**.
- `LightVerifyChainFileSoundness.md` (VCF-1..VCF-E, **VCF-S** the strip-hole lemma) — the **structural sibling**: an OFFLINE, file-based, `--genesis`-anchored verifier whose threat model is an attacker who edits the input file on disk, not (only) a lying daemon over the wire. The bundle inherits that posture; OSB-1 (the key-binding gate) is the bundle's analog of VCF-S — a forge the file-on-disk adversary enables that the gate closes.
- `LightClientArchiveSoundness.md` (AR-1..AR-4) — the **HEADER-side offline analog**. `verify-archive` re-verifies header bytes offline against `--genesis`; the bundle re-verifies a STATE leaf offline against `--genesis`. Both seed the committee from `--genesis` only (the static-`K_0` caveat, OSB-F4 ≡ AR-4).
- `MerkleTreeSoundness.md` (MT-4 inclusion-proof soundness; **S-040** `leaf_count` bound into the root via the root-wrapper) — the inclusion-proof primitive OSB-4 consumes via `verify_state_proof` → `merkle_verify`.
- `LightClientThreatModel.md` (T-L1 genesis-anchored identity, T-L2 committee-sig trust, T-L3 state-proof correctness, T-L4 balance/nonce composition, **L-2** `light_compute_block_digest` byte-equivalence, **L-6** fail-closed exit) — the online pipeline whose pieces this offline composite re-uses.
- `S033StateRootNamespaceCoverage.md` (T-1..T-5 — the 10-namespace coverage of the anchored root; the producer-side population) + `docs/SECURITY.md §S-033 / §S-038 / §S-042`.
- `Preliminaries.md` (F0) §2.0 (assumption labels), §2.1 (A2), §2.2 (A1).

---

## 0. Implementation status

**SHIPPED** (commit `8904d33`). `light/verify_state_bundle.{hpp,cpp}` + the two subcommands `cmd_export_state_bundle` (`light/main.cpp:2681`) / `cmd_verify_state_bundle` (`:2708`), dispatched on `export-state-bundle` / `verify-state-bundle` (`light/main.cpp:6855-6856`), help text at `light/main.cpp:307` / `:314`. Regression: `tools/test_light_state_bundle.sh`.

Nothing in `verify_state_bundle.cpp` re-implements a Merkle / sig / hash / digest primitive (the file's header comment, `:21-27`, records this). It composes the existing in-tree primitives:

- `load_genesis` / `build_genesis_committee` / `committee_bound_state_root` (`light/trustless_read.cpp`),
- `compute_genesis_hash` (`src/chain/genesis`),
- `verify_block_sigs` / `verify_state_proof` (`light/verify.cpp`),
- `Block::from_json` / `Block::compute_hash` (`src/chain/block`).

The **export** side never duplicates the binding logic: it calls the same `committee_bound_state_root` the online readers use and refuses to write unless its committee-bound root equals the proof's claimed root (`light/verify_state_bundle.cpp:146-154`). The **verify** side mirrors that helper reading from the bundle, plus a leading key-binding gate (§2.1 / OSB-1) that the online helper does not need (online, the `(ns,key)` come from the operator's own argv; in a bundle they are attacker-supplied fields next to the proof).

---

## 1. Scope

### 1.1 The bundle envelope (schema `determ-light-state-bundle/1`)

Read off `verify_state_bundle.hpp:31-46` + the assembly at `verify_state_bundle.cpp:157-181`:

```
{
  "schema":            "determ-light-state-bundle/1",
  "genesis_hash":      "<64-hex>",          // chain-identity pin (operator's own recompute)
  "namespace":         "<ns>",              // what is proven, e.g. "a"
  "key":               "<key>",             // e.g. "alice"
  "anchor_index":      <H-1>,               // block whose state_root is proven
  "anchor_block":      { ...FULL block JSON... },   // from the `block` RPC (unstripped)
  "successor_header":  { ...header JSON... },       // committee-signed block anchor_index+1
  "state_proof":       { ...state_proof RPC reply... },
  "account_cleartext": {"balance":N,"next_nonce":N} // OPTIONAL, ns=="a"
}
```

### 1.2 The verify control flow (`light/verify_state_bundle.cpp:227-520`), the authoritative gate order

1. **Envelope parse + schema/shape validation (`:228-285`).** Unreadable `--in` → exit 1 (IO). Non-JSON / non-object / wrong-or-missing `schema` / malformed `genesis_hash` (not 64-hex) / missing `anchor_block` / `successor_header` / `state_proof` objects → UNVERIFIABLE (exit 3).
2. **(1b) KEY-BINDING gate (`:301-352`), runs FIRST among the cryptographic checks, fail-fast.** Reconstruct the canonical `key_bytes` from the DISPLAYED `(ns,key)` — byte-identical to the daemon's `rpc_state_proof` encoding (`src/node/node.cpp:3389-3432`) — and require it `== state_proof.key_bytes` (case-insensitive). Mismatch → UNVERIFIABLE.
3. **(2) CHAIN-IDENTITY PIN (`:354-369`).** `compute_genesis_hash(--genesis) == bundle.genesis_hash` (case-insensitive). Mismatch → UNVERIFIABLE. A bad `--genesis` path makes `load_genesis` throw → caught → exit 1 (args/IO).
4. **(3) Genesis-seeded committee (`:373-374`).** `build_committee_json(build_genesis_committee(genesis))` — derived from the verifier's OWN `--genesis`, NOT a bundle field.
5. **(4) Recompute the anchor `block_hash` (`:377-386`).** `Block::from_json(anchor_block).compute_hash()`. Malformed anchor → UNVERIFIABLE.
6. **(5) Verify the SUCCESSOR header's committee sigs (`:389-399`).** `verify_block_sigs(successor, committee, bft=false)`, BFT-fallback on failure. Sub-quorum / wrong key / size mismatch → UNVERIFIABLE.
7. **(6) THE BINDING (`:406-415`).** `successor.prev_hash == recomputed anchor block_hash`. Mismatch → UNVERIFIABLE.
8. **(7) Root equality (`:419-433`).** Anchor `state_root` non-zero (`:420-425`) AND `anchor.state_root == state_proof.state_root` (`:428-432`). Else → UNVERIFIABLE.
9. **(8) Merkle-verify the proof against the BOUND root (`:437-442`).** `verify_state_proof(state_proof, anchor_root_hex)` — against the anchor's recomputed/bound root, NOT the proof's self-claimed root.
10. **(9) `ns=="a"` value_hash recompute (`:446-479`).** If `account_cleartext` present, `SHA256(u64_be(balance) ‖ u64_be(next_nonce)) == state_proof.value_hash`. Mismatch → UNVERIFIABLE.
11. **(10) SUCCESS (`:481-513`).** Emit VERIFIED + the reported `(ns,key,value)` at `anchor_index`; exit 0.

### 1.3 Out of scope (the verifier's coverage boundary)

- **Committee provenance / committee rotation.** The committee is seeded from the verifier's `--genesis` (`build_genesis_committee`); a successor signed by a creator outside the genesis committee `K_0` fails closed. Mid-chain `REGISTER` rotation is out of scope, **mirroring `trustless_read.hpp`** (OSB-F4 ≡ `LightClientArchiveSoundness.md` AR-4 / `StateRootAnchorSoundness.md §6.2`). The bundle proves the leaf was committed in a chain whose `K_0` (from `--genesis`) signed the successor; it does not separately re-derive the height-correct committee.
- **The chain head is not bundleable.** The head has no committee-signed successor, so export REFUSES to bundle it (`committee_bound_state_root` throws at the missing-successor fetch; export surfaces a "retry once the chain advances" diagnostic, `verify_state_bundle.cpp:131-139`). This is `StateRootAnchorSoundness.md §6.3`'s head-regime fail-closed boundary applied at export time (OSB-F2).
- **Pre-S-033 anchors.** An anchor with a zero/unpopulated `state_root` is rejected at gate (7) (`verify_state_bundle.cpp:420-425`) — there is no committed state to anchor (OSB-F3; the offline analog of `StateRootAnchorSoundness.md` SR-5).
- **Liveness / completeness.** A VERIFIED bundle attests one `(ns,key,value)` at one `anchor_index`. It does not assert the value is current, that the key is the only entry, or anything about other heights. It is a verified point-in-time snapshot, not a trajectory (contrast `account-history` / `AccountHistorySoundness.md` AH-4).
- **Semantic validity.** A VERIFIED bundle does not assert the transactions that produced the state were individually valid, nor that the committee in `K_0` is honest — only that the leaf is committee-attested under the binding.

---

## 2. Construction specification

Read directly off `light/verify_state_bundle.cpp`.

### 2.1 The KEY-BINDING gate — bind the DISPLAYED key to the PROVEN leaf (`:301-352`)

The Merkle proof selects its leaf by `state_proof.key_bytes`; the human-readable `(namespace,key)` is merely echoed in the VERIFIED output. Without binding them, an attacker exports an HONEST bundle for key `"bob"` and edits ONLY `bundle["key"] → "alice"`: every cryptographic leg still passes (bob's real leaf + value + binding), but the verifier would report `(alice, bob's balance)` — a pair the committee never attested. The gate reconstructs the canonical `key_bytes` from the displayed `(ns,key)` and requires equality with `state_proof.key_bytes`. The reconstruction is **byte-identical to the daemon's `rpc_state_proof` encoding** (`src/node/node.cpp:3389-3432`) and `build_state_leaves` (`src/chain/chain.cpp`):

| `ns` | canonical `key_bytes` | verifier code | daemon code |
|---|---|---|---|
| `a` `s` `r` `d` `b` `k` | `"<ns>:" + key` (raw key string bytes) | `:303-307` | `node.cpp:3390-3398` |
| `c` | `"k:" + "c:" + key` | `:308-313` | `node.cpp:3399-3405` |
| `i` `m` `p` | `"<ns>:" + from_hex(key)`, exact width `i=8+32`, `m=4`, `p=8+4` | `:314-336` | `node.cpp:3406-3429` |
| else | unsupported → UNVERIFIABLE | `:337-340` | `node.cpp:3430-3431` |

For the composite namespaces the verifier hex-decodes `key` and enforces the exact body width (`:326-333`) so a malformed key cannot alias a different leaf — the same width check the daemon performs (`node.cpp:3417-3425`). The comparison is case-insensitive on the hex (`:344`). This gate runs FIRST among the cryptographic checks (before the genesis-load gate) and is a pure structural string comparison, so it fail-fasts and is order-independent.

### 2.2 The chain-identity pin (`:354-369`)

`compute_genesis_hash(--genesis)` is recomputed LOCALLY and byte-compared (case-insensitive) against `bundle.genesis_hash`. This is the **sole trust anchor at verify time** (the committee is derived from `--genesis`). It is the one leg that calls `compute_genesis_hash` (the known cross-platform genesis-determinism edge), so it is the SKIP leg on the Windows box; the binding legs below (§2.3-§2.5) do NOT call it and ARE testable offline there (anchored to the file's own block-0 hash). A wrong `--genesis` for the bundle's chain → UNVERIFIABLE; an unreadable/malformed `--genesis` → `load_genesis` throws → exit 1.

### 2.3 The successor committee-sig verify + THE binding (`:389-415`)

`verify_block_sigs(successor, committee, bft)` recomputes `light_compute_block_digest(successor)` internally (`light/verify.cpp:283`) and Ed25519-verifies the committee quorum over it (`LightClientThreatModel.md` L-2 byte-equivalence; MD `K` / `--bft` `⌈2K/3⌉`). Then the load-bearing equality:

```cpp
std::string succ_prev = successor_header.value("prev_hash", "");
if (succ_prev != recomputed_hex)  // recomputed_hex = to_hex(anchor.compute_hash())
    UNVERIFIABLE("successor prev_hash != recomputed anchor block_hash — bundle forged …");
```

`prev_hash` is the second field of `compute_block_digest` (`src/node/producer.cpp:608-620`, `prev_hash` appended at `:611`; mirrored `light/verify.cpp:57-79`, `prev_hash` at `:60`), so it is INSIDE the byte string the committee signed. A daemon/producer that swapped the anchor's `state_root` FIELD (which is in `signing_bytes → block_hash` per `block.cpp:336-350`, NOT in the committee digest) produces a recomputed `block_hash` that no longer matches the `prev_hash` the committee signed over.

### 2.4 Root equality (`:419-433`)

```cpp
Hash zero{};
if (anchor.state_root == zero) UNVERIFIABLE("zero/unpopulated state_root (pre-S-033) …");
if (to_lower(proof_root) != to_lower(anchor_root_hex)) UNVERIFIABLE("proof.state_root != bound anchor.state_root");
```

Gate (8) then verifies the proof against `anchor_root_hex` (the recomputed/bound anchor root), so the only root the inclusion proof is ever checked against is the committee-bound one — closing the self-anchoring attack (a daemon attaching a fabricated `state_proof.state_root` to make its tampered proof verify against itself).

### 2.5 Merkle verify + `ns=="a"` value_hash recompute (`:437-479`)

`verify_state_proof(state_proof, anchor_root_hex)` delegates to `crypto::merkle_verify` (`MerkleTreeSoundness.md` MT-4; `leaf_count` bound into the root via the S-040 root-wrapper). For `ns=="a"` with `account_cleartext` present, the verifier recomputes the leaf value_hash exactly as `build_state_leaves` does (`src/chain/chain.cpp:285-290`):

```cpp
determ::crypto::SHA256Builder b;
b.append(balance);      // append(uint64_t) is big-endian (src/crypto/sha256.cpp:30-34)
b.append(next_nonce);
Hash computed_vh = b.finalize();           // == SHA256(u64_be(balance) ‖ u64_be(next_nonce))
if (computed_vh != proof_vh) UNVERIFIABLE("cleartext does not match the committed leaf");
```

so a daemon that served honest proof+leaf but lied about the cleartext balance/nonce is caught (the offline analog of `LightClientThreatModel.md` L-4 / T-L4's value-hash cross-check). For namespaces other than `a` the value semantics are not decoded here; the binding to the leaf's `value_hash` is via the Merkle proof (gate 8) + the key-binding gate (gate 1b), and the reported value is the proof's `value_hash` (`:489`).

---

## 3. Soundness theorems

Throughout, let a bundle present fields `(ns, key, anchor_index, anchor_block, successor_header, state_proof, genesis_hash[, account_cleartext])`; let `R_T` be the genuine committee-committed `state_root` of the operator's `--genesis`-pinned chain at `anchor_index`, and `(K_T, V_T)` the genuine committed `(key_bytes, value_hash)` leaf the proof should select. `K_0` is the genesis-seeded committee (`build_genesis_committee`). The adversary `A_bundle` is a **malicious bundle producer**: a PPT party that crafts arbitrary bundle bytes (it may have observed honest bundles, run a daemon, or edited an honest bundle on disk). Its goal is to make `verify-state-bundle` exit 0 (VERIFIED) reporting a `(ns, key, value)` at `anchor_index` that the committee never attested for the operator's chain. Bounds follow `Preliminaries.md §2.0` (A1, A2 ≈ `2⁻¹²⁸`).

### 3.0 OSB-MAIN (offline state-bundle soundness)

**Statement.** For any bundle that `verify-state-bundle` accepts (exit 0) against an honest operator's `--genesis`, the reported `(ns, key, value)` at `anchor_index` is **committee-attested** on the `--genesis`-pinned chain: no PPT `A_bundle` can make the command report a value the committee never signed, except with probability `≤ K·2⁻¹²⁸ + c·2⁻¹²⁸` for a small constant `c` (the collision terms of the genesis pin, the anchor `block_hash` recompute, the key-binding, the root equality, and the value_hash recompute), under `{A1, A2}`.

**Proof (the gate chain).** A VERIFIED verdict requires ALL gates of §1.2 to pass. Compose:

- **Genesis pin (OSB-2 §3.2).** Gate (2) forces `compute_genesis_hash(--genesis) == bundle.genesis_hash`; under A2 the bundle's claimed chain identity equals the operator's pinned one, so the committee `K_0` the verifier derives (gate 3) is the operator's chain's genesis committee.
- **Successor binding ⇒ `state_root` committee-attested (OSB-3 §3.3).** Gates (4)+(5)+(6) recompute `compute_hash(anchor)` and require it `== successor.prev_hash` for a successor whose committee sigs verify against `K_0`. By the S-042 / SR-1 transitive-forward argument (`StateRootAnchorSoundness.md §3.3`, SR-L2 + SR-L3), forging an anchor whose `block_hash` the committee-signed successor's `prev_hash` accepts requires either an A2 `signing_bytes` collision at the anchor or an A1 forgery of `K`-of-`K_0` successor signatures over a different `digest`. So the recomputed anchor `block_hash`, and hence (via `block.cpp:336-350`) the anchor's `state_root`, is committee-attested up to `K·2⁻¹²⁸ + 2⁻¹²⁸`. Gate (7) pins the proof's root to that attested anchor `state_root` (`= R_T` up to A2).
- **Merkle verify ⇒ leaf membership (OSB-4 §3.4).** Gate (8) `verify_state_proof(state_proof, R_T)` proves `(state_proof.key_bytes, state_proof.value_hash)` is a member of the tree rooted at `R_T` (MT-4, `≤ log₂(leaf_count)·2⁻¹²⁸`; `leaf_count` itself bound by the S-040 root-wrapper).
- **Key-binding ⇒ the reported key is the proven leaf (OSB-1 §3.1).** Gate (1b) forces `state_proof.key_bytes == canonical(ns, key)` (the daemon's exact encoding). So the leaf proved member of `R_T` is the leaf for the DISPLAYED `(ns, key)`, not some other leaf relabelled (the forge §3.1 records, closed).
- **Value (OSB-5 §3.5).** The reported value is the committed `value_hash` (gate 8); for `ns=="a"` with cleartext, gate (9) additionally pins the human-readable `(balance, next_nonce)` to that `value_hash` under A2.

By the union bound, the probability that VERIFIED is emitted yet the reported `(ns, key, value)` is not the committee-attested leaf at `anchor_index` is `≤ K·2⁻¹²⁸` (A1, successor sigs) `+ O(1)·2⁻¹²⁸` (A2 collisions across the five hash-equality gates), i.e. the OSB-MAIN bound. ∎

The per-gate theorems below establish each conjunct.

### 3.1 OSB-1 (key-binding — the displayed key IS the proven leaf; the strip-hole's state-side analog)

**Statement.** A VERIFIED verdict implies `state_proof.key_bytes` is the canonical daemon-side encoding of the DISPLAYED `(ns, key)` (`verify_state_bundle.cpp:301-352`, byte-identical to `node.cpp:3389-3432`). Equivalently: no `A_bundle` can make the verifier report `(ns, key)` while the Merkle proof actually selects a DIFFERENT committed leaf — the relabel forge is closed.

**The forge this gate closes (found by the adversarial verifier; recorded).** `A_bundle` takes an HONEST, fully-bindable bundle for key `"bob"` (real `bob` leaf, real proof, real successor binding) and edits ONLY `bundle["key"] → "alice"`. Without gate (1b), every cryptographic leg still passes — the proof, the binding, the value_hash all concern `bob`'s genuine leaf — and the verifier would print `VERIFIED … (alice, bob's balance)`, a pair the committee never attested. This is the state-side analog of `LightVerifyChainFileSoundness.md` **VCF-S** (the strip-hole): a file-on-disk adversary exploits a field the cryptographic gates do not themselves constrain.

**Proof.** Gate (1b) reconstructs `expect_key` from `(ns, key)` via the case split of §2.1 (`:303-340`) and requires `to_lower(state_proof.key_bytes) == to_lower(to_hex(expect_key))` (`:342-351`); a mismatch is UNVERIFIABLE. The reconstruction is byte-identical to the daemon's `rpc_state_proof` (`node.cpp:3389-3432`) and to `build_state_leaves`'s leaf-key construction, so `expect_key == K_T` exactly when the displayed `(ns,key)` is the genuine key of the leaf the chain committed. For the verifier to report a `(ns, key)` whose `expect_key ≠` the leaf the proof selects, the attacker would need `state_proof.key_bytes` to equal BOTH `expect_key` (gate 1b) AND select a different committed leaf under `R_T` (gate 8) — but `merkle_verify` selects the leaf by `key_bytes` (it is the leaf preimage), so the two are the same leaf. No relabel survives. The composite-key width check (`:326-333`, mirroring `node.cpp:3417-3425`) additionally prevents a malformed `i/m/p` key from hex-aliasing a different-width leaf. ∎

### 3.2 OSB-2 (chain-identity pin — committee provenance from `--genesis`)

**Statement.** A VERIFIED verdict implies `compute_genesis_hash(--genesis) == bundle.genesis_hash` (`:362`, under A2 the unique commitment to the operator's pinned genesis), so the committee `K_0` the verifier derives (gate 3) is the operator's chain's genesis committee — not a committee chosen by `A_bundle`.

**Proof.** Gate (2) recomputes `compute_genesis_hash(genesis_O)` LOCALLY from `--genesis` and byte-compares (case-insensitive) against `bundle.genesis_hash`; mismatch is UNVERIFIABLE (`:362-369`). For `A_bundle` to present a `genesis_hash` equal to the operator's recompute while committing to a DIFFERENT genesis (and hence a different committee it controls), its genesis encoding must SHA-256-collide with the operator's — an A2 break (`≤ 2⁻¹²⁸`). Crucially, the committee is built from `build_genesis_committee(genesis)` over the verifier's OWN `--genesis` (`:373-374`), NOT from any bundle field — so `A_bundle` cannot inject an attacker-chosen committee even by populating the bundle with one; there is no committee field in the schema for it to populate. (This is the §3.6 forge "attacker-chosen committee", defeated structurally.) ∎

**Note on the Windows skip.** This is the only gate that calls `compute_genesis_hash` (the cross-platform genesis-determinism edge), so it SKIPs on this box. The binding legs (OSB-3..OSB-5) do not call it and ARE testable offline against the file's own block-0 hash (consistent with the project's light-verifier testing note). The SKIP does not weaken OSB-MAIN on a platform where `compute_genesis_hash` is deterministic; on the skip platform the committee provenance reduces to "the committee is whatever `--genesis` yields", which is exactly the OSB-F4 caveat already declared.

### 3.3 OSB-3 (successor binding ⇒ the anchor's `state_root` is committee-attested)

**Statement.** A VERIFIED verdict implies the recomputed `compute_hash(anchor)` equals the `prev_hash` of a successor header whose committee sigs verify against `K_0`; therefore the anchor's `state_root` (`∈ signing_bytes ∈ block_hash`, when non-zero) is committee-attested, `= R_T` except with probability `≤ K·2⁻¹²⁸ + 2⁻¹²⁸`.

**Proof.** Gates (4)+(5)+(6) require: (4) `recomputed = Block::from_json(anchor_block).compute_hash()` (`:385`); (5) `verify_block_sigs(successor, K_0, bft)` ok (`:389-399`); (6) `successor.prev_hash == recomputed` (`:406-415`). This is exactly the in-tree `committee_bound_state_root` (`trustless_read.cpp:335-437`) evaluated over bundle bytes — and the export side already required `committee_bound_state_root(rpc, K_0, anchor_index) == proof.state_root` before writing (`verify_state_bundle.cpp:146-154`), so a writeable bundle is bindable by construction. Apply the SR-1 case split (`StateRootAnchorSoundness.md §4.1`, SR-L2 + SR-L3):

- **Case (i): `A_bundle` kept the recomputed anchor `block_hash` equal to the genuine `block_hash_T`.** Then the served anchor (with whatever `state_root` it carries) must hash to `block_hash_T`. If its `state_root ≠ R_T`, its `signing_bytes` differ from the genuine ones (the `state_root` append at `block.cpp:347-348` differs), so equal hashes are a SHA-256 collision (A2, `≤ 2⁻¹²⁸`).
- **Case (ii): `A_bundle` changed the recomputed anchor `block_hash`.** Then gate (6) requires the SERVED `successor.prev_hash` to equal the new `block_hash`. But `prev_hash` is inside `digest(successor)` (`src/node/producer.cpp:611`; second field of `compute_block_digest`), and gate (5) verifies `K`-of-`K_0` signatures over that digest. The genuine committee signed `prev_hash = block_hash_T`; presenting a successor with a different `prev_hash` that still verifies requires forging each of `K` distinct members' Ed25519 signatures over the altered digest — A1, `≤ K·2⁻¹²⁸` by union bound. (This is `T-L2`'s reduction applied to the successor.)

The two cases are exhaustive, so the recomputed anchor `block_hash` — and via `block.cpp:336-350` the anchor's non-zero `state_root` — equals the genuine `R_T` except with probability `≤ K·2⁻¹²⁸ + 2⁻¹²⁸`. Gate (7) then forces `state_proof.state_root == anchor.state_root` (`:428-432`), so the root the inclusion proof is checked against (gate 8) is `R_T`, not a daemon-attached value. The non-zero guard at gate (7) (`:420-425`) rejects pre-S-033 anchors (OSB-F3). The state-root assurance here is **not a new construction**; it is SR-1's interior-regime statement read from the bundle (the swapped-`state_root` forge of §3.6 is its negation, defeated). ∎

### 3.4 OSB-4 (Merkle inclusion against the BOUND root)

**Statement.** A VERIFIED verdict implies `(state_proof.key_bytes, state_proof.value_hash)` is a member of the Merkle tree rooted at the committee-bound `R_T` (gate 8, `:437-442`), except with probability `≤ log₂(leaf_count)·2⁻¹²⁸` (A2).

**Proof.** Gate (8) calls `verify_state_proof(state_proof, anchor_root_hex)` where `anchor_root_hex = to_hex(anchor.state_root) = R_T` (OSB-3). `verify_state_proof` delegates to `crypto::merkle_verify`; by `MerkleTreeSoundness.md` MT-4, a passing verification implies the `(key_bytes, value_hash)` leaf is a genuine member under that root except with the stated A2 bound, and the S-040 root-wrapper binds `leaf_count` into the committed root so a forged count is rejected. Critically the proof is checked against the BOUND root (OSB-3), not the proof's self-claimed `state_proof.state_root` — gate (7) already forced them equal, so the self-anchoring attack (a fabricated `state_proof.state_root` matching a fabricated proof) cannot reach gate 8 with a root different from `R_T`. ∎

### 3.5 OSB-5 (value faithfulness)

**Statement.** The reported value at `anchor_index` is the committee-committed value: it is the proof's `value_hash` (a member of `R_T`, OSB-4); for `ns=="a"` with `account_cleartext`, the human-readable `(balance, next_nonce)` additionally hashes to that committed `value_hash` (gate 9, `:446-479`), so it equals the genuine committed account state except with probability `≤ 2⁻¹²⁸` (A2).

**Proof.** The VERIFIED output reports `state_proof.value_hash` (`:489`/`:503-504`), which OSB-4 binds to `R_T`. For `ns=="a"` with cleartext, gate (9) recomputes `SHA256(u64_be(balance) ‖ u64_be(next_nonce))` (`:455-458`, `append(uint64_t)` big-endian per `sha256.cpp:30-34`) — byte-identical to `build_state_leaves`'s account leaf (`chain.cpp:285-290`) — and requires equality with `state_proof.value_hash` (`:470-478`); mismatch is UNVERIFIABLE. So for `A_bundle` to report a `(balance, next_nonce)` other than the committed one while passing, two distinct `(balance, next_nonce)` pairs must hash to the same `value_hash` — an A2 collision. This is the offline analog of `LightClientThreatModel.md` L-4 / T-L4's cleartext-vs-`value_hash` cross-check (the §3.6 "forged cleartext" forge, defeated). For namespaces other than `a` the reported value is the committed `value_hash` itself (no cleartext decode here), still bound to `R_T` by OSB-4 + OSB-1. ∎

### 3.6 The worked attack table (five forges the adversarial verifier tried + the one it FOUND)

Every row is an `A_bundle` strategy against `verify-state-bundle`; the rightmost column is the gate that defeats it and the assumption it reduces to.

| # | Forge attempt | Defeated by | Reduces to |
|---|---|---|---|
| 1 | **Anchor `state_root` swap** — serve an honest bundle but flip `anchor_block.state_root` to a different value | Gate (6): the recomputed `compute_hash(anchor)` no longer equals the committee-signed `successor.prev_hash` → UNVERIFIABLE (OSB-3 Case ii). | A2 (collide anchor `block_hash`) ∨ A1 (forge successor sigs) |
| 2 | **Proof swap / self-anchoring** — attach a fabricated `state_proof` (with its own `state_root`) for a value not under `R_T` | Gate (7) forces `state_proof.state_root == anchor.state_root`; gate (8) checks against the BOUND root, not the proof's self-claim → the fabricated proof fails MT-4 (OSB-4). | A2 (MT-4 / collision) |
| 3 | **Forged committee sigs** — present a successor with attacker signatures over the altered digest | Gate (5) `verify_block_sigs` against `K_0` rejects (OSB-3 Case ii). | A1 (Ed25519 EUF-CMA) |
| 4 | **Attacker-chosen committee** — try to make the verifier use a committee the attacker controls | Structural: the committee is built from the verifier's `--genesis` (`:373-374`), not any bundle field; there is no committee field to populate (OSB-2). | A2 (genesis pin) + construction |
| 5 | **Forged cleartext** — serve honest proof+leaf for `ns=="a"` but lie about `(balance, next_nonce)` in `account_cleartext` | Gate (9): recomputed `SHA256(u64_be(balance) ‖ u64_be(next_nonce))` ≠ committed `value_hash` → UNVERIFIABLE (OSB-5). | A2 (value_hash collision) |
| **6 (FOUND)** | **Unbound displayed key (relabel)** — export an honest bundle for key `"bob"`, edit ONLY `bundle["key"] → "alice"`; report `(alice, bob's balance)` | **Gate (1b) — the KEY-BINDING gate, NOW CLOSED**: `canonical("a","alice") ≠ state_proof.key_bytes` (which encodes `"a:bob"`) → UNVERIFIABLE before any crypto gate (OSB-1). | A2 (key encoding equality) |

Forge #6 is the genuine gap the adversarial verifier discovered: forges 1-5 were already defeated by the binding legs (which mirror `committee_bound_state_root`), but the displayed `(ns,key)` are bundle fields the cryptographic gates do not themselves constrain — the state-side analog of `LightVerifyChainFileSoundness.md` VCF-S. The key-binding gate (`verify_state_bundle.cpp:301-352`), running FIRST and fail-fast, closes it. The regression `tools/test_light_state_bundle.sh` §2b pins exactly this — a `key_bytes = "a:bob"` (`613a626f62`) bundle relabelled `"alice"` is REFUSED with the `key_bytes … does not encode` diagnostic, and a control with matching `key_bytes = "a:alice"` (`613a616c696365`) passes the gate (so it is live, not a tautology).

### 3.7 OSB-E (composition error bound) + fail-closed

**Bound.** `Pr[VERIFIED ∧ reported (ns,key,value) not committee-attested at anchor_index] ≤ K·2⁻¹²⁸ (A1, successor sigs) + c·2⁻¹²⁸ (A2: genesis pin, anchor block_hash, key-binding, root equality, value_hash) + log₂(leaf_count)·2⁻¹²⁸ (A2, MT-4)`, with `c` a small constant. For practical `K ≤ 16`, `leaf_count ≤ 2⁶⁴` this is `≤ 2⁻¹⁰⁰`-class.

**Fail-closed (mirrors `LightClientThreatModel.md` L-6).** Every non-VERIFIED pathway yields a non-zero exit with no false VERIFIED: unreadable `--in` / unreadable-or-malformed `--genesis` → exit 1 (`:233-236`, `:514-519`); any schema/shape/parse/key-binding/genesis-pin/anchor-malformed/sub-quorum/binding/root/Merkle/value_hash failure → UNVERIFIABLE exit 3 (`emit_unverifiable`, `:216-223`). The verdict is a faithful conjunction of the gates; the only success exit (0) requires all gates to pass. ∎

---

## 4. Composition with companion proofs

### 4.1 `StateRootAnchorSoundness.md` (SR-1..SR-5) — the online sibling, read from a file

The bundle's anchor binding (OSB-3) is SR-1's **interior-regime** statement evaluated over bundle bytes: it reuses `committee_bound_state_root` (`trustless_read.cpp:335-437`) — the exact helper SR-1 §3.4 / §6.4 documents as the mechanized binding — except the FULL anchor block, the successor header, and the proof come from the bundle, not live RPC. The "head not bundleable" disposition (OSB-F2) is SR-1's **head-regime** fail-closed boundary (`§6.3`), moved to EXPORT time: the head has no committee-signed successor, so `committee_bound_state_root` throws during export and no head bundle is written. The pre-S-033 rejection (OSB-F3) is SR-5's vacuous-binding honesty applied at gate (7).

### 4.2 `LightVerifyChainFileSoundness.md` (VCF-S) — the file-on-disk threat model + the relabel forge

`verify-chain-file` and `verify-state-bundle` share the OFFLINE, `--genesis`-anchored, file-input posture whose adversary edits the artifact on disk (not only a daemon over the wire). Under that posture, fields the cryptographic gates do not themselves constrain are attack surface: VCF-S records the sig-strip (skip keyed on `index`, not emptiness); OSB-1 records the displayed-key relabel (the key-binding gate). Both are real mid-development gaps the adversarial verifier surfaced and both are closed by a leading structural gate.

### 4.3 `LightClientArchiveSoundness.md` (AR-1..AR-4) — the HEADER-side offline analog

`verify-archive` re-verifies HEADER bytes offline against `--genesis`; the bundle re-verifies a STATE leaf offline against `--genesis`. AR-2's pure-function temporal soundness (verdict = function of bytes, no clock/network) holds identically for the bundle (`verify-state-bundle` opens no `RpcClient`). The static-`K_0` committee caveat (OSB-F4) is AR-4 verbatim.

### 4.4 `MerkleTreeSoundness.md` (MT-4 / S-040) + `LightClientThreatModel.md` (L-2 / L-4 / T-L2) + `Preliminaries.md`

OSB-4 consumes MT-4 (with the S-040 `leaf_count` root-wrapper). OSB-3 consumes T-L2 (committee-sig head trust, applied to the successor) + L-2 (`light_compute_block_digest` byte-equivalence inside `verify_block_sigs`). OSB-5 is the offline instance of L-4 (cleartext-vs-`value_hash`). The whole composite reduces to `{A1, A2}` (`Preliminaries.md §2.0`); A3, A4 unused.

---

## 5. Findings (honest limitations)

None undermines OSB-MAIN's per-invocation soundness; all are coverage/scope statements or the committee-provenance boundary.

### OSB-F1 The committee is `--genesis`-seeded; provenance is the residual boundary
A VERIFIED bundle proves the leaf was committed in a chain whose genesis committee `K_0` (from `--genesis`) signed the successor (OSB-2/OSB-3). It does not separately re-derive the height-correct committee. An operator who feeds a fabricated `--genesis` gets a verdict sound *for that genesis's committee* but meaningless for the real chain — identical to `StateRootAnchorSoundness.md §6.2` / `LightClientArchiveSoundness.md` F-AR4. The `--genesis` file is the sole trust anchor at verify time.

### OSB-F2 The chain head is not bundleable
The head has no committee-signed successor to forward-bind its `state_root`, so EXPORT refuses to bundle it (`committee_bound_state_root` throws; `verify_state_bundle.cpp:131-139` surfaces a retry diagnostic). The caller retries once the chain advances one block. This is `StateRootAnchorSoundness.md §6.3`'s head-regime boundary at export time — a liveness constraint, not a soundness gap (no unbound head root is ever bundled or reported).

### OSB-F3 Pre-S-033 anchors are rejected
An anchor with zero `state_root` carries no committed state to anchor; gate (7) (`:420-425`) refuses it (UNVERIFIABLE). The bundle is meaningful only on chains where S-033 + S-038 are active (the anchor carries a non-zero, producer-populated `state_root`).

### OSB-F4 Static committee `K_0` (no rotation tracking)
Mid-chain `REGISTER`/`DEREGISTER` rotation is out of scope, mirroring `trustless_read.hpp`. A successor signed by a creator outside `K_0` fails closed at gate (5) — a safe failure (no under-verified data accepted), but cross-rotation anchors are not bundle-verifiable without an extended committee. ≡ `LightClientArchiveSoundness.md` AR-4.

### OSB-F5 Single-leaf, single-height snapshot (no liveness, no completeness)
A VERIFIED bundle attests ONE `(ns,key,value)` at ONE `anchor_index`. It does not assert the value is current, that no later block changed it, or anything about other keys/heights. It is a verified point-in-time snapshot, not a trajectory (contrast `AccountHistorySoundness.md` AH-4) and not a non-membership proof for absent keys (`MerkleTreeSoundness.md` MT-5).

### OSB-F6 Non-`a` namespaces report the committed `value_hash`, not a decoded value
The `ns=="a"` value_hash recompute (gate 9) binds the human-readable balance/nonce. Other namespaces report the committed `value_hash` (bound to `R_T` via OSB-4 + the key via OSB-1) without decoding the value structure here; an operator wanting the decoded record uses the namespace-specific reader (`stake-trustless`, `verify-registrant`, `verify-dapp-registration`, …). Not a soundness gap — the leaf is still committee-attested; only the human-facing decode is deferred.

---

## 6. Implementation cross-references

| Theorem | Surface | File:lines | Role |
|---|---|---|---|
| — | `run_export_state_bundle` (online producer) | `light/verify_state_bundle.cpp:80-208` | Fetch proof+anchor+successor; re-verify binding via `committee_bound_state_root` BEFORE write (`:146-154`); ns=="a" cleartext (`:170-181`). |
| — | `verify_state_bundle` (offline verifier) | `light/verify_state_bundle.cpp:227-520` | The gate chain (§1.2); exit 0/3/1. |
| — | subcommand dispatch + help | `light/main.cpp:2681` / `:2708` / `:6855-6856` / `:307` / `:314` | `cmd_export_state_bundle` / `cmd_verify_state_bundle`; help lines. |
| OSB-1 | KEY-BINDING gate | `light/verify_state_bundle.cpp:301-352` | `canonical(ns,key) == state_proof.key_bytes`, first + fail-fast. |
| OSB-1 | daemon canonical encoding mirrored | `src/node/node.cpp:3389-3432` | The byte-identical `rpc_state_proof` key construction. |
| OSB-2 | chain-identity pin | `light/verify_state_bundle.cpp:354-369` | `compute_genesis_hash(--genesis) == bundle.genesis_hash`. |
| OSB-2 | committee from `--genesis` only | `light/verify_state_bundle.cpp:373-374` | `build_committee_json(build_genesis_committee(genesis))` — no bundle committee field. |
| OSB-3 | anchor `block_hash` recompute | `light/verify_state_bundle.cpp:377-386` | `Block::from_json(anchor).compute_hash()`. |
| OSB-3 | successor committee-sig verify | `light/verify_state_bundle.cpp:389-399` | `verify_block_sigs` MD + BFT fallback. |
| OSB-3 | THE binding | `light/verify_state_bundle.cpp:406-415` | `successor.prev_hash == recomputed anchor block_hash`. |
| OSB-3 | `state_root` ∈ signing_bytes (not the digest) | `src/chain/block.cpp:336-350` (compute_hash `:356-365`) | The S-042 / S-033 zero-skip shim the binding rests on. |
| OSB-3 | online binding helper reused | `light/trustless_read.cpp:335-437` | `committee_bound_state_root` — same logic, live RPC. |
| OSB-4 | root equality + Merkle verify | `light/verify_state_bundle.cpp:419-442` | non-zero root, `proof.state_root == anchor.state_root`, `verify_state_proof` against the BOUND root. |
| OSB-5 | ns=="a" value_hash recompute | `light/verify_state_bundle.cpp:446-479` | `SHA256(u64_be(balance) ‖ u64_be(next_nonce)) == proof.value_hash`. |
| OSB-5 | account leaf encoding mirrored | `src/chain/chain.cpp:285-290` (big-endian `src/crypto/sha256.cpp:30-34`) | The byte-identical `build_state_leaves` account leaf. |
| OSB-E | fail-closed `emit_unverifiable` | `light/verify_state_bundle.cpp:216-223` | Uniform UNVERIFIABLE (exit 3) reporting. |

**Tests.**

| Test | Coverage |
|---|---|
| `tools/test_light_state_bundle.sh` | OFFLINE legs (always run): help lists both subcommands; missing `--in` → exit 1; garbage `--in` → UNVERIFIABLE exit 3; wrong-schema → exit 3; **§2b KEY-BINDING (OSB-1)**: `key_bytes="a:bob"` relabelled `"alice"` → UNVERIFIABLE with `key_bytes … does not encode` (forge #6), matching `key_bytes="a:alice"` passes the gate. CLUSTER/CI legs (skip gracefully on this box): positive export→verify round-trip → VERIFIED exit 0 with ns=="a" balance+value_hash (OSB-5); tamper `anchor_block.state_root` → UNVERIFIABLE (OSB-3, forge #1); tamper `successor_header.prev_hash` → UNVERIFIABLE (OSB-3, forge #3); wrong `--genesis` on a real bundle → UNVERIFIABLE (OSB-2, forge #4). |

---

## 7. Status

- **Implementation.** **SHIPPED** (commit `8904d33`). `light/verify_state_bundle.{hpp,cpp}` + `cmd_export_state_bundle` (`light/main.cpp:2681`) / `cmd_verify_state_bundle` (`:2708`), dispatched `:6855-6856`. Test `tools/test_light_state_bundle.sh`.
- **Proof.** Complete (this document). OSB-MAIN (offline state-bundle soundness) via the gate chain; OSB-1 (key-binding, the relabel-forge closure — the state-side VCF-S analog), OSB-2 (genesis pin / committee provenance), OSB-3 (successor binding ⇒ committee-attested `state_root`, = SR-1 over bundle bytes), OSB-4 (Merkle inclusion against the bound root), OSB-5 (value faithfulness incl. the ns=="a" value_hash cross-check); OSB-E composition bound + fail-closed.
- **Soundness gap hunt — result.** Five forges (anchor state_root swap, proof swap/self-anchoring, forged committee sigs, attacker-chosen committee, forged cleartext) are defeated by the binding legs that mirror `committee_bound_state_root`. The one genuine gap the adversarial verifier FOUND — the unbound displayed-key relabel — is closed by the leading key-binding gate (OSB-1; regression §2b). The residuals (OSB-F1..OSB-F6) are coverage/scope statements or the committee-provenance boundary; none is a false-VERIFIED path.
- **Cryptographic assumptions used.** A1 (Ed25519 EUF-CMA — successor committee sigs), A2 (SHA-256 collision resistance — genesis pin, anchor `block_hash` recompute, key-binding equality, root equality, Merkle inclusion, value_hash recompute). A3, A4 not used. Per `Preliminaries.md §2.0`.
- **Scope (honest).** Genesis-seeded committee (no mid-chain rotation tracking, OSB-F4); the chain head is not bundleable (no signed successor — export refuses, OSB-F2); single-leaf single-height snapshot, no liveness/completeness (OSB-F5); S-033+S-038 active required (OSB-F3). The live positive export→verify round-trip is a CI leg; the OFFLINE error + key-binding legs and the negative binding legs run on this box / CI respectively.
- **Composes with.** `StateRootAnchorSoundness.md` (SR-1 over bundle bytes), `LightVerifyChainFileSoundness.md` (VCF-S file-on-disk posture), `LightClientArchiveSoundness.md` (AR-1..AR-4 header-side offline analog), `MerkleTreeSoundness.md` (MT-4 / S-040), `LightClientThreatModel.md` (T-L2 / L-2 / L-4 / L-6), `Preliminaries.md` (A1 + A2 base).
