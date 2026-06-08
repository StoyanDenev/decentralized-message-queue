# Light-Client Persisted-Anchor Soundness (`determ-light state` / `verify-chain --persist`)

**Status: implementation + soundness analysis.** Lands the *persisted stateful
light client* substrate the medium-tier light-client scope deferred
(`robust-gathering-oasis.md` "What's explicitly NOT in this scope": *"No
persistence. Each invocation re-anchors from genesis. The 'stateful sync client'
tier would add a `~/.determ-light/state.json` with the last verified head"*) and
the limitation `LightClientCompositionMap.md` §6 records as *"no persistence
(re-anchors from genesis every run)"*. The `verify-chain --persist` writer +
`state` management subcommand + `light/persist.{hpp,cpp}` module are the
validated, genesis-pinned, schema-versioned, fail-closed cache. The fast-resume
*consumer* (`verify_chain_from_anchor` — skip re-verifying `0..head_height`) is
the clearly-marked daemon-bound follow-up (LSP-6).

## 1. Mechanism

`LightState` (`light/persist.hpp`) = `{schema_version, genesis_hash, head_height,
head_block_hash, head_state_root}`.

- **Write** (`verify-chain --persist [--state <path>]`,
  `light/main.cpp::cmd_verify_chain`): after — and only after —
  `anchor_genesis` + `verify_chain_to_head` succeed, the verified head is
  serialized via `save_light_state`. The persisted `genesis_hash` is the
  light-client's LOCAL `compute_genesis_hash` recompute (`genesis_hash_hex`),
  never the daemon's claimed value.
- **Read / validate** (`load_light_state`): parses + validates JSON, throwing a
  field-naming `std::runtime_error` on malformed JSON / unknown `schema_version`
  / missing / wrong-length / non-hex field. A clean return is a well-formed,
  schema-current state — never a partial one.
- **Manage** (`state --show | --clear | --selftest | --verify-anchor`,
  `light/main.cpp::cmd_state`): offline (no daemon). `--show` loads + validates +
  prints; `--clear` deletes; `--selftest` runs the in-binary round-trip +
  reject-path checks; **`--verify-anchor --genesis <file>`** is the concrete
  offline form of the LSP-2 gate — it recomputes `compute_genesis_hash` from the
  supplied genesis locally and reports PASS (exit 0, anchor is for this chain) or
  MISMATCH (exit 2, stale/wrong-chain cache). This is the exact gate the LSP-6
  resume must run before trusting an anchor, landed and tested ahead of it.
- **Resume** (`verify-chain --resume`, `verify_chain_from_anchor`): re-pins the
  genesis against the cached anchor (LSP-2) then verifies ONLY the suffix above
  it (`verify_chain_walk` anchored at `head_block_hash`), skipping the
  committee-signed prefix; falls back to a full verify when the anchor is
  absent/corrupt/wrong-chain or the daemon hasn't advanced (LSP-6). Pair with
  `--persist` for the steady-state resume-then-advance loop. The resume-or-full
  decision lives in the shared `anchored_head` helper (`trustless_read.cpp`), the
  SINGLE source of truth that `cmd_verify_chain` AND the composite trustless reads
  (`balance/nonce/stake/supply-trustless`, all `--resume`-capable) route through —
  so every reader inherits the same adversarially-verified resume soundness +
  genesis re-pin + fallback rules rather than reimplementing them.
- **Path resolution** (`default_state_path`): `--state <path>` ›
  `$DETERM_LIGHT_STATE` › `<home>/.determ-light/state.json`.

## 2. Trust model

`LightClientThreatModel.md` §6 — **trusted local environment**. The state file
lives on the operator's own machine. A locally-tampered `state.json` is OUT of
scope: an attacker who can rewrite it can rewrite the binary that reads it, so
defending the file against its own host buys nothing. The security the code DOES
provide is that a stale, wrong-chain, or corrupt cache cannot cause the client to
*accept an unverified chain* — it can at worst change *where* verification starts,
and the genesis pin + forward re-verification (LSP-2, LSP-6) catch a divergent
chain there. **No new cryptographic assumption** beyond the per-run
`verify-chain` base {A1 Ed25519 EUF-CMA, A2 SHA-256 collision resistance}
(`Preliminaries.md` §2.0–§2.2).

## 3. Theorems

**LSP-1 (No-unverified-write).** `cmd_verify_chain` calls `save_light_state` only
on the success path *after* `anchor_genesis` (genesis pin) and
`verify_chain_to_head` (prev_hash continuity + K-of-K committee Ed25519 over
`compute_block_digest` for every block `1..head`) both return. A genesis
mismatch, chain break, bad signature, or unreachable daemon throws before the
write. Therefore a persisted anchor is *always* a fully committee-verified head
of the operator's pinned chain — never a head the daemon merely asserted. (Test:
`tools/test_light_state.sh` (C) pins that a failed verify leaves no state file.)

**LSP-2 (Genesis-pin on reuse).** The persisted `genesis_hash` is the local
recompute. Any future consumer re-checks it against the `--genesis` the operator
supplies on the resuming run (LSP-6); a state whose `genesis_hash` ≠ the
recomputed genesis of the supplied config is rejected. So an attacker who swaps
in a state file from a *different* chain (eclipse-onto-another-chain) cannot make
a resume silently adopt it — the anchor is only honored under the operator's own
genesis. (This is the persisted analog of the T-L1 anchor.) **This gate is now a
concrete, independently-testable subcommand** — `state --verify-anchor --genesis
<file>` recomputes `compute_genesis_hash` locally and returns PASS / MISMATCH —
so the security-critical half of the LSP-6 resume is exercised offline *before*
the daemon-bound resume consumes it. (Test: `tools/test_light_state.sh` (C2)
asserts PASS on a matching genesis and MISMATCH-exit-2 on a wrong-chain anchor.)

**LSP-3 (Schema-version gate).** `load_light_state` rejects any
`schema_version ≠ 1` with a diagnostic, rather than misreading a field set a
future/past build wrote. A schema change bumps the version; an incompatible
cache fails closed and is cleared, not silently half-parsed.

**LSP-4 (Fail-closed load).** A corrupt cache (malformed JSON, missing required
field, wrong-length / non-hex `genesis_hash` / `head_block_hash` / `head_state_root`)
throws — surfaced as exit 1 on `state --show`, distinct from the exit-0 graceful
"no anchor" for an *absent* file. A corrupt anchor is therefore never silently
treated as empty (which could mask tampering) nor partially loaded (which could
yield a half-populated `LightState`). `head_state_root` is the one field allowed
empty (`""`) — exactly the pre-S-033 chain case — and only that; a non-empty
value must be 64 hex.

**LSP-5 (Read-soundness of the cache).** Combining LSP-1..LSP-4: anything
`load_light_state` returns is (a) well-formed and schema-current, (b) — if it was
written by this client — a committee-verified head, (c) honored on reuse only
under the operator's own genesis. The cache cannot *inject* an unverified or
wrong-chain head into a later decision; the worst a tampered-but-well-formed file
achieves within the threat model is moving the resume origin, which LSP-6's
forward re-verification then validates.

**LSP-6 (Resume soundness — SHIPPED, commit `22c04fa`).** `verify-chain --resume`
consumes the cached anchor and verifies ONLY the suffix above it, skipping the
committee-signed prefix `0..anchor_height-1`. Flow: (1) re-pin genesis (LSP-2 — a
wrong-chain/absent/corrupt anchor falls back to a full verify, never weaker); (2)
if the daemon's head ≤ `anchor_height`, fall back (nothing new); else (3)
`verify_chain_from_anchor` walks the suffix `[anchor_height, head)` with
`prev_anchor = head_block_hash`, so the FIRST suffix block's `prev_hash` must
equal the cached anchor hash, and committee-verifies every suffix block's K-of-K
sigs. **Prefix-skip soundness:** `light_compute_block_digest` binds both `index`
and `prev_hash` (byte-identical to the producer's `compute_block_digest` for
non-F2 blocks), so each suffix block's K-of-K Ed25519 signature forces its
`prev_hash` to a committee-attested value; by induction from the anchor and under
A1+A2, a `block_hash` equal to the cached anchor IS the previously-verified
block (its hash transitively commits the whole prefix), so re-verifying the
prefix is redundant. A suffix that does NOT chain onto the anchor (a fork/rollback
*below* it) is a HARD error, never silently re-verified from genesis (which would
mask the fork). **Adversarial hardening:** a pre-merge adversarial verifier found
that a malicious daemon could serve a suffix header claiming `index 0`, diverting
`verify_headers` into its binding-free genesis branch (anchor `prev_hash` ignored)
while the per-block loop skipped the sig check for index 0 — a false `RESUMED OK`
on an unsigned, daemon-chosen head. Closed three ways: `verify_headers` rejects an
index-0 header when an anchor was supplied (`verify.cpp`); `verify_chain_walk`
asserts page indices are contiguous from `from` so a suffix's first index must be
`anchor_height` not 0 (`trustless_read.cpp`); and the genesis sig-skip is gated on
`from==0` plus a walked-count gate (`headers_seen == head - start_from`) that also
hardens the from-genesis walk against a short final page.

## 4. What it does NOT do (honest limitations)

- **Local-tamper is out of scope** — §2. The file is trusted-local; integrity
  against its own host is not a goal (and not achievable without a separate root
  of trust the medium tier does not assume).
- **Single-anchor, head-only** — the cache stores the verified head, not the full
  committee history or a checkpoint chain. Committee rotation across a long
  offline gap is re-derived by the resume's forward suffix verify, not cached.
- **Live resume path is cluster-bound** — the offline `--resume` *arg contract*
  (accepted; fallback when no/absent/corrupt anchor) is deterministically tested
  on every host; the live suffix-verify + fallback verdicts need a block-minting
  cluster (WSL2/CI), like every other determ-light composite.

## 5. Test surface

`tools/test_light_state.sh` — 23 offline assertions, deterministic on every host
(the persistence module is daemon-free): (A) `state --selftest` (the in-binary
round-trip + 5 fail-closed reject paths: malformed JSON, bad `schema_version`,
short `genesis_hash`, missing field, empty-`state_root` round-trip); (B)
`--show`/`--clear` graceful-absence + valid-show + fail-closed-on-corrupt +
mode-flag / unknown-arg / `$DETERM_LIGHT_STATE`-override contract; (C2)
`--verify-anchor` PASS on a matching genesis + MISMATCH-exit-2 on a wrong-chain
anchor + the no-`--genesis` / absent-cache usage gates (the LSP-2 gate); (C)
`verify-chain --persist`/`--state` arg acceptance + the LSP-1 no-write-on-failed-
verify guarantee; (D) `verify-chain --resume` arg contract (accepted alone and
with `--persist`; in help). The cluster-bound live `--persist` write (a real
verified head landing in the cache) and the live LSP-6 resume suffix-verify +
fallback verdicts are exercised on WSL2 / CI. The resume soundness fix (index-0
diversion) is additionally pinned by the index-contiguity + walked-count gates in
`verify_chain_walk`, which `tools/test_light_verify_chain_file.sh` exercises on a
cluster (tampered-prev_hash / stripped-sig negatives).

## 6. Cross-references

`LightClientThreatModel.md` §6 (trusted local environment; T-L1 anchor reused by
LSP-2), `LightClientCompositionMap.md` §6 (the "no persistence" limitation this
substrate addresses), `MultiPeerCrossCheckSoundness.md` (the sibling §6-residual
closure — multi-peer eclipse detection), `StateRootAnchorSoundness.md` (the
`head_state_root` the cache stores), `Preliminaries.md` §2.0–§2.2 (A1/A2).
