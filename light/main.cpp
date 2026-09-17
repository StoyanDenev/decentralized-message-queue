// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light — trust-minimized light-client wallet binary.
//
// A third Determ binary alongside `determ` (full daemon) and
// `determ-wallet` (account management). The light-client talks to a
// daemon's RPC but verifies every piece of data it receives. Trust
// anchor is the genesis JSON file supplied via --genesis on every
// connection — the light-client computes compute_genesis_hash locally
// and refuses to proceed if the daemon's block 0 doesn't match.
//
// Subcommands (31 total + help / version):
//   verify-headers           Verify a `headers` RPC reply's chain
//   verify-block-sigs        Verify K-of-K committee sigs on a header
//   verify-state-proof       Verify a state-proof against a root
//   verify-state-root        Report the committee-verified state_root at H
//   fetch-headers            Fetch headers from the daemon's RPC
//   fetch-state-proof        Fetch a state-proof from the daemon's RPC
//   verify-chain             Composite: anchor + verify all to head
//                            (--persist caches the verified anchor)
//   cross-check              Multi-peer divergence detector (eclipse defense)
//   state                    Manage the persisted-anchor cache (offline)
//   balance-trustless        Composite: verify chain + state-proof balance
//   nonce-trustless          Composite: verify chain + state-proof nonce
//   stake-trustless          Composite: verify chain + state-proof stake
//   verify-unstake-eligibility Verdict: is s: stake unlockable at head (S-017)
//   supply-trustless         Composite: verify 5 c: counters + A1 identity
//   account-history          Composite: verified balance/nonce over a range
//   sign-tx                  Offline signed TRANSFER/STAKE/UNSTAKE
//   register-note-key        Build a submittable REGISTER_NOTE_KEY (nk:, NC-8)
//   submit-tx                Submit a pre-signed tx to the daemon
//   verify-and-submit        Composite: trustless nonce + sign + submit
//   watch-head               Periodic trust-minimized head monitor
//   export-headers           Verifiable header archive (FETCH+VERIFY+WRITE)
//   verify-archive           OFFLINE re-verify of an export-headers archive
//   verify-tx-inclusion      Prove tx H is (not) in block B vs committee sigs
//   verify-receipt-inclusion Prove cross-shard receipt (src,H) is applied (i:)
//   verify-merge-state       Prove shard S is merged into partner P (m:)
//   verify-param-change      Prove gov param change (eff,idx) is staged (p:)
//   verify-param-value       Prove current effective consensus scalar (k:)
//   verify-dapp-registration Prove domain D is a registered DApp (d:)
//   verify-registrant        Prove domain D is a registered validator (r:)
//   verify-notekey           Prove an account's standing recipient note_pk (nk:)
//   verify-enote-inclusion   Prove a scanned (commitment, ciphertext) enote is
//                            the committed on-chain delivery (en:, MODERN)
//   verify-account           Derive anon-addr + prove EXISTS / NOT-CREATED (a:)
//   verify-rand              D.5: authenticate cumulative_rand[H] (S-042 beacon)
//   verify-selection         D.5: re-derive + refute a government random selection
//   verify-selection-offline D.5: verify-selection over a blocks file (no daemon)
//   verify-equivocation      OFFLINE re-verify an EquivocationEvent (FA6 V11)
//   shard-route              OFFLINE genesis-pinned address-to-shard routing
//   committee-at-height      Report committee-verified creators at block H
//   decode-wire              OFFLINE decode + validate a binary wire frame
//   rpc-auth                 OFFLINE compute/verify the S-001 HMAC RPC tag
//   help / version
//
// Trust-model invariants:
//   * Every command that touches the daemon's RPC takes --genesis to
//     pin the chain identity on first connection.
//   * Composite read commands (balance-trustless, nonce-trustless,
//     stake-trustless) DO NOT trust the daemon's `account` / `stake_info`
//     reply unless the cleartext hashes to the value_hash in a verified
//     state-proof.
//   * verify-and-submit fetches the verified nonce via nonce-trustless
//     (not the daemon's raw `account` reply) before signing.

#include "rpc_client.hpp"
#include "verify.hpp"
#include "trustless_read.hpp"
#include "keyfile.hpp"
#include "sign_tx.hpp"
#include "pq_sign_tx.hpp"
#include "audit_tx.hpp"
#include "ct_tx.hpp"
#include "watch.hpp"
#include "export.hpp"
#include "verify_archive.hpp"
#include "verify_state_bundle.hpp"
#include "account_history.hpp"
#include "verify_tx_inclusion.hpp"
#include "verify_state_root.hpp"
#include "verify_rand.hpp"
#include "verify_selection.hpp"
#include "verify_ct.hpp"
#include "persist.hpp"
#include "outbox_cli.hpp"

#include <determ/chain/block.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/chain/params.hpp>          // bft_committee_size (D3.5e-7e)
#include <determ/crypto/keys.hpp>
#include <determ/crypto/random.hpp>         // epoch_committee_seed / select_m_creators (D3.5e-7e)
#include <determ/crypto/sha256.hpp>
#include <determ/types.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace {

using nlohmann::json;
using namespace determ;
using namespace determ::light;

constexpr const char* DETERM_LIGHT_VERSION = "1.0.0";

void print_usage() {
    std::cout <<
        "Usage: determ-light <command> [options]\n"
        "\n"
        "A trust-minimized light-client wallet for Determ. Reads chain\n"
        "data via a daemon's RPC, verifies every piece locally against a\n"
        "pinned genesis hash, signs txs offline, and submits via RPC.\n"
        "\n"
        "Verification primitives (offline):\n"
        "  verify-headers --in <file> [--genesis-hash <hex>] [--prev-hash <hex>]\n"
        "      Verify the prev_hash chain in a `headers` RPC reply.\n"
        "  verify-block-sigs --header <file> --committee <file> [--bft]\n"
        "                    [--k-block-sigs <n>] [--no-bft-enabled]\n"
        "      Verify K-of-K committee Ed25519 sigs (or ceil(2K/3) BFT).\n"
        "      --k-block-sigs enforces the node's committee-size mode-eligibility\n"
        "      (MD names exactly k creators; BFT ceil(2k/3)); --no-bft-enabled\n"
        "      refuses any BFT block (a mutual-distrust-only chain). LV-1/LV-2.\n"
        "  block-verify --block <file> --committee <file> [--bft] [--json]\n"
        "      Self-contained OFFLINE single-block verifier: STRUCTURE +\n"
        "      TX-ROOT (recompute compute_tx_root == stored) + SIGS (committee\n"
        "      Ed25519 over the INTERNALLY-recomputed block_digest — no operator\n"
        "      digest needed, unlike determ-wallet block-verify) + CT-PROOFS\n"
        "      (A3: every SHIELD/UNSHIELD/CONFIDENTIAL_TRANSFER range/balance\n"
        "      proof re-verified CLIENT-SIDE — CT validity not trusted to the\n"
        "      committee). One PASS/FAIL.\n"
        "  verify-ct-tx --file <tx.json> [--json]\n"
        "      A3 single-tx client-side CT verification: SHIELD balance proof,\n"
        "      UNSHIELD proof context-BOUND to the locally-recomputed\n"
        "      (from,to,nonce,amount) digest, CONFIDENTIAL_TRANSFER DCT1\n"
        "      range+balance + fee match + dup-input reject. Pure local crypto;\n"
        "      note-SET (double-spend) facts stay with the daemon/state_root.\n"
        "      Exit 0 VERIFIED, 3 INVALID (incl. non-CT tx), 1 usage.\n"
        "  verify-ct-block --rpc-port <N> --genesis <file> --height <H>\n"
        "                  [--wait <s>] [--json]\n"
        "      A3 RPC-driven CT block verifier — the composed anchored form of\n"
        "      block-verify. Fetches block[H] from a live daemon and proves, in\n"
        "      ONE command against the pinned genesis: (1) ANCHOR — H chains to\n"
        "      genesis + is committee-attested (verify-state-root / S-042); (2)\n"
        "      BODY-PIN — the full body recomputes to that committee-anchored\n"
        "      block_hash (a doctored body fails closed); (3) CT-PROOFS — every\n"
        "      confidential tx re-verified CLIENT-SIDE. Committee is DERIVED from\n"
        "      genesis (no --committee file). --wait forwards to the head-anchor\n"
        "      poll. Exit 0 OK, 3 anchor/pin/CT failure, 1 usage/transport.\n"
        "  verify-shardtip-records --rpc-port <N> --genesis <file> --height <H>\n"
        "                  [--wait <s>] [--json]\n"
        "      S-036 third-party auditor of the shard-tip distress-record fold.\n"
        "      For BEACON block[H], proves against the pinned genesis: (1) ANCHOR\n"
        "      + (2) BODY-PIN (as verify-ct-block), then for each folded record —\n"
        "      (3) CC-PIN the source-epoch committee checkpoint (cc:[E]) to the\n"
        "      committee-signed state_root, and (4) re-verify the record's full-\n"
        "      tip witness (frozen-committee K-of-K sigs + committee_sig_root) —\n"
        "      the exact validator check_shardtip_witnesses run off an untrusted\n"
        "      daemon. A fabricated distress record fails closed. 0 records =\n"
        "      vacuously OK. Requires cc:[E] within the 16-epoch ring and a\n"
        "      genesis-committed beacon_shard_regions map (a legacy manifest-only\n"
        "      beacon's region map is node-local/uncommitted — invisible under the\n"
        "      untrusted-daemon posture — so records are conservatively rejected).\n"
        "      Exit 0 OK, 3 anchor/pin/witness failure, 1 usage/transport.\n"
        "  verify-chain-file --in <headers> (--committee <file> |\n"
        "                    --committee-manifest <file>)\n"
        "                    [--genesis-hash <hex>] [--prev-hash <hex>]\n"
        "                    [--bft] [--json]\n"
        "      Self-contained OFFLINE whole-chain verifier (file-based dual of\n"
        "      verify-chain): CONTINUITY (prev_hash walk over an exported headers\n"
        "      file, anchored by --genesis-hash/--prev-hash) + SIGS (every\n"
        "      non-genesis header's committee Ed25519 over its self-recomputed\n"
        "      digest). --committee-manifest [{from,to,committee}...] verifies\n"
        "      ACROSS committee rotations (per-range committee). No daemon.\n"
        "  committee-diff --a <file> --b <file> [--json]\n"
        "      Offline diff of two committee files (validators --json shape):\n"
        "      added / removed / key-rotated / region- + stake-changed members.\n"
        "      Companion to --committee-manifest — tells you whether the SIGNING\n"
        "      set changed (exit 0 identical, 2 differs). No daemon.\n"
        "  verify-state-proof --in <file> [--state-root <hex>]\n"
        "      Verify a state-proof Merkle inclusion against a root.\n"
        "\n"
        "RPC fetch primitives:\n"
        "  fetch-headers --rpc-port <N> --from <I> --count <M> [--out <file>]\n"
        "      Fetch headers [I, I+M) from 127.0.0.1:N.\n"
        "  fetch-validators --rpc-port <N> [--out <file>]\n"
        "      Fetch the current committee set (validators RPC) — the committee\n"
        "      input for verify-chain-file / committee-diff, determ-light-only.\n"
        "  fetch-state-proof --rpc-port <N> --ns <NS> --key <K> [--out <file>]\n"
        "      Fetch a state-proof for (NS, K) from 127.0.0.1:N.\n"
        "\n"
        "Composite trustless reads (--genesis required):\n"
        "  verify-chain --rpc-port <N> --genesis <file> [--resume] [--persist [--state <path>]]\n"
        "               [--track-registry]\n"
        "      Anchor genesis + fetch all headers + verify every committee sig.\n"
        "      --track-registry (R52) replays mid-chain REGISTER/DEREGISTER txs\n"
        "      into the committee map (full blocks re-fetched pinned to the\n"
        "      chained block_hash; activation heights via the SAME shared\n"
        "      derive_registration_delay formula the full node applies) and\n"
        "      makes the per-block committee check activity-window-aware —\n"
        "      closing the genesis-frozen-committee limitation for chains with\n"
        "      mid-chain registrations. Full from-genesis walk only\n"
        "      (incompatible with --resume/--persist).\n"
        "      --persist caches the verified anchor (genesis pin + head height /\n"
        "      block_hash / state_root) to <path> (default: $DETERM_LIGHT_STATE,\n"
        "      else ~/.determ-light/state.bin) — written only AFTER full verify.\n"
        "      --resume re-pins the genesis against a cached anchor and verifies\n"
        "      ONLY the suffix the daemon added above it (skips re-walking the\n"
        "      committee-signed prefix); falls back to a full verify when the\n"
        "      anchor is absent/corrupt/wrong-chain — never weaker than a full\n"
        "      verify. LSP-7: a daemon BELOW the cached anchor height is REFUSED\n"
        "      (a fork-free chain never regresses — stale/truncated state; clear\n"
        "      with `state --clear` if the reset was intentional), and a daemon\n"
        "      exactly AT it must present the cached anchor block itself. Pair\n"
        "      with --persist for the steady-state resume-then-advance loop.\n"
        "  state (--show [--json] | --clear | --selftest | --verify-anchor --genesis <file>) [--state <path>]\n"
        "      Manage the persisted anchor cache (offline; no daemon). --show\n"
        "      prints + validates it; --clear deletes it; --selftest runs the\n"
        "      offline round-trip + fail-closed reject-path checks of the module;\n"
        "      --verify-anchor recomputes the genesis hash from <file> locally and\n"
        "      checks the cached anchor is for THAT chain (PASS 0 / MISMATCH 2) —\n"
        "      the offline genesis re-pin gate a future verify-chain --resume runs.\n"
        "  cross-check --genesis <file> (--rpc-port <N> | --peer <host:port>) x2+ [--json]\n"
        "      Multi-peer divergence detector: independently committee-verify each\n"
        "      daemon from the pinned genesis, then require peers sharing a height to\n"
        "      agree on block_hash + state_root. Disagreement at a shared height =\n"
        "      a committee-signed fork (DIVERGENCE, exit 2). A behind peer is benign\n"
        "      lag. Exit 0 AGREE / 2 DIVERGENCE / 3 INCONCLUSIVE / 1 UNVERIFIABLE.\n"
        "  audit --rpc-port <N> --genesis <file> [--json]\n"
        "      One-shot trust-minimized node audit: composes CHAIN (verify-chain:\n"
        "      genesis pin + continuity + every committee sig) and SUPPLY\n"
        "      (supply-trustless: A1 conservation against the signed head) into a\n"
        "      single PASS/FAIL with a per-check breakdown. SUPPLY is SKIPped (not\n"
        "      failed) when CHAIN fails. Exit 0 = all pass, 1 = any fail/error —\n"
        "      suitable as a cron/monitor health gate.\n"
        "  balance-trustless --rpc-port <N> --genesis <file> --domain <D> [--json]\n"
        "                    [--resume [--state <path>]] [--wait <seconds>]\n"
        "      Verified chain + state-proof + cross-check daemon's cleartext.\n"
        "      --resume reuses a cached committee-verified anchor (verify only the\n"
        "      suffix above it) instead of re-verifying from genesis each call;\n"
        "      falls back to a full verify when the cache is absent/unusable.\n"
        "      --wait <s> blocks up to s seconds for the next block when the\n"
        "      anchor is the chain head (default 0 = fail closed at the head).\n"
        "  nonce-trustless --rpc-port <N> --genesis <file> --domain <D> [--json]\n"
        "                  [--resume [--state <path>]] [--wait <seconds>]\n"
        "      Same as balance-trustless but extracts next_nonce.\n"
        "  stake-trustless --rpc-port <N> --genesis <file> --domain <D> [--json]\n"
        "                  [--resume [--state <path>]] [--wait <seconds>]\n"
        "      Verified chain + state-proof (s: namespace) + cross-check the\n"
        "      daemon's `stake_info` cleartext. Prints the committee-verified\n"
        "      locked stake + unlock_height (UINT64_MAX = no active unlock /\n"
        "      bonded). A domain with no stake leaf fails closed (the daemon's\n"
        "      state_proof returns not_found) — never a bare zero.\n"
        "  verify-abort-record --rpc-port <N> --genesis <file> --domain <D> [--json]\n"
        "                      [--resume [--state <path>]] [--wait <seconds>]\n"
        "      Verified chain + state-proof (b: namespace) + cross-check the\n"
        "      daemon's `abort_records` cleartext. RECORDED prints the committee-\n"
        "      verified Phase-1 abort (count, last_block) for node <D> hash-bound\n"
        "      to the signed state_root; NOT-RECORDED (a daemon-asserted negative,\n"
        "      negative_footing=daemon_asserted) means no committed b: leaf. The\n"
        "      trust-minimized complement to operator_slashing_ledger.sh.\n"
        "  verify-constant --rpc-port <N> --genesis <file> --name <NAME>\n"
        "                  {--value <U64> | --value-hex <64-hex>} [--json]\n"
        "                  [--resume [--state <path>]] [--wait <seconds>]\n"
        "      CONFIRM an asserted chain constant against the committee-attested\n"
        "      k: leaf (key-bound + Merkle-bound to the signed state_root). BOTH\n"
        "      verdicts are cryptographic: CONFIRMED (exit 0) = the committee\n"
        "      attests exactly the asserted value; MISMATCH (exit 2) = it attests\n"
        "      a DIFFERENT one. not_found -> UNVERIFIABLE (exit 3; constants are\n"
        "      always committed). 12 u64 constants (min_stake, unstake_delay,\n"
        "      block_subsidy, shard_count, ...) take --value; shard_salt takes\n"
        "      --value-hex. Audits a daemon's governance parameters trustlessly.\n"
        "  verify-unstake-eligibility --rpc-port <N> --genesis <file>\n"
        "                             --domain <D> [--json] [--wait <seconds>]\n"
        "      Prove whether <D>'s locked stake is CURRENTLY eligible to be\n"
        "      unstaked — i.e. whether an UNSTAKE tx mined at the committee-\n"
        "      verified head height H would pass the S-017 chain/producer/\n"
        "      validator gate. Composes stake-trustless (anchor genesis +\n"
        "      committee-verify the header chain to head + Merkle-verify the\n"
        "      s:-namespace leaf + hash-bind the daemon's `stake_info`\n"
        "      cleartext) and then re-runs the SAME predicate the validator\n"
        "      enforces in BlockValidator::check_tx (`b.index >= unlock_height`,\n"
        "      where b.index is the next-block height H+1 at the verified head\n"
        "      H) over the committee-attested unlock_height — never the\n"
        "      daemon's raw claim. Both inputs (the head height AND the\n"
        "      unlock_height) are committee-anchored, so an ELIGIBLE / LOCKED /\n"
        "      BONDED verdict cannot be faked by a lying daemon. Four verdicts\n"
        "      (exit 0): ELIGIBLE (locked>0 and an unlock_height <= H+1 has\n"
        "      matured), LOCKED (locked>0 but H+1 < unlock_height —\n"
        "      blocks_remaining reported), BONDED (locked>0 but\n"
        "      unlock_height==UINT64_MAX — no unlock scheduled; DEREGISTER\n"
        "      first), and NO-STAKE — which has TWO footings: a present s: leaf\n"
        "      with locked==0 is a committee-anchored proof of a zero stake\n"
        "      (negative_footing=cryptographic), while an absent leaf\n"
        "      (state_proof not_found) is a daemon-asserted negative ((H-neg),\n"
        "      negative_footing=daemon_asserted). Any tamper, cleartext/leaf\n"
        "      mismatch, or daemon refusal → UNVERIFIABLE (exit 3), never a\n"
        "      false ELIGIBLE. Distinct from stake-trustless, which reports the\n"
        "      raw (locked, unlock_height) pair but does NOT compute the\n"
        "      height-relative eligibility verdict. --wait blocks up to s seconds\n"
        "      for the head's successor block so the embedded stake read's S-042\n"
        "      successor binding can complete (default 0 fails closed at the head).\n"
        "  supply-trustless --rpc-port <N> --genesis <file> [--json] [--resume [--state <path>]]\n"
        "                   [--wait <seconds>]\n"
        "      Verified chain + the five A1 supply counters from the `c:`\n"
        "      namespace (genesis_total, accumulated_subsidy/inbound/slashed/\n"
        "      outbound), each Merkle-verified against the SAME committee-\n"
        "      signed state_root and hash-bound to the daemon's chain_summary\n"
        "      cleartext, then the closed-form A1 identity (genesis_total +\n"
        "      subsidy + inbound - slashed - outbound) recomputed from the\n"
        "      committed values. CONSERVED means the five committee-committed\n"
        "      counters are internally consistent and equal the daemon's\n"
        "      claimed total_supply; VIOLATED (exit 2) means the recomputed\n"
        "      total disagrees; any tamper, split-root, or daemon refusal →\n"
        "      UNVERIFIABLE (exit 3), never a false CONSERVED. Unlike the\n"
        "      a:/s: single-leaf reads, this is a CROSS-LEAF invariant the\n"
        "      verifier can re-check from committed values alone (it does NOT\n"
        "      enumerate every account, so the daemon's live_total_supply is\n"
        "      cross-checked, not independently re-derived — the S-040\n"
        "      leaf_count boundary).\n"
        "  account-history --rpc-port <N> --genesis <file> --domain <D>\n"
        "                  --from <H1> --to <H2> [--step <S>] [--json] [--wait <seconds>]\n"
        "      Verified balance/nonce trajectory over a height range. For\n"
        "      each sampled height the row's state_root is read from a\n"
        "      committee-verified header chained back to the pinned genesis;\n"
        "      balance/next_nonce are Merkle-verified at the head (the\n"
        "      daemon's state_proof RPC serves the head only). --step\n"
        "      defaults to 1; --to must be <= the daemon's head index.\n"
        "  verify-state-root --rpc-port <N> --genesis <file> --height <H> [--json]\n"
        "                    [--wait <seconds>]\n"
        "      Report the committee-verified state_root at height H. Anchors\n"
        "      genesis, chains header[H] back to block 0, verifies header[H]'s\n"
        "      K-of-K (MD) / ceil(2K/3) (BFT) committee sigs, and prints the\n"
        "      committee-attested state_root + committee size + sig count.\n"
        "      Distinct from verify-state-proof (which checks a Merkle PROOF\n"
        "      against a GIVEN root): this verifies the ROOT ITSELF is\n"
        "      genuinely committee-signed at H. Genesis (H=0) is anchored by\n"
        "      compute_genesis_hash (no committee sigs by construction). A\n"
        "      header whose sigs don't verify fails closed (non-zero exit) —\n"
        "      never a bare daemon-reported root.\n"
        "  committee-at-height --rpc-port <N> --genesis <file> --height <H>\n"
        "                      [--member <D>] [--json] [--wait <seconds>]\n"
        "      Report the committee-verified set of creators (consensus\n"
        "      committee members) that produced block H, in selection order,\n"
        "      each paired with its genesis-committee ed_pub + whether it\n"
        "      signed the block (a sentinel-zero block-sig marks a BFT\n"
        "      abstention). Anchors genesis, chains header[H] back to block 0,\n"
        "      and verifies header[H]'s K-of-K (MD) / ceil(2K/3) (BFT)\n"
        "      committee sigs over the block digest — which BINDS creators[],\n"
        "      so the reported set is committee-attested, not merely\n"
        "      daemon-asserted. Distinct from verify-block-sigs (which checks\n"
        "      sigs against a committee YOU supply): this DERIVES the committee\n"
        "      trustlessly from the chain. With --member <D>, prints a sound\n"
        "      IN-COMMITTEE / NOT-IN-COMMITTEE verdict (plus the member's slot\n"
        "      + sign status). Genesis (H=0) has no committee and is rejected\n"
        "      with a diagnostic. A header whose sigs don't verify fails closed\n"
        "      (non-zero exit) — never a bare daemon-reported committee. --wait\n"
        "      matters only when H == head (the S-042 successor binding needs\n"
        "      block H+1); for any H < head no wait is needed.\n"
        "\n"
        "Sign + submit:\n"
        "  sign-tx --keyfile <path> --type {TRANSFER|STAKE|UNSTAKE}\n"
        "          --to <addr> --amount <N> --fee <N> --nonce <N> [--out <file>]\n"
        "      Offline sign with operator-supplied nonce.\n"
        "  pq-sign-tx --type {TRANSFER|STAKE|UNSTAKE} --from <addr> --to <addr>\n"
        "             --amount <N> --fee <N> --nonce <N>\n"
        "             --scheme {mldsa44|mldsa65|mldsa87|hybrid44|hybrid65|hybrid87}\n"
        "             --mldsa-seed <hex32> [--ed-seed <hex32>] [--out <file>]\n"
        "      Post-quantum tx authentication (CRYPTO-C99-SPEC §3.21): bind the tx's\n"
        "      canonical signing_bytes with a DPQ1 ML-DSA (optionally +Ed25519 hybrid)\n"
        "      envelope. --ed-seed is required for hybrid*. Client tooling; the\n"
        "      consensus accept-rule for such a tx is a separate, owner-gated step.\n"
        "  pq-verify-tx --file <tx.json>\n"
        "      Offline-verify a DPQ1-authenticated tx (exit 0 verified / 3 invalid).\n"
        "  pq-address --scheme {mldsa44|mldsa65|mldsa87} --mldsa-seed <hex32>\n"
        "      Print the PQ-native bearer address (the ML-DSA public key) for a seed.\n"
        "  pq-transfer --to <addr> --amount <N> --fee <N> --nonce <N>\n"
        "              --scheme {mldsa44|mldsa65|mldsa87} --mldsa-seed <hex32> [--out <file>]\n"
        "      Build a canonical, SUBMITTABLE PQ_TRANSFER (§3.21): derives the PQ-native\n"
        "      `from` address, signs a DPQ1 envelope over signing_bytes; feed --out to\n"
        "      submit-tx. Verify a validator would accept it with `determ verify-pq-tx`.\n"
        "  rotate-audit-key --keyfile <path> {--pubkey <hex32>|--clear}\n"
        "                   --fee <N> --nonce <N> [--out <file>]\n"
        "      Build a SUBMITTABLE ROTATE_AUDIT_KEY (TxType 15): set or clear the\n"
        "      account's standing audit view-master key. Account-Ed25519-signed,\n"
        "      fee-only (AuditLayerSoundness.md). Feed --out to submit-tx.\n"
        "  log-audit-access --keyfile <path> --epoch {<N>|all} --auditor <hex32>\n"
        "                   --context <hex32> --fee <N> --nonce <N> [--out <file>]\n"
        "      Build a SUBMITTABLE LOG_AUDIT_ACCESS (TxType 16): post an on-chain\n"
        "      disclosure record. --epoch all = full-history sentinel.\n"
        "  register-note-key --keyfile <path> {--note-pk <hex33>|--clear}\n"
        "                   --fee <N> --nonce <N> [--out <file>]\n"
        "      NC-8: build a SUBMITTABLE REGISTER_NOTE_KEY (TxType 17): set or\n"
        "      clear the account's standing recipient note_pk (the 33-byte P-256\n"
        "      point a sender seals a CONFIDENTIAL_TRANSFER enote to). Account-\n"
        "      Ed25519-signed, fee-only; anon/bearer payees included. Feed --out\n"
        "      to submit-tx; verify a validator accepts it with\n"
        "      `determ verify-audit-tx`. Then verify-notekey proves it on-chain.\n"
        "  build-shield --keyfile <path> --blind-seed <hex> --amount <N>\n"
        "               --fee <N> --nonce <N> [--out <file>]\n"
        "      Build a SUBMITTABLE SHIELD (TxType 12): move PUBLIC amount from your\n"
        "      transparent balance into a confidential note (§3.22). The blinding is\n"
        "      derived from --blind-seed (>= 32 bytes, UNIQUE + high-entropy per note\n"
        "      — reuse leaks the amount) — SAVE the seed + amount to spend it later.\n"
        "  build-unshield --keyfile <path> --blind-seed <hex> --to <addr>\n"
        "                 --amount <N> --fee <N> --nonce <N> [--out <file>]\n"
        "      Build a SUBMITTABLE UNSHIELD (TxType 13): withdraw the note\n"
        "      (amount, blind-seed) to transparent --to (§3.22b). The balance proof is\n"
        "      context-bound to (from,to,nonce,amount). Verify with verify-ct-tx.\n"
        "  build-ct-transfer --keyfile <path> --spec <file> [--out <file>]\n"
        "      Build a SUBMITTABLE CONFIDENTIAL_TRANSFER (TxType 14, §3.22c): spend the\n"
        "      input notes -> new output notes (pool->pool). --spec JSON: {inputs:\n"
        "      [{value,blind_seed}], outputs:[{value,blind_seed}], fee, nonce_seed,\n"
        "      tx_nonce}. Balance MUST hold (Σin = Σout + fee); 1, 2, or 4 outputs.\n"
        "      nonce_seed + every blind_seed must be >= 32 bytes, UNIQUE + high-\n"
        "      entropy (reuse leaks/links amounts). Verify with verify-ct-tx; SAVE\n"
        "      each output (value,blind_seed) so the recipient can spend it.\n"
        "  submit-tx --rpc-port <N> --tx-json <file>\n"
        "      Submit a pre-signed tx via the daemon's submit_tx RPC.\n"
        "  verify-and-submit --rpc-port <N> --genesis <file> --keyfile <path>\n"
        "                    --to <addr> --amount <N> --fee <N> [--out <file>]\n"
        "                    [--resume [--state <path>]] [--wait <seconds>]\n"
        "      Composite: nonce-trustless + sign-tx + submit-tx. --resume reuses a\n"
        "      cached committee-verified anchor for the embedded nonce read.\n"
        "      --wait blocks up to s seconds for the head's successor block so the\n"
        "      embedded nonce read's S-042 successor binding can complete (the read\n"
        "      anchors at the head; default 0 fails closed there, as on the readers).\n"
        "  outbox enqueue --outbox <dir> --genesis <file> --keyfile <path> --to <addr>\n"
        "                 --amount <N> --fee <N> [--payload-hex <hex>] [--nonce <N>]\n"
        "                 [--rpc-port <N>] [--idempotency-key <k>] [--max-messages <N>] [--json]\n"
        "      Sign a TRANSFER once and store the signed bytes DURABLY (fsync + atomic\n"
        "      publish) in a per-(sender, chain) outbox before printing 'queued locally'.\n"
        "      Never stores a key. Nonce = --nonce, else max(verified next_nonce, local slots).\n"
        "  outbox submit --outbox <dir> --genesis <file> --rpc-port <N> [--now] [--json]\n"
        "      Re-send every due slot's SAME bytes (bounded backoff). A daemon 'queued' is\n"
        "      SUBMITTED, a lost reply is UNKNOWN — neither is finality.\n"
        "  outbox reconcile --outbox <dir> --genesis <file> --rpc-port <N> [--resume]\n"
        "                   [--state <path>] [--wait <s>] [--json]\n"
        "      Committee-verify inclusion + the successor binding (FINALIZED) and the\n"
        "      sender's nonce (APPLIED vs SKIPPED); detects orphaned inclusions, consumed\n"
        "      nonces, gaps and stuck slots. Exit 3 when a leg is UNVERIFIABLE.\n"
        "  outbox status --outbox <dir> [--json]     (lock-free; exit 3 if a slot is CORRUPT)\n"
        "  outbox replace --outbox <dir> --genesis <file> --keyfile <path> --nonce <N>\n"
        "                 --fee <N> [--to <addr>] [--amount <N>] [--payload-hex <hex>]\n"
        "      Fee bump (same message, same msg_id) or re-issue (new message) at the same\n"
        "      nonce; every earlier alternate stays watched — the ledger applies at most one.\n"
        "  outbox prune --outbox <dir> [--older-than <s>] [--include-unlocated] [--json]\n"
        "      Remove only PROVEN-consumed slots older than s (default 7 days), bumping the\n"
        "      nonce floor first. Never removes a queued/pending/skipped slot.\n"
        "  outbox recover --outbox <dir>\n"
        "      Rebuild a corrupt status section (bytes intact → UNKNOWN) or an unreadable\n"
        "      outbox.meta; quarantine unreadable records (the nonce stays reserved).\n"
        "      Exit codes: 0 ok, 1 error, 3 corrupt/unverifiable, 4 full, 5 locked,\n"
        "      6 wrong chain/sender, 7 daemon config, 8 idempotency key already held.\n"
        "\n"
        "Monitoring:\n"
        "  watch-head --rpc-port <N> --genesis <file> [--count <N>] [--interval <s>]\n"
        "      Anchor genesis once + poll the daemon's head every <s> seconds.\n"
        "      Verifies committee sigs each tick; prints a structured progress\n"
        "      line per tick. Exits on SIGINT or after --count ticks.\n"
        "\n"
        "Archive:\n"
        "  export-headers --rpc-port <N> --genesis <file> --from <H1> --count <M>\n"
        "                 --out <file> [--include-committee-sigs]\n"
        "      Fetch + verify headers [H1, H1+M) + write a self-contained\n"
        "      verifiable archive to <file>. Re-verifiable offline at any\n"
        "      later date via verify-headers --in <file>.\n"
        "  verify-archive --in <archive> --genesis <file> [--require-sigs]\n"
        "      OFFLINE re-verification of an export-headers archive (no\n"
        "      daemon, no RPC). Anchors genesis (compute_genesis_hash ==\n"
        "      archive.genesis_hash), re-checks the prev_hash chain, and\n"
        "      re-verifies committee sigs when the archive retained them\n"
        "      (--include-committee-sigs at export). --require-sigs makes a\n"
        "      sigs-stripped archive fail.\n"
        "  export-state-bundle --rpc-port <N> --genesis <file> --namespace <ns>\n"
        "                      --key <K> --out <file>\n"
        "      Build an OFFLINE state-proof bundle: the FULL anchor block whose\n"
        "      state_root proves (ns,key), the committee-signed successor header\n"
        "      that binds it via prev_hash, and the Merkle state-proof. The\n"
        "      binding is re-verified before the bundle is written, so an\n"
        "      unbindable (chain-head) bundle is never produced.\n"
        "  verify-state-bundle --in <bundle> --genesis <file> [--json]\n"
        "      OFFLINE re-verification of a state-proof bundle (no daemon, no\n"
        "      RPC). Pins the chain identity, recomputes the anchor block_hash,\n"
        "      verifies the successor's committee sigs, requires\n"
        "      successor.prev_hash == recomputed anchor block_hash (binding the\n"
        "      state_root), then Merkle-verifies the proof against that bound\n"
        "      root. VERIFIED -> exit 0; tamper/forgery -> UNVERIFIABLE exit 3.\n"
        "\n"
        "Trustless inclusion proof (--genesis required):\n"
        "  verify-tx-inclusion --rpc-port <N> --genesis <file>\n"
        "                      --tx-hash <hex> --height <B> [--json]\n"
        "      Prove (or disprove) that tx <hex> is in block <B>. Anchors\n"
        "      genesis, fetches block B's full body, verifies its committee\n"
        "      sigs over the block digest (which binds tx_root +\n"
        "      creator_tx_lists), recomputes tx_root from the committed hash\n"
        "      lists, cross-checks the returned body against that set, then\n"
        "      reports INCLUDED / NOT-INCLUDED. A body that doesn't match the\n"
        "      committee-signed hash set is reported UNVERIFIABLE (never a\n"
        "      false INCLUDED). Inclusion is cryptographically anchored: any\n"
        "      historical block is verifiable (its committee sigs travel with\n"
        "      it), unlike state-proofs which the daemon serves head-only.\n"
        "  verify-receipt-inclusion --rpc-port <N> --genesis <file>\n"
        "                           --src-shard <S> --tx-hash <hex> [--json]\n"
        "                           [--wait <seconds>]\n"
        "      Prove (or disprove) that the cross-shard inbound receipt\n"
        "      (src_shard=<S>, tx_hash=<hex>) has been applied on this shard\n"
        "      — i.e. is a member of the committee-verified `i:`\n"
        "      (applied_inbound_receipts) namespace. Anchors genesis,\n"
        "      committee-verifies the header chain to head, computes the\n"
        "      canonical receipt key (\"i:\" + src_shard_be8 + tx_hash),\n"
        "      fetches the `i:`-namespace state-proof, and Merkle-verifies it\n"
        "      against the committee-signed state_root. The proof's key_bytes\n"
        "      must equal the locally-computed key AND its value_hash must\n"
        "      equal SHA256(0x01) (the presence marker) — binding the proof\n"
        "      to THIS receipt, not some other leaf. Receipts are\n"
        "      append-only once applied, so there is no per-block race.\n"
        "      INCLUDED is a sound committee-anchored verdict; NOT-INCLUDED is a\n"
        "      daemon-asserted negative (sound only under the single-daemon\n"
        "      (H-neg) honesty premise, NOT a cryptographic absence proof; --json\n"
        "      tags negative_footing=daemon_asserted). Current\n"
        "      daemons serve the composite-key `i:` namespace (hex-encoded\n"
        "      key body); against a legacy daemon that cannot, the verdict\n"
        "      is UNVERIFIABLE and the command fails closed — never a false\n"
        "      INCLUDED.\n"
        "  verify-merge-state --rpc-port <N> --genesis <file>\n"
        "                     --shard-id <S> --partner-id <P>\n"
        "                     --refugee-region <R> [--json] [--wait <seconds>]\n"
        "      Prove (or disprove) that shard <S> is currently merged into\n"
        "      partner <P> with refugee region <R> — i.e. that the exact\n"
        "      record (partner_id=<P>, refugee_region=<R>) is a member of the\n"
        "      committee-verified `m:` (merge_state) namespace. Anchors\n"
        "      genesis, committee-verifies the header chain to head, computes\n"
        "      the canonical merge key (\"m:\" + shard_id_be4), fetches the\n"
        "      `m:`-namespace state-proof (hex-encoded key body), and Merkle-\n"
        "      verifies it against the committee-signed state_root. The\n"
        "      proof's key_bytes must equal the locally-computed key AND its\n"
        "      value_hash must equal SHA256(u64_be(partner_id) ||\n"
        "      u64_be(region_len) || region) — binding the proof to THIS\n"
        "      merge record, so a daemon lie about the partner or region is\n"
        "      detected, not propagated. INCLUDED is a sound committee-anchored\n"
        "      verdict anchored to the head height; NOT-INCLUDED is a daemon-\n"
        "      asserted negative ((H-neg), negative_footing=daemon_asserted) —\n"
        "      sound only if the daemon answers absences honestly (merge_state\n"
        "      is mutable: a later revert flips INCLUDED back to NOT-INCLUDED).\n"
        "      Any\n"
        "      tamper, mismatch, or daemon refusal → UNVERIFIABLE (exit 3),\n"
        "      never a false INCLUDED.\n"
        "  verify-param-change --rpc-port <N> --genesis <file>\n"
        "                     --effective-height <H> --idx <I> --name <NAME>\n"
        "                     [--value-hex <HEX>] [--json] [--wait <seconds>]\n"
        "      Prove (or disprove) that a staged governance parameter change\n"
        "      — the entry at index <I> within effective-height bucket <H>,\n"
        "      named <NAME> with value <HEX> — is currently a member of the\n"
        "      committee-verified `p:` (pending_param_changes) namespace, i.e.\n"
        "      that it is STILL STAGED (not yet activated). Anchors genesis,\n"
        "      committee-verifies the header chain to head, computes the\n"
        "      canonical key (\"p:\" + eff_be8 + idx_be4), fetches the\n"
        "      `p:`-namespace state-proof (hex-encoded key body), and Merkle-\n"
        "      verifies it against the committee-signed state_root. The\n"
        "      proof's key_bytes must equal the locally-computed key AND its\n"
        "      value_hash must equal SHA256(u64_be(name_len) || name ||\n"
        "      u64_be(value_len) || value) — binding the proof to THIS staged\n"
        "      change, so a daemon lie about the parameter name or value is\n"
        "      detected, not propagated. Use the daemon's `pending_params` RPC\n"
        "      to discover the (effective_height, name, value_hex) to assert;\n"
        "      --idx is the entry's 0-based position within its bucket.\n"
        "      INCLUDED is a sound committee-anchored verdict anchored to the\n"
        "      head height; NOT-INCLUDED is a daemon-asserted negative ((H-neg),\n"
        "      negative_footing=daemon_asserted) — sound only if the daemon\n"
        "      answers absences honestly (pending_param_changes is consumed at\n"
        "      activation: once the chain advances past <H> the same query flips\n"
        "      INCLUDED back to NOT-INCLUDED). Any tamper, mismatch, or daemon refusal →\n"
        "      UNVERIFIABLE (exit 3), never a false INCLUDED.\n"
        "  verify-param-value --rpc-port <N> --genesis <file>\n"
        "                     --name <NAME> --value <U64> [--json] [--wait <seconds>]\n"
        "      Prove (or disprove) that the CURRENT effective value of the\n"
        "      governance-activated consensus scalar <NAME> equals <U64>, by\n"
        "      Merkle-anchoring its committed `k:` (genesis-pinned constants)\n"
        "      leaf to the committee-verified state_root. This is the ACTIVATED\n"
        "      counterpart to verify-param-change: that command proves a change\n"
        "      is still STAGED in `p:`; this command proves the value that is\n"
        "      live RIGHT NOW after activate_pending_params has drained the\n"
        "      bucket into the `k:` scalar. <NAME> is the build_state_leaves\n"
        "      constant name (min_stake, suspension_slash, unstake_delay,\n"
        "      block_subsidy, merge_threshold_blocks, ...), NOT the uppercase\n"
        "      PARAM_CHANGE whitelist token (MIN_STAKE → min_stake). Anchors\n"
        "      genesis, committee-verifies the header chain to head, fetches\n"
        "      the `k:`-namespace state-proof (simple key: the daemon prepends\n"
        "      \"k:\" to the raw name), and Merkle-verifies it against the\n"
        "      committee-signed state_root. The proof's key_bytes must equal\n"
        "      the locally-computed \"k:\"+name; its value_hash is checked\n"
        "      against the locally-recomputed SHA256(u64_be(<U64>)). A match is\n"
        "      a sound MATCH (the asserted value IS the live consensus scalar);\n"
        "      a `k:` leaf that verifies for the key but whose value_hash does\n"
        "      NOT equal SHA256(u64_be(<U64>)) is a sound MISMATCH (the asserted\n"
        "      value is provably NOT the current effective value — distinct\n"
        "      from UNVERIFIABLE because the leaf itself committee-verified).\n"
        "      MATCH / MISMATCH → exit 0; any tamper, key mismatch, malformed\n"
        "      proof, or daemon refusal → UNVERIFIABLE (exit 3), never a false\n"
        "      MATCH.\n"
        "  verify-dapp-registration --rpc-port <N> --genesis <file>\n"
        "                          --domain <D> [--json] [--wait <seconds>]\n"
        "      Prove (or disprove) that domain <D> is CURRENTLY a registered\n"
        "      DApp — i.e. that it is a member of the committee-verified `d:`\n"
        "      (dapp_registry) namespace, the v2.18 sibling of the a:/s:/i:/m:/\n"
        "      p: trustless readers. Anchors genesis, committee-verifies the\n"
        "      header chain to head, fetches the `d:`-namespace state-proof\n"
        "      (simple key: the daemon prepends \"d:\" to the raw domain), and\n"
        "      Merkle-verifies it against the committee-signed state_root. The\n"
        "      load-bearing cross-check: the daemon's `dapp_info` cleartext\n"
        "      (service_pubkey, endpoint_url, topics, retention, metadata, and\n"
        "      the registered_at / active_from / inactive_from heights) is\n"
        "      re-hashed locally — SHA256 over the build_state_leaves `d:`\n"
        "      encoding — and must equal the proof's value_hash, so a daemon\n"
        "      lie about ANY registration field is detected, not propagated.\n"
        "      On INCLUDED the verdict also reports ACTIVE vs INACTIVE derived\n"
        "      from the committee-attested inactive_from vs the anchored head\n"
        "      height (a deactivated DApp keeps its `d:` leaf, so INACTIVE is a\n"
        "      verified verdict, not a daemon claim). INCLUDED is a sound\n"
        "      committee-anchored verdict anchored to the head height;\n"
        "      NOT-INCLUDED is a daemon-asserted negative ((H-neg),\n"
        "      negative_footing=daemon_asserted); any tamper,\n"
        "      cleartext/leaf mismatch, or daemon refusal → UNVERIFIABLE\n"
        "      (exit 3), never a false INCLUDED.\n"
        "  verify-registrant --rpc-port <N> --genesis <file>\n"
        "                    --domain <D> [--json] [--wait <seconds>]\n"
        "      Prove (or disprove) that domain <D> is CURRENTLY a registered\n"
        "      VALIDATOR — i.e. a member of the committee-verified `r:`\n"
        "      (registrants) namespace, the validator-set sibling of the\n"
        "      a:/s:/d: trustless readers. Anchors genesis, committee-verifies\n"
        "      the header chain to head, fetches the `r:`-namespace state-proof\n"
        "      (simple key: the daemon prepends \"r:\" to the raw domain), and\n"
        "      Merkle-verifies it against the committee-signed state_root. The\n"
        "      load-bearing cross-check: the daemon's `account` registry\n"
        "      cleartext (ed_pub, registered_at, active_from, inactive_from,\n"
        "      region) is re-hashed locally — SHA256 over the\n"
        "      build_state_leaves `r:` encoding — and must equal the proof's\n"
        "      value_hash, so a daemon lie about ANY registrant field is\n"
        "      detected, not propagated. On INCLUDED the verdict also reports\n"
        "      ACTIVE vs INACTIVE derived from the committee-attested\n"
        "      active_from / inactive_from vs the anchored head height. A null\n"
        "      `account` registry is consistent ONLY with a state_proof\n"
        "      not_found (else the daemon contradicts itself → UNVERIFIABLE).\n"
        "      INCLUDED → exit 0 (sound, committee-anchored); NOT-INCLUDED →\n"
        "      exit 0 (a daemon-asserted negative, (H-neg) — the null-registry\n"
        "      cross-check catches a self-contradicting daemon, not a consistent\n"
        "      liar; negative_footing=daemon_asserted in --json); any tamper,\n"
        "      value_hash mismatch, or daemon refusal → UNVERIFIABLE (exit 3),\n"
        "      never a false INCLUDED.\n"
        "  verify-notekey --rpc-port <N> --genesis <file>\n"
        "                    --domain <D> [--json] [--wait <seconds>]\n"
        "      NC-8: trustlessly obtain account <D>'s standing recipient note_pk\n"
        "      (the 33-byte P-256 point a sender seals a CONFIDENTIAL_TRANSFER\n"
        "      enote to). Anchors genesis, committee-verifies the header chain,\n"
        "      fetches the `nk:`-namespace state-proof (simple key: \"nk:\"+addr),\n"
        "      and Merkle-verifies it against the committee-signed state_root.\n"
        "      Load-bearing cross-check: the daemon's `account` note_key cleartext\n"
        "      is re-hashed locally — SHA256(note_pk), the build_state_leaves\n"
        "      `nk:` encoding — and must equal the proof's value_hash, so a lie\n"
        "      about the note_pk is detected, not propagated. On INCLUDED the\n"
        "      verdict reports the verified note_pk. INCLUDED → exit 0 (sound,\n"
        "      committee-anchored); NOT-INCLUDED → exit 0 (daemon-asserted,\n"
        "      (H-neg); the null-note_key cross-check catches a self-contradicting\n"
        "      daemon; negative_footing=daemon_asserted in --json); tamper /\n"
        "      value_hash mismatch / refusal → UNVERIFIABLE (exit 3), never a\n"
        "      false INCLUDED.\n"
        "  verify-enote-inclusion --rpc-port <N> --genesis <file>\n"
        "                    --commitment <hex33> --enote <hex> [--json] [--wait <s>]\n"
        "      NC-8: PROVE a scanned encrypted-note delivery is the genuine\n"
        "      on-chain one before trial-decrypting it. Given a (commitment,\n"
        "      ciphertext) pair pulled from a full node's scan_enotes RPC (an\n"
        "      UNTRUSTED source), anchors genesis, committee-verifies the header\n"
        "      chain, fetches the `en:`-namespace state-proof (simple key:\n"
        "      \"en:\"+hex(commitment)), and Merkle-verifies against the\n"
        "      committee-signed state_root. Load-bearing cross-check: the leaf\n"
        "      value is re-hashed locally — SHA256(commitment || enote), the\n"
        "      build_state_leaves `en:` encoding — and must equal the proof's\n"
        "      value_hash, so a node that fabricates or tampers a ciphertext is\n"
        "      caught. INCLUDED → exit 0 (the ciphertext is exactly the committed\n"
        "      delivery — trial-decrypt safe); NOT-INCLUDED → exit 0 (no `en:`\n"
        "      leaf: spent, never delivered, or a FIPS payload-only chain;\n"
        "      daemon-asserted, (H-neg)); value_hash mismatch / tamper / refusal\n"
        "      → UNVERIFIABLE (exit 3), never a false INCLUDED. MODERN-only (FIPS\n"
        "      keeps enotes payload-only, so there is no leaf to prove).\n"
        "  verify-account --rpc-port <N> --genesis <file>\n"
        "                 {--pubkey <64-hex> | --address <0x...>} [--json] [--wait <seconds>]\n"
        "      Derive an anon-account's canonical address LOCALLY and prove\n"
        "      whether it EXISTS on-chain. With --pubkey the address is\n"
        "      `make_anon_address` of the 32-byte Ed25519 key (\"0x\" +\n"
        "      lowercase-hex) — the SAME transform the chain uses for bearer\n"
        "      wallets, so the operator never trusts the daemon to say which\n"
        "      address a key controls. With --address the pubkey is re-derived\n"
        "      and round-tripped to canonical lowercase (S-028), catching a\n"
        "      case-mixed / malformed input locally. Anchors genesis, committee-\n"
        "      verifies the header chain to head, and reports the account\n"
        "      auto-creation lifecycle against the `a:` namespace: a committee-\n"
        "      anchored `a:` Merkle proof → EXISTS (the verified balance +\n"
        "      next_nonce are printed, hash-bound to the daemon's `account`\n"
        "      cleartext); a state_proof not_found at the verified head →\n"
        "      NOT-CREATED (a daemon-asserted negative, sound only under the\n"
        "      single-daemon (H-neg) honesty premise — stronger than the bare\n"
        "      `account` RPC's fabricated zero for unknown addresses, but NOT a\n"
        "      cryptographic absence proof; --json tags\n"
        "      negative_footing=daemon_asserted). Distinct from\n"
        "      balance-trustless, which THROWS on a not_found leaf and cannot\n"
        "      tell \"never created\" from \"created then drained\". EXISTS /\n"
        "      NOT-CREATED → exit 0 (a definite answer); any tamper,\n"
        "      key/leaf mismatch, or daemon refusal → UNVERIFIABLE (exit 3),\n"
        "      never a false EXISTS.\n"
        "\n"
        "Government random-selection — D.5 citizen verifier (--genesis required):\n"
        "  verify-rand --rpc-port <N> --genesis <file> --height <H> [--json]\n"
        "      Authenticate cumulative_rand[H] — the K-of-K commit-reveal MPDH\n"
        "      beacon D.5 draws its seed from. Fetches block H + its successor\n"
        "      H+1, anchors genesis, and binds the seed via S-042: block_hash[H]\n"
        "      (which commits cumulative_rand[H]) must equal block[H+1].prev_hash,\n"
        "      and H+1's committee sigs must verify. committee-authenticated:YES\n"
        "      (exit 0) or UNVERIFIABLE (exit 1) — never a false YES on a swapped\n"
        "      beacon whose successor sig was not rebound.\n"
        "  verify-selection --rpc-port <N> --genesis <file> --domain <D>\n"
        "                   --case-id <hex> [--member <hex>] [--json]\n"
        "      The D.5 citizen check: re-derive a published government random\n"
        "      selection for <case-id> under DApp <domain> and refute any result\n"
        "      that disagrees. Committee-authenticates the FULL block chain and\n"
        "      collects the D.5 roster / case-open / result streams from EVERY\n"
        "      block body (a truncatable dapp hint cannot hide a message — SPEC\n"
        "      §11 3a), picks the first-open-wins canonical case-open, freezes the\n"
        "      roster to its roster_cutoff_height, authenticates the beacon seed\n"
        "      (verify-rand's S-042 binding), then re-runs the lowest-hash draw\n"
        "      (d5_draw) and compares to the published result. With --member\n"
        "      reports whether that id was fairly SELECTED / NOT_SELECTED; without\n"
        "      it reports that the result verifies. NEVER a false SELECTED: any\n"
        "      mismatch, unauthenticated seed, or missing input → UNVERIFIABLE\n"
        "      (exit 1). >1 case-open for one case_id is surfaced as permanent\n"
        "      public EVIDENCE.\n"
        "  verify-selection-offline --blocks <file|-> --domain <D>\n"
        "                   --case-id <hex> --seed-hex <hex> [--member <hex>] [--json]\n"
        "      OFFLINE (no daemon) counterpart of verify-selection: decide the\n"
        "      selection from a JSON ARRAY of ALREADY-committee-authenticated full\n"
        "      blocks (obtained + verified out of band, e.g. verify-chain) plus the\n"
        "      ALREADY-authenticated beacon seed (confirmed via verify-rand). Runs\n"
        "      the same collect + first-open-wins + roster cutoff-freeze + d5_draw\n"
        "      re-derivation (verify_selection_from_blocks) → SELECTED /\n"
        "      NOT_SELECTED / UNVERIFIABLE, never a false SELECTED. Used by the D.5\n"
        "      reference-RP end-to-end (SPEC §12 inc.6b). The CALLER owns the block\n"
        "      committee-authentication + the seed's S-042 binding.\n"
        "\n"
        "Equivocation forensics (offline, no daemon):\n"
        "  verify-equivocation --in <event.json>\n"
        "                      {--pubkey <64-hex> | --committee <file>} [--json]\n"
        "      OFFLINE re-verification of an EquivocationEvent (the FA6\n"
        "      double-sign proof carried by the EQUIVOCATION_EVIDENCE gossip\n"
        "      message + the submit_equivocation RPC). Re-runs the daemon's V11\n"
        "      evidence gate (BlockValidator::check_equivocation_events)\n"
        "      INDEPENDENTLY (EQV-height-bind + EQV-gen-bind form): kind <= 1,\n"
        "      index_a == index_b == block_index, gen_a == gen_b,\n"
        "      body_root_a != body_root_b, sig_a !=\n"
        "      sig_b, and BOTH Ed25519 signatures verify against digests\n"
        "      DERIVED from the (index, gen, body_root) openings under the kind's\n"
        "      domain tag, against the equivocator's registered key. Supply\n"
        "      that key directly with --pubkey, or resolve it from a {domain,\n"
        "      ed_pub}[] committee/genesis-committee file via --committee +\n"
        "      the event's own `equivocator` domain (the key MUST come from a\n"
        "      source YOU trust, never from the event). All conditions holding\n"
        "      is cryptographic proof the signer double-signed at one height —\n"
        "      EQUIVOCATION-PROVEN (exit 0): the record is valid L2-policy\n"
        "      input (L1 applies NO stake or registry consequence — D4). Any\n"
        "      condition failing (unknown kind, mismatched heights, equal\n"
        "      roots, equal sigs, or a sig that does not verify) is\n"
        "      NOT-EQUIVOCATION (exit 3): the evidence does NOT prove a\n"
        "      double-sign, fail-closed, never a false PROVEN. Per FA6\n"
        "      (EquivocationSlashing.md) this has\n"
        "      no false positives under Ed25519 EUF-CMA — an honest validator\n"
        "      can never be PROVEN here. A malformed event / bad hex / unknown\n"
        "      domain is a usage error (exit 1). Read the event from stdin with\n"
        "      --in -.\n"
        "\n"
        "Sharding (offline, no daemon):\n"
        "  shard-route --genesis <file> --address <addr|domain> [--json]\n"
        "      Report which shard OWNS <addr> on the chain pinned by\n"
        "      <genesis>. Reads BOTH routing parameters (initial_shard_count\n"
        "      + shard_address_salt) FROM the genesis — they are CSPRNG-fixed\n"
        "      at build time and bound into compute_genesis_hash, so the home\n"
        "      shard of any address is a function of the chain identity alone.\n"
        "      Re-implements crypto::shard_id_for_address independently of the\n"
        "      daemon's codec (SHA256(salt || \"shard-route\" || addr) folded\n"
        "      to a u64 mod shard_count; shard_count <= 1 routes everything to\n"
        "      shard 0). Anon-form addresses are normalized to canonical\n"
        "      lowercase first (S-028), so 0xABC... and 0xabc... route\n"
        "      identically; domains route on their exact bytes. Prints the\n"
        "      locally computed genesis hash so the operator can confirm the\n"
        "      routing is anchored to the expected chain (a wrong-genesis file\n"
        "      yields a different hash AND, in general, a different shard).\n"
        "      Pure local computation — no RPC. Distinct from `determ where-is`\n"
        "      (which takes count + salt as raw flags): shard-route binds them\n"
        "      to a pinned chain. Exit 0 on a routing; exit 1 on usage /\n"
        "      genesis-parse error.\n"
        "\n"
        "Wire-format tooling (offline, no daemon):\n"
        "  decode-wire --in <file> [--expect-type <NAME>] [--json]\n"
        "      Decode + structurally validate a single Determ binary wire\n"
        "      envelope (A3 / S8 wire-version 1) read from a raw artifact —\n"
        "      the message BODY (the bytes that ride after the transport\n"
        "      layer's [u32 big-endian length] frame header). Self-contained:\n"
        "      re-implements the published envelope spec (src/net/\n"
        "      binary_codec.cpp) INDEPENDENTLY of the daemon's codec, so it is\n"
        "      an external conformance oracle — a producer that drifts from\n"
        "      the documented byte layout is flagged, not trusted. Checks,\n"
        "      fail-closed: 16 MB framing ceiling; magic 0xB1 + version 0x01 +\n"
        "      zero reserved byte; msg_type in [0,18]; the S-022 per-type body\n"
        "      cap (max_message_bytes: 1 MB chatter / 4 MB block-class / 16 MB\n"
        "      snapshot+chain); and payload well-formedness — every one of the\n"
        "      19 types is a fixed binary frame (D2; the last two, the\n"
        "      HEADERS_RESPONSE page of DHF1 header records and the DSN1\n"
        "      SNAPSHOT_RESPONSE record, since inc7c — no JSON payload exists\n"
        "      on the wire), each consumed exactly with every count proven\n"
        "      against the remaining bytes. VALID → exit 0; any spec violation → MALFORMED\n"
        "      (exit 3); I/O or usage error → exit 1. --expect-type asserts\n"
        "      the decoded MsgType name (case-insensitive); a mismatch is\n"
        "      MALFORMED. Use to fuzz/triage captured frames or to confirm a\n"
        "      build's emitted frame conforms to the wire spec.\n"
        "\n"
        "RPC auth tooling (offline, no daemon):\n"
        "  rpc-auth --secret <hex> --method <NAME>\n"
        "           [--params-file <file> | --params-string <json> | --params-stdin]\n"
        "           [--expect <hex>] [--emit-request] [--json]\n"
        "      Compute (or verify) the S-001 HMAC-SHA256 RPC authentication\n"
        "      tag for a single Determ RPC request — the `auth` field the\n"
        "      daemon's RpcServer::verify_auth re-derives and constant-time\n"
        "      compares when rpc_auth_secret is configured. Pure offline\n"
        "      computation (no socket): re-implements the v2.16 scheme from\n"
        "      src/rpc/rpc.cpp INDEPENDENTLY of the daemon's codec, so it is an\n"
        "      external conformance oracle for the tag, not a wrapper around\n"
        "      the daemon's own HMAC. The tag is\n"
        "      HMAC-SHA256(secret, method + \"|\" + params.dump()) hex-encoded,\n"
        "      where params.dump() is nlohmann's compact sorted-key form (the\n"
        "      verifier parses the supplied params JSON and re-dumps it, the\n"
        "      identical parse-then-dump the server performs after receiving\n"
        "      the request — so an object with keys in any order yields the\n"
        "      same canonical tag). --secret is the SAME hex secret the\n"
        "      operator sets as rpc_auth_secret / DETERM_RPC_AUTH_SECRET; it is\n"
        "      HMAC key material, hex-decoded to the raw key bytes (matching\n"
        "      the server's hex_to_bytes(rpc_auth_secret)). Params default to\n"
        "      `{}` when none of --params-file / --params-string /\n"
        "      --params-stdin is given (a no-param method). With --emit-request\n"
        "      the full request object {method, params, auth} is printed ready\n"
        "      to pipe to the daemon's line-framed RPC socket; otherwise just\n"
        "      the bare tag. With --expect <hex> the command VERIFIES instead\n"
        "      of prints: it recomputes the tag and does a constant-time\n"
        "      compare against <hex> (the same length-then-XOR discipline as\n"
        "      the server, no early-exit timing leak), reporting MATCH (exit 0)\n"
        "      or MISMATCH (exit 3). Note: the S-001 tag is a STATELESS\n"
        "      per-(method,params) MAC — it does NOT bind a nonce or timestamp,\n"
        "      so an observed request is replayable; pair an external RPC bind\n"
        "      with rpc_localhost_only or a TLS terminator, exactly as the\n"
        "      server's external-bind warning states. Malformed hex /\n"
        "      unparseable params / missing flags are usage errors (exit 1).\n"
        "\n"
        "Meta:\n"
        "  help, --help, -h    Show this message.\n"
        "  version, --version  Show binary version.\n"
        "\n"
        "Trust model: --genesis pins chain identity; light-client refuses to\n"
        "talk to any daemon whose block 0 doesn't hash to compute_genesis_hash\n"
        "of the supplied JSON. Verified reads cross-check the daemon's\n"
        "cleartext account RPC against state-proofs anchored to the head's\n"
        "state_root — daemon lies are detected, not propagated.\n";
}

// Read full file into a json. Throws on parse failure with a clear
// path-bearing diagnostic.
json read_json_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open: " + path);
    json j;
    try {
        f >> j;
    } catch (const std::exception& e) {
        throw std::runtime_error("parse error in " + path + ": " + e.what());
    }
    return j;
}

void write_json_file(const std::string& path, const json& j) {
    std::ofstream f(path);
    if (!f) throw std::runtime_error("cannot open --out for write: " + path);
    f << j.dump() << "\n";
    if (!f) throw std::runtime_error("write failed on --out: " + path);
}

// Parse a uint64_t-like CLI argument. Throws on invalid input with a
// diagnostic naming the flag.
uint64_t parse_u64(const std::string& flag, const std::string& v) {
    try {
        size_t pos = 0;
        long long n = std::stoll(v, &pos);
        if (pos != v.size())
            throw std::invalid_argument("trailing chars");
        if (n < 0)
            throw std::invalid_argument("negative value");
        return static_cast<uint64_t>(n);
    } catch (const std::exception&) {
        throw std::runtime_error(
            flag + " must be a non-negative integer (got '" + v + "')");
    }
}

uint16_t parse_u16(const std::string& flag, const std::string& v) {
    uint64_t u = parse_u64(flag, v);
    if (u > 65535) throw std::runtime_error(flag + " out of range (>65535)");
    return static_cast<uint16_t>(u);
}

// ──────────────────────── verify-headers ──────────────────────────────

int cmd_verify_headers(int argc, char** argv) {
    std::string in_path;
    std::string genesis_hash_hex;
    std::string prev_hash_hex;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"           && i + 1 < argc) in_path          = argv[++i];
        else if (a == "--genesis-hash" && i + 1 < argc) genesis_hash_hex = argv[++i];
        else if (a == "--prev-hash"    && i + 1 < argc) prev_hash_hex    = argv[++i];
        else {
            std::cerr << "verify-headers: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    try {
        json doc = in_path.empty()
            ? json::parse(std::cin)
            : read_json_file(in_path);
        auto r = verify_headers(doc, genesis_hash_hex, prev_hash_hex);
        if (!r.ok) { std::cerr << r.detail << "\n"; return 1; }
        std::cout << "OK\n"
                  << "  verified:   " << r.count << " header(s)\n"
                  << "  head_hash:  " << r.block_hash_hex << "\n";
        if (!genesis_hash_hex.empty())
            std::cout << "  genesis pin: matches\n";
        else if (!prev_hash_hex.empty())
            std::cout << "  prev pin:    matches\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-headers: " << e.what() << "\n";
        return 1;
    }
}

// ───────────────────── verify-block-sigs ───────────────────────────────

int cmd_verify_block_sigs(int argc, char** argv) {
    std::string header_path, committee_path;
    bool bft = false;
    // LV-1/LV-2 mode-eligibility inputs. --k-block-sigs supplies the genesis
    // k_block_sigs so verify_block_sigs can enforce the node's committee-size
    // gate (MD names exactly K creators; BFT exactly ceil(2K/3)); default 0
    // keeps this primitive's legacy behaviour (membership + quorum-count only).
    // --no-bft-enabled models a genesis with bft_enabled=false (a
    // mutual-distrust-only chain) — any BFT block is then refused.
    size_t k_block_sigs = 0;
    bool bft_enabled = true;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--header"       && i + 1 < argc) header_path    = argv[++i];
        else if (a == "--committee"    && i + 1 < argc) committee_path = argv[++i];
        else if (a == "--bft")                          bft = true;
        else if (a == "--k-block-sigs" && i + 1 < argc)
            k_block_sigs = static_cast<size_t>(std::stoul(argv[++i]));
        else if (a == "--no-bft-enabled")               bft_enabled = false;
        else {
            std::cerr << "verify-block-sigs: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (header_path.empty() || committee_path.empty()) {
        std::cerr << "verify-block-sigs: --header and --committee are required\n";
        return 1;
    }
    try {
        json header_json = read_json_file(header_path);
        json committee_json = read_json_file(committee_path);
        auto r = verify_block_sigs(header_json, committee_json, bft,
                                   k_block_sigs, bft_enabled);
        if (!r.ok) { std::cerr << r.detail << "\n"; return 1; }
        std::cout << "OK\n"
                  << "  mode:      " << (bft ? "BFT" : "MD") << "\n"
                  << "  verified:  " << r.count << " sig(s)\n";
        if (k_block_sigs > 0)
            std::cout << "  k_block_sigs: " << k_block_sigs
                      << " (mode-eligibility enforced)\n";
        std::cout << "  digest:    " << r.digest_hex << "\n";
        if (!r.state_root_hex.empty())
            std::cout << "  state_root: " << r.state_root_hex << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-block-sigs: " << e.what() << "\n";
        return 1;
    }
}

// ───────────────────── block-verify ────────────────────────────────────

// Self-contained OFFLINE single-block verifier — the light-client analogue of
// `determ-wallet block-verify`, but STRICTLY stronger: because determ-light
// links the block/digest code (`light_compute_block_digest`), it verifies the
// committee signatures against a digest it RECOMPUTES ITSELF, so NO operator-
// supplied block_digest is needed (the wallet cannot recompute the digest — it
// does not link the chain library). Composes three checks over a block JSON +
// committee file into one PASS/FAIL:
//   STRUCTURE — required Block::to_json fields present with the right shapes.
//   TX-ROOT   — recompute compute_tx_root(creator_tx_lists) (the sorted-dedup
//               union SHA-256, mirroring src/node/producer.cpp::compute_tx_root)
//               and compare to the stored tx_root.
//   SIGS      — K-of-K (or ceil(2K/3) with --bft) committee Ed25519 sigs over
//               the INTERNALLY-recomputed digest (via verify_block_sigs).
// SCOPE (F-LBV5, see docs/proofs/LightBlockVerifySoundness.md): light_compute_
// block_digest omits the compute_view_root terms producer.cpp::compute_block_
// digest binds for cross-shard inbound receipts + F2-reconciled eq/abort sets
// (those need the rpc_headers-STRIPPED collections to reconstruct), so on a
// cross-shard / F2 block SIGS FAIL-CLOSES (false-negative, never a false PASS —
// verify those against a full node). It DOES bind partner_subset_hash (S-030-D2
// merge dimension), which survives the header strip, so merged-but-non-F2
// blocks verify exactly. Non-cross-shard/non-F2 blocks keep the byte-identical
// v1 digest, so SIGS is exact there.
// Pure local crypto: no RPC, no daemon, no genesis anchor. (--block must be an
// unwrapped Block JSON or a {block:{...}} envelope.) Exit 0 all pass, 2 a check
// FAILED, 1 args/parse/IO error.
int cmd_block_verify(int argc, char** argv) {
    std::string block_path, committee_path;
    bool bft = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--block"     && i + 1 < argc) block_path     = argv[++i];
        else if (a == "--committee" && i + 1 < argc) committee_path = argv[++i];
        else if (a == "--bft")                       bft = true;
        else if (a == "--json")                      json_out = true;
        else {
            std::cerr << "block-verify: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (block_path.empty() || committee_path.empty()) {
        std::cerr << "block-verify: --block and --committee are required\n";
        return 1;
    }

    json block_json, committee_json;
    try {
        block_json     = read_json_file(block_path);
        committee_json = read_json_file(committee_path);
    } catch (const std::exception& e) {
        std::cerr << "block-verify: " << e.what() << "\n";
        return 1;
    }
    if (block_json.is_object() && block_json.contains("block")
        && block_json["block"].is_object()
        && !block_json.contains("creator_tx_lists"))
        block_json = block_json["block"];
    if (!block_json.is_object()) {
        std::cerr << "block-verify: --block JSON is not an object\n";
        return 1;
    }

    struct CheckResult { std::string name, verdict, detail; };
    std::vector<CheckResult> checks;
    int passed = 0, failed = 0;

    // ── STRUCTURE ──
    bool struct_ok = false;
    std::string struct_detail;
    {
        try {
            struct Req { const char* k; int kind; };  // 0 str / 1 num / 2 arr
            const Req reqs[] = {
                {"index", 1}, {"prev_hash", 0}, {"timestamp", 1},
                {"creators", 2}, {"creator_tx_lists", 2},
                {"tx_root", 0}, {"creator_block_sigs", 2},
            };
            for (auto& r : reqs) {
                if (!block_json.contains(r.k))
                    throw std::runtime_error(std::string("missing field '") + r.k + "'");
                const auto& v = block_json[r.k];
                bool ok = (r.kind == 0 && v.is_string())
                       || (r.kind == 1 && v.is_number())
                       || (r.kind == 2 && v.is_array());
                if (!ok)
                    throw std::runtime_error(std::string("field '") + r.k + "' wrong type");
            }
            if (block_json["creators"].empty())
                throw std::runtime_error("creators[] is empty");
            struct_detail = "well-formed (" + std::to_string(block_json["creators"].size())
                          + " creators, "
                          + std::to_string(block_json["creator_block_sigs"].size())
                          + " creator_block_sigs)";
            struct_ok = true;
        } catch (const std::exception& e) { struct_detail = e.what(); }
        if (!json_out)
            std::cout << "--- STRUCTURE ---\n  " << (struct_ok ? "OK: " : "FAIL: ")
                      << struct_detail << "\n";
        checks.push_back({"STRUCTURE", struct_ok ? "PASS" : "FAIL", struct_detail});
        struct_ok ? ++passed : ++failed;
    }

    // ── TX-ROOT ── recompute the sorted-dedup union commitment.
    if (struct_ok) {
        std::string detail;
        bool ok = false;
        try {
            std::vector<Hash> uni;
            for (auto& list : block_json["creator_tx_lists"]) {
                if (!list.is_array())
                    throw std::runtime_error("creator_tx_lists entry is not an array");
                for (auto& hj : list) {
                    if (!hj.is_string())
                        throw std::runtime_error("tx_hash is not a string");
                    uni.push_back(from_hex_arr<32>(hj.get<std::string>()));
                }
            }
            std::sort(uni.begin(), uni.end());
            uni.erase(std::unique(uni.begin(), uni.end()), uni.end());
            determ::crypto::SHA256Builder b;
            for (auto& h : uni) b.append(h);
            std::string computed = to_hex(b.finalize());
            std::string stored = block_json["tx_root"].get<std::string>();
            for (auto& ch : stored) if (ch >= 'A' && ch <= 'F') ch += 32;  // lc
            ok = (computed == stored);
            detail = ok ? ("recomputed == stored (" + std::to_string(uni.size()) + " tx)")
                        : ("mismatch: " + computed + " != stored " + stored);
        } catch (const std::exception& e) { detail = e.what(); }
        if (!json_out)
            std::cout << "--- TX-ROOT ---\n  " << (ok ? "OK: " : "FAIL: ")
                      << detail << "\n";
        checks.push_back({"TX-ROOT", ok ? "PASS" : "FAIL", detail});
        ok ? ++passed : ++failed;
    } else {
        checks.push_back({"TX-ROOT", "SKIP", "STRUCTURE failed — not attempted"});
    }

    // ── SIGS ── verify_block_sigs recomputes the digest internally.
    if (struct_ok) {
        std::string detail;
        bool ok = false;
        try {
            auto r = verify_block_sigs(block_json, committee_json, bft);
            ok = r.ok;
            detail = ok ? (std::to_string(r.count) + " sig(s) over self-recomputed digest "
                             + r.digest_hex.substr(0, 16) + "... (" + (bft ? "BFT" : "MD") + ")")
                        : r.detail;
        } catch (const std::exception& e) { detail = e.what(); }
        if (!json_out)
            std::cout << "--- SIGS ---\n  " << (ok ? "OK: " : "FAIL: ") << detail << "\n";
        checks.push_back({"SIGS", ok ? "PASS" : "FAIL", detail});
        ok ? ++passed : ++failed;
    } else {
        checks.push_back({"SIGS", "SKIP", "STRUCTURE failed — not attempted"});
    }

    // ── CT-PROOFS ── A3: re-verify every confidential tx's range/balance
    // proof CLIENT-SIDE (SIGS proves the committee signed this block;
    // CT-PROOFS proves the confidential validity independent of the
    // committee). Runs off the tx JSON, so a headers-shape input (no
    // transactions[]) verifies vacuously with an explicit 0-count — the
    // count in the detail line is the anti-silent-vacuity signal. Note-SET
    // membership (double-spend) is NOT checkable statelessly — that half is
    // anchored by the committee-signed state_root over the cn: leaves.
    if (struct_ok) {
        auto r = determ::light::verify_ct_transactions(block_json);
        bool ok = r.ok();
        std::string detail;
        if (ok) {
            detail = std::to_string(r.ct_txs) + " confidential tx(s) of "
                   + std::to_string(r.total_txs) + " re-verified client-side"
                   + (r.ct_txs == 0 ? " (none present — vacuous)" : "");
        } else {
            detail = std::to_string(r.failures.size()) + " of "
                   + std::to_string(r.ct_txs) + " confidential tx(s) FAILED: tx["
                   + std::to_string(r.failures[0].index) + "] "
                   + r.failures[0].detail;
        }
        if (!json_out)
            std::cout << "--- CT-PROOFS ---\n  " << (ok ? "OK: " : "FAIL: ")
                      << detail << "\n";
        checks.push_back({"CT-PROOFS", ok ? "PASS" : "FAIL", detail});
        ok ? ++passed : ++failed;
    } else {
        checks.push_back({"CT-PROOFS", "SKIP", "STRUCTURE failed — not attempted"});
    }

    bool overall = (failed == 0);
    if (json_out) {
        json j;
        j["audit"]  = overall ? "PASS" : "FAIL";
        j["passed"] = passed;
        j["failed"] = failed;
        json arr = json::array();
        for (auto& c : checks)
            arr.push_back({{"check", c.name}, {"verdict", c.verdict}, {"detail", c.detail}});
        j["checks"] = arr;
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "\n=== BLOCK-VERIFY SUMMARY ===\n";
        for (auto& c : checks) {
            std::string pad(c.name.size() < 10 ? 10 - c.name.size() : 1, ' ');
            std::cout << "  " << c.name << pad << c.verdict
                      << (c.detail.empty() ? std::string() : "  (" + c.detail + ")")
                      << "\n";
        }
        std::cout << "\nBLOCK-VERIFY: " << (overall ? "PASS" : "FAIL")
                  << " (" << passed << " passed, " << failed << " failed)\n";
    }
    return overall ? 0 : 2;
}

// ──────────────────── verify-ct-tx ──────────────────────────────────────

// A3 client-side CT verification, single-tx form: re-run the confidential
// accept-rule LOCALLY on one transaction JSON (Transaction::to_json shape,
// or a {"tx":{...}} envelope). Pure local crypto — no daemon, no committee,
// no pool state. What it proves / does not prove:
//   PROVES     — the cryptographic CT validity the validator would check:
//                SHIELD commitment/balance proof for the declared amount;
//                UNSHIELD proof CONTEXT-BOUND to this exact
//                (from,to,nonce,amount) — the locally-recomputed digest, so a
//                redirected/replayed proof FAILS here just as at a validator;
//                CONFIDENTIAL_TRANSFER DCT1 range+balance + fee match +
//                intra-bundle duplicate-input rejection.
//   NOT PROVED — note-SET facts (input unspent / output fresh): stateless.
//                Signature validity: use validate-tx / the daemon for that.
// Exit 0 = CT proof VERIFIED; 3 = INVALID (or not a confidential tx — this
// command's verdict must never read as "verified" for a tx it cannot verify);
// 1 = usage/parse/IO.
int cmd_verify_ct_tx(int argc, char** argv) {
    std::string file_path;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--file" && i + 1 < argc) file_path = argv[++i];
        else if (a == "--json")                 json_out = true;
        else {
            std::cerr << "verify-ct-tx: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (file_path.empty()) {
        std::cerr << "verify-ct-tx: --file <tx.json> is required\n";
        return 1;
    }
    json tx_json;
    try {
        tx_json = read_json_file(file_path);
    } catch (const std::exception& e) {
        std::cerr << "verify-ct-tx: " << e.what() << "\n";
        return 1;
    }
    if (tx_json.is_object() && tx_json.contains("tx") && tx_json["tx"].is_object())
        tx_json = tx_json["tx"];

    auto v = determ::light::verify_ct_tx_json(tx_json);
    if (json_out) {
        json j;
        j["verdict"] = (v.is_ct && v.ok) ? "VERIFIED" : "INVALID";
        j["type"]    = v.type;
        j["is_confidential"] = v.is_ct;
        j["detail"]  = v.detail;
        std::cout << j.dump(2) << "\n";
    } else if (v.is_ct && v.ok) {
        std::cout << "VERIFIED: " << v.detail << "\n";
    } else if (!v.is_ct) {
        std::cout << "INVALID: not a confidential transaction (type "
                  << v.type << ") — nothing this verifier can attest\n";
    } else {
        std::cout << "INVALID: " << v.detail << "\n";
    }
    return (v.is_ct && v.ok) ? 0 : 3;
}

// ──────────────────── verify-chain-file ────────────────────────────────

// Self-contained OFFLINE whole-chain verifier — the file-based dual of the
// online `verify-chain` (which fetches over RPC + anchors genesis via
// compute_genesis_hash). Given an EXPORTED headers file (the `export-headers` /
// `headers` RPC `{headers:[...], from, ...}` shape) + a committee file, it
// verifies the entire exported segment with NO daemon:
//   CONTINUITY — the prev_hash chain-of-hashes across the headers
//                (verify_headers), optionally anchored at block 0 via
//                --genesis-hash or at a mid-chain start via --prev-hash.
//   SIGS       — every non-genesis header's K-of-K (or ceil(2K/3) --bft)
//                committee Ed25519 sigs over the INTERNALLY-recomputed digest
//                (verify_block_sigs per header). ONLY index 0 (the genesis) is
//                exempt; a non-genesis header with stripped/empty sigs FAILS
//                (CONTINUITY does not recompute sigs, so the skip must key on
//                index, not on emptiness).
// A single --committee is applied to every block, so it is sound only for a
// segment with NO mid-chain REGISTER/DEREGISTER committee change (same
// limitation as verify_chain_to_head's genesis-seed). To verify ACROSS rotation
// boundaries in one pass, supply --committee-manifest <file> instead: a JSON
// array [{"from":F,"to":T,"committee":"path"}...] mapping inclusive absolute
// index ranges to committee files. Each non-genesis header is verified against
// the committee whose range covers its index; a header no range covers is a
// SIGS FAIL (uncovered block). Pure local crypto; no RPC, no daemon, no
// compute_genesis_hash. (Cross-shard / F2 blocks fail-close in SIGS — see
// block-verify / F-LBV5.) Exit 0 all pass, 2 a check FAILED, 1 args.
int cmd_verify_chain_file(int argc, char** argv) {
    std::string in_path, committee_path, manifest_path, genesis_hash_hex, prev_hash_hex;
    bool bft = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"                && i + 1 < argc) in_path          = argv[++i];
        else if (a == "--committee"         && i + 1 < argc) committee_path   = argv[++i];
        else if (a == "--committee-manifest"&& i + 1 < argc) manifest_path    = argv[++i];
        else if (a == "--genesis-hash"      && i + 1 < argc) genesis_hash_hex = argv[++i];
        else if (a == "--prev-hash"         && i + 1 < argc) prev_hash_hex    = argv[++i];
        else if (a == "--bft")                               bft = true;
        else if (a == "--json")                              json_out = true;
        else {
            std::cerr << "verify-chain-file: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (in_path.empty()) {
        std::cerr << "verify-chain-file: --in is required\n";
        return 1;
    }
    if (committee_path.empty() == manifest_path.empty()) {
        std::cerr << "verify-chain-file: exactly one of --committee / "
                     "--committee-manifest is required\n";
        return 1;
    }

    json doc, committee_json, manifest_json;
    try {
        doc = read_json_file(in_path);
        if (!committee_path.empty()) committee_json = read_json_file(committee_path);
        else                         manifest_json  = read_json_file(manifest_path);
    } catch (const std::exception& e) {
        std::cerr << "verify-chain-file: " << e.what() << "\n";
        return 1;
    }

    // Per-height committee resolver. Single-committee mode returns the same
    // committee for every index; manifest mode picks the range that covers idx
    // and lazily loads (+ caches) its committee file. Returns false if no range
    // covers idx, so an uncovered block becomes a SIGS FAIL rather than a skip.
    std::map<std::string, json> committee_cache;
    auto committee_for = [&](uint64_t idx, json& out, std::string& why) -> bool {
        if (!committee_path.empty()) { out = committee_json; return true; }
        if (!manifest_json.is_array()) { why = "manifest is not a JSON array"; return false; }
        for (auto& e : manifest_json) {
            if (!e.is_object() || !e.contains("from") || !e.contains("to")
                || !e.contains("committee")) continue;
            uint64_t lo = e["from"].get<uint64_t>(), hi = e["to"].get<uint64_t>();
            if (idx < lo || idx > hi) continue;
            std::string cp = e["committee"].get<std::string>();
            auto it = committee_cache.find(cp);
            if (it == committee_cache.end()) {
                try { it = committee_cache.emplace(cp, read_json_file(cp)).first; }
                catch (const std::exception& ex) {
                    why = "committee file '" + cp + "': " + ex.what(); return false;
                }
            }
            out = it->second; return true;
        }
        why = "no manifest range covers block " + std::to_string(idx);
        return false;
    };

    struct CheckResult { std::string name, verdict, detail; };
    std::vector<CheckResult> checks;
    int passed = 0, failed = 0;

    // ── CONTINUITY ──
    bool cont_ok = false;
    std::string cont_detail;
    {
        try {
            auto r = verify_headers(doc, genesis_hash_hex, prev_hash_hex);
            cont_ok = r.ok;
            std::string anchor = genesis_hash_hex.empty()
                ? (prev_hash_hex.empty() ? "" : " (prev-anchored)")
                : " (genesis-anchored)";
            cont_detail = r.ok ? (std::to_string(r.count) + " headers, head "
                                    + r.block_hash_hex.substr(0, 16) + "..." + anchor)
                               : r.detail;
        } catch (const std::exception& e) { cont_detail = e.what(); }
        if (!json_out)
            std::cout << "--- CONTINUITY ---\n  " << (cont_ok ? "OK: " : "FAIL: ")
                      << cont_detail << "\n";
        checks.push_back({"CONTINUITY", cont_ok ? "PASS" : "FAIL", cont_detail});
        cont_ok ? ++passed : ++failed;
    }

    // ── SIGS ── per non-genesis header (only if CONTINUITY passed).
    if (cont_ok) {
        std::string detail;
        bool ok = false;
        try {
            const json& headers = doc.is_array()
                ? doc
                : (doc.contains("headers") ? doc["headers"] : json::array());
            if (!headers.is_array() || headers.empty())
                throw std::runtime_error("no headers array to verify");
            size_t verified = 0, skipped = 0;
            for (auto& h : headers) {
                // ONLY the true genesis (index 0) is exempt from committee-sig
                // verification — it carries no committee sigs by construction and
                // is anchored instead via --genesis-hash in CONTINUITY. We key the
                // skip on `index`, NOT on empty creator_block_sigs: those sigs are
                // not recomputed by CONTINUITY (verify_headers walks the STORED
                // block_hash linkage), so an emptiness-based skip would let an
                // attacker STRIP a real block's sigs to dodge verification. A
                // non-genesis header with absent/empty sigs therefore flows into
                // verify_block_sigs and FAILS (zero present sigs), as it must.
                uint64_t idx = (h.contains("index") && h["index"].is_number())
                    ? h["index"].get<uint64_t>() : UINT64_MAX;
                if (idx == 0) { ++skipped; continue; }  // genesis: no committee sigs
                std::string lbl = idx == UINT64_MAX ? "?" : std::to_string(idx);
                json committee; std::string why;
                if (!committee_for(idx, committee, why))
                    throw std::runtime_error("block " + lbl + ": " + why);
                auto vbs = verify_block_sigs(h, committee, bft);
                if (!vbs.ok)
                    throw std::runtime_error("block " + lbl + ": " + vbs.detail);
                ++verified;
            }
            if (verified == 0 && skipped > 0)
                throw std::runtime_error("only the genesis header present — no committee-signed block to verify");
            ok = true;
            detail = std::to_string(verified) + " block(s) sig-verified"
                   + (skipped ? (" (" + std::to_string(skipped) + " sig-less/genesis skipped)") : "")
                   + (manifest_path.empty() ? "" : " via " + std::to_string(committee_cache.size()) + "-committee manifest")
                   + " (" + (bft ? "BFT" : "MD") + ")";
        } catch (const std::exception& e) { detail = e.what(); }
        if (!json_out)
            std::cout << "--- SIGS ---\n  " << (ok ? "OK: " : "FAIL: ") << detail << "\n";
        checks.push_back({"SIGS", ok ? "PASS" : "FAIL", detail});
        ok ? ++passed : ++failed;
    } else {
        checks.push_back({"SIGS", "SKIP", "CONTINUITY failed — not attempted"});
    }

    bool overall = (failed == 0);
    if (json_out) {
        json j;
        j["audit"]  = overall ? "PASS" : "FAIL";
        j["passed"] = passed;
        j["failed"] = failed;
        json arr = json::array();
        for (auto& c : checks)
            arr.push_back({{"check", c.name}, {"verdict", c.verdict}, {"detail", c.detail}});
        j["checks"] = arr;
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "\n=== VERIFY-CHAIN-FILE SUMMARY ===\n";
        for (auto& c : checks) {
            std::string pad(c.name.size() < 12 ? 12 - c.name.size() : 1, ' ');
            std::cout << "  " << c.name << pad << c.verdict
                      << (c.detail.empty() ? std::string() : "  (" + c.detail + ")")
                      << "\n";
        }
        std::cout << "\nVERIFY-CHAIN-FILE: " << (overall ? "PASS" : "FAIL")
                  << " (" << passed << " passed, " << failed << " failed)\n";
    }
    return overall ? 0 : 2;
}

// ──────────────────────── committee-diff ───────────────────────────────

// Offline diff of two committee files (the `determ validators --json` shape: a
// bare array, or {members:[...]}, of {domain, ed_pub, region, stake, ...}).
// Reports which members were ADDED / REMOVED / KEY-ROTATED (same domain, new
// ed_pub) / REGION-CHANGED / STAKE-CHANGED / UNCHANGED between snapshot A and B.
//
// Purpose: the companion to verify-chain-file --committee-manifest. A single
// --committee is sound only across a NO-rotation segment; committee-diff tells
// an operator WHETHER the SIGNING set changed between two validator snapshots,
// so they know whether one committee covers a headers segment or must build a
// manifest. The "signing set" verdict keys on the (domain, ed_pub) pairs that
// verify_block_sigs actually uses — REGION/STAKE-only changes do NOT alter it
// (they don't affect signature verification). Pure local JSON, no daemon, no
// crypto. Exit 0 signing set IDENTICAL, 2 signing set DIFFERS, 1 args/parse.
int cmd_committee_diff(int argc, char** argv) {
    std::string a_path, b_path;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") {
            std::cout << "Usage: determ-light committee-diff --a <file> --b <file> [--json]\n"
                         "  Offline diff of two committee files (validators --json shape).\n"
                         "  Reports added / removed / key-rotated / region- + stake-changed\n"
                         "  members. SIGNING SET verdict keys on (domain, ed_pub).\n"
                         "  Exit 0 signing set IDENTICAL, 2 DIFFERS, 1 args/parse.\n";
            return 0;
        }
        if      (a == "--a"   && i + 1 < argc) a_path = argv[++i];
        else if (a == "--b"   && i + 1 < argc) b_path = argv[++i];
        else if (a == "--json")                json_out = true;
        else { std::cerr << "committee-diff: unknown arg '" << a << "'\n"; return 1; }
    }
    if (a_path.empty() || b_path.empty()) {
        std::cerr << "committee-diff: --a and --b are required\n";
        return 1;
    }
    json A, B;
    try { A = read_json_file(a_path); B = read_json_file(b_path); }
    catch (const std::exception& e) { std::cerr << "committee-diff: " << e.what() << "\n"; return 1; }

    struct Member { std::string ed_pub, region; long long stake; bool has_stake; };
    auto normalize = [](const json& doc, std::map<std::string, Member>& out, std::string& why) -> bool {
        const json* arr = nullptr;
        if (doc.is_array()) arr = &doc;
        else if (doc.is_object() && doc.contains("members") && doc["members"].is_array()) arr = &doc["members"];
        else { why = "committee file is neither an array nor {members:[...]}"; return false; }
        for (auto& m : *arr) {
            if (!m.is_object() || !m.contains("domain")) { why = "member missing 'domain'"; return false; }
            Member mem;
            mem.ed_pub = m.contains("ed_pub") && m["ed_pub"].is_string() ? m["ed_pub"].get<std::string>() : "";
            for (auto& ch : mem.ed_pub) if (ch >= 'A' && ch <= 'F') ch += 32;  // lc for compare
            mem.region = m.contains("region") ? (m["region"].is_string() ? m["region"].get<std::string>()
                                                                         : m["region"].dump()) : "";
            mem.has_stake = m.contains("stake") && m["stake"].is_number();
            mem.stake = mem.has_stake ? m["stake"].get<long long>() : 0;
            out[m["domain"].get<std::string>()] = mem;
        }
        return true;
    };
    std::map<std::string, Member> ma, mb;
    std::string why;
    if (!normalize(A, ma, why) || !normalize(B, mb, why)) {
        std::cerr << "committee-diff: " << why << "\n";
        return 1;
    }

    std::vector<std::string> added, removed, rotated, region_chg, stake_chg;
    size_t unchanged = 0;
    for (auto& kv : mb) if (!ma.count(kv.first)) added.push_back(kv.first);
    for (auto& kv : ma) {
        auto it = mb.find(kv.first);
        if (it == mb.end()) { removed.push_back(kv.first); continue; }
        if (it->second.ed_pub != kv.second.ed_pub) { rotated.push_back(kv.first); continue; }
        // ed_pub unchanged: region + stake are independent secondary deltas
        // (neither alters the verify_block_sigs signing set).
        bool secondary = false;
        if (it->second.region != kv.second.region) { region_chg.push_back(kv.first); secondary = true; }
        if (it->second.has_stake && kv.second.has_stake && it->second.stake != kv.second.stake) {
            stake_chg.push_back(kv.first); secondary = true;
        }
        if (!secondary) ++unchanged;
    }
    // The verify_block_sigs signing set changes iff a member is added, removed,
    // or its ed_pub rotated; region/stake-only changes leave it intact.
    bool signing_identical = added.empty() && removed.empty() && rotated.empty();

    auto join = [](const std::vector<std::string>& v) {
        std::string s; for (size_t i = 0; i < v.size(); ++i) { if (i) s += ", "; s += v[i]; } return s;
    };
    if (json_out) {
        json j;
        j["signing_set"] = signing_identical ? "IDENTICAL" : "DIFFERS";
        j["added"]         = added;
        j["removed"]       = removed;
        j["key_rotated"]   = rotated;
        j["region_changed"]= region_chg;
        j["stake_changed"] = stake_chg;
        j["unchanged"]     = unchanged;
        j["a_size"]        = ma.size();
        j["b_size"]        = mb.size();
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "=== COMMITTEE-DIFF (A=" << ma.size() << " members, B=" << mb.size() << ") ===\n";
        std::cout << "  added         (" << added.size()      << "): " << join(added)      << "\n";
        std::cout << "  removed       (" << removed.size()    << "): " << join(removed)    << "\n";
        std::cout << "  key-rotated   (" << rotated.size()    << "): " << join(rotated)    << "\n";
        std::cout << "  region-changed(" << region_chg.size() << "): " << join(region_chg) << "\n";
        std::cout << "  stake-changed (" << stake_chg.size()  << "): " << join(stake_chg)  << "\n";
        std::cout << "  unchanged     (" << unchanged         << ")\n";
        std::cout << "\nSIGNING SET: " << (signing_identical ? "IDENTICAL" : "DIFFERS")
                  << (signing_identical
                        ? " (one --committee covers a segment spanning these two snapshots)"
                        : " (rotation — segment the headers file / use --committee-manifest)")
                  << "\n";
    }
    return signing_identical ? 0 : 2;
}

// ───────────────────── verify-state-proof ──────────────────────────────

int cmd_verify_state_proof(int argc, char** argv) {
    std::string in_path, expected_root_hex;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"         && i + 1 < argc) in_path           = argv[++i];
        else if (a == "--state-root" && i + 1 < argc) expected_root_hex = argv[++i];
        else {
            std::cerr << "verify-state-proof: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    try {
        json doc = in_path.empty()
            ? json::parse(std::cin)
            : read_json_file(in_path);
        auto r = verify_state_proof(doc, expected_root_hex);
        if (!r.ok) { std::cerr << r.detail << "\n"; return 1; }
        std::cout << "OK\n"
                  << "  state_root:  " << r.state_root_hex << "\n"
                  << "  proof depth: " << r.count << " sibling hashes\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-state-proof: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────── fetch-headers ────────────────────────────────

int cmd_fetch_headers(int argc, char** argv) {
    uint16_t port = 0;
    uint64_t from = 0;
    uint64_t count = 256;
    std::string out_path;
    bool have_port = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--from"   && i + 1 < argc) {
            from = parse_u64("--from", argv[++i]);
        } else if (a == "--count"  && i + 1 < argc) {
            count = parse_u64("--count", argv[++i]);
        } else if (a == "--out"    && i + 1 < argc) {
            out_path = argv[++i];
        } else {
            std::cerr << "fetch-headers: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port) {
        std::cerr << "fetch-headers: --rpc-port is required\n";
        return 1;
    }
    try {
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "fetch-headers: " << rpc.last_error() << "\n";
            return 1;
        }
        auto reply = rpc.call("headers", {{"from", from}, {"count", count}});
        if (out_path.empty()) {
            std::cout << reply.dump() << "\n";
        } else {
            write_json_file(out_path, reply);
            std::cout << "OK: wrote "
                      << reply.value("count", uint64_t{0})
                      << " header(s) to " << out_path << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fetch-headers: " << e.what() << "\n";
        return 1;
    }
}

// ────────────────────── fetch-validators ───────────────────────────────

// Fetch the current committee/creator set via the `validators` RPC and save it
// (the bare array of {domain, ed_pub, active_from, registered_at, stake,
// region} the daemon's rpc_validators emits). Completes the determ-light-only
// offline workflow: fetch-headers + fetch-validators give an operator both
// inputs for verify-chain-file / committee-diff using ONLY the trust-minimized
// binary (no full determ node needed). This is an unauthenticated read fetch,
// like fetch-headers; the committee it returns is daemon-asserted — derive the
// genuine height-correct set trustlessly via committee-at-height when soundness
// matters. Exit 0 success, 1 RPC failure / args error.
int cmd_fetch_validators(int argc, char** argv) {
    uint16_t port = 0;
    std::string out_path;
    bool have_port = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--out"    && i + 1 < argc) {
            out_path = argv[++i];
        } else {
            std::cerr << "fetch-validators: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port) {
        std::cerr << "fetch-validators: --rpc-port is required\n";
        return 1;
    }
    try {
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "fetch-validators: " << rpc.last_error() << "\n";
            return 1;
        }
        auto reply = rpc.call("validators", json::object());
        size_t n = reply.is_array() ? reply.size() : 0;
        if (out_path.empty()) {
            std::cout << reply.dump() << "\n";
        } else {
            write_json_file(out_path, reply);
            std::cout << "OK: wrote " << n << " validator(s) to " << out_path << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fetch-validators: " << e.what() << "\n";
        return 1;
    }
}

// ────────────────────── fetch-state-proof ──────────────────────────────

int cmd_fetch_state_proof(int argc, char** argv) {
    uint16_t port = 0;
    std::string ns, key, out_path;
    bool have_port = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--ns"    && i + 1 < argc) ns       = argv[++i];
        else if   (a == "--key"   && i + 1 < argc) key      = argv[++i];
        else if   (a == "--out"   && i + 1 < argc) out_path = argv[++i];
        else {
            std::cerr << "fetch-state-proof: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || ns.empty() || key.empty()) {
        std::cerr << "fetch-state-proof: --rpc-port, --ns, --key are required\n";
        return 1;
    }
    try {
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "fetch-state-proof: " << rpc.last_error() << "\n";
            return 1;
        }
        auto reply = rpc.call("state_proof",
            {{"namespace", ns}, {"key", key}});
        if (out_path.empty()) {
            std::cout << reply.dump() << "\n";
        } else {
            write_json_file(out_path, reply);
            std::cout << "OK: wrote state-proof to " << out_path << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "fetch-state-proof: " << e.what() << "\n";
        return 1;
    }
}

// ───────────────────────── verify-chain ────────────────────────────────

int cmd_verify_chain(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path;
    bool have_port = false;
    bool persist = false;
    bool resume = false;
    bool track_registry = false;   // R52: replay REGISTER/DEREGISTER txs
    std::string state_path;  // empty → default_state_path()
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if (a == "--persist") persist = true;
        else if (a == "--resume") resume = true;
        else if (a == "--track-registry") track_registry = true;
        else if (a == "--state" && i + 1 < argc) state_path = argv[++i];
        else {
            std::cerr << "verify-chain: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty()) {
        std::cerr << "verify-chain: --rpc-port and --genesis are required\n";
        return 1;
    }
    // R52: registry replay reconstructs the registrant set from block 0 —
    // a resumed suffix would skip the prefix's REGISTER txs, and the
    // persisted anchor does not capture registry state, so a later --resume
    // would silently lose it. Both are refused rather than degraded.
    if (track_registry && (resume || persist)) {
        std::cerr << "verify-chain: --track-registry requires the full "
                     "from-genesis walk and is incompatible with "
                     "--resume/--persist\n";
        return 1;
    }
    try {
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-chain: " << rpc.last_error() << "\n";
            return 1;
        }

        if (track_registry) {
            // Full from-genesis walk with REGISTER/DEREGISTER replay (see
            // trustless_read.hpp for the trust model). The committee check
            // becomes activity-window-aware: a creator is accepted only when
            // the block index falls inside its [active_from, inactive_from).
            std::string gh = anchor_genesis(rpc, genesis);
            VerifiedChain vc =
                verify_chain_to_head(rpc, committee_seed, gh,
                                     /*track_registry=*/true,
                                     genesis.k_block_sigs, genesis.bft_enabled);
            std::cout << "OK\n"
                      << "  genesis pin:        matches (" << gh << ")\n"
                      << "  height:             " << vc.height << "\n"
                      << "  headers verified:   " << vc.headers_verified << "\n"
                      << "  block sigs:         " << vc.blocks_with_sigs_verified
                      << " verified\n"
                      << "  registry events:    " << vc.registry_events
                      << " REGISTER/DEREGISTER tx(s) replayed\n"
                      << "  head block_hash:    " << vc.head_block_hash << "\n";
            if (!vc.head_state_root.empty())
                std::cout << "  head state_root:    " << vc.head_state_root << "\n";
            return 0;
        }
        // Anchor genesis + verify to head — full from genesis, or (--resume,
        // LSP-6) only the suffix above a cached anchor. anchored_head is the
        // SINGLE source of truth for the resume-or-full decision (shared with the
        // trustless reads): re-pin genesis, fall back to a full verify when the
        // anchor is absent / corrupt / wrong-chain / not-ahead (never weaker), and
        // a fork below the anchor is a HARD error (verify_chain_from_anchor throws).
        const std::string sp = state_path.empty() ? default_state_path() : state_path;
        auto ah = anchored_head(rpc, committee_seed, genesis, resume, sp);
        const std::string& genesis_hash_hex = ah.genesis_hash_hex;
        const VerifiedChain& vc = ah.vc;
        const std::string& resume_note = ah.note;
        const bool did_resume = ah.resumed;

        std::cout << "OK\n"
                  << "  genesis pin:        matches (" << genesis_hash_hex << ")\n";
        if (!resume_note.empty())
            std::cout << "  resume:             " << resume_note << "\n";
        std::cout << "  height:             " << vc.height << "\n"
                  << "  headers verified:   " << vc.headers_verified
                  << (did_resume ? " (suffix only)" : "") << "\n"
                  << "  blocks (sigs):      " << vc.blocks_with_sigs_verified << "\n"
                  << "  head block_hash:    " << vc.head_block_hash << "\n";
        if (!vc.head_state_root.empty())
            std::cout << "  head state_root:    " << vc.head_state_root << "\n";
        else
            std::cout << "  head state_root:    (not populated — pre-S-033 chain)\n";

        // --persist: cache the just-verified anchor so a future invocation can
        // resume from it. The anchor is only ever written AFTER the full
        // committee-verify above succeeds — never on an unverified head. The
        // genesis_hash is the LOCAL recompute (genesis_hash_hex), so the pin a
        // later run re-checks is the operator's own, not the daemon's claim.
        // (When paired with --resume, this advances the cached anchor to the new
        // verified tip — the steady-state `verify-chain --resume --persist` loop.)
        if (persist) {
            LightState s;
            s.schema_version  = 1;
            s.genesis_hash    = genesis_hash_hex;
            s.head_height     = vc.height;
            s.head_block_hash = vc.head_block_hash;
            s.head_state_root = vc.head_state_root;  // "" on a pre-S-033 chain
            save_light_state(sp, s);             // sp computed above (shared with --resume)
            std::cout << "  persisted anchor:   " << sp << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-chain: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────── state (persisted-anchor cache management) ───────────
//
// Offline cache-management surface for the persisted light-client anchor (see
// persist.hpp). No daemon contact:
//   state --show     [--state <path>]   print + VALIDATE the cached anchor
//   state --clear    [--state <path>]   delete the cache file
//   state --selftest [--state <path>]   offline round-trip + reject-path self-test
//
// --selftest exercises the persist module end-to-end with NO daemon: it writes a
// synthetic state, reads it back asserting byte-equality, then asserts every
// fail-closed reject path (malformed JSON, wrong schema_version, short hex). This
// is how save/load/validate is verified on a host where the cluster can't mint
// blocks. It writes only to a temp path it then removes (never the real cache,
// unless --state explicitly points there — then it restores nothing, by design).
int cmd_state(int argc, char** argv) {
    enum { SHOW, CLEAR, SELFTEST, VERIFY, NONE } mode = NONE;
    std::string state_path;    // empty → default_state_path()
    std::string genesis_path;  // for --verify-anchor
    bool json_out = false;     // --show machine-readable output
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--show")          mode = SHOW;
        else if (a == "--clear")         mode = CLEAR;
        else if (a == "--selftest")      mode = SELFTEST;
        else if (a == "--verify-anchor") mode = VERIFY;
        else if (a == "--json")          json_out = true;
        else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if (a == "--state" && i + 1 < argc) state_path = argv[++i];
        else {
            std::cerr << "state: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (json_out && mode != SHOW) {
        std::cerr << "state: --json is only valid with --show\n";
        return 1;
    }
    if (mode == NONE) {
        std::cerr << "state: one of --show / --clear / --selftest / --verify-anchor is required\n";
        return 1;
    }
    if (mode == VERIFY && genesis_path.empty()) {
        std::cerr << "state --verify-anchor: --genesis <file> is required\n";
        return 1;
    }
    const std::string path = state_path.empty() ? default_state_path() : state_path;

    try {
        if (mode == SHOW) {
            if (!light_state_exists(path)) {
                if (json_out) {
                    std::cout << nlohmann::json{{"present", false},
                                                {"path", path}}.dump(2) << "\n";
                } else {
                    std::cout << "no persisted anchor at " << path << "\n"
                              << "  (run `verify-chain --persist` to create one)\n";
                }
                return 0;  // absence is not an error
            }
            LightState s = load_light_state(path);  // throws if corrupt → fail-closed
            // Cache age from the file's mtime, measured on the file clock so no
            // epoch conversion is needed. 0 on any stat error (age is advisory —
            // staleness POLICY lives in the operator tooling, not here).
            uint64_t age_seconds = 0;
            {
                std::error_code ec;
                auto ft = std::filesystem::last_write_time(
                    std::filesystem::path(path), ec);
                if (!ec) {
                    auto d = decltype(ft)::clock::now() - ft;
                    if (d.count() > 0) {
                        age_seconds = static_cast<uint64_t>(
                            std::chrono::duration_cast<std::chrono::seconds>(d)
                                .count());
                    }
                }
            }
            if (json_out) {
                std::cout << nlohmann::json{
                    {"present",         true},
                    {"path",            path},
                    {"schema_version",  s.schema_version},
                    {"genesis_hash",    s.genesis_hash},
                    {"head_height",     s.head_height},
                    {"head_block_hash", s.head_block_hash},
                    {"head_state_root", s.head_state_root},
                    {"age_seconds",     age_seconds}}.dump(2) << "\n";
                return 0;
            }
            std::cout << "persisted anchor (" << path << ")\n"
                      << "  schema_version:     " << s.schema_version << "\n"
                      << "  genesis_hash:       " << s.genesis_hash << "\n"
                      << "  head_height:        " << s.head_height << "\n"
                      << "  head_block_hash:    " << s.head_block_hash << "\n"
                      << "  head_state_root:    "
                      << (s.head_state_root.empty() ? "(pre-S-033 chain)" : s.head_state_root)
                      << "\n"
                      << "  age:                " << age_seconds << "s\n";
            return 0;
        }
        if (mode == VERIFY) {
            // Offline LSP-2 genesis re-pin gate (the offline half of the LSP-6
            // resume): does the persisted anchor belong to the chain the
            // operator's --genesis describes? Recompute the genesis hash LOCALLY
            // (compute_genesis_hash, no daemon) and compare to the cached pin.
            // This is exactly the check a future `verify-chain --resume` must run
            // before trusting an anchor as a verification starting point.
            if (!light_state_exists(path)) {
                std::cerr << "state --verify-anchor: no persisted anchor at " << path
                          << " (run `verify-chain --persist` first)\n";
                return 1;
            }
            LightState s = load_light_state(path);  // throws → fail-closed
            auto genesis = load_genesis(genesis_path);
            std::string local_hex = to_hex(determ::chain::compute_genesis_hash(genesis));
            if (s.genesis_hash == local_hex) {
                std::cout << "PASS: persisted anchor matches --genesis\n"
                          << "  genesis_hash:       " << local_hex << "\n"
                          << "  head_height:        " << s.head_height << "\n"
                          << "  head_block_hash:    " << s.head_block_hash << "\n"
                          << "  (anchor is for THIS chain; a resume could start from it)\n";
                return 0;
            }
            std::cout << "MISMATCH: persisted anchor is for a DIFFERENT chain\n"
                      << "  cached genesis_hash:  " << s.genesis_hash << "\n"
                      << "  --genesis recompute:  " << local_hex << "\n"
                      << "  (stale/wrong-chain cache — clear it before resuming)\n";
            return 2;
        }
        if (mode == CLEAR) {
            if (!light_state_exists(path)) {
                std::cout << "no persisted anchor at " << path << " (nothing to clear)\n";
                return 0;
            }
            std::error_code ec;
            std::filesystem::remove(std::filesystem::path(path), ec);
            if (ec) {
                std::cerr << "state: cannot remove '" << path << "': " << ec.message() << "\n";
                return 1;
            }
            std::cout << "cleared persisted anchor at " << path << "\n";
            return 0;
        }
        // SELFTEST — offline round-trip + reject-path verification over the
        // canonical binary DLS1 container (D2). Each reject case maps 1:1 to
        // a named guard in load_light_state; deleting a guard flips its case.
        const std::string tp = state_path.empty()
            ? (std::filesystem::temp_directory_path() / "determ-light-selftest.bin").string()
            : path;  // honor an explicit --state target if the operator gave one
        int checks = 0, fails = 0;
        auto check = [&](bool cond, const std::string& name) {
            ++checks;
            if (cond) { std::cout << "  PASS " << name << "\n"; }
            else      { std::cout << "  FAIL " << name << "\n"; ++fails; }
        };
        auto load_rejects = [&]() {
            try { load_light_state(tp); } catch (const std::exception&) { return true; }
            return false;
        };
        auto write_bytes = [&](const std::vector<uint8_t>& b2) {
            std::ofstream f(tp, std::ios::binary | std::ios::trunc);
            f.write(reinterpret_cast<const char*>(b2.data()),
                    static_cast<std::streamsize>(b2.size()));
        };
        auto read_bytes = [&]() {
            std::ifstream f(tp, std::ios::binary);
            return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                        std::istreambuf_iterator<char>());
        };

        // (1) round-trip with state_root: save → load → field-equal; 113 bytes
        LightState in;
        in.schema_version  = 1;
        in.genesis_hash    = std::string(64, 'a');
        in.head_height     = 12345;
        in.head_block_hash = std::string(64, 'b');
        in.head_state_root = std::string(64, 'c');
        save_light_state(tp, in);
        const auto full_bytes = read_bytes();
        LightState out = load_light_state(tp);
        check(out.schema_version == in.schema_version &&
              out.genesis_hash == in.genesis_hash &&
              out.head_height == in.head_height &&
              out.head_block_hash == in.head_block_hash &&
              out.head_state_root == in.head_state_root &&
              full_bytes.size() == 113,
              "round-trip preserves every field (113-byte DLS1)");

        // (2) empty state_root round-trips as empty (81-byte container)
        LightState in2 = in; in2.head_state_root.clear();
        save_light_state(tp, in2);
        const auto base_bytes = read_bytes();
        check(load_light_state(tp).head_state_root.empty()
                  && base_bytes.size() == 81,
              "empty head_state_root round-trips as empty (81-byte DLS1)");

        // (3) wrong magic → reject
        { auto b2 = full_bytes; b2[0] = 'X'; write_bytes(b2); }
        check(load_rejects(), "wrong magic is rejected (fail-closed)");

        // (4) schema_version 999 → reject
        { auto b2 = full_bytes; b2[4] = 0xe7; b2[5] = 0x03; write_bytes(b2); }
        check(load_rejects(), "unsupported schema_version is rejected");

        // (5) has_state_root flag = 2 → reject
        { auto b2 = full_bytes; b2[80] = 2; write_bytes(b2); }
        check(load_rejects(), "has_state_root flag 2 is rejected");

        // (6) truncation at EVERY field boundary → reject
        //     (offsets: 3 inside magic, 7 schema, 39 genesis, 47 height,
        //      79 block hash, 80 flag, 112 state root)
        {
            bool all = true;
            for (size_t n : {size_t(3), size_t(7), size_t(39), size_t(47),
                             size_t(79), size_t(80), size_t(112)}) {
                auto b2 = full_bytes;
                b2.resize(n);
                write_bytes(b2);
                if (!load_rejects()) { all = false; break; }
            }
            check(all, "truncation at every field boundary is rejected");
        }

        // (7) trailing byte → reject (both container lengths)
        {
            auto b2 = full_bytes; b2.push_back(0x00); write_bytes(b2);
            bool r1 = load_rejects();
            auto b3 = base_bytes; b3.push_back(0x00); write_bytes(b3);
            bool r2 = load_rejects();
            check(r1 && r2, "trailing byte is rejected (81- and 113-byte forms)");
        }

        // (8) legacy JSON state file → reject (deleted format, D2)
        { std::ofstream f(tp, std::ios::binary | std::ios::trunc);
          f << "{\"schema_version\":1,\"genesis_hash\":\"" << std::string(64,'a')
            << "\",\"head_height\":1,\"head_block_hash\":\"" << std::string(64,'b')
            << "\",\"head_state_root\":\"\"}"; }
        check(load_rejects(), "legacy JSON state file is rejected");

        // cleanup the temp file (only when we used the default temp target)
        if (state_path.empty()) {
            std::error_code ec; std::filesystem::remove(std::filesystem::path(tp), ec);
        }

        std::cout << (fails == 0 ? "SELFTEST PASS " : "SELFTEST FAIL ")
                  << (checks - fails) << "/" << checks << " checks\n";
        return fails == 0 ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "state: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────── cross-check (multi-peer divergence detector) ────────
//
// Closes the single-daemon limitation every light-client proof flags
// (LightClientCompositionMap §6 "single-daemon (no multi-peer cross-check)"):
// verify N independent daemons against the SAME pinned genesis, then require
// every pair of peers reporting the SAME height to agree on (block_hash,
// state_root). Two genesis-anchored, committee-verified chains that disagree at
// a shared height is a provable committee-signed fork / equivocation — a single
// honest canonical chain has exactly one block per height — so it is reported as
// DIVERGENCE and fails closed. A peer merely BEHIND is benign LAG (not an
// attack; not compared, only reported). Soundness rests on the same {A1
// committee-sig EUF-CMA, A2 SHA-256 collision} the per-peer verify-chain already
// assumes; the cross-check adds eclipse / equivocation DETECTION across peers
// WITHOUT weakening any single-peer guarantee (each peer is independently
// fully verified before any comparison). A peer that fails its own
// genesis-anchor or chain verification makes the whole check UNVERIFIABLE
// (fail-closed) — you cannot cross-check against a peer you cannot verify.
//
// Peers: --rpc-port <N> targets localhost:<N> (the local-cluster pattern);
// --peer <host:port> targets a remote daemon (resolved via RpcClient's
// getaddrinfo host path). Cross-HOST peering is the strongest form of this
// defense (independent operators / machines). See MultiPeerCrossCheckSoundness.md.
//
// Exit codes: 0 AGREE (all shared-height groups consistent), 2 DIVERGENCE,
// 3 INCONCLUSIVE (no two peers share a height this round — retry as they
// converge), 1 UNVERIFIABLE (a peer failed verification) or usage error.
int cmd_cross_check(int argc, char** argv) {
    std::string genesis_path;
    std::vector<std::pair<std::string, uint16_t>> endpoints;  // (host, port)
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            endpoints.push_back({"127.0.0.1", parse_u16("--rpc-port", argv[++i])});
        } else if (a == "--peer" && i + 1 < argc) {
            // host:port (cross-HOST peer). Split on the LAST ':'.
            std::string hp = argv[++i];
            auto pos = hp.rfind(':');
            if (pos == std::string::npos || pos == 0 || pos + 1 >= hp.size()) {
                std::cerr << "cross-check: --peer expects host:port (got '" << hp << "')\n";
                return 1;
            }
            endpoints.push_back({hp.substr(0, pos),
                                 parse_u16("--peer port", hp.substr(pos + 1))});
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if (a == "--json")                      json_out = true;
        else { std::cerr << "cross-check: unknown arg '" << a << "'\n"; return 1; }
    }
    if (genesis_path.empty() || endpoints.size() < 2) {
        std::cerr << "cross-check: --genesis and at least two peers "
                     "(--rpc-port <N> for localhost and/or --peer <host:port>) are required\n";
        return 1;
    }

    struct PeerView { std::string label; uint64_t height; std::string block_hash, state_root; };
    std::vector<PeerView> peers;
    try {
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        for (auto& ep : endpoints) {
            std::string label = ep.first + ":" + std::to_string(ep.second);
            RpcClient rpc(ep.first, ep.second);
            if (!rpc.open()) {
                std::cerr << "cross-check: peer " << label << " UNVERIFIABLE (fail-closed): "
                          << rpc.last_error() << "\n";
                return 1;
            }
            try {
                std::string gh = anchor_genesis(rpc, genesis);
                auto vc = verify_chain_to_head(rpc, committee_seed, gh, /*track_registry=*/false, genesis.k_block_sigs, genesis.bft_enabled);
                peers.push_back({label, vc.height, vc.head_block_hash, vc.head_state_root});
            } catch (const std::exception& e) {
                std::cerr << "cross-check: peer " << label << " UNVERIFIABLE (fail-closed): "
                          << e.what() << "\n";
                return 1;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "cross-check: " << e.what() << "\n";
        return 1;
    }

    // Group peers by height; require intra-group agreement on (block_hash, state_root).
    std::map<uint64_t, std::vector<size_t>> by_height;
    for (size_t i = 0; i < peers.size(); ++i) by_height[peers[i].height].push_back(i);
    // NB: explicit comparisons, not std::min/std::max — <windows.h> (pulled in
    // via rpc_client.hpp on Win32) #defines min/max macros that mangle std::min.
    uint64_t min_h = peers[0].height, max_h = peers[0].height;
    for (auto& pv : peers) {
        if (pv.height < min_h) min_h = pv.height;
        if (pv.height > max_h) max_h = pv.height;
    }

    bool any_shared = false, divergence = false;
    std::string diag;
    for (auto& kv : by_height) {
        const auto& idxs = kv.second;
        if (idxs.size() < 2) continue;
        any_shared = true;
        const auto& ref = peers[idxs[0]];
        for (size_t k = 1; k < idxs.size(); ++k) {
            const auto& q = peers[idxs[k]];
            if (q.block_hash != ref.block_hash || q.state_root != ref.state_root) {
                divergence = true;
                diag += "  DIVERGENCE at height " + std::to_string(kv.first) + ":\n"
                      + "    peer " + ref.label + ": block_hash=" + ref.block_hash
                      + " state_root=" + ref.state_root + "\n"
                      + "    peer " + q.label   + ": block_hash=" + q.block_hash
                      + " state_root=" + q.state_root + "\n";
            }
        }
    }

    if (json_out) {
        nlohmann::json j;
        j["peers"] = nlohmann::json::array();
        for (auto& pv : peers)
            j["peers"].push_back({{"peer", pv.label}, {"height", pv.height},
                                  {"block_hash", pv.block_hash}, {"state_root", pv.state_root}});
        j["min_height"] = min_h;
        j["max_height"] = max_h;
        j["verdict"] = divergence ? "DIVERGENCE" : (any_shared ? "AGREE" : "INCONCLUSIVE");
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "cross-check: " << peers.size() << " peers, heights "
                  << min_h << ".." << max_h << "\n";
        for (auto& pv : peers)
            std::cout << "  peer " << pv.label << ": height " << pv.height
                      << " block_hash " << pv.block_hash << "\n";
        if (divergence) std::cout << diag << "VERDICT: DIVERGENCE (committee-signed fork detected)\n";
        else if (!any_shared)
            std::cout << "VERDICT: INCONCLUSIVE — no two peers share a height this round; "
                         "retry as they converge\n";
        else std::cout << "VERDICT: AGREE — all peers sharing a height agree on block_hash + state_root"
                       << (min_h != max_h ? " (some peers lag — benign)" : "") << "\n";
    }
    if (divergence) return 2;
    if (!any_shared) return 3;
    return 0;
}

// ────────────────────── balance-trustless / nonce-trustless ────────────

int cmd_account_trustless(int argc, char** argv,
                           bool want_balance, const std::string& cmd_name) {
    uint16_t port = 0;
    std::string genesis_path, domain, state_path;
    bool have_port = false, json_out = false, resume = false;
    uint64_t wait_seconds = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--domain"  && i + 1 < argc) domain       = argv[++i];
        else if   (a == "--json")                    json_out     = true;
        else if   (a == "--resume")                  resume       = true;
        else if   (a == "--state" && i + 1 < argc)   state_path   = argv[++i];
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << cmd_name << ": unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || domain.empty()) {
        std::cerr << cmd_name
                  << ": --rpc-port, --genesis, --domain are required\n";
        return 1;
    }
    try {
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << cmd_name << ": " << rpc.last_error() << "\n";
            return 1;
        }
        std::string canon_domain = normalize_anon_address(domain);
        // --resume reuses a cached committee-verified anchor (verify only the
        // suffix above it) instead of re-verifying from genesis on every read;
        // falls back to a full verify when the cache is absent/unusable.
        auto view = read_account_trustless(rpc, committee_seed, genesis,
                                            canon_domain, resume, state_path,
                                            wait_seconds);
        if (json_out) {
            json out = {
                {"domain",        canon_domain},
                {"balance",       view.balance},
                {"next_nonce",    view.next_nonce},
                {"height",        view.height},
                {"state_root",    view.state_root_hex},
                {"verified",      true},
            };
            std::cout << out.dump() << "\n";
        } else {
            uint64_t v = want_balance ? view.balance : view.next_nonce;
            const char* tag = want_balance ? "balance" : "next_nonce";
            std::cout << canon_domain << ": " << v << " ("
                      << tag << " verified via state-proof at height "
                      << view.height << ", state_root "
                      << view.state_root_hex.substr(0, 16) << "...)\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << cmd_name << ": " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────────────── stake-trustless ───────────────────────────
//
// Composite trust-minimized read of the stakes ("s:") namespace, the
// exact analogue of read_account_trustless (light/trustless_read.cpp)
// for the accounts ("a:") namespace. Because the trustless-read helper
// in trustless_read.* hard-codes the "a" namespace + `account` RPC +
// (balance, next_nonce) decode, and that lane is closed to this change,
// the stake variant is implemented here in terms of the SAME exported
// verify/anchor primitives (anchor_genesis, verify_chain_to_head,
// verify_state_proof, verify_block_sigs, verify_headers). Only three
// things differ from the account path: the namespace is "s", the
// cleartext cross-check RPC is `stake_info`, and the committed leaf
// encoding is value_hash = SHA256(u64_be(locked) || u64_be(unlock_height))
// (see chain.cpp::build_state_leaves, "stakes_" branch — it mirrors the
// accounts_ branch field-for-field with locked/unlock_height in place of
// balance/next_nonce).

struct StakeView {
    uint64_t    locked{0};
    uint64_t    unlock_height{0};
    std::string state_root_hex;  // head header's state_root the proof verified
    uint64_t    height{0};       // head block index this view is anchored at
};

StakeView read_stake_trustless(
    RpcClient& rpc,
    const std::map<std::string, PubKey>& committee_seed,
    const determ::chain::GenesisConfig& genesis,
    const std::string& domain,
    bool resume = false,
    const std::string& state_path = "",
    uint64_t max_wait_seconds = 0) {

    StakeView sv;

    // 1+2. Anchor genesis + verify the header chain — full, or (resume) only the
    //      suffix above a cached anchor. anchored_head is the single source of
    //      truth (resume=false ≡ anchor_genesis + verify_chain_to_head).
    auto ah = anchored_head(rpc, committee_seed, genesis, resume, state_path);
    std::string genesis_hash_hex = ah.genesis_hash_hex;
    VerifiedChain vc = ah.vc;  // mutable: the race-window logic below advances it

    if (vc.head_state_root.empty()) {
        throw std::runtime_error(
            "stake-trustless: chain has not activated state_root (S-033) — "
            "head header carries no state_root, so state-proofs can't be "
            "anchored. Use the daemon's `stake_info` RPC directly for "
            "chains without S-033 active.");
    }

    // 3. Fetch the state-proof for ("s:", domain). A domain with no stake
    //    leaf yields {"error":"not_found"} here — we fail closed rather
    //    than fabricate a zero.
    auto proof = rpc.call("state_proof",
        {{"namespace", "s"}, {"key", domain}});
    if (proof.contains("error") && !proof["error"].is_null()) {
        throw std::runtime_error(
            "stake-trustless: state_proof RPC error (domain has no verified "
            "stake leaf?): " + proof["error"].dump());
    }

    // 3a. Bind the proof to THIS domain's key. verify_state_proof (step 4)
    //     Merkle-verifies whatever key_bytes the daemon SUPPLIES — it does
    //     not know which key we asked for — so without this check a Byzantine
    //     daemon could serve a valid proof for SOME OTHER `s:` leaf (any
    //     validator's) and the step-6 cleartext hash-bind would still pass
    //     (the daemon also controls the `stake_info` reply, so it makes the
    //     two consistent). That would let it attribute an arbitrary committed
    //     (locked, unlock_height) to `domain` — forging not just NO-STAKE but
    //     ELIGIBLE/LOCKED/BONDED (NegativeVerdictSoundness.md F-6). The key
    //     bind closes it, mirroring verify-account/-registrant/-receipt:
    //     proof.key_bytes MUST equal the locally-computed canonical key
    //     ("s:" || domain), byte-for-byte.
    {
        std::vector<uint8_t> local_key;
        local_key.reserve(2 + domain.size());
        local_key.push_back('s'); local_key.push_back(':');
        local_key.insert(local_key.end(), domain.begin(), domain.end());
        std::string proof_key_hex = proof.value("key_bytes", std::string{});
        std::string local_key_hex = to_hex(local_key.data(), local_key.size());
        if (proof_key_hex != local_key_hex) {
            throw std::runtime_error(
                "stake-trustless: proof.key_bytes=" + proof_key_hex
                + " does not match the canonical s: key " + local_key_hex
                + " — daemon served a proof for a different leaf");
        }
    }

    // 4. Verify the proof self-consistently (Merkle siblings roll up to
    //    the proof's claimed state_root).
    auto vsp = verify_state_proof(proof, {});
    if (!vsp.ok) {
        throw std::runtime_error("stake-trustless: " + vsp.detail);
    }

    // 5. Anchor the proof's claimed state_root to a committee-signed
    //    header. The chain may have advanced during the round-trip, so
    //    proof.height can be > vc.height; bind the proof root to the
    //    header at proof.height - 1 and re-verify its committee sigs.
    //    This is the identical anchoring logic read_account_trustless
    //    uses (kept in lock-step so both namespaces enjoy the same
    //    chain-advanced-during-round-trip guarantee).
    uint64_t proof_height = proof.value("height", uint64_t{0});
    std::string proof_root = proof.value("state_root", std::string{});
    if (proof_height < vc.height) {
        throw std::runtime_error(
            "stake-trustless: proof.height=" + std::to_string(proof_height)
            + " is BEFORE verified-chain head=" + std::to_string(vc.height)
            + " — daemon is serving stale state");
    }
    // SOUNDNESS: the committee signs compute_block_digest, which EXCLUDES
    // state_root. The daemon's state_root FIELD on a stripped header is NOT
    // committee-attested and can be swapped after signing, so we do NOT
    // trust it. Bind proof_root to the COMMITTEE-SIGNED root committed by
    // the block at proof_height-1 via committee_bound_state_root (fetches
    // the full block, recomputes block_hash, verifies the successor
    // header's sigs, requires successor.prev_hash == recomputed hash). This
    // is identical to read_account_trustless / verify_state_root_at.
    {
        json committee_json;
        {
            json arr = json::array();
            for (auto& [domain_, pk] : committee_seed) {
                arr.push_back({{"domain", domain_}, {"ed_pub", to_hex(pk)}});
            }
            committee_json = json{{"members", arr}};
        }
        uint64_t anchor_index = proof_height - 1;
        std::string attested = determ::light::committee_bound_state_root(rpc, committee_json, anchor_index, max_wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
        if (attested != proof_root) {
            throw std::runtime_error("stake-trustless: SECURITY — committee-attested "
                "state_root at index " + std::to_string(anchor_index) + " = " + attested
                + " does NOT match proof.state_root = " + proof_root
                + " — daemon served a proof against an unattested root");
        }
        vc.head_state_root = attested;  // downstream reporting uses the ATTESTED root
        vc.height = proof_height;
    }

    // 6. Fetch the cleartext (locked, unlock_height) via `stake_info`,
    //    recompute the committed leaf hash, and confirm it matches the
    //    verified value_hash. With step 3a binding the proof to THIS
    //    domain's key, the two binds together are load-bearing: the key
    //    bind fixes WHICH leaf, and this value-hash bind fixes the leaf's
    //    contents — a daemon lying in the `stake_info` cleartext is caught
    //    because the recomputed hash no longer matches the (key-bound)
    //    leaf's value_hash. Encoding matches build_state_leaves exactly:
    //    SHA256(u64_be(locked) || u64_be(unlock_height)).
    auto si = rpc.call("stake_info", {{"domain", domain}});
    if (si.contains("error") && !si["error"].is_null()) {
        throw std::runtime_error(
            "stake-trustless: stake_info RPC error: " + si["error"].dump());
    }
    uint64_t locked = si.value("locked",        uint64_t{0});
    uint64_t unlock = si.value("unlock_height", uint64_t{0});

    determ::crypto::SHA256Builder b;
    b.append(locked);
    b.append(unlock);
    Hash computed_value_hash = b.finalize();

    Hash proof_value_hash = from_hex_arr<32>(
        proof["value_hash"].get<std::string>());

    if (computed_value_hash != proof_value_hash) {
        throw std::runtime_error(
            "stake-trustless: TAMPERED — daemon's `stake_info` reply "
            "(locked=" + std::to_string(locked)
            + ", unlock_height=" + std::to_string(unlock)
            + ") hashes to " + to_hex(computed_value_hash)
            + " but state-proof's value_hash is "
            + to_hex(proof_value_hash)
            + " — daemon is lying about either the cleartext OR the proof");
    }

    sv.locked = locked;
    sv.unlock_height = unlock;
    sv.state_root_hex = vc.head_state_root;
    sv.height = vc.height;
    return sv;
}

int cmd_stake_trustless(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, domain, state_path;
    bool have_port = false, json_out = false, resume = false;
    uint64_t wait_seconds = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--domain"  && i + 1 < argc) domain       = argv[++i];
        else if   (a == "--json")                    json_out     = true;
        else if   (a == "--resume")                  resume       = true;
        else if   (a == "--state" && i + 1 < argc)   state_path   = argv[++i];
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "stake-trustless: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || domain.empty()) {
        std::cerr << "stake-trustless: "
                     "--rpc-port, --genesis, --domain are required\n";
        return 1;
    }
    try {
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "stake-trustless: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string canon_domain = normalize_anon_address(domain);
        auto view = read_stake_trustless(rpc, committee_seed, genesis,
                                         canon_domain, resume, state_path,
                                         wait_seconds);
        if (json_out) {
            json out = {
                {"domain",        canon_domain},
                {"locked",        view.locked},
                {"unlock_height", view.unlock_height},
                {"height",        view.height},
                {"state_root",    view.state_root_hex},
                {"verified",      true},
            };
            std::cout << out.dump() << "\n";
        } else {
            std::cout << canon_domain << ": locked=" << view.locked
                      << " unlock_height=" << view.unlock_height
                      << " (verified via state-proof at height "
                      << view.height << ", state_root "
                      << view.state_root_hex.substr(0, 16) << "...)\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "stake-trustless: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────── verify-abort-record ──────────────────────────
//
// Trust-minimized read of the `b:` (abort_records) namespace — the S-032
// cache of FA5 Phase-1 block-production aborts per node. Proves the
// committee-attested (count, last_block) for a node's abort record at the
// verified head, or a NOT-RECORDED verdict when the node has no record.
//
// Like stake-trustless (`s:`) this DISCOVERS + verifies: it Merkle-verifies
// the `b:` leaf against the COMMITTEE-BOUND state_root (committee_bound_state_root,
// the S-042 successor binding) AND hash-binds the daemon's `abort_records` RPC
// cleartext to the proven value_hash (= SHA256(u64_be(count) ‖ u64_be(last_block)),
// matching chain.cpp::build_state_leaves), so a lying daemon can neither inflate
// nor hide a node's abort count without detection. A `not_found` for the
// canonical key is reported NOT-RECORDED — a DAEMON-ASSERTED negative, sound only
// under the single-daemon (H-neg) honesty premise (NegativeVerdictSoundness.md
// NV-2/NV-3; tagged `negative_footing=daemon_asserted` in --json). The
// trust-minimized complement to operator_slashing_ledger.sh for auditing
// committee-instability / abort suspensions. `--wait` (default 0) forwards to
// the head-anchored binding exactly as on the other readers.
int cmd_verify_abort_record(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, domain, state_path;
    bool have_port = false, json_out = false, resume = false;
    uint64_t wait_seconds = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--domain"  && i + 1 < argc) domain       = argv[++i];
        else if   (a == "--json")                    json_out     = true;
        else if   (a == "--resume")                  resume       = true;
        else if   (a == "--state" && i + 1 < argc)   state_path   = argv[++i];
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "verify-abort-record: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || domain.empty()) {
        std::cerr << "verify-abort-record: "
                     "--rpc-port, --genesis, --domain are required\n";
        return 1;
    }
    try {
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-abort-record: " << rpc.last_error() << "\n";
            return 1;
        }

        // 1+2. Anchor genesis + committee-verify the header chain to head
        //      (full, or --resume only the suffix above a cached anchor).
        auto ah = anchored_head(rpc, committee_seed, genesis, resume, state_path);
        VerifiedChain vc = ah.vc;
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so state-proofs can't be anchored.");
        }

        // 3. Fetch the `b:` state-proof. A `not_found` for the canonical key
        //    means the node has NO abort record — a clean NOT-RECORDED, not an
        //    error.
        auto proof = rpc.call("state_proof",
            {{"namespace", "b"}, {"key", domain}});
        bool recorded = true;
        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].dump();
            if (err.find("not_found") != std::string::npos) recorded = false;
            else throw std::runtime_error(
                "state_proof RPC error: " + err);
        }

        if (!recorded) {
            // NOT-RECORDED — a daemon-asserted negative (NV-2/NV-3): sound only
            // under the single-daemon (H-neg) negative-honesty premise.
            if (json_out) {
                json out = {
                    {"domain",           domain},
                    {"verdict",          "NOT-RECORDED"},
                    {"count",            0},
                    {"verified",         true},
                    {"negative_footing", "daemon_asserted"},
                };
                std::cout << out.dump() << "\n";
            } else {
                std::cout << domain << ": NOT-RECORDED (no committee-verified "
                             "b: leaf — node has no Phase-1 abort record; "
                             "daemon-asserted absence)\n";
            }
            return 0;
        }

        // 3a. Bind the proof to THIS domain's key. verify_state_proof (step 4)
        //     Merkle-verifies whatever key_bytes the daemon SUPPLIES — without
        //     this check a Byzantine daemon could serve a valid proof for SOME
        //     OTHER `b:` leaf and lie consistently in the abort_records
        //     cleartext (step 6 binds the cleartext to the SERVED leaf, not to
        //     this domain's), attributing an arbitrary committed
        //     (count, last_block) to `domain` — e.g. laundering a heavily-
        //     aborted node behind a clean node's record (the F-6 forge class,
        //     NegativeVerdictSoundness.md). proof.key_bytes MUST equal the
        //     locally-computed canonical key ("b:" || domain), byte-for-byte.
        {
            std::vector<uint8_t> local_key;
            local_key.reserve(2 + domain.size());
            local_key.push_back('b'); local_key.push_back(':');
            local_key.insert(local_key.end(), domain.begin(), domain.end());
            std::string proof_key_hex = proof.value("key_bytes", std::string{});
            std::string local_key_hex = to_hex(local_key.data(), local_key.size());
            if (proof_key_hex != local_key_hex) {
                throw std::runtime_error(
                    "proof.key_bytes=" + proof_key_hex
                    + " does not match the canonical b: key " + local_key_hex
                    + " — daemon served a proof for a different leaf");
            }
        }

        // 4. Verify the proof self-consistently (siblings roll up to its root).
        auto vsp = verify_state_proof(proof, {});
        if (!vsp.ok) {
            throw std::runtime_error(vsp.detail);
        }

        // 5. Bind the proof's claimed state_root to a COMMITTEE-SIGNED root via
        //    the block at proof_height-1 (committee_bound_state_root, S-042).
        uint64_t proof_height = proof.value("height", uint64_t{0});
        std::string proof_root = proof.value("state_root", std::string{});
        if (proof_height < vc.height) {
            throw std::runtime_error(
                "proof.height=" + std::to_string(proof_height)
                + " is BEFORE verified-chain head=" + std::to_string(vc.height)
                + " — daemon is serving stale state");
        }
        json committee_json;
        {
            json arr = json::array();
            for (auto& [domain_, pk] : committee_seed)
                arr.push_back({{"domain", domain_}, {"ed_pub", to_hex(pk)}});
            committee_json = json{{"members", arr}};
        }
        uint64_t anchor_index = proof_height - 1;
        std::string attested = determ::light::committee_bound_state_root(rpc, committee_json, anchor_index, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
        if (attested != proof_root) {
            throw std::runtime_error("SECURITY — committee-attested state_root at "
                "index " + std::to_string(anchor_index) + " = " + attested
                + " does NOT match proof.state_root = " + proof_root
                + " — daemon served a proof against an unattested root");
        }

        // 6. Fetch the cleartext (count, last_block) via `abort_records`,
        //    recompute the committed leaf hash, and confirm it matches the
        //    proven value_hash. A daemon could serve an honest proof for THIS
        //    domain while lying in the cleartext; the hash recomputation forces
        //    consistency. Encoding matches build_state_leaves exactly:
        //    value_hash = SHA256(u64_be(count) || u64_be(last_block)).
        auto records = rpc.call("abort_records", json::object());
        if (!records.is_array()) {
            throw std::runtime_error(
                "abort_records RPC did not return a JSON array");
        }
        bool found = false;
        uint64_t count = 0, last_block = 0;
        for (auto& r : records) {
            if (r.value("domain", std::string{}) == domain) {
                count      = r.value("count",      uint64_t{0});
                last_block = r.value("last_block", uint64_t{0});
                found = true;
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(
                "INCONSISTENT — the b: state-proof proves a committed abort leaf "
                "for '" + domain + "' but the daemon's abort_records cleartext "
                "omits it (daemon lying about either the proof or the cleartext)");
        }

        determ::crypto::SHA256Builder b;
        b.append(count);
        b.append(last_block);
        Hash computed_value_hash = b.finalize();
        Hash proof_value_hash = from_hex_arr<32>(
            proof["value_hash"].get<std::string>());
        if (computed_value_hash != proof_value_hash) {
            throw std::runtime_error(
                "TAMPERED — daemon's abort_records reply (count="
                + std::to_string(count) + ", last_block="
                + std::to_string(last_block) + ") hashes to "
                + to_hex(computed_value_hash)
                + " but the state-proof's value_hash is "
                + to_hex(proof_value_hash)
                + " — daemon is lying about either the cleartext OR the proof");
        }

        if (json_out) {
            json out = {
                {"domain",     domain},
                {"verdict",    "RECORDED"},
                {"count",      count},
                {"last_block", last_block},
                {"height",     proof_height},
                {"state_root", attested},
                {"verified",   true},
            };
            std::cout << out.dump() << "\n";
        } else {
            std::cout << domain << ": RECORDED count=" << count
                      << " last_block=" << last_block
                      << " (verified via b: state-proof at height "
                      << proof_height << ", state_root "
                      << attested.substr(0, 16) << "...)\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-abort-record: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────── verify-constant ──────────────────────────────
//
// Trust-minimized read of the `k:` (genesis-pinned constants) namespace.
// verify-param-value already reads the 12 u64 k: constants; the deltas here:
// shard_salt coverage (32-byte leaf), a CLOSED compiled-in name whitelist
// (unknown names rejected before any RPC), --resume, and a MISMATCH-exit-2
// contract (verify-param-value exits 0 on MISMATCH). k: has NO cleartext RPC,
// so CONFIRM-shaped: the OPERATOR asserts (name, value), the reader proves it.
//
// Both verdicts are CRYPTOGRAPHIC (not daemon-asserted): every `k:` leaf is
// unconditionally emitted by chain.cpp::build_state_leaves on an S-033 chain,
// the proof is key-bound to "k:"+name and Merkle-bound to the committee-
// attested state_root (committee_bound_state_root, S-042), and value_hash =
// SHA256(u64_be(value)) is injective over u64 in practice — so CONFIRMED
// means the committee attests exactly the asserted value, and MISMATCH means
// it attests a DIFFERENT one (modulo an A2 collision). A `not_found` is
// UNVERIFIABLE (exit 3), never a negative: constants always exist, so absence
// = a legacy (pre-S-033) or lying daemon. The 12 u64 constants take
// --value <u64>; shard_salt (a 32-byte leaf, value_hash = SHA256(salt)) takes
// --value-hex <64-hex>. Unknown names are rejected with the canonical list
// (the NV-5a canonical-key discipline: the daemon never picks the key).
// Use cases: audit that a daemon's chain runs the governance parameters the
// operator expects (min_stake, unstake_delay, subsidy schedule, shard
// topology) without trusting its config or logs.
static const char* kKnownU64Constants[] = {
    "block_subsidy", "subsidy_pool_initial", "subsidy_mode",
    "lottery_jackpot_multiplier", "min_stake", "suspension_slash",
    "unstake_delay", "merge_threshold_blocks", "revert_threshold_blocks",
    "merge_grace_blocks", "shard_count", "my_shard_id",
};

int cmd_verify_constant(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, name, value_hex, state_path;
    bool have_port = false, have_value = false, json_out = false,
         resume = false;
    uint64_t value = 0, wait_seconds = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--name"    && i + 1 < argc) name         = argv[++i];
        else if   (a == "--value"   && i + 1 < argc) {
            value = parse_u64("--value", argv[++i]); have_value = true;
        } else if (a == "--value-hex" && i + 1 < argc) value_hex  = argv[++i];
        else if   (a == "--json")                    json_out     = true;
        else if   (a == "--resume")                  resume       = true;
        else if   (a == "--state" && i + 1 < argc)   state_path   = argv[++i];
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "verify-constant: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || name.empty()) {
        std::cerr << "verify-constant: "
                     "--rpc-port, --genesis, --name are required\n";
        return 1;
    }
    // Canonical-name gate (NV-5a discipline): only the known k: leaves are
    // queryable, and the value-form must match the leaf's encoding.
    bool is_salt = (name == "shard_salt");
    bool is_u64 = false;
    for (auto* n : kKnownU64Constants) if (name == n) { is_u64 = true; break; }
    if (!is_salt && !is_u64) {
        std::cerr << "verify-constant: unknown constant '" << name
                  << "'. Known u64 constants:";
        for (auto* n : kKnownU64Constants) std::cerr << " " << n;
        std::cerr << "; plus shard_salt (use --value-hex <64-hex>)\n";
        return 1;
    }
    if (is_u64 && !have_value) {
        std::cerr << "verify-constant: '" << name
                  << "' is a u64 constant — pass --value <u64>\n";
        return 1;
    }
    if (is_salt && value_hex.empty()) {
        std::cerr << "verify-constant: shard_salt is a 32-byte leaf — pass "
                     "--value-hex <64-hex>\n";
        return 1;
    }

    try {
        // The asserted value's expected leaf hash, per build_state_leaves:
        // u64 constants: SHA256(u64_be(value)); shard_salt: SHA256(salt_32).
        Hash expected_value_hash;
        if (is_u64) {
            determ::crypto::SHA256Builder b;
            b.append(value);
            expected_value_hash = b.finalize();
        } else {
            Hash salt = from_hex_arr<32>(value_hex);  // throws on bad hex/len
            determ::crypto::SHA256Builder b;
            b.append(salt);
            expected_value_hash = b.finalize();
        }

        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-constant: " << rpc.last_error() << "\n";
            return 1;
        }

        // 1+2. Anchor genesis + committee-verify the header chain to head.
        auto ah = anchored_head(rpc, committee_seed, genesis, resume, state_path);
        VerifiedChain vc = ah.vc;
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so state-proofs can't be anchored.");
        }

        // 3. Fetch the k: state-proof. Constants are UNCONDITIONALLY committed
        //    by build_state_leaves, so not_found is never a sound negative —
        //    it is a legacy daemon or a refusal → UNVERIFIABLE (exit 3).
        auto proof = rpc.call("state_proof",
            {{"namespace", "k"}, {"key", name}});
        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].dump();
            if (json_out) {
                json out = {
                    {"name",     name},
                    {"verdict",  "UNVERIFIABLE"},
                    {"verified", false},
                    {"detail",   "daemon refused the k: state-proof (" + err
                                 + ") — constants are always committed, so "
                                   "this is a legacy or lying daemon"},
                };
                std::cout << out.dump() << "\n";
            } else {
                std::cerr << "verify-constant: UNVERIFIABLE — daemon refused "
                             "the k: proof (" << err << "); constants are "
                             "always committed on an S-033 chain\n";
            }
            return 3;
        }

        // 3a. Key-bind: proof.key_bytes MUST equal "k:" || name (the F-6
        //     forge-class closure — without it the daemon could prove a
        //     DIFFERENT constant's leaf whose value happens to match).
        {
            std::vector<uint8_t> local_key;
            local_key.reserve(2 + name.size());
            local_key.push_back('k'); local_key.push_back(':');
            local_key.insert(local_key.end(), name.begin(), name.end());
            std::string proof_key_hex = proof.value("key_bytes", std::string{});
            std::string local_key_hex = to_hex(local_key.data(), local_key.size());
            if (proof_key_hex != local_key_hex) {
                throw std::runtime_error(
                    "proof.key_bytes=" + proof_key_hex
                    + " does not match the canonical k: key " + local_key_hex
                    + " — daemon served a proof for a different leaf");
            }
        }

        // 4. Verify the proof self-consistently.
        auto vsp = verify_state_proof(proof, {});
        if (!vsp.ok) {
            throw std::runtime_error(vsp.detail);
        }

        // 5. Bind the proof's claimed state_root to a COMMITTEE-SIGNED root
        //    (committee_bound_state_root, S-042; --wait forwarded).
        uint64_t proof_height = proof.value("height", uint64_t{0});
        std::string proof_root = proof.value("state_root", std::string{});
        if (proof_height < vc.height) {
            throw std::runtime_error(
                "proof.height=" + std::to_string(proof_height)
                + " is BEFORE verified-chain head=" + std::to_string(vc.height)
                + " — daemon is serving stale state");
        }
        json committee_json;
        {
            json arr = json::array();
            for (auto& [domain_, pk] : committee_seed)
                arr.push_back({{"domain", domain_}, {"ed_pub", to_hex(pk)}});
            committee_json = json{{"members", arr}};
        }
        uint64_t anchor_index = proof_height - 1;
        std::string attested = determ::light::committee_bound_state_root(rpc, committee_json, anchor_index, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
        if (attested != proof_root) {
            throw std::runtime_error("SECURITY — committee-attested state_root at "
                "index " + std::to_string(anchor_index) + " = " + attested
                + " does NOT match proof.state_root = " + proof_root
                + " — daemon served a proof against an unattested root");
        }

        // 6. The verdict: the committee-bound leaf's value_hash either equals
        //    the asserted value's hash (CONFIRMED) or it does not (MISMATCH —
        //    the committee attests a DIFFERENT value than asserted). Both are
        //    sound under A2; no cleartext RPC is consulted.
        Hash proof_value_hash = from_hex_arr<32>(
            proof["value_hash"].get<std::string>());
        bool confirmed = (proof_value_hash == expected_value_hash);

        if (json_out) {
            json out = {
                {"name",       name},
                {"verdict",    confirmed ? "CONFIRMED" : "MISMATCH"},
                {"height",     proof_height},
                {"state_root", attested},
                {"verified",   true},
            };
            if (is_u64) out["asserted_value"] = value;
            else        out["asserted_value_hex"] = value_hex;
            std::cout << out.dump() << "\n";
        } else if (confirmed) {
            std::cout << name << ": CONFIRMED — the committee attests exactly "
                      << (is_u64 ? std::to_string(value) : value_hex)
                      << " (verified via k: state-proof at height "
                      << proof_height << ", state_root "
                      << attested.substr(0, 16) << "...)\n";
        } else {
            std::cout << name << ": MISMATCH — the committee-attested k: leaf "
                         "commits a DIFFERENT value than the asserted "
                      << (is_u64 ? std::to_string(value) : value_hex)
                      << " (sound under A2; the chain does not run this "
                         "parameter value)\n";
        }
        return confirmed ? 0 : 2;
    } catch (const std::exception& e) {
        std::cerr << "verify-constant: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────── verify-unstake-eligibility ───────────────────────
//
// THEME (R11): staking lifecycle & stake-unlock accounting. A novel
// stake-lifecycle trustless reader — distinct from stake-trustless (which
// reports the raw committed (locked, unlock_height) pair) in that it
// computes the height-RELATIVE eligibility verdict: would an UNSTAKE tx
// mined at the committee-verified head be ACCEPTED?
//
// ─── The predicate it re-enforces ───────────────────────────────────────
//
// The chain admits an UNSTAKE only when the spending block's height has
// reached the staker's unlock_height. The validator's S-017 gate
// (src/node/validator.cpp::BlockValidator::check_tx) rejects the tx when
//     b.index < chain.stake_unlock_height(tx.from)
// and the producer's build_body filter (src/node/producer.cpp) and the
// chain apply path (chain.cpp::apply_transactions) enforce the identical
// `b.index < unlock_height` test. A tx submitted now would land in the
// NEXT block, whose index is H+1 for a verified head at H. So the
// eligibility predicate this reader re-runs over the COMMITTEE-ATTESTED
// unlock_height is exactly:
//     eligible  ⟺  locked > 0  ∧  unlock_height ≠ UINT64_MAX
//                                ∧  (H + 1) ≥ unlock_height
//
// ─── Why this is trustless (and not a stake_info wrapper) ────────────────
//
// BOTH inputs to the predicate are committee-anchored, never daemon-
// asserted: (1) the head height H comes from verify_chain_to_head (every
// header's prev_hash continuity + per-block committee sigs checked back to
// the pinned genesis); (2) the unlock_height comes from read_stake_trustless,
// which Merkle-verifies the s:-namespace leaf against the committee-signed
// state_root AND hash-binds the daemon's `stake_info` cleartext
// (SHA256(u64_be(locked) || u64_be(unlock_height))) to the proof's
// value_hash. A daemon that lies about either the head height or the
// unlock_height is caught by stake-trustless's existing fail-closed paths
// (→ UNVERIFIABLE), so a false ELIGIBLE is unreachable. This adds NO new
// crypto: it composes the existing single-leaf s: read with the validator's
// own arithmetic.
//
// ─── Verdicts ───────────────────────────────────────────────────────────
//   ELIGIBLE     locked>0, a matured unlock_height ≤ H+1  → exit 0
//   LOCKED       locked>0, H+1 < unlock_height (< MAX)     → exit 0 (+blocks)
//   BONDED       locked>0, unlock_height == UINT64_MAX     → exit 0
//                  (genesis/active stake with no unlock scheduled; the
//                   operator must DEREGISTER first to start the timer)
//   NO-STAKE     locked==0 (or no s: leaf)                 → exit 0
//   UNVERIFIABLE any tamper / mismatch / daemon refusal    → exit 3
// All four definite verdicts exit 0; ELIGIBLE / LOCKED / BONDED and the
// proven-zero NO-STAKE arm (present s: leaf, locked==0) are SOUND committee-
// anchored answers, while the not_found NO-STAKE arm is a daemon-asserted
// negative ((H-neg), NegativeVerdictSoundness.md NV-2/NV-3). Only a refusal-
// to-assert is non-zero (exit 3). A transport / parse / usage fault exits 1,
// matching the rest of the binary.

enum class UnstakeVerdict { ELIGIBLE, LOCKED, BONDED, NO_STAKE, UNVERIFIABLE };

const char* unstake_verdict_str(UnstakeVerdict v) {
    switch (v) {
        case UnstakeVerdict::ELIGIBLE:     return "ELIGIBLE";
        case UnstakeVerdict::LOCKED:       return "LOCKED";
        case UnstakeVerdict::BONDED:       return "BONDED";
        case UnstakeVerdict::NO_STAKE:     return "NO-STAKE";
        case UnstakeVerdict::UNVERIFIABLE: return "UNVERIFIABLE";
    }
    return "UNVERIFIABLE";
}

int cmd_verify_unstake_eligibility(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, domain;
    bool have_port = false, json_out = false;
    uint64_t wait_seconds = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--domain"  && i + 1 < argc) domain       = argv[++i];
        else if   (a == "--json")                    json_out     = true;
        else if   (a == "--wait" && i + 1 < argc)    wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "verify-unstake-eligibility: unknown arg '"
                      << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || domain.empty()) {
        std::cerr << "verify-unstake-eligibility: "
                     "--rpc-port, --genesis, --domain are required\n";
        return 1;
    }

    UnstakeVerdict verdict = UnstakeVerdict::UNVERIFIABLE;
    uint64_t locked = 0, unlock_height = 0, head_height = 0;
    uint64_t spend_height = 0;       // H + 1: the height an UNSTAKE would land at
    uint64_t blocks_remaining = 0;   // for LOCKED: unlock_height - spend_height
    std::string state_root_hex, canon_domain, detail;

    try {
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-unstake-eligibility: "
                      << rpc.last_error() << "\n";
            return 1;
        }
        canon_domain = normalize_anon_address(domain);

        // The committee-anchored (locked, unlock_height, head height) read.
        // A domain with no s: leaf throws inside read_stake_trustless (the
        // daemon's state_proof returns not_found); we treat that ONE case as
        // NO-STAKE — a DAEMON-ASSERTED negative, sound only under the
        // single-daemon (H-neg) honesty premise (NegativeVerdictSoundness.md
        // NV-2/NV-3) — and let every other failure (sig break, root mismatch,
        // cleartext/leaf tamper, any non-not_found refusal) surface as
        // UNVERIFIABLE so a lying daemon can never coerce a false ELIGIBLE.
        bool have_stake = true;
        try {
            // --wait (default 0) forwards to the embedded stake read, which
            // anchors at the head: without it the S-042 successor binding
            // fails closed there (UNVERIFIABLE), same as the other readers.
            auto sv = read_stake_trustless(rpc, committee_seed, genesis,
                                           canon_domain, /*resume=*/false,
                                           /*state_path=*/"", wait_seconds);
            locked        = sv.locked;
            unlock_height = sv.unlock_height;
            head_height   = sv.height;
            state_root_hex = sv.state_root_hex;
        } catch (const std::exception& e) {
            std::string msg = e.what();
            // Match ONLY the absence marker. read_stake_trustless's step-3
            // throw prefixes EVERY state_proof RPC error with "domain has
            // no verified stake leaf?", so the former second find-disjunct
            // on that prefix classified ANY daemon refusal (malformed key,
            // rate limit, RPC-layer error) as NO-STAKE instead of
            // UNVERIFIABLE — the opposite of the fail-closed intent
            // (NegativeVerdictSoundness.md F-5; fixed alongside the
            // F-1/F-2 a: closure; ratcheted by test_light_negative_footing).
            if (msg.find("not_found") != std::string::npos) {
                have_stake = false;   // daemon-asserted NO-STAKE ((H-neg))
            } else {
                throw;                // any other refusal → UNVERIFIABLE
            }
        }

        if (!have_stake || locked == 0) {
            verdict = UnstakeVerdict::NO_STAKE;
            detail = have_stake
                ? "stake leaf present but locked == 0 — nothing to unstake"
                : "no committee-verified s: leaf for domain — never staked";
        } else {
            // A tx submitted now mines into the NEXT block: height H + 1.
            // S-017 admits the UNSTAKE iff (H + 1) >= unlock_height. Guard
            // the +1 against the bonded sentinel (UINT64_MAX) so we report
            // BONDED rather than overflow the spend height.
            spend_height = (head_height == UINT64_MAX)
                ? UINT64_MAX : head_height + 1;
            if (unlock_height == UINT64_MAX) {
                verdict = UnstakeVerdict::BONDED;
                detail = "unlock_height == UINT64_MAX — stake is bonded with "
                         "no unlock scheduled; DEREGISTER to start the timer";
            } else if (spend_height >= unlock_height) {
                verdict = UnstakeVerdict::ELIGIBLE;
                detail = "spend_height (H+1) has reached unlock_height — an "
                         "UNSTAKE at the verified head would pass the S-017 gate";
            } else {
                verdict = UnstakeVerdict::LOCKED;
                blocks_remaining = unlock_height - spend_height;
                detail = "spend_height (H+1) is below unlock_height — the "
                         "S-017 gate would reject an UNSTAKE for "
                         + std::to_string(blocks_remaining) + " more block(s)";
            }
        }

        const char* tag = unstake_verdict_str(verdict);
        if (json_out) {
            json out = {
                {"domain",        canon_domain},
                {"verdict",       tag},
                {"locked",        locked},
                {"unlock_height", unlock_height},
                {"head_height",   head_height},
                {"spend_height",  spend_height},
                {"verified",      true},
            };
            if (verdict == UnstakeVerdict::LOCKED)
                out["blocks_remaining"] = blocks_remaining;
            // F-2 (NegativeVerdictSoundness.md): NO-STAKE has TWO sources with
            // DIFFERENT footings — leaf-present-with-locked==0 is a committee-
            // anchored POSITIVE proof of a zero stake (a cryptographically
            // sound negative, A1+A2), while leaf-absent is a daemon-asserted
            // not_found ((H-neg), NV-2/NV-3). Tag which one this verdict is so
            // a consumer applies NV-6 clause (2) vs (3) by machine.
            if (verdict == UnstakeVerdict::NO_STAKE && have_stake)
                out["negative_footing"] = "cryptographic";
            if (verdict == UnstakeVerdict::NO_STAKE && !have_stake)
                out["negative_footing"] = "daemon_asserted";
            if (!state_root_hex.empty())
                out["state_root"] = state_root_hex;
            if (!detail.empty()) out["detail"] = detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << canon_domain << ": " << tag << "\n";
            std::cout << "  locked:         " << locked << "\n";
            if (verdict != UnstakeVerdict::NO_STAKE) {
                std::cout << "  unlock_height:  ";
                if (unlock_height == UINT64_MAX)
                    std::cout << "UINT64_MAX (bonded — no unlock scheduled)\n";
                else
                    std::cout << unlock_height << "\n";
                std::cout << "  head_height:    " << head_height << "\n";
                std::cout << "  spend_height:   " << spend_height
                          << " (H+1 — where an UNSTAKE would land)\n";
                if (verdict == UnstakeVerdict::LOCKED)
                    std::cout << "  blocks_remaining: " << blocks_remaining
                              << "\n";
                std::cout << "  state_root:     " << state_root_hex << "\n";
            }
            if (!detail.empty())
                std::cout << "  detail:         " << detail << "\n";
        }

        // Exit codes match verify-account: every definite verdict (ELIGIBLE /
        // LOCKED / BONDED / NO-STAKE) → 0; UNVERIFIABLE → 3 (refused to
        // assert). Note UNVERIFIABLE only reaches here via --json's catch;
        // the non-json path below maps a thrown exception to exit 1.
        if (verdict == UnstakeVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        // A sig break / root mismatch / cleartext-leaf tamper rethrown from
        // read_stake_trustless lands here. Fail closed: report UNVERIFIABLE,
        // NEVER a bare daemon-reported eligibility.
        if (json_out) {
            json out = {
                {"domain",   canon_domain.empty() ? domain : canon_domain},
                {"verdict",  "UNVERIFIABLE"},
                {"verified", false},
                {"detail",   e.what()},
            };
            std::cout << out.dump() << "\n";
            return 3;
        }
        std::cerr << "verify-unstake-eligibility: " << e.what() << "\n";
        return 3;
    }
}

// ──────────────────────── account-history ──────────────────────────────

int cmd_account_history(int argc, char** argv) {
    AccountHistoryOptions opts;
    bool have_port = false, have_from = false, have_to = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            opts.rpc_port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) {
            opts.genesis_path = argv[++i];
        } else if (a == "--domain"  && i + 1 < argc) {
            opts.domain = argv[++i];
        } else if (a == "--from"    && i + 1 < argc) {
            opts.from = parse_u64("--from", argv[++i]); have_from = true;
        } else if (a == "--to"      && i + 1 < argc) {
            opts.to = parse_u64("--to", argv[++i]); have_to = true;
        } else if (a == "--step"    && i + 1 < argc) {
            opts.step = parse_u64("--step", argv[++i]);
        } else if (a == "--wait"    && i + 1 < argc) {
            opts.wait_seconds = parse_u64("--wait", argv[++i]);
        } else if (a == "--json") {
            opts.json_out = true;
        } else {
            std::cerr << "account-history: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || opts.genesis_path.empty() || opts.domain.empty()
        || !have_from || !have_to) {
        std::cerr << "account-history: --rpc-port, --genesis, --domain, "
                     "--from, --to are required\n";
        return 1;
    }
    try {
        return run_account_history(opts);
    } catch (const std::exception& e) {
        std::cerr << "account-history: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────── verify-state-root ────────────────────────────

int cmd_verify_state_root(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path;
    uint64_t height = 0;
    uint64_t wait_seconds = 0;
    bool have_port = false, have_height = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--height"  && i + 1 < argc) {
            height = parse_u64("--height", argv[++i]); have_height = true;
        } else if (a == "--json")                    json_out     = true;
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "verify-state-root: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || !have_height) {
        std::cerr << "verify-state-root: --rpc-port, --genesis, --height "
                     "are required\n";
        return 1;
    }
    try {
        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-state-root: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        auto r = verify_state_root_at(rpc, committee_seed, genesis_hash_hex, height, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);

        if (json_out) {
            json out = {
                {"height",             r.height},
                {"state_root",         r.state_root_hex},
                {"committee_size",     r.committee_size},
                {"sigs_verified",      r.sigs_verified},
                {"committee_verified", r.committee_verified},
            };
            if (!r.detail.empty()) out["detail"] = r.detail;
            std::cout << out.dump() << "\n";
        } else if (r.ok) {
            std::cout << "OK\n"
                      << "  genesis pin:        matches (" << genesis_hash_hex << ")\n"
                      << "  height:             " << r.height << "\n";
            if (r.height == 0) {
                // Genesis is anchored by hash — it has no committee sigs.
                std::cout << "  anchor:             genesis hash "
                             "(block 0 has no committee sigs)\n";
            } else {
                std::cout << "  committee sigs:     " << r.sigs_verified
                          << " of " << r.committee_size << " verified\n";
            }
            std::cout << "  block_hash:         " << r.block_hash_hex << "\n";
            if (r.state_root_present)
                std::cout << "  state_root:         " << r.state_root_hex << "\n";
            else
                std::cout << "  state_root:         (not populated — "
                             "pre-S-033 chain)\n";
        } else {
            // Verification failed (chain break, sig failure, out-of-range,
            // malformed reply). Fail closed: print the diagnostic, exit
            // non-zero, NEVER emit a bare daemon-reported root.
            std::cerr << "verify-state-root: " << r.detail << "\n";
            return 1;
        }

        // Exit code: ok → 0; not-ok (in --json mode the diagnostic is in
        // the object, but the command still failed) → 1.
        return r.ok ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "verify-state-root: " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────────────── verify-ct-block ────────────────────────────
// A3 composition (register A3 backlog: "a composed anchored verify-ct-block
// --rpc convenience"). Fetch block[H] from a LIVE daemon and, in ONE trustless
// command, prove three things against the pinned genesis:
//
//   (1) ANCHOR   — header[H] chains to the pinned genesis by an unbroken
//                  prev_hash walk and is committee-attested (verify_state_root_at
//                  — the S-042 successor-binding primitive). Yields the
//                  committee-anchored block_hash(H).
//   (2) BODY-PIN — the FULL block the daemon serves recomputes to EXACTLY that
//                  committee-anchored block_hash. A doctored body (swapped /
//                  injected tx) changes compute_hash → fail-closed. This is the
//                  same full-block-recompute trust step trustless_read / verify-
//                  chain rely on; it binds transactions[] to the committee sig.
//   (3) CT-PROOFS— every confidential tx in the (now committee-authenticated)
//                  body re-verifies its range/balance proof CLIENT-SIDE
//                  (verify_ct_transactions — the A3 accept-rule mirror).
//
// This is the RPC-driven form of the offline `block-verify` (which runs off a
// block+committee FILE): here the committee is DERIVED from the pinned genesis
// (untrusted-daemon posture) and the block is fetched + anchored, not supplied.
// Adds NO new crypto — pure composition of shipped, audited primitives. Honest
// scope unchanged: CRYPTOGRAPHIC validity only. Note-SET / double-spend
// rejection stays anchored by the committee-signed state_root over cn: leaves —
// this proves the block is real + its CT proofs are valid, not that its input
// notes were unspent. Proof: docs/proofs/CtBlockVerificationComposition.md.
int cmd_verify_ct_block(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path;
    uint64_t height = 0, wait_seconds = 0;
    bool have_port = false, have_height = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) { port = parse_u16("--rpc-port", argv[++i]); have_port = true; }
        else if (a == "--genesis"  && i + 1 < argc) genesis_path = argv[++i];
        else if (a == "--height"   && i + 1 < argc) { height = parse_u64("--height", argv[++i]); have_height = true; }
        else if (a == "--wait"     && i + 1 < argc) wait_seconds = parse_u64("--wait", argv[++i]);
        else if (a == "--json")                     json_out = true;
        else {
            std::cerr << "verify-ct-block: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || !have_height) {
        std::cerr << "verify-ct-block: --rpc-port, --genesis, --height are required\n";
        return 1;
    }
    try {
        // Pin the chain identity + derive the committee from genesis (NOT a
        // user-supplied committee file — the untrusted-daemon posture).
        auto genesis        = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-ct-block: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // (1) ANCHOR — genesis-chain walk + committee attestation (S-042).
        auto sr = verify_state_root_at(rpc, committee_seed, genesis_hash_hex, height, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
        if (!sr.ok) {
            if (json_out) {
                json out = {{"height", height}, {"committee_verified", false},
                            {"ok", false}, {"detail", "ANCHOR failed: " + sr.detail}};
                std::cout << out.dump() << "\n";
            } else {
                std::cerr << "verify-ct-block: ANCHOR failed: " << sr.detail << "\n";
            }
            return 3;
        }

        // (2) BODY-PIN — fetch the full block and require its recomputed
        //     block_hash == the committee-anchored block_hash from (1).
        json full = rpc.call("block", {{"index", height}});
        if (!full.is_object()
            || (full.contains("error") && !full["error"].is_null())) {
            std::string d = (full.is_object() && full.contains("error"))
                          ? full["error"].dump()
                          : "daemon returned no block object";
            if (json_out) {
                std::cout << json{{"height", height}, {"committee_verified", true},
                                  {"ok", false},
                                  {"detail", "full-block fetch failed: " + d}}.dump() << "\n";
            } else {
                std::cerr << "verify-ct-block: full-block fetch failed: " << d << "\n";
            }
            return 3;
        }
        std::string body_hash;
        try {
            determ::chain::Block fb = determ::chain::Block::from_json(full);
            body_hash = to_hex(fb.compute_hash());
        } catch (const std::exception& e) {
            if (json_out) {
                std::cout << json{{"height", height}, {"committee_verified", true},
                                  {"ok", false},
                                  {"detail", std::string("malformed full block: ") + e.what()}}.dump() << "\n";
            } else {
                std::cerr << "verify-ct-block: malformed full block: " << e.what() << "\n";
            }
            return 3;
        }
        if (body_hash != sr.block_hash_hex) {
            std::string d = "BODY-PIN mismatch: full-block hash " + body_hash
                          + " != committee-anchored block_hash " + sr.block_hash_hex
                          + " (daemon served a body inconsistent with the signed header)";
            if (json_out) {
                std::cout << json{{"height", height}, {"committee_verified", true},
                                  {"body_pinned", false}, {"ok", false},
                                  {"detail", d}}.dump() << "\n";
            } else {
                std::cerr << "verify-ct-block: " << d << "\n";
            }
            return 3;
        }

        // (3) CT-PROOFS — re-verify every confidential tx client-side. A
        //     block with no CT txs verifies vacuously with an explicit
        //     0-count (the anti-silent-vacuity signal).
        auto ct = determ::light::verify_ct_transactions(full);
        bool ok = ct.ok();

        if (json_out) {
            json out = {
                {"height",             height},
                {"genesis_pin",        genesis_hash_hex},
                {"committee_verified", true},
                {"sigs_verified",      sr.sigs_verified},
                {"committee_size",     sr.committee_size},
                {"block_hash",         sr.block_hash_hex},
                {"body_pinned",        true},
                {"total_txs",          ct.total_txs},
                {"ct_txs",             ct.ct_txs},
                {"ct_verified",        ct.verified},
                {"ok",                 ok},
            };
            if (!ok) {
                json fails = json::array();
                for (auto& f : ct.failures)
                    fails.push_back({{"index", f.index}, {"type", f.type},
                                     {"detail", f.detail}});
                out["ct_failures"] = fails;
            }
            std::cout << out.dump() << "\n";
        } else {
            std::cout << (ok ? "OK\n" : "FAIL\n")
                      << "  genesis pin:        matches (" << genesis_hash_hex << ")\n"
                      << "  height:             " << height << "\n";
            if (height == 0)
                std::cout << "  anchor:             genesis hash (block 0 has no committee sigs)\n";
            else
                std::cout << "  committee sigs:     " << sr.sigs_verified
                          << " of " << sr.committee_size
                          << " (successor-attested; block_hash chained from genesis)\n";
            std::cout << "  body pin:           full-block hash == committee-anchored block_hash ("
                      << sr.block_hash_hex.substr(0, 16) << "...)\n"
                      << "  CT-PROOFS:          " << ct.verified << " of " << ct.ct_txs
                      << " confidential tx(s) re-verified client-side"
                      << (ct.ct_txs == 0 ? " (none present — vacuous)" : "")
                      << " [" << ct.total_txs << " tx total]\n";
            if (!ok) {
                std::cout << "  CT-PROOFS FAILURES:\n";
                for (auto& f : ct.failures)
                    std::cout << "    tx[" << f.index << "] type " << f.type
                              << ": " << f.detail << "\n";
            }
        }
        return ok ? 0 : 3;
    } catch (const std::exception& e) {
        std::cerr << "verify-ct-block: " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────────── verify-shardtip-records ────────────────────────
//
// D3.5e-7e / S-036 Layer 2 — the THIRD-PARTY auditor that closes the light-
// client trust residual of the shard-tip distress-record fold. It re-runs, off
// an untrusted daemon, the exact check validator.cpp::check_shardtip_witnesses
// runs at block accept: every ShardTipRecord folded into a BEACON block must
// carry its full-tip witness, and that witness must re-verify against the
// beacon's OWN committed cc:[E_source] committee checkpoint — the frozen source
// committee. A fully-Byzantine K-of-K beacon that fabricates a distress record
// cannot produce a witness whose K-of-K sigs verify against the FROZEN source
// committee, so the auditor rejects it, matching every honest node.
//
// Composition (adds NO new crypto — all shipped, audited primitives):
//   (1) ANCHOR   — verify_state_root_at: genesis pin + [0,H] prev_hash walk +
//                  committee-sig verification of header[H] (S-042 successor
//                  binding) → the committee-anchored block_hash(H).
//   (2) BODY-PIN — fetch the FULL block; its recomputed compute_hash() must
//                  equal the committee-anchored block_hash. signing_bytes binds
//                  shard_tip_witnesses_root (e-7c), so this authenticates the
//                  folded records[] AND witnesses[] against the committee sig.
//   (3) CC-PIN   — for each record's source epoch E_source, fetch the cc:[E]
//                  checkpoint CONTENT (cc_checkpoint RPC — UNTRUSTED), recompute
//                  the cc: leaf hash from that preimage, and Merkle-verify the
//                  "cc"-namespace state_proof for E against the COMMITTEE-SIGNED
//                  state_root (committee_bound_state_root — never the bare header
//                  field, which compute_block_digest excludes). A pass makes the
//                  frozen epoch_rand + member list committee-attested.
//   (4) WITNESS  — with the now-trusted cc: pool the auditor re-derives the
//                  frozen source committee (epoch_committee_seed + select_m_
//                  creators, region-filtered), verifies the witness's K-of-K
//                  sigs over light_compute_block_digest(witness) against the
//                  frozen member keys, recomputes committee_sig_root, and
//                  requires it == the carried record's committee_sig_root, plus
//                  the anti-reuse binds (index/source_shard_id/eligible_count)
//                  and the genesis-committed region.
//
// Scope: cc:[E] must still be within the daemon's 16-epoch checkpoint ring at
// the current head (else the state_proof returns not_found → fail-closed
// UNVERIFIABLE, never a false ACCEPT). Archive-replay beyond the ring is a
// future extension. Honest scope: CRYPTOGRAPHIC provenance of the fold only —
// this proves each folded record was attested by the genuine frozen source
// committee, closing the beacon-fabrication hole; it does not opine on whether
// the source shard's underlying distress was "real" (that is the source
// committee's K-of-K responsibility, which this transitively anchors).
// Proof: docs/proofs/ShardTipMergeClosureSoundness.md §9.6.
namespace {

// A cc:[E] checkpoint whose preimage has been PINNED to a committee-signed
// state_root (step 3). members are in the checkpoint's stored (domain-sorted)
// order — identical to select_committee_pool's frozen-path iteration order.
struct CcTrustedCheckpoint {
    Hash                                                   epoch_rand{};
    std::vector<std::tuple<std::string, PubKey, std::string>> members;  // domain, ed_pub, region
};

// Local mirror of producer.cpp::compute_view_root (set-dedup + concat SHA256).
// determ-light does not link producer.cpp, and verify.cpp's copy is file-local;
// this is byte-identical (same primitive both sides recompute).
Hash shardtip_view_root(const std::vector<Hash>& items) {
    std::set<Hash> u(items.begin(), items.end());
    crypto::SHA256Builder b;
    for (auto& h : u) b.append(h);
    return b.finalize();
}

} // namespace

int cmd_verify_shardtip_records(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path;
    uint64_t height = 0, wait_seconds = 0;
    bool have_port = false, have_height = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) { port = parse_u16("--rpc-port", argv[++i]); have_port = true; }
        else if (a == "--genesis"  && i + 1 < argc) genesis_path = argv[++i];
        else if (a == "--height"   && i + 1 < argc) { height = parse_u64("--height", argv[++i]); have_height = true; }
        else if (a == "--wait"     && i + 1 < argc) wait_seconds = parse_u64("--wait", argv[++i]);
        else if (a == "--json")                     json_out = true;
        else {
            std::cerr << "verify-shardtip-records: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || !have_height) {
        std::cerr << "verify-shardtip-records: --rpc-port, --genesis, --height are required\n";
        return 1;
    }

    auto fail = [&](int code, const std::string& detail) -> int {
        if (json_out)
            std::cout << json{{"height", height}, {"ok", false},
                              {"detail", detail}}.dump() << "\n";
        else
            std::cerr << "verify-shardtip-records: " << detail << "\n";
        return code;
    };

    try {
        // Pin the chain identity + derive the genesis committee (untrusted-daemon
        // posture — NOT a user-supplied committee file).
        auto genesis        = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        const uint64_t eb   = genesis.epoch_blocks;
        const size_t   K    = genesis.k_block_sigs;
        const bool     bft_enabled = genesis.bft_enabled;
        // Genesis-committed shard→region map (authoritative; built identically to
        // node.cpp:490 `committed[sid]=region`, no normalization). A missing
        // entry yields "" (the CURRENT-compat global pool).
        std::map<ShardId, std::string> shard_regions;
        for (auto& kv : genesis.shard_regions) shard_regions[kv.first] = kv.second;

        // committee_json for committee_bound_state_root (the cc-pin anchor).
        json committee_json;
        {
            json arr = json::array();
            for (auto& [domain_, pk] : committee_seed)
                arr.push_back({{"domain", domain_}, {"ed_pub", to_hex(pk)}});
            committee_json = json{{"members", arr}};
        }

        RpcClient rpc(port);
        if (!rpc.open()) return fail(1, rpc.last_error());
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // (1) ANCHOR — committee-attested block_hash(H).
        auto sr = verify_state_root_at(rpc, committee_seed, genesis_hash_hex, height, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
        if (!sr.ok) return fail(3, "ANCHOR failed: " + sr.detail);

        // (2) BODY-PIN — the full block recomputes to the committee-anchored hash.
        json full = rpc.call("block", {{"index", height}});
        if (!full.is_object()
            || (full.contains("error") && !full["error"].is_null()))
            return fail(3, "full-block fetch failed");
        determ::chain::Block fb;
        try {
            fb = determ::chain::Block::from_json(full);
        } catch (const std::exception& e) {
            return fail(3, std::string("malformed full block: ") + e.what());
        }
        if (to_hex(fb.compute_hash()) != sr.block_hash_hex)
            return fail(3, "BODY-PIN mismatch: full-block hash != committee-anchored "
                           "block_hash (daemon served a body inconsistent with the "
                           "signed header)");

        // Structural: records[] and witnesses[] are now committee-authenticated.
        const size_t n_rec = fb.shard_tip_records.size();
        const size_t n_wit = fb.shard_tip_witnesses.size();
        if (n_rec != n_wit)
            return fail(3, "record/witness count mismatch (" + std::to_string(n_rec)
                         + "/" + std::to_string(n_wit) + ") — a committee-authenticated "
                           "block must carry one witness per folded record");

        // Explicit EXTENDED gate (defense-in-depth, mirrors the node's
        // committee_pin_active shard_count()>1 predicate). An honest fold only
        // happens on a sharded chain; a single-shard genesis that nonetheless
        // carries committee-authenticated records is malformed. Rejecting here
        // removes the auditor's reliance on cc:[E] being unfetchable to fail
        // closed, so a future chain.cpp fold-condition change cannot open a
        // light-vs-node verdict divergence. e-7e adversarial-review LOW finding.
        if (n_rec > 0 && genesis.initial_shard_count <= 1)
            return fail(3, "block folds shard-tip records but genesis initial_shard_count<=1 "
                           "(not an EXTENDED chain) — malformed");

        // Per-source-epoch trusted cc: cache (pin each E once).
        std::map<EpochIndex, CcTrustedCheckpoint> cc_cache;
        Signature zero_sig{};
        json records_out = json::array();

        for (size_t i = 0; i < n_rec; ++i) {
            const determ::chain::ShardTipRecord& rec = fb.shard_tip_records[i];
            const determ::chain::Block&          w   = fb.shard_tip_witnesses[i];

            // (0) LEAF invariant on the witness.
            if (!w.shard_tip_records.empty() || !w.shard_tip_witnesses.empty())
                return fail(3, "record[" + std::to_string(i) + "]: witness is not a leaf block");

            // (anti-reuse) the record's claims must be read from INSIDE the
            // witness digest preimage (index/source_shard_id/eligible_count all
            // bound into compute_block_digest).
            if (w.index != rec.height)
                return fail(3, "record[" + std::to_string(i) + "]: witness.index != rec.height");
            if (w.source_shard_id != rec.source_shard_id)
                return fail(3, "record[" + std::to_string(i) + "]: witness.source_shard_id mismatch");
            if (w.eligible_count != rec.eligible_count)
                return fail(3, "record[" + std::to_string(i) + "]: witness.eligible_count mismatch");

            const EpochIndex Es = eb ? (rec.height / eb) : 0;
            // Explicit epoch>=1 gate (mirrors committee_pin_active's epoch>=1
            // predicate). Epoch 0 is intentionally never frozen (chain.cpp never
            // folds cc:[0]), so a record claiming Es==0 can never carry a pinnable
            // checkpoint — reject up front rather than lean on cc:[0] absence.
            if (Es == 0)
                return fail(3, "record[" + std::to_string(i) + "]: source epoch 0 has no "
                               "pinnable committee checkpoint (epoch 0 is never frozen)");

            // (3) region from the GENESIS-committed map, bound against rec.region.
            std::string region;
            if (auto it = shard_regions.find(rec.source_shard_id); it != shard_regions.end())
                region = it->second;
            if (rec.region != region)
                return fail(3, "record[" + std::to_string(i) + "]: region '" + rec.region
                             + "' != genesis-committed region '" + region + "' for shard "
                             + std::to_string(rec.source_shard_id));

            // (3) CC-PIN — fetch + pin cc:[Es] once per epoch.
            auto cit = cc_cache.find(Es);
            if (cit == cc_cache.end()) {
                // (a) cc:[Es] checkpoint CONTENT (UNTRUSTED).
                json cc = rpc.call("cc_checkpoint", {{"epoch", Es}});
                if (!cc.is_object() || (cc.contains("error") && !cc["error"].is_null()))
                    return fail(3, "record[" + std::to_string(i) + "]: cc:[" + std::to_string(Es)
                                 + "] not served (epoch-0 / not-yet-folded / pruned from the "
                                   "16-epoch ring) — fail-closed UNVERIFIABLE");
                CcTrustedCheckpoint ck;
                try {
                    ck.epoch_rand = from_hex_arr<32>(cc.at("epoch_rand").get<std::string>());
                    for (auto& m : cc.at("members")) {
                        PubKey pub = from_hex_arr<32>(m.at("ed_pub").get<std::string>());
                        ck.members.emplace_back(m.at("domain").get<std::string>(), pub,
                                                m.at("region").get<std::string>());
                    }
                } catch (const std::exception& e) {
                    return fail(3, "record[" + std::to_string(i) + "]: malformed cc_checkpoint: "
                                 + e.what());
                }
                // (b) recompute the cc: leaf value from the preimage (== chain.cpp
                //     build_state_leaves cc: exactly).
                crypto::SHA256Builder lb;
                lb.append(ck.epoch_rand.data(), ck.epoch_rand.size());
                lb.append(static_cast<uint64_t>(ck.members.size()));
                for (auto& [dom, pub, reg] : ck.members) {
                    lb.append(static_cast<uint64_t>(dom.size()));
                    lb.append(dom);
                    lb.append(pub.data(), pub.size());
                    lb.append(static_cast<uint64_t>(reg.size()));
                    lb.append(reg);
                }
                Hash cc_leaf_value = lb.finalize();

                // (c) the "cc" state_proof, bound to that leaf value + pinned to a
                //     committee-signed state_root.
                std::vector<uint8_t> eb8(8);
                { uint64_t t = Es; for (int j = 7; j >= 0; --j) { eb8[j] = (uint8_t)(t & 0xff); t >>= 8; } }
                json proof = rpc.call("state_proof",
                                      {{"namespace", "cc"}, {"key", to_hex(eb8.data(), eb8.size())}});
                if (!proof.is_object()
                    || (proof.contains("error") && !proof["error"].is_null()))
                    return fail(3, "record[" + std::to_string(i) + "]: cc:[" + std::to_string(Es)
                                 + "] state_proof not_found — fail-closed UNVERIFIABLE");
                // KEY-BIND (F-6 class, [[light-stake-read-key-bind-gap]]): the
                // epoch lives ONLY in the leaf KEY ("cc:"+epoch_be8), NOT the
                // value preimage (chain.cpp build_state_leaves cc: hashes only
                // epoch_rand‖members). verify_state_proof Merkle-checks whatever
                // key_bytes the daemon supplies, so WITHOUT this bind a Byzantine
                // daemon serves a REAL committed cc:[E_other] leaf under a
                // fabricated-epoch record — value_hash + Merkle both pass and the
                // auditor verifies the witness against the WRONG (attacker-chosen)
                // frozen committee. Single-leaf readers need BOTH key-bind AND
                // value-hash-bind. e-7e adversarial-review HIGH finding.
                std::vector<uint8_t> want_key;
                want_key.reserve(3 + 8);
                want_key.push_back('c'); want_key.push_back('c'); want_key.push_back(':');
                want_key.insert(want_key.end(), eb8.begin(), eb8.end());
                if (proof.value("key_bytes", std::string{})
                        != to_hex(want_key.data(), want_key.size()))
                    return fail(3, "record[" + std::to_string(i) + "]: cc: proof.key_bytes != "
                                   "cc:[" + std::to_string(Es) + "] — daemon served a DIFFERENT "
                                   "epoch's committee checkpoint (epoch-substitution attempt)");
                std::string proof_value_hash = proof.value("value_hash", std::string{});
                if (proof_value_hash != to_hex(cc_leaf_value))
                    return fail(3, "record[" + std::to_string(i) + "]: cc_checkpoint content does "
                                   "NOT hash to the cc:[" + std::to_string(Es) + "] leaf value "
                                   "(daemon served an inconsistent checkpoint)");
                std::string proof_root = proof.value("state_root", std::string{});
                uint64_t    proof_height = proof.value("height", uint64_t{0});
                if (proof_height == 0)
                    return fail(3, "record[" + std::to_string(i) + "]: cc: proof has no height");
                std::string attested = determ::light::committee_bound_state_root(rpc, committee_json, proof_height - 1, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
                if (attested != proof_root)
                    return fail(3, "record[" + std::to_string(i) + "]: cc: proof.state_root is NOT "
                                   "the committee-attested root at index "
                                 + std::to_string(proof_height - 1) + " — unattested root");
                auto vsp = verify_state_proof(proof, attested);
                if (!vsp.ok)
                    return fail(3, "record[" + std::to_string(i) + "]: cc: Merkle verification "
                                   "failed: " + vsp.detail);
                cit = cc_cache.emplace(Es, std::move(ck)).first;
            }
            const CcTrustedCheckpoint& ck = cit->second;

            // (4) WITNESS — re-derive the frozen committee + verify K-of-K sigs +
            //     recompute committee_sig_root (mirrors shardtip_verify.cpp 36-146).
            // Mode-eligibility gate: a BFT-declared witness lowers the bar to
            // ceil(2K/3); reject it outright on a chain that never enabled BFT.
            const bool is_bft = (w.consensus_mode == determ::chain::ConsensusMode::BFT);
            if (is_bft && !bft_enabled)
                return fail(3, "record[" + std::to_string(i) + "]: witness is BFT but genesis "
                               "bft_enabled=false — no reduced-quorum source attestation");
            const size_t expected_k = is_bft ? determ::chain::bft_committee_size(K) : K;

            // Frozen pool + pubkeys (region-filtered, checkpoint stored order).
            std::vector<std::string>      pool;
            std::map<std::string, PubKey> frozen_pub;
            for (auto& [dom, pub, reg] : ck.members) {
                if (!region.empty() && reg != region) continue;
                pool.push_back(dom);
                frozen_pub[dom] = pub;
            }
            std::set<std::string> excluded;
            for (auto& ae : w.abort_events) excluded.insert(ae.aborting_node);
            std::vector<std::string> avail;
            for (auto& dom : pool) if (!excluded.count(dom)) avail.push_back(dom);

            if (avail.size() < expected_k)
                return fail(3, "record[" + std::to_string(i) + "]: insufficient frozen pool to "
                               "derive committee");
            if (w.creators.size() != expected_k)
                return fail(3, "record[" + std::to_string(i) + "]: witness creators count != "
                               "expected_k");

            Hash rand = crypto::epoch_committee_seed(ck.epoch_rand, rec.source_shard_id);
            // S-074: every abort event must carry its CANONICAL identity (the
            // rule the source shard's validators and the beacon enforce), so a
            // chosen hash cannot seat a committee of the witness author's
            // choosing; re-derived from the committee seed + witness height.
            for (size_t j = 0; j < w.abort_events.size(); ++j) {
                const auto& ae = w.abort_events[j];
                const determ::chain::AbortEvent* prev = (j == 0) ? nullptr : &w.abort_events[j - 1];
                if (ae.event_hash != determ::chain::canonical_abort_event_hash(ae, prev, rand, w.index))
                    return fail(3, "record[" + std::to_string(i) + "]: witness abort_event["
                                 + std::to_string(j) + "] event_hash not canonical (S-074)");
            }
            for (auto& ae : w.abort_events)
                rand = crypto::SHA256Builder{}.append(rand).append(ae.event_hash).finalize();
            auto indices = crypto::select_m_creators(rand, avail.size(), expected_k);
            for (size_t j = 0; j < expected_k; ++j)
                if (avail[indices[j]] != w.creators[j])
                    return fail(3, "record[" + std::to_string(i) + "]: creator[" + std::to_string(j)
                                 + "] mismatch vs frozen-committee derivation");

            if (w.creator_block_sigs.size() != w.creators.size())
                return fail(3, "record[" + std::to_string(i) + "]: creator_block_sigs size != "
                               "creators size");
            Hash digest = light_compute_block_digest(w);
            size_t signed_count = 0;
            for (size_t j = 0; j < w.creators.size(); ++j) {
                if (w.creator_block_sigs[j] == zero_sig) continue;
                auto pit = frozen_pub.find(w.creators[j]);
                if (pit == frozen_pub.end())
                    return fail(3, "record[" + std::to_string(i) + "]: creator '" + w.creators[j]
                                 + "' is not a frozen committee member");
                if (!crypto::verify(pit->second, digest.data(), digest.size(),
                                    w.creator_block_sigs[j]))
                    return fail(3, "record[" + std::to_string(i) + "]: invalid sig from '"
                                 + w.creators[j] + "'");
                ++signed_count;
            }
            if (signed_count < expected_k)
                return fail(3, "record[" + std::to_string(i) + "]: insufficient sigs ("
                             + std::to_string(signed_count) + "/" + std::to_string(expected_k) + ")");

            std::vector<Hash> sig_hashes;
            for (const auto& s : w.creator_block_sigs) {
                if (s == zero_sig) continue;
                crypto::SHA256Builder sb;
                sb.append(s.data(), s.size());
                sig_hashes.push_back(sb.finalize());
            }
            Hash sig_set_root = shardtip_view_root(sig_hashes);

            crypto::SHA256Builder cb;
            cb.append(std::string("determ-shardtip-v1"));
            cb.append(static_cast<uint64_t>(rec.source_shard_id));
            cb.append(static_cast<uint64_t>(w.index));
            cb.append(static_cast<uint64_t>(w.eligible_count));
            cb.append(static_cast<uint64_t>(region.size()));
            cb.append(region);
            cb.append(digest);
            cb.append(sig_set_root);
            Hash recomputed = cb.finalize();
            if (recomputed != rec.committee_sig_root)
                return fail(3, "record[" + std::to_string(i) + "]: committee_sig_root recomputed "
                               "from the frozen-committee witness != carried record");

            records_out.push_back({
                {"index",             i},
                {"source_shard_id",   rec.source_shard_id},
                {"source_height",     rec.height},
                {"source_epoch",      Es},
                {"region",            region},
                {"eligible_count",    rec.eligible_count},
                {"committee_size",    expected_k},
                {"sigs_verified",     signed_count},
                {"consensus_mode",    is_bft ? "BFT" : "MD"},
                {"committee_sig_root", to_hex(rec.committee_sig_root)},
                {"verified",          true},
            });
        }

        // 0 records = vacuously verified (an anti-silent-vacuity 0-count).
        if (json_out) {
            std::cout << json{
                {"height",             height},
                {"genesis_pin",        genesis_hash_hex},
                {"committee_verified", true},
                {"body_pinned",        true},
                {"initial_shard_count", genesis.initial_shard_count},
                {"records_total",      n_rec},
                {"records_verified",   records_out.size()},
                {"records",            records_out},
                {"ok",                 true},
            }.dump() << "\n";
        } else {
            std::cout << "verify-shardtip-records: OK — block " << height
                      << " committee-verified + body-pinned; "
                      << n_rec << " shard-tip record(s) "
                      << (n_rec ? "re-verified against the frozen source committees"
                                : "(none folded — vacuously verified)") << "\n";
            for (auto& r : records_out)
                std::cout << "  record[" << r["index"] << "] shard "
                          << r["source_shard_id"] << " @ h" << r["source_height"]
                          << " (epoch " << r["source_epoch"] << ", region '"
                          << r["region"].get<std::string>() << "'): "
                          << r["sigs_verified"] << "/" << r["committee_size"] << " frozen sigs, "
                          << r["consensus_mode"].get<std::string>() << " — VERIFIED\n";
        }
        return 0;
    } catch (const std::exception& e) {
        return fail(1, e.what());
    }
}

// ──────────────────────────── sign-tx ──────────────────────────────────

int cmd_sign_tx(int argc, char** argv) {
    std::string keyfile_path, type_str, to_str, out_path;
    bool have_amount = false, have_fee = false, have_nonce = false;
    uint64_t amount = 0, fee = 0, nonce = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--keyfile" && i + 1 < argc) keyfile_path = argv[++i];
        else if (a == "--type"    && i + 1 < argc) type_str     = argv[++i];
        else if (a == "--to"      && i + 1 < argc) to_str       = argv[++i];
        else if (a == "--amount"  && i + 1 < argc) { amount = parse_u64("--amount", argv[++i]); have_amount = true; }
        else if (a == "--fee"     && i + 1 < argc) { fee    = parse_u64("--fee",    argv[++i]); have_fee    = true; }
        else if (a == "--nonce"   && i + 1 < argc) { nonce  = parse_u64("--nonce",  argv[++i]); have_nonce  = true; }
        else if (a == "--out"     && i + 1 < argc) out_path     = argv[++i];
        else {
            std::cerr << "sign-tx: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (keyfile_path.empty() || type_str.empty()
        || !have_amount || !have_fee || !have_nonce) {
        std::cerr << "sign-tx: --keyfile, --type, --amount, --fee, --nonce "
                     "are required\n";
        return 1;
    }
    try {
        LightTxType type = parse_tx_type(type_str);
        if (type == LightTxType::TRANSFER && to_str.empty()) {
            std::cerr << "sign-tx: TRANSFER requires --to\n";
            return 1;
        }
        // Normalize anon-shape `to` to canonical lowercase (S-028).
        // Other shapes (domain names) pass through unchanged.
        if (!to_str.empty()) {
            std::string canonical = normalize_anon_address(to_str);
            if (canonical != to_str) {
                std::cerr << "sign-tx: --to is anon-shape but not canonical "
                             "lowercase (S-028); got '" << to_str << "'\n";
                return 1;
            }
        }
        auto kf = load_light_keyfile(keyfile_path);
        auto signed_tx = sign_light_tx(kf, type, to_str, amount, fee, nonce);
        if (out_path.empty()) {
            std::cout << signed_tx.dump() << "\n";
        } else {
            write_json_file(out_path, signed_tx);
            std::cout << "OK: wrote signed tx (hash="
                      << signed_tx["hash"].get<std::string>().substr(0, 16)
                      << "...) to " << out_path << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "sign-tx: " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────── rotate-audit-key / log-audit-access ────────────────
//
// A2 audit-layer client tooling (pre-launch register A2). Build + sign a
// submittable ROTATE_AUDIT_KEY (set/clear the account's standing audit key)
// or LOG_AUDIT_ACCESS (post a disclosure record). Both are fee-only,
// account-Ed25519-signed; the consensus half is in verify/apply
// (docs/proofs/AuditLayerSoundness.md). Emits a `Transaction::from_json`-
// compatible envelope (submit via `submit-tx`).

int cmd_rotate_audit_key(int argc, char** argv) {
    std::string keyfile_path, pubkey_hex, out_path;
    bool have_fee = false, have_nonce = false, clear = false;
    uint64_t fee = 0, nonce = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--keyfile" && i + 1 < argc) keyfile_path = argv[++i];
        else if (a == "--pubkey"  && i + 1 < argc) pubkey_hex   = argv[++i];
        else if (a == "--clear")                   clear        = true;
        else if (a == "--fee"     && i + 1 < argc) { fee   = parse_u64("--fee",   argv[++i]); have_fee   = true; }
        else if (a == "--nonce"   && i + 1 < argc) { nonce = parse_u64("--nonce", argv[++i]); have_nonce = true; }
        else if (a == "--out"     && i + 1 < argc) out_path     = argv[++i];
        else { std::cerr << "rotate-audit-key: unknown arg '" << a << "'\n"; return 1; }
    }
    if (keyfile_path.empty() || !have_fee || !have_nonce) {
        std::cerr << "rotate-audit-key: --keyfile, --fee, --nonce are required "
                     "(and exactly one of --pubkey <hex32> / --clear)\n";
        return 1;
    }
    if (clear == !pubkey_hex.empty()) {
        std::cerr << "rotate-audit-key: give EXACTLY one of --pubkey <hex32> "
                     "(set) or --clear (revoke)\n";
        return 1;
    }
    try {
        auto kf = load_light_keyfile(keyfile_path);
        std::optional<std::vector<uint8_t>> pk;
        if (!clear) pk = from_hex(pubkey_hex);
        auto tx = build_rotate_audit_key_tx(kf, pk, fee, nonce);
        if (out_path.empty()) std::cout << tx.dump() << "\n";
        else {
            write_json_file(out_path, tx);
            std::cout << "OK: wrote ROTATE_AUDIT_KEY ("
                      << (clear ? "clear" : "set") << ", hash="
                      << tx["hash"].get<std::string>().substr(0, 16)
                      << "...) to " << out_path << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "rotate-audit-key: " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────────────── register-note-key ───────────────────────────
// NC-8 §5a client tooling: build + sign a submittable REGISTER_NOTE_KEY
// (TxType 17) that publishes/rotates/revokes the account's standing recipient
// note_pk (the 33-byte P-256 point a sender seals a CONFIDENTIAL_TRANSFER enote
// to). Fee-only, account-Ed25519-signed — anon/bearer payees included. Feed the
// output to `submit-tx`; a `determ verify-audit-tx` confirms a validator would
// accept it. (EncryptedNoteDeliveryDesign.md §5.5.)
int cmd_register_note_key(int argc, char** argv) {
    std::string keyfile_path, note_pk_hex, out_path;
    bool have_fee = false, have_nonce = false, clear = false;
    uint64_t fee = 0, nonce = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--keyfile" && i + 1 < argc) keyfile_path = argv[++i];
        else if (a == "--note-pk" && i + 1 < argc) note_pk_hex  = argv[++i];
        else if (a == "--clear")                   clear        = true;
        else if (a == "--fee"     && i + 1 < argc) { fee   = parse_u64("--fee",   argv[++i]); have_fee   = true; }
        else if (a == "--nonce"   && i + 1 < argc) { nonce = parse_u64("--nonce", argv[++i]); have_nonce = true; }
        else if (a == "--out"     && i + 1 < argc) out_path     = argv[++i];
        else { std::cerr << "register-note-key: unknown arg '" << a << "'\n"; return 1; }
    }
    if (keyfile_path.empty() || !have_fee || !have_nonce) {
        std::cerr << "register-note-key: --keyfile, --fee, --nonce are required "
                     "(and exactly one of --note-pk <hex33> / --clear)\n";
        return 1;
    }
    if (clear == !note_pk_hex.empty()) {
        std::cerr << "register-note-key: give EXACTLY one of --note-pk <hex33> "
                     "(set) or --clear (revoke)\n";
        return 1;
    }
    try {
        auto kf = load_light_keyfile(keyfile_path);
        std::optional<std::vector<uint8_t>> pk;
        if (!clear) pk = from_hex(note_pk_hex);
        auto tx = build_register_note_key_tx(kf, pk, fee, nonce);
        if (out_path.empty()) std::cout << tx.dump() << "\n";
        else {
            write_json_file(out_path, tx);
            std::cout << "OK: wrote REGISTER_NOTE_KEY ("
                      << (clear ? "clear" : "set") << ", hash="
                      << tx["hash"].get<std::string>().substr(0, 16)
                      << "...) to " << out_path << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "register-note-key: " << e.what() << "\n";
        return 1;
    }
}

int cmd_log_audit_access(int argc, char** argv) {
    std::string keyfile_path, epoch_str, auditor_hex, context_hex, out_path;
    bool have_fee = false, have_nonce = false;
    uint64_t fee = 0, nonce = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--keyfile" && i + 1 < argc) keyfile_path = argv[++i];
        else if (a == "--epoch"   && i + 1 < argc) epoch_str    = argv[++i];
        else if (a == "--auditor" && i + 1 < argc) auditor_hex  = argv[++i];
        else if (a == "--context" && i + 1 < argc) context_hex  = argv[++i];
        else if (a == "--fee"     && i + 1 < argc) { fee   = parse_u64("--fee",   argv[++i]); have_fee   = true; }
        else if (a == "--nonce"   && i + 1 < argc) { nonce = parse_u64("--nonce", argv[++i]); have_nonce = true; }
        else if (a == "--out"     && i + 1 < argc) out_path     = argv[++i];
        else { std::cerr << "log-audit-access: unknown arg '" << a << "'\n"; return 1; }
    }
    if (keyfile_path.empty() || epoch_str.empty() || auditor_hex.empty()
        || context_hex.empty() || !have_fee || !have_nonce) {
        std::cerr << "log-audit-access: --keyfile, --epoch, --auditor, --context, "
                     "--fee, --nonce are required (--epoch <n>|all)\n";
        return 1;
    }
    try {
        // --epoch accepts a number OR "all" (the full-history sentinel).
        uint64_t epoch = (epoch_str == "all" || epoch_str == "ALL")
            ? UINT64_MAX : parse_u64("--epoch", epoch_str);
        auto kf = load_light_keyfile(keyfile_path);
        auto tx = build_log_audit_access_tx(kf, epoch, from_hex(auditor_hex),
                                            from_hex(context_hex), fee, nonce);
        if (out_path.empty()) std::cout << tx.dump() << "\n";
        else {
            write_json_file(out_path, tx);
            std::cout << "OK: wrote LOG_AUDIT_ACCESS (epoch="
                      << (epoch == UINT64_MAX ? "all" : std::to_string(epoch))
                      << ", hash=" << tx["hash"].get<std::string>().substr(0, 16)
                      << "...) to " << out_path << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "log-audit-access: " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────────── build-shield / build-unshield ──────────────────
//
// CTX-2 confidential on/off-ramp builders (light/ct_tx.cpp). Build + sign a
// SUBMITTABLE SHIELD (transparent -> confidential) or UNSHIELD (confidential ->
// transparent) tx. The note blinding is derived from --blind-seed (SAVE the
// seed + amount to spend the note later). Verify a validator would accept the
// result with `determ-light verify-ct-tx` / `determ verify-ct-tx`; submit via
// `submit-tx`. Soundness: docs/proofs/AuditLayerSoundness.md is unrelated —
// see CRYPTO-C99-SPEC §3.22 / §3.22b + docs/proofs/ (CT balance proofs).

int cmd_build_shield(int argc, char** argv) {
    std::string keyfile_path, seed_hex, out_path;
    bool have_amount = false, have_fee = false, have_nonce = false;
    uint64_t amount = 0, fee = 0, nonce = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--keyfile"    && i + 1 < argc) keyfile_path = argv[++i];
        else if (a == "--blind-seed" && i + 1 < argc) seed_hex     = argv[++i];
        else if (a == "--amount"     && i + 1 < argc) { amount = parse_u64("--amount", argv[++i]); have_amount = true; }
        else if (a == "--fee"        && i + 1 < argc) { fee    = parse_u64("--fee",    argv[++i]); have_fee    = true; }
        else if (a == "--nonce"      && i + 1 < argc) { nonce  = parse_u64("--nonce",  argv[++i]); have_nonce  = true; }
        else if (a == "--out"        && i + 1 < argc) out_path     = argv[++i];
        else { std::cerr << "build-shield: unknown arg '" << a << "'\n"; return 1; }
    }
    if (keyfile_path.empty() || seed_hex.empty() || !have_amount || !have_fee || !have_nonce) {
        std::cerr << "build-shield: --keyfile, --blind-seed <hex>, --amount, --fee, "
                     "--nonce are required\n";
        return 1;
    }
    try {
        auto kf = load_light_keyfile(keyfile_path);
        auto tx = build_shield_tx(kf, amount, from_hex(seed_hex), fee, nonce);
        if (out_path.empty()) std::cout << tx.dump() << "\n";
        else {
            write_json_file(out_path, tx);
            std::cout << "OK: wrote SHIELD (amount=" << amount << ", note C="
                      << tx["payload"].get<std::string>().substr(0, 16)
                      << "..., hash=" << tx["hash"].get<std::string>().substr(0, 16)
                      << "...) to " << out_path
                      << "\n  SAVE your --blind-seed + amount to UNSHIELD/spend this note later.\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "build-shield: " << e.what() << "\n";
        return 1;
    }
}

int cmd_build_unshield(int argc, char** argv) {
    std::string keyfile_path, seed_hex, to, out_path;
    bool have_amount = false, have_fee = false, have_nonce = false;
    uint64_t amount = 0, fee = 0, nonce = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--keyfile"    && i + 1 < argc) keyfile_path = argv[++i];
        else if (a == "--blind-seed" && i + 1 < argc) seed_hex     = argv[++i];
        else if (a == "--to"         && i + 1 < argc) to           = argv[++i];
        else if (a == "--amount"     && i + 1 < argc) { amount = parse_u64("--amount", argv[++i]); have_amount = true; }
        else if (a == "--fee"        && i + 1 < argc) { fee    = parse_u64("--fee",    argv[++i]); have_fee    = true; }
        else if (a == "--nonce"      && i + 1 < argc) { nonce  = parse_u64("--nonce",  argv[++i]); have_nonce  = true; }
        else if (a == "--out"        && i + 1 < argc) out_path     = argv[++i];
        else { std::cerr << "build-unshield: unknown arg '" << a << "'\n"; return 1; }
    }
    if (keyfile_path.empty() || seed_hex.empty() || to.empty()
        || !have_amount || !have_fee || !have_nonce) {
        std::cerr << "build-unshield: --keyfile, --blind-seed <hex>, --to, --amount, "
                     "--fee, --nonce are required\n";
        return 1;
    }
    try {
        // Normalize an anon-shape recipient to canonical lowercase (S-028); other
        // shapes pass through (same rule as sign-tx --to).
        if (!to.empty()) {
            std::string canonical = normalize_anon_address(to);
            if (canonical != to) {
                std::cerr << "build-unshield: --to is anon-shape but not canonical "
                             "lowercase (S-028); got '" << to << "'\n";
                return 1;
            }
        }
        auto kf = load_light_keyfile(keyfile_path);
        auto tx = build_unshield_tx(kf, amount, from_hex(seed_hex), to, fee, nonce);
        if (out_path.empty()) std::cout << tx.dump() << "\n";
        else {
            write_json_file(out_path, tx);
            std::cout << "OK: wrote UNSHIELD (amount=" << amount << " -> " << to
                      << ", hash=" << tx["hash"].get<std::string>().substr(0, 16)
                      << "...) to " << out_path << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "build-unshield: " << e.what() << "\n";
        return 1;
    }
}

// ───────────────────────── build-ct-transfer ────────────────────────────
//
// CTX-2 confidential -> confidential builder. Reads a JSON --spec describing the
// input notes (value + blind_seed), the output notes, the public fee, the
// Bulletproof nonce_seed, and the tx nonce, and emits a submittable
// CONFIDENTIAL_TRANSFER (DCT1 bundle). Balance must hold. Verify with verify-ct-tx.
int cmd_build_ct_transfer(int argc, char** argv) {
    std::string keyfile_path, spec_path, out_path;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--keyfile" && i + 1 < argc) keyfile_path = argv[++i];
        else if (a == "--spec"    && i + 1 < argc) spec_path    = argv[++i];
        else if (a == "--out"     && i + 1 < argc) out_path     = argv[++i];
        else { std::cerr << "build-ct-transfer: unknown arg '" << a << "'\n"; return 1; }
    }
    if (keyfile_path.empty() || spec_path.empty()) {
        std::cerr << "build-ct-transfer: --keyfile and --spec <file> are required\n"
                     "  spec JSON: {\"inputs\":[{\"value\":N,\"blind_seed\":\"hex\"},...],\n"
                     "             \"outputs\":[{\"value\":N,\"blind_seed\":\"hex\"},...],\n"
                     "             \"fee\":N,\"nonce_seed\":\"hex\",\"tx_nonce\":N}\n"
                     "  balance MUST hold: sum(inputs.value) == sum(outputs.value) + fee\n";
        return 1;
    }
    try {
        std::ifstream f(spec_path);
        if (!f) { std::cerr << "build-ct-transfer: cannot read " << spec_path << "\n"; return 1; }
        nlohmann::json spec; f >> spec;
        auto parse_notes = [](const nlohmann::json& arr) {
            std::vector<determ::light::CtNote> v;
            for (const auto& e : arr) {
                determ::light::CtNote note;
                note.value      = e.at("value").get<uint64_t>();
                note.blind_seed = from_hex(e.at("blind_seed").get<std::string>());
                v.push_back(std::move(note));
            }
            return v;
        };
        auto inputs     = parse_notes(spec.at("inputs"));
        auto outputs    = parse_notes(spec.at("outputs"));
        uint64_t fee    = spec.at("fee").get<uint64_t>();
        auto nonce_seed = from_hex(spec.at("nonce_seed").get<std::string>());
        uint64_t txn    = spec.at("tx_nonce").get<uint64_t>();
        auto kf = load_light_keyfile(keyfile_path);
        auto tx = build_confidential_transfer_tx(kf, inputs, outputs, fee, nonce_seed, txn);
        if (out_path.empty()) std::cout << tx.dump() << "\n";
        else {
            write_json_file(out_path, tx);
            std::cout << "OK: wrote CONFIDENTIAL_TRANSFER (" << inputs.size() << " in -> "
                      << outputs.size() << " out, fee=" << fee << ", hash="
                      << tx["hash"].get<std::string>().substr(0, 16) << "...) to " << out_path
                      << "\n  SAVE each output's (value, blind_seed) so the recipient can spend it.\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "build-ct-transfer: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────────── submit-tx ────────────────────────────────

int cmd_submit_tx(int argc, char** argv) {
    uint16_t port = 0;
    std::string tx_path;
    bool have_port = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--tx-json" && i + 1 < argc) tx_path = argv[++i];
        else {
            std::cerr << "submit-tx: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || tx_path.empty()) {
        std::cerr << "submit-tx: --rpc-port and --tx-json are required\n";
        return 1;
    }
    try {
        json tx = read_json_file(tx_path);
        // The daemon's submit_tx RPC accepts {"tx": <canonical-tx-json>}
        // per rpc.cpp:226 params.value("tx", ...). Sign-tx emits the
        // canonical Transaction shape with `sig` (not `signature`); we
        // wrap it here.
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "submit-tx: " << rpc.last_error() << "\n";
            return 1;
        }
        auto reply = rpc.call("submit_tx", {{"tx", tx}});
        std::cout << reply.dump() << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "submit-tx: " << e.what() << "\n";
        return 1;
    }
}

// ────────────────────── verify-and-submit ──────────────────────────────

int cmd_verify_and_submit(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, keyfile_path, to_str, out_path, state_path;
    bool have_port = false, have_amount = false, have_fee = false, resume = false;
    uint64_t amount = 0, fee = 0, wait_seconds = 0;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--keyfile" && i + 1 < argc) keyfile_path = argv[++i];
        else if   (a == "--to"      && i + 1 < argc) to_str       = argv[++i];
        else if   (a == "--amount"  && i + 1 < argc) { amount = parse_u64("--amount", argv[++i]); have_amount = true; }
        else if   (a == "--fee"     && i + 1 < argc) { fee    = parse_u64("--fee",    argv[++i]); have_fee    = true; }
        else if   (a == "--out"     && i + 1 < argc) out_path     = argv[++i];
        else if   (a == "--resume")                  resume       = true;
        else if   (a == "--state" && i + 1 < argc)   state_path   = argv[++i];
        else if   (a == "--wait"  && i + 1 < argc)   wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "verify-and-submit: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || keyfile_path.empty()
        || to_str.empty() || !have_amount || !have_fee) {
        std::cerr << "verify-and-submit: --rpc-port, --genesis, --keyfile, "
                     "--to, --amount, --fee are required\n";
        return 1;
    }
    try {
        // 1. Load genesis + keyfile.
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        auto kf = load_light_keyfile(keyfile_path);
        // 2. Open RPC connection (shared for all three sub-calls).
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-and-submit: " << rpc.last_error() << "\n";
            return 1;
        }
        // 3. Trustless-read the sender's nonce (--resume reuses a cached anchor
        //    for the verification, same as the standalone trustless reads).
        //    --wait blocks for the head's successor block before binding the
        //    held state-proof (the embedded nonce read anchors at the head, so
        //    without it the S-042 successor binding fails closed — exactly as
        //    on nonce-trustless, which this flow embeds).
        auto view = read_account_trustless(rpc, committee_seed, genesis,
                                            kf.anon_address, resume, state_path,
                                            wait_seconds);
        // 4. Sign locally with the verified nonce.
        std::string canonical_to = normalize_anon_address(to_str);
        if (canonical_to != to_str) {
            std::cerr << "verify-and-submit: --to is anon-shape but not "
                         "canonical lowercase (S-028); got '" << to_str << "'\n";
            return 1;
        }
        auto signed_tx = sign_light_tx(kf, LightTxType::TRANSFER,
                                         canonical_to, amount, fee,
                                         view.next_nonce);
        // 5. Submit (params shape per rpc.cpp:226 is {"tx": <tx-json>}).
        auto submit_reply = rpc.call("submit_tx", {{"tx", signed_tx}});
        json out = {
            {"verified_at_height", view.height},
            {"verified_nonce",     view.next_nonce},
            {"verified_balance",   view.balance},
            {"state_root",         view.state_root_hex},
            {"submitted_tx_hash",  signed_tx["hash"]},
            {"submit_reply",       submit_reply},
        };
        if (!out_path.empty()) {
            write_json_file(out_path, out);
            std::cout << "OK: wrote verify-and-submit log to " << out_path
                      << "\n";
        } else {
            std::cout << out.dump() << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-and-submit: " << e.what() << "\n";
        return 1;
    }
}

// ────────────────────────── watch-head ────────────────────────────────

int cmd_watch_head(int argc, char** argv) {
    WatchOptions opts;
    bool have_port = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            opts.rpc_port = parse_u16("--rpc-port", argv[++i]);
            have_port = true;
        } else if (a == "--genesis"  && i + 1 < argc) {
            opts.genesis_path = argv[++i];
        } else if (a == "--count"    && i + 1 < argc) {
            opts.count = parse_u64("--count", argv[++i]);
        } else if (a == "--interval" && i + 1 < argc) {
            opts.interval_secs = parse_u64("--interval", argv[++i]);
        } else {
            std::cerr << "watch-head: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || opts.genesis_path.empty()) {
        std::cerr << "watch-head: --rpc-port and --genesis are required\n";
        return 1;
    }
    try {
        return run_watch_head(opts);
    } catch (const std::exception& e) {
        std::cerr << "watch-head: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────── export-headers ───────────────────────────────

int cmd_export_headers(int argc, char** argv) {
    ExportOptions opts;
    bool have_port = false, have_from = false, have_count = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            opts.rpc_port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) {
            opts.genesis_path = argv[++i];
        } else if (a == "--from"    && i + 1 < argc) {
            opts.from = parse_u64("--from", argv[++i]); have_from = true;
        } else if (a == "--count"   && i + 1 < argc) {
            opts.count = parse_u64("--count", argv[++i]); have_count = true;
        } else if (a == "--out"     && i + 1 < argc) {
            opts.out_path = argv[++i];
        } else if (a == "--include-committee-sigs") {
            opts.include_committee_sigs = true;
        } else {
            std::cerr << "export-headers: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || opts.genesis_path.empty() || !have_from
        || !have_count || opts.out_path.empty()) {
        std::cerr << "export-headers: --rpc-port, --genesis, --from, --count, "
                     "--out are required\n";
        return 1;
    }
    return run_export_headers(opts);
}

// ──────────────────────── verify-archive ───────────────────────────────

int cmd_verify_archive(int argc, char** argv) {
    VerifyArchiveOptions opts;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"      && i + 1 < argc) opts.in_path      = argv[++i];
        else if (a == "--genesis" && i + 1 < argc) opts.genesis_path = argv[++i];
        else if (a == "--require-sigs")            opts.require_sigs  = true;
        else {
            std::cerr << "verify-archive: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (opts.in_path.empty() || opts.genesis_path.empty()) {
        std::cerr << "verify-archive: --in and --genesis are required\n";
        return 1;
    }
    return run_verify_archive(opts);
}

// ──────────────────────── export-state-bundle ──────────────────────────

int cmd_export_state_bundle(int argc, char** argv) {
    ExportStateBundleOptions opts;
    bool have_port = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port"  && i + 1 < argc) {
            opts.rpc_port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis"   && i + 1 < argc) opts.genesis_path = argv[++i];
        else if   (a == "--namespace" && i + 1 < argc) opts.ns           = argv[++i];
        else if   (a == "--key"       && i + 1 < argc) opts.key          = argv[++i];
        else if   (a == "--out"       && i + 1 < argc) opts.out_path     = argv[++i];
        else {
            std::cerr << "export-state-bundle: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || opts.genesis_path.empty() || opts.ns.empty()
        || opts.key.empty() || opts.out_path.empty()) {
        std::cerr << "export-state-bundle: --rpc-port, --genesis, --namespace, "
                     "--key, --out are required\n";
        return 1;
    }
    return run_export_state_bundle(opts);
}

// ──────────────────────── verify-state-bundle ──────────────────────────

int cmd_verify_state_bundle(int argc, char** argv) {
    VerifyStateBundleOptions opts;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"      && i + 1 < argc) opts.in_path      = argv[++i];
        else if (a == "--genesis" && i + 1 < argc) opts.genesis_path = argv[++i];
        else if (a == "--json")                    opts.json_out     = true;
        else {
            std::cerr << "verify-state-bundle: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (opts.in_path.empty() || opts.genesis_path.empty()) {
        std::cerr << "verify-state-bundle: --in and --genesis are required\n";
        return 1;
    }
    return verify_state_bundle(opts);
}

// ──────────────────────── verify-tx-inclusion ──────────────────────────

const char* verdict_str(InclusionVerdict v) {
    switch (v) {
        case InclusionVerdict::INCLUDED:     return "INCLUDED";
        case InclusionVerdict::NOT_INCLUDED: return "NOT-INCLUDED";
        case InclusionVerdict::UNVERIFIABLE: return "UNVERIFIABLE";
    }
    return "UNVERIFIABLE";
}

int cmd_verify_tx_inclusion(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, tx_hash;
    uint64_t height = 0;
    bool have_port = false, have_height = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--tx-hash" && i + 1 < argc) tx_hash      = argv[++i];
        else if   (a == "--height"  && i + 1 < argc) {
            height = parse_u64("--height", argv[++i]); have_height = true;
        } else if (a == "--json")                    json_out     = true;
        else {
            std::cerr << "verify-tx-inclusion: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || tx_hash.empty() || !have_height) {
        std::cerr << "verify-tx-inclusion: --rpc-port, --genesis, --tx-hash, "
                     "--height are required\n";
        return 1;
    }
    try {
        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-tx-inclusion: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        auto r = verify_tx_inclusion(rpc, committee_seed, genesis,
                                     height, tx_hash);

        bool included = (r.verdict == InclusionVerdict::INCLUDED);
        if (json_out) {
            json out = {
                {"included",           included},
                {"verdict",            verdict_str(r.verdict)},
                {"height",             r.height},
                {"tx_hash",            r.tx_hash_hex},
                {"tx_root",            r.tx_root_hex},
                {"block_hash",         r.block_hash_hex},
                {"committee_verified", r.committee_verified},
                {"sigs_verified",      r.sigs_verified},
                {"committee_size",     r.committee_size},
                {"tx_count",           r.tx_count},
            };
            // F-2 (NegativeVerdictSoundness.md): tag a NOT-INCLUDED with its
            // trust footing so a machine consumer can apply NV-6 clause (2) vs
            // (3). The block-body negative is CRYPTOGRAPHIC (NV-1: sound under
            // A2 via the full-set tx_root recompute + bijection gate).
            if (r.verdict == InclusionVerdict::NOT_INCLUDED)
                out["negative_footing"] = "cryptographic";
            if (!r.detail.empty()) out["detail"] = r.detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << verdict_str(r.verdict) << "\n"
                      << "  genesis pin:        matches (" << genesis_hash_hex << ")\n"
                      << "  tx_hash:            " << r.tx_hash_hex << "\n"
                      << "  height:             " << r.height << "\n";
            if (r.committee_verified) {
                if (r.height == 0) {
                    // Genesis is anchored by hash (it has no committee
                    // sigs — see verify_tx_inclusion); say so explicitly.
                    std::cout << "  anchor:             genesis hash "
                                 "(block 0 has no committee sigs)\n";
                } else {
                    std::cout << "  committee sigs:     " << r.sigs_verified
                              << " of " << r.committee_size << " verified\n";
                }
                std::cout << "  tx_root (signed):   " << r.tx_root_hex << "\n"
                          << "  block tx count:     " << r.tx_count << "\n";
            }
            if (!r.detail.empty())
                std::cout << "  detail:             " << r.detail << "\n";
        }

        // Exit codes: INCLUDED → 0; NOT-INCLUDED → 0 (a sound, verified
        // negative answer is success); UNVERIFIABLE → 3 (we refused to
        // answer because the committee binding broke / daemon tampered).
        if (r.verdict == InclusionVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-tx-inclusion: " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────────── verify-receipt-inclusion ──────────────────────
//
// Trust-minimized INCLUDED / NOT-INCLUDED / UNVERIFIABLE verdict on
// whether a cross-shard inbound receipt (src_shard, tx_hash) lives in the
// committee-verified `i:` (applied_inbound_receipts) namespace.
//
// This is the receipt-membership analogue of verify-tx-inclusion (which
// proves tx membership in a block body) and the trustless state-proof
// read of stake-trustless (which Merkle-verifies an `s:`-namespace leaf
// against a committee-signed state_root). The receipt path differs in
// three ways:
//
//   * Namespace is "i" and the leaf key is COMPOSITE — it is NOT a plain
//     ASCII domain. The canonical encoding (see chain.cpp
//     build_state_leaves, "applied_inbound_receipts_" branch) is:
//         key       = 'i' ':' || u64_be(src_shard) || tx_hash[32]
//         value_hash = SHA256(0x01)                 // presence marker
//     The verifier recomputes BOTH locally and demands the proof's
//     key_bytes == local key AND its value_hash == SHA256(0x01). Without
//     those two equalities a daemon could serve a valid Merkle proof for
//     some OTHER leaf and pass a bare verify_state_proof — so they are the
//     load-bearing binding to THIS receipt.
//
//   * A receipt is a SET membership (present/absent), not a (value)
//     decode. There is no cleartext cross-check RPC (unlike `stake_info`
//     for stakes); the presence marker IS the whole payload. Membership
//     is therefore proven entirely by the Merkle inclusion of the
//     canonical (key, SHA256(0x01)) leaf under the committee-signed root.
//
//   * Receipts are append-only / stable once applied (chain.cpp inserts
//     into applied_inbound_receipts_ and never erases — the only mutation
//     is via the atomic snapshot rollback on a FAILED apply). So unlike a
//     per-block counter there is NO per-block race: once present at any
//     height H the receipt is present at every height >= H, and the
//     head-only state_proof RPC is sufficient.
//
// Fail-closed contract: any tamper, malformed proof, key/value mismatch,
// or daemon refusal to serve the `i:` proof yields UNVERIFIABLE (exit 3),
// never a false INCLUDED. A clean Merkle-verified inclusion → INCLUDED
// (exit 0); a daemon `not_found` for the canonical key → NOT-INCLUDED
// (exit 0, a DAEMON-ASSERTED negative — sound only under the single-daemon
// negative-honesty premise (H-neg), NOT a cryptographic absence proof: the
// sorted-leaves tree has no non-membership witness, MerkleTreeSoundness.md
// MT-5 / NegativeVerdictSoundness.md NV-2/NV-3. The --json carries
// negative_footing=daemon_asserted so a consumer applies NV-6 clause 3).

int cmd_verify_receipt_inclusion(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, tx_hash_hex;
    uint64_t src_shard = 0;
    uint64_t wait_seconds = 0;
    bool have_port = false, have_shard = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port"  && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis"   && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--src-shard" && i + 1 < argc) {
            src_shard = parse_u64("--src-shard", argv[++i]); have_shard = true;
        } else if (a == "--tx-hash"   && i + 1 < argc) tx_hash_hex  = argv[++i];
        else if   (a == "--json")                      json_out     = true;
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "verify-receipt-inclusion: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || !have_shard || tx_hash_hex.empty()) {
        std::cerr << "verify-receipt-inclusion: --rpc-port, --genesis, "
                     "--src-shard, --tx-hash are required\n";
        return 1;
    }

    // The verdict mirrors verify-tx-inclusion's tri-state.
    InclusionVerdict verdict = InclusionVerdict::UNVERIFIABLE;
    std::string detail;
    std::string state_root_used;
    uint64_t    anchored_height = 0;

    try {
        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-receipt-inclusion: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // Parse the 32-byte tx_hash now so a malformed hash fails fast.
        Hash tx_hash = from_hex_arr<32>(tx_hash_hex);

        // Compute the canonical receipt key bytes locally, byte-for-byte
        // matching chain.cpp build_state_leaves:
        //   'i' ':' || u64_be(src_shard) || tx_hash[32]
        std::vector<uint8_t> local_key;
        local_key.reserve(2 + 8 + 32);
        local_key.push_back('i'); local_key.push_back(':');
        for (int i = 7; i >= 0; --i)
            local_key.push_back(static_cast<uint8_t>((src_shard >> (8 * i)) & 0xff));
        local_key.insert(local_key.end(), tx_hash.begin(), tx_hash.end());

        // The committed value for a present receipt is SHA256(0x01).
        determ::crypto::SHA256Builder mb;
        uint8_t marker = 1; mb.append(&marker, 1);
        Hash expected_value_hash = mb.finalize();

        // Committee-verify the header chain end-to-end, capturing the
        // head's state_root (the anchor for the Merkle inclusion).
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex, /*track_registry=*/false, genesis.k_block_sigs, genesis.bft_enabled);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `i:` state-proofs cannot be "
                "anchored");
        }

        // Fetch the `i:`-namespace state-proof. The daemon takes a string
        // `key`; for composite-key namespaces it builds the prefixed key
        // bytes from this string. The post-prefix body (everything after
        // "i:") is BINARY — u64_be(src) || tx_hash — which cannot ride raw
        // inside a JSON string: nlohmann::json::dump() throws on the
        // non-UTF-8 bytes a SHA-256 tx_hash almost always contains. So we
        // HEX-encode the body; the daemon hex-decodes it and prepends "i:"
        // to reconstruct the canonical key byte-for-byte.
        std::vector<uint8_t> body;
        body.reserve(8 + 32);
        for (int i = 7; i >= 0; --i)
            body.push_back(static_cast<uint8_t>((src_shard >> (8 * i)) & 0xff));
        body.insert(body.end(), tx_hash.begin(), tx_hash.end());
        std::string key_body_hex = to_hex(body.data(), body.size());

        auto proof = rpc.call("state_proof",
            {{"namespace", "i"}, {"key", key_body_hex}});

        // A daemon that cannot serve the `i:` namespace (e.g. the RPC does
        // not expose composite-key namespaces) returns an `error`. We
        // distinguish a daemon-reported absence (`not_found` for our exact
        // key → NOT-INCLUDED, a daemon-asserted negative per (H-neg) —
        // NV-2/NV-3) from any other refusal (→ UNVERIFIABLE,
        // fail closed — we will not assert membership either way).
        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].is_string()
                ? proof["error"].get<std::string>()
                : proof["error"].dump();
            if (err == "not_found") {
                verdict = InclusionVerdict::NOT_INCLUDED;
                detail  = "daemon reports no `i:` leaf for the canonical "
                          "receipt key (state_proof not_found)";
            } else {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "daemon refused the `i:` state-proof: " + err
                        + " (cannot prove membership trustlessly)";
            }
        } else {
            // Bind the proof to THIS receipt: (1) key_bytes must equal the
            // locally-computed canonical key, (2) value_hash must equal
            // SHA256(0x01). Either mismatch means the daemon served a proof
            // for a different leaf → UNVERIFIABLE.
            std::string proof_key_hex =
                proof.value("key_bytes", std::string{});
            std::string local_key_hex = to_hex(local_key.data(), local_key.size());
            if (proof_key_hex != local_key_hex) {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "proof.key_bytes=" + proof_key_hex
                        + " does not match the canonical receipt key "
                        + local_key_hex
                        + " (daemon served a proof for a different leaf)";
            } else {
                Hash proof_value_hash = from_hex_arr<32>(
                    proof.value("value_hash", std::string{}));
                if (proof_value_hash != expected_value_hash) {
                    verdict = InclusionVerdict::UNVERIFIABLE;
                    detail  = "proof.value_hash=" + to_hex(proof_value_hash)
                            + " is not the presence marker SHA256(0x01)="
                            + to_hex(expected_value_hash);
                } else {
                    // Anchor the proof's claimed state_root to a
                    // committee-signed header (the chain may have advanced
                    // during the round-trip), mirroring stake-trustless.
                    uint64_t proof_height =
                        proof.value("height", uint64_t{0});
                    std::string proof_root =
                        proof.value("state_root", std::string{});
                    std::string anchor_root = vc.head_state_root;
                    uint64_t    anchor_at   = vc.height;

                    if (proof_height < vc.height) {
                        throw std::runtime_error(
                            "proof.height=" + std::to_string(proof_height)
                            + " is BEFORE verified-chain head="
                            + std::to_string(vc.height)
                            + " — daemon is serving stale state");
                    }
                    // SOUNDNESS: the committee signs compute_block_digest,
                    // which EXCLUDES state_root, so the daemon's state_root
                    // FIELD is NOT committee-attested. Bind proof_root to the
                    // COMMITTEE-SIGNED root committed by block proof_height-1
                    // via committee_bound_state_root (full-block recompute +
                    // successor-sig binding), never the bare header field.
                    {
                        json committee_json;
                        {
                            json arr = json::array();
                            for (auto& [domain_, pk] : committee_seed)
                                arr.push_back({{"domain", domain_},
                                               {"ed_pub", to_hex(pk)}});
                            committee_json = json{{"members", arr}};
                        }
                        uint64_t anchor_index = proof_height - 1;
                        std::string attested =
                            determ::light::committee_bound_state_root(rpc, committee_json, anchor_index, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
                        if (attested != proof_root) {
                            throw std::runtime_error(
                                "verify-receipt-inclusion: SECURITY — "
                                "committee-attested state_root at index "
                                + std::to_string(anchor_index) + " = " + attested
                                + " does NOT match proof.state_root = " + proof_root
                                + " — daemon served a proof against an "
                                  "unattested root");
                        }
                        vc.head_state_root = attested;  // downstream reporting uses the ATTESTED root
                        vc.height = proof_height;
                        anchor_root = attested;
                        anchor_at   = proof_height;
                    }

                    // Merkle-verify the proof against the committee-signed
                    // root. verify_state_proof re-derives key_bytes +
                    // value_hash from the proof JSON and rolls the siblings
                    // up to anchor_root; we already bound those to the
                    // canonical receipt above, so a pass here is a sound
                    // INCLUDED.
                    auto vsp = verify_state_proof(proof, anchor_root);
                    if (!vsp.ok) {
                        verdict = InclusionVerdict::UNVERIFIABLE;
                        detail  = "merkle verification failed: " + vsp.detail;
                    } else {
                        verdict = InclusionVerdict::INCLUDED;
                        state_root_used = anchor_root;
                        anchored_height = anchor_at;
                    }
                }
            }
        }

        std::string canon_tx_hash = to_hex(tx_hash);
        bool included = (verdict == InclusionVerdict::INCLUDED);
        if (json_out) {
            json out = {
                {"included",    included},
                {"verdict",     verdict_str(verdict)},
                {"src_shard",   src_shard},
                {"tx_hash",     canon_tx_hash},
                {"namespace",   "i"},
            };
            // F-2 (NegativeVerdictSoundness.md): the i: state-proof negative is
            // DAEMON_ASSERTED — sound only under the non-cryptographic (H-neg)
            // premise (NV-2/NV-3); a consumer MUST apply NV-6 clause (3).
            if (verdict == InclusionVerdict::NOT_INCLUDED)
                out["negative_footing"] = "daemon_asserted";
            if (!state_root_used.empty()) {
                out["state_root"] = state_root_used;
                out["height"]     = anchored_height;
            }
            if (!detail.empty()) out["detail"] = detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << verdict_str(verdict) << "\n"
                      << "  genesis pin:   matches (" << genesis_hash_hex << ")\n"
                      << "  namespace:     i (applied_inbound_receipts)\n"
                      << "  src_shard:     " << src_shard << "\n"
                      << "  tx_hash:       " << canon_tx_hash << "\n";
            if (verdict == InclusionVerdict::INCLUDED) {
                std::cout << "  state_root:    " << state_root_used << "\n"
                          << "  anchored at H: " << anchored_height << "\n";
            }
            if (!detail.empty())
                std::cout << "  detail:        " << detail << "\n";
        }

        // Exit codes match verify-tx-inclusion: INCLUDED / NOT-INCLUDED →
        // 0 (a definite answer; NOT-INCLUDED is daemon-asserted, (H-neg));
        // UNVERIFIABLE → 3 (refused to assert).
        if (verdict == InclusionVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-receipt-inclusion: " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────────── verify-merge-state ────────────────────────────
//
// Trust-minimized INCLUDED / NOT-INCLUDED / UNVERIFIABLE verdict on
// whether a shard's under-quorum-merge record (shard_id → partner_id +
// refugee_region) lives in the committee-verified `m:` (merge_state)
// namespace, with the proof bound to the EXACT (partner_id, refugee_region)
// the caller asserts.
//
// This is the merge-state analogue of verify-receipt-inclusion (which
// proves `i:` receipt membership) and stake-trustless (which Merkle-
// verifies an `s:` leaf against a committee-signed state_root). It uses the
// SAME composite-key state-proof path the daemon now serves (the caller
// hex-encodes the binary key body; see src/node/node.cpp rpc_state_proof).
// The merge path differs from the receipt path in two ways:
//
//   * Namespace is "m" and the leaf key is COMPOSITE but SHORT. The
//     canonical encoding (see chain.cpp build_state_leaves, "merge_state_"
//     branch) is:
//         key        = 'm' ':' || u32_be(shard_id)
//         value_hash = SHA256( u64_be(partner_id)
//                            || u64_be(refugee_region.size())
//                            || refugee_region )
//     The verifier recomputes BOTH locally and demands the proof's
//     key_bytes == local key AND its value_hash == the locally-recomputed
//     hash. The value_hash binding is load-bearing: unlike `i:` (whose
//     value is the constant presence marker SHA256(0x01)), a `m:` leaf
//     carries DATA, so a daemon could serve a valid Merkle proof for shard
//     S that encodes a DIFFERENT partner/region. Recomputing the hash from
//     the caller-asserted (partner_id, refugee_region) forces the proof to
//     match exactly that record — a daemon lie about either field is
//     detected, not propagated.
//
//   * merge_state is mutable: a MERGE_END erases the leaf (chain.cpp). So
//     this is a head-anchored present/absent verdict, NOT an append-only
//     guarantee — INCLUDED means "merged INTO partner_id with that refugee
//     region AS OF the committee-verified head", and a later revert makes
//     the same query return NOT-INCLUDED. The verdict is therefore always
//     anchored to (and reported with) the head height it was proven at.
//
// Fail-closed contract: any tamper, malformed proof, key/value mismatch,
// or daemon refusal to serve the `m:` proof yields UNVERIFIABLE (exit 3),
// never a false INCLUDED. A clean Merkle-verified inclusion → INCLUDED
// (exit 0); a daemon `not_found` for the canonical key → NOT-INCLUDED
// (exit 0, a DAEMON-ASSERTED negative — sound only under (H-neg), NOT a
// cryptographic absence proof, MT-5 / NV-2/NV-3; --json negative_footing=
// daemon_asserted. It says "shard S not merged into THAT partner with THAT
// region" only insofar as the single daemon answers absences honestly).

int cmd_verify_merge_state(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, refugee_region;
    uint64_t shard_id = 0, partner_id = 0;
    uint64_t wait_seconds = 0;
    bool have_port = false, have_shard = false, have_partner = false,
         have_region = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port"  && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis"   && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--shard-id"   && i + 1 < argc) {
            shard_id = parse_u64("--shard-id", argv[++i]); have_shard = true;
        } else if (a == "--partner-id" && i + 1 < argc) {
            partner_id = parse_u64("--partner-id", argv[++i]); have_partner = true;
        } else if (a == "--refugee-region" && i + 1 < argc) {
            refugee_region = argv[++i]; have_region = true;
        } else if (a == "--json")                      json_out     = true;
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "verify-merge-state: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || !have_shard || !have_partner
        || !have_region) {
        std::cerr << "verify-merge-state: --rpc-port, --genesis, --shard-id, "
                     "--partner-id, --refugee-region are required\n";
        return 1;
    }
    // shard_id and partner_id are u32 on the wire (build_state_leaves emits
    // u32_be(shard_id) keys and stores ShardId partner_id). Reject anything
    // that cannot fit so a malformed query can't silently alias a leaf.
    if (shard_id > 0xffffffffull) {
        std::cerr << "verify-merge-state: --shard-id exceeds u32 range\n";
        return 1;
    }
    if (partner_id > 0xffffffffull) {
        std::cerr << "verify-merge-state: --partner-id exceeds u32 range\n";
        return 1;
    }
    // The region binds into the leaf hash with a u64_be length prefix; cap
    // it at the MERGE_EVENT wire ceiling (32 bytes) so a query can't assert
    // a region the protocol could never have stored.
    if (refugee_region.size() > 32) {
        std::cerr << "verify-merge-state: --refugee-region exceeds 32 bytes\n";
        return 1;
    }

    // The verdict mirrors verify-receipt-inclusion's tri-state.
    InclusionVerdict verdict = InclusionVerdict::UNVERIFIABLE;
    std::string detail;
    std::string state_root_used;
    uint64_t    anchored_height = 0;

    try {
        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-merge-state: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // Compute the canonical merge_state key bytes locally, byte-for-byte
        // matching chain.cpp build_state_leaves "merge_state_" branch:
        //   'm' ':' || u32_be(shard_id)
        std::vector<uint8_t> local_key;
        local_key.reserve(2 + 4);
        local_key.push_back('m'); local_key.push_back(':');
        for (int i = 3; i >= 0; --i)
            local_key.push_back(static_cast<uint8_t>(
                (static_cast<uint32_t>(shard_id) >> (8 * i)) & 0xff));

        // The committed value for THIS merge record:
        //   SHA256(u64_be(partner_id) || u64_be(region_len) || region)
        determ::crypto::SHA256Builder mb;
        mb.append(static_cast<uint64_t>(partner_id));
        mb.append(static_cast<uint64_t>(refugee_region.size()));
        mb.append(refugee_region);
        Hash expected_value_hash = mb.finalize();

        // Committee-verify the header chain end-to-end, capturing the
        // head's state_root (the anchor for the Merkle inclusion).
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex, /*track_registry=*/false, genesis.k_block_sigs, genesis.bft_enabled);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `m:` state-proofs cannot be "
                "anchored");
        }

        // Fetch the `m:`-namespace state-proof. The daemon takes a string
        // `key`; for composite-key namespaces it hex-decodes the post-prefix
        // body and prepends "m:" to reconstruct the canonical key. The body
        // here is u32_be(shard_id) (4 bytes) — see rpc_state_proof's width
        // enforcement.
        std::vector<uint8_t> body;
        body.reserve(4);
        for (int i = 3; i >= 0; --i)
            body.push_back(static_cast<uint8_t>(
                (static_cast<uint32_t>(shard_id) >> (8 * i)) & 0xff));
        std::string key_body_hex = to_hex(body.data(), body.size());

        auto proof = rpc.call("state_proof",
            {{"namespace", "m"}, {"key", key_body_hex}});

        // A daemon that cannot serve the `m:` namespace returns an `error`.
        // We distinguish a daemon-reported absence (`not_found` for our exact
        // key → NOT-INCLUDED, a daemon-asserted negative per (H-neg) —
        // NV-2/NV-3) from any other refusal (→ UNVERIFIABLE,
        // fail closed — we will not assert membership either way).
        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].is_string()
                ? proof["error"].get<std::string>()
                : proof["error"].dump();
            if (err == "not_found") {
                verdict = InclusionVerdict::NOT_INCLUDED;
                detail  = "daemon reports no `m:` leaf for shard "
                        + std::to_string(shard_id)
                        + " (state_proof not_found — shard is not currently "
                          "merged)";
            } else {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "daemon refused the `m:` state-proof: " + err
                        + " (cannot prove membership trustlessly)";
            }
        } else {
            // Bind the proof to THIS merge record: (1) key_bytes must equal
            // the locally-computed canonical key, (2) value_hash must equal
            // the locally-recomputed SHA256 over (partner_id, region). Either
            // mismatch means the daemon served a proof for a different leaf
            // OR is lying about the merge's partner/region → UNVERIFIABLE.
            std::string proof_key_hex =
                proof.value("key_bytes", std::string{});
            std::string local_key_hex = to_hex(local_key.data(), local_key.size());
            if (proof_key_hex != local_key_hex) {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "proof.key_bytes=" + proof_key_hex
                        + " does not match the canonical merge key "
                        + local_key_hex
                        + " (daemon served a proof for a different leaf)";
            } else {
                Hash proof_value_hash = from_hex_arr<32>(
                    proof.value("value_hash", std::string{}));
                if (proof_value_hash != expected_value_hash) {
                    verdict = InclusionVerdict::UNVERIFIABLE;
                    detail  = "proof.value_hash=" + to_hex(proof_value_hash)
                            + " does not match the recomputed hash of "
                              "(partner_id=" + std::to_string(partner_id)
                            + ", refugee_region=\"" + refugee_region + "\")="
                            + to_hex(expected_value_hash)
                            + " — daemon is lying about the merge's "
                              "partner/region OR proving a different record";
                } else {
                    // Anchor the proof's claimed state_root to a
                    // committee-signed header (the chain may have advanced
                    // during the round-trip), mirroring verify-receipt-
                    // inclusion / stake-trustless.
                    uint64_t proof_height =
                        proof.value("height", uint64_t{0});
                    std::string proof_root =
                        proof.value("state_root", std::string{});
                    std::string anchor_root = vc.head_state_root;
                    uint64_t    anchor_at   = vc.height;

                    if (proof_height < vc.height) {
                        throw std::runtime_error(
                            "proof.height=" + std::to_string(proof_height)
                            + " is BEFORE verified-chain head="
                            + std::to_string(vc.height)
                            + " — daemon is serving stale state");
                    }
                    // SOUNDNESS: the committee signs compute_block_digest,
                    // which EXCLUDES state_root, so the daemon's state_root
                    // FIELD is NOT committee-attested. Bind proof_root to the
                    // COMMITTEE-SIGNED root committed by block proof_height-1
                    // via committee_bound_state_root (full-block recompute +
                    // successor-sig binding), never the bare header field.
                    {
                        json committee_json;
                        {
                            json arr = json::array();
                            for (auto& [domain_, pk] : committee_seed)
                                arr.push_back({{"domain", domain_},
                                               {"ed_pub", to_hex(pk)}});
                            committee_json = json{{"members", arr}};
                        }
                        uint64_t anchor_index = proof_height - 1;
                        std::string attested =
                            determ::light::committee_bound_state_root(rpc, committee_json, anchor_index, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
                        if (attested != proof_root) {
                            throw std::runtime_error(
                                "verify-merge-state: SECURITY — "
                                "committee-attested state_root at index "
                                + std::to_string(anchor_index) + " = " + attested
                                + " does NOT match proof.state_root = " + proof_root
                                + " — daemon served a proof against an "
                                  "unattested root");
                        }
                        vc.head_state_root = attested;  // downstream reporting uses the ATTESTED root
                        vc.height = proof_height;
                        anchor_root = attested;
                        anchor_at   = proof_height;
                    }

                    // Merkle-verify the proof against the committee-signed
                    // root. verify_state_proof re-derives key_bytes +
                    // value_hash from the proof JSON and rolls the siblings
                    // up to anchor_root; we already bound those to the
                    // canonical merge record above, so a pass here is a
                    // sound INCLUDED.
                    auto vsp = verify_state_proof(proof, anchor_root);
                    if (!vsp.ok) {
                        verdict = InclusionVerdict::UNVERIFIABLE;
                        detail  = "merkle verification failed: " + vsp.detail;
                    } else {
                        verdict = InclusionVerdict::INCLUDED;
                        state_root_used = anchor_root;
                        anchored_height = anchor_at;
                    }
                }
            }
        }

        bool included = (verdict == InclusionVerdict::INCLUDED);
        if (json_out) {
            json out = {
                {"included",       included},
                {"verdict",        verdict_str(verdict)},
                {"shard_id",       shard_id},
                {"partner_id",     partner_id},
                {"refugee_region", refugee_region},
                {"namespace",      "m"},
            };
            // F-2 (NegativeVerdictSoundness.md): the m: state-proof negative is
            // DAEMON_ASSERTED — sound only under the non-cryptographic (H-neg)
            // premise (NV-2/NV-3); a consumer MUST apply NV-6 clause (3).
            if (verdict == InclusionVerdict::NOT_INCLUDED)
                out["negative_footing"] = "daemon_asserted";
            if (!state_root_used.empty()) {
                out["state_root"] = state_root_used;
                out["height"]     = anchored_height;
            }
            if (!detail.empty()) out["detail"] = detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << verdict_str(verdict) << "\n"
                      << "  genesis pin:    matches (" << genesis_hash_hex << ")\n"
                      << "  namespace:      m (merge_state)\n"
                      << "  shard_id:       " << shard_id << "\n"
                      << "  partner_id:     " << partner_id << "\n"
                      << "  refugee_region: " << refugee_region << "\n";
            if (verdict == InclusionVerdict::INCLUDED) {
                std::cout << "  state_root:     " << state_root_used << "\n"
                          << "  anchored at H:  " << anchored_height << "\n";
            }
            if (!detail.empty())
                std::cout << "  detail:         " << detail << "\n";
        }

        // Exit codes match verify-receipt-inclusion: INCLUDED / NOT-INCLUDED
        // → 0 (a definite answer; NOT-INCLUDED is daemon-asserted, (H-neg));
        // UNVERIFIABLE → 3 (refused to assert).
        if (verdict == InclusionVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-merge-state: " << e.what() << "\n";
        return 1;
    }
}

// ────────────────────── verify-param-change ────────────────────────────
//
// Trust-minimized INCLUDED / NOT-INCLUDED / UNVERIFIABLE verdict on
// whether a staged governance parameter change (effective_height, idx →
// name + value) lives in the committee-verified `p:` (pending_param_changes)
// namespace, with the proof bound to the EXACT (name, value) the caller
// asserts.
//
// This is the governance analogue of verify-merge-state (which proves `m:`
// merge-record membership) and verify-receipt-inclusion (which proves `i:`
// receipt membership). It uses the SAME composite-key state-proof path the
// daemon serves (the caller hex-encodes the binary key body; see
// src/node/node.cpp rpc_state_proof). The pending-param path differs from
// the merge path in two ways:
//
//   * Namespace is "p" and the leaf key is COMPOSITE and WIDER. The
//     canonical encoding (see chain.cpp build_state_leaves,
//     "pending_param_changes_" branch) is:
//         key        = 'p' ':' || u64_be(effective_height) || u32_be(idx)
//         value_hash = SHA256( u64_be(name.size())  || name
//                            || u64_be(value.size()) || value )      // value
//                                                                    // omitted
//                                                                    // when empty
//     where idx is the entry's 0-based position within the per-height
//     bucket. The verifier recomputes BOTH locally and demands the proof's
//     key_bytes == local key AND its value_hash == the locally-recomputed
//     hash. The value_hash binding is load-bearing: like `m:` (and unlike
//     `i:` whose value is the constant presence marker SHA256(0x01)), a `p:`
//     leaf carries DATA, so a daemon could serve a valid Merkle proof for
//     slot (eff,idx) that encodes a DIFFERENT parameter name or value.
//     Recomputing the hash from the caller-asserted (name, value_hex) forces
//     the proof to match exactly that staged change — a daemon lie about
//     either field is detected, not propagated.
//
//   * pending_param_changes is consumed at activation: activate_pending_params
//     erases each per-height bucket once current_height reaches it (chain.cpp).
//     So this is a head-anchored present/absent verdict, NOT an append-only
//     guarantee — INCLUDED means "this exact change is STILL STAGED (not yet
//     activated) AS OF the committee-verified head", and once the chain
//     advances past effective_height the same query returns NOT-INCLUDED.
//     The verdict is therefore always anchored to (and reported with) the
//     head height it was proven at.
//
// Discovery: the daemon's `pending_params` RPC lists each staged entry's
// (effective_height, name, value_hex). The caller reads that to obtain the
// (height, name, value) to assert here; --idx is the 0-based position of the
// target entry within its effective_height bucket (the bucket is emitted in
// insertion order by both the RPC and build_state_leaves, so the RPC's
// per-height ordinal IS the leaf idx).
//
// Fail-closed contract: any tamper, malformed proof, key/value mismatch, or
// daemon refusal to serve the `p:` proof yields UNVERIFIABLE (exit 3), never
// a false INCLUDED. A clean Merkle-verified inclusion → INCLUDED (exit 0); a
// daemon `not_found` for the canonical key → NOT-INCLUDED (exit 0, a DAEMON-
// ASSERTED negative — sound only under (H-neg), NOT a cryptographic absence
// proof, MT-5 / NV-2/NV-3; --json negative_footing=daemon_asserted. "No such
// change is staged at that slot" holds only insofar as the daemon answers
// absences honestly).

int cmd_verify_param_change(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, name, value_hex;
    uint64_t eff_height = 0, idx = 0;
    uint64_t wait_seconds = 0;
    bool have_port = false, have_eff = false, have_idx = false,
         have_name = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis"  && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--effective-height" && i + 1 < argc) {
            eff_height = parse_u64("--effective-height", argv[++i]); have_eff = true;
        } else if (a == "--idx"      && i + 1 < argc) {
            idx = parse_u64("--idx", argv[++i]); have_idx = true;
        } else if (a == "--name"     && i + 1 < argc) {
            name = argv[++i]; have_name = true;
        } else if (a == "--value-hex" && i + 1 < argc) value_hex = argv[++i];
        else if   (a == "--json")                      json_out  = true;
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "verify-param-change: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || !have_eff || !have_idx
        || !have_name) {
        std::cerr << "verify-param-change: --rpc-port, --genesis, "
                     "--effective-height, --idx, --name are required\n";
        return 1;
    }
    // idx is u32 on the wire (build_state_leaves emits u32_be(idx)). Reject
    // anything that cannot fit so a malformed query can't silently alias a
    // different leaf.
    if (idx > 0xffffffffull) {
        std::cerr << "verify-param-change: --idx exceeds u32 range\n";
        return 1;
    }

    // The verdict mirrors verify-merge-state's tri-state.
    InclusionVerdict verdict = InclusionVerdict::UNVERIFIABLE;
    std::string detail;
    std::string state_root_used;
    uint64_t    anchored_height = 0;

    try {
        // The asserted value (may be empty — a zero-length param value is
        // legal, and build_state_leaves appends the value bytes only when
        // non-empty). from_hex throws on malformed hex, so a bad --value-hex
        // fails fast before any RPC.
        std::vector<uint8_t> value =
            value_hex.empty() ? std::vector<uint8_t>{} : from_hex(value_hex);

        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-param-change: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // Compute the canonical pending_param_changes key bytes locally,
        // byte-for-byte matching chain.cpp build_state_leaves
        // "pending_param_changes_" branch:
        //   'p' ':' || u64_be(effective_height) || u32_be(idx)
        std::vector<uint8_t> local_key;
        local_key.reserve(2 + 8 + 4);
        local_key.push_back('p'); local_key.push_back(':');
        for (int i = 7; i >= 0; --i)
            local_key.push_back(static_cast<uint8_t>((eff_height >> (8 * i)) & 0xff));
        for (int i = 3; i >= 0; --i)
            local_key.push_back(static_cast<uint8_t>(
                (static_cast<uint32_t>(idx) >> (8 * i)) & 0xff));

        // The committed value for THIS staged change:
        //   SHA256(u64_be(name_len) || name || u64_be(value_len) || value)
        // (value bytes appended only when non-empty — matching the
        // build_state_leaves `if (!value.empty())` guard).
        determ::crypto::SHA256Builder mb;
        mb.append(static_cast<uint64_t>(name.size()));
        mb.append(name);
        mb.append(static_cast<uint64_t>(value.size()));
        if (!value.empty()) mb.append(value.data(), value.size());
        Hash expected_value_hash = mb.finalize();

        // Committee-verify the header chain end-to-end, capturing the
        // head's state_root (the anchor for the Merkle inclusion).
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex, /*track_registry=*/false, genesis.k_block_sigs, genesis.bft_enabled);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `p:` state-proofs cannot be "
                "anchored");
        }

        // Fetch the `p:`-namespace state-proof. The daemon takes a string
        // `key`; for composite-key namespaces it hex-decodes the post-prefix
        // body and prepends "p:" to reconstruct the canonical key. The body
        // here is u64_be(eff_height) || u32_be(idx) (12 bytes) — see
        // rpc_state_proof's width enforcement.
        std::vector<uint8_t> body;
        body.reserve(8 + 4);
        for (int i = 7; i >= 0; --i)
            body.push_back(static_cast<uint8_t>((eff_height >> (8 * i)) & 0xff));
        for (int i = 3; i >= 0; --i)
            body.push_back(static_cast<uint8_t>(
                (static_cast<uint32_t>(idx) >> (8 * i)) & 0xff));
        std::string key_body_hex = to_hex(body.data(), body.size());

        auto proof = rpc.call("state_proof",
            {{"namespace", "p"}, {"key", key_body_hex}});

        // A daemon that cannot serve the `p:` namespace returns an `error`.
        // We distinguish a daemon-reported absence (`not_found` for our exact
        // key → NOT-INCLUDED, a daemon-asserted negative per (H-neg) —
        // NV-2/NV-3) from any other refusal (→ UNVERIFIABLE,
        // fail closed — we will not assert membership either way).
        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].is_string()
                ? proof["error"].get<std::string>()
                : proof["error"].dump();
            if (err == "not_found") {
                verdict = InclusionVerdict::NOT_INCLUDED;
                detail  = "daemon reports no `p:` leaf for slot (eff_height="
                        + std::to_string(eff_height) + ", idx="
                        + std::to_string(idx) + ") — no such change is staged "
                          "(state_proof not_found; may already have activated)";
            } else {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "daemon refused the `p:` state-proof: " + err
                        + " (cannot prove membership trustlessly)";
            }
        } else {
            // Bind the proof to THIS staged change: (1) key_bytes must equal
            // the locally-computed canonical key, (2) value_hash must equal
            // the locally-recomputed SHA256 over (name, value). Either
            // mismatch means the daemon served a proof for a different leaf
            // OR is lying about the change's name/value → UNVERIFIABLE.
            std::string proof_key_hex =
                proof.value("key_bytes", std::string{});
            std::string local_key_hex = to_hex(local_key.data(), local_key.size());
            if (proof_key_hex != local_key_hex) {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "proof.key_bytes=" + proof_key_hex
                        + " does not match the canonical param-change key "
                        + local_key_hex
                        + " (daemon served a proof for a different leaf)";
            } else {
                Hash proof_value_hash = from_hex_arr<32>(
                    proof.value("value_hash", std::string{}));
                if (proof_value_hash != expected_value_hash) {
                    verdict = InclusionVerdict::UNVERIFIABLE;
                    detail  = "proof.value_hash=" + to_hex(proof_value_hash)
                            + " does not match the recomputed hash of "
                              "(name=\"" + name + "\", value_hex="
                            + (value_hex.empty() ? "<empty>" : value_hex) + ")="
                            + to_hex(expected_value_hash)
                            + " — daemon is lying about the change's "
                              "name/value OR proving a different slot";
                } else {
                    // Anchor the proof's claimed state_root to a
                    // committee-signed header (the chain may have advanced
                    // during the round-trip), mirroring verify-merge-state /
                    // verify-receipt-inclusion.
                    uint64_t proof_height =
                        proof.value("height", uint64_t{0});
                    std::string proof_root =
                        proof.value("state_root", std::string{});
                    std::string anchor_root = vc.head_state_root;
                    uint64_t    anchor_at   = vc.height;

                    if (proof_height < vc.height) {
                        throw std::runtime_error(
                            "proof.height=" + std::to_string(proof_height)
                            + " is BEFORE verified-chain head="
                            + std::to_string(vc.height)
                            + " — daemon is serving stale state");
                    }
                    // SOUNDNESS: the committee signs compute_block_digest,
                    // which EXCLUDES state_root, so the daemon's state_root
                    // FIELD is NOT committee-attested. Bind proof_root to the
                    // COMMITTEE-SIGNED root committed by block proof_height-1
                    // via committee_bound_state_root (full-block recompute +
                    // successor-sig binding), never the bare header field.
                    {
                        json committee_json;
                        {
                            json arr = json::array();
                            for (auto& [domain_, pk] : committee_seed)
                                arr.push_back({{"domain", domain_},
                                               {"ed_pub", to_hex(pk)}});
                            committee_json = json{{"members", arr}};
                        }
                        uint64_t anchor_index = proof_height - 1;
                        std::string attested =
                            determ::light::committee_bound_state_root(rpc, committee_json, anchor_index, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
                        if (attested != proof_root) {
                            throw std::runtime_error(
                                "verify-param-change: SECURITY — "
                                "committee-attested state_root at index "
                                + std::to_string(anchor_index) + " = " + attested
                                + " does NOT match proof.state_root = " + proof_root
                                + " — daemon served a proof against an "
                                  "unattested root");
                        }
                        vc.head_state_root = attested;  // downstream reporting uses the ATTESTED root
                        vc.height = proof_height;
                        anchor_root = attested;
                        anchor_at   = proof_height;
                    }

                    // Merkle-verify the proof against the committee-signed
                    // root. verify_state_proof re-derives key_bytes +
                    // value_hash from the proof JSON and rolls the siblings
                    // up to anchor_root; we already bound those to the
                    // canonical staged change above, so a pass here is a
                    // sound INCLUDED.
                    auto vsp = verify_state_proof(proof, anchor_root);
                    if (!vsp.ok) {
                        verdict = InclusionVerdict::UNVERIFIABLE;
                        detail  = "merkle verification failed: " + vsp.detail;
                    } else {
                        verdict = InclusionVerdict::INCLUDED;
                        state_root_used = anchor_root;
                        anchored_height = anchor_at;
                    }
                }
            }
        }

        bool included = (verdict == InclusionVerdict::INCLUDED);
        if (json_out) {
            json out = {
                {"included",         included},
                {"verdict",          verdict_str(verdict)},
                {"effective_height", eff_height},
                {"idx",              idx},
                {"name",             name},
                {"value_hex",        value_hex},
                {"namespace",        "p"},
            };
            // F-2 (NegativeVerdictSoundness.md): the p: state-proof negative is
            // DAEMON_ASSERTED — sound only under the non-cryptographic (H-neg)
            // premise (NV-2/NV-3); a consumer MUST apply NV-6 clause (3).
            if (verdict == InclusionVerdict::NOT_INCLUDED)
                out["negative_footing"] = "daemon_asserted";
            if (!state_root_used.empty()) {
                out["state_root"] = state_root_used;
                out["height"]     = anchored_height;
            }
            if (!detail.empty()) out["detail"] = detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << verdict_str(verdict) << "\n"
                      << "  genesis pin:       matches (" << genesis_hash_hex << ")\n"
                      << "  namespace:         p (pending_param_changes)\n"
                      << "  effective_height:  " << eff_height << "\n"
                      << "  idx:               " << idx << "\n"
                      << "  name:              " << name << "\n"
                      << "  value_hex:         "
                      << (value_hex.empty() ? "<empty>" : value_hex) << "\n";
            if (verdict == InclusionVerdict::INCLUDED) {
                std::cout << "  state_root:        " << state_root_used << "\n"
                          << "  anchored at H:     " << anchored_height << "\n";
            }
            if (!detail.empty())
                std::cout << "  detail:            " << detail << "\n";
        }

        // Exit codes match verify-merge-state: INCLUDED / NOT-INCLUDED → 0
        // (a definite answer; NOT-INCLUDED is daemon-asserted, (H-neg));
        // UNVERIFIABLE → 3 (refused to assert).
        if (verdict == InclusionVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-param-change: " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────────── verify-param-value ────────────────────────────
//
// Trust-minimized MATCH / MISMATCH / UNVERIFIABLE verdict on whether the
// CURRENT effective value of a governance-activated consensus scalar (a
// genesis-pinned constant in the `k:` namespace) equals the value the
// caller asserts, with the proof bound to the EXACT (name, value) pair.
//
// This is the ACTIVATED counterpart to verify-param-change. The two cover
// the two halves of the governance parameter-change lifecycle:
//
//   * verify-param-change proves a change is still STAGED in the `p:`
//     (pending_param_changes) namespace — scheduled for effective_height,
//     not yet live. It is consumed at activation.
//   * verify-param-value (this command) proves the value that is LIVE RIGHT
//     NOW, after Chain::activate_pending_params has drained the matured
//     `p:` bucket into the chain-instance scalar and build_state_leaves has
//     re-committed it under `k:`. It reads the post-activation state, so it
//     is the natural query AFTER effective_height has passed (where the
//     same verify-param-change query flips to NOT-INCLUDED).
//
// The `k:` leaf encoding (see chain.cpp build_state_leaves const_leaf):
//     key        = 'k' ':' || name                  // SIMPLE key
//     value_hash = SHA256( u64_be(value) )           // one u64 scalar
// The daemon's rpc_state_proof handles `k:` on the simple-key path — the
// caller passes the bare constant NAME as `key` and the daemon prepends
// "k:". `name` is the build_state_leaves constant name (lowercase:
// min_stake, suspension_slash, unstake_delay, block_subsidy,
// merge_threshold_blocks, …), NOT the uppercase PARAM_CHANGE whitelist
// token (the validator whitelist uses MIN_STAKE; activate_pending_params
// writes it into min_stake_, which build_state_leaves commits as
// "k:min_stake"). Asserting the wrong name shape yields a sound MISMATCH
// or UNVERIFIABLE, never a false MATCH.
//
// Verdict discipline (distinct from the i:/m:/p: INCLUDED/NOT-INCLUDED
// readers, because every well-known `k:` constant ALWAYS has a leaf — a
// value query is never a membership query):
//
//   MATCH        — the `k:` leaf committee-verifies for the canonical key
//                  AND its value_hash equals SHA256(u64_be(value)). The
//                  asserted value IS the live consensus scalar at the
//                  anchored head. exit 0.
//   MISMATCH     — the `k:` leaf committee-verifies for the canonical key
//                  but its value_hash does NOT equal SHA256(u64_be(value)).
//                  The asserted value is provably NOT the current effective
//                  value. This is a SOUND NEGATIVE (the leaf itself Merkle-
//                  verified against the committee-signed root), distinct
//                  from UNVERIFIABLE. exit 0.
//   UNVERIFIABLE — any tamper, key_bytes mismatch, malformed proof, stale
//                  state, daemon refusal, or a `not_found` for the name
//                  (an unknown / non-`k:` constant — the verifier cannot
//                  assert a value for a leaf it cannot anchor). exit 3,
//                  never a false MATCH.
//
// Because a MISMATCH still needs the daemon's committed value to Merkle-
// verify the leaf, the actual on-chain value is reported alongside the
// MISMATCH verdict (it is read from the daemon and then HASH-CHECKED
// against the committee-signed leaf, so it is trustworthy: a daemon that
// lies about the reported value produces a value_hash that fails the
// Merkle verification → UNVERIFIABLE, not a false MISMATCH).
enum class ParamValueVerdict { MATCH, MISMATCH, UNVERIFIABLE };

const char* param_value_verdict_str(ParamValueVerdict v) {
    switch (v) {
        case ParamValueVerdict::MATCH:        return "MATCH";
        case ParamValueVerdict::MISMATCH:     return "MISMATCH";
        case ParamValueVerdict::UNVERIFIABLE: return "UNVERIFIABLE";
    }
    return "UNVERIFIABLE";
}

int cmd_verify_param_value(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, name;
    uint64_t value = 0;
    uint64_t wait_seconds = 0;
    bool have_port = false, have_name = false, have_value = false,
         json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--name"    && i + 1 < argc) {
            name = argv[++i]; have_name = true;
        } else if (a == "--value"   && i + 1 < argc) {
            value = parse_u64("--value", argv[++i]); have_value = true;
        } else if (a == "--json")                    json_out     = true;
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "verify-param-value: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || !have_name || !have_value) {
        std::cerr << "verify-param-value: --rpc-port, --genesis, --name, "
                     "--value are required\n";
        return 1;
    }
    // The `k:` value leaf commits a single u64 scalar. Reject a name that
    // carries the "c:" counter prefix or an embedded ':' — those are NOT
    // simple `k:` constant names (counters are served under the `c`
    // namespace, which encodes the "c:" sub-prefix daemon-side). Keeping the
    // name a bare token prevents a malformed query from aliasing a different
    // leaf shape.
    if (name.find(':') != std::string::npos || name.empty()) {
        std::cerr << "verify-param-value: --name must be a bare `k:` constant "
                     "name (no ':'); counters live under the `c` namespace\n";
        return 1;
    }

    ParamValueVerdict verdict = ParamValueVerdict::UNVERIFIABLE;
    std::string detail;
    std::string state_root_used;
    uint64_t    anchored_height = 0;
    uint64_t    onchain_value   = 0;   // committed value recovered from the leaf
    bool        have_onchain    = false;

    try {
        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-param-value: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // The committed leaf value for the ASSERTED scalar:
        //   SHA256(u64_be(value))   (matches build_state_leaves' const_leaf).
        determ::crypto::SHA256Builder mb;
        mb.append(value);
        Hash asserted_value_hash = mb.finalize();

        // Committee-verify the header chain end-to-end, capturing the head's
        // state_root (the anchor for the `k:` Merkle inclusion).
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex, /*track_registry=*/false, genesis.k_block_sigs, genesis.bft_enabled);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `k:` state-proofs cannot be "
                "anchored");
        }

        // Fetch the `k:`-namespace state-proof for the bare constant name.
        // The daemon prepends "k:" to the raw `key` (simple-key path).
        auto proof = rpc.call("state_proof",
            {{"namespace", "k"}, {"key", name}});

        // A `not_found` for a `k:` name is treated as UNVERIFIABLE, NOT a
        // negative verdict: unlike a:/d: (where an absent leaf yields a
        // daemon-asserted "never created/registered" verdict, (H-neg) —
        // NV-2/NV-3), every WELL-KNOWN consensus scalar always
        // has a `k:` leaf, so a not_found means the caller named an unknown /
        // non-`k:` constant — we cannot anchor a value for a leaf that is not
        // in the committed tree, and refuse to assert either way.
        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].is_string()
                ? proof["error"].get<std::string>()
                : proof["error"].dump();
            verdict = ParamValueVerdict::UNVERIFIABLE;
            if (err == "not_found") {
                detail = "no `k:` leaf for constant '" + name
                       + "' at the committee-verified head — not a known "
                         "consensus scalar (check the build_state_leaves name; "
                         "it is lowercase, e.g. min_stake, not MIN_STAKE)";
            } else {
                detail = "daemon refused the `k:` state-proof: " + err
                       + " (cannot prove the effective value trustlessly)";
            }
        } else {
            // Bind the proof to THIS constant: its key_bytes must equal the
            // locally-computed canonical key ("k:" || name). A mismatch means
            // the daemon served a proof for a different leaf → UNVERIFIABLE.
            std::vector<uint8_t> local_key;
            local_key.reserve(2 + name.size());
            local_key.push_back('k'); local_key.push_back(':');
            local_key.insert(local_key.end(), name.begin(), name.end());
            std::string proof_key_hex = proof.value("key_bytes", std::string{});
            std::string local_key_hex =
                to_hex(local_key.data(), local_key.size());
            if (proof_key_hex != local_key_hex) {
                verdict = ParamValueVerdict::UNVERIFIABLE;
                detail  = "proof.key_bytes=" + proof_key_hex
                        + " does not match the canonical k: key "
                        + local_key_hex
                        + " (daemon served a proof for a different leaf)";
            } else {
                // Anchor the proof's claimed state_root to a committee-signed
                // header (the chain may have advanced during the round-trip),
                // the identical re-anchoring verify-param-change /
                // verify-account use.
                uint64_t proof_height = proof.value("height", uint64_t{0});
                std::string proof_root =
                    proof.value("state_root", std::string{});
                std::string anchor_root = vc.head_state_root;
                uint64_t    anchor_at   = vc.height;

                if (proof_height < vc.height) {
                    throw std::runtime_error(
                        "proof.height=" + std::to_string(proof_height)
                        + " is BEFORE verified-chain head="
                        + std::to_string(vc.height)
                        + " — daemon is serving stale state");
                }
                // SOUNDNESS: the committee signs compute_block_digest, which
                // EXCLUDES state_root, so the daemon's state_root FIELD is
                // NOT committee-attested. Bind proof_root to the COMMITTEE-
                // SIGNED root committed by block proof_height-1 via
                // committee_bound_state_root (full-block recompute +
                // successor-sig binding), never the bare header field.
                {
                    json committee_json;
                    {
                        json arr = json::array();
                        for (auto& [domain_, pk] : committee_seed)
                            arr.push_back({{"domain", domain_},
                                           {"ed_pub", to_hex(pk)}});
                        committee_json = json{{"members", arr}};
                    }
                    uint64_t anchor_index = proof_height - 1;
                    std::string attested =
                        determ::light::committee_bound_state_root(rpc, committee_json, anchor_index, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
                    if (attested != proof_root) {
                        throw std::runtime_error(
                            "verify-param-value: SECURITY — committee-attested "
                            "state_root at index "
                            + std::to_string(anchor_index) + " = " + attested
                            + " does NOT match proof.state_root = " + proof_root
                            + " — daemon served a proof against an "
                              "unattested root");
                    }
                    vc.head_state_root = attested;  // downstream reporting uses the ATTESTED root
                    vc.height = proof_height;
                    anchor_root = attested;
                    anchor_at   = proof_height;
                }

                // Merkle-verify the proof against the committee-signed root.
                // verify_state_proof rolls the proof's key_bytes + value_hash
                // up to anchor_root. A pass means the daemon's value_hash IS
                // the committed leaf — so we can compare it against the
                // asserted hash WITHOUT trusting the daemon's claim.
                auto vsp = verify_state_proof(proof, anchor_root);
                if (!vsp.ok) {
                    verdict = ParamValueVerdict::UNVERIFIABLE;
                    detail  = "merkle verification failed: " + vsp.detail;
                } else {
                    Hash proof_value_hash = from_hex_arr<32>(
                        proof.value("value_hash", std::string{}));
                    state_root_used = anchor_root;
                    anchored_height = anchor_at;
                    if (proof_value_hash == asserted_value_hash) {
                        verdict       = ParamValueVerdict::MATCH;
                        onchain_value = value;
                        have_onchain  = true;
                    } else {
                        // The leaf committee-verified, but its committed value
                        // is NOT the asserted one — a SOUND negative. The
                        // value_hash is SHA256(u64_be(v)) for a single hidden
                        // u64 v: it commits the live scalar but does not reveal
                        // it (no preimage), so MISMATCH reports only that the
                        // asserted value is provably wrong, not what the live
                        // value is. A caller can binary-search the true value
                        // by re-running with candidate --value's until MATCH,
                        // or read the (untrusted) hint from `determ
                        // pending-params` history. We deliberately do NOT echo
                        // an unverified daemon claim here.
                        verdict = ParamValueVerdict::MISMATCH;
                        detail  = "the committee-verified `k:" + name
                                + "` leaf does NOT commit value "
                                + std::to_string(value)
                                + " (its value_hash=" + to_hex(proof_value_hash)
                                + " != SHA256(u64_be(" + std::to_string(value)
                                + "))=" + to_hex(asserted_value_hash)
                                + ") — the asserted value is provably NOT the "
                                  "current effective scalar";
                    }
                }
            }
        }

        bool matched = (verdict == ParamValueVerdict::MATCH);
        if (json_out) {
            json out = {
                {"verdict",       param_value_verdict_str(verdict)},
                {"match",         matched},
                {"name",          name},
                {"asserted_value", value},
                {"namespace",     "k"},
            };
            if (have_onchain) out["onchain_value"] = onchain_value;
            if (!state_root_used.empty()) {
                out["state_root"] = state_root_used;
                out["height"]     = anchored_height;
            }
            if (!detail.empty()) out["detail"] = detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << param_value_verdict_str(verdict) << "\n"
                      << "  genesis pin:       matches (" << genesis_hash_hex << ")\n"
                      << "  namespace:         k (consensus constants)\n"
                      << "  name:              " << name << "\n"
                      << "  asserted value:    " << value << "\n";
            if (have_onchain)
                std::cout << "  on-chain value:    " << onchain_value << "\n";
            if (verdict == ParamValueVerdict::MATCH
                || verdict == ParamValueVerdict::MISMATCH) {
                std::cout << "  state_root:        " << state_root_used << "\n"
                          << "  anchored at H:     " << anchored_height << "\n";
            }
            if (!detail.empty())
                std::cout << "  detail:            " << detail << "\n";
        }

        // Exit codes mirror the verify-* tri-state: MATCH / MISMATCH → 0
        // (sound verified answer); UNVERIFIABLE → 3 (refused to assert).
        if (verdict == ParamValueVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-param-value: " << e.what() << "\n";
        return 1;
    }
}

// ───────────────────────────── verify-registrant ───────────────────────
//
// Trust-minimized INCLUDED / NOT-INCLUDED / UNVERIFIABLE verdict on whether
// a domain IS (or is NOT) a registered VALIDATOR at the committee-verified
// head, anchored to the `r:` (registrants) S-033 namespace. This is the
// validator-set sibling of verify-dapp-registration (the `d:` DApp reader):
// both are simple-key namespaces (the daemon prepends the prefix to the raw
// domain bytes), and both cross-check the daemon's cleartext fields against
// the committee-signed leaf value_hash so a daemon lie about ANY registrant
// field is detected, never propagated.
//
// The cleartext source is the `account` RPC's `registry` object (ed_pub,
// registered_at, active_from, inactive_from, region). A null/absent
// `registry` means the domain is NOT a registrant — consistent ONLY with a
// state_proof not_found for the exact `r:` key; any other combination is an
// inconsistent daemon and fails closed (UNVERIFIABLE).
int cmd_verify_registrant(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, domain;
    uint64_t wait_seconds = 0;
    bool have_port = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--domain"  && i + 1 < argc) domain       = argv[++i];
        else if   (a == "--json")                    json_out     = true;
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "verify-registrant: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || domain.empty()) {
        std::cerr << "verify-registrant: "
                     "--rpc-port, --genesis, --domain are required\n";
        return 1;
    }

    InclusionVerdict verdict = InclusionVerdict::UNVERIFIABLE;
    std::string detail;
    std::string state_root_used;
    uint64_t    anchored_height = 0;
    // Committee-verified registrant fields (populated only on INCLUDED).
    std::string ed_pub_hex, region;
    uint64_t registered_at = 0, active_from = 0, inactive_from = 0;
    bool active = false;

    try {
        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-registrant: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // `r:` is a simple-key namespace — the daemon prepends "r:" to the
        // raw domain bytes (no hex-encoded composite body). Compute the
        // canonical key locally so we can bind the proof's key_bytes to it.
        std::vector<uint8_t> local_key;
        local_key.reserve(2 + domain.size());
        local_key.push_back('r'); local_key.push_back(':');
        local_key.insert(local_key.end(), domain.begin(), domain.end());

        // Committee-verify the header chain end-to-end, capturing the
        // head's state_root (the anchor for the Merkle inclusion).
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex, /*track_registry=*/false, genesis.k_block_sigs, genesis.bft_enabled);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `r:` state-proofs cannot be "
                "anchored");
        }

        // Fetch the `r:`-namespace state-proof for this domain.
        auto proof = rpc.call("state_proof",
            {{"namespace", "r"}, {"key", domain}});

        // not_found for our exact key → NOT-INCLUDED, a daemon-asserted
        // negative per (H-neg) — NV-2/NV-3 (no such validator registered at
        // the verified head, if the daemon answers absences honestly). Any
        // other refusal → fail-closed UNVERIFIABLE (we will not assert
        // membership either way).
        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].is_string()
                ? proof["error"].get<std::string>()
                : proof["error"].dump();
            if (err == "not_found") {
                verdict = InclusionVerdict::NOT_INCLUDED;
                detail  = "daemon reports no `r:` leaf for domain '" + domain
                        + "' — no such validator is registered at the verified "
                          "head (state_proof not_found)";
                // Cross-check the cleartext: the `account` RPC's registry must
                // ALSO be null/absent, else the daemon contradicts itself.
                // This catches a SELF-CONTRADICTING daemon only; a consistent
                // liar (not_found + null registry for a real registrant) still
                // forges the negative — the (H-neg) footing is unchanged.
                auto acc = rpc.call("account", {{"address", domain}});
                bool reg_null = !acc.contains("registry")
                              || acc["registry"].is_null();
                if (!reg_null) {
                    verdict = InclusionVerdict::UNVERIFIABLE;
                    detail  = "state_proof returned not_found for `r:" + domain
                            + "` but the `account` RPC returns a non-null "
                              "registry object — inconsistent daemon "
                              "(refusing to assert NOT-INCLUDED)";
                }
            } else {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "daemon refused the `r:` state-proof: " + err
                        + " (cannot prove registration trustlessly)";
            }
        } else {
            // Bind the proof to THIS domain: its key_bytes must equal the
            // locally-computed canonical key. A mismatch means the daemon
            // served a proof for a different leaf → UNVERIFIABLE.
            std::string proof_key_hex =
                proof.value("key_bytes", std::string{});
            std::string local_key_hex =
                to_hex(local_key.data(), local_key.size());
            if (proof_key_hex != local_key_hex) {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "proof.key_bytes=" + proof_key_hex
                        + " does not match the canonical r: key "
                        + local_key_hex
                        + " (daemon served a proof for a different leaf)";
            } else {
                // Fetch the cleartext registrant via `account` and recompute
                // the committed leaf value_hash from it. This is the
                // load-bearing cross-check: a daemon could serve an honest
                // proof for the right key while lying in the cleartext; the
                // hash recomputation forces consistency.
                auto acc = rpc.call("account", {{"address", domain}});
                if (acc.contains("error") && !acc["error"].is_null()) {
                    throw std::runtime_error(
                        "state_proof served an `r:` leaf for '" + domain
                        + "' but the account RPC refused it: "
                        + acc["error"].dump() + " (inconsistent daemon)");
                }
                if (!acc.contains("registry") || acc["registry"].is_null()) {
                    // The state-proof said the leaf exists but the cleartext
                    // registry is null — inconsistent daemon, fail closed.
                    throw std::runtime_error(
                        "state_proof served an `r:` leaf for '" + domain
                        + "' but the account RPC returns a null registry "
                          "object (inconsistent daemon)");
                }

                const json& reg = acc["registry"];
                ed_pub_hex    = reg.value("ed_pub",        std::string{});
                region        = reg.value("region",        std::string{});
                registered_at = reg.value("registered_at", uint64_t{0});
                active_from   = reg.value("active_from",   uint64_t{0});
                inactive_from = reg.value("inactive_from", uint64_t{0});

                // Decode the 64-hex ed_pub back to the 32 raw bytes the leaf
                // hashes (from_hex throws on malformed hex → exit 1).
                std::vector<uint8_t> ed_pub = from_hex(ed_pub_hex);
                if (ed_pub.size() != 32) {
                    throw std::runtime_error(
                        "account registry ed_pub is not 32 bytes (got "
                        + std::to_string(ed_pub.size()) + ")");
                }

                // Recompute the committed leaf value_hash byte-for-byte
                // matching chain.cpp build_state_leaves "r:" branch:
                //   ed_pub(32) || registered_at(u64 BE) || active_from(u64 BE)
                //   || inactive_from(u64 BE) || region.size()(u64 BE)
                //   || region(raw bytes)
                determ::crypto::SHA256Builder hb;
                hb.append(ed_pub.data(), ed_pub.size());
                hb.append(registered_at);
                hb.append(active_from);
                hb.append(inactive_from);
                hb.append(static_cast<uint64_t>(region.size()));
                hb.append(region);
                Hash expected_value_hash = hb.finalize();

                Hash proof_value_hash = from_hex_arr<32>(
                    proof.value("value_hash", std::string{}));
                if (proof_value_hash != expected_value_hash) {
                    verdict = InclusionVerdict::UNVERIFIABLE;
                    detail  = "proof.value_hash=" + to_hex(proof_value_hash)
                            + " does not match the recomputed hash of the "
                              "account registry for '" + domain + "'="
                            + to_hex(expected_value_hash)
                            + " — daemon is lying about the registrant "
                              "fields OR proving a different leaf";
                } else {
                    // Anchor the proof's claimed state_root to a
                    // committee-signed header (the chain may have advanced
                    // during the round-trip), mirroring verify-param-change.
                    uint64_t proof_height =
                        proof.value("height", uint64_t{0});
                    std::string proof_root =
                        proof.value("state_root", std::string{});
                    std::string anchor_root = vc.head_state_root;
                    uint64_t    anchor_at   = vc.height;

                    if (proof_height < vc.height) {
                        throw std::runtime_error(
                            "proof.height=" + std::to_string(proof_height)
                            + " is BEFORE verified-chain head="
                            + std::to_string(vc.height)
                            + " — daemon is serving stale state");
                    }
                    // SOUNDNESS: the committee signs compute_block_digest,
                    // which EXCLUDES state_root, so the daemon's state_root
                    // FIELD is NOT committee-attested. Bind proof_root to the
                    // COMMITTEE-SIGNED root committed by block proof_height-1
                    // via committee_bound_state_root (full-block recompute +
                    // successor-sig binding), never the bare header field.
                    {
                        json committee_json;
                        {
                            json arr = json::array();
                            for (auto& [domain_, pk] : committee_seed)
                                arr.push_back({{"domain", domain_},
                                               {"ed_pub", to_hex(pk)}});
                            committee_json = json{{"members", arr}};
                        }
                        uint64_t anchor_index = proof_height - 1;
                        std::string attested =
                            determ::light::committee_bound_state_root(rpc, committee_json, anchor_index, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
                        if (attested != proof_root) {
                            throw std::runtime_error(
                                "verify-registrant: SECURITY — "
                                "committee-attested state_root at index "
                                + std::to_string(anchor_index) + " = " + attested
                                + " does NOT match proof.state_root = " + proof_root
                                + " — daemon served a proof against an "
                                  "unattested root");
                        }
                        vc.head_state_root = attested;  // downstream reporting uses the ATTESTED root
                        vc.height = proof_height;
                        anchor_root = attested;
                        anchor_at   = proof_height;
                    }

                    // Merkle-verify the proof against the committee-signed
                    // root. We already bound key_bytes + value_hash to the
                    // canonical registrant above, so a pass here is a sound
                    // INCLUDED.
                    auto vsp = verify_state_proof(proof, anchor_root);
                    if (!vsp.ok) {
                        verdict = InclusionVerdict::UNVERIFIABLE;
                        detail  = "merkle verification failed: " + vsp.detail;
                    } else {
                        verdict = InclusionVerdict::INCLUDED;
                        state_root_used = anchor_root;
                        anchored_height = anchor_at;
                        // active/inactive is now a verified verdict: the
                        // active_from / inactive_from we hashed are
                        // committee-attested, so derive the lifecycle status
                        // against the committee-anchored head height. A
                        // registrant is ACTIVE once active_from <= height and
                        // not yet deactivated (inactive_from == 0 sentinel, or
                        // inactive_from > height).
                        bool activated   = (active_from <= anchored_height);
                        bool deactivated = (inactive_from != 0
                                            && inactive_from <= anchored_height);
                        active = activated && !deactivated;
                    }
                }
            }
        }

        bool included = (verdict == InclusionVerdict::INCLUDED);
        if (json_out) {
            json out = {
                {"included",  included},
                {"verdict",   verdict_str(verdict)},
                {"domain",    domain},
                {"namespace", "r"},
            };
            // F-2 (NegativeVerdictSoundness.md): the r: state-proof negative is
            // DAEMON_ASSERTED — sound only under the non-cryptographic (H-neg)
            // premise (NV-2/NV-3); a consumer MUST apply NV-6 clause (3). The
            // account-RPC cross-check above does not upgrade the footing.
            if (verdict == InclusionVerdict::NOT_INCLUDED)
                out["negative_footing"] = "daemon_asserted";
            if (included) {
                out["active"]        = active;
                out["ed_pub"]        = ed_pub_hex;
                out["region"]        = region;
                out["registered_at"] = registered_at;
                out["active_from"]   = active_from;
                out["inactive_from"] = inactive_from;
            }
            if (!state_root_used.empty()) {
                out["state_root"] = state_root_used;
                out["height"]     = anchored_height;
            }
            if (!detail.empty()) out["detail"] = detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << verdict_str(verdict) << "\n"
                      << "  genesis pin:       matches (" << genesis_hash_hex << ")\n"
                      << "  namespace:         r (registrants)\n"
                      << "  domain:            " << domain << "\n";
            if (verdict == InclusionVerdict::INCLUDED) {
                std::cout << "  status:            "
                          << (active ? "ACTIVE" : "INACTIVE (deactivated/pending)") << "\n"
                          << "  ed_pub:            " << ed_pub_hex << "\n"
                          << "  region:            " << region << "\n"
                          << "  registered_at:     " << registered_at << "\n"
                          << "  active_from:       " << active_from << "\n"
                          << "  inactive_from:     " << inactive_from << "\n"
                          << "  state_root:        " << state_root_used << "\n"
                          << "  anchored at H:     " << anchored_height << "\n";
            }
            if (!detail.empty())
                std::cout << "  detail:            " << detail << "\n";
        }

        // Exit codes match verify-dapp-registration and the whole InclusionVerdict
        // reader family (verify-tx-inclusion / -receipt-inclusion / -merge-state /
        // -param-change): INCLUDED → 0 (sound, committee-anchored), NOT-INCLUDED
        // → 0 (a daemon-asserted negative, (H-neg) — NV-2/NV-3);
        // UNVERIFIABLE → 3 (refused to assert); args/transport → 1.
        if (verdict == InclusionVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-registrant: " << e.what() << "\n";
        return 1;
    }
}

// ───────────────────────────── verify-notekey ───────────────────────────
// NC-8 §5b: trustlessly obtain an account's standing recipient note_pk (the
// 33-byte P-256 point a sender seals a CONFIDENTIAL_TRANSFER enote to). The
// nk: state leaf commits SHA256(note_pk); this reader binds the daemon's
// cleartext note_pk (from the `account` RPC — UNTRUSTED) to that leaf by
// recomputing the hash, binds the leaf key to the canonical "nk:"+addr, and
// Merkle-verifies against a COMMITTEE-signed state_root. A pass means a sender
// can seal to this note_pk without trusting the daemon. A simplified clone of
// verify-registrant: the leaf value is a single-value hash, not a multi-field
// preimage. INCLUDED → 0; NOT-INCLUDED → 0 (daemon-asserted, (H-neg));
// UNVERIFIABLE → 3; args/transport → 1.
int cmd_verify_notekey(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, domain;
    uint64_t wait_seconds = 0;
    bool have_port = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--domain"  && i + 1 < argc) domain       = argv[++i];
        else if   (a == "--json")                    json_out     = true;
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "verify-notekey: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || domain.empty()) {
        std::cerr << "verify-notekey: "
                     "--rpc-port, --genesis, --domain are required\n";
        return 1;
    }

    InclusionVerdict verdict = InclusionVerdict::UNVERIFIABLE;
    std::string detail;
    std::string state_root_used;
    uint64_t    anchored_height = 0;
    std::string note_pk_hex;   // committee-verified note_pk (only on INCLUDED)

    try {
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-notekey: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // `nk:` is a simple ASCII-suffix namespace (2-char prefix): the daemon
        // builds the leaf key as "nk:" + addr. Compute it locally to bind the
        // proof's key_bytes.
        std::vector<uint8_t> local_key;
        local_key.reserve(3 + domain.size());
        local_key.push_back('n'); local_key.push_back('k'); local_key.push_back(':');
        local_key.insert(local_key.end(), domain.begin(), domain.end());

        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex, /*track_registry=*/false, genesis.k_block_sigs, genesis.bft_enabled);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `nk:` state-proofs cannot be anchored");
        }

        auto proof = rpc.call("state_proof",
            {{"namespace", "nk"}, {"key", domain}});

        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].is_string()
                ? proof["error"].get<std::string>()
                : proof["error"].dump();
            if (err == "not_found") {
                verdict = InclusionVerdict::NOT_INCLUDED;
                detail  = "daemon reports no `nk:` leaf for '" + domain
                        + "' — no standing note key is published at the verified "
                          "head (state_proof not_found)";
                // Self-contradiction cross-check: the `account` RPC's note_key
                // must ALSO be null. Catches only a self-contradicting daemon;
                // a consistent liar still forges the negative ((H-neg)).
                auto acc = rpc.call("account", {{"address", domain}});
                bool nk_null = !acc.contains("note_key")
                             || acc["note_key"].is_null();
                if (!nk_null) {
                    verdict = InclusionVerdict::UNVERIFIABLE;
                    detail  = "state_proof returned not_found for `nk:" + domain
                            + "` but the `account` RPC returns a non-null "
                              "note_key — inconsistent daemon (refusing to "
                              "assert NOT-INCLUDED)";
                }
            } else {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "daemon refused the `nk:` state-proof: " + err
                        + " (cannot prove the note key trustlessly)";
            }
        } else {
            std::string proof_key_hex = proof.value("key_bytes", std::string{});
            std::string local_key_hex = to_hex(local_key.data(), local_key.size());
            if (proof_key_hex != local_key_hex) {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "proof.key_bytes=" + proof_key_hex
                        + " does not match the canonical nk: key " + local_key_hex
                        + " (daemon served a proof for a different leaf)";
            } else {
                // Fetch the cleartext note_pk and recompute the leaf value_hash
                // = SHA256(note_pk). The hash recomputation is the load-bearing
                // cross-check: a daemon serving an honest proof for the right
                // key cannot also lie about the note_pk without failing here.
                auto acc = rpc.call("account", {{"address", domain}});
                if (acc.contains("error") && !acc["error"].is_null()) {
                    throw std::runtime_error(
                        "state_proof served an `nk:` leaf for '" + domain
                        + "' but the account RPC refused it: "
                        + acc["error"].dump() + " (inconsistent daemon)");
                }
                if (!acc.contains("note_key") || acc["note_key"].is_null()) {
                    throw std::runtime_error(
                        "state_proof served an `nk:` leaf for '" + domain
                        + "' but the account RPC returns a null note_key "
                          "(inconsistent daemon)");
                }
                note_pk_hex = acc.value("note_key", std::string{});
                std::vector<uint8_t> note_pk = from_hex(note_pk_hex);
                if (note_pk.size() != 33) {
                    throw std::runtime_error(
                        "account note_key is not 33 bytes (got "
                        + std::to_string(note_pk.size()) + ")");
                }

                // Recompute byte-for-byte matching build_state_leaves "nk:"
                // branch: value = SHA256(note_pk_bytes).
                determ::crypto::SHA256Builder hb;
                hb.append(note_pk.data(), note_pk.size());
                Hash expected_value_hash = hb.finalize();

                Hash proof_value_hash = from_hex_arr<32>(
                    proof.value("value_hash", std::string{}));
                if (proof_value_hash != expected_value_hash) {
                    verdict = InclusionVerdict::UNVERIFIABLE;
                    detail  = "proof.value_hash=" + to_hex(proof_value_hash)
                            + " does not match SHA256(note_pk) for '" + domain
                            + "'=" + to_hex(expected_value_hash)
                            + " — daemon is lying about the note_pk OR proving a "
                              "different leaf";
                } else {
                    uint64_t proof_height = proof.value("height", uint64_t{0});
                    std::string proof_root = proof.value("state_root", std::string{});
                    std::string anchor_root = vc.head_state_root;
                    uint64_t    anchor_at   = vc.height;

                    if (proof_height < vc.height) {
                        throw std::runtime_error(
                            "proof.height=" + std::to_string(proof_height)
                            + " is BEFORE verified-chain head="
                            + std::to_string(vc.height)
                            + " — daemon is serving stale state");
                    }
                    // Bind proof_root to the COMMITTEE-SIGNED root (the header
                    // state_root field is NOT committee-attested), never the
                    // bare field — mirrors verify-registrant.
                    {
                        json committee_json;
                        {
                            json arr = json::array();
                            for (auto& [domain_, pk] : committee_seed)
                                arr.push_back({{"domain", domain_},
                                               {"ed_pub", to_hex(pk)}});
                            committee_json = json{{"members", arr}};
                        }
                        uint64_t anchor_index = proof_height - 1;
                        std::string attested =
                            determ::light::committee_bound_state_root(rpc, committee_json, anchor_index, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
                        if (attested != proof_root) {
                            throw std::runtime_error(
                                "verify-notekey: SECURITY — committee-attested "
                                "state_root at index "
                                + std::to_string(anchor_index) + " = " + attested
                                + " does NOT match proof.state_root = " + proof_root
                                + " — daemon served a proof against an unattested "
                                  "root");
                        }
                        vc.head_state_root = attested;
                        vc.height = proof_height;
                        anchor_root = attested;
                        anchor_at   = proof_height;
                    }

                    auto vsp = verify_state_proof(proof, anchor_root);
                    if (!vsp.ok) {
                        verdict = InclusionVerdict::UNVERIFIABLE;
                        detail  = "merkle verification failed: " + vsp.detail;
                    } else {
                        verdict = InclusionVerdict::INCLUDED;
                        state_root_used = anchor_root;
                        anchored_height = anchor_at;
                    }
                }
            }
        }

        bool included = (verdict == InclusionVerdict::INCLUDED);
        if (json_out) {
            json out = {
                {"included",  included},
                {"verdict",   verdict_str(verdict)},
                {"domain",    domain},
                {"namespace", "nk"},
            };
            if (verdict == InclusionVerdict::NOT_INCLUDED)
                out["negative_footing"] = "daemon_asserted";
            if (included) out["note_pk"] = note_pk_hex;
            if (!state_root_used.empty()) {
                out["state_root"] = state_root_used;
                out["height"]     = anchored_height;
            }
            if (!detail.empty()) out["detail"] = detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << verdict_str(verdict) << "\n"
                      << "  genesis pin:       matches (" << genesis_hash_hex << ")\n"
                      << "  namespace:         nk (recipient note key)\n"
                      << "  domain:            " << domain << "\n";
            if (included) {
                std::cout << "  note_pk:           " << note_pk_hex << "\n"
                          << "  state_root:        " << state_root_used << "\n"
                          << "  anchored at H:     " << anchored_height << "\n";
            }
            if (!detail.empty())
                std::cout << "  detail:            " << detail << "\n";
        }

        if (verdict == InclusionVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-notekey: " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────────── verify-enote-inclusion ──────────────────────────
// NC-8 §5.6 (the final NC-8 increment): the light-client enote scan. A wallet
// pulls candidate (commitment, ciphertext) pairs from a full node's scan_enotes
// RPC (§5.3) — an UNTRUSTED source. Before spending CPU trial-decrypting them
// (or trusting that the node did not fabricate/omit deliveries), it PROVES each
// pair is the genuine on-chain delivery: the MODERN `en:` state leaf commits
// value = SHA256(commitment_bytes || enote_wire_bytes), keyed by the output
// commitment. This reader binds the CALLER-provided (commitment, enote) on BOTH
// axes — key_bytes == "en:"+hex(commitment) AND value_hash == SHA256(commitment
// || enote) — and Merkle-verifies against a COMMITTEE-signed state_root. A pass
// means the ciphertext is exactly the one committed on-chain; a lying node that
// returns a fabricated ciphertext is caught (value_hash mismatch → UNVERIFIABLE)
// and one that invents a commitment is caught (not_found → NOT-INCLUDED).
// Unlike verify-notekey there is NO daemon cleartext to fetch — the caller
// supplies the pair; the leaf value-hash-bind is what makes the read trustless.
// MODERN-only: on a FIPS chain no `en:` leaf exists (the ciphertext is
// payload-only, block-hash-bound), so verify returns NOT-INCLUDED and the light
// client necessarily trusts the serving node's scan there. INCLUDED → 0;
// NOT-INCLUDED → 0 (daemon-asserted, (H-neg)); tamper/mismatch → UNVERIFIABLE
// (exit 3); args/transport → 1.
int cmd_verify_enote_inclusion(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, commitment_hex, enote_hex;
    uint64_t wait_seconds = 0;
    bool have_port = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis"    && i + 1 < argc) genesis_path   = argv[++i];
        else if   (a == "--commitment" && i + 1 < argc) commitment_hex = argv[++i];
        else if   (a == "--enote"      && i + 1 < argc) enote_hex      = argv[++i];
        else if   (a == "--json")                       json_out       = true;
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "verify-enote-inclusion: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || commitment_hex.empty()
        || enote_hex.empty()) {
        std::cerr << "verify-enote-inclusion: "
                     "--rpc-port, --genesis, --commitment, --enote are required\n";
        return 1;
    }

    InclusionVerdict verdict = InclusionVerdict::UNVERIFIABLE;
    std::string detail;
    std::string state_root_used;
    uint64_t    anchored_height = 0;

    try {
        // Decode + shape-check the caller-provided pair up front (from_hex
        // throws on malformed hex → exit 1). The commitment is a 33-byte SEC1
        // point; the enote is the |pt|+49 ECIES wire (49..512 per the inc.2
        // frame bounds). We do NOT enforce the exact enote length here — the
        // value-hash-bind against the committed leaf is the authority; a wrong
        // length simply fails that bind.
        std::vector<uint8_t> commitment = from_hex(commitment_hex);
        std::vector<uint8_t> enote      = from_hex(enote_hex);
        if (commitment.size() != 33) {
            std::cerr << "verify-enote-inclusion: --commitment must be 33 bytes "
                         "(SEC1-compressed P-256 point), got "
                      << commitment.size() << "\n";
            return 1;
        }
        // Canonicalize the commitment hex to lowercase (the daemon keys the en:
        // leaf by to_hex(...) which is lowercase) so key_bytes binds exactly.
        std::string commitment_lc = to_hex(commitment.data(), commitment.size());

        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-enote-inclusion: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // `en:` is a simple ASCII-suffix namespace (2-char prefix): leaf key =
        // "en:" + lowercase-hex(commitment). Compute locally to bind key_bytes.
        std::vector<uint8_t> local_key;
        {
            std::string full = "en:" + commitment_lc;
            local_key.assign(full.begin(), full.end());
        }

        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex, /*track_registry=*/false, genesis.k_block_sigs, genesis.bft_enabled);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `en:` state-proofs cannot be anchored");
        }

        auto proof = rpc.call("state_proof",
            {{"namespace", "en"}, {"key", commitment_lc}});

        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].is_string()
                ? proof["error"].get<std::string>()
                : proof["error"].dump();
            if (err == "not_found") {
                verdict = InclusionVerdict::NOT_INCLUDED;
                detail  = "daemon reports no `en:` leaf for commitment "
                        + commitment_lc + " — no committed delivery at this "
                          "output (unspent) at the verified head: spent, never "
                          "delivered, or a FIPS chain (payload-only) "
                          "(state_proof not_found)";
            } else {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "daemon refused the `en:` state-proof: " + err
                        + " (cannot prove the enote delivery trustlessly)";
            }
        } else {
            std::string proof_key_hex = proof.value("key_bytes", std::string{});
            std::string local_key_hex = to_hex(local_key.data(), local_key.size());
            if (proof_key_hex != local_key_hex) {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "proof.key_bytes=" + proof_key_hex
                        + " does not match the canonical en: key " + local_key_hex
                        + " (daemon served a proof for a different leaf)";
            } else {
                // Recompute value_hash = SHA256(commitment || enote), byte-for-
                // byte matching build_state_leaves' "en:" branch (apply-side
                // chain.cpp). A mismatch means the leaf at this commitment
                // commits a DIFFERENT ciphertext than the one provided — the
                // node handed us a fabricated/tampered enote. Fail closed.
                determ::crypto::SHA256Builder hb;
                hb.append(commitment.data(), commitment.size());
                hb.append(enote.data(), enote.size());
                Hash expected_value_hash = hb.finalize();

                Hash proof_value_hash = from_hex_arr<32>(
                    proof.value("value_hash", std::string{}));
                if (proof_value_hash != expected_value_hash) {
                    verdict = InclusionVerdict::UNVERIFIABLE;
                    detail  = "proof.value_hash=" + to_hex(proof_value_hash)
                            + " does not match SHA256(commitment || enote)="
                            + to_hex(expected_value_hash)
                            + " — the on-chain delivery at this commitment is a "
                              "DIFFERENT ciphertext than the one provided (a "
                              "fabricated/tampered enote), OR a wrong leaf";
                } else {
                    uint64_t proof_height = proof.value("height", uint64_t{0});
                    std::string proof_root = proof.value("state_root", std::string{});
                    std::string anchor_root = vc.head_state_root;
                    uint64_t    anchor_at   = vc.height;

                    if (proof_height < vc.height) {
                        throw std::runtime_error(
                            "proof.height=" + std::to_string(proof_height)
                            + " is BEFORE verified-chain head="
                            + std::to_string(vc.height)
                            + " — daemon is serving stale state");
                    }
                    // Bind proof_root to the COMMITTEE-SIGNED root (the header
                    // state_root field is NOT committee-attested).
                    {
                        json committee_json;
                        {
                            json arr = json::array();
                            for (auto& [domain_, pk] : committee_seed)
                                arr.push_back({{"domain", domain_},
                                               {"ed_pub", to_hex(pk)}});
                            committee_json = json{{"members", arr}};
                        }
                        uint64_t anchor_index = proof_height - 1;
                        std::string attested =
                            determ::light::committee_bound_state_root(rpc, committee_json, anchor_index, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
                        if (attested != proof_root) {
                            throw std::runtime_error(
                                "verify-enote-inclusion: SECURITY — "
                                "committee-attested state_root at index "
                                + std::to_string(anchor_index) + " = " + attested
                                + " does NOT match proof.state_root = " + proof_root
                                + " — daemon served a proof against an unattested "
                                  "root");
                        }
                        vc.head_state_root = attested;
                        vc.height = proof_height;
                        anchor_root = attested;
                        anchor_at   = proof_height;
                    }

                    auto vsp = verify_state_proof(proof, anchor_root);
                    if (!vsp.ok) {
                        verdict = InclusionVerdict::UNVERIFIABLE;
                        detail  = "merkle verification failed: " + vsp.detail;
                    } else {
                        verdict = InclusionVerdict::INCLUDED;
                        state_root_used = anchor_root;
                        anchored_height = anchor_at;
                    }
                }
            }
        }

        bool included = (verdict == InclusionVerdict::INCLUDED);
        if (json_out) {
            json out = {
                {"included",   included},
                {"verdict",    verdict_str(verdict)},
                {"commitment", commitment_lc},
                {"namespace",  "en"},
            };
            if (verdict == InclusionVerdict::NOT_INCLUDED)
                out["negative_footing"] = "daemon_asserted";
            if (!state_root_used.empty()) {
                out["state_root"] = state_root_used;
                out["height"]     = anchored_height;
            }
            if (!detail.empty()) out["detail"] = detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << verdict_str(verdict) << "\n"
                      << "  genesis pin:       matches (" << genesis_hash_hex << ")\n"
                      << "  namespace:         en (encrypted-note delivery)\n"
                      << "  commitment:        " << commitment_lc << "\n";
            if (included) {
                std::cout << "  delivery:          committed on-chain (trial-decrypt safe)\n"
                          << "  state_root:        " << state_root_used << "\n"
                          << "  anchored at H:     " << anchored_height << "\n";
            }
            if (!detail.empty())
                std::cout << "  detail:            " << detail << "\n";
        }

        if (verdict == InclusionVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-enote-inclusion: " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────────── verify-dapp-registration ──────────────────────
//
// Trustless reader for the `d:` (dapp_registry) namespace — the v2.18
// DApp-registry sibling of the a:/s: single-leaf reads and the i:/m:/p:
// composite-key inclusion proofs. Proves (or disproves) that a domain is
// CURRENTLY a registered DApp on the committee-verified chain, with the
// proof bound to the EXACT registration the daemon serves over `dapp_info`
// (a daemon lie about the service key, endpoint, topics, retention, or
// metadata is detected, not propagated).
//
// `d:` is a SIMPLE-key namespace (rpc_state_proof prepends "d:" + the raw
// domain bytes, like a:/s:/r:), so unlike verify-param-change there is no
// hex-encoded composite key body: --domain is passed through verbatim.
// The load-bearing cross-check is the leaf value_hash, which
// build_state_leaves (chain.cpp "d:" branch) computes as:
//
//   SHA256( service_pubkey[32]
//         || u64_be(registered_at) || u64_be(active_from)
//         || u64_be(inactive_from)
//         || u64_be(endpoint_url.size()) || endpoint_url
//         || u64_be(topics.size())
//         || for each topic: u64_be(topic.size()) || topic
//         || u64_be(retention)            // u8 promoted to u64
//         || u64_be(metadata.size()) || metadata )
//
// The `dapp_info` RPC returns every one of those fields verbatim
// (service_pubkey + metadata as hex; topics as a string array; the three
// height fields + retention as integers), so the verifier recomputes the
// hash from the cleartext and rejects any divergence. A registration that
// has been deactivated still has a `d:` leaf (op=1 sets inactive_from but
// keeps the entry), so this command also reports the active/inactive state
// derived from the committee-anchored inactive_from vs the anchored head
// height — INACTIVE is a verified verdict, not a daemon claim.
//
// Verdict tri-state mirrors verify-merge-state / verify-param-change:
// INCLUDED / NOT-INCLUDED (sound, exit 0) and UNVERIFIABLE (fail-closed,
// exit 3); usage / parse errors exit 1. NOT-INCLUDED means the domain has
// no `d:` leaf at the verified head (never registered, or — once the
// chain implements registry pruning — pruned). A daemon that cannot serve
// the `d:` namespace, or whose cleartext disagrees with the committed
// leaf, yields UNVERIFIABLE — never a false INCLUDED.

int cmd_verify_dapp_registration(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, domain;
    uint64_t wait_seconds = 0;
    bool have_port = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--domain"  && i + 1 < argc) domain       = argv[++i];
        else if   (a == "--json")                    json_out     = true;
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "verify-dapp-registration: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || domain.empty()) {
        std::cerr << "verify-dapp-registration: "
                     "--rpc-port, --genesis, --domain are required\n";
        return 1;
    }

    InclusionVerdict verdict = InclusionVerdict::UNVERIFIABLE;
    std::string detail;
    std::string state_root_used;
    uint64_t    anchored_height = 0;
    // Committee-verified registration fields (populated only on INCLUDED).
    std::string service_pubkey_hex, endpoint_url, metadata_hex;
    std::vector<std::string> topics;
    uint64_t registered_at = 0, active_from = 0, inactive_from = 0,
             retention = 0;
    bool active = false;

    try {
        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-dapp-registration: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // `d:` is a simple-key namespace — the daemon prepends "d:" to the
        // raw domain bytes (no hex-encoded composite body). Compute the
        // canonical key locally so we can bind the proof's key_bytes to it.
        std::vector<uint8_t> local_key;
        local_key.reserve(2 + domain.size());
        local_key.push_back('d'); local_key.push_back(':');
        local_key.insert(local_key.end(), domain.begin(), domain.end());

        // Committee-verify the header chain end-to-end, capturing the
        // head's state_root (the anchor for the Merkle inclusion).
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex, /*track_registry=*/false, genesis.k_block_sigs, genesis.bft_enabled);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `d:` state-proofs cannot be "
                "anchored");
        }

        // Fetch the `d:`-namespace state-proof for this domain.
        auto proof = rpc.call("state_proof",
            {{"namespace", "d"}, {"key", domain}});

        // not_found for our exact key → NOT-INCLUDED, a daemon-asserted
        // negative per (H-neg) — NV-2/NV-3 (no such DApp registered at the
        // verified head, if the daemon answers absences honestly). Any other
        // refusal → fail-closed UNVERIFIABLE (we will not assert membership
        // either way).
        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].is_string()
                ? proof["error"].get<std::string>()
                : proof["error"].dump();
            if (err == "not_found") {
                verdict = InclusionVerdict::NOT_INCLUDED;
                detail  = "daemon reports no `d:` leaf for domain '" + domain
                        + "' — no such DApp is registered at the verified "
                          "head (state_proof not_found)";
            } else {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "daemon refused the `d:` state-proof: " + err
                        + " (cannot prove registration trustlessly)";
            }
        } else {
            // Bind the proof to THIS domain: its key_bytes must equal the
            // locally-computed canonical key. A mismatch means the daemon
            // served a proof for a different leaf → UNVERIFIABLE.
            std::string proof_key_hex =
                proof.value("key_bytes", std::string{});
            std::string local_key_hex =
                to_hex(local_key.data(), local_key.size());
            if (proof_key_hex != local_key_hex) {
                verdict = InclusionVerdict::UNVERIFIABLE;
                detail  = "proof.key_bytes=" + proof_key_hex
                        + " does not match the canonical d: key "
                        + local_key_hex
                        + " (daemon served a proof for a different leaf)";
            } else {
                // Fetch the cleartext registration via `dapp_info` and
                // recompute the committed leaf value_hash from it. This is
                // the load-bearing cross-check: a daemon could serve an
                // honest proof for the right key while lying in the
                // cleartext; the hash recomputation forces consistency.
                auto di = rpc.call("dapp_info", {{"domain", domain}});
                if (di.contains("error") && !di["error"].is_null()) {
                    // The state-proof said the leaf exists but dapp_info
                    // refuses it — inconsistent daemon, fail closed.
                    throw std::runtime_error(
                        "state_proof served a `d:` leaf for '" + domain
                        + "' but dapp_info refused it: " + di["error"].dump()
                        + " (inconsistent daemon)");
                }

                service_pubkey_hex = di.value("service_pubkey", std::string{});
                endpoint_url       = di.value("endpoint_url",   std::string{});
                metadata_hex       = di.value("metadata",       std::string{});
                registered_at      = di.value("registered_at",  uint64_t{0});
                active_from        = di.value("active_from",    uint64_t{0});
                inactive_from      = di.value("inactive_from",  uint64_t{0});
                retention          = di.value("retention",      uint64_t{0});
                if (di.contains("topics") && di["topics"].is_array())
                    for (auto& t : di["topics"]) topics.push_back(t.get<std::string>());

                // Decode the hex-encoded blobs back to the raw bytes the
                // leaf hashes (from_hex throws on malformed hex → exit 1).
                std::vector<uint8_t> service_pubkey = from_hex(service_pubkey_hex);
                std::vector<uint8_t> metadata =
                    metadata_hex.empty() ? std::vector<uint8_t>{}
                                         : from_hex(metadata_hex);
                if (service_pubkey.size() != 32) {
                    throw std::runtime_error(
                        "dapp_info service_pubkey is not 32 bytes (got "
                        + std::to_string(service_pubkey.size()) + ")");
                }

                // Recompute the committed leaf value_hash byte-for-byte
                // matching chain.cpp build_state_leaves "d:" branch.
                determ::crypto::SHA256Builder hb;
                hb.append(service_pubkey.data(), service_pubkey.size());
                hb.append(registered_at);
                hb.append(active_from);
                hb.append(inactive_from);
                hb.append(static_cast<uint64_t>(endpoint_url.size()));
                hb.append(endpoint_url);
                hb.append(static_cast<uint64_t>(topics.size()));
                for (auto& t : topics) {
                    hb.append(static_cast<uint64_t>(t.size()));
                    hb.append(t);
                }
                hb.append(retention);  // u8 promoted to u64 on chain too
                hb.append(static_cast<uint64_t>(metadata.size()));
                if (!metadata.empty()) hb.append(metadata.data(), metadata.size());
                Hash expected_value_hash = hb.finalize();

                Hash proof_value_hash = from_hex_arr<32>(
                    proof.value("value_hash", std::string{}));
                if (proof_value_hash != expected_value_hash) {
                    verdict = InclusionVerdict::UNVERIFIABLE;
                    detail  = "proof.value_hash=" + to_hex(proof_value_hash)
                            + " does not match the recomputed hash of the "
                              "dapp_info registration for '" + domain + "'="
                            + to_hex(expected_value_hash)
                            + " — daemon is lying about the registration "
                              "fields OR proving a different leaf";
                } else {
                    // Anchor the proof's claimed state_root to a
                    // committee-signed header (the chain may have advanced
                    // during the round-trip), mirroring verify-param-change.
                    uint64_t proof_height =
                        proof.value("height", uint64_t{0});
                    std::string proof_root =
                        proof.value("state_root", std::string{});
                    std::string anchor_root = vc.head_state_root;
                    uint64_t    anchor_at   = vc.height;

                    if (proof_height < vc.height) {
                        throw std::runtime_error(
                            "proof.height=" + std::to_string(proof_height)
                            + " is BEFORE verified-chain head="
                            + std::to_string(vc.height)
                            + " — daemon is serving stale state");
                    }
                    // SOUNDNESS: the committee signs compute_block_digest,
                    // which EXCLUDES state_root, so the daemon's state_root
                    // FIELD is NOT committee-attested. Bind proof_root to the
                    // COMMITTEE-SIGNED root committed by block proof_height-1
                    // via committee_bound_state_root (full-block recompute +
                    // successor-sig binding), never the bare header field.
                    {
                        json committee_json;
                        {
                            json arr = json::array();
                            for (auto& [domain_, pk] : committee_seed)
                                arr.push_back({{"domain", domain_},
                                               {"ed_pub", to_hex(pk)}});
                            committee_json = json{{"members", arr}};
                        }
                        uint64_t anchor_index = proof_height - 1;
                        std::string attested =
                            determ::light::committee_bound_state_root(rpc, committee_json, anchor_index, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
                        if (attested != proof_root) {
                            throw std::runtime_error(
                                "verify-dapp-registration: SECURITY — "
                                "committee-attested state_root at index "
                                + std::to_string(anchor_index) + " = " + attested
                                + " does NOT match proof.state_root = " + proof_root
                                + " — daemon served a proof against an "
                                  "unattested root");
                        }
                        vc.head_state_root = attested;  // downstream reporting uses the ATTESTED root
                        vc.height = proof_height;
                        anchor_root = attested;
                        anchor_at   = proof_height;
                    }

                    // Merkle-verify the proof against the committee-signed
                    // root. We already bound key_bytes + value_hash to the
                    // canonical registration above, so a pass here is a
                    // sound INCLUDED.
                    auto vsp = verify_state_proof(proof, anchor_root);
                    if (!vsp.ok) {
                        verdict = InclusionVerdict::UNVERIFIABLE;
                        detail  = "merkle verification failed: " + vsp.detail;
                    } else {
                        verdict = InclusionVerdict::INCLUDED;
                        state_root_used = anchor_root;
                        anchored_height = anchor_at;
                        // active/inactive is now a verified verdict: the
                        // inactive_from we hashed is committee-attested, so
                        // compare it against the committee-anchored head.
                        // DAPP_CALL is rejected once inactive_from <= height.
                        active = (anchored_height < inactive_from);
                    }
                }
            }
        }

        bool included = (verdict == InclusionVerdict::INCLUDED);
        if (json_out) {
            json out = {
                {"included",  included},
                {"verdict",   verdict_str(verdict)},
                {"domain",    domain},
                {"namespace", "d"},
            };
            // F-2 (NegativeVerdictSoundness.md): the d: state-proof negative is
            // DAEMON_ASSERTED — sound only under the non-cryptographic (H-neg)
            // premise (NV-2/NV-3); a consumer MUST apply NV-6 clause (3).
            if (verdict == InclusionVerdict::NOT_INCLUDED)
                out["negative_footing"] = "daemon_asserted";
            if (included) {
                out["active"]         = active;
                out["service_pubkey"] = service_pubkey_hex;
                out["endpoint_url"]   = endpoint_url;
                out["topics"]         = topics;
                out["retention"]      = retention;
                out["metadata"]       = metadata_hex;
                out["registered_at"]  = registered_at;
                out["active_from"]    = active_from;
                out["inactive_from"]  = inactive_from;
            }
            if (!state_root_used.empty()) {
                out["state_root"] = state_root_used;
                out["height"]     = anchored_height;
            }
            if (!detail.empty()) out["detail"] = detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << verdict_str(verdict) << "\n"
                      << "  genesis pin:       matches (" << genesis_hash_hex << ")\n"
                      << "  namespace:         d (dapp_registry)\n"
                      << "  domain:            " << domain << "\n";
            if (verdict == InclusionVerdict::INCLUDED) {
                std::cout << "  status:            "
                          << (active ? "ACTIVE" : "INACTIVE (deactivated)") << "\n"
                          << "  service_pubkey:    " << service_pubkey_hex << "\n"
                          << "  endpoint_url:      " << endpoint_url << "\n"
                          << "  topics:            " << topics.size() << "\n"
                          << "  retention:         " << retention << "\n"
                          << "  registered_at:     " << registered_at << "\n"
                          << "  active_from:       " << active_from << "\n"
                          << "  inactive_from:     " << inactive_from << "\n"
                          << "  state_root:        " << state_root_used << "\n"
                          << "  anchored at H:     " << anchored_height << "\n";
            }
            if (!detail.empty())
                std::cout << "  detail:            " << detail << "\n";
        }

        // Exit codes match verify-param-change: INCLUDED / NOT-INCLUDED → 0
        // (a definite answer; NOT-INCLUDED is daemon-asserted, (H-neg));
        // UNVERIFIABLE → 3 (refused to assert).
        if (verdict == InclusionVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-dapp-registration: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────────── verify-account ───────────────────────────

// Tri-state for the anon-account existence check. EXISTS is a sound committee-
// anchored verdict; NOT-CREATED is a daemon-asserted negative (sound only under
// the single-daemon (H-neg) honesty premise, NV-2/NV-3 — not a cryptographic
// absence proof). Both exit 0; UNVERIFIABLE is a refusal to
// assert (exit 3); a transport / parse / usage fault exits 1. Named
// distinctly from InclusionVerdict so the lifecycle semantics are explicit:
// the question is whether the chain has ever MATERIALIZED an `a:` leaf for
// this address, NOT membership in a logical set.
enum class AccountExistVerdict { EXISTS, NOT_CREATED, UNVERIFIABLE };

const char* account_exist_verdict_str(AccountExistVerdict v) {
    switch (v) {
        case AccountExistVerdict::EXISTS:       return "EXISTS";
        case AccountExistVerdict::NOT_CREATED:  return "NOT-CREATED";
        case AccountExistVerdict::UNVERIFIABLE: return "UNVERIFIABLE";
    }
    return "UNVERIFIABLE";
}

// verify-account — trustless anon-account derivation + lifecycle reader.
//
// THEME: anon-address derivation, normalization & account auto-creation.
//
// Given EITHER a raw Ed25519 public key (--pubkey <64-hex>) OR an
// already-formed anon-address (--address <0x...>), this command:
//
//   1. DERIVES the canonical 0x anon-address LOCALLY. With --pubkey it
//      mirrors make_anon_address (types.hpp): "0x" + lowercase-hex(pubkey),
//      the SAME 32-byte→address transform the chain uses for bearer wallets;
//      the operator never has to trust the daemon to tell them which address
//      a key controls. With --address it re-derives the pubkey via
//      parse_anon_pubkey and round-trips it back through make_anon_address,
//      so a case-mixed or malformed input is caught locally (S-028).
//   2. NORMALIZES to the lowercase-canonical storage form (S-028) so the
//      query hits the SAME account-map entry the chain commits under — a
//      0xABC… input and a 0xabc… input resolve to one leaf, never two.
//   3. Anchors genesis, committee-verifies the header chain to head, and
//      makes a sound verdict on the ACCOUNT-AUTO-CREATION lifecycle: an
//      anon-address has NO `a:` state leaf until its first credit (TRANSFER
//      in, an applied cross-shard receipt, or a DEREGISTER refund to a
//      non-registrant) materializes one. So:
//        • a committee-anchored `a:` Merkle proof  → EXISTS, and the
//          verified (balance, next_nonce) are reported;
//        • a state_proof `not_found` at the verified head → NOT-CREATED
//          (never credited — auto-creation has not fired). This is a
//          DAEMON-ASSERTED negative: sound only under the single-daemon
//          negative-honesty premise (H-neg), NOT a cryptographic absence
//          proof (the sorted-leaves tree has no non-membership witness,
//          MerkleTreeSoundness.md MT-5 / NegativeVerdictSoundness.md
//          NV-2/NV-3). The --json carries negative_footing=daemon_asserted
//          so a consumer applies NV-6 clause 3.
//
// ─── Why this is NOT balance-trustless ──────────────────────────────────
//
// balance-trustless THROWS on a not_found `a:` proof (it assumes the account
// exists and treats absence as an error). That conflates two very different
// chain states: "credited to zero" is impossible under auto-creation (a leaf
// only exists once credited), but the daemon's `account` RPC returns a bare
// balance=0 / next_nonce=0 for ANY unknown address WITHOUT erroring (see
// node.cpp rpc_account — it defaults the fields when the address is absent
// from the committed view). A naive client reading `account` alone cannot
// tell "never created" from "created then drained", and would render a
// fabricated zero as though it were chain-attested. verify-account narrows
// that gap: NOT-CREATED is asserted only after the genesis pin + the
// committee-verified header chain + an explicit `a:` state_proof not_found —
// a daemon-asserted absence ((H-neg) footing, NV-2/NV-3), strictly stronger
// than the bare `account` cleartext zero but NOT a cryptographic absence
// proof. On EXISTS it additionally hash-binds the
// daemon's `account` cleartext (SHA256(u64_be(balance) || u64_be(next_nonce))
// per build_state_leaves' "a:" branch) to the proof's value_hash, so a
// daemon lie about the balance of a real account is detected too.
//
// REUSE: the anchor is anchor_genesis + verify_chain_to_head +
// verify_state_proof + the race-window header re-anchoring read_account_-
// trustless uses; this command adds NO new crypto. It composes the existing
// single-leaf `a:` read with local address derivation and the absence path.
int cmd_verify_account(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, pubkey_hex, address_in;
    uint64_t wait_seconds = 0;
    bool have_port = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--pubkey"  && i + 1 < argc) pubkey_hex   = argv[++i];
        else if   (a == "--address" && i + 1 < argc) address_in   = argv[++i];
        else if   (a == "--json")                    json_out     = true;
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "verify-account: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty()
        || (pubkey_hex.empty() == address_in.empty())) {
        std::cerr << "verify-account: --rpc-port, --genesis, and EXACTLY ONE "
                     "of --pubkey <64-hex> / --address <0x...> are required\n";
        return 1;
    }

    // ── Step 1+2: derive + normalize the canonical anon-address LOCALLY ──
    // This is pure local computation — the daemon is never consulted to
    // learn which address a key controls.
    std::string canon_address;
    PubKey pk{};
    try {
        if (!pubkey_hex.empty()) {
            // make_anon_address path: "0x" + lowercase-hex(pubkey). from_hex_arr
            // is case-insensitive and rejects non-64-hex with a throw.
            if (pubkey_hex.size() != 64) {
                std::cerr << "verify-account: --pubkey must be exactly 64 hex "
                             "chars (a 32-byte Ed25519 public key); got "
                          << pubkey_hex.size() << "\n";
                return 1;
            }
            pk = from_hex_arr<32>(pubkey_hex);
            canon_address = make_anon_address(pk);  // already lowercase
        } else {
            // --address path: must be a well-formed anon shape (either case),
            // then re-derive the pubkey and round-trip to the canonical form.
            // This catches a malformed / non-anon --address locally (S-028).
            if (!is_anon_address(address_in)) {
                std::cerr << "verify-account: --address is not an anon-address "
                             "shape (expected \"0x\" + 64 hex chars): "
                          << address_in << "\n";
                return 1;
            }
            pk = parse_anon_pubkey(address_in);
            canon_address = make_anon_address(pk);  // == normalize_anon_address
        }
    } catch (const std::exception& e) {
        std::cerr << "verify-account: address derivation failed: "
                  << e.what() << "\n";
        return 1;
    }

    AccountExistVerdict verdict = AccountExistVerdict::UNVERIFIABLE;
    std::string detail;
    std::string state_root_used;
    uint64_t    anchored_height = 0;
    uint64_t    balance = 0, next_nonce = 0;  // populated only on EXISTS

    try {
        // ── Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-account: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // Committee-verify the header chain end-to-end, capturing the head's
        // state_root (the anchor for the `a:` Merkle proof / its absence).
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex, /*track_registry=*/false, genesis.k_block_sigs, genesis.bft_enabled);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `a:` state-proofs cannot be "
                "anchored");
        }

        // Fetch the `a:`-namespace state-proof for the canonical address.
        auto proof = rpc.call("state_proof",
            {{"namespace", "a"}, {"key", canon_address}});

        // not_found for our exact address → NOT-CREATED, a DAEMON-ASSERTED
        // negative: sound only under (H-neg), NOT a cryptographic absence
        // proof (MT-5 / NV-2/NV-3). Any OTHER refusal → fail-closed
        // UNVERIFIABLE (we will not assert either way).
        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].is_string()
                ? proof["error"].get<std::string>()
                : proof["error"].dump();
            if (err == "not_found") {
                verdict = AccountExistVerdict::NOT_CREATED;
                detail  = "daemon reports no `a:` leaf for '" + canon_address
                        + "' at the committee-verified head — never credited "
                          "(auto-creation has not fired); a daemon-asserted "
                          "negative (H-neg), not a cryptographic absence proof";
            } else {
                verdict = AccountExistVerdict::UNVERIFIABLE;
                detail  = "daemon refused the `a:` state-proof: " + err
                        + " (cannot prove existence trustlessly)";
            }
        } else {
            // Bind the proof to THIS address: its key_bytes must equal the
            // locally-computed canonical key ("a:" || canonical-address).
            std::vector<uint8_t> local_key;
            local_key.reserve(2 + canon_address.size());
            local_key.push_back('a'); local_key.push_back(':');
            local_key.insert(local_key.end(),
                             canon_address.begin(), canon_address.end());
            std::string proof_key_hex = proof.value("key_bytes", std::string{});
            std::string local_key_hex =
                to_hex(local_key.data(), local_key.size());
            if (proof_key_hex != local_key_hex) {
                verdict = AccountExistVerdict::UNVERIFIABLE;
                detail  = "proof.key_bytes=" + proof_key_hex
                        + " does not match the canonical a: key "
                        + local_key_hex
                        + " (daemon served a proof for a different leaf)";
            } else {
                // Fetch the cleartext (balance, next_nonce) via `account`,
                // recompute the committed leaf value_hash, and confirm it
                // matches. This is the load-bearing cross-check: a daemon
                // could serve an honest proof for the right key while lying
                // in the cleartext; the hash recomputation forces consistency.
                // Encoding matches build_state_leaves' "a:" branch exactly:
                // SHA256(u64_be(balance) || u64_be(next_nonce)).
                auto acct = rpc.call("account", {{"address", canon_address}});
                if (acct.contains("error") && !acct["error"].is_null()) {
                    // state_proof served an `a:` leaf but `account` refuses
                    // it — inconsistent daemon, fail closed.
                    throw std::runtime_error(
                        "state_proof served an `a:` leaf for '" + canon_address
                        + "' but the account RPC refused it: "
                        + acct["error"].dump() + " (inconsistent daemon)");
                }
                uint64_t bal = acct.value("balance",    uint64_t{0});
                uint64_t nn  = acct.value("next_nonce", uint64_t{0});

                determ::crypto::SHA256Builder hb;
                hb.append(bal);
                hb.append(nn);
                Hash expected_value_hash = hb.finalize();

                Hash proof_value_hash = from_hex_arr<32>(
                    proof.value("value_hash", std::string{}));
                if (proof_value_hash != expected_value_hash) {
                    verdict = AccountExistVerdict::UNVERIFIABLE;
                    detail  = "proof.value_hash=" + to_hex(proof_value_hash)
                            + " does not match the recomputed hash of the "
                              "account cleartext (balance="
                            + std::to_string(bal) + ", next_nonce="
                            + std::to_string(nn) + ")="
                            + to_hex(expected_value_hash)
                            + " — daemon is lying about the balance/nonce OR "
                              "proving a different leaf";
                } else {
                    // Anchor the proof's claimed state_root to a committee-
                    // signed header (the chain may have advanced during the
                    // round-trip), the identical re-anchoring read_account_-
                    // trustless / verify-dapp-registration use.
                    uint64_t proof_height = proof.value("height", uint64_t{0});
                    std::string proof_root =
                        proof.value("state_root", std::string{});
                    std::string anchor_root = vc.head_state_root;
                    uint64_t    anchor_at   = vc.height;

                    if (proof_height < vc.height) {
                        throw std::runtime_error(
                            "proof.height=" + std::to_string(proof_height)
                            + " is BEFORE verified-chain head="
                            + std::to_string(vc.height)
                            + " — daemon is serving stale state");
                    }
                    // SOUNDNESS: the committee signs compute_block_digest,
                    // which EXCLUDES state_root, so the daemon's state_root
                    // FIELD is NOT committee-attested. Bind proof_root to the
                    // COMMITTEE-SIGNED root committed by block proof_height-1
                    // via committee_bound_state_root (full-block recompute +
                    // successor-sig binding), never the bare header field.
                    {
                        json committee_json;
                        {
                            json arr = json::array();
                            for (auto& [domain_, pkc] : committee_seed)
                                arr.push_back({{"domain", domain_},
                                               {"ed_pub", to_hex(pkc)}});
                            committee_json = json{{"members", arr}};
                        }
                        uint64_t anchor_index = proof_height - 1;
                        std::string attested =
                            determ::light::committee_bound_state_root(rpc, committee_json, anchor_index, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
                        if (attested != proof_root) {
                            throw std::runtime_error(
                                "verify-account: SECURITY — committee-attested "
                                "state_root at index "
                                + std::to_string(anchor_index) + " = " + attested
                                + " does NOT match proof.state_root = " + proof_root
                                + " — daemon served a proof against an "
                                  "unattested root");
                        }
                        vc.head_state_root = attested;  // downstream reporting uses the ATTESTED root
                        vc.height = proof_height;
                        anchor_root = attested;
                        anchor_at   = proof_height;
                    }

                    // Merkle-verify the proof against the committee-signed
                    // root. key_bytes + value_hash are already bound to the
                    // canonical account, so a pass here is a sound EXISTS.
                    auto vsp = verify_state_proof(proof, anchor_root);
                    if (!vsp.ok) {
                        verdict = AccountExistVerdict::UNVERIFIABLE;
                        detail  = "merkle verification failed: " + vsp.detail;
                    } else {
                        verdict        = AccountExistVerdict::EXISTS;
                        balance        = bal;
                        next_nonce     = nn;
                        state_root_used = anchor_root;
                        anchored_height = anchor_at;
                    }
                }
            }
        }

        bool exists = (verdict == AccountExistVerdict::EXISTS);
        if (json_out) {
            json out = {
                {"verdict",   account_exist_verdict_str(verdict)},
                {"exists",    exists},
                {"address",   canon_address},
                {"pubkey",    to_hex(pk)},
                {"namespace", "a"},
            };
            // F-2 (NegativeVerdictSoundness.md): the a: state-proof negative is
            // DAEMON_ASSERTED — sound only under the non-cryptographic (H-neg)
            // premise (NV-2/NV-3); a consumer MUST apply NV-6 clause (3).
            if (verdict == AccountExistVerdict::NOT_CREATED)
                out["negative_footing"] = "daemon_asserted";
            if (exists) {
                out["balance"]    = balance;
                out["next_nonce"] = next_nonce;
            }
            if (!state_root_used.empty()) {
                out["state_root"] = state_root_used;
                out["height"]     = anchored_height;
            }
            if (!detail.empty()) out["detail"] = detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << account_exist_verdict_str(verdict) << "\n"
                      << "  genesis pin:       matches (" << genesis_hash_hex << ")\n"
                      << "  namespace:         a (accounts)\n"
                      << "  pubkey:            " << to_hex(pk) << "\n"
                      << "  address:           " << canon_address << "\n";
            if (verdict == AccountExistVerdict::EXISTS) {
                std::cout << "  balance:           " << balance << "\n"
                          << "  next_nonce:        " << next_nonce << "\n"
                          << "  state_root:        " << state_root_used << "\n"
                          << "  anchored at H:     " << anchored_height << "\n";
            }
            if (!detail.empty())
                std::cout << "  detail:            " << detail << "\n";
        }

        // Exit codes mirror verify-dapp-registration: EXISTS / NOT-CREATED → 0
        // (a definite answer; NOT-CREATED is daemon-asserted per (H-neg));
        // UNVERIFIABLE → 3 (refused to assert).
        if (verdict == AccountExistVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-account: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────── verify-equivocation ──────────────────────────

// verify-equivocation — OFFLINE equivocation-evidence verifier (FA6).
//
// Pure offline forensic oracle: no daemon, no genesis, no RPC. Given an
// EquivocationEvent JSON document (the wire shape emitted by
// EquivocationEvent::to_json / carried by the EQUIVOCATION_EVIDENCE gossip
// message + the submit_equivocation RPC) and the equivocator's registered
// Ed25519 public key, it INDEPENDENTLY re-runs the V11 check the daemon's
// BlockValidator::check_equivocation_events applies before the record is
// baked (EQV-height-bind + EQV-gen-bind form — the event carries per-side
// OPENINGS (index, gen, body_root), and each signed digest is DERIVED as
// SHA256(TAG || index u64 BE || gen u64 BE || body_root) with
// TAG = "DTM-BLKDIG-v3" for kind 0 / "DTM-CONTRIB-v3" for kind 1):
//
//   1. kind <= 1               (known digest family)
//   2. index_a == index_b == block_index   (the height bind)
//  2b. gen_a == gen_b          (the round bind — one abort generation)
//   3. body_root_a != body_root_b (two DISTINCT signed values — not a replay)
//   4. sig_a      != sig_b      (two distinct signatures)
//   5. Verify(pk, derive(index_a, gen_a, body_root_a), sig_a) == 1
//   6. Verify(pk, derive(index_b, gen_b, body_root_b), sig_b) == 1
//
// All passing is cryptographic proof the holder of `pk` signed two
// conflicting digests of ONE family at the SAME block_index with the SAME
// carried `gen`. Under Ed25519 EUF-CMA that cannot be fabricated for a key
// you do not hold, and post height-bind a replay of honest signatures from
// two DIFFERENT heights no longer qualifies (the openings pin each signature
// to its height).
//
// It is NOT, however, proof of a DELIBERATE double-sign, and a PROVEN verdict
// here must not be read as "this validator is dishonest". `gen` is a COUNT
// (abort-tail size), not a round identity: the S-050 stall valve and the
// S-048 depth-1 reorg both re-round at one height WITHOUT changing it, and an
// honest signer's two signatures from such a re-round satisfy every clause
// above. FA6 (EquivocationSlashing.md) is therefore NOT a no-false-positive
// result in that case — its Case (c) residual is open, and closing it needs a
// real per-height round counter (owner decision, DECISION-LOG). Operators:
// treat PROVEN as "two same-height same-gen signatures exist", and corroborate
// before acting on it (L1 itself applies no consequence — D4, 2026-09-16; the
// record is input to the L2 policy).
//
// The public key is supplied directly via --pubkey <64-hex> (the
// equivocator's registered ed_pub) OR resolved from a committee/genesis
// file via --committee <file> + the event's `equivocator` domain — the
// same {domain, ed_pub} array shape parse_committee accepts. Supplying the
// key from a SOURCE THE VERIFIER TRUSTS (not from the event itself) is what
// makes the verdict sound: the event carries the two sigs, the operator
// carries the key.
//
// Verdict discipline mirrors verify-tx-inclusion / decode-wire:
//   EQUIVOCATION-PROVEN → exit 0 (all V11 conditions hold; the record is a
//                         cryptographically valid double-sign proof)
//   NOT-EQUIVOCATION    → exit 3 (a V11 condition fails: unknown kind,
//                         mismatched heights, mismatched round generations,
//                         equal body roots, equal sigs,
//                         or either sig does not verify against its DERIVED
//                         digest — the evidence does NOT prove a double-sign;
//                         fail-closed, never a false PROVEN)
//   I/O / usage error   → exit 1 (missing file, bad hex, unknown domain)
//
// This is the read-side counterpart to the daemon's detection +
// apply path: an auditor, governance script, or counter-party can verify a
// circulating EquivocationEvent BEFORE trusting that it proves a double-sign,
// without running a full node.
enum class EquivVerdict { PROVEN, NOT_EQUIVOCATION };

const char* equiv_verdict_str(EquivVerdict v) {
    switch (v) {
        case EquivVerdict::PROVEN:           return "EQUIVOCATION-PROVEN";
        case EquivVerdict::NOT_EQUIVOCATION: return "NOT-EQUIVOCATION";
    }
    return "NOT-EQUIVOCATION";
}

int cmd_verify_equivocation(int argc, char** argv) {
    std::string in_path, pubkey_hex, committee_path;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"        && i + 1 < argc) in_path        = argv[++i];
        else if (a == "--pubkey"    && i + 1 < argc) pubkey_hex     = argv[++i];
        else if (a == "--committee" && i + 1 < argc) committee_path = argv[++i];
        else if (a == "--json")                      json_out       = true;
        else {
            std::cerr << "verify-equivocation: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (in_path.empty()) {
        std::cerr << "verify-equivocation: --in <event.json> is required "
                     "(read from stdin with --in -)\n";
        return 1;
    }
    if (pubkey_hex.empty() == committee_path.empty()) {
        std::cerr << "verify-equivocation: exactly one of --pubkey <64-hex> "
                     "or --committee <file> is required\n";
        return 1;
    }

    try {
        // Parse the EquivocationEvent via the canonical from_json. It already
        // enforces the field-name + hex-length contract (body_root_a/b
        // 64-hex, sig_a/sig_b 128-hex, kind <= 1) and throws a clear S-018
        // diagnostic on a malformed document — those are usage errors
        // (exit 1), not a NOT-EQUIVOCATION verdict.
        json doc = (in_path == "-") ? json::parse(std::cin)
                                    : read_json_file(in_path);
        determ::chain::EquivocationEvent ev =
            determ::chain::EquivocationEvent::from_json(doc);

        // Resolve the equivocator's Ed25519 key from the trusted source.
        // --pubkey takes the bare 64-hex key; --committee resolves it from a
        // {domain, ed_pub}[] file by the event's own `equivocator` domain (an
        // unknown domain is a usage error, not a soundness verdict).
        PubKey pk{};
        if (!pubkey_hex.empty()) {
            pk = from_hex_arr<32>(pubkey_hex);
        } else {
            auto committee = parse_committee(read_json_file(committee_path));
            auto it = committee.find(ev.equivocator);
            if (it == committee.end()) {
                std::cerr << "verify-equivocation: equivocator '"
                          << ev.equivocator << "' not found in --committee "
                          << committee_path << "\n";
                return 1;
            }
            pk = it->second;
        }

        // V11, re-run independently of the daemon (EQV-height-bind +
        // EQV-gen-bind form). Each clause that fails collapses the verdict to
        // NOT-EQUIVOCATION with a precise reason — the evidence is structurally
        // well-formed but does not prove a double-sign, so we fail closed
        // rather than emit a false PROVEN. The two signed digests are DERIVED
        // from the carried (index, gen, body_root) openings via an inline
        // compose (the offline mirror of producer.cpp::compose_block_digest /
        // compose_contrib_commitment — tag strings byte-identical).
        auto derive_digest = [&](uint64_t index, uint64_t gen,
                                 const Hash& body_root) {
            determ::crypto::SHA256Builder h;
            h.append(std::string(ev.kind == 0 ? "DTM-BLKDIG-v3"
                                              : "DTM-CONTRIB-v3"));
            h.append(index);
            h.append(gen);
            h.append(body_root);
            return h.finalize();
        };
        EquivVerdict verdict = EquivVerdict::PROVEN;
        std::string  reason;
        bool kind_known       = (ev.kind <= 1);
        bool heights_match    = (ev.index_a == ev.block_index
                                 && ev.index_b == ev.block_index);
        // EQV-gen-bind: both sides must be from the SAME abort generation —
        // an honest signer's two same-height signatures from two re-rounds are
        // not a double-sign.
        bool gens_match       = (ev.gen_a == ev.gen_b);
        bool roots_distinct   = (ev.body_root_a != ev.body_root_b);
        bool sigs_distinct    = (ev.sig_a != ev.sig_b);
        Hash digest_a{}, digest_b{};
        if (kind_known) {
            digest_a = derive_digest(ev.index_a, ev.gen_a, ev.body_root_a);
            digest_b = derive_digest(ev.index_b, ev.gen_b, ev.body_root_b);
        }
        bool sig_a_ok = kind_known && roots_distinct && determ::crypto::verify(
            pk, digest_a.data(), digest_a.size(), ev.sig_a);
        bool sig_b_ok = kind_known && roots_distinct && determ::crypto::verify(
            pk, digest_b.data(), digest_b.size(), ev.sig_b);

        if (!kind_known) {
            verdict = EquivVerdict::NOT_EQUIVOCATION;
            reason  = "unknown kind (expected 0=BLOCK_DIGEST or 1=CONTRIB_COMMIT)";
        } else if (!heights_match) {
            verdict = EquivVerdict::NOT_EQUIVOCATION;
            reason  = "index_a/index_b/block_index heights do not match";
        } else if (!gens_match) {
            verdict = EquivVerdict::NOT_EQUIVOCATION;
            reason  = "gen_a != gen_b (two different abort rounds at one "
                      "height, not a double-sign)";
        } else if (!roots_distinct) {
            verdict = EquivVerdict::NOT_EQUIVOCATION;
            reason  = "body_root_a == body_root_b (replay, not equivocation)";
        } else if (!sigs_distinct) {
            verdict = EquivVerdict::NOT_EQUIVOCATION;
            reason  = "sig_a == sig_b (single signature, not two)";
        } else if (!sig_a_ok) {
            verdict = EquivVerdict::NOT_EQUIVOCATION;
            reason  = "sig_a does not verify against the supplied key";
        } else if (!sig_b_ok) {
            verdict = EquivVerdict::NOT_EQUIVOCATION;
            reason  = "sig_b does not verify against the supplied key";
        }

        bool proven = (verdict == EquivVerdict::PROVEN);
        if (json_out) {
            json out = {
                {"verdict",      equiv_verdict_str(verdict)},
                {"proven",       proven},
                {"equivocator",  ev.equivocator},
                {"block_index",  ev.block_index},
                {"kind",         ev.kind},
                {"pubkey",       to_hex(pk)},
                {"index_a",      ev.index_a},
                {"gen_a",        ev.gen_a},
                {"body_root_a",  to_hex(ev.body_root_a)},
                {"index_b",      ev.index_b},
                {"gen_b",        ev.gen_b},
                {"body_root_b",  to_hex(ev.body_root_b)},
                {"derived_digest_a", to_hex(digest_a)},
                {"derived_digest_b", to_hex(digest_b)},
                {"sig_a_valid",  sig_a_ok},
                {"sig_b_valid",  sig_b_ok},
            };
            if (ev.shard_id != 0 || ev.beacon_anchor_height != 0) {
                out["shard_id"]             = ev.shard_id;
                out["beacon_anchor_height"] = ev.beacon_anchor_height;
            }
            if (!reason.empty()) out["reason"] = reason;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << equiv_verdict_str(verdict) << "\n"
                      << "  equivocator:  " << ev.equivocator << "\n"
                      << "  block_index:  " << ev.block_index << "\n"
                      << "  kind:         " << unsigned(ev.kind)
                      << (ev.kind == 0 ? " (BLOCK_DIGEST)"
                          : ev.kind == 1 ? " (CONTRIB_COMMIT)" : " (UNKNOWN)")
                      << "\n"
                      << "  pubkey:       " << to_hex(pk) << "\n"
                      << "  side a:       index=" << ev.index_a
                      << " gen=" << ev.gen_a
                      << " body_root=" << to_hex(ev.body_root_a) << "\n"
                      << "    derived digest: " << to_hex(digest_a)
                      << "  (sig " << (sig_a_ok ? "VALID" : "INVALID") << ")\n"
                      << "  side b:       index=" << ev.index_b
                      << " gen=" << ev.gen_b
                      << " body_root=" << to_hex(ev.body_root_b) << "\n"
                      << "    derived digest: " << to_hex(digest_b)
                      << "  (sig " << (sig_b_ok ? "VALID" : "INVALID") << ")\n";
            if (ev.shard_id != 0 || ev.beacon_anchor_height != 0) {
                std::cout << "  shard_id:     " << ev.shard_id << "\n"
                          << "  beacon anchor: " << ev.beacon_anchor_height
                          << "\n";
            }
            if (!reason.empty())
                std::cout << "  reason:       " << reason << "\n";
        }

        // EQUIVOCATION-PROVEN → exit 0 (a cryptographically valid double-sign
        // proof). NOT-EQUIVOCATION → exit 3 (sound refusal to assert a
        // double-sign; fail-closed). A throw above (bad hex / missing field /
        // I/O) lands in the catch as exit 1.
        return proven ? 0 : 3;
    } catch (const std::exception& e) {
        std::cerr << "verify-equivocation: " << e.what() << "\n";
        return 1;
    }
}

// ────────────────────────── shard-route ────────────────────────────────
//
// shard-route — OFFLINE genesis-pinned address-to-shard routing oracle.
//
// Pure offline reader: no daemon, no RPC. Given a pinned genesis JSON and an
// address (anon-form `0x...64hex` or a registered domain), it reports which
// shard OWNS that address on THIS chain. Unlike the daemon's `where-is`
// diagnostic — which takes the shard count + salt as raw operator-supplied
// flags — shard-route reads BOTH routing parameters FROM THE GENESIS itself
// (initial_shard_count + shard_address_salt). Both are CSPRNG-fixed at build
// time and bound into compute_genesis_hash, so they are immutable for the
// chain's lifetime (see crypto/random.hpp): the home shard of any address is
// a function of the chain identity alone. The command prints the locally
// computed genesis hash so the operator can confirm the routing is anchored
// to the chain they expect — a wrong-genesis file (a different chain) yields
// a different hash AND, in general, a different home shard.
//
// The routing math is re-implemented INDEPENDENTLY of the daemon's codec
// (the light-client never links crypto/random.cpp), byte-for-byte matching
// crypto::shard_id_for_address:
//   shard_count <= 1            -> shard 0 (unsharded; no salt mixing)
//   otherwise  h = SHA256(shard_address_salt || "shard-route" || addr)
//              shard = fold_be8(h[0..7]) % shard_count
// Because the test producer (`determ where-is`) and this decoder are written
// from the SAME spec in DIFFERENT code paths, an agreeing run is a genuine
// cross-implementation conformance check on the v1.x routing primitive.
//
// Anon-form addresses are normalized to canonical lowercase (S-028) before
// routing, mirroring how the chain canonicalizes a TRANSFER's `to` before it
// computes is_cross_shard — so `0xABC...` and `0xabc...` route identically.
// Domain names and other shapes route on their exact bytes (routing is
// case-sensitive on non-anon inputs; upstream address validation is the
// caller's responsibility, exactly as in the daemon).
//
// Exit 0 on a successful routing; exit 1 on a usage / genesis-parse error.
// There is no UNVERIFIABLE state: the genesis IS the trust anchor, so a
// parseable genesis always yields a sound, deterministic home shard.
int cmd_shard_route(int argc, char** argv) {
    std::string genesis_path, address;
    bool have_address = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if (a == "--address" && i + 1 < argc) {
            address = argv[++i]; have_address = true;
        } else if (a == "--json")                  json_out     = true;
        else {
            std::cerr << "shard-route: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (genesis_path.empty() || !have_address) {
        std::cerr << "shard-route: --genesis and --address are required\n";
        return 1;
    }
    try {
        // The genesis IS the trust anchor. load_genesis applies the S-018
        // schema guards (shard_address_salt, if present, must be 64-char
        // hex), so a malformed file fails fast before any routing.
        auto genesis = load_genesis(genesis_path);

        // Pin the chain identity locally so the operator can confirm the
        // routing is anchored to the chain they expect (a different genesis
        // file -> a different hash here).
        Hash genesis_hash = determ::chain::compute_genesis_hash(genesis);

        uint32_t shard_count = genesis.initial_shard_count;

        // Normalize anon-shape addresses to canonical lowercase (S-028),
        // matching the chain's pre-routing canonicalization. Non-anon shapes
        // (domain names) pass through unchanged.
        std::string routed_addr = normalize_anon_address(address);

        // Compute the home shard INDEPENDENTLY of crypto::shard_id_for_address,
        // byte-for-byte matching its algorithm (random.cpp). shard_count <= 1
        // short-circuits to shard 0 with no salt mixing.
        uint64_t shard = 0;
        if (shard_count > 1) {
            determ::crypto::SHA256Builder hb;
            hb.append(genesis.shard_address_salt);
            hb.append(std::string("shard-route"));
            hb.append(routed_addr);
            Hash h = hb.finalize();
            uint64_t v = 0;
            for (int i = 0; i < 8; ++i)
                v = (v << 8) | h[i];
            shard = v % shard_count;
        }

        bool anon = is_anon_address(address);
        if (json_out) {
            json out = {
                {"address",      address},
                {"routed_address", routed_addr},
                {"anon",         anon},
                {"shard",        shard},
                {"shard_count",  shard_count},
                {"genesis_hash", to_hex(genesis_hash)},
            };
            std::cout << out.dump() << "\n";
        } else {
            std::cout << routed_addr << " -> shard " << shard
                      << " (of " << shard_count << ")\n"
                      << "  genesis pin: " << to_hex(genesis_hash) << "\n";
            if (shard_count <= 1)
                std::cout << "  note:        chain is unsharded "
                             "(initial_shard_count=" << shard_count
                          << ") — every address routes to shard 0\n";
            if (anon && routed_addr != address)
                std::cout << "  note:        anon address normalized to "
                             "canonical lowercase (S-028)\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "shard-route: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────── supply-trustless ─────────────────────────────

// Tri-state for the A1 unitary-supply conservation check, mirroring the
// verify-* exit policy but named distinctly so the output cannot be
// confused with a single-leaf inclusion proof. CONSERVED / VIOLATED are
// sound verified verdicts (exit 0 / exit 2); UNVERIFIABLE is a refusal to
// assert (exit 3); a transport/parse fault exits 1.
enum class SupplyVerdict { CONSERVED, VIOLATED, UNVERIFIABLE };

const char* supply_verdict_str(SupplyVerdict v) {
    switch (v) {
        case SupplyVerdict::CONSERVED:    return "CONSERVED";
        case SupplyVerdict::VIOLATED:     return "VIOLATED";
        case SupplyVerdict::UNVERIFIABLE: return "UNVERIFIABLE";
    }
    return "UNVERIFIABLE";
}

// supply-trustless — trustless A1 unitary-supply conservation reader.
//
// Reads the five A1 supply counters (genesis_total, accumulated_subsidy,
// accumulated_inbound, accumulated_slashed, accumulated_outbound) from the
// committee-verified `c:` namespace and recomputes the closed-form A1
// identity entirely from committee-committed values:
//
//   expected_total = genesis_total + accumulated_subsidy
//                  + accumulated_inbound - accumulated_slashed
//                  - accumulated_outbound
//
// ─── Distinct from balance-trustless / stake-trustless ──────────────────
//
//   balance-trustless (a:) and stake-trustless (s:) each verify a SINGLE
//   leaf in isolation; there is no cross-leaf invariant a verifier can
//   re-check. The supply counters are different: the five values are
//   bound by the closed-form A1 identity that the apply path enforces at
//   every block (chain.cpp: `if (live_total_supply() != expected_total())
//   throw`). supply-trustless is the observation that this identity is
//   PUBLICLY RECOMPUTABLE from the five committed counters alone — the
//   light client does not need live_total_supply() (the sum over every
//   a:/s: leaf, which would require enumerating all accounts) to gain a
//   meaningful consistency guarantee on the counters themselves.
//
// ─── Trust model ────────────────────────────────────────────────────────
//
// Anchors genesis, committee-verifies the header chain to head, and
// captures the single committee-signed state_root R. For each of the five
// counters it (1) computes the canonical leaf key ("k:c:" + name — note
// the const_leaf double prefix in chain.cpp build_state_leaves; the daemon
// reconstructs it from the bare counter name passed as the `c:`-namespace
// `key`), (2) fetches the `c:` state-proof, (3) binds the proof to the
// SAME R (rejecting any counter anchored to a different root — the
// split-root attack), (4) Merkle-verifies it, and (5) cross-checks the
// daemon's cleartext counter (from the `chain_summary` RPC) by recomputing
// SHA256(u64_be(value)) against the proof's verified value_hash. A daemon
// lying about a counter value while serving an honest proof must find a
// SHA-256 second-preimage on a single u64 field — negligible.
//
// Once all five are verified against R, the A1 identity is recomputed from
// the committed values and compared against the daemon's claimed
// total_supply: CONSERVED means the five committee-committed counters are
// internally consistent (and, when the daemon's cleartext total_supply is
// available, equal it). Any tamper, mismatch, split-root, or daemon
// refusal → UNVERIFIABLE, never a false CONSERVED.
//
// REUSE: the trustless anchor is verify_chain_to_head + verify_state_proof
// + the race-window header-anchoring used by read_account_trustless; this
// command adds NO new crypto — it repeats the single-leaf c: read five
// times against one head and composes the public closed form.
int cmd_supply_trustless(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, state_path;
    uint64_t wait_seconds = 0;
    bool have_port = false, json_out = false, resume = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--json")                    json_out     = true;
        else if   (a == "--resume")                  resume       = true;
        else if   (a == "--state" && i + 1 < argc)   state_path   = argv[++i];
        else if   (a == "--wait" && i + 1 < argc)
            wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "supply-trustless: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty()) {
        std::cerr << "supply-trustless: --rpc-port, --genesis are required\n";
        return 1;
    }

    // The five A1 supply counters, in the order build_state_leaves emits
    // them. The bare name here is the `c:`-namespace `key` the daemon
    // expects; it reconstructs the full leaf key as "k:c:" + name (see
    // node.cpp rpc_state_proof's `ns == "c"` branch and chain.cpp's
    // const_leaf("c:<name>", ...) calls, which prepend a second "k:").
    static const char* kCounters[5] = {
        "genesis_total", "accumulated_subsidy", "accumulated_inbound",
        "accumulated_slashed", "accumulated_outbound"
    };

    SupplyVerdict verdict = SupplyVerdict::UNVERIFIABLE;
    std::string detail;
    std::string state_root_used;
    uint64_t    anchored_height = 0;
    // Committee-verified counter values, indexed by kCounters position.
    uint64_t cval[5] = {0, 0, 0, 0, 0};

    try {
        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "supply-trustless: " << rpc.last_error() << "\n";
            return 1;
        }
        // Anchor genesis + committee-verify the header chain end-to-end (full,
        // or --resume the suffix above a cached anchor), capturing the head's
        // state_root (the single anchor for ALL five c: proofs).
        auto ah = anchored_head(rpc, committee_seed, genesis, resume, state_path);
        std::string genesis_hash_hex = ah.genesis_hash_hex;
        VerifiedChain vc = ah.vc;
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `c:` state-proofs cannot be "
                "anchored");
        }

        // Fetch the daemon's cleartext counters once. chain_summary exposes
        // all five accumulators plus total_supply (= live_total_supply).
        // last_n=1 keeps the envelope light; we only read the counters.
        // These are UNTRUSTED until each is hash-bound to a verified c:
        // value_hash below.
        auto summary = rpc.call("chain_summary", {{"last_n", uint32_t{1}}});
        if (summary.contains("error") && !summary["error"].is_null()) {
            throw std::runtime_error(
                "chain_summary RPC error: " + summary["error"].dump());
        }
        // The cleartext value the daemon claims for each counter, in
        // kCounters order. total_supply is the claimed live_total_supply.
        uint64_t claimed[5] = {
            summary.value("genesis_total",        uint64_t{0}),
            summary.value("accumulated_subsidy",  uint64_t{0}),
            summary.value("accumulated_inbound",  uint64_t{0}),
            summary.value("accumulated_slashed",  uint64_t{0}),
            summary.value("accumulated_outbound", uint64_t{0}),
        };
        uint64_t claimed_total = summary.value("total_supply", uint64_t{0});
        bool have_claimed_total = summary.contains("total_supply");

        // The single committee-anchored root every counter must commit to.
        // Resolved lazily from the first counter's proof (which may anchor
        // at a height ahead of vc.height if the chain advanced during the
        // round-trip); thereafter every counter is required to match it,
        // closing the split-root attack.
        std::string anchor_root;       // empty until the first proof anchors
        uint64_t    anchor_at = 0;

        bool all_ok = true;
        for (int ci = 0; ci < 5 && all_ok; ++ci) {
            const std::string name = kCounters[ci];

            // Canonical leaf key, byte-for-byte matching build_state_leaves:
            //   "k:" + ("c:" + name)  ==  "k:c:" + name
            std::vector<uint8_t> local_key;
            {
                std::string full = std::string("k:c:") + name;
                local_key.assign(full.begin(), full.end());
            }
            std::string local_key_hex = to_hex(local_key.data(), local_key.size());

            // Fetch the `c:` state-proof. The `c:` namespace is a SIMPLE
            // (ASCII-key) namespace: the daemon takes the bare counter
            // name as `key` and rebuilds "k:c:" + name internally.
            auto proof = rpc.call("state_proof",
                {{"namespace", "c"}, {"key", name}});

            // R51: prefer the proof's ATOMIC raw value (value_hex — served
            // from the SAME locked snapshot as the proof + root) over the
            // earlier chain_summary claim. This closes the height race that
            // made the per-block counters (accumulated_subsidy advances
            // every block) mismatch an HONEST daemon's later proof. Trust
            // is UNCHANGED: the value below must still hash to the
            // Merkle-verified value_hash — a daemon lying in value_hex is
            // caught by exactly the same check as a lying chain_summary.
            bool value_from_proof = false;
            if (proof.contains("value_hex") && proof["value_hex"].is_string()) {
                std::string vh = proof["value_hex"].get<std::string>();
                if (vh.size() == 16) {
                    try {
                        auto vb = from_hex(vh);
                        uint64_t v = 0;
                        for (int i = 0; i < 8; i++) v = (v << 8) | vb[(size_t)i];
                        claimed[ci] = v;
                        value_from_proof = true;
                    } catch (const std::exception&) { /* fall back to summary */ }
                }
            }

            // Committed value for a counter is SHA256(u64_be(value)).
            // Recompute it from the claimed value (atomic value_hex when the
            // daemon serves it, chain_summary cleartext otherwise); the
            // binding is the comparison against the proof's verified
            // value_hash.
            determ::crypto::SHA256Builder mb;
            mb.append(claimed[ci]);
            Hash expected_value_hash = mb.finalize();

            if (proof.contains("error") && !proof["error"].is_null()) {
                std::string err = proof["error"].is_string()
                    ? proof["error"].get<std::string>()
                    : proof["error"].dump();
                // A counter leaf is ALWAYS present on an S-033 chain
                // (const_leaf emits all five unconditionally), so a
                // not_found here is itself anomalous — fail closed.
                verdict = SupplyVerdict::UNVERIFIABLE;
                detail  = "daemon refused the `c:` state-proof for counter '"
                        + name + "': " + err
                        + " (cannot verify supply trustlessly)";
                all_ok = false;
                break;
            }

            // Bind the proof to THIS counter: (1) key_bytes must equal the
            // canonical "k:c:" + name key, (2) value_hash must equal the
            // recomputed SHA256(u64_be(claimed value)). A key mismatch
            // means the daemon served a proof for a different leaf; a
            // value_hash mismatch means it is lying about the counter
            // value while serving an honest proof. Either → UNVERIFIABLE.
            std::string proof_key_hex = proof.value("key_bytes", std::string{});
            if (proof_key_hex != local_key_hex) {
                verdict = SupplyVerdict::UNVERIFIABLE;
                detail  = "proof.key_bytes=" + proof_key_hex
                        + " does not match the canonical counter key "
                        + local_key_hex + " for '" + name
                        + "' (daemon served a proof for a different leaf)";
                all_ok = false;
                break;
            }
            Hash proof_value_hash = from_hex_arr<32>(
                proof.value("value_hash", std::string{}));
            if (proof_value_hash != expected_value_hash) {
                verdict = SupplyVerdict::UNVERIFIABLE;
                detail  = std::string("TAMPERED — daemon's ")
                        + (value_from_proof ? "atomic value_hex"
                                            : "chain_summary cleartext")
                        + " for counter '" + name
                        + "'=" + std::to_string(claimed[ci])
                        + " hashes to " + to_hex(expected_value_hash)
                        + " but the c: state-proof's value_hash is "
                        + to_hex(proof_value_hash)
                        + " — daemon is lying about the counter OR the proof"
                        + (value_from_proof ? "" :
                           " (or the chain advanced between chain_summary and"
                           " the proof — a daemon serving the R51 atomic"
                           " value_hex field does not have this race)");
                all_ok = false;
                break;
            }

            // Anchor the proof's claimed state_root to a committee-signed
            // header. The first counter resolves the single anchor root
            // (handling the race window where the chain advanced past
            // vc.height during the round-trip); every later counter MUST
            // match that exact root, closing the split-root attack.
            uint64_t proof_height = proof.value("height", uint64_t{0});
            std::string proof_root = proof.value("state_root", std::string{});

            if (anchor_root.empty()) {
                if (proof_height < vc.height) {
                    throw std::runtime_error(
                        "proof.height=" + std::to_string(proof_height)
                        + " for '" + name + "' is BEFORE verified-chain head="
                        + std::to_string(vc.height)
                        + " — daemon is serving stale state");
                }
                // SOUNDNESS: the committee signs compute_block_digest, which
                // EXCLUDES state_root, so the daemon's state_root FIELD is
                // NOT committee-attested. Resolve the single anchor root from
                // the FIRST counter's proof by binding proof_root to the
                // COMMITTEE-SIGNED root committed by block proof_height-1 via
                // committee_bound_state_root (full-block recompute +
                // successor-sig binding), never the bare header field. Every
                // later counter must then match this exact attested root (the
                // split-root guard below), closing the split-read attack.
                {
                    json committee_json;
                    {
                        json arr = json::array();
                        for (auto& [domain_, pk] : committee_seed)
                            arr.push_back({{"domain", domain_},
                                           {"ed_pub", to_hex(pk)}});
                        committee_json = json{{"members", arr}};
                    }
                    uint64_t anchor_index = proof_height - 1;
                    std::string attested =
                        determ::light::committee_bound_state_root(rpc, committee_json, anchor_index, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
                    if (attested != proof_root) {
                        throw std::runtime_error(
                            "supply-trustless: SECURITY — committee-attested "
                            "state_root at index "
                            + std::to_string(anchor_index) + " = " + attested
                            + " does NOT match proof.state_root = " + proof_root
                            + " — daemon served a proof against an "
                              "unattested root");
                    }
                    vc.head_state_root = attested;  // downstream reporting uses the ATTESTED root
                    vc.height = proof_height;
                    anchor_root = attested;
                    anchor_at   = proof_height;
                }
            } else if (proof_root != anchor_root) {
                // Split-root attack: this counter is anchored to a
                // DIFFERENT root than the earlier counters. At most one
                // root can equal the committee-verified head, so the five
                // counters would not be a consistent snapshot. Fail closed.
                verdict = SupplyVerdict::UNVERIFIABLE;
                detail  = "counter '" + name + "' anchors to state_root="
                        + proof_root + " but earlier counters anchored to "
                        + anchor_root
                        + " — daemon split the read across two states "
                          "(cannot recompute the A1 identity over a single "
                          "consistent snapshot)";
                all_ok = false;
                break;
            }

            // Merkle-verify the proof against the single anchored root.
            auto vsp = verify_state_proof(proof, anchor_root);
            if (!vsp.ok) {
                verdict = SupplyVerdict::UNVERIFIABLE;
                detail  = "merkle verification failed for counter '" + name
                        + "': " + vsp.detail;
                all_ok = false;
                break;
            }

            // This counter is committee-committed under the single root.
            cval[ci] = claimed[ci];
        }

        if (all_ok) {
            // R51: the claimed_total comparison below is only SOUND when the
            // daemon's total_supply cleartext is from the SAME height the
            // five counters anchored at — on a live chain the pre-loop
            // chain_summary is stale by the time the proofs anchor. Re-fetch
            // and height-gate: compare only if the fresh summary's height
            // equals the anchored height; otherwise skip the (optional)
            // total cross-check rather than report a false VIOLATED. The
            // five-counter A1 identity itself is computed purely from the
            // committee-committed values and is unaffected.
            if (have_claimed_total) {
                auto summary2 = rpc.call("chain_summary",
                                         {{"last_n", uint32_t{1}}});
                bool fresh_ok = !(summary2.contains("error")
                                  && !summary2["error"].is_null());
                uint64_t h2 = fresh_ok ? summary2.value("height", uint64_t{0})
                                       : 0;
                if (fresh_ok && h2 == anchor_at
                    && summary2.contains("total_supply")) {
                    claimed_total = summary2.value("total_supply", uint64_t{0});
                } else if (summary.value("height", uint64_t{0}) != anchor_at) {
                    // Neither summary aligns with the anchored height —
                    // the total cross-check would compare across heights.
                    have_claimed_total = false;
                }
            }

            // All five counters verified against the same committee-anchored
            // root. Recompute the A1 closed-form identity entirely from the
            // committed values (chain.hpp expected_total). Underflow-safe:
            // the apply path maintains genesis_total + subsidy + inbound >=
            // slashed + outbound at every block, but a malicious daemon
            // could in principle present counters where it does not — guard
            // explicitly so VIOLATED is reported rather than wrapping.
            uint64_t pos = cval[0] + cval[1] + cval[2];   // gtotal+subsidy+inbound
            uint64_t neg = cval[3] + cval[4];             // slashed+outbound
            bool underflow = (neg > pos);
            uint64_t expected_total = underflow ? 0 : (pos - neg);

            state_root_used = anchor_root;
            anchored_height = anchor_at;

            if (underflow) {
                // The five committee-committed counters do not satisfy the
                // A1 non-negativity precondition — a genuine VIOLATED.
                verdict = SupplyVerdict::VIOLATED;
                detail  = "committed counters underflow the A1 identity "
                          "(slashed+outbound > genesis+subsidy+inbound)";
            } else if (have_claimed_total && claimed_total != expected_total) {
                // The counters are individually committee-committed and
                // internally well-formed, but the daemon's claimed
                // total_supply disagrees with the closed form. The total
                // is NOT itself leaf-committed (live_total_supply is the
                // sum over a:/s: leaves, which we do not enumerate — the
                // S-040 leaf_count boundary), so we report VIOLATED on the
                // recomputed-vs-claimed mismatch.
                verdict = SupplyVerdict::VIOLATED;
                detail  = "recomputed expected_total="
                        + std::to_string(expected_total)
                        + " from committee-committed counters but daemon "
                          "claims total_supply="
                        + std::to_string(claimed_total)
                        + " (A1 unitary-supply identity violated)";
            } else {
                verdict = SupplyVerdict::CONSERVED;
            }
        }

        // Recompute the closed form for output (zero on a failed read).
        uint64_t pos = cval[0] + cval[1] + cval[2];
        uint64_t neg = cval[3] + cval[4];
        uint64_t expected_total = (neg > pos) ? 0 : (pos - neg);
        bool conserved = (verdict == SupplyVerdict::CONSERVED);

        if (json_out) {
            json out = {
                {"conserved",            conserved},
                {"verdict",              supply_verdict_str(verdict)},
                {"namespace",            "c"},
                {"genesis_total",        cval[0]},
                {"accumulated_subsidy",  cval[1]},
                {"accumulated_inbound",  cval[2]},
                {"accumulated_slashed",  cval[3]},
                {"accumulated_outbound", cval[4]},
                {"expected_total",       expected_total},
            };
            if (have_claimed_total) out["claimed_total_supply"] = claimed_total;
            if (!state_root_used.empty()) {
                out["state_root"] = state_root_used;
                out["height"]     = anchored_height;
            }
            if (!detail.empty()) out["detail"] = detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << supply_verdict_str(verdict) << "\n"
                      << "  genesis pin:           matches (" << genesis_hash_hex << ")\n"
                      << "  namespace:             c (A1 supply counters)\n";
            if (verdict != SupplyVerdict::UNVERIFIABLE) {
                std::cout << "  genesis_total:         " << cval[0] << "\n"
                          << "  +accumulated_subsidy:  " << cval[1] << "\n"
                          << "  +accumulated_inbound:  " << cval[2] << "\n"
                          << "  -accumulated_slashed:  " << cval[3] << "\n"
                          << "  -accumulated_outbound: " << cval[4] << "\n"
                          << "  =expected_total:       " << expected_total << "\n";
                if (have_claimed_total)
                    std::cout << "  daemon total_supply:   " << claimed_total << "\n";
                std::cout << "  state_root:            " << state_root_used << "\n"
                          << "  anchored at H:         " << anchored_height << "\n";
            }
            if (!detail.empty())
                std::cout << "  detail:                " << detail << "\n";
        }

        // Exit codes: CONSERVED → 0; VIOLATED → 2 (a sound verified
        // violation, distinct from CONSERVED so a script can branch);
        // UNVERIFIABLE → 3 (refused to assert). This mirrors the daemon's
        // own `supply` command, which exits 2 on an A1 invariant violation.
        if (verdict == SupplyVerdict::UNVERIFIABLE) return 3;
        if (verdict == SupplyVerdict::VIOLATED)     return 2;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "supply-trustless: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────── committee-at-height ──────────────────────────

// Tri-state for a --member membership query, mirroring the verify-* exit
// policy: a sound verified answer (IN / NOT-IN) exits 0; a refusal to
// assert exits 3; a transport/parse fault exits 1. Named distinctly from
// the inclusion-proof verdicts so the output cannot be confused with a
// state/tx membership proof.
enum class CommitteeVerdict { IN_COMMITTEE, NOT_IN_COMMITTEE, UNVERIFIABLE };

const char* committee_verdict_str(CommitteeVerdict v) {
    switch (v) {
        case CommitteeVerdict::IN_COMMITTEE:     return "IN-COMMITTEE";
        case CommitteeVerdict::NOT_IN_COMMITTEE: return "NOT-IN-COMMITTEE";
        case CommitteeVerdict::UNVERIFIABLE:     return "UNVERIFIABLE";
    }
    return "UNVERIFIABLE";
}

// committee-at-height — trustless committee-membership reader.
//
// Reports the committee-verified set of creators (consensus committee
// members) that produced block H, optionally answering "is domain D a
// member of the committee at H?" as a sound tri-state.
//
// ─── Distinct from verify-block-sigs ───────────────────────────────────
//
//   verify-block-sigs takes a committee file the OPERATOR supplies and
//   checks that header H's sigs verify against THAT set — it cannot tell
//   you who the committee is, only whether the sigs match a list you
//   already trust. committee-at-height DERIVES the committee trustlessly
//   from the chain: it anchors genesis, binds header[H] to block 0 via a
//   prev_hash chain walk, verifies H's K-of-K (MD) / ceil(2K/3) (BFT)
//   committee sigs over light_compute_block_digest(H), and only then
//   reports creators[] — which is committee-attested because the digest
//   the committee signed BINDS creators[] (see verify.cpp
//   light_compute_block_digest: `for (auto& c : b.creators) h.append(c)`).
//
// A forged "header at H with a fabricated creator set" must therefore (a)
// chain to the pinned genesis AND (b) carry committee sigs over a digest
// that commits to that very creator set — both checked here. Genesis
// (H=0) has no committee by construction (the deterministic
// GenesisConfig->Block transform); it is rejected with a clear diagnostic
// rather than reporting an empty committee.
//
// REUSE: the trustless anchor is verify_state_root_at (genesis pin +
// bounded prev_hash walk + committee-sig verification). This command adds
// NO new crypto — it re-fetches the now-attested header[H] and enumerates
// creators[] paired with each member's genesis-committee pubkey + slot +
// signature status (real sig vs BFT sentinel-zero abstention).
int cmd_committee_at_height(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path, member;
    uint64_t height = 0, wait_seconds = 0;
    bool have_port = false, have_height = false, have_member = false,
         json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--height"  && i + 1 < argc) {
            height = parse_u64("--height", argv[++i]); have_height = true;
        } else if (a == "--member"  && i + 1 < argc) {
            member = argv[++i]; have_member = true;
        } else if (a == "--json")                    json_out = true;
        else if   (a == "--wait" && i + 1 < argc)    wait_seconds = parse_u64("--wait", argv[++i]);
        else {
            std::cerr << "committee-at-height: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty() || !have_height) {
        std::cerr << "committee-at-height: --rpc-port, --genesis, --height "
                     "are required\n";
        return 1;
    }

    try {
        // Pin the chain identity first (fail-closed if block 0 != genesis).
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "committee-at-height: " << rpc.last_error() << "\n";
            return 1;
        }
        std::string genesis_hash_hex = anchor_genesis(rpc, genesis);

        // Genesis carries no committee by construction. Refuse rather than
        // report an empty committee a caller might misread as "no members".
        if (height == 0) {
            std::cerr << "committee-at-height: height 0 (genesis) has no "
                         "committee — it is the deterministic GenesisConfig->"
                         "Block transform with no committee sigs; query a "
                         "produced block (H >= 1)\n";
            return 1;
        }

        // Trustless anchor: genesis pin + bounded prev_hash walk [0, H] +
        // committee-sig verification of header[H]. On a sig failure or a
        // height beyond head this returns ok=false (clean error), never a
        // bare daemon-reported committee. --wait (default 0) matters only
        // when H == head: the S-042 successor binding needs block H+1, so a
        // query at the exact head fails closed until the chain advances. For
        // any H < head the successor already exists and no wait is needed.
        auto sr = verify_state_root_at(rpc, committee_seed, genesis_hash_hex, height, wait_seconds, genesis.k_block_sigs, genesis.bft_enabled);
        if (!sr.ok) {
            std::cerr << "committee-at-height: " << sr.detail << "\n";
            return 1;
        }

        // Read creators[] from the COMMITTEE-BOUND FULL block, RECOMPUTE-bound to
        // the attested block_hash. verify_state_root_at (H>=1) verifies committee
        // sigs on the SUCCESSOR H+1, never on H's own header, so H's creators are
        // bound ONLY via committee_bound_state_root's full-block recompute (which
        // sr.block_hash_hex is). Re-fetching the STRIPPED header and string-comparing
        // its (free, daemon-controlled) block_hash field is NOT a bind — a daemon
        // that serves the real full block (to pass the anchor) can serve a stripped
        // header with block_hash copied but a FORGED creators[] -> false IN_COMMITTEE.
        // authenticated_committee recomputes compute_hash over the FULL body and
        // requires it == sr.block_hash_hex; a forged creators[] changes the hash.
        json full = rpc.call("block", {{"index", height}});
        if (!full.is_object()
            || (full.contains("error") && !full["error"].is_null())) {
            throw std::runtime_error(
                "committee-at-height: daemon refused full block "
                + std::to_string(height)
                + " (needed to authenticate creators[])");
        }
        determ::chain::Block b = determ::chain::Block::from_json(full);
        authenticated_committee(b, sr.block_hash_hex);  // throws on a forged body

        // creator_block_sigs is parallel to creators (verify_block_sigs
        // already enforced this size equality during the anchor above, but
        // re-check defensively before indexing).
        bool sigs_parallel =
            (b.creator_block_sigs.size() == b.creators.size());
        Signature zero_sig{};

        // Enumerate the committee. Each creator's pubkey is the
        // genesis-committee key (validators must be genesis members; the
        // anchor's verify_block_sigs already rejected any creator absent
        // from committee_seed). A sentinel-zero block-sig marks a BFT
        // abstention (slot signed in Phase 1 but not Phase 2).
        json members = json::array();
        for (size_t i = 0; i < b.creators.size(); ++i) {
            const std::string& dom = b.creators[i];
            std::string ed_pub;
            auto it = committee_seed.find(dom);
            if (it != committee_seed.end()) ed_pub = to_hex(it->second);
            bool abstained = sigs_parallel
                ? (b.creator_block_sigs[i] == zero_sig)
                : false;
            members.push_back({
                {"slot",      i},
                {"domain",    dom},
                {"ed_pub",    ed_pub},
                {"signed",    !abstained},
            });
        }

        // Optional membership query. creators[] is committee-attested, so a
        // membership decision over it is sound. We never emit UNVERIFIABLE
        // here on the happy path (the anchor already succeeded); the
        // tri-state exists to keep the exit-code contract uniform with the
        // verify-* family and to leave room for fail-closed callers.
        CommitteeVerdict verdict = CommitteeVerdict::UNVERIFIABLE;
        int  member_slot = -1;
        bool member_signed = false;
        if (have_member) {
            for (size_t i = 0; i < b.creators.size(); ++i) {
                if (b.creators[i] == member) {
                    verdict = CommitteeVerdict::IN_COMMITTEE;
                    member_slot = static_cast<int>(i);
                    member_signed = sigs_parallel
                        ? !(b.creator_block_sigs[i] == zero_sig)
                        : true;
                    break;
                }
            }
            if (member_slot < 0)
                verdict = CommitteeVerdict::NOT_IN_COMMITTEE;
        }

        if (json_out) {
            json out = {
                {"height",            height},
                {"block_hash",        sr.block_hash_hex},
                {"committee_size",    sr.committee_size},
                {"sigs_verified",     sr.sigs_verified},
                {"committee_verified", true},
                {"members",           members},
            };
            if (have_member) {
                out["member"]  = member;
                out["verdict"] = committee_verdict_str(verdict);
                if (verdict == CommitteeVerdict::IN_COMMITTEE) {
                    out["member_slot"]   = member_slot;
                    out["member_signed"] = member_signed;
                }
            }
            std::cout << out.dump() << "\n";
        } else {
            std::cout << "OK\n"
                      << "  genesis pin:        matches (" << genesis_hash_hex << ")\n"
                      << "  height:             " << height << "\n"
                      << "  block_hash:         " << sr.block_hash_hex << "\n"
                      << "  committee sigs:     " << sr.sigs_verified
                      << " of " << sr.committee_size << " verified\n"
                      << "  committee (" << sr.committee_size << " members, "
                         "selection order):\n";
            for (auto& m : members) {
                std::cout << "    [" << m["slot"].get<size_t>() << "] "
                          << m["domain"].get<std::string>()
                          << "  ed_pub=" << m["ed_pub"].get<std::string>()
                          << "  " << (m["signed"].get<bool>()
                                        ? "signed" : "abstained (BFT)")
                          << "\n";
            }
            if (have_member) {
                std::cout << "  member query:       " << member << " -> "
                          << committee_verdict_str(verdict) << "\n";
                if (verdict == CommitteeVerdict::IN_COMMITTEE) {
                    std::cout << "    slot:             " << member_slot << "\n"
                              << "    signed block:     "
                              << (member_signed ? "yes" : "no (BFT abstain)")
                              << "\n";
                }
            }
        }

        // Exit codes mirror the verify-* family. With --member: a sound
        // IN / NOT-IN verdict exits 0; an (unreachable on the happy path)
        // UNVERIFIABLE exits 3. Without --member the command is a pure
        // committee dump and exits 0.
        if (have_member && verdict == CommitteeVerdict::UNVERIFIABLE)
            return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "committee-at-height: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────────── decode-wire ──────────────────────────────
//
// OFFLINE decoder + structural validator for a single Determ binary wire
// envelope (A3 / S8 wire-version 1). No daemon, no RPC, no genesis — it
// reads a raw artifact (the message BODY, i.e. the bytes that ride after
// the transport layer's [u32 big-endian length] frame header) and checks
// it conforms to the published envelope spec in src/net/binary_codec.cpp +
// include/determ/net/messages.hpp.
//
// Why a SEPARATE, self-contained decoder (not a link against the daemon's
// binary_codec.cpp)? Same trust-minimization stance as the verify-*
// commands: this binary re-implements the wire spec INDEPENDENTLY from the
// published byte layout, so it is an external conformance oracle. If a
// daemon (or a future codec refactor) emits a frame that drifts from the
// documented format, this decoder flags it — it never inherits the
// producer's bug by sharing the producer's code.
//
// What it enforces (fail-closed — any deviation → MALFORMED, exit 3):
//   * Framing ceiling: body length <= kMaxFrameBytes (16 MB). The peer
//     layer drops oversized frames pre-deserialize; we mirror that bound.
//   * Envelope header (offsets 0..3): magic = 0xB1, version = 0x01,
//     reserved byte = 0x00 (the codec zeroes it on encode; we reject
//     non-zero rather than silently ignore, since a stray reserved byte
//     means the artifact was not produced by a conforming encoder).
//   * msg_type byte in the known MsgType range [0, 18].
//   * S-022 per-type body-size cap: the post-deserialize body length must
//     not exceed max_message_bytes(msg_type) (1 MB consensus chatter /
//     4 MB block-class / 16 MB snapshot+chain). Reimplemented locally from
//     the documented table so the artifact is checked against the SPEC,
//     not against whatever the producing build happened to compile.
//   * Payload well-formedness:
//       - HELLO (0): the D2 fixed binary HELLO frame — [u8 domain_len]
//         [domain][u16 LE port][u8 role][u32 LE shard_id][u8 wire_version],
//         consumed exactly (trailing bytes → MALFORMED). Pre-D2 this
//         decoder REJECTED HELLO-in-binary (HELLO was always JSON); the
//         flip is deliberate and moves lock-step with the daemon codec.
//       - TRANSACTION: the 4×256-bit fixed frame + trailer parses cleanly,
//         reserved amount-block slot is zero, lengths are consistent, the
//         trailer's length-prefixed from/to/sig/hash fit exactly, and an
//         optional trailing [u32 LE len][bytes] pq_auth section (§3.21)
//         consumes the remainder exactly when present.
//       - GET_CHAIN (5) / STATUS_REQUEST (7) / STATUS_RESPONSE (8) /
//         SNAPSHOT_REQUEST (15) / HEADERS_REQUEST (17): the D2-inc6a fixed
//         request/status frames — exact byte lengths (10 / 0 / 9..73 / 4 /
//         12), and STATUS_RESPONSE's genesis_len must be 0 (empty chain) or
//         64 (hex of a 32-byte hash) and must consume the frame exactly.
//       - BLOCK_SIG (3) / ABORT_CLAIM (9) / ABORT_EVENT (10) /
//         EQUIVOCATION_EVIDENCE (11): the D2-inc6b fixed consensus-chatter
//         frames — every length-prefixed string and fixed slot must fit and
//         the frame must be consumed exactly; ABORT_CLAIM must carry
//         EXACTLY one claim in the shared claim-list blob.
//       - HEADERS_RESPONSE (18): the D2-inc7c header page — [from u64 LE]
//         [height u64 LE][count u16 LE] then count x DHF1 records
//         ([magic 'DHF1'][block_hash 32][frame_len u32 LE][Block frame]);
//         count <= 256 (kHeadersPageMax) and proven against the remaining
//         bytes before the walk; every record's Block frame must carry the
//         four heavy collections (transactions / cross_shard_receipts /
//         inbound_receipts / initial_state) EMPTY; consumed exactly.
//       - SNAPSHOT_RESPONSE (16): the D2-inc7c DSN1 snapshot record
//         (Chain::encode_state) — magic 'DSN1', version u32 = 1, the fixed
//         194-byte scalar block, 16 counted sections each proven against
//         the remaining bytes before it is walked, the <= 256 tail-header
//         cap, exact consumption. Walked structurally; the daemon's decoder
//         additionally checks the head_hash / block_index / state_root
//         claims, which need chain state a pure-bytes mirror has no business
//         recomputing.
//       There is no other payload shape: the pre-inc7c
//       [u32 LE json_len][json_bytes] fallback is deleted, so an lp-JSON
//       body under ANY type is MALFORMED.
//
// A clean artifact → VALID (exit 0) and a one-line (or --json) report of
// the decoded type + sizes (+ tx scalar fields for TRANSACTION). A spec
// violation → MALFORMED (exit 3). An I/O / usage error → exit 1. The
// tri-state mirrors verify-tx-inclusion's verdict discipline: exit 3 is
// reserved for "the artifact is structurally unsound", never conflated
// with a usage error.

namespace {

// Local copy of the wire constants from include/determ/net/messages.hpp +
// src/net/binary_codec.cpp. Duplicated ON PURPOSE: this decoder validates
// an artifact against the PUBLISHED spec, so it must not depend on the
// daemon's compiled values (that would defeat the cross-check). If the spec
// ever changes, this table must be updated in lock-step with the codec —
// tools/test_light_decode_wire.sh pins the magic/version/caps so drift is
// caught in CI.
constexpr uint8_t  kWireBinaryMagic    = 0xB1;
constexpr uint8_t  kWireBinaryVersion  = 0x01;
constexpr size_t   kWireMaxFrameBytes  = 16ull * 1024 * 1024;   // kMaxFrameBytes
constexpr uint8_t  kWireMsgTypeMax     = 18;                    // HEADERS_RESPONSE

// max_message_bytes(MsgType) — mirrors include/determ/net/messages.hpp.
size_t wire_max_message_bytes(uint8_t t) {
    switch (t) {
        case 16: // SNAPSHOT_RESPONSE
        case 6:  // CHAIN_RESPONSE
            return 16ull * 1024 * 1024;
        case 1:  // BLOCK
        case 12: // BEACON_HEADER
        case 13: // SHARD_TIP
        case 14: // CROSS_SHARD_RECEIPT_BUNDLE
        case 18: // HEADERS_RESPONSE
            return 4ull * 1024 * 1024;
        default:
            return 1ull * 1024 * 1024;
    }
}

// MsgType name for the report. Only reached for t in [0, kWireMsgTypeMax]
// (the dispatcher rejects out-of-range types as MALFORMED first); the
// default branch returns "" and is effectively unreachable.
const char* wire_msgtype_name(uint8_t t) {
    switch (t) {
        case 0:  return "HELLO";
        case 1:  return "BLOCK";
        case 2:  return "TRANSACTION";
        case 3:  return "BLOCK_SIG";
        case 4:  return "CONTRIB";
        case 5:  return "GET_CHAIN";
        case 6:  return "CHAIN_RESPONSE";
        case 7:  return "STATUS_REQUEST";
        case 8:  return "STATUS_RESPONSE";
        case 9:  return "ABORT_CLAIM";
        case 10: return "ABORT_EVENT";
        case 11: return "EQUIVOCATION_EVIDENCE";
        case 12: return "BEACON_HEADER";
        case 13: return "SHARD_TIP";
        case 14: return "CROSS_SHARD_RECEIPT_BUNDLE";
        case 15: return "SNAPSHOT_REQUEST";
        case 16: return "SNAPSHOT_RESPONSE";
        case 17: return "HEADERS_REQUEST";
        case 18: return "HEADERS_RESPONSE";
        default: return "";
    }
}

inline uint16_t wire_le_u16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}
inline uint32_t wire_le_u32(const uint8_t* p) {
    return  static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) <<  8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}
inline uint64_t wire_le_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (i * 8);
    return v;
}

// Thrown for a structural spec violation → MALFORMED (exit 3). Distinct
// from a plain std::runtime_error (usage / I/O) which maps to exit 1.
struct WireMalformed : std::runtime_error {
    explicit WireMalformed(const std::string& m) : std::runtime_error(m) {}
};

// Read an entire file as raw bytes. Throws std::runtime_error on I/O error
// (exit 1) — a missing/unreadable file is a usage problem, not a malformed
// artifact.
std::vector<uint8_t> read_binary_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open: " + path);
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());
    if (f.bad()) throw std::runtime_error("read error: " + path);
    return buf;
}

// Validate + decode the TRANSACTION payload (body = bytes AFTER the 4-byte
// envelope header). Mirrors decode_tx_frame in src/net/binary_codec.cpp:
//   offset 0..127  : 4×256-bit fixed frame
//     32..39 amount, 40..47 fee, 48..55 nonce, 56..63 reserved (==0)
//     96..127 payload slot (first 32 bytes of payload)
//   128            : type (u8)
//   129..130       : payload_len (u16 LE)
//   131..          : payload_overflow (payload_len-32 bytes, iff > 32)
//   then           : [u8 from_len][from][u8 to_len][to][64 sig][32 hash]
// Populates `report` with the decoded scalar fields. Any inconsistency →
// WireMalformed.
void decode_wire_tx(const uint8_t* body, size_t blen, json& report) {
    if (blen < 128 + 1 + 2)
        throw WireMalformed("TRANSACTION frame too short (need >= 131 bytes, "
                            "got " + std::to_string(blen) + ")");

    uint64_t amount   = wire_le_u64(body + 32);
    uint64_t fee      = wire_le_u64(body + 40);
    uint64_t nonce    = wire_le_u64(body + 48);
    uint64_t reserved = wire_le_u64(body + 56);
    if (reserved != 0)
        throw WireMalformed("TRANSACTION amount-block reserved slot non-zero");

    size_t off = 128;
    uint8_t  type        = body[off++];
    uint16_t payload_len = wire_le_u16(body + off); off += 2;

    std::vector<uint8_t> payload;
    if (payload_len <= 32) {
        payload.assign(body + 96, body + 96 + payload_len);
    } else {
        size_t overflow = static_cast<size_t>(payload_len) - 32;
        if (off + overflow > blen)
            throw WireMalformed("TRANSACTION truncated payload overflow "
                                "(declared payload_len=" +
                                std::to_string(payload_len) + ")");
        payload.reserve(payload_len);
        payload.insert(payload.end(), body + 96, body + 128);
        payload.insert(payload.end(), body + off, body + off + overflow);
        off += overflow;
    }

    // Length-prefixed from/to.
    auto take_lp = [&](const char* what) -> std::string {
        if (off + 1 > blen)
            throw WireMalformed(std::string("TRANSACTION truncated ") + what +
                                " length prefix");
        uint8_t n = body[off++];
        if (off + n > blen)
            throw WireMalformed(std::string("TRANSACTION truncated ") + what +
                                " body (declared " + std::to_string(n) + ")");
        std::string s(reinterpret_cast<const char*>(body + off), n);
        off += n;
        return s;
    };
    std::string from = take_lp("from");
    std::string to   = take_lp("to");

    if (off + 64 + 32 > blen)
        throw WireMalformed("TRANSACTION truncated sig/hash (need 96 trailer "
                            "bytes, have " + std::to_string(blen - off) + ")");
    std::string sig_hex  = to_hex(body + off, 64); off += 64;
    std::string hash_hex = to_hex(body + off, 32); off += 32;

    // §3.21 / D2-inc1 mirror: an OPTIONAL pq_auth section may follow the
    // hash — [u32 LE len][len bytes], emitted only when the tx carries a
    // DPQ1 authenticator. A frame ending at the hash is a non-PQ tx. Any
    // bytes beyond MUST form a well-formed section consuming the frame
    // EXACTLY (zero-length rejected; trailing garbage rejected) — the same
    // fail-closed rule as the daemon's decode_tx_frame.
    size_t pq_auth_len = 0;
    if (off != blen) {
        if (off + 4 > blen)
            throw WireMalformed("TRANSACTION truncated pq_auth section header");
        uint32_t pq_len = wire_le_u32(body + off); off += 4;
        if (pq_len == 0)
            throw WireMalformed("TRANSACTION empty pq_auth section "
                                "(non-canonical: encode omits the section "
                                "when pq_auth is empty)");
        if (pq_len != blen - off)
            throw WireMalformed("TRANSACTION pq_auth length mismatch "
                                "(declared " + std::to_string(pq_len) +
                                ", have " + std::to_string(blen - off) + ")");
        pq_auth_len = pq_len;
        off += pq_len;
    }

    report["amount"]      = amount;
    report["pq_auth_len"] = pq_auth_len;
    report["fee"]         = fee;
    report["nonce"]       = nonce;
    report["tx_type"]     = static_cast<unsigned>(type);
    report["payload_len"] = static_cast<unsigned>(payload_len);
    report["from"]        = from;
    report["to"]          = to;
    report["sig"]         = sig_hex;
    report["hash"]        = hash_hex;
}

// ─── Block-frame structural walker (D2-inc5 container, D2-inc7a payloads) ────
//
// A STRUCTURAL, bounds-only re-implementation of chain::Block::encode_frame's
// layout, written from the published section order in src/chain/block.cpp —
// deliberately NOT sharing code with the daemon, so a passing run is a genuine
// cross-implementation conformance check on the container that BLOCK,
// BEACON_HEADER, SHARD_TIP, CROSS_SHARD_RECEIPT_BUNDLE and CHAIN_RESPONSE all
// carry.
//
// It validates only what a second implementation can validate without the
// chain layer: fixed field widths, u16 counts BACKED by the bytes that remain
// (checked before any loop), length-prefix consistency, section ORDER, the
// witness leaf/depth rule, and exact consumption. No semantic checks —
// signatures, hashes and state are the daemon's business.
//
// Nested transaction frames and ShardTipRecord blobs are length-delimited, so
// they are skipped by their prefix rather than re-parsed here (decode-wire
// already owns an independent TRANSACTION walker for the top-level type).
[[noreturn]] void bfw_bad(const std::string& who, const std::string& what) {
    throw WireMalformed(who + " block frame: " + what);
}

void bfw_need(size_t off, size_t n, size_t len, const std::string& who,
              const char* what) {
    if (n > len || off > len - n)
        bfw_bad(who, std::string("truncated ") + what);
}

void bfw_skip(const uint8_t*, size_t len, size_t& off, size_t n,
              const std::string& who, const char* what) {
    bfw_need(off, n, len, who, what);
    off += n;
}

// Read a u16 count and PROVE the remaining bytes could back it, BEFORE the
// loop — mirrors bf_get_count's Layer-1 cap.
uint16_t bfw_count(const uint8_t* p, size_t len, size_t& off, size_t min_elem,
                   const std::string& who, const char* what) {
    bfw_need(off, 2, len, who, what);
    uint16_t n = wire_le_u16(p + off);
    off += 2;
    if (min_elem != 0 && static_cast<size_t>(n) > (len - off) / min_elem)
        bfw_bad(who, std::string(what) + " declares " + std::to_string(n) +
                     " elements but only " + std::to_string(len - off) +
                     " bytes remain");
    return n;
}

void bfw_lp(const uint8_t* p, size_t len, size_t& off, const std::string& who,
            const char* what) {
    bfw_need(off, 1, len, who, what);
    uint8_t n = p[off++];
    bfw_need(off, n, len, who, what);
    off += n;
}

void bfw_hash_vec(const uint8_t* p, size_t len, size_t& off,
                  const std::string& who, const char* what) {
    uint16_t n = bfw_count(p, len, off, 32, who, what);
    bfw_skip(p, len, off, static_cast<size_t>(n) * 32, who, what);
}

// [u16 outer][outer x [u16 inner][inner x 32]] — the inner count's own two
// bytes are the outer element minimum.
void bfw_hash_lists(const uint8_t* p, size_t len, size_t& off,
                    const std::string& who, const char* what) {
    uint16_t n = bfw_count(p, len, off, 2, who, what);
    for (uint16_t i = 0; i < n; ++i) {
        uint16_t m = bfw_count(p, len, off, 32, who, what);
        bfw_skip(p, len, off, static_cast<size_t>(m) * 32, who, what);
    }
}

void bfw_receipts(const uint8_t* p, size_t len, size_t& off,
                  const std::string& who, const char* what) {
    // [u32 src][u32 dst][u64 idx][32][32][lp from][lp to][u64][u64][u64]
    uint16_t n = bfw_count(p, len, off, 4 + 4 + 8 + 32 + 32 + 1 + 1 + 8 + 8 + 8,
                           who, what);
    for (uint16_t i = 0; i < n; ++i) {
        bfw_skip(p, len, off, 4 + 4 + 8 + 32 + 32, who, what);
        bfw_lp(p, len, off, who, what);
        bfw_lp(p, len, off, who, what);
        bfw_skip(p, len, off, 8 + 8 + 8, who, what);
    }
}

// The smallest possible frame: every fixed field at its width plus the 23
// two-byte counts, all empty (independently derived here: 251 + 46).
constexpr size_t kWireMinBlockFrame = 297;

// Walk one Block frame occupying [off, off+len) of `p`. `allow_witnesses`
// false = the LEAF rule a shard-tip witness (and a SHARD_TIP tip) must obey:
// no folded records, no nested witnesses. Bounds decode depth at 2.
// `header_only` = the D2-inc7c HEADERS_RESPONSE rule: the top-level frame is
// a header (Node::rpc_headers strips the four heavy collections), so a record
// carrying ANY of them is a second encoding of the same header and is
// MALFORMED. It applies to the top level only — a folded beacon header's
// witnesses are full source tips and legitimately carry transactions.
void bfw_walk(const uint8_t* p, size_t len, size_t& off, bool allow_witnesses,
              const std::string& who, json* report, bool header_only = false) {
    const size_t start = off;
    bfw_need(off, 8 + 32 + 8, len, who, "index/prev_hash/timestamp");
    uint64_t index = wire_le_u64(p + off); off += 8;
    off += 32;
    uint64_t ts = wire_le_u64(p + off); off += 8;

    {   // transactions: [u32 frame_len][frame]; a tx frame is >= 131 bytes
        uint16_t n = bfw_count(p, len, off, 4 + 131, who, "transactions");
        if (header_only && n != 0)
            bfw_bad(who, "header frame carries a stripped collection "
                         "(transactions must be empty)");
        for (uint16_t i = 0; i < n; ++i) {
            bfw_need(off, 4, len, who, "transaction frame length");
            uint32_t flen = wire_le_u32(p + off); off += 4;
            bfw_skip(p, len, off, flen, who, "transaction frame body");
        }
        if (report) (*report)["block_transactions"] = n;
    }
    {   // creators: u8-length-prefixed strings
        uint16_t n = bfw_count(p, len, off, 1, who, "creators");
        for (uint16_t i = 0; i < n; ++i) bfw_lp(p, len, off, who, "creators");
        if (report) (*report)["block_creators"] = n;
    }
    bfw_hash_lists(p, len, off, who, "creator_tx_lists");
    {   // creator_ed_sigs: u16 x 64
        uint16_t n = bfw_count(p, len, off, 64, who, "creator_ed_sigs");
        bfw_skip(p, len, off, static_cast<size_t>(n) * 64, who, "creator_ed_sigs");
    }
    bfw_hash_vec(p, len, off, who, "creator_dh_inputs");
    bfw_hash_vec(p, len, off, who, "creator_view_eq_roots");
    bfw_hash_vec(p, len, off, who, "creator_view_abort_roots");
    bfw_hash_vec(p, len, off, who, "creator_view_inbound_roots");
    bfw_hash_lists(p, len, off, who, "creator_view_inbound_lists");
    bfw_hash_lists(p, len, off, who, "creator_view_eq_lists");
    bfw_hash_lists(p, len, off, who, "creator_view_abort_lists");
    bfw_hash_vec(p, len, off, who, "creator_view_shardtip_roots");
    bfw_hash_lists(p, len, off, who, "creator_view_shardtip_lists");
    {   // creator_proposer_times: u16 x 8
        uint16_t n = bfw_count(p, len, off, 8, who, "creator_proposer_times");
        bfw_skip(p, len, off, static_cast<size_t>(n) * 8, who, "creator_proposer_times");
    }
    bfw_hash_vec(p, len, off, who, "creator_dh_secrets");
    bfw_skip(p, len, off, 32 + 32 + 32, who, "tx_root/delay_seed/delay_output");
    bfw_skip(p, len, off, 1, who, "consensus_mode");
    bfw_lp(p, len, off, who, "bft_proposer");
    {   // creator_block_sigs: u16 x 64
        uint16_t n = bfw_count(p, len, off, 64, who, "creator_block_sigs");
        bfw_skip(p, len, off, static_cast<size_t>(n) * 64, who, "creator_block_sigs");
    }
    bfw_skip(p, len, off, 32, who, "cumulative_rand");
    {   // abort_events: [u8 round][lp node][u64 ts][32 hash][u32 blob_len][blob]
        uint16_t n = bfw_count(p, len, off, 1 + 1 + 8 + 32 + 4, who, "abort_events");
        for (uint16_t i = 0; i < n; ++i) {
            bfw_skip(p, len, off, 1, who, "abort_events.round");
            bfw_lp(p, len, off, who, "abort_events.aborting_node");
            bfw_skip(p, len, off, 8 + 32, who, "abort_events.timestamp/event_hash");
            bfw_need(off, 4, len, who, "abort_events claims length");
            uint32_t blen = wire_le_u32(p + off); off += 4;
            bfw_skip(p, len, off, blen, who, "abort_events claims blob");
        }
    }
    {   // equivocation_events
        uint16_t n = bfw_count(p, len, off,
                               1 + 8 + 1 + (8 + 32 + 64) * 2 + 4 + 8, who,
                               "equivocation_events");
        for (uint16_t i = 0; i < n; ++i) {
            bfw_lp(p, len, off, who, "equivocation_events.equivocator");
            bfw_skip(p, len, off, 8 + 1 + (8 + 32 + 64) * 2 + 4 + 8, who,
                     "equivocation_events fields");
        }
    }
    {   // The two receipt lists: a header carries both EMPTY.
        size_t before = off;
        bfw_receipts(p, len, off, who, "cross_shard_receipts");
        if (header_only && off != before + 2)
            bfw_bad(who, "header frame carries a stripped collection "
                         "(cross_shard_receipts must be empty)");
        before = off;
        bfw_receipts(p, len, off, who, "inbound_receipts");
        if (header_only && off != before + 2)
            bfw_bad(who, "header frame carries a stripped collection "
                         "(inbound_receipts must be empty)");
    }
    {   // initial_state: [lp domain][32 ed_pub][u64][u64][lp region]
        uint16_t n = bfw_count(p, len, off, 1 + 32 + 8 + 8 + 1, who, "initial_state");
        if (header_only && n != 0)
            bfw_bad(who, "header frame carries a stripped collection "
                         "(initial_state must be empty)");
        for (uint16_t i = 0; i < n; ++i) {
            bfw_lp(p, len, off, who, "initial_state.domain");
            bfw_skip(p, len, off, 32 + 8 + 8, who, "initial_state fields");
            bfw_lp(p, len, off, who, "initial_state.region");
        }
    }
    bfw_skip(p, len, off, 32 + 32, who, "state_root/partner_subset_hash");
    bfw_skip(p, len, off, 1, who, "signature_form");
    bfw_skip(p, len, off, 4 + 4, who, "eligible_count/source_shard_id");
    {   // shard_tip_records: [u8 rlen][record]
        uint16_t n = bfw_count(p, len, off, 1 + 49, who, "shard_tip_records");
        // A witness — and a SHARD_TIP tip — is a LEAF: it carries no folded
        // records. Checked BEFORE the records are walked, exactly as the
        // daemon's decoder does it.
        if (!allow_witnesses && n != 0)
            bfw_bad(who, "shard_tip_witnesses: a witness must carry empty "
                         "shard_tip_records");
        for (uint16_t i = 0; i < n; ++i) {
            bfw_need(off, 1, len, who, "shard_tip_records length");
            uint8_t rlen = p[off++];
            bfw_skip(p, len, off, rlen, who, "shard_tip_records body");
        }
        if (report) (*report)["block_shard_tip_records"] = n;
    }
    {   // shard_tip_witnesses: [u32 frame_len][frame], each a LEAF
        uint16_t n = bfw_count(p, len, off, 4 + kWireMinBlockFrame, who,
                               "shard_tip_witnesses");
        if (!allow_witnesses && n != 0)
            bfw_bad(who, "shard_tip_witnesses: a witness must be a leaf block "
                         "(no nested witnesses)");
        for (uint16_t i = 0; i < n; ++i) {
            bfw_need(off, 4, len, who, "shard_tip_witnesses frame length");
            uint32_t flen = wire_le_u32(p + off); off += 4;
            bfw_need(off, flen, len, who, "shard_tip_witnesses frame body");
            size_t woff = off;
            bfw_walk(p, off + flen, woff, /*allow_witnesses=*/false, who, nullptr);
            if (woff != off + flen)
                bfw_bad(who, "shard_tip_witnesses frame has " +
                             std::to_string(off + flen - woff) +
                             " unconsumed byte(s)");
            off += flen;
        }
        if (report) (*report)["block_shard_tip_witnesses"] = n;
    }
    if (report) {
        (*report)["block_index"]      = index;
        (*report)["block_timestamp"]  = ts;
        (*report)["block_frame_len"]  = off - start;
    }
}

// ── D2-inc7c: HEADERS_RESPONSE page walker ──────────────────────────────────
// [from u64][height u64][count u16] then count x DHF1 records, each
// [magic 'DHF1'][block_hash 32][frame_len u32][Block frame] — mirrors
// src/net/binary_codec.cpp decode_headers_response_frame: the page cap and
// the byte-budget proof both run BEFORE any record is walked.
constexpr uint32_t kWireHeadersPageMax     = 256;                       // kHeadersPageMax
constexpr size_t   kWireMinHeaderRecord    = 4 + 32 + 4 + kWireMinBlockFrame;   // 337

void hpw_walk(const uint8_t* body, size_t body_len, const std::string& who,
              json& report) {
    size_t off = 0;
    if (body_len < 8 + 8 + 2)
        throw WireMalformed(who + " truncated (need from u64 + height u64 + "
                            "count u16)");
    report["from"]   = wire_le_u64(body + off); off += 8;
    report["height"] = wire_le_u64(body + off); off += 8;
    uint16_t n = wire_le_u16(body + off); off += 2;
    if (n > kWireHeadersPageMax)
        throw WireMalformed(who + " declares " + std::to_string(n) +
                            " headers, above kHeadersPageMax " +
                            std::to_string(kWireHeadersPageMax));
    if (static_cast<size_t>(n) > (body_len - off) / kWireMinHeaderRecord)
        throw WireMalformed(who + " headers declares " + std::to_string(n) +
                            " elements but only " +
                            std::to_string(body_len - off) + " bytes remain");
    report["headers"] = n;
    for (uint16_t i = 0; i < n; ++i) {
        bfw_need(off, 4, body_len, who, "header record magic");
        if (std::memcmp(body + off, "DHF1", 4) != 0)
            throw WireMalformed(who + " bad header frame magic (expected DHF1)");
        off += 4;
        bfw_skip(body, body_len, off, 32, who, "header block_hash");
        bfw_need(off, 4, body_len, who, "header frame length");
        uint32_t flen = wire_le_u32(body + off); off += 4;
        if (flen > body_len || off > body_len - flen)
            throw WireMalformed(who + " truncated header frame body");
        size_t hoff = off;
        bfw_walk(body, off + flen, hoff, /*allow_witnesses=*/true, who, nullptr,
                 /*header_only=*/true);
        if (hoff != off + flen)
            throw WireMalformed(who + " header frame has " +
                                std::to_string(off + flen - hoff) +
                                " unconsumed byte(s)");
        off += flen;
    }
    if (off != body_len)
        throw WireMalformed(who + " has " + std::to_string(body_len - off) +
                            " trailing byte(s) after the last header");
}

// ── D2-inc7c: DSN1 snapshot record walker ───────────────────────────────────
// Re-implemented from the published layout (src/chain/chain.cpp, "DSN1: the
// canonical binary snapshot container"): magic, version u32 = 1, the fixed
// 194-byte scalar block, then 16 counted sections. Every count is proven
// against the remaining bytes with the section's smallest entry BEFORE the
// section is walked (the SnRd::count discipline), the tail-header count is
// capped at 256, and the record must be consumed exactly.
constexpr uint32_t kWireSnapshotHeaderMax = 256;                        // Chain::kSnapshotHeaderMax

void snw_walk(const uint8_t* p, size_t len, const std::string& who, json& report) {
    size_t off = 0;
    auto need = [&](size_t n, const char* what) {
        if (n > len || off > len - n)
            throw WireMalformed(who + " truncated at " + what);
    };
    auto u8  = [&](const char* w) { need(1, w); return p[off++]; };
    auto u16 = [&](const char* w) { need(2, w); uint16_t v = wire_le_u16(p + off); off += 2; return v; };
    auto u32 = [&](const char* w) { need(4, w); uint32_t v = wire_le_u32(p + off); off += 4; return v; };
    auto u64 = [&](const char* w) { need(8, w); uint64_t v = wire_le_u64(p + off); off += 8; return v; };
    auto raw = [&](size_t n, const char* w) { need(n, w); off += n; };
    auto lp16 = [&](const char* w) { uint16_t L = u16(w); raw(L, w); };
    auto lp8  = [&](const char* w) { uint8_t  L = u8(w);  raw(L, w); };
    auto count = [&](const char* w, size_t min_entry) {
        uint32_t k = u32(w);
        if (min_entry > 0 && static_cast<uint64_t>(k) * min_entry > (len - off))
            throw WireMalformed(who + " " + w + " count " + std::to_string(k) +
                                " exceeds remaining bytes");
        return k;
    };

    need(8, "magic/version");
    if (std::memcmp(p, "DSN1", 4) != 0)
        throw WireMalformed(who + " bad magic (expected DSN1)");
    off = 4;
    uint32_t version = u32("version");
    if (version != 1)
        throw WireMalformed(who + " unsupported snapshot version " +
                            std::to_string(version));
    report["block_index"] = u64("block_index");
    raw(32, "head_hash");
    raw(8 + 8 + 1 + 4, "block_subsidy/subsidy_pool_initial/subsidy_mode/lottery");
    raw(8, "min_stake");
    { uint8_t cp = u8("crypto_profile");
      if (cp > 1) throw WireMalformed(who + " unknown crypto_profile " + std::to_string(cp)); }
    raw(8 + 8, "suspension_slash/unstake_delay");
    raw(4 + 4 + 4, "merge thresholds");
    raw(4 + 4 + 4 + 4, "epoch_blocks/k_block_sigs/shard_count/shard_id");
    raw(32, "shard_salt");
    raw(8 * 6, "A1 counters");

    uint32_t n;
    n = count("accounts", 2 + 16);
    report["accounts"] = n;
    for (uint32_t i = 0; i < n; ++i) { lp16("account.domain"); raw(16, "account fields"); }
    n = count("stakes", 2 + 16);
    report["stakes"] = n;
    for (uint32_t i = 0; i < n; ++i) { lp16("stake.domain"); raw(16, "stake fields"); }
    n = count("registrants", 2 + 32 + 24 + 1);
    report["registrants"] = n;
    for (uint32_t i = 0; i < n; ++i) { lp16("registrant.domain"); raw(32 + 24, "registrant fields"); lp8("registrant.region"); }
    n = count("applied_inbound_receipts", 36);
    for (uint32_t i = 0; i < n; ++i) raw(36, "applied receipt");
    n = count("merge_state", 9);
    for (uint32_t i = 0; i < n; ++i) { raw(8, "merge_state ids"); lp8("merge_state.refugee_region"); }
    n = count("shard_tip_records", 49);
    for (uint32_t i = 0; i < n; ++i) { raw(16, "shard_tip fields"); lp8("shard_tip.region"); raw(32, "shard_tip.committee_sig_root"); }
    n = count("committee_checkpoints", 44);
    for (uint32_t i = 0; i < n; ++i) {
        raw(8 + 32, "checkpoint epoch/rand");
        uint32_t m = count("checkpoint.members", 35);
        for (uint32_t k = 0; k < m; ++k) { lp16("member.domain"); raw(32, "member.ed_pub"); lp8("member.region"); }
    }
    n = count("abort_records", 18);
    for (uint32_t i = 0; i < n; ++i) { lp16("abort_record.domain"); raw(16, "abort_record fields"); }
    n = count("dapp_registry", 61);
    for (uint32_t i = 0; i < n; ++i) {
        lp16("dapp.domain"); raw(32, "dapp.service_pubkey"); lp16("dapp.endpoint_url");
        uint16_t t = u16("dapp.topics.count");
        for (uint16_t k = 0; k < t; ++k) lp16("dapp.topic");
        raw(1, "dapp.retention"); lp16("dapp.metadata"); raw(24, "dapp heights");
    }
    n = count("pending_param_changes", 10);
    for (uint32_t i = 0; i < n; ++i) {
        raw(8, "param_change.effective_height");
        uint16_t e = u16("param_change.entries.count");
        for (uint16_t k = 0; k < e; ++k) { lp16("param_change.name"); lp16("param_change.value"); }
    }
    n = count("shielded_pool", 41);
    for (uint32_t i = 0; i < n; ++i) raw(41, "shielded_pool entry");
    n = count("enote_commitments", 65);
    for (uint32_t i = 0; i < n; ++i) raw(65, "enote entry");
    n = count("audit_keys", 4);
    for (uint32_t i = 0; i < n; ++i) { lp16("audit_key.addr"); lp16("audit_key.pk"); }
    n = count("audit_log_counts", 10);
    for (uint32_t i = 0; i < n; ++i) { lp16("audit_log_count.addr"); raw(8, "audit_log_count.n"); }
    n = count("note_keys", 4);
    for (uint32_t i = 0; i < n; ++i) { lp16("note_key.addr"); lp16("note_key.pk"); }
    n = count("headers", 4);
    if (n > kWireSnapshotHeaderMax)
        throw WireMalformed(who + " headers count " + std::to_string(n) +
                            " exceeds the tail-header cap " +
                            std::to_string(kWireSnapshotHeaderMax));
    report["headers"] = n;
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t flen = u32("header.frame_len");
        need(flen, "header.frame");
        size_t hoff = off;
        bfw_walk(p, off + flen, hoff, /*allow_witnesses=*/true, who, nullptr);
        if (hoff != off + flen)
            throw WireMalformed(who + " tail header frame has " +
                                std::to_string(off + flen - hoff) +
                                " unconsumed byte(s)");
        off += flen;
    }
    if (off != len)
        throw WireMalformed(who + " has " + std::to_string(len - off) +
                            " trailing byte(s) after the DSN1 record");
}

} // namespace

int cmd_decode_wire(int argc, char** argv) {
    std::string in_path;
    bool json_out = false;
    bool require_type_set = false;
    std::string require_type;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--in"   && i + 1 < argc) in_path = argv[++i];
        else if (a == "--json")                 json_out = true;
        else if (a == "--expect-type" && i + 1 < argc) {
            require_type = argv[++i]; require_type_set = true;
        } else {
            std::cerr << "decode-wire: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (in_path.empty()) {
        std::cerr << "decode-wire: --in <file> is required\n";
        return 1;
    }

    // VERDICT discipline (mirrors verify-tx-inclusion):
    //   VALID     → exit 0 (artifact conforms to the binary wire spec).
    //   MALFORMED → exit 3 (structural spec violation; fail-closed).
    //   I/O / usage error → exit 1.
    try {
        std::vector<uint8_t> buf = read_binary_file(in_path);
        json report;
        report["file"]      = in_path;
        report["byte_len"]  = buf.size();

        try {
            // Framing ceiling (S-022 kMaxFrameBytes).
            if (buf.size() > kWireMaxFrameBytes)
                throw WireMalformed("frame exceeds 16 MB ceiling (" +
                                    std::to_string(buf.size()) + " bytes)");

            // Envelope header (offsets 0..3).
            if (buf.size() < 4)
                throw WireMalformed("body shorter than 4-byte envelope header");
            if (buf[0] != kWireBinaryMagic)
                throw WireMalformed("bad magic byte (got 0x" +
                                    to_hex(buf.data(), 1) +
                                    ", want 0xb1) — not a binary envelope "
                                    "(the wire is binary-only; the legacy "
                                    "0x7b JSON envelope was deleted by D2)");
            if (buf[1] != kWireBinaryVersion)
                throw WireMalformed("unsupported binary version 0x" +
                                    to_hex(buf.data() + 1, 1) + " (want 0x01)");
            if (buf[3] != 0x00)
                throw WireMalformed("reserved envelope byte non-zero (0x" +
                                    to_hex(buf.data() + 3, 1) + ")");

            uint8_t msg_type = buf[2];
            if (msg_type > kWireMsgTypeMax)
                throw WireMalformed("msg_type " + std::to_string(msg_type) +
                                    " out of known range [0, " +
                                    std::to_string(kWireMsgTypeMax) + "]");

            const char* tname = wire_msgtype_name(msg_type);
            report["msg_type"]      = static_cast<unsigned>(msg_type);
            report["msg_type_name"] = tname;

            // S-022 per-type body-size cap. The "body" is everything after
            // the 4-byte envelope header.
            size_t body_len = buf.size() - 4;
            size_t cap      = wire_max_message_bytes(msg_type);
            report["body_len"]  = body_len;
            report["type_cap"]  = cap;
            if (buf.size() > cap)
                throw WireMalformed(std::string(tname) + " frame (" +
                                    std::to_string(buf.size()) +
                                    " bytes) exceeds its S-022 cap (" +
                                    std::to_string(cap) + " bytes)");

            const uint8_t* body = buf.data() + 4;
            if (msg_type == 0 /* HELLO */) {
                // D2 fixed binary HELLO frame — validated independently
                // against the published layout, consumed exactly.
                report["payload_kind"] = "hello_frame";
                size_t off = 0;
                if (body_len < 1)
                    throw WireMalformed("HELLO truncated domain length prefix");
                uint8_t dlen = body[off++];
                if (off + dlen > body_len)
                    throw WireMalformed("HELLO truncated domain (declared " +
                                        std::to_string(dlen) + " bytes)");
                std::string domain(reinterpret_cast<const char*>(body + off),
                                   dlen);
                off += dlen;
                if (off + 2 + 1 + 4 + 1 > body_len)
                    throw WireMalformed("HELLO truncated fixed fields (need "
                                        "port/role/shard_id/wire_version)");
                uint16_t port         = wire_le_u16(body + off); off += 2;
                uint8_t  role         = body[off++];
                uint32_t shard_id     = wire_le_u32(body + off); off += 4;
                uint8_t  wire_version = body[off++];
                if (off != body_len)
                    throw WireMalformed("HELLO has " +
                                        std::to_string(body_len - off) +
                                        " trailing byte(s) after "
                                        "wire_version");
                report["domain"]       = domain;
                report["port"]         = port;
                report["role"]         = static_cast<unsigned>(role);
                report["shard_id"]     = shard_id;
                report["wire_version"] = static_cast<unsigned>(wire_version);
            } else if (msg_type == 2 /* TRANSACTION */) {
                report["payload_kind"] = "tx_frame";
                decode_wire_tx(body, body_len, report);
            } else if (msg_type == 5  /* GET_CHAIN        */ ||
                       msg_type == 7  /* STATUS_REQUEST   */ ||
                       msg_type == 8  /* STATUS_RESPONSE  */ ||
                       msg_type == 15 /* SNAPSHOT_REQUEST */ ||
                       msg_type == 17 /* HEADERS_REQUEST  */) {
                // D2-inc6a fixed request/status frames — re-implemented
                // independently from the published layout, consumed exactly.
                report["payload_kind"] = "req_frame";
                auto exact = [&](size_t want, const char* what) {
                    if (body_len != want)
                        throw WireMalformed(std::string(tname) + " frame is " +
                                            std::to_string(body_len) +
                                            " bytes, want " +
                                            std::to_string(want) + " (" +
                                            what + ")");
                };
                if (msg_type == 5) {
                    exact(10, "from u64 + count u16");
                    report["from"]  = wire_le_u64(body);
                    report["count"] = wire_le_u16(body + 8);
                } else if (msg_type == 7) {
                    exact(0, "no fields");
                } else if (msg_type == 8) {
                    if (body_len < 9)
                        throw WireMalformed("STATUS_RESPONSE truncated "
                                            "(need height u64 + genesis_len u8)");
                    uint64_t height = wire_le_u64(body);
                    uint8_t  glen   = body[8];
                    if (9 + static_cast<size_t>(glen) != body_len)
                        throw WireMalformed("STATUS_RESPONSE genesis_len=" +
                                            std::to_string(glen) +
                                            " does not consume the frame");
                    // A conforming responder emits 0 (empty chain) or 64.
                    if (glen != 0 && glen != 64)
                        throw WireMalformed("STATUS_RESPONSE genesis length "
                                            "must be 0 or 64, got " +
                                            std::to_string(glen));
                    report["height"]  = height;
                    report["genesis"] = std::string(
                        reinterpret_cast<const char*>(body + 9), glen);
                } else if (msg_type == 15) {
                    exact(4, "headers u32");
                    report["headers"] = wire_le_u32(body);
                } else {  // 17
                    exact(12, "from u64 + count u32");
                    report["from"]  = wire_le_u64(body);
                    report["count"] = wire_le_u32(body + 8);
                }
            } else if (msg_type == 3  /* BLOCK_SIG             */ ||
                       msg_type == 9  /* ABORT_CLAIM           */ ||
                       msg_type == 10 /* ABORT_EVENT           */ ||
                       msg_type == 11 /* EQUIVOCATION_EVIDENCE */) {
                // D2-inc6b fixed consensus-chatter frames — re-implemented
                // independently from the published layout, consumed exactly.
                report["payload_kind"] = "chatter_frame";
                size_t off = 0;
                auto take = [&](size_t n, const char* what) {
                    if (off + n > body_len)
                        throw WireMalformed(std::string(tname) +
                                            " truncated at " + what);
                    size_t at = off; off += n; return at;
                };
                auto take_lp = [&](const char* what) {
                    if (off + 1 > body_len)
                        throw WireMalformed(std::string(tname) +
                                            " truncated " + what + " length");
                    uint8_t n = body[off++];
                    if (off + n > body_len)
                        throw WireMalformed(std::string(tname) +
                                            " truncated " + what + " body");
                    std::string s(reinterpret_cast<const char*>(body + off), n);
                    off += n;
                    return s;
                };
                // The shared claim-list blob: [u16 count] + count x
                // [u64][u8][32][64][u8 len + s][u8 len + s]. Mirrors
                // chain::decode_abort_claims; returns the claim count.
                auto take_claims = [&]() {
                    if (off + 2 > body_len)
                        throw WireMalformed(std::string(tname) +
                                            " truncated claims count");
                    uint16_t n = wire_le_u16(body + off); off += 2;
                    for (uint16_t i = 0; i < n; ++i) {
                        take(8 + 1 + 32 + 64, "claim fixed fields");
                        take_lp("claim missing_creator");
                        take_lp("claim claimer");
                    }
                    return n;
                };
                if (msg_type == 3) {
                    report["block_index"] = wire_le_u64(body + take(8, "block_index"));
                    report["signer"]      = take_lp("signer");
                    take(32 + 32 + 64, "delay_output/dh_secret/ed_sig");
                } else if (msg_type == 9) {
                    uint16_t n = take_claims();
                    // A gossiped ABORT_CLAIM carries exactly one claim.
                    if (n != 1)
                        throw WireMalformed("ABORT_CLAIM must carry exactly one "
                                            "claim, got " + std::to_string(n));
                    report["claims"] = n;
                } else if (msg_type == 10) {
                    report["block_index"] = wire_le_u64(body + take(8, "block_index"));
                    take(32, "prev_hash");
                    take(1, "round");
                    report["aborting_node"] = take_lp("aborting_node");
                    take(8 + 32, "timestamp/event_hash");
                    report["claims"] = take_claims();
                } else {  // 11
                    report["equivocator"] = take_lp("equivocator");
                    take(8 + 32 + 64 + 32 + 64 + 4 + 8,
                         "block_index/digests/sigs/shard_id/anchor");
                }
                if (off != body_len)
                    throw WireMalformed(std::string(tname) + " has " +
                                        std::to_string(body_len - off) +
                                        " trailing byte(s)");
            } else if (msg_type == 1  /* BLOCK                      */ ||
                       msg_type == 12 /* BEACON_HEADER              */ ||
                       msg_type == 13 /* SHARD_TIP                  */ ||
                       msg_type == 14 /* CROSS_SHARD_RECEIPT_BUNDLE */ ||
                       msg_type == 6  /* CHAIN_RESPONSE             */) {
                // D2-inc7a Block-carrying payload frames — re-implemented
                // independently from the published layout, consumed exactly.
                //
                // The allow_witnesses MAP is mirrored here too, or the two
                // implementations would disagree on frame validity (the
                // S-043-class asymmetry the reserved-byte audit found):
                // SHARD_TIP's tip must be a LEAF (no folded records, no
                // witnesses) because only BEACON producers fold; every other
                // Block channel legitimately carries a folded beacon block.
                size_t off = 0;
                if (msg_type == 13 || msg_type == 14) {
                    if (body_len < 4)
                        throw WireMalformed(std::string(tname) +
                                            " truncated shard_id prefix");
                    report[msg_type == 13 ? "shard_id" : "src_shard"] =
                        wire_le_u32(body);
                    off = 4;
                }
                if (msg_type == 6) {
                    report["payload_kind"] = "chain_response_frame";
                    if (body_len < 1)
                        throw WireMalformed("CHAIN_RESPONSE truncated has_more");
                    uint8_t hm = body[off++];
                    if (hm > 1)
                        throw WireMalformed("CHAIN_RESPONSE has_more must be 0 "
                                            "or 1, got " + std::to_string(hm));
                    report["has_more"] = (hm != 0);
                    uint16_t n = bfw_count(body, body_len, off,
                                           4 + kWireMinBlockFrame,
                                           tname, "blocks");
                    report["blocks"] = n;
                    for (uint16_t i = 0; i < n; ++i) {
                        if (off + 4 > body_len)
                            throw WireMalformed("CHAIN_RESPONSE truncated block "
                                                "frame length");
                        uint32_t flen = wire_le_u32(body + off); off += 4;
                        if (flen > body_len || off > body_len - flen)
                            throw WireMalformed("CHAIN_RESPONSE truncated block "
                                                "frame body");
                        size_t boff = off;
                        bfw_walk(body, off + flen, boff,
                                 /*allow_witnesses=*/true, tname, nullptr);
                        if (boff != off + flen)
                            throw WireMalformed("CHAIN_RESPONSE block frame has "
                                                "unconsumed bytes");
                        off += flen;
                    }
                } else {
                    report["payload_kind"] = (msg_type == 13) ? "shard_tip_frame"
                                           : (msg_type == 14) ? "bundle_frame"
                                                              : "block_frame";
                    bfw_walk(body, body_len, off,
                             /*allow_witnesses=*/msg_type != 13, tname, &report);
                }
                if (off != body_len)
                    throw WireMalformed(std::string(tname) + " has " +
                                        std::to_string(body_len - off) +
                                        " trailing byte(s) after the frame");
            } else if (msg_type == 4 /* CONTRIB */) {
                // D2-inc7b CONTRIB frame — ALWAYS-PRESENT layout (every
                // to_json emit gate is value-derived, so the container carries
                // the value and never the gate).
                report["payload_kind"] = "contrib_frame";
                size_t off = 0;
                auto take = [&](size_t n, const char* what) {
                    if (n > body_len || off > body_len - n)
                        throw WireMalformed(std::string(tname) +
                                            " truncated at " + what);
                    size_t at = off; off += n; return at;
                };
                auto take_hashes = [&](const char* what) {
                    uint16_t n = bfw_count(body, body_len, off, 32, tname, what);
                    take(static_cast<size_t>(n) * 32, what);
                    return n;
                };
                report["block_index"] = wire_le_u64(body + take(8, "block_index"));
                {
                    if (off + 1 > body_len)
                        throw WireMalformed("CONTRIB truncated signer length");
                    uint8_t n = body[off++];
                    size_t at = take(n, "signer body");
                    report["signer"] =
                        std::string(reinterpret_cast<const char*>(body + at), n);
                }
                take(32, "prev_hash");
                report["aborts_gen"] = wire_le_u64(body + take(8, "aborts_gen"));
                report["tx_hashes"]  = take_hashes("tx_hashes");
                take(32 + 32 + 32 + 32, "dh_input + the three view roots");
                take_hashes("view_eq_list");
                take_hashes("view_abort_list");
                take_hashes("view_inbound_list");
                report["proposer_time"] = wire_le_u64(body + take(8, "proposer_time"));
                take(32, "view_shardtip_root");
                take_hashes("view_shardtip_list");
                take(64, "ed_sig");
                if (off != body_len)
                    throw WireMalformed(std::string(tname) + " has " +
                                        std::to_string(body_len - off) +
                                        " trailing byte(s)");
            } else if (msg_type == 18 /* HEADERS_RESPONSE */) {
                // D2-inc7c header page — re-implemented independently from
                // the published layout, consumed exactly.
                report["payload_kind"] = "header_page_frame";
                hpw_walk(body, body_len, tname, report);
            } else if (msg_type == 16 /* SNAPSHOT_RESPONSE */) {
                // D2-inc7c: the DSN1 snapshot record, walked structurally.
                report["payload_kind"] = "snapshot_frame";
                snw_walk(body, body_len, tname, report);
            } else {
                // Every type in [0, kWireMsgTypeMax] has a frame above, so
                // this is unreachable — kept total (never a silent accept).
                // The pre-inc7c [u32 json_len][json] fallback is deleted.
                throw WireMalformed(std::string(tname) +
                                    " has no payload frame decoder");
            }

            // Optional caller-supplied expectation: the decoded type must
            // equal --expect-type (name, case-insensitive). A mismatch is a
            // MALFORMED verdict — the artifact is not the message the caller
            // expected to find.
            if (require_type_set) {
                std::string want = require_type;
                std::string got  = tname;
                std::transform(want.begin(), want.end(), want.begin(),
                               [](unsigned char c){ return std::toupper(c); });
                std::transform(got.begin(),  got.end(),  got.begin(),
                               [](unsigned char c){ return std::toupper(c); });
                if (want != got)
                    throw WireMalformed("decoded type " + std::string(tname) +
                                        " != --expect-type " + require_type);
            }

            report["verdict"] = "VALID";
        } catch (const WireMalformed& e) {
            report["verdict"] = "MALFORMED";
            report["detail"]  = e.what();
            if (json_out) {
                std::cout << report.dump() << "\n";
            } else {
                std::cout << "MALFORMED\n"
                          << "  file:   " << in_path << "\n"
                          << "  bytes:  " << buf.size() << "\n"
                          << "  detail: " << e.what() << "\n";
            }
            return 3;
        }

        if (json_out) {
            std::cout << report.dump() << "\n";
        } else {
            std::cout << "VALID\n"
                      << "  file:      " << in_path << "\n"
                      << "  bytes:     " << buf.size() << "\n"
                      << "  msg_type:  " << report["msg_type"] << " ("
                      << report["msg_type_name"].get<std::string>() << ")\n"
                      << "  body_len:  " << report["body_len"] << "\n"
                      << "  type_cap:  " << report["type_cap"] << "\n";
            // Dispatch on the decoded payload kind. (Pre-D2-inc6a this was a
            // two-way tx_frame/else split, so every non-TRANSACTION frame was
            // printed as lp_json — which threw on the fixed frames, whose
            // report carries no json_len/json_type.)
            const std::string kind = report["payload_kind"].get<std::string>();
            if (kind == "tx_frame") {
                std::cout << "  payload:   tx_frame\n"
                          << "  amount:    " << report["amount"] << "\n"
                          << "  fee:       " << report["fee"] << "\n"
                          << "  nonce:     " << report["nonce"] << "\n"
                          << "  tx_type:   " << report["tx_type"] << "\n"
                          << "  from:      " << report["from"].get<std::string>() << "\n"
                          << "  to:        " << report["to"].get<std::string>() << "\n"
                          << "  hash:      " << report["hash"].get<std::string>() << "\n";
            } else {
                // Every other kind is a fixed frame (D2; the lp_json kind
                // died with the fallback in D2-inc7c).
                std::cout << "  payload:   " << kind << "\n";
                // Emit whichever decoded scalars this frame carries.
                for (const char* k : {"domain", "port", "role", "shard_id",
                                      "wire_version", "from", "count",
                                      "height", "genesis", "headers",
                                      "block_index", "signer", "aborting_node",
                                      "equivocator", "claims", "src_shard",
                                      "has_more", "blocks", "aborts_gen",
                                      "tx_hashes", "proposer_time",
                                      "block_timestamp", "block_creators",
                                      "block_transactions",
                                      "block_shard_tip_records",
                                      "block_shard_tip_witnesses",
                                      "block_frame_len", "accounts", "stakes",
                                      "registrants"}) {
                    if (!report.contains(k)) continue;
                    std::cout << "  " << k << ": ";
                    if (report[k].is_string())
                        std::cout << report[k].get<std::string>();
                    else
                        std::cout << report[k];
                    std::cout << "\n";
                }
            }
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "decode-wire: " << e.what() << "\n";
        return 1;
    }
}

// ───────────────────────────── rpc-auth ────────────────────────────────
//
// Offline computor / verifier for the S-001 (v2.16) HMAC RPC auth tag —
// the `auth` field the daemon's RpcServer::verify_auth re-derives and
// constant-time compares whenever rpc_auth_secret is configured. This
// re-implements the daemon's scheme (src/rpc/rpc.cpp::canonical_for_hmac
// + hmac_sha256_hex) INDEPENDENTLY of the daemon's codec — including a
// from-scratch RFC-2104 HMAC-SHA256 built on the shared SHA256Builder
// primitive rather than OpenSSL's HMAC() — so a passing tag is an
// external conformance check on the wire-visible auth field, not a wrapper
// around the daemon's own MAC. No socket: pure local computation.
//
// Canonical message = method + "|" + params.dump(), where params.dump() is
// nlohmann's compact form. The daemon computes the tag AFTER parsing the
// request JSON (json::parse normalizes object keys to sorted order, dump()
// re-serializes), so to agree byte-for-byte the verifier likewise parses
// the supplied params and re-dumps them. An object whose keys are supplied
// in any order therefore yields the SAME canonical tag.

namespace {

// RFC 2104 HMAC-SHA256 over (key, message). Block size B = 64 (SHA-256's
// input block). Keys longer than B are first hashed to 32 bytes; shorter
// keys are zero-padded to B. Returns the 32-byte MAC. Built on the shared
// SHA256Builder so the light binary needs no extra OpenSSL-HMAC linkage and
// the construction is auditable against the spec in one place.
Hash hmac_sha256(const std::vector<uint8_t>& key,
                 const std::string& message) {
    constexpr size_t B = 64;
    std::vector<uint8_t> k0;
    if (key.size() > B) {
        Hash kh = determ::crypto::sha256(key.data(), key.size());
        k0.assign(kh.begin(), kh.end());
    } else {
        k0 = key;
    }
    k0.resize(B, 0x00);  // zero-pad (or leave) to the block size.

    std::vector<uint8_t> ipad(B), opad(B);
    for (size_t i = 0; i < B; ++i) {
        ipad[i] = static_cast<uint8_t>(k0[i] ^ 0x36);
        opad[i] = static_cast<uint8_t>(k0[i] ^ 0x5c);
    }

    // inner = SHA256(ipad || message)
    determ::crypto::SHA256Builder ib;
    ib.append(ipad.data(), ipad.size());
    ib.append(reinterpret_cast<const uint8_t*>(message.data()), message.size());
    Hash inner = ib.finalize();

    // outer = SHA256(opad || inner)
    determ::crypto::SHA256Builder ob;
    ob.append(opad.data(), opad.size());
    ob.append(inner);
    return ob.finalize();
}

// Canonical HMAC input — identical to src/rpc/rpc.cpp::canonical_for_hmac.
std::string canonical_for_hmac(const std::string& method, const json& params) {
    return method + "|" + params.dump();
}

} // namespace

int cmd_rpc_auth(int argc, char** argv) {
    std::string secret_hex, method, params_file, params_string, expect_hex;
    bool have_params_file = false, have_params_string = false;
    bool params_stdin = false, emit_request = false, json_out = false;
    bool have_expect = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--secret"        && i + 1 < argc) secret_hex    = argv[++i];
        else if (a == "--method"        && i + 1 < argc) method        = argv[++i];
        else if (a == "--params-file"   && i + 1 < argc) { params_file   = argv[++i]; have_params_file   = true; }
        else if (a == "--params-string" && i + 1 < argc) { params_string = argv[++i]; have_params_string = true; }
        else if (a == "--params-stdin")                  params_stdin  = true;
        else if (a == "--expect"        && i + 1 < argc) { expect_hex    = argv[++i]; have_expect        = true; }
        else if (a == "--emit-request")                  emit_request  = true;
        else if (a == "--json")                          json_out      = true;
        else {
            std::cerr << "rpc-auth: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (secret_hex.empty() || method.empty()) {
        std::cerr << "rpc-auth: --secret and --method are required\n";
        return 1;
    }
    int src_count = (have_params_file ? 1 : 0)
                  + (have_params_string ? 1 : 0)
                  + (params_stdin ? 1 : 0);
    if (src_count > 1) {
        std::cerr << "rpc-auth: choose at most one of --params-file, "
                     "--params-string, --params-stdin\n";
        return 1;
    }

    // VERDICT discipline (compute mode prints the tag; verify mode mirrors
    // verify-tx-inclusion's fail-closed contract):
    //   compute → exit 0 with the tag (or request object) on stdout.
    //   verify  → MATCH exit 0 / MISMATCH exit 3 (fail-closed).
    //   usage / bad-hex / unparseable-params → exit 1.
    try {
        // Secret is HMAC key material — hex-decoded to raw bytes, exactly
        // as the server does (hex_to_bytes(rpc_auth_secret)). A non-hex
        // secret is a usage error, never a silent empty key.
        std::vector<uint8_t> key;
        try {
            key = from_hex(secret_hex);
        } catch (const std::exception&) {
            std::cerr << "rpc-auth: --secret must be valid hex (2N chars)\n";
            return 1;
        }
        if (key.empty()) {
            std::cerr << "rpc-auth: --secret decodes to an empty key "
                         "(auth would be disabled server-side)\n";
            return 1;
        }

        // Resolve params. Default to {} when no source is given — matching a
        // method whose params object is empty. Parse-then-keep so dump()
        // yields the canonical sorted-key form the server re-derives.
        json params;
        if (have_params_file) {
            params = read_json_file(params_file);
        } else if (have_params_string) {
            try {
                params = json::parse(params_string);
            } catch (const std::exception& e) {
                std::cerr << "rpc-auth: --params-string is not valid JSON: "
                          << e.what() << "\n";
                return 1;
            }
        } else if (params_stdin) {
            try {
                params = json::parse(std::cin);
            } catch (const std::exception& e) {
                std::cerr << "rpc-auth: stdin params are not valid JSON: "
                          << e.what() << "\n";
                return 1;
            }
        } else {
            params = json::object();
        }

        std::string canonical = canonical_for_hmac(method, params);
        Hash mac = hmac_sha256(key, canonical);
        std::string tag = to_hex(mac);

        if (have_expect) {
            // Verify mode. Constant-time compare against the supplied tag,
            // mirroring RpcServer::verify_auth: a length mismatch is an
            // immediate non-match, otherwise XOR-accumulate every byte with
            // no early exit so the comparison time does not leak how many
            // leading characters matched. The expected tag is compared as
            // a lowercase hex STRING (the on-wire form), so case-insensitive
            // input is normalized first.
            std::string got = expect_hex;
            std::transform(got.begin(), got.end(), got.begin(),
                           [](unsigned char c){ return std::tolower(c); });
            bool match;
            if (got.size() != tag.size()) {
                match = false;
            } else {
                int diff = 0;
                for (size_t i = 0; i < tag.size(); ++i)
                    diff |= (tag[i] ^ got[i]);
                match = (diff == 0);
            }
            if (json_out) {
                json out = {
                    {"verdict",  match ? "MATCH" : "MISMATCH"},
                    {"method",   method},
                    {"computed", tag},
                    {"expected", got},
                };
                std::cout << out.dump() << "\n";
            } else if (match) {
                std::cout << "MATCH\n"
                          << "  method: " << method << "\n"
                          << "  tag:    " << tag << "\n";
            } else {
                std::cout << "MISMATCH\n"
                          << "  method:   " << method << "\n"
                          << "  computed: " << tag << "\n"
                          << "  expected: " << got << "\n";
            }
            return match ? 0 : 3;
        }

        // Compute mode.
        if (emit_request) {
            json req = {
                {"method", method},
                {"params", params},
                {"auth",   tag},
            };
            std::cout << req.dump() << "\n";
        } else if (json_out) {
            json out = {
                {"method", method},
                {"auth",   tag},
            };
            std::cout << out.dump() << "\n";
        } else {
            std::cout << tag << "\n";
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "rpc-auth: " << e.what() << "\n";
        return 1;
    }
}

// ─────────────────────────────── audit ─────────────────────────────────
// Composite one-shot trust-minimized node audit. Runs the whole-chain
// verifiers that need only (--rpc-port, --genesis) and aggregates their
// verdicts into a single PASS/FAIL with a per-check breakdown and a
// monitor-friendly exit code (0 = all pass, 1 = any fail / error). It adds
// NO new verification logic — only orchestration over already-tested
// primitives — so its soundness is exactly the conjunction of the
// components it composes (see docs/proofs/LightClientAuditComposition.md):
//   CHAIN  — genesis pin + prev_hash continuity + per-block K-of-K committee
//            Ed25519 sigs genesis->head (verify_chain_to_head; FA1 light-
//            client safety). Also surfaces the head's state-commitment.
//   SUPPLY — trustless A1 unitary-supply conservation read against the same
//            committee-signed head (cmd_supply_trustless; SupplyProofSoundness).
// SUPPLY is attempted only when CHAIN passes (a broken chain makes any state
// read moot); on CHAIN failure SUPPLY is reported SKIP, never a false PASS.
int cmd_audit(int argc, char** argv) {
    uint16_t port = 0;
    std::string genesis_path;
    bool have_port = false, json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if   (a == "--json")                    json_out = true;
        else {
            std::cerr << "audit: unknown arg '" << a << "'\n";
            return 1;
        }
    }
    if (!have_port || genesis_path.empty()) {
        std::cerr << "audit: --rpc-port and --genesis are required\n";
        return 1;
    }

    struct CheckResult { std::string name, verdict, detail; };
    std::vector<CheckResult> checks;
    int passed = 0, failed = 0, skipped = 0;

    // ── CHAIN ── genesis pin + continuity + every block's committee sigs.
    // Direct helper call (rather than cmd_verify_chain) so the audit also
    // learns the head's state-commitment status for the report.
    std::string head_state_root;
    {
        std::string detail;
        bool ok = false;
        try {
            auto genesis = load_genesis(genesis_path);
            auto committee_seed = build_genesis_committee(genesis);
            RpcClient rpc(port);
            if (!rpc.open()) throw std::runtime_error(rpc.last_error());
            std::string gh = anchor_genesis(rpc, genesis);
            auto vc = verify_chain_to_head(rpc, committee_seed, gh, /*track_registry=*/false, genesis.k_block_sigs, genesis.bft_enabled);
            head_state_root = vc.head_state_root;
            detail = "height " + std::to_string(vc.height) + ", "
                   + std::to_string(vc.headers_verified) + " headers, "
                   + std::to_string(vc.blocks_with_sigs_verified) + " sig-sets";
            ok = true;
        } catch (const std::exception& e) {
            detail = e.what();
        }
        if (!json_out)
            std::cout << "--- CHAIN ---\n  " << (ok ? "OK: " : "FAIL: ")
                      << detail << "\n";
        checks.push_back({"CHAIN", ok ? "PASS" : "FAIL", detail});
        ok ? ++passed : ++failed;
    }

    // ── SUPPLY ── trustless A1 supply conservation against the signed head.
    // Reuses the fully-tested cmd_supply_trustless by synthesizing its argv;
    // in --json mode its human output is captured to a sink so only the
    // aggregate JSON reaches stdout.
    if (checks[0].verdict == "PASS") {
        std::vector<std::string> args = {
            "--rpc-port", std::to_string(port), "--genesis", genesis_path};
        std::vector<char*> av;
        for (auto& s : args) av.push_back(const_cast<char*>(s.c_str()));
        std::ostringstream sink;
        // RAII: restore BOTH cout and cerr streambufs even if the sub-command
        // throws. Declared AFTER `sink`, so during stack unwind this guard runs
        // first (un-redirecting the streams) and only then is `sink` destroyed
        // — never leaving a stream pointing at a freed buffer.
        struct RdbufGuard {
            std::streambuf* out_prev{nullptr};
            std::streambuf* err_prev{nullptr};
            ~RdbufGuard() {
                if (out_prev) std::cout.rdbuf(out_prev);
                if (err_prev) std::cerr.rdbuf(err_prev);
            }
        } guard;
        if (json_out) {
            // Capture the sub-command's human stdout AND stderr so only the
            // aggregate JSON reaches the operator; the failure reason is still
            // surfaced via the per-check `detail` field in the JSON.
            guard.out_prev = std::cout.rdbuf(sink.rdbuf());
            guard.err_prev = std::cerr.rdbuf(sink.rdbuf());
        } else {
            std::cout << "--- SUPPLY ---\n";
        }
        int rc = cmd_supply_trustless(static_cast<int>(av.size()), av.data());
        if (guard.out_prev) { std::cout.rdbuf(guard.out_prev); guard.out_prev = nullptr; }
        if (guard.err_prev) { std::cerr.rdbuf(guard.err_prev); guard.err_prev = nullptr; }
        checks.push_back({"SUPPLY", rc == 0 ? "PASS" : "FAIL",
                          rc == 0 ? "conserved"
                                  : "UNVERIFIABLE / mismatch (exit "
                                      + std::to_string(rc) + ")"});
        rc == 0 ? ++passed : ++failed;
    } else {
        checks.push_back({"SUPPLY", "SKIP", "CHAIN failed — not attempted"});
        ++skipped;
    }

    bool overall = (failed == 0);

    if (json_out) {
        json j;
        j["audit"]           = overall ? "PASS" : "FAIL";
        j["passed"]          = passed;
        j["failed"]          = failed;
        j["skipped"]         = skipped;
        j["head_state_root"] = head_state_root;  // "" if pre-S-033
        json arr = json::array();
        for (auto& c : checks)
            arr.push_back({{"check", c.name},
                           {"verdict", c.verdict},
                           {"detail", c.detail}});
        j["checks"] = arr;
        std::cout << j.dump(2) << "\n";
    } else {
        std::cout << "\n=== AUDIT SUMMARY ===\n";
        for (auto& c : checks) {
            std::string pad(c.name.size() < 8 ? 8 - c.name.size() : 1, ' ');
            std::cout << "  " << c.name << pad << c.verdict
                      << (c.detail.empty() ? std::string()
                                           : "  (" + c.detail + ")")
                      << "\n";
        }
        std::cout << "  head state_root: "
                  << (head_state_root.empty() ? "(pre-S-033 / not populated)"
                                              : head_state_root)
                  << "\n";
        std::cout << "\nAUDIT: " << (overall ? "PASS" : "FAIL")
                  << " (" << passed << " passed, " << failed << " failed, "
                  << skipped << " skipped)\n";
    }
    return overall ? 0 : 1;
}

// selftest-readline-cap — offline, NO daemon: drive read_line_capped (the
// testable core of RpcClient::read_line) with a synthetic byte source to prove
// the LRPC-1 hostile-peer cap. A MITM/malicious daemon can stream an endless
// newline-less body; without the cap, read_line grows its buffer toward OOM.
// CTRL cases prove the cap does NOT disturb normal reads; the NEG case proves
// an endless stream is aborted at the 16 MiB cap with bounded memory.
int cmd_selftest_readline_cap(int argc, char** argv) {
    (void)argc; (void)argv;
    int pass = 0, fail = 0;
    auto check = [&](bool ok, const char* what) {
        if (ok) { std::cout << "  PASS: " << what << "\n"; ++pass; }
        else    { std::cout << "  FAIL: " << what << "\n"; ++fail; }
    };

    // CTRL-1: a normal newline-terminated line arrives before the cap ->
    // returned intact, remainder buffered (identical to the pre-cap behaviour).
    {
        std::string inbuf;
        bool fed = false;
        auto fill = [&](std::string& b) -> bool {
            if (fed) return false;
            fed = true;
            b.append("hello\nworld");
            return true;
        };
        bool threw = false;
        std::optional<std::string> line;
        try { line = read_line_capped(inbuf, fill); }
        catch (const std::exception&) { threw = true; }
        check(!threw && line.has_value() && *line == "hello" && inbuf == "world",
              "CTRL: a normal newline-terminated line is returned, remainder buffered");
    }

    // CTRL-2: an under-cap newline-less stream that hits EOF returns nullopt
    // (NOT a throw) — proves the cap does not false-trip on a legitimate short
    // response that the peer simply closes.
    {
        std::string inbuf;
        int calls = 0;
        auto fill = [&](std::string& b) -> bool {
            if (calls++ >= 4) return false;                 // ~4 MiB then EOF (< 16 MiB)
            b.append(std::string(1024 * 1024, 'x'));
            return true;
        };
        bool threw = false;
        std::optional<std::string> line;
        try { line = read_line_capped(inbuf, fill); }
        catch (const std::exception&) { threw = true; }
        check(!threw && !line.has_value(),
              "CTRL: an under-cap newline-less stream that EOFs returns nullopt (no false cap trip)");
    }

    // NEG: a newline-less flood (2 MiB/fill up to 20 MiB — a bounded stand-in
    // for an endless MITM stream) must be ABORTED at the cap with the cap
    // diagnostic, and the buffer must not have grown far past the cap. Without
    // the cap it would read all 20 MiB, EOF, and return nullopt (no throw) —
    // which is exactly what the falsify-on-mutant flips.
    {
        std::string inbuf;
        int calls = 0;
        auto fill = [&](std::string& b) -> bool {
            if (calls++ >= 10) return false;                // 20 MiB then EOF
            b.append(std::string(2 * 1024 * 1024, 'x'));    // never a newline
            return true;
        };
        bool threw = false;
        std::string msg;
        try { (void)read_line_capped(inbuf, fill); }
        catch (const std::exception& e) { threw = true; msg = e.what(); }
        bool hit = threw
                   && msg.find("cap") != std::string::npos
                   && inbuf.size() <= kLightRpcMaxLineBytes + 2 * 1024 * 1024;
        check(hit,
              "NEG: an endless newline-less stream is aborted at the 16 MiB cap (bounded memory)");
    }

    std::cout << "\n  " << pass << " pass / " << fail << " fail\n";
    if (fail == 0) { std::cout << "  PASS: selftest-readline-cap\n"; return 0; }
    std::cout << "  FAIL: selftest-readline-cap\n";
    return 1;
}

// selftest-ct-collision — offline, NO daemon: pin ct_bundle_has_intra_collision,
// the structural intra-bundle note-collision check the CT/enote audit (wf_8f47bd9e)
// added to restore validator parity (light was checking only INPUT dups; the node
// also rejects OUTPUT collisions). Decoupled from the range/balance proof (the
// helper reads only the 33-byte commitment bytes), so it is a pure FAST gate.
int cmd_selftest_ct_collision(int argc, char** argv) {
    (void)argc; (void)argv;
    int pass = 0, fail = 0;
    auto check = [&](bool ok, const char* what) {
        if (ok) { std::cout << "  PASS: " << what << "\n"; ++pass; }
        else    { std::cout << "  FAIL: " << what << "\n"; ++fail; }
    };
    // Build a DCT1-shaped buffer: 15-byte header + n_in*33 input + m*33 output
    // commitments. Each commitment's 33 bytes are filled with a small distinct id
    // (equal ids => identical commitment => collision).
    auto build = [](size_t n_in, size_t m, std::vector<int> in_ids,
                    std::vector<int> out_ids) {
        std::vector<uint8_t> b(15 + (n_in + m) * 33, 0);
        auto setC = [&](size_t off, int id) {
            for (size_t k = 0; k < 33; ++k) b[off + k] = (uint8_t)id;
        };
        for (size_t i = 0; i < n_in; ++i) setC(15 + i * 33, in_ids[i]);
        for (size_t j = 0; j < m; ++j)   setC(15 + n_in * 33 + j * 33, out_ids[j]);
        return b;
    };
    { auto b = build(2, 2, {1, 2}, {3, 4});
      check(!ct_bundle_has_intra_collision(b.data(), 2, 2),
            "ct-collision CTRL: distinct in/out commitments -> no collision"); }
    { auto b = build(2, 1, {5, 5}, {6});
      check(ct_bundle_has_intra_collision(b.data(), 2, 1),
            "ct-collision: duplicate INPUT note -> collision"); }
    { auto b = build(2, 1, {7, 8}, {7});
      check(ct_bundle_has_intra_collision(b.data(), 2, 1),
            "ct-collision (fix): an OUTPUT equal to an INPUT -> collision — the mutant dropping the output half misses it (light-accepts / node-rejects)"); }
    { auto b = build(1, 2, {9}, {10, 10});
      check(ct_bundle_has_intra_collision(b.data(), 1, 2),
            "ct-collision (fix): an OUTPUT equal to another OUTPUT -> collision — the mutant dropping the output half misses it"); }
    std::cout << "\n  " << pass << " pass / " << fail << " fail\n";
    if (fail == 0) { std::cout << "  PASS: selftest-ct-collision\n"; return 0; }
    std::cout << "  FAIL: selftest-ct-collision\n";
    return 1;
}

// selftest-committee-auth — offline, NO daemon: pin the two committee-metadata
// binding helpers the LVS adversarial audit (wf_517af620) hardened —
// authenticated_committee (committee-at-height / verify-state-root committee_size)
// and watch_head_slot_bound (watch-head head-slot relabel). Each mutant that drops
// the bind flips exactly one assertion.
int cmd_selftest_committee_auth(int argc, char** argv) {
    (void)argc; (void)argv;
    int pass = 0, fail = 0;
    auto check = [&](bool ok, const char* what) {
        if (ok) { std::cout << "  PASS: " << what << "\n"; ++pass; }
        else    { std::cout << "  FAIL: " << what << "\n"; ++fail; }
    };

    // ── authenticated_committee: creators[] must be read only from a body whose
    //    recomputed compute_hash == the committee-attested block_hash. A daemon that
    //    serves a stripped header with a copied block_hash but a FORGED creators[]
    //    must be REFUSED (else committee-at-height emits a false IN_COMMITTEE and
    //    verify-state-root a forged committee_size). ──
    {
        determ::chain::Block g;
        g.index    = 5;
        g.creators = { "validator-a", "validator-b", "validator-c" };
        std::string attested = to_hex(g.compute_hash());

        bool ctrl = false;
        try {
            auto ac = authenticated_committee(g, attested);
            ctrl = (ac.creators == g.creators);
        } catch (...) { ctrl = false; }
        check(ctrl, "authenticated_committee: a body matching the attested block_hash yields its creators");

        // A forged creators[] changes compute_hash → must throw against the genuine
        // attested hash. The mutant dropping the hash-equality check returns the
        // forged committee → false IN_COMMITTEE.
        determ::chain::Block f = g;
        f.creators = { "attacker-validator" };
        bool threw = false;
        try { authenticated_committee(f, attested); }
        catch (const std::exception&) { threw = true; }
        check(threw, "authenticated_committee (fix): a forged creators[] with a copied block_hash is REFUSED — the mutant dropping the recompute-bind would accept a forged committee");
    }

    // ── watch_head_slot_bound: report sigs_valid=yes for head_height only if the
    //    committee-verified header sits at slot head_height-1. ──
    check(watch_head_slot_bound(1000000, 999999),
          "watch_head_slot_bound: a header at the true head slot binds");
    check(!watch_head_slot_bound(1000000, 5),
          "watch_head_slot_bound (fix): a genuine EARLIER signed block relabeled as head_height is refused — the mutant dropping the slot bind prints a fictitious head_height as sigs_valid=yes");
    check(!watch_head_slot_bound(0, 0),
          "watch_head_slot_bound: head_height 0 (no head slot) binds to nothing");

    std::cout << "\n  " << pass << " pass / " << fail << " fail\n";
    if (fail == 0) { std::cout << "  PASS: selftest-committee-auth\n"; return 0; }
    std::cout << "  FAIL: selftest-committee-auth\n";
    return 1;
}

// selftest-verify-selection — offline, NO daemon: drive the pure
// verify_selection_core with synthetic DECODED streams to prove the two
// verifier-side defences (D5-RANDOM-SELECTION-SPEC §11 3b/3c). The COMPLETENESS
// of the streams (3a) is the committee-authenticated full-block walk's job (a
// live property, exercised end-to-end later); this gate covers the
// composition-heart: first-open-wins + ordering + the d5_draw re-derivation vs
// the published result.
int cmd_selftest_verify_selection(int argc, char** argv) {
    (void)argc; (void)argv;
    int pass = 0, fail = 0;
    auto check = [&](bool ok, const char* what) {
        if (ok) { std::cout << "  PASS: " << what << "\n"; ++pass; }
        else    { std::cout << "  FAIL: " << what << "\n"; ++fail; }
    };

    std::vector<uint8_t> domain  = { 'd','5','.','c','o','u','r','t' };
    std::vector<uint8_t> case_id = { 'C','A','S','E','-','1' };
    uint8_t seed[32]; for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 7 + 1);

    std::vector<std::vector<uint8_t>> members;
    for (int i = 0; i < 12; i++) { std::string s = "D5-MEMBER-" + std::to_string(i);
        members.push_back(std::vector<uint8_t>(s.begin(), s.end())); }
    D5RosterOp add; add.op = D5_ROSTER_ADD; add.ids = members;
    std::vector<D5RosterOp> roster = { add };

    // Compute the canonical d5_draw selection over `members` so the test's
    // "correct result" matches what the core re-derives.
    auto draw = [&](uint64_t H, uint64_t cutoff, uint32_t N, uint32_t M) {
        std::set<std::vector<uint8_t>> elig(members.begin(), members.end());
        std::vector<std::vector<uint8_t>> ids(elig.begin(), elig.end());
        std::vector<const uint8_t*> idp; std::vector<size_t> idl;
        for (auto& id : ids) { idp.push_back(id.data()); idl.push_back(id.size()); }
        std::vector<size_t> outi(N + M ? N + M : 1); size_t oc = 0;
        d5_draw(seed, domain.data(), domain.size(), case_id.data(), case_id.size(),
                H, cutoff, D5_DRAW_ALGO_LOWEST_HASH, idp.data(), idl.data(), ids.size(),
                N, M, outi.data(), &oc);
        std::vector<std::vector<uint8_t>> sel;
        for (size_t k = 0; k < oc; k++) sel.push_back(ids[outi[k]]);
        return sel;
    };

    // CTRL: single case-open (h_o=90 < H=100 < h_s=110) + correct result.
    {
        D5CaseOpenAt co; co.height = 90; co.roster_cutoff_height = 80; co.draw_height = 100;
        co.n_primary = 3; co.m_alternate = 2; co.draw_algo_version = D5_DRAW_ALGO_LOWEST_HASH;
        auto sel = draw(100, 80, 3, 2);
        D5ResultAt result; result.height = 110; result.draw_height = 100; result.selected_ids = sel;

        auto r1 = verify_selection_core(domain, case_id, seed, roster, {co}, result, sel[0]);
        check(r1.verdict == SelectionVerdict::SELECTED,
              "CTRL: a selected member verifies SELECTED against the canonical draw");
        std::vector<uint8_t> notsel;
        for (auto& m : members) { bool in = false; for (auto& s : sel) if (s == m) { in = true; break; }
            if (!in) { notsel = m; break; } }
        auto r2 = verify_selection_core(domain, case_id, seed, roster, {co}, result, notsel);
        check(r2.verdict == SelectionVerdict::NOT_SELECTED,
              "CTRL: a non-selected eligible member verifies NOT_SELECTED");
    }

    // NEG 3b (first-open-wins): two case-opens for case_id (h1=90 N=3, h2=95 N=5);
    // the result matches the LATER (favorable, N=5) draw. The core picks the
    // FIRST (N=3) -> re-derives 3 -> != result(5) -> UNVERIFIABLE. The mutant
    // (pick max-height) would match -> wrongly accept.
    {
        D5CaseOpenAt co1; co1.height = 90; co1.roster_cutoff_height = 80; co1.draw_height = 100;
        co1.n_primary = 3; co1.m_alternate = 0; co1.draw_algo_version = D5_DRAW_ALGO_LOWEST_HASH;
        // co2 differs by roster_cutoff_height -> different d5_draw ctx -> a
        // DIFFERENT selection of the same size (a rank mismatch, not a count one).
        D5CaseOpenAt co2 = co1; co2.height = 95; co2.roster_cutoff_height = 85;   // favorable, later
        auto sel_favorable = draw(100, 85, 3, 0);                     // matches co2 (cutoff=85)
        D5ResultAt result; result.height = 110; result.draw_height = 100; result.selected_ids = sel_favorable;
        auto r = verify_selection_core(domain, case_id, seed, roster, {co1, co2}, result, sel_favorable[0]);
        bool hit = (r.verdict == SelectionVerdict::UNVERIFIABLE)
                 && r.multiple_case_opens
                 && r.detail.find("re-derivation mismatch") != std::string::npos;
        check(hit, "NEG (first-open-wins): a favorable LATER case-open's result is refused — the canonical FIRST re-derivation mismatches");
    }

    // NEG 3c (ordering): a post-hoc case-open (h_o=100 == draw_height, NOT
    // strictly before) whose result matches. The core rejects at the ordering
    // gate. The mutant relaxing h_o < H to h_o <= H would accept.
    {
        D5CaseOpenAt co; co.height = 100; co.roster_cutoff_height = 80; co.draw_height = 100;  // h_o == H
        co.n_primary = 3; co.m_alternate = 0; co.draw_algo_version = D5_DRAW_ALGO_LOWEST_HASH;
        auto sel = draw(100, 80, 3, 0);
        D5ResultAt result; result.height = 110; result.draw_height = 100; result.selected_ids = sel;
        auto r = verify_selection_core(domain, case_id, seed, roster, {co}, result, sel[0]);
        bool hit = (r.verdict == SelectionVerdict::UNVERIFIABLE)
                 && r.detail.find("not before draw_height") != std::string::npos;
        check(hit, "NEG (ordering): a case-open at h_o == draw_height (post-hoc) is refused at the ordering gate");
    }

    // ── COLLECTOR path (SPEC §11 3a): drive collect_d5_streams over synthetic
    //    committee-verified full blocks carrying DAPP_CALL txs, so the DAPP_CALL
    //    envelope parse + d5codec decode + domain/case_id filter are exercised
    //    end-to-end, then feed the DECODED streams to the core. ──
    {
        std::string domain_str(domain.begin(), domain.end());
        auto hx = [](const uint8_t* p, size_t n){ static const char* H="0123456789abcdef";
            std::string s; for(size_t i=0;i<n;i++){s.push_back(H[p[i]>>4]);s.push_back(H[p[i]&0xf]);} return s; };
        // Wrap a d5codec payload in the DAPP_CALL envelope + a block-body tx json.
        auto mk_tx = [&](const std::string& topic, const std::vector<uint8_t>& ct){
            std::vector<uint8_t> pl; pl.push_back((uint8_t)topic.size());
            pl.insert(pl.end(), topic.begin(), topic.end());
            uint32_t cl=(uint32_t)ct.size();
            pl.push_back((uint8_t)(cl&0xff)); pl.push_back((uint8_t)((cl>>8)&0xff));
            pl.push_back((uint8_t)((cl>>16)&0xff)); pl.push_back((uint8_t)((cl>>24)&0xff));
            pl.insert(pl.end(), ct.begin(), ct.end());
            return nlohmann::json{{"type",10},{"to",domain_str},{"payload",hx(pl.data(),pl.size())}};
        };
        auto enc_roster = [&](uint8_t op, const std::vector<std::vector<uint8_t>>& ids){
            std::vector<const uint8_t*> idp; std::vector<uint16_t> idl;
            for(auto&id:ids){idp.push_back(id.data());idl.push_back((uint16_t)id.size());}
            std::vector<uint8_t> out(64+ids.size()*40); size_t ol=0;
            d5_roster_encode(op, idp.data(), idl.data(), (uint16_t)ids.size(), out.data(), out.size(), &ol);
            out.resize(ol); return out;
        };
        auto enc_case_open = [&](uint64_t cutoff, uint64_t H, uint32_t N, uint32_t M){
            d5_case_open co; co.case_id=case_id.data(); co.case_id_len=(uint16_t)case_id.size();
            co.roster_cutoff_height=cutoff; co.draw_height=H; co.n_primary=N; co.m_alternate=M;
            co.draw_algo_version=D5_DRAW_ALGO_LOWEST_HASH;
            std::vector<uint8_t> out(128); size_t ol=0;
            d5_case_open_encode(&co, out.data(), out.size(), &ol); out.resize(ol); return out;
        };
        auto enc_result = [&](uint64_t H, uint64_t cutoff, const std::vector<std::vector<uint8_t>>& sel){
            d5_result_hdr r; r.case_id=case_id.data(); r.case_id_len=(uint16_t)case_id.size();
            r.draw_height=H; r.roster_cutoff_height=cutoff; for(int i=0;i<32;i++) r.seed[i]=seed[i];
            r.draw_algo_version=D5_DRAW_ALGO_LOWEST_HASH; r.n_primary=(uint32_t)sel.size(); r.m_alternate=0;
            std::vector<const uint8_t*> sp; std::vector<uint16_t> sl;
            for(auto&s:sel){sp.push_back(s.data());sl.push_back((uint16_t)s.size());}
            std::vector<uint8_t> out(128+sel.size()*40); size_t ol=0;
            d5_result_encode(&r, sp.data(), sl.data(), (uint32_t)sel.size(), out.data(), out.size(), &ol);
            out.resize(ol); return out;
        };

        auto sel_all = draw(100, 80, 5, 0);   // canonical draw over ALL 12 members

        // CTRL-collect: honest blocks (add 12, case-open, result over all 12).
        {
            std::vector<nlohmann::json> blocks = {
                {{"index",80},{"transactions",{ mk_tx("roster", enc_roster(D5_ROSTER_ADD, members)) }}},
                {{"index",88},{"transactions",{ mk_tx("case-open", enc_case_open(80,100,5,0)) }}},
                {{"index",110},{"transactions",{ mk_tx("result", enc_result(100,80,sel_all)) }}},
            };
            std::vector<D5RosterOp> rop; std::vector<D5CaseOpenAt> cops; std::vector<D5ResultAt> ress;
            collect_d5_streams(blocks, domain_str, case_id, rop, cops, ress);
            bool decoded = (rop.size()==1 && rop[0].ids.size()==12 && cops.size()==1 && ress.size()==1);
            check(decoded, "COLLECT: DAPP_CALL envelope + d5codec decode materializes the roster/case-open/result streams");
            if (decoded) {
                auto r = verify_selection_core(domain, case_id, seed, rop, cops, ress[0], sel_all[0]);
                check(r.verdict == SelectionVerdict::SELECTED,
                      "COLLECT CTRL: an honest published result verifies SELECTED through the full collect->core pipeline");
            } else check(false, "COLLECT CTRL: (skipped — decode failed)");
        }

        // NEG 3a (roster completeness): the daemon publishes a result over the
        // roster INCLUDING a member it also REMOVED (sel_all's victim), i.e. it
        // ignored its own remove. The COMPLETE walk sees the remove -> the folded
        // roster excludes the victim -> the re-derivation (over 11) mismatches the
        // 12-member published result -> UNVERIFIABLE. The mutant that drops the
        // remove-application (models materializing from a truncatable hint that
        // omitted the remove) folds all 12 -> matches -> false SELECTED.
        {
            std::vector<uint8_t> victim = sel_all[0];
            std::vector<nlohmann::json> blocks = {
                {{"index",80},{"transactions",{ mk_tx("roster", enc_roster(D5_ROSTER_ADD, members)) }}},
                {{"index",85},{"transactions",{ mk_tx("roster", enc_roster(D5_ROSTER_REMOVE, {victim})) }}},
                {{"index",88},{"transactions",{ mk_tx("case-open", enc_case_open(80,100,5,0)) }}},
                {{"index",110},{"transactions",{ mk_tx("result", enc_result(100,80,sel_all)) }}},  // fraudulent (over 12)
            };
            std::vector<D5RosterOp> rop; std::vector<D5CaseOpenAt> cops; std::vector<D5ResultAt> ress;
            collect_d5_streams(blocks, domain_str, case_id, rop, cops, ress);
            auto r = verify_selection_core(domain, case_id, seed, rop, cops, ress.empty()?D5ResultAt{}:ress[0], victim);
            bool hit = (rop.size()==2) && (r.verdict == SelectionVerdict::UNVERIFIABLE)
                     && r.detail.find("re-derivation mismatch") != std::string::npos;
            check(hit, "NEG (roster completeness 3a): a result over an un-removed roster is refused because the applied remove excludes the victim");
        }
    }

    // ── CUTOFF-FREEZE (SPEC §4): the eligible roster is materialized AS OF the
    //    canonical case-open's roster_cutoff_height — a member ADDED AFTER the
    //    cutoff is NOT eligible for that draw (filter_roster_to_cutoff). This NEG
    //    plants a post-cutoff add + a fraudulent result that counts it; once the
    //    correct filter freezes the roster to the pre-cutoff set the count no
    //    longer supports the published draw -> UNVERIFIABLE, so the post-cutoff
    //    member is refused. The mutant (filter_roster_to_cutoff returns the ops
    //    unfiltered) folds the post-cutoff member in and ACCEPTS -> false
    //    SELECTED, exactly the never-false-SELECTED violation. ──
    {
        std::vector<std::vector<uint8_t>> pre(members.begin(), members.begin() + 11);
        std::vector<uint8_t> bonus = { 'D','5','-','B','O','N','U','S' };
        std::vector<std::vector<uint8_t>> all12 = pre; all12.push_back(bonus);

        D5RosterOp add_pre;  add_pre.op  = D5_ROSTER_ADD;  add_pre.height  = 5;  add_pre.ids  = pre;
        D5RosterOp add_post; add_post.op = D5_ROSTER_ADD;  add_post.height = 50; add_post.ids = { bonus };
        std::vector<D5RosterOp> ops = { add_pre, add_post };

        // Canonical case-open: cutoff=10 (BEFORE the post-cutoff add@50); N=12 so
        // the fraudulent 12-member result "selects all" of the padded roster.
        D5CaseOpenAt co; co.height = 12; co.roster_cutoff_height = 10; co.draw_height = 100;
        co.n_primary = 12; co.m_alternate = 0; co.draw_algo_version = D5_DRAW_ALGO_LOWEST_HASH;

        // Fraudulent published result = the draw over the FULL padded 12
        // (want=12==count so `bonus` is in the published set).
        std::vector<const uint8_t*> idp; std::vector<size_t> idl;
        for (auto& id : all12) { idp.push_back(id.data()); idl.push_back(id.size()); }
        std::vector<size_t> outi(12); size_t oc = 0;
        d5_draw(seed, domain.data(), domain.size(), case_id.data(), case_id.size(),
                100, 10, D5_DRAW_ALGO_LOWEST_HASH, idp.data(), idl.data(), 12, 12, 0,
                outi.data(), &oc);
        std::vector<std::vector<uint8_t>> sel12;
        for (size_t k = 0; k < oc; k++) sel12.push_back(all12[outi[k]]);
        D5ResultAt result; result.height = 110; result.draw_height = 100; result.selected_ids = sel12;

        // CORRECT: filter to the cutoff -> the post-cutoff add@50 drops -> 11
        // eligible -> d5_draw(n_primary=12, count=11) fails the count boundary ->
        // UNVERIFIABLE (the post-cutoff `bonus` is refused).
        auto elig = filter_roster_to_cutoff(ops, co.roster_cutoff_height);
        auto r = verify_selection_core(domain, case_id, seed, elig, {co}, result, bonus);
        check(r.verdict == SelectionVerdict::UNVERIFIABLE,
              "NEG (roster cutoff-freeze): a result counting a POST-cutoff member is refused once the roster is frozen to roster_cutoff_height");
    }

    // ── ANTI-GRINDING (SPEC §9 h_r <= h_o): the canonical case-open's
    //    roster_cutoff_height must NOT be AFTER its own block height. Otherwise a
    //    compromised authority opens the case at h_o, waits for cumulative_rand[H]
    //    to be revealed at H, then ADDs a member it computes will WIN the draw at a
    //    height <= the (late) cutoff h_r, and publishes a matching result. This NEG
    //    plants exactly that: h_r=250 > h_o=100, a post-seed add@220, and a
    //    fraudulent result selecting the ground member. The correct core rejects at
    //    the cutoff-ordering gate (h_r<=h_o) BEFORE materializing. The mutant that
    //    drops the h_r<=h_o check folds the post-seed add (220 <= cutoff 250) and
    //    re-derives a draw that matches the rigged result -> false SELECTED. ──
    {
        std::vector<uint8_t> ground = { 'D','5','-','G','R','O','U','N','D' };
        std::vector<std::vector<uint8_t>> padded = members; padded.push_back(ground);

        D5RosterOp add_pre;  add_pre.op  = D5_ROSTER_ADD;  add_pre.height  = 5;   add_pre.ids  = members;
        D5RosterOp add_post; add_post.op = D5_ROSTER_ADD;  add_post.height = 220; add_post.ids = { ground }; // AFTER H=200
        std::vector<D5RosterOp> ops = { add_pre, add_post };

        // h_r=250 > h_o=100 (violates h_r<=h_o); the OTHER legs pass: h_o=100 < H=200 < h_s=260.
        D5CaseOpenAt co; co.height = 100; co.roster_cutoff_height = 250; co.draw_height = 200;
        co.n_primary = 13; co.m_alternate = 0; co.draw_algo_version = D5_DRAW_ALGO_LOWEST_HASH;

        // Rigged published result = the draw over the FULL padded 13 (incl the post-seed ground).
        std::set<std::vector<uint8_t>> es(padded.begin(), padded.end());
        std::vector<std::vector<uint8_t>> eids(es.begin(), es.end());
        std::vector<const uint8_t*> idp; std::vector<size_t> idl;
        for (auto& id : eids) { idp.push_back(id.data()); idl.push_back(id.size()); }
        std::vector<size_t> outi(13); size_t oc = 0;
        d5_draw(seed, domain.data(), domain.size(), case_id.data(), case_id.size(),
                200, 250, D5_DRAW_ALGO_LOWEST_HASH, idp.data(), idl.data(), eids.size(), 13, 0,
                outi.data(), &oc);
        std::vector<std::vector<uint8_t>> sel13;
        for (size_t k = 0; k < oc; k++) sel13.push_back(eids[outi[k]]);
        D5ResultAt result; result.height = 260; result.draw_height = 200; result.selected_ids = sel13;

        // Model the real pipeline: filter to cutoff (250 keeps the post-seed add@220), then core.
        auto elig = filter_roster_to_cutoff(ops, co.roster_cutoff_height);
        auto r = verify_selection_core(domain, case_id, seed, elig, {co}, result, ground);
        bool hit = (r.verdict == SelectionVerdict::UNVERIFIABLE)
                 && r.detail.find("roster_cutoff_height") != std::string::npos
                 && r.detail.find("anti-grinding") != std::string::npos;
        check(hit, "NEG (anti-grinding h_r<=h_o): a case-open whose roster cutoff is AFTER its block height (post-seed roster stuffing) is refused at the cutoff-ordering gate");
    }

    // ── F-7 tx_root laundering (SPEC §11 3a completeness, F-7 interaction): the
    //    D.5 collector decides whether to fetch a block's full body via
    //    must_consult_full_body(header_tx_root, recovered_via_f7). The stripped
    //    header's tx_root is committee-authenticated only when the block's sigs
    //    verified on the NORMAL header-digest path; a block recovered via the F-7
    //    full-block fallback had its header tx_root UNauthenticated, so a daemon
    //    could serve tx_root=0 to make a naive `tx_root != 0` test skip a real
    //    tx-bearing block (hiding a roster REMOVE → false SELECTED). The predicate
    //    must fetch whenever the header claims txs OR the block was F-7-recovered.
    //    The mutant that drops the recovered_via_f7 term makes the F-7 case skip. ──
    {
        std::string zero_root(64, '0');
        std::string txr = std::string(61, '0') + "abc";   // any non-all-zero tx_root
        check(!must_consult_full_body(zero_root, false),
              "F-7 collect: a NORMAL-path zero-tx_root block is skipped (optimization preserved)");
        check(must_consult_full_body(txr, false),
              "F-7 collect: a NORMAL-path tx-bearing block is fetched");
        check(must_consult_full_body(zero_root, true),
              "F-7 collect (fix): an F-7-recovered block is fetched even with a zero header tx_root — the mutant dropping recovered_via_f7 would skip it, laundering a hidden DAPP_CALL into a false SELECTED");
    }

    std::cout << "\n  " << pass << " pass / " << fail << " fail\n";
    if (fail == 0) { std::cout << "  PASS: selftest-verify-selection\n"; return 0; }
    std::cout << "  FAIL: selftest-verify-selection\n";
    return 1;
}

// verify-selection — LIVE: the D.5 citizen verifier. Against an UNTRUSTED daemon,
// authenticate a published government random-selection for `--case-id` under the
// D.5 `--domain`: committee-authenticate the full block chain, collect the D.5
// roster / case-open / result streams from the block bodies (completeness =
// SPEC §11 3a), authenticate the beacon seed (S-042), re-derive d5_draw, and
// report whether an optional `--member` was fairly SELECTED — NEVER a false
// SELECTED. See light/verify_selection.hpp. Exit 0 on a decided verdict
// (SELECTED / NOT_SELECTED), 1 on UNVERIFIABLE.
int cmd_verify_selection(int argc, char** argv) {
    uint16_t port = 0; bool have_port = false;
    std::string genesis_path, domain, case_id_hex, member_hex;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) { port = parse_u16("--rpc-port", argv[++i]); have_port = true; }
        else if (a == "--genesis"  && i + 1 < argc) genesis_path = argv[++i];
        else if (a == "--domain"   && i + 1 < argc) domain = argv[++i];
        else if (a == "--case-id"  && i + 1 < argc) case_id_hex = argv[++i];
        else if (a == "--member"   && i + 1 < argc) member_hex = argv[++i];
        else if (a == "--json") json_out = true;
        else { std::cerr << "verify-selection: unknown arg '" << a << "'\n"; return 1; }
    }
    if (!have_port || genesis_path.empty() || domain.empty() || case_id_hex.empty()) {
        std::cerr << "verify-selection: --rpc-port, --genesis, --domain, --case-id are required\n";
        return 1;
    }
    try {
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        std::vector<uint8_t> case_id = from_hex(case_id_hex);
        std::vector<uint8_t> member;
        if (!member_hex.empty()) member = from_hex(member_hex);
        RpcClient rpc(port);
        if (!rpc.open()) { std::cerr << "verify-selection: " << rpc.last_error() << "\n"; return 1; }
        auto r = verify_selection_at(rpc, committee_seed, genesis, domain, case_id, member,
                                     genesis.k_block_sigs, genesis.bft_enabled);
        const char* verdict =
            r.verdict == SelectionVerdict::SELECTED     ? "SELECTED" :
            r.verdict == SelectionVerdict::NOT_SELECTED ? "NOT_SELECTED" : "UNVERIFIABLE";
        if (json_out) {
            json out = {
                {"domain",              domain},
                {"verdict",             verdict},
                {"multiple_case_opens", r.multiple_case_opens},
                {"eligible_count",      r.eligible_count},
            };
            if (!r.detail.empty()) out["detail"] = r.detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << "verify-selection " << domain << ": " << verdict << "\n";
            if (r.multiple_case_opens)
                std::cout << "  WARNING: multiple case-opens for case_id — permanent public EVIDENCE\n";
            if (!r.detail.empty()) std::cout << "  " << r.detail << "\n";
        }
        return (r.verdict == SelectionVerdict::UNVERIFIABLE) ? 1 : 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-selection: " << e.what() << "\n";
        return 1;
    }
}

// verify-selection-offline — OFFLINE (no daemon): the D.5 citizen decides a
// selection from a JSON array of ALREADY-committee-authenticated full blocks
// (obtained + verified out of band, e.g. `verify-chain`) plus the ALREADY-
// authenticated beacon seed (confirmed via `verify-rand`). Runs the SAME
// collect_d5_streams + first-open-wins + roster cutoff-freeze + d5_draw
// re-derivation as the live `verify-selection` (verify_selection_from_blocks) —
// NEVER a false SELECTED. This is the deterministic counterpart used by the
// reference-RP end-to-end (SPEC §12 inc.6b): d5rp produces the streams, they are
// placed in blocks, and this verifies the published result. The caller is
// responsible for the block committee-authentication + the seed's S-042 binding.
int cmd_verify_selection_offline(int argc, char** argv) {
    std::string blocks_path, domain, case_id_hex, seed_hex, member_hex;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--blocks"   && i + 1 < argc) blocks_path = argv[++i];
        else if (a == "--domain"   && i + 1 < argc) domain = argv[++i];
        else if (a == "--case-id"  && i + 1 < argc) case_id_hex = argv[++i];
        else if (a == "--seed-hex" && i + 1 < argc) seed_hex = argv[++i];
        else if (a == "--member"   && i + 1 < argc) member_hex = argv[++i];
        else if (a == "--json") json_out = true;
        else { std::cerr << "verify-selection-offline: unknown arg '" << a << "'\n"; return 1; }
    }
    if (blocks_path.empty() || domain.empty() || case_id_hex.empty() || seed_hex.empty()) {
        std::cerr << "verify-selection-offline: --blocks, --domain, --case-id, --seed-hex are required\n";
        return 1;
    }
    try {
        std::vector<uint8_t> case_id = from_hex(case_id_hex);
        Hash seed = from_hex_arr<32>(seed_hex);   // throws on bad hex / wrong length
        std::vector<uint8_t> member;
        if (!member_hex.empty()) member = from_hex(member_hex);

        json doc;
        if (blocks_path == "-") { doc = json::parse(std::cin); }
        else {
            std::ifstream f(blocks_path);
            if (!f) { std::cerr << "verify-selection-offline: cannot open --blocks " << blocks_path << "\n"; return 1; }
            doc = json::parse(f);
        }
        if (!doc.is_array()) {
            std::cerr << "verify-selection-offline: --blocks must be a JSON array of block objects\n";
            return 1;
        }
        std::vector<json> blocks(doc.begin(), doc.end());

        auto r = verify_selection_from_blocks(blocks, domain, case_id, seed.data(), member);
        const char* verdict =
            r.verdict == SelectionVerdict::SELECTED     ? "SELECTED" :
            r.verdict == SelectionVerdict::NOT_SELECTED ? "NOT_SELECTED" : "UNVERIFIABLE";
        if (json_out) {
            json out = {
                {"domain", domain}, {"verdict", verdict},
                {"multiple_case_opens", r.multiple_case_opens},
                {"eligible_count", r.eligible_count},
            };
            if (!r.detail.empty()) out["detail"] = r.detail;
            std::cout << out.dump() << "\n";
        } else {
            std::cout << "verify-selection-offline " << domain << ": " << verdict << "\n";
            if (r.multiple_case_opens)
                std::cout << "  WARNING: multiple case-opens for case_id — permanent public EVIDENCE\n";
            if (!r.detail.empty()) std::cout << "  " << r.detail << "\n";
        }
        return (r.verdict == SelectionVerdict::UNVERIFIABLE) ? 1 : 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-selection-offline: " << e.what() << "\n";
        return 1;
    }
}

// verify-rand — LIVE: authenticate cumulative_rand[H] (the MPDH beacon the D.5
// government random-selection DApp draws from) via the S-042 successor binding.
// Fetches block H + H+1 from the daemon, anchors genesis, and never reports a
// false committee-authenticated:YES. See light/verify_rand.hpp.
int cmd_verify_rand(int argc, char** argv) {
    uint16_t port = 0; bool have_port = false;
    std::string genesis_path;
    uint64_t height = 0; bool have_height = false;
    bool json_out = false;
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) { port = parse_u16("--rpc-port", argv[++i]); have_port = true; }
        else if (a == "--genesis"  && i + 1 < argc) genesis_path = argv[++i];
        else if (a == "--height"   && i + 1 < argc) { height = parse_u64("--height", argv[++i]); have_height = true; }
        else if (a == "--json") json_out = true;
        else { std::cerr << "verify-rand: unknown arg '" << a << "'\n"; return 1; }
    }
    if (!have_port || genesis_path.empty() || !have_height) {
        std::cerr << "verify-rand: --rpc-port, --genesis, --height are required\n";
        return 1;
    }
    try {
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) { std::cerr << "verify-rand: " << rpc.last_error() << "\n"; return 1; }
        anchor_genesis(rpc, genesis);   // pin chain identity (fail-closed)
        auto r = verify_rand_at(rpc, committee_seed, genesis, height,
                                genesis.k_block_sigs, genesis.bft_enabled);
        bool ok = (r.verdict == RandVerdict::VERIFIED);
        if (json_out) {
            json out = {
                {"height",                 r.height},
                {"cumulative_rand",        r.cumulative_rand_hex},
                {"block_hash",             r.block_hash_hex},
                {"committee_size",         r.committee_size},
                {"sigs_verified",          r.sigs_verified},
                {"committee_authenticated", ok},
            };
            if (!r.detail.empty()) out["detail"] = r.detail;
            std::cout << out.dump() << "\n";
        } else if (ok) {
            std::cout << "cumulative_rand@" << r.height << " = " << r.cumulative_rand_hex << "\n"
                      << "committee-authenticated: YES (" << r.sigs_verified << " sigs)\n";
        } else {
            std::cout << "cumulative_rand@" << r.height << "\n"
                      << "committee-authenticated: UNVERIFIABLE\n  " << r.detail << "\n";
        }
        return ok ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "verify-rand: " << e.what() << "\n";
        return 1;
    }
}

// selftest-verify-rand — offline, NO daemon: drive verify_rand_from_blocks with
// a synthetic (block[H], block[H+1]) pair to prove the S-042 successor-binding
// gate. Mirrors selftest-tx-inclusion-height: the binding gate is checked
// BEFORE the committee-sig anchor so it is falsifiable with an empty committee.
// NEG proves a swapped-beacon successor (prev_hash != recomputed block_hash[H])
// is refused at the binding gate; CTRL proves a correct binding passes it and
// reaches the committee-sig anchor (non-vacuity). Removing the binding check
// (the SPEC §11 mutant) makes NEG fall through to the committee-sig detail ->
// the NEG assertion flips RED.
int cmd_selftest_verify_rand(int argc, char** argv) {
    (void)argc; (void)argv;
    int pass = 0, fail = 0;
    auto check = [&](bool ok, const char* what) {
        if (ok) { std::cout << "  PASS: " << what << "\n"; ++pass; }
        else    { std::cout << "  FAIL: " << what << "\n"; ++fail; }
    };
    auto mk_block = [](uint64_t index, const std::string& prev_hash, const std::string& cumrand) {
        return nlohmann::json{
            {"index", index},
            {"prev_hash", prev_hash},
            {"timestamp", 0},
            {"transactions", nlohmann::json::array()},
            {"creators", nlohmann::json::array()},
            {"cumulative_rand", cumrand},
            {"abort_events", nlohmann::json::array()}
        };
    };
    std::map<std::string, PubKey> empty_seed;
    const uint64_t H = 100;
    const std::string zero(64, '0');
    const std::string cr_H = std::string(63, '0') + "1";   // cumulative_rand[H]

    auto header_h = mk_block(H, zero, cr_H);
    // Recompute block_hash[H] exactly as the core does (SHA256 over signing_bytes,
    // which include cumulative_rand[H]).
    std::string bh_hash = to_hex(
        determ::chain::Block::from_json(pad_stripped_header(header_h)).compute_hash());

    // CTRL: successor prev_hash == recomputed block_hash[H] -> passes the S-042
    // binding gate -> reaches the committee-sig anchor (empty seed -> fails).
    {
        auto header_h1 = mk_block(H + 1, bh_hash, zero);
        auto r = verify_rand_from_blocks(header_h, header_h1, empty_seed, H);
        bool notrip = (r.verdict == RandVerdict::UNVERIFIABLE)
                    && (r.detail.find("successor prev_hash binding failed") == std::string::npos)
                    && (r.detail.find("committee-sig verification failed") != std::string::npos);
        check(notrip, "CTRL: a correct successor prev_hash passes the S-042 binding gate and reaches the committee-sig anchor (non-vacuity)");
    }

    // NEG (falsify target): successor prev_hash != recomputed block_hash[H]
    // (models a daemon that swapped cumulative_rand[H]) -> UNVERIFIABLE at the
    // S-042 binding gate, BEFORE the committee-sig anchor.
    {
        auto header_h1 = mk_block(H + 1, zero, zero);   // wrong prev_hash
        auto r = verify_rand_from_blocks(header_h, header_h1, empty_seed, H);
        bool hit = (r.verdict == RandVerdict::UNVERIFIABLE)
                 && r.detail.find("successor prev_hash binding failed") != std::string::npos;
        check(hit, "NEG: a successor whose prev_hash != recomputed block_hash[H] (swapped beacon) is refused at the S-042 binding gate");
    }

    // NEG index: block[H].index != requested height -> the index-binding gate.
    {
        auto bad_h = mk_block(H + 5, zero, cr_H);
        auto header_h1 = mk_block(H + 1, bh_hash, zero);
        auto r = verify_rand_from_blocks(bad_h, header_h1, empty_seed, H);
        bool hit = (r.verdict == RandVerdict::UNVERIFIABLE)
                 && r.detail.find("block index binding failed") != std::string::npos;
        check(hit, "NEG: a block[H] whose own index != the requested height is refused at the index-binding gate");
    }

    std::cout << "\n  " << pass << " pass / " << fail << " fail\n";
    if (fail == 0) { std::cout << "  PASS: selftest-verify-rand\n"; return 0; }
    std::cout << "  FAIL: selftest-verify-rand\n";
    return 1;
}

// selftest-tx-inclusion-height — offline, NO daemon: drive the testable core
// verify_tx_inclusion_from_block with a synthetic block to prove the LTX
// index-binding gate. verify-tx-inclusion asks the `block` RPC for index==height
// but anchors on the STATIC genesis committee, so a hostile daemon can return a
// real committee-signed block from a DIFFERENT height that contains the queried
// tx; without the gate every check passes and the verdict is reported at the
// REQUESTED height — a relabel. NEG proves a mismatched index is refused BEFORE
// the committee-sig anchor; CTRL proves a matching index passes the gate.
int cmd_selftest_tx_inclusion_height(int argc, char** argv) {
    (void)argc; (void)argv;
    int pass = 0, fail = 0;
    auto check = [&](bool ok, const char* what) {
        if (ok) { std::cout << "  PASS: " << what << "\n"; ++pass; }
        else    { std::cout << "  FAIL: " << what << "\n"; ++fail; }
    };

    // Minimal parseable block: Block::from_json requires index / prev_hash
    // (64 hex) / timestamp; everything else is optional. Empty creators means
    // the committee-sig anchor (reached only when the index gate PASSES) rejects
    // with a non-index diagnostic — exactly the CTRL non-vacuity signal.
    auto mk_block = [](uint64_t index) {
        return nlohmann::json{
            {"index", index},
            {"prev_hash", std::string(64, '0')},
            {"timestamp", 0},
            {"transactions", nlohmann::json::array()},
            {"creators", nlohmann::json::array()},
            {"cumulative_rand", std::string(64, '0')},
            {"abort_events", nlohmann::json::array()}
        };
    };
    std::map<std::string, PubKey> empty_seed;
    determ::chain::GenesisConfig genesis{};
    const std::string dummy_hash(64, '0');

    // NEG: block's own index (500) != requested height (100) -> UNVERIFIABLE at
    // the index-binding gate, BEFORE the committee-sig anchor.
    {
        auto r = verify_tx_inclusion_from_block(
            mk_block(500), empty_seed, genesis, /*height=*/100, dummy_hash);
        bool hit = (r.verdict == InclusionVerdict::UNVERIFIABLE)
                   && r.detail.find("block index binding failed") != std::string::npos
                   && r.detail.find("index=500") != std::string::npos
                   && r.detail.find("requested height=100") != std::string::npos;
        check(hit, "NEG: a block whose own index != the requested height is refused at the index-binding gate");
    }

    // CTRL: block's own index (100) == requested height (100) -> passes the
    // index gate and falls through to the committee-sig anchor (which fails on
    // the empty committee). Proves the gate is live, not a tautology.
    {
        auto r = verify_tx_inclusion_from_block(
            mk_block(100), empty_seed, genesis, /*height=*/100, dummy_hash);
        // Positively assert control reached the committee-sig anchor (step 2)
        // — proves the index gate PASSED and did not short-circuit, and is
        // robust against a vacuous pass on a parse failure (which would carry
        // a "malformed block body" detail instead).
        bool notrip = (r.detail.find("block index binding failed") == std::string::npos)
                      && (r.detail.find("committee-sig verification failed") != std::string::npos);
        check(notrip, "CTRL: a matching block index passes the index gate and reaches the committee-sig anchor (non-vacuity)");
    }

    std::cout << "\n  " << pass << " pass / " << fail << " fail\n";
    if (fail == 0) { std::cout << "  PASS: selftest-tx-inclusion-height\n"; return 0; }
    std::cout << "  FAIL: selftest-tx-inclusion-height\n";
    return 1;
}

// selftest-watch-label — offline, NO daemon: drive the pure format_watch_tick
// formatter to prove the WATCH-1 relabel. watch-head fetches only the tip and
// printed its state_root next to sigs_valid=yes, but the committee digest
// EXCLUDES state_root and the tip has no committee-signed successor — so a
// hostile daemon can swap the tip's state_root field (digest unchanged → the K
// sigs still verify) and the operator trusts a root the committee never signed.
// The fix renders the tip state_root under a `tip_state_root(UNVERIFIED)` label.
// CTRL proves the honest label is emitted + the digest-quorum verdict still
// renders (non-vacuity); falsify (revert to a bare `state_root=` label) flips
// the label asserts while the non-vacuity assert stays green.
int cmd_selftest_watch_label(int argc, char** argv) {
    (void)argc; (void)argv;
    int pass = 0, fail = 0;
    auto check = [&](bool ok, const char* what) {
        if (ok) { std::cout << "  PASS: " << what << "\n"; ++pass; }
        else    { std::cout << "  FAIL: " << what << "\n"; ++fail; }
    };

    // A forged tip state_root a hostile daemon could inject (the committee
    // digest does NOT cover state_root, so a swapped value still passes
    // sigs_valid=yes). head_hash is likewise the daemon's self-declared id.
    const std::string forged_root(64, 'e');   // "eeee…" — a value never signed
    const std::string served_hash(64, 'a');
    const std::string forged_short = forged_root.substr(0, 16);
    std::string line = format_watch_tick(/*tick=*/1, /*head_height=*/5,
                                         served_hash, forged_root,
                                         /*committee_size=*/3, /*sigs_ok=*/true);

    // FIX: the tip's state_root is rendered UNVERIFIED (never as a verified
    // value). This is the security-relevant assertion — the falsify target.
    check(line.find("tip_state_root(UNVERIFIED)=") != std::string::npos,
          "the tip state_root is rendered under the UNVERIFIED label (not a verified value)");
    // The forged root only ever appears immediately after that UNVERIFIED
    // label — i.e. it is never surfaced as a verified/anchored value.
    check(line.find("tip_state_root(UNVERIFIED)=" + forged_short) != std::string::npos,
          "the forged tip state_root appears ONLY under the UNVERIFIED label");
    // Non-vacuity: a valid tick still renders the digest-quorum verdict + the
    // height + the as-served head_hash label (unaffected by the label mutant).
    check(line.find("sigs_valid=yes") != std::string::npos
          && line.find("height=5") != std::string::npos
          && line.find("head_hash(as-served)=") != std::string::npos,
          "a valid tick still renders sigs_valid=yes + height + as-served head_hash (non-vacuity)");

    std::cout << "\n  " << pass << " pass / " << fail << " fail\n";
    if (fail == 0) { std::cout << "  PASS: selftest-watch-label\n"; return 0; }
    std::cout << "  FAIL: selftest-watch-label\n";
    return 1;
}

// selftest-genesis-row — offline, NO daemon: drive genesis_row_state_root to
// prove the AH-1 fix. account-history's genesis (h=0) row echoed the daemon's
// served `state_root` FIELD, but genesis carries NO committee-attested state_root
// (make_genesis_block never sets it → the genuine value is the all-zero Hash{})
// and the served field is unbound (genesis has zero creator_block_sigs), so a
// hostile daemon could put an arbitrary forged root on the h=0 row. The fix
// returns the genuine (empty) root, IGNORING the served field. NEG: a forged
// served value is NOT echoed. CTRL: an empty served value stays empty (the
// unaffected genuine path). Falsify (return the served value): the NEG asserts
// flip; the CTRL stays green.
int cmd_selftest_genesis_row(int argc, char** argv) {
    (void)argc; (void)argv;
    int pass = 0, fail = 0;
    auto check = [&](bool ok, const char* what) {
        if (ok) { std::cout << "  PASS: " << what << "\n"; ++pass; }
        else    { std::cout << "  FAIL: " << what << "\n"; ++fail; }
    };

    // NEG: a forged served genesis state_root must NOT be echoed onto the row.
    check(genesis_row_state_root(std::string(64, 'e')).empty(),
          "NEG: a forged served genesis state_root is NOT echoed (returns the genuine empty root)");
    // NEG-2: a different, realistic-looking forged 64-hex is likewise ignored.
    check(genesis_row_state_root(
              "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").empty(),
          "NEG-2: any forged served genesis state_root is ignored, not echoed");
    // CTRL: an already-empty served value returns empty (the genuine genesis
    // root); this path is unaffected by the falsify mutant (non-vacuity).
    check(genesis_row_state_root(std::string{}).empty(),
          "CTRL: an empty served value returns the genuine empty genesis root");

    std::cout << "\n  " << pass << " pass / " << fail << " fail\n";
    if (fail == 0) { std::cout << "  PASS: selftest-genesis-row\n"; return 0; }
    std::cout << "  FAIL: selftest-genesis-row\n";
    return 1;
}

// selftest-account-history-label — offline, NO daemon: drive the pure
// balance_source_label formatter to prove the AH-1b tool-correctness fix.
// account-history's state_proof/account RPCs are HEAD-ONLY, so balance/nonce are
// Merkle-PROVEN only at the head; the tool copies the head's balance/nonce onto
// EVERY sampled row. For a non-head height whose balance/nonce changed by the
// head, that row therefore shows the HEAD's value against a non-head height —
// even against an HONEST daemon. If a non-head row were labeled as though it were
// Merkle-proven at its own height, a reader would mistake the head value for
// D's balance-at-h (the false verdict AccountHistorySoundness.md AH-1/§2.3/Gate-3
// used to over-claim). The FIX labels a non-head row `head@H` (head-sourced,
// NOT proven-at-this-height) and only the head row `merkle@H`.
// NEG (the security-relevant, falsify target): a non-head row is labeled
// head-sourced and NEVER claims a per-height Merkle proof. CTRL / non-vacuity:
// the head row is labeled merkle@H. Falsify (make the non-head arm return
// "merkle@..."): the NEG asserts flip RED; CTRL stays green.
int cmd_selftest_account_history_label(int argc, char** argv) {
    (void)argc; (void)argv;
    int pass = 0, fail = 0;
    auto check = [&](bool ok, const char* what) {
        if (ok) { std::cout << "  PASS: " << what << "\n"; ++pass; }
        else    { std::cout << "  FAIL: " << what << "\n"; ++fail; }
    };

    // A non-head sampled row (balance_merkle_verified=false) — the daemon served
    // no per-height proof, so the row carries the HEAD's value proven at height 31.
    const std::string non_head =
        balance_source_label(/*merkle_verified=*/false, /*proven_at_height=*/31);
    // NEG: it is labeled head-sourced (head@H), never as balance-at-this-height.
    check(non_head.rfind("head@", 0) == 0,
          "NEG: a non-head row is labeled head@H (head-sourced), not proven-at-this-height");
    // NEG-2: the label NEVER contains "merkle" — no per-height Merkle claim.
    check(non_head.find("merkle") == std::string::npos,
          "NEG-2: a non-head row's label NEVER claims a Merkle proof (no 'merkle')");
    // NEG-3: it carries the proof height so the reader knows WHERE it was proven.
    check(non_head == "head@31",
          "NEG-3: the non-head label carries the head proof height (head@31)");

    // CTRL / non-vacuity: the head row (balance_merkle_verified=true) IS
    // Merkle-proven at its own height — labeled merkle@H, never head@H. This
    // path is unaffected by the falsify mutant, so it stays green under it.
    const std::string head =
        balance_source_label(/*merkle_verified=*/true, /*proven_at_height=*/31);
    check(head.rfind("merkle@", 0) == 0 && head.find("head@") == std::string::npos,
          "CTRL: the head row is labeled merkle@H (Merkle-proven at its own height)");
    check(head == "merkle@31",
          "CTRL-2: the head label carries its own proof height (merkle@31)");

    std::cout << "\n  " << pass << " pass / " << fail << " fail\n";
    if (fail == 0) { std::cout << "  PASS: selftest-account-history-label\n"; return 0; }
    std::cout << "  FAIL: selftest-account-history-label\n";
    return 1;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { print_usage(); return 1; }
    std::string cmd = argv[1];

    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        print_usage();
        return 0;
    }
    if (cmd == "version" || cmd == "--version") {
        std::cout << "determ-light " << DETERM_LIGHT_VERSION << "\n";
        return 0;
    }

    int sub_argc = argc - 2;
    char** sub_argv = argv + 2;

    try {
        if (cmd == "verify-headers")        return cmd_verify_headers(sub_argc, sub_argv);
        if (cmd == "verify-block-sigs")     return cmd_verify_block_sigs(sub_argc, sub_argv);
        if (cmd == "block-verify")          return cmd_block_verify(sub_argc, sub_argv);
        if (cmd == "verify-ct-tx")          return cmd_verify_ct_tx(sub_argc, sub_argv);
        if (cmd == "verify-ct-block")       return cmd_verify_ct_block(sub_argc, sub_argv);
        if (cmd == "verify-shardtip-records") return cmd_verify_shardtip_records(sub_argc, sub_argv);
        if (cmd == "verify-chain-file")     return cmd_verify_chain_file(sub_argc, sub_argv);
        if (cmd == "committee-diff")        return cmd_committee_diff(sub_argc, sub_argv);
        if (cmd == "verify-state-proof")    return cmd_verify_state_proof(sub_argc, sub_argv);
        if (cmd == "fetch-headers")         return cmd_fetch_headers(sub_argc, sub_argv);
        if (cmd == "fetch-validators")      return cmd_fetch_validators(sub_argc, sub_argv);
        if (cmd == "fetch-state-proof")     return cmd_fetch_state_proof(sub_argc, sub_argv);
        if (cmd == "verify-chain")          return cmd_verify_chain(sub_argc, sub_argv);
        if (cmd == "cross-check")           return cmd_cross_check(sub_argc, sub_argv);
        if (cmd == "state")                 return cmd_state(sub_argc, sub_argv);
        if (cmd == "audit")                 return cmd_audit(sub_argc, sub_argv);
        if (cmd == "balance-trustless")     return cmd_account_trustless(sub_argc, sub_argv, true,  "balance-trustless");
        if (cmd == "nonce-trustless")       return cmd_account_trustless(sub_argc, sub_argv, false, "nonce-trustless");
        if (cmd == "stake-trustless")       return cmd_stake_trustless(sub_argc, sub_argv);
        if (cmd == "verify-abort-record")   return cmd_verify_abort_record(sub_argc, sub_argv);
        if (cmd == "verify-constant")       return cmd_verify_constant(sub_argc, sub_argv);
        if (cmd == "verify-unstake-eligibility") return cmd_verify_unstake_eligibility(sub_argc, sub_argv);
        if (cmd == "supply-trustless")      return cmd_supply_trustless(sub_argc, sub_argv);
        if (cmd == "account-history")       return cmd_account_history(sub_argc, sub_argv);
        if (cmd == "verify-state-root")     return cmd_verify_state_root(sub_argc, sub_argv);
        if (cmd == "sign-tx")               return cmd_sign_tx(sub_argc, sub_argv);
        if (cmd == "pq-sign-tx")            return cmd_pq_sign_tx(sub_argc, sub_argv);
        if (cmd == "pq-verify-tx")          return cmd_pq_verify_tx(sub_argc, sub_argv);
        if (cmd == "selftest-pq-addr-bind") return cmd_selftest_pq_addr_bind(sub_argc, sub_argv);
        if (cmd == "pq-address")            return cmd_pq_address(sub_argc, sub_argv);
        if (cmd == "pq-transfer")           return cmd_pq_transfer(sub_argc, sub_argv);
        if (cmd == "rotate-audit-key")      return cmd_rotate_audit_key(sub_argc, sub_argv);
        if (cmd == "register-note-key")     return cmd_register_note_key(sub_argc, sub_argv);
        if (cmd == "log-audit-access")      return cmd_log_audit_access(sub_argc, sub_argv);
        if (cmd == "build-shield")          return cmd_build_shield(sub_argc, sub_argv);
        if (cmd == "build-unshield")        return cmd_build_unshield(sub_argc, sub_argv);
        if (cmd == "build-ct-transfer")     return cmd_build_ct_transfer(sub_argc, sub_argv);
        if (cmd == "submit-tx")             return cmd_submit_tx(sub_argc, sub_argv);
        if (cmd == "verify-and-submit")     return cmd_verify_and_submit(sub_argc, sub_argv);
        if (cmd == "outbox")                return cmd_outbox(sub_argc, sub_argv);
        if (cmd == "selftest-outbox-record")   return cmd_selftest_outbox_record(sub_argc, sub_argv);
        if (cmd == "selftest-outbox-classify") return cmd_selftest_outbox_classify(sub_argc, sub_argv);
        if (cmd == "selftest-outbox-core")     return cmd_selftest_outbox_core(sub_argc, sub_argv);
        if (cmd == "watch-head")            return cmd_watch_head(sub_argc, sub_argv);
        if (cmd == "export-headers")        return cmd_export_headers(sub_argc, sub_argv);
        if (cmd == "verify-archive")        return cmd_verify_archive(sub_argc, sub_argv);
        if (cmd == "export-state-bundle")   return cmd_export_state_bundle(sub_argc, sub_argv);
        if (cmd == "verify-state-bundle")   return cmd_verify_state_bundle(sub_argc, sub_argv);
        if (cmd == "verify-tx-inclusion")   return cmd_verify_tx_inclusion(sub_argc, sub_argv);
        if (cmd == "verify-receipt-inclusion") return cmd_verify_receipt_inclusion(sub_argc, sub_argv);
        if (cmd == "verify-merge-state")    return cmd_verify_merge_state(sub_argc, sub_argv);
        if (cmd == "verify-param-change")   return cmd_verify_param_change(sub_argc, sub_argv);
        if (cmd == "verify-param-value")    return cmd_verify_param_value(sub_argc, sub_argv);
        if (cmd == "verify-dapp-registration") return cmd_verify_dapp_registration(sub_argc, sub_argv);
        if (cmd == "verify-registrant")     return cmd_verify_registrant(sub_argc, sub_argv);
        if (cmd == "verify-notekey")        return cmd_verify_notekey(sub_argc, sub_argv);
        if (cmd == "verify-enote-inclusion") return cmd_verify_enote_inclusion(sub_argc, sub_argv);
        if (cmd == "verify-account")        return cmd_verify_account(sub_argc, sub_argv);
        if (cmd == "verify-equivocation")   return cmd_verify_equivocation(sub_argc, sub_argv);
        if (cmd == "shard-route")           return cmd_shard_route(sub_argc, sub_argv);
        if (cmd == "committee-at-height")   return cmd_committee_at_height(sub_argc, sub_argv);
        if (cmd == "decode-wire")           return cmd_decode_wire(sub_argc, sub_argv);
        if (cmd == "rpc-auth")              return cmd_rpc_auth(sub_argc, sub_argv);
        if (cmd == "selftest-readline-cap") return cmd_selftest_readline_cap(sub_argc, sub_argv);
        if (cmd == "selftest-tx-inclusion-height") return cmd_selftest_tx_inclusion_height(sub_argc, sub_argv);
        if (cmd == "selftest-watch-label")  return cmd_selftest_watch_label(sub_argc, sub_argv);
        if (cmd == "selftest-genesis-row")  return cmd_selftest_genesis_row(sub_argc, sub_argv);
        if (cmd == "selftest-account-history-label") return cmd_selftest_account_history_label(sub_argc, sub_argv);
        if (cmd == "verify-rand")           return cmd_verify_rand(sub_argc, sub_argv);
        if (cmd == "verify-selection")      return cmd_verify_selection(sub_argc, sub_argv);
        if (cmd == "verify-selection-offline") return cmd_verify_selection_offline(sub_argc, sub_argv);
        if (cmd == "selftest-verify-rand")  return cmd_selftest_verify_rand(sub_argc, sub_argv);
        if (cmd == "selftest-verify-selection") return cmd_selftest_verify_selection(sub_argc, sub_argv);
        if (cmd == "selftest-committee-auth") return cmd_selftest_committee_auth(sub_argc, sub_argv);
        if (cmd == "selftest-ct-collision") return cmd_selftest_ct_collision(sub_argc, sub_argv);
    } catch (const std::exception& e) {
        std::cerr << "determ-light: unhandled error: " << e.what() << "\n";
        return 2;
    }

    std::cerr << "determ-light: unknown subcommand '" << cmd << "'\n"
              << "  run `determ-light help` for the list of commands\n";
    return 1;
}
