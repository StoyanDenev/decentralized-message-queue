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
//   verify-account           Derive anon-addr + prove EXISTS / NOT-CREATED (a:)
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
#include "watch.hpp"
#include "export.hpp"
#include "verify_archive.hpp"
#include "verify_state_bundle.hpp"
#include "account_history.hpp"
#include "verify_tx_inclusion.hpp"
#include "verify_state_root.hpp"
#include "persist.hpp"

#include <determ/chain/block.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/crypto/keys.hpp>
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
#include <string>
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
        "      Verify K-of-K committee Ed25519 sigs (or ceil(2K/3) BFT).\n"
        "  block-verify --block <file> --committee <file> [--bft] [--json]\n"
        "      Self-contained OFFLINE single-block verifier: STRUCTURE +\n"
        "      TX-ROOT (recompute compute_tx_root == stored) + SIGS (committee\n"
        "      Ed25519 over the INTERNALLY-recomputed block_digest — no operator\n"
        "      digest needed, unlike determ-wallet block-verify). One PASS/FAIL.\n"
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
        "      Anchor genesis + fetch all headers + verify every committee sig.\n"
        "      --persist caches the verified anchor (genesis pin + head height /\n"
        "      block_hash / state_root) to <path> (default: $DETERM_LIGHT_STATE,\n"
        "      else ~/.determ-light/state.json) — written only AFTER full verify.\n"
        "      --resume re-pins the genesis against a cached anchor and verifies\n"
        "      ONLY the suffix the daemon added above it (skips re-walking the\n"
        "      committee-signed prefix); always falls back to a full verify when\n"
        "      the anchor is absent/corrupt/wrong-chain or the daemon hasn't\n"
        "      advanced — never weaker than a full verify. Pair with --persist for\n"
        "      the steady-state resume-then-advance loop.\n"
        "  state (--show | --clear | --selftest | --verify-anchor --genesis <file>) [--state <path>]\n"
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
        "      unlock_height) are committee-anchored, so the verdict cannot be\n"
        "      faked by a lying daemon. Four sound verdicts (exit 0): ELIGIBLE\n"
        "      (locked>0 and an unlock_height <= H+1 has matured), LOCKED\n"
        "      (locked>0 but H+1 < unlock_height — blocks_remaining reported),\n"
        "      BONDED (locked>0 but unlock_height==UINT64_MAX — no unlock has\n"
        "      been scheduled; DEREGISTER first), and NO-STAKE (locked==0 or no\n"
        "      s: leaf — nothing to unstake). Any tamper, cleartext/leaf\n"
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
        "      INCLUDED / NOT-INCLUDED are sound verified verdicts. Current\n"
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
        "      detected, not propagated. INCLUDED / NOT-INCLUDED are sound\n"
        "      verdicts anchored to the head height (merge_state is mutable:\n"
        "      a later revert flips INCLUDED back to NOT-INCLUDED). Any\n"
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
        "      INCLUDED / NOT-INCLUDED are sound verdicts anchored to the head\n"
        "      height (pending_param_changes is consumed at activation: once\n"
        "      the chain advances past <H> the same query flips INCLUDED back\n"
        "      to NOT-INCLUDED). Any tamper, mismatch, or daemon refusal →\n"
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
        "      verified verdict, not a daemon claim). INCLUDED / NOT-INCLUDED\n"
        "      are sound verdicts anchored to the head height; any tamper,\n"
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
        "      INCLUDED / NOT-INCLUDED → exit 0 (both sound verified answers,\n"
        "      matching the InclusionVerdict reader family); any tamper,\n"
        "      value_hash mismatch, or daemon refusal → UNVERIFIABLE (exit 3),\n"
        "      never a false INCLUDED/NOT-INCLUDED.\n"
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
        "      cleartext); a sound state_proof not_found at the verified head →\n"
        "      NOT-CREATED (the account has never been credited — its balance is\n"
        "      a TRUE zero, not the daemon-fabricated zero the bare `account`\n"
        "      RPC returns for any unknown address). Distinct from\n"
        "      balance-trustless, which THROWS on a not_found leaf and cannot\n"
        "      tell \"never created\" from \"created then drained\". EXISTS /\n"
        "      NOT-CREATED → exit 0 (sound verified answer); any tamper,\n"
        "      key/leaf mismatch, or daemon refusal → UNVERIFIABLE (exit 3),\n"
        "      never a false EXISTS.\n"
        "\n"
        "Equivocation forensics (offline, no daemon):\n"
        "  verify-equivocation --in <event.json>\n"
        "                      {--pubkey <64-hex> | --committee <file>} [--json]\n"
        "      OFFLINE re-verification of an EquivocationEvent (the FA6\n"
        "      double-sign proof carried by the EQUIVOCATION_EVIDENCE gossip\n"
        "      message + the submit_equivocation RPC). Re-runs the daemon's V11\n"
        "      slash gate (BlockValidator::check_equivocation_events)\n"
        "      INDEPENDENTLY: digest_a != digest_b, sig_a != sig_b, and BOTH\n"
        "      Ed25519 signatures verify against the equivocator's registered\n"
        "      key. Supply that key directly with --pubkey, or resolve it from\n"
        "      a {domain, ed_pub}[] committee/genesis-committee file via\n"
        "      --committee + the event's own `equivocator` domain (the key\n"
        "      MUST come from a source YOU trust, never from the event). All\n"
        "      four conditions holding is cryptographic proof the signer\n"
        "      double-signed at one height — EQUIVOCATION-PROVEN (exit 0), a\n"
        "      slash is justified. Any condition failing (equal digests, equal\n"
        "      sigs, or a sig that does not verify) is NOT-EQUIVOCATION (exit\n"
        "      3): the evidence does NOT prove a double-sign, fail-closed,\n"
        "      never a false PROVEN. Per FA6 (EquivocationSlashing.md) this has\n"
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
        "      zero reserved byte; msg_type in [0,18] (HELLO rejected — it is\n"
        "      always JSON pre-negotiation); the S-022 per-type body cap\n"
        "      (max_message_bytes: 1 MB chatter / 4 MB block-class / 16 MB\n"
        "      snapshot+chain); and payload well-formedness — the TRANSACTION\n"
        "      4×256-bit frame + trailer (reserved slot zero, exact lengths,\n"
        "      no trailing bytes), or the [u32 LE json_len][json] wrapper for\n"
        "      every other type (declared length matches the body exactly and\n"
        "      parses as JSON). VALID → exit 0; any spec violation → MALFORMED\n"
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
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--header"    && i + 1 < argc) header_path    = argv[++i];
        else if (a == "--committee" && i + 1 < argc) committee_path = argv[++i];
        else if (a == "--bft")                       bft = true;
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
        auto r = verify_block_sigs(header_json, committee_json, bft);
        if (!r.ok) { std::cerr << r.detail << "\n"; return 1; }
        std::cout << "OK\n"
                  << "  mode:      " << (bft ? "BFT" : "MD") << "\n"
                  << "  verified:  " << r.count << " sig(s)\n"
                  << "  digest:    " << r.digest_hex << "\n";
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
    std::string state_path;  // empty → default_state_path()
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--rpc-port" && i + 1 < argc) {
            port = parse_u16("--rpc-port", argv[++i]); have_port = true;
        } else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if (a == "--persist") persist = true;
        else if (a == "--resume") resume = true;
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
    try {
        auto genesis = load_genesis(genesis_path);
        auto committee_seed = build_genesis_committee(genesis);
        RpcClient rpc(port);
        if (!rpc.open()) {
            std::cerr << "verify-chain: " << rpc.last_error() << "\n";
            return 1;
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
    for (int i = 0; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--show")          mode = SHOW;
        else if (a == "--clear")         mode = CLEAR;
        else if (a == "--selftest")      mode = SELFTEST;
        else if (a == "--verify-anchor") mode = VERIFY;
        else if (a == "--genesis" && i + 1 < argc) genesis_path = argv[++i];
        else if (a == "--state" && i + 1 < argc) state_path = argv[++i];
        else {
            std::cerr << "state: unknown arg '" << a << "'\n";
            return 1;
        }
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
                std::cout << "no persisted anchor at " << path << "\n"
                          << "  (run `verify-chain --persist` to create one)\n";
                return 0;  // absence is not an error
            }
            LightState s = load_light_state(path);  // throws if corrupt → fail-closed
            std::cout << "persisted anchor (" << path << ")\n"
                      << "  schema_version:     " << s.schema_version << "\n"
                      << "  genesis_hash:       " << s.genesis_hash << "\n"
                      << "  head_height:        " << s.head_height << "\n"
                      << "  head_block_hash:    " << s.head_block_hash << "\n"
                      << "  head_state_root:    "
                      << (s.head_state_root.empty() ? "(pre-S-033 chain)" : s.head_state_root)
                      << "\n";
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
        // SELFTEST — offline round-trip + reject-path verification.
        const std::string tp = state_path.empty()
            ? (std::filesystem::temp_directory_path() / "determ-light-selftest.json").string()
            : path;  // honor an explicit --state target if the operator gave one
        int checks = 0, fails = 0;
        auto check = [&](bool cond, const std::string& name) {
            ++checks;
            if (cond) { std::cout << "  PASS " << name << "\n"; }
            else      { std::cout << "  FAIL " << name << "\n"; ++fails; }
        };

        // (1) round-trip: save → load → byte-equal
        LightState in;
        in.schema_version  = 1;
        in.genesis_hash    = std::string(64, 'a');
        in.head_height     = 12345;
        in.head_block_hash = std::string(64, 'b');
        in.head_state_root = std::string(64, 'c');
        save_light_state(tp, in);
        LightState out = load_light_state(tp);
        check(out.schema_version == in.schema_version &&
              out.genesis_hash == in.genesis_hash &&
              out.head_height == in.head_height &&
              out.head_block_hash == in.head_block_hash &&
              out.head_state_root == in.head_state_root,
              "round-trip preserves every field");

        // (2) empty state_root round-trips as empty (pre-S-033 chain)
        LightState in2 = in; in2.head_state_root.clear();
        save_light_state(tp, in2);
        check(load_light_state(tp).head_state_root.empty(),
              "empty head_state_root round-trips as empty");

        // (3) malformed JSON → reject
        { std::ofstream f(tp, std::ios::binary | std::ios::trunc); f << "{ not json"; }
        bool rejected = false;
        try { load_light_state(tp); } catch (const std::exception&) { rejected = true; }
        check(rejected, "malformed JSON is rejected (fail-closed)");

        // (4) wrong schema_version → reject
        { std::ofstream f(tp, std::ios::binary | std::ios::trunc);
          f << "{\"schema_version\":999,\"genesis_hash\":\"" << std::string(64,'a')
            << "\",\"head_height\":1,\"head_block_hash\":\"" << std::string(64,'b')
            << "\",\"head_state_root\":\"\"}"; }
        rejected = false;
        try { load_light_state(tp); } catch (const std::exception&) { rejected = true; }
        check(rejected, "unsupported schema_version is rejected");

        // (5) short / non-hex genesis_hash → reject
        { std::ofstream f(tp, std::ios::binary | std::ios::trunc);
          f << "{\"schema_version\":1,\"genesis_hash\":\"deadbeef\",\"head_height\":1,"
               "\"head_block_hash\":\"" << std::string(64,'b') << "\",\"head_state_root\":\"\"}"; }
        rejected = false;
        try { load_light_state(tp); } catch (const std::exception&) { rejected = true; }
        check(rejected, "short genesis_hash is rejected");

        // (6) missing required field → reject
        { std::ofstream f(tp, std::ios::binary | std::ios::trunc);
          f << "{\"schema_version\":1,\"head_height\":1}"; }
        rejected = false;
        try { load_light_state(tp); } catch (const std::exception&) { rejected = true; }
        check(rejected, "missing genesis_hash/head_block_hash is rejected");

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
                auto vc = verify_chain_to_head(rpc, committee_seed, gh);
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
        std::string attested = determ::light::committee_bound_state_root(
            rpc, committee_json, anchor_index, max_wait_seconds);
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
    //    verified value_hash. This is the load-bearing cross-check: a
    //    daemon could serve an honest proof for some OTHER stake pair
    //    while lying in the cleartext; the hash recomputation forces
    //    consistency. Encoding matches build_state_leaves exactly:
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
// committee-instability / suspension slashing. `--wait` (default 0) forwards to
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
        std::string attested = determ::light::committee_bound_state_root(
            rpc, committee_json, anchor_index, wait_seconds);
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
// All four positive verdicts are SOUND committee-anchored answers (exit 0);
// only a refusal-to-assert is non-zero (exit 3). A transport / parse / usage
// fault exits 1, matching the rest of the binary.

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
        // a sound NO-STAKE — there is nothing to unstake — and let every
        // other failure (sig break, root mismatch, cleartext/leaf tamper)
        // surface as UNVERIFIABLE so a lying daemon can never coerce a false
        // ELIGIBLE.
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
            if (msg.find("not_found") != std::string::npos
                || msg.find("no verified") != std::string::npos) {
                have_stake = false;          // sound NO-STAKE
            } else {
                throw;                       // sig/root/tamper → UNVERIFIABLE
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

        // Exit codes match verify-account: every sound verdict (ELIGIBLE /
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

        auto r = verify_state_root_at(rpc, committee_seed,
                                      genesis_hash_hex, height, wait_seconds);

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
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex);
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
        // distinguish a genuine absence (`not_found` for our exact key →
        // a sound NOT-INCLUDED) from any other refusal (→ UNVERIFIABLE,
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
                            determ::light::committee_bound_state_root(
                                rpc, committee_json, anchor_index,
                                wait_seconds);
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
        // 0 (sound verified answer); UNVERIFIABLE → 3 (refused to assert).
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
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex);
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
        // We distinguish a genuine absence (`not_found` for our exact key →
        // a sound NOT-INCLUDED) from any other refusal (→ UNVERIFIABLE,
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
                            determ::light::committee_bound_state_root(
                                rpc, committee_json, anchor_index,
                                wait_seconds);
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
        // → 0 (sound verified answer); UNVERIFIABLE → 3 (refused to assert).
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
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex);
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
        // We distinguish a genuine absence (`not_found` for our exact key →
        // a sound NOT-INCLUDED) from any other refusal (→ UNVERIFIABLE,
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
                            determ::light::committee_bound_state_root(
                                rpc, committee_json, anchor_index,
                                wait_seconds);
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
        // (sound verified answer); UNVERIFIABLE → 3 (refused to assert).
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
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex);
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
        // sound negative: unlike a:/d: (where an absent leaf is a genuine
        // "never created" verdict), every WELL-KNOWN consensus scalar always
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
                        determ::light::committee_bound_state_root(
                            rpc, committee_json, anchor_index,
                            wait_seconds);
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
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `r:` state-proofs cannot be "
                "anchored");
        }

        // Fetch the `r:`-namespace state-proof for this domain.
        auto proof = rpc.call("state_proof",
            {{"namespace", "r"}, {"key", domain}});

        // not_found for our exact key → a sound NOT-INCLUDED (no such
        // validator registered at the verified head). Any other refusal →
        // fail-closed UNVERIFIABLE (we will not assert membership either way).
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
                            determ::light::committee_bound_state_root(
                                rpc, committee_json, anchor_index,
                                wait_seconds);
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
        // -param-change): INCLUDED / NOT-INCLUDED → 0 (both sound verified answers);
        // UNVERIFIABLE → 3 (refused to assert); args/transport → 1.
        if (verdict == InclusionVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-registrant: " << e.what() << "\n";
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
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `d:` state-proofs cannot be "
                "anchored");
        }

        // Fetch the `d:`-namespace state-proof for this domain.
        auto proof = rpc.call("state_proof",
            {{"namespace", "d"}, {"key", domain}});

        // not_found for our exact key → a sound NOT-INCLUDED (no such DApp
        // registered at the verified head). Any other refusal → fail-closed
        // UNVERIFIABLE (we will not assert membership either way).
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
                            determ::light::committee_bound_state_root(
                                rpc, committee_json, anchor_index,
                                wait_seconds);
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
        // (sound verified answer); UNVERIFIABLE → 3 (refused to assert).
        if (verdict == InclusionVerdict::UNVERIFIABLE) return 3;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "verify-dapp-registration: " << e.what() << "\n";
        return 1;
    }
}

// ──────────────────────────── verify-account ───────────────────────────

// Tri-state for the anon-account existence check. EXISTS / NOT-CREATED are
// sound committee-anchored verdicts (exit 0); UNVERIFIABLE is a refusal to
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
//        • a sound state_proof `not_found` at the verified head → NOT-CREATED
//          (the account has never been credited — its balance is a TRUE zero,
//          not a daemon-fabricated one).
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
// fabricated zero as though it were chain-attested. verify-account closes
// that gap: NOT-CREATED is a VERIFIED negative anchored to the committee-
// signed state_root via the `a:` state_proof's not_found, never the daemon's
// unverified cleartext zero. On EXISTS it additionally hash-binds the
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
        auto vc = verify_chain_to_head(rpc, committee_seed, genesis_hash_hex);
        if (vc.head_state_root.empty()) {
            throw std::runtime_error(
                "chain has not activated state_root (S-033) — head header "
                "carries no state_root, so `a:` state-proofs cannot be "
                "anchored");
        }

        // Fetch the `a:`-namespace state-proof for the canonical address.
        auto proof = rpc.call("state_proof",
            {{"namespace", "a"}, {"key", canon_address}});

        // not_found for our exact address → a sound NOT-CREATED (the chain
        // has never materialized an account leaf for it). Any OTHER refusal →
        // fail-closed UNVERIFIABLE (we will not assert either way).
        if (proof.contains("error") && !proof["error"].is_null()) {
            std::string err = proof["error"].is_string()
                ? proof["error"].get<std::string>()
                : proof["error"].dump();
            if (err == "not_found") {
                verdict = AccountExistVerdict::NOT_CREATED;
                detail  = "no `a:` leaf for '" + canon_address
                        + "' at the committee-verified head — the account has "
                          "never been credited (auto-creation has not fired); "
                          "its balance is a TRUE zero, not a daemon-fabricated "
                          "one";
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
                            determ::light::committee_bound_state_root(
                                rpc, committee_json, anchor_index,
                                wait_seconds);
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
        // (sound verified answer); UNVERIFIABLE → 3 (refused to assert).
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
// BlockValidator::check_equivocation_events applies before a slash is
// finalized:
//
//   1. digest_a != digest_b   (two DISTINCT signed values — not a replay)
//   2. sig_a    != sig_b       (two distinct signatures)
//   3. Verify(pk, digest_a, sig_a) == 1
//   4. Verify(pk, digest_b, sig_b) == 1
//
// All four passing is cryptographic proof the holder of `pk` signed two
// conflicting block_digests (or contrib commitments — V11 is digest-
// agnostic) at the SAME block_index: a deliberate double-sign that
// forfeits the equivocator's full stake on apply. FA6 (EquivocationSlashing.md)
// proves this has no false positives under Ed25519 EUF-CMA: an honest
// validator can NEVER be named here, because reproducing it would require
// forging a signature by an honest key.
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
//   EQUIVOCATION-PROVEN → exit 0 (all four V11 conditions hold; a slash
//                         against this signer is cryptographically justified)
//   NOT-EQUIVOCATION    → exit 3 (a V11 condition fails: equal digests,
//                         equal sigs, or either sig does not verify — the
//                         evidence does NOT prove a double-sign; fail-closed,
//                         never a false PROVEN)
//   I/O / usage error   → exit 1 (missing file, bad hex, unknown domain)
//
// This is the read-side counterpart to the daemon's detection +
// apply path: an auditor, governance script, or counter-party can verify a
// circulating EquivocationEvent BEFORE trusting that a slash was warranted,
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
        // enforces the field-name + hex-length contract (digest_a/digest_b
        // 64-hex, sig_a/sig_b 128-hex) and throws a clear S-018 diagnostic on
        // a malformed document — those are usage errors (exit 1), not a
        // NOT-EQUIVOCATION verdict.
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

        // V11, re-run independently of the daemon. Each clause that fails
        // collapses the verdict to NOT-EQUIVOCATION with a precise reason —
        // the evidence is structurally well-formed but does not prove a
        // double-sign, so we fail closed rather than emit a false PROVEN.
        EquivVerdict verdict = EquivVerdict::PROVEN;
        std::string  reason;
        bool digests_distinct = (ev.digest_a != ev.digest_b);
        bool sigs_distinct     = (ev.sig_a   != ev.sig_b);
        bool sig_a_ok = digests_distinct && determ::crypto::verify(
            pk, ev.digest_a.data(), ev.digest_a.size(), ev.sig_a);
        bool sig_b_ok = digests_distinct && determ::crypto::verify(
            pk, ev.digest_b.data(), ev.digest_b.size(), ev.sig_b);

        if (!digests_distinct) {
            verdict = EquivVerdict::NOT_EQUIVOCATION;
            reason  = "digest_a == digest_b (replay, not equivocation)";
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
                {"pubkey",       to_hex(pk)},
                {"digest_a",     to_hex(ev.digest_a)},
                {"digest_b",     to_hex(ev.digest_b)},
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
                      << "  pubkey:       " << to_hex(pk) << "\n"
                      << "  digest_a:     " << to_hex(ev.digest_a)
                      << "  (sig " << (sig_a_ok ? "VALID" : "INVALID") << ")\n"
                      << "  digest_b:     " << to_hex(ev.digest_b)
                      << "  (sig " << (sig_b_ok ? "VALID" : "INVALID") << ")\n";
            if (ev.shard_id != 0 || ev.beacon_anchor_height != 0) {
                std::cout << "  shard_id:     " << ev.shard_id << "\n"
                          << "  beacon anchor: " << ev.beacon_anchor_height
                          << "\n";
            }
            if (!reason.empty())
                std::cout << "  reason:       " << reason << "\n";
        }

        // EQUIVOCATION-PROVEN → exit 0 (a slash here is cryptographically
        // justified). NOT-EQUIVOCATION → exit 3 (sound refusal to assert a
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

            // Committed value for a counter is SHA256(u64_be(value)).
            // Recompute it from the daemon's CLEARTEXT claim; the binding
            // is the comparison against the proof's verified value_hash.
            determ::crypto::SHA256Builder mb;
            mb.append(claimed[ci]);
            Hash expected_value_hash = mb.finalize();

            // Fetch the `c:` state-proof. The `c:` namespace is a SIMPLE
            // (ASCII-key) namespace: the daemon takes the bare counter
            // name as `key` and rebuilds "k:c:" + name internally.
            auto proof = rpc.call("state_proof",
                {{"namespace", "c"}, {"key", name}});

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
                detail  = "TAMPERED — daemon's chain_summary counter '" + name
                        + "'=" + std::to_string(claimed[ci])
                        + " hashes to " + to_hex(expected_value_hash)
                        + " but the c: state-proof's value_hash is "
                        + to_hex(proof_value_hash)
                        + " — daemon is lying about the counter OR the proof";
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
                        determ::light::committee_bound_state_root(
                            rpc, committee_json, anchor_index,
                            wait_seconds);
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
        auto sr = verify_state_root_at(rpc, committee_seed,
                                       genesis_hash_hex, height, wait_seconds);
        if (!sr.ok) {
            std::cerr << "committee-at-height: " << sr.detail << "\n";
            return 1;
        }

        // Re-fetch the now-committee-attested header[H] and parse it. The
        // sigs verified above were computed over light_compute_block_digest,
        // which binds creators[] AND creator_block_sigs[] — so the creator
        // set + per-slot sig status read here is itself committee-attested.
        auto page = rpc.call("headers", {{"from", height}, {"count", 1}});
        if (!page.contains("headers") || !page["headers"].is_array()
            || page["headers"].empty()) {
            throw std::runtime_error(
                "daemon returned no header at index "
                + std::to_string(height));
        }
        json header_json = page["headers"][0];

        // Bind the re-fetched header to the anchor: its block_hash must be
        // the one verify_state_root_at just attested. A daemon that serves a
        // different (forged) header on the second fetch is caught here.
        std::string refetched_hash =
            header_json.value("block_hash", std::string{});
        if (refetched_hash != sr.block_hash_hex) {
            throw std::runtime_error(
                "re-fetched header[" + std::to_string(height)
                + "].block_hash=" + refetched_hash
                + " does not match the committee-attested block_hash="
                + sr.block_hash_hex
                + " (daemon served a different header on re-fetch)");
        }

        determ::chain::Block b =
            determ::chain::Block::from_json(
                pad_stripped_header(std::move(header_json)));

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
//   * msg_type byte in the known MsgType range [0, 18]. HELLO (0) is
//     rejected: HELLO is ALWAYS JSON pre-negotiation and is never legally
//     carried inside a binary envelope (encode_binary throws on it).
//   * S-022 per-type body-size cap: the post-deserialize body length must
//     not exceed max_message_bytes(msg_type) (1 MB consensus chatter /
//     4 MB block-class / 16 MB snapshot+chain). Reimplemented locally from
//     the documented table so the artifact is checked against the SPEC,
//     not against whatever the producing build happened to compile.
//   * Payload well-formedness:
//       - TRANSACTION: the 4×256-bit fixed frame + trailer parses cleanly,
//         reserved amount-block slot is zero, lengths are consistent, and
//         the trailer's length-prefixed from/to/sig/hash fit exactly.
//       - all other types: a [u32 LE json_len][json_bytes] payload whose
//         declared length matches the remaining body exactly and whose
//         bytes parse as JSON.
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

    // After hash there must be NOTHING left — a conforming encoder writes
    // sig+hash as the final fields. Trailing bytes mean a malformed or
    // attacker-padded frame.
    if (off != blen)
        throw WireMalformed("TRANSACTION has " + std::to_string(blen - off) +
                            " trailing byte(s) after sig/hash");

    report["amount"]      = amount;
    report["fee"]         = fee;
    report["nonce"]       = nonce;
    report["tx_type"]     = static_cast<unsigned>(type);
    report["payload_len"] = static_cast<unsigned>(payload_len);
    report["from"]        = from;
    report["to"]          = to;
    report["sig"]         = sig_hex;
    report["hash"]        = hash_hex;
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
                                    "(0x7b would be legacy JSON)");
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
            if (msg_type == 0)
                throw WireMalformed("HELLO must never be carried in a binary "
                                    "envelope (it is always JSON pre-"
                                    "negotiation)");

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
            if (msg_type == 2 /* TRANSACTION */) {
                report["payload_kind"] = "tx_frame";
                decode_wire_tx(body, body_len, report);
            } else {
                // [u32 LE json_len][json_bytes] — declared length must
                // match the remaining body EXACTLY and parse as JSON.
                report["payload_kind"] = "lp_json";
                if (body_len < 4)
                    throw WireMalformed(std::string(tname) +
                                        " truncated payload length header");
                uint32_t plen = wire_le_u32(body);
                if (4 + static_cast<size_t>(plen) != body_len)
                    throw WireMalformed(std::string(tname) +
                                        " declared json_len=" +
                                        std::to_string(plen) +
                                        " does not match body (" +
                                        std::to_string(body_len - 4) +
                                        " payload bytes available)");
                report["json_len"] = plen;
                try {
                    json parsed = json::parse(body + 4, body + 4 + plen);
                    // Echo a shallow shape hint, not the whole payload.
                    if (parsed.is_object())
                        report["json_keys"] = static_cast<unsigned>(parsed.size());
                    report["json_type"] = parsed.is_object()  ? "object"
                                        : parsed.is_array()   ? "array"
                                        : parsed.is_string()  ? "string"
                                        : parsed.is_number()  ? "number"
                                        : parsed.is_boolean() ? "bool"
                                        : parsed.is_null()    ? "null"
                                                              : "other";
                } catch (const std::exception& e) {
                    throw WireMalformed(std::string(tname) +
                                        " payload is not valid JSON: " +
                                        e.what());
                }
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
            if (report["payload_kind"] == "tx_frame") {
                std::cout << "  payload:   tx_frame\n"
                          << "  amount:    " << report["amount"] << "\n"
                          << "  fee:       " << report["fee"] << "\n"
                          << "  nonce:     " << report["nonce"] << "\n"
                          << "  tx_type:   " << report["tx_type"] << "\n"
                          << "  from:      " << report["from"].get<std::string>() << "\n"
                          << "  to:        " << report["to"].get<std::string>() << "\n"
                          << "  hash:      " << report["hash"].get<std::string>() << "\n";
            } else {
                std::cout << "  payload:   lp_json (" << report["json_len"]
                          << " bytes, " << report["json_type"].get<std::string>()
                          << ")\n";
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
            auto vc = verify_chain_to_head(rpc, committee_seed, gh);
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
        if (cmd == "verify-unstake-eligibility") return cmd_verify_unstake_eligibility(sub_argc, sub_argv);
        if (cmd == "supply-trustless")      return cmd_supply_trustless(sub_argc, sub_argv);
        if (cmd == "account-history")       return cmd_account_history(sub_argc, sub_argv);
        if (cmd == "verify-state-root")     return cmd_verify_state_root(sub_argc, sub_argv);
        if (cmd == "sign-tx")               return cmd_sign_tx(sub_argc, sub_argv);
        if (cmd == "submit-tx")             return cmd_submit_tx(sub_argc, sub_argv);
        if (cmd == "verify-and-submit")     return cmd_verify_and_submit(sub_argc, sub_argv);
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
        if (cmd == "verify-account")        return cmd_verify_account(sub_argc, sub_argv);
        if (cmd == "verify-equivocation")   return cmd_verify_equivocation(sub_argc, sub_argv);
        if (cmd == "shard-route")           return cmd_shard_route(sub_argc, sub_argv);
        if (cmd == "committee-at-height")   return cmd_committee_at_height(sub_argc, sub_argv);
        if (cmd == "decode-wire")           return cmd_decode_wire(sub_argc, sub_argv);
        if (cmd == "rpc-auth")              return cmd_rpc_auth(sub_argc, sub_argv);
    } catch (const std::exception& e) {
        std::cerr << "determ-light: unhandled error: " << e.what() << "\n";
        return 2;
    }

    std::cerr << "determ-light: unknown subcommand '" << cmd << "'\n"
              << "  run `determ-light help` for the list of commands\n";
    return 1;
}
