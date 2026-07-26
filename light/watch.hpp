// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// determ-light `watch-head` subcommand — periodic trust-minimized head
// monitor. Polls the daemon's head at a fixed interval; on each tick
// fetches the head header, verifies its committee sigs against the
// genesis-seeded committee, and prints one structured line per tick.
//
// Use case: a monitoring operator wants a "watch the head" view that
// surfaces (a) head_hash + state_root + height progression, (b)
// committee-sig validity at each tick (so a daemon that loses quorum
// or starts serving stale heads is immediately visible), and (c) a
// genesis-anchor check at startup (fail-closed if the daemon's block
// 0 doesn't match the local --genesis).
//
// Trust model: every tick re-fetches the head from RPC and re-runs
// verify_block_sigs against the GENESIS-seeded committee map. The
// genesis anchor runs ONCE at startup — once we've confirmed the
// daemon's block 0 matches our local genesis hash, we trust the
// chain identity but continue to verify each new head's committee
// sigs independently.
//
// Output per tick (single line, machine-parseable):
//   TICK <i>: height=<H> head_hash(as-served)=<short> \
//             tip_state_root(UNVERIFIED)=<short> \
//             committee_size=<K> sigs_valid=<yes|no>
//
// WATCH-1 soundness: the committee signature authenticates the block DIGEST
// (light_compute_block_digest — index / prev_hash / tx_root / creators /
// creator_tx_lists / F2 roots), which does NOT cover the block's state_root,
// and the tip has NO committee-signed successor to anchor it. So the tip's own
// state_root is reported UNVERIFIED (never as a verified value) and head_hash
// is labeled as-served (the daemon's self-declared id, not recomputed);
// sigs_valid reflects ONLY the digest quorum. A verified state_root for a
// non-tip height is available via the `verify-state-root` command (which runs
// the committee-signed-successor anchor).
//
// If sigs_valid=no at any tick: print a WARN line + continue polling
// (don't exit — the operator wants visibility, not silence).

#pragma once
#include "rpc_client.hpp"
#include <determ/chain/genesis.hpp>
#include <cstdint>
#include <string>

namespace determ::light {

// Watch-head loop options parsed from CLI flags.
struct WatchOptions {
    uint16_t    rpc_port{0};
    std::string genesis_path;
    // 0 = unbounded (until SIGINT). Positive = exit after N ticks.
    uint64_t    count{0};
    // Sleep between ticks (seconds). Default 5s if not supplied.
    uint64_t    interval_secs{5};
};

// Run the watch-head loop. Returns 0 on clean exit (SIGINT after at
// least one tick, OR --count N ticks completed). Returns non-zero on
// genesis-anchor mismatch at startup, transport failure on the first
// tick, or unrecoverable error. After the first successful tick, a
// transient RPC failure on a subsequent tick prints a WARN line and
// continues — the operator wants visibility into chain liveness, not
// silent exits.
int run_watch_head(const WatchOptions& opts);

// Pure formatter for one watch-head observation line (exposed for the offline
// `selftest-watch-label` self-test; the socket fetch stays in do_one_tick).
// The tip's own state_root is NOT covered by the committee digest and the tip
// has no committee-signed successor, so it is rendered under a
// `tip_state_root(UNVERIFIED)` label — never as a verified value; sigs_ok
// reflects ONLY the digest quorum. head_hash is rendered as-served (the
// daemon's self-declared id). Returns the line WITHOUT a trailing newline.
std::string format_watch_tick(uint64_t tick_index, uint64_t head_height,
                              const std::string& head_hash,
                              const std::string& tip_state_root,
                              size_t committee_size, bool sigs_ok);

} // namespace determ::light
