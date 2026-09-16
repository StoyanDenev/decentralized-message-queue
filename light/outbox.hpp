#pragma once
// light/outbox.hpp — durable sender outbox for determ-light (increment 1).
//
// PROBLEM SOLVED. No client path in the tree persisted a transaction it had
// signed: `verify-and-submit` / `submit-tx` / `bulk-send` sign, call
// `submit_tx` once and forget (light/main.cpp cmd_verify_and_submit,
// wallet/main.cpp bulk-send). A crash, a closed laptop, a daemon restart or a
// lost RPC reply silently lost the message — or, worse, a naive re-send with a
// fresh nonce turned one message into two. The outbox keeps the SIGNED BYTES
// (never a key) in a canonical binary record per (sender, nonce) slot, written
// with platform-correct durable writes, and re-sends exactly those bytes until
// the ledger has provably consumed the nonce.
//
// What each observable proves (docs/PROTOCOL.md §3.6, DurableOutboxSoundness.md):
//   QUEUED     durable in this directory; no node has acknowledged the bytes.
//   SUBMITTED  a node replied `queued` (or "incumbent equal-or-higher fee");
//              mempools are volatile — nothing beyond that instant is implied.
//   UNKNOWN    the request was sent and the reply was lost; the bytes may or
//              may not be in a mempool. Re-sending identical bytes is safe.
//   INCLUDED   membership in a committee-signed block h verified, but block h
//              has no verified committee-signed successor yet (reorg-able head).
//   FINALIZED  inclusion verified AND a committee-signed successor whose
//              prev_hash binds the exact block (the S-042 rule). `apply` says
//              whether the nonce was consumed by this slot's bytes:
//              APPLIED (next_nonce proven > nonce at index >= h) or SKIPPED
//              (proven == nonce: in the block, not applied — chain.cpp:1688).
//   CONSUMED   next_nonce proven > nonce but no CANONICAL inclusion of the
//              slot's bytes located by the daemon (a daemon NEGATIVE — labelled,
//              never trusted as final: the slot is probed again on every pass
//              and upgraded to FINALIZED/APPLIED once an inclusion is located).
// A slot is re-sent only in QUEUED / SUBMITTED / UNKNOWN. Nothing here is
// ever deleted silently; `prune` removes only proven-consumed slots.
#include "rpc_client.hpp"
#include "keyfile.hpp"
#include <determ/chain/block.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/types.hpp>
#include <nlohmann/json.hpp>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace determ::light::outbox {

// ─── limits (refuse, never clamp — like DLS1) ───────────────────────────────
inline constexpr uint32_t SCHEMA_VERSION      = 1;
inline constexpr size_t   MAX_ALTERNATES      = 8;
inline constexpr size_t   MAX_LAST_ERROR      = 512;   // longer errors are truncated
inline constexpr size_t   MAX_IDEMPOTENCY_KEY = 128;
inline constexpr size_t   DEFAULT_MAX_MESSAGES = 256;
inline constexpr size_t   HARD_MAX_MESSAGES   = 4096;
inline constexpr uint64_t BACKOFF_BASE_S      = 2;
inline constexpr uint64_t BACKOFF_CAP_S       = 300;
inline constexpr uint64_t RESEND_CADENCE_S    = 60;    // SUBMITTED re-affirm interval
inline constexpr uint32_t MAX_SKIPS           = 8;     // re-arm cap after SKIPPED
inline constexpr uint64_t STUCK_AFTER_BLOCKS  = 20;
inline constexpr uint64_t DEFAULT_PRUNE_AGE_S = 7 * 24 * 3600;
inline constexpr uint32_t DEFAULT_RPC_TIMEOUT_MS = 15000;

enum class State   : uint8_t { QUEUED = 0, SUBMITTED = 1, UNKNOWN = 2, INCLUDED = 3,
                               FINALIZED = 4, CONSUMED = 5 };
enum class Apply   : uint8_t { UNKNOWN = 0, APPLIED = 1, SKIPPED = 2, UNLOCATED = 3 };
enum class AltKind : uint8_t { ORIGINAL = 0, FEE_BUMP = 1, REISSUE = 2 };
// Outcome of the LAST submit attempt (diagnostic, not a state).
enum class Outcome : uint8_t { NONE = 0, ACK = 1, PENDING = 2, STALE = 3, REPLY_LOST = 4,
                               REJECTED = 5, TRANSPORT = 6, NODE_CONFIG = 7 };

const char* state_name(State s);
const char* apply_name(Apply a);
const char* alt_kind_name(AltKind k);
const char* outcome_name(Outcome o);

struct Alternate {
    AltKind                 kind{AltKind::ORIGINAL};
    std::array<uint8_t, 16> msg_id{};      // logical message this tx carries
    uint64_t                fee{0};
    Hash                    tx_hash{};     // == decode_frame(frame).hash == compute_hash
    std::vector<uint8_t>    frame;         // chain::Transaction::encode_frame bytes
};

// One (sender, nonce) slot. The IMMUTABLE section (genesis, sender, nonce,
// alternates, idempotency key) and the STATUS section each carry their own
// SHA-256, so a corrupt status can be rebuilt (`recover`) while the bytes
// stay intact, and a corrupt immutable section is reported as lost bytes.
struct Record {
    // immutable
    Hash                    genesis_hash{};
    std::string             sender;
    uint64_t                nonce{0};
    uint8_t                 tx_type{0};
    uint64_t                created{0};
    std::string             idempotency_key;   // "" = none
    std::vector<Alternate>  alternates;        // [0] is the original; last is active
    // status
    State                   state{State::QUEUED};
    Apply                   apply{Apply::UNKNOWN};
    uint32_t                attempts{0};
    uint32_t                consecutive_failures{0};
    uint64_t                last_attempt{0};
    uint64_t                next_retry{0};
    uint64_t                first_ack{0};        // unix time of the first ACK/PENDING
    uint64_t                first_ack_height{0}; // daemon head hint at that ack (untrusted)
    Outcome                 last_outcome{Outcome::NONE};
    std::string             last_error;
    uint64_t                included_height{0};
    Hash                    included_block_hash{};
    uint8_t                 included_alt{0};     // index into alternates
    uint64_t                finalized_height{0};
    uint32_t                skipped_count{0};
    uint32_t                orphaned_count{0};
    uint64_t                updated{0};

    const Alternate& active() const { return alternates.back(); }
    bool sendable() const {
        return state == State::QUEUED || state == State::SUBMITTED || state == State::UNKNOWN;
    }
    bool terminal() const {
        return (state == State::FINALIZED && apply == Apply::APPLIED) || state == State::CONSUMED;
    }
};

std::array<uint8_t, 16> derive_msg_id(const Hash& genesis_hash, const std::string& sender,
                                      uint64_t nonce, const Hash& original_tx_hash);

// Canonical binary codec ("DOX1"). decode throws std::runtime_error naming
// the failing field; a status-section hash mismatch throws with
// `what()` starting "status section:" so `recover` can rebuild it.
std::vector<uint8_t> encode_record(const Record& r);
Record               decode_record(const std::vector<uint8_t>& bytes);
// Decode only the immutable section (used by `recover`). Throws on failure.
Record               decode_record_immutable(const std::vector<uint8_t>& bytes);

struct Meta {
    Hash        genesis_hash{};
    std::string sender;
    uint64_t    nonce_floor{0};   // advanced ONLY by prune over proven-consumed nonces
};
std::vector<uint8_t> encode_meta(const Meta& m);
Meta                 decode_meta(const std::vector<uint8_t>& bytes);

// ─── durable file primitives ────────────────────────────────────────────────
// Both: write `<path>.<pid>.tmp`, flush the file to stable storage (fsync /
// FlushFileBuffers), then publish. `durable_write_new` publishes with
// create-new semantics (link(2) / MoveFileExW without REPLACE_EXISTING) so an
// already-acknowledged record can never be overwritten; `durable_write_replace`
// atomically replaces (rename(2) / MoveFileExW REPLACE_EXISTING|WRITE_THROUGH).
// POSIX additionally fsyncs the directory. Any failure removes the temp file
// and throws; nothing is acknowledged.
// Test seams (documented, environment-gated): DETERM_LIGHT_OUTBOX_CRASH_POINT
// = before_write | after_write | after_fsync | after_publish → _exit(97) at
// that point; DETERM_LIGHT_OUTBOX_INJECT=write_fail → the write fails as ENOSPC
// would; DETERM_LIGHT_OUTBOX_INJECT=drop_response → submit discards the daemon's
// reply after the request was sent (the daemon still holds the bytes);
// DETERM_LIGHT_OUTBOX_HOLD_LOCK_S=N → a mutating verb holds the directory lock
// N seconds (≤60); DETERM_LIGHT_OUTBOX_TRACE=<file> appends one line per step.
void durable_write_new(const std::string& path, const std::vector<uint8_t>& bytes);
void durable_write_replace(const std::string& path, const std::vector<uint8_t>& bytes);
void trace_event(const char* what);

// Exclusive advisory lock on <dir>/outbox.lock (fcntl F_SETLK / LockFileEx):
// released by the OS when the process dies, so no pid heuristics. Same-host
// semantics only (network filesystems are not supported).
class Lock {
public:
    explicit Lock(const std::string& dir);   // throws "outbox is locked" (exit 5 at the CLI)
    ~Lock();
    Lock(const Lock&) = delete;
    Lock& operator=(const Lock&) = delete;
private:
#ifdef _WIN32
    void* handle_{nullptr};
#else
    int fd_{-1};
#endif
};

// ─── the on-disk outbox ─────────────────────────────────────────────────────
struct Slot {
    std::string path;            // <dir>/<nonce:020>.msg
    Record      rec;
    bool        corrupt{false};  // immutable section unreadable (bytes lost)
    bool        status_corrupt{false};   // status section unreadable (recoverable)
    std::string corrupt_detail;
};

class Outbox {
public:
    explicit Outbox(std::string dir);
    const std::string& dir() const { return dir_; }
    // Loads meta + every slot. `.tmp` files are ignored (never deleted here).
    // Quarantined files (`<nonce>.msg.corrupt-*`) keep their nonce reserved.
    void load();
    bool has_meta() const { return has_meta_; }
    const Meta& meta() const { return meta_; }
    // An unreadable `outbox.meta` is reported, not thrown: `status` still lists
    // the slots (exit 3), `recover` rebuilds the pin from them, every other
    // verb refuses. The nonce floor is NOT recoverable (it is rebuilt as 0).
    bool meta_corrupt() const { return meta_corrupt_; }
    const std::string& meta_corrupt_detail() const { return meta_corrupt_detail_; }
    std::map<uint64_t, Slot>& slots() { return slots_; }
    const std::map<uint64_t, Slot>& slots() const { return slots_; }
    const std::vector<uint64_t>& quarantined_nonces() const { return quarantined_; }
    size_t message_count() const { return slots_.size() + quarantined_.size(); }
    uint64_t highest_reserved_nonce_plus_one() const;
    bool nonce_reserved(uint64_t nonce) const;      // slot file OR quarantined file
    bool nonce_quarantined(uint64_t nonce) const;   // only a *.corrupt-* file
    std::string slot_path(uint64_t nonce) const;
    // Persist (durable). write_meta_new pins the directory at first use.
    void write_meta_new(const Meta& m);
    void write_meta_replace(const Meta& m);
    void write_slot_new(const Record& r);       // create-new; throws if the slot exists
    void write_slot_replace(Record& r, uint64_t now);   // stamps updated=now
    void quarantine_slot(uint64_t nonce, uint64_t now);  // rename to *.corrupt-<now>
    void remove_slot_file(uint64_t nonce);      // prune only (after the floor bump)
    size_t remove_quarantined_below(uint64_t floor);   // prune only: *.corrupt-* files whose nonce < floor
    void remove_stale_tmp_files();              // mutating commands only (under the lock)
private:
    std::string dir_;
    Meta        meta_;
    bool        has_meta_{false};
    bool        meta_corrupt_{false};
    std::string meta_corrupt_detail_;
    std::map<uint64_t, Slot> slots_;
    std::vector<uint64_t>    quarantined_;
};

// ─── message construction (TRANSFER from a DAK1 keyfile) ────────────────────
// Local refusals = every rejection the chain would make on the bytes
// themselves (the verifier's shape rules the client can decide offline);
// everything the chain decides from state (funds, registry) is left to the
// ledger and reported by reconcile, never guessed here.
struct TransferSpec {
    std::string          to;
    uint64_t             amount{0};
    uint64_t             fee{0};
    std::vector<uint8_t> payload;   // A4 memo, <= TRANSFER_PAYLOAD_MAX
};
determ::chain::Transaction build_transfer(const LightKeyfile& kf, const TransferSpec& spec,
                                          uint64_t nonce);   // throws on a local refusal

// ─── submit ──────────────────────────────────────────────────────────────────
Outcome classify_submit_error(const std::string& err);   // pure; gated by selftest-outbox-classify
uint64_t backoff_seconds(uint32_t consecutive_failures);  // min(cap, base * 2^n)

struct SubmitOptions {
    bool     force_now{false};      // ignore next_retry
    uint64_t head_hint{0};          // daemon head at connect (untrusted, for the stuck hint)
};
struct SubmitReport {
    size_t sent{0}, acked{0}, pending{0}, stale{0}, lost{0}, rejected{0}, skipped_not_due{0};
    bool   node_config_error{false};   // auth_required/auth_failed/Unknown method → exit 7
    bool   transport_error{false};
    std::vector<std::string> lines;
};
// Sends every due sendable slot's ACTIVE bytes in ascending nonce order and
// persists each state change before moving on. The daemon must already be
// genesis-pinned by the caller (pin_daemon_genesis). `now` is unix seconds.
SubmitReport submit_due(Outbox& ob, RpcClient& rpc, const SubmitOptions& opt, uint64_t now,
                        std::function<void(const std::string&)> log = {});

// Reconcile-in-place used by submit on "stale nonce" and by `reconcile`:
struct ReconcileOptions {
    bool        resume{false};
    std::string state_path;
    uint64_t    wait_seconds{0};
};
struct ReconcileReport {
    uint64_t verified_next_nonce{0};
    uint64_t verified_index{0};        // state proven at this block index
    uint64_t verified_balance{0};
    size_t   finalized_applied{0}, finalized_skipped{0}, included{0}, consumed{0},
             orphaned{0}, rearmed{0}, unverifiable{0}, unchanged{0};
    bool     gap{false};               // chain expects a nonce with no local slot
    uint64_t gap_nonce{0};
    std::vector<std::string> lines;    // human-readable per-slot notes
};
ReconcileReport reconcile_all(Outbox& ob, RpcClient& rpc,
                              const determ::chain::GenesisConfig& genesis,
                              const std::map<std::string, PubKey>& committee_seed,
                              const ReconcileOptions& opt, uint64_t now,
                              std::function<void(const std::string&)> log = {});

// Genesis pin at every network command: fetch the FULL block 0 and require
// its recomputed hash == compute_genesis_hash(genesis) == the outbox meta pin.
void pin_daemon_genesis(RpcClient& rpc, const determ::chain::GenesisConfig& genesis,
                        const Hash& expected);

// ─── status rendering ───────────────────────────────────────────────────────
nlohmann::json slot_to_json(const Slot& s, uint64_t now);
std::string    slot_to_line(const Slot& s, uint64_t now);

uint64_t now_unix();

} // namespace determ::light::outbox
