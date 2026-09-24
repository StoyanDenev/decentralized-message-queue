// light/outbox_cli.cpp — `determ-light outbox <verb>` (see outbox.hpp for the
// contract). Every mutating verb takes the directory lock; `status` is
// lock-free and never writes.
//
// ONE parser serves all seven verbs. That is deliberate — the flags spell the
// same things everywhere — but it means the parser RECOGNIZES the union of every
// verb's flags. Until 2026-09-18 it also ACCEPTED that union for every verb, so
// each verb carried a silent accept-and-ignore surface: `outbox status --wait 30`
// exited 0 having waited for nothing, and `outbox enqueue --wait 30` was accepted
// while the wait never reached its head-anchored nonce-hint read (S-112; the class
// is S-113). A flag a verb cannot act on is now REFUSED with the same fail-closed
// shape as an unknown argument — see kVerbFlags below, which is the single place
// the per-verb surface is stated and is what `determ-light help`,
// docs/CLI-REFERENCE.md and tools/test_light_outbox_flag_surface.sh all track.
//
// The same lie had a second, narrower form INSIDE a verb: `enqueue --wait 30`
// with no `--rpc-port`, or with an explicit `--nonce`, is in enqueue's set and is
// still read by nothing, because the block that reads it is skipped. Those are
// refused too, by refuse_inert_flags() below, naming the flag whose presence or
// absence made the request inert.
#include "outbox_cli.hpp"
#include "outbox.hpp"
#include "trustless_read.hpp"
#include <determ/chain/params.hpp>
#include <algorithm>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using json = nlohmann::json;
using namespace determ::light::outbox;

namespace determ::light {
namespace {

constexpr int EXIT_CORRUPT = 3, EXIT_FULL = 4, EXIT_LOCKED = 5, EXIT_MISMATCH = 6, EXIT_NODE_CONFIG = 7, EXIT_EXISTS = 8;

uint64_t arg_u64(const std::string& flag, const std::string& v) {
    if (v.empty() || v.find_first_not_of("0123456789") != std::string::npos || v.size() > 20)
        throw std::runtime_error(flag + " must be a non-negative integer (got '" + v + "')");
    errno = 0;
    unsigned long long n = std::strtoull(v.c_str(), nullptr, 10);
    if (errno == ERANGE) throw std::runtime_error(flag + " out of range");
    return static_cast<uint64_t>(n);
}
uint16_t arg_u16(const std::string& flag, const std::string& v) {
    uint64_t u = arg_u64(flag, v);
    if (u > 65535) throw std::runtime_error(flag + " out of range (>65535)");
    return static_cast<uint16_t>(u);
}

struct Args {
    std::string dir, genesis_path, keyfile, to, payload_hex, idem_key, state_path;
    uint16_t port{0};
    bool have_port{false}, have_nonce{false}, json_out{false}, now{false}, resume{false},
         include_unlocated{false}, have_fee{false}, have_amount{false};
    uint64_t amount{0}, fee{0}, nonce{0}, wait{0}, max_messages{DEFAULT_MAX_MESSAGES},
             older_than{DEFAULT_PRUNE_AGE_S};
    uint32_t timeout_ms{DEFAULT_RPC_TIMEOUT_MS};
    // Every flag the operator actually WROTE. A default is indistinguishable from
    // a value once it is in a field, and refuse_inert_flags() below must refuse
    // only what was asked for.
    std::set<std::string> given;
};

// The flags each verb ACTS ON. Everything the shared parser recognizes but a
// verb does not read is refused by that verb — a flag that is accepted and
// ignored tells the operator a request was honoured when it was not, and no
// build or test can see it (S-112 / S-113). This table is the contract:
// `determ-light help` and docs/CLI-REFERENCE.md advertise exactly these sets and
// tools/test_light_outbox_flag_surface.sh measures the BINARY against both.
//
// It is the PER-VERB surface only. A flag listed here can still be read by
// nothing in a particular invocation; refuse_inert_flags() below is the
// PER-INVOCATION surface and refuses those, so "listed here" never means
// "accepted whatever else you wrote".
//
// Each entry is justified by a value the verb reads, not by plausibility:
//   enqueue    --timeout-ms and --wait bound the optional nonce-hint RPC and its
//              head-anchored read; both need --rpc-port and are refused with an
//              explicit --nonce, which skips that read entirely.
//   submit     --now forces every due slot; --timeout-ms bounds the connection.
//   reconcile  --resume picks the cached anchor and --state names it (refused
//              without --resume); --wait bounds the successor poll of every
//              binding it performs.
//   replace / recover take no --json: neither has a JSON emitter, so accepting
//              the flag would be the same silent lie in miniature.
const std::map<std::string, std::set<std::string>>& verb_flags() {
    static const std::map<std::string, std::set<std::string>> kVerbFlags = {
        {"enqueue",   {"--outbox", "--genesis", "--keyfile", "--to", "--amount", "--fee",
                       "--nonce", "--payload-hex", "--idempotency-key", "--rpc-port",
                       "--max-messages", "--timeout-ms", "--wait", "--json"}},
        {"submit",    {"--outbox", "--genesis", "--rpc-port", "--timeout-ms", "--now", "--json"}},
        {"reconcile", {"--outbox", "--genesis", "--rpc-port", "--timeout-ms", "--resume",
                       "--state", "--wait", "--json"}},
        {"status",    {"--outbox", "--json"}},
        {"replace",   {"--outbox", "--genesis", "--keyfile", "--nonce", "--fee", "--to",
                       "--amount", "--payload-hex"}},
        {"prune",     {"--outbox", "--older-than", "--include-unlocated", "--json"}},
        {"recover",   {"--outbox"}},
    };
    return kVerbFlags;
}

// Every flag ANY verb accepts — DERIVED from the table above, never a second
// hand-kept list, so the two can never disagree. It exists only to tell an
// operator who used a real flag on the wrong verb ("not accepted by") apart from
// one who mistyped ("unknown arg"); both are refused.
bool a_verb_accepts(const std::string& flag) {
    for (const auto& [v, flags] : verb_flags())
        if (flags.count(flag)) return true;
    return false;
}

// A flag can be in its verb's set above and still be read by NOTHING in the
// configuration the operator actually gave. `cmd_enqueue`'s nonce-reservation
// block is the only reader of --rpc-port, --timeout-ms and --wait: it is skipped
// whole when --nonce is explicit, and opens no socket when --rpc-port is absent.
// `reconcile`'s cached anchor is loaded only on the --resume path, so --state is
// never opened without it. Accepting a flag there is the same silent lie as
// accepting it on the wrong verb, one level down — the operator asked for a wait
// and got none — so it is refused the same way: fail-closed, before anything is
// locked or written, naming the flag AND the flag whose presence or absence made
// it inert, not just the flag.
//
// These three rules are MEASURED, not inferred: every accepted (verb, flag) pair
// was driven through the binary in every configuration its verb admits, two runs
// differing only in that flag compared on exit code, output, the bytes of the
// outbox afterwards and wall clock. Six (verb, flag, configuration) triples came
// back inert and they are exactly the ones below; nothing else did. Adding a flag
// whose reader sits behind a condition means adding its rule here, and
// tools/test_light_outbox_flag_surface.sh leg B probes each one in both the inert
// and the enabling configuration.
void refuse_inert_flags(const std::string& verb, const Args& a) {
    auto refuse = [&](std::initializer_list<const char*> flags, const char* why, const char* remedy) {
        std::string named;
        for (const char* f : flags)
            if (a.given.count(f)) { if (!named.empty()) named += " "; named += f; }
        if (named.empty()) return;
        throw std::runtime_error(named + ": INERT as `outbox " + verb + "` was invoked — " + why
                                 + ". Refusing rather than ignoring (S-113): " + remedy);
    };
    if (verb == "enqueue") {
        if (a.have_nonce)
            refuse({"--rpc-port", "--timeout-ms", "--wait"},
                   "an explicit --nonce takes the nonce straight from the flag, so the daemon"
                   " nonce-hint read that --rpc-port, --timeout-ms and --wait bound is never performed",
                   "drop --nonce to use them, or drop the flag(s) this message names");
        else if (!a.have_port)
            refuse({"--timeout-ms", "--wait"},
                   "without --rpc-port no daemon is contacted, so the nonce-hint RPC that"
                   " --timeout-ms and --wait bound is never opened and the nonce comes from local"
                   " reservations alone",
                   "pass --rpc-port <N> to use them, or drop the flag(s) this message names");
    } else if (verb == "reconcile") {
        if (!a.resume)
            refuse({"--state"},
                   "the cached anchor is loaded only on the --resume path, so without --resume the"
                   " file --state names is never opened and every read verifies from genesis",
                   "pass --resume to use it, or drop --state");
    }
}

std::string flag_list(const std::set<std::string>& flags) {
    std::string s;
    for (const auto& f : flags) { if (!s.empty()) s += " "; s += f; }
    return s;
}

Args parse_args(const char* verb, int argc, char** argv) {
    Args a;
    const auto it_v = verb_flags().find(verb);
    if (it_v == verb_flags().end())   // unreachable via cmd_outbox; fail closed rather than accept everything
        throw std::runtime_error(std::string("outbox ") + verb + ": no flag set is declared for this verb");
    const std::set<std::string>& accepted = it_v->second;
    for (int i = 0; i < argc; ++i) {
        std::string k = argv[i];
        auto val = [&](const char* name) -> std::string {
            if (i + 1 >= argc) throw std::runtime_error(std::string("outbox ") + verb + ": " + name + " needs a value");
            return argv[++i];
        };
        if (!accepted.count(k)) {
            // Refused BEFORE the branch that would parse it, so a rejected flag
            // never consumes its value and never reaches a field this verb reads.
            if (a_verb_accepts(k))
                throw std::runtime_error(std::string("outbox ") + verb + ": " + k
                    + " is not accepted by `outbox " + verb + "` (this verb does not act on it; it would have"
                      " been silently ignored) — accepted here: " + flag_list(accepted));
            throw std::runtime_error(std::string("outbox ") + verb + ": unknown arg '" + k + "'");
        }
        a.given.insert(k);   // what the operator WROTE, for refuse_inert_flags below
        if      (k == "--outbox")       a.dir = val("--outbox");
        else if (k == "--genesis")      a.genesis_path = val("--genesis");
        else if (k == "--keyfile")      a.keyfile = val("--keyfile");
        else if (k == "--to")           a.to = val("--to");
        else if (k == "--amount")       { a.amount = arg_u64("--amount", val("--amount")); a.have_amount = true; }
        else if (k == "--fee")          { a.fee = arg_u64("--fee", val("--fee")); a.have_fee = true; }
        else if (k == "--nonce")        { a.nonce = arg_u64("--nonce", val("--nonce")); a.have_nonce = true; }
        else if (k == "--payload-hex")  a.payload_hex = val("--payload-hex");
        else if (k == "--idempotency-key") a.idem_key = val("--idempotency-key");
        else if (k == "--rpc-port")     { a.port = arg_u16("--rpc-port", val("--rpc-port")); a.have_port = true; }
        else if (k == "--max-messages") a.max_messages = arg_u64("--max-messages", val("--max-messages"));
        else if (k == "--older-than")   a.older_than = arg_u64("--older-than", val("--older-than"));
        else if (k == "--wait")         a.wait = arg_u64("--wait", val("--wait"));
        else if (k == "--timeout-ms")   a.timeout_ms = static_cast<uint32_t>(arg_u64("--timeout-ms", val("--timeout-ms")));
        else if (k == "--state")        a.state_path = val("--state");
        else if (k == "--resume")       a.resume = true;
        else if (k == "--now")          a.now = true;
        else if (k == "--json")         a.json_out = true;
        else if (k == "--include-unlocated") a.include_unlocated = true;
        // Unreachable while every flag in the table above has a branch here; a
        // flag added to the table and not to the chain fails closed rather than
        // being accepted and dropped, which is the defect this file just closed.
        else throw std::runtime_error(std::string("outbox ") + verb + ": " + k
                 + " is declared accepted by this verb but has no parser branch");
    }
    if (a.dir.empty()) {
        if (const char* e = std::getenv("DETERM_LIGHT_OUTBOX"); e && *e) a.dir = e;
        else throw std::runtime_error(std::string("outbox ") + verb + ": --outbox <dir> (or $DETERM_LIGHT_OUTBOX) is required");
    }
    // Last, and still inside parse_args: every refusal happens before Lock/Outbox,
    // so a refused invocation creates no directory, no lock and no record.
    refuse_inert_flags(verb, a);
    return a;
}

int fail(const std::string& verb, const std::string& what, int code = 1) {
    std::cerr << "outbox " << verb << ": " << what << "\n";
    return code;
}

int code_for(const std::exception& e) {
    std::string w = e.what();
    if (w.find("locked by another process") != std::string::npos) return EXIT_LOCKED;
    if (w.find("genesis mismatch") != std::string::npos || w.find("does not match this outbox") != std::string::npos) return EXIT_MISMATCH;
    return 1;
}

// An unreadable outbox.meta: only `status` (reports) and `recover` (rebuilds) proceed.
int refuse_if_meta_corrupt(const char* verb, const Outbox& ob) {
    if (!ob.meta_corrupt()) return 0;
    return fail(verb, "outbox.meta is unreadable (" + ob.meta_corrupt_detail() + ") — run `outbox recover`", EXIT_CORRUPT);
}

// The trustless read fetches the `account` cleartext AFTER its successor wait;
// a block that touches this sender in between makes it throw TAMPERED (a benign
// race, DECISION-LOG 2026-09-16 F-4). Re-read at most twice; a persistent
// mismatch surfaces as the error it is.
template <class F> auto with_f4_retry(F read, bool quiet) {
    for (int attempt = 1;; ++attempt) {
        try { return read(); }
        catch (const std::exception& e) {
            std::string w = e.what();
            if (attempt < 3 && w.find("TAMPERED") != std::string::npos && w.find("`account` reply") != std::string::npos) {
                if (!quiet) std::cout << "  (state read raced a new block; re-reading)\n";
                continue;
            }
            throw;
        }
    }
}

// Opens the daemon, applies the timeout, pins genesis. Throws on any failure.
void connect_and_pin(RpcClient& rpc, const Args& a, const determ::chain::GenesisConfig& genesis,
                     const Outbox& ob) {
    if (!rpc.open()) throw std::runtime_error("connect failed: " + rpc.last_error());
    rpc.set_timeout_ms(a.timeout_ms);
    pin_daemon_genesis(rpc, genesis, ob.meta().genesis_hash);
}

int print_status(const Outbox& ob, bool json_out, uint64_t now, const json* extra = nullptr) {
    bool any_corrupt = false;
    if (json_out) {
        json out; out["outbox"] = ob.dir();
        out["sender"] = ob.has_meta() ? ob.meta().sender : "";
        out["genesis_hash"] = ob.has_meta() ? to_hex(ob.meta().genesis_hash) : "";
        out["nonce_floor"] = ob.has_meta() ? ob.meta().nonce_floor : 0;
        json arr = json::array();
        for (auto& [n, s] : ob.slots()) { arr.push_back(slot_to_json(s, now)); any_corrupt |= (s.corrupt || s.status_corrupt); }
        out["slots"] = arr;
        out["meta_corrupt"] = ob.meta_corrupt();
        out["quarantined_nonces"] = ob.quarantined_nonces();
        out["count"] = ob.message_count();
        if (extra) out["report"] = *extra;
        std::cout << out.dump() << "\n";
    } else {
        std::cout << "outbox " << ob.dir() << (ob.has_meta() ? " sender=" + ob.meta().sender : ob.meta_corrupt() ? " META CORRUPT (" + ob.meta_corrupt_detail() + ")" : " (empty)") << "\n";
        for (auto& [n, s] : ob.slots()) { std::cout << "  " << slot_to_line(s, now) << "\n"; any_corrupt |= (s.corrupt || s.status_corrupt); }
        for (uint64_t q : ob.quarantined_nonces()) std::cout << "  nonce=" << q << " QUARANTINED (nonce stays reserved)\n";
    }
    return (any_corrupt || ob.meta_corrupt()) ? EXIT_CORRUPT : 0;
}

// ─── enqueue ────────────────────────────────────────────────────────────────
int cmd_enqueue(int argc, char** argv) {
    Args a;
    try { a = parse_args("enqueue", argc, argv); } catch (const std::exception& e) { return fail("enqueue", e.what()); }
    if (a.genesis_path.empty() || a.keyfile.empty() || a.to.empty() || !a.have_amount || !a.have_fee)
        return fail("enqueue", "--genesis, --keyfile, --to, --amount, --fee are required "
                    "(--payload-hex, --idempotency-key, --max-messages, --json optional; the nonce comes "
                    "from --nonce, or from --rpc-port [--timeout-ms N] [--wait S], or from local reservations)");
    if (a.max_messages == 0 || a.max_messages > HARD_MAX_MESSAGES)
        return fail("enqueue", "--max-messages must be 1.." + std::to_string(HARD_MAX_MESSAGES));
    if (a.idem_key.size() > MAX_IDEMPOTENCY_KEY) return fail("enqueue", "--idempotency-key too long");
    try {
        auto genesis = load_genesis(a.genesis_path);
        const Hash ghash = determ::chain::compute_genesis_hash(genesis);
        auto kf = load_light_keyfile(a.keyfile);
        TransferSpec spec;
        spec.to = a.to; spec.amount = a.amount; spec.fee = a.fee;
        if (!a.payload_hex.empty()) spec.payload = from_hex(a.payload_hex);

        Lock lock(a.dir);
        Outbox ob(a.dir);
        ob.load();
        if (int rc = refuse_if_meta_corrupt("enqueue", ob)) return rc;
        ob.remove_stale_tmp_files();
        if (ob.has_meta() && (ob.meta().genesis_hash != ghash || ob.meta().sender != kf.anon_address)) {
            return fail("enqueue", "this outbox is pinned to sender " + ob.meta().sender + " on genesis "
                        + to_hex(ob.meta().genesis_hash).substr(0, 16) + "…; --keyfile/--genesis do not match this outbox", EXIT_MISMATCH);
        }
        if (!a.idem_key.empty())
            for (auto& [n, s] : ob.slots())
                if (!s.corrupt && s.rec.idempotency_key == a.idem_key) {
                    // A caller retrying after a crash between the publish and the
                    // acknowledgement learns the identity it already holds.
                    std::cout << "already queued: nonce=" << n << " msg_id=" << to_hex(s.rec.active().msg_id)
                              << " tx=" << to_hex(s.rec.active().tx_hash) << " (this idempotency key is present)\n";
                    return EXIT_EXISTS;
                }
        // Capacity is checked BEFORE any write.
        if (ob.message_count() >= a.max_messages)
            return fail("enqueue", "outbox full: " + std::to_string(ob.message_count()) + " messages (cap "
                        + std::to_string(a.max_messages) + "); `outbox prune` or raise --max-messages", EXIT_FULL);

        // Nonce reservation: explicit, else max(daemon hint, local reservations).
        // --rpc-port, --timeout-ms and --wait are read ONLY inside this block, so
        // parse_args has already refused them if --nonce is set or --rpc-port is
        // absent — this is the condition refuse_inert_flags() mirrors, and the two
        // must move together.
        uint64_t nonce = 0;
        if (a.have_nonce) {
            nonce = a.nonce;
        } else {
            uint64_t local = ob.highest_reserved_nonce_plus_one();
            bool have_hint = false; uint64_t hint = 0;
            if (a.have_port) {
                RpcClient rpc(a.port);
                if (rpc.open()) {
                    rpc.set_timeout_ms(a.timeout_ms);
                    try {
                        // The hint read anchors at the chain head, so `--wait` is what
                        // lets its S-042 successor binding complete; dropping it here was
                        // S-112 and the wait is now a required argument of the route.
                        hint = with_f4_retry([&] {
                            return nonce_hint_trustless(rpc, genesis, ghash, kf.anon_address, a.wait);
                        }, a.json_out);
                        have_hint = true;
                    } catch (const std::exception& e) {
                        std::cerr << "outbox enqueue: nonce hint unavailable (" << e.what() << "); using local reservations\n";
                    }
                }
            }
            if (!have_hint && ob.slots().empty() && ob.quarantined_nonces().empty()
                && (!ob.has_meta() || ob.meta().nonce_floor == 0))
                return fail("enqueue", "cannot reserve a nonce offline: no local history and no daemon hint — pass --nonce or --rpc-port");
            nonce = (std::max)(local, have_hint ? hint : 0);
        }
        if (ob.slots().count(nonce))
            return fail("enqueue", "nonce " + std::to_string(nonce) + " is already reserved in this outbox");
        if (ob.has_meta() && nonce < ob.meta().nonce_floor)
            return fail("enqueue", "nonce " + std::to_string(nonce) + " is below this outbox's nonce floor " + std::to_string(ob.meta().nonce_floor)
                        + " (a pruned, proven-consumed nonce is never re-reserved)");
        if (ob.nonce_quarantined(nonce)) {
            if (!a.have_nonce)
                return fail("enqueue", "nonce " + std::to_string(nonce) + " is quarantined; pass --nonce explicitly to re-issue it");
            std::cerr << "outbox enqueue: WARNING nonce " << nonce << " was quarantined (its earlier bytes are unknown and may still "
                         "be applied by the network); whichever message lands first wins\n";
        }

        auto tx = build_transfer(kf, spec, nonce);
        Record r;
        r.genesis_hash = ghash; r.sender = kf.anon_address; r.nonce = nonce;
        r.tx_type = static_cast<uint8_t>(tx.type); r.created = now_unix(); r.updated = r.created;
        r.idempotency_key = a.idem_key;
        Alternate alt; alt.kind = AltKind::ORIGINAL; alt.fee = tx.fee; alt.tx_hash = tx.hash;
        alt.msg_id = derive_msg_id(ghash, kf.anon_address, nonce, tx.hash);
        tx.encode_frame(alt.frame);
        r.alternates.push_back(std::move(alt));
        if (!ob.has_meta()) {   // pin the directory only once every refusal above has passed
            Meta m; m.genesis_hash = ghash; m.sender = kf.anon_address; m.nonce_floor = 0;
            ob.write_meta_new(m);
        }
        ob.write_slot_new(r);   // durable before the acknowledgement below
        trace_event("ack");
        if (a.json_out) {
            json out = {{"queued_locally", true}, {"nonce", nonce}, {"msg_id", to_hex(r.alternates[0].msg_id)},
                        {"tx_hash", to_hex(tx.hash)}, {"outbox", a.dir}, {"durable", true}};
            std::cout << out.dump() << "\n";
        } else {
            std::cout << "queued locally: nonce=" << nonce << " msg_id=" << to_hex(r.alternates[0].msg_id)
                      << " tx=" << to_hex(tx.hash) << " (durable in " << a.dir << ")\n";
        }
        return 0;
    } catch (const std::exception& e) {
        return fail("enqueue", e.what(), code_for(e));
    }
}

// ─── submit ─────────────────────────────────────────────────────────────────
int cmd_submit(int argc, char** argv) {
    Args a;
    try { a = parse_args("submit", argc, argv); } catch (const std::exception& e) { return fail("submit", e.what()); }
    if (a.genesis_path.empty() || !a.have_port) return fail("submit", "--genesis and --rpc-port are required (--now, --timeout-ms, --json optional)");
    try {
        auto genesis = load_genesis(a.genesis_path);
        Lock lock(a.dir);
        Outbox ob(a.dir);
        ob.load();
        if (int rc = refuse_if_meta_corrupt("submit", ob)) return rc;
        ob.remove_stale_tmp_files();
        if (!ob.has_meta()) { std::cout << "outbox submit: nothing queued\n"; return 0; }
        const uint64_t now = now_unix();
        RpcClient rpc(a.port);
        SubmitOptions opt; opt.force_now = a.now;
        try {
            connect_and_pin(rpc, a, genesis, ob);
            try { json st = rpc.call("status", json::object()); if (st.is_object() && st.contains("height")) opt.head_hint = st["height"].get<uint64_t>(); } catch (...) {}
        } catch (const std::exception& e) {
            std::string w = e.what();
            if (w.find("genesis mismatch") != std::string::npos) return fail("submit", w, EXIT_MISMATCH);
            // Daemon unreachable: stamp the due slots so status shows why nothing moved.
            for (auto& [n, s] : ob.slots()) {
                if (s.corrupt || s.status_corrupt || !s.rec.sendable()) continue;
                if (!a.now && s.rec.next_retry > now) continue;
                s.rec.last_outcome = Outcome::TRANSPORT; s.rec.last_attempt = now;
                s.rec.consecutive_failures = std::min<uint32_t>(s.rec.consecutive_failures + 1, UINT32_MAX - 1);
                s.rec.next_retry = now + backoff_seconds(s.rec.consecutive_failures);
                s.rec.last_error = w.substr(0, MAX_LAST_ERROR);
                ob.write_slot_replace(s.rec, now);
            }
            std::cerr << "outbox submit: daemon unreachable — " << w << " (queued slots kept; retry later)\n";
            return print_status(ob, a.json_out, now) == EXIT_CORRUPT ? EXIT_CORRUPT : 0;
        }
        SubmitReport rep = submit_due(ob, rpc, opt, now, [&](const std::string& l) { if (!a.json_out) std::cout << "  " << l << "\n"; });
        json rj = {{"sent", rep.sent}, {"acked", rep.acked}, {"pending", rep.pending}, {"stale", rep.stale},
                   {"reply_lost", rep.lost}, {"rejected", rep.rejected}, {"not_due", rep.skipped_not_due},
                   {"node_config_error", rep.node_config_error}, {"transport_error", rep.transport_error}};
        int rc = print_status(ob, a.json_out, now, &rj);
        if (rep.node_config_error) return EXIT_NODE_CONFIG;
        return rc;
    } catch (const std::exception& e) {
        return fail("submit", e.what(), code_for(e));
    }
}

// ─── reconcile ──────────────────────────────────────────────────────────────
int cmd_reconcile(int argc, char** argv) {
    Args a;
    try { a = parse_args("reconcile", argc, argv); } catch (const std::exception& e) { return fail("reconcile", e.what()); }
    if (a.genesis_path.empty() || !a.have_port) return fail("reconcile", "--genesis and --rpc-port are required (--wait, --timeout-ms, --json and --resume [--state <path>] optional)");
    try {
        auto genesis = load_genesis(a.genesis_path);
        auto seed = build_genesis_committee(genesis);
        Lock lock(a.dir);
        Outbox ob(a.dir);
        ob.load();
        if (int rc = refuse_if_meta_corrupt("reconcile", ob)) return rc;
        ob.remove_stale_tmp_files();
        if (!ob.has_meta()) { std::cout << "outbox reconcile: nothing queued\n"; return 0; }
        const uint64_t now = now_unix();
        RpcClient rpc(a.port);
        connect_and_pin(rpc, a, genesis, ob);
        ReconcileOptions opt; opt.resume = a.resume; opt.state_path = a.state_path; opt.wait_seconds = a.wait;
        ReconcileReport rep = with_f4_retry([&] {
            return reconcile_all(ob, rpc, genesis, seed, opt, now,
                                 [&](const std::string& l) { if (!a.json_out) std::cout << "  " << l << "\n"; });
        }, a.json_out);
        json rj = {{"verified_next_nonce", rep.verified_next_nonce}, {"verified_index", rep.verified_index},
                   {"verified_balance", rep.verified_balance}, {"finalized_applied", rep.finalized_applied},
                   {"finalized_skipped", rep.finalized_skipped}, {"included", rep.included}, {"consumed", rep.consumed},
                   {"orphaned", rep.orphaned}, {"rearmed", rep.rearmed}, {"unverifiable", rep.unverifiable},
                   {"unchanged", rep.unchanged}, {"gap", rep.gap}, {"gap_nonce", rep.gap_nonce}, {"notes", rep.lines}};
        int rc = print_status(ob, a.json_out, now, &rj);
        if (rc == 0 && rep.unverifiable > 0) rc = EXIT_CORRUPT;
        return rc;
    } catch (const std::exception& e) {
        return fail("reconcile", e.what(), code_for(e));
    }
}

// ─── status ─────────────────────────────────────────────────────────────────
int cmd_status(int argc, char** argv) {
    Args a;
    try { a = parse_args("status", argc, argv); } catch (const std::exception& e) { return fail("status", e.what()); }
    try {
        Outbox ob(a.dir);
        ob.load();            // lock-free, read-only, never deletes
        return print_status(ob, a.json_out, now_unix());
    } catch (const std::exception& e) {
        return fail("status", e.what());
    }
}

// ─── replace (fee bump or re-issue at the same nonce) ───────────────────────
int cmd_replace(int argc, char** argv) {
    Args a;
    try { a = parse_args("replace", argc, argv); } catch (const std::exception& e) { return fail("replace", e.what()); }
    if (a.genesis_path.empty() || a.keyfile.empty() || !a.have_nonce || !a.have_fee)
        return fail("replace", "--genesis, --keyfile, --nonce, --fee are required; --to/--amount/--payload-hex re-issue a different message at the same nonce");
    try {
        auto genesis = load_genesis(a.genesis_path);
        const Hash ghash = determ::chain::compute_genesis_hash(genesis);
        auto kf = load_light_keyfile(a.keyfile);
        Lock lock(a.dir);
        Outbox ob(a.dir);
        ob.load();
        if (int rc = refuse_if_meta_corrupt("replace", ob)) return rc;
        ob.remove_stale_tmp_files();
        if (!ob.has_meta() || ob.meta().genesis_hash != ghash || ob.meta().sender != kf.anon_address)
            return fail("replace", "--keyfile/--genesis do not match this outbox", EXIT_MISMATCH);
        auto it = ob.slots().find(a.nonce);
        if (it == ob.slots().end()) return fail("replace", "no slot at nonce " + std::to_string(a.nonce));
        Slot& s = it->second;
        if (s.corrupt) return fail("replace", "slot " + std::to_string(a.nonce) + " is CORRUPT — run `outbox recover` first", EXIT_CORRUPT);
        Record& r = s.rec;
        if (r.terminal()) return fail("replace", "slot " + std::to_string(a.nonce) + " is terminal (" + std::string(state_name(r.state)) + "/" + apply_name(r.apply) + ")");
        if (r.alternates.size() >= MAX_ALTERNATES) return fail("replace", "slot already holds " + std::to_string(MAX_ALTERNATES) + " alternates");
        const Alternate& cur = r.active();
        determ::chain::Transaction cur_tx = determ::chain::Transaction::decode_frame(cur.frame.data(), cur.frame.size());
        TransferSpec spec;
        spec.to = a.to.empty() ? cur_tx.to : a.to;
        spec.amount = a.have_amount ? a.amount : cur_tx.amount;
        spec.payload = a.payload_hex.empty() ? cur_tx.payload : from_hex(a.payload_hex);
        spec.fee = a.fee;
        const bool same_content = (spec.to == cur_tx.to && spec.amount == cur_tx.amount && spec.payload == cur_tx.payload);
        if (spec.fee <= cur.fee)
            return fail("replace", "a replacement must raise the fee (current " + std::to_string(cur.fee) + "): the daemon replaces a pending "
                        "incumbent only on a strict fee increase, so equal-or-lower bytes would never enter a mempool");
        auto tx = build_transfer(kf, spec, a.nonce);
        for (auto& alt : r.alternates) if (alt.tx_hash == tx.hash) return fail("replace", "identical bytes already present in this slot");
        Alternate alt;
        alt.kind = same_content ? AltKind::FEE_BUMP : AltKind::REISSUE;
        alt.fee = tx.fee; alt.tx_hash = tx.hash;
        alt.msg_id = same_content ? cur.msg_id : derive_msg_id(ghash, kf.anon_address, a.nonce, tx.hash);
        tx.encode_frame(alt.frame);
        r.alternates.push_back(std::move(alt));
        // The new bytes are unsent: the slot becomes sendable again while every
        // earlier alternate stays watched (the ledger applies at most one).
        r.state = (r.state == State::INCLUDED) ? State::INCLUDED : State::QUEUED;
        r.next_retry = now_unix(); r.consecutive_failures = 0;
        r.last_error.clear();
        if (!same_content) {   // a new message starts with a fresh skip budget; the earlier
            r.apply = Apply::UNKNOWN; r.skipped_count = 0;   // alternate's counted inclusion stays recorded
        }
        ob.write_slot_replace(r, now_unix());
        trace_event("ack");
        std::cout << (same_content ? "fee bump" : "re-issue") << " recorded: nonce=" << a.nonce
                  << " msg_id=" << to_hex(r.alternates.back().msg_id) << " tx=" << to_hex(tx.hash)
                  << " (" << r.alternates.size() << " alternates watched)\n";
        if (!same_content)
            std::cout << "note: the earlier message at this nonce may still be applied by the network; whichever lands first wins\n";
        return 0;
    } catch (const std::exception& e) {
        return fail("replace", e.what(), code_for(e));
    }
}

// ─── prune ──────────────────────────────────────────────────────────────────
int cmd_prune(int argc, char** argv) {
    Args a;
    try { a = parse_args("prune", argc, argv); } catch (const std::exception& e) { return fail("prune", e.what()); }
    try {
        Lock lock(a.dir);
        Outbox ob(a.dir);
        ob.load();
        if (int rc = refuse_if_meta_corrupt("prune", ob)) return rc;
        ob.remove_stale_tmp_files();
        if (!ob.has_meta()) { std::cout << "outbox prune: nothing to prune\n"; return 0; }
        const uint64_t now = now_unix();
        std::vector<uint64_t> victims;
        for (auto& [n, s] : ob.slots()) {
            if (s.corrupt || s.status_corrupt) continue;
            const Record& r = s.rec;
            bool proven_consumed = (r.state == State::FINALIZED && r.apply == Apply::APPLIED)
                                || (r.state == State::CONSUMED && a.include_unlocated);
            if (!proven_consumed) continue;
            if (r.updated + a.older_than > now) continue;
            victims.push_back(n);
        }
        size_t removed = 0;
        for (uint64_t n : victims) {
            // Floor first (durable), then the file: a crash in between keeps the
            // record, never re-opens the nonce.
            Meta m = ob.meta();
            if (m.nonce_floor < n + 1) { m.nonce_floor = n + 1; ob.write_meta_replace(m); }
            ob.remove_slot_file(n);
            ++removed;
        }
        const size_t dropped = ob.remove_quarantined_below(ob.meta().nonce_floor);   // proven consumed, reserve nothing
        if (a.json_out) std::cout << json{{"pruned", removed}, {"quarantined_dropped", dropped}, {"remaining", ob.message_count()}, {"nonce_floor", ob.meta().nonce_floor}}.dump() << "\n";
        else std::cout << "pruned " << removed << " proven-consumed slot(s) and " << dropped << " quarantined file(s) below the floor; "
                       << ob.message_count() << " remain; nonce_floor=" << ob.meta().nonce_floor << "\n";
        return 0;
    } catch (const std::exception& e) {
        return fail("prune", e.what(), code_for(e));
    }
}

// ─── recover ────────────────────────────────────────────────────────────────
int cmd_recover(int argc, char** argv) {
    Args a;
    try { a = parse_args("recover", argc, argv); } catch (const std::exception& e) { return fail("recover", e.what()); }
    try {
        Lock lock(a.dir);
        Outbox ob(a.dir);
        ob.load();
        ob.remove_stale_tmp_files();
        const uint64_t now = now_unix();
        size_t rebuilt = 0, quarantined = 0;
        std::vector<uint64_t> to_quarantine;
        for (auto& [n, s] : ob.slots()) {
            if (s.status_corrupt) {
                // The bytes are intact (immutable hash verified); the status is
                // unknowable, so the slot resumes as UNKNOWN and re-sends the same bytes.
                Record r = s.rec;
                r.state = State::UNKNOWN; r.apply = Apply::UNKNOWN;
                r.next_retry = now; r.consecutive_failures = 0;
                r.last_error = "status section rebuilt by `outbox recover`";
                ob.write_slot_replace(r, now);
                ++rebuilt;
                std::cout << "slot " << n << ": status rebuilt (bytes intact) — state UNKNOWN\n";
            } else if (s.corrupt) {
                to_quarantine.push_back(n);
            }
        }
        for (uint64_t n : to_quarantine) {
            ob.quarantine_slot(n, now);
            ++quarantined;
            std::cout << "slot " << n << ": bytes unreadable — quarantined as *.corrupt-" << now
                      << "; the nonce stays reserved (re-issue it with `outbox enqueue --nonce " << n << "`)\n";
        }
        if (ob.meta_corrupt()) {
            // Every intact record carries the pin; the nonce floor is lost (0 only
            // loses a refusal — it never blocks a nonce the chain still expects).
            auto it = std::find_if(ob.slots().begin(), ob.slots().end(), [](auto& kv) { return !kv.second.corrupt; });
            if (it == ob.slots().end())
                return fail("recover", "outbox.meta is unreadable and no intact record remains to rebuild it from (" + ob.meta_corrupt_detail() + ")", EXIT_CORRUPT);
            Meta m; m.genesis_hash = it->second.rec.genesis_hash; m.sender = it->second.rec.sender; m.nonce_floor = 0;
            ob.write_meta_replace(m);
            std::cout << "outbox.meta rebuilt from slot " << it->first << " (sender " << m.sender << "); WARNING the nonce floor is lost — "
                         "pass --rpc-port on the next enqueue so the verified next_nonce guides the reservation\n";
        }
        std::cout << "recover: " << rebuilt << " rebuilt, " << quarantined << " quarantined\n";
        return 0;
    } catch (const std::exception& e) {
        return fail("recover", e.what(), code_for(e));
    }
}

} // namespace

int cmd_outbox(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "usage: determ-light outbox <enqueue|submit|reconcile|status|replace|prune|recover> [options]\n";
        return 1;
    }
    std::string verb = argv[0];
    int sub_argc = argc - 1; char** sub_argv = argv + 1;
    if (verb == "enqueue")   return cmd_enqueue(sub_argc, sub_argv);
    if (verb == "submit")    return cmd_submit(sub_argc, sub_argv);
    if (verb == "reconcile") return cmd_reconcile(sub_argc, sub_argv);
    if (verb == "status")    return cmd_status(sub_argc, sub_argv);
    if (verb == "replace")   return cmd_replace(sub_argc, sub_argv);
    if (verb == "prune")     return cmd_prune(sub_argc, sub_argv);
    if (verb == "recover")   return cmd_recover(sub_argc, sub_argv);
    std::cerr << "outbox: unknown verb '" << verb << "' (enqueue|submit|reconcile|status|replace|prune|recover)\n";
    return 1;
}

} // namespace determ::light
