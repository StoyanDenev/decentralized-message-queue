// light/outbox_selftest.cpp — offline gates for the outbox (no daemon).
//
//   selftest-outbox-record    the DOX1/DOM1 codec: round-trip, field-named
//                             truncation, per-section corruption, trailing bytes.
//   selftest-outbox-classify  the submit-error classifier over the daemon's
//                             real error strings (as RpcClient wraps them).
//   selftest-outbox-core      the REAL submit/reconcile cores driven over an
//                             in-process, committee-signed fixture chain
//                             (genesis + signed blocks + Merkle state proofs)
//                             served through a virtual RpcClient, so the
//                             identity / finality / attribution rules are
//                             gated at the layer that enforces them:
//                             lost reply → identical bytes re-sent, exactly one
//                             application; INCLUDED at the head is not
//                             FINALIZED; SKIPPED is proven from the nonce, not
//                             from inclusion; an orphaned inclusion re-arms;
//                             a consumed nonce with no located inclusion is
//                             CONSUMED/UNLOCATED, never lost; fee-bump
//                             attribution; retryable rejection backoff; the
//                             daemon-config outcome; the nonce GAP report.
#include "outbox_cli.hpp"
#include "outbox.hpp"
#include "verify.hpp"
#include "trustless_read.hpp"
#include <determ/chain/block.hpp>
#include <determ/chain/genesis.hpp>
#include <determ/crypto/keys.hpp>
#include <determ/crypto/merkle.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/crypto/ed25519/ed25519.h>
#include <algorithm>
#include <memory>
#include <filesystem>
#include <iostream>
#include <set>

using json = nlohmann::json;
using namespace determ::light::outbox;
using determ::chain::Block;
using determ::chain::Transaction;

namespace determ::light {
namespace {

struct Checker {
    int pass = 0, fail = 0;
    void operator()(bool ok, const std::string& what) {
        if (ok) { std::cout << "  PASS: " << what << "\n"; ++pass; }
        else    { std::cout << "  FAIL: " << what << "\n"; ++fail; }
    }
    int finish(const char* name) {
        std::cout << "\n  " << pass << " pass / " << fail << " fail\n";
        std::cout << (fail == 0 ? "  PASS: " : "  FAIL: ") << name << "\n";
        return fail == 0 ? 0 : 1;
    }
};

LightKeyfile fixture_keyfile(uint8_t seed_byte) {
    LightKeyfile kf;
    kf.key.priv_seed.fill(seed_byte);
    uint8_t pk[32];
    determ_ed25519_pubkey_from_seed(kf.key.priv_seed.data(), pk);
    std::copy_n(pk, 32, kf.key.pub.begin());
    kf.anon_address = "0x" + to_hex(kf.key.pub);
    return kf;
}

std::string tmp_dir(const char* tag) {
    auto p = std::filesystem::temp_directory_path() / ("determ-light-" + std::string(tag) + "-" + std::to_string(now_unix()) + "-" + std::to_string(std::rand()));
    std::filesystem::remove_all(p);
    return p.string();
}

// ─── the fixture daemon ─────────────────────────────────────────────────────
class FixtureRpc : public RpcClient {
public:
    struct Acct { uint64_t balance{0}; uint64_t next_nonce{0}; };

    FixtureRpc(const LightKeyfile& sender, uint64_t funded)
        : RpcClient(uint16_t{0}), sender_(sender.anon_address) {
        committee_key_.priv_seed.fill(0x11);
        uint8_t pk[32];
        determ_ed25519_pubkey_from_seed(committee_key_.priv_seed.data(), pk);
        std::copy_n(pk, 32, committee_key_.pub.begin());
        cfg_.chain_id = "outbox-selftest";
        cfg_.m_creators = 1; cfg_.k_block_sigs = 1;
        cfg_.initial_creators.push_back({"n1", committee_key_.pub, 1000, ""});
        cfg_.initial_balances.push_back({sender_, funded});
        // Genesis carries NO state_root (make_genesis_block never sets it; its
        // hash is what compute_genesis_hash pins), so the fixture mints one
        // empty committee-signed block right away: every read then anchors on
        // a block that has a state_root (S-033 active).
        Block g = determ::chain::make_genesis_block(cfg_);
        acct_ = Acct{funded, 0};
        blocks_.push_back(g);
        state_after_.push_back(acct_);
        mint_empty();
    }
    const determ::chain::GenesisConfig& genesis() const { return cfg_; }
    std::map<std::string, PubKey> committee_seed() const { return build_genesis_committee(cfg_); }
    Hash genesis_hash() const { return determ::chain::compute_genesis_hash(cfg_); }
    uint64_t height() const { return blocks_.size(); }
    const Acct& acct() const { return acct_; }
    size_t mempool_size() const { return mempool_.size(); }
    size_t submits() const { return submits_; }
    const std::vector<Hash>& submitted_hashes() const { return submitted_hashes_; }

    // knobs
    std::string submit_error;      // non-empty: submit_tx throws exactly this text (already wrapped)
    bool        drop_reply{false}; // submit_tx: accept, then "lose" the reply
    bool        auto_mint_includes_mempool{false};   // block minted during a successor wait carries the mempool
    bool        auto_mint_applies{true};

    // A foreign tx from the sender (A1 violation) consumes the next nonce.
    void consume_nonce_externally() {
        Transaction tx; tx.type = determ::chain::TxType::TRANSFER; tx.from = sender_; tx.to = sender_;
        tx.amount = 0; tx.fee = 0; tx.nonce = acct_.next_nonce; tx.hash = tx.compute_hash();
        // The hash is content-derived; the fixture never verifies sigs.
        mint({tx}, /*apply=*/true);
    }
    // Mint the next block: `include` = the mempool txs whose nonce is next
    // (the producer's sequential rule); `apply` = advance the sender's nonce
    // and debit (false models chain.cpp:1688 — in the block, not applied).
    void mint_from_mempool(bool apply) {
        std::vector<Transaction> txs;
        for (auto& tx : mempool_) if (tx.nonce == acct_.next_nonce) { txs.push_back(tx); break; }
        mint(txs, apply);
        for (auto& tx : txs) mempool_.erase(std::remove_if(mempool_.begin(), mempool_.end(),
            [&](const Transaction& m) { return m.hash == tx.hash; }), mempool_.end());
    }
    void mint_empty() { mint({}, true); }
    // S-048 depth-1 reorg: the tip is replaced by a different committee-signed
    // block at the same height carrying no transactions; the tip's txs are dropped.
    void reorg_tip_without_txs() {
        Block old = blocks_.back();
        blocks_.pop_back(); state_after_.pop_back();
        acct_ = state_after_.back();
        mint({}, true, old.timestamp + 7);
        stale_ = old;
    }
    // A Byzantine (or lagging) daemon that keeps serving the ORPHANED block at
    // its height, and locates the tx in it, while its headers follow the
    // canonical chain. The successor binding must refuse to finalize on it.
    bool serve_stale_block{false};
    // A daemon whose `tx` hint names a height it cannot serve (past its head).
    uint64_t bogus_tx_height{0};
    // ... for ONE hash only (the other alternates' hints stay honest).
    Hash unverifiable_hash{};
    // S-048 depth-1 reorg where the sibling block carries the SAME txs (both
    // creators drew them from the mempool) and applies them: the tip's txs are
    // NOT dropped, only their block is; `stale_` keeps the orphaned body.
    void reorg_tip_keeping_txs() {
        Block old = blocks_.back();
        blocks_.pop_back(); state_after_.pop_back();
        acct_ = state_after_.back();
        mint(old.transactions, true, old.timestamp + 7);
        stale_ = old;
    }

    json call(const std::string& method, const json& params) override {
        if (method == "headers") {
            uint64_t from = params.value("from", uint64_t{0});
            uint32_t count = params.value("count", uint32_t{1});
            if (from == blocks_.size() && auto_mint_on_query_) {
                // "the chain advanced one block while the reader waited"
                if (auto_mint_includes_mempool) mint_from_mempool(auto_mint_applies); else mint_empty();
            }
            json arr = json::array();
            for (uint64_t i = from; i < blocks_.size() && i < from + count; ++i) arr.push_back(header_json(i));
            return json{{"headers", arr}, {"from", from}, {"count", count}, {"height", blocks_.size()}};
        }
        if (method == "block") {
            uint64_t idx = params.value("index", uint64_t{0});
            if (serve_stale_block && idx == stale_.index) {
                json j = stale_.to_json(); j["block_hash"] = to_hex(stale_.compute_hash()); return j;
            }
            if (idx >= blocks_.size()) return nullptr;
            return block_json(idx);
        }
        if (method == "status") return json{{"height", blocks_.size()}};
        if (method == "nonce") return json{{"domain", sender_}, {"next_nonce", acct_.next_nonce}};
        if (method == "account") {
            // Served from the same committed view as the last state_proof (a
            // daemon whose cleartext read is consistent with its proof). The live
            // node reads the CURRENT view for both, so a block that touches the
            // account between the two calls makes the real reader throw TAMPERED
            // (a benign race, recorded as a separate finding); the fixture does
            // not reproduce that race so the INCLUDED-at-head leg is testable.
            const Acct& a = proof_acct_valid_ ? proof_acct_ : acct_;
            return json{{"address", sender_}, {"balance", a.balance}, {"next_nonce", a.next_nonce}};
        }
        if (method == "state_proof") {
            proof_acct_ = acct_; proof_acct_valid_ = true;
            auto leaves = leaves_for(acct_);
            std::vector<Hash> proof = determ::crypto::merkle_proof(leaves, 0);
            json ph = json::array();
            for (auto& h : proof) ph.push_back(to_hex(h));
            return json{{"state_root", to_hex(blocks_.back().state_root)},
                        {"key_bytes", to_hex(leaves[0].key.data(), leaves[0].key.size())},
                        {"value_hash", to_hex(leaves[0].value_hash)}, {"target_index", 0},
                        {"leaf_count", leaves.size()}, {"proof", ph}, {"height", blocks_.size()}};
        }
        if (method == "tx") {
            Hash target = from_hex_arr<32>(params.value("hash", std::string(64, '0')));
            if (bogus_tx_height || (unverifiable_hash != Hash{} && target == unverifiable_hash))
                return json{{"tx", nullptr}, {"block_index", bogus_tx_height ? bogus_tx_height : 999}, {"block_hash", std::string(64, '0')}, {"timestamp", 0}};
            if (serve_stale_block)
                for (auto& tx : stale_.transactions)
                    if (tx.hash == target)
                        return json{{"tx", tx.to_json()}, {"block_index", stale_.index},
                                    {"block_hash", to_hex(stale_.compute_hash())}, {"timestamp", stale_.timestamp}};
            for (size_t i = blocks_.size(); i > 0; --i)
                for (auto& tx : blocks_[i - 1].transactions)
                    if (tx.hash == target)
                        return json{{"tx", tx.to_json()}, {"block_index", blocks_[i - 1].index},
                                    {"block_hash", to_hex(blocks_[i - 1].compute_hash())}, {"timestamp", blocks_[i - 1].timestamp}};
            return nullptr;
        }
        if (method == "submit_tx") {
            ++submits_;
            Transaction tx = Transaction::from_json(params.at("tx"));
            submitted_hashes_.push_back(tx.hash);
            if (!submit_error.empty()) throw std::runtime_error(submit_error);
            if (tx.hash != tx.compute_hash()) throw std::runtime_error("RPC error on submit_tx: \"submitted tx hash mismatch\"");
            if (tx.nonce < acct_.next_nonce)
                throw std::runtime_error("RPC error on submit_tx: \"submitted tx has stale nonce " + std::to_string(tx.nonce)
                                         + " (expected >= " + std::to_string(acct_.next_nonce) + ")\"");
            auto it = std::find_if(mempool_.begin(), mempool_.end(), [&](const Transaction& m) { return m.from == tx.from && m.nonce == tx.nonce; });
            if (it != mempool_.end()) {
                if (it->fee >= tx.fee) throw std::runtime_error("RPC error on submit_tx: \"incumbent tx at (from, nonce) has equal-or-higher fee\"");
                mempool_.erase(it);
            }
            mempool_.push_back(tx);
            if (drop_reply) throw std::runtime_error("no response for submit_tx (daemon closed connection or timed out)");
            return json{{"status", "queued"}, {"hash", to_hex(tx.hash)}};
        }
        throw std::runtime_error("RPC error on " + method + ": \"Unknown method: " + method + "\"");
    }

private:
    std::vector<determ::crypto::MerkleLeaf> leaves_for(const Acct& a) const {
        determ::crypto::MerkleLeaf l0, l1;
        l0.key.assign({'a', ':'}); l0.key.insert(l0.key.end(), sender_.begin(), sender_.end());
        determ::crypto::SHA256Builder b; b.append(a.balance); b.append(a.next_nonce);
        l0.value_hash = b.finalize();
        l1.key.assign({'a', ':', 'n', '1'});
        determ::crypto::SHA256Builder b1; b1.append(uint64_t{1000}); b1.append(uint64_t{0});
        l1.value_hash = b1.finalize();
        return {l0, l1};
    }
    Hash state_root_for(const Acct& a) const { return determ::crypto::merkle_root(leaves_for(a)); }

    void mint(std::vector<Transaction> txs, bool apply, int64_t ts = 0) {
        Block b;
        b.index = blocks_.size();
        b.prev_hash = blocks_.back().compute_hash();
        b.timestamp = ts ? ts : static_cast<int64_t>(1'700'000'000 + b.index * 10);
        b.creators = {"n1"};
        std::vector<Hash> hashes;
        for (auto& tx : txs) hashes.push_back(tx.hash);
        b.creator_tx_lists = {hashes};
        b.creator_ed_sigs = {Signature{}};
        b.creator_dh_inputs = {Hash{}};
        b.creator_dh_secrets = {Hash{}};
        std::set<Hash> u(hashes.begin(), hashes.end());
        determ::crypto::SHA256Builder tr; for (auto& h : u) tr.append(h);
        b.tx_root = tr.finalize();
        b.transactions = txs;
        if (apply) for (auto& tx : txs) if (tx.from == sender_ && tx.nonce == acct_.next_nonce) {
            uint64_t cost = tx.amount + tx.fee;
            if (acct_.balance >= cost) { acct_.balance -= cost; acct_.next_nonce++; }
        }
        b.state_root = state_root_for(acct_);
        Hash digest = light_compute_block_digest(b);
        b.creator_block_sigs = {determ::crypto::sign(committee_key_, digest.data(), digest.size())};
        blocks_.push_back(b);
        state_after_.push_back(acct_);
    }
    json block_json(uint64_t i) const {
        json j = blocks_[i].to_json();
        j["block_hash"] = to_hex(blocks_[i].compute_hash());
        return j;
    }
    json header_json(uint64_t i) const {
        json h = block_json(i);
        h.erase("transactions"); h.erase("cross_shard_receipts"); h.erase("inbound_receipts"); h.erase("initial_state");
        return h;
    }

    std::string sender_;
    determ::crypto::NodeKey committee_key_;
    determ::chain::GenesisConfig cfg_;
    std::vector<Block> blocks_;
    std::vector<Acct> state_after_;
    Acct acct_;
    std::vector<Transaction> mempool_;
    size_t submits_{0};
    std::vector<Hash> submitted_hashes_;
    bool auto_mint_on_query_{true};
    Acct proof_acct_; bool proof_acct_valid_{false};
    Block stale_;
};

Record make_record(const LightKeyfile& kf, const Hash& ghash, uint64_t nonce, uint64_t amount, uint64_t fee,
                   const std::string& to, std::vector<uint8_t> payload = {}) {
    TransferSpec spec; spec.to = to; spec.amount = amount; spec.fee = fee; spec.payload = std::move(payload);
    Transaction tx = build_transfer(kf, spec, nonce);
    Record r;
    r.genesis_hash = ghash; r.sender = kf.anon_address; r.nonce = nonce;
    r.tx_type = static_cast<uint8_t>(tx.type); r.created = 1'700'000'000; r.updated = r.created;
    Alternate a; a.kind = AltKind::ORIGINAL; a.fee = fee; a.tx_hash = tx.hash;
    a.msg_id = derive_msg_id(ghash, kf.anon_address, nonce, tx.hash);
    tx.encode_frame(a.frame);
    r.alternates.push_back(std::move(a));
    return r;
}

void add_alternate(Record& r, const LightKeyfile& kf, uint64_t fee, bool same_content) {
    Transaction cur = Transaction::decode_frame(r.active().frame.data(), r.active().frame.size());
    TransferSpec spec; spec.to = cur.to; spec.amount = same_content ? cur.amount : cur.amount + 1; spec.fee = fee; spec.payload = cur.payload;
    Transaction tx = build_transfer(kf, spec, r.nonce);
    Alternate a; a.kind = same_content ? AltKind::FEE_BUMP : AltKind::REISSUE; a.fee = fee; a.tx_hash = tx.hash;
    a.msg_id = same_content ? r.active().msg_id : derive_msg_id(r.genesis_hash, kf.anon_address, r.nonce, tx.hash);
    tx.encode_frame(a.frame);
    r.alternates.push_back(std::move(a));
    r.state = State::QUEUED; r.next_retry = 0;
    if (!same_content) { r.apply = Apply::UNKNOWN; r.skipped_count = 0; }   // as cmd_replace: fresh budget, `finalized_height` kept
}

} // namespace

// ─── selftest-outbox-record ────────────────────────────────────────────────
int cmd_selftest_outbox_record(int, char**) {
    Checker check;
    auto kf = fixture_keyfile(0x42);
    Hash ghash{}; ghash.fill(0xab);
    const std::string to = "0x" + std::string(64, 'c');
    Record r = make_record(kf, ghash, 7, 100, 3, to, {0xde, 0xad});
    r.state = State::SUBMITTED; r.attempts = 3; r.last_error = "mempool: full"; r.first_ack = 5; r.included_height = 0;
    auto bytes = encode_record(r);
    Record back = decode_record(bytes);
    check(back.nonce == 7 && back.sender == kf.anon_address && back.genesis_hash == ghash
          && back.state == State::SUBMITTED && back.attempts == 3 && back.last_error == "mempool: full"
          && back.alternates.size() == 1 && back.alternates[0].tx_hash == r.alternates[0].tx_hash
          && back.alternates[0].frame == r.alternates[0].frame && back.alternates[0].msg_id == r.alternates[0].msg_id,
          "DOX1 round-trip preserves every field (identity, bytes, status)");
    check(encode_record(back) == bytes, "re-encoding the decoded record is byte-identical (canonical)");
    // Field-named truncation at every prefix length must throw and name a field.
    bool all_named = true; size_t n_ok = 0;
    for (size_t cut = 0; cut < bytes.size(); cut += 7) {
        std::vector<uint8_t> t(bytes.begin(), bytes.begin() + cut);
        try { (void)decode_record(t); all_named = false; break; }
        catch (const std::exception& e) {
            std::string w = e.what();
            if (w.find("truncated at '") == std::string::npos && w.find("hash mismatch") == std::string::npos
                && w.find("status section:") == std::string::npos && w.find("bad magic") == std::string::npos
                && w.find("implausible") == std::string::npos && w.find("length") == std::string::npos) { all_named = false; break; }
            ++n_ok;
        }
    }
    check(all_named && n_ok > 10, "every truncation is refused with a field-named diagnostic (" + std::to_string(n_ok) + " prefixes)");
    // Corrupt a byte in the STATUS section → recoverable class.
    {
        auto c = bytes; c[bytes.size() - 40] ^= 0x01;   // inside the status body
        std::string w;
        try { (void)decode_record(c); } catch (const std::exception& e) { w = e.what(); }
        check(w.rfind("status section:", 0) == 0, "a corrupt status section is refused as 'status section:' (recoverable)");
        bool imm_ok = false;
        try { Record im = decode_record_immutable(c); imm_ok = im.alternates.size() == 1 && im.nonce == 7; } catch (...) {}
        check(imm_ok, "the immutable section (bytes) still decodes when only the status is corrupt");
    }
    // Corrupt a byte in the IMMUTABLE section → refused as lost bytes.
    {
        auto c = bytes; c[60] ^= 0x01;   // inside genesis_hash/sender area
        std::string w;
        try { (void)decode_record(c); } catch (const std::exception& e) { w = e.what(); }
        check(!w.empty() && w.rfind("status section:", 0) != 0, "a corrupt immutable section is refused (not as recoverable): " + w.substr(0, 60));
    }
    // Trailing bytes refused.
    {
        auto c = bytes; c.push_back(0);
        std::string w;
        try { (void)decode_record(c); } catch (const std::exception& e) { w = e.what(); }
        check(w.find("trailing") != std::string::npos, "trailing bytes after the record are refused");
    }
    // Frame self-validation: a frame whose hash does not match is refused.
    {
        Record bad = r; bad.alternates[0].tx_hash[0] ^= 0xff;
        std::string w;
        try { (void)decode_record(encode_record(bad)); } catch (const std::exception& e) { w = e.what(); }
        check(w.find("recomputed hash") != std::string::npos, "an alternate whose tx_hash != recomputed frame hash is refused");
    }
    // msg_id stability: same inputs → same id; a fee bump keeps it; different content changes it.
    {
        Record r2 = make_record(kf, ghash, 7, 100, 3, to, {0xde, 0xad});
        check(r2.alternates[0].msg_id == r.alternates[0].msg_id, "msg_id is deterministic over (genesis, sender, nonce, original bytes)");
        Record r3 = r; add_alternate(r3, kf, 9, true);
        check(r3.alternates[1].msg_id == r.alternates[0].msg_id && r3.alternates[1].tx_hash != r.alternates[0].tx_hash,
              "a fee bump keeps the msg_id and changes only the tx hash");
        Record r4 = r; add_alternate(r4, kf, 9, false);
        check(r4.alternates[1].msg_id != r.alternates[0].msg_id, "a re-issue with different content carries a new msg_id");
    }
    // Meta round trip + corruption.
    {
        Meta m; m.genesis_hash = ghash; m.sender = kf.anon_address; m.nonce_floor = 42;
        auto mb = encode_meta(m);
        Meta mm = decode_meta(mb);
        check(mm.nonce_floor == 42 && mm.sender == m.sender && mm.genesis_hash == ghash, "DOM1 meta round-trip");
        mb[10] ^= 1; std::string w;
        try { (void)decode_meta(mb); } catch (const std::exception& e) { w = e.what(); }
        check(w.find("hash mismatch") != std::string::npos, "a corrupt meta is refused");
    }
    // Local refusals at build time (the client-decidable rejection classes).
    {
        auto refused = [&](TransferSpec s) { try { (void)build_transfer(kf, s, 1); return false; } catch (...) { return true; } };
        TransferSpec s1; s1.to = "0x" + std::string(64, 'C'); s1.amount = 1;
        check(refused(s1), "non-canonical (uppercase) anon --to is refused at enqueue (S-028)");
        TransferSpec s2; s2.to = to; s2.amount = 1; s2.payload.assign(129, 0);
        check(refused(s2), "a payload over TRANSFER_PAYLOAD_MAX is refused at enqueue");
        TransferSpec s3; s3.to = to; s3.amount = UINT64_MAX; s3.fee = 1;
        check(refused(s3), "amount + fee overflow is refused at enqueue (S-049 class)");
        TransferSpec s4; s4.to = to; s4.amount = 0; s4.fee = 0; s4.payload = {1, 2, 3};
        check(!refused(s4), "a zero-amount memo TRANSFER is accepted (the verifier has no amount floor)");
    }
    return check.finish("selftest-outbox-record");
}

// ─── selftest-outbox-classify ──────────────────────────────────────────────
int cmd_selftest_outbox_classify(int, char**) {
    Checker check;
    auto wrap = [](const std::string& e) { return "RPC error on submit_tx: \"" + e + "\""; };
    struct Row { std::string err; Outcome want; const char* why; };
    const std::vector<Row> rows = {
        {wrap("incumbent tx at (from, nonce) has equal-or-higher fee"), Outcome::PENDING, "identical bytes already pending = PENDING, never a failure"},
        {wrap("submitted tx has stale nonce 3 (expected >= 4)"), Outcome::STALE, "stale nonce = STALE (reconcile decides)"},
        {wrap("auth_required: missing 'auth' field"), Outcome::NODE_CONFIG, "HMAC-required daemon = NODE_CONFIG"},
        {wrap("auth_failed"), Outcome::NODE_CONFIG, "auth_failed = NODE_CONFIG"},
        {wrap("Unknown method: submit_tx"), Outcome::NODE_CONFIG, "a non-Determ/old daemon = NODE_CONFIG"},
        {"send failed for submit_tx", Outcome::REPLY_LOST, "send failure after open = REPLY_LOST (may have been delivered)"},
        {"no response for submit_tx (daemon closed connection or timed out)", Outcome::REPLY_LOST, "no reply / timeout = REPLY_LOST"},
        {"malformed response for submit_tx: parse error", Outcome::REPLY_LOST, "unparseable reply = REPLY_LOST"},
        {"RPC client: socket not open (call open() first)", Outcome::TRANSPORT, "closed socket = TRANSPORT"},
        {wrap("rate_limited"), Outcome::REJECTED, "rate_limited = retryable REJECTED"},
        {wrap("mempool: full (10000 txs); incoming fee 0 <= mempool minimum 1"), Outcome::REJECTED, "mempool full = retryable"},
        {wrap("mempool full; fee too low to evict any incumbent tx"), Outcome::REJECTED, "fee too low = retryable"},
        {wrap("mempool: per-sender quota exceeded (100 txs from 0xab)"), Outcome::REJECTED, "per-sender quota = retryable"},
        {wrap("submitted tx signature verification failed (from 0xab)"), Outcome::REJECTED, "signature failure is state-dependent (registry lag) = retryable, NOT permanent"},
        {wrap("submitted tx hash mismatch: expected a got b"), Outcome::REJECTED, "hash mismatch = retryable (surfaced), never a silent drop"},
        {wrap("tx payload exceeds the binary frame limit (65535 bytes)"), Outcome::REJECTED, "frame limit = retryable (cannot occur: refused at enqueue)"},
        {wrap("something new the daemon says tomorrow"), Outcome::REJECTED, "an unrecognised string is retryable — permanence is never inferred from text"},
    };
    for (auto& row : rows) {
        Outcome got = classify_submit_error(row.err);
        check(got == row.want, std::string(row.why) + " [got " + outcome_name(got) + "]");
    }
    check(backoff_seconds(0) == 2 && backoff_seconds(1) == 4 && backoff_seconds(3) == 16 && backoff_seconds(10) == 300 && backoff_seconds(40) == 300,
          "backoff is min(300 s, 2 s * 2^n): 2,4,…,16,…,300 and saturates");
    return check.finish("selftest-outbox-classify");
}

// ─── selftest-outbox-core ──────────────────────────────────────────────────
int cmd_selftest_outbox_core(int, char**) {
    Checker check;
    auto kf = fixture_keyfile(0x42);
    const std::string to = "0x" + std::string(64, 'c');
    auto seed_fixture = [&](uint64_t funded) { return std::make_unique<FixtureRpc>(kf, funded); };
    std::vector<std::string> scratch_dirs;
    auto fresh_outbox = [&](FixtureRpc& fx, const char* tag) {
        auto dir = tmp_dir(tag);
        scratch_dirs.push_back(dir);
        auto ob = std::make_unique<Outbox>(dir);
        Meta m; m.genesis_hash = fx.genesis_hash(); m.sender = kf.anon_address; m.nonce_floor = 0;
        ob->write_meta_new(m);
        ob->load();
        return ob;
    };
    auto enqueue = [&](Outbox& ob, FixtureRpc& fx, uint64_t nonce, uint64_t amount, uint64_t fee) {
        Record r = make_record(kf, fx.genesis_hash(), nonce, amount, fee, to);
        ob.write_slot_new(r);
        return r;
    };
    auto submit = [&](Outbox& ob, FixtureRpc& fx, bool now = true) {
        SubmitOptions o; o.force_now = now; o.head_hint = fx.height();
        return submit_due(ob, fx, o, now_unix());
    };
    auto reconcile = [&](Outbox& ob, FixtureRpc& fx) {
        ReconcileOptions o;
        return reconcile_all(ob, fx, fx.genesis(), fx.committee_seed(), o, now_unix());
    };
    auto st = [&](Outbox& ob, uint64_t n) -> const Record& { return ob.slots().at(n).rec; };
    uint64_t t = now_unix();

    // 0. The fixture chain itself is verifiable by the real readers (non-vacuity).
    {
        auto fx = seed_fixture(1000);
        bool ok = false; std::string err;
        try {
            pin_daemon_genesis(*fx, fx->genesis(), fx->genesis_hash());
            auto v = read_account_trustless(*fx, fx->committee_seed(), fx->genesis(), kf.anon_address);
            ok = (v.balance == 1000 && v.next_nonce == 0);
        } catch (const std::exception& e) { err = e.what(); }
        check(ok, "CTRL: the committee-signed fixture chain passes the real genesis pin + trustless account read " + err);
    }

    // 1. Happy path: ACK → inclusion → FINALIZED/APPLIED exactly once; terminal slots are never re-sent.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core1");
        enqueue(*ob, *fx, 0, 100, 5);
        auto rep = submit(*ob, *fx);
        check(rep.acked == 1 && st(*ob, 0).state == State::SUBMITTED && st(*ob, 0).next_retry > t,
              "ACK → SUBMITTED with a re-send cadence, not FINALIZED");
        fx->mint_from_mempool(/*apply=*/true);
        auto rr = reconcile(*ob, *fx);
        check(rr.finalized_applied == 1 && st(*ob, 0).state == State::FINALIZED && st(*ob, 0).apply == Apply::APPLIED
              && st(*ob, 0).finalized_height == 2,
              "inclusion + committee-signed successor + nonce advance → FINALIZED/APPLIED at height 2");
        check(fx->acct().next_nonce == 1 && fx->acct().balance == 895, "the ledger applied the message exactly once");
        size_t before = fx->submits();
        auto rep2 = submit(*ob, *fx);
        check(rep2.sent == 0 && fx->submits() == before, "a terminal slot is never sent again");
    }

    // 2. Lost reply → UNKNOWN → identical bytes re-sent → PENDING → exactly one application.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core2");
        enqueue(*ob, *fx, 0, 100, 5);
        fx->drop_reply = true;
        auto rep = submit(*ob, *fx);
        check(rep.lost == 1 && st(*ob, 0).state == State::UNKNOWN && fx->mempool_size() == 1,
              "a lost reply leaves the slot UNKNOWN while the daemon holds the bytes");
        fx->drop_reply = false;
        auto rep2 = submit(*ob, *fx);
        check(rep2.pending == 1 && st(*ob, 0).state == State::SUBMITTED, "re-send of identical bytes is answered 'incumbent' → SUBMITTED (pending), not a failure");
        check(fx->submitted_hashes().size() == 2 && fx->submitted_hashes()[0] == fx->submitted_hashes()[1]
              && st(*ob, 0).alternates.size() == 1,
              "the retry sent the SAME tx hash (same nonce, same bytes) — no second logical message");
        fx->mint_from_mempool(true);
        auto rr = reconcile(*ob, *fx);
        check(st(*ob, 0).state == State::FINALIZED && st(*ob, 0).apply == Apply::APPLIED && fx->acct().next_nonce == 1 && fx->acct().balance == 895,
              "after the lost reply the ledger still applied exactly one message");
    }

    // 3. In a final block but NOT applied (chain.cpp:1688 skip) → SKIPPED from the nonce proof, re-armed when funded.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core3");
        enqueue(*ob, *fx, 0, 100, 5);
        submit(*ob, *fx);
        fx->mint_from_mempool(/*apply=*/false);
        auto rr = reconcile(*ob, *fx);
        check(rr.rearmed == 1 && st(*ob, 0).state == State::QUEUED && st(*ob, 0).apply == Apply::SKIPPED
              && st(*ob, 0).skipped_count == 1 && st(*ob, 0).finalized_height == 2,
              "inclusion at 2 with next_nonce still 0 → SKIPPED (never APPLIED) and re-armed with the same bytes");
        auto rep = submit(*ob, *fx);
        check(rep.acked == 1 && fx->submitted_hashes().front() == fx->submitted_hashes().back(), "the re-armed slot re-sends the identical hash");
        fx->mint_from_mempool(true);
        auto rr2 = reconcile(*ob, *fx);
        check(st(*ob, 0).state == State::FINALIZED && st(*ob, 0).apply == Apply::APPLIED && st(*ob, 0).finalized_height == 4,
              "the later inclusion (greatest canonical height) is the one attributed as APPLIED");
    }

    // 4. Skipped while underfunded → FINALIZED/SKIPPED (blocked), not re-armed: no zero-cost inclusion loop.
    {
        auto fx = seed_fixture(50);
        auto ob = fresh_outbox(*fx, "core4");
        enqueue(*ob, *fx, 0, 100, 0);
        submit(*ob, *fx);
        fx->mint_from_mempool(false);
        auto rr = reconcile(*ob, *fx);
        check(rr.finalized_skipped == 1 && st(*ob, 0).state == State::FINALIZED && st(*ob, 0).apply == Apply::SKIPPED && !st(*ob, 0).sendable(),
              "underfunded skip stays FINALIZED/SKIPPED (blocked) — not re-sent");
        size_t before = fx->submits();
        submit(*ob, *fx);
        check(fx->submits() == before, "a blocked slot is not re-sent");
        auto rr2 = reconcile(*ob, *fx);
        check(st(*ob, 0).skipped_count == 1, "re-reconciling the same skip does not inflate skipped_count");
    }

    // 5. INCLUDED at the head is NOT FINALIZED; an orphaned inclusion re-arms; then finalizes.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core5");
        enqueue(*ob, *fx, 0, 100, 5);
        submit(*ob, *fx);
        fx->auto_mint_includes_mempool = true;   // the tx lands in the block minted during the successor wait
        auto rr = reconcile(*ob, *fx);
        check(rr.included == 1 && st(*ob, 0).state == State::INCLUDED && st(*ob, 0).apply == Apply::UNKNOWN && st(*ob, 0).included_height == 2,
              "a tx in the head block is INCLUDED (not FINALIZED, not APPLIED) until a successor binds it");
        fx->auto_mint_includes_mempool = false;
        fx->reorg_tip_without_txs();             // S-048: the head is replaced
        auto rr2 = reconcile(*ob, *fx);
        check(rr2.orphaned == 1 && st(*ob, 0).state == State::QUEUED && st(*ob, 0).orphaned_count == 1,
              "the orphaned inclusion is detected by the successor binding and the slot is re-armed");
        submit(*ob, *fx);
        fx->mint_from_mempool(true);
        auto rr3 = reconcile(*ob, *fx);
        check(st(*ob, 0).state == State::FINALIZED && st(*ob, 0).apply == Apply::APPLIED && fx->acct().next_nonce == 1,
              "after the reorg the same bytes are finalized exactly once");
    }

    // 5b. A daemon that keeps serving the orphaned block (and locates the tx in it)
    //     must not get the slot finalized: the successor binding refuses (UNVERIFIABLE).
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core5b");
        enqueue(*ob, *fx, 0, 100, 5);
        submit(*ob, *fx);
        fx->auto_mint_includes_mempool = true;
        reconcile(*ob, *fx);                      // INCLUDED at 2 (head)
        fx->auto_mint_includes_mempool = false;
        fx->reorg_tip_without_txs();
        fx->mint_empty();                         // the stale block is below the read anchor
        fx->serve_stale_block = true;
        auto rr = reconcile(*ob, *fx);
        check(rr.orphaned == 1 && st(*ob, 0).state == State::QUEUED && st(*ob, 0).apply != Apply::APPLIED && st(*ob, 0).orphaned_count == 1,
              "a stale/orphaned block served with the tx in it is refused by the successor binding — never FINALIZED; the slot re-arms");
    }

    // 5c. A transiently UNVERIFIABLE probe never yields a terminal verdict: with the
    //     nonce proven consumed and a hint the daemon cannot back, the slot is left
    //     unchanged (exit-3 class), not CONSUMED.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core5c");
        enqueue(*ob, *fx, 0, 100, 5);
        submit(*ob, *fx);
        fx->mint_from_mempool(true);           // applied at 2
        fx->bogus_tx_height = 999;             // the daemon now points every hint past its head
        auto rr = reconcile(*ob, *fx);
        check(rr.unverifiable >= 1 && rr.consumed == 0 && st(*ob, 0).state == State::SUBMITTED,
              "an unverifiable hint with the nonce consumed leaves the slot unchanged — never CONSUMED/UNLOCATED");
        fx->bogus_tx_height = 0;
        reconcile(*ob, *fx);
        check(st(*ob, 0).state == State::FINALIZED && st(*ob, 0).apply == Apply::APPLIED, "once the daemon answers honestly the slot finalizes");
    }

    // 3b. A skip is counted per inclusion, not per reconcile pass: the re-armed slot
    //     stays sendable across repeated polls that see the same skipped inclusion.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core3b");
        enqueue(*ob, *fx, 0, 100, 5);
        submit(*ob, *fx);
        fx->mint_from_mempool(false);
        reconcile(*ob, *fx);
        for (int i = 0; i < 10; ++i) reconcile(*ob, *fx);
        check(st(*ob, 0).skipped_count == 1 && st(*ob, 0).sendable(),
              "ten reconcile passes over one skip: skipped_count stays 1 and the slot stays sendable");
        submit(*ob, *fx);
        for (int i = 0; i < 10; ++i) reconcile(*ob, *fx);
        check(st(*ob, 0).skipped_count == 1 && st(*ob, 0).state == State::SUBMITTED,
              "after re-submission the pending slot is still not re-counted or re-armed");
    }

    // 3c. A LATER skipped inclusion (greater height) is a NEW skip: counted, re-armed,
    //     and past MAX_SKIPS the slot is disarmed — no zero-cost inclusion loop.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core3c");
        enqueue(*ob, *fx, 0, 100, 5);
        auto skip_once = [&] { submit(*ob, *fx); fx->mint_from_mempool(false); return reconcile(*ob, *fx); };
        skip_once();
        auto rr = skip_once();
        check(rr.rearmed == 1 && st(*ob, 0).skipped_count == 2 && st(*ob, 0).state == State::QUEUED && st(*ob, 0).finalized_height > 2,
              "a second skipped inclusion at a greater height is a new skip: counted (2) and re-armed");
        for (int i = 0; i < 12 && st(*ob, 0).sendable() && st(*ob, 0).skipped_count <= MAX_SKIPS; ++i) skip_once();
        size_t before = fx->submits();
        submit(*ob, *fx);
        check(st(*ob, 0).skipped_count == MAX_SKIPS + 1 && st(*ob, 0).state == State::FINALIZED && st(*ob, 0).apply == Apply::SKIPPED
              && fx->submits() == before,
              "past MAX_SKIPS the slot is FINALIZED/SKIPPED (cap) and never re-sent");
    }

    // 3d. A re-issue after a skip starts a fresh budget: the earlier alternate's
    //     already-counted inclusion is not counted again against it.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core3d");
        enqueue(*ob, *fx, 0, 100, 5);
        submit(*ob, *fx);
        fx->mint_from_mempool(false);
        reconcile(*ob, *fx);                                   // skip 1 at 2, re-armed
        Record r = st(*ob, 0); add_alternate(r, kf, 9, false); ob->write_slot_replace(r, now_unix());
        reconcile(*ob, *fx);
        check(st(*ob, 0).skipped_count == 0 && st(*ob, 0).state == State::QUEUED && st(*ob, 0).alternates.size() == 2,
              "after a re-issue the old alternate's counted inclusion does not count against the fresh budget");
        submit(*ob, *fx);
        fx->mint_from_mempool(false);                          // the re-issue is skipped at a greater height
        reconcile(*ob, *fx);
        check(st(*ob, 0).skipped_count == 1 && st(*ob, 0).included_alt == 1, "the re-issue's own skipped inclusion is counted as its first");
    }

    // 11. A located inclusion that the record already proved SKIPPED can never be
    //     attributed as APPLIED when the nonce is later spent (an A1 violation or a
    //     daemon withholding the applying alternate's hint): CONSUMED/UNLOCATED.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core11");
        enqueue(*ob, *fx, 0, 100, 5);
        submit(*ob, *fx);
        fx->mint_from_mempool(false);
        reconcile(*ob, *fx);                                   // proven skip at 2
        fx->consume_nonce_externally();                        // nonce 0 spent by other bytes
        auto rr = reconcile(*ob, *fx);
        check(rr.finalized_applied == 0 && st(*ob, 0).state == State::CONSUMED && st(*ob, 0).apply == Apply::UNLOCATED
              && st(*ob, 0).last_error.find("proven skipped") != std::string::npos,
              "the proven-skipped inclusion is not re-labelled APPLIED once the nonce is spent — CONSUMED/UNLOCATED names why");
    }

    // 12. Attribution across alternates needs every alternate answered: with one
    //     alternate's probe unverifiable the spent nonce is not attributed (exit-3
    //     class); once every probe verifies, the alternate that applied is named.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core12");
        enqueue(*ob, *fx, 0, 100, 5);
        submit(*ob, *fx);
        fx->mint_from_mempool(false);                          // alt0 included at 2, skipped (not yet reconciled)
        Record r = st(*ob, 0); add_alternate(r, kf, 9, false); ob->write_slot_replace(r, now_unix());
        submit(*ob, *fx);
        fx->mint_from_mempool(true);                           // alt1 applied at 3
        fx->unverifiable_hash = st(*ob, 0).alternates[1].tx_hash;
        auto rr = reconcile(*ob, *fx);
        check(rr.unverifiable >= 1 && rr.finalized_applied == 0 && st(*ob, 0).apply != Apply::APPLIED && st(*ob, 0).state != State::CONSUMED,
              "alt0 canonical + alt1 unverifiable + nonce spent: attribution withheld, no terminal verdict");
        fx->unverifiable_hash = Hash{};
        reconcile(*ob, *fx);
        check(st(*ob, 0).state == State::FINALIZED && st(*ob, 0).apply == Apply::APPLIED && st(*ob, 0).included_alt == 1
              && st(*ob, 0).alternates[1].msg_id != st(*ob, 0).alternates[0].msg_id,
              "with every probe verified the re-issue (greatest canonical height) is the one attributed");
    }

    // 13. A same-height reorg where the SIBLING carried and applied our bytes, while
    //     the daemon still serves the orphaned body: the spent nonce is not
    //     re-armed (a re-send would only be stale) and not attributed to the
    //     orphaned inclusion — CONSUMED/UNLOCATED, not re-stamped, and upgraded to
    //     FINALIZED/APPLIED once the daemon serves the canonical block.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core13");
        enqueue(*ob, *fx, 0, 100, 5);
        submit(*ob, *fx);
        fx->auto_mint_includes_mempool = true;
        reconcile(*ob, *fx);                                   // INCLUDED at 2 (head)
        fx->auto_mint_includes_mempool = false;
        fx->reorg_tip_keeping_txs();                           // sibling at 2 applies the same bytes
        fx->mint_empty();
        fx->serve_stale_block = true;
        auto rr = reconcile(*ob, *fx);
        check(rr.orphaned == 0 && rr.finalized_applied == 0 && st(*ob, 0).state == State::CONSUMED && st(*ob, 0).apply == Apply::UNLOCATED
              && st(*ob, 0).last_error.find("orphaned body") != std::string::npos,
              "orphaned body served + nonce spent: not re-armed, not APPLIED — CONSUMED/UNLOCATED naming the orphaned body");
        const uint64_t stamped = st(*ob, 0).updated;
        size_t before = fx->submits();
        submit(*ob, *fx);
        reconcile(*ob, *fx);
        check(fx->submits() == before && st(*ob, 0).updated == stamped && st(*ob, 0).state == State::CONSUMED,
              "a CONSUMED slot is never re-sent and not re-stamped by a pass that learns nothing new");
        fx->serve_stale_block = false;
        reconcile(*ob, *fx);
        check(st(*ob, 0).state == State::FINALIZED && st(*ob, 0).apply == Apply::APPLIED && st(*ob, 0).finalized_height == 2,
              "once the canonical block is served the CONSUMED slot is upgraded to FINALIZED/APPLIED");
    }

    // 2b. A lost reply ends the run: later slots are not classified from a
    //     desynchronised stream (the next run reconnects and re-sends them).
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core2b");
        enqueue(*ob, *fx, 0, 10, 1); enqueue(*ob, *fx, 1, 10, 1);
        fx->drop_reply = true;
        auto rep = submit(*ob, *fx);
        check(rep.sent == 1 && rep.lost == 1 && st(*ob, 0).state == State::UNKNOWN && st(*ob, 1).state == State::QUEUED && st(*ob, 1).attempts == 0,
              "after a lost reply the run stops; the next slot was not sent on the same stream");
        fx->drop_reply = false;
        auto rep2 = submit(*ob, *fx);
        check(rep2.pending == 1 && rep2.acked == 1, "the next run re-sends slot 0 (pending) and sends slot 1 (queued)");
    }

    // 6. Nonce consumed by a foreign tx (A1 violation): STALE at submit, CONSUMED/UNLOCATED at reconcile, never lost.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core6");
        enqueue(*ob, *fx, 0, 100, 5);
        fx->consume_nonce_externally();
        auto rep = submit(*ob, *fx);
        check(rep.stale == 1 && st(*ob, 0).state == State::QUEUED, "stale nonce at submit is recorded, not treated as failure");
        auto rr = reconcile(*ob, *fx);
        check(rr.consumed == 1 && st(*ob, 0).state == State::CONSUMED && st(*ob, 0).apply == Apply::UNLOCATED && !st(*ob, 0).sendable(),
              "a proven-consumed nonce with no located inclusion is CONSUMED/UNLOCATED (daemon negative labelled)");
    }

    // 7. Fee bump: both alternates watched; the one the ledger applied is attributed; msg_id unchanged.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core7");
        enqueue(*ob, *fx, 0, 100, 1);
        submit(*ob, *fx);
        Record r = st(*ob, 0); add_alternate(r, kf, 9, true); ob->write_slot_replace(r, t);
        auto rep = submit(*ob, *fx);
        check(rep.acked == 1 && fx->mempool_size() == 1, "the fee bump replaces the incumbent at the daemon");
        fx->mint_from_mempool(true);
        reconcile(*ob, *fx);
        const Record& f = st(*ob, 0);
        check(f.state == State::FINALIZED && f.apply == Apply::APPLIED && f.included_alt == 1
              && f.alternates[1].msg_id == f.alternates[0].msg_id && fx->acct().balance == 1000 - 109,
              "the applied alternate (fee 9) is attributed; msg_id is the original's");
    }

    // 8. Retryable rejection: state unchanged, backoff recorded, not re-sent until due; NODE_CONFIG stops without backoff.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core8");
        enqueue(*ob, *fx, 0, 100, 1);
        fx->submit_error = "RPC error on submit_tx: \"mempool: full (10000 txs); incoming fee 1 <= mempool minimum 2\"";
        auto rep = submit(*ob, *fx);
        check(rep.rejected == 1 && st(*ob, 0).state == State::QUEUED && st(*ob, 0).consecutive_failures == 1 && st(*ob, 0).next_retry > t,
              "a retryable rejection keeps the slot QUEUED with backoff");
        auto rep2 = submit(*ob, *fx, /*now=*/false);
        check(rep2.skipped_not_due == 1 && rep2.sent == 0, "not re-sent before next_retry");
        fx->submit_error = "RPC error on submit_tx: \"auth_required: missing 'auth' field\"";
        auto rep3 = submit(*ob, *fx);
        check(rep3.node_config_error && st(*ob, 0).state == State::QUEUED && st(*ob, 0).consecutive_failures == 1,
              "a daemon configuration error is reported without a backoff spiral");
        fx->submit_error.clear();
        submit(*ob, *fx);
        fx->mint_from_mempool(true);
        reconcile(*ob, *fx);
        check(st(*ob, 0).state == State::FINALIZED && st(*ob, 0).apply == Apply::APPLIED, "after the transient rejection the message finalizes");
    }

    // 9. GAP report: the chain expects a nonce no local slot reserves.
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core9");
        enqueue(*ob, *fx, 3, 100, 1);
        auto rr = reconcile(*ob, *fx);
        check(rr.gap && rr.gap_nonce == 0 && st(*ob, 3).state == State::QUEUED, "GAP: chain expects nonce 0, only slot 3 exists — reported, slot untouched");
    }

    // 10. Restart: a fresh Outbox object over the same directory sees every state (persistence is the record, not memory).
    {
        auto fx = seed_fixture(1000);
        auto ob = fresh_outbox(*fx, "core10");
        enqueue(*ob, *fx, 0, 10, 1); enqueue(*ob, *fx, 1, 10, 1); enqueue(*ob, *fx, 2, 10, 1);
        submit(*ob, *fx);
        fx->mint_from_mempool(true);
        reconcile(*ob, *fx);
        Outbox ob2(ob->dir()); ob2.load();
        check(ob2.slots().size() == 3 && ob2.slots().at(0).rec.state == State::FINALIZED && ob2.slots().at(1).rec.state == State::SUBMITTED
              && ob2.slots().at(2).rec.state == State::SUBMITTED && ob2.meta().sender == kf.anon_address,
              "a re-opened outbox reloads finalized + submitted slots from disk");
        auto rep = submit(ob2, *fx);
        check(rep.pending == 2 && rep.sent == 2, "after restart only the non-terminal slots are re-sent (identical bytes → pending)");
    }

    for (auto& d : scratch_dirs) { std::error_code ec; std::filesystem::remove_all(d, ec); }
    return check.finish("selftest-outbox-core");
}

} // namespace determ::light
