// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#include <determ/chain/block.hpp>
#include <determ/crypto/sha256.hpp>
#include <determ/util/json_validate.hpp>
#include <cstring>
#include <set>
#include <stdexcept>

namespace determ::chain {

using namespace determ::crypto;
using determ::util::json_require;
using determ::util::json_require_hex;
using determ::util::json_require_array;
using json = nlohmann::json;

// ─── Transaction ─────────────────────────────────────────────────────────────

std::vector<uint8_t> Transaction::signing_bytes() const {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(type));
    out.insert(out.end(), from.begin(), from.end());
    out.push_back(0);
    out.insert(out.end(), to.begin(), to.end());
    out.push_back(0);
    for (int i = 7; i >= 0; --i) out.push_back((amount >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) out.push_back((fee    >> (i * 8)) & 0xFF);
    for (int i = 7; i >= 0; --i) out.push_back((nonce  >> (i * 8)) & 0xFF);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

Hash Transaction::compute_hash() const {
    auto sb = signing_bytes();
    return sha256(sb.data(), sb.size());
}

json Transaction::to_json() const {
    json j;
    j["type"]    = static_cast<int>(type);
    j["from"]    = from;
    j["to"]      = to;
    j["amount"]  = amount;
    j["fee"]     = fee;
    j["nonce"]   = nonce;
    j["payload"] = to_hex(payload.data(), payload.size());
    j["sig"]     = to_hex(sig);
    j["hash"]    = to_hex(hash);
    // §3.21: the DPQ1 PQ authenticator is emitted ONLY when present, so every
    // non-PQ tx serializes byte-identically to before this field existed.
    if (!pq_auth.empty()) j["pq_auth"] = to_hex(pq_auth.data(), pq_auth.size());
    return j;
}

Transaction Transaction::from_json(const json& j) {
    // S-018: every required field is fetched via json_require<T> /
    // json_require_hex so missing or wrong-type fields throw with
    // clear field-name diagnostics rather than opaque
    // nlohmann-internal type errors. Optional fields (`fee`) keep the
    // existing `j.value(...)` defaults.
    Transaction tx;
    tx.type    = static_cast<TxType>(json_require<int>(j, "type"));
    tx.from    = json_require<std::string>(j, "from");
    tx.to      = json_require<std::string>(j, "to");
    tx.amount  = json_require<uint64_t>(j, "amount");
    tx.fee     = j.value("fee", uint64_t{0});
    tx.nonce   = json_require<uint64_t>(j, "nonce");
    tx.payload = from_hex(json_require<std::string>(j, "payload"));
    tx.sig     = from_hex_arr<64>(json_require_hex(j, "sig", 128));
    tx.hash    = from_hex_arr<32>(json_require_hex(j, "hash", 64));
    // §3.21: optional DPQ1 PQ authenticator (present only for PQ_TRANSFER).
    // Absent for every legacy tx, so pre-§3.21 JSON round-trips unchanged.
    if (j.contains("pq_auth") && j["pq_auth"].is_string())
        tx.pq_auth = from_hex(j["pq_auth"].get<std::string>());
    return tx;
}

// ─── Transaction binary frame (canonical, D2) ────────────────────────────────
//
// Moved here from src/net/binary_codec.cpp (which now delegates) so the
// chain layer — the COMPOSABLE_BATCH validator accept rule and apply path —
// can share the ONE frame codec without a chain→net dependency. The byte
// layout is UNCHANGED (the wire gates test-tx-binary-codec /
// test-binary-codec-roundtrip-exhaustive pin it); the full layout comment
// lives in binary_codec.cpp.

namespace {

inline void le_put_u16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

inline void le_put_u32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

inline void le_put_u64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

inline uint16_t le_get_u16(const uint8_t* p) {
    return  static_cast<uint16_t>(p[0])
         | (static_cast<uint16_t>(p[1]) << 8);
}

inline uint32_t le_get_u32(const uint8_t* p) {
    return  static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) <<  8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t le_get_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<uint64_t>(p[i]) << (i * 8);
    return v;
}

// Append `n` bytes of `src` (right-padded with 0x00 if shorter than n).
inline void put_padded(std::vector<uint8_t>& out, const uint8_t* src, size_t src_len, size_t n) {
    size_t take = src_len < n ? src_len : n;
    out.insert(out.end(), src, src + take);
    out.insert(out.end(), n - take, 0x00);
}

// Append a u8-length-prefixed string (length capped at 255).
inline void put_lp_str(std::vector<uint8_t>& out, const std::string& s) {
    size_t n = s.size();
    if (n > 255) throw std::runtime_error("tx frame: string > 255 bytes");
    out.push_back(static_cast<uint8_t>(n));
    out.insert(out.end(), s.begin(), s.end());
}

inline std::string get_lp_str(const uint8_t* data, size_t len, size_t& off) {
    if (off + 1 > len) throw std::runtime_error("tx frame: truncated lp_str header");
    uint8_t n = data[off++];
    if (off + n > len) throw std::runtime_error("tx frame: truncated lp_str body");
    std::string s(reinterpret_cast<const char*>(data + off), n);
    off += n;
    return s;
}

} // namespace

void Transaction::encode_frame(std::vector<uint8_t>& out) const {
    // sender_pubkey slot — 32 bytes, derived from `from`. `from` is the
    // string-form account identifier; the trailer's `from_len + from`
    // reconstructs it authoritatively.
    put_padded(out,
        reinterpret_cast<const uint8_t*>(from.data()),
        from.size(),
        32);

    // amount block: 32 bytes total — [amount LE][fee LE][nonce LE][reserved LE]
    le_put_u64(out, amount);
    le_put_u64(out, fee);
    le_put_u64(out, nonce);
    le_put_u64(out, 0);             // reserved — must be zero (deterministic)

    // recipient_pubkey slot
    put_padded(out,
        reinterpret_cast<const uint8_t*>(to.data()),
        to.size(),
        32);

    // payload slot — first 32 bytes of payload (right-padded if shorter)
    put_padded(out,
        payload.data(),
        payload.size(),
        32);

    // trailer
    out.push_back(static_cast<uint8_t>(type));
    // FAIL-CLOSED, not clamped. `payload_len` is a u16, but the overflow
    // section below writes payload.size() - 32 bytes UNCLAMPED. Clamping the
    // declared length while writing the true length desynchronizes encode from
    // decode: for payload.size() > 0xFFFF the decoder reads only 0xFFFF - 32
    // overflow bytes and then parses `from`'s length prefix out of the middle
    // of the payload — attacker-chosen bytes, silently, with no error. So the
    // encoder refuses instead, exactly like the pq_auth sibling 15 lines below.
    // Ingress rejects such a payload first (Node::mempool_admit_check); this is
    // the backstop that makes the ambiguity unrepresentable at the codec.
    if (payload.size() > TX_FRAME_PAYLOAD_MAX)
        throw std::runtime_error("tx frame: payload exceeds u16 length");
    uint16_t payload_len = static_cast<uint16_t>(payload.size());
    le_put_u16(out, payload_len);
    if (payload.size() > 32) {
        size_t overflow = payload.size() - 32;
        out.insert(out.end(),
            payload.begin() + 32, payload.begin() + 32 + overflow);
    }
    put_lp_str(out, from);
    put_lp_str(out, to);
    out.insert(out.end(), sig.begin(),  sig.end());
    out.insert(out.end(), hash.begin(), hash.end());

    // §3.21: optional DPQ1 PQ authenticator — appended ONLY when present so
    // every non-PQ tx frame is byte-identical to the pre-§3.21 layout.
    if (!pq_auth.empty()) {
        if (pq_auth.size() > 0xFFFFFFFFu)
            throw std::runtime_error("tx frame: pq_auth exceeds u32 length");
        le_put_u32(out, static_cast<uint32_t>(pq_auth.size()));
        out.insert(out.end(), pq_auth.begin(), pq_auth.end());
    }
}

Transaction Transaction::decode_frame(const uint8_t* data, size_t len) {
    Transaction tx;
    if (len < 128 + 1 + 2)
        throw std::runtime_error("tx frame too short");

    // Canonical numeric fields live in the fixed-slot area (S-002: the
    // admission-side sig verify reads them from here, not the trailer).
    tx.amount = le_get_u64(data + 32);
    tx.fee    = le_get_u64(data + 40);
    tx.nonce  = le_get_u64(data + 48);
    uint64_t reserved = le_get_u64(data + 56);
    if (reserved != 0)
        throw std::runtime_error("tx frame: reserved field non-zero");

    // Trailer starts at offset 128.
    size_t off = 128;

    tx.type = static_cast<TxType>(data[off++]);
    uint16_t payload_len = le_get_u16(data + off); off += 2;

    if (payload_len <= 32) {
        tx.payload.assign(data + 96, data + 96 + payload_len);
    } else {
        size_t overflow = payload_len - 32;
        if (off + overflow > len)
            throw std::runtime_error("tx frame: truncated payload overflow");
        tx.payload.reserve(payload_len);
        tx.payload.insert(tx.payload.end(), data + 96, data + 128);
        tx.payload.insert(tx.payload.end(), data + off, data + off + overflow);
        off += overflow;
    }

    tx.from = get_lp_str(data, len, off);
    tx.to   = get_lp_str(data, len, off);
    if (off + 64 + 32 > len)
        throw std::runtime_error("tx frame: truncated sig/hash");
    std::memcpy(tx.sig.data(),  data + off, 64); off += 64;
    std::memcpy(tx.hash.data(), data + off, 32); off += 32;

    // §3.21: optional pq_auth section — [u32 LE len][len bytes], consuming
    // the frame EXACTLY. Fail-closed on trailing garbage; a zero-length
    // section is rejected so the encoding stays canonical.
    if (off != len) {
        if (off + 4 > len)
            throw std::runtime_error("tx frame: truncated pq_auth header");
        uint32_t pq_len = le_get_u32(data + off); off += 4;
        if (pq_len == 0)
            throw std::runtime_error("tx frame: empty pq_auth section");
        if (pq_len != len - off)
            throw std::runtime_error("tx frame: pq_auth length mismatch");
        tx.pq_auth.assign(data + off, data + off + pq_len);
        off += pq_len;
    }
    return tx;
}

// ─── COMPOSABLE_BATCH payload codec (canonical, D2) ─────────────────────────
//
// [inner_count: u16 LE] + inner_count × [frame_len: u32 LE][frame bytes].
// The per-frame length prefix is load-bearing: the tx frame's optional
// pq_auth tail is "present iff bytes remain", so bare concatenation would
// be ambiguous. Count-BOUNDS policy (1..MAX_COMPOSABLE_INNER) deliberately
// stays in the validator so its pinned reject strings keep firing; decode
// here is total over the structure (work is O(payload bytes) — every
// declared frame must be backed by payload bytes, so a huge claimed count
// on a small payload throws at the first missing frame).

std::vector<uint8_t> encode_batch_payload(const std::vector<Transaction>& inner) {
    if (inner.size() > MAX_COMPOSABLE_INNER)
        throw std::runtime_error(
            "batch payload: inner count exceeds MAX_COMPOSABLE_INNER");
    std::vector<uint8_t> out;
    le_put_u16(out, static_cast<uint16_t>(inner.size()));
    std::vector<uint8_t> frame;
    for (const auto& tx : inner) {
        frame.clear();
        tx.encode_frame(frame);
        le_put_u32(out, static_cast<uint32_t>(frame.size()));
        out.insert(out.end(), frame.begin(), frame.end());
    }
    return out;
}

std::vector<Transaction> decode_batch_payload(const std::vector<uint8_t>& payload) {
    if (payload.size() < 2)
        throw std::runtime_error("batch payload: truncated inner_count header");
    uint16_t count = le_get_u16(payload.data());
    size_t off = 2;
    std::vector<Transaction> inner;
    inner.reserve(count <= MAX_COMPOSABLE_INNER ? count : MAX_COMPOSABLE_INNER);
    for (uint16_t i = 0; i < count; ++i) {
        if (off + 4 > payload.size())
            throw std::runtime_error(
                "batch payload: truncated frame length prefix (inner "
                + std::to_string(i) + ")");
        uint32_t flen = le_get_u32(payload.data() + off); off += 4;
        if (flen > payload.size() - off)
            throw std::runtime_error(
                "batch payload: truncated inner frame (inner "
                + std::to_string(i) + ")");
        inner.push_back(Transaction::decode_frame(payload.data() + off, flen));
        off += flen;
    }
    if (off != payload.size())
        throw std::runtime_error(
            "batch payload: trailing bytes after last inner frame");
    return inner;
}

// ─── GenesisAlloc ────────────────────────────────────────────────────────────

json GenesisAlloc::to_json() const {
    return {
        {"domain",  domain},
        {"ed_pub",  to_hex(ed_pub)},
        {"balance", balance},
        {"stake",   stake},
        {"region",  region}
    };
}

GenesisAlloc GenesisAlloc::from_json(const json& j) {
    // S-018: `domain` is required (parses genesis initial_state from
    // chain.json + snapshot.json); other fields have sensible
    // defaults via `j.value(...)`.
    GenesisAlloc a;
    a.domain  = json_require<std::string>(j, "domain");
    a.ed_pub  = from_hex_arr<32>(j.value("ed_pub", std::string(64, '0')));
    a.balance = j.value("balance", uint64_t{0});
    a.stake   = j.value("stake",   uint64_t{0});
    // rev.9 R1: region absent on legacy genesis blocks → empty string.
    a.region  = j.value("region",  std::string{});
    return a;
}

// ─── AbortEvent ──────────────────────────────────────────────────────────────

// ─── AbortClaim list codec (canonical, D2-inc3) ─────────────────────────────
//
// The one shared byte-counting definition (MergeEvent/ShardTipRecord
// discipline) for the in-block claim list. These bytes are BOTH the
// hash_abort_event digest preimage and (hex-wrapped) the block-container
// form, so the stored value and the hashed bytes cannot drift.
//
// D2-inc3 note on F-10: the typed fixed layout supersedes the JSON
// canonicalize-on-ingest defense (abort_canonical.hpp, deleted) — unknown
// members, float-encoded ints, mixed-case hex and injected nesting are
// structurally impossible here, so claim depth is a constant of the schema
// again and nothing attacker-shaped survives ingest to be re-served.

std::vector<uint8_t> encode_abort_claims(const std::vector<AbortClaim>& claims) {
    if (claims.size() > 0xFFFF)
        throw std::runtime_error("abort claims: count exceeds u16");
    std::vector<uint8_t> out;
    le_put_u16(out, static_cast<uint16_t>(claims.size()));
    for (const auto& c : claims) {
        le_put_u64(out, c.block_index);
        out.push_back(c.round);
        out.insert(out.end(), c.prev_hash.begin(), c.prev_hash.end());
        out.insert(out.end(), c.ed_sig.begin(), c.ed_sig.end());
        put_lp_str(out, c.missing_creator);
        put_lp_str(out, c.claimer);
    }
    return out;
}

Hash canonical_abort_event_hash(const AbortEvent& ae, const AbortEvent* prev,
                                const Hash& committee_seed, uint64_t block_index) {
    // Inputs are the committed decision only — WHICH member was excluded, in
    // WHICH round, at WHICH height and tail position — seeded by the committee
    // seed of the height (itself a function of committed commit-reveal rand).
    // The event's timestamp is deliberately NOT an input: the parent committee
    // chooses the block timestamp inside the ±30 s window (lower median of its
    // proposer_times), which would be a free ~60-way re-draw of the post-abort
    // committee.
    crypto::SHA256Builder h;
    h.append(std::string("DTM-ABORT-ID-v1"));
    if (prev) {
        h.append(static_cast<uint8_t>(1)).append(prev->event_hash);
    } else {
        h.append(static_cast<uint8_t>(0)).append(committee_seed).append(block_index);
    }
    return h.append(ae.round).append(ae.aborting_node).finalize();
}

std::vector<AbortClaim> decode_abort_claims(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 2)
        throw std::runtime_error("abort claims: truncated count header");
    uint16_t count = le_get_u16(bytes.data());
    size_t off = 2;
    std::vector<AbortClaim> claims;
    claims.reserve(count <= 64 ? count : 64);
    for (uint16_t i = 0; i < count; ++i) {
        AbortClaim c;
        // Fixed section: u64 + u8 + 32 + 64 = 105 bytes.
        if (bytes.size() - off < 105)
            throw std::runtime_error("abort claims: truncated claim "
                                     + std::to_string(i));
        c.block_index = le_get_u64(bytes.data() + off); off += 8;
        c.round       = bytes[off++];
        std::copy(bytes.begin() + off, bytes.begin() + off + 32,
                  c.prev_hash.begin());
        off += 32;
        std::copy(bytes.begin() + off, bytes.begin() + off + 64,
                  c.ed_sig.begin());
        off += 64;
        c.missing_creator = get_lp_str(bytes.data(), bytes.size(), off);
        c.claimer         = get_lp_str(bytes.data(), bytes.size(), off);
        claims.push_back(std::move(c));
    }
    if (off != bytes.size())
        throw std::runtime_error("abort claims: trailing bytes after last claim");
    return claims;
}

json AbortEvent::to_json() const {
    json j;
    j["round"]         = round;
    j["aborting_node"] = aborting_node;
    j["timestamp"]     = timestamp;
    j["event_hash"]    = to_hex(event_hash);
    // D2-inc3: the claim list travels as ONE hex-of-binary string (the
    // shard_tip_records container pattern) — unconditional, like the old
    // JSON array was.
    auto enc = encode_abort_claims(claims);
    j["claims"]        = to_hex(enc.data(), enc.size());
    return j;
}

AbortEvent AbortEvent::from_json(const json& j) {
    // S-018: clear field-name diagnostics on malformed AbortEvent.
    AbortEvent ae;
    ae.round         = json_require<uint8_t>(j, "round");
    ae.aborting_node = json_require<std::string>(j, "aborting_node");
    ae.timestamp     = json_require<int64_t>(j, "timestamp");
    ae.event_hash    = from_hex_arr<32>(json_require_hex(j, "event_hash", 64));
    // D2-inc3: fail-closed typed decode. The pre-D2 schema-free JSON array
    // (and with it the whole F-10 canonicalize-on-ingest machinery) is
    // gone — a non-string "claims", bad hex, or a malformed blob throws
    // here, at the parse boundary, with a specific reason.
    ae.claims        = decode_abort_claims(
        from_hex(json_require<std::string>(j, "claims")));
    return ae;
}

// ─── EquivocationEvent ───────────────────────────────────────────────────────

json EquivocationEvent::to_json() const {
    json j;
    j["equivocator"]          = equivocator;
    j["block_index"]          = block_index;
    j["kind"]                 = kind;
    j["index_a"]              = index_a;
    j["gen_a"]                = gen_a;
    j["body_root_a"]          = to_hex(body_root_a);
    j["sig_a"]                = to_hex(sig_a);
    j["index_b"]              = index_b;
    j["gen_b"]                = gen_b;
    j["body_root_b"]          = to_hex(body_root_b);
    j["sig_b"]                = to_hex(sig_b);
    j["shard_id"]             = shard_id;
    j["beacon_anchor_height"] = beacon_anchor_height;
    return j;
}

EquivocationEvent EquivocationEvent::from_json(const json& j) {
    // S-018: clear field-name diagnostics on malformed EquivocationEvent.
    // (External submission via submit_equivocation RPC is the primary
    // attack surface — a clear error makes the forensic tool's job
    // easier when an operator types a bad hash.) Every consensus field is
    // REQUIRED (EQV-height-bind + EQV-gen-bind: kind + the two
    // (index, gen, body_root) openings are what the verifier derives the
    // signed digests from).
    EquivocationEvent e;
    e.equivocator          = json_require<std::string>(j, "equivocator");
    e.block_index          = json_require<uint64_t>(j, "block_index");
    uint64_t kind_wide     = json_require<uint64_t>(j, "kind");
    if (kind_wide > 1)
        throw std::runtime_error(
            "EquivocationEvent.kind > 1 (expected 0=BLOCK_DIGEST or 1=CONTRIB_COMMIT)");
    e.kind                 = static_cast<uint8_t>(kind_wide);
    e.index_a              = json_require<uint64_t>(j, "index_a");
    e.gen_a                = json_require<uint64_t>(j, "gen_a");
    e.body_root_a          = from_hex_arr<32>(json_require_hex(j, "body_root_a", 64));
    e.sig_a                = from_hex_arr<64>(json_require_hex(j, "sig_a", 128));
    e.index_b              = json_require<uint64_t>(j, "index_b");
    e.gen_b                = json_require<uint64_t>(j, "gen_b");
    e.body_root_b          = from_hex_arr<32>(json_require_hex(j, "body_root_b", 64));
    e.sig_b                = from_hex_arr<64>(json_require_hex(j, "sig_b", 128));
    e.shard_id             = j.value("shard_id",             uint32_t{0});
    e.beacon_anchor_height = j.value("beacon_anchor_height", uint64_t{0});
    return e;
}

// ─── MergeEvent ──────────────────────────────────────────────────────────────

std::vector<uint8_t> MergeEvent::encode() const {
    std::vector<uint8_t> out;
    out.reserve(26 + merging_shard_region.size());
    out.push_back(event_type);
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>((shard_id   >> (8 * i)) & 0xff));
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>((partner_id >> (8 * i)) & 0xff));
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<uint8_t>((effective_height       >> (8 * i)) & 0xff));
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<uint8_t>((evidence_window_start  >> (8 * i)) & 0xff));
    out.push_back(static_cast<uint8_t>(merging_shard_region.size()));
    out.insert(out.end(),
                 merging_shard_region.begin(), merging_shard_region.end());
    return out;
}

std::optional<MergeEvent> MergeEvent::decode(const std::vector<uint8_t>& p) {
    if (p.size() < 26) return std::nullopt;
    if (p[0] > 1)      return std::nullopt;
    size_t rlen = p[25];
    if (rlen > 32)     return std::nullopt;
    if (p.size() != 26 + rlen) return std::nullopt;
    MergeEvent ev;
    ev.event_type = p[0];
    ev.shard_id = 0;
    ev.partner_id = 0;
    for (int i = 0; i < 4; ++i) {
        ev.shard_id   |= uint32_t(p[1 + i]) << (8 * i);
        ev.partner_id |= uint32_t(p[5 + i]) << (8 * i);
    }
    ev.effective_height = 0;
    ev.evidence_window_start = 0;
    for (int i = 0; i < 8; ++i) {
        ev.effective_height      |= uint64_t(p[9  + i]) << (8 * i);
        ev.evidence_window_start |= uint64_t(p[17 + i]) << (8 * i);
    }
    ev.merging_shard_region.assign(
        reinterpret_cast<const char*>(p.data() + 26), rlen);
    return ev;
}

// ─── ShardTipRecord (D3.1 / ShardTipMergeDesign.md §9) ───────────────────────
std::vector<uint8_t> ShardTipRecord::encode() const {
    std::vector<uint8_t> out;
    out.reserve(49 + region.size());
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>((source_shard_id >> (8 * i)) & 0xff));
    for (int i = 0; i < 8; ++i)
        out.push_back(static_cast<uint8_t>((height         >> (8 * i)) & 0xff));
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>((eligible_count >> (8 * i)) & 0xff));
    out.insert(out.end(), committee_sig_root.begin(), committee_sig_root.end());
    out.push_back(static_cast<uint8_t>(region.size()));
    out.insert(out.end(), region.begin(), region.end());
    return out;
}

std::optional<ShardTipRecord> ShardTipRecord::decode(const std::vector<uint8_t>& p) {
    if (p.size() < 49) return std::nullopt;
    size_t rlen = p[48];
    if (rlen > 32)     return std::nullopt;
    if (p.size() != 49 + rlen) return std::nullopt;
    ShardTipRecord r;
    for (int i = 0; i < 4; ++i)
        r.source_shard_id |= uint32_t(p[i])      << (8 * i);
    for (int i = 0; i < 8; ++i)
        r.height          |= uint64_t(p[4  + i]) << (8 * i);
    for (int i = 0; i < 4; ++i)
        r.eligible_count  |= uint32_t(p[12 + i]) << (8 * i);
    std::copy(p.begin() + 16, p.begin() + 48, r.committee_sig_root.begin());
    r.region.assign(reinterpret_cast<const char*>(p.data() + 49), rlen);
    return r;
}

// ─── CrossShardReceipt ───────────────────────────────────────────────────────

json CrossShardReceipt::to_json() const {
    json j;
    j["src_shard"]       = src_shard;
    j["dst_shard"]       = dst_shard;
    j["src_block_index"] = src_block_index;
    j["src_block_hash"]  = to_hex(src_block_hash);
    j["tx_hash"]         = to_hex(tx_hash);
    j["from"]            = from;
    j["to"]              = to;
    j["amount"]          = amount;
    j["fee"]             = fee;
    j["nonce"]           = nonce;
    return j;
}

CrossShardReceipt CrossShardReceipt::from_json(const json& j) {
    // S-018 follow-on: every consensus-critical field is required. A
    // receipt is bound into the parent block's signing_bytes, so a
    // tampered receipt fails K-of-K — but defense-in-depth at the
    // parse layer means a malformed receipt is rejected immediately
    // with a clear field-name diagnostic rather than silently zeroing
    // the missing field and propagating to deeper validation.
    CrossShardReceipt r;
    r.src_shard       = json_require<uint32_t>(j, "src_shard");
    r.dst_shard       = json_require<uint32_t>(j, "dst_shard");
    r.src_block_index = json_require<uint64_t>(j, "src_block_index");
    r.src_block_hash  = from_hex_arr<32>(json_require_hex(j, "src_block_hash", 64));
    r.tx_hash         = from_hex_arr<32>(json_require_hex(j, "tx_hash",        64));
    r.from            = json_require<std::string>(j, "from");
    r.to              = json_require<std::string>(j, "to");
    r.amount          = json_require<uint64_t>(j, "amount");
    r.fee             = json_require<uint64_t>(j, "fee");
    r.nonce           = json_require<uint64_t>(j, "nonce");
    return r;
}

// ─── Block ───────────────────────────────────────────────────────────────────

// D3.5a / S-036: one order-independent commitment over a block's ShardTipRecord
// set — SHA256 over the dedup-sorted set of per-record SHA256(rec.encode()). This
// replicates compute_view_root(...) (producer.cpp:377: a std::set<Hash> fed into a
// rolling SHA256) at the chain layer, so Block::signing_bytes binds the SAME root
// value the node's compute_block_digest + the light mirror bind. Callers skip the
// append on an empty set, so the empty-set value is never used.
static Hash shard_tip_records_root(const std::vector<ShardTipRecord>& recs) {
    std::set<Hash> keys;
    for (auto& r : recs) {
        auto enc = r.encode();
        SHA256Builder rb;
        rb.append(enc.data(), enc.size());
        keys.insert(rb.finalize());
    }
    SHA256Builder b;
    for (auto& k : keys) b.append(k);
    return b.finalize();
}

// D3.5e-7 / S-036: one order-independent root over the shard-tip WITNESS set, keyed
// on each witness's full block identity (compute_hash). Bound into signing_bytes so a
// relayer that strips/reorders/forges a witness yields a distinct block hash (the
// anti-strip closure). Uses compute_hash — chain-lib-local, no node/digest dependency;
// a witness is a leaf (empty shard_tip_witnesses) so its own signing_bytes skips this
// append and the recursion terminates at depth ≤ 2. Callers skip the append on an
// empty set, so the empty-set value is never used.
static Hash shard_tip_witnesses_root(const std::vector<Block>& ws) {
    std::set<Hash> keys;
    for (auto& w : ws) keys.insert(w.compute_hash());
    SHA256Builder b;
    for (auto& k : keys) b.append(k);
    return b.finalize();
}

std::vector<uint8_t> Block::signing_bytes() const {
    SHA256Builder b;
    b.append(static_cast<uint64_t>(index));
    b.append(prev_hash);
    b.append(timestamp);

    SHA256Builder txh;
    for (auto& tx : transactions) {
        auto sb = tx.signing_bytes();
        txh.append(sb.data(), sb.size());
    }
    b.append(txh.finalize());

    for (auto& c : creators) b.append(c);

    for (auto& list : creator_tx_lists)
        for (auto& h : list) b.append(h);
    for (auto& s : creator_ed_sigs)
        b.append(s.data(), s.size());
    for (auto& h : creator_dh_inputs) b.append(h);
    for (auto& h : creator_dh_secrets) b.append(h);

    b.append(tx_root);
    b.append(delay_seed);
    b.append(delay_output);
    b.append(static_cast<uint8_t>(consensus_mode));
    b.append(bft_proposer);
    b.append(cumulative_rand);
    for (auto& ae : abort_events) b.append(ae.event_hash);
    // Bind equivocation events into the block hash so any tampering
    // with evidence (changing equivocator, sigs, openings) changes the
    // block hash and breaks consensus on it. Same field list/order as
    // the EQUIV_REC frame (EQV-height-bind + EQV-gen-bind).
    for (auto& ev : equivocation_events) {
        b.append(ev.equivocator);
        b.append(ev.block_index);
        b.append(ev.kind);
        b.append(ev.index_a);
        b.append(ev.gen_a);
        b.append(ev.body_root_a);
        b.append(ev.sig_a.data(), ev.sig_a.size());
        b.append(ev.index_b);
        b.append(ev.gen_b);
        b.append(ev.body_root_b);
        b.append(ev.sig_b.data(), ev.sig_b.size());
        b.append(static_cast<uint64_t>(ev.shard_id));
        b.append(ev.beacon_anchor_height);
    }

    // Bind cross-shard receipts into the block hash. Any tampering with
    // receipt fields (especially `to` or `amount`) would change the hash
    // and break K-of-K signing on the source side, so dst-side credits
    // remain safe even though dst doesn't re-sign receipts.
    for (auto& r : cross_shard_receipts) {
        b.append(static_cast<uint64_t>(r.src_shard));
        b.append(static_cast<uint64_t>(r.dst_shard));
        b.append(r.src_block_index);
        b.append(r.src_block_hash);
        b.append(r.tx_hash);
        b.append(r.from);
        b.append(r.to);
        b.append(r.amount);
        b.append(r.fee);
        b.append(r.nonce);
    }

    // rev.9 B3.4: bind inbound receipts (this block credits them) so
    // the destination committee's K-of-K signing certifies the exact
    // set credited. Source K-of-K verification happens at receive time
    // (each producer ratifies independently); the destination block's
    // signing is the committee's collective attestation.
    for (auto& r : inbound_receipts) {
        b.append(static_cast<uint64_t>(r.src_shard));
        b.append(static_cast<uint64_t>(r.dst_shard));
        b.append(r.src_block_index);
        b.append(r.tx_hash);
        b.append(r.to);
        b.append(r.amount);
    }

    for (auto& a : initial_state) {
        b.append(a.domain);
        b.append(a.ed_pub.data(), a.ed_pub.size());
        b.append(a.balance);
        b.append(a.stake);
        // rev.9 R1: bind region into the genesis block hash ONLY when
        // non-empty. Empty region preserves byte-identical signing
        // bytes with pre-R1 genesis blocks (backward-compat invariant).
        if (!a.region.empty()) {
            b.append(static_cast<uint8_t>(a.region.size()));
            b.append(a.region);
        }
    }

    // R4 Phase 3: bind partner_subset_hash into block signing-bytes
    // ONLY when non-zero. Default zero-hash preserves byte-identical
    // signing bytes for all pre-R4 / non-merged blocks — every existing
    // test stays hash-stable. Non-zero binds the partner shard's tx
    // subset commitment into the K-of-K committee signature, closing
    // the cross-chain merged-signing path described in the R4 design.
    {
        Hash zero{};
        if (partner_subset_hash != zero) {
            b.append(partner_subset_hash);
        }
    }

    // S-033 / v2.1: bind state_root into the block hash chain ONLY when
    // non-zero. Same backward-compat pattern as partner_subset_hash —
    // pre-S-033 blocks have zero state_root and contribute nothing to
    // signing_bytes. When the producer populates it (post-feature-toggle),
    // the K-of-K committee signatures cover the state-after-apply
    // commitment. Validator re-derives and rejects on mismatch. The
    // prev_hash chain then forward-binds the commitment so any future
    // block's verification transitively authenticates all prior state
    // roots — turning the chain into a verifiable state log.
    {
        Hash zero{};
        if (state_root != zero) {
            b.append(state_root);
        }
    }

    // A6 / §7.5.1: bind signature_form ONLY when non-zero (the same
    // zero-skip pattern). Two blocks that agree on every other field but
    // differ in signature_form must have distinct hashes, so a relabelled
    // sig array can never alias the Ed25519 form's hash. v1.1 blocks are
    // all form 0 (validator fail-closes on anything else) → byte-identical.
    if (signature_form != 0) {
        b.append(static_cast<uint8_t>(signature_form));
    }

    // D3.4 / S-036: bind eligible_count into the block hash ONLY when non-zero
    // (the same zero-skip pattern as signature_form / partner_subset_hash). Two
    // blocks that agree on every other field but differ in the source's self-
    // reported count get DISTINCT hashes, so the count is part of block identity
    // — belt-and-suspenders alongside the compute_block_digest binding (which is
    // what the K-of-K signatures actually cover). Zero (every SINGLE / CURRENT /
    // BEACON / pre-feature block) appends nothing → byte-identical hash. Widened
    // to u64 to match the canonical field encoding used in the digest mirrors.
    if (eligible_count != 0) {
        b.append(static_cast<uint64_t>(eligible_count));
        // D3.5e-6 / S-036: bind the SOURCE SHARD IDENTITY into block identity too,
        // riding the same EXTENDED-source gate (eligible_count != 0 fires for every
        // produced source block incl. shard 0). Keeps the block hash in lockstep
        // with the K-of-K digest (producer.cpp compute_block_digest) so a tip that
        // is replayed under a different claimed shard has both a mismatched signed
        // digest AND a distinct block identity. Field order: …, eligible_count,
        // source_shard_id.
        b.append(static_cast<uint64_t>(source_shard_id));
    }

    // D3.5a / S-036: bind the shard-tip-record set into the block hash ONLY when
    // non-empty (same empty-skip pattern). Bound as ONE order-independent root, so
    // a stripped/reordered record after signing yields a distinct hash. Empty (every
    // SINGLE / CURRENT / BEACON / pre-feature block, and every EXTENDED block until
    // D3.5c populates it) appends nothing → byte-identical. Field order (all last):
    // …, signature_form, eligible_count, shard_tip_records.
    if (!shard_tip_records.empty()) {
        b.append(shard_tip_records_root(shard_tip_records));
    }

    // D3.5e-7 / S-036: bind the shard-tip WITNESS set into the block hash ONLY when
    // non-empty (same empty-skip pattern), as ONE order-independent root over each
    // witness's compute_hash. This is the ANTI-STRIP closure — a relayer that
    // strips/reorders/forges a witness yields a distinct block hash that no honest
    // node's prev_hash chain commits to. NOT bound into compute_block_digest (the
    // Byzantine-beacon-signed value is not the witness's trust anchor). Empty on
    // every non-distress block ⇒ appends nothing ⇒ byte-identical. Field order (all
    // last): …, eligible_count, source_shard_id, shard_tip_records, shard_tip_witnesses.
    if (!shard_tip_witnesses.empty()) {
        b.append(shard_tip_witnesses_root(shard_tip_witnesses));
    }

    Hash h = b.finalize();
    return std::vector<uint8_t>(h.begin(), h.end());
}

Hash Block::compute_hash() const {
    auto sb = signing_bytes();
    SHA256Builder b;
    b.append(sb.data(), sb.size());
    // Bind per-creator block sigs into the hash so any equivocation on them
    // produces a different block hash.
    for (auto& s : creator_block_sigs)
        b.append(s.data(), s.size());
    return b.finalize();
}

json Block::to_json() const {
    json j;
    j["index"]          = index;
    j["prev_hash"]      = to_hex(prev_hash);
    j["timestamp"]      = timestamp;

    json txs = json::array();
    for (auto& tx : transactions) txs.push_back(tx.to_json());
    j["transactions"]   = txs;

    json jc = json::array();
    for (auto& c : creators) jc.push_back(c);
    j["creators"]        = jc;

    json jctl = json::array();
    for (auto& list : creator_tx_lists) {
        json one = json::array();
        for (auto& h : list) one.push_back(to_hex(h));
        jctl.push_back(one);
    }
    j["creator_tx_lists"] = jctl;

    json jeds = json::array();
    for (auto& s : creator_ed_sigs) jeds.push_back(to_hex(s));
    j["creator_ed_sigs"]  = jeds;

    json jdi = json::array();
    for (auto& h : creator_dh_inputs) jdi.push_back(to_hex(h));
    j["creator_dh_inputs"] = jdi;

    // v2.7 F2 / S-016: per-creator view roots. Emitted ONLY when at least one
    // root is non-zero, so pre-F2 / non-cross-shard blocks keep byte-identical
    // JSON (and chain.json representation). from_json defaults them to empty;
    // the validator treats empty/zero as the v1 (no-view) commit.
    bool any_view_root = false;
    for (auto& h : creator_view_inbound_roots) if (h != Hash{}) { any_view_root = true; break; }
    if (!any_view_root)
        for (auto& h : creator_view_eq_roots) if (h != Hash{}) { any_view_root = true; break; }
    if (!any_view_root)
        for (auto& h : creator_view_abort_roots) if (h != Hash{}) { any_view_root = true; break; }
    if (any_view_root) {
        json jve = json::array();
        for (auto& h : creator_view_eq_roots) jve.push_back(to_hex(h));
        json jva = json::array();
        for (auto& h : creator_view_abort_roots) jva.push_back(to_hex(h));
        json jvi = json::array();
        for (auto& h : creator_view_inbound_roots) jvi.push_back(to_hex(h));
        j["creator_view_eq_roots"]      = jve;
        j["creator_view_abort_roots"]   = jva;
        j["creator_view_inbound_roots"] = jvi;
        // site 3: the inbound view lists (enforce the intersection).
        json jvil = json::array();
        for (auto& list : creator_view_inbound_lists) {
            json one = json::array();
            for (auto& h : list) one.push_back(to_hex(h));
            jvil.push_back(one);
        }
        j["creator_view_inbound_lists"] = jvil;
        // v2.7 F2 / S-030-D2 (eq/abort dimension): the eq/abort view lists
        // (enforce subset-of-union). Emitted under the same any_view_root gate.
        json jvel = json::array();
        for (auto& list : creator_view_eq_lists) {
            json one = json::array();
            for (auto& h : list) one.push_back(to_hex(h));
            jvel.push_back(one);
        }
        j["creator_view_eq_lists"] = jvel;
        json jval = json::array();
        for (auto& list : creator_view_abort_lists) {
            json one = json::array();
            for (auto& h : list) one.push_back(to_hex(h));
            jval.push_back(one);
        }
        j["creator_view_abort_lists"] = jval;
    }

    // D3.5d: emit the shard-tip view roots + lists under their OWN any-nonzero
    // gate (independent of the F2 any_view_root block above — a beacon block may
    // carry a shard-tip view with no eq/abort/inbound view). Every non-beacon /
    // pre-D3.5 block omits them entirely, keeping a byte-identical block JSON.
    bool any_shardtip_root = false;
    for (auto& h : creator_view_shardtip_roots) if (h != Hash{}) { any_shardtip_root = true; break; }
    if (any_shardtip_root) {
        json jstr = json::array();
        for (auto& h : creator_view_shardtip_roots) jstr.push_back(to_hex(h));
        j["creator_view_shardtip_roots"] = jstr;
        json jstl = json::array();
        for (auto& list : creator_view_shardtip_lists) {
            json one = json::array();
            for (auto& h : list) one.push_back(to_hex(h));
            jstl.push_back(one);
        }
        j["creator_view_shardtip_lists"] = jstl;
    }

    // S-030-D2 timestamp reconciliation: per-creator committed times. Emitted
    // only when present (production reconciled blocks); pre-feature / legacy /
    // test blocks omit the field entirely, so their JSON stays byte-identical.
    if (!creator_proposer_times.empty()) {
        json jpt = json::array();
        for (uint64_t t : creator_proposer_times) jpt.push_back(t);
        j["creator_proposer_times"] = jpt;
    }

    json jds = json::array();
    for (auto& h : creator_dh_secrets) jds.push_back(to_hex(h));
    j["creator_dh_secrets"] = jds;

    j["tx_root"]         = to_hex(tx_root);
    j["delay_seed"]      = to_hex(delay_seed);
    j["delay_output"]    = to_hex(delay_output);
    j["consensus_mode"]  = static_cast<uint8_t>(consensus_mode);
    j["bft_proposer"]    = bft_proposer;

    json jbs = json::array();
    for (auto& s : creator_block_sigs) jbs.push_back(to_hex(s));
    j["creator_block_sigs"] = jbs;

    j["cumulative_rand"] = to_hex(cumulative_rand);

    json aes = json::array();
    for (auto& ae : abort_events) aes.push_back(ae.to_json());
    j["abort_events"]   = aes;

    json eqs = json::array();
    for (auto& ev : equivocation_events) eqs.push_back(ev.to_json());
    j["equivocation_events"] = eqs;

    json csrs = json::array();
    for (auto& r : cross_shard_receipts) csrs.push_back(r.to_json());
    j["cross_shard_receipts"] = csrs;

    json ibrs = json::array();
    for (auto& r : inbound_receipts) ibrs.push_back(r.to_json());
    j["inbound_receipts"] = ibrs;

    json is_arr = json::array();
    for (auto& a : initial_state) is_arr.push_back(a.to_json());
    j["initial_state"]  = is_arr;

    // S-033 / v2.1: serialize state_root only when non-zero.
    {
        Hash zero{};
        if (state_root != zero)
            j["state_root"] = to_hex(state_root);
    }
    // R4 Phase 3: serialize partner_subset_hash only when non-zero.
    // Pre-R4 / non-merged blocks omit the key entirely, keeping JSON
    // byte-identical for existing chain.json files.
    {
        Hash zero{};
        if (partner_subset_hash != zero)
            j["partner_subset_hash"] = to_hex(partner_subset_hash);
    }
    // A6 / §7.5.1: serialize signature_form only when non-zero (form 0 =
    // the shipped Ed25519 K-of-K default — omitted, byte-identical JSON).
    if (signature_form != 0)
        j["signature_form"] = static_cast<int>(signature_form);
    // D3.4 / S-036: serialize eligible_count only when non-zero (zero = the
    // SINGLE/CURRENT/BEACON default — omitted, byte-identical JSON). A produced
    // SHARD block always carries >= K >= 1, so zero unambiguously means absent.
    if (eligible_count != 0) {
        j["eligible_count"] = eligible_count;
        // D3.5e-6 / S-036: serialize source_shard_id under the SAME gate so a
        // reloaded/gossiped EXTENDED source block reconstructs the exact
        // digest-bound value. Coupled to eligible_count (never source_shard_id != 0)
        // because shard 0's legitimate source_shard_id is 0 yet must round-trip;
        // conversely a non-EXTENDED block (eligible_count == 0) omits it and stays
        // byte-identical regardless of any in-memory shard id.
        j["source_shard_id"] = source_shard_id;
    }
    // D3.5a / S-036: serialize the shard-tip-record set only when non-empty (each
    // element the hex of its canonical D3.1 encode()); omitted ⇒ byte-identical JSON.
    if (!shard_tip_records.empty()) {
        json arr = json::array();
        for (auto& r : shard_tip_records) {
            auto enc = r.encode();
            arr.push_back(to_hex(enc.data(), enc.size()));
        }
        j["shard_tip_records"] = arr;
    }
    // D3.5e-7 / S-036: serialize the shard-tip WITNESS set only when non-empty (each
    // element the full source tip Block via its own to_json); omitted ⇒ byte-identical
    // JSON. Index-aligned to shard_tip_records.
    if (!shard_tip_witnesses.empty()) {
        json arr = json::array();
        for (auto& w : shard_tip_witnesses) arr.push_back(w.to_json());
        j["shard_tip_witnesses"] = arr;
    }

    return j;
}

Block Block::from_json(const json& j) {
    // D3.5e-7: the public entry allows a beacon block to carry witnesses; each
    // witness is a LEAF parsed with allow_witnesses=false (see the overload).
    return Block::from_json(j, /*allow_witnesses=*/true);
}

Block Block::from_json(const json& j, bool allow_witnesses) {
    // S-018: required Block fields fetched through json_require<T> /
    // json_require_hex so a malformed BLOCK gossip message produces a
    // diagnostic naming the failing field. Optional fields keep the
    // existing `j.contains(...)` guards (already structured; not the
    // S-018 surface).
    Block b;
    b.index         = json_require<uint64_t>(j, "index");
    b.prev_hash     = from_hex_arr<32>(json_require_hex(j, "prev_hash", 64));
    b.timestamp     = json_require<int64_t>(j, "timestamp");

    for (auto& tx : json_require_array(j, "transactions"))
        b.transactions.push_back(Transaction::from_json(tx));

    for (auto& c : json_require_array(j, "creators"))
        b.creators.push_back(c.get<std::string>());

    // S-018 defense-in-depth: optional fields gain the same wrong-
    // type rejection that required fields get via json_require_array.
    // Pattern: outer `j.contains(...)` makes the field optional;
    // inner `json_require_array` ensures that IF present, the field
    // is a JSON array (not a scalar). Without this, a peer sending
    // `"creator_tx_lists": 42` would throw an opaque nlohmann error
    // mid-iteration; now it throws a clean S-018 field-name diagnostic.
    if (j.contains("creator_tx_lists")) {
        for (auto& one : json_require_array(j, "creator_tx_lists")) {
            std::vector<Hash> list;
            for (auto& h : one) list.push_back(from_hex_arr<32>(h.get<std::string>()));
            b.creator_tx_lists.push_back(std::move(list));
        }
    }
    if (j.contains("creator_ed_sigs")) {
        for (auto& s : json_require_array(j, "creator_ed_sigs"))
            b.creator_ed_sigs.push_back(from_hex_arr<64>(s.get<std::string>()));
    }
    if (j.contains("creator_dh_inputs")) {
        for (auto& h : json_require_array(j, "creator_dh_inputs"))
            b.creator_dh_inputs.push_back(from_hex_arr<32>(h.get<std::string>()));
    }
    // v2.7 F2 / S-016: per-creator view roots (absent on pre-F2 blocks).
    if (j.contains("creator_view_eq_roots")) {
        for (auto& h : json_require_array(j, "creator_view_eq_roots"))
            b.creator_view_eq_roots.push_back(from_hex_arr<32>(h.get<std::string>()));
    }
    if (j.contains("creator_view_abort_roots")) {
        for (auto& h : json_require_array(j, "creator_view_abort_roots"))
            b.creator_view_abort_roots.push_back(from_hex_arr<32>(h.get<std::string>()));
    }
    if (j.contains("creator_view_inbound_roots")) {
        for (auto& h : json_require_array(j, "creator_view_inbound_roots"))
            b.creator_view_inbound_roots.push_back(from_hex_arr<32>(h.get<std::string>()));
    }
    if (j.contains("creator_view_inbound_lists")) {
        for (auto& one : json_require_array(j, "creator_view_inbound_lists")) {
            std::vector<Hash> list;
            for (auto& h : one) list.push_back(from_hex_arr<32>(h.get<std::string>()));
            b.creator_view_inbound_lists.push_back(std::move(list));
        }
    }
    // v2.7 F2 / S-030-D2: per-creator eq/abort view lists (absent on pre-F2).
    if (j.contains("creator_view_eq_lists")) {
        for (auto& one : json_require_array(j, "creator_view_eq_lists")) {
            std::vector<Hash> list;
            for (auto& h : one) list.push_back(from_hex_arr<32>(h.get<std::string>()));
            b.creator_view_eq_lists.push_back(std::move(list));
        }
    }
    if (j.contains("creator_view_abort_lists")) {
        for (auto& one : json_require_array(j, "creator_view_abort_lists")) {
            std::vector<Hash> list;
            for (auto& h : one) list.push_back(from_hex_arr<32>(h.get<std::string>()));
            b.creator_view_abort_lists.push_back(std::move(list));
        }
    }
    // D3.5d shard-tip view roots + lists (optional; absent on non-beacon / pre-
    // D3.5 blocks → empty vectors, nothing bound). Mirrors the inbound parse.
    if (j.contains("creator_view_shardtip_roots")) {
        for (auto& h : json_require_array(j, "creator_view_shardtip_roots"))
            b.creator_view_shardtip_roots.push_back(from_hex_arr<32>(h.get<std::string>()));
    }
    if (j.contains("creator_view_shardtip_lists")) {
        for (auto& one : json_require_array(j, "creator_view_shardtip_lists")) {
            std::vector<Hash> list;
            for (auto& h : one) list.push_back(from_hex_arr<32>(h.get<std::string>()));
            b.creator_view_shardtip_lists.push_back(std::move(list));
        }
    }
    if (j.contains("creator_dh_secrets")) {
        for (auto& h : json_require_array(j, "creator_dh_secrets"))
            b.creator_dh_secrets.push_back(from_hex_arr<32>(h.get<std::string>()));
    }
    // S-030-D2 timestamp reconciliation: per-creator committed times (optional;
    // absent on pre-feature / legacy blocks → empty vector, timestamp not bound).
    if (j.contains("creator_proposer_times")) {
        for (auto& t : json_require_array(j, "creator_proposer_times"))
            b.creator_proposer_times.push_back(t.get<uint64_t>());
    }

    // S-018: optional fields with wrong-type detection. The
    // `j.contains(...)` guard handles the missing case; if present,
    // json_require_hex surfaces a clear diagnostic on length mismatch
    // or wrong inner type.
    if (j.contains("tx_root"))
        b.tx_root = from_hex_arr<32>(json_require_hex(j, "tx_root", 64));
    if (j.contains("delay_seed"))
        b.delay_seed = from_hex_arr<32>(json_require_hex(j, "delay_seed", 64));
    if (j.contains("delay_output"))
        b.delay_output = from_hex_arr<32>(json_require_hex(j, "delay_output", 64));
    if (j.contains("consensus_mode"))
        b.consensus_mode = static_cast<ConsensusMode>(json_require<uint8_t>(j, "consensus_mode"));
    if (j.contains("bft_proposer"))
        b.bft_proposer = json_require<std::string>(j, "bft_proposer");

    if (j.contains("creator_block_sigs")) {
        for (auto& s : json_require_array(j, "creator_block_sigs"))
            b.creator_block_sigs.push_back(from_hex_arr<64>(s.get<std::string>()));
    }

    b.cumulative_rand = from_hex_arr<32>(json_require_hex(j, "cumulative_rand", 64));
    for (auto& ae : json_require_array(j, "abort_events"))
        b.abort_events.push_back(AbortEvent::from_json(ae));

    if (j.contains("equivocation_events")) {
        for (auto& ej : json_require_array(j, "equivocation_events"))
            b.equivocation_events.push_back(EquivocationEvent::from_json(ej));
    }

    if (j.contains("cross_shard_receipts")) {
        for (auto& rj : json_require_array(j, "cross_shard_receipts"))
            b.cross_shard_receipts.push_back(CrossShardReceipt::from_json(rj));
    }

    if (j.contains("inbound_receipts")) {
        for (auto& rj : json_require_array(j, "inbound_receipts"))
            b.inbound_receipts.push_back(CrossShardReceipt::from_json(rj));
    }

    if (j.contains("initial_state"))
        for (auto& ia : json_require_array(j, "initial_state"))
            b.initial_state.push_back(GenesisAlloc::from_json(ia));

    if (j.contains("partner_subset_hash"))
        b.partner_subset_hash =
            from_hex_arr<32>(json_require_hex(j, "partner_subset_hash", 64));
    if (j.contains("state_root"))
        b.state_root =
            from_hex_arr<32>(json_require_hex(j, "state_root", 64));
    // A6 / §7.5.1: absent key = form 0 (the pre-A6 encoding). S-018: a
    // present key must be an in-range integer — out-of-range u8 fails closed
    // here rather than truncating into a DIFFERENT (possibly accepted) form.
    if (j.contains("signature_form")) {
        int f = json_require<int>(j, "signature_form");
        if (f < 0 || f > 0xFF)
            throw std::runtime_error("block.signature_form out of u8 range");
        b.signature_form = static_cast<uint8_t>(f);
    }
    // D3.4 / S-036: parse eligible_count when present (u32; absent = zero). An
    // out-of-range value fails closed rather than truncating into a smaller
    // count that could spuriously read as "distressed" (< 2K) downstream.
    if (j.contains("eligible_count")) {
        uint64_t ec = json_require<uint64_t>(j, "eligible_count");
        if (ec > 0xFFFFFFFFull)
            throw std::runtime_error("block.eligible_count out of u32 range");
        b.eligible_count = static_cast<uint32_t>(ec);
    }
    // D3.5e-6 / S-036: parse source_shard_id when present (u32; absent = zero).
    // Fail closed on an out-of-range value rather than truncating into a different
    // shard id that could spoof a region-mate tip. Independent of eligible_count on
    // the parse side (a hand-authored JSON may carry either), but the two are
    // emitted together by to_json and bound together by the digest/hash.
    if (j.contains("source_shard_id")) {
        uint64_t sid = json_require<uint64_t>(j, "source_shard_id");
        if (sid > 0xFFFFFFFFull)
            throw std::runtime_error("block.source_shard_id out of u32 range");
        b.source_shard_id = static_cast<uint32_t>(sid);
    }
    // D3.5a / S-036: parse the shard-tip-record set (hex of each canonical encode()).
    // Fail closed on a malformed / over-long record rather than silently dropping it.
    if (j.contains("shard_tip_records")) {
        for (auto& e : json_require_array(j, "shard_tip_records")) {
            auto dec = ShardTipRecord::decode(from_hex(e.get<std::string>()));
            if (!dec) throw std::runtime_error("block.shard_tip_records: malformed record");
            b.shard_tip_records.push_back(*dec);
        }
    }
    // D3.5e-7 / S-036: parse the shard-tip WITNESS set (each a full source tip
    // Block). Depth-1 DoS guard: a witness is a LEAF — parsed with
    // allow_witnesses=false so a nested `shard_tip_witnesses` throws BEFORE the
    // recursive descent (bounds parse depth ≤ 2). Also reject a witness carrying its
    // own records (only a beacon block folds records; a source tip never does).
    if (j.contains("shard_tip_witnesses")) {
        if (!allow_witnesses)
            throw std::runtime_error(
                "block.shard_tip_witnesses: a witness must be a leaf block (no nested witnesses)");
        for (auto& e : json_require_array(j, "shard_tip_witnesses")) {
            Block w = Block::from_json(e, /*allow_witnesses=*/false);
            if (!w.shard_tip_records.empty())
                throw std::runtime_error(
                    "block.shard_tip_witnesses: a witness must carry empty shard_tip_records");
            b.shard_tip_witnesses.push_back(std::move(w));
        }
    }

    return b;
}

// ─── Block binary frame (canonical, D2-inc5) ─────────────────────────────────
//
// Layout, in Block::to_json emission order so the two are diffable side by
// side. All integers little-endian; Hash = 32 raw bytes; Signature = 64 raw;
// PubKey = 32 raw; lp_str = [u8 len][bytes]; ⟨n⟩ = [u16 LE count].
//
//   index u64 · prev_hash 32 · timestamp i64-as-u64
//   transactions          ⟨n⟩ × [u32 frame_len][tx frame]
//   creators              ⟨n⟩ × lp_str
//   creator_tx_lists      ⟨n⟩ × ( ⟨m⟩ × 32 )
//   creator_ed_sigs       ⟨n⟩ × 64
//   creator_dh_inputs     ⟨n⟩ × 32
//   creator_view_eq_roots / _abort_roots / _inbound_roots      ⟨n⟩ × 32   (×3)
//   creator_view_inbound_lists / _eq_lists / _abort_lists  ⟨n⟩ × (⟨m⟩ × 32) (×3)
//   creator_view_shardtip_roots ⟨n⟩ × 32 · _shardtip_lists ⟨n⟩ × (⟨m⟩ × 32)
//   creator_proposer_times ⟨n⟩ × u64
//   creator_dh_secrets    ⟨n⟩ × 32
//   tx_root 32 · delay_seed 32 · delay_output 32
//   consensus_mode u8 · bft_proposer lp_str
//   creator_block_sigs    ⟨n⟩ × 64
//   cumulative_rand 32
//   abort_events          ⟨n⟩ × ABORT_EVENT_REC
//   equivocation_events   ⟨n⟩ × EQUIV_REC
//   cross_shard_receipts  ⟨n⟩ × RECEIPT_REC
//   inbound_receipts      ⟨n⟩ × RECEIPT_REC
//   initial_state         ⟨n⟩ × ALLOC_REC
//   state_root 32 · partner_subset_hash 32 · signature_form u8
//   eligible_count u32 · source_shard_id u32
//   shard_tip_records     ⟨n⟩ × [u8 rec_len][ShardTipRecord::encode()]
//   shard_tip_witnesses   ⟨n⟩ × [u32 frame_len][BLOCK FRAME]
//
// The three length prefixes ([u32] on a tx frame and a witness frame, [u8] on a
// record) are MANDATORY, not stylistic: every nested codec is exact-consuming
// over the whole buffer it is handed (Transaction::decode_frame,
// decode_abort_claims, ShardTipRecord::decode all reject trailing bytes), so
// none of them can be handed a suffix and asked to stop at the right place.
// The claims blob inside ABORT_EVENT_REC needs one for the same reason — it is
// last within its record but not last within the frame.
//
//   ABORT_EVENT_REC  [round u8][aborting_node lp_str][timestamp i64-as-u64]
//                    [event_hash 32][u32 claims_len][encode_abort_claims bytes]
//   EQUIV_REC        [equivocator lp_str][block_index u64][kind u8]
//                    [index_a u64][gen_a u64][body_root_a 32][sig_a 64]
//                    [index_b u64][gen_b u64][body_root_b 32][sig_b 64]
//                    [shard_id u32][beacon_anchor_height u64]
//                    (EQV-height-bind + EQV-gen-bind: decode fail-closes on
//                    kind > 1, the MergeEvent::decode precedent; layout
//                    identical to the EQUIVOCATION_EVIDENCE gossip frame)
//   RECEIPT_REC      [src_shard u32][dst_shard u32][src_block_index u64]
//                    [src_block_hash 32][tx_hash 32][from lp_str][to lp_str]
//                    [amount u64][fee u64][nonce u64]
//   ALLOC_REC        [domain lp_str][ed_pub 32][balance u64][stake u64]
//                    [region lp_str]

namespace {

// Minimum encoded size of ONE element of each counted array. Used to reject an
// impossible count BEFORE allocating for it: a 2-byte prefix claiming 65535
// elements must be backed by at least count*min bytes of body, or it is a lie.
// This is the whole defense against a count-driven allocation blow-up, so it
// runs before every reserve and every loop.
constexpr size_t kMinTxFrame        = 131 + 4; // decode_frame minimum + length prefix
constexpr size_t kMinLpStr          = 1;       // the length byte alone (empty string)
constexpr size_t kMinInnerHashList  = 2;       // an inner ⟨m⟩ count of zero
constexpr size_t kMinHash           = 32;
constexpr size_t kMinSig            = 64;
constexpr size_t kMinU64            = 8;
constexpr size_t kMinAbortEvent     = 1 + 1 + 8 + 32 + 4;      // + claims blob
constexpr size_t kMinEquivEvent     = 1 + 8 + 1 + (8 + 8 + 32 + 64) * 2 + 4 + 8; // = 246
constexpr size_t kMinReceipt        = 4 + 4 + 8 + 32 + 32 + 1 + 1 + 8 + 8 + 8;
constexpr size_t kMinAlloc          = 1 + 32 + 8 + 8 + 1;
constexpr size_t kMinShardTipRecord = 1 + 49;                  // u8 len + minimum record
// The smallest possible Block frame: every fixed field at its width plus the
// 23 two-byte counts, all empty. Pinned by a gate (BF-0) so this constant
// cannot silently drift out of agreement with the encoder — if it were set too
// HIGH, the Layer-1 cap would reject legitimate one-witness frames.
constexpr size_t kMinBlockFrame     = 297;
constexpr size_t kMinWitness        = 4 + kMinBlockFrame;      // u32 len + frame

[[noreturn]] void bf_throw(const std::string& what) {
    throw std::runtime_error("block frame: " + what);
}

void bf_need(size_t off, size_t need, size_t len, const char* what) {
    if (off + need > len) bf_throw(std::string("truncated ") + what);
}

// Write a u16 count, refusing rather than clamping — the 1a1b98f lesson.
void bf_put_count(std::vector<uint8_t>& out, size_t n, const char* what) {
    if (n > 0xFFFF)
        bf_throw(std::string(what) + " exceeds the u16 count field (" +
                 std::to_string(n) + ")");
    out.push_back(static_cast<uint8_t>(n & 0xFF));
    out.push_back(static_cast<uint8_t>((n >> 8) & 0xFF));
}

// Read a u16 count AND prove the body can back it, before the caller reserves.
uint16_t bf_get_count(const uint8_t* data, size_t len, size_t& off,
                      size_t min_elem, const char* what) {
    bf_need(off, 2, len, what);
    uint16_t n = static_cast<uint16_t>(data[off]) |
                 static_cast<uint16_t>(static_cast<uint16_t>(data[off + 1]) << 8);
    off += 2;
    // The cap runs HERE — before any reserve, before the loop. A frame
    // declaring more elements than its remaining bytes could possibly hold is
    // rejected having allocated nothing.
    if (min_elem != 0 && static_cast<size_t>(n) > (len - off) / min_elem)
        bf_throw(std::string(what) + " declares " + std::to_string(n) +
                 " elements but only " + std::to_string(len - off) +
                 " bytes remain");
    return n;
}

// lp_str with block-frame diagnostics. The tx-frame helper cannot be reused
// here: its throws say "tx frame: ...", which would misreport a truncated
// creators[3] inside a Block as a transaction-framing fault.
void bf_put_lp_str(std::vector<uint8_t>& out, const std::string& s,
                   const char* what) {
    if (s.size() > 255)
        bf_throw(std::string(what) + " exceeds 255 bytes (" +
                 std::to_string(s.size()) + ")");
    out.push_back(static_cast<uint8_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
}

std::string bf_get_lp_str(const uint8_t* data, size_t len, size_t& off,
                          const char* what) {
    bf_need(off, 1, len, what);
    uint8_t n = data[off++];
    bf_need(off, n, len, what);
    std::string s(reinterpret_cast<const char*>(data + off), n);
    off += n;
    return s;
}

void bf_put_u32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}
void bf_put_u64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}
uint32_t bf_get_u32(const uint8_t* data, size_t len, size_t& off, const char* what) {
    bf_need(off, 4, len, what);
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(data[off + i]) << (i * 8);
    off += 4;
    return v;
}
uint64_t bf_get_u64(const uint8_t* data, size_t len, size_t& off, const char* what) {
    bf_need(off, 8, len, what);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(data[off + i]) << (i * 8);
    off += 8;
    return v;
}
void bf_put_bytes(std::vector<uint8_t>& out, const uint8_t* p, size_t n) {
    out.insert(out.end(), p, p + n);
}
void bf_get_bytes(const uint8_t* data, size_t len, size_t& off,
                  uint8_t* dst, size_t n, const char* what) {
    bf_need(off, n, len, what);
    std::memcpy(dst, data + off, n);
    off += n;
}

void bf_put_hash_vec(std::vector<uint8_t>& out, const std::vector<Hash>& v,
                     const char* what) {
    bf_put_count(out, v.size(), what);
    for (auto& h : v) bf_put_bytes(out, h.data(), 32);
}
std::vector<Hash> bf_get_hash_vec(const uint8_t* data, size_t len, size_t& off,
                                  const char* what) {
    uint16_t n = bf_get_count(data, len, off, kMinHash, what);
    std::vector<Hash> v;
    v.reserve(n);
    for (uint16_t i = 0; i < n; ++i) {
        Hash h{};
        bf_get_bytes(data, len, off, h.data(), 32, what);
        v.push_back(h);
    }
    return v;
}

void bf_put_hash_lists(std::vector<uint8_t>& out,
                       const std::vector<std::vector<Hash>>& v, const char* what) {
    bf_put_count(out, v.size(), what);
    for (auto& list : v) {
        bf_put_count(out, list.size(), what);
        for (auto& h : list) bf_put_bytes(out, h.data(), 32);
    }
}
std::vector<std::vector<Hash>> bf_get_hash_lists(const uint8_t* data, size_t len,
                                                 size_t& off, const char* what) {
    uint16_t n = bf_get_count(data, len, off, kMinInnerHashList, what);
    std::vector<std::vector<Hash>> v;
    v.reserve(n);
    for (uint16_t i = 0; i < n; ++i) {
        uint16_t m = bf_get_count(data, len, off, kMinHash, what);
        std::vector<Hash> one;
        one.reserve(m);
        for (uint16_t k = 0; k < m; ++k) {
            Hash h{};
            bf_get_bytes(data, len, off, h.data(), 32, what);
            one.push_back(h);
        }
        v.push_back(std::move(one));
    }
    return v;
}

void bf_put_sig_vec(std::vector<uint8_t>& out, const std::vector<Signature>& v,
                    const char* what) {
    bf_put_count(out, v.size(), what);
    for (auto& s : v) bf_put_bytes(out, s.data(), 64);
}
std::vector<Signature> bf_get_sig_vec(const uint8_t* data, size_t len, size_t& off,
                                      const char* what) {
    uint16_t n = bf_get_count(data, len, off, kMinSig, what);
    std::vector<Signature> v;
    v.reserve(n);
    for (uint16_t i = 0; i < n; ++i) {
        Signature s{};
        bf_get_bytes(data, len, off, s.data(), 64, what);
        v.push_back(s);
    }
    return v;
}

void bf_put_receipts(std::vector<uint8_t>& out,
                     const std::vector<CrossShardReceipt>& v, const char* what) {
    bf_put_count(out, v.size(), what);
    for (auto& r : v) {
        bf_put_u32(out, r.src_shard);
        bf_put_u32(out, r.dst_shard);
        bf_put_u64(out, r.src_block_index);
        bf_put_bytes(out, r.src_block_hash.data(), 32);
        bf_put_bytes(out, r.tx_hash.data(), 32);
        bf_put_lp_str(out, r.from, what);
        bf_put_lp_str(out, r.to, what);
        bf_put_u64(out, r.amount);
        bf_put_u64(out, r.fee);
        bf_put_u64(out, r.nonce);
    }
}
std::vector<CrossShardReceipt> bf_get_receipts(const uint8_t* data, size_t len,
                                               size_t& off, const char* what) {
    uint16_t n = bf_get_count(data, len, off, kMinReceipt, what);
    std::vector<CrossShardReceipt> v;
    v.reserve(n);
    for (uint16_t i = 0; i < n; ++i) {
        CrossShardReceipt r;
        r.src_shard       = bf_get_u32(data, len, off, what);
        r.dst_shard       = bf_get_u32(data, len, off, what);
        r.src_block_index = bf_get_u64(data, len, off, what);
        bf_get_bytes(data, len, off, r.src_block_hash.data(), 32, what);
        bf_get_bytes(data, len, off, r.tx_hash.data(), 32, what);
        r.from  = bf_get_lp_str(data, len, off, what);
        r.to    = bf_get_lp_str(data, len, off, what);
        r.amount = bf_get_u64(data, len, off, what);
        r.fee    = bf_get_u64(data, len, off, what);
        r.nonce  = bf_get_u64(data, len, off, what);
        v.push_back(std::move(r));
    }
    return v;
}

} // namespace

void Block::encode_frame(std::vector<uint8_t>& out) const {
    bf_put_u64(out, index);
    bf_put_bytes(out, prev_hash.data(), 32);
    bf_put_u64(out, static_cast<uint64_t>(timestamp));

    bf_put_count(out, transactions.size(), "transactions");
    for (auto& tx : transactions) {
        std::vector<uint8_t> f;
        tx.encode_frame(f);
        if (f.size() > 0xFFFFFFFFu) bf_throw("transaction frame exceeds u32 length");
        bf_put_u32(out, static_cast<uint32_t>(f.size()));
        out.insert(out.end(), f.begin(), f.end());
    }

    bf_put_count(out, creators.size(), "creators");
    for (auto& c : creators) bf_put_lp_str(out, c, "creators");

    bf_put_hash_lists(out, creator_tx_lists, "creator_tx_lists");
    bf_put_sig_vec(out, creator_ed_sigs, "creator_ed_sigs");
    bf_put_hash_vec(out, creator_dh_inputs, "creator_dh_inputs");

    // to_json emits the six-key view bundle only when some root is non-zero,
    // and DISCARDS the lists otherwise. Mirror that exactly (see block.hpp):
    // carrying the lists here instead would let a relayer append unsigned,
    // unhashed data that the validator then rejects.
    bool any_view_root = false;
    for (auto& h : creator_view_inbound_roots) if (h != Hash{}) { any_view_root = true; break; }
    if (!any_view_root)
        for (auto& h : creator_view_eq_roots) if (h != Hash{}) { any_view_root = true; break; }
    if (!any_view_root)
        for (auto& h : creator_view_abort_roots) if (h != Hash{}) { any_view_root = true; break; }
    static const std::vector<Hash> kNoRoots;
    static const std::vector<std::vector<Hash>> kNoLists;
    bf_put_hash_vec(out, any_view_root ? creator_view_eq_roots      : kNoRoots, "creator_view_eq_roots");
    bf_put_hash_vec(out, any_view_root ? creator_view_abort_roots   : kNoRoots, "creator_view_abort_roots");
    bf_put_hash_vec(out, any_view_root ? creator_view_inbound_roots : kNoRoots, "creator_view_inbound_roots");
    bf_put_hash_lists(out, any_view_root ? creator_view_inbound_lists : kNoLists, "creator_view_inbound_lists");
    bf_put_hash_lists(out, any_view_root ? creator_view_eq_lists     : kNoLists, "creator_view_eq_lists");
    bf_put_hash_lists(out, any_view_root ? creator_view_abort_lists  : kNoLists, "creator_view_abort_lists");

    bool any_shardtip_root = false;
    for (auto& h : creator_view_shardtip_roots) if (h != Hash{}) { any_shardtip_root = true; break; }
    bf_put_hash_vec(out, any_shardtip_root ? creator_view_shardtip_roots : kNoRoots, "creator_view_shardtip_roots");
    bf_put_hash_lists(out, any_shardtip_root ? creator_view_shardtip_lists : kNoLists, "creator_view_shardtip_lists");

    bf_put_count(out, creator_proposer_times.size(), "creator_proposer_times");
    for (uint64_t t : creator_proposer_times) bf_put_u64(out, t);

    bf_put_hash_vec(out, creator_dh_secrets, "creator_dh_secrets");

    bf_put_bytes(out, tx_root.data(), 32);
    bf_put_bytes(out, delay_seed.data(), 32);
    bf_put_bytes(out, delay_output.data(), 32);
    out.push_back(static_cast<uint8_t>(consensus_mode));
    bf_put_lp_str(out, bft_proposer, "bft_proposer");

    bf_put_sig_vec(out, creator_block_sigs, "creator_block_sigs");
    bf_put_bytes(out, cumulative_rand.data(), 32);

    bf_put_count(out, abort_events.size(), "abort_events");
    for (auto& ae : abort_events) {
        out.push_back(ae.round);
        bf_put_lp_str(out, ae.aborting_node, "abort_events.aborting_node");
        bf_put_u64(out, static_cast<uint64_t>(ae.timestamp));
        bf_put_bytes(out, ae.event_hash.data(), 32);
        // The shared claim-list codec is exact-consuming over the whole buffer
        // it is handed, so inside a larger frame it needs an explicit window.
        auto blob = encode_abort_claims(ae.claims);
        if (blob.size() > 0xFFFFFFFFu) bf_throw("abort_events claims blob exceeds u32 length");
        bf_put_u32(out, static_cast<uint32_t>(blob.size()));
        out.insert(out.end(), blob.begin(), blob.end());
    }

    bf_put_count(out, equivocation_events.size(), "equivocation_events");
    for (auto& ev : equivocation_events) {
        bf_put_lp_str(out, ev.equivocator, "equivocation_events.equivocator");
        bf_put_u64(out, ev.block_index);
        out.push_back(ev.kind);
        bf_put_u64(out, ev.index_a);
        bf_put_u64(out, ev.gen_a);
        bf_put_bytes(out, ev.body_root_a.data(), 32);
        bf_put_bytes(out, ev.sig_a.data(), 64);
        bf_put_u64(out, ev.index_b);
        bf_put_u64(out, ev.gen_b);
        bf_put_bytes(out, ev.body_root_b.data(), 32);
        bf_put_bytes(out, ev.sig_b.data(), 64);
        bf_put_u32(out, ev.shard_id);
        bf_put_u64(out, ev.beacon_anchor_height);
    }

    bf_put_receipts(out, cross_shard_receipts, "cross_shard_receipts");
    bf_put_receipts(out, inbound_receipts, "inbound_receipts");

    bf_put_count(out, initial_state.size(), "initial_state");
    for (auto& a : initial_state) {
        bf_put_lp_str(out, a.domain, "initial_state.domain");
        bf_put_bytes(out, a.ed_pub.data(), 32);
        bf_put_u64(out, a.balance);
        bf_put_u64(out, a.stake);
        bf_put_lp_str(out, a.region, "initial_state.region");
    }

    bf_put_bytes(out, state_root.data(), 32);
    bf_put_bytes(out, partner_subset_hash.data(), 32);
    out.push_back(signature_form);
    bf_put_u32(out, eligible_count);
    // to_json emits source_shard_id ONLY under the eligible_count != 0 gate, so
    // a block with eligible_count == 0 loses it across a JSON round trip.
    // Mirror that: write zero, or the two containers would disagree.
    bf_put_u32(out, eligible_count != 0 ? source_shard_id : 0u);

    bf_put_count(out, shard_tip_records.size(), "shard_tip_records");
    for (auto& r : shard_tip_records) {
        auto enc = r.encode();
        if (enc.size() > 255) bf_throw("shard_tip_records record exceeds 255 bytes");
        out.push_back(static_cast<uint8_t>(enc.size()));
        out.insert(out.end(), enc.begin(), enc.end());
    }

    bf_put_count(out, shard_tip_witnesses.size(), "shard_tip_witnesses");
    for (auto& w : shard_tip_witnesses) {
        std::vector<uint8_t> f;
        w.encode_frame(f);
        if (f.size() > 0xFFFFFFFFu) bf_throw("witness frame exceeds u32 length");
        bf_put_u32(out, static_cast<uint32_t>(f.size()));
        out.insert(out.end(), f.begin(), f.end());
    }
}

Block Block::decode_frame(const uint8_t* data, size_t len) {
    return decode_frame(data, len, /*allow_witnesses=*/true);
}

Block Block::decode_frame(const uint8_t* data, size_t len, bool allow_witnesses) {
    Block b;
    size_t off = 0;

    b.index = bf_get_u64(data, len, off, "index");
    bf_get_bytes(data, len, off, b.prev_hash.data(), 32, "prev_hash");
    b.timestamp = static_cast<int64_t>(bf_get_u64(data, len, off, "timestamp"));

    {
        uint16_t n = bf_get_count(data, len, off, kMinTxFrame, "transactions");
        b.transactions.reserve(n);
        for (uint16_t i = 0; i < n; ++i) {
            uint32_t flen = bf_get_u32(data, len, off, "transactions frame length");
            bf_need(off, flen, len, "transactions frame body");
            b.transactions.push_back(Transaction::decode_frame(data + off, flen));
            off += flen;
        }
    }

    {
        uint16_t n = bf_get_count(data, len, off, kMinLpStr, "creators");
        b.creators.reserve(n);
        for (uint16_t i = 0; i < n; ++i)
            b.creators.push_back(bf_get_lp_str(data, len, off, "creators"));
    }

    b.creator_tx_lists   = bf_get_hash_lists(data, len, off, "creator_tx_lists");
    b.creator_ed_sigs    = bf_get_sig_vec(data, len, off, "creator_ed_sigs");
    b.creator_dh_inputs  = bf_get_hash_vec(data, len, off, "creator_dh_inputs");

    b.creator_view_eq_roots      = bf_get_hash_vec(data, len, off, "creator_view_eq_roots");
    b.creator_view_abort_roots   = bf_get_hash_vec(data, len, off, "creator_view_abort_roots");
    b.creator_view_inbound_roots = bf_get_hash_vec(data, len, off, "creator_view_inbound_roots");
    b.creator_view_inbound_lists = bf_get_hash_lists(data, len, off, "creator_view_inbound_lists");
    b.creator_view_eq_lists      = bf_get_hash_lists(data, len, off, "creator_view_eq_lists");
    b.creator_view_abort_lists   = bf_get_hash_lists(data, len, off, "creator_view_abort_lists");

    b.creator_view_shardtip_roots = bf_get_hash_vec(data, len, off, "creator_view_shardtip_roots");
    b.creator_view_shardtip_lists = bf_get_hash_lists(data, len, off, "creator_view_shardtip_lists");

    {
        uint16_t n = bf_get_count(data, len, off, kMinU64, "creator_proposer_times");
        b.creator_proposer_times.reserve(n);
        for (uint16_t i = 0; i < n; ++i)
            b.creator_proposer_times.push_back(bf_get_u64(data, len, off, "creator_proposer_times"));
    }

    b.creator_dh_secrets = bf_get_hash_vec(data, len, off, "creator_dh_secrets");

    bf_get_bytes(data, len, off, b.tx_root.data(), 32, "tx_root");
    bf_get_bytes(data, len, off, b.delay_seed.data(), 32, "delay_seed");
    bf_get_bytes(data, len, off, b.delay_output.data(), 32, "delay_output");
    bf_need(off, 1, len, "consensus_mode");
    b.consensus_mode = static_cast<ConsensusMode>(data[off++]);
    b.bft_proposer = bf_get_lp_str(data, len, off, "bft_proposer");

    b.creator_block_sigs = bf_get_sig_vec(data, len, off, "creator_block_sigs");
    bf_get_bytes(data, len, off, b.cumulative_rand.data(), 32, "cumulative_rand");

    {
        uint16_t n = bf_get_count(data, len, off, kMinAbortEvent, "abort_events");
        b.abort_events.reserve(n);
        for (uint16_t i = 0; i < n; ++i) {
            AbortEvent ae;
            bf_need(off, 1, len, "abort_events.round");
            ae.round = data[off++];
            ae.aborting_node = bf_get_lp_str(data, len, off, "abort_events.aborting_node");
            ae.timestamp = static_cast<int64_t>(bf_get_u64(data, len, off, "abort_events.timestamp"));
            bf_get_bytes(data, len, off, ae.event_hash.data(), 32, "abort_events.event_hash");
            uint32_t clen = bf_get_u32(data, len, off, "abort_events claims length");
            bf_need(off, clen, len, "abort_events claims blob");
            ae.claims = decode_abort_claims(std::vector<uint8_t>(data + off, data + off + clen));
            off += clen;
            b.abort_events.push_back(std::move(ae));
        }
    }

    {
        uint16_t n = bf_get_count(data, len, off, kMinEquivEvent, "equivocation_events");
        b.equivocation_events.reserve(n);
        for (uint16_t i = 0; i < n; ++i) {
            EquivocationEvent ev;
            ev.equivocator = bf_get_lp_str(data, len, off, "equivocation_events.equivocator");
            ev.block_index = bf_get_u64(data, len, off, "equivocation_events.block_index");
            bf_need(off, 1, len, "equivocation_events.kind");
            ev.kind = data[off++];
            // EQV-height-bind: fail-closed on an unknown digest family (the
            // MergeEvent::decode precedent) — the verifier could not derive a
            // digest for it, so the bytes are rejected at the parse boundary.
            if (ev.kind > 1)
                bf_throw("equivocation_events.kind > 1 "
                         "(expected 0=BLOCK_DIGEST or 1=CONTRIB_COMMIT)");
            ev.index_a = bf_get_u64(data, len, off, "equivocation_events.index_a");
            ev.gen_a   = bf_get_u64(data, len, off, "equivocation_events.gen_a");
            bf_get_bytes(data, len, off, ev.body_root_a.data(), 32, "equivocation_events.body_root_a");
            bf_get_bytes(data, len, off, ev.sig_a.data(), 64, "equivocation_events.sig_a");
            ev.index_b = bf_get_u64(data, len, off, "equivocation_events.index_b");
            ev.gen_b   = bf_get_u64(data, len, off, "equivocation_events.gen_b");
            bf_get_bytes(data, len, off, ev.body_root_b.data(), 32, "equivocation_events.body_root_b");
            bf_get_bytes(data, len, off, ev.sig_b.data(), 64, "equivocation_events.sig_b");
            ev.shard_id = bf_get_u32(data, len, off, "equivocation_events.shard_id");
            ev.beacon_anchor_height = bf_get_u64(data, len, off, "equivocation_events.beacon_anchor_height");
            b.equivocation_events.push_back(std::move(ev));
        }
    }

    b.cross_shard_receipts = bf_get_receipts(data, len, off, "cross_shard_receipts");
    b.inbound_receipts     = bf_get_receipts(data, len, off, "inbound_receipts");

    {
        uint16_t n = bf_get_count(data, len, off, kMinAlloc, "initial_state");
        b.initial_state.reserve(n);
        for (uint16_t i = 0; i < n; ++i) {
            GenesisAlloc a;
            a.domain = bf_get_lp_str(data, len, off, "initial_state.domain");
            bf_get_bytes(data, len, off, a.ed_pub.data(), 32, "initial_state.ed_pub");
            a.balance = bf_get_u64(data, len, off, "initial_state.balance");
            a.stake   = bf_get_u64(data, len, off, "initial_state.stake");
            a.region  = bf_get_lp_str(data, len, off, "initial_state.region");
            b.initial_state.push_back(std::move(a));
        }
    }

    bf_get_bytes(data, len, off, b.state_root.data(), 32, "state_root");
    bf_get_bytes(data, len, off, b.partner_subset_hash.data(), 32, "partner_subset_hash");
    bf_need(off, 1, len, "signature_form");
    b.signature_form = data[off++];
    b.eligible_count = bf_get_u32(data, len, off, "eligible_count");
    b.source_shard_id = bf_get_u32(data, len, off, "source_shard_id");

    {
        uint16_t n = bf_get_count(data, len, off, kMinShardTipRecord, "shard_tip_records");
        // A witness is a LEAF: it carries no records. Enforced INLINE (not as a
        // parent-side post-check) so exactly one site produces this string and
        // it fires before the records are parsed.
        if (!allow_witnesses && n != 0)
            bf_throw("shard_tip_witnesses: a witness must carry empty shard_tip_records");
        b.shard_tip_records.reserve(n);
        for (uint16_t i = 0; i < n; ++i) {
            bf_need(off, 1, len, "shard_tip_records length");
            uint8_t rlen = data[off++];
            bf_need(off, rlen, len, "shard_tip_records body");
            auto rec = ShardTipRecord::decode(
                std::vector<uint8_t>(data + off, data + off + rlen));
            // ShardTipRecord::decode returns nullopt rather than throwing, so a
            // malformed record would be SILENTLY DROPPED without this.
            if (!rec) bf_throw("shard_tip_records: malformed record");
            off += rlen;
            b.shard_tip_records.push_back(*rec);
        }
    }

    {
        uint16_t n = bf_get_count(data, len, off, kMinWitness, "shard_tip_witnesses");
        if (!allow_witnesses && n != 0)
            bf_throw("shard_tip_witnesses: a witness must be a leaf block (no nested witnesses)");
        b.shard_tip_witnesses.reserve(n);
        for (uint16_t i = 0; i < n; ++i) {
            uint32_t flen = bf_get_u32(data, len, off, "shard_tip_witnesses frame length");
            bf_need(off, flen, len, "shard_tip_witnesses frame body");
            b.shard_tip_witnesses.push_back(
                decode_frame(data + off, flen, /*allow_witnesses=*/false));
            off += flen;
        }
    }

    if (off != len)
        bf_throw("trailing bytes after last section (" +
                 std::to_string(len - off) + ")");
    return b;
}

} // namespace determ::chain
