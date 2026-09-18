// light/outbox.cpp — durable sender outbox for determ-light. See outbox.hpp.
#include "outbox.hpp"
#include "trustless_read.hpp"
#include "verify_tx_inclusion.hpp"
#include <determ/chain/params.hpp>
#include <determ/crypto/keys.hpp>
#include <determ/crypto/sha256.hpp>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <thread>
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <process.h>
#else
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;
using determ::chain::Transaction;
using determ::chain::TxType;

namespace determ::light::outbox {

// ─── byte helpers (LE, like DLS1 / the tx frame) ─────────────────────────────
namespace {

void put_u8 (std::vector<uint8_t>& o, uint8_t v)  { o.push_back(v); }
void put_u16(std::vector<uint8_t>& o, uint16_t v) { for (int i = 0; i < 2; ++i) o.push_back(uint8_t(v >> (8 * i))); }
void put_u32(std::vector<uint8_t>& o, uint32_t v) { for (int i = 0; i < 4; ++i) o.push_back(uint8_t(v >> (8 * i))); }
void put_u64(std::vector<uint8_t>& o, uint64_t v) { for (int i = 0; i < 8; ++i) o.push_back(uint8_t(v >> (8 * i))); }
void put_bytes(std::vector<uint8_t>& o, const uint8_t* p, size_t n) { o.insert(o.end(), p, p + n); }
void put_lp16(std::vector<uint8_t>& o, const std::string& s, const char* field, size_t max) {
    if (s.size() > max)
        throw std::runtime_error(std::string("outbox record: ") + field + " exceeds "
                                 + std::to_string(max) + " bytes");
    put_u16(o, static_cast<uint16_t>(s.size()));
    put_bytes(o, reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// Fail-closed reader: every read names the field it was reading.
struct Reader {
    const std::vector<uint8_t>& b;
    size_t off{0};
    void need(size_t n, const char* field) const {
        if (off + n > b.size())
            throw std::runtime_error(std::string("outbox record: truncated at '") + field + "'");
    }
    uint8_t  u8 (const char* f) { need(1, f); return b[off++]; }
    uint16_t u16(const char* f) { need(2, f); uint16_t v = 0; for (int i = 0; i < 2; ++i) v |= uint16_t(b[off + i]) << (8 * i); off += 2; return v; }
    uint32_t u32(const char* f) { need(4, f); uint32_t v = 0; for (int i = 0; i < 4; ++i) v |= uint32_t(b[off + i]) << (8 * i); off += 4; return v; }
    uint64_t u64(const char* f) { need(8, f); uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= uint64_t(b[off + i]) << (8 * i); off += 8; return v; }
    template <size_t N> std::array<uint8_t, N> arr(const char* f) {
        need(N, f); std::array<uint8_t, N> a{}; std::memcpy(a.data(), b.data() + off, N); off += N; return a;
    }
    std::string lp16(const char* f, size_t max) {
        uint16_t n = u16(f);
        if (n > max) throw std::runtime_error(std::string("outbox record: '") + f + "' length " + std::to_string(n) + " > " + std::to_string(max));
        need(n, f); std::string s(reinterpret_cast<const char*>(b.data() + off), n); off += n; return s;
    }
    std::vector<uint8_t> bytes(size_t n, const char* f) {
        need(n, f); std::vector<uint8_t> v(b.begin() + off, b.begin() + off + n); off += n; return v;
    }
};

Hash sha_over(const std::vector<uint8_t>& v, size_t from, size_t to) {
    return determ::crypto::sha256(v.data() + from, to - from);
}

std::string trunc_error(std::string s) {
    if (s.size() > MAX_LAST_ERROR) s.resize(MAX_LAST_ERROR);
    return s;
}

uint32_t sat_inc(uint32_t v) { return v == UINT32_MAX ? v : v + 1; }

const char* getenv_c(const char* k) {
    const char* v = std::getenv(k);
    return (v && *v) ? v : nullptr;
}

} // namespace

// ─── names ───────────────────────────────────────────────────────────────────
const char* state_name(State s) {
    switch (s) {
    case State::QUEUED:    return "QUEUED";
    case State::SUBMITTED: return "SUBMITTED";
    case State::UNKNOWN:   return "UNKNOWN";
    case State::INCLUDED:  return "INCLUDED";
    case State::FINALIZED: return "FINALIZED";
    case State::CONSUMED:  return "CONSUMED";
    }
    return "?";
}
const char* apply_name(Apply a) {
    switch (a) {
    case Apply::UNKNOWN:   return "UNKNOWN";
    case Apply::APPLIED:   return "APPLIED";
    case Apply::SKIPPED:   return "SKIPPED";
    case Apply::UNLOCATED: return "UNLOCATED";
    }
    return "?";
}
const char* alt_kind_name(AltKind k) {
    switch (k) {
    case AltKind::ORIGINAL: return "original";
    case AltKind::FEE_BUMP: return "fee-bump";
    case AltKind::REISSUE:  return "reissue";
    }
    return "?";
}
const char* outcome_name(Outcome o) {
    switch (o) {
    case Outcome::NONE:        return "none";
    case Outcome::ACK:         return "ack";
    case Outcome::PENDING:     return "pending";
    case Outcome::STALE:       return "stale-nonce";
    case Outcome::REPLY_LOST:  return "reply-lost";
    case Outcome::REJECTED:    return "rejected";
    case Outcome::TRANSPORT:   return "transport";
    case Outcome::NODE_CONFIG: return "node-config";
    }
    return "?";
}

uint64_t now_unix() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

// ─── identity ────────────────────────────────────────────────────────────────
std::array<uint8_t, 16> derive_msg_id(const Hash& genesis_hash, const std::string& sender,
                                      uint64_t nonce, const Hash& original_tx_hash) {
    determ::crypto::SHA256Builder h;
    h.append(std::string("DTM-OUTBOX-MSG-v1"));
    h.append(genesis_hash);
    h.append(sender);
    h.append(nonce);
    h.append(original_tx_hash);
    Hash full = h.finalize();
    std::array<uint8_t, 16> id{};
    std::memcpy(id.data(), full.data(), 16);
    return id;
}

// ─── record codec ────────────────────────────────────────────────────────────
namespace {
constexpr char kMagic[4]     = {'D', 'O', 'X', '1'};
constexpr char kMetaMagic[4] = {'D', 'O', 'M', '1'};

void encode_immutable(std::vector<uint8_t>& o, const Record& r) {
    put_bytes(o, reinterpret_cast<const uint8_t*>(kMagic), 4);
    put_u32(o, SCHEMA_VERSION);
    put_bytes(o, r.genesis_hash.data(), 32);
    put_lp16(o, r.sender, "sender", 255);
    put_u64(o, r.nonce);
    put_u8 (o, r.tx_type);
    put_u64(o, r.created);
    put_lp16(o, r.idempotency_key, "idempotency_key", MAX_IDEMPOTENCY_KEY);
    if (r.alternates.empty() || r.alternates.size() > MAX_ALTERNATES)
        throw std::runtime_error("outbox record: alternates count must be 1.."
                                 + std::to_string(MAX_ALTERNATES));
    put_u8(o, static_cast<uint8_t>(r.alternates.size()));
    for (auto& a : r.alternates) {
        put_u8(o, static_cast<uint8_t>(a.kind));
        put_bytes(o, a.msg_id.data(), 16);
        put_u64(o, a.fee);
        put_bytes(o, a.tx_hash.data(), 32);
        if (a.frame.size() > 0xFFFFFFu) throw std::runtime_error("outbox record: frame too large");
        put_u32(o, static_cast<uint32_t>(a.frame.size()));
        put_bytes(o, a.frame.data(), a.frame.size());
    }
}

void encode_status(std::vector<uint8_t>& o, const Record& r) {
    put_u8 (o, static_cast<uint8_t>(r.state));
    put_u8 (o, static_cast<uint8_t>(r.apply));
    put_u32(o, r.attempts);
    put_u32(o, r.consecutive_failures);
    put_u64(o, r.last_attempt);
    put_u64(o, r.next_retry);
    put_u64(o, r.first_ack);
    put_u64(o, r.first_ack_height);
    put_u8 (o, static_cast<uint8_t>(r.last_outcome));
    put_lp16(o, trunc_error(r.last_error), "last_error", MAX_LAST_ERROR);
    put_u64(o, r.included_height);
    put_bytes(o, r.included_block_hash.data(), 32);
    put_u8 (o, r.included_alt);
    put_u64(o, r.finalized_height);
    put_u32(o, r.skipped_count);
    put_u32(o, r.orphaned_count);
    put_u64(o, r.updated);
}

// Parses the immutable section, verifies its hash, and validates every
// alternate frame against itself (hash recompute) and the slot (nonce, sender).
Record parse_immutable(Reader& rd) {
    Record r;
    auto magic = rd.arr<4>("magic");
    if (std::memcmp(magic.data(), kMagic, 4) != 0)
        throw std::runtime_error("outbox record: bad magic (expected DOX1)");
    uint32_t schema = rd.u32("schema_version");
    if (schema != SCHEMA_VERSION)
        throw std::runtime_error("outbox record: unsupported schema_version " + std::to_string(schema));
    r.genesis_hash    = rd.arr<32>("genesis_hash");
    r.sender          = rd.lp16("sender", 255);
    r.nonce           = rd.u64("nonce");
    r.tx_type         = rd.u8("tx_type");
    r.created         = rd.u64("created");
    r.idempotency_key = rd.lp16("idempotency_key", MAX_IDEMPOTENCY_KEY);
    uint8_t n = rd.u8("alt_count");
    if (n == 0 || n > MAX_ALTERNATES)
        throw std::runtime_error("outbox record: alt_count " + std::to_string(n) + " outside 1.."
                                 + std::to_string(MAX_ALTERNATES));
    for (uint8_t i = 0; i < n; ++i) {
        Alternate a;
        uint8_t kind = rd.u8("alt.kind");
        if (kind > 2) throw std::runtime_error("outbox record: alt.kind " + std::to_string(kind) + " unknown");
        a.kind    = static_cast<AltKind>(kind);
        a.msg_id  = rd.arr<16>("alt.msg_id");
        a.fee     = rd.u64("alt.fee");
        a.tx_hash = rd.arr<32>("alt.tx_hash");
        uint32_t flen = rd.u32("alt.frame_len");
        if (flen < 131 || flen > 70000)
            throw std::runtime_error("outbox record: alt.frame_len " + std::to_string(flen) + " implausible");
        a.frame = rd.bytes(flen, "alt.frame");
        Transaction tx;
        try { tx = Transaction::decode_frame(a.frame.data(), a.frame.size()); }
        catch (const std::exception& e) {
            throw std::runtime_error(std::string("outbox record: alt.frame does not decode: ") + e.what());
        }
        if (tx.compute_hash() != a.tx_hash || tx.hash != a.tx_hash)
            throw std::runtime_error("outbox record: alt.tx_hash != recomputed hash of the frame");
        if (tx.nonce != r.nonce || tx.from != r.sender)
            throw std::runtime_error("outbox record: alt.frame nonce/sender != slot nonce/sender");
        if (tx.fee != a.fee)
            throw std::runtime_error("outbox record: alt.fee != frame fee");
        if (static_cast<uint8_t>(tx.type) != r.tx_type)
            throw std::runtime_error("outbox record: alt.frame type != slot tx_type");
        if (i == 0 && a.kind != AltKind::ORIGINAL)
            throw std::runtime_error("outbox record: alternates[0] must be the original");
        if (a.kind == AltKind::FEE_BUMP && (i == 0 || a.msg_id != r.alternates[i - 1].msg_id))
            throw std::runtime_error("outbox record: a fee bump must carry the previous alternate's msg_id");
        if (a.kind != AltKind::FEE_BUMP && a.msg_id != derive_msg_id(r.genesis_hash, r.sender, r.nonce, a.tx_hash))
            throw std::runtime_error("outbox record: alt.msg_id != derived msg_id");
        r.alternates.push_back(std::move(a));
    }
    return r;
}

void parse_status(Reader& rd, Record& r) {
    uint8_t st = rd.u8("state");
    if (st > 5) throw std::runtime_error("status section: state " + std::to_string(st) + " unknown");
    r.state = static_cast<State>(st);
    uint8_t ap = rd.u8("apply");
    if (ap > 3) throw std::runtime_error("status section: apply " + std::to_string(ap) + " unknown");
    r.apply                = static_cast<Apply>(ap);
    r.attempts             = rd.u32("attempts");
    r.consecutive_failures = rd.u32("consecutive_failures");
    r.last_attempt         = rd.u64("last_attempt");
    r.next_retry           = rd.u64("next_retry");
    r.first_ack            = rd.u64("first_ack");
    r.first_ack_height     = rd.u64("first_ack_height");
    uint8_t oc = rd.u8("last_outcome");
    if (oc > 7) throw std::runtime_error("status section: last_outcome " + std::to_string(oc) + " unknown");
    r.last_outcome         = static_cast<Outcome>(oc);
    r.last_error           = rd.lp16("last_error", MAX_LAST_ERROR);
    r.included_height      = rd.u64("included_height");
    r.included_block_hash  = rd.arr<32>("included_block_hash");
    r.included_alt         = rd.u8("included_alt");
    if (r.included_alt >= r.alternates.size())
        throw std::runtime_error("status section: included_alt out of range");
    r.finalized_height     = rd.u64("finalized_height");
    r.skipped_count        = rd.u32("skipped_count");
    r.orphaned_count       = rd.u32("orphaned_count");
    r.updated              = rd.u64("updated");
}
} // namespace

std::vector<uint8_t> encode_record(const Record& r) {
    std::vector<uint8_t> o;
    encode_immutable(o, r);
    Hash ih = sha_over(o, 0, o.size());
    put_bytes(o, ih.data(), 32);
    size_t status_start = o.size();
    encode_status(o, r);
    determ::crypto::SHA256Builder h;
    h.append(ih);
    h.append(o.data() + status_start, o.size() - status_start);
    Hash sh = h.finalize();
    put_bytes(o, sh.data(), 32);
    return o;
}

Record decode_record_immutable(const std::vector<uint8_t>& bytes) {
    Reader rd{bytes};
    Record r = parse_immutable(rd);
    Hash stored = rd.arr<32>("immutable_hash");
    Hash actual = sha_over(bytes, 0, rd.off - 32);
    if (stored != actual) throw std::runtime_error("outbox record: immutable section hash mismatch");
    return r;
}

Record decode_record(const std::vector<uint8_t>& bytes) {
    Reader rd{bytes};
    Record r = parse_immutable(rd);
    Hash stored = rd.arr<32>("immutable_hash");
    Hash ih = sha_over(bytes, 0, rd.off - 32);
    if (stored != ih) throw std::runtime_error("outbox record: immutable section hash mismatch");
    size_t status_start = rd.off;
    try {
        parse_status(rd, r);
    } catch (const std::exception& e) {
        std::string w = e.what();
        if (w.rfind("status section:", 0) == 0) throw;
        throw std::runtime_error("status section: " + w);
    }
    Hash sstored = rd.arr<32>("status_hash");
    determ::crypto::SHA256Builder h;
    h.append(ih);
    h.append(bytes.data() + status_start, rd.off - 32 - status_start);
    if (sstored != h.finalize()) throw std::runtime_error("status section: hash mismatch");
    if (rd.off != bytes.size())
        throw std::runtime_error("status section: trailing bytes after the record");
    return r;
}

// ─── meta codec ("DOM1") ────────────────────────────────────────────────────
std::vector<uint8_t> encode_meta(const Meta& m) {
    std::vector<uint8_t> o;
    put_bytes(o, reinterpret_cast<const uint8_t*>(kMetaMagic), 4);
    put_u32(o, SCHEMA_VERSION);
    put_bytes(o, m.genesis_hash.data(), 32);
    put_lp16(o, m.sender, "sender", 255);
    put_u64(o, m.nonce_floor);
    Hash h = sha_over(o, 0, o.size());
    put_bytes(o, h.data(), 32);
    return o;
}

Meta decode_meta(const std::vector<uint8_t>& bytes) {
    Reader rd{bytes};
    auto magic = rd.arr<4>("magic");
    if (std::memcmp(magic.data(), kMetaMagic, 4) != 0)
        throw std::runtime_error("outbox meta: bad magic (expected DOM1)");
    uint32_t schema = rd.u32("schema_version");
    if (schema != SCHEMA_VERSION)
        throw std::runtime_error("outbox meta: unsupported schema_version " + std::to_string(schema));
    Meta m;
    m.genesis_hash = rd.arr<32>("genesis_hash");
    m.sender       = rd.lp16("sender", 255);
    m.nonce_floor  = rd.u64("nonce_floor");
    Hash stored    = rd.arr<32>("hash");
    if (stored != sha_over(bytes, 0, rd.off - 32))
        throw std::runtime_error("outbox meta: hash mismatch");
    if (rd.off != bytes.size()) throw std::runtime_error("outbox meta: trailing bytes");
    return m;
}

// ─── durable writes ─────────────────────────────────────────────────────────
namespace {

void crash_point(const char* name) {
    const char* want = getenv_c("DETERM_LIGHT_OUTBOX_CRASH_POINT");
    if (want && std::strcmp(want, name) == 0) {
        std::fflush(stdout);
        std::fflush(stderr);
        std::_Exit(97);
    }
}

std::string pid_string() {
#ifdef _WIN32
    return std::to_string(static_cast<unsigned long>(GetCurrentProcessId()));
#else
    return std::to_string(static_cast<unsigned long>(getpid()));
#endif
}

#ifdef _WIN32
std::wstring wide(const std::string& s) { return fs::path(s).wstring(); }
#endif

std::vector<uint8_t> read_file(const std::string& path) {
#ifdef _WIN32
    // FILE_SHARE_DELETE: a lock-free `status` must never make a concurrent
    // MoveFileExW(REPLACE_EXISTING) in a mutating verb fail with a sharing
    // violation.
    HANDLE h = CreateFileW(wide(path).c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) throw std::runtime_error("cannot open " + path);
    std::vector<uint8_t> out;
    for (;;) {
        uint8_t buf[65536]; DWORD n = 0;
        if (!ReadFile(h, buf, sizeof buf, &n, nullptr)) { CloseHandle(h); throw std::runtime_error("read failed " + path); }
        if (n == 0) break;
        out.insert(out.end(), buf, buf + n);
    }
    CloseHandle(h);
    return out;
#else
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot open " + path);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
#endif
}

#ifndef _WIN32
// Flush to stable storage. On Darwin fsync(2) does not push the drive cache;
// F_FULLFSYNC does (falls back to fsync where the filesystem refuses it).
int full_fsync(int fd) {
#ifdef __APPLE__
    if (::fcntl(fd, F_FULLFSYNC) == 0) return 0;
#endif
    return ::fsync(fd);
}
#endif

void durable_write_impl(const std::string& path, const std::vector<uint8_t>& bytes, bool create_new) {
    const std::string tmp = path + "." + pid_string() + ".tmp";
    crash_point("before_write");
    if (const char* inj = getenv_c("DETERM_LIGHT_OUTBOX_INJECT"); inj && std::strcmp(inj, "write_fail") == 0)
        throw std::runtime_error("write failed (injected ENOSPC): " + tmp);
#ifdef _WIN32
    HANDLE h = CreateFileW(wide(tmp).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        throw std::runtime_error("cannot create " + tmp + " (error " + std::to_string(GetLastError()) + ")");
    auto fail = [&](const std::string& what) {
        DWORD err = GetLastError();
        CloseHandle(h);
        DeleteFileW(wide(tmp).c_str());
        throw std::runtime_error(what + " " + tmp + " (error " + std::to_string(err) + ")");
    };
    size_t done = 0;
    while (done < bytes.size()) {
        DWORD n = 0;
        DWORD chunk = static_cast<DWORD>(std::min<size_t>(bytes.size() - done, 1u << 20));
        if (!WriteFile(h, bytes.data() + done, chunk, &n, nullptr) || n == 0) fail("write failed for");
        done += n;
    }
    trace_event("write");
    crash_point("after_write");
    if (!FlushFileBuffers(h)) fail("flush failed for");
    CloseHandle(h);
    trace_event("fsync_file");
    crash_point("after_fsync");
    DWORD flags = MOVEFILE_WRITE_THROUGH | (create_new ? 0 : MOVEFILE_REPLACE_EXISTING);
    if (!MoveFileExW(wide(tmp).c_str(), wide(path).c_str(), flags)) {
        DWORD err = GetLastError();
        DeleteFileW(wide(tmp).c_str());
        if (create_new && err == ERROR_ALREADY_EXISTS)
            throw std::runtime_error("refusing to overwrite an existing record: " + path);
        throw std::runtime_error("publish failed for " + path + " (error " + std::to_string(err) + ")");
    }
    trace_event("publish");
    // The file's own bytes were flushed (FlushFileBuffers) before the publish;
    // NTFS journals the rename itself. Windows offers no directory flush, and
    // MOVEFILE_WRITE_THROUGH's documented flush applies to the copy-and-delete
    // (cross-volume) case only — the same-volume rename is a journaled metadata
    // operation, which is the guarantee stated in DurableOutboxSoundness.md.
    crash_point("after_publish");
#else
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) throw std::runtime_error("cannot create " + tmp + ": " + std::strerror(errno));
    auto fail = [&](const std::string& what) {
        int err = errno;
        ::close(fd);
        ::unlink(tmp.c_str());
        throw std::runtime_error(what + " " + tmp + ": " + std::strerror(err));
    };
    size_t done = 0;
    while (done < bytes.size()) {
        ssize_t n = ::write(fd, bytes.data() + done, bytes.size() - done);
        if (n < 0) { if (errno == EINTR) continue; fail("write failed for"); }
        if (n == 0) { errno = EIO; fail("short write for"); }
        done += static_cast<size_t>(n);
    }
    trace_event("write");
    crash_point("after_write");
    // An fsync error is terminal for this write: the kernel may have dropped
    // the dirty pages, so the temp file is discarded, never published.
    if (full_fsync(fd) != 0) fail("fsync failed for");
    if (::close(fd) != 0) { int err = errno; ::unlink(tmp.c_str()); throw std::runtime_error("close failed for " + tmp + ": " + std::strerror(err)); }
    trace_event("fsync_file");
    crash_point("after_fsync");
    if (create_new) {
        if (::link(tmp.c_str(), path.c_str()) == 0) {
            ::unlink(tmp.c_str());
        } else {
            int err = errno;
            if (err == EEXIST) { ::unlink(tmp.c_str()); throw std::runtime_error("refusing to overwrite an existing record: " + path); }
            // Filesystems without hard links (exFAT/FAT, some FUSE mounts): the
            // directory lock already excludes a second writer, so an existence
            // check followed by rename keeps the create-new contract there.
            if (::access(path.c_str(), F_OK) == 0) { ::unlink(tmp.c_str()); throw std::runtime_error("refusing to overwrite an existing record: " + path); }
            if (::rename(tmp.c_str(), path.c_str()) != 0) {
                int e2 = errno;
                ::unlink(tmp.c_str());
                throw std::runtime_error("publish failed for " + path + ": link: " + std::strerror(err) + "; rename: " + std::strerror(e2));
            }
        }
    } else {
        if (::rename(tmp.c_str(), path.c_str()) != 0) {
            int err = errno;
            ::unlink(tmp.c_str());
            throw std::runtime_error("publish (rename) failed for " + path + ": " + std::strerror(err));
        }
    }
    trace_event("publish");
    std::string dir = fs::path(path).parent_path().string();
    if (dir.empty()) dir = ".";
    int dfd = ::open(dir.c_str(), O_RDONLY | O_CLOEXEC);
    if (dfd < 0) throw std::runtime_error("cannot open directory " + dir + " for fsync: " + std::strerror(errno));
    if (full_fsync(dfd) != 0) {
        int err = errno;
        ::close(dfd);
        throw std::runtime_error("directory fsync failed for " + dir + ": " + std::strerror(err));
    }
    ::close(dfd);
    trace_event("fsync_dir");
    crash_point("after_publish");
#endif
}
} // namespace

void trace_event(const char* what) {
    const char* p = getenv_c("DETERM_LIGHT_OUTBOX_TRACE");
    if (!p) return;
    std::ofstream f(p, std::ios::app);
    f << what << "\n";
}

void durable_write_new(const std::string& path, const std::vector<uint8_t>& bytes) {
    durable_write_impl(path, bytes, /*create_new=*/true);
}
void durable_write_replace(const std::string& path, const std::vector<uint8_t>& bytes) {
    durable_write_impl(path, bytes, /*create_new=*/false);
}

// ─── lock ───────────────────────────────────────────────────────────────────
Lock::Lock(const std::string& dir) {
    fs::create_directories(dir);
    const std::string p = (fs::path(dir) / "outbox.lock").string();
#ifdef _WIN32
    HANDLE h = CreateFileW(wide(p).c_str(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        throw std::runtime_error("cannot open lock file " + p);
    OVERLAPPED ov{};
    if (!LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov)) {
        CloseHandle(h);
        throw std::runtime_error("outbox is locked by another process (" + p + ")");
    }
    handle_ = h;
#else
    int fd = ::open(p.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) throw std::runtime_error("cannot open lock file " + p + ": " + std::strerror(errno));
    struct flock fl{};
    fl.l_type = F_WRLCK; fl.l_whence = SEEK_SET; fl.l_start = 0; fl.l_len = 0;
    if (::fcntl(fd, F_SETLK, &fl) != 0) {
        ::close(fd);
        throw std::runtime_error("outbox is locked by another process (" + p + ")");
    }
    fd_ = fd;
#endif
    // Test seam (documented in outbox.hpp): hold the lock for N seconds so the
    // exclusion leg of tools/test_light_outbox.sh runs on every platform
    // through the binary's own lock path (fcntl and LockFileEx alike).
    if (const char* hold = getenv_c("DETERM_LIGHT_OUTBOX_HOLD_LOCK_S")) {
        unsigned long secs = std::strtoul(hold, nullptr, 10);
        if (secs > 0 && secs <= 60) std::this_thread::sleep_for(std::chrono::seconds(secs));
    }
}
Lock::~Lock() {
#ifdef _WIN32
    if (handle_) {
        OVERLAPPED ov{};
        UnlockFileEx(static_cast<HANDLE>(handle_), 0, 1, 0, &ov);
        CloseHandle(static_cast<HANDLE>(handle_));
    }
#else
    if (fd_ >= 0) ::close(fd_);   // closing releases the fcntl lock
#endif
}

// ─── the on-disk outbox ─────────────────────────────────────────────────────
namespace {
std::string nonce_name(uint64_t nonce) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%020llu", static_cast<unsigned long long>(nonce));
    return buf;
}
bool parse_slot_name(const std::string& name, uint64_t& nonce, bool& quarantined) {
    // "<20 digits>.msg" or "<20 digits>.msg.corrupt-<digits>"
    if (name.size() < 24 || name.compare(20, 4, ".msg") != 0) return false;
    for (size_t i = 0; i < 20; ++i) if (name[i] < '0' || name[i] > '9') return false;
    if (name.size() == 24) { quarantined = false; }
    else if (name.compare(24, 9, ".corrupt-") == 0 && name.size() > 33) { quarantined = true; }
    else return false;
    nonce = std::strtoull(name.substr(0, 20).c_str(), nullptr, 10);
    return true;
}
} // namespace

Outbox::Outbox(std::string dir) : dir_(std::move(dir)) {}

std::string Outbox::slot_path(uint64_t nonce) const {
    return (fs::path(dir_) / (nonce_name(nonce) + ".msg")).string();
}

void Outbox::load() {
    slots_.clear(); quarantined_.clear(); has_meta_ = false;
    meta_corrupt_ = false; meta_corrupt_detail_.clear();
    if (!fs::exists(dir_)) return;
    const std::string meta_path = (fs::path(dir_) / "outbox.meta").string();
    if (fs::exists(meta_path)) {
        try {
            meta_ = decode_meta(read_file(meta_path));
            has_meta_ = true;
        } catch (const std::exception& ex) {
            meta_corrupt_ = true; meta_corrupt_detail_ = ex.what();   // reported by status; rebuilt by recover
        }
    }
    for (auto& e : fs::directory_iterator(dir_)) {
        if (!e.is_regular_file()) continue;
        const std::string name = e.path().filename().string();
        uint64_t nonce = 0; bool q = false;
        if (!parse_slot_name(name, nonce, q)) continue;   // .tmp, lock, meta, others: ignored
        if (q) { quarantined_.push_back(nonce); continue; }
        Slot s;
        s.path = e.path().string();
        std::vector<uint8_t> bytes;
        try {
            bytes = read_file(s.path);
            s.rec = decode_record(bytes);
        } catch (const std::exception& ex) {
            std::string w = ex.what();
            s.corrupt_detail = w;
            if (w.rfind("status section:", 0) == 0) {
                try {
                    s.rec = decode_record_immutable(bytes);
                    s.rec.state = State::UNKNOWN;   // bytes may have been released
                    s.status_corrupt = true;
                } catch (const std::exception&) {
                    s.corrupt = true;
                }
            } else {
                s.corrupt = true;
            }
            if (s.corrupt) s.rec.nonce = nonce;   // a decoded immutable section keeps its own nonce for the check below
        }
        if (!s.corrupt && s.rec.nonce != nonce) {
            s.corrupt = true;
            s.corrupt_detail = "file name nonce != record nonce";
            s.rec.nonce = nonce;
        }
        if (!s.corrupt && has_meta_
            && (s.rec.sender != meta_.sender || s.rec.genesis_hash != meta_.genesis_hash)) {
            s.corrupt = true;
            s.corrupt_detail = "record sender/genesis != outbox meta pin";
        }
        slots_.emplace(nonce, std::move(s));
    }
    std::sort(quarantined_.begin(), quarantined_.end());
}

uint64_t Outbox::highest_reserved_nonce_plus_one() const {
    uint64_t hi = has_meta_ ? meta_.nonce_floor : 0;
    if (!slots_.empty()) hi = std::max(hi, slots_.rbegin()->first + 1);
    if (!quarantined_.empty()) hi = std::max(hi, quarantined_.back() + 1);
    return hi;
}
bool Outbox::nonce_reserved(uint64_t nonce) const {
    return slots_.count(nonce) > 0
        || std::binary_search(quarantined_.begin(), quarantined_.end(), nonce);
}
bool Outbox::nonce_quarantined(uint64_t nonce) const {
    return slots_.count(nonce) == 0
        && std::binary_search(quarantined_.begin(), quarantined_.end(), nonce);
}
void Outbox::write_meta_new(const Meta& m) {
    fs::create_directories(dir_);
    durable_write_new((fs::path(dir_) / "outbox.meta").string(), encode_meta(m));
    meta_ = m; has_meta_ = true; meta_corrupt_ = false;
}
void Outbox::write_meta_replace(const Meta& m) {
    durable_write_replace((fs::path(dir_) / "outbox.meta").string(), encode_meta(m));
    meta_ = m; has_meta_ = true; meta_corrupt_ = false;
}
void Outbox::write_slot_new(const Record& r) {
    if (slots_.count(r.nonce))
        throw std::runtime_error("nonce " + std::to_string(r.nonce) + " is already reserved in this outbox");
    durable_write_new(slot_path(r.nonce), encode_record(r));
    Slot s; s.path = slot_path(r.nonce); s.rec = r;
    slots_[r.nonce] = std::move(s);
}
void Outbox::write_slot_replace(Record& r, uint64_t now) {
    r.updated = now;
    durable_write_replace(slot_path(r.nonce), encode_record(r));
    auto it = slots_.find(r.nonce);
    if (it != slots_.end()) { it->second.rec = r; it->second.status_corrupt = false; it->second.corrupt_detail.clear(); }
}
void Outbox::quarantine_slot(uint64_t nonce, uint64_t now) {
    const std::string from = slot_path(nonce);
    const std::string to   = from + ".corrupt-" + std::to_string(now);
    fs::rename(from, to);
    slots_.erase(nonce);
    quarantined_.push_back(nonce);
    std::sort(quarantined_.begin(), quarantined_.end());
}
void Outbox::remove_slot_file(uint64_t nonce) {
    fs::remove(slot_path(nonce));
    slots_.erase(nonce);
}
size_t Outbox::remove_quarantined_below(uint64_t floor) {
    // Below the floor every nonce is proven consumed (the floor moves only over
    // pruned FINALIZED/APPLIED or CONSUMED slots, and nonces are sequential), so
    // a quarantined file there reserves nothing any more.
    size_t removed = 0;
    if (!fs::exists(dir_)) return 0;
    for (auto& e : fs::directory_iterator(dir_)) {
        if (!e.is_regular_file()) continue;
        uint64_t nonce = 0; bool q = false;
        if (!parse_slot_name(e.path().filename().string(), nonce, q) || !q || nonce >= floor) continue;
        fs::remove(e.path());
        ++removed;
    }
    quarantined_.erase(std::remove_if(quarantined_.begin(), quarantined_.end(),
                                      [&](uint64_t n) { return n < floor; }), quarantined_.end());
    return removed;
}
void Outbox::remove_stale_tmp_files() {
    if (!fs::exists(dir_)) return;
    for (auto& e : fs::directory_iterator(dir_)) {
        if (!e.is_regular_file()) continue;
        const std::string name = e.path().filename().string();
        if (name.size() > 4 && name.compare(name.size() - 4, 4, ".tmp") == 0) fs::remove(e.path());
    }
}

// ─── message construction ───────────────────────────────────────────────────
Transaction build_transfer(const LightKeyfile& kf, const TransferSpec& spec, uint64_t nonce) {
    if (spec.to.empty()) throw std::runtime_error("TRANSFER requires --to");
    if (kf.anon_address == determ::chain::ZEROTH_ADDRESS)
        throw std::runtime_error("the Zeroth pool address cannot send (validator.cpp E1 guard)");
    if (is_anon_address(spec.to) && spec.to != normalize_anon_address(spec.to))
        throw std::runtime_error("--to is anon-shape but not canonical lowercase (S-028); use "
                                 + normalize_anon_address(spec.to));
    if (spec.payload.size() > determ::chain::TRANSFER_PAYLOAD_MAX)
        throw std::runtime_error("payload exceeds TRANSFER_PAYLOAD_MAX ("
                                 + std::to_string(determ::chain::TRANSFER_PAYLOAD_MAX) + " bytes)");
    if (spec.amount > UINT64_MAX - spec.fee)
        throw std::runtime_error("amount + fee overflows u64 (the verifier's S-049 guard)");
    Transaction tx;
    tx.type = TxType::TRANSFER;
    tx.from = kf.anon_address;
    tx.to = spec.to;
    tx.amount = spec.amount;
    tx.fee = spec.fee;
    tx.nonce = nonce;
    tx.payload = spec.payload;
    auto sb = tx.signing_bytes();
    tx.sig = determ::crypto::sign(kf.key, sb.data(), sb.size());
    tx.hash = tx.compute_hash();
    // Round-trip through the canonical frame: what is stored is exactly what
    // will be submitted, and it must decode to the same hash.
    std::vector<uint8_t> frame;
    tx.encode_frame(frame);
    Transaction back = Transaction::decode_frame(frame.data(), frame.size());
    if (back.compute_hash() != tx.hash) throw std::runtime_error("tx frame round-trip mismatch");
    return tx;
}

// ─── submit ─────────────────────────────────────────────────────────────────
Outcome classify_submit_error(const std::string& err) {
    auto has = [&](const char* s) { return err.find(s) != std::string::npos; };
    if (has("incumbent tx at (from, nonce) has equal-or-higher fee")) return Outcome::PENDING;
    if (has("stale nonce"))                                          return Outcome::STALE;
    if (has("auth_required") || has("auth_failed") || has("Unknown method")) return Outcome::NODE_CONFIG;
    if (has("send failed for") || has("no response for") || has("malformed response for")
        || has("timed out"))                                         return Outcome::REPLY_LOST;
    if (has("socket not open"))                                      return Outcome::TRANSPORT;
    return Outcome::REJECTED;   // retryable: the node's rejection strings are state-dependent
}

uint64_t backoff_seconds(uint32_t consecutive_failures) {
    uint32_t n = std::min<uint32_t>(consecutive_failures, 20);
    uint64_t d = BACKOFF_BASE_S << n;
    return std::min<uint64_t>(d, BACKOFF_CAP_S);
}

SubmitReport submit_due(Outbox& ob, RpcClient& rpc, const SubmitOptions& opt, uint64_t now,
                        std::function<void(const std::string&)> log) {
    SubmitReport rep;
    auto note = [&](const std::string& s) { rep.lines.push_back(s); if (log) log(s); };
    const bool inject_drop = [] {
        const char* v = getenv_c("DETERM_LIGHT_OUTBOX_INJECT");
        return v && std::strcmp(v, "drop_response") == 0;
    }();
    for (auto& [nonce, slot] : ob.slots()) {
        if (slot.corrupt || slot.status_corrupt) {
            note("slot " + std::to_string(nonce) + ": CORRUPT — not sent (" + slot.corrupt_detail + ")");
            continue;
        }
        Record& r = slot.rec;
        if (!r.sendable()) continue;
        if (!opt.force_now && r.next_retry > now) { rep.skipped_not_due++; continue; }
        const Alternate& a = r.active();
        json txj = Transaction::decode_frame(a.frame.data(), a.frame.size()).to_json();
        r.attempts = sat_inc(r.attempts);
        r.last_attempt = now;
        rep.sent++;
        bool stop = false;
        try {
            json reply = rpc.call("submit_tx", {{"tx", txj}});
            if (inject_drop) throw std::runtime_error("no response for submit_tx (injected reply loss)");
            // The reply must name OUR hash: after a desynchronised stream a
            // reply for another request must never be taken as this slot's ack.
            if (reply.is_object() && reply.value("status", std::string{}) == "queued"
                && reply.value("hash", std::string{}) == to_hex(a.tx_hash)) {
                r.state = State::SUBMITTED;
                r.consecutive_failures = 0;
                r.next_retry = now + RESEND_CADENCE_S;
                r.last_outcome = Outcome::ACK;
                r.last_error.clear();
                if (r.first_ack == 0) { r.first_ack = now; r.first_ack_height = opt.head_hint; }
                rep.acked++;
                note("slot " + std::to_string(nonce) + ": SUBMITTED (queued) tx=" + to_hex(a.tx_hash));
            } else {
                r.consecutive_failures = sat_inc(r.consecutive_failures);
                r.next_retry = now + backoff_seconds(r.consecutive_failures);
                r.last_outcome = Outcome::REJECTED;
                r.last_error = trunc_error("unexpected submit_tx reply: " + reply.dump());
                rep.rejected++;
                note("slot " + std::to_string(nonce) + ": unexpected reply (stream out of sync?) — retry in "
                     + std::to_string(r.next_retry - now) + "s");
                stop = true;   // a reply not naming this slot's hash: the stream may be out of sync
            }
        } catch (const std::exception& e) {
            const std::string err = e.what();
            Outcome o = classify_submit_error(err);
            r.last_outcome = o;
            switch (o) {
            case Outcome::PENDING:
                r.state = State::SUBMITTED;
                r.consecutive_failures = 0;
                r.next_retry = now + RESEND_CADENCE_S;
                r.last_error.clear();
                if (r.first_ack == 0) { r.first_ack = now; r.first_ack_height = opt.head_hint; }
                rep.pending++;
                note("slot " + std::to_string(nonce) + ": SUBMITTED (already pending at the daemon)");
                break;
            case Outcome::STALE:
                r.next_retry = now + RESEND_CADENCE_S;
                r.last_error = trunc_error(err);
                rep.stale++;
                note("slot " + std::to_string(nonce) + ": daemon reports a stale nonce — run `outbox reconcile`");
                break;
            case Outcome::REPLY_LOST:
                // The stream is no longer in sync (a late reply would be read
                // as the next slot's); this run ends here, the next one reconnects.
                r.state = State::UNKNOWN;
                r.consecutive_failures = sat_inc(r.consecutive_failures);
                r.next_retry = now + backoff_seconds(r.consecutive_failures);
                r.last_error = trunc_error(err);
                rep.lost++;
                note("slot " + std::to_string(nonce) + ": UNKNOWN (reply lost) — will re-send the same bytes on the next run");
                stop = true;
                break;
            case Outcome::NODE_CONFIG:
                r.last_error = trunc_error(err);
                rep.node_config_error = true;
                note("slot " + std::to_string(nonce) + ": daemon configuration error: " + err);
                stop = true;
                break;
            case Outcome::TRANSPORT:
                r.attempts = r.attempts ? r.attempts - 1 : 0;   // nothing was sent
                r.last_error = trunc_error(err);
                rep.transport_error = true;
                note("slot " + std::to_string(nonce) + ": transport error: " + err);
                stop = true;
                break;
            default:
                r.consecutive_failures = sat_inc(r.consecutive_failures);
                r.next_retry = now + backoff_seconds(r.consecutive_failures);
                r.last_error = trunc_error(err);
                rep.rejected++;
                note("slot " + std::to_string(nonce) + ": rejected (retryable) — retry in "
                     + std::to_string(r.next_retry - now) + "s: " + err);
                break;
            }
        }
        ob.write_slot_replace(r, now);
        if (stop) break;
    }
    return rep;
}

// ─── genesis pin ─────────────────────────────────────────────────────────────
void pin_daemon_genesis(RpcClient& rpc, const determ::chain::GenesisConfig& genesis,
                        const Hash& expected) {
    Hash local = determ::chain::compute_genesis_hash(genesis);
    if (local != expected)
        throw std::runtime_error("genesis mismatch: --genesis hashes to " + to_hex(local)
                                 + " but this outbox is pinned to " + to_hex(expected));
    json b0 = rpc.call("block", {{"index", 0}});
    if (!b0.is_object())
        throw std::runtime_error("genesis mismatch: daemon returned no block 0");
    Hash served = determ::chain::Block::from_json(b0).compute_hash();
    if (served != local)
        throw std::runtime_error("genesis mismatch: daemon's block 0 recomputes to " + to_hex(served)
                                 + ", this outbox is pinned to " + to_hex(local)
                                 + " — refusing to submit to a daemon on another chain");
}

// ─── the enqueue nonce hint (a head-anchored trust-minimized read) ───────────
// One named route so the operator's `--wait` has a wait PARAMETER to land in
// rather than a defaulted argument nobody has to pass (S-112: the wait was
// omitted here and the read silently ran with 0). `wait_seconds` is deliberately
// not defaulted — see outbox.hpp.
uint64_t nonce_hint_trustless(RpcClient& rpc, const determ::chain::GenesisConfig& genesis,
                              const Hash& genesis_hash, const std::string& sender,
                              uint64_t wait_seconds) {
    pin_daemon_genesis(rpc, genesis, genesis_hash);   // a wrong-chain daemon must not steer the reservation
    // The hint is the committee-verified next_nonce (A2: no unverified daemon
    // positive steers a reservation — a hint above the chain's truth would
    // reserve a nonce the chain never reaches).
    AccountView v = read_account_trustless(rpc, build_genesis_committee(genesis), genesis,
                                           sender, /*resume=*/false, /*state_path=*/"",
                                           wait_seconds);
    return v.next_nonce;
}

// ─── reconcile ──────────────────────────────────────────────────────────────
namespace {
struct Located { size_t alt{0}; uint64_t height{0}; std::string block_hash; };

// Verified, canonical inclusion of alternate `alt` at `h`: membership by the
// block's own committee sigs, then the successor binding; returns the bound
// block hash or "" (with a reason) when it cannot be established.
enum class Bind { CANONICAL, ORPHANED, UNVERIFIABLE, NOT_INCLUDED };
Bind verify_and_bind(RpcClient& rpc, const std::map<std::string, PubKey>& seed,
                     const determ::chain::GenesisConfig& genesis, const json& committee_json,
                     uint64_t h, const std::string& tx_hash_hex, uint64_t wait_seconds,
                     std::string& block_hash_out, std::string& reason) {
    TxInclusionResult inc = verify_tx_inclusion(rpc, seed, genesis, h, tx_hash_hex);
    if (inc.verdict == InclusionVerdict::UNVERIFIABLE) { reason = inc.detail; return Bind::UNVERIFIABLE; }
    if (inc.verdict == InclusionVerdict::NOT_INCLUDED) { reason = "daemon hint wrong: not in block " + std::to_string(h); return Bind::NOT_INCLUDED; }
    block_hash_out = inc.block_hash_hex;
    std::string bound;
    try {
        committee_bound_state_root(rpc, committee_json, h, wait_seconds,
                                   genesis.k_block_sigs, genesis.bft_enabled, &bound);
    } catch (const std::exception& e) {
        const std::string w = e.what();
        // The served body at h does not chain into the committee-signed
        // successor: whatever the daemon is doing, THIS body is not the
        // canonical block, so an inclusion in it is not canonical.
        if (w.find("SECURITY") != std::string::npos && w.find("prev_hash") != std::string::npos) {
            reason = "served block " + std::to_string(h) + " is not the canonical block at that height (" + w.substr(0, 96) + "…)";
            return Bind::ORPHANED;
        }
        reason = "successor binding unavailable: " + w;
        return Bind::UNVERIFIABLE;
    }
    if (bound != inc.block_hash_hex) { reason = "block " + std::to_string(h) + " is not the canonical block at that height (successor binds " + bound.substr(0, 16) + "…)"; return Bind::ORPHANED; }
    return Bind::CANONICAL;
}
} // namespace

ReconcileReport reconcile_all(Outbox& ob, RpcClient& rpc,
                              const determ::chain::GenesisConfig& genesis,
                              const std::map<std::string, PubKey>& committee_seed,
                              const ReconcileOptions& opt, uint64_t now,
                              std::function<void(const std::string&)> log) {
    ReconcileReport rep;
    auto note = [&](const std::string& s) { rep.lines.push_back(s); if (log) log(s); };
    if (!ob.has_meta()) return rep;
    const std::string sender = ob.meta().sender;

    AccountView view = read_account_trustless(rpc, committee_seed, genesis, sender,
                                              opt.resume, opt.state_path, opt.wait_seconds);
    const uint64_t nn = view.next_nonce;
    const uint64_t vi = view.height == 0 ? 0 : view.height - 1;   // state proven at this index
    rep.verified_next_nonce = nn; rep.verified_index = vi; rep.verified_balance = view.balance;

    json committee_json;
    {
        json arr = json::array();
        for (auto& [d, pk] : committee_seed) arr.push_back({{"domain", d}, {"ed_pub", to_hex(pk)}});
        committee_json = json{{"members", arr}};
    }

    // GAP: the chain expects nonce nn, no local slot reserves it, and a
    // higher slot is waiting — nothing local can ever fill it. A quarantined
    // file at nn reserves the nonce but cannot be sent: the same blockage.
    {
        bool higher_pending = false;
        for (auto& [n, s] : ob.slots()) if (n > nn && !s.corrupt && !s.rec.terminal()) { higher_pending = true; break; }
        if (higher_pending && !ob.nonce_reserved(nn)) {
            rep.gap = true; rep.gap_nonce = nn;
            note("GAP: the chain expects nonce " + std::to_string(nn) + " from " + sender
                 + " but no local slot reserves it — higher slots cannot be included until it is filled "
                   "(`outbox enqueue --nonce " + std::to_string(nn) + "`)");
        } else if (higher_pending && ob.nonce_quarantined(nn)) {
            note("BLOCKING: nonce " + std::to_string(nn) + " is the next expected nonce and its slot is quarantined — "
                 "higher slots cannot be included until it is re-issued (`outbox enqueue --nonce " + std::to_string(nn) + "`)");
        }
    }

    for (auto& [nonce, slot] : ob.slots()) {
        if (slot.corrupt || slot.status_corrupt) {
            note("slot " + std::to_string(nonce) + ": CORRUPT — " + slot.corrupt_detail);
            if (nn == nonce) note("BLOCKING: slot " + std::to_string(nonce) + " is the next expected nonce and cannot be sent — `outbox recover` / `outbox replace`");
            rep.unverifiable++;
            continue;
        }
        Record& r = slot.rec;
        const std::string tag = "slot " + std::to_string(nonce);
        // FINALIZED/APPLIED is final. CONSUMED is final for SENDING but is probed
        // again: a daemon that later locates the canonical inclusion upgrades it.
        if (r.state == State::FINALIZED && r.apply == Apply::APPLIED) { rep.unchanged++; continue; }
        if (nn < nonce) { rep.unchanged++; continue; }        // earlier nonces pending; nothing to learn yet

        // Every probe below is per alternate and fail-soft: a hostile or odd
        // reply is an UNVERIFIABLE note, never an escape that skips later slots.
        std::vector<Located> canonical;
        bool ahead = false; Located ahead_loc;
        bool any_unverifiable = false, any_orphaned = false, any_not_included = false;
        auto probe = [&](size_t i, uint64_t h) {
            std::string bh, reason;
            try {
                if (h > vi) {
                    // Included after the verified state index: membership only; the
                    // apply half is unknowable until the state read catches up.
                    TxInclusionResult inc = verify_tx_inclusion(rpc, committee_seed, genesis, h, to_hex(r.alternates[i].tx_hash));
                    if (inc.verdict == InclusionVerdict::INCLUDED) {
                        if (nn > nonce) { note(tag + ": daemon inconsistent — nonce proven consumed at index " + std::to_string(vi) + " but reports inclusion at " + std::to_string(h)); any_unverifiable = true; return; }
                        if (!ahead || h > ahead_loc.height) { ahead = true; ahead_loc = {i, h, inc.block_hash_hex}; }
                    } else { any_unverifiable = true; note(tag + ": inclusion at " + std::to_string(h) + " not verifiable: " + inc.detail); }
                    return;
                }
                Bind b = verify_and_bind(rpc, committee_seed, genesis, committee_json, h,
                                         to_hex(r.alternates[i].tx_hash), opt.wait_seconds, bh, reason);
                if (b == Bind::CANONICAL) canonical.push_back({i, h, bh});
                else if (b == Bind::UNVERIFIABLE) { any_unverifiable = true; note(tag + ": " + reason); }
                else if (b == Bind::ORPHANED) { any_orphaned = true; note(tag + ": inclusion at " + std::to_string(h) + " orphaned (" + reason + ")"); }
                else { any_not_included = true; note(tag + ": " + reason); }
            } catch (const std::exception& e) {
                any_unverifiable = true;
                note(tag + ": probe at " + std::to_string(h) + " failed: " + e.what());
            }
        };
        // Daemon hints for every alternate (a NEGATIVE is never trusted).
        for (size_t i = 0; i < r.alternates.size(); ++i) {
            uint64_t h = 0; bool have = false;
            try {
                json t = rpc.call("tx", {{"hash", to_hex(r.alternates[i].tx_hash)}});
                if (t.is_object() && t.contains("block_index") && t["block_index"].is_number_unsigned()) { h = t["block_index"].get<uint64_t>(); have = true; }
            } catch (const std::exception& e) {
                any_unverifiable = true; note(tag + ": tx hint failed: " + e.what());
            }
            if (have) probe(i, h);
        }
        // A recorded inclusion is our own committee-verified fact: re-verify it
        // directly, whether or not the daemon still reports the hash.
        auto have_canonical_at = [&](uint64_t h) {
            return std::any_of(canonical.begin(), canonical.end(), [&](const Located& c) { return c.height == h; });
        };
        if (r.state == State::INCLUDED && r.included_height <= vi && !have_canonical_at(r.included_height)) {
            const bool unverifiable_before = any_unverifiable;
            probe(r.included_alt, r.included_height);
            if (!have_canonical_at(r.included_height) && any_unverifiable == unverifiable_before)
                any_orphaned = true;   // bound to another block, refused, or no longer included → ours was orphaned
        }
        if (any_unverifiable) rep.unverifiable++;   // exit-3 class whatever verdict follows

        // The reason a spent nonce could not be attributed (named in the verdict).
        std::string unlocated_why;
        if (!canonical.empty()) {
            // A nonce-N tx cannot be included after its apply (validator nonce
            // rule), so the GREATEST canonical height is the one that decided the
            // nonce; every lower canonical inclusion was a skip. WHICH alternate
            // that is comes from the daemon's per-alternate hints (A2).
            auto best = *std::max_element(canonical.begin(), canonical.end(),
                                          [](const Located& a, const Located& b) { return a.height < b.height; });
            // A skip is counted once per canonical INCLUSION, never per reconcile
            // pass: `finalized_height` names the inclusion already counted, so it
            // is compared BEFORE it is moved to `best` (a later skipped inclusion
            // at a greater height is a new skip and advances the cap).
            const bool same_skip = (r.finalized_height == best.height);
            if (nn > nonce && same_skip) {
                // This inclusion was proven a skip earlier (nonce unchanged at an
                // index ≥ its height): it cannot be the one that spent the nonce.
                unlocated_why = "its only located inclusion (" + std::to_string(best.height) + ") was proven skipped";
            } else if (nn > nonce && any_unverifiable && r.alternates.size() > 1) {
                // Attribution needs every alternate answered: another alternate may
                // have applied at a height this pass could not verify.
                rep.unchanged++;
                note(tag + ": nonce spent; attribution withheld — an alternate's probe was unverifiable this pass");
                continue;
            } else {
                r.included_height = best.height;
                r.included_block_hash = from_hex_arr<32>(best.block_hash);
                r.included_alt = static_cast<uint8_t>(best.alt);
                r.finalized_height = best.height;
                if (nn > nonce) {
                    r.state = State::FINALIZED; r.apply = Apply::APPLIED;
                    r.last_error.clear();
                    rep.finalized_applied++;
                    note(tag + ": FINALIZED/APPLIED at " + std::to_string(best.height) + " tx=" + to_hex(r.alternates[best.alt].tx_hash)
                         + " msg=" + to_hex(r.alternates[best.alt].msg_id));
                    ob.write_slot_replace(r, now);
                    continue;
                }
                // Proven: in a final block, not applied (nonce unchanged at vi >= h).
                // A slot already re-armed for this inclusion is left alone (its
                // backoff included).
                if (!same_skip) r.skipped_count = sat_inc(r.skipped_count);
                const Alternate& a = r.alternates[best.alt];
                uint64_t cost = a.fee + Transaction::decode_frame(a.frame.data(), a.frame.size()).amount;
                const bool funded = view.balance >= cost;
                const bool rearm = r.skipped_count <= MAX_SKIPS && funded;
                if (same_skip && (r.sendable() || !rearm)) {
                    rep.unchanged++;   // this inclusion was handled on an earlier pass; nothing changed on disk
                    note(tag + (r.sendable() ? ": still awaiting re-inclusion after the skip at " : ": still not re-armed after the skip at ") + std::to_string(best.height));
                    continue;
                }
                if (rearm) {
                    r.state = State::QUEUED; r.apply = Apply::SKIPPED;
                    r.next_retry = now; r.consecutive_failures = 0;
                    r.last_error = trunc_error("included at " + std::to_string(best.height) + " but not applied; re-armed (skip " + std::to_string(r.skipped_count) + ")");
                    rep.rearmed++;
                    note(tag + ": included at " + std::to_string(best.height) + " but NOT applied — re-armed (same bytes; the consumer will see this hash again)");
                } else {
                    r.state = State::FINALIZED; r.apply = Apply::SKIPPED;
                    r.last_error = trunc_error(funded ? "skipped " + std::to_string(r.skipped_count) + " times; not re-armed (cap) — `outbox replace`"
                                                      : "blocked: balance " + std::to_string(view.balance) + " < amount+fee " + std::to_string(cost));
                    rep.finalized_skipped++;
                    note(tag + ": FINALIZED/SKIPPED at " + std::to_string(best.height) + " — " + r.last_error);
                }
                ob.write_slot_replace(r, now);
                continue;
            }
        }

        if (ahead) {
            if (r.state != State::INCLUDED || r.included_height != ahead_loc.height || r.included_alt != ahead_loc.alt) {
                r.state = State::INCLUDED; r.apply = Apply::UNKNOWN;
                r.included_height = ahead_loc.height;
                r.included_block_hash = from_hex_arr<32>(ahead_loc.block_hash);
                r.included_alt = static_cast<uint8_t>(ahead_loc.alt);
                r.last_error.clear();
                ob.write_slot_replace(r, now);
            }
            rep.included++;
            note(tag + ": INCLUDED at " + std::to_string(ahead_loc.height) + " (head; not final until a committee-signed successor binds it)");
            continue;
        }

        if (any_unverifiable) {
            // Something could not be verified this pass: leave the slot as it is.
            rep.unchanged++;
            note(tag + ": left unchanged (a leg was UNVERIFIABLE this pass)");
            continue;
        }

        if (nn == nonce && r.state == State::INCLUDED && any_orphaned) {
            r.state = State::QUEUED; r.apply = Apply::UNKNOWN;
            r.orphaned_count = sat_inc(r.orphaned_count);
            r.next_retry = now; r.consecutive_failures = 0;
            r.last_error = trunc_error("orphaned at " + std::to_string(r.included_height) + " (same-height reorg / non-canonical served block); re-armed");
            r.included_height = 0; r.included_block_hash = Hash{}; r.included_alt = 0;
            rep.orphaned++;
            note(tag + ": recorded inclusion was orphaned — re-armed with the same bytes");
            ob.write_slot_replace(r, now);
            continue;
        }

        if (nn > nonce) {
            // The nonce is spent and this daemon located no CANONICAL inclusion of
            // the slot's bytes; what it did serve (if anything) is named. Not
            // re-stamped once recorded; probed again on every pass.
            if (unlocated_why.empty())
                unlocated_why = any_orphaned     ? "it served only an orphaned body carrying the bytes"
                              : any_not_included ? "its hint named a block that does not carry the bytes"
                                                 : "it locates none of the slot's bytes";
            if (r.state == State::CONSUMED) { rep.unchanged++; continue; }
            r.state = State::CONSUMED; r.apply = Apply::UNLOCATED;
            r.last_error = trunc_error("nonce proven consumed at index " + std::to_string(vi) + "; " + unlocated_why + " (unverified negative)");
            rep.consumed++;
            note(tag + ": CONSUMED/UNLOCATED — the nonce is spent on-chain; " + unlocated_why + "; another daemon may locate the applying bytes");
            ob.write_slot_replace(r, now);
            continue;
        }

        // nn == nonce and nothing located: unchanged. Report what may be wrong.
        rep.unchanged++;
        if (r.sendable()) {
            const Alternate& a = r.active();
            uint64_t cost = a.fee + Transaction::decode_frame(a.frame.data(), a.frame.size()).amount;
            if (view.balance < cost)
                note(tag + ": blocked — verified balance " + std::to_string(view.balance) + " < amount+fee " + std::to_string(cost));
            if (r.state == State::SUBMITTED && r.first_ack_height > 0
                && view.height >= r.first_ack_height + STUCK_AFTER_BLOCKS)
                note(tag + ": STUCK — acknowledged " + std::to_string(view.height - r.first_ack_height)
                     + " blocks ago and still not included (daemon-side eviction? check the daemon log; `outbox replace` to bump the fee)");
        }
    }
    return rep;
}

// ─── status rendering ───────────────────────────────────────────────────────
json slot_to_json(const Slot& s, uint64_t now) {
    json j;
    j["nonce"] = s.rec.nonce;
    if (s.corrupt) {
        j["state"] = "CORRUPT"; j["detail"] = s.corrupt_detail;
        return j;
    }
    const Record& r = s.rec;
    const Alternate& a = r.active();
    Transaction tx = Transaction::decode_frame(a.frame.data(), a.frame.size());
    j["msg_id"] = to_hex(a.msg_id);
    j["state"] = s.status_corrupt ? "CORRUPT-STATUS" : state_name(r.state);
    j["apply"] = apply_name(r.apply);
    j["sendable"] = !s.status_corrupt && r.sendable();
    j["type"] = static_cast<int>(tx.type);
    j["to"] = tx.to;
    j["amount"] = tx.amount;
    j["fee"] = tx.fee;
    j["payload_len"] = tx.payload.size();
    j["payload_sha256_prefix"] = tx.payload.empty() ? "" : to_hex(determ::crypto::sha256(tx.payload.data(), tx.payload.size())).substr(0, 16);
    j["tx_hash"] = to_hex(a.tx_hash);
    j["attempts"] = r.attempts;
    j["consecutive_failures"] = r.consecutive_failures;
    j["last_attempt"] = r.last_attempt;
    j["next_retry"] = r.next_retry;
    j["due"] = r.sendable() && r.next_retry <= now;
    j["last_outcome"] = outcome_name(r.last_outcome);
    j["last_error"] = r.last_error;
    j["included_height"] = r.included_height;
    j["included_block_hash"] = r.included_height ? to_hex(r.included_block_hash) : "";
    j["finalized_height"] = r.finalized_height;
    j["skipped_count"] = r.skipped_count;
    j["orphaned_count"] = r.orphaned_count;
    j["idempotency_key"] = r.idempotency_key;
    j["created"] = r.created;
    j["updated"] = r.updated;
    json alts = json::array();
    for (auto& alt : r.alternates)
        alts.push_back({{"kind", alt_kind_name(alt.kind)}, {"fee", alt.fee},
                        {"tx_hash", to_hex(alt.tx_hash)}, {"msg_id", to_hex(alt.msg_id)}});
    j["alternates"] = alts;
    if (s.status_corrupt) j["detail"] = s.corrupt_detail;
    return j;
}

std::string slot_to_line(const Slot& s, uint64_t now) {
    json j = slot_to_json(s, now);
    std::string line = "nonce=" + std::to_string(s.rec.nonce) + " " + j["state"].get<std::string>();
    if (s.corrupt) return line + " " + j["detail"].get<std::string>();
    line += "/" + j["apply"].get<std::string>()
          + " msg=" + j["msg_id"].get<std::string>().substr(0, 16)
          + " tx=" + j["tx_hash"].get<std::string>().substr(0, 16)
          + " to=" + j["to"].get<std::string>()
          + " amount=" + std::to_string(j["amount"].get<uint64_t>())
          + " fee=" + std::to_string(j["fee"].get<uint64_t>())
          + " attempts=" + std::to_string(j["attempts"].get<uint32_t>())
          + " last=" + j["last_outcome"].get<std::string>();
    if (j["included_height"].get<uint64_t>()) line += " h=" + std::to_string(j["included_height"].get<uint64_t>());
    if (!j["last_error"].get<std::string>().empty()) line += " note=\"" + j["last_error"].get<std::string>() + "\"";
    return line;
}

} // namespace determ::light::outbox
