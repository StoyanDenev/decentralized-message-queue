// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
#pragma once

// The ONE restricted-write primitive: put a blob of bytes on disk in a file
// that is owner-only (0600) BEFORE its first byte is written, and leave
// nothing behind on any failure path.
//
// WHY THIS EXISTS. Three hand-rolled copies of this loop were written
// independently over two days (`wallet/main.cpp::write_bytes_file_0600`
// 2026-09-17, `src/crypto/keys.cpp::save_node_key` 2026-09-17,
// `src/main.cpp::write_account_file_0600` 2026-09-18) and they drifted TWICE,
// measurably, inside those two days:
//   * two of them disagreed on `write() == 0` — one guarded it, one would have
//     spun forever — caught by review and fixed on 2026-09-18;
//   * only the wallet copy omitted `::unlink` on the write- and close-failure
//     paths, so a TRUNCATED key container survived under the final name where
//     both siblings removed it and said at the locus why.
// The third copy was written deliberately, with the reason stated in its own
// DECISION-LOG entry, which named this extraction as the follow-up. This header
// is that follow-up: the MECHANISM lives here once, and every difference
// between the three call sites that is a deliberate policy of that site is a
// parameter below or stays at the site.
//
// HEADER-ONLY, deliberately, and checked against CMakeLists.txt rather than
// assumed: the three consumers are the `determ` daemon (src/main.cpp,
// src/crypto/keys.cpp) and the `determ-wallet` executable — two separate
// add_executable targets. The only library between them is `determ-crypto-c99`,
// whose source list is exclusively `.c` under the C99 / Minix-portable
// discipline (CRYPTO-C99-SPEC.md), so a C++ translation unit cannot be added
// there. Everything below is `inline`.
//
// WHAT THIS PRIMITIVE OWNS (the part that drifted):
//   * `::open(O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW, 0600)`. Both the
//     create mode AND the fchmod below are load-bearing and neither implies the
//     other — measured 2026-09-17/18: `O_CREAT|O_TRUNC` with a mode does NOT
//     narrow a file that already EXISTS, so the create mode alone leaves the
//     whole window open on every overwrite while a fresh-create test stays
//     green. `O_NOFOLLOW` is independent: without it a symlink planted at the
//     path is followed, which both writes the secret into whatever file it
//     names and aims the narrowing at the wrong inode; it guards the FINAL path
//     component only. `O_CLOEXEC` keeps the descriptor out of any child.
//   * `::fchmod(fd, 0600)` on the DESCRIPTOR, before the first byte. A chmod by
//     PATH after the write is both a TOCTOU window and a period in which the
//     secret is on disk world-readable.
//   * the write loop: EINTR, short writes, and a refusal to spin on
//     `write() == 0` (which cannot happen for a positive count on a regular
//     file, and must not become an infinite loop if it ever does).
//   * a CHECKED `::close`.
//   * removing the file on every failure path that has already truncated it.
//   * optionally the trailing, belt-and-braces `std::filesystem::permissions`
//     call, whose `std::error_code` is handed BACK rather than swallowed.
//
// WHAT IT DELIBERATELY DOES NOT OWN, because the three sites differ on purpose:
//   * every diagnostic STRING, and the choice of warn / warn+flag / throw. The
//     three reporting shapes are three separate recorded decisions; this
//     returns a status and the caller renders it.
//   * whether a failed pre-write narrowing REFUSES or continues (`on_narrow_
//     failure`) — see that field.
//   * whether the trailing `permissions` call happens at all (`final_narrow`).
//   * Windows text vs binary mode (`windows_binary`) — that is on-disk BYTES.
//   * `fsync`, deliberately: `keyfile-rotate` re-opens and fsyncs its staging
//     file itself "rather than pushing an fsync into a primitive ten other
//     callers share", and that reason applies to this primitive verbatim.
//   * creating or narrowing PARENT DIRECTORIES (only `save_node_key` does that,
//     and only for a directory it created itself).
//
// WINDOWS. Nothing about the permission WINDOW is closed there and this header
// does not pretend otherwise: `_S_IREAD|_S_IWRITE` on `_open` drives only
// FILE_ATTRIBUTE_READONLY and the effective ACL arrives by inheritance from the
// parent directory (docs/proofs/S005PassphraseKeyfile.md F-4). The Windows arm
// is an `std::ofstream` in the caller's chosen mode, exactly as all three sites
// already had it, and the exposure there stands.

#include <cstddef>
#include <filesystem>
#include <string>
#include <system_error>

#ifdef _WIN32
#  include <fstream>
#else
#  include <cerrno>
#  include <fcntl.h>     // ::open + O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW
#  include <sys/stat.h>  // ::fchmod
#  include <unistd.h>    // ::write, ::close, ::unlink
#endif

namespace determ::util {

// Where the write stopped. `Ok` is the only value on which a file exists.
enum class RestrictedWriteStatus {
    Ok,
    OpenFailed,      // nothing of ours exists on disk
    NarrowRefused,   // the pre-write narrowing failed and the policy is Refuse
    WriteFailed,     // a ::write failed, or returned 0 for a positive count
    CloseFailed      // the contents are not trustworthy
};

// What to do when the pre-write `::fchmod` fails. This is the one behavioural
// knob that the three call sites genuinely disagree on, each with a recorded
// reason, so it is a parameter and not a fourth opinion:
//
//   Continue — write the secret anyway into a file that could not be narrowed,
//     and let the caller warn about it. `wallet/main.cpp` and `src/main.cpp`.
//     The wallet's reason: destroying a `keyfile-recover` result the operator
//     may be unable to regenerate is a worse outcome than a wide file they were
//     told about. The daemon's: refusing is an exit-code change on a shipped
//     command, separable, and named as the S-111 remainder.
//   Refuse  — close, remove the (already truncated) file and report, writing
//     nothing. `src/crypto/keys.cpp`. Its reason: a node identity is written
//     ONCE into a provisioning shell nobody reads and then read on every start
//     for the life of the deployment, and unlike a recovery transcript it can
//     be REGENERATED at no cost, so refusing costs one re-run where continuing
//     costs a world-readable identity that stakes and signs blocks.
enum class OnNarrowFailure { Continue, Refuse };

struct RestrictedWriteOptions {
    OnNarrowFailure on_narrow_failure = OnNarrowFailure::Continue;

    // Perform the trailing, belt-and-braces `std::filesystem::permissions`
    // narrowing after a successful close, and report its `error_code` in
    // `final_ec`. `save_node_key` passes false: on POSIX its create+fchmod has
    // already done it and a by-path chmod after close is exactly the TOCTOU
    // shape that site removed, and on Windows the call "would look like a fix
    // and change nothing measurable" (DECISION-LOG 2026-09-17). The other two
    // keep it, because on Windows it is the only narrowing there is and on
    // POSIX its failure is the hook their P-2 reporting hangs on.
    bool final_narrow = true;

    // Windows only, and it is about ON-DISK BYTES, not about permissions. The
    // wallet writes binary containers and switched to binary mode knowingly,
    // changing its Windows output (`keyfile-decrypt --out` emits LF where the
    // old text-mode stream emitted CRLF). `account create` and `save_node_key`
    // write JSON through a TEXT-mode stream and deliberately kept it so their
    // Windows bytes stay identical. Ignored on POSIX, where the two modes are
    // the same stream.
    bool windows_binary = false;

    // TEST-ONLY, and non-zero at exactly one call site. A failed narrowing
    // cannot be produced from outside the process on the platforms this is
    // gated on — the test runs as the file's owner and an owner's `fchmod` on a
    // local filesystem does not fail — so without a hook the "report the
    // failure, do not swallow it" rule at `save_node_key` would have no gate
    // that can go RED, i.e. no gate at all (wave doctrine rule 5). The decision
    // to use it, and the `getenv` that drives it, stay in
    // `src/crypto/keys.cpp` where they were justified; this is only the
    // parameter that carries it in. It can turn a success into a REPORTED
    // failure and never the reverse: the real `::fchmod` runs first and only
    // its RESULT is overridden, so the file is narrowed whether or not the hook
    // fires. An earlier shape replaced the call and did weaken the permission on
    // a pre-existing target; the comment said otherwise, which is the trap a
    // shared primitive must not set for its next caller.
    int simulate_narrow_failure_errno = 0;
};

struct RestrictedWriteResult {
    RestrictedWriteStatus status = RestrictedWriteStatus::Ok;

    // errno at the point of failure, or 0 where the platform gives none (the
    // Windows `ofstream` arm). Captured BEFORE the close/unlink that follow it,
    // which would otherwise clobber it. Callers render
    //   msg + (err ? ": " + std::strerror(err) : "")
    // which reproduces each site's previous POSIX and Windows text verbatim.
    int err = 0;

    // The write stopped because `::write` returned 0 for a positive count.
    // `err` is EIO in that case; the two sites that print "wrote 0 bytes"
    // instead of an errno string use this flag to pick their wording.
    bool wrote_zero = false;

    // The pre-write `::fchmod` failed. Set on BOTH policies: under Refuse it
    // accompanies status == NarrowRefused, under Continue the write went ahead
    // and this is what the caller warns about.
    bool narrow_failed = false;
    int  narrow_err = 0;

    // The trailing `std::filesystem::permissions` call's error_code, when
    // `final_narrow` was set. Handed back rather than discarded: swallowing it
    // is precisely the P-2 defect (`(void)perm_ec`) the wallet increment
    // removed.
    std::error_code final_ec{};

    bool ok() const { return status == RestrictedWriteStatus::Ok; }
};

// Write `len` bytes from `data` to `path`, owner-only from creation.
//
// On every failure path after the file has been truncated — a refused
// narrowing, a failed write, a failed close — the file is REMOVED before
// returning. `O_TRUNC` runs before anything can be checked, so what would
// otherwise survive under the final name is a zero-byte or truncated key
// container that an operator, and this repo's own `fs::exists()` guards, read
// as a provisioned artifact: measured 2026-09-17, an empty `node_key.json` left
// by a refusal made the next `determ init` print "already exists" and exit 0,
// and the failure resurfaced later as an unrelated JSON parse error. A
// fragment cannot be recovered from in any case — every container this writes
// (DAK1 / DSS1 / DNK1 / DWE2 / the JSON keyfiles) fails its own decoder's magic
// and length checks when truncated — so nothing is lost by removing it.
inline RestrictedWriteResult
write_restricted_0600(const std::string& path,
                      const void* data,
                      std::size_t len,
                      const RestrictedWriteOptions& opts = RestrictedWriteOptions{}) {
    RestrictedWriteResult r;

#ifdef _WIN32
    // Text vs binary is the caller's; `ofstream`'s constructor ORs in
    // `ios::out`, so `trunc` alone is byte-for-byte the default-constructed
    // stream all three sites used, and `binary|trunc` is the wallet's.
    std::ofstream f(path, opts.windows_binary
                              ? (std::ios::binary | std::ios::trunc)
                              : std::ios::trunc);
    if (!f) {
        r.status = RestrictedWriteStatus::OpenFailed;
        return r;
    }
    if (len > 0)
        f.write(static_cast<const char*>(data), static_cast<std::streamsize>(len));
    f.close();
    if (!f) {
        r.status = RestrictedWriteStatus::WriteFailed;
        // Truncated by the open; do not publish a fragment under the final name.
        std::error_code rm_ec;
        std::filesystem::remove(path, rm_ec);
        return r;
    }
    (void)opts.on_narrow_failure;
    (void)opts.simulate_narrow_failure_errno;
#else
    const int fd = ::open(path.c_str(),
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                          0600);
    if (fd < 0) {
        r.status = RestrictedWriteStatus::OpenFailed;
        r.err = errno;
        return r;
    }
    {
        // The real narrowing ALWAYS runs; the hook only overrides the RESULT
        // afterwards. Replacing the call instead (the first shape of this code)
        // meant that under `Continue` — the policy at two of the three sites —
        // a pre-existing file was never narrowed at all, because O_CREAT|O_TRUNC
        // does not narrow an existing file. Measured against the shipped header:
        // a 0644 target stayed 0644 through the write. The hook is reachable
        // only from a site that passes a non-zero errno, but a shared primitive
        // must not carry a path by which a test aid weakens a real permission.
        int rc = ::fchmod(fd, 0600);
        if (opts.simulate_narrow_failure_errno != 0) {
            rc = -1;
            errno = opts.simulate_narrow_failure_errno;
        }
        if (rc != 0) {
            r.narrow_failed = true;
            r.narrow_err = errno;
            if (opts.on_narrow_failure == OnNarrowFailure::Refuse) {
                ::close(fd);
                ::unlink(path.c_str());
                r.status = RestrictedWriteStatus::NarrowRefused;
                r.err = r.narrow_err;
                return r;
            }
        }
    }
    const unsigned char* p = static_cast<const unsigned char*>(data);
    std::size_t left = len;
    while (left > 0) {
        const ssize_t n = ::write(fd, p, left);
        if (n < 0 && errno == EINTR) continue;
        // n == 0 for a positive count cannot happen on a regular file, but it
        // must not become a spin: fail the write instead of looping forever.
        if (n <= 0) {
            const int e = (n == 0) ? EIO : errno;
            ::close(fd);
            ::unlink(path.c_str());
            r.status = RestrictedWriteStatus::WriteFailed;
            r.wrote_zero = (n == 0);
            r.err = e;
            return r;
        }
        p += n;
        left -= static_cast<std::size_t>(n);
    }
    if (::close(fd) != 0) {
        const int e = errno;
        ::unlink(path.c_str());
        r.status = RestrictedWriteStatus::CloseFailed;
        r.err = e;
        return r;
    }
#endif

    if (opts.final_narrow) {
        std::filesystem::permissions(
            path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace,
            r.final_ec);
    }
    return r;
}

} // namespace determ::util
