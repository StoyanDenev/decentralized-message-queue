// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// ReactorEventLoop implementation (minix §4.5 — epoll on Linux, kqueue on
// Darwin). POSIX-only TU — pruned from SOURCES on Windows by CMakeLists.txt.
#ifndef _WIN32

#include <determ/net/reactor_event_loop.hpp>

#if defined(__APPLE__)
#include <sys/event.h>
#include <fcntl.h>
#else
#include <sys/epoll.h>
#include <sys/eventfd.h>
#endif
#include <unistd.h>
#include <cerrno>
#include <stdexcept>
#include <utility>

namespace determ::net {

namespace {

/* Post `units` wakeups to the wake channel. Linux: one eventfd add of
 * `units` (EFD_SEMAPHORE pops one per read). Darwin: `units` single bytes
 * down the wake pipe (one byte == one unit; an O_NONBLOCK short write means
 * >64 KiB of wakeups are already pending — every thread is awake anyway). */
void wake_write(int fd, uint64_t units) {
#if defined(__APPLE__)
    for (uint64_t i = 0; i < units; ++i) {
        char c = 1;
        if (::write(fd, &c, 1) < 0) break;
    }
#else
    [[maybe_unused]] ssize_t rc = ::write(fd, &units, sizeof units);
#endif
}

#if defined(__APPLE__)

uint32_t from_kqueue(const struct kevent& ev) {
    uint32_t out = 0;
    if (ev.filter == EVFILT_READ)  out |= kEventRead;
    if (ev.filter == EVFILT_WRITE) out |= kEventWrite;
    /* EOF/error: deliver BOTH readiness bits too — the handler's parked
     * ops attempt their syscalls and surface the real errno (§4.5 §2.1). */
    if (ev.flags & (EV_EOF | EV_ERROR)) out |= kEventError | kEventRead | kEventWrite;
    return out;
}

#else

uint32_t to_epoll(uint32_t interest) {
    uint32_t ev = EPOLLONESHOT;
    if (interest & kEventRead) ev |= EPOLLIN;
    if (interest & kEventWrite) ev |= EPOLLOUT;
    return ev;
}

uint32_t from_epoll(uint32_t ev) {
    uint32_t out = 0;
    if (ev & EPOLLIN) out |= kEventRead;
    if (ev & EPOLLOUT) out |= kEventWrite;
    // Error/hangup: deliver BOTH readiness bits too — the handler's parked
    // ops attempt their syscalls and surface the real errno (§4.5 §2.1).
    if (ev & (EPOLLERR | EPOLLHUP)) out |= kEventError | kEventRead | kEventWrite;
    return out;
}

#endif /* __APPLE__ / epoll */

} // namespace

ReactorEventLoop::ReactorEventLoop() {
#if defined(__APPLE__)
    epfd_ = ::kqueue();
    if (epfd_ < 0)
        throw std::runtime_error("ReactorEventLoop: kqueue failed");
    /* Wake channel: a pipe, one byte per wakeup unit — the EFD_SEMAPHORE
     * analogue (each byte wakes exactly one reader, which pops exactly one
     * closure). No pipe2 on Darwin: flip CLOEXEC/NONBLOCK per fd. */
    int p[2];
    if (::pipe(p) != 0) {
        ::close(epfd_);
        throw std::runtime_error("ReactorEventLoop: wake pipe failed");
    }
    for (int i = 0; i < 2; ++i) {
        ::fcntl(p[i], F_SETFD, FD_CLOEXEC);
        ::fcntl(p[i], F_SETFL, O_NONBLOCK);
    }
    wake_fd_ = p[0];
    wake_wr_ = p[1];
    /* Level-triggered (no ONESHOT/CLEAR), like the epoll wake registration:
     * remaining bytes keep the read end readable, so N pending posts wake
     * up to N threads; a thread that loses the read race (EAGAIN) just
     * re-enters kevent. */
    struct kevent ev;
    EV_SET(&ev, wake_fd_, EVFILT_READ, EV_ADD, 0, 0, nullptr);
    if (::kevent(epfd_, &ev, 1, nullptr, 0, nullptr) != 0) {
        ::close(wake_fd_);
        ::close(wake_wr_);
        ::close(epfd_);
        throw std::runtime_error("ReactorEventLoop: wake-fd registration failed");
    }
#else
    epfd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (epfd_ < 0)
        throw std::runtime_error("ReactorEventLoop: epoll_create1 failed");
    // EFD_SEMAPHORE: each write(1) wakes exactly one reader — post() wakes
    // exactly one run() thread, which pops exactly one closure.
    wake_fd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE);
    if (wake_fd_ < 0) {
        ::close(epfd_);
        throw std::runtime_error("ReactorEventLoop: eventfd failed");
    }
    // Level-triggered, NOT one-shot: with EFD_SEMAPHORE the remaining count
    // keeps the fd readable, so N pending posts wake up to N threads; a
    // thread that loses the read race (EAGAIN) just re-enters epoll_wait.
    epoll_event ev{};
    ev.events  = EPOLLIN;
    ev.data.fd = wake_fd_;
    if (::epoll_ctl(epfd_, EPOLL_CTL_ADD, wake_fd_, &ev) != 0) {
        ::close(wake_fd_);
        ::close(epfd_);
        throw std::runtime_error("ReactorEventLoop: wake-fd registration failed");
    }
    wake_wr_ = wake_fd_;   // eventfd is written and read through one fd
#endif /* __APPLE__ / epoll */
}

ReactorEventLoop::~ReactorEventLoop() {
    stop();
    // Stop the timer thread BEFORE teardown so no timer post races the
    // close below (post() to a closed wake fd would just drop the wakeup;
    // shutting down first keeps the reasoning simple).
    timers_.shutdown();
    // Undelivered posts are dropped without invoking — the never-dispatched-
    // handler semantics all backends share. Registry should be empty
    // (consumers destroy connections/acceptors first); clear defensively.
    {
        std::lock_guard<std::mutex> lk(post_mu_);
        post_q_.clear();
    }
    {
        std::lock_guard<std::mutex> lk(reg_mu_);
        registry_.clear();
    }
    if (wake_wr_ != wake_fd_) ::close(wake_wr_);   // Darwin pipe write end
    ::close(wake_fd_);
    ::close(epfd_);
}

void ReactorEventLoop::run() {
    threads_in_run_.fetch_add(1);
    struct Dec {
        std::atomic<int>& c;
        ~Dec() { c.fetch_sub(1); }
    } dec{threads_in_run_};

    for (;;) {
        if (stopped_.load()) return;
#if defined(__APPLE__)
        struct kevent evs[16];
        int n = ::kevent(epfd_, nullptr, 0, evs, 16, nullptr);
#else
        epoll_event evs[16];
        int n = ::epoll_wait(epfd_, evs, 16, -1);
#endif
        if (n < 0) {
            if (errno == EINTR) continue;
            return;   // poller fd closed under us — teardown
        }
        // Pass 1: dispatch EVERY socket readiness event in the batch FIRST.
        // One-shot events exist only in this thread's local array — running
        // a posted closure before them would hold them hostage for as long
        // as the closure runs, and RpcServer's sessions are posted closures
        // that block for the CONNECTION'S LIFETIME: a gossip peer's parked
        // exactly-N read caught behind one would freeze silently, with no
        // re-delivery possible (one-shot disabled it at delivery). IOCP has
        // no such window (one completion per GQCS dequeue) — this ordering
        // is what buys the reactor the same property per batch.
        bool wake = false;
        for (int i = 0; i < n; ++i) {
#if defined(__APPLE__)
            const int      ev_fd   = static_cast<int>(evs[i].ident);
            const uint32_t ev_bits = from_kqueue(evs[i]);
#else
            const int      ev_fd   = evs[i].data.fd;
            const uint32_t ev_bits = from_epoll(evs[i].events);
#endif
            if (ev_fd == wake_fd_) {
                wake = true;   // level-triggered: at most one entry per batch
                continue;
            }
            // Pin the handler for the dispatch, then call outside reg_mu_
            // (on_event takes the handler's own lock; a concurrent
            // deregister cannot free it mid-call).
            std::shared_ptr<ReactorHandler> h;
            {
                std::lock_guard<std::mutex> lk(reg_mu_);
                auto it = registry_.find(ev_fd);
                if (it != registry_.end()) h = it->second;
            }
            if (h) h->on_event(ev_bits);
        }
        // Pass 2: one posted closure, last. It may occupy this thread
        // indefinitely (the session-occupies-a-loop-thread model all three
        // backends share) — remaining queue units keep wake_fd_ readable,
        // so OTHER run() threads pick up the rest of the queue and all
        // future socket events.
        if (wake) {
            // Consume ONE unit (or lose the race to another thread — then
            // there is nothing to pop): an EFD_SEMAPHORE read on Linux, a
            // one-byte pipe read on Darwin.
#if defined(__APPLE__)
            char v = 0;
            if (::read(wake_fd_, &v, 1) < 0) continue;
#else
            uint64_t v = 0;
            if (::read(wake_fd_, &v, sizeof v) < 0) continue;
#endif
            if (stopped_.load()) return;   // stop() wakeup
            std::function<void()> fn;
            {
                std::lock_guard<std::mutex> lk(post_mu_);
                if (!post_q_.empty()) {
                    fn = std::move(post_q_.front());
                    post_q_.pop_front();
                }
            }
            if (fn) fn();
        }
    }
}

void ReactorEventLoop::stop() {
    if (stopped_.exchange(true)) return;
    // One semaphore unit per thread currently inside run(), plus one for a
    // racing entrant — the IocpEventLoop::stop() parity. (A fixed count
    // would strand threads beyond it in epoll_wait forever on many-core
    // machines: Node spawns hardware_concurrency() run() threads, and each
    // exiting thread consumes exactly one unit.) Leftover units keep
    // wake_fd_ readable, which is harmless: threads re-check stopped_
    // before popping.
    wake_write(wake_wr_, static_cast<uint64_t>(threads_in_run_.load()) + 1);
}

void ReactorEventLoop::post(std::function<void()> fn) {
    {
        std::lock_guard<std::mutex> lk(post_mu_);
        post_q_.push_back(std::move(fn));
    }
    // A failed write (fd closed at teardown) leaves the closure queued;
    // the destructor drops it — the stopped-io_context drop semantics.
    wake_write(wake_wr_, 1);
}

void ReactorEventLoop::arm(int fd, uint32_t interest,
                           std::shared_ptr<ReactorHandler> h) {
    bool add;
    {
        std::lock_guard<std::mutex> lk(reg_mu_);
        auto [it, inserted] = registry_.try_emplace(fd, std::move(h));
        if (!inserted) it->second = std::move(h ? h : it->second);
        add = inserted;
    }
#if defined(__APPLE__)
    /* Set EXACTLY the requested interest (the epoll-MOD-replaces contract).
     * One change per kevent() call, with an EMPTY eventlist: a non-empty
     * eventlist could dequeue-and-drop a pending event right here, and a
     * batched changelist stops at the first erroring change when there is
     * no room to report it — ENOENT on a never-armed DELETE would abort a
     * sibling ADD. Requested filters are (re)armed EV_ONESHOT — one
     * delivery per (fd, direction) until the handler re-arms (the §4.5
     * no-split-read property); the un-requested filter is DELETEd so a
     * stale one-shot from a previous arm cannot fire spuriously. Errors
     * (ENOENT on delete, EBADF on a closed-fd race) are the tolerated
     * epoll-fallback analogues. */
    (void)add;
    struct kevent ch;
    if (!(interest & kEventRead)) {
        EV_SET(&ch, fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        ::kevent(epfd_, &ch, 1, nullptr, 0, nullptr);
    }
    if (!(interest & kEventWrite)) {
        EV_SET(&ch, fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        ::kevent(epfd_, &ch, 1, nullptr, 0, nullptr);
    }
    if (interest & kEventRead) {
        EV_SET(&ch, fd, EVFILT_READ, EV_ADD | EV_ONESHOT, 0, 0, nullptr);
        ::kevent(epfd_, &ch, 1, nullptr, 0, nullptr);
    }
    if (interest & kEventWrite) {
        EV_SET(&ch, fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT, 0, 0, nullptr);
        ::kevent(epfd_, &ch, 1, nullptr, 0, nullptr);
    }
#else
    epoll_event ev{};
    ev.events  = to_epoll(interest);
    ev.data.fd = fd;
    if (::epoll_ctl(epfd_, add ? EPOLL_CTL_ADD : EPOLL_CTL_MOD, fd, &ev) != 0) {
        // ADD-after-external-close or MOD-after-DEL races surface here;
        // fall back to the other op once (covers an fd re-added after a
        // prior deregister left kernel state behind).
        ::epoll_ctl(epfd_, add ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, fd, &ev);
    }
#endif /* __APPLE__ / epoll */
}

void ReactorEventLoop::deregister(int fd) {
    {
        std::lock_guard<std::mutex> lk(reg_mu_);
        registry_.erase(fd);
    }
#if defined(__APPLE__)
    // One delete per call (a batched pair would stop at the first ENOENT);
    // empty eventlist so no pending event can be dequeued-and-dropped.
    struct kevent ch;
    EV_SET(&ch, fd, EVFILT_READ,  EV_DELETE, 0, 0, nullptr);
    ::kevent(epfd_, &ch, 1, nullptr, 0, nullptr);
    EV_SET(&ch, fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
    ::kevent(epfd_, &ch, 1, nullptr, 0, nullptr);     // idempotent-enough
#else
    ::epoll_ctl(epfd_, EPOLL_CTL_DEL, fd, nullptr);   // idempotent-enough
#endif /* __APPLE__ / epoll */
}

} // namespace determ::net

#endif // !_WIN32
