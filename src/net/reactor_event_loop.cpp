// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// ReactorEventLoop implementation (minix §4.5, epoll). POSIX-only TU —
// pruned from SOURCES on Windows by CMakeLists.txt.
#ifndef _WIN32

#include <determ/net/reactor_event_loop.hpp>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <cerrno>
#include <stdexcept>
#include <utility>

namespace determ::net {

namespace {

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

} // namespace

ReactorEventLoop::ReactorEventLoop() {
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
        epoll_event evs[16];
        int n = ::epoll_wait(epfd_, evs, 16, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            return;   // epfd closed under us — teardown
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
            if (evs[i].data.fd == wake_fd_) {
                wake = true;   // level-triggered: at most one entry per batch
                continue;
            }
            // Pin the handler for the dispatch, then call outside reg_mu_
            // (on_event takes the handler's own lock; a concurrent
            // deregister cannot free it mid-call).
            std::shared_ptr<ReactorHandler> h;
            {
                std::lock_guard<std::mutex> lk(reg_mu_);
                auto it = registry_.find(evs[i].data.fd);
                if (it != registry_.end()) h = it->second;
            }
            if (h) h->on_event(from_epoll(evs[i].events));
        }
        // Pass 2: one posted closure, last. It may occupy this thread
        // indefinitely (the session-occupies-a-loop-thread model all three
        // backends share) — remaining queue units keep wake_fd_ readable,
        // so OTHER run() threads pick up the rest of the queue and all
        // future socket events.
        if (wake) {
            uint64_t v = 0;
            // EFD_SEMAPHORE read: consume ONE unit (or lose the race to
            // another thread — then there is nothing to pop).
            if (::read(wake_fd_, &v, sizeof v) < 0) continue;
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
    uint64_t v = static_cast<uint64_t>(threads_in_run_.load()) + 1;
    [[maybe_unused]] ssize_t rc = ::write(wake_fd_, &v, sizeof v);
}

void ReactorEventLoop::post(std::function<void()> fn) {
    {
        std::lock_guard<std::mutex> lk(post_mu_);
        post_q_.push_back(std::move(fn));
    }
    uint64_t v = 1;
    [[maybe_unused]] ssize_t rc = ::write(wake_fd_, &v, sizeof v);
    // A failed write (fd closed at teardown) leaves the closure queued;
    // the destructor drops it — the stopped-io_context drop semantics.
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
    epoll_event ev{};
    ev.events  = to_epoll(interest);
    ev.data.fd = fd;
    if (::epoll_ctl(epfd_, add ? EPOLL_CTL_ADD : EPOLL_CTL_MOD, fd, &ev) != 0) {
        // ADD-after-external-close or MOD-after-DEL races surface here;
        // fall back to the other op once (covers an fd re-added after a
        // prior deregister left kernel state behind).
        ::epoll_ctl(epfd_, add ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, fd, &ev);
    }
}

void ReactorEventLoop::deregister(int fd) {
    {
        std::lock_guard<std::mutex> lk(reg_mu_);
        registry_.erase(fd);
    }
    ::epoll_ctl(epfd_, EPOLL_CTL_DEL, fd, nullptr);   // idempotent-enough
}

} // namespace determ::net

#endif // !_WIN32
