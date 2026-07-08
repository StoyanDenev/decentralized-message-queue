// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// IocpEventLoop — the native Windows backend for net::EventLoop (minix §4.5,
// increment 1). One I/O completion port services everything: socket
// completions (IocpTransport), posted closures, and timer expiries (a small
// deadline-heap thread posts them back onto the loop, so on_expire runs on a
// loop thread exactly like the asio waitable-timer model). run() keeps the
// interface's multi-thread contract natively — N worker threads all blocked
// in GetQueuedCompletionStatus on the same port IS the IOCP threading model
// the contract was written against (event_loop.hpp).
//
// stop() is permanent (no restart), matching how Node and the contract tests
// use the loop: run from N threads, stop once at shutdown, destroy.
//
// This header is OS-include-free (the §4.5 layout rule): the port is an
// opaque void* (HANDLE); all <windows.h>/<winsock2.h> usage lives in
// src/net/iocp_event_loop.cpp.
#pragma once
#include <determ/net/event_loop.hpp>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace determ::net {

class IocpEventLoop final : public EventLoop {
public:
    // Creates the completion port (NumberOfConcurrentThreads = 0: OS default,
    // matching the N-workers-call-run() contract). Throws std::runtime_error
    // on failure.
    IocpEventLoop();

    // stop() + joins the timer thread + drains still-queued packets via
    // on_abandon (freed WITHOUT invoking user callbacks — the asio semantics
    // for handlers never dispatched) + closes the port. Callers must have
    // joined their own run() threads first, as with asio::io_context.
    ~IocpEventLoop() override;

    IocpEventLoop(const IocpEventLoop&) = delete;
    IocpEventLoop& operator=(const IocpEventLoop&) = delete;

    void run() override;
    void stop() override;
    void post(std::function<void()> fn) override;

    // The HANDLE of the completion port — IocpTransport/IocpAcceptor
    // associate their sockets against it. Opaque here to keep this header
    // OS-include-free.
    void* native_port() const { return port_; }

    // ── Timer service (backs IocpTimer) ─────────────────────────────────
    // IOCP has no native timer primitive; a dedicated deadline thread owns a
    // small entry list and post()s each due callback onto the loop. Returns
    // an id; timer_cancel(id) before the deadline suppresses the callback.
    // Same suppression window as asio's waitable-timer thread: a cancel that
    // races the exact expiry moment may lose (the completion is already
    // posted) — the seam contract tests use unreachable deadlines for their
    // cancel assertions for exactly this reason.
    uint64_t timer_schedule(std::chrono::milliseconds delay,
                            std::function<void()> fn);
    void     timer_cancel(uint64_t id);

private:
    void timer_thread_body();

    void*             port_ = nullptr;   // HANDLE
    std::atomic<bool> stopped_{false};
    std::atomic<int>  threads_in_run_{0};

    struct TimerEntry {
        std::chrono::steady_clock::time_point deadline;
        uint64_t                              id;
        std::function<void()>                 fn;
    };
    std::mutex              timer_mu_;
    std::condition_variable timer_cv_;
    std::vector<TimerEntry> timer_entries_;   // tiny N (3 per Node) — linear ops
    uint64_t                next_timer_id_ = 1;
    bool                    timer_shutdown_ = false;
    std::thread             timer_thread_;    // started lazily on first schedule
};

} // namespace determ::net
