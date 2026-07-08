// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// TimerService — the shared deadline-thread timer engine behind every
// EventLoop's timer_schedule/timer_cancel (and thus net::LoopTimer, minix
// §4.5). Neither IOCP nor epoll/kqueue has a timer
// primitive that fits the seam's model directly, and the engine is pure
// std:: (a lazily-started thread, a tiny entry list, a condition variable),
// so both native event loops delegate to one implementation: schedule(delay,
// fn) hands the callback to the owning loop's post() when the deadline
// passes — on_expire runs on a LOOP thread, exactly like the asio
// waitable-timer model. cancel(id) before the deadline suppresses the
// callback; a cancel that races the exact expiry moment may lose (the
// completion is already posted) — the same window every backend has, which
// is why the seam contract tests use unreachable deadlines for their cancel
// assertions.
#pragma once
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace determ::net {

class TimerService {
public:
    // `post` queues a callback onto the owning event loop; only invoked
    // from the deadline thread, never during construction.
    explicit TimerService(std::function<void(std::function<void()>)> post)
        : post_(std::move(post)) {}

    ~TimerService() { shutdown(); }

    TimerService(const TimerService&) = delete;
    TimerService& operator=(const TimerService&) = delete;

    uint64_t schedule(std::chrono::milliseconds delay,
                      std::function<void()> fn) {
        std::lock_guard<std::mutex> lk(mu_);
        uint64_t id = next_id_++;
        entries_.push_back(
            {std::chrono::steady_clock::now() + delay, id, std::move(fn)});
        if (!thread_.joinable())
            thread_ = std::thread([this] { thread_body(); });
        cv_.notify_all();
        return id;
    }

    void cancel(uint64_t id) {
        if (id == 0) return;
        std::lock_guard<std::mutex> lk(mu_);
        for (auto it = entries_.begin(); it != entries_.end(); ++it) {
            if (it->id == id) {
                entries_.erase(it);
                break;
            }
        }
        // Already-fired ids: nothing to remove — the suppression window
        // closed when the entry was popped for posting (header comment).
    }

    // Idempotent stop+join. The owning loop calls this at the START of its
    // destructor — before tearing down its dispatch machinery — so no timer
    // post can race the teardown; the destructor calls it again harmlessly.
    void shutdown() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            shutdown_ = true;
        }
        cv_.notify_all();
        if (thread_.joinable()) thread_.join();
    }

private:
    struct Entry {
        std::chrono::steady_clock::time_point deadline;
        uint64_t                              id;
        std::function<void()>                 fn;
    };

    void thread_body() {
        std::unique_lock<std::mutex> lk(mu_);
        while (!shutdown_) {
            if (entries_.empty()) {
                cv_.wait(lk);
                continue;
            }
            auto next = entries_.front().deadline;
            for (const auto& e : entries_)
                if (e.deadline < next) next = e.deadline;

            if (std::chrono::steady_clock::now() < next) {
                cv_.wait_until(lk, next);
                continue;   // re-evaluate: entries may have changed
            }

            // Pop everything due; post outside the lock (post() never
            // blocks, but holding mu_ across foreign code invites
            // lock-order knots).
            auto now = std::chrono::steady_clock::now();
            std::vector<std::function<void()>> due;
            for (auto it = entries_.begin(); it != entries_.end();) {
                if (it->deadline <= now) {
                    due.push_back(std::move(it->fn));
                    it = entries_.erase(it);
                } else {
                    ++it;
                }
            }
            lk.unlock();
            for (auto& f : due) post_(std::move(f));
            lk.lock();
        }
    }

    std::function<void(std::function<void()>)> post_;
    std::mutex              mu_;
    std::condition_variable cv_;
    std::vector<Entry>      entries_;   // tiny N (3 per Node) — linear ops
    uint64_t                next_id_ = 1;
    bool                    shutdown_ = false;
    std::thread             thread_;    // started lazily on first schedule
};

} // namespace determ::net
