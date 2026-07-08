// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Determ Contributors
//
// ReactorTransport implementation (minix §4.5, epoll). POSIX-only TU —
// pruned from SOURCES on Windows by CMakeLists.txt.
#ifndef _WIN32

#include <determ/net/reactor_transport.hpp>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace determ::net {

namespace {

std::error_code make_ec(int err) {
    return std::error_code(err, std::system_category());
}

std::string format_endpoint(const sockaddr_in& sa) {
    char ip[INET_ADDRSTRLEN] = {};
    if (!::inet_ntop(AF_INET, &sa.sin_addr, ip, sizeof ip)) return "unknown";
    return std::string(ip) + ":" + std::to_string(ntohs(sa.sin_port));
}

// Portable non-blocking flip (no accept4/SOCK_NONBLOCK: this code is
// destined to be shared verbatim with the kqueue policy — §4.5).
bool set_nonblocking(int fd) {
    int fl = ::fcntl(fd, F_GETFL, 0);
    return fl >= 0 && ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0;
}

} // namespace

// ── ReactorConnection ────────────────────────────────────────────────────────

ReactorConnection::ReactorConnection(ReactorEventLoop& loop, int fd,
                                     std::string endpoint)
    : loop_(loop), fd_(fd), endpoint_(std::move(endpoint)) {
    set_nonblocking(fd_);
}

ReactorConnection::~ReactorConnection() {
    close();
    // The fd number is released only HERE — after every shared_ptr owner
    // (parked ops, sessions, the acceptor/connect paths) is gone — so a
    // stale epoll event or a sync-half poll() can never land on a REUSED
    // fd (§4.5 risk 3). close() already shutdown() the conversation.
    ::close(fd_);
}

bool ReactorConnection::advance_locked(Op& op, bool is_read,
                                       std::function<void()>& fire) {
    while (op.active) {
        ssize_t r;
        if (is_read) {
            r = ::recv(fd_, op.buf + op.done, op.n - op.done, 0);
        } else {
            r = ::send(fd_, op.buf + op.done, op.n - op.done, MSG_NOSIGNAL);
        }
        if (r > 0) {
            op.done += static_cast<std::size_t>(r);
            if (op.done >= op.n) {
                fire = [cb = std::move(op.cb), n = op.done] { cb({}, n); };
                op.active = false;
                return true;
            }
            continue;
        }
        if (r == 0 && is_read) {
            // Orderly remote close mid-read — asio's eof semantics.
            fire = [cb = std::move(op.cb), n = op.done] {
                cb(make_ec(ECONNRESET), n);
            };
            op.active = false;
            return true;
        }
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return false;   // parked — caller re-arms interest
        int err = r < 0 ? errno : ECONNRESET;
        fire = [cb = std::move(op.cb), n = op.done, err] {
            cb(make_ec(err), n);
        };
        op.active = false;
        return true;
    }
    return false;   // spurious wakeup for an inactive op — nothing to do
}

void ReactorConnection::update_interest_locked() {
    uint32_t interest = 0;
    if (rd_.active) interest |= kEventRead;
    if (wr_.active) interest |= kEventWrite;
    if (interest == 0) return;
    registered_ = true;
    loop_.arm(fd_, interest,
              std::static_pointer_cast<ReactorHandler>(shared_from_this()));
}

void ReactorConnection::start_op(bool is_read, void* buf, std::size_t n,
                                 IoCb cb) {
    if (closed_.load()) {
        loop_.post([cb = std::move(cb)] { cb(make_ec(ECANCELED), 0); });
        return;
    }
    if (n == 0) {
        loop_.post([cb = std::move(cb)] { cb({}, 0); });
        return;
    }
    std::function<void()> fire;
    {
        std::lock_guard<std::mutex> lk(op_mu_);
        Op& op   = is_read ? rd_ : wr_;
        op.buf   = static_cast<uint8_t*>(buf);
        op.n     = n;
        op.done  = 0;
        op.cb    = std::move(cb);
        op.active = true;
        if (!advance_locked(op, is_read, fire)) update_interest_locked();
    }
    // Completions run on loop threads, never inline in the caller — post
    // the synchronously-finished case (asio's dispatch discipline).
    if (fire) loop_.post(std::move(fire));
}

void ReactorConnection::async_read(void* buf, std::size_t n, IoCb cb) {
    start_op(true, buf, n, std::move(cb));
}

void ReactorConnection::async_write(const void* buf, std::size_t n, IoCb cb) {
    start_op(false, const_cast<void*>(buf), n, std::move(cb));
}

void ReactorConnection::on_event(uint32_t events) {
    // Runs on a loop thread. EPOLLONESHOT disabled the fd on delivery;
    // whatever stays parked is re-armed below. Error events attempt both
    // ops — the syscall surfaces the real errno (§4.5 §2.1).
    std::function<void()> fire_rd, fire_wr;
    {
        std::lock_guard<std::mutex> lk(op_mu_);
        if ((events & (kEventRead | kEventError)) && rd_.active)
            advance_locked(rd_, true, fire_rd);
        if ((events & (kEventWrite | kEventError)) && wr_.active)
            advance_locked(wr_, false, fire_wr);
        update_interest_locked();
    }
    if (fire_rd) fire_rd();
    if (fire_wr) fire_wr();
}

void ReactorConnection::close() {
    if (closed_.exchange(true)) return;
    // The §4.5 POSIX abort recipe: no blocked syscall exists to interrupt —
    // synthesize the parked ops' aborted completions NOW, exactly once each
    // (op_mu_ serializes against a racing real completion).
    std::function<void()> abort_rd, abort_wr;
    {
        std::lock_guard<std::mutex> lk(op_mu_);
        if (rd_.active) {
            abort_rd = [cb = std::move(rd_.cb), n = rd_.done] {
                cb(make_ec(ECANCELED), n);
            };
            rd_.active = false;
        }
        if (wr_.active) {
            abort_wr = [cb = std::move(wr_.cb), n = wr_.done] {
                cb(make_ec(ECANCELED), n);
            };
            wr_.active = false;
        }
        if (registered_) loop_.deregister(fd_);
        registered_ = false;
    }
    // Kills the TCP conversation AND wakes any thread parked in the sync
    // half's poll() (the FB71 stuck-writer release — free on POSIX).
    ::shutdown(fd_, SHUT_RDWR);
    if (abort_rd) loop_.post(std::move(abort_rd));
    if (abort_wr) loop_.post(std::move(abort_wr));
    // fd deliberately NOT ::close()d here — see the destructor.
}

void ReactorConnection::set_keep_alive(bool on) {
    int v = on ? 1 : 0;
    ::setsockopt(fd_, SOL_SOCKET, SO_KEEPALIVE, &v, sizeof v);
}

bool ReactorConnection::write_all(const void* buf, std::size_t n) {
    const char* p   = static_cast<const char*>(buf);
    std::size_t off = 0;
    while (off < n) {
        if (closed_.load()) return false;
        ssize_t r = ::send(fd_, p + off, n - off, MSG_NOSIGNAL);
        if (r > 0) {
            off += static_cast<std::size_t>(r);
            continue;
        }
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            pollfd pf{};
            pf.fd     = fd_;
            pf.events = POLLOUT;
            uint32_t t  = send_timeout_ms_.load();
            int      pr = ::poll(&pf, 1, t == 0 ? -1 : static_cast<int>(t));
            if (pr == 0) return false;   // stalled past the bound
            if (pr < 0 && errno != EINTR) return false;
            continue;   // ready / woken (a close()'s shutdown lands here as
                        // POLLHUP → the next send errors → false)
        }
        return false;
    }
    return true;
}

void ReactorConnection::set_send_timeout(std::chrono::milliseconds ms) {
    send_timeout_ms_.store(static_cast<uint32_t>(ms.count()));
}

bool ReactorConnection::read_line(std::string& out_line) {
    for (;;) {
        auto nl = carry_.find('\n');
        if (nl != std::string::npos) {
            out_line = carry_.substr(0, nl);
            carry_.erase(0, nl + 1);
            return true;
        }
        if (closed_.load()) return false;
        char buf[4096];
        ssize_t r = ::recv(fd_, buf, sizeof buf, 0);
        if (r > 0) {
            carry_.append(buf, static_cast<std::size_t>(r));
            continue;
        }
        if (r == 0) return false;   // EOF — session ends
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            pollfd pf{};
            pf.fd     = fd_;
            pf.events = POLLIN;
            int pr = ::poll(&pf, 1, -1);   // blocking-recv semantics
            if (pr < 0 && errno != EINTR) return false;
            continue;
        }
        return false;
    }
}

// ── ReactorAcceptor ──────────────────────────────────────────────────────────

// Shared-ptr'd so the loop registry can pin it across a dispatch that races
// ~ReactorAcceptor; `dead` (under mu) makes a stale dispatch a no-op.
struct ReactorAcceptor::State final : ReactorHandler {
    ReactorEventLoop* loop = nullptr;
    int               fd   = -1;
    std::mutex        mu;
    Acceptor::AcceptCb parked;
    bool              dead       = false;
    bool              registered = false;

    void on_event(uint32_t) override {
        Acceptor::AcceptCb cb;
        std::shared_ptr<ReactorConnection> conn;
        std::error_code    ec;
        {
            std::lock_guard<std::mutex> lk(mu);
            if (dead || !parked) return;   // spurious / already-torn-down
            sockaddr_in peer{};
            socklen_t   plen = sizeof peer;
            int nfd = ::accept(fd, reinterpret_cast<sockaddr*>(&peer), &plen);
            if (nfd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK ||
                    errno == EINTR || errno == ECONNABORTED) {
                    // Not a real arrival — stay parked, re-arm the one-shot.
                    loop->arm(fd, kEventRead, shared_from_this_state());
                    return;
                }
                ec = make_ec(errno);
                cb = std::move(parked);
                parked = nullptr;
            } else {
                cb = std::move(parked);
                parked = nullptr;
                conn = std::make_shared<ReactorConnection>(
                    *loop, nfd, format_endpoint(peer));
            }
        }
        cb(ec, std::move(conn));
    }

    // enable_shared_from_this on a nested struct held via shared_ptr<State>:
    // the registry stores shared_ptr<ReactorHandler>, so keep one weak self
    // reference instead of the full base class.
    std::weak_ptr<State> weak_self;
    std::shared_ptr<ReactorHandler> shared_from_this_state() {
        return weak_self.lock();
    }
};

ReactorAcceptor::ReactorAcceptor(ReactorEventLoop& loop, uint16_t port,
                                 bool localhost_only)
    : loop_(loop) {
    int fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) throw std::runtime_error("ReactorAcceptor: socket failed");

    // Behavior parity with AsioAcceptor's reuse_address default (§4.5
    // risk 7 — on POSIX this is also what makes restart-racing-TIME_WAIT
    // rebinds work at all).
    int reuse = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof reuse);

    sockaddr_in sa{};
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr.s_addr = htonl(localhost_only ? INADDR_LOOPBACK : INADDR_ANY);
    if (::bind(fd, reinterpret_cast<const sockaddr*>(&sa), sizeof sa) != 0) {
        ::close(fd);
        throw std::runtime_error("ReactorAcceptor: bind failed on port " +
                                 std::to_string(port));
    }
    sockaddr_in bound{};
    socklen_t   blen = sizeof bound;
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &blen) == 0)
        local_port_ = ntohs(bound.sin_port);
    if (::listen(fd, SOMAXCONN) != 0) {
        ::close(fd);
        throw std::runtime_error("ReactorAcceptor: listen failed");
    }
    if (!set_nonblocking(fd)) {
        ::close(fd);
        throw std::runtime_error("ReactorAcceptor: O_NONBLOCK failed");
    }

    listen_fd_        = fd;
    state_            = std::make_shared<State>();
    state_->loop      = &loop_;
    state_->fd        = fd;
    state_->weak_self = state_;
}

ReactorAcceptor::~ReactorAcceptor() {
    {
        std::lock_guard<std::mutex> lk(state_->mu);
        state_->dead   = true;
        state_->parked = nullptr;   // dropped, never invoked (header contract)
    }
    if (state_->registered) loop_.deregister(listen_fd_);
    ::close(listen_fd_);
}

void ReactorAcceptor::async_accept(AcceptCb cb) {
    {
        std::lock_guard<std::mutex> lk(state_->mu);
        state_->parked     = std::move(cb);
        state_->registered = true;
    }
    loop_.arm(listen_fd_, kEventRead,
              std::static_pointer_cast<ReactorHandler>(state_));
}

// ── ReactorTransport ─────────────────────────────────────────────────────────

ReactorTransport::~ReactorTransport() {
    std::lock_guard<std::mutex> lk(connects_mu_);
    for (auto& pc : connects_)
        if (pc.thread.joinable()) pc.thread.join();
    connects_.clear();
}

void ReactorTransport::reap_finished_connects() {
    for (auto it = connects_.begin(); it != connects_.end();) {
        if (it->done->load()) {
            if (it->thread.joinable()) it->thread.join();
            it = connects_.erase(it);
        } else {
            ++it;
        }
    }
}

std::unique_ptr<Acceptor> ReactorTransport::listen(uint16_t port,
                                                   bool localhost_only) {
    return std::make_unique<ReactorAcceptor>(loop_, port, localhost_only);
}

void ReactorTransport::async_connect(const std::string& host, uint16_t port,
                                     ConnectCb cb) {
    ReactorEventLoop* loop = &loop_;
    auto done = std::make_shared<std::atomic<bool>>(false);
    std::thread helper([loop, host, port, cb = std::move(cb),
                        done]() mutable {
        addrinfo hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfo* res = nullptr;
        int rc = ::getaddrinfo(host.c_str(), std::to_string(port).c_str(),
                               &hints, &res);
        if (rc != 0 || !res) {
            loop->post([cb = std::move(cb)] {
                cb(make_ec(EHOSTUNREACH), nullptr);
            });
            done->store(true);
            return;
        }
        int         fd       = -1;
        std::string endpoint = "unknown";
        int         last_err = ECONNREFUSED;
        for (addrinfo* ai = res; ai; ai = ai->ai_next) {
            int c = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (c < 0) {
                last_err = errno;
                continue;
            }
            if (::connect(c, ai->ai_addr, ai->ai_addrlen) == 0) {
                fd = c;
                if (ai->ai_addrlen >= sizeof(sockaddr_in))
                    endpoint = format_endpoint(
                        *reinterpret_cast<const sockaddr_in*>(ai->ai_addr));
                break;
            }
            last_err = errno;
            ::close(c);
        }
        ::freeaddrinfo(res);
        if (fd < 0) {
            loop->post([cb = std::move(cb), last_err] {
                cb(make_ec(last_err), nullptr);
            });
            done->store(true);
            return;
        }
        auto conn = std::make_shared<ReactorConnection>(*loop, fd,
                                                        std::move(endpoint));
        loop->post([cb = std::move(cb), conn]() mutable {
            cb({}, std::move(conn));
        });
        done->store(true);
    });
    std::lock_guard<std::mutex> lk(connects_mu_);
    reap_finished_connects();
    connects_.push_back({std::move(helper), std::move(done)});
}

} // namespace determ::net

#endif // !_WIN32
