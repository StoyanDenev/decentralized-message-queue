/* SPDX-License-Identifier: Apache-2.0
 * Exercise HTTP platform failure handling over its actual source, with only
 * the POSIX boundary injected. Signals and oversized memory accesses are never
 * accepted as mutation kills: every failure is ASSERTION FAILED + exit 1.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include <determ/rpc/http_rpc_server.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "ASSERTION FAILED: %s (%s:%d)\n", #x, __FILE__, __LINE__); \
    exit(1); \
} } while (0)

static int fail_nonblocking, fail_sigpipe, pending_accept = -1;
static int send_calls, send_fd, send_flags;
static size_t send_length;
static int injected_fcntl(int fd, int command, ...) {
    if (command == F_GETFL) return fcntl(fd, command);
    CHECK(command == F_SETFL);
    va_list args;
    va_start(args, command);
    int flags = va_arg(args, int);
    va_end(args);
    if (fail_nonblocking) { errno = EIO; return -1; }
    return fcntl(fd, command, flags);
}
static int injected_setsockopt(int fd, int level, int option, const void *value, socklen_t len) {
#ifdef SO_NOSIGPIPE
    if (option == SO_NOSIGPIPE && fail_sigpipe) { errno = EIO; return -1; }
#else
    (void)fail_sigpipe;
#endif
    return setsockopt(fd, level, option, value, len);
}
static ssize_t injected_send(int fd, const void *data, size_t len, int flags) {
    (void)data;
    ++send_calls; send_fd = fd; send_flags = flags; send_length = len;
    errno = EPIPE;
    return -1;
}
static int injected_poll(struct pollfd *fds, nfds_t count, int timeout) {
    (void)timeout;
    for (nfds_t i = 0; i < count; ++i) fds[i].revents = 0;
    if (pending_accept >= 0) fds[0].revents = POLLIN;
    else if (count > 1) fds[1].revents = POLLOUT;
    return pending_accept >= 0 || count > 1 ? 1 : 0;
}
static int injected_accept(int fd, struct sockaddr *addr, socklen_t *len) {
    (void)fd; (void)addr; (void)len;
    int result = pending_accept;
    pending_accept = -1;
    if (result < 0) errno = EAGAIN;
    return result;
}
#define fcntl injected_fcntl
#define setsockopt injected_setsockopt
#define send injected_send
#define poll injected_poll
#define accept injected_accept
#include "../src/rpc/http_rpc_server.c"
#undef fcntl
#undef setsockopt
#undef send
#undef poll
#undef accept

static http_rpc_server_t server;
static void init_server(void) {
    http_rpc_config_t config = {0};
    CHECK(http_rpc_server_init(&server, &config) == 0);
    server.server_fd = open("/dev/null", O_RDONLY);
    CHECK(server.server_fd >= 0);
    fail_nonblocking = fail_sigpipe = send_calls = 0;
    pending_accept = -1;
}
static void test_accept_failure(int option_failure) {
    int pair[2];
    init_server();
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pending_accept = pair[0];
    if (option_failure) fail_sigpipe = 1;
    else fail_nonblocking = 1;
    CHECK(http_rpc_server_poll(&server, 0) == 0);
    for (size_t i = 0; i < HTTP_RPC_MAX_CLIENTS; ++i) {
        CHECK(server.clients[i].state == HTTP_CLIENT_INACTIVE);
        CHECK(server.clients[i].fd == -1);
    }
    CHECK(fcntl(pair[0], F_GETFD) == -1 && errno == EBADF);
    close(pair[1]);
    http_rpc_server_close(&server);
}
static void check_send(int expected_fd, size_t expected_length) {
    CHECK(send_calls == 1 && send_fd == expected_fd && send_length == expected_length);
#ifdef MSG_NOSIGNAL
    CHECK((send_flags & MSG_NOSIGNAL) != 0);
#else
    CHECK(send_flags == 0);
#endif
}
static void test_accepted_and_sending(void) {
    int pair[2];
    init_server();
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pending_accept = pair[0];
    CHECK(http_rpc_server_poll(&server, 0) == 0);
    CHECK(server.clients[0].fd == pair[0]);
    CHECK(server.clients[0].state == HTTP_CLIENT_READING);
    CHECK((fcntl(pair[0], F_GETFL) & O_NONBLOCK) != 0);
#if !defined(MSG_NOSIGNAL) && defined(SO_NOSIGPIPE)
    int no_sigpipe = 0;
    socklen_t len = sizeof(no_sigpipe);
    CHECK(getsockopt(pair[0], SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, &len) == 0);
    CHECK(no_sigpipe == 1);
#endif
    /* Exercise the public poll->response path, not only the send helper. */
    server.clients[0].state = HTTP_CLIENT_SENDING;
    server.clients[0].tx_buf[0] = 'x';
    server.clients[0].tx_len = 1;
    CHECK(http_rpc_server_poll(&server, 0) == 0);
    check_send(pair[0], 1);
    CHECK(server.clients[0].fd == -1 && server.clients[0].state == HTTP_CLIENT_INACTIVE);
    close(pair[1]);
    http_rpc_server_close(&server);
}
static void test_saturated_send(void) {
    int pair[2];
    init_server();
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    for (size_t i = 0; i < HTTP_RPC_MAX_CLIENTS; ++i)
        server.clients[i].state = HTTP_CLIENT_READING;
    pending_accept = pair[0];
    CHECK(http_rpc_server_poll(&server, 0) == 0);
    CHECK(send_calls == 1 && send_fd == pair[0] && send_length > 0);
#ifdef MSG_NOSIGNAL
    CHECK((send_flags & MSG_NOSIGNAL) != 0);
#endif
    CHECK(fcntl(pair[0], F_GETFD) == -1 && errno == EBADF);
    close(pair[1]);
    http_rpc_server_close(&server);
}
int main(void) {
    (void)injected_send; /* Remain buildable when a mutant bypasses send(). */
    test_accept_failure(0);
#if !defined(MSG_NOSIGNAL) && defined(SO_NOSIGPIPE)
    test_accept_failure(1);
#endif
    test_accepted_and_sending();
    test_saturated_send();
    puts("PASS: HTTP accepted descriptor ownership and signal-safe send paths");
    return 0;
}
