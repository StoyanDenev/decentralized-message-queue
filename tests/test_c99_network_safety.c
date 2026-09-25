/* SPDX-License-Identifier: Apache-2.0
 * Receiver-lifetime regressions for the hosted C99 networking implementation.
 * Tests run through ci_local; no claim about a freestanding production node.
 */
#define _POSIX_C_SOURCE 200809L
#include <determ/net/reactor.h>
#include <determ/net/peer_mesh.h>
#include <determ/net/k2_net.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "NETWORK_SAFETY_ASSERT: %s at %s:%d\n", #c, __FILE__, __LINE__); \
    exit(1); \
} } while (0)

/* A hang is a failed assertion, not an infrastructure timeout: a reentrant loop
 * that spins must be reported with the marker and exit status 1. Only
 * async-signal-safe calls run in the handler. */
static const char *watchdog_what = "";
static void watchdog_fired(int sig) {
    static const char prefix[] = "NETWORK_SAFETY_ASSERT: watchdog: ";
    (void)sig;
    if (write(2, prefix, sizeof(prefix) - 1) < 0) { /* reported by exit status */ }
    if (write(2, watchdog_what, strlen(watchdog_what)) < 0) { /* same */ }
    if (write(2, "\n", 1) < 0) { /* same */ }
    _exit(1);
}
static void arm_watchdog(const char *what, unsigned seconds) {
    watchdog_what = what;
    CHECK(signal(SIGALRM, watchdog_fired) != SIG_ERR);
    alarm(seconds);
}
static void disarm_watchdog(void) { alarm(0); }

static reactor_t reactor;
static peer_mesh_t mesh;
static unsigned reads, close_calls, replaced;
static int replacement[2], old_fd;
static uintptr_t old_registration;
static uint16_t mesh_port;
static int replace_on_message;
static volatile sig_atomic_t sigpipe_count;

/* Compile the real reactor/mesh once in this harness. Test-only copy adapters
 * catch a removed length/lifetime guard before it becomes undefined behavior;
 * ordinary peer-mesh and node tests retain the real libc operations. */
static void *network_checked_memcpy(void *dst, const void *src, size_t len) {
    uintptr_t d = (uintptr_t)dst;
    CHECK(len <= PEER_MESH_RX_BUF_SIZE);
    for (size_t i = 0; i < REACTOR_MAX_SOCKETS; i++) {
        uintptr_t start = (uintptr_t)reactor.slots[i].tx_buf;
        if (d >= start && d - start <= REACTOR_BUFFER_CAPACITY)
            CHECK(len <= REACTOR_BUFFER_CAPACITY - (d - start));
    }
    return memcpy(dst, src, len);
}

static void *network_checked_memmove(void *dst, const void *src, size_t len) {
    CHECK(len <= PEER_MESH_RX_BUF_SIZE);
    return memmove(dst, src, len);
}

/* Registration failure injection for the included sources only; the event loop
 * itself is the real library object. */
static int fail_loop_add, failed_add_fd = -1;
static int injected_loop_add(net_event_loop_t *loop, int fd, uint32_t events, void *user_data) {
    if (fail_loop_add) { failed_add_fd = fd; return -1; }
    return net_event_loop_add(loop, fd, events, user_data);
}

#undef memcpy
#undef memmove
#define memcpy network_checked_memcpy
#define memmove network_checked_memmove
#define net_event_loop_add injected_loop_add
#include "../src/net/reactor.c"
#include "../src/net/peer_mesh.c"
#undef memcpy
#undef memmove
#undef net_event_loop_add

static void tcp_pair(int pair[2]) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    CHECK(listen(listener, 1) == 0);
    CHECK(getsockname(listener, (struct sockaddr *)&addr, &addr_len) == 0);
    pair[1] = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(pair[1] >= 0);
    CHECK(connect(pair[1], (struct sockaddr *)&addr, sizeof(addr)) == 0);
    pair[0] = accept(listener, NULL, NULL);
    CHECK(pair[0] >= 0);
    close(listener);
}

static void count_read(int fd, const uint8_t *data, size_t len, void *user) {
    (void)fd; (void)data; (void)len; (void)user;
    reads++;
}

static void recursive_close(int fd, void *user) {
    (void)user;
    close_calls++;
    CHECK(close_calls == 1);
    CHECK(reactor.slots[0].state == REACTOR_SLOT_UNUSED);
    CHECK(reactor.active_count == 0);
    CHECK(reactor_step(&reactor, 0) < 0);
    CHECK(reactor_init(&reactor) < 0);
    CHECK(!reactor.running);
    arm_watchdog("reactor_run from on_close must return, not spin", 10);
    reactor_run(&reactor);
    disarm_watchdog();
    CHECK(!reactor.running);
    reactor_close_fd(&reactor, fd);
    /* fd number and slot both reused while the outer close callback runs. */
    CHECK(dup2(replacement[0], fd) == fd);
    if (replacement[0] != fd) close(replacement[0]);
    replacement[0] = fd;
    CHECK(reactor_register_client(&reactor, fd, count_read, NULL, NULL) == 0);
}

static void replace_read(int fd, const uint8_t *data, size_t len, void *user) {
    (void)data; (void)len; (void)user;
    CHECK(reactor_step(&reactor, 0) < 0);
    CHECK(reactor_init(&reactor) < 0);
    CHECK(!reactor.running);
    arm_watchdog("reactor_run from on_read must return, not spin", 10);
    reactor_run(&reactor);
    disarm_watchdog();
    CHECK(!reactor.running);
    reactor_close_fd(&reactor, fd);
    CHECK(dup2(replacement[0], fd) == fd);
    if (replacement[0] != fd) close(replacement[0]);
    replacement[0] = fd;
    CHECK(reactor_register_client(&reactor, fd, count_read, NULL, NULL) == 0);
    /* The old callback must not read or flush this replacement in its old event. */
    reactor.slots[0].tx_buf[0] = 0x5a;
    reactor.slots[0].tx_len = 1;
    replaced++;
}

static void test_reactor_lifetimes(void) {
    int pair[2];
    CHECK(reactor_init(&reactor) == 0);
    tcp_pair(pair);
    tcp_pair(replacement);
    CHECK(reactor_register_client(&reactor, pair[0], replace_read, NULL, NULL) == 0);
    CHECK(reactor_register_client(&reactor, pair[0], count_read, NULL, NULL) < 0);
    CHECK(reactor.active_count == 1);
    old_registration = reactor.slots[0].registration;
    CHECK(net_event_loop_mod(&reactor.loop, pair[0], NET_EV_READ | NET_EV_WRITE,
                              (void *)old_registration) == 0);
    CHECK(write(pair[1], "a", 1) == 1);
    CHECK(write(replacement[1], "b", 1) == 1);
    {
        /* The first step must see READ and WRITE together; wait for delivery. */
        struct pollfd ready;
        ready.fd = pair[0]; ready.events = POLLIN; ready.revents = 0;
        CHECK(poll(&ready, 1, 2000) == 1 && (ready.revents & POLLIN));
    }
    reads = 0; replaced = 0;
    for (unsigned n = 0; n < 20 && !replaced; n++) CHECK(reactor_step(&reactor, 100) >= 0);
    CHECK(replaced == 1);
    CHECK(reads == 0);
    CHECK(reactor.slots[0].tx_len == 1);
    CHECK(reactor.slots[0].registration != old_registration);
    /* Emulate an already queued OS event bearing the retired registration;
     * its descriptor number and slot now both name the replacement. */
    CHECK(net_event_loop_mod(&reactor.loop, replacement[0], NET_EV_READ,
                              (void *)old_registration) == 0);
    CHECK(reactor_step(&reactor, 100) > 0);
    CHECK(reads == 0);
    CHECK(reactor.slots[0].state == REACTOR_SLOT_CONNECTED);
    CHECK(net_event_loop_mod(&reactor.loop, replacement[0], NET_EV_READ,
                              (void *)reactor.slots[0].registration) == 0);
    CHECK(reactor_step(&reactor, 100) > 0);
    CHECK(reads == 1);
    reactor_destroy(&reactor);
    close(pair[1]); close(replacement[1]);

    CHECK(reactor_init(&reactor) == 0);
    tcp_pair(pair); tcp_pair(replacement);
    close_calls = 0;
    CHECK(reactor_register_client(&reactor, pair[0], NULL, recursive_close, NULL) == 0);
    old_registration = reactor.slots[0].registration;
    reactor_close_fd(&reactor, pair[0]);
    CHECK(close_calls == 1 && reactor.active_count == 1);
    CHECK(reactor.slots[0].registration != old_registration);
    CHECK(fcntl(replacement[0], F_GETFD) >= 0);
    reactor_destroy(&reactor);
    close(pair[1]); close(replacement[1]);
}

static void test_reactor_capacity(void) {
    int pair[2];
    uint8_t data[2] = {1, 2};
    static uint8_t oversized[REACTOR_BUFFER_CAPACITY + 1U];
    CHECK(reactor_init(&reactor) == 0);
    tcp_pair(pair);
    CHECK(reactor_register_client(&reactor, pair[0], NULL, NULL, NULL) == 0);
    /* With an empty queue the kernel would take the whole oversized request;
     * the API bound must reject it before any byte is written. */
    CHECK(reactor_send(&reactor, pair[0], oversized, sizeof(oversized)) < 0);
    CHECK(reactor.slots[0].tx_len == 0);
    {
        /* Nothing reached the peer (poll(2) is portable; MSG_DONTWAIT is not). */
        struct pollfd nothing;
        nothing.fd = pair[1]; nothing.events = POLLIN; nothing.revents = 0;
        CHECK(poll(&nothing, 1, 50) == 0);
    }
    reactor.slots[0].tx_len = REACTOR_BUFFER_CAPACITY - 1U;
    CHECK(reactor_send(&reactor, pair[0], data, 2) < 0);
    CHECK(reactor_send(&reactor, pair[0], data, SIZE_MAX) < 0);
    CHECK(reactor.slots[0].tx_len == REACTOR_BUFFER_CAPACITY - 1U);
    CHECK(reactor_send(&reactor, pair[0], data, 1) == 1);
    CHECK(reactor.slots[0].tx_len == REACTOR_BUFFER_CAPACITY);
    CHECK(reactor_send(&reactor, pair[0], data, 1) < 0);
    reactor_close_fd(&reactor, pair[0]); close(pair[1]);
    reactor.next_generation = (UINTPTR_MAX >> 8U);
    tcp_pair(pair);
    CHECK(reactor_register_client(&reactor, pair[0], NULL, NULL, NULL) < 0);
    CHECK(reactor.active_count == 0);
    CHECK(reactor.next_generation == (UINTPTR_MAX >> 8U));
    close(pair[0]); close(pair[1]);
    reactor_destroy(&reactor);
}

static void replace_peer(peer_mesh_t *m, int index) {
    peer_mesh_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    CHECK(peer_mesh_poll(m, 0) < 0);
    CHECK(peer_mesh_init(m, &cfg) < 0);
    old_fd = m->peers[index].fd;
    old_registration = m->peers[index].registration;
    peer_mesh_disconnect(m, index);
    CHECK(peer_mesh_connect(m, "127.0.0.1", mesh_port) == index);
    CHECK(m->peers[index].fd == old_fd);
    CHECK(m->peers[index].registration != old_registration);
    replaced++;
}

static void on_mesh_connect(peer_mesh_t *m, int index, void *user) {
    (void)user;
    if (!replace_on_message && !replaced) replace_peer(m, index);
}

static void on_mesh_message(peer_mesh_t *m, int index, const wire_envelope_t *env, void *user) {
    (void)env; (void)user;
    if (replace_on_message && !replaced) replace_peer(m, index);
}

static int start_mesh(void) {
    peer_mesh_config_t cfg;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    memset(&cfg, 0, sizeof(cfg));
    cfg.on_connect = on_mesh_connect;
    cfg.on_message = on_mesh_message;
    CHECK(peer_mesh_init(&mesh, &cfg) == 0);
    CHECK(peer_mesh_listen(&mesh, 0) == 0);
    CHECK(getsockname(mesh.listen_fd, (struct sockaddr *)&addr, &addr_len) == 0);
    mesh_port = ntohs(addr.sin_port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    CHECK(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    return fd;
}

static void send_envelope(int fd, uint8_t type, const uint8_t *payload, size_t len) {
    uint8_t frame[1024];
    size_t env_len = 0;
    CHECK(wire_envelope_encode(frame + 4, sizeof(frame) - 4, type, payload, len, &env_len) == WIRE_CODEC_OK);
    frame[0] = (uint8_t)(env_len >> 24); frame[1] = (uint8_t)(env_len >> 16);
    frame[2] = (uint8_t)(env_len >> 8); frame[3] = (uint8_t)env_len;
    CHECK(write(fd, frame, env_len + 4) == (ssize_t)(env_len + 4));
}

static void test_mesh_callback_lifetimes(void) {
    uint8_t hello[256];
    size_t hello_len = 0;
    wire_hello_t h = {"peer", 4, 1, 0, 0, 1};
    CHECK(wire_hello_encode(hello, sizeof(hello), &h, &hello_len) == WIRE_CODEC_OK);
    for (replace_on_message = 0; replace_on_message <= 1; replace_on_message++) {
        int fd = start_mesh();
        replaced = 0;
        send_envelope(fd, WIRE_MSG_HELLO, hello, hello_len);
        if (replace_on_message) send_envelope(fd, WIRE_MSG_TRANSACTION, hello, hello_len);
        for (unsigned n = 0; n < 20 && !replaced; n++) CHECK(peer_mesh_poll(&mesh, 100) >= 0);
        CHECK(replaced == 1);
        CHECK(mesh.peers[0].rx_cursor == 0);
        CHECK(mesh.peers[0].state != PEER_STATE_FREE);
        /* Retired cookie must not disconnect its replacement on EOF. */
        CHECK(net_event_loop_mod(&mesh.loop, mesh.peers[0].fd, NET_EV_READ,
                                  (void *)old_registration) == 0);
        CHECK(shutdown(mesh.peers[0].fd, SHUT_RDWR) == 0);
        CHECK(peer_mesh_poll(&mesh, 100) >= 0);
        CHECK(mesh.peers[0].state != PEER_STATE_FREE);
        peer_mesh_close(&mesh); close(fd);
    }
}

static int reconnect_attempt;
static void no_resurrection(peer_mesh_t *m, int index, void *user) {
    (void)index; (void)user;
    reconnect_attempt++;
    CHECK(peer_mesh_connect(m, "127.0.0.1", mesh_port) < 0);
    CHECK(peer_mesh_listen(m, 0) < 0);
}

static void test_mesh_failed_init(void) {
    peer_mesh_config_t cfg;
    /* Occupy descriptor 0 with a probe so that a stray close(0) is observable. */
    int saved_stdin = dup(0);
    int fd = open("/dev/null", O_RDONLY);
    CHECK(fd >= 0);
    CHECK(dup2(fd, 0) == 0);
    memset(&mesh, 0, sizeof(mesh));
    CHECK(peer_mesh_init(&mesh, NULL) < 0);
    CHECK(mesh.loop.poll_fd == -1 && mesh.listen_fd == -1);
    peer_mesh_close(&mesh);
    CHECK(fcntl(0, F_GETFD) >= 0);
    memset(&cfg, 0, sizeof(cfg));
    memset(cfg.domain, 'x', sizeof(cfg.domain));
    CHECK(peer_mesh_init(&mesh, &cfg) < 0);
    CHECK(mesh.loop.poll_fd == -1 && mesh.listen_fd == -1);
    peer_mesh_close(&mesh);
    CHECK(fcntl(0, F_GETFD) >= 0);
    if (saved_stdin >= 0) { CHECK(dup2(saved_stdin, 0) == 0); close(saved_stdin); }
    else close(0);
    close(fd);
}

static unsigned disconnect_calls;
static void count_disconnect(peer_mesh_t *m, int index, void *user) {
    (void)m; (void)index; (void)user;
    disconnect_calls++;
}

/* A failed connect returns an error and releases the slot without announcing a
 * disconnect for an index the caller never received. */
static void test_mesh_connect_failure(void) {
    int fd = start_mesh();
    /* The lowest free descriptor is the one the failing connect will take:
     * after the failure it must be closed again, not leaked. */
    int probe = open("/dev/null", O_RDONLY);
    CHECK(probe >= 0);
    close(probe);
    mesh.config.on_disconnect = count_disconnect;
    disconnect_calls = 0;
    fail_loop_add = 1;
    failed_add_fd = -1;
    CHECK(peer_mesh_connect(&mesh, "127.0.0.1", mesh_port) < 0);
    fail_loop_add = 0;
    CHECK(failed_add_fd == probe); /* the probe named the connect's descriptor */
    CHECK(disconnect_calls == 0);
    CHECK(fcntl(probe, F_GETFD) < 0 && errno == EBADF);
    /* An unparsable address fails after socket(): that descriptor is closed too. */
    probe = open("/dev/null", O_RDONLY);
    CHECK(probe >= 0);
    close(probe);
    CHECK(peer_mesh_connect(&mesh, "not-an-address", mesh_port) == -4);
    CHECK(fcntl(probe, F_GETFD) < 0 && errno == EBADF);
    CHECK(disconnect_calls == 0);
    for (unsigned i = 0; i < PEER_MESH_MAX_PEERS; i++) {
        CHECK(mesh.peers[i].state == PEER_STATE_FREE);
        CHECK(mesh.peers[i].fd == -1);
    }
    mesh.config.on_disconnect = NULL;
    peer_mesh_close(&mesh);
    close(fd);
}

static void test_mesh_exhaustion_and_close(void) {
    int fd = start_mesh();
    CHECK(peer_mesh_poll(&mesh, 100) > 0);
    CHECK(mesh.peers[0].state != PEER_STATE_FREE);
    mesh.next_generation = (UINTPTR_MAX >> 8U);
    CHECK(peer_mesh_connect(&mesh, "127.0.0.1", mesh_port) < 0);
    CHECK(mesh.next_generation == (UINTPTR_MAX >> 8U));
    mesh.config.on_disconnect = no_resurrection;
    reconnect_attempt = 0;
    peer_mesh_close(&mesh);
    CHECK(reconnect_attempt == 1);
    CHECK(mesh.loop.poll_fd == -1 && mesh.listen_fd == -1);
    for (unsigned i = 0; i < PEER_MESH_MAX_PEERS; i++) CHECK(mesh.peers[i].fd == -1);
    peer_mesh_close(&mesh);
    close(fd);
}

static void caught_sigpipe(int sig) { (void)sig; sigpipe_count++; }
static void test_sigpipe(void) {
    int pair[2];
    uint8_t data = 0;
    CHECK(signal(SIGPIPE, caught_sigpipe) != SIG_ERR);
    sigpipe_count = 0;
    CHECK(reactor_init(&reactor) == 0);
    tcp_pair(pair);
    CHECK(reactor_register_client(&reactor, pair[0], NULL, NULL, NULL) == 0);
    CHECK(shutdown(pair[0], SHUT_WR) == 0);
    CHECK(reactor_send(&reactor, pair[0], &data, 1) < 0);
    CHECK(sigpipe_count == 0);
    reactor_destroy(&reactor); close(pair[1]);

    /* The queued-flush path (handle_client_write) must use the same protected
     * send as the direct path. Queue a remainder, then break the pipe locally. */
    CHECK(reactor_init(&reactor) == 0);
    tcp_pair(pair);
    CHECK(reactor_register_client(&reactor, pair[0], NULL, NULL, NULL) == 0);
    reactor.slots[0].tx_buf[0] = 1;
    reactor.slots[0].tx_len = 1;
    reactor.slots[0].registered_events |= NET_EV_WRITE;
    CHECK(net_event_loop_mod(&reactor.loop, pair[0], reactor.slots[0].registered_events,
                              (void *)reactor.slots[0].registration) == 0);
    CHECK(shutdown(pair[0], SHUT_WR) == 0);
    for (unsigned n = 0; n < 20 && reactor.slots[0].state != REACTOR_SLOT_UNUSED; n++)
        CHECK(reactor_step(&reactor, 100) >= 0);
    CHECK(reactor.slots[0].state == REACTOR_SLOT_UNUSED); /* EPIPE closed the slot */
    CHECK(sigpipe_count == 0);
    reactor_destroy(&reactor); close(pair[1]);

    int fd = start_mesh();
    CHECK(peer_mesh_poll(&mesh, 100) > 0); /* accept + queue HELLO */
    CHECK(mesh.peers[0].tx_len > 0);
    CHECK(shutdown(mesh.peers[0].fd, SHUT_WR) == 0);
    /* kqueue may report EOF before WRITE, so poll alone can skip the send.
     * Exercise the real mesh send boundary before that EOF short circuit. */
    CHECK(peer_socket_send(mesh.peers[0].fd, &data, 1) < 0);
    CHECK(sigpipe_count == 0);
    CHECK(peer_mesh_poll(&mesh, 100) >= 0);
    CHECK(sigpipe_count == 0);
    CHECK(mesh.peers[0].state == PEER_STATE_FREE);
    peer_mesh_close(&mesh); close(fd);
    CHECK(signal(SIGPIPE, SIG_DFL) != SIG_ERR);
}

static void test_k2_close(void) {
    k2_aggregator_t agg;
    k2_contributor_t cont;
    /* A connected contributor refuses a second connect: the first descriptor is
     * neither leaked nor replaced under the loop's registration token. */
    {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        int listener = socket(AF_INET, SOCK_STREAM, 0);
        CHECK(listener >= 0);
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        CHECK(bind(listener, (struct sockaddr *)&addr, sizeof(addr)) == 0);
        CHECK(listen(listener, 4) == 0);
        CHECK(getsockname(listener, (struct sockaddr *)&addr, &addr_len) == 0);
        CHECK(k2_contributor_init(&cont) == 0);
        CHECK(k2_contributor_connect(&cont, "127.0.0.1", ntohs(addr.sin_port)) == 0);
        int first = cont.conn.fd;
        CHECK(first >= 0 && cont.conn.connected);
        CHECK(k2_contributor_connect(&cont, "127.0.0.1", ntohs(addr.sin_port)) < 0);
        CHECK(cont.conn.fd == first && cont.conn.connected);
        k2_contributor_close(&cont);
        CHECK(cont.conn.fd == -1);
        close(listener);
    }
    CHECK(k2_aggregator_init(&agg, 0) == 0);
    k2_aggregator_close(&agg);
    CHECK(agg.listen_fd == -1 && agg.peer.fd == -1 && agg.loop.poll_fd == -1);
    k2_aggregator_close(&agg);
    CHECK(k2_contributor_init(&cont) == 0);
    k2_contributor_close(&cont);
    CHECK(cont.conn.fd == -1 && cont.loop.poll_fd == -1);
    k2_contributor_close(&cont);
    CHECK(k2_contributor_connect(&cont, "127.0.0.1", 1) < 0);
}

int main(void) {
    test_reactor_lifetimes();
    test_reactor_capacity();
    test_mesh_callback_lifetimes();
    test_mesh_failed_init();
    test_mesh_connect_failure();
    test_mesh_exhaustion_and_close();
    test_sigpipe();
    test_k2_close();
    puts("PASS: C99 network lifetime, capacity, and descriptor regressions");
    return 0;
}
