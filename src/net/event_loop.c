/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Determ Contributors
 *
 * Core Zero-Dependency C99 Non-Blocking Event Loop.
 * Strictly zero dynamic memory allocations.
 * Native OS Multiplexer:
 *   #if defined(__linux__) -> epoll
 *   #elif defined(__APPLE__) -> kqueue
 *   #elif defined(_WIN32) -> select() fallback
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <determ/net/virtual_transport.h>
#include <determ/net/event_loop.h>

#if defined(__linux__)
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#define NET_USE_EPOLL 1
#include <sys/epoll.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#define NET_USE_KQUEUE 1
#include <sys/event.h>
#include <sys/time.h>
#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#define NET_USE_SELECT 1
#define close(s) closesocket(s)
#define EWOULDBLOCK WSAEWOULDBLOCK
#define EAGAIN WSAEWOULDBLOCK
#define EINTR WSAEINTR
#define errno WSAGetLastError()
typedef int socklen_t;
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#define NET_USE_SELECT 1
#include <sys/select.h>
#endif

int net_event_loop_init(net_event_loop_t *loop) {
    if (!loop) {
        return -1;
    }
    memset(loop, 0, sizeof(*loop));

#if defined(NET_USE_KQUEUE)
    loop->poll_fd = kqueue();
    if (loop->poll_fd < 0) {
        return -1;
    }
#elif defined(NET_USE_EPOLL)
    loop->poll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (loop->poll_fd < 0) {
        return -1;
    }
#else
    loop->poll_fd = 0;
#endif

    loop->running = true;
    return 0;
}

int net_event_loop_add(net_event_loop_t *loop, int fd, uint32_t events, void *user_data) {
    if (!loop || loop->poll_fd < 0 || fd < 0) {
        return -1;
    }

#if defined(NET_USE_KQUEUE)
    struct kevent kev[2];
    int n = 0;

    if (events & NET_EV_READ) {
        EV_SET(&kev[n], (uintptr_t)fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, user_data);
        n++;
    }
    if (events & NET_EV_WRITE) {
        EV_SET(&kev[n], (uintptr_t)fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, user_data);
        n++;
    }
    if (n > 0) {
        if (kevent(loop->poll_fd, kev, n, NULL, 0, NULL) < 0) {
            return -1;
        }
    }
    return 0;
#elif defined(NET_USE_EPOLL)
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.data.ptr = user_data;

    if (events & NET_EV_READ)  ev.events |= EPOLLIN;
    if (events & NET_EV_WRITE) ev.events |= EPOLLOUT;
    ev.events |= EPOLLERR | EPOLLHUP | EPOLLET;

    return epoll_ctl(loop->poll_fd, EPOLL_CTL_ADD, fd, &ev);
#elif defined(NET_USE_SELECT)
    (void)events; (void)user_data;
    return 0;
#else
    (void)events; (void)user_data;
    return 0;
#endif
}

int net_event_loop_mod(net_event_loop_t *loop, int fd, uint32_t events, void *user_data) {
    if (!loop || loop->poll_fd < 0 || fd < 0) {
        return -1;
    }

#if defined(NET_USE_KQUEUE)
    return net_event_loop_add(loop, fd, events, user_data);
#elif defined(NET_USE_EPOLL)
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.data.ptr = user_data;

    if (events & NET_EV_READ)  ev.events |= EPOLLIN;
    if (events & NET_EV_WRITE) ev.events |= EPOLLOUT;
    ev.events |= EPOLLERR | EPOLLHUP;

    return epoll_ctl(loop->poll_fd, EPOLL_CTL_MOD, fd, &ev);
#else
    (void)events; (void)user_data;
    return 0;
#endif
}

int net_event_loop_del(net_event_loop_t *loop, int fd) {
    if (!loop || loop->poll_fd < 0 || fd < 0) {
        return -1;
    }

#if defined(NET_USE_KQUEUE)
    struct kevent kev[2];
    EV_SET(&kev[0], (uintptr_t)fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
    EV_SET(&kev[1], (uintptr_t)fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    (void)kevent(loop->poll_fd, kev, 2, NULL, 0, NULL);
    return 0;
#elif defined(NET_USE_EPOLL)
    return epoll_ctl(loop->poll_fd, EPOLL_CTL_DEL, fd, NULL);
#else
    return 0;
#endif
}

int net_event_loop_poll(net_event_loop_t *loop, int timeout_ms,
                        net_event_t *out_events, int max_events) {
    if (!loop || loop->poll_fd < 0 || !out_events || max_events <= 0) {
        return -1;
    }

#if defined(DETERM_DSF_ENABLED)
    int v_count = determ_dsf_poll_hook(loop, out_events, max_events);
    if (v_count > 0) {
        return v_count;
    }
#endif

#if defined(NET_USE_KQUEUE)
    struct kevent event_list[NET_MAX_EVENTS_PER_POLL];
    int cap = (max_events < NET_MAX_EVENTS_PER_POLL) ? max_events : NET_MAX_EVENTS_PER_POLL;

    struct timespec ts;
    struct timespec *pts = NULL;
    if (timeout_ms >= 0) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
        pts = &ts;
    }

    int nev = kevent(loop->poll_fd, NULL, 0, event_list, cap, pts);
    if (nev < 0) {
        if (errno == EINTR) {
            return 0;
        }
        return -1;
    }

    for (int i = 0; i < nev; ++i) {
        out_events[i].fd = (int)event_list[i].ident;
        out_events[i].flags = 0;
        out_events[i].user_data = event_list[i].udata;

        if (event_list[i].filter == EVFILT_READ) {
            out_events[i].flags |= NET_EV_READ;
        }
        if (event_list[i].filter == EVFILT_WRITE) {
            out_events[i].flags |= NET_EV_WRITE;
        }
        if (event_list[i].flags & EV_EOF) {
            out_events[i].flags |= NET_EV_EOF;
        }
        if (event_list[i].flags & EV_ERROR) {
            out_events[i].flags |= NET_EV_ERROR;
        }
    }
    return nev;

#elif defined(NET_USE_EPOLL)
    struct epoll_event event_list[NET_MAX_EVENTS_PER_POLL];
    int cap = (max_events < NET_MAX_EVENTS_PER_POLL) ? max_events : NET_MAX_EVENTS_PER_POLL;

    int nev = epoll_wait(loop->poll_fd, event_list, cap, timeout_ms);
    if (nev < 0) {
        if (errno == EINTR) {
            return 0;
        }
        return -1;
    }

    for (int i = 0; i < nev; ++i) {
        out_events[i].fd = -1;
        out_events[i].flags = 0;
        out_events[i].user_data = event_list[i].data.ptr;

        if (event_list[i].events & EPOLLIN)  out_events[i].flags |= NET_EV_READ;
        if (event_list[i].events & EPOLLOUT) out_events[i].flags |= NET_EV_WRITE;
        if (event_list[i].events & EPOLLERR) out_events[i].flags |= NET_EV_ERROR;
        if (event_list[i].events & (EPOLLHUP | EPOLLRDHUP)) out_events[i].flags |= NET_EV_EOF;
    }
    return nev;

#elif defined(NET_USE_SELECT)
    struct timeval tv;
    struct timeval *ptv = NULL;
    if (timeout_ms >= 0) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (long)(timeout_ms % 1000) * 1000L;
        ptv = &tv;
    }
    fd_set rfds, wfds, efds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    int res = select(0, &rfds, &wfds, &efds, ptv);
    if (res < 0) {
        if (errno == EINTR) return 0;
        return -1;
    }
    return 0;
#else
    return 0;
#endif
}

void net_event_loop_stop(net_event_loop_t *loop) {
    if (loop) {
        loop->running = false;
    }
}

void net_event_loop_close(net_event_loop_t *loop) {
    if (loop && loop->poll_fd >= 0) {
#if defined(_WIN32)
        closesocket((SOCKET)loop->poll_fd);
#else
        close(loop->poll_fd);
#endif
        loop->poll_fd = -1;
        loop->running = false;
    }
}

int net_socket_set_nonblocking(int fd) {
    if (fd < 0) return -1;
#if defined(_WIN32)
    u_long mode = 1;
    return ioctlsocket((SOCKET)fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

int net_socket_set_reuseaddr(int fd) {
    if (fd < 0) return -1;
    int opt = 1;
#if defined(_WIN32)
    return setsockopt((SOCKET)fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
#else
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, (socklen_t)sizeof(opt));
#endif
}

int net_socket_set_nodelay(int fd) {
    if (fd < 0) return -1;
    int opt = 1;
#if defined(_WIN32)
    return setsockopt((SOCKET)fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&opt, sizeof(opt));
#else
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, (socklen_t)sizeof(opt));
#endif
}
