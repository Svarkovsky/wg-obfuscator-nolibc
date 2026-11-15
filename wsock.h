/*
 * wsock.h - Freestanding Network, Epoll, Time & Signal Layer over nolibc.h
 * Part of whitehttpd / wg-obfuscator-nolibc
 *
 * Copyright (C) 2024-2026 Ivan Svarkovsky <ivansvarkovsky@gmail.com>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#ifndef WSOCK_H
#define WSOCK_H

#if !defined(_NOLIBC_H) && !defined(NOLIBC)
#include "nolibc.h"
#endif

/* ============================================================================
 * 1. Architecture-Specific Socket, Epoll & Signal Constants (MIPS vs x86_64)
 * ============================================================================
 * On MIPS Linux O32 ABI:
 *   - SOCK_DGRAM is 1, SOCK_STREAM is 2 (reversed from x86!)
 *   - SOL_SOCKET is 0xffff (1 on x86)
 *   - SO_REUSEADDR is 0x0004 (2 on x86)
 *   - SOCK_NONBLOCK is 0x0080 (0x0800 on x86)
 *   - epoll_event is NOT packed on MIPS (16 bytes), packed on x86_64 (12 bytes)
 *   - rt_sigaction sigsetsize is 16 bytes on MIPS (_NSIG=128), 8 on x86_64
 */
#define WS_AF_UNSPEC        0
#define WS_AF_INET          2
#define WS_AF_INET6         10

#define WS_IPPROTO_IP       0
#define WS_IPPROTO_TCP      6
#define WS_IPPROTO_UDP      17
#define WS_IPPROTO_IPV6     41

/* IPPROTO_IP & IPPROTO_IPV6 options */
#define WS_IP_MTU_DISCOVER   10
#define WS_IP_PMTUDISC_DONT  0
#define WS_IP_PMTUDISC_WANT  1
#define WS_IP_PMTUDISC_DO    2

#define WS_IPV6_MTU_DISCOVER 23
#define WS_IPV6_V6ONLY       26

#if defined(__mips__)
#define WS_SOCK_DGRAM       1
#define WS_SOCK_STREAM      2
#define WS_SOL_SOCKET       0xffff
#define WS_SO_REUSEADDR     0x0004
#define WS_SO_BROADCAST     0x0020
#define WS_SO_RCVBUF        0x1002
#define WS_SO_SNDBUF        0x1001
#define WS_SO_MARK          36
#define WS_SOCK_NONBLOCK    0x0080
#define WS_SOCK_CLOEXEC     0x80000
#define WS_O_NONBLOCK       0x0080
#define WS_SIGSETSIZE       16
#define WS_EPOLL_PACKED
#else
#define WS_SOCK_STREAM      1
#define WS_SOCK_DGRAM       2
#define WS_SOL_SOCKET       1
#define WS_SO_REUSEADDR     2
#define WS_SO_BROADCAST     6
#define WS_SO_SNDBUF        7
#define WS_SO_RCVBUF        8
#define WS_SO_MARK          36
#define WS_SOCK_NONBLOCK    0x0800
#define WS_SOCK_CLOEXEC     0x80000
#define WS_O_NONBLOCK       0x0800
#define WS_SIGSETSIZE       8
#define WS_EPOLL_PACKED     __attribute__((packed))
#endif

/* fcntl commands */
#define WS_F_GETFL          3
#define WS_F_SETFL          4

/* recvfrom / sendto flags */
#define WS_MSG_PEEK         0x02
#define WS_MSG_TRUNC        0x20
#define WS_MSG_DONTWAIT     0x40
#define WS_MSG_NOSIGNAL     0x4000

/* Epoll constants */
#define WS_EPOLL_CTL_ADD    1
#define WS_EPOLL_CTL_DEL    2
#define WS_EPOLL_CTL_MOD    3

#define WS_EPOLLIN          0x001
#define WS_EPOLLOUT         0x004
#define WS_EPOLLERR         0x008
#define WS_EPOLLHUP         0x010
#define WS_EPOLLET          (1U << 31)

/* Clock IDs */
#define WS_CLOCK_REALTIME   0
#define WS_CLOCK_MONOTONIC  1

/* ============================================================================
 * 2. Endianness Conversion Macros (nolibc-mips32el / x86_64 vs mips32be)
 * ============================================================================ */
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define ws_htons(x) ((uint16_t)(x))
#define ws_ntohs(x) ((uint16_t)(x))
#define ws_htonl(x) ((uint32_t)(x))
#define ws_ntohl(x) ((uint32_t)(x))
#else
#define ws_htons(x) ((uint16_t)((((uint16_t)(x) & 0x00ffU) << 8) | \
                                (((uint16_t)(x) & 0xff00U) >> 8)))
#define ws_ntohs(x) ws_htons(x)
#define ws_htonl(x) ((uint32_t)((((uint32_t)(x) & 0x000000ffUL) << 24) | \
                                (((uint32_t)(x) & 0x0000ff00UL) <<  8) | \
                                (((uint32_t)(x) & 0x00ff0000UL) >>  8) | \
                                (((uint32_t)(x) & 0xff000000UL) >> 24)))
#define ws_ntohl(x) ws_htonl(x)
#endif

/* ============================================================================
 * 3. Kernel ABI Structures (IPv4, IPv6 & Unified Address Union)
 * ============================================================================ */
struct ws_sockaddr {
    uint16_t sa_family;
    char     sa_data[14];
};

struct ws_in_addr {
    uint32_t s_addr;
};

struct ws_sockaddr_in {
    uint16_t          sin_family;
    uint16_t          sin_port;
    struct ws_in_addr sin_addr;
    uint8_t           sin_zero[8];
};

struct ws_sockaddr_in6 {
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t  sin6_addr[16];
    uint32_t sin6_scope_id;
};

/* Unified 28-byte IPv4/IPv6 socket address union */
union ws_sockaddr_any {
    struct ws_sockaddr     sa;
    struct ws_sockaddr_in  v4;
    struct ws_sockaddr_in6 v6;
};

static inline uint32_t ws_sockaddr_len(const union ws_sockaddr_any *a)
{
    return (a->sa.sa_family == WS_AF_INET6)
        ? (uint32_t)sizeof(struct ws_sockaddr_in6)
        : (uint32_t)sizeof(struct ws_sockaddr_in);
}

static inline int ws_is_v4mapped(const uint8_t ip6[16])
{
    for (int i = 0; i < 10; i++) {
        if (ip6[i] != 0)
            return 0;
    }
    return (ip6[10] == 0xFF && ip6[11] == 0xFF);
}

static inline void ws_v4_to_v4mapped(const struct ws_sockaddr_in *v4,
                                     struct ws_sockaddr_in6 *v6)
{
    uint32_t ip = v4->sin_addr.s_addr;
    uint16_t port = v4->sin_port;
    memset(v6, 0, sizeof(*v6));
    v6->sin6_family = WS_AF_INET6;
    v6->sin6_port   = port;
    v6->sin6_addr[10] = 0xFF;
    v6->sin6_addr[11] = 0xFF;
    memcpy(&v6->sin6_addr[12], &ip, 4);
}

typedef union ws_epoll_data {
    void    *ptr;
    int      fd;
    uint32_t u32;
    uint64_t u64;
} ws_epoll_data_t;

struct ws_epoll_event {
    uint32_t        events;
    ws_epoll_data_t data;
} WS_EPOLL_PACKED;

struct ws_timespec {
    long tv_sec;
    long tv_nsec;
};

struct ws_timeval {
    long tv_sec;
    long tv_usec;
};

struct ws_sigaction {
#if defined(__mips__)
    unsigned int  sa_flags;
    void        (*sa_handler)(int);
    unsigned long sa_mask[4];
#else
    void        (*sa_handler)(int);
    unsigned long sa_flags;
    void        (*sa_restorer)(void);
    unsigned long sa_mask[2];
#endif
};

/* ============================================================================
 * 4. Zero-Stack MIPS32 O32 Syscall Primitives & Network Wrappers
 * ============================================================================ */
#if defined(__mips__)

#define WS_SYSCALL_CLOBBERS \
    "$1", "$3", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", \
    "$24", "$25", "hi", "lo", "memory"

static inline long ws_syscall1(long n, long a)
{
    register long v0 __asm__("$2") = n;
    register long a0 __asm__("$4") = a;
    register long a3 __asm__("$7");
    __asm__ volatile ("syscall"
                      : "+r"(v0), "=r"(a3), "+r"(a0)
                      :
                      : WS_SYSCALL_CLOBBERS);
    return a3 ? -v0 : v0;
}

static inline long ws_syscall2(long n, long a, long b)
{
    register long v0 __asm__("$2") = n;
    register long a0 __asm__("$4") = a;
    register long a1 __asm__("$5") = b;
    register long a3 __asm__("$7");
    __asm__ volatile ("syscall"
                      : "+r"(v0), "=r"(a3), "+r"(a0), "+r"(a1)
                      :
                      : WS_SYSCALL_CLOBBERS);
    return a3 ? -v0 : v0;
}

static inline long ws_syscall3(long n, long a, long b, long c)
{
    register long v0 __asm__("$2") = n;
    register long a0 __asm__("$4") = a;
    register long a1 __asm__("$5") = b;
    register long a2 __asm__("$6") = c;
    register long a3 __asm__("$7");
    __asm__ volatile ("syscall"
                      : "+r"(v0), "=r"(a3), "+r"(a0), "+r"(a1), "+r"(a2)
                      :
                      : WS_SYSCALL_CLOBBERS);
    return a3 ? -v0 : v0;
}

static inline long ws_syscall4(long n, long a, long b, long c, long d)
{
    register long v0 __asm__("$2") = n;
    register long a0 __asm__("$4") = a;
    register long a1 __asm__("$5") = b;
    register long a2 __asm__("$6") = c;
    register long a3 __asm__("$7") = d;
    __asm__ volatile ("syscall"
                      : "+r"(v0), "+r"(a3), "+r"(a0), "+r"(a1), "+r"(a2)
                      :
                      : WS_SYSCALL_CLOBBERS);
    return a3 ? -v0 : v0;
}

#else /* x86_64 / generic nolibc */

#define ws_syscall1(n, a)          my_syscall1(n, a)
#define ws_syscall2(n, a, b)       my_syscall2(n, a, b)
#define ws_syscall3(n, a, b, c)    my_syscall3(n, a, b, c)
#define ws_syscall4(n, a, b, c, d) my_syscall4(n, a, b, c, d)

#endif

#define ws_syscall5(n, a, b, c, d, e)    my_syscall5(n, a, b, c, d, e)
#define ws_syscall6(n, a, b, c, d, e, f) my_syscall6(n, a, b, c, d, e, f)

/* Socket creation & configuration */
static inline int ws_socket(int domain, int type, int proto)
{
    return (int)ws_syscall3(__NR_socket, domain, type, proto);
}

static inline int ws_bind(int fd, const void *addr, uint32_t addrlen)
{
    return (int)ws_syscall3(__NR_bind, fd, (long)addr, addrlen);
}

static inline int ws_connect(int fd, const void *addr, uint32_t addrlen)
{
    return (int)ws_syscall3(__NR_connect, fd, (long)addr, addrlen);
}

static inline int ws_getsockname(int fd, void *addr, uint32_t *addrlen)
{
    return (int)ws_syscall3(__NR_getsockname, fd, (long)addr, (long)addrlen);
}

static inline int ws_setsockopt(int fd, int level, int optname,
                                const void *optval, uint32_t optlen)
{
    return (int)ws_syscall5(__NR_setsockopt, fd, level, optname,
                            (long)optval, optlen);
}

static inline int ws_setsockopt_int(int fd, int level, int optname, int val)
{
    return ws_setsockopt(fd, level, optname, &val, sizeof(val));
}

static inline void ws_apply_pmtud(int fd, int family)
{
    if (family == WS_AF_INET6) {
        ws_setsockopt_int(fd, WS_IPPROTO_IPV6, WS_IPV6_MTU_DISCOVER, WS_IP_PMTUDISC_WANT);
    }
    ws_setsockopt_int(fd, WS_IPPROTO_IP, WS_IP_MTU_DISCOVER, WS_IP_PMTUDISC_WANT);
}

static inline int ws_set_nonblock(int fd)
{
    long fl = ws_syscall3(__NR_fcntl, fd, WS_F_GETFL, 0);
    if (fl < 0)
        return (int)fl;
    return (int)ws_syscall3(__NR_fcntl, fd, WS_F_SETFL, fl | WS_O_NONBLOCK);
}

/* Data transfer */
static inline ssize_t ws_sendto(int fd, const void *buf, size_t len, int flags,
                                const void *dest_addr, uint32_t addrlen)
{
    return (ssize_t)ws_syscall6(__NR_sendto, fd, (long)buf, len, flags,
                                (long)dest_addr, addrlen);
}

static inline ssize_t ws_recvfrom(int fd, void *buf, size_t len, int flags,
                                  void *src_addr, uint32_t *addrlen)
{
    return (ssize_t)ws_syscall6(__NR_recvfrom, fd, (long)buf, len, flags,
                                (long)src_addr, (long)addrlen);
}

static inline ssize_t ws_send(int fd, const void *buf, size_t len, int flags)
{
#if defined(__mips__) && defined(__NR_send)
    return (ssize_t)ws_syscall4(__NR_send, fd, (long)buf, len, flags);
#else
    return ws_sendto(fd, buf, len, flags, NULL, 0);
#endif
}

static inline ssize_t ws_recv(int fd, void *buf, size_t len, int flags)
{
#if defined(__mips__) && defined(__NR_recv)
    return (ssize_t)ws_syscall4(__NR_recv, fd, (long)buf, len, flags);
#else
    return ws_recvfrom(fd, buf, len, flags, NULL, NULL);
#endif
}

/* Epoll wrappers */
static inline int ws_epoll_create(void)
{
    return (int)ws_syscall1(__NR_epoll_create1, 0);
}

static inline int ws_epoll_ctl(int epfd, int op, int fd,
                               struct ws_epoll_event *ev)
{
    return (int)ws_syscall4(__NR_epoll_ctl, epfd, op, fd, (long)ev);
}

static inline int ws_epoll_wait(int epfd, struct ws_epoll_event *evs,
                                int maxevents, int timeout_ms)
{
    return (int)ws_syscall4(__NR_epoll_wait, epfd, (long)evs,
                            maxevents, timeout_ms);
}

/* ============================================================================
 * 5. Signal Handling (SIGINT, SIGTERM, SIGHUP, SIGPIPE)
 * ============================================================================ */
#if defined(__x86_64__)
#define WS_SA_RESTORER 0x04000000UL
__asm__(
    ".section .text\n"
    ".global __ws_restore_rt\n"
    "__ws_restore_rt:\n"
    "mov $15, %rax\n"
    "syscall\n"
);
extern void __ws_restore_rt(void);
#endif

static inline int ws_sigaction(int sig, void (*handler)(int))
{
    struct ws_sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
#if defined(__x86_64__)
    if (handler != SIG_IGN && handler != SIG_DFL) {
        sa.sa_flags = WS_SA_RESTORER;
        sa.sa_restorer = __ws_restore_rt;
    }
#endif
    return (int)ws_syscall4(__NR_rt_sigaction, sig, (long)&sa, 0, WS_SIGSETSIZE);
}

static inline void ws_ignore_sigpipe(void)
{
    ws_sigaction(SIGPIPE, SIG_IGN);
}

/* ============================================================================
 * 6. Time & Randomness Primitives (clock_gettime, gettimeofday, getrandom)
 * ============================================================================ */
static inline uint64_t ws_clock_ms(void)
{
    struct ws_timespec ts;
    if (ws_syscall2(__NR_clock_gettime, WS_CLOCK_MONOTONIC, (long)&ts) == 0) {
        return (uint64_t)(uint32_t)ts.tv_sec * 1000ULL +
               (uint64_t)((uint32_t)ts.tv_nsec / 1000000UL);
    }
    struct ws_timeval tv;
    if (ws_syscall2(__NR_gettimeofday, (long)&tv, 0) == 0) {
        return (uint64_t)(uint32_t)tv.tv_sec * 1000ULL +
               (uint64_t)((uint32_t)tv.tv_usec / 1000UL);
    }
    return 0;
}

static inline void ws_realtime(long *sec, long *msec)
{
    struct ws_timeval tv;
    if (ws_syscall2(__NR_gettimeofday, (long)&tv, 0) == 0) {
        *sec  = tv.tv_sec;
        *msec = tv.tv_usec / 1000;
    } else {
        *sec  = 0;
        *msec = 0;
    }
}

static inline void ws_sleep_ms(uint32_t ms)
{
    struct ws_timespec req;
    req.tv_sec  = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000L;
    ws_syscall2(__NR_nanosleep, (long)&req, 0);
}

/* Fast xorshift32 PRNG seeded via getrandom / clock / pid */
static uint32_t ws_prng_state = 0x9E3779B9U;

static inline void ws_rand_seed(void)
{
    uint32_t seed = 0;
#ifdef __NR_getrandom
    if (ws_syscall3(__NR_getrandom, (long)&seed, sizeof(seed), 0) == sizeof(seed) && seed != 0) {
        ws_prng_state = seed;
        return;
    }
#endif
    int fd = open("/dev/urandom", O_RDONLY, 0);
    if (fd >= 0) {
        if (read(fd, &seed, sizeof(seed)) == sizeof(seed) && seed != 0)
            ws_prng_state = seed;
        close(fd);
        if (seed != 0)
            return;
    }
    ws_prng_state ^= (uint32_t)ws_clock_ms() ^
                     ((uint32_t)ws_syscall1(__NR_getpid, 0) << 16);
    if (ws_prng_state == 0)
        ws_prng_state = 0xA5A55A5AU;
}

static inline uint32_t ws_rand32(void)
{
    uint32_t x = ws_prng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    ws_prng_state = x;
    return x;
}

static inline void ws_random_bytes(void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    while (len >= 4) {
        uint32_t r = ws_rand32();
        p[0] = (uint8_t)(r);
        p[1] = (uint8_t)(r >> 8);
        p[2] = (uint8_t)(r >> 16);
        p[3] = (uint8_t)(r >> 24);
        p += 4;
        len -= 4;
    }
    if (len > 0) {
        uint32_t r = ws_rand32();
        while (len--) {
            *p++ = (uint8_t)(r & 0xFF);
            r >>= 8;
        }
    }
}

/* ============================================================================
 * 7. Compact IPv4 & IPv6 Parsing & Formatting (No stdio / inet_pton / inet_ntop)
 * ============================================================================ */
static inline int ws_inet_aton(const char *s, uint32_t *out_net_ip)
{
    uint32_t octets[4];
    for (int i = 0; i < 4; i++) {
        uint32_t val = 0;
        int digits = 0;
        while (*s >= '0' && *s <= '9') {
            val = val * 10 + (uint32_t)(*s - '0');
            if (val > 255)
                return -1;
            s++;
            digits++;
        }
        if (digits == 0)
            return -1;
        octets[i] = val;
        if (i < 3) {
            if (*s != '.')
                return -1;
            s++;
        }
    }
    if (*s != '\0')
        return -1;
    uint32_t host_ip = (octets[0] << 24) | (octets[1] << 16) |
                       (octets[2] << 8)  | octets[3];
    *out_net_ip = ws_htonl(host_ip);
    return 0;
}

static inline int ws_hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse IPv6 string (with optional [brackets], :: compression, and ::ffff:a.b.c.d) */
static inline int ws_inet_pton6(const char *s, uint8_t out[16])
{
    if (!s || !*s)
        return -1;

    char tmp[64];
    if (*s == '[') {
        s++;
        const char *cb = strchr(s, ']');
        if (!cb || cb[1] != '\0' || (size_t)(cb - s) >= sizeof(tmp))
            return -1;
        memcpy(tmp, s, (size_t)(cb - s));
        tmp[cb - s] = '\0';
        s = tmp;
    }

    uint16_t words[8];
    int n_words = 0;
    int dc_idx  = -1;

    if (s[0] == ':') {
        if (s[1] != ':')
            return -1;
        dc_idx = 0;
        s += 2;
        if (*s == '\0') {
            memset(out, 0, 16);
            return 0;
        }
    }

    while (*s) {
        if (n_words >= 8)
            return -1;

        /* Check for embedded IPv4 dotted quad at tail (e.g. ::ffff:127.0.0.1) */
        const char *colon = strchr(s, ':');
        const char *dot   = strchr(s, '.');
        if (dot && (!colon || dot < colon)) {
            if (n_words > 6)
                return -1;
            uint32_t v4;
            if (ws_inet_aton(s, &v4) < 0)
                return -1;
            memcpy(&words[n_words], &v4, 4);
            n_words += 2;
            break;
        }

        uint32_t val = 0;
        int digits = 0;
        while (*s) {
            int hv = ws_hex_val(*s);
            if (hv < 0)
                break;
            val = (val << 4) | (uint32_t)hv;
            if (++digits > 4)
                return -1;
            s++;
        }
        if (digits == 0)
            return -1;

        words[n_words++] = ws_htons((uint16_t)val);

        if (*s == '\0')
            break;
        if (*s != ':')
            return -1;
        s++;
        if (*s == ':') {
            if (dc_idx >= 0)
                return -1;
            dc_idx = n_words;
            s++;
            if (*s == '\0')
                break;
        } else if (*s == '\0') {
            return -1;
        }
    }

    if (dc_idx >= 0) {
        if (n_words >= 8)
            return -1;
        int tail = n_words - dc_idx;
        int gap  = 8 - n_words;
        for (int i = tail - 1; i >= 0; i--)
            words[dc_idx + gap + i] = words[dc_idx + i];
        for (int i = 0; i < gap; i++)
            words[dc_idx + i] = 0;
    } else if (n_words != 8) {
        return -1;
    }

    memcpy(out, words, 16);
    return 0;
}

static inline char *ws_u32_to_str(char *p, uint32_t v)
{
    char tmp[12];
    int n = 0;
    if (v == 0) {
        *p++ = '0';
        return p;
    }
    while (v > 0) {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (n > 0)
        *p++ = tmp[--n];
    return p;
}

static inline char *ws_u16_to_hex(char *p, uint16_t v)
{
    static const char hex[] = "0123456789abcdef";
    if (v == 0) {
        *p++ = '0';
        return p;
    }
    char tmp[4];
    int n = 0;
    while (v > 0) {
        tmp[n++] = hex[v & 0xF];
        v >>= 4;
    }
    while (n > 0)
        *p++ = tmp[--n];
    return p;
}

static inline char *ws_format_ip_port(char *buf, const struct ws_sockaddr_in *sa)
{
    uint32_t ip = ws_ntohl(sa->sin_addr.s_addr);
    uint16_t port = ws_ntohs(sa->sin_port);
    char *p = buf;
    p = ws_u32_to_str(p, (ip >> 24) & 0xFF); *p++ = '.';
    p = ws_u32_to_str(p, (ip >> 16) & 0xFF); *p++ = '.';
    p = ws_u32_to_str(p, (ip >> 8)  & 0xFF); *p++ = '.';
    p = ws_u32_to_str(p, ip & 0xFF);         *p++ = ':';
    p = ws_u32_to_str(p, port);
    *p = '\0';
    return buf;
}

/* Format IPv4 or IPv6 address + port ("a.b.c.d:port" or "[x:x:..:x]:port") into buf (64B) */
static inline char *ws_format_addr_port(char *buf, const union ws_sockaddr_any *sa)
{
    if (sa->sa.sa_family == WS_AF_INET6) {
        if (ws_is_v4mapped(sa->v6.sin6_addr)) {
            struct ws_sockaddr_in v4;
            v4.sin_family = WS_AF_INET;
            v4.sin_port   = sa->v6.sin6_port;
            memcpy(&v4.sin_addr.s_addr, &sa->v6.sin6_addr[12], 4);
            return ws_format_ip_port(buf, &v4);
        }
        char *p = buf;
        *p++ = '[';
        for (int i = 0; i < 8; i++) {
            if (i > 0)
                *p++ = ':';
            uint16_t w = (uint16_t)(((uint16_t)sa->v6.sin6_addr[i * 2] << 8) |
                                     sa->v6.sin6_addr[i * 2 + 1]);
            p = ws_u16_to_hex(p, w);
        }
        *p++ = ']';
        *p++ = ':';
        p = ws_u32_to_str(p, ws_ntohs(sa->v6.sin6_port));
        *p = '\0';
        return buf;
    }
    return ws_format_ip_port(buf, &sa->v4);
}

#endif /* WSOCK_H */
