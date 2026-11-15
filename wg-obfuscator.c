/*
 * wg-obfuscator (nolibc + wsock.h edition, IPv4/IPv6 Dual-Stack)
 *
 * Ultra-compact freestanding C port of ClusterM/wg-obfuscator v1.6
 * for embedded Linux routers.
 *
 * Copyright (C) 2024 ClusterM (original WireGuard obfuscator logic)
 * Copyright (C) 2024-2026 Ivan Svarkovsky <ivansvarkovsky@gmail.com>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Based on ClusterM/wg-obfuscator (licensed under GNU GPLv3).
 * Combined with whitehttpd components under GNU AGPLv3 as permitted
 * by Section 13 of the GNU General Public License v3.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include "wsock.h"

#define WG_OBFUSCATOR_VERSION     "1.6+-nolibc"
#define OBFUSCATION_VERSION       1

/* ============================================================================
 * 1. Protocol & Sizing Constants (Optimized for Embedded MIPS32 Routers)
 * ============================================================================ */
#ifndef BUFFER_SIZE
#define BUFFER_SIZE                 4096
#endif
#define PREBUFFER_SIZE              128
#ifndef MAX_CLIENTS_HARD
#define MAX_CLIENTS_HARD            64     /* Static .bss pool capacity */
#endif
#ifndef MAX_CLIENTS_DEFAULT
#define MAX_CLIENTS_DEFAULT         MAX_CLIENTS_HARD
#endif
#ifndef HASH_BUCKETS
#define HASH_BUCKETS                128    /* Power of 2 open-addressing hash */
#endif
#define IDLE_TIMEOUT_DEFAULT        300000 /* 5 minutes (ms) */
#define IN_TIMEOUT_DEFAULT          180000 /* 3 minutes (ms) */
#define HANDSHAKE_TIMEOUT           5000   /* 5 seconds (ms) */
#define ITERATE_INTERVAL            1000   /* 1 second tick (ms) */
#define MAX_DUMMY_LENGTH_TOTAL      1024
#define MAX_DUMMY_LENGTH_HANDSHAKE  512
#define MAX_DUMMY_LENGTH_DATA_DEF   4
#define MAX_KEY_LENGTH              255
#ifndef MAX_STATIC_BINDINGS
#define MAX_STATIC_BINDINGS         16
#endif
#ifndef MAX_SECTIONS
#define MAX_SECTIONS                4
#endif
#define KEYSTREAM_ROW_MAX           2048

/* WireGuard message types */
#define WG_TYPE_HANDSHAKE           0x01
#define WG_TYPE_HANDSHAKE_RESP      0x02
#define WG_TYPE_COOKIE              0x03
#define WG_TYPE_DATA                0x04
#define WG_TYPE(data)               ((uint32_t)((data)[0]) | ((uint32_t)((data)[1]) << 8) | \
                                     ((uint32_t)((data)[2]) << 16) | ((uint32_t)((data)[3]) << 24))

/* Handshake direction */
#define DIR_NONE                    0
#define DIR_CLIENT_TO_SERVER        1
#define DIR_SERVER_TO_CLIENT        2

/* Masking types */
#define MASKING_NONE                0
#define MASKING_STUN                1
#define MASKING_AUTO                2

/* Verbosity levels */
#define LL_ERROR                    0
#define LL_WARN                     1
#define LL_INFO                     2
#define LL_DEBUG                    3
#define LL_TRACE                    4

/* STUN constants (Matching masking_stun.c & RFC 5389) */
#define STUN_WRAP_OVERHEAD          24
#define STUN_BINDING_REQ            0x0001
#define STUN_BINDING_RESP           0x0101
#define STUN_TYPE_DATA_IND          0x0115
#define STUN_ATTR_DATA              0x0013
#define STUN_ATTR_XORMAPPED         0x0020
#define STUN_ATTR_FINGERPR          0x8028
#define STUN_TIMER_INTERVAL_MS      10000

static const uint8_t STUN_COOKIE_BE[4] = { 0x21, 0x12, 0xA4, 0x42 };

/* ============================================================================
 * 2. Data Structures (100% Static .bss Allocation - Zero Heap)
 * ============================================================================ */
struct static_binding {
    char                  bind_host[64];
    union ws_sockaddr_any client_addr;
    uint16_t              src_port;
};

struct obfuscator_config {
    char                  section_name[32];
    char                  listen_ip[64];
    int                   listen_port;
    char                  forward_host[128];
    uint16_t              forward_port;
    union ws_sockaddr_any forward_addr;
    char                  key[MAX_KEY_LENGTH + 1];
    int                   key_len;
    uint8_t               masking_type;      /* MASKING_NONE / MASKING_STUN / MASKING_AUTO */
    uint8_t               masking_set;       /* 1 if explicitly set to NONE or STUN */
    uint8_t               allow_clean;
    uint8_t               is_static_set;
    int                   max_clients;
    uint32_t              idle_timeout;
    uint32_t              in_timeout;
    int                   max_dummy_length_data;
    uint32_t              fwmark;
    int                   resolve_interval;
    struct static_binding bindings[MAX_STATIC_BINDINGS];
    int                   num_bindings;
};

struct client_entry {
    uint8_t               active;
    uint8_t               handshaked;
    uint8_t               is_static;
    uint8_t               client_clean;
    uint8_t               client_obfuscated;
    uint8_t               server_obfuscated;
    uint8_t               handshake_direction;
    uint8_t               masking_type;      /* MASKING_NONE or MASKING_STUN */
    uint8_t               version;
    uint16_t              our_port;          /* Replaces 16B our_addr -> saves .bss! */
    int                   server_sock;
    union ws_sockaddr_any client_addr;
    char                  bind_host[64];
    uint64_t              last_activity_time;
    uint64_t              last_incoming_time;
    uint64_t              last_handshake_request_time;
    uint64_t              last_handshake_time;
    uint64_t              last_masking_timer_time;
};

/* Global static state in .bss */
static struct obfuscator_config g_cfg;
static struct client_entry      g_clients[MAX_CLIENTS_HARD];
static int16_t                  g_addr_hash[HASH_BUCKETS]; /* -1 = empty, -2 = tombstone */
static int                      g_num_clients;
static int                      g_listen_sock   = -1;
static int                      g_listen_family = WS_AF_INET;
static int                      g_epoll_fd      = -1;

/* Logging state */
static int   g_verbose        = LL_INFO;
static int   g_log_fd         = STDERR_FILENO;
static int   g_log_timestamps = 0;
static char  g_log_file_path[256];

/* Signal state */
static volatile int g_stop_flag   = 0;
static volatile int g_sighup_flag = 0;

/* Packet buffer with 128-byte prebuffer for zero-copy STUN header insertion */
static uint8_t g_pkt_raw[PREBUFFER_SIZE + BUFFER_SIZE + 64] __attribute__((aligned(8)));

/* Keystream CRC8 single LUT (256 B) & 1-row MRU cache (2 KB) in .bss */
static uint8_t  g_crc_lut[256];
static uint8_t  g_crc_ready;
static uint8_t  g_ks_row[KEYSTREAM_ROW_MAX] __attribute__((aligned(8)));
static int      g_ks_row_cls = -1;
static uint16_t g_ks_row_valid;
static uint8_t  g_ks_row_crc;
static char     g_ks_cached_key[MAX_KEY_LENGTH + 1];
static int      g_ks_cached_klen;

/* Multi-section supervisor state */
static pid_t g_child_pids[MAX_SECTIONS];
static int   g_num_children;

/* ============================================================================
 * 3. Compact Buffer Writer & Logger (No printf / vsnprintf / stdio)
 * ============================================================================ */
struct strbuf {
    char  *buf;
    size_t cap;
    size_t len;
};

static void sb_init(struct strbuf *sb, char *buf, size_t cap)
{
    sb->buf = buf;
    sb->cap = cap;
    sb->len = 0;
    if (cap > 0)
        buf[0] = '\0';
}

static void sb_putc(struct strbuf *sb, char c)
{
    if (sb->len + 1 < sb->cap) {
        sb->buf[sb->len++] = c;
        sb->buf[sb->len] = '\0';
    }
}

static void sb_puts(struct strbuf *sb, const char *s)
{
    if (!s)
        return;
    while (*s && sb->len + 1 < sb->cap)
        sb->buf[sb->len++] = *s++;
    if (sb->cap > 0)
        sb->buf[sb->len] = '\0';
}

static void sb_putu(struct strbuf *sb, uint32_t v)
{
    char tmp[16];
    int n = 0;
    if (v == 0) {
        sb_putc(sb, '0');
        return;
    }
    while (v > 0) {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (n > 0)
        sb_putc(sb, tmp[--n]);
}

static void sb_puti(struct strbuf *sb, long v)
{
    if (v < 0) {
        sb_putc(sb, '-');
        sb_putu(sb, (uint32_t)(-v));
    } else {
        sb_putu(sb, (uint32_t)v);
    }
}

static void sb_putu_pad2(struct strbuf *sb, uint32_t v)
{
    sb_putc(sb, (char)('0' + ((v / 10) % 10)));
    sb_putc(sb, (char)('0' + (v % 10)));
}

static void sb_putu_pad3(struct strbuf *sb, uint32_t v)
{
    sb_putc(sb, (char)('0' + ((v / 100) % 10)));
    sb_putc(sb, (char)('0' + ((v / 10) % 10)));
    sb_putc(sb, (char)('0' + (v % 10)));
}

static void sb_put_addr(struct strbuf *sb, const union ws_sockaddr_any *sa)
{
    char ipbuf[64];
    ws_format_addr_port(ipbuf, sa);
    sb_puts(sb, ipbuf);
}

static void sb_put_timestamp(struct strbuf *sb)
{
    long sec = 0, msec = 0;
    ws_realtime(&sec, &msec);
    uint32_t s = (uint32_t)(sec >= 0 ? sec : 0);
    uint32_t days = s / 86400U;
    uint32_t rem  = s % 86400U;
    uint32_t hour = rem / 3600U;
    uint32_t min  = (rem % 3600U) / 60U;
    uint32_t secs = rem % 60U;

    int32_t z = (int32_t)days + 719468;
    int32_t era = (z >= 0 ? z : z - 146096) / 146097;
    uint32_t doe = (uint32_t)(z - era * 146097);
    uint32_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int32_t y = (int32_t)yoe + era * 400;
    uint32_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    uint32_t mp = (5 * doy + 2) / 153;
    uint32_t d = doy - (153 * mp + 2) / 5 + 1;
    uint32_t m = mp + (mp < 10 ? 3 : -9);
    y += (m <= 2);

    sb_putc(sb, '[');
    sb_putu(sb, (uint32_t)y);
    sb_putc(sb, '-');
    sb_putu_pad2(sb, m);
    sb_putc(sb, '-');
    sb_putu_pad2(sb, d);
    sb_putc(sb, ' ');
    sb_putu_pad2(sb, hour);
    sb_putc(sb, ':');
    sb_putu_pad2(sb, min);
    sb_putc(sb, ':');
    sb_putu_pad2(sb, secs);
    sb_putc(sb, '.');
    sb_putu_pad3(sb, (uint32_t)msec);
    sb_puts(sb, "] ");
}

static const char *level_tag(int level)
{
    switch (level) {
    case LL_ERROR: return "[E]";
    case LL_WARN:  return "[W]";
    case LL_INFO:  return "[I]";
    case LL_DEBUG: return "[D]";
    case LL_TRACE: return "[T]";
    default:       return "[?]";
    }
}

static void log_begin(struct strbuf *sb, char *buf, size_t cap, int level)
{
    sb_init(sb, buf, cap);
    if (g_log_timestamps)
        sb_put_timestamp(sb);
    if (g_cfg.section_name[0]) {
        sb_putc(sb, '[');
        sb_puts(sb, g_cfg.section_name);
        sb_putc(sb, ']');
    }
    sb_puts(sb, level_tag(level));
    sb_putc(sb, ' ');
}

static void log_flush(struct strbuf *sb)
{
    sb_putc(sb, '\n');
    write(g_log_fd, sb->buf, sb->len);
}

static void log_msg(int level, const char *msg)
{
    if (g_verbose < level)
        return;
    char buf[512];
    struct strbuf sb;
    log_begin(&sb, buf, sizeof(buf), level);
    sb_puts(&sb, msg);
    log_flush(&sb);
}

static void log_msg_str(int level, const char *prefix, const char *val, const char *suffix)
{
    if (g_verbose < level)
        return;
    char buf[512];
    struct strbuf sb;
    log_begin(&sb, buf, sizeof(buf), level);
    sb_puts(&sb, prefix);
    sb_puts(&sb, val);
    if (suffix)
        sb_puts(&sb, suffix);
    log_flush(&sb);
}

static void log_msg_err(int level, const char *prefix, int err_code)
{
    if (g_verbose < level)
        return;
    char buf[512];
    struct strbuf sb;
    log_begin(&sb, buf, sizeof(buf), level);
    sb_puts(&sb, prefix);
    sb_puts(&sb, " (errno=");
    sb_puti(&sb, err_code);
    sb_putc(&sb, ')');
    log_flush(&sb);
}

static int log_open_file(const char *path)
{
    if (!path || !path[0])
        return 0;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        log_msg_err(LL_ERROR, "Failed to open log file", errno);
        return -1;
    }
    if (g_log_fd != STDERR_FILENO && g_log_fd >= 0)
        close(g_log_fd);
    g_log_fd = fd;
    g_log_timestamps = 1;
    return 0;
}

static void log_reopen(void)
{
    if (g_log_file_path[0])
        log_open_file(g_log_file_path);
}

/* ============================================================================
 * 4. WireGuard Obfuscation Engine (100% Byte-for-Byte Match with obfuscation.h/.c)
 * ============================================================================ */
static inline uint8_t crc8_step(uint8_t crc, uint8_t inbyte)
{
    for (int b = 0; b < 8; b++) {
        uint8_t mix = (crc ^ inbyte) & 0x01;
        crc >>= 1;
        if (mix)
            crc ^= 0x8C;
        inbyte >>= 1;
    }
    return crc;
}

static void init_crc_tables(void)
{
    for (int i = 0; i < 256; i++) {
        g_crc_lut[i] = crc8_step((uint8_t)i, 0);
    }
    g_crc_ready = 1;
}

static inline void xor_block(uint8_t *dst, const uint8_t *ks, int len)
{
    int i = 0;
#if defined(__x86_64__)
    for (; i + 8 <= len; i += 8) {
        uint64_t d, k;
        memcpy(&d, dst + i, 8);
        memcpy(&k, ks + i, 8);
        d ^= k;
        memcpy(dst + i, &d, 8);
    }
#endif
    for (; i + 4 <= len; i += 4) {
        uint32_t d, k;
        memcpy(&d, dst + i, 4);
        memcpy(&k, ks + i, 4);
        d ^= k;
        memcpy(dst + i, &d, 4);
    }
    for (; i < len; i++)
        dst[i] ^= ks[i];
}

static void ks_ensure_key(const char *key, int key_length)
{
    if (!g_crc_ready)
        init_crc_tables();
    if (g_ks_cached_klen != key_length ||
        memcmp(g_ks_cached_key, key, (size_t)key_length) != 0) {
        g_ks_row_cls = -1;
        g_ks_row_valid = 0;
        g_ks_row_crc = 0;
        memcpy(g_ks_cached_key, key, (size_t)key_length);
        g_ks_cached_key[key_length] = '\0';
        g_ks_cached_klen = key_length;
    }
}

static void xor_data(uint8_t *buffer, int length, const char *key, int key_length)
{
    if (key_length <= 0 || length <= 0)
        return;

    ks_ensure_key(key, key_length);

    const uint8_t cls = (uint8_t)(length & 0xFF);
    const int cached_target = (length <= KEYSTREAM_ROW_MAX) ? length : KEYSTREAM_ROW_MAX;

    if (g_ks_row_cls != (int)cls) {
        g_ks_row_cls = (int)cls;
        g_ks_row_valid = 0;
        g_ks_row_crc = 0;
    }

    uint16_t valid = g_ks_row_valid;
    uint8_t crc = g_ks_row_crc;

    if ((int)valid < cached_target) {
        int ki = (int)valid % key_length;
        for (int i = (int)valid; i < cached_target; i++) {
            uint8_t inbyte = (uint8_t)((uint8_t)key[ki] + cls + key_length);
            crc = g_crc_lut[crc ^ inbyte];
            g_ks_row[i] = crc;
            ki++;
            if (ki == key_length)
                ki = 0;
        }
        g_ks_row_crc = crc;
        g_ks_row_valid = (uint16_t)cached_target;
    }

    if (cached_target > 0)
        xor_block(buffer, g_ks_row, cached_target);

    if (length > KEYSTREAM_ROW_MAX) {
        crc = g_ks_row_crc;
        int ki = KEYSTREAM_ROW_MAX % key_length;
        for (int i = KEYSTREAM_ROW_MAX; i < length; i++) {
            uint8_t inbyte = (uint8_t)((uint8_t)key[ki] + cls + key_length);
            crc = g_crc_lut[crc ^ inbyte];
            buffer[i] ^= crc;
            ki++;
            if (ki == key_length)
                ki = 0;
        }
    }
}

static inline uint8_t is_obfuscated(const uint8_t *data)
{
    uint32_t packet_type = WG_TYPE(data);
    return !(packet_type >= 1 && packet_type <= 4);
}

static int encode_packet(uint8_t *buffer, int length, const char *key,
                         int key_length, uint8_t version, int max_dummy_length_data)
{
    if (version >= 1) {
        uint32_t packet_type = WG_TYPE(buffer);
        uint8_t rnd = (uint8_t)(1 + (ws_rand32() % 255));
        buffer[0] ^= rnd;
        buffer[1] = rnd;
        if (length < MAX_DUMMY_LENGTH_TOTAL) {
            uint16_t dummy_length = 0;
            uint16_t max_dummy = (uint16_t)(MAX_DUMMY_LENGTH_TOTAL - length);
            switch (packet_type) {
            case WG_TYPE_HANDSHAKE:
            case WG_TYPE_HANDSHAKE_RESP:
                if (max_dummy > MAX_DUMMY_LENGTH_HANDSHAKE)
                    max_dummy = MAX_DUMMY_LENGTH_HANDSHAKE;
                if (max_dummy > 0)
                    dummy_length = (uint16_t)(ws_rand32() % max_dummy);
                break;
            case WG_TYPE_COOKIE:
            case WG_TYPE_DATA:
                if (max_dummy_length_data > 0) {
                    if (max_dummy > (uint16_t)max_dummy_length_data)
                        max_dummy = (uint16_t)max_dummy_length_data;
                    if (max_dummy > 0)
                        dummy_length = (uint16_t)(ws_rand32() % max_dummy);
                }
                break;
            default:
                break;
            }
            buffer[2] = (uint8_t)(dummy_length & 0xFF);
            buffer[3] = (uint8_t)(dummy_length >> 8);
            if (dummy_length > 0) {
                int i = length;
                length += (int)dummy_length;
                for (; i < length; ++i)
                    buffer[i] = 0xFF;
            }
        }
    }

    xor_data(buffer, length, key, key_length);
    return length;
}

static int decode_packet(uint8_t *buffer, int length, const char *key,
                         int key_length, uint8_t *version_out)
{
    xor_data(buffer, length, key, key_length);

    if (!is_obfuscated(buffer)) {
        *version_out = 0;
        return length;
    }

    buffer[0] ^= buffer[1];
    length -= (int)(uint16_t)((uint16_t)buffer[2] | ((uint16_t)buffer[3] << 8));
    buffer[1] = buffer[2] = buffer[3] = 0;
    *version_out = 1;
    return length;
}

/* ============================================================================
 * 5. STUN Protocol Masking (IPv4 family 0x01 & IPv6 family 0x02 RFC 5389)
 * ============================================================================ */
static uint32_t stun_crc32(const uint8_t *p, size_t n)
{
    uint32_t crc = ~0U;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320U & (-(int32_t)(crc & 1U)));
    }
    return ~crc;
}

static int stun_check_magic(const uint8_t *buf, int len)
{
    if (!buf || len < 8)
        return 0;
    return memcmp(buf + 4, STUN_COOKIE_BE, 4) == 0;
}

static uint16_t stun_peek_type(const uint8_t *buf)
{
    return (uint16_t)(((uint16_t)buf[0] << 8) | buf[1]);
}

static int stun_write_header(uint8_t *b, uint16_t type, uint16_t mlen, const uint8_t txid[12])
{
    b[0] = (uint8_t)(type >> 8);
    b[1] = (uint8_t)(type & 0xFF);
    b[2] = (uint8_t)(mlen >> 8);
    b[3] = (uint8_t)(mlen & 0xFF);
    memcpy(b + 4, STUN_COOKIE_BE, 4);
    memcpy(b + 8, txid, 12);
    return 20;
}

/*
 * RFC 5389 Section 15.2 XOR-MAPPED-ADDRESS:
 *   - For IPv4 or IPv4-mapped IPv6 (::ffff:a.b.c.d): emits family 0x01 (8B value)
 *     to prevent DPI anomalies when Dual-Stack socket receives IPv4 packets.
 *   - For native IPv6: emits family 0x02 (20B value), XORing first 4B of IPv6
 *     with STUN_COOKIE_BE[0..3] and remaining 12B with txid[0..11].
 */
static int stun_attr_xor_mapped_addr(uint8_t *b, const union ws_sockaddr_any *src,
                                     const uint8_t txid[12])
{
    b[0] = (uint8_t)(STUN_ATTR_XORMAPPED >> 8);
    b[1] = (uint8_t)(STUN_ATTR_XORMAPPED & 0xFF);
    b[2] = 0;
    b[4] = 0;

    if (src->sa.sa_family == WS_AF_INET6 && !ws_is_v4mapped(src->v6.sin6_addr)) {
        b[3] = 20;   /* len = 20 (family + port + 16B IPv6) */
        b[5] = 0x02; /* family IPv6 */
        memcpy(b + 6, &src->v6.sin6_port, 2);
        b[6] ^= STUN_COOKIE_BE[0];
        b[7] ^= STUN_COOKIE_BE[1];
        memcpy(b + 8, src->v6.sin6_addr, 16);
        for (int i = 0; i < 4; i++)
            b[8 + i] ^= STUN_COOKIE_BE[i];
        for (int i = 0; i < 12; i++)
            b[12 + i] ^= txid[i];
        return 24; /* 4 hdr + 20 val */
    }

    /* IPv4 or IPv4-mapped IPv6 */
    b[3] = 8;    /* len = 8 (family + port + 4B IPv4) */
    b[5] = 0x01; /* family IPv4 */
    if (src->sa.sa_family == WS_AF_INET6) {
        memcpy(b + 6, &src->v6.sin6_port, 2);
        memcpy(b + 8, &src->v6.sin6_addr[12], 4);
    } else {
        memcpy(b + 6, &src->v4.sin_port, 2);
        memcpy(b + 8, &src->v4.sin_addr.s_addr, 4);
    }
    b[6]  ^= STUN_COOKIE_BE[0];
    b[7]  ^= STUN_COOKIE_BE[1];
    b[8]  ^= STUN_COOKIE_BE[0];
    b[9]  ^= STUN_COOKIE_BE[1];
    b[10] ^= STUN_COOKIE_BE[2];
    b[11] ^= STUN_COOKIE_BE[3];
    return 12; /* 4 hdr + 8 val */
}

static int stun_attr_fingerprint(uint8_t *pkt, size_t cur_len)
{
    uint8_t *b = pkt + cur_len;
    b[0] = (uint8_t)(STUN_ATTR_FINGERPR >> 8);
    b[1] = (uint8_t)(STUN_ATTR_FINGERPR & 0xFF);
    b[2] = 0;
    b[3] = 4;
    uint32_t fp = ws_htonl(stun_crc32(pkt, cur_len) ^ 0x5354554EU);
    memcpy(b + 4, &fp, 4);
    return 8;
}

static int stun_build_binding_request(uint8_t *out)
{
    uint8_t txid[12];
    ws_random_bytes(txid, 12);
    stun_write_header(out, STUN_BINDING_REQ, 0, txid);
    size_t mlen = (size_t)stun_attr_fingerprint(out, 20);
    out[2] = (uint8_t)((mlen >> 8) & 0xFF);
    out[3] = (uint8_t)(mlen & 0xFF);
    return (int)(20 + mlen);
}

static int stun_build_binding_success(uint8_t *out, const uint8_t txid[12],
                                      const union ws_sockaddr_any *src)
{
    stun_write_header(out, STUN_BINDING_RESP, 0, txid);
    size_t mlen = 0;
    mlen += (size_t)stun_attr_xor_mapped_addr(out + 20 + mlen, src, txid);
    mlen += (size_t)stun_attr_fingerprint(out, 20 + mlen);
    out[2] = (uint8_t)((mlen >> 8) & 0xFF);
    out[3] = (uint8_t)(mlen & 0xFF);
    return (int)(20 + mlen);
}

static int stun_wrap(uint8_t **buf_ptr, int data_len)
{
    if (data_len > BUFFER_SIZE)
        return -1;
    *buf_ptr -= STUN_WRAP_OVERHEAD;
    uint8_t *buf = *buf_ptr;
    uint8_t txid[12];
    ws_random_bytes(txid, 12);
    int mlen = stun_write_header(buf, STUN_TYPE_DATA_IND, 0, txid);
    buf[mlen]     = (uint8_t)(STUN_ATTR_DATA >> 8);
    buf[mlen + 1] = (uint8_t)(STUN_ATTR_DATA & 0xFF);
    buf[mlen + 2] = (uint8_t)((data_len >> 8) & 0xFF);
    buf[mlen + 3] = (uint8_t)(data_len & 0xFF);
    return STUN_WRAP_OVERHEAD + data_len;
}

static int stun_unwrap_data_ind(uint8_t **buf_ptr, int len)
{
    uint8_t *buf = *buf_ptr;
    if (len < 24)
        return -1;
    uint16_t msg_type = (uint16_t)(((uint16_t)buf[0] << 8) | buf[1]);
    if (msg_type != STUN_TYPE_DATA_IND)
        return -1;
    uint16_t msg_len = (uint16_t)(((uint16_t)buf[2] << 8) | buf[3]);
    if ((int)msg_len + 20 > len)
        return -1;
    uint16_t attr_type = (uint16_t)(((uint16_t)buf[20] << 8) | buf[21]);
    if (attr_type != STUN_ATTR_DATA)
        return -1;
    uint16_t data_len = (uint16_t)(((uint16_t)buf[22] << 8) | buf[23]);
    if ((int)data_len + 24 > len)
        return -1;
    *buf_ptr += 24;
    return (int)data_len;
}

static void stun_send_binding_req_to_client(const union ws_sockaddr_any *client_addr)
{
    uint8_t req[64];
    int len = stun_build_binding_request(req);
    if (len > 0)
        ws_sendto(g_listen_sock, req, (size_t)len, 0,
                  client_addr, ws_sockaddr_len(client_addr));
}

static void stun_send_binding_req_to_server(int server_sock)
{
    uint8_t req[64];
    int len = stun_build_binding_request(req);
    if (len > 0)
        ws_send(server_sock, req, (size_t)len, 0);
}

static int stun_on_data_unwrap(uint8_t **buffer_ptr, int length,
                               const union ws_sockaddr_any *src_addr,
                               int reply_sock_is_listen, int server_sock)
{
    if (!stun_check_magic(*buffer_ptr, length))
        return -EINVAL;

    uint16_t stun_type = stun_peek_type(*buffer_ptr);
    switch (stun_type) {
    case STUN_BINDING_REQ: {
        uint8_t txid[12];
        memcpy(txid, (*buffer_ptr) + 8, 12);
        uint8_t resp[64];
        int resp_len = stun_build_binding_success(resp, txid, src_addr);
        if (resp_len > 0) {
            if (reply_sock_is_listen)
                ws_sendto(g_listen_sock, resp, (size_t)resp_len, 0,
                          src_addr, ws_sockaddr_len(src_addr));
            else if (server_sock >= 0)
                ws_send(server_sock, resp, (size_t)resp_len, 0);
        }
        return 0;
    }
    case STUN_BINDING_RESP:
        return 0;
    case STUN_TYPE_DATA_IND:
        return stun_unwrap_data_ind(buffer_ptr, length);
    default:
        return 0;
    }
}

/* ============================================================================
 * 6. Static .bss NAT Client Hash Table (Supports IPv4 & 128-bit IPv6)
 * ============================================================================ */
static inline uint32_t hash_sockaddr(const union ws_sockaddr_any *sa)
{
    uint32_t h;
    if (sa->sa.sa_family == WS_AF_INET6) {
        uint32_t w[4];
        memcpy(w, sa->v6.sin6_addr, 16);
        h = w[0] ^ w[1] ^ w[2] ^ w[3] ^ ((uint32_t)sa->v6.sin6_port * 0x9E3779B9U);
    } else {
        h = sa->v4.sin_addr.s_addr ^ ((uint32_t)sa->v4.sin_port * 0x9E3779B9U);
    }
    h ^= h >> 16;
    h *= 0x85EBCA6BU;
    h ^= h >> 13;
    return h & (HASH_BUCKETS - 1);
}

static inline int sockaddr_equal(const union ws_sockaddr_any *a,
                                 const union ws_sockaddr_any *b)
{
    if (a->sa.sa_family != b->sa.sa_family)
        return 0;
    if (a->sa.sa_family == WS_AF_INET6) {
        return (a->v6.sin6_port == b->v6.sin6_port) &&
               (memcmp(a->v6.sin6_addr, b->v6.sin6_addr, 16) == 0);
    }
    return (a->v4.sin_addr.s_addr == b->v4.sin_addr.s_addr) &&
           (a->v4.sin_port == b->v4.sin_port);
}

static void client_table_init(void)
{
    memset(g_clients, 0, sizeof(g_clients));
    for (int i = 0; i < HASH_BUCKETS; i++)
        g_addr_hash[i] = -1;
    g_num_clients = 0;
}

static struct client_entry *find_client(const union ws_sockaddr_any *addr)
{
    uint32_t idx = hash_sockaddr(addr);
    for (int probe = 0; probe < HASH_BUCKETS; probe++) {
        int16_t slot = g_addr_hash[idx];
        if (slot == -1)
            return NULL;
        if (slot >= 0 && g_clients[slot].active &&
            sockaddr_equal(&g_clients[slot].client_addr, addr)) {
            return &g_clients[slot];
        }
        idx = (idx + 1) & (HASH_BUCKETS - 1);
    }
    return NULL;
}

static void hash_insert_client(int16_t slot)
{
    uint32_t idx = hash_sockaddr(&g_clients[slot].client_addr);
    for (int probe = 0; probe < HASH_BUCKETS; probe++) {
        if (g_addr_hash[idx] < 0) {
            g_addr_hash[idx] = slot;
            return;
        }
        idx = (idx + 1) & (HASH_BUCKETS - 1);
    }
}

static void hash_remove_client(int16_t slot)
{
    uint32_t idx = hash_sockaddr(&g_clients[slot].client_addr);
    for (int probe = 0; probe < HASH_BUCKETS; probe++) {
        int16_t cur = g_addr_hash[idx];
        if (cur == -1)
            return;
        if (cur == slot) {
            g_addr_hash[idx] = -2; /* Tombstone */
            return;
        }
        idx = (idx + 1) & (HASH_BUCKETS - 1);
    }
}

static void delete_client(struct client_entry *c)
{
    if (!c || !c->active)
        return;
    int16_t slot = (int16_t)(c - g_clients);
    hash_remove_client(slot);
    if (c->server_sock >= 0) {
        ws_epoll_ctl(g_epoll_fd, WS_EPOLL_CTL_DEL, c->server_sock, NULL);
        close(c->server_sock);
        c->server_sock = -1;
    }
    c->active = 0;
    if (g_num_clients > 0)
        g_num_clients--;
}

static struct client_entry *new_client_entry(const union ws_sockaddr_any *client_addr,
                                             uint16_t bind_port,
                                             const char *bind_host)
{
    if (g_num_clients >= g_cfg.max_clients || g_num_clients >= MAX_CLIENTS_HARD) {
        log_msg(LL_ERROR, "Maximum number of clients reached");
        return NULL;
    }
    if (bind_port > 0 && find_client(client_addr) != NULL) {
        log_msg(LL_ERROR, "Static binding with client already exists");
        return NULL;
    }

    int16_t slot = -1;
    for (int16_t i = 0; i < MAX_CLIENTS_HARD; i++) {
        if (!g_clients[i].active) {
            slot = i;
            break;
        }
    }
    if (slot < 0)
        return NULL;

    /* Create outgoing server_sock using target's address family (enables IPv4 <-> IPv6 bridging!) */
    int target_family = g_cfg.forward_addr.sa.sa_family;
    int sock = ws_socket(target_family, WS_SOCK_DGRAM, 0);
    if (sock < 0) {
        log_msg_err(LL_ERROR, "Failed to create client UDP socket", (int)(-sock));
        return NULL;
    }

    if (bind_port > 0) {
        union ws_sockaddr_any local_sa;
        memset(&local_sa, 0, sizeof(local_sa));
        local_sa.sa.sa_family = (uint16_t)target_family;
        if (target_family == WS_AF_INET6)
            local_sa.v6.sin6_port = ws_htons(bind_port);
        else
            local_sa.v4.sin_port = ws_htons(bind_port);

        if (ws_bind(sock, &local_sa, ws_sockaddr_len(&local_sa)) < 0) {
            log_msg(LL_ERROR, "Failed to bind static client port");
            close(sock);
            return NULL;
        }
    }

    ws_apply_pmtud(sock, target_family);
    if (g_cfg.fwmark > 0)
        ws_setsockopt_int(sock, WS_SOL_SOCKET, WS_SO_MARK, (int)g_cfg.fwmark);

    if (ws_connect(sock, &g_cfg.forward_addr, ws_sockaddr_len(&g_cfg.forward_addr)) < 0) {
        log_msg(LL_ERROR, "Failed to connect client socket to target");
        close(sock);
        return NULL;
    }

    union ws_sockaddr_any our_sa;
    memset(&our_sa, 0, sizeof(our_sa));
    uint32_t addr_len = sizeof(our_sa);
    if (ws_getsockname(sock, &our_sa, &addr_len) < 0) {
        close(sock);
        return NULL;
    }

    ws_set_nonblock(sock);

    struct client_entry *c = &g_clients[slot];
    memset(c, 0, sizeof(*c));
    c->active       = 1;
    c->server_sock  = sock;
    c->client_addr  = *client_addr;
    c->our_port     = ws_ntohs((our_sa.sa.sa_family == WS_AF_INET6)
                               ? our_sa.v6.sin6_port : our_sa.v4.sin_port);
    c->is_static    = (bind_port > 0) ? 1 : 0;
    c->version      = OBFUSCATION_VERSION;
    c->masking_type = (g_cfg.masking_type == MASKING_STUN) ? MASKING_STUN : MASKING_NONE;
    if (bind_host && bind_host[0]) {
        size_t bl = strlen(bind_host);
        if (bl >= sizeof(c->bind_host))
            bl = sizeof(c->bind_host) - 1;
        memcpy(c->bind_host, bind_host, bl);
        c->bind_host[bl] = '\0';
    }

    uint64_t now = ws_clock_ms();
    c->last_activity_time = now;

    struct ws_epoll_event ev;
    ev.events   = WS_EPOLLIN;
    ev.data.ptr = c;
    if (ws_epoll_ctl(g_epoll_fd, WS_EPOLL_CTL_ADD, sock, &ev) < 0) {
        log_msg(LL_ERROR, "Failed to add client socket to epoll");
        close(sock);
        c->active = 0;
        return NULL;
    }

    hash_insert_client(slot);
    g_num_clients++;
    return c;
}

static void update_clients_forward_addr(void)
{
    uint32_t flen = ws_sockaddr_len(&g_cfg.forward_addr);
    for (int i = 0; i < MAX_CLIENTS_HARD; i++) {
        if (g_clients[i].active && g_clients[i].server_sock >= 0) {
            ws_connect(g_clients[i].server_sock, &g_cfg.forward_addr, flen);
        }
    }
}

/* ============================================================================
 * 7. Compact Freestanding IPv4/IPv6 DNS (A + AAAA) & /etc/hosts Resolver
 * ============================================================================ */
static int ci_strcmp(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (char)(*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (char)(*b + 32) : *b;
        if (ca != cb)
            return (int)(unsigned char)ca - (int)(unsigned char)cb;
        a++;
        b++;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static int resolve_literal_ip(const char *host, uint16_t port_net,
                              union ws_sockaddr_any *out)
{
    uint32_t v4;
    if (ws_inet_aton(host, &v4) == 0) {
        memset(out, 0, sizeof(*out));
        out->v4.sin_family      = WS_AF_INET;
        out->v4.sin_port        = port_net;
        out->v4.sin_addr.s_addr = v4;
        return 0;
    }
    uint8_t v6[16];
    if (ws_inet_pton6(host, v6) == 0) {
        memset(out, 0, sizeof(*out));
        out->v6.sin6_family = WS_AF_INET6;
        out->v6.sin6_port   = port_net;
        memcpy(out->v6.sin6_addr, v6, 16);
        return 0;
    }
    return -1;
}

static int resolve_from_etc_hosts(const char *host, uint16_t port_net,
                                  union ws_sockaddr_any *out)
{
    if (ci_strcmp(host, "localhost") == 0) {
        memset(out, 0, sizeof(*out));
        out->v4.sin_family      = WS_AF_INET;
        out->v4.sin_port        = port_net;
        out->v4.sin_addr.s_addr = ws_htonl(0x7F000001U);
        return 0;
    }
    int fd = open("/etc/hosts", O_RDONLY, 0);
    if (fd < 0)
        return -1;
    char buf[2048];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';

    char *p = buf;
    while (*p) {
        char *line = p;
        while (*p && *p != '\n')
            p++;
        if (*p == '\n')
            *p++ = '\0';

        char *hash = strchr(line, '#');
        if (hash)
            *hash = '\0';

        while (*line == ' ' || *line == '\t' || *line == '\r')
            line++;
        if (!*line)
            continue;

        char *ip_tok = line;
        while (*line && *line != ' ' && *line != '\t' && *line != '\r')
            line++;
        if (!*line)
            continue;
        *line++ = '\0';

        union ws_sockaddr_any cand;
        if (resolve_literal_ip(ip_tok, port_net, &cand) < 0)
            continue;

        while (*line) {
            while (*line == ' ' || *line == '\t' || *line == '\r')
                line++;
            if (!*line)
                break;
            char *name_tok = line;
            while (*line && *line != ' ' && *line != '\t' && *line != '\r')
                line++;
            if (*line)
                *line++ = '\0';
            if (ci_strcmp(name_tok, host) == 0) {
                *out = cand;
                return 0;
            }
        }
    }
    return -1;
}

static uint32_t get_system_nameserver(void)
{
    int fd = open("/etc/resolv.conf", O_RDONLY, 0);
    if (fd >= 0) {
        char buf[1024];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            char *p = buf;
            while (*p) {
                char *line = p;
                while (*p && *p != '\n')
                    p++;
                if (*p == '\n')
                    *p++ = '\0';
                while (*line == ' ' || *line == '\t')
                    line++;
                if (strncmp(line, "nameserver", 10) == 0 &&
                    (line[10] == ' ' || line[10] == '\t')) {
                    line += 10;
                    while (*line == ' ' || *line == '\t')
                        line++;
                    char *end = line;
                    while (*end && *end != ' ' && *end != '\t' && *end != '\r' && *end != '#')
                        end++;
                    *end = '\0';
                    uint32_t ns_ip;
                    if (ws_inet_aton(line, &ns_ip) == 0)
                        return ns_ip;
                }
            }
        }
    }
    return ws_htonl(0x08080808U);
}

static int dns_skip_name(const uint8_t *pkt, int pkt_len, int offset)
{
    int hops = 0;
    while (offset < pkt_len && hops++ < 64) {
        uint8_t c = pkt[offset];
        if (c == 0) {
            return offset + 1;
        } else if ((c & 0xC0) == 0xC0) {
            if (offset + 1 >= pkt_len)
                return -1;
            return offset + 2;
        } else {
            offset += 1 + c;
        }
    }
    return -1;
}

/* Query DNS for qtype=1 (A, 4B) or qtype=28 (AAAA, 16B) */
static int dns_query_record(const char *host, uint16_t qtype, uint8_t *out_bytes, int expected_len)
{
    uint8_t qpkt[512];
    memset(qpkt, 0, sizeof(qpkt));
    uint16_t tx_id = (uint16_t)(ws_rand32() & 0xFFFF);
    qpkt[0] = (uint8_t)(tx_id >> 8);
    qpkt[1] = (uint8_t)(tx_id & 0xFF);
    qpkt[2] = 0x01; /* RD = 1 */
    qpkt[5] = 0x01; /* QDCOUNT = 1 */

    int pos = 12;
    const char *p = host;
    while (*p) {
        const char *dot = strchr(p, '.');
        int label_len = dot ? (int)(dot - p) : (int)strlen(p);
        if (label_len <= 0 || label_len > 63 || pos + label_len + 2 >= 500)
            return -1;
        qpkt[pos++] = (uint8_t)label_len;
        memcpy(qpkt + pos, p, (size_t)label_len);
        pos += label_len;
        if (!dot)
            break;
        p = dot + 1;
    }
    qpkt[pos++] = 0x00;
    qpkt[pos++] = (uint8_t)(qtype >> 8);
    qpkt[pos++] = (uint8_t)(qtype & 0xFF);
    qpkt[pos++] = 0x00; qpkt[pos++] = 0x01; /* QCLASS = IN */

    int sock = ws_socket(WS_AF_INET, WS_SOCK_DGRAM, 0);
    if (sock < 0)
        return -1;
    ws_set_nonblock(sock);

    struct ws_sockaddr_in ns;
    memset(&ns, 0, sizeof(ns));
    ns.sin_family      = WS_AF_INET;
    ns.sin_port        = ws_htons(53);
    ns.sin_addr.s_addr = get_system_nameserver();

    ws_sendto(sock, qpkt, (size_t)pos, 0, &ns, sizeof(ns));

    uint8_t rpkt[512];
    for (int wait = 0; wait < 30; wait++) {
        ssize_t rlen = ws_recvfrom(sock, rpkt, sizeof(rpkt), 0, NULL, NULL);
        if (rlen >= 12) {
            uint16_t r_id = (uint16_t)(((uint16_t)rpkt[0] << 8) | rpkt[1]);
            uint16_t flags = (uint16_t)(((uint16_t)rpkt[2] << 8) | rpkt[3]);
            uint16_t qdcount = (uint16_t)(((uint16_t)rpkt[4] << 8) | rpkt[5]);
            uint16_t ancount = (uint16_t)(((uint16_t)rpkt[6] << 8) | rpkt[7]);
            if (r_id == tx_id && (flags & 0x8000) && (flags & 0x000F) == 0 && ancount > 0) {
                int off = 12;
                for (uint16_t q = 0; q < qdcount; q++) {
                    off = dns_skip_name(rpkt, (int)rlen, off);
                    if (off < 0 || off + 4 > (int)rlen) { close(sock); return -1; }
                    off += 4;
                }
                for (uint16_t a = 0; a < ancount; a++) {
                    off = dns_skip_name(rpkt, (int)rlen, off);
                    if (off < 0 || off + 10 > (int)rlen) { close(sock); return -1; }
                    uint16_t rtype = (uint16_t)(((uint16_t)rpkt[off] << 8) | rpkt[off + 1]);
                    uint16_t rdlen = (uint16_t)(((uint16_t)rpkt[off + 8] << 8) | rpkt[off + 9]);
                    off += 10;
                    if (off + rdlen > (int)rlen) { close(sock); return -1; }
                    if (rtype == qtype && rdlen == (uint16_t)expected_len) {
                        memcpy(out_bytes, rpkt + off, (size_t)expected_len);
                        close(sock);
                        return 0;
                    }
                    off += rdlen;
                }
            }
            break;
        }
        ws_sleep_ms(50);
    }
    close(sock);
    return -1;
}

static int resolve_host_any(const char *host, uint16_t port_net,
                            union ws_sockaddr_any *out)
{
    if (resolve_literal_ip(host, port_net, out) == 0)
        return 0;
    if (resolve_from_etc_hosts(host, port_net, out) == 0)
        return 0;

    /* Try DNS A (IPv4) first, then AAAA (IPv6) */
    uint32_t v4 = 0;
    if (dns_query_record(host, 1, (uint8_t *)&v4, 4) == 0) {
        memset(out, 0, sizeof(*out));
        out->v4.sin_family      = WS_AF_INET;
        out->v4.sin_port        = port_net;
        out->v4.sin_addr.s_addr = v4;
        return 0;
    }
    uint8_t v6[16];
    if (dns_query_record(host, 28, v6, 16) == 0) {
        memset(out, 0, sizeof(*out));
        out->v6.sin6_family = WS_AF_INET6;
        out->v6.sin6_port   = port_net;
        memcpy(out->v6.sin6_addr, v6, 16);
        return 0;
    }
    return -1;
}

/* Parse "host:port" or "[ipv6]:port" and resolve into sa */
static int parse_and_resolve_host_port(const char *str, char *save_host,
                                       size_t save_cap, uint16_t *save_port,
                                       union ws_sockaddr_any *sa)
{
    const char *host_start = str;
    size_t hlen = 0;
    const char *pstr = NULL;

    if (str[0] == '[') {
        const char *close_br = strchr(str + 1, ']');
        if (!close_br || close_br[1] != ':')
            return -1;
        host_start = str + 1;
        hlen = (size_t)(close_br - host_start);
        pstr = close_br + 2;
    } else {
        const char *colon = strrchr(str, ':');
        if (!colon || strchr(str, ':') != colon)
            return -1;
        hlen = (size_t)(colon - str);
        pstr = colon + 1;
    }

    if (hlen == 0 || hlen >= save_cap || !*pstr)
        return -1;
    memcpy(save_host, host_start, hlen);
    save_host[hlen] = '\0';

    uint32_t port = 0;
    while (*pstr) {
        if (*pstr < '0' || *pstr > '9')
            return -1;
        port = port * 10 + (uint32_t)(*pstr - '0');
        if (port > 65535)
            return -1;
        pstr++;
    }
    if (port == 0)
        return -1;
    *save_port = (uint16_t)port;

    if (resolve_host_any(save_host, ws_htons((uint16_t)port), sa) < 0)
        return -1;
    return 0;
}

static void refresh_hostnames(int force_log)
{
    union ws_sockaddr_any resolved;
    if (g_cfg.forward_host[0] &&
        resolve_literal_ip(g_cfg.forward_host, ws_htons(g_cfg.forward_port), &resolved) < 0) {
        if (resolve_host_any(g_cfg.forward_host, ws_htons(g_cfg.forward_port), &resolved) == 0) {
            if (!sockaddr_equal(&resolved, &g_cfg.forward_addr)) {
                g_cfg.forward_addr = resolved;
                update_clients_forward_addr();
                char abuf[64];
                ws_format_addr_port(abuf, &g_cfg.forward_addr);
                log_msg_str(LL_INFO, "Target IP updated to ", abuf, NULL);
            } else if (force_log) {
                log_msg(LL_DEBUG, "Target hostname re-resolved (unchanged)");
            }
        }
    }
    for (int i = 0; i < MAX_CLIENTS_HARD; i++) {
        struct client_entry *c = &g_clients[i];
        if (c->active && c->is_static && c->bind_host[0]) {
            uint16_t cport = (c->client_addr.sa.sa_family == WS_AF_INET6)
                             ? c->client_addr.v6.sin6_port : c->client_addr.v4.sin_port;
            if (resolve_literal_ip(c->bind_host, cport, &resolved) < 0 &&
                resolve_host_any(c->bind_host, cport, &resolved) == 0) {
                if (g_listen_family == WS_AF_INET6 && resolved.sa.sa_family == WS_AF_INET) {
                    union ws_sockaddr_any v6m;
                    ws_v4_to_v4mapped(&resolved.v4, &v6m.v6);
                    resolved = v6m;
                }
                if (!sockaddr_equal(&resolved, &c->client_addr)) {
                    int16_t slot = (int16_t)i;
                    hash_remove_client(slot);
                    c->client_addr = resolved;
                    hash_insert_client(slot);
                }
            }
        }
    }
}

/* ============================================================================
 * 8. Configuration & CLI Argument Parser (Full Parity with v1.6 + IPv6)
 * ============================================================================ */
static void config_set_defaults(struct obfuscator_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    memcpy(cfg->section_name, "main", 5);
    cfg->listen_port           = -1;
    cfg->max_clients           = MAX_CLIENTS_DEFAULT;
    cfg->idle_timeout          = IDLE_TIMEOUT_DEFAULT;
    cfg->in_timeout            = IN_TIMEOUT_DEFAULT;
    cfg->max_dummy_length_data = MAX_DUMMY_LENGTH_DATA_DEF;
    cfg->masking_type          = MASKING_NONE;
    cfg->masking_set           = 0;
    cfg->resolve_interval      = 300;
}

static int parse_uint(const char *s, uint32_t *out)
{
    if (!s || !*s)
        return -1;
    uint32_t v = 0;
    while (*s) {
        if (*s < '0' || *s > '9')
            return -1;
        v = v * 10 + (uint32_t)(*s - '0');
        s++;
    }
    *out = v;
    return 0;
}

static int parse_masking_name(struct obfuscator_config *cfg, const char *s)
{
    if (ci_strcmp(s, "NONE") == 0) {
        cfg->masking_type = MASKING_NONE;
        cfg->masking_set  = 1;
        return 0;
    }
    if (ci_strcmp(s, "STUN") == 0) {
        cfg->masking_type = MASKING_STUN;
        cfg->masking_set  = 1;
        return 0;
    }
    if (ci_strcmp(s, "AUTO") == 0) {
        cfg->masking_type = MASKING_AUTO;
        cfg->masking_set  = 0;
        return 0;
    }
    return -1;
}

static int parse_verbosity_name(const char *s, int *out)
{
    if (ci_strcmp(s, "ERRORS") == 0)   { *out = LL_ERROR; return 0; }
    if (ci_strcmp(s, "WARNINGS") == 0) { *out = LL_WARN;  return 0; }
    if (ci_strcmp(s, "INFO") == 0)     { *out = LL_INFO;  return 0; }
    if (ci_strcmp(s, "DEBUG") == 0)    { *out = LL_DEBUG; return 0; }
    if (ci_strcmp(s, "TRACE") == 0)    { *out = LL_TRACE; return 0; }
    return -1;
}

static int parse_static_bindings(struct obfuscator_config *cfg, const char *str)
{
    cfg->num_bindings = 0;
    const char *p = str;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',')
            p++;
        if (!*p)
            break;
        char entry[128];
        int len = 0;
        while (*p && *p != ',' && len < (int)sizeof(entry) - 1)
            entry[len++] = *p++;
        entry[len] = '\0';
        while (len > 0 && (entry[len - 1] == ' ' || entry[len - 1] == '\t'))
            entry[--len] = '\0';

        char *last_colon = strrchr(entry, ':');
        if (!last_colon)
            return -1;
        *last_colon = '\0';
        uint32_t lport = 0;
        if (parse_uint(last_colon + 1, &lport) < 0 || lport == 0 || lport > 65535)
            return -1;

        if (cfg->num_bindings >= MAX_STATIC_BINDINGS)
            return -1;
        struct static_binding *b = &cfg->bindings[cfg->num_bindings];
        uint16_t tmp_port = 0;
        if (parse_and_resolve_host_port(entry, b->bind_host, sizeof(b->bind_host),
                                        &tmp_port, &b->client_addr) < 0)
            return -1;
        b->src_port = (uint16_t)lport;
        cfg->num_bindings++;
    }
    cfg->is_static_set = (cfg->num_bindings > 0) ? 1 : 0;
    return 0;
}

static int apply_kv_option(struct obfuscator_config *cfg, const char *key, const char *val)
{
    uint32_t u = 0;
    if (strcmp(key, "source-if") == 0) {
        size_t l = strlen(val);
        if (l >= sizeof(cfg->listen_ip)) return -1;
        memcpy(cfg->listen_ip, val, l + 1);
        return 0;
    }
    if (strcmp(key, "source-lport") == 0) {
        if (parse_uint(val, &u) < 0 || u > 65535) return -1;
        cfg->listen_port = (int)u;
        return 0;
    }
    if (strcmp(key, "target") == 0) {
        return parse_and_resolve_host_port(val, cfg->forward_host,
                                           sizeof(cfg->forward_host),
                                           &cfg->forward_port,
                                           &cfg->forward_addr);
    }
    if (strcmp(key, "key") == 0) {
        size_t l = strlen(val);
        if (l == 0 || l > MAX_KEY_LENGTH) return -1;
        memcpy(cfg->key, val, l + 1);
        cfg->key_len = (int)l;
        return 0;
    }
    if (strcmp(key, "masking") == 0) {
        return parse_masking_name(cfg, val);
    }
    if (strcmp(key, "static-bindings") == 0) {
        return parse_static_bindings(cfg, val);
    }
    if (strcmp(key, "max-clients") == 0) {
        if (parse_uint(val, &u) < 0 || u == 0) return -1;
        cfg->max_clients = (u > MAX_CLIENTS_HARD) ? MAX_CLIENTS_HARD : (int)u;
        return 0;
    }
    if (strcmp(key, "idle-timeout") == 0) {
        if (parse_uint(val, &u) < 0) return -1;
        cfg->idle_timeout = u * 1000U;
        return 0;
    }
    if (strcmp(key, "in-timeout") == 0) {
        if (parse_uint(val, &u) < 0) return -1;
        cfg->in_timeout = u * 1000U;
        return 0;
    }
    if (strcmp(key, "max-dummy") == 0) {
        if (parse_uint(val, &u) < 0 || u > MAX_DUMMY_LENGTH_TOTAL) return -1;
        cfg->max_dummy_length_data = (int)u;
        return 0;
    }
    if (strcmp(key, "fwmark") == 0) {
        if (parse_uint(val, &u) < 0) return -1;
        cfg->fwmark = u;
        return 0;
    }
    if (strcmp(key, "allow-clean") == 0) {
        if (!val || !val[0] || strcmp(val, "1") == 0 ||
            ci_strcmp(val, "true") == 0 || ci_strcmp(val, "yes") == 0) {
            cfg->allow_clean = 1;
        } else {
            cfg->allow_clean = 0;
        }
        return 0;
    }
    if (strcmp(key, "verbose") == 0) {
        return parse_verbosity_name(val, &g_verbose);
    }
    if (strcmp(key, "log-file") == 0) {
        size_t l = strlen(val);
        if (l >= sizeof(g_log_file_path)) return -1;
        memcpy(g_log_file_path, val, l + 1);
        return log_open_file(g_log_file_path);
    }
    if (strcmp(key, "log-timestamps") == 0) {
        g_log_timestamps = 1;
        return 0;
    }
    if (strcmp(key, "resolve-interval") == 0) {
        if (parse_uint(val, &u) < 0) return -1;
        cfg->resolve_interval = (int)u;
        return 0;
    }
    return -1;
}

static void print_help(void)
{
    static const char help_txt[] =
        "Usage: wg-obfuscator [OPTION...]\n"
        "WireGuard MyST-based obfuscator v" WG_OBFUSCATOR_VERSION " (freestanding IPv4/IPv6 Dual-Stack)\n\n"
        "  -c, --config=<file>             Read configuration from file\n"
        "  -i, --source-if=<ip>            Source IPv4/IPv6 to listen on (default: [::] dual-stack)\n"
        "  -p, --source-lport=<port>       Source port to listen on\n"
        "  -t, --target=<host:port>        Target WireGuard IPv4/[IPv6]/host and port\n"
        "  -k, --key=<key>                 Obfuscation key\n"
        "  -a, --masking=<type>            Masking type: NONE, STUN, AUTO\n"
        "  -b, --static-bindings=<list>    host:port:localport,... static bindings\n"
        "  -m, --max-clients=<num>         Maximum number of clients (default: 64)\n"
        "  -l, --idle-timeout=<sec>        Idle timeout in seconds (default: 300)\n"
        "  -n, --in-timeout=<sec>          Incoming traffic timeout in seconds (default: 180)\n"
        "  -d, --max-dummy=<bytes>         Max dummy length for data packets (default: 4)\n"
        "  -f, --fwmark=<mark>             Firewall mark for sockets\n"
        "  -e, --allow-clean               Allow unobfuscated packets\n"
        "  -v, --verbose=<level>           ERRORS, WARNINGS, INFO, DEBUG, TRACE\n"
        "  -L, --log-file=<path>           Write logs to file\n"
        "  -T, --log-timestamps            Enable timestamps in logs\n"
        "  -R, --resolve-interval=<sec>    DNS re-resolve interval in seconds\n"
        "  -?, --help                      Give this help list\n"
        "  -V, --version                   Print program version\n";
    write(STDOUT_FILENO, help_txt, sizeof(help_txt) - 1);
}

static void print_version(void)
{
    static const char ver_txt[] = "wg-obfuscator v" WG_OBFUSCATOR_VERSION "\n";
    write(STDOUT_FILENO, ver_txt, sizeof(ver_txt) - 1);
}

static struct obfuscator_config g_sections[MAX_SECTIONS];
static int g_num_sections;

static int parse_config_file(const char *path)
{
    int fd = open(path, O_RDONLY, 0);
    if (fd < 0) {
        log_msg_str(LL_ERROR, "Cannot open config file: ", path, NULL);
        return -1;
    }
    static char fbuf[4096];
    ssize_t n = read(fd, fbuf, sizeof(fbuf) - 1);
    close(fd);
    if (n < 0)
        return -1;
    fbuf[n] = '\0';

    struct obfuscator_config *cur = NULL;
    char *p = fbuf;
    while (*p) {
        char *line = p;
        while (*p && *p != '\n')
            p++;
        if (*p == '\n')
            *p++ = '\0';

        char *hash = strchr(line, '#');
        if (hash)
            *hash = '\0';

        while (*line == ' ' || *line == '\t' || *line == '\r')
            line++;
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == ' ' || line[len - 1] == '\t' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (len == 0)
            continue;

        if (line[0] == '[') {
            char *close_br = strchr(line, ']');
            if (!close_br)
                return -1;
            *close_br = '\0';
            if (g_num_sections >= MAX_SECTIONS)
                return -1;
            cur = &g_sections[g_num_sections++];
            config_set_defaults(cur);
            size_t slen = strlen(line + 1);
            if (slen >= sizeof(cur->section_name))
                slen = sizeof(cur->section_name) - 1;
            memcpy(cur->section_name, line + 1, slen);
            cur->section_name[slen] = '\0';
            continue;
        }

        if (!cur) {
            cur = &g_sections[g_num_sections++];
            config_set_defaults(cur);
        }

        char *eq = strchr(line, '=');
        if (!eq)
            return -1;
        *eq = '\0';
        char *k = line;
        char *v = eq + 1;
        size_t kl = strlen(k);
        while (kl > 0 && (k[kl - 1] == ' ' || k[kl - 1] == '\t'))
            k[--kl] = '\0';
        while (*v == ' ' || *v == '\t')
            v++;
        if (apply_kv_option(cur, k, v) < 0) {
            log_msg_str(LL_ERROR, "Invalid config option: ", k, NULL);
            return -1;
        }
    }
    return 0;
}

static const char *short_opt_to_key(char c)
{
    switch (c) {
    case 'i': return "source-if";
    case 'p': return "source-lport";
    case 't': return "target";
    case 'k': return "key";
    case 'a': return "masking";
    case 'b': return "static-bindings";
    case 'm': return "max-clients";
    case 'l': return "idle-timeout";
    case 'n': return "in-timeout";
    case 'd': return "max-dummy";
    case 'f': return "fwmark";
    case 'e': return "allow-clean";
    case 'v': return "verbose";
    case 'L': return "log-file";
    case 'T': return "log-timestamps";
    case 'R': return "resolve-interval";
    default:  return NULL;
    }
}

/* ============================================================================
 * 9. Signal Handlers
 * ============================================================================ */
static void on_term_signal(int sig)
{
    g_stop_flag = sig;
}

static void on_sighup(int sig)
{
    (void)sig;
    g_sighup_flag = 1;
}

/* ============================================================================
 * 10. Core Bidirectional Event Loop (IPv4 & IPv6 Dual-Stack)
 * ============================================================================ */
static void handle_listen_sock_packet(uint64_t now)
{
    uint8_t *buffer = g_pkt_raw + PREBUFFER_SIZE;
    union ws_sockaddr_any sender_addr;
    memset(&sender_addr, 0, sizeof(sender_addr));
    uint32_t sender_len = sizeof(sender_addr);

    ssize_t rlen = ws_recvfrom(g_listen_sock, buffer, BUFFER_SIZE,
                               WS_MSG_TRUNC | WS_MSG_DONTWAIT,
                               &sender_addr, &sender_len);
    if (rlen <= 0 || rlen > BUFFER_SIZE)
        return;

    /* Clear sin6_flowinfo on incoming IPv6 packets so hash/equality depends only on IP + port */
    if (sender_addr.sa.sa_family == WS_AF_INET6)
        sender_addr.v6.sin6_flowinfo = 0;

    int length = (int)rlen;
    struct client_entry *client = find_client(&sender_addr);

    uint8_t obfuscated = (length >= 4) && is_obfuscated(buffer);
    uint8_t detected_masking = (g_cfg.masking_type == MASKING_STUN) ? MASKING_STUN : MASKING_NONE;

    if (obfuscated) {
        if (!client && !g_cfg.masking_set) {
            uint8_t *saved_buf = buffer;
            int r = stun_on_data_unwrap(&buffer, length, &sender_addr, 1, -1);
            if (r < 0) {
                buffer = saved_buf;
                detected_masking = MASKING_NONE;
            } else if (r == 0) {
                return;
            } else {
                length = r;
                detected_masking = MASKING_STUN;
            }
        } else {
            uint8_t active_masking = client ? client->masking_type : detected_masking;
            if (active_masking == MASKING_STUN) {
                int r = stun_on_data_unwrap(&buffer, length, &sender_addr, 1,
                                            client ? client->server_sock : -1);
                if (r <= 0)
                    return;
                length = r;
            }
        }
    }

    if (length < 4)
        return;

    uint8_t version = client ? client->version : OBFUSCATION_VERSION;

    if (obfuscated) {
        int orig_len = length;
        length = decode_packet(buffer, length, g_cfg.key, g_cfg.key_len, &version);
        if (length < 4 || length > orig_len)
            return;
    }

    uint32_t pkt_type = WG_TYPE(buffer);

    if (pkt_type == WG_TYPE_HANDSHAKE) {
        if (!client) {
            client = new_client_entry(&sender_addr, 0, NULL);
            if (!client)
                return;
            client->last_activity_time = now;
            client->last_incoming_time = 0;
            client->masking_type = detected_masking;
        }
        if (g_cfg.allow_clean) {
            client->client_clean = !obfuscated;
            if (client->client_clean)
                client->masking_type = MASKING_NONE;
        }
        if (!obfuscated && !client->client_clean && client->masking_type == MASKING_STUN) {
            stun_send_binding_req_to_server(client->server_sock);
        }
        client->handshake_direction = DIR_CLIENT_TO_SERVER;
        client->last_handshake_request_time = now;
    } else if (pkt_type == WG_TYPE_HANDSHAKE_RESP) {
        if (!client)
            return;
        if (now - client->last_handshake_request_time > HANDSHAKE_TIMEOUT)
            return;
        if (client->handshake_direction != DIR_SERVER_TO_CLIENT)
            return;

        if (!client->handshaked) {
            char lbuf[256];
            struct strbuf sb;
            log_begin(&sb, lbuf, sizeof(lbuf), LL_INFO);
            sb_puts(&sb, "Handshake established with ");
            sb_put_addr(&sb, &sender_addr);
            sb_puts(&sb, " (reverse, local port ");
            sb_putu(&sb, client->our_port);
            sb_putc(&sb, ')');
            log_flush(&sb);
        }
        client->handshaked        = 1;
        client->client_obfuscated = obfuscated;
        client->server_obfuscated = !obfuscated;
        client->last_handshake_time = now;
    } else if (!client || !client->handshaked) {
        return;
    }

    if (version < client->version)
        client->version = version;

    if (!obfuscated && !client->client_clean) {
        length = encode_packet(buffer, length, g_cfg.key, g_cfg.key_len,
                               client->version, g_cfg.max_dummy_length_data);
        if (length < 4)
            return;
        if (client->masking_type == MASKING_STUN) {
            length = stun_wrap(&buffer, length);
            if (length < 0)
                return;
        }
    }

    if (ws_send(client->server_sock, buffer, (size_t)length, 0) >= 0)
        client->last_activity_time = now;
}

static void handle_client_sock_packet(struct client_entry *client, uint64_t now)
{
    uint8_t *buffer = g_pkt_raw + PREBUFFER_SIZE;
    ssize_t rlen = ws_recv(client->server_sock, buffer, BUFFER_SIZE,
                           WS_MSG_TRUNC | WS_MSG_DONTWAIT);
    if (rlen <= 0 || rlen > BUFFER_SIZE)
        return;

    int length = (int)rlen;
    uint8_t obfuscated = (length >= 4) && is_obfuscated(buffer);

    if (obfuscated && client->masking_type == MASKING_STUN) {
        int r = stun_on_data_unwrap(&buffer, length, &g_cfg.forward_addr,
                                    0, client->server_sock);
        if (r <= 0)
            return;
        length = r;
    }

    if (length < 4)
        return;

    uint8_t version = client->version;
    if (obfuscated) {
        int orig_len = length;
        length = decode_packet(buffer, length, g_cfg.key, g_cfg.key_len, &version);
        if (length < 4 || length > orig_len)
            return;
    }

    uint32_t pkt_type = WG_TYPE(buffer);

    if (pkt_type == WG_TYPE_HANDSHAKE) {
        if (!obfuscated && !client->client_clean && client->masking_type == MASKING_STUN) {
            stun_send_binding_req_to_client(&client->client_addr);
        }
        client->handshake_direction = DIR_SERVER_TO_CLIENT;
        client->last_handshake_request_time = now;
    } else if (pkt_type == WG_TYPE_HANDSHAKE_RESP) {
        if (now - client->last_handshake_request_time > HANDSHAKE_TIMEOUT)
            return;
        if (client->handshake_direction != DIR_CLIENT_TO_SERVER)
            return;

        if (!client->handshaked) {
            char lbuf[256];
            struct strbuf sb;
            log_begin(&sb, lbuf, sizeof(lbuf), LL_INFO);
            sb_puts(&sb, "Handshake established with ");
            sb_put_addr(&sb, &client->client_addr);
            sb_puts(&sb, " (direct, local port ");
            sb_putu(&sb, client->our_port);
            sb_putc(&sb, ')');
            log_flush(&sb);
        }
        client->handshaked        = 1;
        client->client_obfuscated = !obfuscated && !client->client_clean;
        client->server_obfuscated = obfuscated;
        client->last_handshake_time = now;
    } else if (!client->handshaked) {
        return;
    }

    if (version < client->version)
        client->version = version;

    if (!obfuscated && !client->client_clean) {
        length = encode_packet(buffer, length, g_cfg.key, g_cfg.key_len,
                               client->version, g_cfg.max_dummy_length_data);
        if (length < 4)
            return;
        if (client->masking_type == MASKING_STUN) {
            length = stun_wrap(&buffer, length);
            if (length < 0)
                return;
        }
    }

    if (ws_sendto(g_listen_sock, buffer, (size_t)length, 0,
                  &client->client_addr, ws_sockaddr_len(&client->client_addr)) >= 0) {
        client->last_activity_time = now;
        client->last_incoming_time = now;
    }
}

static void run_periodic_timers(uint64_t now, uint64_t *last_resolve_time)
{
    for (int i = 0; i < MAX_CLIENTS_HARD; i++) {
        struct client_entry *c = &g_clients[i];
        if (!c->active)
            continue;

        uint8_t idle = (now - c->last_activity_time >= g_cfg.idle_timeout);
        uint8_t incoming_to = (g_cfg.in_timeout > 0 &&
                               now - c->last_incoming_time >= g_cfg.in_timeout);
        uint8_t handshake_to = (!c->handshaked &&
                                now - c->last_activity_time >= HANDSHAKE_TIMEOUT);

        if ((idle || incoming_to || handshake_to) && !c->is_static) {
            delete_client(c);
            continue;
        }

        if (c->masking_type == MASKING_STUN &&
            now - c->last_masking_timer_time >= STUN_TIMER_INTERVAL_MS) {
            c->last_masking_timer_time = now;
            if (c->client_obfuscated)
                stun_send_binding_req_to_client(&c->client_addr);
            if (c->server_obfuscated)
                stun_send_binding_req_to_server(c->server_sock);
        }
    }

    if (g_cfg.resolve_interval > 0 &&
        now - *last_resolve_time >= (uint64_t)g_cfg.resolve_interval * 1000ULL) {
        refresh_hostnames(0);
        *last_resolve_time = now;
    }
}

static int run_instance(void)
{
    if (g_cfg.listen_port < 0) {
        log_msg(LL_ERROR, "'source-lport' is not set");
        return 1;
    }
    if (g_cfg.forward_port == 0) {
        log_msg(LL_ERROR, "'target' is not set");
        return 1;
    }
    if (g_cfg.key_len <= 0) {
        log_msg(LL_ERROR, "'key' is not set");
        return 1;
    }
    if (g_cfg.allow_clean && g_cfg.is_static_set) {
        log_msg(LL_ERROR, "'allow-clean' cannot be used together with 'static-bindings'");
        return 1;
    }

    ws_rand_seed();
    init_crc_tables();
    client_table_init();

    g_epoll_fd = ws_epoll_create();
    if (g_epoll_fd < 0) {
        log_msg_err(LL_ERROR, "epoll_create1 failed", -g_epoll_fd);
        return 1;
    }

    union ws_sockaddr_any listen_sa;
    memset(&listen_sa, 0, sizeof(listen_sa));
    uint16_t lport_net = ws_htons((uint16_t)g_cfg.listen_port);

    if (g_cfg.listen_ip[0]) {
        if (resolve_host_any(g_cfg.listen_ip, lport_net, &listen_sa) < 0) {
            log_msg_str(LL_ERROR, "Invalid source-if: ", g_cfg.listen_ip, NULL);
            return 1;
        }
        g_listen_family = listen_sa.sa.sa_family;
        g_listen_sock = ws_socket(g_listen_family, WS_SOCK_DGRAM, 0);
        if (g_listen_sock < 0) {
            log_msg_err(LL_ERROR, "socket() failed", -g_listen_sock);
            return 1;
        }
        if (g_listen_family == WS_AF_INET6) {
            /* Enable Dual-Stack if bound to wildcard [::] */
            static const uint8_t zero16[16] = {0};
            int v6only = (memcmp(listen_sa.v6.sin6_addr, zero16, 16) == 0) ? 0 : 1;
            ws_setsockopt_int(g_listen_sock, WS_IPPROTO_IPV6, WS_IPV6_V6ONLY, v6only);
        }
    } else {
        /* Default: try Dual-Stack IPv6 ([::] with IPV6_V6ONLY=0), fallback to IPv4 0.0.0.0 */
        g_listen_sock = ws_socket(WS_AF_INET6, WS_SOCK_DGRAM, 0);
        if (g_listen_sock >= 0) {
            g_listen_family = WS_AF_INET6;
            ws_setsockopt_int(g_listen_sock, WS_IPPROTO_IPV6, WS_IPV6_V6ONLY, 0);
            listen_sa.v6.sin6_family = WS_AF_INET6;
            listen_sa.v6.sin6_port   = lport_net;
        } else {
            g_listen_family = WS_AF_INET;
            g_listen_sock = ws_socket(WS_AF_INET, WS_SOCK_DGRAM, 0);
            if (g_listen_sock < 0) {
                log_msg_err(LL_ERROR, "socket() failed", -g_listen_sock);
                return 1;
            }
            listen_sa.v4.sin_family = WS_AF_INET;
            listen_sa.v4.sin_port   = lport_net;
        }
    }

    ws_setsockopt_int(g_listen_sock, WS_SOL_SOCKET, WS_SO_REUSEADDR, 1);
    ws_apply_pmtud(g_listen_sock, g_listen_family);
    if (g_cfg.fwmark > 0)
        ws_setsockopt_int(g_listen_sock, WS_SOL_SOCKET, WS_SO_MARK, (int)g_cfg.fwmark);

    if (ws_bind(g_listen_sock, &listen_sa, ws_sockaddr_len(&listen_sa)) < 0) {
        log_msg(LL_ERROR, "Failed to bind listen socket");
        return 1;
    }
    ws_set_nonblock(g_listen_sock);

    struct ws_epoll_event ev;
    ev.events   = WS_EPOLLIN;
    ev.data.ptr = NULL;
    if (ws_epoll_ctl(g_epoll_fd, WS_EPOLL_CTL_ADD, g_listen_sock, &ev) < 0) {
        log_msg(LL_ERROR, "Failed to add listen socket to epoll");
        return 1;
    }

    for (int i = 0; i < g_cfg.num_bindings; i++) {
        struct static_binding *b = &g_cfg.bindings[i];
        /* If listen socket is Dual-Stack AF_INET6 and static binding is IPv4, map to ::ffff:a.b.c.d */
        if (g_listen_family == WS_AF_INET6 && b->client_addr.sa.sa_family == WS_AF_INET) {
            union ws_sockaddr_any v6m;
            ws_v4_to_v4mapped(&b->client_addr.v4, &v6m.v6);
            b->client_addr = v6m;
        }
        struct client_entry *c = new_client_entry(&b->client_addr, b->src_port, b->bind_host);
        if (!c) {
            log_msg(LL_ERROR, "Failed to create static binding");
            return 1;
        }
        char buf[192];
        struct strbuf sb;
        log_begin(&sb, buf, sizeof(buf), LL_INFO);
        sb_puts(&sb, "Added static binding: ");
        sb_put_addr(&sb, &b->client_addr);
        sb_puts(&sb, " <-> :");
        sb_putu(&sb, b->src_port);
        log_flush(&sb);
    }

    {
        char buf[256];
        struct strbuf sb;
        log_begin(&sb, buf, sizeof(buf), LL_INFO);
        sb_puts(&sb, "WireGuard obfuscator v" WG_OBFUSCATOR_VERSION " started on ");
        sb_put_addr(&sb, &listen_sa);
        sb_puts(&sb, " -> ");
        sb_put_addr(&sb, &g_cfg.forward_addr);
        log_flush(&sb);
    }

    uint64_t last_cleanup_time = ws_clock_ms();
    uint64_t last_resolve_time = last_cleanup_time;
    struct ws_epoll_event events[32];

    while (!g_stop_flag) {
        if (g_sighup_flag) {
            g_sighup_flag = 0;
            log_reopen();
            refresh_hostnames(1);
        }

        int nfds = ws_epoll_wait(g_epoll_fd, events, 32, ITERATE_INTERVAL);
        uint64_t now = ws_clock_ms();

        if (nfds > 0) {
            for (int i = 0; i < nfds; i++) {
                if (events[i].data.ptr == NULL) {
                    handle_listen_sock_packet(now);
                } else {
                    struct client_entry *c = (struct client_entry *)events[i].data.ptr;
                    if (c->active)
                        handle_client_sock_packet(c, now);
                }
            }
        }

        if (now - last_cleanup_time >= ITERATE_INTERVAL) {
            run_periodic_timers(now, &last_resolve_time);
            last_cleanup_time = now;
        }
    }

    for (int i = 0; i < MAX_CLIENTS_HARD; i++) {
        if (g_clients[i].active)
            delete_client(&g_clients[i]);
    }
    if (g_listen_sock >= 0)
        close(g_listen_sock);
    if (g_epoll_fd >= 0)
        close(g_epoll_fd);

    log_msg(LL_INFO, "Stopped cleanly.");
    return 0;
}

/* ============================================================================
 * 11. Main Entry Point & Multi-Section Fork Supervisor
 * ============================================================================ */
int main(int argc, char **argv, char **envp)
{
    (void)envp;
    ws_ignore_sigpipe();
    ws_sigaction(SIGINT,  on_term_signal);
    ws_sigaction(SIGTERM, on_term_signal);
    ws_sigaction(SIGHUP,  on_sighup);

    config_set_defaults(&g_cfg);
    const char *config_path = NULL;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "-?") == 0 || strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            print_help();
            return 0;
        }
        if (strcmp(arg, "-V") == 0 || strcmp(arg, "--version") == 0) {
            print_version();
            return 0;
        }
        if (strncmp(arg, "--", 2) == 0) {
            const char *opt = arg + 2;
            const char *eq = strchr(opt, '=');
            char keybuf[64];
            const char *val = NULL;
            if (eq) {
                size_t kl = (size_t)(eq - opt);
                if (kl >= sizeof(keybuf)) return 1;
                memcpy(keybuf, opt, kl);
                keybuf[kl] = '\0';
                val = eq + 1;
            } else {
                size_t kl = strlen(opt);
                if (kl >= sizeof(keybuf)) return 1;
                memcpy(keybuf, opt, kl + 1);
                if (strcmp(keybuf, "allow-clean") == 0 || strcmp(keybuf, "log-timestamps") == 0) {
                    val = "1";
                } else if (i + 1 < argc) {
                    val = argv[++i];
                } else {
                    log_msg_str(LL_ERROR, "Missing argument for --", keybuf, NULL);
                    return 1;
                }
            }
            if (strcmp(keybuf, "config") == 0) {
                config_path = val;
            } else if (apply_kv_option(&g_cfg, keybuf, val) < 0) {
                log_msg_str(LL_ERROR, "Invalid CLI option --", keybuf, NULL);
                return 1;
            }
        } else if (arg[0] == '-' && arg[1] != '\0') {
            char c = arg[1];
            const char *val = NULL;
            if (c == 'e' || c == 'T') {
                val = "1";
            } else if (arg[2] != '\0') {
                val = (arg[2] == '=') ? (arg + 3) : (arg + 2);
            } else if (i + 1 < argc) {
                val = argv[++i];
            } else {
                log_msg(LL_ERROR, "Missing value for short option");
                return 1;
            }
            if (c == 'c') {
                config_path = val;
            } else {
                const char *k = short_opt_to_key(c);
                if (!k || apply_kv_option(&g_cfg, k, val) < 0) {
                    log_msg(LL_ERROR, "Invalid short CLI option");
                    return 1;
                }
            }
        }
    }

    if (config_path) {
        if (parse_config_file(config_path) < 0 || g_num_sections == 0)
            return 1;
        if (g_num_sections == 1) {
            g_cfg = g_sections[0];
            return run_instance();
        }
        for (int s = 0; s < g_num_sections; s++) {
            pid_t pid = fork();
            if (pid == 0) {
                g_cfg = g_sections[s];
                return run_instance();
            } else if (pid > 0) {
                g_child_pids[g_num_children++] = pid;
            } else {
                log_msg(LL_ERROR, "fork() failed for section");
            }
        }
        while (!g_stop_flag && g_num_children > 0) {
            if (g_sighup_flag) {
                g_sighup_flag = 0;
                log_reopen();
                for (int c = 0; c < g_num_children; c++) {
                    if (g_child_pids[c] > 0)
                        kill(g_child_pids[c], SIGHUP);
                }
            }
            int status = 0;
            pid_t done = waitpid(-1, &status, 0);
            if (done > 0) {
                for (int c = 0; c < g_num_children; c++) {
                    if (g_child_pids[c] == done)
                        g_child_pids[c] = 0;
                }
            }
        }
        for (int c = 0; c < g_num_children; c++) {
            if (g_child_pids[c] > 0) {
                kill(g_child_pids[c], SIGTERM);
                waitpid(g_child_pids[c], NULL, 0);
            }
        }
        return 0;
    }

    return run_instance();
}
