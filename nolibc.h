/* SPDX-License-Identifier: LGPL-2.1 OR MIT */
/*
 * Minimal Linux kernel-style nolibc.h for freestanding builds (-nostdlib)
 * Supports MIPS32 O32 (mips32el / mips32be) and x86_64.
 * Compatible with upstream Linux tools/include/nolibc/nolibc.h.
 */
#ifndef _NOLIBC_H
#define _NOLIBC_H

#define NOLIBC 1

/* Standard fixed-width and POSIX types */
typedef unsigned char      uint8_t;
typedef signed char        int8_t;
typedef unsigned short     uint16_t;
typedef signed short       int16_t;
typedef unsigned int       uint32_t;
typedef signed int         int32_t;
typedef unsigned long long uint64_t;
typedef signed long long   int64_t;

typedef __SIZE_TYPE__      size_t;
typedef __PTRDIFF_TYPE__   ssize_t;
typedef __UINTPTR_TYPE__   uintptr_t;
typedef __INTPTR_TYPE__    intptr_t;
typedef int                pid_t;
typedef long               off_t;
typedef long               time_t;

#ifndef NULL
#define NULL ((void *)0)
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#endif

/* errno definitions */
#define EPERM        1
#define ENOENT       2
#define ESRCH        3
#define EINTR        4
#define EIO          5
#define EBADF        9
#define ECHILD      10
#define EAGAIN      11
#define ENOMEM      12
#define EACCES      13
#define EFAULT      14
#define EBUSY       16
#define EEXIST      17
#define EINVAL      22
#define EMFILE      24
#define EPIPE       32

#if defined(__mips__)
#define EWOULDBLOCK 11
#define EINPROGRESS 150
#else
#define EWOULDBLOCK 11
#define EINPROGRESS 115
#endif

/* open() flags */
#define O_RDONLY     0
#define O_WRONLY     1
#define O_RDWR       2

#if defined(__mips__)
#define O_CREAT      0x0100
#define O_TRUNC      0x0200
#define O_APPEND     0x0008
#define O_NONBLOCK   0x0080
#else
#define O_CREAT      0x0040
#define O_TRUNC      0x0200
#define O_APPEND     0x0400
#define O_NONBLOCK   0x0800
#endif

/* Signals */
#define SIGHUP       1
#define SIGINT       2
#define SIGQUIT      3
#define SIGKILL      9
#define SIGPIPE     13
#define SIGALRM     14
#define SIGTERM     15
#if defined(__mips__)
#define SIGCHLD     18
#else
#define SIGCHLD     17
#endif

#define SIG_DFL      ((void (*)(int))0)
#define SIG_IGN      ((void (*)(int))1)

/* Syscall numbers */
#if defined(__mips__)
#define __NR_Linux          4000
#define __NR_syscall        (__NR_Linux +   0)
#define __NR_exit           (__NR_Linux +   1)
#define __NR_fork           (__NR_Linux +   2)
#define __NR_read           (__NR_Linux +   3)
#define __NR_write          (__NR_Linux +   4)
#define __NR_open           (__NR_Linux +   5)
#define __NR_close          (__NR_Linux +   6)
#define __NR_waitpid        (__NR_Linux +   7)
#define __NR_unlink         (__NR_Linux +  10)
#define __NR_time           (__NR_Linux +  13)
#define __NR_lseek          (__NR_Linux +  19)
#define __NR_getpid         (__NR_Linux +  20)
#define __NR_kill           (__NR_Linux +  37)
#define __NR_pipe           (__NR_Linux +  42)
#define __NR_fcntl          (__NR_Linux +  55)
#define __NR_gettimeofday   (__NR_Linux +  78)
#define __NR_wait4          (__NR_Linux + 114)
#define __NR_nanosleep      (__NR_Linux + 166)
#define __NR_poll           (__NR_Linux + 188)
#define __NR_bind           (__NR_Linux + 169)
#define __NR_connect        (__NR_Linux + 170)
#define __NR_getsockname    (__NR_Linux + 172)
#define __NR_recv           (__NR_Linux + 175)
#define __NR_recvfrom       (__NR_Linux + 176)
#define __NR_send           (__NR_Linux + 178)
#define __NR_sendto         (__NR_Linux + 180)
#define __NR_setsockopt     (__NR_Linux + 181)
#define __NR_socket         (__NR_Linux + 183)
#define __NR_rt_sigreturn   (__NR_Linux + 193)
#define __NR_rt_sigaction   (__NR_Linux + 194)
#define __NR_rt_sigprocmask (__NR_Linux + 195)
#define __NR_stat64         (__NR_Linux + 213)
#define __NR_epoll_create   (__NR_Linux + 248)
#define __NR_epoll_ctl      (__NR_Linux + 249)
#define __NR_epoll_wait     (__NR_Linux + 250)
#define __NR_clock_gettime  (__NR_Linux + 263)
#define __NR_openat         (__NR_Linux + 288)
#define __NR_epoll_create1  (__NR_Linux + 326)
#define __NR_getrandom      (__NR_Linux + 353)

#elif defined(__x86_64__)
#define __NR_read              0
#define __NR_write             1
#define __NR_open              2
#define __NR_close             3
#define __NR_stat              4
#define __NR_fstat             5
#define __NR_poll              7
#define __NR_lseek             8
#define __NR_rt_sigaction     13
#define __NR_rt_sigprocmask   14
#define __NR_rt_sigreturn     15
#define __NR_pipe             22
#define __NR_nanosleep        35
#define __NR_getpid           39
#define __NR_socket           41
#define __NR_connect          42
#define __NR_sendto           44
#define __NR_recvfrom         45
#define __NR_bind             49
#define __NR_getsockname      51
#define __NR_setsockopt       54
#define __NR_fork             57
#define __NR_exit             60
#define __NR_wait4            61
#define __NR_kill             62
#define __NR_fcntl            72
#define __NR_unlink           87
#define __NR_gettimeofday     96
#define __NR_time            201
#define __NR_epoll_create    213
#define __NR_clock_gettime   228
#define __NR_epoll_wait      232
#define __NR_epoll_ctl       233
#define __NR_openat          257
#define __NR_epoll_create1   291
#define __NR_getrandom       318
#endif

static int errno;

/* Architecture-specific raw syscalls */
#if defined(__mips__)

#define _NOLIBC_SYSCALL_CLOBBERS \
    "$1", "$3", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", \
    "$24", "$25", "hi", "lo", "memory"

#define my_syscall0(num) ({                                                   \
    register long _num __asm__("v0") = (num);                                 \
    register long _err __asm__("a3");                                         \
    __asm__ volatile ("syscall\n"                                             \
                      : "+r"(_num), "=r"(_err)                                \
                      :                                                       \
                      : _NOLIBC_SYSCALL_CLOBBERS);                            \
    _err ? -_num : _num;                                                      \
})

#define my_syscall1(num, arg1) ({                                             \
    register long _num __asm__("v0") = (num);                                 \
    register long _a1  __asm__("a0") = (long)(arg1);                          \
    register long _err __asm__("a3");                                         \
    __asm__ volatile ("syscall\n"                                             \
                      : "+r"(_num), "=r"(_err), "+r"(_a1)                     \
                      :                                                       \
                      : _NOLIBC_SYSCALL_CLOBBERS);                            \
    _err ? -_num : _num;                                                      \
})

#define my_syscall2(num, arg1, arg2) ({                                       \
    register long _num __asm__("v0") = (num);                                 \
    register long _a1  __asm__("a0") = (long)(arg1);                          \
    register long _a2  __asm__("a1") = (long)(arg2);                          \
    register long _err __asm__("a3");                                         \
    __asm__ volatile ("syscall\n"                                             \
                      : "+r"(_num), "=r"(_err), "+r"(_a1), "+r"(_a2)          \
                      :                                                       \
                      : _NOLIBC_SYSCALL_CLOBBERS);                            \
    _err ? -_num : _num;                                                      \
})

#define my_syscall3(num, arg1, arg2, arg3) ({                                 \
    register long _num __asm__("v0") = (num);                                 \
    register long _a1  __asm__("a0") = (long)(arg1);                          \
    register long _a2  __asm__("a1") = (long)(arg2);                          \
    register long _a3  __asm__("a2") = (long)(arg3);                          \
    register long _err __asm__("a3");                                         \
    __asm__ volatile ("syscall\n"                                             \
                      : "+r"(_num), "=r"(_err), "+r"(_a1), "+r"(_a2),         \
                        "+r"(_a3)                                             \
                      :                                                       \
                      : _NOLIBC_SYSCALL_CLOBBERS);                            \
    _err ? -_num : _num;                                                      \
})

#define my_syscall4(num, arg1, arg2, arg3, arg4) ({                           \
    register long _num __asm__("v0") = (num);                                 \
    register long _a1  __asm__("a0") = (long)(arg1);                          \
    register long _a2  __asm__("a1") = (long)(arg2);                          \
    register long _a3  __asm__("a2") = (long)(arg3);                          \
    register long _a4  __asm__("a3") = (long)(arg4);                          \
    __asm__ volatile ("syscall\n"                                             \
                      : "+r"(_num), "+r"(_a4), "+r"(_a1), "+r"(_a2),          \
                        "+r"(_a3)                                             \
                      :                                                       \
                      : _NOLIBC_SYSCALL_CLOBBERS);                            \
    _a4 ? -_num : _num;                                                       \
})

#define my_syscall5(num, arg1, arg2, arg3, arg4, arg5) ({                     \
    register long _num __asm__("v0") = (num);                                 \
    register long _a1  __asm__("a0") = (long)(arg1);                          \
    register long _a2  __asm__("a1") = (long)(arg2);                          \
    register long _a3  __asm__("a2") = (long)(arg3);                          \
    register long _a4  __asm__("a3") = (long)(arg4);                          \
    register long _a5  = (long)(arg5);                                        \
    __asm__ volatile (                                                        \
        ".set push\n"                                                         \
        ".set noreorder\n"                                                    \
        "addiu $sp, $sp, -32\n"                                               \
        "sw %5, 16($sp)\n"                                                    \
        "syscall\n"                                                           \
        "addiu $sp, $sp, 32\n"                                                \
        ".set pop\n"                                                          \
        : "+r"(_num), "+r"(_a4), "+r"(_a1), "+r"(_a2), "+r"(_a3)              \
        : "r"(_a5)                                                            \
        : _NOLIBC_SYSCALL_CLOBBERS);                                          \
    _a4 ? -_num : _num;                                                       \
})

#define my_syscall6(num, arg1, arg2, arg3, arg4, arg5, arg6) ({               \
    register long _num __asm__("v0") = (num);                                 \
    register long _a1  __asm__("a0") = (long)(arg1);                          \
    register long _a2  __asm__("a1") = (long)(arg2);                          \
    register long _a3  __asm__("a2") = (long)(arg3);                          \
    register long _a4  __asm__("a3") = (long)(arg4);                          \
    register long _a5  = (long)(arg5);                                        \
    register long _a6  = (long)(arg6);                                        \
    __asm__ volatile (                                                        \
        ".set push\n"                                                         \
        ".set noreorder\n"                                                    \
        "addiu $sp, $sp, -32\n"                                               \
        "sw %5, 16($sp)\n"                                                    \
        "sw %6, 20($sp)\n"                                                    \
        "syscall\n"                                                           \
        "addiu $sp, $sp, 32\n"                                                \
        ".set pop\n"                                                          \
        : "+r"(_num), "+r"(_a4), "+r"(_a1), "+r"(_a2), "+r"(_a3)              \
        : "r"(_a5), "r"(_a6)                                                  \
        : _NOLIBC_SYSCALL_CLOBBERS);                                          \
    _a4 ? -_num : _num;                                                       \
})

#elif defined(__x86_64__)

#define my_syscall0(num) ({                                                   \
    long _ret;                                                                \
    register long _num __asm__("rax") = (num);                                \
    __asm__ volatile ("syscall\n"                                             \
                      : "=a"(_ret)                                            \
                      : "0"(_num)                                             \
                      : "rcx", "r11", "memory", "cc");                        \
    _ret;                                                                     \
})

#define my_syscall1(num, arg1) ({                                             \
    long _ret;                                                                \
    register long _num __asm__("rax") = (num);                                \
    register long _a1  __asm__("rdi") = (long)(arg1);                         \
    __asm__ volatile ("syscall\n"                                             \
                      : "=a"(_ret)                                            \
                      : "0"(_num), "r"(_a1)                                   \
                      : "rcx", "r11", "memory", "cc");                        \
    _ret;                                                                     \
})

#define my_syscall2(num, arg1, arg2) ({                                       \
    long _ret;                                                                \
    register long _num __asm__("rax") = (num);                                \
    register long _a1  __asm__("rdi") = (long)(arg1);                         \
    register long _a2  __asm__("rsi") = (long)(arg2);                         \
    __asm__ volatile ("syscall\n"                                             \
                      : "=a"(_ret)                                            \
                      : "0"(_num), "r"(_a1), "r"(_a2)                         \
                      : "rcx", "r11", "memory", "cc");                        \
    _ret;                                                                     \
})

#define my_syscall3(num, arg1, arg2, arg3) ({                                 \
    long _ret;                                                                \
    register long _num __asm__("rax") = (num);                                \
    register long _a1  __asm__("rdi") = (long)(arg1);                         \
    register long _a2  __asm__("rsi") = (long)(arg2);                         \
    register long _a3  __asm__("rdx") = (long)(arg3);                         \
    __asm__ volatile ("syscall\n"                                             \
                      : "=a"(_ret)                                            \
                      : "0"(_num), "r"(_a1), "r"(_a2), "r"(_a3)               \
                      : "rcx", "r11", "memory", "cc");                        \
    _ret;                                                                     \
})

#define my_syscall4(num, arg1, arg2, arg3, arg4) ({                           \
    long _ret;                                                                \
    register long _num __asm__("rax") = (num);                                \
    register long _a1  __asm__("rdi") = (long)(arg1);                         \
    register long _a2  __asm__("rsi") = (long)(arg2);                         \
    register long _a3  __asm__("rdx") = (long)(arg3);                         \
    register long _a4  __asm__("r10") = (long)(arg4);                         \
    __asm__ volatile ("syscall\n"                                             \
                      : "=a"(_ret)                                            \
                      : "0"(_num), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4)     \
                      : "rcx", "r11", "memory", "cc");                        \
    _ret;                                                                     \
})

#define my_syscall5(num, arg1, arg2, arg3, arg4, arg5) ({                     \
    long _ret;                                                                \
    register long _num __asm__("rax") = (num);                                \
    register long _a1  __asm__("rdi") = (long)(arg1);                         \
    register long _a2  __asm__("rsi") = (long)(arg2);                         \
    register long _a3  __asm__("rdx") = (long)(arg3);                         \
    register long _a4  __asm__("r10") = (long)(arg4);                         \
    register long _a5  __asm__("r8")  = (long)(arg5);                         \
    __asm__ volatile ("syscall\n"                                             \
                      : "=a"(_ret)                                            \
                      : "0"(_num), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4),    \
                        "r"(_a5)                                              \
                      : "rcx", "r11", "memory", "cc");                        \
    _ret;                                                                     \
})

#define my_syscall6(num, arg1, arg2, arg3, arg4, arg5, arg6) ({               \
    long _ret;                                                                \
    register long _num __asm__("rax") = (num);                                \
    register long _a1  __asm__("rdi") = (long)(arg1);                         \
    register long _a2  __asm__("rsi") = (long)(arg2);                         \
    register long _a3  __asm__("rdx") = (long)(arg3);                         \
    register long _a4  __asm__("r10") = (long)(arg4);                         \
    register long _a5  __asm__("r8")  = (long)(arg5);                         \
    register long _a6  __asm__("r9")  = (long)(arg6);                         \
    __asm__ volatile ("syscall\n"                                             \
                      : "=a"(_ret)                                            \
                      : "0"(_num), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4),    \
                        "r"(_a5), "r"(_a6)                                    \
                      : "rcx", "r11", "memory", "cc");                        \
    _ret;                                                                     \
})

#endif

/* POSIX syscall wrappers */
static __inline__ __attribute__((noreturn))
void exit(int status)
{
    my_syscall1(__NR_exit, status);
    __builtin_unreachable();
}

static __inline__
ssize_t read(int fd, void *buf, size_t count)
{
    long ret = my_syscall3(__NR_read, fd, buf, count);
    if (ret < 0) { errno = (int)(-ret); return -1; }
    return (ssize_t)ret;
}

static __inline__
ssize_t write(int fd, const void *buf, size_t count)
{
    long ret = my_syscall3(__NR_write, fd, buf, count);
    if (ret < 0) { errno = (int)(-ret); return -1; }
    return (ssize_t)ret;
}

static __inline__
int open(const char *path, int flags, int mode)
{
    long ret = my_syscall3(__NR_open, path, flags, mode);
    if (ret < 0) { errno = (int)(-ret); return -1; }
    return (int)ret;
}

static __inline__
int close(int fd)
{
    long ret = my_syscall1(__NR_close, fd);
    if (ret < 0) { errno = (int)(-ret); return -1; }
    return 0;
}

static __inline__
pid_t fork(void)
{
    long ret = my_syscall0(__NR_fork);
    if (ret < 0) { errno = (int)(-ret); return -1; }
    return (pid_t)ret;
}

static __inline__
int kill(pid_t pid, int sig)
{
    long ret = my_syscall2(__NR_kill, pid, sig);
    if (ret < 0) { errno = (int)(-ret); return -1; }
    return 0;
}

static __inline__
pid_t waitpid(pid_t pid, int *wstatus, int options)
{
    long ret = my_syscall4(__NR_wait4, pid, wstatus, options, 0);
    if (ret < 0) { errno = (int)(-ret); return -1; }
    return (pid_t)ret;
}

/* Freestanding string & memory primitives */
__attribute__((weak, used))
void *memset(void *dst, int b, size_t len)
{
    unsigned char *p = (unsigned char *)dst;
    while (len--)
        *p++ = (unsigned char)b;
    return dst;
}

__attribute__((weak, used))
void *memcpy(void *dst, const void *src, size_t len)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (len--)
        *d++ = *s++;
    return dst;
}

__attribute__((weak, used))
void *memmove(void *dst, const void *src, size_t len)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    if (d < s || d >= s + len) {
        while (len--)
            *d++ = *s++;
    } else if (d > s) {
        d += len;
        s += len;
        while (len--)
            *--d = *--s;
    }
    return dst;
}

__attribute__((weak, used))
int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;
    while (n--) {
        if (*p1 != *p2)
            return (int)*p1 - (int)*p2;
        p1++;
        p2++;
    }
    return 0;
}

static __inline__
size_t strlen(const char *s)
{
    const char *p = s;
    while (*p)
        p++;
    return (size_t)(p - s);
}

static __inline__
int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

static __inline__
int strncmp(const char *a, const char *b, size_t n)
{
    while (n && *a && *a == *b) {
        a++;
        b++;
        n--;
    }
    return n ? ((int)(unsigned char)*a - (int)(unsigned char)*b) : 0;
}

static __inline__
char *strchr(const char *s, int c)
{
    while (*s) {
        if (*s == (char)c)
            return (char *)s;
        s++;
    }
    return (c == 0) ? (char *)s : NULL;
}

static __inline__
char *strrchr(const char *s, int c)
{
    const char *ret = NULL;
    while (*s) {
        if (*s == (char)c)
            ret = s;
        s++;
    }
    return (c == 0) ? (char *)s : (char *)ret;
}

/* Entry point (_start) for freestanding -nostdlib binary */
int main(int argc, char **argv, char **envp);

__attribute__((used))
static void __start_c(long *sp)
{
    int argc = (int)(*sp);
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    exit(main(argc, argv, envp));
}

#if defined(__mips__)
__asm__(
    ".section .text\n"
    ".globl __start\n"
    ".globl _start\n"
    ".set push\n"
    ".set noreorder\n"
    ".ent __start\n"
    "__start:\n"
    "_start:\n"
    "move $fp, $zero\n"
    "move $a0, $sp\n"
    "li   $t0, -8\n"
    "and  $sp, $sp, $t0\n"
    "addiu $sp, $sp, -16\n"
    "jal  __start_c\n"
    " nop\n"
    ".end __start\n"
    ".set pop\n"
);
#elif defined(__x86_64__)
__asm__(
    ".section .text\n"
    ".globl _start\n"
    "_start:\n"
    "xor %ebp, %ebp\n"
    "mov %rsp, %rdi\n"
    "and $-16, %rsp\n"
    "call __start_c\n"
    "hlt\n"
);
#endif

#endif /* _NOLIBC_H */
