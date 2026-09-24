// Minimal x86_64 Firecracker F2 guest: bounded input -> deterministic result.
typedef unsigned long long u64;
typedef unsigned long usize;

static inline long sc1(long n, long a1) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return r;
}
static inline long sc2(long n, long a1, long a2) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
    return r;
}
static inline long sc3(long n, long a1, long a2, long a3) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
    return r;
}
static inline long sc4(long n, long a1, long a2, long a3, long a4) {
    long r;
    register long r10 __asm__("r10") = a4;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10) : "rcx", "r11", "memory");
    return r;
}

static usize append_lit(char *out, usize at, const char *s) {
    while (*s) out[at++] = *s++;
    return at;
}
static usize append_dec(char *out, usize at, u64 value) {
    char tmp[32];
    usize n = 0;
    if (value == 0) {
        out[at++] = '0';
        return at;
    }
    while (value) {
        tmp[n++] = (char)('0' + (value % 10));
        value /= 10;
    }
    while (n) out[at++] = tmp[--n];
    return at;
}
static usize append_hex16(char *out, usize at, u64 value) {
    static const char hex[] = "0123456789abcdef";
    for (int shift = 60; shift >= 0; shift -= 4)
        out[at++] = hex[(value >> shift) & 0xf];
    return at;
}
static void reboot_guest(void) {
    const long SYS_reboot = 169;
    sc4(SYS_reboot, 0xfee1dead, 672274793, 0x01234567, 0);
    for (;;) __asm__ volatile("hlt");
}

void _start(void) {
    const long SYS_read = 0, SYS_write = 1, SYS_open = 2, SYS_dup2 = 33, SYS_close = 3;
    const long O_RDONLY = 0, O_RDWR = 2;
    static const char console[] = "/dev/console";
    static const char input_path[] = "/work/input.txt";
    static const char error_msg[] = "FIRECRACKER_F2_ERROR=input-read\n";
    char buf[512];
    char out[160];
    u64 hash = 14695981039346656037ULL;
    u64 total = 0;

    long console_fd = sc3(SYS_open, (long)console, O_RDWR, 0);
    if (console_fd >= 0) {
        sc2(SYS_dup2, console_fd, 0);
        sc2(SYS_dup2, console_fd, 1);
        sc2(SYS_dup2, console_fd, 2);
    }

    long fd = sc3(SYS_open, (long)input_path, O_RDONLY, 0);
    if (fd < 0) {
        sc3(SYS_write, 1, (long)error_msg, sizeof(error_msg) - 1);
        reboot_guest();
    }

    for (;;) {
        long n = sc3(SYS_read, fd, (long)buf, sizeof(buf));
        if (n < 0) {
            sc3(SYS_write, 1, (long)error_msg, sizeof(error_msg) - 1);
            sc1(SYS_close, fd);
            reboot_guest();
        }
        if (n == 0) break;
        total += (u64)n;
        for (long i = 0; i < n; ++i) {
            hash ^= (unsigned char)buf[i];
            hash *= 1099511628211ULL;
        }
    }
    sc1(SYS_close, fd);

    usize at = 0;
    at = append_lit(out, at, "FIRECRACKER_F2_RESULT bytes=");
    at = append_dec(out, at, total);
    at = append_lit(out, at, " fnv1a64=");
    at = append_hex16(out, at, hash);
    out[at++] = '\n';
    sc3(SYS_write, 1, (long)out, (long)at);
    reboot_guest();
}
