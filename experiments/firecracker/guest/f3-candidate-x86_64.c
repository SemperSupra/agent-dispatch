// Firecracker F3 candidate executable: deterministic bounded text analysis.
typedef unsigned long long u64;
typedef unsigned long usize;

struct timespec { long tv_sec; long tv_nsec; };

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

static usize append_lit(char *out, usize at, const char *s) {
    while (*s) out[at++] = *s++;
    return at;
}
static usize append_dec(char *out, usize at, u64 value) {
    char tmp[32];
    usize n = 0;
    if (value == 0) { out[at++] = '0'; return at; }
    while (value) { tmp[n++] = (char)('0' + (value % 10)); value /= 10; }
    while (n) out[at++] = tmp[--n];
    return at;
}
static usize append_hex16(char *out, usize at, u64 value) {
    static const char hex[] = "0123456789abcdef";
    for (int shift = 60; shift >= 0; shift -= 4) out[at++] = hex[(value >> shift) & 0xf];
    return at;
}
static int whitespace(unsigned char c) {
    return c == ' ' || c == '\n' || c == '\t' || c == '\r' || c == '\f' || c == '\v';
}
static u64 ns_between(struct timespec a, struct timespec b) {
    long sec = b.tv_sec - a.tv_sec;
    long nsec = b.tv_nsec - a.tv_nsec;
    if (nsec < 0) { sec -= 1; nsec += 1000000000L; }
    return (u64)sec * 1000000000ULL + (u64)nsec;
}

void _start(void) {
    const long SYS_read = 0, SYS_write = 1, SYS_open = 2, SYS_close = 3;
    const long SYS_exit = 60, SYS_clock_gettime = 228;
    const long CLOCK_MONOTONIC = 1, O_RDONLY = 0;
    static const char input_path[] = "/work/input.txt";
    static const char error_msg[] = "FIRECRACKER_F3_CANDIDATE_ERROR=input-read\n";
    char buf[512], out[256];
    u64 bytes = 0, lines = 0, words = 0;
    u64 hash = 14695981039346656037ULL;
    int in_word = 0;
    struct timespec start = {0, 0}, end = {0, 0};

    sc2(SYS_clock_gettime, CLOCK_MONOTONIC, (long)&start);
    long fd = sc3(SYS_open, (long)input_path, O_RDONLY, 0);
    if (fd < 0) {
        sc3(SYS_write, 1, (long)error_msg, sizeof(error_msg) - 1);
        sc1(SYS_exit, 111);
    }

    for (;;) {
        long n = sc3(SYS_read, fd, (long)buf, sizeof(buf));
        if (n < 0) {
            sc3(SYS_write, 1, (long)error_msg, sizeof(error_msg) - 1);
            sc1(SYS_close, fd);
            sc1(SYS_exit, 112);
        }
        if (n == 0) break;
        bytes += (u64)n;
        for (long i = 0; i < n; ++i) {
            unsigned char ch = (unsigned char)buf[i];
            if (ch == '\n') lines++;
            if (whitespace(ch)) {
                in_word = 0;
            } else if (!in_word) {
                words++;
                in_word = 1;
            }
            hash ^= ch;
            hash *= 1099511628211ULL;
        }
    }
    sc1(SYS_close, fd);
    sc2(SYS_clock_gettime, CLOCK_MONOTONIC, (long)&end);
    u64 work_ns = ns_between(start, end);

    usize at = 0;
    at = append_lit(out, at, "FIRECRACKER_F3_CANDIDATE_RESULT bytes=");
    at = append_dec(out, at, bytes);
    at = append_lit(out, at, " lines=");
    at = append_dec(out, at, lines);
    at = append_lit(out, at, " words=");
    at = append_dec(out, at, words);
    at = append_lit(out, at, " fnv1a64=");
    at = append_hex16(out, at, hash);
    at = append_lit(out, at, " work_ns=");
    at = append_dec(out, at, work_ns);
    out[at++] = '\n';
    sc3(SYS_write, 1, (long)out, (long)at);
    sc1(SYS_exit, 0);
}
