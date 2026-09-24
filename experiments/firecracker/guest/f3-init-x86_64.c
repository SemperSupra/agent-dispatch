// Firecracker F3 PID 1: execute a separate bounded candidate and report lifecycle.
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
    if (value == 0) { out[at++] = '0'; return at; }
    while (value) { tmp[n++] = (char)('0' + (value % 10)); value /= 10; }
    while (n) out[at++] = tmp[--n];
    return at;
}
static u64 ns_between(struct timespec a, struct timespec b) {
    long sec = b.tv_sec - a.tv_sec;
    long nsec = b.tv_nsec - a.tv_nsec;
    if (nsec < 0) { sec -= 1; nsec += 1000000000L; }
    return (u64)sec * 1000000000ULL + (u64)nsec;
}
static void reboot_guest(void) {
    sc4(169, 0xfee1dead, 672274793, 0x01234567, 0);
    for (;;) __asm__ volatile("hlt");
}

void _start(void) {
    const long SYS_write = 1, SYS_open = 2, SYS_dup2 = 33, SYS_fork = 57;
    const long SYS_execve = 59, SYS_exit = 60, SYS_wait4 = 61, SYS_clock_gettime = 228;
    const long CLOCK_MONOTONIC = 1, O_RDWR = 2;
    static const char console[] = "/dev/console";
    static const char candidate[] = "/work/candidate";
    static const char child_error[] = "FIRECRACKER_F3_INIT_ERROR=execve\n";
    char out[160];
    struct timespec start = {0, 0}, end = {0, 0};

    long console_fd = sc3(SYS_open, (long)console, O_RDWR, 0);
    if (console_fd >= 0) {
        sc2(SYS_dup2, console_fd, 0);
        sc2(SYS_dup2, console_fd, 1);
        sc2(SYS_dup2, console_fd, 2);
    }

    sc2(SYS_clock_gettime, CLOCK_MONOTONIC, (long)&start);
    long pid = sc1(SYS_fork, 0);
    if (pid == 0) {
        char *argv[] = {(char *)candidate, 0};
        char *envp[] = {0};
        sc3(SYS_execve, (long)candidate, (long)argv, (long)envp);
        sc3(SYS_write, 1, (long)child_error, sizeof(child_error) - 1);
        sc1(SYS_exit, 111);
    }

    int status = 0;
    long waited = sc4(SYS_wait4, pid, (long)&status, 0, 0);
    sc2(SYS_clock_gettime, CLOCK_MONOTONIC, (long)&end);
    int exit_code = 255;
    if (waited == pid && (status & 0x7f) == 0) exit_code = (status >> 8) & 0xff;
    u64 elapsed_ns = ns_between(start, end);

    usize at = 0;
    at = append_lit(out, at, "FIRECRACKER_F3_EXIT code=");
    at = append_dec(out, at, (u64)exit_code);
    at = append_lit(out, at, " elapsed_ns=");
    at = append_dec(out, at, elapsed_ns);
    out[at++] = '\n';
    sc3(SYS_write, 1, (long)out, (long)at);
    reboot_guest();
}
