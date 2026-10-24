// Fixed 1.2 s CPU coexistence helper. Freestanding x86_64, no libc/network/filesystem.
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
    char tmp[32]; usize n = 0;
    if (value == 0) { out[at++]='0'; return at; }
    while (value) { tmp[n++] = (char)('0' + value % 10); value /= 10; }
    while (n) out[at++] = tmp[--n];
    return at;
}
static u64 ns(struct timespec t) { return (u64)t.tv_sec * 1000000000ULL + (u64)t.tv_nsec; }

void _start(void) {
    const long SYS_write=1, SYS_exit=60, SYS_clock_gettime=228;
    const long CLOCK_MONOTONIC=1;
    const u64 duration_ns = 1200000000ULL;
    struct timespec start={0,0}, now={0,0};
    volatile u64 x=0x9e3779b97f4a7c15ULL;
    u64 iterations=0;
    sc2(SYS_clock_gettime,CLOCK_MONOTONIC,(long)&start);
    u64 start_ns=ns(start);
    for (;;) {
        for (int i=0;i<4096;i++) {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            iterations++;
        }
        sc2(SYS_clock_gettime,CLOCK_MONOTONIC,(long)&now);
        if (ns(now)-start_ns >= duration_ns) break;
    }
    u64 elapsed=ns(now)-start_ns;
    char out[160]; usize at=0;
    at=append_lit(out,at,"P2_CPU_HELPER iterations=");
    at=append_dec(out,at,iterations);
    at=append_lit(out,at," elapsed_ns=");
    at=append_dec(out,at,elapsed);
    out[at++]='\n';
    sc3(SYS_write,1,(long)out,(long)at);
    sc1(SYS_exit,0);
}
