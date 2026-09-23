// Fixed bounded CPU competitor for Firecracker P2 coexistence.
typedef unsigned long long u64;
extern long write(int, const void*, unsigned long);

static u64 burn(u64 iterations) {
    u64 x = 0x9e3779b97f4a7c15ULL;
    for (u64 i = 0; i < iterations; ++i) {
        x ^= i + 0x517cc1b727220a95ULL;
        x *= 0xbf58476d1ce4e5b9ULL;
        x ^= x >> 31;
    }
    return x;
}

static int parse(const char *s, u64 *out) {
    u64 v = 0;
    if (!s || !*s) return 0;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9') return 0;
        v = v * 10 + (u64)(*s - '0');
        if (v > 2000000000ULL) return 0;
    }
    *out = v;
    return 1;
}

int main(int argc, char **argv) {
    u64 iterations = 0;
    if (argc != 2 || !parse(argv[1], &iterations) || iterations == 0) return 2;
    volatile u64 result = burn(iterations);
    (void)result;
    return 0;
}
