// Minimal x86_64 init for Firecracker F1. No libc, filesystem, or network.
typedef unsigned long usize;

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

void _start(void) {
    static const char console[] = "/dev/console";
    static const char msg[] = "FIRECRACKER_F1_GUEST_NONCE=fcf1c0de\n";
    const long SYS_write = 1;
    const long SYS_open = 2;
    const long SYS_dup2 = 33;
    const long SYS_reboot = 169;
    const long O_RDWR = 2;
    const long MAGIC1 = 0xfee1dead;
    const long MAGIC2 = 672274793;
    const long CMD_RESTART = 0x01234567;

    long fd = sc3(SYS_open, (long)console, O_RDWR, 0);
    if (fd >= 0) {
        sc2(SYS_dup2, fd, 0);
        sc2(SYS_dup2, fd, 1);
        sc2(SYS_dup2, fd, 2);
    }
    sc3(SYS_write, 1, (long)msg, (long)(sizeof(msg) - 1));
    sc4(SYS_reboot, MAGIC1, MAGIC2, CMD_RESTART, 0);
    for (;;) {
        __asm__ volatile("hlt");
    }
}
