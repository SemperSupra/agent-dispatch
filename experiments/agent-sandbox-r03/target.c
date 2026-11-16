/* Public synthetic deterministic foreign-ISA ELF fixture. No network, file IO or secrets. */
#include <stdint.h>
#include <stdio.h>
#ifndef TARGET_ARCH_NAME
#error TARGET_ARCH_NAME must be defined by disposable builder
#endif
int main(void) {
    volatile uint64_t total = 0;
    for (uint64_t i = 1; i <= 100000; ++i) total += i;
    if (total != UINT64_C(5000050000)) return 7;
    printf("R03_FOREIGN_ELF_FUNCTIONAL_ORACLE=PASS ARCH=%s SUM=%llu\n",
           TARGET_ARCH_NAME, (unsigned long long)total);
    return 0;
}
