/* Public synthetic arithmetic workload for paired native/foreign-ISA tasks.
   No file/network I/O, secrets, OS installation or privileged operations. */
#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#ifndef R07_ARCH
#define R07_ARCH "undefined"
#endif
int main(void) {
 struct timespec start,end;
 if (clock_gettime(CLOCK_MONOTONIC,&start)!=0) return 1;
 volatile uint64_t sum=0;
 for (uint64_t i=1;i<=10000000u;i++) sum+=i;
 if (clock_gettime(CLOCK_MONOTONIC,&end)!=0) return 2;
 if(sum!=UINT64_C(50000005000000)) return 3;
 int64_t ns=(int64_t)(end.tv_sec-start.tv_sec)*1000000000LL+end.tv_nsec-start.tv_nsec;
 if (ns<=0) return 4;
 printf("R07_WORKLOAD_RESULT=PASS ISA=%s SUM=%"PRIu64" COMPUTE_NS=%"PRId64"\n",R07_ARCH,(uint64_t)sum,ns);
 return 0;
}
