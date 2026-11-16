/* Public-synthetic R10: same C source on native x86 and cross ISA.
 * Workload families exercise different dynamic behaviors; measurements are
 * indicative only: compiler ISA differences remain material confounders. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifndef TARGET_LABEL
#error TARGET_LABEL is mandatory
#endif
static volatile uint64_t sink;
static uint64_t ns_diff(struct timespec a,struct timespec b){
 return (uint64_t)(b.tv_sec-a.tv_sec)*1000000000ull+(uint64_t)(b.tv_nsec-a.tv_nsec);
}
int main(int argc,char **argv){
 if(argc!=2)return 3;
 struct timespec a,b;
 if(clock_gettime(CLOCK_MONOTONIC,&a)!=0)return 4;
 uint64_t result=0;
 if(strcmp(argv[1],"integer")==0){
  volatile uint64_t n=2000000;
  for(uint64_t i=1;i<=n;i++)result+=i;
  if(result!=UINT64_C(2000001000000))return 11;
 }else if(strcmp(argv[1],"memory")==0){
  const size_t size=1048576;
  uint8_t *buf=(uint8_t*)malloc(size);
  if(buf==NULL)return 12;
  for(size_t i=0;i<size;i++)buf[i]=(uint8_t)(i%256u);
  for(int pass=0;pass<32;pass++){
   for(size_t i=0;i<size;i++)result+=buf[i];
   sink=result;
  }
  free(buf);
  if(result!=UINT64_C(4278190080))return 13;
 }else if(strcmp(argv[1],"syscall")==0){
  volatile int n=30000;
  for(int i=0;i<n;i++){
   pid_t parent=getppid();
   if(parent<=0)return 14;
   result++;
  }
  if(result!=30000)return 15;
 }else return 16;
 sink=result;
 if(clock_gettime(CLOCK_MONOTONIC,&b)!=0)return 17;
 uint64_t elapsed=ns_diff(a,b);
 if(elapsed==0)return 18;
 printf("R10_TASK_RESULT=PASS ISA=%s CLASS=%s RESULT=%"PRIu64" COMPUTE_NS=%"PRIu64"\n",TARGET_LABEL,argv[1],result,elapsed);
 return 0;
}
