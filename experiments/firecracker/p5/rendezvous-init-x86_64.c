// P5 long-lived coordination witness guest: no network, no disks, periodic heartbeat.
typedef unsigned long long u64;
typedef unsigned long usize;
struct timespec { long tv_sec; long tv_nsec; };
static volatile u64 counter=0;
static inline long s2(long n,long a,long b){long r;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b):"rcx","r11","memory");return r;}
static inline long s3(long n,long a,long b,long c){long r;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");return r;}
static inline long s4(long n,long a,long b,long c,long d){long r;register long r10 __asm__("r10")=d;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10):"rcx","r11","memory");return r;}
static usize lit(char*o,usize a,const char*s){while(*s)o[a++]=*s++;return a;}
static usize dec(char*o,usize a,u64 v){char t[32];usize n=0;if(!v){o[a++]='0';return a;}while(v){t[n++]=(char)('0'+v%10);v/=10;}while(n)o[a++]=t[--n];return a;}
static void emit(const char*p,u64 v){char o[128];usize a=0;a=lit(o,a,p);a=dec(o,a,v);o[a++]='\n';s3(1,1,(long)o,(long)a);}
static void reboot(void){s4(169,0xfee1dead,672274793,0x01234567,0);for(;;)__asm__ volatile("hlt");}
void _start(void){
  static const char con[]="/dev/console";long fd=s3(2,(long)con,2,0);
  if(fd>=0){s2(33,fd,0);s2(33,fd,1);s2(33,fd,2);}
  emit("FIRECRACKER_P5_READY counter=",counter);
  struct timespec req={0,500000000};
  while(counter<120){s2(35,(long)&req,0);counter++;emit("FIRECRACKER_P5_HEARTBEAT counter=",counter);}
  emit("FIRECRACKER_P5_DONE counter=",counter);reboot();
}
