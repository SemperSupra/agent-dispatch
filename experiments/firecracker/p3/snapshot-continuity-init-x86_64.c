// P3 snapshot-continuity guest: one READY, periodic in-memory heartbeats, then reboot.
typedef unsigned long long u64;
typedef unsigned long usize;
struct timespec { long tv_sec; long tv_nsec; };

static volatile u64 counter = 0;

static inline long sc2(long n, long a1, long a2) {
    long r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2):"rcx","r11","memory"); return r;
}
static inline long sc3(long n, long a1, long a2, long a3) {
    long r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2),"d"(a3):"rcx","r11","memory"); return r;
}
static inline long sc4(long n, long a1, long a2, long a3, long a4) {
    long r; register long r10 __asm__("r10")=a4;
    __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2),"d"(a3),"r"(r10):"rcx","r11","memory"); return r;
}
static usize lit(char *o, usize at, const char *s){while(*s)o[at++]=*s++;return at;}
static usize dec(char *o, usize at, u64 v){char t[32];usize n=0;if(!v){o[at++]='0';return at;}while(v){t[n++]=(char)('0'+v%10);v/=10;}while(n)o[at++]=t[--n];return at;}
static void emit(const char *prefix,u64 value){
    char o[128];usize at=0;at=lit(o,at,prefix);at=dec(o,at,value);o[at++]='\n';sc3(1,1,(long)o,(long)at);
}
static void reboot_guest(void){sc4(169,0xfee1dead,672274793,0x01234567,0);for(;;)__asm__ volatile("hlt");}

void _start(void){
    const long SYS_open=2,SYS_dup2=33,SYS_nanosleep=35;
    static const char console[]="/dev/console";
    long fd=sc3(SYS_open,(long)console,2,0);
    if(fd>=0){sc2(SYS_dup2,fd,0);sc2(SYS_dup2,fd,1);sc2(SYS_dup2,fd,2);}
    emit("FIRECRACKER_P3_READY counter=",counter);
    struct timespec req={0,100000000};
    while(counter<20){
        sc2(SYS_nanosleep,(long)&req,0);
        counter++;
        emit("FIRECRACKER_P3_HEARTBEAT counter=",counter);
    }
    emit("FIRECRACKER_P3_DONE counter=",counter);
    reboot_guest();
}
