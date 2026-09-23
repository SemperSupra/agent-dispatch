// R0b active CPU/RAM resource probe. Freestanding x86_64 Linux, no libc.
typedef unsigned long long u64;
typedef unsigned long usize;

struct timespec { long tv_sec; long tv_nsec; };

static inline long sc1(long n,long a1){ long r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1):"rcx","r11","memory"); return r; }
static inline long sc2(long n,long a1,long a2){ long r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2):"rcx","r11","memory"); return r; }
static inline long sc3(long n,long a1,long a2,long a3){ long r; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2),"d"(a3):"rcx","r11","memory"); return r; }
static inline long sc4(long n,long a1,long a2,long a3,long a4){ long r; register long r10 __asm__("r10")=a4; __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2),"d"(a3),"r"(r10):"rcx","r11","memory"); return r; }
static inline long sc6(long n,long a1,long a2,long a3,long a4,long a5,long a6){
    long r; register long r10 __asm__("r10")=a4; register long r8 __asm__("r8")=a5; register long r9 __asm__("r9")=a6;
    __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2),"d"(a3),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory"); return r;
}
static usize slen(const char*s){ usize n=0; while(s[n])n++; return n; }
static usize append_lit(char*out,usize at,const char*s){ while(*s)out[at++]=*s++; return at; }
static usize append_dec(char*out,usize at,u64 v){ char t[32];usize n=0;if(v==0){out[at++]='0';return at;}while(v){t[n++]=(char)('0'+v%10);v/=10;}while(n)out[at++]=t[--n];return at; }
static usize append_hex16(char*out,usize at,u64 v){ static const char h[]="0123456789abcdef";for(int s=60;s>=0;s-=4)out[at++]=h[(v>>s)&15];return at; }
static u64 ns_between(struct timespec a,struct timespec b){ long s=b.tv_sec-a.tv_sec,n=b.tv_nsec-a.tv_nsec;if(n<0){s--;n+=1000000000L;}return (u64)s*1000000000ULL+(u64)n; }

static long read_config(char*buf,usize cap){
    long fd=sc3(2,(long)"/work/config.txt",0,0); if(fd<0)return -1;
    long n=sc3(0,fd,(long)buf,(long)(cap-1)); sc1(3,fd); if(n<0)return -1; buf[n]=0; return n;
}
static u64 parse_u64_after(const char*buf,const char*key){
    usize kl=slen(key); for(usize i=0;buf[i];i++){ usize j=0;while(j<kl&&buf[i+j]==key[j])j++; if(j==kl){u64 v=0;usize p=i+j;while(buf[p]>='0'&&buf[p]<='9'){v=v*10+(u64)(buf[p]-'0');p++;}return v;}} return 0;
}
static int has_mode(const char*buf,const char*mode){
    const char*key="mode=";usize ml=slen(mode);for(usize i=0;buf[i];i++){usize j=0;while(key[j]&&buf[i+j]==key[j])j++;if(!key[j]){usize p=i+j,k=0;while(k<ml&&buf[p+k]==mode[k])k++;if(k==ml)return 1;}}return 0;
}
static u64 burn(u64 seed,u64 iters){
    u64 x=seed^0x9e3779b97f4a7c15ULL;
    for(u64 i=0;i<iters;i++){x^=i+0x517cc1b727220a95ULL;x*=0xbf58476d1ce4e5b9ULL;x^=x>>31;}
    return x;
}

static int cpu_mode(const char*cfg){
    const long SYS_mmap=9,SYS_munmap=11,SYS_fork=57,SYS_wait4=61,SYS_exit=60,SYS_clock_gettime=228;
    const long PROT_READ=1,PROT_WRITE=2,MAP_SHARED=1,MAP_ANONYMOUS=0x20,CLOCK_MONOTONIC=1;
    u64 workers=parse_u64_after(cfg,"workers="),iters=parse_u64_after(cfg,"iterations=");
    if(workers<1||workers>32||iters<1)return 21;
    usize bytes=(usize)(workers*sizeof(u64));
    long m=sc6(SYS_mmap,0,(long)bytes,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(m<0)return 22;
    volatile u64*slots=(volatile u64*)m;
    struct timespec a={0},b={0};sc2(SYS_clock_gettime,CLOCK_MONOTONIC,(long)&a);
    for(u64 w=0;w<workers;w++){
        long pid=sc1(SYS_fork,0);
        if(pid==0){slots[w]=burn(w+1,iters);sc1(SYS_exit,0);}
        if(pid<0)return 23;
    }
    int status=0;u64 reaped=0;
    while(reaped<workers){long p=sc4(SYS_wait4,-1,(long)&status,0,0);if(p<0)return 24;if((status&0x7f)!=0||((status>>8)&255)!=0)return 25;reaped++;}
    sc2(SYS_clock_gettime,CLOCK_MONOTONIC,(long)&b);
    u64 combined=14695981039346656037ULL;for(u64 w=0;w<workers;w++){combined^=slots[w];combined*=1099511628211ULL;}
    sc2(SYS_munmap,m,(long)bytes);
    char out[256];usize at=0;at=append_lit(out,at,"FIRECRACKER_R0B_CPU workers=");at=append_dec(out,at,workers);at=append_lit(out,at," iterations=");at=append_dec(out,at,iters);at=append_lit(out,at," elapsed_ns=");at=append_dec(out,at,ns_between(a,b));at=append_lit(out,at," checksum=");at=append_hex16(out,at,combined);out[at++]='\n';sc3(1,1,(long)out,(long)at);return 0;
}
static int mem_mode(const char*cfg){
    const long SYS_mmap=9,SYS_munmap=11,SYS_clock_gettime=228;
    const long PROT_READ=1,PROT_WRITE=2,MAP_PRIVATE=2,MAP_ANONYMOUS=0x20,CLOCK_MONOTONIC=1;
    u64 mib=parse_u64_after(cfg,"mib="); if(mib<1||mib>8192)return 31;
    u64 bytes=mib*1024ULL*1024ULL; long m=sc6(SYS_mmap,0,(long)bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); if(m<0)return 32;
    volatile unsigned char*p=(volatile unsigned char*)m;struct timespec a={0},b={0};sc2(SYS_clock_gettime,CLOCK_MONOTONIC,(long)&a);
    u64 pages=0;for(u64 off=0;off<bytes;off+=4096){p[off]=(unsigned char)((off>>12)^0x5a);pages++;}
    u64 check=0;for(u64 off=0;off<bytes;off+=4096)check+=p[off];
    sc2(SYS_clock_gettime,CLOCK_MONOTONIC,(long)&b);
    sc2(SYS_munmap,m,(long)bytes);
    char out[256];usize at=0;at=append_lit(out,at,"FIRECRACKER_R0B_MEM mib=");at=append_dec(out,at,mib);at=append_lit(out,at," pages=");at=append_dec(out,at,pages);at=append_lit(out,at," elapsed_ns=");at=append_dec(out,at,ns_between(a,b));at=append_lit(out,at," checksum=");at=append_dec(out,at,check);out[at++]='\n';sc3(1,1,(long)out,(long)at);return 0;
}
void _start(void){
    char cfg[256];long n=read_config(cfg,sizeof(cfg));int rc=40;if(n>=0){if(has_mode(cfg,"cpu"))rc=cpu_mode(cfg);else if(has_mode(cfg,"mem"))rc=mem_mode(cfg);}
    sc1(60,rc);
}
