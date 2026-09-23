// R1 writable virtio-block scratch probe. Freestanding x86_64 Linux PID1.
typedef unsigned long long u64;
typedef unsigned long usize;
struct timespec { long tv_sec; long tv_nsec; };

static inline long sc1(long n,long a1){long r;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1):"rcx","r11","memory");return r;}
static inline long sc2(long n,long a1,long a2){long r;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2):"rcx","r11","memory");return r;}
static inline long sc3(long n,long a1,long a2,long a3){long r;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2),"d"(a3):"rcx","r11","memory");return r;}
static inline long sc4(long n,long a1,long a2,long a3,long a4){long r;register long r10 __asm__("r10")=a4;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2),"d"(a3),"r"(r10):"rcx","r11","memory");return r;}
static inline long sc5(long n,long a1,long a2,long a3,long a4,long a5){long r;register long r10 __asm__("r10")=a4;register long r8 __asm__("r8")=a5;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2),"d"(a3),"r"(r10),"r"(r8):"rcx","r11","memory");return r;}
static usize append_lit(char*out,usize at,const char*s){while(*s)out[at++]=*s++;return at;}
static usize append_dec(char*out,usize at,u64 v){char t[32];usize n=0;if(!v){out[at++]='0';return at;}while(v){t[n++]=(char)('0'+v%10);v/=10;}while(n)out[at++]=t[--n];return at;}
static u64 ns_between(struct timespec a,struct timespec b){long s=b.tv_sec-a.tv_sec,n=b.tv_nsec-a.tv_nsec;if(n<0){s--;n+=1000000000L;}return(u64)s*1000000000ULL+(u64)n;}

static void reboot_guest(void){sc4(169,0xfee1dead,672274793,0x01234567,0);for(;;)__asm__ volatile("hlt");}
static void emit_error(u64 code){
    char out[96];usize at=0;at=append_lit(out,at,"FIRECRACKER_R1_STORAGE_ERROR code=");at=append_dec(out,at,code);out[at++]='\n';sc3(1,1,(long)out,(long)at);reboot_guest();
}

#define CHUNK (1024*1024)
#define TOTAL (64ULL*1024ULL*1024ULL)
static unsigned char buffer[CHUNK];

void _start(void){
    const long SYS_open=2,SYS_close=3,SYS_lseek=8,SYS_write=1,SYS_read=0,SYS_fsync=74,SYS_mount=165,SYS_clock_gettime=228,SYS_nanosleep=35;
    const long O_CREAT=0100,O_TRUNC=01000,O_RDWR=2,CLOCK_MONOTONIC=1,SEEK_SET=0;
    static const char dev[]="/dev/vda",scratch[]="/scratch",fstype[]="ext4",file[]="/scratch/probe.bin";
    struct timespec nap={0,10*1000*1000};
    long testfd=-1;
    for(int i=0;i<300;i++){testfd=sc3(SYS_open,(long)dev,O_RDWR,0);if(testfd>=0){sc1(SYS_close,testfd);break;}sc2(SYS_nanosleep,(long)&nap,0);}
    if(testfd<0)emit_error(1);
    long mr=sc5(SYS_mount,(long)dev,(long)scratch,(long)fstype,0,0);if(mr<0)emit_error(2);
    long fd=sc3(SYS_open,(long)file,O_CREAT|O_TRUNC|O_RDWR,0644);if(fd<0)emit_error(3);

    struct timespec a={0},b={0},c={0};u64 expected=0,observed=0;
    for(usize i=0;i<CHUNK;i++)buffer[i]=(unsigned char)((i*131u+17u)&0xffu);
    for(usize i=0;i<CHUNK;i++)expected+=buffer[i];

    sc2(SYS_clock_gettime,CLOCK_MONOTONIC,(long)&a);
    for(u64 off=0;off<TOTAL;off+=CHUNK){
        long n=sc3(SYS_write,fd,(long)buffer,CHUNK);if(n!=CHUNK)emit_error(4);
    }
    if(sc1(SYS_fsync,fd)<0)emit_error(5);
    sc2(SYS_clock_gettime,CLOCK_MONOTONIC,(long)&b);
    if(sc3(SYS_lseek,fd,0,SEEK_SET)<0)emit_error(6);
    for(u64 off=0;off<TOTAL;off+=CHUNK){
        long n=sc3(SYS_read,fd,(long)buffer,CHUNK);if(n!=CHUNK)emit_error(7);
        for(usize i=0;i<CHUNK;i++)observed+=buffer[i];
    }
    sc2(SYS_clock_gettime,CLOCK_MONOTONIC,(long)&c);
    sc1(SYS_close,fd);
    expected*=64ULL;

    char out[256];usize at=0;
    at=append_lit(out,at,"FIRECRACKER_R1_STORAGE bytes=");at=append_dec(out,at,TOTAL);
    at=append_lit(out,at," write_fsync_ns=");at=append_dec(out,at,ns_between(a,b));
    at=append_lit(out,at," read_ns=");at=append_dec(out,at,ns_between(b,c));
    at=append_lit(out,at," expected_checksum=");at=append_dec(out,at,expected);
    at=append_lit(out,at," observed_checksum=");at=append_dec(out,at,observed);
    out[at++]='\n';sc3(SYS_write,1,(long)out,(long)at);
    reboot_guest();
}
