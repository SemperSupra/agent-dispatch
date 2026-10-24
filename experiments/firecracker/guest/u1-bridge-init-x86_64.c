// U1 bridge PID1: mount pinned read-only Ubuntu rootfs and writable scratch, then run ordinary shell/Python userspace.
typedef unsigned long usize;
typedef unsigned long long u64;

static inline long sc1(long n,long a1){long r;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1):"rcx","r11","memory");return r;}
static inline long sc2(long n,long a1,long a2){long r;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2):"rcx","r11","memory");return r;}
static inline long sc3(long n,long a1,long a2,long a3){long r;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2),"d"(a3):"rcx","r11","memory");return r;}
static inline long sc4(long n,long a1,long a2,long a3,long a4){long r;register long r10 __asm__("r10")=a4;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2),"d"(a3),"r"(r10):"rcx","r11","memory");return r;}
static inline long sc5(long n,long a1,long a2,long a3,long a4,long a5){long r;register long r10 __asm__("r10")=a4;register long r8 __asm__("r8")=a5;__asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a1),"S"(a2),"d"(a3),"r"(r10),"r"(r8):"rcx","r11","memory");return r;}

static usize append_lit(char*out,usize at,const char*s){while(*s)out[at++]=*s++;return at;}
static usize append_dec(char*out,usize at,u64 v){char t[32];usize n=0;if(!v){out[at++]='0';return at;}while(v){t[n++]=(char)('0'+v%10);v/=10;}while(n)out[at++]=t[--n];return at;}
static void reboot_guest(void){sc4(169,0xfee1dead,672274793,0x01234567,0);for(;;)__asm__ volatile("hlt");}
static void fail(u64 code){char out[96];usize at=0;at=append_lit(out,at,"FIRECRACKER_U1_ERROR code=");at=append_dec(out,at,code);out[at++]='\n';sc3(1,1,(long)out,(long)at);reboot_guest();}

static int wait_dev(const char*path){
    struct timespec { long tv_sec; long tv_nsec; } nap={0,10*1000*1000};
    for(int i=0;i<400;i++){
        long fd=sc3(2,(long)path,0,0);
        if(fd>=0){sc1(3,fd);return 1;}
        sc2(35,(long)&nap,0);
    }
    return 0;
}
static int copy_file(const char*src,const char*dst){
    const long O_RDONLY=0,O_WRONLY=1,O_CREAT=0100,O_TRUNC=01000;
    long in=sc3(2,(long)src,O_RDONLY,0); if(in<0)return 0;
    long out=sc3(2,(long)dst,O_WRONLY|O_CREAT|O_TRUNC,0755); if(out<0){sc1(3,in);return 0;}
    char buf[4096];
    for(;;){
        long n=sc3(0,in,(long)buf,sizeof(buf));
        if(n<0){sc1(3,in);sc1(3,out);return 0;}
        if(n==0)break;
        long off=0;
        while(off<n){long w=sc3(1,out,(long)(buf+off),n-off);if(w<=0){sc1(3,in);sc1(3,out);return 0;}off+=w;}
    }
    sc1(3,in);sc1(3,out);return 1;
}

void _start(void){
    const long SYS_open=2,SYS_dup2=33,SYS_fork=57,SYS_execve=59,SYS_exit=60,SYS_wait4=61,SYS_chdir=80,SYS_chroot=161,SYS_mount=165;
    const long O_RDWR=2,MS_RDONLY=1;
    static const char console[]="/dev/console",rootdev[]="/dev/vda",scratchdev[]="/dev/vdb";
    static const char newroot[]="/newroot",squash[]="squashfs",ext4[]="ext4";
    static const char script_src[]="/work/u1.py",script_dst[]="/newroot/tmp/u1.py";

    long cfd=sc3(SYS_open,(long)console,O_RDWR,0);
    if(cfd>=0){sc2(SYS_dup2,cfd,0);sc2(SYS_dup2,cfd,1);sc2(SYS_dup2,cfd,2);}

    if(!wait_dev(rootdev))fail(1);
    if(!wait_dev(scratchdev))fail(2);
    if(sc5(SYS_mount,(long)rootdev,(long)newroot,(long)squash,MS_RDONLY,0)<0)fail(3);
    if(sc5(SYS_mount,(long)scratchdev,(long)"/newroot/tmp",(long)ext4,0,0)<0)fail(4);
    if(!copy_file(script_src,script_dst))fail(5);

    if(sc1(SYS_chroot,(long)newroot)<0)fail(6);
    if(sc1(SYS_chdir,(long)"/")<0)fail(7);
    sc5(SYS_mount,(long)"proc",(long)"/proc",(long)"proc",0,0);

    long pid=sc1(SYS_fork,0);
    if(pid==0){
        char *argv[]={(char*)"/bin/sh",(char*)"-c",(char*)"python3 /tmp/u1.py",0};
        char *envp[]={(char*)"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",(char*)"HOME=/root",(char*)"TMPDIR=/tmp",(char*)"LANG=C",0};
        sc3(SYS_execve,(long)"/bin/sh",(long)argv,(long)envp);
        sc1(SYS_exit,111);
    }
    int status=0;
    long waited=sc4(SYS_wait4,pid,(long)&status,0,0);
    int code=255;
    if(waited==pid && (status&0x7f)==0)code=(status>>8)&0xff;
    char out[96];usize at=0;at=append_lit(out,at,"FIRECRACKER_U1_EXIT code=");at=append_dec(out,at,(u64)code);out[at++]='\n';sc3(1,1,(long)out,(long)at);
    reboot_guest();
}
