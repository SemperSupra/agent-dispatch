// Firecracker Playwright control PID1.
// Mount an immutable Playwright squashfs root, writable ext4 /tmp, then run
// the deterministic control as unprivileged uid/gid 20001.
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
static void fail(u64 code){char out[96];usize at=0;at=append_lit(out,at,"FIRECRACKER_PLAYWRIGHT_INIT_ERROR code=");at=append_dec(out,at,code);out[at++]='\n';sc3(1,1,(long)out,(long)at);reboot_guest();}
static int wait_dev(const char*path){struct timespec{long tv_sec;long tv_nsec;}nap={0,10*1000*1000};for(int i=0;i<600;i++){long fd=sc3(2,(long)path,0,0);if(fd>=0){sc1(3,fd);return 1;}sc2(35,(long)&nap,0);}return 0;}
static int copy_file(const char*src,const char*dst){
    const long O_RDONLY=0,O_WRONLY=1,O_CREAT=0100,O_TRUNC=01000;
    long in=sc3(2,(long)src,O_RDONLY,0);if(in<0)return 0;
    long out=sc3(2,(long)dst,O_WRONLY|O_CREAT|O_TRUNC,0644);if(out<0){sc1(3,in);return 0;}char buf[8192];
    for(;;){long n=sc3(0,in,(long)buf,sizeof(buf));if(n<0){sc1(3,in);sc1(3,out);return 0;}if(n==0)break;long off=0;while(off<n){long w=sc3(1,out,(long)(buf+off),n-off);if(w<=0){sc1(3,in);sc1(3,out);return 0;}off+=w;}}
    sc1(3,in);sc1(3,out);return 1;
}
static void mkdir_if_needed(const char*path,unsigned mode){long r=sc2(83,(long)path,mode);(void)r;}
void _start(void){
    const long SYS_open=2,SYS_dup2=33,SYS_fork=57,SYS_execve=59,SYS_exit=60,SYS_wait4=61,SYS_chdir=80,SYS_chmod=90,SYS_setgid=106,SYS_setuid=105,SYS_chroot=161,SYS_mount=165;
    const long O_RDWR=2,MS_RDONLY=1;
    long cfd=sc3(SYS_open,(long)"/dev/console",O_RDWR,0);if(cfd>=0){sc2(SYS_dup2,cfd,0);sc2(SYS_dup2,cfd,1);sc2(SYS_dup2,cfd,2);}
    if(!wait_dev("/dev/vda"))fail(1);
    if(!wait_dev("/dev/vdb"))fail(2);
    if(sc5(SYS_mount,(long)"/dev/vda",(long)"/newroot",(long)"squashfs",MS_RDONLY,0)<0)fail(3);
    mkdir_if_needed("/newroot/tmp",01777);
    if(sc5(SYS_mount,(long)"/dev/vdb",(long)"/newroot/tmp",(long)"ext4",0,0)<0)fail(4);
    if(sc2(SYS_chmod,(long)"/newroot/tmp",01777)<0)fail(5);
    mkdir_if_needed("/newroot/dev",0755);
    mkdir_if_needed("/newroot/dev/shm",01777);
    mkdir_if_needed("/newroot/proc",0555);
    mkdir_if_needed("/newroot/sys",0555);
    if(sc5(SYS_mount,(long)"devtmpfs",(long)"/newroot/dev",(long)"devtmpfs",0,0)<0)fail(6);
    mkdir_if_needed("/newroot/dev/shm",01777);
    if(sc5(SYS_mount,(long)"tmpfs",(long)"/newroot/dev/shm",(long)"tmpfs",0,(long)"size=268435456,mode=1777")<0)fail(7);
    if(sc5(SYS_mount,(long)"proc",(long)"/newroot/proc",(long)"proc",0,0)<0)fail(8);
    // sysfs is useful to Chromium but failure is not fatal for this control.
    sc5(SYS_mount,(long)"sysfs",(long)"/newroot/sys",(long)"sysfs",MS_RDONLY,0);
    if(!copy_file("/work/control.js","/newroot/tmp/playwright-control.js"))fail(9);
    if(!copy_file("/work/control.html","/newroot/tmp/playwright-control.html"))fail(10);
    if(sc1(SYS_chroot,(long)"/newroot")<0)fail(11);
    if(sc1(SYS_chdir,(long)"/")<0)fail(12);
    long pid=sc1(SYS_fork,0);
    if(pid==0){
        if(sc1(SYS_setgid,20001)<0)sc1(SYS_exit,120);
        if(sc1(SYS_setuid,20001)<0)sc1(SYS_exit,121);
        char *argv[]={(char*)"/usr/bin/node",(char*)"/tmp/playwright-control.js",0};
        char *envp[]={
            (char*)"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            (char*)"HOME=/home/pwguest",
            (char*)"TMPDIR=/tmp",
            (char*)"LANG=C.UTF-8",
            (char*)"NODE_PATH=/opt/pw/node_modules",
            (char*)"PLAYWRIGHT_BROWSERS_PATH=/ms-playwright",
            (char*)"XDG_RUNTIME_DIR=/tmp/xdg",
            0
        };
        sc3(SYS_execve,(long)"/usr/bin/node",(long)argv,(long)envp);
        sc1(SYS_exit,111);
    }
    int status=0;long waited=sc4(SYS_wait4,pid,(long)&status,0,0);int code=255;
    if(waited==pid&&(status&0x7f)==0)code=(status>>8)&0xff;
    char out[96];usize at=0;at=append_lit(out,at,"FIRECRACKER_PLAYWRIGHT_EXIT code=");at=append_dec(out,at,(u64)code);out[at++]='\n';sc3(1,1,(long)out,(long)at);
    reboot_guest();
}
