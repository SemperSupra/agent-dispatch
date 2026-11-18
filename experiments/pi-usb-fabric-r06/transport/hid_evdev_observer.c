/* Real Linux evdev observer for USB/IP HID A-down/A-up.
 * Reads only a disposable guest's kernel input device; never synthesizes events.
 * Test traffic is fixed synthetic key A, no host keylogging or physical USB.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
static int64_t nowms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC,&ts)!=0) return -1;
    return (int64_t)ts.tv_sec*1000+ts.tv_nsec/1000000;
}
int main(int argc,char **argv) {
    if(argc!=2) return 2;
    int fd=open(argv[1],O_RDONLY|O_NONBLOCK|O_CLOEXEC);
    if(fd<0){perror("R06_EVENT_OPEN");return 3;}
    puts("USBFABRIC_R06_EVDEV_OBSERVER_READY=PASS");
    fflush(stdout);
    int down=0;
    int64_t deadline=nowms()+16000;
    while(nowms()<deadline){
        struct pollfd p={.fd=fd,.events=POLLIN};
        int rc=poll(&p,1,250);
        if(rc<0&&errno==EINTR)continue;
        if(rc<0){perror("R06_EVENT_POLL");close(fd);return 4;}
        if(rc==0)continue;
        struct input_event ev;
        ssize_t n=read(fd,&ev,sizeof(ev));
        if(n<0&&(errno==EAGAIN||errno==EINTR))continue;
        if(n<0){perror("R06_EVENT_READ");close(fd);return 5;}
        if(n!=(ssize_t)sizeof(ev))continue;
        if(ev.type!=EV_KEY||ev.code!=KEY_A)continue;
        if(ev.value==1){down=1;puts("USBFABRIC_R06_REAL_KEY_A_DOWN=PASS");fflush(stdout);}
        if(ev.value==0&&down){
            puts("USBFABRIC_R06_REAL_KEY_A_UP=PASS");
            puts("USBFABRIC_R06_EVDEV_REPORT_TRANSFER=PASS");
            fflush(stdout);
            close(fd);
            return 0;
        }
    }
    printf("USBFABRIC_R06_EVDEV_REPORT_TRANSFER=RED down=%d\n",down);
    close(fd);
    return 6;
}
