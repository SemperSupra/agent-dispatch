/* R09 independent guest evdev observer: provider sends KEY_A down only,
 * then drops virtual Ethernet with the USB/IP TCP session open.
 * No synthetic up from this observer. Do not count device removal as key-up.
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
  struct timespec ts; if(clock_gettime(CLOCK_MONOTONIC,&ts))return -1;
  return (int64_t)ts.tv_sec*1000+ts.tv_nsec/1000000;
}
int main(int argc, char **argv) {
  if(argc!=2)return 2;
  int fd=open(argv[1],O_RDONLY|O_NONBLOCK|O_CLOEXEC);
  if(fd<0){perror("R09_EVDEV_OPEN");return 3;}
  puts("R09_OBSERVER_OPENED=PASS");fflush(stdout);
  int down=0,up=0;
  int64_t deadline=nowms()+16000;
  while(nowms()<deadline) {
    struct pollfd p={.fd=fd,.events=POLLIN|POLLHUP|POLLERR};
    int rc=poll(&p,1,200);
    if(rc<0&&errno==EINTR)continue;
    if(rc<0){perror("R09_EVDEV_POLL");close(fd);return 4;}
    if(rc==0)continue;
    if(p.revents&(POLLERR|POLLHUP)){puts("R09_EVDEV_HUP_OR_ERROR=YES");fflush(stdout);break;}
    struct input_event ev;
    ssize_t n=read(fd,&ev,sizeof(ev));
    if(n<0&&(errno==EINTR||errno==EAGAIN))continue;
    if(n<0){perror("R09_EVDEV_READ");break;}
    if(n!=(ssize_t)sizeof(ev))continue;
    if(ev.type!=EV_KEY||ev.code!=KEY_A)continue;
    if(ev.value==1&&!down){down=1;puts("R09_OBSERVER_REAL_KEY_A_DOWN=PASS");fflush(stdout);}
    if(ev.value==0&&down){up=1;puts("R09_OBSERVER_REAL_KEY_A_UP=PASS");fflush(stdout);break;}
  }
  printf("R09_REAL_DOWN=%d REAL_UP=%d\n",down,up);fflush(stdout);
  close(fd);
  if(!down)return 5;
  if(!up){puts("R09_HELD_INPUT_NO_OBSERVED_RELEASE=RED");return 17;}
  puts("R09_ACTUAL_KERNEL_KEY_RELEASE_AFTER_LINK_CUT=PASS");
  return 0;
}
