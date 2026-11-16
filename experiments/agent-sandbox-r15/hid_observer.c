/* R15 independent Linux USB HID evdev oracle. NO synthesized events.
 * Reads the kernel's real USB keyboard event node and witnesses KEY_A press
 * AND release only after remote host QMP generates them.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static int64_t monotonic_ms(void) {
 struct timespec t;
 if (clock_gettime(CLOCK_MONOTONIC,&t)!=0)return -1;
 return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
int main(int argc,char**argv) {
 if (argc!=2) return 2;
 int fd=open(argv[1],O_RDONLY|O_NONBLOCK|O_CLOEXEC);
 if (fd<0) {
  perror("R15_CANNOT_OPEN_HID_NODE");
  return 3;
 }
 printf("R15_GUEST_HID_OBSERVER_READY=PASS\n");
 fflush(stdout);
 const int64_t deadline=monotonic_ms()+23000;
 int down=0,up=0;
 while(monotonic_ms()<deadline) {
  struct pollfd p={.fd=fd,.events=POLLIN};
  int rc=poll(&p,1,300);
  if(rc<0 && errno==EINTR)continue;
  if(rc<0){perror("R15_POLL_ERROR");close(fd);return 4;}
  if(rc==0)continue;
  struct input_event ev;
  ssize_t n=read(fd,&ev,sizeof(ev));
  if(n<0 && (errno==EAGAIN||errno==EINTR))continue;
  if(n<0){perror("R15_READ_ERROR");close(fd);return 5;}
  if(n!=(ssize_t)sizeof(ev))continue;
  if(ev.type!=EV_KEY||ev.code!=KEY_A)continue;
  if(ev.value==1) {
   down=1;
   printf("R15_GUEST_USB_KEY_A_DOWN=PASS\n");
   fflush(stdout);
  } else if(ev.value==0 && down) {
   up=1;
   printf("R15_GUEST_USB_KEY_A_UP=PASS\n");
   fflush(stdout);
   break;
  }
 }
 close(fd);
 if(down && up) {
  printf("R15_REAL_USB_KEY_A_DOWN_AND_UP_OBSERVED=PASS\n");
  fflush(stdout);
  return 0;
 }
 printf("R15_REAL_USB_HID_EVENT_ORACLE=RED down=%d up=%d\n",down,up);
 fflush(stdout);
 return 6;
}
