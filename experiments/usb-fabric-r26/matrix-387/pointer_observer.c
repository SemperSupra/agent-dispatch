/* Independent Linux USB mouse/tablet evdev sensor, not host QMP ACK. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
static int64_t ms(void) {
 struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
 return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;
}
int main(int argc,char **argv) {
 if(argc!=3)return 2;
 int is_abs=strcmp(argv[2],"tablet")==0;
 if(!is_abs && strcmp(argv[2],"mouse")!=0)return 3;
 int fd=open(argv[1],O_RDONLY|O_NONBLOCK|O_CLOEXEC);
 if(fd<0){perror("R26_M1_EVENT_OPEN");return 4;}
 printf("R26_M1_GUEST_POINTER_OBSERVER_READY=PASS kind=%s\n",argv[2]);
 fflush(stdout);
 int moved=0,down=0,up=0;
 int64_t end=ms()+23000;
 while(ms()<end){
  struct pollfd p={.fd=fd,.events=POLLIN};
  int rc=poll(&p,1,300);
  if(rc<0 && errno==EINTR)continue;
  if(rc<0){perror("R26_M1_EVENT_POLL");break;}
  if(rc<=0)continue;
  struct input_event ev;
  ssize_t n=read(fd,&ev,sizeof(ev));
  if(n!=(ssize_t)sizeof(ev))continue;
  if(is_abs && ev.type==EV_ABS && (ev.code==ABS_X||ev.code==ABS_Y))moved=1;
  if(!is_abs && ev.type==EV_REL && (ev.code==REL_X||ev.code==REL_Y))moved=1;
  if(ev.type==EV_KEY && ev.code==BTN_LEFT){
   if(ev.value==1)down=1;
   if(ev.value==0 && down)up=1;
  }
  if(moved && down && up)break;
 }
 close(fd);
 if(moved)printf("R26_M1_GUEST_POINTER_MOTION=PASS kind=%s\n",argv[2]);
 if(down && up)printf("R26_M1_GUEST_BTN_LEFT_DOWN_UP=PASS kind=%s\n",argv[2]);
 if(moved && down && up){
  printf("R26_M1_REAL_GUEST_POINTER_FUNCTION=PASS kind=%s\n",argv[2]);
  fflush(stdout);return 0;
 }
 printf("R26_M1_REAL_GUEST_POINTER_FUNCTION=RED kind=%s moved=%d down=%d up=%d\n",
        argv[2],moved,down,up);fflush(stdout);return 6;
}
