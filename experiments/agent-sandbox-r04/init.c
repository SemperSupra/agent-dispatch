/* R04 synthetic user-space PID1 for independently observed foreign Linux boot.
 * No credentials, sockets, network, persistent storage, or guest agents. */
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/reboot.h>
#if defined(__aarch64__)
static const char banner[]="R04_GUEST_INIT_REACHED=PASS ARCH=aarch64\n";
#elif defined(__riscv) && __riscv_xlen == 64
static const char banner[]="R04_GUEST_INIT_REACHED=PASS ARCH=riscv64\n";
#else
#error Unsupported ISA for this public synthetic fixture
#endif
int main(void) {
  int fd = open("/dev/console", O_WRONLY | O_NOCTTY);
  if (fd >= 0) { (void)write(fd, banner, sizeof(banner)-1); close(fd); }
  (void)write(STDOUT_FILENO, banner, sizeof(banner)-1);
  sync();
  sleep(1);
  (void)reboot(RB_POWER_OFF);
  for (;;) sleep(10);
}
