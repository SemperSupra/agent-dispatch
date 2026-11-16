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
  if (fd >= 0) {
    const ssize_t sent = write(fd, banner, sizeof(banner)-1);
    close(fd);
    if (sent != (ssize_t)(sizeof(banner)-1)) return 2;
  }
  const ssize_t sent_stdout = write(STDOUT_FILENO, banner, sizeof(banner)-1);
  if (sent_stdout != (ssize_t)(sizeof(banner)-1)) return 3;
  sync();
  sleep(1);
  (void)reboot(RB_POWER_OFF);
  for (;;) sleep(10);
}
