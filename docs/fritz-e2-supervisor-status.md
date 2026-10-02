# FRITZ E2 R3 — supervisor control/status observation

Authority: `SemperSupra/fritzbox-automation-private#72`.

E2-R2 proved that the exact service target

```
/bin/supervisor /lib/systemd/system ctlmgr.service
```

keeps supervisor alive while ctlmgr is not observed. R3 keeps that treatment
unchanged and adds read-only observation only:

1. inspect whether `/tmp/supervisor.ctrl.socket` exists and is a Unix socket;
2. invoke exact shipped `/bin/svctl status ctlmgr`;
3. retain only status exit code, stdout/stderr byte counts, normalized missing
   absolute guest paths, process/socket/listener observations, and bounded login
   probe metadata if a TCP listener unexpectedly appears.

R3 does **not** authorize `svctl start`, broad `network.target`, creation of
`/var/tmp/psupport.data`, startup of `avmipcd`, hardware/config fixtures, or
physical-router contact.

The runtime remains a disposable chroot in fresh mount/PID/network namespaces
with loopback as the only interface and no default route. Raw firmware, rootfs,
binaries, stdout/stderr, strace, and HTTP response bodies remain ephemeral.

A typed negative is a successful experiment result when it distinguishes the
next evidence-earned dependency or control-plane state.
