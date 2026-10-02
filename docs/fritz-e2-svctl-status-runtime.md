# FRITZ E2 R3 — supervisor control and ctlmgr status

Authority: `SemperSupra/fritzbox-automation-private#72`.

R2 proved that exact:

```
/bin/supervisor /lib/systemd/system ctlmgr.service
```

keeps the supervisor process alive but does not materialize `ctlmgr`.

R3 preserves the same isolated treatment and adds only two observations:

1. whether `/tmp/supervisor.ctrl.socket` exists and is a Unix socket after supervisor startup;
2. read-only execution of exact shipped `/bin/svctl status ctlmgr`.

R3 does not invoke `svctl start`, create `/var/tmp/psupport.data`, start `avmipcd`, broaden to `network.target`, or contact a physical router.

Durable output contains only path/type booleans, exit codes, byte counts, normalized missing paths, process/socket observations, and bounded login-response metadata if a listener unexpectedly appears. Raw svctl output and target traces remain ephemeral.
