# FRITZ E2 R4 — one-variable /var/tmp runtime fixture

Authority: `SemperSupra/fritzbox-automation-private#72`.

D4 proves exact `/tmp -> ./var/tmp` while `/var/tmp` is absent from the immutable SquashFS root. R3 proves supervisor fails binding `/tmp/supervisor.ctrl.socket` before loading `ctlmgr.service`.

R4 therefore creates exactly one generic runtime path in the disposable extracted root:

```
/var/tmp
```

It preserves the firmware's exact `/tmp` symlink and does not create `/var/run`, `/dev/shm`, `psupport.data`, avmipcd state, hardware state, or any FRITZ-specific semantic shim.

The directory mode used by this falsification treatment is a local harness choice, not an exact FRITZ boot-mode claim. The experiment asks only whether satisfying the exact symlink target advances the unchanged supervisor treatment across the control-socket boundary.

Only sanitized runtime metadata and the fixed-path trace reduction are durable.
