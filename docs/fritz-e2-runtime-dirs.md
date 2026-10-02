# FRITZ E2 D4 — runtime-directory contract

Authority: `SemperSupra/fritzbox-automation-private#72`.

R3 proved that supervisor fails at its control-socket boundary before `ctlmgr.service` is loaded. D4 therefore inspects only fixed runtime filesystem paths and fixed-path boot/init materialization references from the exact FRITZ!OS 8.25 image.

Fixed paths:
- `/tmp`
- `/var/tmp`
- `/run`
- `/var/run`
- `/dev/shm`
- `/tmp/supervisor.ctrl.socket`

Durable output is limited to path existence/type/mode/symlink target and normalized source-path + fixed-path + operation relations such as mkdir/mount/symlink. Raw scripts, arbitrary source strings, firmware/rootfs bytes, and runtime target state are not published.

D4 creates no runtime fixture. Its purpose is to earn the smallest generic filesystem setup for the next unchanged supervisor retry.
