# FRITZ E2 supervisor runtime

E2-D1 proved the exact 8.25 image contains `/bin/supervisor`,
`/bin/svctl`, the corresponding libraries, and an `rc.net` surface carrying
ctlmgr/svctl/supervisor markers. It did not prove a literal start command.

This E2-R1 rep therefore treats `svctl start ctlmgr` as a falsifiable
hypothesis, not an accepted target contract.

Inside the same loopback-only chroot + mount/PID/network namespace used for
E2-R0, it:

1. launches exact `/bin/supervisor`;
2. confirms a supervisor guest process is observable;
3. only then invokes exact `/bin/svctl start ctlmgr`;
4. observes ctlmgr guest-process and socket state;
5. probes `/login_sid.lua?version=2` only if a TCP listener appears.

No target-specific runtime shim is added. Raw stdout/stderr/strace/HTTP bodies
remain ephemeral. A typed negative is a successful experiment result.

Private product authority: `SemperSupra/fritzbox-automation-private#72`.
