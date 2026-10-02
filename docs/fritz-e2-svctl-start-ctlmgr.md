# FRITZ E2 R6 — one-shot ctlmgr service-manager actuator

Private authority: `SemperSupra/fritzbox-automation-private#72`.

R5 established a live supervisor control plane for the exact
`prodtest-network.target` treatment with only the evidence-earned
`/var/tmp` runtime-directory fixture. The supervisor reads
`prodtest-network.target`, `avmipcd.service`, and `ctlmgr.service`, and
`svctl status ctlmgr` returns successfully, but ctlmgr is not automatically
executed.

R6 crosses one new boundary, inside the disposable emulator only:

```
inspect: svctl status ctlmgr
apply:   svctl start ctlmgr     # exactly once
verify:  svctl status ctlmgr + process/listener/login observations
rollback: dispose the emulator root/namespace
```

The treatment does not add `psupport.data`, avmipcd runtime state, hardware
state, `/var/run`, `/dev/shm`, a broader target, or external networking.

Raw `svctl`, target stdout/stderr, syscall traces, and HTTP bodies remain
ephemeral. Status values are compared only through exit code, byte count, and
SHA-256 so a state transition can be detected without publishing proprietary
output.

This is also the first concrete mutation primitive shaped like the eventual
shared human/automation/agent contract: inspect -> apply -> verify with explicit
authority and disposal-based rollback. It does not authorize the equivalent
action on physical HIL.
