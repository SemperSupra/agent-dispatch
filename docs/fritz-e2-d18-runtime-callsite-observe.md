# FRITZ E2-D18 runtime callsite observation

Authority: `SemperSupra/fritzbox-automation-private#72`.

D17 recovered exactly one static `/bin/svctl` callsite into `_svctl_init` and
one into `_svctl_send_pkt`, but static analysis could not associate their
argument classes with `status` versus `start`.

D18 uses the admitted instrumented-emulator lane while preserving the accepted
R9 `status ctlmgr -> start ctlmgr -> status ctlmgr` transaction and isolated
loopback-only network namespace. QEMU's GDB stub is used only at the two exact
D17 callsites. A GDB Python breakpoint reduces MIPS `a0..a3` immediately to:

- scalar classes;
- SHA-256 digests of readable 8-byte and 260-byte pointed regions.

Raw register values, pointer contents, debugger output, callsite addresses, raw
wire payload, and raw host strace are never written to the durable receipt.
Repeated pre/post status observations must be equal before any start/status
argument difference is accepted.

A differing argument class or digest is correlation evidence for the R9 request
class distinction. It is not protocol enum or packet-field-layout proof.
