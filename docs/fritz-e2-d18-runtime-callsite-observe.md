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


## Attach-only/no-strace falsification

After exact runs localized the first instrumentation failure to the GDB
`target remote` boundary while the QEMU gdbserver listener was already
present, the next treatment removes host `strace`, breakpoint setup, wire
capture, and guest `continue`.

The control launches the exact shipped `/bin/svctl status ctlmgr` under the
same QEMU CPU profile in an isolated loopback-only namespace, attempts only the
RSP attach, records sanitized listener/stage/exit/error classes, and terminates
the disposable target immediately after classification. Raw debugger or target
output is not persisted.

An attach success exonerates the bare QEMU-user RSP path and points to combined
instrumentation interference. A repeated attach stall keeps the fault localized
to the QEMU-user/GDB RSP session boundary. Neither outcome is product behavior
evidence or HIL authority.
