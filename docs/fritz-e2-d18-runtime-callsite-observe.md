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


## D18a host-strace-only attach control

The accepted no-strace control proves bare QEMU-user/GDB RSP attachment reaches
`post_target`. D18a restores exactly one factor: the host `strace -f` wrapper
used by the earlier combined D18 treatment.

Everything else stays at the accepted control:
- exact shipped `/bin/svctl status ctlmgr`;
- same QEMU CPU profile and isolated loopback-only namespace;
- no breakpoint configuration;
- no wire interpretation;
- no explicit guest `continue`;
- immediate disposable-target termination after attach classification.

If D18a stalls before `post_target`, host ptrace/strace interaction is the
causal candidate for the earlier attach failure. If D18a succeeds, strace alone
is exonerated and the next treatment must add only one remaining instrumentation
factor. Raw strace/debugger/target output is never published.


## D18b debugger-only runtime observation

D18a reproduced the attach stall by restoring host `strace` alone. D18b
therefore removes host strace from each `svctl` process and returns to the
accepted R6 `status -> start -> status` transaction with the D17-constrained
GDB breakpoints.

The runtime receipt accepts only:
- sanitized a0..a3 scalar classes and pointed-memory SHA-256 digests;
- breakpoint-hit completeness for both selected D17 targets;
- pre/start/post equality/difference relationships;
- sanitized GDB listener/stage/exit classes.

Same-run wire capture is deliberately excluded. The already-accepted R9
wire-digest experiment remains an independent oracle and is not reinterpreted
inside D18b. This avoids the strace/RSP observer interaction while preserving a
clean path to runtime verb/argument discrimination.

A status instability or no-difference outcome is an admissible typed result.
No protocol enum, packet-field layout, physical-router behavior, or HIL
authority is inferred.


## D18c dimension-stable comparison

D18b made all six selected breakpoint observations available across the
pre-status / start / post-status transaction, but whole-argument equality was
too coarse: one sub-dimension of `_svctl_send_pkt.a1` varied between the two
status controls.

D18c changes only the reducer. For each already-sanitized a0..a3 observation it
compares:

- scalar class stability across pre/post status;
- presence and equality of the 8-byte memory digest;
- presence and equality of the 260-byte memory digest;
- whether start differs on a dimension that is stable across both status
  controls.

The durable summary contains only class labels and equality/presence booleans.
Digest values are not copied into the comparison receipt. An unstable dimension
does not veto a separate stable sibling dimension, but it also cannot contribute
a discriminator.

No runtime calls, breakpoints, target files, network exposure, wire capture, or
HIL authority are added by D18c.


## D18e shared downstream `_svctl_send` observation

D18d corrected the earlier observation-role model and mechanically earned the
shared `_svctl_send -> send` path as the next runtime role. D18e therefore
moves exactly one step downstream. Before any runtime claim, the exact pinned
D13/D14 topology must reproduce all three edges:

- `_svctl_init -> _svctl_send`;
- `_svctl_send_pkt -> _svctl_send`;
- `_svctl_send -> send`.

Only after that precondition passes does the debugger bind the shared-library
symbol `_svctl_send` across the existing pre-status / start / post-status
transaction. Host strace and same-run wire capture remain excluded.

The reducer is unchanged in spirit: only scalar classes, bounded memory-digest
presence/equality relations, hit completeness, and pre/post status stability
are durable. A start discriminator is accepted only on a dimension stable
across both status controls. A typed negative is an acceptable result.

D18e does not infer protocol enums, packet layout, downstream offsets, physical
router semantics, or modified-HIL authority.
