# FRITZ E2-R9 wire digest discrimination

Authority: `SemperSupra/fritzbox-automation-private#72`.

R9 repeats the already-accepted disposable emulator transaction from E2-R8:

`status ctlmgr -> start ctlmgr (once) -> status ctlmgr`.

The only new observation is an ephemeral **host-side strace wrapper around the shipped
svctl client process**. Control-socket bytes are reduced in memory to:

- direction and syscall order;
- per-syscall returned byte length;
- per-chunk SHA-256;
- concatenated request-stream byte length and SHA-256;
- concatenated response-stream byte length and SHA-256.

Raw control payload bytes and raw host-strace output are not written to the durable
receipt or uploaded as artifacts.

The experiment does not add a target fixture, contact a physical router, authorize
HIL mutation, or infer protocol field semantics from hashes. Syscall chunks are
observation boundaries only; they are not asserted to be protocol message boundaries.
