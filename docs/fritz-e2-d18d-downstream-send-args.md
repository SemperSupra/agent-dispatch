# FRITZ E2-D18d downstream send argument roles

Authority: `SemperSupra/fritzbox-automation-private#72`.

D18c found no stable start/status discriminator at the entry points of
`_svctl_init` and `_svctl_send_pkt`. That negative does not justify arbitrary
digest-window tuning.

Accepted D13/D14 static evidence already provides one mechanically earned
downstream convergence point:

- `_svctl_init -> _svctl_send -> send`;
- `_svctl_send_pkt -> _svctl_send -> send`.

D12 independently localized the accepted R9 size constants 8 and 260 to the two
source paths. D18d therefore follows only those accepted edges and recovers
same-basic-block a0..a3 setup classes at each `_svctl_send` call. The MIPS
`jalr` delay slot is included because it executes before the callee begins.

Only the already-admitted R9 sizes may be labeled specially. No raw
disassembly, instruction addresses, GOT offsets, argument values, binary bytes,
or wire bytes are retained.

A positive result mechanically justifies `_svctl_send` as the next runtime
observation point. It still does not establish verb mapping, protocol enums,
packet layout, physical-router behavior, or HIL authority.
