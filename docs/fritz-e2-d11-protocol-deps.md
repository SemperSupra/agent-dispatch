# FRITZ E2-D11 protocol dependency slice

Authority: `SemperSupra/fritzbox-automation-private#72`.

D10 showed that the exact `/bin/svctl` carries the fixed command vocabulary and
`supervisor.ctrl.socket` marker but does not directly expose the searched
socket/read/write import surface. Earlier exact runtime tracing already observed
`libsvctl.so.1` and `libsupervisor.so.1`.

D11 follows exact ELF dependency edges into those shipped libraries and reduces
only dependency metadata, selected control-related symbol names, fixed token
counts, and fixed 8/260-byte adjacency around allowlisted I/O references.

Raw binaries, disassembly, arbitrary strings, and wire payload bytes are excluded.
Symbol presence and fixed-size adjacency are candidate relationships, not proof of
protocol field layout or enum semantics.
