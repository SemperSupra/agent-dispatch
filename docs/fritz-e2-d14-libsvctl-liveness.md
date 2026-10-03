# FRITZ E2-D14 libsvctl basic-block liveness

Authority: `SemperSupra/fritzbox-automation-private#72`.

D13 recovered several exact PIC call edges but left `_svctl_init` and
`_svctl_read` partial because its acceptance rule used a fixed four-instruction
load-to-`jalr` window.

D14 removes that arbitrary distance bound. It accepts a selected GOT target only
when it is loaded into `t9`, remains live, and reaches `jalr t9` without a
`t9` clobber or intervening control transfer in the same basic block.

The reducer is intentionally limited to `_svctl_init` and `_svctl_read`.
Durable evidence contains only selected function/symbol names, accepted edge
classes, outcome counts, and exact target identity. It excludes firmware/rootfs
bytes, binary payloads, disassembly, instruction addresses, GOT offsets, and
wire payload bytes.

A recovered static call edge is structural evidence only. It does not by itself
prove runtime order, packet layout, command enum values, or service-state
semantics.
