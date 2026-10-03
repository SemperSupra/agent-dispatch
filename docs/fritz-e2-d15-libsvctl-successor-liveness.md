# FRITZ E2-D15 libsvctl successor liveness

Authority: `SemperSupra/fritzbox-automation-private#72`.

D14 recovered `_svctl_init -> _svctl_send` but correctly stopped the
`_svctl_read` treatment at a basic-block boundary. D15 follows only that first
mechanically identified direct control-flow boundary.

The reducer:

- keeps the selected libc `read` GOT target in `t9` as the only admitted target;
- models the MIPS branch delay slot explicitly;
- models branch-likely annul behavior on the not-taken path;
- follows only direct in-function successor(s);
- stops before a second control transfer;
- accepts `_svctl_read -> read` only when the same `t9` value remains live to
  `jalr t9` on an admitted successor path.

A typed partial/negative is an acceptable result. The reducer does not publish
instruction addresses, disassembly, GOT offsets, firmware/rootfs bytes, or wire
payload. Static call-edge recovery is structural evidence only and does not
establish runtime execution order, protocol field layout, enum values, or
service-state semantics.
