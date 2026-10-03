# FRITZ E2-D16 libsvctl call/return boundary

Authority: `SemperSupra/fritzbox-automation-private#72`.

D15 showed that the selected libc `read` GOT target in `_svctl_read` reaches a
call/terminal transfer before a provable `jalr t9`. D16 does not assume the
caller-saved `t9` register survives that transfer.

The edge can be accepted only if either:

1. the exact selected `read` target is freshly reloaded into `t9` after the
   call returns and remains live to `jalr t9`; or
2. a directly resolved bounded callee contains no `t9` writes, no nested calls,
   and at least one return, after which the post-return path reaches `jalr t9`
   without another transfer or clobber.

The MIPS delay slot is checked. Durable evidence excludes instruction addresses,
raw disassembly, GOT offsets, firmware/rootfs bytes, and wire payload. Static
call-edge recovery remains structural evidence, not runtime-order or protocol
state proof.
