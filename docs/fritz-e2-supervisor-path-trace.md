# FRITZ E2 R4 — supervisor path-access trace reduction

Private product authority: `SemperSupra/fritzbox-automation-private#72`.

R3 proved the exact supervisor invocation exists for only ~40 ms, exits zero,
never exposes `/tmp/supervisor.ctrl.socket`, and rejects a read-only
`svctl status ctlmgr` attempt made ~6 ms after launch.

R4 does not change the target. It reduces the existing QEMU syscall trace into
an allowlisted sequence of guest absolute path accesses.

Durable evidence contains only:

- path;
- syscall;
- result class (`success`, `ENOENT`, or errno class);
- count;
- first-seen order.

Raw strace remains ephemeral.

The purpose is to distinguish:
- exit before the unit tree;
- actual access to `ctlmgr.service`;
- access to `avmipcd.service`;
- access to `/var/tmp/psupport.data`;
- control-socket attempts;
- other allowlisted runtime dependencies.

A path access is not proof of semantic use, and this rep authorizes no fixture
by itself. It identifies which dependency is eligible for the next causal
treatment.
