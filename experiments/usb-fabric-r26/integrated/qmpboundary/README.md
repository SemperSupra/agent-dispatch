# R27-H26 — separate-QMP-UID and no-inherited-FD primitive

**Security thesis.** Linux socket pathname unlink and cooperative QMP locks do not stop same-UID attackers or inherited file descriptors. H7 is a real-QEMU same-UID raw-device RED; H24 is the inherited FD RED primitive. The next host design must place QMP custody in a separate privileged identity and confine all untrusted actors to broker IPC, with explicit authenticated policies and non-inheritable descriptors.

**This workcell:** a disposable public Ubuntu root-runner Go test makes an owner-only 0700 QMP directory, 0600 Unix socket, verifies privileged owner connection, drops an independent child to uid/gid 65534 using SysProcAttr Credential (no supplemental groups), and proves the other UID cannot connect even with the socket path. A second child tests an established socket FD is not inherited on ordinary exec when marked FD_CLOEXEC. It retains the H24 RED for deliberate ExtraFiles inheritance, same-UID attackers, ptrace/process compromise, SCM_RIGHTS passing, and host-private guest key custody.

**No full QEMU integration:** tests are Linux kernel access-control primitives, not a source-verified management daemon/authorized QMP intermediary. No production account or privilege change. Both positive and negative controls must run on a disposable public free-tier runner. If the public worker does not have privilege for the UID test, report NOT_TESTED, never PASS.

**Next design:** integrate a privileged QMP owner service with authenticated narrow broker IPC, QEMU FD custody, privilege drop for clients, hostile same-UID raw-QMP adversary on actual QEMU, and sole authorized recovery. Never merge the primitive by itself as closure of H7.
