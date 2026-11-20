# R27-H24 — inherited QMP FD negative evidence

This critic reproduces the Linux file-descriptor lifetime invariant in disposable public CI. After a Unix QMP-style listener accepts a connection, unlinking its pathname prevents *new* connections but leaves established connections and inherited file descriptors usable. An independently launched subprocess given the existing FD sends a raw QMP-shaped `query-status` frame successfully.

**Evidence type:** kernel/socket **RED primitive**, not an actual new QEMU `device_add` / `device_del` exploit. H7 remains the authoritative actual-QEMU same-UID RED witness. An existing-FD attack is now proven at the IPC primitive level but NOT_TESTED against the full H23 guarded QEMU runtime.

**Threat controls to qualify next:** independently managed privileged QMP owner process, private service identity, authenticated FD-transfer if justified, explicit owner revocation, and no untrusted inheritable QMP FD. An abstract namespace lock and pathname unlink are not security boundaries against an actor who already possesses a live FD.

**No release promotion:** do not interpret successful CI as mitigation of the RED. No physical HIL, production service changes or private runner minutes.
