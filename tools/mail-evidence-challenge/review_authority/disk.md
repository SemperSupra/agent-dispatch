# Linux bounded sealed catalog disk transaction reference

This qualification adapter composes the existing signed journal replay with
private regular files, a cooperative nonblocking advisory writer lock,
bounded canonical JSON snapshots, file sync, atomic rename, and directory
sync. It keeps every previously sealed event in the new snapshot. Commit
requires externally held old and approved new head pins and an exact signed
extension. A conflicting stale writer is rejected; identical retry after
publication is idempotent. Load always requires the independent exact trusted
head. Invalid or untrusted on-disk content does not grant authority.

Tests use public fictional keys and temporary directories. Real subprocess
termination before and after rename exercises restart and retry behavior;
this is NOT a hardware power-loss, filesystem failure, distributed consensus,
or multi-host locking qualification. Abandoned staging files can remain after
process death, are ignored, and need separately controlled garbage collection.
No automatic deletion of catalog history, no private source or real mail,
no production key provisioning, mutable external pin update, root rotation,
semantic re-review or release acceptance. Linux-only local-filesystem
reference. Caller controls a private directory and trusted parents; untrusted
writers with directory access and noncooperative processes are out of scope.
The application must reconcile its independently durable trusted head with
the committed receipt; a filesystem snapshot cannot authenticate itself.
