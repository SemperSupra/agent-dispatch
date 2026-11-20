# H27 real-QEMU private-UID access-control experiment

Runs an **actual QEMU** process as uid/gid 65532 in a private 0700 monitor directory on a disposable public Ubuntu Actions runner, and tests QMP query-status through the owner principal. A second process running as UID/GID 65534 must fail to connect even with full pathname knowledge. The surviving QEMU process and cleanup must be witnessed.

**Scope:** genuine QEMU host pathname access denial to a *different* UID only. Same UID (H7), existing/explicitly inherited descriptors (H24), process compromise, ptrace, credential theft, guest key custody, a deployable privileged QMP owner, kernel namespace escapes and complete crash recovery are NOT mitigated. In particular, this does not imply an existing broker/actuator now runs under a separate credential or that a QMP management-plane release gate can pass. Production remains RED/BLOCKED.

No physical HIL, existing system account changes, cloud paid minutes, or production deployment. The test obtains temporary root only within a disposable public Actions job.
