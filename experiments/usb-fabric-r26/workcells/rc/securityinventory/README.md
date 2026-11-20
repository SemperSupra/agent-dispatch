# E16 — RED-preserving USB Fabric QMP threat inventory

Independent reviewer branch based E15 exact live source ancestry. This is a source-pinned *offline* release critic, not an automatically updating GitHub evidence validator or a security remediation.

- H7: actual same-service-UID raw QMP mutation RED (must stay RED).
- H24: inherited Unix FD after unlink RED primitive (must stay RED).
- H26: separate-UID private socket + close-on-exec synthetic PASS_LIMITED.
- H27: real-QEMU different-UID proof is pending at initial source commit, recorded NOT_TESTED even if later CI passes until provenance/manifest are updated and independently verified.

A production exclusive QMP controller, same-UID and inherited-FD mitigations, epoch lineage, fsynced journal clearance, safe next lease and release approval remain false. Any attempted promotion or erasure fails. No merge or production action.

This document is not a replacement for the full cross-repository DLE. Rollback discard this draft branch.
