# E16 — RED-preserving USB Fabric QMP threat inventory

Independent reviewer branch based E15 exact live source ancestry. This is a source-pinned *offline* release critic, not an automatically updating GitHub evidence validator or a security remediation.

- H7: actual same-service-UID raw QMP mutation RED (must stay RED).
- H24: inherited Unix FD after unlink RED primitive (must stay RED).
- H26: separate-UID private socket + close-on-exec synthetic PASS_LIMITED.
- H27: real-QEMU different-UID proof is **PASS_LIMITED**, exact PR #945 source a5c26d1ea06cc6877712fb21bd02168b4f9af806, public run 44747558368 job 136326687148 SUCCESS; actual QMP owner query and different-UID denial observed. Same-UID attackers, deliberate FD transfer and a deployed privileged recovery controller are NOT mitigated.

A production exclusive QMP controller, same-UID and inherited-FD mitigations, epoch lineage, fsynced journal clearance, safe next lease and release approval remain false. Any attempted promotion or erasure fails. No merge or production action.

This document is not a replacement for the full cross-repository DLE. Rollback discard this draft branch.
