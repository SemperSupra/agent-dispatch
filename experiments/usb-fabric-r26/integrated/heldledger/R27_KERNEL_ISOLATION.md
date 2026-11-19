# R27-C — Typed Linux USB/IP kernel release stage (ORIGINAL Go authority)

Authoritative DLE: [#531](https://github.com/mark-e-deyoung/infrastructure-as-code-private/issues/531), parent [#525](https://github.com/mark-e-deyoung/infrastructure-as-code-private/issues/525).

This is a **controlled patch to the existing R26 Go heldledger and blue.Manager**, not a second manager, QMP actuator, USB/IP transport or identity provider. Existing `qmp-acked` release semantics remain intact for QEMU-owned virtual USB devices. The new domain-specific `kernel-isolated` stage is valid ONLY after a trusted host sensor verifies actual provider Linux ConfigFS UDC unbind and consumer Linux VHCI quiescence for the exact VM/guest/device/lease, then fsyncs a SHA256 fingerprint while HELD remains true. A separate authenticated in-guest evdev UP must match lease generation/release/event sequence and the same original manager lock before release.

**Non-equivalence:** `AcknowledgeQMPRelease` can never satisfy `ConfirmGuestKernelRelease`; `AcknowledgeKernelIsolation` cannot satisfy the original `ConfirmGuestRelease`. No callback `true` alone represents independent trust; only a properly enrolled, privileged host sensor can supply accepted `KernelIsolationVerifier`. Test callbacks here are synthetic to falsify state machine invariants; actual R27-A ConfigFS + direct B test [#912](https://github.com/SemperSupra/agent-dispatch/pull/912) and R27-B real Linux USBIP preboot key test [#915](https://github.com/SemperSupra/agent-dispatch/pull/915) pass **separately**. Integrate both with this original manager under a single real QEMU/Linux run before promoting any full release gate.

The next owner must thread actual privileged kernel exporter/VHCI sensors into this verifier, cryptographically bind the guest's dynamic lease-scoped Ed25519 UP to the original `blue.Lease`, and fault-inject between UDC unbind, A detach, fsync, B bind/import and broker restart. Tests here do not establish hardware-root guest identity, production authorization, or real-device causality.

No production, physical Pi HIL, site credentials, paid private GHA, automatic merges or branch rewrites.
