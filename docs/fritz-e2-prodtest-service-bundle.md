# FRITZ E2-D6 prodtest service-bundle recovery

Authority: `SemperSupra/fritzbox-automation-private#72`.

This public-safe reducer inspects only the six exact units admitted by the already-accepted
`prodtest-network.target` graph. It emits standard service-manager metadata needed to
plan the next runtime falsification: service type, dependency unit names, executable paths
with sanitized argument shapes, fixed absolute EnvironmentFile/PIDFile paths, and sanitized
Condition/Assert operands.

It deliberately distinguishes ordering-only edges such as `After=` from hard activation
requirements such as `Requires=`, `BindsTo=`, or explicit Condition/Assert predicates.

No unit-file body, arbitrary literal value, firmware/rootfs payload, private router evidence,
or mutation capability is retained. The exact firmware is downloaded and extracted
ephemerally on public GitHub Actions and only the reduced JSON receipt is uploaded.
