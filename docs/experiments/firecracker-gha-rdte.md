# Firecracker on public GHA: RDTE experiment

Authority: `SemperSupra/agent-dispatch-private#280`

## Purpose

Public GitHub-hosted Actions is used here as disposable research/development/test/evaluation compute to learn the mechanics of KVM-backed Firecracker execution without consuming sovereign/local resources.

It is not the intended operational venue.

The experiment succeeds only when the useful artifacts and contracts can later be reproduced on an ordinary sovereign KVM-capable Linux host without depending on GitHub Actions for correctness.

## Separation of concerns

Portable experiment state:

- exact VMM artifact identity and digest;
- later guest kernel/rootfs/initrd identity;
- later guest boot and work-capsule contracts;
- later input/output and result-receipt semantics;
- later timeout, shutdown, disposal, and failure semantics.

Venue adapter state:

- runner image and architecture;
- whether `/dev/kvm` is exposed;
- whether the current user may open KVM;
- whether the venue's existing passwordless-`sudo` boundary can call the KVM API;
- temporary workspace and artifact transport.

A venue observation must not be promoted into a portable capability claim.

## Ladder

1. **F0** — verify the exact Firecracker archive and binary version, then record KVM venue preflight.
2. **F1** — boot a minimal pinned Linux guest and prove a serial nonce.
3. **F2** — deliver bounded read-only input and recover bounded output.
4. **F3** — execute a useful networkless work capsule.
5. **F4** — mutate guest machine state, verify behavior, destroy the guest, and prove no authoritative state was lost.
6. Qualify real portfolio workloads only where native/Docker cannot provide the required semantics.
7. Reproduce the accepted portable contract on sovereign/local KVM compute before operational promotion.

Each rung is independently evidenced. F0 does not imply guest boot; F1 does not imply a useful workcell.

## Initial artifact

F0 pins Firecracker v1.17.0 x86_64 by the release archive SHA-256 published with that release. The workflow downloads the exact archive, verifies its bytes, runs the binary version oracle, and records the current runner's KVM boundary separately.

## Guardrails

- public-safe inputs only;
- no credentials or private repository value;
- no guest networking until a workload earns it;
- no snapshots, jailer/cgroup tuning, or generic VM-management layer until required;
- no automatic placement authority;
- no generic `microvm` capability promotion merely because a VMM boots;
- stop for a task class when native or Docker satisfies the same requirements with materially less machinery.

## Transfer check

At every rung ask:

> What would fail if the exact same portable artifacts were handed to an ordinary KVM-capable sovereign Linux host?

Any unnecessary GitHub-specific dependency is debt to eliminate before promotion.
