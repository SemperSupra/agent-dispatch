# GitHub-hosted runner environment census V2 — accepted evidence

Authority: `SemperSupra/agent-dispatch-private#400`.

Prior evidence retained rather than reconstructed:

- `agent-dispatch-private#78` — original zero-cost Actions terrain and Q0.1 primitive qualification;
- `agent-dispatch-private#223` — common `github-runner-capability/v1` receipt semantics;
- `agent-dispatch-private#281/#283` — latent hardware/accelerator annex;
- public implementation lineage through `SemperSupra/agent-dispatch#23`.

This document records the bounded accepted V2 expansion. A green CI job is not
a blanket capability verdict; individual receipt classifications remain
authoritative for the named oracle.

## Accepted execution evidence

### Native hosts and Actions execution models

Initial complete V2 run: `36477984871`.

The contract, every explicit native label, the Actions job-container profile,
and the service-container profile completed successfully:

- Ubuntu 22.04, 24.04, and 26.04 on x64 and arm64;
- `ubuntu-slim`;
- Windows Server 2022, Windows Server 2025, Windows Server 2025 VS2026;
- Windows 11 arm64 and Windows 11 VS2026 arm64;
- macOS 14, macOS 15 arm64, macOS 15 Intel, macOS 26 arm64, macOS 26 Intel;
- `xcode-27`;
- Ubuntu 24.04 job container using Python 3.13/Bookworm;
- Ubuntu 24.04 host with Redis 7 Alpine service container.

Hardening repeat: `36488140449`, final workflow attempt 2 — success.

One macOS 15 Intel first-attempt job produced its receipt successfully but the
artifact upload failed because GitHub's artifact blob hostname returned DNS
`ENOTFOUND`. Only that failed job was retried; the retry succeeded. Preserve
the first attempt as `ENVIRONMENT_FAILURE`/artifact transport evidence, not a
macOS substrate failure.

### Digest-bound Linux userlands

Initial run: `36477984887`.
Hardening repeat: `36488140483` — success.

Both x64 and arm64 parent runners exercised:

- Ubuntu 24.04;
- Debian 13.7 slim;
- Debian 12 slim;
- Alpine 3.24.2;
- Fedora 44;
- Rocky Linux 10.2 minimal.

Each receipt records the parent runner separately from the container userland,
resolves the requested image to repository digest evidence, runs without
container network access, and does not install packages. Alpine identifies a
musl userland; Debian/Fedora/Rocky/Ubuntu remain glibc-family profiles where the
probe can identify libc.

### BSD, illumos, and Haiku guests

Initial run: `36477984889`.

Guest-provenance hardening run: `36488140378`.

The matrix contains:

- FreeBSD 14.5 and 15.1 x86-64;
- FreeBSD 15.1 arm64 and riscv64;
- OpenBSD 7.8/7.9 x86-64 and 7.9 arm64;
- NetBSD 10.1/11.0 x86-64 and 11.0 arm64;
- OmniOS r151056/r151058;
- DragonFlyBSD 6.4.2;
- Haiku R1/beta5 and R1/beta6.

Guest evidence is explicitly `qemu-guest` portability evidence on an
Ubuntu-24.04 parent; it is not a GitHub-native runner claim. The third-party
adapter is pinned to
`cross-platform-actions/action@e0b9770014ba65d5e0815f15b74031c3a635f641`.

The hardening receipts resolve the exact guest image through the builder release
selected by that pinned adapter. Acceptance of `guest:image-identity` requires
both an immutable GitHub release and an exact asset SHA-256.

Representative accepted identities include:

- FreeBSD 15.1 x86-64:
  `sha256:34e4cd936a2484fd7d873a61dbd0b2b6bb31387897e4c7e63a8fdd5b9a72f805`;
- FreeBSD 15.1 riscv64:
  `sha256:1b074283b69944a56a337f9a3a6310c398ec7e7f0fe1a7d7b07a47250f9a01e3`;
- OmniOS r151058:
  `sha256:4c05f975f935be6a40643ddcc5076812f3becf8e5e69c3f78e12fa974bf32d88`;
- Haiku R1/beta6:
  `sha256:ea06282c9c17ab9e9f87ef0a500effb18a4490633329590a2c89ab36723a6c59`.

OmniOS now uses illumos-native resource fallbacks and reports the configured
two logical CPUs and 2 GiB of guest RAM. Haiku's temporary filesystem supports
the symlink oracle but does not satisfy the hard-link oracle in the tested
profile; this is retained as a `NEGATIVE_OBSERVATION`, not a harness failure.

## Placement-relevant observations

These are observations for the exact jobs/images, not provider guarantees.

- Full Ubuntu x64 and arm64 remain approximately four-logical-CPU / 16.7-GB
  observed classes with a live Docker daemon.
- Ubuntu x64 exposes `/dev/kvm`; arm64 does not. Prior #78 Q0.1 evidence
  remains authoritative that the ordinary runner user could not open x64 KVM
  without a furnished privilege step. Presence alone is not baseline KVM
  support.
- `ubuntu-slim` remains materially different: one CPU, roughly 5.2 GB
  observed memory, shared-container semantics, Docker CLI without a local
  daemon, and no KVM device.
- Windows Server x64 retains Administrator context, live Docker daemon, and
  Visual Studio/MSBuild discovery.
- Windows 11 arm64 is a real arm64 native environment with four logical CPUs,
  roughly 17.2 GB observed memory, Administrator context, broad build
  toolchains and MSBuild, but no baseline Docker installation.
- WSL command presence on clean Windows images is not a ready Linux workcell.
- macOS Apple Silicon remains roughly three CPU / 7 GiB observed class; Intel
  remains roughly four CPU / 14 GiB. Intel reports Hypervisor.framework
  callability/`kern.hv_support=1`, but nested virtualization remains
  unqualified unless a real workload oracle earns it.
- IPv4 and IPv6 loopback nonces and experiment-owned filesystem semantics are
  exercised rather than inferred from package/image documentation.

## Furnished execution classes reused from existing evidence

Do not conflate baseline runner state with an environment that can be furnished
inside an explicitly authorized job.

### Windows 2025 -> WSL2

FolioRelay Windows qualification run `36473359879` proves a furnished
`windows-2025 -> WSL2 imported-rootfs` class: WSL2 rootfs import, bounded
network/firewall configuration, host-to-guest reachability, real services,
native Windows print-client interaction, and teardown all complete.

This does not make clean Windows baseline WSL-ready and does not automatically
generalize to Windows 11 arm64.

### Ubuntu 24.04 x64 -> Android 15/API 35 emulator

FolioRelay mobile run `36473359850`, Android capability job
`109100857532`, proves scoped KVM enablement, Android emulator boot, and the
real Android print framework/spooler/BIPS capability surface. Product-specific
PrintManager delivery remains a separate oracle.

### macOS -> CoreSimulator

FolioRelay mobile run `36473359850`, iOS capability job `109100857186`,
proves CoreSimulator and native UIKit printing API execution. The hosted
simulator can report printer contact/completion without durable network
delivery, so it is not admission-quality evidence for real AirPrint delivery.

## Evidence-class vocabulary

Keep at least these classes distinct:

`native-host | shared-container | job-container |
native-host-with-service-container | docker-container-userland | qemu-guest |
furnished-wsl2 | furnished-android-emulator | coresimulator`.

Also preserve the #78 distinction:

`intrinsic/native primitive | furnishable primitive |
absent/documented-negative | unknown`.

## Requalification policy

The V2, userland, and guest workflows are manual after this campaign. Re-run a
whole matrix only when broad image drift makes that useful. Prefer a targeted
runner/profile rep when a concrete workload or regression question names the
needed environment.

Known low-priority gap: Haiku-native resource introspection can be enriched if
a real placement question needs CPU/RAM/storage values. The current identity,
filesystem, tool-surface, architecture, and immutable-image evidence is
sufficient for the present portability question.

No paid/larger runner, private Actions minute, new credential, OIDC grant,
private-value projection, merge/release authority, or automatic placement
promotion was used by this campaign.
