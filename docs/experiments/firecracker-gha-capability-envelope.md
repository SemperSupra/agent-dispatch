# Firecracker on GitHub-hosted Actions: qualified capability envelope

Authority: \`SemperSupra/agent-dispatch-private#287\`

This document records empirical Firecracker capability on GitHub-hosted runners. It is a placement aid and RDTE record, not a statement that GitHub Actions is the intended operational microVM platform.

## Evidence classes

Use these classes instead of a single \`firecracker=true\` flag:

- **BLOCKED_PREREQUISITE** — the hosted runner does not expose a prerequisite such as \`/dev/kvm\`.
- **CORE_SUPPORTED** — pinned Firecracker can boot the pinned Linux guest and complete the fixed useful-work oracle.
- **HARDENED_SUPPORTED** — jailer privilege drop / namespaces / seccomp and selected resource controls are observed while the guest oracle still passes.
- **RESOURCE_CHARACTERIZED** — CPU/RAM/concurrency behavior has been actively measured, not only configured.
- **STORAGE_SUPPORTED** — writable virtio-block persistence and host reconciliation pass.
- **STORAGE_POLICY_SUPPORTED** — Firecracker block-device rate limiting is observed to change behavior while preserving correctness.
- **NETWORK_SUPPORTED** — bounded guest egress plus negative policy oracles and clean host teardown pass.
- **MOBILITY_CHARACTERIZED** — snapshot/handoff or compatibility-gated state movement has been exercised.

Do not infer a higher class from a lower one.

## Current runner-family fit

| GitHub-hosted runner | Architecture | KVM observation | Firecracker evidence | Current placement status |
| --- | --- | --- | --- | --- |
| \`ubuntu-26.04\` | x86_64 | \`/dev/kvm\` present; KVM API 12 callable through existing non-interactive sudo boundary | Full F3 useful-work guest PASS; deep follow-on qualification on this runner family | **CORE_SUPPORTED + deep characterization** |
| \`ubuntu-24.04\` | x86_64 | \`/dev/kvm\` present; KVM API 12 callable through existing non-interactive sudo boundary | Full F3 useful-work guest PASS | **CORE_SUPPORTED** |
| \`ubuntu-slim\` | x86_64 | \`/dev/kvm\` absent | Guest not attempted | **BLOCKED_PREREQUISITE** |
| \`ubuntu-24.04-arm\` | aarch64 | \`/dev/kvm\` absent | Guest not attempted | **BLOCKED_PREREQUISITE** |
| \`ubuntu-26.04-arm\` | aarch64 | \`/dev/kvm\` absent | Guest not attempted | **BLOCKED_PREREQUISITE** |
| macOS hosted runners | x86_64 / arm64 | no Linux KVM host contract | not a Firecracker host target | **Not applicable to Firecracker** |
| Windows hosted runners | x86_64 / arm64 | no Linux KVM host contract | not a Firecracker host target | **Not applicable to Firecracker** |

The ARM64 hosted-runner result is a GitHub substrate limitation, not a Firecracker AArch64 limitation. Requalify if GitHub begins exposing callable KVM on ARM64.

## Core execution on x86_64 Ubuntu

The fixed F3 workload uses:

- Firecracker v1.17.0 exact pinned archive;
- pinned Linux 6.18.48 guest kernel;
- repo-built deterministic initramfs;
- 1 vCPU / 128 MiB baseline guest;
- separate guest candidate executable;
- no credentials;
- no network or block devices in the core baseline;
- independent host reconciliation.

Direct runner-fit run \`35883807656\` proved the same F3 capsule on both \`ubuntu-24.04\` and \`ubuntu-26.04\`.

Deep experiments below were performed primarily on \`ubuntu-26.04\`; do not project them onto \`ubuntu-24.04\` without a demand-driven parity rep.

## Jailer / defense-in-depth

Observed with the exact v1.17.0 jailer:

- dedicated ephemeral UID/GID privilege drop;
- distinct mount namespace;
- Firecracker seccomp filter mode (\`Seccomp: 2\`);
- \`--new-pid-ns\`;
- \`RLIMIT_NOFILE=128\`;
- \`RLIMIT_FSIZE=1 MiB\`;
- cgroup-v2 \`memory.max=512 MiB\`;
- guest useful-work oracle remains satisfied.

Matched jailed/unjailed concurrency at N=1,2,4 remained functional. At N=4 in run \`35852572661\`:

- unjailed makespan: 1752.830 ms;
- jailed makespan: 1784.951 ms;
- ratio: 1.0183x;
- unjailed aggregate Firecracker RSS: 218,451,968 B;
- jailed aggregate Firecracker RSS: 216,190,976 B.

This single rep does not justify claiming either a speedup or a fixed 1.8% tax. The evidence supports a narrower conclusion: **jailer overhead was small relative to normal hosted-runner variability for this workload and did not create a distinct placement class.**

## CPU envelope

Two facts must remain separate:

### Virtual shape

Firecracker successfully configured and executed guests through 32 vCPUs.

### Effective compute

The GHA host exposes four logical CPUs. Active CPU work shows useful scaling near that physical envelope; increasing guest vCPUs beyond it increases oversubscription and latency rather than creating more compute.

Therefore:

- \`vcpu_count <= 4\` is the natural first-use region for CPU-active work on this runner class;
- higher vCPU counts are valid machine shapes but should be treated as oversubscribed;
- never interpret 32 configured vCPUs as 32 host CPUs.

## Memory envelope

Configured RAM and actively consumed RAM were both tested.

Active deterministic page-touch/readback/checksum oracles passed at:

- 4 GiB working set;
- 6 GiB working set;
- 8 GiB working set.

The final 8 GiB point used a 9 GiB guest and observed:

- Firecracker RSS: 8,906,178,560 B;
- complete guest lifecycle: about 17.05 s;
- host CPU busy: about 40.4%;
- full working-set checksum: PASS.

Memory expansion stopped after this point by design. It establishes feasibility, not a recommendation to consume most of a hosted runner's RAM.

## Same-host concurrency

The unjailed F3 lifecycle workload passed through a deliberately bounded N=6 point on a four-logical-CPU host.

The important observation is not a universal VM-count limit. It is:

- multiple independent Firecracker processes can coexist;
- lifecycle throughput continued to rise into bounded CPU oversubscription;
- CPU pressure and latency increased;
- no instability was observed through the tested point.

Jailed concurrency was separately confirmed at N=1,2,4.

## Writable storage

Run \`35882428970\` qualified a writable non-root virtio-block device:

- 128 MiB ext4 backing image;
- guest wrote and fsynced 64 MiB;
- guest readback checksum matched;
- guest unmounted and shut down cleanly;
- host independently inspected the ext4 image after VM exit;
- persisted \`/probe.bin\` size was exactly 67,108,864 B.

Observed guest write+fsync was about 236.7 ms and read about 29.1 ms in that rep.

### Storage policy

Run \`35883807481\` applied a 16 MiB/s Firecracker block bandwidth token bucket to the same workload:

- baseline write+fsync: 153.711 ms;
- throttled write+fsync: 2420.133 ms;
- slowdown: 15.7446x;
- correctness and persistence remained intact.

Short transfers can exceed the nominal steady-state token-bucket rate because capacity is initially available. Qualify enforcement from matched behavioral change plus correctness, not exact short-window Mbps.

## Network

Firecracker provides a TAP-backed virtio-net device; host routing/filtering is an operator responsibility.

The bounded GHA experiment uses:

- one temporary TAP;
- static /30 guest subnet;
- kernel-command-line guest IP configuration;
- scoped \`iptables-nft\` rules inserted into the host's existing chains;
- outbound masquerade only for the guest IP;
- explicit guest drops for private, link-local and metadata ranges;
- host INPUT drop for guest-originated traffic;
- exact cleanup and restoration of original \`net.ipv4.ip_forward\`;
- no credentials.

A functional R2 rep demonstrated:

- DNS resolution;
- HTTPS status 200 from \`https://example.com/\`;
- TLS 1.3;
- metadata connection blocked;
- host-gateway connection blocked;
- metadata firewall drop counter incremented;
- guest NAT and allowed-forward counters incremented;
- clean Firecracker exit and networking teardown.

Final run `35885788404` classified **SUPPORTED** and established **NETWORK_SUPPORTED** for the bounded Ubuntu 26.04 x64 path:

- DNS returned two IPv4 addresses;
- verified HTTPS returned status 200 and 559 bytes;
- TLS version 772 (TLS 1.3);
- guest probe to `169.254.169.254:80` was blocked;
- guest probe to host gateway `192.0.2.1:80` was blocked;
- metadata drop counter: 1 packet;
- guest NAT counter: 4 packets;
- Firecracker exited cleanly;
- scoped TAP/firewall rules were removed and the original `ip_forward` state was restored.

The guest-side DNS+HTTPS+negative-policy phase took about 1.04 s; the Firecracker network guest lifecycle wrapper was about 2.23 s in that rep.

## Mobility and snapshots

Same-host stateful handoff is qualified:

\`Firecracker A -> pause -> full snapshot -> terminate A -> Firecracker B -> load -> resume\`

The guest continued an in-memory counter in B without re-emitting its boot/READY marker.

Cross-runner snapshot files can be transported, but actual restore is compatibility-gated. Two bounded GHA producer/consumer samples landed on Intel/AMD mismatches, so restore was correctly withheld.

Do not treat GitHub-hosted runners as a homogeneous migration pool.

## Normal Linux userspace

Run `35886922626` qualified the pinned official Firecracker CI Ubuntu 24.04 userspace behind the same microVM boundary:

- Ubuntu 24.04 squashfs: 108,204,032 B, SHA-256 `9820d05b360b5838bfdf3c6d5bc6dc71adfa966075dc7fcd824172134746be21`;
- root userspace remained read-only and retained the exact pre/post SHA-256;
- separate 256 MiB ext4 scratch device mounted over `/tmp`;
- Python 3.12.3 executed successfully;
- `/bin/sh` subprocess behavior passed;
- curl, fio, iproute2 and strace were present and discoverable;
- deterministic scratch payload persisted and was independently recovered by the host after VM exit;
- Firecracker userspace lifecycle: about 1.03 s;
- post-VM scratch reconciliation: about 4.7 ms.

This establishes that Firecracker on the qualified GHA x64 path is not limited to tiny freestanding/initramfs probes. A normal Linux CLI/runtime environment suitable for Python-based tooling can execute inside the microVM while keeping the authoritative root image immutable.

## Native-resource boundary

Firecracker does not make arbitrary host-native devices automatically available to the guest. For the qualified GHA path, assume the portable guest resource vocabulary is limited to deliberately exposed virtual resources such as:

- vCPU;
- RAM;
- virtio-block;
- virtio-net;
- vsock where separately qualified;
- serial/control surfaces.

Do not assume guest access to hosted-runner GPU, USB, FPGA, display, host Docker socket, or other native host resources.

For model-driven work this favors two patterns:

1. trusted actor/model harness outside the microVM, with only bounded execution inside;
2. guest-side thin agent/harness using a deliberately bounded network path to a remote inference API or sovereign model-serving endpoint.

Provider credentials should not be placed into a guest merely because network egress works. A separate secret/inference-broker design must earn that authority.

## Where Firecracker currently fits well on GHA

Strong fit:

- generated or unfamiliar Linux code needing a guest-kernel boundary;
- disposable parser/build/tool execution;
- machine-semantics tests that Docker cannot faithfully represent;
- bounded stateful workcells needing snapshot/checkpoint semantics;
- experiments needing explicit CPU/RAM/block/network controls;
- agent workcells where the model remains outside the guest or is accessed through a narrow API boundary.

Weak fit:

- simple trusted compilation/builds already satisfied by Docker/native;
- workloads requiring host GPU or arbitrary physical devices;
- Windows/macOS-native workloads;
- ARM64 GHA while KVM is absent;
- tasks where reconstructing a tiny environment is cheaper than snapshot transport;
- very low-latency cross-runner coordination.

## Placement invariant

Select Firecracker because the workload requires a property such as:

- separate guest kernel;
- stronger isolation from the host than an ordinary container;
- destructive disposability;
- Linux machine semantics;
- snapshot/checkpoint continuity;
- explicit virtual resource controls.

Do not select Firecracker merely because KVM happens to be available.

Absolute GHA timing/capacity numbers are RDTE observations, not sovereign-host capacity forecasts.
