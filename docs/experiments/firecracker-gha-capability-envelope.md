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

## Composed jailed normal userspace

Run \`35955263741\` qualified the complete execution envelope as one unit:

- Firecracker v1.17.0;
- matching jailer;
- dedicated ephemeral UID/GID;
- new PID namespace and separate mount namespace;
- Firecracker seccomp filters;
- pinned Ubuntu 24.04 / Python 3.12.3 userspace;
- immutable squashfs root;
- writable ext4 scratch;
- one TAP-backed virtio-net interface;
- bounded DNS/HTTPS egress;
- host/private/link-local/metadata access denied;
- exact network cleanup.

Observed jailed connected-userspace lifecycle was about **2.70 s**. The guest returned HTTPS 200 over TLS 1.3, persisted scratch state, preserved the exact rootfs hash, and satisfied all jailer/process-boundary oracles.

This closes the composition question: these features are not merely individually compatible; they have been exercised together on \`ubuntu-26.04\` x64.

## Representative Agent Dispatch workload

Run \`35955796457\` executed the actual public Agent Dispatch sealed-execution contract inside a jailed normal-userspace Firecracker guest.

The trusted host staged the exact public bytes of:

- \`scripts/sealed_public_execution.py\`;
- \`tests/test_sealed_public_execution.py\`.

The guest had no repository checkout, no network and no credentials.

Results:

- native contract: **9/9 tests PASS**;
- guest contract: **9/9 tests PASS**;
- exact source SHA reconciled before/inside/after guest execution;
- exact test SHA reconciled before/inside/after guest execution;
- immutable rootfs preserved;
- UID/GID drop, seccomp, PID namespace and mount namespace all observed.

Matched timing in that rep:

- native unittest wall: **105.314 ms**;
- same unittest work inside guest: **237.681 ms**;
- full jailed microVM lifecycle: **1181.012 ms**.

For a trusted ~100 ms task, Firecracker does **not** earn its keep on performance. The extra boundary is justified only when isolation, destructive disposability, machine semantics or warm/stateful behavior materially matters.

The validated architecture is:

\`trusted host authority -> exact bounded work capsule -> jailed Firecracker executor -> reconciled bounded result\`.

## Minimum-authority inference seam

Run \`35958097407\` qualified the credential boundary needed for a guest-side thin harness without putting a reusable model-provider key in the microVM.

The guest could reach exactly one TAP-local host broker endpoint:

\`192.0.2.1:38080/v1/infer\`

The broker:

- accepted one bounded request schema;
- used one random per-run bearer capability;
- accepted exactly one call;
- rejected capability replay with HTTP 409;
- exposed no generic proxy/destination field;
- had no provider credential;
- preserved exact request/response hashes;
- retained only the token SHA in evidence, not the token value.

The guest also proved:

- another host port was blocked;
- metadata was blocked;
- general forwarding was blocked;
- the one-use capability configuration was removed from scratch after consumption.

This qualifies the seam:

\`jailed guest thin harness -> one-use capability -> narrow host broker -> allowlisted backend\`.

A real-provider backend is **NOT_REACHED / CREDENTIAL_OR_BACKEND_PLACEMENT_GATE** on the current public Agent Dispatch surface because no already-authorized host-side provider binding has been established. Do not weaken the boundary by injecting a reusable provider key into the guest.

## Warm normal-userspace snapshots

### W1 — warm-start economics

Run \`35962047767\` snapshotted a live Ubuntu/Python workcell after Python initialization and restored it in a fresh Firecracker process on the same host.

Observed:

- cold boot -> Python READY: **709.196 ms**;
- full 512 MiB snapshot create: **376.203 ms**;
- destination process start: **24.660 ms**;
- snapshot-load stage: **28.663 ms**;
- resume -> first guest output: **44.011 ms**;
- load start -> first guest output: **72.694 ms**;
- cold-ready / warm-first-output ratio: **9.7559x**;
- post-resume Python work completed and persisted correctly.

Warm restore therefore materially reduces response latency when a prepared snapshot already exists. Creating a new snapshot for every tiny task does not automatically beat cold boot because snapshot creation itself is material.

### W2 — raw template reuse duplicates user-space state

Run \`35962360077\` restored the same paused warm snapshot twice sequentially.

The clones shared exactly the same snapshotted:

- application session identifier;
- next Python stdlib PRNG output.

At the same time, both restores logged Linux VM-fork CRNG reseeding and produced different:

- \`os.urandom\` output;
- \`secrets\` output.

Therefore a raw warm snapshot is **not equivalent to a fresh application instance**. Kernel randomness is refreshed, but arbitrary cached/user-space random, identity, token and session state remains cloned.

### W3 — qualified post-restore reinitialization barrier

Run \`35962683812\` turned the W2 warning into an executable template contract.

The template is snapshotted at a named \`TEMPLATE_READY\` barrier. The source is never resumed. Every restored clone's next application phase must:

1. obtain fresh kernel randomness;
2. reseed application PRNG state;
3. regenerate workcell/session identity;
4. regenerate ephemeral capabilities;
5. only then accept or perform work.

Two sequential restores from the same 512 MiB snapshot preserved the same template nonce while producing unique reset state:

- reset seed: unique;
- application session: unique;
- Python PRNG output: unique;
- one-shot capability: unique;
- post-reset work digest: valid and clone-specific.

Warm availability remained fast:

- clone 1 load-start -> reset-ready: **81.278 ms**;
- clone 2 load-start -> reset-ready: **93.156 ms**;
- clone 1 resume -> reset-ready: **47.890 ms**;
- clone 2 resume -> reset-ready: **59.655 ms**.

For the currently pinned Linux 6.18.48 guest, the qualified reusable-template rule is therefore explicit application reinitialization after restore. Do not assume all libraries/runtimes automatically detect snapshot cloning.

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

## Current placement decision table

| Workload property | Native | Docker | Jailed Firecracker on qualified GHA x64 |
| --- | --- | --- | --- |
| Trusted short process/tool work | Preferred when reproducibility/isolation needs are low | Good when packaging matters | Usually unnecessary lifecycle cost |
| Reproducible trusted build/toolchain | Viable | Usually preferred | Use only when separate guest kernel materially matters |
| Generated/unfamiliar Linux code | Weaker containment | Shares host kernel | **Strong current fit** |
| Normal Python/CLI runtime needed | Yes | Yes | **Qualified** with immutable Ubuntu root + scratch |
| Host kernel must not be shared with candidate | No | No | **Qualified property** |
| Bounded writable storage | Host filesystem | Container mount/volume | **Qualified virtio-block + rate limiting** |
| Bounded outbound HTTPS | Host network | Container network | **Qualified TAP/firewall policy** |
| Reusable provider credential inside workload | Possible but authority-sensitive | Possible but authority-sensitive | **Do not place in guest; use narrow broker seam** |
| Warm prepared state / checkpoint | Process-specific | Container-specific | **Qualified snapshot path with reset barrier** |
| Same-host state handoff | Process-specific | Not VM state | **Qualified** |
| Cross-runner state movement | N/A | Reconstruct/image pull usually easier | Transport works; restore remains CPU/host compatibility-gated |
| Host GPU/USB/FPGA/direct device access | Strong | Often possible with explicit pass-through | **Poor fit / not exposed by current qualified path** |
| ARM64 GitHub-hosted runner | Native works | Docker works | **Blocked: no /dev/kvm observed** |
| ubuntu-slim | Native works | venue-specific | **Blocked: no /dev/kvm observed** |

This table is descriptive evidence, not automatic placement authority.

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
