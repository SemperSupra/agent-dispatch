# GitHub-hosted runner capability census

This repository contains the public-safe execution side of a bounded runner
capability experiment.

The census records facts about the ephemeral GitHub-hosted runner itself:
OS/architecture, observed CPU/RAM/storage, selected command/device/framework
presence, and GitHub image provenance. It does not dump environment variables,
addresses, hostnames, credentials, repository secrets, or private target data.

The first experiment mode is passive only. Presence is deliberately not promoted
to proof of callability or workload suitability. Active probes belong in
separate fresh jobs and are added only when passive evidence justifies them.

Receipt schema identifier: github-runner-capability/v1.

Evidence ladder:

advertised -> observed -> installed -> callable -> exercised -> oracleSatisfied

A negative observation is data and must not be converted into a harness failure.
Observed capacity describes one job and is not a GitHub service guarantee.


## Qualified Windows hosted frontier

Current decision-grade evidence from the public `windows-2025` lane is tracked
as exercised workload evidence rather than as a static inventory promise.

### Hyper-V L2

WinInspect PR #32 qualified a bounded Generation-2 Hyper-V Linux guest on
GitHub-hosted `windows-2025`.

Observed/exercised:

- Hyper-V VM creation/start and guest heartbeat;
- guest-generated nonce/boot identity;
- controlled internal vSwitch + WinNAT;
- L1-to-L2 reachability by ICMP and TCP/22;
- guest DNS through the runner-provided Azure resolver;
- guest HTTPS/TCP egress and exact artifact fetch.

Run: `35506233566`.
Artifact: `10604485131`
(`sha256:1a0545602bede66c566cde379fc03320d8709cb5b4b9ede4f02913e466d483b8`).

ICMP to `1.1.1.1` was blocked in that allocation, but DNS + HTTPS succeeded.
Therefore Internet-install/download workflows must use an application-level
oracle rather than requiring public ICMP.

### Windows containers

The same public runner class also qualified the official
`mcr.microsoft.com/windows/nanoserver:ltsc2025` image under both Windows
process isolation and Hyper-V isolation. Each cell produced a distinct
container-generated identity and nonce.

Run: `35508693383`.
Resolved image digest:
`sha256:15760261db306980fd96acf7e2c73779eaaeefdff289339b9526295c88957e56`.

This establishes a cheap disposable Windows user-space execution cell. It does
not establish interactive-desktop, device/driver, full VM lifecycle, or native
WinBot acceptance.


### PowerShell/.NET on Nano Server

A smaller PowerShell-capable Windows cell was qualified using
`mcr.microsoft.com/dotnet/sdk:10.0-nanoserver-ltsc2025`.

Observed on run `35509241703`:

- resolved image digest:
  `sha256:fb909bd5c26908d9e45bae873a279695867e0270ad0a86dc84ae0e3006e80ad6`;
- observed image size: 1,525,644,762 bytes;
- pull time on that allocation: 60.523 seconds;
- PowerShell 7.6.6 and .NET SDK 10.0.401 executed under both process isolation
  and Hyper-V isolation;
- each cell produced a distinct in-container GUID nonce.

Receipt artifact: `10604738980`
(`sha256:ca246bbf0261325a0d13a916e6f1de754b3505bb5a05c9b25b43c3b2b83138b5`).

Prefer this cell for bounded PowerShell/.NET/user-space Windows work when the
workload does not require Server Core-only APIs, desktop/session semantics,
devices/drivers, servicing, or full VM lifecycle. A Server Core LTSC 2025
candidate was observed at about 5.62 GB with about a 289 second pull on one
allocation; it is therefore an explicit workload-earned fallback rather than
the default PowerShell substrate.

### Placement consequence

Prefer the least expensive qualified substrate that preserves the workload's
required semantics:

1. ordinary hosted Windows process execution for non-isolation-sensitive tests;
2. Hyper-V-isolated Windows containers for disposable Windows user-space,
   service, and package experiments when the required API surface is present;
3. full Hyper-V L2 only for VM lifecycle, boot/install, network-appliance,
   desktop/session, or device/driver semantics that containers cannot supply;
4. prepared native Windows/native WinBot executors for acceptance claims that
   require those exact evidence classes.

Do not infer substrate availability from a command alone. Runner allocation and
service state can vary between otherwise identical `windows-2025` jobs; active
work should retain bounded preflight/recovery and preserve the distinction
between unavailable capability and product failure.
