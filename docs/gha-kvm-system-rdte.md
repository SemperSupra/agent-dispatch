# Real-system KVM RDTE on public GitHub Actions

Private experiment authority: `SemperSupra/agent-dispatch-private#396`.

This public experiment qualifies whether the already-proven x64 GitHub-hosted KVM
surface can run disposable **real TrueNAS and Proxmox systems** for development and
compatibility testing. It extends the accepted runner census from
`SemperSupra/agent-dispatch-private#223`; it does not reopen or reinterpret that census.

## Responsibility boundary

```text
Agent Dispatch / private experiment authority
                |
                v
public-safe system RDTE adapters
  SemperSupra/agent-dispatch
        |               |
        v               v
   TrueNAS ISO      Proxmox ISO
        |               |
        +---- QEMU/KVM -+
                |
                v
       sanitized qualification receipt

TrueNAS App Foundry consumes a proven TrueNAS target profile later.
It does not own or duplicate the VM substrate.
```

The common contract is deliberately small: host/resource preflight, exact source
identity, KVM entry gate, bounded target shape, target oracle, evidence classification,
diagnostics, and teardown. Installer behavior stays target-local.

## Initial target rungs

### TrueNAS

Initial target: pinned `26.0.0-BETA.3`.

- **T0 (implemented here):** vendor SHA256 sidecar -> exact ISO verification -> serial-observable installer boot.
- **T1:** invoke the vendor's own installer machinery deterministically.
- **T2:** boot installed TrueNAS and prove middleware/API health.
- **T3:** attach disposable sparse data disks and create a real ZFS pool.
- **T4:** initialize Apps and run one synthetic public-safe custom app.
- **T5:** app lifecycle/configuration/restart/delete.
- **T6:** consume an exact public TrueNAS App Foundry materialization control.
- **T7:** only after T0-T6, add stable and moving prerelease/nightly profiles.

The T0 ISO modification changes only GRUB console observability so the experiment has
a machine-readable serial oracle. It does not substitute a different installer.

### Proxmox VE

Initial target: pinned `9.2-1`.

The adapter embeds a minimal answer file using the vendor automated-installer contract,
constructs an auto-installable ISO, patches only the automated boot entry to expose its
console on `ttyS0`, installs to a disposable sparse SCSI disk, boots the installed
system, and probes its HTTPS API.

Current rungs:

- **P0:** exact ISO + published digest.
- **P1:** official unattended installation.
- **P2:** installed management-plane/API response.
- **P4 observation:** if SSH is available, record whether nested KVM is exposed.
- **P3/P5:** LXC lifecycle and an actual L3 KVM VCPU nonce are follow-up gates; presence
  of `/dev/kvm` is not sufficient evidence for P5.

## Resource and safety guardrails

- public/free GitHub-hosted x64 runners only;
- one heavyweight system VM at a time;
- no private repository payloads or credentials;
- no paid/larger runner assumptions;
- TrueNAS guest capped at 8 GiB for the first rung;
- sparse virtual disks only;
- host RAM/disk headroom checked before a multi-gigabyte download/VM launch;
- localhost port forwards instead of persistent host bridges/TAP configuration;
- no stress/load testing;
- experiment-owned state removed on exit;
- failures are receipts, not automatically failed CI jobs.

A public GHA pass is RDTE evidence for this virtual target profile. It is not physical
hardware qualification and is not production hosting.

## Evidence semantics

Retain the existing ladder:

```text
advertised -> observed -> installed -> callable -> exercised -> oracleSatisfied
```

and classifications including `SUPPORTED`, `INCONCLUSIVE`,
`HARNESS_FAILURE`, `ENVIRONMENT_FAILURE`, `ORACLE_FAILURE`, and
`SKIPPED_GUARDRAIL`.

Do not promote placement or target support merely because the workflow is green.

## Active-campaign workflow posture

During the bounded experiment campaign the workflow is allowed to run on pushes to the
single experiment branch so harness corrections receive real hosted-runner evidence.
After the active qualification rungs complete, freeze it back to explicit
`workflow_dispatch` as done by the earlier runner-census campaign.

The workflow installs only host-side packages required to supply the already-qualified
QEMU/KVM test mechanism (`qemu-system-x86`, `qemu-utils`, `xorriso`, and
`sshpass`). Target operating-system packages are supplied by their pinned vendor ISOs.

## Promotion boundary

Only after TrueNAS T4/T5 pass should TrueNAS App Foundry receive a runtime target-profile
adapter. Only public materializations are eligible for this public RDTE. Application
development remains in product repositories and private promotion/evaluator authority
remains outside this public repository.


## Active-campaign target scoping

Heavy system jobs are demand-scoped during the experiment campaign. A push that
changes only the Proxmox adapter runs the Proxmox lane; a push that changes the
TrueNAS adapter or installer RPC probe runs the TrueNAS lane. Contract, test, or
documentation-only changes do not launch a system VM. Manual dispatch can request
`proxmox`, `truenas`, or `both`.

When both heavy targets are requested they remain serialized. This keeps the public
free-tier RDTE useful without replaying multi-gigabyte installs that cannot change the
evidence under test.


### TrueNAS T1 service-oracle semantics

QEMU user-mode `hostfwd` accepting a localhost TCP connection is not a TrueNAS
installer-service oracle. T1 records that condition only as
`installer_rpc_hostfwd_accepted` diagnostic evidence. T1 is satisfied only by a
completed WebSocket/JSON-RPC exchange with the pinned installer that successfully
returns the read-only discovery methods.

The T0 serial marker remains the T0-only oracle. On T1, a successful response from
the vendor installer RPC is stronger evidence that the installer environment is
running, so lack of an earlier serial-label observation does not negate a completed
RPC oracle. This avoids both a premature TCP false positive and a weaker-oracle
dependency blocking a stronger observed interface.


### TrueNAS T2 install + installed middleware

T2 is a single disposable-system execution with separately retained sub-oracles:

1. T1 read-only installer JSON-RPC discovery must pass.
2. The mutating installer client refuses adopted state, requires exactly one
   non-removable destination disk and one non-loopback NIC, configures
   `truenas_admin` with an ephemeral non-repository password, enables DHCP,
   and requires the vendor `install` RPC to return successfully.
3. Only after that response (the upstream installer has exported `boot-pool`)
   is the installer VM terminated.
4. The same qcow2 is booted with a stable virtual NIC identity.
5. Installed middleware is qualified independently over its source-defined DDP
   `/websocket` interface using `auth.login_ex` with `PASSWORD_PLAIN`,
   followed by `system.version` and `system.info`.

An installed-middleware failure therefore does not erase a successful installer
sub-oracle. Fresh TrueNAS installation installs both i386-pc GRUB and EFI GRUB,
so the disposable legacy-BIOS QEMU target is a valid post-install boot oracle.


### TrueNAS T3 disposable ZFS data pool

T3 extends the accepted T2 system without changing the installer disk shape. The
installer still sees only the 24-GiB boot target. After vendor installation completes,
the installed-system boot adds exactly two experiment-owned 8-GiB sparse virtio disks. They are attached as explicit virtio-blk devices with deterministic serial identities `RDTE_DATA_0` and `RDTE_DATA_1`. The installed-system topology is explicit: the virtio NIC is PCI `0x3`, the TrueNAS boot virtio-blk device is PCI `0x4` with `bootindex=1`, and the data disks are PCI `0x5` and `0x6`. QEMU `-boot order=c` is not mixed with `bootindex`; the installed boot uses `-boot strict=on` so firmware follows the per-device boot priority.

The T3 middleware client then:
- authenticates through the accepted installed-system DDP surface;
- records `boot.get_disks` and refuses any overlap with data candidates;
- requires exactly two disks from `disk.get_unused`;
- creates `rdtepool` as one two-disk `MIRROR`;
- waits for the returned `pool.create` job ID to reach `SUCCESS`;
- requires an independent `pool.query` oracle reporting `ONLINE` and healthy;
- requires `pool.get_disks` membership to match exactly the two selected data disks.

QEMU disk attachment, middleware unused-disk classification, job acceptance, and pool
health are separate observations. T3 does not imply Apps support; T4 remains a distinct
gate.


### QEMU T3 topology oracle

Before another full TrueNAS T3 installation is spent, a cheap Ubuntu 26.04 job
instantiates the proposed installed-guest hardware shape under the hosted runner's
actual QEMU package without booting an operating system. QMP must report:

- virtio NIC at PCI slot 0x3;
- explicit TrueNAS boot virtio-blk device at slot 0x4 with `bootindex=1`;
- experiment data disks at slots 0x5 and 0x6;
- data-disk serials `RDTE_DATA_0` and `RDTE_DATA_1`.

This oracle exists because QEMU auto-assigns PCI devices to the first available
non-reserved slot and virtio-blk exposes both `serial` and `bootindex` as device
properties. It validates QEMU realization separately from the expensive TrueNAS
installer/boot/pool oracle.


### TrueNAS T4 Apps runtime

T4 builds directly on the accepted T3 disposable mirror. The BETA.3 source-defined
control path is used end-to-end:

1. require the `APPS` entitlement reported by `truenas.entitlements.check`;
2. run the real `docker.update({"pool":"rdtepool"})` job and independently require
   `docker.config.pool == "rdtepool"` plus `docker.status == RUNNING`;
3. create the upstream-test-shaped custom app `rdte-t4-probe` with a minimal
   `nginx:1.27-alpine` Compose service;
4. wait for the `app.create` job to succeed, then independently poll `app.query`;
5. require app state `RUNNING`, `custom_app == true`, exactly one active container,
   service name `web`, image `nginx:1.27-alpine`, and container state `running`.

The TrueNAS 26.0 entitlement matrix grants Apps to an unlicensed generic/VM Community
Edition system, so this QEMU target is expected to be eligible without adding a license.
T4 still does not promote broader lifecycle semantics or App Foundry materialization;
those remain T5 and T6.


### TrueNAS BETA.3 source binding

Runtime API contracts for the 26.0.0-BETA.3 lane are bound to the published
`TS-26.0.0-BETA.3` middleware tag, commit
`81e1265a86083888ba94a2bdfc02ff5c9c5ef6a3`.

That tagged tree predates the later `truenas.entitlements.*` service. Its Apps gate
is `docker.license_active`: non-HA systems are permitted directly, while HA-capable
systems consult `system.feature_enabled("APPS")`. The T4 client therefore does not
call the later entitlement API; `docker.update` and Docker startup exercise the
actual BETA.3 product gate.
