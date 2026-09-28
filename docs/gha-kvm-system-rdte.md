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
