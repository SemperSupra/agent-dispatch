# Windows 2025 Hyper-V placement probe for WinBot

Authority: `SemperSupra/agent-dispatch-private#405`.

Upstream runner census: `SemperSupra/agent-dispatch-private#400`.
Consumer: `mark-e-deyoung/WinBot#70`.

## Question

This is a targeted placement rep, not a new runner census:

> Can one standard public `windows-2025` GitHub-hosted runner control one
> tiny run-owned Hyper-V VM through create, start, inspect, stop, remove, and
> cleanup?

The existing census establishes only passive/adjacent Windows virtualization
state. The separately qualified `windows-2025 -> WSL2` furnished environment
does not establish this Hyper-V VM lifecycle.

## Invocation through Agent Dispatch

The public Agent Dispatch repository is the execution/evidence plane for this
rep. Use the existing GitHub Actions `workflow_dispatch` mechanism; do not add
a scheduler, runner registry, task registry entry, or new receipt schema.

From an authorized GitHub CLI session:

```powershell
gh workflow run windows-2025-hyperv-lifecycle.yml \
  --repo SemperSupra/agent-dispatch \
  --ref <reviewed-ref>
```

The workflow uses exactly one `windows-2025` runner for the capability rep.
Its output is an ordinary Actions artifact containing:

- `receipt.json` — existing `github-runner-capability/v1` receipt augmented
  with `windows:hyper-v-vm-lifecycle`;
- `hyperv-lifecycle.json` — bounded raw evidence for the lifecycle stages.

The raw evidence file is not a second receipt contract.

## Probe prerequisites and guardrails

Prerequisites are intentionally minimal:

- public Agent Dispatch source at the exact reviewed ref;
- standard public `windows-2025` runner availability;
- the Hyper-V feature/module/control surface already present and callable if
  the image provides it.

The probe does **not**:

- enable Windows features;
- start/reconfigure Hyper-V services as a repair;
- reboot the runner;
- attach a guest image, VHD/VHDX, ISO, or network switch;
- use secrets or private WinBot assets;
- access a private repository.

The run-owned VM is Generation 2, 64 MiB startup memory, no VHD, and all
network adapters are removed before start.

## Acceptance oracle

`windows:hyper-v-vm-lifecycle` is `SUPPORTED` only when all of these are
independently observed:

1. the run-owned VM is created;
2. it reaches `Running`;
3. inspection confirms `Running`, zero virtual disks, and zero network
   adapters;
4. it reaches `Off`;
5. it is removed;
6. final cleanup proves both the VM and run-owned directory are absent.

A green workflow is not sufficient by itself. The final workflow gate reads the
receipt and fails unless the capability is `SUPPORTED`,
`oracleSatisfied=true`, and the cleanup oracle passes.

Failures remain evidence-bearing:

- `ENVIRONMENT_FAILURE` — the hosted substrate/control plane rejects the
  required Hyper-V operation;
- `HARNESS_FAILURE` — the probe itself fails independently of the substrate;
- `ORACLE_FAILURE` — a lifecycle/cleanup invariant fails after exercising the
  path.

## WinBot build/qualification placement

Do not couple WinBot qualification inputs to this probe.

If and only if the Hyper-V lifecycle capability is `SUPPORTED`, a separate
WinBot job may target `windows-2025`. That job must bind all inputs
immutably/explicitly:

- exact WinBot source commit;
- exact public guest-image source and SHA-256 (or equivalent immutable
  identity);
- exact contract/validator revision;
- pinned Actions dependencies.

The job must independently validate the resulting guest/WinBot behavior rather
than treating VM boot or workflow success as qualification.

Current WinBot CI is **not** a public-hosted input contract: it looks for a
pre-existing `WinBot-clone-*` VM and reads `C:\WinBot\.api_token`.
The local WinBot master VHDX, local ISO, API token, credentials, and any other
private values must not be projected into public GitHub Actions.

Therefore, even after a Hyper-V-positive result, WinBot build placement remains
blocked until an explicitly authorized public guest input with immutable
identity is selected and its independent validation oracle is documented. Stop
at that dependency rather than substituting a local/private guest.

A permanent self-hosted Hyper-V runner remains an optional optimization under
WinBot #70 only if repeated use later justifies it.

## Accepted qualification evidence

Accepted targeted rep:

- workflow run: `36688159026`;
- execution commit: `e82b65bcf1513e58e79331b70f4d043941466082`;
- requested runner: `windows-2025`;
- observed image: `win25-vs2026` / `20260922.246.2`;
- retained artifact: `windows-2025-hyperv-lifecycle-36688159026-1`;
- artifact digest: `sha256:323eeff03762316814404cfe8b8db8475844f887a16e66ae3f7e4b760d821df7`.

The receipt classified `windows:hyper-v-vm-lifecycle` as `SUPPORTED` with
`oracleSatisfied=true`. The raw evidence records:

- Hyper-V module `2.0.0.0` present;
- Hyper-V server feature installed;
- `vmms` present and running;
- `Get-VMHost` callable;
- hypervisor present and firmware virtualization reported enabled;
- one Generation-2, 64 MiB, no-VHD VM created;
- zero disks and zero network adapters before start;
- `Running` observed;
- running-state inspection again confirmed zero disks/network adapters;
- `Off` observed after stop;
- VM absent after removal;
- run-owned directory absent after final cleanup.

The `Get-WindowsOptionalFeature Microsoft-Hyper-V-All` observation itself
returned a PowerShell property-query failure in this image; the separate
Windows Server feature query reported Hyper-V `Installed`. This is retained as
preflight evidence and does not substitute for the successful lifecycle oracle.

**Placement status:** Hyper-V VM control is proven usable for this exact
`windows-2025` hosted image observation. This is image-bound evidence, not a
provider guarantee that future `windows-2025` images will retain the same
capability.

**WinBot build/qualification status:** not ready yet. The remaining dependency
is an explicitly authorized public guest input with immutable identity plus its
independent WinBot validation oracle. No local/private WinBot image or
credential is an acceptable substitute.

## Public guest-input dependency

The current WinBot source has a reproducibility-oriented `ExactSource` build
path: it can consume an explicit ISO, independently verify media identity/hash,
build a VHDX, run `Test-VHD`, and bind the accepted master hash. That is the
right shape for a future hosted build job.

However, no public-GHA guest input is currently bound as an authorized immutable
input for this placement:

- the canonical builder requires an explicit, already acquired ISO for its
  `ExactSource` path;
- the downloader's built-in CDN table is release-specific and explicitly warns
  that URLs change;
- the legacy Microsoft pre-built-VM path is deprecated and requires a separately
  supplied guest password;
- the existing WinBot parity workflow assumes a pre-existing clone and a local
  API token rather than constructing a public hosted guest from pinned inputs.

A Microsoft Enterprise Evaluation ISO is a plausible public source, but it is
not accepted for this job until one reviewed binding records at least the exact
source identity, expected SHA-256, edition/version/language/architecture,
permitted use for the qualification rep, and resource fit for the hosted
runner. Until then the correct state is `BLOCKED_PUBLIC_GUEST_INPUT`.

When that dependency is satisfied, the separate WinBot job should:

1. check out the exact authorized WinBot source commit with persisted
   credentials disabled;
2. acquire only the authorized guest artifact and fail closed unless its hash
   and declared identity match;
3. generate any run-only guest credential inside the job rather than importing
   local/private credentials;
4. use WinBot's exact-source builder and independently verify the produced
   master (`Test-VHD` + bound master hash);
5. create one disposable run-owned WinBot VM, verify boot/API identity, and run
   the pinned conformance/qualification validator;
6. capture source/build/validator/cleanup evidence;
7. remove the disposable VM, run-owned disks/directories, and run-only
   credentials in an `always()` cleanup path;
8. fail the job unless the independent validation oracle and cleanup both pass.

Do not reinterpret the Hyper-V placement receipt as a WinBot qualification
receipt; it only establishes that the hosted runner can control Hyper-V VMs.
