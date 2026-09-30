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
