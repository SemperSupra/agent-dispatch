# Demand-driven Firecracker workload placement

Authority: `SemperSupra/agent-dispatch-private#415`

This campaign is stacked on public PR #22. PR #27 merged into #22's branch, not `main`; therefore the current Firecracker implementation remains behind #22's promotion/review gate.

## Intent

Use Firecracker as an eligible disposable Linux execution body when a bounded responsibility materially benefits from at least one of:

- stronger isolation for unfamiliar/generated execution;
- destructive disposability;
- real Linux machine/kernel semantics that a container cannot honestly supply;
- controlled body/resource variation for actor qualification;
- prepared-snapshot reset economics demonstrated by repeated workloads.

Do not use Firecracker merely because it is available.

## Execution boundary

```text
project-native durable authority / DLE
        |
        v
Agent Dispatch bounded assignment
        |
        v
body eligibility
  | native | Docker | Firecracker | specialist/HIL
        |
        v
disposable execution
        |
        v
immutable candidate/result/evidence
        |
        v
independent validation
        |
        v
durable reconciliation
        |
        v
destroy disposable body
```

Firecracker owns only materialization, execution, evidence externalization, and teardown. It does not own mission meaning, durable task truth, acceptance, disclosure policy, or provider credentials.

## Current qualified Firecracker envelope

Consume the existing evidence on the #22 branch:

- Firecracker v1.17.0 x86_64 and KVM adapter;
- pinned Linux 6.18.48 guest kernel used by the campaign;
- jailer with UID/GID, PID/mount namespace, seccomp and bounded cgroup/resource controls;
- normal Ubuntu 24.04 userspace;
- immutable root plus writable scratch;
- bounded DNS/HTTPS egress with private/link-local/metadata/host blocking;
- one-use narrow host broker semantics;
- same-host concurrency;
- snapshot/restore;
- mandatory post-restore identity/PRNG/capability reset.

GHA observations remain RDTE observations, not sovereign sizing values.

## Workload flight

### P0 — Playwright control

First establish a public-safe, networkless browser control inside a jailed Firecracker guest.

Required behavior:

1. materialize a pinned Playwright userspace from the official Playwright container;
2. preserve browser sandboxing rather than relying on the outer microVM;
3. launch headless Chromium as an unprivileged guest user;
4. load a local deterministic HTML fixture;
5. execute JavaScript and assert DOM state;
6. capture a screenshot and structured result to writable scratch;
7. independently read and validate outputs outside the guest;
8. prove jail cleanup and rootfs immutability.

Then add matched native and Docker controls and, only after that, bounded external HTTPS.

### P1 — BHADA

Use Firecracker as a qualification body for drift-prone provider/browser paths under BHADA's existing authority. Do not replace BHADA steady-state runtime or alter release/TrueNAS gates.

### P2 — actor/body qualification

Treat `model x harness x config/persona x tools x body x resources x network` as separable variables. Hold mission/authority/acceptance constant when attributing body effects. Preserve multidimensional evidence and failure attribution; no scalar "agent score."

### P3 — dual-track Dream/Tinker/Wake

Run positive/prior-art and challenger/negative/white-space tracks in separate disposable bodies. External reconciliation preserves assumptions, observations, synthetic evidence, validated findings and UNKNOWN. Dream lanes yield resources to accomplishment/validation.

### P4 — specialist pilots

Demand-driven only: RE, EDA, then Blender background/CPU automation. GPU, Windows, TrueNAS appliance, FPGA/USB/BLE/HID/HIL and Android device semantics exit to their qualified specialist substrates.

### P5 — sovereign reproduction

Before private operational placement, reproduce the portable contract on the actual KVM-capable sovereign host and measure that host's own concurrency/coexistence envelope.


## P0a execution substrate

Prefer reuse of the existing `.github/workflows/sealed-public-execution.yml` worker over creating a workload-specific Actions workflow.

The sealed worker already owns the needed generic mechanism:

- public-safe bounded capsule input with content digest;
- standard public GitHub-hosted Linux execution;
- bounded task timeout and output budgets;
- captured task stdout/stderr;
- result-file collection;
- encrypted result mailbox;
- no project acceptance semantics inside the worker.

The P0a capsule is deliberately small. It verifies the exact public repository/revision, installs only `squashfs-tools`, runs the P0a contract tests, and invokes `github_runner_firecracker_playwright_control.py`. The workload itself performs an explicit callable-KVM preflight; a venue without KVM returns `VENUE_LIMITATION` rather than being misclassified as a browser or Firecracker workload failure.

The current sealed workflow is not yet an Agent Dispatch target. The sidecar reserves `workset_id`, `delegation_id`, and `assignment_id` dispatch inputs and correlates runs by the display-title prefix `sidecar:<workset>:<delegation>:<assignment>`. The sealed workflow already declares `assignment_id`; the minimum compatibility delta is therefore:

1. declare required string inputs `workset_id` and `delegation_id`;
2. set `run-name` to `sidecar:${{ inputs.workset_id }}:${{ inputs.delegation_id }}:${{ inputs.assignment_id }}`;
3. leave the sealed worker implementation and existing capsule/result contract unchanged.

Do not add a generic command input, script path, repository selector, arbitrary ref selector, or broader credential. The execution target remains a fixed capability binding for the reviewed P0a capsule.

## Placement test

```text
Linux responsibility?
  no -> another body

Can native/Docker honestly provide every required semantic?
  yes -> does isolation/reset/machine-boundary materially affect
         risk, experiment validity or destructive freedom?
           no  -> native/Docker
           yes -> Firecracker eligible

Requires GPU/device/Windows/TrueNAS/HIL semantics?
  yes -> specialist body
```

Eligibility is not a global score and does not create a scheduler.

## Receipt/evidence minimum

Execution evidence should preserve:

- assignment reference and revision supplied by the caller;
- public-safe/private visibility classification;
- placement reason(s);
- exact input/source digests;
- Firecracker/kernel/rootfs/workload identities;
- resource shape and granted network/capability envelope;
- exit/failure classification;
- exact output artifact digests;
- independent validator reference/result where available;
- cleanup result.

These fields describe execution; they are not a second task schema.

## Red-team controls

Kill/simplify if the implementation begins to create:

- a microVM fleet manager;
- a new work queue or scheduler;
- an image/provider registry;
- a credential vault or generic proxy;
- long-lived authority inside a guest;
- validation that depends only on executor self-report;
- template/image sprawl without measured reuse economics;
- automatic Firecracker-first placement;
- public-GHA private-data handling;
- claims of GPU/HIL/Windows/TrueNAS semantics;
- more coordination/maintenance work than the boundary removes.

## Reusable body/template promotion

Do not pre-create browser/RE/EDA/Blender image families.

A prepared body is earned only when repeated real responsibilities demonstrate all of:

1. materially common dependency set;
2. setup cost large enough to matter;
3. qualified reset semantics;
4. maintenance cheaper than reconstructing per assignment.

Every retained body must have explicit invalidation/deoptimization triggers such as tool/browser/kernel drift, security changes, dependency behavior changes, or failed requalification.

## Deployment tiers

- **Public GHA:** public-safe/synthetic RDTE and qualification only.
- **Sovereign KVM:** private operational placement after reproduction gates.
- **Specialist resources:** GPUs, TrueNAS, Windows, HIL and physical-device semantics.

## Immediate implementation sequence

1. Preserve #22 as the promotion gate to `main`.
2. Add the minimal execution-evidence helper and deterministic contract tests.
3. Execute P0 Firecracker Playwright control on a public hosted x64 runner.
4. Add native/Docker matched controls after the Firecracker control establishes browser feasibility.
5. Reconcile evidence to #415 and proceed only to the next earned workload.
