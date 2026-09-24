# Firecracker sovereign transfer package

Authority: `SemperSupra/agent-dispatch-private#280`

This package transfers the mechanics learned on public GitHub-hosted Actions to a later sovereign KVM-capable Linux host. It is **not** a claim that the sovereign environment is already qualified.

## What transfers

The portable contract is:

- Firecracker v1.17.0 x86_64, exact archive SHA-256
  `06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558`;
- Linux guest kernel 6.18.48, exact SHA-256
  `9204218e8bcca6ac23848d74f45df2eb19d7f31e8277840a7d145a0df8b078d2`;
- deterministic repo-built initramfs;
- fixed public-safe useful-work capsule and result oracle;
- lifecycle timing schema;
- one Firecracker process per microVM;
- networkless guest by default;
- same-host snapshot handoff semantics:
  `pause -> full snapshot -> terminate source -> fresh Firecracker -> load -> resume`;
- host fingerprint gate before cross-host snapshot restore.

GitHub workflow scheduling, GitHub artifact storage, runner image selection, and the hosted runner's passwordless-sudo policy are **venue adapters**, not part of the portable correctness contract.

## Host admission

From a checkout of this repository:

```bash
mkdir -p evidence/firecracker-sovereign
python3 scripts/firecracker_sovereign_preflight.py \
  --out evidence/firecracker-sovereign/preflight.json
```

Admission prerequisites require Linux x86_64, KVM API 12 callable either directly or through an already-authorized passwordless-sudo boundary, the required local tools, and the exact pinned repository artifacts.

A preflight PASS does not qualify the host for operational placement. It only says the reproduction experiments may begin.

Prefer direct user access to `/dev/kvm` on sovereign systems where local policy allows it. The GHA-specific passwordless-sudo crossing is not an architectural requirement.

## Reproduction sequence

Run the smallest useful-work baseline first:

```bash
python3 scripts/github_runner_firecracker_f3_useful_work.py \
  --label sovereign-f3 \
  --input experiments/firecracker/guest/f3-input.txt \
  --out evidence/firecracker-sovereign/f3.json
```

The historical `github_runner_` filename is not a GHA correctness dependency; the script records GHA metadata only when those environment variables exist.

If F3 passes, characterize the local resource class rather than importing GHA capacity assumptions:

```bash
python3 scripts/github_runner_firecracker_p1_concurrency.py \
  --label sovereign-p1 \
  --points 1,2,4 \
  --out evidence/firecracker-sovereign/p1.json
```

Expand past N=4 only when the actual host resource count and workload justify it. Do not adopt the GHA N=6 observation as a local limit or target.

If the intended host will share microVMs with normal process/container work, run coexistence:

```bash
python3 scripts/github_runner_firecracker_p2_coexistence.py \
  --label sovereign-p2 \
  --out evidence/firecracker-sovereign/p2.json
```

P2 requires a callable local Docker daemon. Skip it when Docker coexistence is not part of the intended deployment.

If stateful handoff is intended, reproduce same-host snapshot continuity:

```bash
python3 scripts/github_runner_firecracker_p3_same_host_handoff.py \
  --label sovereign-p3 \
  --out evidence/firecracker-sovereign/p3.json
```

Require a different destination Firecracker PID, source absence before destination resume, no fresh guest READY, a strictly increasing heartbeat counter, and clean destination shutdown.

## Cross-host snapshot admission

Run the preflight independently on each proposed host. On the destination:

```bash
python3 scripts/firecracker_sovereign_preflight.py \
  --compare-to /path/to/source-preflight.json \
  --out evidence/firecracker-sovereign/destination-preflight.json
```

The initial gate requires matching architecture, CPU vendor/model/feature fingerprint, host kernel release, and KVM API. Do not weaken the gate simply to obtain a restore success.

P4 on public GHA demonstrated why this matters: two bounded producer/consumer samples landed on opposite Intel/AMD CPU families. Snapshot transport worked, but restore was correctly withheld.

The transport for a sovereign snapshot bundle is deliberately unspecified. It may be shared storage, object storage, or another locally authorized mechanism. GitHub artifacts are not part of the sovereign microVM contract.

## Coordination

P5 proved that two heterogeneous hosts can keep independent Firecracker guests alive while their host supervisors perform a low-rate offer/ack exchange. The GitHub artifact rendezvous used in RDTE is **not** the sovereign coordination design.

Do not add an overlay network, daemon, or scheduler until a real local workload requires a lower-latency or bidirectional control plane.

## Lifecycle evidence

Keep these categories separate in every local receipt:

- **venue** — artifact acquisition and host-specific adapter work;
- **portable** — VMM extraction/configuration, capsule construction, Firecracker lifecycle, snapshot/load;
- **derived guest** — kernel-to-init, guest work, resume-to-output.

Do not add derived guest timings to host wall-clock stage sums.

## Promotion gate

A sovereign resource class is eligible for Agent Dispatch placement only after the applicable local reps pass:

1. host preflight;
2. F3 fixed useful-work oracle;
3. P1 local concurrency envelope;
4. P2 coexistence when co-resident native/container work is intended;
5. P3 snapshot continuity when stateful handoff is intended;
6. compatibility-gated cross-host validation before any snapshot mobility between hosts;
7. lifecycle/resource receipts retained with exact artifact digests;
8. no GHA environment variable or GitHub artifact service required for portable correctness.

Promotion should remain workload-specific. Do not promote a generic `primitive:microvm` merely because these infrastructure reps pass.
