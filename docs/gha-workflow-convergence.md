# GHA workflow convergence inventory

Snapshot: 2026-10-05. Campaign authority: `SemperSupra/agent-dispatch-private#485`.

The public Agent Dispatch repository currently has **75** workflow YAML files:

- **60 FRITZ** workflows;
- **11 GitHub-runner** qualification/workload workflows;
- **2 sealed-public-execution** workflows;
- **1 Jules dispatch** workflow;
- **1 Android edge-host** qualification workflow.

Filename count is not itself technical debt, but the concentration shows where
the next equivalence analysis has the highest potential return.

## Execution-shape families

### A. No-setup direct-Python receipt workloads

Examples:
- `github-runner-primitive.yml`
- `github-runner-workload-frontier.yml`

This is the first earned family for `gha-workload-request/v1`. PR #259 proves
Linux and macOS request bodies through one stable executor while preserving
native receipt classifications.

**Disposition:** migrate candidates only after before/after receipt equivalence.

### B. Audited host-setup + direct-Python receipt workloads

Many FRITZ runtime probes repeat a shape resembling:

1. checkout;
2. install a bounded QEMU/binutils/debugging dependency set;
3. invoke one repository Python probe with exact firmware identity;
4. enforce a probe-specific receipt/oracle boundary;
5. upload sanitized receipt evidence.

The correct generalization is **not** arbitrary `apt-get` input. A future
request version may reference a small, versioned, audited setup profile such as
`fritz-qemu-mips-v1`, while the workload keeps its own semantic oracle.

**Disposition:** inventory exact repeated dependency sets and earn a profile
only if at least two workflows share the same setup semantics.

### C. Sealed public capsule execution

`sealed-public-execution.yml` already has a stable, typed executor boundary
with capsule identity, timeout, result sealing and receipt evidence.

**Disposition:** keep separate. Do not force it behind the generic Python
request executor; its confidentiality/result-mailbox semantics materially
differ.

### D. Heavyweight disposable-system RDTE

TrueNAS/Proxmox work under private #396/#480 binds exact system images,
virtualization/resource policy, immutable session/capsule manifests and
contamination cleanup.

**Disposition:** keep separate and serialized. Reuse the *request/plan/receipt*
pattern, not the lightweight executor implementation.

### E. Specialized runner lifecycle/topology

Service containers, privileged/nested virtualization, Android setup/install,
Windows-native setup and other lifecycle-specific jobs may need dedicated
qualified executors or audited setup profiles.

**Disposition:** consolidate only when repeated geometry is demonstrated; do not
make the v1 executor an arbitrary shell/package runner.

## Migration invariant

The target is **sublinear workflow-YAML growth with workload growth**, not the
smallest possible YAML count.

A dedicated workflow earns its keep when it materially changes:
- privilege/trust boundary;
- runner lifecycle or topology;
- setup semantics;
- confidentiality/publication boundary;
- heavyweight resource/serialization policy;
- native semantic oracle that cannot remain cleanly workload-owned.

Otherwise prefer:

`committed request -> validate/admit -> stable executor -> native receipt/oracle -> reconcile`

Existing workflows are evidence baselines until equivalence is proven. Deletion
is the final step, not the first.


## FRITZ runtime sample — measured duplication

A bounded sample of eight runtime-oriented FRITZ workflows confirms the suspected
shared geometry. All sampled workflows use `ubuntu-24.04`, a contract job plus
a runtime job, a repository Python probe, inline Python receipt enforcement, and
one uploaded receipt artifact.

Two independently named workflows already share an exact host dependency set:

- `fritz-e2-d18-runtime-callsite-observe.yml`
- `fritz-e2-d19d-read-return-runtime.yml`

Both install:

`binutils binutils-mips-linux-gnu curl gdb-multiarch iproute2 qemu-user-static squashfs-tools util-linux`

The sample also contains narrower variants such as
`fritz-e2-order-chain-runtime.yml`, which installs only
`curl iproute2 qemu-user-static squashfs-tools`.

This earns an **audited setup-profile candidate**, but not yet a migration:
`fritz-qemu-mips-debug-v1` can represent the exact repeated dependency set.
The remaining blocker is semantic—not package installation. Current workflows
also contain probe-specific inline receipt assertions. Those assertions should
remain authoritative and move behind explicit verifier entrypoints before a
generic executor replaces the dedicated YAML.

Therefore the next safe decomposition is:

`request -> audited setup profile -> probe argv -> verifier argv -> receipt upload`

not:

`request -> arbitrary packages/shell -> upload whatever happened`.

This keeps setup reuse orthogonal to the workload oracle and lets FRITZ retain
its existing evidence boundaries.
