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


## Historical cross-repo candidate register

A deeper 2026-10-05 sweep across active SemperSupra repositories and older
`mark-e-deyoung` repositories identified additional workflow families worth
tracking. These are candidates, not commitments. The current
`gha-workload-request/v1` generalization must demonstrate sustained value
before more executor families are added.

### P0 — strongest candidates

#### GARM provider fixture exporters

Repository: `SemperSupra/garm-provider-truenas`

Measured workflows:
- `export-g2-nested-fixtures.yml`
- `export-g3-nested-fixture.yml`
- `export-g4-nested-fixture.yml`
- `export-g5-version-matrix.yml`

G2/G3/G4 share a particularly clean execution geometry:

`exact provider ref -> validate SHA -> checkout -> Go contract tests -> export fixture -> native verifier -> artifact`

This is a strong future candidate for a typed fixture-export request and stable
Go-oriented executor. G5 should remain separate until its larger
upstream-source oracle can be represented without weakening semantics.

**Status:** observe. Do not implement until the current request-driven executor
has accumulated enough successful reps to justify a second family.

#### OCI multi-architecture build and publish

Historical repositories:
- `mark-e-deyoung/minecraft-server-caprover-private`
- `mark-e-deyoung/papermc-server-caprover-private`
- `mark-e-deyoung/velocity-server-caprover-private`

These workflows are nearly identical:

`checkout -> GHCR login -> QEMU -> Buildx -> metadata -> amd64/arm64 build -> conditional publish`

A future `oci-build-request/v1` could type Dockerfile, context, platform set,
image identity, tag policy and publication policy. Package-write authority must
remain explicit and must not be inherited by the read-only generic executor.

**Status:** observe. Strong candidate if another active product repeats this
geometry.

### P1 — worthwhile families after more clustering

#### Android artifact-recovery qualification

Repository: `SemperSupra/android-artifact-recovery`

The repository currently contains 22 qualification/build workflows. Sampling
shows at least four distinct setup families:

- no-setup Python contract/unit-test workloads;
- Java 17 + Gradle + Android/NDK;
- Java 21 + exact Ghidra acquisition/digest verification;
- pinned Android NDK + exact upstream source build.

Potential future audited setup profiles include:

- `android-gradle-j17-v1`
- `ghidra-j21-exact-v1`
- `android-ndk27-source-build-v1`

These must remain bounded profiles, not user-supplied packages/actions/shell.
The native workload verifier remains authoritative.

**Status:** inventory later. Some no-setup Python jobs may fit
`gha-workload-request/v1` directly after equivalence testing.

#### Windows native package lifecycle

Repository: `SemperSupra/windows-package-foundry`

WinGet portable, Scoop and Chocolatey qualification already share:

`release identity + exact digest -> Windows runner -> bounded PowerShell harness -> JSON evidence -> artifact`

A possible `windows-package-lifecycle-request/v1` should expose a bounded
client enum rather than arbitrary PowerShell.

**Status:** hold until the current executor pattern proves durable and the
existing JSON evidence contract is stable.

#### TrueNAS Foundry lightweight validators

Repository: `SemperSupra/truenas-app-foundry`

Lightweight profile, source-contract and target-registry validators may converge
on request-driven execution. Heavy materialization, service-container
qualification, exact-system virtualization and hardware-facing RDTE remain
separate executor classes.

**Status:** evaluate lightweight validators only; do not collapse heavy system
RDTE.

### P2 — preserve as patterns, extract only when another consumer appears

#### Browser / Playwright soak

Repository: `mark-e-deyoung/open-space-duel`

The public black-box and candidate workflows demonstrate a useful typed
browser-soak pattern with bounded iterations and a Chromium/Firefox/WebKit
matrix.

**Status:** do not create `browser-soak-request/v1` until a second product
needs the same lifecycle.

#### WOW Sidecar candidate/publication pipelines

Repository: `SemperSupra/wow-sidecar`

Wheelhouse and container candidate/publication workflows have useful reusable
primitives, but candidate construction and publication deliberately cross
different authority boundaries.

**Status:** harvest primitives opportunistically; keep candidate and publication
boundaries separate.

#### Invite-only repository governance

Observed in:
- `SemperSupra/WineBot`
- `mark-e-deyoung/infrastructure-as-code-private`

The duplicated approved-issues/approved-PRs workflows are a reusable governance
candidate, but this is policy enforcement rather than workload execution.

**Status:** track separately from Agent Dispatch executor convergence.

## Observation period and revisit gate

The campaign now enters an observation-first phase. Do not add a new executor
family merely because duplication exists. The current generalization should
first earn its keep through ordinary use.

Revisit this candidate register when one or more of the following is true:

1. `gha-workload-request/v1` has accumulated multiple independent workload
   reps beyond the initial proving set;
2. at least two workload-specific YAML files have been safely retired or
   materially simplified with equivalent native receipts;
3. a second active project independently repeats one of the candidate execution
   geometries above;
4. maintenance friction, drift or defect evidence shows the duplicated YAML is
   causing measurable cost;
5. a candidate profile can remove duplication without adding arbitrary shell,
   package, PowerShell or GitHub-Action authority.

At revisit, judge the current generalization against these questions:

- Did request count grow faster than executor/workflow count?
- Did operator/human toil decrease?
- Did native semantic receipts remain authoritative?
- Did debugging become easier rather than more indirect?
- Did request validation catch malformed or drifting work before execution?
- Did new setup profiles remain few, bounded and auditable?
- Did any dedicated workflow prove simpler or safer than the generalized path?

A candidate is promoted only when the answers show net reduction in toil and
complexity without weakening provenance, trust boundaries, or semantic oracles.
If the generalized executor adds indirection without measurable benefit, keep
the dedicated workflows and stop expanding the abstraction.

The default posture until that revisit is therefore:

`use current executor -> collect reps -> measure -> generalize only where earned`.
