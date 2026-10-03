# TrueNAS parallel execution and resource-governance plan

Authority: `SemperSupra/agent-dispatch-private#480`.

This plan separates conceptual parallelism from runner parallelism. Many read-only,
design, source-audit, matrix, and code lanes may proceed independently. Expensive CI
and real-system execution remain deliberately bounded.

## Resource policy

### Heavyweight

- At most one active Real-system TrueNAS run.
- No automatic retry.
- No speculative matrix sweep.
- Every push-launched TrueNAS run requires a fresh run-request edge with a changed
  `request_id`, an exact-head cheap gate, and reconciliation of the heavyweight
  ownership authority before dispatch.

### Cheap GitHub Actions

- Prefer one orchestration-surface pull request at a time when it runs the shared RDTE
  contract suite.
- A second independent cheap lane is acceptable when it does not duplicate the same
  heavyweight provider smoke/download work.
- Prep branches use the pull-request gate as the authoritative exact-head gate; they do
  not also pay for an identical push gate.
- G3/G4/G5 provider container smokes run only when their provider surfaces changed, or
  by explicit manual dispatch.

### Read-only work

Repository inspection, receipt classification, source/API audits, issue/matrix
reconciliation, documentation, and manifest design may proceed in parallel without a
TrueNAS VM.

## Parallel lanes

A. Session runner / WP2: session envelope, capsule receipts, cleanup/platform membrane.

B. FolioRelay causal qualification: isolate the current public-URI mismatch and prepare
only the bounded successor proven by that evidence.

C. Foundry matrices: keep product inventory/readiness in Foundry and project only READY
exact cells to session manifests.

D. Synthetic OCI/custom-app controls: small orthogonal fixtures that can first be proven
as ordinary containers before admission to TrueNAS capsules.

E. Orchestration/resource governance: fresh-request routing, prep-CI cost control,
cancellation/evidence handling, and stale-replay regression coverage.

F. VM/API source audit: read-only management-plane capability census; nested KVM remains
a separate optional late capsule.

## Sequential gates

1. Session/capsule contracts before a session runner gains mutation authority.
2. Contamination semantics before multi-capsule runtime execution.
3. Single-capsule runtime equivalence before multi-capsule proving.
4. Multi-capsule clean-continuation proof before intentional contamination reps.
5. Product-specific causal fix before its next heavyweight rep.
6. `SUPPORTED` plus `oracleSatisfied=true` on a product/version before advancing that
   product to its next exact target.
7. BETA.3 session acceptance before exact-version session rollout.

## Red-team invariants

- Harness/probe/workflow changes must not replay a stale committed TrueNAS request.
- Session PASS never substitutes for capsule/product PASS.
- Failed cleanup or platform-health reconciliation stops later mutation.
- Resource or authority drift fails closed.
- Parallel branches that modify shared orchestration files are serialized at merge time.
- Existing accepted evidence is reused when semantically equivalent instead of rerun.
- VM/nested-virtualization experiments are excluded from the first multiplexed proving
  session.

## Blue-team expected effect

This preserves independent causal evidence while reducing repeated ISO install/pool
initialization and duplicate cheap CI. Parallel work prepares the next bounded edge while
the single heavyweight lane executes the current one, so runner utilization increases
without creating a thundering herd.
