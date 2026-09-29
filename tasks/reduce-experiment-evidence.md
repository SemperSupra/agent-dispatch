# Reduce experiment evidence

## Objective

Reduce existing experiment, CI, Actions, test, and repository evidence into the smallest decision-relevant update to the target repository's current disposition.

## Responsibilities

- Read repository-local guidance and the active authority first.
- Use existing receipts, logs, artifacts, commits, PRs, issues, and tests; do not rerun experiments merely to create more data unless the authority explicitly requires it.
- Separate advertised, installed, callable, exercised, oracle-satisfied, and workload-relevant evidence where those distinctions matter.
- Identify only evidence that changes a preserve/replace/retire/defer decision, closes/reopens a gate, invalidates stale evidence, or establishes a meaningful blocker.
- Preserve exact provenance when the consequence requires it.
- Prefer editing the repository's existing authority/evidence surface over creating a new ledger or report.

## Constraints

- Review/evidence reduction only unless a tiny documentation/evidence correction is explicitly part of the target authority.
- Do not change product/runtime behavior, workflows, dependencies, secrets, release state, or infrastructure.
- Do not infer success from a green wrapper job when the required inner oracle did not execute.
- Do not infer native-Windows or other executor-specific acceptance from weaker evidence.
- Do not create dashboards, databases, registries, or recurring reporting machinery.
- Do not duplicate routine successful execution evidence.

## Completion criteria

- Material evidence is reconciled against current exact state.
- Stale or weaker evidence is clearly bounded.
- Any disposition or gate change is explicit and supported.
- If nothing decision-relevant changed, no new durable record is created.

## Result contract

When a decision-relevant change exists, update the target repository's existing governing issue/PR/document with the minimum supporting evidence. If mutation requires a PR, return one narrowly scoped PR. If no decision-relevant change exists, make no repository change.
