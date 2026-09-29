# Exact-head qualification

## Objective

Qualify the target repository's current bounded candidate at the exact Git commit/PR head identified by the repository's own durable authority.

## Responsibilities

- Read repository-local agent/contributor guidance and the active issue/PR/workset first.
- Resolve the exact candidate SHA from authoritative repository state; do not reuse evidence from an older head.
- Run only repository-provided deterministic checks, tests, linters, parsers, contract validators, or build steps that are applicable in the hosted environment.
- Distinguish product failure, harness/test defect, unavailable capability, transient infrastructure failure, and evidence that requires a different executor.
- Prefer existing native/project validation commands over new helpers.
- If a small cloud-visible defect prevents the existing qualification path from running, repair only that defect when the target authority permits ordinary repository mutation and validate the repair.
- Keep acceptance claims within the evidence class actually produced.

## Constraints

- Do not merge, release, publish, deploy, change secrets, change repository visibility, spend money, or perform destructive cleanup.
- Do not claim native-Windows, interactive-desktop, driver/device, hardware, or other executor-specific acceptance from a hosted environment that cannot produce that evidence.
- Do not create a new test framework, scheduler, registry, orchestration service, or broad compatibility layer merely to obtain a result.
- Do not broaden scope into adjacent cleanup.
- Do not treat agent/provider "completed" state as qualification evidence.
- If the exact head changes during the task, stop and classify prior results as stale rather than silently applying them to the new head.

## Completion criteria

- The exact candidate head is identified.
- Applicable deterministic qualification has run against that exact head.
- Any failure is classified with the smallest useful evidence.
- Any repair is minimal and revalidated.
- Remaining executor/authority boundaries are explicit.

## Result contract

If repository changes are required, return one narrowly scoped pull request. Otherwise return the exact head, commands/checks run, result classification, and the next unresolved evidence boundary through the target repository's normal durable result surface when one exists. Record only evidence that changes a decision or is required to establish exact-head qualification.
