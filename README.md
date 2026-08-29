# agent-dispatch

Minimal, falsifiable experiment for dispatching bounded engineering tasks to cloud coding agents while keeping GitHub as the durable source/result plane.

## MVP hypothesis

A small public control-plane workflow can invoke the Google Jules REST API against an authorized target repository (including a private repository), return a durable Jules session/result, and do so without copying private source into this repository or keeping a GitHub Actions runner alive while Jules works.

## Current hardened design

The public workflow is intentionally not a generic repository/prompt relay. It accepts only:

- an opaque approved target ID; and
- an approved task ID from `config/tasks.json`.

The real repository and starting branch are supplied through the secret-backed `JULES_TARGETS_JSON` policy. The dispatcher validates both identifiers, loads only registered task files under `tasks/`, resolves the approved target through Jules Sources, and creates the Jules session. Public workflow output is deliberately limited to non-sensitive acceptance/correlation metadata.

The public status workflow was removed. Result inspection is intentionally kept out of public Actions logs.

## Phase 0 experiment status

### Run 001 — control-path partial success / task failure

The first successful dispatch invocation proved that the public GitHub Actions control plane could authenticate to Jules and that Jules could resolve an authorized private target. Jules then failed before repository work began because the submitted starting branch did not exist on the target repository.

This run therefore establishes:

- public Actions -> Jules API authentication: **PASS**;
- Jules -> authorized private repository resolution/access path: **PASS**;
- repository clone: **FAIL (invalid starting branch)**;
- task execution: **NOT TESTED**;
- private pull request/result round trip: **NOT TESTED**.

The hardened design removes caller-supplied branches, so this failure mode is now controlled by the approved target policy rather than workflow input.

No private source, patch, commit, branch, or pull request was produced by Run 001. Historical pre-hardening public Actions logs should be deleted as cleanup because they contain private target/session metadata even though the API credential itself was masked.

## Phase 0 procedure

1. Connect a low-risk target repository to Jules through the Jules web app.
2. Store `JULES_API_KEY` as a secret available only to the protected `jules-dispatch` Environment.
3. Store `JULES_TARGETS_JSON` as a secret mapping opaque target IDs to approved repository/branch pairs.
4. Configure GitHub Workflow Execution Protection, branch/ruleset protection, CODEOWNER review, and Environment approval before treating the dispatcher as reusable.
5. Run **Jules Dispatch** with only an approved target ID and task ID.
6. Inspect the Jules result through a trusted/private path; do not expose private session or PR metadata in public Actions logs.

The dispatcher deliberately does **not** poll. Jules is the compute plane; GitHub Actions is only the short-lived control plane.

## Success criterion

Phase 0 succeeds only when a hardened manual dispatch can create a Jules session against an approved private target and that session completes with a durable private pull request/result, without private source or result metadata entering this public repository or its Actions logs.

## Kill / reassess criteria

Stop and reassess before building a generalized dispatcher if the API path cannot reliably target private repositories, requires long-lived Actions polling, exposes target source in the public control plane, or needs substantial provider-specific orchestration beyond a thin adapter.

## Security boundary

See `SECURITY.md` for the threat model and required controls. Key invariants are:

- never commit Jules API keys, private target names, or private target credentials;
- do not accept free-form prompts, repository names, branches, or arbitrary task paths from workflow callers;
- do not execute pull-request/fork-controlled code in a workflow that receives Jules credentials;
- public output must not contain private repository names, branches, Jules session IDs/URLs, source identifiers, activities, patches, or private PR metadata;
- expansion of authority requires an explicit change to the approved target/task policy.

## Current scope

This repository is intentionally **not** yet a multi-agent platform. No scheduler, database, queue, routing engine, backend registry, automatic retries, or provider abstraction should be added until Phase 0 is demonstrated.

The Jules REST API is currently alpha, so the adapter should remain small and replaceable.
