# agent-dispatch

Minimal public control plane for dispatching bounded engineering tasks to hosted coding agents while keeping GitHub as the durable source/result plane.

## Purpose

This repository intentionally contains only the public-safe implementation and operating contract for the dispatcher. Detailed experiment history, private target metadata, provider/model notes, incident details, and future-work research belong in the private companion repository.

## Current design

The public workflow is not a generic repository/prompt relay. It accepts only:

- an opaque approved target ID; and
- an approved task ID from `config/tasks.json`.

The real repository and starting branch are supplied through secret-backed policy. The dispatcher validates both identifiers, loads only registered task files under `tasks/`, resolves the approved target through the provider, creates the asynchronous session, and exits.

The public control plane does not poll long-running sessions and does not expose private result metadata.

## Task contract

Tasks should be bounded and independently verifiable. Prefer:

- a clear objective;
- explicit constraints;
- deterministic validation commands where practical;
- a clear completion condition;
- no routine corrective prompting.

## Security boundary

See `SECURITY.md` for the public security contract. Core invariants are:

- never commit provider credentials or private target mappings;
- do not accept free-form prompts, repository names, branches, or arbitrary task paths from workflow callers;
- do not execute pull-request/fork-controlled code in a workflow that receives provider credentials;
- public output must not contain private repository names, branches, provider session identifiers/URLs, source identifiers, activities, patches, or private PR metadata;
- expanding authority requires an explicit reviewed policy/task change.

## Phase 0 status

The control path is still experimental. Do not treat the dispatcher as reusable until the documented authorization, branch/ruleset, environment, secret-policy, and public-log controls are active and a hardened end-to-end private-repository round trip has succeeded.

Detailed run history and operational notes are intentionally not maintained in this public repository.

## Scope

This repository is intentionally not a multi-agent platform. Do not add a scheduler, database, queue, routing engine, backend registry, automatic retries, cost optimizer, or broad provider abstraction until experiments demonstrate a concrete need.
