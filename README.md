# agent-dispatch

Minimal, falsifiable experiment for dispatching bounded engineering tasks to cloud coding agents while keeping GitHub as the durable source/result plane.

## MVP hypothesis

A small public control-plane workflow can invoke the Google Jules REST API against an authorized target repository (including a private repository), return a durable Jules session/result, and do so without copying private source into this repository or keeping a GitHub Actions runner alive while Jules works.

## Phase 0: Jules control-plane smoke test

1. Connect a low-risk target repository to Jules through the Jules web app.
2. Generate a Jules REST API key and store it as the `JULES_API_KEY` Actions secret in this repository.
3. Run the **Jules Dispatch** workflow with a target `owner/repo`, branch, and bounded task prompt.
4. The workflow resolves the target through the Jules Sources API, creates a Jules session, prints the session ID/URL, and exits.
5. After Jules has had time to work, run **Jules Status** with that session ID to retrieve state and any resulting pull request.

The dispatcher deliberately does **not** poll. Jules is the compute plane; GitHub Actions is only the short-lived control plane.

## Success criterion

Phase 0 succeeds if a manually dispatched workflow can create a Jules session against an authorized private target repository and a later status invocation reports the session and resulting private PR, without `@Jules` issue/PR choreography and without private source entering this public repository.

## Kill / reassess criteria

Stop and reassess before building a generalized dispatcher if the API path cannot reliably target private repositories, requires long-lived Actions polling, exposes target source in the public control plane, or needs substantial provider-specific orchestration beyond a thin adapter.

## Security boundary

- Never commit Jules API keys or target-repository credentials.
- Only manual `workflow_dispatch` triggers are used in Phase 0.
- Do not execute pull-request or fork-controlled code in workflows that receive `JULES_API_KEY`.
- Workflow output records only target identifiers and Jules result metadata; it must not copy private source, patches, or activity contents into this public repository.

## Current scope

This repository is intentionally **not** yet a multi-agent platform. No scheduler, database, queue, routing engine, backend registry, automatic retries, or provider abstraction should be added until Phase 0 is demonstrated.

The Jules REST API is currently alpha, so the adapter should remain small and replaceable.
