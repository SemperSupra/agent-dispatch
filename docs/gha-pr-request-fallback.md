# Public-safe PR-triggered CPU request fallback (candidate)

**Status:** Draft platform implementation. Not a replacement for authenticated Agent Dispatch workset admission. This is a reusable public-synthetic PR-event fallback when `workflow_dispatch` is not exposed to an otherwise authorized GitHub branch/PR actor.

## One-time platform installation

Extend the **existing** `.github/workflows/gha-typed-public-cpu.yml` with one `pr-public-synthetic-request` job. The workflow already listens to `requests/gha/**`; no new workflow, per-job YAML change, scheduler, credentials, webhook endpoint, GitHub App, or service is required.

The platform job executes only for a new PR (`opened`, run attempt 1), with `permissions: contents: read`, pinned `actions/checkout`, no persisted checkout credentials and the existing fixed public CPU executor and independent receipt verifier.

## Request-only operation

Add **exactly one new file** named `requests/gha/pr-<opaque-assignment-id>.json` to an otherwise unchanged, same-repository branch and open one **draft** PR against the reviewed executor branch. A normal production install uses reviewed `main`.

Example public-synthetic request:

```json
{
  "schema": "gha-workload-request/v1",
  "assignment_id": "pr-example-cpu-one",
  "runner": "ubuntu-24.04",
  "workload": "arithmetic-oracle",
  "timeout_seconds": 30,
  "data_class": "public-synthetic",
  "max_attempts": 1,
  "max_cost_usd": 0
}
```

All fields must match the **existing** `scripts/gha_workload_request.py` validator. Only the fixed x64 arithmetic oracle is admitted in this first bounded slice; other workload profiles still require independently justified explicit expansion. The filename stem must equal `assignment_id`. Only `pr-[a-z0-9-]` names within the bounded pattern are accepted.

GitHub's native PR event checks out its read-only **merge ref**. The adapter compares actual merge commit, first parent (base) and second parent (PR head) with the trusted GitHub event identities. It requires exactly one newly added PR request file versus base. Mixed code+request edits, modified existing manifests, symlinks, fork origins, duplicated JSON keys, unsupported profiles, private data classes, extra fields, nonzero cost, retries, event replays, and wrong source identity fail closed **before the PR-specific workload**. Normal PRs with no `pr-` manifest produce `NOT_APPLICABLE` and do not execute the optional PR-specific workload.

The adapter calls the **existing** typed `plan/run` implementation and existing independent receipt verifier; it does not accept shell, scripts, URLs or executable artifacts from request input.

## Required native evidence

Read back GitHub Actions **actual** run, PR head/merge source SHA, job IDs, runner image/arch, attempt number, admission and workload step logs, fixed workload verdict, `request_sha256`, receipt artifact SHA and independent verdict. Distinguish an observed public-synthetic CPU oracle from workset authorization, private source compilation, or live-system proof. Public job success alone is not semantic qualification.

No user queries, confidential code, media, signed URLs, tokens, credentials, real host topology or private project names belong in public PR source, logs or artifacts. Native PR event write access is **not** a general Agent Dispatch `dispatch_execution` grant. Keep PRs draft/unmerged until an independent review; do not force a rerun/replay to satisfy a failed gate.

## Minimal reusable WOW prompt

> Execute the next *public-synthetic* bounded RDTE assignment through the existing public typed CPU workflow. Confirm the reviewed base/executor first. Create a same-repository draft PR containing exactly one new `requests/gha/pr-<id>.json` manifest using an already-approved static workload profile; do not edit workflow YAML, execute arbitrary code, publish private source, or use secrets/media. Read back the native GHA run/job/attempt/source SHA/request digest/log/artifact and independently verify the verdict. Reconcile evidence and remaining holds to the originating authoritative DLE. Preserve draft/unmerged state and classify any unsupported private-source/live-system proof as NOT_RUN.

## Limits and future scope

This first lane is x64 CPU + deterministic arithmetic fixtures only. No ARM matrix expansion, arbitrary binaries, network access, automatic merge, replay control across *distinct PRs*, or authenticated project-specific workset admission. A trusted coordinator must prevent two different PRs from claiming the same logical assignment; native PR trigger alone is not a globally atomic admission database. Parent typed executor architecture remains authoritative. Later profiles require their own bounded qualification and release decision.
