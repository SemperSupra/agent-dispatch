# Public GHA MCP worker — synthetic RDTE

This is a **public-safe, read-only synthetic MCP worker**, not a persistent dispatcher, secret-bearing executor, or replacement for the independently operated control plane.

The standard-library Go server implements sessionless HTTP MCP on loopback only. The supported methods are `initialize`, `ping`, `tools/list`, and the zero-argument `worker_ping`. It **never** accesses a repository, runner filesystem, secrets, shell, ambient credentials, or external URLs. Its marker `PUBLIC_SYNTHETIC_MCP_WORKER_OK` does **not** mean any delegated task ran.

The public workflow `.github/workflows/mcp-gha-worker.yml` has two paths:

- **Public PR / manual smoke:** Go formatting, race tests, vet, actual local MCP HTTP probe, and pull/inspect/help of the digest-pinned official OpenAI tunnel-client image **without credentials**. No private GHA minutes.
- **Explicit manual live (reviewed default branch only):** Starts a loopback MCP canary and an outbound official tunnel runtime for **120, 300, or 600 seconds** and then stops. The runtime is detached inside a restricted container, no public inbound MCP listener. This proves temporary process lifecycle only until a separate ChatGPT plugin invokes it and evidence is independently correlated.

## On-demand wake from ordinary ChatGPT

The normal GitHub connector can post a PR conversation comment. This repository currently has **Issues disabled**, so the narrowly scoped GitHub Actions `issue_comment` wake event is bound to the **existing PR #553 only**, using immutable GitHub author ID **1854350**, event type `created`, and the exact comment body:

```text
/mcpgha start smoke
```

For a **separately approved** time-bounded OpenAI tunnel (requires protected GitHub Environment credentials and owner review), use:

```text
/mcpgha start live
```

Example ChatGPT request once this workflow is merged into `main`: *"Post exactly `/mcpgha start smoke` as a new comment on SemperSupra/agent-dispatch PR #553, then observe the new public Actions run."* ChatGPT uses its connected GitHub account—there is no GitHub token or OpenAI key in the chat. The worker run is addressed by the public GitHub comment ID and its native Actions run ID, **not** by a fabricated worker handle.

**Control limitation:** the public repo's Issues feature is disabled (GitHub API 410), so the PR conversation is a provisional wake surface rather than a dedicated operations issue. This does not authorize public user comments, review comments, forks, arbitrary workflow selection, shell arguments, code publication or new cloud resources. Non-owner comments, wrong PRs and other text must produce **zero work**. The `issue_comment` workflow must be on the default branch before the trigger can function. Do not assume this works until a real comment-induced GitHub Actions run is observed. Moving to a permanent issue later requires enabling Issues and reviewing the exact issue/author gate.

**Governed Sidecar alternative:** the existing always-on Agent Dispatch Sidecar can independently call GitHub `workflow_dispatch` using its installed GitHub App. The public workflow now accepts the native `workset_id`, `delegation_id`, `assignment_id` identity fields and emits Sidecar-compatible run names. Separate exact caller/workset/assignment admissions and a narrow runtime target binding are prerequisites; the comment wake is *not* represented as a Sidecar-authorized dispatch. The Sidecar path is the preferred mission/assignment and observation authority.

## Credentials: references only; no values

For a dedicated, separately admitted **temporary** tunnel, configure the GitHub Environment `mcp-ephemeral-live` with branch restrictions, a human reviewer, and two secrets:

- `OPENAI_TUNNEL_RUNTIME_KEY`: dedicated OpenAI tunnel runtime **Tunnels Read + Use** key, **not** an admin key.
- `OPENAI_GHA_MCP_TUNNEL_ID`: dedicated `tunnel_...` identifier, never reused by another active runtime.

Do **not** put secret values in public workflow inputs, source, issues, pull requests, artifacts, logs, or ChatGPT messages. The GitHub source connector cannot retrieve masked secrets or a credential stored only on another machine; runtime credentials must be added through the owner's approved GitHub/OpenAI secret-management surface. Environment protections must be verified before any live run. Creating the branch/PR does not enable live mode.

## Local verification

```sh
cd tools/mcp-gha-worker
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -race -count=3 ./...
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go vet ./...
go run . --listen 127.0.0.1:18765
```

A GET to `/healthz` returns synthetic health. A JSON-RPC `tools/call` with `{"name":"worker_ping","arguments":{}}` at `/mcp` returns the public marker. Non-loopback bind addresses are rejected.

## Acceptance limitations

- The normal smoke has no OpenAI key and does **not** establish a working hosted tunnel or a ChatGPT app connection.
- A running tunnel-client process alone is not proof of authentication, `/readyz`, or MCP invocation from ChatGPT; require a later correlated client-side evidence receipt.
- Public GitHub-hosted jobs are short-lived and cannot be started through their own **stopped** tunnel. Use an existing persistent control service to launch native GitHub `workflow_dispatch` and later observe Actions run IDs. Reuse the portfolio's existing typed and sealed public executor for actual admitted tasks.
- Never project real private source, environment/host identity, private network topology, credentials, dynamic shell/code/URLs, or unreviewed commands into this public job.
- This uses the official `ghcr.io/openai/tunnel-client` image by exact digest; do not implement an alternative tunnel transport.
