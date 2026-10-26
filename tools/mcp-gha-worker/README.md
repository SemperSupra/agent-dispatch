# Public GHA MCP worker — synthetic RDTE

This is a **public-safe, read-only synthetic MCP worker**, not a persistent dispatcher, secret-bearing executor, or replacement for the independently operated control plane.

The standard-library Go server implements sessionless HTTP MCP on loopback only. The supported methods are `initialize`, `ping`, `tools/list`, and the zero-argument `worker_ping`. It **never** accesses a repository, runner filesystem, secrets, shell, ambient credentials, or external URLs. Its marker `PUBLIC_SYNTHETIC_MCP_WORKER_OK` does **not** mean any delegated task ran.

The public workflow `.github/workflows/mcp-gha-worker.yml` has two paths:

- **Public PR / manual smoke:** Go formatting, race tests, vet, actual local MCP HTTP probe, and pull/inspect/help of the digest-pinned official OpenAI tunnel-client image **without credentials**. No private GHA minutes.
- **Explicit manual live (reviewed default branch only):** Starts a loopback MCP canary and an outbound official tunnel runtime for **120, 300, or 600 seconds** and then stops. The runtime is detached inside a restricted container, no public inbound MCP listener. This proves temporary process lifecycle only until a separate ChatGPT plugin invokes it and evidence is independently correlated.

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
