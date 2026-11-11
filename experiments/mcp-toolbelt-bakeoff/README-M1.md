# M1 shared Tool Belt bake-off — free-tier cloud execution and O&M

Authority: private `SemperSupra/mcp-projection-dev` issue #170 (M1), parent #18. This directory contains **synthetic, public-safe qualification material only**; do not place private source, user data, tokens, internal domains, or workset definitions in this public repo. Draft PR #577 has **no merge/deployment authority**.

## Execution stages
1. G0: `qualification_oracle.py` generates a deterministic 12-service / 60-tool / three-belt policy reference and verifies deny mutation detection. Two free public hosted GHA architectures run the same input, compare `catalogHash`.
2. G1: Existing separate workflows test actual Agentgateway two-upstream routing and MCPHub two-upstream routing, anonymous denial, and principal-scoped access. Their completed receipts **do not** establish the full 12-service candidate test, production AAA, real OAuth, or Tool Belt switching.
3. G1 next: each candidate implements a single adapter that consumes the same vector file. Record `PASS`, `FAIL`, `BLOCKED`, `UNTESTED`, and `N/A` distinctly; product claims cannot be inferred from the oracle.
4. G2: independent red-team cases for forged identity, revoked/expired grant, cross-user lookup, authorization bypass, preflight failures, audit outage, private-network SSRF/DNS rebinding, untrusted descriptions, replay, and cancellation. Mandatory audit outage for privileged calls is fail-closed.
5. G3: only candidates passing hard correctness and security gates enter paired resource tests; use fixed commit and image digest, matched CPUs, randomized order, direct upstream baseline, confidence intervals; do not treat a single `docker stats` observation as a comparative benchmark.
6. G4: real Cloudflare MCP Portal and external ChatGPT/Gemini tests require authorized external account and entitlement. No provider credential goes into public CI. Absence of access is `BLOCKED`, not `PASS`.
7. G5: rootless Podman/Quadlet, non-root user, read-only config, external secret references, no host Docker socket; build x64/ARM64 repeatably; only on admitted hosts/cloud runners. Finalists undergo restart, upgrade, rollback and endurance.
8. G6: produce full-stack scorecard, sensitivity analysis, costs and provider lock-in. Owner decides; no automatic winner or merge.

## Resource placement and cleanup
- **Public free GitHub Actions**: ephemeral public-safe source, fixture, function and regression tests only. Prefer parallel independent jobs, minimum `contents:read`, no secret environments, no persistent runners, no private minutes. Every job is time-bounded; teardown ephemeral test containers on `if:always()`.
- **Cloudflare Free**: requires authenticated Cloudflare tenant and scoped portal authority. Do not assert portal acceptance by reading public documentation.
- **Oracle Always Free**: separate admission for host access; no direct control or deployment implied here. For soak/operations use only pre-existing qualified resources; avoid expiring paid trials or hidden billing.
- **OpenAI outbound tunnel**: only after account/agent entitlement verification; use official client unmodified. Tunnel connection does not prove individual human identity or native workset authority.

## Operations and maintenance contract
**Declare:** pinned source SHA, image digests, complete nonsecret policy/config revision, entrypoint, architecture, allowed upstream CIDRs, secrets identifiers, stated resource budgets, dependency versions.
**Start:** validate topology and no unintended public listener; verify health and issuer/audience-bound external principal. Default deny if policy absent. No Docker socket in accepted production topology.
**Observe:** record per-operation correlation ID, agent and delegating principal pseudonymous references, policy decision and version, selected belt ID/version, upstream service, result class, audit sink commit/ack, timings and resource sample. Never store request/response secrets in logs.
**Contain:** when AAA, audit sink or native admission unavailable, deny consequential invocation; maintain read-only service availability only when its separate gate permits. Fail isolated unhealthy upstreams without creating rights.
**Recover:** rotate/revoke tokens, invalidate stale selection/cache/session on revocation, test persistent saved belt reconstruction, restart/reconnect and idempotent operations, restore previous signed config, report exact rollback action.
**Report:** machine-readable immutable receipt for each workcell plus human summary back to private DLE #170/#18. A passing source grep or container startup is NOT a production qualification. Read back linked GitHub run/jobs/logs/artifacts and classify any missing evidence.
**Stop:** two bounded corrective attempts for harness/config failures, then route to triage; do not widen credentials/ports/SSRF CIDRs to turn tests green.

## Current evidence (2026-11-11)
- G0 M1 oracle: github.com/SemperSupra/agent-dispatch/actions/runs/42975829605 (revised audit mutation; actual pass verified on x64 and ARM64).
- G1 Agentgateway two-upstream: github.com/SemperSupra/agent-dispatch/actions/runs/42950819621.
- G1 MCPHub two-upstream: github.com/SemperSupra/agent-dispatch/actions/runs/42952018067.
- G1 MCPHub scoped principal: github.com/SemperSupra/agent-dispatch/actions/runs/42952728022.

All results are strictly scoped to the tests listed. No production-selection conclusion yet.
