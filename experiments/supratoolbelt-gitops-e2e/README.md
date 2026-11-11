# M1 joined GitOps + signed Tool Belt + real gateway RDTE

**Synthetic-only, public free GitHub Actions.** This is a bounded *integration proof*, not a deployable production permission authority or an application distribution package.

## Exact trust chain exercised

1. Create **two real local Git commits** for two immutable synthetic saved-belt manifests, swapping Research and Engineering assignments.
2. Independently validate the pinned manifests and compute raw SHA-256 snapshot digests using source pinned at `32790dbe1a64a4d0ca8e0394447f1803383f0a34` (Go oracle from #594). Distinct Git commit objects and distinct manifest contents are both required.
3. Create an ephemeral P-256 issuer via source pinned at `ea198e844e6989fc1a9bea77ab6367725d34ac9a` (#589), sign two logical same-principal contexts per revision; separate `belt` and `snapshot` JWT claims.
4. Start real Agentgateway OCI `sha256:60216aafb03d37f94e952ff3d51d2f630a65b10ecaebdc0a864882f92610c45b`, enforce strict JWT, CEL and tool target conditions; invoke two actual synthetic MCP upstreams.
5. Verify **both** legitimate contexts discover/call only their own tools and deny direct cross-belt calls.
6. Destroy and recreate the gateway with the **new** validated snapshot. Previously signed, still-unexpired tokens must not discover or invoke tools from the old revision.
7. Destroy the gateway, local Git fixture, short-lived signing private key, JWTs and config files. Upload only sanitized digests, Git commit witness and allow/deny receipts.

## Explicit limits and promotion rules

- No provider OAuth, live GitOps controller, current-grant revocation during unexpired token, native Agent Dispatch/WOW workset AAA, independent durable audit, real user, model inference or provider tunnel.
- **This workflow is not Gate Z deployment evidence:** the workcell runs on a wholly disposable public hosted runner, but the gateway here is a synthetic container launched by the runner Docker daemon, not a qualified rootless production deployment.
- A green run proves only the exact scenario assertions stated in its receipts. It **does not combine** independent tests elsewhere into a full service/SoS approval.
- No commits/merges to authority branches; this test is confined to a draft PR, with private M1 DLE #170 holding architecture decisions.
- Owner's toolchain rules: prefer disposable containers, disposable VMs and free public GHA; user `~/.local` / project `.local` are permitted but less-preferred tooling fallbacks. Application/service runtime must remain disposable/stateless.
