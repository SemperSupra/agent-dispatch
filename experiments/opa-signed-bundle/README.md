# OPA S2 — synthetic signed-bundle + native Quadlet qualification

**Authority:** Agent Dispatch private DLE [#748](https://github.com/SemperSupra/agent-dispatch-private/issues/748), proposal S2; standalone **public-safe and synthetic** source. This is **not** a Pandora deployment or an authorization grant.

## Why a separate gate after the 10/10 policy bakeoff?

The initial [policy-engine runtime comparison](https://github.com/SemperSupra/agent-dispatch/pull/576) measured in-memory allow/deny latency. It did **not** qualify policy Git promotion, signatures, webhook events, revocation, bundle persistence, replay prevention or actual current-call Sidecar gating.

A newly relevant upstream **high severity** advisory, [GHSA-g2pf-6v5v-qcc8](https://github.com/open-policy-agent/opa/security/advisories/GHSA-g2pf-6v5v-qcc8) (published 2026-10-19), affects OPA 0.22.0–1.21.2 and is fixed at 1.21.3: (1) certain configurations lacking explicit `signing.keyid` could accept unsigned snapshot bundles despite apparent signature configuration; (2) unsigned delta bundles could bypass verification. **This RDTE uses OPA 1.22.3, explicit `signing.keyid`, and does not enable unsigned delta exceptions.**

## Actual experiment

On each native Linux AMD64 and ARM64 **public GitHub-hosted disposable runner**:

1. Install Podman/systemd Quadlet, pull the version-pinned public OPA container image, record its architecture/digest/version. Generate a *test-only ephemeral* RSA signing key that has no operational authority or longevity.
2. Build two synthetic signed Rego/data snapshot bundles from the same strict allow rule, with accepted and revoked `data.authz.enabled` states. Use OPA's **native** `build --bundle --signing-key` path and explicit verification key ID and scope. Also build unsigned snapshot, tampered signed snapshot and unsigned valid delta fixtures.
3. Run a loopback-only Python static ETag bundle server on port 8099 and **actual systemd-generated Podman Quadlet** OPA service on port 8181, both loopback-only. Configure `bundles.authz.signing.keyid` and the synthetic public verification key.
4. Verify initial signed grant permits exactly one synthetic tuple; unrelated principal/workset denies. Switch served bundles **without restarting OPA** and require: unsigned snapshot rejected/previous allow retained; correctly signed deny activated; tampered signed snapshot rejected/deny retained; unsigned delta rejected/deny retained; signed allow reactivated; signed deny reactivated. Every candidate must be observed delivered over the local HTTP service; collect elapsed milliseconds.
5. Archive JSON stage results, local static-server HTTP receipt, sanitized systemd/journal, native architecture and image digest. All source/identifiers are fictional.

**Do not confuse green workflow execution with production security acceptance.** This test is intentionally rootful systemd Podman on disposable GH runners to match the previous S0 baseline, NOT production **rootless user Quadlet**. It does not prove a trusted GitHub approval/signer boundary, immutable signed policy generation anti-rollback, bounded stale-cache TTL, caller/assignment identity, hardened OPA write API, offline persisted startup, rootless mount integrity, host failure recovery, public-to-private source isolation, or actual Sidecar MCP authorization. Those gates remain S1/S3/S4/S5 OPEN.

**No credentials, private source, protected worksets, actual policy data, real execution endpoints or host administration** are exposed. No Pandora, WOW v0.0.2, release, merge, token or tunnel changes are in scope.

## Reusable upstream behavior, not a bespoke controller

OPA's [bundle configuration](https://www.openpolicyagent.org/docs/configuration) supports remote ETag-polling, signature enforcement, and optional persistence. [Bundle management docs](https://www.openpolicyagent.org/docs/management-bundles) document acceptance/rejection, but JWT `iat` and `iss` do not themselves validate expiration/issuer. Independently approved signed bundles and monotonic generation with an explicit freshness gate are **required before effect authority**. This RDTE should guide a minimal Go/Python Sidecar adapter, not justify a second scheduler or policy DB.

Upstream OPA version release: [v1.22.3](https://github.com/open-policy-agent/opa/releases/tag/v1.22.3). Pin a reviewed image *digest* on a later accepted release; a semver image tag is only suitable for this disposable trial with captured runtime digest.
