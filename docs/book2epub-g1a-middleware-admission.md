# Book2EPUB G1a middleware observation — admitted-code / unadmitted-system contract

**Authority:** [Agent Dispatch private #480](https://github.com/SemperSupra/agent-dispatch-private/issues/480), parent #396, [TrueNAS Foundry private #325](https://github.com/SemperSupra/truenas-app-foundry-private/issues/325), [ShelfMark pipeline #50](https://github.com/ShelfMark-Bindery/pipeline/issues/50).
**Consumer:** Source-only [Agent Dispatch draft #544](https://github.com/SemperSupra/agent-dispatch/pull/544), stacked on gateway draft #542.
**Status:** `SOURCE_QUALIFIED`; `IN_GUEST_NOT_RUN`; `SESSION_NOT_ADMITTED`; `G1B_NOT_RUN`. No production, licensed Book2EPUB image, model or physical TrueNAS deployment.

## Reuse instead of duplicate infrastructure

The existing Agent Dispatch session/TrueNAS middleware transport owns guest boot, connection, authentication, TLS verification, slot fencing, exact-source pinning, cleanup and independent receipts. This G1a slice must never instantiate a second VM or create host privileges.

There are two **different** read-only observers. Their evidentiary claims must not be conflated:

1. `scripts/book2epub_g1a_guest_observe.py`: guest-local `midclt`/Docker daemon status, registry configuration digest, and pinned guest-side `http://10.0.2.2:5000/v2/` probe. It is **not** a registered or isolated capsule, cannot be run in an ordinary container without separately proving guest-runtime access, and cannot prove a Docker pull.
2. `scripts/book2epub_g1a_middleware_readonly.py`: host-controller pure reducer using a caller-supplied authenticated read-only RPC callable; calls only `system.version`, `docker.status`, `docker.config`, in that order. `scripts/book2epub_g1a_rpc_adapter.py` is a candidate glue layer for an **already authenticated** existing DDP socket and the existing `ddp_call` primitive. The adapter neither authenticates nor opens a socket, and it never attests TLS or role grants by itself.

**API-based consumer integration, executable only inside an independently admitted one-use session** (illustrative source contract, not an execution request):

```python
from book2epub_g1a_rpc_adapter import observe_ddp_session
from truenas_middleware_ddp_probe import ddp_call

# ws: already-authenticated short-lived connection supplied by existing
# authorized Agent Dispatch session. Do not construct a connection here.
result = observe_ddp_session(ws, ddp_call, "tn-25-04-2-6-g1a-001")
# Assert result["classification"] only as middleware-status observation.
# A positive result still has guest_identity_verified == False.
```

The TrueNAS **25.04.2** documented read roles for both `docker.status` and `docker.config` are **`DOCKER_READ`** (not automatically `APPS_READ`), see:
- https://api.truenas.com/v25.04.2/api_methods_docker.status.html
- https://api.truenas.com/v25.04/api_methods_docker.config.html

Official TrueNAS 25.04 uses versioned **JSON-RPC 2.0 over WebSocket**; the existing codebase contains a legacy DDP helper. Its availability and method privilege behavior on the *exact target version and actual role-scoped principal* are **not yet verified**. If DDP is unavailable or privileged, a separate source-qualified JSON-RPC session adapter should be bound through the existing session owner, not silently promoted from synthetic tests. No default `truenas_admin` credential is authorized merely by this source contract.

## 2026-10-25 first failure: hidden RPC on the official client connection

The **exact** source for `truenas/api_client@3576b3cf9a87ae92bbf1d873e23215b48ca90819` (file Git blob `ccd59b19381b0d494528c6854db228e1c2a6665c`) calls `core.set_options` from `JSONRPCClient.on_open()` when it establishes the WebSocket. The B1 app adapter counts *only application-triggered* `system.version`, `docker.status`, and `docker.config`, not all RPCs on the wire. Auth/login can also involve additional RPCs owned by the runtime actor.

This invalidates a blanket **three-wire-RPC-only** statement. It does not mean `core.set_options` is a persistent guest mutation; upstream source describes it as response-format session options. Before admission, classify this exact setup method independently and bind a lifecycle-complete transport allowlist: connect/verification, bounded `core.set_options` bootstrap, exact version-correct authentication, three observation RPCs and close. Record actual method names and counts in the *independently verified* session receipt, not a claim from a fixture or injected fake client. Any unexpected/dynamic setup method, write RPC, downgrade, missing `DOCKER_READ` scope, unverified peer or replayed request **HOLD**.

Public [CI run #40214377308](https://github.com/SemperSupra/agent-dispatch/actions/runs/40214377308) at exact executable head `5ed127854abd9384a4b1426a16a0993d525b94ab` passed **59/59** tests and asserted that the source audit lists `core.set_options` as a setup RPC requiring separate authorization, not a pre-proved effect or complete wire-count proof. No actual WebSocket session, credentials, TrueNAS guest or socket trace was exercised.

## Falsifiable gates before an actual G1a observation

- Independently verify current one-heavyweight-slot owner and terminal cleanup of the previous capsule. The 2026-10-24 Minecraft OP4P-023 receipt established a working disposable 25.04.2.6 guest and zero residue, but its request is **CONSUMED** and not reusable.
- Preserve $0 **public** hosted execution, pinned TrueNAS 25.04.2.6 ISO source/digest/middleware and exact one-use job-bound request; no private hosted minutes, no direct physical-NAS access.
- Resolve explicit owner authority for the session and independent provider admission. Existing `config/truenas-capsule-providers.json` does not register Book2EPUB G1a; **do not** add a fake registered provider or feed a source-only manifest to the heavyweight executor.
- For middleware-only G1a, independently verify TLS and exact ephemeral guest identity and an authenticated principal with `DOCKER_READ` (or a stronger role separately justified). Do not claim that a method call's success alone proves role confinement or target provenance. Any credentials remain in the existing session owner.
- Validate version `TrueNAS-25.04.2.6` **before** any Docker read, refuse drift; return sanitized status only. The pure reducer never sees Docker raw metadata outside its callback lifetime.
- Host-side `docker.status`/`docker.config` reports **do not establish** guest-to-registry reachability, daemon TLS or insecure-registry trust, actual digest addressed image pull, or offline image-load provenance. These are separate G1b/transport oracles.
- Do not borrow G2/G3 production rights from owner attestations without separately bound exact source/model/output/security/site acceptance. F0–F5/H0–H5 and physical TrueNAS APPLY stay HOLD.

## Source-only qualification & first failures

Public [GHA #40077173406](https://github.com/SemperSupra/agent-dispatch/actions/runs/40077173406) 9/9 unit tests PASS; [#40119385675](https://github.com/SemperSupra/agent-dispatch/actions/runs/40119385675) 19/19 PASS after fixing exact canonical version `TrueNAS-25.04.2.6` vs SCALE-prefixed variants. Native [GHA #40148711759](https://github.com/SemperSupra/agent-dispatch/actions/runs/40148711759) checked out exact `02ce7d8b0b0f967ace795e475d743860a2accc38`, compiled all observer/adapter source and **28/28 tests PASS**, job #121035504143 terminal SUCCESS. This does **not** count as a real guest RPC observation or an approved executor transport.

## Next READY / handoff

Independent source review of PR #544 at current head and original #542 base; verify the existing TrueNAS 25.04.2.6 JSON-RPC read-only connection mode and `DOCKER_READ` grant without adding an unreviewed credential to public source; obtain one-use manifest/source and clear the shared heavyweight slot. Only then execute an actual guest observation, bind exact identity and zero-residue receipt to #480 / #325 and move to separately admitted G1b digest-pull/offline-load. No merge, physical APPLY or production promotion from this file.
