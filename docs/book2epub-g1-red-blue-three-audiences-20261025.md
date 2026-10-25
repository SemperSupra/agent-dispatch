# Book2EPUB G1a–G3: adversarial review, blue-team recovery and three-audience acceptance

**Date:** 2026-10-25. **Status:** reviewed design / proposed corrective work; not runtime admission.
**Public source:** Agent Dispatch draft [#544](https://github.com/SemperSupra/agent-dispatch/pull/544) stacked on [#542](https://github.com/SemperSupra/agent-dispatch/pull/542). **Authority:** [private Agent Dispatch #480](https://github.com/SemperSupra/agent-dispatch-private/issues/480), parent [#396](https://github.com/SemperSupra/agent-dispatch-private/issues/396); product/app in [private Foundry #325](https://github.com/SemperSupra/truenas-app-foundry-private/issues/325), ShelfMark [#50](https://github.com/ShelfMark-Bindery/pipeline/issues/50), and the model artifact foundry.
**Work method:** Discover → Observe → Plan → Apply → Verify → Record/Handoff; durable, legible, executable (DLE), without transferring decision authority into an executor.

## Verified baseline and decision

- Public GHA [#40148711759](https://github.com/SemperSupra/agent-dispatch/actions/runs/40148711759) previously ran **28/28** source-only tests on exact executable-code commit `02ce7d8b0b0f967ace795e475d743860a2accc38`; current draft also has a documentation-only commit `dd849c7a84e688a51986282175c4c5acec38e8b7`. The result is not a real guest observation.
- An *unrelated* product used the existing public $0 KVM lab to qualify real disposable TrueNAS **25.04.2.6** ([Minecraft OP4P-023 run #40119184140](https://github.com/SemperSupra/agent-dispatch/actions/runs/40119184140)); its one-use request is **CONSUMED**. Reconcile slot ownership before any new boot.
- Current G1a guest-local CLI prototype and host-side pure `system.version`, `docker.status`, `docker.config` reducer do not independently establish a scope-bound login, certificate/guest identity, API protocol support, registry trust or an exact digest pull. Current ingress is **not admitted**.
- TrueNAS 25.04 introduces JSON-RPC 2.0 WebSocket and retains legacy `/websocket` compatibility; official version-matched API client `TS-25.04.2.6` supports both, and `/api/current` is canonical. Official library notes **25.04 does not support SCRAM API-key auth**: any plain API-key mode is explicit, and must be over separately verified TLS. Do not infer the latest library's features apply to 25.04.
- Keep existing AD session/provider, target registry, single-heavyweight lease, provider harness and receipt authority. **Do not create** a Book2EPUB-specific VM harness, scheduler, credential broker, web console, registry service or Docker socket bridge. The lowest-risk first probe uses an already-authorized read-only middleware channel. Guest-side CLI and G1b registry experiments stay independent.

## Red-team findings — hostile/negative scenarios

| ID / priority | Failure or attack | First failure oracle | Blue-team action |
| --- | --- | --- | --- |
| R1 P0 | Green unit suite / fake callback silently represented as real guest | No independent guest/transport/slot receipt | Source evidence remains `SOURCE_ONLY`; trusted external verifier binds exact VM identity, API transport, role, run/job ID and system version |
| R2 P0 | Default admin or plain API key used over HTTP; opaque TLS, logged secrets, key survives teardown | Missing cert validation, scoped service account, auth-mode proof or zero-residue | One ephemeral restricted principal; verified WSS/pin; 25.04-compatible explicit auth choice; no public credentials/logs; revoke and prove destruction |
| R3 P0 | Legacy DDP works in a unit stub but fails on 25.04 production target; JSON-RPC response confusion | No exact-version protocol handshake and role test | Prefer version-matched official JSON-RPC client under the existing session owner; legacy DDP allowed only if independently proven on exact target, never silently downgrade |
| R4 P0 | Network `/v2/` 200/401 or Docker `RUNNING` misread as image-pull/trust PASS | No digest-pinned engine pull identity, TLS trust or registry disposition | G1a middleware health is its own scope; G1b uses a separately admitted public-safe immutable fixture and independent pull/cleanup oracle |
| R5 P0 | Replay a consumed one-use guest request / two simultaneous heavyweight jobs | Reused request ID; lease or job binding missing | Slot and exact-job owner arbitration precedes VM start; fail closed on stale/replayed request; never borrow Minecraft OP4P-023 |
| R6 P0 | Private models, book text, keys, reader outputs or source leak through public GHA receipts | Source/output/rights/taint not explicitly public-safe | G1a public synthetic status only; restricted source/weights and private output never projected; private producer authority reviews any sanitized projection |
| R7 P1 | Output fields are typed as `SUPPORTED` and over-promote contradictory evidence | `SUPPORTED` despite guest identity unknown or product gates incomplete | Separate `code_test`, `middleware_observed`, `network_observed`, `engine_trust`, `digest_pull`, `product_oracle` evidence classes; one external evaluator enforces monotonic claims |
| R8 P1 | Cleanup claim lacks executor-owned filesystem/port/process proof | Success flag despite owned residue or no teardown receipt | Independent zero-residue verifier, exact namespace/lease, teardown after failure/interruption, owner-aware reaper; incomplete cleanup => HOLD |
| R9 P1 | UI unavailable to keyboard/screen reader; color-only status; dangerous mode ambiguous | Automated accessibility and manual assistive-technology probes fail | All actions keyboard operable, accessible labels and status text, visible focus, plain-language reasons, no color-only meanings; WCAG 2.2 AA target |
| R10 P1 | Automation and agents see different status than human UI; duplicate or irreversible action after retry | Different gates or duplicated run against same idempotency key | Same schema/receipt and explicit command capability across accessible UI, stable API/CLI and MCP/agent wrapper only where earned; idempotent retry/result semantics |
| R11 P1 | EPUB is structurally valid but unreadable/incorrect in English, German or Thai | EPUBCheck passes; reader order, glyph or layout QA fails | Independent reader screen/AT visual and text order checks, language tags, normalization, OCR correction/human override, provenance/rights |
| R12 P2 | Excessive observability, frontend proliferation, broad multilingual work before a real G1 | New artifacts do not affect acceptance or have a consumer | Retain thin templates over DLE; introduce only components whose test results justify upkeep; no heavyweight matrix by default |

## Blue-team recovery: minimum viable implementation in priority order

**B0 — Gate normalization, offline and public-safe (highest ROI).** Define a **single immutable, independently verifiable evidence envelope** with `work_ref`, `run_id`, `actor/role`, `target_version`, `source_sha`, `manifest_sha256`, `evidence_class`, `observations`, `first_failure`, `cleanup`, `authority_refs`, `validation`, `next_ready`. Do not treat self-reported booleans, a green CI status, or a source file as external runtime attestation. Keep a compact explicit hold list (including reason, owner, and what receipt clears it). Human-friendly Markdown/HTML status and agent/machine JSON are *views of the same stored evidence*, not separate stores. Validate schemas, falsify missing/conflicting/replayed receipts and reject unknown states. **No new general observability platform.**

**B1 — Transport choice/authority (parallel with B0).** Inspect and qualify the **existing** AD 25.04 guest middleware session and its authenticated socket on pinned TrueNAS 25.04.2.6, first using offline synthetic contract tests and current upstream source. Prefer the official version-matched JSON-RPC `/api/current` client. Reuse a legacy DDP socket *only* when exact-target accepted evidence demonstrates support and authorization. Bind read-only access to `DOCKER_READ` on the ephemeral guest; `APPS_READ` alone is not sufficient by policy. Verify certificate/peer identity, connection context, role assignment from external identity/audit authority and nonleaking/revocable credentials. Call exactly the three methods; no `docker.update` or Docker socket. Fail closed on auth downgrade or method error.

**B2 — G1a one-use system observation (serial heavy; depends on B0/B1 plus slot).** Under existing Agent Dispatch #480/#396, independently admit a single pinned **$0 public-hosted** 25.04.2.6 guest session with bounded budget and exclusive slot; run a read-only middleware status check and capture runtime evidence of exact guest/version/role/transport. Re-observe owned teardown. A successful G1a receipt means *only* actual middleware status observed; it says nothing about guest-side registry reachability, Docker image distribution or product readiness.

**B3 — G1b neutral image transfer experiment (serial heavy; independent of product rights).** Reuse a disposable guest and a **public-safe digest-pinned benign OCI fixture** with license/provenance; compare (a) host-local ephemeral registry and guest-engine digest pull with registry trust, (b) separately admitted verified local image load and `Never` pull policy if technically supported. Distinguish registry transport from locally preloaded OCI. Verify content digest, no ambiguous tag-only identity, restart/cleanup, no public/private payload crossover. Publish only public-safe sanitized receipts. Require separate write-mode admission and nonce/ownership checks.

**B4 — G2 source/MAF/rights/site admission (parallel with B0–B3, different actor).** Under ShelfMark, TrueNAS Foundry and MAF authority, bind actually accepted upstream licenses, exact artifact bytes, model weights and derivatives, source/output use rights, site/security evidence and immutable release-OCI digest. Preserve `research` vs `production` user selection but prevent switching modes from conferring unverified rights or bypassing release gates. No public distribution of restricted source/models/output.

**B5 — G3 product F0–F5 + H0–H5 (after B2/B3/B4).** Run one serial authorized product app lifecycle on disposable TrueNAS and independent Book2EPUB reader oracles (actual EPUBCheck **and** independent reader/AT visual/content QA). Include mode persisted across restart, job cancellation/retry/idempotency, worker/policy isolation, resource limits, cleanup after injected failure, health vs readiness separation, artifact/audience API access. Do not infer physical TrueNAS permission, release merge or canonical ShelfMark promotion.

## Three audiences: one core, appropriate surfaces

**Human / assistive technology (UI + UX):**
- Now: GitHub issue/PR and a compact, accessible status report exposing *stage, what is proved, what's missing, next action, owner*; distinct `Blocked` vs `Not run` vs `Observed` vs `Verified`. Provide accessible text beyond color and copyable evidence links.
- Product stage: use ShelfMark's existing web UI rather than creating a separate AD UI. Provide keyboard-only action flows, semantic controls and labels, visible focus, screen-reader status announcements, accessible error recovery, cancellation, and human review/override of OCR/language/illustration placement. Track WCAG 2.2 AA and manual VoiceOver/NVDA sample validation in addition to automated axe-core/Playwright checks. Accessible final EPUB must have reading order/nav structure, real language metadata, alt-text review and usable EN/DE/TH font/segmentation behavior.
- Avoid showing raw approval jargon to casual readers, while preserving a detailed evidence view for expert reviewers. Plain-language explanations must never hide gating failures.

**Automation (API + DX):**
- Now: stable, versioned JSON receipts with deterministic exit codes; read status/plan without side effects. Optional CLI wrapper should call the *existing* orchestration/evidence core, never create its own scheduler/VM or data copy.
- Product stage: the existing admitted ShelfMark job interface supports create/read/retry/cancel/inspect with idempotency keys and immutable inputs/artifact digests; events/status are replayable. Assert tests for errors, timeout, retries, version drift, partial outputs and cleanup. All clients derive display state from the same core contract.

**Agents (tool UX + DX):**
- Now: narrow discover/observe/plan capabilities that return the same JSON evidence and explicit hold reasons. Untrusted documents or model outputs cannot issue runtime admissions. Bounded apply/dispatch is a *different* authenticated and one-use capability, not another spelling of read-only.
- Product stage: agents may recommend OCR layout, translations, metadata, illustration placement, QA fixes and workflow steps, each with evidence/provenance and confidence. Human approval and privileged actions remain explicit gates. Require stale-lease/replay, hostile tool output, prompt injection, missing rights and false-positive oracle falsification tests.

**Decision:** All three audiences must be able to review the *same* session, independently inspect what happened, and understand the next admissible step. Simultaneous **reads** are expected; mutating actions are serialized by actor/lease/idempotency and authority. An MCP server or extra GUI is **not** a prerequisite if current interfaces already satisfy their audience's needs.

## Plan economics, sequencing and stop conditions

| Work | Resource & parallelism | Gate evidence |
| --- | --- | --- |
| B0 claims/receipt checks; B1 transport/role source audit | Public $0 GHA + existing native GitHub; **parallel** | Contract/negative tests and independently reviewed code |
| B4 model/image/rights/MAF research | Private source authority; **parallel**; no public restricted bytes | Exact external approvals and immutable digest references |
| B2 G1a real guest | **One** serial $0 approved heavyweight slot | Actual authenticated guest+role+version status, teardown |
| B3 G1b benign image | **One** serial $0 approved heavyweight slot | Actual engine pull or separately labeled verified offline load and teardown |
| B5 G3 Book2EPUB app | **One** serial $0 approved heavyweight slot | Full F/H oracle, independent readers, zero residue, no release inference |

**Efficiency gates:** (1) Before any new abstraction, name two actual consumers or a missing requirement demonstrated by evidence. (2) Reuse existing sample/data/oracles; no duplicate schedulers, VM abstractions, CI matrices or status stores. (3) Test cheap deterministic negatives before expensive positive guest runs. (4) Fresh heavyweight source or target must have a decision-relevant change and active slot lease; never blindly replay a consumed request. (5) Every state and stop condition has a human-readable reason and a machine-testable representation.

**Minimum next batch (no heavyweight authorization assumed):** review actual 25.04.2.6 client/server protocol and role handling; add negative auth/role/TLS/downgrade/false-promotion tests to the existing draft; verify one-source-of-truth status projections and accessible plain-language summaries; present exact one-use G1a session request to #480 for *independent* admission. If no matching provider/slot/identity/credential: leave `G1A_GUEST_NOT_RUN`, record first blocker and continue B0/B4. **Do not add a Docker-socket container merely to satisfy a provider schema.**

## Explicit independent acceptance checklist

- **Source:** exact new head independently reviewed; public free-tier CI unit/security tests green, full exact SHA+job recorded.
- **Role/transport:** real TLS identity and `DOCKER_READ` credential on exact 25.04.2.6; restricted principal demonstrably cannot call a write method; no credential in a public receipt.
- **Causal evidence:** G1a cannot imply network/engine pull, G1b cannot imply licensed Book2EPUB release, G3 cannot imply physical APPLY. Conflicting inputs hard fail.
- **Accessibility:** accessible read-only status for human AT before G1b; keyboard/screen-reader review/corrections and reader accessibility for product G3; assistive-tech spot-check is distinct from automated checker.
- **Developer/automation:** same schema for UI/CLI/agent, deterministic errors, idempotent replays, version and provenance, no client-specific permissions.
- **Cost and custody:** public $0 hosted only, one heavyweight owner, disposal and independent cleanup proof, public-safe only.
- **Handoff:** first failure, accepted/rejected hypotheses, next READY and authority in DLE, with no dependency on this chat.

**External verification basis:** TrueNAS 25.04 API/role/version docs, the version-matched [TrueNAS api_client](https://github.com/truenas/api_client/blob/master/README.md), [TrueNAS API overview](https://www.truenas.com/docs/scale/api/), [user API-key transport warning](https://cdn.truenas.com/docs/scale/scaleuireference/toptoolbar/settings/apikeysscreen/), [WCAG 2.2](https://www.w3.org/TR/WCAG22/). These are external reference claims, **not** actual runtime test results.
