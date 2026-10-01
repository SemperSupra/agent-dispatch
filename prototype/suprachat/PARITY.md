# SupraChat capability/parity ledger

Evidence date: 2026-10-01.

## Scope rule

SupraChat does **not** define scope by the smallest common denominator across clients.

The campaign tracks every consequential capability exposed by any authoritative plane:

1. recovered ChatGPT Android;
2. official ChatGPT Windows desktop;
3. official ChatGPT web/product;
4. documented Sign in with ChatGPT (SIWC) / ChatGPT-plan Responses;
5. pinned open-source Codex CLI/app-server.

A feature missing from one plane remains in the ledger as `SUPPORTED`, `PARTIAL`, `GAP`, `BLOCKED`, or `UNKNOWN`; it is not deleted to make the surfaces look equivalent.

Broad inventory is separate from runtime authority. Destructive, privileged, credential-bearing, or externally consequential capabilities remain explicit-consent/authority operations even when the implementation knows how to invoke them.

## Evidence planes

### Android first-party oracle

- Authority: `SemperSupra/android-artifact-recovery-private#79`
- Public-safe recovery: `SemperSupra/android-artifact-recovery#37`
- Sample: `com.openai.chatgpt` 1.2026.265 / versionCode 2626541
- 20 APK splits; signer-verified.
- Derived markers include WebRTC/realtime voice, media projection, screen share, camera, sharing, push messaging, temporary chat, file library, connectors, conversation bubbles, Codex handoff, PKCE and OAuth device code.

### Windows first-party oracle

- Authority: `SemperSupra/connected-device-recovery-private#59`
- Official Windows help: https://help.openai.com/en/articles/9982051
- Windows release notes: https://help.openai.com/en/articles/10003026
- Work/Codex desktop behavior: https://help.openai.com/en/articles/20001275-chatgpt-work-and-codex
- Built-in browser: https://help.openai.com/en/articles/20001277-using-the-built-in-browser-in-the-chatgpt-desktop-app

Current official documentation establishes Windows-specific surfaces including companion window, desktop Voice, Work/Codex, computer/local-file/app context where available, and a built-in browser with its own state/tabs/download/sign-in behavior. Those are independent parity targets, not assumed to be properties of the web surface.

### SIWC / ChatGPT-plan contract

- Authority: `SemperSupra/agent-dispatch-private#424`
- Current docs: https://developers.openai.com/siwc/token-sharing-open-source
- Current plan-sharing calls require `store:false` and `stream:true`.
- Model availability is account/plan/workspace dependent and discovered at runtime.
- Text, image and file input are supported where the selected model accepts them.
- Web search and supported function/custom tools are available subject to the current contract/model/policy.
- Unsupported request fields/tools remain in the qualification matrix as typed constraints; the raw Responses surface deliberately lets upstream validation provide the authoritative result rather than silently removing probe fields.

### Codex source/runtime oracle

- Revision: `openai/codex@57ac6f51639f7cad705a48ac4bd8073034a2f150`
- Inventory: `oracles/codex-app-server-surface-20261001.json`
- At this revision: 172 client→server RPC methods, 9 server→client requests and 85 notifications = 266 protocol surfaces.
- Codex is a source-level/runtime oracle and actor candidate. It does not prove implementation details of the proprietary Android or Windows applications.

## Product parity matrix

| Capability family | Android | Windows first-party | SupraChat route | State |
| --- | --- | --- | --- | --- |
| Chat / normal conversations | observed/recovered | documented | persistent official ChatGPT web surface | SUPPORTED / qualify account |
| Conversation history / search | recovered | documented, including history search | official surface; native quick access may supplement | SUPPORTED / qualify |
| Model selection | recovered | documented | official surface + SIWC runtime model catalog | SUPPORTED |
| Projects | recovered | documented in desktop Work flow | official surface | SUPPORTED / qualify |
| Memory | recovered markers | product capability | official surface | SUPPORTED / qualify |
| Search / web-backed answers | recovered | product capability | official surface + SIWC web-search tool where eligible | SUPPORTED |
| Files / attachments / Library | recovered | documented file/local-folder behavior | official surface + SIWC file input + Codex file/fs surfaces | SUPPORTED / broaden qualification |
| Images / photo input | recovered | Windows webcam/photo and file surfaces documented historically | official surface + SIWC image input; native capture adapter | PARTIAL / qualify capture |
| Image generation/editing | recovered | documented product behavior | official ChatGPT surface; not synthesized through unsupported SIWC hosted image tool | SUPPORTED via product plane |
| Camera capture | recovered | Windows take-photo behavior documented | native Windows capture + product/web where exposed | GAP → implementation |
| Voice | realtime/WebRTC evidence | desktop Voice documented; Work/Codex Voice available on eligible accounts | official surface + Windows-native/audio qualification | PARTIAL / live qualification |
| Advanced Voice video | mobile capability | not documented as equivalent Windows capability | no equivalent supported SIWC surface | BLOCKED / monitor |
| Advanced Voice continuous screen share | mobile screen-share evidence | desktop computer context exists, but semantics differ | desktop context/native capture experiments; no false equivalence | PARTIAL/BLOCKED |
| Work | product surface | first-party Windows Work documented | official product plane; future native integrations may supplement | SUPPORTED / qualify |
| Codex desktop view | mobile handoff/Remote relationship | first-party Windows Codex documented | native Codex app-server actor + product oracle comparison | PARTIAL → expand |
| Mobile Codex Remote | Android/mobile relationship | supported desktop Codex can be accessed from mobile Remote | Codex remote-control protocol is inventoried; qualify pairing/control | GAP → active |
| Built-in browser | browser/search markers | first-party Windows built-in browser documented | official product surface + Codex/browser capabilities where supported | GAP/PARTIAL |
| Browser state / tabs / downloads | mobile/web behaviors differ | Windows first-party browser has independent state, tabs and downloads | native/WebView + Codex/browser qualification | GAP/PARTIAL |
| Companion window / quick access | Android bubble/overlay | Windows companion window documented | native Alt+Space global summon/toggle + persistent main window | IMPLEMENTED / qualify interaction |
| Notifications / push | recovered receivers/push | Windows behavior to acquire/observe | native Windows background-completion notification adapter + web behavior | PARTIAL / IMPLEMENTED local notification |
| Sharing / share target | recovered | desktop behavior to observe | Windows Open With + suprachat:// deep-link launch + official surface | PARTIAL / IMPLEMENTED ingress |
| Temporary chat | recovered | product behavior to observe | official surface | SUPPORTED / qualify |
| Connected apps / plugins/connectors | recovered | Work/Codex/product surfaces | official product surface + complete Codex plugin/app/MCP surfaces | SUPPORTED/PARTIAL |
| Local files/apps context | mobile semantics differ | Windows Work/Codex documented | Codex fs/process/MCP + explicit desktop permission adapters | PARTIAL → expand |
| Screen/computer context | media-projection evidence | Windows desktop computer-context permissions documented | explicit desktop context adapters + Codex runtime | PARTIAL → expand |
| Local shell/process | not ChatGPT-mobile parity feature | Codex desktop behavior | full Codex app-server process/command protocol | SUPPORTED surface / qualify |
| MCP | connector/tool evidence | Codex/Work ecosystem | full Codex MCP OAuth/status/resource/event/tool surfaces | SUPPORTED surface / qualify |
| Skills / plugins / apps / marketplace | product markers | Codex ecosystem | full Codex skills/plugin/apps/marketplace surfaces | SUPPORTED surface / qualify |
| Threads / turns / goals / queues / projects | product conversations differ | Codex runtime | full Codex protocol | SUPPORTED surface / qualify |
| Realtime Codex audio/text/speech | Android has realtime/voice indicators | Codex desktop Voice documented | Codex realtime protocol inventory + UI adapters | GAP → active |
| Remote control / pairing | mobile Remote relationship | desktop host side | Codex remote-control/pairing/client protocol | GAP → active |
| Approvals / elicitation / permissions | user-consent surfaces | desktop agentic interactions | all 9 Codex server-request classes exposed for explicit human response | SUPPORTED surface / qualify |
| Windows sandbox setup/readiness | n/a | Codex Windows concern | Codex Windows sandbox RPC/notifications | SUPPORTED surface / qualify |
| Account / rate limits / token usage | account/product surfaces | account/product surfaces | SIWC grant metadata + Codex account/rate-limit/usage protocol | SUPPORTED surface / qualify |
| Sign-out / grant revocation | product auth | product auth | SIWC refresh-token revocation + local credential deletion | IMPLEMENTED / qualify |
| Location / Places | recovered markers | browser/product-dependent | official product/browser geolocation if requested; native adapter only if justified | UNKNOWN/PARTIAL |

## Direct SIWC surface policy

SupraChat has two direct Responses paths:

1. typed interview UI for normal text/image/file/web-search qualification;
2. raw Responses console for the complete request surface.

The raw surface:
- preserves arbitrary request fields and tool definitions;
- injects the selected account model when `model` is omitted;
- forces only the current ChatGPT-plan invariants `store:false` and `stream:true`;
- surfaces upstream success/error behavior and request IDs;
- does not reinterpret an upstream rejection as proof that the underlying model can never support the feature through another OpenAI surface.

This is intentionally broader than a hand-authored allowlist.

## Codex full-surface policy

SupraChat uses a generic app-server JSON-RPC transport rather than wrapping only a few methods.

The current client can:
- send arbitrary client RPC methods/params;
- monitor every notification;
- surface every server-initiated request;
- explicitly return a result or rejection to a pending server request;
- run typed Codex interviews using the same refreshed ChatGPT-plan entitlement;
- keep typed convenience flows separate from the generic protocol substrate.

The typed qualification interview currently uses an ephemeral empty workspace, read-only sandbox, no approvals and instructions not to call tools. **That is a qualification fixture, not a global capability restriction.** The generic app-server console retains the complete protocol surface.

## Architecture invariants

1. Do not treat decompiled proprietary implementation as reusable source.
2. Do not scrape browser cookies or depend on undocumented private ChatGPT endpoints.
3. Preserve Android, Windows, web/product, SIWC and Codex as distinct evidence planes.
4. Prefer official first-party product surfaces for first-party product semantics.
5. Use documented SIWC for third-party ChatGPT-plan authorization/inference.
6. Use Codex source/app-server for open-source agent/runtime capabilities.
7. Keep authority and capability distinct: knowing a method exists does not automatically authorize invoking it.
8. Negative results and unsupported surfaces are durable evidence, not reasons to delete a capability from the ledger.

## Windows MVP exit rule

The Windows artifact is a working MVP when it:
- builds and launches self-contained on a clean Windows runner;
- loads the official ChatGPT product surface in a persistent app-owned browser profile;
- can complete normal product sign-in at the user boundary;
- can complete SIWC registration/consent and a real streamed ChatGPT-plan request;
- exposes typed and raw direct Responses surfaces;
- initializes Codex app-server with the same refreshed entitlement;
- can perform a real Codex thread/turn interview;
- exposes the full pinned Codex RPC/notification/server-request substrate;
- stores secrets only in the local credential boundary;
- produces redacted qualification receipts;
- has every discovered Android/Windows/product capability represented in this ledger with an explicit state.

Full Android parity is a later qualification claim and must not be asserted while platform-specific mobile capabilities remain blocked or behaviorally nonequivalent.


## R2/R3 clean-room desktop-runtime tranche

Authority: `SemperSupra/agent-dispatch-private#427`.
Integration candidate: public PR #93.

### R2 — portable plugin marketplace

Implementation state: **IMPLEMENTED / qualification pending**.

- Reuses the upstream Codex marketplace/plugin lifecycle; SupraChat does not implement a second plugin manager.
- Bundled marketplace root: `runtime/marketplace`.
- Local marketplace: `sempersupra-local`.
- First harmless plugin: `suprachat-diagnostics@sempersupra-local`.
- The first plugin is skill-only and requires no network, MCP server, or destructive hook.
- Bundled Codex runs with an app-owned `CODEX_HOME` beneath SupraChat state rather than the user's unrelated standalone-Codex home.
- Local marketplace/plugin operations can start Codex without a ChatGPT-plan token.
- Model inference remains separately gated by SIWC plan authorization.
- Human: Agent Lab Local plugin marketplace controls.
- Automation: marketplace/plugin lifecycle JSON commands.
- Agent: marketplace/plugin JSON-RPC methods plus raw `codex/request`.

### R3 — portable browser host

Implementation state: **IMPLEMENTED / browser-runtime qualification pending**.

- Clean-room implementation source: Microsoft Playwright .NET `1.63.0`, MIT.
- Browser profiles are app-owned and separate from the ChatGPT product WebView profile.
- No browser-cookie scraping/import is used.
- Shared host covers persistent profile, pages/tabs, navigation, accessibility + optional DOM observation, screenshot, click/fill/key input, file-input upload, permissions, tracing, and explicit JavaScript evaluation.
- Human: Browser Lab.
- Automation: one-shot observe/screenshot plus stdio for multi-step flows.
- Agent: sessionful JSON-RPC browser methods.
- Browser screenshot is not considered OS screen/computer context; desktop capture remains a separate R4/native-adapter concern.
