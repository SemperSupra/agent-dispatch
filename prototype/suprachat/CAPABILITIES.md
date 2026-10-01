# SupraChat capability and endpoint registry

Evidence date: 2026-10-01.

This registry is intentionally broader than the MVP. It tracks every capability surface currently relevant to the campaign and keeps distinct evidence/authority planes:

1. **WEB_PRODUCT** — first-party ChatGPT WebUI/product behavior at `https://chatgpt.com/`.
2. **ANDROID_OBSERVED** — recovered first-party Android behavior/capability/endpoint evidence.
3. **WINDOWS_DESKTOP_OBSERVED** — official unified Windows desktop package/product behavior.
4. **MACOS_DESKTOP_OBSERVED** — official unified macOS desktop behavior.
5. **MACOS_CLASSIC_OBSERVED** — separately supported legacy/Classic macOS lineage.
6. **LINUX_DESKTOP_OBSERVED** — official Linux public-preview package/product behavior.
7. **SIWC_SUPPORTED** — documented Sign in with ChatGPT / ChatGPT-plan third-party contract.
8. **CODEX_ORACLE** — open-source Codex CLI/app-server capabilities at an exact upstream revision.

Desktop/Web/Android observations are first-party oracles, not automatically supported third-party integration contracts.

An observed first-party or Codex capability is not automatically a supported SIWC contract.

## SIWC / ChatGPT-plan endpoint inventory

Current documented production endpoints:

| Endpoint/surface | Method | State | Notes |
| --- | --- | --- | --- |
| `https://auth.openai.com/.well-known/openid-configuration` | GET | SIWC_SUPPORTED | issuer/JWKS/revocation discovery |
| `https://auth.openai.com/api/accounts/authorize` | browser GET | SIWC_SUPPORTED | dynamic registration or saved-client OAuth; PKCE/state/nonce |
| `https://auth.openai.com/api/accounts/oauth/token` | POST | SIWC_SUPPORTED | authorization-code exchange and rotating refresh |
| discovered `revocation_endpoint` | POST | SIWC_SUPPORTED | end renewable session with refresh token |
| `https://api.openai.com/v1/models` | GET | SIWC_SUPPORTED | account-specific model catalog; keep `visibility=list` |
| `https://api.openai.com/v1/responses` | POST/SSE | SIWC_SUPPORTED | `store=false`, `stream=true`; success requires `response.completed` |

Supported direct-plan capabilities currently include:
- text input;
- image input when selected model supports it;
- file input using inline/base64 or external URL when selected model supports it;
- stateless multi-turn by resending required history in `input`;
- instructions/developer messages under the documented preview rules;
- function/custom tools;
- web search subject to model/account/workspace policy;
- streamed response events and exact terminal/error handling.

Current SIWC preview exclusions are retained as explicit capability states, not silently omitted:
- no persistent Responses `conversation` or HTTP `previous_response_id`;
- no `background`, `multi_agent`, hosted file search, hosted image generation, Code Interpreter, native computer use, hosted MCP/connectors, Responses `tool_search`, or top-level programmatic tool calling;
- no audio/video input, Files upload API, or transcription API through this plan-sharing flow;
- several ordinary Responses request knobs are currently rejected by the subscription-sharing route.

Where useful, an excluded hosted capability may still be available through **Codex local tools** or the **first-party ChatGPT product surface**, but it remains a different binding.

## General OpenAI API surfaces outside the SIWC plan-sharing contract

Track but do not charge these to a ChatGPT plan unless OpenAI documents that route in the future:

- Realtime API (WebRTC/WebSocket/SIP);
- Images generation/edit endpoints;
- Files upload/vector-store/file-search administration;
- Audio speech/transcription/translation endpoints;
- video generation endpoints;
- embeddings and moderation endpoints;
- hosted shell/code interpreter/computer-use/tool-search where not admitted by SIWC;
- administration/project/API-key/audit endpoints.

These can become optional API-key/provider bindings later without contaminating ChatGPT-plan accounting.

## ChatGPT product plane

The official top-level ChatGPT surface remains the broadest supported product-parity route. The embedded persistent native webview is expected to expose whatever the signed-in ChatGPT account is entitled to on the web product, including account-dependent combinations of:

- chats/history/model selection;
- search/web-backed answers;
- projects, memory, tasks and other product work surfaces;
- file/image attachment, file library and image generation/editing;
- Canvas/Work-style surfaces where available;
- connected apps/connectors/plugins;
- sharing and account settings;
- web voice and browser-mediated media capabilities;
- Codex/agent product experiences exposed in ChatGPT.

Capability availability is runtime/account dependent and must be qualified rather than hard-coded from a marketing list.

## Codex CLI/app-server oracle

Initial oracle: `openai/codex@57ac6f51639f7cad705a48ac4bd8073034a2f150`.

Expanded current oracle: `openai/codex@cc31e374fc15cd616fca19c07d55f9fa7e6d7e31` (2026-10-01T17:10:03Z).

At the expanded snapshot, the app-server protocol definition exposes **266 method/notification names**. The implementation should not blindly invoke every experimental/internal method; this list is an exhaustive discovery/oracle surface used to determine what the open-source runtime can do and what stable subsets SupraChat should bind.

### Account/auth/usage
`account/login/start`, `account/login/cancel`, `account/logout`, `account/read`, `account/updated`, `account/rateLimits/read`, `account/usage/read`, workspace messages, gateway OAuth, Bedrock discovery/setup, auth-recovery notifications, and related account surfaces.

### Model/runtime
`model/list`, `modelProvider/capabilities/read`, model verification/reroute/safety-buffer notifications, collaboration modes, permission profiles, experimental feature inventory, server diagnostics and current time.

### Thread lifecycle and history
`thread/start`, `thread/read`, `thread/list`, `thread/search`, `thread/resume`, `thread/fork`, `thread/revert`, `thread/archive`, `thread/unarchive`, `thread/delete`, `thread/compact/start`, thread sections, metadata/name/settings, timeline/items/turn lists, memory mode and thread goals.

### Turn lifecycle
`turn/start`, `turn/steer`, `turn/interrupt`, turn settings and plan/diff/status notifications, streamed reasoning/agent-message/item events, raw-response events, approvals and user-input requests.

### Realtime
`thread/realtime/start`, `thread/realtime/stop`, `thread/realtime/sdp`, `thread/realtime/listVoices`, append text/audio/speech, transcript/audio deltas, item lifecycle, error and close events.

### Attachments / queue / background terminals
Thread attachment add/list/remove/update; queue add/list/update/reorder/delete/start; background terminal list/terminate/clean.

### Shell/process/filesystem
`command/exec` plus resize/write/terminate/output; `process/spawn`, stdin/PTY/output/kill; filesystem read/write/copy/remove/mkdir/metadata/watch; fuzzy file search; thread shell commands.

### MCP/tools/skills/plugins/apps
MCP status/resource/tool/OAuth/elicitation/event-stream operations; tool calls and approvals; skills list/config/extra-roots/change notifications; plugin list/search/read/install/uninstall/reconcile/share/skill operations; app list/read/install state.

### Projects/environments
Project create/read/list/update/move/import/delete/change; environment add/info/status; external-agent configuration detection/import/history.

### Remote control
Remote-control enable/disable/status, pairing start/status, client list/revoke.

### Safety/permissions/verification
Guardian/auto-approval flows, permission requests/profiles, user verification enroll/status/verify/cancel/delete, attestation, Windows sandbox readiness/setup, warnings/deprecations.

The complete method-name inventory is reproducible by extracting `=> "…"` protocol labels from:
`codex-rs/app-server-protocol/src/protocol/common.rs`
at the exact oracle revision above.

### Credential-free local read frontier

Public qualification on 2026-10-01 used the bundled pinned Codex app-server with known OpenAI/Codex credential environment variables removed and an isolated Codex home. The same read-only/local methods returned results on Windows, Linux and macOS without OpenAI authorization:

- `config/read`;
- `configRequirements/read`;
- `experimentalFeature/list`;
- `collaborationMode/list`;
- `model/list`;
- `plugin/list`;
- `permissionProfile/list`;
- `app/list`;
- `mcpServerStatus/list`;
- `skills/list`;
- `windowsSandbox/readiness`;
- `thread/realtime/listVoices`;
- `remoteControl/status/read`;
- `thread/list`.

SupraChat binds exactly this set through `CodexLocalReadPolicy` and the `codex-local-read` / `codex/local/read` machine surfaces. Calls outside that allowlist do **not** silently fall through to guest execution.

Observed account-backed boundaries remain separate:
- public guest-probe run `36927142694` returned authentication-required outcomes for `account/rateLimits/read`, `account/usage/read`, and `account/workspaceMessages/read`;
- `account/read` returned invalid-parameters because the first probe omitted its request object. Current upstream protocol source defines `GetAccountParams.refreshToken` with a default false value and upstream tests send `params: {}`; that source evidence nominates a corrected guest rep but does **not** qualify `account/read` for this allowlist until a clean empirical run passes.

This frontier is a capability boundary, not an authority shortcut: inference, account/usage data, plugin/app mutation, Remote mutation, sandbox setup, server-request approval, and other consequential methods retain their existing authorization/confirmation requirements.

## ChatGPT Android observed capability plane

AAR authority: `SemperSupra/android-artifact-recovery-private#79`.

Verified sample:
- package `com.openai.chatgpt`;
- version `1.2026.265` / versionCode `2626541`;
- 20 signer-verified APK splits;
- 8 DEX, 11 ELF, 4 JavaScript entries, 3 nested archives.

Recovered/observed categories include:
- conversations/history/models;
- temporary chat;
- files/attachments/File Library;
- images/photo/image generation/image editing;
- search/browser;
- memory/projects/canvas/task markers;
- connectors/plugin/auth flows;
- voice/realtime/audio/WebRTC;
- camera/capture/media projection/screen share;
- sharing/deep links/text processing;
- Firebase push/notifications;
- conversation bubbles/overlay concepts;
- widgets and quick settings tile;
- accessibility/screen-context and Android voice-interaction service;
- location, NFC, Bluetooth, contacts and biometric-related platform permissions;
- Codex handoff/realtime-voice concepts;
- first-party OpenAI hosts and protocol markers.

AAR is being expanded to retain sanitized URL/route/deep-link candidates while dropping userinfo, query strings, fragments and opaque account/token material. Those endpoint shapes are **ANDROID_OBSERVED**, not automatically callable by SupraChat.

## Product implementation policy

SupraChat should implement the union of capabilities through the strongest supported route:

1. use the first-party ChatGPT web surface for product semantics;
2. use SIWC for documented account identity + plan-backed eligible Responses;
3. use Codex app-server for local agent/runtime capabilities, including shell/MCP/skills and thread lifecycle where stable;
4. add desktop-native adapters for OS capabilities such as capture, notifications, global summon, file handoff and media devices;
5. retain Android-only/private endpoint behavior as discovery/oracle evidence until there is a supported equivalent;
6. never omit a known capability silently: classify it as `IMPLEMENTED`, `QUALIFY`, `GAP`, `BLOCKED_SUPPORTED_INTERFACE`, `ORACLE_ONLY`, or `NOT_PLAN_SHAREABLE`.

This registry is expected to grow as AAR, Codex upstream, ChatGPT web, and OpenAI documentation change.

Accessibility and audience parity are first-class capability metadata. The shared AccessibilityContract is exposed through the GUI, suprachat-cli accessibility, and JSON-RPC accessibility/read; stable UI automation IDs also serve assistive technology and qualification tooling.


## First-party platform oracle expansion — 2026-10-01

Durable CDR authorities:
- Android consumer/oracle: `SemperSupra/connected-device-recovery-private#58` fed by AAR #79.
- Windows unified desktop: `SemperSupra/connected-device-recovery-private#59`.
- macOS unified + Classic: `SemperSupra/connected-device-recovery-private#62`.
- Linux desktop public preview: `SemperSupra/connected-device-recovery-private#63`.
- WebUI/runtime: `SemperSupra/connected-device-recovery-private#64`.

### Windows

Current unified desktop Store identity is `9PLM9XGG6VKS`. Credential-free Store metadata discovery succeeds, but hosted-runner package-byte download currently returns a typed Microsoft Entra authentication requirement. Preserve that as an acquisition boundary rather than substituting an unverified package.

### macOS

Track at least three official distribution candidates independently:
- unified Apple Silicon: `https://persistent.oaistatic.com/codex-app-prod/ChatGPT.dmg`;
- unified Intel/x64: `https://persistent.oaistatic.com/codex-app-prod/ChatGPT-latest-x64.dmg`;
- ChatGPT Classic: `https://persistent.oaistatic.com/classic/public/ChatGPT_Classic.dmg`.

Do not collapse unified and Classic behavior merely because both are first-party ChatGPT clients.

### Linux

The official desktop app is in public preview with x64 + ARM64 packages for supported Ubuntu/Debian/Fedora distributions plus an Arch install/repository path. Linux remains a distinct behavior plane because current platform support differs from macOS/Windows, including missing Computer Use and experimental native Wayland support.

### WebUI / guest

Public qualification run `SemperSupra/connected-device-recovery` run `36902044519` established:
- OpenAI OIDC discovery is publicly readable without authentication (`200`);
- `GET /v1/models` without a bearer token returns `401`;
- `POST /v1/responses` without bearer/basic authentication returns `401`;
- stock public-GHA requests to `chatgpt.com/` and selected observed `backend-anon` routes are challenged by Cloudflare (`403`), so guest product availability must not be modeled as a generic anonymous server-to-server API.

Guest capability should therefore be qualified through an actual supported browser/product surface where applicable, while documented API execution remains authenticated.

## Cross-platform parity rule

For every capability, track a vector rather than a single desktop state:

`Android × Windows × macOS unified × macOS Classic × Linux × WebUI × SIWC × Codex × SupraChat`

Each cell must be one of:
`IMPLEMENTED | QUALIFY | GAP | BLOCKED_SUPPORTED_INTERFACE | ORACLE_ONLY | NOT_PLAN_SHAREABLE | UNKNOWN`.

A capability present on one first-party surface must not disappear because another platform lacks it, and platform-specific behavior must not be generalized without evidence.


## Clean-room browser / computer-use substrate

SupraChat now has an application-owned browser plane separate from the first-party ChatGPT product WebView.

Current substrate:
- pinned `Microsoft.Playwright 1.63.0`;
- Chromium packaged under `runtime/browser` by public qualification;
- fresh/ephemeral browser context by default with no inherited ChatGPT WebView cookies or credentials;
- visible headed browser session for humans with an explicit Stop control;
- AI-optimized ARIA snapshots as the primary structured observation for accessible-human, automation and agent use;
- one-shot automation: `browser-status`, `browser-snapshot`, `browser-click`, `browser-fill`;
- sessionful agent JSON-RPC: `browser/start`, `browser/navigate`, `browser/read`, `browser/click`, `browser/fill`, `browser/stop`;
- semantic click uses ARIA role + accessible name;
- semantic fill uses the accessible label.

This is the clean-room base for Computer Use. It deliberately starts with semantic locators rather than coordinates so the agent-facing representation and the assistive-technology representation converge. Pixel screenshots and raw pointer/keyboard operations remain a later fallback/actuator layer and must retain explicit stop/permission/approval semantics.
