# ChatGPT Android vs Codex CLI/app-server vs SIWC

Evidence date: 2026-10-01.

This note is an implementation comparison, not a claim that the three surfaces share one codebase or one feature contract.

## Pinned evidence

- ChatGPT Android AAR authority: `SemperSupra/android-artifact-recovery-private#79`
- Verified Android sample: `com.openai.chatgpt` 1.2026.265 / versionCode 2626541
- Verified AAR manifest: `corpus/manifests/chatgpt/chatgpt-android-1.2026.265-2026-10-01.json`
- Public-safe AAR execution: `SemperSupra/android-artifact-recovery#37`, run `36891186715`
- Codex source oracle: `openai/codex@57ac6f51639f7cad705a48ac4bd8073034a2f150`
- SIWC contract: OpenAI developer documentation checked 2026-10-01
- Actor qualification authority: `SemperSupra/agent-dispatch-private#424`

## Architectural comparison

| Dimension | ChatGPT Android | Codex CLI / app-server | SIWC / ChatGPT-plan usage |
| --- | --- | --- | --- |
| Primary role | First-party ChatGPT product client | Open-source coding/agent runtime and RPC server | Third-party authorization + eligible inference contract |
| Implementation evidence | Proprietary Android app; 20 APK splits, 8 DEX, 11 ELF, JS/assets | Apache-2.0 Rust source | Public OAuth/OIDC + Responses documentation |
| UI | Rich native/mobile ChatGPT product UI | Terminal/TUI plus clients that drive app-server | No product UI; integrator supplies UI |
| Product account semantics | First-party ChatGPT account/product surface | Explicit account/login protocol and ChatGPT/API modes | User consents to app identity and separately grants plan-use scope |
| Authentication evidence | AAR observes OpenAI auth hosts, PKCE marker, device-code marker; internal details remain first-party/proprietary | Browser login, device-code login, account state, refresh/rate-limit surfaces visible in source | PKCE public-client flow; initial dynamic registration; stable `ext_agent_host_id`; explicit `chatgpt.tokens.use.direct` |
| Inference path | Product-specific first-party service behavior; do not treat recovered endpoints as third-party contract | Responses-backed provider can be configured explicitly | Public `/v1/responses`; `store:false`, `stream:true` in current OSS plan-sharing contract |
| Conversation/product history | Full ChatGPT product behavior | Local Codex threads/resume semantics | Direct Responses route is intentionally narrower; app owns state allowed by the contract |
| Tools | ChatGPT product tools/connectors/features | Local shell/MCP/tools/agents through Codex runtime | Supported Responses tools are constrained by SIWC preview; Codex local tools remain separate |
| Voice/media | AAR shows realtime/audio/WebRTC/capture surfaces | Not the ChatGPT mobile media client; Codex has its own agent/runtime media-related surfaces where implemented | Current plan-sharing route is not a general ChatGPT voice/video API |
| Files/images | AAR shows attachments, file library, images/imagegen surfaces | Agent/runtime file/tool semantics | Text, images and files supported where the selected model accepts them; current SIWC limitations still apply |
| Camera/screen share | Native Android/mobile integration including media-projection/screen-share evidence | Not equivalent | No supported route to recreate mobile Advanced Voice continuous camera/screen-share semantics |
| Push/background/mobile integration | Android notifications, receivers/services, bubble/share/widget/quick-tile related surfaces | CLI/app-server lifecycle rather than mobile OS integration | Integrator responsibility; no automatic ChatGPT mobile parity |
| Source availability | Proprietary; only bounded derived evidence retained | Open source | Documentation/contract, not ChatGPT product source |
| Qualification use | First-party behavior/capability oracle | Source-level runtime oracle and actor candidate | Supported third-party auth/inference substrate |

## High-signal Android recovery facts

The verified AAR sample has:
- XAPK SHA-256 `535355701ff1c1f01b1ea4c526e8311f8c390229d113012f717c1445bb6adb22`;
- OpenAI signer SHA-256 `b24f4bfbb3cf293f938703b9d87027c1102cc36dc4fa206910e08927db40473c`;
- 61 activities, 26 services, 17 receivers, and 15 providers in the bounded derived surface;
- markers for WebRTC, realtime voice, media projection, screen share, camera, share intents, push messaging, temporary chat, file library, connector auth, conversation bubbles, Codex handoff, PKCE, and OAuth device code.

The bounded scan did **not** match SIWC-specific literals:
- `dynamic_agent_client`
- `ext_agent_host_id`
- `chatgpt.tokens.use.direct`
- the targeted SIWC authorize/token path literals
- the targeted Responses API path literal

That negative result is bounded static evidence only. It is useful because it argues against treating SIWC as a reconstruction of the Android login implementation, but it cannot prove those concepts never appear at runtime or in code missed by the bounded recovery.

## Codex oracle facts at the pinned revision

The pinned Codex source exposes:
- distinct API-key and ChatGPT account modes;
- browser and device-code ChatGPT login protocol variants;
- account, plan, rate-limit and token-usage surfaces;
- app-server RPC lifecycle;
- thread/turn execution semantics;
- a Responses-provider configuration that can consume an externally supplied ChatGPT-plan OAuth access token.

The experimental/internal token-injection login variant in Codex is **not** the integration contract for SupraChat. SupraChat follows the public SIWC contract.

## Product consequences for SupraChat

SupraChat deliberately has two independent planes:

### 1. ChatGPT product plane

Use the official top-level `https://chatgpt.com/` experience inside a persistent native WebView profile.

This preserves first-party product semantics for:
- normal chat and history;
- model selection;
- projects/memory/search;
- files/images and other web-exposed ChatGPT features;
- account settings and product-specific behavior.

The app does not scrape cookies or call recovered private mobile endpoints.

### 2. Agent Lab plane

Use the documented SIWC grant for:
- model discovery;
- direct streamed Responses interviews;
- redacted actor-qualification receipts;
- Codex app-server as a distinct actor/runtime binding.

A direct Responses binding and a Codex app-server binding are different candidates even if they use the same ChatGPT-plan entitlement.

## Parity rule

A capability may be marked equivalent only when the supported Windows/cross-platform path preserves the consequential semantics.

If the Android app has a mobile-only capability and no supported desktop/web/SIWC/Codex interface can reproduce it, keep the row `BLOCKED` or `GAP`. Do not fill it with an undocumented endpoint merely to increase a parity percentage.
