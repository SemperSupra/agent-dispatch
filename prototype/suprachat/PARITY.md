# SupraChat feature-parity ledger

Evidence date: 2026-10-01.

This ledger separates **product parity** from **actor-runtime parity**. The official ChatGPT surface is the primary route for ChatGPT product features; SIWC/Codex are separate supported execution surfaces and must not be used as a pretext to call undocumented ChatGPT backend APIs.

## Evidence planes

- AAR Android recovery: `SemperSupra/android-artifact-recovery-private#79`, public execution `SemperSupra/android-artifact-recovery#37`.
- Android sample: `com.openai.chatgpt` 1.2026.265 / versionCode 2626541, signer-verified.
- Codex source oracle: `openai/codex@57ac6f51639f7cad705a48ac4bd8073034a2f150`.
- SIWC contract: OpenAI developer documentation, checked 2026-10-01.
- ChatGPT product capability/availability: OpenAI Help Center, checked 2026-10-01.

## Parity matrix

| Capability family | Android evidence | Windows MVP route | State |
| --- | --- | --- | --- |
| Chat, conversation history, model selection | recovered conversation/model/history surfaces | official `chatgpt.com` NativeWebView | MVP route |
| Search / web-backed answers | recovered search/browser markers | official ChatGPT surface | MVP route |
| Projects and memory | recovered project/memory markers | official ChatGPT surface | MVP route |
| Files, attachments, Library | recovered file-library/upload/attachment surfaces | official ChatGPT surface; web has full Library | MVP route |
| Image input and image generation/editing | recovered image/photo/imagegen surfaces | official ChatGPT surface | MVP route |
| Canvas / rich work surfaces | recovered canvas markers | official ChatGPT surface | MVP route |
| Plugins / connected apps / connectors | recovered connector auth + plugin surfaces | official ChatGPT surface | MVP route |
| Sharing | recovered share-flow surfaces | official ChatGPT share UI | MVP route |
| Live Voice | recovered voice/realtime/WebRTC surfaces | official ChatGPT web Voice through native webview microphone support | qualify live account |
| Work | Android/web product surface | official ChatGPT surface | MVP route |
| Codex access / handoff | recovered Codex handoff + realtime-voice analytics surfaces | native Agent Lab + Codex app-server; official ChatGPT web remains separate | partial; deliberate non-equivalence |
| OAuth / account session | recovered auth/OAuth surfaces | ChatGPT web owns product login; Agent Lab separately uses documented SIWC | MVP route |
| Camera / image capture | recovered camera/capture surfaces | web upload/camera where exposed; native adapter can provide still-image context | qualification needed |
| Location / Places | recovered location markers | browser geolocation only if official ChatGPT web requests it | qualification needed |
| Notifications | recovered notification surfaces | web notification behavior not yet qualified | gap |
| Android conversation bubble / overlay | recovered Android bubble lifecycle surface | Windows companion window/global shortcut not yet implemented | gap |
| Advanced Voice live video | mobile Advanced Voice capability | no supported SIWC or current desktop/web equivalent | BLOCKED by current supported interface |
| Advanced Voice continuous screen share | recovered Android screen-share bubble + mobile Advanced Voice capability | desktop has screen context in supported experiences, but not mobile-style continuous screen share | BLOCKED / native approximation only |
| Mobile Codex Remote tab controlling another host | OpenAI mobile feature; recovered Codex handoff surfaces | Agent Lab controls local Codex app-server; remote-host pairing not yet implemented | gap |

## Architectural conclusion

The recovered Android client is not a thin Responses wrapper. It contains a large Android/JVM graph, native WebRTC/capture code, OpenAI cross-platform native code, and product-specific service/UI behavior. Codex CLI/app-server is a different open-source agent runtime. SIWC is a third, intentionally narrower OAuth + eligible Responses contract.

Therefore:

1. **Do not port/decompile proprietary Android implementation into the product.**
2. Use the official ChatGPT surface for product semantics and account-backed ChatGPT features.
3. Keep SIWC direct Responses and Codex app-server as separate Agent Lab actor bindings.
4. Implement native desktop adapters only where they can use documented/supported interfaces.
5. Preserve explicit `BLOCKED` rather than silently replacing Advanced Voice video/screen-share semantics with a weaker feature.

## MVP exit rule

The Windows artifact may be called a **working MVP** when:
- it builds and launches on Windows without development tooling;
- the official ChatGPT surface loads and can complete normal account sign-in;
- SIWC can complete one real human-consented registration and one streamed `response.completed` request;
- Codex app-server starts using the same refreshed entitlement;
- all non-blocked rows above are either qualified or explicitly deferred with a bounded implementation node.

It must not be called full Android parity while the two current Advanced Voice mobile-only rows remain blocked by supported OpenAI interfaces.
