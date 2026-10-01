# SupraChat prototype

Windows-first, cross-platform ChatGPT parity client and actor-interview surface.

Architecture:

1. ChatGPT parity surface: an Avalonia NativeWebView pointed at the official https://chatgpt.com/ top-level experience. This inherits the user's normal ChatGPT product/session instead of cloning undocumented backend APIs.
2. Agent Lab: OpenAI's documented Sign in with ChatGPT / ChatGPT-plan usage flow, direct streamed Responses API calls, and an optional Codex app-server binding.

The separation is intentional: the SIWC preview route does not expose every ChatGPT product capability. The official ChatGPT surface remains the parity path; Agent Lab is the empirical actor qualification path.

Security boundaries:

- no browser-cookie scraping;
- no undocumented ChatGPT backend endpoints;
- OAuth uses the system browser, PKCE S256, state, nonce, dynamic client registration, and OIDC ID-token validation;
- the required chatgpt.tokens.use.direct grant is checked before inference;
- Responses calls force store=false and stream=true;
- tokens are never passed on a command line or logged;
- Codex app-server receives the token only through ACCESS_TOKEN;
- local credential state remains outside Git.

Current parity posture:

The embedded official ChatGPT surface is intended to carry normal chat/history/model selection, files/images, memory/projects/search/images and web voice according to the user's account and the official web product. Mobile-only Advanced Voice video/screen-share behavior remains a tracked parity gap until an official desktop/web surface or a native adapter is qualified.

Build:

dotnet build prototype/suprachat/SupraChat/SupraChat.csproj -c Release
dotnet run --project prototype/suprachat/SupraChat.ContractTests/SupraChat.ContractTests.csproj -c Release

Windows 11 includes the Edge WebView2 runtime. Windows 10 may require the WebView2 runtime as an installer prerequisite.
