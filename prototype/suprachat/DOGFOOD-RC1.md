# SupraChat Windows Dogfood RC1 gate

This bounded qualification branch exists to prove the first user-usable Windows baseline without making full cross-platform parity a prerequisite.

## Release gate

RC1 is eligible for human dogfood only when the public workflow proves:

- self-contained Windows build and packaged Codex/browser runtimes;
- per-user install and uninstall lifecycle;
- GUI launch survival;
- accessibility static contracts, with hosted-runner live-UIA limitations recorded rather than confused with product failures;
- automation and JSON-RPC agent shells;
- semantic browser snapshot;
- explicit confirmation boundaries for consequential actions.

## Human authorization gate

Public CI intentionally carries no OpenAI credentials. The remaining account-bound rep is performed by the user in the packaged Windows build:

1. clean launch with no saved credential;
2. Continue with ChatGPT;
3. complete human authorization in the system browser;
4. return to SupraChat authenticated;
5. make one authenticated model response;
6. close/reopen and verify credential reuse/refresh;
7. log out/revoke and verify return to unauthenticated state.

No copied browser cookies, private endpoints, embedded secrets, or automated approval are permitted.

## Non-blocking follow-ons

Computer Use fallback primitives and credential-free local Codex reads remain bounded children. They may be incorporated only after their own evidence is green and they do not destabilize RC1.
