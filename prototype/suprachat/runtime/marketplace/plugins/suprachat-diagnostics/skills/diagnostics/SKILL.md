# SupraChat Diagnostics

Use this skill when the task is to inspect the local SupraChat runtime, its authorization readiness, packaged capability catalogs, or machine-facing interfaces.

Prefer the public machine contracts rather than scraping GUI text:

- `suprachat-cli doctor` — local runtime and redacted authorization readiness.
- `suprachat-cli auth-status` — redacted identity/plan-scope state.
- `suprachat-cli capabilities` — audience and binding inventory.
- `suprachat-cli catalog` — packaged SIWC + Codex stable/frontier catalogs.
- `suprachat-cli codex-catalog` — bundled Codex runtime versus upstream frontier.
- `suprachat-cli siwc-catalog` — plan-sharing capability contract.

Do not print, copy, or request access/refresh/ID tokens. If authorization is required, return the typed boundary and direct the human to complete authorization through the SupraChat GUI.

For agent use, the equivalent JSON-RPC methods are available through `suprachat-cli stdio`.
