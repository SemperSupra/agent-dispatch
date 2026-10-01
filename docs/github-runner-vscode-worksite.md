# GitHub Runner vscode.dev worksite

This is a public-safe experiment for presenting a disposable GitHub-hosted Linux runner
through `vscode.dev` without making an arbitrary web endpoint part of the human work
surface.

## Current rung: pre-authentication only

The first rung intentionally does **not** start a VS Code Remote Tunnel and does not receive
any credential.

It proves only that a fresh public GitHub-hosted runner can:

1. acquire the current standalone VS Code CLI;
2. expose the expected Remote Tunnel command/flag contract;
3. reach `vscode.dev`;
4. reach the Microsoft Dev Tunnels relay endpoint; and
5. retain a public-safe receipt with no login code or credential material.

The actual installed CLI is the oracle. Documentation/source observations inform the
experiment but do not replace the runtime receipt.

## Security boundary

This experiment follows the repository security model:

- public source only;
- no private repository or branch locator in workflow inputs or logs;
- no provider or VS Code tunnel secret;
- no `pull_request_target`;
- pinned third-party Actions;
- persisted checkout credentials disabled;
- `GITHUB_TOKEN` limited to `contents: read`;
- no interactive device authorization emitted into public logs.

The preflight receipt records only CLI/version/flag and endpoint-reachability facts.

## Promotion gate

An identity-bearing tunnel workflow is a separate rung and requires explicit evidence that
the host login mechanism is supported, bounded, revocable, and suitable for headless use.

Do not add a reusable VS Code access token or other tunnel credential to this repository
until that gate is satisfied and the secret-bearing workflow boundary is separately
reviewed/protected.

If safe ephemeral host authentication is not available, preserve this preflight result and
use a persistent private host (for example OCI) or Colab as the approved presentation-side
workbench instead of weakening the identity boundary.
