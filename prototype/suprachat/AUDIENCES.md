# SupraChat human / automation / agent contract

Evidence/design date: 2026-10-01.

SupraChat is one capability product with three first-class interaction shells. No audience gets a separate backend or divergent capability implementation.

## Audience invariant

| Audience | Primary shell | Contract |
| --- | --- | --- |
| Human | \`SupraChat\` desktop GUI | discoverable desktop navigation, first-party ChatGPT product view, Agent Lab, native OS integrations |
| Automation | \`SupraChat.Automation\` | deterministic JSON on stdout, diagnostics on stderr, stable exit codes, no token material |
| Agent | \`SupraChat.Automation stdio\` | line-delimited JSON-RPC 2.0 over stdin/stdout, explicit methods and typed errors |

Accessibility is a cross-cutting fourth invariant: keyboard/screen-reader users, automation, and agents must receive equivalent semantic access to consequential state and actions. See `ACCESSIBILITY.md`.

All three shells reuse:
- the same local SIWC credential store;
- the same Responses implementation;
- the same bundled Codex app-server runtime;
- the same capability/authority boundaries;
- the same platform-specific adapters.

Interactive OAuth remains a human authorization boundary. After authorization, automation and agents may use the saved local grant according to its scopes.

## Automation CLI

Every successful command writes one JSON object to stdout.

Common commands:

\`\`\`text
SupraChat.Automation capabilities
SupraChat.Automation doctor
SupraChat.Automation auth-status
SupraChat.Automation models
SupraChat.Automation respond --model <id> --input <text> [--web-search]
SupraChat.Automation responses-raw --model <id> [--body <json>]
SupraChat.Automation codex-rpc --method <method> [--params <json>]
SupraChat.Automation stdio
\`\`\`

For \`responses-raw\`, JSON may be supplied on stdin when \`--body\` is omitted.

Exit codes:
- \`0\`: success;
- \`2\`: usage / invalid parameters / unsupported machine method;
- \`3\`: local authorization or ChatGPT-plan scope required;
- \`4\`: runtime/upstream execution failure.

Credential/token values are never emitted.

## Agent stdio protocol

Start:

\`\`\`text
SupraChat.Automation stdio
\`\`\`

Each stdin line is one JSON-RPC 2.0 request. Each stdout line is one JSON-RPC 2.0 response.

Current methods:
- \`capabilities/read\`
- \`doctor/read\`
- \`auth/status\`
- \`models/list\`
- \`responses/create\`
- \`responses/raw\`
- \`codex/request\`

Example:

\`\`\`json
{"jsonrpc":"2.0","id":1,"method":"capabilities/read"}
\`\`\`

Typed error example:

\`\`\`json
{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"No local ChatGPT authorization is available.","data":{"type":"AUTH_REQUIRED"}}}
\`\`\`

The machine protocol deliberately does not auto-approve Codex server requests, bypass interactive consent, or manufacture authority. Agent capability and agent authority remain separate.

## Platform UX/DX

### Windows

Human:
- Start Menu entry;
- optional Desktop shortcut;
- Alt+Space companion summon/toggle;
- \`suprachat://\` protocol;
- Open With integration for Agent Lab attachment types;
- Add/Remove Programs uninstall.

Automation/agent:
- installed \`SupraChat.Automation.exe\`;
- installer exposes a command shim / PATH entry when qualified;
- same stdio JSON-RPC surface as other platforms.

### macOS

Human target:
- normal \`SupraChat.app\` application bundle;
- \`suprachat://\` URL handling;
- Finder/open-file integration where supported.

Automation/agent:
- packaged \`SupraChat.Automation\` binary;
- user-installable command shim;
- same stdio JSON-RPC contract.

### Linux

Human target:
- per-user desktop entry;
- \`x-scheme-handler/suprachat\`;
- supported file/MIME association where qualified.

Automation/agent:
- \`~/.local/bin/suprachat\` command for the automation shell;
- GUI command remains separately addressable;
- same stdio JSON-RPC contract.

## DX rules

1. Human-readable UX must never be the only way to inspect a capability.
2. Machine-readable output must never require scraping GUI text.
3. Agent integration must not require shell-screen scraping or hidden browser cookies.
4. Every feature added to the core should answer: how does a human discover it, how does automation invoke/inspect it, and how does an agent invoke/inspect it?
5. When an interaction is intrinsically human (OAuth consent, destructive approval, sensitive permission), machine shells return a typed boundary state instead of bypassing it.
6. Machine schemas are versioned. Breaking changes require a new schema/method version rather than silent reinterpretation.
7. CI qualifies all three audience shells on every packaged desktop target.


## Accessibility parity

Every capability review must record four access paths, not three:
- human GUI;
- accessible human GUI (keyboard + assistive technology semantics);
- automation JSON;
- agent JSON-RPC.

A control that exists only visually is incomplete. A machine method with no discoverable human/accessibility equivalent is also incomplete unless it is intentionally machine-only and documented as such.

Stable Avalonia automation IDs are part of the product contract because they serve both assistive technology and UI-automation qualification. Dynamic status must be exposed through live regions and structured machine state rather than color or position alone.
