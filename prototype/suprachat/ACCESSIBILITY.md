# SupraChat accessibility contract

Evidence/design date: 2026-10-01.

Accessibility is a product invariant across the human, automation, and agent shells. It is not a separate edition or a Windows-only feature.

## Human UI contract

Every packaged desktop target must preserve:

- complete keyboard reachability for all consequential controls;
- stable `AutomationProperties.AutomationId` values for UI automation and assistive technology;
- explicit accessible names/help text where visible text alone is ambiguous;
- semantic headings for major sections;
- labeled input controls;
- polite/assertive live regions for changing status that would otherwise be visual-only;
- textual status/error/result output so state is never conveyed by color alone;
- system light/dark/high-contrast theme following through Avalonia's platform settings;
- platform DPI/render scaling without fixed-pixel-only interaction assumptions;
- no required pointer-only gesture;
- no custom motion that is required to understand or operate the product;
- persistent native WebView/product state without disabling browser/web accessibility support;
- a clearly labeled **Open in browser** fallback when a platform/browser combination exposes a stronger assistive-technology experience outside the embedded WebView.

Keyboard baseline:

- macOS: `Command+1`, `Command+2`, `Command+3`, `Command+L`;
- Windows/Linux: `Control+1`, `Control+2`, `Control+3`, `Control+L`;
- the actions are identical: ChatGPT tab, Agent Lab, Automation & Agents, and focus interview input.
- standard Tab / Shift+Tab, arrow-key, Enter/Space, text-selection and platform accessibility navigation remain primary.

The Windows `Alt+Space` companion shortcut is additive and must never be the only way to summon the application.

## Automation accessibility / DX contract

Automation clients must not need screen coordinates, OCR, color interpretation, or GUI text scraping.

- deterministic JSON output;
- stable schemas and exit codes;
- typed authorization/permission boundary states;
- `capabilities` and `accessibility` commands expose machine-readable parity metadata;
- all consequential human-visible state that machines need is also available through a structured command/RPC;
- stdout remains machine data; stderr remains diagnostics.

## Agent accessibility / protocol contract

Agents use line-delimited JSON-RPC 2.0 over stdio rather than desktop UI automation.

- `accessibility/read` returns the same accessibility contract used by the GUI/CLI;
- methods and errors are semantic, not screen-position dependent;
- server-initiated Codex approvals remain explicit and are never auto-approved for convenience;
- agents may assist a user who relies on accessibility features without taking over consent boundaries.

## Platform expectations

### Windows

- UI Automation semantics through Avalonia automation peers;
- Windows high-contrast preference is inherited through Avalonia platform settings;
- keyboard-only install/run/use/uninstall path;
- Start Menu, protocol, Open With and companion shortcut remain additive access paths.

### macOS

- native accessibility tree through Avalonia/macOS automation support;
- system light/dark/high-contrast appearance is inherited;
- normal app bundle, URL/file opening, GUI and CLI entry points.

### Linux

- Avalonia accessibility semantics must remain present on supported desktop backends;
- keyboard-only operation;
- desktop entry, URL handler, GUI and CLI entry points;
- no assumption that one specific compositor/input stack is required for core operation.

## Qualification rule

A feature is not considered cross-audience complete until its parity ledger answers:

1. how a human discovers and operates it;
2. how a keyboard/screen-reader user discovers and operates it;
3. how automation inspects/invokes it;
4. how an agent inspects/invokes it;
5. what human authorization or permission boundary remains.

Accessibility regressions are qualification failures, not documentation debt.


## User-adjustable preferences

SupraChat stores non-secret accessibility preferences per user in the normal application-state directory and exposes the same values through every audience shell.

Current preferences:

- native SupraChat interface/text scale from 80% through 200%, in 10% steps;
- reduced-motion preference for SupraChat-owned interface effects.

Human GUI:

- **Smaller text**, **Reset text size**, and **Larger text** controls in the Accessibility section;
- **Reduce motion** checkbox;
- keyboard scale shortcuts: Command/Ctrl + `+`, `-`, and `0`;
- a live semantic status line announces the effective scale and reduced-motion state.

Automation:

```text
suprachat-cli accessibility-preferences
suprachat-cli accessibility-set --scale 1.5 --reduced-motion true
```

Agent JSON-RPC:

```json
{"jsonrpc":"2.0","id":1,"method":"accessibility/preferences/read"}
{"jsonrpc":"2.0","id":2,"method":"accessibility/preferences/write","params":{"interface_scale":1.5,"reduced_motion":true}}
```

The native interface scale is independent of the embedded first-party ChatGPT web content. Users who need stronger browser/WebView zoom or assistive-technology behavior retain the clearly labeled system-browser fallback.