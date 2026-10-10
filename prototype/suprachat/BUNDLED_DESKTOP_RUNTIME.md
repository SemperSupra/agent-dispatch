# Bundled desktop runtime decomposition

Evidence date: 2026-10-01.

Authority:
- campaign: `SemperSupra/agent-dispatch-private#425`
- decomposition: `SemperSupra/connected-device-recovery-private#65`
- Linux recovery: CDR-private #63 / public CDR #12/#15
- macOS recovery: CDR-private #62 / public CDR #13/#16
- Windows recovery: CDR-private #59 / public CDR #11
- upstream source oracle: `openai/codex`

## Finding

The unified ChatGPT desktop runtime is a **superset host around Codex**, not merely a renamed standalone CLI.

The open-source Codex repository already contains the generic machinery for:
- app-server / JSON-RPC;
- plugin marketplaces and the `openai-bundled` marketplace class;
- skills, hooks, MCP and plugin lifecycle;
- CUA-aware review/Guardian behavior;
- remote-control protocol;
- desktop/local user-verification RPCs;
- filesystem/process/shell/environment operations;
- browser/CUA MCP routing.

The desktop distribution supplies concrete product/runtime payloads that activate and extend that machinery:
- a version-pinned bundled Codex executable;
- the OpenAI bundled plugin marketplace;
- local CUA/Sky runtime;
- Playwright/browser automation payloads;
- native OS integration modules;
- Chromium/Electron product shell and app state;
- browser-extension/peer integration;
- GUI permission/approval/authentication handlers;
- product-specific plugins and data.

Current external evidence reports desktop generation `26.928.31416` using bundled `codex-cli 0.159.2`, while public standalone Codex has already advanced to `0.159.3`. Therefore the application pins its backend independently of the standalone update channel. CDR #65 is performing byte/hash comparison against the matching public release where available.

## Recovered component families

### 1. Codex core/runtime

Observed:
- `resources/codex` / `codex-cli`;
- `codex-code-mode-host`;
- app-server protocol;
- plugin/skills/MCP/remote-control/account/thread/turn surfaces.

Disposition: **REUSE_UPSTREAM_OSS**.

SupraChat should package an exact, verified open-source Codex release and use app-server as the primary local agent/runtime API. Product-specific binary differences are evidence, not source to copy.

### 2. OpenAI bundled plugin marketplace

Common to recovered unified Linux/macOS:
- `browser`
- `chrome`
- `code-review`
- `codex-app-tools`
- `deep-research`
- `latex`
- `unified-computer-use`
- `visualize`

Additional recovered macOS plugins:
- `computer-history`
- `computer-use`
- `messages`
- `record-and-replay`

Upstream Codex source explicitly knows `openai-bundled`, bundled cleanup hooks, plugin cache/marketplace synchronization, and discovery of bundled Chrome/Computer Use plugins.

Disposition:
- plugin framework/schema: **REUSE_UPSTREAM_OSS**
- plugin manifests/interfaces: **ORACLE -> CLEAN_ROOM_SPEC**
- plugin implementations with no published source: **CLEAN_ROOM_REIMPLEMENT**
- public/OSS dependencies inside plugin packages: **REACQUIRE_UPSTREAM**, never copy from proprietary app package.

### 3. CUA / Sky runtime

Recovered examples:
- `cua_node/bin/node`
- `@oai/cua`
- `@oai/sky`
- `sky_linux_x64` and architecture variants
- `cua_repl` integration
- image/native dependencies such as Sharp
- local LevelDB/classic-level state

Disposition: **HYBRID**.

Use the public Codex CUA/MCP protocol and safety/approval semantics as the compatibility contract. Reacquire public dependencies upstream. Treat unpublished `@oai/*` implementation bodies as oracle material and replace them with independently implemented adapters.

### 4. Playwright/browser runtime

Recovered:
- full `playwright-core` package;
- browser registry;
- Chromium/BiDi/CDP/client/server/recorder/download/tracing/input machinery;
- browser plugin;
- Chrome plugin;
- browser peer authorization native module on macOS;
- Chromium/Electron runtime resources.

Disposition:
- Playwright: **REUSE_UPSTREAM_OSS**
- browser automation adapter: **CLEAN_ROOM_REIMPLEMENT around Playwright**
- product browser state/security/permission behavior: **ORACLE -> BEHAVIORAL_TESTS**
- Chrome-extension integration: **SUPPORTED EXTENSION/API BINDING where available; otherwise clean-room adapter**.

### 5. Native desktop integration modules

Recovered Linux examples:
- `hid-topology-watcher.node`
- `remote-control-device-key.node`
- `pty.node`
- `serial_control.node`
- filesystem watcher
- SQLite/LevelDB/native image libraries

Additional macOS examples:
- `browser-use-peer-authorization.node`
- `input-monitoring-permission.node`
- `devicecheck.node`
- `usb_webauthn.node`
- `permissions.node`
- `airpods-mute.node`
- `sparkle.node`
- `sky.node`

Disposition: **OS_ADAPTER_REIMPLEMENT** unless an upstream public package/source is positively identified.

For each module CDR #65 records ABI, imports/dependencies, hashes, architecture and the calling/plugin context. Reimplementation should target the observable interface and supported OS APIs, not decompiled source reuse.

### 6. Electron/Chromium application shell

Recovered:
- `app.asar`;
- `app.asar.unpacked`;
- Chromium PAK/locales/GPU libraries;
- Electron/native Node modules;
- application metadata and desktop integration.

Disposition:
- Electron/Chromium: **REUSE_UPSTREAM_OSS or retain Avalonia/WebView where functionally superior**
- product application code inside ASAR: **ORACLE_ONLY**
- ASAR file/module tree, package metadata, interface names and behavior: **CLEAN_ROOM_SPEC INPUT**.

CDR transiently extracts ASAR for analysis but public evidence retains only paths, hashes and normalized manifests.

### 7. Product-specific host services

Observed/inferred from package + open-source app-server:
- plugin marketplace synchronization into Codex home;
- local browser/CUA process lifecycle;
- host-owned MCP services;
- desktop/native user verification;
- remote-control device identity;
- application permission brokerage;
- app-specific account/session and product-mode switching;
- Work/Codex/Chat routing;
- crash/update lifecycle.

Disposition: **CLEAN_ROOM_HOST IMPLEMENTATION** using public Codex/app-server/plugin contracts and native OS APIs.

## Extraction outputs required by CDR #65

For every recovered package/bundle:
- complete compressed NDJSON file inventory: path, size, SHA-256, component tags;
- component-level manifest digest;
- every `package.json`: normalized name/version/license/dependencies/entry points;
- every `.codex-plugin/plugin.json`: normalized schema/capability metadata;
- every `.mcp.json`: server names, command basename, arg count, environment-key names and URL host only;
- Playwright `browsers.json`: browser names/revisions/default status;
- native `.node` modules: SHA-256, architecture/type and imported libraries;
- license-file inventory/hashes;
- bundled executables: version probe/hash/size;
- ASAR container hash plus transient extraction census;
- bundled-vs-standalone Codex comparison.

Proprietary source bodies and package bytes are not durable public outputs.

## Reimplementation order

1. **Codex parity substrate** — package pinned upstream Codex and expose the full app-server protocol.
2. **Plugin substrate** — use Codex's native marketplace/plugin APIs; create a SemperSupra-compatible marketplace rather than cloning OpenAI's proprietary plugin bodies.
3. **Browser** — Playwright-backed browser runtime + browser state/permission model.
4. **Computer Use** — CUA-compatible MCP surface backed by platform capture/input adapters and explicit approval.
5. **Native host** — HID topology, PTY, permission checks, secure device identity, WebAuthn/biometric verification, remote-control host.
6. **Product plugins** — implement clean-room equivalents one by one from normalized contracts and black-box behavioral tests.
7. **Cross-platform qualification** — Windows primary; Linux/macOS use the same interfaces with platform-specific implementations.
8. **Negative-space qualification** — preserve packaged-but-disabled capability distinctions (for example Linux packages may contain Computer Use assets even when product enablement is off).

## Invariant

**Capability presence, code presence, product enablement and authority are four separate facts.**

A packaged plugin or method is not proof that a user is entitled to it, that the host exposes it, or that SupraChat should invoke it automatically.
