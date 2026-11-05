# WRT3200ACM public cloud recovery workcell

This workcell is the zero-incremental-cost execution surface for the WRT3200ACM recovery campaign.

It deliberately separates **public execution** from **private durable mission authority**. The workflow receives no private-repository contents or secrets. It obtains only public artifacts by URL, performs static analysis in the ephemeral GitHub-hosted runner, and uploads derived reports rather than firmware payloads.

## First workcell

`wrt3200acm-cloud-recovery.yml`:

- pins the open `mwlwifi` source to commit `db97edf20fadea2617805006f5230665fadc6a8c`;
- derives a host-command catalog from `hif/hostcmd.h` and `hif/fwcmd.c`;
- downloads OEM/GPL/OpenWrt/radio-firmware inputs by public URL;
- records SHA-256, size, file signature, entropy, magic offsets, bounded strings, and archive listing probes;
- scans radio firmware for known host-command constants and ranks 512-byte windows containing multiple distinct command IDs;
- never uploads the downloaded firmware binaries.

The raw constant scan is intentionally a **candidate generator**, not a semantic conclusion. A match becomes a finding only after independent structural/disassembly evidence.

## Agent Dispatch fit

The task is modeled in the private authority workset as bounded delegations. Until the live Sidecar admits the current browser client to that workset, this PR-triggered public workflow is the execution materialization. It must remain semantically replaceable by a Sidecar-bound public-GHA target; no recovery semantics depend on the PR trigger.

## Qualification use

Natural bounded subtasks (protocol extraction, candidate-window labeling, cross-family comparison, falsification) are suitable actor interviews. Each treatment must record model, harness, configuration, tools, compute substrate, context, and team structure independently. Depth-1 teams only unless recursive delegation is separately qualified.
