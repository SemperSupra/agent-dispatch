# R27-E14 — Read-only adoption inventory

This manifest is a **review inventory**, not GitHub's live ancestry graph. All head SHAs are immutable snapshots from the checked R27 H20/H21/H22/H23 and E12/E13 draft PRs. `parent` represents the intended qualifying workcell chain; actual Git merge-base and differential file overlap must be independently rechecked before a reviewed integration branch is created.

No merge, force-push, branch deletion, issue closure, promotion or production operation occurs.

The separate reviewer must establish:
- entire open USB Fabric PR census; identify overlap with R25 Pi USB/IP and Peripheral Plugboard workcells, classify carry/critic/defer
- exact GitHub branch ancestry and merge-base for all selected carries
- one immutable RC head built only after source ownership and all red evidence are reviewed
- negative H7 raw-QMP bypass, H24 inherited-FD RED and partial H9 unlink mitigation preserved
- actual integrated G0–G5 guest/QMP/USB packet capture, audit, CLI and crash recovery evidence, then owner approval.

All draft tests can remain green while the release is still blocked.
