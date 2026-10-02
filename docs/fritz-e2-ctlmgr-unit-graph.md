# FRITZ E2 ctlmgr unit graph

This D3 slice reduces exact `/lib/systemd/system/ctlmgr.service` and reverse
unit references into standard service-manager metadata only.

Allowed durable fields:
- unit names and dependency keys;
- service type from a fixed generic allowlist;
- ExecStart/Pre/Post executable path plus sanitized argv shape;
- EnvironmentFile/PIDFile absolute paths;
- unit/symlink references that admit ctlmgr.service;
- candidate target units justified by those references.

Raw unit-file text and arbitrary literal values are never emitted.

The resulting candidate target is used only to design the next isolated
supervisor runtime falsification rep.

Private product authority: `SemperSupra/fritzbox-automation-private#72`.
