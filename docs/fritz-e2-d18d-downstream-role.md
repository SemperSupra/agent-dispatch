# FRITZ E2-D18d downstream observation-role reconciliation

Authority: `SemperSupra/fritzbox-automation-private#72`.

D18c returned a typed negative for the current sanitized caller-side argument dimensions. D18d does not add another runtime probe. It first reconciles what the existing debugger actually observes and whether accepted static evidence has earned a downstream role.

The D18 locator breaks at the selected `jalr t9` callsite in `/bin/svctl`; this is a caller-side PIC callsite before callee entry, not a function-entry breakpoint.

Accepted D13/D14 topology independently provides:
- `_svctl_init -> _svctl_send -> send`;
- `_svctl_send_pkt -> _svctl_send -> send`.

If those exact edges reproduce, D18d qualifies the shared `_svctl_send` entry/send-boundary argument role as the next mechanically earned runtime observation point. It does not claim a verb discriminator, packet field, enum, offset, or payload layout.
