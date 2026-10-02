# FRITZ E2 supervisor discovery

E2-R0 proved that direct no-argument execution of the exact shipped
`/usr/bin/ctlmgr` exits normally without creating a listener.

This E2-D1 slice therefore recovers the exact FRITZ!OS 8.25 supervisor/startup
surface before any second launch attempt.

Durable output is limited to:

- paths containing fixed markers `ctlmgr`, `svctl`, or `supervisor`;
- path-marker and content-marker booleans;
- strict mechanically recognized relations such as
  `svctl -> start -> ctlmgr`;
- ctlmgr/svctl/supervisor-related symlink path/target metadata;
- ELF metadata and DT_NEEDED library names for marker-bearing binaries.

Raw init/service scripts, arbitrary strings, firmware/rootfs bytes, and binary
payloads are not published.

Community Freetz evidence is used only as a prior; this exact 8.25 receipt is
the target-specific authority for the next launch mechanism.

Private product authority: `SemperSupra/fritzbox-automation-private#72`.
