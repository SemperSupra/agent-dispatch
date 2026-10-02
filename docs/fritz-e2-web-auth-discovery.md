# FRITZ E2 Web/auth discovery

This experiment is the first E2 discovery rung for the exact FRITZ!Box 7590 /
FRITZ!OS 8.25 image.

It does not launch a service and does not claim a complete Web stack. It
narrows the next runtime target from evidence by emitting only:

- exact target hash/size identity;
- file paths;
- ELF metadata and interpreter paths;
- DT_NEEDED library names;
- booleans for a fixed marker set (`login_sid.lua`, `data.lua`,
  `/webservices/`);
- mechanically derived init-file-to-candidate references.

It deliberately does not emit arbitrary strings, script/source contents, Web
UI source/body, firmware/rootfs bytes, or private router observations.

The resulting candidate ordering is mechanical and non-authoritative:
fixed-marker evidence outranks init references, which outrank path-token
evidence. Runtime evidence is required before any service is accepted as part
of the minimum constellation.

Private product authority remains
`SemperSupra/fritzbox-automation-private#72`.
