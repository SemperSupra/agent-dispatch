# FRITZ M1 — observability-only emulator overlay

Private architecture authority: `SemperSupra/fritzbox-automation-private#73`.

M1 proves the smallest modified-emulator mechanism without creating a forked
firmware distribution.

The workflow:

1. downloads and verifies the exact stock FRITZ!OS 8.25 image;
2. extracts one ephemeral root;
3. applies a declarative overlay whose destinations are restricted to
   `/opt/supra/**`;
4. refuses to replace any pre-existing target path;
5. adds one public helper:
   `/opt/supra/bin/observe-supervisor`;
6. executes that helper explicitly with the already-qualified MIPS qemu-user
   profile;
7. uploads only a sanitized receipt and lets the derived root disappear with
   the runner.

The helper only reports whether the known supervisor control-socket path is a
Unix socket. It does not start a service, modify AVM state, contact a router, or
replace a shipped binary.

The QEMU static executable copied into the root is harness scaffolding, not part
of overlay identity.

This establishes the transformation/receipt contract needed for later
instrumentation and evidence-earned dependency fixtures while the exact stock
image remains the behavioral oracle.
