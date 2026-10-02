# FRITZ E2 ctlmgr runtime probe

This is the first executable E2 service-process probe after E2-D0 narrowed the
Web/auth topology.

The exact shipped `/usr/bin/ctlmgr` is executed under the already-qualified
`qemu-mips-static -cpu 24KEc` profile, but with stronger containment than
E0/E1:

- extracted firmware root as a filesystem chroot;
- fresh mount namespace;
- fresh PID namespace;
- fresh network namespace;
- loopback as the only network interface;
- no default route;
- namespace-local procfs;
- only null/zero/random/urandom pseudo-devices exposed.

No FRITZ-specific runtime shim is added. The first rep is intentionally allowed
to fail.

Durable evidence is limited to:
- target/candidate identity;
- process survival/exit classification;
- listener TCP ports and Unix socket paths;
- bounded HTTP/HTTPS attempts to `/login_sid.lua?version=2` on observed
  loopback listeners;
- response byte counts and fixed XML-schema marker booleans;
- missing absolute guest paths mechanically recovered from ephemeral QEMU
  strace.

Raw stdout, stderr, strace, response bodies, firmware, rootfs, and target
binaries are never uploaded.

Private product authority: `SemperSupra/fritzbox-automation-private#72`.
