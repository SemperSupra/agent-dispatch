# GitHub-hosted runner environment census V2

Authority: \`SemperSupra/agent-dispatch-private#400\`.

This is a drift/environment-model annex over the prior substrate work. It does
not replace the accepted evidence in private issues #78, #223, #281/#283 or the
public latent-hardware implementation.

## What V2 adds

- refreshes the current standard/free public runner labels across Ubuntu,
  Windows and macOS;
- makes Windows first-class in the shared \`github-runner-capability/v1\`
  receipt;
- records execution model separately from operating-system label;
- adds bounded loopback and filesystem semantic oracles;
- improves selected resource, privilege, container/virtualization, print-stack
  and toolchain observations without dumping host/environment identifiers;
- adds host-vs-job-container-vs-service-container evidence;
- adds a non-scalar receipt diff that preserves oracle regressions separately
  from image/resource drift.

## Native-label sweep

The workflow intentionally uses explicit OS/version labels instead of
\`*-latest\` aliases:

- Ubuntu 22.04/24.04/26.04 x64 and arm64 plus \`ubuntu-slim\`;
- Windows Server 2022/2025, the VS2026 image alias, and Windows 11 arm64 with
  and without the VS2026 image;
- macOS 14/15/26 across available arm64/Intel labels plus \`xcode-27\`.

Deprecated/preview labels remain evidence-bearing but must not become new
long-lived placement dependencies merely because the census can still run them.

## Evidence classes

Keep these distinct:

1. GitHub native host/VM;
2. GitHub shared container (\`ubuntu-slim\`);
3. Actions job container;
4. native host with service container;
5. ordinary Docker container primitive;
6. KVM/QEMU or WSL guest;
7. Android/CoreSimulator guest/emulator;
8. future BSD/illumos VM guests and Linux userland containers.

A capability observed in one class is not silently generalized to another.

## Follow-on

After the native V2 sweep is stable:

- reduce against retained #78/#223/#281 receipts;
- add version-pinned userland portability profiles (Debian, Alpine, Fedora,
  RHEL-family compatible images);
- add BSD/illumos guest profiles on the already-qualified x64 KVM lane;
- only promote a resulting fact to placement when a real workset requirement
  consumes it.

No scalar runner score and no automatic placement promotion are introduced.
