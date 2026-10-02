# FRITZ QEMU userspace probe

This public-safe experiment exercises an exact publicly downloadable FRITZ!OS
firmware image without publishing the proprietary image or extracted filesystem.

The first ladder is intentionally narrow:

1. **E0** — require the exact byte length and SHA-256, extract the outer image
   and embedded SquashFS, and derive the shipped ELF ABI from evidence.
2. **E1** — select a harmless shipped executable and run it under the QEMU user
   emulator implied by the observed MIPS endianness.

A successful E1 result means only that a real shipped userspace executable can
run under foreign-architecture QEMU on the GitHub-hosted Linux runner. It does
**not** claim full FRITZ!Box 7590/GRX550 system emulation and does not replace a
real router as behavioral authority.

## Safety boundary

- The firmware is downloaded into `RUNNER_TEMP` and digest-pinned before use.
- The extracted filesystem remains in `RUNNER_TEMP` only.
- No firmware, root filesystem, executable, Web UI source, credential, or
  private topology is uploaded.
- The only workflow artifact is a sanitized JSON receipt containing hashes
  already used as public target identity, counts, ELF metadata, selected path
  names, and exit/oracle state.
- E0/E1 contact no physical router and authorize no router mutation.

Private interpretation and acceptance for the FRITZ workstream remains in
`SemperSupra/fritzbox-automation-private#71`.
