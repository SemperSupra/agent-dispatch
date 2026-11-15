# Buildroot minimal read-only rootfs — experimental, not production-signed
Pinned upstream stable: `2026.08.1`, SHA256 of upstream `.tar.xz`:
`34fb7bea8a213ffde39cc02e61703391560f26e0850f03138c722d0b09880f2b`.

**Core:** BusyBox init, musl libc, Dropbear **server only**, /var/log+/run+/tmp tmpfs,
no automatic SSH host-key generation, no package manager, no VM/QEMU/Docker,
no Python, no browser, no GPU tooling and no runtime eMMC logs.
The Dropbear service is deliberately disabled until a *node-specific* host key
and authorized operator key are verified and populated under /run/wyse-keys.
The actual production implementation must supply the Go recoverd/TPM/signed
policy/verity/UEFI boot chain before any node release: this is a measured,
not-signed rootfs build fixture.

Build (only in a disposable sandbox):
```sh
export BR2_EXTERNAL="${PWD}/tools/wyse-buildroot"
make -C /path/to/buildroot O="$PWD/br-output" \
    BR2_EXTERNAL="$BR2_EXTERNAL" wyse_minimal_defconfig
make -C /path/to/buildroot O="$PWD/br-output" -j4
```
**Never** flash rootfs to real eMMC/SSD from this source-only artifact.
