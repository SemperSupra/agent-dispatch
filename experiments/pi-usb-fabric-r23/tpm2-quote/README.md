# R23-C — TPM2 quote tests in a disposable *host userspace* swtpm

DLE #482, parent #477 / #476. Reuses standard Debian `swtpm`, `tpm2-tools` and `tcti-swtpm`, no bespoke TPM crypto. Public/free CI uses nonroot Docker, no external network, no host TPM/kernel modules or secrets.

The test starts a software TPM2 over container-local loopback, executes TPM2_GetRandom, reads sha256 PCRs, creates disposable EK/AK, generates a PCR quote under a random nonce, verifies via upstream `tpm2_checkquote`, and demands rejection on wrong nonce/altered PCR bytes. Archive emits only public/limited markers; fresh throwaway state and keys destroyed by container cleanup.

**Trust classification:** host-side software TPM simulator. Even a passing quote does not prove independently enrolled guest identity, trusted hardware root, actual guest `/dev/tpm0`, guest-owned vTPM secret isolation, or Ed25519 TPM key custody. The next phase is an actual QEMU boot with guest TPM driver + quote and attacker/rollback critics. Do not block P0 security work or promote to production.
