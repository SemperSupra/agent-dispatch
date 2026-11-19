# R23-C — TPM2 quote tests in a disposable *host userspace* swtpm

DLE #482, parent #477 / #476. Reuses standard Debian `swtpm`, `tpm2-tools` and `tcti-swtpm`, no bespoke TPM crypto. Public/free CI uses nonroot Docker, no external network, no host TPM/kernel modules or secrets.

The test starts a software TPM2 over paired Unix data/control sockets (`swtpm.sock` and `swtpm.sock.ctrl`), executes TPM2_GetRandom, reads sha256 PCRs, creates disposable EK/AK, generates a PCR quote under a random nonce, verifies via upstream `tpm2_checkquote`, and demands rejection on wrong nonce, a **real PCR extend followed by independent re-read**, a swapped PCR-selection header, and an altered quote signature. An earlier arbitrary serialized-file trailing-byte flip was accepted; this did not establish a TPM security vulnerability because that byte was not verified to represent a measured PCR value. The follow-on semantic PCR critics passed with upstream Debian `tpm2-tools 5.7-1`. Archive emits only public/limited markers; fresh throwaway state and keys destroyed by container cleanup.

**Trust classification:** host-side software TPM simulator. Even a passing quote does not prove independently enrolled guest identity, trusted hardware root, actual guest `/dev/tpm0`, guest-owned vTPM secret isolation, or Ed25519 TPM key custody. The next phase is an actual QEMU boot with guest TPM driver + quote and attacker/rollback critics. Do not block P0 security work or promote to production.

## Durable qualification receipts (test-only)

- Initial RED `44554619152`: inaccessible TCP TCTI under `--network none`; retained.
- Second RED `44555097992`: Unix control socket filename mismatch; retained.
- Third RED `44555514616`: transient TPM context exhaustion `0x902` when creating quote; retained.
- Fourth RED `44556104974`: overly ambiguous trailing-byte PCR mutation was accepted; not proof of a security defect; retained.
- First qualified host-side green `44556932606` (job `135675403542`, head `c642c55cf6787a89919688308536f0b2f6018067`): actual GetRandom, PCR read, signed quote, nonce rejection, semantic PCR-change rejection, selection-swap rejection, signature tamper rejection. Artifact `14544608906`, archive SHA256 `c8ee727c28d16cd16b88bb190da1bfb0882a81bf2a71035b9d60d87ded93449d`.

Always preserve `R23_C_TPM2_QUOTE_IN_GUEST=NOT_TESTED` and independently verify CI run, SHA and job before promoting a later change.
