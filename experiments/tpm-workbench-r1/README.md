# TPM Workbench R1 — TPM command observability (test-only)

Authority: [private DLE #490](https://github.com/mark-e-deyoung/infrastructure-as-code-private/issues/490). Reuse public QEMU/swtpm feasibility and host quote precedents (#859, #874); do not duplicate the emulator or TPM crypto.

## Qualified by source and local development test, not yet free-tier CI

`go test ./...` in this directory validates TPM2 header interpretation, strictly matched request/response pairing, rejection of incorrect lengths/tags, orphan and overlapping requests, and backwards timestamps. `cmd/tpmtrace` emits redacted JSONL to humans, automation and agents.

```sh
printf 'request 80010000000a0000017b\nresponse 80010000000a00000000\n' | go run ./cmd/tpmtrace
```

This CLI consumes *annotated raw TPM2 wire messages*, NOT pcapng and NOT QEMU guest/process context. Payloads are not emitted. The word `UNKNOWN` is mandatory for guest caller attribution without independent evidence. Do not use output timestamp deltas as calibrated TPM hardware latency: the CLI currently timestamps ingestion, not the original wire event.

## Native upstream capture first

- swtpm >=0.11 `--pcap file=...` emits real TPM command/response exchange in pcapng suitable for Wireshark; detect the `cmdarg-pcap` capability and verify size and capture continuity. swtpm may **silently ignore capture write errors**. Capture presence is not capture completeness.
- For older swtpm, `--log file=...,level=20` is possible but may contain plaintext TPM data; do not publish logs. A host-side Go TPM proxy exists upstream (CyberDefenseInstitute/tpmproxy), but do not put a bespoke proxy into MVP without a demonstrated gap.
- Native pcap provenance must include VM ID/epoch, swtpm and libtpms versions, clock source, source commit, payload policy, and command count (when accurately measurable). Do not confuse internal startup commands with guest-issued commands.

## Sensor workcells (independent)

A. TPM2 headers and native swtpm capture; malformed/truncated/unpaired critics.
B. QEMU TPM frontend and backend tracepoints, QMP query-tpm and TIS/CRB MMIO; capture explicit guest command submit/return, reset, locality and TCG/KVM mode.
C. libtpms `TPMLIB_Process`, state callbacks and persistence; experiment-only snapshot/mutation/fault hooks, never production state.
D. Guest OS context: Linux task/mm/current CR3 and Windows EPROCESS/ETHREAD/TBS/CNG using **version-qualified symbols and address-space evidence**. Timestamps alone do not prove process attribution. Guest memory and secrets stay private; no public CI trace dumps.
E. Performance/security/compliance: command timing decomposition, backpressure, drops and trace overhead; fail closed on unsupported sensors. Test-only PCR/NV/quote/rollback.
F. Shared UI/API/agent event schema: one immutable event ID per boundary, joins by VM epoch + operation ID + time uncertainty, calibrated confidence and source link. No separate semantic implementations for each audience.

## Nonclaims and gates

- Host swtpm commands are NOT in-guest TPM calls; software TPM is NOT hardware-rooted trust.
- No implementation yet of TCG plugin, KVM guest memory introspection, OS process attribution, native PCAP ingestion, live proxy, state mutation, or human UI.
- Failures are RED/UNKNOWN, not PASS. Preserve no-secrets, no host TPM, disposable labs, public/free runner and no-auto-merge requirements. Parent USB security-critical path must not be blocked.

Prior art: https://www.qemu.org/docs/master/specs/tpm.html ; https://www.qemu.org/docs/master/devel/tcg-plugins.html ; https://github.com/stefanberger/swtpm ; https://github.com/CyberDefenseInstitute/tpmproxy .
