# Workcell G — TPM-guided guest-memory provenance

Private DLE [#490](https://github.com/mark-e-deyoung/infrastructure-as-code-private/issues/490); public draft [#882](https://github.com/SemperSupra/agent-dispatch/pull/882). This is an additive independent lane, NOT guest memory introspection or a complete process-level trace.

## Implemented, host-only synthetic fixture
- The Go package exposes `FindExactMemoryMatches` on known lab-synthetic probes and bounded physical-memory regions. Returns a stable VM/epoch/snapshot/region scope, physical offset, exact-match evidence, and explicit UNKNOWN caller/use status.
- Never returns/logs matching bytes or a hash of the key. Private sensitive buffers are never CI artifacts.
- Rejects short/oversized probes, duplicate identifiers, malformed regions, address overflow, partial overflow reports and cross-VM/boot-epoch confusion.
- Tests cover two copies of a 32-byte synthetic value, a near-miss, VM/epoch mismatches, invalid inputs, and JSON redaction. Runs in stdlib Go on public/free CI.

## Not implemented and not established
- No live QEMU RAM read, VMI page-table translation, Windows or Linux task attribution, key derivation, secret access tracing, API stack correlation, zeroization inference or temporal tracking.
- Raw byte equality does not demonstrate active key use. Raw non-exportable TPM private keys should not appear in guest memory; TPM unsealed outputs may.
- A memory snapshot with no hit is only `NOT_OBSERVED_IN_SNAPSHOT`, not a key-isolation proof.

## Required next independent workcells
1. Bind native QEMU TPM command request IDs (guest source vs emulator internal), actual physical TPM DMA/MMIO buffers, and a verified guest-memory snapshot epoch; no implicit trust in wall clock alone.
2. Map GPA->GVA via exact guest page tables; attach OS symbol-profile hashes, process creation epoch, PID/TID, call stack and OS service context when independent evidence exists. Distinguish TCG and KVM support.
3. Controlled lineage: unseal secret, GetRandom output, NV read, TPM public key, PCR value; track exact value, UTF-16/base64 **known** encodings, explicit KDF transformations, allocations/copied/scrubbed buffers, swaps and remaps; never conflate derived BitLocker VMK/FVEK with TPM blob byte equality.
4. Compare cold/warm/reset and process lifecycle snapshots with read/write traps for live use evidence; ensure observation perturbation overhead is measured and capture/drop completeness graded.
5. Add red-team test: known secret in one VM but false attribution to sibling VM or a stale boot epoch MUST be denied; zeroized buffer must disappear at later snapshot without claiming that no copy remains.
6. Add a minimal human evidence timeline, stable JSON/CLI, agent tool contracts to the same typed event graph; provenance and uncertainty are mandatory.

Reference: QEMU QMP `dump-guest-memory`, QEMU TCG plugin memory callbacks, LibVMI Windows/Linux symbol support, swtpm/libtpms, and upstream Windows BitLocker VMK/FVEK documentation. No bespoke TPM crypto, no private material in public CI, no production guest mutation.
