# TPM Workbench — cross-boundary observability schema and falsifiers

## A single durable causal graph, not process attribution by proximity

- A native TPM trace event: `vm_id, vm_epoch, backend_id, request_id, tpm_code, locality, start_monotonic_ns, end_monotonic_ns, outcome, evidence_ref, source, status`.
- Guest MMIO event: `vcpu_id, mode, guest_physical_address, guest_virtual_address_if_resolved, host_timestamp, mmio_op, source`.
- Guest OS observation: `os, version, kernel_build, debug_symbol_hash, process_create_epoch, pid, tid, address_space_id, caller_module, kernel_stack_fingerprint, measurement_interval`.
- Join edge: `request_id` only when a tracepoint actually propagates it. Otherwise retain `candidate` with time window, clock error bounds, MMIO register/queue matching, and `verified|correlated|inferred|unknown` confidence.

Never attach the currently running vCPU at swtpm response time as verified origin. TPM2 commands may be mediated, queued or injected by firmware/hypervisor; internal swtpm startup is not a guest call. On Windows, TBS/CNG or BitLocker may submit on behalf of a different application; on Linux, /dev/tpmrm0 multiplexes access.

## Sensor placements

1. Upstream swtpm 0.11 PCAP (or non-public debug log on older versions): ground-truth command/response and operation duration when packet timestamps are verified; redact parameters.
2. QEMU `backends/tpm/tpm_emulator.c` plus TIS/CRB frontend: command origin as physical interface, VM and vCPU IDs when known; QMP `query-tpm` for topology. Existing trace events first.
3. libtpms `TPMLIB_Process` wrappers and storage callbacks: inner execution and persistent mutations; separate original upstream engine from instrumented adversarial build.
4. TCG plugin (when applicable): guest instruction/read/write observation, code location and registers, optional guest virtual/physical memory snapshots under lab ownership. TCG plugin is NOT equivalent to KVM full guest execution tracing.
5. OS-aware VMI/symbol decoders: live or offline guest memory plus WinDbg/PDB (Windows), BTF/DWARF and exact kernel symbols (Linux); symbol/profile mismatch => UNKNOWN.
6. UEFI boot event log, guest OS TPM logs when available, storage and API boundary observations: correlate PCR measurement sequence to OS and firmware lifecycle.

## Adversarial critics

- False process association at TPM response; reject.
- Two overlapping requests or orphan response; reject or mark missing evidence.
- Exit without capture bytes, full filesystem, log truncation, synthetic internal TPM startup mistaken for guest request; reject capture completeness.
- Clock drift and PID/TID reuse; join only with lifecycle epoch and bounded uncertainty.
- Replayed TPM state with identical disk; detect clone identity and disallow attestation-strength promotion.
- Instrumented guest memory evidence accidentally exported to public CI artifact; reject publication.
- Capture-on/off p50/p95/p99 command latency should be reported separately for TCG and KVM, and never inferred from userspace receipt time.

Three audiences receive one typed API; human timeline, automation JSONL/CLI, and agent evidence queries must consume the same events and operation authorization gates.
