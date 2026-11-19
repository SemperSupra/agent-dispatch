# TPM Workbench x Observatory — source-first multilingual concept sweep (2026-11-19)

**Authority:** TPM Workbench [private #490](https://github.com/mark-e-deyoung/infrastructure-as-code-private/issues/490); Observatory shared reversing DLE [ghidra-tools #4](https://github.com/mark-e-deyoung/ghidra-tools/issues/4). **Existing public draft:** [agent-dispatch #882](https://github.com/SemperSupra/agent-dispatch/pull/882). **Status:** RESEARCH/SOURCE-REVIEW ONLY, not proof of interoperability or an implemented Observatory sensor. Observatory #4 has a hygiene-first functional work pause. Do not initiate new Observatory feature branches, deployments or runner dispatch from this note.

## Answer / placement

Do NOT build a new reverse-engineering suite in TPM Workbench. **TPM Workbench owns TPM-specific commands, object semantics, emulator-state inspection and adversarial laboratory adapters. Observatory owns sensor registry, time/address normalization, causal evidence graph, runtime OS context, replay, controlled interventions and common human/API/agent UX.** Agent Dispatch remains execution/resource admission; GitHub DLE is authority. USB Fabric may consume verified TPM evidence but its P0 release gates remain independent and unchanged.

## Global multilingual evidence scan — non-exhaustive

- **Japanese (JA)**: CyberDefenseInstitute describes a real Windows 11/QEMU/swtpm experiment using its [Go tpmproxy](https://io.cyberdefense.jp/entry/tpmproxy-qemu-swtpm/) ([source](https://github.com/CyberDefenseInstitute/tpmproxy)). This is directly reusable code for intercepting the QEMU Unix control channel, proxying command traffic, decoding and deliberate response alteration, not just a concept. Japanese [parallel swtpm tests](https://qiita.com/hyperfinitism/items/fc2b998bcc76e1347edf) note one disposable TPM per test and preference for Unix sockets over TCP port allocation. Confirm deployment license and own tool version.
- **German (DE)**: Microsoft [Measured Boot PCR decoding documentation](https://learn.microsoft.com/de-de/troubleshoot/windows-client/windows-security/decode-measured-boot-logs-to-track-pcr-changes) and [Windows TPM use](https://learn.microsoft.com/de-de/windows/security/hardware-security/tpm/how-windows-uses-the-tpm) tie PCR values to boot evidence, BitLocker and operational recovery. Reference German BSI's SiSyPHus TPM study as a future more formal source-review item, not a validated binary experiment.
- **Chinese (ZH)**: [Virtual TPM design discussion](https://cloud.tencent.com/developer/article/2409982) emphasizes virtual PCRs, migration, trust-base changes, and protection against cross-domain vTPM state leakage; [seL4 TPM interface patent](https://patents.google.com/patent/CN116049844A/zh) describes separation of ordinary TPM requests and privileged update interfaces. Treat patent as architectural disclosure, not independently proven implementation.
- **English (EN)**: upstream QEMU, swtpm, Microsoft TPM reference, PANDA/taint2, LibVMI, DRAKVUF, Keylime and Google's eventlog implementation provide primary code/docs below.
- **French, Russian, Thai, Korean, Spanish/Portuguese** were included in query exploration but returned mainly mirrors/translations or lower-evidence material for the exact QEMU-to-TPM-to-memory causal problem. Do not imply evidence of an independent implementation from a translated result. **Coverage is not exhaustive.** Follow-on native-language source coding search only when a gap cannot be filled by verifiable upstream code.

## Source and integration primitives (read before reimplementing)

| Source and code area | Tested/documented primitive | Reuse decision and limits |
|---|---|---|
| [QEMU TPM backend](https://github.com/qemu/qemu/blob/master/backends/tpm/tpm_emulator.c), [TIS/CRB trace events](https://github.com/qemu/qemu/blob/master/hw/tpm/trace-events), [backend trace events](https://github.com/qemu/qemu/blob/master/backends/tpm/trace-events) | frontend MMIO, locality, command handoff, VM-state and swtpm state blob events | **Reuse first**; raw buffer tracing can leak secrets; does not identify caller PID |
| [swtpm](https://github.com/stefanberger/swtpm/blob/master/man/man8/swtpm.pod), [swtpm protocol](https://github.com/stefanberger/swtpm/blob/master/include/swtpm/tpm_ioctl.h) | QEMU data/control channels, state locking/backup/fsync, optional encrypted state, version >=0.11 native `--pcap` | **Reuse**; pcap includes internally generated commands and silently ignores failed writes; do not equate nonempty capture with complete trace |
| [libtpms callback API](https://man.archlinux.org/man/extra/libtpms/TPMLIB_RegisterCallbacks.3.en) | TPMLIB_Process/TPMLIB_GetState/SetState, state load/store callbacks | **Reuse for host-only white-box tests**; distinguish emulator-internal values from guest memory; snapshot atomically |
| [tpmproxy](https://github.com/CyberDefenseInstitute/tpmproxy/blob/main/intercept.go), [QEMU relayer](https://github.com/CyberDefenseInstitute/tpmproxy/blob/main/relay_qemu.go) | Go `Interceptor.HandleRequest/HandleResponse`, QEMU control/data socket FD relayer and request decoder | **Strongest immediate candidate for transparent guest-initiated commands**. Source review identified relayer `os.Chmod(...,0666)` and Linux-only runtime: never use unchanged for production/host secrets. Pin revision, audit socket permissions/ownership, cap parser bounds, fail-closed response pairing; lab only |
| [Microsoft TPM reference architecture](https://github.com/microsoft/ms-tpm-20-ref/blob/main/docs/architecture/Library.Architecture.md) | protocol/core/crypto/platform abstraction, ExecuteCommand, platform persistence and locality | **Use as independent semantic oracle** and to locate instrumentation boundaries; core non-reentrant, so serialize command dispatch and save/restore |
| [TPM2-TSS](https://github.com/tpm2-software/tpm2-tss) and [go-tpm](https://github.com/google/go-tpm) | SAPI/ESAPI/TCTI, typed TPM commands, MU codec | **Use for authoritative decoding and operations**; avoid a second homemade full TPM command parser/crypto implementation |
| [PANDA replay + OSI](https://github.com/panda-re/panda/blob/dev/panda/docs/manual.md), [taint2](https://github.com/panda-re/panda/blob/dev/panda/plugins/taint2/README.md) | record/replay, memory callbacks, OS structures, byte-label sets and transformation propagation | **Top candidate for forensic TCG-mode temporal dataflow**; extremely high overhead; external swtpm state and I/O must be captured for replay consistency |
| [QEMU TCG plugins](https://github.com/qemu/qemu/blob/master/docs/devel/tcg-plugins.rst) | instruction execution and successful read/write memory callbacks with VCPU/address | **Use lighter first** on targeted guest memory ranges. Callbacks do not prove process-origin or failed accesses; TCG-only |
| [LibVMI](https://libvmi.com/docs/gcode-intro.html), [MemProcFS](https://github.com/ufrisk/MemProcFS), [Volatility3 pslist](https://volatility3.readthedocs.io/en/stable/_modules/volatility3/plugins/windows/pslist.html), [DRAKVUF](https://github.com/tklengyel/drakvuf/wiki/DRAKVUF-Plugin-Documentation) | GPA/GVA translation, physical and virtual memory, guest OS symbols, EPROCESS and syscall attribution | **Adapter bakeoff** not a new VMI engine. LibVMI live KVM support is deployment-specific; MemProcFS offline dump baseline is attractive; version-matched symbols mandatory |
| [Windows TBS](https://learn.microsoft.com/windows/win32/tbs/tpm-base-services-portal), [Measured Boot logs](https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-security/decode-measured-boot-logs-to-track-pcr-changes) | resource multiplexing, RPC-mediated TPM commands, WBCL and PCR evidence | **OS semantic adapter**. Caller of hardware request can be TBS, not original application; API call, OS service and TPM response are distinct nodes |
| [google/go-eventlog](https://github.com/google/go-eventlog) and [Keylime](https://github.com/keylime/keylime) | event-log parsing/replay, PCR reconstruction, attestation workflow and policy | **Reuse measured-boot validation**. go-eventlog does NOT verify TPM quotes; pair with independent signature/nonce checker |
| [Microsoft OpenHCL architecture](https://github.com/microsoft/openvmm/blob/main/Guide/src/reference/architecture/openhcl.md) and [TPM worker](https://github.com/microsoft/openvmm/blob/main/Guide/src/reference/architecture/openhcl/processes.md) | alternative vTPM deployment inside more privileged paravisor/isolated worker | **Compare security/placement envelopes**, never assume ordinary host QEMU process has same access in shielded/confidential configurations |

## First-class data structures

- **TPM command transaction:** stable `vm_instance, boot_epoch, tpm_instance, tpm_state_epoch, request_id, origin(guest|firmware|emulator_internal|host_lab|unknown), locality, interface(TIS|CRB|I2C|SPAPR), command_code, request/response status, monotonic interval, transport_id, evidence_ref`. Only actual instrumented IDs support a VERIFIED causal edge.
- **Address provenance:** `physical_GPA, guest_virtual_GVA, page-table root/version, address_space_id, allocation_id+generation, process_identity+creation_epoch, thread_identity+creation_epoch, module_load_id+relocation, instruction_IP, timestamp uncertainty`. VM RAM is NOT a single guest VA. Never merge address spaces or periods by numeric address alone.
- **TPM object/value identity:** `handle` scoped by TPM instance and lifetime, `Name/qualifiedName` when supported, `NV_index+attributes+size`, `PCR_bank+index+epoch`, `session_handle+generation`, `sealed_object_id`; distinction between wrapped blob, private TPM key and released plaintext. Handles are reused and may be transient.
- **Sensitivity and flow:** `taint_label_id` (opaque, not secret content), `lineage_edge_type (exact-copy|known-encoding|observed-transform|inferred|unknown)`, `memory_access(read|write|execute)`, source and sink event IDs, raw-evidence custody label, capture-loss counters, evidence strength VERIFIED/CORRELATED/INFERRED/UNKNOWN.
- **Time domains:** host monotonic, guest vCPU/instruction count, wall UTC, QEMU/panda replay ordinal and snapshots each have different calibration. No naive timestamp join across host/guest.

## Algorithms to reuse / qualify

1. **TPM PCR extend:** PCR'[bank,i] = H_bank(PCR[bank,i] || event_digest). Verify measured boot event log independently against quoted PCR (quote authenticity/nonce checked separately).
2. **Source-local byte-label taint:** label synthetic TPM release buffer once; propagate per instruction and memory read/write; label algebra forms sets, requiring identity/semantic provenance. PANDA `taint2` is the prior art; exact byte scan is only a seed and proves no active use.
3. **Program-address mapping:** GPA->GVA through versioned page tables and ASID/CR3; GVA->process/thread via independently validated OS symbol/stack frame. Kernel-mediated requests and asynchronous TBS/resource managers break naive direct causality.
4. **Interval correlation:** causal interval [start,end], clocks+uncertainty, actual request/response ID, process create epoch, state generation, and VM epoch. Ambiguous joins must return candidate set/UNKNOWN, not the nearest PID.
5. **Snapshot/replay:** VM RAM, disk, firmware NVRAM, vTPM permanent/volatile/saved state, external nondeterminism, and replay marker must be coordinated. SANDBOX only. Partial rewind must fail closed, because independent replay of software TPM state can generate false successes and duplicate identities.
6. **Mutation/falsifier:** controlled condition→expected trace→observed trace→independent oracle; compare unmodified emulator baseline to instrumented adversarial behavior; do not classify injected authorization bypass as an upstream vulnerability.
7. **Performance envelope:** p50/p95/p99 end-to-end and segmented latency, trace overhead vs capture-disabled, byte volume/drop and memory use, TCG vs KVM, guest OS/firmware versions, and functionality loss if instrumentation alters scheduling. Preserve failures and unsupported capabilities.

## Core invariants

- One serialized TPM command transaction per independent backend instance; recognize guest RM/TBS mediation.
- Output of a normal TPM command cannot reveal TPM private keys by intent; never treat missing raw key match as proof of absolute isolation.
- No implication of guest process identity from swtpm thread, vCPU at response time, or timestamp alone.
- Transcript accounting must distinguish firmware, internal startup and guest commands; drop/truncation -> INCOMPLETE.
- No OS symbol/profile mismatch accepted as verified EPROCESS/ETHREAD/task_struct/alloc semantic interpretation.
- PCR quote and event-log reconstruction, challenge nonce and signer/endorsement binding are distinct checks; software-only trust cannot graduate to hardware-root trust.
- No clone/migration without version, lock, epoch and authoritative owner; rollback can reproduce identity and violate anti-replay assumptions.
- Plaintext keys, unsealed secrets and raw memory remain private, never public CI, GHA logs, telemetry or agent model prompts. Lab permits raw local inspection by specifically authorized actors only.
- Read-only for production-equivalent observer; writable sensor/actuator requires isolated test target and explicit experiment admission.
- Observable tests must use independent falsifiers, no auto-merge, no extra paid CI/private minutes, no change to unrelated USB/Observatory critical paths.

## Candidate state machines

**vTPM lifecycle:** ABSENT -> MANUFACTURED -> POWERED_OFF -> STARTUP_CLEAR|STARTUP_STATE -> ACTIVE -> SHUTDOWN_CLEAR|SHUTDOWN_STATE -> SNAPSHOT/MIGRATE -> RESTORED/POWERED_OFF; track RESET, EPOCH_CHANGE and ERROR without silently claiming normal TPM transitions. Different backends implement differing subsets.

**Command observation:** FRAME_PENDING -> VALIDATED -> SUBMITTED -> RESPONSE|TIMEOUT|CANCELLED -> PERSISTED -> CORRELATED|UNKNOWN. A timeout is not evidence that the command did not execute.

**RDTE test:** DISCOVER -> ADMIT -> CAPTURE_BASELINE -> EXPERIMENT -> CORRELATE -> INDEPENDENT_ORACLE -> RECONCILE_DLE -> CLEANUP, with FAIL/UNKNOWN branches for missing evidence; no new Observatory execution until parent hygiene gate clears.

## Integration and bounded follow-ons

**Sensor boundary (TPM Workbench plugin):** `DiscoverCapabilities, SubscribeTpmTransactions, SnapshotTpmState, ReadLabTpmObjects, EmitValueLabels, ValidateCapture` as *proposed* contracts; not implemented. Never pass plaintext data into Observatory public event stream.

**Observatory domain boundary:** existing registry/control, normalized evidence, address/time correlation, process/thread/memory/file graphs, renderer/API/agent parity. Append TPM-specific event types, not a second evidence store or scheduling system.

**Actuator boundary (test-only):** `PlanMutation, ApplyToDisposableClone, VerifyRollback, Dispose`; independent approval and typed UNKNOWN on unverified VM quiescence.

**Independent qualification lanes:** (A) source-level proxy code audit and capability tests (Go); (B) upstream swtpm old/new pcap and loss detection (Linux); (C) offline QEMU MMIO trace and real guest-origin request; (D) PANDA taint2 seeded synthetic TPM output; (E) offline LibVMI/MemProcFS process-context replay; (F) PCR event log/quote falsifiers; (G) common event schema and UI/agent contract. A,B,F,G can start in public/free CI on disposable synthetic inputs. Real guest TPM+OS context integration must wait for reproducible guest images/runner capability; no need to block USB Fabric MVP.

## Evidence and known baseline

Previous exact-head [public run 44576628973](https://github.com/SemperSupra/agent-dispatch/actions/runs/44576628973) PASS for Go synthetic memory matching, TPM header and independent contract critics and host-only swtpm 0.7.3 GetRandom/PCR. Pcap 0.11 capability, real guest /dev/tpm0, process attribution, PANDA taint lineage, Win11/Hyper-V and compliant secure vTPM isolation remain **NOT QUALIFIED**. Scope of this concept scan is source-first inspection and proposed composition, not execution of those tests.

**Repository discipline:** current draft branch diverged one commit behind moving main when last checked; do not merge/rebase automatically. Preserve public PR #882 draft; exact-head/CI must be reverified after this document-only update. Observatory parent #4 hygiene-first hold stays in effect.
