# Reversing correlation experiment — synthetic public v1

Authority: https://github.com/mark-e-deyoung/ghidra-tools/issues/4

## Scope

Deterministically correlate sampled runtime instruction virtual addresses with *unique* static function RVA intervals, only when bound to the exact loaded module identity and artifact SHA-256. Preserve all unknowns and do not infer that static-only functions are unreachable. External file/network/memory/driver events remain unattributed unless an explicit same-run causal observation points to a uniquely matched instruction. Clock proximity does **not** establish causality.

This is a public-safe synthetic contract, **not an implemented Ghidra plugin, VM debugger, QEMU/PANDA trace, or demonstration of a live process**. No real target binary is executed.

## Run

    python3 -m unittest -v tests/test_reversing_evidence_correlate.py
    python3 scripts/reversing_evidence_correlate.py --input fixtures/reversing-correlation-synthetic-v1.json --output /tmp/reversing-correlation.json

Inputs: schema/version, run/mode, SHA-256, static functions (RVA/size), runtime module loads (VA/size/SHA-256), sensor events (kind/vantage/run/time domain), and optional **explicit** causal witnesses. Outputs: matched instructions, unresolved observations/links, external events, unobserved static functions and canonical input SHA-256.

Only identifiers/tokens allowed. No raw firmware/APKs/private binaries, process memory, raw packet payloads, credentials, paths or private target metadata may be published. File size <= 1 MiB and up to 1024 records per family. Synthetic, bounded, disposable public CI; no new paid resources or credentials.

## Reuse points and future work

- Ghidra headless, FID/BSim and Trace RMI should provide *separate adapters* to artifact/function/load data; Ghidra project IDs are not stable evidence identity.
- FRITZ QEMU-user/GDB/strace can supply **accepted sanitized evidence** from existing experiments, without reopening D19 or publishing proprietary artifacts; stock vs instrumented results remain different modes and never acquire physical parity by implication.
- Windows PE fixture requires an independently verified symbol ground truth and a qualified real debugger/guest run.
- Android DEX method identity and native ELF/ART module VA require separate typed address spaces, not a DEX-to-VA guess.
- Host packet/disk/driver observations remain independent of guest instruction traces unless explicitly linked by proven correlation.

Human/AT report, CLI/SDK, and agent typed/MCP tools must share semantic evidence. CLI/JSON works at this experiment stage. Screen-reader qualification, independent Ghidra integration, real runtime execution, OS/VM sensor completeness, and source reconstruction are **NOT_RUN**.

A local/CI unit test passing means only SYNTHETIC_CONTRACT_PASS for that exact source head. Native program tracing and independent oracle need their own qualified experiment. No second orchestration control plane, scheduler, workflow-per-task family, direct Sidecar dispatch, automatic merge/release or permission expansion.
