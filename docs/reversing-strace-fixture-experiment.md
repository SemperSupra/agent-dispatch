# Synthetic Linux syscall tracing — bounded RDT&E, not an accepted product

**Product/mission authority:** [mark-e-deyoung/ghidra-tools#4](https://github.com/mark-e-deyoung/ghidra-tools/issues/4). **Public disposable experiment runner:** SemperSupra/agent-dispatch. **WoW:** SemperSupra/engineering-governance-private@main:WAY_OF_WORKING.md v0.0.4, Durable/Legible/Executable, mission command, Discover → Observe → Plan → Apply → Verify.

## End state, authority and scope

Prove that a native Linux syscall tracer can observe and distinguish one deterministic generated ELF's openat/write/close/exit sequence, that an independent file-content oracle agrees, and that receipt parsers reject misleading, incomplete, reordered, cross-PID and contradictory evidence. No general binary execution, private target, unrestricted tracing, network traffic, secrets, privileged host/VM, new Sidecar grant or actor admission. No merge/release/adoption implied.

Reuses the existing public Runner Frontier workflow on standard ubuntu-24.04 using a non-privileged child trace. This experiment is stacked on **DRAFT/unmerged PR #514** so that the existing reversing source, CI and admission boundary remain untouched; this does **not** independently approve #514 or earlier PRs.

## Discover / use / observe / diagnose

- Fixed source: scripts/reversing_strace_fixture_probe.py, embedded C, accepts only --output for a fresh JSON receipt, no target path/command/attach PID input.
- Input: Python >=3.10, gcc, strace with permission to trace its own child. The CI job may install official Ubuntu strace package if not present. Package/runtime versions should be visible in native log.
- Unit: python3 -m unittest -v tests/test_reversing_strace_fixture_probe.py
- Native: python3 scripts/reversing_strace_fixture_probe.py --output "$RUNNER_TEMP/reversing-strace-fixture.json"
- Native result: one five-event ordered witness, generated ELF/source/trace/output sha256, actual exact output bytes, and typed status. CI prints only this fixed synthetic receipt; entire syscall trace stays in runner temp and is discarded on runner teardown.
- Failure: BLOCKED_CAPABILITY (missing binary, denied ptrace); OracleError (ambiguous/missing/mismatched trace/output); native/test failure does not automatically become a PASS.
- Expected limitation: syscall events do not expose instruction PCs or prove Ghidra address/interval mapping, arbitrary app behavior, all paths or causal relationships. A single generated target does not qualify generic OS sensor coverage.
- Acceptance: independent fresh reviewer rereads exact PR head, CI merge checkout, tool versions, witness lines, all source/trace/output hashes and actual fixture effects. The separate project-owned schema in private ghidra-tools draft PR #5 remains unaccepted; never copy public proof into private product without rights/owner decision.

## R4 / safety

TemporaryDirectory for compilation, generated output and raw syscall log; exclusive-create receipt path; bounded trace size and tool timeouts; no executable supplied by an adversary; collector spawns its own fixed child; trace uses only a syscall allowlist and captures just one known string payload. Parse five allowlisted public-synthetic lines, not unrestricted private arguments. PR CI uses pull_request (NOT pull_request_target), checkout without persisted credentials, contents:read, and no secret/billing escalation. Negative tests target incomplete syscalls, PID mixing, ordering, duplicate events, false clean exit and receipt overwrite.

## DLE continuation / next bounded action

After the PR event runs, independently inspect its actual run/job and compare the native fixture events with documented expectations. If strace returns blocked or parser rejects legitimate runner output, preserve exact negative evidence and make a reviewable scoped correction without weakening the oracle, then rerun only at a new exact head. On success, pass a small project-owned metadata mapping proposal to ghidra-tools#4 and plan Windows ETW / macOS capability canaries as separate workcells. **Do not merge or promote this stacked experiment or #514 without independent review and upstream-stack reconciliation.**
