# Sovereign runner runtime templates

Authority: `SemperSupra/agent-dispatch-private#514`

This contract turns the existing GitHub-hosted runner census into a reproducible
local/private runner-template program.

## Compatibility model

GitHub-hosted runners are a workload-compatibility reference, not a hardware clone
target. Local hardware may differ materially while still satisfying the same
runtime contract.

Three classifications are allowed:

- **GHA_EQUIVALENT** — materially equivalent OS/architecture/runtime/toolchain and
  representative workload behavior.
- **GHA_COMPATIBLE_DELTA** — satisfies the selected GHA workload contract with
  explicitly recorded image, hardware, provider, or control-plane differences.
- **SOVEREIGN_ENHANCED** — derives from one compatible local base and adds local-only
  capabilities that are independently qualified.

The machine-readable authority is
`config/runner-runtime-templates.json`.

## Initial GHA reference set

The first catalog freezes the already-censused classes:

- Ubuntu 24.04 x64 / ARM64
- Ubuntu 26.04 x64 / ARM64
- ubuntu-slim x64
- macOS 26 ARM64 / Intel
- Xcode 27 ARM64
- Windows 2025 x64
- Windows 11 ARM64

Each reference class carries only predicates that already have durable census,
primitive, or representative-workload evidence. A local candidate must reproduce
those predicates independently; source-image similarity is insufficient.

## Sovereign mappings

The first candidate mappings intentionally use existing execution surfaces:

- TrueNAS VM/container/App backends for Linux x64 and slim contracts;
- Apple Virtualization.framework on the Big Mac for Linux ARM64 and future Windows
  ARM64 candidates;
- native Big Mac macOS/Xcode profiles when exact local OS/toolchain identity earns
  compatibility;
- Windows development host Hyper-V for Windows 2025-compatible materialization.

No new scheduler, task database, or placement engine is introduced by this
catalog.

## Sovereign-enhanced classes

Local capabilities that GitHub free-tier runners do not provide are modeled as
extensions rather than silently changing a parity template. Initial examples:

- TrueNAS Linux x64 with NVIDIA GPU access;
- TrueNAS larger-memory/local-storage throughput class;
- Big Mac native Apple Silicon / Metal / large-unified-memory class;
- Windows development host local Hyper-V/WSL/LAN control class.

An accelerator or large-memory observation is only discovery evidence. Admission
requires a bounded runtime oracle and a representative workload showing that the
capability is usable and valuable.

## Qualification ladder

1. **T0** freeze exact GHA reference predicates and local source identity.
2. **T1** build/materialize the candidate.
3. **T2** run the same passive census schema locally.
4. **T3** reproduce required primitive oracles.
5. **T4** reproduce representative GHA workload predicates.
6. **T5** prove lifecycle/rebuild/reconciliation and zero residue.
7. **T6** execute one real ephemeral GARM/GitHub runner workload.
8. **T7** independently prove sovereign enhancements.
9. **T8** admit the exact template to placement with evidence refs.

This ordering prevents a stronger local machine from being called GHA-compatible
before the actual workload contract is demonstrated.
