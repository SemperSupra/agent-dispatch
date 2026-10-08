# Local runner environment equivalence

The local/private runner program treats a GitHub-hosted runner label as a
reference environment, not as a hardware SKU to clone literally.

## Two independent axes

1. **Environment compatibility** — OS/architecture, runner version, shells,
   toolchains, filesystem/workspace expectations, container/virtualization
   features, and workload-specific behavior that matter to a job.
2. **Resource class** — CPU, RAM, storage, accelerators, and local I/O/network
   characteristics. A local runner may intentionally exceed the observed
   GitHub-hosted resources without ceasing to be compatible.

This prevents two opposite errors: pretending sovereign hardware is identical
to GitHub's fleet, and needlessly discarding local advantages in order to mimic
the cloud.

## Profile classes

- **GHA_PARITY**: local template intended to run workloads that are qualified on
  a named GitHub-hosted reference label. Stronger local CPU/RAM/storage is
  allowed, but the environment contract may not silently diverge.
- **SOVEREIGN_EXTENSION**: starts from a GHA-compatible environment where useful,
  then adds explicitly qualified local-only capabilities such as GPU compute or
  Apple Silicon/Metal.
- **REFERENCE_ONLY**: a GHA environment for which there is intentionally no local
  materialization target yet.

## Qualification

The registry in `config/runner-environment-profiles.json` defines P0-P5:

- P0 retain exact GHA census/capacity/frontier receipts.
- P1 build immutable local template identity.
- P2 run the same passive census locally and compare required fields.
- P3 run callable/frontier oracles required by the environment.
- P4 run representative placement workloads on both sides.
- P5 admit the local template for workloads whose oracles passed.

S1 separately qualifies sovereign-only capabilities. A GPU or Metal PASS never
creates a GHA parity claim by itself.

## Initial references

The current public census enumerates:

- ubuntu-26.04
- ubuntu-26.04-arm
- ubuntu-24.04
- ubuntu-24.04-arm
- ubuntu-slim
- macos-26
- macos-26-intel
- xcode-27

The local registry starts matching candidates as OPEN. No architecture,
toolchain, capacity, or workload claim is inherited from the label; those facts
must come from retained receipts.

## Initial sovereign targets

- A Linux x64 accelerated profile on sovereign TrueNAS substrates, with GPU
  compute treated as an explicit S1 capability.
- A native Apple-Silicon high-performance profile, with Metal and
  Apple-Silicon-native execution treated as explicit S1 capabilities.
- Apple-Silicon Linux VMs as candidates for the GHA ARM Ubuntu references.

The same environment profile IDs should be consumable by GARM regardless of
whether the eventual materialization provider is a TrueNAS App, TrueNAS
Container, TrueNAS VM, or another sovereign provider.

## Placement rule

Jobs should select an environment profile plus required capabilities, rather
than a physical host. The placement layer may then choose the cheapest admitted
runtime that satisfies both. For example, a normal Ubuntu x64 build can use any
P5-qualified local Ubuntu x64 substrate, while a CUDA/GPU workload requires the
sovereign GPU capability and an iOS/Metal workload requires the Apple-Silicon
capability.

The registry is planning/qualification authority only; all candidates begin
OPEN and support inheritance is prohibited.
