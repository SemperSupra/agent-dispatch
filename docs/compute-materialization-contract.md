# Cross-platform compute materialization contract

Private authority: `SemperSupra/agent-dispatch-private#426`.

This contract describes how Agent Dispatch will select a native product adapter
for system containers and VMs without pretending the API is stable across
TrueNAS releases or that one Proxmox release proves another.

## TrueNAS source-discovered transition

- 25.04.1: `virt.instance` is Incus-backed and owns both CONTAINER and VM instances.
- 25.04.2.6 / 25.10.7: the Incus `virt.instance` family remains, while a
  separate `vm.*` libvirt/QEMU family is also present.
- 26.0.0-BETA.3: the legacy `virt` plugin is gone; first-class
  `container.*` uses the new LXC-oriented implementation and `vm.*`
  remains the VM surface.

The planner therefore chooses by exact profile **and observed methods**. Version
alone never authorizes apply.

## Proxmox

The current real-system harness admits only PVE 9.2-1. The compute contract
defines REST-family LXC and QEMU adapters for that exact profile. Additional PVE
versions must be added as exact source/package/ISO profiles before execution.

## Fixtures

Three semantic fixtures are tracked:
1. small Linux system container with lifecycle + nonce;
2. Linux VM with nested-KVM observation and Firecracker only when KVM is
   actually available inside the VM;
3. Windows 11 evaluation VM with firmware/security capability checks.

The registry and planner are cheap/source-level contracts. They perform no
mutation and grant no runtime support claim.
