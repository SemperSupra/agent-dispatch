# Native and system container substrate qualification

This experiment qualifies container execution classes for later Agent Dispatch and GARM placement. It is deliberately broader than a lifecycle smoke test: each lane records the resource, network, device, accelerator, privilege, storage, and kernel envelope visible **inside** the container and compares it with the host.

Private experiment authority: `SemperSupra/agent-dispatch-private#397`.

## Evidence rule

Use the same ladder as the runner census:

`advertised -> observed -> installed -> callable -> exercised -> oracleSatisfied`

A green workflow job is not a capability verdict. A visible device is not automatically callable. A callable API is not automatically useful for a workload.

Receipts classify each lane independently and retain raw, bounded observations.

## Initial lanes

| Lane | Isolation/runtime | Public GHA rep | Intended later placement |
| --- | --- | --- | --- |
| Windows | HCS-backed Windows process container via Docker/container runtime | `windows-2025` | Windows GARM/self-hosted Windows capacity |
| Apple | `apple/container` + Containerization + Virtualization.framework; one lightweight Linux VM per container | `macos-26` | Apple-silicon self-hosted/GARM-like Mac capacity |
| LXC | Linux system container sharing host kernel | `ubuntu-26.04` | raw-LXC oracle; underlying primitive for TrueNAS/Proxmox comparisons |
| Incus | LXC-backed system-container control plane with explicit device/network API | `ubuntu-26.04` | portable Linux system-container manager comparison |

Tracked but not in this first batch: FreeBSD jails, systemd-nspawn, Kata Containers, gVisor. Firecracker is already tracked separately in the private experiment authority.

## Common execution-envelope census

Every successful container lane should capture enough evidence to answer placement questions without a second exploratory session.

### CPU and memory

- host and container ISA;
- visible logical CPU count;
- affinity/cpuset and quota evidence when exposed;
- visible RAM and cgroup/job-object limits;
- VM-backed vs shared-kernel semantics.

### Storage and filesystem

- root filesystem and mount table;
- writable/read-only state;
- volumes/bind mounts/tmpfs;
- visible block devices;
- free space.

### Privilege and isolation

- user/UID or Windows token context;
- Linux capabilities and cgroups;
- AppArmor/seccomp/SELinux evidence when available;
- process isolation vs VM isolation.

### Network

- interfaces, addresses, routes, DNS, MTU;
- default connectivity model;
- bridge/NAT/macvlan/vmnet/HNS evidence;
- later reps should exercise host reachability, peer reachability and port publishing rather than infer them from configuration alone.

### Devices and accelerators

Record host/container deltas for:

- GPU: NVIDIA, AMD, Intel, DirectX, virtio-gpu separately;
- USB;
- serial/COM;
- GPIO, I2C, SPI where the platform supports them;
- TPM;
- InfiniBand/RDMA;
- tun/tap and FUSE;
- PCI/VF/MIG/SR-IOV or mediated devices when the manager exposes them;
- KVM/Hyper-V/HVF only as a nested-execution capability, not as a generic container requirement.

The common rule is **visible != callable != exercised**. Accelerator/device admission requires an oracle.

## Product-specific notes

### Windows containers

The first rep builds a Windows Server Core LTSC 2025 image and executes a PowerShell census in a process-isolated Windows container. Windows HCS/HNS are the underlying compute/network services; containerd/runhcs are future direct runtime surfaces.

Windows supports selected host device classes in process-isolated containers. GPU acceleration is a special DirectX path and is not equivalent to generic CUDA/ROCm passthrough. Device assignment and the documented DirectX GPU mechanism do not apply to Hyper-V-isolated Windows/Linux containers.

Local reproduction:

```powershell
python scripts/container_substrate_qualification.py --lane windows --out receipt.json
```

Precondition: a Windows container engine capable of running an LTSC 2025 Windows image.

### Apple container / Containerization

Apple's `container` consumes and produces OCI images but each running Linux container is placed in its own lightweight VM. CPU and memory are VM allocations; networking is backed by vmnet and storage/mounts by the Containerization/Virtio stack.

The public `macos-26` hosted runner is useful for proving that the runtime builds and for testing whether Virtualization.framework is actually usable in that environment. A failure to start the service is retained as a negative environment observation, not rewritten into a successful container claim.

The first rep builds the pinned `apple/container` source and then attempts:

```text
container system start --enable-kernel-install
container build ...
container run ...
```

Local reproduction on an Apple-silicon Mac with macOS 26 uses the pinned signed 1.4.1 release package. Verify the release SHA-256 before installation:

```bash
curl -fL -o /tmp/container-1.4.1.pkg \
  https://github.com/apple/container/releases/download/1.4.1/container-1.4.1-installer-signed.pkg
echo 'c0d2716afefbb194c93fae662e9cae7cc186bcbcf746816608ec673dd648a6a4  /tmp/container-1.4.1.pkg' | shasum -a 256 -c -
sudo installer -pkg /tmp/container-1.4.1.pkg -target /
python3 scripts/container_substrate_qualification.py \
  --lane apple --runtime "$(command -v container)" --out receipt.json
```

The first public GHA rep also built 1.4.1 successfully from source; routine requalification uses the signed package to reduce setup cost. Do not infer Apple-GPU availability inside the Linux guest. It must be proven through an actual guest-visible GPU/accelerator API before a `gpu:apple` capability can exist.

### Raw LXC

This is the primitive system-container lane. It downloads a small Alpine root filesystem, creates a real LXC container, starts it, enters it, captures the execution-envelope census, and destroys it.

Local Debian/Ubuntu example:

```bash
sudo apt-get install -y lxc lxc-templates uidmap bridge-utils dnsmasq-base iproute2 pciutils usbutils
sudo systemctl start lxc-net || true
sudo -E python3 scripts/container_substrate_qualification.py --lane lxc --out /tmp/lxc-receipt.json
```

Raw LXC success does **not** prove either TrueNAS Containers or Proxmox `pct`.

### TrueNAS Containers

TrueNAS 25.04 documentation describes Linux Containers as LXC-backed, including CPU/memory allocation, default/bridge/macvlan networking, USB attachment, and GPU attachment. Product management behavior is version-sensitive.

The 25.04.0/25.04.1 "Instances" period differs from 25.04.2+ UI behavior, so a TrueNAS adapter must begin by discovering the target version and exposed middleware API instead of assuming a later contract.

Future supported wrapper rep:

```text
discover version/API
-> discover image/container/device/network capabilities
-> plan exact create/start/work/evidence/destroy operations
-> apply through supported middleware API
-> verify readback and cleanup
```

Do not automate by shelling directly into undocumented TrueNAS internals merely because raw LXC is qualified.

### Proxmox VE LXC

Proxmox VE uses LXC but adds the `pct` and REST control planes, storage/network integration, permissions and cluster semantics. A later Proxmox-specific qualification must prove the wrapper contract rather than reuse raw-LXC success.

Future rep:

```text
PVE API/pct create
-> start
-> bounded exec/work
-> resource/device/network census
-> stop/destroy
-> verify storage/network cleanup
```

This is the likely interface for a future GARM provider; direct LXC calls underneath Proxmox should not bypass Proxmox ownership.

### Incus

Incus is included because it exposes a rich, provider-neutral system-container API and explicit device model: NIC, disk, USB, GPU, InfiniBand, Unix character/block/hotplug, TPM and other device types. It gives us a useful comparison for what a generic system-container execution class can express without binding the work contract to TrueNAS or Proxmox.

Local example:

```bash
sudo apt-get install -y incus
sudo incus admin init --minimal
sudo -E python3 scripts/container_substrate_qualification.py --lane incus --out /tmp/incus-receipt.json
```

## Normalized capability-fact projection

Each receipt now emits `capability_facts` alongside the raw census. The projection is intentionally small and non-prescriptive:

- `SUPPORTED` means an exercised oracle passed.
- `OBSERVED` means the object/interface is visible but callability is not proven.
- `NEGATIVE_OBSERVATION` records a tested absence in this exact environment.
- `DOCUMENTED_NEGATIVE` records an upstream/platform limitation represented by the qualification contract.
- `INCONCLUSIVE` means the rep does not justify either a positive or negative placement claim.

Examples from the current contract include `runtime:lxc`, `kernel:shared`, `network:dns`, `network:tcp443`, `network:https-egress`, `device:tun`, `device:fuse`, `device:kvm`, `gpu:directx`, and `apple-container:control-plane`.

The projection exists so later Agent Dispatch/GARM placement code does not parse human diagnostic logs. It is evidence input, not a scheduler or admission decision.

## Agent Dispatch / GARM mapping

Do not introduce a scheduler for this experiment. Preserve primitive facts that a later placement layer can match:

```text
runtime:windows-container
runtime:apple-container
runtime:lxc
runtime:incus

kernel:shared
kernel:guest-linux-vm
isa:x86_64
isa:arm64

device:usb
device:tpm
device:infiniband
device:tun
device:fuse
gpu:nvidia
gpu:amd
gpu:intel
gpu:directx
gpu:apple
network:bridge
network:macvlan
network:nat
network:vmnet
isolation:process
isolation:vm
```

Each primitive needs its own evidence state. For example, a host with NVIDIA hardware does not imply `gpu:nvidia` in a container until the device and a workload/API oracle pass inside that container.

## Repeatability

The public workflow is both a public zero-cost GHA experiment and a reproducible specification. Local/GARM adapters should run the same probe contract where possible and add only the product-specific preparation/binding step.

Keep GHA-specific setup outside the portable receipt semantics. A GHA pass proves the tested hosted environment. Operational admission on a TrueNAS, Proxmox, Windows or Mac host requires reproducing the relevant lifecycle + resource/device/network oracle on that target.
