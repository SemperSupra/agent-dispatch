# R48 — ARM64 and AMD64 node profile policy

This is an independently authored **Go stdlib, synthetic-only admission model** to extend private IaC #403 and #402 beyond the Dell Wyse 5070 profile. A matching CPU ISA does **not** establish bootloader, BSP, virtualization, GPU, GPU passthrough, NVMe boot or hardware recovery compatibility.

Profile examples cover Raspberry Pi 4/5 and Compute Module (64-bit Linux and SD/USB/network boot; Pi 5/CM NVMe needs observed appropriate adapter), NVIDIA Jetson Orin/Thor (vendor Jetson Linux/JetPack qualified BSP and UEFI, native NVIDIA compute runtime), generic AMD64 desktop/server/laptop (UEFI/legacy BIOS, laptop unattended AC and suspend policy), and generic ARM64 vendor-qualified boards. ARM64 KVM and GPU/USB guest support are independent HIL evidence, not implied. CUDA inference is native Jetson host-only in this initial policy; never claim a generic GPU passthrough VM or CUDA guest.

Every Boolean and SHA in this model is an **untrusted fixture field**, not a signed observation. The existing Foundry fleet controller must independently verify owner-device pairing, signed recovery boot, exact board/BSP version, physical PCI/IOMMU/USB topology, thermal/power policy, KVM guest boot and vendor runtime before promoting an actual node. Tenant-facing views must exclude host device inventory per private #395/#399, and Agent Dispatch remains the sole workload scheduler.

Native public GitHub Actions ubuntu-24.04 and ubuntu-24.04-arm perform architecture-portability tests without hardware access. Successful CI is **not Raspberry Pi or Jetson hardware-in-the-loop**. No real network discovery, DHCP, vendor flashing, CUDA installs, EEPROM/firmware changes, GPU binds, raw storage, USB, TPM or production keys are touched.

Sources:
- Raspberry Pi bootloader and hardware: https://www.raspberrypi.com/documentation/computers/raspberry-pi.html
- JetPack release/hardware matrix: https://developer.nvidia.com/embedded/jetpack/downloads
- Public free ARM64 GHA: https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
