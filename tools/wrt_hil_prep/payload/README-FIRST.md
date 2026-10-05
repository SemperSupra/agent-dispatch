# WRT3200ACM EasyMesh / Local Scout HIL Prep Kit

Build date: 2026-10-05
Qualified software baseline: OpenWrt 25.12.5
Current authority phase: R1 READ-ONLY

This kit follows the proven AAR/CDR packaging pattern: immutable bytes, checksums, provenance, scripts, and runbooks travel together; campaign authority remains fail-closed.

## Start here

1. Label the routers DUT-A and DUT-B.
2. Photograph/record each underside label, MAC address, serial number, and current firmware.
3. Do not immediately flash both routers.
4. If a router already runs OpenWrt and SSH works, run the included R1 read-only collector before flashing.
5. If it still runs Linksys/OEM firmware, preserve the existing alternate NAND slot while bootstrapping OpenWrt. Do not intentionally homogenize both slots yet.
6. Locate or obtain 3.3 V TTL serial hardware before R2 recovery qualification.
7. R2 Gold/Rescue and R3 prplMesh deployment wait for reviewed R1 evidence.

## Included immutable software

- OpenWrt 25.12.5 WRT3200ACM factory image.
- OpenWrt 25.12.5 WRT3200ACM sysupgrade image.
- OpenWrt 25.12.5 WRT3200ACM initramfs kernel.
- Official target sha256sums, signature, and profiles.json.
- Qualified stock prplMesh 6.0.1-r1 package from Agent Dispatch CP0 run 37273250460, staged for later R3.
- Offline R1 collector/reducer/wrapper.
- Linux and Windows hash verification.
- Windows serial-port enumeration.
- Physical and serial checklists plus offline diagrams.

## R1 authority boundary

No persistent DUT changes are authorized. Do not use the kit yet for fw_setenv, sysupgrade, package installation, UCI changes, service restarts, reboot/power-cycle experiments, MTD/UBI writes, bootloader writes, factory/calibration writes, or radio-firmware mutation.

## First command when OpenWrt + SSH is already available

scripts/r1-readonly-remote.sh root@DUT-MANAGEMENT-IP-OR-SSH-ALIAS
