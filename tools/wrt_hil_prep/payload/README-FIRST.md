# WRT3200ACM EasyMesh / Local Scout HIL Prep Kit

Qualified software baseline: OpenWrt 25.12.5
Current physical authority phase: R1 READ-ONLY

This kit carries immutable firmware/package bytes plus the current fail-closed R1 -> R2 -> R3 tooling. Emulator qualification never grants physical write authority.

## Start here

1. Label routers DUT-A and DUT-B.
2. Record underside label, MAC address, serial number, and current firmware.
3. Do not flash both routers.
4. Run the no-write arrival preflight before touching either DUT:
   - Windows PowerShell: `scripts/Invoke-HilPreflight.ps1 -DutA root@DUT-A -DutB root@DUT-B`
   - Linux/USB host: `scripts/hil-preflight.sh root@DUT-A root@DUT-B`
5. Only if a DUT reports R1 eligible, collect R1:
   - Linux/macOS/WSL: `scripts/r1-readonly-remote.sh root@DUT`
   - Windows PowerShell: `scripts/R1-Readonly-Remote.ps1 root@DUT`
6. R1 may establish inventory sufficiency only. It does not admit R2 by itself.
7. R2 requires separately evidenced serial console, independent power cycle, Gold identity, Rescue identity, independent evidence sink, and review.
8. R3 remains external package/config generation only after a GREEN R2 verdict. Protected NAND remains denied.

## Included qualification tooling

- R1 collector + fail-closed reducer.
- Linux and native Windows no-write arrival preflights.
- Linux and native Windows R1 wrappers.
- R2 admission gate.
- Serial transcript observation reducer.
- Fake independent-power actuator for zero-hardware orchestration tests.
- R2 Gold/Rescue evidence reducer.
- R3 physical generation binder.
- R1/R2/R3 JSON schemas and fill-in templates.
- DUT generation and independent-power contracts.
- Linux/Windows bundle verification and Windows serial-port inventory.

## Immutable software

- OpenWrt 25.12.5 WRT3200ACM factory/sysupgrade/initramfs images.
- Official target sha256sums, signature, and profiles.json.
- Qualified prplMesh 6.0.1-r1 package staged for later R3.

## Physical authority boundary

Until reviewed R1 evidence exists, do not perform fw_setenv, sysupgrade, package installation, UCI changes, service restarts, reboot/power-cycle experiments, MTD/UBI writes, bootloader writes, factory/calibration writes, or radio-firmware mutation.
