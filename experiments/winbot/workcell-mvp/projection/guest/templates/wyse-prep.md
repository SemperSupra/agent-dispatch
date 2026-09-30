# Wyse 5070 Thin Client -- WinBot Preparation Guide

This guide covers everything needed to prepare a Dell Wyse 5070 thin client for PXE-booted WinBot deployment. Once configured, the machine will network-boot from the WinBot PXE server, auto-install Windows 11 Enterprise, provision the WinBot API, and auto-register as a node.

## Hardware Overview

| Spec | Value |
|------|-------|
| **SoC** | Intel Gemini Lake (Celeron J4105 / Pentium Silver J5005) |
| **RAM** | 4GB or 8GB DDR4-2400 (soldered, dual-channel on 8GB models) |
| **Storage** | 32GB/64GB eMMC (model 5C10W) or 128GB M.2 SATA SSD (model 5C11W) |
| **NIC** | Realtek RTL8168/8111 Gigabit Ethernet |
| **Video** | Intel UHD Graphics 600/605 (2x DisplayPort 1.2) |
| **USB** | 4x USB 3.0 Type-A (front), 2x USB 2.0 (rear) |
| **Audio** | Realtek ALC3253 HD Audio (3.5mm combo jack) |
| **Wireless** | Optional Intel Dual Band Wireless-AC 9560 (M.2 slot) |
| **BIOS** | Dell Wyse 5070 System BIOS (Aptio V / AMI UEFI) |
| **TPM** | Intel PTT (fTPM 2.0) -- firmware-based, no discrete TPM chip |
| **Power** | 65W barrel jack (7.4mm x 5.0mm). USB-C does NOT support PD. |

### Model Identification

Look at the label on the bottom of the unit:
- **5C10W** = eMMC storage model (32GB or 64GB eMMC soldered)
- **5C11W** = M.2 SATA SSD model (128GB SSD in M.2 slot)

Both models have an empty internal M.2 SATA slot. You can install a standard M.2 SATA SSD (not NVMe) in an eMMC model for more storage.

## BIOS / Firmware Update

### Check Current Version

Power on the Wyse, press **F2** during boot to enter BIOS Setup. The BIOS version is shown on the main **System Information** screen.

**Minimum recommended version: 1.15.0** (October 2023 or later). Earlier versions have known issues with UEFI PXE and Intel PTT/TPM detection.

### Update via USB (Recommended)

1. Go to [Dell Support](https://www.dell.com/support) and enter your Wyse 5070 Service Tag (7-character alphanumeric, on bottom label).
2. Download the latest **Wyse 5070 System BIOS** (.exe file).
3. Format a USB flash drive as **FAT32**.
4. Copy the BIOS .exe file to the root of the USB drive.
5. Insert the USB drive into the Wyse.
6. Power on and press **F12** at the Dell logo to enter the Boot Menu.
7. Select **BIOS Flash Update** from the menu.
8. Follow the on-screen prompts. The system will reboot automatically.

### Update via Dell Command Update (If Windows Is Already Installed)

```cmd
dcu-cli.exe /applyUpdates -updateType=bios,firmware -reboot=enable
```

## UEFI / BIOS Configuration

Enter BIOS Setup by pressing **F2** during boot at the Dell logo. Navigate using the arrow keys, Enter to select, Esc to go back.

### Step 1: Disable Secure Boot

```
Boot Configuration -> Secure Boot -> Secure Boot Enable -> Disabled
```

**Rationale:** The WinPE boot.wim is not UEFI-signed by Microsoft. Secure Boot would block it.

**Alternative (advanced):** If you need Secure Boot enabled for compliance, you can enroll the WinBot certificate. Export the certificate from another WinBot-deployed machine and enroll it via:
```
Boot Configuration -> Secure Boot -> Secure Boot Custom Mode -> Enroll Efi Image
```

### Step 2: Enable UEFI Network Stack

```
System Configuration -> Integrated NIC -> Enabled with PXE
```

This enables the Realtek RTL8168 UEFI PXE ROM. If this option is not visible, update your BIOS first.

### Step 3: Set Boot Order (PXE First)

```
Boot Configuration -> UEFI Boot Order
```

Move **"UEFI: PXE IP4 Realtek PCIe GBE Family Controller"** to the top of the list.

Also check:
```
Boot Configuration -> Boot Sequence
```
Uncheck everything except **"Integrated NIC"** (and optionally **"USB Storage Device"** for recovery USB).

### Step 4: Enable Legacy Option ROMs

```
General -> Advanced Boot Options -> Enable Legacy Option ROMs -> Checked
```

**Critical:** Some Realtek PXE ROM implementations need legacy option ROM support to chainload iPXE correctly. Without this, the DHCP handshake may succeed but the TFTP/iPXE download may fail silently.

### Step 5: Configure TPM / Intel PTT

```
Security -> TPM 2.0 Security -> PTT On -> Checked
```

Windows 11 requires TPM 2.0. Intel PTT (Platform Trust Technology) is the firmware TPM implementation.

**Before re-imaging:** Clear the TPM to avoid stale key issues:
```
Security -> TPM 2.0 Security -> Clear -> Yes
```

**Known issue:** Some early BIOS versions (< 1.10.0) have broken PTT that causes TPM detection to fail even when enabled. Update BIOS first if you see "TPM Not Detected" in Windows setup.

### Step 6: Storage Configuration

```
System Configuration -> Drives
```
Ensure the storage device is enabled:
- For eMMC models: confirm **eMMC** is present and enabled
- For SSD models: confirm **M.2 SATA** is present and enabled
- If you installed an M.2 SATA SSD in an eMMC model: both should appear

Set SATA Operation to **AHCI** (not RAID):
```
System Configuration -> SATA Operation -> AHCI
```

### Step 7: Power Settings

```
Power Management -> Wake on LAN -> LAN Only
```

Enables the WinBot host to remotely power-on the node. Not required for PXE deployment but recommended for fleet management.

```
Power Management -> AC Recovery -> Power On
```

Ensures the node powers on automatically after a power outage.

## PXE Boot Test

1. Connect the Wyse to the same network as the WinBot PXE server.
2. Power on. If DHCP and PXE are configured correctly, you should see:
   - Dell logo -> PXE ROM initializes -> "Start PXE over IPv4"
   - DHCP lease acquired
   - iPXE downloads from the PXE server
   - **"WinBot PXE Boot Menu"** appears
3. Select **"WinBot Auto-Deploy"** (selected automatically after 10 seconds).

### If PXE Boot Fails

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| "No boot filename received" | DHCP option 67 not set | Configure PXE server DHCP or use `-Mode LinuxVM` for dnsmasq |
| iPXE downloads but hangs | Realtek PXE ROM compatibility | Enable Legacy Option ROMs (Step 4 above) |
| "No bootable device" after PXE succeeds | Storage not detected | Check SATA mode is AHCI, storage device is enabled (Step 6) |
| PXE ROM never appears | Integrated NIC PXE disabled | Check Step 2 |
| DHCP times out | VLAN / network isolation | Verify the PXE network is reachable; check switch configuration |
| WinPE boots but no network | NIC driver missing from boot.wim | Rebuild WinPE with `-Hypervisors wyse5070 -NICOnly` inject |

## Known Quirks and Workarounds

### Realtek RTL8168 PXE ROM Issues

The Realtek UEFI PXE ROM on the Wyse 5070 can be finicky. Specific issues observed:

1. **Single-attempt failure:** The PXE ROM sometimes fails on the first attempt and succeeds on the second. If the first PXE attempt fails with "PXE-E16: No offer received," wait for the retry (usually 5 seconds).

2. **iPXE chainload failure:** The ROM's built-in TFTP client sometimes corrupts the iPXE download. Workaround: boot from a USB stick containing `ipxe.efi`:
   - Download `ipxe.efi` from https://ipxe.org/download
   - Copy to a FAT32 USB drive as `/efi/boot/bootx64.efi`
   - Insert USB, boot, press F12, select "UEFI: USB Storage Device"
   - iPXE loads from USB → chains to HTTP iPXE script → PXE server

3. **Link negotiation delay:** The RTL8168 sometimes takes 3-5 seconds to negotiate link after cold boot. The PXE ROM may timeout before link is established. If this happens consistently, enable the "PXE Retry Count" setting (if available in your BIOS version) or set "Link Speed" to a fixed value in BIOS:
   ```
   System Configuration -> Integrated NIC -> Link Speed -> 1 Gbps Full Duplex
   ```

### eMMC Wear Considerations

The 32GB/64GB eMMC used in 5C10W models has limited write endurance (typically 150-300 TBW for a 64GB eMMC). For a WinBot automation node:
- **Enable UWF (Unified Write Filter)** after provisioning: `.\guest\tools\enable-uwf.ps1` -- this redirects all writes to a RAM overlay, protecting the eMMC.
- With UWF, the eMMC sees zero writes during normal operation. The overlay is discarded on reboot.
- UWF requires a reboot to enable. The provision script handles this automatically if the node is configured as a physical node.

### M.2 SATA Detection After Cold Boot

Some Wyse 5070 units fail to detect an M.2 SATA SSD on the first cold boot after AC power loss. If this happens:
1. Enter BIOS Setup (F2)
2. Go to System Configuration -> Drives
3. Confirm M.2 SATA is listed. If not, try "Load Defaults" -> Save & Exit -> Re-enter Setup
4. This typically only affects units that have had their CMOS battery replaced or have been unplugged for > 24 hours.

### Dual Monitor Handshake

The Wyse 5070 has two DisplayPort outputs driven by Intel UHD Graphics 600/605. Some monitors fail DP handshake on the first output during POST/UEFI phase. If you see no video output:
1. Try the other DisplayPort
2. Try a different DisplayPort cable (the Wyse is DP 1.2, some DP 1.4 cables have compatibility issues)
3. Connect both DisplayPort outputs -- the BIOS sometimes outputs to the "second" port during UEFI phase
4. HDMI is NOT available -- do not use passive DP-to-HDMI adapters (they require DP++ which the Wyse does not support). Active adapters work.

### BIOS Password / CMOS Reset

If a BIOS password is set and unknown:
1. Disconnect power
2. Remove the bottom cover (4 screws)
3. Locate the CMOS battery (CR2032 coin cell, near the M.2 slot)
4. Remove the battery, wait 60 seconds
5. Short the two RTC reset pads (unlabeled -- they are two bare copper pads near the battery holder, about 2mm apart)
6. Reinstall the battery, reassemble, power on

The BIOS settings will be reset to defaults. Re-apply all configuration steps above.

## Pre-Flight Checklist

Before deploying a Wyse 5070 as a WinBot node:

- [ ] BIOS updated to latest version (check Dell Support with Service Tag)
- [ ] Secure Boot: Disabled
- [ ] UEFI Network Stack: Enabled (Integrated NIC -> Enabled with PXE)
- [ ] PXE/Network: First in boot order
- [ ] Legacy Option ROMs: Enabled
- [ ] TPM/PTT: On (and cleared before imaging)
- [ ] SATA Operation: AHCI
- [ ] Storage device detected and enabled (eMMC or M.2 SATA)
- [ ] Wake on LAN: Enabled (LAN Only)
- [ ] AC Recovery: Power On
- [ ] Ethernet cable connected to PXE network (NOT an isolated/management VLAN)
- [ ] DHCP reachable on the PXE network (the PXE server must be the DHCP server OR DHCP proxy must be configured)
- [ ] PXE server running: `.\host\setup-pxe.ps1` on the WinBot host
- [ ] Golden WIM exported: `C:\WinBot\pxe\WinBot-Golden.wim`
- [ ] WinPE boot.wim built with Wyse NIC drivers: `.\guest\winpe\build-winpe.ps1 -Hypervisors wyse5070 -NICOnly`
- [ ] MAC address recorded (printed on chassis label, or visible in BIOS: System Information -> MAC Address)
- [ ] RAM verified: at least 4GB (check BIOS -> System Information -> Memory)

## Post-Deployment

After the Wyse PXE-boots, installs Windows, and provisions the WinBot API:

1. The node auto-enrolls with the host MCP server (via `POST /nodes/register`)
2. Verify enrollment: `Get-ChildItem C:\WinBot\nodes\` (should list `<hostname>.json`)
3. Test connectivity: use `mcp__WinBot__health` with `target: "<hostname>"`
4. For instant reset capability, enable UWF: deploy `enable-uwf.ps1` via `mcp__WinBot__run_python` or WinRM
5. The node is now ready for agent-driven automation -- all WinBot MCP tools work against it

## Troubleshooting

### Machine Powers On But No PXE Attempt

1. Enter BIOS (F2), verify Integrated NIC is "Enabled with PXE"
2. Check the Ethernet link LED on the RJ45 port (solid green = link, blinking amber = activity)
3. Try a different Ethernet cable
4. Check the switch port configuration (should be access port on the PXE VLAN, no 802.1X, no port security)

### PXE Gets IP But "No Boot Filename Received"

The DHCP server is not sending option 67 (boot filename). On the WinBot PXE host:

```powershell
# Stop and restart PXE in LinuxVM mode for full dnsmasq DHCP proxy
.\host\setup-pxe.ps1 -Stop
.\host\setup-pxe.ps1 -Mode LinuxVM
```

### WinPE Boots But "No Drives Found"

The Wyse storage is not visible to Windows PE:
1. Enter BIOS, confirm SATA mode is AHCI (not RAID)
2. Confirm the storage device is detected in BIOS -> System Configuration -> Drives
3. For eMMC: Windows PE includes a standard eMMC driver (sdbus.sys + sdbus2.sys). If missing, add them to the WinPE image.
4. For M.2 SATA: Standard AHCI driver handles this. No additional driver needed.

### Machine Boots to BIOS After WinPE Completes

Windows was applied to disk but the EFI boot entry was not created:
1. Check the `bcdboot` command in `winpe/deploy.ps1` -- should target the EFI partition
2. Verify the disk was partitioned as GPT (not MBR)
3. Manually boot from USB, open command prompt, run:
   ```
   diskpart -> select disk 0 -> list partition
   ```
   Confirm an EFI system partition (100MB FAT32) and a Windows partition exist.

### Windows Boots But Stuck at Login Screen

AutoLogon failed. This is rare with the three-layer defense (autounattend XML + offline registry + provision-time re-establishment), but if it happens:
1. Log in manually with username `winbot` and the VM password (from CredMan: `Get-WinBotCredential -Name vm-password -AsPlaintext`)
2. Check `C:\WinBot\logs\provision.log` for errors
3. Run `C:\WinBot\provision.ps1` manually
4. After provisioning completes, the API service should start and AutoLogon should work for subsequent boots
