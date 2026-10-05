# Physical preparation checklist

## DUT-A and DUT-B
- [ ] Label both devices.
- [ ] Photograph underside labels.
- [ ] Record MAC addresses, serial numbers, and current firmware.
- [ ] Connect management Ethernet.
- [ ] Keep the DUTs out of the production-gateway role.
- [ ] Do not overwrite both NAND firmware slots.

## HIL host
- [ ] Linux host available for R1/R2 automation.
- [ ] Python 3.
- [ ] OpenSSH client.
- [ ] Evidence workspace.
- [ ] Separate management and test networks preferred.
- [ ] Later R2: independent power control per DUT.

## Serial
- [ ] 3.3 V USB-TTL UART adapter(s).
- [ ] JST-PH 2.0 mm lead or safe insulated jumpers.
- [ ] 115200 8N1.
- [ ] GND/RX/TX only; no VCC connection.
- [ ] COM/tty device identified.

## First software action
If OpenWrt and SSH already work, run scripts/r1-readonly-remote.sh before flashing.
If OEM firmware is present, stop after recording the current state and preserve the alternate slot during the OpenWrt bootstrap.
