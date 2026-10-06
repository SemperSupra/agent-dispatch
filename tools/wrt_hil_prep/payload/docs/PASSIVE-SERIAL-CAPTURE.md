# Passive Serial Capture Contract

Status: source-qualified helper for R1/R2 observation; no actuation authority.

The WRT serial helpers configure the **host-side** USB-UART for 115200 8N1 and then read incoming bytes for a bounded window.

Invariants:
- GND/RX/TX only; no VCC.
- No serial payload bytes are transmitted by the helper.
- DTR and RTS are disabled on Windows; Linux uses no hardware/software flow control.
- The transcript is SHA-256 hashed and accompanied by machine-readable capture metadata.
- When the serial reducer is available, the transcript is reduced to `rdte-wrt-serial-observation/v1`.
- Opening/configuring the host UART is not permission to interrupt U-Boot, send commands, change boot state, or perform any physical mutation.

Current authority remains `SENSOR_ONLY_NO_ACTUATION` / physical campaign phase `R1_READ_ONLY`.
