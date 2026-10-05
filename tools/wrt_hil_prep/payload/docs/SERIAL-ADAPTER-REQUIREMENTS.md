# Serial adapter requirements

The WRT3200ACM serial console uses 3.3 V TTL UART, not conventional +/-12 V RS-232.

OpenWrt documents:
- 115200 baud, 8 data bits, no parity, 1 stop bit.
- 3.3 V logic.
- 6-pin JST-PH 2.0 mm family connector.
- documented signals: pin 1 GND, pin 2 router TX, pin 4 router RX.

Connection:
- adapter GND -> router GND
- adapter RX -> router TX
- adapter TX -> router RX
- do not connect adapter VCC/power to the router

For eventual unattended R2 work, two independent adapters, one per DUT, are preferred. One adapter is enough for sequential manual bring-up.

Check your parts bin for explicitly 3.3 V-capable FT232/FTDI, CP210x, or CH340 USB-TTL adapters and JST-PH 2.0 mm leads.

References:
- https://openwrt.org/toh/linksys/wrt3200acm
- https://openwrt.org/toh/linksys/wrt_ac_series
- https://openwrt.org/docs/techref/hardware/port.serial
