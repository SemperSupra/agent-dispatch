# FRITZ E2-D13 libsvctl MIPS PIC call edges

Authority: `SemperSupra/fritzbox-automation-private#72`.

D12 localized the fixed 8-byte constant to `_svctl_init` and 260-byte constant
to `_svctl_send_pkt`, but generic disassembly did not resolve PIC calls. D13
uses exact GNU readelf MIPS GOT metadata ephemerally and accepts an edge only when
an allowlisted GOT symbol is loaded into t9 and a bounded following `jalr t9`
is observed in one of the five admitted functions.

Durable output contains only function/symbol names, call-edge sets, and counts.
GOT offsets, instruction addresses, disassembly, arbitrary strings, and packet
payloads are excluded.
