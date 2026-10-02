# FRITZ E2-D12 libsvctl function slice

Authority: `SemperSupra/fritzbox-automation-private#72`.

D11 established that exact `/lib/libsvctl.so.1` carries the control transport.
D12 limits analysis to five exported functions: `_svctl_init`,
`_svctl_connect`, `_svctl_send_pkt`, `_svctl_send`, and `_svctl_read`.

Durable output contains only function sizes, instruction/branch counts, fixed
8/260/268 constant presence, and allowlisted call-reference names. Raw
disassembly, instruction addresses, arbitrary strings, and packet bytes are not
published.
