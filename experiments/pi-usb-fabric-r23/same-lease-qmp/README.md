# R23-A: Same-lease policy interlock — NOT actual QMP↔USB/IP completion

Authoritative private DLE #480, parent #477/#473. This **first increment** reuses the existing R26 releasegate.Gate, evidence.Bridge, Go Manager and heldledger with R22 Interlock/ExportGate. It adds no QMP protocol client, USB/IP implementation, or independent broker.

The public Go unit tests simulate an R26 QMP ACK and a fake export gate. They require a matching dynamic blue.Lease scope, valid guest DOWN and later UP, persisted HELD qmp-acked journal, and only one bind; ACK-only, guest-UP-only, wrong VM/epoch/generation, detach and restart/refusal are denied. This is **source-level qualification only**. The essential next step is a single THREE-kernel Linux QEMU run where the EXISTING R26 actuator delivers an actual QMP ACK for this EXACT dynamically allocated lease, QMP guest UP is observed independently, then native ConfigFS VUDC rebind and B attach proceed. Until then REAL_QMP_SAME_LEASE_USBIP=NOT_TESTED.

DO NOT infer production trust from public R26 test MAC, TOFU guest key, fake UDC, or synthetic QMP ACK. No private paid GitHub minutes, production resources, physical Pi or auto-merge. Preserve original RED, source hash, CI jobs and explicit gaps.
