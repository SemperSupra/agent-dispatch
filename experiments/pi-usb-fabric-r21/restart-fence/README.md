# R21-A restart-fence workcell — DLE #467

Independent execution lane based on R20-A exact source `5d77145076731740b49acfc05dc1a8dc022b6fed`. This branch must remain stacked, draft and unmerged.

## Actual acceptance (not yet qualified)

1. Boot actual provider/A/B separate QEMU Linux kernels, import real HID at A, observe kernel evdev down/up.
2. VUDC unbind must precede A detach; native B direct attach denied, provider still reachable.
3. Existing Go Manager persists HELD with test-only simulated QMP ACK; SIGKILL the actual Go PID, read disk HELD after kill.
4. **Start a NEW Go process using the SAME journal path**, witness reloaded HELD and no authorization signal, then issue a fresh B native USB/IP attach probe and require no exported VUDC or ghost VHCI.
5. Wrong generation, transport-only, stale guest release and corrupt journal remain deny-only and cannot modify a valid held journal.
6. Only a fresh scoped test-only release can authorize export restoration, a *new* generation, and B's genuine evdev.

This README is a test design only. R20-A's passing process-kill result is NOT restart qualification. The R21-A tests need code and first-hand CI receipts before changing the DLE state. Use a dedicated workflow, separate subtree, public/free runner, strict timeouts, independent no-taint check. No production guest attestation, host crash/power loss, real QMP, physical Pi, Windows/macOS or merge claimed.
