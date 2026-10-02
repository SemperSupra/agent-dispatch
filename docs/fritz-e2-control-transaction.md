# FRITZ E2-R8 control transaction

Authority: `SemperSupra/fritzbox-automation-private#72`.

R8 repeats the already-authorized disposable emulator transaction from merged PR #157
exactly once, but adds sanitized controller-protocol metadata:
- Unix-socket syscall counts/byte totals, never payloads;
- fixed state-word markers only when those words also occur in the shipped supervisor/svctl binaries;
- pre/start/post exchange classification.

No new fixture, command, physical router contact, or HIL authority is introduced.
