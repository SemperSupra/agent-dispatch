# FRITZ E2-D7 activation semantics

Authority: `SemperSupra/fritzbox-automation-private#72`.

D7 answers the activation question exposed by R6 without starting any service. It reduces
only fixed allowlisted command verbs/object words from the exact shipped `supervisor` and
`svctl` binaries, plus normalized `svctl` and `supervisor` command shapes from exact
boot/init text.

Raw binary strings, init lines, firmware/rootfs bytes, and arbitrary literals are never
published. The output determines whether a bounded R7 start command is evidence-backed.
