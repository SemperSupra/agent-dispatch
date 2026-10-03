# FRITZ H0-D1i selector to destination mapping

Authority: `SemperSupra/fritzbox-automation-private#75`.

D1h established that the exact AVM MTD source normalizes
`linux_fs_start` to the domain `{0,1}` and that the destination assignment is
downstream of the switch. D1i examines only the post-switch region in the same
enclosing block and only assignments to the already observed `new_name`
destination identifier.

The reducer accepts a selector-to-destination mapping only when a simple ternary
condition can be normalized exactly over selector values 0 and 1 and both arms
are restrictive destination-like strings. It then cross-checks those destination
names in independently selected AVM partition/device-tree sources.

A mapping is not bootability, inactive-slot safety, flash-offset, recovery, or
rollback proof. No source snippets, arbitrary literals, physical-router contact,
or mutation authority are introduced. Modified HIL remains blocked.
