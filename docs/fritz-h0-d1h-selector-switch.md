# FRITZ H0-D1h selector switch

Authority: `SemperSupra/fritzbox-automation-private#75`.

D1g proved `prom_getenv("linux_fs_start") -> p -> kstrtoul -> linux_fs_start -> switch`.
D1h reduces that exact switch into case labels, bounded assignments/calls, and
safe destination identifiers. Safe destination strings are emitted only from
the known destination LHS `new_name` and a restrictive identifier-like syntax.

The reducer also counts exact destination-name matches in independently selected
AVM partition/device-tree sources. A name match is not bootability, inactive-slot,
flash-offset, or rollback proof, and modified HIL remains blocked.
