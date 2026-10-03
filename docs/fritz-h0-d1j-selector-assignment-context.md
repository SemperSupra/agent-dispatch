# FRITZ H0-D1j selector assignment context

Authority: `SemperSupra/fritzbox-automation-private#75`.

D1i falsified the narrow hypothesis that a selector-bearing `new_name`
assignment exists in the same enclosing block after
`switch(linux_fs_start)`. D1j removes that location assumption and inventories
`new_name` assignments across the exact selected AVM MTD source.

Durable evidence is limited to:

- assignment counts;
- relation to the accepted selector switch: before / inside / after;
- whether the assignment is in the same enclosing block as the selector switch;
- selector-reference counts and operator classes on the assignment RHS;
- restrictive destination-like strings mechanically bound to `new_name`;
- whether a simple selector ternary shape is mechanically recognizable.

D1j does **not** bind selector values 0/1 to destinations. That is a later step
only after the assignment context is located. Name matches in partition or
device-tree source are corroboration, not bootability, inactive-slot, flash,
recovery, or rollback proof. Modified HIL remains blocked.
