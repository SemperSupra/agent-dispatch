# FRITZ H0-D1c exact source symbol graph

Authority: `SemperSupra/fritzbox-automation-private#75`.

D1c reads only the small exact open-source AVM MTD/TFFS/PROM/GRX file set selected by
D1b. It emits symbol names, fixed seed-token membership, selected call edges, include
paths, and relevant macro names. It does not publish source snippets or macro values.

The output is a source-level graph for tracing `linux_fs_start` from boot/environment
state toward TFFS and AVM MTD/partition handling. It remains a structural source oracle;
partition layout, dual-slot safety, flash destinations, and rollback remain unaccepted.
