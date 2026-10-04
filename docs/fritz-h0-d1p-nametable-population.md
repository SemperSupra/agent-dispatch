# FRITZ H0-D1p nametable population recovery

Authority: `SemperSupra/fritzbox-automation-private#75`.

D1o established that the target-relevant symbol in
`drivers/mtd/avm/avm_mtd.c` is a declaration of `struct mtd_entry nametable`
with no initializer. D1p therefore inspects only that exact source file for the
next mechanically provable producer edges:

- declaration shape (pointer/array/storage class);
- direct assignments to `nametable`;
- writes to `nametable[index].field`;
- function calls that receive `nametable` as an argument.

Receipts contain only safe identifier/role classes, operator classes, argument
indexes, and counts. They do not retain source snippets, arbitrary literal
contents, numeric flash offsets, or writable HIL instructions.

A producer edge is provenance evidence only. It does not establish bootability,
inactive-slot safety, rollback safety, or modified-HIL admission.
