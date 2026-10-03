# FRITZ H0-D1m nametable binding

Authority: `SemperSupra/fritzbox-automation-private#75`.

D1l reduced the exact selector expression to:

- selector 0 -> `nametable[i].runtime_name_0`;
- selector 1 -> `nametable[i].runtime_name_1`.

D1m examines only the `nametable` declaration/initializer and mechanically
recognized `nametable[i].field` uses. It recovers:

- table type class and safe field names;
- initializer row count;
- restrictive destination-like strings bound to `runtime_name_0/1`;
- a row-selection field only when exactly one non-runtime table field is used in
  a recognized string-comparison context.

Row bindings are emitted only when the selection field and both runtime names
resolve mechanically. Runtime names are then cross-checked against independently
selected partition/device-tree sources.

The table does not prove bootability, inactive-slot safety, exact flash offsets,
rollback safety, or modified-HIL admission. Those remain separate gates.
