# FRITZ H0-D1n runtime-name expression recovery

Authority: `SemperSupra/fritzbox-automation-private#75`.

D1m recovered the exact `nametable` type/field shape and the unique
`urlader_name` row-selection relation, but the single recovered row still had
unresolved `runtime_name_0` and `runtime_name_1` initializer expressions.

D1n examines only those two field expressions. It publishes:

- safe identifier names and role classes;
- expression operator/shape classes;
- restrictive destination-like strings only when mechanically bound to one of
  the two runtime-name fields;
- unique local identifier/macro resolution when unambiguous;
- independent occurrence checks against the already-selected partition/device
  tree source slice.

It does not publish source snippets, arbitrary string literals, numeric flash
offsets, or mutation instructions. Even a complete selector-to-runtime-name
mapping is not bootability, inactive-slot, rollback, or modified-HIL admission
evidence by itself.
