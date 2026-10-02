# FRITZ H0-D1e selector table schema

Authority: `SemperSupra/fritzbox-automation-private#75`.

D1e decodes only the global initializer/table structures that own exact
`linux_fs_start` occurrences in the selected AVM MTD/TFFS open-source files.

Durable output is limited to:
- owning symbol and type identifiers;
- designated field names;
- identifier/enum-like references;
- callback-like symbol references.

Source lines, string values, numeric values/offsets, archive bytes, and HIL mutation
are excluded. This is structural recovery evidence, not slot-selection authority.
