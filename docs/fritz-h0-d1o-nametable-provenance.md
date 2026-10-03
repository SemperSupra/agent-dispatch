# FRITZ H0-D1o nametable provenance scan

Authority: `SemperSupra/fritzbox-automation-private#75`.

The corrected D1m/D1n exact reps proved that the selected `avm_mtd.c`
source contains real `nametable[i]` field uses but no declaration-shaped local
initializer. D1o therefore searches the exact pinned AVM OSP source corpus for
where `nametable` and `mtd_entry` are actually declared or defined.

The reducer publishes only:
- source file paths;
- masked identifier occurrence counts;
- declaration-shape counts and coarse storage/type classes;
- whether a declaration candidate contains an assignment or braced initializer.

No source snippets, arbitrary string literals, numeric flash offsets, or mutation
instructions are persisted. Declaration-shape matches are candidate provenance,
not bootability, inactive-slot safety, rollback safety, or modified-HIL authority.
