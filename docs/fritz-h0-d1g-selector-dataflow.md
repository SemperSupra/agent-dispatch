# FRITZ H0-D1g selector dataflow

Authority: `SemperSupra/fritzbox-automation-private#75`.

D1f superseded the D1d parser-negative by showing an exact
`prom_getenv` assignment context followed by numeric parsing and
selector-controlled code. D1g uses whole-file bounded patterns rather than a
function-header parser to recover direct getter, numeric-parse, condition, and
branch-assignment relations.

String RHS values are represented only by SHA-256 + length; numeric values are
not published. The result does not by itself establish value-to-slot mapping,
partition layout, or rollback safety.
