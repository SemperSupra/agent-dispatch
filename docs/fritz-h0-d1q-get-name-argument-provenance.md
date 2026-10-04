# FRITZ H0-D1q get_name argument provenance

Authority: `SemperSupra/fritzbox-automation-private#75`.

D1p accepted one bounded producer edge in which `get_name` receives a
`nametable`/mtd-entry-derived argument. D1q follows only that edge.

The reducer records:

- `get_name` callsite cardinality for arguments that reference `nametable`;
- a sanitized argument expression skeleton;
- the enclosing function name and safe parameter names;
- only local function-parameter bindings or nearest lexical assignment
  candidates for non-member identifiers feeding that argument;
- local `get_name` definition signature metadata when mechanically present.

Nearest lexical assignment is candidate provenance only; it is not control-flow
or runtime execution proof. Receipts retain no source snippets, arbitrary string
literals, destination names, numeric flash offsets, or writable HIL instructions.

Typed partial, ambiguous, and negative outcomes are valid evidence. This rung
does not establish bootability, inactive-slot safety, rollback safety, or
modified-HIL admission.
