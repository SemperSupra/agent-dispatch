# FRITZ H0-D1q get_name hypothesis falsification

Authority: `SemperSupra/fritzbox-automation-private#75`.

D1q was opened to follow a D1p candidate that appeared to show a `get_name`
invocation receiving a `nametable`-derived argument. Its first exact run
falsified that premise: the candidate was a local function-definition signature,
not a callsite. Corrected D1p now reports no local population/producer edge.

D1q is therefore retained as a bounded falsification oracle. It records:

- real `get_name` callsite cardinality for arguments that reference `nametable`;
- local `get_name` definition signature metadata;
- a sanitized argument expression skeleton only when a real callsite exists;
- enclosing-function metadata and only local parameter/nearest lexical assignment
  candidates for non-member identifiers feeding such a callsite.

A zero-callsite result is an admissible typed negative, not a harness failure.
Nearest lexical assignment remains candidate provenance only; it is not
control-flow or runtime execution proof.

Receipts retain no source snippets, arbitrary string literals, destination names,
numeric flash offsets, or writable HIL instructions. This rung does not establish
bootability, inactive-slot safety, rollback safety, or modified-HIL admission.
