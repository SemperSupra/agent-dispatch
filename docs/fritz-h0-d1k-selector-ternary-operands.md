# FRITZ H0-D1k selector ternary operands

Authority: `SemperSupra/fritzbox-automation-private#75`.

D1j located the actual selector-bearing `new_name` assignment: it is after the
accepted selector switch, outside that switch's lexical enclosing block, and has
an equality + ternary shape. Its arms are not direct safe strings.

D1k decodes only selector-bearing `new_name` assignments. Each ternary arm is
classified as a restrictive destination string, a safe identifier, or an opaque
expression. A safe identifier is promoted to a destination only when the
selected source contains exactly one direct string write for that identifier
(and no string macro), or exactly one direct string macro and no writes.
Ambiguous identifiers remain unresolved.

A selector-value mapping is emitted only when the condition is mechanically
normalized over the accepted `{0,1}` selector domain and both arms resolve to
destinations. A stronger crosschecked classification additionally requires every
mapped destination to occur in independently selected partition/device-tree
sources.

Name mapping is not bootability, inactive-slot safety, flash-offset, recovery,
or rollback proof. Modified HIL remains blocked.
