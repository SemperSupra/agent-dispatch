# FRITZ E2-D8 rc.net caller binding

Authority: `SemperSupra/fritzbox-automation-private#72`.

D8 follows the generic `svctl <verb> $1` contract back across exact init/boot callers of
`rc.net`. It emits only normalized argv shapes and mechanically safe literal/variable
bindings. Raw shell lines and arbitrary values are excluded.

A later R7 start operation is admitted only if D8 resolves a concrete service or unit
operand through exact shipped caller semantics.
