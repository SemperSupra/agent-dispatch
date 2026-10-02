# FRITZ E2-D9 shell include/function graph

Authority: `SemperSupra/fritzbox-automation-private#72`.

D9 follows shell source/include edges and function calls across the exact init surface so
a generic `svctl start $1` function can be tied to a concrete caller operand without
publishing shell bodies. The result admits R7 only if a mechanically resolved service/unit
binding exists.
