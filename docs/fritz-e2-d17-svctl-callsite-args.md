# FRITZ E2-D17 svctl callsite argument classes

Authority: `SemperSupra/fritzbox-automation-private#72`.

R9 proved a stable wire distinction: `status` and `start` share the same
260-byte request object while their first 8-byte request chunks differ. D11-D16
localized the exact libsvctl transport path but did not establish protocol enum
values or packet fields.

D17 performs one bounded static pass over exact `/bin/svctl`. It mechanically
recovers same-basic-block PIC callsites into selected libsvctl entry points and
emits only argument-setup **classes** for MIPS `a0..a3` (for example immediate,
register move, memory load, base-plus-immediate). It also retains only the
already-admitted fixed `start` and `status` token counts.

D17 explicitly does not associate a verb with a callsite, publish argument
values, infer protocol enums, or infer packet layout. If the static callsite
classes do not uniquely explain the R9 wire distinction, the next step is an
instrumented-emulator function-entry observation that records only argument
classes/digests.
