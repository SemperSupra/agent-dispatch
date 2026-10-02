# FRITZ H0-D1b boot-selector / TFFS / MTD reduction

Authority: `SemperSupra/fritzbox-automation-private#75`.

This rep consumes the exact pinned AVM 7590 / FRITZ!OS 8.25 OSP archive and scans only
the direct source domains already admitted by H0-D1a: GRX500 MIPS boot, Lantiq DTS,
AVM PROM/config, TFFS, and Linux MTD.

Durable output contains only source paths, fixed-token counts, domain classification,
and token-cooccurrence relationships. It publishes no source snippets or archive bytes.

The result is a narrowing oracle for the next exact partition/boot-selector model.
It does not itself establish A/B safety, flash destinations, or rollback semantics.
