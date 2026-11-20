# R27-H25 — Durable journal pre-clear proof contract

This offline-only `recoveryprepare` package inspects a held ledger state and refuses to produce a prepared token unless *all* expected guest, VM, QMP and provenance flags are present. It intentionally contains **no** function that writes a journal, clears HELD, grants a lease, or repairs a broken record. Its replayable prepared hash can only be used to detect concurrent changes when re-reading a journal.

The boolean inputs are **not** attestation; they must be supplied later by independent, authenticated evidence. In particular, H23 proved signed guest recovery, QMP event and QOM absence only within an exposed TEST-ONLY second QMP monitor. H7 same-UID QMP bypass RED remains, so actual H23 evidence cannot set `NoHostileRawQMP` to true. Production key attestation, verified exclusive QMP control and epoch lineage also remain NOT_TESTED.

**Next controlled implementation** requires a source-verified host controller that owns QMP, checks actual receipts, persists an atomic fsynced release and safely readmits exactly one new lease; no current code here performs any of those actions.
