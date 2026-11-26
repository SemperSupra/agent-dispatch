# Mail evidence R6 — temporal look-ahead and contradictory-state negative oracles

This change strengthens the **fictional Go typed evidence evaluator**, not the private product's authoritative temporal model, native PST reader, or model answer pipeline.

## Failure mode and behavior

The prior `fact-asof` rule selected a maximum `Claim.ValidAt` not later than the requested cutoff, but could use an observation whose `CapturedAt` was later than the question's cutoff. It could also choose an arbitrary source by lexicographic ID when two distinct messages asserted contradictory values at the same latest valid time. Neither selection is safe for a query meaning **"what was known as of this date?"**.

For that explicit interpretation, the updated evaluator requires both `Claim.ValidAt <= cutoff` and `SourceOccurrence.CapturedAt <= cutoff`. If equally recent valid-time claims disagree, it **ABSTAINS** with no invented source citation. If they agree, it retains source-occurrence identity and a byte-anchored citation. An old observation acquired later can establish a historical fact for a later *knowledge-as-of* query but must not retroactively change the previously available evidence.

**Semantic limitation:** "What was true on that date, according to everything we know today?" is a different query mode and must not be silently mapped to the knowledge-as-of rule. Production temporal retrieval should represent at least event-valid time, observation/acquisition time, query knowledge cutoff, and conflict state as distinct dimensions; today's toy only tests one bounded interpretation. Do not replace the Mail Evidence canonical packet or dedup/version models.

## Independent adversarial qualification

Added separate tests in `tools/mail-evidence-challenge/temporal_conflict_test.go` for: (a) future-acquired historical claim excluded from earlier query and included after acquisition; (b) simultaneous contradictory values at same valid time force abstention even after source row reversal; (c) late-discovered contradiction cannot rewrite earlier knowledge, but must invalidate a later unqualified claim; (d) original 21 EN/DE/TH typed gold remains unchanged. No model, no private source data, no library dependency, no environment install.

Run `GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly go test -count=2 ./...` from `tools/mail-evidence-challenge`. The pre-existing four-core public GHA matrix already triggers on this directory and emits a provider-bound independent receipt. Zero external/paid model calls, no new workflow or scheduler. Failure should be preserved as an exact red DLE finding, not silently reduced by changing task labels.
