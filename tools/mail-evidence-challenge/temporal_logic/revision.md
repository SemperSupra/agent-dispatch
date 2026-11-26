# Explicit scoped temporal revision reference

The existing four-valued source support resolver is retained. A reviewed revision annotation names two actual claim occurrences, same tenant, same source lineage and same predicate, and a quote anchored in the successor source. No automatic "latest wins" rule, inferred lineage, NLP extraction, or objective truth claim.

The projection suppresses the predecessor only in the overlap of the two claims' half-open valid intervals and only when both sources were acquired by the requested knowledge cutoff. Outside that overlap it remains eligible. All original source bytes and claims remain unchanged. Independent counterclaims cannot be removed by this conservative same-lineage policy; cycles, forged anchors, cross-tenant or cross-predicate relationships fail closed. Audit witnesses name each applied relation. This interval-overlap policy is not an unconditional legal retraction or a complete belief revision engine. It is a bounded synthetic adapter, not production authorization for editing claims or mail.

Tests exercise late acquisition, historical queries, expiry boundaries, independent contradiction, foreign tenant, order permutations, chain replay and invalid revision edges. Use existing module tests. No actual email, PST, model inference, paid resource or release claim.

## Review-recorded knowledge clock

Revision.RecordedAt is mandatory, RFC3339, and cannot precede the acquisition of either linked source. Source acquisition is not review/annotation time. A later reviewed relationship cannot change a prior knowledge-time query: its suppression and audit witness become visible only from its own recorded timestamp. This is a caller-supplied reviewed annotation clock, not authenticated append-only review storage, external reviewer authorization or retroactive source modification.
