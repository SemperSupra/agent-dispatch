# Temporal DOE R1-B — sourced four-valued assessments and justification DAG

Authority: Mail Evidence [historical identity #4](https://github.com/SupraShellScripts/mail-evidence-private/issues/4) and [DOE #39](https://github.com/SupraShellScripts/mail-evidence-private/issues/39).

## Reuse versus implementation

This **tiny Go standard-library contract** qualifies the boundary between immutable claims, Belnap-style four-valued evidence support, and a conservative explanation DAG. It does **not** implement a production ATMS, AGM belief-revision theory, Event Calculus, Prolog, or Graphiti. Compare mature reasoning systems against this same independent oracle before choosing a production engine. Do not turn an exploratory rule evaluator into a bespoke general-purpose solver.

An immutable `Source` has source occurrence ID, lineage, tenant, original text bytes/hash, authored and acquired timestamps. A `Claim` has source ID, proposition, polarity (support or refute), modality (actual versus planned), exact source quote, and effective interval. A `Rule` has fixed tenant, identified policy hash, conclusion and explicit premises. No rule text or arbitrary code is generated from email content.

**Separate clocks:** `validAt` queries historical applicability; `knowledgeAt` filters evidence based on when it was acquired. Derived status denotes evidence-support balance, never objective truth. For a proposition and cutoff pair: no applicable source = NEITHER; positive only = SUPPORTED; negative only = REFUTED; both = BOTH. Copies of the same original source retain *each* source ID/citation but count as one lineage in support totals.

**Conservative derivation:** A reviewed rule fires only when all its premises are unambiguously supported and none is refuted. An unresolved contrary source quarantines dependent conclusions; no newest-source-wins override. A rule DAG is cycle-checked and evaluated to a deterministic fixed point independent of source/rule ordering; derived assessments retain rule ID, policy hash, premises, original source IDs, and lineage IDs. A later contradictory source changes assessments with a later knowledge cutoff but cannot retroactively rewrite an earlier query.

## Adversarial qualification

Native Go tests exercise: late-discovered contrary claim, extra archive copy with duplicate lineage, actual versus prospective event, beta cross-tenant isolation, neither/both/supported/refuted, 2-stage derived conclusion and its source proofs, late retraction preventing derived release, identical result under reversed rule ordering, and refusal of altered source bytes, invalid interval/modality, unanchored quotes, unknown source IDs, policy cycles and invalid source timestamps. Existing public typed `mail-evidence-go-v1` profile automatically runs `go test -count=2 ./...` without additional workflow or dependencies. No network, private source, model inference, database service or scheduled cloud job.

## Open architecture and limitations

- Reuse W3C PROV-O for source/activity/derivation identities and OWL-Time interval vocabulary; avoid inventing generic fact/provenance standards.
- Evaluate Prolog/s(CASP Event Calculus and Graphiti on identical frozen fictional gold before adoption; a graph's invalidated edge must not delete a source fact.
- The lightweight Go evaluator is intentionally small and scans sources and rules; large knowledge graphs need indexes and mature engines.
- The lineage key is a synthetic fixture assumption, **not a verified identity match across PST exports**. Producing one from similar Message-ID or text would violate #4.
- Evidence-support polarity and temporal applicability are not equivalent to the physical-world truth of the asserted fact, legal authority, epistemic confidence, or ontological reasoning.
- No regression score in this lane is LLM accuracy, native PST parity, or approval for autonomous memory mutation. All derived policies remain versioned and reviewable.
