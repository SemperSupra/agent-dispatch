# Go evidence-contract adversarial hardening: metamorphic R5

This independently testable change targets the public fictional Go evidence challenge, **not** real PST/OST source bytes, identity reconciliation, or a model reasoning result. Product DLE authority remains private Mail Evidence #39 and canonical source/attachments/overlap #1/#3/#4.

## Changes and admission decisions

- Reorder all eight source occurrences across 32 deterministic seeds, rerun each of the original 21 externally labeled typed questions (672 observations), and demand byte-for-byte equivalent typed answers and a stable corpus digest. Keep the original held-out gold untouched. This is not statistically independent new user-question generalization; it is a source-order invariance test.
- Add ten adversarial source-graph mutations. Reject duplicate native locator within one exact source archive, malformed capture time, two-node thread cycles, cross-account thread links, absent parent, mutated raw bytes, changed attachment bytes, duplicated attachment ID, unanchored claim quotation and invalid valid-at time.
- Recover persisted synthetic snapshots using JSON decoder `DisallowUnknownFields` and reject any appended non-whitespace JSON. Reject appended gold data as well, preventing silent schema evolution or extra untrusted records.
- All fixture inputs are public/fictional, Go standard library, no network calls or model APIs. Existing Go typed workcell `mail-evidence-go-v1` reruns independently on standard public GitHub Actions; adding `tools/mail-evidence-challenge/**` as an existing workflow path trigger ensures future code/gold changes do not bypass its CI.
- Native receipt must remain `ModelInference=false`, `NativePSTConformance=NOT_TESTED`; any failing metamorphic test makes the fixed profile FAIL, not a vacuous PASS.

## Operational tradeoffs

Native locator uniqueness here is scoped to the **same source archive ID and native locator**; independent repeated acquisitions have different source acquisition/archive keys and preserve their own occurrences. This is a reference-invariant toy, not a native PST identity derivation. Cycle rejection applies only to explicit thread-parent edges; do not infer such edges from Internet Message-ID. The naive O(n-squared) parent lookup is acceptable for this tiny fixture, **not** a production-scale graph index.

Go 1.23+ and `GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local` are required. Run the preserved offline tests using:
`cd tools/mail-evidence-challenge && go test -count=2 ./...`

No new scheduler, workflow or service deployment. No private Actions, private mail, paid model access or destructive archive edits. Revert only the incremental hardening if it causes incompatible behavior and preserve the first-failure test witness in DLE. Next model-based work requires a separately admitted free-tier inference route and true independent natural-language question evaluation.
