# Scoped mail intelligence reference pipeline

This public-synthetic Go workcell joins the existing immutable occurrence ledger,
typed fact-as-of resolver and independent answer/citation gate. No additional
executor, model server, corpus authority, or scheduler is introduced.

Flow: validate and detach ledger -> explicit disjoint source partitions ->
tenant and knowledge-cutoff projection -> typed reference answer/citation ->
independent frozen gold evaluator. Model-context output contains only raw
visible text, source IDs, hashes, acquisition clocks and question metadata.
It never carries oracle-side expected values, claims, attachment bytes, or the
full source catalog. Context digests bind the projected input, not actual
inference. The scope/tenant is pre-authorized by the caller; no authentication
or production ACL enforcement is claimed.

Run existing module tests: `GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -count=2 ./...`.
The original typed resolver uses one combined cutoff; the separate
valid/effective-time vs acquisition-time research contract is not replaced.
The independent integration fixtures include English, German and Thai,
reacquired bytes, a foreign tenant, revisions, abstention and exact UTF-8
citations. The abstain-only control is deliberately negative, not an
optimized policy or competitive LLM. The held-out fixture has four questions,
not a statistically adequate semantic benchmark. No native PST/OST, actual
mail, model inference, model training, or automatic promotion is qualified.
