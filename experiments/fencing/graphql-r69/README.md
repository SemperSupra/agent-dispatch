# R69 GitHub GraphQL conditional-ref capability (read-only)

A GitHub-hosted **public** pull-request test uses its short-lived **read-only** workflow token to make a GraphQL *query* that introspects the native `RefUpdate`, `UpdateRefsInput`, and `Mutation` types. It checks `beforeOid`, `afterOid`, qualified ref name, `force`, batch `repositoryId/refUpdates`, and the `updateRefs` operation. The task never invokes that mutation or changes refs. Run offline negatives with `python3 -m unittest discover -s experiments/fencing/graphql-r69 -p 'test_*.py' -v`.

**Qualification ceiling:** live schema presence, not atomic conditional writes or two-principal contention. No write token, protected ref/custody, rollback resistance, real reserve-and-effect transaction, credential provisioning, provider publication or production authority. A failed GraphQL API access remains HOLD. This does not make GitHub CAS the accepted external monotonic writer.

Public reference: GitHub GraphQL Git mutation docs, `updateRefs`, `RefUpdate.beforeOid`; this test independently probes the actual available API schema.

## R70 — Applicable branch-policy census (read-only)

As separate native read-only GitHub REST observations, `rules.py --native` retrieves applicable rulesets for the public repository's `main` branch and distinguishes a visible no-force-push rule (`non_fast_forward`), deletion prohibition and pull-request review rule. `classic.py --native` independently probes the *classic* branch-protection endpoint. A native 404 from classic protection is an observation (`NOT_VISIBLE`), **not** proof of every possible bypass, and rule-list emptiness alone cannot rule out classic branch protection. A 200 classic configuration is also not a tested force-push denial. The two outputs must be reconciled before making even a narrow public-branch claim. Neither API identifies a protected dedicated high-water ref with two admitted principals, nor proves denial of privileged reset/force writes. Only owner-approved live mutations can qualify that. Run the same unittest discovery command; `test_rules.py` and `test_classic.py` provide failure and interpretation controls.
