# R72 — disposable public GitHub ref-update precondition qualification

This single public experiment branch is NOT a protected high-water witness, dispatcher, deployment, or production authority. It tests connected GitHub update_ref behavior on an isolated synthetic ref.

## Bounded oracle
- Start at publicly pinned main and add this documentation on a new branch; do not change main or other actor branches.
- Prepare synthetic empty-tree descendant commits Q -> A -> B on this experiment ref.
- Advance Q -> A using expected_sha=Q and force=false. Verify the ref equals A.
- Attempt A -> B with STALE expected_sha=Q despite B fast-forwarding A. It must reject; if it succeeds this is EXPECTED RED to the connector's expected-head contract. Do not repair or mask it.
- Only after independent readback still shows A, advance A -> B with expected_sha=A and force=false and verify.
- No blind retry after unknown provider ACK; observe before continuation.

## Qualification ceiling
One GitHub connector identity, one nonprotected public experiment branch. A sequential stale-head rejection cannot prove indivisible provider CAS under concurrent clients, cross-identity exclusivity, independently nonrollbackable high water, signed witness, force-denial, production effect or budget. The connector may enforce preconditions before invoking GitHub rather than inside a provider-native atomic mutation. Exact receipts go to the private governing DLE; this public README has no protected workset locator. All release holds remain.
