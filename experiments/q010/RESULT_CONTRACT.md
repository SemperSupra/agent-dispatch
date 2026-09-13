# Q0.10 result contract

PASS requires a fresh workflow run to:

1. observe the exact prior Q0.8 and Q0.9 workflow runs through GitHub's durable API state;
2. reacquire the exact final receipt artifacts from those earlier runs;
3. verify the pinned head SHAs, artifact identities/digests, successful job dispositions, and key semantic receipt invariants;
4. prove the observer run id differs from both source run ids;
5. emit a new final receipt stating that no hidden process memory, private context, model/inference, or external mutation was required.

Any inability to establish those facts must fail closed rather than infer continuity.
