# personal-ops #189 native PowerShell qualification projection

This subtree is an execution-only, public-safe projection used to validate the synthetic
portable-workcell contract from the private infrastructure authority without checking out or
authenticating to the private repository from a public runner.

Projected inputs are intentionally limited to:
- two synthetic/example JSON fixtures;
- the deterministic Pester test that consumes only those fixtures;
- the exact repository PSScriptAnalyzer settings.

No live endpoint, host identity, credential, private source data, policy secret, enrollment
key, or runtime observation is projected. Results are also public-safe deterministic
validation evidence.

Exact source Git blob identities:
- profile: `6edc4bd0bad0335259ea812b17d9b23c2f2c82ba`
- receipt: `cf4d545452149a7a84d5543f6858e43fa1787c31`
- Pester test: `8625caecf2faa9ce0123824176bc9d9174ac7aae`
- analyzer settings: `79f597d10545ccfa13aac0f66452e40d1acad097`

The runner must verify those Git blob identities before executing. This public branch is an
execution/evidence lane only; project authority remains in personal-ops #97/#98 and
infrastructure issue/PR #188/#189.
