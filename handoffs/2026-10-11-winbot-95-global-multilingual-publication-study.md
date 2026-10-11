# WinBot 9.5 workflow-publication blocker — historical and multilingual survey
Date: 2026-10-11. Authority: SemperSupra/agent-dispatch-private#406. This is read-only research, not launch authorization.

## Result
YES: direct GitHub Actions workflow publication and execution have worked in the same public Agent Dispatch repo and across other projects. The current error is a tool safety refusal before a demonstrated GitHub HTTP response; GitHub App permissions and branch rules remain separate, unverified hypotheses. Do not treat prior successes as proof the current credential/scopes are unchanged.

## First-party evidence, directly reconciled in GitHub
- SemperSupra/agent-dispatch PR #53, HEAD 7bc3feb433f40de6f7ce0b9593cd3093a729af6e: actually ADDED .github/workflows/windows-2025-hyperv-lifecycle.yml, blob 45fc3c7364895eb68ad0488f9380c0074048b8fd. Run 36688159026: Hyper-V lifecycle on windows-2025 SUCCESS, including cleanup.
- Same repo PR #379 has SEVEN .github/workflows files in patch; run 37866844289 executed REAL sealed nested Windows A-only, negative only at guest bootstrap (ORACLE_FAILURE, RC36). Thus workflow and guest execution mechanisms have worked.
- mark-e-deyoung/WinBot PR #104 added or modified two workflow files. Windows run 37893964564 PS5.1+PS7 PASS.
- SemperSupra/model-spelunker PR #6 includes .github/workflows/mvp-rep.yml. Run 34961560499 SUCCESS with model inference and evidence.
- SemperSupra/android-artifact-recovery-private commit fb7394a2c40f163cb92ebbfe19d298eb0940902e adds workflow files for JOYHUB acquisition/analysis. Commit observed; no assertion that particular workflow job succeeded.
- The provenance above proves project/repo capability, NOT the identical connector identity/token or future publishability.

## Specific current boundary
- Owner exact ONE A-only approval: #406 comment 6076235901; frozen source 33f047df21269d8556b47f3cda7122ca22ca88ad, projection SHA256 270ab93819eb7f0a1c95bdb38f27233af6396bd9cd978aedc47f734ae150deee.
- Dormant qualified wrapper Git blob 7574e3e5a5fe8b4dc09b06cbc444c6657f5a99d7.
- ChatGPT GitHub create_file attempt returned the tool error "This tool call was blocked by OpenAI's safety checks", without GitHub HTTP 403/422 response. A later attempt to expand non-workflow tests also hit this safety gate, while numerous workflow writes succeeded.
- Current GHA run 38103864971 PASS for 82-file full projection, PS7/PS5.1, 20 anti-replay tests. Read-only workflow observation ABSENT_404. Owner's one-run approval UNUSED; no new guest.

## Global multilingual search: positive, negative and latent concepts
EN community: https://github.com/orgs/community/discussions/35410 and https://stackoverflow.com/questions/66643917 document a DIFFERENT failure signature, the actual GitHub server message "refusing to allow a GitHub App to create or update workflow ... without workflows permission". Reported resolutions: GitHub App Workflows:write accepted at installation/org and deliberately scoped PAT/App tokens, but anecdotes disagree whether actions:write helps. Never prescribe a broad token without proving it is required.
EN counterexample: https://github.com/orgs/community/discussions/108402 shows even a GitHub App with Contents/Workflows write can fail a special fork PR update operation.
EN docs: https://docs.github.com/en/rest/repos/contents distinguishes classic workflow-scope tokens and fine-grained permission alternatives; https://docs.github.com/en/enterprise-cloud@latest/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app explains accepted GitHub permissions headers on actual HTTP failures. https://docs.github.com/en/actions/concepts/security/github_token states events caused by an in-workflow GITHUB_TOKEN generally do not trigger additional runs — an AFTER-WRITE trap, unlike our missing-file state.
JA practitioner: https://qiita.com/suin/items/75f42ea9ca752854afcd distinguishes Actions runs vs GitHub App Workflows file-edit permissions.
ZH GitHub official: https://docs.github.com/zh/actions/reference/workflows-and-actions/workflow-syntax separates job GITHUB_TOKEN permissions from GitHub App installation scopes.
DE GitHub official: https://docs.github.com/de/rest/actions/permissions explains organization, repository and token permission layers.
ES GitHub official: https://docs.github.com/es/actions/reference/workflows-and-actions/workflow-syntax clarifies least-privilege job tokens and inherited org restrictions.
PT GitHub official: https://docs.github.com/pt/actions/reference/workflows-and-actions/workflow-syntax likewise distinguishes job permissions and broader policies.
NOTE: ZH/DE/ES/PT pages are localized versions of ONE GitHub primary authority, NOT independent corroborations.
GitHub rulesets: https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/managing-rulesets-for-a-repository gives branch ruleset diagnostics and read-only insights.
New latent capability as of 18 June 2026: https://github.blog/changelog/2026-06-18-control-who-and-what-triggers-github-actions-workflows/ announces preview actor/event-based GitHub Actions execution-protection rulesets with evaluate mode. Potential long-term separation of code publication authority from runner-launch authority; no claim it is enabled for our account.

Positive: previously working direct workflow writes, Windows/Hyper-V real execution, immutable graph identities and bounded CI. Negative: confusing tool safety gate with GitHub 403, assuming permissions unchanged, over-granting tokens, GitHub in-workflow token trigger suppression, ruleset protection, substituting code or actors merely to evade rejected safety write. Latent: consent of GitHub App installation scope, event/actor execution rulesets, distinct build/publish/execute identities and read-only receipt classification.

## Prioritized corrective decision procedure
1. Inspect original actor identity and app/permission scope for PR #53 and prior PR #379 heavy workflow commits; compare to present connector identity. Do not assume old token class remains.
2. Request legitimate tool/platform review of exact rejected create_file operation, repository/branch/path and qualified blob. Confirm tool rejection before GitHub, or receive a true outbound HTTP status.
3. If platform approves the operation, check GitHub App Workflows permission and org installation consent, then ruleset insights only if an actual GitHub authorization/branch rejection occurs. Minimize scope.
4. Only through a permitted publication action, read back the exact Git blob, refresh heavy-lane census, launch at most ONE owner-approved A-only, gather Python/gsudo/OpenSSH/authenticated API and zero-residue evidence. Never retry/merge/seed/terminal without separate authority.

No publication, no guest launch, and no changes to approved source/projection occur in this research pass.
