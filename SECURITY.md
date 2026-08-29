# Security model

`agent-dispatch` is a public control-plane repository that can indirectly exercise authority granted to an external coding-agent account. Its security model therefore treats the Jules API credential and the set of Jules-authorized repositories as privileged capabilities.

## Primary threat

The main risk is a confused-deputy path: a caller able to cause the public workflow to submit arbitrary repository names, branches, prompts, or task files could use the dispatcher to spend Jules quota or direct Jules toward repositories the credential is authorized to access.

The dispatcher must therefore be incapable of expressing arbitrary provider operations from untrusted workflow input.

## Required invariants

1. Only approved operators may execute the secret-bearing workflow.
2. Workflow callers supply only opaque target IDs and approved task IDs.
3. The real repository and branch are loaded from a secret-backed allowlist and are never accepted as workflow input.
4. Prompts come only from reviewed task files registered in `config/tasks.json`.
5. Task paths must resolve beneath `tasks/`, must be Markdown files, and must not be symlinks.
6. Provider error bodies are not echoed to public Actions logs.
7. Public dispatch output must not contain private repository names, branches, Jules source IDs, Jules session IDs/URLs, activity content, patches, or private PR metadata.
8. No PR/fork-controlled code is executed in a job that receives Jules credentials.
9. The public control plane does not poll long-running Jules sessions.
10. Expanding target or task authority requires a reviewed policy/code change.

## Priority-ordered controls

### P0 — authority restriction

- Configure GitHub Workflow Execution Protection so only the designated operator or a very small trusted maintainer group can execute the dispatch workflow.
- Keep the in-workflow actor check as defense in depth, not as the sole authorization mechanism.
- Protect `main` using a ruleset/branch-protection policy requiring pull requests and review for security-sensitive changes.
- Require CODEOWNER review for `.github/workflows/**`, `scripts/**`, `config/**`, `tasks/**`, `SECURITY.md`, and `.github/CODEOWNERS`.
- Restrict direct pushes; block force pushes and deletion of the protected branch.
- Store the provider key and target mapping as secrets, not public variables.
- Use a protected `jules-dispatch` Environment with required reviewer approval while Phase 0 remains experimental.

### P1 — capability minimization

- `JULES_TARGETS_JSON` maps opaque aliases to the only repositories/branches this dispatcher may reach.
- `config/tasks.json` maps opaque task IDs to reviewed files.
- The adapter fails closed on missing or malformed target/task policy.
- Remove Jules Sources from the provider account when they do not need to be reachable by this dispatcher/key.
- Keep provider credentials scoped to this experiment where possible and rotate them after suspected exposure.

### P1 — workflow hardening

- Pin third-party actions to immutable commit SHAs.
- Disable persisted checkout credentials.
- Use the minimum `GITHUB_TOKEN` permissions (`contents: read`).
- Keep timeout limits short because GitHub Actions is only a control plane.
- Do not add `pull_request_target`, issue-comment, fork, arbitrary webhook, or other untrusted-content triggers to a secret-bearing workflow.

### P1 — public-log minimization

Public logs are part of the public attack surface. They must contain only enough information to know that dispatch was accepted or rejected.

Allowed output:

- opaque target ID;
- opaque task ID;
- boolean acceptance state;
- non-reversible local correlation value.

Disallowed output:

- private repository name or owner;
- private branch name;
- provider source identifier;
- Jules session ID or session URL;
- prompts when they might contain private context;
- activities, patches, diffs, commits, PR URLs/titles, or other private result metadata;
- provider response bodies on errors.

The public status workflow was removed because result/status output can inherently disclose private target metadata. Status/result inspection belongs in a trusted/private path.

## Pre-hardening Run 001 incident record

The first end-to-end dispatch experiment reached Jules successfully and Jules resolved the authorized private target, but Jules failed while cloning because the caller supplied a non-existent starting branch. No repository work, commit, branch, or pull request was created.

Security-relevant observations:

- the public Actions run log contained private target metadata and Jules session metadata;
- the Jules API credential itself was masked by Actions in the observed logs;
- the failed run produced no private source or patch content in the dispatcher repository;
- the caller-supplied branch failure mode has been removed: branch selection now comes only from the secret-backed approved-target policy.

Required residue cleanup for this pre-hardening run:

1. delete the historical public workflow runs that contain private target/session metadata;
2. verify the target repository has no Jules-created branch, commit, or PR from the failed run;
3. retain only the sanitized experiment outcome in repository documentation;
4. rotate `JULES_API_KEY` if policy requires credential rotation after any public metadata incident or if there is any evidence the secret itself escaped masking;
5. do not rerun the experiment until the P0 administrative controls and `JULES_TARGETS_JSON` are configured.

## Incident response

If unauthorized dispatch is suspected:

1. Disable the dispatch workflow or remove access to its protected Environment.
2. Revoke/rotate `JULES_API_KEY`.
3. Review Jules sessions and connected Sources for unexpected activity.
4. Review private target repositories for unexpected branches, commits, and pull requests.
5. Remove unneeded Jules Sources.
6. Delete public workflow runs containing sensitive metadata where possible.
7. Determine whether a workflow/code/policy change expanded authority and revert it.
8. Record a sanitized incident outcome without copying private provider/repository data into this public repository.

## Phase 0 release gate

Do not treat this dispatcher as safely reusable until all of the following are true:

- Workflow Execution Protection is configured;
- `main` protection and CODEOWNER enforcement are active;
- the `jules-dispatch` Environment is protected;
- `JULES_TARGETS_JSON` exists and contains only intended target aliases;
- a hardened dispatch confirms public logs contain no private target/session metadata;
- the Jules account's connected Sources have been reviewed for least privilege.
