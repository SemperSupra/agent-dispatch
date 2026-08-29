# Security model

`agent-dispatch` is a public control-plane repository that can indirectly exercise authority granted to an external coding-agent account. Its security model therefore treats provider credentials and provider-authorized repositories as privileged capabilities.

## Primary threat

The main risk is a confused-deputy path: a caller able to cause the public workflow to submit arbitrary repositories, branches, prompts, or task files could use the dispatcher to exercise authority beyond the intended task scope.

The public dispatcher must therefore be incapable of expressing arbitrary provider operations from untrusted workflow input.

## Required invariants

1. Only approved operators may execute the secret-bearing workflow.
2. Workflow callers supply only opaque target IDs and approved task IDs.
3. The real repository and branch are loaded from secret-backed policy and are never accepted as workflow input.
4. Prompts come only from reviewed task files registered in `config/tasks.json`.
5. Task paths must resolve beneath `tasks/`, must be Markdown files, and must not be symlinks.
6. Provider error bodies are not echoed to public Actions logs.
7. Public dispatch output must not contain private repository names, branches, source IDs, session IDs/URLs, activity content, patches, or private PR metadata.
8. No PR/fork-controlled code is executed in a job that receives provider credentials.
9. The public control plane does not poll long-running provider sessions.
10. Expanding target or task authority requires a reviewed policy/code change.

## Required controls

- Restrict workflow execution to approved operators.
- Protect the default branch and require review for security-sensitive changes.
- Protect the secret-bearing deployment/environment boundary during experimental operation.
- Store provider credentials and private target mappings as secrets, not public variables.
- Pin third-party actions to immutable commits where practical.
- Disable persisted checkout credentials.
- Use minimum `GITHUB_TOKEN` permissions.
- Keep runner timeouts short because Actions is only the control plane.
- Do not add untrusted-content triggers to a secret-bearing workflow.

## Public log policy

Allowed output should be limited to non-sensitive acceptance/correlation information using opaque identifiers.

Public output must not contain private repository or branch names, provider source identifiers, session identifiers/URLs, prompts containing private context, activities, patches, diffs, commits, private PR metadata, or provider response bodies that may disclose account/source details.

Status/result inspection belongs in a trusted/private path.

## Credential handling

Do not commit provider credentials or target mappings. Treat any credential exposed to an agent execution environment as available to code executed in that environment. Prefer low-privilege, quota-limited, task-specific, or brokered credentials for future external integrations.

## Incident response

If unauthorized dispatch or metadata disclosure is suspected:

1. disable the dispatch path or remove access to the protected secret-bearing environment;
2. revoke/rotate affected credentials if necessary;
3. review provider sessions and authorized sources for unexpected activity;
4. review target repositories for unexpected branches, commits, or pull requests;
5. remove unneeded provider source authorizations;
6. remove public workflow logs containing sensitive metadata where practical;
7. revert any workflow/code/policy change that expanded authority;
8. record only a sanitized public outcome; keep detailed operational incident history in the private companion repository.

## Release gate

Do not treat this dispatcher as safely reusable until operator restriction, branch/ruleset protection, secret/environment protection, private target policy, log minimization, and least-privilege source authorization are active and verified.
