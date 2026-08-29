# Security model

`agent-dispatch` is a **public control plane with private downstream authority**. The public repository must therefore be treated like a small privileged gateway, not like a normal build repository.

## Security objective

A public workflow may request a narrowly pre-approved operation from Jules, but public repository contents, workflow inputs, logs, forks, pull requests, and untrusted contributors must not be able to expand the set of private repositories or tasks that Jules may access.

## Threat model

The high-value credential is `JULES_API_KEY`. Its effective authority is the set of repositories connected to the associated Jules account. A second sensitive value, `JULES_TARGETS_JSON`, maps opaque public target IDs to private repository names and pinned starting branches.

Primary threats, in priority order:

| Priority | Threat | Mitigation |
| --- | --- | --- |
| P0 | Arbitrary actor uses the workflow as a confused deputy | GitHub Workflow Execution Protection; workflow actor guard |
| P0 | Authorized dispatcher can target any Jules-connected repository | Secret-backed target allowlist; workflow accepts only opaque target IDs |
| P0 | Arbitrary prompt/path is supplied to Jules | Fixed task registry; task files constrained to `tasks/*.md`; no free-form prompt input |
| P0 | Workflow/script is modified to exfiltrate secrets | Protect `main`; require reviewed PRs; CODEOWNERS on workflows/scripts/config/tasks |
| P1 | Private target/session/PR metadata leaks through public logs | Opaque target IDs; sanitized API errors/output; no public status workflow |
| P1 | Third-party action compromise captures credentials | Pin Actions dependencies to immutable commit SHAs; minimize steps |
| P1 | Secret is released without an explicit policy gate | `jules-dispatch` GitHub Environment; configure required reviewer while experimental |
| P2 | Future event triggers expose secrets to untrusted content | Keep the secret-bearing workflow manual-only; prohibit `pull_request_target`, issue-comment, fork, and PR-content execution paths |
| P2 | Provider authority silently expands | Periodically review Jules Sources and the secret-backed target allowlist |

## Implemented controls

1. The only secret-bearing workflow is manual `workflow_dispatch`.
2. The workflow has `contents: read` and checks that `github.actor` is the designated operator.
3. The workflow accepts only an opaque `target` ID and an approved `task` ID.
4. Private repository names and pinned branches live in `JULES_TARGETS_JSON`, not in this public repository.
5. `config/tasks.json` maps approved task IDs to committed Markdown task specifications.
6. `scripts/jules.py` validates identifiers, constrains task paths to the `tasks` directory, rejects symlink task files, and fails closed on unknown targets/tasks.
7. Jules API error bodies are not emitted to public logs.
8. Successful public dispatch output omits private repository names, branches, Jules session IDs/URLs, source IDs, activities, patches, and PR URLs.
9. The public Jules status workflow has been removed; detailed status is a trusted/local operation.
10. `actions/checkout` is pinned to an immutable commit and persistent Git credentials are disabled.
11. CODEOWNERS marks workflows, scripts, policy configuration, tasks, and this security document as security-sensitive.
12. The dispatch job references the `jules-dispatch` GitHub Environment so repository administrators can add approval/protection rules without changing code.

## Required repository / organization settings

These controls require GitHub administrative configuration and cannot be guaranteed by repository code alone:

1. **Workflow Execution Protection:** allow manual execution only for the designated operator or a very small maintainer group.
2. **Protect `main`:** require pull requests, require CODEOWNER review for security-sensitive files, block force pushes and deletion, and restrict direct pushes.
3. **Environment protection:** configure the `jules-dispatch` environment with a required reviewer while this remains experimental.
4. **Secrets:** keep `JULES_API_KEY` and `JULES_TARGETS_JSON` in GitHub Secrets. Do not place private target names in repository variables, workflow defaults, task files, or logs.
5. **Actions policy:** prefer only GitHub-authored actions and actions pinned to full commit SHAs.

CODEOWNERS is advisory until branch/ruleset protections enforce reviews.

## Target policy format

`JULES_TARGETS_JSON` is a secret JSON object. Public callers see only aliases:

```json
{
  "phase0": {
    "repository": "OWNER/PRIVATE_REPOSITORY",
    "branch": "PINNED_BRANCH"
  }
}
```

Adding a target is an authority-expanding operation and should be reviewed like a credential-scope change.

## Task policy

Task definitions are public and reviewable. Add a Markdown specification under `tasks/`, then explicitly register its ID in `config/tasks.json`. The dispatcher does not accept arbitrary prompt text or arbitrary filesystem paths.

A task should state its objective, constraints, validation/completion criteria, and permitted change scope. Avoid placing private source, credentials, private issue text, or private repository names in task files.

## Logging policy

Public logs may contain only non-sensitive control-plane information such as opaque target/task IDs, success/failure, and a one-way correlation value. They must not contain:

- private repository names or branch names;
- Jules source identifiers;
- Jules session IDs or URLs;
- private PR URLs/titles;
- provider API response bodies;
- source, patches, activities, or generated artifacts.

## Event policy

Do not add secret-bearing triggers for `pull_request`, `pull_request_target`, `issues`, `issue_comment`, forks, or arbitrary repository content. If automated dispatch is explored later, it needs a separate authenticated policy boundary rather than widening this workflow.

## Incident response

If a secret may have been exposed, disable the dispatch workflow, revoke/rotate the Jules API key, inspect recent Actions runs and Jules sessions, review connected Jules Sources, and only then re-enable dispatch. Treat unexpected new Jules sessions or PRs as an authority-boundary incident.
