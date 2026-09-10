# Repository state reconciliation

## Objective

Inspect the approved target repository and reconcile its **durable documentation and coordination state** so a fresh human or agent can determine the current architecture, active work, stale/superseded guidance, and safe next action without transcript archaeology or reliance on obsolete handoffs.

## Responsibilities

- Read the repository's own agent/contributor guidance first.
- Identify files or documents explicitly presented as current architecture, current baton, current queue, current handoff, roadmap, or read-first guidance.
- Compare those claims against the repository's current code/docs/branch state available to the agent.
- Prefer a thin read-first/index/alignment change over rewriting historical documents wholesale.
- Mark clearly stale or superseded guidance so it cannot be mistaken for current execution authority.
- Preserve historical design evidence and useful implementation detail.
- If a current coordination artifact names an old branch/head/task as directly resumable but that cannot be proven current, make it fail closed and require reconciliation rather than guessing.
- Create one narrowly scoped pull request containing the reconciliation changes and a concise explanation of what was found.

## Constraints

- Documentation/coordination hygiene only.
- Do not change product/runtime behavior, tests, workflows, dependency files, provider configuration, release/publication logic, secrets, credentials, or authentication behavior.
- Do not delete branches, worktrees, releases, evidence, historical documents, or source files.
- Do not merge, publish, deploy, dispatch another agent, or perform destructive cleanup.
- Do not infer local-machine/worktree state that is not observable from the hosted environment.
- Do not convert stale local-worktree descriptions into deletion authority.
- Do not weaken security, validation, qualification, public/private projection, or human-command boundaries documented by the target repository.
- Respect any repository-local rule that designates qualified/immutable evidence or source; do not modify those artifacts.
- If the repository has a public/private projection boundary, keep private architecture details out of public-projected files unless the repository's own policy explicitly permits the wording.
- Do not add dependencies.

## Completion criteria

- A fresh actor has one obvious read-first/current-state path.
- Materially stale execution/coordination guidance is clearly marked historical, superseded, blocked, or reconciliation-required rather than silently left as current.
- No production/runtime behavior changed.
- No destructive or local-machine-only action was attempted.
- The pull request identifies any remaining work that requires a local machine, separate authority, independent qualification, or human decision.
- The proposed changes are reversible and limited to the minimum files needed to remove current-state ambiguity.

## Result contract

Return a pull request. In its description summarize:

1. current authoritative entry points found;
2. stale/conflicting guidance found;
3. files changed and why;
4. work deliberately left untouched;
5. any remaining boundary that prevents further safe hosted work.
