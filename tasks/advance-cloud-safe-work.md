# Advance cloud-safe work

## Objective

Advance the next bounded unit of work that the target repository's durable authority explicitly identifies as safe and useful in the current hosted execution environment.

## Responsibilities

- Read repository-local instructions and the active issue/PR/workset before acting.
- Recover the current accepted state, UNKNOWNs, next bounded action, and reserved authority from repository-native durable state.
- Confirm the hosted environment satisfies the hard capability requirements before mutation.
- Prefer existing native, standard, maintained open-source, or already-local capabilities over custom machinery.
- Implement the smallest change that advances the authorized cloud-safe frontier.
- Run applicable repository-provided validation.
- Preserve explicit boundaries for work that requires another executor, privilege level, secret, device, interactive session, paid resource, or human acceptance.

## Constraints

- Do not infer authority from authentication or tool availability.
- Do not merge, release, publish, deploy to production, rotate/change secrets, change visibility, spend money, or perform destructive host/repository actions.
- Do not claim native-Windows or other executor-specific acceptance unless the target authority explicitly identifies the current executor as suitable for that evidence class.
- Do not invent a scheduler, queue, database, registry, router, callback service, orchestration layer, or broad abstraction to avoid an ordinary boundary.
- Do not weaken validation to obtain a pass.
- Do not broaden into unrelated refactors or cleanup.

## Completion criteria

- One bounded cloud-safe increment is implemented or a concrete capability/authority blocker is established.
- Existing relevant validation passes, or failures are classified.
- The resulting change is reviewable and reversible through Git.
- Any remaining native/local/human boundary is explicit.

## Result contract

Return one narrowly scoped pull request when mutation is warranted. In the PR describe the authoritative work item, the bounded increment advanced, validation performed, evidence class produced, and work deliberately left for another executor/authority. Do not duplicate routine evidence already expressed by authoritative CI/result state.
