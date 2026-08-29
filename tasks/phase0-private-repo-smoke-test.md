# Phase 0 — Private repository smoke test

## Objective

Inspect the target repository and add a `VALIDATION.md` file that documents the minimal end-to-end validation sequence already described by the repository's existing documentation.

## Constraints

- Documentation-only change.
- Do not modify production code, Docker/container configuration, project files, tests, or existing documentation.
- Verify that the documented commands are internally consistent with the repository structure before writing them into `VALIDATION.md`.
- If an inconsistency is found, document it in `VALIDATION.md` rather than changing the implementation.
- Do not add dependencies.
- Keep the change narrowly scoped to the requested file.

## Completion criteria

- `VALIDATION.md` exists and provides a concise, reproducible validation sequence.
- The sequence is grounded in commands and paths that already exist in the repository.
- Any observed inconsistencies are explicitly identified.
- Create a pull request containing only this documentation change.

## Experiment purpose

This task is intentionally low risk. Its purpose is to verify the control path from the public `agent-dispatch` repository through the Jules REST API into an authorized private GitHub repository and back to a durable private pull request. Coding quality is not the primary variable in this run.
