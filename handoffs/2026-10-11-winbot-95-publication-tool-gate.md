# WinBot 9.5 workflow publication diagnostic — 2026-10-11

**Classification:** `PUBLICATION_TOOL_GATE`, not `WINBOT_PRODUCT_FAILURE`.

**Execution authority:** [SemperSupra/agent-dispatch-private#406, comment 6076235901](https://github.com/SemperSupra/agent-dispatch-private/issues/406#issuecomment-6076235901) approved exactly one sealed Windows A-only for source `33f047df21269d8556b47f3cda7122ca22ca88ad`, projection SHA-256 `270ab93819eb7f0a1c95bdb38f27233af6396bd9cd978aedc47f734ae150deee`, and stage blob `fea7b9871e8d569f5cd868b85f2f9870249be71c`.

## Reproduced observations

- GitHub connection successfully writes normal source files and other cheap, read-only workflows to branch `exp/winbot-95-bounded-diagnostic-20261009`. It read back the qualified immutable 82-file projection (1,054,722 bytes).
- Qualifying A-only Windows preflight `38103311909` succeeded under PowerShell 5.1 and 7 with 20 synthetic first-publication/replay checks.
- Attempted **once** to create `.github/workflows/winbot-95-owner-approved-a-only.yml` using the normal GitHub `create_file` action with the exact qualified workflow bytes. Tool returned `This tool call was blocked by OpenAI's safety checks. Please double check what you are sending.`
- The tool yielded **no GitHub HTTP response, status code, accepted-permissions header, or server request ID** for this blocked operation. Therefore the source of the denial within the safety tool is not observable from this session, and GitHub-side permission sufficiency **for that specific write** remains unverified.
- Fetching the target file through the GitHub connector returned 404 afterward. The branch PR head did not change as a result of the blocked write. The approved A-only guest has **not** run, and the one-use authorization is **unused**.
- A separate later effort to expand the guest-admission test harness was also rejected by tool safety, whereas ordinary updates succeeded. This is evidence of action/request-specific filtering, **not proof of any single exact rule or content trigger**.

## Classification and decision tree

| Question | Evidence | Conclusion |
|---|---|---|
| Does the owner still need to approve the exact A-only source? | #406 comment 6076235901 | No |
| Is the source/projection still unqualified? | Windows `38103311909`; 82-file exact hash receipt | No |
| Are all GitHub workflow writes prohibited? | Earlier successful read-only workflow creation | No |
| Did GitHub's API reject the proposed write? | Tool-level safety error; no HTTP status observed | **Unknown, not demonstrated** |
| Does the GitHub App have suitable workflow-write scope for this write? | No token permission headers exposed by tool | **Unknown; verify via legitimate app/admin permission review** |
| Did the rejected request launch a guest? | Target file absent, no committed run | No |

GitHub documents that updating Actions workflow files requires appropriate workflow-related permissions, which may be separate from ordinary contents writes. This is a **possible second gate**, not an established cause of the observed tool-level rejection.

## Corrective action implemented

`scripts/winbot_95_approved_graph_preflight.py` now queries only the exact target file via authenticated GitHub Contents **GET**. Its bounded CI receipt includes:

- `publication_state`: `ABSENT_404` or `EXACT_PUBLISHED_UNTRIGGERED_STATUS_UNKNOWN`
- `publication_read_method`: `GitHub Contents API GET`
- `publication_is_launch_proof`: `false`
- `workflow_write_attempted`: `false`
- `owner_single_use_consumed`: `UNKNOWN_FROM_PREFLIGHT`

Any unexpected published blob or non-404 API error fails closed. The check never publishes/modifies a workflow, dispatches GitHub Actions, supplies broader credentials, consumes authorization, or launches a guest.

## Legitimate resolution path / successor baton

1. **Platform/tool review:** provide the exact tool error, repo/branch/path, immutable qualified wrapper blob `7574e3e5a5fe8b4dc09b06cbc444c6657f5a99d7`, and the read-only proof above to the responsible connector/tool review operator. Request a disposition: *approved write*, *declined by policy*, or *specific remediable issue*. Do not infer a bypass from the lack of a reason.
2. **GitHub authorization inspection:** through authorized integration administration, verify Workflows write permission for the connected GitHub App and branch protections. Do not broaden OAuth scopes or credentials in this diagnostic without explicit owner action.
3. **If publication is permitted**, admit only the exact qualified wrapper and source pair, verify the published Git blob matches the approved wrapper, refresh the heavyweight-lane census, and consume the owner's one-use assignment at most once.
4. **If publication remains denied**, stop at `BLOCKED_EXTERNAL_TOOL_POLICY` and return the specific platform/operator decision for owner adjudication. Do not create a differently named, split, or indirectly dispatched workflow to defeat the restriction.

**Non-goals:** rerunning prior Windows guest `37866844289`, introducing WinBot #107 or Sidecar #571 as new dependencies, changing source/policy SHA, bypassing safety rejections, using depleted private GHA minutes, or requiring local sovereign infrastructure.

**Next actual product oracle after legitimate publication:** collect bounded Python/gsudo/OpenSSH/authenticated-API readiness plus zero-residue cleanup, then stop before seed or terminal work.
