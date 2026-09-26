# BHADA remote provider survey

This is a standing Agent Dispatch execution projection for BHADA provider/backend health observation.

## Why it exists

BHADA is private. GitHub-hosted Actions in private repositories consume the owner's private-repository minute quota and can be blocked when that allowance is exhausted. The historical BHADA Provider Health Check series showed this failure mode is operationally confounding: the provider survey can disappear before provider code executes.

The remote survey therefore executes from the **public** `SemperSupra/agent-dispatch` repository on a standard GitHub-hosted runner. BHADA remains private and is cloned ephemerally with a repository-specific read-only deploy key.

Local sovereign compute is an optional alternate executor, never a continuity dependency.

## Cadence

The workflow runs once per week at 03:17 UTC on Sunday.

`auto` alternates:

- **core** on odd ISO weeks: Miruro, AllAnime, 9anime, KickAssAnime.
- **broad** on even ISO weeks: the core set plus AnimePahe, Kawaiifu, GogoAnime, Zoro, Haho, and AnimeOut.

This gives a weekly signal on important/high-churn paths and approximately biweekly broader coverage. Manual `core` and `broad` runs remain available.

The cadence is an experimental starting point, not a permanent SLA. Freshness evidence should decide later whether components need shorter, longer, or refresh-on-use horizons.

## Authority

The remote survey may:

- read BHADA source;
- execute `tools/provider_status_probe.py`;
- make bounded external requests required by that probe;
- write ephemeral survey evidence;
- seal detailed output;
- publish a sanitized receipt.

It may not:

- modify BHADA;
- download full media;
- mutate libraries;
- publish releases;
- write back to BHADA;
- change credentials.

## Privacy/value boundary

Detailed BHADA output stays encrypted with `age`. The public receipt contains only provider name, overall status, stage status, counts, source revision, and execution provenance. URLs, raw exceptions, headers, cookies, signed URLs, and detailed backend evidence are omitted.

Required repository configuration on `SemperSupra/agent-dispatch`:

- secret `BHADA_SURVEY_DEPLOY_KEY`: a **read-only deploy-key private key** whose public half is installed only on `mark-e-deyoung/BHADA`;
- variable `BHADA_SURVEY_AGE_RECIPIENT`: the public `age1...` recipient used to seal detailed survey output.

Do not reuse the Agent Dispatch GitHub App private key for this purpose. The deploy key is intentionally narrower.

## Failure attribution

A workflow unable to clone BHADA is a credential/readiness result, not provider failure.

A runner/setup/install failure is an execution-substrate result, not provider failure.

Only after `provider_status_probe.py` actually executes may its stage results contribute provider/backend health evidence.

The sanitized receipt is public-safe qualification/O&M evidence. The sealed artifact is the detailed maintenance evidence for later diagnosis.

## Continuity limits

This design removes dependence on local sovereign resources and private-repository hosted minutes, but it still depends on GitHub Actions availability and GitHub's scheduled-workflow behavior. Public repositories with no repository activity for long periods may have scheduled workflows disabled by GitHub, so this should be monitored as an external execution readiness condition rather than hidden.
