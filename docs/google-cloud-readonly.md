# Fixed Google Cloud read-only qualification executor

**Status: SOURCE CANDIDATE / LIVE HOLD.** This workflow does not provision Cloud resources, activate OAuth, manage personal Google data, or replace Agent Dispatch's admitted CPU executor.

## Discovery and supported entrypoints

- Credential-free source tests: `python3 -m unittest -v tests/test_google_cloud_readonly.py`
- Privileged workflow: `.github/workflows/google-cloud-readonly.yml`, native **workflow_dispatch on protected main only**. No input fields.
- Read-only executable: `python3 scripts/google_cloud_readonly.py --probe .google-oidc/receipt.json`; verifier: `--verify .google-oidc/receipt.json`.
- CI source acceptance: `.github/workflows/google-cloud-source-check.yml`, tokenless PR validation only.

Cloud bootstrap configuration and project inventory belong to the private IaC work item #250; the public repository never stores account/project IDs or tokens. GitHub environment policy/secrets belong to GitHub Ops. Agent Dispatch owns dispatch admission, not Cloud IAM.

## Exact trust boundary

Google provider policy must admit **all** of these verified GitHub OIDC claims:

| Claim | Expected |
| --- | --- |
| `repository_owner_id` | `68664496` |
| `repository_id` | `1350205857` |
| `repository` | `SemperSupra/agent-dispatch` |
| `ref` | `refs/heads/main` |
| `workflow_ref` | `SemperSupra/agent-dispatch/.github/workflows/google-cloud-readonly.yml@refs/heads/main` |
| `event_name` | `workflow_dispatch` |
| `environment` | `google-cloud-readonly` |
| `ref_type` | `branch` |

The script additionally rejects rerun attempts, missing/wrong run identity and source revision. Authentication requires a Google OIDC provider and `roles/iam.workloadIdentityUser` on a resource-scoped service account. The first service account receives only `roles/browser` for one approved project. That permission is read-only but can still expose metadata; keep provider IDs and service-account identifiers private.

## Admission prerequisites — not yet proven

1. The exact Google WIF IAM configuration must be independently reviewed and applied by the authorized Google account owner; project/billing/credits and potential provider-name conflicts must be reconciled first. The private IaC source generates an offline Terraform configuration; applying that plan is **not** implied by this PR.
2. GitHub Ops must inspect and configure branch/ruleset/workflow/environment protections through its existing admin reconciler, with a bounded environment `google-cloud-readonly` and secrets `GOOGLE_RO_WIF_PROVIDER`, `GOOGLE_RO_SERVICE_ACCOUNT`, `GOOGLE_RO_PROJECT_ID`. Never print values or inject them as free-form workflow inputs.
3. Admit only a fixed main-branch dispatch under the existing DLE authority. Ordinary pull requests execute only tokenless tests. No PR/fork-controlled code enters the OIDC job.
4. After native run completes, examine the sanitized artifact and tokenless second-job verifier. A verifier PASS confirms deterministic structure and run correlation, **not** independent Google IAM/account acceptance; obtain provider-native IAM audit or an authorized read-only out-of-band check for final qualification.
5. If the project metadata probe fails, no receipt is published and the workflow fails closed; raw Google API responses, credentials and errors stay out of logs.

## Rollback and recovery

- Before admission: discard draft PR/branch, no runtime effects.
- After admission: disable the exact GitHub environment, remove its bound secrets using GitHub Ops, and disable/delete the Google provider binding in a separately approved native IaC plan; verify the actual state.
- Changing a workflow path, branch, owning repo or OIDC provider requires a new trust condition/review, never an automatic wildcard.
- Keep `gha-creds-*.json` and any Terraform state out of all source and artifacts. Do not add broadly privileged GitHub token permissions or dynamic command execution.

## Relationship to other Google surfaces

Colab CLI and its human ADC flow are owned by the existing private IaC Colab #79 workstream; Personal Ops owns `clasp`, Apps Script and user-consented Google services. They are not accessible through this cloud service identity. Kaggle and Agent Dispatch's CPU profile retain their separate existing execution contracts.
