# Public GHA Windows nested guest service installer RDTE

**Owner:** private infrastructure issue #608, downstream consumer #590. This is a PUBLIC-SAFE original test payload; no private source, real endpoint names, cloud credentials, cloud account tokens, local host state or private service is fetched or installed.

## What is actually exercised

This public draft uses the existing, previously accepted Windows Evaluation ISO + SHA256/wimlib + run-owned VHDX + UEFI/vTPM + first-logon + PowerShell Direct pattern from public [Agent Dispatch run 44608439342](https://github.com/SemperSupra/agent-dispatch/actions/runs/44608439342) at public source commit `604f27ddb99a0e14b088e836c99479eac6debf58`. Earlier [run 44558554583](https://github.com/SemperSupra/agent-dispatch/actions/runs/44558554583) independently accepted native guest boot and [run 44613887489](https://github.com/SemperSupra/agent-dispatch/actions/runs/44613887489) accepted its separately recovered first-logon/PowerShell Direct witness.

A fresh standard free `windows-2025` hosted runner downloads the **exact same pinned Microsoft Enterprise Evaluation ISO**, constructs one new run-owned 64GB dynamic VHDX, verifies its disk mapping before formatting, applies Windows, stages one public Go Windows service executable, creates and boots its single no-NIC Gen2 Windows guest, observes first logon, then uses PowerShell Direct to install a *real Windows service registration* inside the guest.

The public Go service `PublicRDTECanary` is deliberately inert: no network listener, no agent commands, no remote authentication, no provider API, no SSH and no persistence beyond two named marker files in the run-owned guest directory. Service tests check: SHA256 before guest OS, SHA256 inside guest, native `sc.exe create` → Windows running state + service health marker → idempotent readback → intentionally wrong digest denied before mutation → stop health marker → `sc.exe delete` and removed state → delete exact owned executable. A final run-owned VM/VHDX/workdir cleanup stage is appended by the outer host, with fail-closed independent Go receipt verification.

The workflow also runs **two independent light jobs** while the heavy Windows guest builds: Linux race+negative proof tests and Windows native Go source/PowerShell 5.1 parse. A separate Ubuntu job verifies the guest's receipt *after* completion without having performed the guest actions itself. This is one heavy VM at a time, not a matrix of 8GB ISO downloads.

## What is not claimed

- This is NOT the private `accessctl`/Headscale/Cloudflare/OCI service installer, signed authorization issuer, Colab/Kaggle identity bridge, or production access.
- No guest network interface is attached, so no cloud-to-sovereign transport or TCP positive/negative canary is inferred.
- A signed public binary/source hash is **not** an owner grant, and a hosted runner's Hyper-V rights do not transfer to the local Windows OpenCode/Qwen actor.
- This public workload must not consume the frozen WinBot #406 sealed admission, private WinBot source, or #632 gateway H1 admission. It is a distinct user-requested public-only experiment with its own private #608 authority.
- If the evaluation image source changes, the digest is not waived or replaced ad hoc: record a source integrity failure and stop.

## Acceptance and hygiene

- Public Go service+proof module (Go 1.25, x/sys v0.45.0 verified by public sums)
- Exact-source public CI, native Windows 2025 guest install and independent job, plus cleanup receipt, all PASS; do not infer from green job alone
- Negative wrong-hash, incomplete/false-claim receipts and no residual guest service, disk, network attachment or VM
- No auto-merge, no private GHA minutes, no self-hosted runner, no leaked secret/host identifiers, no public release of a fake production installer
- Next step only after evidence: protected/private source projection through existing signed Agent Dispatch authority, approved native host census and credentials, **not** copying private sources into public CI

If a large ISO download or runner capability fails, preserve its exact classification; do not substitute a synthetic file test and call it native guest installation.
