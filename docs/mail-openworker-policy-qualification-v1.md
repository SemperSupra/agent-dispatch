# OpenWorker pinned upstream policy-primitive interview (candidate)

**Consumer:** Mail Evidence autonomous reasoning bakeoff (private owner #39). **Executor:** existing public Agent Dispatch typed CPU workflow, no new YAML. This is an isolated inspection of *original upstream* OpenWorker code, **not** an operational mail agent, self-improvement, unrestricted shell or full OpenWorker service.

## Build / acquisition / runtime

- Exact public upstream repository: `andrewyng/openworker` at commit `ecb445490fc054d52b8ea610d97ba947f57033d2`.
- MIT `LICENSE` (Git blob SHA1 `60d3824636ee279c14389ea0b858f00fe0c4a913`).
- Source modules: `coworker/readonly.py` Git blob `d621e606eea85be031c27237b0bc2ffcdfe590cb` and `coworker/sandbox/network_profiles.py` `4f253ac14839d522abeff8d8dd2cc21066d2d3f3`.
- Only bounded read from `raw.githubusercontent.com` at immutable SHA with exact Git object verification, 90 KB cap per file, 12 second timeout, no requester supplied URL, no credentials and no other network endpoint.
- Python 3.10+ with standard library only; tests run modules in a disposable directory, classify commands without invoking them, destroy all source snapshots. No `pip`, external data, model or server dependencies.
- Offline harness guards: `python3 -m unittest discover -s tests -p test_qualify_openworker_readonly.py -v`. Real upstream self-contained probe: `python3 scripts/qualify_openworker_readonly.py` (network required for pinned public source acquisition).
- Public CI matrix: reviewed `requests/gha/mail-openworker-policy-v1.json`, standard `ubuntu-24.04`, fixed one attempt, max 180 seconds, `max_cost_usd=0`; independent native receipt verifies source identity, bounded case count and inference/credential absence.

## What is actually tested

Two safe source-only commands should be auto-classified as read-only; six adversarial variants involving shell deletion, chained destructive commands, `find -exec`, inline Python, redirection and network egress must **not** be auto-classified as read-only. Upstream source executes **none** of these commands; it only computes permission decisions. The tiny network-profile module checks host normalization and rejects unknown profile types. The separate email pipeline must still have an **independent action-broker policy**, path and trust gates; a permissive classification is never itself permission to run code.

## Trust and O&M

All candidate source bytes are immutable-public and Git-blob-verified before import; process and temporary filesystem are disposable. Fail closed for upstream SHA drift, rights ambiguity, network unavailable, malicious/oversized response, runtime exception, any admitted dangerous command, or independent receipt mismatch. CI is not a model/capability promotion gate, and a green workflow only establishes the reported eight command-classification controls. Do not treat third-party static validation as an operating security sandbox. Bounded public-network acquisition is confined to this source-only workcell; product execution is offline/local-first.

For real OpenWorker qualification, require a separate exact-version dependency-locked headless installation and fake IMAP connector test, runtime policy adversarial suite, clean shutdown/restart, logs/trajectory/ATTIF formats, CPU/RAM/disk/latency and update/rollback. Do not attach live mailboxes or public cloud secrets.
