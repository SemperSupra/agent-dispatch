# USB Fabric R25 — release evidence snapshot validator

DLE authority: [private infrastructure-as-code-private#512](https://github.com/mark-e-deyoung/infrastructure-as-code-private/issues/512), handoff #477, source release governance #447. This does **not** change source-of-truth ownership, merge policies, or QEMU/USBIP runtime behavior.

## Purpose

Three-audience surface:
- **Human:** `go run . -manifest manifest.json -format human` prints unsatisfied P0 gate IDs and an explicit lack of release eligibility.
- **Automation:** `go run . -manifest manifest.json -format json` emits a stable result contract and exits nonzero for malformed or fabricated evidence.
- **Constrained agent:** consume `schema`, `receipts` and `gates` with typed exact-head source references; never derive permissions from conversation narrative.

The manifest is an offline point-in-time DLE *snapshot*. Its PR numbers, commit SHAs, Actions run/job IDs, and artifact SHA256 are retrospective evidence references, **not** live GitHub revalidation. A release manager must independently refetch PR heads, review the changed-path DAG and inspect first-hand job artifacts. This offline tool MUST NOT initiate builds, merges, or devices and cannot grant release authority.

## Invariants

1. A `contract` receipt cannot satisfy a `real-qemu` or `real-usbip` gate. The R25-A simulated-QMP/UDC PASS is NOT a live QMP+VUDC handoff.
2. Every PASS must name a unique receipt with a full SHA, PR, job/run IDs, artifact ID, SHA256 and first-hand CI marker. Path overlap between declared workcells is a conflict.
3. All P0 gates require first-hand qualification for requested release; owner approval is a separate mandatory action. No owner-approved release is inferred here.
4. Missing/corrupt/unknown journals, raw USBIP bypass and wrong VM identity remain blocking until same-run evidence says otherwise. The current `release_requested=false`, `owner_approved=false` values are intentional.
5. Negative evidence is retained in GitHub DLE/Actions; this snapshot includes qualified green heads only and must not erase historical RED runs.

## Workflow

Observe → Plan → Apply → Verify, updating exact evidence receipts *after* an independently reviewed source+CI run. New R25-B/C workcells have different source ownership and cannot be marked PASS in this manifest until their exact source/run/job evidence is verified. Keep all PRs draft; no paid private minutes, physical Pi HIL, site secrets or production.

## R25-B/C qualified follow-up

R25-B #894 is a real three-kernel USBIP HID and actual consumer-A QMP
**read-only VM query** in one run. It does NOT satisfy R26 QMP device-release
authority or guest identity attestation. R25-C #895 is a legitimate,
independently tested **stacked security correction** to R25-A #884. Their
recorded changed-path overlap on `handoff_r25.go` is allowed only with the
explicit exact `parent_head` of #884's qualified head; sibling conflicts
remain forbidden. An offline declared parent is still NOT live proof of
Git ancestry and cannot authorize merge. Re-fetch exact PR bases/heads
before any owner-reviewed adoption.
