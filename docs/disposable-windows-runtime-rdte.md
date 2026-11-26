# Disposable Windows runtime RDTE methodology

This is a public, synthetic-only qualification method, not a production deployment or a new executor. Reuse the existing static Agent Dispatch fixtures and typed execution boundary. Keep private operational authority and admission records outside this public repository.

## Evidence already recovered

As of 2026-11-23:

- [Public Windows guest service PR 951](https://github.com/SemperSupra/agent-dispatch/pull/951), head `090ab386bb8f35824a697ad3678e93567bd0159c`: [run 44877486836](https://github.com/SemperSupra/agent-dispatch/actions/runs/44877486836) completed SUCCESS for Windows guest boot (job 136765360852), native Windows source checks (136765361045), independent Linux source checks (136765361081), and independent guest evidence verification (136768688093).
- The downloaded artifact `public-guest-service-install-receipt` (artifact ID 14696319893) reports verified official ISO/tool hashes, image application, UEFI boot, heartbeat, first logon, PowerShell Direct, synthetic service install/start/idempotent readback, wrong-hash denial, service and binary removal, and guest cleanup. No guest network was attached; no operational product was installed.
- Run metadata names PR head `090ab386bb8f35824a697ad3678e93567bd0159c`; the receipt names the actual PR merge execution commit `abe8278a212d1d5df69558fbc4d9d56e5a54edce`. Its parents are main `b9b681f300187dc9bfa4cea28fd42ee250f7abd6` and that PR head. Preserve both identities; do not incorrectly compare a merge execution receipt directly with the PR head.
- [Container substrate PR 40](https://github.com/SemperSupra/agent-dispatch/pull/40), head `dd9da9961584680f331c338c50849dc93ab5f544`, has green contract/Windows/Apple/LXC/Incus jobs in [run 36448365614](https://github.com/SemperSupra/agent-dispatch/actions/runs/36448365614).
- [Runner readiness PR 41](https://github.com/SemperSupra/agent-dispatch/pull/41), head `2e762b3146c3f9923f75b37913fff63fdf5b0bc3`, has green contract/Windows/LXC/Incus jobs in [run 36451835792](https://github.com/SemperSupra/agent-dispatch/actions/runs/36451835792). Its artifact listing is now empty. Green jobs may include supported negative classifications; this readback does **not** establish runtime support or live runner registration.

The guest-service evidence qualifies the observed synthetic lifecycle only. CPU/memory/disk resizing, reboot recovery, lease expiry, repeated clean reconstruction, hostile isolation, and the other runtime families remain separate acceptance work. Do not rerun an unchanged successful proof merely to obtain another green run.

## Free cloud envelope

Use standard GitHub-hosted runners in this public repository. [GitHub documents](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) standard public runner execution as free, subject to platform usage/concurrency limits; the documented Windows x64 envelope is 4 CPUs, 16 GB RAM and 14 GB storage. Record actual available resources before an image download.

Do not use larger runners, billable cloud VMs, trials requiring payment authority, private hosted minutes, persistent self-hosted capacity, or budget-setting changes. Free runner minutes do not establish that arbitrary artifact storage or transfer is free: use tiny JSON receipts, short retention, and check the current storage allowance before publication. Never upload ISO/VHD images or vendor installers as artifacts.

Each admitted execution must specify one immutable fixture, fixed runner label, maximum jobs/time/storage, allowed downloads and hashes, owned resource prefix, cleanup timeout, and zero monetary budget. Run one heavy guest at a time. Reject insufficient capacity rather than expanding the machine or budget. Start with one execution per changed hypothesis; no automatic retry after UNKNOWN or cleanup failure.

## Runtime matrix

| Family | Best use | Reuse and next bounded experiment | Present verdict |
| --- | --- | --- | --- |
| Hyper-V Gen2 Windows guest | OS deployment, native service installation, reboot and rollback tests | Extend PR 951 fixture with one changed lifecycle hypothesis; use PowerShell Direct and no network initially | Boot/service lifecycle and cleanup observed in the exact run above; broader CRUD incomplete |
| Hyper-V Gen2 Linux guest | Linux build agents, OCI engines and portable systems tests | Reuse [Linux guest PR 781](https://github.com/SemperSupra/agent-dispatch/pull/781) and [run 44168026636](https://github.com/SemperSupra/agent-dispatch/actions/runs/44168026636); recover its actual receipt before accepting its lifecycle | Prior run reference identified; receipt not requalified here |
| Hyper-V Gen1 guest | BIOS/legacy boot and compatibility regression | Separate tiny legacy fixture only when a test requires Gen1; never infer its support from Gen2 | NOT_RUN |
| Windows process-isolated container | Fast trusted Windows build/app tests sharing host kernel | Recover PR 40 per-lane verdict, then use compatible pinned image and explicit process isolation; create/start/exec/stop/delete and image ownership checks | Green harness jobs recovered; runtime verdict not recovered |
| Windows Hyper-V-isolated container | Per-container kernel boundary and host/image compatibility tests | Same fixture family with explicit Hyper-V isolation; verify actual isolation, HCS state and cleanup | NOT_RUN |
| Linux OCI in disposable Linux guest | Linux build/test dependencies without persistent workstation tooling | Place a pinned OCI runtime inside the existing Linux guest; synthetic image, read-only inputs, disposable writable layer | NOT_RUN for this composed lifecycle |
| Disposable WSL2 distribution | Windows/Linux interoperability and toolchain tests | Import an exclusively owned distribution from verified rootfs; start/read/terminate/unregister; prove foreign distributions untouched | NOT_RUN |
| Windows Sandbox | Client GUI/MSI smoke tests and disposable interactive environments | Requires suitable client guest and supported nested virtualization; mapped inputs read-only, networking off, explicit completion marker | NOT_RUN; hosted Windows Server is not a client Sandbox substitute |
| Native WSL containers | Current Windows-native Linux container integration | Independently verify OS/WSL/runtime requirements; fixed public fixture and image; do not infer from ordinary WSL2 | NOT_RUN |
| Hyper-V inside the disposable Windows guest | Hypervisor-management code, nested VM lifecycle, inner Hyper-V container tests | First probe exposed extensions; then a tiny no-NIC inner VM, start/read/stop/remove; record every virtualization layer | Outer runner-to-Windows-guest proven; another inner layer NOT_RUN |

A fixture inside an already nested guest may require an additional virtualization layer. [Microsoft's nested virtualization requirements](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/enable-nested-virtualization) apply at the relevant boundary. Do not claim extensions pass through every layer. [Sandbox in a VM](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-install) also requires nested virtualization. An unavailable extension is an environment limit, not permission to alter the underlying provider host.

WHP/QEMU, VMware and VirtualBox are deferred until a concrete compatibility need justifies them. They are not prerequisites for this Microsoft runtime methodology.

## Common lifecycle oracle

Use the existing fixture's receipt shape and verifier; extend it only for a demonstrated missing observation. Do not build a second scheduler, lease store, backend registry or generic arbitrary-command launcher.

1. **Preflight:** bind source execution SHA, PR head where relevant, run ID, runner image, OS/kernel, runtime versions, virtualization layer, resources and artifact budget. Enumerate foreign resources read-only. Refuse an unowned existing name.
2. **Create:** construct exactly one owned VM/container/distribution from verified public input. Record actual runtime ID, image digest and allocated resources. No product data or standing credentials.
3. **Read:** verify desired and observed state, isolation mode, guest readiness and exact synthetic binary/image hash. A created process or started VM alone is insufficient.
4. **Update:** change one supported property or synthetic payload; read it back. For immutable systems, replace from the declared image and prove the old object absent. Separately test idempotent repeated reconciliation.
5. **Negative controls:** wrong hash/image/source or ownership must deny before effects. Inject a bounded start/workload failure; cleanup must still run. Reject foreign-resource deletion.
6. **Delete:** stop/remove only owned objects; detach owned media, release owned mounts and remove temporary input copies. Verify absence through the runtime API and filesystem, not merely command exit codes.
7. **Recreate:** build a fresh owned instance from the same declared inputs; assert no marker/state leaked from the deleted instance. Compare material image/configuration identity, excluding intentionally fresh IDs.
8. **Independent acceptance:** a separate verifier checks exact source/run identity, required ordered events, negative result, final cleanup and no product effects. Missing fields, wrong source/run, UNKNOWN and cleanup failure cannot PASS.

Distinguish SUPPORTED (required oracle passed), ENVIRONMENT_LIMIT (runtime prerequisite unavailable), HARNESS_FAILURE, ORACLE_FAILURE, NOT_RUN and UNKNOWN. Preserve the earliest failure plus cleanup outcome. A green job that successfully reports ENVIRONMENT_LIMIT remains an unsupported lane.

## Execution sequence and transfer

First recover existing per-lane receipts; next qualify process versus Hyper-V containers and Linux guest/OCI independently. Then attempt the extra nested layer and client-only WSL/Sandbox/native-container lanes only where prerequisites pass. Legacy Gen1 stays demand-driven.

Before any new launch, resolve a genuinely admitted workset, delegation and assignment through the existing Agent Dispatch tools; inspect previous effects, plan the immutable target and bounds, then dispatch only if admitted. No admitted assignment for this expanded matrix was recovered in this session. That is an execution admission gap, not a request for broader public-data authority. Do not borrow another consumer's grant, dispatch directly, or introduce a push-triggered bypass.

Cloud acceptance produces a reproducible methodology, not workstation admission. Transfer source and configuration through review; rerun bounded read-only census and the same synthetic oracles on local hardware only after its separate effect gate. Never project cloud hardware isolation, performance or device support onto the workstation.
