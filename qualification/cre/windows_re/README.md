# Actual Windows program recovery exercise

This bounded Product 1 exercise inspects and runs the official **dos2unix 7.5.7
Windows x64** executable, reconstructs an explicitly measured behavioral surface,
and compares the same original/rebuilt PE files on native Windows and Wine.

The target is acquired from the author's official release, with archive SHA-256
`8c1af6e366e641a859a1d58457663aedd1f3b4aae37e67621449beef145cf934`.
The actual package license is retained verbatim. The reference is not built by
this exercise. Upstream implementation source is not inspected. Public release
metadata, license, PE bytes, documented interface and measured behavior are
permitted evidence. This is a development exercise, not a blind benchmark.

## Sequence and current state

`campaign.json` controls the phase in reviewed source. Discovery runs the released
program first. The replacement is implemented only after those observations.
Validation uses a separate 30-case corpus frozen before discovery and replacement
implementation. All seven binary/encoding challenges remain in its verdict.
The manifest digest is pinned in configuration and the independent verifier.

1. Verify official archive digest, safely select the actual PE and license.
2. Inspect PE headers, sections, imports and bounded strings, with address bounds.
3. Run fixed cases through an external native Win32 debugger on both systems.
4. Retain exact streams, exit, sensor health and independently hashed file effects.
5. Derive and record the recovered contract, then implement a replacement.
6. Compare original/replacement within each system and each PE across systems.
7. Reject deliberate byte tampering and launched-image identity mismatch.

No arbitrary target, URL or command is accepted by the workflow. It uses standard
public `ubuntu-24.04` and `windows-2025` GitHub-hosted runners, no repository or
provider secrets, read-only repository permission and no persisted checkout
credentials. Each process is bounded to five seconds and each target stream to
64 KiB. Package upload is bounded to 8 MiB; reports to 16 MiB each; retention is
one day. No guest image, Wine prefix or upstream installer is retained.

## Actual sensors and actuators

`runtime_observer.c` uses an owned child process, debugger events,
`ReadProcessMemory`, loaded image inspection, retained process handles,
`GetProcessTimes`, `GetProcessIoCounters`, and bounded pipe capture. API failures
remain explicit. Static imports do not establish actual calls, and I/O counters
do not establish per-file syscall order.

The breakpoint mode writes an INT3 byte at the observed loaded entry point,
records the exact stop and context, restores the byte and protection, rewinds the
instruction pointer and resumes. The abort mode terminates before the initial
create event is continued; independent snapshots require no conversion effect.
A fresh run then demonstrates recovery. These are separately checked from
ordinary compatibility cases. Wine runs the same observer and target PEs; absent
debugger behavior is an environment/sensor failure, never an invented success.

This is not hostile isolation. Descendant retirement remains unknown. The task
does not qualify a desktop UI, assistive technology, every Windows release,
full-stack visibility or unmeasured command-line options.

## Human and automation interfaces

Each system emits a UTF-8 `report.json`, small summary and semantic HTML report.
The HTML uses real headings, labeled table headers, keyboard scrolling, system
font/colors and visible focus; it presents missing capture explicitly. JSON
retains exact hexadecimal output and file bytes, complete identities, raw
observer receipts and environment information. No terminal color is required.
The independent comparator exits nonzero for disagreement or missing evidence;
it reports behavioral and observation qualification separately.

The test corpus includes German and Thai content and filenames. File-content
conversion, Unicode path support and diagnostic encoding are distinct results.
Platform differences remain visible instead of being normalized away.

## Reproduction

The workflow is `.github/workflows/rdte-windows-program-recovery.yml`.
On a disposable Ubuntu builder with the distribution MinGW x64 compiler:

```sh
python3 qualification/cre/windows_re/acquire.py --outputdir package
python3 qualification/cre/windows_re/pe_static.py --input package/reference/dos2unix.exe --output package/static.json
python3 qualification/cre/windows_re/build_package.py
```

Use the same `package` on native Windows and a disposable Wine prefix. The output
and work directories must not already exist:

```sh
python qualification/cre/windows_re/run_campaign.py --platform windows --package package --outputdir results/windows --workdir cases/windows
python3 qualification/cre/windows_re/run_campaign.py --platform wine --package package --outputdir results/wine --workdir cases/wine
python3 qualification/cre/windows_re/validate.py --windows results/windows/report.json --wine results/wine/report.json --outputdir comparison
```

The final command applies after the phase has become validation and a recovered
candidate has been built. Do not run a validation comparator over discovery cases.

## Reused source lineage

This extracts patterns from the public upstream state-recovery, PE correspondence
and external GDB/MI experiments in PR #1009 at
`da6229720542687adbf48d8a1e35a61b588bd9ec`. It is a thin actual-PE adapter, not a
new scheduler or execution service. The older PE fixture reports its own dynamic
state; this exercise requires external process observations. It also corrects
the older subprocess adapter's unbounded stdout/stderr capture.

Official sources: [release](https://waterlander.net/dos2unix.html),
[archive metadata](https://sourceforge.net/projects/dos2unix/files/dos2unix/7.5.7/dos2unix-7.5.7-win64.zip/download),
[license](https://waterlander.net/dos2unix/doc/COPYING.txt).
