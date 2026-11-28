# External Windows process observer for the recovery exercise

`runtime_observer.c` is a qualification instrument for this fixed public Windows/Wine campaign. It starts a new process owned by the experiment, observes Win32 debug events, and optionally makes one reversible change at the program's actual entry point. It does not attach to an existing host process, elevate privilege, accept an arbitrary memory address, or claim to retire descendants.

## Build and invocation

Build one x64 Windows PE and use that exact observer binary on native Windows and Wine:

```sh
x86_64-w64-mingw32-gcc -std=c11 -O2 -Wall -Wextra -municode runtime_observer.c -o observer.exe
```

The source also uses the native Windows x64 ABI and `wmain`; a Windows compiler must target x64. The MinGW build above is the campaign's reference build.

```text
observer.exe --receipt RECEIPT --stdout OUT --stderr ERR --mode run|breakpoint|abort --timeout-ms 5000 -- TARGET ARGS...
```

The process inherits the observer's current directory, so the driver can select an isolated case directory. Use absolute receipt/output paths outside that case directory. The observer quotes individual target arguments using the Windows CRT argument rules. Target stdin is `NUL`; this first exercise uses named input/output files.

The observer exits with `0` only when it has a completed observation and has successfully written its receipt. This **does not mean the target exited successfully**. Read `target_exit.available` and `target_exit.code` separately. A fully observed abort, timeout or output overflow can also produce observer exit `0`; those are explicit receipt flags and must not be accepted as a normal target result. CLI errors exit `2`; observation or receipt errors exit nonzero.

## Three modes

| Mode | Actual behavior | Required interpretation |
| --- | --- | --- |
| `run` | Start with `DEBUG_ONLY_THIS_PROCESS`, read the mapped PE, record debug events, continue normal execution and capture output. | No writes to target memory or context. Debugger attachment itself can affect a program. |
| `breakpoint` | At the create-process stop, read the original entry byte; install one `INT3` with `VirtualProtectEx`, `WriteProcessMemory` and `FlushInstructionCache`; read back the byte; restore page protection. At the exact entry exception, read the thread context, restore/read back the original byte and page protection, set RIP back to the entry address, verify RIP, and continue. | Check every breakpoint flag. An original entry byte already equal to `INT3`, unexpected RIP semantics, a failed API or a missed entry point is an explicit observer failure. |
| `abort` | Request `TerminateProcess` on the owned process during `CREATE_PROCESS_DEBUG_EVENT`, before the first `ContinueDebugEvent`, then drain terminal events and streams. | The driver independently verifies no target effect and separately reruns the clean case. This cancellation occurs before target startup; it does not test rollback of a partially completed conversion. |

Only two exception classes are handled: the exact breakpoint installed by this observer, and the first bootstrap breakpoint on the initial thread inside the actual loaded `ntdll.dll` image. The latter is identified from the DLL load event, its file-handle basename, and its mapped PE size. When the file handle/name is absent, a bounded read of the mapped PE export-directory Name provides a fallback. Missing identity at the initial outside-target breakpoint is an explicit observer error, so it cannot masquerade as a target compatibility defect. Other exceptions receive `DBG_EXCEPTION_NOT_HANDLED`; the observer does not hide access violations or unrelated target breakpoints. DLL/debug-event names may be unavailable; addresses and event types remain recorded. Debug-string content is not collected.

## Actual observations and bounds

The loaded base comes from `CREATE_PROCESS_DEBUG_EVENT.lpBaseOfImage`. PE headers and section metadata are read with `ReadProcessMemory` from that live mapping. The adapter accepts PE32+ AMD64 only, limits header offsets and section count, checks image bounds, and requires a unique executable section containing the target entry. It never substitutes the preferred on-disk image base for an observed address.

The observer keeps its own process/thread handles. Debug-event process/thread handles are managed by the Windows debugger lifecycle; image/DLL file handles are closed by the observer. The retained process handle allows final `GetProcessTimes` and `GetProcessIoCounters` queries after exit. Each metric has `attempted`, `available` and `error`; unsupported metrics are not fabricated as observed zeroes. I/O accounting identifies totals, not per-file attribution. The campaign's independent file snapshots provide its file-effect oracle.

Each output stream is read in binary through `PeekNamedPipe`/`ReadFile`, preserving its first 65,536 bytes unchanged in its named output file. The receipt reports bytes seen, bytes retained, overflow, pipe EOF and capture errors separately. Overflow terminates the owned process and continues bounded cleanup. A 256-event retention limit records the number of dropped events. Timeout is 100–60,000 ms, with a 5,000 ms default. After a termination request the debug-event drain has a 2,500 ms limit; final process wait and pipe drain add bounded cleanup time. The enclosing workflow remains the outer deadline for OS API stalls.

The child receives only inherited stdin/stdout/stderr handles through `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. Its environment contains only values present under the sorted whitelist `LANG`, `LC_ALL`, `PATH`, `SYSTEMROOT`, `TEMP`, `TMP`, `WINDIR`. No GitHub/provider credential variables cross this boundary. The receipt records whitelist names, not their values. `DebugSetProcessKillOnExit(TRUE)` is enabled after process creation. Cancellation and error cleanup target only the owned process; descendant retirement is always `unknown`.

## Receipt contract

The schema is `cre-win32-observer-v1`.

| Field | Type and meaning |
| --- | --- |
| `observer_ok` | Boolean: creation, terminal event, signaled process, complete stream closure, no observer error. Receipt-write success is also required for exit `0`. |
| `mode`, `created`, `pid` | Selected mode string, creation boolean, actual numeric process ID. |
| `target_exit.available`, `target_exit.code` | Boolean and unsigned 32-bit number, obtained from `EXIT_PROCESS_DEBUG_EVENT`. |
| `image.available`, `image.error` | Whether the mapped x64 PE observation completed; Win32/error code when it did not. |
| `image.base_hex`, `image.entry_rva`, `image.entry_address_hex` | Actual base and computed mapped entry as hex strings; entry RVA as a number. |
| `image.machine`, `image.optional_magic`, `image.image_size` | Numeric observed PE identity/size. |
| `breakpoint.requested`, `install_attempted`, `installed`, `hit` | Separate mode, attempt, completed installation and exact exception-hit facts. |
| `breakpoint.original_known`, `original_byte`, `install_readback` | Original-byte availability/value and verification of the inserted byte. |
| `breakpoint.context_read`, `byte_restored`, `byte_restore_verified` | Actual context query and restoration/read-back results. |
| `breakpoint.install_protection_restored`, `protection_restored` | Protection restoration after installation and after original-byte restoration. |
| `breakpoint.context_rewound`, `continued` | Verified RIP rewind and successful debug continuation after that rewind. |
| `breakpoint.thread_id`, `rip_before_hex`, `rip_after_hex`, `rsp_hex`, `eflags` | Actual stopped-thread context evidence; address strings avoid JSON integer precision loss. |
| `breakpoint.error`, `operation` | First breakpoint failure code and operation string; empty/zero when absent. |
| `cancelled`, `abort_before_first_continue` | Successful requested abort at the create-process event; independently verifiable ordering. |
| `timed_out`, `output_overflow` | Bound violations. These are not normal successful target execution. |
| `termination.attempted`, `succeeded`, `error`, `reason` | Owned-process termination action and API result. |
| `streams.stdout`, `streams.stderr` | Each has numeric `bytes_seen`, `bytes_retained`, boolean `overflow`, boolean `eof`, and numeric `error`. |
| `metrics.times` | `attempted`, `available`, `error`; creation/exit/kernel/user values in fields ending `_100ns`. |
| `metrics.io` | `attempted`, `available`, `error`; `read_operations`, `write_operations`, `other_operations`, `read_bytes`, `write_bytes`, `other_bytes`. |
| `debug.create_event_seen`, `bootstrap_breakpoints`, `dll_events`, `exception_events` | Raw observation-presence/count fields. |
| `events`, `events_total`, `events_dropped` | Bounded event sequence and explicit retention loss. Each retained event includes type, PID/TID, relevant address/base/code, first-chance status, continuation status/success/error, and available DLL basename. |
| `cleanup.exit_event_seen`, `process_signaled`, `complete` | Terminal event and actual process wait/pipe-EOF results. |
| `cleanup.descendant_retirement` | Always the string `unknown`. |
| `observer_error.operation`, `win32` | First observation failure operation and numeric error; empty/zero when absent. |

All booleans are JSON booleans. Counts, error codes, exit codes and RVAs are JSON numbers. Addresses are hexadecimal strings. **All 64-bit process metric values are decimal strings** to preserve exact values through JavaScript/JSON consumers. Values in a metric whose `available` flag is false are placeholders and must not be interpreted as observations.

The campaign should accept ordinary capture only when both streams have EOF, no capture errors, no overflow, and the observer cleanup is complete. It should evaluate metrics, static/live image data, debug events and breakpoint evidence independently. A receipt is evidence of the stated operations, not an assertion of every Windows/Wine or Product 1 capability.

## API references

- [WaitForDebugEvent and debug-handle ownership](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent)
- [CREATE_PROCESS_DEBUG_INFO and loaded image base](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-create_process_debug_info)
- [ContinueDebugEvent and exception disposition](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-continuedebugevent)
- [Explicit inherited-handle attribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [GetProcessTimes](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)
- [GetProcessIoCounters](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprocessiocounters)

Runtime qualification must be established by the campaign's retained native Windows and Wine results. Static source review is not substituted for either execution result.
