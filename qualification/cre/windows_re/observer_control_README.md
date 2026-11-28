# Synthetic observer controls

`observer_control.c` provides three fixed synthetic controls for the external process observer. Label every result as `synthetic_observer_control`. These cases qualify the instrument's timeout, capture bound and exception disposition; they do not contribute to the recovered program's compatibility count.

Build the same x64 PE once and use its exact digest on native Windows and Wine:

```sh
x86_64-w64-mingw32-gcc -std=c11 -O2 -Wall -Wextra -Werror -municode -Wl,--no-insert-timestamp observer_control.c -o observer_control.exe
```

Use the observer's `run` mode for all three controls. Preserve its full raw receipt and binary captures. A nonzero target exit caused by a bound or exception is expected; the observer must still finish its observation and cleanup successfully.

| Control argument | Fixed behavior | Suggested observer deadline | Expected evidence |
| --- | --- | --- | --- |
| `sleep` | Sleep for 1,500 ms, then write `sleep completed` followed by LF. | `100` ms | `timed_out=true`; successful owned-process termination; terminal event, signaled process and stream EOF; no completion text. |
| `stdout` | Write exactly 81,920 ASCII `X` bytes through binary `WriteFile`, then exit zero if allowed to finish. | `5000` ms | `output_overflow=true`; stdout `bytes_seen > 65536`, `bytes_retained=65536`, `overflow=true`; retained file is exactly 65,536 `X` bytes; complete cleanup. |
| `exception` | Raise the unhandled, noncontinuable application exception `0xe0421001`; no exception handler is installed. | `5000` ms | The matching first-chance and second-chance exception events are passed as `DBG_EXCEPTION_NOT_HANDLED` (`0x80010001`); target exits with `0xe0421001`; no timeout, overflow or breakpoint-hit claim. |

The exception's numeric unsigned exit/code value is `3762425857`. Addresses and elapsed times vary. Check event code and disposition rather than expecting a fixed address or exact duration. The system's initial debugger bootstrap breakpoint is expected and separate from this custom exception.

For every control require observer exit `0`, `observer_ok=true`, an available actual target exit, `cleanup.exit_event_seen=true`, `cleanup.process_signaled=true`, both streams at EOF and no capture errors. For timeout/overflow, their explicit flags are expected outcomes, so an ordinary successful-target acceptance predicate must not be reused unchanged.

The timeout includes loader/debugger startup. A 100 ms deadline proves the observer deadline and owned-process cleanup even if the sleeping entry has not yet been reached; it does not prove 100 ms of target execution. Do not tighten elapsed-time expectations around a hosted runner's scheduling latency. The workflow/driver should retain its outer deadline as well.

After overflow, the observer may retain additional observed-byte counts while draining but must never retain more than 65,536 bytes in either stream. Whether termination races with the control's final exit is a separate raw fact; bound detection, exact retained prefix and successful cleanup are the primary assertions. Every control should leave `cleanup.descendant_retirement="unknown"`, since these controls create no child process and do not establish descendant retirement.

The source has no reads or writes of fixture files, no child launches, no network calls and no inspection of the released program's implementation. Any refinement inferred from these controls must be distinguished from a real-target behavior mismatch.
