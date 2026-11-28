# Behavior-derived Windows reconstruction: first contract

This contract was written from retained observations before the reconstruction was implemented. The reference implementation source and frozen validation fixtures were not read. Public release documentation, binary metadata, imports, and actual process/file/stream observations were available. The reconstruction is independently authored C, not a build of the upstream source.

## Evidence identity

- Reference: upstream dos2unix 7.5.7 Windows 64-bit English release.
- Reference executable SHA-256: `98ce6d01bb0fc3b7c2b81830377e1f1f94b0ab6bb4f0d6669786687ac43fb92b`.
- Reference archive SHA-256: `8c1af6e366e641a859a1d58457663aedd1f3b4aae37e67621449beef145cf934`.
- Initial discovery run: [46164840366](https://github.com/SemperSupra/agent-dispatch/actions/runs/46164840366), source commit `05f8804f6eea95d29b3d09068f3b26dd075a7493`.
- Additional isolated discovery run: [46165391933](https://github.com/SemperSupra/agent-dispatch/actions/runs/46165391933), source commit `0932e0ab70b919ef47148a67f64a048deb7319ef`, which probes remaining control classes separately from the frozen validation corpus.
- Evidence artifacts: `windows-re-windows/report.json`, `windows-re-wine/report.json`, raw per-case `stdout.bin` and `stderr.bin`, and `windows-re-package/static.json`.
- Observed native environment: Windows Server 2025, build 10.0.26100, AMD64. Initial Wine environment: Wine 9.0 on Ubuntu 24.04, x86-64.

The initial native run completed 25 discovery cases. Its entry-breakpoint, controlled abort, and subsequent normal-run checks passed. Those are evidence of the exercise's actual observer/actuator path, not evidence that the reconstruction already matches the reference.

## Supported first interface

```text
cre-dos2unix -n INPUT OUTPUT [INPUT OUTPUT ...]
```

The implemented conversion surface is paired mode for regular files, including ASCII-compatible byte text, UTF-8 with or without its complete leading BOM, and valid BOM-marked UTF-16LE/UTF-16BE. Windows paths are passed through wide-character file APIs. Complete pairs are processed incrementally, in argument order. The output from a completed pair remains when a later pair fails.

`--newfile` aliases `-n`; `--` ends option parsing. These two convenience forms are documented interface extensions until separately measured. The measured compatibility claim centers on `-n`.

The candidate's own `--help` and `--version` identify it as CRE and describe only its supported subset. Unsupported options are rejected; they never silently enable a partially implemented upstream mode.

## Rules recovered from discovery

| Rule | Direct observations |
| --- | --- |
| Replace each CRLF with LF; preserve standalone CR, existing LF, and lack of a final newline. | d01, d02, d03; d03 includes CRCRLF and a final standalone CR. |
| Empty input creates an empty output. | d04. |
| Preserve non-newline UTF-8 bytes, including German and Thai text. | d05. |
| Remove a complete leading UTF-8 BOM; preserve an incomplete BOM-like prefix as ordinary bytes. | d07 and d24. |
| Decode BOM-marked UTF-16LE and UTF-16BE to UTF-8, remove the BOM, and normalize CRLF at the character level. | d08 and d09. |
| Decode a valid UTF-16 surrogate pair to its four-byte UTF-8 representation. | d23. |
| Binary input is skipped with exit code 0, two diagnostic lines, and no new output. | d10 for NUL, d11 for 0x01, d12 for 0x0B. |
| Binary skip preserves an already-existing output byte for byte. | d22. |
| Binary diagnostics identify the first encountered forbidden symbol in uppercase hexadecimal and its source line. | d10 reports NUL at line 2 after CRLF; d11 and d12 report line 1. |
| Missing input reports a file error and a non-regular-file skip message, produces no output, and returns 2. | d13. |
| Missing output parent reports the OS directory error plus the conversion failure, preserves input, and returns 1. | d14. |
| Successful conversion replaces an existing output. | d15. |
| Process complete pairs incrementally; retain prior completed outputs when a later input is missing. | d16 and d17. |
| Ignore a final unmatched input argument without a diagnostic; previous conversions remain committed and the observed example returns 0. | d18. |
| Spaces and Unicode filenames work on native Windows; displayed filenames use the active Windows ANSI code page. | d06 and d25. German letters remain representable; Thai characters appear as question marks in the native diagnostic. |
| Conversion diagnostics go to stderr; normal paired conversion emits no stdout. | All observed paired-mode cases. |

The initial Wine Unicode-path failure was not treated as a reference filename rule: the host supplied a non-UTF-8 locale while transporting Unicode arguments. Corrected discovery run 46165391933 used a UTF-8 host locale, retained the observer's actual UTF-16 argument receipt, and observed successful conversion of the intended Unicode filenames. All 32 corrected discovery captures completed on both native Windows and Wine. The candidate uses wide Windows paths and does not reproduce the earlier transport corruption.

The missing-output-parent message is environment-dependent. Native Windows emitted `The directory name is invalid.`; Wine emitted `Directory name invalid.`. Both carried the same observed extra carriage return and blank line. The candidate obtains the actual error from `GetTempFileNameW`, formats it through the OS, and lets the C text stream expand line endings. No platform-name-to-message lookup table is used.

## Measured refinement before candidate validation

The first 25 cases did not establish the entire binary-symbol class. d12 contains several controls but stops at 0x0B, so it did not prove the treatment of later 0x0C or 0x7F. The initial hypothesis treated C0 controls other than HT, LF and CR as binary, and advanced source line numbering at LF.

The additional isolated discovery in run 46165391933 falsified part of that hypothesis: **formfeed (0x0C) is preserved as text**. DEL (0x7F) is also preserved. BEL (0x07), BS (0x08), SUB (0x1A) and ESC (0x1B) each produce a binary skip at line 1. NUL after a standalone CR is reported at line 1, supporting LF-based line numbering. The implementation was corrected to allow HT, LF, FF and CR while rejecting other C0 controls; DEL and higher bytes remain unchanged. This is a generalized rule derived from those probes, with no fixture-specific input or expected-output table in the program.

The extension was read before candidate validation; no frozen validation bytes were used to select or implement these rules.

Before cloud candidate validation, the exact portable C conversion functions were compiled with C11, optimization, `-Wall`, `-Wextra` and `-Werror` in a temporary harness. Fifty-four conversion/skip comparisons against the corrected native and Wine discovery reports passed, including both directions of UTF-16 byte ordering, a surrogate pair, mixed CR/LF, BOM boundaries, and binary symbol/line reporting. This checks the conversion core; it does not substitute for a Windows build or validation of filesystem APIs, diagnostics, and complete command behavior.

## Explicitly unqualified edges

Continuing with later pairs after an error and combining multiple distinct failure categories are generalized interface choices beyond the directly observed successful-then-missing sequence. The candidate retains a nonzero status across subsequent pairs and combines pair status bits. Mixed error-category aggregation remains outside the qualified envelope until measured.

Malformed UTF-16 is rejected explicitly and preserves the destination. The exact malformed-input diagnostics are a CRE interface decision, not a claimed reconstruction of unobserved reference wording.

## Honest help and the unknown-option difference

The observed reference unknown option, d19, returned 1, changed no files, wrote no stderr, and wrote its complete help to stdout. That help advertises many modes outside this reconstruction. Reproducing it would misrepresent the candidate's capabilities.

The candidate therefore preserves the error status, stream selection and absence of file effects, but prints its own concise subset help. This is an intentional, visible stdout difference. It must remain present in comparison evidence and must not be erased by normalization or silently excluded from results. Explicit `--help` and `--version` also identify CRE rather than impersonating the upstream utility.

## Implementation bounds and exclusions

- Each input is limited to 64 MiB, with a 128 MiB output allocation bound. These are declared qualification limits, not upstream limits.
- Input bytes are fully checked and converted before a destination is replaced. Output is written to a temporary file in the destination directory and committed by a Windows rename operation. Failed or skipped conversion preserves the pre-existing destination.
- Byte text is not subjected to UTF-8 validation; high bytes are preserved. Only complete leading BOM signatures select a Unicode transformation.
- File contents, exit status, stdout/stderr and final file effects are compatibility observations. Exact temporary filenames, syscall sequences, timing, process I/O totals, timestamps, ACLs, ownership, hard-link identity and atomicity under concurrent adversarial changes are not claimed equivalent.
- In-place/default mode, stdin/stdout conversion, code-page conversion modes, UTF-16 output retention, forced binary conversion, additional-BOM/EOL options, quiet/verbose/info modes, wildcard expansion, recursive traversal, symlinks/reparse-point semantics, device paths and long-path behavior are outside this first envelope.
- No Windows desktop accessibility or general Windows-version compatibility claim follows from a server CLI exercise.

The final qualified scope must be determined by the independently retained comparisons on native Windows and Wine, including failures and intentional differences. This document is a reconstruction contract, not a passing validation certificate.
