# R56 — synthetic generation pointer crash/recovery primitive

Public-safe **concept qualification** only. The current Winnow R46-W2 recovery explicitly reports `RECOVERY_ATOMICITY_NOT_IMPLEMENTED` for sequential multi-job manifest saves. This experiment tests an **alternative design primitive** without copying or modifying Winnow source: prepare an immutable three-record generation, flush file and directory metadata, then atomically switch one small pointer file through `os.replace`.

A synthetic writer terminates via `os._exit` in three modes: **before pointer**, **after pointer**, and **invalid late record before pointer**. In three repetitions on native AMD64 and ARM64 disposable public Ubuntu GitHub runners, a reader must see either the complete old batch or complete new batch, never a mixture, and owned scratch must be removed. No external modules or public API traffic.

This **does not** prove power-loss durability, multi-process writer locking, concurrent-reader GC, immutable generation data lifecycle, symlink/race resistance, a real external durable boundary, target macOS/TrueNAS behavior, product implementation, or legal acquisition. No private code, credentials, Instagram, media, downloader or release. Any design promotion requires private product architecture review and independently qualified target runtime.
