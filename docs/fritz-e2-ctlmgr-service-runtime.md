# FRITZ E2 R2 — exact ctlmgr.service runtime

Authority: `SemperSupra/fritzbox-automation-private#72`.

This probe executes the exact E2-D3-derived service-manager treatment:

```
/bin/supervisor /lib/systemd/system ctlmgr.service
```

against the pinned FRITZ!Box 7590 FRITZ!OS 8.25 image.

The target runs only inside a disposable filesystem chroot plus fresh mount, PID and network namespaces. The network namespace contains loopback only and has no default route.

R2 deliberately does **not** fabricate `/var/tmp/psupport.data`, `avmipcd` runtime state, hardware state, or any FRITZ-specific shim. Missing dependencies are experiment results.

Durable output is restricted to exact target identity, path-presence booleans, process/listener observations, bounded login probe metadata, and normalized missing absolute guest paths. Raw firmware, rootfs, binaries, target stdout/stderr, strace and HTTP response bodies remain ephemeral.

A typed negative is a valid product result when it identifies the next evidence-earned dependency.
