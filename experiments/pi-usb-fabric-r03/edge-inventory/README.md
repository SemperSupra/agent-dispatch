# USB Edge inventory component

Read-only Linux USB inventory via upstream sysfs. Observed busid, VID/PID, class, device driver and authorized state are observations, not enrollment or grants. No serial or manufacturer/product strings are collected. No USBIP bind/unbind, kernel module load, listener, lease or hardware claim. Only use a trusted sysfs mount; this is not a hostile mutable filesystem sandbox.

Build: `go test ./...`, `go vet ./...`, `bash build-deb.sh /existing/disposable/output`. Rehearsal: `dpkg-deb -x package.deb /disposable/root`, execute extracted `usr/bin/usb-edge-inventory`. Remove only the disposable extraction to roll back. No package maintainer scripts or service activation. Production activation, host authorization, stable resource enrollment, original Fabric-managed grants, effective exporter isolation, driver restoration and physical Pi HIL are separate gates.

Packaging qualification uses a fixed SOURCE_DATE_EPOCH and normalized archive times/permissions. CI builds twice and compares bytes, then installs/reinstalls/purges using a disposable dpkg root with its own empty package database. No maintainer scripts, service activation or host package database modifications. Bounded public qualification artifact is not a production release or signed distribution.
