#!/bin/sh
set -eu
: "${BENCH_ACTOR:?missing actor}"
case "$BENCH_ACTOR" in alpha|bravo|charlie) ;; *) exit 8 ;; esac
dd if=/dev/zero of=/tmp/workfile bs=1048576 count=24 status=none
for i in 1 2 3 4; do sha256sum /tmp/workfile >/dev/null; done
echo "BENCH_ACTOR_${BENCH_ACTOR}=PASS"
