#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 "$root/cell-git-cas/git_cas_probe.py"
(cd "$root/cell-sink" && go vet ./... && go test -race -count=1 -v ./... && go test -race -count=10 ./...)
python3 "$root/cell-sql-restore/sqlite_restore_probe.py"
