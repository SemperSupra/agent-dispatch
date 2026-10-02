#!/bin/sh
set -eu
if [ -S /tmp/supervisor.ctrl.socket ]; then
    socket=true
else
    socket=false
fi
printf '{"schemaVersion":1,"helper":"fritz-observe-supervisor/v1","supervisorControlSocket":%s}\n' "$socket"
