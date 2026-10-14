#!/usr/bin/env python3
"""Strict passive inspection of a one-shot container in an *already admitted* guest.

This module has no Docker client, socket, subprocess, network or host mutation.
It consumes independently collected JSON and is NOT an accepted TrueNAS
Apps native terminal observer or an authorization to admit a KVM guest.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re

SHA = re.compile(r'sha256:[0-9a-f]{64}\Z')
ID = re.compile(r'[0-9a-f]{64}\Z')


class Blocked(ValueError):
    pass


def require(ok: bool, why: str) -> None:
    if not ok:
        raise Blocked(why)


def utc_timestamp(value: str) -> datetime:
    require(isinstance(value, str) and value, 'TIMESTAMP_MISSING')
    try:
        d = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise Blocked('TIMESTAMP_INVALID') from None
    require(d.tzinfo is not None and d.year >= 2020, 'TIMESTAMP_UNQUALIFIED')
    return d.astimezone(timezone.utc)


def verify(app: dict, inspect: list, *, app_name: str, project: str,
           service: str, config_sha: str, archive_host: str,
           state_host: str, not_before: str) -> dict:
    require(isinstance(app, dict) and app.get('name') == app_name,
            'APP_IDENTITY_MISMATCH')
    require(app.get('state') == 'STOPPED', 'APP_NOT_STOPPED')
    require(isinstance(inspect, list) and len(inspect) == 1 and
            isinstance(inspect[0], dict), 'INSPECT_CARDINALITY')
    x = inspect[0]
    require(isinstance(x.get('Id'), str) and ID.fullmatch(x['Id']) is not None,
            'CONTAINER_IDENTITY_INVALID')
    require(isinstance(config_sha, str) and SHA.fullmatch(config_sha) is not None and
            x.get('Image') == config_sha, 'IMAGE_CONFIG_MISMATCH')
    cfg = x.get('Config') or {}
    labels = cfg.get('Labels') or {}
    require(isinstance(labels, dict) and labels.get('com.docker.compose.project') == project and
            labels.get('com.docker.compose.service') == service and
            labels.get('com.docker.compose.container-number') == '1',
            'COMPOSE_OWNERSHIP_MISMATCH')
    require(cfg.get('User') == '10001:10001', 'WRONG_RUNTIME_USER')
    require(not cfg.get('ExposedPorts'), 'INGRESS_EXPOSED')
    host = x.get('HostConfig') or {}
    require(host.get('ReadonlyRootfs') is True and host.get('Privileged') is False,
            'HOST_ISOLATION_MISMATCH')
    require(not host.get('PortBindings') and not host.get('PublishAllPorts'),
            'INGRESS_PUBLISHED')
    require(isinstance(host.get('CapDrop'), list) and
            'ALL' in [str(v).upper() for v in host['CapDrop']], 'CAPABILITIES_NOT_DROPPED')
    require(isinstance(host.get('SecurityOpt'), list) and
            any(str(v).startswith('no-new-privileges') for v in host['SecurityOpt']),
            'PRIVILEGE_ESCALATION_NOT_BLOCKED')
    mounts = x.get('Mounts')
    require(isinstance(mounts, list) and len(mounts) == 2, 'MOUNT_INVENTORY')
    expected = {'/archive': archive_host, '/state': state_host}
    require(all(isinstance(v, str) and v.startswith('/mnt/') and
                not v.endswith('/.') and '/..' not in v for v in expected.values()) and
            len(set(expected.values())) == 2, 'EXPECTED_MOUNT_SCOPE')
    observed = {}
    for m in mounts:
        require(isinstance(m, dict) and m.get('Type') == 'bind' and
                m.get('RW') is True and isinstance(m.get('Destination'), str) and
                isinstance(m.get('Source'), str), 'MOUNT_ATTRIBUTES')
        require(m['Destination'] not in observed, 'DUPLICATE_MOUNT')
        observed[m['Destination']] = m['Source']
    require(observed == expected, 'MOUNT_IDENTITY_MISMATCH')
    state = x.get('State') or {}
    require(state.get('Status') == 'exited' and state.get('Running') is False and
            state.get('Dead') is False and state.get('OOMKilled') is False and
            (state.get('Error') or '') == '', 'CONTAINER_NOT_CLEANLY_EXITED')
    require(type(state.get('ExitCode')) is int and state['ExitCode'] == 0,
            'PROCESS_EXIT_NONZERO_OR_UNKNOWN')
    started, finished, boundary = (utc_timestamp(state.get('StartedAt')),
                                  utc_timestamp(state.get('FinishedAt')),
                                  utc_timestamp(not_before))
    require(boundary <= started <= finished, 'STALE_OR_INCOHERENT_OPERATION')
    return {'schema': 'takeout-guest-terminal-diagnostic/v1',
            'classification': 'DISPOSABLE_GUEST_DIAGNOSTIC_ONLY',
            'status': 'PROCESS_EXIT_ZERO_OBSERVED',
            'app_state': 'STOPPED',
            'image_config_sha256': config_sha,
            'checked_services': [service], 'checked_mount_roles': ['archive', 'state'],
            'native_truenas_observer_qualified': False,
            'foundry_ensure_completed_qualified': False,
            'physical_apply': 'HOLD'}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app-observation', type=Path, required=True)
    p.add_argument('--container-inspect', type=Path, required=True)
    p.add_argument('--app-name', required=True)
    p.add_argument('--compose-project', required=True)
    p.add_argument('--service', default='takeoutsynthetic')
    p.add_argument('--config-sha', required=True)
    p.add_argument('--archive-host', required=True)
    p.add_argument('--state-host', required=True)
    p.add_argument('--not-before', required=True)
    a = p.parse_args()
    try:
        result = verify(json.loads(a.app_observation.read_text()),
                        json.loads(a.container_inspect.read_text()),
                        app_name=a.app_name, project=a.compose_project,
                        service=a.service, config_sha=a.config_sha,
                        archive_host=a.archive_host, state_host=a.state_host,
                        not_before=a.not_before)
    except (OSError, ValueError, TypeError):
        print(json.dumps({'status': 'BLOCKED',
                          'classification': 'DISPOSABLE_GUEST_DIAGNOSTIC_ONLY'}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
