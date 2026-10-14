#!/usr/bin/env python3
"""Pure parser for PRECOLLECTED TrueNAS docker.events; no subscription or actuator.

TrueNAS SCALE 25.04.2.6 middleware relays Docker container messages through
an event stream registered with DOCKER_READ. This parser cannot attest that a
caller captured that stream from the true guest or remained connected. It only
qualifies the event *shape* and strict correlation before a disposable pilot.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

HEX_ID = re.compile(r'[0-9a-f]{64}\Z')


class Blocked(ValueError):
    pass


def require(predicate: bool, message: str) -> None:
    if not predicate:
        raise Blocked(message)


def event_witness(events: list, app: dict, subscription: dict, *,
                  app_name: str, project: str, service: str,
                  expected_container_id: str, not_before_ns: int) -> dict:
    require(isinstance(app, dict) and app.get('name') == app_name and
            app.get('state') == 'STOPPED', 'NATIVE_APP_NOT_STOPPED')
    require(isinstance(expected_container_id, str) and
            HEX_ID.fullmatch(expected_container_id) is not None,
            'EXPECTED_CONTAINER_ID_INVALID')
    require(type(not_before_ns) is int and not_before_ns > 0,
            'OPERATION_TIME_UNBOUND')
    require(isinstance(subscription, dict) and
            subscription.get('stream') == 'docker.events' and
            subscription.get('permission') == 'DOCKER_READ' and
            subscription.get('ready_before_apply') is True and
            type(subscription.get('disconnect_count')) is int and
            subscription['disconnect_count'] == 0,
            'SUBSCRIPTION_NOT_CONTINUOUS')
    opened = subscription.get('opened_ns')
    closed = subscription.get('closed_ns')
    require(type(opened) is int and type(closed) is int and
            0 < opened <= not_before_ns <= closed,
            'SUBSCRIPTION_TIME_UNBOUND')
    require(isinstance(events, list) and 0 < len(events) <= 10000,
            'EVENT_INVENTORY_UNBOUNDED')
    timeline = {}
    for item in events:
        require(isinstance(item, dict), 'EVENT_ENVELOPE_INVALID')
        if item.get('id') != project:
            continue  # Docker event stream is global; do not emit other metadata.
        data = item.get('fields')
        require(isinstance(data, dict) and data.get('Type') == 'container',
                'NATIVE_EVENT_INVALID')
        actor = data.get('Actor') or {}
        attrs = actor.get('Attributes') or {}
        require(isinstance(attrs, dict) and
                attrs.get('com.docker.compose.project') == project,
                'EVENT_PROJECT_IDENTITY_MISMATCH')
        if attrs.get('com.docker.compose.service') != service:
            continue  # Permissions utility container is not the job worker.
        require(attrs.get('com.docker.compose.container-number') == '1',
                'EVENT_REPLICA_MISMATCH')
        require(actor.get('ID') == expected_container_id and
                data.get('id', expected_container_id) == expected_container_id,
                'EVENT_CONTAINER_IDENTITY_MISMATCH')
        action = data.get('Action')
        require(isinstance(action, str) and action,
                'EVENT_ACTION_MISSING')
        stamp = data.get('timeNano')
        require(type(stamp) is int and opened <= stamp <= closed,
                'EVENT_TIME_OUTSIDE_SUBSCRIPTION')
        if action in ('oom', 'kill', 'restart'):
            raise Blocked('FATAL_OR_AMBIGUOUS_EVENT')
        if action == 'destroy':
            # --rm and Compose cleanup may destroy an already-successful
            # exited container. A *premature* destroy still invalidates proof.
            require('die' in timeline and stamp >= timeline['die'][0],
                    'PREMATURE_CONTAINER_DESTROY')
            continue
        if action in ('create', 'start', 'die'):
            require(action not in timeline, 'DUPLICATE_OPERATION_EVENT')
            timeline[action] = (stamp, attrs)
    require(set(timeline) == {'create', 'start', 'die'},
            'INCOMPLETE_OPERATION_EVENT_SEQUENCE')
    require(not_before_ns <= timeline['create'][0] < timeline['start'][0] < timeline['die'][0],
            'INCOHERENT_OPERATION_EVENT_SEQUENCE')
    code = timeline['die'][1].get('exitCode')
    require(code == '0', 'NONZERO_OR_UNKNOWN_EXIT_CODE')
    return {'schema': 'takeout-truenas-native-event-shape/v1',
            'status': 'EVENT_SEQUENCE_EXIT_ZERO_OBSERVED',
            'classification': 'NATIVE_EVENT_SHAPE_ONLY',
            'required_stream_role': 'DOCKER_READ',
            'service': service,
            'docker_exit_zero_component': True,
            'image_config_identity_verified': False,
            'subscription_provenance_verified': False,
            'site_role_admission_verified': False,
            'foundry_ensure_completed_qualified': False,
            'physical_apply': 'HOLD'}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--events', type=Path, required=True)
    p.add_argument('--app-observation', type=Path, required=True)
    p.add_argument('--subscription', type=Path, required=True)
    p.add_argument('--app-name', required=True)
    p.add_argument('--project', required=True)
    p.add_argument('--service', default='takeoutsynthetic')
    p.add_argument('--expected-container-id', required=True)
    p.add_argument('--not-before-ns', type=int, required=True)
    opts = p.parse_args()
    try:
        result = event_witness(json.loads(opts.events.read_text()),
                               json.loads(opts.app_observation.read_text()),
                               json.loads(opts.subscription.read_text()),
                               app_name=opts.app_name, project=opts.project,
                               service=opts.service,
                               expected_container_id=opts.expected_container_id,
                               not_before_ns=opts.not_before_ns)
    except (OSError, ValueError, TypeError):
        print(json.dumps({'status': 'BLOCKED', 'classification': 'NATIVE_EVENT_SHAPE_ONLY'}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
