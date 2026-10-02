#!/usr/bin/env python3
"""E2-R9: reduce the svctl↔supervisor Unix-socket wire exchange to digests.

This repeats only the already-accepted disposable emulator transaction:
  status ctlmgr -> start ctlmgr (once) -> status ctlmgr

Only the svctl client process is wrapped in host strace. Control-socket payload
bytes exist only ephemerally in process memory and are reduced to direction,
order, lengths, and SHA-256 digests before the receipt is written.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys

_R6 = pathlib.Path(__file__).with_name("fritz_qemu_e2_svctl_start_ctlmgr.py")
_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_svctl_start_ctlmgr", _R6)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load R6")
r6 = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(r6)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-wire-digest/v1"
CONTROL_SOCKET = r6.CONTROL_SOCKET
QEMU_GUEST_PATH = r6.QEMU_GUEST_PATH
CPU_PROFILE = r6.CPU_PROFILE
SVCTL = r6.SVCTL
SUPERVISOR = r6.SUPERVISOR
CONTROL_SOCKET_HEX = "".join(f"\\x{b:02x}" for b in CONTROL_SOCKET.encode("utf-8"))


def _split_strace_prefix(line: str) -> tuple[str, str]:
    line = line.strip()
    m = re.match(r"^\[pid\s+(\d+)\]\s+(.*)$", line)
    if m:
        return m.group(1), m.group(2)
    m = re.match(r"^(\d+)\s+(.*)$", line)
    if m:
        return m.group(1), m.group(2)
    return "main", line


def _decode_hex_string(token: str) -> bytes:
    return bytes(
        int(value, 16)
        for value in re.findall(r"\\x([0-9a-fA-F]{2})", token)
    )


def _digest(parts: list[bytes]) -> dict:
    h = hashlib.sha256()
    total = 0
    for part in parts:
        h.update(part)
        total += len(part)
    return {
        "eventCount": len(parts),
        "totalBytes": total,
        "sha256": h.hexdigest() if parts else None,
    }


def parse_wire_trace(trace: str) -> dict:
    connected: set[tuple[str, int]] = set()
    raw_events: list[tuple[str, str, bytes, int, bool]] = []
    control_connects = 0
    unsupported_control_io = 0
    incomplete_events = 0

    for raw in trace.splitlines():
        pid, body = _split_strace_prefix(raw)

        if "connect(" in body and (CONTROL_SOCKET in body or CONTROL_SOCKET_HEX in body):
            m = re.search(r"\bconnect\((\d+),.*\)\s*=\s*(-?\d+)", body)
            if m and int(m.group(2)) == 0:
                connected.add((pid, int(m.group(1))))
                control_connects += 1

        m = re.search(
            r'\b(read|write|sendto|recvfrom)\((\d+),\s*"((?:\\x[0-9a-fA-F]{2})*)".*\)\s*=\s*(-?\d+)',
            body,
        )
        if m:
            syscall = m.group(1)
            fd = int(m.group(2))
            ret = int(m.group(4))
            if (pid, fd) in connected and ret > 0:
                decoded = _decode_hex_string(m.group(3))
                complete = len(decoded) >= ret
                payload = decoded[:ret]
                if not complete:
                    incomplete_events += 1
                direction = (
                    "request" if syscall in ("write", "sendto") else "response"
                )
                raw_events.append((direction, syscall, payload, ret, complete))
            continue

        m = re.search(r"\b(sendmsg|recvmsg|writev|readv)\((\d+),", body)
        if m and (pid, int(m.group(2))) in connected:
            unsupported_control_io += 1

        m = re.search(r"\bclose\((\d+)\)\s*=\s*0", body)
        if m:
            connected.discard((pid, int(m.group(1))))

    request_parts = [e[2] for e in raw_events if e[0] == "request"]
    response_parts = [e[2] for e in raw_events if e[0] == "response"]

    events = []
    for ordinal, (direction, syscall, payload, ret, complete) in enumerate(
        raw_events, start=1
    ):
        events.append(
            {
                "ordinal": ordinal,
                "direction": direction,
                "syscall": syscall,
                "length": ret,
                "capturedBytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "complete": complete,
            }
        )

    request = _digest(request_parts)
    response = _digest(response_parts)
    capture_complete = bool(
        control_connects
        and request["eventCount"]
        and response["eventCount"]
        and incomplete_events == 0
        and unsupported_control_io == 0
    )
    return {
        "controlConnectCount": control_connects,
        "captureComplete": capture_complete,
        "unsupportedControlIoCount": unsupported_control_io,
        "incompleteEventCount": incomplete_events,
        "request": request,
        "response": response,
        "eventSequence": events,
        "payloadPublished": False,
        "rawTracePublished": False,
    }


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def svctl_call_wire(
    root: pathlib.Path, env: dict, verb: str, service: str
) -> dict:
    cp = subprocess.run(
        [
            "strace",
            "-f",
            "-qq",
            "-xx",
            "-s",
            "8192",
            "-e",
            "trace=socket,connect,read,write,sendto,recvfrom,sendmsg,recvmsg,writev,readv,close",
            "chroot",
            str(root),
            QEMU_GUEST_PATH,
            "-cpu",
            CPU_PROFILE,
            SVCTL,
            verb,
            service,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )

    wire = parse_wire_trace(cp.stderr)
    vocab = r6.binary_state_vocabulary(root)
    allowed = set(vocab.get(SVCTL, {})) | set(vocab.get(SUPERVISOR, {}))
    return {
        "verb": verb,
        "service": service,
        "exitCode": cp.returncode,
        "stdoutBytes": len(cp.stdout.encode("utf-8", errors="replace")),
        "stdoutSha256": sha256_text(cp.stdout),
        "stderrBytes": len(cp.stderr.encode("utf-8", errors="replace")),
        "missingGuestPaths": [],
        "stateMarkers": r6.state_markers(cp.stdout, allowed),
        "controllerVocabulary": vocab,
        "wireCapture": wire,
        "rawOutputPublished": False,
        "rawHostStracePublished": False,
    }


def namespace_helper(args: argparse.Namespace) -> int:
    original = r6.svctl_call
    r6.svctl_call = svctl_call_wire
    try:
        return r6.namespace_helper(args)
    finally:
        r6.svctl_call = original


def _wire_for(runtime: dict, key: str) -> dict:
    call = runtime.get(key)
    if not isinstance(call, dict):
        return {}
    value = call.get("wireCapture")
    return value if isinstance(value, dict) else {}


def summarize_wire(runtime: dict) -> dict:
    pre = _wire_for(runtime, "preStatus")
    start = _wire_for(runtime, "start")
    post = _wire_for(runtime, "postStatus")
    complete = all(x.get("captureComplete") is True for x in (pre, start, post))

    def d(call: dict, direction: str):
        obj = call.get(direction, {})
        return (obj.get("totalBytes"), obj.get("sha256"))

    pre_req, start_req, post_req = d(pre, "request"), d(start, "request"), d(post, "request")
    pre_rsp, start_rsp, post_rsp = d(pre, "response"), d(start, "response"), d(post, "response")

    return {
        "captureComplete": complete,
        "preStatus": pre,
        "start": start,
        "postStatus": post,
        "comparisons": {
            "prePostStatusRequestEqual": bool(complete and pre_req == post_req),
            "prePostStatusResponseEqual": bool(complete and pre_rsp == post_rsp),
            "startRequestDiffersFromStatus": bool(complete and start_req != pre_req),
            "startResponseDiffersFromStatus": bool(complete and start_rsp != pre_rsp),
        },
        "payloadPublished": False,
    }


def classify(runtime: dict, wire: dict) -> str:
    if runtime.get("ctlmgrProcessObserved"):
        return "E2_R9_CTLMGR_PROCESS_OBSERVED"
    if not wire.get("captureComplete"):
        return "E2_R9_WIRE_CAPTURE_INCOMPLETE"
    c = wire.get("comparisons", {})
    if (
        c.get("prePostStatusRequestEqual")
        and c.get("prePostStatusResponseEqual")
        and c.get("startRequestDiffersFromStatus")
    ):
        return "E2_R9_WIRE_CLASSES_DISTINGUISHED"
    if not c.get("startRequestDiffersFromStatus"):
        return "E2_R9_START_REQUEST_NOT_DISTINGUISHED"
    return "E2_R9_WIRE_CAPTURED_DIFFERENT_STATUS_CLASS"


def run_probe(args: argparse.Namespace) -> dict:
    root, meta = r6.prepare_root(args)
    ns_result = pathlib.Path(args.work_dir).resolve() / "namespace-result-r9.json"
    cp = r6._run(
        [
            "sudo",
            "-n",
            "unshare",
            "--net",
            "--pid",
            "--fork",
            "--kill-child",
            "--mount-proc",
            sys.executable,
            str(pathlib.Path(__file__).resolve()),
            "--namespace-helper",
            "--root",
            str(root),
            "--namespace-result",
            str(ns_result),
            "--control-wait-seconds",
            str(args.control_wait_seconds),
            "--verify-seconds",
            str(args.verify_seconds),
            "--sample-interval-seconds",
            str(args.sample_interval_seconds),
        ],
        timeout=max(45, int(args.control_wait_seconds + args.verify_seconds) + 30),
    )
    if cp.returncode != 0:
        raise RuntimeError(
            f"isolated R9 probe failed (exit={cp.returncode}, stderrBytes={len(cp.stderr.encode())})"
        )
    if not ns_result.exists():
        raise RuntimeError("R9 namespace probe emitted no result")
    runtime = json.loads(ns_result.read_text(encoding="utf-8"))
    wire = summarize_wire(runtime)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classify(runtime, wire),
        "oracleSatisfied": bool(runtime.get("probeCompleted") and wire["captureComplete"]),
        **meta,
        "transaction": {
            "inspect": ["svctl", "status", "ctlmgr"],
            "apply": ["svctl", "start", "ctlmgr"],
            "applyCount": 1 if runtime.get("start", {}).get("exitCode") is not None else 0,
            "verify": ["svctl", "status", "ctlmgr"],
            "disposalIsRollback": True,
        },
        "runtime": runtime,
        "wire": wire,
        "interpretationBoundary": {
            "wireDigestDoesNotRevealPayload": True,
            "syscallChunksAreNotAssumedToBeProtocolMessageBoundaries": True,
            "startExitZeroDoesNotProveServiceHealthy": True,
            "physicalRouterSemanticsNotInferred": True,
        },
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "rawControlPayloadPublished": False,
            "controlPayloadPersisted": False,
            "rawHostStracePublished": False,
            "rawSvctlOutputPublished": False,
            "physicalRouterContact": False,
            "routerMutationAuthorized": False,
            "externalNetworkAvailableToTarget": False,
            "targetSpecificShimAdded": False,
            "genericRuntimeFixtureAdded": True,
            "onlyVarTmpCreated": True,
            "psupportDataFabricated": False,
            "avmipcdStateFabricated": False,
            "serviceStartRequested": True,
            "serviceStartCountMaximum": 1,
            "disposableEmulatorMutationOnly": True,
        },
    }


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url")
    p.add_argument("--expected-size", type=int)
    p.add_argument("--expected-sha256")
    p.add_argument("--work-dir")
    p.add_argument("--receipt")
    p.add_argument("--control-wait-seconds", type=float, default=2.0)
    p.add_argument("--verify-seconds", type=float, default=2.0)
    p.add_argument("--sample-interval-seconds", type=float, default=0.05)
    p.add_argument("--namespace-helper", action="store_true")
    p.add_argument("--root")
    p.add_argument("--namespace-result")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.namespace_helper:
        if not args.root or not args.namespace_result:
            raise SystemExit("namespace helper requires root/result")
        return namespace_helper(args)

    required = (
        args.firmware_url,
        args.expected_size,
        args.expected_sha256,
        args.work_dir,
        args.receipt,
    )
    if any(v is None for v in required):
        raise SystemExit("normal mode requires firmware/size/hash/work/receipt")

    receipt_path = pathlib.Path(args.receipt)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt = run_probe(args)
        rc = 0 if receipt.get("oracleSatisfied") else 2
    except Exception as exc:
        receipt = {
            "schemaVersion": SCHEMA_VERSION,
            "experiment": EXPERIMENT,
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "error": {"type": type(exc).__name__, "message": str(exc)[:1000]},
            "safety": {
                "rawControlPayloadPublished": False,
                "controlPayloadPersisted": False,
                "rawHostStracePublished": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
            },
        }
        rc = 3

    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "classification": receipt["classification"],
                "oracleSatisfied": receipt["oracleSatisfied"],
            },
            sort_keys=True,
        )
    )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
