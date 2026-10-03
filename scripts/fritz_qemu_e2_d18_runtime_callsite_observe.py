#!/usr/bin/env python3
"""E2-D18: instrument exact svctl callsites during the accepted R9 transaction.

D17 recovered exactly one static /bin/svctl callsite into _svctl_init and one
into _svctl_send_pkt, but static analysis could not associate their argument
classes with status versus start. D18 uses the admitted instrumented-emulator
lane to observe those exact callsites under QEMU's GDB stub.

The debugger Python hook reduces a0..a3 immediately to scalar classes plus
SHA-256 digests of readable 8- and 260-byte pointed regions. Raw register values,
memory bytes, debugger output, callsite addresses, and wire payload are never
written to the durable receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

_R9_PATH = pathlib.Path(__file__).with_name("fritz_qemu_e2_wire_digest.py")
_R9_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_wire_digest", _R9_PATH)
if _R9_SPEC is None or _R9_SPEC.loader is None:
    raise RuntimeError("unable to load R9")
r9 = importlib.util.module_from_spec(_R9_SPEC)
_R9_SPEC.loader.exec_module(r9)
r6 = r9.r6

_D17_PATH = pathlib.Path(__file__).with_name("fritz_qemu_e2_d17_svctl_callsite_args.py")
_D17_SPEC = importlib.util.spec_from_file_location("fritz_qemu_e2_d17_svctl_callsite_args", _D17_PATH)
if _D17_SPEC is None or _D17_SPEC.loader is None:
    raise RuntimeError("unable to load D17")
d17 = importlib.util.module_from_spec(_D17_SPEC)
_D17_SPEC.loader.exec_module(d17)
d13 = d17.d13
d14 = d17.d14

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-d18-runtime-callsite-observe/v1"
TARGETS = ("_svctl_init", "_svctl_send_pkt")
MEMORY_SIZES = (8, 260)
_RECORD_RE = re.compile(
    r"^\s*(?P<addr>[0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2,8}\s+)+(?P<asm>.+)$"
)
_PORT_COUNTER = 25480


def instruction_records(disassembly: str) -> list[dict]:
    out = []
    for line in disassembly.splitlines():
        m = _RECORD_RE.match(line)
        if m:
            out.append({
                "addr": int(m.group("addr"), 16),
                "asm": m.group("asm").strip(),
            })
    return out


def locate_callsite_addresses(path: pathlib.Path, objdump: str) -> dict[str, int]:
    got = d13.readelf_selected_got(path)
    cp = subprocess.run(
        [objdump, "-dr", str(path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if cp.returncode:
        raise RuntimeError("objdump failed for instrumented /bin/svctl")
    records = instruction_records(cp.stdout)
    found: dict[str, list[int]] = {target: [] for target in TARGETS}

    for i, rec in enumerate(records):
        load = d13.got_load(rec["asm"])
        if not load:
            continue
        reg, off = load
        target = got.get(off)
        if target not in TARGETS or reg not in {"t9", "25"}:
            continue
        for later in records[i + 1:]:
            asm = later["asm"]
            if d13.is_jalr_t9(asm):
                found[target].append(later["addr"])
                break
            if d14.writes_t9(asm) or d14.control_transfer(asm):
                break

    bad = {target: len(addrs) for target, addrs in found.items() if len(addrs) != 1}
    if bad:
        raise RuntimeError(f"expected exactly one selected callsite per target; counts={bad}")
    return {target: addrs[0] for target, addrs in found.items()}


def elf_type(path: pathlib.Path) -> str:
    readelf = shutil.which("readelf")
    if not readelf:
        raise RuntimeError("readelf unavailable")
    cp = subprocess.run([readelf, "-h", str(path)], capture_output=True, text=True, timeout=30)
    if cp.returncode:
        raise RuntimeError("readelf header failed")
    for line in cp.stdout.splitlines():
        m = re.match(r"\s*Type:\s+(\S+)", line)
        if m:
            return m.group(1)
    return "UNKNOWN"


def scalar_class(value: int) -> str:
    value &= 0xFFFFFFFF
    if value == 0:
        return "zero"
    if value == 1:
        return "one"
    if 2 <= value <= 16:
        return "small_positive"
    if value >= 0xFFFF0000:
        return "negative_or_high_word"
    if value >= 0x00010000:
        return "address_like"
    return "word_scalar"


def gdb_command_text(
    root: pathlib.Path,
    port: int,
    breakpoint_specs: dict[str, str],
) -> str:
    exe = root / r6.SVCTL.lstrip("/")
    solib = ":".join(str(root / p) for p in ("lib", "usr/lib"))
    bp_lines = "\n".join(
        f"Obs({json.dumps(spec)}, {json.dumps(target)})"
        for target, spec in sorted(breakpoint_specs.items())
    )
    return f"""set pagination off
set confirm off
set breakpoint pending on
set auto-solib-add on
set sysroot {root}
set solib-search-path {solib}
file {exe}
target remote 127.0.0.1:{port}
python
import gdb, hashlib, json

MEMORY_SIZES = {MEMORY_SIZES!r}

def scalar_class(value):
    value = int(value) & 0xffffffff
    if value == 0:
        return "zero"
    if value == 1:
        return "one"
    if 2 <= value <= 16:
        return "small_positive"
    if value >= 0xffff0000:
        return "negative_or_high_word"
    if value >= 0x00010000:
        return "address_like"
    return "word_scalar"

def memory_digests(value):
    value = int(value) & 0xffffffff
    if value < 0x10000:
        return {{}}
    inferior = gdb.selected_inferior()
    out = {{}}
    for size in MEMORY_SIZES:
        try:
            raw = bytes(inferior.read_memory(value, size))
            out[str(size)] = hashlib.sha256(raw).hexdigest()
        except Exception:
            pass
    return out

class Obs(gdb.Breakpoint):
    def __init__(self, spec, label):
        super().__init__(spec, internal=False)
        self.silent = True
        self.label = label

    def stop(self):
        record = {{"target": self.label, "args": {{}}}}
        for reg in ("a0", "a1", "a2", "a3"):
            try:
                value = int(gdb.parse_and_eval("$" + reg)) & 0xffffffff
                record["args"][reg] = {{
                    "scalarClass": scalar_class(value),
                    "memoryDigests": memory_digests(value),
                }}
            except Exception:
                record["args"][reg] = {{
                    "scalarClass": "unreadable",
                    "memoryDigests": {{}},
                }}
        print("FRITZOBS:" + json.dumps(record, sort_keys=True))
        self.enabled = False
        return True

{bp_lines}
end
continue
continue
detach
quit
"""


def parse_gdb_observations(stdout: str) -> list[dict]:
    out = []
    for line in stdout.splitlines():
        if not line.startswith("FRITZOBS:"):
            continue
        try:
            record = json.loads(line.split(":", 1)[1])
        except json.JSONDecodeError:
            continue
        if record.get("target") not in TARGETS:
            continue
        args = record.get("args")
        if not isinstance(args, dict) or set(args) != {"a0", "a1", "a2", "a3"}:
            continue
        out.append(record)
    return out


def _next_port() -> int:
    global _PORT_COUNTER
    value = _PORT_COUNTER
    _PORT_COUNTER += 1
    return value


def instrumented_svctl_call(
    root: pathlib.Path,
    env: dict,
    verb: str,
    service: str,
) -> dict:
    stage = "tool_discovery"
    try:
        gdb = shutil.which("gdb-multiarch")
        objdump = shutil.which("mips-linux-gnu-objdump")
        if not gdb or not objdump:
            raise RuntimeError("gdb-multiarch or mips objdump unavailable")

        stage = "elf_type"
        exe = (root / r6.SVCTL.lstrip("/")).resolve()
        etype = elf_type(exe)

        stage = "callsite_resolution"

    # D17's exact-one-callsite invariant is required in both modes. For fixed
    # ET_EXEC binaries we can break at the callsite itself. For PIE/ET_DYN,
    # preserve that provenance constraint but bind GDB to the exported function
    # entry symbol so relocation is handled by the dynamic loader/GDB.
        callsites = locate_callsite_addresses(exe, objdump)
        if etype == "EXEC":
            binding_mode = "static_callsite"
            breakpoint_specs = {
                target: f"*0x{address:x}"
                for target, address in callsites.items()
            }
        elif etype == "DYN":
            binding_mode = "symbol_entry"
            breakpoint_specs = {target: target for target in TARGETS}
        else:
            return {
                "verb": verb,
                "service": service,
                "exitCode": None,
                "stdoutBytes": 0,
                "stdoutSha256": None,
                "stderrBytes": 0,
                "missingGuestPaths": [],
                "stateMarkers": [],
                "controllerVocabulary": r6.binary_state_vocabulary(root),
                "wireCapture": {},
                "instrumentation": {
                    "ready": False,
                    "reason": "unsupported_elf_type",
                    "elfType": etype,
                    "bindingMode": "unsupported",
                    "observations": [],
                    "rawDebuggerOutputPublished": False,
                },
                "rawOutputPublished": False,
            }

        port = _next_port()

        with tempfile.TemporaryDirectory(prefix="fritz-d18-") as td:
            command_path = pathlib.Path(td) / "observe.gdb"
            command_path.write_text(
                gdb_command_text(root, port, breakpoint_specs),
                encoding="utf-8",
            )

            strace_argv = [
                "strace", "-f", "-qq", "-xx", "-s", "8192",
                "-e",
                "trace=socket,connect,read,write,sendto,recvfrom,sendmsg,recvmsg,writev,readv,close",
                "chroot", str(root), r6.QEMU_GUEST_PATH, "-cpu", r6.CPU_PROFILE,
                "-g", str(port), r6.SVCTL, verb, service,
            ]
            stage = "process_launch"
            proc = subprocess.Popen(
                strace_argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                start_new_session=True,
            )

            time.sleep(0.2)
            stage = "gdb_run"
            gdb_timed_out = False
            gdb_returncode = None
            gdb_stdout = ""
            gdb_stderr = ""
            try:
                gdb_cp = subprocess.run(
                    [gdb, "--batch", "--nx", "-x", str(command_path)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                gdb_returncode = gdb_cp.returncode
                gdb_stdout = gdb_cp.stdout or ""
                gdb_stderr = gdb_cp.stderr or ""
            except subprocess.TimeoutExpired as exc:
                gdb_timed_out = True
                gdb_stdout = exc.stdout or ""
                gdb_stderr = exc.stderr or ""
                if isinstance(gdb_stdout, bytes):
                    gdb_stdout = gdb_stdout.decode("utf-8", errors="replace")
                if isinstance(gdb_stderr, bytes):
                    gdb_stderr = gdb_stderr.decode("utf-8", errors="replace")

            stage = "guest_communicate"
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = proc.communicate(timeout=2)

        stage = "postprocess"
        observations = parse_gdb_observations(gdb_stdout)
        wire = r9.parse_wire_trace(stderr)
        vocab = r6.binary_state_vocabulary(root)
        allowed = set(vocab.get(r6.SVCTL, {})) | set(vocab.get(r6.SUPERVISOR, {}))
        gdb_connection_seen = any(
            marker in (gdb_stdout + "\n" + gdb_stderr)
            for marker in ("Remote debugging using ", "Remote debugging from host ")
        )

        ready = bool(
            not gdb_timed_out
            and gdb_returncode == 0
            and proc.returncode is not None
            and observations
            and wire.get("captureComplete") is True
        )
        return {
            "verb": verb,
            "service": service,
            "exitCode": proc.returncode,
            "stdoutBytes": len(stdout.encode("utf-8", errors="replace")),
            "stdoutSha256": r6.sha256_text(stdout),
            "stderrBytes": len(stderr.encode("utf-8", errors="replace")),
            "missingGuestPaths": r6.r1.parse_missing_paths(stderr),
            "stateMarkers": r6.state_markers(stdout, allowed),
            "controllerVocabulary": vocab,
            "wireCapture": wire,
            "instrumentation": {
                "ready": ready,
                "reason": (
                    "ok" if ready
                    else "gdb_timeout" if gdb_timed_out
                    else "debugger_or_wire_incomplete"
                ),
                "elfType": etype,
                "bindingMode": binding_mode,
                "observationCount": len(observations),
                "observations": observations,
                "gdbExitClass": (
                    "timeout" if gdb_timed_out
                    else "zero" if gdb_returncode == 0
                    else "nonzero"
                ),
                "gdbConnectionSeen": gdb_connection_seen,
                "breakpointObservationCount": len(observations),
                "rawDebuggerOutputPublished": False,
                "rawRegisterValuesPublished": False,
                "rawPointedMemoryPublished": False,
                "callsiteAddressesPublished": False,
            },
            "rawOutputPublished": False,
        }


    except Exception as exc:
        return instrumentation_failure_result(
            root,
            verb,
            service,
            type(exc).__name__,
            stage,
        )

def instrumentation_failure_result(
    root: pathlib.Path,
    verb: str,
    service: str,
    error_type: str,
    error_stage: str = "instrumented_svctl_call",
) -> dict:
    """Return a sanitized typed instrumentation failure without raw debugger data."""
    vocab = r6.binary_state_vocabulary(root)
    return {
        "verb": verb,
        "service": service,
        "exitCode": None,
        "stdoutBytes": 0,
        "stdoutSha256": None,
        "stderrBytes": 0,
        "missingGuestPaths": [],
        "stateMarkers": [],
        "controllerVocabulary": vocab,
        "wireCapture": {},
        "instrumentation": {
            "ready": False,
            "reason": "instrumentation_exception",
            "errorType": error_type,
            "errorStage": error_stage,
            "elfType": None,
            "bindingMode": None,
            "observationCount": 0,
            "observations": [],
            "gdbExitClass": None,
            "rawDebuggerOutputPublished": False,
            "rawRegisterValuesPublished": False,
            "rawPointedMemoryPublished": False,
            "callsiteAddressesPublished": False,
        },
        "rawOutputPublished": False,
    }


def safe_instrumented_svctl_call(
    root: pathlib.Path,
    env: dict,
    verb: str,
    service: str,
) -> dict:
    try:
        return instrumented_svctl_call(root, env, verb, service)
    except Exception as exc:
        return instrumentation_failure_result(
            root, verb, service, type(exc).__name__, "outer_wrapper"
        )


def namespace_helper(args: argparse.Namespace) -> int:
    original = r6.svctl_call
    # Keep the R6 transaction alive even when debugger binding fails so the
    # durable receipt records a typed, sanitized instrumentation negative.
    r6.svctl_call = safe_instrumented_svctl_call
    try:
        return r6.namespace_helper(args)
    finally:
        r6.svctl_call = original


def canonical_observations(call: dict | None) -> list[dict]:
    if not isinstance(call, dict):
        return []
    inst = call.get("instrumentation")
    if not isinstance(inst, dict):
        return []
    obs = inst.get("observations")
    if not isinstance(obs, list):
        return []
    return sorted(obs, key=lambda x: json.dumps(x, sort_keys=True))


def _target_arg_index(obs: list[dict]) -> dict[str, dict]:
    out = {}
    for item in obs:
        target = item.get("target")
        if target in TARGETS and target not in out:
            out[target] = item.get("args", {})
    return out


def summarize_instrumentation(runtime: dict) -> dict:
    pre = canonical_observations(runtime.get("preStatus"))
    start = canonical_observations(runtime.get("start"))
    post = canonical_observations(runtime.get("postStatus"))

    calls = {
        "preStatus": runtime.get("preStatus") or {},
        "start": runtime.get("start") or {},
        "postStatus": runtime.get("postStatus") or {},
    }
    call_diagnostics = {
        key: {
            "ready": (call.get("instrumentation") or {}).get("ready"),
            "reason": (call.get("instrumentation") or {}).get("reason"),
            "errorType": (call.get("instrumentation") or {}).get("errorType"),
            "errorStage": (call.get("instrumentation") or {}).get("errorStage"),
            "elfType": (call.get("instrumentation") or {}).get("elfType"),
            "bindingMode": (call.get("instrumentation") or {}).get("bindingMode"),
            "observationCount": (call.get("instrumentation") or {}).get("observationCount", 0),
            "gdbExitClass": (call.get("instrumentation") or {}).get("gdbExitClass"),
        }
        for key, call in calls.items()
    }
    all_ready = all(
        isinstance(call.get("instrumentation"), dict)
        and call["instrumentation"].get("ready") is True
        for call in calls.values()
    )
    status_stable = bool(all_ready and pre == post)
    start_differs = bool(all_ready and start != pre)

    pre_idx = _target_arg_index(pre)
    start_idx = _target_arg_index(start)
    post_idx = _target_arg_index(post)
    per_target = []
    for target in TARGETS:
        p = pre_idx.get(target)
        s = start_idx.get(target)
        q = post_idx.get(target)
        stable_args = []
        differing_args = []
        if isinstance(p, dict) and isinstance(s, dict) and isinstance(q, dict):
            for reg in ("a0", "a1", "a2", "a3"):
                if p.get(reg) == q.get(reg):
                    stable_args.append(reg)
                    if s.get(reg) != p.get(reg):
                        differing_args.append(reg)
        per_target.append({
            "target": target,
            "preHit": target in pre_idx,
            "startHit": target in start_idx,
            "postHit": target in post_idx,
            "statusStableArgs": stable_args,
            "startDifferingArgs": differing_args,
        })

    return {
        "allCallsInstrumentationReady": all_ready,
        "prePostStatusEqual": status_stable,
        "startDiffersFromStatus": start_differs,
        "perTarget": per_target,
        "callDiagnostics": call_diagnostics,
        "bindingModes": sorted(set(
            x.get("bindingMode")
            for x in call_diagnostics.values()
            if x.get("bindingMode")
        )),
        "rawRegisterValuesPublished": False,
        "rawPointedMemoryPublished": False,
        "rawDebuggerOutputPublished": False,
    }


def classify(runtime: dict, wire: dict, instrument: dict) -> str:
    if runtime.get("ctlmgrProcessObserved"):
        return "E2_D18_CTLMGR_PROCESS_OBSERVED"
    if not wire.get("captureComplete"):
        return "E2_D18_WIRE_CAPTURE_INCOMPLETE"
    if not instrument.get("allCallsInstrumentationReady"):
        return "E2_D18_INSTRUMENTATION_INCOMPLETE"
    if not instrument.get("prePostStatusEqual"):
        return "E2_D18_STATUS_INSTRUMENTATION_UNSTABLE"
    if instrument.get("startDiffersFromStatus"):
        return "E2_D18_RUNTIME_ARGUMENT_CLASSES_DISTINGUISHED"
    return "E2_D18_RUNTIME_ARGUMENT_CLASSES_NOT_DISTINGUISHED"


def run_probe(args: argparse.Namespace) -> dict:
    root, meta = r6.prepare_root(args)
    ns_result = pathlib.Path(args.work_dir).resolve() / "namespace-result-d18.json"
    cp = r6._run(
        [
            "sudo", "-n", "unshare", "--net", "--pid", "--fork", "--kill-child",
            "--mount-proc", sys.executable, str(pathlib.Path(__file__).resolve()),
            "--namespace-helper", "--root", str(root),
            "--namespace-result", str(ns_result),
            "--control-wait-seconds", str(args.control_wait_seconds),
            "--verify-seconds", str(args.verify_seconds),
            "--sample-interval-seconds", str(args.sample_interval_seconds),
        ],
        timeout=max(60, int(args.control_wait_seconds + args.verify_seconds) + 45),
    )
    if cp.returncode != 0:
        raise RuntimeError(
            f"isolated D18 probe failed (exit={cp.returncode}, stderrBytes={len(cp.stderr.encode())})"
        )
    if not ns_result.exists():
        raise RuntimeError("D18 namespace probe emitted no result")
    runtime = json.loads(ns_result.read_text(encoding="utf-8"))
    wire = r9.summarize_wire(runtime)
    instrument = summarize_instrumentation(runtime)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": classify(runtime, wire, instrument),
        "oracleSatisfied": bool(
            runtime.get("probeCompleted")
            and wire.get("captureComplete")
            and instrument.get("allCallsInstrumentationReady")
        ),
        **meta,
        "transaction": {
            "inspect": ["svctl", "status", "ctlmgr"],
            "apply": ["svctl", "start", "ctlmgr"],
            "applyCount": 1 if runtime.get("start", {}).get("exitCode") is not None else 0,
            "verify": ["svctl", "status", "ctlmgr"],
            "disposalIsRollback": True,
        },
        "wire": wire,
        "instrumentation": instrument,
        "runtimeSummary": {
            "statusChanged": runtime.get("statusChanged"),
            "ctlmgrProcessObserved": runtime.get("ctlmgrProcessObserved"),
            "maxCtlmgrProcessCount": runtime.get("maxCtlmgrProcessCount"),
        },
        "interpretationBoundary": {
            "d17UniqueCallsiteConstraintApplied": True,
            "relocationAwareBreakpointBinding": True,
            "breakpointsDoNotModifyShippedFiles": True,
            "argumentScalarClassesAndMemoryDigestsOnly": True,
            "prePostStatusStabilityRequired": True,
            "wireDigestDoesNotRevealPayload": True,
            "memoryDigestDoesNotRevealPointedBytes": True,
            "argumentDifferenceIsNotProtocolFieldLayoutProof": True,
            "protocolEnumValuesAccepted": False,
            "packetFieldLayoutAccepted": False,
        },
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "rawControlPayloadPublished": False,
            "controlPayloadPersisted": False,
            "rawHostStracePublished": False,
            "rawDebuggerOutputPublished": False,
            "rawRegisterValuesPublished": False,
            "rawPointedMemoryPublished": False,
            "callsiteAddressesPublished": False,
            "physicalRouterContact": False,
            "routerMutationAuthorized": False,
            "externalNetworkAvailableToTarget": False,
            "targetSpecificShimAdded": False,
            "shippedFilesModified": False,
            "genericRuntimeFixtureAdded": True,
            "onlyVarTmpCreated": True,
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
        args.firmware_url, args.expected_size, args.expected_sha256,
        args.work_dir, args.receipt,
    )
    if any(v is None for v in required):
        raise SystemExit("normal mode requires firmware/size/hash/work/receipt")

    receipt = pathlib.Path(args.receipt)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = run_probe(args)
        rc = 0 if data.get("oracleSatisfied") else 2
    except Exception as exc:
        data = {
            "schemaVersion": SCHEMA_VERSION,
            "experiment": EXPERIMENT,
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "error": {"type": type(exc).__name__, "message": str(exc)[:1000]},
            "safety": {
                "rawFirmwarePublished": False,
                "rootfsPublished": False,
                "rawControlPayloadPublished": False,
                "controlPayloadPersisted": False,
                "rawHostStracePublished": False,
                "rawDebuggerOutputPublished": False,
                "rawRegisterValuesPublished": False,
                "rawPointedMemoryPublished": False,
                "callsiteAddressesPublished": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
                "externalNetworkAvailableToTarget": False,
                "targetSpecificShimAdded": False,
                "shippedFilesModified": False,
                "genericRuntimeFixtureAdded": False,
                "onlyVarTmpCreated": False,
                "serviceStartRequested": False,
                "serviceStartCountMaximum": 1,
                "disposableEmulatorMutationOnly": True,
            },
        }
        rc = 3
    receipt.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    diagnostic = {
        "classification": data["classification"],
        "oracleSatisfied": data["oracleSatisfied"],
    }
    if isinstance(data.get("wire"), dict):
        diagnostic["wire"] = {
            "captureComplete": data["wire"].get("captureComplete"),
            "perCallCaptureComplete": {
                key: (data["wire"].get(key) or {}).get("captureComplete")
                for key in ("preStatus", "start", "postStatus")
            },
            "comparisons": data["wire"].get("comparisons", {}),
        }
    if isinstance(data.get("instrumentation"), dict):
        diagnostic["instrumentation"] = {
            "allCallsInstrumentationReady": data["instrumentation"].get("allCallsInstrumentationReady"),
            "prePostStatusEqual": data["instrumentation"].get("prePostStatusEqual"),
            "startDiffersFromStatus": data["instrumentation"].get("startDiffersFromStatus"),
            "perTarget": data["instrumentation"].get("perTarget", []),
            "callDiagnostics": data["instrumentation"].get("callDiagnostics", {}),
        }
    if isinstance(data.get("runtimeSummary"), dict):
        diagnostic["runtimeSummary"] = data["runtimeSummary"]
    print(json.dumps(diagnostic, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
