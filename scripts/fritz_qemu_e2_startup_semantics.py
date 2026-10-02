#!/usr/bin/env python3
"""Public-safe FRITZ!OS E2-D2 startup-semantics recovery.

Recover only normalized launch/control metadata from exact 8.25 shell startup
files. Raw proprietary script lines and arbitrary strings are never emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shlex

_BASE_SCRIPT = pathlib.Path(__file__).with_name("fritz_qemu_user_probe.py")
_BASE_SPEC = importlib.util.spec_from_file_location("fritz_qemu_user_probe", _BASE_SCRIPT)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("unable to load fritz_qemu_user_probe.py")
base = importlib.util.module_from_spec(_BASE_SPEC)
_BASE_SPEC.loader.exec_module(base)

SCHEMA_VERSION = 1
EXPERIMENT = "fritz-qemu-e2-startup-semantics/v1"

SCAN_PREFIXES = ("etc/init.d/", "etc/boot.d/", "etc/rc")
SAFE_SERVICES = {"ctlmgr"}
SAFE_CONTROLLERS = {"svctl", "supervisor"}
SAFE_VERBS = {"start", "stop", "restart", "reload", "status"}
MAX_FILE_BYTES = 2 * 1024 * 1024


def read_text(path: pathlib.Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > MAX_FILE_BYTES or b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def clean_token(token: str) -> str:
    return token.strip().strip("'\"")


def token_kind(token: str) -> dict:
    t = clean_token(token)
    if not t:
        return {"kind": "empty"}
    if t.startswith("$"):
        name = t[1:]
        if name.startswith("{") and name.endswith("}"):
            name = name[1:-1]
        return {"kind": "variable", "name": name[:128]}
    if t.startswith("/") and len(t) <= 512:
        return {"kind": "absolute_path", "value": t}
    if t in SAFE_SERVICES:
        return {"kind": "service", "value": t}
    if t in SAFE_VERBS:
        return {"kind": "verb", "value": t}
    if t.startswith("-") and len(t) <= 64 and re.fullmatch(r"-{1,2}[A-Za-z0-9_-]+", t):
        return {"kind": "option", "value": t}
    return {
        "kind": "opaque",
        "sha256": hashlib.sha256(t.encode("utf-8", errors="replace")).hexdigest(),
        "length": len(t),
    }


def safe_shell_words(line: str) -> list[str]:
    try:
        return shlex.split(line, comments=True, posix=True)
    except ValueError:
        return []


def supervisor_invocations(text: str, source: str) -> list[dict]:
    out: list[dict] = []
    for line in text.splitlines():
        if "supervisor" not in line:
            continue
        words = safe_shell_words(line)
        for idx, word in enumerate(words):
            base_name = pathlib.PurePosixPath(clean_token(word)).name
            if base_name != "supervisor":
                continue
            args: list[dict] = []
            for raw in words[idx + 1 :]:
                if raw in (";", "&&", "||", "|"):
                    break
                args.append(token_kind(raw))
            out.append({
                "source": source,
                "executable": "/bin/supervisor" if word.endswith("/supervisor") else "supervisor",
                "argCount": len(args),
                "args": args,
            })
    return out


def ctlmgr_assignment_facts(text: str, source: str) -> list[dict]:
    facts: list[dict] = []
    assign_re = re.compile(
        r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^#;]+)"
    )
    for line in text.splitlines():
        m = assign_re.match(line)
        if not m:
            continue
        var = m.group(1)
        rhs = m.group(2).strip().strip("'\"")
        words = rhs.split()
        if "ctlmgr" not in words and rhs != "ctlmgr":
            continue
        facts.append({
            "source": source,
            "variable": var,
            "containsCtlmgr": True,
            "literalTokenCount": len(words) if words else 1,
            "exactCtlmgrOnly": rhs == "ctlmgr",
        })

    for_re = re.compile(
        r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^;]+)"
    )
    for line in text.splitlines():
        m = for_re.search(line)
        if not m:
            continue
        words = [clean_token(x) for x in m.group(2).split()]
        if "ctlmgr" not in words:
            continue
        facts.append({
            "source": source,
            "variable": m.group(1),
            "containsCtlmgr": True,
            "literalTokenCount": len(words),
            "exactCtlmgrOnly": len(words) == 1,
            "bindingKind": "for-list",
        })
    return facts


def svctl_consumers(text: str, source: str) -> list[dict]:
    out: list[dict] = []
    for line in text.splitlines():
        if "svctl" not in line:
            continue
        words = safe_shell_words(line)
        indices = [
            i for i, word in enumerate(words)
            if pathlib.PurePosixPath(clean_token(word)).name == "svctl"
        ]
        for idx in indices:
            tail = words[idx + 1 :]
            verb = next((clean_token(x) for x in tail if clean_token(x) in SAFE_VERBS), None)
            service = next((clean_token(x) for x in tail if clean_token(x) in SAFE_SERVICES), None)
            variables = [
                token_kind(x)["name"]
                for x in tail
                if token_kind(x).get("kind") == "variable"
            ]
            out.append({
                "source": source,
                "controller": "svctl",
                "verb": verb,
                "literalService": service,
                "variableRefs": sorted(set(variables)),
                "argShape": [token_kind(x) for x in tail[:8]],
            })
    return out


def fixed_related_paths(text: str, source: str) -> list[dict]:
    paths: set[str] = set()
    for line in text.splitlines():
        if not any(k in line for k in ("supervisor", "svctl", "ctlmgr")):
            continue
        for p in re.findall(r"(?<![A-Za-z0-9_])(/(?:etc|bin|sbin|usr|var)/[^\s'\";|&()]{1,300})", line):
            p = p.rstrip(",:")
            if len(p) <= 512:
                paths.add(p)
    return [{"source": source, "path": p} for p in sorted(paths)]


def correlate(assignments: list[dict], consumers: list[dict]) -> list[dict]:
    assigned: dict[tuple[str, str], dict] = {
        (x["source"], x["variable"]): x for x in assignments
    }
    out: list[dict] = []
    for c in consumers:
        if c.get("literalService") == "ctlmgr" and c.get("verb"):
            out.append({
                "source": c["source"],
                "controller": "svctl",
                "verb": c["verb"],
                "service": "ctlmgr",
                "evidenceKind": "literal",
            })
        for var in c.get("variableRefs", []):
            fact = assigned.get((c["source"], var))
            if not fact or not c.get("verb"):
                continue
            out.append({
                "source": c["source"],
                "controller": "svctl",
                "verb": c["verb"],
                "service": "ctlmgr",
                "variable": var,
                "evidenceKind": "same-file-variable-flow",
                "exactCtlmgrOnly": fact.get("exactCtlmgrOnly", False),
                "bindingKind": fact.get("bindingKind", "assignment"),
            })
    uniq = {
        json.dumps(x, sort_keys=True): x for x in out
    }
    return [uniq[k] for k in sorted(uniq)]


def build(root: pathlib.Path) -> dict:
    invocations: list[dict] = []
    assignments: list[dict] = []
    consumers: list[dict] = []
    paths: list[dict] = []
    scanned: list[str] = []

    for path in base.regular_files(root):
        rel = str(path.relative_to(root)).replace(os.sep, "/")
        if not rel.startswith(SCAN_PREFIXES):
            continue
        text = read_text(path)
        if text is None:
            continue
        if not any(k in text for k in ("supervisor", "svctl", "ctlmgr")):
            continue
        source = "/" + rel
        scanned.append(source)
        invocations.extend(supervisor_invocations(text, source))
        assignments.extend(ctlmgr_assignment_facts(text, source))
        consumers.extend(svctl_consumers(text, source))
        paths.extend(fixed_related_paths(text, source))

    unique_paths = {
        (x["source"], x["path"]): x for x in paths
    }
    return {
        "relevantTextFiles": sorted(set(scanned)),
        "supervisorInvocations": invocations,
        "ctlmgrVariableBindings": assignments,
        "svctlConsumers": consumers,
        "ctlmgrSvctlRelations": correlate(assignments, consumers),
        "relatedAbsolutePaths": [unique_paths[k] for k in sorted(unique_paths)],
    }


def run_probe(args: argparse.Namespace) -> dict:
    work = pathlib.Path(args.work_dir).resolve()
    firmware = work / "original" / "firmware.image"
    payload = work / "payload"
    roots_dir = work / "roots"
    scratch = work / "scratch"
    for p in (firmware.parent, payload, roots_dir, scratch):
        p.mkdir(parents=True, exist_ok=True)

    exact = base.download_exact(
        args.firmware_url, firmware,
        expected_size=args.expected_size,
        expected_sha256=args.expected_sha256,
    )
    outer = base.extract_outer(firmware, payload)
    roots = base.extract_squashfs_roots(payload, roots_dir, scratch)
    root = base.select_root(roots)
    discovery = build(root)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "experiment": EXPERIMENT,
        "classification": "STARTUP_SEMANTICS_DISCOVERY_COMPLETE",
        "oracleSatisfied": True,
        "target": {
            "kind": "public-runtime-download",
            "expectedBytes": args.expected_size,
            "expectedSha256": args.expected_sha256.lower(),
            "observedBytes": exact["bytes"],
            "observedSha256": exact["sha256"],
        },
        "extraction": {
            "outerMemberCount": len(outer),
            "squashfsRootCount": len(roots),
            "selectedRootRegularFileCount": base.root_file_count(root),
        },
        "discovery": discovery,
        "safety": {
            "rawFirmwarePublished": False,
            "rootfsPublished": False,
            "binaryPayloadPublished": False,
            "rawSourceContentPublished": False,
            "arbitraryExtractedStringsPublished": False,
            "physicalRouterContact": False,
            "routerMutationAuthorized": False,
        },
    }


def parse_args(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--firmware-url", required=True)
    p.add_argument("--expected-size", required=True, type=int)
    p.add_argument("--expected-sha256", required=True)
    p.add_argument("--work-dir", required=True)
    p.add_argument("--receipt", required=True)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    receipt_path = pathlib.Path(args.receipt)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        receipt = run_probe(args)
        rc = 0
    except Exception as exc:
        receipt = {
            "schemaVersion": SCHEMA_VERSION,
            "experiment": EXPERIMENT,
            "classification": "HARNESS_FAILURE",
            "oracleSatisfied": False,
            "error": {"type": type(exc).__name__, "message": str(exc)[:1000]},
            "safety": {
                "rawFirmwarePublished": False,
                "rootfsPublished": False,
                "binaryPayloadPublished": False,
                "rawSourceContentPublished": False,
                "arbitraryExtractedStringsPublished": False,
                "physicalRouterContact": False,
                "routerMutationAuthorized": False,
            },
        }
        rc = 3
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"classification": receipt["classification"], "oracleSatisfied": receipt["oracleSatisfied"]}, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
