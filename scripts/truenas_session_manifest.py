#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

SCHEMA = "truenas-session/v1"
CAPSULE_SCHEMA = "truenas-capsule/v1"
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,79}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
KINDS = {
    "substrate-sanity", "foundry-control", "official-catalog-control",
    "foundry-product", "oci-custom-app-feature", "vm-management-plane",
    "nested-virtualization",
}
RETRY_POLICIES = {"none", "read-only-reconcile"}
MAX_CAPSULES = 24

class SessionError(RuntimeError):
    pass

def _load_json(path: pathlib.Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SessionError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SessionError(f"{path}: top-level value must be an object")
    return value

def _positive_int(value, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise SessionError(f"{label} must be a positive integer")
    return value

def _string(value, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SessionError(f"{label} must be a non-empty string")
    return value

def canonical_payload(doc: dict) -> bytes:
    payload = dict(doc)
    payload.pop("manifest_sha256", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def manifest_digest(doc: dict) -> str:
    return hashlib.sha256(canonical_payload(doc)).hexdigest()

def load_target_versions(path: pathlib.Path) -> set[str]:
    registry = _load_json(path)
    if registry.get("schema") != "gha-kvm-truenas-targets/v1":
        raise SessionError("unsupported TrueNAS target registry schema")
    targets = registry.get("targets")
    if not isinstance(targets, list) or not targets:
        raise SessionError("TrueNAS target registry has no targets")
    versions = set()
    for index, target in enumerate(targets):
        if not isinstance(target, dict):
            raise SessionError(f"targets[{index}] must be an object")
        version = _string(target.get("version"), f"targets[{index}].version")
        if version in versions:
            raise SessionError(f"duplicate TrueNAS target version: {version}")
        versions.add(version)
    return versions

def load_provider_ids(path: pathlib.Path) -> set[str]:
    registry = _load_json(path)
    if registry.get("schema") != "truenas-capsule-providers/v1":
        raise SessionError("unsupported capsule provider registry schema")
    providers = registry.get("providers")
    if not isinstance(providers, list):
        raise SessionError("capsule provider registry providers must be a list")
    ids = set()
    for index, provider in enumerate(providers):
        if not isinstance(provider, dict):
            raise SessionError(f"providers[{index}] must be an object")
        provider_id = _string(provider.get("id"), f"providers[{index}].id")
        if provider_id in ids:
            raise SessionError(f"duplicate capsule provider id: {provider_id}")
        ids.add(provider_id)
    return ids

def validate_capsule(capsule: dict, index: int, provider_ids: set[str]) -> dict:
    prefix = f"capsules[{index}]"
    if not isinstance(capsule, dict):
        raise SessionError(f"{prefix} must be an object")
    if capsule.get("schema") != CAPSULE_SCHEMA:
        raise SessionError(f"{prefix}: unsupported capsule schema")
    capsule_id = _string(capsule.get("id"), f"{prefix}.id")
    if not ID_RE.fullmatch(capsule_id):
        raise SessionError(f"{prefix}.id has invalid syntax")
    kind = _string(capsule.get("kind"), f"{prefix}.kind")
    if kind not in KINDS:
        raise SessionError(f"{prefix}.kind is not admitted: {kind}")
    provider = _string(capsule.get("provider"), f"{prefix}.provider")
    if provider not in provider_ids:
        raise SessionError(f"{prefix}.provider is not registered: {provider}")
    authority = capsule.get("authority")
    if not isinstance(authority, dict):
        raise SessionError(f"{prefix}.authority must be an object")
    repo = _string(authority.get("repository"), f"{prefix}.authority.repository")
    if not REPO_RE.fullmatch(repo):
        raise SessionError(f"{prefix}.authority.repository must be owner/name")
    issue = _positive_int(authority.get("issue"), f"{prefix}.authority.issue")
    exact = capsule.get("exact")
    if not isinstance(exact, dict) or not exact:
        raise SessionError(f"{prefix}.exact must be a non-empty object")
    for key, value in exact.items():
        _string(key, f"{prefix}.exact key")
        _string(value, f"{prefix}.exact.{key}")
    namespace = _string(capsule.get("namespace"), f"{prefix}.namespace")
    if not ID_RE.fullmatch(namespace):
        raise SessionError(f"{prefix}.namespace has invalid syntax")
    ports = capsule.get("ports", [])
    if not isinstance(ports, list):
        raise SessionError(f"{prefix}.ports must be a list")
    normalized_ports = []
    for port in ports:
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise SessionError(f"{prefix}.ports contains an invalid port")
        normalized_ports.append(port)
    if len(normalized_ports) != len(set(normalized_ports)):
        raise SessionError(f"{prefix}.ports contains duplicates")
    requirements = capsule.get("requirements", [])
    if not isinstance(requirements, list) or any(not isinstance(x, str) or not x for x in requirements):
        raise SessionError(f"{prefix}.requirements must be a list of non-empty strings")
    resources = capsule.get("resources")
    if not isinstance(resources, dict):
        raise SessionError(f"{prefix}.resources must be an object")
    memory_mib = _positive_int(resources.get("memory_mib"), f"{prefix}.resources.memory_mib")
    download_mib = _positive_int(resources.get("download_mib"), f"{prefix}.resources.download_mib")
    estimated_minutes = _positive_int(resources.get("estimated_minutes"), f"{prefix}.resources.estimated_minutes")
    phases = capsule.get("phases")
    if not isinstance(phases, dict):
        raise SessionError(f"{prefix}.phases must be an object")
    for phase in ("setup", "apply", "verify", "cleanup"):
        if phases.get(phase) is not True:
            raise SessionError(f"{prefix}.phases.{phase} must be true")
    oracle = _string(capsule.get("oracle"), f"{prefix}.oracle")
    receipt_contract = _string(capsule.get("receipt_contract"), f"{prefix}.receipt_contract")
    retry_policy = _string(capsule.get("retry_policy"), f"{prefix}.retry_policy")
    if retry_policy not in RETRY_POLICIES:
        raise SessionError(f"{prefix}.retry_policy is not admitted: {retry_policy}")
    mutating = capsule.get("mutating")
    if not isinstance(mutating, bool):
        raise SessionError(f"{prefix}.mutating must be boolean")
    cleanup_required = capsule.get("cleanup_required")
    if not isinstance(cleanup_required, bool):
        raise SessionError(f"{prefix}.cleanup_required must be boolean")
    if mutating and not cleanup_required:
        raise SessionError(f"{prefix}: mutating capsules must require cleanup")
    dependencies = capsule.get("dependencies", [])
    if not isinstance(dependencies, list) or any(not isinstance(x, str) or not x for x in dependencies):
        raise SessionError(f"{prefix}.dependencies must be a list of capsule ids")
    return {
        "id": capsule_id, "kind": kind, "provider": provider,
        "authority": {"repository": repo, "issue": issue},
        "namespace": namespace, "ports": normalized_ports,
        "resources": {"memory_mib": memory_mib, "download_mib": download_mib, "estimated_minutes": estimated_minutes},
        "oracle": oracle, "receipt_contract": receipt_contract,
        "retry_policy": retry_policy, "mutating": mutating,
        "cleanup_required": cleanup_required, "dependencies": dependencies,
    }

def validate_manifest(manifest_path: pathlib.Path, target_registry_path: pathlib.Path, provider_registry_path: pathlib.Path) -> dict:
    doc = _load_json(manifest_path)
    if doc.get("schema") != SCHEMA:
        raise SessionError("unsupported TrueNAS session schema")
    session_id = _string(doc.get("session_id"), "session_id")
    if not ID_RE.fullmatch(session_id):
        raise SessionError("session_id has invalid syntax")
    version = _string(doc.get("version"), "version")
    if version not in load_target_versions(target_registry_path):
        raise SessionError(f"exact TrueNAS target is not registered: {version}")
    authority = doc.get("authority")
    if not isinstance(authority, dict):
        raise SessionError("authority must be an object")
    authority_repo = _string(authority.get("repository"), "authority.repository")
    if not REPO_RE.fullmatch(authority_repo):
        raise SessionError("authority.repository must be owner/name")
    authority_issue = _positive_int(authority.get("issue"), "authority.issue")
    budget = doc.get("budget")
    if not isinstance(budget, dict):
        raise SessionError("budget must be an object")
    guest_memory_mib = _positive_int(budget.get("guest_memory_mib"), "budget.guest_memory_mib")
    download_mib = _positive_int(budget.get("download_mib"), "budget.download_mib")
    timeout_minutes = _positive_int(budget.get("timeout_minutes"), "budget.timeout_minutes")
    if guest_memory_mib > 8192:
        raise SessionError("budget.guest_memory_mib exceeds the current 8-GiB guardrail")
    if timeout_minutes > 50:
        raise SessionError("budget.timeout_minutes exceeds the current 50-minute guardrail")
    pool = doc.get("pool")
    if not isinstance(pool, dict):
        raise SessionError("pool must be an object")
    pool_name = _string(pool.get("name"), "pool.name")
    if not ID_RE.fullmatch(pool_name):
        raise SessionError("pool.name has invalid syntax")
    if _positive_int(pool.get("data_disks"), "pool.data_disks") != 2:
        raise SessionError("pool.data_disks must preserve the qualified two-disk topology")
    capsules = doc.get("capsules")
    if not isinstance(capsules, list) or not capsules:
        raise SessionError("capsules must be a non-empty list")
    if len(capsules) > MAX_CAPSULES:
        raise SessionError(f"capsules exceeds bounded limit {MAX_CAPSULES}")
    provider_ids = load_provider_ids(provider_registry_path)
    normalized = [validate_capsule(c, i, provider_ids) for i, c in enumerate(capsules)]
    ids = [c["id"] for c in normalized]
    if len(ids) != len(set(ids)):
        raise SessionError("capsule ids must be unique")
    namespaces = [c["namespace"] for c in normalized]
    if len(namespaces) != len(set(namespaces)):
        raise SessionError("capsule namespaces must be unique")
    all_ports = [p for c in normalized for p in c["ports"]]
    if len(all_ports) != len(set(all_ports)):
        raise SessionError("capsule ports must be globally unique within a session")
    ids_set = set(ids)
    depmap = {c["id"]: c["dependencies"] for c in normalized}
    for c in normalized:
        if c["id"] in c["dependencies"]:
            raise SessionError(f"{c['id']}: self-dependency is forbidden")
        missing = sorted(set(c["dependencies"]) - ids_set)
        if missing:
            raise SessionError(f"{c['id']}: unknown dependencies: {', '.join(missing)}")
    visiting, visited = set(), set()
    def visit(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            raise SessionError("capsule dependency cycle detected")
        visiting.add(node)
        for dep in depmap[node]:
            visit(dep)
        visiting.remove(node)
        visited.add(node)
    for node in ids:
        visit(node)
    max_memory = max(c["resources"]["memory_mib"] for c in normalized)
    total_download = sum(c["resources"]["download_mib"] for c in normalized)
    total_minutes = sum(c["resources"]["estimated_minutes"] for c in normalized)
    if max_memory > guest_memory_mib:
        raise SessionError("capsule memory ceiling exceeds session guest-memory budget")
    if total_download > download_mib:
        raise SessionError("capsule download budgets exceed session download budget")
    if total_minutes > timeout_minutes:
        raise SessionError("capsule estimated time exceeds session timeout budget")
    computed = manifest_digest(doc)
    declared = doc.get("manifest_sha256")
    if not isinstance(declared, str) or not SHA256_RE.fullmatch(declared):
        raise SessionError("manifest_sha256 must be exact lowercase sha256")
    if declared != computed:
        raise SessionError(f"manifest_sha256 mismatch: declared {declared}, computed {computed}")
    return {
        "schema": SCHEMA, "session_id": session_id, "version": version,
        "authority": {"repository": authority_repo, "issue": authority_issue},
        "manifest_sha256": computed, "capsule_count": len(normalized),
        "mutating_capsule_count": sum(1 for c in normalized if c["mutating"]),
        "max_capsule_memory_mib": max_memory,
        "total_download_mib": total_download,
        "total_estimated_minutes": total_minutes,
    }

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--targets", type=pathlib.Path, default=pathlib.Path("config/truenas-rdte-targets.json"))
    parser.add_argument("--providers", type=pathlib.Path, default=pathlib.Path("config/truenas-capsule-providers.json"))
    parser.add_argument("--digest-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.digest_only:
            print(manifest_digest(_load_json(args.manifest)))
            return 0
        print(json.dumps(validate_manifest(args.manifest, args.targets, args.providers), indent=2, sort_keys=True))
        return 0
    except SessionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
