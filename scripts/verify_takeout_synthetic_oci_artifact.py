#!/usr/bin/env python3
"""Offline, read-only integrity gate for an exact GHA synthetic OCI artifact.

This is a portable OCI integrity probe, not an OCI importer or TrueNAS actuator.
All inputs are public fixture bytes; receipts cannot prove actual guest execution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile
import zipfile

DIGEST = re.compile(r"sha256:([0-9a-f]{64})\Z")
ARTIFACT_FILES = frozenset({
    "first.json", "restart.json", "receipt.json", "source-sha.txt",
    "loaded-config-digest.txt", "image.json", "fixture.oci.tar",
})
MAX_TAR = 512 * 1024 * 1024
DOCKER_TRANSPORT = "fixture.docker.tar.gz"
MAX_SMALL = 256 * 1024


class Blocked(ValueError):
    pass


def require(value: bool, reason: str) -> None:
    if not value:
        raise Blocked(reason)


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for data in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(data)
    return "sha256:" + h.hexdigest()


def json_obj(data: bytes, description: str) -> dict:
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise Blocked(description + "_JSON") from exc
    require(isinstance(value, dict), description + "_OBJECT")
    return value


def digest_hex(value: str) -> str:
    match = DIGEST.fullmatch(value) if isinstance(value, str) else None
    require(match is not None, "UNQUALIFIED_DIGEST")
    return match.group(1)


def stream_oci(stream, image_digest: str, loaded_config: str) -> dict:
    collected, sizes = {}, {}
    seen_files = set()
    size_total = 0
    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        for entry in archive:
            require(entry.name not in seen_files, "DUPLICATE_OCI_PATH")
            seen_files.add(entry.name)
            require(entry.isdir() or entry.isfile(), "UNSAFE_OCI_MEMBER")
            if entry.isdir():
                require(entry.name in {"blobs", "blobs/sha256"}, "FOREIGN_OCI_DIRECTORY")
                continue
            require(entry.name in {"index.json", "oci-layout"} or
                    (entry.name.startswith("blobs/sha256/") and
                     re.fullmatch(r"[0-9a-f]{64}", entry.name.split("/")[-1])),
                    "FOREIGN_OCI_MEMBER")
            require(0 <= entry.size <= MAX_TAR, "OCI_MEMBER_TOO_LARGE")
            size_total += entry.size
            require(size_total <= MAX_TAR, "OCI_ARCHIVE_TOO_LARGE")
            body = archive.extractfile(entry)
            require(body is not None, "OCI_MISSING_BODY")
            h = hashlib.sha256()
            capture = bytearray()
            remaining = entry.size
            while remaining:
                data = body.read(min(1024 * 1024, remaining))
                require(bool(data), "TRUNCATED_OCI_BLOB")
                h.update(data)
                if entry.size <= MAX_SMALL:
                    capture.extend(data)
                remaining -= len(data)
            if entry.name.startswith("blobs/sha256/"):
                require(h.hexdigest() == entry.name.split("/")[-1], "TAMPERED_OCI_BLOB")
            if entry.size <= MAX_SMALL:
                collected[entry.name] = bytes(capture)
            sizes[entry.name] = entry.size
    require(set(sizes) >= {"index.json", "oci-layout"}, "INCOMPLETE_OCI_LAYOUT")
    layout = json_obj(collected.get("oci-layout", b""), "LAYOUT")
    require(layout.get("imageLayoutVersion") == "1.0.0", "UNSUPPORTED_OCI_LAYOUT")
    index = json_obj(collected.get("index.json", b""), "INDEX")
    descriptors = index.get("manifests")
    require(isinstance(descriptors, list) and len(descriptors) == 1, "AMBIGUOUS_OCI_INDEX")
    descriptor = descriptors[0]
    require(isinstance(descriptor, dict) and descriptor.get("digest") == image_digest,
            "IMAGE_DIGEST_MISMATCH")
    platform = descriptor.get("platform") or {}
    require(platform.get("os") == "linux" and platform.get("architecture") == "amd64",
            "WRONG_PLATFORM")
    manifest_path = "blobs/sha256/" + digest_hex(image_digest)
    require(descriptor.get("size") == sizes.get(manifest_path), "MANIFEST_SIZE_MISMATCH")
    manifest = json_obj(collected.get(manifest_path, b""), "MANIFEST")
    require(manifest.get("schemaVersion") == 2, "UNSUPPORTED_IMAGE_MANIFEST")
    config_descriptor = manifest.get("config") or {}
    require(config_descriptor.get("digest") == loaded_config, "LOADED_CONFIG_MISMATCH")
    config_path = "blobs/sha256/" + digest_hex(loaded_config)
    require(config_descriptor.get("size") == sizes.get(config_path), "CONFIG_SIZE_MISMATCH")
    config = json_obj(collected.get(config_path, b""), "CONFIG")
    require(config.get("os") == "linux" and config.get("architecture") == "amd64",
            "CONFIG_PLATFORM_MISMATCH")
    runtime = config.get("config") or {}
    require(runtime.get("User") == "10001:10001", "WRONG_RUNTIME_USER")
    require(runtime.get("Entrypoint") == ["python3", "/app/fixture.py"], "WRONG_ENTRYPOINT")
    require(not runtime.get("ExposedPorts"), "UNEXPECTED_PUBLIC_PORT")
    layers = manifest.get("layers")
    require(isinstance(layers, list) and len(layers) == 5, "UNEXPECTED_LAYER_COUNT")
    expected = {manifest_path, config_path}
    for item in layers:
        require(isinstance(item, dict), "MALFORMED_OCI_LAYER")
        name = "blobs/sha256/" + digest_hex(item.get("digest"))
        require(item.get("size") == sizes.get(name), "LAYER_SIZE_MISMATCH")
        expected.add(name)
    require({name for name in sizes if name.startswith("blobs/sha256/")} == expected,
            "UNEXPECTED_OCI_BLOBS")
    return {"image_digest": image_digest, "layers": len(layers),
            "os": "linux", "arch": "amd64", "uid": "10001:10001"}


def verify(path: Path, artifact_digest: str, image_digest: str, source_sha: str) -> dict:
    digest_hex(artifact_digest)
    digest_hex(image_digest)
    require(isinstance(source_sha, str) and re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None,
            "INVALID_SOURCE_SHA")
    require(path.is_file() and not path.is_symlink(), "UNTRUSTED_ARTIFACT_PATH")
    require(file_hash(path) == artifact_digest, "ARTIFACT_DIGEST_MISMATCH")
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        docker_transport = DOCKER_TRANSPORT in names
        expected = ARTIFACT_FILES | ({DOCKER_TRANSPORT} if docker_transport else set())
        require(len(names) == len(expected) and set(names) == expected,
                "ARTIFACT_MEMBER_INVENTORY")
        require(all(not z.getinfo(name).is_dir() and not z.getinfo(name).flag_bits & 1 for name in names),
                "UNSAFE_ARTIFACT_MEMBER")
        require(z.getinfo("fixture.oci.tar").file_size <= MAX_TAR, "OCI_ARCHIVE_TOO_LARGE")
        receipt = json_obj(z.read("receipt.json"), "RECEIPT")
        require(z.read("source-sha.txt").decode("ascii").strip() == source_sha,
                "SOURCE_SHA_MISMATCH")
        require(receipt.get("source_sha") == source_sha and
                receipt.get("image_digest") == image_digest, "RECEIPT_IDENTITY_MISMATCH")
        require(receipt.get("guest") == "NOT_RUN" and receipt.get("admission") == "HOLD" and
                receipt.get("guest_attempt_budget") == 0, "INVALID_QUALIFICATION_CLAIM")
        if docker_transport:
            require(z.getinfo(DOCKER_TRANSPORT).file_size <= MAX_TAR,
                    "DOCKER_ARCHIVE_TOO_LARGE")
            require(receipt.get("docker_archive_format") == "gzip-docker-save" and
                    receipt.get("offline_docker_archive_load") == "PASS" and
                    receipt.get("imported_image_config_identity") == "PASS" and
                    receipt.get("imported_container_noop") == "PASS",
                    "DOCKER_IMPORT_NOT_QUALIFIED")
            h = hashlib.sha256()
            with z.open(DOCKER_TRANSPORT) as f:
                require(f.read(2) == b"\x1f\x8b", "DOCKER_ARCHIVE_FORMAT")
                f.seek(0) if f.seekable() else None
            with z.open(DOCKER_TRANSPORT) as f:
                for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
                    h.update(chunk)
            require(receipt.get("docker_archive_sha256") == "sha256:" + h.hexdigest(),
                    "DOCKER_ARCHIVE_DIGEST_MISMATCH")
        loaded = z.read("loaded-config-digest.txt").decode("ascii").strip()
        digest_hex(loaded)
        with z.open("fixture.oci.tar") as f:
            result = stream_oci(f, image_digest, loaded)
    return {"status": "PASS", "classification": "OCI_ARTIFACT_INTEGRITY_ONLY",
            "artifact_digest": artifact_digest, "source_sha": source_sha,
            **result, "docker_archive_transferred": docker_transport,
            "docker_archive_import_receipt": "PASS" if docker_transport else "NOT_RUN",
            "truenas_guest": "NOT_RUN", "physical_apply": "HOLD"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_zip", type=Path)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    try:
        result = verify(args.artifact_zip, args.artifact_digest,
                        args.image_digest, args.source_sha)
    except (Blocked, ValueError, zipfile.BadZipFile, tarfile.TarError,
            OSError, UnicodeError) as exc:
        # Never leak filename, HTTP URL or exception detail from untrusted input.
        print(json.dumps({"status": "BLOCKED", "reason": exc.args[0] if isinstance(exc, Blocked) else "MALFORMED_ARTIFACT"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
