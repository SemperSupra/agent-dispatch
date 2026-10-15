#!/usr/bin/env python3
"""Bounded actual Lantern ZIP stage into ONE disposable TrueNAS vanilla26.3 ZFS world.

No untrusted archive extraction, no general file manager or world controller,
no player semantics and no physical TrueNAS authority. The native T6 owner
probe supplies authenticated guest-only middleware callbacks.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile

SCHEMA = "supracraft.native-vanilla263-lantern-artifact-stage/1"
PRODUCER = "SupraCraft/mc-server-images@7f888b5829f4e5576d5ce512d86327348c43f01e"
WORLD = "/mnt/rdtepool/minecraft-vanilla-263-t6-world"
NAME = "lantern-restoration-26.3.zip"
SHA = "da25005e8729e6f013f7108ac5b8869dd46323befc78efdae18221b26cafe5f8"
TARGET = WORLD + "/datapacks/" + NAME
MEMBERS = {
    "pack.mcmeta",
    "data/minecraft/tags/function/tick.json",
    "data/supracraft_core_restore/function/tick.mcfunction",
}
MAX_ZIP = 1024 * 1024

class Refused(RuntimeError):
    pass

def require(test: bool, code: str) -> None:
    if not test:
        raise Refused(code)

def verify_exact_candidate(blob_path: Path, manifest_path: Path) -> tuple[bytes,dict]:
    require(blob_path.is_file() and not blob_path.is_symlink()
            and manifest_path.is_file() and not manifest_path.is_symlink(),
            "PINNED_REAL_ARTIFACT_MISSING")
    require(0 < blob_path.stat().st_size < MAX_ZIP
            and 0 < manifest_path.stat().st_size < 65536,
            "PINNED_REAL_ARTIFACT_SIZE_OUT_OF_BOUNDS")
    m = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(type(m) is dict and
            m.get("schema") == "supracraft-vanilla-datapack-candidate/1" and
            m.get("classification") == "SOURCE_ARTIFACT_EXPORTED" and
            m.get("producer") == PRODUCER and
            m.get("kind") == "datapack" and m.get("backend") == "vanilla" and
            m.get("minecraft_version") == "26.3" and
            m.get("world_id") == "lantern-rdte" and
            m.get("release_id") == "lantern-core-restore-26-3" and
            m.get("pack_format") == [121, 0] and
            m.get("relative_path") == NAME and
            m.get("world_save_included") is False and
            m.get("collage_deployed") is False,
            "PINNED_REAL_ARTIFACT_CONTRACT_DRIFT")
    content = blob_path.read_bytes()
    require(hashlib.sha256(content).hexdigest() == SHA and
            m.get("sha256") == SHA and
            m.get("archive_size") == len(content),
            "PINNED_REAL_ARTIFACT_SHA_DRIFT")
    require(type(m.get("members")) is list and len(m["members"]) == 3,
            "PINNED_REAL_ARTIFACT_MEMBERS_INVALID")
    rows = m["members"]
    require(all(type(r) is dict and set(r) == {"path","sha256","bytes"} and
                type(r.get("path")) is str and r["path"] in MEMBERS and
                isinstance(r.get("sha256"),str) and
                type(r.get("bytes")) is int for r in rows) and
            {r["path"] for r in rows} == MEMBERS,
            "PINNED_REAL_ARTIFACT_MEMBER_DECLARATION_DRIFT")
    expected = {r["path"]: r for r in rows}
    with zipfile.ZipFile(blob_path) as z:
        info = z.infolist()
        require(len(info) == len(MEMBERS) and
                {f.filename for f in info} == MEMBERS,
                "PINNED_REAL_ZIP_MEMBER_SET_DRIFT")
        for row in info:
            require(not row.is_dir() and not (row.flag_bits & 1) and
                    (row.external_attr >> 16) & 0o170000 == 0o100000 and
                    row.file_size <= 128*1024 and
                    not row.filename.startswith("/") and
                    ".." not in PurePosixPath(row.filename).parts,
                    "PINNED_REAL_ZIP_MEMBER_UNSAFE")
            member = z.read(row)
            want = expected[row.filename]
            require(len(member) == want["bytes"] and
                    hashlib.sha256(member).hexdigest() == want["sha256"],
                    "PINNED_REAL_ZIP_MEMBER_SHA_DRIFT")
        metadata = json.loads(z.read("pack.mcmeta"))
        require(metadata.get("pack",{}).get("min_format") == [121,0] and
                metadata.get("pack",{}).get("max_format") == [121,0],
                "PINNED_REAL_ZIP_PACK_FORMAT_DRIFT")
    return content, {"schema":SCHEMA, "producer":PRODUCER, "sha256":SHA,
                     "size":len(content), "world":"lantern-rdte",
                     "release":"lantern-core-restore-26-3",
                     "target": "disposable_native_truenas_25.04.2.6"}

def stage(call, wait_job, multipart_upload, http_bytes, *,
          host: str, port: int, tls: bool, username: str, password: str,
          timeout: float, blob: bytes, evidence: dict) -> dict:
    """Stage solely while exact native App is STOPPED. No filesystem shell."""
    require(type(blob) is bytes and hashlib.sha256(blob).hexdigest() == SHA and
            evidence.get("sha256") == SHA, "UNVERIFIED_ARTIFACT_BYTES")
    rows = call("app.query", [[["id", "=", "rdte-t6-minecraft-vanilla-263"]]])
    require(type(rows) is list and len(rows) == 1 and
            rows[0].get("state") == "STOPPED",
            "NATIVE_APP_MUST_BE_QUIESCED_BEFORE_STAGE")
    parent = call("filesystem.stat", [WORLD + "/datapacks"])
    require(type(parent) is dict and parent.get("type") == "DIRECTORY",
            "OWNED_WORLD_DATAPACK_DIRECTORY_ABSENT")
    try:
        current = call("filesystem.stat", [TARGET])
    except Exception:
        current = None
    require(current is None, "REFUSE_TO_OVERWRITE_EXISTING_NATIVE_WORLD_ARTIFACT")
    upload_job = multipart_upload(host,port,tls,username,password,TARGET,blob,0o644,timeout)
    wait_job(upload_job,"Lantern datapack exact native ZFS world file stage")
    observed = readback(call,wait_job,http_bytes,host=host,port=port,tls=tls,timeout=timeout)
    require(observed == SHA, "NATIVE_WORLD_ARTIFACT_UPLOAD_READBACK_SHA_DRIFT")
    return {"schema":SCHEMA,"classification":"REAL_NATIVE_GUEST_ARTIFACT_BYTES_STAGED",
            "artifact_sha256":SHA,"artifact_size":len(blob),
            "world_id":"lantern-rdte","release_id":"lantern-core-restore-26-3",
            "native_truenas_version":"25.04.2.6",
            "native_app":"rdte-t6-minecraft-vanilla-263",
            "zfs_world_owned":True,"app_quiesced_before_write":True,
            "download_readback_sha256":observed,
            "artifact_gameplay_effect_verified":False,
            "collage_managed_deployment":False,"principal_authorized_to_apply":False,
            "physical_truenas_apply":"HOLD"}

def readback(call,wait_job,http_bytes, *,host:str,port:int,tls:bool,timeout:float)->str:
    row = call("core.download",["filesystem.get",[TARGET],"lantern-stage-sha-readback.zip",True])
    require(type(row) is list and len(row) == 2 and type(row[0]) is int and
            isinstance(row[1],str) and row[1].startswith("/_download/") and
            ".." not in row[1], "NATIVE_WORLD_ARTIFACT_DOWNLOAD_REF_INVALID")
    wait_job(row[0],"native Lantern artifact byte readback")
    actual = http_bytes(host,port,tls,row[1],timeout=timeout)
    require(type(actual) is bytes and len(actual) <= MAX_ZIP,
            "NATIVE_WORLD_ARTIFACT_READBACK_OVERSIZED")
    return hashlib.sha256(actual).hexdigest()
