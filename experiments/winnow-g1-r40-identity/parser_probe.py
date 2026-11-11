#!/usr/bin/env python3
"""R40 actual pinned upstream REST carousel parser, synthetic dict input only.

No private Winnow code, real Instagram URL, login, network source or bytes.
Runs as nonroot/caps=0 in public GHA's isolated Linux network namespace.
"""
import errno
import json
import os
from pathlib import Path
import socket
import sys

IDS = ["10001", "10002", "10003"]
PERMUTATIONS = [
    (0, 1, 2),
    (2, 0, 1),
    (0, 2, 1),
]


def source_child(identifier, salt):
    return {
        "pk": identifier,
        "code": "FAKE" + identifier,
        "taken_at": 1700000000,
        "image_versions2": {"candidates": [{
            "url": "https://i.cdninstagram.com/synthetic/" + identifier +
                   ".jpg?signature=" + salt,
            "width": 640,
            "height": 640,
        }]},
    }


def fake_post(order, salt):
    return {
        "pk": "99999",
        "code": "FAKEPOST",
        "user": {"pk": "synthetic-owner", "username": "synthetic"},
        "caption": None,
        "taken_at": 1700000000,
        "carousel_media": [source_child(IDS[i], salt) for i in order],
    }


def gallery_parse(post):
    from gallery_dl.extractor.instagram import InstagramExtractor
    p = object.__new__(InstagramExtractor)
    # Parser-only instance: no Extractor init, no API/session/auth/request call.
    p._find_tags = lambda *_: []
    p._warn_image = 0
    p._warn_video = False
    p._static_video = True
    p.videos_dash = False
    data = p._parse_post_rest(post)
    return [
        {"id": str(child.get("media_id", "")),
         "ordinal": child.get("num"),
         "has_display_url": bool(child.get("display_url"))}
        for child in data["_files"]
    ]


def parth_parse(post):
    from parth_dl.extractors import MediaExtractor
    # Avoid BaseExtractor construction, cookies, token/config/session creation.
    p = object.__new__(MediaExtractor)
    result = p._parse_media_item(post)
    return [
        {"id": str(e.get("id", "")),
         "ordinal": i,
         "has_display_url": bool(e.get("formats", [{}])[0].get("url"))}
        for i, e in enumerate(result["entries"], 1)
    ]


def network_namespace_guard(host_ns):
    actual = os.readlink("/proc/self/ns/net")
    if actual == host_ns or not actual.startswith("net:["):
        raise RuntimeError("R40_NETWORK_NAMESPACE_NOT_ISOLATED")
    if os.geteuid() != 65534 or os.getegid() != 65534:
        raise RuntimeError("R40_NONROOT_IDENTITY_FAILED")
    cap = [line.split()[1] for line in Path("/proc/self/status").read_text().splitlines()
           if line.startswith("CapEff:")]
    if len(cap) != 1 or int(cap[0], 16) != 0:
        raise RuntimeError("R40_CAPABILITIES_EFFECTIVE")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.2)
        result = s.connect_ex(("192.0.2.1", 443))
    if result not in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM):
        raise RuntimeError("R40_NETWORK_CANARY_NOT_DENIED:" + str(result))


def main():
    if len(sys.argv) != 3 or sys.argv[2] not in ("gallery", "parth"):
        raise SystemExit("usage: parser_probe.py <host-netns-id> <gallery|parth>")
    network_namespace_guard(sys.argv[1])
    candidate = sys.argv[2]
    parser = gallery_parse if candidate == "gallery" else parth_parse
    results = []
    for rep, order in enumerate(PERMUTATIONS, 1):
        expected = [IDS[i] for i in order]
        # Rotate only fictional CDN signature independently of child ID.
        parsed = parser(fake_post(order, "synthetic-version-" + str(rep)))
        observed = [child["id"] for child in parsed]
        if len(parsed) != 3 or not all(x["has_display_url"] for x in parsed):
            raise RuntimeError("R40_NATIVE_PARSER_DROPPED_OR_ADDED_MEDIA")
        if [child["ordinal"] for child in parsed] != [1, 2, 3]:
            raise RuntimeError("R40_NATIVE_ORDINAL_UNEXPECTED")
        if candidate == "gallery":
            if observed != expected or len(set(observed)) != 3:
                raise RuntimeError("R40_GALLERY_NATIVE_CHILD_ID_MISMATCH")
            disposition = "NATIVE_CHILD_ID_PRESENT_FOR_SYNTHETIC_REST"
        else:
            if observed != ["", "", ""]:
                raise RuntimeError("R40_PARTH_CHILD_ID_SHAPE_CHANGED_REEVALUATE")
            disposition = "NATIVE_CHILD_ID_ABSENT_FAIL_CLOSED"
        results.append({
            "rep": rep,
            "fixture": "PUBLIC_FAKE_REST_CAROUSEL",
            "expected_source_ids": expected,
            "observed_native_ids": observed,
            "ordinal_count": len(parsed),
            "native_identity_disposition": disposition,
        })

    if candidate == "gallery" and all(r["expected_source_ids"] != r["observed_native_ids"] for r in results):
        raise RuntimeError("R40_FALSE_GREEN_GALLERY")
    report = {
        "schema_version": 1,
        "scope": "UPSTREAM_NATIVE_REST_PARSER_ONLY_OFFLINE",
        "candidate": candidate,
        "arch": os.uname().machine,
        "native_parser_reps": results,
        "rep_count": len(results),
        "kernel_network_canary_denied": True,
        "real_instagram_requests": 0,
        "real_original_media_bytes": 0,
        "source_owner_rights_verified": False,
        "no_login_real_source_verified": False,
        "production_selected_child_verified": False,
        "actual_vendor_download_performed": False,
        "sandbox_on_production_host_verified": False,
    }
    print(json.dumps(report, sort_keys=True))
    print("R40_NATIVE_IDENTITY_PARSER_OBSERVED candidate=%s arch=%s reps=3 %s source=NOT_RUN" %
          (candidate, report["arch"], disposition))


if __name__ == "__main__":
    main()
