#!/usr/bin/env python3
"""Public-safe EAC-TM official-source transport census. No TU text printed/stored.

Independent metadata observation, NOT the committed private CPE probe.
No source archive publication, private repository access or credentials.
"""
import collections
import hashlib
import io
import json
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone

URL = "https://wt-public.emm4u.eu/Resources/EAC-TM/EAC-TM-all.zip"
MAX_BYTES = 16 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
XLANG = "{http://www.w3.org/XML/1998/namespace}lang"


def local(tag):
    return tag.rsplit("}", 1)[-1]


def inspect_zip(raw):
    result = []
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        info = zf.infolist()
        if not info or len(info) > 32:
            raise ValueError("Unexpected archive member count")
        for f in info:
            if (f.file_size > MAX_MEMBER_BYTES or f.flag_bits & 1
                    or f.filename.startswith("/") or "\\" in f.filename
                    or ".." in f.filename.split("/")):
                raise ValueError("Unsafe, encrypted, or oversized archive member")
        tmx = [f for f in info if f.filename.lower().endswith(".tmx")]
        if len(tmx) != 2:
            raise ValueError("Expected two independently named TMX files; preserve actual names")
        for member in tmx:
            by_language = collections.Counter()
            tu_count = 0
            with zf.open(member) as stream:
                events = ET.iterparse(stream, events=("start", "end"))
                _, root = next(events)
                for event, node in events:
                    if event != "end" or local(node.tag) != "tu":
                        continue
                    tu_count += 1
                    languages = set()
                    for child in node.iter():
                        if local(child.tag) == "tuv":
                            tag = (child.get(XLANG) or child.get("lang") or "").lower().replace("_", "-")
                            if tag:
                                languages.add(tag)
                    for lang in languages:
                        by_language[lang] += 1
                    node.clear()
                    root.clear()
            result.append({"member": member.filename, "uncompressed_bytes": member.file_size,
                           "crc32": format(member.CRC, "08x"), "tu_count": tu_count,
                           "tus_by_language": dict(sorted(by_language.items()))})
        return {"members": [{"name": f.filename, "size": f.file_size,
                             "crc32": format(f.CRC, "08x")} for f in info], "tmx": result}


def acquire():
    req = urllib.request.Request(URL, headers={"User-Agent": "EAC-TM-source-census/1.0"})
    with urllib.request.urlopen(req, timeout=25) as response:
        final_url = response.geturl()
        if response.status != 200 or urllib.parse.urlsplit(final_url).scheme != "https":
            raise RuntimeError("Official HTTPS transport failed")
        chunks = []
        total = 0
        while True:
            part = response.read(256 * 1024)
            if not part:
                break
            total += len(part)
            if total > MAX_BYTES:
                raise ValueError("Archive transport size bound exceeded")
            chunks.append(part)
        return b"".join(chunks), response.status, final_url


def smoke():
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        for label in ("EAC_FORMS.tmx", "EAC_REFRENCE_DATA.tmx"):
            z.writestr(label, '<tmx><body><tu><tuv xml:lang="en"><seg>abc</seg></tuv>'
                       '<tuv xml:lang="de"><seg>def</seg></tuv></tu></body></tmx>')
    a = inspect_zip(bio.getvalue())
    assert len(a["tmx"]) == 2 and all(
        x["tu_count"] == 1 and x["tus_by_language"] == {"de": 1, "en": 1}
        for x in a["tmx"])
    print(json.dumps({"status": "PASS_SYNTHETIC_PARSER_SMOKE_NOT_SOURCE"}))


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        smoke()
    else:
        try:
            raw, status, final = acquire()
            observed = inspect_zip(raw)
            print(json.dumps({
                "status": "TRANSPORT_OBSERVED_METADATA_ONLY_NOT_PRIVATE_CPE_PROBE",
                "source_url": URL, "final_url": final, "http_status": status,
                "observed_at_utc": datetime.now(timezone.utc).isoformat(),
                "archive_size_bytes": len(raw),
                "archive_sha256": hashlib.sha256(raw).hexdigest(),
                **observed}, ensure_ascii=True, sort_keys=True))
        except Exception as exc:
            print(json.dumps({
                "status": "FIRST_FAILURE_TRANSPORT_OR_FORMAT",
                "error_class": type(exc).__name__,
                "error_category": str(exc)[:200]}, sort_keys=True), file=sys.stderr)
            raise SystemExit(1)
