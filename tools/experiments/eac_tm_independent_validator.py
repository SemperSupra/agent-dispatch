#!/usr/bin/env python3
"""Independent, bounded DOM validator for official EAC-TM metadata, no TU text.

Does not import/reference private CPE probe or public streaming-census algorithm.
"""
import hashlib
import io
import json
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

URL = "https://wt-public.emm4u.eu/Resources/EAC-TM/EAC-TM-all.zip"
EXPECTED_SHA = "d0c6399ad8782d5bccd309e330b9637bdeeb38aa0f8f7e39832377cf5afc9acd"
EXPECTED = {"EAC_FORMS.tmx": (2512, 2512), "EAC_REFRENCE_DATA.tmx": (2642, 2642)}
XML_LANG = "{http://www.w3.org/XML/1998/namespace}lang"


def parse_dom(payload):
    results = {}
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for filename in EXPECTED:
            item = archive.getinfo(filename)
            if item.file_size > 32 * 1024 * 1024:
                raise ValueError("Oversized TMX member")
            root = ET.fromstring(archive.read(filename))
            tus = [node for node in root.iter() if node.tag.split("}")[-1] == "tu"]
            english = 0
            for tu in tus:
                has_english = False
                for child in tu:
                    if child.tag.split("}")[-1] != "tuv":
                        continue
                    language = (child.attrib.get(XML_LANG) or child.attrib.get("lang") or "").lower().replace("_", "-")
                    if language == "en":
                        has_english = True
                if has_english:
                    english += 1
            results[filename] = {"tu_count": len(tus), "english_present": english}
    return results


def selftest():
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as out:
        for filename in EXPECTED:
            out.writestr(filename, '<tmx><body><tu><tuv xml:lang="en"><seg>synthetic</seg></tuv></tu></body></tmx>')
    got = parse_dom(archive.getvalue())
    assert all(v == {"tu_count": 1, "english_present": 1} for v in got.values())
    print(json.dumps({"status": "PASS_INDEPENDENT_SYNTHETIC_DOM_SMOKE_NOT_SOURCE"}))


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        selftest()
    else:
        try:
            with urllib.request.urlopen(URL, timeout=25) as r:
                if r.status != 200 or r.geturl() != URL:
                    raise RuntimeError("Original URL or HTTP status changed")
                payload = r.read(16 * 1024 * 1024 + 1)
            if len(payload) > 16 * 1024 * 1024:
                raise ValueError("Archive too large")
            digest = hashlib.sha256(payload).hexdigest()
            if digest != EXPECTED_SHA:
                raise ValueError("Official archive digest drift")
            result = parse_dom(payload)
            for name, expected in EXPECTED.items():
                if (result[name]["tu_count"], result[name]["english_present"]) != expected:
                    raise ValueError("Published counts and independent DOM census disagree")
            print(json.dumps({"status": "PASS_INDEPENDENT_SOURCE_METADATA_DOM_VALIDATION",
                              "archive_sha256": digest, "archive_size_bytes": len(payload),
                              "tmx": result}, sort_keys=True))
        except Exception as exc:
            print(json.dumps({"status": "FAIL_INDEPENDENT_SOURCE_METADATA",
                              "error_class": type(exc).__name__,
                              "error_category": str(exc)[:200]}), file=sys.stderr)
            raise SystemExit(1)
