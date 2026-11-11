#!/usr/bin/env python3
"""Public-safe G1 extractor comparison: pinned wheels, offline contracts only.

No Winnow/private source, Instagram request, user permalink, account, credential,
cookies, real media, or external search. Executing an installed --help/--version
is NOT proof of anonymous Instagram acquisition.
"""
import hashlib
import importlib
import importlib.metadata
import inspect
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time
import urllib.parse

CANDIDATES = {
    "gallery": {
        "dist": "gallery-dl", "module": "gallery_dl", "command": "gallery-dl",
        "version": "1.32.19",
        "wheel": "gallery_dl-1.32.19-py3-none-any.whl",
        "sha256": "f6b1eb5e9a7409a988b754335d99dbb1873e130d133ed5d164d32e5e645d1c50",
        "flags": ["--get-urls", "--range", "--config-ignore", "--no-input",
                  "--filesize-max", "--no-postprocessors", "--http-timeout"],
        "license": "GPL-2.0",
    },
    "parth": {
        "dist": "parth-dl", "module": "parth_dl", "command": "parth-dl",
        "version": "1.2.1",
        "wheel": "parth_dl-1.2.1-py3-none-any.whl",
        "sha256": "3117e4c7bd6fe7c6f1b668d05c40c303e54fc3992019bf6a40ab13b98434ebff",
        "flags": ["--json", "--list-formats", "--help", "--version"],
        "license": "MIT",
    },
}
NAME = sys.argv[1]
assert NAME in CANDIDATES, "unsupported candidate"
P = CANDIDATES[NAME]
EVIDENCE = Path(sys.argv[2])
WHEEL = Path(sys.argv[3])
EVIDENCE.mkdir(parents=True, exist_ok=True)
START = time.monotonic()
report = {
    "schema_version": 1,
    "candidate": NAME,
    "runner_architecture": __import__("platform").machine(),
    "python": __import__("platform").python_version(),
    "scope": "PINNED_WHEEL_OFFLINE_METADATA_CLI_URL_NEGATIVES_ONLY",
    "instagram_network_requests": 0,
    "instagram_bytes_retrieved": 0,
    "login_free_source_verified": False,
    "authorization_proven": False,
    "carousel_selected_slide_bytes_verified": False,
    "acceptable_for_winnow_release": False,
    "limitations": [
        "No real permitted Instagram original-byte acquisition",
        "CLI help/source behavior cannot prove live anonymous access",
        "No stable preview-to-selected-carousel-child proof",
        "No SearXNG, Meta OAuth or signed-CDN source qualification",
    ],
    "checks": [],
    "security_findings": [],
}

def check(name, passed, evidence="", severity="gate"):
    report["checks"].append({"name": name, "passed": bool(passed),
                             "evidence": str(evidence)[:240], "severity": severity})

def finding(name, note):
    report["security_findings"].append({"id": name, "note": note[:260]})

def run_cli(args, timeout=8):
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(EVIDENCE / "empty-home"),
        "XDG_CONFIG_HOME": str(EVIDENCE / "empty-home" / "config"),
        "XDG_CACHE_HOME": str(EVIDENCE / "empty-home" / "cache"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "NO_COLOR": "1",
        "LANG": "C.UTF-8",
    }
    (EVIDENCE / "empty-home").mkdir(exist_ok=True)
    start = time.perf_counter_ns()
    proc = subprocess.run([P["command"], *args], env=env, text=True,
                          capture_output=True, timeout=timeout, check=False)
    elapsed = (time.perf_counter_ns() - start) / 1e6
    return proc.returncode, (proc.stdout + "\n" + proc.stderr)[:32768], elapsed

def security_parth():
    from parth_dl.utils import ValidationError, validate_url, validate_media_url, finalize_info
    # Every input here is a synthetic literal; none is passed to an HTTP client.
    source_cases = [
        ("valid_post_https", "https://www.instagram.com/p/FAKE001/", True),
        ("reject_lookalike", "https://www.instagram.com.evil.invalid/p/X/", False),
        ("reject_userinfo", "https://user:pass@instagram.com/p/X/", False),
        ("reject_http", "http://www.instagram.com/p/X/", False),
        ("reject_file", "file:///tmp/nope", False),
    ]
    media_cases = [
        ("cdn_https", "https://i.cdninstagram.com/media.jpg", True),
        ("reject_cdn_lookalike", "https://cdninstagram.com.evil.invalid/img.jpg", False),
        ("reject_local_http", "http://127.0.0.1/a", False),
        ("reject_file", "file:///etc/passwd", False),
        ("reject_media_userinfo", "https://user:pass@cdninstagram.com/a.jpg", False),
        ("reject_media_non443", "https://cdninstagram.com:4444/a.jpg", False),
    ]
    for name, value, expected in source_cases + media_cases:
        f = validate_url if name in {x[0] for x in source_cases} else validate_media_url
        try:
            allowed = (f(value) is True) if f is validate_url else (f(value) is True)
            # validate_media_url returns True on success in released version.
        except (ValidationError, ValueError):
            allowed = False
        except Exception as e:
            allowed = False
            finding("PARTH_UNEXPECTED_EXCEPTION", type(e).__name__)
        passed = allowed == expected
        check(name, passed, "ACCEPT" if allowed else "REJECT", "security")
        if not passed:
            finding("PARTH_"+name.upper(),
                    "Input acceptance differs from Winnow's strict origin/input policy; wrapper enforcement required.")
    # Presence of entries is not evidence of selecting only one child from a
    # real source. Report as a capability observation rather than PASS.
    source = inspect.getsource(importlib.import_module("parth_dl.core"))
    extractor = inspect.getsource(importlib.import_module("parth_dl.extractors"))
    check("json_entry_structure_in_source", "entries" in source and "carousel_media" in extractor,
          "synthetic source code only", "informational")
    if "HTTPCookieProcessor" in extractor or "CookieJar" in extractor:
        finding("NO_LOGIN_IS_NOT_COOKIELESS",
                "Upstream creates a CookieJar and reuses anonymous Set-Cookie; no supplied account credentials != stateless/cookieless.")
    if "LOGGED_OUT_QUERY_DOC_ID" in extractor or "X-IG-App-ID" in extractor:
        finding("NONPUBLIC_ENDPOINT_DEPENDENCY",
                "Upstream uses hard-coded Instagram API/query identifiers and browser-like headers; unsupported by official access proof.")
    if "response.read()" in extractor:
        finding("UNBOUNDED_METADATA_BODY",
                "Extractor reads unbounded response body (and may gzip decompress); enforce independent resource/effect limits.")

def security_gallery():
    import gallery_dl.extractor as ex
    for name, url, expected in [
        ("recognizes_instagram_post", "https://www.instagram.com/p/FAKE001/", True),
        ("does_not_recognize_lookalike", "https://instagram.com.evil.invalid/p/FAKE001/", False),
    ]:
        try:
            selected = ex.find(url)
            recognized = bool(selected) and "instagram" in type(selected).__module__.lower()
            check(name, recognized == expected, "EXTRACTOR_MATCH" if recognized else "NONE", "security")
            if recognized != expected:
                finding("GALLERY_"+name.upper(), "Unexpected offline URL dispatcher classification")
        except Exception as e:
            check(name, False, type(e).__name__, "security")
    finding("GALLERY_RANGE_IDENTITY_UNPROVEN",
            "Documented --range indexes extraction order; no stable cross-request selected-child identity or real byte equivalence proven.")
    finding("GALLERY_DEFAULT_CONFIG_RISK",
            "Always enforce --config-ignore/--no-input/--no-postprocessors and isolated HOME to avoid inherited cookies/config.")

try:
    actual_wheel_sha = hashlib.sha256(WHEEL.read_bytes()).hexdigest()
    check("wheel_sha256", actual_wheel_sha == P["sha256"], actual_wheel_sha)
    check("wheel_filename", WHEEL.name == P["wheel"], WHEEL.name)
    ver = importlib.metadata.version(P["dist"])
    check("installed_exact_version", ver == P["version"], ver)
    requirements = importlib.metadata.requires(P["dist"]) or []
    report["installed_requirements"] = requirements
    check("package_importable", importlib.import_module(P["module"]) is not None,
          P["module"])
    rc, help_msg, t = run_cli(["--help"])
    check("help_exit_zero", rc == 0, f"exit={rc} ms={t:.2f}")
    for flag in P["flags"]:
        check("help_flag_"+flag, flag in help_msg,
              "found" if flag in help_msg else "NOT_ADVERTISED", "feature")
    rc, version_msg, _ = run_cli(["--version"])
    check("version_command", rc == 0 and P["version"] in version_msg,
          f"exit={rc}, version_in_output={P['version'] in version_msg}")
    if NAME == "parth":
        security_parth()
    else:
        security_gallery()
    timings = []
    for _ in range(15):
        rc, _, ms = run_cli(["--version"])
        if rc != 0:
            raise RuntimeError("CLI startup nonzero during latency trial")
        timings.append(ms)
    ordered = sorted(timings)
    report["cli_startup_15_reps_ms"] = {
        "p50": round(statistics.median(ordered), 3),
        "p95": round(ordered[int(len(ordered)*0.95)], 3),
        "mean": round(statistics.mean(ordered), 3),
        "max": round(max(ordered), 3),
    }
    report["status"] = "QUALIFICATION_COMPLETED"
except Exception as e:
    report["status"] = "TEST_SETUP_OR_RUNTIME_FAILED"
    report["failure"] = f"{type(e).__name__}: {str(e)[:500]}"
finally:
    report["elapsed_seconds"] = round(time.monotonic()-START,3)
    report["rejected_security_checks"] = sum(
        not x["passed"] for x in report["checks"] if x["severity"]=="security")
    report["positive_package_checks"] = sum(x["passed"] for x in report["checks"] if x["severity"]=="gate")
    report["verdict"] = "SOURCE_AUTHORIZATION_AND_SELECTED_BYTES_HOLD"
    (EVIDENCE/"result.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["status"] != "QUALIFICATION_COMPLETED":
        sys.exit(1)
