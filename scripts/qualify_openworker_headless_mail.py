#!/usr/bin/env python3
"""Pinned original OpenWorker headless parser + fake IMAP connector qualification.

Exact MIT source bytes are acquired from immutable public Git blobs, imported
with stdlib-only test doubles, and exercised with fictional mail. No real
account, provider, command execution, live SMTP or full OpenWorker install.
"""
from __future__ import annotations

from email.message import EmailMessage
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import urllib.request

SCHEMA = "public-openworker-headless-mail-contract/v1"
COMMIT = "ecb445490fc054d52b8ea610d97ba947f57033d2"
BASE = "https://raw.githubusercontent.com/andrewyng/openworker/" + COMMIT + "/"
SOURCES = {
    "LICENSE": "60d3824636ee279c14389ea0b858f00fe0c4a913",
    "coworker/headless/runner.py": "3cadae25bd4a3c90d363ae296522058e578af917",
    "coworker/connectors/email_tools.py": "7be4e1f9e78e8fd9d1ef81b58bbc86a916c48e76",
}


class Refused(ValueError):
    pass


def git_blob_hash(payload: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload).hexdigest()


def acquire(path: str) -> bytes:
    if path not in SOURCES:
        raise Refused("UNREVIEWED_PUBLIC_SOURCE")
    url = BASE + path
    with urllib.request.urlopen(urllib.request.Request(
            url, headers={"User-Agent": "public-mail-openworker-research/1"}),
            timeout=12) as response:
        if response.status != 200 or response.geturl() != url:
            raise Refused("UNREVIEWED_HTTP_OR_REDIRECT")
        raw = response.read(90_001)
    if not 100 <= len(raw) <= 90_000 or git_blob_hash(raw) != SOURCES[path]:
        raise Refused("SOURCE_BYTES_OR_DIGEST_MISMATCH")
    return raw


class FakeStore:
    def __init__(self, profile=None):
        self.profile = profile or {}
    def get(self, key):
        if key != "email:default":
            raise AssertionError("UNREVIEWED_CREDENTIAL_NAME")
        return dict(self.profile)


class FakeIMAP:
    def __init__(self, messages):
        self.messages = messages
        self.calls = []
        self.logout_called = False
    def login(self, user, password):
        if user != "fictional@icloud.com" or password != "synthetic-test-only":
            raise AssertionError("UNREVIEWED_FAKE_LOGIN")
        self.calls.append(("login",))
        return "OK", [b"logged in"]
    def select(self, folder, readonly=False):
        self.calls.append(("select", folder, readonly))
        return "OK", [b"2"]
    def uid(self, command, *args):
        self.calls.append(("uid", command, *args))
        if command == "SEARCH":
            return "OK", [b"7 8"]
        if command == "FETCH":
            uid = args[0].decode("ascii") if isinstance(args[0], bytes) else args[0]
            raw = self.messages[uid].as_bytes()
            metadata = b'1 (UID ' + uid.encode() + b' FLAGS (\\Seen) BODYSTRUCTURE ("ATTACHMENT")'
            return "OK", [(metadata, raw), b")"]
        raise AssertionError("UNREVIEWED_IMAP_COMMAND")
    def logout(self):
        self.logout_called = True
        self.calls.append(("logout",))


def fixture_messages():
    first = EmailMessage()
    first["From"] = "Anna <anna@invalid.test>"
    first["To"] = "fictional@icloud.com"
    first["Message-ID"] = "<collision@invalid.test>"
    first["Subject"] = "German and Thai budget update"
    first.set_content("Fictional mail about Budgetfreigabe and อนุมัติ")
    first.add_attachment(b"first fictional payload", maintype="application",
                         subtype="octet-stream", filename="report.txt")
    first.add_attachment(b"second fictional payload", maintype="application",
                         subtype="octet-stream", filename="report.txt")
    second = EmailMessage()
    second["From"] = "Kai <kai@invalid.test>"
    second["To"] = "fictional@icloud.com"
    second["Message-ID"] = "<collision@invalid.test>"
    second["Subject"] = "Unrelated ferry schedule"
    second.set_content("Entirely separate fictional message sharing an Internet Message-ID.")
    return {"7": first, "8": second}


def fake_packages():
    def package(name):
        mod = types.ModuleType(name)
        mod.__path__ = []
        return mod
    ai = types.ModuleType("aisuite")
    ai.ToolMetadata = lambda **kwargs: types.SimpleNamespace(**kwargs)
    roots = types.ModuleType("coworker.roots")
    roots.RootDir = type("RootDir", (), {})
    secrets = types.ModuleType("coworker.secrets")
    secrets.SecretStore = FakeStore
    tool_defs = types.ModuleType("coworker.connectors.tool_defs")
    tool_defs.approval_for_tool = lambda name, default: default
    return {
        "aisuite": ai, "coworker": package("coworker"),
        "coworker.connectors": package("coworker.connectors"),
        "coworker.headless": package("coworker.headless"),
        "coworker.roots": roots, "coworker.secrets": secrets,
        "coworker.connectors.tool_defs": tool_defs,
    }


def import_original(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    if spec is None or spec.loader is None:
        raise Refused("INVALID_UPSTREAM_MODULE")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def qualify() -> dict:
    with tempfile.TemporaryDirectory(prefix="openworker-synthetic-mail-") as temp:
        base = Path(temp)
        for path in SOURCES:
            destination = base / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(acquire(path))
        if not (base / "LICENSE").read_text(encoding="utf-8").startswith("MIT License"):
            raise Refused("LICENSE_UNQUALIFIED")
        from unittest.mock import patch
        with patch.dict(sys.modules, fake_packages()):
            parser = import_original("coworker.headless.runner",
                base / "coworker/headless/runner.py")
            connector = import_original("coworker.connectors.email_tools",
                base / "coworker/connectors/email_tools.py")
            args = parser.parse_args([
                "--isolated", "--prompt", "synthetic evidence only",
                "--model", "fixture/noop", "--out", str(base / "out"),
                "--no-web-tools", "--max-iterations", "1"])
            isolation_safe = (args.isolated is True and args.no_web_tools is True
                              and args.mcp is False and args.mode == "interactive"
                              and args.approval_mode == "ask"
                              and args.max_iterations == 1)
            imap = FakeIMAP(fixture_messages())
            factory = lambda host, port: imap
            smtp_called = []
            def deny_smtp(host, port):
                smtp_called.append(host)
                raise AssertionError("SMTP_MUST_NOT_BE_USED")
            toolset = connector.make_email_tools(FakeStore({
                "address": "fictional@icloud.com", "app_password": "synthetic-test-only"}),
                imap_factory=factory, smtp_factory=deny_smtp)
            tools = {f.__name__: f for f in toolset}
            names = {"email_list_folders", "email_search", "email_read",
                     "email_download_attachment", "email_send"}
            approval_safe = (
                set(tools) == names and
                all(getattr(tools[n], "__aisuite_tool_metadata__").requires_approval
                    for n in ("email_send", "email_download_attachment")) and
                not any(getattr(tools[n], "__aisuite_tool_metadata__").requires_approval
                        for n in ("email_search", "email_read", "email_list_folders")))
            matches = tools["email_search"](max_results=10)
            distinct_uids = (matches.get("ok") is True and
                             matches.get("total_matches") == 2 and
                             {m["uid"] for m in matches.get("messages", [])} == {"7", "8"})
            first = tools["email_read"](uid="7")
            duplicate_attachments_visible = (
                first.get("ok") is True and
                len(first.get("attachments", [])) == 2 and
                [a["filename"] for a in first["attachments"]] == ["report.txt", "report.txt"])
            no_write_root = "error" in tools["email_download_attachment"]("7", "report.txt")
            # Expected negative: the original name-addressed download API
            # cannot select the SECOND same-filename attachment occurrence.
            scratch = base / "fake-downloads"
            scratch.mkdir()
            rooted = {fn.__name__: fn for fn in connector.make_email_tools(
                FakeStore({"address": "fictional@icloud.com",
                           "app_password": "synthetic-test-only"}),
                roots=[types.SimpleNamespace(path=scratch, writable=True)],
                imap_factory=factory, smtp_factory=deny_smtp)}
            downloaded_first = rooted["email_download_attachment"]("7", "report.txt")
            downloaded_again = rooted["email_download_attachment"]("7", "report.txt")
            same_name_second_unaddressable = (
                downloaded_first.get("ok") is True and
                downloaded_again.get("ok") is True and
                downloaded_first["path"] != downloaded_again["path"] and
                Path(downloaded_first["path"]).read_bytes() ==
                    b"first fictional payload" and
                Path(downloaded_again["path"]).read_bytes() ==
                    b"first fictional payload" and
                fixture_messages()["7"].get_payload()[-1].get_payload(decode=True) ==
                    b"second fictional payload")
            disconnected = {f.__name__: f for f in connector.make_email_tools(
                FakeStore(), imap_factory=factory, smtp_factory=deny_smtp)}
            unconnected_send_rejected = "error" in disconnected["email_send"](
                to="nobody@invalid.test", subject="never send", body="synthetic")
            utf8_criteria, utf8_error = connector.build_search_criteria(text="อนุมัติ")
            utf8_accepted = (
                utf8_error == "" and isinstance(utf8_criteria, bytes)
                and utf8_criteria.startswith(b"CHARSET UTF-8 ")
                and "อนุมัติ".encode("utf-8") in utf8_criteria)
            bad_date, bad_error = connector.build_search_criteria(since="2026-99-01")
            bad_date_rejected = bad_date is None and bool(bad_error)
            peek_only = all(
                "(BODY.PEEK" in call[3]
                for call in imap.calls if call[0] == "uid" and call[1] == "FETCH")
            selects_readonly = all(
                call[2] is True for call in imap.calls if call[0] == "select")
            passed = (isolation_safe and approval_safe and distinct_uids and
                      duplicate_attachments_visible and no_write_root and
                      same_name_second_unaddressable and
                      unconnected_send_rejected and utf8_accepted and bad_date_rejected
                      and peek_only and selects_readonly and imap.logout_called and
                      not smtp_called)
    return {
        "schema": SCHEMA,
        "classification": "UPSTREAM_HEADLESS_AND_FAKE_IMAP_ONLY",
        "upstream_repository": "andrewyng/openworker",
        "upstream_commit": COMMIT,
        "connector_blob_sha": SOURCES["coworker/connectors/email_tools.py"],
        "headless_blob_sha": SOURCES["coworker/headless/runner.py"],
        "license": "MIT",
        "qualified": bool(passed),
        "control_count": 12,
        "isolated_defaults": bool(isolation_safe),
        "fake_mail_readonly": bool(distinct_uids and peek_only and selects_readonly),
        "duplicate_attachments_visible": bool(duplicate_attachments_visible),
        "no_smtp_attempts": not smtp_called,
        "same_name_second_unaddressable": bool(same_name_second_unaddressable),
        "attachment_download_occurrence_complete": False,
        "approval_metadata_only": True,
        "headless_engine_run": False,
        "model_inference": False,
        "real_mail": False,
    }


def main():
    try:
        result = qualify()
    except (ValueError, OSError, UnicodeError) as error:
        print("OPENWORKER_FAKE_MAIL_BLOCKED=" +
              (str(error) if isinstance(error, Refused) else "RUNTIME_ERROR"), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["qualified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
