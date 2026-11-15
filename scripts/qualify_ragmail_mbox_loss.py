#!/usr/bin/env python3
"""Independent public synthetic negative witness for exact pinned RAG-Mail MBOX loader.

Original upstream MIT source is imported with disposable fake DB/storage and
only standard-library MIME/MBOX fixtures. This is a *known-failure witness*
for canonical source-occurrence preservation, not a successful reader.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from email.message import EmailMessage
import hashlib
import importlib.util
import io
import json
import mailbox
from pathlib import Path
import sys
import tempfile
import types
import urllib.request
from unittest.mock import patch

SCHEMA = "public-ragmail-mbox-loss-witness/v1"
COMMIT = "afab46bfdd83d11af8bacee8231871ff1292fced"
BASE = "https://raw.githubusercontent.com/ManiAm/RAG-Mail/" + COMMIT + "/"
PINNED = {
    "LICENSE": "9f2503cd9335d109ad1a2e67f264bd9aa7097021",
    "services/email_loader_mbox.py": "5a9ee91a0f1b7d04439ab8808bf7b1c88df868d6",
}


class WitnessDenied(ValueError):
    pass


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\x00" + data).hexdigest()


def fetch(path: str) -> bytes:
    if path not in PINNED:
        raise WitnessDenied("SOURCE_PATH_NOT_ALLOWED")
    url = BASE + path
    request = urllib.request.Request(url, headers={"User-Agent": "mail-rdte-public/1"})
    with urllib.request.urlopen(request, timeout=12) as response:
        if response.status != 200 or response.geturl() != url:
            raise WitnessDenied("SOURCE_RETRIEVAL_NOT_ADMITTED")
        blob = response.read(16385)
    if not 100 <= len(blob) <= 16384 or git_blob_sha(blob) != PINNED[path]:
        raise WitnessDenied("SOURCE_HASH_OR_SIZE_MISMATCH")
    return blob


class FakeEmail:
    def __init__(self, **data):
        self.__dict__.update(data)


class FakeAttachment:
    def __init__(self, **data):
        self.__dict__.update(data)


class Query:
    def __init__(self, owner):
        self.owner = owner
        self.identity = None

    def filter_by(self, **values):
        self.identity = values["id"]
        return self

    def first(self):
        return self.owner.emails.get(self.identity)


class FakeSession:
    def __init__(self):
        self.emails = {}
        self.attachments = []
        self.commits = 0
        self.closed = False

    def query(self, model):
        if model is not FakeEmail:
            raise WitnessDenied("UNEXPECTED_MODEL")
        return Query(self)

    def add(self, obj):
        if isinstance(obj, FakeEmail):
            self.emails[obj.id] = obj
        elif isinstance(obj, FakeAttachment):
            self.attachments.append(obj)
        else:
            raise WitnessDenied("UNEXPECTED_OBJECT")

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


class FakeEmailLoader:
    """Only attachment-text helper stubs; original MBOX loader is unmodified."""
    def get_mime_type(self, mime_type, filename, binary_data):
        return mime_type

    def get_file_extension(self, filename):
        return Path(filename).suffix.lower()

    def extract_text(self, effective_mime, binary_data):
        return binary_data.decode("utf-8", "replace")


def load_original_module(path: Path, session: FakeSession):
    fake_services = types.ModuleType("services")
    fake_services.__path__ = []
    fake_parent = types.ModuleType("services.email_loader")
    fake_parent.Email_loader = FakeEmailLoader
    fake_db = types.ModuleType("db")
    fake_db.__path__ = []
    fake_session = types.ModuleType("db.session")
    fake_session.SessionLocal = lambda: session
    fake_models = types.ModuleType("db.models")
    fake_models.Email = FakeEmail
    fake_models.Attachment = FakeAttachment
    mapping = {
        "services": fake_services,
        "services.email_loader": fake_parent,
        "db": fake_db, "db.session": fake_session, "db.models": fake_models,
    }
    with patch.dict(sys.modules, mapping):
        spec = importlib.util.spec_from_file_location("rdte_ragmail_mbox", path)
        if spec is None or spec.loader is None:
            raise WitnessDenied("SOURCE_MODULE_INVALID")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module.Email_loader_mbox


def messages() -> list[EmailMessage]:
    first = EmailMessage()
    first["From"] = "alpha@invalid.test"
    first["To"] = "beta@invalid.test"
    first["Subject"] = "Synthetic baseline observation"
    first["Message-ID"] = "<collision@invalid.test>"
    first.set_content("First occurrence with two distinct attachments.")
    first.add_attachment("attachment A".encode(), maintype="text",
                         subtype="plain", filename="report.txt")
    first.add_attachment("attachment B".encode(), maintype="text",
                         subtype="plain", filename="report.txt")

    second = EmailMessage()
    second["From"] = "alpha@invalid.test"
    second["Subject"] = "Synthetic revised observation"
    second["Message-ID"] = "<collision@invalid.test>"
    second.set_content("Second independent occurrence sharing an ID.")

    third = EmailMessage()
    third["From"] = "gamma@invalid.test"
    third["Subject"] = "Synthetic missing ID"
    third.set_content("Third independent occurrence without Message-ID.")
    return [first, second, third]


def qualify() -> dict:
    with tempfile.TemporaryDirectory(prefix="public-ragmail-witness-") as td:
        root = Path(td)
        source = root / "email_loader_mbox.py"
        source.write_bytes(fetch("services/email_loader_mbox.py"))
        license_body = fetch("LICENSE").decode("utf-8")
        if not license_body.startswith("MIT License"):
            raise WitnessDenied("UPSTREAM_RIGHTS_NOT_QUALIFIED")
        corpus = root / "test.mbox"
        mbox = mailbox.mbox(str(corpus))
        for m in messages():
            mbox.add(m)
        mbox.flush()
        mbox.close()
        store = FakeSession()
        Original = load_original_module(source, store)
        loader = Original(str(corpus))
        with redirect_stdout(io.StringIO()):
            raw_count = sum(1 for _ in loader._iter_mbox_stream())
            loader.load_emails(max_results=-1, batch_size=5)
    found = len(store.emails)
    stored_attachments = len(store.attachments)
    loss_observed = (raw_count == 3 and found == 1
                     and stored_attachments == 1 and store.closed
                     and "<collision@invalid.test>" in store.emails)
    return {
        "schema": SCHEMA,
        "classification": "EXPECTED_EVIDENCE_LOSS_WITNESS",
        "upstream_repository": "ManiAm/RAG-Mail",
        "upstream_commit": COMMIT,
        "upstream_source_blob": PINNED["services/email_loader_mbox.py"],
        "license": "MIT",
        "input_source_occurrences": raw_count,
        "input_attachment_occurrences": 2,
        "stored_messages": found,
        "stored_attachments": stored_attachments,
        "dropped_message_occurrences": raw_count - found,
        "dropped_attachment_occurrences": 2 - stored_attachments,
        "canonical_evidence_compatible": False,
        "expected_loss_reproduced": bool(loss_observed),
        "real_database_used": False,
        "real_mail_used": False,
        "model_inference": False,
        "cost_usd": 0,
    }


def main() -> int:
    try:
        outcome = qualify()
    except (OSError, UnicodeError, ValueError) as exc:
        name = str(exc) if isinstance(exc, WitnessDenied) else "UNQUALIFIED_RUNTIME"
        print("RAGMAIL_SOURCE_WITNESS_BLOCKED=" + name, file=sys.stderr)
        return 2
    print(json.dumps(outcome, sort_keys=True))
    return 0 if outcome["expected_loss_reproduced"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
