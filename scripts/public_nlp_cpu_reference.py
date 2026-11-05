#!/usr/bin/env python3
"""Public synthetic spaCy CPU reference; no private/source-book inputs.

Single fixed fixture and public-only receipt, not literary entity discovery.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path

import spacy
from spacy.matcher import PhraseMatcher

SCHEMA = "public-synthetic-nlp-cpu-reference/v1"
FIXTURES = (
    "Mira Voss visited Sable Junction. She carried a Copper Lantern.",
    "Taro Sen crossed Glass Vale. Presently the visitors rested.",
    "The quiet travelers returned at sunrise."
)
PATTERNS = {
    "PERSON": ("Mira Voss", "Taro Sen"),
    "PLACE": ("Sable Junction", "Glass Vale"),
    "OBJECT": ("Copper Lantern",),
}


def reference() -> dict:
    nlp = spacy.blank("en")
    nlp.add_pipe("sentencizer")
    matcher = PhraseMatcher(nlp.vocab, attr="LOWER")
    for label, surfaces in PATTERNS.items():
        matcher.add(label, [nlp.make_doc(value) for value in surfaces])
    all_spans = []
    sentences = 0
    for index, source in enumerate(FIXTURES):
        doc = nlp(source)
        sentences += sum(1 for _ in doc.sents)
        spans = []
        for match_id, start, end in matcher(doc):
            span = doc[start:end]
            spans.append({"label": nlp.vocab.strings[match_id],
                          "text": span.text, "start": span.start_char, "end": span.end_char})
        spans.sort(key=lambda row: (row["start"], row["end"], row["label"]))
        all_spans.append({"fixture_index": index, "spans": spans})
    raw = json.dumps(FIXTURES, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return {"schema": SCHEMA, "classification": "PUBLIC_SYNTHETIC_ONLY",
            "model": "blank-en", "spacy_version": spacy.__version__,
            "python": platform.python_version(), "machine": platform.machine(),
            "fixture_sha256": hashlib.sha256(raw).hexdigest(),
            "fixture_count": len(FIXTURES), "sentence_count": sentences,
            "spans": all_spans, "provider_access_verified": False,
            "original_literary_sources_used": False,
            "private_repository_used": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    receipt = reference()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("PUBLIC_SYNTHETIC_ONLY fixture_count=" + str(receipt["fixture_count"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
