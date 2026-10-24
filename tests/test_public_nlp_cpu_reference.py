"""Independent fixed-string oracle for the public synthetic spaCy CPU reference."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import hashlib
import json
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "public_nlp_cpu_reference.py"
spec = importlib.util.spec_from_file_location("nlp_public_cpu", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class SyntheticReferenceTests(unittest.TestCase):
    EXPECTED = (
        ((0, 9, "PERSON", "Mira Voss"), (18, 32, "PLACE", "Sable Junction"),
         (48, 62, "OBJECT", "Copper Lantern")),
        ((0, 8, "PERSON", "Taro Sen"), (17, 27, "PLACE", "Glass Vale")),
        (),
    )

    def test_independent_spans_and_absences(self):
        receipt = mod.reference()
        self.assertEqual(receipt["classification"], "PUBLIC_SYNTHETIC_ONLY")
        self.assertEqual(receipt["model"], "blank-en")
        self.assertEqual(receipt["sentence_count"], 5)
        self.assertFalse(receipt["private_repository_used"])
        self.assertFalse(receipt["original_literary_sources_used"])
        self.assertFalse(receipt["provider_access_verified"])
        for i, entries in enumerate(receipt["spans"]):
            self.assertEqual(entries["fixture_index"], i)
            self.assertEqual(tuple((x["start"], x["end"], x["label"], x["text"])
                             for x in entries["spans"]), self.EXPECTED[i])
            for span in entries["spans"]:
                self.assertEqual(mod.FIXTURES[i][span["start"]:span["end"]], span["text"])

    def test_repeatable_fixture_digest_and_output(self):
        first, second = mod.reference(), mod.reference()
        self.assertEqual(first, second)
        self.assertEqual(first["fixture_count"], 3)
        self.assertEqual(sum(len(x["spans"]) for x in first["spans"]), 5)
        recomputed = hashlib.sha256(json.dumps(mod.FIXTURES, ensure_ascii=True,
                             separators=(",", ":")).encode("utf-8")).hexdigest()
        self.assertEqual(recomputed, first["fixture_sha256"])

    def test_does_not_offer_remote_or_script_controls(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("urllib", source)
        self.assertNotIn("requests.get", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("eval(", source)

if __name__ == "__main__":
    unittest.main()
