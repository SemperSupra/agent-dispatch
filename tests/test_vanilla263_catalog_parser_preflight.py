"""Causal OP4J-017 harness failure reproduction; never opens a TrueNAS guest."""
from __future__ import annotations
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import truenas_middleware_minecraft_t6_probe as native
WORKFLOW = ROOT / ".github/workflows/gha-kvm-system-rdte.yml"
HARNESS = ROOT / "scripts/gha_kvm_truenas_rdte.sh"
REQUEST = ROOT / "config/truenas-rdte-run-request.json"


def cli(profile: str, catalog: str) -> list[str]:
    return [
        "--host", "127.0.0.1", "--port", "10000",
        "--status-port", "25580", "--status-oracle", "/never/open/oracle.py",
        "--password-file", "/never/open/secret-file",
        "--control-dir", "/never/open/control",
        "--foundry-commit", "5ee204df205edfd531304441fd1a6a24004557b1",
        "--expected-system-version", "TrueNAS-25.04.2.6",
        "--out", "/never/write/probe.json",
        "--product-profile", profile,
        "--native-catalog-profile", catalog,
    ]


class ProductScopedParserTests(unittest.TestCase):
    def test_017_reproduced_profile_accepted_without_guest_io(self):
        self.assertNotIn("1.15.31", native.CATALOG_PROFILES)
        args = native.parse_guest_args(cli("vanilla263", "1.15.31"))
        self.assertEqual(args.product_profile, "vanilla263")
        self.assertEqual(args.native_catalog_profile, "1.15.31")
        self.assertFalse(Path("/never/write/probe.json").exists())
        self.assertNotIn("1.15.31", native.CATALOG_PROFILES)
        self.assertTrue(native.product_catalog_admitted("vanilla263", "1.15.31"))

    def test_old_paper_versions_remain_distinct_and_admitted(self):
        for version in ("1.15.29", "1.15.30"):
            with self.subTest(version=version):
                args = native.parse_guest_args(cli("legacy-paper", version))
                self.assertEqual(args.native_catalog_profile, version)
                self.assertTrue(native.product_catalog_admitted("legacy-paper", version))

    def test_cross_product_and_unpinned_profiles_fail_before_guest(self):
        rows = (("legacy-paper", "1.15.31"),
                ("vanilla263", "1.15.29"),
                ("vanilla263", "1.15.30"),
                ("vanilla263", "1.15.32"),
                ("legacy-paper", "1.15.32"))
        for product, catalog in rows:
            with self.subTest(product=product, catalog=catalog):
                sink = io.StringIO()
                with contextlib.redirect_stderr(sink), self.assertRaises(SystemExit) as raised:
                    native.parse_guest_args(cli(product, catalog))
                self.assertEqual(raised.exception.code, 2)
                self.assertFalse(native.product_catalog_admitted(product, catalog))
                self.assertNotIn("secret-file", sink.getvalue())
                self.assertFalse(Path("/never/write/probe.json").exists())

    def test_runner_uses_same_qualified_exact_catalog_without_modifying_request(self):
        harness = HARNESS.read_text(encoding="utf-8")
        workflow = WORKFLOW.read_text(encoding="utf-8")
        request = json.loads(REQUEST.read_text(encoding="utf-8"))
        self.assertIn("--product-profile vanilla263 --native-catalog-profile 1.15.31", harness)
        self.assertIn('--native-catalog-profile "1.15.30"', harness)
        self.assertIn("--expected 1.15.31", workflow)
        self.assertEqual(request["request_id"],
            "tn-25-04-2-6-t6-vanilla-263-op4l-019-pinned-readonly-join-anvil-three-checkpoint")
        self.assertNotIn("018", request["request_id"])
        self.assertIn("019", request["request_id"])
        self.assertEqual(request["consumer_authority_issue"], 627)
        self.assertEqual(request["authority_issue"], 423)
        self.assertEqual(set(request), {
            "schema", "request_id", "version", "rung", "product",
            "authority_issue", "consumer_authority_issue", "purpose",
            "collage_readback", "lantern_stage", "native_world_rollback",
            "native_offline_player", "native_backend_region"
        })

    def test_runtime_parse_always_precedes_mutating_configuration(self):
        source = (ROOT/"scripts/truenas_middleware_minecraft_t6_probe.py").read_text()
        main = source[source.index("def main() -> int:"):]
        self.assertLess(main.index("a = parse_guest_args()"),
                        main.index("configure_exact_vanilla263()"))
        self.assertLess(main.index("configure_exact_vanilla263()"),
                        main.index("started = time.monotonic()"))
        self.assertIn("PRODUCT_SCOPED_CATALOG_NOT_ADMITTED", source)


if __name__ == "__main__":
    unittest.main()
