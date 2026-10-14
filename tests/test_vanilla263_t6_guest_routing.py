"""Static red/blue: distinct native guest selector; no request-edge replay."""
from __future__ import annotations
import json
from pathlib import Path
import re
import unittest

ROOT=Path(__file__).resolve().parents[1]
WORKFLOW=(ROOT/".github/workflows/gha-kvm-system-rdte.yml").read_text()
HARNESS=(ROOT/"scripts/gha_kvm_truenas_rdte.sh").read_text()


class TestVanilla263GuestRouting(unittest.TestCase):
    def test_native_product_is_explicit_not_paper_alias(self):
        self.assertIn("- minecraft-vanilla-263",WORKFLOW)
        self.assertIn('or . == "minecraft-vanilla-263"',WORKFLOW)
        self.assertIn('needs.changes.outputs.truenas_t6_product == \'minecraft-vanilla-263\'',WORKFLOW)
        self.assertIn('needs.changes.outputs.truenas_version == \'25.04.2.6\'',WORKFLOW)
        self.assertIn('[[ "$VERSION" == "25.04.2.6" ]]',HARNESS)
        self.assertIn('|| "$T6_PRODUCT" == "minecraft-vanilla-263"',HARNESS)

    def test_producer_signer_and_fresh_exact_artifact_seam(self):
        pin="29ec6cba7df51e316b0329926aa85807805dd07b"
        self.assertIn("foundry-minecraft-vanilla263-t6-control:",WORKFLOW)
        self.assertIn(
            "export-minecraft-vanilla-263-t6-control.yml@"+pin,WORKFLOW)
        self.assertIn("foundry_ref: "+pin,WORKFLOW)
        self.assertIn(
            "name: minecraft-vanilla263-java25-truenas-250426-t6-source-candidate",WORKFLOW)
        self.assertIn("scripts/admit_vanilla263_native_t6_control.py",WORKFLOW)
        self.assertIn('foundry_commit="'+pin+'"',WORKFLOW)
        self.assertIn(
            "needs['foundry-minecraft-vanilla263-t6-control'].result == 'success'",
            WORKFLOW)

    def test_exact_oracle_not_legacy_paper_status(self):
        self.assertIn("Checkout independently qualified vanilla26.3 protocol777 status oracle",WORKFLOW)
        self.assertIn("4df9fbbfea0ae0e824719db367bd551349a86378",WORKFLOW)
        self.assertIn("python3 scripts/assert_vanilla263_native_t6_receipt.py",WORKFLOW)
        self.assertIn("--product-profile vanilla263 --native-catalog-profile 1.15.30",HARNESS)
        self.assertIn('"minecraft_protocol": 777',HARNESS)
        self.assertIn('"minecraft_version": "26.3"',HARNESS)
        self.assertIn('"rdte-t6-minecraft-vanilla-263"',HARNESS)
        self.assertIn("--status-port \"$MINECRAFT_HOST_PORT\"",HARNESS)
        self.assertIn("MINECRAFT_HOSTFWD",HARNESS)

    def test_existing_request_edge_untouched_during_source_qualification(self):
        current=json.loads((ROOT/"config/truenas-rdte-run-request.json").read_text())
        proposal=json.loads((ROOT/"config/truenas-vanilla263-native-admission-request.json").read_text())
        self.assertEqual(current.get("product"),"minecraft-vanilla-263")
        self.assertEqual(current["version"],"25.04.2.6")
        self.assertEqual(current["rung"],"t6")
        self.assertEqual(current["authority_issue"],423)
        self.assertEqual(current["consumer_authority_issue"],627)
        self.assertEqual(current["request_id"],"tn-25-04-2-6-t6-vanilla-263-op4c-004-scoped-tls-readback")
        self.assertEqual(proposal["request_id"],"tn-25-04-2-6-t6-vanilla-263-op4b-001")
        self.assertEqual(proposal["consumer_authority_issue"],627)
        self.assertIn("NOT wired",proposal["purpose"])
        # Exactly one bounded heavyweight request edge is admitted in this PR.
        # A replay of this request_id without a new distinct edge is forbidden.
        self.assertIn("config/truenas-rdte-run-request.json)",WORKFLOW)
        self.assertIn('"$current_request_id" == "$previous_request_id"',WORKFLOW)

    def test_scoped_native_collage_readback_explicit_only_not_default_guest(self):
        self.assertIn('truenas_collage_readback=false',WORKFLOW)
        self.assertIn('(.collage_readback // false)',WORKFLOW)
        self.assertIn('truenas_collage_readback=$truenas_collage_readback',WORKFLOW)
        self.assertIn('--vanilla-collage-readback',WORKFLOW)
        self.assertIn('needs.changes.outputs.truenas_collage_readback',WORKFLOW)
        self.assertIn('--require-collage-readback',WORKFLOW)
        self.assertIn('ref: 17dfacc4351053fa06f8bdbaed7d931c97c1707e',WORKFLOW)
        self.assertIn('[[ "$truenas_collage_readback" == "true" ]]',WORKFLOW)
        self.assertIn('"$T6_PRODUCT" == "minecraft-vanilla-263"',HARNESS)
        self.assertIn('VANILLA_COLLAGE_READBACK=false',HARNESS)
        self.assertIn('--collage-source-ref "17dfacc4351053fa06f8bdbaed7d931c97c1707e"',HARNESS)
        self.assertIn('NATIVE_READBACK_ARGS=()',HARNESS)
        self.assertIn('"${NATIVE_READBACK_ARGS[@]}"',HARNESS)
        request=json.loads((ROOT/"config/truenas-rdte-run-request.json").read_text())
        self.assertIs(request.get("collage_readback"),True)
        self.assertEqual(request["request_id"],"tn-25-04-2-6-t6-vanilla-263-op4c-004-scoped-tls-readback")
        self.assertEqual(request["product"],"minecraft-vanilla-263")
        self.assertEqual(request["version"],"25.04.2.6")
        self.assertNotIn("--vanilla-collage-readback",
                         str(request))
        # Synthetic source tests cannot count as a live TLS/Go observation.
        probe=(ROOT/"scripts/truenas_middleware_collage_readback_p2.py").read_text()
        self.assertIn('VANILLA263_SOURCE_SHA',probe)
        self.assertIn('profile="vanilla263" if VANILLA263 else "paper"',
                      (ROOT/"scripts/truenas_middleware_minecraft_t6_probe.py").read_text())

    def test_no_fallback_guest_or_physical_promotion(self):
        self.assertNotIn('product == "minecraft-vanilla-263" && needs[\'foundry-minecraft-paper',WORKFLOW)
        self.assertIn("agent-dispatch-heavyweight-rdte",WORKFLOW)
        self.assertIn("queue: max",WORKFLOW)
        self.assertIn("cancel-in-progress: false",WORKFLOW)
        # Exact accepted source consumer must refuse a wrong Foundry SHA
        from scripts.admit_vanilla263_native_t6_control import CONTROL_SHA
        self.assertEqual(CONTROL_SHA,"c1d6d9bd6306de55b12072ea9d0d6411fa7d7f106a6a87bdbe1913c0d82c0615")

if __name__=="__main__":
    unittest.main()
