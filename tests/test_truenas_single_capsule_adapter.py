#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SCRIPTS=ROOT/"scripts"
import sys
sys.path.insert(0,str(SCRIPTS))
import truenas_session_manifest as session
import truenas_single_capsule_adapter as adapter

TARGETS=ROOT/"config"/"truenas-rdte-targets.json"
PROVIDERS=ROOT/"config"/"truenas-capsule-providers.json"

EXPECTED={
 "litellm-t6":("litellm","litellm-truenas-t6-control","scripts/truenas_middleware_litellm_t6_probe.py"),
 "wow-sidecar-t6":("wow-sidecar","wow-sidecar-truenas-t6-control","scripts/truenas_middleware_wow_sidecar_t6_probe.py"),
 "garm-t6":("garm","garm-truenas-t6-control","scripts/truenas_middleware_garm_t6_probe.py"),
 "official-catalog-t6":("official-catalog","official-catalog-truenas-t6-control","scripts/truenas_middleware_official_catalog_t6_probe.py"),
 "foliorelay-t6":("foliorelay","foliorelay-t6-control","scripts/truenas_middleware_foliorelay_t6_probe.py"),
}

def manifest(provider):
    doc={
      "schema":"truenas-session/v1",
      "session_id":"tn-26-beta3-single-equivalence-001",
      "version":"26.0.0-BETA.3",
      "authority":{"repository":"SemperSupra/agent-dispatch-private","issue":480},
      "budget":{"guest_memory_mib":8192,"download_mib":1024,"timeout_minutes":30},
      "pool":{"name":"rdtepool","data_disks":2},
      "capsules":[{
        "schema":"truenas-capsule/v1","id":"equivalence-capsule-001",
        "kind":"official-catalog-control" if provider=="official-catalog-t6" else "foundry-product",
        "provider":provider,
        "authority":{"repository":"SemperSupra/truenas-app-foundry-private","issue":282},
        "exact":{"source_ref":"0123456789012345678901234567890123456789","artifact":"fixture"},
        "namespace":"rdte-equivalence-001","ports":[18080],
        "requirements":["apps","zfs-pool"],
        "resources":{"memory_mib":1024,"download_mib":256,"estimated_minutes":10},
        "phases":{"setup":True,"apply":True,"verify":True,"cleanup":True},
        "oracle":"existing product oracle unchanged",
        "receipt_contract":"existing-product-receipt/unchanged",
        "retry_policy":"read-only-reconcile","mutating":True,"cleanup_required":True,
        "dependencies":[]
      }]
    }
    doc["manifest_sha256"]=session.manifest_digest(doc)
    return doc

class SingleCapsuleEquivalenceTests(unittest.TestCase):
    def write(self,doc):
        f=tempfile.NamedTemporaryFile("w",suffix=".json",delete=False)
        with f:
            json.dump(doc,f,indent=2,sort_keys=True); f.write("\n")
        p=pathlib.Path(f.name)
        self.addCleanup(lambda:p.unlink(missing_ok=True))
        return p

    def test_every_existing_t6_provider_lowers_without_runtime_semantic_change(self):
        for provider,(selector,artifact,probe) in EXPECTED.items():
            with self.subTest(provider=provider):
                lowered=adapter.lower_single(self.write(manifest(provider)),TARGETS,PROVIDERS)
                self.assertEqual(lowered["existing_selector"],selector)
                self.assertEqual(lowered["control_artifact"],artifact)
                self.assertEqual(lowered["probe"],probe)
                self.assertFalse(lowered["runtime_semantics_changed"])
                self.assertEqual(lowered["manifest_sha256"],session.manifest_digest(manifest(provider)))

    def test_multi_capsule_manifest_is_rejected_by_equivalence_adapter(self):
        doc=manifest("foliorelay-t6")
        second=json.loads(json.dumps(doc["capsules"][0]))
        second["id"]="equivalence-capsule-002"
        second["namespace"]="rdte-equivalence-002"
        second["ports"]=[18081]
        doc["capsules"].append(second)
        doc["manifest_sha256"]=session.manifest_digest(doc)
        with self.assertRaisesRegex(session.SessionError,"exactly one capsule"):
            adapter.lower_single(self.write(doc),TARGETS,PROVIDERS)

if __name__=="__main__":
    unittest.main()
