import copy, pathlib, unittest
from scripts.truenas_product_t6_admission import AdmissionError, get_product, validate

ROOT=pathlib.Path(".")
def cfg():
    import json
    return json.loads((ROOT/"config/truenas-product-t6-admission.json").read_text())
def targets():
    import json
    return json.loads((ROOT/"config/truenas-rdte-targets.json").read_text())

class AdmissionTests(unittest.TestCase):
    def test_current_contract_validates(self):
        self.assertEqual(validate(cfg(),targets(),ROOT)["status"],"PASS")
    def test_beta_existing_admitted(self):
        p=get_product(cfg(),"litellm")
        self.assertEqual(p["target_admission"]["26.0.0-BETA.3"]["status"],"ADMITTED_EXISTING")
    def test_2504_is_admitted_after_generic_control_acceptance(self):
        p=get_product(cfg(),"garm")
        self.assertEqual(p["target_admission"]["25.04.1"]["status"],"ADMITTED")
    def test_new_target_invalidates_coverage(self):
        t=targets(); t["targets"].append({**t["targets"][-1],"version":"27.0.0-NIGHTLY"})
        with self.assertRaises(AdmissionError): validate(cfg(),t,ROOT)
    def test_consumer_blob_drift_fails(self):
        c=cfg(); c["products"][0]["consumer"]["blob_sha"]="0"*40
        with self.assertRaises(AdmissionError): validate(c,targets(),ROOT)
    def test_nonadmitted_cannot_carry_evidence(self):
        c=cfg(); c["products"][0]["target_admission"]["25.04.2.6"]["evidence"]={"fake":True}
        with self.assertRaises(AdmissionError): validate(c,targets(),ROOT)

if __name__=="__main__": unittest.main()
