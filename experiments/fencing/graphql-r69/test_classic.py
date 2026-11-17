import unittest
from classic import classify,Hold

class ClassicProtection(unittest.TestCase):
    def test_404_is_observation_not_authority(self):
        x=classify(404,None)
        self.assertEqual(x["classic_protection"],"NOT_VISIBLE")
        self.assertEqual(x["protected_external_high_water"],"NOT_PROVEN")
    def test_config_does_not_prove_denial(self):
        x=classify(200,{"enforce_admins":{"enabled":True},
                        "allow_force_pushes":{"enabled":False},
                        "allow_deletions":{"enabled":False},
                        "required_pull_request_reviews":{}})
        self.assertEqual(x["endpoint_observation"],"PROTECTION_CONFIG_VISIBLE")
        self.assertEqual(x["force_push_denial"],"NOT_VERIFIED")
        self.assertEqual(x["production_authority"],"HOLD")
    def test_not_enforce_admins_is_not_promoted(self):
        x=classify(200,{"enforce_admins":{"enabled":False}})
        self.assertEqual(x["enforce_admins_flag"],False)
        self.assertEqual(x["protected_external_high_water"],"NOT_PROVEN")
    def test_unknown_missing_fields_do_not_invent_enforcement(self):
        x=classify(200,{})
        self.assertIsNone(x["allow_force_pushes_flag"])
    def test_malformed_setting_denied(self):
        with self.assertRaisesRegex(Hold,"INVALID_BRANCH"):classify(200,{"enforce_admins":{"enabled":"true"}})
    def test_non_json_denied(self):
        with self.assertRaisesRegex(Hold,"INVALID_PROVIDER"):classify(200,[])
    def test_unexpected_status_denied(self):
        with self.assertRaisesRegex(Hold,"INVALID_PROVIDER"):classify(403,{})
if __name__=="__main__":unittest.main()
