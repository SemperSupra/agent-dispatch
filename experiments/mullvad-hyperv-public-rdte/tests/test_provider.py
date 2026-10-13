"""No live provider traffic. Positive, negative and mutated-response controls."""
import pathlib
import sys
import unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from oracles.provider import Relay, Device, select_relay, authorize_device_change, public_safe_diagnostic


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.relays = (
            Relay("eu-aa-1", "de", "fra", True),
            Relay("jp-aa-1", "jp", "osa", True),
            Relay("jp-aa-2", "jp", "osa", False),
            Relay("us-bb-1", "us", "nyc", True),
        )
        self.devices = (Device("synthetic-A", "account-placeholder", True),
                        Device("synthetic-B", "account-placeholder", True))

    def test_primary_eligible(self):
        choice = select_relay(self.relays, "jp", "osa")
        self.assertEqual(choice.relay.name, "jp-aa-1")
        self.assertEqual(choice.reason, "PRIMARY")

    def test_no_wrong_country_or_city_fallback(self):
        for country, city in [("fr", ""), ("jp", "tok"), ("zz", "xxx"), ("us", "sfo")]:
            with self.subTest(country=country, city=city):
                selection = select_relay(self.relays, country, city)
                self.assertIsNone(selection.relay)
                self.assertEqual(selection.reason, "BLOCKED_CONSTRAINT_UNAVAILABLE")

    def test_explicit_fallback_only(self):
        sel = select_relay(self.relays, "jp", "tok", approved_fallbacks=(("de", "fra"),))
        self.assertEqual(sel.relay.name, "eu-aa-1")
        self.assertEqual(sel.reason, "EXPLICIT_FALLBACK")
        sel = select_relay(self.relays, "jp", "tok", approved_fallbacks=(("de", "ber"),))
        self.assertIsNone(sel.relay)

    def test_inactive_and_empty_result_fail_closed(self):
        self.assertIsNone(select_relay(tuple(), "de").relay)
        self.assertIsNone(select_relay((Relay("n1", "de", "fra", False),), "de").relay)
        self.assertIsNone(select_relay(self.relays, "", "osa").relay)

    def test_mutation_wrong_location_never_accepted(self):
        mut = tuple(Relay(x.name, "us" if x.name == "jp-aa-1" else x.country,
                          x.city, x.active) for x in self.relays)
        self.assertIsNone(select_relay(mut, "jp", "osa").relay)

    def test_device_change_requires_exact_id_owner_action_and_approval(self):
        self.assertTrue(authorize_device_change(
            self.devices, "synthetic-A", "account-placeholder", "rotate-key", True))
        for id_, alias, action, approval in [
            ("synthetic-C", "account-placeholder", "rotate-key", True),
            ("*", "account-placeholder", "revoke", True),
            ("synthetic-A", "another-account", "revoke", True),
            ("synthetic-A", "account-placeholder", "list", True),
            ("synthetic-A", "account-placeholder", "revoke", False),
            ("", "account-placeholder", "revoke", True),
        ]:
            with self.subTest(id=id_, action=action, approval=approval):
                self.assertFalse(authorize_device_change(self.devices, id_, alias, action, approval))
        duplicated = self.devices + (self.devices[0],)
        self.assertFalse(authorize_device_change(
            duplicated, "synthetic-A", "account-placeholder", "revoke", True))

    def test_public_receipt_is_default_deny(self):
        raw = {"phase": "synthetic", "result": "BLOCKED", "test_case": "T1",
               "account_number": "SECRET_FAKE_ACCOUNT", "bearer": "SECRET_FAKE_BEARER",
               "wireguard_private_key": "SECRET_FAKE_KEY", "endpoint": "PRIVATE_FAKE_IP"}
        result = public_safe_diagnostic(raw)
        self.assertEqual(set(result), {"phase", "result", "test_case"})
        for sentinel in ("SECRET_FAKE_ACCOUNT", "SECRET_FAKE_BEARER", "SECRET_FAKE_KEY", "PRIVATE_FAKE_IP"):
            self.assertNotIn(sentinel, str(result))

    def test_secret_in_approved_field_is_not_echoed(self):
        fake_secret = "FAKE_BEARER_SHOULD_NOT_APPEAR"
        hostile = {"phase": fake_secret, "result": fake_secret,
                   "error_class": fake_secret, "oracle": fake_secret,
                   "test_case": fake_secret, "unexpected": fake_secret}
        self.assertEqual(public_safe_diagnostic(hostile), {})
        self.assertNotIn(fake_secret, str(public_safe_diagnostic(hostile)))
        self.assertEqual(public_safe_diagnostic({
            "phase": "connecting", "result": "BLOCKED", "error_class": "ORACLE",
            "oracle": "provider", "test_case": "T99"
        }), {"phase": "connecting", "result": "BLOCKED",
             "error_class": "ORACLE", "oracle": "provider", "test_case": "T99"})


if __name__ == "__main__":
    unittest.main()
