"""Independent source rights/fixture/temporal oracle checks: no Docker needed."""
from pathlib import Path
import re
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import qualify_temporal_xtdb_frozen_oracle_r3 as q

class OriginalXTDBFrozenGold(unittest.TestCase):
    def test_frozen_fixture_source_and_claim_identity(self):
        sources,claims,digest=q.baseline_source()
        self.assertEqual(len(sources),6)
        self.assertEqual(len(claims),6)
        self.assertTrue(all(row[7] is None for row in claims),
                        "finite valid-to requires a separate interval fixture")
        self.assertEqual(len({x[0] for x in sources}),6)
        self.assertEqual(len({x[0] for x in claims}),6)
        self.assertEqual(sum(x[3]=="beta" for x in sources),1)
        self.assertEqual(sum(x[5]=="planned" for x in claims),1)
        self.assertTrue(all(x[1] in {s[0] for s in sources} for x in claims))
        self.assertNotEqual(digest("Approval denied."),digest("Approval granted."))

    def test_expected_independent_eight_case_gold(self):
        self.assertEqual(len(q.GOLD),8)
        self.assertEqual({x[0] for x in q.GOLD},
                         {"before_any","early_known","late_retro","pre_arrival",
                          "later_known","late_reacquisition","beta_private","alpha_unknown"})
        outcomes={item[0]:(item[4],item[5]) for item in q.GOLD}
        self.assertEqual(outcomes["early_known"],("REFUTED",("a1",)))
        self.assertEqual(outcomes["late_retro"],("BOTH",("a1","a3","a4")))
        self.assertEqual(outcomes["later_known"],("BOTH",("a1","a2")))
        self.assertEqual(outcomes["beta_private"],("SUPPORTED",("beta1",)))
        self.assertEqual(outcomes["alpha_unknown"],("NEITHER",()))

    def test_exact_original_xtdb_and_pg_client_digests(self):
        engine=q.load_original()
        self.assertEqual(engine.XTDB_DIGEST,
            "aa7483e48674446a4892e0ea56a0953502fa5ccb9c4c803a9fb569ea5f0c28fe")
        self.assertEqual(engine.CLIENT.rsplit("@sha256:",1)[-1],
            "e754b839f447639b7004895f4d8a4bfcb4e9dbe3a1bc035f27f646562a16fd61")
        self.assertEqual(q.quote("O'Hara"),"'O''Hara'")
        self.assertEqual(q.quote(None),"NULL")

    def test_no_user_supplied_sql_and_invalid_clock_refused(self):
        original=q.load_original()
        for bad in ("2026-05-01T12:00Z","today","2026-05-01T12:00:00+02:00",
                    "2026-05-01T12:00:00Z;DROP TABLE mail_sources"):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(q.Blocked,"UNREVIEWED_QUERY_CLOCK"):
                    q.query(original,"test-net","test-host","alpha",bad,"2026-05-11T00:00:00Z")
        with self.assertRaisesRegex(q.Blocked,"UNREVIEWED_TENANT"):
            q.query(original,"test-net","test-host","beta' OR 1=1--",
                    "2026-05-01T12:00:00Z","2026-05-11T00:00:00Z")

    def test_no_contaminating_source_or_credentials(self):
        body=(ROOT/"scripts/qualify_temporal_xtdb_frozen_oracle_r3.py").read_text()
        self.assertIn('"--network",network',body)
        self.assertNotIn("PST=",body)
        self.assertNotIn("GH_TOKEN",body)
        self.assertNotIn("GITHUB_TOKEN",body)
        self.assertNotIn("shell=True",body)
        self.assertIn("xtdb_source_immutability_enforced",body)
        self.assertIn("XTDB_UPSERT_ID_REQUIRES_APPLICATION_GUARD",body)

if __name__=="__main__":
    unittest.main()
