"""Offline fixed original PostgreSQL source/image and structural admission tests."""
from pathlib import Path
import re
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import qualify_temporal_postgres18 as q

class PostgreSQLTemporalAdmission(unittest.TestCase):
    def test_fixed_official_image_and_network_cutoff(self):
        self.assertEqual(q.SCHEMA,"mail-temporal-native-postgresql18-r2")
        self.assertTrue(q.IMAGE.startswith("postgres:18.7-trixie@sha256:"))
        self.assertTrue(re.fullmatch(r"[a-f0-9]{64}",q.IMAGE.rsplit("@sha256:",1)[-1]))
        self.assertNotIn("latest",q.IMAGE)
        self.assertEqual(q.MAX_SECONDS,190)
        self.assertNotIn("PASSWORD",q.DDL)
        self.assertIn("WITHOUT OVERLAPS",q.DDL)
        self.assertIn("CREATE EXTENSION IF NOT EXISTS btree_gist",q.DDL)
        self.assertIn("CREATE TRIGGER protect_source",q.DDL)
        self.assertIn("CREATE TRIGGER protect_assessment",q.DDL)
        self.assertIn("CROSS_TENANT_CLAIM",q.DDL)

    def test_same_fictional_source_and_claim_fixture_as_sqlite(self):
        source,claims,digest=q.original_fixture()
        self.assertEqual(len(source),6)
        self.assertEqual(len(claims),6)
        self.assertEqual(sum(row[3]=="beta" for row in source),1)
        self.assertEqual([r[0] for r in source][:3],["a1","a2","a3"])
        self.assertNotEqual(digest("Approval denied."),digest("Approval granted."))
        self.assertEqual(q.quote("O'Hara"),"'O''Hara'")
        self.assertEqual(q.quote(None),"NULL")

    def test_exact_sql_source_contract_not_generic_user_commands(self):
        body=(ROOT/"scripts/qualify_temporal_postgres18.py").read_text()
        for fragment in ('"--network","none"','"--memory","1024m"','"docker","exec","-i"'):
            self.assertIn(fragment,body)
        self.assertIn("POSTGRES_HOST_AUTH_METHOD=trust",body)
        self.assertIn("docker(\"volume\",\"rm\",\"-f\",volume",body)
        self.assertNotIn("docker.socket",body)
        self.assertNotIn("subprocess.Popen(",body)

if __name__=="__main__":
    unittest.main()
