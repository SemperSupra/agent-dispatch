"""Offline negative source, image and runtime isolation gates for original XTDB."""
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
import qualify_temporal_xtdb as q

class SourceRightsTests(unittest.TestCase):
    def test_exact_ghcr_amd64_source_and_postgres_client(self):
        self.assertEqual(q.SCHEMA,"public-mail-xtdb-native-temporal-r2")
        self.assertEqual(q.XTDB_DIGEST,
          "aa7483e48674446a4892e0ea56a0953502fa5ccb9c4c803a9fb569ea5f0c28fe")
        self.assertEqual(q.ENGINE,"ghcr.io/xtdb/xtdb@sha256:"+q.XTDB_DIGEST)
        self.assertEqual(q.CLIENT,
          "postgres:18.7-trixie@sha256:e754b839f447639b7004895f4d8a4bfcb4e9dbe3a1bc035f27f646562a16fd61")
        self.assertNotIn("latest",q.ENGINE)
        self.assertLessEqual(q.MAX_SECONDS,240)
    def test_psql_successful_dml_with_no_result_row(self):
        # The first native red rep was diagnosed only as NATIVE_XTDB_IO.
        # A successful fixed INSERT may produce no stdout under psql -q -t.
        # Never turn an empty result into an IndexError or a fake SELECT row.
        for output in ("","\\n","\\n\\n"):
            self.assertEqual(q.last_result_row(output),"")
        self.assertEqual(q.last_result_row("1\\n"),"1")
        self.assertEqual(q.last_result_row("READY\\n"),"READY")
        self.assertEqual(q.last_result_row(" \\n approved \\n"),"approved")

    def test_reviewed_full_source_is_no_port_and_no_paid_service(self):
        content=(ROOT/"scripts/qualify_temporal_xtdb.py").read_text()
        self.assertIn('docker("network","create","--internal"',content)
        self.assertIn('"--security-opt","no-new-privileges"',content)
        self.assertIn("FOR VALID_TIME AS OF",content)
        self.assertIn("FOR VALID_TIME ALL FOR SYSTEM_TIME ALL",content)
        self.assertIn("same_eight_case_oracle_qualified\":False",content)
        self.assertNotIn("--publish",content)
        self.assertNotIn("-p 5432",content)
        self.assertNotIn("subprocess.Popen(",content)

if __name__=="__main__":
    unittest.main()
