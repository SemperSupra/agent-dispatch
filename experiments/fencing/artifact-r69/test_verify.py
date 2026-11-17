import hashlib
import io
import json
import unittest
import zipfile
from verify import Hold, NoFollow, validate_artifact_redirect, validate_meta, validate_zip

REPO="SemperSupra/agent-dispatch"
HEAD="a"*40
RUN=123
ATTEMPT=1
AID=456
NAME="r69-evidence-123-1"
MANIFEST={"class":"synthetic-evidence-only","repository":REPO,
          "run_id":RUN,"run_attempt":ATTEMPT,"event":"pull_request",
          "source_head":HEAD}

def zip_one(name="receipt.json",manifest=None):
    b=io.BytesIO()
    with zipfile.ZipFile(b,"w",zipfile.ZIP_DEFLATED) as f:
        f.writestr(name,json.dumps(MANIFEST if manifest is None else manifest))
    return b.getvalue()

def meta(digest):
    return {"total_count":1,"artifacts":[{"name":NAME,"id":AID,"expired":False,
            "digest":"sha256:"+digest,
            "workflow_run":{"id":RUN,"repository_id":7,"head_sha":HEAD}}]}

class Tests(unittest.TestCase):
    def test_artifact_redirect_origin_admission(self):
        valid = [
            "https://store.blob.core.windows.net/artifact.zip",
            "https://store.blob.core.windows.net:443/artifact.zip",
            "https://objects.githubusercontent.com/artifact.zip",
        ]
        for url in valid:
            with self.subTest(url=url):
                self.assertEqual(url, validate_artifact_redirect(url))

    def test_artifact_redirect_origin_denials(self):
        invalid = [
            "http://store.blob.core.windows.net/archive",
            "https://store.blob.core.windows.net:444/archive",
            "https://store.blob.core.windows.net:0/archive",
            "https://store.blob.core.windows.net:bad/archive",
            "https://user@store.blob.core.windows.net/archive",
            "https://user:pass@store.blob.core.windows.net/archive",
            "https://store.blob.core.windows.net.evil.example/archive",
            "https://127.0.0.1/archive",
            "https://localhost/archive",
            "file:///etc/passwd",
            "//store.blob.core.windows.net/archive",
            "",
        ]
        for url in invalid:
            with self.subTest(url=url):
                with self.assertRaisesRegex(Hold, "ORIGIN_NOT_ADMITTED"):
                    validate_artifact_redirect(url)

    def test_second_hop_redirect_refused(self):
        import urllib.request
        handler = NoFollow()
        request = urllib.request.Request("https://store.blob.core.windows.net/archive")
        self.assertIsNone(handler.redirect_request(
            request, None, 302, "Found", {}, "https://127.0.0.1/private"
        ))

    def test_valid_realistic_metadata_and_zip(self):
        payload=zip_one()
        dg=hashlib.sha256(payload).hexdigest()
        self.assertTrue(validate_meta(meta(dg),7,RUN,HEAD,AID,NAME,dg))
        self.assertTrue(validate_zip(payload,dg,REPO,RUN,ATTEMPT,HEAD))
    def test_duplicate_artifact(self):
        p=zip_one(); dg=hashlib.sha256(p).hexdigest(); m=meta(dg)
        m["artifacts"].append(dict(m["artifacts"][0]))
        m["total_count"]=2
        with self.assertRaisesRegex(Hold,"DUPLICATE"): validate_meta(m,7,RUN,HEAD,AID,NAME,dg)
    def test_partial_artifact_listing_holds_even_if_expected_artifact_present(self):
        p=zip_one(); dg=hashlib.sha256(p).hexdigest()
        for count in (-1, 0, 2, 101, True):
            with self.subTest(count=count):
                m=meta(dg); m["total_count"]=count
                with self.assertRaises(Hold):
                    validate_meta(m,7,RUN,HEAD,AID,NAME,dg)

    def test_false_uniqueness_from_partial_result_holds(self):
        p=zip_one(); dg=hashlib.sha256(p).hexdigest()
        m=meta(dg); m["artifacts"].append({"name":"other-artifact","id":789})
        with self.assertRaisesRegex(Hold,"PAGINATION_AMBIGUOUS"):
            validate_meta(m,7,RUN,HEAD,AID,NAME,dg)

    def test_valid_multi_artifact_listing(self):
        p=zip_one(); dg=hashlib.sha256(p).hexdigest()
        m=meta(dg); m["artifacts"].append({"name":"other-artifact","id":789})
        m["total_count"]=2
        self.assertEqual(AID, validate_meta(m,7,RUN,HEAD,AID,NAME,dg)["id"])

    def test_wrong_workflow_run(self):
        p=zip_one(); dg=hashlib.sha256(p).hexdigest(); m=meta(dg)
        m["artifacts"][0]["workflow_run"]["id"]=999
        with self.assertRaisesRegex(Hold,"WORKFLOW_MISMATCH"):validate_meta(m,7,RUN,HEAD,AID,NAME,dg)
    def test_digest_changed(self):
        p=zip_one(); dg=hashlib.sha256(p).hexdigest()
        with self.assertRaisesRegex(Hold,"ARCHIVE_DIGEST_MISMATCH"):validate_zip(p,"b"*64,REPO,RUN,ATTEMPT,HEAD)
    def test_path_traversal(self):
        p=zip_one("../../receipt.json"); dg=hashlib.sha256(p).hexdigest()
        with self.assertRaisesRegex(Hold,"LAYOUT"):validate_zip(p,dg,REPO,RUN,ATTEMPT,HEAD)
    def test_wrong_attempt(self):
        p=zip_one(); dg=hashlib.sha256(p).hexdigest()
        with self.assertRaisesRegex(Hold,"IDENTITY"):validate_zip(p,dg,REPO,RUN,2,HEAD)
    def test_wrong_source(self):
        p=zip_one(); dg=hashlib.sha256(p).hexdigest()
        with self.assertRaisesRegex(Hold,"IDENTITY"):validate_zip(p,dg,REPO,RUN,ATTEMPT,"b"*40)
    def test_missing_artifact(self):
        p=zip_one(); dg=hashlib.sha256(p).hexdigest(); m=meta(dg);m["artifacts"]=[];m["total_count"]=0
        with self.assertRaisesRegex(Hold,"MISSING"):validate_meta(m,7,RUN,HEAD,AID,NAME,dg)
    def test_expired_artifact(self):
        p=zip_one(); dg=hashlib.sha256(p).hexdigest(); m=meta(dg);m["artifacts"][0]["expired"]=True
        with self.assertRaisesRegex(Hold,"DIGEST"):validate_meta(m,7,RUN,HEAD,AID,NAME,dg)
if __name__=="__main__":unittest.main()
