"""OP4D static, synthetic and negative source tests; NOT a guest-acceptance claim."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts import qualify_vanilla263_native_lantern_stage as s


class StageContract(unittest.TestCase):
    def make(self):
        self.td=tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        root=Path(self.td.name)
        path=root/s.NAME
        payloads={
            "pack.mcmeta": json.dumps({"pack":{"min_format":[121,0],
                                                 "max_format":[121,0]}}).encode(),
            "data/minecraft/tags/function/tick.json": b'{"values":[]}\n',
            "data/supracraft_core_restore/function/tick.mcfunction": b"say synthetic\n",
        }
        with zipfile.ZipFile(path,"w") as z:
            for name,data in sorted(payloads.items()):
                row=zipfile.ZipInfo(name,(1980,1,1,0,0,0))
                row.create_system=3
                row.external_attr=0o100644<<16
                z.writestr(row,data)
        blob=path.read_bytes()
        sha=hashlib.sha256(blob).hexdigest()
        m={
            "schema":"supracraft-vanilla-datapack-candidate/1",
            "classification":"SOURCE_ARTIFACT_EXPORTED",
            "producer":s.PRODUCER,"kind":"datapack","backend":"vanilla",
            "minecraft_version":"26.3","world_id":"lantern-rdte",
            "release_id":"lantern-core-restore-26-3","pack_format":[121,0],
            "relative_path":s.NAME,"world_save_included":False,
            "collage_deployed":False,"sha256":sha,"archive_size":len(blob),
            "members":[{"path":name,"sha256":hashlib.sha256(data).hexdigest(),
                        "bytes":len(data)} for name,data in sorted(payloads.items())],
        }
        manifest=root/"manifest.json"
        manifest.write_text(json.dumps(m))
        return path,manifest,blob,sha

    def test_real_manifest_shape_synthetic_zip_never_confused_with_immutable_bytes(self):
        zip_file,manifest,blob,sha=self.make()
        with self.assertRaisesRegex(s.Refused,"PINNED_REAL_ARTIFACT_SHA_DRIFT"):
            s.verify_exact_candidate(zip_file,manifest)
        with patch.object(s,"SHA",sha):
            content,receipt=s.verify_exact_candidate(zip_file,manifest)
            self.assertEqual(content,blob)
            self.assertEqual(receipt["sha256"],sha)
        for field,bad in (("minecraft_version","1.21.11"),
                          ("world_id","two-rivers-operations"),
                          ("collage_deployed",True),
                          ("producer","foreign/provenance@"+"0"*40),
                          ("pack_format",[80,0])):
            m=json.loads(manifest.read_text())
            m[field]=bad
            manifest.write_text(json.dumps(m))
            with patch.object(s,"SHA",sha),self.subTest(field=field):
                with self.assertRaises(s.Refused):
                    s.verify_exact_candidate(zip_file,manifest)
            m[field]=json.loads(json.dumps({
                "minecraft_version":"26.3","world_id":"lantern-rdte",
                "collage_deployed":False,"producer":s.PRODUCER,
                "pack_format":[121,0]}))[field]
            manifest.write_text(json.dumps(m))

    def test_disposable_app_must_be_stopped_before_native_file_upload(self):
        _,_,blob,sha=self.make()
        called=[]
        def fake(method,args):
            called.append(method)
            if method=="app.query":
                return [{"state":"RUNNING"}]
            raise AssertionError("mutating step called before quiesce")
        with patch.object(s,"SHA",sha):
            with self.assertRaisesRegex(s.Refused,"NATIVE_APP_MUST_BE_QUIESCED"):
                s.stage(fake,None,None,None,host="127.0.0.1",port=80,tls=False,
                        username="rdte",password="test-not-secret",timeout=8,
                        blob=blob,evidence={"sha256":sha})
        self.assertEqual(called,["app.query"])

    def test_native_own_world_writes_and_two_separate_digest_reads(self):
        _,_,blob,sha=self.make()
        called=[]
        def fake(method,args):
            called.append(method)
            if method=="app.query":return [{"state":"STOPPED"}]
            if method=="filesystem.stat":
                if args[0].endswith("/datapacks"):
                    return {"type":"DIRECTORY"}
                raise FileNotFoundError()
            if method=="core.download":
                self.assertEqual(args[1][0],s.TARGET)
                return [77,"/_download/exact-owned-artifact"]
            raise AssertionError(method)
        def upload(host,port,tls,user,password,target,content,mode,timeout):
            self.assertEqual(target,s.TARGET)
            self.assertEqual(content,blob)
            self.assertEqual(mode,0o644)
            called.append("filesystem.put")
            return 76
        def jobs(job,label):
            self.assertIn(job,(76,77))
            called.append("job_"+str(job))
        def http(host,port,tls,path,timeout):
            called.append("download_bytes")
            return blob
        with patch.object(s,"SHA",sha):
            r=s.stage(fake,jobs,upload,http,host="127.0.0.1",port=80,
                      tls=False,username="rdte",password="test-not-secret",
                      timeout=8,blob=blob,evidence={"sha256":sha})
        self.assertEqual(r["classification"],"REAL_NATIVE_GUEST_ARTIFACT_BYTES_STAGED")
        self.assertFalse(r["artifact_gameplay_effect_verified"])
        self.assertFalse(r["collage_managed_deployment"])
        self.assertEqual(r["physical_truenas_apply"],"HOLD")
        self.assertLess(called.index("app.query"),called.index("filesystem.put"))
        self.assertEqual(called.count("download_bytes"),1)

    def test_unsafe_readback_contract_refused(self):
        with self.assertRaisesRegex(s.Refused,"NATIVE_WORLD_ARTIFACT_DOWNLOAD_REF_INVALID"):
            s.readback(lambda method,args:[4,"https://external-host/forbidden"],None,None,
                       host="127.0.0.1",port=80,tls=False,timeout=8)


if __name__=="__main__":
    unittest.main()
