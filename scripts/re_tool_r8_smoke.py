#!/usr/bin/env python3
"""R8 optimizer availability and valid DEX proof from authored Java."""
import hashlib,json,os,subprocess,tempfile,zipfile
from pathlib import Path
from androguard.core.dex import DEX

SOURCE='public class R8Fixture { public static String test(int n) { if(n<0) { try { throw new RuntimeException("NEGATIVE"); } catch(RuntimeException e) { return "CAUGHT"; } } return n==1 ? "ONE" : "OTHER"; } public static void main(String[] a) { System.out.print(test(Integer.parseInt(a[0]))); } }'
PIN='305622ad00535684534eb8f742cbf5e628a9abc09d8ea4d39d1babb95bf0cee5'
def call(cmd):
    p=subprocess.run([str(x) for x in cmd],capture_output=True,text=True,timeout=90)
    if p.returncode:raise RuntimeError(str(cmd[0])+':'+p.stderr[-500:])
    return p.stdout.strip() or p.stderr.strip()
def main():
    sdk=Path(os.environ.get('ANDROID_HOME','/usr/local/lib/android/sdk'))
    jar=sdk/'build-tools/35.0.0/lib/d8.jar'
    assert hashlib.sha256(jar.read_bytes()).hexdigest()==PIN
    with tempfile.TemporaryDirectory() as t:
        root=Path(t);src=root/'R8Fixture.java';src.write_text(SOURCE)
        classes=root/'classes';classes.mkdir()
        call(['javac','--release','17','-d',classes,src])
        truth={k:call(['java','-cp',classes,'R8Fixture',k]) for k in ['-1','0','1']}
        assert truth=={'-1':'CAUGHT','0':'OTHER','1':'ONE'}
        rules=root/'rules.pro'
        rules.write_text('-keep class R8Fixture { *; }\n-printmapping '+str(root/'mapping.txt')+'\n')
        output=root/'output';output.mkdir()
        call(['java','-cp',jar,'com.android.tools.r8.R8','--release','--min-api','26',
              '--lib',sdk/'platforms/android-35/android.jar','--pg-conf',rules,
              '--output',output,classes/'R8Fixture.class'])
        dex=(output/'classes.dex').read_bytes()
        parser=DEX(dex)
        names=[c.get_name() for c in parser.get_classes()]
        receipt={'schema':'r8-synthetic-optimizer/v1','r8_jar_sha256':PIN,
                 'source_sha256':hashlib.sha256(SOURCE.encode()).hexdigest(),
                 'dex_sha256':hashlib.sha256(dex).hexdigest(),
                 'jvm_truth':truth,'dex_classes':names,'mapping_exists':(root/'mapping.txt').is_file(),
                 'pass':'LR8Fixture;' in names and (root/'mapping.txt').is_file()}
    out=Path(os.environ['RUNNER_TEMP'])/'evidence'/'r8-smoke.json'
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(receipt,indent=2)+'\n')
    print('R8_SMOKE',json.dumps(receipt))
    return 0 if receipt['pass'] else 1
if __name__=='__main__':raise SystemExit(main())
