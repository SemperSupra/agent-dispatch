#!/usr/bin/env python3
"""R8 optimizer availability and valid DEX proof from authored Java."""
import hashlib,json,os,subprocess,sys,tempfile,zipfile
from pathlib import Path
from androguard.core.dex import DEX

SOURCE='public class R8Fixture { public static String test(int n) { if(n<0) { try { throw new RuntimeException("NEGATIVE"); } catch(RuntimeException e) { return "CAUGHT"; } } return n==1 ? "ONE" : "OTHER"; } public static void main(String[] a) { System.out.print(test(Integer.parseInt(a[0]))); } }'
PIN='305622ad00535684534eb8f742cbf5e628a9abc09d8ea4d39d1babb95bf0cee5'
def call(cmd):
    p=subprocess.run([str(x) for x in cmd],capture_output=True,text=True,timeout=90)
    if p.returncode:raise RuntimeError(str(cmd[0])+':'+p.stderr[-500:])
    return p.stdout.strip() or p.stderr.strip()
def main(obfuscate=False):
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
        rules.write_text(('-keep,allowobfuscation' if obfuscate else '-keep')+' class R8Fixture { *; }\n-printmapping '+str(root/'mapping.txt')+'\n')
        output=root/'output';output.mkdir()
        call(['java','-cp',jar,'com.android.tools.r8.R8','--release','--min-api','26',
              '--lib',sdk/'platforms/android-35/android.jar','--pg-conf',rules,
              '--output',output,classes/'R8Fixture.class'])
        dex=(output/'classes.dex').read_bytes()
        parser=DEX(dex)
        names=[c.get_name() for c in parser.get_classes()]
        from droidasc.asc_client.apk_handler import ApkHandler
        archive=root/'optimized.apk'
        with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
            z.writestr('classes.dex',dex)
        handler=ApkHandler(str(archive),max_workers=2)
        asc_names=handler.list_classes(None)
        parity={}
        for token in ('ONE','OTHER','CAUGHT','UNREACHABLE_ABSENT_TOKEN'):
            andro=set()
            for cls in parser.get_classes():
                for method in cls.get_methods():
                    for inst in method.get_instructions():
                        if inst.get_name() in ('const-string','const-string/jumbo') and token in inst.get_string():
                            andro.add(cls.get_name()+'->'+method.get_name())
            actual=set()
            for _member,lines in handler.for_each_findrefs('string',{'string':token}):
                actual.update(line.split(' | ')[1].split(' |')[0] for line in lines if '->' in line)
            parity[token]={'androguard':sorted(andro),'asc':sorted(actual),'match':andro==actual}
        branch_ops=sum(inst.get_name().startswith('if-') or 'switch' in inst.get_name()
            for cls in parser.get_classes() for method in cls.get_methods()
            for inst in method.get_instructions())
        dexdump=sdk/'build-tools/35.0.0/dexdump'
        if dexdump.is_file():
            p=subprocess.run([str(dexdump),'-d',str(output/'classes.dex')],
                             capture_output=True,text=True,timeout=30)
            import re
            independent_branch_mentions=re.findall(r'\bif-[a-z]+\b',p.stdout)
            independent_dexdump={
                'available':True,'exit_code':p.returncode,
                'binary_sha256':hashlib.sha256(dexdump.read_bytes()).hexdigest(),
                'branch_mentions':len(independent_branch_mentions),
                'stdout_sha256':hashlib.sha256(p.stdout.encode()).hexdigest()}
        else:
            independent_dexdump={'available':False,'status':'NOT_INSTALLED'}
        independent_dexdump['branch_agreement']=(
            independent_dexdump.get('exit_code')==0 and
            independent_dexdump.get('branch_mentions')==branch_ops)
        receipt={'schema':'r8-synthetic-optimizer/v1','r8_jar_sha256':PIN,'obfuscation_mode':obfuscate,
                 'source_sha256':hashlib.sha256(SOURCE.encode()).hexdigest(),
                 'dex_sha256':hashlib.sha256(dex).hexdigest(),
                 'jvm_truth':truth,'dex_classes':names,'asc_classes':asc_names,
                 'xref_parity':parity,'conditional_opcodes':branch_ops,
                 'independent_dexdump':independent_dexdump,'mapping_exists':(root/'mapping.txt').is_file(),
                 'pass':(names!=['LR8Fixture;'] if obfuscate else 'LR8Fixture;' in names) and names==asc_names and branch_ops>0
                    and independent_dexdump['branch_agreement']
                    and all(x['match'] for x in parity.values())
                    and not parity['UNREACHABLE_ABSENT_TOKEN']['asc']
                    and (root/'mapping.txt').is_file()}
    out=Path(os.environ['RUNNER_TEMP'])/'evidence'/('r8-obfuscated.json' if obfuscate else 'r8-smoke.json')
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(receipt,indent=2)+'\n')
    print('R8_SMOKE',json.dumps(receipt))
    return 0 if receipt['pass'] else 1
if __name__=='__main__':raise SystemExit(main('--obfuscate' in sys.argv))
