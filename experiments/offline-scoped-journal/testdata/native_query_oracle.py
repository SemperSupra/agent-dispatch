import hashlib,json,pathlib,subprocess,sys,tempfile
exe=sys.argv[1]
def sha(b): return hashlib.sha256(b).hexdigest()
def ref(scope,occ,b): return {"scope":scope,"occurrence":occ,"sha256":sha(b),"size":str(len(b))}
def dumps(x): return json.dumps(x,separators=(",",":")).encode()
with tempfile.TemporaryDirectory() as t:
    d=pathlib.Path(t)
    c=d/"probe.c"
    c.write_text('#include <stdio.h>\n#include <stdint.h>\n__attribute__((noinline,used)) int observed(int x){return x+7;}\nint main(void){printf("p=0x%jx\\n",(uintmax_t)(uintptr_t)observed);FILE*f=fopen("/proc/self/maps","r");if(!f)return 2;char b[4096];while(fgets(b,sizeof(b),f))fputs(b,stdout);return fclose(f);}\n')
    cases={"positive":0,"unknown":0,"refused":0}
    for pie in (True,False):
        image=d/("pie" if pie else "exec")
        subprocess.run(["cc","-O0","-g",*(["-fPIE","-pie"] if pie else ["-fno-pie","-no-pie"]),"-o",str(image),str(c)],check=True)
        ib=image.read_bytes()
        want=int(next(l.split()[0] for l in subprocess.check_output(["nm","-n",str(image)],text=True).splitlines() if l.split()[-1]=="observed"),16)
        for i in range(3):
            scope={"run":f"fixture-{pie}-{i}","branch":"root","space":"process","producer":"observer"}
            raw=subprocess.check_output([str(image)],timeout=5)
            cap=d/"capture";cap.write_bytes(raw)
            first,rows=raw.split(b"\n",1);addr=int(first.split(b"=")[1],16);n=len(first)+1
            row=next(l.decode().split(maxsplit=5) for l in rows.splitlines() if int(l.split()[0].split(b"-")[0],16)<=addr<int(l.split()[0].split(b"-")[1],16))
            lo,hi=(int(v,16) for v in row[0].split("-"));off=int(row[2],16)
            assert row[5]==str(image) and row[1][2]=="x"
            cr=ref(scope,"capture",raw);ir=ref({**scope,"space":"file","producer":"build"},"image",ib)
            cp=d/"capture.json";ip=d/"image.json";cp.write_bytes(dumps(cr));ip.write_bytes(dumps(ir))
            q={"schema":"native-correspondence/v1","expected_scope":scope,"pointer":{"artifact":cr,"offset":"0","length":str(n)},"maps":{"artifact":cr,"offset":str(n),"length":str(len(rows))},"label":"p","module_path":str(image),"image":ir}
            query=d/"query.json";query.write_bytes(dumps(q))
            def call(*,question=q,extra=(),pins=True,querypin=True,raw_query=None,source=True):
                b=dumps(question) if raw_query is None else raw_query;query.write_bytes(b)
                args=[exe,"-query",str(query)]
                if querypin:args+=["-query-sha256",sha(b) if querypin is True else querypin]
                if pins:args+=["-capture-pin",str(cp),"-image-pin",str(ip)]
                if source:args+=["-capture",str(cap),"-image",str(image)]
                return subprocess.run(args+list(extra),capture_output=True,text=True,timeout=5)
            def check(r,status=None):
                if status is None:
                    assert r.returncode==2 and not r.stdout,(r.returncode,r.stdout,r.stderr);cases["refused"]+=1;return
                code=0 if status=="candidate_correspondence" else 3
                assert r.returncode==code,(r.returncode,r.stdout,r.stderr)
                o=json.loads(r.stdout);assert o["status"]==status and o["evidence_ceiling"]=="reported_pointer_candidate_only"
                assert ("location" in o)==(code==0);cases["positive" if code==0 else "unknown"]+=1;return o
            expected=["-expect-address",str(addr),"-expect-elf-virtual",str(want),"-expect-map-base",str(lo),"-expect-map-end",str(hi)]
            o=check(call(extra=expected),"candidate_correspondence")
            assert o["location"]=={"address":str(addr),"elf_virtual":str(want),"file_offset":str(addr-lo+off),"map_base":str(lo),"map_end":str(hi),"map_offset":str(off),"device":row[3],"inode":row[4]}
            assert o["query_sha256"]==sha(dumps(q)) and o["expectation_check"]=="supplied_coordinates_match" and o["artifact_integrity"]=="retained_byte_match"
            check(call(querypin=False,pins=False,source=False),"unknown_no_query_pin")
            check(call(pins=False,source=False),"unknown_no_independent_pin")
            check(call(question={**q,"module_path":str(image)+".foreign"}),"unknown_mapping")
            check(call(querypin="0"*64,source=False))
            check(call(extra=["-expect-address",str(addr+1)]))
            check(call(extra=["-expect-elf-virtual",str(want+1)]))
            check(call(extra=["-expect-map-base",str(lo+1),"-expect-map-end",str(hi)]))
            check(call(extra=["-expect-map-base",str(lo)]))
            check(call(question={**q,"expected_scope":{**scope,"branch":"foreign"}},source=False))
            check(call(question={**q,"maps":{**q["maps"],"artifact":{**cr,"occurrence":"foreign"}}},source=False))
            check(call(raw_query=dumps(q).replace(b'"label":"p"',b'"label":"p","label":"x"'),source=False))
            check(call(question={**q,"image":None},source=False))
            cp.write_bytes(dumps({**cr,"scope":{**scope,"branch":"stale"}}));check(call(source=False));cp.write_bytes(dumps(cr))
            cap.write_bytes(raw+b"x");check(call());cap.write_bytes(raw)
            # Selection is independently pinned: substituting a valid query under the old pin must refuse.
            check(call(question={**q,"module_path":str(image)+".other"},querypin=sha(dumps(q)),source=False))
    print("Native query CLI oracle",json.dumps(cases,sort_keys=True))
    assert cases=={"positive":6,"unknown":18,"refused":72},cases
