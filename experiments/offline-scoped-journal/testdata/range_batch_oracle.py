import copy,hashlib,json,pathlib,subprocess,sys,tempfile
exe=sys.argv[1]
def sha(b):return hashlib.sha256(b).hexdigest()
def dump(v):return json.dumps(v,separators=(",",":")).encode()
with tempfile.TemporaryDirectory() as tmp:
    d=pathlib.Path(tmp);a=bytes(range(256))*16384;b=bytearray(a);b[512:1024]=b"x"*512;b=bytes(b)
    refs=[];paths=[]
    for i,data in enumerate((a,b)):
        path=d/f"source{i}";path.write_bytes(data);paths.append(path)
        refs.append({"scope":{"run":"fixture","branch":f"b{i}","space":"file","producer":"p"},"occurrence":f"o{i}","sha256":sha(data),"size":str(len(data))})
    questions=[]
    for i in range(24):
        off=(i%8)*512
        questions.append({"id":f"q{i}","left":{"artifact":refs[0],"offset":str(off),"length":"512"},"right":{"artifact":refs[1],"offset":str(off),"length":"512"}})
    q={"schema":"range-relation-batch/v1","questions":questions}
    m={"schema":"range-relation-sources/v1","sources":[{"artifact":r,"path":str(p)} for r,p in zip(refs,paths)]}
    qp=d/"q.json";mp=d/"sources.json";counts={"compared":0,"unknown":0,"refused":0}
    def call(question=q,manifest=m,*,pin=True,raw=None):
        raw=dump(question) if raw is None else raw;qp.write_bytes(raw)
        args=[exe,"batch","-query",str(qp)]
        if pin:args+=["-query-sha256",sha(raw) if pin is True else pin]
        if manifest is not None:mp.write_bytes(dump(manifest));args+=["-sources",str(mp)]
        return subprocess.run(args,capture_output=True,text=True,timeout=10)
    def check(p,status=None):
        if status is None:
            assert p.returncode==2 and not p.stdout,(p.returncode,p.stdout,p.stderr);counts["refused"]+=1;return
        assert p.returncode==(0 if status=="batch_compared" else 3),(p.returncode,p.stderr)
        r=json.loads(p.stdout)["result"];assert r["status"]==status and r["causality"]=="unknown"
        counts["compared" if status=="batch_compared" else "unknown"]+=1
        if status!="batch_compared":assert "answers" not in r and r["verified_source_bytes"]=="0"
        return r
    z=check(call(),"batch_compared");assert len(z["answers"])==24
    for item,x in zip(questions,z["answers"]):
        off=int(item["left"]["offset"]);u,v=a[off:off+512],b[off:off+512]
        assert x["id"]==item["id"] and x["content"]==("equal" if u==v else "different")
        assert x["dependency"]=="unknown" and x["occurrence_relation"]=="distinct_declared_occurrences"
        if u!=v:assert int(x["first_difference"])==next(i for i,(y,w) in enumerate(zip(u,v)) if y!=w)
    assert z["verified_source_bytes"]==str(2*len(a)) and z["separate_query_source_bytes"]==str(48*len(a))
    assert z["verified_occurrences"]==2 and z["logical_selected_bytes"]==str(24*1024) and z["retained_selection_bytes"]==str(16*512)
    check(call(pin=False,manifest=None),"unknown_no_query_pin")
    check(call(manifest=None),"unknown_no_independent_pin")
    partial=copy.deepcopy(m);partial["sources"]=partial["sources"][:1];partial["sources"][0]["path"]=str(d/"absent")
    check(call(manifest=partial),"unknown_no_independent_pin")
    altered=copy.deepcopy(q);altered["questions"][0]["left"]["offset"]="1";check(call(altered,pin=sha(dump(q))))
    bad=copy.deepcopy(q);bad["questions"][1]["id"]=bad["questions"][0]["id"];check(call(bad))
    bad=copy.deepcopy(q);bad["questions"][1]["left"]["artifact"]["sha256"]="0"*64;check(call(bad))
    bad=copy.deepcopy(q);bad["questions"]=bad["questions"]*2;check(call(bad))
    bad=copy.deepcopy(m);bad["sources"].append(copy.deepcopy(bad["sources"][0]));check(call(manifest=bad))
    bad=copy.deepcopy(partial);bad["sources"][0]["artifact"]["sha256"]="0"*64;check(call(manifest=bad))
    bad=copy.deepcopy(m);bad["sources"][0]["artifact"]["scope"]["branch"]="foreign";check(call(manifest=bad))
    check(call(raw=dump(q).replace(b'"id":"q0"',b'"id":"q0","id":"duplicate"')))
    check(call(raw=dump(q)+b"{}"))
    changed=a[:-1]+bytes([a[-1]^1]);assert changed!=a and changed[:4096]==a[:4096]
    paths[0].write_bytes(changed);check(call());paths[0].write_bytes(a)
    paths[1].write_bytes(b[:-1]);check(call());paths[1].write_bytes(b)
    z2=check(call(),"batch_compared");assert z2==z
    print("Batch range oracle",json.dumps(counts,sort_keys=True),"logical selected",z["logical_selected_bytes"],"retained",z["retained_selection_bytes"],"verified",z["verified_source_bytes"],"separate",z["separate_query_source_bytes"])
    assert counts=={"compared":2,"unknown":3,"refused":11},counts
