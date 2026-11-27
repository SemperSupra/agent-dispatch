import hashlib,json,pathlib,subprocess,sys,tempfile,copy
exe=sys.argv[1]
def sha(b):return hashlib.sha256(b).hexdigest()
def dump(x):return json.dumps(x,separators=(",",":")).encode()
def ref(scope,occ,b):return {"scope":scope,"occurrence":occ,"sha256":sha(b),"size":str(len(b))}
with tempfile.TemporaryDirectory() as t:
    d=pathlib.Path(t);a=b"0123abcXYZ";b=b"xxabcZZZZ"
    l=d/"left";r=d/"right";l.write_bytes(a);r.write_bytes(b)
    s={"run":"r","branch":"root","space":"file","producer":"p"}
    ar=ref(s,"a",a);br=ref({**s,"branch":"restore","producer":"q"},"b",b)
    lp=d/"lp.json";rp=d/"rp.json";lp.write_bytes(dump(ar));rp.write_bytes(dump(br))
    q={"schema":"range-relation/v1","left":{"artifact":ar,"offset":"4","length":"3"},"right":{"artifact":br,"offset":"2","length":"3"}}
    file=d/"q.json";counts={"compared":0,"unknown":0,"refused":0}
    def invoke(question=q,*,pin=True,leftpin=True,rightpin=True,sources=True,raw=None):
        raw=dump(question) if raw is None else raw;file.write_bytes(raw)
        args=[exe,"-query",str(file)]
        if pin:args+=["-query-sha256",sha(raw) if pin is True else pin]
        if leftpin:args+=["-left-pin",str(lp)]
        if rightpin:args+=["-right-pin",str(rp)]
        if sources:args+=["-left",str(l),"-right",str(r)]
        return subprocess.run(args,capture_output=True,text=True,timeout=5)
    def check(p,status=None):
        if status is None:
            assert p.returncode==2 and not p.stdout,(p.returncode,p.stdout,p.stderr);counts["refused"]+=1;return
        assert p.returncode==(0 if status=="range_compared" else 3),(p.returncode,p.stderr)
        z=json.loads(p.stdout)["result"];assert z["status"]==status and z["causality"]=="unknown" and z["evidence_ceiling"]=="selected_retained_byte_relation_only"
        counts["compared" if status=="range_compared" else "unknown"]+=1;return z
    z=check(invoke(),"range_compared")
    assert z["content"]=="equal" and z["occurrence_relation"]=="distinct_declared_occurrences" and z["dependency"]=="unknown" and z["selected_bytes"]=="3" and z["verified_source_bytes"]=="19" and "first_difference" not in z
    other=copy.deepcopy(q);other["right"]["offset"]="3"
    z=check(invoke(other),"range_compared");assert z["content"]=="different" and z["first_difference"]=="0"
    same=copy.deepcopy(q);same["right"]=copy.deepcopy(q["left"]);rp.write_bytes(dump(ar));r.write_bytes(a)
    z=check(invoke(same),"range_compared");assert z["dependency"]=="shared_declared_occurrence" and z["occurrence_relation"]=="same_declared_occurrence"
    copied=copy.deepcopy(same);copied["right"]["artifact"]["occurrence"]="copy";rp.write_bytes(dump(copied["right"]["artifact"]))
    z=check(invoke(copied),"range_compared");assert z["dependency"]=="unknown" and z["occurrence_relation"]=="distinct_declared_occurrences" and z["content"]=="equal"
    rp.write_bytes(dump(br));r.write_bytes(b)
    check(invoke(pin=False,sources=False),"unknown_no_query_pin")
    check(invoke(leftpin=False,sources=False),"unknown_no_independent_pin")
    check(invoke(rightpin=False,sources=False),"unknown_no_independent_pin")
    check(invoke(other,pin=sha(dump(q)),sources=False))
    for key,value in [("offset","18446744073709551615"),("length","0"),("length","4")]:
        bad=copy.deepcopy(q);bad["right"][key]=value;check(invoke(bad,sources=False))
    bad=copy.deepcopy(same);bad["right"]["artifact"]["sha256"]=br["sha256"];check(invoke(bad,sources=False))
    bad=copy.deepcopy(q);bad["right"]["artifact"]["scope"]["branch"]="foreign";check(invoke(bad,sources=False))
    check(invoke(raw=dump(q).replace(b'"offset":"4"',b'"offset":"4","offset":"5"'),sources=False))
    check(invoke(raw=dump(q)+b"{}",sources=False))
    rp.write_bytes(dump(ar));check(invoke(leftpin=False,sources=False));rp.write_bytes(dump(br))
    r.write_bytes(b+b"x");check(invoke());r.write_bytes(b)
    l.write_bytes(a[:-1]+b"Z");check(invoke());l.write_bytes(a)
    bad=copy.deepcopy(q);bad["schema"]="causal-link/v1";check(invoke(bad,sources=False))
    print("Range relation CLI oracle",json.dumps(counts,sort_keys=True))
    assert counts=={"compared":4,"unknown":3,"refused":12},counts
