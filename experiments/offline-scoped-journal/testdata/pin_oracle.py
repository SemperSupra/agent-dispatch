import hashlib,json,pathlib,subprocess,sys,tempfile
exe=sys.argv[1]
with tempfile.TemporaryDirectory() as tmp:
    d=pathlib.Path(tmp)
    source=d/"source.bin"; source.write_bytes(b"original retained synthetic artifact")
    claim={"scope":{"run":"r","branch":"root","space":"file","producer":"p"},"occurrence":"o1","sha256":hashlib.sha256(source.read_bytes()).hexdigest(),"size":str(source.stat().st_size)}
    c=d/"claim.json"; p=d/"pin.json"; c.write_text(json.dumps(claim));p.write_text(json.dumps(claim))
    def invoke(*args):
        return subprocess.run([exe,"-claim",str(c),*args],capture_output=True,text=True,timeout=5)
    def refuse(*args):
        r=invoke(*args);assert r.returncode==2 and not r.stdout,(r.returncode,r.stdout,r.stderr)
    r=invoke("-source",str(d/"nonexistent"))
    assert r.returncode==3 and json.loads(r.stdout)["status"]=="unknown_no_independent_pin"
    args=["-pin",str(p),"-source",str(source)]
    r=invoke(*args);assert r.returncode==0 and json.loads(r.stdout)=={"status":"retained_byte_match","artifact":claim}
    for key,value in [("occurrence","other"),("size",str(source.stat().st_size+1)),("sha256","0"*64)]:
        c.write_text(json.dumps({**claim,key:value}));refuse(*args)
    for key in claim["scope"]:
        c.write_text(json.dumps({**claim,"scope":{**claim["scope"],key:"different"}}));refuse(*args)
    c.write_text(json.dumps(claim))
    refuse("-pin",str(p))
    refuse("-pin",str(p),"-source",str(d))
    source.write_bytes(b"re-sealed sibling")
    refuse(*args)
    c.write_text(json.dumps({**claim,"sha256":hashlib.sha256(source.read_bytes()).hexdigest(),"size":str(source.stat().st_size)}))
    refuse(*args)
    c.write_text(json.dumps(claim)+"{}");refuse(*args)
    print("Retained pin CLI: 2 outcome classes and 12 refusals PASS")
