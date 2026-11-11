package gitops
import (
 "encoding/json"
 "fmt"
 "strings"
 "sync"
 "testing"
)
func snapshot(t *testing.T,research string)Snapshot{
 t.Helper()
 raw:=fmt.Sprintf(`{"schema":"m1.gitops.synthetic/v1","catalog":["alpha.read","alpha.write","beta.read","beta.write"],"belts":{"research":{"owner":"shared","tools":[%q]},"engineering":{"owner":"shared","tools":["beta.read"]},"personal":{"owner":"alpha","tools":["alpha.read"]}}}`,research)
 s,e:=Load([]byte(raw));if e!=nil{t.Fatal(e)};return s
}
func fixture()Policy{return Policy{Grants:map[string][]string{"alpha":{"alpha.read","beta.read","alpha.write"},"beta":{"beta.read"}},Epoch:4,Fresh:true}}
func req(s Snapshot,who,belt,tool string)Request{return Request{Authenticated:true,Principal:who,Belt:belt,Tool:tool,PinnedDigest:s.Digest,NativeAdmitted:true,AuditReady:true,RequiredPolicyEpoch:4}}
func TestTwoIndependentContexts(t *testing.T){
 s:=snapshot(t,"alpha.read");p:=fixture()
 tests:=[]struct{belt,tool string;allow bool}{
 {"research","alpha.read",true},{"engineering","beta.read",true},
 {"research","beta.read",false},{"engineering","alpha.read",false},
 {"personal","alpha.read",true},
 }
 var wg sync.WaitGroup
 for _,tc:=range tests {tc:=tc;wg.Add(1);go func(){
  defer wg.Done()
  for i:=0;i<60;i++{
   v:=Check(s,p,req(s,"alpha",tc.belt,tc.tool))
   if v.Allow!=tc.allow {t.Errorf("%s %s: %+v",tc.belt,tc.tool,v)}
  }
 }()};wg.Wait()
}
func TestGitRevisionPinnedPolicyCurrent(t *testing.T){
 old:=snapshot(t,"alpha.read");newer:=snapshot(t,"beta.read");p:=fixture()
 if old.Digest==newer.Digest{t.Fatal("snapshot revision did not change")}
 if !Check(old,p,req(old,"alpha","research","alpha.read")).Allow{t.Fatal("old pinned snapshot rejected")}
 if !Check(newer,p,req(newer,"alpha","research","beta.read")).Allow{t.Fatal("new pinned snapshot rejected")}
 if Check(newer,p,req(old,"alpha","research","alpha.read")).Allow{t.Fatal("cross-revision request accepted")}
 delete(p.Grants,"alpha")
 if Check(old,p,req(old,"alpha","research","alpha.read")).Allow{t.Fatal("revoke bypass old pinned snapshot")}
}
func TestFailClosed(t *testing.T){
 s:=snapshot(t,"alpha.read");p:=fixture()
 tests:=[]struct{name string; mutate func(*Policy,*Request)}{
 {"unverified",func(_ *Policy,r *Request){r.Authenticated=false}},
 {"missing-policy",func(p *Policy,_ *Request){p.Fresh=false}},
 {"stale-policy",func(p *Policy,_ *Request){p.Epoch=1}},
 {"provider-deny",func(_ *Policy,r *Request){r.NativeAdmitted=false}},
 {"snapshot-forgery",func(_ *Policy,r *Request){r.PinnedDigest="forged"}},
 {"unknown-principal",func(_ *Policy,r *Request){r.Principal="unknown"}},
 }
 for _,tc:=range tests{t.Run(tc.name,func(t *testing.T){
  p:=fixture();r:=req(s,"alpha","research","alpha.read");tc.mutate(&p,&r)
  if Check(s,p,r).Allow{t.Fatal("fail-open")}
 })}
 if Check(s,p,req(s,"beta","personal","alpha.read")).Allow{t.Fatal("owner isolation bypass")}
}
func TestPrivilegedAuditOutage(t *testing.T){
 raw:=`{"schema":"m1.gitops.synthetic/v1","catalog":["alpha.write"],"belts":{"ops":{"owner":"alpha","tools":["alpha.write"]}}}`
 s,e:=Load([]byte(raw));if e!=nil{t.Fatal(e)}
 p:=fixture();r:=req(s,"alpha","ops","alpha.write")
 if !Check(s,p,r).Allow{t.Fatal("audited synthetic mutation rejected")}
 r.AuditReady=false
 if Check(s,p,r).Allow{t.Fatal("audit sink outage permitted synthetic mutation")}
}
func TestInvalidBundles(t *testing.T){
 for _,raw:=range []string{
  `{}`,
  `{"schema":"m1.gitops.synthetic/v1","catalog":["x","x"],"belts":{"b":{"owner":"shared","tools":["x"]}}}`,
  `{"schema":"m1.gitops.synthetic/v1","catalog":["x"],"belts":{"b":{"owner":"shared","tools":["y"]}}}`,
 }{
  if _,e:=Load([]byte(raw));e==nil{t.Errorf("bad manifest accepted %s",raw)}
 }
}
func TestReceipt(t *testing.T){
 s:=snapshot(t,"alpha.read");v:=Check(s,fixture(),req(s,"alpha","research","alpha.read"))
 b,e:=json.Marshal(v)
 if e!=nil||!strings.Contains(string(b),`"allow":true`){t.Fatalf("bad verdict %s: %v",string(b),e)}
}
