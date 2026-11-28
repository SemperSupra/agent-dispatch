package main

import (
 "context"
 "encoding/json"
 "os"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)
const testImage="ghcr.io/searxng/searxng:2026.10.23-629368e40@sha256:66d58661af069af77b29153aa8e5b9504d8681de905f87e58188f2ba6084ebf2"
func fixture() (Plan,Projection,[]byte,[]byte) {
 cpe:=Projection{Schema:"cpe-search-projection/v1",AuthorityRef:"cpe-exact-unverified-test-ref",Queries:[]Query{{Language:"en",Text:"concept learning",Role:"web"},{Language:"th",Text:"การเรียนรู้แนวคิด",Role:"web"},{Language:"de",Text:"Begriffslernen",Role:"web"}}}
 cp,_:=json.Marshal(cpe)
 p:=Plan{Schema:schema,ID:"public-sweep-test",DataClass:"public-reviewed",IntentRef:"reviewed-synthetic",Reference:[]Query{{Language:"en",Text:"learning",Role:"web"},{Language:"de",Text:"Lernen",Role:"web"},{Language:"th",Text:"การศึกษา",Role:"web"}},Languages:[]string{"en","de","th"},CPEProjectionSHA256:digest(cp),ImageDigest:testImage,ConfigSHA256:strings.Repeat("a",64)}
 pb,_:=json.Marshal(p);return p,cpe,pb,cp
}
func TestSixRealHTTPRequestsWithoutSemanticPromotion(t *testing.T){
 p,c,pb,cb:=fixture()
 calls:=0
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  calls++
  if r.URL.Path!="/search"||r.URL.Query().Get("format")!="json"{t.Errorf("bad path or format: %s",r.URL)}
  if r.URL.Query().Get("q")==""{t.Error("empty query")}
  w.Header().Set("Content-Type","application/json")
  _,_=w.Write([]byte(`{"results":[{"url":"https://example.org/article","title":"Source title","content":"Descriptive retrieval only","engine":"unit-test"}],"unresponsive_engines":[]}`))
 }))
 defer server.Close()
 result,err:=run(context.Background(),p,c,pb,cb,server.URL,server.Client())
 if err!=nil{t.Fatal(err)}
 if calls!=6||result.Attempted!=6||result.Succeeded!=6||result.Failed!=0||result.State!="RETRIEVAL_PASS"{t.Fatalf("not live provider: %+v calls=%d",result,calls)}
 if result.Attempts[0].Track!="reference"||result.Attempts[3].Track!="cpe"{t.Fatal("track order")}
 b,_:=json.Marshal(result)
 for _,s:=range []string{"semantic_findings","concept_promotion","relation_truth","ontology_pass"}{if strings.Contains(string(b),s){t.Fatalf("Stage R leaked semantic claim: %s",s)}}
 if !strings.Contains(string(b),"PROJECTION_DIGEST_MATCH_ONLY_NOT_AUTHORITY_VERIFIED"){t.Fatal("authority claimed without attestation")}
}
func TestNetworkFailureIsNotMadeUpEvidence(t *testing.T){
 p,c,pb,cb:=fixture()
 broken:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(503);_,_=w.Write([]byte("backend down"))}))
 base:=broken.URL;broken.Close()
 result,err:=run(context.Background(),p,c,pb,cb,base,&http.Client{})
 if err!=nil{t.Fatal(err)}
 if result.State!="SOURCE_EXECUTOR_GAP"||result.Succeeded!=0||result.Failed!=6{t.Fatalf("fabricated success %+v",result)}
 for _,a:=range result.Attempts {if a.State!="FAILED_PROVIDER"||len(a.Hits)>0{t.Fatalf("fabricated evidence %+v",a)}}
}
func TestProviderRedirectCannotSendQueryToAnotherOrigin(t *testing.T){
 p,c,pb,cb:=fixture()
 redirected:=0
 target:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){redirected++;w.WriteHeader(200)}))
 defer target.Close()
 local:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  http.Redirect(w,r,target.URL+"/search",http.StatusFound)
 }))
 defer local.Close()
 result,err:=run(context.Background(),p,c,pb,cb,local.URL,local.Client())
 if err!=nil{t.Fatal(err)}
 if redirected!=0||result.State!="SOURCE_EXECUTOR_GAP"||result.Succeeded!=0||result.Failed!=6{
  t.Fatalf("redirect escaped admitted origin: redirected=%d result=%+v",redirected,result)
 }
 for _,a:=range result.Attempts {
  if a.State!="FAILED_PROVIDER"||a.HTTPStatus!=http.StatusFound||len(a.Hits)!=0{t.Fatalf("redirect accepted: %+v",a)}
 }
}
func TestWrongPinnedCPEBytesFailBeforeNetwork(t *testing.T){
 p,c,pb,cb:=fixture()
 p.CPEProjectionSHA256=strings.Repeat("0",64)
 attempts:=0
 s:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){attempts++;w.WriteHeader(200)}));defer s.Close()
 _,err:=run(context.Background(),p,c,pb,cb,s.URL,s.Client())
 if err==nil||attempts!=0{t.Fatalf("CPE digest bypass %v %d",err,attempts)}
}
func TestPublicAndLoopbackAdmission(t *testing.T){
 p,c,_,cb:=fixture()
 p.DataClass="private";if validate(p,c,cb)==nil{t.Fatal("private task accepted on public worker")}
 p,_,_,_=fixture()
 p.CPEProjectionSHA256=""
 if validate(p,c,cb)==nil{t.Fatal("missing CPE projection accepted")}
 for _,u:=range []string{"https://127.0.0.1:18888","http://10.0.0.1:18888","http://example.org:18888","http://127.0.0.1:18888/search","http://127.0.0.1:18888?url=http://x"} {
  if endpointOK(u)==nil{t.Fatalf("unapproved endpoint %s",u)}
 }
 if endpointOK("http://127.0.0.1:18888")!=nil{t.Fatal("loopback blocked")}
}
func TestMalformedProviderCannotBeReportedSuccessful(t *testing.T){
 p,c,pb,cb:=fixture()
 s:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){_,_=w.Write([]byte("<html>not-json</html>"))}));defer s.Close()
 x,e:=run(context.Background(),p,c,pb,cb,s.URL,s.Client())
 if e!=nil||x.State!="SOURCE_EXECUTOR_GAP"||x.Succeeded!=0{t.Fatalf("bad provider accepted %+v %v",x,e)}
}
func TestGlobalLanguageAndQueryBudget(t *testing.T){
 p,c,_,cb:=fixture()
 p.Languages=[]string{"en","en","th"}
 if validate(p,c,cb)==nil{t.Fatal("duplicate locale allowed")}
 p,_,_,_=fixture()
 p.Reference[0].Text=strings.Repeat("q",maxQueryChars+1)
 if validate(p,c,cb)==nil{t.Fatal("unbounded query accepted")}
}

func TestCommittedPublicPilotFixtureDigestAndRuntime(t *testing.T){
 var p Plan
 planBytes,e:=readJSON("pilot-plan.json",&p)
 if e!=nil{t.Fatal(e)}
 var projection Projection
 projBytes,e:=readJSON("pilot-projection.json",&projection)
 if e!=nil{t.Fatal(e)}
 if err:=validate(p,projection,projBytes);err!=nil{t.Fatalf("pilot must fail only on real provider/runtime boundary: %v",err)}
 cfg,e:=os.ReadFile("searxng.settings.yml")
 if e!=nil{t.Fatal(e)}
 if got:=digest(cfg);got!=p.ConfigSHA256{t.Fatalf("runtime config drift: %s",got)}
 if p.CPEProjectionSHA256!=digest(projBytes){t.Fatal("projection digest drift")}
 if !strings.HasPrefix(projection.AuthorityRef,"SYNTHETIC_TEST_ONLY_"){t.Fatal("test packet could be mistaken for approved CPE authority")}
 if !strings.Contains(string(planBytes),"PUBLIC_SYNTHETIC_PROTOCOL_TEST_ONLY"){t.Fatal("pilot must not be counted as real science")}
}

func TestHTTP200ProviderErrorCannotMasqueradeAsEmptySearch(t *testing.T) {
 p,c,pb,cb:=fixture()
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","application/json")
  _,_=w.Write([]byte(`{"error":"quota or upstream unavailable"}`))
 }))
 defer srv.Close()
 result,err:=run(context.Background(),p,c,pb,cb,srv.URL,srv.Client())
 if err!=nil{t.Fatal(err)}
 if result.Succeeded!=0||result.Failed!=6||result.State!="SOURCE_EXECUTOR_GAP"{t.Fatalf("fabricated HTTP 200 success: %+v",result)}
 for _,a:=range result.Attempts{
  if a.State!="FAILED_PROVIDER"||len(a.Hits)!=0{t.Fatalf("fabricated results: %+v",a)}
 }
}

func TestUnqualifiedSourceRolesFailClosed(t *testing.T) {
 p,c,_,cb:=fixture()
 p.Reference[0].Role="dictionary"
 if validate(p,c,cb)==nil { t.Fatal("dictionary role mislabeled as general web") }
 p,c,_,cb=fixture()
 c.Queries[0].Role="ontology"
 updated,_:=json.Marshal(c)
 p.CPEProjectionSHA256=digest(updated)
 if validate(p,c,updated)==nil { t.Fatal("ontology role mislabeled as general web") }
}
