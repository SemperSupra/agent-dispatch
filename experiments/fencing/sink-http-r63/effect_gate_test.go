package gate

import (
 "bytes"
 "encoding/json"
 "io"
 "net/http"
 "net/http/httptest"
 "sync"
 "testing"
)

type envelope struct {
 Scope string `json:"scope"`
 Owner string `json:"owner"`
 Key string `json:"key"`
 Epoch uint64 `json:"epoch"`
 Cost uint64 `json:"cost"`
}
type view struct {
 Remaining uint64 `json:"remaining"`
 Effects map[string]string `json:"effects"`
}
type fakeSink struct {
 mu sync.Mutex
 scope, owner string
 epoch, remaining uint64
 effects map[string]string
 enforceAtCommit bool
}
func newSink(enforce bool) *fakeSink {
 return &fakeSink{scope:"synthetic-budget",owner:"old",epoch:1,remaining:1,effects:make(map[string]string),enforceAtCommit:enforce}
}
func (s *fakeSink) ServeHTTP(w http.ResponseWriter,r *http.Request) {
 s.mu.Lock()
 defer s.mu.Unlock()
 if r.Method=="GET" && r.URL.Path=="/read" {
  w.Header().Set("Content-Type","application/json")
  _=json.NewEncoder(w).Encode(view{Remaining:s.remaining,Effects:s.effects})
  return
 }
 if r.Method!="POST" {http.Error(w,"method",405);return}
 var e envelope
 if json.NewDecoder(io.LimitReader(r.Body,4096)).Decode(&e)!=nil {http.Error(w,"bad request",400);return}
 switch r.URL.Path {
 case "/prepare":
  // This check is *not* enough to authorize a later irreversible effect.
  if e.Owner!=s.owner||e.Epoch!=s.epoch||e.Scope!=s.scope {http.Error(w,"stale",409);return}
  w.WriteHeader(204)
 case "/rotate":
  // Privileged test-only owner change, not a production epoch authority.
  if e.Epoch<=s.epoch {http.Error(w,"nonmonotonic",409);return}
  s.owner=e.Owner;s.epoch=e.Epoch;w.WriteHeader(204)
 case "/apply":
  if s.enforceAtCommit && (e.Owner!=s.owner||e.Epoch!=s.epoch||e.Scope!=s.scope) {http.Error(w,"stale",409);return}
  if _,ok:=s.effects[e.Key];ok {w.WriteHeader(208);return}
  if e.Key==""||e.Cost==0||e.Cost>s.remaining {http.Error(w,"no budget",429);return}
  s.effects[e.Key]="UNKNOWN";s.remaining-=e.Cost
  if r.Header.Get("X-Drop-Ack")=="1" {
   // Commit occurs, but the client does not receive success.
   h,ok:=w.(http.Hijacker);if !ok {panic("httptest HTTP1 hijacking unavailable")}
   c,_,err:=h.Hijack();if err!=nil {panic(err)}
   _=c.Close();return
  }
  w.WriteHeader(http.StatusCreated)
 default:
  http.Error(w,"unknown",404)
 }
}
func request(t *testing.T,client *http.Client,url,path string,e envelope,drop bool)(int,error){
 t.Helper()
 b,err:=json.Marshal(e);if err!=nil{t.Fatal(err)}
 req,err:=http.NewRequest("POST",url+path,bytes.NewReader(b));if err!=nil{t.Fatal(err)}
 if drop {req.Header.Set("X-Drop-Ack","1")}
 req.Header.Set("Content-Type","application/json")
 res,err:=client.Do(req);if err!=nil{return 0,err}
 defer res.Body.Close()
 _,_=io.Copy(io.Discard,res.Body)
 return res.StatusCode,nil
}
func current(t *testing.T,client *http.Client,url string)view{
 t.Helper()
 res,err:=client.Get(url+"/read");if err!=nil{t.Fatal(err)}
 defer res.Body.Close()
 var v view
 if err=json.NewDecoder(res.Body).Decode(&v);err!=nil{t.Fatal(err)}
 return v
}
func TestAtCommitRejectsDelayedOldOwner(t *testing.T){
 srv:=httptest.NewServer(newSink(true));defer srv.Close()
 c:=srv.Client();old:=envelope{Scope:"synthetic-budget",Owner:"old",Epoch:1,Key:"late",Cost:1}
 if code,err:=request(t,c,srv.URL,"/prepare",old,false);err!=nil||code!=204{t.Fatalf("prepare: %d %v",code,err)}
 if code,err:=request(t,c,srv.URL,"/rotate",envelope{Owner:"new",Epoch:2},false);err!=nil||code!=204{t.Fatalf("rotate: %d %v",code,err)}
 if code,err:=request(t,c,srv.URL,"/apply",old,false);err!=nil||code!=409{t.Fatalf("stale apply: %d %v",code,err)}
 if v:=current(t,c,srv.URL);v.Remaining!=1||len(v.Effects)!=0{t.Fatalf("stale effect admitted: %#v",v)}
}
func TestUnsafePreflightToActualHTTPEffectExpectedRed(t *testing.T){
 srv:=httptest.NewServer(newSink(false));defer srv.Close()
 c:=srv.Client();old:=envelope{Scope:"synthetic-budget",Owner:"old",Epoch:1,Key:"unsafe-late",Cost:1}
 if code,_:=request(t,c,srv.URL,"/prepare",old,false);code!=204{t.Fatal(code)}
 if code,_:=request(t,c,srv.URL,"/rotate",envelope{Owner:"new",Epoch:2},false);code!=204{t.Fatal(code)}
 if code,err:=request(t,c,srv.URL,"/apply",old,false);err!=nil||code!=201{t.Fatalf("negative control changed: %d %v",code,err)}
 t.Log("EXPECTED RED: preflight-only gate permits old actor's late HTTP effect after owner transfer")
}
func TestLostAckReservesUNKNOWNAndIdempotentReceipt(t *testing.T){
 srv:=httptest.NewServer(newSink(true));defer srv.Close()
 c:=srv.Client();e:=envelope{Scope:"synthetic-budget",Owner:"old",Epoch:1,Key:"receipt-1",Cost:1}
 if _,err:=request(t,c,srv.URL,"/apply",e,true);err==nil{t.Fatal("expected lost ack")}
 if v:=current(t,c,srv.URL);v.Remaining!=0||v.Effects[e.Key]!="UNKNOWN"{t.Fatalf("liability missing: %#v",v)}
 if code,err:=request(t,c,srv.URL,"/apply",e,false);err!=nil||code!=208{t.Fatalf("not idempotent %d %v",code,err)}
 e.Key="different"
 if code,err:=request(t,c,srv.URL,"/apply",e,false);err!=nil||code!=429{t.Fatalf("overclaim %d %v",code,err)}
}
func TestParallelHTTPContendersExactlyOne(t *testing.T){
 srv:=httptest.NewServer(newSink(true));defer srv.Close()
 c:=srv.Client();gate:=make(chan struct{})
 codes:=make(chan int,2)
 var wg sync.WaitGroup
 for _,key:=range []string{"actor-a","actor-b"} {
  wg.Add(1)
  go func(key string){
   defer wg.Done();<-gate
   code,err:=request(t,c,srv.URL,"/apply",envelope{Scope:"synthetic-budget",Owner:"old",Epoch:1,Key:key,Cost:1},false)
   if err!=nil {codes<-0;return};codes<-code
  }(key)
 }
 close(gate);wg.Wait();close(codes)
 created,denied:=0,0
 for code:=range codes{if code==201{created++};if code==429{denied++}}
 if created!=1||denied!=1 {t.Fatalf("created=%d denied=%d",created,denied)}
 if v:=current(t,c,srv.URL);v.Remaining!=0||len(v.Effects)!=1{t.Fatalf("bad sink state: %#v",v)}
}
func TestWrongScopeAndEpochDenied(t *testing.T){
 srv:=httptest.NewServer(newSink(true));defer srv.Close()
 c:=srv.Client()
 for _,e:=range []envelope{{Scope:"other",Owner:"old",Epoch:1,Key:"a",Cost:1},{Scope:"synthetic-budget",Owner:"other",Epoch:1,Key:"b",Cost:1},{Scope:"synthetic-budget",Owner:"old",Epoch:0,Key:"c",Cost:1}}{
  if code,err:=request(t,c,srv.URL,"/apply",e,false);err!=nil||code!=409{t.Fatalf("expected scope deny: %d %v",code,err)}
 }
}
