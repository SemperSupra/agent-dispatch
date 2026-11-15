package main

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

type reply struct {ID string `json:"id"`;Challenge string `json:"challenge"`;Witness string `json:"witness"`;State string `json:"state"`;Revision int64 `json:"revision"`}
func setup(t *testing.T)(*Service,string,string) {
 t.Helper()
 file:=filepath.Join(t.TempDir(),"state.json");token:=strings.Repeat("t",40)
 s,err:=newService(file,[]byte(token));if err!=nil{t.Fatal(err)}
 return s,file,token
}
func call(s *Service,token,actorName,method,path,body,idem string)(int,[]byte) {
 req:=httptest.NewRequest(method,path,bytes.NewBufferString(body))
 if body!="" {req.Header.Set("Content-Type","application/json")}
 if token!="" {req.Header.Set("Authorization","Bearer "+token)}
 req.Header.Set("X-Actor",actorName)
 if idem!="" {req.Header.Set("Idempotency-Key",idem)}
 w:=httptest.NewRecorder();s.Handler().ServeHTTP(w,req)
 return w.Code,w.Body.Bytes()
}
func enroll(t *testing.T,s *Service,token,id string,priv ed25519.PrivateKey) reply {
 t.Helper()
 key:=base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
 b,_:=json.Marshal(map[string]any{"id":id,"public_key":key})
 code,raw:=call(s,token,"human","POST","/api/v1/lab/enrollments",string(b),"enroll-"+id+"-once")
 if code!=201{t.Fatalf("init enroll %d: %s",code,raw)}
 var p reply;if err:=json.Unmarshal(raw,&p);err!=nil{t.Fatal(err)}
 if p.Challenge==""||p.Witness==""{t.Fatal("no console witness")}
 wrong,_:=call(s,token,"agent","POST","/api/v1/lab/enrollments/"+id+"/confirm",`{"witness":"WRONG"}`,"")
 if wrong!=403{t.Fatal("incorrect witness accepted")}
 msg:=enrollDomain+id+"\x00"+p.Challenge
 proof:=base64.StdEncoding.EncodeToString(ed25519.Sign(priv,[]byte(msg)))
 confirm,_:=json.Marshal(map[string]any{"witness":p.Witness,"signature":proof})
 code,raw=call(s,token,"agent","POST","/api/v1/lab/enrollments/"+id+"/confirm",string(confirm),"")
 if code!=200{t.Fatalf("confirm %d: %s",code,raw)}
 var n reply;_ =json.Unmarshal(raw,&n)
 if n.State!="ENROLLED"||n.Revision!=1{t.Fatalf("bad enroll state %+v",n)}
 return n
}
func TestLifecycleAllThreeAudiencesAndPersistence(t *testing.T) {
 s,file,token:=setup(t)
 _,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 n:=enroll(t,s,token,"synthetic-node-01",priv)
 sequence:=[]struct{action,actor,state string}{
  {"commission","human","COMMISSIONED"},
  {"qualify","automation","READY"},
  {"drain","agent","DRAINED"},
  {"resume","automation","READY"},
  {"drain","human","DRAINED"},
  {"retire","agent","RETIRED"},
 }
 for _,step:=range sequence {
  b,_:=json.Marshal(map[string]any{"action":step.action,"expected_revision":n.Revision})
  code,raw:=call(s,token,step.actor,"POST","/api/v1/lab/nodes/"+n.ID+"/actions",string(b),"")
  if code!=200{t.Fatalf("action %s returned %d: %s",step.action,code,raw)}
  _=json.Unmarshal(raw,&n)
  if n.State!=step.state{t.Fatalf("transition %s: got %s",step.action,n.State)}
 }
 if n.Revision!=7{t.Fatalf("revision %d",n.Revision)}
 invalid,_:=call(s,token,"human","POST","/api/v1/lab/nodes/"+n.ID+"/actions",`{"action":"commission","expected_revision":7}`,"")
 if invalid!=409{t.Fatal("retired device allowed transition")}
 loaded,err:=newService(file,[]byte(token));if err!=nil{t.Fatal(err)}
 code,raw:=call(loaded,token,"agent","GET","/api/v1/lab/nodes","","")
 if code!=200||!bytes.Contains(raw,[]byte("RETIRED"))||!bytes.Contains(raw,[]byte(`"hardware_verified":false`)){t.Fatalf("persistent state %d %s",code,raw)}
 code,raw=call(loaded,token,"automation","GET","/api/v1/lab/events","","")
 if code!=200||!bytes.Contains(raw,[]byte(`"actor":"human"`))||!bytes.Contains(raw,[]byte(`"actor":"automation"`))||!bytes.Contains(raw,[]byte(`"actor":"agent"`)){t.Fatalf("audience evidence %d %s",code,raw)}
 info,err:=os.Stat(file);if err!=nil||info.Mode().Perm()!=0600{t.Fatalf("persist perms %#v %v",info,err)}
}
func TestEnrollRejectsKeyReplayExpiryAndIdempotency(t *testing.T) {
 s,_,token:=setup(t)
 pk,priv,_:=ed25519.GenerateKey(rand.Reader)
 key:=base64.StdEncoding.EncodeToString(pk)
 b,_:=json.Marshal(map[string]any{"id":"test-node-02","public_key":key})
 c1,r1:=call(s,token,"automation","POST","/api/v1/lab/enrollments",string(b),"once-test-22")
 c2,r2:=call(s,token,"automation","POST","/api/v1/lab/enrollments",string(b),"once-test-22")
 if c1!=201||c2!=200{t.Fatalf("idempotency status %d %d",c1,c2)}
 var a,d reply;_ =json.Unmarshal(r1,&a);_ =json.Unmarshal(r2,&d)
 if a.Challenge!=d.Challenge||a.Witness!=d.Witness{t.Fatal("retry minted new witness")}
 another,_:=json.Marshal(map[string]any{"id":"test-node-03","public_key":key})
 conflict,_:=call(s,token,"automation","POST","/api/v1/lab/enrollments",string(another),"once-test-22")
 if conflict!=409{t.Fatal("idempotency token reused")}
 s.now=func()time.Time{return time.Now().Add(11*time.Minute)}
 sig:=base64.StdEncoding.EncodeToString(ed25519.Sign(priv,[]byte(enrollDomain+"test-node-02"+"\x00"+a.Challenge)))
 confirmation,_:=json.Marshal(map[string]any{"witness":a.Witness,"signature":sig})
 expired,_:=call(s,token,"agent","POST","/api/v1/lab/enrollments/test-node-02/confirm",string(confirmation),"")
 if expired!=409{t.Fatal("accepted expired challenge")}
}
func TestKeyRotationDualProofAndNegativeCases(t *testing.T) {
 s,_,token:=setup(t)
 _,priv,_:=ed25519.GenerateKey(rand.Reader)
 n:=enroll(t,s,token,"synthetic-node-04",priv)
 code,b:=call(s,token,"human","POST","/api/v1/lab/nodes/"+n.ID+"/rotation-challenge","","")
 if code!=200{t.Fatalf("prepare %d %s",code,b)}
 var q reply;_ =json.Unmarshal(b,&q)
 pubNew,privNew,_:=ed25519.GenerateKey(rand.Reader)
 msg:=rotateDomain+n.ID+"\x00"+q.Challenge
 oldSig:=base64.StdEncoding.EncodeToString(ed25519.Sign(priv,[]byte(msg)))
 newSig:=base64.StdEncoding.EncodeToString(ed25519.Sign(privNew,[]byte(msg)))
 payload,_:=json.Marshal(map[string]any{"public_key":base64.StdEncoding.EncodeToString(pubNew),"old_signature":oldSig,"new_signature":newSig,"expected_revision":n.Revision})
 code,b=call(s,token,"agent","POST","/api/v1/lab/nodes/"+n.ID+"/rotate-key",string(payload),"")
 if code!=200{t.Fatalf("rotate failed %d %s",code,b)}
 code,_=call(s,token,"agent","POST","/api/v1/lab/nodes/"+n.ID+"/rotate-key",string(payload),"")
 if code!=409{t.Fatal("accepted replay rotation")}
 if bytes.Contains(b,[]byte(string(privNew))){t.Fatal("private key leaked")}
}
func TestUnauthorizedUnsafeActionsAndHumanAssets(t *testing.T) {
 s,_,token:=setup(t)
 for _,methodPath:=range []struct{method,path string}{{"GET","/api/v1/lab/nodes"},{"GET","/api/v1/lab/events"},{"POST","/api/v1/lab/enrollments"}} {
  code,_:=call(s,"","agent",methodPath.method,methodPath.path,`{}`,"not-authorized")
  if code!=401{t.Errorf("unauthorized %s returned %d",methodPath.path,code)}
 }
 for _,path:=range []string{"/api/v1/lab/reimage","/api/v1/lab/flash","/api/v1/lab/bootnext","/api/v1/lab/garm/register"}{
  code,_:=call(s,token,"automation","POST",path,`{}`,"safety-test")
  if code==200||code==202||code==201{t.Fatalf("unsafe endpoint %s admitted",path)}
 }
 for _,p:=range []string{"/","/app.js","/style.css","/api/v1/lab/schema"}{
  code,b:=call(s,"","human","GET",p,"","")
  if code!=200||len(b)<30{t.Fatalf("missing human/agent asset %s: %d",p,code)}
 }
 code,body:=call(s,token,"human","GET","/api/v1/lab/schema","","")
 if code!=200||!bytes.Contains(body,[]byte(`"real_garm_admission":false`)){t.Fatal("failed to disclose simulation boundary")}
}
