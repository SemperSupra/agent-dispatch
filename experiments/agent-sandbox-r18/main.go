// Public synthetic R18: integrate immutable R16 Linux hub leases and R17
// Linux-local QMP HID through a separate IP gateway. No guest OS or real USB.
// This makes a source-level qualification claim, not a production deployment.
package main

import (
 "bytes"
 "crypto/subtle"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "os"
 "sync"
 "time"
)
const (
 frontURL = "http://r18-gateway:18083"
 r16URL = "http://r16-gateway:18081"
 r17URL = "http://r17-broker:18082"
 userToken = "r18-fixture-user"
 ownerToken = "r18-fixture-owner"
 hubToken = "r16-public-synthetic-control"
 hubOwner = "r16-public-synthetic-owner"
 hidToken = "r17-synthetic-control-only"
 hidOwner = "r17-synthetic-owner-only"
)
var role="unset"
var httpClient=&http.Client{Timeout:3*time.Second}
type UserCommand struct {
 Actor string
 Guest string
 Mission string
 Kind string
 Down bool
}
type Reply struct {
 Accepted bool
 Reason string
 Active bool
}
type Hub struct {Ports []struct{
 ID string `json:"id"`
 Owner string `json:"owner"`
 Guest string `json:"guest"`
 Mission string `json:"mission"`
 Attached bool `json:"attached"`
 Generation uint64 `json:"generation"`
 } `json:"ports"`
}
type BackendReply struct{
 Accepted bool `json:"accepted"`
 Lease string `json:"lease"`
 Generation uint64 `json:"generation"`
 Held bool `json:"held"`
}
type Session struct{
 Actor,Guest,Mission string
 HubLease,HidLease string
 HubGen,HidGen uint64
 Active bool
}
type Gateway struct{
 mu sync.Mutex
 s Session
 poisoned bool
}
func call(method,url,token string,body any)(int,[]byte,error){
 var input io.Reader
 if body!=nil{raw,_:=json.Marshal(body);input=bytes.NewReader(raw)}
 req,e:=http.NewRequest(method,url,input)
 if e!=nil{return 0,nil,e}
 if token!=""{req.Header.Set("Authorization","Bearer "+token)}
 if body!=nil{req.Header.Set("Content-Type","application/json")}
 resp,e:=httpClient.Do(req)
 if e!=nil{return 0,nil,e}
 defer resp.Body.Close()
 b,e:=io.ReadAll(io.LimitReader(resp.Body,16<<10))
 return resp.StatusCode,b,e
}
func backend(method,url,token string,body any)(int,BackendReply,error){
 status,data,e:=call(method,url,token,body)
 if e!=nil{return 0,BackendReply{},e}
 var out BackendReply
 if status!=401&&status!=405&&status!=400{
  if e=json.Unmarshal(data,&out);e!=nil{return status,BackendReply{},e}
 }
 return status,out,nil
}
func port() (Hub,error){
 status,data,e:=call("GET",r16URL+"/v1/hubs",hubToken,nil)
 if e!=nil{return Hub{},e}
 if status!=200{return Hub{},fmt.Errorf("R16 inventory rejected HTTP %d",status)}
 var hub Hub
 if e=json.Unmarshal(data,&hub);e!=nil{return Hub{},e}
 return hub,nil
}
func r16Port() (string,uint64,bool,string,string,string,error){
 h,e:=port()
 if e!=nil{return "",0,false,"","","",e}
 for _,p:=range h.Ports{
  if p.ID=="kbd-1"{return p.ID,p.Generation,p.Attached,p.Owner,p.Guest,p.Mission,nil}
 }
 return "",0,false,"","","",errors.New("R16 keyboard port absent")
}
func hubCommand(action string,s Session,gen uint64,lease string,owner bool)(int,BackendReply,error){
 c:=map[string]any{
  "action":action,"device":"kbd-1","actor":s.Actor,
  "guest":s.Guest,"mission":s.Mission,"generation":gen,"lease":lease,
 }
 if action=="claim"{c["ttl_seconds"]=30}
 token:=hubToken
 if owner{token=hubOwner}
 return backend("POST",r16URL+"/v1/commands",token,c)
}
func hidCommand(path string,s Session,gen uint64,kind string,down,owner bool)(int,BackendReply,error){
 c:=map[string]any{
  "actor":s.Actor,"guest":s.Guest,"mission":s.Mission,
  "lease":s.HidLease,"generation":gen,"kind":kind,"down":down,
 }
 if path=="/v1/claim"{c["ttl_seconds"]=6}
 token:=hidToken
 if owner{token=hidOwner}
 return backend("POST",r17URL+path,token,c)
}
func hidStatus()(uint64,error){
 code,data,e:=call("GET",r17URL+"/v1/status",hidToken,nil)
 if e!=nil{return 0,e}
 if code!=200{return 0,errors.New("R17 status rejected")}
 var r BackendReply
 if e=json.Unmarshal(data,&r);e!=nil{return 0,e}
 return r.Generation,nil
}
func valid(s string)bool {
 if len(s)<1||len(s)>64{return false}
 for _,r:=range s{if !(r>='a'&&r<='z'||r>='A'&&r<='Z'||r>='0'&&r<='9'||r=='-'||r=='_'){return false}}
 return true
}
func (g *Gateway) claim(c UserCommand)Reply{
 if g.poisoned{return Reply{Reason:"broker_fail_closed"}}
 if g.s.Active{return Reply{Reason:"exclusive_focus_held"}}
 if !valid(c.Actor)||!valid(c.Guest)||!valid(c.Mission){return Reply{Reason:"invalid_scope"}}
 _,gen,attached,owner,guest,mission,e:=r16Port()
 if e!=nil{return Reply{Reason:"hub_unavailable"}}
 if attached||owner!=""||guest!=""||mission!=""{return Reply{Reason:"hub_device_unavailable"}}
 session:=Session{Actor:c.Actor,Guest:c.Guest,Mission:c.Mission}
 code,leased,e:=hubCommand("claim",session,gen,"",false)
 if e!=nil||code!=200||leased.Lease==""{return Reply{Reason:"hub_lease_refused"}}
 session.HubLease=leased.Lease
 session.HubGen=leased.Generation
 code,attachedResponse,e:=hubCommand("attach",session,session.HubGen,session.HubLease,false)
 if e!=nil||code!=200{
  _,release,releaseErr:=hubCommand("release",session,session.HubGen,session.HubLease,false)
  if releaseErr!=nil||!release.Accepted{g.poisoned=true}
  return Reply{Reason:"hub_simulated_route_denied"}
 }
 session.HubGen=attachedResponse.Generation
 hidGen,e:=hidStatus()
 if e!=nil{
  _,r,rollbackErr:=hubCommand("release",session,session.HubGen,session.HubLease,false)
  if rollbackErr!=nil||!r.Accepted{g.poisoned=true}
  return Reply{Reason:"hid_broker_unavailable"}
 }
 code,hidLease,e:=hidCommand("/v1/claim",session,hidGen,"",false,false)
 if e!=nil||code!=200||hidLease.Lease==""{
  _,r,rollbackErr:=hubCommand("release",session,session.HubGen,session.HubLease,false)
  if rollbackErr!=nil||!r.Accepted{g.poisoned=true}
  return Reply{Reason:"hid_focus_lease_refused"}
 }
 session.HidLease=hidLease.Lease
 session.HidGen=hidLease.Generation
 session.Active=true
 g.s=session
 fmt.Println("R18_R16_LEASE_PRECEDES_R17_FOCUS=PASS")
 return Reply{Accepted:true,Active:true}
}
func (g *Gateway) revokeHid()bool{
 if !g.s.Active{return true}
 code,r,e:=hidCommand("/v1/revoke",g.s,g.s.HidGen,"",false,true)
 if e!=nil||code!=200||!r.Accepted{
  g.poisoned=true
  return false
 }
 return true
}
func (g *Gateway) input(c UserCommand)Reply{
 if g.poisoned{return Reply{Reason:"broker_fail_closed"}}
 if !g.s.Active{return Reply{Reason:"no_active_session"}}
 if c.Actor!=g.s.Actor||c.Guest!=g.s.Guest||c.Mission!=g.s.Mission{
  return Reply{Reason:"scope_mismatch"}
 }
 if c.Kind!="key-a"&&c.Kind!="button-left"{return Reply{Reason:"unsupported_input"}}
 _,gen,attached,owner,guest,mission,e:=r16Port()
 if e!=nil{return Reply{Reason:"hub_unavailable_fail_closed"}}
 if gen!=g.s.HubGen||!attached||owner!=g.s.Actor||guest!=g.s.Guest||mission!=g.s.Mission{
  if !g.revokeHid(){return Reply{Reason:"revoke_failed_fail_closed"}}
  g.s=Session{}
  fmt.Println("R18_HUB_REVOKE_FENCED_REMOTE_QMP_INPUT=PASS")
  return Reply{Reason:"hub_lease_revoked"}
 }
 code,r,e:=hidCommand("/v1/input",g.s,g.s.HidGen,c.Kind,c.Down,false)
 if e!=nil||code!=200||!r.Accepted{
  g.poisoned=true
  return Reply{Reason:"QMP_input_not_accepted_fail_closed"}
 }
 g.s.HidGen=r.Generation
 fmt.Println("R18_R16_GENERATION_VALIDATED_BEFORE_QMP_INPUT=PASS")
 return Reply{Accepted:true,Active:true}
}
func (g *Gateway) ownerRevoke(hubOnly bool)Reply{
 if !g.s.Active{return Reply{Reason:"no_active_session"}}
 code,r,e:=hubCommand("revoke",g.s,g.s.HubGen,"",true)
 if e!=nil||code!=200||!r.Accepted{
  g.poisoned=true
  return Reply{Reason:"owner_hub_revoke_failed_closed"}
 }
 if hubOnly{
  fmt.Println("R18_INDEPENDENT_HUB_OWNER_REVOKE=PASS")
  return Reply{Accepted:true,Active:true}
 }
 if !g.revokeHid(){return Reply{Reason:"QMP_focus_revoke_failed"}}
 g.s=Session{}
 fmt.Println("R18_OWNER_REVOKED_HUB_AND_QMP_FOCUS=PASS")
 return Reply{Accepted:true}
}
func match(r *http.Request,token string)bool{
 got:=r.Header.Get("Authorization")
 want:="Bearer "+token
 return len(got)==len(want)&&subtle.ConstantTimeCompare([]byte(got),[]byte(want))==1
}
func (g *Gateway) handler()http.Handler{
 mux:=http.NewServeMux()
 mux.HandleFunc("/health",func(w http.ResponseWriter,r *http.Request){
  if r.Method!="GET"{http.Error(w,"method",405);return}
  fmt.Fprint(w,"R18_LINUX_GATEWAY_HEALTH")
 })
 mux.HandleFunc("/v1/claim",func(w http.ResponseWriter,r *http.Request){
  if !match(r,userToken){http.Error(w,"unauthorized",401);return}
  if r.Method!="POST"{http.Error(w,"method",405);return}
  var c UserCommand
  r.Body=http.MaxBytesReader(w,r.Body,2048)
  decoder:=json.NewDecoder(r.Body)
  decoder.DisallowUnknownFields()
  if decoder.Decode(&c)!=nil{http.Error(w,"bad_json",400);return}
  g.mu.Lock();ans:=g.claim(c);g.mu.Unlock()
  write(w,ans)
 })
 mux.HandleFunc("/v1/input",func(w http.ResponseWriter,r *http.Request){
  if !match(r,userToken){http.Error(w,"unauthorized",401);return}
  if r.Method!="POST"{http.Error(w,"method",405);return}
  var c UserCommand
  r.Body=http.MaxBytesReader(w,r.Body,2048)
  decoder:=json.NewDecoder(r.Body);decoder.DisallowUnknownFields()
  if decoder.Decode(&c)!=nil{http.Error(w,"bad_json",400);return}
  g.mu.Lock();ans:=g.input(c);g.mu.Unlock()
  write(w,ans)
 })
 for _,route:=range []string{"/test/revoke-hub","/v1/revoke"}{
  path:=route
  mux.HandleFunc(path,func(w http.ResponseWriter,r *http.Request){
   if !match(r,ownerToken){http.Error(w,"unauthorized",401);return}
   if r.Method!="POST"{http.Error(w,"method",405);return}
   g.mu.Lock();ans:=g.ownerRevoke(path=="/test/revoke-hub");g.mu.Unlock()
   write(w,ans)
  })
 }
 return mux
}
func write(w http.ResponseWriter,ans Reply){
 w.Header().Set("Content-Type","application/json")
 if !ans.Accepted{w.WriteHeader(403)}
 _=json.NewEncoder(w).Encode(ans)
}
func serve()error{
 g:=&Gateway{}
 fmt.Println("R18_LINUX_HUB_QMP_POLICY_GATEWAY_IP_READY=PASS")
 s:=http.Server{Addr:":18083",Handler:g.handler(),ReadHeaderTimeout:3*time.Second}
 return s.ListenAndServe()
}
func submit(path,auth string,c *UserCommand)(int,Reply,error){
 method:="POST"
 var payload io.Reader
 if c!=nil{b,_:=json.Marshal(c);payload=bytes.NewReader(b)}
 req,e:=http.NewRequest(method,frontURL+path,payload)
 if e!=nil{return 0,Reply{},e}
 if auth!=""{req.Header.Set("Authorization","Bearer "+auth)}
 if c!=nil{req.Header.Set("Content-Type","application/json")}
 resp,e:=httpClient.Do(req);if e!=nil{return 0,Reply{},e}
 defer resp.Body.Close()
 raw,e:=io.ReadAll(io.LimitReader(resp.Body,2048))
 if e!=nil{return 0,Reply{},e}
 var r Reply
 if resp.StatusCode!=401&&resp.StatusCode!=400{
  if e=json.Unmarshal(raw,&r);e!=nil{return 0,Reply{},e}
 }
 return resp.StatusCode,r,nil
}
func probe(name string,cond bool)error{
 if !cond{return errors.New("R18_"+name+"=RED")}
 fmt.Println("R18_"+name+"=PASS")
 return nil
}
func testClient()error{
 for i:=0;i<70;i++{
  resp,e:=httpClient.Get(frontURL+"/health")
  if e==nil{_ =resp.Body.Close();if resp.StatusCode==200{break}}
  if i==69{return errors.New("gateway IP not reachable")}
  time.Sleep(100*time.Millisecond)
 }
 for _,port:=range []string{"r16-gateway:18081","r17-broker:18082","r17-broker:4444"}{
  c,e:=net.DialTimeout("tcp",port,300*time.Millisecond)
  if e==nil{c.Close();return fmt.Errorf("client crossed backend isolation: %s",port)}
 }
 fmt.Println("R18_UNTRUSTED_CLIENT_CANNOT_CONNECT_R16_R17_OR_RAW_QMP=PASS")
 c:=UserCommand{Actor:"human-a",Guest:"linux-vm",Mission:"synthetic"}
 status,_,e:=submit("/v1/claim","",&c)
 if e!=nil{return e}
 if e=probe("UNAUTHENTICATED_CLAIM_DENIED",status==401);e!=nil{return e}
 status,ans,e:=submit("/v1/claim",userToken,&c)
 if e!=nil{return e}
 if e=probe("R16_AND_R17_BOTH_REQUIRED_TO_CLAIM",status==200&&ans.Accepted);e!=nil{return e}
 competing:=UserCommand{Actor:"agent-b",Guest:"windows-vm",Mission:"synthetic"}
 status,_,e=submit("/v1/claim",userToken,&competing)
 if e!=nil{return e}
 if e=probe("COMPETING_GUEST_FOCUS_DENIED",status==403);e!=nil{return e}
 in:=c;in.Kind="key-a";in.Down=true
 status,_,e=submit("/v1/input",userToken,&in)
 if e!=nil||status!=200{return errors.New("remote key down failed")}
 in.Down=false
 status,_,e=submit("/v1/input",userToken,&in)
 if e!=nil||status!=200{return errors.New("remote key up failed")}
 fmt.Println("R18_AUTHORIZED_REMOTE_QMP_KEY_DOWN_UP=PASS")
 bad:=competing;bad.Kind="key-a";bad.Down=true
 status,_,e=submit("/v1/input",userToken,&bad)
 if e!=nil{return e}
 if e=probe("WRONG_ACTOR_GUEST_SCOPE_DENIED",status==403);e!=nil{return e}
 status,_,e=submit("/test/revoke-hub",userToken,nil)
 if e!=nil{return e}
 if e=probe("UNAUTHORIZED_HUB_REVOKE_DENIED",status==401);e!=nil{return e}
 status,_,e=submit("/test/revoke-hub",ownerToken,nil)
 if e!=nil||status!=200{return errors.New("independent R16 owner revoke failed")}
 in.Down=true
 status,_,e=submit("/v1/input",userToken,&in)
 if e!=nil{return e}
 if e=probe("EXTERNAL_HUB_REVOKE_PREVENTED_FURTHER_QMP",status==403);e!=nil{return e}
 status,_,e=submit("/v1/claim",userToken,&competing)
 if e!=nil||status!=200{return errors.New("new owner claim after R16 revoke denied")}
 status,_,e=submit("/v1/revoke",ownerToken,nil)
 if e!=nil||status!=200{return errors.New("coordinated R16/R17 revoke denied")}
 bad=competing;bad.Kind="button-left";bad.Down=true
 status,_,e=submit("/v1/input",userToken,&bad)
 if e!=nil{return e}
 if e=probe("STALE_CLIENT_INPUT_AFTER_COORDINATED_REVOKE_DENIED",status==403);e!=nil{return e}
 fmt.Println("R18_SYNTHETIC_POLICY_GATED_HUB_TO_QMP_INTEGRATION=PASS")
 fmt.Println("R18_TRUE_USBIP_URB_AND_IN_GUEST_USB_EVENTS=NOT_TESTED")
 fmt.Println("R18_STRONG_ATOMIC_CROSS_BROKER_REVOCATION=NOT_TESTED")
 return nil
}
func main(){
 var err error
 if role=="gateway"{err=serve()}else if role=="client"{err=testClient()}else{err=errors.New("unknown role")}
 if err!=nil{fmt.Fprintln(os.Stderr,"R18_RESULT=RED",err);os.Exit(1)}
}
