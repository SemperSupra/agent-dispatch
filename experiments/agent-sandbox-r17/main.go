// R17: a disposable Linux QMP HID adapter with a separate management client.
// Public synthetic tokens, commands, and an empty TCG VM: not a production
// issuer, hostile-guest sandbox, USB/IP URB bridge or guest HID event proof.
package main

import (
 "bufio"
 "bytes"
 "crypto/rand"
 "crypto/subtle"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "os"
 "os/exec"
 "strings"
 "sync"
 "time"
)

const (
 socket = "/tmp/r17-qmp.sock"
 controlToken = "r17-synthetic-control-only"
 ownerToken = "r17-synthetic-owner-only"
 serviceURL = "http://r17-broker:18082"
)
var role = "unset"

type QMP struct {
 sock net.Conn
 rd *bufio.Reader
 mu sync.Mutex
}
func (q *QMP) read() (map[string]json.RawMessage,error) {
 for i:=0;i<1000;i++{
  line,e:=q.rd.ReadBytes('\n')
  if e!=nil{return nil,e}
  var msg map[string]json.RawMessage
  if e=json.Unmarshal(line,&msg);e!=nil{return nil,e}
  if _,isEvent:=msg["event"];isEvent{continue}
  return msg,nil
 }
 return nil,errors.New("QMP event flood")
}
func (q *QMP) call(name string,args any) (json.RawMessage,error) {
 q.mu.Lock();defer q.mu.Unlock()
 cmd:=map[string]any{"execute":name}
 if args!=nil{cmd["arguments"]=args}
 b,e:=json.Marshal(cmd)
 if e!=nil{return nil,e}
 b=append(b,'\n')
 if _,e=q.sock.Write(b);e!=nil{return nil,e}
 r,e:=q.read()
 if e!=nil{return nil,e}
 if raw,ok:=r["error"];ok{return nil,fmt.Errorf("QMP %s: %s",name,string(raw))}
 if raw,ok:=r["return"];ok{return raw,nil}
 return nil,errors.New("QMP missing return")
}
func openQMP(path string,proc *exec.Cmd)(*QMP,error){
 for i:=0;i<100;i++{
  conn,e:=net.DialTimeout("unix",path,time.Second)
  if e==nil {
   _=conn.SetDeadline(time.Now().Add(60*time.Second))
   q:=&QMP{sock:conn,rd:bufio.NewReader(conn)}
   hi,e:=q.read()
   if e!=nil{conn.Close();return nil,e}
   if _,ok:=hi["QMP"];!ok{conn.Close();return nil,errors.New("invalid QMP greeting")}
   if _,e=q.call("qmp_capabilities",nil);e!=nil{conn.Close();return nil,e}
   _=conn.SetDeadline(time.Time{})
   return q,nil
  }
  if proc.ProcessState!=nil{return nil,errors.New("QEMU ended before local QMP")}
  time.Sleep(70*time.Millisecond)
 }
 return nil,errors.New("local-only QMP unavailable")
}
func makeEvent(kind string,down bool) map[string]any {
 if kind=="key-a" {
  return map[string]any{"events":[]any{map[string]any{
   "type":"key","data":map[string]any{"down":down,
    "key":map[string]any{"type":"qcode","data":"a"}}}}}
 }
 return map[string]any{"events":[]any{map[string]any{
  "type":"btn","data":map[string]any{"down":down,"button":"left"}}}}
}
type Command struct{
 Actor string `json:"actor"`
 Guest string `json:"guest"`
 Mission string `json:"mission"`
 Lease string `json:"lease"`
 Generation uint64 `json:"generation"`
 TTLSeconds int `json:"ttl_seconds"`
 Kind string `json:"kind"`
 Down bool `json:"down"`
}
type Reply struct{
 Accepted bool `json:"accepted"`
 Reason string `json:"reason,omitempty"`
 Lease string `json:"lease,omitempty"`
 Generation uint64 `json:"generation"`
 Held bool `json:"held"`
 KeyDown bool `json:"key_down"`
 ButtonDown bool `json:"button_down"`
}
type Broker struct {
 mu sync.Mutex
 q *QMP
 generation uint64
 actor,guest,mission,lease string
 expires time.Time
 keyDown,buttonDown bool
 unsafe bool
}
func allowedLabel(s string)bool{
 if len(s)==0||len(s)>64{return false}
 for _,c:=range s{
  if !((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'){return false}
 }
 return true
}
func newLease()(string,error){
 var b[16]byte
 if _,err:=rand.Read(b[:]);err!=nil{return "",err}
 return hex.EncodeToString(b[:]),nil
}
func (b *Broker) snapshot(accepted bool,why,lease string)Reply{
 return Reply{Accepted:accepted,Reason:why,Lease:lease,Generation:b.generation,
  Held:b.lease!="",KeyDown:b.keyDown,ButtonDown:b.buttonDown}
}
func (b *Broker) releaseKeys(reason string)error{
 if b.keyDown {
  if _,e:=b.q.call("input-send-event",makeEvent("key-a",false));e!=nil{b.unsafe=true;return e}
  b.keyDown=false
 }
 if b.buttonDown{
  if _,e:=b.q.call("input-send-event",makeEvent("button-left",false));e!=nil{b.unsafe=true;return e}
  b.buttonDown=false
 }
 if reason=="revoke"{fmt.Println("R17_QMP_RELEASE_ON_OWNER_REVOKE_SUBMITTED=PASS")}
 if reason=="expire"{fmt.Println("R17_QMP_RELEASE_ON_EXPIRY_SUBMITTED=PASS")}
 return nil
}
func (b *Broker) expireLocked(now time.Time){
 if b.lease!="" && !now.Before(b.expires){
  if e:=b.releaseKeys("expire");e!=nil{
   fmt.Fprintln(os.Stderr,"R17_RELEASE_FAILURE_FAIL_CLOSED",e)
   return
  }
  b.actor="";b.guest="";b.mission="";b.lease=""
  b.expires=time.Time{};b.generation++
 }
}
func (b *Broker) apply(path string,c Command,owner bool)Reply{
 b.mu.Lock();defer b.mu.Unlock()
 b.expireLocked(time.Now())
 if b.unsafe{return b.snapshot(false,"QMP_RELEASE_FAILURE_FAIL_CLOSED","")}
 if c.Generation!=b.generation{return b.snapshot(false,"stale_generation","")}
 if path=="/v1/revoke"{
  if !owner{return b.snapshot(false,"owner_grant_required","")}
  if e:=b.releaseKeys("revoke");e!=nil{return b.snapshot(false,"QMP_release_failed","")}
  b.actor="";b.guest="";b.mission="";b.lease=""
  b.generation++;b.expires=time.Time{}
  return b.snapshot(true,"","")
 }
 if !allowedLabel(c.Actor)||!allowedLabel(c.Guest)||!allowedLabel(c.Mission){
  return b.snapshot(false,"invalid_identity_scope","")
 }
 if path=="/v1/claim"{
  if b.lease!=""{return b.snapshot(false,"exclusive_focus_held","")}
  if c.TTLSeconds<1||c.TTLSeconds>6{return b.snapshot(false,"invalid_ttl","")}
  token,e:=newLease();if e!=nil{return b.snapshot(false,"nonce_error","")}
  b.actor=c.Actor;b.guest=c.Guest;b.mission=c.Mission;b.lease=token
  b.expires=time.Now().Add(time.Duration(c.TTLSeconds)*time.Second)
  b.generation++
  return b.snapshot(true,"",token)
 }
 if b.lease==""||len(c.Lease)!=len(b.lease)||
   subtle.ConstantTimeCompare([]byte(c.Lease),[]byte(b.lease))!=1||
   c.Actor!=b.actor||c.Guest!=b.guest||c.Mission!=b.mission{
  return b.snapshot(false,"invalid_lease_or_scope","")
 }
 if path=="/v1/release"{
  if e:=b.releaseKeys("release");e!=nil{return b.snapshot(false,"QMP_release_failed","")}
  b.actor="";b.guest="";b.mission="";b.lease=""
  b.expires=time.Time{};b.generation++
  return b.snapshot(true,"","")
 }
 if path=="/v1/input"{
  if c.Kind!="key-a"&&c.Kind!="button-left"{return b.snapshot(false,"disallowed_input_kind","")}
  if _,e:=b.q.call("input-send-event",makeEvent(c.Kind,c.Down));e!=nil{
   b.unsafe=true
   return b.snapshot(false,"QMP_input_failed_closed","")
  }
  if c.Kind=="key-a"{b.keyDown=c.Down}else{b.buttonDown=c.Down}
  b.generation++
  return b.snapshot(true,"","")
 }
 return b.snapshot(false,"unknown_command","")
}
func auth(r *http.Request,expected string)bool{
 got:=r.Header.Get("Authorization")
 want:="Bearer "+expected
 return len(got)==len(want)&&subtle.ConstantTimeCompare([]byte(got),[]byte(want))==1
}
func (b *Broker) handler()http.Handler{
 mux:=http.NewServeMux()
 mux.HandleFunc("/health",func(w http.ResponseWriter,r *http.Request){
  if r.Method!="GET"{http.Error(w,"method",405);return}
  fmt.Fprint(w,"R17_QMP_BROKER_HEALTH")
 })
 mux.HandleFunc("/v1/status",func(w http.ResponseWriter,r *http.Request){
  if !auth(r,controlToken)&&!auth(r,ownerToken){http.Error(w,"unauthorized",401);return}
  if r.Method!="GET"{http.Error(w,"method",405);return}
  b.mu.Lock();b.expireLocked(time.Now());ans:=b.snapshot(true,"","");b.mu.Unlock()
  w.Header().Set("Content-Type","application/json")
  _=json.NewEncoder(w).Encode(ans)
 })
 for _,path:=range []string{"/v1/claim","/v1/input","/v1/release","/v1/revoke"}{
  route:=path
  mux.HandleFunc(route,func(w http.ResponseWriter,r *http.Request){
   isOwner:=auth(r,ownerToken)
   if !isOwner&&!auth(r,controlToken){http.Error(w,"unauthorized",401);return}
   if r.Method!="POST"{http.Error(w,"method",405);return}
   r.Body=http.MaxBytesReader(w,r.Body,4096)
   dec:=json.NewDecoder(r.Body)
   dec.DisallowUnknownFields()
   var cmd Command
   if dec.Decode(&cmd)!=nil{http.Error(w,"bad_json",400);return}
   var other any
   if dec.Decode(&other)!=io.EOF{http.Error(w,"trailing_data",400);return}
   ans:=b.apply(route,cmd,isOwner)
   w.Header().Set("Content-Type","application/json")
   if !ans.Accepted{w.WriteHeader(403)}
   _=json.NewEncoder(w).Encode(ans)
  })
 }
 return mux
}
func serve()error{
 _=os.Remove(socket)
 cmd:=exec.Command("qemu-system-x86_64",
  "-machine","q35","-cpu","qemu64","-accel","tcg",
  "-m","128M","-smp","1","-S","-nodefaults",
  "-display","none","-monitor","none","-serial","none","-net","none",
  "-device","qemu-xhci,id=xhci0",
  "-qmp","unix:"+socket+",server=on,wait=off")
 cmd.Stderr=os.Stderr
 if e:=cmd.Start();e!=nil{return e}
 defer func(){if cmd.Process!=nil{_ =cmd.Process.Kill();_ =cmd.Wait()}}()
 q,e:=openQMP(socket,cmd)
 if e!=nil{return e}
 defer q.sock.Close()
 var status struct{Running bool `json:"running"`}
 raw,e:=q.call("query-status",nil);if e!=nil{return e}
 if e=json.Unmarshal(raw,&status);e!=nil{return e}
 if status.Running{return errors.New("QMP initial VM not paused")}
 for _,dev:=range []map[string]any{
  {"driver":"usb-kbd","id":"r17kbd","bus":"xhci0.0"},
  {"driver":"usb-tablet","id":"r17tablet","bus":"xhci0.0"},
 }{
  if _,e=q.call("device_add",dev);e!=nil{return e}
 }
 var devices []struct{Name string `json:"name"`}
 raw,e=q.call("qom-list",map[string]string{"path":"/machine/peripheral"})
 if e!=nil{return e}
 if e=json.Unmarshal(raw,&devices);e!=nil{return e}
 present:=map[string]bool{}
 for _,d:=range devices{present[d.Name]=true}
 if !present["r17kbd"]||!present["r17tablet"]{return errors.New("guest-facing USB HID devices absent from host QOM")}
 if _,e=q.call("cont",nil);e!=nil{return e}
 raw,e=q.call("query-status",nil);if e!=nil{return e}
 if e=json.Unmarshal(raw,&status);e!=nil{return e}
 if !status.Running{return errors.New("QEMU VM did not start")}
 fmt.Println("R17_LOCAL_QMP_XHCI_HID_TOPOLOGY_AND_RUNNING_VM=PASS")
 b:=&Broker{q:q,generation:1}
 go func(){
  tick:=time.NewTicker(100*time.Millisecond)
  defer tick.Stop()
  for range tick.C {
   b.mu.Lock();b.expireLocked(time.Now());b.mu.Unlock()
  }
 }()
 server:=&http.Server{Addr:":18082",Handler:b.handler(),ReadHeaderTimeout:3*time.Second}
 fmt.Println("R17_LINUX_MANAGEMENT_IP_API_READY=PASS")
 return server.ListenAndServe()
}
func clientCall(hc *http.Client,path,token string,c *Command)(int,Reply,error){
 method:="GET"
 var data io.Reader
 if c!=nil{
  method="POST"
  b,_:=json.Marshal(c);data=bytes.NewReader(b)
 }
 req,e:=http.NewRequest(method,serviceURL+path,data);if e!=nil{return 0,Reply{},e}
 if token!=""{req.Header.Set("Authorization","Bearer "+token)}
 if c!=nil{req.Header.Set("Content-Type","application/json")}
 resp,e:=hc.Do(req);if e!=nil{return 0,Reply{},e}
 defer resp.Body.Close()
 raw,e:=io.ReadAll(io.LimitReader(resp.Body,4096));if e!=nil{return 0,Reply{},e}
 var reply Reply
 if resp.StatusCode!=401&&resp.StatusCode!=405&&resp.StatusCode!=400 {
  if e=json.Unmarshal(raw,&reply);e!=nil{return 0,Reply{},e}
 }
 return resp.StatusCode,reply,nil
}
func require(cond bool,name string)error{
 if !cond{return errors.New(name)}
 fmt.Println(name+"=PASS")
 return nil
}
func testClient()error{
 hc:=&http.Client{Timeout:4*time.Second}
 for i:=0;i<45;i++{
  r,e:=hc.Get(serviceURL+"/health")
  if e==nil{
   _=r.Body.Close()
   if r.StatusCode==200{break}
  }
  if i==44{return errors.New("linux QMP broker not reachable by IP")}
  time.Sleep(100*time.Millisecond)
 }
 code,_,e:=clientCall(hc,"/v1/status","",nil)
 if e!=nil{return e}
 if e=require(code==401,"R17_UNAUTHENTICATED_REMOTE_MANAGEMENT_DENIED");e!=nil{return e}
 code,current,e:=clientCall(hc,"/v1/status",controlToken,nil)
 if e!=nil{return e}
 if code!=200||current.Generation!=1||current.Held{return errors.New("unexpected initial QMP adapter state")}
 claim:=Command{Actor:"human-a",Guest:"linux-vm",Mission:"synthetic",Generation:1,TTLSeconds:6}
 code,leased,e:=clientCall(hc,"/v1/claim",controlToken,&claim)
 if e!=nil||code!=200||leased.Generation!=2||leased.Lease==""{return errors.New("authorized remote focus lease not issued")}
 competing:=Command{Actor:"agent-b",Guest:"windows-vm",Mission:"synthetic",Generation:2,TTLSeconds:3}
 code,_,e=clientCall(hc,"/v1/claim",controlToken,&competing)
 if e!=nil{return e}
 if e=require(code==403,"R17_EXCLUSIVE_FOCUS_LEASE_CONFLICT_DENIED");e!=nil{return e}
 in:=claim
 in.Lease=leased.Lease
 in.Generation=1
 in.Kind="key-a";in.Down=true
 code,_,e=clientCall(hc,"/v1/input",controlToken,&in)
 if e!=nil{return e}
 if e=require(code==403,"R17_STALE_GENERATION_INPUT_DENIED");e!=nil{return e}
 in.Generation=2
 code,down,e:=clientCall(hc,"/v1/input",controlToken,&in)
 if e!=nil||code!=200||!down.KeyDown||down.Generation!=3{return errors.New("remote key down not brokered")}
 in.Generation=3;in.Down=false
 code,up,e:=clientCall(hc,"/v1/input",controlToken,&in)
 if e!=nil||code!=200||up.KeyDown||up.Generation!=4{return errors.New("remote key up not brokered")}
 fmt.Println("R17_AUTHORIZED_REMOTE_KEY_DOWN_UP_QMP_ACCEPTED=PASS")
 in.Generation=4;in.Kind="button-left";in.Down=true
 code,mouse,e:=clientCall(hc,"/v1/input",controlToken,&in)
 if e!=nil||code!=200||!mouse.ButtonDown||mouse.Generation!=5{return errors.New("remote mouse down not brokered")}
 bad:=in;bad.Generation=5;bad.Kind="host.raw_qmp"
 code,_,e=clientCall(hc,"/v1/input",controlToken,&bad)
 if e!=nil{return e}
 if e=require(code==403,"R17_RAW_QMP_AND_UNRECOGNIZED_INPUT_DENIED");e!=nil{return e}
 revoke:=Command{Generation:5}
 code,_,e=clientCall(hc,"/v1/revoke",controlToken,&revoke)
 if e!=nil{return e}
 if e=require(code==403,"R17_UNAUTHORIZED_REVOKE_DENIED");e!=nil{return e}
 code,rev,e:=clientCall(hc,"/v1/revoke",ownerToken,&revoke)
 if e!=nil||code!=200||rev.Generation!=6||rev.Held||rev.ButtonDown||rev.KeyDown{return errors.New("owner revoke did not release pressed mouse")}
 fmt.Println("R17_OWNER_REVOKE_FORCES_POINTER_RELEASE=PASS")
 in.Generation=6;in.Kind="key-a"
 code,_,e=clientCall(hc,"/v1/input",controlToken,&in)
 if e!=nil{return e}
 if e=require(code==403,"R17_STALE_LEASE_AFTER_REVOKE_DENIED");e!=nil{return e}
 competing.Generation=6;competing.TTLSeconds=2
 code,released,e:=clientCall(hc,"/v1/claim",controlToken,&competing)
 if e!=nil||code!=200||released.Generation!=7{return errors.New("next tenant not granted focus")}
 press:=competing
 press.Lease=released.Lease;press.Kind="button-left";press.Down=true;press.Generation=7
 code,pressed,e:=clientCall(hc,"/v1/input",controlToken,&press)
 if e!=nil||code!=200||!pressed.ButtonDown||pressed.Generation!=8{return errors.New("next tenant mouse not pressed")}
 time.Sleep(2600*time.Millisecond)
 code,expired,e:=clientCall(hc,"/v1/status",controlToken,nil)
 if e!=nil||code!=200||expired.Held||expired.ButtonDown||expired.Generation!=9{return errors.New("expired lease did not automatically release mouse")}
 fmt.Println("R17_TTL_EXPIRY_CLEARS_GUEST_INPUT_FOCUS=PASS")
 conn,e:=net.DialTimeout("tcp","r17-broker:4444",450*time.Millisecond)
 if e==nil{_ =conn.Close();return errors.New("raw QMP unexpectedly reachable via network")}
 fmt.Println("R17_RAW_QMP_NOT_EXPOSED_OVER_IP=PASS")
 fmt.Println("R17_REAL_GUEST_EVDEV_DELIVERY=NOT_TESTED")
 fmt.Println("R17_PRODUCTION_AUTHN_AUTHZ=NOT_TESTED")
 return nil
}
func main(){
 if role=="broker"{
  if e:=serve();e!=nil{fmt.Fprintln(os.Stderr,"R17_BROKER_RED",strings.ReplaceAll(e.Error(),string(rune(10)),";"));os.Exit(1)}
  return
 }
 if role=="client"{
  if e:=testClient();e!=nil{fmt.Fprintln(os.Stderr,"R17_CLIENT_RED",strings.ReplaceAll(e.Error(),string(rune(10)),";"));os.Exit(1)}
  return
 }
 fmt.Fprintln(os.Stderr,"R17_INVALID_BINARY_ROLE");os.Exit(2)
}
