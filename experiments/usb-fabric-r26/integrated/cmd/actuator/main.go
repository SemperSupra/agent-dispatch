// R26-L2 synthetic sole-QMP actuator: the frontend has only this Unix socket.
// No REST listener, network authentication, privileged device access or
// distributed fencing is implemented here. Only a trusted per-host service
// should ever be allowed to start this process in a production design.
package main

import (
 "bufio"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "net"
 "os"
 "strings"
 "sync"
 "time"

 blue "example.org/usb-fabric-r26-integrated/blue"
 heldledger "example.org/usb-fabric-r26-integrated/heldledger"
)
type qmp struct {
 mu sync.Mutex
 conn net.Conn
 enc *json.Encoder
 dec *json.Decoder
}
func openQMP(path string)(*qmp,error){
 var conn net.Conn;var err error
 for i:=0;i<150;i++{
  conn,err=net.DialTimeout("unix",path,500*time.Millisecond)
  if err==nil{break}
  time.Sleep(40*time.Millisecond)
 }
 if err!=nil{return nil,err}
 q:=&qmp{conn:conn,enc:json.NewEncoder(conn),dec:json.NewDecoder(conn)}
 _=conn.SetDeadline(time.Now().Add(10*time.Second))
 var greet map[string]json.RawMessage
 if err=q.dec.Decode(&greet);err!=nil{conn.Close();return nil,err}
 if _,ok:=greet["QMP"];!ok{conn.Close();return nil,errors.New("QMP greeting absent")}
 if err=q.call("qmp_capabilities",nil);err!=nil{conn.Close();return nil,err}
 return q,nil
}
func (q *qmp) call(name string,args map[string]any)error{
 q.mu.Lock();defer q.mu.Unlock()
 _=q.conn.SetDeadline(time.Now().Add(10*time.Second))
 msg:=map[string]any{"execute":name}
 if args!=nil{msg["arguments"]=args}
 if err:=q.enc.Encode(msg);err!=nil{return err}
 for i:=0;i<150;i++{
  var response map[string]json.RawMessage
  if err:=q.dec.Decode(&response);err!=nil{return err}
  if _,ok:=response["event"];ok{continue}
  if e,ok:=response["error"];ok{return fmt.Errorf("QMP %s: %s",name,string(e))}
  if _,ok:=response["return"];ok{return nil}
  return errors.New("QMP response missing return")
 }
 return errors.New("QMP response limit")
}
type executor struct {
 q *qmp
 journal heldledger.Store
 mu sync.Mutex
}
func (e *executor) qmpKey(down bool)error {
 return e.q.call("input-send-event",map[string]any{"events":[]any{
  map[string]any{"type":"key","data":map[string]any{
   "down":down,"key":map[string]any{"type":"qcode","data":"a"},
  }},
 }})
}
// Held=true is fsynced BEFORE a potentially effective QMP keydown.
// Held=false is fsynced ONLY AFTER successful QMP key-up ACK.
// A partial failure preserves held=true for emergency restart recovery.
func (e *executor) Input(command string)error {
 e.mu.Lock();defer e.mu.Unlock()
 switch command {
 case "key-a-down":
  state,err:=e.journal.Read()
  if err!=nil{return err}
  if state.Held{return blue.ErrDenied}
  if _,err=e.journal.Transition(state.Sequence,true);err!=nil{return err}
  return e.qmpKey(true)
 case "key-a-up":
  if err:=e.qmpKey(false);err!=nil{return err}
  state,err:=e.journal.Read()
  if err!=nil{return err}
  if state.Held {
   _,err=e.journal.Transition(state.Sequence,false)
   return err
  }
  return nil
 default:return blue.ErrDenied
 }
}
func (e *executor) ReleaseAll()error{return e.Input("key-a-up")}

type request struct{
 Op string `json:"op"`
 Actor string `json:"actor"`
 Epoch string `json:"epoch"`
 Generation uint64 `json:"generation"`
 Command string `json:"command"`
}
type response struct{
 OK bool `json:"ok"`
 Error string `json:"error,omitempty"`
 State blue.State `json:"state,omitempty"`
 Epoch string `json:"epoch,omitempty"`
 Generation uint64 `json:"generation,omitempty"`
}
type actuator struct{
 m *blue.Manager
 q *qmp
 media,pcap string
 attachMu sync.Mutex
 devicesAttached,vmStarted bool
}
func (a *actuator) attach()error {
 a.attachMu.Lock();defer a.attachMu.Unlock()
 if a.devicesAttached{return nil}
 commands:=[]struct{name string;args map[string]any}{
  {"device_add",map[string]any{"driver":"usb-kbd","id":"r26-l-kbd","bus":"xhci0.0","pcap":a.pcap}},
  {"device_add",map[string]any{"driver":"usb-tablet","id":"r26-l-tablet","bus":"xhci0.0"}},
  {"blockdev-add",map[string]any{"driver":"file","filename":a.media,"node-name":"r26-l-file","read-only":true}},
  {"blockdev-add",map[string]any{"driver":"raw","file":"r26-l-file","node-name":"r26-l-raw","read-only":true}},
  {"device_add",map[string]any{"driver":"usb-storage","id":"r26-l-storage","drive":"r26-l-raw","bus":"xhci0.0"}},
 }
 for _,c:=range commands{
  if err:=a.q.call(c.name,c.args);err!=nil{
   a.m.Offline()
   return err
  }
 }
 a.devicesAttached=true
 return nil
}
func (a *actuator) start()error{
 a.attachMu.Lock();defer a.attachMu.Unlock()
 if a.vmStarted{return nil}
 if err:=a.q.call("cont",nil);err!=nil{
  a.m.Offline()
  return err
 }
 a.vmStarted=true
 return nil
}
func (a *actuator) handle(c net.Conn){
 defer c.Close()
 reader:=json.NewDecoder(bufio.NewReader(c))
 writer:=bufio.NewWriter(c)
 write:=func(r response){
  b,_:=json.Marshal(r)
  fmt.Fprintln(writer,string(b))
  _=writer.Flush()
 }
 var held blue.Lease
 defer func(){
  if held.Generation!=0{
   if err:=a.m.Revoke(held);err!=nil{
    fmt.Fprintln(os.Stderr,"R26_L_RELEASE_FAILURE_QUARANTINE=RED",err)
   }else{
    fmt.Println("R26_L_ACTUATOR_CLIENT_LOSS_RELEASE_ACCEPTED=PASS")
   }
  }
 }()
 for {
  _=c.SetReadDeadline(time.Now().Add(90*time.Second))
  var req request
  if err:=reader.Decode(&req);err!=nil{return}
  // The fixed actor is a synthetic test selector, NOT authentication.
  if req.Actor!="approved-agent" {
   write(response{Error:"actor denied"});continue
  }
  if req.Op=="reserve"{
   if held.Generation!=0{write(response{Error:"connection already has lease"});continue}
   l,err:=a.m.Reserve(req.Actor,"keyboard","xhci0/auto")
   if err!=nil{write(response{Error:err.Error()});continue}
   held=l
   write(response{OK:true,State:blue.Reserved,Epoch:l.Epoch,Generation:l.Generation})
   continue
  }
  wanted:=blue.Lease{Device:"keyboard",Port:"xhci0/auto",Actor:req.Actor,Epoch:req.Epoch,Generation:req.Generation}
  if held.Generation==0 || wanted!=held {
   write(response{Error:"missing or stale connection lease"});continue
  }
  var err error
  switch req.Op{
  case "attach":
   err=a.m.Attach(held)
   if err==nil{err=a.attach()}
  case "start":
   state,active,_:=a.m.Snapshot()
   if state!=blue.Attached || active!=held{err=blue.ErrDenied}else{err=a.start()}
  case "input":
   if req.Command!="key-a-down" && req.Command!="key-a-up" {
    err=blue.ErrDenied
   }else{err=a.m.Input(held,req.Command)}
  case "revoke":
   err=a.m.Revoke(held)
   if err==nil{held=blue.Lease{}}
  default:
   err=blue.ErrDenied
  }
  if err!=nil{write(response{Error:err.Error()});continue}
  state,_,_:=a.m.Snapshot()
  write(response{OK:true,State:state})
 }
}
func main(){
 qmpPath:=flag.String("qmp","","QEMU local QMP Unix socket; never passed to clients")
 socketPath:=flag.String("socket","","new owned frontend Unix socket")
 media:=flag.String("media","","synthetic media path")
 pcap:=flag.String("capture","","synthetic USB capture path")
 journalPath:=flag.String("journal","","host-local fsynced key state path")
 flag.Parse()
 if *qmpPath==""||*socketPath==""||*media==""||*pcap==""||*journalPath==""{
  fmt.Fprintln(os.Stderr,"missing QMP/socket/media/capture/journal");os.Exit(2)
 }
 q,err:=openQMP(*qmpPath)
 if err!=nil{fmt.Fprintln(os.Stderr,"QMP unavailable:",err);os.Exit(3)}
 defer q.conn.Close()
 journal:=heldledger.Store{Path:*journalPath}
 recovered,err:=journal.Read()
 if err!=nil{
  fmt.Fprintln(os.Stderr,"R26_L3_CORRUPT_JOURNAL_QUARANTINE=RED",err)
  os.Exit(8)
 }
 ex:=&executor{q:q,journal:journal}
 if recovered.Held {
  if err:=ex.ReleaseAll();err!=nil{
   fmt.Fprintln(os.Stderr,"R26_L3_RECOVERY_RELEASE_FAILED_QUARANTINE=RED",err)
   os.Exit(9)
  }
  fmt.Println("R26_L3_ACTUATOR_RESTART_FORCED_QMP_KEY_UP=PASS")
  fmt.Println("R26_L3_RECOVERY_HOLD_REQUIRES_TOPOLOGY_RECONCILIATION=PASS")
  // Stop here: journal recovery alone must never admit a fresh lease when
  // previous guest device attachments are still un-reconciled.
  return
 }
 if _,err=os.Lstat(*socketPath);err==nil{
  fmt.Fprintln(os.Stderr,"refusing existing socket path");os.Exit(4)
 }else if !errors.Is(err,os.ErrNotExist){fmt.Fprintln(os.Stderr,err);os.Exit(4)}
 listener,err:=net.Listen("unix",*socketPath)
 if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(5)}
 defer listener.Close()
 defer os.Remove(*socketPath)
 if err=os.Chmod(*socketPath,0600);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(6)}
 a:=&actuator{m:blue.New("keyboard","xhci0/auto",ex),q:q,media:*media,pcap:*pcap}
 fmt.Println("R26_L_SOLE_QMP_ACTUATOR_LISTENING=PASS")
 for {
  c,err:=listener.Accept()
  if err!=nil{fmt.Fprintln(os.Stderr,"accept:",err);os.Exit(7)}
  go a.handle(c)
 }
}
