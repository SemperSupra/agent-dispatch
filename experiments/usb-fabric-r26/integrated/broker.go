package main

// Public synthetic integration: a separate host-local Go process owns QMP.
// The JSON-line stdin protocol is a test interface, not an authenticated or
// network-hardened product API. No raw QMP is exposed through this interface.
import (
 "bufio"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "net"
 "os"
 "strings"
 "time"

 blue "example.org/usb-fabric-r26-integrated/blue"
)

type qmp struct {
 conn net.Conn
 enc *json.Encoder
 dec *json.Decoder
}

func dial(path string) (*qmp,error) {
 var conn net.Conn
 var err error
 for i:=0;i<100;i++{
  conn,err=net.DialTimeout("unix",path,500*time.Millisecond)
  if err==nil{break}
  time.Sleep(50*time.Millisecond)
 }
 if err!=nil{return nil,err}
 q:=&qmp{conn:conn,enc:json.NewEncoder(conn),dec:json.NewDecoder(conn)}
 var greet map[string]json.RawMessage
 if err=q.dec.Decode(&greet);err!=nil{conn.Close();return nil,err}
 if _,ok:=greet["QMP"];!ok{conn.Close();return nil,errors.New("QMP greeting absent")}
 if _,err=q.call("qmp_capabilities",nil);err!=nil{conn.Close();return nil,err}
 return q,nil
}
func (q *qmp) call(name string,args map[string]any)(map[string]any,error){
 q.conn.SetDeadline(time.Now().Add(12*time.Second))
 msg:=map[string]any{"execute":name}
 if args!=nil{msg["arguments"]=args}
 if err:=q.enc.Encode(msg);err!=nil{return nil,err}
 for i:=0;i<100;i++{
  var v map[string]json.RawMessage
  if err:=q.dec.Decode(&v);err!=nil{return nil,err}
  if _,ok:=v["event"];ok{continue}
  if e,ok:=v["error"];ok{return nil,fmt.Errorf("QMP %s: %s",name,string(e))}
  r,ok:=v["return"];if !ok{return nil,fmt.Errorf("QMP %s missing return",name)}
  var out map[string]any
  if len(r)>0 && string(r)!="{}" && string(r)!="null"{
   // Scalar/array result does not alter a successful command.
   _=json.Unmarshal(r,&out)
  }
  return out,nil
 }
 return nil,errors.New("too many QMP events")
}

type executor struct {q *qmp}
func (e *executor) Input(command string)error {
 switch command{
 case "key-a-down","key-a-up":
  down:=strings.HasSuffix(command,"down")
  _,err:=e.q.call("input-send-event",map[string]any{"events":[]any{
   map[string]any{"type":"key","data":map[string]any{
    "down":down,"key":map[string]any{"type":"qcode","data":"a"},
   }},
  }})
  return err
 default:return blue.ErrDenied
 }
}
func (e *executor) ReleaseAll()error {
 return e.Input("key-a-up")
}

type request struct {
 Op string `json:"op"`
 Actor string `json:"actor"`
 Generation uint64 `json:"generation"`
 Epoch string `json:"epoch"`
 Command string `json:"command"`
}
type response struct {
 OK bool `json:"ok"`
 Generation uint64 `json:"generation,omitempty"`
 Epoch string `json:"epoch,omitempty"`
 State blue.State `json:"state,omitempty"`
 Error string `json:"error,omitempty"`
}
func main(){
 path:=flag.String("qmp","","local QMP socket")
 media:=flag.String("media","","synthetic backing file")
 capture:=flag.String("capture","","synthetic QEMU USB pcap")
 flag.Parse()
 if *path==""||*media==""||*capture==""{fmt.Fprintln(os.Stderr,"missing local QMP, media or capture");os.Exit(2)}
 q,err:=dial(*path)
 if err!=nil{fmt.Fprintln(os.Stderr,"QMP unavailable:",err);os.Exit(3)}
 defer q.conn.Close()
 e:=&executor{q:q}
 m:=blue.New("keyboard","xhci0/auto",e)
 out:=bufio.NewWriter(os.Stdout)
 emit:=func(r response){b,_:=json.Marshal(r);fmt.Fprintln(out,string(b));out.Flush()}
 emit(response{OK:true,State:"ready"})
 scanner:=bufio.NewScanner(os.Stdin)
 scanner.Buffer(make([]byte,1024),65536)
 for scanner.Scan(){
  var req request
  if err:=json.Unmarshal(scanner.Bytes(),&req);err!=nil{emit(response{Error:"invalid request"});continue}
  state,active,_:=m.Snapshot()
  l:=blue.Lease{Device:"keyboard",Port:"xhci0/auto",Actor:req.Actor,Epoch:req.Epoch,Generation:req.Generation}
  if req.Op=="reserve"{
   if req.Actor!="approved-agent"{emit(response{Error:"actor denied"});continue}
   lease,e:=m.Reserve(req.Actor,"keyboard","xhci0/auto")
   if e!=nil{emit(response{Error:e.Error()});continue}
   emit(response{OK:true,Generation:lease.Generation,Epoch:lease.Epoch,State:blue.Reserved});continue
  }
  var runErr error
  switch req.Op{
  case "attach":
   runErr=m.Attach(l)
   if runErr==nil {
    cmds:=[]struct{name string;args map[string]any}{
     {"device_add",map[string]any{"driver":"usb-kbd","id":"r26-int-key","bus":"xhci0.0","pcap":*capture}},
     {"device_add",map[string]any{"driver":"usb-tablet","id":"r26-int-tablet","bus":"xhci0.0"}},
     {"blockdev-add",map[string]any{"driver":"file","filename":*media,"node-name":"r26-int-file","read-only":true}},
     {"blockdev-add",map[string]any{"driver":"raw","file":"r26-int-file","node-name":"r26-int-raw","read-only":true}},
     {"device_add",map[string]any{"driver":"usb-storage","id":"r26-int-disk","drive":"r26-int-raw","bus":"xhci0.0"}},
    }
    for _,c:=range cmds{if _,runErr=q.call(c.name,c.args);runErr!=nil{m.Offline();break}}
   }
  case "start":
   if state!=blue.Attached || req.Actor!="approved-agent" || active!=l {
    runErr=blue.ErrDenied
   }else{
    _,runErr=q.call("cont",nil)
    if runErr!=nil{m.Offline()}
   }
  case "input":
   runErr=m.Input(l,req.Command)
  case "revoke":
   runErr=m.Revoke(l)
  case "snapshot":
   if req.Actor!="approved-agent"{runErr=blue.ErrDenied}
  default:
   runErr=blue.ErrDenied
  }
  if runErr!=nil{emit(response{Error:runErr.Error()});continue}
  s,_,_:=m.Snapshot()
  emit(response{OK:true,State:s})
 }
 if scanner.Err()!=nil {fmt.Fprintln(os.Stderr,"broker input:",scanner.Err());os.Exit(5)}
}
