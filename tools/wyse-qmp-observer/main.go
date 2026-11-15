// wyse-vm-observer is a read-only QMP observer. The program cannot
// execute device_add, blockdev-add, reset, guest-exec or any other mutation.
package main

import (
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "net"
 "os"
 "time"
)
type Message struct {
 QMP json.RawMessage `json:"QMP"`
 Return json.RawMessage `json:"return"`
 Error json.RawMessage `json:"error"`
 Event string `json:"event"`
 ID string `json:"id"`
}
type Result struct{
 Query string `json:"query"`
 Supported bool `json:"supported"`
 Data json.RawMessage `json:"data,omitempty"`
}
type Receipt struct{
 Schema string `json:"schema"`
 QMPReadOnly bool `json:"qmp_read_only"`
 PhysicalTPMExposed bool `json:"physical_tpm_exposed"`
 Metrics []Result `json:"metrics"`
 Limitations []string `json:"limitations"`
}
var allowedQueries=[]string{
 "query-status","query-cpus-fast","query-memory-size-summary",
 "query-blockstats","query-tpm","query-pci",
}
func readResponse(d *json.Decoder,id string)(Message,error){
 for i:=0;i<20;i++{
  var msg Message
  if err:=d.Decode(&msg);err!=nil{return msg,err}
  if msg.Event!=""{continue}
  if msg.ID==id{return msg,nil}
 }
 return Message{},errors.New("no matching QMP response")
}
func Observe(socket string) (Receipt,error) {
 r:=Receipt{Schema:"wyse-vm-host-observer/v1",QMPReadOnly:true,Metrics:[]Result{},Limitations:[]string{
  "QMP data is host-observed resource state, not readable encrypted guest memory contents",
  "GPU utilization requires host DRM/driver metrics and passthrough-specific qualification",
  "Traffic counters and denied flows require host tap/nftables/eBPF metrics outside QMP",
  "vTPM state is distinct from physical host TPM; never give physical TPM to guest",
  "Bare-metal runtime cannot be observed by a stopped local recovery host",
 }}
 c,err:=net.DialTimeout("unix",socket,3*time.Second);if err!=nil{return r,err}
 defer c.Close()
 if err=c.SetDeadline(time.Now().Add(10*time.Second));err!=nil{return r,err}
 dec:=json.NewDecoder(io.LimitReader(c,3<<20));enc:=json.NewEncoder(c)
 var greeting Message
 if err=dec.Decode(&greeting);err!=nil{return r,err}
 if len(greeting.QMP)==0{return r,errors.New("not a QMP socket")}
 if err=enc.Encode(map[string]any{"execute":"qmp_capabilities","id":"hello"});err!=nil{return r,err}
 hand,err:=readResponse(dec,"hello")
 if err!=nil||len(hand.Error)!=0{return r,errors.New("QMP capability negotiation failed")}
 for _,name:=range allowedQueries {
  if err=enc.Encode(map[string]any{"execute":name,"id":name});err!=nil{return r,err}
  msg,e:=readResponse(dec,name)
  if e!=nil{return r,e}
  result:=Result{Query:name,Supported:len(msg.Error)==0,Data:msg.Return}
  if !result.Supported{result.Data=nil}
  r.Metrics=append(r.Metrics,result)
 }
 return r,nil
}
func main(){
 path:=flag.String("qmp-socket","","locally protected QMP Unix socket")
 flag.Parse()
 if *path==""{fmt.Fprintln(os.Stderr,"usage: wyse-vm-observer -qmp-socket /run/private/qmp.sock");os.Exit(2)}
 r,err:=Observe(*path);if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 if err=json.NewEncoder(os.Stdout).Encode(r);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
