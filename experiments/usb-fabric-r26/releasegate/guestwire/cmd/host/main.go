// Disposable Linux-host guest receipt ingress. Test-only proof key is
// compiled in. This process sees guest virtio messages relayed by the isolated
// test oracle; no network, production trust store or raw QMP capability.
package main

import (
 "bufio"
 "encoding/json"
 "fmt"
 "os"

 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/evidence"
 "example.org/usb-fabric-r26-releasegate/guestwire"
)

type command struct {
 Op string `json:"op"`
 Event evidence.Event `json:"event"`
}
type result struct {
 OK bool `json:"ok"`
 Phase releasegate.Phase `json:"phase"`
 Reclaimable bool `json:"reclaimable"`
 Error string `json:"error,omitempty"`
}

func main(){
 scope:=guestwire.Scope()
 gate,err:=releasegate.New(scope)
 if err!=nil{panic(err)}
 bridge,err:=evidence.New(gate,scope,guestwire.VerifySyntheticGuest)
 if err!=nil{panic(err)}
 s:=bufio.NewScanner(os.Stdin)
 s.Buffer(make([]byte,1024),16384)
 out:=json.NewEncoder(os.Stdout)
 for s.Scan(){
  var cmd command
  err:=json.Unmarshal(s.Bytes(),&cmd)
  if err==nil{
   switch cmd.Op{
   case "event":
    if cmd.Event.Down{err=bridge.ObserveDown(cmd.Event)
    }else{err=bridge.ConfirmUp(cmd.Event)}
   case "qmp-up-ack":
    // Only the trusted test orchestrator may assert the QMP ACK in this
    // harness. A remotely supplied acknowledgment would be invalid.
    err=gate.RequestRelease(scope)
    if err==nil{err=gate.AcknowledgeQMP(scope)}
   case "status":
   default:err=fmt.Errorf("unknown action")
   }
  }
  response:=result{
   OK:err==nil,Phase:gate.Snapshot().Phase,
   Reclaimable:bridge.Reclaimable(),
  }
  if err!=nil{response.Error=err.Error()}
  _=out.Encode(response)
 }
 if err:=s.Err();err!=nil{fmt.Fprintln(os.Stderr,"R26_L8_HOST_INGRESS=RED",err);os.Exit(2)}
}
