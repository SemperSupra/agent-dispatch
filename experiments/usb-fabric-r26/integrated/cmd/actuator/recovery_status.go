package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "time"
)

// recoveryRunning validates that emergency QMP key-up is directed at a
// genuinely executing VM. An ACK against a prelaunch, suspended, shutdown,
// or unidentified incarnation is not a credible recovery path. This is a
// test-only same-host control, not production guest attestation.
func(q *qmp) recoveryRunning()(bool,error){
 q.mu.Lock();defer q.mu.Unlock()
 if err:=q.conn.SetDeadline(time.Now().Add(10*time.Second));err!=nil{return false,err}
 if err:=q.enc.Encode(map[string]any{"execute":"query-status"});err!=nil{return false,err}
 for i:=0;i<150;i++{
  var response map[string]json.RawMessage
  if err:=q.dec.Decode(&response);err!=nil{return false,err}
  if _,ok:=response["event"];ok{continue}
  if raw,ok:=response["error"];ok{return false,fmt.Errorf("recovery query-status: %s",string(raw))}
  raw,ok:=response["return"]
  if !ok{return false,errors.New("recovery QMP response missing return")}
  var state struct{
   Running bool `json:"running"`
   Status string `json:"status"`
  }
  if err:=json.Unmarshal(raw,&state);err!=nil{return false,err}
  if state.Status==""{return false,errors.New("empty QEMU recovery run-state")}
  return state.Running && state.Status=="running",nil
 }
 return false,errors.New("recovery QMP response limit")
}
