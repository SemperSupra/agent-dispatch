// Package topology performs bounded, synthetic QMP QOM topology observation.
// Removal/absence is one necessary condition only, not authority to clear a
// durable HELD journal or admit a new lease.
package topology
import (
 "encoding/json"
 "errors"
 "fmt"
 "time"
)
var ErrUntrusted=errors.New("topology: absent, duplicate or unverified device")
type Call func(name string,args map[string]any)(json.RawMessage,error)
type item struct {Name string `json:"name"`;Type string `json:"type"`}
func Present(call Call,id string)(bool,error){
 if call==nil||id==""{return false,ErrUntrusted}
 raw,err:=call("qom-list",map[string]any{"path":"/machine/peripheral"})
 if err!=nil{return false,fmt.Errorf("%w: %v",ErrUntrusted,err)}
 var list []item
 if err=json.Unmarshal(raw,&list);err!=nil{return false,fmt.Errorf("%w: malformed QOM",ErrUntrusted)}
 n:=0
 for _,entry:=range list{
  if entry.Name==id{
   if entry.Type==""{return false,ErrUntrusted}
   n++
  }
 }
 if n>1{return false,ErrUntrusted}
 return n==1,nil
}
func DetachAndConfirm(call Call,id string)(bool,error){
 if call==nil||id==""{return false,ErrUntrusted}
 before,err:=Present(call,id)
 if err!=nil||!before{return false,ErrUntrusted}
 if _,err=call("device_del",map[string]any{"id":id});err!=nil{return false,err}
 for i:=0;i<60;i++{
  present,checkErr:=Present(call,id)
  if checkErr!=nil{return false,checkErr}
  if !present{return true,nil}
  time.Sleep(50*time.Millisecond)
 }
 return false,errors.New("device not absent from QOM after QMP device_del")
}
