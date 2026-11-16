package main
import (
 "encoding/json"
 "testing"
)
func TestLabelsFailClosed(t *testing.T){
 for _,s:=range []string{"","a/b","hello world","a:admin","💾"}{
  if allowedLabel(s){t.Fatalf("unsafe label allowed: %q",s)}
 }
 for _,s:=range []string{"linux-vm","actor_1","mission2"}{
  if !allowedLabel(s){t.Fatalf("valid label rejected: %q",s)}
 }
}
func TestQMPEventsAreStandardAndRestrained(t *testing.T){
 for _,kind:=range []string{"key-a","button-left"}{
  for _,down:=range []bool{true,false}{
   b,e:=json.Marshal(makeEvent(kind,down))
   if e!=nil{t.Fatal(e)}
   if len(b)<30 {t.Fatal("empty QMP input event")}
  }
 }
}
