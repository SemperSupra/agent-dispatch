package topology
import (
 "encoding/json"
 "errors"
 "testing"
)
type mock struct{present bool;invalid bool;duplicates bool;denied bool;calls int}
func(m *mock)call(name string,args map[string]any)(json.RawMessage,error){
 m.calls++
 if m.denied{return nil,errors.New("QMP error")}
 if name=="device_del"{
  if args["id"]!="r26-l-kbd"{return nil,errors.New("wrong id")}
  m.present=false
  return json.RawMessage(`{}`),nil
 }
 if name!="qom-list"||args["path"]!="/machine/peripheral"{return nil,errors.New("unknown command")}
 if m.invalid{return json.RawMessage(`{"not":"list"}`),nil}
 if !m.present{return json.RawMessage(`[]`),nil}
 if m.duplicates{return json.RawMessage(`[{"name":"r26-l-kbd","type":"child<usb-kbd>"},{"name":"r26-l-kbd","type":"child<usb-kbd>"}]`),nil}
 return json.RawMessage(`[{"name":"r26-l-kbd","type":"child<usb-kbd>"}]`),nil
}
func TestDevicePresentThenDetach(t *testing.T){m:=&mock{present:true};ok,e:=DetachAndConfirm(m.call,"r26-l-kbd");if e!=nil||!ok||m.present{t.Fatal(ok,e)}}
func TestAbsentBeforeDetachDenied(t *testing.T){m:=&mock{};if ok,e:=DetachAndConfirm(m.call,"r26-l-kbd");e==nil||ok{t.Fatal("device absent before detach")}}
func TestDuplicateQOMIdentityDenied(t *testing.T){m:=&mock{present:true,duplicates:true};if ok,e:=Present(m.call,"r26-l-kbd");e==nil||ok{t.Fatal("ambiguous QOM identity")}}
func TestMalformedQOMDenied(t *testing.T){m:=&mock{present:true,invalid:true};if ok,e:=Present(m.call,"r26-l-kbd");e==nil||ok{t.Fatal("malformed QMP accepted")}}
func TestDeniedQMPDoesNotClaimClear(t *testing.T){m:=&mock{present:true,denied:true};if ok,e:=DetachAndConfirm(m.call,"r26-l-kbd");e==nil||ok{t.Fatal("QMP denial ignored")}}
func TestEmptyDeviceIDRejected(t *testing.T){m:=&mock{present:true};if ok,e:=Present(m.call,"");e==nil||ok{t.Fatal("empty ID accepted")}}
func TestDifferentDeviceNotConfused(t *testing.T){m:=&mock{present:true};if ok,e:=Present(m.call,"other");e!=nil||ok{t.Fatal("other ID matched",ok,e)}}
