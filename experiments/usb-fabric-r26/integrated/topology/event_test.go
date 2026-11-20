package topology
import(
 "bytes"
 "encoding/json"
 "strings"
 "testing"
)
func witness(t *testing.T,response string)error{
 t.Helper()
 var out bytes.Buffer
 return DetachWithEvent(json.NewEncoder(&out),json.NewDecoder(strings.NewReader(response)),"r26-l-kbd")
}
func TestEventBeforeSuccessAccepted(t *testing.T){
 e:=witness(t,`{"event":"DEVICE_DELETED","data":{"device":"r26-l-kbd"}}`+"\n"+`{"return":{}}`)
 if e!=nil{t.Fatal(e)}
}
func TestEventAfterSuccessAccepted(t *testing.T){
 e:=witness(t,`{"return":{}}`+"\n"+`{"event":"DEVICE_DELETED","data":{"device":"r26-l-kbd"}}`)
 if e!=nil{t.Fatal(e)}
}
func TestMissingEventRejected(t *testing.T){if e:=witness(t,`{"return":{}}`);e==nil{t.Fatal("QMP ACK falsely proves device deletion")}}
func TestMissingReturnRejected(t *testing.T){if e:=witness(t,`{"event":"DEVICE_DELETED","data":{"device":"r26-l-kbd"}}`);e==nil{t.Fatal("event with no successful command")}}
func TestWrongDeviceRejected(t *testing.T){
 e:=witness(t,`{"return":{}}`+"\n"+`{"event":"DEVICE_DELETED","data":{"device":"other"}}`)
 if e==nil{t.Fatal("unrelated device deleted accepted")}
}
func TestQMPErrorRejected(t *testing.T){
 e:=witness(t,`{"error":{"class":"GenericError","desc":"denied"}}`+"\n"+`{"event":"DEVICE_DELETED","data":{"device":"r26-l-kbd"}}`)
 if e==nil{t.Fatal("QMP error accepted")}
}
func TestMalformedEventRejected(t *testing.T){if e:=witness(t,`{"event":"DEVICE_DELETED","data":{"device":7}}`);e==nil{t.Fatal("malformed event admitted")}}
func TestUnrelatedEventSkipped(t *testing.T){
 e:=witness(t,`{"event":"STOP","data":{}}`+"\n"+`{"return":{}}`+"\n"+`{"event":"DEVICE_DELETED","data":{"device":"r26-l-kbd"}}`)
 if e!=nil{t.Fatal(e)}
}
func TestNilDecoderFailClosed(t *testing.T){if e:=DetachWithEvent(nil,nil,"r26-l-kbd");e==nil{t.Fatal("nil QMP accepted")}}
