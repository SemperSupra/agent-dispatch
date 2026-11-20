package main
import(
 "encoding/json"
 "net"
 "testing"
)
func recoveryProbe(t *testing.T,response string)(bool,error){
 t.Helper()
 client,server:=net.Pipe();defer client.Close();defer server.Close()
 q:=&qmp{conn:client,enc:json.NewEncoder(client),dec:json.NewDecoder(client)}
 done:=make(chan error,1)
 go func(){
  var req struct{Execute string `json:"execute"`}
  if err:=json.NewDecoder(server).Decode(&req);err!=nil{done<-err;return}
  if req.Execute!="query-status"{done<-net.InvalidAddrError("wrong QMP command");return}
  _,err:=server.Write([]byte(response+"\n"));done<-err
 }()
 running,err:=q.recoveryRunning()
 if werr:=<-done;werr!=nil{t.Fatal(werr)}
 return running,err
}
func TestRecoveryRequiresActuallyRunningVM(t *testing.T){ok,err:=recoveryProbe(t,`{"return":{"running":true,"status":"running"}}`);if err!=nil||!ok{t.Fatal(ok,err)}}
func TestPrelaunchNotRecovery(t *testing.T){ok,_:=recoveryProbe(t,`{"return":{"running":false,"status":"prelaunch"}}`);if ok{t.Fatal("prelaunch accepted as recovered VM")}}
func TestPausedGuestNotRecovery(t *testing.T){ok,_:=recoveryProbe(t,`{"return":{"running":false,"status":"paused"}}`);if ok{t.Fatal("paused guest accepted")}}
func TestStoppedGuestNotRecovery(t *testing.T){ok,_:=recoveryProbe(t,`{"return":{"running":false,"status":"shutdown"}}`);if ok{t.Fatal("stopped guest accepted")}}
func TestContradictoryRunStateDenied(t *testing.T){ok,_:=recoveryProbe(t,`{"return":{"running":true,"status":"paused"}}`);if ok{t.Fatal("contradictory VM status accepted")}}
func TestMissingStateDenied(t *testing.T){ok,err:=recoveryProbe(t,`{"return":{"running":true}}`);if ok||err==nil{t.Fatal("no status string accepted")}}
func TestMalformedStateDenied(t *testing.T){ok,err:=recoveryProbe(t,`{"return":{"running":"yes","status":"running"}}`);if ok||err==nil{t.Fatal("malformed QMP status accepted")}}
func TestQMPErrorDenied(t *testing.T){ok,err:=recoveryProbe(t,`{"error":{"class":"GenericError","desc":"denied"}}`);if ok||err==nil{t.Fatal("QMP error accepted")}}
func TestUnrecognizedSuccessDenied(t *testing.T){ok,err:=recoveryProbe(t,`{"not-a-return":{}}`);if ok||err==nil{t.Fatal("missing QMP return accepted")}}
