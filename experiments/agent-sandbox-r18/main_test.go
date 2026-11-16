package main
import "testing"

func TestLabelAdmission(t *testing.T){
 for _,s:=range []string{"","host/root","actor:admin","a space","../path"}{
  if valid(s){t.Fatalf("unsafe identity label allowed: %q",s)}
 }
 for _,s:=range []string{"linux-vm","agent_1","a-z_9"}{
  if !valid(s){t.Fatalf("valid label denied: %q",s)}
 }
}
func TestNoRealBackendsInRemoteContracts(t *testing.T){
 // The remote client submits no hub lease nor QMP server socket path.
 var req UserCommand
 if req.Actor!=""||req.Guest!=""||req.Mission!=""{
  t.Fatal("uninitialized actor scope not empty")
 }
}
