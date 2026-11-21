package blue

import (
 "os"
 "path/filepath"
 "testing"
 "example.org/usb-fabric-r26-integrated/heldledger"
)

// R27-P adversarial negative test: recovered journal cleanliness does not
// confer exclusive ownership of a live USB/IP busid across Managers. This
// simulates two independent controller instances in the same Go process.
// A real cross-PID lock test must reuse/compose the R26-L10 host owner.
func TestR27PDualManagerSameRecoveredCleanJournalMustFenceSecond(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"clean.json")
 // Test fixture, not authenticated production release proof.
 if err:=os.WriteFile(path,[]byte("{\"version\":1,\"sequence\":2,\"held\":false}\n"),0600);err!=nil{t.Fatal(err)}
 store:=heldledger.Store{Path:path}
 first,err:=NewAfterJournalRecovery("keyboard","vhci_hcd/port0",nil,store)
 if err!=nil{t.Fatalf("first recovered owner refused clean fixture: %v",err)}
 second,err:=NewAfterJournalRecovery("keyboard","vhci_hcd/port0",nil,store)
 if err!=nil {
  t.Log("R27_P_SECOND_RECOVERED_OWNER_DENIED=PASS")
  return
 }
 a,err:=first.Reserve("consumer-A","keyboard","vhci_hcd/port0")
 if err!=nil{t.Fatalf("first controlled admission refused unexpectedly: %v",err)}
 b,err:=second.Reserve("consumer-B","keyboard","vhci_hcd/port0")
 if err==nil {
  t.Fatalf("R27_P_DUAL_RECOVERED_MANAGER_SAME_PORT_ADMISSION=RED: independent manager-A actor=%q epoch=%q and manager-B actor=%q epoch=%q both reserved same port on unchanged clean durable ledger",a.Actor,a.Epoch,b.Actor,b.Epoch)
 }
 t.Log("R27_P_SECOND_RECOVERED_OWNER_DENIED=PASS")
}
