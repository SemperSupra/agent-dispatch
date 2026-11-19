package recoveryguard
import(
 "testing"
 "example.org/usb-fabric-r26-integrated/heldledger"
)
func original()heldledger.State{return heldledger.State{Held:true,Sequence:11,ReleasePhase:""}}
func TestUnchangedHeldAfterEmergencyKeyUp(t *testing.T){s:=original();if e:=VerifyEmergencyHold(s,s);e!=nil{t.Fatal(e)}}
func TestQmpCannotClearHeld(t *testing.T){s:=original();a:=s;a.Held=false;if e:=VerifyEmergencyHold(s,a);e==nil{t.Fatal("QMP-only guest release accepted")}}
func TestCannotJumpJournalSequence(t *testing.T){s:=original();a:=s;a.Sequence++;if e:=VerifyEmergencyHold(s,a);e==nil{t.Fatal("unverified journal event admitted")}}
func TestCannotChangeReleasePhase(t *testing.T){s:=original();a:=s;a.ReleasePhase="verified";if e:=VerifyEmergencyHold(s,a);e==nil{t.Fatal("unverified release phase admitted")}}
func TestCannotStartEmergencyAlreadyClear(t *testing.T){s:=original();s.Held=false;if e:=VerifyEmergencyHold(s,s);e==nil{t.Fatal("already cleared state")}}
