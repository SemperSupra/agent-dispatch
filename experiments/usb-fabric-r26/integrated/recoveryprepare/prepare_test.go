package recoveryprepare
import(
 "errors"
 "path/filepath"
 "testing"
 heldledger "example.org/usb-fabric-r26-integrated/heldledger"
)
func state()heldledger.State{return heldledger.State{Version:heldledger.Version,Sequence:1,Held:true,Key:heldledger.KeyA}}
func valid()Evidence{return Evidence{GuestSignedUp:true,ExactDeviceDeleted:true,QOMAbsent:true,SameQEMUProcess:true,SameHostEpoch:true,SameGuestEpoch:true,SameLeaseEpoch:true,SoleQMPController:true,NoHostileRawQMP:true,ProductionGuestTrust:true}}
func TestNoPreparedReleaseFromSignedUpAlone(t *testing.T){
 e:=Evidence{GuestSignedUp:true}
 if _,err:=Prepare(state(),e);!errors.Is(err,ErrUntrusted){t.Fatal("signed UP alone prepared release",err)}
}
func TestEveryNecessaryClaimFailClosed(t *testing.T){
 cases:=map[string]func(*Evidence){
 "signedUP":func(e *Evidence){e.GuestSignedUp=false},
 "device-event":func(e *Evidence){e.ExactDeviceDeleted=false},
 "qom":func(e *Evidence){e.QOMAbsent=false},
 "qemu-pid":func(e *Evidence){e.SameQEMUProcess=false},
 "host-epoch":func(e *Evidence){e.SameHostEpoch=false},
 "guest-epoch":func(e *Evidence){e.SameGuestEpoch=false},
 "lease-epoch":func(e *Evidence){e.SameLeaseEpoch=false},
 "sole-controller":func(e *Evidence){e.SoleQMPController=false},
 "H7-raw-qmp":func(e *Evidence){e.NoHostileRawQMP=false},
 "production-key":func(e *Evidence){e.ProductionGuestTrust=false},
 }
 for name,mutate:=range cases{t.Run(name,func(t *testing.T){e:=valid();mutate(&e);if _,err:=Prepare(state(),e);err==nil{t.Fatal("missing proof allowed prepared release")}})}
}
func TestHeldMustBeDurableAndKnown(t *testing.T){
 s:=state();s.Held=false;if _,e:=Prepare(s,valid());e==nil{t.Fatal("unheld accepted")}
 s=state();s.Version=2;if _,e:=Prepare(s,valid());e==nil{t.Fatal("unknown version accepted")}
}
func TestPreparedTokenDoesNotModifyJournal(t *testing.T){
 s:=state();p,e:=Prepare(s,valid());if e!=nil||p.Sequence!=1{t.Fatal(p,e)}
 // A token is deliberately NOT a write or a new-lease grant.
 if s.Held!=true{t.Fatal("prepare cleared durable HELD")}
}
func TestMissingJournalRefused(t *testing.T){
 p,_:=Prepare(state(),valid())
 if e:=p.Recheck(heldledger.Store{Path:filepath.Join(t.TempDir(),"missing")});e==nil{
  t.Fatal("absent journal treated as original held evidence")
 }
}
func TestInvalidTokenRejected(t *testing.T){
 if e:=(Prepared{}).Recheck(heldledger.Store{Path:""});e==nil{t.Fatal("empty token accepted")}
}
func TestJournalDriftChangesDigest(t *testing.T){
 s:=state();other:=s;other.ReleasePhase="qmp-acked"
 if digest(s)==digest(other){t.Fatal("release phase drift not detected")}
 other=s;other.LastReleaseEventSequence=100
 if digest(s)==digest(other){t.Fatal("proof sequence drift not detected")}
}
