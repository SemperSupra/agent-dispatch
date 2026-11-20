package recoveryproof
import(
 "crypto/ed25519"
 "crypto/rand"
 "testing"
 releasegate "example.org/usb-fabric-r26-releasegate"
)
type fixture struct{priv ed25519.PrivateKey;scope releasegate.Scope;c [32]byte;a *Authority}
func setup(t *testing.T)*fixture{
 t.Helper()
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 c,err:=Challenge();if err!=nil{t.Fatal(err)}
 scope:=releasegate.Scope{GuestID:"synthetic-qemu",DeviceID:"usb-kbd-a",HostEpoch:"host/7",GuestEpoch:"guest/8",LeaseEpoch:"lease/9",Generation:3,ReleaseSequence:11}
 a,err:=NewAuthority(pub,scope,c,10);if err!=nil{t.Fatal(err)}
 return &fixture{priv:priv,scope:scope,c:c,a:a}
}
func(f *fixture)event(t *testing.T,phase,source string,held bool,seq uint64)Event{
 t.Helper();e,err:=Sign(f.priv,Event{Scope:f.scope,Challenge:f.c,Phase:phase,Source:source,KeyCode:"key-a",Held:held,EventSequence:seq});if err!=nil{t.Fatal(err)};return e
}
func TestTwoIndependentSignedPhasesRequired(t *testing.T){
 f:=setup(t);s:=f.event(t,HeldSnapshot,"guest.evdev-state",true,11)
 u:=f.event(t,GuestKeyUp,"guest.evdev",false,12)
 if f.a.ConfirmGuestKeyUp(u)==nil{t.Fatal("accepted UP before snapshot")}
 if f.a.ObserveHeldSnapshot(s)!=nil{t.Fatal("snapshot")}
 if f.a.Reclaimable(){t.Fatal("snapshot released journal")}
 if f.a.ConfirmGuestKeyUp(u)==nil{t.Fatal("accepted UP without QMP ACK")}
 if f.a.MarkEmergencyQMPAcknowledged()!=nil{t.Fatal("ack")}
 if f.a.Reclaimable(){t.Fatal("QMP ACK released journal")}
 if f.a.ConfirmGuestKeyUp(u)!=nil||!f.a.Reclaimable(){t.Fatal("signed post-ACK guest UP not accepted")}
 if f.a.ConfirmGuestKeyUp(u)==nil{t.Fatal("replayed key-up accepted")}
}
func TestWrongPinnedKey(t *testing.T){
 f:=setup(t);_,other,_:=ed25519.GenerateKey(rand.Reader)
 bad,_:=Sign(other,Event{Scope:f.scope,Challenge:f.c,Phase:HeldSnapshot,Source:"guest.evdev-state",KeyCode:"key-a",Held:true,EventSequence:11})
 if f.a.ObserveHeldSnapshot(bad)==nil{t.Fatal("untrusted signer admitted")}
}
func TestOldChallengeReplay(t *testing.T){
 f:=setup(t);e:=f.event(t,HeldSnapshot,"guest.evdev-state",true,11)
 other,err:=Challenge();if err!=nil{t.Fatal(err)}
 a,err:=NewAuthority(f.priv.Public().(ed25519.PublicKey),f.scope,other,10);if err!=nil{t.Fatal(err)}
 if a.ObserveHeldSnapshot(e)==nil{t.Fatal("old challenge replay admitted")}
}
func TestScopeTampering(t *testing.T){
 f:=setup(t);e:=f.event(t,HeldSnapshot,"guest.evdev-state",true,11)
 e.Scope.HostEpoch="host/other"
 if f.a.ObserveHeldSnapshot(e)==nil{t.Fatal("epoch tampering admitted")}
}
func TestEventSequenceMustAdvance(t *testing.T){
 f:=setup(t);s:=f.event(t,HeldSnapshot,"guest.evdev-state",true,10)
 if f.a.ObserveHeldSnapshot(s)==nil{t.Fatal("stale original event reused")}
 s=f.event(t,HeldSnapshot,"guest.evdev-state",true,11)
 if f.a.ObserveHeldSnapshot(s)!=nil{t.Fatal("fresh snapshot")}
 if f.a.MarkEmergencyQMPAcknowledged()!=nil{t.Fatal("ack")}
 if f.a.ConfirmGuestKeyUp(f.event(t,GuestKeyUp,"guest.evdev",false,11))==nil{t.Fatal("non-advancing UP accepted")}
}
func TestHostCommandCannotPretendGuestSensor(t *testing.T){
 f:=setup(t);e:=f.event(t,HeldSnapshot,"host.qmp",true,11)
 if f.a.ObserveHeldSnapshot(e)==nil{t.Fatal("QMP assertion accepted instead of evdev kernel state")}
}
func TestWrongKeyStateDenied(t *testing.T){
 f:=setup(t);e:=f.event(t,HeldSnapshot,"guest.evdev-state",false,11)
 if f.a.ObserveHeldSnapshot(e)==nil{t.Fatal("guest UP without HELD snapshot admitted")}
}
func TestReleaseWithoutObservedUpDenied(t *testing.T){
 f:=setup(t);s:=f.event(t,HeldSnapshot,"guest.evdev-state",true,11)
 _=f.a.ObserveHeldSnapshot(s);_=f.a.MarkEmergencyQMPAcknowledged()
 if f.a.Reclaimable(){t.Fatal("QMP ACK treated as actual evdev UP")}
}
func TestNoEmptyOrUnpinnedAuthority(t *testing.T){
 f:=setup(t);if _,err:=NewAuthority(nil,f.scope,f.c,10);err==nil{t.Fatal("TOFU accepted")}
 if _,err:=NewAuthority(f.priv.Public().(ed25519.PublicKey),f.scope,[32]byte{},10);err==nil{t.Fatal("zero challenge accepted")}
}
func TestReplaySnapshotDenied(t *testing.T){
 f:=setup(t);s:=f.event(t,HeldSnapshot,"guest.evdev-state",true,11)
 if f.a.ObserveHeldSnapshot(s)!=nil{t.Fatal("snapshot")}
 if f.a.ObserveHeldSnapshot(s)==nil{t.Fatal("replayed held snapshot accepted")}
}
