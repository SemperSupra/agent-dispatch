//go:build linux

package blue

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "errors"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"

 "example.org/usb-fabric-r26-integrated/heldledger"
)
func scopedOwnerFixture(t *testing.T)(heldledger.GenesisScope,heldledger.Store){
 t.Helper()
 d:=t.TempDir()
 if e:=os.Chmod(d,0700);e!=nil{t.Fatal(e)}
 return heldledger.GenesisScope{
  SourceAuthority:"test-authority",SourceController:"ctl-a",DownstreamPort:"1-2",
  DeviceResource:"device-a",ConflictGroup:"hub-a",SourceHostIncarnation:"host-a",SourceControllerIncarnation:"boot-a",
 },heldledger.Store{Path:filepath.Join(d,"held.json")}
}
func TestScopedOwnerConflictsAndRollback(t *testing.T){
 scope,store:=scopedOwnerFixture(t)
 o,e:=OpenScopedGenesisOwner(scope,store)
 if e!=nil{t.Fatal(e)}
 defer o.Close()
 if _,e=o.CreateHeldGenesis();e!=nil{t.Fatal(e)}
 for _,modify:=range []func(*heldledger.GenesisScope){
  func(s *heldledger.GenesisScope){s.DeviceResource="other";s.ConflictGroup="other"},
  func(s *heldledger.GenesisScope){s.DownstreamPort="other";s.SourceController="other";s.ConflictGroup="other"},
  func(s *heldledger.GenesisScope){s.DownstreamPort="other";s.DeviceResource="other"},
  func(s *heldledger.GenesisScope){s.SourceHostIncarnation="host-b";s.SourceControllerIncarnation="boot-b"},
 }{
  v:=scope;modify(&v)
  _,p:=scopedOwnerFixture(t)
  other,e:=OpenScopedGenesisOwner(v,p)
  if other!=nil{_=other.Close();t.Fatal("conflicting scoped owner acquired")}
  if e==nil{t.Fatal("conflict not denied")}
 }
 independent:=scope
 independent.DownstreamPort="1-3";independent.DeviceResource="device-b";independent.ConflictGroup="hub-b"
 other,e:=OpenScopedGenesisOwner(independent,store)
 if other!=nil{_=other.Close();t.Fatal("same journal admitted with different scope")}
 if e==nil{t.Fatal("same journal not denied")}
 _,p:=scopedOwnerFixture(t)
 other,e=OpenScopedGenesisOwner(independent,p)
 if e!=nil{t.Fatal("failed acquire leaked a partial lock",e)}
 if e=other.Close();e!=nil{t.Fatal(e)}
 if e=o.Close();e!=nil{t.Fatal(e)}
 if _,e=o.CreateHeldGenesis();!errors.Is(e,ErrQuarantined){t.Fatal("closed owner could write",e)}
 if _,e=o.PrepareAdmission("",nil,nil);!errors.Is(e,ErrQuarantined){t.Fatal("closed owner could prepare",e)}
 reopened,e:=OpenScopedGenesisOwner(scope,store)
 if e!=nil{t.Fatal(e)}
 defer reopened.Close()
 if _,e=reopened.CreateHeldGenesis();!errors.Is(e,heldledger.ErrConflict){t.Fatal("existing genesis overwritten",e)}
 t.Log("SCOPED_STABLE_PORT_DEVICE_GROUP_AND_JOURNAL_LOCKS=PASS")
}
func TestScopedOwnerCrossProcess(t *testing.T){
 if os.Getenv("USB_SCOPED_OWNER_CHILD")=="1"{
  var scope heldledger.GenesisScope
  if e:=json.Unmarshal([]byte(os.Getenv("USB_SCOPED_SCOPE")),&scope);e!=nil{t.Fatal(e)}
  o,e:=OpenScopedGenesisOwner(scope,heldledger.Store{Path:os.Getenv("USB_SCOPED_JOURNAL")})
  if o!=nil{_=o.Close();t.Fatal("second PID acquired conflicting resource")}
  if e==nil{t.Fatal("cross-process conflict not denied")}
  t.Log("SCOPED_SECOND_PID_DENIED=PASS");return
 }
 scope,store:=scopedOwnerFixture(t)
 o,e:=OpenScopedGenesisOwner(scope,store);if e!=nil{t.Fatal(e)}
 defer o.Close()
 scope.DeviceResource="replacement";scope.ConflictGroup="hub-b";scope.SourceHostIncarnation="host-b"
 _,p:=scopedOwnerFixture(t)
 b,e:=json.Marshal(scope);if e!=nil{t.Fatal(e)}
 cmd:=exec.Command(os.Args[0],"-test.run=^TestScopedOwnerCrossProcess$","-test.v")
 cmd.Env=append(os.Environ(),"USB_SCOPED_OWNER_CHILD=1","USB_SCOPED_SCOPE="+string(b),"USB_SCOPED_JOURNAL="+p.Path)
 out,e:=cmd.CombinedOutput()
 if e!=nil||!strings.Contains(string(out),"SCOPED_SECOND_PID_DENIED=PASS"){t.Fatalf("actual child denial failed: %v %s",e,out)}
 t.Log("SCOPED_PORT_CONFLICT_INDEPENDENT_PID=PASS")
}
func TestScopedOwnerSignedIntentNoGrant(t *testing.T){
 scope,store:=scopedOwnerFixture(t)
 o,e:=OpenScopedGenesisOwner(scope,store);if e!=nil{t.Fatal(e)}
 defer o.Close()
 st,e:=o.CreateHeldGenesis();if e!=nil{t.Fatal(e)}
 op:=strings.Repeat("ab",32)
 pins:=map[string]ed25519.PublicKey{}
 var ws []heldledger.GenesisWitness
 for domain,obs:=range map[string]string{"host-actuator":"OLD_ACCESS_FENCED","usbip-exporter":"OLD_EXPORT_DENIED","linux-vhci":"OLD_IMPORT_ABSENT","network-effective-deny":"OLD_SESSIONS_DENIED","guest-input-release":"NEUTRAL_INPUT_OBSERVED"}{
  pub,priv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
  w:=heldledger.GenesisWitness{Domain:domain,Scope:scope,Nonce:st.GenesisNonce,Operation:op,Observation:obs}
  b,e:=w.SigningBytes();if e!=nil{t.Fatal(e)}
  w.Signature=ed25519.Sign(priv,b);pins[domain]=pub;ws=append(ws,w)
 }
 intent,e:=o.PrepareAdmission(op,ws,pins)
 if e!=nil||!intent.AdmissionIntent||intent.Held{t.Fatal("durable intent missing",e)}
 if _,e=o.PrepareAdmission(op,ws,pins);e==nil{t.Fatal("replay admitted")}
 if m,old,e:=NewAfterExclusiveDurableAdmission(scope.DeviceResource,scope.DownstreamPort,nil,store);e==nil||old!=nil{
  if old!=nil{_=old.Close()};t.Fatalf("legacy Manager admitted v2: %v",m)
 }
 t.Log("SCOPED_RETAINED_OWNER_SIGNED_INTENT_NO_GRANT=PASS")
}
