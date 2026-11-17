package mobilereceipt

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "strings"
 "testing"
)

const now int64=1900000000
type onceLedger struct{seen map[string]struct{}}
func (l *onceLedger)ConsumeOnce(alias,nonce string,expires int64)bool{
 if l.seen==nil{l.seen=map[string]struct{}{}}
 k:=alias+"|"+nonce
 if _,ok:=l.seen[k];ok{return false}
 l.seen[k]=struct{}{}
 return true
}
func fixture(t *testing.T,substrate string)(Claims,Enrollment,ed25519.PrivateKey){
 t.Helper()
 pub,priv,e:=ed25519.GenerateKey(rand.Reader)
 if e!=nil{t.Fatal(e)}
 platform:="android"
 if substrate=="ios_simulator"{platform="ios"}
 role:="simulator_ui_oracle"
 if substrate=="physical"{role="interactive_assist"}
 c:=Claims{
  Schema:Schema,DeviceAlias:"mob_aaaaaaaaaaaaaaaa",Platform:platform,
  Substrate:substrate,EnrollmentGeneration:strings.Repeat("a",64),
  ConsentGeneration:strings.Repeat("b",64),
  Nonce:"nonce_nonce_nonce_nonce_01",IssuedAt:now-20,ExpiresAt:now+120,
  Scope:role,
 }
 eRec:=Enrollment{
  DeviceAlias:c.DeviceAlias,Platform:platform,Substrate:substrate,
  EnrollmentGeneration:c.EnrollmentGeneration,ConsentGeneration:c.ConsentGeneration,
  PublicKey:pub,ConsentLive:true,RealDeviceAttested:substrate=="physical",
  ApprovedScopes:[]string{role},
 }
 return c,eRec,priv
}
func sign(t *testing.T,c Claims,priv ed25519.PrivateKey)Signed{
 t.Helper()
 b,e:=json.Marshal(c);if e!=nil{t.Fatal(e)}
 return Signed{Payload:b,SignatureBase64:base64.StdEncoding.EncodeToString(ed25519.Sign(priv,b))}
}
func TestDisposableSignedSimulatorReceiptsNeverPromotedToPhysical(t *testing.T){
 for _,substrate:=range []string{"android_emulator","ios_simulator"}{
  t.Run(substrate,func(t *testing.T){
   claims,reg,key:=fixture(t,substrate)
   w:=sign(t,claims,key)
   v,e:=Check(w,reg,now,&onceLedger{})
   if e!=nil||v.CapabilityClass!="SIMULATED_TEST_RECEIPT_NOT_FLEET_PLACEMENT"{
    t.Fatalf("simulated payload classification %+v %v",v,e)
   }
   claims.Scope="local_inference"
   reg.ApprovedScopes=[]string{"local_inference"}
   w=sign(t,claims,key)
   if _,e:=Check(w,reg,now,&onceLedger{});e==nil{t.Fatal("emulator upgraded to fleet inference capacity")}
  })
 }
}
func TestPhysicalCapacityRequiresTrustedRegistrarAndConsent(t *testing.T){
 c,r,key:=fixture(t,"physical")
 w:=sign(t,c,key)
 r.RealDeviceAttested=false
 if _,e:=Check(w,r,now,&onceLedger{});e==nil{t.Fatal("client self-asserted physical HIL")}
 r.RealDeviceAttested=true
 v,e:=Check(w,r,now,&onceLedger{})
 if e!=nil||v.CapabilityClass!="REGISTERED_PHYSICAL_APP_ASSERTION_NEEDS_RUNTIME_ADMISSION"{
  t.Fatalf("attested admission not recorded correctly %+v %v",v,e)
 }
 // A signature is merely an app assertion, not proof of OS background
 // grants, radio, thermal, battery and production capacity; verifier
 // deliberately refuses those claims in this contract.
}
func TestTamperReplayExpiryAndTrustContextFailsClosed(t *testing.T){
 tests:=[]struct{name string;edit func(*Claims,*Enrollment,*Signed)}{
  {"consent-revoked",func(_ *Claims,r *Enrollment,_ *Signed){r.ConsentLive=false}},
  {"enrollment-replaced",func(_ *Claims,r *Enrollment,_ *Signed){r.EnrollmentGeneration=strings.Repeat("c",64)}},
  {"consent-generation-changed",func(_ *Claims,r *Enrollment,_ *Signed){r.ConsentGeneration=strings.Repeat("c",64)}},
  {"platform-mismatch",func(_ *Claims,r *Enrollment,_ *Signed){r.Platform="ipados"}},
  {"spoof-simulator-as-phone",func(_ *Claims,r *Enrollment,_ *Signed){r.Substrate="physical";r.RealDeviceAttested=true}},
  {"unknown-scope",func(_ *Claims,r *Enrollment,_ *Signed){r.ApprovedScopes=[]string{"usb_passthrough"}}},
  {"bad-device-public-key",func(_ *Claims,r *Enrollment,_ *Signed){r.PublicKey=make([]byte,32)}},
  {"invalid-schema",func(c *Claims,_ *Enrollment,_ *Signed){c.Schema="candidate-v2"}},
  {"bad-alias",func(c *Claims,_ *Enrollment,_ *Signed){c.DeviceAlias="de:ad:be:ef:01:23"}},
  {"expired",func(c *Claims,_ *Enrollment,_ *Signed){c.ExpiresAt=now-2}},
  {"future",func(c *Claims,_ *Enrollment,_ *Signed){c.IssuedAt=now+45;c.ExpiresAt=now+100}},
  {"long-ttl",func(c *Claims,_ *Enrollment,_ *Signed){c.ExpiresAt=c.IssuedAt+301}},
  {"old-issued",func(c *Claims,_ *Enrollment,_ *Signed){c.IssuedAt=now-600;c.ExpiresAt=now+2}},
  {"blank-nonce",func(c *Claims,_ *Enrollment,_ *Signed){c.Nonce=""}},
  {"wrong-platform",func(c *Claims,_ *Enrollment,_ *Signed){c.Platform="watchos"}},
  {"signature-mutated",func(_ *Claims,_ *Enrollment,w *Signed){w.SignatureBase64="AA"}},
  {"trailing-json",func(_ *Claims,_ *Enrollment,w *Signed){w.Payload=append(w.Payload,[]byte(" {}")...)}},
  {"unknown-json-field",func(_ *Claims,_ *Enrollment,w *Signed){w.Payload=append(w.Payload[:len(w.Payload)-1],[]byte(,"danger":true}`)...)}},
  {"noncanonical-json",func(_ *Claims,_ *Enrollment,w *Signed){w.Payload=append([]byte(" "),w.Payload...)}},
  {"duplicate-json-field",func(_ *Claims,_ *Enrollment,w *Signed){w.Payload=append(w.Payload[:len(w.Payload)-1],[]byte(,"scope":"simulator_ui_oracle"}`)...)}},
 }
 for _,tc:=range tests{
  t.Run(tc.name,func(t *testing.T){
   c,r,key:=fixture(t,"android_emulator")
   w:=sign(t,c,key)
   tc.edit(&c,&r,&w)
   // If the test mutated *claims*, sign the now-malicious claim using
   // a valid disposable key: validators, not signatures, must refuse it.
   if tc.name=="invalid-schema"||tc.name=="bad-alias"||tc.name=="expired"||
      tc.name=="future"||tc.name=="long-ttl"||tc.name=="old-issued"||
      tc.name=="blank-nonce"||tc.name=="wrong-platform"{
    w=sign(t,c,key)
   }
   if _,e:=Check(w,r,now,&onceLedger{});e==nil{t.Fatalf("accepted bad %s",tc.name)}
  })
 }
}
func TestBoundedNonceReplay(t *testing.T){
 c,r,key:=fixture(t,"physical")
 w:=sign(t,c,key)
 l:=&onceLedger{}
 if _,e:=Check(w,r,now,l);e!=nil{t.Fatal(e)}
 if _,e:=Check(w,r,now,l);e==nil{t.Fatal("accepted nonce replay")}
}
func TestTenantProjectionOnlyAssignedVirtualTaskHandles(t *testing.T){
 out,e:=ProjectAssignedGuest([]string{"task_aaaaaaaaaaaa","task_bbbbbbbbbbbb"})
 if e!=nil||len(out.VirtualTaskHandles)!=2{t.Fatalf("assigned tasks projection %+v %v",out,e)}
 b,_:=json.Marshal(out)
 for _,leak:=range []string{"platform","substrate","device","inventory","pci","usb","serial","gpu","battery","enrollment","consent"}{
  if strings.Contains(string(b),leak){t.Fatalf("host mobile fact escaped tenant view %s",leak)}
 }
 for _,bad:=range [][]string{
  {"mob_aaaaaaaaaaaa"},{"192.168.1.1"},{"00:ab:cd:ef:12:34"},
  {"task_aaaaaaaaaaaa","task_aaaaaaaaaaaa"}, {"task_bad"},
 }{
  if _,e:=ProjectAssignedGuest(bad);e==nil{t.Fatalf("unsafe handle accepted %+v",bad)}
 }
}
