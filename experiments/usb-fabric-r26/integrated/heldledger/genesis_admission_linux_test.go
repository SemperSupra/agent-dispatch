//go:build linux

package heldledger

import (
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "os"
 "strings"
 "testing"
)

func signedGenesis(t *testing.T)(Store,GenesisScope,State,string,[]GenesisWitness,map[string]ed25519.PublicKey){
 t.Helper()
 s,scope:=scopedFixture(t)
 st,e:=s.CreateScopedHeldGenesis(scope);if e!=nil{t.Fatal(e)}
 op:=strings.Repeat("ab",32)
 pins:=map[string]ed25519.PublicKey{}
 ws:=[]GenesisWitness{}
 for _,domain:=range genesisDomains{
  pub,priv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
  w:=GenesisWitness{Domain:domain,Scope:scope,Nonce:st.GenesisNonce,Operation:op,Observation:genesisObservation(domain)}
  b,e:=w.SigningBytes();if e!=nil{t.Fatal(e)}
  w.Signature=ed25519.Sign(priv,b);pins[domain]=pub;ws=append(ws,w)
 }
 return s,scope,st,op,ws,pins
}

func TestScopedAdmissionWitnessesAndReplay(t *testing.T){
 s,scope,st,op,ws,pins:=signedGenesis(t)
 before,e:=os.ReadFile(s.Path);if e!=nil{t.Fatal(e)}
 attempts:=[]func()error{
  func()error{_,e:=s.PrepareScopedAdmission(scope,op,ws[:4],pins);return e},
  func()error{w:=append([]GenesisWitness(nil),ws...);w[1]=w[0];_,e:=s.PrepareScopedAdmission(scope,op,w,pins);return e},
  func()error{w:=append([]GenesisWitness(nil),ws...);w[0].Nonce=strings.Repeat("cd",32);_,e:=s.PrepareScopedAdmission(scope,op,w,pins);return e},
  func()error{w:=append([]GenesisWitness(nil),ws...);w[0].Scope.DeviceResource="foreign";_,e:=s.PrepareScopedAdmission(scope,op,w,pins);return e},
  func()error{w:=append([]GenesisWitness(nil),ws...);w[0].Signature=make([]byte,ed25519.SignatureSize);_,e:=s.PrepareScopedAdmission(scope,op,w,pins);return e},
  func()error{p:=map[string]ed25519.PublicKey{};for k,v:=range pins{p[k]=v};p[genesisDomains[1]]=p[genesisDomains[0]];_,e:=s.PrepareScopedAdmission(scope,op,ws,p);return e},
  func()error{_,e:=s.PrepareScopedAdmission(scope,strings.Repeat("de",32),ws,pins);return e},
 }
 for i,attempt:=range attempts{if e:=attempt();e==nil{t.Fatalf("bad proof %d admitted",i)};b,e:=os.ReadFile(s.Path);if e!=nil||string(b)!=string(before){t.Fatal("denied proof changed journal")}}
 next,e:=s.PrepareScopedAdmission(scope,op,ws,pins);if e!=nil{t.Fatal(e)}
 if next.Sequence!=2||next.Held||!next.AdmissionIntent||next.GenesisNonce!=st.GenesisNonce{t.Fatalf("bad intent: %+v",next)}
 got,e:=s.ReadScopedAdmissionIntent(scope);if e!=nil||got.GenesisEvidenceHash!=next.GenesisEvidenceHash{t.Fatal("intent readback failed",e)}
 if _,e=s.Read();e==nil{t.Fatal("legacy read admitted v2")}
 if _,e=s.BeginAdmission(2);e==nil{t.Fatal("legacy admission accepted v2")}
 if _,e=s.PrepareScopedAdmission(scope,op,ws,pins);e==nil{t.Fatal("witness replay admitted")}
 // Recreated HELD has a fresh nonce, even for identical resource/boot.
 if e=os.Remove(s.Path);e!=nil{t.Fatal(e)}
 fresh,e:=s.CreateScopedHeldGenesis(scope);if e!=nil||fresh.GenesisNonce==st.GenesisNonce{t.Fatal("genesis nonce reused",e)}
 if _,e=s.PrepareScopedAdmission(scope,op,ws,pins);e==nil{t.Fatal("old proof accepted after recreation")}
 t.Log("V2_DISTINCT_PINNED_WITNESSES_DURABLE_INTENT_AND_REPLAY_DENIAL=PASS")
}
func TestScopedAdmissionAmbiguousWriteNeverAdmits(t *testing.T){
 s,scope,_,op,ws,pins:=signedGenesis(t)
 fault:=errors.New("injected error after durable visibility")
 _,e:=s.prepareScopedAdmission(scope,op,ws,pins,func(st State)error{
  if e:=s.writeAtomic(st);e!=nil{return e};return fault
 })
 if !errors.Is(e,fault){t.Fatalf("fault lost: %v",e)}
 if got,e:=s.ReadScopedAdmissionIntent(scope);e!=nil||!got.AdmissionIntent{t.Fatal("intent not retained",e)}
 if _,e=s.PrepareScopedAdmission(scope,op,ws,pins);e==nil{t.Fatal("ambiguous write replay admitted")}
 if _,e=s.BeginAdmission(2);e==nil{t.Fatal("legacy grant after ambiguity")}
 t.Log("V2_AMBIGUOUS_WRITE_INTENT_NO_RETRY=PASS")
}
