package heldledger

import (
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
)

// Each independently enrolled observer must positively attest its specific
// fact for this exact resource, boot, genesis nonce and operation. These
// names describe required observations; signatures alone do not prove them.
var genesisDomains=[]string{"host-actuator","usbip-exporter","linux-vhci","network-effective-deny","guest-input-release"}

type GenesisWitness struct{
 Domain string `json:"domain"`
 Scope GenesisScope `json:"scope"`
 Nonce string `json:"nonce"`
 Operation string `json:"operation"`
 Observation string `json:"observation"`
 Signature []byte `json:"signature"`
}

func validGenesisHex(s string)bool{
 if len(s)!=64{return false}
 b,e:=hex.DecodeString(s)
 return e==nil&&len(b)==32&&hex.EncodeToString(b)==s
}
func newGenesisNonce()(string,error){
 var nonce [32]byte
 if _,e:=rand.Read(nonce[:]);e!=nil{return "",e}
 return hex.EncodeToString(nonce[:]),nil
}
func genesisObservation(domain string)string{
 switch domain{
 case "host-actuator":return "OLD_ACCESS_FENCED"
 case "usbip-exporter":return "OLD_EXPORT_DENIED"
 case "linux-vhci":return "OLD_IMPORT_ABSENT"
 case "network-effective-deny":return "OLD_SESSIONS_DENIED"
 case "guest-input-release":return "NEUTRAL_INPUT_OBSERVED"
 }
 return ""
}
// SigningBytes is a domain-separated, exact typed message, not a bearer grant.
func(w GenesisWitness)SigningBytes()([]byte,error){
 if !w.Scope.valid()||!validGenesisHex(w.Nonce)||!validGenesisHex(w.Operation)||
  genesisObservation(w.Domain)==""||w.Observation!=genesisObservation(w.Domain){
  return nil,ErrInvalid
 }
 w.Signature=nil
 b,e:=json.Marshal(w)
 if e!=nil{return nil,e}
 return append([]byte("usb-fabric/scoped-genesis-witness/v2\x00"),b...),nil
}

func verifyGenesisWitnesses(st State,operation string,witnesses []GenesisWitness,pins map[string]ed25519.PublicKey)(string,error){
 if st.Scope==nil||!validGenesisHex(operation)||len(witnesses)!=len(genesisDomains)||len(pins)!=len(genesisDomains){return "",ErrInvalid}
 seenKeys:=map[string]bool{}
 byDomain:=map[string]GenesisWitness{}
 for _,w:=range witnesses{
  if _,ok:=byDomain[w.Domain];ok{return "",ErrInvalid}
  byDomain[w.Domain]=w
 }
 h:=sha256.New()
 for _,domain:=range genesisDomains{
  key,w:=pins[domain],byDomain[domain]
  if len(key)!=ed25519.PublicKeySize||seenKeys[string(key)]{return "",ErrInvalid}
  seenKeys[string(key)]=true
  if w.Domain!=domain||w.Scope!=*st.Scope||w.Nonce!=st.GenesisNonce||w.Operation!=operation{return "",ErrInvalid}
  b,e:=w.SigningBytes()
  if e!=nil||!ed25519.Verify(key,b,w.Signature){return "",ErrUnverified}
  h.Write(b);h.Write(key);h.Write(w.Signature)
 }
 return hex.EncodeToString(h.Sum(nil)),nil
}

// PrepareScopedAdmission is a write-ahead fence, NOT a grant. Invoke only
// while retaining the sole enrolled resource owner, with independently
// provisioned observer public keys and still-effective backend fences.
// There is no visible clean/unowned admission window. No existing Manager
// constructor accepts v2, including the post-fsync state. An interrupted or
// ambiguous operation requires separately observed recovery, never replay.
func(s Store)PrepareScopedAdmission(expected GenesisScope,operation string,witnesses []GenesisWitness,pins map[string]ed25519.PublicKey)(State,error){
 return s.prepareScopedAdmission(expected,operation,witnesses,pins,s.writeAtomic)
}
func(s Store)prepareScopedAdmission(expected GenesisScope,operation string,witnesses []GenesisWitness,pins map[string]ed25519.PublicKey,write func(State)error)(State,error){
 st,e:=s.ReadScopedHeldGenesis(expected)
 if e!=nil{return State{},e}
 hash,e:=verifyGenesisWitnesses(st,operation,witnesses,pins)
 if e!=nil{return State{},e}
 // Re-read the exact held genesis before the original caller-serialized
 // fsync+rename+parent-fsync transaction. Owner serialization is mandatory.
 check,e:=s.ReadScopedHeldGenesis(expected)
 if e!=nil||check.GenesisNonce!=st.GenesisNonce{return State{},ErrConflict}
 next:=State{Version:ScopedVersion,Sequence:2,Scope:st.Scope,GenesisNonce:st.GenesisNonce,
  GenesisOperation:operation,GenesisEvidenceHash:hash,AdmissionIntent:true}
 if write==nil{return State{},ErrInvalid}
 if e=write(next);e!=nil{return State{},fmt.Errorf("scoped admission remains unavailable: %w",e)}
 return next,nil
}

// Observation only. Never use this API to reconstruct an owner/grant.
func(s Store)ReadScopedAdmissionIntent(expected GenesisScope)(State,error){
 st,e:=s.readDecodedState()
 if e!=nil{return State{},e}
 if st.Version!=ScopedVersion||st.Scope==nil||*st.Scope!=expected||!expected.valid()||
  st.Sequence!=2||st.Held||st.Key!=""||!st.AdmissionIntent||st.ReleasePhase!=""||
  st.KernelWitnessHash!=""||st.LastReleaseEventSequence!=0||st.LastReleaseProofHash!=""||
  !validGenesisHex(st.GenesisNonce)||!validGenesisHex(st.GenesisOperation)||!validGenesisHex(st.GenesisEvidenceHash){
  return State{},errors.New("invalid scoped admission intent")
 }
 return st,nil
}
