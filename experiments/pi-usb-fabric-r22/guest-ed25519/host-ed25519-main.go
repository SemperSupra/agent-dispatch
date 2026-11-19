//go:build r22_host

// This is a disposable TEST-ONLY host verifier. The first valid guest
// event enrolls an untrusted per-run public key. It never claims production
// VM identity; it does ensure the existing R26 evidence.Bridge uses
// Ed25519, NOT the legacy public-MAC field, as its release authority.
package main

import (
 "bufio"
 "crypto/ed25519"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"

 releasegate "example.org/usb-fabric-r26-releasegate"
 "example.org/usb-fabric-r26-releasegate/evidence"
 "example.org/usb-fabric-r26-releasegate/guestwire"
)

type command struct {
 Op string `json:"op"`
 Event json.RawMessage `json:"event"`
}
type result struct {
 OK bool `json:"ok"`
 Phase releasegate.Phase `json:"phase"`
 Reclaimable bool `json:"reclaimable"`
 Error string `json:"error,omitempty"`
}
type enrollment struct{
 Public string `json:"r22_pub"`
 Signature string `json:"r22_sig"`
}
type verifier struct{
 pub ed25519.PublicKey
 nonce [32]byte
}
func (v *verifier) validate(event evidence.Event)bool {
 if len(v.pub)!=ed25519.PublicKeySize||len(event.Proof)!=128{return false}
 sig,err:=hex.DecodeString(event.Proof);if err!=nil{return false}
 event.Proof=""
 wire,err:=json.Marshal(struct{
  Domain string
  Event evidence.Event
  Challenge [32]byte
 }{Domain:"USB-FABRIC-R22-TEST-ONLY-ED25519-v1",Event:event,Challenge:v.nonce})
 return err==nil&&ed25519.Verify(v.pub,wire,sig)
}
func (v *verifier) decode(raw json.RawMessage)(evidence.Event,error){
 var evt evidence.Event
 if err:=json.Unmarshal(raw,&evt);err!=nil{return evidence.Event{},err}
 var extra enrollment
 if err:=json.Unmarshal(raw,&extra);err!=nil{return evidence.Event{},err}
 key,err:=hex.DecodeString(extra.Public)
 if err!=nil||len(key)!=ed25519.PublicKeySize||len(extra.Signature)!=128{
  return evidence.Event{},fmt.Errorf("R22 missing guest-origin Ed25519 sidecar")
 }
 // A signed event with a caller-provided key is not sufficient to enroll
 // an identity. Reject semantically invalid first-event claims BEFORE any
 // TOFU pinning; otherwise a console/transport impostor can permanently
 // seize the per-run test key slot even though the gate rejects its event.
 if evt.Scope!=guestwire.Scope() || evt.Source!="guest.evdev" ||
  evt.KeyCode!="key-a" || evt.EventSequence==0 ||
  (v.pub==nil && !evt.Down) {
  return evidence.Event{},fmt.Errorf("R22 unauthorized first key/source/scope")
 }
 evt.Proof=extra.Signature // reject legacy public HMAC as admission evidence
 if v.pub==nil{
  if !evt.Down{return evidence.Event{},fmt.Errorf("unbound guest identity cannot admit UP")}
  if !ed25519.Verify(ed25519.PublicKey(key),mustWire(evt,v.nonce),mustSignature(evt.Proof)){
   return evidence.Event{},fmt.Errorf("first guest key/signature invalid")
  }
  v.pub=append(ed25519.PublicKey(nil),key...)
  fmt.Fprintln(os.Stderr,"R22_A_FIRST_GUEST_PUBLIC_KEY_TOFU_TEST_ENROLLED=PASS")
 }else if !ed25519.PublicKey(key).Equal(v.pub){
  return evidence.Event{},fmt.Errorf("foreign guest key denied after first enrollment")
 }
 if !v.validate(evt){return evidence.Event{},fmt.Errorf("R22 invalid signed guest event")}
 return evt,nil
}
func mustSignature(s string)[]byte {b,err:=hex.DecodeString(s);if err!=nil{return nil};return b}
func mustWire(e evidence.Event,challenge [32]byte)[]byte{
 e.Proof=""
 b,_:=json.Marshal(struct{
  Domain string
  Event evidence.Event
  Challenge [32]byte
 }{Domain:"USB-FABRIC-R22-TEST-ONLY-ED25519-v1",Event:e,Challenge:challenge})
 return b
}
func main(){
 var v verifier
 raw,err:=hex.DecodeString(os.Getenv("R22_CHALLENGE"))
 if err!=nil||len(raw)!=32{fmt.Fprintln(os.Stderr,"missing out-of-band test nonce");os.Exit(2)}
 copy(v.nonce[:],raw)
 if v.nonce==([32]byte{}){fmt.Fprintln(os.Stderr,"zero challenge");os.Exit(2)}
 scope:=guestwire.Scope()
 gate,err:=releasegate.New(scope);if err!=nil{panic(err)}
 bridge,err:=evidence.New(gate,scope,v.validate);if err!=nil{panic(err)}
 s:=bufio.NewScanner(os.Stdin)
 s.Buffer(make([]byte,1024),16384)
 out:=json.NewEncoder(os.Stdout)
 for s.Scan(){
  var cmd command
  err:=json.Unmarshal(s.Bytes(),&cmd)
  if err==nil{
   switch cmd.Op{
   case "event":
    var e evidence.Event
    e,err=v.decode(cmd.Event)
    if err==nil {
     if e.Down{err=bridge.ObserveDown(e)}else{err=bridge.ConfirmUp(e)}
    }
   case "qmp-up-ack":
    err=gate.RequestRelease(scope)
    if err==nil{err=gate.AcknowledgeQMP(scope)}
   case "status":
   default:err=fmt.Errorf("unknown op")
   }
  }
  response:=result{OK:err==nil,Phase:gate.Snapshot().Phase,Reclaimable:bridge.Reclaimable()}
  if err!=nil{response.Error=err.Error()}
  _=out.Encode(response)
 }
 if err:=s.Err();err!=nil{fmt.Fprintln(os.Stderr,"R22 host stream error:",err);os.Exit(3)}
}
