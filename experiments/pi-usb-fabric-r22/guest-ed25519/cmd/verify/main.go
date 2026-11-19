// Command verify checks a guest-generated Ed25519 sidecar against the
// R22-A R26 event-schema adapter. The public key must be given separately
// from the message; the ORACLE enrolls it from first untrusted event only,
// so this is TEST-ONLY and NOT authenticated guest identity.
package main

import (
 "crypto/ed25519"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "example.org/usb-fabric-r26-releasegate/evidence"
 guestsign "example.org/usb-fabric-r22-guest-ed25519"
)
func main(){
 if len(os.Args)!=3{fmt.Fprintln(os.Stderr,"need challenge-hex pinned-public-hex");os.Exit(2)}
 nonce,err:=hex.DecodeString(os.Args[1])
 if err!=nil||len(nonce)!=32{os.Exit(3)}
 var c [32]byte;copy(c[:],nonce)
 pinned,err:=hex.DecodeString(os.Args[2]);if err!=nil||len(pinned)!=ed25519.PublicKeySize{os.Exit(4)}
 raw,err:=io.ReadAll(io.LimitReader(os.Stdin,16384));if err!=nil{os.Exit(5)}
 var event evidence.Event
 if err=json.Unmarshal(raw,&event);err!=nil{os.Exit(6)}
 var extra struct {
  Public string `json:"r22_pub"`
  Signature string `json:"r22_sig"`
 }
 if err=json.Unmarshal(raw,&extra);err!=nil || extra.Public!=os.Args[2] {os.Exit(7)}
 event.Proof=extra.Signature
 if !guestsign.VerifyWithPinnedPublicKey(event,c,ed25519.PublicKey(pinned)){
  fmt.Fprintln(os.Stderr,"R22_A_QEMU_GUEST_ED25519_SIGNATURE=RED")
  os.Exit(8)
 }
 fmt.Println("R22_A_QEMU_GUEST_ED25519_SIGNATURE_VERIFIED=PASS")
}
